// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const {
  isPlainObject,
  readJson,
  resolveExistingRepositoryFile,
} = require("./common");
const { fingerprint } = require("./evidence");
const { canonicalLocalProfileRoot } = require("./qualification-profile");

const LIVE_CANDIDATE_RECEIPT = ".quality/qualification/live-candidate.json";
const LIVE_CANDIDATE_ARTIFACT = ".quality/qualification/live-candidate.vsix";
const AUTHENTICATED_CANDIDATE_RECEIPT = ".quality/qualification/authenticated-candidate.json";
const AUTHENTICATED_CANDIDATE_ARTIFACT = ".quality/qualification/authenticated-candidate.vsix";
const UI_CANDIDATE_RECEIPT = ".quality/qualification/ui-candidate.json";
const UI_CANDIDATE_ARTIFACT = ".quality/qualification/ui-candidate.vsix";
const MAX_VSIX_BYTES = 12 * 1024 * 1024;
const MAX_VSIX_ENTRIES = 1250;
const EXACT_FILE_READ_FLAGS = fs.constants.O_RDONLY
  | (fs.constants.O_NOFOLLOW || 0)
  | (fs.constants.O_NONBLOCK || 0);
const EXACT_FILE_IDENTITY_KEYS = Object.freeze([
  "changedNanoseconds",
  "device",
  "inode",
  "links",
  "mode",
  "modifiedNanoseconds",
  "size",
]);
const CANDIDATE_BINDING_KEYS = Object.freeze([
  "developmentPath",
  "extensionId",
  "extensionVersion",
  "installedExtensionId",
  "installedExtensionVersion",
  "profileMode",
  "profileRootIdentity",
  "receiptFingerprint",
  "sourceFingerprint",
  "sourceSha",
  "vscodeVersion",
  "vsixSha256",
]);
const IMMUTABLE_CANDIDATE_KEYS = Object.freeze([
  "developmentPath",
  "extensionId",
  "extensionVersion",
  "installedExtensionId",
  "installedExtensionVersion",
  "sourceFingerprint",
  "sourceSha",
  "vscodeVersion",
  "vsixSha256",
]);
const IMMUTABLE_EXTENSION_ARTIFACT_KEYS = Object.freeze(
  IMMUTABLE_CANDIDATE_KEYS.filter(key => key !== "vscodeVersion")
);

function hasExactKeys(value, keys) {
  return isPlainObject(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function exactSource(value) {
  return hasExactKeys(value, ["fingerprint", "sha"])
    && /^[a-f0-9]{40,64}$/u.test(value.sha || "")
    && /^[a-f0-9]{64}$/u.test(value.fingerprint || "");
}

function sameSource(left, right) {
  return exactSource(left) && exactSource(right)
    && left.sha === right.sha && left.fingerprint === right.fingerprint;
}

function sameFilesystemPath(left, right) {
  const normalizedLeft = path.normalize(left);
  const normalizedRight = path.normalize(right);
  return process.platform === "win32"
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight;
}

function exactFileIdentity(stat) {
  return Object.freeze({
    changedNanoseconds: String(stat.ctimeNs),
    device: String(stat.dev),
    inode: String(stat.ino),
    links: String(stat.nlink),
    mode: String(stat.mode),
    modifiedNanoseconds: String(stat.mtimeNs),
    size: String(stat.size),
  });
}

function sameExactFileIdentity(left, right) {
  return Boolean(left && right && EXACT_FILE_IDENTITY_KEYS.every(key => {
    const leftDescriptor = Object.getOwnPropertyDescriptor(left, key);
    const rightDescriptor = Object.getOwnPropertyDescriptor(right, key);
    return leftDescriptor && rightDescriptor
      && Object.prototype.hasOwnProperty.call(leftDescriptor, "value")
      && Object.prototype.hasOwnProperty.call(rightDescriptor, "value")
      && leftDescriptor.value === rightDescriptor.value;
  }));
}

function assertBoundedSingleLinkFile(stat, minimumBytes, maximumBytes, errorMessage) {
  const one = typeof stat.nlink === "bigint" ? 1n : 1;
  const size = typeof stat.size === "bigint" ? stat.size : BigInt(stat.size);
  if (!stat.isFile() || stat.nlink !== one
    || size < BigInt(minimumBytes) || size > BigInt(maximumBytes)) {
    throw new Error(errorMessage);
  }
  return stat;
}

function withStableSingleLinkFile(file, options = {}, consume) {
  const fileSystem = options.fileSystem || fs;
  const errorMessage = options.errorMessage || "Exact file proof is unsafe or changed.";
  const minimumBytes = options.minimumBytes === undefined ? 0 : options.minimumBytes;
  const maximumBytes = options.maximumBytes;
  const expectedBytes = options.expectedBytes;
  if (!Number.isSafeInteger(minimumBytes) || minimumBytes < 0
    || !Number.isSafeInteger(maximumBytes) || maximumBytes < minimumBytes
    || !(expectedBytes === undefined
      || (Number.isSafeInteger(expectedBytes)
        && expectedBytes >= minimumBytes && expectedBytes <= maximumBytes))) {
    throw new Error(errorMessage);
  }
  if (typeof consume !== "function") throw new Error(errorMessage);
  let descriptor;
  let bytes;
  let result;
  let completed = false;
  try {
    const pathStat = assertBoundedSingleLinkFile(
      fileSystem.lstatSync(file, { bigint: true }),
      minimumBytes,
      maximumBytes,
      errorMessage,
    );
    if (expectedBytes !== undefined && pathStat.size !== BigInt(expectedBytes)) {
      throw new Error(errorMessage);
    }
    if (pathStat.isSymbolicLink()
      || !sameFilesystemPath(fileSystem.realpathSync(file), file)) {
      throw new Error(errorMessage);
    }
    const pathIdentity = exactFileIdentity(pathStat);
    if (options.expectedIdentity
      && !sameExactFileIdentity(options.expectedIdentity, pathIdentity)) {
      throw new Error(errorMessage);
    }

    descriptor = fileSystem.openSync(file, EXACT_FILE_READ_FLAGS);
    const openedStat = assertBoundedSingleLinkFile(
      fileSystem.fstatSync(descriptor, { bigint: true }),
      minimumBytes,
      maximumBytes,
      errorMessage,
    );
    const openedIdentity = exactFileIdentity(openedStat);
    if (!sameExactFileIdentity(pathIdentity, openedIdentity)) throw new Error(errorMessage);

    const openedBytes = Number(openedStat.size);
    bytes = Buffer.allocUnsafe(openedBytes);
    let offset = 0;
    while (offset < openedBytes) {
      const bytesRead = fileSystem.readSync(
        descriptor,
        bytes,
        offset,
        openedBytes - offset,
        offset,
      );
      if (!Number.isSafeInteger(bytesRead) || bytesRead <= 0
        || bytesRead > openedBytes - offset) {
        throw new Error(errorMessage);
      }
      offset += bytesRead;
    }

    assertStableOpenFile(
      file,
      descriptor,
      openedIdentity,
      minimumBytes,
      maximumBytes,
      fileSystem,
      errorMessage,
    );
    result = consume(bytes, openedIdentity);
    if (result && typeof result.then === "function") throw new Error(errorMessage);
    assertStableOpenFile(
      file,
      descriptor,
      openedIdentity,
      minimumBytes,
      maximumBytes,
      fileSystem,
      errorMessage,
    );
    completed = true;
  } catch {
    completed = false;
  } finally {
    if (Buffer.isBuffer(bytes)) bytes.fill(0);
    if (descriptor !== undefined) {
      try {
        fileSystem.closeSync(descriptor);
      } catch {
        completed = false;
      }
    }
  }
  if (!completed) throw new Error(errorMessage);
  return result;
}

function assertStableOpenFile(
  file,
  descriptor,
  openedIdentity,
  minimumBytes,
  maximumBytes,
  fileSystem,
  errorMessage,
) {
  const descriptorStat = assertBoundedSingleLinkFile(
    fileSystem.fstatSync(descriptor, { bigint: true }),
    minimumBytes,
    maximumBytes,
    errorMessage,
  );
  const pathStat = assertBoundedSingleLinkFile(
    fileSystem.lstatSync(file, { bigint: true }),
    minimumBytes,
    maximumBytes,
    errorMessage,
  );
  if (pathStat.isSymbolicLink()
    || !sameFilesystemPath(fileSystem.realpathSync(file), file)
    || !sameExactFileIdentity(openedIdentity, exactFileIdentity(descriptorStat))
    || !sameExactFileIdentity(openedIdentity, exactFileIdentity(pathStat))) {
    throw new Error(errorMessage);
  }
  return true;
}

function readStableSingleLinkFile(file, options = {}) {
  return withStableSingleLinkFile(file, options, (bytes, identity) => Object.freeze({
    bytes: Buffer.from(bytes),
    identity,
  }));
}

function digestStableSingleLinkFile(file, options = {}) {
  const digestBytes = options.digestBytes || (bytes => (
    crypto.createHash("sha256").update(bytes).digest("hex")
  ));
  return withStableSingleLinkFile(file, options, (bytes, identity) => {
    const sha256 = digestBytes(bytes);
    if (!/^[a-f0-9]{64}$/u.test(sha256 || "")) {
      throw new Error(options.errorMessage || "Exact file proof is unsafe or changed.");
    }
    return Object.freeze({ identity, sha256 });
  });
}

function profileRootIdentity(mode, root) {
  if (!new Set(["ci", "local"]).has(mode)
    || typeof root !== "string"
    || !path.isAbsolute(root)
    || path.resolve(root) !== root
    || path.normalize(root) !== root
    || /[\u0000-\u001f\u007f]/u.test(root)) {
    throw new Error("Qualification candidate profile identity is invalid.");
  }
  return fingerprint({ mode, root });
}

function candidateBindingFromReceipt(receipt, options = {}) {
  if (!hasExactKeys(receipt, [
    "artifact", "capturedAt", "extension", "fingerprint", "installation", "launch",
    "profile", "repository", "schemaVersion", "source", "status", "toolchain", "vscode",
  ])
    || receipt.schemaVersion !== 3
    || receipt.status !== "passed"
    || !canonicalTimestamp(receipt.capturedAt)
    || !/^[a-f0-9]{64}$/u.test(receipt.fingerprint || "")) {
    throw new Error("Qualification candidate receipt fields are invalid.");
  }
  const unsigned = { ...receipt };
  delete unsigned.fingerprint;
  if (fingerprint(unsigned) !== receipt.fingerprint) {
    throw new Error("Qualification candidate receipt fingerprint is invalid.");
  }
  if (!exactSource(receipt.source)
    || (options.source && !sameSource(receipt.source, options.source))) {
    throw new Error("Qualification candidate receipt source is stale or mismatched.");
  }
  if (!validRepositoryState(receipt.repository)) {
    throw new Error("Qualification candidate repository state is invalid.");
  }
  if (options.repositoryState) {
    if (!validRepositoryState(options.repositoryState)
      || JSON.stringify(receipt.repository) !== JSON.stringify(options.repositoryState)) {
      throw new Error("Qualification candidate repository state is stale or mismatched.");
    }
  }

  const toolchain = receipt.toolchain;
  if (!hasExactKeys(toolchain, [
    "nodeVersion", "npmInstallationSha256", "npmVersion", "platform",
  ])
    || !/^v\d+\.\d+\.\d+$/u.test(toolchain.nodeVersion || "")
    || !/^\d+\.\d+\.\d+$/u.test(toolchain.npmVersion || "")
    || !/^[a-f0-9]{64}$/u.test(toolchain.npmInstallationSha256 || "")
    || !new Set(["darwin", "linux", "win32"]).has(toolchain.platform)) {
    throw new Error("Qualification candidate toolchain provenance is invalid.");
  }
  const toolchainRoot = options.toolchainRoot || options.root;
  if (toolchainRoot) {
    const readVersionPin = name => withStableSingleLinkFile(
      path.join(toolchainRoot, name),
      { errorMessage: "Qualification candidate toolchain pin is invalid.", maximumBytes: 64 },
      bytes => {
        const match = /^(\d+\.\d+\.\d+)(?:\r?\n)?$/u.exec(bytes.toString("utf8"));
        if (!match) throw new Error("Qualification candidate toolchain pin is invalid.");
        return match[1];
      },
    );
    const integrityPins = withStableSingleLinkFile(
      path.join(toolchainRoot, ".npm-integrity"),
      { errorMessage: "Qualification candidate toolchain pin is invalid.", maximumBytes: 256 },
      bytes => {
        const pins = JSON.parse(bytes.toString("utf8"));
        if (!hasExactKeys(pins, ["posix", "win32"])
          || !/^[a-f0-9]{64}$/u.test(pins.posix || "")
          || !/^[a-f0-9]{64}$/u.test(pins.win32 || "")) {
          throw new Error("Qualification candidate toolchain pin is invalid.");
        }
        return pins;
      },
    );
    const integrityKey = toolchain.platform === "win32" ? "win32" : "posix";
    if (toolchain.nodeVersion !== `v${readVersionPin(".node-version")}`
      || toolchain.npmVersion !== readVersionPin(".npm-version")
      || toolchain.npmInstallationSha256 !== integrityPins[integrityKey]) {
      throw new Error("Qualification candidate toolchain provenance is stale or mismatched.");
    }
  }

  const extension = receipt.extension;
  const installation = receipt.installation;
  if (!hasExactKeys(extension, ["id", "name", "publisher", "version"])
    || !/^[A-Za-z0-9][A-Za-z0-9.-]*$/u.test(extension.id || "")
    || extension.id !== `${extension.publisher}.${extension.name}`
    || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(extension.version || "")
    || !hasExactKeys(installation, ["id", "status", "version"])
    || installation.status !== "passed"
    || installation.id !== extension.id
    || installation.version !== extension.version) {
    throw new Error("Qualification candidate installed identity is invalid.");
  }
  if (options.root) {
    const manifest = readJson("package.json", options.root);
    if (extension.id !== `${manifest.publisher}.${manifest.name}`
      || extension.publisher !== manifest.publisher
      || extension.name !== manifest.name
      || extension.version !== manifest.version) {
      throw new Error("Qualification candidate extension identity is stale or mismatched.");
    }
  }

  const artifact = receipt.artifact;
  const artifactFilename = `${extension.name}-${extension.version}.vsix`;
  const allowedArtifactPaths = new Set([
    `out/development/${artifactFilename}`,
    `out/release/${artifactFilename}`,
  ]);
  if (!hasExactKeys(artifact, [
    "absoluteVsixPath", "archiveBytes", "entryCount", "sha256", "sourceFingerprint",
    "sourceSha", "vsixPath",
  ])
    || !/^[a-f0-9]{64}$/u.test(artifact.sha256 || "")
    || artifact.sourceSha !== receipt.source.sha
    || artifact.sourceFingerprint !== receipt.source.fingerprint
    || !Number.isSafeInteger(artifact.archiveBytes) || artifact.archiveBytes <= 0
    || artifact.archiveBytes > MAX_VSIX_BYTES
    || !Number.isSafeInteger(artifact.entryCount) || artifact.entryCount <= 0
    || artifact.entryCount > MAX_VSIX_ENTRIES
    || typeof artifact.vsixPath !== "string"
    || !allowedArtifactPaths.has(artifact.vsixPath)
    || !absoluteNormalizedPath(artifact.absoluteVsixPath)) {
    throw new Error("Qualification candidate VSIX provenance is invalid.");
  }
  if (options.root
    && artifact.absoluteVsixPath !== path.resolve(options.root, artifact.vsixPath)) {
    throw new Error("Qualification candidate VSIX absolute path is stale or mismatched.");
  }
  if (options.artifactPath) {
    const proofPath = containedRealProofPath(options.artifactPath, options.root);
    assertVsixProof(
      proofPath,
      artifact,
      "Qualification candidate VSIX proof is stale or mismatched.",
      { fileSystem: options.fileSystem },
    );
  }

  const profile = receipt.profile;
  const expectedUserDataName = profile?.mode === "local" ? "user-data" : "settings";
  if (!hasExactKeys(profile, [
    "extensionsDir", "mode", "persistent", "root", "testResourcesDir", "userDataDir",
  ])
    || !new Set(["ci", "local"]).has(profile.mode)
    || profile.persistent !== (profile.mode === "local")
    || profile.testResourcesDir !== profile.root
    || profile.userDataDir !== path.join(profile.root, expectedUserDataName)
    || profile.extensionsDir !== path.join(profile.root, "extensions")) {
    throw new Error("Qualification candidate profile binding is invalid.");
  }
  if (profile.mode === "local") {
    let expectedLocalRoot;
    try {
      expectedLocalRoot = canonicalLocalProfileRoot(options.homeDirectory);
    } catch {
      throw new Error("Qualification candidate local profile root is not canonical.");
    }
    if (profile.root !== expectedLocalRoot) {
      throw new Error("Qualification candidate local profile root is not canonical.");
    }
  }
  const rootIdentity = profileRootIdentity(profile.mode, profile.root);

  const vscode = receipt.vscode;
  if (!hasExactKeys(vscode, ["cli", "executable", "version"])
    || !/^\d+\.\d+\.\d+$/u.test(vscode.version || "")
    || !absoluteNormalizedPath(vscode.executable)
    || !absoluteNormalizedPath(vscode.cli)
    || !hasExactKeys(receipt.launch, ["developmentPath", "status"])
    || receipt.launch.developmentPath !== false
    || !new Set(["not-requested", "command-accepted"]).has(receipt.launch.status)) {
    throw new Error("Qualification candidate launch identity is invalid.");
  }

  return Object.freeze({
    developmentPath: false,
    extensionId: extension.id,
    extensionVersion: extension.version,
    installedExtensionId: installation.id,
    installedExtensionVersion: installation.version,
    profileMode: profile.mode,
    profileRootIdentity: rootIdentity,
    receiptFingerprint: receipt.fingerprint,
    sourceFingerprint: receipt.source.fingerprint,
    sourceSha: receipt.source.sha,
    vscodeVersion: vscode.version,
    vsixSha256: artifact.sha256,
  });
}

function containedRealProofPath(file, root) {
  if (!absoluteNormalizedPath(file)) {
    throw new Error("Qualification candidate VSIX proof is stale or mismatched.");
  }
  try {
    if (!root) {
      if (fs.realpathSync(file) !== file) throw new Error("noncanonical proof");
      return file;
    }
    const realRoot = fs.realpathSync(path.resolve(root));
    const relative = path.relative(realRoot, file).split(path.sep).join("/");
    if (!relative || relative.startsWith("../") || path.posix.isAbsolute(relative)) {
      throw new Error("escaped proof");
    }
    const resolved = resolveExistingRepositoryFile(relative, root);
    if (resolved !== file) throw new Error("noncanonical proof");
    return resolved;
  } catch {
    throw new Error("Qualification candidate VSIX proof is stale or mismatched.");
  }
}

function assertVsixProof(file, artifact, errorMessage, options = {}) {
  try {
    const proof = digestStableSingleLinkFile(file, {
      errorMessage,
      expectedBytes: artifact.archiveBytes,
      fileSystem: options.fileSystem,
      maximumBytes: MAX_VSIX_BYTES,
      minimumBytes: 1,
    });
    if (proof.identity.size !== String(artifact.archiveBytes)
      || proof.sha256 !== artifact.sha256) {
      throw new Error(errorMessage);
    }
  } catch {
    throw new Error(errorMessage);
  }
}

function validateCandidateBinding(value, expected = null) {
  if (!hasExactKeys(value, CANDIDATE_BINDING_KEYS)
    || value.developmentPath !== false
    || !/^[A-Za-z0-9][A-Za-z0-9.-]*$/u.test(value.extensionId || "")
    || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(value.extensionVersion || "")
    || value.installedExtensionId !== value.extensionId
    || value.installedExtensionVersion !== value.extensionVersion
    || !new Set(["ci", "local"]).has(value.profileMode)
    || !/^[a-f0-9]{64}$/u.test(value.profileRootIdentity || "")
    || !/^[a-f0-9]{64}$/u.test(value.receiptFingerprint || "")
    || !/^[a-f0-9]{64}$/u.test(value.sourceFingerprint || "")
    || !/^[a-f0-9]{40,64}$/u.test(value.sourceSha || "")
    || !/^\d+\.\d+\.\d+$/u.test(value.vscodeVersion || "")
    || !/^[a-f0-9]{64}$/u.test(value.vsixSha256 || "")) {
    throw new Error("Qualification candidate binding fields are invalid.");
  }
  if (expected && CANDIDATE_BINDING_KEYS.some(key => value[key] !== expected[key])) {
    throw new Error("Qualification candidate binding is stale or mismatched.");
  }
  return value;
}

function validateEquivalentCandidateProduct(localCandidate, ciCandidate) {
  validateCandidateBinding(localCandidate);
  validateCandidateBinding(ciCandidate);
  if (IMMUTABLE_CANDIDATE_KEYS.some(key => localCandidate[key] !== ciCandidate[key])) {
    throw new Error(
      "Local and authenticated-CI candidates do not identify the same immutable product artifact."
    );
  }
  return true;
}

function validateEquivalentExtensionArtifact(leftCandidate, rightCandidate) {
  validateCandidateBinding(leftCandidate);
  validateCandidateBinding(rightCandidate);
  if (IMMUTABLE_EXTENSION_ARTIFACT_KEYS.some(
    key => leftCandidate[key] !== rightCandidate[key]
  )) {
    throw new Error(
      "Qualification candidates do not identify the same immutable extension artifact."
    );
  }
  return true;
}

function validateAuthenticatedExecutionReceipt(receipt, candidate, source) {
  const unsigned = { ...receipt };
  delete unsigned.fingerprint;
  if (!hasExactKeys(receipt, [
    "candidate", "credentialBoundary", "fingerprint", "phases", "reasonCode",
    "schemaVersion", "source", "status", "workspace",
  ])
    || receipt.schemaVersion !== 2
    || receipt.status !== "passed"
    || receipt.reasonCode !== null
    || !sameSource(receipt.source, source)
    || fingerprint(unsigned) !== receipt.fingerprint
    || !/^[a-f0-9]{64}$/u.test(receipt.fingerprint || "")) {
    throw new Error("Authenticated qualification receipt is missing, stale, or not passed.");
  }
  validateCandidateBinding(receipt.candidate, candidate);
  if (candidate.profileMode !== "ci"
    || !hasExactKeys(receipt.workspace, ["expected", "observed", "surface"])
    || receipt.workspace.expected !== "dl-technology-consulting"
    || receipt.workspace.observed !== receipt.workspace.expected
    || receipt.workspace.surface !== "production-connected-workspace"
    || !hasExactKeys(receipt.credentialBoundary, [
      "digestRecorded", "storageKey", "transport", "valueRecorded",
    ])
    || receipt.credentialBoundary.storageKey !== "cloudsmith-vsc.authToken"
    || receipt.credentialBoundary.transport !== "creator-bound-0700-0600-handoff"
    || receipt.credentialBoundary.valueRecorded !== false
    || receipt.credentialBoundary.digestRecorded !== false
    || !hasExactKeys(receipt.phases, [
      "candidate", "handoff", "outputBoundary", "productionWorkspaceCheck",
      "profileCleanup", "secretStorageCleanup", "seed",
    ])
    || receipt.phases.candidate !== "prepared"
    || receipt.phases.handoff !== "consumed-before-store-completion"
    || receipt.phases.seed !== "passed"
    || receipt.phases.productionWorkspaceCheck !== "passed"
    || receipt.phases.secretStorageCleanup !== "passed"
    || receipt.phases.profileCleanup !== "passed"
    || receipt.phases.outputBoundary !== "passed") {
    throw new Error("Authenticated qualification receipt lacks exact successful lifecycle proof.");
  }
  return receipt;
}

function absoluteNormalizedPath(value) {
  return typeof value === "string"
    && path.isAbsolute(value)
    && path.resolve(value) === value
    && path.normalize(value) === value
    && !/[\u0000-\u001f\u007f]/u.test(value);
}

function canonicalTimestamp(value) {
  if (typeof value !== "string") return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function validRepositoryState(value) {
  return hasExactKeys(value, ["branch", "dirty", "status"])
    && (value.branch === null || (
      typeof value.branch === "string"
      && value.branch.length > 0
      && value.branch.length <= 255
      && !/[\u0000-\u001f\u007f]/u.test(value.branch)
    ))
    && typeof value.dirty === "boolean"
    && value.status === (value.dirty ? "dirty" : "clean");
}

module.exports = {
  AUTHENTICATED_CANDIDATE_ARTIFACT,
  AUTHENTICATED_CANDIDATE_RECEIPT,
  CANDIDATE_BINDING_KEYS,
  EXACT_FILE_IDENTITY_KEYS,
  IMMUTABLE_EXTENSION_ARTIFACT_KEYS,
  IMMUTABLE_CANDIDATE_KEYS,
  LIVE_CANDIDATE_ARTIFACT,
  LIVE_CANDIDATE_RECEIPT,
  UI_CANDIDATE_ARTIFACT,
  UI_CANDIDATE_RECEIPT,
  candidateBindingFromReceipt,
  digestStableSingleLinkFile,
  exactFileIdentity,
  profileRootIdentity,
  readStableSingleLinkFile,
  sameExactFileIdentity,
  sameSource,
  validateAuthenticatedExecutionReceipt,
  validateCandidateBinding,
  validateEquivalentCandidateProduct,
  validateEquivalentExtensionArtifact,
  withStableSingleLinkFile,
};

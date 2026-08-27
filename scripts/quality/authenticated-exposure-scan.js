// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  ROOT,
  assertRepositoryRelativePath,
  removeOutputFile,
  writeJson,
} = require("./common");
const { fingerprint } = require("./evidence");
const {
  GITLEAKS_VERSION,
  assertScannerVersion,
  scanGeneratedEvidence,
  scanVsix,
  scanWithGitleaks,
} = require("./secret-scan");

const AUTHENTICATED_EXPOSURE_RESULT = ".quality/secrets/authenticated-ci.json";
const MAX_RUNTIME_LOG_FILES = 10_000;
const profileBoundaryProofs = new WeakSet();

function exactPrivateDirectory(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value)
    || path.resolve(value) !== value || path.normalize(value) !== value
    || value.includes("\u0000")) {
    throw new Error(`${label} must be an absolute normalized path.`);
  }
  const stat = fs.lstatSync(value);
  if (stat.isSymbolicLink() || !stat.isDirectory() || fs.realpathSync(value) !== value
    || (process.platform !== "win32" && (stat.mode & 0o077) !== 0)
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error(`${label} must be an owned private real directory.`);
  }
  return stat;
}

function exactParentDirectory(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value)
    || path.resolve(value) !== value || path.normalize(value) !== value
    || value.includes("\u0000")) {
    throw new Error(`${label} must be an absolute normalized path.`);
  }
  const stat = fs.lstatSync(value);
  if (stat.isSymbolicLink() || !stat.isDirectory() || fs.realpathSync(value) !== value) {
    throw new Error(`${label} must be a real directory.`);
  }
  return stat;
}

function createRuntimeLogRoot(options = {}) {
  const parent = fs.realpathSync(options.temporaryParent || os.tmpdir());
  exactParentDirectory(parent, "Authenticated runtime-log parent");
  const root = fs.realpathSync(fs.mkdtempSync(path.join(
    parent,
    "cloudsmith-authenticated-runtime-logs-",
  )));
  if (process.platform !== "win32") fs.chmodSync(root, 0o700);
  const stat = exactPrivateDirectory(root, "Authenticated runtime-log root");
  return Object.freeze({ root, dev: stat.dev, ino: stat.ino });
}

function destroyRuntimeLogRoot(descriptor) {
  if (!descriptor || typeof descriptor !== "object" || Array.isArray(descriptor)) {
    throw new Error("Authenticated runtime-log ownership descriptor is invalid.");
  }
  const stat = exactPrivateDirectory(descriptor.root, "Authenticated runtime-log root");
  if (stat.dev !== descriptor.dev || stat.ino !== descriptor.ino) {
    throw new Error("Authenticated runtime-log cleanup refuses a replaced directory.");
  }
  fs.rmSync(descriptor.root, { recursive: true, force: false });
  return !fs.existsSync(descriptor.root);
}

function assertProfileMetadataBoundary(profile) {
  if (!profile || profile.mode !== "ci" || profile.persistent !== false
    || profile.testResourcesDir !== profile.root
    || profile.homeDir !== path.join(profile.root, "home")
    || profile.userDataDir !== path.join(profile.root, "settings")
    || profile.extensionsDir !== path.join(profile.root, "extensions")) {
    throw new Error("Authenticated profile metadata boundary is invalid.");
  }
  const root = exactPrivateDirectory(profile.root, "Authenticated profile root");
  for (const [label, directory] of [
    ["home", profile.homeDir],
    ["user data", profile.userDataDir],
    ["extensions", profile.extensionsDir],
  ]) {
    const stat = exactPrivateDirectory(directory, `Authenticated profile ${label}`);
    if (stat.dev !== root.dev) {
      throw new Error("Authenticated profile metadata crossed filesystems.");
    }
  }
  const proof = Object.freeze({ directoryCount: 4, contentRead: false });
  profileBoundaryProofs.add(proof);
  return proof;
}

function consumeProfileMetadataBoundaryProof(proof) {
  if (!proofBoundaryShape(proof) || !profileBoundaryProofs.has(proof)) {
    throw new Error("Authenticated profile metadata proof is not owned by this scan lifecycle.");
  }
  profileBoundaryProofs.delete(proof);
  return proof;
}

function proofBoundaryShape(proof) {
  return Boolean(proof && typeof proof === "object" && !Array.isArray(proof)
    && Object.keys(proof).sort().join(",") === "contentRead,directoryCount"
    && proof.directoryCount === 4 && proof.contentRead === false);
}

function runtimeLogInventory(root) {
  exactPrivateDirectory(root, "Authenticated runtime-log root");
  const pending = [root];
  let fileCount = 0;
  let directoryCount = 1;
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const target = path.join(directory, entry.name);
      const stat = fs.lstatSync(target);
      if (stat.isSymbolicLink()) {
        throw new Error("Authenticated runtime logs reject symbolic links.");
      }
      if (stat.isDirectory()) {
        if (fs.realpathSync(target) !== target) {
          throw new Error("Authenticated runtime log directory is not canonical.");
        }
        directoryCount += 1;
        pending.push(target);
      } else if (stat.isFile()) {
        fileCount += 1;
      } else {
        throw new Error("Authenticated runtime logs contain an unsupported entry type.");
      }
      if (fileCount + directoryCount > MAX_RUNTIME_LOG_FILES) {
        throw new Error("Authenticated runtime log inventory exceeded its structural bound.");
      }
    }
  }
  return Object.freeze({ fileCount, directoryCount });
}

function safeComponent(component) {
  return Object.freeze({
    id: component.id,
    status: component.status,
    fileCount: component.fileCount,
    findingCount: component.findings.length,
  });
}

function assertExposureReceipt(value) {
  const unsigned = { ...value };
  delete unsigned.fingerprint;
  const exactKeys = [
    "candidateReceiptFingerprint", "components", "credentialBoundary", "findingCount",
    "fingerprint", "scanner", "schemaVersion", "sourceSha", "status",
  ];
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join(",") !== exactKeys.sort().join(",")
    || value.schemaVersion !== 1
    || !new Set(["passed", "failed"]).has(value.status)
    || !/^[0-9a-f]{40,64}$/u.test(value.sourceSha || "")
    || !/^[a-f0-9]{64}$/u.test(value.candidateReceiptFingerprint || "")
    || !value.scanner || Object.keys(value.scanner).sort().join(",")
      !== "name,secretBearingFieldsPersisted,version"
    || value.scanner.name !== "gitleaks"
    || value.scanner.version !== GITLEAKS_VERSION
    || value.scanner.secretBearingFieldsPersisted !== false
    || !value.credentialBoundary
    || Object.keys(value.credentialBoundary).sort().join(",")
      !== "credentialDigestRecorded,credentialValueRecorded,keychainRead,profileContentRead,secretStorageRead"
    || Object.values(value.credentialBoundary).some(flag => flag !== false)
    || !Array.isArray(value.components) || value.components.length !== 4
    || value.components.some(component => (
      !component || Object.keys(component).sort().join(",")
        !== "fileCount,findingCount,id,status"
      || typeof component.id !== "string"
      || !new Set(["scanned", "not-present"]).has(component.status)
      || !(component.fileCount === null
        || (Number.isSafeInteger(component.fileCount) && component.fileCount >= 0))
      || !Number.isSafeInteger(component.findingCount) || component.findingCount < 0
    ))
    || value.findingCount !== value.components.reduce(
      (total, component) => total + component.findingCount,
      0,
    )
    || (value.status === "passed") !== (value.findingCount === 0)
    || fingerprint(unsigned) !== value.fingerprint) {
    throw new Error("Authenticated exposure receipt is not value-blind.");
  }
  return value;
}

function validateAuthenticatedExposureProof(receipt, candidateReceipt, source) {
  assertExposureReceipt(receipt);
  const expectedIds = [
    "authenticated-generated-evidence",
    `vsix:${candidateReceipt?.artifact?.vsixPath || ""}`,
    "authenticated-runtime-logs",
    "profile-boundary-metadata-only",
  ];
  const [generated, artifact, runtimeLogs, profile] = receipt.components;
  if (receipt.status !== "passed"
    || receipt.sourceSha !== source?.sha
    || receipt.candidateReceiptFingerprint !== candidateReceipt?.fingerprint
    || JSON.stringify(receipt.components.map(component => component.id))
      !== JSON.stringify(expectedIds)
    || generated.status !== "scanned"
    || !Number.isSafeInteger(generated.fileCount) || generated.fileCount <= 0
    || artifact.status !== "scanned"
    || !Number.isSafeInteger(artifact.fileCount) || artifact.fileCount <= 1
    || !new Set(["scanned", "not-present"]).has(runtimeLogs.status)
    || !Number.isSafeInteger(runtimeLogs.fileCount) || runtimeLogs.fileCount < 0
    || (runtimeLogs.status === "not-present") !== (runtimeLogs.fileCount === 0)
    || profile.status !== "scanned" || profile.fileCount !== 4
    || receipt.components.some(component => component.findingCount !== 0)) {
    throw new Error("Authenticated exposure evidence lacks its exact value-blind components.");
  }
  return receipt;
}

async function runAuthenticatedExposureScan(context, options = {}) {
  const root = context.root || ROOT;
  if (root !== ROOT || context.source?.sha === undefined
    || context.candidate?.receipt?.fingerprint !== context.candidateReceiptFingerprint) {
    throw new Error("Authenticated exposure scan context is invalid.");
  }
  const outputPath = options.outputPath || AUTHENTICATED_EXPOSURE_RESULT;
  removeOutputFile(outputPath, root, { subtree: ".quality/secrets" });
  const assertScanner = options.assertScannerVersion || assertScannerVersion;
  const scanGenerated = options.scanGeneratedEvidence || scanGeneratedEvidence;
  const scanArtifact = options.scanVsix || scanVsix;
  const scanLogs = options.scanWithGitleaks || scanWithGitleaks;
  assertScanner({
    root,
    execute: options.execute,
    environment: context.environment,
  });
  const profile = consumeProfileMetadataBoundaryProof(
    context.profileBoundaryProof
      || assertProfileMetadataBoundary(context.candidate.profile),
  );
  const runtimeLogs = runtimeLogInventory(context.runtimeLogRoot);
  const generated = scanGenerated(root, ".quality", {
    id: "authenticated-generated-evidence",
    excludedPrefixes: [".quality/secrets"],
    execute: options.execute,
    environment: context.environment,
  });
  const artifactPath = assertRepositoryRelativePath(
    context.candidate.receipt.artifact.vsixPath,
    { subtree: "out" },
  );
  const artifact = await scanArtifact(root, artifactPath, {
    execute: options.execute,
    environment: context.environment,
  });
  const logFindings = runtimeLogs.fileCount === 0 ? [] : scanLogs(
    "dir",
    context.runtimeLogRoot,
    {
      root,
      scanRoot: context.runtimeLogRoot,
      label: "authenticated-runtime-logs",
      execute: options.execute,
      environment: context.environment,
    },
  );
  const components = [
    safeComponent(generated),
    safeComponent(artifact),
    safeComponent({
      id: "authenticated-runtime-logs",
      status: runtimeLogs.fileCount === 0 ? "not-present" : "scanned",
      fileCount: runtimeLogs.fileCount,
      findings: logFindings,
    }),
    safeComponent({
      id: "profile-boundary-metadata-only",
      status: "scanned",
      fileCount: profile.directoryCount,
      findings: [],
    }),
  ];
  const findingCount = components.reduce((total, component) => (
    total + component.findingCount
  ), 0);
  const base = {
    schemaVersion: 1,
    status: findingCount === 0 ? "passed" : "failed",
    sourceSha: context.source.sha,
    candidateReceiptFingerprint: context.candidateReceiptFingerprint,
    scanner: {
      name: "gitleaks",
      version: GITLEAKS_VERSION,
      secretBearingFieldsPersisted: false,
    },
    credentialBoundary: {
      profileContentRead: profile.contentRead,
      secretStorageRead: false,
      keychainRead: false,
      credentialValueRecorded: false,
      credentialDigestRecorded: false,
    },
    findingCount,
    components,
  };
  const receipt = validateAuthenticatedExposureProof(
    assertExposureReceipt({ ...base, fingerprint: fingerprint(base) }),
    context.candidate.receipt,
    context.source,
  );
  const persist = options.writeReceipt || (value => writeJson(
    outputPath,
    value,
    root,
    { subtree: ".quality/secrets" },
  ));
  persist(receipt);
  return Object.freeze(receipt);
}

module.exports = {
  AUTHENTICATED_EXPOSURE_RESULT,
  assertExposureReceipt,
  assertProfileMetadataBoundary,
  createRuntimeLogRoot,
  destroyRuntimeLogRoot,
  runAuthenticatedExposureScan,
  runtimeLogInventory,
  validateAuthenticatedExposureProof,
};

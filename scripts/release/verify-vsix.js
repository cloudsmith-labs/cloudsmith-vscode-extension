// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const { spawnSync } = require("child_process");
const { TextDecoder } = require("util");
const yauzl = require("yauzl");
const {
  exactFileIdentity,
  sameExactFileIdentity,
  withStableSingleLinkFile,
} = require("../quality/candidate-binding");
const { withNonAuthQualityEnvironment } = require("../quality/non-auth-environment");
const { FORMAT_ICON_FILES } = require("../../util/formatIconInventory");

const root = path.resolve(__dirname, "../..");
const limits = Object.freeze({
  archiveBytes: 12 * 1024 * 1024,
  centralDirectoryBytes: 256 * 1024,
  entryCount: 1250,
  entryBytes: 5 * 1024 * 1024,
  pathBytes: 160,
  totalBytes: 16 * 1024 * 1024,
});
const MAX_CHECKSUM_SIDECAR_BYTES = 4 * 1024;
const MAX_PROVENANCE_SIDECAR_BYTES = 32 * 1024;
const EXACT_FILE_READ_FLAGS = fs.constants.O_RDONLY
  | (fs.constants.O_NOFOLLOW || 0)
  | (fs.constants.O_NONBLOCK || 0);
const unstableArtifactFailures = new WeakSet();
const verificationFailureDiagnostics = new WeakMap();
const verificationPhases = new Set(["snapshot", "rebind", "semantics", "sidecars"]);
const verificationChecks = new Set([
  "open", "descriptor-stat", "path-stat", "file-kind", "links", "size",
  "expected-identity", "descriptor-identity", "path-identity", "canonical-path",
  "read", "read-size", "close", "archive-validation", "central-directory",
  "manifest", "source-inventory", "source-bytes", "module-closure", "embedded-metadata",
  "artifact-file", "checksum-file", "provenance-file", "artifact-bytes",
  "checksum-encoding", "checksum-bytes", "provenance-encoding", "provenance-json",
  "provenance-fields", "provenance-values", "provenance-schema", "provenance-source",
  "provenance-toolchain", "provenance-commit", "provenance-epoch",
  "provenance-pin", "provenance-expected-source", "provenance-publishable",
]);
const verificationErrnos = new Set([
  "EACCES", "EBUSY", "EIO", "EISDIR", "ELOOP", "EMFILE", "ENAMETOOLONG",
  "ENOENT", "ENOTDIR", "EPERM", "ESTALE",
]);
const WINDOWS_ARTIFACT_VERIFICATION_RETRIES = 8;
const EXACT_ARTIFACT_IDENTITY_KEYS = Object.freeze([
  "changedNanoseconds",
  "device",
  "inode",
  "links",
  "mode",
  "modifiedNanoseconds",
  "size",
]);

function verificationFailureDiagnostic(error) {
  return error && (typeof error === "object" || typeof error === "function")
    ? verificationFailureDiagnostics.get(error) || null
    : null;
}

function annotateVerificationFailure(error, phase, check, expected, actual) {
  // Diagnostics must not inspect messages, invoke accessors, or change rejection
  // and buffer cleanup when an untrusted thrown value is a hostile Proxy.
  try {
  if (!error || (typeof error !== "object" && typeof error !== "function")
    || verificationFailureDiagnostics.has(error)
    || !verificationPhases.has(phase) || !verificationChecks.has(check)) return error;
  const code = phase === "snapshot" || phase === "rebind"
    ? Object.getOwnPropertyDescriptor(error, "code")
    : null;
  const errno = code && Object.prototype.hasOwnProperty.call(code, "value")
    && verificationErrnos.has(code.value) ? code.value : null;
  const changed = expected && actual ? EXACT_ARTIFACT_IDENTITY_KEYS.filter(key => {
    const left = Object.getOwnPropertyDescriptor(expected, key);
    const right = Object.getOwnPropertyDescriptor(actual, key);
    return !left || !right || !Object.prototype.hasOwnProperty.call(left, "value")
      || !Object.prototype.hasOwnProperty.call(right, "value") || left.value !== right.value;
  }) : [];
  verificationFailureDiagnostics.set(error,
    [phase, check, errno, changed.length ? changed.join(",") : null].filter(Boolean).join(":"));
  return error;
  } catch {
    return error;
  }
}

function verificationCheckError(message, phase, check, expected, actual) {
  return annotateVerificationFailure(new Error(message), phase, check, expected, actual);
}

function runVerificationCheck(phase, check, operation) {
  try {
    return operation();
  } catch (error) {
    throw annotateVerificationFailure(error, phase, check);
  }
}
const generatedEntries = new Set(["[Content_Types].xml", "extension.vsixmanifest"]);
const baseMedia = new Set([
  "media/icon.svg",
  "media/logo.png",
  "media/workspace_dark.svg",
  "media/workspace_light.svg",
  "media/readme/brand-banner.png",
  ...FORMAT_ICON_FILES,
]);
const documentMappings = new Map([
  ["README.md", "extension/readme.md"],
  ["LICENSE", "extension/LICENSE.txt"],
  ["CHANGELOG.md", "extension/changelog.md"],
  ["CONTRIBUTORS.md", "extension/CONTRIBUTORS.md"],
]);
const reverseDocumentMappings = new Map([...documentMappings].map(([source, archive]) => [archive, source]));
const forbiddenSegments = new Set([
  ".agents", ".claude", ".codex", ".github", ".vscode", ".vscode-test",
  "__tests__", "build", "coverage", "dist", "internal_docs", "node_modules",
  "out", "scripts", "temp", "test", "tests",
]);
const sensitivePatterns = Object.freeze([
  { id: "developer-home-posix", expression: /\/(?:Users|home)\/[A-Za-z0-9._-]+\// },
  { id: "developer-home-windows", expression: /[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\/ },
  { id: "private-key", expression: /-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----/ },
  { id: "ssh-private-key", expression: /(?:PuTTY-User-Key-File-[23]:|---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----)/ },
  { id: "url-userinfo", expression: /[a-z][a-z0-9+.-]{1,20}:\/\/[^\s/:@]{1,128}:[^\s/@]{1,256}@/i },
  { id: "authorization-header", expression: /\bauthorization\s*:\s*(?:basic|bearer)\s+[A-Za-z0-9._~+/=-]{8,}/i },
  { id: "cloudsmith-token", expression: /csa_[A-Za-z0-9]{20,}/ },
  { id: "github-token", expression: /(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}/ },
  { id: "npm-token", expression: /\bnpm_[A-Za-z0-9]{20,}/ },
  { id: "gitlab-token", expression: /\bglpat-[A-Za-z0-9_-]{20,}/ },
  { id: "azure-devops-token", expression: /\b[A-Za-z0-9]{75}AZDO[A-Za-z0-9]{5}\b/ },
  { id: "gcp-api-key", expression: /\bAIza[A-Za-z0-9_-]{35}\b/ },
  { id: "openai-token", expression: /sk-[A-Za-z0-9]{20,}/ },
  { id: "slack-token", expression: /xox[baprs]-[A-Za-z0-9-]{20,}/ },
  { id: "aws-access-key", expression: /AKIA[0-9A-Z]{16}/ },
]);

function runGit(arguments_, encoding = "utf8", options = {}) {
  const spawn = options.spawnSync || spawnSync;
  return withNonAuthQualityEnvironment({
    environment: options.environment || process.env,
    platform: options.platform,
    temporaryParent: options.temporaryParent,
  }, environment => {
    const result = spawn("git", arguments_, {
      cwd: root,
      encoding,
      env: environment,
      maxBuffer: 64 * 1024 * 1024,
    });
    if (result.status !== 0) {
      throw new Error((result.stderr || result.stdout || "git command failed").toString().trim());
    }
    return result.stdout;
  });
}

function isApprovedSourcePath(sourcePath) {
  if (["package.json", "extension.js", ...documentMappings.keys()].includes(sourcePath)) {
    return true;
  }
  if (/^(?:commands|domain|models|util|views)\/(?:[^/]+\/)*[^/]+\.js$/.test(sourcePath)) {
    return true;
  }
  if (baseMedia.has(sourcePath)) {
    return true;
  }
  return false;
}

function sourceToArchivePath(sourcePath) {
  return documentMappings.get(sourcePath) || `extension/${sourcePath}`;
}

function archiveToSourcePath(archivePath) {
  return reverseDocumentMappings.get(archivePath) || archivePath.replace(/^extension\//, "");
}

function parseGitEntries(buffer, sourceSha) {
  const entries = new Map();
  for (const record of buffer.toString("utf8").split("\0")) {
    if (!record) {
      continue;
    }
    const match = sourceSha
      ? /^(\d+)\s+blob\s+([0-9a-f]+)\t(.+)$/.exec(record)
      : /^(\d+)\s+([0-9a-f]+)\s+(\d+)\t(.+)$/.exec(record);
    if (!match) {
      continue;
    }
    const mode = match[1];
    const oid = match[2];
    const stage = sourceSha ? "0" : match[3];
    const sourcePath = sourceSha ? match[3] : match[4];
    if (stage !== "0") {
      throw new Error(`Tracked source has an unresolved index stage: ${sourcePath}`);
    }
    entries.set(sourcePath, { mode, oid });
  }
  return entries;
}

function buildExpectedInventory({ sourceSha = null } = {}) {
  const output = sourceSha
    ? runGit(["ls-tree", "-r", "-z", sourceSha], null)
    : runGit(["ls-files", "-s", "-z"], null);
  const tracked = parseGitEntries(output, sourceSha);
  if (!sourceSha) {
    const untracked = runGit(["ls-files", "--others", "--exclude-standard", "-z"], null)
      .toString("utf8")
      .split("\0")
      .filter(Boolean);
    for (const sourcePath of untracked) {
      if (isApprovedSourcePath(sourcePath) && !tracked.has(sourcePath)) {
        tracked.set(sourcePath, { mode: "100644", oid: null, untracked: true });
      }
    }
  }
  const expected = new Map();
  for (const [sourcePath, metadata] of tracked) {
    if (!isApprovedSourcePath(sourcePath)) {
      continue;
    }
    const worktreeStats = sourceSha ? null : fs.lstatSync(path.join(root, sourcePath));
    const forbiddenMode = sourceSha
      ? metadata.mode === "120000" || (Number.parseInt(metadata.mode.slice(-3), 8) & 0o111)
      : worktreeStats.isSymbolicLink() || !worktreeStats.isFile() || (worktreeStats.mode & 0o111);
    if (forbiddenMode) {
      throw new Error(`Packaged source has a symbolic-link or executable Git mode: ${sourcePath}`);
    }
    expected.set(sourceToArchivePath(sourcePath), { sourcePath, ...metadata });
  }
  for (const required of ["package.json", "extension.js", "README.md", "LICENSE", "CHANGELOG.md", "CONTRIBUTORS.md"] ) {
    if (!tracked.has(required)
      || tracked.get(required).untracked
      || !expected.has(sourceToArchivePath(required))) {
      throw new Error(`Required packaged source is not tracked: ${required}`);
    }
  }
  return { expected, tracked };
}

function parseCentralDirectory(buffer) {
  const minimumOffset = Math.max(0, buffer.length - 22 - 0xffff);
  let offset = -1;
  for (let candidate = buffer.length - 22; candidate >= minimumOffset; candidate -= 1) {
    if (buffer.readUInt32LE(candidate) === 0x06054b50) {
      const commentLength = buffer.readUInt16LE(candidate + 20);
      if (candidate + 22 + commentLength === buffer.length) {
        offset = candidate;
        break;
      }
    }
  }
  if (offset === -1) {
    throw new Error("VSIX has no valid end-of-central-directory record");
  }
  const disk = buffer.readUInt16LE(offset + 4);
  const centralDisk = buffer.readUInt16LE(offset + 6);
  const diskEntries = buffer.readUInt16LE(offset + 8);
  const totalEntries = buffer.readUInt16LE(offset + 10);
  const centralSize = buffer.readUInt32LE(offset + 12);
  const centralOffset = buffer.readUInt32LE(offset + 16);
  if (disk || centralDisk || diskEntries !== totalEntries) {
    throw new Error("Multi-disk VSIX archives are not supported");
  }
  if (totalEntries === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff) {
    throw new Error("ZIP64 VSIX archives are outside the bounded release format");
  }
  if (centralOffset + centralSize !== offset || centralSize > limits.centralDirectoryBytes) {
    throw new Error("VSIX central directory is inconsistent or exceeds its review limit");
  }
  if (totalEntries === 0 || totalEntries > limits.entryCount) {
    throw new Error(`VSIX entry count must be between 1 and ${limits.entryCount}`);
  }
  return { centralSize, totalEntries };
}

function validateArchivePath(fileName, seen = new Set()) {
  if (!fileName || Buffer.byteLength(fileName, "utf8") > limits.pathBytes) {
    throw new Error("VSIX contains an empty or overlong path");
  }
  if (fileName !== fileName.normalize("NFC")) {
    throw new Error("VSIX paths must use Unicode NFC normalization");
  }
  if (/^[A-Za-z]:/.test(fileName) || fileName.startsWith("/") || fileName.includes("\\")) {
    throw new Error("VSIX contains an absolute, drive-qualified, or backslash path");
  }
  if (/[\x00-\x1f\x7f]/.test(fileName)) {
    throw new Error("VSIX contains a control character in a path");
  }
  const segments = fileName.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) {
    throw new Error("VSIX contains an empty or traversing path segment");
  }
  const lowerSegments = segments.map((segment) => segment.toLowerCase());
  if (lowerSegments.some((segment) => forbiddenSegments.has(segment))) {
    throw new Error("VSIX contains a forbidden path segment");
  }
  const baseName = lowerSegments.at(-1);
  if (
    baseName === ".ds_store"
    || baseName === ".npmrc"
    || baseName === ".mcp.json"
    || baseName === "mcp.json"
    || baseName.startsWith(".env")
    || /(?:^|[._-])(?:audit|project-plan|prompt)(?:[._-]|$)/.test(baseName)
    || /\.(?:key|pem|p12|pfx|vsix|map)$/.test(baseName)
    || /^(?:credentials(?:\.json)?|id_(?:rsa|dsa|ecdsa|ed25519))$/.test(baseName)
  ) {
    throw new Error("VSIX contains a forbidden local, secret, or release-planning file");
  }
  const folded = fileName.toLowerCase();
  if (seen.has(folded)) {
    throw new Error("VSIX contains duplicate paths under case folding");
  }
  seen.add(folded);
  return fileName;
}

function scanSensitiveBytes(buffer, ordinal) {
  const content = buffer.toString("latin1");
  for (const pattern of sensitivePatterns) {
    if (pattern.expression.test(content)) {
      throw new Error(`Sensitive-content rule ${pattern.id} matched archive entry ${ordinal}`);
    }
  }
}

function gitBlobHash(buffer, oid) {
  const algorithm = oid.length === 64 ? "sha256" : "sha1";
  return crypto.createHash(algorithm)
    .update(`blob ${buffer.length}\0`)
    .update(buffer)
    .digest("hex");
}

function normalizeReadme(buffer, manifest) {
  const repository = typeof manifest.repository === "string"
    ? manifest.repository
    : manifest.repository?.url;
  const base = (repository || "").replace(/^git\+/, "").replace(/\.git$/, "").replace(/\/$/, "");
  if (!base.startsWith("https://github.com/")) {
    throw new Error("README transformation verification requires an HTTPS GitHub repository URL");
  }
  return Buffer.from(buffer.toString("utf8").replaceAll(`${base}/raw/HEAD/`, ""), "utf8");
}

function readStableWorktreeFile(filePath, sourcePath) {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
  const descriptor = fs.openSync(filePath, flags);
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.size > BigInt(limits.entryBytes)) {
      throw new Error(`Packaged worktree source is not a bounded regular file: ${sourcePath}`);
    }
    const expectedSize = Number(before.size);
    const allocation = Buffer.alloc(expectedSize + 1);
    let offset = 0;
    while (offset < allocation.length) {
      const bytesRead = fs.readSync(descriptor, allocation, offset, allocation.length - offset, offset);
      if (!bytesRead) {
        break;
      }
      offset += bytesRead;
    }
    if (offset !== expectedSize) {
      throw new Error(`Packaged worktree source changed size while being read: ${sourcePath}`);
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    for (const field of ["dev", "ino", "size", "mtimeNs", "ctimeNs"]) {
      if (before[field] !== after[field]) {
        throw new Error(`Packaged worktree source changed while being read: ${sourcePath}`);
      }
    }
    return Buffer.from(allocation.subarray(0, expectedSize));
  } finally {
    fs.closeSync(descriptor);
  }
}

function assertSourceBytes(archivePath, bytes, source, manifest, sourceSha) {
  let comparable = bytes;
  if (archivePath === "extension/readme.md") {
    comparable = normalizeReadme(bytes, manifest);
  }
  if (sourceSha) {
    if (gitBlobHash(comparable, source.oid) !== source.oid) {
      throw new Error(`VSIX bytes do not match source commit for ${source.sourcePath}`);
    }
    return;
  }
  const sourcePath = path.join(root, source.sourcePath);
  if (!comparable.equals(readStableWorktreeFile(sourcePath, source.sourcePath))) {
    throw new Error(`VSIX bytes do not match the worktree for ${source.sourcePath}`);
  }
}

function assertRelativeModuleClosure(entries, expected) {
  for (const [archivePath, bytes] of entries) {
    if (!/^extension\/(?:extension|commands\/.*|domain\/.*|models\/.*|util\/.*|views\/.*)\.js$/.test(archivePath)) {
      continue;
    }
    const sourcePath = archiveToSourcePath(archivePath);
    const source = bytes.toString("utf8");
    for (const match of source.matchAll(/require\(\s*["'](\.{1,2}\/[^"']+)["']\s*\)/g)) {
      const base = path.posix.normalize(path.posix.join(path.posix.dirname(sourcePath), match[1]));
      if (base.startsWith("../") || base === "..") {
        throw new Error(`Runtime module escapes approved roots from ${sourcePath}`);
      }
      const candidates = path.posix.extname(base)
        ? [base]
        : [base, `${base}.js`, `${base}.json`, `${base}/index.js`];
      if (!candidates.some((candidate) => expected.has(sourceToArchivePath(candidate)))) {
        throw new Error(`VSIX omits relative runtime module ${match[1]} required by ${sourcePath}`);
      }
    }
  }
}

function assertEmbeddedMetadata(entries, expected, manifest) {
  const embeddedPackage = JSON.parse(entries.get("extension/package.json").toString("utf8"));
  for (const field of ["name", "publisher", "version", "main", "icon"]) {
    if (embeddedPackage[field] !== manifest[field]) {
      throw new Error(`Embedded package.json field ${field} does not match the source manifest`);
    }
  }
  if (Object.keys(embeddedPackage.dependencies || {}).length !== 0) {
    throw new Error("Packaged extension must not contain runtime dependencies");
  }
  const requiredSources = [manifest.main, manifest.icon]
    .filter(Boolean)
    .map((entry) => entry.replace(/^\.\//, ""));
  for (const container of manifest.contributes?.viewsContainers?.activitybar || []) {
    requiredSources.push(container.icon);
  }
  for (const required of requiredSources) {
    if (!expected.has(sourceToArchivePath(required))) {
      throw new Error(`Manifest-required packaged asset is missing: ${required}`);
    }
  }

  const vsixManifest = entries.get("extension.vsixmanifest").toString("utf8");
  const identityTag = /<Identity\b[^>]*\/>/.exec(vsixManifest)?.[0];
  if (!identityTag) {
    throw new Error("VSIX manifest has no Identity element");
  }
  const attributes = Object.fromEntries([...identityTag.matchAll(/([A-Za-z]+)="([^"]*)"/g)]
    .map((match) => [match[1], match[2]]));
  if (
    attributes.Id !== manifest.name
    || attributes.Publisher !== manifest.publisher
    || attributes.Version !== manifest.version
  ) {
    throw new Error("VSIX identity does not match package.json");
  }
}

function openZip(buffer) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(buffer, {
      autoClose: false,
      decodeStrings: true,
      lazyEntries: true,
      strictFileNames: true,
      validateEntrySizes: true,
    }, (error, zipfile) => error ? reject(error) : resolve(zipfile));
  });
}

function assertBoundedArtifactStat(stat, errorMessage, phase) {
  if (!stat.isFile()) throw verificationCheckError(errorMessage, phase, "file-kind");
  if (stat.nlink !== 1n) throw verificationCheckError(errorMessage, phase, "links");
  if (stat.size <= 0n || stat.size > BigInt(limits.archiveBytes)) {
    throw verificationCheckError(errorMessage, phase, "size");
  }
  return stat;
}

function assertStableArtifactPath(filePath, descriptor, identity, fileSystem, errorMessage, phase) {
  const descriptorStat = assertBoundedArtifactStat(
    runVerificationCheck(phase, "descriptor-stat", () => fileSystem.fstatSync(descriptor, { bigint: true })),
    errorMessage, phase,
  );
  const pathStat = assertBoundedArtifactStat(
    runVerificationCheck(phase, "path-stat", () => fileSystem.lstatSync(filePath, { bigint: true })),
    errorMessage, phase,
  );
  if (pathStat.isSymbolicLink()
    || runVerificationCheck(phase, "canonical-path", () => fileSystem.realpathSync(filePath)) !== filePath) {
    throw verificationCheckError(errorMessage, phase, "canonical-path");
  }
  const descriptorIdentity = exactFileIdentity(descriptorStat);
  if (!sameExactFileIdentity(identity, descriptorIdentity)) {
    throw verificationCheckError(errorMessage, phase, "descriptor-identity", identity, descriptorIdentity);
  }
  const pathIdentity = exactFileIdentity(pathStat);
  if (!sameExactFileIdentity(identity, pathIdentity)) {
    throw verificationCheckError(errorMessage, phase, "path-identity", identity, pathIdentity);
  }
}

function artifactTransactionFailure(transactionFailure, errorMessage, retryable = true) {
  const error = new Error(errorMessage);
  const diagnostic = verificationFailureDiagnostic(transactionFailure);
  if (diagnostic) verificationFailureDiagnostics.set(error, diagnostic);
  const code = (typeof transactionFailure === "object" || typeof transactionFailure === "function")
    ? Object.getOwnPropertyDescriptor(transactionFailure, "code")
    : null;
  if (retryable && code && Object.prototype.hasOwnProperty.call(code, "value")
    && new Set(["EBUSY", "EPERM"]).has(code.value)) {
    unstableArtifactFailures.add(error);
  }
  return error;
}

function runArtifactTransaction(options, operation) {
  const platform = options.platform || process.platform;
  const retryDelay = options.retryDelay || boundedArtifactRetryDelay;
  const maximumRetries = platform === "win32"
    ? WINDOWS_ARTIFACT_VERIFICATION_RETRIES
    : 0;
  let attempt = 0;
  while (true) {
    try {
      return operation();
    } catch (error) {
      if (attempt >= maximumRetries || !isUnstableArtifactFailure(error)) throw error;
      retryDelay(attempt);
      attempt += 1;
    }
  }
}

function captureStableArtifactSnapshot(filePath, options) {
  const fileSystem = options.fileSystem || fs;
  const errorMessage = "VSIX pathname is not an exact bounded single-link file.";
  const absolutePath = path.resolve(filePath);
  let allocation;
  let descriptor;
  let identity;
  let transactionFailure = null;
  let transactionRetryable = true;
  let check = "open";
  try {
    descriptor = fileSystem.openSync(absolutePath, EXACT_FILE_READ_FLAGS, 0o600);
    check = "descriptor-stat";
    const openedStat = assertBoundedArtifactStat(
      fileSystem.fstatSync(descriptor, { bigint: true }),
      errorMessage, "snapshot",
    );
    identity = exactFileIdentity(openedStat);
    if (options.expectedIdentity
      && !sameExactFileIdentity(options.expectedIdentity, identity)) {
      throw verificationCheckError(errorMessage, "snapshot", "expected-identity", options.expectedIdentity, identity);
    }
    assertStableArtifactPath(absolutePath, descriptor, identity, fileSystem, errorMessage, "snapshot");
    const expectedSize = Number(openedStat.size);
    allocation = Buffer.allocUnsafe(expectedSize);
    let offset = 0;
    while (offset < expectedSize) {
      check = "read";
      const bytesRead = fileSystem.readSync(
        descriptor,
        allocation,
        offset,
        expectedSize - offset,
        offset,
      );
      if (!Number.isSafeInteger(bytesRead) || bytesRead < 0
        || bytesRead > expectedSize - offset) {
        throw verificationCheckError(errorMessage, "snapshot", "read-size");
      }
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset !== expectedSize) throw verificationCheckError(errorMessage, "snapshot", "read-size");
    assertStableArtifactPath(absolutePath, descriptor, identity, fileSystem, errorMessage, "snapshot");
  } catch (error) {
    transactionFailure = annotateVerificationFailure(error, "snapshot", check);
  } finally {
    if (descriptor !== undefined) {
      try {
        fileSystem.closeSync(descriptor);
      } catch (error) {
        transactionFailure = annotateVerificationFailure(error, "snapshot", "close");
        transactionRetryable = false;
      }
    }
  }
  if (transactionFailure) {
    if (Buffer.isBuffer(allocation)) allocation.fill(0);
    throw artifactTransactionFailure(transactionFailure, errorMessage, transactionRetryable);
  }
  return { allocation, identity };
}

function rebindStableArtifactPath(filePath, identity, options) {
  const fileSystem = options.fileSystem || fs;
  const errorMessage = "VSIX pathname is not an exact bounded single-link file.";
  const absolutePath = path.resolve(filePath);
  let descriptor;
  let transactionFailure = null;
  let transactionRetryable = true;
  let check = "open";
  try {
    descriptor = fileSystem.openSync(absolutePath, EXACT_FILE_READ_FLAGS, 0o600);
    check = "descriptor-stat";
    const reboundStat = assertBoundedArtifactStat(
      fileSystem.fstatSync(descriptor, { bigint: true }),
      errorMessage, "rebind",
    );
    const reboundIdentity = exactFileIdentity(reboundStat);
    if (!sameExactFileIdentity(identity, reboundIdentity)) {
      throw verificationCheckError(errorMessage, "rebind", "expected-identity", identity, reboundIdentity);
    }
    assertStableArtifactPath(absolutePath, descriptor, identity, fileSystem, errorMessage, "rebind");
  } catch (error) {
    transactionFailure = annotateVerificationFailure(error, "rebind", check);
  } finally {
    if (descriptor !== undefined) {
      try {
        fileSystem.closeSync(descriptor);
      } catch (error) {
        transactionFailure = annotateVerificationFailure(error, "rebind", "close");
        transactionRetryable = false;
      }
    }
  }
  if (transactionFailure) {
    throw artifactTransactionFailure(transactionFailure, errorMessage, transactionRetryable);
  }
}

async function withStableArtifact(filePath, options = {}, consume) {
  const snapshot = runArtifactTransaction(
    options,
    () => captureStableArtifactSnapshot(filePath, options),
  );
  let result;
  try {
    result = await consume(snapshot.allocation, snapshot.identity);
  } catch (error) {
    snapshot.allocation.fill(0);
    throw annotateVerificationFailure(error, "semantics", "archive-validation");
  }
  try {
    runArtifactTransaction(
      options,
      () => rebindStableArtifactPath(filePath, snapshot.identity, options),
    );
  } finally {
    snapshot.allocation.fill(0);
  }
  return result;
}

function isUnstableArtifactFailure(error) {
  return Boolean(error && (typeof error === "object" || typeof error === "function")
    && unstableArtifactFailures.has(error));
}

function exactArtifactIdentity(value) {
  if (!value || (typeof value !== "object" && typeof value !== "function")
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...EXACT_ARTIFACT_IDENTITY_KEYS].sort())) {
    return false;
  }
  return EXACT_ARTIFACT_IDENTITY_KEYS.every(key => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && Object.prototype.hasOwnProperty.call(descriptor, "value")
      && typeof descriptor.value === "string" && /^\d+$/u.test(descriptor.value);
  });
}

function boundedArtifactRetryDelay(attempt) {
  const milliseconds = Math.min(25 * (2 ** attempt), 800);
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

async function verifyFreshVsix(filePath, options = {}) {
  const expectedIdentityDescriptor = Object.getOwnPropertyDescriptor(
    options,
    "expectedIdentity",
  );
  const expectedIdentity = expectedIdentityDescriptor
    && Object.prototype.hasOwnProperty.call(expectedIdentityDescriptor, "value")
    ? expectedIdentityDescriptor.value
    : null;
  if (!exactArtifactIdentity(expectedIdentity)) {
    throw new Error("Fresh VSIX verification identity is unsafe or invalid.");
  }
  const verify = options.verifyVsix || verifyVsix;
  return verify(filePath, {
    expectedIdentity,
    platform: options.platform || process.platform,
    retryDelay: options.retryDelay || boundedArtifactRetryDelay,
    sourceSha: options.sourceSha || null,
  });
}

function withBoundedNamedFile(filePath, options, consume, check) {
  let semanticError;
  const result = runVerificationCheck("sidecars", check, () => withStableSingleLinkFile(filePath, options, (bytes, identity) => {
    try {
      return consume(bytes, identity);
    } catch (error) {
      semanticError = error;
      return undefined;
    }
  }));
  if (semanticError) throw semanticError;
  return result;
}

async function verifyVsix(filePath, options = {}) {
  const { sourceSha = null } = options;
  return withStableArtifact(filePath, options, async (artifactBytes, artifactIdentity) => {
  const buffer = artifactBytes;
  const central = runVerificationCheck("semantics", "central-directory", () => parseCentralDirectory(buffer));
  const manifest = runVerificationCheck("semantics", "manifest", () => (
    JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"))
  ));
  if (!manifest.dependencies || Object.keys(manifest.dependencies).length) {
    throw new Error("package.json dependencies must be explicitly empty before packaging");
  }
  const { expected } = runVerificationCheck("semantics", "source-inventory", () => buildExpectedInventory({ sourceSha }));
  const requiredArchivePaths = new Set([...generatedEntries, ...expected.keys()]);
  const seen = new Set();
  const entries = new Map();
  let totalDeclared = 0;
  let totalActual = 0;
  let ordinal = 0;
  const zipfile = await openZip(buffer);
  try {
    for await (const entry of zipfile.eachEntry()) {
      ordinal += 1;
      const fileName = validateArchivePath(entry.fileName, seen);
      if (!requiredArchivePaths.has(fileName)) {
        throw new Error(`VSIX contains an unexpected entry at ordinal ${ordinal}`);
      }
      if (entry.isEncrypted() || ![0, 8].includes(entry.compressionMethod)) {
        throw new Error(`VSIX entry ${ordinal} uses encryption or unsupported compression`);
      }
      const unixMode = entry.externalFileAttributes >>> 16;
      const fileType = unixMode & 0o170000;
      if ((fileType && fileType !== 0o100000) || (unixMode & 0o111)) {
        throw new Error(`VSIX entry ${ordinal} is not a non-executable regular file`);
      }
      if (entry.uncompressedSize > limits.entryBytes) {
        throw new Error(`VSIX entry ${ordinal} exceeds the per-entry size limit`);
      }
      totalDeclared += entry.uncompressedSize;
      if (totalDeclared > limits.totalBytes) {
        throw new Error("VSIX declared uncompressed size exceeds the aggregate limit");
      }

      const stream = await zipfile.openReadStreamPromise(entry);
      const chunks = [];
      let actual = 0;
      let checksum = 0;
      for await (const chunk of stream) {
        actual += chunk.length;
        totalActual += chunk.length;
        if (actual > limits.entryBytes || totalActual > limits.totalBytes) {
          throw new Error(`VSIX entry ${ordinal} exceeds actual byte limits while streaming`);
        }
        checksum = zlib.crc32(chunk, checksum);
        chunks.push(chunk);
      }
      if (actual !== entry.uncompressedSize || (checksum >>> 0) !== (entry.crc32 >>> 0)) {
        throw new Error(`VSIX entry ${ordinal} failed size or CRC validation`);
      }
      const bytes = Buffer.concat(chunks, actual);
      scanSensitiveBytes(bytes, ordinal);
      entries.set(fileName, bytes);
      if (!generatedEntries.has(fileName)) {
        runVerificationCheck("semantics", "source-bytes", () => (
          assertSourceBytes(fileName, bytes, expected.get(fileName), manifest, sourceSha)
        ));
      }
    }
  } finally {
    zipfile.close();
  }

  if (ordinal !== central.totalEntries || ordinal !== requiredArchivePaths.size) {
    throw new Error("VSIX entry count does not match its central directory and expected inventory");
  }
  for (const required of requiredArchivePaths) {
    if (!entries.has(required)) {
      throw new Error(`VSIX omits expected entry: ${required}`);
    }
  }
  runVerificationCheck("semantics", "module-closure", () => assertRelativeModuleClosure(entries, expected));
  runVerificationCheck("semantics", "embedded-metadata", () => assertEmbeddedMetadata(entries, expected, manifest));

  return {
    artifactIdentity,
    buffer: Buffer.from(buffer),
    sha256: crypto.createHash("sha256").update(buffer).digest("hex"),
    archiveBytes: buffer.length,
    entryCount: ordinal,
    totalUncompressedBytes: totalActual,
    paths: [...entries.keys()].sort(),
    manifest: {
      name: manifest.name,
      publisher: manifest.publisher,
      version: manifest.version,
    },
  };
  });
}

function validateProvenance(provenance, filePath, verification, options) {
  let check = "provenance-fields";
  try {
  const allowedFields = new Set([
    "archiveBytes", "entryCount", "filename", "name", "nodeVersion", "npmVersion",
    "npmInstallationSha256", "platform", "publishable", "publisher", "schemaVersion", "sha256",
    "sourceClean", "sourceCommitEpoch", "sourceSha", "totalUncompressedBytes", "version",
  ]);
  const provenanceFields = Object.keys(provenance);
  if (
    provenanceFields.length !== allowedFields.size
    || provenanceFields.some((field) => !allowedFields.has(field))
  ) {
    throw new Error("Provenance sidecar fields do not match schema version 3");
  }
  const expected = {
    filename: path.basename(filePath),
    sha256: verification.sha256,
    archiveBytes: verification.archiveBytes,
    entryCount: verification.entryCount,
    totalUncompressedBytes: verification.totalUncompressedBytes,
    name: verification.manifest.name,
    publisher: verification.manifest.publisher,
    version: verification.manifest.version,
  };
  check = "provenance-values";
  for (const [field, value] of Object.entries(expected)) {
    if (provenance[field] !== value) {
      throw new Error(`Provenance sidecar field ${field} does not match the verified VSIX`);
    }
  }
  check = "provenance-schema";
  if (provenance.schemaVersion !== 3 || !/^[0-9a-f]{40,64}$/.test(provenance.sourceSha || "")) {
    throw new Error("Provenance sidecar has an unsupported schema or invalid source SHA");
  }
  check = "provenance-source";
  if (
    typeof provenance.sourceClean !== "boolean"
    || typeof provenance.publishable !== "boolean"
    || (provenance.publishable && !provenance.sourceClean)
    || !Number.isSafeInteger(provenance.sourceCommitEpoch)
    || provenance.sourceCommitEpoch <= 0
  ) {
    throw new Error("Provenance sidecar has invalid source cleanliness or commit metadata");
  }
  check = "provenance-toolchain";
  if (!/^v\d+\.\d+\.\d+$/.test(provenance.nodeVersion || "")
    || !/^\d+\.\d+\.\d+$/.test(provenance.npmVersion || "")
    || !/^[a-f0-9]{64}$/u.test(provenance.npmInstallationSha256 || "")
    || !new Set(["darwin", "linux", "win32"]).has(provenance.platform)) {
    throw new Error("Provenance sidecar has invalid Node.js or npm version metadata");
  }
  const git = options.runGitCommand || runGit;
  check = "provenance-commit";
  const resolvedCommit = git(["rev-parse", "--verify", `${provenance.sourceSha}^{commit}`]).trim();
  if (resolvedCommit !== provenance.sourceSha) {
    throw new Error("Provenance source SHA does not resolve to the exact recorded commit");
  }
  check = "provenance-epoch";
  const commitEpoch = Number(git(["show", "-s", "--format=%ct", provenance.sourceSha]).trim());
  if (commitEpoch !== provenance.sourceCommitEpoch) {
    throw new Error("Provenance commit epoch does not match the recorded source commit");
  }
  check = "provenance-pin";
  const repositoryRoot = path.resolve(options.repositoryRoot || root);
  const fileSystem = options.fileSystem || fs;
  const parseVersionPin = bytes => {
    const match = /^(\d+\.\d+\.\d+)(?:\r?\n)?$/u.exec(bytes.toString("utf8"));
    if (!match) throw new Error("Canonical toolchain provenance pin is unsafe or invalid");
    return match[1];
  };
  const parseIntegrityPins = bytes => {
    const pins = JSON.parse(bytes.toString("utf8"));
    if (!pins || typeof pins !== "object" || Array.isArray(pins)
      || JSON.stringify(Object.keys(pins).sort()) !== JSON.stringify(["posix", "win32"])
      || !/^[a-f0-9]{64}$/u.test(pins.posix || "")
      || !/^[a-f0-9]{64}$/u.test(pins.win32 || "")) {
      throw new Error("Canonical toolchain provenance pin is unsafe or invalid");
    }
    return pins;
  };
  const readWorktreePin = (name, maximumBytes, parse) => withStableSingleLinkFile(
    path.join(repositoryRoot, name),
    {
      errorMessage: "Canonical toolchain provenance pin is unsafe or invalid",
      fileSystem,
      maximumBytes,
      minimumBytes: 1,
    },
    parse,
  );
  const readCommitPin = (name, maximumBytes, parse) => {
    const object = `${provenance.sourceSha}:${name}`;
    const sizeText = git(["cat-file", "-s", object]).trim();
    if (!/^[1-9]\d*$/u.test(sizeText)) {
      throw new Error("Canonical toolchain provenance pin is unsafe or invalid");
    }
    const size = Number(sizeText);
    if (!Number.isSafeInteger(size) || size > maximumBytes) {
      throw new Error("Canonical toolchain provenance pin is unsafe or invalid");
    }
    const value = git(["show", object]);
    const bytes = Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from(value, "utf8");
    if (bytes.length !== size) {
      throw new Error("Canonical toolchain provenance pin is unsafe or invalid");
    }
    return parse(bytes);
  };
  const readPin = provenance.sourceClean ? readCommitPin : readWorktreePin;
  const nodeVersion = readPin(".node-version", 64, parseVersionPin);
  const npmVersion = readPin(".npm-version", 64, parseVersionPin);
  const npmIntegrityPins = readPin(".npm-integrity", 256, parseIntegrityPins);
  const npmIntegrity = npmIntegrityPins[provenance.platform === "win32" ? "win32" : "posix"];
  check = "provenance-toolchain";
  if (provenance.nodeVersion !== `v${nodeVersion}`
    || provenance.npmVersion !== npmVersion
    || provenance.npmInstallationSha256 !== npmIntegrity) {
    throw new Error("Provenance toolchain does not match the exact repository pins");
  }
  check = "provenance-expected-source";
  if (options.expectedSourceSha && provenance.sourceSha !== options.expectedSourceSha) {
    throw new Error("Provenance source SHA does not match the expected workflow source");
  }
  check = "provenance-publishable";
  if (options.requirePublishable && (!provenance.sourceClean || !provenance.publishable)) {
    throw new Error("Artifact handoff requires clean, publishable provenance");
  }
  return provenance;
  } catch (error) {
    throw annotateVerificationFailure(error, "sidecars", check);
  }
}

function readProvenanceSidecar(filePath, options = {}) {
  const provenancePath = `${path.resolve(filePath)}.provenance.json`;
  return withBoundedNamedFile(provenancePath, {
    errorMessage: "Provenance sidecar is not an exact bounded single-link file.",
    expectedIdentity: options.expectedIdentity,
    fileSystem: options.fileSystem,
    maximumBytes: MAX_PROVENANCE_SIDECAR_BYTES,
    minimumBytes: 1,
  }, (bytes, identity) => Object.freeze({
    identity,
    provenance: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)),
  }), "provenance-file");
}

function withStableSidecarSet(filePath, verification, options = {}, consume) {
  const absolutePath = path.resolve(filePath);
  const checksumPath = `${absolutePath}.sha256`;
  const provenancePath = `${absolutePath}.provenance.json`;
  if (!Buffer.isBuffer(verification?.buffer)
    || verification.buffer.length !== verification.archiveBytes
    || crypto.createHash("sha256").update(verification.buffer).digest("hex")
      !== verification.sha256) {
    throw verificationCheckError("Sidecar validation requires exact verified VSIX bytes", "sidecars", "artifact-bytes");
  }
  return withBoundedNamedFile(absolutePath, {
    errorMessage: "Verified VSIX pathname is not an exact bounded single-link file.",
    expectedBytes: verification.archiveBytes,
    expectedIdentity: verification.artifactIdentity,
    fileSystem: options.fileSystem,
    maximumBytes: limits.archiveBytes,
    minimumBytes: 1,
  }, (artifactBytes, artifactIdentity) => {
    if (!artifactBytes.equals(verification.buffer)) {
      throw verificationCheckError("Verified VSIX pathname does not contain the verified artifact bytes", "sidecars", "artifact-bytes");
    }
    return withBoundedNamedFile(checksumPath, {
      errorMessage: "Checksum sidecar is not an exact bounded single-link file.",
      expectedIdentity: options.expectedChecksumIdentity,
      fileSystem: options.fileSystem,
      maximumBytes: MAX_CHECKSUM_SIDECAR_BYTES,
      minimumBytes: 1,
    }, (checksumBytes, checksumIdentity) => {
      return withBoundedNamedFile(provenancePath, {
        errorMessage: "Provenance sidecar is not an exact bounded single-link file.",
        expectedIdentity: options.expectedProvenanceIdentity,
        fileSystem: options.fileSystem,
        maximumBytes: MAX_PROVENANCE_SIDECAR_BYTES,
        minimumBytes: 1,
      }, (provenanceBytes, provenanceIdentity) => {
        return consume(Object.freeze({
          absolutePath,
          artifactBytes,
          artifactIdentity,
          checksumBytes,
          checksumIdentity,
          checksumPath,
          provenanceBytes,
          provenanceIdentity,
          provenancePath,
        }));
      }, "provenance-file");
    }, "checksum-file");
  }, "artifact-file");
}

function validateSidecars(filePath, verification, options = {}) {
  return withStableSidecarSet(filePath, verification, options, proof => {
    const checksum = runVerificationCheck("sidecars", "checksum-encoding", () => (
      new TextDecoder("utf-8", { fatal: true }).decode(proof.checksumBytes)
    ));
    if (checksum !== `${verification.sha256}  ${path.basename(proof.absolutePath)}\n`) {
      throw verificationCheckError("Checksum sidecar does not match the verified VSIX", "sidecars", "checksum-bytes");
    }
    const provenanceText = runVerificationCheck("sidecars", "provenance-encoding", () => (
      new TextDecoder("utf-8", { fatal: true }).decode(proof.provenanceBytes)
    ));
    const provenance = runVerificationCheck("sidecars", "provenance-json", () => JSON.parse(provenanceText));
    validateProvenance(provenance, proof.absolutePath, verification, options);
    return Object.freeze({
      artifactIdentity: proof.artifactIdentity,
      checksumIdentity: proof.checksumIdentity,
      checksumPath: proof.checksumPath,
      provenance,
      provenanceIdentity: proof.provenanceIdentity,
      provenancePath: proof.provenancePath,
    });
  });
}

function artifactSourceSha(filePath, options = {}) {
  const fileSystem = options.fileSystem || fs;
  if (!fileSystem.existsSync(filePath)) return null;
  try {
    const { provenance } = readProvenanceSidecar(filePath, options);
    return /^[0-9a-f]{40,64}$/.test(provenance?.sourceSha || "")
      ? provenance.sourceSha
      : null;
  } catch {
    return null;
  }
}

function selectArtifactPath({ releasePath, developmentPath, expectedSourceSha, fileSystem = fs }) {
  if (!/^[0-9a-f]{40,64}$/.test(expectedSourceSha || "")) {
    throw new Error("Default VSIX selection requires an exact expected source SHA");
  }
  const candidates = [releasePath, developmentPath]
    .filter(candidate => fileSystem.existsSync(candidate));
  if (candidates.length === 0) {
    throw new Error("No release or development VSIX artifact exists for the current package");
  }
  const matches = candidates.filter(candidate => (
    artifactSourceSha(candidate, { fileSystem }) === expectedSourceSha
  ));
  if (matches.length === 0) {
    throw new Error("No VSIX artifact has valid provenance for the expected source SHA");
  }
  if (matches.length > 1) {
    throw new Error("VSIX artifact selection is ambiguous for the expected source SHA");
  }
  return matches[0];
}

function resolveExpectedSourceSha(options, currentSourceSha) {
  if (options.currentSource
    && !/^[0-9a-f]{40,64}$/.test(currentSourceSha || "")) {
    throw new Error("Could not resolve the exact current source SHA");
  }
  if (options.currentSource
    && options.expectedSourceSha
    && options.expectedSourceSha !== currentSourceSha) {
    throw new Error("Explicit expected source SHA does not match the current checkout");
  }
  return options.expectedSourceSha || currentSourceSha || null;
}

function verificationSourceSha(provenance, {
  currentSource = false,
  currentSourceDirty = false,
} = {}) {
  if (currentSourceDirty && !currentSource) {
    throw new Error("Dirty-worktree verification state requires --current-source");
  }
  if (!provenance?.sourceClean || (currentSource && currentSourceDirty)) return null;
  return provenance.sourceSha;
}

function parseCliArguments(arguments_) {
  const options = {
    currentSource: false,
    expectedSourceSha: null,
    explicitPath: null,
    list: false,
    requirePublishable: false,
    requireSidecars: false,
  };
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--require-sidecars") {
      options.requireSidecars = true;
    } else if (argument === "--current-source") {
      options.currentSource = true;
    } else if (argument === "--require-publishable") {
      options.requirePublishable = true;
    } else if (argument === "--list") {
      options.list = true;
    } else if (argument === "--expected-source-sha") {
      options.expectedSourceSha = arguments_[index + 1];
      index += 1;
    } else if (argument.startsWith("--")) {
      throw new Error(`Unknown VSIX verifier option: ${argument}`);
    } else if (options.explicitPath) {
      throw new Error("VSIX verifier accepts only one artifact path");
    } else {
      options.explicitPath = argument;
    }
  }
  if (options.expectedSourceSha !== null && !/^[0-9a-f]{40,64}$/.test(options.expectedSourceSha || "")) {
    throw new Error("--expected-source-sha requires a full hexadecimal commit SHA");
  }
  if ((options.currentSource || options.expectedSourceSha) && !options.requireSidecars) {
    throw new Error("VSIX source binding requires --require-sidecars");
  }
  if (!options.explicitPath && !options.currentSource && !options.expectedSourceSha) {
    throw new Error("VSIX verification requires an explicit artifact path or source binding");
  }
  if (options.requirePublishable && !options.requireSidecars) {
    throw new Error("--require-publishable requires --require-sidecars");
  }
  return options;
}

async function main() {
  const options = parseCliArguments(process.argv.slice(2));
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const filename = `${manifest.name}-${manifest.version}.vsix`;
  const releasePath = path.join(root, "out", "release", filename);
  const developmentPath = path.join(root, "out", "development", filename);
  const currentSourceSha = options.currentSource
    ? runGit(["rev-parse", "--verify", "HEAD^{commit}"]).trim()
    : null;
  const currentSourceDirty = options.currentSource
    ? runGit(["status", "--porcelain=v1", "--untracked-files=all"]).length > 0
    : false;
  const expectedSourceSha = resolveExpectedSourceSha(options, currentSourceSha);
  const filePath = options.explicitPath
    ? path.resolve(root, options.explicitPath)
    : selectArtifactPath({ releasePath, developmentPath, expectedSourceSha });
  let sourceSha = null;
  let provenanceIdentity;
  if (options.requireSidecars) {
    const provenanceProof = readProvenanceSidecar(filePath);
    provenanceIdentity = provenanceProof.identity;
    sourceSha = verificationSourceSha(provenanceProof.provenance, {
      currentSource: options.currentSource,
      currentSourceDirty,
    });
  }
  const verification = await verifyVsix(filePath, { sourceSha });
  if (options.requireSidecars) {
    validateSidecars(filePath, verification, {
      expectedSourceSha,
      expectedProvenanceIdentity: provenanceIdentity,
      requirePublishable: options.requirePublishable,
    });
  }
  if (options.list) {
    process.stdout.write(`${verification.paths.join("\n")}\n`);
  }
  console.log(
    `Verified ${path.basename(filePath)}: ${verification.entryCount} entries, `
    + `${verification.archiveBytes} bytes, sha256 ${verification.sha256}.`,
  );
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}

module.exports = {
  assertRelativeModuleClosure,
  buildExpectedInventory,
  isApprovedSourcePath,
  limits,
  parseCentralDirectory,
  parseCliArguments,
  readProvenanceSidecar,
  runPackageGitCommand: runGit,
  resolveExpectedSourceSha,
  scanSensitiveBytes,
  selectArtifactPath,
  verificationSourceSha,
  verificationFailureDiagnostic,
  validateArchivePath,
  validateSidecars,
  verifyFreshVsix,
  verifyVsix,
  withStableArtifact,
  withStableSidecarSet,
};

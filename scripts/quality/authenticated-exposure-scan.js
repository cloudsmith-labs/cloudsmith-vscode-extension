// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  ROOT,
  removeOutputFile,
  writeJson,
} = require("./common");
const { fingerprint } = require("./evidence");
const { removeExactOwnedDirectoryTree } = require("./non-auth-environment");
const {
  AUTHENTICATED_CANDIDATE_ARTIFACT,
  candidateBindingFromReceipt,
} = require("./candidate-binding");
const {
  GITLEAKS_VERSION,
  assertScannerVersion,
  scanGeneratedEvidence,
  scanVsix,
  scanWithGitleaks,
} = require("./secret-scan");

const AUTHENTICATED_EXPOSURE_RESULT = ".quality/secrets/authenticated-ci.json";
const MAX_RUNTIME_LOG_FILES = 10_000;
const MAX_RUNTIME_LOG_FILE_BYTES = 64 * 1024 * 1024;
const RUNTIME_LOG_COPY_BUFFER_BYTES = 64 * 1024;
const RUNTIME_LOG_READ_FLAGS = fs.constants.O_RDONLY
  | (fs.constants.O_NOFOLLOW || 0)
  | (fs.constants.O_NONBLOCK || 0);
const RUNTIME_LOG_CHANGED_ERROR =
  "Authenticated runtime logs changed during snapshot or scanning.";
const profileBoundaryProofs = new WeakSet();
const PROOF_IDENTITY_KEYS = Object.freeze([
  "changedNanoseconds",
  "device",
  "inode",
  "modifiedNanoseconds",
  "size",
]);
const PROOF_SNAPSHOT_KEYS = Object.freeze([
  "artifactPath",
  "candidateReceiptFingerprint",
  "identity",
  "sourceFingerprint",
  "sourceSha",
  "vsixSha256",
]);

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
  removeExactOwnedDirectoryTree(descriptor.root, {
    allowAdditionalRootEntries: true,
    errorMessage: "Authenticated runtime-log cleanup refused an unsafe or changed tree.",
    expectedRootEntries: [],
    expectedRootIdentity: descriptor,
  });
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

function runtimeLogIdentity(stat) {
  return Object.freeze({
    changedNanoseconds: String(stat.ctimeNs),
    device: String(stat.dev),
    group: String(stat.gid),
    inode: String(stat.ino),
    links: String(stat.nlink),
    mode: String(stat.mode),
    modifiedNanoseconds: String(stat.mtimeNs),
    owner: String(stat.uid),
    size: String(stat.size),
  });
}

function assertSingleLinkRuntimeLogFile(stat) {
  const expected = typeof stat.nlink === "bigint" ? 1n : 1;
  if (stat.isFile() && stat.nlink !== expected) {
    throw new Error("Authenticated runtime log regular files must have exactly one hard link.");
  }
  return stat;
}

function runtimeLogRelativePath(root, target) {
  if (target === root) return ".";
  const relative = path.relative(root, target);
  if (!relative || path.isAbsolute(relative) || relative === ".."
    || relative.startsWith(`..${path.sep}`)) {
    throw new Error("Authenticated runtime log inventory crossed its root.");
  }
  return relative;
}

function runtimeLogTarget(root, relativePath) {
  if (relativePath === ".") return root;
  const target = path.resolve(root, relativePath);
  if (target === root || !target.startsWith(`${root}${path.sep}`)) {
    throw new Error("Authenticated runtime log snapshot path is invalid.");
  }
  return target;
}

function captureRuntimeLogInventory(root) {
  exactPrivateDirectory(root, "Authenticated runtime-log root");
  const pending = [root];
  let fileCount = 0;
  let directoryCount = 1;
  const entries = [Object.freeze({
    path: ".",
    type: "directory",
    identity: runtimeLogIdentity(fs.lstatSync(root, { bigint: true })),
  })];
  while (pending.length > 0) {
    const directory = pending.pop();
    const children = fs.readdirSync(directory, { withFileTypes: true })
      .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
    for (const entry of children) {
      const target = path.join(directory, entry.name);
      const stat = fs.lstatSync(target, { bigint: true });
      if (stat.isSymbolicLink()) {
        throw new Error("Authenticated runtime logs reject symbolic links.");
      }
      let type;
      if (stat.isDirectory()) {
        if (fs.realpathSync(target) !== target) {
          throw new Error("Authenticated runtime log directory is not canonical.");
        }
        type = "directory";
        directoryCount += 1;
        pending.push(target);
      } else if (stat.isFile()) {
        assertSingleLinkRuntimeLogFile(stat);
        type = "file";
        fileCount += 1;
      } else {
        throw new Error("Authenticated runtime logs contain an unsupported entry type.");
      }
      entries.push(Object.freeze({
        path: runtimeLogRelativePath(root, target),
        type,
        identity: runtimeLogIdentity(stat),
      }));
      if (fileCount + directoryCount > MAX_RUNTIME_LOG_FILES) {
        throw new Error("Authenticated runtime log inventory exceeded its structural bound.");
      }
    }
  }
  entries.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  return Object.freeze({
    fileCount,
    directoryCount,
    entries: Object.freeze(entries),
  });
}

function runtimeLogInventory(root) {
  const inventory = captureRuntimeLogInventory(root);
  return Object.freeze({
    fileCount: inventory.fileCount,
    directoryCount: inventory.directoryCount,
  });
}

function sameRuntimeLogInventory(left, right) {
  return left.fileCount === right.fileCount
    && left.directoryCount === right.directoryCount
    && JSON.stringify(left.entries) === JSON.stringify(right.entries);
}

function assertSameRuntimeLogInventory(expected, actual) {
  if (!sameRuntimeLogInventory(expected, actual)) {
    throw new Error("Authenticated runtime logs changed during snapshot or scanning.");
  }
  return actual;
}

function assertRuntimeLogStructure(source, snapshot) {
  const sourceStructure = source.entries.map(entry => [entry.path, entry.type]);
  const snapshotStructure = snapshot.entries.map(entry => [entry.path, entry.type]);
  if (JSON.stringify(sourceStructure) !== JSON.stringify(snapshotStructure)) {
    throw new Error("Authenticated runtime log snapshot structure is incomplete.");
  }
}

function runtimeLogExpectedSize(identity) {
  if (!identity || typeof identity.size !== "string"
    || !/^(?:0|[1-9]\d*)$/u.test(identity.size)) {
    throw new Error(RUNTIME_LOG_CHANGED_ERROR);
  }
  try {
    const size = BigInt(identity.size);
    if (size > BigInt(MAX_RUNTIME_LOG_FILE_BYTES)) {
      throw new Error(RUNTIME_LOG_CHANGED_ERROR);
    }
    return size;
  } catch {
    throw new Error(RUNTIME_LOG_CHANGED_ERROR);
  }
}

function boundedRuntimeLogRead(descriptor, buffer, remaining) {
  const requested = Number(remaining > BigInt(buffer.length)
    ? BigInt(buffer.length)
    : remaining);
  const bytesRead = fs.readSync(descriptor, buffer, 0, requested, null);
  if (!Number.isSafeInteger(bytesRead) || bytesRead <= 0 || bytesRead > requested) {
    throw new Error(RUNTIME_LOG_CHANGED_ERROR);
  }
  return bytesRead;
}

function writeExactRuntimeLogChunk(descriptor, buffer, bytesRead) {
  let written = 0;
  while (written < bytesRead) {
    const bytesWritten = fs.writeSync(
      descriptor,
      buffer,
      written,
      bytesRead - written,
      null,
    );
    if (!Number.isSafeInteger(bytesWritten) || bytesWritten <= 0
      || bytesWritten > bytesRead - written) {
      throw new Error(RUNTIME_LOG_CHANGED_ERROR);
    }
    written += bytesWritten;
  }
}

function assertExactRuntimeLogDescriptor(descriptor, identity) {
  const stat = fs.fstatSync(descriptor, { bigint: true });
  assertSingleLinkRuntimeLogFile(stat);
  if (!stat.isFile() || JSON.stringify(runtimeLogIdentity(stat)) !== JSON.stringify(identity)) {
    throw new Error(RUNTIME_LOG_CHANGED_ERROR);
  }
  return stat;
}

function assertExactRuntimeLogPath(target, identity) {
  let stat;
  let realPath;
  try {
    stat = fs.lstatSync(target, { bigint: true });
    realPath = fs.realpathSync(target);
    assertSingleLinkRuntimeLogFile(stat);
  } catch {
    throw new Error(RUNTIME_LOG_CHANGED_ERROR);
  }
  if (stat.isSymbolicLink() || !stat.isFile() || realPath !== target
    || JSON.stringify(runtimeLogIdentity(stat)) !== JSON.stringify(identity)) {
    throw new Error(RUNTIME_LOG_CHANGED_ERROR);
  }
  return stat;
}

function closeRuntimeLogDescriptors(descriptors) {
  let failed = false;
  for (const descriptor of descriptors) {
    if (descriptor === undefined) continue;
    try {
      fs.closeSync(descriptor);
    } catch {
      failed = true;
    }
  }
  if (failed) throw new Error(RUNTIME_LOG_CHANGED_ERROR);
}

function openExactRuntimeLogFile(target, identity) {
  if (identity?.links !== "1") {
    throw new Error("Authenticated runtime log regular files must have exactly one hard link.");
  }
  let descriptor;
  try {
    assertExactRuntimeLogPath(target, identity);
    descriptor = fs.openSync(target, RUNTIME_LOG_READ_FLAGS);
    assertExactRuntimeLogDescriptor(descriptor, identity);
    assertExactRuntimeLogPath(target, identity);
    return descriptor;
  } catch {
    if (descriptor !== undefined) {
      try {
        fs.closeSync(descriptor);
      } catch {
        // The fixed failure below is intentionally value-blind.
      }
    }
    throw new Error(RUNTIME_LOG_CHANGED_ERROR);
  }
}

function readExactRuntimeLogFile(target, identity) {
  let descriptor;
  let bytes;
  let failed = false;
  try {
    const expectedSize = runtimeLogExpectedSize(identity);
    descriptor = openExactRuntimeLogFile(target, identity);
    bytes = Buffer.alloc(Number(expectedSize));
    let remaining = expectedSize;
    let offset = 0;
    while (remaining > 0n) {
      const windowBytes = Number(remaining > BigInt(RUNTIME_LOG_COPY_BUFFER_BYTES)
        ? BigInt(RUNTIME_LOG_COPY_BUFFER_BYTES)
        : remaining);
      const window = bytes.subarray(offset, offset + windowBytes);
      const bytesRead = boundedRuntimeLogRead(descriptor, window, remaining);
      offset += bytesRead;
      remaining -= BigInt(bytesRead);
    }
    assertExactRuntimeLogDescriptor(descriptor, identity);
    assertExactRuntimeLogPath(target, identity);
  } catch {
    failed = true;
  }
  if (descriptor !== undefined) {
    try {
      fs.closeSync(descriptor);
    } catch {
      failed = true;
    }
  }
  if (failed || !Buffer.isBuffer(bytes)) {
    if (Buffer.isBuffer(bytes)) bytes.fill(0);
    throw new Error(RUNTIME_LOG_CHANGED_ERROR);
  }
  return bytes;
}

function copyExactRuntimeLogFile(source, destination, identity) {
  let sourceDescriptor;
  let destinationDescriptor;
  const buffer = Buffer.alloc(RUNTIME_LOG_COPY_BUFFER_BYTES);
  try {
    const expectedSize = runtimeLogExpectedSize(identity);
    let remaining = expectedSize;
    sourceDescriptor = openExactRuntimeLogFile(source, identity);
    destinationDescriptor = fs.openSync(
      destination,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
      0o600,
    );
    const initialDestinationStat = fs.fstatSync(destinationDescriptor, { bigint: true });
    assertSingleLinkRuntimeLogFile(initialDestinationStat);
    if (!initialDestinationStat.isFile() || initialDestinationStat.size !== 0n) {
      throw new Error(RUNTIME_LOG_CHANGED_ERROR);
    }
    while (remaining > 0n) {
      const bytesRead = boundedRuntimeLogRead(sourceDescriptor, buffer, remaining);
      writeExactRuntimeLogChunk(destinationDescriptor, buffer, bytesRead);
      buffer.fill(0, 0, bytesRead);
      remaining -= BigInt(bytesRead);
    }
    assertExactRuntimeLogDescriptor(sourceDescriptor, identity);
    const finalDestinationStat = fs.fstatSync(destinationDescriptor, { bigint: true });
    assertSingleLinkRuntimeLogFile(finalDestinationStat);
    if (!finalDestinationStat.isFile() || finalDestinationStat.size !== expectedSize) {
      throw new Error(RUNTIME_LOG_CHANGED_ERROR);
    }
    if (process.platform !== "win32") fs.fchmodSync(destinationDescriptor, 0o600);
  } catch {
    throw new Error(RUNTIME_LOG_CHANGED_ERROR);
  } finally {
    buffer.fill(0);
    closeRuntimeLogDescriptors([destinationDescriptor, sourceDescriptor]);
  }
}

function exactRuntimeLogBytes(leftPath, leftIdentity, rightPath, rightIdentity) {
  // Runtime logs can contain credential material. Compare private copies directly;
  // never hash/stringify their bytes or persist either bytes or identity metadata.
  let leftDescriptor;
  let rightDescriptor;
  const leftBuffer = Buffer.alloc(RUNTIME_LOG_COPY_BUFFER_BYTES);
  const rightBuffer = Buffer.alloc(RUNTIME_LOG_COPY_BUFFER_BYTES);
  try {
    const leftSize = runtimeLogExpectedSize(leftIdentity);
    const rightSize = runtimeLogExpectedSize(rightIdentity);
    if (leftSize !== rightSize) throw new Error(RUNTIME_LOG_CHANGED_ERROR);
    let remaining = leftSize;
    leftDescriptor = openExactRuntimeLogFile(leftPath, leftIdentity);
    rightDescriptor = openExactRuntimeLogFile(rightPath, rightIdentity);
    while (remaining > 0n) {
      const leftBytes = boundedRuntimeLogRead(leftDescriptor, leftBuffer, remaining);
      const rightBytes = boundedRuntimeLogRead(rightDescriptor, rightBuffer, remaining);
      if (leftBytes !== rightBytes
        || !leftBuffer.subarray(0, leftBytes).equals(rightBuffer.subarray(0, rightBytes))) {
        throw new Error(RUNTIME_LOG_CHANGED_ERROR);
      }
      leftBuffer.fill(0, 0, leftBytes);
      rightBuffer.fill(0, 0, rightBytes);
      remaining -= BigInt(leftBytes);
    }
    assertExactRuntimeLogDescriptor(leftDescriptor, leftIdentity);
    assertExactRuntimeLogDescriptor(rightDescriptor, rightIdentity);
    return true;
  } catch {
    throw new Error(RUNTIME_LOG_CHANGED_ERROR);
  } finally {
    leftBuffer.fill(0);
    rightBuffer.fill(0);
    closeRuntimeLogDescriptors([rightDescriptor, leftDescriptor]);
  }
}

function assertExactRuntimeLogBytes(sourceRoot, source, snapshotRoot, snapshot) {
  const snapshotByPath = new Map(snapshot.entries.map(entry => [entry.path, entry]));
  for (const sourceEntry of source.entries) {
    if (sourceEntry.type !== "file") continue;
    const snapshotEntry = snapshotByPath.get(sourceEntry.path);
    if (!snapshotEntry || snapshotEntry.type !== "file") {
      throw new Error("Authenticated runtime log snapshot structure is incomplete.");
    }
    exactRuntimeLogBytes(
      runtimeLogTarget(sourceRoot, sourceEntry.path),
      sourceEntry.identity,
      runtimeLogTarget(snapshotRoot, snapshotEntry.path),
      snapshotEntry.identity,
    );
  }
}

function destroyRuntimeLogSnapshot(descriptor) {
  if (!descriptor || typeof descriptor !== "object" || Array.isArray(descriptor)) {
    throw new Error("Authenticated runtime-log snapshot descriptor is invalid.");
  }
  const stat = exactPrivateDirectory(
    descriptor.snapshotRoot,
    "Authenticated runtime-log snapshot root",
  );
  if (stat.dev !== descriptor.dev || stat.ino !== descriptor.ino) {
    throw new Error("Authenticated runtime-log snapshot cleanup refuses a replaced directory.");
  }
  removeExactOwnedDirectoryTree(descriptor.snapshotRoot, {
    allowAdditionalRootEntries: true,
    errorMessage: "Authenticated runtime-log snapshot cleanup refused an unsafe or changed tree.",
    expectedRootEntries: [],
    expectedRootIdentity: descriptor,
  });
  return !fs.existsSync(descriptor.snapshotRoot);
}

function captureRuntimeLogSnapshot(root, options = {}) {
  const source = captureRuntimeLogInventory(root);
  const parent = fs.realpathSync(options.temporaryParent || os.tmpdir());
  exactParentDirectory(parent, "Authenticated runtime-log snapshot parent");
  const snapshotRoot = fs.realpathSync(fs.mkdtempSync(path.join(
    parent,
    "cloudsmith-authenticated-runtime-snapshot-",
  )));
  if (process.platform !== "win32") fs.chmodSync(snapshotRoot, 0o700);
  const rootStat = exactPrivateDirectory(
    snapshotRoot,
    "Authenticated runtime-log snapshot root",
  );
  const ownership = { snapshotRoot, dev: rootStat.dev, ino: rootStat.ino };
  try {
    const directories = source.entries
      .filter(entry => entry.type === "directory" && entry.path !== ".")
      .sort((left, right) => (
        left.path.split(path.sep).length - right.path.split(path.sep).length
        || (left.path < right.path ? -1 : left.path > right.path ? 1 : 0)
      ));
    for (const entry of directories) {
      fs.mkdirSync(runtimeLogTarget(snapshotRoot, entry.path), { mode: 0o700 });
    }
    for (const entry of source.entries) {
      if (entry.type !== "file") continue;
      if (entry.identity.links !== "1") {
        throw new Error("Authenticated runtime log regular files must have exactly one hard link.");
      }
      copyExactRuntimeLogFile(
        runtimeLogTarget(root, entry.path),
        runtimeLogTarget(snapshotRoot, entry.path),
        entry.identity,
      );
    }
    assertSameRuntimeLogInventory(source, captureRuntimeLogInventory(root));
    const snapshot = captureRuntimeLogInventory(snapshotRoot);
    assertRuntimeLogStructure(source, snapshot);
    assertExactRuntimeLogBytes(root, source, snapshotRoot, snapshot);
    assertSameRuntimeLogInventory(source, captureRuntimeLogInventory(root));
    assertSameRuntimeLogInventory(snapshot, captureRuntimeLogInventory(snapshotRoot));
    return Object.freeze({
      ...ownership,
      sourceRoot: root,
      source,
      snapshot,
      fileCount: source.fileCount,
      directoryCount: source.directoryCount,
    });
  } catch (error) {
    try {
      destroyRuntimeLogSnapshot(ownership);
    } catch {
      throw new Error("Authenticated runtime-log snapshot cleanup failed.");
    }
    throw error;
  }
}

function assertStableRuntimeLogSnapshot(descriptor) {
  assertSameRuntimeLogInventory(
    descriptor.source,
    captureRuntimeLogInventory(descriptor.sourceRoot),
  );
  assertSameRuntimeLogInventory(
    descriptor.snapshot,
    captureRuntimeLogInventory(descriptor.snapshotRoot),
  );
  assertExactRuntimeLogBytes(
    descriptor.sourceRoot,
    descriptor.source,
    descriptor.snapshotRoot,
    descriptor.snapshot,
  );
  assertSameRuntimeLogInventory(
    descriptor.source,
    captureRuntimeLogInventory(descriptor.sourceRoot),
  );
  assertSameRuntimeLogInventory(
    descriptor.snapshot,
    captureRuntimeLogInventory(descriptor.snapshotRoot),
  );
  return descriptor;
}

function runtimeLogLogicalPath(relativePath) {
  const logicalPath = relativePath.split(path.sep).join("/");
  if (!logicalPath || logicalPath === "." || path.posix.isAbsolute(logicalPath)
    || logicalPath.split("/").some(segment => !segment || segment === "." || segment === "..")
    || /[\\\u0000-\u001f\u007f]/u.test(logicalPath)) {
    throw new Error(RUNTIME_LOG_CHANGED_ERROR);
  }
  return logicalPath;
}

async function scanRuntimeLogSnapshot(descriptor, scan, options = {}) {
  const findings = [];
  assertStableRuntimeLogSnapshot(descriptor);
  for (const entry of descriptor.snapshot.entries) {
    if (entry.type !== "file") continue;
    let provenBytes;
    let scannerBytes;
    try {
      const logicalPath = runtimeLogLogicalPath(entry.path);
      provenBytes = readExactRuntimeLogFile(
        runtimeLogTarget(descriptor.snapshotRoot, entry.path),
        entry.identity,
      );
      scannerBytes = Buffer.from(provenBytes);
      const result = await scan("stdin", logicalPath, {
        root: options.root,
        label: "authenticated-runtime-logs",
        logicalPath,
        input: scannerBytes,
        execute: options.execute,
        environment: options.environment,
      });
      if (!Array.isArray(result)) throw new Error(RUNTIME_LOG_CHANGED_ERROR);
      findings.push(...result);
    } finally {
      if (Buffer.isBuffer(scannerBytes)) scannerBytes.fill(0);
      if (Buffer.isBuffer(provenBytes)) provenBytes.fill(0);
    }
    assertStableRuntimeLogSnapshot(descriptor);
  }
  return findings;
}

function safeComponent(component) {
  return Object.freeze({
    id: component.id,
    status: component.status,
    fileCount: component.fileCount,
    findingCount: component.findings.length,
  });
}

function exactKeys(value, keys) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).sort().join(",") === [...keys].sort().join(","));
}

function authenticatedProofIdentity(root) {
  const artifactPath = path.join(
    root,
    ...AUTHENTICATED_CANDIDATE_ARTIFACT.split("/"),
  );
  let stat;
  let realPath;
  try {
    stat = fs.lstatSync(artifactPath, { bigint: true });
    realPath = fs.realpathSync(artifactPath);
  } catch {
    throw new Error("Authenticated candidate VSIX proof is missing or unreadable.");
  }
  if (stat.isSymbolicLink() || !stat.isFile() || realPath !== artifactPath) {
    throw new Error("Authenticated candidate VSIX proof must be an exact real file.");
  }
  return Object.freeze({
    device: String(stat.dev),
    inode: String(stat.ino),
    size: String(stat.size),
    modifiedNanoseconds: String(stat.mtimeNs),
    changedNanoseconds: String(stat.ctimeNs),
  });
}

function assertAuthenticatedProofSnapshot(snapshot, candidateReceipt, source) {
  if (!exactKeys(snapshot, PROOF_SNAPSHOT_KEYS)
    || snapshot.artifactPath !== AUTHENTICATED_CANDIDATE_ARTIFACT
    || snapshot.candidateReceiptFingerprint !== candidateReceipt?.fingerprint
    || snapshot.sourceSha !== source?.sha
    || snapshot.sourceFingerprint !== source?.fingerprint
    || snapshot.vsixSha256 !== candidateReceipt?.artifact?.sha256
    || !/^[a-f0-9]{64}$/u.test(snapshot.candidateReceiptFingerprint || "")
    || !/^[a-f0-9]{40,64}$/u.test(snapshot.sourceSha || "")
    || !/^[a-f0-9]{64}$/u.test(snapshot.sourceFingerprint || "")
    || !/^[a-f0-9]{64}$/u.test(snapshot.vsixSha256 || "")
    || !exactKeys(snapshot.identity, PROOF_IDENTITY_KEYS)
    || Object.values(snapshot.identity).some(value => !/^\d+$/u.test(value || ""))
    || snapshot.identity.size !== String(candidateReceipt?.artifact?.archiveBytes)) {
    throw new Error("Authenticated candidate VSIX proof snapshot is invalid or stale.");
  }
  return snapshot;
}

function assertStableAuthenticatedProof(before, after) {
  if (!exactKeys(before, PROOF_SNAPSHOT_KEYS)
    || !exactKeys(after, PROOF_SNAPSHOT_KEYS)
    || PROOF_SNAPSHOT_KEYS.some(key => (
      key === "identity"
        ? JSON.stringify(before.identity) !== JSON.stringify(after.identity)
        : before[key] !== after[key]
    ))) {
    throw new Error(
      "Authenticated candidate VSIX proof identity or bytes changed during scanning.",
    );
  }
  return after;
}

function captureAuthenticatedCandidateProof(root, candidateReceipt, source, options = {}) {
  const before = authenticatedProofIdentity(root);
  const bindCandidate = options.candidateBindingFromReceipt || candidateBindingFromReceipt;
  const binding = bindCandidate(candidateReceipt, {
    root,
    source,
    artifactPath: path.join(root, ...AUTHENTICATED_CANDIDATE_ARTIFACT.split("/")),
  });
  const after = authenticatedProofIdentity(root);
  if (JSON.stringify(before) !== JSON.stringify(after)) {
    throw new Error(
      "Authenticated candidate VSIX proof identity or bytes changed during validation.",
    );
  }
  return assertAuthenticatedProofSnapshot(Object.freeze({
    artifactPath: AUTHENTICATED_CANDIDATE_ARTIFACT,
    candidateReceiptFingerprint: binding.receiptFingerprint,
    sourceFingerprint: binding.sourceFingerprint,
    sourceSha: binding.sourceSha,
    vsixSha256: binding.vsixSha256,
    identity: after,
  }), candidateReceipt, source);
}

function assertExposureReceipt(value) {
  const unsigned = { ...value };
  delete unsigned.fingerprint;
  const exactKeys = [
    "candidateReceiptFingerprint", "components", "credentialBoundary", "findingCount",
    "fingerprint", "scanner", "schemaVersion", "sourceSha", "status", "vsixSha256",
  ];
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join(",") !== exactKeys.sort().join(",")
    || value.schemaVersion !== 2
    || !new Set(["passed", "failed"]).has(value.status)
    || !/^[0-9a-f]{40,64}$/u.test(value.sourceSha || "")
    || !/^[a-f0-9]{64}$/u.test(value.candidateReceiptFingerprint || "")
    || !/^[a-f0-9]{64}$/u.test(value.vsixSha256 || "")
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
    `vsix:${AUTHENTICATED_CANDIDATE_ARTIFACT}`,
    "authenticated-runtime-logs",
    "profile-boundary-metadata-only",
  ];
  const [generated, artifact, runtimeLogs, profile] = receipt.components;
  if (receipt.status !== "passed"
    || receipt.sourceSha !== source?.sha
    || receipt.candidateReceiptFingerprint !== candidateReceipt?.fingerprint
    || receipt.vsixSha256 !== candidateReceipt?.artifact?.sha256
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
  const captureProof = options.captureAuthenticatedCandidateProof
    || captureAuthenticatedCandidateProof;
  assertScanner({
    root,
    execute: options.execute,
    environment: context.environment,
  });
  const profile = consumeProfileMetadataBoundaryProof(
    context.profileBoundaryProof
      || assertProfileMetadataBoundary(context.candidate.profile),
  );
  const runtimeLogs = captureRuntimeLogSnapshot(context.runtimeLogRoot, {
    temporaryParent: options.temporaryParent,
  });
  const persist = options.writeReceipt || (value => writeJson(
    outputPath,
    value,
    root,
    { subtree: ".quality/secrets" },
  ));
  let receipt;
  let persistenceAttempted = false;
  try {
    const generated = scanGenerated(root, ".quality", {
      id: "authenticated-generated-evidence",
      excludedPrefixes: [".quality/secrets"],
      execute: options.execute,
      environment: context.environment,
    });
    const proofBefore = assertAuthenticatedProofSnapshot(
      await captureProof(root, context.candidate.receipt, context.source, {
        candidateBindingFromReceipt: options.candidateBindingFromReceipt,
      }),
      context.candidate.receipt,
      context.source,
    );
    const artifact = await scanArtifact(root, AUTHENTICATED_CANDIDATE_ARTIFACT, {
      execute: options.execute,
      environment: context.environment,
    });
    const proofAfter = await captureProof(
      root,
      context.candidate.receipt,
      context.source,
      { candidateBindingFromReceipt: options.candidateBindingFromReceipt },
    );
    assertAuthenticatedProofSnapshot(
      assertStableAuthenticatedProof(proofBefore, proofAfter),
      context.candidate.receipt,
      context.source,
    );
    const logFindings = runtimeLogs.fileCount === 0 ? []
      : await scanRuntimeLogSnapshot(runtimeLogs, scanLogs, {
        root,
        execute: options.execute,
        environment: context.environment,
      });
    assertStableRuntimeLogSnapshot(runtimeLogs);
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
      schemaVersion: 2,
      status: findingCount === 0 ? "passed" : "failed",
      sourceSha: context.source.sha,
      candidateReceiptFingerprint: context.candidateReceiptFingerprint,
      vsixSha256: proofBefore.vsixSha256,
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
    receipt = validateAuthenticatedExposureProof(
      assertExposureReceipt({ ...base, fingerprint: fingerprint(base) }),
      context.candidate.receipt,
      context.source,
    );
    assertStableRuntimeLogSnapshot(runtimeLogs);
    persistenceAttempted = true;
    await persist(receipt);
    assertStableRuntimeLogSnapshot(runtimeLogs);
    if (!destroyRuntimeLogSnapshot(runtimeLogs)) {
      throw new Error("Authenticated runtime-log snapshot cleanup failed.");
    }
    return Object.freeze(receipt);
  } catch (error) {
    if (persistenceAttempted) {
      try {
        removeOutputFile(outputPath, root, { subtree: ".quality/secrets" });
      } catch {
        throw new Error("Authenticated exposure receipt cleanup failed.");
      }
    }
    throw error;
  } finally {
    if (fs.existsSync(runtimeLogs.snapshotRoot)) {
      destroyRuntimeLogSnapshot(runtimeLogs);
    }
  }
}

module.exports = {
  AUTHENTICATED_EXPOSURE_RESULT,
  assertAuthenticatedProofSnapshot,
  assertExposureReceipt,
  assertProfileMetadataBoundary,
  assertStableAuthenticatedProof,
  captureAuthenticatedCandidateProof,
  createRuntimeLogRoot,
  destroyRuntimeLogRoot,
  runAuthenticatedExposureScan,
  runtimeLogInventory,
  validateAuthenticatedExposureProof,
};

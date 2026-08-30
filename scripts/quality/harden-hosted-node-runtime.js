// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const {
  assertCanonicalNpmRuntime,
  assertCanonicalNodeRuntime,
  assertExactNodeExecutable,
} = require("./canonical-node-runtime");
const { withStableSingleLinkFile } = require("./candidate-binding");

const HARDENING_ERROR = "Hosted Node.js runtime hardening refused an unsafe or changed tree";
const MAX_NPM_ENTRIES = 5000;
const MAX_NODE_BYTES = 256 * 1024 * 1024;

function fail() {
  throw new Error(HARDENING_ERROR);
}

function exactAbsolutePath(value) {
  if (typeof value !== "string" || !path.isAbsolute(value)
    || path.resolve(value) !== value || path.normalize(value) !== value
    || /[\u0000-\u001f\u007f]/u.test(value)) {
    fail();
  }
  return value;
}

function invariantIdentity(stat, kind) {
  return Object.freeze({
    dev: String(stat.dev),
    gid: String(stat.gid),
    ino: String(stat.ino),
    kind,
    modifiedNanoseconds: String(stat.mtimeNs),
    nlink: String(stat.nlink),
    size: String(stat.size),
    uid: String(stat.uid),
  });
}

function sameIdentity(left, right) {
  return left && right && Object.keys(left).every(key => left[key] === right[key]);
}

function stableFileDigest(target, identity, fileSystem) {
  let descriptor = fileSystem.openSync(
    target,
    fileSystem.constants.O_RDONLY | (fileSystem.constants.O_NOFOLLOW || 0),
  );
  let bytes;
  try {
    const opened = fileSystem.fstatSync(descriptor, { bigint: true });
    if (!sameIdentity(identity, invariantIdentity(opened, "file"))
      || opened.size < 1n || opened.size > BigInt(MAX_NODE_BYTES)) {
      fail();
    }
    bytes = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fileSystem.readSync(
        descriptor,
        bytes,
        offset,
        Math.min(1024 * 1024, bytes.length - offset),
        offset,
      );
      if (!Number.isSafeInteger(count) || count <= 0) fail();
      offset += count;
    }
    const descriptorAfter = fileSystem.fstatSync(descriptor, { bigint: true });
    if (!sameIdentity(identity, invariantIdentity(descriptorAfter, "file"))) {
      fail();
    }
    const sha256 = crypto.createHash("sha256").update(bytes).digest("hex");
    fileSystem.closeSync(descriptor);
    descriptor = null;
    const pathAfter = fileSystem.lstatSync(target, { bigint: true });
    if (!sameIdentity(identity, invariantIdentity(pathAfter, "file"))
      || fileSystem.realpathSync(target) !== target) {
      fail();
    }
    const finalPathStat = fileSystem.lstatSync(target, { bigint: true });
    if (!sameIdentity(identity, invariantIdentity(finalPathStat, "file"))) fail();
    return sha256;
  } finally {
    if (bytes) bytes.fill(0);
    if (descriptor !== null) fileSystem.closeSync(descriptor);
  }
}

function snapshotEntry(target, fileSystem, state, recursive = true, digest = false) {
  if (state.entries >= MAX_NPM_ENTRIES) fail();
  state.entries += 1;
  const stat = fileSystem.lstatSync(target, { bigint: true });
  const kind = stat.isDirectory() ? "directory" : stat.isFile() ? "file" : null;
  if (!kind || stat.isSymbolicLink() || stat.nlink < 1n
    || fileSystem.realpathSync(target) !== target) {
    fail();
  }
  const record = {
    identity: invariantIdentity(stat, kind),
    kind,
    target,
  };
  if (digest) {
    if (kind !== "file") fail();
    record.sha256 = stableFileDigest(target, record.identity, fileSystem);
  }
  if (kind === "directory" && recursive) {
    const names = fileSystem.readdirSync(target).sort();
    if (names.length !== new Set(names).size) fail();
    record.children = names.map(name => {
      if (typeof name !== "string" || name.length === 0 || name === "." || name === ".."
        || /[\/\\\u0000-\u001f\u007f]/u.test(name)) {
        fail();
      }
      return snapshotEntry(path.join(target, name), fileSystem, state, true);
    });
    if (JSON.stringify(names) !== JSON.stringify(fileSystem.readdirSync(target).sort())
      || !sameIdentity(record.identity, invariantIdentity(
        fileSystem.lstatSync(target, { bigint: true }),
        kind,
      ))) {
      fail();
    }
  }
  return Object.freeze(record);
}

function snapshotSelectedTree(distributionRoot, fileSystem) {
  const bin = path.join(distributionRoot, "bin");
  const lib = path.join(distributionRoot, "lib");
  const nodeModules = path.join(lib, "node_modules");
  const npmRoot = path.join(nodeModules, "npm");
  const state = { entries: 0 };
  return Object.freeze([
    snapshotEntry(distributionRoot, fileSystem, state, false),
    snapshotEntry(bin, fileSystem, state, false),
    snapshotEntry(path.join(bin, "node"), fileSystem, state, false, true),
    snapshotEntry(lib, fileSystem, state, false),
    snapshotEntry(nodeModules, fileSystem, state, false),
    snapshotEntry(npmRoot, fileSystem, state, true),
  ]);
}

function flattenSelectedSnapshot(snapshot) {
  const records = new Map();
  const visit = node => {
    const prior = records.get(node.target);
    if (prior && !sameIdentity(prior.identity, node.identity)) fail();
    records.set(node.target, node);
    for (const child of node.children || []) visit(child);
  };
  for (const node of snapshot) visit(node);
  return records;
}

function hardenEntry(node, fileSystem) {
  const flags = fileSystem.constants.O_RDONLY
    | (fileSystem.constants.O_NOFOLLOW || 0)
    | (node.kind === "directory" ? (fileSystem.constants.O_DIRECTORY || 0) : 0);
  const descriptor = fileSystem.openSync(node.target, flags);
  try {
    const before = fileSystem.fstatSync(descriptor, { bigint: true });
    if (!sameIdentity(node.identity, invariantIdentity(before, node.kind))) fail();
    const safeMode = Number(before.mode & ~0o022n);
    fileSystem.fchmodSync(descriptor, safeMode);
    const after = fileSystem.fstatSync(descriptor, { bigint: true });
    const current = fileSystem.lstatSync(node.target, { bigint: true });
    if ((after.mode & 0o022n) !== 0n || (current.mode & 0o022n) !== 0n
      || !sameIdentity(node.identity, invariantIdentity(after, node.kind))
      || !sameIdentity(node.identity, invariantIdentity(current, node.kind))
      || fileSystem.realpathSync(node.target) !== node.target) {
      fail();
    }
  } finally {
    fileSystem.closeSync(descriptor);
  }
}

function hardenHostedNodeRuntime(options = {}) {
  const fileSystem = options.fileSystem || fs;
  const repositoryRoot = exactAbsolutePath(options.repositoryRoot || path.resolve(__dirname, "../.."));
  const toolCache = exactAbsolutePath(options.toolCache || process.env.RUNNER_TOOL_CACHE);
  const nodeExecutable = exactAbsolutePath(options.nodeExecutable || process.execPath);
  const currentVersion = options.currentVersion || process.version;
  const architecture = options.architecture || process.arch;
  const version = withStableSingleLinkFile(
    path.join(repositoryRoot, ".node-version"),
    {
      errorMessage: HARDENING_ERROR,
      fileSystem,
      maximumBytes: 64,
      minimumBytes: 1,
    },
    bytes => {
      const match = /^(\d+\.\d+\.\d+)(?:\r?\n)?$/u.exec(bytes.toString("utf8"));
      if (!match) fail();
      return match[1];
    },
  );
  const realToolCache = exactAbsolutePath(fileSystem.realpathSync(toolCache));
  if (realToolCache !== toolCache || currentVersion !== `v${version}`) fail();
  const distributionRoot = path.join(realToolCache, "node", version, architecture);
  if (fileSystem.realpathSync(distributionRoot) !== distributionRoot
    || fileSystem.realpathSync(nodeExecutable) !== path.join(distributionRoot, "bin", "node")) {
    fail();
  }

  const before = flattenSelectedSnapshot(snapshotSelectedTree(distributionRoot, fileSystem));
  const initialNode = before.get(nodeExecutable);
  if (!initialNode?.sha256) fail();
  const ordered = [...before.values()].sort((left, right) => (
    right.target.split(path.sep).length - left.target.split(path.sep).length
      || left.target.localeCompare(right.target)
  ));
  for (const node of ordered) hardenEntry(node, fileSystem);
  const after = flattenSelectedSnapshot(snapshotSelectedTree(distributionRoot, fileSystem));
  if (before.size !== after.size || [...before].some(([target, node]) => (
    !after.has(target) || !sameIdentity(node.identity, after.get(target).identity)
      || node.sha256 !== after.get(target).sha256
  ))) {
    fail();
  }

  assertCanonicalNodeRuntime(repositoryRoot, currentVersion);
  assertExactNodeExecutable(nodeExecutable, { fileSystem, platform: "linux" });
  assertCanonicalNpmRuntime(repositoryRoot, undefined, {
    fileSystem,
    nodeExecutable,
    platform: "linux",
  });
  if (stableFileDigest(nodeExecutable, initialNode.identity, fileSystem)
    !== initialNode.sha256) {
    fail();
  }
  return Object.freeze({ architecture, nodeExecutable, version });
}

if (require.main === module) {
  try {
    if (process.platform !== "linux" || process.env.GITHUB_ACTIONS !== "true"
      || process.env.RUNNER_OS !== "Linux") {
      fail();
    }
    const result = hardenHostedNodeRuntime();
    console.log(`Hardened exact hosted Node.js ${result.version} runtime for ${result.architecture}.`);
  } catch {
    console.error(HARDENING_ERROR);
    process.exit(1);
  }
}

module.exports = { HARDENING_ERROR, hardenHostedNodeRuntime };

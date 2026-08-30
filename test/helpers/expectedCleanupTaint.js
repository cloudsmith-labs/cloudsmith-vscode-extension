// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  NON_AUTH_CLEANUP_TAINT_ENV,
  expectedExactCleanupTreeEntry,
  removeExactOwnedDirectoryTree,
} = require("../../scripts/quality/non-auth-environment");

const SINK_PREFIX = "cloudsmith-non-auth-test-sink-";
const SINK_RECEIPT = ".cloudsmith-non-auth-cleanup-taint";
const SINK_ERROR = "Expected cleanup taint sink is unsafe or invalid.";
const SINK_CLEANUP_ERROR = "Expected cleanup taint sink cleanup refused an unsafe tree.";
const STABLE_RECEIPT_IDENTITY_KEYS = Object.freeze([
  "device",
  "group",
  "inode",
  "links",
  "mode",
  "owner",
]);

let activeScope = false;

function exactRootIdentity(stat) {
  return Object.freeze({
    dev: String(stat.dev),
    ino: String(stat.ino),
  });
}

function exactReceiptIdentity(stat) {
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

function assertPrivateDirectory(directory, expectedIdentity = null) {
  const stat = fs.lstatSync(directory, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()
    || fs.realpathSync(directory) !== directory
    || (process.platform !== "win32" && (stat.mode & 0o077n) !== 0n)
    || (typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid()))
    || (expectedIdentity && (String(stat.dev) !== expectedIdentity.dev
      || String(stat.ino) !== expectedIdentity.ino))) {
    throw new Error(SINK_ERROR);
  }
  return stat;
}

function assertPrivateReceipt(receipt, expectedIdentity = null) {
  const stat = fs.lstatSync(receipt, { bigint: true });
  const identity = exactReceiptIdentity(stat);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n
    || fs.realpathSync(receipt) !== receipt
    || (process.platform !== "win32" && (stat.mode & 0o077n) !== 0n)
    || (typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid()))
    || (expectedIdentity && STABLE_RECEIPT_IDENTITY_KEYS.some(
      key => identity[key] !== expectedIdentity[key],
    ))) {
    throw new Error(SINK_ERROR);
  }
  return Object.freeze({ identity, stat });
}

function canonicalTemporaryParent(value) {
  const selected = value === undefined ? os.tmpdir() : value;
  if (typeof selected !== "string" || !path.isAbsolute(selected)
    || path.normalize(selected) !== selected || path.resolve(selected) !== selected
    || selected.includes("\u0000")) {
    throw new Error(SINK_ERROR);
  }
  const parent = fs.realpathSync(selected);
  const stat = fs.lstatSync(parent);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(SINK_ERROR);
  return parent;
}

function createSink(options) {
  const parent = canonicalTemporaryParent(options.temporaryParent);
  let root = null;
  let rootIdentity = null;
  let initialReceiptEntry = null;
  try {
    root = fs.realpathSync(fs.mkdtempSync(path.join(parent, SINK_PREFIX)));
    if (path.dirname(root) !== parent || !path.basename(root).startsWith(SINK_PREFIX)) {
      throw new Error(SINK_ERROR);
    }
    if (process.platform !== "win32") fs.chmodSync(root, 0o700);
    const rootStat = assertPrivateDirectory(root);
    rootIdentity = exactRootIdentity(rootStat);

    const receipt = path.join(root, SINK_RECEIPT);
    fs.writeFileSync(receipt, "", { encoding: "utf8", flag: "wx", mode: 0o600 });
    if (process.platform !== "win32") fs.chmodSync(receipt, 0o600);
    const receiptState = assertPrivateReceipt(receipt);
    if (receiptState.stat.size !== 0n) throw new Error(SINK_ERROR);
    initialReceiptEntry = expectedExactCleanupTreeEntry(receipt, {
      errorMessage: SINK_CLEANUP_ERROR,
    });
    const capability = JSON.stringify({
      schemaVersion: 1,
      path: receipt,
      identity: receiptState.identity,
    });
    if (capability.length < 1 || capability.length > 4096) throw new Error(SINK_ERROR);
    return Object.freeze({
      capability,
      initialReceiptEntry,
      initialReceiptIdentity: receiptState.identity,
      receipt,
      root,
      rootIdentity,
    });
  } catch (error) {
    if (root && rootIdentity) {
      try {
        removeExactOwnedDirectoryTree(root, {
          errorMessage: SINK_CLEANUP_ERROR,
          expectedRootEntries: initialReceiptEntry ? [initialReceiptEntry] : [],
          expectedRootIdentity: rootIdentity,
        });
      } catch {
        // The original creation failure remains authoritative, and an unsafe
        // partial sink is preserved rather than adopted for cleanup.
      }
    }
    throw error;
  }
}

function restoreInheritedCapability(saved) {
  if (saved.present) {
    process.env[NON_AUTH_CLEANUP_TAINT_ENV] = saved.value;
    if (process.env[NON_AUTH_CLEANUP_TAINT_ENV] !== saved.value) {
      throw new Error(SINK_ERROR);
    }
    return;
  }
  delete process.env[NON_AUTH_CLEANUP_TAINT_ENV];
  if (Object.prototype.hasOwnProperty.call(process.env, NON_AUTH_CLEANUP_TAINT_ENV)) {
    throw new Error(SINK_ERROR);
  }
}

function inspectLatchedSink(sink) {
  assertPrivateDirectory(sink.root, sink.rootIdentity);
  if (JSON.stringify(fs.readdirSync(sink.root).sort()) !== JSON.stringify([SINK_RECEIPT])) {
    throw new Error(SINK_ERROR);
  }
  const receiptState = assertPrivateReceipt(sink.receipt, sink.initialReceiptIdentity);
  if (receiptState.stat.size !== 1n) {
    if (receiptState.stat.size === 0n
      && Object.keys(sink.initialReceiptIdentity).every(
        key => receiptState.identity[key] === sink.initialReceiptIdentity[key],
      )) {
      return Object.freeze({ entry: sink.initialReceiptEntry, latched: false });
    }
    throw new Error(SINK_ERROR);
  }
  return Object.freeze({
    entry: expectedExactCleanupTreeEntry(sink.receipt, {
      errorMessage: SINK_CLEANUP_ERROR,
    }),
    latched: true,
  });
}

function cleanupSink(sink, expectedReceiptEntry) {
  removeExactOwnedDirectoryTree(sink.root, {
    errorMessage: SINK_CLEANUP_ERROR,
    expectedRootEntries: [expectedReceiptEntry],
    expectedRootIdentity: sink.rootIdentity,
  });
}

function throwScopeErrors(errors) {
  if (errors.length === 1) throw errors[0];
  if (errors.length > 1) {
    throw new AggregateError(errors, "Expected cleanup taint scope failed.");
  }
}

function finishScope(sink, saved, callbackState, result) {
  const errors = [];
  if (callbackState.failed) errors.push(callbackState.error);
  let restored = false;
  try {
    restoreInheritedCapability(saved);
    restored = true;
  } catch (error) {
    errors.push(error);
  }

  let expectedReceiptEntry = sink.initialReceiptEntry;
  try {
    const state = inspectLatchedSink(sink);
    expectedReceiptEntry = state.entry;
    if (!state.latched) {
      errors.push(new Error("Expected cleanup taint sink was not latched."));
    }
  } catch (error) {
    errors.push(error);
  }

  if (restored) {
    try {
      cleanupSink(sink, expectedReceiptEntry);
    } catch (error) {
      errors.push(error);
    }
  }
  activeScope = false;
  throwScopeErrors(errors);
  return result;
}

function abortScopeBeforeCallback(sink, saved, originalError) {
  const errors = [originalError];
  let restored = false;
  try {
    restoreInheritedCapability(saved);
    restored = true;
  } catch (error) {
    errors.push(error);
  }
  if (restored) {
    try {
      cleanupSink(sink, sink.initialReceiptEntry);
    } catch (error) {
      errors.push(error);
    }
  }
  activeScope = false;
  throwScopeErrors(errors);
}

function withExpectedCleanupTaint(callback, options = {}) {
  if (typeof callback !== "function") {
    throw new TypeError("Expected cleanup taint scope requires a callback.");
  }
  if (!options || typeof options !== "object" || Array.isArray(options)
    || Object.keys(options).some(key => key !== "temporaryParent")) {
    throw new TypeError("Expected cleanup taint scope options are invalid.");
  }
  if (activeScope) throw new Error("Expected cleanup taint scope is already active.");
  activeScope = true;

  let sink;
  try {
    sink = createSink(options);
  } catch (error) {
    activeScope = false;
    throw error;
  }
  const saved = Object.freeze({
    present: Object.prototype.hasOwnProperty.call(process.env, NON_AUTH_CLEANUP_TAINT_ENV),
    value: process.env[NON_AUTH_CLEANUP_TAINT_ENV],
  });
  try {
    process.env[NON_AUTH_CLEANUP_TAINT_ENV] = sink.capability;
    if (process.env[NON_AUTH_CLEANUP_TAINT_ENV] !== sink.capability) {
      throw new Error(SINK_ERROR);
    }
  } catch (error) {
    return abortScopeBeforeCallback(sink, saved, error);
  }

  let result;
  try {
    result = callback(Object.freeze({ receipt: sink.receipt, root: sink.root }));
  } catch (error) {
    return finishScope(sink, saved, { error, failed: true });
  }
  let then;
  try {
    then = result === null || result === undefined ? null : result.then;
  } catch (error) {
    return finishScope(sink, saved, { error, failed: true });
  }
  if (typeof then === "function") {
    let promise;
    try {
      promise = Promise.resolve(result);
    } catch (error) {
      return finishScope(sink, saved, { error, failed: true });
    }
    return promise.then(
      value => finishScope(sink, saved, { error: null, failed: false }, value),
      error => finishScope(sink, saved, { error, failed: true }),
    );
  }
  return finishScope(sink, saved, { error: null, failed: false }, result);
}

module.exports = {
  withExpectedCleanupTaint,
};

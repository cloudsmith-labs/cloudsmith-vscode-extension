// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { exactPackageIdentity } = require("../domain/package");
const { fromRecentPackageRecord } = require("../domain/packageAdapters");

const MAX_RECENT = 10;
const recent = [];

/**
 * Store one exact immutable package. Invalid or coordinate-only selections are
 * ignored so they cannot evict an existing trusted identity.
 *
 * @param {object} value Canonical package or supported legacy package selection.
 */
function add(value) {
  let pkg;
  try {
    pkg = fromRecentPackageRecord(value);
  } catch {
    return;
  }
  const identity = exactPackageIdentity(pkg);
  for (let index = recent.length - 1; index >= 0; index -= 1) {
    if (exactPackageIdentity(recent[index]) === identity) {
      if (!sameCoreSignature(recent[index], pkg)) return;
      recent.splice(index, 1);
    }
  }
  recent.unshift(pkg);
  if (recent.length > MAX_RECENT) recent.length = MAX_RECENT;
}

function sameCoreSignature(left, right) {
  return left.name === right.name
    && left.version === right.version
    && left.format === right.format;
}

/** Return an immutable most-recent-first snapshot of exact package values. */
function getAll() {
  return Object.freeze(recent.slice());
}

function clear() {
  recent.length = 0;
}

module.exports = { add, clear, getAll };

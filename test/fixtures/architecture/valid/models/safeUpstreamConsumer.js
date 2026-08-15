// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const {
  isSafeInventoryUpstream,
  sanitizeSafeInventoryUpstream,
} = require("../util/upstreamChecker");

class UpstreamChecker {}

const unrelatedLocalChecker = new UpstreamChecker();

function sanitizeInventory(value) {
  if (!isSafeInventoryUpstream(value)) return undefined;
  return sanitizeSafeInventoryUpstream(value);
}

module.exports = { sanitizeInventory, unrelatedLocalChecker };

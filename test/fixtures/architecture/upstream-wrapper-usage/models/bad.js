// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const {
  getAllUpstreamData: acquireUpstream,
} = require("../util/upstreamChecker");

function loadInventory() {
  return acquireUpstream();
}

module.exports = { loadInventory };

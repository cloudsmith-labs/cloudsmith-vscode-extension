// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const checkerModule = require("./upstreamChecker");

function createChecker() {
  return new checkerModule.UpstreamChecker();
}

module.exports = { checkerModule, createChecker };

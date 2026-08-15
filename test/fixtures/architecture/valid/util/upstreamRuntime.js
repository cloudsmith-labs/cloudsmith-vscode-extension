// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { UpstreamChecker } = require("./upstreamChecker");

class UpstreamRuntime {
  constructor() {
    this.checker = new UpstreamChecker();
  }

  dispose() {}
}

module.exports = { UpstreamRuntime };

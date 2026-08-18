// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { createChecker } = require("./hiddenCheckerFactory");
const { UpstreamChecker } = require("./upstreamChecker");

class UpstreamRuntime {
  constructor() {
    this.checker = createChecker();
  }
}

module.exports = { UpstreamChecker, UpstreamRuntime };

// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { registerCommands } = require("./registrar");
const { UpstreamChecker: Checker } = require("../util/upstreamChecker");

function registerGeneralCommands({ registerCommand }) {
  return registerCommands(registerCommand, [
    ["cloudsmith-vsc.valid", () => new Checker()],
  ]);
}

module.exports = { registerGeneralCommands };

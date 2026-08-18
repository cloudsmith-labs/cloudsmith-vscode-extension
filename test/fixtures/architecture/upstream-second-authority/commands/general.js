// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { registerCommands } = require("./registrar");
const { UpstreamRuntime: Runtime } = require("../util/upstreamRuntime");

function registerGeneralCommands({ registerCommand }) {
  return registerCommands(registerCommand, [
    ["cloudsmith-vsc.valid", () => new Runtime()],
  ]);
}

module.exports = { registerGeneralCommands };

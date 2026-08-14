// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { registerCommands } = require("./registrar");

function registerGeneralCommands({ registerCommand }) {
  return registerCommands(registerCommand, [
    ["cloudsmith-vsc.valid", () => undefined],
  ]);
}

module.exports = { registerGeneralCommands };

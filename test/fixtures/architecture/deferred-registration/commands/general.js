// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { registerCommands } = require("./registrar");
function registerGeneralCommands({ registerCommand }) {
  const commands = registerCommands(registerCommand, [
    ["cloudsmith-vsc.valid", () => undefined],
  ]);
  queueMicrotask(() => registerCommand("cloudsmith-vsc.hidden", () => undefined));
  return commands;
}
module.exports = { registerGeneralCommands };

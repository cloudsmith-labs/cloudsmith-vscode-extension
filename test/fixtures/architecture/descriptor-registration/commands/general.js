// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { registerCommands } = require("./registrar");

function registerGeneralCommands(deps) {
  const { registerCommand } = deps;
  const commands = registerCommands(registerCommand, [
    ["cloudsmith-vsc.valid", () => undefined],
  ]);
  if (Object.keys(deps).length > 0) {
    const name = "register" + "Command";
    Object.getOwnPropertyDescriptor(deps, name).value(
      "cloudsmith-vsc.hidden",
      () => undefined
    );
  }
  return commands;
}

module.exports = { registerGeneralCommands };

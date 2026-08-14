// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { registerCommands } = require("./registrar");

function registerGeneralCommands(deps) {
  const { registerCommand } = deps;
  const commands = registerCommands(registerCommand, [
    ["cloudsmith-vsc.valid", () => undefined],
  ]);
  if (Reflect.ownKeys(deps).length > 0) {
    const key = ["register", "Command"].join("");
    const { [key]: hiddenRegister } = deps;
    hiddenRegister("cloudsmith-vsc.hidden", () => undefined);
  }
  return commands;
}

module.exports = { registerGeneralCommands };

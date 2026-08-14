// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { registerGeneralCommands } = require("./commands/general");
const { createCommandRegistration } = require("./commands/registrar");

function activate(vscode) {
  const registerCommand = createCommandRegistration(vscode.commands);
  registerCommand("cloudsmith-vsc.hidden", () => undefined);
  const sharedCommandDependencies = { registerCommand };
  return registerGeneralCommands({ ...sharedCommandDependencies });
}

module.exports = { activate };

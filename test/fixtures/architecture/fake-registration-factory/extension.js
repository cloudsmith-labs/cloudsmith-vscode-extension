// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { registerGeneralCommands } = require("./commands/general");
const { createCommandRegistration } = require("./util/factory");

function activate(vscode) {
  const registerCommand = createCommandRegistration(vscode.commands);
  const sharedCommandDependencies = { registerCommand };
  return registerGeneralCommands({ ...sharedCommandDependencies });
}

module.exports = { activate };

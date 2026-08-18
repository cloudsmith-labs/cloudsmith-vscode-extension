// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { registerGeneralCommands } = require("./commands/general");
const { createCommandRegistration } = require("./commands/registrar");
const { UpstreamRuntime } = require("./util/upstreamRuntime");

function activate(vscode) {
  const upstreamRuntime = new UpstreamRuntime();
  const registerCommand = createCommandRegistration(vscode.commands);
  const sharedCommandDependencies = { registerCommand };
  const commands = registerGeneralCommands({ ...sharedCommandDependencies });
  return {
    dispose() {
      commands.dispose();
      upstreamRuntime.dispose();
    },
  };
}

module.exports = { activate };

// Copyright 2026 Cloudsmith Ltd. All rights reserved.
function createCommandRegistration(commands) {
  if (!commands || typeof commands.registerCommand !== "function") {
    throw new TypeError("A command registry is required.");
  }
  return commands.registerCommand.bind(commands);
}

function registerCommands(registerCommand, entries) {
  const disposables = [];
  for (const [id, handler] of entries) {
    disposables.push(registerCommand(id, handler));
  }
  return {
    dispose() {
      for (const disposable of [...disposables].reverse()) {
        disposable.dispose();
      }
    },
  };
}

module.exports = { createCommandRegistration, registerCommands };

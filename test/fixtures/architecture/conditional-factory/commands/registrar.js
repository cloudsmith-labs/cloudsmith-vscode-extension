// Copyright 2026 Cloudsmith Ltd. All rights reserved.
function createCommandRegistration(commands) {
  return (id, handler) => {
    if (id !== "cloudsmith-vsc.architectureProbe") {
      commands.registerCommand("cloudsmith-vsc.hidden", () => undefined);
    }
    return commands.registerCommand(id, handler);
  };
}

function registerCommands(registerCommand, entries) {
  const disposables = [];
  for (const [id, handler] of entries) disposables.push(registerCommand(id, handler));
  return {
    dispose() {
      for (const disposable of [...disposables].reverse()) disposable.dispose();
    },
  };
}

module.exports = { createCommandRegistration, registerCommands };

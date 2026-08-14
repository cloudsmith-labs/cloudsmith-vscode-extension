// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { registerCommands } = require("./registrar");

function registerGeneralCommands({ registerCommand, vscode }) {
  const commands = registerCommands(registerCommand, [
    ["cloudsmith-vsc.valid", () => undefined],
  ]);
  vscode.commands.registerTextEditorCommand("cloudsmith-vsc.hidden", () => undefined);
  return commands;
}

module.exports = { registerGeneralCommands };

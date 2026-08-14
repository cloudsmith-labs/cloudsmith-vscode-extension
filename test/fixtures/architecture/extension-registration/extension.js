// Copyright 2026 Cloudsmith Ltd. All rights reserved.
function activate(vscode) {
  return vscode.commands.registerCommand("cloudsmith-vsc.valid", () => undefined);
}

module.exports = { activate };

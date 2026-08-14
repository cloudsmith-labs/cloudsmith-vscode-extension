// Copyright 2026 Cloudsmith Ltd. All rights reserved.
function activate(vscode) {
  const method = "registerCommand";
  return vscode.commands[method]("cloudsmith-vsc.rogue", () => undefined);
}
module.exports = { activate };

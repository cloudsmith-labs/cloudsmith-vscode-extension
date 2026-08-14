// Copyright 2026 Cloudsmith Ltd. All rights reserved.
function activate(vscode) {
  const method = ["register", "Command"].join("");
  return vscode.commands[method]("cloudsmith-vsc.rogue", () => undefined);
}
module.exports = { activate };

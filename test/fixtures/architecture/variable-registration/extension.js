// Copyright 2026 Cloudsmith Ltd. All rights reserved.
function activate(vscode) {
  const first = "register";
  const method = `${first}Command`;
  return vscode.commands[method]("cloudsmith-vsc.rogue", () => undefined);
}
module.exports = { activate };

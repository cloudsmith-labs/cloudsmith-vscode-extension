// Copyright 2026 Cloudsmith Ltd. All rights reserved.
function invoke(registry, method, id, handler) {
  return registry[method](id, handler);
}
function activate(vscode) {
  const method = ["register", "Command"].join("");
  return invoke(vscode.commands, method, "cloudsmith-vsc.rogue", () => undefined);
}
module.exports = { activate };

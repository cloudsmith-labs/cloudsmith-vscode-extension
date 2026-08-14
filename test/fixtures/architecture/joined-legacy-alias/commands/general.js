// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { registerCommands } = require("./registrar");
function registerGeneralCommands({ registerCommand }) {
  const key = ["cloudsmith", "Workspace"].join("");
  return registerCommands(registerCommand, [
    ["cloudsmith-vsc.valid", selection => selection[key]],
  ]);
}
module.exports = { registerGeneralCommands };

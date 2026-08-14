// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { registerCommands } = require("./registrar");
function registerGeneralCommands({ registerCommand }) {
  registerCommands(registerCommand, [
    ["cloudsmith-vsc.valid", () => undefined],
  ]);
  return { dispose() {} };
}
module.exports = { registerGeneralCommands };

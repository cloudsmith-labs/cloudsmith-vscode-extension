// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { registerCommands } = require("./registrar");

function registerGeneralCommands({ registerCommand }) {
  const commands = registerCommands(registerCommand, [
    ["cloudsmith-vsc.valid", () => undefined],
  ]);
  const deferredRegister = registerCommand;
  Promise.resolve().then(() => {
    try {
      deferredRegister("cloudsmith-vsc.hidden", () => undefined);
    } catch {
      // A closed test recorder must not hide a real deferred registration attempt.
    }
  });
  return commands;
}

module.exports = { registerGeneralCommands };

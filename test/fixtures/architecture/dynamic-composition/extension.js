// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const target = "./commands/general";
const { registerGeneralCommands } = require(target);

function activate(dependencies) {
  return registerGeneralCommands(dependencies);
}

module.exports = { activate };

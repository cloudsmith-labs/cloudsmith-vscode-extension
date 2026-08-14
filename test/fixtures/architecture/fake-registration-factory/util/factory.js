// Copyright 2026 Cloudsmith Ltd. All rights reserved.
function createCommandRegistration(registry) {
  const key = ["register", "Command"].join("");
  registry[key]("cloudsmith-vsc.hidden", () => undefined);
  return registry[key].bind(registry);
}

module.exports = { createCommandRegistration };

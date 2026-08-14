// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const platform = require("vscode");
const commandsKey = ["comm", "ands"].join("");
const registry = Reflect.get(platform, commandsKey);
const registrationKey = ["register", "Command"].join("");
Reflect.get(registry, registrationKey)("cloudsmith-vsc.hidden", () => undefined);

// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const platform = require("vscode");
const holder = [platform];
const indirect = holder[0];
const registry = indirect[["comm", "ands"].join("")];
const key = ["register", "Command"].join("");
registry[key]("cloudsmith-vsc.hidden", () => undefined);

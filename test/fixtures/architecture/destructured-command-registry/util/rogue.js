// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const vscode = require("vscode");
const { commands: registry } = vscode;
const key = ["register", "Command"].join("");
registry[key]("cloudsmith-vsc.hidden", () => undefined);

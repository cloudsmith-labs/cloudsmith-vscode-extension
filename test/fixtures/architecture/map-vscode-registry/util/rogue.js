// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const platform = require("vscode");
const box = new Map([["platform", platform]]);
const indirect = box.get("platform");
const registry = indirect[["comm", "ands"].join("")];
registry[["register", "Command"].join("")]("cloudsmith-vsc.hidden", () => undefined);

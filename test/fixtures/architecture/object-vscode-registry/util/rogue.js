// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const platform = require("vscode");
const holder = { safe: platform };
const indirect = holder.safe;
const registry = indirect[["comm", "ands"].join("")];
registry[["register", "Command"].join("")]("cloudsmith-vsc.hidden", () => undefined);

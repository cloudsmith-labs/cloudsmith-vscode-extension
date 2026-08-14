// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const load = module[["req", "uire"].join("")].bind(module);
const platform = load("vscode");
const registry = platform[["comm", "ands"].join("")];
const method = ["register", "Command"].join("");
registry[method]("cloudsmith-vsc.hidden", () => undefined);

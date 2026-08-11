// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const root = path.resolve(__dirname, "..");
const roots = [
  "extension.js",
  ".vscode-test.mjs",
  "eslint.config.mjs",
  "models",
  "scripts",
  "test",
  "util",
  "views",
];
const maxEntries = 500;
const files = [];

function collect(relativePath) {
  const absolutePath = path.join(root, relativePath);
  const stats = fs.lstatSync(absolutePath);
  if (stats.isSymbolicLink()) {
    throw new Error(`Syntax roots may not contain symbolic links: ${relativePath}`);
  }
  if (stats.isDirectory()) {
    for (const entry of fs.readdirSync(absolutePath, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name))) {
      collect(path.join(relativePath, entry.name));
    }
    return;
  }
  if (!stats.isFile()) {
    throw new Error(`Syntax root entry is not a regular file: ${relativePath}`);
  }
  if (/\.(?:js|mjs)$/.test(relativePath)) {
    files.push(relativePath);
    if (files.length > maxEntries) {
      throw new Error(`Syntax file count exceeds the ${maxEntries}-file review limit`);
    }
  }
}

for (const relativePath of roots) {
  collect(relativePath);
}

for (const relativePath of files) {
  const result = spawnSync(process.execPath, ["--check", path.join(root, relativePath)], {
    encoding: "utf8",
  });
  if (result.status !== 0) {
    process.stderr.write(result.stderr || result.stdout);
    process.exit(result.status ?? 1);
  }
}

console.log(`Syntax-checked ${files.length} JavaScript files.`);

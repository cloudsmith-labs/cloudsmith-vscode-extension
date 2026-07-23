// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  buildTree,
  createDependency,
  getSourceFileName,
  getWorkspacePath,
  pathExists,
  readUtf8,
} = require("./shared");

const goParser = {
  name: "goParser",
  ecosystem: "go",

  async canResolve(workspaceFolder) {
    return pathExists(path.join(getWorkspacePath(workspaceFolder), "go.mod"), workspaceFolder);
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    const manifestPath = path.join(rootPath, "go.mod");
    if (!(await pathExists(manifestPath, workspaceFolder))) {
      return [];
    }
    return [{
      resolverName: this.name,
      ecosystem: this.ecosystem,
      lockfilePath: manifestPath,
      manifestPath,
      sourceFile: "go.mod",
    }];
  },

  async resolve({ manifestPath, workspaceFolder }) {
    const dependencies = [];
    const sourceFile = getSourceFileName(manifestPath);
    let inRequireBlock = false;

    for (const rawLine of String(await readUtf8(manifestPath, workspaceFolder)).split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("//")) {
        continue;
      }
      if (line === "require (") {
        inRequireBlock = true;
        continue;
      }
      if (line === ")" && inRequireBlock) {
        inRequireBlock = false;
        continue;
      }

      const lineToParse = line.startsWith("require ") ? line.slice("require ".length).trim() : line;
      if (!inRequireBlock && !line.startsWith("require ")) {
        continue;
      }

      const cleaned = lineToParse.split("//")[0].trim();
      const parts = cleaned.split(/\s+/);
      if (parts.length < 2) {
        continue;
      }

      dependencies.push(createDependency({
        name: parts[0],
        version: parts[1].replace(/^v/, ""),
        ecosystem: "go",
        isDirect: !rawLine.includes("// indirect"),
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: rawLine.includes("// indirect"),
      }));
    }

    return buildTree("go", sourceFile, dependencies);
  },
};

module.exports = goParser;

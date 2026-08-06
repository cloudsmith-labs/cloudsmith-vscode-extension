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
const { parseMixExsManifest } = require("./manifestHelpers");

const hexParser = {
  name: "hexParser",
  ecosystem: "hex",

  async canResolve(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    return (await pathExists(path.join(rootPath, "mix.lock"), workspaceFolder))
      || (await pathExists(path.join(rootPath, "mix.exs"), workspaceFolder));
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    const lockfilePath = await pathExists(path.join(rootPath, "mix.lock"), workspaceFolder)
      ? path.join(rootPath, "mix.lock")
      : null;
    const manifestPath = await pathExists(path.join(rootPath, "mix.exs"), workspaceFolder)
      ? path.join(rootPath, "mix.exs")
      : null;
    if (!lockfilePath && !manifestPath) {
      return [];
    }
    return [{
      resolverName: this.name,
      ecosystem: this.ecosystem,
      lockfilePath,
      manifestPath,
      sourceFile: getSourceFileName(lockfilePath || manifestPath),
    }];
  },

  async resolve({ lockfilePath, manifestPath, workspaceFolder }) {
    const sourceFile = getSourceFileName(lockfilePath || manifestPath);
    if (!lockfilePath) {
      return buildTree("hex", sourceFile, parseMixExsManifest(await readUtf8(manifestPath, workspaceFolder)).map((dependency) => createDependency({
        name: dependency.name,
        version: dependency.version,
        ecosystem: "hex",
        isDirect: true,
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: false,
      })));
    }

    const directNames = manifestPath && await pathExists(manifestPath, workspaceFolder)
      ? new Set(parseMixExsManifest(await readUtf8(manifestPath, workspaceFolder)).map((dependency) => dependency.name.toLowerCase()))
      : new Set();
    const entryPattern = /"([^"]+)"\s*:\s*\{\s*:hex,\s*(?::"[^"]+"|:[^,]+)\s*,\s*"([^"]+)"/g;
    const dependencies = [];
    for (const match of String(await readUtf8(lockfilePath, workspaceFolder)).matchAll(entryPattern)) {
      dependencies.push(createDependency({
        name: match[1],
        version: match[2],
        ecosystem: "hex",
        isDirect: directNames.size === 0 || directNames.has(match[1].toLowerCase()),
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: false,
      }));
    }

    if (dependencies.length === 0) {
      throw new Error("Malformed mix.lock: no Hex package entries found");
    }

    return buildTree("hex", sourceFile, dependencies);
  },
};

module.exports = hexParser;

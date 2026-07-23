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
const { parseChartManifest } = require("./manifestHelpers");

const helmParser = {
  name: "helmParser",
  ecosystem: "helm",

  async canResolve(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    return (await pathExists(path.join(rootPath, "Chart.lock"), workspaceFolder))
      || (await pathExists(path.join(rootPath, "Chart.yaml"), workspaceFolder));
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    const lockfilePath = await pathExists(path.join(rootPath, "Chart.lock"), workspaceFolder)
      ? path.join(rootPath, "Chart.lock")
      : null;
    const manifestPath = await pathExists(path.join(rootPath, "Chart.yaml"), workspaceFolder)
      ? path.join(rootPath, "Chart.yaml")
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
    const sourcePath = lockfilePath || manifestPath;
    const sourceFile = getSourceFileName(sourcePath);
    const dependencies = parseChartManifest(await readUtf8(sourcePath, workspaceFolder)).map((dependency) => createDependency({
      name: dependency.name,
      version: dependency.version,
      ecosystem: "helm",
      isDirect: true,
      parent: null,
      parentChain: [],
      transitives: [],
      sourceFile,
      isDevelopmentDependency: false,
    }));

    return buildTree("helm", sourceFile, dependencies);
  },
};

module.exports = helmParser;

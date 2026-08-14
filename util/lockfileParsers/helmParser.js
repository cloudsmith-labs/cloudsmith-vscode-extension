// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  buildTree,
  createDependency,
  getSourceFileName,
  getWorkspacePath,
  pathExists,
  readUtf8,
  throwIfTraversalCancelled,
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

  async resolve({ lockfilePath, manifestPath, workspaceFolder, options = {} }) {
    const cancellationToken = options.cancellationToken;
    throwIfTraversalCancelled(cancellationToken);
    const sourcePath = lockfilePath || manifestPath;
    const sourceFile = getSourceFileName(sourcePath);
    const manifestDependencies = manifestPath && manifestPath !== sourcePath
      && await pathExists(manifestPath, workspaceFolder)
      ? parseChartManifest(await readUtf8(manifestPath, workspaceFolder, options))
      : [];
    const manifestByName = new Map(manifestDependencies.map((dependency) => [
      dependency.name.toLowerCase(),
      dependency,
    ]));
    const dependencies = parseChartManifest(
      await readUtf8(sourcePath, workspaceFolder, options)
    ).map((dependency) => {
      throwIfTraversalCancelled(cancellationToken);
      const declaration = manifestByName.get(dependency.name.toLowerCase()) || {};
      const repository = dependency.repository || declaration.repository;
      const alias = dependency.alias || declaration.alias;
      const packageSource = dependency.packageSource && dependency.packageSource.kind !== "registry"
        ? dependency.packageSource
        : declaration.packageSource || dependency.packageSource;
      return createDependency({
      name: dependency.name,
      version: dependency.version,
      ecosystem: "helm",
      isDirect: true,
      parent: null,
      parentChain: [],
      transitives: [],
      sourceFile,
      isDevelopmentDependency: false,
      repository,
      alias,
      packageSource,
    });
    });

    return buildTree("helm", sourceFile, dependencies);
  },
};

module.exports = helmParser;

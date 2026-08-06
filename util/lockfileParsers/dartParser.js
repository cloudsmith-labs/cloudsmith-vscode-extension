// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  buildTree,
  countIndent,
  createDependency,
  getSourceFileName,
  getWorkspacePath,
  pathExists,
  readUtf8,
  stripYamlComment,
} = require("./shared");
const { parsePubspecManifest } = require("./manifestHelpers");

const dartParser = {
  name: "dartParser",
  ecosystem: "dart",

  async canResolve(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    return (await pathExists(path.join(rootPath, "pubspec.lock"), workspaceFolder))
      || (await pathExists(path.join(rootPath, "pubspec.yaml"), workspaceFolder));
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    const lockfilePath = await pathExists(path.join(rootPath, "pubspec.lock"), workspaceFolder)
      ? path.join(rootPath, "pubspec.lock")
      : null;
    const manifestPath = await pathExists(path.join(rootPath, "pubspec.yaml"), workspaceFolder)
      ? path.join(rootPath, "pubspec.yaml")
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
      return buildTree("dart", sourceFile, parsePubspecManifest(await readUtf8(manifestPath, workspaceFolder)).map((dependency) => createDependency({
        name: dependency.name,
        version: dependency.version,
        ecosystem: "dart",
        isDirect: true,
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: dependency.isDevelopmentDependency,
      })));
    }

    const dependencies = [];
    let inPackages = false;
    let current = null;

    const flushCurrent = () => {
      if (!current || !current.name) {
        current = null;
        return;
      }
      dependencies.push(createDependency({
        name: current.name,
        version: current.version,
        ecosystem: "dart",
        isDirect: !String(current.dependencyType || "").toLowerCase().includes("transitive"),
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: String(current.dependencyType || "").toLowerCase().includes("dev"),
      }));
      current = null;
    };

    for (const rawLine of String(await readUtf8(lockfilePath, workspaceFolder)).split(/\r?\n/)) {
      const line = stripYamlComment(rawLine).trim();
      if (!line) {
        continue;
      }

      const indent = countIndent(rawLine);
      if (indent === 0 && line === "packages:") {
        inPackages = true;
        continue;
      }
      if (indent === 0 && line.endsWith(":") && line !== "packages:") {
        inPackages = false;
        flushCurrent();
        continue;
      }
      if (!inPackages) {
        continue;
      }
      if (indent === 2 && line.endsWith(":")) {
        flushCurrent();
        current = { name: line.slice(0, -1), version: "", dependencyType: "" };
        continue;
      }
      if (!current) {
        continue;
      }
      if (indent === 4 && line.startsWith("dependency:")) {
        current.dependencyType = line.slice("dependency:".length).trim().replace(/^["']|["']$/g, "");
      }
      if (indent === 4 && line.startsWith("version:")) {
        current.version = line.slice("version:".length).trim().replace(/^["']|["']$/g, "");
      }
    }

    flushCurrent();
    return buildTree("dart", sourceFile, dependencies);
  },
};

module.exports = dartParser;

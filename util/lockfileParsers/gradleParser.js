// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  buildTree,
  createDependency,
  deduplicateDeps,
  getSourceFileName,
  getWorkspacePath,
  pathExists,
  readUtf8,
} = require("./shared");
const { parseBuildGradleManifest } = require("./manifestHelpers");

const BUILD_FILES = ["build.gradle", "build.gradle.kts"];

const gradleParser = {
  name: "gradleParser",
  ecosystem: "gradle",

  async canResolve(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    for (const buildFile of BUILD_FILES) {
      if (await pathExists(path.join(rootPath, buildFile), workspaceFolder)) {
        return true;
      }
    }
    return false;
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    for (const buildFile of BUILD_FILES) {
      const manifestPath = path.join(rootPath, buildFile);
      if (!(await pathExists(manifestPath, workspaceFolder))) {
        continue;
      }
      const lockfilePath = await pathExists(path.join(rootPath, "gradle.lockfile"), workspaceFolder)
        ? path.join(rootPath, "gradle.lockfile")
        : null;
      return [{
        resolverName: this.name,
        ecosystem: this.ecosystem,
        lockfilePath,
        manifestPath,
        sourceFile: buildFile,
      }];
    }
    return [];
  },

  async resolve({ lockfilePath, manifestPath, workspaceFolder }) {
    const directDependencies = parseBuildGradleManifest(await readUtf8(manifestPath, workspaceFolder));
    const sourceFile = getSourceFileName(manifestPath);

    if (!lockfilePath) {
      return buildTree("gradle", sourceFile, directDependencies.map((dependency) => createDependency({
        name: dependency.name,
        version: dependency.version,
        ecosystem: "gradle",
        isDirect: true,
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: dependency.isDevelopmentDependency,
      })));
    }

    const lockVersions = parseGradleLockfile(await readUtf8(lockfilePath, workspaceFolder));
    const dependencies = [];

    for (const directDependency of directDependencies) {
      const resolvedVersion = lockVersions.get(directDependency.name) || directDependency.version;
      dependencies.push(createDependency({
        name: directDependency.name,
        version: resolvedVersion,
        ecosystem: "gradle",
        isDirect: true,
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: directDependency.isDevelopmentDependency,
      }));
    }

    for (const [name, version] of lockVersions.entries()) {
      dependencies.push(createDependency({
        name,
        version,
        ecosystem: "gradle",
        isDirect: directDependencies.some((dependency) => dependency.name === name),
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: false,
      }));
    }

    return buildTree("gradle", sourceFile, deduplicateDeps(dependencies));
  },
};

function parseGradleLockfile(content) {
  const versions = new Map();

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }
    const entry = line.split("=", 1)[0].trim();
    const parts = entry.split(":");
    if (parts.length < 3) {
      continue;
    }
    versions.set(`${parts[0]}:${parts[1]}`, parts[2]);
  }

  return versions;
}

module.exports = gradleParser;

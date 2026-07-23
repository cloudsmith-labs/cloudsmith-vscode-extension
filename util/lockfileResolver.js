// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const npmParser = require("./lockfileParsers/npmParser");
const pythonParser = require("./lockfileParsers/pythonParser");
const mavenParser = require("./lockfileParsers/mavenParser");
const gradleParser = require("./lockfileParsers/gradleParser");
const goParser = require("./lockfileParsers/goParser");
const cargoParser = require("./lockfileParsers/cargoParser");
const rubyParser = require("./lockfileParsers/rubyParser");
const dockerParser = require("./lockfileParsers/dockerParser");
const nugetParser = require("./lockfileParsers/nugetParser");
const dartParser = require("./lockfileParsers/dartParser");
const composerParser = require("./lockfileParsers/composerParser");
const helmParser = require("./lockfileParsers/helmParser");
const swiftParser = require("./lockfileParsers/swiftParser");
const hexParser = require("./lockfileParsers/hexParser");
const {
  getWorkspacePath,
  resolveWorkspaceFilePath,
} = require("./lockfileParsers/shared");

const REGISTERED_RESOLVERS = [
  npmParser,
  pythonParser,
  mavenParser,
  gradleParser,
  goParser,
  cargoParser,
  rubyParser,
  dockerParser,
  nugetParser,
  dartParser,
  composerParser,
  helmParser,
  swiftParser,
  hexParser,
];

class LockfileResolver {
  static getResolvers() {
    return REGISTERED_RESOLVERS.slice();
  }

  static async detectResolvers(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    const matches = [];

    for (const resolver of REGISTERED_RESOLVERS) {
      if (!resolver || typeof resolver.canResolve !== "function") {
        continue;
      }

      if (!(await resolver.canResolve(rootPath))) {
        continue;
      }

      const detections = typeof resolver.detect === "function"
        ? await resolver.detect(rootPath)
        : [{
          resolverName: resolver.name,
          ecosystem: resolver.ecosystem,
          workspaceFolder: rootPath,
          lockfilePath: null,
          manifestPath: null,
        }];

      for (const detection of detections) {
        matches.push({
          resolverName: resolver.name,
          ecosystem: resolver.ecosystem,
          workspaceFolder: rootPath,
          lockfilePath: detection.lockfilePath || null,
          manifestPath: detection.manifestPath || null,
          sourceFile: detection.sourceFile
            || path.basename(detection.lockfilePath || detection.manifestPath || ""),
        });
      }
    }

    return matches;
  }

  static async resolve(resolverName, lockfilePath, manifestPath, options = {}) {
    const resolver = REGISTERED_RESOLVERS.find((candidate) => candidate.name === resolverName);
    if (!resolver) {
      throw new Error(`Unknown lockfile resolver: ${resolverName}`);
    }

    const workspaceFolder = getWorkspacePath(options.workspaceFolder || path.dirname(lockfilePath || manifestPath || ""));
    const safeLockfilePath = lockfilePath
      ? await resolveWorkspaceFilePath(lockfilePath, workspaceFolder)
      : null;
    const safeManifestPath = manifestPath
      ? await resolveWorkspaceFilePath(manifestPath, workspaceFolder)
      : null;

    if (lockfilePath && !safeLockfilePath) {
      throw new Error("Lockfile paths must stay within the workspace folder.");
    }

    if (manifestPath && !safeManifestPath) {
      throw new Error("Manifest paths must stay within the workspace folder.");
    }

    return resolver.resolve({
      workspaceFolder,
      lockfilePath: safeLockfilePath,
      manifestPath: safeManifestPath,
      options,
    });
  }

  static async resolveAll(workspaceFolder, options = {}) {
    const matches = await LockfileResolver.detectResolvers(workspaceFolder);
    const trees = [];

    for (const match of matches) {
      const tree = await LockfileResolver.resolve(
        match.resolverName,
        match.lockfilePath,
        match.manifestPath,
        {
          ...options,
          workspaceFolder: match.workspaceFolder,
          detection: match,
        }
      );

      if (tree) {
        trees.push(tree);
      }
    }

    return trees;
  }
}

module.exports = {
  LockfileResolver,
};

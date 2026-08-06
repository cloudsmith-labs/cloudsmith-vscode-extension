// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  buildTree,
  createDependency,
  getSourceFileName,
  getWorkspacePath,
  readJson,
  pathExists,
  readUtf8,
} = require("./shared");
const { normalizeSwiftIdentity, parsePackageSwiftManifest } = require("./manifestHelpers");

const swiftParser = {
  name: "swiftParser",
  ecosystem: "swift",

  async canResolve(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    return (await pathExists(path.join(rootPath, "Package.resolved"), workspaceFolder))
      || (await pathExists(path.join(rootPath, "Package.swift"), workspaceFolder));
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    const lockfilePath = await pathExists(path.join(rootPath, "Package.resolved"), workspaceFolder)
      ? path.join(rootPath, "Package.resolved")
      : null;
    const manifestPath = await pathExists(path.join(rootPath, "Package.swift"), workspaceFolder)
      ? path.join(rootPath, "Package.swift")
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
      return buildTree("swift", sourceFile, parsePackageSwiftManifest(await readUtf8(manifestPath, workspaceFolder)).map((dependency) => createDependency({
        name: dependency.name,
        version: dependency.version,
        ecosystem: "swift",
        isDirect: true,
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: false,
      })));
    }

    const manifestDirectNames = manifestPath && await pathExists(manifestPath, workspaceFolder)
      ? new Set(parsePackageSwiftManifest(await readUtf8(manifestPath, workspaceFolder)).map((dependency) => dependency.name))
      : new Set();
    const root = await readJson(lockfilePath);
    const pins = Array.isArray(root.pins)
      ? root.pins
      : (root.object && Array.isArray(root.object.pins) ? root.object.pins : []);
    if (pins.length === 0) {
      throw new Error("Malformed Package.resolved: missing pins array");
    }

    return buildTree("swift", sourceFile, pins.map((pin) => {
      const state = pin.state || {};
      const identity = normalizeSwiftIdentity(pin.identity || pin.package || pin.location || "");
      return createDependency({
        name: identity,
        version: state.version || state.revision || state.branch || "",
        ecosystem: "swift",
        isDirect: manifestDirectNames.size === 0 || manifestDirectNames.has(identity),
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: false,
      });
    }));
  },
};

module.exports = swiftParser;

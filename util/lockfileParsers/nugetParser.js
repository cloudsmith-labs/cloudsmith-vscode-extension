// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const fs = require("fs");
const path = require("path");
const {
  buildTree,
  createDependency,
  deduplicateDeps,
  flattenDependencies,
  getSourceFileName,
  getWorkspacePath,
  pathExists,
  readJson,
  readUtf8,
  resolveWorkspaceFilePath,
} = require("./shared");
const { parseCsprojManifest } = require("./manifestHelpers");

const nugetParser = {
  name: "nugetParser",
  ecosystem: "nuget",

  async canResolve(workspaceFolder) {
    const matches = await this.detect(workspaceFolder);
    return matches.length > 0;
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    const safeRootPath = await resolveWorkspaceFilePath(rootPath, workspaceFolder);
    if (!safeRootPath) {
      return [];
    }
    const entries = await fs.promises.readdir(safeRootPath);
    const csprojPath = entries.find((entry) => entry.toLowerCase().endsWith(".csproj"));
    const lockfilePath = await pathExists(path.join(safeRootPath, "packages.lock.json"), workspaceFolder)
      ? path.join(safeRootPath, "packages.lock.json")
      : null;
    const manifestPath = csprojPath ? path.join(safeRootPath, csprojPath) : null;

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
    const manifestDependencies = manifestPath && await pathExists(manifestPath, workspaceFolder)
      ? parseCsprojManifest(await readUtf8(manifestPath, workspaceFolder))
      : [];
    const directNames = new Set(manifestDependencies.map((dependency) => dependency.name.toLowerCase()));

    if (!lockfilePath) {
      return buildTree("nuget", sourceFile, manifestDependencies.map((dependency) => createDependency({
        name: dependency.name,
        version: dependency.version,
        ecosystem: "nuget",
        isDirect: true,
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: dependency.isDevelopmentDependency,
      })));
    }

    const root = await readJson(lockfilePath, workspaceFolder);
    const dependencyRoot = root && root.dependencies && typeof root.dependencies === "object"
      ? root.dependencies
      : null;
    if (!dependencyRoot) {
      throw new Error("Malformed packages.lock.json: missing dependencies object");
    }

    const recordsByName = new Map();
    for (const frameworkDependencies of Object.values(dependencyRoot)) {
      if (!frameworkDependencies || typeof frameworkDependencies !== "object") {
        continue;
      }
      for (const [name, details] of Object.entries(frameworkDependencies)) {
        const dependencies = details && details.dependencies && typeof details.dependencies === "object"
          ? Object.keys(details.dependencies)
          : [];
        const existing = recordsByName.get(name.toLowerCase());
        recordsByName.set(name.toLowerCase(), {
          name,
          version: details.resolved || "",
          dependencies: deduplicateStringValues([...(existing ? existing.dependencies : []), ...dependencies]),
          isDirect: Boolean(existing && existing.isDirect) || String(details.type || "").toLowerCase() === "direct",
        });
      }
    }

    const rootRecords = manifestDependencies.length > 0
      ? manifestDependencies.map((dependency) => recordsByName.get(dependency.name.toLowerCase())).filter(Boolean)
      : [...recordsByName.values()].filter((record) => record.isDirect);

    const directRoots = deduplicateDeps(rootRecords.map((record) => buildNugetDependency(
      record,
      [],
      recordsByName,
      new Set(),
      sourceFile,
      directNames
    )));
    let dependencies = deduplicateDeps(flattenDependencies(directRoots));

    for (const record of recordsByName.values()) {
      const key = `${record.name.toLowerCase()}@${record.version.toLowerCase()}`;
      if (dependencies.some((dependency) => `${dependency.name.toLowerCase()}@${dependency.version.toLowerCase()}` === key)) {
        continue;
      }
      dependencies.push(createDependency({
        name: record.name,
        version: record.version,
        ecosystem: "nuget",
        isDirect: directNames.has(record.name.toLowerCase()) || record.isDirect,
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: false,
      }));
    }

    return buildTree("nuget", sourceFile, dependencies);
  },
};

function buildNugetDependency(record, parentChain, recordsByName, visiting, sourceFile, directNames) {
  const key = `${record.name.toLowerCase()}@${record.version.toLowerCase()}`;
  if (visiting.has(key)) {
    return createDependency({
      name: record.name,
      version: record.version,
      ecosystem: "nuget",
      isDirect: parentChain.length === 0 || directNames.has(record.name.toLowerCase()) || record.isDirect,
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile,
      isDevelopmentDependency: false,
    });
  }

  const nextVisiting = new Set(visiting);
  nextVisiting.add(key);
  const nextParentChain = parentChain.concat(record.name);
  const transitives = [];

  for (const dependencyName of record.dependencies) {
    const childRecord = recordsByName.get(dependencyName.toLowerCase());
    if (!childRecord) {
      continue;
    }
    transitives.push(buildNugetDependency(
      childRecord,
      nextParentChain,
      recordsByName,
      nextVisiting,
      sourceFile,
      directNames
    ));
  }

  return createDependency({
    name: record.name,
    version: record.version,
    ecosystem: "nuget",
    isDirect: parentChain.length === 0 || directNames.has(record.name.toLowerCase()) || record.isDirect,
    parent: parentChain[parentChain.length - 1] || null,
    parentChain,
    transitives: deduplicateDeps(transitives),
    sourceFile,
    isDevelopmentDependency: false,
  });
}

function deduplicateStringValues(values) {
  return [...new Set(values.filter(Boolean))];
}

module.exports = nugetParser;

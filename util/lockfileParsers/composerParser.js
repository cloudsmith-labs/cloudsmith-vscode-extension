// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  buildTree,
  createDependency,
  deduplicateDeps,
  flattenDependencies,
  getSourceFileName,
  getWorkspacePath,
  readJson,
  pathExists,
  readUtf8,
} = require("./shared");
const { parseComposerManifest } = require("./manifestHelpers");

const composerParser = {
  name: "composerParser",
  ecosystem: "composer",

  async canResolve(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    return (await pathExists(path.join(rootPath, "composer.lock"), workspaceFolder))
      || (await pathExists(path.join(rootPath, "composer.json"), workspaceFolder));
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    const lockfilePath = await pathExists(path.join(rootPath, "composer.lock"), workspaceFolder)
      ? path.join(rootPath, "composer.lock")
      : null;
    const manifestPath = await pathExists(path.join(rootPath, "composer.json"), workspaceFolder)
      ? path.join(rootPath, "composer.json")
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
    const manifestDependencies = manifestPath && await pathExists(manifestPath, workspaceFolder)
      ? parseComposerManifest(await readUtf8(manifestPath, workspaceFolder))
      : [];

    if (!lockfilePath) {
      return buildTree("composer", sourceFile, manifestDependencies.map((dependency) => createDependency({
        name: dependency.name,
        version: dependency.version,
        ecosystem: "composer",
        isDirect: true,
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: dependency.isDevelopmentDependency,
      })));
    }

    const root = await readJson(lockfilePath);
    const records = [];

    for (const record of [...(root.packages || []), ...(root["packages-dev"] || [])]) {
      if (!record || !record.name) {
        continue;
      }
      records.push({
        name: record.name,
        version: record.version || "",
        dependencies: Object.keys(record.require || {}).filter((name) => name.includes("/") && !name.startsWith("ext-") && !name.startsWith("lib-") && name !== "php"),
      });
    }

    const directNames = new Set(manifestDependencies.map((dependency) => dependency.name.toLowerCase()));
    const recordsByName = new Map(records.map((record) => [record.name.toLowerCase(), record]));
    const incomingCounts = new Map();
    for (const record of records) {
      for (const dependencyName of record.dependencies) {
        incomingCounts.set(dependencyName.toLowerCase(), (incomingCounts.get(dependencyName.toLowerCase()) || 0) + 1);
      }
    }

    const rootRecords = directNames.size > 0
      ? [...directNames].map((name) => recordsByName.get(name)).filter(Boolean)
      : records.filter((record) => !incomingCounts.get(record.name.toLowerCase()));

    const directRoots = deduplicateDeps(rootRecords.map((record) => buildComposerDependency(
      record,
      [],
      recordsByName,
      new Set(),
      sourceFile,
      directNames
    )));
    let dependencies = deduplicateDeps(flattenDependencies(directRoots));

    for (const record of records) {
      const key = `${record.name.toLowerCase()}@${record.version.toLowerCase()}`;
      if (dependencies.some((dependency) => `${dependency.name.toLowerCase()}@${dependency.version.toLowerCase()}` === key)) {
        continue;
      }
      dependencies.push(createDependency({
        name: record.name,
        version: record.version,
        ecosystem: "composer",
        isDirect: directNames.has(record.name.toLowerCase()),
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: false,
      }));
    }

    return buildTree("composer", sourceFile, dependencies);
  },
};

function buildComposerDependency(record, parentChain, recordsByName, visiting, sourceFile, directNames) {
  const key = `${record.name.toLowerCase()}@${record.version.toLowerCase()}`;
  if (visiting.has(key)) {
    return createDependency({
      name: record.name,
      version: record.version,
      ecosystem: "composer",
      isDirect: parentChain.length === 0 || directNames.has(record.name.toLowerCase()),
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
    transitives.push(buildComposerDependency(
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
    ecosystem: "composer",
    isDirect: parentChain.length === 0 || directNames.has(record.name.toLowerCase()),
    parent: parentChain[parentChain.length - 1] || null,
    parentChain,
    transitives: deduplicateDeps(transitives),
    sourceFile,
    isDevelopmentDependency: false,
  });
}

module.exports = composerParser;

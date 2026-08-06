// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  buildTree,
  createDependency,
  deduplicateDeps,
  flattenDependencies,
  getSourceFileName,
  getWorkspacePath,
  parseKeyValueLine,
  pathExists,
  readUtf8,
} = require("./shared");
const { parseCargoTomlManifest } = require("./manifestHelpers");

const cargoParser = {
  name: "cargoParser",
  ecosystem: "cargo",

  async canResolve(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    return (await pathExists(path.join(rootPath, "Cargo.lock"), workspaceFolder))
      || (await pathExists(path.join(rootPath, "Cargo.toml"), workspaceFolder));
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    const lockfilePath = await pathExists(path.join(rootPath, "Cargo.lock"), workspaceFolder)
      ? path.join(rootPath, "Cargo.lock")
      : null;
    const manifestPath = await pathExists(path.join(rootPath, "Cargo.toml"), workspaceFolder)
      ? path.join(rootPath, "Cargo.toml")
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
    const manifestDependencies = manifestPath && await pathExists(manifestPath, workspaceFolder)
      ? parseCargoTomlManifest(await readUtf8(manifestPath, workspaceFolder))
      : [];
    const sourceFile = getSourceFileName(lockfilePath || manifestPath);

    if (!lockfilePath) {
      return buildTree("cargo", sourceFile, manifestDependencies.map((dependency) => createDependency({
        name: dependency.name,
        version: dependency.version,
        ecosystem: "cargo",
        isDirect: true,
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: dependency.isDevelopmentDependency,
      })));
    }

    const records = parseCargoLock(await readUtf8(lockfilePath, workspaceFolder));
    if (records.length === 0) {
      throw new Error("Malformed Cargo.lock: no package entries found");
    }
    const directNames = new Set(manifestDependencies.map((dependency) => dependency.name.toLowerCase()));
    const recordsByName = new Map();
    const incomingCounts = new Map();

    for (const record of records) {
      if (!recordsByName.has(record.name.toLowerCase())) {
        recordsByName.set(record.name.toLowerCase(), []);
      }
      recordsByName.get(record.name.toLowerCase()).push(record);
      for (const dependency of record.dependencies) {
        incomingCounts.set(
          dependency.name.toLowerCase(),
          (incomingCounts.get(dependency.name.toLowerCase()) || 0) + 1
        );
      }
    }

    const rootRecords = manifestDependencies.length > 0
      ? manifestDependencies.map((dependency) => selectCargoRecord(recordsByName, dependency.name, dependency.version)).filter(Boolean)
      : records.filter((record) => !incomingCounts.get(record.name.toLowerCase()));

    const directRoots = deduplicateDeps(rootRecords.map((record) => buildCargoDependency(
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
        ecosystem: "cargo",
        isDirect: directNames.has(record.name.toLowerCase()),
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: false,
      }));
    }

    return buildTree("cargo", sourceFile, dependencies);
  },
};

function parseCargoLock(content) {
  const records = [];
  let current = null;
  let inDependenciesArray = false;

  const flushCurrent = () => {
    if (!current || !current.name || !current.version) {
      current = null;
      inDependenciesArray = false;
      return;
    }
    const source = String(current.source || "").trim();
    if (source && !source.startsWith("path+") && !source.startsWith("git+")) {
      records.push(current);
    }
    current = null;
    inDependenciesArray = false;
  };

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }
    if (line === "[[package]]") {
      flushCurrent();
      current = { name: "", version: "", source: "", dependencies: [] };
      continue;
    }
    if (!current) {
      continue;
    }

    if (inDependenciesArray) {
      if (line === "]") {
        inDependenciesArray = false;
        continue;
      }
      const match = line.trim().replace(/,$/, "").replace(/^"|"$/g, "").match(/^([^ ]+)(?: ([^ ]+))?/);
      if (match) {
        current.dependencies.push({
          name: match[1],
          version: match[2] ? match[2].replace(/^\(/, "").replace(/\)$/, "") : "",
        });
      }
      continue;
    }

    if (line.startsWith("name =")) {
      current.name = parseKeyValueLine(line).value.replace(/^"|"$/g, "");
      continue;
    }
    if (line.startsWith("version =")) {
      current.version = parseKeyValueLine(line).value.replace(/^"|"$/g, "");
      continue;
    }
    if (line.startsWith("source =")) {
      current.source = parseKeyValueLine(line).value.replace(/^"|"$/g, "");
      continue;
    }
    if (line.startsWith("dependencies = [")) {
      inDependenciesArray = true;
      const inline = line.slice(line.indexOf("[") + 1, line.lastIndexOf("]"));
      if (inline.trim()) {
        for (const item of inline.split(",")) {
          const cleaned = item.trim().replace(/^"|"$/g, "");
          if (!cleaned) {
            continue;
          }
          const match = cleaned.match(/^([^ ]+)(?: ([^ ]+))?/);
          if (match) {
            current.dependencies.push({ name: match[1], version: match[2] || "" });
          }
        }
        inDependenciesArray = false;
      }
    }
  }

  flushCurrent();
  return deduplicateCargoRecords(records);
}

function deduplicateCargoRecords(records) {
  const seen = new Set();
  const results = [];
  for (const record of records) {
    const key = `${record.name.toLowerCase()}@${record.version.toLowerCase()}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    results.push(record);
  }
  return results;
}

function selectCargoRecord(recordsByName, name, version) {
  const candidates = recordsByName.get(name.toLowerCase()) || [];
  if (candidates.length === 0) {
    return null;
  }
  if (version) {
    const exactMatch = candidates.find((record) => record.version === version);
    if (exactMatch) {
      return exactMatch;
    }
  }
  return candidates[0];
}

function buildCargoDependency(record, parentChain, recordsByName, visiting, sourceFile, directNames) {
  const key = `${record.name.toLowerCase()}@${record.version.toLowerCase()}`;
  if (visiting.has(key)) {
    return createDependency({
      name: record.name,
      version: record.version,
      ecosystem: "cargo",
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

  for (const dependency of record.dependencies) {
    const childRecord = selectCargoRecord(recordsByName, dependency.name, dependency.version);
    if (!childRecord) {
      continue;
    }
    transitives.push(buildCargoDependency(
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
    ecosystem: "cargo",
    isDirect: parentChain.length === 0 || directNames.has(record.name.toLowerCase()),
    parent: parentChain[parentChain.length - 1] || null,
    parentChain,
    transitives: deduplicateDeps(transitives),
    sourceFile,
    isDevelopmentDependency: false,
  });
}

module.exports = cargoParser;

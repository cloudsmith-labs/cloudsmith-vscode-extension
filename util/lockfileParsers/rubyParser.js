// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  buildTree,
  countIndent,
  createDependency,
  deduplicateDeps,
  flattenDependencies,
  getSourceFileName,
  getWorkspacePath,
  pathExists,
  readUtf8,
} = require("./shared");
const { parseGemfileManifest } = require("./manifestHelpers");

const rubyParser = {
  name: "rubyParser",
  ecosystem: "ruby",

  async canResolve(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    return (await pathExists(path.join(rootPath, "Gemfile.lock"), workspaceFolder))
      || (await pathExists(path.join(rootPath, "Gemfile"), workspaceFolder));
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    const lockfilePath = await pathExists(path.join(rootPath, "Gemfile.lock"), workspaceFolder)
      ? path.join(rootPath, "Gemfile.lock")
      : null;
    const manifestPath = await pathExists(path.join(rootPath, "Gemfile"), workspaceFolder)
      ? path.join(rootPath, "Gemfile")
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
      const dependencies = parseGemfileManifest(await readUtf8(manifestPath, workspaceFolder)).map((dependency) => createDependency({
        name: dependency.name,
        version: dependency.version,
        ecosystem: "ruby",
        isDirect: true,
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: dependency.isDevelopmentDependency,
      }));
      return buildTree("ruby", sourceFile, dependencies);
    }

    const directNames = manifestPath && await pathExists(manifestPath, workspaceFolder)
      ? new Set(parseGemfileManifest(await readUtf8(manifestPath, workspaceFolder)).map((dependency) => dependency.name.toLowerCase()))
      : null;
    const records = parseGemfileLock(await readUtf8(lockfilePath, workspaceFolder));
    const recordsByName = new Map();
    const incomingCounts = new Map();

    for (const record of records) {
      recordsByName.set(record.name.toLowerCase(), record);
      for (const dependencyName of record.dependencies) {
        incomingCounts.set(dependencyName.toLowerCase(), (incomingCounts.get(dependencyName.toLowerCase()) || 0) + 1);
      }
    }

    const rootRecords = directNames && directNames.size > 0
      ? [...directNames].map((name) => recordsByName.get(name)).filter(Boolean)
      : records.filter((record) => !incomingCounts.get(record.name.toLowerCase()));

    const directRoots = deduplicateDeps(rootRecords.map((record) => buildRubyDependency(
      record,
      [],
      recordsByName,
      new Set(),
      sourceFile,
      directNames || new Set()
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
        ecosystem: "ruby",
        isDirect: directNames ? directNames.has(record.name.toLowerCase()) : false,
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: false,
      }));
    }

    return buildTree("ruby", sourceFile, dependencies);
  },
};

function parseGemfileLock(content) {
  const records = [];
  let section = "";
  let inSpecs = false;
  let current = null;

  const flushCurrent = () => {
    if (current && current.name && current.version) {
      records.push(current);
    }
    current = null;
  };

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const trimmed = rawLine.trimEnd();
    if (!trimmed) {
      continue;
    }
    const indent = countIndent(rawLine);
    const line = trimmed.trim();

    if (indent === 0 && /^[A-Z][A-Z0-9_ ]+$/.test(line)) {
      flushCurrent();
      section = line;
      inSpecs = false;
      continue;
    }
    if (section === "GEM" && indent === 2 && line === "specs:") {
      inSpecs = true;
      continue;
    }
    if (!inSpecs) {
      continue;
    }
    if (indent === 4) {
      flushCurrent();
      const match = line.match(/^([^\s(]+) \(([^)]+)\)/);
      if (!match) {
        continue;
      }
      current = { name: match[1], version: match[2], dependencies: [] };
      continue;
    }
    if (indent >= 6 && current) {
      const dependencyName = line.split(" ", 1)[0].split("(", 1)[0].replace(/!$/, "").trim();
      if (dependencyName) {
        current.dependencies.push(dependencyName);
      }
    }
  }

  flushCurrent();
  return records;
}

function buildRubyDependency(record, parentChain, recordsByName, visiting, sourceFile, directNames) {
  const key = `${record.name.toLowerCase()}@${record.version.toLowerCase()}`;
  if (visiting.has(key)) {
    return createDependency({
      name: record.name,
      version: record.version,
      ecosystem: "ruby",
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
    transitives.push(buildRubyDependency(
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
    ecosystem: "ruby",
    isDirect: parentChain.length === 0 || directNames.has(record.name.toLowerCase()),
    parent: parentChain[parentChain.length - 1] || null,
    parentChain,
    transitives: deduplicateDeps(transitives),
    sourceFile,
    isDevelopmentDependency: false,
  });
}

module.exports = rubyParser;

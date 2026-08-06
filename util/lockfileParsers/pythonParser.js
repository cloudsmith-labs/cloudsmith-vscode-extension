// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  buildTree,
  createDependency,
  deduplicateDeps,
  flattenDependencies,
  getSourceFileName,
  getWorkspacePath,
  normalizeVersion,
  parseInlineTomlValue,
  parseKeyValueLine,
  readJson,
  parseQuotedArray,
  pathExists,
  readUtf8,
  stripTomlComment,
} = require("./shared");
const {
  parsePyprojectManifest,
  parseRequirementSpec,
} = require("./manifestHelpers");
const { normalizePackageName } = require("../packageNameNormalizer");

const SOURCE_PRIORITY = ["uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt"];

const pythonParser = {
  name: "pythonParser",
  ecosystem: "python",

  async canResolve(workspaceFolder) {
    const matches = await this.detect(workspaceFolder);
    return matches.length > 0;
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    for (const fileName of SOURCE_PRIORITY) {
      const lockfilePath = path.join(rootPath, fileName);
      if (await pathExists(lockfilePath, workspaceFolder)) {
        const pyprojectPath = path.join(rootPath, "pyproject.toml");
        return [{
          resolverName: this.name,
          ecosystem: this.ecosystem,
          lockfilePath,
          manifestPath: await pathExists(pyprojectPath, workspaceFolder) ? pyprojectPath : null,
          sourceFile: fileName,
        }];
      }
    }
    return [];
  },

  async resolve({ lockfilePath, manifestPath, workspaceFolder }) {
    const sourceFile = getSourceFileName(lockfilePath);
    const pyproject = manifestPath && await pathExists(manifestPath, workspaceFolder)
      ? parsePyprojectManifest(await readUtf8(manifestPath, workspaceFolder))
      : { projectName: "", dependencies: [], directNames: new Set(), devNames: new Set() };

    if (sourceFile === "requirements.txt") {
      return parseRequirements(lockfilePath, workspaceFolder);
    }
    if (sourceFile === "Pipfile.lock") {
      return parsePipfile(lockfilePath, workspaceFolder);
    }
    if (sourceFile === "poetry.lock" || sourceFile === "uv.lock") {
      return parseTomlLock(lockfilePath, pyproject, workspaceFolder, sourceFile === "uv.lock");
    }

    throw new Error(`Unsupported Python dependency source: ${sourceFile}`);
  },
};

async function parseRequirements(lockfilePath, workspaceFolder) {
  const dependencies = [];

  for (const rawLine of String(await readUtf8(lockfilePath, workspaceFolder)).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) {
      continue;
    }
    const parsed = parseRequirementSpec(line);
    if (!parsed) {
      throw new Error(`Malformed requirements.txt entry: ${line}`);
    }
    dependencies.push(createDependency({
      name: parsed.name,
      version: parsed.version,
      ecosystem: "python",
      isDirect: true,
      parent: null,
      parentChain: [],
      transitives: [],
      sourceFile: getSourceFileName(lockfilePath),
      isDevelopmentDependency: false,
    }));
  }

  return buildTree("python", getSourceFileName(lockfilePath), dependencies, [
    "requirements.txt does not encode transitive dependencies. Showing direct requirements only.",
  ]);
}

async function parsePipfile(lockfilePath, workspaceFolder) {
  const root = await readJson(lockfilePath, workspaceFolder);
  const dependencies = [];

  for (const [name, details] of Object.entries(root.default || {})) {
    dependencies.push(createDependency({
      name,
      version: normalizeVersion(details && details.version),
      ecosystem: "python",
      isDirect: true,
      parent: null,
      parentChain: [],
      transitives: [],
      sourceFile: getSourceFileName(lockfilePath),
      isDevelopmentDependency: false,
    }));
  }

  for (const [name, details] of Object.entries(root.develop || {})) {
    dependencies.push(createDependency({
      name,
      version: normalizeVersion(details && details.version),
      ecosystem: "python",
      isDirect: true,
      parent: null,
      parentChain: [],
      transitives: [],
      sourceFile: getSourceFileName(lockfilePath),
      isDevelopmentDependency: true,
    }));
  }

  return buildTree("python", getSourceFileName(lockfilePath), deduplicateDeps(dependencies));
}

async function parseTomlLock(lockfilePath, pyproject, workspaceFolder, skipEditableRoot) {
  const records = parsePythonPackageRecords(
    await readUtf8(lockfilePath, workspaceFolder),
    skipEditableRoot
  );
  if (records.length === 0) {
    throw new Error(`Malformed ${getSourceFileName(lockfilePath)}: no package entries found`);
  }

  const sourceFile = getSourceFileName(lockfilePath);
  const normalizedDirectNames = pyproject.directNames.size > 0 || pyproject.devNames.size > 0
    ? new Set(
      [...pyproject.directNames, ...pyproject.devNames]
        .map((name) => normalizePackageName(name, "python"))
    )
    : new Set(records.filter((record) => record.isRootDependency).map((record) => record.normalizedName));

  const recordsByName = new Map();
  const incomingCounts = new Map();
  for (const record of records) {
    if (!recordsByName.has(record.normalizedName)) {
      recordsByName.set(record.normalizedName, []);
    }
    recordsByName.get(record.normalizedName).push(record);
    for (const dependencyName of record.dependencies) {
      const normalizedDependencyName = normalizePackageName(dependencyName, "python");
      incomingCounts.set(
        normalizedDependencyName,
        (incomingCounts.get(normalizedDependencyName) || 0) + 1
      );
    }
  }

  const rootRecords = normalizedDirectNames.size > 0
    ? [...normalizedDirectNames].map((name) => (recordsByName.get(name) || [])[0]).filter(Boolean)
    : records.filter((record) => !incomingCounts.get(record.normalizedName));

  const directRoots = deduplicateDeps(rootRecords.map((record) => buildPythonDependency(
    record,
    [],
    recordsByName,
    new Set(),
    sourceFile,
    new Set([...pyproject.devNames].map((name) => normalizePackageName(name, "python")))
  )));

  let dependencies = deduplicateDeps(flattenDependencies(directRoots));
  for (const record of records) {
    const key = `${record.normalizedName}@${record.version.toLowerCase()}`;
    if (dependencies.some((dependency) => (
      `${normalizePackageName(dependency.name, "python")}@${dependency.version.toLowerCase()}` === key
    ))) {
      continue;
    }

    dependencies.push(createDependency({
      name: record.name,
      version: record.version,
      ecosystem: "python",
      isDirect: normalizedDirectNames.has(record.normalizedName),
      parent: null,
      parentChain: [],
      transitives: [],
      sourceFile,
      isDevelopmentDependency: false,
    }));
  }

  return buildTree("python", sourceFile, dependencies);
}

function buildPythonDependency(record, parentChain, recordsByName, visiting, sourceFile, normalizedDevNames) {
  const key = `${record.normalizedName}@${record.version.toLowerCase()}`;
  if (visiting.has(key)) {
    return createDependency({
      name: record.name,
      version: record.version,
      ecosystem: "python",
      isDirect: parentChain.length === 0,
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile,
      isDevelopmentDependency: normalizedDevNames.has(record.normalizedName),
    });
  }

  const nextVisiting = new Set(visiting);
  nextVisiting.add(key);
  const nextParentChain = parentChain.concat(record.name);
  const transitives = [];

  for (const dependencyName of record.dependencies) {
    const normalizedDependencyName = normalizePackageName(dependencyName, "python");
    const childRecord = (recordsByName.get(normalizedDependencyName) || [])[0];
    if (!childRecord) {
      continue;
    }
    transitives.push(buildPythonDependency(
      childRecord,
      nextParentChain,
      recordsByName,
      nextVisiting,
      sourceFile,
      normalizedDevNames
    ));
  }

  return createDependency({
    name: record.name,
    version: record.version,
    ecosystem: "python",
    isDirect: parentChain.length === 0,
    parent: parentChain[parentChain.length - 1] || null,
    parentChain,
    transitives: deduplicateDeps(transitives),
    sourceFile,
    isDevelopmentDependency: normalizedDevNames.has(record.normalizedName),
  });
}

function parsePythonPackageRecords(content, skipEditableRoot) {
  const records = [];
  let current = null;
  let section = "";
  let metadataDirectNames = [];

  const flushCurrent = () => {
    if (!current || !current.name || !current.version) {
      current = null;
      return;
    }
    const isEditableRoot = skipEditableRoot && current.sourceEditable === ".";
    if (!isEditableRoot) {
      records.push({
        ...current,
        normalizedName: normalizePackageName(current.name, "python"),
        isRootDependency: metadataDirectNames.includes(normalizePackageName(current.name, "python")),
      });
    }
    current = null;
  };

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const line = stripTomlComment(rawLine).trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    if (line === "[[package]]") {
      flushCurrent();
      current = {
        name: "",
        version: "",
        dependencies: [],
        sourceEditable: "",
      };
      section = "package";
      continue;
    }

    if (line === "[package.dependencies]") {
      section = "package.dependencies";
      continue;
    }

    if (line === "[metadata]") {
      flushCurrent();
      section = "metadata";
      continue;
    }

    if (line.startsWith("[") && line.endsWith("]")) {
      section = "";
      continue;
    }

    if (section === "package" && current) {
      if (line.startsWith("name =")) {
        current.name = parseKeyValueLine(line).value.replace(/^["']|["']$/g, "");
        continue;
      }
      if (line.startsWith("version =")) {
        current.version = parseKeyValueLine(line).value.replace(/^["']|["']$/g, "");
        continue;
      }
      if (line.startsWith("source =")) {
        current.sourceEditable = parseInlineTomlValue(parseKeyValueLine(line).value, "editable");
        continue;
      }
      if (line.startsWith("dependencies =")) {
        const value = parseKeyValueLine(line).value;
        if (value.startsWith("[")) {
          current.dependencies.push(...parsePythonDependencyArray(value));
        } else if (value.startsWith("{")) {
          current.dependencies.push(...parsePythonDependencyInlineObjects(value));
        }
      }
      continue;
    }

    if (section === "package.dependencies" && current) {
      const parts = parseKeyValueLine(line);
      if (parts && parts.key) {
        current.dependencies.push(parts.key.replace(/^["']|["']$/g, ""));
      }
      continue;
    }

    if (section === "metadata") {
      if (line.startsWith("direct-dependencies =") || line.startsWith("root-dependencies =")) {
        metadataDirectNames = parseQuotedArray(parseKeyValueLine(line).value)
          .map((name) => normalizePackageName(name, "python"));
      }
    }
  }

  flushCurrent();
  return records;
}

function parsePythonDependencyArray(value) {
  const names = [];
  for (const item of parseQuotedArray(value)) {
    const parsed = parseRequirementSpec(item);
    if (parsed) {
      names.push(parsed.name);
    }
  }
  if (names.length > 0) {
    return names;
  }
  return parsePythonDependencyInlineObjects(value);
}

function parsePythonDependencyInlineObjects(value) {
  const names = [];
  const pattern = /name\s*=\s*"([^"]+)"/g;
  for (const match of String(value || "").matchAll(pattern)) {
    names.push(match[1]);
  }
  return names;
}

module.exports = pythonParser;

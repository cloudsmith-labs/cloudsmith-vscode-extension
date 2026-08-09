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
  resolveWorkspaceFilePath,
  stripTomlComment,
} = require("./shared");
const {
  hasCompleteTomlArray,
  parsePyprojectManifest,
  parseRequirementSpec,
} = require("./manifestHelpers");
const { normalizePackageName } = require("../packageNameNormalizer");

const SOURCE_PRIORITY = ["uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt"];
const MAX_REQUIREMENTS_INCLUDE_DEPTH = 32;
const MAX_REQUIREMENTS_FILES = 128;
const MAX_REQUIREMENT_LINE_LENGTH = 64 * 1024;

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
  const rootPath = getWorkspacePath(workspaceFolder) || path.dirname(lockfilePath);
  const state = {
    dependencies: [],
    activePaths: new Set(),
    visitedPaths: new Set(),
    filesRead: 0,
    environmentMarkerCount: 0,
  };

  await parseRequirementsFile(lockfilePath, rootPath, state, 0);

  const warnings = [
    "requirements.txt does not encode transitive dependencies. Showing direct requirements only.",
  ];
  if (state.environmentMarkerCount > 0) {
    warnings.push(
      "Python environment markers were not evaluated. Conditional requirements are retained without a concrete version."
    );
  }

  return buildTree(
    "python",
    getSourceFileName(lockfilePath),
    deduplicateDeps(state.dependencies),
    warnings
  );
}

async function parseRequirementsFile(filePath, workspaceRoot, state, depth) {
  if (depth > MAX_REQUIREMENTS_INCLUDE_DEPTH) {
    throw new Error(`requirements.txt include depth exceeds ${MAX_REQUIREMENTS_INCLUDE_DEPTH}`);
  }

  const safePath = await resolveWorkspaceFilePath(filePath, workspaceRoot);
  if (!safePath) {
    if (depth === 0) {
      throw new Error("Refusing to read files outside the workspace folder.");
    }
    throw new Error("Requirements include paths must stay within the workspace folder.");
  }
  if (state.activePaths.has(safePath)) {
    throw new Error(`Circular requirements.txt include: ${getSourceFileName(safePath)}`);
  }
  if (state.visitedPaths.has(safePath)) {
    return;
  }
  if (state.filesRead >= MAX_REQUIREMENTS_FILES) {
    throw new Error(`requirements.txt includes exceed ${MAX_REQUIREMENTS_FILES} files`);
  }

  state.filesRead += 1;
  state.activePaths.add(safePath);
  try {
    const content = await readUtf8(safePath, workspaceRoot);
    for (const rawLine of buildLogicalRequirementLines(content)) {
      const line = stripRequirementComment(rawLine).trim();
      if (!line) {
        continue;
      }

      const includeTarget = parseRequirementsIncludeTarget(line);
      if (includeTarget) {
        await parseRequirementsFile(
          path.resolve(path.dirname(safePath), includeTarget),
          workspaceRoot,
          state,
          depth + 1
        );
        continue;
      }

      if (line.startsWith("-")) {
        continue;
      }

      const requirementText = stripRequirementOptions(line);
      const marker = getEnvironmentMarker(requirementText);
      const parsed = parseRequirementSpec(requirementText);
      if (!parsed || !isSupportedRequirementConstraint(parsed.declaredConstraint)) {
        throw new Error(`Malformed requirements.txt entry: ${line}`);
      }

      if (marker) {
        state.environmentMarkerCount += 1;
      }
      const dependency = createDependency({
        name: parsed.name,
        version: marker ? "" : getExactRequirementVersion(parsed.declaredConstraint),
        ecosystem: "python",
        isDirect: true,
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile: getSourceFileName(safePath),
        isDevelopmentDependency: false,
      });
      dependency.declaredConstraint = parsed.declaredConstraint;
      dependency.environmentMarker = marker;
      dependency.sourceManifestPath = safePath;
      state.dependencies.push(dependency);
    }
    state.visitedPaths.add(safePath);
  } finally {
    state.activePaths.delete(safePath);
  }
}

function buildLogicalRequirementLines(content) {
  const lines = [];
  let current = "";

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const trimmedEnd = rawLine.trimEnd();
    const continues = trimmedEnd.endsWith("\\");
    const segment = continues ? trimmedEnd.slice(0, -1).trimEnd() : trimmedEnd;
    current += current ? ` ${segment.trimStart()}` : segment;
    if (current.length > MAX_REQUIREMENT_LINE_LENGTH) {
      throw new Error(`requirements.txt entries must not exceed ${MAX_REQUIREMENT_LINE_LENGTH} characters`);
    }
    if (!continues) {
      lines.push(current);
      current = "";
    }
  }

  if (current) {
    lines.push(current);
  }
  return lines;
}

function stripRequirementComment(line) {
  const commentIndex = String(line || "").search(/(^|\s)#/);
  return commentIndex === -1 ? String(line || "") : String(line || "").slice(0, commentIndex).trimEnd();
}

function parseRequirementsIncludeTarget(line) {
  const match = String(line || "").match(/^(?:-r\s*|--requirement(?:\s+|=))(.+)$/i);
  if (!match) {
    return null;
  }

  return match[1].trim().replace(/^["']|["']$/g, "") || null;
}

function stripRequirementOptions(line) {
  const optionMatch = String(line || "").match(/\s+--(?:hash|config-settings|global-option|install-option)(?:=|\s)/);
  return optionMatch ? line.slice(0, optionMatch.index).trim() : String(line || "").trim();
}

function getEnvironmentMarker(requirement) {
  const markerIndex = String(requirement || "").indexOf(";");
  return markerIndex === -1 ? null : String(requirement).slice(markerIndex + 1).trim() || null;
}

function isSupportedRequirementConstraint(constraint) {
  const value = String(constraint || "").trim().replace(/^\(|\)$/g, "").trim();
  return !value || value.startsWith("@") || /^(?:===|==|~=|!=|<=|>=|<|>)/.test(value);
}

function getExactRequirementVersion(constraint) {
  const value = String(constraint || "").trim().replace(/^\(|\)$/g, "").trim();
  const match = value.match(/^(?:===|==)\s*([^\s,]+)$/);
  if (!match || match[1].includes("*")) {
    return "";
  }
  return match[1];
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
    ? [...normalizedDirectNames].flatMap((name) => recordsByName.get(name) || [])
    : records.filter((record) => !incomingCounts.get(record.normalizedName));

  const normalizedDevNames = new Set(
    [...pyproject.devNames].map((name) => normalizePackageName(name, "python"))
  );

  const directRoots = deduplicateDeps(rootRecords.map((record) => buildPythonDependency(
    record,
    [],
    recordsByName,
    new Set(),
    sourceFile,
    normalizedDevNames
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
      isDevelopmentDependency: normalizedDevNames.has(record.normalizedName),
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
    const childRecords = recordsByName.get(normalizedDependencyName) || [];
    for (const childRecord of childRecords) {
      transitives.push(buildPythonDependency(
        childRecord,
        nextParentChain,
        recordsByName,
        nextVisiting,
        sourceFile,
        normalizedDevNames
      ));
    }
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
  let dependencyArrayBuffer = "";
  let metadataArrayBuffer = "";

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

    if (dependencyArrayBuffer) {
      dependencyArrayBuffer += ` ${line}`;
      if (hasCompleteTomlArray(dependencyArrayBuffer)) {
        current.dependencies.push(...parsePythonDependencyArray(dependencyArrayBuffer));
        dependencyArrayBuffer = "";
      }
      continue;
    }

    if (metadataArrayBuffer) {
      metadataArrayBuffer += ` ${line}`;
      if (hasCompleteTomlArray(metadataArrayBuffer)) {
        metadataDirectNames = parseQuotedArray(metadataArrayBuffer)
          .map((name) => normalizePackageName(name, "python"));
        metadataArrayBuffer = "";
      }
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
          if (hasCompleteTomlArray(value)) {
            current.dependencies.push(...parsePythonDependencyArray(value));
          } else {
            dependencyArrayBuffer = value;
          }
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
        const value = parseKeyValueLine(line).value;
        if (hasCompleteTomlArray(value)) {
          metadataDirectNames = parseQuotedArray(value)
            .map((name) => normalizePackageName(name, "python"));
        } else {
          metadataArrayBuffer = value;
        }
      }
    }
  }

  if (dependencyArrayBuffer || metadataArrayBuffer) {
    throw new Error("Malformed Python lockfile: unterminated dependency array");
  }

  flushCurrent();
  for (const record of records) {
    record.isRootDependency = metadataDirectNames.includes(record.normalizedName);
  }
  return records;
}

function parsePythonDependencyArray(value) {
  const inlineObjectNames = parsePythonDependencyInlineObjects(value);
  if (inlineObjectNames.length > 0) {
    return inlineObjectNames;
  }

  const names = [];
  for (const item of parseQuotedArray(value)) {
    const parsed = parseRequirementSpec(item);
    if (parsed) {
      names.push(parsed.name);
    }
  }
  return names;
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

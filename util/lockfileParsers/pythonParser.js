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
const MAX_PYTHON_GRAPH_DEPTH = 128;
const MAX_PYTHON_GRAPH_NODES = 50000;
const MAX_PYTHON_GRAPH_EDGES = 500000;

const pythonParser = {
  name: "pythonParser",
  ecosystem: "python",

  parsePipfileManifest(content, options = {}) {
    return parsePipfileManifest(content, options).dependencies;
  },

  async canResolve(workspaceFolder, options = {}) {
    const matches = await this.detect(workspaceFolder, options);
    return matches.length > 0;
  },

  async detect(workspaceFolder, options = {}) {
    const rootPath = getWorkspacePath(workspaceFolder);
    for (const fileName of SOURCE_PRIORITY) {
      throwIfPythonCancelled(options);
      const lockfilePath = path.join(rootPath, fileName);
      if (await pathExists(lockfilePath, workspaceFolder)) {
        const preferredManifestName = fileName === "Pipfile.lock"
          ? "Pipfile"
          : fileName === "requirements.txt" ? null : "pyproject.toml";
        const preferredManifestPath = preferredManifestName
          ? path.join(rootPath, preferredManifestName)
          : null;
        return [{
          resolverName: this.name,
          ecosystem: this.ecosystem,
          lockfilePath,
          manifestPath: preferredManifestPath
            && await pathExists(preferredManifestPath, workspaceFolder)
            ? preferredManifestPath
            : null,
          sourceFile: fileName,
        }];
      }
    }
    return [];
  },

  async resolve({ lockfilePath, manifestPath, workspaceFolder, options = {} }) {
    throwIfPythonCancelled(options);
    const sourceFile = getSourceFileName(lockfilePath);
    const pyproject = manifestPath
      && getSourceFileName(manifestPath).toLowerCase() === "pyproject.toml"
      && await pathExists(manifestPath, workspaceFolder)
      ? parsePyprojectManifest(await readUtf8(manifestPath, workspaceFolder, options))
      : { projectName: "", dependencies: [], directNames: new Set(), devNames: new Set() };

    if (sourceFile === "requirements.txt") {
      return parseRequirements(lockfilePath, workspaceFolder, options);
    }
    if (sourceFile === "Pipfile.lock") {
      return parsePipfile(lockfilePath, manifestPath, workspaceFolder, options);
    }
    if (sourceFile === "poetry.lock" || sourceFile === "uv.lock") {
      return parseTomlLock(lockfilePath, pyproject, workspaceFolder, sourceFile === "uv.lock", options);
    }

    throw new Error(`Unsupported Python dependency source: ${sourceFile}`);
  },
};

async function parseRequirements(lockfilePath, workspaceFolder, options) {
  const rootPath = getWorkspacePath(workspaceFolder) || path.dirname(lockfilePath);
  const state = {
    dependencies: [],
    activePaths: new Set(),
    visitedPaths: new Set(),
    filesRead: 0,
    environmentMarkerCount: 0,
    options,
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
  throwIfPythonCancelled(state.options);
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
    const content = await readUtf8(safePath, workspaceRoot, state.options);
    for (const rawLine of buildLogicalRequirementLines(content)) {
      throwIfPythonCancelled(state.options);
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
        packageSource: classifyPythonRequirementSource(parsed.declaredConstraint),
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

async function parsePipfile(lockfilePath, manifestPath, workspaceFolder, options) {
  throwIfPythonCancelled(options);
  const root = JSON.parse(await readUtf8(lockfilePath, workspaceFolder, options));
  if (!root || typeof root !== "object" || Array.isArray(root)) {
    throw new Error("Malformed Pipfile.lock: expected a JSON object");
  }
  const manifest = manifestPath && await pathExists(manifestPath, workspaceFolder)
    ? parsePipfileManifest(await readUtf8(manifestPath, workspaceFolder, options), options)
    : { directNames: new Set(), devNames: new Set(), packageSources: new Map() };
  const hasDirectManifest = manifest.directNames.size > 0 || manifest.devNames.size > 0;
  const dependencies = [];
  const defaultNames = new Set(
    Object.keys(root.default || {}).map((name) => normalizePackageName(name, "python"))
  );

  for (const [name, details] of Object.entries(root.default || {})) {
    throwIfPythonCancelled(options);
    const normalizedName = normalizePackageName(name, "python");
    dependencies.push(createDependency({
      name,
      version: normalizeVersion(details && details.version),
      ecosystem: "python",
      isDirect: hasDirectManifest && manifest.directNames.has(normalizedName),
      parent: null,
      parentChain: [],
      transitives: [],
      sourceFile: getSourceFileName(lockfilePath),
      isDevelopmentDependency: false,
      packageSource: classifyPipfileLockSource(details, manifest.packageSources.get(normalizedName)),
    }));
  }

  for (const [name, details] of Object.entries(root.develop || {})) {
    throwIfPythonCancelled(options);
    const normalizedName = normalizePackageName(name, "python");
    dependencies.push(createDependency({
      name,
      version: normalizeVersion(details && details.version),
      ecosystem: "python",
      isDirect: hasDirectManifest && manifest.devNames.has(normalizedName),
      parent: null,
      parentChain: [],
      transitives: [],
      sourceFile: getSourceFileName(lockfilePath),
      isDevelopmentDependency: !defaultNames.has(normalizedName),
      packageSource: classifyPipfileLockSource(details, manifest.packageSources.get(normalizedName)),
    }));
  }

  const warnings = hasDirectManifest
    ? []
    : ["Pipfile was not found, so direct dependency relationships could not be determined."];
  return buildTree(
    "python",
    getSourceFileName(lockfilePath),
    deduplicatePythonDependencies(dependencies),
    warnings
  );
}

async function parseTomlLock(lockfilePath, pyproject, workspaceFolder, skipEditableRoot, options) {
  throwIfPythonCancelled(options);
  const records = parsePythonPackageRecords(
    await readUtf8(lockfilePath, workspaceFolder, options),
    skipEditableRoot,
    options
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
    throwIfPythonCancelled(options);
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
  const normalizedRuntimeNames = new Set(
    [...normalizedDirectNames].filter((name) => !normalizedDevNames.has(name))
  );
  const runtimeRelationshipState = createPythonTraversalState(options);
  const developmentRelationshipState = createPythonTraversalState(options);
  const runtimeReachable = collectReachablePythonRecords(
    normalizedRuntimeNames,
    recordsByName,
    runtimeRelationshipState
  );
  const developmentReachable = collectReachablePythonRecords(
    normalizedDevNames,
    recordsByName,
    developmentRelationshipState
  );
  const developmentOnlyKeys = new Set();
  for (const record of records) {
    const key = pythonRecordKey(record);
    const hasMainGroup = record.groups.includes("main");
    const hasDevelopmentGroup = record.groups.some((group) => group !== "main");
    if (
      (!hasMainGroup && hasDevelopmentGroup)
      || (!record.groups.length && developmentReachable.has(key) && !runtimeReachable.has(key))
    ) {
      developmentOnlyKeys.add(key);
    }
  }

  const traversalState = createPythonTraversalState(options);
  const directRoots = [];
  for (const record of rootRecords) {
    const dependency = buildPythonDependency(
      record,
      [],
      recordsByName,
      new Set(),
      sourceFile,
      normalizedDirectNames,
      developmentOnlyKeys,
      traversalState,
      true
    );
    if (dependency) {
      directRoots.push(dependency);
    }
  }

  let dependencies = deduplicatePythonDependencies(flattenDependencies(directRoots, options));
  const dependencyKeys = new Set(dependencies.map((dependency) => pythonDependencyKey(dependency)));
  for (const record of records) {
    throwIfPythonCancelled(options);
    const key = pythonRecordKey(record);
    if (dependencyKeys.has(key)) {
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
      isDevelopmentDependency: developmentOnlyKeys.has(key),
      packageSource: record.packageSource,
    }));
    dependencyKeys.add(key);
  }

  const warnings = [];
  if (
    runtimeRelationshipState.truncated
    || developmentRelationshipState.truncated
    || traversalState.truncated
  ) {
    warnings.push("Some Python dependency relationships could not be fully analyzed.");
  }
  return buildTree("python", sourceFile, dependencies, warnings);
}

function buildPythonDependency(
  record,
  parentChain,
  recordsByName,
  visiting,
  sourceFile,
  normalizedDirectNames,
  developmentOnlyKeys,
  traversalState,
  forceExpand = false
) {
  throwIfPythonCancelled(traversalState.options);
  const key = pythonRecordKey(record);
  if (visiting.has(key)) {
    return createDependency({
      name: record.name,
      version: record.version,
      ecosystem: "python",
      isDirect: parentChain.length === 0 && normalizedDirectNames.has(record.normalizedName),
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile,
      isDevelopmentDependency: developmentOnlyKeys.has(key),
      packageSource: record.packageSource,
    });
  }

  const nextVisiting = new Set(visiting);
  nextVisiting.add(key);
  const nextParentChain = parentChain.concat(record.name);
  const transitives = [];

  if (!canExpandPythonRecord(parentChain, key, traversalState, forceExpand)) {
    return createDependency({
      name: record.name,
      version: record.version,
      ecosystem: "python",
      isDirect: parentChain.length === 0 && normalizedDirectNames.has(record.normalizedName),
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile,
      isDevelopmentDependency: developmentOnlyKeys.has(key),
      packageSource: record.packageSource,
    });
  }

  for (const dependencyName of record.dependencies) {
    if (!reservePythonEdge(traversalState)) {
      break;
    }
    const normalizedDependencyName = normalizePackageName(dependencyName, "python");
    const childRecords = recordsByName.get(normalizedDependencyName) || [];
    for (const childRecord of childRecords) {
      transitives.push(buildPythonDependency(
        childRecord,
        nextParentChain,
        recordsByName,
        nextVisiting,
        sourceFile,
        normalizedDirectNames,
        developmentOnlyKeys,
        traversalState,
        false
      ));
    }
  }

  return createDependency({
    name: record.name,
    version: record.version,
    ecosystem: "python",
    isDirect: parentChain.length === 0 && normalizedDirectNames.has(record.normalizedName),
    parent: parentChain[parentChain.length - 1] || null,
    parentChain,
    transitives: deduplicatePythonDependencies(transitives),
    sourceFile,
    isDevelopmentDependency: developmentOnlyKeys.has(key),
    packageSource: record.packageSource,
  });
}

function parsePythonPackageRecords(content, skipEditableRoot, options = {}) {
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
    current.packageSource = finalizePythonPackageSource(current);
    const isEditableRoot = skipEditableRoot
      && current.packageSource.kind === "local"
      && current.packageSource.location === ".";
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
    throwIfPythonCancelled(options);
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
        groups: [],
        sourceFields: {},
        packageSource: { kind: "registry" },
      };
      section = "package";
      continue;
    }

    if (line === "[package.dependencies]") {
      section = "package.dependencies";
      continue;
    }

    if (line === "[package.source]") {
      section = "package.source";
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
        current.packageSource = parsePythonInlinePackageSource(parseKeyValueLine(line).value);
        continue;
      }
      if (line.startsWith("groups =")) {
        current.groups = parseQuotedArray(parseKeyValueLine(line).value)
          .map((group) => String(group).trim().toLowerCase())
          .filter(Boolean);
        continue;
      }
      if (line.startsWith("category =")) {
        const category = unquoteTomlScalar(parseKeyValueLine(line).value).toLowerCase();
        current.groups = category ? [category === "main" ? "main" : category] : [];
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

    if (section === "package.source" && current) {
      const parts = parseKeyValueLine(line);
      if (parts && parts.key) {
        current.sourceFields[parts.key] = unquoteTomlScalar(parts.value);
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

function parsePipfileManifest(content, options = {}) {
  const directNames = new Set();
  const devNames = new Set();
  const packageSources = new Map();
  const dependencies = [];
  let section = "";

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    throwIfPythonCancelled(options);
    const line = stripTomlComment(rawLine).trim();
    if (!line) {
      continue;
    }
    if (line.startsWith("[") && line.endsWith("]")) {
      section = line.toLowerCase();
      continue;
    }
    if (!["[packages]", "[dev-packages]"].includes(section)) {
      continue;
    }
    const parts = parseKeyValueLine(line);
    if (!parts) {
      continue;
    }
    const name = unquoteTomlScalar(parts.key);
    const normalizedName = normalizePackageName(name, "python");
    if (!normalizedName) {
      continue;
    }
    const isDevelopmentDependency = section === "[dev-packages]";
    if (isDevelopmentDependency) {
      devNames.add(normalizedName);
    } else {
      directNames.add(normalizedName);
    }
    const packageSource = classifyPipfileManifestSource(parts.value);
    packageSources.set(normalizedName, packageSource);
    const rawValue = String(parts.value || "").trim();
    const declaredConstraint = rawValue.startsWith("{")
      ? parseInlineTomlValue(rawValue, "version") || null
      : unquoteTomlScalar(rawValue) || null;
    dependencies.push({
      name,
      version: normalizeVersion(declaredConstraint || ""),
      declaredConstraint: declaredConstraint === "*" ? null : declaredConstraint,
      isDevelopmentDependency,
      packageSource,
    });
  }

  return { dependencies, directNames, devNames, packageSources };
}

function classifyPipfileManifestSource(rawValue) {
  const value = String(rawValue || "").trim();
  if (!value.startsWith("{")) {
    return classifyPythonRequirementSource(unquoteTomlScalar(value));
  }
  const editable = parseInlineTomlValue(value, "editable");
  const pathValue = parseInlineTomlValue(value, "path");
  const fileValue = parseInlineTomlValue(value, "file");
  const gitValue = parseInlineTomlValue(value, "git");
  if (pathValue || fileValue) {
    return {
      kind: editable === "true" ? "local" : "path",
      location: boundPythonSourceValue(pathValue || fileValue),
    };
  }
  if (gitValue) {
    const reference = parseInlineTomlValue(value, "ref")
      || parseInlineTomlValue(value, "rev")
      || parseInlineTomlValue(value, "branch");
    return {
      kind: "git",
      location: boundPythonSourceValue(gitValue),
      ...(reference ? { revision: boundPythonSourceReference(reference) } : {}),
    };
  }
  return { kind: "registry" };
}

function classifyPipfileLockSource(details, manifestSource) {
  if (manifestSource && manifestSource.kind !== "registry") {
    return manifestSource;
  }
  if (!details || typeof details !== "object" || Array.isArray(details)) {
    return manifestSource || { kind: "registry" };
  }
  const pathValue = details.path || details.file;
  if (pathValue) {
    return {
      kind: details.editable === true ? "local" : "path",
      location: boundPythonSourceValue(pathValue),
    };
  }
  if (details.git) {
    return {
      kind: "git",
      location: boundPythonSourceValue(details.git),
      ...(details.ref ? { revision: boundPythonSourceReference(details.ref) } : {}),
    };
  }
  return manifestSource || { kind: "registry" };
}

function classifyPythonRequirementSource(constraint) {
  const value = String(constraint || "").trim().replace(/^@\s*/, "");
  if (!value) {
    return { kind: "registry" };
  }
  if (/^(?:\.\.?[/\\]|[/\\]|file:)/i.test(value)) {
    return { kind: "path", location: boundPythonSourceValue(value) };
  }
  if (/^(?:git\+|git:|ssh:)|\.git(?:#|$)/i.test(value)) {
    return { kind: "git", location: boundPythonSourceValue(value) };
  }
  if (/^(?:https?|ftp):/i.test(value)) {
    return { kind: "unknown", location: boundPythonSourceValue(value) };
  }
  return { kind: "registry" };
}

function parsePythonInlinePackageSource(value) {
  const sourceType = parseInlineTomlValue(value, "type").toLowerCase();
  const editable = parseInlineTomlValue(value, "editable");
  if (editable) {
    return { kind: "local", location: boundPythonSourceValue(editable) };
  }
  const virtual = parseInlineTomlValue(value, "virtual");
  if (virtual) {
    return { kind: "local", location: boundPythonSourceValue(virtual) };
  }
  const pathValue = parseInlineTomlValue(value, "path");
  if (pathValue) {
    return { kind: "path", location: boundPythonSourceValue(pathValue) };
  }
  const gitValue = parseInlineTomlValue(value, "git")
    || (sourceType === "git" ? parseInlineTomlValue(value, "url") : "");
  if (gitValue) {
    const revision = parseInlineTomlValue(value, "rev")
      || parseInlineTomlValue(value, "revision")
      || parseInlineTomlValue(value, "resolved_reference")
      || parseInlineTomlValue(value, "reference");
    return {
      kind: "git",
      location: boundPythonSourceValue(gitValue),
      ...(revision ? { revision: boundPythonSourceReference(revision) } : {}),
    };
  }
  if (parseInlineTomlValue(value, "registry")) {
    return { kind: "registry" };
  }
  const url = parseInlineTomlValue(value, "url");
  return url
    ? { kind: "unknown", location: boundPythonSourceValue(url) }
    : { kind: "registry" };
}

function finalizePythonPackageSource(record) {
  if (record.packageSource && record.packageSource.kind !== "registry") {
    return record.packageSource;
  }
  const fields = record.sourceFields || {};
  const type = String(fields.type || "").trim().toLowerCase();
  const location = fields.url || fields.path || "";
  if (type === "git") {
    return {
      kind: "git",
      ...(location ? { location: boundPythonSourceValue(location) } : {}),
      ...(fields.resolved_reference || fields.reference
        ? { revision: boundPythonSourceReference(fields.resolved_reference || fields.reference) }
        : {}),
    };
  }
  if (["directory", "file", "path"].includes(type)) {
    return {
      kind: "path",
      ...(location ? { location: boundPythonSourceValue(location) } : {}),
    };
  }
  if (type && !["legacy", "supplemental", "explicit"].includes(type)) {
    return {
      kind: "unknown",
      ...(location ? { location: boundPythonSourceValue(location) } : {}),
    };
  }
  return record.packageSource || { kind: "registry" };
}

function createPythonTraversalState(options = {}) {
  return {
    options,
    expandedKeys: new Set(),
    expandedNodes: 0,
    edges: 0,
    truncated: false,
    maxDepth: lowerOnlyPythonLimit(options.pythonGraphMaxDepth, MAX_PYTHON_GRAPH_DEPTH),
    maxNodes: lowerOnlyPythonLimit(options.pythonGraphMaxNodes, MAX_PYTHON_GRAPH_NODES),
    maxEdges: lowerOnlyPythonLimit(options.pythonGraphMaxEdges, MAX_PYTHON_GRAPH_EDGES),
  };
}

function lowerOnlyPythonLimit(requested, maximum) {
  return Number.isSafeInteger(requested) && requested > 0
    ? Math.min(requested, maximum)
    : maximum;
}

function canExpandPythonRecord(parentChain, key, state, forceExpand) {
  if (parentChain.length >= state.maxDepth) {
    state.truncated = true;
    return false;
  }
  if (state.expandedKeys.has(key) && !forceExpand) {
    return false;
  }
  if (state.expandedNodes >= state.maxNodes) {
    state.truncated = true;
    return false;
  }
  state.expandedKeys.add(key);
  state.expandedNodes += 1;
  return true;
}

function reservePythonEdge(state) {
  if (state.edges >= state.maxEdges) {
    state.truncated = true;
    return false;
  }
  state.edges += 1;
  return true;
}

function collectReachablePythonRecords(rootNames, recordsByName, state) {
  const reachable = new Set();
  const stack = [...rootNames].flatMap((name) => (
    (recordsByName.get(name) || []).map((record) => ({ record, depth: 0 }))
  ));
  while (stack.length > 0) {
    throwIfPythonCancelled(state.options);
    const { record, depth } = stack.pop();
    const key = pythonRecordKey(record);
    if (reachable.has(key)) {
      continue;
    }
    if (reachable.size >= state.maxNodes) {
      state.truncated = true;
      break;
    }
    reachable.add(key);
    if (depth >= state.maxDepth) {
      if (record.dependencies.length > 0) {
        state.truncated = true;
      }
      continue;
    }
    for (const dependencyName of record.dependencies) {
      if (!reservePythonEdge(state)) {
        break;
      }
      const childRecords = recordsByName.get(normalizePackageName(dependencyName, "python")) || [];
      for (const childRecord of childRecords) {
        stack.push({ record: childRecord, depth: depth + 1 });
      }
    }
  }
  return reachable;
}

function pythonRecordKey(record) {
  return JSON.stringify([
    record.normalizedName,
    String(record.version || ""),
    record.packageSource || null,
  ]);
}

function pythonDependencyKey(dependency) {
  return JSON.stringify([
    normalizePackageName(dependency && dependency.name, "python"),
    String(dependency && dependency.version || ""),
    dependency && dependency.packageSource || null,
  ]);
}

function deduplicatePythonDependencies(dependencies) {
  const unique = [];
  const indexes = new Map();
  for (const dependency of Array.isArray(dependencies) ? dependencies : []) {
    const key = pythonDependencyKey(dependency);
    if (!indexes.has(key)) {
      indexes.set(key, unique.length);
      unique.push(dependency);
      continue;
    }
    const index = indexes.get(key);
    const existing = unique[index];
    if (!existing.isDirect && dependency.isDirect) {
      unique[index] = dependency;
      continue;
    }
    if (
      !existing.isDirect
      && existing.parentChain.length === 0
      && dependency.parentChain.length > 0
    ) {
      unique[index] = { ...existing, parent: dependency.parent, parentChain: dependency.parentChain.slice() };
    }
  }
  return unique;
}

function unquoteTomlScalar(value) {
  const normalized = String(value || "").trim();
  return normalized.length >= 2
    && ((normalized.startsWith('"') && normalized.endsWith('"'))
      || (normalized.startsWith("'") && normalized.endsWith("'")))
    ? normalized.slice(1, -1)
    : normalized;
}

function boundPythonSourceValue(value) {
  return String(value || "").trim().slice(0, 4096);
}

function boundPythonSourceReference(value) {
  return String(value || "").trim().slice(0, 1024);
}

function throwIfPythonCancelled(options) {
  const cancelled = Boolean(
    options
    && (
      (options.cancellationToken && options.cancellationToken.isCancellationRequested)
      || (typeof options.shouldCancel === "function" && options.shouldCancel())
    )
  );
  if (!cancelled) {
    return;
  }
  const error = new Error("Dependency parsing was canceled.");
  error.code = "ERR_DEPENDENCY_PARSING_CANCELLED";
  throw error;
}

module.exports = pythonParser;

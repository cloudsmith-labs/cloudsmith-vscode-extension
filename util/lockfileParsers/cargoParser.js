// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  buildTree,
  createDependency,
  getSourceFileName,
  getWorkspacePath,
  parseInlineTomlValue,
  parseKeyValueLine,
  pathExists,
  readUtf8,
  stripTomlComment,
} = require("./shared");
const { parseCargoTomlManifest } = require("./manifestHelpers");

const MAX_CARGO_GRAPH_DEPTH = 128;
const MAX_CARGO_GRAPH_NODES = 10000;
const MAX_CARGO_GRAPH_EDGES = 50000;

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

  async resolve({ lockfilePath, manifestPath, workspaceFolder, options = {} }) {
    throwIfCargoCancelled(options.cancellationToken);
    const manifestContent = manifestPath && await pathExists(manifestPath, workspaceFolder)
      ? await readUtf8(manifestPath, workspaceFolder, options)
      : "";
    const manifest = parseCargoManifest(manifestContent);
    const manifestDependencies = manifest.dependencies;
    const sourceFile = getSourceFileName(lockfilePath || manifestPath);
    const graphState = createCargoGraphState(options);

    if (!lockfilePath) {
      const dependencies = manifestDependencies.map((dependency) => {
        throwIfCargoCancelled(options.cancellationToken);
        return createCargoDependency({
          name: dependency.name,
          version: dependency.version,
          ecosystem: "cargo",
          isDirect: true,
          parent: null,
          parentChain: [],
          transitives: [],
          sourceFile,
          isDevelopmentDependency: dependency.isDevelopmentDependency,
        }, dependency);
      });
      return buildTree("cargo", sourceFile, dependencies);
    }

    const records = parseCargoLock(await readUtf8(lockfilePath, workspaceFolder, options));
    throwIfCargoCancelled(options.cancellationToken);
    const projectRecord = selectCargoProjectRecord(records, manifest.project);
    const packageRecords = records.filter((record) => record !== projectRecord);
    if (packageRecords.length === 0) {
      throw new Error("Malformed Cargo.lock: no package entries found");
    }
    const recordsByName = new Map();

    for (const record of packageRecords) {
      throwIfCargoCancelled(options.cancellationToken);
      if (!recordsByName.has(record.name.toLowerCase())) {
        recordsByName.set(record.name.toLowerCase(), []);
      }
      recordsByName.get(record.name.toLowerCase()).push(record);
    }

    const rootSelections = manifestDependencies.map((dependency) => ({
      dependency,
      record: selectDirectCargoRecord(recordsByName, projectRecord, dependency),
    }));
    const directDeclarations = new Map();
    for (const selection of rootSelections) {
      if (!selection.record) {
        continue;
      }
      const key = cargoRecordKey(selection.record);
      const existing = directDeclarations.get(key);
      directDeclarations.set(key, {
        dependency: existing ? existing.dependency : selection.dependency,
        isDevelopmentDependency: Boolean(
          (existing && existing.isDevelopmentDependency)
          || selection.dependency.isDevelopmentDependency
        ),
      });
    }

    const relationships = buildCargoRelationships({
      rootSelections,
      recordsByName,
      inventoryKeys: new Set(packageRecords.map(cargoRecordKey)),
      graphState,
      cancellationToken: options.cancellationToken,
    });
    const dependencies = materializeCargoInventory({
      packageRecords,
      directDeclarations,
      relationships,
      sourceFile,
      cancellationToken: options.cancellationToken,
    });

    for (const { dependency, record } of rootSelections) {
      throwIfCargoCancelled(options.cancellationToken);
      if (record) {
        continue;
      }
      dependencies.push(createCargoDependency({
        name: dependency.name,
        version: "",
        ecosystem: "cargo",
        isDirect: true,
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: dependency.isDevelopmentDependency,
      }, dependency));
    }

    return {
      ecosystem: "cargo",
      sourceFile,
      dependencies,
      warnings: cargoGraphWarnings(graphState),
    };
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
    records.push(current);
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
      const parsedDependency = parseCargoDependencyReference(
        line.trim().replace(/,$/, "").replace(/^"|"$/g, "")
      );
      if (parsedDependency) {
        current.dependencies.push(parsedDependency);
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
          const parsedDependency = parseCargoDependencyReference(cleaned);
          if (parsedDependency) {
            current.dependencies.push(parsedDependency);
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
    const key = cargoRecordKey(record);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    results.push(record);
  }
  return results;
}

function selectCargoRecord(recordsByName, name, version, source = "") {
  const candidates = recordsByName.get(name.toLowerCase()) || [];
  if (candidates.length === 0) {
    return null;
  }
  if (version) {
    const versionMatches = candidates.filter((record) => record.version === version);
    const exactMatch = source
      ? versionMatches.find((record) => record.source === source)
      : versionMatches.length === 1 ? versionMatches[0] : null;
    if (exactMatch) {
      return exactMatch;
    }
  }
  return candidates.length === 1 ? candidates[0] : null;
}

function buildCargoRelationships({
  rootSelections,
  recordsByName,
  inventoryKeys,
  graphState,
  cancellationToken,
}) {
  const parents = new Map();
  const children = new Map();
  const depths = new Map();
  const visited = new Set();
  const queue = [];

  for (const { record } of rootSelections) {
    throwIfCargoCancelled(cancellationToken);
    if (!record) {
      continue;
    }
    const key = cargoRecordKey(record);
    if (visited.has(key)) {
      continue;
    }
    if (!reserveCargoGraphNode(graphState)) {
      continue;
    }
    visited.add(key);
    depths.set(key, 0);
    queue.push({ record, key, depth: 0, parentChain: [] });
  }

  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    throwIfCargoCancelled(cancellationToken);
    const current = queue[cursor];
    if (current.depth >= graphState.maxDepth) {
      if (current.record.dependencies.some((reference) => {
        const child = selectCargoRecord(
          recordsByName,
          reference.name,
          reference.version,
          reference.source
        );
        return child && inventoryKeys.has(cargoRecordKey(child));
      })) {
        graphState.depthLimitReached = true;
      }
      continue;
    }

    for (const reference of current.record.dependencies) {
      throwIfCargoCancelled(cancellationToken);
      if (!reserveCargoGraphEdge(graphState)) {
        break;
      }
      const child = selectCargoRecord(
        recordsByName,
        reference.name,
        reference.version,
        reference.source
      );
      if (!child) {
        continue;
      }
      const childKey = cargoRecordKey(child);
      if (!inventoryKeys.has(childKey) || visited.has(childKey)) {
        continue;
      }
      if (!reserveCargoGraphNode(graphState)) {
        break;
      }

      const childParentChain = current.parentChain.concat(current.record.name);
      visited.add(childKey);
      depths.set(childKey, current.depth + 1);
      parents.set(childKey, {
        parentKey: current.key,
        parentName: current.record.name,
        parentChain: childParentChain,
      });
      if (!children.has(current.key)) {
        children.set(current.key, []);
      }
      children.get(current.key).push(childKey);
      queue.push({
        record: child,
        key: childKey,
        depth: current.depth + 1,
        parentChain: childParentChain,
      });
    }
  }

  return { parents, children, depths };
}

function materializeCargoInventory({
  packageRecords,
  directDeclarations,
  relationships,
  sourceFile,
  cancellationToken,
}) {
  const recordsByKey = new Map(packageRecords.map((record) => [cargoRecordKey(record), record]));
  const orderedKeys = packageRecords
    .map(cargoRecordKey)
    .sort((left, right) => (
      (relationships.depths.get(right) ?? -1) - (relationships.depths.get(left) ?? -1)
    ));
  const materialized = new Map();

  for (const key of orderedKeys) {
    throwIfCargoCancelled(cancellationToken);
    const record = recordsByKey.get(key);
    const declaration = directDeclarations.get(key) || null;
    const parent = relationships.parents.get(key) || null;
    const transitives = (relationships.children.get(key) || [])
      .map((childKey) => materialized.get(childKey))
      .filter(Boolean);
    const dependency = createDependency({
      name: record.name,
      version: record.version,
      ecosystem: "cargo",
      isDirect: Boolean(declaration),
      parent: parent && parent.parentName || null,
      parentChain: parent ? parent.parentChain : [],
      transitives,
      sourceFile,
      // Development is a property of a direct Cargo root, not every package
      // reachable below that root.
      isDevelopmentDependency: Boolean(declaration && declaration.isDevelopmentDependency),
    });
    materialized.set(key, attachCargoDeclaration({
      ...dependency,
      cargoSource: record.source || null,
      packageSource: cargoPackageSourceForRecord(record),
    }, declaration && declaration.dependency));
  }

  return packageRecords.map((record) => {
    const key = cargoRecordKey(record);
    const dependency = materialized.get(key);
    // Only direct roots need nested relationship objects for presentation.
    // Every lock record remains a top-level inventory entry, but shallow
    // non-roots avoid re-adapting the same descendant subtree repeatedly.
    return directDeclarations.has(key)
      ? dependency
      : { ...dependency, transitives: [] };
  });
}

function createCargoGraphState(options) {
  return {
    maxDepth: boundedCargoGraphLimit(
      options && options.cargoGraphMaxDepth,
      MAX_CARGO_GRAPH_DEPTH
    ),
    maxNodes: boundedCargoGraphLimit(
      options && options.cargoGraphMaxNodes,
      MAX_CARGO_GRAPH_NODES
    ),
    maxEdges: boundedCargoGraphLimit(
      options && options.cargoGraphMaxEdges,
      MAX_CARGO_GRAPH_EDGES
    ),
    expandedNodes: 0,
    expandedEdges: 0,
    depthLimitReached: false,
    nodeLimitReached: false,
    edgeLimitReached: false,
  };
}

function boundedCargoGraphLimit(value, maximum) {
  const numericValue = Number(value);
  if (!Number.isSafeInteger(numericValue) || numericValue <= 0) {
    return maximum;
  }
  return Math.min(numericValue, maximum);
}

function reserveCargoGraphNode(graphState) {
  if (graphState.expandedNodes >= graphState.maxNodes) {
    graphState.nodeLimitReached = true;
    return false;
  }
  graphState.expandedNodes += 1;
  return true;
}

function reserveCargoGraphEdge(graphState) {
  if (graphState.expandedEdges >= graphState.maxEdges) {
    graphState.edgeLimitReached = true;
    return false;
  }
  graphState.expandedEdges += 1;
  return true;
}

function cargoGraphWarnings(graphState) {
  return graphState.depthLimitReached || graphState.nodeLimitReached || graphState.edgeLimitReached
    ? ["Some Cargo dependency relationships were omitted to keep the scan responsive. Package inventory remains complete."]
    : [];
}

function parseCargoManifest(content) {
  const dependencies = parseCargoTomlManifest(content);
  const declarations = new Map();
  const project = { name: "", version: "" };
  let section = "";

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const line = stripTomlComment(rawLine).trim();
    if (!line) {
      continue;
    }
    if (line.startsWith("[") && line.endsWith("]")) {
      section = line;
      continue;
    }

    const parts = parseKeyValueLine(line);
    if (!parts) {
      continue;
    }
    if (section === "[package]" && (parts.key === "name" || parts.key === "version")) {
      project[parts.key] = unquote(parts.value);
      continue;
    }
    if (!["[dependencies]", "[dev-dependencies]", "[build-dependencies]", "[workspace.dependencies]"].includes(section)) {
      continue;
    }

    const actualName = parseInlineTomlValue(parts.value, "package") || parts.key;
    const isDevelopmentDependency = section !== "[dependencies]" && section !== "[workspace.dependencies]";
    const key = cargoManifestDependencyKey(actualName, isDevelopmentDependency);
    if (!declarations.has(key)) {
      declarations.set(key, []);
    }
    const declaredConstraint = getCargoDeclaredConstraint(parts.value);
    declarations.get(key).push({
      declaredConstraint,
      versionState: classifyCargoDeclaredConstraint(declaredConstraint),
      packageSource: cargoPackageSourceForDeclaration(parts.value),
    });
  }

  return {
    project,
    dependencies: dependencies.map((dependency) => {
      const key = cargoManifestDependencyKey(dependency.name, dependency.isDevelopmentDependency);
      const declaration = declarations.get(key) && declarations.get(key).shift();
      return {
        ...dependency,
        version: declaration && declaration.versionState === "incomplete"
          ? ""
          : dependency.version,
        declaredConstraint: declaration && declaration.declaredConstraint || null,
        versionState: declaration && declaration.versionState || "unresolved",
        packageSource: declaration && declaration.packageSource || { kind: "registry" },
      };
    }),
  };
}

function getCargoDeclaredConstraint(rawValue) {
  const value = String(rawValue || "").trim();
  if (!value.startsWith("{")) {
    return unquote(value) || null;
  }

  const localPath = parseInlineTomlValue(value, "path");
  if (localPath) {
    return `path:${localPath}`;
  }
  const gitUrl = parseInlineTomlValue(value, "git");
  if (gitUrl) {
    return `git:${gitUrl}`;
  }
  if (/\bworkspace\s*=\s*true\b/.test(value)) {
    return "workspace:*";
  }
  const version = parseInlineTomlValue(value, "version");
  if (version) {
    return version;
  }
  return value || null;
}

function classifyCargoDeclaredConstraint(declaredConstraint) {
  const value = String(declaredConstraint || "").trim();
  if (!value) {
    return "unresolved";
  }
  if (/^(?:path|git|workspace):/i.test(value) || value.startsWith("{")) {
    return "incomplete";
  }
  return /^=\s*v?\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$/.test(value)
    ? "exact-declaration"
    : "range";
}

function selectCargoProjectRecord(records, project) {
  if (!project.name) {
    return null;
  }
  const candidates = records.filter((record) => (
    !record.source
    && record.name.toLowerCase() === project.name.toLowerCase()
  ));
  if (project.version) {
    const exact = candidates.find((record) => record.version === project.version);
    if (exact) {
      return exact;
    }
  }
  return candidates.length === 1 ? candidates[0] : null;
}

function selectDirectCargoRecord(recordsByName, projectRecord, dependency) {
  const rootReferences = projectRecord
    ? projectRecord.dependencies.filter((candidate) => (
      candidate.name.toLowerCase() === dependency.name.toLowerCase()
    ))
    : [];
  if (rootReferences.length === 1) {
    return selectCargoRecord(
      recordsByName,
      rootReferences[0].name,
      rootReferences[0].version,
      rootReferences[0].source
    );
  }

  if (dependency.versionState === "incomplete") {
    return null;
  }

  const exactVersion = getExactCargoDeclarationVersion(dependency.declaredConstraint);
  if (rootReferences.length > 1 && exactVersion) {
    const rootReference = rootReferences.find((candidate) => candidate.version === exactVersion);
    return rootReference
      ? selectCargoRecord(recordsByName, rootReference.name, rootReference.version)
      : null;
  }

  const candidates = recordsByName.get(dependency.name.toLowerCase()) || [];
  if (exactVersion) {
    return candidates.find((candidate) => candidate.version === exactVersion) || null;
  }
  return candidates.length === 1 ? candidates[0] : null;
}

function getExactCargoDeclarationVersion(declaredConstraint) {
  const match = String(declaredConstraint || "").trim().match(
    /^=\s*(v?\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?)$/
  );
  return match ? match[1].replace(/^v/, "") : "";
}

function parseCargoDependencyReference(reference) {
  const match = String(reference || "").trim().match(
    /^(\S+?)(?:\s+([^\s()]+))?(?:\s+\(([^)]*)\))?$/
  );
  if (!match) {
    return null;
  }
  return { name: match[1], version: match[2] || "", source: match[3] || "" };
}

function createCargoDependency(values, declaration) {
  return attachCargoDeclaration({
    ...createDependency(values),
    packageSource: declaration && declaration.packageSource || { kind: "registry" },
  }, declaration);
}

function attachCargoDeclaration(dependency, declaration) {
  return {
    ...dependency,
    declaredConstraint: declaration && declaration.declaredConstraint || null,
    versionState: declaration && declaration.versionState || null,
  };
}

function cargoManifestDependencyKey(name, isDevelopmentDependency) {
  return `${String(name || "").toLowerCase()}:${isDevelopmentDependency ? "development" : "runtime"}`;
}

function cargoRecordKey(record) {
  return JSON.stringify([
    record.name.toLowerCase(),
    record.version,
    String(record.source || "").trim(),
  ]);
}

function cargoPackageSourceForDeclaration(rawValue) {
  const value = String(rawValue || "").trim();
  const localPath = parseInlineTomlValue(value, "path");
  if (localPath) {
    return { kind: "path", location: localPath };
  }
  const gitUrl = parseInlineTomlValue(value, "git");
  if (gitUrl) {
    return { kind: "git", location: gitUrl };
  }
  if (/\bworkspace\s*=\s*true\b/.test(value)) {
    return { kind: "local" };
  }
  return { kind: "registry" };
}

function cargoPackageSourceForRecord(record) {
  const rawSource = String(record && record.source || "").trim();
  if (!rawSource) {
    return { kind: "local" };
  }
  for (const [prefix, kind] of [
    ["registry+", "registry"],
    ["sparse+", "registry"],
    ["git+", "git"],
    ["path+", "path"],
  ]) {
    if (rawSource.startsWith(prefix)) {
      return { kind, location: rawSource.slice(prefix.length) };
    }
  }
  return { kind: "unknown" };
}

function throwIfCargoCancelled(cancellationToken) {
  if (!cancellationToken || cancellationToken.isCancellationRequested !== true) {
    return;
  }
  const error = new Error("Cargo dependency parsing was canceled.");
  error.code = "dependency-scan-cancelled";
  throw error;
}

function unquote(value) {
  return String(value || "").trim().replace(/^["']|["']$/g, "");
}

module.exports = cargoParser;

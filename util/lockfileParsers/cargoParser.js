// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  buildTree,
  createDependency,
  deduplicateDeps,
  flattenDependencies,
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
    const manifestContent = manifestPath && await pathExists(manifestPath, workspaceFolder)
      ? await readUtf8(manifestPath, workspaceFolder)
      : "";
    const manifest = parseCargoManifest(manifestContent);
    const manifestDependencies = manifest.dependencies;
    const sourceFile = getSourceFileName(lockfilePath || manifestPath);
    const graphState = createCargoGraphState(options);

    if (!lockfilePath) {
      const dependencies = [];
      for (const dependency of manifestDependencies) {
        if (!reserveCargoGraphNode(graphState)) {
          break;
        }
        dependencies.push(createCargoDependency({
          name: dependency.name,
          version: dependency.version,
          ecosystem: "cargo",
          isDirect: true,
          parent: null,
          parentChain: [],
          transitives: [],
          sourceFile,
          isDevelopmentDependency: dependency.isDevelopmentDependency,
        }, dependency));
      }
      return buildTree("cargo", sourceFile, dependencies, cargoGraphWarnings(graphState));
    }

    const records = parseCargoLock(await readUtf8(lockfilePath, workspaceFolder));
    const packageRecords = records.filter(isRegistryCargoRecord);
    if (packageRecords.length === 0) {
      throw new Error("Malformed Cargo.lock: no package entries found");
    }
    const recordsByName = new Map();

    for (const record of packageRecords) {
      if (!recordsByName.has(record.name.toLowerCase())) {
        recordsByName.set(record.name.toLowerCase(), []);
      }
      recordsByName.get(record.name.toLowerCase()).push(record);
    }

    const projectRecord = selectCargoProjectRecord(records, manifest.project);
    const rootSelections = manifestDependencies.map((dependency) => ({
      dependency,
      record: selectDirectCargoRecord(recordsByName, projectRecord, dependency),
    }));
    const directRecordKeys = new Set(
      rootSelections
        .filter((selection) => selection.record)
        .map((selection) => cargoRecordKey(selection.record))
    );

    const directRootCandidates = [];
    for (const { dependency, record } of rootSelections) {
      if (graphState.nodeLimitReached) {
        break;
      }
      if (record) {
        const resolvedDependency = buildCargoDependency(
          record,
          [],
          recordsByName,
          new Set(),
          sourceFile,
          dependency.isDevelopmentDependency,
          graphState
        );
        if (resolvedDependency) {
          directRootCandidates.push(attachCargoDeclaration(resolvedDependency, dependency));
        }
        continue;
      }

      if (!reserveCargoGraphNode(graphState)) {
        break;
      }
      directRootCandidates.push(createCargoDependency({
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
    const directRoots = deduplicateDeps(directRootCandidates);

    const dependencies = deduplicateDeps(flattenDependencies(directRoots));
    const dependencyKeys = new Set(dependencies.map(cargoDependencyKey));
    for (const record of packageRecords) {
      const key = cargoRecordKey(record);
      if (dependencyKeys.has(key)) {
        continue;
      }
      if (!reserveCargoGraphNode(graphState)) {
        break;
      }
      dependencies.push(createDependency({
        name: record.name,
        version: record.version,
        ecosystem: "cargo",
        isDirect: directRecordKeys.has(key),
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: false,
      }));
      dependencyKeys.add(key);
    }

    return buildTree("cargo", sourceFile, dependencies, cargoGraphWarnings(graphState));
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
    const key = `${record.name.toLowerCase()}@${record.version}`;
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
  return candidates.length === 1 ? candidates[0] : null;
}

function buildCargoDependency(
  record,
  parentChain,
  recordsByName,
  visiting,
  sourceFile,
  inheritedDevelopment,
  graphState
) {
  if (!reserveCargoGraphNode(graphState)) {
    return null;
  }

  const key = cargoRecordKey(record);
  if (visiting.has(key)) {
    return createCargoLockDependency(record, parentChain, [], sourceFile, inheritedDevelopment);
  }

  const nextVisiting = new Set(visiting);
  nextVisiting.add(key);

  if (parentChain.length >= graphState.maxDepth) {
    const hasUnvisitedChild = record.dependencies.some((dependency) => {
      const childRecord = selectCargoRecord(recordsByName, dependency.name, dependency.version);
      return childRecord && !nextVisiting.has(cargoRecordKey(childRecord));
    });
    if (hasUnvisitedChild) {
      graphState.depthLimitReached = true;
    }
    return createCargoLockDependency(record, parentChain, [], sourceFile, inheritedDevelopment);
  }

  const nextParentChain = parentChain.concat(record.name);
  const transitives = [];

  for (const dependency of record.dependencies) {
    const childRecord = selectCargoRecord(recordsByName, dependency.name, dependency.version);
    if (!childRecord) {
      continue;
    }
    const childDependency = buildCargoDependency(
      childRecord,
      nextParentChain,
      recordsByName,
      nextVisiting,
      sourceFile,
      inheritedDevelopment,
      graphState
    );
    if (childDependency) {
      transitives.push(childDependency);
    }
    if (graphState.nodeLimitReached) {
      break;
    }
  }

  return createCargoLockDependency(
    record,
    parentChain,
    deduplicateDeps(transitives),
    sourceFile,
    inheritedDevelopment
  );
}

function createCargoLockDependency(record, parentChain, transitives, sourceFile, inheritedDevelopment) {
  return createDependency({
    name: record.name,
    version: record.version,
    ecosystem: "cargo",
    isDirect: parentChain.length === 0,
    parent: parentChain[parentChain.length - 1] || null,
    parentChain,
    transitives,
    sourceFile,
    isDevelopmentDependency: inheritedDevelopment,
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
    expandedNodes: 0,
    depthLimitReached: false,
    nodeLimitReached: false,
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

function cargoGraphWarnings(graphState) {
  const warnings = [];
  if (graphState.depthLimitReached) {
    warnings.push(
      `Cargo dependency graph exceeded the maximum depth of ${graphState.maxDepth}; nested dependency paths were truncated.`
    );
  }
  if (graphState.nodeLimitReached) {
    warnings.push(
      `Cargo dependency graph exceeded the maximum expansion of ${graphState.maxNodes} nodes; results are incomplete.`
    );
  }
  return warnings;
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
    !isRegistryCargoRecord(record)
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
  if (dependency.versionState === "incomplete") {
    return null;
  }

  const rootReferences = projectRecord
    ? projectRecord.dependencies.filter((candidate) => (
      candidate.name.toLowerCase() === dependency.name.toLowerCase()
    ))
    : [];
  if (rootReferences.length === 1) {
    return selectCargoRecord(recordsByName, rootReferences[0].name, rootReferences[0].version);
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
    /^(\S+?)(?:\s+([^\s()]+))?(?:\s+\([^)]*\))?$/
  );
  if (!match) {
    return null;
  }
  return { name: match[1], version: match[2] || "" };
}

function isRegistryCargoRecord(record) {
  const source = String(record && record.source || "").trim();
  return Boolean(source) && !source.startsWith("path+") && !source.startsWith("git+");
}

function createCargoDependency(values, declaration) {
  return attachCargoDeclaration(createDependency(values), declaration);
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
  return `${record.name.toLowerCase()}@${record.version}`;
}

function cargoDependencyKey(dependency) {
  return `${dependency.name.toLowerCase()}@${dependency.version}`;
}

function unquote(value) {
  return String(value || "").trim().replace(/^["']|["']$/g, "");
}

module.exports = cargoParser;

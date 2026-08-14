// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  createDependency,
  flattenDependencies,
  getSourceFileName,
  getWorkspacePath,
  pathExists,
  readBoundedDirectoryEntries,
  readJson,
  readUtf8,
  resolveWorkspaceFilePath,
  throwIfTraversalCancelled,
} = require("./shared");
const { parseCsprojManifest } = require("./manifestHelpers");

const MAX_NUGET_GRAPH_DEPTH = 128;
const MAX_NUGET_GRAPH_NODES = 10000;
const MAX_NUGET_GRAPH_EDGES = 50000;
const MAX_NUGET_TARGET_FRAMEWORK_LENGTH = 256;

const nugetParser = {
  name: "nugetParser",
  ecosystem: "nuget",

  async canResolve(workspaceFolder, options = {}) {
    const matches = await this.detect(workspaceFolder, options);
    return matches.length > 0;
  },

  async detect(workspaceFolder, options = {}) {
    throwIfTraversalCancelled(options.cancellationToken);
    const rootPath = getWorkspacePath(workspaceFolder);
    const safeRootPath = await resolveWorkspaceFilePath(rootPath, workspaceFolder);
    if (!safeRootPath) {
      return [];
    }
    const directory = await readBoundedDirectoryEntries(safeRootPath, undefined, {
      ...options,
      workspaceFolder,
    });
    const entries = directory.entries
      .filter((entry) => entry.isFile())
      .map((entry) => entry.name)
      .sort((left, right) => left.localeCompare(right));
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

  async resolve({ lockfilePath, manifestPath, workspaceFolder, options = {} }) {
    throwIfNugetCancelled(options.cancellationToken);
    const sourceFile = getSourceFileName(lockfilePath || manifestPath);
    const manifestDependencies = manifestPath && await pathExists(manifestPath, workspaceFolder)
      ? parseCsprojManifest(await readUtf8(manifestPath, workspaceFolder, options))
      : [];
    if (!lockfilePath) {
      return buildNugetTree(sourceFile, manifestDependencies.map((dependency) => createNugetDependency({
        name: dependency.name,
        version: dependency.version,
        ecosystem: "nuget",
        isDirect: true,
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: dependency.isDevelopmentDependency,
      }, null)));
    }

    const root = await readJson(lockfilePath, workspaceFolder, options);
    const dependencyRoot = root && root.dependencies && typeof root.dependencies === "object"
      ? root.dependencies
      : null;
    if (!dependencyRoot) {
      throw new Error("Malformed packages.lock.json: missing dependencies object");
    }

    const dependencies = [];
    const graphState = createNugetGraphState(options);
    for (const [targetFramework, frameworkDependencies] of Object.entries(dependencyRoot)) {
      throwIfNugetCancelled(options.cancellationToken);
      if (!frameworkDependencies || typeof frameworkDependencies !== "object") {
        continue;
      }
      const normalizedTargetFramework = normalizeNugetTargetFramework(targetFramework);

      const recordsByName = new Map();
      for (const [name, details] of Object.entries(frameworkDependencies)) {
        throwIfNugetCancelled(options.cancellationToken);
        const dependencies = details && details.dependencies && typeof details.dependencies === "object"
          ? Object.keys(details.dependencies)
          : [];
        recordsByName.set(name.toLowerCase(), {
          name,
          version: details.resolved || "",
          dependencies: deduplicateStringValues(dependencies),
          isDirect: String(details.type || "").toLowerCase() === "direct",
          targetFramework: normalizedTargetFramework,
        });
      }

      // packages.lock.json records directness per target framework. A
      // manifest-wide package-name set cannot safely override that evidence.
      const rootRecords = [...recordsByName.values()].filter((record) => record.isDirect);

      const directRoots = deduplicateNugetDependencies(rootRecords.map((record) => buildNugetDependency(
        record,
        [],
        recordsByName,
        new Set(),
        sourceFile,
        graphState,
        options.cancellationToken
      )).filter(Boolean));
      const frameworkResults = deduplicateNugetDependencies(flattenDependencies(directRoots, {
        cancellationToken: options.cancellationToken,
      }));

      for (const record of recordsByName.values()) {
        throwIfNugetCancelled(options.cancellationToken);
        const key = `${record.name.toLowerCase()}@${record.version.toLowerCase()}`;
        if (frameworkResults.some((dependency) => `${dependency.name.toLowerCase()}@${dependency.version.toLowerCase()}` === key)) {
          continue;
        }
        frameworkResults.push(createNugetDependency({
          name: record.name,
          version: record.version,
          ecosystem: "nuget",
          isDirect: record.isDirect,
          parent: null,
          parentChain: [],
          transitives: [],
          sourceFile,
          isDevelopmentDependency: false,
        }, normalizedTargetFramework));
      }

      dependencies.push(...frameworkResults);
    }

    return buildNugetTree(sourceFile, dependencies, nugetGraphWarnings(graphState));
  },
};

function buildNugetDependency(
  record,
  parentChain,
  recordsByName,
  visiting,
  sourceFile,
  graphState,
  cancellationToken
) {
  throwIfNugetCancelled(cancellationToken);
  const key = nugetRecordKey(record);
  if (visiting.has(key)) {
    return createNugetLockDependency(record, parentChain, [], sourceFile);
  }
  if (graphState.expanded.has(key)) {
    return createNugetLockDependency(record, parentChain, [], sourceFile);
  }
  if (!reserveNugetGraphNode(graphState)) {
    return null;
  }
  graphState.expanded.add(key);

  const nextVisiting = new Set(visiting);
  nextVisiting.add(key);
  if (parentChain.length >= graphState.maxDepth) {
    if (record.dependencies.length > 0) {
      graphState.depthLimitReached = true;
    }
    return createNugetLockDependency(record, parentChain, [], sourceFile);
  }
  const nextParentChain = parentChain.concat(record.name);
  const transitives = [];

  for (const dependencyName of record.dependencies) {
    throwIfNugetCancelled(cancellationToken);
    if (!reserveNugetGraphEdge(graphState)) {
      break;
    }
    const childRecord = recordsByName.get(dependencyName.toLowerCase());
    if (!childRecord) {
      continue;
    }
    const childDependency = buildNugetDependency(
      childRecord,
      nextParentChain,
      recordsByName,
      nextVisiting,
      sourceFile,
      graphState,
      cancellationToken
    );
    if (childDependency) {
      transitives.push(childDependency);
    }
  }

  return createNugetLockDependency(
    record,
    parentChain,
    deduplicateNugetDependencies(transitives),
    sourceFile
  );
}

function createNugetLockDependency(record, parentChain, transitives, sourceFile) {
  return createNugetDependency({
    name: record.name,
    version: record.version,
    ecosystem: "nuget",
    isDirect: record.isDirect,
    parent: parentChain[parentChain.length - 1] || null,
    parentChain,
    transitives,
    sourceFile,
    isDevelopmentDependency: false,
  }, record.targetFramework);
}

function createNugetDependency(values, targetFramework) {
  const normalizedFramework = String(targetFramework || "").trim() || null;
  return {
    ...createDependency(values),
    targetFramework: normalizedFramework,
    qualifiers: normalizedFramework ? { targetFramework: normalizedFramework } : {},
    packageSource: { kind: "registry" },
  };
}

function deduplicateNugetDependencies(dependencies) {
  const unique = [];
  const seen = new Set();
  for (const dependency of dependencies) {
    if (!dependency) {
      continue;
    }
    const key = JSON.stringify([
      dependency.name.toLowerCase(),
      dependency.version.toLowerCase(),
      dependency.targetFramework || "",
      dependency.parentChain || [],
      dependency.isDirect,
    ]);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(dependency);
  }
  return unique;
}

function buildNugetTree(sourceFile, dependencies, warnings = []) {
  return {
    ecosystem: "nuget",
    sourceFile,
    dependencies: deduplicateNugetDependencies(dependencies),
    warnings: Array.isArray(warnings) ? warnings.slice() : [],
  };
}

function createNugetGraphState(options) {
  return {
    maxDepth: boundedNugetGraphLimit(options.nugetGraphMaxDepth, MAX_NUGET_GRAPH_DEPTH),
    maxNodes: boundedNugetGraphLimit(options.nugetGraphMaxNodes, MAX_NUGET_GRAPH_NODES),
    maxEdges: boundedNugetGraphLimit(options.nugetGraphMaxEdges, MAX_NUGET_GRAPH_EDGES),
    nodeCount: 0,
    edgeCount: 0,
    depthLimitReached: false,
    nodeLimitReached: false,
    edgeLimitReached: false,
    expanded: new Set(),
  };
}

function boundedNugetGraphLimit(value, maximum) {
  const numeric = Number(value);
  return Number.isSafeInteger(numeric) && numeric > 0 ? Math.min(numeric, maximum) : maximum;
}

function reserveNugetGraphNode(state) {
  if (state.nodeCount >= state.maxNodes) {
    state.nodeLimitReached = true;
    return false;
  }
  state.nodeCount += 1;
  return true;
}

function reserveNugetGraphEdge(state) {
  if (state.edgeCount >= state.maxEdges) {
    state.edgeLimitReached = true;
    return false;
  }
  state.edgeCount += 1;
  return true;
}

function nugetGraphWarnings(state) {
  return state.depthLimitReached || state.nodeLimitReached || state.edgeLimitReached
    ? ["Some NuGet dependency relationships were omitted to keep the scan responsive. Package inventory remains complete."]
    : [];
}

function nugetRecordKey(record) {
  return JSON.stringify([
    record.name.toLowerCase(),
    record.version.toLowerCase(),
    record.targetFramework || "",
  ]);
}

function normalizeNugetTargetFramework(value) {
  const normalized = String(value || "").trim();
  if (
    !normalized
    || normalized.length > MAX_NUGET_TARGET_FRAMEWORK_LENGTH
    || /[\0\r\n]/.test(normalized)
  ) {
    throw new Error("NuGet target framework metadata could not be parsed safely.");
  }
  return normalized;
}

function throwIfNugetCancelled(cancellationToken) {
  if (!cancellationToken || cancellationToken.isCancellationRequested !== true) {
    return;
  }
  const error = new Error("NuGet dependency parsing was canceled.");
  error.code = "dependency-scan-cancelled";
  throw error;
}

function deduplicateStringValues(values) {
  return [...new Set(values.filter(Boolean))];
}

module.exports = nugetParser;

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
  pathExists,
  readUtf8,
  stripYamlComment,
} = require("./shared");
const { parsePackageJsonManifest } = require("./manifestHelpers");

const LOCKFILE_NAMES = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"];
const MAX_GRAPH_DEPTH = 128;
const MAX_GRAPH_NODES = 50000;
const MAX_GRAPH_EDGES = 500000;

const npmParser = {
  name: "npmParser",
  ecosystem: "npm",

  async canResolve(workspaceFolder, options = {}) {
    const matches = await this.detect(workspaceFolder, options);
    return matches.length > 0;
  },

  async detect(workspaceFolder, options = {}) {
    const rootPath = getWorkspacePath(workspaceFolder);
    for (const fileName of LOCKFILE_NAMES) {
      throwIfNpmCancelled(options);
      const lockfilePath = path.join(rootPath, fileName);
      if (await pathExists(lockfilePath, workspaceFolder)) {
        const manifestPath = await pathExists(path.join(rootPath, "package.json"), workspaceFolder)
          ? path.join(rootPath, "package.json")
          : null;
        return [{
          resolverName: this.name,
          ecosystem: this.ecosystem,
          lockfilePath,
          manifestPath,
          sourceFile: fileName,
        }];
      }
    }
    return [];
  },

  async resolve({ lockfilePath, manifestPath, workspaceFolder, options = {} }) {
    throwIfNpmCancelled(options);
    const sourceFile = getSourceFileName(lockfilePath);
    let manifest = { dependencies: [], directNames: new Set(), devNames: new Set() };
    if (manifestPath && await pathExists(manifestPath, workspaceFolder)) {
      const content = await readUtf8(manifestPath, workspaceFolder, options);
      try {
        JSON.parse(content);
      } catch {
        throw new Error("Malformed package.json: invalid JSON");
      }
      manifest = parsePackageJsonManifest(content);
    }

    if (sourceFile === "package-lock.json") {
      return parsePackageLock(lockfilePath, manifest, workspaceFolder, options);
    }

    if (sourceFile === "yarn.lock") {
      return parseYarnLock(lockfilePath, manifest, workspaceFolder, options);
    }

    if (sourceFile === "pnpm-lock.yaml") {
      return parsePnpmLock(lockfilePath, manifest, workspaceFolder, options);
    }

    throw new Error(`Unsupported npm lockfile: ${sourceFile}`);
  },
};

async function parsePackageLock(lockfilePath, manifest, workspaceFolder, options) {
  const warnings = [];
  throwIfNpmCancelled(options);

  const root = JSON.parse(await readUtf8(lockfilePath, workspaceFolder, options));
  const packages = root && typeof root === "object" && root.packages && typeof root.packages === "object"
    ? root.packages
    : null;

  if (!packages) {
    throw new Error("Malformed package-lock.json: missing packages object");
  }

  const rootEntry = packages[""] || {};
  const rootDependencyMap = {
    ...(rootEntry.dependencies || {}),
    ...(rootEntry.optionalDependencies || {}),
    ...(rootEntry.devDependencies || {}),
  };

  const entriesByPath = new Map();
  const uniqueEntries = new Map();
  const developmentEvidenceByIdentity = new Map();

  for (const [packagePath, packageInfo] of Object.entries(packages)) {
    throwIfNpmCancelled(options);
    if (packagePath === "" || !packageInfo || typeof packageInfo !== "object") {
      continue;
    }

    const installedName = extractPackageLockName(packagePath);
    const name = String(packageInfo.name || installedName || "").trim();
    const version = String(packageInfo.version || "").trim();
    // Local file/workspace links are not registry resolution evidence. Keep a
    // direct declaration unresolved instead of looking up the workspace's own
    // package/version in Cloudsmith.
    if (!installedName || !name || !version || packageInfo.link === true) {
      continue;
    }

    const occurrenceKey = packagePath;
    const identityKey = npmPackageVersionKey(name, version);
    const dependencies = {
      ...(packageInfo.dependencies || {}),
      ...(packageInfo.optionalDependencies || {}),
    };
    const sourceHints = createNpmSourceHints({
      resolutions: [packageInfo.resolved],
    });
    const packageSource = classifyNpmPackageSource(sourceHints);
    const entry = {
      key: occurrenceKey,
      packagePath,
      installedName,
      name,
      version,
      dependencies,
      isDevelopmentDependency: packageInfo.dev === true,
      sourceHints,
      packageSource,
      hasResolutionEvidence: packageSource.kind === "registry",
    };
    entriesByPath.set(packagePath, entry);
    recordPackageLockDevelopmentEvidence(
      developmentEvidenceByIdentity,
      identityKey,
      entry.isDevelopmentDependency
    );
    if (!uniqueEntries.has(identityKey)) {
      uniqueEntries.set(identityKey, entry);
    }
  }

  const directNames = manifest.directNames.size > 0 || manifest.devNames.size > 0
    ? new Set([...manifest.directNames, ...manifest.devNames])
    : new Set(Object.keys(rootDependencyMap));

  const directRoots = [];
  const seenDirectKeys = new Set();
  const traversalState = createGraphTraversalState(options);
  const dependencyGraph = buildPackageLockGraph(entriesByPath, directNames, manifest, traversalState);

  for (const directName of directNames) {
    const manifestReference = manifest.dependencies.find((dependency) => (
      dependency.name === directName
    ));
    const directSourceHints = {
      specifiers: [
        rootDependencyMap[directName],
        manifestReference && (manifestReference.declaredConstraint || manifestReference.version),
      ],
    };
    const entry = selectPackageLockEntry(entriesByPath, "", directName);
    const directEntry = applyNpmSourceHints(entry, directSourceHints);
    const dependency = buildNpmDependency(directEntry, directName, [], entriesByPath, new Set(), {
      sourceFile: getSourceFileName(lockfilePath),
      devNames: manifest.devNames,
    }, manifest.devNames.has(directName), traversalState, true) || createNpmDependency({
      name: directEntry ? directEntry.name : directName,
      version: directEntry ? directEntry.version : "",
      ecosystem: "npm",
      isDirect: true,
      parent: null,
      parentChain: [],
      transitives: [],
      sourceFile: getSourceFileName(lockfilePath),
      isDevelopmentDependency: manifest.devNames.has(directName)
        || Boolean(directEntry && directEntry.isDevelopmentDependency),
      packageSource: directEntry
        ? directEntry.packageSource
        : classifyNpmPackageSource(directSourceHints),
      hasResolutionEvidence: Boolean(directEntry && directEntry.hasResolutionEvidence),
    }, directEntry ? directEntry.installedName : directName);
    const key = npmPackageVersionKey(dependency.name, dependency.version);
    if (!seenDirectKeys.has(key)) {
      seenDirectKeys.add(key);
      directRoots.push(dependency);
    }
  }

  let dependencies = deduplicateDeps(flattenDependencies(directRoots, {
    cancellationToken: options.cancellationToken,
  }));
  const addedKeys = new Set();
  collectDependencyKeys(dependencies, addedKeys);
  for (const entry of uniqueEntries.values()) {
    const key = npmPackageVersionKey(entry.name, entry.version);
    if (addedKeys.has(key)) {
      continue;
    }
    addedKeys.add(key);
    dependencies.push(createNpmDependency({
      name: entry.name,
      version: entry.version,
      ecosystem: "npm",
      isDirect: false,
      parent: null,
      parentChain: [],
      transitives: [],
      sourceFile: getSourceFileName(lockfilePath),
      isDevelopmentDependency: entry.isDevelopmentDependency,
      packageSource: entry.packageSource,
      hasResolutionEvidence: entry.hasResolutionEvidence,
    }, entry.installedName));
  }
  dependencies = normalizePackageLockArtifactDevelopment(
    dependencies,
    developmentEvidenceByIdentity
  );

  if (options.maxDependenciesToScan && dependencies.length > options.maxDependenciesToScan) {
    warnings.push("Some dependencies are hidden by the configured display setting. Package inventory remains complete.");
  }
  appendGraphLimitWarning(warnings, traversalState);
  publishGraphMetrics(options, traversalState, entriesByPath.size, uniqueEntries.size);

  return {
    ...buildTree("npm", getSourceFileName(lockfilePath), dependencies, warnings),
    dependencyGraph,
  };
}

function buildPackageLockGraph(entriesByPath, directNames, manifest, traversalState) {
  const graphEntries = [];
  const includedKeys = new Set();
  let edgeCount = 0;

  for (const entry of entriesByPath.values()) {
    throwIfNpmCancelled(traversalState.options);
    if (graphEntries.length >= traversalState.maxNodes) {
      traversalState.nodeLimitReached = true;
      traversalState.truncated = true;
      break;
    }
    const edges = [];
    for (const declaredName in entry.dependencies || {}) {
      if (!Object.prototype.hasOwnProperty.call(entry.dependencies, declaredName)) {
        continue;
      }
      if (edgeCount >= traversalState.maxEdges) {
        traversalState.edgeLimitReached = true;
        traversalState.truncated = true;
        break;
      }
      const child = selectPackageLockEntry(entriesByPath, entry.packagePath, declaredName);
      traversalState.structuralEdgesExamined += 1;
      edgeCount += 1;
      if (child) {
        traversalState.resolvedEdges += 1;
      } else {
        traversalState.unresolvedEdges += 1;
      }
      edges.push(Object.freeze({
        declaredName,
        childKey: child ? child.key : null,
      }));
    }
    includedKeys.add(entry.key);
    graphEntries.push(Object.freeze({
      key: entry.key,
      name: entry.name,
      installedName: entry.installedName,
      version: entry.version,
      isDevelopmentDependency: entry.isDevelopmentDependency,
      edges: Object.freeze(edges),
    }));
  }

  const roots = [...directNames].map((declaredName) => {
    const entry = selectPackageLockEntry(entriesByPath, "", declaredName);
    return Object.freeze({
      declaredName,
      // Keep the authoritative occurrence key even when the structural graph
      // was truncated before indexing it. Consumers can then distinguish a
      // resolved-but-omitted root from a genuinely unresolved declaration.
      entryKey: entry ? entry.key : null,
      isDevelopmentDependency: manifest.devNames.has(declaredName),
    });
  });

  let hasOmittedRelationships = traversalState.nodeLimitReached
    || traversalState.edgeLimitReached;
  if (!hasOmittedRelationships) {
    hasOmittedRelationships = graphEntries.some((entry) => entry.edges.some((edge) => (
      edge.childKey && !includedKeys.has(edge.childKey)
    )));
  }
  if (hasOmittedRelationships) {
    traversalState.truncated = true;
  }

  return Object.freeze({
    kind: "package-lock",
    entries: Object.freeze(graphEntries),
    roots: Object.freeze(roots),
    incomplete: hasOmittedRelationships,
    maxDepth: traversalState.maxDepth,
    maxNodes: traversalState.maxNodes,
    maxEdges: traversalState.maxEdges,
  });
}

function collectDependencyKeys(dependencies, addedKeys) {
  for (const dependency of Array.isArray(dependencies) ? dependencies : []) {
    addedKeys.add(npmPackageVersionKey(dependency.name, dependency.version));
    if (Array.isArray(dependency.transitives) && dependency.transitives.length > 0) {
      collectDependencyKeys(dependency.transitives, addedKeys);
    }
  }
}

function buildNpmDependency(
  entry,
  fallbackName,
  parentChain,
  entriesByPath,
  visiting,
  context,
  inheritedDevelopment,
  traversalState,
  forceExpand = false
) {
  throwIfNpmCancelled(traversalState && traversalState.options);
  if (!reserveMaterializedNode(parentChain, traversalState)) {
    return null;
  }
  if (!entry) {
    return createNpmDependency({
      name: fallbackName,
      version: "",
      ecosystem: "npm",
      isDirect: parentChain.length === 0,
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile: context.sourceFile,
      isDevelopmentDependency: inheritedDevelopment
        || (parentChain.length === 0 && context.devNames.has(fallbackName)),
      packageSource: classifyNpmPackageSource(),
      hasResolutionEvidence: false,
    }, fallbackName);
  }

  if (visiting.has(entry.key)) {
    traversalState.cycleEdgesSkipped += 1;
    return createNpmDependency({
      name: entry.name,
      version: entry.version,
      ecosystem: "npm",
      isDirect: parentChain.length === 0,
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile: context.sourceFile,
      isDevelopmentDependency: inheritedDevelopment || entry.isDevelopmentDependency,
      packageSource: entry.packageSource,
      hasResolutionEvidence: entry.hasResolutionEvidence,
    }, entry.installedName);
  }

  const nextVisiting = new Set(visiting);
  nextVisiting.add(entry.key);
  const nextParentChain = parentChain.concat(entry.name);
  const transitives = [];
  const isDevelopmentDependency = inheritedDevelopment
    || entry.isDevelopmentDependency;

  if (!canExpandGraphNode(parentChain, entry.key, traversalState, forceExpand)) {
    return createNpmDependency({
      name: entry.name,
      version: entry.version,
      ecosystem: "npm",
      isDirect: parentChain.length === 0,
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile: context.sourceFile,
      isDevelopmentDependency,
      packageSource: entry.packageSource,
      hasResolutionEvidence: entry.hasResolutionEvidence,
    }, entry.installedName);
  }

  for (const dependencyName of Object.keys(entry.dependencies || {})) {
    const childEntry = applyNpmSourceHints(
      selectPackageLockEntry(entriesByPath, entry.packagePath, dependencyName),
      { specifiers: [entry.dependencies[dependencyName]] }
    );
    if (childEntry && nextVisiting.has(childEntry.key)) {
      traversalState.cycleEdgesSkipped += 1;
      continue;
    }
    const childDependency = buildNpmDependency(
      childEntry,
      dependencyName,
      nextParentChain,
      entriesByPath,
      nextVisiting,
      context,
      isDevelopmentDependency,
      traversalState,
      false
    );
    if (childDependency) {
      transitives.push(childDependency);
    }
  }

  return createNpmDependency({
    name: entry.name,
    version: entry.version,
    ecosystem: "npm",
    isDirect: parentChain.length === 0,
    parent: parentChain[parentChain.length - 1] || null,
    parentChain,
    transitives: deduplicateDeps(transitives),
    sourceFile: context.sourceFile,
    isDevelopmentDependency,
    packageSource: entry.packageSource,
    hasResolutionEvidence: entry.hasResolutionEvidence,
  }, entry.installedName);
}

function recordPackageLockDevelopmentEvidence(evidenceByIdentity, identityKey, isDevelopment) {
  const evidence = evidenceByIdentity.get(identityKey) || {
    hasDevelopmentOccurrence: false,
    hasProductionOccurrence: false,
  };
  if (isDevelopment) {
    evidence.hasDevelopmentOccurrence = true;
  } else {
    evidence.hasProductionOccurrence = true;
  }
  evidenceByIdentity.set(identityKey, evidence);
}

function normalizePackageLockArtifactDevelopment(dependencies, evidenceByIdentity) {
  return (Array.isArray(dependencies) ? dependencies : []).map((dependency) => {
    const identityKey = npmPackageVersionKey(dependency.name, dependency.version);
    const evidence = evidenceByIdentity.get(identityKey);
    if (!evidence) {
      return dependency;
    }
    const isDevelopmentDependency = evidence.hasDevelopmentOccurrence
      && !evidence.hasProductionOccurrence;
    if (dependency.isDevelopmentDependency === isDevelopmentDependency) {
      return dependency;
    }
    return {
      ...dependency,
      isDevelopmentDependency,
    };
  });
}

function selectPackageLockEntry(entriesByPath, parentPackagePath, dependencyName) {
  let searchPath = String(parentPackagePath || "");
  while (true) {
    const candidatePath = searchPath
      ? `${searchPath}/node_modules/${dependencyName}`
      : `node_modules/${dependencyName}`;
    if (entriesByPath.has(candidatePath)) {
      return entriesByPath.get(candidatePath);
    }

    const nestedMarker = searchPath.lastIndexOf("/node_modules/");
    if (nestedMarker !== -1) {
      searchPath = searchPath.slice(0, nestedMarker);
      continue;
    }
    if (searchPath) {
      searchPath = "";
      continue;
    }
    return null;
  }
}

function extractPackageLockName(packagePath) {
  const marker = "node_modules/";
  const lastMarkerIndex = packagePath.lastIndexOf(marker);
  if (lastMarkerIndex === -1) {
    return "";
  }
  const relativePath = packagePath.slice(lastMarkerIndex + marker.length);
  const segments = relativePath.split("/").filter(Boolean);
  if (segments.length === 0) {
    return "";
  }
  if (segments[0].startsWith("@") && segments.length >= 2) {
    return `${segments[0]}/${segments[1]}`;
  }
  return segments[0];
}

async function parseYarnLock(lockfilePath, manifest, workspaceFolder, options) {
  throwIfNpmCancelled(options);
  const content = await readUtf8(lockfilePath, workspaceFolder, options);
  const parsed = parseYarnEntries(content, options);
  if (parsed.entries.size === 0) {
    throw new Error("Malformed yarn.lock: no package entries found");
  }

  const sourceFile = getSourceFileName(lockfilePath);
  const manifestVersionHints = new Map();
  for (const dependency of manifest.dependencies) {
    manifestVersionHints.set(
      dependency.name,
      dependency.declaredConstraint || dependency.version
    );
  }
  const directNames = manifest.directNames.size > 0 || manifest.devNames.size > 0
    ? new Set([...manifest.directNames, ...manifest.devNames])
    : new Set([...parsed.entries.values()].map((entry) => entry.name));

  const directRoots = [];
  const traversalState = createGraphTraversalState(options);
  for (const directName of directNames) {
    throwIfNpmCancelled(options);
    const entry = applyNpmSourceHints(
      selectYarnEntry(parsed, directName, manifestVersionHints.get(directName)),
      { specifiers: [manifestVersionHints.get(directName)] }
    );
    directRoots.push(buildYarnDependency(
      entry,
      directName,
      [],
      parsed,
      new Set(),
      sourceFile,
      manifest.devNames,
      false,
      traversalState,
      true
    ));
  }

  let dependencies = deduplicateDeps(flattenDependencies(directRoots, {
    cancellationToken: options.cancellationToken,
  }));
  for (const entry of parsed.entries.values()) {
    const key = npmPackageVersionKey(entry.name, entry.version);
    if (dependencies.some((dependency) => npmPackageVersionKey(
      dependency.name,
      dependency.version
    ) === key)) {
      continue;
    }
    dependencies.push(createNpmDependency({
      name: entry.name,
      version: entry.version,
      ecosystem: "npm",
      isDirect: false,
      parent: null,
      parentChain: [],
      transitives: [],
      sourceFile,
      isDevelopmentDependency: manifest.devNames.has(entry.installedName || entry.name),
      packageSource: entry.packageSource,
      hasResolutionEvidence: entry.hasResolutionEvidence,
    }, entry.installedName || entry.name));
  }

  const warnings = [];
  if (options.maxDependenciesToScan && dependencies.length > options.maxDependenciesToScan) {
    warnings.push("Some dependencies are hidden by the configured display setting. Package inventory remains complete.");
  }
  appendGraphLimitWarning(warnings, traversalState);
  publishGraphMetrics(options, traversalState, parsed.entries.size, countUniqueNpmIdentities(parsed.entries.values()));

  return buildTree("npm", sourceFile, dependencies, warnings);
}

function buildYarnDependency(
  entry,
  fallbackName,
  parentChain,
  parsedEntries,
  visiting,
  sourceFile,
  devNames,
  inheritedDevelopment = false,
  traversalState,
  forceExpand = false
) {
  throwIfNpmCancelled(traversalState && traversalState.options);
  if (!entry) {
    return createNpmDependency({
      name: fallbackName,
      version: "",
      ecosystem: "npm",
      isDirect: parentChain.length === 0,
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile,
      isDevelopmentDependency: inheritedDevelopment || devNames.has(fallbackName),
      packageSource: classifyNpmPackageSource(),
      hasResolutionEvidence: false,
    }, fallbackName);
  }

  const key = entry.key || npmPackageVersionKey(entry.name, entry.version);
  if (visiting.has(key)) {
    traversalState.cycleEdgesSkipped += 1;
    return createNpmDependency({
      name: entry.name,
      version: entry.version,
      ecosystem: "npm",
      isDirect: parentChain.length === 0,
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile,
      isDevelopmentDependency: inheritedDevelopment || devNames.has(entry.installedName || entry.name),
      packageSource: entry.packageSource,
      hasResolutionEvidence: entry.hasResolutionEvidence,
    }, entry.installedName || entry.name);
  }

  const nextVisiting = new Set(visiting);
  nextVisiting.add(key);
  const nextParentChain = parentChain.concat(entry.name);
  const transitives = [];
  const isDevelopmentDependency = inheritedDevelopment
    || devNames.has(entry.installedName || entry.name);

  if (!canExpandGraphNode(parentChain, key, traversalState, forceExpand)) {
    return createNpmDependency({
      name: entry.name,
      version: entry.version,
      ecosystem: "npm",
      isDirect: parentChain.length === 0,
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile,
      isDevelopmentDependency,
      packageSource: entry.packageSource,
      hasResolutionEvidence: entry.hasResolutionEvidence,
    }, entry.installedName || entry.name);
  }

  for (const dependencyName of Object.keys(entry.dependencies || {})) {
    if (!reserveNpmRelationshipEdge(traversalState)) {
      break;
    }
    const versionHint = entry.dependencies[dependencyName];
    const childEntry = applyNpmSourceHints(
      selectYarnEntry(parsedEntries, dependencyName, versionHint),
      { specifiers: [versionHint] }
    );
    if (childEntry) {
      traversalState.resolvedEdges += 1;
    } else {
      traversalState.unresolvedEdges += 1;
    }
    transitives.push(buildYarnDependency(
      childEntry,
      dependencyName,
      nextParentChain,
      parsedEntries,
      nextVisiting,
      sourceFile,
      devNames,
      isDevelopmentDependency,
      traversalState,
      false
    ));
  }

  return createNpmDependency({
    name: entry.name,
    version: entry.version,
    ecosystem: "npm",
    isDirect: parentChain.length === 0,
    parent: parentChain[parentChain.length - 1] || null,
    parentChain,
    transitives: deduplicateDeps(transitives),
    sourceFile,
    isDevelopmentDependency,
    packageSource: entry.packageSource,
    hasResolutionEvidence: entry.hasResolutionEvidence,
  }, entry.installedName || entry.name);
}

function parseYarnEntries(content, options = {}) {
  const entries = new Map();
  const entriesByName = new Map();
  const selectorIndex = new Map();
  const lines = String(content || "").split(/\r?\n/);
  let currentEntry = null;
  let inDependencies = false;

  const flushCurrent = () => {
    if (currentEntry && currentEntry.name && currentEntry.version) {
      const key = JSON.stringify((currentEntry.selectors || []).slice().sort());
      currentEntry.sourceHints = createNpmSourceHints({
        specifiers: currentEntry.selectors || [],
        resolutions: [currentEntry.resolution],
      });
      currentEntry.packageSource = classifyNpmPackageSource(currentEntry.sourceHints);
      currentEntry.hasResolutionEvidence = currentEntry.packageSource.kind === "registry";
      const existing = entries.get(key);
      if (existing) {
        Object.assign(existing.dependencies, currentEntry.dependencies);
        for (const selector of currentEntry.selectors || []) {
          if (!existing.selectors.includes(selector)) {
            existing.selectors.push(selector);
          }
          selectorIndex.set(selector, key);
        }
      } else {
        currentEntry.key = key;
        entries.set(key, currentEntry);
        if (!entriesByName.has(currentEntry.installedName)) {
          entriesByName.set(currentEntry.installedName, []);
        }
        entriesByName.get(currentEntry.installedName).push(currentEntry);
        for (const selector of currentEntry.selectors || []) {
          selectorIndex.set(selector, key);
        }
      }
    }
    currentEntry = null;
    inDependencies = false;
  };

  for (const rawLine of lines) {
    throwIfNpmCancelled(options);
    const line = rawLine.replace(/\r$/, "");
    const trimmed = line.trim();
    if (!trimmed) {
      flushCurrent();
      continue;
    }
    if (trimmed === "__metadata:") {
      flushCurrent();
      continue;
    }

    if (!line.startsWith(" ")) {
      flushCurrent();
      const header = trimmed.replace(/:$/, "");
      const selectors = header.split(",").map((selector) => selector.trim().replace(/^["']|["']$/g, ""));
      const primarySelector = selectors[0] || "";
      const installedName = parseYarnSelectorName(primarySelector);
      if (!installedName) {
        continue;
      }
      const alias = parseNpmAliasSpecifier(primarySelector.slice(installedName.length + 1));
      currentEntry = {
        name: alias ? alias.name : installedName,
        installedName,
        version: "",
        dependencies: {},
        selectors,
        resolution: "",
      };
      continue;
    }

    if (!currentEntry) {
      continue;
    }

    if (trimmed === "dependencies:") {
      inDependencies = true;
      continue;
    }

    const versionMatch = trimmed.match(/^version(?:\s+|:\s*)["']?([^"'\s]+)["']?/);
    if (versionMatch) {
      currentEntry.version = versionMatch[1];
      inDependencies = false;
      continue;
    }

    const resolutionMatch = trimmed.match(/^resolution(?:\s+|:\s*)["']?(.+?)["']?$/);
    if (resolutionMatch) {
      currentEntry.resolution = resolutionMatch[1].replace(/^['"]|['"]$/g, "");
      inDependencies = false;
      continue;
    }

    if (inDependencies) {
      const dependencyMatch = trimmed.match(/^("[^"]+"|'[^']+'|[^:\s]+)(?:\s*:\s*|\s+)["']?([^"'\s]+)["']?/);
      if (!dependencyMatch) {
        continue;
      }
      const dependencyName = dependencyMatch[1].replace(/^["']|["']$/g, "");
      currentEntry.dependencies[dependencyName] = dependencyMatch[2];
    }
  }

  flushCurrent();
  return {
    entries,
    entriesByName,
    selectorIndex,
  };
}

function selectYarnEntry(parsedEntries, dependencyName, versionHint) {
  if (!parsedEntries || !dependencyName) {
    return null;
  }

  const normalizedName = String(dependencyName || "").trim();
  if (!normalizedName) {
    return null;
  }

  const normalizedHint = String(versionHint || "").trim().replace(/^["']|["']$/g, "");
  if (normalizedHint) {
    for (const exactSelectorKey of [
      `${normalizedName}@${normalizedHint}`,
      `${normalizedName}@npm:${normalizedHint}`,
    ]) {
      const selectedKey = parsedEntries.selectorIndex.get(exactSelectorKey);
      if (selectedKey && parsedEntries.entries.has(selectedKey)) {
        return parsedEntries.entries.get(selectedKey);
      }
    }
  }

  const candidates = parsedEntries.entriesByName.get(normalizedName) || [];
  if (candidates.length === 0) {
    return null;
  }

  if (normalizedHint) {
    const exactVersionMatch = candidates.find((entry) => entry.version === normalizedHint);
    if (exactVersionMatch) {
      return exactVersionMatch;
    }
  }

  return candidates[0];
}

function parseNpmAliasSpecifier(specifier) {
  const value = String(specifier || "").trim();
  if (!value.startsWith("npm:")) {
    return null;
  }
  const target = value.slice("npm:".length);
  const separator = target.lastIndexOf("@");
  if (separator <= 0) {
    return null;
  }
  const name = target.slice(0, separator);
  return name ? { name, constraint: target.slice(separator + 1) } : null;
}

function createNpmDependency(values, declaredName) {
  const dependency = {
    ...createDependency(values),
    declaredName: String(declaredName || values.name || "").trim(),
  };
  if (values && values.packageSource) {
    dependency.packageSource = { ...values.packageSource };
  }
  if (values && Object.prototype.hasOwnProperty.call(values, "hasResolutionEvidence")) {
    dependency.hasResolutionEvidence = values.hasResolutionEvidence === true;
  }
  return dependency;
}

function classifyNpmPackageSource(hints = {}) {
  const sourceHints = createNpmSourceHints(hints);
  const signals = [...sourceHints.specifiers, ...sourceHints.resolutions];
  const value = signals.join(" ");
  if (/\b(?:workspace|link):/i.test(value)) {
    return { kind: "local", ...(value ? { location: boundedSourceLocation(value) } : {}) };
  }
  if (/\bfile:/i.test(value)) {
    return { kind: "path", location: boundedSourceLocation(value) };
  }
  if (/(?:^|\s)(?:git\+|git:|github:|gitlab:|bitbucket:)|\.git(?:#|\s|$)/i.test(value)) {
    return { kind: "git", location: boundedSourceLocation(value) };
  }
  // A URL in a declaration/selector is a direct artifact dependency and must
  // not become registry lookup evidence. In contrast, lockfile `resolved` or
  // `tarball` URLs are transport metadata: private npm registries may use any
  // hostname, so those URLs remain registry evidence when the selector itself
  // is an ordinary npm version/range.
  if (hasHttpNpmSpecifier(sourceHints.specifiers)) {
    return {
      kind: "unknown",
      location: boundedSourceLocation(sourceHints.specifiers.join(" ")),
    };
  }
  return { kind: "registry" };
}

function createNpmSourceHints(hints = {}) {
  const value = hints && typeof hints === "object" && !Array.isArray(hints)
    ? hints
    : { specifiers: [hints] };
  return {
    specifiers: normalizeNpmSourceSignals(value.specifiers),
    resolutions: normalizeNpmSourceSignals(value.resolutions),
  };
}

function normalizeNpmSourceSignals(signals) {
  const values = Array.isArray(signals) ? signals : [signals];
  return values
    .map((signal) => String(signal || "").trim())
    .filter(Boolean);
}

function applyNpmSourceHints(entry, hints = {}) {
  if (!entry) {
    return null;
  }
  const existingHints = createNpmSourceHints(entry.sourceHints);
  const additionalHints = createNpmSourceHints(hints);
  const sourceHints = createNpmSourceHints({
    specifiers: [...existingHints.specifiers, ...additionalHints.specifiers],
    resolutions: [...existingHints.resolutions, ...additionalHints.resolutions],
  });
  const packageSource = classifyNpmPackageSource(sourceHints);
  return {
    ...entry,
    sourceHints,
    packageSource,
    hasResolutionEvidence: packageSource.kind === "registry",
  };
}

function hasHttpNpmSpecifier(specifiers) {
  return specifiers.some((specifier) => /https?:\/\//i.test(specifier));
}

function boundedSourceLocation(value) {
  return String(value || "").trim().slice(0, 4096);
}

function countUniqueNpmIdentities(entries) {
  const identities = new Set();
  for (const entry of entries || []) {
    identities.add(npmPackageVersionKey(entry && entry.name, entry && entry.version));
  }
  return identities.size;
}

function npmPackageVersionKey(name, version) {
  return JSON.stringify([
    String(name || "").trim().toLowerCase(),
    String(version || "").trim(),
  ]);
}

function parseYarnSelectorName(selector) {
  const normalizedSelector = selector.trim().replace(/^["']|["']$/g, "");
  if (!normalizedSelector) {
    return "";
  }

  if (normalizedSelector.startsWith("@")) {
    const secondAt = normalizedSelector.indexOf("@", 1);
    return secondAt === -1 ? normalizedSelector : normalizedSelector.slice(0, secondAt);
  }

  const atIndex = normalizedSelector.indexOf("@");
  return atIndex === -1 ? normalizedSelector : normalizedSelector.slice(0, atIndex);
}

async function parsePnpmLock(lockfilePath, manifest, workspaceFolder, options) {
  throwIfNpmCancelled(options);
  const parsed = parsePnpmEntries(await readUtf8(lockfilePath, workspaceFolder, options), options);
  if (parsed.packageEntries.size === 0) {
    throw new Error("Malformed pnpm-lock.yaml: no package entries found");
  }

  const sourceFile = getSourceFileName(lockfilePath);
  const directNames = manifest.directNames.size > 0 || manifest.devNames.size > 0
    ? new Set([...manifest.directNames, ...manifest.devNames])
    : new Set(parsed.directReferences.keys());
  const devNames = new Set([...manifest.devNames, ...parsed.directDevNames]);
  const directRoots = [];
  const traversalState = createGraphTraversalState(options);

  for (const directName of directNames) {
    throwIfNpmCancelled(options);
    const directReference = parsed.directReferences.get(directName);
    const directSpecifier = parsed.directSpecifiers.get(directName);
    const manifestReference = manifest.dependencies.find((dependency) => (
      dependency.name === directName
    ));
    const entry = applyNpmSourceHints(
      selectPnpmEntry(parsed, directName, directReference),
      {
        specifiers: [
          directSpecifier,
          manifestReference && (manifestReference.declaredConstraint || manifestReference.version),
        ],
        resolutions: [directReference],
      }
    );
    directRoots.push(buildPnpmDependency(
      entry,
      directName,
      [],
      parsed,
      new Set(),
      sourceFile,
      devNames,
      traversalState,
      devNames.has(directName),
      true,
      {
        specifiers: [
          directSpecifier,
          manifestReference && (manifestReference.declaredConstraint || manifestReference.version),
        ],
        resolutions: [directReference],
      }
    ));
  }

  let dependencies = deduplicateDeps(flattenDependencies(directRoots, {
    cancellationToken: options.cancellationToken,
  }));
  for (const entry of parsed.packageEntries.values()) {
    const key = npmPackageVersionKey(entry.name, entry.version);
    if (dependencies.some((dependency) => npmPackageVersionKey(
      dependency.name,
      dependency.version
    ) === key)) {
      continue;
    }
    dependencies.push(createNpmDependency({
      name: entry.name,
      version: entry.version,
      ecosystem: "npm",
      isDirect: false,
      parent: null,
      parentChain: [],
      transitives: [],
      sourceFile,
      isDevelopmentDependency: devNames.has(entry.installedName || entry.name),
      packageSource: entry.packageSource,
      hasResolutionEvidence: entry.hasResolutionEvidence,
    }, entry.installedName || entry.name));
  }

  const warnings = [];
  if (options.maxDependenciesToScan && dependencies.length > options.maxDependenciesToScan) {
    warnings.push("Some dependencies are hidden by the configured display setting. Package inventory remains complete.");
  }
  appendGraphLimitWarning(warnings, traversalState);
  publishGraphMetrics(options, traversalState, parsed.packageEntries.size, countUniqueNpmIdentities(parsed.packageEntries.values()));

  return buildTree("npm", sourceFile, dependencies, warnings);
}

function buildPnpmDependency(
  entry,
  fallbackName,
  parentChain,
  parsedEntries,
  visiting,
  sourceFile,
  devNames,
  traversalState,
  inheritedDevelopment = false,
  forceExpand = false,
  fallbackSourceHints = {}
) {
  throwIfNpmCancelled(traversalState && traversalState.options);
  if (!entry) {
    const packageSource = classifyNpmPackageSource(fallbackSourceHints);
    return createNpmDependency({
      name: fallbackName,
      version: "",
      ecosystem: "npm",
      isDirect: parentChain.length === 0,
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile,
      isDevelopmentDependency: inheritedDevelopment || devNames.has(fallbackName),
      packageSource,
      hasResolutionEvidence: false,
    }, fallbackName);
  }

  const key = entry.key;
  if (visiting.has(key)) {
    traversalState.cycleEdgesSkipped += 1;
    return createNpmDependency({
      name: entry.name,
      version: entry.version,
      ecosystem: "npm",
      isDirect: parentChain.length === 0,
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile,
      isDevelopmentDependency: inheritedDevelopment || devNames.has(entry.installedName || entry.name),
      packageSource: entry.packageSource,
      hasResolutionEvidence: entry.hasResolutionEvidence,
    }, entry.installedName || entry.name);
  }

  const nextVisiting = new Set(visiting);
  nextVisiting.add(key);
  const nextParentChain = parentChain.concat(entry.name);
  const transitives = [];
  const isDevelopmentDependency = inheritedDevelopment
    || devNames.has(entry.installedName || entry.name);

  if (!canExpandGraphNode(parentChain, key, traversalState, forceExpand)) {
    return createNpmDependency({
      name: entry.name,
      version: entry.version,
      ecosystem: "npm",
      isDirect: parentChain.length === 0,
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile,
      isDevelopmentDependency,
      packageSource: entry.packageSource,
      hasResolutionEvidence: entry.hasResolutionEvidence,
    }, entry.installedName || entry.name);
  }

  for (const [dependencyName, versionHint] of Object.entries(entry.dependencies || {})) {
    if (!reserveNpmRelationshipEdge(traversalState)) {
      break;
    }
    const childEntry = applyNpmSourceHints(
      selectPnpmEntry(parsedEntries, dependencyName, versionHint),
      { specifiers: [versionHint] }
    );
    if (childEntry) {
      traversalState.resolvedEdges += 1;
    } else {
      traversalState.unresolvedEdges += 1;
    }
    transitives.push(buildPnpmDependency(
      childEntry,
      dependencyName,
      nextParentChain,
      parsedEntries,
      nextVisiting,
      sourceFile,
      devNames,
      traversalState,
      isDevelopmentDependency,
      false,
      versionHint
    ));
  }

  return createNpmDependency({
    name: entry.name,
    version: entry.version,
    ecosystem: "npm",
    isDirect: parentChain.length === 0,
    parent: parentChain[parentChain.length - 1] || null,
    parentChain,
    transitives: deduplicateDeps(transitives),
    sourceFile,
    isDevelopmentDependency,
    packageSource: entry.packageSource,
    hasResolutionEvidence: entry.hasResolutionEvidence,
  }, entry.installedName || entry.name);
}

function createGraphTraversalState(options = {}) {
  return {
    options,
    expandedNodes: 0,
    materializedNodes: 0,
    repeatedOccurrenceEncounters: 0,
    directRootReexpansions: 0,
    structuralEdgesExamined: 0,
    resolvedEdges: 0,
    unresolvedEdges: 0,
    cycleEdgesSkipped: 0,
    maxObservedDepth: 0,
    depthLimitReached: false,
    nodeLimitReached: false,
    edgeLimitReached: false,
    truncated: false,
    expandedEntryKeys: new Set(),
    maxDepth: lowerOnlyGraphLimit(options.npmGraphMaxDepth, MAX_GRAPH_DEPTH),
    maxNodes: lowerOnlyGraphLimit(options.npmGraphMaxNodes, MAX_GRAPH_NODES),
    maxEdges: lowerOnlyGraphLimit(options.npmGraphMaxEdges, MAX_GRAPH_EDGES),
  };
}

function lowerOnlyGraphLimit(requested, productionMaximum) {
  return Number.isSafeInteger(requested) && requested > 0
    ? Math.min(requested, productionMaximum)
    : productionMaximum;
}

function reserveMaterializedNode(parentChain, state) {
  if (!state) {
    return true;
  }
  state.maxObservedDepth = Math.max(state.maxObservedDepth, parentChain.length);
  if (state.materializedNodes >= state.maxNodes) {
    state.nodeLimitReached = true;
    state.truncated = true;
    return false;
  }
  state.materializedNodes += 1;
  return true;
}

function canExpandGraphNode(parentChain, entryKey, state, forceExpand) {
  if (!state) {
    return true;
  }
  if (parentChain.length >= state.maxDepth) {
    state.depthLimitReached = true;
    state.truncated = true;
    return false;
  }
  if (state.expandedEntryKeys.has(entryKey) && !forceExpand) {
    state.repeatedOccurrenceEncounters += 1;
    return false;
  }
  if (state.expandedNodes >= state.maxNodes) {
    state.nodeLimitReached = true;
    state.truncated = true;
    return false;
  }
  if (forceExpand && state.expandedEntryKeys.has(entryKey)) {
    state.directRootReexpansions += 1;
  }
  state.expandedEntryKeys.add(entryKey);
  state.expandedNodes += 1;
  return true;
}

function reserveNpmRelationshipEdge(state) {
  if (state.structuralEdgesExamined >= state.maxEdges) {
    state.edgeLimitReached = true;
    state.truncated = true;
    return false;
  }
  state.structuralEdgesExamined += 1;
  return true;
}

function appendGraphLimitWarning(warnings, state) {
  if (state && state.truncated) {
    warnings.push("Some dependency relationships could not be fully analyzed.");
  }
}

function publishGraphMetrics(options, state, indexedOccurrences, uniquePackageIdentities) {
  if (!options || typeof options.onNpmGraphMetrics !== "function") {
    return;
  }
  options.onNpmGraphMetrics(Object.freeze({
    indexedOccurrences,
    uniquePackageIdentities,
    structuralOccurrencesExpanded: state.expandedNodes,
    dependencyRecordsMaterialized: state.materializedNodes,
    repeatedOccurrenceEncounters: state.repeatedOccurrenceEncounters,
    directRootReexpansions: state.directRootReexpansions,
    structuralEdgesExamined: state.structuralEdgesExamined,
    resolvedEdges: state.resolvedEdges,
    unresolvedEdges: state.unresolvedEdges,
    cycleEdgesSkipped: state.cycleEdgesSkipped,
    maxObservedDepth: state.maxObservedDepth,
    depthLimitReached: state.depthLimitReached,
    nodeLimitReached: state.nodeLimitReached,
    edgeLimitReached: state.edgeLimitReached,
    maxDepth: state.maxDepth,
    maxNodes: state.maxNodes,
    maxEdges: state.maxEdges,
  }));
}

function selectPnpmEntry(parsedEntries, dependencyName, versionHint) {
  const reference = parsePnpmReference(dependencyName, versionHint);
  if (reference.local) {
    return null;
  }
  const packageEntries = parsedEntries && parsedEntries.packageEntries || new Map();
  if (reference.entryKey && packageEntries.has(reference.entryKey)) {
    return { ...packageEntries.get(reference.entryKey), installedName: dependencyName };
  }
  const entries = parsedEntries && parsedEntries.entriesByName
    ? parsedEntries.entriesByName.get(reference.name) || []
    : [...packageEntries.values()].filter((entry) => entry.name === reference.name);
  if (entries.length === 0) {
    return null;
  }
  if (reference.version) {
    const exactMatch = entries.find((entry) => entry.version === reference.version);
    if (exactMatch) {
      return { ...exactMatch, installedName: dependencyName };
    }
  }
  return { ...entries[0], installedName: dependencyName };
}

function parsePnpmReference(dependencyName, versionHint) {
  let value = unquoteYamlScalar(versionHint)
    .trim()
    .trim();
  if (/^(?:link|workspace|file):/i.test(value)) {
    return { name: dependencyName, version: "", local: true };
  }
  if (value.startsWith("npm:")) {
    value = value.slice("npm:".length);
  }

  const withoutPeerSuffix = value.split("(")[0].trim();
  const separator = withoutPeerSuffix.lastIndexOf("@");
  if (separator > 0) {
    const name = withoutPeerSuffix.slice(0, separator);
    const version = normalizeVersion(withoutPeerSuffix.slice(separator + 1));
    return {
      name,
      version,
      entryKey: normalizePnpmEntryKey(value),
      local: false,
    };
  }
  const version = normalizeVersion(withoutPeerSuffix);
  return {
    name: dependencyName,
    version,
    entryKey: value ? normalizePnpmEntryKey(`${dependencyName}@${value}`) : "",
    local: false,
  };
}

function parsePnpmEntries(content, options = {}) {
  const packageEntries = new Map();
  const entriesByName = new Map();
  const directReferences = new Map();
  const directSpecifiers = new Map();
  const directDevNames = new Set();
  const snapshotDependencies = new Map();
  const lines = String(content || "").split(/\r?\n/);
  let section = "";
  let currentPackage = null;
  let currentPackageSubsection = "";
  let inImporter = false;
  let importerSection = "";
  let currentImporterPackage = "";
  let currentSnapshotKey = "";
  let currentSnapshotSubsection = "";

  const flushPackage = () => {
    if (!currentPackage || !currentPackage.name || !currentPackage.version) {
      currentPackage = null;
      currentPackageSubsection = "";
      return;
    }
    const existing = packageEntries.get(currentPackage.key);
    if (existing) {
      Object.assign(existing.dependencies, currentPackage.dependencies);
      existing.sourceSignal ||= currentPackage.sourceSignal;
    } else {
      packageEntries.set(currentPackage.key, currentPackage);
    }
    currentPackage = null;
    currentPackageSubsection = "";
  };

  for (const rawLine of lines) {
    throwIfNpmCancelled(options);
    const lineWithoutComment = stripYamlComment(rawLine);
    const line = lineWithoutComment.trimEnd();
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }

    const indent = rawLine.search(/\S/);
    if (indent === 0 && trimmed === "importers:") {
      flushPackage();
      section = "importers";
      inImporter = false;
      continue;
    }
    if (indent === 0 && trimmed === "packages:") {
      flushPackage();
      section = "packages";
      continue;
    }
    if (indent === 0 && trimmed === "snapshots:") {
      flushPackage();
      section = "snapshots";
      currentSnapshotKey = "";
      currentSnapshotSubsection = "";
      continue;
    }
    if (indent === 0 && trimmed.endsWith(":") && !["importers:", "packages:", "snapshots:"].includes(trimmed)) {
      flushPackage();
      section = "";
      continue;
    }

    if (section === "importers") {
      if (indent === 2 && trimmed.endsWith(":")) {
        inImporter = true;
        importerSection = "";
        currentImporterPackage = "";
        continue;
      }
      if (!inImporter) {
        continue;
      }
      if (indent === 4 && trimmed.endsWith(":")) {
        importerSection = trimmed.slice(0, -1);
        currentImporterPackage = "";
        continue;
      }
      if (!["dependencies", "devDependencies", "optionalDependencies"].includes(importerSection)) {
        continue;
      }
      if (indent === 6) {
        const mapping = parseYamlMappingLine(trimmed);
        if (!mapping) {
          continue;
        }
        currentImporterPackage = mapping.key;
        if (mapping.value) {
          const shortReference = unquoteYamlScalar(mapping.value);
          directReferences.set(currentImporterPackage, shortReference);
          directSpecifiers.set(currentImporterPackage, shortReference);
          if (importerSection === "devDependencies") {
            directDevNames.add(currentImporterPackage);
          }
          currentImporterPackage = "";
        }
        continue;
      }
      if (indent === 8 && trimmed.startsWith("specifier:") && currentImporterPackage) {
        directSpecifiers.set(
          currentImporterPackage,
          unquoteYamlScalar(trimmed.slice("specifier:".length))
        );
        continue;
      }
      if (indent === 8 && trimmed.startsWith("version:") && currentImporterPackage) {
        directReferences.set(currentImporterPackage, unquoteYamlScalar(trimmed.slice("version:".length)));
        if (importerSection === "devDependencies") {
          directDevNames.add(currentImporterPackage);
        }
      }
      continue;
    }

    if (section === "packages") {
      if (indent === 2) {
        flushPackage();
        const mapping = parseYamlMappingLine(trimmed);
        const parsedKey = mapping && parsePnpmPackageKey(mapping.key);
        if (!parsedKey) {
          continue;
        }
        currentPackage = {
          ...parsedKey,
          dependencies: {},
          sourceSignal: "",
        };
        continue;
      }
      if (!currentPackage) {
        continue;
      }
      if (indent === 4 && trimmed.endsWith(":")) {
        currentPackageSubsection = trimmed.slice(0, -1);
        continue;
      }
      if (indent === 4 && trimmed.startsWith("resolution:")) {
        currentPackage.sourceSignal = trimmed.slice("resolution:".length).trim();
        currentPackageSubsection = "resolution";
        continue;
      }
      if (currentPackageSubsection === "resolution" && indent === 6 && trimmed.startsWith("tarball:")) {
        currentPackage.sourceSignal = trimmed.slice("tarball:".length).trim();
        continue;
      }
      if (!["dependencies", "optionalDependencies"].includes(currentPackageSubsection)) {
        continue;
      }
      if (indent === 6 && trimmed.includes(":")) {
        const mapping = parseYamlMappingLine(trimmed);
        if (mapping) {
          currentPackage.dependencies[mapping.key] = unquoteYamlScalar(mapping.value);
        }
      }
      continue;
    }

    if (section === "snapshots") {
      if (indent === 2) {
        const mapping = parseYamlMappingLine(trimmed);
        if (!mapping) {
          currentSnapshotKey = "";
          currentSnapshotSubsection = "";
          continue;
        }
        currentSnapshotKey = normalizePnpmEntryKey(mapping.key);
        currentSnapshotSubsection = "";
        if (!snapshotDependencies.has(currentSnapshotKey)) {
          snapshotDependencies.set(currentSnapshotKey, {});
        }
        continue;
      }
      if (!currentSnapshotKey) {
        continue;
      }
      if (indent === 4 && trimmed.endsWith(":")) {
        currentSnapshotSubsection = trimmed.slice(0, -1);
        continue;
      }
      if (
        indent === 6
        && ["dependencies", "optionalDependencies"].includes(currentSnapshotSubsection)
      ) {
        const mapping = parseYamlMappingLine(trimmed);
        if (mapping) {
          snapshotDependencies.get(currentSnapshotKey)[mapping.key] = unquoteYamlScalar(mapping.value);
        }
      }
    }
  }

  flushPackage();
  for (const [snapshotKey, dependencies] of snapshotDependencies) {
    let entry = packageEntries.get(snapshotKey);
    if (!entry) {
      const parsedKey = parsePnpmPackageKey(snapshotKey);
      if (!parsedKey) {
        continue;
      }
      entry = { ...parsedKey, dependencies: {}, sourceSignal: "" };
      packageEntries.set(entry.key, entry);
    }
    Object.assign(entry.dependencies, dependencies);
  }
  for (const entry of packageEntries.values()) {
    entry.sourceHints = createNpmSourceHints({
      specifiers: [entry.key],
      resolutions: [entry.sourceSignal],
    });
    entry.packageSource = classifyNpmPackageSource(entry.sourceHints);
    entry.hasResolutionEvidence = entry.packageSource.kind === "registry";
    if (!entriesByName.has(entry.name)) {
      entriesByName.set(entry.name, []);
    }
    entriesByName.get(entry.name).push(entry);
  }
  return {
    packageEntries,
    entriesByName,
    directReferences,
    directSpecifiers,
    directDevNames,
  };
}

function parsePnpmPackageKey(rawKey) {
  const cleaned = normalizePnpmEntryKey(rawKey);
  if (!cleaned) {
    return null;
  }

  const withoutPeerSuffix = cleaned.split("(")[0];
  const atIndex = withoutPeerSuffix.lastIndexOf("@");
  if (atIndex <= 0) {
    return null;
  }

  return {
    key: cleaned,
    name: withoutPeerSuffix.slice(0, atIndex),
    version: withoutPeerSuffix.slice(atIndex + 1),
  };
}

function normalizePnpmEntryKey(rawKey) {
  return unquoteYamlScalar(String(rawKey || "").replace(/^\/+/, "").trim());
}

function unquoteYamlScalar(value) {
  const normalized = String(value || "").trim();
  if (
    normalized.length >= 2
    && ((normalized.startsWith('"') && normalized.endsWith('"'))
      || (normalized.startsWith("'") && normalized.endsWith("'")))
  ) {
    return normalized.slice(1, -1);
  }
  return normalized;
}

function parseYamlMappingLine(line) {
  const text = String(line || "").trim();
  let quote = "";
  let escaped = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quote) {
      if (quote === '"' && character === "\\" && !escaped) {
        escaped = true;
        continue;
      }
      if (character === quote && !escaped) {
        quote = "";
      }
      escaped = false;
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }
    if (character !== ":") {
      continue;
    }
    const key = unquoteYamlScalar(text.slice(0, index));
    return key ? { key, value: text.slice(index + 1).trim() } : null;
  }
  return null;
}

function throwIfNpmCancelled(options) {
  const cancelled = Boolean(
    options
    && (
      options.cancellationToken && options.cancellationToken.isCancellationRequested
      || typeof options.shouldCancel === "function" && options.shouldCancel()
    )
  );
  if (!cancelled) {
    return;
  }
  const error = new Error("Dependency parsing was canceled.");
  error.code = "ERR_DEPENDENCY_PARSING_CANCELLED";
  throw error;
}

module.exports = npmParser;

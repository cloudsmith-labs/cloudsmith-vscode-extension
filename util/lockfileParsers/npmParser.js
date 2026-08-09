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
  readJson,
  pathExists,
  readUtf8,
  stripYamlComment,
} = require("./shared");
const { parsePackageJsonManifest } = require("./manifestHelpers");

const LOCKFILE_NAMES = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"];
const MAX_GRAPH_DEPTH = 128;
const MAX_GRAPH_NODES = 50000;

const npmParser = {
  name: "npmParser",
  ecosystem: "npm",

  async canResolve(workspaceFolder) {
    const matches = await this.detect(workspaceFolder);
    return matches.length > 0;
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    for (const fileName of LOCKFILE_NAMES) {
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
    const sourceFile = getSourceFileName(lockfilePath);
    let manifest = { dependencies: [], directNames: new Set(), devNames: new Set() };
    if (manifestPath && await pathExists(manifestPath, workspaceFolder)) {
      const content = await readUtf8(manifestPath, workspaceFolder);
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

  const root = await readJson(lockfilePath, workspaceFolder);
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

  for (const [packagePath, packageInfo] of Object.entries(packages)) {
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
    const entry = {
      key: occurrenceKey,
      packagePath,
      installedName,
      name,
      version,
      dependencies,
      isDevelopmentDependency: packageInfo.dev === true,
    };
    entriesByPath.set(packagePath, entry);
    if (!uniqueEntries.has(identityKey)) {
      uniqueEntries.set(identityKey, entry);
    }
  }

  const directNames = manifest.directNames.size > 0 || manifest.devNames.size > 0
    ? new Set([...manifest.directNames, ...manifest.devNames])
    : new Set(Object.keys(rootDependencyMap));

  const directRoots = [];
  const seenDirectKeys = new Set();
  const traversalState = createGraphTraversalState();

  for (const directName of directNames) {
    const entry = selectPackageLockEntry(entriesByPath, "", directName);
    const dependency = buildNpmDependency(entry, directName, [], entriesByPath, new Set(), {
      sourceFile: getSourceFileName(lockfilePath),
      devNames: manifest.devNames,
    }, manifest.devNames.has(directName), traversalState);
    const key = npmPackageVersionKey(dependency.name, dependency.version);
    if (!seenDirectKeys.has(key)) {
      seenDirectKeys.add(key);
      directRoots.push(dependency);
    }
  }

  let dependencies = deduplicateDeps(flattenDependencies(directRoots));
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
    }, entry.installedName));
  }

  if (options.maxDependenciesToScan && dependencies.length > options.maxDependenciesToScan) {
    warnings.push(
      `Large npm dependency tree (${dependencies.length} unique packages). ` +
      `Display is capped at ${options.maxDependenciesToScan} dependencies.`
    );
  }
  appendGraphLimitWarning(warnings, traversalState);

  return buildTree("npm", getSourceFileName(lockfilePath), dependencies, warnings);
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
  traversalState
) {
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
      isDevelopmentDependency: inheritedDevelopment || context.devNames.has(fallbackName),
    }, fallbackName);
  }

  if (visiting.has(entry.key)) {
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
    }, entry.installedName);
  }

  const nextVisiting = new Set(visiting);
  nextVisiting.add(entry.key);
  const nextParentChain = parentChain.concat(entry.name);
  const transitives = [];
  const isDevelopmentDependency = inheritedDevelopment
    || entry.isDevelopmentDependency
    || context.devNames.has(entry.installedName);

  if (!canExpandGraphNode(parentChain, traversalState)) {
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
    }, entry.installedName);
  }

  for (const dependencyName of Object.keys(entry.dependencies || {})) {
    const childEntry = selectPackageLockEntry(entriesByPath, entry.packagePath, dependencyName);
    if (childEntry && nextVisiting.has(childEntry.key)) {
      continue;
    }
    transitives.push(buildNpmDependency(
      childEntry,
      dependencyName,
      nextParentChain,
      entriesByPath,
      nextVisiting,
      context,
      isDevelopmentDependency,
      traversalState
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
    sourceFile: context.sourceFile,
    isDevelopmentDependency,
  }, entry.installedName);
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
  const content = await readUtf8(lockfilePath, workspaceFolder);
  const parsed = parseYarnEntries(content);
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
  const traversalState = createGraphTraversalState();
  for (const directName of directNames) {
    const entry = selectYarnEntry(parsed, directName, manifestVersionHints.get(directName));
    directRoots.push(buildYarnDependency(
      entry,
      directName,
      [],
      parsed,
      new Set(),
      sourceFile,
      manifest.devNames,
      false,
      traversalState
    ));
  }

  let dependencies = deduplicateDeps(flattenDependencies(directRoots));
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
    }, entry.installedName || entry.name));
  }

  const warnings = [];
  if (options.maxDependenciesToScan && dependencies.length > options.maxDependenciesToScan) {
    warnings.push(
      `Large npm dependency tree (${dependencies.length} unique packages). ` +
      `Display is capped at ${options.maxDependenciesToScan} dependencies.`
    );
  }
  appendGraphLimitWarning(warnings, traversalState);

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
  traversalState
) {
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
    }, fallbackName);
  }

  const key = entry.key || npmPackageVersionKey(entry.name, entry.version);
  if (visiting.has(key)) {
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
    }, entry.installedName || entry.name);
  }

  const nextVisiting = new Set(visiting);
  nextVisiting.add(key);
  const nextParentChain = parentChain.concat(entry.name);
  const transitives = [];
  const isDevelopmentDependency = inheritedDevelopment
    || devNames.has(entry.installedName || entry.name);

  if (!canExpandGraphNode(parentChain, traversalState)) {
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
    }, entry.installedName || entry.name);
  }

  for (const dependencyName of Object.keys(entry.dependencies || {})) {
    const versionHint = entry.dependencies[dependencyName];
    transitives.push(buildYarnDependency(
      selectYarnEntry(parsedEntries, dependencyName, versionHint),
      dependencyName,
      nextParentChain,
      parsedEntries,
      nextVisiting,
      sourceFile,
      devNames,
      isDevelopmentDependency,
      traversalState
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
  }, entry.installedName || entry.name);
}

function parseYarnEntries(content) {
  const entries = new Map();
  const entriesByName = new Map();
  const selectorIndex = new Map();
  const lines = String(content || "").split(/\r?\n/);
  let currentEntry = null;
  let inDependencies = false;

  const flushCurrent = () => {
    if (currentEntry && currentEntry.name && currentEntry.version) {
      const key = [
        currentEntry.installedName.toLowerCase(),
        currentEntry.name.toLowerCase(),
        currentEntry.version,
      ].join("@");
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

    if (inDependencies) {
      const dependencyMatch = trimmed.match(/^("?[^"\s]+"?)\s+"([^"]+)"/);
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
  return {
    ...createDependency(values),
    declaredName: String(declaredName || values.name || "").trim(),
  };
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
  const parsed = parsePnpmEntries(await readUtf8(lockfilePath, workspaceFolder));
  if (parsed.packageEntries.size === 0) {
    throw new Error("Malformed pnpm-lock.yaml: no package entries found");
  }

  const sourceFile = getSourceFileName(lockfilePath);
  const directNames = manifest.directNames.size > 0 || manifest.devNames.size > 0
    ? new Set([...manifest.directNames, ...manifest.devNames])
    : new Set(parsed.directVersions.keys());
  const directRoots = [];
  const traversalState = createGraphTraversalState();

  for (const directName of directNames) {
    const entry = selectPnpmEntry(parsed.packageEntries, directName, parsed.directVersions.get(directName));
    directRoots.push(buildPnpmDependency(
      entry,
      directName,
      [],
      parsed.packageEntries,
      new Set(),
      sourceFile,
      manifest.devNames,
      traversalState
    ));
  }

  let dependencies = deduplicateDeps(flattenDependencies(directRoots));
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
      isDevelopmentDependency: manifest.devNames.has(entry.name),
    }, entry.name));
  }

  const warnings = [];
  if (options.maxDependenciesToScan && dependencies.length > options.maxDependenciesToScan) {
    warnings.push(
      `Large npm dependency tree (${dependencies.length} unique packages). ` +
      `Display is capped at ${options.maxDependenciesToScan} dependencies.`
    );
  }
  appendGraphLimitWarning(warnings, traversalState);

  return buildTree("npm", sourceFile, dependencies, warnings);
}

function buildPnpmDependency(
  entry,
  fallbackName,
  parentChain,
  packageEntries,
  visiting,
  sourceFile,
  devNames,
  traversalState
) {
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
      isDevelopmentDependency: devNames.has(fallbackName),
    }, fallbackName);
  }

  const key = npmPackageVersionKey(entry.name, entry.version);
  if (visiting.has(key)) {
    return createNpmDependency({
      name: entry.name,
      version: entry.version,
      ecosystem: "npm",
      isDirect: parentChain.length === 0,
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile,
      isDevelopmentDependency: devNames.has(entry.installedName || entry.name),
    }, entry.installedName || entry.name);
  }

  const nextVisiting = new Set(visiting);
  nextVisiting.add(key);
  const nextParentChain = parentChain.concat(entry.name);
  const transitives = [];

  if (!canExpandGraphNode(parentChain, traversalState)) {
    return createNpmDependency({
      name: entry.name,
      version: entry.version,
      ecosystem: "npm",
      isDirect: parentChain.length === 0,
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile,
      isDevelopmentDependency: devNames.has(entry.installedName || entry.name),
    }, entry.installedName || entry.name);
  }

  for (const [dependencyName, versionHint] of Object.entries(entry.dependencies || {})) {
    transitives.push(buildPnpmDependency(
      selectPnpmEntry(packageEntries, dependencyName, versionHint),
      dependencyName,
      nextParentChain,
      packageEntries,
      nextVisiting,
      sourceFile,
      devNames,
      traversalState
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
    isDevelopmentDependency: devNames.has(entry.installedName || entry.name),
  }, entry.installedName || entry.name);
}

function createGraphTraversalState() {
  return { expandedNodes: 0, truncated: false };
}

function canExpandGraphNode(parentChain, state) {
  if (!state) {
    return true;
  }
  if (parentChain.length >= MAX_GRAPH_DEPTH || state.expandedNodes >= MAX_GRAPH_NODES) {
    state.truncated = true;
    return false;
  }
  state.expandedNodes += 1;
  return true;
}

function appendGraphLimitWarning(warnings, state) {
  if (state && state.truncated) {
    warnings.push(
      `npm dependency graph expansion reached its bounded limit `
      + `(${MAX_GRAPH_NODES} nodes or depth ${MAX_GRAPH_DEPTH}); deeper relationships were omitted.`
    );
  }
}

function selectPnpmEntry(packageEntries, dependencyName, versionHint) {
  const reference = parsePnpmReference(dependencyName, versionHint);
  if (reference.local) {
    return null;
  }
  const entries = [...packageEntries.values()].filter((entry) => entry.name === reference.name);
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
  let value = String(versionHint || "")
    .trim()
    .replace(/^['"]|['"]$/g, "")
    .split("(")[0]
    .trim();
  if (/^(?:link|workspace|file):/i.test(value)) {
    return { name: dependencyName, version: "", local: true };
  }
  if (value.startsWith("npm:")) {
    value = value.slice("npm:".length);
  }

  const separator = value.lastIndexOf("@");
  if (separator > 0) {
    return {
      name: value.slice(0, separator),
      version: normalizeVersion(value.slice(separator + 1)),
      local: false,
    };
  }
  return {
    name: dependencyName,
    version: normalizeVersion(value),
    local: false,
  };
}

function parsePnpmEntries(content) {
  const packageEntries = new Map();
  const directVersions = new Map();
  const lines = String(content || "").split(/\r?\n/);
  let section = "";
  let currentPackage = null;
  let currentPackageSubsection = "";
  let inImporter = false;
  let importerSection = "";
  let currentImporterPackage = "";

  const flushPackage = () => {
    if (!currentPackage || !currentPackage.name || !currentPackage.version) {
      currentPackage = null;
      currentPackageSubsection = "";
      return;
    }
    packageEntries.set(npmPackageVersionKey(currentPackage.name, currentPackage.version), currentPackage);
    currentPackage = null;
    currentPackageSubsection = "";
  };

  for (const rawLine of lines) {
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
    if (indent === 0 && trimmed.endsWith(":") && !["importers:", "packages:"].includes(trimmed)) {
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
      if (indent === 6 && trimmed.endsWith(":")) {
        currentImporterPackage = trimmed.slice(0, -1).replace(/^["']|["']$/g, "");
        continue;
      }
      if (indent === 8 && trimmed.startsWith("version:") && currentImporterPackage) {
        directVersions.set(
          currentImporterPackage,
          normalizeVersion(trimmed.slice("version:".length).trim()).split("(")[0].trim()
        );
      }
      continue;
    }

    if (section === "packages") {
      if (indent === 2 && trimmed.endsWith(":")) {
        flushPackage();
        const parsedKey = parsePnpmPackageKey(trimmed.slice(0, -1));
        if (!parsedKey) {
          continue;
        }
        currentPackage = {
          ...parsedKey,
          dependencies: {},
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
      if (!["dependencies", "optionalDependencies"].includes(currentPackageSubsection)) {
        continue;
      }
      if (indent === 6 && trimmed.includes(":")) {
        const parts = trimmed.split(":", 2);
        currentPackage.dependencies[parts[0].trim()] = normalizeVersion(parts[1].trim()).split("(")[0].trim();
      }
    }
  }

  flushPackage();
  return {
    packageEntries,
    directVersions,
  };
}

function parsePnpmPackageKey(rawKey) {
  const cleaned = rawKey.replace(/^\/+/, "").trim().replace(/^["']|["']$/g, "");
  if (!cleaned) {
    return null;
  }

  const withoutPeerSuffix = cleaned.split("(")[0];
  const atIndex = withoutPeerSuffix.lastIndexOf("@");
  if (atIndex <= 0) {
    return null;
  }

  return {
    name: withoutPeerSuffix.slice(0, atIndex),
    version: withoutPeerSuffix.slice(atIndex + 1),
  };
}

module.exports = npmParser;

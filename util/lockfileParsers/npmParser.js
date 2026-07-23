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
  statSafe,
  stripYamlComment,
} = require("./shared");
const { parsePackageJsonManifest } = require("./manifestHelpers");

const LOCKFILE_NAMES = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"];

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
    const manifest = manifestPath && await pathExists(manifestPath, workspaceFolder)
      ? parsePackageJsonManifest(await readUtf8(manifestPath, workspaceFolder))
      : { dependencies: [], directNames: new Set(), devNames: new Set() };

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
  const stats = await statSafe(lockfilePath, workspaceFolder);
  if (stats && stats.size > 50 * 1024 * 1024) {
    warnings.push("Large package-lock.json detected. Parsing may take longer than usual.");
  }

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

  const mergedManifestVersionHints = new Map();
  for (const dependency of manifest.dependencies) {
    mergedManifestVersionHints.set(dependency.name, dependency.version);
  }
  for (const [name, version] of Object.entries(rootDependencyMap)) {
    if (!mergedManifestVersionHints.has(name)) {
      mergedManifestVersionHints.set(name, normalizeVersion(version));
    }
  }

  const uniqueEntries = new Map();
  const nameIndex = new Map();
  const nameIndexKeys = new Map();

  for (const [packagePath, packageInfo] of Object.entries(packages)) {
    if (packagePath === "" || !packageInfo || typeof packageInfo !== "object") {
      continue;
    }

    const name = extractPackageLockName(packagePath);
    const version = String(packageInfo.version || "").trim();
    if (!name || !version) {
      continue;
    }

    const key = `${name.toLowerCase()}@${version.toLowerCase()}`;
    const existing = uniqueEntries.get(key);
    const dependencies = {
      ...(packageInfo.dependencies || {}),
      ...(packageInfo.optionalDependencies || {}),
    };
    const merged = existing || {
      key,
      name,
      version,
      dependencies: {},
    };
    Object.assign(merged.dependencies, dependencies);
    uniqueEntries.set(key, merged);

    const existingByName = nameIndex.get(name) || [];
    const existingKeys = nameIndexKeys.get(name) || new Set();
    if (!existingKeys.has(key)) {
      existingKeys.add(key);
      existingByName.push(merged);
      nameIndex.set(name, existingByName);
      nameIndexKeys.set(name, existingKeys);
    }
  }

  const directNames = manifest.directNames.size > 0 || manifest.devNames.size > 0
    ? new Set([...manifest.directNames, ...manifest.devNames])
    : new Set(Object.keys(rootDependencyMap));

  const directRoots = [];
  const seenDirectKeys = new Set();

  for (const directName of directNames) {
    const entry = selectEntryByName(nameIndex, directName, mergedManifestVersionHints.get(directName));
    const dependency = buildNpmDependency(entry, directName, [], nameIndex, new Set(), {
      sourceFile: getSourceFileName(lockfilePath),
      directNames,
      devNames: manifest.devNames,
    });
    const key = `${dependency.name.toLowerCase()}@${dependency.version.toLowerCase()}`;
    if (!seenDirectKeys.has(key)) {
      seenDirectKeys.add(key);
      directRoots.push(dependency);
    }
  }

  let dependencies = deduplicateDeps(flattenDependencies(directRoots));
  const addedKeys = new Set();
  collectDependencyKeys(dependencies, addedKeys);
  for (const entry of uniqueEntries.values()) {
    const key = `${entry.name.toLowerCase()}@${entry.version.toLowerCase()}`;
    if (addedKeys.has(key)) {
      continue;
    }
    addedKeys.add(key);
    dependencies.push(createDependency({
      name: entry.name,
      version: entry.version,
      ecosystem: "npm",
      isDirect: false,
      parent: null,
      parentChain: [],
      transitives: [],
      sourceFile: getSourceFileName(lockfilePath),
      isDevelopmentDependency: manifest.devNames.has(entry.name),
    }));
  }

  if (options.maxDependenciesToScan && dependencies.length > options.maxDependenciesToScan) {
    warnings.push(
      `Large npm dependency tree (${dependencies.length} unique packages). ` +
      `Display is capped at ${options.maxDependenciesToScan} dependencies.`
    );
  }

  return buildTree("npm", getSourceFileName(lockfilePath), dependencies, warnings);
}

function collectDependencyKeys(dependencies, addedKeys) {
  for (const dependency of Array.isArray(dependencies) ? dependencies : []) {
    addedKeys.add(`${dependency.name.toLowerCase()}@${dependency.version.toLowerCase()}`);
    if (Array.isArray(dependency.transitives) && dependency.transitives.length > 0) {
      collectDependencyKeys(dependency.transitives, addedKeys);
    }
  }
}

function buildNpmDependency(entry, fallbackName, parentChain, nameIndex, visiting, context) {
  if (!entry) {
    return createDependency({
      name: fallbackName,
      version: "",
      ecosystem: "npm",
      isDirect: parentChain.length === 0,
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile: context.sourceFile,
      isDevelopmentDependency: context.devNames.has(fallbackName),
    });
  }

  if (visiting.has(entry.key)) {
    return createDependency({
      name: entry.name,
      version: entry.version,
      ecosystem: "npm",
      isDirect: parentChain.length === 0,
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile: context.sourceFile,
      isDevelopmentDependency: context.devNames.has(entry.name),
    });
  }

  const nextVisiting = new Set(visiting);
  nextVisiting.add(entry.key);
  const nextParentChain = parentChain.concat(entry.name);
  const transitives = [];

  for (const [dependencyName, versionHint] of Object.entries(entry.dependencies || {})) {
    const childEntry = selectEntryByName(nameIndex, dependencyName, normalizeVersion(versionHint));
    if (childEntry && nextVisiting.has(childEntry.key)) {
      continue;
    }
    transitives.push(buildNpmDependency(
      childEntry,
      dependencyName,
      nextParentChain,
      nameIndex,
      nextVisiting,
      context
    ));
  }

  return createDependency({
    name: entry.name,
    version: entry.version,
    ecosystem: "npm",
    isDirect: parentChain.length === 0 || context.directNames.has(entry.name),
    parent: parentChain[parentChain.length - 1] || null,
    parentChain,
    transitives: deduplicateDeps(transitives),
    sourceFile: context.sourceFile,
    isDevelopmentDependency: context.devNames.has(entry.name),
  });
}

function selectEntryByName(nameIndex, dependencyName, versionHint) {
  const entries = nameIndex.get(dependencyName) || [];
  if (entries.length === 0) {
    return null;
  }

  const normalizedHint = normalizeVersion(versionHint);
  if (normalizedHint) {
    const exactMatch = entries.find((entry) => entry.version === normalizedHint);
    if (exactMatch) {
      return exactMatch;
    }
  }

  return entries[0];
}

function extractPackageLockName(packagePath) {
  const marker = "node_modules/";
  const lastMarkerIndex = packagePath.lastIndexOf(marker);
  const relativePath = lastMarkerIndex === -1
    ? packagePath
    : packagePath.slice(lastMarkerIndex + marker.length);
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
    manifestVersionHints.set(dependency.name, dependency.version);
  }
  const directNames = manifest.directNames.size > 0 || manifest.devNames.size > 0
    ? new Set([...manifest.directNames, ...manifest.devNames])
    : new Set([...parsed.entries.values()].map((entry) => entry.name));

  const directRoots = [];
  for (const directName of directNames) {
    const entry = selectYarnEntry(parsed, directName, manifestVersionHints.get(directName));
    directRoots.push(buildYarnDependency(
      entry,
      directName,
      [],
      parsed,
      new Set(),
      sourceFile,
      manifest.devNames
    ));
  }

  let dependencies = deduplicateDeps(flattenDependencies(directRoots));
  for (const entry of parsed.entries.values()) {
    const key = `${entry.name.toLowerCase()}@${entry.version.toLowerCase()}`;
    if (dependencies.some((dependency) => `${dependency.name.toLowerCase()}@${dependency.version.toLowerCase()}` === key)) {
      continue;
    }
    dependencies.push(createDependency({
      name: entry.name,
      version: entry.version,
      ecosystem: "npm",
      isDirect: false,
      parent: null,
      parentChain: [],
      transitives: [],
      sourceFile,
      isDevelopmentDependency: manifest.devNames.has(entry.name),
    }));
  }

  const warnings = [];
  if (options.maxDependenciesToScan && dependencies.length > options.maxDependenciesToScan) {
    warnings.push(
      `Large npm dependency tree (${dependencies.length} unique packages). ` +
      `Display is capped at ${options.maxDependenciesToScan} dependencies.`
    );
  }

  return buildTree("npm", sourceFile, dependencies, warnings);
}

function buildYarnDependency(entry, fallbackName, parentChain, parsedEntries, visiting, sourceFile, devNames) {
  if (!entry) {
    return createDependency({
      name: fallbackName,
      version: "",
      ecosystem: "npm",
      isDirect: parentChain.length === 0,
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile,
      isDevelopmentDependency: devNames.has(fallbackName),
    });
  }

  const key = `${entry.name.toLowerCase()}@${entry.version.toLowerCase()}`;
  if (visiting.has(key)) {
    return createDependency({
      name: entry.name,
      version: entry.version,
      ecosystem: "npm",
      isDirect: parentChain.length === 0,
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile,
      isDevelopmentDependency: devNames.has(entry.name),
    });
  }

  const nextVisiting = new Set(visiting);
  nextVisiting.add(key);
  const nextParentChain = parentChain.concat(entry.name);
  const transitives = [];

  for (const dependencyName of Object.keys(entry.dependencies || {})) {
    const versionHint = entry.dependencies[dependencyName];
    transitives.push(buildYarnDependency(
      selectYarnEntry(parsedEntries, dependencyName, versionHint),
      dependencyName,
      nextParentChain,
      parsedEntries,
      nextVisiting,
      sourceFile,
      devNames
    ));
  }

  return createDependency({
    name: entry.name,
    version: entry.version,
    ecosystem: "npm",
    isDirect: parentChain.length === 0,
    parent: parentChain[parentChain.length - 1] || null,
    parentChain,
    transitives: deduplicateDeps(transitives),
    sourceFile,
    isDevelopmentDependency: devNames.has(entry.name),
  });
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
      const key = `${currentEntry.name.toLowerCase()}@${currentEntry.version.toLowerCase()}`;
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
        if (!entriesByName.has(currentEntry.name)) {
          entriesByName.set(currentEntry.name, []);
        }
        entriesByName.get(currentEntry.name).push(currentEntry);
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
      const name = parseYarnSelectorName(primarySelector);
      if (!name) {
        continue;
      }
      currentEntry = {
        name,
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

    const versionMatch = trimmed.match(/^version\s+"([^"]+)"/);
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
    const exactSelectorKey = `${normalizedName}@${normalizedHint}`;
    const selectedKey = parsedEntries.selectorIndex.get(exactSelectorKey);
    if (selectedKey && parsedEntries.entries.has(selectedKey)) {
      return parsedEntries.entries.get(selectedKey);
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

  for (const directName of directNames) {
    const entry = selectPnpmEntry(parsed.packageEntries, directName, parsed.directVersions.get(directName));
    directRoots.push(buildPnpmDependency(
      entry,
      directName,
      [],
      parsed.packageEntries,
      new Set(),
      sourceFile,
      manifest.devNames
    ));
  }

  let dependencies = deduplicateDeps(flattenDependencies(directRoots));
  for (const entry of parsed.packageEntries.values()) {
    const key = `${entry.name.toLowerCase()}@${entry.version.toLowerCase()}`;
    if (dependencies.some((dependency) => `${dependency.name.toLowerCase()}@${dependency.version.toLowerCase()}` === key)) {
      continue;
    }
    dependencies.push(createDependency({
      name: entry.name,
      version: entry.version,
      ecosystem: "npm",
      isDirect: false,
      parent: null,
      parentChain: [],
      transitives: [],
      sourceFile,
      isDevelopmentDependency: manifest.devNames.has(entry.name),
    }));
  }

  const warnings = [];
  if (options.maxDependenciesToScan && dependencies.length > options.maxDependenciesToScan) {
    warnings.push(
      `Large npm dependency tree (${dependencies.length} unique packages). ` +
      `Display is capped at ${options.maxDependenciesToScan} dependencies.`
    );
  }

  return buildTree("npm", sourceFile, dependencies, warnings);
}

function buildPnpmDependency(entry, fallbackName, parentChain, packageEntries, visiting, sourceFile, devNames) {
  if (!entry) {
    return createDependency({
      name: fallbackName,
      version: "",
      ecosystem: "npm",
      isDirect: parentChain.length === 0,
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile,
      isDevelopmentDependency: devNames.has(fallbackName),
    });
  }

  const key = `${entry.name.toLowerCase()}@${entry.version.toLowerCase()}`;
  if (visiting.has(key)) {
    return createDependency({
      name: entry.name,
      version: entry.version,
      ecosystem: "npm",
      isDirect: parentChain.length === 0,
      parent: parentChain[parentChain.length - 1] || null,
      parentChain,
      transitives: [],
      sourceFile,
      isDevelopmentDependency: devNames.has(entry.name),
    });
  }

  const nextVisiting = new Set(visiting);
  nextVisiting.add(key);
  const nextParentChain = parentChain.concat(entry.name);
  const transitives = [];

  for (const [dependencyName, versionHint] of Object.entries(entry.dependencies || {})) {
    transitives.push(buildPnpmDependency(
      selectPnpmEntry(packageEntries, dependencyName, versionHint),
      dependencyName,
      nextParentChain,
      packageEntries,
      nextVisiting,
      sourceFile,
      devNames
    ));
  }

  return createDependency({
    name: entry.name,
    version: entry.version,
    ecosystem: "npm",
    isDirect: parentChain.length === 0,
    parent: parentChain[parentChain.length - 1] || null,
    parentChain,
    transitives: deduplicateDeps(transitives),
    sourceFile,
    isDevelopmentDependency: devNames.has(entry.name),
  });
}

function selectPnpmEntry(packageEntries, dependencyName, versionHint) {
  const normalizedHint = normalizeVersion(versionHint).split("(")[0].trim();
  const entries = [...packageEntries.values()].filter((entry) => entry.name === dependencyName);
  if (entries.length === 0) {
    return null;
  }
  if (normalizedHint) {
    const exactMatch = entries.find((entry) => entry.version === normalizedHint);
    if (exactMatch) {
      return exactMatch;
    }
  }
  return entries[0];
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
    packageEntries.set(`${currentPackage.name.toLowerCase()}@${currentPackage.version.toLowerCase()}`, currentPackage);
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

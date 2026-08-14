// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  buildTree,
  createDependency,
  getSourceFileName,
  getWorkspacePath,
  pathExists,
  readJson,
  readUtf8,
} = require("./shared");
const { parseComposerManifest } = require("./manifestHelpers");

const MAX_COMPOSER_INVENTORY = 50000;
const MAX_COMPOSER_EDGES = 500000;
const MAX_COMPOSER_DEPTH = 128;

const composerParser = {
  name: "composerParser",
  ecosystem: "composer",

  async canResolve(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    return (await pathExists(path.join(rootPath, "composer.lock"), workspaceFolder))
      || (await pathExists(path.join(rootPath, "composer.json"), workspaceFolder));
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    const lockfilePath = await pathExists(path.join(rootPath, "composer.lock"), workspaceFolder)
      ? path.join(rootPath, "composer.lock") : null;
    const manifestPath = await pathExists(path.join(rootPath, "composer.json"), workspaceFolder)
      ? path.join(rootPath, "composer.json") : null;
    if (!lockfilePath && !manifestPath) return [];
    return [{
      resolverName: this.name,
      ecosystem: this.ecosystem,
      lockfilePath,
      manifestPath,
      sourceFile: getSourceFileName(lockfilePath || manifestPath),
    }];
  },

  async resolve({ lockfilePath, manifestPath, workspaceFolder, options = {} }) {
    const cancellationToken = options.cancellationToken;
    throwIfComposerCancelled(cancellationToken);
    const sourceFile = getSourceFileName(lockfilePath || manifestPath);
    let manifestDependencies = [];
    if (manifestPath && await pathExists(manifestPath, workspaceFolder)) {
      const content = await readUtf8(manifestPath, workspaceFolder, options);
      try {
        JSON.parse(content);
      } catch {
        throw new Error("The Composer manifest is not valid JSON.");
      }
      manifestDependencies = parseComposerManifest(content);
    }

    if (!lockfilePath) {
      return buildTree("composer", sourceFile, manifestDependencies.map((dependency) => createDependency({
        name: dependency.name,
        version: dependency.version,
        ecosystem: "composer",
        isDirect: true,
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: dependency.isDevelopmentDependency,
        packageSource: dependency.packageSource,
        section: dependency.isDevelopmentDependency ? "require-dev" : "require",
      })));
    }

    const root = await readJson(lockfilePath, workspaceFolder, options);
    const records = parseComposerLockRecords(root, cancellationToken);
    if (records.length === 0) throw new Error("The Composer lockfile did not contain package records.");
    if (records.length > MAX_COMPOSER_INVENTORY) {
      throw new Error("The Composer lockfile inventory is too large to scan completely.");
    }

    const directByName = new Map(manifestDependencies.map((dependency) => [
      dependency.name.toLowerCase(), dependency,
    ]));
    const graph = buildComposerGraph(records, directByName, cancellationToken);
    const dependencies = materializeComposerInventory({
      records,
      directByName,
      graph,
      sourceFile,
      cancellationToken,
    });
    const warnings = graph.truncated
      ? ["Some Composer dependency relationships were omitted to keep the scan responsive. Package inventory remains complete."]
      : [];
    return buildTree("composer", sourceFile, dependencies, warnings);
  },
};

function parseComposerLockRecords(root, cancellationToken) {
  const records = [];
  for (const [section, sectionRecords] of [
    ["packages", root && root.packages],
    ["packages-dev", root && root["packages-dev"]],
  ]) {
    for (const record of Array.isArray(sectionRecords) ? sectionRecords : []) {
      throwIfComposerCancelled(cancellationToken);
      if (!record || typeof record.name !== "string" || !record.name.includes("/")) continue;
      records.push({
        name: record.name,
        version: String(record.version || ""),
        section,
        packageSource: composerPackageSource(record),
        dependencies: Object.keys(record.require || {}).filter(isComposerPackageName),
      });
    }
  }
  const seen = new Set();
  return records.filter((record) => {
    const key = composerRecordKey(record);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function buildComposerGraph(records, directByName, cancellationToken) {
  const byName = new Map(records.map((record) => [record.name.toLowerCase(), record]));
  const byKey = new Map(records.map((record) => [composerRecordKey(record), record]));
  const runtimeReachable = new Set();
  const developmentReachable = new Set();
  const parentByKey = new Map();
  const childrenByKey = new Map();
  const depthByKey = new Map();
  const queue = [];
  let edges = 0;
  let truncated = false;

  const declarations = directByName.size > 0
    ? directByName
    : new Map(records.filter((record) => record.section === "packages")
      .map((record) => [record.name.toLowerCase(), { isDevelopmentDependency: false }]));
  for (const [name, declaration] of declarations) {
    const record = byName.get(name);
    if (!record) continue;
    const key = composerRecordKey(record);
    const reachability = declaration.isDevelopmentDependency ? developmentReachable : runtimeReachable;
    reachability.add(key);
    depthByKey.set(key, 0);
    queue.push({ record, key, depth: 0, development: declaration.isDevelopmentDependency });
  }

  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    throwIfComposerCancelled(cancellationToken);
    const current = queue[cursor];
    if (current.depth >= MAX_COMPOSER_DEPTH) {
      if (current.record.dependencies.length > 0) truncated = true;
      continue;
    }
    for (const dependencyName of current.record.dependencies) {
      if (edges >= MAX_COMPOSER_EDGES) {
        truncated = true;
        break;
      }
      edges += 1;
      const child = byName.get(dependencyName.toLowerCase());
      if (!child) continue;
      const childKey = composerRecordKey(child);
      const reachability = current.development ? developmentReachable : runtimeReachable;
      if (!parentByKey.has(childKey) && childKey !== current.key) {
        parentByKey.set(childKey, current.key);
        if (!childrenByKey.has(current.key)) childrenByKey.set(current.key, []);
        childrenByKey.get(current.key).push(childKey);
        depthByKey.set(childKey, current.depth + 1);
      }
      if (!reachability.has(childKey)) {
        reachability.add(childKey);
        queue.push({ record: child, key: childKey, depth: current.depth + 1, development: current.development });
      }
    }
  }
  return {
    byKey,
    runtimeReachable,
    developmentReachable,
    parentByKey,
    childrenByKey,
    depthByKey,
    truncated,
  };
}

function materializeComposerInventory({ records, directByName, graph, sourceFile, cancellationToken }) {
  const materialized = new Map();
  const ordered = records.slice().sort((left, right) => (
    (graph.depthByKey.get(composerRecordKey(right)) || 0)
      - (graph.depthByKey.get(composerRecordKey(left)) || 0)
  ));
  for (const record of ordered) {
    throwIfComposerCancelled(cancellationToken);
    const key = composerRecordKey(record);
    const declaration = directByName.get(record.name.toLowerCase()) || null;
    const parentKey = declaration ? null : graph.parentByKey.get(key) || null;
    const parentRecord = parentKey ? graph.byKey.get(parentKey) : null;
    const isDevelopmentDependency = graph.developmentReachable.has(key)
      && !graph.runtimeReachable.has(key);
    const parentChain = composerParentChain(parentKey, graph);
    const dependency = createDependency({
      name: record.name,
      version: record.version,
      ecosystem: "composer",
      isDirect: Boolean(declaration),
      parent: parentRecord && parentRecord.name || null,
      parentChain,
      transitives: (graph.childrenByKey.get(key) || []).map((childKey) => materialized.get(childKey)).filter(Boolean),
      sourceFile,
      isDevelopmentDependency,
      packageSource: record.packageSource,
      section: record.section,
    });
    materialized.set(key, {
      ...dependency,
      declaredConstraint: declaration && declaration.version || null,
      hasResolutionEvidence: Boolean(record.version),
    });
  }
  return records.map((record) => materialized.get(composerRecordKey(record)));
}

function composerParentChain(parentKey, graph) {
  const names = [];
  const seen = new Set();
  let key = parentKey;
  while (key && !seen.has(key) && names.length < MAX_COMPOSER_DEPTH) {
    seen.add(key);
    const record = graph.byKey.get(key);
    if (record) names.unshift(record.name);
    key = graph.parentByKey.get(key);
  }
  return names;
}

function composerPackageSource(record) {
  const distType = String(record.dist && record.dist.type || "").toLowerCase();
  const distUrl = record.dist && record.dist.url;
  const sourceType = String(record.source && record.source.type || "").toLowerCase();
  const sourceUrl = record.source && record.source.url;
  if (distType === "path" || sourceType === "path") {
    return { kind: "path", ...(sanitizeComposerLocation(distUrl || sourceUrl) ? { location: sanitizeComposerLocation(distUrl || sourceUrl) } : {}) };
  }
  if (["git", "hg", "svn", "fossil"].includes(sourceType)) {
    return { kind: "git", ...(sanitizeComposerLocation(sourceUrl) ? { location: sanitizeComposerLocation(sourceUrl) } : {}) };
  }
  return { kind: "registry" };
}

function sanitizeComposerLocation(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  if (path.isAbsolute(raw)) return path.basename(raw).slice(0, 4096);
  try {
    const url = new URL(raw);
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return url.toString().slice(0, 4096);
  } catch {
    return raw.replace(/[?#].*$/, "").slice(0, 4096);
  }
}

function composerRecordKey(record) {
  return JSON.stringify([
    record.name.toLowerCase(),
    record.version,
    record.packageSource.kind,
    record.packageSource.location || "",
  ]);
}

function isComposerPackageName(name) {
  return typeof name === "string"
    && name.includes("/")
    && !name.startsWith("ext-")
    && !name.startsWith("lib-")
    && name !== "php";
}

function throwIfComposerCancelled(cancellationToken) {
  if (cancellationToken && cancellationToken.isCancellationRequested) {
    const error = new Error("Dependency traversal was cancelled.");
    error.code = "ERR_DEPENDENCY_TRAVERSAL_CANCELLED";
    throw error;
  }
}

module.exports = composerParser;

// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  buildTree,
  createDependency,
  getSourceFileName,
  getWorkspacePath,
  pathExists,
  readUtf8,
} = require("./shared");
const { parseMixExsManifest } = require("./manifestHelpers");

const MAX_HEX_INVENTORY = 50000;
const MAX_HEX_EDGES = 500000;
const MAX_HEX_DEPTH = 128;

const hexParser = {
  name: "hexParser",
  ecosystem: "hex",

  async canResolve(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    return (await pathExists(path.join(rootPath, "mix.lock"), workspaceFolder))
      || (await pathExists(path.join(rootPath, "mix.exs"), workspaceFolder));
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    const lockfilePath = await pathExists(path.join(rootPath, "mix.lock"), workspaceFolder)
      ? path.join(rootPath, "mix.lock") : null;
    const manifestPath = await pathExists(path.join(rootPath, "mix.exs"), workspaceFolder)
      ? path.join(rootPath, "mix.exs") : null;
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
    throwIfHexCancelled(cancellationToken);
    const sourceFile = getSourceFileName(lockfilePath || manifestPath);
    const manifestDependencies = manifestPath && await pathExists(manifestPath, workspaceFolder)
      ? parseMixExsManifest(await readUtf8(manifestPath, workspaceFolder, options))
      : [];
    if (!lockfilePath) {
      return buildTree("hex", sourceFile, manifestDependencies.map((dependency) => createDependency({
        name: dependency.name,
        version: dependency.version,
        ecosystem: "hex",
        isDirect: true,
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: dependency.isDevelopmentDependency,
        packageSource: dependency.packageSource,
        qualifiers: dependency.qualifiers,
      })));
    }

    const records = parseMixLock(
      await readUtf8(lockfilePath, workspaceFolder, options),
      cancellationToken
    );
    if (records.length === 0) throw new Error("The Mix lockfile did not contain package records.");
    if (records.length > MAX_HEX_INVENTORY) {
      throw new Error("The Mix lockfile inventory is too large to scan completely.");
    }
    const directByName = new Map(manifestDependencies.map((dependency) => [
      dependency.name.toLowerCase(), dependency,
    ]));
    const graph = buildHexGraph(records, directByName, cancellationToken);
    const dependencies = materializeHexInventory({
      records,
      directByName,
      graph,
      sourceFile,
      cancellationToken,
    });

    // Path dependencies are not guaranteed to appear in mix.lock. Preserve
    // direct declarations as visible non-registry occurrences when absent.
    for (const declaration of manifestDependencies) {
      if (records.some((record) => record.name.toLowerCase() === declaration.name.toLowerCase())) continue;
      dependencies.push(createDependency({
        name: declaration.name,
        version: declaration.version,
        ecosystem: "hex",
        isDirect: true,
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: declaration.isDevelopmentDependency,
        packageSource: declaration.packageSource,
        qualifiers: declaration.qualifiers,
      }));
    }
    const warnings = graph.truncated
      ? ["Some Mix dependency relationships were omitted to keep the scan responsive. Package inventory remains complete."]
      : [];
    return buildTree("hex", sourceFile, dependencies, warnings);
  },
};

function parseMixLock(content, cancellationToken) {
  const records = [];
  const text = String(content || "");
  const entryPattern = /"([^"]+)"\s*:\s*\{/g;
  let match;
  while ((match = entryPattern.exec(text)) !== null) {
    throwIfHexCancelled(cancellationToken);
    const tuple = readBalancedTuple(text, match.index + match[0].lastIndexOf("{"));
    if (!tuple) continue;
    const record = parseMixLockTuple(match[1], tuple.value);
    if (record) records.push(record);
    entryPattern.lastIndex = tuple.end + 1;
  }
  const seen = new Set();
  return records.filter((record) => {
    const key = hexRecordKey(record);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function parseMixLockTuple(name, tuple) {
  const kindMatch = tuple.match(/^\{\s*:([A-Za-z0-9_]+)/);
  if (!kindMatch) return null;
  const kind = kindMatch[1].toLowerCase();
  if (kind === "hex") {
    const versionMatch = tuple.match(/^\{\s*:hex\s*,\s*(?::[A-Za-z0-9_]+|"[^"]+")\s*,\s*"([^"]+)"/);
    if (!versionMatch) return null;
    return {
      name,
      version: versionMatch[1],
      packageSource: { kind: "registry" },
      dependencies: parseHexDependencyTuples(tuple),
    };
  }
  if (kind === "git") {
    const strings = [...tuple.matchAll(/"([^"]*)"/g)].map((item) => item[1]);
    const location = sanitizeHexLocation(strings[0]);
    const revision = String(strings[1] || "").slice(0, 1024);
    return {
      name,
      version: revision,
      packageSource: {
        kind: "git",
        ...(location ? { location } : {}),
        ...(revision ? { revision } : {}),
      },
      dependencies: parseHexDependencyTuples(tuple),
    };
  }
  if (kind === "path") {
    const locationMatch = tuple.match(/"([^"]+)"/);
    const location = sanitizeHexLocation(locationMatch && locationMatch[1]);
    return {
      name,
      version: "",
      packageSource: { kind: "path", ...(location ? { location } : {}) },
      dependencies: parseHexDependencyTuples(tuple),
    };
  }
  return {
    name,
    version: "",
    packageSource: { kind: "unknown" },
    dependencies: [],
  };
}

function parseHexDependencyTuples(tuple) {
  const dependencies = [];
  const pattern = /\{\s*:([A-Za-z0-9_]+)\s*,\s*"[^"]*"\s*,\s*\[/g;
  for (const match of tuple.matchAll(pattern)) {
    if (!dependencies.includes(match[1])) dependencies.push(match[1]);
  }
  return dependencies;
}

function buildHexGraph(records, directByName, cancellationToken) {
  const byName = new Map(records.map((record) => [record.name.toLowerCase(), record]));
  const runtimeReachable = new Set();
  const developmentReachable = new Set();
  const parentByName = new Map();
  const childrenByName = new Map();
  const depthByName = new Map();
  let truncated = false;
  let edges = 0;
  const queue = [];
  const rootDeclarations = directByName.size > 0
    ? directByName
    : new Map(records.filter((record) => !records.some((other) => other.dependencies.includes(record.name)))
      .map((record) => [record.name.toLowerCase(), { isDevelopmentDependency: false }]));
  for (const [name, declaration] of rootDeclarations) {
    const record = byName.get(name);
    if (!record) continue;
    const reachability = declaration.isDevelopmentDependency ? developmentReachable : runtimeReachable;
    reachability.add(name);
    depthByName.set(name, 0);
    queue.push({ record, name, depth: 0, development: declaration.isDevelopmentDependency });
  }

  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    throwIfHexCancelled(cancellationToken);
    const current = queue[cursor];
    if (current.depth >= MAX_HEX_DEPTH) {
      if (current.record.dependencies.length > 0) truncated = true;
      continue;
    }
    for (const childName of current.record.dependencies) {
      if (edges >= MAX_HEX_EDGES) {
        truncated = true;
        break;
      }
      edges += 1;
      const normalizedChild = childName.toLowerCase();
      const child = byName.get(normalizedChild);
      if (!child) continue;
      const reachability = current.development ? developmentReachable : runtimeReachable;
      if (!parentByName.has(normalizedChild) && normalizedChild !== current.name) {
        parentByName.set(normalizedChild, current.name);
        if (!childrenByName.has(current.name)) childrenByName.set(current.name, []);
        childrenByName.get(current.name).push(normalizedChild);
        depthByName.set(normalizedChild, current.depth + 1);
      }
      if (!reachability.has(normalizedChild)) {
        reachability.add(normalizedChild);
        queue.push({
          record: child,
          name: normalizedChild,
          depth: current.depth + 1,
          development: current.development,
        });
      }
    }
  }
  return {
    byName,
    runtimeReachable,
    developmentReachable,
    parentByName,
    childrenByName,
    depthByName,
    truncated,
  };
}

function materializeHexInventory({ records, directByName, graph, sourceFile, cancellationToken }) {
  const materialized = new Map();
  const ordered = records.slice().sort((left, right) => (
    (graph.depthByName.get(right.name.toLowerCase()) || 0)
      - (graph.depthByName.get(left.name.toLowerCase()) || 0)
  ));
  for (const record of ordered) {
    throwIfHexCancelled(cancellationToken);
    const name = record.name.toLowerCase();
    const declaration = directByName.get(name) || null;
    const parentName = declaration ? null : graph.parentByName.get(name) || null;
    const parentRecord = parentName ? graph.byName.get(parentName) : null;
    const dependency = createDependency({
      name: record.name,
      version: record.version,
      ecosystem: "hex",
      isDirect: Boolean(declaration) || directByName.size === 0 && !parentName,
      parent: parentRecord && parentRecord.name || null,
      parentChain: hexParentChain(parentName, graph),
      transitives: (graph.childrenByName.get(name) || []).map((childName) => materialized.get(childName)).filter(Boolean),
      sourceFile,
      isDevelopmentDependency: graph.developmentReachable.has(name) && !graph.runtimeReachable.has(name),
      packageSource: record.packageSource,
      qualifiers: declaration && declaration.qualifiers,
    });
    materialized.set(name, {
      ...dependency,
      declaredConstraint: declaration && declaration.version || null,
      hasResolutionEvidence: Boolean(record.version),
    });
  }
  return records.map((record) => materialized.get(record.name.toLowerCase()));
}

function hexParentChain(parentName, graph) {
  const names = [];
  const seen = new Set();
  let current = parentName;
  while (current && !seen.has(current) && names.length < MAX_HEX_DEPTH) {
    seen.add(current);
    const record = graph.byName.get(current);
    if (record) names.unshift(record.name);
    current = graph.parentByName.get(current);
  }
  return names;
}

function readBalancedTuple(content, start) {
  let depth = 0;
  let quote = "";
  let escaped = false;
  for (let index = start; index < content.length; index += 1) {
    const character = content[index];
    if (quote) {
      if (character === "\\" && !escaped) {
        escaped = true;
        continue;
      }
      if (character === quote && !escaped) quote = "";
      escaped = false;
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }
    if (character === "{") depth += 1;
    if (character === "}") {
      depth -= 1;
      if (depth === 0) return { value: content.slice(start, index + 1), end: index };
    }
  }
  return null;
}

function sanitizeHexLocation(value) {
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

function hexRecordKey(record) {
  return JSON.stringify([
    record.name.toLowerCase(),
    record.version,
    record.packageSource.kind,
    record.packageSource.location || "",
  ]);
}

function throwIfHexCancelled(cancellationToken) {
  if (cancellationToken && cancellationToken.isCancellationRequested) {
    const error = new Error("Dependency traversal was cancelled.");
    error.code = "ERR_DEPENDENCY_TRAVERSAL_CANCELLED";
    throw error;
  }
}

module.exports = hexParser;

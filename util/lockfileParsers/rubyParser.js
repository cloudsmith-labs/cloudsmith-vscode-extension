// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  buildTree,
  countIndent,
  createDependency,
  getSourceFileName,
  getWorkspacePath,
  pathExists,
  readUtf8,
} = require("./shared");
const { parseGemfileManifest } = require("./manifestHelpers");

const MAX_RUBY_INVENTORY = 50000;
const MAX_RUBY_RELATIONSHIP_EDGES = 500000;
const MAX_RUBY_RELATIONSHIP_DEPTH = 128;

const rubyParser = {
  name: "rubyParser",
  ecosystem: "ruby",

  async canResolve(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    return (await pathExists(path.join(rootPath, "Gemfile.lock"), workspaceFolder))
      || (await pathExists(path.join(rootPath, "Gemfile"), workspaceFolder));
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    const lockfilePath = await pathExists(path.join(rootPath, "Gemfile.lock"), workspaceFolder)
      ? path.join(rootPath, "Gemfile.lock")
      : null;
    const manifestPath = await pathExists(path.join(rootPath, "Gemfile"), workspaceFolder)
      ? path.join(rootPath, "Gemfile")
      : null;
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
    throwIfRubyCancelled(cancellationToken);
    const sourceFile = getSourceFileName(lockfilePath || manifestPath);
    const manifestDependencies = manifestPath && await pathExists(manifestPath, workspaceFolder)
      ? parseGemfileManifest(await readUtf8(manifestPath, workspaceFolder, options))
      : [];
    if (!lockfilePath) {
      return buildTree("ruby", sourceFile, manifestDependencies.map((dependency) => ({
        ...createDependency({
          name: dependency.name,
          version: dependency.version,
          ecosystem: "ruby",
          isDirect: true,
          parent: null,
          parentChain: [],
          transitives: [],
          sourceFile,
          isDevelopmentDependency: dependency.isDevelopmentDependency,
          packageSource: dependency.packageSource,
        }),
        declaredConstraint: dependency.version || null,
      })));
    }

    const parsed = parseGemfileLock(
      await readUtf8(lockfilePath, workspaceFolder, options),
      cancellationToken
    );
    if (parsed.records.length === 0) {
      throw new Error("The Ruby lockfile did not contain package records.");
    }
    if (parsed.records.length > MAX_RUBY_INVENTORY) {
      throw new Error("The Ruby lockfile inventory is too large to scan completely.");
    }

    const declarations = manifestDependencies.length > 0
      ? manifestDependencies
      : parsed.directNames.map((name) => ({
        name,
        version: "",
        isDevelopmentDependency: false,
        packageSource: { kind: "registry" },
      }));
    const directByName = new Map();
    for (const declaration of declarations) {
      const key = declaration.name.toLowerCase();
      const previous = directByName.get(key);
      directByName.set(key, {
        ...declaration,
        isDevelopmentDependency: previous
          ? previous.isDevelopmentDependency && declaration.isDevelopmentDependency
          : declaration.isDevelopmentDependency,
      });
    }

    const graph = buildRubyGraph(parsed.records, directByName, cancellationToken);
    const dependencies = materializeRubyInventory({
      records: parsed.records,
      directByName,
      graph,
      sourceFile,
      cancellationToken,
    });
    const warnings = graph.truncated
      ? ["Some Ruby dependency relationships were omitted to keep the scan responsive. Package inventory remains complete."]
      : [];
    return buildTree("ruby", sourceFile, dependencies, warnings);
  },
};

function parseGemfileLock(content, cancellationToken) {
  const records = [];
  const directNames = [];
  let section = "";
  let inSpecs = false;
  let current = null;
  let currentSource = { kind: "registry" };

  const flushCurrent = () => {
    if (current && current.name && current.version) records.push(current);
    current = null;
  };

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    throwIfRubyCancelled(cancellationToken);
    const trimmed = rawLine.trimEnd();
    if (!trimmed) continue;
    const indent = countIndent(rawLine);
    const line = trimmed.trim();

    if (indent === 0 && /^[A-Z][A-Z0-9_ ]+$/.test(line)) {
      flushCurrent();
      section = line;
      inSpecs = false;
      currentSource = rubySourceForSection(section, "");
      continue;
    }
    if (section === "DEPENDENCIES" && indent === 2) {
      const name = line.split(/[\s(!]/, 1)[0].replace(/!$/, "").trim();
      if (name) directNames.push(name);
      continue;
    }
    if (!["GEM", "GIT", "PATH"].includes(section)) continue;
    if (indent === 2 && line.startsWith("remote:")) {
      currentSource = rubySourceForSection(section, line.slice("remote:".length).trim());
      continue;
    }
    if (indent === 2 && line === "specs:") {
      inSpecs = true;
      continue;
    }
    if (!inSpecs) continue;
    if (indent === 4) {
      flushCurrent();
      const match = line.match(/^([^\s(]+) \(([^)]+)\)/);
      if (!match) continue;
      const parsedVersion = splitRubyVersionAndPlatform(match[2]);
      current = {
        name: match[1],
        version: parsedVersion.version,
        platform: parsedVersion.platform,
        packageSource: currentSource,
        dependencies: [],
      };
      continue;
    }
    if (indent >= 6 && current) {
      const match = line.match(/^([^\s(]+)(?: \(([^)]+)\))?/);
      if (match) {
        current.dependencies.push({
          name: match[1].replace(/!$/, ""),
          version: exactRubyDependencyVersion(match[2]),
        });
      }
    }
  }
  flushCurrent();
  return { records: dedupeRubyRecords(records), directNames: [...new Set(directNames)] };
}

function buildRubyGraph(records, directByName, cancellationToken) {
  const byName = new Map();
  const byKey = new Map();
  for (const record of records) {
    const key = rubyRecordKey(record);
    byKey.set(key, record);
    const name = record.name.toLowerCase();
    if (!byName.has(name)) byName.set(name, []);
    byName.get(name).push(record);
  }

  const runtimeReachable = new Set();
  const developmentReachable = new Set();
  const parentByKey = new Map();
  const depthByKey = new Map();
  const childrenByKey = new Map();
  let edgeCount = 0;
  let truncated = false;
  const queue = [];
  for (const [name, declaration] of directByName) {
    for (const record of byName.get(name) || []) {
      const key = rubyRecordKey(record);
      const reachability = declaration.isDevelopmentDependency
        ? developmentReachable
        : runtimeReachable;
      if (!reachability.has(key)) {
        reachability.add(key);
        queue.push({ record, key, depth: 0, development: declaration.isDevelopmentDependency });
      }
      if (!depthByKey.has(key)) depthByKey.set(key, 0);
    }
  }

  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    throwIfRubyCancelled(cancellationToken);
    const item = queue[cursor];
    if (item.depth >= MAX_RUBY_RELATIONSHIP_DEPTH) {
      if (item.record.dependencies.length > 0) truncated = true;
      continue;
    }
    for (const reference of item.record.dependencies) {
      if (edgeCount >= MAX_RUBY_RELATIONSHIP_EDGES) {
        truncated = true;
        break;
      }
      edgeCount += 1;
      for (const child of selectRubyChildren(byName, reference, item.record.platform)) {
        const childKey = rubyRecordKey(child);
        const reachability = item.development ? developmentReachable : runtimeReachable;
        if (!parentByKey.has(childKey) && childKey !== item.key) {
          parentByKey.set(childKey, item.key);
          if (!childrenByKey.has(item.key)) childrenByKey.set(item.key, []);
          childrenByKey.get(item.key).push(childKey);
          depthByKey.set(childKey, item.depth + 1);
        }
        if (!reachability.has(childKey)) {
          reachability.add(childKey);
          queue.push({
            record: child,
            key: childKey,
            depth: item.depth + 1,
            development: item.development,
          });
        }
      }
    }
  }

  return {
    byKey,
    parentByKey,
    childrenByKey,
    depthByKey,
    runtimeReachable,
    developmentReachable,
    truncated,
  };
}

function materializeRubyInventory({
  records,
  directByName,
  graph,
  sourceFile,
  cancellationToken,
}) {
  const materialized = new Map();
  const parentChainMemo = new Map();
  const ordered = records.slice().sort((left, right) => (
    (graph.depthByKey.get(rubyRecordKey(right)) || 0)
      - (graph.depthByKey.get(rubyRecordKey(left)) || 0)
  ));
  for (const record of ordered) {
    throwIfRubyCancelled(cancellationToken);
    const key = rubyRecordKey(record);
    const declaration = directByName.get(record.name.toLowerCase()) || null;
    const parentKey = declaration ? null : graph.parentByKey.get(key) || null;
    const parentRecord = parentKey ? graph.byKey.get(parentKey) : null;
    const parentChain = parentKey
      ? rubyParentChain(parentKey, graph, parentChainMemo)
      : [];
    const isDevelopmentDependency = graph.developmentReachable.has(key)
      && !graph.runtimeReachable.has(key);
    const dependency = createDependency({
      name: record.name,
      version: record.version,
      ecosystem: "ruby",
      isDirect: Boolean(declaration),
      parent: parentRecord && parentRecord.name || null,
      parentChain,
      transitives: (graph.childrenByKey.get(key) || []).map((childKey) => materialized.get(childKey)).filter(Boolean),
      sourceFile,
      isDevelopmentDependency,
      platform: record.platform,
      packageSource: record.packageSource,
    });
    materialized.set(key, {
      ...dependency,
      declaredConstraint: declaration && declaration.version || null,
      hasResolutionEvidence: Boolean(record.version),
    });
  }
  return records.map((record) => materialized.get(rubyRecordKey(record)));
}

function rubyParentChain(key, graph, memo, visiting = new Set()) {
  if (memo.has(key)) return memo.get(key);
  if (visiting.has(key)) return [];
  const nextVisiting = new Set(visiting);
  nextVisiting.add(key);
  const parentKey = graph.parentByKey.get(key);
  if (!parentKey) return [];
  const parent = graph.byKey.get(parentKey);
  const chain = rubyParentChain(parentKey, graph, memo, nextVisiting).concat(parent ? parent.name : []);
  memo.set(key, chain);
  return chain;
}

function selectRubyChildren(byName, reference, parentPlatform) {
  let candidates = byName.get(reference.name.toLowerCase()) || [];
  if (reference.version) candidates = candidates.filter((record) => record.version === reference.version);
  if (candidates.length <= 1 || !parentPlatform) return candidates;
  const samePlatform = candidates.filter((record) => record.platform === parentPlatform);
  return samePlatform.length > 0 ? samePlatform : candidates;
}

function splitRubyVersionAndPlatform(value) {
  const version = String(value || "").trim();
  const match = version.match(/^(\d+(?:\.[0-9A-Za-z]+)*?)-(java|ruby|(?:arm64|aarch64|x86_64|x86|x64|universal|wasm32|powerpc|sparc|mswin|mingw)[A-Za-z0-9_.-]*|[A-Za-z0-9_.-]*(?:linux|darwin|freebsd|mingw|mswin)[A-Za-z0-9_.-]*)$/i);
  return match
    ? { version: match[1], platform: match[2] }
    : { version, platform: "ruby" };
}

function exactRubyDependencyVersion(constraint) {
  const match = String(constraint || "").trim().match(/^=\s*([^,\s]+)$/);
  return match ? match[1] : "";
}

function rubySourceForSection(section, location) {
  const kind = section === "GIT" ? "git" : section === "PATH" ? "path" : "registry";
  const safeLocation = sanitizeRubyLocation(location);
  return {
    kind,
    ...(safeLocation ? { location: safeLocation } : {}),
  };
}

function sanitizeRubyLocation(value) {
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

function rubyRecordKey(record) {
  return JSON.stringify([
    record.name.toLowerCase(),
    record.version,
    record.platform,
    record.packageSource.kind,
    record.packageSource.location || "",
  ]);
}

function dedupeRubyRecords(records) {
  const seen = new Set();
  return records.filter((record) => {
    const key = rubyRecordKey(record);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function throwIfRubyCancelled(cancellationToken) {
  if (cancellationToken && cancellationToken.isCancellationRequested) {
    const error = new Error("Dependency traversal was cancelled.");
    error.code = "ERR_DEPENDENCY_TRAVERSAL_CANCELLED";
    throw error;
  }
}

module.exports = rubyParser;

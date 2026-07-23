// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { canonicalFormat, normalizePackageName } = require("./packageNameNormalizer");
const { normalizeUpstreamFormat } = require("./upstreamFormats");
const { UpstreamChecker } = require("./upstreamChecker");

const UPSTREAM_REPO_CONCURRENCY = 5;

function getUncoveredDependencyKey(dependency) {
  const format = canonicalFormat(dependency && (dependency.format || dependency.ecosystem));
  const normalizedName = normalizePackageName(dependency && dependency.name, format);
  const version = String(dependency && dependency.version || "").trim().toLowerCase();

  if (!format || !normalizedName) {
    return null;
  }

  return `${format}:${normalizedName}:${version}`;
}

function formatLabel(format) {
  const normalized = String(format || "").trim();
  if (!normalized) {
    return "package";
  }
  if (normalized === "npm") {
    return "npm";
  }
  if (normalized === "python") {
    return "PyPI";
  }
  if (normalized === "go") {
    return "Go";
  }
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

function buildProxyLabel(upstream, format) {
  const configuredName = String(upstream && upstream.name || "").trim();
  if (!configuredName) {
    return `${formatLabel(format)} proxy`;
  }
  return configuredName.toLowerCase().includes("proxy")
    ? configuredName
    : `${configuredName} proxy`;
}

function buildReachableDetail(snapshot, upstream, format) {
  return `${buildProxyLabel(upstream, format)} on ${snapshot.repo}`;
}

function classifyDependency(dependency, snapshots) {
  const key = getUncoveredDependencyKey(dependency);
  const format = canonicalFormat(dependency && (dependency.format || dependency.ecosystem));
  if (!key || !format) {
    return {
      upstreamStatus: "unreachable",
      upstreamDetail: "Not available through Cloudsmith",
    };
  }

  const upstreamFormat = normalizeUpstreamFormat(format);
  if (!upstreamFormat) {
    return {
      upstreamStatus: "unreachable",
      upstreamDetail: "Not available through Cloudsmith",
    };
  }

  for (const snapshot of snapshots) {
    const formatUpstreams = Array.isArray(snapshot.groupedUpstreams.get(upstreamFormat))
      ? snapshot.groupedUpstreams.get(upstreamFormat)
      : [];
    const activeUpstream = formatUpstreams.find((upstream) => upstream.is_active !== false);
    if (!activeUpstream) {
      continue;
    }

    return {
      upstreamStatus: "reachable",
      upstreamDetail: buildReachableDetail(snapshot, activeUpstream, upstreamFormat),
    };
  }

  return {
    upstreamStatus: "no_proxy",
    upstreamDetail: `No upstream proxy configured for ${upstreamFormat}`,
  };
}

function buildGapPatch(uncoveredDependencies, snapshots) {
  const patchMap = new Map();

  for (const dependency of Array.isArray(uncoveredDependencies) ? uncoveredDependencies : []) {
    if (dependency.cloudsmithStatus !== "NOT_FOUND") {
      continue;
    }

    const key = getUncoveredDependencyKey(dependency);
    if (!key || patchMap.has(key)) {
      continue;
    }

    patchMap.set(key, classifyDependency(dependency, snapshots));
  }

  return patchMap;
}

function applyGapPatch(dependencies, patchMap) {
  return (Array.isArray(dependencies) ? dependencies : []).map((dependency) => {
    const key = getUncoveredDependencyKey(dependency);
    if (!key || !patchMap.has(key)) {
      return dependency;
    }

    const gap = patchMap.get(key);
    return {
      ...dependency,
      upstreamStatus: gap.upstreamStatus,
      upstreamDetail: gap.upstreamDetail,
    };
  });
}

async function analyzeUpstreamGaps(uncoveredDependencies, workspace, repositories, options = {}) {
  const onProgress = typeof options.onProgress === "function" ? options.onProgress : null;
  const cancellationToken = options.cancellationToken || null;
  const upstreamChecker = options.upstreamChecker || new UpstreamChecker(options.context);
  const repositoriesToInspect = Array.isArray(repositories)
    ? repositories.map((repo) => String(repo || "").trim()).filter(Boolean)
    : [];

  if (repositoriesToInspect.length === 0) {
    const emptyPatch = buildGapPatch(uncoveredDependencies, []);
    if (onProgress && emptyPatch.size > 0) {
      onProgress(new Map(emptyPatch), {
        completed: 0,
        total: 0,
        workspace,
        stage: "upstream",
      });
    }
    return applyGapPatch(uncoveredDependencies, emptyPatch);
  }

  const repoUpstreamStates = new Map();
  let completed = 0;

  await runPromisePool(repositoriesToInspect, UPSTREAM_REPO_CONCURRENCY, async (repo) => {
    if (cancellationToken && cancellationToken.isCancellationRequested) {
      return;
    }

    const state = await upstreamChecker.getRepositoryUpstreamState(workspace, repo);
    repoUpstreamStates.set(repo, {
      repo,
      groupedUpstreams: state && state.groupedUpstreams instanceof Map
        ? state.groupedUpstreams
        : new Map(),
    });

    completed += 1;
    if (onProgress) {
      onProgress(new Map(), {
        completed,
        total: repositoriesToInspect.length,
        workspace,
        stage: "upstream",
      });
    }
  });

  const snapshots = repositoriesToInspect
    .filter((repo) => repoUpstreamStates.has(repo))
    .map((repo) => repoUpstreamStates.get(repo));

  const patchMap = buildGapPatch(uncoveredDependencies, snapshots);
  if (onProgress && patchMap.size > 0) {
    onProgress(new Map(patchMap), {
      completed,
      total: repositoriesToInspect.length,
      workspace,
      stage: "upstream",
    });
  }
  return applyGapPatch(uncoveredDependencies, patchMap);
}

async function runPromisePool(items, concurrency, worker) {
  const workers = [];
  let index = 0;
  const size = Math.max(1, Math.min(concurrency, items.length || 1));

  for (let workerIndex = 0; workerIndex < size; workerIndex += 1) {
    workers.push((async () => {
      while (index < items.length) {
        const item = items[index];
        index += 1;
        if (item === undefined) {
          break;
        }
        await worker(item);
      }
    })());
  }

  await Promise.all(workers);
}

module.exports = {
  analyzeUpstreamGaps,
  getUncoveredDependencyKey,
};

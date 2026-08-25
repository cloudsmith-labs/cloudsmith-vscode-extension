// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { canonicalFormat, normalizePackageName } = require("./packageNameNormalizer");
const { getUpstreamFormatDescriptor, normalizeUpstreamFormat } = require("./upstreamFormats");
const { sanitizeSafeInventoryUpstream } = require("./upstreamChecker");

const UPSTREAM_REPO_CONCURRENCY = 4;
const DEFAULT_REPOSITORY_OPERATION_TIMEOUT_MS = 50_000;
const MAX_REPOSITORY_OPERATION_TIMEOUT_MS = 120_000;

function getUncoveredDependencyKey(dependency) {
  const format = canonicalFormat(dependency && (dependency.format || dependency.ecosystem));
  const normalizedName = normalizePackageName(dependency && dependency.name, format);
  const version = String(dependency && dependency.version || "").trim();

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

function classifyDependency(dependency, snapshots, options = {}) {
  const key = getUncoveredDependencyKey(dependency);
  const format = canonicalFormat(dependency && (dependency.format || dependency.ecosystem));
  if (!key || !format) {
    return {
      upstreamStatus: "unreachable",
      upstreamDetail: "Not available through Cloudsmith",
    };
  }

  const upstreamFormat = normalizeUpstreamFormat(format);
  if (!upstreamFormat || !getUpstreamFormatDescriptor(upstreamFormat)?.inspectable) {
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

  const incompleteRepositoryState = snapshots.some(snapshot => (
    (
      snapshot.complete === false
      && (!Array.isArray(snapshot.failedFormats) || snapshot.failedFormats.length === 0)
      && (!Array.isArray(snapshot.uninspectedFormats) || snapshot.uninspectedFormats.length === 0)
    )
    || (Array.isArray(snapshot.failedFormats) && snapshot.failedFormats.includes(upstreamFormat))
    || (
      Array.isArray(snapshot.uninspectedFormats)
      && snapshot.uninspectedFormats.includes(upstreamFormat)
    )
  ));
  if (options.repositoriesComplete === false || incompleteRepositoryState) {
    return {
      upstreamStatus: "unknown",
      upstreamDetail: `Upstream coverage for ${upstreamFormat} could not be inspected completely`,
    };
  }

  return {
    upstreamStatus: "no_proxy",
    upstreamDetail: `No upstream proxy configured for ${upstreamFormat}`,
  };
}

function buildGapPatch(uncoveredDependencies, snapshots, options = {}) {
  const patchMap = new Map();

  for (const dependency of Array.isArray(uncoveredDependencies) ? uncoveredDependencies : []) {
    if (!["ABSENT", "NOT_FOUND"].includes(dependency.cloudsmithStatus)) {
      continue;
    }

    const key = getUncoveredDependencyKey(dependency);
    if (!key || patchMap.has(key)) {
      continue;
    }

    patchMap.set(key, classifyDependency(dependency, snapshots, options));
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
  const repositoriesToInspect = Array.isArray(repositories)
    ? [...new Set(repositories.map((repo) => String(repo || "").trim()).filter(Boolean))]
    : [];
  const repositoriesComplete = options.repositoriesComplete !== false;
  const formatsToInspect = [...new Set((Array.isArray(uncoveredDependencies)
    ? uncoveredDependencies
    : []).map(dependency => normalizeUpstreamFormat(canonicalFormat(
      dependency && (dependency.format || dependency.ecosystem)
    ))).filter(format => getUpstreamFormatDescriptor(format)?.inspectable))];

  if (repositoriesToInspect.length === 0 || formatsToInspect.length === 0) {
    const emptyPatch = buildGapPatch(uncoveredDependencies, [], { repositoriesComplete });
    if (onProgress && emptyPatch.size > 0) {
      publishProgress(onProgress, new Map(emptyPatch), {
        completed: 0,
        total: 0,
        workspace,
        stage: "upstream",
      });
    }
    return applyGapPatch(uncoveredDependencies, emptyPatch);
  }

  const upstreamRuntime = options.upstreamRuntime;
  if (
    !upstreamRuntime
    || typeof upstreamRuntime.getRepositoryUpstreamStateForFormats !== "function"
    || typeof upstreamRuntime.createOperationScope !== "function"
  ) {
    throw new TypeError("Upstream gap analysis requires a safe upstream runtime facade.");
  }
  const operationScope = upstreamRuntime.createOperationScope({
    kind: "gap-analysis",
    account: options.account,
    cancellationToken,
    scheduler: options.scheduler,
    workspace,
    formats: formatsToInspect,
  });

  const repoUpstreamStates = new Map();
  const accountedRepositories = new Set();
  const repositoryOperationTimeoutMs = boundedRepositoryOperationTimeoutMs(
    options.repositoryOperationTimeoutMs
  );
  let completed = 0;

  const publishRepositoryProgress = () => {
    if (!onProgress) return;
    publishProgress(onProgress, new Map(), {
      completed,
      inspected: repoUpstreamStates.size,
      total: repositoriesToInspect.length,
      workspace,
      stage: "upstream",
    });
  };
  const accountRepository = (repo, state, publish = true) => {
    if (accountedRepositories.has(repo)) return;
    accountedRepositories.add(repo);
    if (state !== undefined) {
      const safeState = snapshotSafeRepositoryState(state, formatsToInspect);
      repoUpstreamStates.set(repo, {
        repo,
        ...safeState,
      });
    }
    completed = accountedRepositories.size;
    if (publish && completed < repositoriesToInspect.length) publishRepositoryProgress();
  };

  try {
    await runPromisePool(repositoriesToInspect, UPSTREAM_REPO_CONCURRENCY, async (repo) => {
      if (
        isCancelled(cancellationToken)
        || operationScope.signal?.aborted
        || operationScope.scheduler?.stopped
      ) return false;

      const completion = await settleRepositoryOperation(
        signal => upstreamRuntime.getRepositoryUpstreamStateForFormats(
          workspace,
          repo,
          formatsToInspect,
          {
            account: options.account,
            operationScope,
            operationTimeoutMs: options.operationTimeoutMs,
            signal,
          }
        ),
        {
          cancellationToken,
          signal: operationScope.signal,
          timeoutMs: repositoryOperationTimeoutMs,
        }
      );
      if (
        isCancelled(cancellationToken)
        || operationScope.signal?.aborted
        || completion.kind === "cancelled"
      ) return false;
      // A rejected or timed-out repository was admitted and reached a terminal
      // inspection attempt. Snapshot it as incomplete so progress terminates
      // without inventing authoritative negative evidence.
      const state = completion.kind === "fulfilled" ? completion.value : null;
      // A request can safely settle while opening the shared scheduler's
      // circuit. Retain and account that terminal state; `stopped` only
      // prevents new fan-out and does not invalidate work already completed.
      accountRepository(repo, state);
      return operationScope.scheduler?.stopped ? false : true;
    });

    if (
      !isCancelled(cancellationToken)
      && !operationScope.signal?.aborted
      && operationScope.scheduler?.stopped
    ) {
      // Repositories not admitted after a circuit/budget stop are terminally
      // accounted as uninspected. They intentionally have no snapshot, which
      // keeps `repositoriesComplete` false and all negative evidence unknown.
      for (const repo of repositoriesToInspect) accountRepository(repo, undefined, false);
    }

    const cancelled = isCancelled(cancellationToken) || operationScope.signal?.aborted;
    const snapshots = repositoriesToInspect
      .filter((repo) => repoUpstreamStates.has(repo))
      .map((repo) => repoUpstreamStates.get(repo));

    const patchMap = buildGapPatch(uncoveredDependencies, snapshots, {
      repositoriesComplete: repositoriesComplete
        && snapshots.length === repositoriesToInspect.length
        && !cancelled,
    });
    const inspectionComplete = repositoriesComplete
      && snapshots.length === repositoriesToInspect.length
      && snapshots.every(snapshot => repositorySnapshotComplete(snapshot, formatsToInspect))
      && !cancelled;
    // Cancellation/supersession owns settlement at the scan transaction. Do
    // not misrepresent it as a completed-but-partial coverage inspection or
    // publish enrichment state from an operation the caller no longer owns.
    if (onProgress && !cancelled) {
      publishProgress(onProgress, new Map(patchMap), {
        completed,
        inspected: snapshots.length,
        total: repositoriesToInspect.length,
        workspace,
        stage: "upstream",
        terminal: true,
        outcome: inspectionComplete ? "complete" : "partial",
      });
    }
    return applyGapPatch(uncoveredDependencies, patchMap);
  } finally {
    operationScope.dispose();
  }
}

function repositorySnapshotComplete(snapshot, requestedFormats) {
  if (snapshot?.complete !== true) return false;
  return requestedFormats.every(format => (
    !snapshot.failedFormats.includes(format)
    && !snapshot.uninspectedFormats.includes(format)
  ));
}

function snapshotSafeRepositoryState(state, requestedFormats) {
  const groupedUpstreams = new Map();
  let safe = Boolean(state && state.groupedUpstreams instanceof Map);
  for (const format of requestedFormats) {
    const candidates = state?.groupedUpstreams instanceof Map
      ? state.groupedUpstreams.get(format)
      : null;
    if (candidates === undefined) continue;
    if (!Array.isArray(candidates)) {
      safe = false;
      continue;
    }
    const upstreams = candidates.map(candidate => sanitizeSafeInventoryUpstream(candidate, format));
    if (upstreams.some(upstream => upstream === null)) {
      safe = false;
      continue;
    }
    groupedUpstreams.set(format, Object.freeze(upstreams));
  }
  const uninspectedFormats = Array.isArray(state?.uninspectedFormats)
    ? [...state.uninspectedFormats]
    : [];
  if (!safe) {
    for (const format of requestedFormats) {
      if (!uninspectedFormats.includes(format)) uninspectedFormats.push(format);
    }
  }
  return {
    groupedUpstreams,
    complete: safe && state?.complete === true,
    failedFormats: Array.isArray(state?.failedFormats) ? [...state.failedFormats] : [],
    uninspectedFormats,
    unsupportedFormats: Array.isArray(state?.unsupportedFormats)
      ? [...state.unsupportedFormats]
      : [],
  };
}

function isCancelled(cancellationToken) {
  return Boolean(cancellationToken && cancellationToken.isCancellationRequested);
}

function publishProgress(onProgress, patchMap, metadata) {
  try {
    onProgress(patchMap, metadata);
  } catch {
    // Progress callbacks are observers and cannot abort or outlive the bounded work pool.
  }
}

async function settleRepositoryOperation(operation, options = {}) {
  const controller = new AbortController();
  const signal = options.signal;
  const cancellationToken = options.cancellationToken;
  let timer = null;
  let cancellationDisposable = null;
  let resolveBoundary;
  let boundarySettled = false;
  const boundary = new Promise((resolve) => {
    resolveBoundary = resolve;
  });
  const settleBoundary = (kind) => {
    if (boundarySettled) return;
    boundarySettled = true;
    controller.abort();
    resolveBoundary({ kind });
  };
  const onAbort = () => settleBoundary("cancelled");

  if (signal?.aborted || isCancelled(cancellationToken)) {
    settleBoundary("cancelled");
  } else {
    signal?.addEventListener?.("abort", onAbort, { once: true });
    if (typeof cancellationToken?.onCancellationRequested === "function") {
      cancellationDisposable = cancellationToken.onCancellationRequested(onAbort);
    }
    if (signal?.aborted || isCancelled(cancellationToken)) onAbort();
    if (!boundarySettled) {
      timer = setTimeout(() => settleBoundary("timeout"), options.timeoutMs);
      timer.unref?.();
    }
  }

  // Both branches stay observed after a timeout/cancellation wins the race.
  // A non-cooperative runtime cannot strand the repository pool or surface a
  // late unhandled rejection.
  let observed;
  if (controller.signal.aborted) {
    observed = Promise.resolve({ kind: "cancelled" });
  } else {
    try {
      // Invoke synchronously so shared scheduler/circuit state is visible to
      // the next pool worker before it can admit additional repository work.
      observed = Promise.resolve(operation(controller.signal)).then(
        value => ({ kind: "fulfilled", value }),
        () => ({ kind: "rejected" })
      );
    } catch {
      observed = Promise.resolve({ kind: "rejected" });
    }
  }

  try {
    return await Promise.race([observed, boundary]);
  } finally {
    if (timer !== null) clearTimeout(timer);
    signal?.removeEventListener?.("abort", onAbort);
    cancellationDisposable?.dispose?.();
  }
}

function boundedRepositoryOperationTimeoutMs(value) {
  return Number.isSafeInteger(value) && value > 0
    ? Math.min(value, MAX_REPOSITORY_OPERATION_TIMEOUT_MS)
    : DEFAULT_REPOSITORY_OPERATION_TIMEOUT_MS;
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
        if (await worker(item) === false) break;
      }
    })());
  }

  await Promise.allSettled(workers);
}

module.exports = {
  analyzeUpstreamGaps,
  getUncoveredDependencyKey,
};

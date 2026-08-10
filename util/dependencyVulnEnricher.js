// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { CloudsmithAPI } = require("./cloudsmithAPI");
const { apiEndpoint } = require("./apiEndpoint");
const { getFoundDependencyKey } = require("./foundDependencyKey");
const {
  captureAccount,
  isAccountCurrent,
  resolveConnectionManager,
} = require("./accountOperation");

const VULNERABILITY_CACHE_TTL_MS = 10 * 60 * 1000;
const VULNERABILITY_CACHE_MAX_SIZE = 5000;
const VULNERABILITY_CONCURRENCY = 10;
const vulnerabilityCache = new Map();

function severityRank(severity) {
  switch (String(severity || "").trim().toLowerCase()) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

function canonicalSeverity(severity) {
  const normalized = String(severity || "").trim().toLowerCase();
  switch (normalized) {
    case "critical":
      return "Critical";
    case "high":
      return "High";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
    default:
      return severity ? String(severity).trim() : null;
  }
}

function getIndicatorCount(packageModel) {
  const rawCount = packageModel && (
    packageModel.vulnerability_scan_results_count
    || packageModel.num_vulnerabilities
    || packageModel.vulnerabilityCount
  );
  const count = Number(rawCount);
  return Number.isFinite(count) && count > 0 ? count : 0;
}

function buildEmptySummary(packageModel) {
  return {
    count: 0,
    maxSeverity: canonicalSeverity(packageModel && packageModel.max_severity),
    cveIds: [],
    hasFixAvailable: false,
    severityCounts: {},
    entries: [],
    detailsLoaded: false,
    policyViolated: Boolean(packageModel && packageModel.vulnerability_policy_violated),
  };
}

function buildIndicatorSummary(packageModel) {
  const count = getIndicatorCount(packageModel);
  if (count === 0) {
    return buildEmptySummary(packageModel);
  }

  const maxSeverity = canonicalSeverity(packageModel && packageModel.max_severity);
  const severityCounts = {};
  if (maxSeverity) {
    severityCounts[maxSeverity] = 1;
  }

  return {
    count,
    maxSeverity,
    cveIds: [],
    hasFixAvailable: false,
    severityCounts,
    entries: [],
    detailsLoaded: false,
    policyViolated: Boolean(packageModel && packageModel.vulnerability_policy_violated),
  };
}

function extractVulnerabilityEntries(payload) {
  if (Array.isArray(payload)) {
    return payload;
  }

  if (!payload || typeof payload !== "object") {
    return [];
  }

  if (Array.isArray(payload.results)) {
    return payload.results;
  }

  if (Array.isArray(payload.vulnerabilities)) {
    return payload.vulnerabilities;
  }

  if (Array.isArray(payload.items)) {
    return payload.items;
  }

  if (!Array.isArray(payload.scans)) {
    return [];
  }

  const results = [];
  for (const scan of payload.scans) {
    if (!scan || !Array.isArray(scan.results)) {
      continue;
    }
    results.push(...scan.results);
  }

  return results;
}

function extractFixVersion(entry) {
  const candidates = [
    entry && entry.fixed_version,
    entry && entry.fix_version,
    entry && entry.fixedVersion,
    entry && entry.fixVersion,
    entry && entry.suggested_fix,
    entry && entry.suggestedFix,
  ];

  if (entry && Array.isArray(entry.fixed_in_versions) && entry.fixed_in_versions.length > 0) {
    candidates.push(entry.fixed_in_versions[0]);
  }

  if (entry && Array.isArray(entry.fix_versions) && entry.fix_versions.length > 0) {
    candidates.push(entry.fix_versions[0]);
  }

  for (const candidate of candidates) {
    const value = String(candidate || "").trim();
    if (value) {
      return value;
    }
  }

  return null;
}

function normalizeEntry(entry) {
  const severity = canonicalSeverity(
    entry && (
      entry.severity
      || entry.severity_label
      || entry.max_severity
    )
  ) || "Unknown";

  const cveId = String(
    (entry && (
      entry.vulnerability_id
      || entry.identifier
      || entry.id
      || entry.name
    )) || "Unknown"
  ).trim();

  const fixVersion = extractFixVersion(entry);

  return {
    cveId,
    severity,
    description: String(entry && (entry.title || entry.description || "") || "").trim(),
    fixVersion,
    hasFixAvailable: Boolean(fixVersion),
  };
}

function summarizeEntries(entries, fallbackSummary) {
  const severityCounts = {};
  const cveIds = [];
  const normalizedEntries = [];
  let maxSeverity = null;
  let hasFixAvailable = false;

  for (const entry of entries.map(normalizeEntry)) {
    normalizedEntries.push(entry);
    if (!cveIds.includes(entry.cveId)) {
      cveIds.push(entry.cveId);
    }
    severityCounts[entry.severity] = (severityCounts[entry.severity] || 0) + 1;
    if (!maxSeverity || severityRank(entry.severity) > severityRank(maxSeverity)) {
      maxSeverity = entry.severity;
    }
    if (entry.hasFixAvailable) {
      hasFixAvailable = true;
    }
  }

  return {
    count: normalizedEntries.length || fallbackSummary.count || 0,
    maxSeverity: maxSeverity || fallbackSummary.maxSeverity || null,
    cveIds,
    hasFixAvailable,
    severityCounts,
    entries: normalizedEntries,
    detailsLoaded: true,
    policyViolated: Boolean(fallbackSummary.policyViolated),
  };
}

function isCancellationRequested(cancellationToken) {
  return Boolean(cancellationToken && cancellationToken.isCancellationRequested);
}

function sortGroups(left, right) {
  if (left.priority !== right.priority) {
    return left.priority - right.priority;
  }

  if (left.workspace !== right.workspace) {
    return left.workspace.localeCompare(right.workspace);
  }

  if (left.repo !== right.repo) {
    return left.repo.localeCompare(right.repo);
  }

  return left.name.localeCompare(right.name);
}

function collectPackageGroups(dependencies) {
  const groups = new Map();

  for (const dependency of Array.isArray(dependencies) ? dependencies : []) {
    if (dependency.cloudsmithStatus !== "FOUND" || !dependency.cloudsmithPackage) {
      continue;
    }

    const packageKey = getFoundDependencyKey(dependency);
    if (!packageKey) {
      continue;
    }

    const existing = groups.get(packageKey);
    const priority = dependency.isDirect ? 0 : 1;

    if (!existing) {
      groups.set(packageKey, {
        key: packageKey,
        packageModel: dependency.cloudsmithPackage,
        workspace: String(dependency.cloudsmithPackage.namespace || "").toLowerCase(),
        repo: String(dependency.cloudsmithPackage.repository || "").toLowerCase(),
        name: String(dependency.name || "").toLowerCase(),
        priority,
      });
      continue;
    }

    if (priority < existing.priority) {
      existing.priority = priority;
    }
  }

  return [...groups.values()].sort(sortGroups);
}

async function runPool(items, concurrency, worker) {
  const workers = [];
  let index = 0;
  const poolSize = Math.max(1, Math.min(concurrency, items.length || 1));

  for (let workerIndex = 0; workerIndex < poolSize; workerIndex += 1) {
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

function pruneExpiredVulnerabilityCache(now = Date.now()) {
  for (const [cacheKey, cacheEntry] of vulnerabilityCache.entries()) {
    if (!cacheEntry || cacheEntry.expiresAt <= now) {
      vulnerabilityCache.delete(cacheKey);
    }
  }
}

function getCachedVulnerabilitySummary(packageKey, account, now) {
  const cached = vulnerabilityCache.get(packageKey);
  if (!cached) {
    return null;
  }

  if (
    cached.expiresAt > now
    && cached.activationId === account.activationId
    && cached.accountEpoch === account.accountEpoch
  ) {
    // Reinsert cache hits so the hard-cap eviction policy is deterministic LRU.
    vulnerabilityCache.delete(packageKey);
    vulnerabilityCache.set(packageKey, cached);
    return cached.value;
  }

  vulnerabilityCache.delete(packageKey);
  return null;
}

function setCachedVulnerabilitySummary(packageKey, value, account, now) {
  vulnerabilityCache.delete(packageKey);
  if (vulnerabilityCache.size >= VULNERABILITY_CACHE_MAX_SIZE) {
    pruneExpiredVulnerabilityCache(now);
  }
  while (vulnerabilityCache.size >= VULNERABILITY_CACHE_MAX_SIZE) {
    const oldestKey = vulnerabilityCache.keys().next().value;
    if (oldestKey === undefined) break;
    vulnerabilityCache.delete(oldestKey);
  }

  vulnerabilityCache.set(packageKey, {
    activationId: account.activationId,
    accountEpoch: account.accountEpoch,
    expiresAt: now + VULNERABILITY_CACHE_TTL_MS,
    value,
  });
}

async function fetchVulnerabilitySummary(
  api,
  packageModel,
  fallbackSummary,
  cancellationToken,
  connectionManager,
  account,
  now
) {
  const packageKey = getFoundDependencyKey({ cloudsmithPackage: packageModel });
  if (!packageKey) {
    return fallbackSummary;
  }

  if (!isAccountCurrent(connectionManager, account)) return null;
  const cachedValue = getCachedVulnerabilitySummary(packageKey, account, now());
  if (cachedValue) {
    return cachedValue;
  }

  if (isCancellationRequested(cancellationToken)) {
    return fallbackSummary;
  }

  const workspace = String(packageModel.namespace || "").trim();
  const repo = String(packageModel.repository || "").trim();
  const identifier = String(
    packageModel.slug_perm
      || packageModel.slugPerm
      || packageModel.slug
      || packageModel.identifier
      || ""
  ).trim();

  if (!workspace || !repo || !identifier) {
    return fallbackSummary;
  }

  let endpoint;
  try {
    endpoint = apiEndpoint(["vulnerabilities", workspace, repo, identifier]);
  } catch {
    return null;
  }
  const response = await api.getV2(endpoint, {
    responseType: "json",
    validate: isRecognizedVulnerabilityDetail,
    retry: "never",
    cancellationToken,
  });
  if (
    !response.ok
    || isCancellationRequested(cancellationToken)
    || !isAccountCurrent(connectionManager, account)
  ) {
    return null;
  }

  const summary = summarizeEntries(extractVulnerabilityEntries(response.data), fallbackSummary);
  if (!isAccountCurrent(connectionManager, account)) return null;
  setCachedVulnerabilitySummary(packageKey, summary, account, now());
  return summary;
}

function applyVulnerabilityPatch(dependencies, patchMap) {
  return (Array.isArray(dependencies) ? dependencies : []).map((dependency) => {
    const packageKey = getFoundDependencyKey(dependency);
    if (!packageKey || !patchMap.has(packageKey)) {
      return dependency;
    }

    return {
      ...dependency,
      vulnerabilities: patchMap.get(packageKey),
    };
  });
}

async function enrichVulnerabilities(dependencies, workspace, options = {}) {
  const onProgress = typeof options.onProgress === "function" ? options.onProgress : null;
  const cancellationToken = options.cancellationToken || null;
  const connectionManager = resolveConnectionManager(options.context, options.connectionManager);
  const account = options.account || captureAccount(connectionManager);
  if (!account || !isAccountCurrent(connectionManager, account)) {
    return Array.isArray(dependencies) ? dependencies : [];
  }
  const api = options.cloudsmithAPI || new CloudsmithAPI(options.context);
  const now = options.now || Date.now;
  const groups = collectPackageGroups(dependencies);
  const patchMap = new Map();
  const detailTargets = [];

  for (const group of groups) {
    const indicatorSummary = buildIndicatorSummary(group.packageModel);
    patchMap.set(group.key, indicatorSummary);
    if (indicatorSummary.count > 0) {
      detailTargets.push({
        ...group,
        fallbackSummary: indicatorSummary,
      });
    }
  }

  if (onProgress && patchMap.size > 0 && isAccountCurrent(connectionManager, account)) {
    onProgress(new Map(patchMap), {
      completed: 0,
      total: detailTargets.length,
      workspace,
      stage: "initial",
    });
  }

  let completed = 0;
  let stale = false;
  await runPool(detailTargets, VULNERABILITY_CONCURRENCY, async (target) => {
    if (isCancellationRequested(cancellationToken) || !isAccountCurrent(connectionManager, account)) {
      stale = stale || !isAccountCurrent(connectionManager, account);
      return;
    }

    const summary = await fetchVulnerabilitySummary(
      api,
      target.packageModel,
      target.fallbackSummary,
      cancellationToken,
      connectionManager,
      account,
      now
    );

    if (!isAccountCurrent(connectionManager, account)) {
      stale = true;
      return;
    }
    if (summary) {
      patchMap.set(target.key, summary);
    }
    completed += 1;

    if (onProgress && isAccountCurrent(connectionManager, account)) {
      onProgress(summary ? new Map([[target.key, summary]]) : new Map(), {
        completed,
        total: detailTargets.length,
        workspace,
        stage: "details",
      });
    }
  });

  if (stale || !isAccountCurrent(connectionManager, account)) {
    return Array.isArray(dependencies) ? dependencies : [];
  }
  return applyVulnerabilityPatch(dependencies, patchMap);
}

function isRecognizedVulnerabilityDetail(value) {
  if (Array.isArray(value)) {
    return isVulnerabilityRecordArray(value);
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  if (Object.prototype.hasOwnProperty.call(value, "results")) {
    return Array.isArray(value.results) && isVulnerabilityRecordArray(value.results);
  }
  if (Object.prototype.hasOwnProperty.call(value, "vulnerabilities")) {
    return Array.isArray(value.vulnerabilities) && isVulnerabilityRecordArray(value.vulnerabilities);
  }
  if (Object.prototype.hasOwnProperty.call(value, "items")) {
    return Array.isArray(value.items) && isVulnerabilityRecordArray(value.items);
  }
  return Array.isArray(value.scans) && value.scans.every(scan => (
    scan
    && typeof scan === "object"
    && !Array.isArray(scan)
    && Array.isArray(scan.results)
    && isVulnerabilityRecordArray(scan.results)
  ));
}

function isVulnerabilityRecordArray(value) {
  return Array.isArray(value) && value.every(entry => (
    Boolean(entry)
    && typeof entry === "object"
    && !Array.isArray(entry)
    && [entry.vulnerability_id, entry.identifier, entry.id, entry.name]
      .some(identifier => typeof identifier === "string" && identifier.trim().length > 0)
    && (entry.severity === undefined || entry.severity === null || typeof entry.severity === "string")
  ));
}

module.exports = {
  clearVulnerabilityCache() {
    vulnerabilityCache.clear();
  },
  enrichVulnerabilities,
  getVulnerabilityCacheSize() {
    return vulnerabilityCache.size;
  },
  VULNERABILITY_CACHE_MAX_SIZE,
};

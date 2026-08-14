// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { CloudsmithAPI } = require("./cloudsmithAPI");
const { apiEndpoint } = require("./apiEndpoint");
const { getFoundDependencyKey } = require("./foundDependencyKey");
const { getPackageVulnerabilityState } = require("./packageVulnerabilities");
const {
  deriveMaximumVulnerabilitySeverity,
  normalizeVulnerabilitySeverity,
} = require("./vulnerabilitySeverity");
const {
  captureAccount,
  isAccountCurrent,
  resolveConnectionManager,
} = require("./accountOperation");

const VULNERABILITY_CACHE_TTL_MS = 10 * 60 * 1000;
const VULNERABILITY_CACHE_MAX_SIZE = 5000;
const VULNERABILITY_CONCURRENCY = 4;
const MAX_VULNERABILITY_DETAIL_REQUESTS = 1000;
const MAX_VULNERABILITY_DETAIL_ENTRIES = 5000;
const MAX_VULNERABILITY_IDENTIFIER_LENGTH = 512;
const MAX_VULNERABILITY_DISPLAY_LENGTH = 4096;
const vulnerabilityCache = new Map();

function canonicalSeverity(severity) {
  return normalizeVulnerabilitySeverity(severity);
}

function getIndicatorCount(packageModel) {
  const state = getPackageVulnerabilityState(packageModel);
  if (state.count !== null) {
    return {
      count: state.count,
      authoritative: true,
      detected: state.count > 0,
      unknown: false,
    };
  }
  if (state.detected) {
    return {
      count: state.candidateCount && state.candidateCount > 0 ? state.candidateCount : 0,
      authoritative: false,
      detected: true,
      unknown: state.unknown,
    };
  }
  return {
    count: 0,
    authoritative: !state.unknown,
    detected: false,
    unknown: state.unknown,
  };
}

function buildEmptySummary(packageModel) {
  return {
    count: 0,
    maxSeverity: canonicalSeverity(
      packageModel && packageModel.vulnerability && packageModel.vulnerability.maxSeverity
    ),
    cveIds: [],
    hasFixAvailable: false,
    severityCounts: Object.create(null),
    entries: [],
    detailsLoaded: false,
    policyViolated: Boolean(
      packageModel && packageModel.policy && packageModel.policy.vulnerabilityViolated
    ),
  };
}

function buildIndicatorSummary(packageModel) {
  const indicator = getIndicatorCount(packageModel);
  const { count } = indicator;
  if (count === 0 && !indicator.detected && !indicator.unknown) {
    return {
      ...buildEmptySummary(packageModel),
      countAuthoritative: indicator.authoritative,
      countKnown: indicator.authoritative,
      detected: false,
      unknown: false,
    };
  }

  const maxSeverity = canonicalSeverity(
    packageModel && packageModel.vulnerability && packageModel.vulnerability.maxSeverity
  );
  const severityCounts = Object.create(null);
  if (indicator.detected && maxSeverity && maxSeverity !== "Unknown") {
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
    countAuthoritative: indicator.authoritative,
    countKnown: indicator.authoritative,
    detected: indicator.detected,
    unknown: indicator.unknown,
    policyViolated: Boolean(
      packageModel && packageModel.policy && packageModel.policy.vulnerabilityViolated
    ),
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
    const value = boundedDisplayString(candidate, MAX_VULNERABILITY_IDENTIFIER_LENGTH);
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

  const cveId = boundedDisplayString(
    (entry && (
      entry.vulnerability_id
      || entry.identifier
      || entry.id
      || entry.name
    )) || "Unknown",
    MAX_VULNERABILITY_IDENTIFIER_LENGTH
  ) || "Unknown";

  const fixVersion = extractFixVersion(entry);

  return {
    cveId,
    severity,
    description: boundedDisplayString(
      entry && (entry.title || entry.description || ""),
      MAX_VULNERABILITY_DISPLAY_LENGTH
    ) || "",
    fixVersion,
    hasFixAvailable: Boolean(fixVersion),
  };
}

function vulnerabilityIdentity(entry) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return null;
  const aliases = ["vulnerability_id", "identifier", "id", "name"]
    .filter(key => Object.prototype.hasOwnProperty.call(entry, key))
    .map(key => boundedDisplayString(entry[key], MAX_VULNERABILITY_IDENTIFIER_LENGTH))
    .filter(Boolean);
  if (aliases.length === 0) return null;
  const identities = new Set(aliases.map(value => value.toLocaleLowerCase("en-US")));
  return identities.size === 1 ? [...identities][0] : null;
}

function summarizeEntries(entries, fallbackSummary) {
  const identities = entries.map(vulnerabilityIdentity);
  if (
    identities.some(identity => !identity)
    || new Set(identities).size !== identities.length
    || fallbackSummary.countAuthoritative !== true
    || entries.length !== fallbackSummary.count
  ) return fallbackSummary;

  const severityCounts = Object.create(null);
  const cveIds = [];
  const seenCveIds = new Set();
  const normalizedEntries = [];
  let hasFixAvailable = false;

  for (const entry of entries.map(normalizeEntry)) {
    normalizedEntries.push(entry);
    if (!seenCveIds.has(entry.cveId)) {
      seenCveIds.add(entry.cveId);
      cveIds.push(entry.cveId);
    }
    severityCounts[entry.severity] = (severityCounts[entry.severity] || 0) + 1;
    if (entry.hasFixAvailable) {
      hasFixAvailable = true;
    }
  }

  return {
    count: fallbackSummary.count,
    maxSeverity: deriveMaximumVulnerabilitySeverity(normalizedEntries),
    cveIds,
    hasFixAvailable,
    severityCounts,
    entries: normalizedEntries,
    detailsLoaded: true,
    countAuthoritative: true,
    countKnown: true,
    detected: normalizedEntries.length > 0,
    unknown: false,
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
        workspace: dependency.cloudsmithPackage.workspace,
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

  await Promise.allSettled(workers);
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

  const workspace = packageModel.workspace;
  const repo = packageModel.repository;
  const identifier = packageModel.packageIdentifier;

  if (!workspace || !repo || !identifier) {
    return fallbackSummary;
  }

  let endpoint;
  try {
    endpoint = apiEndpoint(["vulnerabilities", workspace, repo, identifier]);
  } catch {
    return null;
  }
  let response;
  try {
    response = await api.getV2(endpoint, {
      responseType: "json",
      validate: isRecognizedVulnerabilityDetail,
      retry: "never",
      cancellationToken,
    });
  } catch {
    return null;
  }
  if (
    !response.ok
    || isCancellationRequested(cancellationToken)
    || !isAccountCurrent(connectionManager, account)
  ) {
    return null;
  }

  const entries = extractVulnerabilityEntries(response.data);
  if (!isVulnerabilityRecordArray(entries)) return null;
  const summary = summarizeEntries(entries, fallbackSummary);
  if (!isAccountCurrent(connectionManager, account)) return null;
  if (summary.detailsLoaded) {
    setCachedVulnerabilitySummary(packageKey, summary, account, now());
  }
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
    if (
      indicatorSummary.count > 0
      && indicatorSummary.count <= MAX_VULNERABILITY_DETAIL_ENTRIES
      && indicatorSummary.countAuthoritative === true
    ) {
      if (detailTargets.length < MAX_VULNERABILITY_DETAIL_REQUESTS) {
        detailTargets.push({
          ...group,
          fallbackSummary: indicatorSummary,
        });
      }
    }
  }

  if (onProgress && patchMap.size > 0 && isAccountCurrent(connectionManager, account)) {
    publishProgress(onProgress, new Map(patchMap), {
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
      publishProgress(onProgress, summary ? new Map([[target.key, summary]]) : new Map(), {
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

function publishProgress(onProgress, patchMap, metadata) {
  try {
    onProgress(patchMap, metadata);
  } catch {
    // Progress callbacks are observers and cannot abort or outlive the bounded work pool.
  }
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
  if (!Array.isArray(value.scans) || value.scans.length > 100) return false;
  let totalEntries = 0;
  for (const scan of value.scans) {
    if (
      !scan
      || typeof scan !== "object"
      || Array.isArray(scan)
      || !Array.isArray(scan.results)
      || !isVulnerabilityRecordArray(scan.results)
    ) return false;
    totalEntries += scan.results.length;
    if (totalEntries > MAX_VULNERABILITY_DETAIL_ENTRIES) return false;
  }
  return true;
}

function isVulnerabilityRecordArray(value) {
  if (
    !Array.isArray(value)
    || value.length > MAX_VULNERABILITY_DETAIL_ENTRIES
    || !value.every(entry => (
    Boolean(entry)
    && typeof entry === "object"
    && !Array.isArray(entry)
    && [entry.vulnerability_id, entry.identifier, entry.id, entry.name]
      .some(identifier => Boolean(boundedDisplayString(
        identifier,
        MAX_VULNERABILITY_IDENTIFIER_LENGTH
      )))
    && (
      entry.severity === undefined
      || entry.severity === null
      || Boolean(boundedDisplayString(entry.severity, 100))
    )
  ))
  ) return false;
  const identities = value.map(vulnerabilityIdentity);
  return identities.every(Boolean) && new Set(identities).size === identities.length;
}

function boundedDisplayString(value, maxLength) {
  if (typeof value !== "string" && typeof value !== "number") return null;
  const normalized = String(value).trim();
  return normalized.length > 0 && normalized.length <= maxLength ? normalized : null;
}

module.exports = {
  clearVulnerabilityCache() {
    vulnerabilityCache.clear();
  },
  enrichVulnerabilities,
  getVulnerabilityCacheSize() {
    return vulnerabilityCache.size;
  },
  MAX_VULNERABILITY_DETAIL_REQUESTS,
  VULNERABILITY_CACHE_MAX_SIZE,
};

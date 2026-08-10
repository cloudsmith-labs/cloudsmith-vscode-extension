// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { CloudsmithAPI } = require("./cloudsmithAPI");
const { apiEndpoint } = require("./apiEndpoint");
const { SearchQueryBuilder } = require("./searchQueryBuilder");
const {
  captureAccount,
  isAccountCurrent,
  resolveConnectionManager,
} = require("./accountOperation");
const {
  getSupportedUpstreamFormats,
  SUPPORTED_UPSTREAM_FORMATS,
} = require("./upstreamFormats");

const UPSTREAM_CACHE_SCHEMA_VERSION = 3;
const UPSTREAM_CACHE_TTL_MS = 10 * 60 * 1000;
const UPSTREAM_FETCH_BATCH_SIZE = 5;
const UPSTREAM_CACHE_KEY_PREFIX = "cloudsmith-upstreams:v3";
const MAX_PERSISTED_UPSTREAMS = 5000;
const MAX_PERSISTED_UPSTREAMS_PER_FORMAT = 500;
const MAX_PERSISTED_STRING_LENGTH = 2048;
const MAX_PERSISTED_NAME_LENGTH = 500;
const MAX_PERSISTED_DISTRO_VERSIONS = 100;
const MAX_RUNTIME_UPSTREAMS = 5000;
const MAX_RUNTIME_UPSTREAMS_PER_FORMAT = 500;
const MAX_RUNTIME_URL_LENGTH = 8192;
const BENIGN_UPSTREAM_FORMAT_STATUS_CODES = new Set([400, 404, 405, 422]);
const PERSISTED_UPSTREAM_KEYS = Object.freeze([
  "name",
  "is_active",
  "_format",
  "format",
  "mode",
  "created_at",
  "trust_level",
  "verify_ssl",
  "index_status",
  "index_package_count",
  "priority",
  "distribution",
  "distro_versions",
  "upstream_distribution",
]);
const persistedUpstreamKeySet = new Set(PERSISTED_UPSTREAM_KEYS);
const persistedStringFieldLimits = new Map([
  ["name", MAX_PERSISTED_NAME_LENGTH],
  ["_format", MAX_PERSISTED_NAME_LENGTH],
  ["format", MAX_PERSISTED_NAME_LENGTH],
  ["mode", MAX_PERSISTED_NAME_LENGTH],
  ["created_at", MAX_PERSISTED_NAME_LENGTH],
  ["trust_level", MAX_PERSISTED_NAME_LENGTH],
  ["index_status", MAX_PERSISTED_NAME_LENGTH],
  ["distribution", MAX_PERSISTED_STRING_LENGTH],
  ["upstream_distribution", MAX_PERSISTED_STRING_LENGTH],
]);
const cacheOperations = new WeakMap();
const cacheWriteQueues = new WeakMap();

function isObjectRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value, expectedKeys) {
  if (!isObjectRecord(value)) return false;
  const keys = Object.keys(value).sort();
  return keys.length === expectedKeys.length
    && keys.every((key, index) => key === expectedKeys[index]);
}

function getUpstreamCacheKey(workspace, repo, formats = SUPPORTED_UPSTREAM_FORMATS) {
  const normalizedFormats = getSupportedUpstreamFormats(formats);
  const isAllFormats = normalizedFormats.length === SUPPORTED_UPSTREAM_FORMATS.length
    && normalizedFormats.every((format, index) => format === SUPPORTED_UPSTREAM_FORMATS[index]);
  const tuple = isAllFormats
    ? ["all", workspace, repo]
    : ["formats", workspace, repo, normalizedFormats];
  return `${UPSTREAM_CACHE_KEY_PREFIX}:${encodeURIComponent(JSON.stringify(tuple))}`;
}

function getCacheMap(registry, globalState) {
  let cacheMap = registry.get(globalState);
  if (!cacheMap) {
    cacheMap = new Map();
    registry.set(globalState, cacheMap);
  }
  return cacheMap;
}

function beginCacheOperation(globalState, cacheKey) {
  if (!globalState || !isObjectRecord(globalState)) return null;
  const operations = getCacheMap(cacheOperations, globalState);
  const operationToken = Symbol(cacheKey);
  operations.set(cacheKey, operationToken);
  return operationToken;
}

function isCacheOperationCurrent(globalState, cacheKey, operationToken) {
  return Boolean(operationToken)
    && getCacheMap(cacheOperations, globalState).get(cacheKey) === operationToken;
}

function finishCacheOperation(globalState, cacheKey, operationToken) {
  if (!globalState || !operationToken) return;
  const operations = cacheOperations.get(globalState);
  if (!operations || operations.get(cacheKey) !== operationToken) return;
  operations.delete(cacheKey);
  if (operations.size === 0) cacheOperations.delete(globalState);
}

function getActiveUpstreamCacheOperationCount(globalState) {
  return cacheOperations.get(globalState)?.size || 0;
}

function queueCacheWrite(globalState, cacheKey, write) {
  const queues = getCacheMap(cacheWriteQueues, globalState);
  const previous = queues.get(cacheKey) || Promise.resolve();
  const pending = previous.then(write, write);
  const settled = pending.then(() => undefined, () => undefined);
  queues.set(cacheKey, settled);
  settled.finally(() => {
    if (queues.get(cacheKey) === settled) queues.delete(cacheKey);
  });
  return pending;
}

function cacheErrorMessage(action) {
  const safeAction = action === "persist" || action === "evict invalid entry from"
    ? action
    : "update";
  return `[UpstreamChecker] Failed to ${safeAction} upstream cache.`;
}

function logCacheError(action) {
  console.warn(cacheErrorMessage(action));
}

function evictCacheEntry(globalState, cacheKey, workspace, repo) {
  if (!globalState || typeof globalState.update !== "function") return;
  queueCacheWrite(globalState, cacheKey, async () => {
    try {
      await globalState.update(cacheKey, undefined);
    } catch (error) {
      logCacheError("evict invalid entry from", workspace, repo, error);
    }
  });
}

function boundedString(value, maxLength = MAX_PERSISTED_STRING_LENGTH) {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength
    ? value
    : null;
}

function normalizePersistedField(key, value) {
  if (persistedStringFieldLimits.has(key)) {
    return boundedString(value, persistedStringFieldLimits.get(key));
  }
  if (["is_active", "verify_ssl"].includes(key)) {
    return typeof value === "boolean" ? value : null;
  }
  if (["index_package_count", "priority"].includes(key)) {
    return Number.isSafeInteger(value) && value >= 0 ? value : null;
  }
  if (key === "distro_versions") {
    if (
      !Array.isArray(value)
      || value.length > MAX_PERSISTED_DISTRO_VERSIONS
      || !value.every(item => boundedString(item, MAX_PERSISTED_NAME_LENGTH))
    ) return null;
    return value.slice();
  }
  return null;
}

function serializeUpstream(upstream) {
  const serialized = {};
  for (const key of PERSISTED_UPSTREAM_KEYS) {
    if (upstream[key] === undefined) continue;
    const normalized = normalizePersistedField(key, upstream[key]);
    if (normalized !== null) serialized[key] = normalized;
  }
  return serialized.name ? serialized : null;
}

function serializeUpstreamArray(upstreams, max = MAX_PERSISTED_UPSTREAMS) {
  if (!Array.isArray(upstreams) || upstreams.length > max) return null;
  const serialized = upstreams.map(serializeUpstream);
  return serialized.every(Boolean) ? serialized : null;
}

function canonicalizeRuntimeUpstream(value) {
  if (!isObjectRecord(value)) return null;
  const name = boundedString(value.name, MAX_PERSISTED_NAME_LENGTH);
  if (!name) return null;
  const canonical = { name };
  for (const key of PERSISTED_UPSTREAM_KEYS) {
    if (key === "name" || value[key] === undefined) continue;
    const normalized = normalizePersistedField(key, value[key]);
    if (normalized !== null) canonical[key] = normalized;
  }
  if (typeof value.upstream_url === "string" && value.upstream_url.length <= MAX_RUNTIME_URL_LENGTH) {
    canonical.upstream_url = value.upstream_url;
  }
  for (const key of [
    "auth_mode", "auth_username", "extra_header_1", "extra_value_1",
    "extra_header_2", "extra_value_2",
  ]) {
    const normalized = boundedString(value[key], MAX_PERSISTED_STRING_LENGTH);
    if (normalized !== null) canonical[key] = normalized;
  }
  if (
    typeof value.priority === "string"
    && boundedString(value.priority, MAX_PERSISTED_NAME_LENGTH)
  ) {
    canonical.priority = value.priority;
  }
  return canonical;
}

function isPersistedUpstream(value) {
  return isUpstreamRecord(value)
    && Object.keys(value).every(key => persistedUpstreamKeySet.has(key))
    && Object.entries(value).every(([key, fieldValue]) => {
      const normalized = normalizePersistedField(key, fieldValue);
      if (normalized === null) return false;
      return Array.isArray(normalized)
        ? JSON.stringify(normalized) === JSON.stringify(fieldValue)
        : normalized === fieldValue;
    });
}

function isAccountEnvelope(value, account, expectedKeys) {
  return hasExactKeys(value, expectedKeys)
    && value.version === UPSTREAM_CACHE_SCHEMA_VERSION
    && value.activationId === account.activationId
    && value.accountEpoch === account.accountEpoch
    && Number.isFinite(value.timestamp);
}

function isFresh(timestamp, now) {
  return timestamp <= now && now - timestamp < UPSTREAM_CACHE_TTL_MS;
}

function getCachedFlatResponse(globalState, cacheKey, workspace, repo, account, now) {
  if (!globalState || typeof globalState.get !== "function") return null;
  const cached = globalState.get(cacheKey);
  if (cached === undefined) return null;
  const valid = isAccountEnvelope(cached, account, [
    "accountEpoch", "activationId", "active", "failedFormats", "successfulFormats",
    "timestamp", "total", "upstreams", "version",
  ])
    && isFresh(cached.timestamp, now)
    && Array.isArray(cached.upstreams)
    && cached.upstreams.length <= MAX_PERSISTED_UPSTREAMS
    && cached.upstreams.every(isPersistedUpstream)
    && Number.isInteger(cached.active) && cached.active >= 0
    && Number.isInteger(cached.total) && cached.total === cached.upstreams.length
    && cached.active <= cached.total
    && Array.isArray(cached.failedFormats) && cached.failedFormats.length === 0
    && Number.isInteger(cached.successfulFormats)
    && cached.successfulFormats >= 0
    && cached.successfulFormats <= SUPPORTED_UPSTREAM_FORMATS.length;
  if (!valid) {
    evictCacheEntry(globalState, cacheKey, workspace, repo);
    return null;
  }
  return {
    upstreams: cached.upstreams.map(upstream => ({ ...upstream })),
    active: cached.active,
    total: cached.total,
    failedFormats: [],
    successfulFormats: cached.successfulFormats,
  };
}

async function persistFlatResponse(
  globalState,
  cacheKey,
  workspace,
  repo,
  response,
  account,
  connectionManager,
  operationId,
  now
) {
  if (!globalState || typeof globalState.update !== "function") return;
  const serializedUpstreams = serializeUpstreamArray(response.upstreams);
  if (
    !serializedUpstreams
    || !Number.isSafeInteger(response.active)
    || response.active < 0
    || response.active > serializedUpstreams.length
    || response.total !== serializedUpstreams.length
    || !Number.isSafeInteger(response.successfulFormats)
    || response.successfulFormats < 0
    || response.successfulFormats > SUPPORTED_UPSTREAM_FORMATS.length
  ) return;
  await queueCacheWrite(globalState, cacheKey, async () => {
    if (
      !isAccountCurrent(connectionManager, account)
      || !isCacheOperationCurrent(globalState, cacheKey, operationId)
    ) return;
    try {
      await globalState.update(cacheKey, {
        version: UPSTREAM_CACHE_SCHEMA_VERSION,
        activationId: account.activationId,
        accountEpoch: account.accountEpoch,
        timestamp: now(),
        upstreams: serializedUpstreams,
        active: response.active,
        total: response.total,
        failedFormats: [],
        successfulFormats: response.successfulFormats,
      });
    } catch (error) {
      logCacheError("persist", workspace, repo, error);
    }
  });
}

function isBenignUpstreamFormatError(error) {
  return Boolean(error) && BENIGN_UPSTREAM_FORMAT_STATUS_CODES.has(error.status);
}

function isWarningWorthyUpstreamFormatError(error) {
  return !isBenignUpstreamFormatError(error);
}

function isAbortError(error) {
  return error && (error.name === "AbortError" || error.code === "ABORT_ERR");
}

function isCancelled(options = {}) {
  return Boolean(options.signal?.aborted || options.cancellationToken?.isCancellationRequested);
}

function getActiveUpstreamsFromRepositoryState(state, format) {
  const upstreams = state && state.groupedUpstreams instanceof Map
    ? state.groupedUpstreams.get(format)
    : null;
  return Array.isArray(upstreams)
    ? upstreams.filter(upstream => upstream && upstream.is_active !== false)
    : [];
}

function sortUpstreams(left, right) {
  const leftName = typeof left.name === "string" ? left.name : "";
  const rightName = typeof right.name === "string" ? right.name : "";
  if (leftName !== rightName) {
    return leftName.localeCompare(rightName, undefined, { sensitivity: "base" });
  }
  const leftFormat = typeof left._format === "string" ? left._format : (left.format || "");
  const rightFormat = typeof right._format === "string" ? right._format : (right.format || "");
  return leftFormat.localeCompare(rightFormat, undefined, { sensitivity: "base" });
}

async function fetchFormatUpstreams(api, workspace, repo, format, options = {}) {
  try {
    if (isCancelled(options)) return { format, status: "aborted", upstreams: [] };
    const result = await api.get(apiEndpoint(["repos", workspace, repo, "upstream", format]), {
      responseType: "array",
      validate: isUpstreamArray,
      retry: "never",
      signal: options.signal,
      cancellationToken: options.cancellationToken,
    });
    if (isCancelled(options)) return { format, status: "aborted", upstreams: [] };
    if (!result.ok) {
      if (result.error.kind === "cancelled") return { format, status: "aborted", upstreams: [] };
      return isWarningWorthyUpstreamFormatError(result.error)
        ? { format, status: "failed", error: result.error, upstreams: [] }
        : { format, status: "loaded", upstreams: [] };
    }
    if (!isUpstreamArray(result.data)) {
      return {
        format,
        status: "failed",
        error: invalidUpstreamResponseError(),
        upstreams: [],
      };
    }
    return {
      format,
      status: "loaded",
      upstreams: result.data.map(upstream => ({
        ...canonicalizeRuntimeUpstream(upstream),
        _format: format,
        format,
      })),
    };
  } catch (error) {
    return isAbortError(error) || isCancelled(options)
      ? { format, status: "aborted", upstreams: [] }
      : { format, status: "failed", error, upstreams: [] };
  }
}

class UpstreamChecker {
  constructor(context, options = {}) {
    this.context = context;
    this.connectionManager = resolveConnectionManager(context, options.connectionManager);
    this.api = options.cloudsmithAPI || new CloudsmithAPI(context);
    this.now = options.now || Date.now;
  }

  _captureAccount(options = {}) {
    const account = options.account || captureAccount(this.connectionManager);
    return isAccountCurrent(this.connectionManager, account) ? account : null;
  }

  _emptyRepositoryState() {
    return this._buildRepositoryUpstreamState(new Map(), [], 0);
  }

  async existsLocally(workspace, repo, name, format, options = {}) {
    const account = this._captureAccount(options);
    if (!account) return { data: null, error: null, stale: true };
    let endpoint;
    try {
      const query = new SearchQueryBuilder().name(name).format(format).build();
      endpoint = apiEndpoint(["packages", workspace, repo], { query: { query, page_size: 1 } });
    } catch (error) {
      return { data: null, error };
    }
    const result = await this.api.get(endpoint, {
      responseType: "array",
      validate: isPackageArray,
      retry: "safe-read",
    });
    if (!isAccountCurrent(this.connectionManager, account)) {
      return { data: null, error: null, stale: true };
    }
    if (!result.ok) return { data: null, error: result.error };
    return { data: result.data[0] || null, error: null };
  }

  async getUpstreamsForFormat(workspace, repo, format, options = {}) {
    const account = this._captureAccount(options);
    if (!account) return { data: [], error: null, stale: true };
    let endpoint;
    try {
      endpoint = apiEndpoint(["repos", workspace, repo, "upstream", format]);
    } catch (error) {
      return { data: [], error };
    }
    const result = await this.api.get(endpoint, {
      responseType: "array",
      validate: isUpstreamArray,
      retry: "safe-read",
    });
    if (!isAccountCurrent(this.connectionManager, account)) {
      return { data: [], error: null, stale: true };
    }
    if (!result.ok) {
      return isBenignUpstreamFormatError(result.error)
        ? { data: [], error: null }
        : { data: [], error: result.error };
    }
    if (!isUpstreamArray(result.data)) {
      return { data: [], error: invalidUpstreamResponseError() };
    }
    return { data: result.data.map(canonicalizeRuntimeUpstream), error: null };
  }

  async getUpstreamDataForFormats(workspace, repo, formats, options = {}) {
    const account = this._captureAccount(options);
    if (!account || isCancelled(options)) return null;
    const requestedFormats = getSupportedUpstreamFormats(formats);
    if (requestedFormats.length === 0) {
      return { upstreams: [], active: 0, total: 0, failedFormats: [], successfulFormats: 0 };
    }
    const cacheKey = getUpstreamCacheKey(workspace, repo, requestedFormats);
    const globalState = this.context && this.context.globalState;
    const operationToken = globalState ? beginCacheOperation(globalState, cacheKey) : null;
    try {
      const cached = getCachedFlatResponse(
        globalState,
        cacheKey,
        workspace,
        repo,
        account,
        this.now()
      );
      if (cached && isAccountCurrent(this.connectionManager, account)) return cached;

      const upstreams = [];
      const failedFormats = [];
      let successfulFormats = 0;
      for (let index = 0; index < requestedFormats.length; index += UPSTREAM_FETCH_BATCH_SIZE) {
        if (isCancelled(options) || !isAccountCurrent(this.connectionManager, account)) return null;
        const batch = requestedFormats.slice(index, index + UPSTREAM_FETCH_BATCH_SIZE);
        const results = await Promise.all(batch.map(format => (
          fetchFormatUpstreams(this.api, workspace, repo, format, options)
        )));
        if (isCancelled(options) || !isAccountCurrent(this.connectionManager, account)) return null;
        for (const result of results) {
          if (result.status === "aborted") return null;
          if (result.status === "failed") failedFormats.push(result.format);
          if (result.status === "loaded") {
            if (upstreams.length + result.upstreams.length > MAX_RUNTIME_UPSTREAMS) {
              failedFormats.push(result.format);
              continue;
            }
            successfulFormats += 1;
            upstreams.push(...result.upstreams);
          }
        }
      }
      upstreams.sort(sortUpstreams);
      const response = {
        upstreams,
        active: upstreams.filter(upstream => upstream.is_active !== false).length,
        total: upstreams.length,
        failedFormats,
        successfulFormats,
      };
      if (!isAccountCurrent(this.connectionManager, account)) return null;
      if (!isCancelled(options) && failedFormats.length === 0 && globalState) {
        await persistFlatResponse(
          globalState,
          cacheKey,
          workspace,
          repo,
          response,
          account,
          this.connectionManager,
          operationToken,
          this.now
        );
      }
      return isAccountCurrent(this.connectionManager, account) ? response : null;
    } finally {
      finishCacheOperation(globalState, cacheKey, operationToken);
    }
  }

  getAllUpstreamData(workspace, repo, options = {}) {
    return this.getUpstreamDataForFormats(workspace, repo, SUPPORTED_UPSTREAM_FORMATS, options);
  }

  async getAllUpstreams(workspace, repo, options = {}) {
    const result = await this.getAllUpstreamData(workspace, repo, options);
    if (result === null) return { data: [], error: null, aborted: true };
    if (result.failedFormats.length > 0 && result.upstreams.length === 0) {
      return { data: [], error: `Could not load upstream data for: ${result.failedFormats.join(", ")}` };
    }
    return { data: result.upstreams, error: null };
  }

  async getRepositoryUpstreamState(workspace, repo, options = {}) {
    const account = this._captureAccount(options);
    if (!account || isCancelled(options)) return this._emptyRepositoryState();
    const globalState = this.context && this.context.globalState;
    const cacheKey = this._getRepositoryUpstreamCacheKey(workspace, repo);
    const operationToken = globalState ? beginCacheOperation(globalState, cacheKey) : null;
    try {
      const cached = this._getCachedRepositoryUpstreamState(workspace, repo, account);
      if (cached && isAccountCurrent(this.connectionManager, account)) return cached;
      const fetched = await this._fetchRepositoryUpstreamState(workspace, repo, {
        ...options,
        account,
      });
      if (!isAccountCurrent(this.connectionManager, account)) return this._emptyRepositoryState();
      if (!isCancelled(options) && fetched.failedFormats.length === 0) {
        await this._cacheRepositoryUpstreamState(workspace, repo, fetched, account, operationToken);
      }
      return isAccountCurrent(this.connectionManager, account) ? fetched : this._emptyRepositoryState();
    } finally {
      finishCacheOperation(globalState, cacheKey, operationToken);
    }
  }

  async getRepositoryUpstreams(workspace, repo, options = {}) {
    return (await this.getRepositoryUpstreamState(workspace, repo, options)).upstreams;
  }

  async getActiveRepositoryUpstreamsForFormat(workspace, repo, format, options = {}) {
    const state = await this.getRepositoryUpstreamState(workspace, repo, options);
    return getActiveUpstreamsFromRepositoryState(state, format);
  }

  async previewResolution(workspace, repo, name, format, options = {}) {
    const account = this._captureAccount(options);
    if (!account) return null;
    const sharedOptions = { ...options, account };
    const [localPkg, upstreams] = await Promise.all([
      this.existsLocally(workspace, repo, name, format, sharedOptions),
      this.getUpstreamsForFormat(workspace, repo, format, sharedOptions),
    ]);
    if (!isAccountCurrent(this.connectionManager, account)) return null;
    const configs = Array.isArray(upstreams.data) ? upstreams.data : [];
    const active = configs.filter(upstream => upstream.is_active !== false);
    return {
      name,
      format,
      workspace,
      repo,
      local: localPkg,
      upstreams: {
        data: { total: configs.length, active: active.length, configs },
        error: upstreams.error,
      },
      canResolveViaUpstream: active.length > 0,
    };
  }

  _getRepositoryUpstreamCacheKey(workspace, repo) {
    const tuple = ["repository", workspace, repo];
    return `${UPSTREAM_CACHE_KEY_PREFIX}:${encodeURIComponent(JSON.stringify(tuple))}`;
  }

  _logRepositoryUpstreamCacheError(action, workspace, repo, error) {
    logCacheError(action, workspace, repo, error);
  }

  _evictInvalidRepositoryUpstreamCacheEntry(workspace, repo, globalState) {
    evictCacheEntry(globalState, this._getRepositoryUpstreamCacheKey(workspace, repo), workspace, repo);
  }

  _getCachedRepositoryUpstreamState(workspace, repo, suppliedAccount = null) {
    const account = suppliedAccount || captureAccount(this.connectionManager);
    if (!account || !isAccountCurrent(this.connectionManager, account)) return null;
    const globalState = this.context && this.context.globalState;
    if (!globalState || typeof globalState.get !== "function") return null;
    const cached = globalState.get(this._getRepositoryUpstreamCacheKey(workspace, repo));
    if (cached === undefined) return null;
    const formats = isObjectRecord(cached.groupedUpstreams)
      ? Object.keys(cached.groupedUpstreams)
      : [];
    const valid = isAccountEnvelope(cached, account, [
      "accountEpoch", "activationId", "groupedUpstreams", "successfulFormats",
      "timestamp", "version",
    ])
      && isFresh(cached.timestamp, this.now())
      && isObjectRecord(cached.groupedUpstreams)
      && formats.every(format => SUPPORTED_UPSTREAM_FORMATS.includes(format))
      && formats.every(format => (
        Array.isArray(cached.groupedUpstreams[format])
        && cached.groupedUpstreams[format].length <= MAX_PERSISTED_UPSTREAMS_PER_FORMAT
        && cached.groupedUpstreams[format].every(isPersistedUpstream)
      ))
      && formats.reduce((total, format) => (
        total + cached.groupedUpstreams[format].length
      ), 0) <= MAX_PERSISTED_UPSTREAMS
      && Number.isInteger(cached.successfulFormats)
      && cached.successfulFormats >= 0
      && cached.successfulFormats <= SUPPORTED_UPSTREAM_FORMATS.length;
    if (!valid) {
      this._evictInvalidRepositoryUpstreamCacheEntry(workspace, repo, globalState);
      return null;
    }
    return this._buildRepositoryUpstreamState(
      this._deserializeGroupedUpstreams(cached.groupedUpstreams),
      [],
      cached.successfulFormats
    );
  }

  async _cacheRepositoryUpstreamState(workspace, repo, state, account, operationId) {
    const globalState = this.context && this.context.globalState;
    if (!globalState || typeof globalState.update !== "function") return;
    const cacheKey = this._getRepositoryUpstreamCacheKey(workspace, repo);
    const groupedUpstreams = {};
    let persistedCount = 0;
    for (const format of SUPPORTED_UPSTREAM_FORMATS) {
      const upstreams = state.groupedUpstreams.get(format);
      if (Array.isArray(upstreams) && upstreams.length > 0) {
        const serialized = serializeUpstreamArray(
          upstreams,
          MAX_PERSISTED_UPSTREAMS_PER_FORMAT
        );
        if (!serialized || persistedCount + serialized.length > MAX_PERSISTED_UPSTREAMS) return;
        groupedUpstreams[format] = serialized;
        persistedCount += serialized.length;
      }
    }
    await queueCacheWrite(globalState, cacheKey, async () => {
      if (
        !isAccountCurrent(this.connectionManager, account)
        || !isCacheOperationCurrent(globalState, cacheKey, operationId)
      ) return;
      try {
        await globalState.update(cacheKey, {
          version: UPSTREAM_CACHE_SCHEMA_VERSION,
          activationId: account.activationId,
          accountEpoch: account.accountEpoch,
          timestamp: this.now(),
          successfulFormats: state.successfulFormats,
          groupedUpstreams,
        });
      } catch (error) {
        this._logRepositoryUpstreamCacheError("persist", workspace, repo, error);
      }
    });
  }

  async _fetchRepositoryUpstreamState(workspace, repo, options = {}) {
    const grouped = new Map();
    const failed = [];
    let successful = 0;
    for (let index = 0; index < SUPPORTED_UPSTREAM_FORMATS.length; index += UPSTREAM_FETCH_BATCH_SIZE) {
      if (isCancelled(options) || !isAccountCurrent(this.connectionManager, options.account)) {
        return this._emptyRepositoryState();
      }
      const batch = SUPPORTED_UPSTREAM_FORMATS.slice(index, index + UPSTREAM_FETCH_BATCH_SIZE);
      const results = await Promise.all(batch.map(format => (
        fetchFormatUpstreams(this.api, workspace, repo, format, options)
      )));
      if (isCancelled(options) || !isAccountCurrent(this.connectionManager, options.account)) {
        return this._emptyRepositoryState();
      }
      for (const result of results) {
        if (result.status === "failed") failed.push(result.format);
        if (result.status === "loaded") {
          const retainedCount = Array.from(grouped.values()).reduce(
            (total, upstreams) => total + upstreams.length,
            0
          );
          if (retainedCount + result.upstreams.length > MAX_RUNTIME_UPSTREAMS) {
            failed.push(result.format);
            continue;
          }
          successful += 1;
          if (result.upstreams.length > 0) grouped.set(result.format, result.upstreams);
        }
      }
    }
    return this._buildRepositoryUpstreamState(grouped, failed, successful);
  }

  _buildRepositoryUpstreamState(groupedUpstreams, failedFormats, successfulFormats) {
    const normalizedGrouped = new Map();
    const upstreams = [];
    let active = 0;
    for (const format of SUPPORTED_UPSTREAM_FORMATS) {
      const values = Array.isArray(groupedUpstreams.get(format))
        ? groupedUpstreams.get(format).slice().sort(sortUpstreams)
        : [];
      if (values.length === 0) continue;
      const tagged = values.map(upstream => ({
        ...upstream,
        format: typeof upstream.format === "string" && upstream.format ? upstream.format : format,
      }));
      normalizedGrouped.set(format, tagged);
      upstreams.push(...tagged);
      active += tagged.filter(upstream => upstream.is_active !== false).length;
    }
    return {
      groupedUpstreams: normalizedGrouped,
      failedFormats: Array.isArray(failedFormats) ? failedFormats.slice() : [],
      successfulFormats,
      upstreams,
      active,
      total: upstreams.length,
    };
  }

  _deserializeGroupedUpstreams(groupedUpstreams) {
    const grouped = new Map();
    for (const format of SUPPORTED_UPSTREAM_FORMATS) {
      if (Array.isArray(groupedUpstreams[format])) {
        grouped.set(format, groupedUpstreams[format].map(upstream => ({ ...upstream })));
      }
    }
    return grouped;
  }

  _isAbortError(error) {
    return isAbortError(error);
  }

  _isWarningWorthyFormatError(error) {
    return isWarningWorthyUpstreamFormatError(error);
  }
}

function isRecordArray(value) {
  return Array.isArray(value) && value.every(item => isObjectRecord(item));
}

function isPackageArray(value) {
  return isRecordArray(value) && value.length <= 100 && value.every(item => (
    boundedString(item.name, MAX_PERSISTED_STRING_LENGTH)
    && boundedString(item.format, MAX_PERSISTED_NAME_LENGTH)
  ));
}

function isUpstreamRecord(value) {
  return canonicalizeRuntimeUpstream(value) !== null;
}

function isUpstreamArray(value) {
  return Array.isArray(value)
    && value.length <= MAX_RUNTIME_UPSTREAMS_PER_FORMAT
    && value.every(isUpstreamRecord);
}

function invalidUpstreamResponseError() {
  return Object.freeze({
    kind: "invalid_response",
    status: null,
    retryable: false,
    message: "Cloudsmith returned an invalid upstream response.",
    requestId: null,
    retryAfterMs: null,
    outcomeUnknown: false,
    diagnostic: Object.freeze({}),
  });
}

async function getAllUpstreamData(context, workspace, repo, options = {}) {
  const checker = new UpstreamChecker(context, options);
  return checker.getAllUpstreamData(workspace, repo, options);
}

async function getUpstreamDataForFormats(context, workspace, repo, formats, options = {}) {
  const checker = new UpstreamChecker(context, options);
  return checker.getUpstreamDataForFormats(workspace, repo, formats, options);
}

module.exports = {
  cacheErrorMessage,
  getAllUpstreamData,
  getUpstreamDataForFormats,
  getActiveUpstreamsFromRepositoryState,
  getActiveUpstreamCacheOperationCount,
  isBenignUpstreamFormatError,
  getUpstreamCacheKey,
  MAX_PERSISTED_UPSTREAMS,
  MAX_RUNTIME_UPSTREAMS_PER_FORMAT,
  PERSISTED_UPSTREAM_KEYS,
  SUPPORTED_UPSTREAM_FORMATS,
  UpstreamChecker,
  UPSTREAM_CACHE_SCHEMA_VERSION,
  UPSTREAM_FETCH_BATCH_SIZE,
  UPSTREAM_CACHE_TTL_MS,
};

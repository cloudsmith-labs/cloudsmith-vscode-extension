// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { types: { isProxy } } = require("util");
const { CloudsmithAPI } = require("./cloudsmithAPI");
const { apiEndpoint } = require("./apiEndpoint");
const { SearchQueryBuilder } = require("./searchQueryBuilder");
const { PaginatedFetch } = require("./paginatedFetch");
const { packageCollectionIdentity } = require("./collectionIdentity");
const {
  captureAccount,
  isAccountCurrent,
  resolveConnectionManager,
} = require("./accountOperation");
const {
  getInspectableUpstreamFormats,
  getSupportedUpstreamFormats,
  getUpstreamFormatDescriptor,
  SUPPORTED_UPSTREAM_FORMATS,
} = require("./upstreamFormats");
const { UpstreamOperationScheduler } = require("./upstreamOperationScheduler");
const {
  formatUpstreamError,
  formatUpstreamOrigin,
  normalizeUpstreamFailure,
} = require("./upstreamPresentation");

const UPSTREAM_CACHE_SCHEMA_VERSION = 5;
const UPSTREAM_CACHE_TTL_MS = 10 * 60 * 1000;
// Four active page requests is conservative enough for the API rate limit while
// avoiding the latency-amplifying batch barriers used by the previous path.
const UPSTREAM_REQUEST_CONCURRENCY = 4;
// Compatibility export for callers that referenced the former batching name.
const UPSTREAM_FETCH_BATCH_SIZE = UPSTREAM_REQUEST_CONCURRENCY;
const UPSTREAM_CACHE_KEY_PREFIX = "cloudsmith-upstreams:v5";
const MAX_PERSISTED_UPSTREAMS = 5000;
const MAX_PERSISTED_UPSTREAMS_PER_FORMAT = 500;
const MAX_PERSISTED_STRING_LENGTH = 2048;
const MAX_PERSISTED_NAME_LENGTH = 500;
const MAX_PERSISTED_DISTRO_VERSIONS = 100;
const MAX_RUNTIME_UPSTREAMS = 5000;
const MAX_RUNTIME_UPSTREAMS_PER_FORMAT = 500;
const MAX_RUNTIME_URL_LENGTH = 8192;
const MAX_REPOSITORY_IDENTITY_LENGTH = 500;
const LOCAL_PACKAGE_PAGE_SIZE = 100;
const MAX_LOCAL_PACKAGE_PAGES = 20;
const MAX_LOCAL_PACKAGES = LOCAL_PACKAGE_PAGE_SIZE * MAX_LOCAL_PACKAGE_PAGES;
const UPSTREAM_PAGE_SIZE = 100;
const MAX_UPSTREAM_PAGES_PER_FORMAT = 5;
const UPSTREAM_OPERATION_TIMEOUT_MS = 45_000;
const PERSISTED_UPSTREAM_KEYS = Object.freeze([
  "name",
  "slug_perm",
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
  "origin",
]);
const persistedUpstreamKeySet = new Set(PERSISTED_UPSTREAM_KEYS);
const persistedStringFieldLimits = new Map([
  ["name", MAX_PERSISTED_NAME_LENGTH],
  ["slug_perm", MAX_PERSISTED_NAME_LENGTH],
  ["_format", MAX_PERSISTED_NAME_LENGTH],
  ["format", MAX_PERSISTED_NAME_LENGTH],
  ["mode", MAX_PERSISTED_NAME_LENGTH],
  ["created_at", MAX_PERSISTED_NAME_LENGTH],
  ["trust_level", MAX_PERSISTED_NAME_LENGTH],
  ["index_status", MAX_PERSISTED_NAME_LENGTH],
  ["distribution", MAX_PERSISTED_STRING_LENGTH],
  ["upstream_distribution", MAX_PERSISTED_STRING_LENGTH],
  ["origin", MAX_PERSISTED_STRING_LENGTH],
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
  const normalizedFormats = getSupportedUpstreamFormats(formats).sort();
  const canonicalAllFormats = [...SUPPORTED_UPSTREAM_FORMATS].sort();
  const isAllFormats = normalizedFormats.length === SUPPORTED_UPSTREAM_FORMATS.length
    && normalizedFormats.every((format, index) => format === canonicalAllFormats[index]);
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
  if (key === "origin") {
    if (value === "") return "";
    const origin = boundedString(value, MAX_PERSISTED_STRING_LENGTH);
    const formatted = origin ? formatUpstreamOrigin(origin) : null;
    return formatted && formatted !== "Origin unavailable" && formatted === origin
      ? origin
      : null;
  }
  if (persistedStringFieldLimits.has(key)) {
    return boundedString(value, persistedStringFieldLimits.get(key));
  }
  if (["is_active", "verify_ssl"].includes(key)) {
    return typeof value === "boolean" ? value : null;
  }
  if (key === "priority") {
    return Number.isSafeInteger(value) && value >= 0
      ? value
      : boundedString(value, MAX_PERSISTED_NAME_LENGTH);
  }
  if (key === "index_package_count") {
    return Number.isSafeInteger(value) && value >= 0 ? value : null;
  }
  if (key === "distro_versions") {
    return snapshotStringArray(
      value,
      MAX_PERSISTED_DISTRO_VERSIONS,
      MAX_PERSISTED_NAME_LENGTH
    );
  }
  return null;
}

function serializeUpstream(upstream) {
  const safeUpstream = sanitizeSafeInventoryUpstream(upstream);
  if (!safeUpstream) return null;
  const serialized = {};
  for (const key of PERSISTED_UPSTREAM_KEYS) {
    if (safeUpstream[key] === undefined) continue;
    const normalized = normalizePersistedField(key, safeUpstream[key]);
    if (normalized !== null) serialized[key] = normalized;
  }
  return serialized.name ? serialized : null;
}

function serializeUpstreamArray(upstreams, max = MAX_PERSISTED_UPSTREAMS) {
  if (!Array.isArray(upstreams) || upstreams.length > max) return null;
  const serialized = upstreams.map(serializeUpstream);
  return serialized.every(Boolean) ? serialized : null;
}

function canonicalizeRuntimeUpstream(value, options = {}) {
  const source = snapshotOwnDataRecord(value);
  if (!source) return null;
  const name = boundedString(source.name, MAX_PERSISTED_NAME_LENGTH);
  if (!name) return null;
  const expectedDescriptor = getUpstreamFormatDescriptor(options.expectedFormat);
  if (expectedDescriptor) {
    for (const key of ["_format", "format"]) {
      if (source[key] == null) continue;
      const sourceDescriptor = getUpstreamFormatDescriptor(source[key]);
      if (sourceDescriptor?.format !== expectedDescriptor.format) return null;
    }
  }
  const canonical = { name };
  for (const key of PERSISTED_UPSTREAM_KEYS) {
    if (["name", "origin", "_format", "format"].includes(key) || source[key] == null) continue;
    const normalized = normalizePersistedField(key, source[key]);
    if (normalized !== null) {
      canonical[key] = normalized;
      continue;
    }
    return null;
  }
  if (!isValidUpstreamUrl(source.upstream_url)) return null;
  canonical.origin = safeInventoryOrigin(source.upstream_url);
  // Privileged projection is explicit, ephemeral, and never persisted. The
  // default inventory projection contains no URL path, userinfo, query, hash,
  // authentication, or custom-header values.
  if (options.privileged === true) {
    canonical.upstream_url = source.upstream_url;
  }
  for (const key of [
    "auth_mode", "auth_username", "extra_header_1", "extra_value_1",
    "extra_header_2", "extra_value_2",
  ]) {
    if (source[key] == null) continue;
    const normalized = boundedString(source[key], MAX_PERSISTED_STRING_LENGTH);
    if (normalized === null) return null;
    if (options.privileged === true) canonical[key] = normalized;
  }
  return canonical;
}

function safeInventoryOrigin(value) {
  try {
    const parsed = new URL(value);
    if (
      !["http:", "https:"].includes(parsed.protocol)
      || parsed.username
      || parsed.password
      || parsed.search
      || parsed.hash
    ) return "";
    const origin = formatUpstreamOrigin(value);
    return origin === "Origin unavailable" ? "" : origin;
  } catch {
    return "";
  }
}

function isValidUpstreamUrl(value) {
  if (!boundedString(value, MAX_RUNTIME_URL_LENGTH)) return false;
  try {
    const parsed = new URL(value);
    return ["http:", "https:"].includes(parsed.protocol) && Boolean(parsed.hostname);
  } catch {
    return false;
  }
}

/**
 * Validates the exact secret-free record emitted by the default inventory
 * projection. `origin` is mandatory: an empty string is the canonical
 * withheld/unavailable sentinel, while a non-empty value must already be an
 * origin-only HTTP(S) URL. Privileged and unknown fields are rejected.
 */
function sanitizeSafeInventoryUpstream(value, expectedFormat = null) {
  const source = snapshotOwnDataRecord(value);
  if (!source) return null;
  const keys = Object.keys(source);
  if (!keys.every(key => persistedUpstreamKeySet.has(key))) return null;
  if (!["name", "_format", "format", "origin"].every(key => (
    Object.prototype.hasOwnProperty.call(source, key)
  ))) return null;
  const descriptor = getUpstreamFormatDescriptor(source.format);
  const expectedDescriptor = expectedFormat === null
    ? null
    : getUpstreamFormatDescriptor(expectedFormat);
  if (
    !descriptor?.inspectable
    || source._format !== descriptor.format
    || source.format !== descriptor.format
    || (expectedFormat !== null && expectedDescriptor?.format !== descriptor.format)
  ) return null;
  const safe = {};
  for (const [key, fieldValue] of Object.entries(source)) {
    const normalized = normalizePersistedField(key, fieldValue);
    if (normalized === null) return null;
    if (Array.isArray(normalized)) {
      const original = snapshotStringArray(
        fieldValue,
        MAX_PERSISTED_DISTRO_VERSIONS,
        MAX_PERSISTED_NAME_LENGTH
      );
      if (!original || normalized.length !== original.length
        || normalized.some((item, index) => item !== original[index])) return null;
      safe[key] = Object.freeze(normalized.slice());
    } else {
      if (normalized !== fieldValue) return null;
      safe[key] = normalized;
    }
  }
  return Object.freeze(safe);
}

function isSafeInventoryUpstream(value, expectedFormat = null) {
  return sanitizeSafeInventoryUpstream(value, expectedFormat) !== null;
}

function snapshotOwnDataRecord(value) {
  if (!value || typeof value !== "object" || isProxy(value)) return null;
  let prototype;
  let descriptors;
  try {
    if (Array.isArray(value)) return null;
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return null;
  }
  if (prototype !== Object.prototype && prototype !== null) return null;
  const ownKeys = Reflect.ownKeys(descriptors);
  if (ownKeys.some(key => typeof key !== "string")) return null;
  const snapshot = Object.create(null);
  for (const key of ownKeys) {
    const descriptor = descriptors[key];
    if (!descriptor || descriptor.enumerable !== true
      || !Object.prototype.hasOwnProperty.call(descriptor, "value")) return null;
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function snapshotStringArray(value, maxItems, maxStringLength) {
  const values = snapshotOwnDataArray(value, maxItems);
  if (!values) return null;
  const copy = [];
  for (const valueItem of values) {
    const item = boundedString(valueItem, maxStringLength);
    if (!item) return null;
    copy.push(item);
  }
  return copy;
}

function snapshotOwnDataArray(value, maxItems) {
  if (isProxy(value)) return null;
  let descriptors;
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return null;
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return null;
  }
  const lengthDescriptor = descriptors.length;
  if (!lengthDescriptor || !Object.prototype.hasOwnProperty.call(lengthDescriptor, "value")) {
    return null;
  }
  const length = lengthDescriptor.value;
  if (!Number.isSafeInteger(length) || length < 0 || length > maxItems) return null;
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some(key => (
    typeof key !== "string" || (key !== "length" && !/^(0|[1-9]\d*)$/u.test(key))
  ))) return null;
  const copy = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || descriptor.enumerable !== true
      || !Object.prototype.hasOwnProperty.call(descriptor, "value")) return null;
    copy.push(descriptor.value);
  }
  return copy;
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

function getCachedFlatResponse(
  globalState,
  cacheKey,
  workspace,
  repo,
  requestedFormats,
  account,
  now
) {
  if (!globalState || typeof globalState.get !== "function") return null;
  const cachedValue = globalState.get(cacheKey);
  if (cachedValue === undefined) return null;
  const cached = snapshotOwnDataRecord(cachedValue);
  const cachedValues = cached
    ? snapshotOwnDataArray(cached.upstreams, MAX_PERSISTED_UPSTREAMS)
    : null;
  const cachedUpstreams = cachedValues
    ? cachedValues.map(upstream => sanitizeSafeInventoryUpstream(upstream))
    : null;
  const inspectableFormats = getInspectableUpstreamFormats(requestedFormats);
  const valid = cachedUpstreams !== null
    && cachedUpstreams.every(Boolean)
    && isAccountEnvelope(cached, account, [
    "accountEpoch", "activationId", "active", "failedFormats", "successfulFormats",
    "timestamp", "total", "upstreams", "version",
  ])
    && isFresh(cached.timestamp, now)
    && Number.isInteger(cached.active) && cached.active >= 0
    && Number.isInteger(cached.total) && cached.total === cachedUpstreams.length
    && cached.active === cachedUpstreams.filter(upstream => upstream.is_active !== false).length
    && Array.isArray(cached.failedFormats) && cached.failedFormats.length === 0
    && Number.isInteger(cached.successfulFormats)
    && cached.successfulFormats === inspectableFormats.length
    && cachedUpstreams.every((upstream) => {
      const taggedFormats = [upstream._format, upstream.format]
        .filter(value => value !== undefined);
      return taggedFormats.length > 0
        && taggedFormats.every(value => value === taggedFormats[0])
        && inspectableFormats.includes(taggedFormats[0]);
    })
    && new Set(cachedUpstreams.map((upstream) => {
      const format = upstream._format || upstream.format;
      const identity = upstream.slug_perm ? `slug:${upstream.slug_perm}` : `name:${upstream.name}`;
      return `${format}\0${identity}`;
    })).size
      === cachedUpstreams.length;
  if (!valid) {
    evictCacheEntry(globalState, cacheKey, workspace, repo);
    return null;
  }
  const outcomes = getUniqueRequestedDescriptors(requestedFormats).map((descriptor) => {
    if (!descriptor.inspectable) {
      return makeFormatOutcome(descriptor.format, null, "unsupported", [], true);
    }
    return makeFormatOutcome(
      descriptor.format,
      descriptor.apiFormat,
      "success",
      cachedUpstreams.filter(upstream => (
        (upstream._format || upstream.format) === descriptor.format
      )),
      true
    );
  });
  return buildAggregateResult(outcomes, 0);
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
  requestedFormats,
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
    || response.successfulFormats !== requestedFormats.length
    || !serializedUpstreams.every((upstream) => {
      const format = upstream._format || upstream.format;
      return requestedFormats.includes(format);
    })
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

// Retained for compatibility with callers outside the inventory path. HTTP
// status alone can never prove that a format is unsupported or empty.
function isBenignUpstreamFormatError() {
  return false;
}

function isWarningWorthyUpstreamFormatError() {
  return true;
}

function isAbortError(error) {
  return error && (error.name === "AbortError" || error.code === "ABORT_ERR");
}

function isCancelled(options = {}) {
  return Boolean(options.signal?.aborted || options.cancellationToken?.isCancellationRequested);
}

function isCanonicalRepositoryIdentity(value) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= MAX_REPOSITORY_IDENTITY_LENGTH
    && value === value.trim()
    && !/[\u0000-\u001f\u007f]/u.test(value);
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
  const descriptor = getUpstreamFormatDescriptor(format);
  if (!descriptor) {
    return makeFormatOutcome(format, null, "failed", [], false, {
      kind: "invalid_request",
    });
  }
  if (!descriptor.inspectable) {
    return makeFormatOutcome(descriptor.format, null, "unsupported", [], true, null);
  }

  const retained = [];
  const seen = new Set();
  let page = 1;
  let paginationAnchor = null;
  try {
    while (page <= MAX_UPSTREAM_PAGES_PER_FORMAT) {
      if (isCancelled(options)) {
        return makeFormatOutcome(
          descriptor.format, descriptor.apiFormat, "cancelled", retained, false,
          { kind: "cancelled" }, page
        );
      }
      const endpoint = apiEndpoint(
        ["repos", workspace, repo, "upstream", descriptor.apiFormat],
        { query: { page, page_size: UPSTREAM_PAGE_SIZE } }
      );
      const request = () => api.get(endpoint, {
        responseType: "array",
        validate: Array.isArray,
        retry: "never",
        signal: options.signal,
        cancellationToken: options.cancellationToken,
      });
      const result = options.scheduler
        ? await options.scheduler.run(request, options)
        : await request();
      if (isCancelled(options)) {
        return makeFormatOutcome(
          descriptor.format, descriptor.apiFormat, "cancelled", retained, false,
          { kind: "cancelled" }, page
        );
      }
      if (!result || !result.ok) {
        const failure = normalizeUpstreamFailure(result || null);
        const state = failure.category === "cancelled" ? "cancelled" : "failed";
        return makeFormatOutcome(
          descriptor.format, descriptor.apiFormat, state, retained, false, result || null, page
        );
      }
      const raw = Array.isArray(result.data) ? result.data : null;
      if (!raw || raw.length > MAX_RUNTIME_UPSTREAMS_PER_FORMAT) {
        return makeFormatOutcome(
          descriptor.format, descriptor.apiFormat, "failed", retained, false,
          { kind: "invalid_response", status: result.status, requestId: result.requestId,
            serverRequestId: result.serverRequestId }, page
        );
      }
      const canonicalPage = raw.map(value => canonicalizeRuntimeUpstream(value, {
        expectedFormat: descriptor.format,
        privileged: options.projection === "privileged",
      }));
      if (canonicalPage.some((value, index) => (
        value === null || !hasCompatibleRawFormatIdentity(raw[index], descriptor)
      ))) {
        return makeFormatOutcome(
          descriptor.format, descriptor.apiFormat, "failed", retained, false,
          { kind: "invalid_response", status: result.status, requestId: result.requestId,
            serverRequestId: result.serverRequestId }, page
        );
      }
      for (const upstream of canonicalPage) {
        const identity = upstreamIdentity(descriptor, upstream);
        if (!identity || seen.has(identity)) {
          return makeFormatOutcome(
            descriptor.format, descriptor.apiFormat, "failed", retained, false,
            { kind: "invalid_response", status: result.status, requestId: result.requestId,
              serverRequestId: result.serverRequestId }, page
          );
        }
        seen.add(identity);
        retained.push({ ...upstream, _format: descriptor.format, format: descriptor.format });
      }

      const pagination = parseUpstreamPagination(result.headers || {}, page, raw.length);
      if (pagination === "empty") {
        return makeFormatOutcome(
          descriptor.format, descriptor.apiFormat, "success", retained, true, null, page
        );
      }
      if (!pagination) {
        return makeFormatOutcome(
          descriptor.format, descriptor.apiFormat, "incomplete", retained, false,
          { kind: "invalid_response", status: result.status, requestId: result.requestId,
            serverRequestId: result.serverRequestId }, page
        );
      }
      if (pagination !== "empty") {
        if (paginationAnchor && (
          pagination.count !== paginationAnchor.count
          || pagination.pageTotal !== paginationAnchor.pageTotal
          || pagination.pageSize !== paginationAnchor.pageSize
        )) {
          return makeFormatOutcome(
            descriptor.format, descriptor.apiFormat, "incomplete", retained, false,
            { kind: "invalid_response", status: result.status, requestId: result.requestId,
              serverRequestId: result.serverRequestId }, page
          );
        }
        paginationAnchor ||= pagination;
      }
      if (page >= pagination.pageTotal) {
        return makeFormatOutcome(
          descriptor.format, descriptor.apiFormat, "success", retained, true, null, page
        );
      }
      page += 1;
    }
    return makeFormatOutcome(
      descriptor.format, descriptor.apiFormat, "incomplete", retained, false,
      { kind: "resource_limit" }, MAX_UPSTREAM_PAGES_PER_FORMAT
    );
  } catch (error) {
    const failure = normalizeUpstreamFailure(error);
    const state = isCancelled(options) || failure.category === "cancelled"
      ? "cancelled"
      : ["request_limit", "rate_limit"].includes(failure.category)
        ? "uninspected"
        : "failed";
    return makeFormatOutcome(
      descriptor.format, descriptor.apiFormat, state, retained, false, error, page
    );
  }
}

function hasCompatibleRawFormatIdentity(value, descriptor) {
  return [value?._format, value?.format].every((format) => {
    if (format == null) return true;
    return getUpstreamFormatDescriptor(format)?.format === descriptor.format;
  });
}

function upstreamIdentity(descriptor, upstream) {
  const slug = boundedString(upstream.slug_perm, MAX_PERSISTED_NAME_LENGTH);
  const fallback = boundedString(upstream.name, MAX_PERSISTED_NAME_LENGTH);
  return slug
    ? `${descriptor.apiFormat}\0slug:${slug}`
    : fallback ? `${descriptor.apiFormat}\0name:${fallback}` : null;
}

function parseUpstreamPagination(headers, requestedPage, itemCount) {
  const names = [
    "x-pagination-page", "x-pagination-pagetotal", "x-pagination-count",
    "x-pagination-pagesize",
  ];
  const present = names.some(name => headers[name] !== undefined);
  if (!present) return requestedPage === 1 && itemCount === 0 ? "empty" : null;
  const values = names.map(name => parseStrictNonNegativeInteger(headers[name]));
  if (values.some(value => value === null)) return null;
  const [page, pageTotal, count, pageSize] = values;
  if (
    page !== requestedPage
    || pageTotal < 1
    || page > pageTotal
    || pageSize < 1
    || pageSize > UPSTREAM_PAGE_SIZE
    || itemCount > pageSize
    || pageTotal !== Math.max(1, Math.ceil(count / pageSize))
  ) return null;
  const expected = Math.min(pageSize, Math.max(0, count - ((page - 1) * pageSize)));
  return expected === itemCount ? { page, pageTotal, count, pageSize } : null;
}

function parseStrictNonNegativeInteger(value) {
  if (value === undefined) return null;
  const text = String(value).trim();
  if (!/^\d+$/.test(text)) return null;
  const parsed = Number(text);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

function makeFormatOutcome(format, apiFormat, state, entries, authoritative, source = null, pageCount = 0) {
  const failure = ["failed", "incomplete", "uninspected", "cancelled"].includes(state)
    ? normalizeUpstreamFailure(source)
    : null;
  return Object.freeze({
    format,
    apiFormat,
    state,
    status: state === "success" ? "loaded" : state === "cancelled" ? "aborted" : state,
    entries: Object.freeze(entries.map(entry => Object.freeze({ ...entry }))),
    upstreams: Object.freeze(entries.map(entry => Object.freeze({ ...entry }))),
    authoritative: authoritative === true,
    failure,
    pageCount,
  });
}

function getUniqueRequestedDescriptors(formats) {
  return formats.map(getUpstreamFormatDescriptor).filter(Boolean);
}

function createOperationDeadline(options, scheduler) {
  const controller = new AbortController();
  const externalSignal = options.signal;
  let expired = false;
  const abort = () => {
    controller.abort();
    scheduler.cancel();
  };
  const onExternalAbort = () => abort();
  if (externalSignal?.aborted) abort();
  else externalSignal?.addEventListener?.("abort", onExternalAbort, { once: true });
  const requestedTimeout = Number(options.operationTimeoutMs);
  const timeoutMs = Number.isSafeInteger(requestedTimeout) && requestedTimeout > 0
    ? Math.min(requestedTimeout, UPSTREAM_OPERATION_TIMEOUT_MS)
    : UPSTREAM_OPERATION_TIMEOUT_MS;
  const timer = setTimeout(() => {
    expired = true;
    abort();
  }, timeoutMs);
  timer.unref?.();
  return {
    signal: controller.signal,
    timedOut: () => expired,
    dispose() {
      clearTimeout(timer);
      externalSignal?.removeEventListener?.("abort", onExternalAbort);
    },
  };
}

function buildAggregateResult(outcomes, requestCount, options = {}) {
  const entries = outcomes.flatMap(outcome => outcome.entries);
  if (entries.length > MAX_RUNTIME_UPSTREAMS) {
    const overflow = outcomes.find(outcome => outcome.entries.length > 0);
    return buildAggregateResult(outcomes.map(outcome => outcome === overflow
      ? makeFormatOutcome(
        outcome.format, outcome.apiFormat, "failed", [], false,
        { kind: "resource_limit" }, outcome.pageCount
      )
      : outcome), requestCount, options);
  }
  entries.sort(sortUpstreams);
  const failedOutcomes = outcomes.filter(outcome => outcome.state === "failed");
  const uninspectedOutcomes = outcomes.filter(outcome => (
    ["incomplete", "uninspected", "cancelled"].includes(outcome.state)
  ));
  const unsupportedOutcomes = outcomes.filter(outcome => outcome.state === "unsupported");
  const successfulOutcomes = outcomes.filter(outcome => (
    outcome.state === "success" && outcome.authoritative
  ));
  const inspectableOutcomes = outcomes.filter(outcome => outcome.apiFormat !== null);
  const authoritative = outcomes.length === 0 || (
    inspectableOutcomes.length > 0
    && inspectableOutcomes.every(outcome => (
      outcome.state === "success" && outcome.authoritative
    ))
  );
  const cancelled = options.cancelled === true
    || outcomes.some(outcome => outcome.state === "cancelled");
  let state = "failed";
  if (cancelled) state = "cancelled";
  else if (inspectableOutcomes.length === 0 && unsupportedOutcomes.length > 0) {
    state = "unsupported";
  } else if (authoritative) state = entries.length > 0 ? "complete" : "empty";
  else if (successfulOutcomes.length > 0 || entries.length > 0) state = "partial";
  const failures = Object.freeze([
    ...failedOutcomes,
    ...uninspectedOutcomes.filter(outcome => outcome.failure),
  ].map(outcome => Object.freeze({
    format: outcome.format,
    apiFormat: outcome.apiFormat,
    state: outcome.state,
    ...outcome.failure,
  })));
  const configuredTotal = authoritative ? entries.length : null;
  return Object.freeze({
    state,
    outcomes: Object.freeze(outcomes.slice()),
    upstreams: Object.freeze(entries),
    entries: Object.freeze(entries),
    active: entries.filter(upstream => upstream.is_active !== false).length,
    loadedCount: entries.length,
    total: configuredTotal,
    configuredTotal,
    failedFormats: Object.freeze(failedOutcomes.map(outcome => outcome.format)),
    failures,
    unsupportedFormats: Object.freeze(unsupportedOutcomes.map(outcome => outcome.format)),
    uninspectedFormats: Object.freeze(uninspectedOutcomes.map(outcome => outcome.format)),
    successfulFormats: successfulOutcomes.length,
    complete: authoritative,
    incomplete: !authoritative,
    partial: state === "partial",
    cancelled,
    requestCount: Number.isSafeInteger(requestCount) ? requestCount : 0,
  });
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
    return this._buildRepositoryUpstreamState(
      new Map(),
      [],
      0,
      SUPPORTED_UPSTREAM_FORMATS,
      { cancelled: true }
    );
  }

  async existsLocally(workspace, repo, name, format, options = {}) {
    const account = this._captureAccount(options);
    if (!account) return { data: null, error: null, complete: false, stale: true };
    let endpoint;
    let query;
    try {
      query = new SearchQueryBuilder().name(name).format(format).build();
      endpoint = apiEndpoint(["packages", workspace, repo]);
    } catch (error) {
      return { data: null, error, complete: false };
    }
    const paginatedFetch = new PaginatedFetch(this.api);
    const descriptor = `upstream-local-preview:${workspace}:${repo}:${format}`;
    let resume = null;
    const knownIdentities = new Set();
    while (true) {
      const result = await paginatedFetch.fetchCollection(endpoint, {
        pageSize: LOCAL_PACKAGE_PAGE_SIZE,
        maxPages: MAX_LOCAL_PACKAGE_PAGES,
        maxRequests: MAX_LOCAL_PACKAGE_PAGES,
        maxItems: MAX_LOCAL_PACKAGES,
        pageBatchLimit: 1,
        resume,
        knownIdentities,
        query,
        descriptor,
        canonicalIdentity: packageCollectionIdentity,
        validate: value => isLocalPackageArray(value, workspace, repo),
        retry: "never",
        signal: options.signal,
        cancellationToken: options.cancellationToken,
      });
      if (!isAccountCurrent(this.connectionManager, account)) {
        return { data: null, error: null, complete: false, stale: true };
      }
      const exact = result.items.find(candidate => (
        candidate.name === name
        && candidate.format === format
        && candidate.namespace === workspace
        && candidate.repository === repo
      ));
      if (exact) return { data: exact, error: null, complete: result.complete, stale: false };
      for (const candidate of result.items) {
        const identity = packageCollectionIdentity(candidate);
        if (identity) knownIdentities.add(identity);
      }
      if (result.complete) {
        return { data: null, error: null, complete: true, stale: false };
      }
      if (!result.continuation) {
        return {
          data: null,
          error: result.failures[0]?.error || incompleteLocalPackageError(),
          complete: false,
          stale: false,
        };
      }
      resume = result.continuation;
    }
  }

  async getUpstreamsForFormat(workspace, repo, format, options = {}) {
    const result = await this.getUpstreamDataForFormats(workspace, repo, [format], options);
    if (!result) return { data: [], error: null, complete: false, stale: true };
    const failure = result.failures[0] || null;
    return {
      data: result.upstreams,
      error: failure,
      complete: result.complete,
      stale: false,
    };
  }

  async getUpstreamDataForFormats(workspace, repo, formats, options = {}) {
    if (!isCanonicalRepositoryIdentity(workspace) || !isCanonicalRepositoryIdentity(repo)) {
      throw new TypeError("Upstream repository identity must be a bounded canonical string");
    }
    if (!Array.isArray(formats)) {
      throw new TypeError("Upstream formats must be an array");
    }
    if (formats.some(format => !getUpstreamFormatDescriptor(format))) {
      throw new TypeError("Upstream formats contain an unrecognized format");
    }
    const account = this._captureAccount(options);
    if (!account || isCancelled(options)) return null;
    const requestedFormats = getSupportedUpstreamFormats(formats);
    if (formats.length > 0 && requestedFormats.length === 0) {
      throw new TypeError("Upstream formats did not contain a recognized canonical format");
    }
    if (requestedFormats.length === 0) {
      return buildAggregateResult([], 0);
    }
    const cacheKey = getUpstreamCacheKey(workspace, repo, requestedFormats);
    const globalState = this.context && this.context.globalState;
    const operationToken = globalState && options.projection !== "privileged"
      ? beginCacheOperation(globalState, cacheKey)
      : null;
    try {
      const cached = options.bypassCache === true || options.projection === "privileged"
        ? null
        : getCachedFlatResponse(
          globalState,
          cacheKey,
          workspace,
          repo,
          requestedFormats,
          account,
          this.now()
        );
      if (cached && isAccountCurrent(this.connectionManager, account)) return cached;

      const descriptors = getUniqueRequestedDescriptors(requestedFormats);
      const inspectableCount = descriptors.filter(descriptor => descriptor.inspectable).length;
      const scheduler = options.scheduler || new UpstreamOperationScheduler({
        concurrency: UPSTREAM_REQUEST_CONCURRENCY,
        maxRequests: Math.max(1, inspectableCount * MAX_UPSTREAM_PAGES_PER_FORMAT),
      });
      const deadline = createOperationDeadline(options, scheduler);
      let outcomes;
      try {
        outcomes = await Promise.all(descriptors.map(descriptor => fetchFormatUpstreams(
          this.api,
          workspace,
          repo,
          descriptor.format,
          { ...options, signal: deadline.signal, scheduler }
        )));
      } finally {
        deadline.dispose();
      }
      if (!isAccountCurrent(this.connectionManager, account)) return null;
      if (deadline.timedOut()) {
        outcomes = outcomes.map(outcome => outcome.state === "cancelled"
          ? makeFormatOutcome(
            outcome.format, outcome.apiFormat, "uninspected", outcome.entries, false,
            { kind: "timeout", retryable: true }, outcome.pageCount
          )
          : outcome);
      }
      const response = buildAggregateResult(outcomes, scheduler.requestCount, {
        cancelled: isCancelled(options),
      });
      if (!isAccountCurrent(this.connectionManager, account)) return null;
      if (
        !isCancelled(options)
        && options.projection !== "privileged"
        && response.complete
        && globalState
      ) {
        await persistFlatResponse(
          globalState,
          cacheKey,
          workspace,
          repo,
          response,
          account,
          this.connectionManager,
          operationToken,
          getInspectableUpstreamFormats(requestedFormats),
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
    const failedFormats = Array.isArray(result.failedFormats) ? result.failedFormats : [];
    const uninspectedFormats = Array.isArray(result.uninspectedFormats)
      ? result.uninspectedFormats
      : [];
    const unavailableFormats = [...failedFormats, ...uninspectedFormats];
    if (unavailableFormats.length > 0 && result.upstreams.length === 0) {
      return {
        data: [],
        error: `Could not load upstream data for: ${unavailableFormats.join(", ")}`,
        complete: false,
        partial: false,
        failedFormats,
        uninspectedFormats,
      };
    }
    return {
      data: result.upstreams,
      error: null,
      complete: result.complete,
      partial: result.partial,
      failedFormats,
      uninspectedFormats,
    };
  }

  async getRepositoryUpstreamState(workspace, repo, options = {}) {
    return this.getRepositoryUpstreamStateForFormats(
      workspace, repo, SUPPORTED_UPSTREAM_FORMATS, options
    );
  }

  async getRepositoryUpstreamStateForFormats(workspace, repo, formats, options = {}) {
    const result = await this.getUpstreamDataForFormats(workspace, repo, formats, options);
    const requestedFormats = getSupportedUpstreamFormats(formats);
    if (result === null) {
      return this._buildRepositoryUpstreamState(
        new Map(),
        [],
        0,
        requestedFormats,
        { cancelled: true }
      );
    }
    const grouped = new Map();
    for (const upstream of result.upstreams) {
      const format = typeof upstream._format === "string" ? upstream._format : upstream.format;
      if (!requestedFormats.includes(format)) continue;
      const values = grouped.get(format) || [];
      values.push(upstream);
      grouped.set(format, values);
    }
    return {
      ...result,
      groupedUpstreams: grouped,
    };
  }

  async getRepositoryUpstreams(workspace, repo, options = {}) {
    return (await this.getRepositoryUpstreamState(workspace, repo, options)).upstreams;
  }

  async getActiveRepositoryUpstreamsForFormat(workspace, repo, format, options = {}) {
    const state = await this.getRepositoryUpstreamState(workspace, repo, options);
    return getActiveUpstreamsFromRepositoryState(state, format);
  }

  async previewResolution(workspace, repo, name, format, options = {}) {
    const descriptor = getUpstreamFormatDescriptor(format);
    if (!descriptor?.inspectable) {
      throw new TypeError("Upstream preview format must be a recognized inspectable format");
    }
    const canonicalFormat = descriptor.format;
    const account = this._captureAccount(options);
    if (!account) return null;
    const sharedOptions = { ...options, account };
    const [localResult, upstreamResult] = await Promise.allSettled([
      this.existsLocally(workspace, repo, name, canonicalFormat, sharedOptions),
      this.getUpstreamsForFormat(workspace, repo, canonicalFormat, sharedOptions),
    ]);
    if (!isAccountCurrent(this.connectionManager, account)) return null;
    const localPkg = localResult.status === "fulfilled"
      ? localResult.value
      : { data: null, error: localResult.reason, complete: false };
    const upstreams = upstreamResult.status === "fulfilled"
      && upstreamResult.value && typeof upstreamResult.value === "object"
      ? upstreamResult.value
      : { data: [], error: upstreamResult.reason, complete: false };
    const rawConfigs = Array.isArray(upstreams.data) ? upstreams.data : [];
    const sanitizedConfigs = rawConfigs.map(upstream => (
      sanitizeSafeInventoryUpstream(upstream, canonicalFormat)
    ));
    const configsValid = sanitizedConfigs.every(Boolean);
    const configs = sanitizedConfigs.filter(Boolean);
    const active = configs.filter(upstream => upstream.is_active !== false);
    const upstreamError = upstreams.error || (configsValid ? null : { kind: "invalid_response" });
    return {
      name,
      format: canonicalFormat,
      workspace,
      repo,
      local: {
        data: localPkg.data || null,
        errorMessage: localPkg.error ? formatUpstreamError(localPkg.error, "local") : null,
        complete: localPkg.complete === true,
      },
      upstreams: {
        data: { total: configs.length, active: active.length, configs },
        errorMessage: upstreamError ? formatUpstreamError(upstreamError, "upstream") : null,
        complete: upstreams.complete === true && configsValid,
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
    const cachedValue = globalState.get(this._getRepositoryUpstreamCacheKey(workspace, repo));
    if (cachedValue === undefined) return null;
    const cached = snapshotOwnDataRecord(cachedValue);
    const groupedValue = cached ? snapshotOwnDataRecord(cached.groupedUpstreams) : null;
    const formats = groupedValue ? Object.keys(groupedValue) : [];
    const safeGrouped = new Map();
    let groupedValid = groupedValue !== null;
    for (const format of formats) {
      const values = snapshotOwnDataArray(
        groupedValue[format],
        MAX_PERSISTED_UPSTREAMS_PER_FORMAT
      );
      const safeValues = values?.map(upstream => (
        sanitizeSafeInventoryUpstream(upstream, format)
      ));
      if (!safeValues || safeValues.some(value => value === null)) {
        groupedValid = false;
        break;
      }
      safeGrouped.set(format, safeValues);
    }
    const valid = groupedValid && isAccountEnvelope(cached, account, [
      "accountEpoch", "activationId", "groupedUpstreams", "successfulFormats",
      "timestamp", "version",
    ])
      && isFresh(cached.timestamp, this.now())
      && formats.every(format => SUPPORTED_UPSTREAM_FORMATS.includes(format))
      && formats.every(format => (
        safeGrouped.get(format).every(upstream => (
          upstream._format === format && upstream.format === format
        ))
        && new Set(safeGrouped.get(format).map((upstream) => (
          upstream.slug_perm ? `slug:${upstream.slug_perm}` : `name:${upstream.name}`
        ))).size
          === safeGrouped.get(format).length
      ))
      && formats.reduce((total, format) => (
        total + safeGrouped.get(format).length
      ), 0) <= MAX_PERSISTED_UPSTREAMS
      && Number.isInteger(cached.successfulFormats)
      && cached.successfulFormats === SUPPORTED_UPSTREAM_FORMATS.length;
    if (!valid) {
      this._evictInvalidRepositoryUpstreamCacheEntry(workspace, repo, globalState);
      return null;
    }
    return this._buildRepositoryUpstreamState(
      safeGrouped,
      [],
      cached.successfulFormats,
      []
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
    return this.getRepositoryUpstreamStateForFormats(
      workspace,
      repo,
      SUPPORTED_UPSTREAM_FORMATS,
      options
    );
  }

  _buildRepositoryUpstreamState(
    groupedUpstreams,
    failedFormats,
    successfulFormats,
    uninspectedFormats = [],
    options = {}
  ) {
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
    const normalizedFailedFormats = [...new Set(Array.isArray(failedFormats) ? failedFormats : [])];
    const normalizedUninspectedFormats = [
      ...new Set(Array.isArray(uninspectedFormats) ? uninspectedFormats : []),
    ];
    const complete = normalizedFailedFormats.length === 0 && normalizedUninspectedFormats.length === 0;
    return {
      groupedUpstreams: normalizedGrouped,
      failedFormats: normalizedFailedFormats,
      uninspectedFormats: normalizedUninspectedFormats,
      successfulFormats,
      upstreams,
      active,
      total: upstreams.length,
      complete,
      incomplete: !complete,
      partial: !complete && successfulFormats > 0,
      cancelled: options.cancelled === true,
      requestCount: Number.isSafeInteger(options.requestCount) ? options.requestCount : 0,
    };
  }

  _deserializeGroupedUpstreams(groupedUpstreams) {
    const grouped = new Map();
    for (const format of SUPPORTED_UPSTREAM_FORMATS) {
      if (Array.isArray(groupedUpstreams[format])) {
        const upstreams = groupedUpstreams[format]
          .map(upstream => sanitizeSafeInventoryUpstream(upstream, format))
          .filter(Boolean);
        grouped.set(format, upstreams);
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

function isLocalPackageArray(value, workspace, repository) {
  return Array.isArray(value)
    && value.length <= LOCAL_PACKAGE_PAGE_SIZE
    && value.every(item => isLocalPackage(item, workspace, repository));
}

function isLocalPackage(item, workspace, repository) {
  if (
    !isObjectRecord(item)
    || !boundedString(item.name, MAX_PERSISTED_STRING_LENGTH)
    || !boundedString(item.format, MAX_PERSISTED_NAME_LENGTH)
    || item.namespace !== workspace
    || item.repository !== repository
  ) return false;
  try {
    packageCollectionIdentity(item);
    return true;
  } catch {
    return false;
  }
}

function incompleteLocalPackageError() {
  return Object.freeze({
    kind: "incomplete_collection",
    status: null,
    retryable: true,
    message: "The local package collection could not be verified completely.",
    requestId: null,
    retryAfterMs: null,
    outcomeUnknown: false,
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
  isSafeInventoryUpstream,
  sanitizeSafeInventoryUpstream,
  getUpstreamCacheKey,
  MAX_PERSISTED_UPSTREAMS,
  MAX_RUNTIME_UPSTREAMS_PER_FORMAT,
  PERSISTED_UPSTREAM_KEYS,
  SUPPORTED_UPSTREAM_FORMATS,
  UpstreamChecker,
  UPSTREAM_CACHE_SCHEMA_VERSION,
  UPSTREAM_FETCH_BATCH_SIZE,
  UPSTREAM_REQUEST_CONCURRENCY,
  UPSTREAM_CACHE_TTL_MS,
};

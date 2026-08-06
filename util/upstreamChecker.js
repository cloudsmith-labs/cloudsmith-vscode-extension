// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { CloudsmithAPI } = require("./cloudsmithAPI");
const { CredentialManager } = require("./credentialManager");
const { SearchQueryBuilder } = require("./searchQueryBuilder");
const {
  getSupportedUpstreamFormats,
  SUPPORTED_UPSTREAM_FORMATS,
} = require("./upstreamFormats");
const UPSTREAM_CACHE_TTL_MS = 10 * 60 * 1000;
const UPSTREAM_FETCH_BATCH_SIZE = 5;
const REPOSITORY_UPSTREAM_CACHE_KEY_PREFIX = "cloudsmith-upstreams:v2";
const BENIGN_UPSTREAM_FORMAT_STATUS_CODES = new Set([400, 404, 405, 422]);

function isCacheObjectRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function getUpstreamCacheKey(workspace, repo, formats = SUPPORTED_UPSTREAM_FORMATS) {
  const normalizedFormats = getSupportedUpstreamFormats(formats);
  const isAllFormats =
    normalizedFormats.length === SUPPORTED_UPSTREAM_FORMATS.length &&
    normalizedFormats.every((format, index) => format === SUPPORTED_UPSTREAM_FORMATS[index]);

  if (isAllFormats) {
    return `cloudsmith-upstreams:all:${workspace}:${repo}`;
  }

  return `cloudsmith-upstreams:formats:${workspace}:${repo}:${normalizedFormats.join(",")}`;
}

function logUpstreamCacheError(action, workspace, repo, error) {
  const message = error && error.message ? error.message : String(error);
  console.warn(
    `[UpstreamChecker] Failed to ${action} upstream cache for ${workspace}/${repo}: ${message}`
  );
}

function evictInvalidUpstreamCacheEntry(globalState, cacheKey, workspace, repo) {
  if (!globalState || typeof globalState.update !== "function") {
    return;
  }

  try {
    const updateResult = globalState.update(cacheKey, undefined);
    if (updateResult && typeof updateResult.catch === "function") {
      updateResult.catch((error) => {
        logUpstreamCacheError("evict invalid entry from", workspace, repo, error);
      });
    }
  } catch (error) {
    logUpstreamCacheError("evict invalid entry from", workspace, repo, error);
  }
}

function getCachedUpstreamResponse(globalState, cacheKey, workspace, repo) {
  if (!globalState || typeof globalState.get !== "function") {
    return null;
  }

  const cached = globalState.get(cacheKey);
  if (cached === undefined) {
    return null;
  }

  const isValidCacheEntry = isCacheObjectRecord(cached)
    && Number.isFinite(cached.timestamp)
    && Array.isArray(cached.upstreams)
    && Number.isFinite(cached.active)
    && Number.isFinite(cached.total)
    && Array.isArray(cached.failedFormats)
    && cached.failedFormats.length === 0
    && Number.isFinite(cached.successfulFormats);

  if (!isValidCacheEntry) {
    evictInvalidUpstreamCacheEntry(globalState, cacheKey, workspace, repo);
    return null;
  }

  if ((Date.now() - cached.timestamp) >= UPSTREAM_CACHE_TTL_MS) {
    return null;
  }

  return {
    upstreams: cached.upstreams,
    active: cached.active,
    total: cached.total,
    failedFormats: cached.failedFormats,
    successfulFormats: cached.successfulFormats,
  };
}

async function persistUpstreamResponse(globalState, cacheKey, workspace, repo, response) {
  if (!globalState || typeof globalState.update !== "function") {
    return;
  }

  try {
    await globalState.update(cacheKey, {
      timestamp: Date.now(),
      ...response,
    });
  } catch (error) {
    logUpstreamCacheError("persist", workspace, repo, error);
  }
}

function getUpstreamErrorStatusCode(message) {
  const normalized = typeof message === "string" ? message.toLowerCase() : "";
  const statusMatch = normalized.match(/response status:\s*(\d{3})/);
  if (!statusMatch) {
    return null;
  }

  return Number(statusMatch[1]);
}

function isBenignUpstreamFormatError(message) {
  const normalized = typeof message === "string" ? message.toLowerCase() : "";
  if (!normalized) {
    return false;
  }

  const statusCode = getUpstreamErrorStatusCode(normalized);
  if (statusCode !== null) {
    return BENIGN_UPSTREAM_FORMAT_STATUS_CODES.has(statusCode);
  }

  const benignKeywords = [
    "not found",
    "unsupported",
    "not applicable",
    "unknown format",
    "no upstream",
    "does not exist",
  ];

  if (benignKeywords.some((keyword) => normalized.includes(keyword))) {
    return true;
  }

  return false;
}

function isWarningWorthyUpstreamFormatError(message) {
  const normalized = typeof message === "string" ? message.toLowerCase() : "";
  if (!normalized) {
    return true;
  }

  return !isBenignUpstreamFormatError(normalized);
}

function isAbortError(error) {
  return error && (error.name === "AbortError" || error.code === "ABORT_ERR");
}

function getActiveUpstreamsFromRepositoryState(state, format) {
  if (!state || !(state.groupedUpstreams instanceof Map)) {
    return [];
  }

  const upstreams = state.groupedUpstreams.get(format);
  if (!Array.isArray(upstreams)) {
    return [];
  }

  return upstreams.filter((upstream) => upstream && upstream.is_active !== false);
}

function getUpstreamRequestOptions(apiKey, signal) {
  const headers = {
    accept: "application/json",
    "content-type": "application/json",
  };

  if (apiKey) {
    headers["X-Api-Key"] = apiKey;
  }

  return {
    method: "GET",
    headers,
    signal,
  };
}

function sortUpstreams(left, right) {
  const leftName = typeof left.name === "string" ? left.name : "";
  const rightName = typeof right.name === "string" ? right.name : "";
  if (leftName !== rightName) {
    return leftName.localeCompare(rightName, undefined, { sensitivity: "base" });
  }

  const leftFormat = typeof left._format === "string"
    ? left._format
    : (typeof left.format === "string" ? left.format : "");
  const rightFormat = typeof right._format === "string"
    ? right._format
    : (typeof right.format === "string" ? right.format : "");

  return leftFormat.localeCompare(rightFormat, undefined, { sensitivity: "base" });
}

async function fetchFormatUpstreams(api, workspace, repo, format, apiKey, signal) {
  try {
    if (signal && signal.aborted) {
      return { format, status: "aborted", upstreams: [] };
    }

    const result = await api.makeRequest(
      `repos/${workspace}/${repo}/upstream/${format}/`,
      getUpstreamRequestOptions(apiKey, signal)
    );

    if (signal && signal.aborted) {
      return { format, status: "aborted", upstreams: [] };
    }

    if (typeof result === "string") {
      if (isWarningWorthyUpstreamFormatError(result)) {
        return { format, status: "failed", error: result, upstreams: [] };
      }

      return { format, status: "loaded", upstreams: [] };
    }

    if (!Array.isArray(result)) {
      return {
        format,
        status: "failed",
        error: `Unexpected upstream response for format "${format}".`,
        upstreams: [],
      };
    }

    return {
      format,
      status: "loaded",
      upstreams: result.map((upstream) => ({
        ...upstream,
        _format: format,
        format,
      })),
    };
  } catch (error) {
    if (isAbortError(error) || (signal && signal.aborted)) {
      return { format, status: "aborted", upstreams: [] };
    }

    const message = error && error.message ? error.message : String(error);
    if (!isWarningWorthyUpstreamFormatError(message)) {
      return { format, status: "loaded", upstreams: [] };
    }

    return { format, status: "failed", error: message, upstreams: [] };
  }
}

class UpstreamChecker {
  constructor(context) {
    this.context = context;
    this.api = new CloudsmithAPI(context);
  }

  /**
   * Check if a package exists locally in a repository.
   *
   * @param   {string} workspace  Workspace slug.
   * @param   {string} repo       Repository slug.
   * @param   {string} name       Package name.
   * @param   {string} format     Package format (e.g., 'python', 'npm').
   * @returns {Object|null}       Package object if found, null otherwise.
   */
  async existsLocally(workspace, repo, name, format) {
    const qb = new SearchQueryBuilder();
    const query = encodeURIComponent(qb.name(name).format(format).build());
    const result = await this.api.get(
      `packages/${workspace}/${repo}/?query=${query}&page_size=1`
    );
    if (typeof result === "string") {
      return { data: null, error: result };
    }
    if (!Array.isArray(result) || result.length === 0) {
      return { data: null, error: null };
    }
    return { data: result[0], error: null };
  }

  /**
   * Get active upstream configurations for a specific format in a repository.
   *
   * @param   {string} workspace  Workspace slug.
   * @param   {string} repo       Repository slug.
   * @param   {string} format     Package format slug.
   * @returns {Array}             Array of upstream config objects.
   */
  async getUpstreamsForFormat(workspace, repo, format) {
    const result = await this.api.get(`repos/${workspace}/${repo}/upstream/${format}/`);
    if (typeof result === "string") {
      return { data: [], error: result };
    }
    if (!Array.isArray(result)) {
      return { data: [], error: null };
    }
    return { data: result, error: null };
  }

  async getUpstreamDataForFormats(workspace, repo, formats, options = {}) {
    const { signal } = options;
    const requestedFormats = getSupportedUpstreamFormats(formats);

    if (signal && signal.aborted) {
      return null;
    }

    if (requestedFormats.length === 0) {
      return {
        upstreams: [],
        active: 0,
        total: 0,
        failedFormats: [],
        successfulFormats: 0,
      };
    }

    const cacheKey = getUpstreamCacheKey(workspace, repo, requestedFormats);
    const globalState = this.context && this.context.globalState
      ? this.context.globalState
      : null;
    const cached = getCachedUpstreamResponse(globalState, cacheKey, workspace, repo);

    if (cached) {
      return cached;
    }

    let apiKey = null;
    try {
      const credentialManager = new CredentialManager(this.context);
      apiKey = await credentialManager.getApiKey();
    } catch {
      apiKey = null;
    }

    if (signal && signal.aborted) {
      return null;
    }

    const upstreams = [];
    const failedFormats = [];
    let successfulFormats = 0;

    for (let index = 0; index < requestedFormats.length; index += UPSTREAM_FETCH_BATCH_SIZE) {
      if (signal && signal.aborted) {
        return null;
      }

      const batch = requestedFormats.slice(index, index + UPSTREAM_FETCH_BATCH_SIZE);
      const batchResults = await Promise.all(
        batch.map((format) => fetchFormatUpstreams(this.api, workspace, repo, format, apiKey, signal))
      );

      if (signal && signal.aborted) {
        return null;
      }

      for (const result of batchResults) {
        if (result.status === "aborted") {
          return null;
        }

        if (result.status === "failed") {
          failedFormats.push(result.format);
          continue;
        }

        if (result.status !== "loaded") {
          continue;
        }

        successfulFormats += 1;
        upstreams.push(...result.upstreams);
      }
    }

    upstreams.sort(sortUpstreams);
    const active = upstreams.filter((upstream) => upstream.is_active !== false).length;
    const response = {
      upstreams,
      active,
      total: upstreams.length,
      failedFormats,
      successfulFormats,
    };

    if (
      !signal?.aborted &&
      failedFormats.length === 0 &&
      globalState
    ) {
      await persistUpstreamResponse(globalState, cacheKey, workspace, repo, response);
    }

    return response;
  }

  async getAllUpstreamData(workspace, repo, options = {}) {
    return this.getUpstreamDataForFormats(workspace, repo, SUPPORTED_UPSTREAM_FORMATS, options);
  }

  async getAllUpstreams(workspace, repo, options = {}) {
    const result = await this.getAllUpstreamData(workspace, repo, options);
    if (result === null) {
      return { data: [], error: null, aborted: true };
    }

    if (result.failedFormats.length > 0 && result.upstreams.length === 0) {
      return {
        data: result.upstreams,
        error: `Could not load upstream data for: ${result.failedFormats.join(", ")}`,
      };
    }

    return { data: result.upstreams, error: null };
  }

  /**
   * Load all upstream configurations for a repository across every supported format.
   * Results are cached in globalState for 10 minutes when the fetch completes without failures.
   *
   * @param   {string} workspace Workspace slug.
   * @param   {string} repo      Repository slug.
   * @param   {Object} options   Optional request settings.
   * @returns {Object}           Aggregated upstream state.
   */
  async getRepositoryUpstreamState(workspace, repo, options = {}) {
    const cachedState = this._getCachedRepositoryUpstreamState(workspace, repo);
    if (cachedState) {
      return cachedState;
    }

    const signal = options && options.signal ? options.signal : null;
    const fetchState = await this._fetchRepositoryUpstreamState(workspace, repo, signal);

    if (!signal?.aborted && fetchState.failedFormats.length === 0) {
      await this._cacheRepositoryUpstreamState(workspace, repo, fetchState);
    }

    return fetchState;
  }

  /**
   * Load the flattened upstream list for a repository across every supported format.
   *
   * @param   {string} workspace Workspace slug.
   * @param   {string} repo      Repository slug.
   * @param   {Object} options   Optional request settings.
   * @returns {Array}            Flattened upstream list.
   */
  async getRepositoryUpstreams(workspace, repo, options = {}) {
    const state = await this.getRepositoryUpstreamState(workspace, repo, options);
    return state.upstreams;
  }

  async getActiveRepositoryUpstreamsForFormat(workspace, repo, format, options = {}) {
    const state = await this.getRepositoryUpstreamState(workspace, repo, options);
    return getActiveUpstreamsFromRepositoryState(state, format);
  }

  /**
   * Orchestrate a full upstream resolution preview.
   * Checks local existence and upstream configs for a package preview.
   *
   * @param   {string} workspace  Workspace slug.
   * @param   {string} repo       Repository slug.
   * @param   {string} name       Package name.
   * @param   {string} format     Package format.
   * @returns {Object}            Combined result with local and upstream info.
   */
  async previewResolution(workspace, repo, name, format) {
    const [localPkg, upstreams] = await Promise.all([
      this.existsLocally(workspace, repo, name, format),
      this.getUpstreamsForFormat(workspace, repo, format),
    ]);

    const upstreamList = Array.isArray(upstreams.data) ? upstreams.data : [];
    const activeUpstreams = upstreamList.filter((upstream) => upstream.is_active !== false);

    return {
      name,
      format,
      workspace,
      repo,
      local: localPkg,
      upstreams: {
        data: {
          total: upstreamList.length,
          active: activeUpstreams.length,
          configs: upstreamList,
        },
        error: upstreams.error,
      },
      canResolveViaUpstream: activeUpstreams.length > 0,
    };
  }

  _getRepositoryUpstreamCacheKey(workspace, repo) {
    return `${REPOSITORY_UPSTREAM_CACHE_KEY_PREFIX}:${workspace}:${repo}`;
  }

  _isCacheObjectRecord(value) {
    return isCacheObjectRecord(value);
  }

  _logRepositoryUpstreamCacheError(action, workspace, repo, error) {
    const message = error && error.message ? error.message : String(error);
    console.warn(
      `[UpstreamChecker] Failed to ${action} repository upstream cache for ${workspace}/${repo}: ${message}`
    );
  }

  _evictInvalidRepositoryUpstreamCacheEntry(workspace, repo, globalState) {
    if (!globalState || typeof globalState.update !== "function") {
      return;
    }

    try {
      const updateResult = globalState.update(
        this._getRepositoryUpstreamCacheKey(workspace, repo),
        undefined
      );

      if (updateResult && typeof updateResult.catch === "function") {
        updateResult.catch((error) => {
          this._logRepositoryUpstreamCacheError("evict invalid entry from", workspace, repo, error);
        });
      }
    } catch (error) {
      this._logRepositoryUpstreamCacheError("evict invalid entry from", workspace, repo, error);
    }
  }

  _getCachedRepositoryUpstreamState(workspace, repo) {
    const globalState = this.context && this.context.globalState;
    if (!globalState || typeof globalState.get !== "function") {
      return null;
    }

    const cached = globalState.get(this._getRepositoryUpstreamCacheKey(workspace, repo));
    const isValidCacheEntry = this._isCacheObjectRecord(cached)
      && Number.isFinite(cached.timestamp)
      && this._isCacheObjectRecord(cached.groupedUpstreams);

    if (!isValidCacheEntry) {
      if (cached !== undefined) {
        this._evictInvalidRepositoryUpstreamCacheEntry(workspace, repo, globalState);
      }
      return null;
    }

    if ((Date.now() - cached.timestamp) >= UPSTREAM_CACHE_TTL_MS) {
      return null;
    }

    const groupedUpstreams = this._deserializeGroupedUpstreams(cached.groupedUpstreams);
    const successfulFormats = Number.isFinite(cached.successfulFormats)
      ? cached.successfulFormats
      : SUPPORTED_UPSTREAM_FORMATS.length;

    return this._buildRepositoryUpstreamState(groupedUpstreams, [], successfulFormats);
  }

  async _cacheRepositoryUpstreamState(workspace, repo, state) {
    const globalState = this.context && this.context.globalState;
    if (!globalState || typeof globalState.update !== "function") {
      return;
    }

    const groupedUpstreams = {};
    for (const format of SUPPORTED_UPSTREAM_FORMATS) {
      const upstreams = state.groupedUpstreams.get(format);
      if (Array.isArray(upstreams) && upstreams.length > 0) {
        groupedUpstreams[format] = upstreams;
      }
    }

    try {
      await globalState.update(this._getRepositoryUpstreamCacheKey(workspace, repo), {
        timestamp: Date.now(),
        successfulFormats: state.successfulFormats,
        groupedUpstreams,
      });
    } catch (error) {
      this._logRepositoryUpstreamCacheError("persist", workspace, repo, error);
    }
  }

  async _fetchRepositoryUpstreamState(workspace, repo, signal) {
    const groupedUpstreams = new Map();
    const failedFormats = [];
    let successfulFormats = 0;
    let apiKey = null;

    try {
      const credentialManager = new CredentialManager(this.context);
      apiKey = await credentialManager.getApiKey();
    } catch (error) {
      if (this._isAbortError(error) || signal?.aborted) {
        return this._buildRepositoryUpstreamState(groupedUpstreams, failedFormats, successfulFormats);
      }

      return this._buildRepositoryUpstreamState(
        groupedUpstreams,
        [...SUPPORTED_UPSTREAM_FORMATS],
        successfulFormats
      );
    }

    for (
      let index = 0;
      index < SUPPORTED_UPSTREAM_FORMATS.length;
      index += UPSTREAM_FETCH_BATCH_SIZE
    ) {
      if (signal?.aborted) {
        return this._buildRepositoryUpstreamState(groupedUpstreams, failedFormats, successfulFormats);
      }

      const batch = SUPPORTED_UPSTREAM_FORMATS.slice(
        index,
        index + UPSTREAM_FETCH_BATCH_SIZE
      );

      const batchResults = await Promise.all(
        batch.map((format) =>
          this._fetchFormatUpstreams(workspace, repo, format, apiKey, signal)
        )
      );

      if (signal?.aborted) {
        return this._buildRepositoryUpstreamState(groupedUpstreams, failedFormats, successfulFormats);
      }

      for (const result of batchResults) {
        if (result.status === "failed") {
          failedFormats.push(result.format);
          continue;
        }

        if (result.status !== "loaded") {
          continue;
        }

        successfulFormats += 1;

        if (result.upstreams.length === 0) {
          continue;
        }

        groupedUpstreams.set(result.format, result.upstreams);
      }
    }

    return this._buildRepositoryUpstreamState(groupedUpstreams, failedFormats, successfulFormats);
  }

  async _fetchFormatUpstreams(workspace, repo, format, apiKey, signal) {
    try {
      if (signal?.aborted) {
        return { format, status: "aborted", upstreams: [] };
      }

      const result = await this.api.makeRequest(
        `repos/${workspace}/${repo}/upstream/${format}/`,
        this._getRequestOptions(apiKey, signal)
      );

      if (signal?.aborted) {
        return { format, status: "aborted", upstreams: [] };
      }

      if (typeof result === "string") {
        if (this._isWarningWorthyFormatError(result)) {
          return { format, status: "failed", upstreams: [] };
        }
        return { format, status: "loaded", upstreams: [] };
      }

      if (!Array.isArray(result)) {
        return { format, status: "failed", upstreams: [] };
      }

      return {
        format,
        status: "loaded",
        upstreams: result.map((upstream) => ({ ...upstream, format })),
      };
    } catch (error) {
      if (this._isAbortError(error) || signal?.aborted) {
        return { format, status: "aborted", upstreams: [] };
      }

      const message = error && error.message ? error.message : "";
      if (!this._isWarningWorthyFormatError(message)) {
        return { format, status: "loaded", upstreams: [] };
      }

      return { format, status: "failed", upstreams: [] };
    }
  }

  _buildRepositoryUpstreamState(groupedUpstreams, failedFormats, successfulFormats) {
    const normalizedGrouped = new Map();
    const upstreams = [];
    let active = 0;

    for (const format of SUPPORTED_UPSTREAM_FORMATS) {
      const formatUpstreams = Array.isArray(groupedUpstreams.get(format))
        ? groupedUpstreams.get(format).slice()
        : [];

      if (formatUpstreams.length === 0) {
        continue;
      }

      formatUpstreams.sort((left, right) => {
        const leftName = typeof left.name === "string" ? left.name : "";
        const rightName = typeof right.name === "string" ? right.name : "";
        return leftName.localeCompare(rightName, undefined, { sensitivity: "base" });
      });

      const taggedUpstreams = formatUpstreams.map((upstream) => ({
        ...upstream,
        format: typeof upstream.format === "string" && upstream.format
          ? upstream.format
          : format,
      }));

      normalizedGrouped.set(format, taggedUpstreams);
      upstreams.push(...taggedUpstreams);
      active += taggedUpstreams.filter((upstream) => upstream.is_active !== false).length;
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
    const source = groupedUpstreams && typeof groupedUpstreams === "object"
      ? groupedUpstreams
      : {};

    for (const format of SUPPORTED_UPSTREAM_FORMATS) {
      if (Array.isArray(source[format])) {
        grouped.set(format, source[format].slice());
      }
    }

    return grouped;
  }

  _getRequestOptions(apiKey, signal) {
    return getUpstreamRequestOptions(apiKey, signal);
  }

  _isAbortError(error) {
    return isAbortError(error);
  }

  _isWarningWorthyFormatError(message) {
    return isWarningWorthyUpstreamFormatError(message);
  }
}

async function getAllUpstreamData(context, workspace, repo, options = {}) {
  const checker = new UpstreamChecker(context);
  return checker.getAllUpstreamData(workspace, repo, options);
}

async function getUpstreamDataForFormats(context, workspace, repo, formats, options = {}) {
  const checker = new UpstreamChecker(context);
  return checker.getUpstreamDataForFormats(workspace, repo, formats, options);
}

module.exports = {
  getAllUpstreamData,
  getUpstreamDataForFormats,
  getActiveUpstreamsFromRepositoryState,
  isBenignUpstreamFormatError,
  SUPPORTED_UPSTREAM_FORMATS,
  UpstreamChecker,
  UPSTREAM_FETCH_BATCH_SIZE,
  UPSTREAM_CACHE_TTL_MS,
};

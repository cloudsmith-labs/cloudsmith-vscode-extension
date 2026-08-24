// Copyright 2026 Cloudsmith Ltd. All rights reserved.

// Remediation helper - finds safe alternative versions of a package

const { SearchQueryBuilder } = require('./searchQueryBuilder');
const { apiEndpoint } = require('./apiEndpoint');
const { PaginatedFetch } = require('./paginatedFetch');
const { packageCollectionIdentity } = require('./collectionIdentity');
const { fromApiPackageRecord } = require('../domain/packageAdapters');

const SAFE_VERSION_PREVIEW_SIZE = 10;

class RemediationHelper {
  constructor(cloudsmithAPI) {
    this.api = cloudsmithAPI;
    this._paginatedFetch = new PaginatedFetch(cloudsmithAPI);
  }

  /**
   * Search for clean versions of a package within a specific repo.
   * Returns a bounded newest-version preview and authoritative pagination metadata.
   *
   * @param   {string} workspace  Workspace/owner slug.
   * @param   {string} repo       Repository slug.
   * @param   {string} packageName Package name.
   * @param   {string} format     Package format (e.g., 'python', 'npm').
   * @param   {Object} options     Compatibility and cancellation constraints.
   * @returns {Object} Safe-version preview result.
   */
  async findSafeVersions(workspace, repo, packageName, format, options = {}) {
    let settings;
    let query;
    let endpoint;
    try {
      settings = normalizedSafeVersionOptions(options);
      query = buildSafeVersionQuery(packageName, format, settings);
      endpoint = apiEndpoint(["packages", workspace, repo], { query: { sort: "-version" } });
    } catch (error) {
      return { success: false, versions: [], error };
    }

    const result = await this._paginatedFetch.fetchPage(endpoint, 1, SAFE_VERSION_PREVIEW_SIZE, query, {
      validate: isSafePackageArray,
      retry: "safe-read",
      signal: settings.signal,
      cancellationToken: settings.cancellationToken,
    });

    return safeVersionResult(result, workspace, repo, packageName, format);
  }

  /**
   * Search workspace-wide for clean versions of a package across all repos.
   * Returns a bounded newest-version preview and authoritative pagination metadata.
   *
   * @param   {string} workspace   Workspace/owner slug.
   * @param   {string} packageName Package name.
   * @param   {string} format      Package format (e.g., 'python', 'npm').
   * @param   {Object} options     Compatibility and cancellation constraints.
   * @returns {Object} Safe-version preview result.
   */
  async findSafeVersionsAcrossRepos(workspace, packageName, format, options = {}) {
    let settings;
    let query;
    let endpoint;
    try {
      settings = normalizedSafeVersionOptions(options);
      query = buildSafeVersionQuery(packageName, format, settings);
      endpoint = apiEndpoint(["packages", workspace], { query: { sort: "-version" } });
    } catch (error) {
      return { success: false, versions: [], error };
    }

    const result = await this._paginatedFetch.fetchPage(endpoint, 1, SAFE_VERSION_PREVIEW_SIZE, query, {
      validate: isSafePackageArray,
      retry: "safe-read",
      signal: settings.signal,
      cancellationToken: settings.cancellationToken,
    });
    return safeVersionResult(result, workspace, null, packageName, format);
  }
}

function normalizedSafeVersionOptions(value) {
  if (value === undefined || value === null) return Object.freeze(Object.create(null));
  try {
    if (
      typeof value !== "object"
      || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) {
      throw new Error("invalid option object");
    }
    const allowed = new Set([
      "cancellationToken",
      "currentVersion",
      "fixedVersions",
      "signal",
    ]);
    const keys = Reflect.ownKeys(value);
    if (
      keys.length > allowed.size
      || keys.some(key => typeof key !== "string" || !allowed.has(key))
    ) {
      throw new Error("invalid option fields");
    }
    const snapshot = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor)) throw new Error("invalid option property");
      snapshot[key] = key === "fixedVersions"
        ? snapshotFixedVersions(descriptor.value)
        : descriptor.value;
    }
    return Object.freeze(snapshot);
  } catch {
    throw new TypeError("Safe-version options must be a plain data object.");
  }
}

function snapshotFixedVersions(value) {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    throw new TypeError("Safe-version fixed-version constraints must be an array.");
  }
  const keys = Reflect.ownKeys(value);
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (
    !lengthDescriptor
    || !("value" in lengthDescriptor)
    || !Number.isSafeInteger(lengthDescriptor.value)
    || lengthDescriptor.value < 0
    || lengthDescriptor.value > SAFE_VERSION_PREVIEW_SIZE * 10
    || keys.some(key => key !== "length" && (
      typeof key !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(key)
    ))
  ) {
    throw new TypeError("Safe-version fixed-version constraints were invalid.");
  }
  const snapshot = [];
  for (let index = 0; index < lengthDescriptor.value; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor)) {
      throw new TypeError("Safe-version fixed-version constraints were invalid.");
    }
    snapshot.push(descriptor.value);
  }
  return Object.freeze(snapshot);
}

function buildSafeVersionQuery(packageName, format, options) {
  const settings = options && typeof options === "object" && !Array.isArray(options)
    ? options
    : {};
  const query = new SearchQueryBuilder()
    .exactName(packageName)
    .format(format);
  const currentVersion = boundedVersionConstraint(settings.currentVersion);
  if (currentVersion) query.versionGreaterThan(currentVersion);

  const fixedVersions = normalizedFixedVersions(settings.fixedVersions);
  for (const fixedVersion of fixedVersions) query.versionAtLeast(fixedVersion);

  return query
    .raw('vulnerabilities:0')
    .raw('NOT status:quarantined')
    .raw('deny_policy_violated:false')
    .build();
}

function normalizedFixedVersions(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new TypeError("Safe-version fixed-version constraints must be an array.");
  }
  const versions = [];
  const seen = new Set();
  for (const candidate of value) {
    const version = boundedVersionConstraint(candidate);
    if (!version) {
      throw new TypeError("Safe-version fixed-version constraints were invalid.");
    }
    if (seen.has(version)) continue;
    seen.add(version);
    versions.push(version);
  }
  return versions;
}

function boundedVersionConstraint(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" && typeof value !== "number") {
    throw new TypeError("Safe-version compatibility constraints were invalid.");
  }
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new TypeError("Safe-version compatibility constraints were invalid.");
  }
  const normalized = String(value);
  if (
    normalized.length === 0
    || normalized.length > 2048
    || normalized.trim() !== normalized
    || /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u.test(normalized)
  ) {
    throw new TypeError("Safe-version compatibility constraints were invalid.");
  }
  return normalized;
}

function safeVersionResult(result, workspace, repository, packageName, format) {
  if (result.error) {
    return {
      success: false,
      versions: [],
      error: result.error,
      complete: false,
      totalCount: null,
      absenceProven: false,
    };
  }
  const exactScope = result.data.every(pkg => (
    pkg.namespace === workspace
    && (repository === null || pkg.repository === repository)
    && pkg.name === packageName
    && pkg.format === format
  ));
  if (!exactScope) {
    return {
      success: false,
      versions: [],
      error: Object.freeze({
        kind: "invalid_response",
        message: "Cloudsmith returned safe-version results outside the requested package scope.",
      }),
      complete: false,
      totalCount: null,
      absenceProven: false,
    };
  }
  const identities = new Set();
  try {
    for (const pkg of result.data) {
      const identity = packageCollectionIdentity(fromApiPackageRecord(pkg, {
        expectedWorkspace: workspace,
        expectedRepository: repository,
      }));
      if (identities.has(identity)) throw new TypeError("duplicate package identity");
      identities.add(identity);
    }
  } catch {
    return {
      success: false,
      versions: [],
      error: Object.freeze({
        kind: "invalid_response",
        message: "Cloudsmith returned duplicate or invalid safe-version identities.",
      }),
      complete: false,
      totalCount: null,
      absenceProven: false,
    };
  }
  const totalCount = result.pagination.countAuthoritative ? result.pagination.count : null;
  return {
    success: true,
    versions: result.data,
    error: null,
    complete: result.pagination.page >= result.pagination.pageTotal,
    totalCount,
    absenceProven: totalCount === 0,
  };
}

function isRecordArray(value) {
  return Array.isArray(value) && value.every(item => (
    Boolean(item) && typeof item === "object" && !Array.isArray(item)
  ));
}

function isSafePackageArray(value) {
  return isRecordArray(value) && value.every(pkg => (
    typeof pkg.name === "string" && pkg.name.length > 0 && pkg.name.length <= 2048
    && typeof pkg.format === "string" && pkg.format.length > 0 && pkg.format.length <= 100
    && (typeof pkg.version === "string" || typeof pkg.version === "number")
    && String(pkg.version).length > 0 && String(pkg.version).length <= 2048
    && typeof pkg.repository === "string" && pkg.repository.length > 0 && pkg.repository.length <= 512
    && typeof pkg.namespace === "string" && pkg.namespace.length > 0 && pkg.namespace.length <= 512
    && typeof pkg.slug_perm === "string" && pkg.slug_perm.length > 0 && pkg.slug_perm.length <= 512
    && pkg.status_str === "Completed"
    && pkg.deny_policy_violated === false
  ));
}

module.exports = { RemediationHelper, SAFE_VERSION_PREVIEW_SIZE };

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
   * @returns {Object} Safe-version preview result.
   */
  async findSafeVersions(workspace, repo, packageName, format) {
    const qb = new SearchQueryBuilder();
    const query = qb.name(packageName).format(format).raw('NOT status:quarantined').raw('deny_policy_violated:false').build();
    let endpoint;
    try {
      endpoint = apiEndpoint(["packages", workspace, repo], { query: { sort: "-version" } });
    } catch (error) {
      return { success: false, versions: [], error };
    }

    const result = await this._paginatedFetch.fetchPage(endpoint, 1, SAFE_VERSION_PREVIEW_SIZE, query, {
      validate: isSafePackageArray,
      retry: "safe-read",
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
   * @returns {Object} Safe-version preview result.
   */
  async findSafeVersionsAcrossRepos(workspace, packageName, format) {
    const qb = new SearchQueryBuilder();
    const query = qb.name(packageName).format(format).raw('NOT status:quarantined').raw('deny_policy_violated:false').build();
    let endpoint;
    try {
      endpoint = apiEndpoint(["packages", workspace], { query: { sort: "-version" } });
    } catch (error) {
      return { success: false, versions: [], error };
    }

    const result = await this._paginatedFetch.fetchPage(endpoint, 1, SAFE_VERSION_PREVIEW_SIZE, query, {
      validate: isSafePackageArray,
      retry: "safe-read",
    });
    return safeVersionResult(result, workspace, null, packageName, format);
  }
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
  ));
}

module.exports = { RemediationHelper, SAFE_VERSION_PREVIEW_SIZE };

// Remediation helper - finds safe alternative versions of a package

const { SearchQueryBuilder } = require('./searchQueryBuilder');
const { apiEndpoint } = require('./apiEndpoint');

class RemediationHelper {
  constructor(cloudsmithAPI) {
    this.api = cloudsmithAPI;
  }

  /**
   * Search for clean versions of a package within a specific repo.
   * Returns array of package objects sorted by version descending, or [] on error.
   *
   * @param   {string} workspace  Workspace/owner slug.
   * @param   {string} repo       Repository slug.
   * @param   {string} packageName Package name.
   * @param   {string} format     Package format (e.g., 'python', 'npm').
   * @returns {Array} Array of package objects.
   */
  async findSafeVersions(workspace, repo, packageName, format) {
    const qb = new SearchQueryBuilder();
    const query = qb.name(packageName).format(format).raw('NOT status:quarantined').raw('deny_policy_violated:false').build();
    let endpoint;
    try {
      endpoint = apiEndpoint(["packages", workspace, repo], {
        query: { query, sort: "-version", page_size: 10 },
      });
    } catch (error) {
      return { success: false, versions: [], error };
    }

    const result = await this.api.get(endpoint, {
      responseType: "array",
      validate: isSafePackageArray,
      retry: "safe-read",
    });

    return result.ok
      ? { success: true, versions: result.data, error: null }
      : { success: false, versions: [], error: result.error };
  }

  /**
   * Search workspace-wide for clean versions of a package across all repos.
   * Returns array of package objects sorted by version descending, or [] on error.
   *
   * @param   {string} workspace   Workspace/owner slug.
   * @param   {string} packageName Package name.
   * @param   {string} format      Package format (e.g., 'python', 'npm').
   * @returns {Array} Array of package objects.
   */
  async findSafeVersionsAcrossRepos(workspace, packageName, format) {
    const qb = new SearchQueryBuilder();
    const query = qb.name(packageName).format(format).raw('NOT status:quarantined').raw('deny_policy_violated:false').build();
    let endpoint;
    try {
      endpoint = apiEndpoint(["packages", workspace], {
        query: { query, sort: "-version", page_size: 10 },
      });
    } catch (error) {
      return { success: false, versions: [], error };
    }

    const result = await this.api.get(endpoint, {
      responseType: "array",
      validate: isSafePackageArray,
      retry: "safe-read",
    });
    return result.ok
      ? { success: true, versions: result.data, error: null }
      : { success: false, versions: [], error: result.error };
  }
}

function isRecordArray(value) {
  return Array.isArray(value) && value.every(item => (
    Boolean(item) && typeof item === "object" && !Array.isArray(item)
  ));
}

function unwrapIdentifier(value) {
  if (typeof value === "string" && value.length > 0) {
    return value;
  }
  return value && typeof value === "object" && typeof value.value === "string" && value.value.length > 0
    ? value.value
    : null;
}

function isSafePackageArray(value) {
  return isRecordArray(value) && value.every(pkg => (
    typeof pkg.name === "string" && pkg.name.length > 0
    && typeof pkg.format === "string" && pkg.format.length > 0
    && (typeof pkg.version === "string" || typeof pkg.version === "number")
    && String(pkg.version).length > 0
    && typeof pkg.repository === "string" && pkg.repository.length > 0
    && typeof pkg.namespace === "string" && pkg.namespace.length > 0
    && Boolean(unwrapIdentifier(pkg.slug_perm || pkg.slug_perm_raw || pkg.slug))
  ));
}

module.exports = { RemediationHelper };

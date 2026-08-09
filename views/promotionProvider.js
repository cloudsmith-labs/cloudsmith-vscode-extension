// Cross-repository promotion provider.
// Shows a package's lifecycle across repos (dev -> staging -> production)
// and enables one-click promotion with automatic tagging.

const vscode = require("vscode");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { apiEndpoint, encodeApiPathSegment } = require("../util/apiEndpoint");
const { formatApiError } = require("../util/errorFormatter");
const { buildExactPackageQuery, packageMatchesExactIdentity } = require("../util/packageQuery");

class PromotionProvider {
  constructor(context) {
    this.context = context;
    this.api = new CloudsmithAPI(context);
  }

  _getPackageIdentifier(pkg) {
    if (!pkg || typeof pkg !== "object") {
      return null;
    }
    if (typeof pkg.slug_perm === "string") {
      return pkg.slug_perm;
    }
    if (pkg.slug_perm && typeof pkg.slug_perm === "object" && pkg.slug_perm.value) {
      return String(pkg.slug_perm.value);
    }
    if (typeof pkg.slug_perm_raw === "string") {
      return pkg.slug_perm_raw;
    }
    if (typeof pkg.slug === "string") {
      return pkg.slug;
    }
    return null;
  }

  _normalizePackage(pkg) {
    if (!pkg || typeof pkg !== "object") {
      return null;
    }

    return {
      name: pkg.name || null,
      version: pkg.version || null,
      format: pkg.format || null,
      repository: pkg.repository || null,
      slug_perm: this._getPackageIdentifier(pkg),
    };
  }

  _replacePlaceholders(template, sourceRepo, targetRepo, dateStr) {
    return template
      .replace(/\{target\}/g, targetRepo)
      .replace(/\{source\}/g, sourceRepo)
      .replace(/\{date\}/g, dateStr);
  }

  async _tagPackage(workspace, repo, identifier, tags, apiKey, label) {
    if (!identifier) {
      console.warn(`[Promotion] Skipping ${label} tags because package identifier was not available.`);
      return false;
    }

    let endpoint;
    try {
      endpoint = apiEndpoint(["packages", workspace, repo, identifier, "tag"]);
    } catch {
      console.warn(`[Promotion] Skipping ${label} tags because the package endpoint was invalid.`);
      return false;
    }
    const tagResult = await this.api.post(
      endpoint,
      { action: "add", tags },
      {
        apiKey,
        responseType: "object",
        validate: isPackageWriteRecord,
      }
    );

    if (!tagResult.ok) {
      console.warn(`[Promotion] Failed to apply ${label} tags: ${formatApiError(tagResult.error)}`);
      return false;
    }

    return true;
  }

  async _locateCopiedPackage(workspace, targetRepo, packageInfo, apiKey) {
    if (!packageInfo || !packageInfo.name || !packageInfo.version || !packageInfo.format) {
      return null;
    }

    let endpoint;
    try {
      const query = buildExactPackageQuery(packageInfo.name, packageInfo.version, packageInfo.format);
      endpoint = apiEndpoint(["packages", workspace, targetRepo], {
        query: { query, page_size: 100 },
      });
    } catch {
      return null;
    }
    const results = await this.api.get(
      endpoint,
      {
        apiKey,
        responseType: "array",
        validate: isPackageWriteArray,
        retry: "never",
      }
    );

    if (!results.ok) {
      console.warn(`[Promotion] Could not locate copied package: ${formatApiError(results.error)}`);
      return null;
    }

    if (results.data.length === 0) {
      console.warn(`[Promotion] Could not locate copied package in ${workspace}/${targetRepo}: no matching package found.`);
      return null;
    }

    const exactResults = results.data.filter(pkg => packageMatchesExactIdentity(pkg, packageInfo));
    if (exactResults.length === 0) {
      console.warn(
        `[Promotion] Could not locate copied package in ${workspace}/${targetRepo}: query returned packages but none matched ${packageInfo.name}@${packageInfo.version} (${packageInfo.format}).`
      );
      return null;
    }

    if (packageInfo.slug_perm) {
      const exactMatch = exactResults.find(pkg => this._getPackageIdentifier(pkg) === packageInfo.slug_perm);
      if (exactMatch) {
        return exactMatch;
      }
    }

    return exactResults.find(pkg => pkg.repository === targetRepo) || exactResults[0] || null;
  }

  /**
   * Get the configured promotion pipeline from settings.
   * Validates repo slugs against cached data and warns about invalid entries.
   * @returns {string[]} Ordered list of repository slugs.
   */
  getPipeline() {
    const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
    const pipeline = config.get("promotionPipeline") || [];
    if (pipeline.length > 0 && !this._pipelineValidated) {
      this._pipelineValidated = true;
      this._validatePipeline(pipeline);
    }
    return pipeline;
  }

  /**
   * Validate pipeline repo slugs against cached workspace data.
   * Shows a warning for any invalid entries.
   */
  async _validatePipeline(pipeline) {
    const defaultWs = vscode.workspace.getConfiguration("cloudsmith-vsc").get("defaultWorkspace");
    if (!defaultWs) {
      return;
    }
    let endpoint;
    try {
      endpoint = apiEndpoint(["repos", defaultWs], { query: { sort: "name" } });
    } catch {
      return;
    }
    const repos = await this.api.get(endpoint, {
      responseType: "array",
      validate: isRepositoryArray,
      retry: "safe-read",
    });
    if (!repos.ok) {
      return;
    }
    const validSlugs = new Set(repos.data.map(r => r.slug));
    const invalidSlugs = pipeline.filter(s => !validSlugs.has(s));
    if (invalidSlugs.length > 0) {
      vscode.window.showWarningMessage(
        `Promotion pipeline contains unknown repositories: ${invalidSlugs.join(", ")}. Check the cloudsmith-vsc.promotionPipeline setting.`
      );
    }
  }

  /**
   * Get the configured tag templates from settings.
   * @returns {Object} Tag templates with onPromote and onReceive arrays.
   */
  getTagTemplates() {
    const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
    return config.get("promotionTags") || {
      onPromote: ["promoted-to-{target}", "approved-{date}"],
      onReceive: ["promoted-from-{source}"],
    };
  }

  /**
   * Get promotion status for a package across all pipeline repos.
   *
   * @param   {string} workspace  Workspace slug.
   * @param   {string} name       Package name.
   * @param   {string} version    Package version.
   * @param   {string} format     Package format.
   * @returns {Object}            Structured status items and an optional error.
   */
  async getPromotionStatus(workspace, name, version, format) {
    const pipeline = this.getPipeline();
    if (pipeline.length === 0) {
      return { items: [], error: null };
    }
    if (!name || !version || !format) {
      return { items: [], error: new Error("Package identity is incomplete.") };
    }

    // Search workspace-wide for this package name+version
    let endpoint;
    try {
      const query = buildExactPackageQuery(name, version, format);
      endpoint = apiEndpoint(["packages", workspace], {
        query: { query, page_size: 100 },
      });
    } catch (error) {
      return { items: [], error };
    }
    const results = await this.api.get(
      endpoint,
      { responseType: "array", validate: isPromotionStatusArray, retry: "never" }
    );

    if (!results.ok) {
      return { items: [], error: results.error };
    }

    // Build a map of repo slug -> package data
    const repoMap = new Map();
    const exactResults = results.data.filter(pkg =>
      packageMatchesExactIdentity(pkg, { name, version, format })
    );
    for (const pkg of exactResults) {
      repoMap.set(pkg.repository, pkg);
    }

    // Map pipeline repos to their status
    return { items: pipeline.map(repo => {
      const pkg = repoMap.get(repo) || null;
      return {
        repo,
        found: !!pkg,
        status: pkg ? (pkg.status_str || "Unknown") : "Not present",
        quarantined: pkg ? (pkg.status_str === "Quarantined") : false,
        policyViolated: pkg ? (pkg.policy_violated || false) : false,
        pkg,
      };
    }), error: null };
  }

  /**
   * Promote a package from one repo to another with tagging.
   *
   * @param   {string} workspace   Workspace slug.
   * @param   {string} sourceRepo  Source repository slug.
   * @param   {string} slugPerm    Package slug_perm identifier.
   * @param   {string} targetRepo  Target repository slug.
   * @returns {boolean}            True if promotion succeeded.
   */
  async promote(workspace, sourceRepo, slugPerm, targetRepo) {
    const credentialManager = require("../util/credentialManager");
    const cm = new credentialManager.CredentialManager(this.context);
    const apiKey = await cm.getApiKey();
    const templates = this.getTagTemplates();
    const dateStr = new Date().toISOString().split("T")[0]; // YYYY-MM-DD

    let sourceEndpoint;
    let copyEndpoint;
    try {
      sourceEndpoint = apiEndpoint(["packages", workspace, sourceRepo, slugPerm]);
      copyEndpoint = apiEndpoint(["packages", workspace, sourceRepo, slugPerm, "copy"]);
      encodeApiPathSegment(targetRepo);
    } catch (error) {
      return { success: false, error };
    }
    const sourcePackageResult = await this.api.get(sourceEndpoint, {
      apiKey,
      responseType: "object",
      validate: isPackageIdentityRecord,
      retry: "never",
    });
    const sourcePackage = this._normalizePackage(
      sourcePackageResult.ok ? sourcePackageResult.data : null
    );

    // Step 1: Copy the package to the target repo
    const copyPayload = {
      destination: `${workspace}/${targetRepo}`,
    };

    const copyResult = await this.api.post(copyEndpoint, copyPayload, {
      apiKey,
      responseType: "object",
      validate: isPackageWriteRecord,
    });

    if (!copyResult.ok) {
      console.warn(`[Promotion] Copy failed: ${formatApiError(copyResult.error)}`);
      return { success: false, error: copyResult.error };
    }

    if (templates.onPromote && templates.onPromote.length > 0) {
      const tags = templates.onPromote.map(tmpl =>
        this._replacePlaceholders(tmpl, sourceRepo, targetRepo, dateStr)
      );
      await this._tagPackage(workspace, sourceRepo, slugPerm, tags, apiKey, "onPromote");
    }

    if (templates.onReceive && templates.onReceive.length > 0) {
      const copiedPackage = this._normalizePackage(copyResult.data) || sourcePackage;
      const locatedPackage = await this._locateCopiedPackage(
        workspace,
        targetRepo,
        copiedPackage,
        apiKey
      );

      if (locatedPackage) {
        const tags = templates.onReceive.map(tmpl =>
          this._replacePlaceholders(tmpl, sourceRepo, targetRepo, dateStr)
        );
        const identifier = this._getPackageIdentifier(locatedPackage);
        await this._tagPackage(workspace, targetRepo, identifier, tags, apiKey, "onReceive");
      } else {
        console.warn(
          `[Promotion] Skipping onReceive tags for ${workspace}/${targetRepo} because the copied package could not be located.`
        );
      }
    }

    return { success: true, error: null };
  }
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isRecordArray(value) {
  return Array.isArray(value) && value.every(isRecord);
}

function packageIdentifier(value) {
  if (typeof value === "string" && value.length > 0) {
    return value;
  }
  return value && typeof value === "object" && typeof value.value === "string" && value.value.length > 0
    ? value.value
    : null;
}

function isPackageIdentityRecord(value) {
  return isRecord(value)
    && typeof value.name === "string" && value.name.length > 0
    && (typeof value.version === "string" || typeof value.version === "number")
    && String(value.version).length > 0
    && typeof value.format === "string" && value.format.length > 0;
}

function isPackageWriteRecord(value) {
  return isPackageIdentityRecord(value)
    && Boolean(packageIdentifier(value.slug_perm || value.slug_perm_raw || value.slug));
}

function isPackageWriteArray(value) {
  return Array.isArray(value) && value.every(isPackageWriteRecord);
}

function isPromotionStatusArray(value) {
  return Array.isArray(value) && value.every(pkg => (
    isPackageIdentityRecord(pkg)
    && typeof pkg.repository === "string"
    && pkg.repository.length > 0
  ));
}

function isRepositoryArray(value) {
  return isRecordArray(value) && value.every(repo => (
    typeof repo.slug === "string" && repo.slug.length > 0
  ));
}

module.exports = { PromotionProvider };

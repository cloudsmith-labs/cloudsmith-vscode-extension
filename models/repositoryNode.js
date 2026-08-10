// Repo node treeview

const vscode = require("vscode");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { apiEndpoint } = require("../util/apiEndpoint");
const upstreamChecker = require("../util/upstreamChecker");
const {
  normalizeUpstreamFormat,
  SUPPORTED_UPSTREAM_FORMATS,
} = require("../util/upstreamFormats");
const UpstreamIndicatorNode = require("./upstreamIndicatorNode");
const { activeFilters } = require("../util/filterState");
const InfoNode = require("./infoNode");
const { EntitlementSummaryNode } = require("./entitlementNode");
const {
  captureAccount,
  isAccountCurrent,
  resolveConnectionManager,
} = require("../util/accountOperation");

class RepositoryNode {
  constructor(repo, workspace, context, options = {}) {
    this.context = context;
    this._connectionManager = resolveConnectionManager(context, options.connectionManager);
    this._createCloudsmithAPI = options.createCloudsmithAPI
      || (() => new CloudsmithAPI(this.context));
    this._upstreamChecker = options.upstreamChecker || upstreamChecker;
    this.slug = repo.slug;
    this.slug_perm = repo.slug_perm;
    this.name = repo.name;
    this.workspace = workspace;
    this.storageRegion = repo.storage_region || repo.region || null;
  }

  /** Get the active filter from the module-level singleton Map. */
  _getActiveFilter() {
    return activeFilters.get(`${this.workspace}/${this.slug}`) || null;
  }

  _getStorageRegionLabel(region, depth = 0) {
    if (region == null) {
      return null;
    }

    if (
      typeof region === "string" ||
      typeof region === "number" ||
      typeof region === "boolean"
    ) {
      return String(region);
    }

    if (typeof region !== "object") {
      return null;
    }

    if (depth >= 3) {
      try {
        return JSON.stringify(region);
      } catch {
        return "Unknown";
      }
    }

    const directKeys = ["name", "label", "slug", "value"];
    for (const key of directKeys) {
      if (region[key] != null) {
        const directLabel = this._getStorageRegionLabel(region[key], depth + 1);
        if (directLabel) {
          return directLabel;
        }
      }
    }

    const nestedKeys = ["region", "storage_region", "details", "location"];
    for (const key of nestedKeys) {
      if (region[key] != null) {
        const nestedLabel = this._getStorageRegionLabel(region[key], depth + 1);
        if (nestedLabel) {
          return nestedLabel;
        }
      }
    }

    for (const value of Object.values(region)) {
      if (value != null && typeof value === "object") {
        const nestedLabel = this._getStorageRegionLabel(value, depth + 1);
        if (nestedLabel) {
          return nestedLabel;
        }
      }
    }

    try {
      return JSON.stringify(region);
    } catch {
      return "Unknown";
    }
  }

  getTreeItem() {
    const repo = this.name;
    const activeFilter = this._getActiveFilter();
    const filterLabel = activeFilter
      ? `filtered: ${activeFilter.label || activeFilter}`
      : undefined;

    return {
      label: repo,
      description: filterLabel,
      collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
      contextValue: activeFilter ? "repositoryFiltered" : "repository",
    };
  }

  async getPackages() {
    const account = captureAccount(this._connectionManager);
    if (!account) return [];
    const cloudsmithAPI = this._createCloudsmithAPI();
    let packages = '';
    

    let workspace = this.workspace;
    let repo = this.slug;
    let groupContext = { "repo": repo, "workspace": workspace  };

    const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
    const maxPackages = await config.get("showMaxPackages"); // get legacy app setting from configuration settings
    const groupByPackageGroup = await config.get("groupByPackageGroups");
    if (!isAccountCurrent(this._connectionManager, account)) return [];

    const activeFilter = this._getActiveFilter();
    const filterQuery = activeFilter ? (activeFilter.query || activeFilter) : null;
    let apiFailed = false;
    try {
      const query = {
        sort: groupByPackageGroup ? "-last_push" : "-date",
        page_size: maxPackages,
        ...(filterQuery ? { query: filterQuery } : {}),
      };
      if (!groupByPackageGroup) {
        const result = await cloudsmithAPI.get(
          apiEndpoint(["packages", workspace, repo], { query }),
          { responseType: "array", validate: isPackageArray, retry: "safe-read" }
        );
        if (result.ok) {
          packages = result.data;
        } else {
          apiFailed = true;
          packages = [];
        }
      } else {
        const result = await cloudsmithAPI.get(
          apiEndpoint(["packages", workspace, repo, "groups"], { query }),
          {
            responseType: "object",
            validate: value => isPackageGroupArray(value.results),
            retry: "safe-read",
          }
        );
        if (result.ok) {
          packages = result.data.results;
        } else {
          apiFailed = true;
          packages = [];
        }
      }
    } catch {
      if (!isAccountCurrent(this._connectionManager, account)) return [];
      apiFailed = true;
      packages = [];
    }
    if (!isAccountCurrent(this._connectionManager, account)) return [];
    this._lastApiFailed = apiFailed;

    const PackageNodes = [];
    if (packages && packages.length > 0) {
      for (const pkg of packages) {
        if (!groupByPackageGroup) {
          const packageNode = require("./packageNode");
          let packageNodeInst = new packageNode(pkg, this.context, {
            connectionManager: this._connectionManager,
          });
          PackageNodes.push(packageNodeInst);
        } else {
          const packageGroupsNode = require("./packageGroupsNode");
          const groupPkg = { ...pkg, ...groupContext };
          const packageGroupNodeInst = new packageGroupsNode(groupPkg, this.context);
          PackageNodes.push(packageGroupNodeInst);
        }
      }
    }
    return PackageNodes;
  }

  /**
   * Infer relevant formats from the loaded package list and fetch upstream configs
   * only for those formats as a hint. Repository-level configured upstream
   * counts must reconcile against the full all-format path unless the inferred
   * set is known to cover every supported upstream format.
   *
   * @returns {Array} Array of upstream config objects (may be empty).
   */
  async getUpstreams(packageNodes = []) {
    const account = captureAccount(this._connectionManager);
    if (!account) return [];
    const inferredFormats = this._inferUpstreamFormats(packageNodes);
    if (inferredFormats.length === 0) {
      const result = await this._upstreamChecker.getAllUpstreamData(
        this.context,
        this.workspace,
        this.slug,
        { account, connectionManager: this._connectionManager }
      );
      return isAccountCurrent(this._connectionManager, account)
        ? this._getUpstreamList(result)
        : [];
    }

    const hintedResult = await this._upstreamChecker.getUpstreamDataForFormats(
      this.context,
      this.workspace,
      this.slug,
      inferredFormats,
      { account, connectionManager: this._connectionManager }
    );
    if (!isAccountCurrent(this._connectionManager, account)) return [];

    if (this._hasCompleteUpstreamCoverage(inferredFormats)) {
      return this._getUpstreamList(hintedResult);
    }

    const result = await this._upstreamChecker.getAllUpstreamData(
      this.context,
      this.workspace,
      this.slug,
      { account, connectionManager: this._connectionManager }
    );
    return isAccountCurrent(this._connectionManager, account)
      ? this._getUpstreamList(result)
      : [];
  }

  _getUpstreamList(result) {
    if (!result || !Array.isArray(result.upstreams)) {
      return [];
    }

    return result.upstreams;
  }

  _hasCompleteUpstreamCoverage(formats) {
    return Array.isArray(formats) && formats.length === SUPPORTED_UPSTREAM_FORMATS.length;
  }

  _inferUpstreamFormats(packageNodes) {
    if (!Array.isArray(packageNodes) || packageNodes.length === 0) {
      return [];
    }

    const formats = new Set();
    for (const node of packageNodes) {
      this._addInferredFormat(formats, node && node.format);

      if (Array.isArray(node && node.formats)) {
        for (const format of node.formats) {
          this._addInferredFormat(formats, format);
        }
      }
    }

    return SUPPORTED_UPSTREAM_FORMATS.filter((format) => formats.has(format));
  }

  _addInferredFormat(target, value) {
    const normalized = normalizeUpstreamFormat(value);
    if (normalized) {
      target.add(normalized);
    }
  }

  /**
   * Fetch entitlement tokens for this repository.
   * @returns {Array} Array of entitlement objects.
   */
  async getEntitlements() {
    const account = captureAccount(this._connectionManager);
    if (!account) return [];
    const cloudsmithAPI = this._createCloudsmithAPI();
    let endpoint;
    try {
      endpoint = apiEndpoint(["entitlements", this.workspace, this.slug], {
        query: { page_size: 50 },
      });
    } catch {
      throw new Error("The entitlement endpoint was invalid.");
    }
    const result = await cloudsmithAPI.get(endpoint, {
      responseType: "array",
      validate: isEntitlementArray,
      retry: "safe-read",
    });
    if (!isAccountCurrent(this._connectionManager, account)) return [];
    if (!result.ok) {
      throw result.error;
    }
    return result.data;
  }

  async getChildren() {
    const account = captureAccount(this._connectionManager);
    if (!account) return [];
    const packages = await this.getPackages();
    if (!isAccountCurrent(this._connectionManager, account)) return [];
    const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
    const showEntitlements = config.get("showEntitlements");

    const children = [];

    // Fetch upstreams lazily (only when repo is expanded)
    if (packages.length > 0) {
      const upstreams = await this.getUpstreams(packages);
      if (!isAccountCurrent(this._connectionManager, account)) return [];
      if (upstreams.length > 0) {
        children.push(new UpstreamIndicatorNode(
          upstreams,
          {
            workspace: this.workspace,
            slug: this.slug,
            name: this.name,
          },
          this.context
        ));
      }
    }

    if (this.storageRegion) {
      const regionLabel = this._getStorageRegionLabel(this.storageRegion);

      children.push({
        getTreeItem: () => ({
          label: "Storage Region",
          description: regionLabel,
          collapsibleState: vscode.TreeItemCollapsibleState.None,
          contextValue: "repoDetail",
          iconPath: new vscode.ThemeIcon("globe"),
        }),
        getChildren: () => [],
      });
    }

    // Entitlement tokens (Phase 12)
    if (showEntitlements) {
      try {
        const entitlements = await this.getEntitlements();
        if (!isAccountCurrent(this._connectionManager, account)) return [];
        if (entitlements.length > 0) {
          children.push(new EntitlementSummaryNode(entitlements, this.context));
        }
      } catch (e) {
        if (!isAccountCurrent(this._connectionManager, account)) return [];
        children.push(new InfoNode(
          "Entitlements: failed to load",
          "",
          e.message || "An error occurred loading entitlement tokens.",
          "warning"
        ));
      }
    }

    if (packages.length === 0) {
      const activeFilter = this._getActiveFilter();
      let placeholderNode;
      if (this._lastApiFailed) {
        placeholderNode = new InfoNode(
          "Failed to load packages",
          "Check your connection and try refreshing",
          "The Cloudsmith API returned an error when loading packages for this repository.",
          "warning"
        );
      } else if (activeFilter) {
        const filterLabel = activeFilter.label || "custom query";
        placeholderNode = new InfoNode(
          "No packages match filter",
          filterLabel,
          "Click to change or clear the filter",
          "filter",
          undefined,
          { command: "cloudsmith-vsc.changeFilter", title: "Change Filter", arguments: [this] }
        );
      } else {
        placeholderNode = new InfoNode(
          "Repository is empty",
          "",
          "This repository does not contain any packages.",
          "info"
        );
      }
      children.push(placeholderNode);
    }

    // packages are already PackageNode or PackageGroupsNode instances from getPackages()
    // Push them directly — do NOT re-wrap in new packageNode(item)
    for (const node of packages) {
      children.push(node);
    }

    return isAccountCurrent(this._connectionManager, account) ? children : [];
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

function isPackageArray(value) {
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

function isPackageGroupArray(value) {
  return isRecordArray(value) && value.every(group => (
    typeof group.name === "string"
    && group.name.length > 0
    && [group.format, group.package_format, group.packageFormat]
      .some(format => typeof format === "string" && format.length > 0)
  ));
}

function isEntitlementArray(value) {
  return isRecordArray(value) && value.every(entitlement => (
    typeof entitlement.name === "string"
    && entitlement.name.trim().length > 0
    && (entitlement.is_active === undefined || typeof entitlement.is_active === "boolean")
  ));
}

module.exports = RepositoryNode;

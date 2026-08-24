// Copyright 2026 Cloudsmith Ltd. All rights reserved.

// Repo node treeview

const vscode = require("vscode");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { apiEndpoint } = require("../util/apiEndpoint");
const { PaginatedFetch, replaceCollectionItems } = require("../util/paginatedFetch");
const { formatApiError } = require("../util/errorFormatter");
const { fromApiPackageRecord } = require("../domain/packageAdapters");
const {
  entitlementCollectionIdentity,
  packageCollectionIdentity,
  packageGroupCollectionIdentity,
} = require("../util/collectionIdentity");
const { sanitizeSafeInventoryUpstream } = require("../util/upstreamChecker");
const UpstreamIndicatorNode = require("./upstreamIndicatorNode");
const { activeFilters } = require("../util/filterState");
const InfoNode = require("./infoNode");
const { EntitlementSummaryNode } = require("./entitlementNode");
const RepositoryLoadMoreNode = require("./repositoryLoadMoreNode");
const { RepositoryTerminalNode } = require("./repositoryTerminalNode");
const {
  captureAccount,
  isAccountCurrent,
  resolveConnectionManager,
} = require("../util/accountOperation");
const { inheritSelection, markSelection } = require("../util/selectionProvenance");

const MAX_COLLECTION_PAGES = 20;
const MAX_COLLECTION_REQUESTS = 24;
const MAX_COLLECTION_ITEMS = 600;
const ENTITLEMENT_PAGE_SIZE = 50;
const MAX_NAME_LENGTH = 2048;
const MAX_FORMAT_LENGTH = 100;
const MAX_IDENTITY_LENGTH = 512;
const MAX_OPTIONAL_STRING_LENGTH = 4096;
const COLLECTION_TERMINATIONS = new Set([
  "cancelled",
  "duplicate_or_invalid_identity",
  "exhausted",
  "invalid_continuation",
  "invalid_pagination",
  "invalid_request",
  "item_limit",
  "page_batch",
  "page_limit",
  "request_failed",
  "request_limit",
]);

class RepositoryNode {
  constructor(repo, workspace, context, options = {}) {
    if (
      !options.upstreamInventory
      || typeof options.upstreamInventory.getAllUpstreamData !== "function"
    ) {
      throw new TypeError("RepositoryNode requires an upstream inventory facade.");
    }
    this.context = context;
    this._connectionManager = resolveConnectionManager(context, options.connectionManager);
    markSelection(this, this._connectionManager);
    this._createCloudsmithAPI = options.createCloudsmithAPI
      || (() => new CloudsmithAPI(this.context));
    this._createPaginatedFetch = options.createPaginatedFetch
      || (api => new PaginatedFetch(api));
    this._upstreamInventory = options.upstreamInventory;
    this._requestRefresh = typeof options.requestRefresh === "function"
      ? options.requestRefresh
      : () => {};
    this._vulnerabilityStateService = options.vulnerabilityStateService || null;
    this._registerVulnerabilitySummary = typeof options.registerVulnerabilitySummary === "function"
      ? options.registerVulnerabilitySummary
      : () => {};
    this._unregisterVulnerabilitySummaries = typeof options.unregisterVulnerabilitySummaries === "function"
      ? options.unregisterVulnerabilitySummaries
      : () => {};
    this._withProgress = options.withProgress || ((progressOptions, task) => (
      vscode.window.withProgress(progressOptions, task)
    ));
    this.slug = repo.slug;
    this.slug_perm = repo.slug_perm;
    this.name = repo.name;
    this.workspace = workspace;
    this.storageRegion = repo.storage_region || repo.region || null;
    this._disposed = false;
    this._generation = 0;
    this._lifecycleController = new AbortController();
    this._packageDescriptor = null;
    this._packageState = createEmptyPackageState();
    this._activePackageLoad = null;
    this._metadataPromise = null;
    this._metadataChildren = [];
    this._metadataLoaded = false;
    this._entitlementNodes = new WeakSet();
  }

  invalidate() {
    if (this._disposed) return;
    this._unregisterVulnerabilitySummaries(this);
    this._disposed = true;
    this._generation += 1;
    this._lifecycleController.abort();
    this._activePackageLoad = null;
    this._metadataPromise = null;
    this._metadataChildren = [];
    this._metadataLoaded = false;
    this._entitlementNodes = new WeakSet();
  }

  dispose() {
    this.invalidate();
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
    if (this._disposed) return [];
    const descriptor = this._readPackageDescriptor();
    this._ensurePackageDescriptor(descriptor);
    if (!this._packageState.initialized && !this._activePackageLoad) {
      await this._startPackageLoad(descriptor, null, false);
    } else if (!this._packageState.initialized && this._activePackageLoad) {
      await this._activePackageLoad.promise;
    }
    return this._disposed ? [] : this._packageState.nodes;
  }

  loadMorePackages() {
    if (this._disposed || !this._packageState.initialized || !this._packageState.continuation) {
      return Promise.resolve();
    }
    if (this._activePackageLoad) {
      return this._activePackageLoad.promise;
    }
    const descriptor = this._packageDescriptor;
    if (!descriptor) return Promise.resolve();
    return this._startPackageLoad(descriptor, this._packageState.continuation, true);
  }

  isPackageLoadActive() {
    return Boolean(!this._disposed && this._activePackageLoad);
  }

  _readPackageDescriptor() {
    const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
    const account = captureAccount(this._connectionManager);
    const pageSize = normalizePageSize(config.get("showMaxPackages"));
    const groupByPackageGroup = config.get("groupByPackageGroups") === true;
    const showEntitlements = config.get("showEntitlements") === true;
    const activeFilter = this._getActiveFilter();
    const filterQuery = activeFilter ? String(activeFilter.query || activeFilter) : null;
    const mode = groupByPackageGroup ? "groups" : "packages";
    const sort = groupByPackageGroup ? "-last_push" : "-date";
    const key = JSON.stringify([
      account ? account.activationId : null,
      account ? account.accountEpoch : null,
      this.workspace,
      this.slug,
      mode,
      sort,
      pageSize,
      filterQuery,
      showEntitlements,
    ]);
    return Object.freeze({ key, mode, sort, pageSize, filterQuery, showEntitlements });
  }

  _ensurePackageDescriptor(descriptor) {
    if (this._packageDescriptor?.key === descriptor.key) return;
    this._unregisterVulnerabilitySummaries(this);
    this._generation += 1;
    this._lifecycleController.abort();
    this._lifecycleController = new AbortController();
    this._packageDescriptor = descriptor;
    this._packageState = createEmptyPackageState();
    this._activePackageLoad = null;
    this._metadataPromise = null;
    this._metadataChildren = [];
    this._metadataLoaded = false;
    this._entitlementNodes = new WeakSet();
  }

  _startPackageLoad(descriptor, resume, showProgress) {
    if (this._activePackageLoad) return this._activePackageLoad.promise;
    const account = captureAccount(this._connectionManager);
    if (!account || this._disposed || this._packageDescriptor?.key !== descriptor.key) {
      return Promise.resolve();
    }
    const operation = Object.freeze({
      generation: this._generation,
      account,
      descriptor,
      resume,
    });
    const task = (_progress, cancellationToken) => this._fetchPackageBatch(
      operation,
      cancellationToken
    );
    const promise = Promise.resolve().then(() => (
      showProgress
        ? this._withProgress({
          location: vscode.ProgressLocation.Notification,
          title: descriptor.mode === "groups"
            ? "Loading more package groups..."
            : "Loading more packages...",
          cancellable: true,
        }, task)
        : task({ report() {} }, null)
    )).finally(() => {
      if (this._activePackageLoad?.operation === operation) {
        this._activePackageLoad = null;
        if (showProgress && this._isOperationCurrent(operation)) {
          this._requestRefresh(this);
        }
      }
    });
    this._activePackageLoad = Object.freeze({ operation, promise });
    if (showProgress) this._requestRefresh(this);
    return promise;
  }

  async _fetchPackageBatch(operation, cancellationToken) {
    const { descriptor, resume } = operation;
    let endpoint;
    try {
      endpoint = apiEndpoint(
        descriptor.mode === "groups"
          ? ["packages", this.workspace, this.slug, "groups"]
          : ["packages", this.workspace, this.slug],
        { query: { sort: descriptor.sort } }
      );
    } catch {
      this._commitPackageFailure(operation, localCollectionFailure(
        "invalid_request",
        "The repository package endpoint was invalid."
      ));
      return;
    }

    let result;
    try {
      const paginatedFetch = this._createPaginatedFetch(this._createCloudsmithAPI());
      const collectionOptions = {
        pageSize: descriptor.pageSize,
        query: descriptor.filterQuery,
        maxPages: MAX_COLLECTION_PAGES,
        maxRequests: MAX_COLLECTION_REQUESTS,
        maxItems: MAX_COLLECTION_ITEMS,
        pageBatchLimit: 1,
        descriptor: descriptor.key,
        resume,
        ...(resume ? { knownIdentities: new Set(this._packageState.resultKeys) } : {}),
        retry: "never",
        signal: this._lifecycleController.signal,
        cancellationToken,
      };
      if (descriptor.mode === "groups") {
        Object.assign(collectionOptions, {
          responseType: "object",
          validate: isPackageGroupArray,
          validateResponse: isPackageGroupResponse,
          extractItems: response => response.results,
          canonicalIdentity: group => packageGroupCollectionIdentity(
            this.workspace,
            this.slug,
            canonicalizePackageGroup(group)
          ),
        });
      } else {
        Object.assign(collectionOptions, {
          validate: value => isPackageArray(value, this.workspace, this.slug),
          canonicalIdentity: pkg => {
            const canonical = canonicalizeRepositoryPackage(pkg, this.workspace, this.slug);
            return canonical ? packageCollectionIdentity(canonical) : null;
          },
        });
      }
      result = await paginatedFetch.fetchCollection(endpoint, collectionOptions);
    } catch {
      this._commitPackageFailure(operation, localCollectionFailure(
        "unexpected",
        "The package collection could not be loaded."
      ), { preserveContinuation: Boolean(resume) });
      return;
    }

    if (!this._isOperationCurrent(operation)) return;
    if (!isCollectionResult(result)) {
      this._commitPackageFailure(operation, localCollectionFailure(
        "invalid_response",
        "Cloudsmith returned an invalid package collection."
      ));
      return;
    }
    if (result.cancelled) {
      // Cancellation still consumes a dispatched request. Commit the returned
      // continuation so repeated retries cannot reset the cumulative budget.
      this._commitPackageResult(operation, result);
      return;
    }
    this._commitPackageResult(operation, result);
  }

  _commitPackageResult(operation, result) {
    if (!this._isOperationCurrent(operation)) return;
    const descriptor = operation.descriptor;
    const previous = this._packageState;
    const keys = new Set(previous.resultKeys);
    const appendedNodes = [];
    let duplicateCount = result.duplicateCount || 0;
    try {
      for (const item of result.items) {
        const canonical = descriptor.mode === "groups"
          ? canonicalizePackageGroup(item)
          : canonicalizeRepositoryPackage(item, this.workspace, this.slug);
        if (!canonical) throw new Error("invalid collection item");
        const key = descriptor.mode === "groups"
          ? packageGroupCollectionIdentity(this.workspace, this.slug, canonical)
          : packageCollectionIdentity(canonical);
        if (keys.has(key)) {
          duplicateCount += 1;
          continue;
        }
        keys.add(key);
        appendedNodes.push(this._createPackageNode(canonical, descriptor.mode));
      }
    } catch {
      this._commitPackageFailure(operation, localCollectionFailure(
        "invalid_response",
        "Cloudsmith returned an invalid package record."
      ));
      return;
    }

    const nodes = [...previous.nodes, ...appendedNodes];
    const crossPageDuplicate = duplicateCount > (result.duplicateCount || 0);
    const complete = result.complete === true && !crossPageDuplicate;
    const continuation = complete || crossPageDuplicate
      ? null
      : validContinuation(result.continuation, descriptor.key, nodes.length, result);
    // A continuation failure is retryable. Once that exact page succeeds, the
    // prior failure no longer describes the collection and must not keep a
    // subsequently complete result labelled as partial.
    const failures = [...result.failures];
    if (crossPageDuplicate) {
      failures.push(localCollectionFailure(
        "duplicate_identity",
        "Cloudsmith returned a package identity that was already loaded."
      ));
    }
    const invalidContinuation = !complete
      && !crossPageDuplicate
      && ((result.continuation && !continuation)
        || (result.termination === "page_batch" && !continuation));
    if (invalidContinuation) {
      failures.push(localCollectionFailure(
        "invalid_continuation",
        "Cloudsmith returned contradictory package continuation metadata."
      ));
    }
    const capReached = !complete && !continuation && isCollectionCapReached(result, nodes.length);
    this._packageState = Object.freeze({
      initialized: true,
      nodes: Object.freeze(nodes),
      resultKeys: Object.freeze([...keys]),
      pagination: result.pagination,
      complete,
      partial: !complete && nodes.length > 0,
      continuation,
      failures: Object.freeze(failures),
      pageCount: result.pageCount,
      requestCount: result.requestCount,
      duplicateCount,
      termination: crossPageDuplicate
        ? "duplicate_identity"
        : invalidContinuation ? "invalid_continuation" : result.termination,
      capReached,
    });
  }

  _commitPackageFailure(operation, failure, options = {}) {
    if (!this._isOperationCurrent(operation)) return;
    const previous = this._packageState;
    this._packageState = Object.freeze({
      ...previous,
      initialized: true,
      complete: false,
      partial: previous.nodes.length > 0,
      continuation: options.preserveContinuation ? operation.resume : null,
      failures: Object.freeze([...previous.failures, failure]),
      termination: failure.kind,
    });
  }

  _createPackageNode(item, mode) {
    if (mode === "groups") {
      const PackageGroupsNode = require("./packageGroupsNode");
      const node = new PackageGroupsNode({
        ...item,
        repo: this.slug,
        workspace: this.workspace,
      }, this.context);
      return inheritSelection(node, this);
    }
    const PackageNode = require("./packageNode");
    return new PackageNode(item, this.context, {
      connectionManager: this._connectionManager,
      vulnerabilityStateService: this._vulnerabilityStateService,
      lifecycleSignal: this._lifecycleController.signal,
      registerVulnerabilitySummary: (identity, element, packageNode) => (
        this._registerVulnerabilitySummary(identity, element, {
          repositoryNode: this,
          packageNode,
          generation: this._generation,
        })
      ),
    });
  }

  ownsVulnerabilitySummary(owner) {
    return Boolean(
      !this._disposed
      && owner
      && owner.repositoryNode === this
      && owner.generation === this._generation
      && this._packageState.nodes.includes(owner.packageNode)
      && !this._lifecycleController.signal.aborted
    );
  }

  ownsPackageSelection(selection) {
    return Boolean(
      !this._disposed
      && selection
      && this._packageState.nodes.includes(selection)
      && !this._lifecycleController.signal.aborted
    );
  }

  ownsEntitlementSelection(selection) {
    return Boolean(
      !this._disposed
      && selection
      && this._entitlementNodes.has(selection)
      && !this._lifecycleController.signal.aborted
    );
  }

  ownsRepositoryContextSelection(selection) {
    return Boolean(
      !this._disposed
      && selection
      && (selection === this || this._metadataChildren.includes(selection))
      && !this._lifecycleController.signal.aborted
    );
  }

  _isOperationCurrent(operation) {
    return Boolean(
      !this._disposed
      && operation
      && operation.generation === this._generation
      && this._packageDescriptor?.key === operation.descriptor.key
      && !this._lifecycleController.signal.aborted
      && isAccountCurrent(this._connectionManager, operation.account)
    );
  }

  /** Fetch the single repository-wide upstream state used by the tree summary. */
  async getUpstreamState() {
    const account = captureAccount(this._connectionManager);
    if (!account || this._disposed) return emptyUpstreamState();
    const requestOptions = {
      account,
      connectionManager: this._connectionManager,
      signal: this._lifecycleController.signal,
    };
    const result = await this._upstreamInventory.getAllUpstreamData(
      this.workspace,
      this.slug,
      requestOptions
    );
    return isAccountCurrent(this._connectionManager, account)
      ? normalizeUpstreamState(result)
      : emptyUpstreamState();
  }

  async getUpstreams(packageNodes = []) {
    return (await this.getUpstreamState(packageNodes)).upstreams;
  }

  /**
   * Fetch entitlement tokens for this repository.
   * @returns {Array} Array of entitlement objects.
   */
  async getEntitlementCollection() {
    const account = captureAccount(this._connectionManager);
    if (!account || this._disposed) return emptyCollectionResult();
    const cloudsmithAPI = this._createCloudsmithAPI();
    let endpoint;
    try {
      endpoint = apiEndpoint(["entitlements", this.workspace, this.slug], {
        query: { sort: "name" },
      });
    } catch {
      throw new Error("The entitlement endpoint was invalid.");
    }
    const result = await this._createPaginatedFetch(cloudsmithAPI).fetchCollection(endpoint, {
      pageSize: ENTITLEMENT_PAGE_SIZE,
      maxPages: MAX_COLLECTION_PAGES,
      maxRequests: MAX_COLLECTION_REQUESTS,
      maxItems: MAX_COLLECTION_ITEMS,
      descriptor: JSON.stringify(["entitlements", this.workspace, this.slug]),
      canonicalIdentity: entitlement => entitlementCollectionIdentity(
        this.workspace,
        this.slug,
        entitlement
      ),
      validate: isEntitlementArray,
      retry: "never",
      signal: this._lifecycleController.signal,
    });
    if (!isAccountCurrent(this._connectionManager, account) || this._disposed) {
      return emptyCollectionResult(true);
    }
    if (!isCollectionResult(result)) {
      throw new Error("Cloudsmith returned an invalid entitlement collection.");
    }
    return replaceCollectionItems(
      result,
      result.items.map(entitlement => canonicalizeEntitlement(entitlement))
    );
  }

  async getEntitlements() {
    const result = await this.getEntitlementCollection();
    if (!result.cancelled && result.items.length === 0 && result.failureCount > 0) {
      throw result.failures[0]?.error || result.failures[0];
    }
    return result.items;
  }

  async getChildren() {
    const account = captureAccount(this._connectionManager);
    if (!account || this._disposed) return [];
    const packages = await this.getPackages();
    if (!isAccountCurrent(this._connectionManager, account) || this._disposed) return [];
    const generation = this._generation;
    const descriptor = this._packageDescriptor;
    const metadata = await this._getMetadataChildren(packages, account, generation, descriptor);
    if (
      !isAccountCurrent(this._connectionManager, account)
      || this._disposed
      || generation !== this._generation
    ) return [];

    const children = [...metadata];

    if (this._activePackageLoad && this._packageState.initialized) {
      const loadingKind = this._packageDescriptor?.mode === "groups"
        ? "package groups"
        : "packages";
      children.push(new InfoNode(
        `Loading more ${loadingKind}...`,
        "",
        `Loading more ${loadingKind}.`,
        "loading~spin"
      ));
    }

    for (const node of packages) {
      children.push(node);
    }

    const terminalNode = this._activePackageLoad
      ? null
      : this._createPackageTerminalNode(packages);
    if (terminalNode) children.push(terminalNode);

    if (this._packageState.continuation && !this._activePackageLoad && !terminalNode) {
      children.push(new RepositoryLoadMoreNode(this, {
        kind: this._packageDescriptor?.mode === "groups" ? "package groups" : "packages",
        loadedCount: packages.length,
        pagination: this._packageState.pagination,
        retry: packages.length === 0
          && ["cancelled", "request_failed"].includes(this._packageState.termination),
      }));
    }

    return isAccountCurrent(this._connectionManager, account) ? children : [];
  }

  _createPackageTerminalNode(packages) {
    const state = this._packageState;
    const activeFilter = this._getActiveFilter();
    if (packages.length === 0) {
      if (state.complete) {
        if (activeFilter) {
          return new RepositoryTerminalNode("empty", this, {
            scope: "filter",
            description: activeFilter.label || "Custom filter",
          });
        }
        return new RepositoryTerminalNode("empty", this);
      }
      if (state.termination === "cancelled") {
        return new RepositoryTerminalNode("cancelled", this, {
          command: this._packageRetryCommand(),
        });
      }
      if (state.failures.length > 0) {
        return new RepositoryTerminalNode("failed", this, {
          command: this._packageRetryCommand(),
        });
      }
      return new RepositoryTerminalNode("partial", this, {
        command: this._packageRetryCommand(),
      });
    }

    if (state.termination === "cancelled") {
      return new RepositoryTerminalNode("cancelled", this, {
        command: this._packageRetryCommand(),
      });
    }
    if (state.failures.length > 0 || (!state.complete && !state.continuation)) {
      if (state.capReached) {
        return new RepositoryTerminalNode("partial", this, {
          action: "change-filter",
          label: this._packageDescriptor?.mode === "groups"
            ? "Some package groups are not shown"
            : "Some packages are not shown",
          command: {
            command: "cloudsmith-vsc.changeFilter",
            title: "Change filter",
            arguments: [this],
          },
        });
      }
      return new RepositoryTerminalNode("partial", this, {
        command: this._packageRetryCommand(),
      });
    }
    return null;
  }

  _packageRetryCommand() {
    if (this._packageState.continuation) {
      return {
        command: "cloudsmith-vsc.loadMoreRepositoryPackages",
        title: "Retry",
        arguments: [this],
      };
    }
    return {
      command: "cloudsmith-vsc.refreshView",
      title: "Retry",
    };
  }

  _getMetadataChildren(packages, account, generation, descriptor) {
    if (this._metadataLoaded) return Promise.resolve(this._metadataChildren);
    if (this._metadataPromise) return this._metadataPromise;
    const promise = this._loadMetadataChildren(packages, account, generation, descriptor)
      .finally(() => {
        if (this._metadataPromise === promise) this._metadataPromise = null;
      });
    this._metadataPromise = promise;
    return promise;
  }

  async _loadMetadataChildren(packages, account, generation, descriptor) {
    const children = [];
    const hasValidatedPackagePage = this._packageState.pageCount > 0;
    if (hasValidatedPackagePage) {
      let upstreamState;
      try {
        upstreamState = await this.getUpstreamState(packages);
      } catch {
        upstreamState = null;
      }
      if (!this._isMetadataCurrent(account, generation, descriptor)) return [];
      if (upstreamState) {
        const upstreamNode = new UpstreamIndicatorNode(
          upstreamState.upstreams,
          {
            workspace: this.workspace,
            slug: this.slug,
            name: this.name,
          },
          this.context,
          {
            complete: upstreamState.complete,
            failedFormats: upstreamState.failedFormats,
            failures: upstreamState.failures,
            unsupportedFormats: upstreamState.unsupportedFormats,
            uninspectedFormats: upstreamState.uninspectedFormats,
          }
        );
        children.push(inheritSelection(upstreamNode, this));
      } else {
        children.push(new InfoNode(
          "Upstreams: failed to load",
          "The upstream collection could not be verified",
          "Package results remain available.",
          "warning"
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

    if (descriptor?.showEntitlements) {
      try {
        const entitlements = await this.getEntitlementCollection();
        if (!this._isMetadataCurrent(account, generation, descriptor)) return [];
        if (entitlements.items.length > 0) {
          children.push(new EntitlementSummaryNode(entitlements.items, this.context, {
            complete: entitlements.complete,
            totalCount: entitlements.pagination?.countAuthoritative
              ? entitlements.pagination.count
              : null,
            failureCount: entitlements.failureCount,
            termination: entitlements.termination,
            selectionOwner: this,
            registerEntitlement: (node) => {
              if (
                !this._disposed
                && generation === this._generation
                && descriptor?.key === this._packageDescriptor?.key
              ) {
                this._entitlementNodes.add(node);
              }
            },
          }));
        } else if (!entitlements.complete) {
          children.push(new InfoNode(
            entitlements.failureCount > 0
              ? "Entitlements: failed to load"
              : "Entitlements: incomplete",
            "The entitlement collection could not be verified.",
            entitlements.failureCount > 0
              ? collectionFailureMessage(entitlements.failures[0])
              : "A safe collection limit was reached or loading was cancelled.",
            "warning"
          ));
        }
      } catch {
        if (!this._isMetadataCurrent(account, generation, descriptor)) return [];
        children.push(new InfoNode(
          "Entitlements: failed to load",
          "The entitlement collection could not be verified.",
          "An error occurred loading entitlement tokens.",
          "warning"
        ));
      }
    }

    if (!this._isMetadataCurrent(account, generation, descriptor)) return [];
    this._metadataChildren = Object.freeze(children);
    this._metadataLoaded = true;
    return this._metadataChildren;
  }

  _isMetadataCurrent(account, generation, descriptor) {
    return Boolean(
      !this._disposed
      && generation === this._generation
      && descriptor?.key === this._packageDescriptor?.key
      && isAccountCurrent(this._connectionManager, account)
    );
  }
}

function isRecordArray(value) {
  return Array.isArray(value) && value.every(item => (
    Boolean(item) && typeof item === "object" && !Array.isArray(item)
  ));
}

function createEmptyPackageState() {
  return Object.freeze({
    initialized: false,
    nodes: Object.freeze([]),
    resultKeys: Object.freeze([]),
    pagination: null,
    complete: false,
    partial: false,
    continuation: null,
    failures: Object.freeze([]),
    pageCount: 0,
    requestCount: 0,
    duplicateCount: 0,
    termination: "not_started",
    capReached: false,
  });
}

function emptyCollectionResult(cancelled = false) {
  return Object.freeze({
    items: Object.freeze([]),
    complete: false,
    incomplete: true,
    partial: false,
    cancelled,
    continuation: null,
    failures: Object.freeze([]),
    failureCount: 0,
    termination: cancelled ? "cancelled" : "not_started",
    pageCount: 0,
    requestCount: 0,
    duplicateCount: 0,
    pagination: null,
  });
}

function isCollectionResult(value) {
  return Boolean(
    value
    && typeof value === "object"
    && !Array.isArray(value)
    && Array.isArray(value.items)
    && typeof value.complete === "boolean"
    && value.incomplete === !value.complete
    && typeof value.partial === "boolean"
    && typeof value.cancelled === "boolean"
    && Array.isArray(value.failures)
    && Number.isSafeInteger(value.failureCount)
    && value.failureCount >= value.failures.length
    && typeof value.termination === "string"
    && value.termination.length > 0
    && value.termination.length <= 80
    && COLLECTION_TERMINATIONS.has(value.termination)
    && Number.isSafeInteger(value.pageCount)
    && value.pageCount >= 0
    && value.pageCount <= MAX_COLLECTION_PAGES
    && Number.isSafeInteger(value.requestCount)
    && value.requestCount >= value.pageCount
    && value.requestCount <= MAX_COLLECTION_REQUESTS
    && Number.isSafeInteger(value.duplicateCount)
    && value.duplicateCount >= 0
    && (!value.complete || (
      value.termination === "exhausted"
      && value.continuation === null
      && !value.cancelled
      && value.failureCount === 0
    ))
    && (!value.cancelled || !value.complete)
    && (value.pagination === null || isPagination(value.pagination))
  );
}

function isPagination(value) {
  return Boolean(
    value
    && Number.isSafeInteger(value.page)
    && value.page >= 1
    && Number.isSafeInteger(value.pageTotal)
    && value.pageTotal >= value.page
    && Number.isSafeInteger(value.pageSize)
    && value.pageSize >= 1
    && typeof value.countAuthoritative === "boolean"
    && (value.countAuthoritative
      ? Number.isSafeInteger(value.count) && value.count >= 0
      : value.count === null)
  );
}

function validContinuation(value, descriptor, itemCount, result) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const anchor = value.anchor;
  const cumulative = value.cumulative;
  const firstPageRetry = value.nextPage === 1 && anchor === null;
  if (
    value.descriptor !== descriptor
    || typeof value.binding !== "string"
    || !/^[a-f0-9]{64}$/.test(value.binding)
    || !Number.isSafeInteger(value.nextPage)
    || value.nextPage < 1
    || (!firstPageRetry && !isPagination(anchor))
    || (!firstPageRetry && anchor.page + 1 !== value.nextPage)
    || (!firstPageRetry && anchor.page >= anchor.pageTotal)
    || !cumulative
    || !Number.isSafeInteger(cumulative.pageCount)
    || cumulative.pageCount < (firstPageRetry ? 0 : 1)
    || cumulative.pageCount >= MAX_COLLECTION_PAGES
    || !Number.isSafeInteger(cumulative.requestCount)
    || cumulative.requestCount < cumulative.pageCount
    || cumulative.requestCount >= MAX_COLLECTION_REQUESTS
    || !Number.isSafeInteger(cumulative.itemCount)
    || cumulative.itemCount !== itemCount
    || cumulative.itemCount >= MAX_COLLECTION_ITEMS
    || !Number.isSafeInteger(cumulative.duplicateCount)
    || cumulative.duplicateCount < 0
    || !Number.isSafeInteger(cumulative.failureCount)
    || cumulative.failureCount < 0
    || cumulative.pageCount !== result.pageCount
    || cumulative.requestCount !== result.requestCount
    || cumulative.duplicateCount !== result.duplicateCount
    || (firstPageRetry
      ? result.pagination !== null
        || cumulative.pageCount !== 0
        || cumulative.itemCount !== 0
        || value.nextPage !== 1
      : cumulative.pageCount !== anchor.page
        || value.nextPage !== cumulative.pageCount + 1
        || cumulative.itemCount !== committedItemCount(anchor)
        || !samePagination(anchor, result.pagination))
  ) return null;
  return value;
}

function committedItemCount(pagination) {
  const fullPageCount = pagination.page * pagination.pageSize;
  if (!Number.isSafeInteger(fullPageCount)) return -1;
  return pagination.countAuthoritative
    ? Math.min(pagination.count, fullPageCount)
    : fullPageCount;
}

function samePagination(left, right) {
  return Boolean(left && right)
    && left.page === right.page
    && left.pageTotal === right.pageTotal
    && left.pageSize === right.pageSize
    && left.count === right.count
    && left.countAuthoritative === right.countAuthoritative;
}

function isCollectionCapReached(result, itemCount) {
  return result.pageCount >= MAX_COLLECTION_PAGES
    || result.requestCount >= MAX_COLLECTION_REQUESTS
    || itemCount >= MAX_COLLECTION_ITEMS
    || /(?:cap|limit)/i.test(result.termination);
}

function normalizePageSize(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 30;
  return Math.min(30, Math.max(1, Math.floor(numeric)));
}

function boundedString(value, maxLength, options = {}) {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) return null;
  if (options.trimmed !== false && value !== value.trim()) return null;
  if (/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/.test(value)) return null;
  return value;
}

function optionalString(value, maxLength = MAX_OPTIONAL_STRING_LENGTH) {
  if (value == null) return null;
  return typeof value === "string" && value.length <= maxLength
    && !/[\u0000-\u001f\u007f]/.test(value)
    ? value
    : null;
}

function canonicalizeRepositoryPackage(pkg, workspace, repository) {
  try {
    return fromApiPackageRecord(pkg, {
      expectedWorkspace: workspace,
      expectedRepository: repository,
    });
  } catch {
    return null;
  }
}

function isPackageArray(value, workspace, repository) {
  return isRecordArray(value)
    && value.every(pkg => canonicalizeRepositoryPackage(pkg, workspace, repository) !== null);
}

function canonicalPackageGroupFormat(group) {
  const formats = [group?.format, group?.package_format, group?.packageFormat]
    .filter(value => value != null)
    .map(value => boundedString(value, MAX_FORMAT_LENGTH));
  if (formats.length === 0 || formats.some(value => !value || value !== formats[0])) return null;
  return formats[0];
}

function canonicalizePackageGroup(group) {
  if (!group || typeof group !== "object" || Array.isArray(group)) return null;
  const name = boundedString(group.name, MAX_NAME_LENGTH, { trimmed: false });
  const format = canonicalPackageGroupFormat(group);
  if (!name || !format) return null;
  const formats = Array.isArray(group.formats)
    ? group.formats.map(value => boundedString(value, MAX_FORMAT_LENGTH))
    : [];
  if (formats.some(value => !value) || formats.length > 100) return null;
  return {
    name,
    format,
    formats,
    count: Number.isSafeInteger(group.count) && group.count >= 0 ? group.count : 0,
    size: Number.isSafeInteger(group.size) && group.size >= 0 ? group.size : 0,
    num_downloads: Number.isSafeInteger(group.num_downloads) && group.num_downloads >= 0
      ? group.num_downloads
      : 0,
    last_push: optionalString(group.last_push),
  };
}

function isPackageGroupArray(value) {
  return isRecordArray(value) && value.every(group => canonicalizePackageGroup(group) !== null);
}

function isPackageGroupResponse(value) {
  return Boolean(
    value
    && typeof value === "object"
    && !Array.isArray(value)
    && isPackageGroupArray(value.results)
  );
}

function isEntitlementArray(value) {
  return isRecordArray(value)
    && value.every(entitlement => canonicalizeEntitlement(entitlement) !== null);
}

function canonicalizeEntitlement(entitlement) {
  if (!entitlement || typeof entitlement !== "object" || Array.isArray(entitlement)) return null;
  const name = boundedString(entitlement.name, MAX_NAME_LENGTH, { trimmed: false });
  const slugPerm = boundedString(entitlement.slug_perm, MAX_IDENTITY_LENGTH);
  if (!name || !slugPerm || typeof entitlement.is_active !== "boolean") return null;
  const token = entitlement.token == null
    ? null
    : optionalString(entitlement.token, MAX_OPTIONAL_STRING_LENGTH);
  const queryValues = [entitlement.limit_package_query, entitlement.package_query]
    .filter(value => value != null);
  const packageQuery = queryValues.length === 0
    ? null
    : optionalString(queryValues[0], MAX_OPTIONAL_STRING_LENGTH);
  const limitBandwidthUnit = entitlement.limit_bandwidth_unit == null
    ? null
    : optionalString(entitlement.limit_bandwidth_unit, 100);
  const limitDateRangeFrom = entitlement.limit_date_range_from == null
    ? null
    : optionalString(entitlement.limit_date_range_from, 100);
  const limitDateRangeTo = entitlement.limit_date_range_to == null
    ? null
    : optionalString(entitlement.limit_date_range_to, 100);
  if (
    (entitlement.token != null && token === null)
    || (queryValues.length > 0 && (
      packageQuery === null || queryValues.some(value => value !== queryValues[0])
    ))
    || (entitlement.limit_bandwidth_unit != null && limitBandwidthUnit === null)
    || (entitlement.limit_date_range_from != null && limitDateRangeFrom === null)
    || (entitlement.limit_date_range_to != null && limitDateRangeTo === null)
  ) return null;
  const limitBandwidth = optionalNonNegativeNumber(entitlement.limit_bandwidth);
  const limitDownloads = optionalNonNegativeNumber(entitlement.limit_num_downloads);
  const limitClients = optionalNonNegativeNumber(entitlement.limit_num_clients);
  if ([limitBandwidth, limitDownloads, limitClients].includes(false)) return null;
  return {
    name,
    slug_perm: slugPerm,
    is_active: entitlement.is_active,
    token,
    package_query: packageQuery,
    limit_bandwidth: limitBandwidth,
    limit_bandwidth_unit: limitBandwidthUnit,
    limit_num_downloads: limitDownloads,
    limit_num_clients: limitClients,
    limit_date_range_from: limitDateRangeFrom,
    limit_date_range_to: limitDateRangeTo,
  };
}

function optionalNonNegativeNumber(value) {
  if (value == null) return null;
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : false;
}

function normalizeUpstreamState(result) {
  if (!result || !Array.isArray(result.upstreams)) return emptyUpstreamState();
  const upstreams = result.upstreams.map(upstream => sanitizeSafeInventoryUpstream(upstream));
  if (upstreams.some(upstream => upstream === null)) return emptyUpstreamState();
  const failedFormats = Array.isArray(result.failedFormats) ? [...result.failedFormats] : [];
  const uninspectedFormats = Array.isArray(result.uninspectedFormats)
    ? [...result.uninspectedFormats]
    : [];
  const failures = Array.isArray(result.failures) ? [...result.failures] : [];
  const unsupportedFormats = Array.isArray(result.unsupportedFormats)
    ? [...result.unsupportedFormats]
    : [];
  return Object.freeze({
    upstreams: Object.freeze(upstreams),
    failedFormats: Object.freeze(failedFormats),
    failures: Object.freeze(failures),
    unsupportedFormats: Object.freeze(unsupportedFormats),
    uninspectedFormats: Object.freeze(uninspectedFormats),
    configuredTotal: Number.isSafeInteger(result.configuredTotal)
      ? result.configuredTotal
      : null,
    loadedCount: upstreams.length,
    state: typeof result.state === "string" ? result.state : "failed",
    complete: result.complete === true
      && failedFormats.length === 0
      && uninspectedFormats.length === 0,
  });
}

function emptyUpstreamState() {
  return Object.freeze({
    upstreams: Object.freeze([]),
    failedFormats: Object.freeze([]),
    failures: Object.freeze([]),
    unsupportedFormats: Object.freeze([]),
    uninspectedFormats: Object.freeze([]),
    configuredTotal: null,
    loadedCount: 0,
    state: "cancelled",
    complete: false,
  });
}

function localCollectionFailure(kind, message) {
  return Object.freeze({
    kind,
    status: null,
    retryable: false,
    message,
    requestId: null,
    retryAfterMs: null,
    outcomeUnknown: false,
    diagnostic: Object.freeze({}),
  });
}

function collectionFailureMessage(failure) {
  if (!failure) return "The collection could not be verified.";
  try {
    return formatApiError(failure.error || failure);
  } catch {
    return "The collection could not be verified.";
  }
}

module.exports = RepositoryNode;

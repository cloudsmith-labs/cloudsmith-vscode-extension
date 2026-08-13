// This class handles the main Cloudsmith view. Workspaces are generated and populated here.
// When cloudsmith-vsc.defaultWorkspace is set, repositories load directly as root items.

const vscode = require("vscode");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { apiEndpoint } = require("../util/apiEndpoint");
const {
  captureAccount,
  isAccountCurrent,
  resolveConnectionManager,
} = require("../util/accountOperation");
const { WorkspaceCache } = require("../util/workspaceCache");
const InfoNode = require("../models/infoNode");
const { WorkspaceInfoNode } = require("../models/workspaceInfoNode");
const WorkspaceNode = require("../models/workspaceNode");
const RepositoryNode = require("../models/repositoryNode");
const workspaceFetcher = require("../util/workspaceFetcher");
const workspaceRepositoryFetcher = require("../util/workspaceRepositoryFetcher");
const { getWorkspaceContextProjector } = require("../util/workspaceContextProjector");
const { packageCollectionIdentity } = require("../util/collectionIdentity");

class CloudsmithProvider {
  constructor(context, options = {}) {
    this.context = context;
    this._connectionManager = resolveConnectionManager(context, options.connectionManager);
    this._workspaceCache = options.workspaceCache
      || new WorkspaceCache(this._connectionManager, options.workspaceCacheOptions);
    this._createCloudsmithAPI = options.createCloudsmithAPI
      || (() => new CloudsmithAPI(this.context));
    this._fetchWorkspaceRepositories = options.fetchWorkspaceRepositories
      || workspaceRepositoryFetcher.fetchWorkspaceRepositories;
    this._fetchWorkspaces = options.fetchWorkspaces || workspaceFetcher.fetchWorkspaces;
    this._workspaceContextProjector = options.workspaceContextProjector
      || getWorkspaceContextProjector(context);
    this._repositoryNodeOptions = Object.freeze({
      createPaginatedFetch: options.createPaginatedFetch,
      upstreamChecker: options.upstreamChecker,
      withProgress: options.withProgress,
    });
    this._vulnerabilityStateService = options.vulnerabilityStateService || null;
    this._vulnerabilitySummaries = new Map();
    this._treeParents = new WeakMap();
    this._vulnerabilityRefreshTimers = new Map();
    this._vulnerabilityStateSubscription = this._vulnerabilityStateService?.onDidChange?.(
      event => this._publishVulnerabilityState(event)
    ) || null;
    this._onDidChangeTreeData = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    this._defaultWorkspaceFallbackHandler = null;
    this._treeView = null;
    this._expandedVulnerabilitySummaries = new WeakSet();
    this._treeExpansionSubscriptions = [];
    this._suppressMissingCredentialsWarningOnce = false;
    this._operationId = 0;
    this._loadingOperationId = null;
    this._operationController = null;
    this._repositoryNodes = new Set();
  }

  getTreeItem(element) {
    return element.getTreeItem();
  }

  getParent(element) {
    return this._treeParents.get(element);
  }

  getChildren(element) {
    if (!element) {
      // Root level — check if default workspace is configured
      const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
      const defaultWorkspace = config.get("defaultWorkspace");

      if (defaultWorkspace) {
        return this.getRepositories(defaultWorkspace);
      }
      return this.getWorkspaces();
    }
    return element.getChildren();
  }

  refresh(options = {}) {
    if (options.suppressMissingCredentialsWarning) {
      this._suppressMissingCredentialsWarningOnce = true;
    }
    this._invalidateRepositoryNodes();
    this._abortActiveOperation();
    this._operationId += 1;
    void this._projectMultipleWorkspaces(
      Boolean(captureAccount(this._connectionManager))
    ).catch(() => {});
    this._onDidChangeTreeData.fire();
  }

  dispose() {
    this._invalidateRepositoryNodes();
    this._abortActiveOperation();
    this._operationId += 1;
    this._workspaceCache.clear();
    this._vulnerabilitySummaries.clear();
    this._clearVulnerabilityRefreshTimers();
    this._vulnerabilityStateSubscription?.dispose?.();
    for (const subscription of this._treeExpansionSubscriptions) subscription.dispose?.();
    this._onDidChangeTreeData.dispose();
  }

  _consumeMissingCredentialsWarningSuppression() {
    const suppressed = this._suppressMissingCredentialsWarningOnce;
    this._suppressMissingCredentialsWarningOnce = false;
    return suppressed;
  }

  _beginOperation() {
    this._invalidateRepositoryNodes();
    this._abortActiveOperation();
    const account = captureAccount(this._connectionManager);
    if (!account) return null;
    const controller = new AbortController();
    this._operationController = controller;
    const operation = {
      id: ++this._operationId,
      account,
      controller,
      signal: controller.signal,
    };
    operation.projection = this._workspaceContextProjector.begin({
      isCurrent: () => this._isOperationCurrent(operation),
    });
    return Object.freeze(operation);
  }

  _isOperationCurrent(operation) {
    return Boolean(
      operation
      && operation.id === this._operationId
      && operation.signal.aborted === false
      && isAccountCurrent(this._connectionManager, operation.account)
    );
  }

  _abortActiveOperation() {
    this._operationController?.abort();
    this._operationController = null;
  }

  _signedOutNode() {
    return new InfoNode(
      "Connect to Cloudsmith",
      "Use the key icon above to set up a personal or service account API key, CLI import, or SSO.",
      "Set up Cloudsmith authentication to get started.",
      "plug",
      undefined,
      { command: "cloudsmith-vsc.configureCredentials", title: "Set up authentication" }
    );
  }

  _loadFailureNode(kind = "workspaces") {
    return new InfoNode(
      `Could not load ${kind}`,
      "Check the connection and credentials",
      "The Cloudsmith API returned an error. Refresh or configure credentials.",
      "warning"
    );
  }

  _startLoading(operation) {
    this._loadingOperationId = operation.id;
    if (this._treeView) this._treeView.message = "Loading...";
  }

  _finishLoading(operation) {
    if (this._loadingOperationId !== operation.id) return;
    this._loadingOperationId = null;
    if (this._treeView) this._treeView.message = undefined;
  }

  _projectMultipleWorkspaces(hasMultiple, operation = null) {
    return this._workspaceContextProjector.project(hasMultiple, {
      operation: operation?.projection,
    });
  }

  _createWorkspaceNodes(workspaces, signal = null) {
    return workspaces.map((workspace) => {
      let workspaceNode;
      workspaceNode = new WorkspaceNode(workspace, this.context, {
        connectionManager: this._connectionManager,
        createCloudsmithAPI: this._createCloudsmithAPI,
        fetchWorkspaceRepositories: this._fetchWorkspaceRepositories,
        signal,
        createRepositoryNode: (repository, workspaceSlug) => (
          this._createRepositoryNode(repository, workspaceSlug, workspaceNode)
        ),
      });
      return workspaceNode;
    });
  }

  _createRepositoryNode(repository, workspaceSlug, parent = null) {
    const node = new RepositoryNode(repository, workspaceSlug, this.context, {
      connectionManager: this._connectionManager,
      createCloudsmithAPI: this._createCloudsmithAPI,
      requestRefresh: element => this.refreshNode(element),
      vulnerabilityStateService: this._vulnerabilityStateService,
      registerVulnerabilitySummary: (identity, element, owner) => (
        this._registerVulnerabilitySummary(identity, element, owner)
      ),
      unregisterVulnerabilitySummaries: repositoryNode => (
        this._unregisterVulnerabilitySummaries(repositoryNode)
      ),
      ...this._repositoryNodeOptions,
    });
    this._repositoryNodes.add(node);
    if (parent) this._treeParents.set(node, parent);
    return node;
  }

  _invalidateRepositoryNodes() {
    for (const node of this._repositoryNodes) {
      node.invalidate();
    }
    this._repositoryNodes.clear();
    this._vulnerabilitySummaries.clear();
    this._clearVulnerabilityRefreshTimers();
  }

  refreshNode(element) {
    if (element && this._repositoryNodes.has(element)) {
      this._onDidChangeTreeData.fire(element);
    }
  }

  _registerVulnerabilitySummary(identity, element, owner) {
    if (typeof identity !== "string" || !element || !owner) return;
    let entries = this._vulnerabilitySummaries.get(identity);
    if (!entries) {
      entries = new Set();
      this._vulnerabilitySummaries.set(identity, entries);
    }
    entries.add(Object.freeze({ element, owner }));
    this._treeParents.set(element, owner.packageNode);
    this._treeParents.set(owner.packageNode, owner.repositoryNode);
  }

  _publishVulnerabilityState(event) {
    const identity = vulnerabilityEventIdentity(event);
    if (!identity) return;
    const entries = this._vulnerabilitySummaries.get(identity);
    if (!entries) return;
    for (const entry of [...entries]) {
      const repository = entry.owner.repositoryNode;
      if (
        !this._repositoryNodes.has(repository)
        || !repository.ownsVulnerabilitySummary(entry.owner)
      ) {
        entries.delete(entry);
        continue;
      }
      if (event.presentation) {
        entry.element.acceptVulnerabilityPresentation?.(event.presentation);
      }
      if (event.state?.status !== "loading") {
        this._scheduleVulnerabilityRefresh(entry.element, () => (
          this._repositoryNodes.has(repository)
          && repository.ownsVulnerabilitySummary(entry.owner)
        ));
      }
    }
    if (entries.size === 0) this._vulnerabilitySummaries.delete(identity);
  }

  _scheduleVulnerabilityRefresh(element, isCurrent) {
    const current = this._vulnerabilityRefreshTimers.get(element);
    if (current) clearTimeout(current);
    const timer = setTimeout(() => {
      this._vulnerabilityRefreshTimers.delete(element);
      if (!isCurrent()) return;
      const wasExpanded = this._expandedVulnerabilitySummaries.has(element);
      this._onDidChangeTreeData.fire(element);
      if (wasExpanded) {
        void this._treeView?.reveal?.(element, { expand: true, focus: false, select: false })
          ?.catch?.(() => {});
      }
    }, 0);
    this._vulnerabilityRefreshTimers.set(element, timer);
  }

  _clearVulnerabilityRefreshTimers() {
    for (const timer of this._vulnerabilityRefreshTimers.values()) clearTimeout(timer);
    this._vulnerabilityRefreshTimers.clear();
  }

  _unregisterVulnerabilitySummaries(repositoryNode) {
    for (const [identity, entries] of this._vulnerabilitySummaries) {
      for (const entry of [...entries]) {
        if (entry.owner.repositoryNode === repositoryNode) entries.delete(entry);
      }
      if (entries.size === 0) this._vulnerabilitySummaries.delete(identity);
    }
  }

  setDefaultWorkspaceFallbackHandler(handler) {
    this._defaultWorkspaceFallbackHandler = handler;
  }

  setTreeView(treeView) {
    for (const subscription of this._treeExpansionSubscriptions) subscription.dispose?.();
    this._treeExpansionSubscriptions = [];
    this._treeView = treeView;
    const expanded = treeView?.onDidExpandElement?.(({ element }) => {
      if (element?.getTreeItem?.().contextValue === "vulnerabilitySummary") {
        this._expandedVulnerabilitySummaries.add(element);
      }
    });
    const collapsed = treeView?.onDidCollapseElement?.(({ element }) => {
      this._expandedVulnerabilitySummaries.delete(element);
    });
    if (expanded) this._treeExpansionSubscriptions.push(expanded);
    if (collapsed) this._treeExpansionSubscriptions.push(collapsed);
  }

  async getWorkspaces() {
    this._consumeMissingCredentialsWarningSuppression();
    const operation = this._beginOperation();
    if (!operation) {
      if (this._treeView) this._treeView.message = undefined;
      await this._projectMultipleWorkspaces(false);
      return [this._signedOutNode()];
    }

    this._startLoading(operation);
    try {
      const cached = this._workspaceCache.get();
      if (cached) {
        if (!this._isOperationCurrent(operation)) return [];
        await this._projectMultipleWorkspaces(cached.length > 1, operation);
        if (!this._isOperationCurrent(operation)) return [];
        return this._createWorkspaceNodes(cached, operation.signal);
      }

      await this._projectMultipleWorkspaces(true, operation);
      if (!this._isOperationCurrent(operation)) return [];

      const result = await this._fetchWorkspaces(this.context, {
        account: operation.account,
        connectionManager: this._connectionManager,
        cloudsmithAPI: this._createCloudsmithAPI(),
        signal: operation.signal,
      });
      if (!this._isOperationCurrent(operation) || result.stale) return [];
      if (!Array.isArray(result.items)) throw new TypeError("Invalid workspace collection.");
      const workspaces = result.items.map(workspace => ({
        slug: workspace.slug,
        name: workspaceFetcher.normalizedWorkspaceName(workspace),
      }));
      const incomplete = result.complete !== true;
      await this._projectMultipleWorkspaces(incomplete || workspaces.length > 1, operation);
      if (!this._isOperationCurrent(operation)) return [];
      if (result.complete) this._workspaceCache.set(workspaces, operation.account);

      const nodes = this._createWorkspaceNodes(workspaces, operation.signal);
      if (incomplete) nodes.push(this._incompleteCollectionNode("workspaces", result));
      return nodes;
    } catch {
      if (!this._isOperationCurrent(operation)) return [];
      try {
        await this._projectMultipleWorkspaces(true, operation);
      } catch {
        // Loading cleanup and the fixed failure node remain authoritative.
      }
      return this._isOperationCurrent(operation)
        ? [this._loadFailureNode("workspaces")]
        : [];
    } finally {
      this._finishLoading(operation);
    }
  }

  /**
   * Load repositories directly for a specific workspace (skipping workspace level).
   * Used when cloudsmith-vsc.defaultWorkspace is configured.
   *
   * @param   {string} workspaceSlug  The workspace slug to load repos for.
   * @returns {Array} Array of RepositoryNode instances, or empty on error.
   */
  async getRepositories(workspaceSlug) {
    this._consumeMissingCredentialsWarningSuppression();
    const operation = this._beginOperation();
    if (!operation) {
      if (this._treeView) this._treeView.message = undefined;
      return [this._signedOutNode()];
    }

    this._startLoading(operation);
    try {
      const result = await this._fetchWorkspaceRepositories(this.context, workspaceSlug, {
        account: operation.account,
        connectionManager: this._connectionManager,
        signal: operation.signal,
      });
      if (!this._isOperationCurrent(operation) || result.stale) return [];

      if (!Array.isArray(result.items)) {
        return [this._loadFailureNode("repositories")];
      }
      if (result.cancelled === true) {
        if (result.items.length === 0) {
          return [new InfoNode(
            "Repository loading cancelled",
            "No workspace fallback or quota request was started",
            "Refresh the view to try loading the repository collection again.",
            "warning"
          )];
        }
        const cancelledNodes = [new WorkspaceInfoNode(workspaceSlug, null)];
        for (const repo of result.items) {
          cancelledNodes.push(this._createRepositoryNode(repo, workspaceSlug));
        }
        cancelledNodes.push(this._incompleteCollectionNode("repositories", result));
        return cancelledNodes;
      }
      if (result.complete !== true && result.items.length === 0) {
        if (this._defaultWorkspaceFallbackHandler) {
          this._defaultWorkspaceFallbackHandler(workspaceSlug);
        } else {
          vscode.window.showWarningMessage(
            `Could not verify the repository list for workspace "${workspaceSlug}". Showing all workspaces.`
          );
        }
        // Fall back to full workspace tree
        return this.getWorkspaces();
      }

      const repos = result.items;
      let quotaData = null;
      try {
        const quotaResult = await this._createCloudsmithAPI().get(apiEndpoint(["quota", workspaceSlug]), {
          responseType: "object",
          retry: "safe-read",
          signal: operation.signal,
        });
        if (quotaResult.ok && quotaResult.data.usage && typeof quotaResult.data.usage === "object") {
          quotaData = quotaResult.data;
        }
      } catch {
        // Quota access is optional for the workspace summary row.
      }
      if (!this._isOperationCurrent(operation)) return [];

      const RepositoryNodes = [
        new WorkspaceInfoNode(workspaceSlug, quotaData),
      ];
      for (const repo of repos) {
        // Pass workspaceSlug as the workspace parameter so downstream calls work
        RepositoryNodes.push(this._createRepositoryNode(repo, workspaceSlug));
      }
      if (result.complete !== true) {
        RepositoryNodes.push(this._incompleteCollectionNode("repositories", result));
      }
      return RepositoryNodes;
    } catch {
      return this._isOperationCurrent(operation)
        ? [this._loadFailureNode("repositories")]
        : [];
    } finally {
      this._finishLoading(operation);
    }
  }

  _incompleteCollectionNode(kind, result) {
    const loaded = Array.isArray(result?.items) ? result.items.length : 0;
    const failure = result?.failures?.[0]?.error;
    return new InfoNode(
      loaded > 0
        ? `${kind[0].toUpperCase()}${kind.slice(1)} are incomplete`
        : `Could not load ${kind}`,
      loaded > 0 ? `${loaded.toLocaleString()} loaded` : "Check the connection and credentials",
      failure?.message || "A safe collection limit was reached before completeness was proven.",
      "warning"
    );
  }
}

function vulnerabilityEventIdentity(event) {
  if (typeof event === "string") return event;
  if (typeof event?.identity === "string") return event.identity;
  const ref = event?.ref || event?.packageRef || event;
  try {
    return packageCollectionIdentity(ref);
  } catch {
    return null;
  }
}

module.exports = { CloudsmithProvider };

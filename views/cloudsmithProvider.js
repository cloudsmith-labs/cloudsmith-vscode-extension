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
const workspaceRepositoryFetcher = require("../util/workspaceRepositoryFetcher");
const { getWorkspaceContextProjector } = require("../util/workspaceContextProjector");

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
    this._workspaceContextProjector = options.workspaceContextProjector
      || getWorkspaceContextProjector(context);
    this._onDidChangeTreeData = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    this._defaultWorkspaceFallbackHandler = null;
    this._treeView = null;
    this._suppressMissingCredentialsWarningOnce = false;
    this._operationId = 0;
    this._loadingOperationId = null;
  }

  getTreeItem(element) {
    return element.getTreeItem();
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
    this._operationId += 1;
    void this._projectMultipleWorkspaces(false).catch(() => {});
    this._onDidChangeTreeData.fire();
  }

  dispose() {
    this._operationId += 1;
    this._workspaceCache.clear();
    this._onDidChangeTreeData.dispose();
  }

  _consumeMissingCredentialsWarningSuppression() {
    const suppressed = this._suppressMissingCredentialsWarningOnce;
    this._suppressMissingCredentialsWarningOnce = false;
    return suppressed;
  }

  _beginOperation() {
    const account = captureAccount(this._connectionManager);
    if (!account) return null;
    const operation = {
      id: ++this._operationId,
      account,
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
      && isAccountCurrent(this._connectionManager, operation.account)
    );
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

  _createWorkspaceNodes(workspaces) {
    return workspaces.map(workspace => new WorkspaceNode(workspace, this.context, {
      connectionManager: this._connectionManager,
      createCloudsmithAPI: this._createCloudsmithAPI,
      fetchWorkspaceRepositories: this._fetchWorkspaceRepositories,
    }));
  }

  setDefaultWorkspaceFallbackHandler(handler) {
    this._defaultWorkspaceFallbackHandler = handler;
  }

  setTreeView(treeView) {
    this._treeView = treeView;
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
        return this._createWorkspaceNodes(cached);
      }

      const result = await this._createCloudsmithAPI().get("namespaces/?sort=slug", {
        responseType: "array",
        validate: value => Array.isArray(value) && value.every(workspace => (
          workspace
          && typeof workspace === "object"
          && !Array.isArray(workspace)
          && typeof workspace.slug === "string"
          && workspace.slug.length > 0
        )),
        retry: "safe-read",
      });
      if (!this._isOperationCurrent(operation)) return [];

      const workspaces = result.ok
        ? result.data.map(workspace => ({
          slug: workspace.slug,
          name: typeof workspace.name === "string" && workspace.name.length > 0
            ? workspace.name
            : workspace.slug,
        }))
        : null;

      if (!workspaces) {
        await this._projectMultipleWorkspaces(false, operation);
        if (!this._isOperationCurrent(operation)) return [];
        return [this._loadFailureNode("workspaces")];
      }
      await this._projectMultipleWorkspaces(workspaces.length > 1, operation);
      if (!this._isOperationCurrent(operation)) return [];
      this._workspaceCache.set(workspaces, operation.account);

      return this._createWorkspaceNodes(workspaces);
    } catch {
      if (!this._isOperationCurrent(operation)) return [];
      try {
        await this._projectMultipleWorkspaces(false, operation);
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
      });
      if (!this._isOperationCurrent(operation) || result.stale) return [];

      if (result.error) {
        if (this._defaultWorkspaceFallbackHandler) {
          this._defaultWorkspaceFallbackHandler(workspaceSlug);
        } else {
          vscode.window.showWarningMessage(
            `Could not access workspace "${workspaceSlug}". Showing all workspaces.`
          );
        }
        // Fall back to full workspace tree
        return this.getWorkspaces();
      }

      const repos = result.repositories;
      let quotaData = null;
      try {
        const quotaResult = await this._createCloudsmithAPI().get(apiEndpoint(["quota", workspaceSlug]), {
          responseType: "object",
          retry: "safe-read",
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
        RepositoryNodes.push(new RepositoryNode(repo, workspaceSlug, this.context, {
          connectionManager: this._connectionManager,
          createCloudsmithAPI: this._createCloudsmithAPI,
        }));
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
}

module.exports = { CloudsmithProvider };

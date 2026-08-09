// This class handles the main Cloudsmith view. Workspaces are generated and populated here.
// When cloudsmith-vsc.defaultWorkspace is set, repositories load directly as root items.

const vscode = require("vscode");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { apiEndpoint } = require("../util/apiEndpoint");
const { ConnectionManager } = require("../util/connectionManager");
const InfoNode = require("../models/infoNode");
const { WorkspaceInfoNode } = require("../models/workspaceInfoNode");
const workspaceRepositoryFetcher = require("../util/workspaceRepositoryFetcher");

class CloudsmithProvider {
  constructor(context) {
    this.context = context;
    this._onDidChangeTreeData = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    this._defaultWorkspaceFallbackHandler = null;
    this._treeView = null;
    this._suppressMissingCredentialsWarningOnce = false;
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
    this._onDidChangeTreeData.fire();
  }

  _consumeConnectionOptions() {
    const promptOnMissingCredentials = !this._suppressMissingCredentialsWarningOnce;
    this._suppressMissingCredentialsWarningOnce = false;
    return { promptOnMissingCredentials };
  }

  setDefaultWorkspaceFallbackHandler(handler) {
    this._defaultWorkspaceFallbackHandler = handler;
  }

  setTreeView(treeView) {
    this._treeView = treeView;
  }

  async getWorkspaces() {
    const context = this.context;
    const cloudsmithAPI = new CloudsmithAPI(context);
    const connectionManager = new ConnectionManager(context);
    let workspaces = "";

    if (this._treeView) {
      this._treeView.message = "Loading...";
    }

    const connStatus = await connectionManager.connect(this._consumeConnectionOptions());

    if (connStatus === "false" || connStatus === "error") {
      await vscode.commands.executeCommand("setContext", "cloudsmith.hasMultipleWorkspaces", false);
      if (this._treeView) {
        this._treeView.message = undefined;
      }
      return [new InfoNode(
        "Connect to Cloudsmith",
        "Use the key icon above to set up a personal or service account API key, CLI import, or SSO.",
        "Set up Cloudsmith authentication to get started.",
        "plug",
        undefined,
        { command: "cloudsmith-vsc.configureCredentials", title: "Set up authentication" }
      )];
    }

    const result = await cloudsmithAPI.get("namespaces/?sort=slug", {
      responseType: "array",
      validate: value => value.every(workspace => (
        workspace
        && typeof workspace === "object"
        && !Array.isArray(workspace)
        && typeof workspace.slug === "string"
        && workspace.slug.length > 0
      )),
      retry: "safe-read",
    });
    workspaces = result.ok
      ? result.data.map(workspace => ({
        ...workspace,
        name: typeof workspace.name === "string" && workspace.name.length > 0
          ? workspace.name
          : workspace.slug,
      }))
      : null;

    if (this._treeView) {
      this._treeView.message = undefined;
    }

    const WorkspaceNodes = [];
    if (!workspaces) {
      await vscode.commands.executeCommand("setContext", "cloudsmith.hasMultipleWorkspaces", false);
      return [new InfoNode(
        "Could not load workspaces",
        "Check the connection and credentials",
        "The Cloudsmith API returned an error. Refresh or configure credentials.",
        "warning"
      )];
    }
    await vscode.commands.executeCommand(
      "setContext",
      "cloudsmith.hasMultipleWorkspaces",
      workspaces.length > 1
    );
    if (workspaces.length > 0) {
      for (const workspace of workspaces) {
        const workspaceNode = require("../models/workspaceNode");
        const workspaceNodeInst = new workspaceNode(workspace, context);
        WorkspaceNodes.push(workspaceNodeInst);
      }
      context.globalState.update('CloudsmithCache', {
        name: 'Workspaces',
        lastSync: Date.now(),
        workspaces: workspaces
      });
    }

    return WorkspaceNodes;
  }

  /**
   * Load repositories directly for a specific workspace (skipping workspace level).
   * Used when cloudsmith-vsc.defaultWorkspace is configured.
   *
   * @param   {string} workspaceSlug  The workspace slug to load repos for.
   * @returns {Array} Array of RepositoryNode instances, or empty on error.
   */
  async getRepositories(workspaceSlug) {
    const context = this.context;
    const cloudsmithAPI = new CloudsmithAPI(context);
    const connectionManager = new ConnectionManager(context);

    if (this._treeView) {
      this._treeView.message = "Loading...";
    }

    const connStatus = await connectionManager.connect(this._consumeConnectionOptions());
    if (connStatus === "false" || connStatus === "error") {
      if (this._treeView) {
        this._treeView.message = undefined;
      }
      return [new InfoNode(
        "Connect to Cloudsmith",
        "Use the key icon above to set up a personal or service account API key, CLI import, or SSO.",
        "Set up Cloudsmith authentication to get started.",
        "plug",
        undefined,
        { command: "cloudsmith-vsc.configureCredentials", title: "Set up authentication" }
      )];
    }

    const result = await workspaceRepositoryFetcher.fetchWorkspaceRepositories(
      context,
      workspaceSlug
    );

    if (this._treeView) {
      this._treeView.message = undefined;
    }

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

    const RepositoryNode = require("../models/repositoryNode");
    let quotaData = null;

    try {
      const quotaResult = await cloudsmithAPI.get(apiEndpoint(["quota", workspaceSlug]), {
        responseType: "object",
        retry: "safe-read",
      });
      if (quotaResult.ok && quotaResult.data.usage && typeof quotaResult.data.usage === "object") {
        quotaData = quotaResult.data;
      }
    } catch {
      // Quota access is optional for the workspace summary row.
    }

    const RepositoryNodes = [
      new WorkspaceInfoNode(workspaceSlug, quotaData),
    ];

    for (const repo of repos) {
      // Pass workspaceSlug as the workspace parameter so downstream calls work
      const repoNode = new RepositoryNode(repo, workspaceSlug, context);
      RepositoryNodes.push(repoNode);
    }

    // Also update the workspace cache so search commands can find it
    context.globalState.update('CloudsmithCache', {
      name: 'Workspaces',
      lastSync: Date.now(),
      workspaces: [{ name: workspaceSlug, slug: workspaceSlug }]
    });

    return RepositoryNodes;
  }
}

module.exports = { CloudsmithProvider };

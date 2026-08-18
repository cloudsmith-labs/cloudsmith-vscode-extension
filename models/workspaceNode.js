// Workspace node treeview

const vscode = require("vscode");
const path = require("path");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { apiEndpoint } = require("../util/apiEndpoint");
const { formatApiError } = require("../util/errorFormatter");
const InfoNode = require("./infoNode");
const repositoryNode = require("./repositoryNode");
const { WorkspaceInfoNode } = require("./workspaceInfoNode");
const workspaceRepositoryFetcher = require("../util/workspaceRepositoryFetcher");
const {
  captureAccount,
  isAccountCurrent,
  resolveConnectionManager,
} = require("../util/accountOperation");
const { markSelection } = require("../util/selectionProvenance");

class WorkspaceNode {
  constructor(item, context, options = {}) {
    this.context = context;
    this._connectionManager = resolveConnectionManager(context, options.connectionManager);
    markSelection(this, this._connectionManager);
    this._createCloudsmithAPI = options.createCloudsmithAPI
      || (() => new CloudsmithAPI(this.context));
    this._fetchWorkspaceRepositories = options.fetchWorkspaceRepositories
      || workspaceRepositoryFetcher.fetchWorkspaceRepositories;
    this._signal = options.signal || null;
    this._createRepositoryNode = options.createRepositoryNode
      || ((repo, workspace) => new repositoryNode(
        repo,
        workspace,
        this.context,
        { connectionManager: this._connectionManager, createCloudsmithAPI: this._createCloudsmithAPI }
      ));
    this.name = item.name;
    this.slug = item.slug;
    this.workspace = item.slug;
    this.repos = [];
  }

  getTreeItem() {
    const workspace = this.name;
    let iconPath = {
      light: path.join(__filename, "..", "..", "media", "workspace_light.svg"),
      dark: path.join(__filename, "..", "..", "media", "workspace_dark.svg"),
    };
    return {
      label: workspace,
      collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
      contextValue: "workspace",
      iconPath: iconPath,
    };
  }

  async getRepositories() {
    const account = captureAccount(this._connectionManager);
    if (!account) return [];
    const workspace = this.workspace;
    let result;
    try {
      result = await this._fetchWorkspaceRepositories(this.context, workspace, {
        account,
        connectionManager: this._connectionManager,
        signal: this._signal,
      });
    } catch {
      return isAccountCurrent(this._connectionManager, account)
        ? [repositoryCollectionWarning(workspace, null)]
        : [];
    }
    if (!result || !Array.isArray(result.items)) {
      return [repositoryCollectionWarning(workspace, result)];
    }
    if (!isAccountCurrent(this._connectionManager, account) || result.stale) return [];

    const repositories = result.items;
    const RepositoryNodes = [];

    for (const repo of repositories) {
      const repositoryNodeInst = this._createRepositoryNode(repo, this.slug);
      RepositoryNodes.push(repositoryNodeInst);
    }
    if (result.complete !== true) {
      RepositoryNodes.push(repositoryCollectionWarning(workspace, result));
    }
    return RepositoryNodes;
  }

  async getChildren() {
    const account = captureAccount(this._connectionManager);
    if (!account) return [];
    let quotaData = null;

    try {
      const cloudsmithAPI = this._createCloudsmithAPI();
      const result = await cloudsmithAPI.get(apiEndpoint(["quota", this.workspace]), {
        responseType: "object",
        retry: "safe-read",
        signal: this._signal,
      });

      if (result.ok && result.data.usage && typeof result.data.usage === "object") {
        quotaData = result.data;
      }
    } catch {
      // Quota access is optional for this node.
    }
    if (!isAccountCurrent(this._connectionManager, account)) return [];

    const children = [];
    children.push(new WorkspaceInfoNode(this.name || this.workspace, quotaData));

    const repos = await this.getRepositories();
    if (!isAccountCurrent(this._connectionManager, account)) return [];
    children.push(...repos);

    return children;
  }
}

function repositoryCollectionWarning(workspace, result) {
  const loaded = Array.isArray(result?.items) ? result.items.length : 0;
  const error = result?.failures?.[0]?.error;
  const detail = error
    ? formatApiError(error)
    : "A safe collection limit was reached before completeness was proven.";
  return new InfoNode(
    loaded > 0 ? "Repository list is incomplete" : "Failed to load repositories",
    loaded > 0 ? `${loaded.toLocaleString()} repositories loaded` : "Check your connection and try refreshing",
    `Repositories for ${workspace} are incomplete: ${detail}`,
    "warning"
  );
}

module.exports = WorkspaceNode;

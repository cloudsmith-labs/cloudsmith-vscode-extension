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

class WorkspaceNode {
  constructor(item, context, options = {}) {
    this.context = context;
    this._connectionManager = resolveConnectionManager(context, options.connectionManager);
    this._createCloudsmithAPI = options.createCloudsmithAPI
      || (() => new CloudsmithAPI(this.context));
    this._fetchWorkspaceRepositories = options.fetchWorkspaceRepositories
      || workspaceRepositoryFetcher.fetchWorkspaceRepositories;
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
    const result = await this._fetchWorkspaceRepositories(this.context, workspace, {
      account,
      connectionManager: this._connectionManager,
    });
    if (!isAccountCurrent(this._connectionManager, account) || result.stale) return [];

    if (result.error) {
      return [new InfoNode(
        "Failed to load repositories",
        "Check your connection and try refreshing",
        `Failed to load repositories for ${workspace}: ${formatApiError(result.error)}`,
        "warning"
      )];
    }

    const repositories = result.repositories;
    const RepositoryNodes = [];

    for (const repo of repositories) {
      const repositoryNodeInst = new repositoryNode(
        repo,
        this.slug,
        this.context,
        { connectionManager: this._connectionManager, createCloudsmithAPI: this._createCloudsmithAPI }
      );
      RepositoryNodes.push(repositoryNodeInst);
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

module.exports = WorkspaceNode;

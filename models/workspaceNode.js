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

class WorkspaceNode {
  constructor(item, context) {
    this.context = context;
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
    const context = this.context;
    const workspace = this.workspace;
    const result = await workspaceRepositoryFetcher.fetchWorkspaceRepositories(
      context,
      workspace
    );

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
        this.context
      );
      RepositoryNodes.push(repositoryNodeInst);
    }

    context.globalState.update("CloudsmithCache", {
      name: "Repositories",
      lastSync: Date.now(),
      workspaces: repositories,
    });
    return RepositoryNodes;
  }

  async getChildren() {
    let quotaData = null;

    try {
      const cloudsmithAPI = new CloudsmithAPI(this.context);
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

    const children = [];
    children.push(new WorkspaceInfoNode(this.name || this.workspace, quotaData));

    const repos = await this.getRepositories();
    children.push(...repos);

    return children;
  }
}

module.exports = WorkspaceNode;

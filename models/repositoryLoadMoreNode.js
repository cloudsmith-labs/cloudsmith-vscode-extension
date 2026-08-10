// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const vscode = require("vscode");

class RepositoryLoadMoreNode {
  constructor(repositoryNode, options = {}) {
    this.repositoryNode = repositoryNode;
    this.kind = options.kind === "package groups" ? "package groups" : "packages";
    this.loadedCount = Number.isSafeInteger(options.loadedCount) && options.loadedCount >= 0
      ? options.loadedCount
      : 0;
    this.pagination = options.pagination || null;
    this.retry = options.retry === true;
  }

  getTreeItem() {
    const loaded = this.loadedCount.toLocaleString();
    const progress = this.pagination?.countAuthoritative
      ? `showing ${loaded} of ${this.pagination.count.toLocaleString()}`
      : this.pagination
        ? `${loaded} loaded; page ${this.pagination.page} of ${this.pagination.pageTotal}`
        : `${loaded} loaded`;
    return {
      label: this.retry
        ? `Retry loading ${this.kind} (${progress})`
        : `Load more ${this.kind} (${progress})`,
      tooltip: this.retry
        ? `Retry the failed bounded page of repository ${this.kind}.`
        : `Load the next bounded page of repository ${this.kind}.`,
      collapsibleState: vscode.TreeItemCollapsibleState.None,
      contextValue: "repositoryLoadMore",
      iconPath: new vscode.ThemeIcon("ellipsis"),
      command: {
        command: "cloudsmith-vsc.loadMoreRepositoryPackages",
        title: `Load more ${this.kind}`,
        arguments: [this.repositoryNode],
      },
    };
  }

  getChildren() {
    return [];
  }
}

module.exports = RepositoryLoadMoreNode;

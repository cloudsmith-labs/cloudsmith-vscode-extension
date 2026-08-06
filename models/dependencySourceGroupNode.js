// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const vscode = require("vscode");

class DependencySourceGroupNode {
  constructor(tree, provider) {
    this.tree = tree;
    this.provider = provider;
  }

  getTreeItem() {
    const directCount = this.tree.dependencies.filter((dependency) => dependency.isDirect).length;
    const transitiveCount = this.tree.dependencies.length - directCount;
    const item = new vscode.TreeItem(
      this.tree.sourceFile,
      vscode.TreeItemCollapsibleState.Collapsed
    );
    item.description = `${this.tree.dependencies.length} dependencies `
      + `(${directCount} direct, ${transitiveCount} transitive)`;
    item.tooltip = [
      this.tree.sourceFile,
      `${this.tree.dependencies.length} dependencies`,
      `${directCount} direct`,
      `${transitiveCount} transitive`,
    ].join("\n");
    item.contextValue = "dependencyHealthSourceGroup";
    item.iconPath = new vscode.ThemeIcon("folder-library");
    return item;
  }

  getChildren() {
    return this.provider.buildDependencyNodesForTree(this.tree);
  }
}

module.exports = DependencySourceGroupNode;

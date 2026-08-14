// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const vscode = require("vscode");
const { getDependencyArtifactKey } = require("../util/dependencyRecord");

class DependencySourceGroupNode {
  constructor(tree, provider) {
    this.tree = tree;
    this.provider = provider;
  }

  getTreeItem() {
    const directCount = this.tree.dependencies.filter((dependency) => dependency.isDirect).length;
    const transitiveCount = this.tree.dependencies.length - directCount;
    const artifactCount = new Set(this.tree.dependencies.map(getDependencyArtifactKey)).size;
    const item = new vscode.TreeItem(
      this.tree.sourceFile,
      vscode.TreeItemCollapsibleState.Collapsed
    );
    item.description = `${this.tree.dependencies.length} occurrences, ${artifactCount} artifacts `
      + `(${directCount} direct, ${transitiveCount} transitive)`;
    item.tooltip = [
      this.tree.sourceFile,
      `${this.tree.dependencies.length} dependency occurrences`,
      `${artifactCount} unique artifacts`,
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

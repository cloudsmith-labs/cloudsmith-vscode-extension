// Package Groupde node treeview

const vscode = require("vscode");
const PackageDetailsNode = require("./packageDetailsNode");

class PackageGroupsNode {
  constructor(pkg, context) {
    this.context = context;
    this.num_downloads = { id: "Downloads", value: String(pkg.num_downloads) };
    this.last_push = { id: "Last Pushed", value: pkg.last_push };
    this.count = { id: "Count", value: String(pkg.count) };
    this.size = { id: "Size", value: String(pkg.size) };
    this.pkgDetails = [
      this.count,
      this.size,
      this.num_downloads,
      this.last_push,
    ];
    this.name = pkg.name;
    this.format = pkg.format || pkg.package_format || pkg.packageFormat || null;
    this.formats = Array.isArray(pkg.formats)
      ? pkg.formats
      : (Array.isArray(pkg.package_formats) ? pkg.package_formats : []);
    this.repo = pkg.repo;
    this.workspace = pkg.workspace;
  }

  getTreeItem() {
    let iconPath = new vscode.ThemeIcon('package');
    let pkg = this.name;

    return {
      label: pkg,
      collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
      contextValue: "packageGroup",
      iconPath: iconPath,
    };
  }

  async getPackageDetails() {
    let pkgDetails = this.pkgDetails;
    const PackageDetailsNodes = [];
    if (pkgDetails) {
      for (const id of pkgDetails) {
        const packageDetailsNodeInst = new PackageDetailsNode(id, this.context, this);
        PackageDetailsNodes.push(packageDetailsNodeInst);
      }
    }
    return PackageDetailsNodes;
  }

  async getChildren() {
    return this.getPackageDetails();
  }
}

module.exports = PackageGroupsNode;

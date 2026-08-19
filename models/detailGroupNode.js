// Collapsible container node that groups a subset of PackageDetailsNode instances.

const vscode = require("vscode");
const PackageDetailsNode = require("./packageDetailsNode");
const { inheritSelection } = require("../util/selectionProvenance");

class DetailGroupNode {
  /**
   * @param {string} label    Display label (e.g., "More Details").
   * @param {vscode.ThemeIcon} icon  ThemeIcon for the group.
   * @param {Array<{id: string, value: *}>} details  Array of detail objects.
   * @param {vscode.ExtensionContext} context
   */
  constructor(label, icon, details, context, owner = null) {
    this._label = label;
    this._icon = icon;
    this._details = details;
    this.context = context;
    inheritSelection(this, owner);
  }

  getTreeItem() {
    return {
      label: this._label,
      iconPath: this._icon,
      collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
      contextValue: "detailGroup",
    };
  }

  getChildren() {
    return this._details.map(d => new PackageDetailsNode(d, this.context, this));
  }
}

module.exports = DetailGroupNode;

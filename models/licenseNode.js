// License node treeview - shows license with risk-tier coloring

const vscode = require("vscode");
const { LicenseClassifier } = require("../util/licenseClassifier");
const { inheritSelection } = require("../util/selectionProvenance");

class LicenseNode {
  /**
   * @param   {Object|string|null} licenseSource  Cloudsmith license metadata or license string.
   * @param   {string|vscode.ExtensionContext|null} licenseUrlOrContext  License URL when using the legacy signature, or context when using metadata.
   * @param   {vscode.ExtensionContext} context
   */
  constructor(licenseSource, licenseUrlOrContext, context, owner = null) {
    if (context === undefined && licenseSource && typeof licenseSource === "object" && !Array.isArray(licenseSource)) {
      this.context = licenseUrlOrContext;
      this.licenseInfo = LicenseClassifier.inspect(licenseSource);
    } else {
      this.context = context;
      this.licenseInfo = LicenseClassifier.inspect({
        license: licenseSource,
        license_url: licenseUrlOrContext,
      });
    }

    this.license = this.licenseInfo.displayValue;
    this.licenseUrl = this.licenseInfo.licenseUrl || null;
    this.classification = this.licenseInfo;
    inheritSelection(this, owner);
  }

  _getIcon() {
    const iconMap = {
      "restrictive": new vscode.ThemeIcon("shield", new vscode.ThemeColor("errorForeground")),
      "cautious": new vscode.ThemeIcon("shield", new vscode.ThemeColor("editorWarning.foreground")),
      "permissive": new vscode.ThemeIcon("shield", new vscode.ThemeColor("testing.iconPassed")),
      "unknown": new vscode.ThemeIcon("shield", new vscode.ThemeColor("descriptionForeground")),
    };
    return iconMap[this.classification.tier] || iconMap["unknown"];
  }

  _getDescription() {
    return this.classification.metadata.description;
  }

  _buildTooltip() {
    const licenseLabel = this.license || "Not specified";
    const lines = [licenseLabel, "", this.classification.metadata.tooltip];
    if (this.classification.spdxLicense && this.classification.spdxLicense !== licenseLabel) {
      lines.push("", `Canonical SPDX: ${this.classification.spdxLicense}`);
    }
    if (this.classification.overrideApplied) {
      lines.push("", "Local restrictive override applied via cloudsmith-vsc.restrictiveLicenses.");
    }
    return lines.join("\n");
  }

  getTreeItem() {
    const licenseLabel = this.license || "No license specified";

    const treeItem = {
      label: `License: ${licenseLabel}`,
      description: this._getDescription(),
      tooltip: this._buildTooltip(),
      collapsibleState: vscode.TreeItemCollapsibleState.None,
      contextValue: this.licenseUrl ? "licenseDetailWithUrl" : "licenseDetail",
      iconPath: this._getIcon(),
    };

    // If license URL is available, clicking opens it in browser
    if (this.licenseUrl) {
      treeItem.command = {
        command: "cloudsmith-vsc.openLicenseUrl",
        title: "View license",
        arguments: [this],
      };
    }

    return treeItem;
  }

  getChildren() {
    return [];
  }
}

module.exports = LicenseNode;

// Entitlement token tree node.
// Shows entitlement token info under a repository for debugging access issues.

const vscode = require("vscode");
const InfoNode = require("./infoNode");

/**
 * Summary header node with an authoritative total only for complete collections.
 */
class EntitlementSummaryNode {
  constructor(entitlements, context, options = {}) {
    this.context = context;
    this.entitlements = entitlements || [];
    this.activeCount = this.entitlements.filter(e => e.is_active !== false).length;
    this.complete = options.complete === true;
    this.totalCount = Number.isSafeInteger(options.totalCount) && options.totalCount >= 0
      ? options.totalCount
      : null;
    this.failureCount = Number.isSafeInteger(options.failureCount) && options.failureCount >= 0
      ? options.failureCount
      : 0;
    this.termination = typeof options.termination === "string" ? options.termination : null;
  }

  getTreeItem() {
    const loadedCount = this.entitlements.length;
    const label = this.complete
      ? `Entitlement tokens: ${this.activeCount} active of ${loadedCount}`
      : `Entitlement tokens: ${this.activeCount} active among ${loadedCount} loaded (partial)`;
    const tooltip = this.complete
      ? `${loadedCount} entitlement token${loadedCount === 1 ? "" : "s"} configured`
      : this.totalCount !== null
        ? `${loadedCount} of ${this.totalCount} entitlement tokens loaded; the collection is incomplete`
        : `${loadedCount} entitlement tokens loaded; the configured total could not be verified`;
    return {
      label,
      tooltip,
      collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
      contextValue: "entitlementSummary",
      iconPath: new vscode.ThemeIcon("key"),
    };
  }

  getChildren() {
    const children = this.entitlements.map(e => new EntitlementNode(e, this.context));
    if (!this.complete) {
      children.unshift(new InfoNode(
        "Entitlement list is incomplete",
        this.failureCount > 0
          ? `${this.failureCount} page request${this.failureCount === 1 ? "" : "s"} failed`
          : "A safe collection limit was reached",
        "Loaded entitlement tokens remain available, but the configured total is not being claimed.",
        "warning"
      ));
    }
    return children;
  }
}

/**
 * Individual entitlement token node.
 */
class EntitlementNode {
  constructor(entitlement, context) {
    this.context = context;
    this.entitlement = entitlement;
    this.tokenName = entitlement.name || "Unnamed token";
    this.isActive = entitlement.is_active !== false;
    this.token = entitlement.token || null;
    this.scope = entitlement.package_query || null;
    this.slugPerm = entitlement.slug_perm || null;

    // Limits
    this.limitBandwidth = entitlement.limit_bandwidth || null;
    this.limitBandwidthUnit = entitlement.limit_bandwidth_unit || null;
    this.limitDownloads = entitlement.limit_num_downloads || null;
    this.limitClients = entitlement.limit_num_clients || null;
    this.limitDateRangeFrom = entitlement.limit_date_range_from || null;
    this.limitDateRangeTo = entitlement.limit_date_range_to || null;
  }

  getTreeItem() {
    const statusLabel = this.isActive ? "Active" : "Disabled";
    const descParts = [statusLabel];
    if (this.scope) {
      descParts.push(`Scope: ${this.scope}`);
    }

    const iconColor = this.isActive
      ? new vscode.ThemeColor("testing.iconPassed")
      : new vscode.ThemeColor("descriptionForeground");

    return {
      label: this.tokenName,
      description: descParts.join(" \u2014 "),
      tooltip: this._buildTooltip(),
      collapsibleState: vscode.TreeItemCollapsibleState.None,
      contextValue: "entitlement",
      iconPath: new vscode.ThemeIcon("key", iconColor),
    };
  }

  _buildTooltip() {
    const parts = [`Name: ${this.tokenName}`, `Status: ${this.isActive ? "Active" : "Disabled"}`];
    if (this.scope) {
      parts.push(`Package scope: ${this.scope}`);
    }
    if (this.limitBandwidth) {
      parts.push(`Bandwidth limit: ${this.limitBandwidth} ${this.limitBandwidthUnit || ""}`);
    }
    if (this.limitDownloads) {
      parts.push(`Download limit: ${this.limitDownloads}`);
    }
    if (this.limitClients) {
      parts.push(`Client limit: ${this.limitClients}`);
    }
    if (this.limitDateRangeFrom || this.limitDateRangeTo) {
      parts.push(`Valid: ${this.limitDateRangeFrom || "—"} to ${this.limitDateRangeTo || "—"}`);
    }
    return parts.join("\n");
  }

  getChildren() {
    return [];
  }
}

module.exports = { EntitlementSummaryNode };

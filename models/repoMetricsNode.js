// Repository storage and bandwidth metrics tree node.
// Shows usage indicators under each repository.

const vscode = require("vscode");

class RepoMetricsNode {
  /**
   * @param {Object} quota      Workspace quota from GET /v1/quota/{workspace}/
   * @param {Object} metrics    Per-repo metrics from GET /v1/metrics/packages/{workspace}/{repo}/
   * @param {Object} context    VS Code extension context.
   */
  constructor(quota, metrics, context) {
    this.context = context;
    this.quota = quota || {};
    this.metrics = metrics || {};
  }

  getTreeItem() {
    let description = "";

    try {
      // Quota is workspace-level: { usage: { display: { storage: {used, plan_limit}, bandwidth: {used, plan_limit} } } }
      const storage = this.quota?.usage?.display?.storage;
      const bandwidth = this.quota?.usage?.display?.bandwidth;

      const parts = [];
      if (storage?.used) parts.push(`Storage: ${storage.used} / ${storage.plan_limit}`);
      if (bandwidth?.used) parts.push(`Bandwidth: ${bandwidth.used} / ${bandwidth.plan_limit}`);

      // Download count from metrics
      if (this.metrics.downloads != null) {
        parts.push(`Downloads: ${this.metrics.downloads}`);
      }

      description = parts.join(" | ") || "No usage data available";
    } catch {
      description = "Could not load metrics";
    }

    return {
      label: "Usage",
      description: description,
      tooltip: this._buildTooltip(),
      collapsibleState: vscode.TreeItemCollapsibleState.None,
      contextValue: "repoMetrics",
      iconPath: new vscode.ThemeIcon("graph"),
    };
  }

  _buildTooltip() {
    const parts = ["Workspace quota"];
    const storage = this.quota?.usage?.display?.storage;
    const rawStorage = this.quota?.usage?.raw?.storage;
    const storagePct = rawStorage?.used != null && rawStorage?.plan_limit
      ? ` (${Math.round((rawStorage.used / rawStorage.plan_limit) * 100)}%)`
      : (storage?.percentage_used ? ` (${storage.percentage_used})` : "");

    parts.push(`Storage: ${storage?.used || "—"} / ${storage?.plan_limit || "—"}${storagePct}`);

    const bandwidth = this.quota?.usage?.display?.bandwidth;
    const rawBandwidth = this.quota?.usage?.raw?.bandwidth;
    if (bandwidth?.used) {
      const bwPct = rawBandwidth?.used != null && rawBandwidth?.plan_limit
        ? ` (${Math.round((rawBandwidth.used / rawBandwidth.plan_limit) * 100)}%)`
        : "";
      parts.push(`Bandwidth: ${bandwidth.used} / ${bandwidth.plan_limit || "\u221E"}${bwPct}`);
    }

    if (this.metrics.downloads != null) {
      parts.push(`Total downloads: ${this.metrics.downloads}`);
    }

    return parts.join("\n");
  }

  _formatBytes(bytes) {
    if (bytes == null) return "—";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    let val = bytes;
    while (val >= 1024 && i < units.length - 1) {
      val /= 1024;
      i++;
    }
    return `${val.toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
  }

  getChildren() {
    return [];
  }
}

module.exports = RepoMetricsNode;

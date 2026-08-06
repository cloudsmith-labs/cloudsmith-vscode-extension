// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const vscode = require("vscode");

class DependencySummaryNode {
  constructor(summary) {
    this.summary = {
      total: 0,
      direct: 0,
      transitive: 0,
      found: 0,
      notFound: 0,
      reachableViaUpstream: 0,
      unreachableViaUpstream: 0,
      ecosystems: {},
      coveragePercent: 0,
      checking: 0,
      vulnerable: 0,
      severityCounts: {},
      restrictiveLicenses: 0,
      weakCopyleftLicenses: 0,
      permissiveLicenses: 0,
      unknownLicenses: 0,
      policyViolations: 0,
      quarantined: 0,
      filterMode: null,
      filterLabel: null,
      filteredCount: 0,
      ...summary,
    };
  }

  getTreeItem() {
    const item = new vscode.TreeItem(buildPrimaryLabel(this.summary), vscode.TreeItemCollapsibleState.None);
    item.description = buildSecondaryLabel(this.summary);
    item.tooltip = buildTooltip(this.summary);
    item.contextValue = "dependencyHealthSummary";
    item.iconPath = this.summary.checking > 0
      ? new vscode.ThemeIcon("loading~spin")
      : new vscode.ThemeIcon("graph");
    return item;
  }

  getChildren() {
    return [];
  }
}

function buildPrimaryLabel(summary) {
  if (summary.filterMode && summary.filterLabel) {
    return `Showing ${summary.filteredCount} of ${summary.total} dependencies (filtered: ${summary.filterLabel})`;
  }

  const parts = [
    `${summary.total} dependencies (${summary.direct} direct, ${summary.transitive} transitive)`,
    `${summary.coveragePercent}% coverage`,
  ];

  if (summary.vulnerable > 0) {
    parts.push(`${summary.vulnerable} vulnerable`);
  }

  if (summary.restrictiveLicenses > 0) {
    parts.push(`${summary.restrictiveLicenses} restrictive licenses`);
  }

  return parts.join(" · ");
}

function buildSecondaryLabel(summary) {
  const parts = [];
  const severityParts = buildSeverityParts(summary.severityCounts);

  if (severityParts.length > 0) {
    parts.push(severityParts.join(" · "));
  }

  if (summary.quarantined > 0) {
    parts.push(`${summary.quarantined} would be quarantined by policy`);
  } else if (summary.policyViolations > 0) {
    parts.push(`${summary.policyViolations} policy violations`);
  }

  if (summary.notFound > 0) {
    const upstreamParts = [`${summary.notFound} not found in Cloudsmith`];
    if (summary.reachableViaUpstream > 0) {
      upstreamParts.push(`${summary.reachableViaUpstream} reachable via configured upstream proxies`);
    }
    if (summary.unreachableViaUpstream > 0) {
      upstreamParts.push(`${summary.unreachableViaUpstream} not reachable`);
    }
    parts.push(upstreamParts.join(" · "));
  }

  if (parts.length > 0) {
    return parts.join(" · ");
  }

  const ecosystemEntries = Object.entries(summary.ecosystems || {});
  if (ecosystemEntries.length > 1) {
    return ecosystemEntries
      .map(([ecosystem, count]) => `${formatEcosystemLabel(ecosystem)}: ${count}`)
      .join(" · ");
  }

  return "";
}

function buildSeverityParts(severityCounts) {
  const order = ["Critical", "High", "Medium", "Low"];
  return order
    .filter((severity) => severityCounts && severityCounts[severity] > 0)
    .map((severity) => `${severityCounts[severity]} ${severity}`);
}

function buildTooltip(summary) {
  const lines = [
    `${summary.total} total dependencies`,
    `${summary.direct} direct`,
    `${summary.transitive} transitive`,
    `${summary.found} covered in Cloudsmith`,
    `${summary.notFound} not found`,
    `${summary.coveragePercent}% coverage`,
  ];

  if (summary.vulnerable > 0) {
    lines.push(`${summary.vulnerable} vulnerable`);
    for (const part of buildSeverityParts(summary.severityCounts)) {
      lines.push(`  ${part}`);
    }
  }

  if (summary.restrictiveLicenses > 0 || summary.weakCopyleftLicenses > 0 || summary.unknownLicenses > 0) {
    lines.push("");
    lines.push("License summary");
    lines.push(`  ${summary.permissiveLicenses} permissive`);
    lines.push(`  ${summary.weakCopyleftLicenses} weak copyleft`);
    lines.push(`  ${summary.restrictiveLicenses} restrictive`);
    lines.push(`  ${summary.unknownLicenses} unknown`);
  }

  if (summary.policyViolations > 0 || summary.quarantined > 0) {
    lines.push("");
    lines.push(`Policy violations: ${summary.policyViolations}`);
    lines.push(`Would be quarantined: ${summary.quarantined}`);
  }

  if (summary.notFound > 0) {
    lines.push("");
    lines.push(`Reachable via upstream: ${summary.reachableViaUpstream}`);
    lines.push(`Not reachable: ${summary.unreachableViaUpstream}`);
  }

  const ecosystemEntries = Object.entries(summary.ecosystems || {});
  if (ecosystemEntries.length > 0) {
    lines.push("");
    for (const [ecosystem, count] of ecosystemEntries) {
      lines.push(`${formatEcosystemLabel(ecosystem)}: ${count}`);
    }
  }

  return lines.join("\n");
}

function formatEcosystemLabel(ecosystem) {
  const value = String(ecosystem || "");
  if (!value) {
    return "";
  }
  if (value === "npm") {
    return "npm";
  }
  return value.charAt(0).toUpperCase() + value.slice(1);
}

module.exports = DependencySummaryNode;

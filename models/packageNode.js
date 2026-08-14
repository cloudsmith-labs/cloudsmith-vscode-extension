// Copyright 2026 Cloudsmith Ltd. All rights reserved.

// Package node treeview

const vscode = require("vscode");
const { LicenseClassifier } = require("../util/licenseClassifier");
const { getFormatIconPath } = require("../util/formatIcons");
const { packageCollectionIdentity } = require("../util/collectionIdentity");
const { fromApiPackageRecord } = require("../domain/packageAdapters");
const VulnerabilitySummaryNode = require("./vulnerabilitySummaryNode");

class PackageNode {
  constructor(pkg, context, options = {}) {
    const packageModel = fromApiPackageRecord(pkg);
    this.package = packageModel;
    this.context = context;
    this._connectionManager = options.connectionManager || null;
    this._vulnerabilityStateService = options.vulnerabilityStateService || null;
    this._registerVulnerabilitySummary = typeof options.registerVulnerabilitySummary === "function"
      ? options.registerVulnerabilitySummary
      : () => {};
    this._lifecycleSignal = options.lifecycleSignal || null;
    this.slug = { id: "Slug", value: packageModel.slug };
    this.slug_perm = { id: "Slug", value: packageModel.packageIdentifier };
    this.name = packageModel.name;
    this.status_str = { id: "Status", value: packageModel.status };
    this.downloads = { id: "Downloads", value: String(packageModel.downloads ?? 0) };
    this.version = { id: "Version", value: packageModel.version };
    this.format = packageModel.format;
    this.uploaded_at = { id: "Uploaded at", value: packageModel.uploadedAt };
    this.repository = packageModel.repository;
    this.namespace = packageModel.workspace;
    this.is_copyable = packageModel.copyable;
    this.status_reason = packageModel.statusReason;
    this.checksum_sha256 = packageModel.checksumSha256;
    this.version_digest = packageModel.versionDigest;
    this.cdn_url = packageModel.cdnUrl;
    this.filename = packageModel.filename;

    // Raw status for permissibility icon logic
    this.status_str_raw = packageModel.status;

    // Policy fields from API response
    this.policy_violated = packageModel.policy.violated;
    this.deny_policy_violated = packageModel.policy.denyViolated;
    this.license_policy_violated = packageModel.policy.licenseViolated;
    this.vulnerability_policy_violated = packageModel.policy.vulnerabilityViolated;

    // Structured policy detail entries with human-readable labels and Yes/No values
    this.policy_violated_detail = { id: "Policy violated", value: this.policy_violated ? "Yes" : "No" };
    this.deny_policy_violated_detail = { id: "Deny policy violated (legacy)", value: this.deny_policy_violated ? "Yes" : "No" };
    this.license_policy_violated_detail = { id: "License policy violated (legacy)", value: this.license_policy_violated ? "Yes" : "No" };
    this.vulnerability_policy_violated_detail = { id: "Vulnerability policy violated (legacy)", value: this.vulnerability_policy_violated ? "Yes" : "No" };

    // Vulnerability fields from API response
    // slug_perm_raw must be a plain string for API URLs.
    // Handle both raw API data (string) and double-wrapped nodes ({ id, value } object).
    this.slug_perm_raw = packageModel.packageIdentifier;
    this.num_vulnerabilities = packageModel.vulnerability.count !== null
      ? packageModel.vulnerability.count
      : packageModel.vulnerability.detected ? -1 : null;
    this.max_severity = packageModel.vulnerability.maxSeverity;
    this.vulnerability_scan_results_url = null;
    this.security_scan_status = packageModel.vulnerability.scanStatus;
    this._vulnerabilityIdentity = packageCollectionIdentity(packageModel);
    this._vulnerabilitySummary = new VulnerabilitySummaryNode(packageModel, this.context, {
        connectionManager: this._connectionManager,
        vulnerabilityStateService: this._vulnerabilityStateService,
        lifecycleSignal: this._lifecycleSignal,
      });
    this._registerVulnerabilitySummary(
      this._vulnerabilityIdentity,
      this._vulnerabilitySummary,
      this
    );

    // License fields from API response (may be absent in list endpoint)
    this.licenseInfo = LicenseClassifier.inspect({
      spdx_license: packageModel.license.spdx,
      license: packageModel.license.declared,
      raw_license: packageModel.license.raw,
      license_url: packageModel.license.url,
    });
    this.spdx_license = this.licenseInfo.spdxLicense;
    this.raw_license = this.licenseInfo.rawLicense;
    this.license = this.licenseInfo.displayValue;
    this.license_url = this.licenseInfo.licenseUrl;

    // Raw tags for upstream origin detection
    this.tags_raw = legacyTags(packageModel.tags);

    // Determine upstream origin from tags
    this.upstreamSource = this._detectUpstreamSource();
    this.origin_detail = {
      id: "Source",
      value: this.upstreamSource ? `Cached from ${this.upstreamSource}` : "This repository",
    };

    if (packageModel.tags.info.length > 0) {
      // handle tags since we split tags between tags.info and tags.version as both may not coexist at the same time
      if (packageModel.tags.version.length > 0) {
        this.tags = {
          id: "Tags",
          value: String([packageModel.tags.info, packageModel.tags.version]),
        }; //combine tags sources
      } else {
        this.tags = { id: "Tags", value: packageModel.tags.info };
      }
    } else {
      if (packageModel.tags.version.length > 0) {
        this.tags = { id: "Tags", value: packageModel.tags.version };
      } else {
        this.tags = { id: "Tags", value: "" };
      }
    }

  }

  /**
   * Detect if this package was cached from an upstream source.
   * Cloudsmith tags upstream-sourced packages with the upstream source name.
   * Returns the upstream name if found, or null for direct uploads.
   */
  _detectUpstreamSource() {
    const info = this.tags_raw.info;
    if (!info || !Array.isArray(info)) {
      return null;
    }
    for (const tag of info) {
      if (typeof tag === 'string' && tag.toLowerCase().includes('upstream')) {
        return tag;
      }
    }
    return null;
  }

  _getFormatIcon() {
    const format = this.format;
    if (format === "raw") {
      return new vscode.ThemeIcon("file-binary");
    }
    return getFormatIconPath(format, this.context && this.context.extensionPath);
  }

  _buildTooltip() {
    const parts = [this.name, this.format];
    const status = this.status_str_raw;
    if (status) {
      parts.push(`Status: ${status}`);
    }
    if (this.upstreamSource) {
      parts.push(`Origin: Upstream (${this.upstreamSource})`);
    }
    if (this.deny_policy_violated) {
      parts.push("Deny policy violated");
    } else if (this.policy_violated) {
      parts.push("Policy violated (non-deny)");
    }
    if (this.license_policy_violated) {
      parts.push("License policy violated");
    }
    if (this.vulnerability_policy_violated) {
      parts.push("Vulnerability policy violated");
    }
    if (this.status_str_raw === "Quarantined" || this.policy_violated || this.deny_policy_violated) {
      parts.push("Right-click \u2192 Explain quarantine or find safe version");
    }
    return parts.join(" — ");
  }

  getTreeItem() {
    let iconPath;
    const pkg = this.name;
    const status = this.status_str_raw;

    const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
    const showPermissibility = config.get("showPermissibilityIndicators") !== false;

    if (showPermissibility) {
      // Priority: quarantined > deny violated > policy violated > syncing > format icon
      if (status === "Quarantined" || this.deny_policy_violated) {
        iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
      } else if (this.policy_violated) {
        iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
      } else if (status === "Completed") {
        iconPath = this._getFormatIcon();
      } else {
        // Syncing, awaiting scan, etc.
        iconPath = new vscode.ThemeIcon('sync');
      }
    } else {
      iconPath = this._getFormatIcon();
    }

    // Build description: combine quarantine and upstream origin info
    const descParts = [];
    if (status === "Quarantined") {
      descParts.push("Quarantined \u2014 right-click for details");
    }
    if (this.upstreamSource) {
      descParts.push("(via upstream)");
    }
    const description = descParts.length > 0 ? descParts.join(" ") : undefined;

    return {
      label: pkg,
      description: description,
      tooltip: this._buildTooltip(),
      collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
      contextValue: status === "Quarantined" ? "packageQuarantined" : "package",
      iconPath: iconPath,
    };
  }

  getChildren() {
    const PackageDetailsNode = require("./packageDetailsNode");
    const DetailGroupNode = require("./detailGroupNode");
    const children = [];

    // --- Primary details (always visible on expand) ---

    // 1. Status
    children.push(new PackageDetailsNode(this.status_str, this.context));

    // 2. Version
    children.push(new PackageDetailsNode(this.version, this.context));

    // 3. License
    const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
    const showLicense = config.get("showLicenseIndicators") !== false;
    if (showLicense) {
      const LicenseNode = require("./licenseNode");
      children.push(new LicenseNode(this.licenseInfo, this.context));
    }

    // 4. Vulnerability summary (expandable)
    children.push(this._vulnerabilitySummary);

    // 5. Quarantine Reason (if quarantined)
    if (this.status_str_raw === "Quarantined" && this.status_reason) {
      const truncated = this.status_reason.length > 80
        ? this.status_reason.substring(0, 80) + "..."
        : this.status_reason;
      children.push(new PackageDetailsNode({ id: "Quarantine reason", value: truncated }, this.context));
    }

    // 6. Policy Violated
    children.push(new PackageDetailsNode(this.policy_violated_detail, this.context));

    // Legacy policy fields (optional)
    const legacyConfig = vscode.workspace.getConfiguration("cloudsmith-vsc");
    if (legacyConfig.get("showLegacyPolicies")) {
      children.push(new PackageDetailsNode(this.deny_policy_violated_detail, this.context));
      children.push(new PackageDetailsNode(this.license_policy_violated_detail, this.context));
      children.push(new PackageDetailsNode(this.vulnerability_policy_violated_detail, this.context));
    }

    // 6. Origin
    children.push(new PackageDetailsNode(this.origin_detail, this.context));

    // 7. "More Details" (collapsible sub-group)
    const secondaryDetails = [
      { id: "Format", value: this.format },
      this.downloads,
      this.tags,
      this.uploaded_at,
      this.slug,
      this.slug_perm,
      { id: "Namespace", value: this.namespace },
    ];
    children.push(new DetailGroupNode(
      "More Details",
      new vscode.ThemeIcon("ellipsis"),
      secondaryDetails,
      this.context
    ));

    return children;
  }
}

function legacyTags(tags) {
  const value = {};
  if (tags.info.length > 0) value.info = tags.info;
  if (tags.version.length > 0) value.version = tags.version;
  return Object.freeze(value);
}

module.exports = PackageNode;

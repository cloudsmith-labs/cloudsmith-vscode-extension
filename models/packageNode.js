// Package node treeview

const vscode = require("vscode");
const { LicenseClassifier } = require("../util/licenseClassifier");
const { getFormatIconPath } = require("../util/formatIcons");

class PackageNode {
  constructor(pkg, context) {
    this.context = context;
    this.slug = { id: "Slug", value: pkg.slug };
    this.slug_perm = { id: "Slug", value: pkg.slug_perm };
    this.name = pkg.name;
    this.status_str = { id: "Status", value: pkg.status_str };
    this.downloads = { id: "Downloads", value: String(pkg.downloads) };
    this.version = { id: "Version", value: pkg.version };
    this.format = pkg.format;
    this.uploaded_at = { id: "Uploaded at", value: pkg.uploaded_at };
    this.repository = pkg.repository;
    this.namespace = pkg.namespace;
    this.status_reason = pkg.status_reason || null;
    this.checksum_sha256 = pkg.checksum_sha256 || null;
    this.version_digest = pkg.version_digest || null;
    this.cdn_url = pkg.cdn_url || null;
    this.filename = pkg.filename || null;

    // Raw status for permissibility icon logic
    this.status_str_raw = pkg.status_str;

    // Policy fields from API response
    this.policy_violated = pkg.policy_violated || false;
    this.deny_policy_violated = pkg.deny_policy_violated || false;
    this.license_policy_violated = pkg.license_policy_violated || false;
    this.vulnerability_policy_violated = pkg.vulnerability_policy_violated || false;

    // Structured policy detail entries with human-readable labels and Yes/No values
    this.policy_violated_detail = { id: "Policy violated", value: this.policy_violated ? "Yes" : "No" };
    this.deny_policy_violated_detail = { id: "Deny policy violated (legacy)", value: this.deny_policy_violated ? "Yes" : "No" };
    this.license_policy_violated_detail = { id: "License policy violated (legacy)", value: this.license_policy_violated ? "Yes" : "No" };
    this.vulnerability_policy_violated_detail = { id: "Vulnerability policy violated (legacy)", value: this.vulnerability_policy_violated ? "Yes" : "No" };

    // Vulnerability fields from API response
    // slug_perm_raw must be a plain string for API URLs.
    // Handle both raw API data (string) and double-wrapped nodes ({ id, value } object).
    this.slug_perm_raw = (typeof pkg.slug_perm === 'object' && pkg.slug_perm !== null && pkg.slug_perm.value)
      ? pkg.slug_perm.value
      : pkg.slug_perm;
    this.num_vulnerabilities = pkg.num_vulnerabilities || 0;
    this.max_severity = pkg.max_severity || null;
    this.vulnerability_scan_results_url = pkg.vulnerability_scan_results_url || null;
    this.security_scan_status = pkg.security_scan_status || null;

    // If the list endpoint didn't include num_vulnerabilities but the scan status
    // indicates vulnerabilities were detected, set a flag so the summary node appears.
    if (this.num_vulnerabilities === 0 && this.security_scan_status &&
        this.security_scan_status.toLowerCase().includes("detected")) {
      this.num_vulnerabilities = -1; // sentinel: "has vulns but count unknown"
      this.max_severity = this.max_severity || "Unknown";
    }

    // License fields from API response (may be absent in list endpoint)
    this.licenseInfo = LicenseClassifier.inspect(pkg);
    this.spdx_license = this.licenseInfo.spdxLicense;
    this.raw_license = this.licenseInfo.rawLicense;
    this.license = this.licenseInfo.displayValue;
    this.license_url = this.licenseInfo.licenseUrl;

    // Raw tags for upstream origin detection
    this.tags_raw = pkg.tags || {};

    // Determine upstream origin from tags
    this.upstreamSource = this._detectUpstreamSource();
    this.origin_detail = {
      id: "Source",
      value: this.upstreamSource ? `Cached from ${this.upstreamSource}` : "This repository",
    };

    if (pkg.tags && pkg.tags.info) {
      // handle tags since we split tags between tags.info and tags.version as both may not coexist at the same time
      if (pkg.tags.version) {
        this.tags = {
          id: "Tags",
          value: String([pkg.tags.info, pkg.tags.version]),
        }; //combine tags sources
      } else {
        this.tags = { id: "Tags", value: pkg.tags.info };
      }
    } else {
      if (pkg.tags && pkg.tags.version) {
        this.tags = { id: "Tags", value: pkg.tags.version };
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
    if (this.num_vulnerabilities !== 0) {
      const VulnerabilitySummaryNode = require("./vulnerabilitySummaryNode");
      children.push(new VulnerabilitySummaryNode({
        namespace: this.namespace,
        repository: this.repository,
        slug_perm: this.slug_perm_raw,
        num_vulnerabilities: this.num_vulnerabilities,
        max_severity: this.max_severity,
      }, this.context));
    }

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

module.exports = PackageNode;

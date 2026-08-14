// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const vscode = require("vscode");
const { LicenseClassifier } = require("../util/licenseClassifier");
const { getFormatIconPath } = require("../util/formatIcons");
const { canonicalFormat } = require("../util/packageNameNormalizer");
const {
  getDependencyPackageSourceDisplayLocation,
  getDependencyPackageSourceDisplayRef,
  getDependencyQualifierDisplayValue,
  getDependencySourceLabel,
} = require("../util/dependencyRecord");
const { getPackageVulnerabilityState } = require("../util/packageVulnerabilities");

class DependencyHealthNode {
  constructor(dep, cloudsmithMatchOrContext, maybeContext, maybeOptions) {
    const hasExplicitCloudsmithMatch = arguments.length >= 3
      || (
        cloudsmithMatchOrContext
        && typeof cloudsmithMatchOrContext === "object"
        && (
          Object.prototype.hasOwnProperty.call(cloudsmithMatchOrContext, "status_str")
          || Object.prototype.hasOwnProperty.call(cloudsmithMatchOrContext, "slug_perm")
          || Object.prototype.hasOwnProperty.call(cloudsmithMatchOrContext, "namespace")
        )
      );

    this.context = hasExplicitCloudsmithMatch ? maybeContext : cloudsmithMatchOrContext;
    this.options = hasExplicitCloudsmithMatch ? (maybeOptions || {}) : (maybeContext || {});
    this._vulnerabilitySummary = null;
    this.name = dep.name;
    this.declarationName = dep.declarationName || dep.name;
    this.declaredConstraint = dep.declaredConstraint || null;
    this.resolvedVersion = dep.resolvedVersion || null;
    this.versionState = dep.versionState || null;
    this.resolutionSource = dep.resolutionSource || null;
    this.sourceManifest = dep.sourceManifest || null;
    this.packageSource = dep.packageSource || null;
    this.lookupEligibility = dep.lookupEligibility || null;
    this.qualifiers = dep.qualifiers || {};
    this.environmentMarker = dep.environmentMarker || null;
    this.normalizedName = dep.normalizedName || null;
    this.cloudsmithLookupDetail = dep.cloudsmithLookupDetail || null;
    this.legacyVersion = Object.prototype.hasOwnProperty.call(dep, "legacyVersion")
      ? dep.legacyVersion
      : dep.version;
    // Retained for existing display and diagnostic consumers during M4 migration.
    this.declaredVersion = this.resolvedVersion
      || (this.versionState === "exact-declaration" ? this.legacyVersion : null)
      || this.declaredConstraint
      || (Object.prototype.hasOwnProperty.call(dep, "version") ? dep.version : dep.legacyVersion);
    this.format = dep.format || canonicalFormat(dep.ecosystem);
    this.ecosystem = dep.ecosystem || this.format;
    this.sourceFile = dep.sourceFile || null;
    this.isDev = Boolean(dep.devDependency || dep.isDevelopmentDependency);
    this.isDevelopmentDependency = this.isDev;
    this.isDirect = dep.isDirect !== false;
    this.parent = dep.parent || (Array.isArray(dep.parentChain) ? dep.parentChain[dep.parentChain.length - 1] : null);
    this.parentChain = Array.isArray(dep.parentChain) ? dep.parentChain.slice() : [];
    this.transitives = Array.isArray(dep.transitives) ? dep.transitives.slice() : [];
    this.cloudsmithMatch = dep.cloudsmithPackage
      || dep.cloudsmithMatch
      || (hasExplicitCloudsmithMatch ? cloudsmithMatchOrContext : null);
    this.cloudsmithStatus = dep.cloudsmithStatus || (this.cloudsmithMatch ? "FOUND" : null);
    this.vulnerabilities = dep.vulnerabilities || null;
    this.licenseData = dep.license || null;
    this.policy = dep.policy || null;
    this.upstreamStatus = dep.upstreamStatus || null;
    this.upstreamDetail = dep.upstreamDetail || null;
    this._childMode = this.options.childMode || "details";
    this._treeChildren = Array.isArray(this.options.treeChildren) ? this.options.treeChildren.slice() : [];
    this._duplicateReference = Boolean(this.options.duplicateReference);
    this._firstOccurrencePath = this.options.firstOccurrencePath || null;
    this._dimmedForFilter = Boolean(this.options.dimmedForFilter);
    this._treeChildFactory = typeof this.options.treeChildFactory === "function"
      ? this.options.treeChildFactory
      : null;
    this.licenseInfo = this._deriveLicenseInfo();
    this.state = this._deriveState();

    if (this.cloudsmithMatch) {
      this.namespace = this.cloudsmithMatch.namespace;
      this.repository = this.cloudsmithMatch.repository;
      this.slug_perm = { id: "Slug", value: this.cloudsmithMatch.slug_perm };
      this.slug_perm_raw = this.cloudsmithMatch.slug_perm;
      this.is_copyable = this.cloudsmithMatch.is_copyable === true
        ? true
        : this.cloudsmithMatch.is_copyable === false
          ? false
          : null;
      this.version = { id: "Version", value: this.cloudsmithMatch.version };
      this.status_str = { id: "Status", value: this.cloudsmithMatch.status_str };
      this.checksum_sha256 = this.cloudsmithMatch.checksum_sha256 || null;
      this.version_digest = this.cloudsmithMatch.version_digest || null;
      this.tags_raw = this.cloudsmithMatch.tags || {};
      this.cdn_url = this.cloudsmithMatch.cdn_url || null;
      this.filename = this.cloudsmithMatch.filename || null;
      const vulnerabilityState = getPackageVulnerabilityState(this.cloudsmithMatch);
      this.num_vulnerabilities = vulnerabilityState.count !== null
        ? vulnerabilityState.count
        : vulnerabilityState.detected ? -1 : null;
      this.max_severity = this.cloudsmithMatch.max_severity || null;
      this.status_reason = this.cloudsmithMatch.status_reason || null;
    }
    this.spdx_license = this.licenseInfo.spdxLicense;
    this.raw_license = this.licenseInfo.rawLicense;
    this.license = this.licenseInfo.displayValue;
    this.license_url = this.licenseInfo.licenseUrl;
  }

  _deriveLicenseInfo() {
    if (this.licenseData) {
      return LicenseClassifier.inspect({
        license: this.licenseData.display || this.licenseData.raw || null,
        spdx_license: this.licenseData.spdx || null,
        license_url: this.licenseData.url || null,
      });
    }

    if (this.cloudsmithMatch) {
      return LicenseClassifier.inspect(this.cloudsmithMatch);
    }

    return LicenseClassifier.inspect(null);
  }

  _deriveState() {
    if (this.cloudsmithStatus === "CHECKING") {
      return "checking";
    }

    if (this.cloudsmithStatus === "ABSENT" || this.cloudsmithStatus === "NOT_FOUND") {
      return "not_found";
    }

    if (this.cloudsmithStatus === "UNRESOLVED") {
      return "unresolved";
    }

    if (this.cloudsmithStatus === "NOT_APPLICABLE") {
      return "not_applicable";
    }

    if (this.cloudsmithStatus === "LOOKUP_FAILED") {
      return "lookup_failed";
    }

    if (this.cloudsmithStatus === "LOOKUP_INCOMPLETE" || this.cloudsmithStatus === "RATE_LIMITED") {
      return "lookup_incomplete";
    }

    if (this.cloudsmithStatus !== "FOUND" || !this.cloudsmithMatch) {
      return "unknown";
    }

    if (this._isQuarantined()) {
      return "quarantined";
    }

    if (
      this._hasVulnerabilities()
      || this._hasVulnerabilityUncertainty()
      || this._hasPolicyViolation()
      || this._hasRestrictiveLicense()
      || this._hasWeakCopyleftLicense()
    ) {
      return "violated";
    }

    return "available";
  }

  _hasVulnerabilities() {
    const vulnerabilities = this._getVulnerabilityData();
    return Boolean(vulnerabilities && (
      vulnerabilities.detected === true
      || (vulnerabilities.countKnown !== false && vulnerabilities.count > 0)
    ));
  }

  _hasVulnerabilityUncertainty() {
    return this._getVulnerabilityData()?.unknown === true;
  }

  _hasCriticalVulnerability() {
    const vulnerabilities = this._getVulnerabilityData();
    return Boolean(this._hasVulnerabilities() && vulnerabilities.maxSeverity === "Critical");
  }

  _hasHighVulnerability() {
    const vulnerabilities = this._getVulnerabilityData();
    return Boolean(this._hasVulnerabilities() && vulnerabilities.maxSeverity === "High");
  }

  _hasMediumOrLowVulnerability() {
    return this._hasVulnerabilities()
      && !this._hasCriticalVulnerability()
      && !this._hasHighVulnerability();
  }

  _hasRestrictiveLicense() {
    return Boolean(
      (this.licenseData && this.licenseData.classification === "restrictive")
      || this.licenseInfo.tier === "restrictive"
    );
  }

  _hasWeakCopyleftLicense() {
    return Boolean(
      (this.licenseData && this.licenseData.classification === "weak_copyleft")
      || this.licenseInfo.tier === "cautious"
    );
  }

  _hasPolicyViolation() {
    const policy = this._getPolicyData();
    return Boolean(policy && policy.violated);
  }

  _isQuarantined() {
    const policy = this._getPolicyData();
    return Boolean(policy && (policy.quarantined || policy.denied));
  }

  _getLicenseLabel() {
    if (this.licenseData) {
      return this.licenseData.display || this.licenseData.spdx || this.licenseData.raw || null;
    }

    return this.licenseInfo.displayValue || null;
  }

  _shouldFlagRestrictiveLicenses() {
    const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
    return config.get("flagRestrictiveLicenses") !== false;
  }

  _getContextValue() {
    if (this.cloudsmithStatus === "CHECKING") {
      return "dependencyHealthSyncing";
    }

    if (this.cloudsmithStatus === "NOT_APPLICABLE") {
      return "dependencyHealthNotApplicable";
    }

    if (this.cloudsmithStatus === "ABSENT" || this.cloudsmithStatus === "NOT_FOUND") {
      if (this.upstreamStatus === "reachable") {
        return "dependencyHealthUpstreamReachable";
      }

      if (this.upstreamStatus === "no_proxy" || this.upstreamStatus === "unreachable") {
        return "dependencyHealthUpstreamUnreachable";
      }

      return "dependencyHealthMissing";
    }

    if (this.cloudsmithStatus !== "FOUND") {
      return "dependencyHealthUnknown";
    }

    if (this._isQuarantined()) {
      return "dependencyHealthQuarantined";
    }

    if (this._hasVulnerabilities()) {
      return "dependencyHealthVulnerable";
    }

    return "dependencyHealthFound";
  }

  _getStateIcon() {
    if (this.cloudsmithStatus === "CHECKING") {
      return new vscode.ThemeIcon("loading~spin");
    }

    if (this.cloudsmithStatus === "NOT_APPLICABLE") {
      return getFormatIconPath(this.format, this.context && this.context.extensionPath, {
        fallbackIcon: new vscode.ThemeIcon("circle-slash", new vscode.ThemeColor("descriptionForeground")),
      });
    }

    if (this.cloudsmithStatus !== "FOUND") {
      return getFormatIconPath(this.format, this.context && this.context.extensionPath, {
        fallbackIcon: new vscode.ThemeIcon(
          this.state === "not_found" ? "package" : "question",
          new vscode.ThemeColor("descriptionForeground")
        ),
      });
    }

    if (this._isQuarantined()) {
      return new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground"));
    }

    if (this._hasCriticalVulnerability()) {
      return new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground"));
    }

    if (this._hasHighVulnerability() || this._hasRestrictiveLicense()) {
      return new vscode.ThemeIcon("warning", new vscode.ThemeColor("charts.orange"));
    }

    if (
      this._hasMediumOrLowVulnerability()
      || this._hasVulnerabilityUncertainty()
      || this._hasWeakCopyleftLicense()
      || this._hasPolicyViolation()
    ) {
      return new vscode.ThemeIcon("warning", new vscode.ThemeColor("charts.yellow"));
    }

    return new vscode.ThemeIcon("check", new vscode.ThemeColor("testing.iconPassed"));
  }

  _buildVersionPrefix() {
    return this.declaredVersion || "Unknown version";
  }

  _buildVulnerabilityDescription() {
    const vulnerabilities = this._getVulnerabilityData();
    if (!vulnerabilities) {
      return null;
    }
    if (vulnerabilities.unknown && !this._hasVulnerabilities()) {
      return "Vulnerability status unknown";
    }
    if (!this._hasVulnerabilities()) return null;

    if (
      vulnerabilities.detailsLoaded
      && vulnerabilities.maxSeverity
      && vulnerabilities.severityCounts
      && vulnerabilities.severityCounts[vulnerabilities.maxSeverity]
    ) {
      const maxCount = vulnerabilities.severityCounts[vulnerabilities.maxSeverity];
      return `Vulnerabilities found (${maxCount} ${vulnerabilities.maxSeverity})`;
    }

    if (vulnerabilities.countKnown === false) {
      const severity = vulnerabilities.maxSeverity && vulnerabilities.maxSeverity !== "Unknown"
        ? ` (${vulnerabilities.maxSeverity})`
        : "";
      return `Vulnerabilities detected${severity}`;
    }
    const countLabel = String(vulnerabilities.count);
    const summary = vulnerabilities.maxSeverity && vulnerabilities.maxSeverity !== "Unknown"
      ? `${countLabel} ${vulnerabilities.maxSeverity}`
      : countLabel;
    return `Vulnerabilities found (${summary})`;
  }

  _buildMissingDescription() {
    switch (this.cloudsmithStatus) {
      case "ABSENT":
      case "NOT_FOUND":
        return "Not found in Cloudsmith";
      case "UNRESOLVED":
        return "Version unresolved";
      case "LOOKUP_FAILED":
        return "Cloudsmith lookup failed";
      case "LOOKUP_INCOMPLETE":
        return "Cloudsmith lookup incomplete";
      case "RATE_LIMITED":
        return "Cloudsmith lookup rate limited";
      case "NOT_APPLICABLE":
        return "Cloudsmith lookup not applicable";
      default:
        return "Cloudsmith status unknown";
    }
  }

  _buildDescription() {
    if (this._duplicateReference) {
      return `${this._buildVersionPrefix()} (see first occurrence)`;
    }

    let detail;
    if (this.cloudsmithStatus === "CHECKING") {
      detail = "Checking coverage";
    } else if (this.cloudsmithStatus !== "FOUND") {
      detail = this._buildMissingDescription();
    } else if (this._isQuarantined()) {
      detail = "Quarantined";
    } else if (this._hasVulnerabilities()) {
      detail = this._buildVulnerabilityDescription();
    } else if (this._shouldFlagRestrictiveLicenses() && this._hasRestrictiveLicense()) {
      detail = this._getLicenseLabel()
        ? `Restrictive license (${this._getLicenseLabel()})`
        : "Restrictive license";
    } else if (this._hasWeakCopyleftLicense()) {
      detail = this._getLicenseLabel()
        ? `Weak copyleft license (${this._getLicenseLabel()})`
        : "Weak copyleft license";
    } else if (this._hasPolicyViolation()) {
      detail = "Policy violation";
    } else {
      detail = "No issues found";
    }

    if (this._dimmedForFilter && this.cloudsmithStatus === "FOUND") {
      detail += " · context";
    }

    return `${this._buildVersionPrefix()}${this._buildQualifierSuffix()} — ${detail}`;
  }

  _buildQualifierSuffix() {
    const values = [
      this.qualifiers.targetFramework,
      this.qualifiers.platform,
      this.qualifiers.classifier,
      this.qualifiers.stage,
    ].filter(Boolean);
    return values.length > 0 ? ` [${values.join(", ")}]` : "";
  }

  _buildTooltip() {
    const lines = [`${this.name} ${this._buildVersionPrefix()}`.trim()];
    lines.push(`Format: ${this.format}`);
    lines.push(`Relationship: ${this._getRelationshipLabel()}`);
    const sourceLabel = getDependencySourceLabel(this);
    if (sourceLabel) {
      lines.push(`Source: ${sourceLabel}`);
    }
    for (const [key, value] of Object.entries(this.qualifiers)) {
      const displayValue = getDependencyQualifierDisplayValue(key, value);
      lines.push(`${formatQualifierLabel(key)}: ${displayValue}`);
    }
    if (this.packageSource && this.packageSource.kind) {
      lines.push(`Package source: ${this.packageSource.kind}`);
      const displayLocation = getDependencyPackageSourceDisplayLocation(this.packageSource);
      if (displayLocation) lines.push(`Source location: ${displayLocation}`);
      const displayBranch = getDependencyPackageSourceDisplayRef(this.packageSource.branch);
      const displayRevision = getDependencyPackageSourceDisplayRef(this.packageSource.revision);
      if (displayBranch) lines.push(`Source branch: ${displayBranch}`);
      if (displayRevision) lines.push(`Source revision: ${displayRevision}`);
    }
    if (this.isDev) {
      lines.push("Development dependency");
    }

    lines.push("");

    if (this.cloudsmithStatus === "CHECKING") {
      lines.push("Coverage check in progress.");
    } else if (this.cloudsmithStatus === "ABSENT" || this.cloudsmithStatus === "NOT_FOUND") {
      lines.push("Not found in the configured Cloudsmith workspace.");
      if (this.upstreamDetail) {
        lines.push(this.upstreamDetail);
      } else {
        lines.push("This package may need to be uploaded or fetched through an upstream.");
      }
    } else if (this.cloudsmithStatus !== "FOUND" || !this.cloudsmithMatch) {
      lines.push(this._buildMissingDescription() + ".");
      if (this.cloudsmithLookupDetail) {
        lines.push(this.cloudsmithLookupDetail);
      }
    } else {
      lines.push(`Found in Cloudsmith (${this.cloudsmithMatch.repository})`);
      const policy = this._getPolicyData();
      if (policy && policy.status) {
        lines.push(`Status: ${policy.status}`);
      } else if (this.cloudsmithMatch.status_str) {
        lines.push(`Status: ${this.cloudsmithMatch.status_str}`);
      }

      const vulnerabilities = this._getVulnerabilityData();
      if (vulnerabilities) {
        if (this._hasVulnerabilities()) {
          const severitySummary = Object.entries(vulnerabilities.severityCounts || {})
            .map(([severity, count]) => `${count} ${severity}`)
            .join(", ");
          const suffix = severitySummary
            ? ` (${severitySummary})`
            : vulnerabilities.maxSeverity && vulnerabilities.maxSeverity !== "Unknown"
              ? ` (${vulnerabilities.maxSeverity})`
              : "";
          const countLabel = vulnerabilities.countKnown === false
            ? "Detected"
            : String(vulnerabilities.count);
          lines.push(`Vulnerabilities: ${countLabel}${suffix}`);

          if (Array.isArray(vulnerabilities.entries)) {
            for (const entry of vulnerabilities.entries) {
              const fixText = entry.fixVersion ? `Fix: ${entry.fixVersion}` : "No fix available";
              lines.push(`  ${entry.cveId} (${entry.severity}) — ${fixText}`);
            }
          }
        } else if (vulnerabilities.unknown) {
          lines.push("Vulnerabilities: Unknown");
        } else {
          lines.push("Vulnerabilities: none known");
        }
      }

      if (this.licenseData) {
        lines.push(
          `License: ${this._getLicenseLabel() || "No license detected"} (${formatLicenseClassification(this.licenseData.classification)})`
        );
      } else if (this.licenseInfo.displayValue) {
        lines.push(
          `License: ${this.licenseInfo.displayValue} (${formatLicenseClassification(classificationFromTier(this.licenseInfo.tier))})`
        );
      } else {
        lines.push("License: No license detected");
      }

      if (policy && policy.violated) {
        lines.push(`Policy violated: ${policy.denied ? "deny" : "yes"}`);
      }

      if (policy && policy.statusReason) {
        lines.push(`Policy reason: ${policy.statusReason}`);
      }
    }

    if (this._duplicateReference && this._firstOccurrencePath) {
      lines.push("");
      lines.push(`See first occurrence: ${this._firstOccurrencePath}`);
    }

    return lines.join("\n");
  }

  _buildDetailsChildren() {
    if (!this.cloudsmithMatch || this.state === "checking") {
      return [];
    }

    const PackageDetailsNode = require("./packageDetailsNode");
    const children = [];

    children.push(new PackageDetailsNode({
      id: "Status",
      value: this.policy && this.policy.status ? this.policy.status : this.cloudsmithMatch.status_str,
    }, this.context));

    children.push(new PackageDetailsNode({
      id: "Version",
      value: this.cloudsmithMatch.version,
    }, this.context));

    const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
    if (config.get("showLicenseIndicators") !== false && this.licenseInfo && this.licenseInfo.displayValue) {
      const LicenseNode = require("./licenseNode");
      children.push(new LicenseNode(this.licenseInfo, this.context));
    }

    const vulnerabilities = this._getVulnerabilityData();
    if (vulnerabilities && this._hasVulnerabilities()) {
      if (!this._vulnerabilitySummary) {
        const VulnerabilitySummaryNode = require("./vulnerabilitySummaryNode");
        this._vulnerabilitySummary = new VulnerabilitySummaryNode({
          namespace: this.cloudsmithMatch.namespace,
          repository: this.cloudsmithMatch.repository,
          slug_perm: this.cloudsmithMatch.slug_perm,
          num_vulnerabilities: vulnerabilities.countKnown === false ? -1 : vulnerabilities.count,
          max_severity: vulnerabilities.maxSeverity,
        }, this.context, {
          connectionManager: this.options.connectionManager,
          vulnerabilityStateService: this.options.vulnerabilityStateService,
        });
        this.options.registerVulnerabilitySummary?.(
          this._vulnerabilitySummary.identity,
          this._vulnerabilitySummary,
          this
        );
      }
      children.push(this._vulnerabilitySummary);
    }

    const policy = this._getPolicyData();
    if (policy) {
      children.push(new PackageDetailsNode({
        id: "Policy violated",
        value: policy.violated ? "Yes" : "No",
      }, this.context));

      if (policy.statusReason) {
        children.push(new PackageDetailsNode({
          id: "Policy reason",
          value: policy.statusReason,
        }, this.context));
      }
    }

    return children;
  }

  _getVulnerabilityData() {
    if (this.vulnerabilities) {
      return this.vulnerabilities;
    }

    if (!this.cloudsmithMatch) {
      return null;
    }

    const state = getPackageVulnerabilityState(this.cloudsmithMatch);
    if (state.count === 0 && !state.detected && !state.unknown) {
      return {
        count: 0,
        maxSeverity: null,
        cveIds: [],
        hasFixAvailable: false,
        severityCounts: {},
        entries: [],
        detailsLoaded: false,
      };
    }

    const count = state.count !== null ? state.count : (state.candidateCount || 0);
    const maxSeverity = this.cloudsmithMatch.max_severity || null;
    const severityCounts = maxSeverity ? { [maxSeverity]: 1 } : {};
    return {
      count,
      countKnown: state.count !== null,
      detected: state.detected,
      unknown: state.unknown,
      maxSeverity,
      cveIds: [],
      hasFixAvailable: false,
      severityCounts,
      entries: [],
      detailsLoaded: false,
    };
  }

  _getPolicyData() {
    if (this.policy) {
      return this.policy;
    }

    if (!this.cloudsmithMatch) {
      return null;
    }

    const status = String(this.cloudsmithMatch.status_str || "").trim() || null;
    const quarantined = status === "Quarantined";
    const denied = quarantined || Boolean(this.cloudsmithMatch.deny_policy_violated);
    const violated = denied
      || Boolean(this.cloudsmithMatch.policy_violated)
      || Boolean(this.cloudsmithMatch.license_policy_violated)
      || Boolean(this.cloudsmithMatch.vulnerability_policy_violated);

    return {
      violated,
      denied,
      quarantined,
      status,
      statusReason: String(this.cloudsmithMatch.status_reason || "").trim() || null,
    };
  }

  _getRelationshipLabel() {
    if (this.isDirect) {
      return "Direct";
    }

    const firstParent = this.parentChain[0] || this.parent || "unknown";
    return `Transitive (via ${firstParent})`;
  }

  getTreeItem() {
    const item = new vscode.TreeItem(
      `${this.name}${this.isDev ? " (dev)" : ""}`,
      this._getCollapsibleState()
    );
    item.description = this._buildDescription();
    item.tooltip = this._buildTooltip();
    item.contextValue = this._getContextValue();
    item.iconPath = this._getStateIcon();
    return item;
  }

  _getCollapsibleState() {
    if (this._childMode === "tree") {
      if (this._duplicateReference || this._treeChildren.length === 0) {
        return vscode.TreeItemCollapsibleState.None;
      }
      return vscode.TreeItemCollapsibleState.Collapsed;
    }

    return this.cloudsmithMatch
      ? vscode.TreeItemCollapsibleState.Collapsed
      : vscode.TreeItemCollapsibleState.None;
  }

  getChildren() {
    if (this._childMode === "tree") {
      if (!this._treeChildFactory || this._duplicateReference || this._treeChildren.length === 0) {
        return [];
      }
      return this._treeChildFactory(this._treeChildren);
    }

    return this._buildDetailsChildren();
  }
}

function formatLicenseClassification(classification) {
  switch (classification) {
    case "permissive":
      return "Permissive";
    case "weak_copyleft":
      return "Weak copyleft";
    case "restrictive":
      return "Restrictive";
    default:
      return "Unclassified";
  }
}

function classificationFromTier(tier) {
  switch (tier) {
    case "permissive":
      return "permissive";
    case "cautious":
      return "weak_copyleft";
    case "restrictive":
      return "restrictive";
    default:
      return "unknown";
  }
}

function formatQualifierLabel(key) {
  return String(key || "")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/^./, (character) => character.toUpperCase());
}

module.exports = DependencyHealthNode;

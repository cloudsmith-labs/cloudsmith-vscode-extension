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
  normalizeDependencyDisplayValue,
} = require("../util/dependencyRecord");
const {
  PackageAdapterError,
  fromApiPackageRecord,
  fromDependencyHealthNode,
} = require("../domain/packageAdapters");
const { PackageDomainError } = require("../domain/package");
const packageDomain = require("../domain/package");
const { InstallCommandBuilder } = require("../util/installCommandBuilder");
const { hasInstallGuidanceForPackage } = require("../domain/installGuidanceSupport");
const { markSelection } = require("../util/selectionProvenance");
const {
  PACKAGE_ACTION_SURFACES,
  derivePackageActionCapabilities,
  encodePackageActionContext,
} = require("../domain/packageActionCapabilities");

const UNEXPECTED_PACKAGE_MATCH_WARNING =
  "[Cloudsmith] Unexpected dependency package match validation failure.";

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
    markSelection(this, this.options.connectionManager || null);
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
    this.qualifiers = dep.qualifiers
      && typeof dep.qualifiers === "object"
      && !Array.isArray(dep.qualifiers)
      ? dep.qualifiers
      : {};
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
    const explicitPackageMatch = hasExplicitCloudsmithMatch ? cloudsmithMatchOrContext : null;
    const packageMatchSupplied = hasDependencyPackageEvidence(dep)
      || (explicitPackageMatch !== null && explicitPackageMatch !== undefined);
    const canonicalPackage = canonicalMatchedPackage(dep, explicitPackageMatch);
    const requestedCloudsmithStatus = dep.cloudsmithStatus || (packageMatchSupplied ? "FOUND" : null);
    this.package = requestedCloudsmithStatus === "FOUND" ? canonicalPackage : null;
    // Retain the compatibility projection only for trusted canonical values. A rejected
    // optional match must not remain available as a second exact-identity authority.
    this.cloudsmithMatch = this.package;
    this.cloudsmithStatus = requestedCloudsmithStatus === "FOUND" && !this.package
      ? "LOOKUP_FAILED"
      : requestedCloudsmithStatus;
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

    if (this.package) {
      this.namespace = this.package.workspace;
      this.repository = this.package.repository;
      const packageIdentifier = this.package.packageIdentifier;
      this.slug_perm = { id: "Slug", value: packageIdentifier };
      this.slug_perm_raw = packageIdentifier;
      this.is_copyable = this.package.copyable;
      this.version = { id: "Version", value: this.package.version };
      this.status_str = { id: "Status", value: this.package.status };
      this.checksum_sha256 = this.package.checksumSha256;
      this.version_digest = this.package.versionDigest;
      this.tags_raw = legacyTags(this.package.tags);
      this.cdn_url = this.package.cdnUrl;
      this.filename = this.package.filename;
      const vulnerabilityState = canonicalVulnerabilityState(this.package.vulnerability);
      this.num_vulnerabilities = vulnerabilityState.count !== null
        ? vulnerabilityState.count
        : vulnerabilityState.detected ? -1 : null;
      this.max_severity = this.package.vulnerability.maxSeverity;
      this.status_reason = this.package.statusReason;
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

    if (this.package) {
      return LicenseClassifier.inspect({
        license: this.package.license.declared,
        spdx_license: this.package.license.spdx,
        raw_license: this.package.license.raw,
        license_url: this.package.license.url,
      });
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

    if (this.cloudsmithStatus !== "FOUND" || !this.package) {
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

  getActionCapabilities() {
    const denied = this._isQuarantined();
    const quarantined = this._getPolicyData()?.quarantined === true;
    return derivePackageActionCapabilities({
      surface: PACKAGE_ACTION_SURFACES.DEPENDENCY_HEALTH,
      found: this.cloudsmithStatus === "FOUND" && this.package?.identityState === "exact",
      exact: this.package?.identityState === "exact",
      copyable: this.package?.copyable === true,
      installGuidance: !denied && hasInstallGuidanceForPackage(
        packageDomain,
        InstallCommandBuilder,
        this.package
      ),
      vulnerable: this._hasVulnerabilities(),
      quarantined,
      policyViolation: this._hasPolicyViolation(),
      restrictiveLicense: this._hasRestrictiveLicense(),
    });
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

    return encodePackageActionContext(
      "dependencyHealthActions",
      this.getActionCapabilities()
    ) || "dependencyHealthUnknown";
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
    } else {
      const materialStates = [];
      if (this._isQuarantined()) materialStates.push("Quarantined");
      if (this._hasVulnerabilities() || this._hasVulnerabilityUncertainty()) {
        const vulnerabilityDescription = this._buildVulnerabilityDescription();
        if (vulnerabilityDescription) materialStates.push(vulnerabilityDescription);
      }
      if (this._shouldFlagRestrictiveLicenses() && this._hasRestrictiveLicense()) {
        materialStates.push(this._getLicenseLabel()
          ? `Restrictive license (${this._getLicenseLabel()})`
          : "Restrictive license");
      } else if (this._hasWeakCopyleftLicense()) {
        materialStates.push(this._getLicenseLabel()
          ? `Weak copyleft license (${this._getLicenseLabel()})`
          : "Weak copyleft license");
      }
      if (this._hasPolicyViolation()) materialStates.push("Policy violation");
      detail = materialStates.length > 0 ? materialStates.join(" · ") : "No issues found";
    }

    if (this._dimmedForFilter && this.cloudsmithStatus === "FOUND") {
      detail += " · context";
    }

    return `${this._buildVersionPrefix()}${this._buildQualifierSuffix()} — ${detail}`;
  }

  _buildQualifierSuffix() {
    const values = ["targetFramework", "platform", "classifier", "stage"]
      .map((key) => normalizeDependencyDisplayValue(
        getDependencyQualifierDisplayValue(key, this.qualifiers[key])
      ))
      .filter((value) => value != null);
    return values.length > 0 ? ` [${values.join(", ")}]` : "";
  }

  _buildTooltip() {
    const lines = [`${this.name} ${this._buildVersionPrefix()}`.trim()];
    lines.push(`Format: ${this.format}`);
    lines.push(`Relationship: ${this._getRelationshipLabel()}`);
    const sourceLabel = normalizeDependencyDisplayValue(getDependencySourceLabel(this));
    if (sourceLabel) {
      lines.push(`Source: ${sourceLabel}`);
    }
    for (const [key, value] of Object.entries(this.qualifiers)) {
      const displayLabel = normalizeDependencyDisplayValue(formatQualifierLabel(key));
      const displayValue = normalizeDependencyDisplayValue(
        getDependencyQualifierDisplayValue(key, value)
      );
      if (displayLabel && displayValue != null) {
        lines.push(`${displayLabel}: ${displayValue}`);
      }
    }
    const packageSourceKind = normalizeDependencyDisplayValue(
      this.packageSource && this.packageSource.kind
    );
    if (packageSourceKind) {
      lines.push(`Package source: ${packageSourceKind}`);
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
      const upstreamDetail = normalizeDependencyDisplayValue(this.upstreamDetail);
      if (upstreamDetail) {
        lines.push(upstreamDetail);
      } else {
        lines.push("This package may need to be uploaded or fetched through an upstream.");
      }
    } else if (this.cloudsmithStatus !== "FOUND" || !this.package) {
      lines.push(this._buildMissingDescription() + ".");
      const lookupDetail = normalizeDependencyDisplayValue(this.cloudsmithLookupDetail);
      if (lookupDetail) {
        lines.push(lookupDetail);
      }
    } else {
      lines.push(`Found in Cloudsmith (${this.package.repository})`);
      const policy = this._getPolicyData();
      if (policy && policy.status) {
        lines.push(`Status: ${policy.status}`);
      } else if (this.package.status) {
        lines.push(`Status: ${this.package.status}`);
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
    if (!this.package || this.state === "checking") {
      return [];
    }

    const PackageDetailsNode = require("./packageDetailsNode");
    const children = [];

    const statusSource = this.policy && this.policy.status
      ? this.policy.status
      : this.package.status;
    const status = typeof statusSource === "string"
      ? normalizeDependencyDisplayValue(statusSource)
      : null;
    if (status) {
      children.push(new PackageDetailsNode({
        id: "Status",
        value: status,
      }, this.context, this));
    }

    children.push(new PackageDetailsNode({
      id: "Version",
      value: this.package.version,
    }, this.context, this));

    const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
    if (config.get("showLicenseIndicators") !== false && this.licenseInfo && this.licenseInfo.displayValue) {
      const LicenseNode = require("./licenseNode");
      children.push(new LicenseNode(this.licenseInfo, this.context, undefined, this));
    }

    const vulnerabilities = this._getVulnerabilityData();
    if (vulnerabilities && this._hasVulnerabilities() && this.package) {
      if (!this._vulnerabilitySummary) {
        const VulnerabilitySummaryNode = require("./vulnerabilitySummaryNode");
        this._vulnerabilitySummary = new VulnerabilitySummaryNode(this.package, this.context, {
          connectionManager: this.options.connectionManager,
          vulnerabilityStateService: this.options.vulnerabilityStateService,
          selectionOwner: this,
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
      }, this.context, this));

      if (policy.statusReason) {
        children.push(new PackageDetailsNode({
          id: "Policy reason",
          value: policy.statusReason,
        }, this.context, this));
      }
    }

    return children;
  }

  _getVulnerabilityData() {
    if (this.vulnerabilities) {
      return this.vulnerabilities;
    }

    if (!this.package) {
      return null;
    }

    const state = canonicalVulnerabilityState(this.package.vulnerability);
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
    const maxSeverity = this.package.vulnerability.maxSeverity;
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

    if (!this.package) {
      return null;
    }

    const status = this.package.status;
    const quarantined = status === "Quarantined";
    const denied = quarantined || this.package.policy.denyViolated;
    const violated = this.package.policy.violated
      || this.package.policy.denyViolated
      || this.package.policy.licenseViolated
      || this.package.policy.vulnerabilityViolated;

    return {
      violated,
      denied,
      quarantined,
      status,
      statusReason: this.package.statusReason,
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

    return this.package
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

function canonicalMatchedPackage(dep, explicitMatch) {
  try {
    const dependencyPackage = hasDependencyPackageEvidence(dep)
      ? fromApiPackageRecord(fromDependencyHealthNode(dep))
      : null;
    const explicitPackage = explicitMatch === null || explicitMatch === undefined
      ? null
      : fromApiPackageRecord(explicitMatch, {
        coordinateName: dep.name,
        coordinateQualifiers: dep.qualifiers,
      });
    if (dependencyPackage && explicitPackage) {
      return fromDependencyHealthNode({
        cloudsmithPackage: dependencyPackage,
        cloudsmithMatch: explicitPackage,
      });
    }
    if (dependencyPackage) return dependencyPackage;
    if (!explicitPackage) return null;

    const boundary = { package: explicitPackage };
    for (const field of [
      "workspace",
      "namespace",
      "cloudsmithWorkspace",
      "repository",
      "cloudsmithRepo",
      "packageIdentifier",
      "slug_perm",
      "slug_perm_raw",
    ]) {
      const descriptor = Object.getOwnPropertyDescriptor(dep, field);
      if (descriptor) Object.defineProperty(boundary, field, descriptor);
    }
    return fromDependencyHealthNode(boundary);
  } catch (error) {
    if (shouldReportUnexpectedPackageMatchError(error)) {
      reportUnexpectedPackageMatchError();
    }
    return null;
  }
}

function shouldReportUnexpectedPackageMatchError(error) {
  try {
    if (PackageDomainError.isTrusted(error)) return false;
    if (!PackageAdapterError.isTrusted(error)) return true;
    const unexpected = Object.getOwnPropertyDescriptor(error, "unexpected");
    return Boolean(unexpected && "value" in unexpected && unexpected.value === true);
  } catch {
    return true;
  }
}

function reportUnexpectedPackageMatchError() {
  try {
    console.warn(UNEXPECTED_PACKAGE_MATCH_WARNING);
  } catch {
    // Tree rendering must remain available even if the internal reporting sink fails.
  }
}

function hasDependencyPackageEvidence(dep) {
  return ["package", "cloudsmithPackage", "cloudsmithMatch"].some((field) => {
    const descriptor = Object.getOwnPropertyDescriptor(dep, field);
    return Boolean(descriptor && (
      !Object.prototype.hasOwnProperty.call(descriptor, "value")
      || (descriptor.value !== null && descriptor.value !== undefined)
    ));
  });
}

function canonicalVulnerabilityState(value) {
  return {
    count: value.count,
    detected: value.detected,
    unknown: value.evidence === "unknown",
    candidateCount: value.count,
  };
}

function legacyTags(tags) {
  const value = {};
  if (tags.info.length > 0) value.info = tags.info;
  if (tags.version.length > 0) value.version = tags.version;
  return Object.freeze(value);
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
  const words = String(key || "").replace(/([a-z])([A-Z])/g, "$1 $2");
  return words
    ? `${words[0].toUpperCase()}${words.slice(1).toLowerCase()}`
    : "";
}

module.exports = DependencyHealthNode;

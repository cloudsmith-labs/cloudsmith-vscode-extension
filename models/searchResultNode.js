// Search result node treeview.
// Similar to PackageNode but includes repository context and status-based icons.

const vscode = require("vscode");
const path = require("path");
const PackageDetailsNode = require("./packageDetailsNode");
const { LicenseClassifier } = require("../util/licenseClassifier");
const { getPackageVulnerabilityCount } = require("../util/packageVulnerabilities");
const { packageCollectionIdentity } = require("../util/collectionIdentity");
const VulnerabilitySummaryNode = require("./vulnerabilitySummaryNode");

class SearchResultNode {
    constructor(pkg, context, options = {}) {
        this.context = context;
        this._connectionManager = options.connectionManager || null;
        this._vulnerabilityStateService = options.vulnerabilityStateService || null;
        this._registerVulnerabilitySummary = typeof options.registerVulnerabilitySummary === "function"
            ? options.registerVulnerabilitySummary
            : () => {};

        // Store fields matching PackageNode's shape so existing commands work
        this.name = pkg.name;
        this.format = pkg.format;
        this.repository = pkg.repository;
        this.namespace = pkg.namespace;
        this.is_copyable = pkg.is_copyable === true
            ? true
            : pkg.is_copyable === false
                ? false
                : null;
        this.status_str = { id: "Status", value: pkg.status_str };
        this.slug = { id: "Slug", value: pkg.slug };
        this.slug_perm = { id: "Slug", value: pkg.slug_perm };
        this.downloads = { id: "Downloads", value: String(pkg.downloads) };
        this.version = { id: "Version", value: pkg.version };
        this.uploaded_at = { id: "Uploaded at", value: pkg.uploaded_at };
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
        this.slug_perm_raw = (typeof pkg.slug_perm === 'object' && pkg.slug_perm !== null && pkg.slug_perm.value)
            ? pkg.slug_perm.value
            : pkg.slug_perm;
        this.num_vulnerabilities = getPackageVulnerabilityCount(pkg);
        this.max_severity = pkg.max_severity || null;
        this.vulnerability_scan_results_url = pkg.vulnerability_scan_results_url || null;
        this.security_scan_status = pkg.security_scan_status || null;
        this._vulnerabilityIdentity = packageCollectionIdentity({
            namespace: this.namespace,
            repository: this.repository,
            slug_perm: this.slug_perm_raw,
        });
        this._vulnerabilitySummary = new VulnerabilitySummaryNode({
                namespace: this.namespace,
                repository: this.repository,
                slug_perm: this.slug_perm_raw,
                num_vulnerabilities: this.num_vulnerabilities,
                max_severity: this.max_severity,
                security_scan_status: this.security_scan_status,
            }, this.context, {
                connectionManager: this._connectionManager,
                vulnerabilityStateService: this._vulnerabilityStateService,
            });
        this._registerVulnerabilitySummary(
            this._vulnerabilityIdentity,
            this._vulnerabilitySummary,
            this
        );

        // License fields from API response (may be absent in list endpoint)
        this.licenseInfo = cloneCanonicalValue(LicenseClassifier.inspect(pkg));
        this.spdx_license = this.licenseInfo.spdxLicense;
        this.raw_license = this.licenseInfo.rawLicense;
        this.license = this.licenseInfo.displayValue;
        this.license_url = this.licenseInfo.licenseUrl;

        // Raw tags for upstream origin detection
        this.tags_raw = cloneCanonicalValue(pkg.tags) || {};

        // Determine upstream origin from tags
        this.upstreamSource = this._detectUpstreamSource();
        this.origin_detail = {
            id: "Source",
            value: this.upstreamSource ? `Cached from ${this.upstreamSource}` : "This repository",
        };

        // Tags handling (same pattern as PackageNode)
        if (this.tags_raw.info) {
            if (this.tags_raw.version) {
                this.tags = { id: "Tags", value: String([this.tags_raw.info, this.tags_raw.version]) };
            } else {
                this.tags = { id: "Tags", value: this.tags_raw.info };
            }
        } else {
            if (this.tags_raw.version) {
                this.tags = { id: "Tags", value: this.tags_raw.version };
            } else {
                this.tags = { id: "Tags", value: "" };
            }
        }

    }

    /**
     * Detect if this package was cached from an upstream source.
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
        const iconURI = "file_type_" + format + ".svg";
        return path.join(__filename, "..", "..", "media", "vscode_icons", iconURI);
    }

    _buildTooltip() {
        const parts = [this.name, this.version.value, this.format, `Repository: ${this.repository}`];
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

        // Build description: version + repo + optional quarantine/upstream info
        const descParts = [`${this.version.value}  (${this.repository})`];
        if (status === "Quarantined") {
            descParts.push("Quarantined");
        }
        if (this.upstreamSource) {
            descParts.push("(via upstream)");
        }

        return {
            label: this.name,
            description: descParts.join(" "),
            tooltip: this._buildTooltip(),
            collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
            contextValue: status === "Quarantined" ? "packageQuarantined" : "package",
            iconPath: iconPath,
        };
    }

    getChildren() {
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

function cloneCanonicalValue(value, depth = 0) {
    if (
        value === null
        || typeof value === "string"
        || typeof value === "number"
        || typeof value === "boolean"
    ) {
        return value;
    }
    if (depth >= 10) return null;
    if (Array.isArray(value)) {
        return value.map(item => cloneCanonicalValue(item, depth + 1));
    }
    if (value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
        const clone = {};
        for (const [key, nested] of Object.entries(value)) {
            const cloned = cloneCanonicalValue(nested, depth + 1);
            if (cloned !== undefined) clone[key] = cloned;
        }
        return clone;
    }
    return undefined;
}

module.exports = SearchResultNode;

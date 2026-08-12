// Copyright 2026 Cloudsmith Ltd. All rights reserved.

// Upstream indicator node treeview.
// Appears at the top of a repository's package list when upstream sources are configured.

const vscode = require("vscode");
const {
    formatUpstreamFailureCategory,
    formatUpstreamOrigin,
    formatUpstreamText,
} = require("../util/upstreamPresentation");

const MAX_TOOLTIP_UPSTREAMS = 20;

class UpstreamIndicatorNode {
    constructor(upstreams, repositoryContext = {}, context, options = {}) {
        this.context = context;
        this.upstreams = upstreams;
        this.failedFormats = Array.isArray(options.failedFormats)
            ? options.failedFormats.filter(format => typeof format === "string")
            : [];
        this.uninspectedFormats = Array.isArray(options.uninspectedFormats)
            ? options.uninspectedFormats.filter(format => typeof format === "string")
            : [];
        this.failures = Array.isArray(options.failures) ? options.failures : [];
        this.complete = options.complete === true
            && this.failedFormats.length === 0
            && this.uninspectedFormats.length === 0;
        this.workspace = repositoryContext.workspace || null;
        this.slug = repositoryContext.slug || null;
        this.name = repositoryContext.name || null;
    }

    getTreeItem() {
        const count = this.upstreams.length;
        const active = this.upstreams.filter(u => u.is_active !== false).length;
        const partial = !this.complete;
        const label = partial
            ? count > 0
                ? `Upstreams: ${active} active among ${count} loaded (partial)`
                : "Upstreams: incomplete"
            : count > 0
                ? `Upstreams: ${active} active of ${count} configured`
                : "Upstreams: none configured";
        const unavailableFormats = [...new Set([
            ...this.failedFormats,
            ...this.uninspectedFormats,
        ])];
        const safeFailureLines = this.failures.slice(0, 20).map(failure => (
            `${formatUpstreamText(failure.format, "unknown")} — ${formatUpstreamFailureCategory(
                failure.category
            )}`
        ));
        const failureDetail = unavailableFormats.length > 0
            ? `\nCould not inspect:\n${safeFailureLines.length > 0
                ? safeFailureLines.join("\n")
                : unavailableFormats.join(", ")}`
            : partial ? "\nThe configured total could not be verified." : "";
        const displayedUpstreams = this.upstreams.slice(0, MAX_TOOLTIP_UPSTREAMS);
        const loadedUpstreamDetail = displayedUpstreams.map((upstream) => (
            `${formatUpstreamText(upstream.name, "Unnamed")} (${formatUpstreamText(
                formatUpstreamOrigin(
                    upstream.origin
                ),
                "Origin unavailable"
            )})`
        )).join("\n");
        const omittedDetail = this.upstreams.length > displayedUpstreams.length
            ? `\nShowing ${displayedUpstreams.length} of ${this.upstreams.length} loaded upstreams.`
            : "";

        return {
            label,
            tooltip: `${loadedUpstreamDetail}${omittedDetail}${failureDetail}`,
            collapsibleState: vscode.TreeItemCollapsibleState.None,
            contextValue: "upstreamIndicator",
            iconPath: new vscode.ThemeIcon('cloud'),
        };
    }

    getChildren() {
        return [];
    }
}

module.exports = UpstreamIndicatorNode;

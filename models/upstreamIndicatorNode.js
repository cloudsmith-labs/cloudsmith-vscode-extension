// Upstream indicator node treeview.
// Appears at the top of a repository's package list when upstream sources are configured.

const vscode = require("vscode");
const {
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
            ? `Upstreams: ${active} active among ${count} loaded (partial)`
            : `Upstreams: ${active} active of ${count} configured`;
        const unavailableFormats = [...new Set([
            ...this.failedFormats,
            ...this.uninspectedFormats,
        ])];
        const failureDetail = unavailableFormats.length > 0
            ? `\nCould not load formats: ${unavailableFormats.join(", ")}`
            : partial ? "\nThe configured total could not be verified." : "";

        const displayedUpstreams = this.upstreams.slice(0, MAX_TOOLTIP_UPSTREAMS);
        const loadedUpstreamDetail = displayedUpstreams.map((upstream) => (
            `${formatUpstreamText(upstream.name, "Unnamed")} (${formatUpstreamOrigin(upstream.upstream_url)})`
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

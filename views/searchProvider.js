// Search results tree data provider for the Package Search view.

const vscode = require("vscode");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { apiEndpoint } = require("../util/apiEndpoint");
const { PaginatedFetch } = require("../util/paginatedFetch");
const SearchResultNode = require("../models/searchResultNode");
const LoadMoreNode = require("../models/loadMoreNode");
const InfoNode = require("../models/infoNode");
const { formatApiError } = require("../util/errorFormatter");

class SearchProvider {
    constructor(context) {
        this.context = context;
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
        this.searchResults = [];
        this.pagination = null;
        this.currentWorkspace = null;
        this.currentQuery = null;
        this.currentRepo = null;
        this.currentPage = 1;
        // Auto-refresh when connection status changes in secrets store.
        // This ensures the welcome/connected state updates without external refresh calls.
        this.context.secrets.onDidChange(e => {
            if (e.key === "cloudsmith-vsc.isConnected") {
                this.refresh();
            }
        });
    }

    /**
     * Execute a search against a workspace, optionally scoped to a single repo.
     *
     * @param   workspace  Workspace slug
     * @param   query      Cloudsmith search query string
     * @param   page       Page number (default 1)
     * @param   repo       Optional repo slug for repo-scoped search
     */
    async search(workspace, query, page = 1, repo = null) {
        const cloudsmithAPI = new CloudsmithAPI(this.context);
        const paginatedFetch = new PaginatedFetch(cloudsmithAPI);

        const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
        const pageSize = config.get("searchPageSize") || 50;

        let endpoint;
        try {
            endpoint = repo
                ? apiEndpoint(["packages", workspace, repo])
                : apiEndpoint(["packages", workspace]);
        } catch {
            vscode.window.showErrorMessage("Could not search packages. The search scope was invalid.");
            return;
        }
        const result = await vscode.window.withProgress(
            {
                location: vscode.ProgressLocation.Notification,
                title: "Searching packages...",
                cancellable: true,
            },
            (_progress, token) => paginatedFetch.fetchPage(
                endpoint,
                page,
                pageSize,
                query,
                { cancellationToken: token, retry: "never", validate: isPackageSearchArray }
            )
        );

        if (result.error) {
            if (result.error.kind === "cancelled") {
                return;
            }
            vscode.window.showErrorMessage(`Could not search packages. ${formatApiError(result.error)}`);
            return;
        }

        this.currentWorkspace = workspace;
        this.currentQuery = query;
        this.currentPage = page;
        this.currentRepo = repo ? repo : null;

        const newNodes = result.data.map(pkg => new SearchResultNode(pkg, this.context));

        if (page > 1) {
            // Remove existing LoadMoreNode before appending
            this.searchResults = this.searchResults.filter(
                node => !(node instanceof LoadMoreNode)
            );
            this.searchResults = this.searchResults.concat(newNodes);
        } else {
            this.searchResults = newNodes;
        }

        this.pagination = result.pagination;

        // Add LoadMoreNode if more pages exist
        if (this.pagination.page < this.pagination.pageTotal) {
            this.searchResults.push(
                new LoadMoreNode(this.pagination.page, this.pagination.pageTotal, this.pagination.count)
            );
        }

        if (newNodes.length === 0 && page === 1) {
            vscode.window.showInformationMessage(`No packages found for "${query}".`);
        }

        this.refresh();
    }

    /**
     * Execute a search against specific repositories within a workspace.
     * Merges results from multiple per-repo API calls.
     *
     * @param   workspace  Workspace slug
     * @param   repos      Array of repo slugs
     * @param   query      Cloudsmith search query string
     */
    async searchRepos(workspace, repos, query) {
        const cloudsmithAPI = new CloudsmithAPI(this.context);
        const paginatedFetch = new PaginatedFetch(cloudsmithAPI);

        const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
        const pageSize = config.get("searchPageSize") || 50;

        // Fetch first page from each repo in parallel
        const promises = repos.map(repo => {
            let endpoint;
            try {
                endpoint = apiEndpoint(["packages", workspace, repo]);
            } catch {
                return Promise.resolve({
                    data: [],
                    error: { kind: "invalid_request", message: "The repository identifier was invalid." },
                });
            }
            return paginatedFetch.fetchPage(endpoint, 1, pageSize, query, {
                retry: "never",
                validate: isPackageSearchArray,
            });
        });
        const results = await Promise.all(promises);

        const allNodes = [];
        const failedRepos = [];
        results.forEach((result, index) => {
            if (result.error) {
                failedRepos.push(repos[index]);
            }
        });
        for (const result of results) {
            if (!result.error && result.data) {
                const nodes = result.data.map(pkg => new SearchResultNode(pkg, this.context));
                allNodes.push(...nodes);
            }
        }

        this.searchResults = allNodes;
        this.pagination = null; // No unified pagination for multi-repo search
        this.currentWorkspace = workspace;
        this.currentQuery = query;
        this.currentPage = 1;
        this.currentRepo = null;

        if (failedRepos.length > 0) {
            vscode.window.showWarningMessage(`Could not search some repositories: ${failedRepos.join(", ")}.`);
        }

        if (allNodes.length === 0 && failedRepos.length === 0) {
            vscode.window.showInformationMessage(`No packages found for "${query}".`);
        }

        this.refresh();
    }

    /** Load the next page of the current search. */
    async loadNextPage() {
        if (!this.currentWorkspace || !this.currentQuery) {
            return;
        }
        if (this.pagination && this.currentPage >= this.pagination.pageTotal) {
            return;
        }
        await this.search(this.currentWorkspace, this.currentQuery, this.currentPage + 1, this.currentRepo);
    }

    /** Clear all search results. */
    clear() {
        this.searchResults = [];
        this.pagination = null;
        this.currentWorkspace = null;
        this.currentQuery = null;
        this.currentPage = 1;
        this.currentRepo = null;
        this.refresh();
    }

    getTreeItem(element) {
        return element.getTreeItem();
    }

    // IMPORTANT: Connection status is checked live from context.secrets every render.
    // Do NOT cache this value or rely on external refresh calls to set a connection flag.
    // This pattern was adopted after three regressions caused by refresh wiring changes.
    async getChildren(element) {
        if (!element) {
            if (this.searchResults.length === 0 && !this.currentQuery) {
                const isConnected = await this.context.secrets.get("cloudsmith-vsc.isConnected");
                if (isConnected !== "true") {
                    return [new InfoNode(
                        "Connect to Cloudsmith",
                        "Use the key icon above to set up a personal or service account API key, CLI import, or SSO.",
                        "Set up Cloudsmith authentication to get started.",
                        "plug",
                        undefined,
                        { command: "cloudsmith-vsc.configureCredentials", title: "Set up authentication" }
                    )];
                }
                // Connected but no search run yet
                return [new InfoNode(
                    "Search packages across a Cloudsmith workspace",
                    "Use the search icon above or Ctrl+Shift+P \u2192 Search packages.",
                    "Search by name, format, version, license, or policy status across repositories in a workspace.",
                    "search"
                )];
            }
            // Prepend a summary node if we have search results
            if (this.searchResults.length > 0 && this.currentQuery) {
                const count = this.pagination ? this.pagination.count : this.searchResults.length;
                const scopeLabel = this.currentRepo
                    ? `${this.currentWorkspace}/${this.currentRepo}`
                    : (this.currentWorkspace || "workspace");
                const summaryNode = new InfoNode(
                    `Results for: ${this.currentQuery}`,
                    `${count} package${count !== 1 ? "s" : ""} in ${scopeLabel}`,
                    `Query: ${this.currentQuery}\nWorkspace: ${this.currentWorkspace || ""}${this.currentRepo ? `\nRepository: ${this.currentRepo}` : ""}`,
                    "search",
                    "searchSummary"
                );
                return [summaryNode, ...this.searchResults];
            }
            return this.searchResults;
        }
        return element.getChildren();
    }

    refresh() {
        this._onDidChangeTreeData.fire();
    }
}

function unwrapIdentifier(value) {
    if (typeof value === "string" && value.length > 0) {
        return value;
    }
    return value && typeof value === "object" && typeof value.value === "string" && value.value.length > 0
        ? value.value
        : null;
}

function isPackageSearchArray(value) {
    return Array.isArray(value) && value.every(pkg => (
        pkg
        && typeof pkg === "object"
        && !Array.isArray(pkg)
        && typeof pkg.name === "string"
        && pkg.name.length > 0
        && typeof pkg.format === "string"
        && pkg.format.length > 0
        && (typeof pkg.version === "string" || typeof pkg.version === "number")
        && String(pkg.version).length > 0
        && typeof pkg.repository === "string"
        && pkg.repository.length > 0
        && typeof pkg.namespace === "string"
        && pkg.namespace.length > 0
        && Boolean(unwrapIdentifier(pkg.slug_perm || pkg.slug_perm_raw || pkg.slug))
    ));
}

module.exports = { SearchProvider };

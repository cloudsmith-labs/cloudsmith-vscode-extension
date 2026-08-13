// Search results tree data provider for the Package Search view.

const vscode = require("vscode");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { apiEndpoint } = require("../util/apiEndpoint");
const { PaginatedFetch } = require("../util/paginatedFetch");
const SearchResultNode = require("../models/searchResultNode");
const LoadMoreNode = require("../models/loadMoreNode");
const InfoNode = require("../models/infoNode");
const { formatApiError } = require("../util/errorFormatter");
const {
    getPackagePolicyFlags,
    getPackageVulnerabilityState,
} = require("../util/packageVulnerabilities");
const {
    MAX_COLLECTION_IDENTITY_PART_LENGTH,
    packageCollectionIdentity,
} = require("../util/collectionIdentity");

const MAX_RESULTS = 5000;
const MAX_REPOSITORIES = 1000;
const MAX_WORKSPACE_LENGTH = 200;
const MAX_REPOSITORY_LENGTH = 200;
const MAX_QUERY_LENGTH = 2048;
const MAX_PACKAGE_NAME_LENGTH = 2048;
const MAX_PACKAGE_FORMAT_LENGTH = 100;
const MAX_PACKAGE_VERSION_LENGTH = 2048;
const MAX_PACKAGE_IDENTITY_LENGTH = MAX_COLLECTION_IDENTITY_PART_LENGTH;
const MAX_PACKAGE_OPTIONAL_STRING_LENGTH = 4096;
const MAX_PACKAGE_URL_LENGTH = 8192;
const MAX_PACKAGE_TAGS = 100;
const MAX_PACKAGE_TAG_LENGTH = 500;
const MULTI_REPO_CONCURRENCY = 4;
const MAX_MULTI_REPO_REQUESTS = 2000;
const MAX_MULTI_REPO_PAGES = 20;
const MAX_SINGLE_SEARCH_PAGES = 20;
const MAX_SINGLE_SEARCH_REQUESTS = 24;
const MAX_FAILURE_DETAILS = 20;
// Broad package queries can exceed the transport deadline at larger page sizes.
// Keep the interactive workspace/repository path small and predictable; the
// configurable size remains available only to bounded selected-repository runs.
const INTERACTIVE_SEARCH_PAGE_SIZE = 10;

class SearchProvider {
    constructor(context, options = {}) {
        this.context = context;
        this.connectionManager = options.connectionManager || disconnectedConnectionManager();
        this._createCloudsmithAPI = options.createCloudsmithAPI || (() => new CloudsmithAPI(this.context));
        this._createPaginatedFetch = options.createPaginatedFetch || (api => new PaginatedFetch(api));
        this._withProgress = options.withProgress || ((progressOptions, task) => (
            vscode.window.withProgress(progressOptions, task)
        ));
        this._notifications = options.notifications || {
            error: message => vscode.window.showErrorMessage(message),
            information: message => vscode.window.showInformationMessage(message),
            warning: message => vscode.window.showWarningMessage(message),
        };
        this._getAggregationPageSize = options.getAggregationPageSize || (() => {
            const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
            return config.get("searchPageSize");
        });

        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
        this._state = freezeState({ committed: null, pending: null, failure: null });
        this._nextOperationId = 0;
        this._activeRoot = null;
        this._activePage = null;
        this._disposed = false;
        this._account = this._readConnectedAccount();

        this._connectionSubscription = this.connectionManager.onDidChange?.(state => {
            const nextAccount = normalizeConnectedAccount(state);
            if ((nextAccount || this._account) && !sameAccount(nextAccount, this._account)) {
                this._account = nextAccount;
                this.clear();
                return;
            }
            this.refresh();
        });
    }

    get state() {
        const account = this._readConnectedAccount();
        if (
            !account
            || (this._state.committed && !sameAccount(account, this._state.committed))
            || (this._state.pending && !sameAccount(account, this._state.pending))
            || (this._state.failure && !sameAccount(account, this._state.failure))
        ) {
            return EMPTY_STATE;
        }
        return this._state;
    }

    // Compatibility projections for command wiring and older extension consumers.
    get searchResults() {
        return this._currentCommitted()?.results || EMPTY_RESULTS;
    }

    get pagination() {
        return this._currentCommitted()?.pagination || null;
    }

    get currentWorkspace() {
        return this._currentCommitted()?.descriptor.workspace || null;
    }

    get currentQuery() {
        return this._currentCommitted()?.descriptor.query || null;
    }

    get currentRepo() {
        const committed = this._currentCommitted();
        return committed?.descriptor.kind === "repository"
            ? committed.descriptor.repository
            : null;
    }

    get currentPage() {
        return this._currentCommitted()?.pagination?.page || 1;
    }

    /**
     * Synchronously claim ownership of a new root search. Call this before any
     * command-history or persistence await that belongs to the search intent.
     */
    beginSearch(descriptor) {
        this._invalidateOperations();

        let normalizedDescriptor = null;
        let validationError = null;
        try {
            normalizedDescriptor = normalizeDescriptor(descriptor);
        } catch (error) {
            validationError = error instanceof Error ? error.message : "The search scope was invalid.";
            normalizedDescriptor = freezeDescriptor({
                kind: "invalid",
                workspace: "",
                query: "",
                page: 1,
            });
        }

        const controller = new AbortController();
        const operation = Object.freeze({
            id: ++this._nextOperationId,
            descriptor: normalizedDescriptor,
            validationError,
            account: this._readConnectedAccount(),
            controller,
        });
        this._activeRoot = operation;
        this._state = freezeState({
            committed: this._state.committed,
            pending: {
                operationId: operation.id,
                activationId: operation.account?.activationId || null,
                accountEpoch: operation.account?.accountEpoch ?? null,
                descriptor: operation.descriptor,
            },
            failure: null,
        });
        this.refresh();
        return operation;
    }

    async executeSearch(operation) {
        if (!this._ownsRoot(operation)) {
            return;
        }
        if (!this._isCurrentRoot(operation)) {
            this._discardRoot(operation);
            return;
        }
        if (operation.validationError) {
            this._failRoot(operation, operation.validationError, null, "invalid_request");
            return;
        }
        try {
            if (operation.descriptor.kind === "repositories") {
                await this._executeRepositorySearch(operation);
                return;
            }
            await this._executeSingleSearch(operation);
        } catch {
            if (this._isCurrentRoot(operation)) {
                this._failRoot(
                    operation,
                    "Could not search packages. The operation failed unexpectedly. Retry the search.",
                    null,
                    "unexpected"
                );
            }
        }
    }

    /** Execute a workspace or single-repository root search. */
    async search(workspace, query, page = 1, repo = null) {
        const operation = this.beginSearch({
            kind: repo ? "repository" : "workspace",
            workspace,
            query,
            page,
            ...(repo ? { repository: repo } : {}),
        });
        return this.executeSearch(operation);
    }

    /** Execute a bounded first-page search against an exact repository set. */
    async searchRepos(workspace, repos, query) {
        const operation = this.beginSearch({
            kind: "repositories",
            workspace,
            repositories: repos,
            query,
            page: 1,
        });
        return this.executeSearch(operation);
    }

    async _executeSingleSearch(operation) {
        const { descriptor } = operation;
        const pageSize = INTERACTIVE_SEARCH_PAGE_SIZE;
        let endpoint;
        try {
            endpoint = descriptor.kind === "repository"
                ? apiEndpoint(["packages", descriptor.workspace, descriptor.repository])
                : apiEndpoint(["packages", descriptor.workspace]);
        } catch {
            this._failRoot(operation, "Could not search packages. The search scope was invalid.", null, "invalid_request");
            return;
        }

        let result;
        let progressToken = null;
        try {
            const paginatedFetch = this._createPaginatedFetch(this._createCloudsmithAPI());
            if (!this._isCurrentRoot(operation)) {
                this._discardRoot(operation);
                return;
            }
            result = await this._withProgress(progressOptions(), (_progress, token) => {
                progressToken = token;
                if (token?.isCancellationRequested) return null;
                return paginatedFetch.fetchPage(
                    endpoint,
                    descriptor.page,
                    pageSize,
                    descriptor.query,
                    {
                        cancellationToken: token,
                        retry: "never",
                        signal: operation.controller.signal,
                        validate: isPackageSearchArray,
                    }
                );
            });
        } catch (error) {
            if (!this._continueRoot(operation, progressToken)) return;
            this._failRoot(operation, `Could not search packages. ${safeErrorMessage(error)}`, null, "unexpected");
            return;
        }

        if (!this._continueRoot(operation, progressToken)) return;
        if (result?.error) {
            if (result.error.kind === "cancelled") {
                this._cancelRoot(operation);
                return;
            }
            this._failRoot(
                operation,
                `Could not search packages. ${formatApiError(result.error)}`,
                result.error,
                result.error.kind
            );
            return;
        }
        if (!isValidFetchedPage(result, descriptor.page, pageSize)) {
            this._failRoot(
                operation,
                "Could not search packages. Cloudsmith returned an invalid result page.",
                null,
                "invalid_response"
            );
            return;
        }
        if (!hasExactPackageScope(result?.data, descriptor)) {
            this._failRoot(
                operation,
                "Could not search packages. Cloudsmith returned packages outside the requested scope.",
                null,
                "invalid_response"
            );
            return;
        }

        if (!this._continueRoot(operation, progressToken)) return;
        let builtRoot;
        try {
            builtRoot = buildUniqueNodes(
                result.data,
                this.context,
                new Set(),
                this.connectionManager
            );
        } catch (error) {
            this._failRoot(operation, `Could not display search results. ${safeErrorMessage(error)}`, null, "invalid_response");
            return;
        }
        if (!this._continueRoot(operation, progressToken)) return;
        if (builtRoot.duplicateCount > 0) {
            this._failRoot(
                operation,
                "Could not search packages. Cloudsmith returned duplicate package identities.",
                null,
                "invalid_response"
            );
            return;
        }

        const keptNodes = builtRoot.nodes.slice(0, MAX_RESULTS);
        const droppedResultCount = builtRoot.nodes.length - keptNodes.length;
        const pagination = freezePagination(result.pagination);
        const resultLimitReached = keptNodes.length >= MAX_RESULTS
            && pagination.page < pagination.pageTotal;
        // This is a per-search session bound, independent of the API page at
        // which an explicitly requested root search began.
        const successfulPageCount = 1;
        const pageLimitReached = successfulPageCount >= MAX_SINGLE_SEARCH_PAGES
            && pagination.page < pagination.pageTotal;
        const capReached = resultLimitReached || pageLimitReached;
        const committed = this._commitRoot(operation, {
            descriptor,
            results: keptNodes,
            pagination,
            pageable: !capReached && pagination.page < pagination.pageTotal,
            totalCount: pagination.count,
            diagnostics: {
                failedRepositoryCount: 0,
                failureDetails: [],
                unsearchedRepositoryCount: 0,
                droppedResultCount,
                capReached,
                partial: capReached || droppedResultCount > 0,
                requestCount: 1,
                pageCount: successfulPageCount,
                pageLimitReached,
            },
        }, progressToken);
        if (committed && keptNodes.length === 0) {
            this._notify("information", `No packages found for "${descriptor.query}".`);
        }
    }

    async _executeRepositorySearch(operation) {
        const { descriptor } = operation;
        const pageSize = clampPageSize(this._getAggregationPageSize());
        const paginatedFetch = this._createPaginatedFetch(this._createCloudsmithAPI());
        if (!this._isCurrentRoot(operation)) {
            this._discardRoot(operation);
            return;
        }

        let collection;
        let progressToken = null;
        try {
            const outcome = await this._withProgress(progressOptions(), async (_progress, token) => {
                progressToken = token;
                const run = createRepositorySearchRun(descriptor);
                await runRepositorySearchWorkers({
                    run,
                    operation,
                    pageSize,
                    paginatedFetch,
                    token,
                    isCurrent: () => this._isCurrentRoot(operation),
                });
                return {
                    run,
                    cancelled: Boolean(token?.isCancellationRequested || run.cancelled),
                    stale: run.stale,
                };
            });
            if (!this._continueRoot(operation, progressToken)) return;
            if (outcome.cancelled || outcome.stale) {
                this._cancelRoot(operation);
                return;
            }
            if (!this._continueRoot(operation, progressToken)) return;
            collection = finalizeRepositorySearchRun(outcome.run);
        } catch (error) {
            if (!this._continueRoot(operation, progressToken)) return;
            this._failRoot(operation, `Could not search packages. ${safeErrorMessage(error)}`, null, "unexpected");
            return;
        }

        if (!this._continueRoot(operation, progressToken)) return;
        if (collection.successfulPageCount === 0) {
            const detail = collection.failureDetails.length > 0
                ? ` ${collection.failureDetails[0].message}`
                : " No repository search completed.";
            this._failRoot(
                operation,
                `Could not search the selected repositories.${detail}`,
                null,
                collection.firstFailureKind || "search_failed"
            );
            return;
        }

        if (!this._continueRoot(operation, progressToken)) return;
        let built;
        try {
            const nodes = buildUniqueNodes(
                collection.packages,
                this.context,
                new Set(),
                this.connectionManager
            ).nodes;
            const keptNodes = nodes.slice(0, MAX_RESULTS);
            built = {
                nodes: keptNodes,
                droppedResultCount: collection.droppedResultCount + nodes.length - keptNodes.length,
            };
        } catch (error) {
            this._failRoot(operation, `Could not display search results. ${safeErrorMessage(error)}`, null, "invalid_response");
            return;
        }
        if (!this._continueRoot(operation, progressToken)) return;

        const partial = !collection.complete || built.droppedResultCount > 0;
        const committed = this._commitRoot(operation, {
            descriptor,
            results: built.nodes,
            pagination: null,
            pageable: false,
            totalCount: collection.totalCount,
            diagnostics: {
                failedRepositoryCount: collection.failedRepositoryCount,
                failureDetails: collection.failureDetails,
                unsearchedRepositoryCount: collection.unsearchedRepositoryCount,
                truncatedRepositoryCount: collection.truncatedRepositoryCount,
                truncationDetails: collection.truncationDetails,
                truncatedResultCount: collection.truncatedResultCount,
                droppedResultCount: built.droppedResultCount,
                partial,
                capReached: built.droppedResultCount > 0
                    || collection.requestLimitReached
                    || collection.pageLimitReached
                    || collection.resultLimitReached,
                requestCount: collection.requestCount,
                pageCount: collection.pageCount,
                rateLimited: collection.rateLimited,
                requestLimitReached: collection.requestLimitReached,
                pageLimitReached: collection.pageLimitReached,
            },
        }, progressToken);

        if (committed && collection.failedRepositoryCount > 0) {
            const names = collection.failureDetails.map(detail => detail.repository);
            const suffix = collection.failedRepositoryCount > names.length
                ? `, and ${collection.failedRepositoryCount - names.length} more`
                : "";
            this._notify("warning", `Could not search some repositories: ${names.join(", ")}${suffix}.`);
        }
        if (committed && built.nodes.length === 0 && !partial) {
            this._notify("information", `No packages found for "${descriptor.query}".`);
        }
    }

    /**
     * Load exactly one next page. Duplicate commands for the same committed
     * session and target page receive the same promise and cannot double-fetch.
     */
    loadNextPage() {
        const account = this._readConnectedAccount();
        const committed = this._currentCommitted(account);
        if (
            !account
            || !committed
            || !committed.pageable
            || !committed.pagination
            || committed.descriptor.kind === "repositories"
            || this._activeRoot
        ) {
            return Promise.resolve();
        }
        const targetPage = committed.pagination.page + 1;
        if (
            this._activePage
            && this._activePage.operation.committed === committed
            && this._activePage.operation.targetPage === targetPage
        ) {
            return this._activePage.promise;
        }

        this._abortPage();
        const operation = Object.freeze({
            id: ++this._nextOperationId,
            committed,
            targetPage,
            account,
            controller: new AbortController(),
            requestAttempt: { started: false },
        });
        const promise = Promise.resolve()
            .then(() => this._executePage(operation))
            .finally(() => {
                if (this._activePage?.operation === operation) {
                    this._activePage = null;
                }
            });
        this._activePage = Object.freeze({ operation, promise });
        this._state = freezeState({
            committed,
            pending: {
                operationId: operation.id,
                activationId: operation.account.activationId,
                accountEpoch: operation.account.accountEpoch,
                descriptor: committed.descriptor,
                kind: "page",
                targetPage,
            },
            failure: null,
        });
        this.refresh();
        return promise;
    }

    async _executePage(operation) {
        if (!this._isCurrentPage(operation)) {
            this._discardPage(operation);
            return;
        }
        const { committed, targetPage } = operation;
        const { descriptor } = committed;
        const pageSize = committed.pagination.pageSize || INTERACTIVE_SEARCH_PAGE_SIZE;
        let endpoint;
        try {
            endpoint = descriptor.kind === "repository"
                ? apiEndpoint(["packages", descriptor.workspace, descriptor.repository])
                : apiEndpoint(["packages", descriptor.workspace]);
        } catch {
            this._failPage(
                operation,
                "Could not load more packages. The search scope was invalid.",
                null,
                "invalid_request",
                true
            );
            return;
        }

        let result;
        let progressToken = null;
        try {
            const paginatedFetch = this._createPaginatedFetch(this._createCloudsmithAPI());
            if (!this._isCurrentPage(operation)) {
                this._discardPage(operation);
                return;
            }
            result = await this._withProgress(progressOptions("Loading more packages..."), (_progress, token) => {
                progressToken = token;
                if (token?.isCancellationRequested) return null;
                operation.requestAttempt.started = true;
                return paginatedFetch.fetchPage(
                    endpoint,
                    targetPage,
                    pageSize,
                    descriptor.query,
                    {
                        cancellationToken: token,
                        retry: "never",
                        signal: operation.controller.signal,
                        validate: isPackageSearchArray,
                    }
                );
            });
        } catch (error) {
            if (!this._continuePage(operation, progressToken)) return;
            this._failPage(
                operation,
                `Could not load more packages. ${safeErrorMessage(error)}`,
                null,
                "unexpected",
                true
            );
            return;
        }

        if (!this._continuePage(operation, progressToken)) return;
        if (result?.error) {
            if (result.error.kind === "cancelled") {
                this._cancelPage(operation);
                return;
            }
            this._failPage(
                operation,
                `Could not load more packages. ${formatApiError(result.error)}`,
                result.error,
                result.error.kind,
                !isRetryablePageFailure(result.error)
            );
            return;
        }
        if (!isValidFetchedPage(result, targetPage, pageSize)) {
            this._failPage(
                operation,
                "Could not load more packages. Cloudsmith returned an invalid result page.",
                null,
                "invalid_response",
                true
            );
            return;
        }
        if (!samePaginationAnchor(committed.pagination, result.pagination)) {
            this._failPage(
                operation,
                "Could not load more packages. Cloudsmith changed pagination metadata between pages.",
                null,
                "invalid_response",
                true
            );
            return;
        }
        if (result.pagination?.page !== targetPage || !hasExactPackageScope(result.data, descriptor)) {
            this._failPage(
                operation,
                "Could not load more packages. Cloudsmith returned an unexpected page or package scope.",
                null,
                "invalid_response",
                true
            );
            return;
        }

        if (!this._continuePage(operation, progressToken)) return;
        let built;
        try {
            const seen = new Set(committed.resultKeys);
            built = buildUniqueNodes(
                result.data,
                this.context,
                seen,
                this.connectionManager
            );
        } catch (error) {
            this._failPage(
                operation,
                `Could not display more search results. ${safeErrorMessage(error)}`,
                null,
                "invalid_response",
                true
            );
            return;
        }
        if (built.duplicateCount > 0) {
            this._failPage(
                operation,
                "Could not load more packages. Cloudsmith repeated a package identity.",
                null,
                "invalid_response",
                true
            );
            return;
        }
        if (!this._continuePage(operation, progressToken)) return;

        const available = Math.max(0, MAX_RESULTS - committed.results.length);
        const appended = built.nodes.slice(0, available);
        const results = [...committed.results, ...appended];
        const pagination = freezePagination(result.pagination);
        const pageDropped = built.nodes.length - appended.length;
        const requestCount = committed.diagnostics.requestCount + 1;
        const pageCount = committed.diagnostics.pageCount + 1;
        const resultLimitReached = results.length >= MAX_RESULTS
            && pagination.page < pagination.pageTotal;
        const pageLimitReached = pageCount >= MAX_SINGLE_SEARCH_PAGES
            && pagination.page < pagination.pageTotal;
        const requestLimitReached = requestCount >= MAX_SINGLE_SEARCH_REQUESTS
            && pagination.page < pagination.pageTotal;
        const capReached = resultLimitReached || pageLimitReached || requestLimitReached;
        const nextCommitted = freezeCommitted({
            ...committed,
            results,
            resultKeys: [...committed.resultKeys, ...appended.map(packageKeyFromNode)],
            pagination,
            pageable: !capReached && pagination.page < pagination.pageTotal,
            totalCount: pagination.count,
            diagnostics: {
                ...committed.diagnostics,
                droppedResultCount: committed.diagnostics.droppedResultCount + pageDropped,
                capReached: committed.diagnostics.capReached || capReached,
                partial: committed.diagnostics.partial || capReached || pageDropped > 0,
                requestCount,
                pageCount,
                requestLimitReached,
                pageLimitReached,
            },
        });
        if (!this._continuePage(operation, progressToken)) return;
        this._state = freezeState({ committed: nextCommitted, pending: null, failure: null });
        this.refresh();
    }

    _commitRoot(operation, value, progressToken = null) {
        if (!this._continueRoot(operation, progressToken)) {
            return false;
        }
        const resultKeys = value.results.map(packageKeyFromNode);
        const committed = freezeCommitted({
            operationId: operation.id,
            activationId: operation.account.activationId,
            accountEpoch: operation.account.accountEpoch,
            descriptor: value.descriptor,
            results: value.results,
            resultKeys,
            pagination: value.pagination,
            pageable: value.pageable,
            totalCount: value.totalCount,
            diagnostics: value.diagnostics,
        });
        this._activeRoot = null;
        this._state = freezeState({ committed, pending: null, failure: null });
        this.refresh();
        return true;
    }

    _cancelRoot(operation) {
        if (!this._isCurrentRoot(operation)) {
            return;
        }
        this._activeRoot = null;
        this._state = freezeState({ committed: this._state.committed, pending: null, failure: null });
        this.refresh();
    }

    _failRoot(operation, message, _error, kind) {
        if (!this._isCurrentRoot(operation)) {
            return;
        }
        this._activeRoot = null;
        this._state = freezeState({
            committed: this._state.committed,
            pending: null,
            failure: {
                operationId: operation.id,
                activationId: operation.account.activationId,
                accountEpoch: operation.account.accountEpoch,
                descriptor: operation.descriptor,
                kind: kind || "search_failed",
                message,
            },
        });
        this._notify("error", message);
        this.refresh();
    }

    _failPage(operation, message, _error, kind, terminal = false) {
        if (!this._isCurrentPage(operation)) {
            return;
        }
        const committed = commitPageAttempt(operation, { terminal, failed: true });
        this._state = freezeState({
            committed,
            pending: null,
            failure: {
                operationId: operation.id,
                activationId: operation.account.activationId,
                accountEpoch: operation.account.accountEpoch,
                descriptor: committed.descriptor,
                kind: kind || "page_failed",
                message,
            },
        });
        this._notify("error", message);
        this.refresh();
    }

    _cancelPage(operation) {
        if (!this._isCurrentPage(operation)) {
            return;
        }
        this._state = freezeState({
            committed: commitPageAttempt(operation),
            pending: null,
            failure: null,
        });
        this.refresh();
    }

    _isCurrentRoot(operation) {
        return Boolean(
            this._ownsRoot(operation)
            && this._isAccountCurrent(operation.account)
        );
    }

    _ownsRoot(operation) {
        return Boolean(
            !this._disposed
            && operation
            && this._activeRoot === operation
            && !operation.controller.signal.aborted
        );
    }

    _isCurrentPage(operation) {
        return Boolean(
            !this._disposed
            && operation
            && this._activePage?.operation === operation
            && this._state.committed === operation.committed
            && !operation.controller.signal.aborted
            && this._isAccountCurrent(operation.account)
        );
    }

    _continueRoot(operation, progressToken = null) {
        if (!this._isCurrentRoot(operation)) return false;
        if (progressToken?.isCancellationRequested) {
            this._cancelRoot(operation);
            return false;
        }
        return true;
    }

    _continuePage(operation, progressToken = null) {
        if (!this._isCurrentPage(operation)) return false;
        if (progressToken?.isCancellationRequested) {
            this._cancelPage(operation);
            return false;
        }
        return true;
    }

    _readConnectedAccount() {
        return normalizeConnectedAccount(this.connectionManager.getState?.());
    }

    _isAccountCurrent(account) {
        return sameAccount(account, this._readConnectedAccount());
    }

    _currentCommitted(account = this._readConnectedAccount()) {
        const committed = this._state.committed;
        return account && committed && sameAccount(account, committed)
            ? committed
            : null;
    }

    _discardRoot(operation) {
        if (!this._ownsRoot(operation)) return;
        this._activeRoot = null;
        this._state = freezeState({ committed: null, pending: null, failure: null });
        this.refresh();
    }

    _discardPage(operation) {
        if (this._activePage?.operation !== operation) return;
        this._activePage = null;
        this._state = freezeState({ committed: null, pending: null, failure: null });
        this.refresh();
    }

    _invalidateOperations() {
        if (this._activeRoot) {
            this._activeRoot.controller.abort();
            this._activeRoot = null;
        }
        this._abortPage();
    }

    _abortPage() {
        if (this._activePage) {
            this._activePage.operation.controller.abort();
            this._activePage = null;
        }
    }

    clear() {
        this._invalidateOperations();
        this._state = freezeState({ committed: null, pending: null, failure: null });
        this.refresh();
    }

    dispose() {
        if (this._disposed) {
            return;
        }
        this._disposed = true;
        this._invalidateOperations();
        this._connectionSubscription?.dispose?.();
        this._onDidChangeTreeData.dispose();
    }

    getTreeItem(element) {
        return element.getTreeItem();
    }

    async getChildren(element) {
        if (element) {
            return element.getChildren();
        }

        const account = this._readConnectedAccount();
        if (!account) {
            return [new InfoNode(
                "Connect to Cloudsmith",
                "Use the key icon above to set up a personal or service account API key, CLI import, or SSO.",
                "Set up Cloudsmith authentication to get started.",
                "plug",
                undefined,
                { command: "cloudsmith-vsc.configureCredentials", title: "Set up authentication" }
            )];
        }
        const committed = this._currentCommitted(account);
        const pending = sameAccount(account, this._state.pending) ? this._state.pending : null;
        const failure = sameAccount(account, this._state.failure) ? this._state.failure : null;
        if (!committed) {
            if (failure) {
                return [failureNode(failure)];
            }
            if (pending) {
                return [new InfoNode(
                    "Searching packages...",
                    `Searching for: ${pending.descriptor.query || ""}`,
                    `Query: ${pending.descriptor.query || ""}`,
                    "loading~spin"
                )];
            }
            return [new InfoNode(
                "Search packages across a Cloudsmith workspace",
                "Use the search icon above or Ctrl+Shift+P \u2192 Search packages.",
                "Search by name, format, version, license, or policy status across repositories in a workspace.",
                "search"
            )];
        }

        const children = [summaryNode(committed)];
        if (pending) {
            const description = pending.kind === "page"
                ? `Loading page ${pending.targetPage}...`
                : `Searching for: ${pending.descriptor.query}`;
            children.push(new InfoNode(
                "Search in progress",
                description,
                description,
                "loading~spin"
            ));
        }
        if (failure) {
            children.push(failureNode(failure));
        }
        children.push(...diagnosticNodes(committed));
        children.push(...committed.results);
        if (committed.pageable && !pending) {
            children.push(new LoadMoreNode(
                committed.pagination.page,
                committed.pagination.pageTotal,
                committed.pagination.count,
                committed.results.length
            ));
        }
        return children;
    }

    refresh() {
        if (!this._disposed) {
            this._onDidChangeTreeData.fire();
        }
    }

    _notify(kind, message) {
        try {
            const result = this._notifications[kind]?.(message);
            Promise.resolve(result).catch(() => {});
        } catch {
            // Notifications are best-effort and never own search state.
        }
    }
}

const EMPTY_RESULTS = Object.freeze([]);
const EMPTY_STATE = freezeState({ committed: null, pending: null, failure: null });

function normalizeDescriptor(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Could not search packages. The search scope was invalid.");
    }
    const workspace = normalizeRequiredString(
        value.workspace,
        "workspace",
        MAX_WORKSPACE_LENGTH
    );
    if (typeof value.query !== "string" || value.query.length > MAX_QUERY_LENGTH) {
        throw new Error("Could not search packages. The search query was invalid.");
    }
    const query = value.query;
    const page = normalizePage(value.page);
    if (value.kind === "workspace") {
        return freezeDescriptor({ kind: "workspace", workspace, query, page });
    }
    if (value.kind === "repository") {
        return freezeDescriptor({
            kind: "repository",
            workspace,
            repository: normalizeRequiredString(
                value.repository,
                "repository",
                MAX_REPOSITORY_LENGTH
            ),
            query,
            page,
        });
    }
    if (value.kind === "repositories") {
        if (!Array.isArray(value.repositories)) {
            throw new Error("Select between 1 and 1,000 repositories to search.");
        }
        const repositories = [...new Set(value.repositories.map(repository => (
            normalizeRequiredString(repository, "repository", MAX_REPOSITORY_LENGTH)
        )))];
        if (repositories.length < 1 || repositories.length > MAX_REPOSITORIES) {
            throw new Error("Select between 1 and 1,000 repositories to search.");
        }
        return freezeDescriptor({ kind: "repositories", workspace, repositories, query, page: 1 });
    }
    throw new Error("Could not search packages. The search scope was invalid.");
}

function normalizeRequiredString(value, label, maxLength) {
    if (
        typeof value !== "string"
        || value.trim().length === 0
        || value.length > maxLength
    ) {
        throw new Error(`The ${label} identifier was invalid.`);
    }
    return value.trim();
}

function normalizePage(value) {
    if (value === undefined) {
        return 1;
    }
    const page = Number(value);
    if (!Number.isSafeInteger(page) || page < 1) {
        throw new Error("Could not search packages. The page number was invalid.");
    }
    return page;
}

function clampPageSize(value) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) {
        return 50;
    }
    return Math.min(100, Math.max(1, Math.floor(numeric)));
}

function isPackageSearchArray(value) {
    return Array.isArray(value) && value.every(pkg => canonicalizeSearchPackage(pkg) !== null);
}

function requiredString(value, maxLength) {
    return typeof value === "string" && value.length > 0 && value.length <= maxLength
        ? value
        : null;
}

function optionalString(value, maxLength = MAX_PACKAGE_OPTIONAL_STRING_LENGTH) {
    return typeof value === "string" && value.length <= maxLength ? value : null;
}

function canonicalTagValue(value) {
    if (typeof value === "string" && value.length <= MAX_PACKAGE_TAG_LENGTH) {
        return value;
    }
    if (
        Array.isArray(value)
        && value.length <= MAX_PACKAGE_TAGS
        && value.every(item => typeof item === "string" && item.length <= MAX_PACKAGE_TAG_LENGTH)
    ) {
        return [...value];
    }
    return null;
}

function canonicalTags(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return {};
    const tags = {};
    const info = canonicalTagValue(value.info);
    const version = canonicalTagValue(value.version);
    if (info !== null) tags.info = info;
    if (version !== null) tags.version = version;
    return tags;
}

function canonicalizeSearchPackage(pkg) {
    if (!pkg || typeof pkg !== "object" || Array.isArray(pkg)) return null;
    const name = requiredString(pkg.name, MAX_PACKAGE_NAME_LENGTH);
    const format = requiredString(pkg.format, MAX_PACKAGE_FORMAT_LENGTH);
    const version = (typeof pkg.version === "string" || typeof pkg.version === "number")
        ? requiredString(String(pkg.version), MAX_PACKAGE_VERSION_LENGTH)
        : null;
    const repository = requiredString(pkg.repository, MAX_REPOSITORY_LENGTH);
    const namespace = requiredString(pkg.namespace, MAX_WORKSPACE_LENGTH);
    const slugPerm = requiredString(pkg.slug_perm, MAX_PACKAGE_IDENTITY_LENGTH);
    const policyFlags = getPackagePolicyFlags(pkg);
    if (!name || !format || !version || !repository || !namespace || !slugPerm || !policyFlags) {
        return null;
    }

    const downloads = Number.isSafeInteger(pkg.downloads) && pkg.downloads >= 0
        ? pkg.downloads
        : 0;
    const vulnerabilityState = getPackageVulnerabilityState(pkg);
    const numVulnerabilities = vulnerabilityState.count === null
        ? undefined
        : vulnerabilityState.count;
    return {
        name,
        format,
        version,
        repository,
        namespace,
        slug_perm: slugPerm,
        is_copyable: pkg.is_copyable === true
            ? true
            : pkg.is_copyable === false
                ? false
                : null,
        status_str: optionalString(pkg.status_str),
        slug: optionalString(pkg.slug, MAX_PACKAGE_IDENTITY_LENGTH),
        downloads,
        uploaded_at: optionalString(pkg.uploaded_at),
        status_reason: optionalString(pkg.status_reason),
        checksum_sha256: optionalString(pkg.checksum_sha256),
        version_digest: optionalString(pkg.version_digest),
        cdn_url: optionalString(pkg.cdn_url, MAX_PACKAGE_URL_LENGTH),
        filename: optionalString(pkg.filename),
        ...policyFlags,
        num_vulnerabilities: numVulnerabilities,
        // Canonicalize all list-response aliases through the shared indicator contract.
        // Omitting both fields intentionally remains "unknown" to downstream nodes.
        has_vulnerabilities: vulnerabilityState.detected ? true : undefined,
        max_severity: optionalString(pkg.max_severity),
        vulnerability_scan_results_url: optionalString(
            pkg.vulnerability_scan_results_url,
            MAX_PACKAGE_URL_LENGTH
        ),
        security_scan_status: optionalString(pkg.security_scan_status),
        spdx_license: optionalString(pkg.spdx_license),
        license: optionalString(pkg.license),
        raw_license: optionalString(pkg.raw_license),
        license_url: optionalString(pkg.license_url, MAX_PACKAGE_URL_LENGTH),
        tags: canonicalTags(pkg.tags),
    };
}

function isValidFetchedPage(result, requestedPage, requestedPageSize) {
    if (!(
        result
        && isPackageSearchArray(result.data)
        && result.data.length <= requestedPageSize
        && result.pagination
        && result.pagination.page === requestedPage
        && Number.isSafeInteger(result.pagination.pageTotal)
        && result.pagination.pageTotal >= requestedPage
        && Number.isSafeInteger(result.pagination.pageSize)
        && result.pagination.pageSize >= 1
        && result.pagination.pageSize <= 100
        && result.pagination.pageSize <= requestedPageSize
        && result.data.length <= result.pagination.pageSize
    )) return false;
    const countAuthoritative = result.pagination.countAuthoritative === true
        || (
            result.pagination.countAuthoritative === undefined
            && Number.isSafeInteger(result.pagination.count)
        );
    if (countAuthoritative) {
        if (!Number.isSafeInteger(result.pagination.count) || result.pagination.count < 0) return false;
        const calculatedPages = Math.max(
            1,
            Math.ceil(result.pagination.count / result.pagination.pageSize)
        );
        const expectedItems = Math.min(
            result.pagination.pageSize,
            Math.max(
                0,
                result.pagination.count - ((requestedPage - 1) * result.pagination.pageSize)
            )
        );
        return calculatedPages === result.pagination.pageTotal
            && result.data.length === expectedItems;
    }
    return (result.pagination.count === null || result.pagination.count === undefined)
        && (
            requestedPage >= result.pagination.pageTotal
            || result.data.length === result.pagination.pageSize
        );
}

function samePaginationAnchor(previous, current) {
    if (!previous || !current || current.page !== previous.page + 1) return false;
    const previousCountAuthoritative = previous.countAuthoritative === true
        || (previous.countAuthoritative === undefined && Number.isSafeInteger(previous.count));
    const currentCountAuthoritative = current.countAuthoritative === true
        || (current.countAuthoritative === undefined && Number.isSafeInteger(current.count));
    return previous.pageTotal === current.pageTotal
        && previous.pageSize === current.pageSize
        && previousCountAuthoritative === currentCountAuthoritative
        && previous.count === current.count;
}

function hasExactPackageScope(packages, descriptor) {
    return Array.isArray(packages) && packages.every(pkg => (
        pkg.namespace === descriptor.workspace
        && (descriptor.kind !== "repository" || pkg.repository === descriptor.repository)
    ));
}

function packageKey(pkg) {
    return packageCollectionIdentity(pkg);
}

function packageKeyFromNode(node) {
    return packageCollectionIdentity({
        namespace: node.namespace,
        repository: node.repository,
        slug_perm: node.slug_perm_raw,
    });
}

function buildUniqueNodes(packages, context, seen, connectionManager) {
    const nodes = [];
    let duplicateCount = 0;
    for (const pkg of packages) {
        const canonicalPackage = canonicalizeSearchPackage(pkg);
        if (!canonicalPackage) {
            throw new Error("Cloudsmith returned an invalid package record.");
        }
        const key = packageKey(canonicalPackage);
        if (seen.has(key)) {
            duplicateCount += 1;
            continue;
        }
        seen.add(key);
        nodes.push(freezeSearchNode(new SearchResultNode(canonicalPackage, context, { connectionManager })));
    }
    return { nodes, duplicateCount };
}

function freezeSearchNode(node) {
    for (const key of Object.keys(node)) {
        if (key !== "context" && key !== "_connectionManager") {
            deepFreezeOwned(node[key]);
        }
    }
    return Object.freeze(node);
}

function deepFreezeOwned(value) {
    if (!value || typeof value !== "object" || Object.isFrozen(value)) {
        return value;
    }
    if (Array.isArray(value) || Object.getPrototypeOf(value) === Object.prototype) {
        for (const nested of Object.values(value)) {
            deepFreezeOwned(nested);
        }
        Object.freeze(value);
    }
    return value;
}

function freezeDescriptor(descriptor) {
    if (descriptor.repositories) {
        Object.freeze(descriptor.repositories);
    }
    return Object.freeze(descriptor);
}

function freezePagination(pagination) {
    const countAuthoritative = pagination.countAuthoritative === true
        || (pagination.countAuthoritative === undefined && Number.isSafeInteger(pagination.count));
    return Object.freeze({
        page: pagination.page,
        pageTotal: pagination.pageTotal,
        count: countAuthoritative ? pagination.count : null,
        countAuthoritative,
        pageSize: pagination.pageSize,
    });
}

function freezeCommitted(value) {
    const diagnostics = value.diagnostics || {};
    const failureDetails = Object.freeze((diagnostics.failureDetails || []).map(detail => Object.freeze({ ...detail })));
    const truncationDetails = Object.freeze((diagnostics.truncationDetails || []).map(detail => (
        Object.freeze({ ...detail })
    )));
    return Object.freeze({
        operationId: value.operationId,
        activationId: value.activationId,
        accountEpoch: value.accountEpoch,
        descriptor: value.descriptor,
        results: Object.freeze([...value.results]),
        resultKeys: Object.freeze([...value.resultKeys]),
        pagination: value.pagination ? freezePagination(value.pagination) : null,
        pageable: Boolean(value.pageable),
        totalCount: Number.isSafeInteger(value.totalCount) && value.totalCount >= 0
            ? value.totalCount
            : null,
        diagnostics: Object.freeze({
            failedRepositoryCount: diagnostics.failedRepositoryCount || 0,
            failureDetails,
            unsearchedRepositoryCount: diagnostics.unsearchedRepositoryCount || 0,
            truncatedRepositoryCount: diagnostics.truncatedRepositoryCount || 0,
            truncationDetails,
            truncatedResultCount: diagnostics.truncatedResultCount || 0,
            droppedResultCount: diagnostics.droppedResultCount || 0,
            partial: Boolean(diagnostics.partial),
            capReached: Boolean(diagnostics.capReached),
            requestCount: diagnostics.requestCount || 0,
            pageCount: diagnostics.pageCount || 0,
            rateLimited: Boolean(diagnostics.rateLimited),
            requestLimitReached: Boolean(diagnostics.requestLimitReached),
            pageLimitReached: Boolean(diagnostics.pageLimitReached),
        }),
    });
}

function commitPageAttempt(operation, { terminal = false } = {}) {
    const committed = operation.committed;
    const requestCount = committed.diagnostics.requestCount
        + (operation.requestAttempt.started ? 1 : 0);
    const requestLimitReached = requestCount >= MAX_SINGLE_SEARCH_REQUESTS;
    const pageLimitReached = committed.diagnostics.pageCount >= MAX_SINGLE_SEARCH_PAGES;
    const hardLimitReached = requestLimitReached || pageLimitReached;
    return freezeCommitted({
        ...committed,
        pageable: committed.pageable && !terminal && !hardLimitReached,
        diagnostics: {
            ...committed.diagnostics,
            requestCount,
            capReached: committed.diagnostics.capReached || hardLimitReached,
            partial: committed.diagnostics.partial || terminal || hardLimitReached,
            requestLimitReached,
            pageLimitReached,
        },
    });
}

function freezeState(value) {
    let pending = value.pending;
    if (pending) {
        pending = Object.freeze({ ...pending });
    }
    let failure = value.failure;
    if (failure) {
        failure = Object.freeze({ ...failure });
    }
    return Object.freeze({ committed: value.committed, pending, failure });
}

function normalizeConnectedAccount(state) {
    if (
        !state
        || state.sessionConnected !== true
        || typeof state.activationId !== "string"
        || state.activationId.length === 0
        || !Number.isSafeInteger(state.accountEpoch)
        || state.accountEpoch < 0
    ) {
        return null;
    }
    return Object.freeze({
        activationId: state.activationId,
        accountEpoch: state.accountEpoch,
    });
}

function sameAccount(left, right) {
    return Boolean(
        left
        && right
        && left.activationId === right.activationId
        && left.accountEpoch === right.accountEpoch
    );
}

function disconnectedConnectionManager() {
    return Object.freeze({
        getState: () => Object.freeze({
            activationId: null,
            accountEpoch: 0,
            sessionConnected: false,
            status: "absent",
        }),
        onDidChange: () => Object.freeze({ dispose() {} }),
    });
}

function progressOptions(title = "Searching packages...") {
    return {
        location: vscode.ProgressLocation.Notification,
        title,
        cancellable: true,
    };
}

function createRepositorySearchRun(descriptor) {
    const repositories = descriptor.repositories.map((repository, index) => ({
        repository,
        index,
        anchor: null,
        complete: false,
        failed: false,
        pagesFetched: 0,
        itemCount: 0,
        uniqueCount: 0,
    }));
    return {
        descriptor,
        repositories,
        queue: repositories.map(repository => ({ repositoryIndex: repository.index, page: 1 })),
        nextQueueIndex: 0,
        requestCount: 0,
        successfulPageCount: 0,
        records: [],
        identities: new Map(),
        failureRepositories: new Set(),
        failureDetails: [],
        firstFailureKind: null,
        cancelled: false,
        stale: false,
        circuitOpen: false,
        rateLimited: false,
        requestLimitReached: false,
        pageLimitReached: false,
        resultLimitReached: false,
        internalFailure: false,
    };
}

async function runRepositorySearchWorkers(options) {
    const workers = Array.from(
        { length: MULTI_REPO_CONCURRENCY },
        () => runRepositorySearchWorker(options)
    );
    const outcomes = await Promise.allSettled(workers);
    if (outcomes.some(outcome => outcome.status === "rejected")) {
        options.run.internalFailure = true;
        options.run.circuitOpen = true;
        if (!options.run.firstFailureKind) options.run.firstFailureKind = "unexpected";
    }
}

async function runRepositorySearchWorker(options) {
    const workerState = { repository: null };
    try {
        await runRepositorySearchWorkerLoop(options, workerState);
    } catch {
        options.run.circuitOpen = true;
        if (workerState.repository) {
            recordRepositoryFailure(
                options.run,
                workerState.repository,
                "unexpected",
                "The repository result could not be processed safely."
            );
        } else {
            options.run.internalFailure = true;
            if (!options.run.firstFailureKind) options.run.firstFailureKind = "unexpected";
        }
    }
}

async function runRepositorySearchWorkerLoop(options, workerState) {
    const { run, operation, pageSize, paginatedFetch, token, isCurrent } = options;
    while (true) {
        workerState.repository = null;
        const task = reserveRepositoryTask(run, token, isCurrent);
        if (!task) return;
        const repositoryState = run.repositories[task.repositoryIndex];
        workerState.repository = repositoryState;
        let endpoint;
        try {
            endpoint = apiEndpoint([
                "packages",
                run.descriptor.workspace,
                repositoryState.repository,
            ]);
        } catch {
            recordRepositoryFailure(
                run,
                repositoryState,
                "invalid_request",
                "The repository identifier was invalid."
            );
            continue;
        }

        let result;
        try {
            result = await paginatedFetch.fetchPage(
                endpoint,
                task.page,
                pageSize,
                run.descriptor.query,
                {
                    cancellationToken: token,
                    retry: "never",
                    signal: operation.controller.signal,
                    validate: isPackageSearchArray,
                }
            );
        } catch {
            if (!isCurrent()) {
                run.stale = true;
                return;
            }
            if (token?.isCancellationRequested) {
                run.cancelled = true;
                return;
            }
            recordRepositoryFailure(
                run,
                repositoryState,
                "unexpected",
                "The repository request failed unexpectedly."
            );
            continue;
        }

        if (!isCurrent()) {
            run.stale = true;
            return;
        }
        if (token?.isCancellationRequested) {
            run.cancelled = true;
            return;
        }
        if (result?.error) {
            if (result.error.kind === "cancelled") {
                run.cancelled = true;
                return;
            }
            recordRepositoryFailure(
                run,
                repositoryState,
                result.error.kind || "search_failed",
                formatApiError(result.error)
            );
            if (result.error.kind === "rate_limited" || result.error.status === 429) {
                run.rateLimited = true;
                run.circuitOpen = true;
            }
            continue;
        }

        const validation = validateRepositoryPage(result, task, repositoryState, pageSize);
        if (!validation.ok) {
            recordRepositoryFailure(
                run,
                repositoryState,
                "invalid_response",
                validation.message
            );
            continue;
        }
        if (!hasExactPackageScope(result.data, {
            kind: "repository",
            workspace: run.descriptor.workspace,
            repository: repositoryState.repository,
        })) {
            recordRepositoryFailure(
                run,
                repositoryState,
                "invalid_response",
                "Cloudsmith returned packages outside the requested repository."
            );
            continue;
        }

        let duplicateKind = null;
        const pageIdentities = new Map();
        const pageRecords = [];
        for (let itemIndex = 0; itemIndex < result.data.length; itemIndex += 1) {
            const canonicalPackage = canonicalizeSearchPackage(result.data[itemIndex]);
            if (!canonicalPackage) {
                duplicateKind = "malformed";
                break;
            }
            const key = packageKey(canonicalPackage);
            const signature = packageIdentitySignature(canonicalPackage);
            const existing = run.identities.get(key);
            const pageSignature = pageIdentities.get(key);
            if (existing || pageSignature) {
                duplicateKind = (existing ? existing.signature : pageSignature) === signature
                    ? "duplicate"
                    : "collision";
                break;
            }
            pageIdentities.set(key, signature);
            pageRecords.push({
                repositoryIndex: repositoryState.index,
                page: task.page,
                itemIndex,
                package: canonicalPackage,
                key,
                signature,
            });
        }

        if (duplicateKind) {
            const messages = {
                collision: "Cloudsmith returned conflicting records for one package identity.",
                duplicate: "Cloudsmith repeated a package identity across result pages.",
                malformed: "Cloudsmith returned an invalid package record.",
            };
            recordRepositoryFailure(
                run,
                repositoryState,
                duplicateKind === "duplicate" ? "pagination_no_progress" : "invalid_response",
                messages[duplicateKind]
            );
            continue;
        }

        run.successfulPageCount += 1;
        repositoryState.pagesFetched = task.page;
        repositoryState.itemCount += result.data.length;
        repositoryState.uniqueCount += pageRecords.length;
        if (!repositoryState.anchor) repositoryState.anchor = validation.anchor;
        for (const record of pageRecords) {
            run.identities.set(record.key, {
                signature: record.signature,
                repositoryIndex: repositoryState.index,
            });
            run.records.push({
                repositoryIndex: record.repositoryIndex,
                page: record.page,
                itemIndex: record.itemIndex,
                package: record.package,
            });
        }

        if (run.identities.size >= MAX_RESULTS) {
            run.resultLimitReached = true;
        }

        if (task.page >= validation.anchor.pageTotal) {
            if (
                validation.anchor.countAuthoritative
                && repositoryState.itemCount !== validation.anchor.count
            ) {
                recordRepositoryFailure(
                    run,
                    repositoryState,
                    "invalid_response",
                    "Cloudsmith pagination did not match its authoritative result count."
                );
                continue;
            }
            repositoryState.complete = true;
            continue;
        }

        if (task.page >= MAX_MULTI_REPO_PAGES) {
            run.pageLimitReached = true;
            continue;
        }
        if (!run.circuitOpen && !run.resultLimitReached) {
            run.queue.push({ repositoryIndex: repositoryState.index, page: task.page + 1 });
        }
    }
}

function reserveRepositoryTask(run, token, isCurrent) {
    if (!isCurrent()) {
        run.stale = true;
        return null;
    }
    if (token?.isCancellationRequested) {
        run.cancelled = true;
        return null;
    }
    if (run.circuitOpen || run.resultLimitReached) return null;
    if (run.requestCount >= MAX_MULTI_REPO_REQUESTS) {
        if (run.nextQueueIndex < run.queue.length) run.requestLimitReached = true;
        return null;
    }
    if (run.nextQueueIndex >= run.queue.length) return null;

    const task = run.queue[run.nextQueueIndex];
    run.nextQueueIndex += 1;
    run.requestCount += 1;
    return task;
}

function validateRepositoryPage(result, task, repositoryState, requestedPageSize) {
    if (!result || !Array.isArray(result.data) || !result.pagination) {
        return { ok: false, message: "Cloudsmith returned an invalid result page." };
    }
    const pagination = result.pagination;
    const countAuthoritative = pagination.countAuthoritative === true
        || (pagination.countAuthoritative === undefined && Number.isSafeInteger(pagination.count));
    if (
        pagination.page !== task.page
        || !Number.isSafeInteger(pagination.pageTotal)
        || pagination.pageTotal < task.page
        || !Number.isSafeInteger(pagination.pageSize)
        || pagination.pageSize < 1
        || pagination.pageSize > requestedPageSize
        || result.data.length > pagination.pageSize
        || (countAuthoritative && (!Number.isSafeInteger(pagination.count) || pagination.count < 0))
        || (!countAuthoritative && pagination.count !== null && pagination.count !== undefined)
    ) {
        return { ok: false, message: "Cloudsmith returned invalid pagination metadata." };
    }

    const anchor = {
        pageTotal: pagination.pageTotal,
        pageSize: pagination.pageSize,
        count: countAuthoritative ? pagination.count : null,
        countAuthoritative,
    };
    if (repositoryState.anchor && (
        repositoryState.anchor.pageTotal !== anchor.pageTotal
        || repositoryState.anchor.pageSize !== anchor.pageSize
        || repositoryState.anchor.count !== anchor.count
        || repositoryState.anchor.countAuthoritative !== anchor.countAuthoritative
    )) {
        return { ok: false, message: "Cloudsmith changed pagination metadata between pages." };
    }
    if (task.page !== repositoryState.pagesFetched + 1) {
        return { ok: false, message: "Cloudsmith repeated or skipped a repository result page." };
    }
    if (countAuthoritative) {
        const calculatedPages = Math.max(1, Math.ceil(anchor.count / anchor.pageSize));
        if (calculatedPages !== anchor.pageTotal) {
            return { ok: false, message: "Cloudsmith returned contradictory pagination metadata." };
        }
        const expectedItems = task.page < anchor.pageTotal
            ? anchor.pageSize
            : anchor.count - ((task.page - 1) * anchor.pageSize);
        if (expectedItems < 0 || expectedItems > anchor.pageSize || result.data.length !== expectedItems) {
            return { ok: false, message: "Cloudsmith returned a page with contradictory cardinality." };
        }
    } else if (task.page < anchor.pageTotal && result.data.length !== anchor.pageSize) {
        return { ok: false, message: "Cloudsmith returned a short page before the final page." };
    }
    return { ok: true, anchor };
}

function packageIdentitySignature(pkg) {
    return JSON.stringify([
        pkg.namespace,
        pkg.repository,
        pkg.slug_perm,
        pkg.name,
        pkg.format,
        pkg.version,
    ]);
}

function recordRepositoryFailure(run, repositoryState, kind, message) {
    repositoryState.failed = true;
    repositoryState.complete = false;
    if (!run.failureRepositories.has(repositoryState.index)) {
        run.failureRepositories.add(repositoryState.index);
        if (run.failureDetails.length < MAX_FAILURE_DETAILS) {
            run.failureDetails.push({ repository: repositoryState.repository, message });
        }
    }
    if (!run.firstFailureKind) run.firstFailureKind = kind;
}

function finalizeRepositorySearchRun(run) {
    run.records.sort((left, right) => (
        left.repositoryIndex - right.repositoryIndex
        || left.page - right.page
        || left.itemIndex - right.itemIndex
    ));
    const packages = run.records.slice(0, MAX_RESULTS).map(record => record.package);
    const droppedResultCount = Math.max(0, run.records.length - packages.length);
    const unsearched = run.repositories.filter(repository => (
        !repository.failed && repository.pagesFetched === 0
    ));
    const truncated = run.repositories.filter(repository => (
        !repository.failed && !repository.complete && repository.pagesFetched > 0
    ));
    const truncationDetails = truncated.slice(0, MAX_FAILURE_DETAILS).map(repository => ({
        repository: repository.repository,
        loadedCount: repository.uniqueCount,
        totalCount: repository.anchor?.countAuthoritative
            ? repository.anchor.count
            : null,
        page: repository.pagesFetched,
        pageTotal: repository.anchor?.pageTotal || repository.pagesFetched,
    }));
    const totalCount = boundedCountSum(run.repositories.map(repository => (
        repository.anchor?.countAuthoritative ? repository.anchor.count : repository.uniqueCount
    )));
    const truncatedResultCount = boundedCountSum(truncated.map(repository => (
        repository.anchor?.countAuthoritative
            ? Math.max(0, repository.anchor.count - repository.uniqueCount)
            : 0
    )));
    const resultLimitReached = droppedResultCount > 0 || (
        run.resultLimitReached
        && run.repositories.some(repository => !repository.complete && !repository.failed)
    );
    const complete = run.failureRepositories.size === 0
        && !run.internalFailure
        && unsearched.length === 0
        && truncated.length === 0
        && !run.requestLimitReached
        && !run.pageLimitReached
        && !resultLimitReached;
    return {
        packages,
        droppedResultCount,
        complete,
        successfulPageCount: run.successfulPageCount,
        failedRepositoryCount: run.failureRepositories.size,
        failureDetails: run.failureDetails,
        firstFailureKind: run.firstFailureKind,
        unsearchedRepositoryCount: unsearched.length,
        truncatedRepositoryCount: truncated.length,
        truncationDetails,
        truncatedResultCount,
        totalCount,
        requestCount: run.requestCount,
        pageCount: run.successfulPageCount,
        rateLimited: run.rateLimited,
        requestLimitReached: run.requestLimitReached,
        pageLimitReached: run.pageLimitReached,
        resultLimitReached,
    };
}

function safeErrorMessage() {
    return "The operation failed unexpectedly. Retry the search.";
}

function isRetryablePageFailure(error) {
    return Boolean(
        error
        && typeof error === "object"
        && (
            error.retryable === true
            || error.kind === "rate_limited"
            || error.kind === "network_error"
            || error.kind === "timeout"
            || error.kind === "server_error"
        )
    );
}

function boundedCountSum(counts) {
    let total = 0;
    for (const count of counts) {
        if (!Number.isSafeInteger(count) || count < 0) continue;
        if (count > Number.MAX_SAFE_INTEGER - total) return Number.MAX_SAFE_INTEGER;
        total += count;
    }
    return total;
}

function summaryNode(committed) {
    const { descriptor } = committed;
    let scopeLabel = descriptor.workspace;
    let tooltipScope = `Workspace: ${descriptor.workspace}`;
    if (descriptor.kind === "repository") {
        scopeLabel = `${descriptor.workspace}/${descriptor.repository}`;
        tooltipScope += `\nRepository: ${descriptor.repository}`;
    } else if (descriptor.kind === "repositories") {
        scopeLabel = `${descriptor.workspace} (${descriptor.repositories.length} selected repositories)`;
        tooltipScope += `\nRepositories: ${descriptor.repositories.join(", ")}`;
    }
    const count = committed.totalCount;
    const loadedCount = committed.results.length;
    let countDescription;
    if (committed.diagnostics.partial) {
        countDescription = count !== null && count > loadedCount
            ? `${loadedCount.toLocaleString()} of ${count.toLocaleString()} known matching packages loaded (incomplete)`
            : `${loadedCount.toLocaleString()} package${loadedCount !== 1 ? "s" : ""} loaded (incomplete)`;
    } else if (count !== null && committed.pageable) {
        countDescription = `${loadedCount.toLocaleString()} of ${count.toLocaleString()} matching packages loaded`;
    } else if (count !== null) {
        countDescription = `${count.toLocaleString()} package${count !== 1 ? "s" : ""}`;
    } else if (committed.pageable) {
        countDescription = `${loadedCount.toLocaleString()} package${loadedCount !== 1 ? "s" : ""} loaded (more available)`;
    } else {
        countDescription = `${loadedCount.toLocaleString()} package${loadedCount !== 1 ? "s" : ""} loaded`;
    }
    return new InfoNode(
        `Results for: ${descriptor.query}`,
        `${countDescription} in ${scopeLabel}`,
        `Query: ${descriptor.query}\n${tooltipScope}${committed.diagnostics.partial ? "\nIncomplete results" : ""}`,
        "search",
        "searchSummary"
    );
}

function failureNode(failure) {
    return new InfoNode(
        `Search failed for: ${failure.descriptor.query}`,
        failure.message,
        `Query: ${failure.descriptor.query}\n${failure.message}`,
        "error"
    );
}

function diagnosticNodes(committed) {
    const diagnostics = committed.diagnostics;
    const nodes = [];
    if (diagnostics.failedRepositoryCount > 0) {
        const details = diagnostics.failureDetails
            .map(detail => `${detail.repository}: ${detail.message}`)
            .join("\n");
        const omitted = diagnostics.failedRepositoryCount - diagnostics.failureDetails.length;
        nodes.push(new InfoNode(
            `${diagnostics.failedRepositoryCount} repositories could not be searched`,
            omitted > 0 ? `${details}\n…and ${omitted} more.` : details,
            omitted > 0 ? `${details}\n…and ${omitted} more.` : details,
            "warning"
        ));
    }
    if (diagnostics.unsearchedRepositoryCount > 0) {
        nodes.push(new InfoNode(
            `${diagnostics.unsearchedRepositoryCount} repositories were not searched`,
            "The search stopped before their next request could be scheduled.",
            "Refine the query or select fewer repositories to search every selected repository.",
            "info"
        ));
    }
    if (diagnostics.truncatedRepositoryCount > 0) {
        const details = diagnostics.truncationDetails
            .map(detail => {
                const count = Number.isSafeInteger(detail.totalCount)
                    ? ` of ${detail.totalCount.toLocaleString()}`
                    : "";
                return `${detail.repository}: loaded ${detail.loadedCount.toLocaleString()}${count} matches `
                    + `(page ${detail.page} of ${detail.pageTotal})`;
            })
            .join("\n");
        const omitted = diagnostics.truncatedRepositoryCount - diagnostics.truncationDetails.length;
        const suffix = omitted > 0 ? `\n…and ${omitted} more.` : "";
        nodes.push(new InfoNode(
            `${diagnostics.truncatedRepositoryCount} repositories were not fully searched`,
            `${details}${suffix}`,
            "The search stopped at a page, request, result, or rate-limit boundary. Refine the query to avoid omitted matches.",
            "info"
        ));
    }
    if (diagnostics.rateLimited) {
        nodes.push(new InfoNode(
            "Search stopped after rate limiting",
            "No further repository requests were scheduled after Cloudsmith returned HTTP 429.",
            "Successful repository pages were preserved, but the result is incomplete.",
            "warning"
        ));
    }
    if (diagnostics.droppedResultCount > 0) {
        nodes.push(new InfoNode(
            `${diagnostics.droppedResultCount} results were omitted`,
            `Only the first ${MAX_RESULTS.toLocaleString()} results are retained.`,
            "Refine the search query to see omitted results.",
            "info"
        ));
    } else if (
        (diagnostics.pageLimitReached || diagnostics.requestLimitReached)
        && diagnostics.truncatedRepositoryCount === 0
    ) {
        nodes.push(new InfoNode(
            "Search loading limit reached",
            `${committed.results.length.toLocaleString()} results were retained; more results may exist.`,
            "Refine the search query before loading more pages.",
            "info"
        ));
    } else if (diagnostics.capReached && diagnostics.truncatedRepositoryCount === 0) {
        nodes.push(new InfoNode(
            `Showing the first ${MAX_RESULTS.toLocaleString()} results`,
            "Additional results or repository searches are available but were not loaded.",
            "Refine the search query to narrow the result set.",
            "info"
        ));
    }
    return nodes;
}

module.exports = {
    SearchProvider,
    isPackageSearchArray,
    packageKey,
};

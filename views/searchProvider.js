// Search results tree data provider for the Package Search view.

const vscode = require("vscode");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { apiEndpoint } = require("../util/apiEndpoint");
const { PaginatedFetch } = require("../util/paginatedFetch");
const SearchResultNode = require("../models/searchResultNode");
const LoadMoreNode = require("../models/loadMoreNode");
const InfoNode = require("../models/infoNode");
const { formatApiError } = require("../util/errorFormatter");

const MAX_RESULTS = 5000;
const MAX_REPOSITORIES = 100;
const MAX_WORKSPACE_LENGTH = 200;
const MAX_REPOSITORY_LENGTH = 200;
const MAX_QUERY_LENGTH = 2048;
const MAX_PACKAGE_NAME_LENGTH = 2048;
const MAX_PACKAGE_FORMAT_LENGTH = 100;
const MAX_PACKAGE_VERSION_LENGTH = 2048;
const MAX_PACKAGE_IDENTITY_LENGTH = 2048;
const MAX_PACKAGE_OPTIONAL_STRING_LENGTH = 4096;
const MAX_PACKAGE_URL_LENGTH = 8192;
const MAX_PACKAGE_TAGS = 100;
const MAX_PACKAGE_TAG_LENGTH = 500;
const MULTI_REPO_CONCURRENCY = 4;
const MAX_FAILURE_DETAILS = 20;

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
        this._getPageSize = options.getPageSize || (() => {
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
        if (operation.descriptor.kind === "repositories") {
            await this._executeRepositorySearch(operation);
            return;
        }
        await this._executeSingleSearch(operation);
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
        const pageSize = clampPageSize(this._getPageSize());
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
        try {
            const paginatedFetch = this._createPaginatedFetch(this._createCloudsmithAPI());
            if (!this._isCurrentRoot(operation)) {
                this._discardRoot(operation);
                return;
            }
            result = await this._withProgress(progressOptions(), (_progress, token) => (
                paginatedFetch.fetchPage(
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
                )
            ));
        } catch (error) {
            if (!this._isCurrentRoot(operation)) {
                return;
            }
            this._failRoot(operation, `Could not search packages. ${safeErrorMessage(error)}`, null, "unexpected");
            return;
        }

        if (!this._isCurrentRoot(operation)) {
            this._discardRoot(operation);
            return;
        }
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

        let nodes;
        try {
            nodes = buildUniqueNodes(
                result.data,
                this.context,
                new Set(),
                this.connectionManager
            ).nodes;
        } catch (error) {
            this._failRoot(operation, `Could not display search results. ${safeErrorMessage(error)}`, null, "invalid_response");
            return;
        }
        if (!this._isCurrentRoot(operation)) {
            return;
        }

        const keptNodes = nodes.slice(0, MAX_RESULTS);
        const droppedResultCount = nodes.length - keptNodes.length;
        const pagination = freezePagination(result.pagination);
        const capReached = keptNodes.length >= MAX_RESULTS
            && pagination.page < pagination.pageTotal;
        this._commitRoot(operation, {
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
            },
        });
        if (keptNodes.length === 0) {
            this._notify("information", `No packages found for "${descriptor.query}".`);
        }
    }

    async _executeRepositorySearch(operation) {
        const { descriptor } = operation;
        const pageSize = clampPageSize(this._getPageSize());
        const searchableCount = Math.min(
            descriptor.repositories.length,
            Math.floor(MAX_RESULTS / pageSize)
        );
        const searchedRepositories = descriptor.repositories.slice(0, searchableCount);
        const unsearchedRepositoryCount = descriptor.repositories.length - searchedRepositories.length;
        const paginatedFetch = this._createPaginatedFetch(this._createCloudsmithAPI());
        if (!this._isCurrentRoot(operation)) {
            this._discardRoot(operation);
            return;
        }

        let repositoryResults;
        try {
            const outcome = await this._withProgress(progressOptions(), async (_progress, token) => {
                const results = await mapWithConcurrency(
                    searchedRepositories,
                    MULTI_REPO_CONCURRENCY,
                    async repository => {
                        if (!this._isCurrentRoot(operation)) {
                            return staleRepositoryResult(repository);
                        }
                        let endpoint;
                        try {
                            endpoint = apiEndpoint(["packages", descriptor.workspace, repository]);
                        } catch {
                            return failedRepositoryResult(repository, localSearchError(
                                "invalid_request",
                                "The repository identifier was invalid."
                            ));
                        }
                        let result;
                        try {
                            result = await paginatedFetch.fetchPage(
                                endpoint,
                                1,
                                pageSize,
                                descriptor.query,
                                {
                                    cancellationToken: token,
                                    retry: "never",
                                    signal: operation.controller.signal,
                                    validate: isPackageSearchArray,
                                }
                            );
                        } catch (error) {
                            return failedRepositoryResult(repository, localSearchError(
                                "unexpected",
                                safeErrorMessage(error)
                            ));
                        }
                        if (!this._isCurrentRoot(operation)) {
                            return staleRepositoryResult(repository);
                        }
                        if (result.error) {
                            return failedRepositoryResult(repository, result.error);
                        }
                        if (!isValidFetchedPage(result, 1, pageSize)) {
                            return failedRepositoryResult(repository, localSearchError(
                                "invalid_response",
                                "Cloudsmith returned an invalid result page."
                            ));
                        }
                        if (!hasExactPackageScope(result.data, {
                            kind: "repository",
                            workspace: descriptor.workspace,
                            repository,
                        })) {
                            return failedRepositoryResult(repository, localSearchError(
                                "invalid_response",
                                "Cloudsmith returned packages outside the requested scope."
                            ));
                        }
                        return Object.freeze({ repository, result, stale: false });
                    },
                    () => this._isCurrentRoot(operation) && !token?.isCancellationRequested
                );
                return { results, cancelled: Boolean(token?.isCancellationRequested) };
            });
            if (!this._isCurrentRoot(operation)) {
                return;
            }
            if (outcome.cancelled) {
                this._cancelRoot(operation);
                return;
            }
            repositoryResults = outcome.results;
        } catch (error) {
            if (!this._isCurrentRoot(operation)) {
                return;
            }
            this._failRoot(operation, `Could not search packages. ${safeErrorMessage(error)}`, null, "unexpected");
            return;
        }

        if (!this._isCurrentRoot(operation)) {
            return;
        }
        const completedResults = repositoryResults.filter(result => result && !result.stale);
        const failures = completedResults.filter(result => result.error);
        const successes = completedResults.filter(result => !result.error);
        if (successes.length === 0) {
            const detail = failures.length > 0
                ? ` ${formatApiError(failures[0].error)}`
                : " No repository search completed.";
            this._failRoot(
                operation,
                `Could not search the selected repositories.${detail}`,
                failures[0]?.error || null,
                failures[0]?.error?.kind || "search_failed"
            );
            return;
        }

        let built;
        try {
            const seen = new Set();
            const nodes = [];
            for (const success of successes) {
                const next = buildUniqueNodes(
                    success.result.data,
                    this.context,
                    seen,
                    this.connectionManager
                );
                nodes.push(...next.nodes);
            }
            const keptNodes = nodes.slice(0, MAX_RESULTS);
            built = {
                nodes: keptNodes,
                droppedResultCount: nodes.length - keptNodes.length,
            };
        } catch (error) {
            this._failRoot(operation, `Could not display search results. ${safeErrorMessage(error)}`, null, "invalid_response");
            return;
        }
        if (!this._isCurrentRoot(operation)) {
            return;
        }

        const failureDetails = failures.slice(0, MAX_FAILURE_DETAILS).map(({ repository, error }) => ({
            repository,
            message: formatApiError(error),
        }));
        const truncatedRepositories = successes.filter(({ result }) => (
            result.pagination.page < result.pagination.pageTotal
            || result.pagination.count > result.data.length
        ));
        const truncationDetails = truncatedRepositories
            .slice(0, MAX_FAILURE_DETAILS)
            .map(({ repository, result }) => ({
                repository,
                loadedCount: result.data.length,
                totalCount: result.pagination.count,
                page: result.pagination.page,
                pageTotal: result.pagination.pageTotal,
            }));
        const matchedResultCount = boundedCountSum(
            successes.map(({ result }) => result.pagination.count)
        );
        const truncatedResultCount = boundedCountSum(
            truncatedRepositories.map(({ result }) => (
                Math.max(0, result.pagination.count - result.data.length)
            ))
        );
        const partial = failures.length > 0
            || unsearchedRepositoryCount > 0
            || truncatedRepositories.length > 0
            || built.droppedResultCount > 0;
        this._commitRoot(operation, {
            descriptor,
            results: built.nodes,
            pagination: null,
            pageable: false,
            totalCount: matchedResultCount,
            diagnostics: {
                failedRepositoryCount: failures.length,
                failureDetails,
                unsearchedRepositoryCount,
                truncatedRepositoryCount: truncatedRepositories.length,
                truncationDetails,
                truncatedResultCount,
                droppedResultCount: built.droppedResultCount,
                partial,
                capReached: built.nodes.length >= MAX_RESULTS
                    || unsearchedRepositoryCount > 0
                    || truncatedRepositories.length > 0,
            },
        });

        if (failures.length > 0) {
            const names = failures.slice(0, MAX_FAILURE_DETAILS).map(result => result.repository);
            const suffix = failures.length > names.length ? `, and ${failures.length - names.length} more` : "";
            this._notify("warning", `Could not search some repositories: ${names.join(", ")}${suffix}.`);
        }
        if (built.nodes.length === 0) {
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
        const pageSize = committed.pagination.pageSize || clampPageSize(this._getPageSize());
        let endpoint;
        try {
            endpoint = descriptor.kind === "repository"
                ? apiEndpoint(["packages", descriptor.workspace, descriptor.repository])
                : apiEndpoint(["packages", descriptor.workspace]);
        } catch {
            this._failPage(operation, "Could not load more packages. The search scope was invalid.", null, "invalid_request");
            return;
        }

        let result;
        try {
            const paginatedFetch = this._createPaginatedFetch(this._createCloudsmithAPI());
            if (!this._isCurrentPage(operation)) {
                this._discardPage(operation);
                return;
            }
            result = await this._withProgress(progressOptions("Loading more packages..."), (_progress, token) => (
                paginatedFetch.fetchPage(
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
                )
            ));
        } catch (error) {
            if (!this._isCurrentPage(operation)) {
                return;
            }
            this._failPage(operation, `Could not load more packages. ${safeErrorMessage(error)}`, null, "unexpected");
            return;
        }

        if (!this._isCurrentPage(operation)) {
            this._discardPage(operation);
            return;
        }
        if (result?.error) {
            if (result.error.kind === "cancelled") {
                this._cancelPage(operation);
                return;
            }
            this._failPage(
                operation,
                `Could not load more packages. ${formatApiError(result.error)}`,
                result.error,
                result.error.kind
            );
            return;
        }
        if (!isValidFetchedPage(result, targetPage, pageSize)) {
            this._failPage(
                operation,
                "Could not load more packages. Cloudsmith returned an invalid result page.",
                null,
                "invalid_response"
            );
            return;
        }
        if (result.pagination?.page !== targetPage || !hasExactPackageScope(result.data, descriptor)) {
            this._failPage(
                operation,
                "Could not load more packages. Cloudsmith returned an unexpected page or package scope.",
                null,
                "invalid_response"
            );
            return;
        }

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
            this._failPage(operation, `Could not display more search results. ${safeErrorMessage(error)}`, null, "invalid_response");
            return;
        }
        if (!this._isCurrentPage(operation)) {
            return;
        }

        const available = Math.max(0, MAX_RESULTS - committed.results.length);
        const appended = built.nodes.slice(0, available);
        const results = [...committed.results, ...appended];
        const pagination = freezePagination(result.pagination);
        const pageDropped = built.nodes.length - appended.length;
        const capReached = results.length >= MAX_RESULTS && pagination.page < pagination.pageTotal;
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
            },
        });
        this._state = freezeState({ committed: nextCommitted, pending: null, failure: null });
        this.refresh();
    }

    _commitRoot(operation, value) {
        if (!this._isCurrentRoot(operation)) {
            return;
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

    _failPage(operation, message, _error, kind) {
        if (!this._isCurrentPage(operation)) {
            return;
        }
        this._state = freezeState({
            committed: operation.committed,
            pending: null,
            failure: {
                operationId: operation.id,
                activationId: operation.account.activationId,
                accountEpoch: operation.account.accountEpoch,
                descriptor: operation.committed.descriptor,
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
        this._state = freezeState({ committed: operation.committed, pending: null, failure: null });
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
                    "The current search is still running.",
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
        if (committed.pageable) {
            children.push(new LoadMoreNode(
                committed.pagination.page,
                committed.pagination.pageTotal,
                committed.pagination.count
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
            throw new Error("Select between 1 and 100 repositories to search.");
        }
        const repositories = [...new Set(value.repositories.map(repository => (
            normalizeRequiredString(repository, "repository", MAX_REPOSITORY_LENGTH)
        )))];
        if (repositories.length < 1 || repositories.length > MAX_REPOSITORIES) {
            throw new Error("Select between 1 and 100 repositories to search.");
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
    if (!name || !format || !version || !repository || !namespace || !slugPerm) return null;

    const downloads = Number.isSafeInteger(pkg.downloads) && pkg.downloads >= 0
        ? pkg.downloads
        : 0;
    const numVulnerabilities = Number.isSafeInteger(pkg.num_vulnerabilities)
        && pkg.num_vulnerabilities >= 0
        ? pkg.num_vulnerabilities
        : undefined;
    return {
        name,
        format,
        version,
        repository,
        namespace,
        slug_perm: slugPerm,
        status_str: optionalString(pkg.status_str),
        slug: optionalString(pkg.slug, MAX_PACKAGE_IDENTITY_LENGTH),
        downloads,
        uploaded_at: optionalString(pkg.uploaded_at),
        status_reason: optionalString(pkg.status_reason),
        checksum_sha256: optionalString(pkg.checksum_sha256),
        version_digest: optionalString(pkg.version_digest),
        cdn_url: optionalString(pkg.cdn_url, MAX_PACKAGE_URL_LENGTH),
        filename: optionalString(pkg.filename),
        policy_violated: pkg.policy_violated === true,
        deny_policy_violated: pkg.deny_policy_violated === true,
        license_policy_violated: pkg.license_policy_violated === true,
        vulnerability_policy_violated: pkg.vulnerability_policy_violated === true,
        num_vulnerabilities: numVulnerabilities,
        has_vulnerabilities: pkg.has_vulnerabilities === true
            ? true
            : pkg.has_vulnerabilities === false
                ? false
                : undefined,
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
    return Boolean(
        result
        && isPackageSearchArray(result.data)
        && result.data.length <= requestedPageSize
        && result.pagination
        && result.pagination.page === requestedPage
        && Number.isSafeInteger(result.pagination.pageTotal)
        && result.pagination.pageTotal >= requestedPage
        && Number.isSafeInteger(result.pagination.count)
        && result.pagination.count >= result.data.length
        && Number.isSafeInteger(result.pagination.pageSize)
        && result.pagination.pageSize >= 1
        && result.pagination.pageSize <= 100
    );
}

function hasExactPackageScope(packages, descriptor) {
    return Array.isArray(packages) && packages.every(pkg => (
        pkg.namespace === descriptor.workspace
        && (descriptor.kind !== "repository" || pkg.repository === descriptor.repository)
    ));
}

function packageKey(pkg) {
    return JSON.stringify([pkg.namespace, pkg.repository, pkg.slug_perm]);
}

function packageKeyFromNode(node) {
    return JSON.stringify([node.namespace, node.repository, node.slug_perm_raw]);
}

function buildUniqueNodes(packages, context, seen, connectionManager) {
    const nodes = [];
    for (const pkg of packages) {
        const canonicalPackage = canonicalizeSearchPackage(pkg);
        if (!canonicalPackage) {
            throw new Error("Cloudsmith returned an invalid package record.");
        }
        const key = packageKey(canonicalPackage);
        if (seen.has(key)) {
            continue;
        }
        seen.add(key);
        nodes.push(freezeSearchNode(new SearchResultNode(canonicalPackage, context, { connectionManager })));
    }
    return { nodes };
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
    return Object.freeze({
        page: pagination.page,
        pageTotal: pagination.pageTotal,
        count: pagination.count,
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
        totalCount: Number.isFinite(value.totalCount) ? value.totalCount : value.results.length,
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
        }),
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

async function mapWithConcurrency(items, concurrency, worker, shouldContinue) {
    const results = new Array(items.length);
    let nextIndex = 0;
    const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
        while (shouldContinue()) {
            const index = nextIndex;
            nextIndex += 1;
            if (index >= items.length) {
                return;
            }
            results[index] = await worker(items[index], index);
            if (!shouldContinue()) {
                return;
            }
        }
    });
    await Promise.all(workers);
    return results;
}

function failedRepositoryResult(repository, error) {
    return Object.freeze({ repository, error, stale: false });
}

function staleRepositoryResult(repository) {
    return Object.freeze({ repository, error: null, stale: true });
}

function localSearchError(kind, message) {
    return Object.freeze({
        kind,
        status: null,
        retryable: false,
        message,
        requestId: null,
        retryAfterMs: null,
        outcomeUnknown: false,
        diagnostic: Object.freeze({}),
    });
}

function safeErrorMessage() {
    return "The operation failed unexpectedly. Retry the search.";
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
    const countDescription = descriptor.kind === "repositories" && committed.diagnostics.partial
        ? count > loadedCount
            ? `${loadedCount.toLocaleString()} of ${count.toLocaleString()} matching packages loaded (partial)`
            : `${loadedCount.toLocaleString()} package${loadedCount !== 1 ? "s" : ""} loaded (partial)`
        : `${count.toLocaleString()} package${count !== 1 ? "s" : ""}`;
    return new InfoNode(
        `Results for: ${descriptor.query}`,
        `${countDescription} in ${scopeLabel}`,
        `Query: ${descriptor.query}\n${tooltipScope}${committed.diagnostics.partial ? "\nPartial results" : ""}`,
        "search",
        "searchSummary"
    );
}

function failureNode(failure) {
    return new InfoNode(
        "Search failed",
        failure.message,
        failure.message,
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
            `The search stopped before scheduling them to stay within the ${MAX_RESULTS.toLocaleString()}-item work budget.`,
            "Refine the query or select fewer repositories to search every selected repository.",
            "info"
        ));
    }
    if (diagnostics.truncatedRepositoryCount > 0) {
        const details = diagnostics.truncationDetails
            .map(detail => (
                `${detail.repository}: loaded ${detail.loadedCount.toLocaleString()} of `
                + `${detail.totalCount.toLocaleString()} matches `
                + `(page ${detail.page} of ${detail.pageTotal})`
            ))
            .join("\n");
        const omitted = diagnostics.truncatedRepositoryCount - diagnostics.truncationDetails.length;
        const suffix = omitted > 0 ? `\n…and ${omitted} more.` : "";
        nodes.push(new InfoNode(
            `${diagnostics.truncatedRepositoryCount} repositories have additional matching pages`,
            `${details}${suffix}`,
            "Multi-repository search loads only the first page from each repository. Refine the query to avoid omitted matches.",
            "info"
        ));
    }
    if (diagnostics.droppedResultCount > 0) {
        nodes.push(new InfoNode(
            `${diagnostics.droppedResultCount} results were omitted`,
            `Only the first ${MAX_RESULTS.toLocaleString()} results are retained.`,
            "Refine the search query to see omitted results.",
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

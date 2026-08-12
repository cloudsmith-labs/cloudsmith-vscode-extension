// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const vscode = require("vscode");
const { CloudsmithAPI } = require("./cloudsmithAPI");
const { CredentialManager } = require("./credentialManager");
const { fetchWorkspaceRepositories } = require("./workspaceRepositoryFetcher");
const {
  buildRegistryTriggerPlan,
  findPythonDistributionUrl,
  formatForDependency,
  isPullUnsupportedFormat,
  isTrustedRegistryUrl,
  parseComposerDistUrl,
  parseDartArchiveUrl,
  resolveAndValidateRegistryUrl,
} = require("./registryEndpoints");
const { canonicalFormat, normalizePackageName } = require("./packageNameNormalizer");
const { sanitizeSafeInventoryUpstream, UpstreamChecker } = require("./upstreamChecker");
const { UpstreamOperationScheduler } = require("./upstreamOperationScheduler");
const { getUpstreamFormatDescriptor, normalizeUpstreamFormat } = require("./upstreamFormats");
const {
  captureAccount,
  isAccountCurrent,
  resolveConnectionManager,
} = require("./accountOperation");

const MAX_CONCURRENT_PULLS = 5;
const INITIAL_AUTH_PROBE_CONCURRENCY = 3;
const MAX_REGISTRY_REDIRECTS = 5;
const REQUEST_TIMEOUT_MS = 30 * 1000;
const MAX_REGISTRY_METADATA_BYTES = 1024 * 1024;
const SAFE_REGISTRY_ERROR_MESSAGES = new Set([
  "Refused to send Cloudsmith credentials to an untrusted registry host.",
  "Registry metadata response exceeded the size limit.",
  "Registry redirect target was rejected.",
  "Registry request exceeded the redirect limit.",
]);

const PULL_STATUS = Object.freeze({
  PENDING: "pending",
  PULLING: "pulling",
  CACHED: "cached",
  ALREADY_EXISTS: "exists",
  NOT_FOUND: "not_found",
  AUTH_FAILED: "auth_failed",
  FORMAT_MISMATCH: "mismatch",
  ERROR: "error",
  SKIPPED: "skipped",
});

const PULL_SKIP_REASON = Object.freeze({
  NO_ACTIVE_UPSTREAM: "no_active_upstream",
  NO_PULL_SUPPORT: "no_pull_support",
  NO_TRIGGER_URL: "no_trigger_url",
});

class UpstreamPullService {
  constructor(context, options = {}) {
    this.context = context;
    this._api = options.api || new CloudsmithAPI(context);
    this._credentialManager = options.credentialManager || new CredentialManager(context);
    this._fetchImpl = options.fetchImpl || fetch;
    this._setTimeout = options.setTimeout || setTimeout;
    this._clearTimeout = options.clearTimeout || clearTimeout;
    this._fetchRepositories = options.fetchRepositories || this._fetchWorkspaceRepositories.bind(this);
    this._showQuickPick = options.showQuickPick || vscode.window.showQuickPick.bind(vscode.window);
    this._showErrorMessage = options.showErrorMessage || vscode.window.showErrorMessage.bind(vscode.window);
    this._showInformationMessage = options.showInformationMessage || vscode.window.showInformationMessage.bind(vscode.window);
    this._showWarningMessage = options.showWarningMessage || vscode.window.showWarningMessage.bind(vscode.window);
    this._upstreamChecker = options.upstreamChecker || new UpstreamChecker(context);
    this._connectionManager = resolveConnectionManager(context, options.connectionManager);
  }

  async run(options) {
    const prepared = await this.prepare(options);
    if (!prepared) {
      return null;
    }

    const execution = await this.execute(prepared, options);
    if (!execution) {
      return null;
    }

    return {
      ...prepared,
      ...execution,
    };
  }

  async prepare({
    workspace,
    repositoryHint,
    dependencies,
    token = null,
    cancellationToken = null,
    signal = null,
  }) {
    const operation = this._createPreparationOperation(cancellationToken || token, signal);
    if (!this._isPreparationCurrent(operation)) return null;
    const uncoveredDependencies = dedupePullDependencies(
      (Array.isArray(dependencies) ? dependencies : [])
        .filter((dependency) => dependency && isConclusiveCloudsmithAbsence(dependency.cloudsmithStatus))
    );

    if (!workspace) {
      await this._showErrorMessage("Run a dependency scan against a Cloudsmith workspace first.");
      return null;
    }

    if (uncoveredDependencies.length === 0) {
      await this._showInformationMessage("No uncovered dependencies are available to pull.");
      return null;
    }

    const projectFormats = [...new Set(
      uncoveredDependencies
        .map((dependency) => normalizeUpstreamFormat(formatForDependency(dependency)))
        .filter(Boolean)
    )];
    const inspectionFormats = projectFormats.filter(isPullInspectionFormat);

    if (inspectionFormats.length === 0) {
      await this._showInformationMessage(
        "Pull-through caching is not available for the uncovered dependency formats in this project."
      );
      return null;
    }

    let repositoryCollection;
    try {
      repositoryCollection = normalizeRepositoryCollection(
        await this._fetchRepositories(workspace, operation)
      );
    } catch (error) {
      if (!this._isPreparationCurrent(operation)) return null;
      await this._showErrorMessage(repositoryCollectionFailureMessage(error));
      return null;
    }
    if (!this._isPreparationCurrent(operation)) return null;

    const repositorySearch = await this._findMatchingRepositories(
      workspace,
      repositoryCollection.items,
      inspectionFormats,
      operation
    );
    if (!this._isPreparationCurrent(operation)) return null;
    if (repositorySearch.matches.length === 0) {
      const incomplete = !repositoryCollection.complete || !repositorySearch.complete;
      const message = incomplete
        ? `Repository upstream inspection was incomplete for ${formatListLabel(inspectionFormats)}. No matching proxy was found in the repositories that could be inspected.`
        : `No repositories have upstream proxies configured for the dependency formats in this project (${formatListLabel(inspectionFormats)}). Configure an upstream proxy in Cloudsmith to enable pull-through caching.`;
      await (incomplete ? this._showWarningMessage(message) : this._showInformationMessage(message));
      return null;
    }

    if (!repositoryCollection.complete || !repositorySearch.complete) {
      await this._showWarningMessage(
        "Repository upstream inspection was incomplete. Verified matching repositories are shown, but additional matches may exist."
      );
    }
    const orderedMatches = sortRepositoryMatches(repositorySearch.matches, repositoryHint);
    const selected = await this._showQuickPick(
      orderedMatches.map((match) => ({
        label: match.repo.slug || match.repo.name,
        description: match.repo.name && match.repo.name !== match.repo.slug ? match.repo.name : "",
        detail: `${formatListLabel(match.activeFormats)} upstream${match.activeFormats.length === 1 ? "" : "s"} configured`,
        _match: match,
      })),
      {
        placeHolder: "Select a repository to pull dependencies through",
        matchOnDescription: true,
        matchOnDetail: true,
      }
    );

    if (!this._isPreparationCurrent(operation) || !selected || !selected._match) {
      return null;
    }

    const repository = selected._match.repo;
    const plan = buildPullExecutionPlan(
      workspace,
      repository.slug,
      uncoveredDependencies,
      selected._match.activeFormats
    );

    if (plan.pullableDependencies.length === 0) {
      await this._showInformationMessage(buildPullPlanErrorMessage(repository.slug, plan));
      return null;
    }

    const confirmation = await this._showWarningMessage(
      buildPullConfirmationMessage(plan, repository.slug),
      { modal: true },
      "Pull dependencies"
    );

    if (!this._isPreparationCurrent(operation) || confirmation !== "Pull dependencies") {
      return null;
    }

    return {
      workspace,
      repository,
      plan,
      account: operation.account,
      repositorySearchComplete: repositoryCollection.complete && repositorySearch.complete,
    };
  }

  async prepareSingle({
    workspace,
    repositoryHint,
    dependency,
    token = null,
    cancellationToken = null,
    signal = null,
  }) {
    const operation = this._createPreparationOperation(cancellationToken || token, signal);
    if (!this._isPreparationCurrent(operation)) return null;
    const normalizedDependency = normalizeSingleDependency(dependency);
    if (!workspace) {
      await this._showErrorMessage("Run a dependency scan against a Cloudsmith workspace first.");
      return null;
    }

    if (!normalizedDependency) {
      await this._showWarningMessage("Could not determine the dependency details to pull.");
      return null;
    }

    if (!isConclusiveCloudsmithAbsence(normalizedDependency.cloudsmithStatus)) {
      await this._showWarningMessage(
        "This dependency cannot be pulled because Cloudsmith package absence was not conclusively established."
      );
      return null;
    }

    const dependencyFormat = normalizeUpstreamFormat(formatForDependency(normalizedDependency));
    if (!dependencyFormat || !isPullInspectionFormat(dependencyFormat)) {
      await this._showInformationMessage(
        `Pull-through caching is not available for ${formatDisplayName(normalizedDependency.format)} dependencies.`
      );
      return null;
    }

    let repositoryCollection;
    try {
      repositoryCollection = normalizeRepositoryCollection(
        await this._fetchRepositories(workspace, operation)
      );
    } catch (error) {
      if (!this._isPreparationCurrent(operation)) return null;
      await this._showErrorMessage(repositoryCollectionFailureMessage(error));
      return null;
    }
    if (!this._isPreparationCurrent(operation)) return null;

    const repositorySearch = await this._findMatchingRepositories(
      workspace,
      repositoryCollection.items,
      [dependencyFormat],
      operation
    );
    if (!this._isPreparationCurrent(operation)) return null;
    if (repositorySearch.matches.length === 0) {
      const incomplete = !repositoryCollection.complete || !repositorySearch.complete;
      const message = incomplete
        ? `Repository upstream inspection was incomplete. No ${formatDisplayName(dependencyFormat)} proxy was found in the repositories that could be inspected.`
        : `No repositories have a ${formatDisplayName(dependencyFormat)} upstream configured. Add one in Cloudsmith to pull this dependency.`;
      await (incomplete ? this._showWarningMessage(message) : this._showInformationMessage(message));
      return null;
    }

    if (!repositoryCollection.complete || !repositorySearch.complete) {
      await this._showWarningMessage(
        "Repository upstream inspection was incomplete. Verified matching repositories are shown, but additional matches may exist."
      );
    }
    const orderedMatches = sortRepositoryMatches(repositorySearch.matches, repositoryHint);
    const selected = await this._showQuickPick(
      orderedMatches.map((match) => ({
        label: match.repo.slug || match.repo.name,
        description: match.repo.name && match.repo.name !== match.repo.slug ? match.repo.name : "",
        detail: buildSingleDependencyRepositoryDetail(match, dependencyFormat),
        _match: match,
      })),
      {
        placeHolder: `Select a repository to pull ${buildDependencyLabel(normalizedDependency)} through`,
        matchOnDescription: true,
        matchOnDetail: true,
      }
    );

    if (!this._isPreparationCurrent(operation) || !selected || !selected._match) {
      return null;
    }

    const repository = selected._match.repo;
    const plan = buildPullExecutionPlan(
      workspace,
      repository.slug,
      [normalizedDependency],
      selected._match.activeFormats
    );

    if (plan.pullableDependencies.length === 0) {
      await this._showInformationMessage(buildPullPlanErrorMessage(repository.slug, plan));
      return null;
    }

    return {
      workspace,
      repository,
      plan,
      dependency: normalizedDependency,
      account: operation.account,
      repositorySearchComplete: repositoryCollection.complete && repositorySearch.complete,
    };
  }

  async execute(prepared, options = {}) {
    if (!this._isPreparedAccountCurrent(prepared)) {
      return { canceled: true, stale: true };
    }
    let apiKey;
    try {
      apiKey = await this._credentialManager.getApiKey();
    } catch {
      if (!this._isPreparedAccountCurrent(prepared)) {
        return { canceled: true, stale: true };
      }
      await this._showErrorMessage("Authentication failed. Check your API key in Cloudsmith settings.");
      return null;
    }
    if (!this._isPreparedAccountCurrent(prepared)) {
      return { canceled: true, stale: true };
    }
    if (!apiKey) {
      await this._showErrorMessage("Authentication failed. Check your API key in Cloudsmith settings.");
      return null;
    }

    const progress = options.progress || null;
    const token = options.token || null;
    const onStatus = typeof options.onStatus === "function" ? options.onStatus : null;
    const queue = prepared.plan.pullableDependencies.slice();
    let nextDependencyIndex = 0;
    const details = [];
    const counts = createResultCounts(prepared.plan.pullableDependencies.length);
    const state = {
      authFailureCount: 0,
      nonAuthOutcomeCount: 0,
      stopForAuthFailure: false,
      canceled: false,
      allowedConcurrency: Math.min(
        prepared.plan.pullableDependencies.length || 1,
        INITIAL_AUTH_PROBE_CONCURRENCY
      ),
      expandedConcurrency: false,
      stale: false,
    };
    const pending = new Set();
    const launchedTasks = [];
    let activeCount = 0;
    let launchedCount = 0;

    const takeNextDependency = () => {
      if (nextDependencyIndex >= queue.length) {
        return null;
      }

      const dependency = queue[nextDependencyIndex];
      nextDependencyIndex += 1;
      return dependency;
    };

    const processNext = async () => {
      if (!this._isPreparedAccountCurrent(prepared)) {
        state.canceled = true;
        state.stale = true;
        return;
      }
      if (token && token.isCancellationRequested) {
        state.canceled = true;
        return;
      }

      if (state.stopForAuthFailure) {
        return;
      }

      const dependency = takeNextDependency();
      if (!dependency) {
        return;
      }

      activeCount += 1;

      try {
        const pullingDetail = {
          dependency,
          status: PULL_STATUS.PULLING,
          errorMessage: null,
        };
        await publishStatus(onStatus, pullingDetail);
        if (!this._isPreparedAccountCurrent(prepared)) {
          state.canceled = true;
          state.stale = true;
          return;
        }

        let result;
        try {
          result = await this._pullDependency(
            prepared.workspace,
            prepared.repository.slug,
            dependency,
            apiKey,
            token,
            () => this._isPreparedAccountCurrent(prepared)
          );
        } catch {
          result = createPullFailure(
            dependency,
            "The upstream pull failed unexpectedly."
          );
        }

        if (!this._isPreparedAccountCurrent(prepared)) {
          state.canceled = true;
          state.stale = true;
          return;
        }

        if (result.canceled) {
          state.canceled = true;
          state.stale = result.stale === true;
          return;
        }

        result = toPublicPullDetail(result);
        details.push(result);
        updateResultCounts(counts, result);

        if (result.status === PULL_STATUS.AUTH_FAILED) {
          state.authFailureCount += 1;
        } else {
          state.nonAuthOutcomeCount += 1;
        }

        if (
          result.status === PULL_STATUS.AUTH_FAILED
          && state.authFailureCount >= INITIAL_AUTH_PROBE_CONCURRENCY
          && state.nonAuthOutcomeCount === 0
        ) {
          state.stopForAuthFailure = true;
        }

        if (
          !state.expandedConcurrency
          && state.nonAuthOutcomeCount > 0
          && state.allowedConcurrency < MAX_CONCURRENT_PULLS
        ) {
          state.allowedConcurrency = Math.min(MAX_CONCURRENT_PULLS, counts.total);
          state.expandedConcurrency = true;
        }

        publishProgress(progress, {
          message: buildProgressMessage(counts),
          increment: counts.total > 0 ? 100 / counts.total : 100,
        });

        await publishStatus(onStatus, result);
      } catch {
        const failure = createPullFailure(
          dependency,
          "The upstream pull failed unexpectedly."
        );
        details.push(failure);
        updateResultCounts(counts, failure);
      } finally {
        activeCount -= 1;
        fillConcurrency();
      }
    };

    const fillConcurrency = () => {
      while (
        activeCount < state.allowedConcurrency
        && (state.expandedConcurrency || launchedCount < INITIAL_AUTH_PROBE_CONCURRENCY)
        && nextDependencyIndex < queue.length
        && !(token && token.isCancellationRequested)
        && this._isPreparedAccountCurrent(prepared)
        && !state.stopForAuthFailure
      ) {
        launchedCount += 1;
        const promise = processNext();
        pending.add(promise);
        launchedTasks.push(promise);
        promise.then(
          () => pending.delete(promise),
          () => pending.delete(promise)
        );
      }
      if (!this._isPreparedAccountCurrent(prepared)) {
        state.canceled = true;
        state.stale = true;
      }
    };

    fillConcurrency();

    while (pending.size > 0) {
      await Promise.race([...pending]);
    }
    await Promise.allSettled(launchedTasks);

    if (state.stale || !this._isPreparedAccountCurrent(prepared)) {
      return { canceled: true, stale: true };
    }

    if (state.stopForAuthFailure) {
      while (nextDependencyIndex < queue.length) {
        const dependency = queue[nextDependencyIndex];
        nextDependencyIndex += 1;
        details.push({
          dependency,
          status: PULL_STATUS.AUTH_FAILED,
          errorMessage: "Skipped after repeated authentication failures.",
          networkError: false,
        });
      }
      recomputeResultCounts(counts, details);
      await this._showErrorMessage("Authentication failed. Check your API key in Cloudsmith settings.");
    } else if (state.canceled) {
      return {
        canceled: true,
      };
    } else if (
      counts.completed > 0
      && counts.completed === counts.errors
      && counts.networkErrors === counts.errors
    ) {
      await this._showErrorMessage("Cannot reach the Cloudsmith registry. Check your network connection.");
    }

    return {
      canceled: false,
      pullResult: {
        total: counts.total,
        cached: counts.cached,
        alreadyExisted: counts.alreadyExisted,
        notFound: counts.notFound,
        formatMismatched: counts.formatMismatched,
        errors: counts.errors,
        networkErrors: counts.networkErrors,
        authFailed: counts.authFailed,
        skipped: counts.skipped,
        details,
      },
    };
  }

  async _findMatchingRepositories(
    workspace,
    repositories,
    projectFormats,
    operation
  ) {
    const matches = [];
    let complete = true;
    const scheduler = new UpstreamOperationScheduler();
    const cancellationToken = operation && operation.cancellationToken;
    const signal = operation && operation.signal;
    const cancellationDisposable = cancellationToken
      && typeof cancellationToken.onCancellationRequested === "function"
      ? cancellationToken.onCancellationRequested(() => scheduler.cancel())
      : null;
    const abortListener = () => scheduler.cancel();
    if (signal && typeof signal.addEventListener === "function") {
      signal.addEventListener("abort", abortListener, { once: true });
    }

    try {
      await runPromisePool(repositories, 4, async (repo) => {
        if (!this._isPreparationCurrent(operation) || scheduler.stopped) {
          complete = false;
          return false;
        }
        const repoSlug = repo && repo.slug ? repo.slug : null;
        if (!repoSlug) {
          complete = false;
          return true;
        }

        let state;
        try {
          const requestOptions = {
            scheduler,
            cancellationToken,
            signal,
            account: operation.account,
          };
          state = typeof this._upstreamChecker.getRepositoryUpstreamStateForFormats === "function"
            ? await this._upstreamChecker.getRepositoryUpstreamStateForFormats(
              workspace,
              repoSlug,
              projectFormats,
              requestOptions
            )
            : await this._upstreamChecker.getRepositoryUpstreamState(
              workspace,
              repoSlug,
              requestOptions
            );
        } catch {
          complete = false;
          return this._isPreparationCurrent(operation) && !scheduler.stopped;
        }
        if (!isRepositoryInspectionCompleteForFormats(state, projectFormats)) complete = false;
        const activeUpstreamsByFormat = new Map();
        const activeFormats = projectFormats.filter((format) => {
          const upstreams = state && state.groupedUpstreams instanceof Map
            ? state.groupedUpstreams.get(format)
            : [];
          const activeUpstreams = Array.isArray(upstreams)
            ? upstreams.map(upstream => sanitizeSafeInventoryUpstream(upstream, format))
              .filter(upstream => upstream && upstream.is_active !== false)
            : [];
          if (activeUpstreams.length > 0) {
            activeUpstreamsByFormat.set(format, activeUpstreams);
            return true;
          }
          return false;
        });

        if (activeFormats.length === 0) {
          return true;
        }

        matches.push({
          repo,
          activeFormats,
          activeUpstreamsByFormat,
        });
        return true;
      });
    } finally {
      if (!this._isPreparationCurrent(operation)) scheduler.cancel();
      if (cancellationDisposable) cancellationDisposable.dispose();
      if (signal && typeof signal.removeEventListener === "function") {
        signal.removeEventListener("abort", abortListener);
      }
    }
    if (!this._isPreparationCurrent(operation)) complete = false;

    const sortedMatches = matches.sort((left, right) => {
      const leftSlug = String(left.repo.slug || left.repo.name || "");
      const rightSlug = String(right.repo.slug || right.repo.name || "");
      return leftSlug.localeCompare(rightSlug, undefined, { sensitivity: "base" });
    });
    return { matches: sortedMatches, complete };
  }

  async _fetchWorkspaceRepositories(workspace, operation = {}) {
    return fetchWorkspaceRepositories(this.context, workspace, {
      cloudsmithAPI: this._api,
      connectionManager: this._connectionManager,
      retry: "never",
      cancellationToken: operation.cancellationToken,
      signal: operation.signal,
      account: operation.account,
    });
  }

  _createPreparationOperation(cancellationToken, signal) {
    const account = this._connectionManager ? captureAccount(this._connectionManager) : null;
    return { cancellationToken, signal, account };
  }

  _isPreparationCurrent(operation) {
    if (
      !operation
      || isCancellationRequested(operation.cancellationToken)
      || operation.signal?.aborted
    ) return false;
    return !this._connectionManager
      || Boolean(operation.account && isAccountCurrent(this._connectionManager, operation.account));
  }

  _isPreparedAccountCurrent(prepared) {
    return !this._connectionManager
      || Boolean(prepared?.account && isAccountCurrent(this._connectionManager, prepared.account));
  }

  async _pullDependency(workspace, repo, dependency, apiKey, token, isCurrent = null) {
    const plan = buildRegistryTriggerPlan(workspace, repo, dependency);
    const format = formatForDependency(dependency);

    if (!plan) {
      const errorMessage = isPullUnsupportedFormat(format)
        ? `Pull-through caching is not supported for ${formatDisplayName(format)} dependencies.`
        : `No registry trigger URL is available for ${formatDisplayName(format)} dependencies.`;

      return {
        dependency,
        status: PULL_STATUS.FORMAT_MISMATCH,
        errorMessage,
        networkError: false,
      };
    }

    const metadataAttempt = await this._requestRegistry(
      plan.request,
      apiKey,
      token,
      { captureBody: plan.strategy !== "direct", isCurrent }
    );
    if (metadataAttempt.canceled) {
      return metadataAttempt;
    }

    if (plan.strategy === "direct") {
      return mapRegistryAttempt(dependency, metadataAttempt, format);
    }

    if (metadataAttempt.statusCode === 401 || metadataAttempt.statusCode === 403) {
      return mapRegistryAttempt(dependency, metadataAttempt, format);
    }

    if (metadataAttempt.statusCode === 404) {
      return mapRegistryAttempt(dependency, metadataAttempt, format);
    }

    if (metadataAttempt.statusCode < 200 || metadataAttempt.statusCode >= 300) {
      return mapRegistryAttempt(dependency, metadataAttempt, format);
    }

    let artifactUrl = null;
    if (plan.strategy === "python-simple-index") {
      artifactUrl = findPythonDistributionUrl(metadataAttempt.body, dependency.version, plan.request.url);
    } else if (plan.strategy === "dart-api") {
      artifactUrl = parseDartArchiveUrl(metadataAttempt.body, dependency.version, plan.request.url);
    } else if (plan.strategy === "composer-p2") {
      artifactUrl = parseComposerDistUrl(
        metadataAttempt.body,
        plan.packageName || dependency.name,
        dependency.version,
        plan.request.url
      );
    }

    if (!artifactUrl) {
      return {
        dependency,
        status: PULL_STATUS.NOT_FOUND,
        errorMessage: missingArtifactMessage(plan.strategy, dependency.version),
        networkError: false,
      };
    }

    if (isCurrent && !isCurrent()) {
      return { canceled: true, stale: true };
    }

    const artifactAttempt = await this._requestRegistry(
      {
        method: "GET",
        url: artifactUrl,
        headers: {},
      },
      apiKey,
      token,
      { captureBody: false, isCurrent }
    );

    if (artifactAttempt.canceled) {
      return artifactAttempt;
    }

    return mapRegistryAttempt(dependency, artifactAttempt, format);
  }

  async _requestRegistry(request, apiKey, token, options = {}) {
    const isCurrent = typeof options.isCurrent === "function" ? options.isCurrent : null;
    if (isCurrent && !isCurrent()) {
      return { canceled: true, stale: true };
    }
    const controller = new AbortController();
    let abortCause = null;
    const abort = (cause) => {
      if (abortCause) {
        return;
      }
      abortCause = cause;
      controller.abort();
    };
    const timeoutHandle = this._setTimeout(() => {
      abort("timeout");
    }, REQUEST_TIMEOUT_MS);

    const cancellationDisposable = token && typeof token.onCancellationRequested === "function"
      ? token.onCancellationRequested(() => abort("cancelled"))
      : null;
    if (token && token.isCancellationRequested) {
      abort("cancelled");
    }

    try {
      if (abortCause === "cancelled") {
        return { canceled: true };
      }
      const response = await this._fetchRegistryResponse(
        request,
        apiKey,
        controller.signal,
        0,
        isCurrent
      );

      const body = options.captureBody === false
        ? await discardRegistryBody(response, controller.signal)
        : await readRegistryBody(response, MAX_REGISTRY_METADATA_BYTES, controller.signal);

      if (abortCause === "cancelled" || (token && token.isCancellationRequested)) {
        return { canceled: true };
      }
      if (abortCause === "timeout" || controller.signal.aborted) {
        throw new Error("Registry request was aborted.");
      }

      return {
        statusCode: response.status,
        body,
      };
    } catch (error) {
      if (isCurrent && !isCurrent()) {
        return { canceled: true, stale: true };
      }
      if (abortCause === "cancelled" || (token && token.isCancellationRequested)) {
        return { canceled: true };
      }

      return {
        statusCode: 0,
        body: "",
        errorMessage: abortCause === "timeout"
          ? "Registry request timed out."
          : buildRegistryErrorMessage(request.url, error),
        networkError: isNetworkError(error) || abortCause === "timeout",
      };
    } finally {
      this._clearTimeout(timeoutHandle);
      if (cancellationDisposable && typeof cancellationDisposable.dispose === "function") {
        cancellationDisposable.dispose();
      }
    }
  }

  async _fetchRegistryResponse(request, apiKey, signal, redirectCount, isCurrent = null) {
    if (!request || !isTrustedRegistryUrl(request.url)) {
      throw new Error("Refused to send Cloudsmith credentials to an untrusted registry host.");
    }
    if (isCurrent && !isCurrent()) {
      throw new Error("The Cloudsmith account changed during the registry request.");
    }

    const fetchResult = await this._awaitRegistryAbortable(this._fetchImpl(request.url, {
      method: request.method || "GET",
      headers: {
        Authorization: buildBasicAuthHeader(apiKey),
        ...buildRegistryRequestHeaders(request.headers),
      },
      redirect: "manual",
      signal,
    }), signal, cancelRegistryBody);
    if (fetchResult.aborted) {
      throw new Error("Registry request was aborted.");
    }
    if (!fetchResult.ok) {
      throw fetchResult.error;
    }
    const response = fetchResult.value;

    if (!isRedirectStatus(response.status)) {
      return response;
    }

    if (redirectCount >= MAX_REGISTRY_REDIRECTS) {
      await cancelRegistryBody(response);
      throw new Error("Registry request exceeded the redirect limit.");
    }

    const location = response.headers && typeof response.headers.get === "function"
      ? response.headers.get("location")
      : "";
    const redirectUrl = resolveAndValidateRegistryUrl(location, request.url);
    const currentUrl = new URL(request.url);
    const nextUrl = redirectUrl ? new URL(redirectUrl) : null;
    if (!nextUrl || nextUrl.hostname !== currentUrl.hostname) {
      await cancelRegistryBody(response);
      throw new Error("Registry redirect target was rejected.");
    }

    await cancelRegistryBody(response);

    if (isCurrent && !isCurrent()) {
      throw new Error("The Cloudsmith account changed during the registry request.");
    }

    return this._fetchRegistryResponse(
      {
        ...request,
        url: redirectUrl,
      },
      apiKey,
      signal,
      redirectCount + 1,
      isCurrent
    );
  }

  _awaitRegistryAbortable(promise, signal, onLateValue = null) {
    return new Promise((resolve) => {
      let settled = false;
      const finish = (result) => {
        if (settled) return false;
        settled = true;
        signal.removeEventListener("abort", onAbort);
        resolve(result);
        return true;
      };
      const onAbort = () => finish({ aborted: true });
      signal.addEventListener("abort", onAbort, { once: true });
      if (signal.aborted) {
        onAbort();
      }
      Promise.resolve(promise).then(
        (value) => {
          if (!finish({ ok: true, value }) && typeof onLateValue === "function") {
            try {
              Promise.resolve(onLateValue(value)).catch(() => {});
            } catch {
              // Late response cleanup is best effort.
            }
          }
        },
        error => finish({ ok: false, error })
      );
      if (signal.aborted) {
        onAbort();
      }
    });
  }
}

function normalizeRepositoryCollection(value) {
  if (!value || typeof value !== "object") return { items: [], complete: false };
  const items = Array.isArray(value.items) ? value.items : [];
  return {
    items,
    complete: value.complete === true && value.stale !== true,
  };
}

function isRepositoryInspectionCompleteForFormats(state, formats) {
  if (!state || typeof state !== "object") return false;
  if (!Array.isArray(formats) || formats.length === 0) return false;
  const descriptors = [];
  const seen = new Set();
  for (const format of formats) {
    const descriptor = getUpstreamFormatDescriptor(format);
    if (!descriptor) return false;
    if (!seen.has(descriptor.format)) descriptors.push(descriptor);
    seen.add(descriptor.format);
  }
  if (!hasCanonicalCapabilityLists(state)) return false;
  const inspectable = descriptors.filter(descriptor => descriptor.inspectable);
  if (inspectable.length === 0) return true;
  if (!Array.isArray(state.outcomes)) return false;
  const outcomes = new Map();
  for (const outcome of state.outcomes) {
    if (!isCanonicalFormatOutcome(outcome) || outcomes.has(outcome.format)) return false;
    outcomes.set(outcome.format, outcome);
  }
  const expectedFailed = new Set();
  const expectedUninspected = new Set();
  const expectedUnsupported = new Set();
  for (const outcome of outcomes.values()) {
    if (outcome.state === "failed") expectedFailed.add(outcome.format);
    else if (["incomplete", "uninspected", "cancelled"].includes(outcome.state)) {
      expectedUninspected.add(outcome.format);
    } else if (outcome.state === "unsupported") expectedUnsupported.add(outcome.format);
  }
  if (!sameFormatSet(state.failedFormats, expectedFailed)
    || !sameFormatSet(state.uninspectedFormats, expectedUninspected)
    || !sameFormatSet(state.unsupportedFormats, expectedUnsupported)) return false;
  const globalInspectable = [...outcomes.values()].filter(outcome => outcome.apiFormat !== null);
  const aggregateComplete = globalInspectable.length > 0 && globalInspectable.every(outcome => (
    outcome.state === "success" && outcome.authoritative === true
  ));
  if (typeof state.complete !== "boolean") return false;
  if (state.complete === true && !aggregateComplete) return false;
  if (state.complete === false && aggregateComplete) return false;
  if (state.incomplete !== undefined && state.incomplete !== !state.complete) return false;
  if (!hasValidRequestedGroupedUpstreams(state, inspectable)) return false;
  return inspectable.every((descriptor) => {
    const outcome = outcomes.get(descriptor.format);
    return outcome?.apiFormat === descriptor.apiFormat
      && outcome.state === "success"
      && outcome.authoritative === true;
  });
}

function hasValidRequestedGroupedUpstreams(state, descriptors) {
  if (!(state.groupedUpstreams instanceof Map)) return false;
  for (const descriptor of descriptors) {
    if (!state.groupedUpstreams.has(descriptor.format)) continue;
    const upstreams = state.groupedUpstreams.get(descriptor.format);
    if (!Array.isArray(upstreams) || upstreams.some(upstream => (
      !sanitizeSafeInventoryUpstream(upstream, descriptor.format)
    ))) return false;
  }
  return true;
}

function sameFormatSet(values, expected) {
  return values.length === expected.size && values.every(value => expected.has(value));
}

function isPullInspectionFormat(format) {
  const descriptor = getUpstreamFormatDescriptor(format);
  return Boolean(descriptor?.inspectable && !isPullUnsupportedFormat(descriptor.format));
}

function hasCanonicalCapabilityLists(state) {
  const lists = [
    [state.failedFormats, true],
    [state.uninspectedFormats, true],
    [state.unsupportedFormats, false],
  ];
  const seen = new Set();
  for (const [list, inspectable] of lists) {
    if (!Array.isArray(list)) return false;
    for (const format of list) {
      const descriptor = getUpstreamFormatDescriptor(format);
      if (!descriptor || descriptor.format !== format || descriptor.inspectable !== inspectable) {
        return false;
      }
      if (seen.has(format)) return false;
      seen.add(format);
    }
  }
  return true;
}

function isCanonicalFormatOutcome(outcome) {
  if (!outcome || typeof outcome !== "object") return false;
  const descriptor = getUpstreamFormatDescriptor(outcome.format);
  if (!descriptor || descriptor.format !== outcome.format) return false;
  if (outcome.apiFormat !== descriptor.apiFormat) return false;
  if (descriptor.inspectable) {
    if (outcome.state === "success") return outcome.authoritative === true;
    return ["failed", "incomplete", "uninspected", "cancelled"].includes(outcome.state)
      && outcome.authoritative === false;
  }
  return outcome.state === "unsupported" && outcome.authoritative === true;
}

function buildRegistryRequestHeaders(headers) {
  if (!headers || typeof headers !== "object") {
    return {};
  }
  const accept = headers.Accept || headers.accept;
  if (typeof accept !== "string" || accept.length > 1024 || /[\r\n]/.test(accept)) {
    return {};
  }
  return { Accept: accept };
}

function cancelRegistryBody(response) {
  if (response && response.body && typeof response.body.cancel === "function") {
    try {
      Promise.resolve(response.body.cancel()).catch(() => {});
    } catch {
      // The connection may already have been closed by the fetch implementation.
    }
  }
}

async function discardRegistryBody(response, signal) {
  if (!response || !response.body) {
    return "";
  }
  if (typeof response.body.getReader !== "function") {
    await cancelRegistryBody(response);
    throw new Error("Registry response did not provide a readable body stream.");
  }

  const reader = response.body.getReader();
  try {
    while (true) {
      if (signal && signal.aborted) {
        cancelRegistryReader(reader);
        throw new Error("Registry response body read was aborted.");
      }
      const chunkResult = await readRegistryChunk(reader, signal);
      if (chunkResult.aborted) {
        throw new Error("Registry response body read was aborted.");
      }
      if (!chunkResult.ok) {
        throw chunkResult.error;
      }
      const chunk = chunkResult.value;
      if (chunk.done) {
        break;
      }
    }
    if (signal && signal.aborted) {
      throw new Error("Registry response body read was aborted.");
    }
    return "";
  } catch (error) {
    try {
      cancelRegistryReader(reader);
    } catch {
      // The connection may already be closed.
    }
    throw error;
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // The stream may already be detached.
    }
  }
}

async function readRegistryBody(response, byteLimit, signal) {
  const contentLength = response && response.headers && typeof response.headers.get === "function"
    ? Number(response.headers.get("content-length"))
    : NaN;
  if (Number.isFinite(contentLength) && contentLength > byteLimit) {
    await cancelRegistryBody(response);
    throw new Error("Registry metadata response exceeded the size limit.");
  }

  if (!response || !response.body) {
    return "";
  }
  if (typeof response.body.getReader !== "function") {
    await cancelRegistryBody(response);
    throw new Error("Registry metadata response did not provide a readable body stream.");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let bytesRead = 0;
  let text = "";
  let completed = false;
  try {
    while (true) {
      if (signal && signal.aborted) {
        cancelRegistryReader(reader);
        throw new Error("Registry metadata response read was aborted.");
      }
      const chunkResult = await readRegistryChunk(reader, signal);
      if (chunkResult.aborted) {
        throw new Error("Registry metadata response read was aborted.");
      }
      if (!chunkResult.ok) {
        throw chunkResult.error;
      }
      const chunk = chunkResult.value;
      if (chunk.done) {
        break;
      }
      bytesRead += chunk.value.byteLength;
      if (bytesRead > byteLimit) {
        cancelRegistryReader(reader);
        throw new Error("Registry metadata response exceeded the size limit.");
      }
      text += decoder.decode(chunk.value, { stream: true });
    }
    if (signal && signal.aborted) {
      throw new Error("Registry metadata response read was aborted.");
    }
    text += decoder.decode();
    completed = true;
    return text;
  } catch (error) {
    if (!completed) {
      try {
        cancelRegistryReader(reader);
      } catch {
        // The connection may already be closed.
      }
    }
    throw error;
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // The stream may already be detached.
    }
  }
}

function cancelRegistryReader(reader) {
  if (!reader || typeof reader.cancel !== "function") {
    return;
  }
  try {
    Promise.resolve(reader.cancel()).catch(() => {});
  } catch {
    // The stream may already be closed or detached.
  }
}

function readRegistryChunk(reader, signal) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      resolve(result);
    };
    const onAbort = () => {
      cancelRegistryReader(reader);
      finish({ aborted: true });
    };
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) {
      onAbort();
      return;
    }
    Promise.resolve()
      .then(() => reader.read())
      .then(value => finish({ ok: true, value }), error => finish({ ok: false, error }));
    if (signal.aborted) {
      onAbort();
    }
  });
}

function buildPullExecutionPlan(workspace, repo, dependencies, activeUpstreamFormats) {
  const normalizedActiveFormats = [...new Set(
    (Array.isArray(activeUpstreamFormats) ? activeUpstreamFormats : [])
      .map((format) => normalizeUpstreamFormat(format))
      .filter(Boolean)
  )];

  const uniqueDependencies = dedupePullDependencies(dependencies);
  const skippedDependencies = [];
  const pullableDependencies = [];

  for (const dependency of uniqueDependencies) {
    const format = canonicalFormat(formatForDependency(dependency) || dependency.ecosystem || "");
    const triggerPlan = buildRegistryTriggerPlan(workspace, repo, dependency);

    if (isPullUnsupportedFormat(format)) {
      skippedDependencies.push({
        dependency,
        format,
        reason: PULL_SKIP_REASON.NO_PULL_SUPPORT,
        message: `Pull-through caching is not supported for ${formatDisplayName(format)} dependencies.`,
      });
      continue;
    }

    if (!triggerPlan) {
      skippedDependencies.push({
        dependency,
        format,
        reason: PULL_SKIP_REASON.NO_TRIGGER_URL,
        message: `No registry trigger URL is available for ${formatDisplayName(format)} dependencies.`,
      });
      continue;
    }

    if (!normalizedActiveFormats.includes(normalizeUpstreamFormat(format))) {
      skippedDependencies.push({
        dependency,
        format,
        reason: PULL_SKIP_REASON.NO_ACTIVE_UPSTREAM,
        message: `No ${formatDisplayName(format)} upstream is configured on this repository.`,
      });
      continue;
    }

    pullableDependencies.push(dependency);
  }

  return {
    dependencies: uniqueDependencies,
    pullableDependencies,
    skippedDependencies,
    activeUpstreamFormats: normalizedActiveFormats,
  };
}

function buildPullConfirmationMessage(plan, repositoryLabel) {
  const totalCount = plan.dependencies.length;
  const pullableCount = plan.pullableDependencies.length;
  const header = plan.skippedDependencies.length > 0
    ? `Pull ${pullableCount} of ${totalCount} dependencies through ${repositoryLabel}?`
    : singleFormatPullHeader(plan.pullableDependencies, repositoryLabel);
  const pulledLine = buildPullableSummary(plan.pullableDependencies, plan.skippedDependencies.length > 0);
  const skippedLine = buildSkippedSummary(plan.skippedDependencies);

  return [
    header,
    pulledLine,
    skippedLine,
    "Packages not already cached will be fetched from the upstream source.",
  ].filter(Boolean).join("\n");
}

function buildPullPlanErrorMessage(repositoryLabel, plan) {
  const noUpstreamFormats = [...new Set(
    plan.skippedDependencies
      .filter((entry) => entry.reason === PULL_SKIP_REASON.NO_ACTIVE_UPSTREAM)
      .map((entry) => entry.format)
      .filter(Boolean)
  )];

  if (plan.pullableDependencies.length === 0 && noUpstreamFormats.length > 0) {
    return `No ${formatListLabel(noUpstreamFormats)} upstream${noUpstreamFormats.length === 1 ? "" : "s"} are configured on ${repositoryLabel}.`;
  }

  return "Pull-through caching is not available for the uncovered dependencies in this project.";
}

function buildPullSummaryMessage(result, skippedCount) {
  const pulledCount = result.cached + result.alreadyExisted;
  const parts = [
    `Pulled ${pulledCount} of ${result.total} dependencies.`,
    `${result.cached} cached`,
    `${result.alreadyExisted} already existed`,
    `${result.notFound} not found upstream`,
  ];

  if (skippedCount > 0) {
    parts.push(`${skippedCount} skipped`);
  }

  if (result.errors > 0) {
    parts.push(`${result.errors} errors`);
  }

  return `${parts.shift()} ${parts.join(", ")}.`;
}

function buildProgressMessage(counts) {
  const parts = [`Pulling dependencies... ${counts.completed}/${counts.total}`];
  const detail = [];

  if (counts.cached > 0) {
    detail.push(`${counts.cached} cached`);
  }
  if (counts.notFound > 0) {
    detail.push(`${counts.notFound} not found`);
  }
  if (counts.errors > 0) {
    detail.push(`${counts.errors} errors`);
  }

  if (detail.length > 0) {
    parts.push(`(${detail.join(", ")})`);
  }

  return parts.join(" ");
}

function createResultCounts(total) {
  return {
    total,
    completed: 0,
    cached: 0,
    alreadyExisted: 0,
    notFound: 0,
    formatMismatched: 0,
    errors: 0,
    networkErrors: 0,
    authFailed: 0,
    skipped: 0,
  };
}

function updateResultCounts(counts, result) {
  counts.completed += 1;
  switch (result.status) {
    case PULL_STATUS.CACHED:
      counts.cached += 1;
      break;
    case PULL_STATUS.ALREADY_EXISTS:
      counts.alreadyExisted += 1;
      break;
    case PULL_STATUS.NOT_FOUND:
      counts.notFound += 1;
      break;
    case PULL_STATUS.FORMAT_MISMATCH:
      counts.formatMismatched += 1;
      break;
    case PULL_STATUS.AUTH_FAILED:
      counts.authFailed += 1;
      counts.errors += 1;
      break;
    case PULL_STATUS.SKIPPED:
      counts.skipped += 1;
      break;
    case PULL_STATUS.ERROR:
      counts.errors += 1;
      if (result.networkError) {
        counts.networkErrors += 1;
      }
      break;
    default:
      break;
  }
}

function recomputeResultCounts(counts, results) {
  const next = createResultCounts(results.length);
  for (const result of results) {
    updateResultCounts(next, result);
  }

  Object.assign(counts, next);
}

function mapRegistryAttempt(dependency, attempt, format) {
  if (attempt.statusCode >= 200 && attempt.statusCode < 300) {
    return {
      dependency,
      status: PULL_STATUS.CACHED,
      errorMessage: null,
      networkError: false,
    };
  }

  if (attempt.statusCode === 304 || attempt.statusCode === 409) {
    return {
      dependency,
      status: PULL_STATUS.ALREADY_EXISTS,
      errorMessage: null,
      networkError: false,
    };
  }

  if (attempt.statusCode === 401 || attempt.statusCode === 403) {
    return {
      dependency,
      status: PULL_STATUS.AUTH_FAILED,
      errorMessage: "Authentication failed.",
      networkError: false,
    };
  }

  if (attempt.statusCode === 404) {
    return {
      dependency,
      status: PULL_STATUS.NOT_FOUND,
      errorMessage: defaultNotFoundMessage(format),
      networkError: false,
    };
  }

  if (attempt.statusCode === 0) {
    return {
      dependency,
      status: PULL_STATUS.ERROR,
      errorMessage: attempt.errorMessage || "Registry request failed.",
      networkError: Boolean(attempt.networkError),
    };
  }

  return {
    dependency,
    status: PULL_STATUS.ERROR,
    errorMessage: `Registry request returned HTTP ${attempt.statusCode}.`,
    networkError: false,
  };
}

function defaultNotFoundMessage(format) {
  switch (format) {
    case "docker":
      return "Image manifest not found upstream.";
    case "go":
      return "Go module metadata not found upstream.";
    case "cargo":
      return "Cargo index entry not found upstream.";
    case "helm":
      return "Chart archive not found upstream.";
    default:
      return "Package not found upstream.";
  }
}

function missingArtifactMessage(strategy, version) {
  switch (strategy) {
    case "python-simple-index":
      return `No distribution file was found for version ${version}.`;
    case "dart-api":
      return `No Dart archive URL was found for version ${version}.`;
    case "composer-p2":
      return `No Composer dist URL was found for version ${version}.`;
    default:
      return "No downloadable artifact was found.";
  }
}

function buildRegistryErrorMessage(url, error) {
  if (isNetworkError(error)) {
    return "Cannot reach the Cloudsmith registry. Check your network connection.";
  }

  if (error && SAFE_REGISTRY_ERROR_MESSAGES.has(error.message)) {
    return error.message;
  }
  const host = safeHost(url);
  return host ? `Registry request failed (${host}).` : "Registry request failed.";
}

function isNetworkError(error) {
  const code = error && (
    error.code
    || (error.cause && error.cause.code)
    || (error.errno)
  );

  if (["ECONNREFUSED", "ECONNRESET", "ENOTFOUND", "EHOSTUNREACH", "ETIMEDOUT"].includes(code)) {
    return true;
  }

  const message = String(error && error.message || "").toLowerCase();
  return message.includes("fetch failed")
    || message.includes("network")
    || message.includes("timed out")
    || message.includes("econnrefused")
    || message.includes("enotfound");
}

function buildBasicAuthHeader(apiKey) {
  return `Basic ${Buffer.from(`token:${apiKey}`).toString("base64")}`;
}

function isRedirectStatus(statusCode) {
  return Number.isInteger(statusCode) && statusCode >= 300 && statusCode < 400;
}

function safeHost(url) {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}

function dedupePullDependencies(dependencies) {
  const unique = new Map();

  for (const dependency of Array.isArray(dependencies) ? dependencies : []) {
    const key = pullDependencyKey(dependency);
    if (!unique.has(key)) {
      unique.set(key, dependency);
    }
  }

  return [...unique.values()];
}

function isConclusiveCloudsmithAbsence(status) {
  return status === "ABSENT" || status === "NOT_FOUND";
}

function pullDependencyKey(dependency) {
  const format = String(
    canonicalFormat(dependency && (dependency.format || dependency.ecosystem)) || ""
  ).toLowerCase();
  return [
    format,
    normalizePackageName(dependency && dependency.name, format),
    String(dependency && dependency.version || "").trim(),
  ].join(":");
}

function singleFormatPullHeader(dependencies, repositoryLabel) {
  const formats = [...new Set(
    dependencies.map((dependency) => canonicalFormat(formatForDependency(dependency))).filter(Boolean)
  )];

  if (formats.length === 1) {
    return `Pull ${dependencies.length} ${formatDisplayName(formats[0])} dependenc${dependencies.length === 1 ? "y" : "ies"} through ${repositoryLabel}?`;
  }

  return `Pull ${dependencies.length} dependencies through ${repositoryLabel}?`;
}

function buildPullableSummary(dependencies, forceSummary) {
  const groups = groupCountsByFormat(dependencies);
  if (groups.length === 0) {
    return "";
  }

  if (!forceSummary && groups.length === 1) {
    return "";
  }

  return `${groups.map(({ count, format }) => `${count} ${formatDisplayName(format)}`).join(" + ")} will be pulled.`;
}

function buildSkippedSummary(skippedDependencies) {
  const groups = groupCountsByFormat(skippedDependencies.map((entry) => ({
    format: entry.format,
  })));

  if (groups.length === 0) {
    return "";
  }

  const reason = skippedDependencies.every((entry) => entry.reason === PULL_SKIP_REASON.NO_ACTIVE_UPSTREAM)
    ? "no matching upstream is configured on this repository"
    : "pull-through is not available for these formats";

  return `${groups.map(({ count, format }) => `${count} ${formatDisplayName(format)}`).join(" + ")} will be skipped (${reason}).`;
}

function groupCountsByFormat(dependencies) {
  const counts = new Map();

  for (const dependency of Array.isArray(dependencies) ? dependencies : []) {
    const format = canonicalFormat(
      dependency && (dependency.format || dependency.ecosystem || formatForDependency(dependency))
    );
    if (!format) {
      continue;
    }
    counts.set(format, (counts.get(format) || 0) + 1);
  }

  return [...counts.entries()]
    .map(([format, count]) => ({ format, count }))
    .sort((left, right) => {
      if (right.count !== left.count) {
        return right.count - left.count;
      }
      return formatDisplayName(left.format).localeCompare(formatDisplayName(right.format), undefined, {
        sensitivity: "base",
      });
    });
}

function formatDisplayName(format) {
  const normalized = String(canonicalFormat(format) || format || "").trim().toLowerCase();
  switch (normalized) {
    case "npm":
      return "npm";
    case "python":
      return "Python";
    case "go":
      return "Go";
    case "nuget":
      return "NuGet";
    default:
      return normalized ? normalized.charAt(0).toUpperCase() + normalized.slice(1) : "Unknown";
  }
}

function formatListLabel(formats) {
  return [...new Set(
    (Array.isArray(formats) ? formats : [])
      .map((format) => formatDisplayName(format))
      .filter(Boolean)
  )].join(", ");
}

function normalizeSingleDependency(dependency) {
  if (!dependency || typeof dependency !== "object") {
    return null;
  }

  const format = canonicalFormat(formatForDependency(dependency) || dependency.format || dependency.ecosystem);
  const name = String(dependency.name || "").trim();
  if (!name || !format) {
    return null;
  }

  return {
    ...dependency,
    name,
    version: dependency.version || dependency.declaredVersion || "",
    format,
    ecosystem: dependency.ecosystem || format,
  };
}

function buildDependencyLabel(dependency) {
  const name = String(dependency && dependency.name || "").trim() || "dependency";
  const version = String(dependency && dependency.version || "").trim();
  return version ? `${name}@${version}` : name;
}

function buildSingleDependencyRepositoryDetail(match, format) {
  const upstreams = match && match.activeUpstreamsByFormat instanceof Map
    ? match.activeUpstreamsByFormat.get(format)
    : [];
  const activeUpstream = Array.isArray(upstreams) ? upstreams[0] : null;
  const configuredName = String(activeUpstream && activeUpstream.name || "").trim();
  const sourceLabel = configuredName || defaultUpstreamSourceLabel(format);
  if (!sourceLabel) {
    return `${formatDisplayName(format)} upstream configured`;
  }
  return `${formatDisplayName(format)} upstream (${sourceLabel})`;
}

function defaultUpstreamSourceLabel(format) {
  switch (canonicalFormat(format)) {
    case "cargo":
      return "crates.io";
    case "composer":
      return "Packagist";
    case "conda":
      return "Conda";
    case "dart":
      return "pub.dev";
    case "docker":
      return "Docker";
    case "go":
      return "Go";
    case "helm":
      return "Helm";
    case "hex":
      return "Hex";
    case "maven":
      return "Maven";
    case "npm":
      return "npm";
    case "nuget":
      return "NuGet";
    case "python":
      return "PyPI";
    case "ruby":
      return "RubyGems";
    case "swift":
      return "Swift";
    default:
      return null;
  }
}

function sortRepositoryMatches(matches, repositoryHint) {
  const hint = String(repositoryHint || "").trim().toLowerCase();
  if (!hint) {
    return matches;
  }

  return matches.slice().sort((left, right) => {
    const leftSlug = String(left.repo.slug || "").toLowerCase();
    const rightSlug = String(right.repo.slug || "").toLowerCase();
    const leftPriority = leftSlug === hint ? 0 : 1;
    const rightPriority = rightSlug === hint ? 0 : 1;
    if (leftPriority !== rightPriority) {
      return leftPriority - rightPriority;
    }
    return leftSlug.localeCompare(rightSlug, undefined, { sensitivity: "base" });
  });
}

async function runPromisePool(items, concurrency, worker) {
  const workers = [];
  let index = 0;
  const size = Math.max(1, Math.min(concurrency, items.length || 1));

  for (let workerIndex = 0; workerIndex < size; workerIndex += 1) {
    workers.push((async () => {
      while (index < items.length) {
        const item = items[index];
        index += 1;
        if (item === undefined) {
          break;
        }
        if (await worker(item) === false) break;
      }
    })());
  }

  await Promise.allSettled(workers);
}

function isCancellationRequested(token) {
  return Boolean(token && token.isCancellationRequested);
}

async function publishStatus(onStatus, detail) {
  if (!onStatus) return true;
  try {
    await onStatus(detail);
    return true;
  } catch {
    return false;
  }
}

function publishProgress(progress, update) {
  if (!progress || typeof progress.report !== "function") return;
  try {
    progress.report(update);
  } catch {
    // Progress is observational; a disposed or faulty reporter must not alter pull outcomes.
  }
}

function createPullFailure(dependency, errorMessage) {
  return {
    dependency,
    status: PULL_STATUS.ERROR,
    errorMessage,
    networkError: false,
  };
}

function toPublicPullDetail(result) {
  return {
    dependency: result.dependency,
    status: result.status,
    errorMessage: result.errorMessage || null,
    networkError: result.networkError === true,
  };
}

function repositoryCollectionFailureMessage(error) {
  switch (error && error.kind) {
    case "rate_limited":
      return "Cloudsmith rate limited the repository lookup. Try again later.";
    case "unauthorized":
    case "forbidden":
      return "Cloudsmith repository access could not be authorized.";
    default:
      return "Could not fetch workspace repositories.";
  }
}

module.exports = {
  PULL_SKIP_REASON,
  PULL_STATUS,
  UpstreamPullService,
  buildPullSummaryMessage,
};

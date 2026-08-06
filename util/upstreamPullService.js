// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const vscode = require("vscode");
const { CloudsmithAPI } = require("./cloudsmithAPI");
const { CredentialManager } = require("./credentialManager");
const { PaginatedFetch } = require("./paginatedFetch");
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
const { canonicalFormat } = require("./packageNameNormalizer");
const { UpstreamChecker } = require("./upstreamChecker");
const { normalizeUpstreamFormat } = require("./upstreamFormats");

const MAX_CONCURRENT_PULLS = 5;
const INITIAL_AUTH_PROBE_CONCURRENCY = 3;
const MAX_REGISTRY_REDIRECTS = 5;
const REQUEST_TIMEOUT_MS = 30 * 1000;
const WORKSPACE_REPOSITORY_PAGE_SIZE = 500;

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
    this._fetchRepositories = options.fetchRepositories || this._fetchWorkspaceRepositories.bind(this);
    this._showQuickPick = options.showQuickPick || vscode.window.showQuickPick.bind(vscode.window);
    this._showErrorMessage = options.showErrorMessage || vscode.window.showErrorMessage.bind(vscode.window);
    this._showInformationMessage = options.showInformationMessage || vscode.window.showInformationMessage.bind(vscode.window);
    this._showWarningMessage = options.showWarningMessage || vscode.window.showWarningMessage.bind(vscode.window);
    this._upstreamChecker = options.upstreamChecker || new UpstreamChecker(context);
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
  }) {
    const uncoveredDependencies = dedupePullDependencies(
      (Array.isArray(dependencies) ? dependencies : [])
        .filter((dependency) => dependency && dependency.cloudsmithStatus !== "FOUND")
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

    if (projectFormats.length === 0) {
      await this._showInformationMessage(
        "Pull-through caching is not available for the uncovered dependency formats in this project."
      );
      return null;
    }

    let repositories;
    try {
      repositories = await this._fetchRepositories(workspace);
    } catch (error) {
      const message = error && error.message ? error.message : "Could not fetch workspace repositories.";
      await this._showErrorMessage(message);
      return null;
    }

    const repositoryMatches = await this._findMatchingRepositories(workspace, repositories, projectFormats);
    if (repositoryMatches.length === 0) {
      await this._showInformationMessage(
        `No repositories have upstream proxies configured for the dependency formats in this project (${formatListLabel(projectFormats)}). Configure an upstream proxy in Cloudsmith to enable pull-through caching.`
      );
      return null;
    }

    const orderedMatches = sortRepositoryMatches(repositoryMatches, repositoryHint);
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

    if (!selected || !selected._match) {
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

    if (confirmation !== "Pull dependencies") {
      return null;
    }

    return {
      workspace,
      repository,
      plan,
    };
  }

  async prepareSingle({
    workspace,
    repositoryHint,
    dependency,
  }) {
    const normalizedDependency = normalizeSingleDependency(dependency);
    if (!workspace) {
      await this._showErrorMessage("Run a dependency scan against a Cloudsmith workspace first.");
      return null;
    }

    if (!normalizedDependency) {
      await this._showWarningMessage("Could not determine the dependency details to pull.");
      return null;
    }

    const dependencyFormat = normalizeUpstreamFormat(formatForDependency(normalizedDependency));
    if (!dependencyFormat) {
      await this._showInformationMessage(
        `Pull-through caching is not available for ${formatDisplayName(normalizedDependency.format)} dependencies.`
      );
      return null;
    }

    let repositories;
    try {
      repositories = await this._fetchRepositories(workspace);
    } catch (error) {
      const message = error && error.message ? error.message : "Could not fetch workspace repositories.";
      await this._showErrorMessage(message);
      return null;
    }

    const repositoryMatches = await this._findMatchingRepositories(workspace, repositories, [dependencyFormat]);
    if (repositoryMatches.length === 0) {
      await this._showInformationMessage(
        `No repositories have a ${formatDisplayName(dependencyFormat)} upstream configured. Add one in Cloudsmith to pull this dependency.`
      );
      return null;
    }

    const orderedMatches = sortRepositoryMatches(repositoryMatches, repositoryHint);
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

    if (!selected || !selected._match) {
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
    };
  }

  async execute(prepared, options = {}) {
    const apiKey = await this._credentialManager.getApiKey();
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
    };
    const pending = new Set();
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
          requestUrl: buildPullRequestUrl(prepared.workspace, prepared.repository.slug, dependency),
        };
        if (onStatus) {
          await onStatus(pullingDetail);
        }

        const result = await this._pullDependency(
          prepared.workspace,
          prepared.repository.slug,
          dependency,
          apiKey,
          token
        );

        if (result.canceled) {
          state.canceled = true;
          return;
        }

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

        if (progress) {
          progress.report({
            message: buildProgressMessage(counts),
            increment: counts.total > 0 ? 100 / counts.total : 100,
          });
        }

        if (onStatus) {
          await onStatus(result);
        }
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
        && !state.stopForAuthFailure
      ) {
        launchedCount += 1;
        const promise = processNext();
        pending.add(promise);
        promise.finally(() => pending.delete(promise));
      }
    };

    fillConcurrency();

    while (pending.size > 0) {
      await Promise.race([...pending]);
    }

    if (state.stopForAuthFailure) {
      while (nextDependencyIndex < queue.length) {
        const dependency = queue[nextDependencyIndex];
        nextDependencyIndex += 1;
        details.push({
          dependency,
          status: PULL_STATUS.AUTH_FAILED,
          errorMessage: "Skipped after repeated authentication failures.",
          requestUrl: buildPullRequestUrl(prepared.workspace, prepared.repository.slug, dependency),
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

  async _findMatchingRepositories(workspace, repositories, projectFormats) {
    const matches = [];

    await runPromisePool(repositories, 5, async (repo) => {
      const repoSlug = repo && repo.slug ? repo.slug : null;
      if (!repoSlug) {
        return;
      }

      const state = await this._upstreamChecker.getRepositoryUpstreamState(workspace, repoSlug);
      const activeUpstreamsByFormat = new Map();
      const activeFormats = projectFormats.filter((format) => {
        const upstreams = state && state.groupedUpstreams instanceof Map
          ? state.groupedUpstreams.get(format)
          : [];
        const activeUpstreams = Array.isArray(upstreams)
          ? upstreams.filter((upstream) => upstream && upstream.is_active !== false)
          : [];
        if (activeUpstreams.length > 0) {
          activeUpstreamsByFormat.set(format, activeUpstreams);
          return true;
        }
        return false;
      });

      if (activeFormats.length === 0) {
        return;
      }

      matches.push({
        repo,
        activeFormats,
        activeUpstreamsByFormat,
      });
    });

    return matches.sort((left, right) => {
      const leftSlug = String(left.repo.slug || left.repo.name || "");
      const rightSlug = String(right.repo.slug || right.repo.name || "");
      return leftSlug.localeCompare(rightSlug, undefined, { sensitivity: "base" });
    });
  }

  async _fetchWorkspaceRepositories(workspace) {
    const paginatedFetch = new PaginatedFetch(this._api);
    const endpoint = `repos/${workspace}/?sort=name`;
    const repositories = [];
    let page = 1;

    while (true) {
      const result = await paginatedFetch.fetchPage(endpoint, page, WORKSPACE_REPOSITORY_PAGE_SIZE);
      if (result.error) {
        throw new Error(`Could not fetch workspace repositories. ${result.error}`);
      }

      repositories.push(...(Array.isArray(result.data) ? result.data : []));

      const pageTotal = result.pagination && result.pagination.pageTotal
        ? result.pagination.pageTotal
        : 1;
      if (page >= pageTotal) {
        break;
      }
      page += 1;
    }

    return repositories;
  }

  async _pullDependency(workspace, repo, dependency, apiKey, token) {
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
        requestUrl: null,
        networkError: false,
      };
    }

    const metadataAttempt = await this._requestRegistry(plan.request, apiKey, token);
    if (metadataAttempt.canceled) {
      return metadataAttempt;
    }

    if (plan.strategy === "direct") {
      return mapRegistryAttempt(dependency, metadataAttempt, plan.request.url, format);
    }

    if (metadataAttempt.statusCode === 401 || metadataAttempt.statusCode === 403) {
      return mapRegistryAttempt(dependency, metadataAttempt, plan.request.url, format);
    }

    if (metadataAttempt.statusCode === 404) {
      return mapRegistryAttempt(dependency, metadataAttempt, plan.request.url, format);
    }

    if (metadataAttempt.statusCode < 200 || metadataAttempt.statusCode >= 300) {
      return mapRegistryAttempt(dependency, metadataAttempt, plan.request.url, format);
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
        requestUrl: plan.request.url,
        networkError: false,
      };
    }

    const artifactAttempt = await this._requestRegistry(
      {
        method: "GET",
        url: artifactUrl,
        headers: {},
      },
      apiKey,
      token
    );

    if (artifactAttempt.canceled) {
      return artifactAttempt;
    }

    return mapRegistryAttempt(dependency, artifactAttempt, artifactUrl, format);
  }

  async _requestRegistry(request, apiKey, token) {
    const controller = new AbortController();
    let didTimeout = false;
    const timeoutHandle = setTimeout(() => {
      didTimeout = true;
      controller.abort();
    }, REQUEST_TIMEOUT_MS);

    const cancellationDisposable = token && typeof token.onCancellationRequested === "function"
      ? token.onCancellationRequested(() => controller.abort())
      : null;

    try {
      const response = await this._fetchRegistryResponse(
        request,
        apiKey,
        controller.signal,
        0
      );

      return {
        statusCode: response.status,
        body: await response.text(),
      };
    } catch (error) {
      if (token && token.isCancellationRequested) {
        return { canceled: true };
      }

      return {
        statusCode: 0,
        body: "",
        errorMessage: didTimeout
          ? "Registry request timed out."
          : buildRegistryErrorMessage(request.url, error),
        networkError: isNetworkError(error) || didTimeout,
      };
    } finally {
      clearTimeout(timeoutHandle);
      if (cancellationDisposable && typeof cancellationDisposable.dispose === "function") {
        cancellationDisposable.dispose();
      }
    }
  }

  async _fetchRegistryResponse(request, apiKey, signal, redirectCount) {
    if (!request || !isTrustedRegistryUrl(request.url)) {
      throw new Error("Refused to send Cloudsmith credentials to an untrusted registry host.");
    }

    const response = await this._fetchImpl(request.url, {
      method: request.method || "GET",
      headers: {
        Authorization: buildBasicAuthHeader(apiKey),
        ...(request.headers || {}),
      },
      redirect: "manual",
      signal,
    });

    if (!isRedirectStatus(response.status)) {
      return response;
    }

    if (redirectCount >= MAX_REGISTRY_REDIRECTS) {
      throw new Error("Registry request exceeded the redirect limit.");
    }

    const location = response.headers && typeof response.headers.get === "function"
      ? response.headers.get("location")
      : "";
    const redirectUrl = resolveAndValidateRegistryUrl(location, request.url);
    if (!redirectUrl || !isTrustedRegistryUrl(redirectUrl)) {
      throw new Error("Registry redirect target was rejected.");
    }

    return this._fetchRegistryResponse(
      {
        ...request,
        url: redirectUrl,
      },
      apiKey,
      signal,
      redirectCount + 1
    );
  }
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

function mapRegistryAttempt(dependency, attempt, requestUrl, format) {
  if (attempt.statusCode >= 200 && attempt.statusCode < 300) {
    return {
      dependency,
      status: PULL_STATUS.CACHED,
      errorMessage: null,
      requestUrl,
      networkError: false,
    };
  }

  if (attempt.statusCode === 304 || attempt.statusCode === 409) {
    return {
      dependency,
      status: PULL_STATUS.ALREADY_EXISTS,
      errorMessage: null,
      requestUrl,
      networkError: false,
    };
  }

  if (attempt.statusCode === 401 || attempt.statusCode === 403) {
    return {
      dependency,
      status: PULL_STATUS.AUTH_FAILED,
      errorMessage: "Authentication failed.",
      requestUrl,
      networkError: false,
    };
  }

  if (attempt.statusCode === 404) {
    return {
      dependency,
      status: PULL_STATUS.NOT_FOUND,
      errorMessage: defaultNotFoundMessage(format),
      requestUrl,
      networkError: false,
    };
  }

  if (attempt.statusCode === 0) {
    return {
      dependency,
      status: PULL_STATUS.ERROR,
      errorMessage: attempt.errorMessage || "Registry request failed.",
      requestUrl,
      networkError: Boolean(attempt.networkError),
    };
  }

  return {
    dependency,
    status: PULL_STATUS.ERROR,
    errorMessage: `Registry request returned HTTP ${attempt.statusCode}.`,
    requestUrl,
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

  const host = safeHost(url);
  const message = error && error.message ? error.message : "Registry request failed.";
  return host ? `${message} (${host})` : message;
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

function buildPullRequestUrl(workspace, repo, dependency) {
  const plan = buildRegistryTriggerPlan(workspace, repo, dependency);
  return plan && plan.request ? plan.request.url : null;
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

function pullDependencyKey(dependency) {
  return [
    String(canonicalFormat(dependency && (dependency.format || dependency.ecosystem)) || "").toLowerCase(),
    String(dependency && dependency.name || "").toLowerCase(),
    String(dependency && dependency.version || "").toLowerCase(),
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
        await worker(item);
      }
    })());
  }

  await Promise.all(workers);
}

module.exports = {
  PULL_SKIP_REASON,
  PULL_STATUS,
  UpstreamPullService,
  buildPullSummaryMessage,
};

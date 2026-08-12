// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const vscode = require("vscode");
const crypto = require("crypto");
const { types: { isProxy } } = require("util");
const {
  getAllUpstreamData,
  getUpstreamDataForFormats,
  isSafeInventoryUpstream,
  sanitizeSafeInventoryUpstream,
} = require("../util/upstreamChecker");
const {
  getUpstreamFormatDescriptor,
  INSPECTABLE_UPSTREAM_FORMATS,
  SUPPORTED_UPSTREAM_FORMATS,
} = require("../util/upstreamFormats");
const {
  formatUpstreamFailureCategory,
  formatUpstreamOrigin,
  formatUpstreamText,
} = require("../util/upstreamPresentation");

const SUPPORTED_FORMATS = SUPPORTED_UPSTREAM_FORMATS;
const MAX_RENDERED_UPSTREAMS = 200;
const MAX_DISTRIBUTION_VERSIONS = 20;
const MAX_VALIDATED_UPSTREAMS = 5000;
const MAX_VALIDATED_UPSTREAMS_PER_FORMAT = 500;
const FAILURE_CATEGORIES = new Set([
  "authentication", "cancelled", "invalid_response", "network", "not_found",
  "permission", "rate_limit", "request_limit", "request_rejected", "server",
  "timeout", "uninspected", "unknown",
]);
const FAILURE_KEYS = new Set([
  "apiFormat", "category", "format", "httpStatus", "message", "requestId",
  "retryable", "retryAfterMs", "serverRequestId", "state",
]);
const OUTCOME_FAILURE_KEYS = new Set([
  "category", "httpStatus", "message", "requestId", "retryable", "retryAfterMs",
  "serverRequestId",
]);

class UpstreamDetailProvider {
  constructor(context, options = {}) {
    this.context = context;
    this._loadUpstreams = options.loadUpstreams || ((workspace, repoSlug, requestOptions) => (
      Array.isArray(requestOptions.formats)
        ? getUpstreamDataForFormats(
          this.context, workspace, repoSlug, requestOptions.formats, requestOptions
        )
        : getAllUpstreamData(this.context, workspace, repoSlug, requestOptions)
    ));
    this._panel = null;
    this._abortController = null;
    this._requestId = 0;
    this._loadPromise = null;
    this._lastSettled = null;
    this._scope = null;
    this._messageDisposable = null;
  }

  async show(workspace, repoSlug, repoName) {
    if (!workspace || !repoSlug || !repoName) {
      vscode.window.showWarningMessage("Could not determine repository details for upstream inspection.");
      return;
    }

    const scope = JSON.stringify([workspace, repoSlug]);
    if (this._loadPromise && this._scope === scope) {
      this._panel?.reveal(vscode.ViewColumn.One);
      return this._loadPromise;
    }
    this._abortInFlightRequest();
    if (this._scope !== scope) this._lastSettled = null;
    this._scope = scope;
    const requestId = ++this._requestId;
    const abortController = new AbortController();
    this._abortController = abortController;
    const panel = this._getOrCreatePanel(repoName);
    let loadPromise = null;

    try {
      if (!this._canRender(panel, requestId)) {
        return;
      }

      panel.title = `Upstreams: ${formatUpstreamText(repoName, "Unknown repository")}`;
      panel.webview.html = this._lastSettled
        ? this._getHtmlContent(workspace, repoSlug, repoName, this._lastSettled, { refreshing: true })
        : this._getLoadingHtml(workspace, repoSlug, repoName);

      loadPromise = this._fetchGroupedUpstreams(
        workspace, repoSlug, abortController.signal, { bypassCache: false }
      );
      this._loadPromise = loadPromise;
      let fetchState;
      try {
        fetchState = await loadPromise;
      } catch {
        fetchState = failedFetchState();
      }

      if (!fetchState) {
        if (this._canRender(panel, requestId) && !abortController.signal.aborted) {
          panel.webview.html = this._getHtmlContent(workspace, repoSlug, repoName, {
            groupedUpstreams: new Map(),
            failedFormats: SUPPORTED_UPSTREAM_FORMATS,
            uninspectedFormats: [],
            successfulFormats: 0,
            complete: false,
          });
        }
        return;
      }

      if (!this._canRender(panel, requestId) || abortController.signal.aborted) {
        return;
      }

      panel.title = `Upstreams: ${formatUpstreamText(repoName, "Unknown repository")}`;
      this._lastSettled = fetchState;
      panel.webview.html = this._getHtmlContent(workspace, repoSlug, repoName, fetchState);
    } finally {
      if (this._abortController === abortController) {
        this._abortController = null;
      }
      if (this._loadPromise === loadPromise) this._loadPromise = null;
    }
  }

  retry() {
    if (!this._scope || this._loadPromise) return this._loadPromise;
    const [workspace, repoSlug] = JSON.parse(this._scope);
    const repoName = this._panel?.title?.replace(/^Upstreams:\s*/, "") || repoSlug;
    return this._reload(workspace, repoSlug, repoName);
  }

  async _reload(workspace, repoSlug, repoName) {
    const retryFormats = getRetryFormats(this._lastSettled);
    if (retryFormats.length === 0) return;
    this._abortInFlightRequest();
    const requestId = ++this._requestId;
    const abortController = new AbortController();
    this._abortController = abortController;
    const panel = this._panel;
    if (!panel) return;
    panel.webview.html = this._lastSettled
      ? this._getHtmlContent(workspace, repoSlug, repoName, this._lastSettled, { refreshing: true })
      : this._getLoadingHtml(workspace, repoSlug, repoName);
    const promise = this._fetchGroupedUpstreams(workspace, repoSlug, abortController.signal, {
      bypassCache: true,
      formats: retryFormats,
    });
    this._loadPromise = promise;
    try {
      const result = await promise;
      if (!result || !this._canRender(panel, requestId) || abortController.signal.aborted) return;
      const settled = mergeRetryState(this._lastSettled, result, retryFormats);
      this._lastSettled = settled;
      panel.webview.html = this._getHtmlContent(
        workspace,
        repoSlug,
        repoName,
        settled,
        settled.retainedFormats.length > 0 || result.complete !== true
          ? { refreshFailed: true }
          : {}
      );
    } catch {
      if (this._canRender(panel, requestId) && !abortController.signal.aborted) {
        const result = this._lastSettled || failedFetchState();
        panel.webview.html = this._getHtmlContent(
          workspace, repoSlug, repoName, result, { refreshFailed: true }
        );
      }
    } finally {
      if (this._abortController === abortController) this._abortController = null;
      if (this._loadPromise === promise) this._loadPromise = null;
    }
  }

  _getOrCreatePanel(repoName) {
    if (this._panel) {
      this._panel.reveal(vscode.ViewColumn.One);
      return this._panel;
    }

    const panel = vscode.window.createWebviewPanel(
      "cloudsmithUpstreams",
      `Upstreams: ${formatUpstreamText(repoName, "Unknown repository")}`,
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        localResourceRoots: [],
      }
    );

    panel.onDidDispose(() => {
      if (this._panel === panel) {
        this._panel = null;
        this._abortInFlightRequest();
      }
    });
    this._messageDisposable?.dispose?.();
    this._messageDisposable = panel.webview.onDidReceiveMessage?.((message) => {
      let validRetry = false;
      try {
        const keys = message && typeof message === "object" && !Array.isArray(message)
          ? Reflect.ownKeys(message)
          : [];
        validRetry = keys.length === 1 && keys[0] === "command" && message.command === "retry";
      } catch {
        validRetry = false;
      }
      if (!validRetry) return;
      void this.retry();
    }) || null;

    this._panel = panel;
    return panel;
  }

  async _fetchGroupedUpstreams(workspace, repoSlug, signal, options = {}) {
    const requestedFormats = Array.isArray(options.formats)
      ? options.formats
      : SUPPORTED_UPSTREAM_FORMATS;
    const upstreamData = await this._loadUpstreams(workspace, repoSlug, {
      signal,
      bypassCache: options.bypassCache === true,
      formats: options.formats,
    });
    if (upstreamData === null || signal.aborted) {
      return null;
    }
    const aggregate = snapshotAggregateContract(upstreamData);
    if (!aggregate || !isValidAggregate(aggregate, requestedFormats)) return failedFetchState();

    const grouped = new Map();

    for (const candidate of aggregate.upstreams) {
      const upstream = sanitizeSafeInventoryUpstream(candidate);
      if (!upstream) return failedFetchState();
      const format = typeof upstream._format === "string"
        ? upstream._format
        : (typeof upstream.format === "string" ? upstream.format : "");

      if (!format) {
        continue;
      }

      if (!grouped.has(format)) {
        grouped.set(format, []);
      }

      grouped.get(format).push(upstream);
    }

    for (const upstreams of grouped.values()) {
      upstreams.sort((left, right) => {
        const leftName = typeof left.name === "string" ? left.name : "";
        const rightName = typeof right.name === "string" ? right.name : "";
        return leftName.localeCompare(rightName, undefined, { sensitivity: "base" });
      });
    }

    const failedFormats = aggregate.failedFormats;
    const uninspectedFormats = aggregate.uninspectedFormats;
    const unsupportedFormats = aggregate.unsupportedFormats;
    const failures = Object.freeze(aggregate.failures.map(failure => Object.freeze({
      format: failure.format,
      apiFormat: failure.apiFormat,
      state: failure.state,
      category: failure.category,
      message: failure.message,
      httpStatus: failure.httpStatus,
      retryable: failure.retryable,
      retryAfterMs: failure.retryAfterMs,
      requestId: failure.requestId,
      serverRequestId: failure.serverRequestId,
    })));
    for (const [format, upstreams] of grouped) {
      grouped.set(format, Object.freeze(upstreams.slice()));
    }
    return {
      groupedUpstreams: grouped,
      failedFormats,
      uninspectedFormats,
      successfulFormats: typeof aggregate.successfulFormats === "number"
        ? aggregate.successfulFormats
        : 0,
      complete: aggregate.complete === true,
      state: aggregate.state,
      failures,
      unsupportedFormats,
      configuredTotal: Number.isSafeInteger(aggregate.configuredTotal)
        ? aggregate.configuredTotal
        : null,
      retainedFormats: [],
    };
  }
  _abortInFlightRequest() {
    if (this._abortController) {
      this._abortController.abort();
      this._abortController = null;
    }
  }

  _canRender(panel, requestId) {
    return this._panel === panel && this._requestId === requestId;
  }

  _getLoadingHtml(workspace, repoSlug, repoName) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; base-uri 'none'; form-action 'none';">
  <style>
    body {
      margin: 0;
      padding: 16px 24px;
      font-family: var(--vscode-font-family);
      color: var(--vscode-foreground);
      background: var(--vscode-editor-background);
    }
    h2 {
      margin: 0 0 4px 0;
      font-size: 1.35em;
      font-weight: 600;
      line-height: 1.3;
    }
    p {
      margin: 0;
      line-height: 1.4;
    }
    .subtle {
      margin-bottom: 10px;
      color: var(--vscode-descriptionForeground);
      font-size: 0.95em;
    }
    .loading-copy {
      color: var(--vscode-foreground);
    }
  </style>
</head>
<body>
  <h2>${this._escape(repoName)}</h2>
  <p class="subtle">${this._escape(workspace)}/${this._escape(repoSlug)}</p>
  <p class="loading-copy">Loading upstreams...</p>
</body>
</html>`;
  }

  _getHtmlContent(workspace, repoSlug, repoName, fetchState, options = {}) {
    const {
      groupedUpstreams,
      failedFormats = [],
      uninspectedFormats = [],
      successfulFormats,
      failures = [],
    } = fetchState;
    const formatSections = [];
    const hasLoadedUpstreams = groupedUpstreams.size > 0;
    const unavailableFormats = [...new Set([...failedFormats, ...uninspectedFormats])];
    const hasFailures = unavailableFormats.length > 0 || fetchState.complete === false;
    let renderedCount = 0;
    let loadedCount = 0;

    for (const format of SUPPORTED_UPSTREAM_FORMATS) {
      const upstreams = groupedUpstreams.get(format);
      if (!upstreams || upstreams.length === 0) {
        continue;
      }

      loadedCount += upstreams.length;
      const remaining = Math.max(0, MAX_RENDERED_UPSTREAMS - renderedCount);
      const displayed = upstreams.slice(0, remaining);
      renderedCount += displayed.length;
      if (displayed.length === 0) continue;
      const cards = displayed.map((upstream) => this._renderUpstreamCard(upstream)).join("\n");
      formatSections.push(`<section class="format-group">
  <div class="format-header">${this._escape(format)}</div>
  <div class="card-list">
    ${cards}
  </div>
</section>`);
    }

    const safeFailureList = failures.slice(0, 20).map(failure => (
      `<li><strong>${this._escape(failure.format)}</strong> — ${this._escape(
        formatUpstreamFailureCategory(failure.category)
      )}</li>`
    )).join("");
    const retryable = getRetryFormats(fetchState).length > 0;
    const partialWarning = hasLoadedUpstreams && hasFailures
      ? `<div class="error-state">
  <span class="error-state-title">Some upstream data could not be loaded.</span>
  ${this._escape(successfulFormats || 0)} formats loaded. The configured total is not available.
  ${safeFailureList ? `<ul>${safeFailureList}</ul>` : this._escape(
    unavailableFormats.length > 0 ? unavailableFormats.join(", ") : "One or more formats were not inspected."
  )}
</div>`
      : "";
    const refreshNotice = options.refreshing
      ? `<p class="subtle">Refreshing upstreams… Existing results remain visible.</p>`
      : options.refreshFailed
        ? `<p class="subtle">Refresh failed; showing the previous verified results.${
          Array.isArray(fetchState.retainedFormats) && fetchState.retainedFormats.length > 0
            ? ` Previously verified: ${this._escape(fetchState.retainedFormats.join(", "))}.`
            : ""
        }</p>`
        : "";
    const retryButton = retryable
      ? `<button id="retry" type="button">${options.refreshing ? "Retrying…" : "Retry"}</button>`
      : "";
    const displayLimitNotice = loadedCount > renderedCount
      ? `<p class="subtle">Showing ${renderedCount} of ${loadedCount} loaded upstreams.</p>`
      : "";
    const contentHtml = hasLoadedUpstreams
      ? `${refreshNotice}${partialWarning}${displayLimitNotice}${formatSections.join("\n")}${retryButton}`
      : `${refreshNotice}${this._getEmptyOrErrorState(hasFailures, successfulFormats, failures)}${retryButton}`;
    const nonce = crypto.randomBytes(16).toString("base64");
    const script = retryButton ? `<script nonce="${nonce}">
  const vscode = acquireVsCodeApi();
  const retry = document.getElementById("retry");
  retry?.addEventListener("click", () => {
    retry.disabled = true;
    vscode.postMessage({ command: "retry" });
  });
</script>` : "";

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; img-src 'none'; font-src 'none'; base-uri 'none'; form-action 'none';">
  <style>
    body {
      margin: 0;
      padding: 16px 24px;
      font-family: var(--vscode-font-family);
      color: var(--vscode-foreground);
      background: var(--vscode-editor-background);
      line-height: 1.45;
    }
    h1 {
      margin: 0 0 4px 0;
      font-size: 1.35em;
      font-weight: 600;
      line-height: 1.3;
    }
    .repo-meta {
      margin: 0 0 16px 0;
      color: var(--vscode-descriptionForeground);
      font-size: 0.95em;
      line-height: 1.35;
    }
    .error-state {
      margin-top: 8px;
      padding: 12px 14px;
      border: 1px solid var(--vscode-inputValidation-errorBorder);
      border-radius: 6px;
      background: var(--vscode-inputValidation-errorBackground);
      color: var(--vscode-foreground);
      line-height: 1.4;
    }
    .error-state-title {
      display: block;
      margin-bottom: 3px;
      font-weight: 600;
      color: var(--vscode-errorForeground);
    }
    .format-group + .format-group {
      margin-top: 20px;
    }
    .format-header {
      margin: 0 0 8px 0;
      padding-bottom: 6px;
      border-bottom: 1px solid var(--vscode-panel-border);
      font-size: 1em;
      font-weight: 600;
      color: var(--vscode-foreground);
      line-height: 1.3;
    }
    .card-list {
      display: grid;
      gap: 8px;
    }
    .upstream-card {
      padding: 12px 14px;
      border: 1px solid var(--vscode-panel-border);
      border-radius: 6px;
      background: var(--vscode-editor-background);
    }
    .card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 8px;
    }
    .card-title {
      font-size: 1em;
      font-weight: 600;
      color: var(--vscode-foreground);
      line-height: 1.35;
      overflow-wrap: anywhere;
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      padding: 1px 8px;
      border: 1px solid var(--vscode-panel-border);
      border-radius: 999px;
      background: var(--vscode-editor-inactiveSelectionBackground);
      font-size: 0.85em;
      line-height: 1.3;
      white-space: nowrap;
    }
    .status-badges {
      display: inline-flex;
      align-items: center;
      justify-content: flex-end;
      flex-wrap: wrap;
      gap: 6px;
    }
    .status-badge-active {
      color: var(--vscode-testing-iconPassed);
    }
    .status-badge-inactive {
      color: var(--vscode-editorWarning-foreground);
    }
    .details-grid {
      display: grid;
      grid-template-columns: minmax(118px, 136px) minmax(0, 1fr);
      gap: 5px 10px;
      align-items: start;
    }
    .detail-label {
      color: var(--vscode-descriptionForeground);
      font-weight: 600;
      font-size: 0.9em;
      line-height: 1.35;
    }
    .detail-value {
      color: var(--vscode-foreground);
      line-height: 1.35;
      overflow-wrap: anywhere;
      word-break: normal;
    }
    .mono {
      font-family: var(--vscode-editor-font-family);
      font-size: 0.95em;
    }
    .status-badge-trusted {
      color: var(--vscode-textLink-foreground);
    }
    .status-badge-untrusted {
      color: var(--vscode-testing-iconPassed);
    }
    .empty-state {
      margin: 8px 0 0 0;
      color: var(--vscode-descriptionForeground);
    }
  </style>
</head>
<body>
  <h1>${this._escape(repoName)}</h1>
  <p class="repo-meta">${this._escape(workspace)}/${this._escape(repoSlug)}</p>
  ${contentHtml}
  ${script}
</body>
</html>`;
  }

  _getEmptyOrErrorState(hasFailures, successfulFormats, failures = []) {
    if (!hasFailures) {
      return `<p class="empty-state">No upstreams configured for this repository.</p>`;
    }

    const detail = successfulFormats > 0
      ? "No configured upstream could be verified; some formats were inspected successfully."
      : "The upstream inventory could not be loaded for this repository.";
    const lines = failures.slice(0, 20).map(failure => (
      `<li><strong>${this._escape(failure.format)}</strong> — ${this._escape(
        formatUpstreamFailureCategory(failure.category)
      )}</li>`
    )).join("");

    return `<div class="error-state">
  <span class="error-state-title">Could not load upstreams.</span>
  ${this._escape(detail)}
  ${lines ? `<ul>${lines}</ul>` : ""}
</div>`;
  }

  _renderUpstreamCard(upstream) {
    const isActive = upstream.is_active !== false;
    const statusLabel = isActive ? "Active" : "Inactive";
    const statusClass = isActive ? "status-badge-active" : "status-badge-inactive";

    const details = [
      this._renderDetail(
        "Origin",
        formatUpstreamOrigin(upstream.origin),
        "mono"
      ),
      this._renderDetail("Mode", typeof upstream.mode === "string" ? upstream.mode : "", ""),
      this._renderDetail("Priority", this._getPriority(upstream), ""),
      this._renderDetail("SSL verification", this._getSslVerification(upstream), ""),
      this._renderDetail("Indexing", this._getIndexingDisplay(upstream), ""),
      this._renderDetail("Distribution", this._getDistribution(upstream), ""),
      this._renderDetail("Created", this._formatCreatedAt(upstream.created_at), ""),
    ].filter(Boolean).join("\n");

    return `<article class="upstream-card">
  <div class="card-header">
    <div class="card-title">${this._escape(formatUpstreamText(upstream.name, "Unnamed"))}</div>
    <div class="status-badges">
      <span class="status-badge ${statusClass}">${this._escape(statusLabel)}</span>
      ${this._renderTrustBadge(upstream)}
    </div>
  </div>
  <div class="details-grid">
    ${details}
  </div>
</article>`;
  }

  _renderDetail(label, value, valueClass) {
    const displayValue = formatUpstreamText(value);
    if (!displayValue) return "";

    const className = valueClass ? `detail-value ${valueClass}` : "detail-value";
    return `<div class="detail-label">${label}</div><div class="${className}">${this._escape(displayValue)}</div>`;
  }

  _renderTrustBadge(upstream) {
    if (upstream.trust_level === "Trusted") {
      return `<span class="status-badge status-badge-trusted">Trusted</span>`;
    }
    if (upstream.trust_level === "Untrusted") {
      return `<span class="status-badge status-badge-untrusted">Untrusted</span>`;
    }
    return "";
  }

  _getSslVerification(upstream) {
    if (typeof upstream.verify_ssl !== "boolean") {
      return "";
    }
    return upstream.verify_ssl ? "Enabled" : "Disabled";
  }

  _getIndexingDisplay(upstream) {
    const indexStatus = formatUpstreamText(upstream.index_status);
    const packageCount = this._formatIndexPackageCount(upstream.index_package_count);

    if (!indexStatus && !packageCount) {
      return "";
    }

    const indicator = this._getIndexingIndicator(indexStatus);
    const statusText = indicator ? `${indicator} ${indexStatus}` : indexStatus;

    if (!statusText) {
      return packageCount;
    }

    if (!packageCount) {
      return statusText;
    }

    return `${statusText} - ${packageCount}`;
  }

  _getIndexingIndicator(indexStatus) {
    const normalized = typeof indexStatus === "string" ? indexStatus.toLowerCase() : "";
    if (normalized.includes("in progress")) {
      return "↻";
    }
    if (normalized.includes("up-to-date")) {
      return "✓";
    }
    return "";
  }

  _formatIndexPackageCount(indexPackageCount) {
    if (typeof indexPackageCount === "number" && Number.isFinite(indexPackageCount)) {
      const label = indexPackageCount === 1 ? "package" : "packages";
      return `${indexPackageCount.toLocaleString()} ${label}`;
    }
    if (typeof indexPackageCount === "string") {
      const displayValue = formatUpstreamText(indexPackageCount);
      if (!displayValue) return "";
      const numericValue = Number(displayValue);
      if (Number.isFinite(numericValue)) {
        const label = numericValue === 1 ? "package" : "packages";
        return `${numericValue.toLocaleString()} ${label}`;
      }
    }
    return "";
  }

  _getPriority(upstream) {
    if (typeof upstream.priority === "number" && Number.isFinite(upstream.priority)) {
      return String(upstream.priority);
    }
    if (typeof upstream.priority === "string") {
      return formatUpstreamText(upstream.priority);
    }
    return "";
  }

  _getDistribution(upstream) {
    if (typeof upstream.distribution === "string" && upstream.distribution) {
      return formatUpstreamText(upstream.distribution);
    }
    if (Array.isArray(upstream.distro_versions) && upstream.distro_versions.length > 0) {
      const versions = upstream.distro_versions
        .slice(0, MAX_DISTRIBUTION_VERSIONS)
        .map(value => formatUpstreamText(value))
        .filter(Boolean);
      if (versions.length === 0) return "";
      return `${versions.join(", ")}${upstream.distro_versions.length > versions.length ? ", …" : ""}`;
    }
    if (typeof upstream.upstream_distribution === "string" && upstream.upstream_distribution) {
      return formatUpstreamText(upstream.upstream_distribution);
    }
    return "";
  }

  _escape(value) {
    return formatUpstreamText(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  _formatCreatedAt(createdAt) {
    const displayValue = formatUpstreamText(createdAt);
    if (!displayValue) {
      return "";
    }

    const parsed = new Date(displayValue);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed.toLocaleDateString();
    }

    return displayValue.slice(0, 10);
  }

  dispose() {
    this._abortInFlightRequest();

    if (this._panel) {
      this._panel.dispose();
      this._panel = null;
    }
    this._messageDisposable?.dispose?.();
    this._messageDisposable = null;
    this._lastSettled = null;
    this._scope = null;
  }


  resetForAccountChange() {
    this.dispose();
  }
}

function failedFetchState() {
  return {
    groupedUpstreams: new Map(),
    failedFormats: INSPECTABLE_UPSTREAM_FORMATS,
    uninspectedFormats: [],
    unsupportedFormats: [],
    failures: INSPECTABLE_UPSTREAM_FORMATS.map(format => ({
      format,
      message: "Upstream availability could not be determined.",
    })),
    successfulFormats: 0,
    configuredTotal: null,
    complete: false,
    state: "failed",
    retainedFormats: [],
  };
}

function getRetryFormats(state) {
  if (!state || typeof state !== "object") return [];
  const retryableFailures = Array.isArray(state.failures)
    ? state.failures.filter(failure => failure?.retryable !== false).map(failure => failure.format)
    : [];
  return [...new Set([
    ...retryableFailures,
    ...(Array.isArray(state.uninspectedFormats) ? state.uninspectedFormats : []),
  ].filter(format => getUpstreamFormatDescriptor(format)?.inspectable))];
}

function mergeRetryState(previous, replacement, retriedFormats) {
  if (!previous) return { ...replacement, retainedFormats: [] };
  const retried = new Set(retriedFormats);
  const replacementUnavailable = new Set([
    ...replacement.failedFormats,
    ...replacement.uninspectedFormats,
  ]);
  const groupedUpstreams = new Map(previous.groupedUpstreams);
  const retainedFormats = [];
  for (const format of retried) {
    if (replacementUnavailable.has(format)) {
      if (groupedUpstreams.has(format)) retainedFormats.push(format);
      else if (replacement.groupedUpstreams.has(format)) {
        groupedUpstreams.set(format, replacement.groupedUpstreams.get(format));
      }
    } else if (replacement.groupedUpstreams.has(format)) {
      groupedUpstreams.set(format, replacement.groupedUpstreams.get(format));
    } else {
      groupedUpstreams.delete(format);
    }
  }
  const mergeFormats = (oldValues, newValues) => [...new Set([
    ...oldValues.filter(format => !retried.has(format)),
    ...newValues,
  ])];
  const failedFormats = mergeFormats(previous.failedFormats, replacement.failedFormats);
  const uninspectedFormats = mergeFormats(
    previous.uninspectedFormats,
    replacement.uninspectedFormats
  );
  const unsupportedFormats = mergeFormats(
    previous.unsupportedFormats,
    replacement.unsupportedFormats
  );
  const failures = [
    ...previous.failures.filter(failure => !retried.has(failure.format)),
    ...replacement.failures,
  ];
  const complete = failedFormats.length === 0 && uninspectedFormats.length === 0;
  const loadedCount = [...groupedUpstreams.values()].reduce((sum, entries) => sum + entries.length, 0);
  const cancelled = replacement.state === "cancelled";
  const successfulFormats = complete
    ? INSPECTABLE_UPSTREAM_FORMATS.length
    : Math.max(previous.successfulFormats, replacement.successfulFormats);
  return {
    groupedUpstreams,
    failedFormats,
    uninspectedFormats,
    unsupportedFormats,
    failures,
    successfulFormats,
    configuredTotal: complete ? loadedCount : null,
    complete,
    state: complete
      ? (loadedCount > 0 ? "complete" : "empty")
      : cancelled
        ? "cancelled"
        : loadedCount > 0 || successfulFormats > 0 ? "partial" : "failed",
    retainedFormats,
  };
}

function snapshotAggregateContract(value) {
  const root = snapshotOwnDataRecord(value);
  if (!root) return null;
  const upstreams = snapshotOwnDataArray(root.upstreams, MAX_VALIDATED_UPSTREAMS);
  const failedFormats = snapshotOwnDataArray(root.failedFormats, SUPPORTED_UPSTREAM_FORMATS.length);
  const uninspectedFormats = snapshotOwnDataArray(
    root.uninspectedFormats, SUPPORTED_UPSTREAM_FORMATS.length
  );
  const unsupportedFormats = snapshotOwnDataArray(
    root.unsupportedFormats, SUPPORTED_UPSTREAM_FORMATS.length
  );
  const rawFailures = snapshotOwnDataArray(root.failures, INSPECTABLE_UPSTREAM_FORMATS.length);
  const rawOutcomes = snapshotOwnDataArray(root.outcomes, SUPPORTED_UPSTREAM_FORMATS.length);
  if (!upstreams || !failedFormats || !uninspectedFormats || !unsupportedFormats
    || !rawFailures || !rawOutcomes) return null;

  const failures = [];
  for (const value of rawFailures) {
    const failure = snapshotOwnDataRecord(value);
    if (!failure) return null;
    failures.push(failure);
  }
  const outcomes = [];
  for (const value of rawOutcomes) {
    const outcome = snapshotOwnDataRecord(value);
    if (!outcome) return null;
    const entries = snapshotOwnDataArray(
      outcome.entries, MAX_VALIDATED_UPSTREAMS_PER_FORMAT
    );
    const outcomeUpstreams = snapshotOwnDataArray(
      outcome.upstreams, MAX_VALIDATED_UPSTREAMS_PER_FORMAT
    );
    if (!entries || !outcomeUpstreams) return null;
    let failure = null;
    if (outcome.failure !== null) {
      failure = snapshotOwnDataRecord(outcome.failure);
      if (!failure) return null;
    }
    outcomes.push(Object.freeze({
      ...outcome,
      entries,
      upstreams: outcomeUpstreams,
      failure,
    }));
  }
  return Object.freeze({
    ...root,
    upstreams,
    failedFormats,
    uninspectedFormats,
    unsupportedFormats,
    failures: Object.freeze(failures),
    outcomes: Object.freeze(outcomes),
  });
}

function snapshotOwnDataRecord(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || isProxy(value)) return null;
  try {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const copy = {};
    for (const key of Reflect.ownKeys(descriptors)) {
      if (typeof key !== "string") return null;
      const descriptor = descriptors[key];
      if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) return null;
      copy[key] = descriptor.value;
    }
    return Object.freeze(copy);
  } catch {
    return null;
  }
}

function snapshotOwnDataArray(value, maximum = MAX_VALIDATED_UPSTREAMS) {
  if (!Array.isArray(value) || isProxy(value)) return null;
  try {
    if (Object.getPrototypeOf(value) !== Array.prototype) return null;
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    const length = lengthDescriptor?.value;
    if (!Number.isSafeInteger(length) || length < 0 || length > maximum) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== length + 1) return null;
    const copy = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) return null;
      copy.push(descriptor.value);
    }
    if (!keys.every(key => key === "length"
      || (typeof key === "string" && /^(0|[1-9]\d*)$/u.test(key)))) return null;
    return Object.freeze(copy);
  } catch {
    return null;
  }
}

function isValidAggregate(value, requestedFormats) {
  if (!value || typeof value !== "object" || !isOwnDataArray(value.upstreams)) return false;
  if (value.upstreams.length > MAX_VALIDATED_UPSTREAMS) return false;
  const requestedDescriptors = getExactRequestedDescriptors(requestedFormats);
  if (!requestedDescriptors) return false;
  if (typeof value.complete !== "boolean") return false;
  const validStates = new Set(["complete", "empty", "partial", "failed", "cancelled", "unsupported"]);
  if (!validStates.has(value.state)) return false;
  const formatLists = [
    value.failedFormats,
    value.uninspectedFormats,
    value.unsupportedFormats,
  ];
  if (formatLists.some(list => !isOwnDataArray(list) || list.some(format => (
    typeof format !== "string"
    || getUpstreamFormatDescriptor(format)?.format !== format
  )))) return false;
  if (value.failedFormats.some(format => !getUpstreamFormatDescriptor(format)?.inspectable)
    || value.uninspectedFormats.some(format => !getUpstreamFormatDescriptor(format)?.inspectable)
    || value.unsupportedFormats.some(format => getUpstreamFormatDescriptor(format)?.inspectable)) {
    return false;
  }
  if (!isOwnDataArray(value.failures) || value.failures.some(failure => (
    !isValidAggregateFailure(failure)
  ))) return false;
  if (!Number.isSafeInteger(value.successfulFormats)
    || value.successfulFormats < 0
    || value.successfulFormats > INSPECTABLE_UPSTREAM_FORMATS.length) return false;
  if (value.configuredTotal !== null && (
    !Number.isSafeInteger(value.configuredTotal)
    || value.configuredTotal < 0
    || value.configuredTotal !== value.upstreams.length
  )) return false;
  if (value.complete === true && (
    value.configuredTotal === null
    || value.failedFormats.length > 0
    || value.uninspectedFormats.length > 0
  )) return false;
  if (value.complete === false && value.configuredTotal !== null) return false;
  if (value.complete !== ["complete", "empty"].includes(value.state)) return false;
  if (value.state === "empty" && value.upstreams.length !== 0) return false;
  if (value.state === "complete" && value.upstreams.length === 0) return false;
  if (value.state === "unsupported" && value.unsupportedFormats.length === 0) return false;
  const hasUsefulResult = value.upstreams.length > 0 || value.successfulFormats > 0;
  if (value.state === "partial" && !hasUsefulResult) return false;
  if (value.state === "failed" && hasUsefulResult) return false;
  const unavailable = new Set([...value.failedFormats, ...value.uninspectedFormats]);
  if (value.failures.some(failure => !unavailable.has(failure.format))) return false;
  if (new Set([
    ...value.failedFormats,
    ...value.uninspectedFormats,
    ...value.unsupportedFormats,
  ]).size !== value.failedFormats.length
    + value.uninspectedFormats.length
    + value.unsupportedFormats.length) return false;
  if (!isValidOutcomeScope(value, requestedDescriptors)) return false;
  const identities = new Set();
  return value.upstreams.every((upstream) => {
    if (!upstream || typeof upstream !== "object"
      || typeof upstream.name !== "string"
      || !upstream.name
      || upstream.name.length > 500) return false;
    const format = upstream._format;
    const identity = `${format}\0${upstream.slug_perm || upstream.name}`;
    if (identities.has(identity)) return false;
    identities.add(identity);
    return isSafeInventoryUpstream(upstream);
  });
}

function getExactRequestedDescriptors(formats) {
  if (!Array.isArray(formats) || formats.length === 0) return null;
  const descriptors = [];
  const seen = new Set();
  for (const format of formats) {
    const descriptor = getUpstreamFormatDescriptor(format);
    if (!descriptor || descriptor.format !== format || seen.has(descriptor.format)) return null;
    seen.add(descriptor.format);
    descriptors.push(descriptor);
  }
  return descriptors;
}

function isValidOutcomeScope(value, requestedDescriptors) {
  if (!isOwnDataArray(value.outcomes)
    || value.outcomes.length !== requestedDescriptors.length) {
    return false;
  }
  const expected = new Map(requestedDescriptors.map(descriptor => [descriptor.format, descriptor]));
  const seen = new Set();
  const failed = [];
  const uninspected = [];
  const unsupported = [];
  let successful = 0;
  let cancelled = false;
  const aggregateEntryKeys = [];

  for (const outcome of value.outcomes) {
    if (!outcome || typeof outcome !== "object" || Array.isArray(outcome)) return false;
    const descriptor = expected.get(outcome.format);
    if (!descriptor || seen.has(outcome.format) || outcome.apiFormat !== descriptor.apiFormat) {
      return false;
    }
    seen.add(outcome.format);
    if (!isOwnDataArray(outcome.entries) || !isOwnDataArray(outcome.upstreams)
      || outcome.entries.length !== outcome.upstreams.length
      || outcome.entries.length > MAX_VALIDATED_UPSTREAMS_PER_FORMAT
      || !Number.isSafeInteger(outcome.pageCount) || outcome.pageCount < 0) return false;
    const safeEntries = outcome.entries.every((entry, index) => (
      isSafeInventoryUpstream(entry)
      && entry.format === descriptor.format
      && entry._format === descriptor.format
      && sameInventoryEntry(entry, outcome.upstreams[index])
    ));
    if (!safeEntries) return false;
    aggregateEntryKeys.push(...outcome.entries.map(inventoryEntryKey));

    if (!descriptor.inspectable) {
      if (outcome.state !== "unsupported" || outcome.authoritative !== true
        || outcome.entries.length !== 0 || outcome.failure !== null) return false;
      unsupported.push(outcome.format);
      continue;
    }
    if (outcome.state === "success") {
      if (outcome.authoritative !== true || outcome.failure !== null) return false;
      successful += 1;
      continue;
    }
    if (!["failed", "incomplete", "uninspected", "cancelled"].includes(outcome.state)
      || outcome.authoritative !== false || !isValidOutcomeFailure(outcome.failure)) return false;
    if (outcome.state === "failed") failed.push(outcome.format);
    else uninspected.push(outcome.format);
    if (outcome.state === "cancelled") cancelled = true;
  }

  if (seen.size !== expected.size
    || !sameSet(failed, value.failedFormats)
    || !sameSet(uninspected, value.uninspectedFormats)
    || !sameSet(unsupported, value.unsupportedFormats)
    || successful !== value.successfulFormats) return false;
  const aggregateKeys = value.upstreams.map(inventoryEntryKey);
  if (!sameMultiset(aggregateEntryKeys, aggregateKeys)) return false;
  const aggregateComplete = requestedDescriptors.some(descriptor => descriptor.inspectable)
    && requestedDescriptors.filter(descriptor => descriptor.inspectable)
      .every(descriptor => !failed.includes(descriptor.format)
        && !uninspected.includes(descriptor.format));
  if (value.complete !== aggregateComplete) return false;
  if (cancelled !== (value.state === "cancelled")) return false;

  const failureByFormat = new Map();
  for (const failure of value.failures) {
    if (failureByFormat.has(failure.format)) return false;
    failureByFormat.set(failure.format, failure);
  }
  const unavailable = [...failed, ...uninspected];
  if (!sameSet([...failureByFormat.keys()], unavailable)) return false;
  return value.outcomes.every((outcome) => {
    if (!unavailable.includes(outcome.format)) return true;
    const failure = failureByFormat.get(outcome.format);
    return failure.apiFormat === outcome.apiFormat
      && failure.state === outcome.state
      && failure.category === outcome.failure.category
      && failure.message === outcome.failure.message
      && failure.retryable === outcome.failure.retryable
      && failure.httpStatus === outcome.failure.httpStatus
      && failure.retryAfterMs === outcome.failure.retryAfterMs
      && failure.requestId === outcome.failure.requestId
      && failure.serverRequestId === outcome.failure.serverRequestId;
  });
}

function isValidOutcomeFailure(failure) {
  return hasExactDataKeys(failure, OUTCOME_FAILURE_KEYS)
    && typeof failure.category === "string"
    && FAILURE_CATEGORIES.has(failure.category)
    && failure.message === formatUpstreamFailureCategory(failure.category)
    && typeof failure.retryable === "boolean"
    && isValidFailureMetadata(failure);
}

function isValidAggregateFailure(failure) {
  if (!hasExactDataKeys(failure, FAILURE_KEYS)) return false;
  const descriptor = getUpstreamFormatDescriptor(failure.format);
  return descriptor?.inspectable === true
    && descriptor.format === failure.format
    && failure.apiFormat === descriptor.apiFormat
    && ["failed", "incomplete", "uninspected", "cancelled"].includes(failure.state)
    && FAILURE_CATEGORIES.has(failure.category)
    && failure.message === formatUpstreamFailureCategory(failure.category)
    && typeof failure.retryable === "boolean"
    && isValidFailureMetadata(failure);
}

function isValidFailureMetadata(failure) {
  return (failure.httpStatus === null
      || (Number.isSafeInteger(failure.httpStatus)
        && failure.httpStatus >= 100 && failure.httpStatus <= 599))
    && (failure.retryAfterMs === null
      || (Number.isSafeInteger(failure.retryAfterMs)
        && failure.retryAfterMs >= 0 && failure.retryAfterMs <= 86_400_000))
    && isValidFailureId(failure.requestId)
    && isValidFailureId(failure.serverRequestId);
}

function isValidFailureId(value) {
  return value === null || (typeof value === "string" && value.length <= 128
    && /^[A-Za-z0-9][A-Za-z0-9._:-]*$/u.test(value));
}

function hasExactDataKeys(value, expectedKeys) {
  if (!value || typeof value !== "object" || Array.isArray(value) || isProxy(value)) return false;
  try {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return false;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== expectedKeys.size
      || keys.some(key => typeof key !== "string" || !expectedKeys.has(key))) return false;
    return keys.every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor && Object.prototype.hasOwnProperty.call(descriptor, "value")
        && descriptor.enumerable === true;
    });
  } catch {
    return false;
  }
}

function isOwnDataArray(value) {
  return snapshotOwnDataArray(value) !== null;
}

function inventoryEntryKey(entry) {
  return `${entry.format}\0${entry.slug_perm || entry.name}\0${JSON.stringify(entry)}`;
}

function sameInventoryEntry(left, right) {
  return isSafeInventoryUpstream(right) && inventoryEntryKey(left) === inventoryEntryKey(right);
}

function sameSet(left, right) {
  return left.length === right.length && new Set(left).size === left.length
    && left.every(value => right.includes(value));
}

function sameMultiset(left, right) {
  if (left.length !== right.length) return false;
  const remaining = new Map();
  for (const value of left) remaining.set(value, (remaining.get(value) || 0) + 1);
  for (const value of right) {
    const count = remaining.get(value) || 0;
    if (count === 0) return false;
    if (count === 1) remaining.delete(value);
    else remaining.set(value, count - 1);
  }
  return remaining.size === 0;
}

module.exports = { UpstreamDetailProvider, SUPPORTED_FORMATS };

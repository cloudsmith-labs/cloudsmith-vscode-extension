// Copyright 2026 Cloudsmith Ltd. All rights reserved.

// Quarantine Explanation WebView panel provider.
// Shows a focused, current explanation of why a package was quarantined.

const crypto = require("crypto");
const vscode = require("vscode");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { apiEndpoint } = require("../util/apiEndpoint");
const { buildPackageUrl } = require("../util/webAppUrls");
const { parseWebviewMessage } = require("../util/webviewMessage");
const {
  captureAccount,
  isAccountCurrent,
  resolveConnectionManager,
} = require("../util/accountOperation");
const {
  createQuarantineLocator,
  fetchDecisionLogDetail,
  fetchPackageDecisionLogs,
  normalizePolicyStatusReason,
  parsePolicyStatusReason,
  selectCausalDecision,
} = require("../util/policyDecisionLogs");

const MAX_DISPLAY_LENGTH = 4096;
const STATUS_QUARANTINED = "Quarantined";
const CURRENT_PACKAGE_MISSING = Object.freeze({ missing: true });
const CONTROL_PATTERN = /[\u0000-\u001f\u007f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g;

class QuarantineExplainProvider {
  constructor(context, options = {}) {
    this.context = context;
    this._panel = null;
    this._operation = null;
    this._operationVersion = 0;
    this._connectionManager = resolveConnectionManager(context, options.connectionManager);
    this._cloudsmithAPI = options.cloudsmithAPI || null;
    this._createWebviewPanel = options.createWebviewPanel || ((...args) => (
      vscode.window.createWebviewPanel(...args)
    ));
    this._executeCommand = options.executeCommand || ((...args) => vscode.commands.executeCommand(...args));
    this._writeClipboard = options.writeClipboard || (value => vscode.env.clipboard.writeText(value));
    this._openExternal = options.openExternal || (value => vscode.env.openExternal(vscode.Uri.parse(value)));
    this._notifications = options.notifications || {
      information: message => vscode.window.showInformationMessage(message),
      warning: message => vscode.window.showWarningMessage(message),
    };
    this._createNonce = options.createNonce || (() => crypto.randomBytes(16).toString("hex"));
  }

  async show(item) {
    if (!item) {
      this._notifications.warning("No package selected.");
      return;
    }
    let locator;
    try {
      locator = createQuarantineLocator(item);
    } catch {
      locator = null;
    }
    if (!locator) {
      this._notifications.warning("Could not open quarantine details. Select the package again and retry.");
      return;
    }
    const account = captureAccount(this._connectionManager);
    if (!account || !isAccountCurrent(this._connectionManager, account)) return;

    if (this._operation) this._disposeOperation(this._operation, true);
    const caller = this._normalizeCallerPackage(item, locator);
    const panel = this._createWebviewPanel(
      "cloudsmithQuarantineExplain",
      `Quarantine details: ${caller.name || "Package"}${caller.version ? ` ${caller.version}` : ""}`,
      vscode.ViewColumn.One,
      { enableScripts: true, localResourceRoots: [] }
    );
    this._panel = panel;
    const operation = {
      account,
      controller: new AbortController(),
      disposed: false,
      disposeSubscription: null,
      item,
      locator,
      messageSubscription: null,
      nonce: this._getNonce(),
      panel,
      trace: this._initialTrace(caller, locator),
      version: ++this._operationVersion,
    };
    this._operation = operation;
    operation.disposeSubscription = panel.onDidDispose(() => this._disposeOperation(operation, false));
    operation.messageSubscription = panel.webview.onDidReceiveMessage(message => (
      this._handleMessage(operation, message)
    ));

    this._render(operation);
    await this._refreshOperation(operation, this._cloudsmithAPI || new CloudsmithAPI(this.context));
  }

  _normalizeCallerPackage(item, locator) {
    return Object.freeze({
      confirmed: false,
      format: displayString(unwrapOwnValue(ownData(item, "format")), 64),
      name: displayString(unwrapOwnValue(ownData(item, "name")), 512) || "Package",
      status: displayString(
        unwrapOwnValue(ownData(item, "status_str_raw") ?? ownData(item, "status_str")),
        64
      ),
      statusReason: normalizePolicyStatusReason(ownData(item, "status_reason")),
      uploadedAt: dateTime(unwrapOwnValue(ownData(item, "uploaded_at"))),
      version: displayString(unwrapOwnValue(ownData(item, "version")), 512),
      workspace: locator.workspace,
      repository: locator.repository,
      packageSlugPerm: locator.packageSlugPerm,
    });
  }

  _initialTrace(caller, locator) {
    const parsedReason = parsePolicyStatusReason(caller.statusReason);
    return {
      current: caller,
      decision: null,
      error: null,
      locator,
      packageUrl: this._packageUrl(caller, locator),
      parsedReason,
      policyDescription: null,
      refreshed: false,
    };
  }

  async _refreshOperation(operation, api) {
    const current = await this._fetchCurrentPackage(api, operation.locator, operation.controller.signal);
    if (!this._isOperationCurrent(operation)) return;
    if (current === CURRENT_PACKAGE_MISSING) {
      operation.trace = { ...operation.trace, error: "missing", refreshed: true };
      this._render(operation);
      return;
    }
    if (!current) {
      operation.trace = { ...operation.trace, current: null, error: "load", refreshed: true };
      this._render(operation);
      return;
    }

    operation.trace = {
      ...operation.trace,
      current,
      decision: null,
      error: current.status === STATUS_QUARANTINED ? null : "stale",
      packageUrl: this._packageUrl(current, operation.locator),
      parsedReason: parsePolicyStatusReason(current.statusReason),
      policyDescription: null,
      refreshed: true,
    };
    this._render(operation);
    if (current.status !== STATUS_QUARANTINED) return;

    const parsedPolicySlug = operation.trace.parsedReason?.policySlug || null;
    const work = [];
    if (current.uploadedAt && (!usefulStatusReason(current.statusReason) || parsedPolicySlug)) {
      work.push(this._loadDecision(operation, api, parsedPolicySlug));
    } else if (current.statusReason && !parsedPolicySlug) {
      this._diagnostic("decision_policy_identity_unavailable");
    } else {
      this._diagnostic("decision_time_boundary_unavailable");
    }
    if (parsedPolicySlug) work.push(this._loadPolicyDescription(operation, api, parsedPolicySlug));
    await Promise.allSettled(work);
  }

  async _fetchCurrentPackage(api, locator, signal) {
    if (!api || typeof api.get !== "function") return null;
    let endpoint;
    try {
      endpoint = apiEndpoint(["packages", locator.workspace, locator.repository, locator.packageSlugPerm]);
    } catch {
      return null;
    }
    try {
      const result = await api.get(endpoint, {
        responseType: "object",
        validate: isRecord,
        retry: "never",
        signal,
      });
      if (signal.aborted) return null;
      if (!result.ok) return result.status === 404 ? CURRENT_PACKAGE_MISSING : null;
      return normalizeCurrentPackage(result.data, locator);
    } catch {
      return null;
    }
  }

  async _loadDecision(operation, api, policySlug) {
    let collection;
    try {
      collection = await fetchPackageDecisionLogs(
        api,
        operation.locator,
        operation.trace.current.uploadedAt,
        { policySlug, signal: operation.controller.signal }
      );
    } catch {
      this._diagnostic("decision_collection_failed");
      return;
    }
    if (!this._isOperationCurrent(operation)) return;
    const exactItems = collection.items.filter(item => (
      item.packageSlugPerm === operation.locator.packageSlugPerm
      && item.repositorySlug === operation.locator.repository
    ));
    if (exactItems.length !== collection.items.length) {
      this._diagnostic("decision_identity_mismatch");
      return;
    }
    const summary = selectCausalDecision(exactItems, policySlug);
    if (!summary) {
      if (!collection.complete) this._diagnostic("decision_collection_incomplete");
      return;
    }

    let decision = summary;
    const needsDetail = !usefulStatusReason(operation.trace.current.statusReason) || !policySlug;
    if (needsDetail) {
      const detail = await fetchDecisionLogDetail(api, operation.locator, summary, {
        signal: operation.controller.signal,
      });
      if (!this._isOperationCurrent(operation) || !detail) {
        this._diagnostic("decision_detail_unavailable");
        return;
      }
      decision = detail;
    }
    if (!this._isOperationCurrent(operation)) return;
    if (
      policySlug
      && operation.trace.parsedReason?.policySlug
      && decision.policySlugPerm !== operation.trace.parsedReason.policySlug
    ) {
      this._diagnostic("decision_policy_conflict");
      return;
    }
    operation.trace = { ...operation.trace, decision };
    this._render(operation);
    if (!policySlug && decision.policySlugPerm) {
      await this._loadPolicyDescription(operation, api, decision.policySlugPerm);
    }
  }

  async _loadPolicyDescription(operation, api, policySlug) {
    if (!api || typeof api.getV2 !== "function" || !policySlug) return;
    let endpoint;
    try {
      endpoint = apiEndpoint(["workspaces", operation.locator.workspace, "policies", policySlug]);
    } catch {
      return;
    }
    try {
      const result = await api.getV2(endpoint, {
        responseType: "object",
        validate: isRecord,
        retry: "never",
        signal: operation.controller.signal,
      });
      if (!this._isOperationCurrent(operation) || !result.ok) return;
      const returnedSlug = displayString(result.data.slug_perm, 512);
      const description = displayString(result.data.description, 1024);
      if (returnedSlug !== policySlug || !description) {
        if (returnedSlug !== policySlug) this._diagnostic("policy_identity_mismatch");
        return;
      }
      const reason = customerReason(operation.trace);
      if (reason && normalizedComparison(reason) === normalizedComparison(description)) return;
      operation.trace = { ...operation.trace, policyDescription: description };
      this._render(operation);
    } catch {
      this._diagnostic("policy_description_unavailable");
    }
  }

  async _handleMessage(operation, message) {
    if (!this._isOperationCurrent(operation)) return;
    const parsed = parseWebviewMessage(message, QUARANTINE_MESSAGE_CONTRACTS);
    if (!parsed || !this._isOperationCurrent(operation)) return;
    if (parsed.command === "retry") {
      await this.show(operation.item);
      return;
    }
    const trace = operation.trace;
    if (!trace.refreshed || !trace.current?.confirmed || trace.current.status !== STATUS_QUARANTINED) {
      return;
    }
    try {
      if (parsed.command === "findSafeVersion") {
        await this._executeCommand("cloudsmith-vsc.findSafeVersion", operation.item);
      } else if (parsed.command === "showVulnerabilities") {
        await this._executeCommand("cloudsmith-vsc.showVulnerabilities", operation.item);
      } else if (parsed.command === "openInCloudsmith" && trace.packageUrl) {
        await this._openExternal(trace.packageUrl);
      } else if (parsed.command === "copyReport") {
        await this._writeClipboard(this._buildPlainTextReport(trace));
        if (this._isOperationCurrent(operation)) {
          await this._notifications.information("Quarantine report copied.");
        }
      }
    } catch {
      if (this._isOperationCurrent(operation)) {
        await this._notifications.warning(actionFailureMessage(parsed.command));
      }
    }
  }

  _render(operation) {
    if (!this._isOperationCurrent(operation)) return;
    operation.panel.webview.html = this._getHtmlContent(operation.nonce, operation.trace);
  }

  _getHtmlContent(nonce, trace) {
    const current = trace.current;
    const name = current?.name || "Package";
    const version = current?.version;
    const heading = [name, version].filter(Boolean).join(" ");
    const metadata = [current?.format, current ? `${current.workspace}/${current.repository}` : null]
      .filter(Boolean).join(" · ");
    let body;
    if (
      !trace.refreshed
      && (current?.status !== STATUS_QUARANTINED || !customerReason(trace))
    ) {
      body = `<p class="loading" role="status" aria-live="polite">Loading quarantine details...</p>`;
    } else if (trace.error === "missing") {
      body = `<div class="state"><p>This package is no longer available.</p></div>`;
    } else if (trace.error === "load") {
      body = `<div class="state" role="alert"><p>Could not load quarantine details.</p><button type="button" data-command="retry">Retry</button></div>`;
    } else if (trace.error === "stale") {
      body = `<div class="state"><p>This package is no longer quarantined.</p></div>`;
    } else {
      const reason = customerReason(trace);
      const policyName = trace.parsedReason?.policyName || trace.decision?.policyName || null;
      const recorded = trace.decision?.endedAt || null;
      const rows = [
        policyName ? `<div><dt>Policy</dt><dd>${this._esc(policyName)}</dd></div>` : "",
        reason ? `<div><dt>Reason</dt><dd>${this._esc(reason)}</dd></div>` : "",
        `<div><dt>Action</dt><dd>Quarantined</dd></div>`,
        recorded ? `<div><dt>Decision recorded</dt><dd>${this._esc(formatTimestamp(recorded))}</dd></div>` : "",
      ].join("");
      const description = trace.policyDescription
        ? `<section><h3>About this policy</h3><p>${this._esc(trace.policyDescription)}</p></section>`
        : "";
      const actions = trace.refreshed
        ? `<section><h2>Next steps</h2><div class="actions">
            <button type="button" data-command="findSafeVersion">Find safe version</button>
            <button type="button" data-command="showVulnerabilities">Show vulnerabilities</button>
            ${trace.packageUrl ? `<button type="button" data-command="openInCloudsmith">View in Cloudsmith</button>` : ""}
            <button type="button" class="secondary" data-command="copyReport">Copy report</button>
          </div></section>`
        : `<p class="loading" role="status" aria-live="polite">Refreshing current package status...</p>`;
      body = `<span class="badge"><span aria-hidden="true">⛔</span> Quarantined</span>
        <section><h2>Quarantine details</h2><dl>${rows}</dl></section>
        ${description}${actions}`;
    }

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; img-src 'none';">
  <style>
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); background: var(--vscode-editor-background); padding: 16px 24px; line-height: 1.5; }
    h1 { margin: 0 0 2px; font-size: 1.65em; } h2 { margin: 22px 0 8px; } h3 { margin: 16px 0 6px; }
    .meta { color: var(--vscode-descriptionForeground); margin-bottom: 14px; }
    .badge { display: inline-block; padding: 3px 10px; border-radius: 3px; font-weight: 600; color: var(--vscode-errorForeground); background: var(--vscode-inputValidation-errorBackground, rgba(255,0,0,.1)); }
    dl { border: 1px solid var(--vscode-panel-border); border-radius: 4px; margin: 0; }
    dl div { display: grid; grid-template-columns: minmax(8rem, 25%) 1fr; gap: 12px; padding: 9px 12px; border-bottom: 1px solid var(--vscode-panel-border); }
    dl div:last-child { border-bottom: 0; } dt { font-weight: 600; } dd { margin: 0; overflow-wrap: anywhere; }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; }
    button { border: 0; border-radius: 2px; padding: 6px 14px; cursor: pointer; color: var(--vscode-button-foreground); background: var(--vscode-button-background); }
    button:hover { background: var(--vscode-button-hoverBackground); } button:focus-visible { outline: 2px solid var(--vscode-focusBorder); outline-offset: 2px; }
    button.secondary { color: var(--vscode-button-secondaryForeground); background: var(--vscode-button-secondaryBackground); }
    .loading, .meta { color: var(--vscode-descriptionForeground); } .state { margin-top: 20px; }
  </style>
</head>
<body>
  <h1>${this._esc(heading)}</h1>
  ${metadata ? `<div class="meta">${this._esc(metadata)}</div>` : ""}
  ${body}
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    document.querySelectorAll("[data-command]").forEach((button) => {
      button.addEventListener("click", () => vscode.postMessage({ command: button.dataset.command }));
    });
  </script>
</body>
</html>`;
  }

  _buildPlainTextReport(trace) {
    const current = trace.current;
    const reason = customerReason(trace);
    const policyName = trace.parsedReason?.policyName || trace.decision?.policyName || null;
    const lines = [
      "Quarantine report",
      `Package: ${reportValue([current.name, current.version].filter(Boolean).join(" "))}`,
    ];
    if (current.format) lines.push(`Format: ${reportValue(current.format)}`);
    lines.push(`Location: ${reportValue(`${current.workspace}/${current.repository}`)}`);
    lines.push("Status: Quarantined");
    if (policyName) lines.push(`Policy: ${reportValue(policyName)}`);
    if (reason) lines.push(`Reason: ${reportValue(reason)}`);
    lines.push("Action: Quarantined");
    if (trace.decision?.endedAt) {
      lines.push(`Decision recorded: ${reportValue(formatTimestamp(trace.decision.endedAt))}`);
    }
    if (trace.policyDescription) {
      lines.push(`Policy description: ${reportValue(trace.policyDescription)}`);
    }
    return lines.join("\n");
  }

  _packageUrl(current, locator) {
    try {
      return buildPackageUrl(
        locator.workspace,
        locator.repository,
        current.format,
        current.name,
        current.version,
        locator.packageSlugPerm
      );
    } catch {
      return null;
    }
  }

  _esc(value) {
    return typeof value === "string" ? value
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;") : "";
  }

  _diagnostic(category) {
    console.warn(`[Quarantine] ${category}`);
  }

  _getNonce() { return this._createNonce(); }

  _isOperationCurrent(operation) {
    return Boolean(
      operation
      && this._operation === operation
      && this._panel === operation.panel
      && operation.version === this._operationVersion
      && !operation.controller.signal.aborted
      && isAccountCurrent(this._connectionManager, operation.account)
    );
  }

  resetForAccountChange() {
    if (this._operation) {
      this._disposeOperation(this._operation, true);
      return;
    }
    const panel = this._panel;
    this._panel = null;
    if (panel) panel.dispose();
  }

  dispose() { this.resetForAccountChange(); }

  _disposeOperation(operation, disposePanel) {
    if (!operation || operation.disposed) return;
    operation.disposed = true;
    operation.controller.abort();
    operation.messageSubscription?.dispose();
    operation.disposeSubscription?.dispose();
    operation.messageSubscription = null;
    operation.disposeSubscription = null;
    if (this._operation === operation) this._operation = null;
    if (this._panel === operation.panel) this._panel = null;
    if (disposePanel) operation.panel.dispose();
  }
}

function normalizeCurrentPackage(value, locator) {
  if (!isRecord(value)) return null;
  const workspace = displayString(ownData(value, "namespace"), 512);
  const repository = displayString(ownData(value, "repository"), 512);
  const packageSlugPerm = displayString(ownData(value, "slug_perm"), 512);
  const packageSlugPermRaw = ownData(value, "slug_perm_raw") == null
    ? null
    : displayString(ownData(value, "slug_perm_raw"), 512);
  const status = displayString(unwrapOwnValue(
    ownData(value, "status_str") ?? ownData(value, "status")
  ), 64);
  const uploadedAt = dateTime(ownData(value, "uploaded_at"));
  const format = displayString(ownData(value, "format"), 64);
  const name = displayString(ownData(value, "name"), 512);
  const version = displayString(ownData(value, "version"), 512);
  if (
    workspace !== locator.workspace
    || repository !== locator.repository
    || packageSlugPerm !== locator.packageSlugPerm
    || (packageSlugPermRaw !== null && packageSlugPermRaw !== packageSlugPerm)
    || !status
    || !format
    || !name
    || !version
  ) return null;
  return Object.freeze({
    confirmed: true,
    format,
    name,
    packageSlugPerm,
    repository,
    status,
    statusReason: normalizePolicyStatusReason(ownData(value, "status_reason")),
    uploadedAt,
    version,
    workspace,
  });
}

function displayString(value, maxLength = MAX_DISPLAY_LENGTH) {
  if (typeof value !== "string") return null;
  const normalized = value.replace(CONTROL_PATTERN, " ").trim();
  if (!normalized) return null;
  return normalized.length <= maxLength ? normalized : `${normalized.slice(0, maxLength - 1)}…`;
}

function dateTime(value) {
  return typeof value === "string"
    && value.length <= 128
    && /^\d{4}-\d{2}-\d{2}T/.test(value)
    && Number.isFinite(Date.parse(value))
    ? value
    : null;
}

function formatTimestamp(value) {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toLocaleString() : "";
}

function normalizedComparison(value) {
  return displayString(value)?.toLocaleLowerCase() || "";
}

function customerReason(trace) {
  if (usefulStatusReason(trace.current?.statusReason)) {
    return trace.parsedReason?.description || trace.parsedReason?.raw || trace.current.statusReason;
  }
  return trace.decision?.reason || null;
}

function usefulStatusReason(value) {
  const normalized = displayString(value);
  return Boolean(normalized && !/^quarantined[.!]?$/i.test(normalized));
}

function reportValue(value) {
  const normalized = displayString(value, 1024) || "";
  return normalized.replace(/\s+/g, " ").replace(/^[=+\-@]/, "'$&");
}

function actionFailureMessage(command) {
  const messages = {
    copyReport: "Could not copy the quarantine report. Retry.",
    findSafeVersion: "Could not find a safe version. Retry.",
    openInCloudsmith: "Could not open this package in Cloudsmith. Retry.",
    showVulnerabilities: "Could not show vulnerabilities. Retry.",
  };
  return messages[command] || "Could not complete this action. Retry.";
}

function isRecord(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function ownData(value, key) {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && Object.prototype.hasOwnProperty.call(descriptor, "value")
      ? descriptor.value
      : undefined;
  } catch {
    return undefined;
  }
}

function unwrapOwnValue(value) {
  let current = value;
  for (let depth = 0; depth < 4; depth += 1) {
    if (!isRecord(current)) return current;
    const descriptor = Object.getOwnPropertyDescriptor(current, "value");
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")) return null;
    current = descriptor.value;
  }
  return isRecord(current) ? null : current;
}

const QUARANTINE_MESSAGE_CONTRACTS = Object.freeze({
  copyReport: Object.freeze([]),
  findSafeVersion: Object.freeze([]),
  openInCloudsmith: Object.freeze([]),
  retry: Object.freeze([]),
  showVulnerabilities: Object.freeze([]),
});

module.exports = { QuarantineExplainProvider };

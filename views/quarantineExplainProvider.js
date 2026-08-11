// Quarantine Explanation WebView panel provider.
// Shows a focused explanation of why a package was quarantined,
// including policy trace, decision logs, and remediation actions.

const crypto = require("crypto");
const vscode = require("vscode");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { apiEndpoint } = require("../util/apiEndpoint");
const { formatApiError } = require("../util/errorFormatter");
const { buildPackageUrl } = require("../util/webAppUrls");
const { parseWebviewMessage } = require("../util/webviewMessage");
const {
  captureAccount,
  isAccountCurrent,
  resolveConnectionManager,
} = require("../util/accountOperation");
const {
  fetchPackageDecisionLogs,
  normalizePolicyStatusReason,
  parsePolicyStatusReason,
} = require("../util/policyDecisionLogs");

class QuarantineExplainProvider {
  constructor(context, options = {}) {
    this.context = context;
    this._panel = null;
    this._operation = null;
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

  /**
   * Show the quarantine explanation panel for a package.
   * @param {Object} item - PackageNode, SearchResultNode, or DependencyHealthNode
   */
  async show(item) {
    if (!item) {
      this._notifications.warning("No package selected.");
      return;
    }

    const workspace = item.namespace || item.cloudsmithWorkspace;
    const repo = item.repository || item.cloudsmithRepo;
    const name = item.name;
    const format = item.format;

    // Unwrap slug_perm
    let slugPerm = item.slug_perm_raw;
    if (!slugPerm) {
      slugPerm = item.slug_perm;
      if (slugPerm && typeof slugPerm === "object" && slugPerm.value) {
        slugPerm = typeof slugPerm.value === "object" ? slugPerm.value.value : slugPerm.value;
      }
    }

    // Unwrap version
    let version = item.version;
    if (version && typeof version === "object" && version.value) {
      version = typeof version.value === "object" ? version.value.value : version.value;
    }

    const statusReason = normalizePolicyStatusReason(item.status_reason);
    const packageUrl = buildPackageUrl(workspace, repo, format, name, version, slugPerm);

    if (!workspace || !slugPerm) {
      this._notifications.warning("Could not determine package details for quarantine explanation.");
      return;
    }

    const account = captureAccount(this._connectionManager);
    if (!account || !isAccountCurrent(this._connectionManager, account)) return;

    // Create or reveal the WebView panel
    if (this._operation) this._disposeOperation(this._operation, true);

    const panel = this._createWebviewPanel(
      "cloudsmithQuarantineExplain",
      `Quarantine: ${name || ""} ${version || ""}`,
      vscode.ViewColumn.One,
      { enableScripts: true, localResourceRoots: [] }
    );
    this._panel = panel;
    const requestController = new AbortController();
    const operation = {
      account,
      controller: requestController,
      panel,
      messageSubscription: null,
      disposeSubscription: null,
      disposed: false,
    };
    this._operation = operation;
    const nonce = this._getNonce();

    operation.disposeSubscription = panel.onDidDispose(() => {
      this._disposeOperation(operation, false);
    });

    // Show loading state
    panel.webview.html = this._getLoadingHtml(name, version);

    // Fetch policy decision trace
    const cloudsmithAPI = this._cloudsmithAPI || new CloudsmithAPI(this.context);
    const policyTrace = await this._fetchPolicyDecisionTrace(
      cloudsmithAPI,
      workspace,
      slugPerm,
      statusReason,
      requestController.signal
    );

    if (!this._isOperationCurrent(operation)) {
      return;
    }

    // Render the full panel
    panel.webview.html = this._getHtmlContent(
      nonce, name, version, format, workspace, repo, slugPerm,
      statusReason, packageUrl, policyTrace
    );

    // Handle messages from the WebView
    operation.messageSubscription = panel.webview.onDidReceiveMessage(message => (
      this._handleMessage(
        operation,
        message,
        item,
        name,
        version,
        statusReason,
        packageUrl,
        policyTrace
      ).catch(() => {
        if (this._isOperationCurrent(operation)) {
          return this._notifications.warning("Could not complete the quarantine panel action.");
        }
        return undefined;
      })
    ));
  }

  async _handleMessage(operation, message, item, name, version, statusReason, packageUrl, policyTrace) {
    if (!this._isOperationCurrent(operation)) return;
    const parsed = parseWebviewMessage(message, QUARANTINE_MESSAGE_CONTRACTS);
    if (!parsed || !this._isOperationCurrent(operation)) return;

    if (parsed.command === "findSafeVersion") {
      await this._executeCommand("cloudsmith-vsc.findSafeVersion", item);
    } else if (parsed.command === "showVulnerabilities") {
      await this._executeCommand("cloudsmith-vsc.showVulnerabilities", item);
    } else if (parsed.command === "openInCloudsmith" && packageUrl) {
      await this._openExternal(packageUrl);
    } else if (parsed.command === "copyReport") {
      const report = this._buildPlainTextReport(name, version, statusReason, policyTrace);
      await this._writeClipboard(report);
      if (this._isOperationCurrent(operation)) {
        await this._notifications.information("Quarantine report copied.");
      }
    }
  }

  /**
   * Fetch policy decision logs for a package from the v2 API.
   * Parses the status_reason field and fetches decision logs when available.
   *
   * @returns {Object} { parsedReason, decisionLogs: [...], policyDetail: Object|null }
   */
  async _fetchPolicyDecisionTrace(cloudsmithAPI, workspace, slugPerm, statusReason, signal) {
    const trace = {
      parsedReason: null,
      decisionLogs: [],
      decisionLogsComplete: false,
      decisionLogsPartial: false,
      decisionLogsIncomplete: true,
      decisionLogsFailureCount: 0,
      policyDetail: null,
    };

    // Parse the status_reason field if present
    trace.parsedReason = parsePolicyStatusReason(statusReason);

    // Fetch decision logs from v2 API
    try {
      const logsResult = await fetchPackageDecisionLogs(cloudsmithAPI, workspace, slugPerm, {
        signal,
      });
      if (signal && signal.aborted) return trace;
      trace.decisionLogs = [...logsResult.items];
      trace.decisionLogsComplete = logsResult.complete;
      trace.decisionLogsPartial = logsResult.partial;
      trace.decisionLogsIncomplete = logsResult.incomplete;
      trace.decisionLogsFailureCount = logsResult.failureCount;
    } catch {
      trace.decisionLogsComplete = false;
      trace.decisionLogsPartial = false;
      trace.decisionLogsIncomplete = true;
      trace.decisionLogsFailureCount = 1;
    }

    // If we have a policy slug, fetch the policy detail for the description
    if (trace.parsedReason && trace.parsedReason.policySlug && !(signal && signal.aborted)) {
      try {
        const policyEndpoint = apiEndpoint([
          "workspaces",
          workspace,
          "policies",
          trace.parsedReason.policySlug,
        ]);
        const policyResult = await cloudsmithAPI.getV2(policyEndpoint, {
          responseType: "object",
          validate: isRecord,
          retry: "never",
          signal,
        });
        if (signal && signal.aborted) return trace;
        if (policyResult.ok) {
          trace.policyDetail = policyResult.data;
        } else if (policyResult.error.kind !== "cancelled") {
          console.warn(`[Quarantine] Policy detail unavailable: ${formatApiError(policyResult.error)}`);
        }
      } catch (error) { // eslint-disable-line no-unused-vars
        // Policy detail may not be accessible
      }
    }

    return trace;
  }

  _getLoadingHtml(name, version) {
    return `<!DOCTYPE html>
<html>
<head><style>body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 20px; }</style></head>
<body><h2>Loading quarantine details for ${this._esc(name || "")} ${this._esc(version || "")}...</h2></body>
</html>`;
  }

  _getHtmlContent(nonce, name, version, format, workspace, repo, slugPerm, statusReason, packageUrl, policyTrace) {
    // Determine if this is vulnerability-related by checking for CVE references in decision logs
    const hasCVEs = policyTrace.decisionLogs.some(entry =>
      (entry.reason && /CVE-/i.test(entry.reason)) ||
      (entry.action && /vulnerabilit/i.test(entry.action))
    );

    // Build policy info section
    let policyInfoHtml = "";
    if (statusReason) {
      policyInfoHtml += `<div class="status-reason-box">
        <h3>Quarantine reason</h3>
        <p class="status-reason">${this._esc(statusReason)}</p>
      </div>`;
    }

    if (policyTrace.parsedReason && policyTrace.parsedReason.policyName) {
      policyInfoHtml += `<div class="policy-card">
        <strong>Policy:</strong> ${this._esc(policyTrace.parsedReason.policyName)}${policyTrace.parsedReason.policySlug ? ` <span class="slug">(${this._esc(policyTrace.parsedReason.policySlug)})</span>` : ""}<br>
        <strong>Action:</strong> Quarantined<br>
        ${policyTrace.parsedReason.description ? `<strong>Detail:</strong> ${this._esc(policyTrace.parsedReason.description)}` : ""}
      </div>`;
    }

    // Show the full policy description from the EPM policy object if available
    if (policyTrace.policyDetail && policyTrace.policyDetail.description) {
      policyInfoHtml += `<div class="policy-description">
        <h4>Policy description</h4>
        <p>${this._esc(policyTrace.policyDetail.description)}</p>
      </div>`;
    }

    // Decision logs table
    let decisionLogsHtml = "";
    if (policyTrace.decisionLogs.length > 0) {
      decisionLogsHtml = `<div class="decision-logs">
        <h3>Decision log entries</h3>
        <table class="decision-log-table">
          <thead><tr><th>Policy</th><th>Matched</th><th>Action</th><th>Reason</th></tr></thead>
          <tbody>`;
      for (const entry of policyTrace.decisionLogs) {
        decisionLogsHtml += `<tr>
          <td>${this._esc(entry.policy_name || entry.name || "Unknown")}</td>
          <td>${this._esc(entry.matched === true ? "Yes" : entry.matched === false ? "No" : "Unknown")}</td>
          <td>${this._esc(entry.action || entry.actions_taken || "\u2014")}</td>
          <td>${this._esc(entry.reason || "\u2014")}</td>
        </tr>`;
      }
      decisionLogsHtml += "</tbody></table></div>";
    }

    // Non-vulnerability notice
    const decisionLogsWarning = policyTrace.decisionLogsComplete === false
      ? `<div class="warning-banner">Policy decision log history is incomplete. Loaded entries are shown, but additional policy or vulnerability decisions may exist.</div>`
      : "";
    const nonVulnNotice = !hasCVEs && policyTrace.decisionLogsComplete === true
      ? `<div class="info-banner">This quarantine was triggered by policy rules, not a specific vulnerability.</div>`
      : "";

    return `<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; img-src 'none';">
<style>
  body {
    font-family: var(--vscode-font-family);
    color: var(--vscode-foreground);
    background-color: var(--vscode-editor-background);
    padding: 16px 24px;
    line-height: 1.5;
  }
  h2 { margin: 0 0 4px 0; }
  h3 { margin: 16px 0 8px 0; }
  h4 { margin: 12px 0 6px 0; }
  .header-meta {
    color: var(--vscode-descriptionForeground);
    margin-bottom: 16px;
  }
  .quarantine-badge {
    display: inline-block;
    background: var(--vscode-inputValidation-errorBackground, rgba(255,0,0,0.1));
    color: var(--vscode-errorForeground);
    padding: 2px 10px;
    border-radius: 3px;
    font-weight: bold;
    font-size: 13px;
  }
  .actions { margin: 16px 0 20px 0; }
  .actions button {
    background-color: var(--vscode-button-background);
    color: var(--vscode-button-foreground);
    border: none;
    padding: 6px 14px;
    margin-right: 8px;
    cursor: pointer;
    font-size: 13px;
    border-radius: 2px;
  }
  .actions button:hover {
    background-color: var(--vscode-button-hoverBackground);
  }
  .status-reason-box {
    background: var(--vscode-inputValidation-warningBackground, rgba(255,200,0,0.08));
    border: 1px solid var(--vscode-inputValidation-warningBorder, #c8a000);
    border-radius: 4px;
    padding: 12px 16px;
    margin-bottom: 16px;
  }
  .status-reason-box h3 { margin-top: 0; }
  .status-reason { color: var(--vscode-editorWarning-foreground, orange); }
  .policy-card {
    margin: 8px 0 16px 0;
    padding: 10px 14px;
    background: var(--vscode-editor-background);
    border: 1px solid var(--vscode-panel-border, #444);
    border-radius: 3px;
  }
  .slug { color: var(--vscode-descriptionForeground); font-size: 0.9em; }
  .policy-description {
    margin: 8px 0 16px 0;
    padding: 10px 14px;
    background: var(--vscode-textBlockQuote-background, rgba(127,127,127,0.1));
    border-left: 3px solid var(--vscode-textBlockQuote-border, #444);
  }
  .policy-description h4 { margin-top: 0; }
  .decision-log-table { width: 100%; border-collapse: collapse; margin: 4px 0; }
  .decision-log-table th, .decision-log-table td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--vscode-panel-border); }
  .decision-log-table th { font-size: 0.9em; color: var(--vscode-descriptionForeground); border-bottom: 2px solid var(--vscode-panel-border, #444); }
  .info-banner {
    background: var(--vscode-textBlockQuote-background, rgba(127,127,127,0.1));
    border: 1px solid var(--vscode-panel-border, #444);
    border-radius: 4px;
    padding: 10px 14px;
    margin: 16px 0;
    color: var(--vscode-descriptionForeground);
  }
  .warning-banner {
    background: var(--vscode-inputValidation-warningBackground, rgba(255,200,0,0.08));
    border: 1px solid var(--vscode-inputValidation-warningBorder, #c8a000);
    border-radius: 4px;
    padding: 10px 14px;
    margin: 16px 0;
  }
</style>
</head>
<body>
  <h2>${this._esc(name || "")} ${this._esc(version || "")}</h2>
  <div class="header-meta">
    ${this._esc(format || "")}${workspace ? ` &middot; ${this._esc(workspace)}` : ""}${repo ? `/${this._esc(repo)}` : ""}
  </div>
  <span class="quarantine-badge">\u26D4 Quarantined</span>

  ${policyInfoHtml}
  ${decisionLogsWarning}
  ${nonVulnNotice}
  ${decisionLogsHtml}

  <div class="actions">
    <button data-command="findSafeVersion">Find safe version</button>
    ${packageUrl ? `<button data-command="openInCloudsmith">View in Cloudsmith</button>` : ""}
    ${hasCVEs ? `<button data-command="showVulnerabilities">Show vulnerabilities</button>` : ""}
    <button data-command="copyReport">Copy quarantine report</button>
  </div>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    document.querySelectorAll("[data-command]").forEach((button) => {
      button.addEventListener("click", () => {
        vscode.postMessage({ command: button.dataset.command });
      });
    });
  </script>
</body>
</html>`;
  }

  _buildPlainTextReport(name, version, statusReason, policyTrace) {
    const lines = [];
    lines.push(`Quarantine report: ${name || ""} ${version || ""}`);
    lines.push("=".repeat(60));
    lines.push("");
    if (statusReason) {
      lines.push(`Reason: ${statusReason}`);
      lines.push("");
    }
    if (policyTrace.parsedReason && policyTrace.parsedReason.policyName) {
      lines.push(`Policy: ${policyTrace.parsedReason.policyName}`);
      if (policyTrace.parsedReason.description) {
        lines.push(`Detail: ${policyTrace.parsedReason.description}`);
      }
      lines.push("");
    }
    if (policyTrace.policyDetail && policyTrace.policyDetail.description) {
      lines.push(`Policy description: ${policyTrace.policyDetail.description}`);
      lines.push("");
    }
    if (policyTrace.decisionLogs.length > 0) {
      lines.push("Decision log:");
      for (const entry of policyTrace.decisionLogs) {
        lines.push(`  - ${entry.policy_name || entry.name || "Unknown"}: ${entry.reason || entry.action || "\u2014"}`);
      }
    }
    if (policyTrace.decisionLogsComplete === false) {
      lines.push("Policy decision log history is incomplete; additional entries may exist.");
    }
    return lines.join("\n");
  }

  _esc(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  _getNonce() {
    return this._createNonce();
  }

  _isOperationCurrent(operation) {
    return Boolean(
      operation
      && this._operation === operation
      && this._panel === operation.panel
      && !operation.controller.signal.aborted
      && isAccountCurrent(this._connectionManager, operation.account)
    );
  }

  resetForAccountChange() {
    const operation = this._operation;
    if (operation) {
      this._disposeOperation(operation, true);
      return;
    }
    const panel = this._panel;
    this._panel = null;
    if (panel) panel.dispose();
  }

  dispose() {
    this.resetForAccountChange();
  }

  _disposeOperation(operation, disposePanel) {
    if (!operation || operation.disposed) return;
    operation.disposed = true;
    operation.controller.abort();
    operation.messageSubscription?.dispose();
    operation.messageSubscription = null;
    operation.disposeSubscription?.dispose();
    operation.disposeSubscription = null;
    if (this._operation === operation) this._operation = null;
    if (this._panel === operation.panel) this._panel = null;
    if (disposePanel) operation.panel.dispose();
  }
}

const QUARANTINE_MESSAGE_CONTRACTS = Object.freeze({
  findSafeVersion: Object.freeze([]),
  showVulnerabilities: Object.freeze([]),
  openInCloudsmith: Object.freeze([]),
  copyReport: Object.freeze([]),
});

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

module.exports = { QuarantineExplainProvider };

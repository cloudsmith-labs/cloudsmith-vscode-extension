// Upstream resolution preview WebView panel.
// Shows a "what if I pull this?" dry run for packages that don't exist locally.

const vscode = require("vscode");

class UpstreamPreviewProvider {
  constructor(context) {
    this.context = context;
    this._panel = null;
  }

  /**
   * Show the upstream preview panel for a resolution result.
   * @param {Object} result - Output from UpstreamChecker.previewResolution()
   */
  show(result) {
    if (!result || typeof result !== "object") return;
    if (this._panel) {
      this._panel.dispose();
    }

    this._panel = vscode.window.createWebviewPanel(
      "cloudsmithUpstreamPreview",
      `Upstream preview: ${result.name}`,
      vscode.ViewColumn.One,
      { enableScripts: false, localResourceRoots: [] }
    );

    this._panel.webview.html = this._getHtmlContent(result);

    this._panel.onDidDispose(() => {
      this._panel = null;
    });
  }

  _getHtmlContent(result) {
    const upstreamComplete = result.upstreams.complete === true;
    const localStatus = result.local.error
      ? `<span class="status-error">Could not verify local package data: ${this._escapeHtml(this._errorMessage(result.local.error))}</span>`
      : result.local.data
        ? `<span class="status-found">Found in ${this._escapeHtml(result.repo)} (${this._escapeHtml(result.local.data.status_str || "Unknown")})</span>`
        : result.local.complete === true
          ? `<span class="status-missing">Not found in ${this._escapeHtml(result.repo)}</span>`
          : '<span class="status-error">Local package status is incomplete.</span>';

    let upstreamHtml = "";
    if (result.upstreams.error) {
      upstreamHtml = `<p class="error-banner">Could not load upstream data: ${this._escapeHtml(result.upstreams.error)}</p>`;
    } else if (result.upstreams.data.configs.length === 0) {
      upstreamHtml = upstreamComplete
        ? '<p class="muted">No upstreams configured for this format.</p>'
        : '<p class="error-banner">Upstream inspection is incomplete. Additional upstreams may exist.</p>';
    } else {
      if (!upstreamComplete) {
        upstreamHtml += '<p class="error-banner">Upstream inspection is incomplete. The loaded configurations are shown below.</p>';
      }
      upstreamHtml += '<table class="data-table"><thead><tr><th>Name</th><th>URL</th><th>Status</th></tr></thead><tbody>';
      for (const u of result.upstreams.data.configs) {
        const active = u.is_active !== false;
        const statusClass = active ? "status-active" : "status-inactive";
        const statusLabel = active ? "Active" : "Inactive";
        upstreamHtml += `<tr>
          <td>${this._escapeHtml(u.name || "Unnamed")}</td>
          <td class="mono">${this._escapeHtml(u.upstream_url || "")}</td>
          <td class="${statusClass}">${statusLabel}</td>
        </tr>`;
      }
      upstreamHtml += "</tbody></table>";
    }

    const resolutionSummary = result.canResolveViaUpstream
      ? `<div class="resolution-yes">This package can likely resolve through ${result.upstreams.data.active} active upstream${result.upstreams.data.active === 1 ? "" : "s"}.</div>`
      : upstreamComplete && !result.upstreams.error
        ? '<div class="resolution-no">No active upstreams for this format. Upload the package directly.</div>'
        : '<div class="resolution-no">Upstream resolution could not be determined because inspection is incomplete.</div>';

    const upstreamHeading = upstreamComplete
      ? `Upstreams (${result.upstreams.data.active} active of ${result.upstreams.data.total})`
      : `Loaded upstreams (${result.upstreams.data.active} active of ${result.upstreams.data.total} loaded)`;

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; base-uri 'none'; form-action 'none';">
<style>
  body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); background: var(--vscode-editor-background); padding: 16px; margin: 0; }
  h2 { color: var(--vscode-foreground); margin-top: 0; border-bottom: 1px solid var(--vscode-panel-border); padding-bottom: 8px; }
  h3 { color: var(--vscode-foreground); margin-top: 20px; }
  .header-info { display: grid; grid-template-columns: auto 1fr; gap: 4px 12px; margin-bottom: 16px; }
  .header-info dt { font-weight: 600; color: var(--vscode-descriptionForeground); }
  .header-info dd { margin: 0; }
  .data-table { width: 100%; border-collapse: collapse; margin: 8px 0; }
  .data-table th, .data-table td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--vscode-panel-border); }
  .data-table th { color: var(--vscode-descriptionForeground); font-weight: 600; font-size: 0.9em; }
  .mono { font-family: var(--vscode-editor-font-family); font-size: 0.9em; }
  .status-found { color: var(--vscode-testing-iconPassed); }
  .status-missing { color: var(--vscode-errorForeground); }
  .status-active { color: var(--vscode-testing-iconPassed); }
  .status-inactive { color: var(--vscode-descriptionForeground); }
  .status-error { color: var(--vscode-errorForeground); font-weight: 600; }
  .muted { color: var(--vscode-descriptionForeground); font-style: italic; }
  .error-banner { background: var(--vscode-inputValidation-errorBackground, rgba(255,0,0,0.08)); border: 1px solid var(--vscode-inputValidation-errorBorder, #c42b1c); color: var(--vscode-errorForeground); padding: 10px 12px; border-radius: 4px; }
  .resolution-yes { background: var(--vscode-inputValidation-infoBackground); border: 1px solid var(--vscode-inputValidation-infoBorder); padding: 10px; border-radius: 4px; margin: 12px 0; }
  .resolution-no { background: var(--vscode-inputValidation-warningBackground); border: 1px solid var(--vscode-inputValidation-warningBorder); padding: 10px; border-radius: 4px; margin: 12px 0; }
</style>
</head>
<body>
  <h2>Upstream resolution preview</h2>
  <dl class="header-info">
    <dt>Package</dt><dd>${this._escapeHtml(result.name)}</dd>
    <dt>Format</dt><dd>${this._escapeHtml(result.format)}</dd>
    <dt>Target repository</dt><dd>${this._escapeHtml(result.workspace)}/${this._escapeHtml(result.repo)}</dd>
    <dt>Local status</dt><dd>${localStatus}</dd>
  </dl>

  ${resolutionSummary}

  <h3>${upstreamHeading}</h3>
  ${upstreamHtml}
</body>
</html>`;
  }

  _escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  _errorMessage(error) {
    return error && typeof error === "object" && typeof error.message === "string"
      ? error.message
      : String(error || "The local package collection could not be verified.");
  }

  dispose() {
    if (this._panel) {
      this._panel.dispose();
      this._panel = null;
    }
  }

  resetForAccountChange() {
    this.dispose();
  }
}

module.exports = { UpstreamPreviewProvider };

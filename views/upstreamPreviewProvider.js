// Upstream resolution preview WebView panel.
// Shows a "what if I pull this?" dry run for packages that don't exist locally.

const vscode = require("vscode");
const {
  formatUpstreamError,
  formatUpstreamOrigin,
  formatUpstreamText,
} = require("../util/upstreamPresentation");

const MAX_RENDERED_UPSTREAMS = 100;
const MAX_PREVIEW_UPSTREAMS = 500;

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
      `Upstream preview: ${formatUpstreamText(result.name, "Unknown")}`,
      vscode.ViewColumn.One,
      { enableScripts: false, localResourceRoots: [] }
    );

    this._panel.webview.html = this._getHtmlContent(result);

    this._panel.onDidDispose(() => {
      this._panel = null;
    });
  }

  _getHtmlContent(result) {
    const local = result.local && typeof result.local === "object" ? result.local : {};
    const upstreamState = result.upstreams && typeof result.upstreams === "object"
      ? result.upstreams
      : {};
    const upstreamData = upstreamState.data && typeof upstreamState.data === "object"
      ? upstreamState.data
      : {};
    const rawConfigs = Array.isArray(upstreamData.configs) ? upstreamData.configs : [];
    const boundedConfigs = rawConfigs.slice(0, MAX_PREVIEW_UPSTREAMS);
    const configs = boundedConfigs.filter(isPreviewUpstreamConfig);
    const metadataConsistent = rawConfigs.length <= MAX_PREVIEW_UPSTREAMS
      && configs.length === rawConfigs.length
      && upstreamData.total === configs.length
      && upstreamData.active === configs.filter(config => config.is_active !== false).length;
    const displayedConfigs = configs
      .slice(0, MAX_RENDERED_UPSTREAMS);
    const loadedTotal = configs.length;
    const activeTotal = configs.filter(config => config.is_active !== false).length;
    const localError = local.errorMessage == null
      ? null
      : formatUpstreamError(local.errorMessage, "local");
    const upstreamError = upstreamState.errorMessage == null
      ? null
      : formatUpstreamError(upstreamState.errorMessage, "upstream");
    const upstreamComplete = upstreamState.complete === true
      && metadataConsistent
      && upstreamError === null;
    const localStatus = localError
      ? `<span class="status-error">Could not verify local package data: ${this._escapeHtml(localError)}</span>`
      : local.data
        ? `<span class="status-found">Found in ${this._escapeHtml(formatUpstreamText(result.repo))} (${this._escapeHtml(formatUpstreamText(local.data.status_str, "Unknown"))})</span>`
        : local.complete === true
          ? `<span class="status-missing">Not found in ${this._escapeHtml(formatUpstreamText(result.repo))}</span>`
          : '<span class="status-error">Local package status is incomplete.</span>';

    let upstreamHtml = "";
    if (upstreamError) {
      upstreamHtml = `<p class="error-banner">Could not load upstream data: ${this._escapeHtml(upstreamError)}</p>`;
    } else if (configs.length === 0) {
      upstreamHtml = upstreamComplete
        ? '<p class="muted">No upstreams configured for this format.</p>'
        : '<p class="error-banner">Upstream inspection is incomplete. Additional upstreams may exist.</p>';
    } else {
      if (!upstreamComplete) {
        upstreamHtml += '<p class="error-banner">Upstream inspection is incomplete. The loaded configurations are shown below.</p>';
      }
      upstreamHtml += '<table class="data-table"><thead><tr><th>Name</th><th>Origin</th><th>Status</th></tr></thead><tbody>';
      for (const u of displayedConfigs) {
        const active = u.is_active !== false;
        const statusClass = active ? "status-active" : "status-inactive";
        const statusLabel = active ? "Active" : "Inactive";
        upstreamHtml += `<tr>
          <td>${this._escapeHtml(formatUpstreamText(u.name, "Unnamed"))}</td>
          <td class="mono">${this._escapeHtml(formatUpstreamOrigin(u.upstream_url))}</td>
          <td class="${statusClass}">${statusLabel}</td>
        </tr>`;
      }
      upstreamHtml += "</tbody></table>";
      if (configs.length > displayedConfigs.length) {
        upstreamHtml += `<p class="muted">Showing ${displayedConfigs.length} of ${configs.length} loaded upstreams.</p>`;
      }
    }

    const resolutionSummary = activeTotal > 0
      ? `<div class="resolution-yes">This package can likely resolve through ${activeTotal} active upstream${activeTotal === 1 ? "" : "s"}.</div>`
      : upstreamComplete && !upstreamError
        ? '<div class="resolution-no">No active upstreams for this format. Upload the package directly.</div>'
        : '<div class="resolution-no">Upstream resolution could not be determined because inspection is incomplete.</div>';

    const upstreamHeading = upstreamComplete
      ? `Upstreams (${activeTotal} active of ${loadedTotal})`
      : `Loaded upstreams (${activeTotal} active of ${loadedTotal} loaded)`;

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
    <dt>Package</dt><dd>${this._escapeHtml(formatUpstreamText(result.name, "Unknown"))}</dd>
    <dt>Format</dt><dd>${this._escapeHtml(formatUpstreamText(result.format, "Unknown"))}</dd>
    <dt>Target repository</dt><dd>${this._escapeHtml(formatUpstreamText(result.workspace, "Unknown"))}/${this._escapeHtml(formatUpstreamText(result.repo, "Unknown"))}</dd>
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

function isPreviewUpstreamConfig(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && typeof value.name === "string"
    && value.name.length > 0
    && (value.is_active === undefined || typeof value.is_active === "boolean")
    && (value.upstream_url === undefined || typeof value.upstream_url === "string");
}

module.exports = { UpstreamPreviewProvider };

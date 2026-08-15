// Upstream resolution preview WebView panel.
// Shows a "what if I pull this?" dry run for packages that don't exist locally.

const { types: { isProxy } } = require("util");
const vscode = require("vscode");
const { sanitizeSafeInventoryUpstream } = require("../util/upstreamChecker");
const { getUpstreamFormatDescriptor } = require("../util/upstreamFormats");
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
   * @param {Object} result - Output from the upstream preview runtime facade.
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
    const formatDescriptor = getUpstreamFormatDescriptor(ownDataValue(result, "format"));
    const canonicalFormat = formatDescriptor?.inspectable ? formatDescriptor.format : null;
    const localValue = ownDataValue(result, "local");
    const local = localValue && typeof localValue === "object" ? localValue : {};
    const upstreamValue = ownDataValue(result, "upstreams");
    const upstreamState = upstreamValue && typeof upstreamValue === "object"
      ? upstreamValue
      : {};
    const upstreamDataValue = ownDataValue(upstreamState, "data");
    const upstreamData = upstreamDataValue && typeof upstreamDataValue === "object"
      ? upstreamDataValue
      : {};
    const rawConfigState = snapshotOwnDataArray(
      ownDataValue(upstreamData, "configs"),
      MAX_PREVIEW_UPSTREAMS
    );
    const rawConfigs = rawConfigState.values;
    const sanitizedConfigs = canonicalFormat
      ? rawConfigs.map(config => sanitizeSafeInventoryUpstream(config, canonicalFormat))
      : [];
    const configs = sanitizedConfigs.filter(Boolean);
    const metadataConsistent = canonicalFormat !== null
      && rawConfigState.valid
      && configs.length === rawConfigs.length
      && ownDataValue(upstreamData, "total") === configs.length
      && ownDataValue(upstreamData, "active")
        === configs.filter(config => config.is_active !== false).length;
    const displayedConfigs = configs
      .slice(0, MAX_RENDERED_UPSTREAMS);
    const loadedTotal = configs.length;
    const activeTotal = configs.filter(config => config.is_active !== false).length;
    const localErrorValue = ownDataValue(local, "errorMessage");
    const localData = ownDataValue(local, "data");
    const localComplete = ownDataValue(local, "complete");
    const upstreamErrorValue = ownDataValue(upstreamState, "errorMessage");
    const upstreamCompleteValue = ownDataValue(upstreamState, "complete");
    const repository = ownDataValue(result, "repo");
    const localError = localErrorValue == null
      ? null
      : formatUpstreamError(localErrorValue, "local");
    const upstreamError = upstreamErrorValue == null
      ? null
      : formatUpstreamError(upstreamErrorValue, "upstream");
    const upstreamComplete = upstreamCompleteValue === true
      && metadataConsistent
      && upstreamError === null;
    const localStatus = localError
      ? `<span class="status-error">Could not verify local package data: ${this._escapeHtml(localError)}</span>`
      : localData
        ? `<span class="status-found">Found in ${this._escapeHtml(formatUpstreamText(
          repository
        ))} (${this._escapeHtml(formatUpstreamText(
          ownDataValue(localData, "status_str"), "Unknown"
        ))})</span>`
        : localComplete === true
          ? `<span class="status-missing">Not found in ${this._escapeHtml(formatUpstreamText(repository))}</span>`
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
          <td class="mono">${this._escapeHtml(formatUpstreamOrigin(u.origin))}</td>
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
    <dt>Package</dt><dd>${this._escapeHtml(formatUpstreamText(ownDataValue(result, "name"), "Unknown"))}</dd>
    <dt>Format</dt><dd>${this._escapeHtml(formatUpstreamText(canonicalFormat, "Unknown"))}</dd>
    <dt>Target repository</dt><dd>${this._escapeHtml(formatUpstreamText(
      ownDataValue(result, "workspace"), "Unknown"
    ))}/${this._escapeHtml(formatUpstreamText(ownDataValue(result, "repo"), "Unknown"))}</dd>
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

function ownDataValue(value, property) {
  if (!value || typeof value !== "object" || isProxy(value)) return null;
  try {
    if (Array.isArray(value)) return null;
    const descriptor = Object.getOwnPropertyDescriptor(value, property);
    return descriptor && Object.prototype.hasOwnProperty.call(descriptor, "value")
      ? descriptor.value
      : null;
  } catch {
    return null;
  }
}

function snapshotOwnDataArray(value, maximum) {
  if (isProxy(value)) return { valid: false, values: [] };
  let descriptors;
  try {
    if (!Array.isArray(value)) return { valid: false, values: [] };
    if (Object.getPrototypeOf(value) !== Array.prototype) return { valid: false, values: [] };
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return { valid: false, values: [] };
  }
  const lengthDescriptor = descriptors.length;
  const length = lengthDescriptor?.value;
  if (!Number.isSafeInteger(length) || length < 0 || length > maximum) {
    return { valid: false, values: [] };
  }
  if (Reflect.ownKeys(descriptors).some(key => (
    typeof key !== "string" || (key !== "length" && !/^(0|[1-9]\d*)$/u.test(key))
  ))) return { valid: false, values: [] };
  const values = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      return { valid: false, values: [] };
    }
    values.push(descriptor.value);
  }
  return { valid: true, values };
}

module.exports = { UpstreamPreviewProvider };

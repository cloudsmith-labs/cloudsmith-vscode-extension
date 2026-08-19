// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const vscode = require("vscode");
const {
  getDependencyPackageSourceDisplayLocation,
  getDependencyQualifierDisplayValue,
  normalizeDependencyDisplayValue,
} = require("../util/dependencyRecord");

class ComplianceReportProvider {
  constructor(context) {
    this.context = context;
    this._panel = null;
  }

  show(reportData) {
    if (!reportData) {
      vscode.window.showInformationMessage("Run a dependency scan before opening the report.");
      return;
    }

    if (this._panel) {
      this._panel.reveal(vscode.ViewColumn.One);
    } else {
      this._panel = vscode.window.createWebviewPanel(
        "cloudsmithComplianceReport",
        "Dependency Health Report",
        vscode.ViewColumn.One,
        {
          enableScripts: false,
          localResourceRoots: [],
        }
      );

      this._panel.onDidDispose(() => {
        this._panel = null;
      });
    }

    this._panel.webview.html = this._getHtml(reportData);
  }

  dispose() {
    if (this._panel) {
      this._panel.dispose();
      this._panel = null;
    }
  }

  _getHtml(reportData) {
    const summary = reportData.summary || {};
    const total = normalizeSummaryCount(summary.total);
    const occurrences = summary.occurrences == null
      ? total
      : normalizeSummaryCount(summary.occurrences);
    const direct = normalizeSummaryCount(summary.direct);
    const found = normalizeSummaryCount(summary.found);
    const notFound = normalizeSummaryCount(summary.notFound);
    const notApplicable = normalizeSummaryCount(summary.notApplicable);
    const vulnCount = normalizeSummaryCount(summary.vulnCount);
    const restrictiveLicenseCount = normalizeSummaryCount(summary.restrictiveLicenseCount);
    const coveragePct = clampPercent(summary.coveragePct);
    const licenseIds = uniqueLicenseIds(reportData.restrictiveLicenseDeps || []);
    const sections = [];

    if (Object.keys(reportData.ecosystemBreakdown || {}).length > 1) {
      sections.push(renderEcosystemSection(reportData.ecosystemBreakdown));
    }

    if ((reportData.vulnerableDeps || []).length > 0) {
      sections.push(renderVulnerabilitySection(reportData.vulnerableDeps));
    }

    if ((reportData.restrictiveLicenseDeps || []).length > 0) {
      sections.push(renderLicenseSection(reportData.restrictiveLicenseDeps));
    }

    if ((reportData.policyViolationDeps || []).length > 0) {
      sections.push(renderPolicySection(reportData.policyViolationDeps));
    }

    if (notFound > 0) {
      sections.push(renderUncoveredSection(reportData.uncoveredDeps || []));
    }

    const notApplicableDeps = Array.isArray(reportData.notApplicableDeps)
      ? reportData.notApplicableDeps
      : [];
    if (notApplicable > 0 && notApplicableDeps.length > 0) {
      sections.push(renderNotApplicableSection(notApplicableDeps));
    }

    const incompleteCount = [
      summary.unresolved,
      summary.lookupFailed,
      summary.lookupIncomplete,
      summary.rateLimited,
      summary.checking,
    ].reduce((total, value) => (
      Number.isSafeInteger(value) && value > 0 ? total + value : total
    ), 0);
    const emptyState = sections.length === 0
      ? incompleteCount > 0
        ? `
        <div class="card empty-card">
          <h2>Compliance status incomplete</h2>
          <p>${escapeHtml(String(incompleteCount))} dependency lookups were unresolved, failed, incomplete, rate limited, or still in progress. No clean compliance conclusion can be made.</p>
        </div>
      `
        : `
        <div class="card empty-card">
          <h2>No compliance issues detected</h2>
          <p>All scanned dependencies were covered by Cloudsmith and no report sections were triggered for this scan.</p>
        </div>
      `
      : "";

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; base-uri 'none'; form-action 'none';">
  <title>Dependency Health report</title>
  <style>
    :root {
      --cs-teal: #1abc9c;
      --cs-amber: #f39c12;
      --cs-red: #e74c3c;
      --cs-blue: #3498db;
      --cs-gray-bg: var(--vscode-editor-background);
      --cs-gray-card: var(--vscode-editorWidget-background);
      --cs-text: var(--vscode-editor-foreground);
      --cs-text-secondary: var(--vscode-descriptionForeground);
      --cs-border: var(--vscode-panel-border, var(--vscode-editorWidget-border));
      --cs-row: color-mix(in srgb, var(--vscode-list-hoverBackground) 72%, transparent);
      --cs-shadow: 0 16px 36px rgba(0, 0, 0, 0.08);
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      padding: 32px 28px 40px;
      color: var(--cs-text);
      background:
        radial-gradient(circle at top right, rgba(52, 152, 219, 0.10), transparent 32%),
        radial-gradient(circle at top left, rgba(26, 188, 156, 0.10), transparent 28%),
        var(--cs-gray-bg);
      font-family: var(--vscode-font-family);
      font-size: var(--vscode-font-size);
      line-height: 1.5;
    }

    .shell {
      max-width: 1180px;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 18px;
    }

    .report-header {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .report-header h1 {
      margin: 0;
      font-size: 28px;
      line-height: 1.15;
      font-weight: 700;
      letter-spacing: -0.02em;
    }

    .subtitle {
      margin: 0;
      color: var(--cs-text-secondary);
    }

    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 12px;
    }

    .card,
    .summary-card,
    .report-section {
      border: 1px solid var(--cs-border);
      border-radius: 16px;
      background: var(--cs-gray-card);
      box-shadow: var(--cs-shadow);
    }

    .summary-card {
      padding: 16px 18px;
      border-left-width: 5px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .summary-card.dependencies {
      border-left-color: var(--vscode-editorWarning-foreground);
    }

    .summary-card.vulnerabilities {
      border-left-color: var(--vscode-errorForeground);
    }

    .summary-card.licenses {
      border-left-color: var(--vscode-errorForeground);
    }

    .summary-card.coverage {
      border-left-color: var(--vscode-testing-iconPassed);
    }

    .summary-value {
      font-size: 30px;
      line-height: 1;
      font-weight: 700;
    }

    .summary-label {
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--cs-text-secondary);
    }

    .summary-detail {
      font-size: 13px;
      color: var(--cs-text-secondary);
    }

    .package-detail {
      margin-top: 3px;
      color: var(--cs-text-secondary);
      font-size: 12px;
    }

    .coverage-panel {
      padding: 18px;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .coverage-bar {
      width: 100%;
      height: 14px;
      border-radius: 999px;
      overflow: hidden;
      background: color-mix(in srgb, var(--cs-border) 60%, transparent);
    }

    .coverage-fill {
      height: 100%;
      background: linear-gradient(90deg, var(--cs-teal), color-mix(in srgb, var(--cs-teal) 68%, white));
    }

    .coverage-label {
      margin: 0;
      color: var(--cs-text-secondary);
    }

    .report-section {
      overflow: hidden;
    }

    .report-section > summary {
      list-style: none;
      cursor: pointer;
      padding: 14px 18px;
      font-size: 15px;
      font-weight: 700;
      border-bottom: 1px solid transparent;
      background: color-mix(in srgb, var(--cs-border) 26%, transparent);
    }
    .report-section > summary h2 { display: inline; margin: 0; font: inherit; }

    .report-section[open] > summary {
      border-bottom-color: var(--cs-border);
    }

    .report-section > summary::-webkit-details-marker {
      display: none;
    }

    .report-section > summary::before {
      content: "▸";
      display: inline-block;
      margin-right: 8px;
    }

    .report-section[open] > summary::before {
      content: "▾";
    }

    .report-section > summary:focus-visible,
    table:focus-visible {
      outline: 2px solid var(--vscode-focusBorder);
      outline-offset: -2px;
    }

    .section-body {
      padding: 16px 18px 18px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .section-group {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .section-group h3 {
      margin: 0;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--cs-text-secondary);
    }

    table {
      width: 100%;
      max-width: 100%;
      display: block;
      overflow-x: auto;
      border-collapse: collapse;
      font-size: 13px;
    }

    th,
    td {
      padding: 11px 12px;
      text-align: left;
      vertical-align: top;
      border-bottom: 1px solid color-mix(in srgb, var(--cs-border) 78%, transparent);
    }

    th {
      color: var(--cs-text-secondary);
      font-weight: 700;
    }

    tbody tr:nth-child(even) td {
      background: var(--cs-row);
    }

    .badge {
      display: inline-flex;
      align-items: center;
      padding: 3px 9px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      white-space: nowrap;
    }

    .severity-critical,
    .status-quarantined,
    .classification-restrictive {
      background: var(--vscode-inputValidation-errorBackground);
      color: var(--vscode-errorForeground);
    }

    .severity-high {
      background: var(--vscode-inputValidation-warningBackground);
      color: var(--vscode-editorWarning-foreground);
    }

    .severity-medium,
    .severity-low,
    .classification-weak-copyleft {
      background: var(--vscode-inputValidation-warningBackground);
      color: var(--vscode-editorWarning-foreground);
    }

    .status-default,
    .classification-default {
      background: var(--vscode-inputValidation-infoBackground);
      color: var(--vscode-textLink-foreground);
    }

    .empty-card {
      padding: 20px;
    }

    .empty-card h2 {
      margin: 0 0 6px;
      font-size: 18px;
    }

    .empty-card p {
      margin: 0;
      color: var(--cs-text-secondary);
    }

    @media (max-width: 720px) {
      body {
        padding: 20px 16px 28px;
      }

      .summary-grid {
        grid-template-columns: 1fr;
      }

      th,
      td {
        padding: 10px 8px;
      }
    }

    @media (forced-colors: active) {
      .card, .summary-card, .report-section, .badge, .coverage-bar {
        border: 1px solid CanvasText;
        box-shadow: none;
      }
      .coverage-fill { background: Highlight; }
    }
  </style>
</head>
<body>
  <main class="shell">
    <header class="report-header">
      <h1>Dependency Health report</h1>
      <p class="subtitle">${escapeHtml(reportData.projectName || "workspace")} · Scanned ${escapeHtml(formatScanDate(reportData.scanDate))}</p>
    </header>

    <div class="summary-grid">
      ${renderSummaryCard("dependencies", total, "Dependencies", `${occurrences} occurrences · ${direct} direct`)}
      ${renderSummaryCard("vulnerabilities", vulnCount, "Vulnerable", formatSeverityBreakdown(summary))}
      ${renderSummaryCard("licenses", restrictiveLicenseCount, "Restrictive licenses", formatLicenseBreakdown(licenseIds))}
      ${renderSummaryCard("coverage", found, "Cloudsmith coverage", `${coveragePct}% coverage`)}
    </div>

    <div class="card coverage-panel">
      <div>
        <strong>Coverage overview</strong>
      </div>
      <div class="coverage-bar" aria-hidden="true">
        <div class="coverage-fill" style="width: ${coveragePct}%"></div>
      </div>
      <p class="coverage-label">${escapeHtml(formatCoverageLabel(summary))}</p>
    </div>

    ${emptyState}
    ${sections.join("\n")}
  </main>
</body>
</html>`;
  }
}

function renderSummaryCard(cssClass, value, label, detail) {
  return `
    <div class="summary-card ${cssClass}" role="group" aria-label="${escapeHtml(label)}: ${escapeHtml(String(value))}">
      <div class="summary-value">${escapeHtml(String(value))}</div>
      <div class="summary-label">${escapeHtml(label)}</div>
      <div class="summary-detail">${escapeHtml(detail)}</div>
    </div>
  `;
}

function renderSection(title, bodyHtml) {
  return `
    <details class="report-section" open>
      <summary><h2>${escapeHtml(title)}</h2></summary>
      <div class="section-body">
        ${bodyHtml}
      </div>
    </details>
  `;
}

function renderEcosystemSection(ecosystemBreakdown) {
  const rows = Object.entries(ecosystemBreakdown || {})
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .map(([ecosystem, count]) => `
      <tr>
        <td>${escapeHtml(ecosystem)}</td>
        <td>${escapeHtml(String(count))}</td>
      </tr>
    `)
    .join("");

  return renderSection("Ecosystem breakdown", `
    <table tabindex="0">
      <caption>Dependencies by ecosystem</caption>
      <thead>
        <tr>
          <th scope="col">Ecosystem</th>
          <th scope="col">Dependencies</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `);
}

function renderVulnerabilitySection(vulnerableDeps) {
  const rows = vulnerableDeps.map((dependency) => {
    const severityClass = severityClassName(dependency.maxSeverity);
    const vulnerabilityEvidence = Number.isSafeInteger(dependency.cveCount)
      && dependency.cveCount >= 0
      ? String(dependency.cveCount)
      : boundedVulnerabilityStatus(dependency.vulnerabilityStatus);
    return `
      <tr>
        <td>${renderPackageCell(dependency)}</td>
        <td>${escapeHtml(displayValue(dependency.version))}</td>
        <td>${escapeHtml(dependency.isDirect ? "Direct" : "Transitive")}</td>
        <td><span class="badge ${severityClass}">${escapeHtml(dependency.maxSeverity || "Unknown")}</span></td>
        <td>${escapeHtml(vulnerabilityEvidence)}</td>
        <td>${escapeHtml(dependency.hasFixAvailable ? "Yes" : "No")}</td>
      </tr>
    `;
  }).join("");

  return renderSection("Vulnerability findings", `
    <table tabindex="0">
      <caption>Dependencies with known vulnerabilities</caption>
      <thead>
        <tr>
          <th scope="col">Package</th>
          <th scope="col">Version</th>
          <th scope="col">Type</th>
          <th scope="col">Severity</th>
          <th scope="col">CVE count / status</th>
          <th scope="col">Fix available</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `);
}

function boundedVulnerabilityStatus(value) {
  return value === "Detected" ? "Detected" : "Unknown";
}

function renderLicenseSection(restrictiveLicenseDeps) {
  const rows = restrictiveLicenseDeps.map((dependency) => `
    <tr>
      <td>${renderPackageCell(dependency)}</td>
      <td>${escapeHtml(displayValue(dependency.version))}</td>
      <td>${escapeHtml(displayValue(dependency.spdx))}</td>
      <td><span class="badge ${licenseClassName(dependency.classification)}">${escapeHtml(dependency.classification)}</span></td>
    </tr>
  `).join("");

  return renderSection("License summary", `
    <table tabindex="0">
      <caption>Dependencies with restrictive or weak copyleft licenses</caption>
      <thead>
        <tr>
          <th scope="col">Package</th>
          <th scope="col">Version</th>
          <th scope="col">SPDX</th>
          <th scope="col">Classification</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `);
}

function renderPolicySection(policyViolationDeps) {
  const rows = policyViolationDeps.map((dependency) => `
    <tr>
      <td>${renderPackageCell(dependency)}</td>
      <td>${escapeHtml(displayValue(dependency.version))}</td>
      <td><span class="badge ${policyClassName(dependency.status)}">${escapeHtml(dependency.status)}</span></td>
      <td>${escapeHtml(displayValue(dependency.detail))}</td>
    </tr>
  `).join("");

  return renderSection("Policy compliance", `
    <table tabindex="0">
      <caption>Dependencies with policy findings</caption>
      <thead>
        <tr>
          <th scope="col">Package</th>
          <th scope="col">Version</th>
          <th scope="col">Status</th>
          <th scope="col">Detail</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `);
}

function renderUncoveredSection(uncoveredDeps) {
  const reachable = uncoveredDeps.filter((dependency) => dependency.upstreamStatus === "reachable");
  const notReachable = uncoveredDeps.filter((dependency) => (
    dependency.upstreamStatus === "no_proxy" || dependency.upstreamStatus === "unreachable"
  ));
  const unknown = uncoveredDeps.filter((dependency) => (
    dependency.upstreamStatus !== "reachable"
    && dependency.upstreamStatus !== "no_proxy"
    && dependency.upstreamStatus !== "unreachable"
  ));
  const groups = [];

  if (reachable.length > 0) {
    groups.push(`
      <div class="section-group">
        <h3>Reachable via upstream proxy</h3>
        <table tabindex="0">
          <caption>Uncovered dependencies reachable through an upstream</caption>
          <thead>
            <tr>
              <th scope="col">Package</th>
              <th scope="col">Version</th>
              <th scope="col">Ecosystem</th>
              <th scope="col">Available in</th>
            </tr>
          </thead>
          <tbody>
            ${reachable.map((dependency) => `
              <tr>
                <td>${renderPackageCell(dependency)}</td>
                <td>${escapeHtml(displayValue(dependency.version))}</td>
                <td>${escapeHtml(displayValue(dependency.ecosystem))}</td>
                <td>${escapeHtml(displayValue(dependency.upstreamDetail))}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    `);
  }

  if (notReachable.length > 0) {
    groups.push(`
      <div class="section-group">
        <h3>Not reachable</h3>
        <table tabindex="0">
          <caption>Uncovered dependencies not reachable through an upstream</caption>
          <thead>
            <tr>
              <th scope="col">Package</th>
              <th scope="col">Version</th>
              <th scope="col">Ecosystem</th>
              <th scope="col">Reason</th>
            </tr>
          </thead>
          <tbody>
            ${notReachable.map((dependency) => `
              <tr>
                <td>${renderPackageCell(dependency)}</td>
                <td>${escapeHtml(displayValue(dependency.version))}</td>
                <td>${escapeHtml(displayValue(dependency.ecosystem))}</td>
                <td>${escapeHtml(displayValue(dependency.upstreamDetail))}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    `);
  }

  if (unknown.length > 0) {
    groups.push(`
      <div class="section-group">
        <h3>Reachability unknown</h3>
        <table tabindex="0">
          <caption>Dependencies with unknown upstream reachability</caption>
          <thead>
            <tr>
              <th scope="col">Package</th>
              <th scope="col">Version</th>
              <th scope="col">Ecosystem</th>
              <th scope="col">Detail</th>
            </tr>
          </thead>
          <tbody>
            ${unknown.map((dependency) => `
              <tr>
                <td>${renderPackageCell(dependency)}</td>
                <td>${escapeHtml(displayValue(dependency.version))}</td>
                <td>${escapeHtml(displayValue(dependency.ecosystem))}</td>
                <td>${escapeHtml(displayValue(dependency.upstreamDetail))}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    `);
  }

  return renderSection("Uncovered dependencies", groups.join(""));
}

function renderNotApplicableSection(dependencies) {
  const rows = dependencies.map((dependency) => `
    <tr>
      <td>${renderPackageCell(dependency)}</td>
      <td>${escapeHtml(displayValue(dependency.version))}</td>
      <td>${escapeHtml(displayValue(dependency.sourceKind))}</td>
      <td>${escapeHtml(displayValue(dependency.detail))}</td>
    </tr>
  `).join("");
  return renderSection("Registry lookup not applicable", `
    <table tabindex="0">
      <caption>Dependencies not eligible for registry lookup</caption>
      <thead>
        <tr>
          <th scope="col">Package</th>
          <th scope="col">Version</th>
          <th scope="col">Source kind</th>
          <th scope="col">Detail</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `);
}

function renderPackageCell(dependency) {
  const detailParts = [];
  const qualifierVariants = new Set();
  const provenance = Array.isArray(dependency && dependency.provenance)
    ? dependency.provenance
    : [];
  const qualifierSources = [
    dependency && dependency.qualifiers || {},
    ...provenance.map((entry) => entry && entry.qualifiers || {}),
  ];
  for (const qualifiers of qualifierSources) {
    if (!qualifiers || typeof qualifiers !== "object" || Array.isArray(qualifiers)) continue;
    for (const [key, value] of Object.entries(qualifiers)) {
      const displayLabel = normalizeDependencyDisplayValue(formatQualifierLabel(key));
      const displayValue = normalizeDependencyDisplayValue(
        getDependencyQualifierDisplayValue(key, value)
      );
      if (displayLabel && displayValue != null) {
        qualifierVariants.add(`${displayLabel}: ${displayValue}`);
      }
    }
  }
  detailParts.push(...qualifierVariants);
  const packageSourceLocations = new Set();
  for (const packageSource of [
    dependency && dependency.packageSource,
    ...provenance.map((entry) => entry && entry.packageSource),
  ]) {
    const displayLocation = getDependencyPackageSourceDisplayLocation(packageSource);
    if (displayLocation) packageSourceLocations.add(displayLocation);
  }
  if (packageSourceLocations.size > 0) {
    detailParts.push(`Package source: ${[...packageSourceLocations].join(", ")}`);
  }
  const sources = [...new Set(provenance
    .map((entry) => getDependencyPackageSourceDisplayLocation({
      kind: "path",
      location: entry && entry.source,
    }))
    .filter((display) => display != null))];
  if (sources.length > 0) detailParts.push(`Source: ${sources.join(", ")}`);
  if (dependency && dependency.occurrenceCount > 1) {
    detailParts.push(`${dependency.occurrenceCount} occurrences`);
  }
  const detail = detailParts.length > 0
    ? `<div class="package-detail">${escapeHtml(detailParts.join(" · "))}</div>`
    : "";
  return `<strong>${escapeHtml(dependency && dependency.name || "")}</strong>${detail}`;
}

function formatQualifierLabel(key) {
  const words = String(key || "").replace(/([a-z])([A-Z])/g, "$1 $2");
  return words
    ? `${words[0].toUpperCase()}${words.slice(1).toLowerCase()}`
    : "";
}

function formatScanDate(scanDate) {
  const date = new Date(scanDate);
  if (Number.isNaN(date.getTime())) {
    return "Unknown date";
  }
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "long",
    day: "numeric",
  }).format(date);
}

function formatSeverityBreakdown(summary) {
  const parts = [];
  for (const [key, label] of [
    ["criticalCount", "Critical"],
    ["highCount", "High"],
    ["mediumCount", "Medium"],
    ["lowCount", "Low"],
    ["vulnUnknownCount", "Unknown"],
  ]) {
    const count = normalizeSummaryCount(summary && summary[key]);
    if (count > 0) parts.push(`${count} ${label}`);
  }
  return parts.length > 0 ? parts.join(", ") : "No known vulnerabilities";
}

function formatLicenseBreakdown(licenseIds) {
  if (licenseIds.length === 0) {
    return "No restrictive or weak copyleft licenses";
  }
  return licenseIds.slice(0, 3).join(", ");
}

function formatCoverageLabel(summary) {
  const total = normalizeSummaryCount(summary && summary.total);
  const found = normalizeSummaryCount(summary && summary.found);
  const notApplicable = normalizeSummaryCount(summary && summary.notApplicable);
  const applicable = Math.max(total - notApplicable, 0);
  const coveragePct = clampPercent(summary && summary.coveragePct);
  const label = `${found} of ${applicable} applicable artifacts served by Cloudsmith (${coveragePct}%)`;
  return notApplicable > 0 ? `${label}; ${notApplicable} not applicable` : label;
}

function uniqueLicenseIds(restrictiveLicenseDeps) {
  return [...new Set(
    restrictiveLicenseDeps
      .map((dependency) => dependency.spdx)
      .filter(Boolean)
  )];
}

function clampPercent(value) {
  const number = typeof value === "number" || typeof value === "string"
    ? Number(value)
    : 0;
  return Math.max(0, Math.min(100, Number.isFinite(number) ? number : 0));
}

function displayValue(value) {
  return normalizeDependencyDisplayValue(value) || "—";
}

function normalizeSummaryCount(value) {
  const number = typeof value === "number" || typeof value === "string"
    ? Number(value)
    : 0;
  return Number.isFinite(number) && number > 0 ? Math.floor(number) : 0;
}

function severityClassName(severity) {
  switch (severity) {
    case "Critical":
      return "severity-critical";
    case "High":
      return "severity-high";
    case "Medium":
    case "Low":
      return "severity-medium";
    default:
      return "status-default";
  }
}

function licenseClassName(classification) {
  switch (classification) {
    case "Restrictive":
      return "classification-restrictive";
    case "Weak copyleft":
      return "classification-weak-copyleft";
    default:
      return "classification-default";
  }
}

function policyClassName(status) {
  return status === "Quarantined" ? "status-quarantined" : "status-default";
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

module.exports = {
  ComplianceReportProvider,
  escapeHtml,
};

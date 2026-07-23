// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const vscode = require("vscode");

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

    if ((summary.notFound || 0) > 0) {
      sections.push(renderUncoveredSection(reportData.uncoveredDeps || []));
    }

    const emptyState = sections.length === 0
      ? `
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
  <title>Dependency Health Report</title>
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
      border-left-color: var(--cs-amber);
    }

    .summary-card.vulnerabilities {
      border-left-color: #e67e22;
    }

    .summary-card.licenses {
      border-left-color: var(--cs-red);
    }

    .summary-card.coverage {
      border-left-color: var(--cs-teal);
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

    .report-section[open] > summary {
      border-bottom-color: var(--cs-border);
    }

    .report-section > summary::-webkit-details-marker {
      display: none;
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
      background: rgba(231, 76, 60, 0.14);
      color: #ff8d84;
    }

    .severity-high {
      background: rgba(230, 126, 34, 0.16);
      color: #f1a35a;
    }

    .severity-medium,
    .severity-low,
    .classification-weak-copyleft {
      background: rgba(243, 156, 18, 0.15);
      color: #f7c66d;
    }

    .status-default,
    .classification-default {
      background: rgba(52, 152, 219, 0.13);
      color: #7ebaf2;
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
  </style>
</head>
<body>
  <div class="shell">
    <div class="report-header">
      <h1>Dependency Health Report</h1>
      <p class="subtitle">${escapeHtml(reportData.projectName || "workspace")} · Scanned ${escapeHtml(formatScanDate(reportData.scanDate))}</p>
    </div>

    <div class="summary-grid">
      ${renderSummaryCard("dependencies", summary.total || 0, "Dependencies", `${summary.direct || 0} direct · ${summary.transitive || 0} transitive`)}
      ${renderSummaryCard("vulnerabilities", summary.vulnCount || 0, "Vulnerable", formatSeverityBreakdown(summary))}
      ${renderSummaryCard("licenses", summary.restrictiveLicenseCount || 0, "Restrictive licenses", formatLicenseBreakdown(licenseIds))}
      ${renderSummaryCard("coverage", summary.found || 0, "Cloudsmith coverage", `${summary.coveragePct || 0}% coverage`)}
    </div>

    <div class="card coverage-panel">
      <div>
        <strong>Coverage overview</strong>
      </div>
      <div class="coverage-bar" aria-hidden="true">
        <div class="coverage-fill" style="width: ${clampPercent(summary.coveragePct || 0)}%"></div>
      </div>
      <p class="coverage-label">${escapeHtml(formatCoverageLabel(summary))}</p>
    </div>

    ${emptyState}
    ${sections.join("\n")}
  </div>
</body>
</html>`;
  }
}

function renderSummaryCard(cssClass, value, label, detail) {
  return `
    <div class="summary-card ${cssClass}">
      <div class="summary-value">${escapeHtml(String(value))}</div>
      <div class="summary-label">${escapeHtml(label)}</div>
      <div class="summary-detail">${escapeHtml(detail)}</div>
    </div>
  `;
}

function renderSection(title, bodyHtml) {
  return `
    <details class="report-section" open>
      <summary>${escapeHtml(title)}</summary>
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

  return renderSection("Ecosystem Breakdown", `
    <table>
      <thead>
        <tr>
          <th>Ecosystem</th>
          <th>Dependencies</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `);
}

function renderVulnerabilitySection(vulnerableDeps) {
  const rows = vulnerableDeps.map((dependency) => {
    const severityClass = severityClassName(dependency.maxSeverity);
    return `
      <tr>
        <td>${escapeHtml(dependency.name)}</td>
        <td>${escapeHtml(displayValue(dependency.version))}</td>
        <td>${escapeHtml(dependency.isDirect ? "Direct" : "Transitive")}</td>
        <td><span class="badge ${severityClass}">${escapeHtml(dependency.maxSeverity || "Unknown")}</span></td>
        <td>${escapeHtml(String(dependency.cveCount || 0))}</td>
        <td>${escapeHtml(dependency.hasFixAvailable ? "Yes" : "No")}</td>
      </tr>
    `;
  }).join("");

  return renderSection("Vulnerable Dependencies", `
    <table>
      <thead>
        <tr>
          <th>Package</th>
          <th>Version</th>
          <th>Type</th>
          <th>Severity</th>
          <th>CVE Count</th>
          <th>Fix Available</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `);
}

function renderLicenseSection(restrictiveLicenseDeps) {
  const rows = restrictiveLicenseDeps.map((dependency) => `
    <tr>
      <td>${escapeHtml(dependency.name)}</td>
      <td>${escapeHtml(displayValue(dependency.version))}</td>
      <td>${escapeHtml(displayValue(dependency.spdx))}</td>
      <td><span class="badge ${licenseClassName(dependency.classification)}">${escapeHtml(dependency.classification)}</span></td>
    </tr>
  `).join("");

  return renderSection("License Summary", `
    <table>
      <thead>
        <tr>
          <th>Package</th>
          <th>Version</th>
          <th>SPDX</th>
          <th>Classification</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `);
}

function renderPolicySection(policyViolationDeps) {
  const rows = policyViolationDeps.map((dependency) => `
    <tr>
      <td>${escapeHtml(dependency.name)}</td>
      <td>${escapeHtml(displayValue(dependency.version))}</td>
      <td><span class="badge ${policyClassName(dependency.status)}">${escapeHtml(dependency.status)}</span></td>
      <td>${escapeHtml(displayValue(dependency.detail))}</td>
    </tr>
  `).join("");

  return renderSection("Policy Compliance", `
    <table>
      <thead>
        <tr>
          <th>Package</th>
          <th>Version</th>
          <th>Status</th>
          <th>Detail</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `);
}

function renderUncoveredSection(uncoveredDeps) {
  const reachable = uncoveredDeps.filter((dependency) => dependency.upstreamStatus === "reachable");
  const notReachable = uncoveredDeps.filter((dependency) => dependency.upstreamStatus !== "reachable");
  const groups = [];

  if (reachable.length > 0) {
    groups.push(`
      <div class="section-group">
        <h3>Reachable via upstream proxy</h3>
        <table>
          <thead>
            <tr>
              <th>Package</th>
              <th>Version</th>
              <th>Ecosystem</th>
              <th>Available In</th>
            </tr>
          </thead>
          <tbody>
            ${reachable.map((dependency) => `
              <tr>
                <td>${escapeHtml(dependency.name)}</td>
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
        <table>
          <thead>
            <tr>
              <th>Package</th>
              <th>Version</th>
              <th>Ecosystem</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            ${notReachable.map((dependency) => `
              <tr>
                <td>${escapeHtml(dependency.name)}</td>
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

  return renderSection("Uncovered Dependencies", groups.join(""));
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
  if (summary.criticalCount) {
    parts.push(`${summary.criticalCount} Critical`);
  }
  if (summary.highCount) {
    parts.push(`${summary.highCount} High`);
  }
  if (summary.mediumCount) {
    parts.push(`${summary.mediumCount} Medium`);
  }
  if (summary.lowCount) {
    parts.push(`${summary.lowCount} Low`);
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
  return `${summary.found || 0} of ${summary.total || 0} dependencies served by Cloudsmith (${summary.coveragePct || 0}%)`;
}

function uniqueLicenseIds(restrictiveLicenseDeps) {
  return [...new Set(
    restrictiveLicenseDeps
      .map((dependency) => dependency.spdx)
      .filter(Boolean)
  )];
}

function clampPercent(value) {
  return Math.max(0, Math.min(100, Number(value) || 0));
}

function displayValue(value) {
  return value || "—";
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

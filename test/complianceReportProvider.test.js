const assert = require("assert");
const vscode = require("vscode");
const { ComplianceReportProvider } = require("../views/complianceReportProvider");
const { buildComplianceReportData } = require("../views/dependencyHealthProvider");

suite("ComplianceReportProvider", () => {
  test("report data and HTML escape dynamic content", () => {
    const dependencies = [
      {
        name: "evil<script>alert(1)</script>'\"",
        version: "1.0.0'\"",
        format: "npm",
        ecosystem: "npm",
        isDirect: true,
        cloudsmithStatus: "FOUND",
        cloudsmithPackage: {
          repository: "prod",
          status_str: "Completed",
          license: "MIT",
        },
        vulnerabilities: {
          count: 2,
          maxSeverity: "High",
          severityCounts: { High: 2 },
          hasFixAvailable: true,
          entries: [{ fixVersion: "1.0.1" }],
          detailsLoaded: true,
        },
      },
      {
        name: "license-risk",
        version: "2.0.0",
        format: "npm",
        ecosystem: "npm",
        isDirect: false,
        cloudsmithStatus: "FOUND",
        cloudsmithPackage: {
          repository: "prod",
          status_str: "Completed",
          license: "GPL-3.0",
        },
        license: {
          display: "GPL-3.0",
          spdx: "GPL-3.0",
          classification: "restrictive",
        },
      },
      {
        name: "policy-fail",
        version: "3.0.0",
        format: "pypi",
        ecosystem: "pypi",
        isDirect: true,
        cloudsmithStatus: "FOUND",
        cloudsmithPackage: {
          repository: "prod",
          status_str: "Quarantined",
        },
        policy: {
          violated: true,
          denied: true,
          quarantined: true,
          status: "Quarantined",
          statusReason: "Blocked by policy <rule>",
        },
      },
      {
        name: "missing-lib",
        version: "0.1.0",
        format: "npm",
        ecosystem: "npm",
        isDirect: true,
        cloudsmithStatus: "NOT_FOUND",
        upstreamStatus: "reachable",
        upstreamDetail: "proxy <prod>",
      },
      {
        name: "missing-lib",
        version: "0.1.0",
        format: "npm",
        ecosystem: "npm",
        isDirect: false,
        cloudsmithStatus: "NOT_FOUND",
        upstreamStatus: "reachable",
        upstreamDetail: "proxy <prod>",
      },
    ];

    const reportData = buildComplianceReportData("fixture <app>", dependencies, {
      scanDate: "2026-04-05T12:30:00Z",
    });

    assert.strictEqual(reportData.summary.total, 4);
    assert.strictEqual(reportData.summary.found, 3);
    assert.strictEqual(reportData.summary.notFound, 1);
    assert.strictEqual(reportData.summary.coveragePct, 75);
    assert.strictEqual(reportData.summary.vulnCount, 1);
    assert.strictEqual(reportData.summary.restrictiveLicenseCount, 1);
    assert.strictEqual(reportData.summary.policyViolationCount, 1);

    const provider = new ComplianceReportProvider({});
    const html = provider._getHtml(reportData);

    assert.match(html, /fixture &lt;app&gt;/);
    assert.match(html, /evil&lt;script&gt;alert\(1\)&lt;\/script&gt;&#39;&quot;/);
    assert.match(html, /1\.0\.0&#39;&quot;/);
    assert.match(html, /proxy &lt;prod&gt;/);
    assert.match(html, /Blocked by policy &lt;rule&gt;/);
    assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
    assert.match(html, /Vulnerable Dependencies/);
    assert.match(html, /License Summary/);
    assert.match(html, /Policy Compliance/);
    assert.match(html, /Uncovered Dependencies/);
    assert.match(html, /Ecosystem Breakdown/);
  });

  test("show creates a static webview with no local resource access", () => {
    const originalCreateWebviewPanel = vscode.window.createWebviewPanel;
    let capturedOptions = null;

    vscode.window.createWebviewPanel = (_viewType, _title, _column, options) => {
      capturedOptions = options;
      return {
        webview: { html: "" },
        onDidDispose() {
          return { dispose() {} };
        },
        reveal() {},
        dispose() {},
      };
    };

    try {
      const provider = new ComplianceReportProvider({});
      provider.show({
        projectName: "fixture",
        summary: {
          notFound: 0,
        },
      });

      assert.deepStrictEqual(capturedOptions, {
        enableScripts: false,
        localResourceRoots: [],
      });
    } finally {
      vscode.window.createWebviewPanel = originalCreateWebviewPanel;
    }
  });
});

const assert = require("assert");
const vscode = require("vscode");
const { ComplianceReportProvider } = require("../views/complianceReportProvider");
const { buildComplianceReportData } = require("../views/dependencyHealthProvider");
const { assertWebviewDocument } = require("./helpers/webviewSemanticContract");

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

    assert.strictEqual(reportData.summary.total, 5);
    assert.strictEqual(reportData.summary.occurrences, 5);
    assert.strictEqual(reportData.summary.found, 3);
    assert.strictEqual(reportData.summary.notFound, 2);
    assert.strictEqual(reportData.summary.coveragePct, 60);
    assert.strictEqual(reportData.summary.vulnCount, 1);
    assert.strictEqual(reportData.summary.restrictiveLicenseCount, 1);
    assert.strictEqual(reportData.summary.policyViolationCount, 1);

    const provider = new ComplianceReportProvider({});
    const html = provider._getHtml(reportData);
    assertWebviewDocument(html, { interactive: true, tables: true });

    assert.match(html, /fixture &lt;app&gt;/);
    assert.match(html, /evil&lt;script&gt;alert\(1\)&lt;\/script&gt;&#39;&quot;/);
    assert.match(html, /1\.0\.0&#39;&quot;/);
    assert.match(html, /proxy &lt;prod&gt;/);
    assert.match(html, /Blocked by policy &lt;rule&gt;/);
    assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
    assert.match(html, /Vulnerability findings/);
    assert.match(html, /License summary/);
    assert.match(html, /Policy compliance/);
    assert.match(html, /Uncovered dependencies/);
    assert.match(html, /Ecosystem breakdown/);
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

  test("renders unknown vulnerability totals without manufacturing zero CVEs", () => {
    const reportData = buildComplianceReportData("fixture", [{
      name: "unknown-package",
      version: "1.0.0",
      format: "npm",
      isDirect: true,
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: { num_vulnerabilities: "0x10" },
    }]);
    assert.strictEqual(reportData.summary.vulnCount, 0);
    assert.strictEqual(reportData.summary.vulnUnknownCount, 1);
    assert.strictEqual(reportData.vulnerableDeps[0].cveCount, null);
    assert.strictEqual(reportData.vulnerableDeps[0].vulnerabilityStatus, "Unknown");

    const provider = new ComplianceReportProvider({});
    const html = provider._getHtml(reportData);

    assert.match(html, /CVE count \/ status/);
    assert.match(html, />Unknown<\/td>/);
    assert.match(html, /1 Unknown/);
    assert.doesNotMatch(html, /unknown-package[\s\S]*?<td>0<\/td>/);
  });

  test("does not render an incomplete lookup set as clean or unreachable", () => {
    const provider = new ComplianceReportProvider({});
    const incompleteHtml = provider._getHtml({
      projectName: "fixture",
      summary: { lookupIncomplete: 2 },
    });
    assert.match(incompleteHtml, /Compliance status incomplete/);
    assert.doesNotMatch(incompleteHtml, /No compliance issues detected/);

    const upstreamHtml = provider._getHtml({
      projectName: "fixture",
      summary: { notFound: 1 },
      uncoveredDeps: [{
        name: "unknown-package",
        version: "1.0.0",
        ecosystem: "npm",
        upstreamStatus: "unknown",
        upstreamDetail: "Inspection incomplete",
      }],
    });
    assert.match(upstreamHtml, /Reachability unknown/);
    assert.doesNotMatch(upstreamHtml, /<h3>Not reachable<\/h3>/);
  });

  test("coverage label omits missing and zero not-applicable counts", () => {
    const provider = new ComplianceReportProvider({});
    for (const summary of [
      { total: 5, found: 3, coveragePct: 60 },
      { total: 5, found: 3, coveragePct: 60, notApplicable: 0 },
    ]) {
      const html = provider._getHtml({ projectName: "fixture", summary });
      assert.match(
        html,
        /3 of 5 applicable artifacts served by Cloudsmith \(60%\)/
      );
      assert.doesNotMatch(html, /0 not applicable/);
      assert.doesNotMatch(html, /Registry lookup not applicable/);
    }
  });

  test("coverage label and section retain positive not-applicable context", () => {
    const dependencies = [
      ...["one", "two", "three"].map((name) => ({
        name,
        version: "1.0.0",
        format: "npm",
        ecosystem: "npm",
        cloudsmithStatus: "FOUND",
        packageSource: { kind: "registry" },
        qualifiers: {},
      })),
      {
        name: "missing",
        version: "1.0.0",
        format: "npm",
        ecosystem: "npm",
        cloudsmithStatus: "NOT_FOUND",
        packageSource: { kind: "registry" },
        qualifiers: {},
      },
      {
        name: "local-package",
        version: "1.0.0",
        format: "npm",
        ecosystem: "npm",
        cloudsmithStatus: "NOT_APPLICABLE",
        cloudsmithLookupDetail: "Path dependency; Cloudsmith package lookup is not applicable.",
        packageSource: { kind: "path", location: "/Users/private-user/libs/local-package" },
        qualifiers: {},
      },
    ];
    const reportData = buildComplianceReportData("fixture", dependencies);
    const html = new ComplianceReportProvider({})._getHtml(reportData);

    assert.strictEqual(reportData.summary.total, 5);
    assert.strictEqual(reportData.summary.notApplicable, 1);
    assert.strictEqual(reportData.summary.coveragePct, 75);
    assert.match(
      html,
      /3 of 4 applicable artifacts served by Cloudsmith \(75%\); 1 not applicable/
    );
    assert.strictEqual((html.match(/1 not applicable/g) || []).length, 1);
    assert.match(html, /<summary><h2>Registry lookup not applicable<\/h2><\/summary>/);
    assert.match(html, /local-package/);
    assert.match(html, />path<\/td>/);
    assert.doesNotMatch(html, /private-user|\/Users\//);
  });

  test("coverage remains truthful when every artifact is not applicable", () => {
    const dependencies = Array.from({ length: 5 }, (_value, index) => ({
      name: `local-${index}`,
      version: "1.0.0",
      format: "npm",
      ecosystem: "npm",
      cloudsmithStatus: "NOT_APPLICABLE",
      packageSource: { kind: "path", location: `../local-${index}` },
      qualifiers: {},
    }));
    const reportData = buildComplianceReportData("fixture", dependencies);
    const html = new ComplianceReportProvider({})._getHtml(reportData);

    assert.strictEqual(reportData.summary.coveragePct, 0);
    assert.match(
      html,
      /0 of 0 applicable artifacts served by Cloudsmith \(0%\); 5 not applicable/
    );
    assert.match(html, /<summary><h2>Registry lookup not applicable<\/h2><\/summary>/);
  });

  test("malformed optional summary values do not leak into report copy", () => {
    const html = new ComplianceReportProvider({})._getHtml({
      projectName: "fixture",
      summary: {
        total: 5,
        found: 3,
        coveragePct: 60,
        vulnCount: { unsafe: true },
        restrictiveLicenseCount: { unsafe: true },
        criticalCount: { unsafe: true },
        highCount: "0",
        mediumCount: undefined,
      },
    });

    assert.match(html, /3 of 5 applicable artifacts served by Cloudsmith \(60%\)/);
    assert.match(html, /No known vulnerabilities/);
    assert.doesNotMatch(html, /\[object Object\]|undefined|0 Critical|0 High/);
  });

  test("report provenance does not expose source credentials or absolute paths", () => {
    const reportData = buildComplianceReportData("fixture", [{
      name: "local-package",
      version: "1.0.0",
      format: "maven",
      ecosystem: "maven",
      isDirect: true,
      cloudsmithStatus: "NOT_APPLICABLE",
      cloudsmithLookupDetail: "Local dependency",
      lookupEligibility: { state: "not-applicable", reason: "path-source" },
      packageSource: {
        kind: "path",
        location: "/Users/private-user/workspace/libs/local-package.jar",
      },
      sourceFile: "/Users/private-user/workspace/pom.xml",
      qualifiers: {
        repository: "https://user:secret@example.com/index?token=hidden#private",
        classifier: undefined,
        scope: { unsafe: "raw-object" },
      },
    }]);

    const html = new ComplianceReportProvider({})._getHtml(reportData);
    assert.match(html, /Package source: local-package\.jar/);
    assert.match(html, /Repository: https:\/\/example\.com\/index/);
    assert.match(html, /Source: pom\.xml/);
    assert.doesNotMatch(
      html,
      /private-user|\/Users\/|user:secret|token=|#private|null|undefined|\[object Object\]|raw-object/
    );
  });
});

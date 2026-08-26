const assert = require("assert");
const vscode = require("vscode");
const {
  ComplianceReportProvider,
  MAX_INLINE_COMPLIANCE_DETAIL,
  MAX_INLINE_COMPLIANCE_PRIMARY,
} = require("../views/complianceReportProvider");
const { buildComplianceReportData } = require("../views/dependencyHealthProvider");
const { assertWebviewDocument } = require("./helpers/webviewSemanticContract");

suite("ComplianceReportProvider", () => {
  test("bounds repeated compliance row content without omitting records", () => {
    assert.strictEqual(MAX_INLINE_COMPLIANCE_PRIMARY, 320);
    assert.strictEqual(MAX_INLINE_COMPLIANCE_DETAIL, 512);
    const provider = new ComplianceReportProvider({});
    const recordCount = 10;
    const makeRows = multiplier => Array.from({ length: recordCount }, (_, index) => ({
      name: `policy-${index}-${"N".repeat(MAX_INLINE_COMPLIANCE_PRIMARY * multiplier)} NAME-TAIL-${index}`,
      version: `1.${index}.0`,
      status: "Quarantined",
      detail: `Policy ${index} ${"\"&<>'".repeat(MAX_INLINE_COMPLIANCE_DETAIL * multiplier)} DETAIL-TAIL-${index}`,
    }));
    const render = policyViolationDeps => provider._getHtml({
      projectName: "fixture",
      summary: {
        total: policyViolationDeps.length,
        found: policyViolationDeps.length,
        policyViolationCount: policyViolationDeps.length,
      },
      policyViolationDeps,
    });
    const rows = makeRows(2);
    const html = render(rows);
    const longerHtml = render(makeRows(3));
    const emptyShell = render([]);
    const expectedUpperEnvelope = emptyShell.length + recordCount * (
      6 * (MAX_INLINE_COMPLIANCE_PRIMARY + MAX_INLINE_COMPLIANCE_DETAIL) + 1200
    );

    assert.strictEqual(html.length, longerHtml.length, "canonical tails must not affect report HTML size");
    assert.ok(html.length <= expectedUpperEnvelope, `${html.length} exceeds ${expectedUpperEnvelope}`);
    assert.ok(rows[0].detail.length > MAX_INLINE_COMPLIANCE_DETAIL);
    assert.match(html, /Policy 0 [^<]+…/);
    assert.doesNotMatch(html, /<script|DETAIL-TAIL|NAME-TAIL/);
    for (let index = 0; index < recordCount; index += 1) {
      assert.match(html, new RegExp(`policy-${index}-`));
      assert.match(html, new RegExp(`1\\.${index}\\.0`));
    }
  });

  test("bounds derived provenance without dropping collectively long detail", () => {
    const provider = new ComplianceReportProvider({});
    const provenance = Array.from({ length: 10 }, (_, index) => ({
      source: `https://example.com/${"S".repeat(1200)}-${index}`,
    }));
    const html = provider._getHtml({
      projectName: "fixture",
      summary: { total: 1, found: 1, vulnCount: 1 },
      vulnerableDeps: [{
        name: "derived-provenance",
        version: "1.0.0",
        maxSeverity: "High",
        cveCount: 1,
        provenance,
      }],
    });

    assert.match(html, /<div class="package-detail">Source: [^<]+…<\/div>/);
    assert.doesNotMatch(html, /-9/);
  });

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
    assert.match(html, /1 status unavailable/);
    assert.doesNotMatch(html, /unknown-package[\s\S]*?<td>0<\/td>/);
  });

  test("positive vulnerability indicators never render false-clean compliance copy", () => {
    const reportData = buildComplianceReportData("fixture", Array.from(
      { length: 4 },
      (_value, index) => ({
        name: `vulnerable-${index}`,
        version: "1.0.0",
        format: "npm",
        isDirect: index === 0,
        cloudsmithStatus: "FOUND",
        cloudsmithPackage: { repository: "prod", status_str: "Completed" },
        vulnerabilities: {
          count: 1,
          countKnown: true,
          countAuthoritative: true,
          detected: true,
          unknown: false,
          detailsLoaded: false,
          maxSeverity: null,
          entries: [],
        },
      })
    ));

    assert.strictEqual(reportData.summary.vulnCount, 4);
    assert.strictEqual(reportData.summary.vulnDetectedUnknownSeverityCount, 4);
    assert.strictEqual(reportData.summary.vulnIncompleteCount, 4);
    assert.strictEqual(reportData.summary.vulnerabilityCoverageComplete, false);
    assert.strictEqual(reportData.vulnerableDeps.length, 4);
    assert.ok(reportData.vulnerableDeps.every(row => row.vulnerabilityStatus === "Detected"));
    assert.ok(reportData.vulnerableDeps.every(row => (
      row.fixAvailability === "unknown" && row.hasFixAvailable === null
    )));

    const html = new ComplianceReportProvider({})._getHtml(reportData);
    assert.match(html, /4 severity unknown/);
    assert.doesNotMatch(html, /No known vulnerabilities/);
  });

  test("a contradictory complete-clean detail state cannot erase a positive indicator", () => {
    const reportData = buildComplianceReportData("fixture", [{
      name: "contradictory-package",
      version: "1.0.0",
      format: "npm",
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: { repository: "prod", status_str: "Completed" },
      vulnerabilities: {
        count: 1,
        countKnown: true,
        countAuthoritative: true,
        detected: true,
        unknown: false,
        detailsLoaded: false,
        entries: [],
      },
    }], {
      vulnerabilityStateFor: () => ({
        status: "complete-clean",
        complete: true,
        stale: false,
        count: 0,
        records: [],
      }),
    });

    assert.strictEqual(reportData.summary.vulnCount, 1);
    assert.strictEqual(reportData.summary.vulnerabilityCoverageComplete, false);
    assert.strictEqual(reportData.vulnerableDeps[0].vulnerabilityStatus, "Detected");
    assert.doesNotMatch(
      new ComplianceReportProvider({})._getHtml(reportData),
      /No known vulnerabilities|No compliance issues detected/
    );
  });

  test("canonical vulnerability detail drives compliance severity, count, and fix parity", () => {
    const reportData = buildComplianceReportData("fixture", [{
      name: "js-yaml",
      version: "3.14.2",
      format: "npm",
      isDirect: false,
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: { repository: "prod", status_str: "Completed" },
      vulnerabilities: {
        count: 1,
        countKnown: true,
        detected: true,
        detailsLoaded: false,
      },
    }], {
      vulnerabilityStateFor: () => Object.freeze({
        status: "complete-vulnerable",
        complete: true,
        stale: false,
        count: 1,
        maxSeverity: "Medium",
        records: Object.freeze([Object.freeze({
          vulnerability_id: "CVE-2026-53550",
          severity: "Medium",
          fixed_version: Object.freeze({ version: "4.2.0" }),
        })]),
      }),
    });

    assert.strictEqual(reportData.summary.vulnCount, 1);
    assert.strictEqual(reportData.summary.mediumCount, 1);
    assert.strictEqual(reportData.summary.vulnIncompleteCount, 0);
    assert.strictEqual(reportData.summary.vulnerabilityCoverageComplete, true);
    assert.deepStrictEqual(reportData.vulnerableDeps.map(row => ({
      maxSeverity: row.maxSeverity,
      cveCount: row.cveCount,
      hasFixAvailable: row.hasFixAvailable,
    })), [{ maxSeverity: "Medium", cveCount: 1, hasFixAvailable: true }]);

    const html = new ComplianceReportProvider({})._getHtml(reportData);
    assert.match(html, /1 Medium/);
    assert.doesNotMatch(html, /No known vulnerabilities/);
  });

  test("global clean copy requires explicit complete-clean evidence", () => {
    const dependency = {
      name: "clean-package",
      version: "1.0.0",
      format: "npm",
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: { repository: "prod", status_str: "Completed" },
      vulnerabilities: {
        count: 0,
        countKnown: true,
        countAuthoritative: true,
        detected: false,
        unknown: false,
        detailsLoaded: false,
      },
    };
    const complete = buildComplianceReportData("fixture", [dependency], {
      vulnerabilityStateFor: () => ({
        status: "complete-clean",
        complete: true,
        stale: false,
        count: 0,
        records: [],
      }),
    });
    const unknown = buildComplianceReportData("fixture", [{
      ...dependency,
      vulnerabilities: {
        count: 0,
        countKnown: false,
        countAuthoritative: false,
        detected: false,
        unknown: true,
        detailsLoaded: false,
      },
    }], {
      vulnerabilityStateFor: () => ({
        status: "unknown",
        complete: false,
        stale: false,
        count: null,
        detected: false,
        records: [],
      }),
    });
    const contradictoryUnknown = buildComplianceReportData("fixture", [dependency], {
      vulnerabilityStateFor: () => ({
        status: "unknown",
        complete: false,
        stale: false,
        count: null,
        detected: false,
        records: [],
      }),
    });

    assert.strictEqual(complete.summary.vulnerabilityCoverageComplete, true);
    assert.match(new ComplianceReportProvider({})._getHtml(complete), /No known vulnerabilities/);
    assert.strictEqual(unknown.summary.vulnerabilityCoverageComplete, false);
    assert.doesNotMatch(
      new ComplianceReportProvider({})._getHtml(unknown),
      /No known vulnerabilities|No compliance issues detected/
    );
    assert.strictEqual(contradictoryUnknown.summary.vulnerabilityCoverageComplete, false);
    assert.doesNotMatch(
      new ComplianceReportProvider({})._getHtml(contradictoryUnknown),
      /No known vulnerabilities|No compliance issues detected/
    );
  });

  test("global vulnerability coverage requires every applicable lookup to be found", () => {
    const reportData = buildComplianceReportData("fixture", [
      {
        name: "clean-npm",
        version: "1.0.0",
        format: "npm",
        cloudsmithStatus: "FOUND",
        cloudsmithPackage: { repository: "prod", status_str: "Completed" },
        vulnerabilities: {
          count: 0,
          countKnown: true,
          countAuthoritative: true,
          detected: false,
          unknown: false,
          detailsLoaded: false,
        },
      },
      {
        name: "failed-python",
        version: "2.0.0",
        format: "python",
        cloudsmithStatus: "LOOKUP_FAILED",
      },
    ], {
      vulnerabilityStateFor: dependency => dependency.cloudsmithStatus === "FOUND"
        ? {
          status: "complete-clean",
          complete: true,
          stale: false,
          count: 0,
          records: [],
        }
        : null,
    });

    assert.strictEqual(reportData.summary.found, 1);
    assert.strictEqual(reportData.summary.lookupFailed, 1);
    assert.strictEqual(reportData.summary.vulnerabilityCoverageComplete, false);
    const html = new ComplianceReportProvider({})._getHtml(reportData);
    assert.match(html, /Compliance status incomplete/);
    assert.doesNotMatch(
      html,
      /No known vulnerabilities|No compliance issues detected/
    );
  });

  test("mixed complete, partial, failed, and unknown vulnerability states stay distinct", () => {
    const dependencies = [
      ["complete-no-fix", "1.0.0"],
      ["partial-with-fix", "2.0.0"],
      ["failed-scan", "3.0.0"],
      ["unknown-scan", "4.0.0"],
    ].map(([name, version]) => ({
      name,
      version,
      format: "npm",
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: { repository: "prod", status_str: "Completed" },
      vulnerabilities: {
        detected: false,
        count: null,
        countKnown: false,
        countAuthoritative: false,
        unknown: true,
        detailsLoaded: false,
      },
    }));
    const states = new Map([
      ["complete-no-fix", {
        status: "complete-vulnerable",
        complete: true,
        stale: false,
        count: 2,
        records: [
          { vulnerability_id: "CVE-2026-1", severity: "Critical" },
          { vulnerability_id: "CVE-2026-2", severity: "High" },
        ],
      }],
      ["partial-with-fix", {
        status: "partial",
        complete: false,
        stale: false,
        detected: true,
        reportedCount: 2,
        records: [{
          vulnerability_id: "CVE-2026-3",
          severity: "Medium",
          fixed_version: { version: "2.1.0" },
        }],
      }],
      ["failed-scan", {
        status: "failed",
        complete: false,
        stale: false,
        detected: false,
        records: [],
      }],
      ["unknown-scan", {
        status: "unknown",
        complete: false,
        stale: false,
        detected: false,
        records: [],
      }],
    ]);

    const reportData = buildComplianceReportData("fixture", dependencies, {
      vulnerabilityStateFor: dependency => states.get(dependency.name),
    });

    assert.strictEqual(reportData.summary.vulnerabilityCoverageComplete, false);
    assert.deepStrictEqual({
      vulnCount: reportData.summary.vulnCount,
      vulnUnknownCount: reportData.summary.vulnUnknownCount,
      vulnDetectedUnknownSeverityCount:
        reportData.summary.vulnDetectedUnknownSeverityCount,
      vulnIncompleteCount: reportData.summary.vulnIncompleteCount,
      criticalCount: reportData.summary.criticalCount,
      highCount: reportData.summary.highCount,
      mediumCount: reportData.summary.mediumCount,
      lowCount: reportData.summary.lowCount,
    }, {
      vulnCount: 2,
      vulnUnknownCount: 2,
      vulnDetectedUnknownSeverityCount: 0,
      vulnIncompleteCount: 3,
      criticalCount: 1,
      highCount: 0,
      mediumCount: 1,
      lowCount: 0,
    });
    assert.deepStrictEqual(reportData.vulnerableDeps.map(row => ({
      name: row.name,
      state: row.vulnerabilityState,
      severity: row.maxSeverity,
      fixAvailability: row.fixAvailability,
      hasFixAvailable: row.hasFixAvailable,
    })), [
      {
        name: "complete-no-fix",
        state: "complete-vulnerable",
        severity: "Critical",
        fixAvailability: "no",
        hasFixAvailable: false,
      },
      {
        name: "partial-with-fix",
        state: "partial",
        severity: "Medium",
        fixAvailability: "yes",
        hasFixAvailable: true,
      },
      {
        name: "failed-scan",
        state: "failed",
        severity: null,
        fixAvailability: "unknown",
        hasFixAvailable: null,
      },
      {
        name: "unknown-scan",
        state: "unknown",
        severity: null,
        fixAvailability: "unknown",
        hasFixAvailable: null,
      },
    ]);
    const html = new ComplianceReportProvider({})._getHtml(reportData);
    assert.match(html, /Dependency vulnerability status/);
    const vulnerabilityRow = name => {
      const fragment = html.split("<tr>").find(row => (
        row.includes(`<strong>${name}</strong>`)
      ));
      assert(fragment, name);
      return fragment.split("</tr>")[0];
    };
    assert.match(
      vulnerabilityRow("complete-no-fix"),
      /<span class="badge severity-critical">Critical<\/span>[\s\S]*<td>2<\/td>[\s\S]*<td>No<\/td>/u
    );
    assert.match(
      vulnerabilityRow("partial-with-fix"),
      /<span class="badge severity-medium">Medium<\/span>[\s\S]*<td>2<\/td>[\s\S]*<td>Yes<\/td>/u
    );
    for (const name of ["failed-scan", "unknown-scan"]) {
      assert.match(
        vulnerabilityRow(name),
        /<span class="badge status-default">Unknown<\/span>[\s\S]*<td>Unknown<\/td>[\s\S]*<td>Unknown<\/td>/u
      );
    }
    assert.match(
      html,
      /<div class="summary-card vulnerabilities"[\s\S]*?<div class="summary-value">2<\/div>[\s\S]*?<div class="summary-label">Vulnerable<\/div>[\s\S]*?<div class="summary-detail">1 Critical, 1 Medium, 2 status unavailable<\/div>/u
    );
    assert.doesNotMatch(html, /Dependencies with known vulnerabilities/);
  });

  test("zero vulnerability evidence cannot establish a clean compliance result", () => {
    const reportData = buildComplianceReportData("fixture", []);

    assert.strictEqual(reportData.summary.vulnerabilityCoverageComplete, false);
    const html = new ComplianceReportProvider({})._getHtml(reportData);
    assert.match(html, /Compliance status unavailable/);
    assert.doesNotMatch(html, /No known vulnerabilities|No compliance issues detected/);
  });

  test("zero count without explicit authority cannot establish clean coverage", () => {
    const reportData = buildComplianceReportData("fixture", [{
      name: "authority-unknown",
      version: "1.0.0",
      format: "npm",
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: { repository: "prod", status_str: "Completed" },
      vulnerabilities: {
        count: 0,
        countKnown: true,
        detected: false,
        unknown: false,
        detailsLoaded: false,
      },
    }]);

    assert.strictEqual(reportData.summary.vulnerabilityCoverageComplete, false);
    assert.strictEqual(reportData.vulnerableDeps[0].vulnerabilityStatus, "Unknown");
    assert.doesNotMatch(
      new ComplianceReportProvider({})._getHtml(reportData),
      /No known vulnerabilities|No compliance issues detected/
    );
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

  test("lookup-incomplete notice renders alongside unrelated report sections", () => {
    const html = new ComplianceReportProvider({})._getHtml({
      projectName: "fixture",
      summary: {
        total: 2,
        found: 1,
        lookupFailed: 1,
        restrictiveLicenseCount: 1,
        vulnerabilityCoverageComplete: false,
      },
      restrictiveLicenseDeps: [{
        name: "licensed-package",
        version: "1.0.0",
        spdx: "GPL-3.0-only",
        classification: "Restrictive",
      }],
    });

    assert.match(html, /Compliance status incomplete/);
    assert.match(html, /License summary/);
    assert.doesNotMatch(html, /No known vulnerabilities|No compliance issues detected/);
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
    assert.match(html, /Vulnerability status unavailable/);
    assert.doesNotMatch(html, /No known vulnerabilities|No compliance issues detected/);
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

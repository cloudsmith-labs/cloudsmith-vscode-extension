const assert = require("assert");
const {
  fetchPackageVulnerabilities,
  getPackageVulnerabilityCount,
} = require("../util/packageVulnerabilities");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");

suite("Package vulnerability scan collection", () => {
  function page(data, pageNumber, pageTotal, count) {
    return apiSuccess(data, {
      headers: {
        "x-pagination-page": String(pageNumber),
        "x-pagination-pagetotal": String(pageTotal),
        "x-pagination-pagesize": "100",
        "x-pagination-count": String(count),
      },
    });
  }

  function scan(index, createdAt) {
    return {
      identifier: `scan-${index}`,
      created_at: createdAt,
      has_vulnerabilities: true,
      num_vulnerabilities: 1,
      max_severity: "High",
    };
  }

  test("selects the latest scan only after later pages prove collection completeness", async () => {
    const firstPage = Array.from(
      { length: 100 },
      (_, index) => scan(index, "2026-01-01T00:00:00Z")
    );
    const calls = [];
    const api = {
      async get(endpoint) {
        calls.push(endpoint);
        if (endpoint.includes("?page=1")) return page(firstPage, 1, 2, 101);
        if (endpoint.includes("?page=2")) {
          return page([scan(100, "2026-02-01T00:00:00Z")], 2, 2, 101);
        }
        assert.ok(endpoint.endsWith("scan-100/"));
        return apiSuccess({
          scan: { results: [{ vulnerability_id: "CVE-2026-1000", severity: "High" }] },
        });
      },
    };

    const result = await fetchPackageVulnerabilities(
      api,
      "workspace-a",
      "repo-a",
      "package-a",
      1
    );

    assert.strictEqual(result.complete, true);
    assert.deepStrictEqual(result.results.map(item => item.vulnerability_id), ["CVE-2026-1000"]);
    assert.strictEqual(calls.length, 3);
  });

  test("does not publish an older scan as current when a later page fails", async () => {
    const firstPage = Array.from(
      { length: 100 },
      (_, index) => scan(index, "2026-01-01T00:00:00Z")
    );
    const api = {
      async get(endpoint) {
        if (endpoint.includes("?page=1")) return page(firstPage, 1, 2, 101);
        if (endpoint.includes("?page=2")) {
          return apiFailure("rate_limited", { status: 429, retryable: true });
        }
        throw new Error("scan detail must not be requested from partial history");
      },
    };

    const result = await fetchPackageVulnerabilities(
      api,
      "workspace-a",
      "repo-a",
      "package-a",
      1
    );

    assert.strictEqual(result.complete, false);
    assert.deepStrictEqual(result.results, []);
    assert.strictEqual(result.error.kind, "rate_limited");
  });

  test("rejects oversized identifiers and ambiguous complete scan histories", async () => {
    const oversized = await fetchPackageVulnerabilities({
      async get(_endpoint, options) {
        const data = [{ identifier: "x".repeat(513), has_vulnerabilities: true }];
        assert.strictEqual(options.validate(data), false);
        return apiFailure("invalid_response", { status: 200 });
      },
    }, "workspace-a", "repo-a", "package-a", 1);
    assert.strictEqual(oversized.error.kind, "invalid_response");

    const ambiguous = await fetchPackageVulnerabilities({
      async get(endpoint) {
        if (endpoint.includes("?page=1")) {
          return page([
            { identifier: "scan-a", has_vulnerabilities: true },
            { identifier: "scan-b", has_vulnerabilities: true },
          ], 1, 1, 2);
        }
        throw new Error("an ambiguous scan history must not select a detail endpoint");
      },
    }, "workspace-a", "repo-a", "package-a", 1);
    assert.strictEqual(ambiguous.complete, false);
    assert.strictEqual(ambiguous.error.kind, "invalid_response");
  });

  test("keeps bounded successful details partial when they contradict the scan count", async () => {
    const api = {
      async get(endpoint) {
        if (endpoint.includes("?page=1")) {
          return page([{
            identifier: "scan-a",
            created_at: "2026-02-01T00:00:00Z",
            has_vulnerabilities: true,
            num_vulnerabilities: 2,
            max_severity: "High",
          }], 1, 1, 1);
        }
        return apiSuccess({
          results: [{ vulnerability_id: "CVE-1", severity: "High" }],
        });
      },
    };

    const result = await fetchPackageVulnerabilities(
      api,
      "workspace-a",
      "repo-a",
      "package-a",
      2
    );

    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.partial, true);
    assert.strictEqual(result.numVulns, -1);
    assert.deepStrictEqual(result.results.map(item => item.vulnerability_id), ["CVE-1"]);
    assert.strictEqual(result.error.kind, "invalid_response");
  });

  test("rejects vulnerability detail arrays beyond the structural item cap", async () => {
    const api = {
      async get(endpoint) {
        if (endpoint.includes("?page=1")) {
          return page([{
            identifier: "scan-a",
            created_at: "2026-02-01T00:00:00Z",
            has_vulnerabilities: true,
          }], 1, 1, 1);
        }
        return apiSuccess({
          results: Array.from(
            { length: 5001 },
            (_value, index) => ({ vulnerability_id: `CVE-${index}`, severity: "Low" })
          ),
        });
      },
    };

    const result = await fetchPackageVulnerabilities(
      api,
      "workspace-a",
      "repo-a",
      "package-a",
      1
    );

    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.partial, false);
    assert.deepStrictEqual(result.results, []);
    assert.strictEqual(result.error.kind, "invalid_response");
  });

  test("rejects nested vulnerability arrays whose aggregate exceeds the item cap", async () => {
    const nested = {
      scans: [0, 2501].map((offset) => ({
        results: Array.from(
          { length: 2501 },
          (_value, index) => ({ vulnerability_id: `CVE-${offset + index}`, severity: "Low" })
        ),
      })),
    };
    const result = await fetchPackageVulnerabilities({
      async get(endpoint, options) {
        if (endpoint.includes("?page=1")) {
          return page([{
            identifier: "scan-a",
            created_at: "2026-02-01T00:00:00Z",
            has_vulnerabilities: true,
          }], 1, 1, 1);
        }
        assert.strictEqual(options.validate(nested), false);
        return apiSuccess(nested);
      },
    }, "workspace-a", "repo-a", "package-a", 1);

    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.partial, false);
    assert.deepStrictEqual(result.results, []);
    assert.strictEqual(result.error.kind, "invalid_response");
  });

  test("rejects duplicate and conflicting vulnerability identities", async () => {
    for (const results of [
      [
        { vulnerability_id: "CVE-1", severity: "High" },
        { vulnerability_id: "cve-1", severity: "Low" },
      ],
      [{ vulnerability_id: "CVE-1", identifier: "CVE-2", severity: "High" }],
    ]) {
      const result = await fetchPackageVulnerabilities({
        async get(endpoint) {
          if (endpoint.includes("?page=1")) {
            return page([{
              identifier: "scan-a",
              created_at: "2026-02-01T00:00:00Z",
              has_vulnerabilities: true,
              num_vulnerabilities: results.length,
            }], 1, 1, 1);
          }
          return apiSuccess({ results });
        },
      }, "workspace-a", "repo-a", "package-a", results.length);

      assert.strictEqual(result.complete, false);
      assert.strictEqual(result.partial, false);
      assert.deepStrictEqual(result.results, []);
      assert.strictEqual(result.numVulns, -1);
      assert.strictEqual(result.error.kind, "invalid_response");
    }
  });

  test("strictly reconciles count, presence, and detected-status indicators", () => {
    for (const malformed of ["0x10", "1e3", " 1 "]) {
      assert.strictEqual(getPackageVulnerabilityCount({ num_vulnerabilities: malformed }), null);
    }
    assert.strictEqual(getPackageVulnerabilityCount({
      num_vulnerabilities: 0,
      has_vulnerabilities: true,
    }), -1);
    assert.strictEqual(getPackageVulnerabilityCount({
      num_vulnerabilities: 0,
      security_scan_status: "scan detected vulnerabilities",
    }), -1);
    assert.strictEqual(getPackageVulnerabilityCount({
      num_vulnerabilities: "2",
      has_vulnerabilities: true,
    }), 2);
    assert.strictEqual(getPackageVulnerabilityCount({
      num_vulnerabilities: undefined,
      vulnerability_scan_results_count: null,
      vulnerabilityCount: "",
      has_vulnerabilities: false,
    }), 0);
    assert.strictEqual(getPackageVulnerabilityCount({
      security_scan_status: "Scan Detected No Vulnerabilities",
    }), 0);
    assert.strictEqual(getPackageVulnerabilityCount({
      security_scan_status: "Scan Pending",
    }), null);
  });
});

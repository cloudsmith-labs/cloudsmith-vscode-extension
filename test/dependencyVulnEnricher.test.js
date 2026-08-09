const assert = require("assert");
const {
  clearVulnerabilityCache,
  enrichVulnerabilities,
  getVulnerabilityCacheSize,
} = require("../util/dependencyVulnEnricher");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");

suite("dependencyVulnEnricher", () => {
  function createFoundDependency(slug, count = 1) {
    return {
      name: `pkg-${slug}`,
      version: "1.0.0",
      format: "maven",
      ecosystem: "maven",
      isDirect: false,
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: {
        namespace: "workspace-a",
        repository: "production-maven",
        slug_perm: slug,
        vulnerability_scan_results_count: count,
        max_severity: "High",
      },
    };
  }

  setup(() => {
    clearVulnerabilityCache();
  });

  test("hydrates vulnerability summaries from the detail endpoint", async () => {
    const calls = [];
    const dependencies = [createFoundDependency("pkg-1", 2)];

    const enriched = await enrichVulnerabilities(dependencies, "workspace-a", {
      cloudsmithAPI: {
        async getV2(endpoint) {
          calls.push(endpoint);
          return apiSuccess({
            results: [
              {
                vulnerability_id: "CVE-2024-1234",
                severity: "High",
                fix_version: "10.1.20",
              },
              {
                vulnerability_id: "CVE-2024-5678",
                severity: "Medium",
              },
            ],
          });
        },
      },
    });

    assert.deepStrictEqual(calls, [
      "vulnerabilities/workspace-a/production-maven/pkg-1/",
    ]);
    assert.strictEqual(enriched[0].vulnerabilities.count, 2);
    assert.strictEqual(enriched[0].vulnerabilities.maxSeverity, "High");
    assert.deepStrictEqual(enriched[0].vulnerabilities.cveIds, [
      "CVE-2024-1234",
      "CVE-2024-5678",
    ]);
    assert.strictEqual(enriched[0].vulnerabilities.hasFixAvailable, true);
    assert.strictEqual(enriched[0].vulnerabilities.severityCounts.High, 1);
    assert.strictEqual(enriched[0].vulnerabilities.severityCounts.Medium, 1);
  });

  test("skips vulnerability lookups for dependencies not found in Cloudsmith", async () => {
    let calls = 0;
    const dependencies = [
      {
        name: "accepts",
        version: "1.3.8",
        format: "npm",
        ecosystem: "npm",
        isDirect: false,
        cloudsmithStatus: "NOT_FOUND",
        cloudsmithPackage: null,
      },
    ];

    const enriched = await enrichVulnerabilities(dependencies, "workspace-a", {
      cloudsmithAPI: {
        async getV2() {
          calls += 1;
          return apiSuccess({ results: [] });
        },
      },
    });

    assert.strictEqual(calls, 0);
    assert.strictEqual(enriched[0].vulnerabilities, undefined);
  });

  test("malformed nested vulnerability entries are rejected and never cached as clean", async () => {
    const enriched = await enrichVulnerabilities([createFoundDependency("pkg-malformed")], "workspace-a", {
      cloudsmithAPI: {
        async getV2(_endpoint, options) {
          const payload = { results: [null] };
          assert.strictEqual(options.validate(payload), false);
          return apiFailure("invalid_response", { status: 200 });
        },
      },
    });

    assert.strictEqual(enriched[0].vulnerabilities.detailsLoaded, false);
    assert.strictEqual(enriched[0].vulnerabilities.count, 1);
    assert.strictEqual(getVulnerabilityCacheSize(), 0);
  });

  test("deletes expired cache entries on read when the refresh does not replace them", async () => {
    const originalNow = Date.now;
    let now = 1_000;

    try {
      Date.now = () => now;

      await enrichVulnerabilities([
        createFoundDependency("pkg-1"),
        createFoundDependency("pkg-2"),
      ], "workspace-a", {
        cloudsmithAPI: {
          async getV2() {
            return apiSuccess({
              results: [{
                vulnerability_id: "CVE-2024-1234",
                severity: "High",
              }],
            });
          },
        },
      });

      assert.strictEqual(getVulnerabilityCacheSize(), 2);

      now += 20 * 60 * 1000;

      const enriched = await enrichVulnerabilities([createFoundDependency("pkg-1")], "workspace-a", {
        cloudsmithAPI: {
          async getV2() {
            return apiFailure("network_error", { retryable: true });
          },
        },
      });

      assert.strictEqual(getVulnerabilityCacheSize(), 1);
      assert.strictEqual(enriched[0].vulnerabilities.count, 1);
      assert.strictEqual(enriched[0].vulnerabilities.detailsLoaded, false);
    } finally {
      Date.now = originalNow;
    }
  });

  test("prunes expired entries before inserting when the cache reaches the soft size cap", async () => {
    const originalNow = Date.now;
    let now = 1_000;

    try {
      Date.now = () => now;

      const dependencies = Array.from({ length: 5000 }, (_, index) => createFoundDependency(`pkg-${index}`));
      await enrichVulnerabilities(dependencies, "workspace-a", {
        cloudsmithAPI: {
          async getV2() {
            return apiSuccess({
              results: [{
                vulnerability_id: "CVE-2024-1234",
                severity: "High",
              }],
            });
          },
        },
      });

      assert.strictEqual(getVulnerabilityCacheSize(), 5000);

      now += 20 * 60 * 1000;

      await enrichVulnerabilities([createFoundDependency("pkg-fresh")], "workspace-a", {
        cloudsmithAPI: {
          async getV2() {
            return apiSuccess({
              results: [{
                vulnerability_id: "CVE-2024-5678",
                severity: "Medium",
              }],
            });
          },
        },
      });

      assert.strictEqual(getVulnerabilityCacheSize(), 1);
    } finally {
      Date.now = originalNow;
    }
  });

  test("scan cancellation aborts a hanging vulnerability fetch and does not cache a clean result", async () => {
    let cancellationListener;
    let disposedListeners = 0;
    let fetchSignal;
    const cancellationToken = {
      isCancellationRequested: false,
      onCancellationRequested(listener) {
        cancellationListener = listener;
        return { dispose() { disposedListeners += 1; } };
      },
    };
    const api = new CloudsmithAPI({}, {
      credentialManager: { async getApiKey() { return "test-key"; } },
      fetchImpl: async (_url, options) => {
        fetchSignal = options.signal;
        return new Promise((_resolve, reject) => {
          options.signal.addEventListener("abort", () => {
            reject(new DOMException("aborted", "AbortError"));
          }, { once: true });
        });
      },
    });

    const pending = enrichVulnerabilities([createFoundDependency("pkg-hanging")], "workspace-a", {
      cloudsmithAPI: api,
      cancellationToken,
    });
    while (!fetchSignal) {
      await new Promise(resolve => setImmediate(resolve));
    }
    cancellationToken.isCancellationRequested = true;
    cancellationListener();
    const enriched = await pending;

    assert.strictEqual(fetchSignal.aborted, true);
    assert.strictEqual(disposedListeners, 1);
    assert.strictEqual(enriched[0].vulnerabilities.detailsLoaded, false);
    assert.strictEqual(getVulnerabilityCacheSize(), 0);
  });
});

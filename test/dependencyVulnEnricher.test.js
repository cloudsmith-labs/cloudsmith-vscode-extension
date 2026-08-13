const assert = require("assert");
const {
  clearVulnerabilityCache,
  enrichVulnerabilities: enrichVulnerabilitiesImpl,
  getVulnerabilityCacheSize,
  MAX_VULNERABILITY_DETAIL_REQUESTS,
} = require("../util/dependencyVulnEnricher");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");

suite("dependencyVulnEnricher", () => {
  let accountState;
  const connectionManager = {
    getState() { return { ...accountState }; },
    setState(next) { accountState = { ...accountState, ...next }; },
  };

  function enrichVulnerabilities(dependencies, workspace, options = {}) {
    return enrichVulnerabilitiesImpl(dependencies, workspace, {
      connectionManager,
      ...options,
    });
  }

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
    accountState = {
      activationId: "activation-a",
      accountEpoch: 1,
      sessionConnected: true,
    };
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

  test("mixed known and unrecognized severities keep the canonical maximum unknown", async () => {
    const enriched = await enrichVulnerabilities(
      [createFoundDependency("pkg-mixed", 2)],
      "workspace-a",
      {
        cloudsmithAPI: {
          async getV2() {
            return apiSuccess({
              results: [
                { vulnerability_id: "CVE-1", severity: "HIGH" },
                { vulnerability_id: "CVE-2", severity: "Future" },
              ],
            });
          },
        },
      }
    );

    assert.strictEqual(enriched[0].vulnerabilities.maxSeverity, "Unknown");
    assert.deepStrictEqual(
      enriched[0].vulnerabilities.entries.map(entry => entry.severity),
      ["High", "Unknown"]
    );
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

  test("preserves an authoritative indicator count when detail records are incomplete", async () => {
    const enriched = await enrichVulnerabilities([createFoundDependency("pkg-partial", 5)], "workspace-a", {
      cloudsmithAPI: {
        async getV2() {
          return apiSuccess({
            results: [
              { vulnerability_id: "CVE-1", severity: "High" },
              { vulnerability_id: "CVE-2", severity: "Medium" },
            ],
          });
        },
      },
    });

    assert.strictEqual(enriched[0].vulnerabilities.count, 5);
    assert.strictEqual(enriched[0].vulnerabilities.detailsLoaded, false);
    assert.strictEqual(getVulnerabilityCacheSize(), 0);
  });

  test("keeps duplicate, conflicting, and excess detail records indicator-only", async () => {
    for (const results of [
      [
        { vulnerability_id: "CVE-1", severity: "High" },
        { vulnerability_id: "cve-1", severity: "Low" },
      ],
      [{ vulnerability_id: "CVE-1", identifier: "CVE-2", severity: "High" }],
      [
        { vulnerability_id: "CVE-1", severity: "High" },
        { vulnerability_id: "CVE-2", severity: "Low" },
      ],
    ]) {
      const count = results.length === 1 ? 1 : 1;
      const enriched = await enrichVulnerabilities(
        [createFoundDependency(`identity-${results.length}-${results[0].identifier || "duplicate"}`, count)],
        "workspace-a",
        { cloudsmithAPI: { async getV2() { return apiSuccess({ results }); } } }
      );
      assert.strictEqual(enriched[0].vulnerabilities.count, count);
      assert.strictEqual(enriched[0].vulnerabilities.detailsLoaded, false);
      assert.deepStrictEqual(enriched[0].vulnerabilities.entries, []);
    }
    assert.strictEqual(getVulnerabilityCacheSize(), 0);
  });

  test("does not let zero or conflicting indicator aliases silently select another count", async () => {
    let calls = 0;
    const dependency = createFoundDependency("alias-conflict", 0);
    dependency.cloudsmithPackage.num_vulnerabilities = 3;
    const [enriched] = await enrichVulnerabilities([dependency], "workspace-a", {
      cloudsmithAPI: { async getV2() { calls += 1; return apiSuccess({ results: [] }); } },
    });

    assert.strictEqual(calls, 0);
    assert.strictEqual(enriched.vulnerabilities.count, 3);
    assert.strictEqual(enriched.vulnerabilities.countAuthoritative, false);
    assert.strictEqual(enriched.vulnerabilities.detailsLoaded, false);
  });

  test("positive presence and detected status remain visible when counts are zero or missing", async () => {
    for (const indicator of [
      { vulnerability_scan_results_count: 0, has_vulnerabilities: true },
      { vulnerability_scan_results_count: undefined, security_scan_status: "scan detected vulnerabilities" },
    ]) {
      let calls = 0;
      const dependency = createFoundDependency(`presence-${calls}`, 0);
      Object.assign(dependency.cloudsmithPackage, indicator);
      const [enriched] = await enrichVulnerabilities([dependency], "workspace-a", {
        cloudsmithAPI: { async getV2() { calls += 1; return apiSuccess({ results: [] }); } },
      });
      assert.strictEqual(calls, 0);
      assert.strictEqual(enriched.vulnerabilities.count, 0);
      assert.strictEqual(enriched.vulnerabilities.countKnown, false);
      assert.strictEqual(enriched.vulnerabilities.detected, true);
      assert.strictEqual(enriched.vulnerabilities.detailsLoaded, false);
    }
  });

  test("keeps malformed-only vulnerability evidence unknown without inventing a detection", async () => {
    let calls = 0;
    const dependency = createFoundDependency("malformed-only", 0);
    dependency.cloudsmithPackage.vulnerability_scan_results_count = undefined;
    dependency.cloudsmithPackage.num_vulnerabilities = "0x10";
    const [enriched] = await enrichVulnerabilities([dependency], "workspace-a", {
      cloudsmithAPI: { async getV2() { calls += 1; return apiSuccess({ results: [] }); } },
    });

    assert.strictEqual(calls, 0);
    assert.strictEqual(enriched.vulnerabilities.count, 0);
    assert.strictEqual(enriched.vulnerabilities.countKnown, false);
    assert.strictEqual(enriched.vulnerabilities.detected, false);
    assert.strictEqual(enriched.vulnerabilities.unknown, true);
    assert.strictEqual(Object.getPrototypeOf(enriched.vulnerabilities.severityCounts), null);
    assert.strictEqual(Object.keys(enriched.vulnerabilities.severityCounts).length, 0);
  });

  test("contains throwing progress observers and waits for all bounded detail work", async () => {
    let calls = 0;
    const enriched = await enrichVulnerabilities(
      Array.from({ length: 8 }, (_value, index) => createFoundDependency(`progress-${index}`)),
      "workspace-a",
      {
        cloudsmithAPI: {
          async getV2() {
            calls += 1;
            return apiSuccess({
              results: [{ vulnerability_id: `CVE-${calls}`, severity: "High" }],
            });
          },
        },
        onProgress() { throw new Error("observer failure"); },
      }
    );

    assert.strictEqual(calls, 8);
    assert.strictEqual(enriched.every(item => item.vulnerabilities.detailsLoaded), true);
  });

  test("bounds vulnerability detail fan-out and leaves uninspected indicators incomplete", async () => {
    const dependencies = Array.from(
      { length: MAX_VULNERABILITY_DETAIL_REQUESTS + 100 },
      (_value, index) => createFoundDependency(`bounded-${index}`)
    );
    let calls = 0;
    const enriched = await enrichVulnerabilities(dependencies, "workspace-a", {
      cloudsmithAPI: {
        async getV2() {
          calls += 1;
          return apiSuccess({
            results: [{ vulnerability_id: `CVE-${calls}`, severity: "High" }],
          });
        },
      },
    });

    assert.strictEqual(calls, MAX_VULNERABILITY_DETAIL_REQUESTS);
    assert.strictEqual(
      enriched.filter(dependency => dependency.vulnerabilities.detailsLoaded).length,
      MAX_VULNERABILITY_DETAIL_REQUESTS
    );
    assert.strictEqual(
      enriched.filter(dependency => !dependency.vulnerabilities.detailsLoaded).length,
      100
    );
  });

  test("limits vulnerability detail concurrency to four fixed workers", async () => {
    let active = 0;
    let maxActive = 0;
    let calls = 0;
    let releaseFirstWave;
    const firstWave = new Promise(resolve => { releaseFirstWave = resolve; });
    const pending = enrichVulnerabilities(
      Array.from({ length: 100 }, (_value, index) => createFoundDependency(`concurrent-${index}`)),
      "workspace-a",
      {
        cloudsmithAPI: {
          async getV2() {
            calls += 1;
            active += 1;
            maxActive = Math.max(maxActive, active);
            if (calls <= 4) await firstWave;
            active -= 1;
            return apiSuccess({
              results: [{ vulnerability_id: `CVE-${calls}`, severity: "High" }],
            });
          },
        },
      }
    );
    await new Promise(resolve => setImmediate(resolve));
    assert.strictEqual(calls, 4);
    releaseFirstWave();
    await pending;

    assert.strictEqual(maxActive, 4);
    assert.strictEqual(active, 0);
    assert.strictEqual(calls, 100);
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

      for (let batch = 0; batch < 5; batch += 1) {
        const dependencies = Array.from(
          { length: MAX_VULNERABILITY_DETAIL_REQUESTS },
          (_, index) => createFoundDependency(`pkg-${batch}-${index}`)
        );
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
      }

      assert.strictEqual(getVulnerabilityCacheSize(), 5000);

      await enrichVulnerabilities([createFoundDependency("pkg-over-cap")], "workspace-a", {
        cloudsmithAPI: {
          async getV2() {
            return apiSuccess({
              results: [{ vulnerability_id: "CVE-2024-9999", severity: "Low" }],
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

  test("does not cache or publish vulnerability details completed by an old account", async () => {
    let release;
    const response = new Promise(resolve => { release = resolve; });
    const dependencies = [createFoundDependency("pkg-old")];
    const pending = enrichVulnerabilities(dependencies, "workspace-a", {
      cloudsmithAPI: { async getV2() { return response; } },
    });
    await new Promise(resolve => setImmediate(resolve));
    connectionManager.setState({ accountEpoch: 2 });
    release(apiSuccess({
      results: [{ vulnerability_id: "CVE-OLD", severity: "Critical" }],
    }));

    const result = await pending;
    assert.strictEqual(result, dependencies);
    assert.strictEqual(result[0].vulnerabilities, undefined);
    assert.strictEqual(getVulnerabilityCacheSize(), 0);
  });
});

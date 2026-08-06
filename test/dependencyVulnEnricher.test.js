const assert = require("assert");
const {
  clearVulnerabilityCache,
  enrichVulnerabilities,
  getVulnerabilityCacheSize,
} = require("../util/dependencyVulnEnricher");

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
          return {
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
          };
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
          return { results: [] };
        },
      },
    });

    assert.strictEqual(calls, 0);
    assert.strictEqual(enriched[0].vulnerabilities, undefined);
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
            return {
              results: [{
                vulnerability_id: "CVE-2024-1234",
                severity: "High",
              }],
            };
          },
        },
      });

      assert.strictEqual(getVulnerabilityCacheSize(), 2);

      now += 20 * 60 * 1000;

      const enriched = await enrichVulnerabilities([createFoundDependency("pkg-1")], "workspace-a", {
        cloudsmithAPI: {
          async getV2() {
            return "temporarily unavailable";
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
            return {
              results: [{
                vulnerability_id: "CVE-2024-1234",
                severity: "High",
              }],
            };
          },
        },
      });

      assert.strictEqual(getVulnerabilityCacheSize(), 5000);

      now += 20 * 60 * 1000;

      await enrichVulnerabilities([createFoundDependency("pkg-fresh")], "workspace-a", {
        cloudsmithAPI: {
          async getV2() {
            return {
              results: [{
                vulnerability_id: "CVE-2024-5678",
                severity: "Medium",
              }],
            };
          },
        },
      });

      assert.strictEqual(getVulnerabilityCacheSize(), 1);
    } finally {
      Date.now = originalNow;
    }
  });
});

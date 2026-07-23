const assert = require("assert");
const {
  analyzeUpstreamGaps,
} = require("../util/upstreamGapAnalyzer");

suite("upstreamGapAnalyzer", () => {
  function createState(entries = {}) {
    return {
      groupedUpstreams: new Map(Object.entries(entries)),
    };
  }

  test("classifies uncovered dependencies as reachable when a matching proxy exists", async () => {
    const dependencies = [
      {
        name: "accepts",
        version: "1.3.8",
        format: "npm",
        ecosystem: "npm",
        cloudsmithStatus: "NOT_FOUND",
      },
    ];

    const enriched = await analyzeUpstreamGaps(dependencies, "workspace-a", ["production"], {
      upstreamChecker: {
        async getRepositoryUpstreamState() {
          return createState({
            npm: [
              { name: "npm", is_active: true },
            ],
          });
        },
      },
    });

    assert.strictEqual(enriched[0].upstreamStatus, "reachable");
    assert.strictEqual(enriched[0].upstreamDetail, "npm proxy on production");
  });

  test("classifies supported formats with no proxy as no_proxy", async () => {
    const dependencies = [
      {
        name: "requests",
        version: "2.31.0",
        format: "python",
        ecosystem: "python",
        cloudsmithStatus: "NOT_FOUND",
      },
    ];

    const enriched = await analyzeUpstreamGaps(dependencies, "workspace-a", ["production"], {
      upstreamChecker: {
        async getRepositoryUpstreamState() {
          return createState();
        },
      },
    });

    assert.strictEqual(enriched[0].upstreamStatus, "no_proxy");
    assert.strictEqual(enriched[0].upstreamDetail, "No upstream proxy configured for python");
  });

  test("classifies unsupported formats as unreachable", async () => {
    const dependencies = [
      {
        name: "custom-lib",
        version: "1.0.0",
        format: "custom",
        ecosystem: "custom",
        cloudsmithStatus: "NOT_FOUND",
      },
    ];

    const enriched = await analyzeUpstreamGaps(dependencies, "workspace-a", ["production"], {
      upstreamChecker: {
        async getRepositoryUpstreamState() {
          return createState();
        },
      },
    });

    assert.strictEqual(enriched[0].upstreamStatus, "unreachable");
    assert.strictEqual(enriched[0].upstreamDetail, "Not available through Cloudsmith");
  });

  test("limits upstream repository lookups to five concurrent requests and emits one final patch", async () => {
    const dependencies = [
      {
        name: "accepts",
        version: "1.3.8",
        format: "npm",
        ecosystem: "npm",
        cloudsmithStatus: "NOT_FOUND",
      },
    ];
    const repositories = Array.from({ length: 12 }, (_, index) => `repo-${index + 1}`);
    const progressEvents = [];
    let inFlight = 0;
    let maxInFlight = 0;

    const enriched = await analyzeUpstreamGaps(dependencies, "workspace-a", repositories, {
      onProgress: (patchMap, meta) => {
        progressEvents.push({
          size: patchMap.size,
          completed: meta.completed,
          total: meta.total,
        });
      },
      upstreamChecker: {
        async getRepositoryUpstreamState(_workspace, repo) {
          inFlight += 1;
          maxInFlight = Math.max(maxInFlight, inFlight);
          await new Promise((resolve) => setTimeout(resolve, 5));
          inFlight -= 1;

          if (repo === "repo-9") {
            return createState({
              npm: [
                { name: "npm", is_active: true },
              ],
            });
          }

          return createState();
        },
      },
    });

    assert.ok(maxInFlight <= 5);
    assert.strictEqual(progressEvents.filter((event) => event.size > 0).length, 1);
    assert.strictEqual(progressEvents[progressEvents.length - 1].completed, repositories.length);
    assert.strictEqual(progressEvents[progressEvents.length - 1].size, 1);
    assert.strictEqual(enriched[0].upstreamStatus, "reachable");
    assert.strictEqual(enriched[0].upstreamDetail, "npm proxy on repo-9");
  });
});

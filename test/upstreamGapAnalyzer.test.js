const assert = require("assert");
const {
  analyzeUpstreamGaps,
} = require("../util/upstreamGapAnalyzer");
const { UpstreamOperationScheduler } = require("../util/upstreamOperationScheduler");

suite("upstreamGapAnalyzer", () => {
  function createState(entries = {}) {
    return {
      groupedUpstreams: new Map(Object.entries(entries)),
      complete: true,
      failedFormats: [],
      uninspectedFormats: [],
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

  test("limits upstream repository lookups to four concurrent requests and emits one final patch", async () => {
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

    assert.ok(maxInFlight <= 4);
    assert.strictEqual(progressEvents.filter((event) => event.size > 0).length, 1);
    assert.strictEqual(progressEvents[progressEvents.length - 1].completed, repositories.length);
    assert.strictEqual(progressEvents[progressEvents.length - 1].size, 1);
    assert.strictEqual(enriched[0].upstreamStatus, "reachable");
    assert.strictEqual(enriched[0].upstreamDetail, "npm proxy on repo-9");
  });

  test("contains throwing progress observers until every repository worker settles", async () => {
    const dependencies = [{
      name: "accepts",
      version: "1.3.8",
      format: "npm",
      cloudsmithStatus: "NOT_FOUND",
    }];
    let completed = 0;
    const enriched = await analyzeUpstreamGaps(
      dependencies,
      "workspace-a",
      Array.from({ length: 12 }, (_value, index) => `repo-${index}`),
      {
        onProgress() { throw new Error("observer failure"); },
        upstreamChecker: {
          async getRepositoryUpstreamState() {
            completed += 1;
            return createState();
          },
        },
      }
    );

    assert.strictEqual(completed, 12);
    assert.strictEqual(enriched[0].upstreamStatus, "no_proxy");
  });

  test("accepts conclusive absence and ignores unresolved lookup states", async () => {
    const dependencies = [
      {
        name: "absent-package",
        version: "1.0.0",
        format: "npm",
        cloudsmithStatus: "ABSENT",
      },
      {
        name: "unresolved-package",
        version: "",
        format: "npm",
        cloudsmithStatus: "UNRESOLVED",
      },
    ];

    const enriched = await analyzeUpstreamGaps(dependencies, "workspace-a", [], {});

    assert.strictEqual(enriched[0].upstreamStatus, "no_proxy");
    assert.strictEqual(enriched[1].upstreamStatus, undefined);
  });

  test("keeps positive matches but reports unknown when relevant inspection is incomplete", async () => {
    const dependencies = [{
      name: "package-a",
      version: "1.0.0",
      format: "npm",
      cloudsmithStatus: "ABSENT",
    }];
    const unknown = await analyzeUpstreamGaps(dependencies, "workspace-a", ["repo-a"], {
      upstreamChecker: {
        async getRepositoryUpstreamState() {
          return {
            groupedUpstreams: new Map(),
            complete: false,
            failedFormats: ["npm"],
            uninspectedFormats: [],
          };
        },
      },
    });
    assert.strictEqual(unknown[0].upstreamStatus, "unknown");

    const unrelatedFailure = await analyzeUpstreamGaps(
      dependencies,
      "workspace-a",
      ["repo-a"],
      {
        upstreamChecker: {
          async getRepositoryUpstreamState() {
            return {
              groupedUpstreams: new Map(),
              complete: false,
              failedFormats: ["python"],
              uninspectedFormats: [],
            };
          },
        },
      }
    );
    assert.strictEqual(unrelatedFailure[0].upstreamStatus, "no_proxy");

    const positive = await analyzeUpstreamGaps(dependencies, "workspace-a", ["repo-a"], {
      repositoriesComplete: false,
      upstreamChecker: {
        async getRepositoryUpstreamState() {
          return {
            groupedUpstreams: new Map([["npm", [{ name: "npm", is_active: true }]]]),
            complete: false,
            failedFormats: [],
            uninspectedFormats: ["python"],
          };
        },
      },
    });
    assert.strictEqual(positive[0].upstreamStatus, "reachable");
  });

  test("stops repository fan-out structurally when the shared request budget is exhausted", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 1 });
    let repositoryCalls = 0;
    const enriched = await analyzeUpstreamGaps([{
      name: "package-a",
      version: "1.0.0",
      format: "npm",
      cloudsmithStatus: "ABSENT",
    }], "workspace-a", Array.from({ length: 1000 }, (_, index) => `repo-${index}`), {
      scheduler,
      upstreamChecker: {
        async getRepositoryUpstreamState(_workspace, _repo, options) {
          repositoryCalls += 1;
          await options.scheduler.run(async () => ({ ok: true }));
          return createState();
        },
      },
    });

    assert.strictEqual(repositoryCalls, 1);
    assert.strictEqual(scheduler.requestCount, 1);
    assert.strictEqual(enriched[0].upstreamStatus, "unknown");
  });
});

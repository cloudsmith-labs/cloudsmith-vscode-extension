const assert = require("assert");
const {
  analyzeUpstreamGaps,
} = require("../util/upstreamGapAnalyzer");
const { UpstreamChecker } = require("../util/upstreamChecker");
const { UpstreamOperationScheduler } = require("../util/upstreamOperationScheduler");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");

suite("upstreamGapAnalyzer", () => {
  const TEST_ACCOUNT = Object.freeze({ activationId: "activation-a", accountEpoch: 1 });

  function createRuntime(reader) {
    return {
      createOperationScope(options = {}) {
        const controller = new AbortController();
        const scheduler = options.scheduler || new UpstreamOperationScheduler();
        return Object.freeze({
          scheduler,
          signal: controller.signal,
          account: options.account || TEST_ACCOUNT,
          dispose() {
            controller.abort();
            scheduler.cancel();
          },
        });
      },
      getRepositoryUpstreamStateForFormats(workspace, repo, formats, options = {}) {
        return reader.getRepositoryUpstreamStateForFormats(
          workspace,
          repo,
          formats,
          { ...options, scheduler: options.operationScope.scheduler }
        );
      },
    };
  }

  function createState(entries = {}) {
    return {
      groupedUpstreams: new Map(Object.entries(entries).map(([format, upstreams]) => [
        format,
        upstreams.map(upstream => ({
          ...upstream,
          _format: format,
          format,
          origin: "",
        })),
      ])),
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
      account: TEST_ACCOUNT,
      upstreamRuntime: createRuntime({
        async getRepositoryUpstreamStateForFormats() {
          return createState({
            npm: [
              { name: "npm", is_active: true },
            ],
          });
        },
      }),
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
      account: TEST_ACCOUNT,
      upstreamRuntime: createRuntime({
        async getRepositoryUpstreamStateForFormats() {
          return createState();
        },
      }),
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
      upstreamRuntime: createRuntime({
        async getRepositoryUpstreamStateForFormats() {
          return createState();
        },
      }),
    });

    assert.strictEqual(enriched[0].upstreamStatus, "unreachable");
    assert.strictEqual(enriched[0].upstreamDetail, "Not available through Cloudsmith");
  });

  test("does not inspect a recognized package format without an upstream API", async () => {
    let calls = 0;
    const enriched = await analyzeUpstreamGaps([{
      name: "archive",
      version: "1.0.0",
      format: "raw",
      ecosystem: "raw",
      cloudsmithStatus: "NOT_FOUND",
    }], "workspace-a", ["production"], {
      upstreamRuntime: createRuntime({
        async getRepositoryUpstreamStateForFormats() {
          calls += 1;
          return createState();
        },
      }),
    });
    assert.strictEqual(calls, 0);
    assert.strictEqual(enriched[0].upstreamStatus, "unreachable");
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
      account: TEST_ACCOUNT,
      upstreamRuntime: createRuntime({
        async getRepositoryUpstreamStateForFormats(_workspace, repo) {
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
      }),
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
        account: TEST_ACCOUNT,
        upstreamRuntime: createRuntime({
          async getRepositoryUpstreamStateForFormats() {
            completed += 1;
            return createState();
          },
        }),
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
      account: TEST_ACCOUNT,
      upstreamRuntime: createRuntime({
        async getRepositoryUpstreamStateForFormats() {
          return {
            groupedUpstreams: new Map(),
            complete: false,
            failedFormats: ["npm"],
            uninspectedFormats: [],
          };
        },
      }),
    });
    assert.strictEqual(unknown[0].upstreamStatus, "unknown");

    const unrelatedFailure = await analyzeUpstreamGaps(
      dependencies,
      "workspace-a",
      ["repo-a"],
      {
        account: TEST_ACCOUNT,
        upstreamRuntime: createRuntime({
          async getRepositoryUpstreamStateForFormats() {
            return {
              groupedUpstreams: new Map(),
              complete: false,
              failedFormats: ["python"],
              uninspectedFormats: [],
            };
          },
        }),
      }
    );
    assert.strictEqual(unrelatedFailure[0].upstreamStatus, "no_proxy");

    const positive = await analyzeUpstreamGaps(dependencies, "workspace-a", ["repo-a"], {
      repositoriesComplete: false,
      account: TEST_ACCOUNT,
      upstreamRuntime: createRuntime({
        async getRepositoryUpstreamStateForFormats() {
          return {
            groupedUpstreams: new Map([["npm", [{
              name: "npm",
              _format: "npm",
              format: "npm",
              origin: "",
              is_active: true,
            }]]]),
            complete: false,
            failedFormats: [],
            uninspectedFormats: ["python"],
          };
        },
      }),
    });
    assert.strictEqual(positive[0].upstreamStatus, "reachable");
  });

  test("completes with positive and unknown results when optional cache persistence hangs", async () => {
    const connectionManager = {
      getState() {
        return {
          activationId: "activation-a",
          accountEpoch: 1,
          sessionConnected: true,
        };
      },
    };
    const context = {
      globalState: {
        get() {},
        update() {
          return new Promise(() => {});
        },
      },
    };
    const checker = new UpstreamChecker(context, {
      cacheWriteWaitMs: 5,
      connectionManager,
      cloudsmithAPI: {
        async get(endpoint) {
          const match = endpoint.match(/repos\/workspace-a\/([^/]+)\/upstream\/([^/?]+)/);
          const repository = match && match[1];
          const format = match && match[2];
          if (repository === "repo-positive" && format === "npm") {
            return apiSuccess([{
              name: "npm",
              upstream_url: "https://registry.npmjs.org/",
              is_active: true,
            }]);
          }
          if (repository === "repo-incomplete" && format === "python") {
            return apiFailure("server_error", { status: 503 });
          }
          return apiSuccess([]);
        },
      },
    });
    const progressEvents = [];
    const dependencies = [
      { name: "accepts", version: "1.3.8", format: "npm", cloudsmithStatus: "ABSENT" },
      { name: "requests", version: "2.31.0", format: "python", cloudsmithStatus: "ABSENT" },
    ];

    const enriched = await Promise.race([
      analyzeUpstreamGaps(
        dependencies,
        "workspace-a",
        ["repo-positive", "repo-incomplete"],
        {
          account: TEST_ACCOUNT,
          upstreamRuntime: createRuntime(checker),
          onProgress(_patchMap, meta) {
            progressEvents.push({ completed: meta.completed, total: meta.total });
          },
        }
      ),
      new Promise((_resolve, reject) => {
        setTimeout(() => reject(new Error("upstream phase did not settle")), 250);
      }),
    ]);

    assert.strictEqual(enriched[0].upstreamStatus, "reachable");
    assert.strictEqual(enriched[0].upstreamDetail, "npm proxy on repo-positive");
    assert.strictEqual(enriched[1].upstreamStatus, "unknown");
    assert.deepStrictEqual(progressEvents.at(-1), { completed: 2, total: 2 });
  });

  test("settles all repository progress when one active transport ignores abort", async () => {
    const repositories = [
      ...Array.from({ length: 10 }, (_value, index) => `repo-${index + 1}`),
      "repo-hung",
    ];
    const scheduler = new UpstreamOperationScheduler({ concurrency: 4, maxRequests: 100 });
    const connectionManager = {
      getState() {
        return {
          activationId: "activation-a",
          accountEpoch: 1,
          sessionConnected: true,
        };
      },
    };
    let rejectLate;
    const checker = new UpstreamChecker({}, {
      connectionManager,
      cloudsmithAPI: {
        async get(endpoint) {
          if (endpoint.includes("/repo-hung/")) {
            return new Promise((_resolve, reject) => {
              rejectLate = reject;
            });
          }
          return apiSuccess([]);
        },
      },
    });
    const progressEvents = [];
    const unhandled = [];
    const onUnhandled = reason => unhandled.push(reason);
    process.on("unhandledRejection", onUnhandled);

    try {
      const enriched = await Promise.race([
        analyzeUpstreamGaps(
          [{ name: "missing", version: "1.0.0", format: "npm", cloudsmithStatus: "ABSENT" }],
          "workspace-a",
          repositories,
          {
            operationTimeoutMs: 5,
            scheduler,
            account: TEST_ACCOUNT,
            upstreamRuntime: createRuntime(checker),
            onProgress(_patchMap, meta) {
              progressEvents.push({ completed: meta.completed, total: meta.total });
            },
          }
        ),
        new Promise((_resolve, reject) => {
          setTimeout(() => reject(new Error("repository pool did not settle")), 250);
        }),
      ]);

      assert.ok(progressEvents.some(event => event.completed === 10 && event.total === 11));
      assert.deepStrictEqual(progressEvents.at(-1), { completed: 11, total: 11 });
      assert.strictEqual(enriched[0].upstreamStatus, "unknown");
      assert.strictEqual(scheduler.stopped, true);
      assert.strictEqual(scheduler.activeCount, 0);
      assert.strictEqual(scheduler.queuedCount, 0);

      const snapshot = JSON.stringify(enriched);
      rejectLate(new Error("late repository transport failure"));
      await new Promise(resolve => setImmediate(resolve));
      await new Promise(resolve => setImmediate(resolve));
      assert.strictEqual(JSON.stringify(enriched), snapshot);
      assert.deepStrictEqual(unhandled, []);
      assert.strictEqual(scheduler.activeCount, 0);
      assert.strictEqual(scheduler.queuedCount, 0);
    } finally {
      process.removeListener("unhandledRejection", onUnhandled);
    }
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
      account: TEST_ACCOUNT,
      upstreamRuntime: createRuntime({
        async getRepositoryUpstreamStateForFormats(_workspace, _repo, _formats, options) {
          repositoryCalls += 1;
          await options.scheduler.run(async () => ({ ok: true }));
          return createState();
        },
      }),
    });

    assert.strictEqual(repositoryCalls, 1);
    assert.strictEqual(scheduler.requestCount, 1);
    assert.strictEqual(enriched[0].upstreamStatus, "unknown");
  });
});

const assert = require("assert");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { CredentialManager } = require("../util/credentialManager");
const {
  isBenignUpstreamFormatError,
  SUPPORTED_UPSTREAM_FORMATS,
  UpstreamChecker,
} = require("../util/upstreamChecker");
const {
  SUPPORTED_UPSTREAM_FORMATS: SHARED_SUPPORTED_UPSTREAM_FORMATS,
} = require("../util/upstreamFormats");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");

function toApiResult(response) {
  if (response && typeof response === "object" && typeof response.ok === "boolean") {
    return response;
  }
  if (response instanceof Error) {
    return apiFailure("server_error", { status: 503, message: response.message });
  }
  return apiSuccess(response === undefined ? [] : response);
}

suite("UpstreamChecker repository upstream cache", () => {
  let originalGet;
  let originalGetApiKey;
  let formatResponses;
  let requestCount;
  let store;
  let context;

  setup(() => {
    originalGet = CloudsmithAPI.prototype.get;
    originalGetApiKey = CredentialManager.prototype.getApiKey;
    formatResponses = {};
    requestCount = 0;
    store = new Map();
    context = {
      globalState: {
        get(key) {
          return store.get(key);
        },
        async update(key, value) {
          if (value === undefined) {
            store.delete(key);
            return;
          }
          store.set(key, value);
        },
      },
    };

    CredentialManager.prototype.getApiKey = async () => "test-api-key";
    CloudsmithAPI.prototype.get = async function(endpoint, options = {}) {
      requestCount += 1;
      const match = endpoint.match(/upstream\/([^/]+)\/$/);
      const format = match ? match[1] : null;
      const response = formatResponses[format];

      try {
        if (typeof response === "function") {
          const result = toApiResult(response());
          return result.ok && typeof options.validate === "function" && options.validate(result.data) !== true
            ? apiFailure("invalid_response", { status: 200 })
            : result;
        }
        if (response !== undefined) {
          const result = toApiResult(response);
          return result.ok && typeof options.validate === "function" && options.validate(result.data) !== true
            ? apiFailure("invalid_response", { status: 200 })
            : result;
        }
      } catch {
        return apiFailure("server_error", { status: 503 });
      }

      return apiSuccess([]);
    };
  });

  teardown(() => {
    CloudsmithAPI.prototype.get = originalGet;
    CredentialManager.prototype.getApiKey = originalGetApiKey;
  });

  function createCachedEntry(overrides = {}) {
    return {
      timestamp: Date.now(),
      successfulFormats: 1,
      groupedUpstreams: {
        python: [
          { name: "PyPI", upstream_url: "https://pypi.org/simple/" },
        ],
      },
      ...overrides,
    };
  }

  async function assertInvalidCachedEntry(entry) {
    const checker = new UpstreamChecker(context);
    const cacheKey = checker._getRepositoryUpstreamCacheKey("workspace-a", "repo-a");
    store.set(cacheKey, entry);

    const cachedState = checker._getCachedRepositoryUpstreamState("workspace-a", "repo-a");

    await Promise.resolve();

    assert.strictEqual(cachedState, null);
    assert.strictEqual(store.has(cacheKey), false);
  }

  test("aggregates repository upstreams across formats and reuses the shared cache", async () => {
    formatResponses = {
      python: [
        { name: "PyPI", upstream_url: "https://pypi.org/simple/" },
        { name: "Internal mirror", upstream_url: "https://mirror.example/python" },
        { name: "Legacy", upstream_url: "https://legacy.example/python" },
      ],
      npm: [
        { name: "npmjs", upstream_url: "https://registry.npmjs.org/" },
        { name: "Disabled", upstream_url: "https://disabled.example/npm", is_active: false },
      ],
      docker: [
        { name: "Docker Hub", upstream_url: "https://registry-1.docker.io/" },
      ],
      conda: apiFailure("not_found", { status: 404 }),
    };

    const checker = new UpstreamChecker(context);
    const firstState = await checker.getRepositoryUpstreamState("workspace-a", "repo-a");

    assert.strictEqual(requestCount, SUPPORTED_UPSTREAM_FORMATS.length);
    assert.strictEqual(firstState.total, 6);
    assert.strictEqual(firstState.active, 5);
    assert.deepStrictEqual(firstState.failedFormats, []);
    assert.strictEqual(firstState.groupedUpstreams.get("python").length, 3);
    assert.strictEqual(firstState.groupedUpstreams.get("npm").length, 2);
    assert.strictEqual(firstState.groupedUpstreams.get("docker").length, 1);
    assert.strictEqual(firstState.groupedUpstreams.get("docker")[0].format, "docker");
    assert.strictEqual(store.size, 1);

    const secondState = await checker.getRepositoryUpstreamState("workspace-a", "repo-a");

    assert.strictEqual(requestCount, SUPPORTED_UPSTREAM_FORMATS.length);
    assert.strictEqual(secondState.total, 6);
    assert.strictEqual(secondState.active, 5);
    assert.strictEqual(secondState.groupedUpstreams.get("python")[0].name, "Internal mirror");
  });

  test("does not cache partial upstream data when any format fails", async () => {
    formatResponses = {
      python: [
        { name: "PyPI", upstream_url: "https://pypi.org/simple/" },
      ],
      npm: () => {
        return apiFailure("server_error", { status: 503 });
      },
    };

    const checker = new UpstreamChecker(context);
    const firstState = await checker.getRepositoryUpstreamState("workspace-a", "repo-a");

    assert.ok(firstState.failedFormats.includes("npm"));
    assert.strictEqual(firstState.total, 1);
    assert.strictEqual(firstState.active, 1);
    assert.strictEqual(store.size, 0);

    await checker.getRepositoryUpstreamState("workspace-a", "repo-a");

    assert.strictEqual(requestCount, SUPPORTED_UPSTREAM_FORMATS.length * 2);
    assert.strictEqual(store.size, 0);
  });

  test("rejects blank upstream records instead of reporting false active reachability", async () => {
    formatResponses = { python: [{}] };

    const checker = new UpstreamChecker(context);
    const state = await checker.getRepositoryUpstreamState("workspace-a", "repo-a");

    assert.strictEqual(state.active, 0);
    assert.strictEqual(state.total, 0);
    assert.ok(state.failedFormats.includes("python"));
    assert.strictEqual(store.size, 0);
  });

  test("treats missing timestamp as an invalid cached repository upstream state", async () => {
    const entry = createCachedEntry();
    delete entry.timestamp;
    await assertInvalidCachedEntry(entry);
  });

  test("treats non-number timestamp as an invalid cached repository upstream state", async () => {
    await assertInvalidCachedEntry(createCachedEntry({ timestamp: "123" }));
  });

  test("treats non-finite timestamp as an invalid cached repository upstream state", async () => {
    await assertInvalidCachedEntry(createCachedEntry({ timestamp: Number.NaN }));
  });

  test("treats missing groupedUpstreams as an invalid cached repository upstream state", async () => {
    const entry = createCachedEntry();
    delete entry.groupedUpstreams;
    await assertInvalidCachedEntry(entry);
  });

  test("treats non-object groupedUpstreams as an invalid cached repository upstream state", async () => {
    await assertInvalidCachedEntry(createCachedEntry({ groupedUpstreams: [] }));
  });

  test("treats unnamed cached upstream records as invalid", async () => {
    await assertInvalidCachedEntry(createCachedEntry({ groupedUpstreams: { python: [{}] } }));
  });

  test("treats expired cached repository upstream state as invalid", () => {
    const checker = new UpstreamChecker(context);
    const cacheKey = checker._getRepositoryUpstreamCacheKey("workspace-a", "repo-a");
    store.set(cacheKey, createCachedEntry({ timestamp: Date.now() - (11 * 60 * 1000) }));

    const cachedState = checker._getCachedRepositoryUpstreamState("workspace-a", "repo-a");

    assert.strictEqual(cachedState, null);
  });

  test("accepts a valid cached repository upstream state", () => {
    const checker = new UpstreamChecker(context);
    const cacheKey = checker._getRepositoryUpstreamCacheKey("workspace-a", "repo-a");
    store.set(cacheKey, createCachedEntry({ successfulFormats: 7 }));

    const cachedState = checker._getCachedRepositoryUpstreamState("workspace-a", "repo-a");

    assert.ok(cachedState);
    assert.strictEqual(cachedState.successfulFormats, 7);
    assert.strictEqual(cachedState.total, 1);
    assert.strictEqual(cachedState.active, 1);
    assert.strictEqual(cachedState.groupedUpstreams.get("python").length, 1);
  });

  test("returns computed upstream state when repository cache persistence fails", async () => {
    formatResponses = {
      python: [
        { name: "PyPI", upstream_url: "https://pypi.org/simple/" },
      ],
      npm: [
        { name: "npmjs", upstream_url: "https://registry.npmjs.org/" },
      ],
    };

    const originalUpdate = context.globalState.update;
    const logCalls = [];

    context.globalState.update = async () => {
      throw new Error("quota exceeded");
    };

    try {
      const checker = new UpstreamChecker(context);
      checker._logRepositoryUpstreamCacheError = (...args) => logCalls.push(args);
      const state = await checker.getRepositoryUpstreamState("workspace-a", "repo-a");

      assert.strictEqual(state.total, 2);
      assert.strictEqual(state.active, 2);
      assert.deepStrictEqual(state.failedFormats, []);
      assert.strictEqual(store.size, 0);
      assert.strictEqual(logCalls.length, 1);
      assert.deepStrictEqual(logCalls[0].slice(0, 3), [
        "persist",
        "workspace-a",
        "repo-a",
      ]);
      assert.strictEqual(logCalls[0][3].message, "quota exceeded");
    } finally {
      context.globalState.update = originalUpdate;
    }
  });
});

suite("UpstreamChecker shared helper and format handling", () => {
  function createContext() {
    const store = new Map();
    const updates = [];

    return {
      store,
      updates,
      context: {
        globalState: {
          get(key) {
            return store.get(key);
          },
          async update(key, value) {
            updates.push({ key, value });
            if (value === undefined) {
              store.delete(key);
              return;
            }

            store.set(key, value);
          },
        },
      },
    };
  }

  function createCachedEntry(overrides = {}) {
    return {
      timestamp: Date.now(),
      upstreams: [
        {
          name: "PyPI",
          _format: "python",
          format: "python",
          upstream_url: "https://pypi.org/simple/",
          is_active: true,
        },
      ],
      active: 1,
      total: 1,
      failedFormats: [],
      successfulFormats: 1,
      ...overrides,
    };
  }

  function createResponseAwareChecker(context, formatResponses) {
    let requestCount = 0;
    const checker = new UpstreamChecker(context);

    checker.api.get = async (endpoint) => {
      requestCount += 1;
      const match = endpoint.match(/upstream\/([^/]+)\/$/);
      const format = match ? match[1] : null;
      const response = formatResponses[format];

      try {
        if (typeof response === "function") {
          return toApiResult(response());
        }
        if (response !== undefined) {
          return toApiResult(response);
        }
      } catch {
        return apiFailure("server_error", { status: 503 });
      }

      return apiSuccess([]);
    };

    return {
      checker,
      getRequestCount() {
        return requestCount;
      },
    };
  }

  test("uses the shared canonical upstream format list for all-format fetches", () => {
    assert.strictEqual(SUPPORTED_UPSTREAM_FORMATS, SHARED_SUPPORTED_UPSTREAM_FORMATS);
    assert.deepStrictEqual(SUPPORTED_UPSTREAM_FORMATS, [
      "alpine",
      "cargo",
      "cocoapods",
      "composer",
      "conan",
      "conda",
      "cran",
      "dart",
      "deb",
      "docker",
      "generic",
      "go",
      "helm",
      "hex",
      "huggingface",
      "luarocks",
      "maven",
      "npm",
      "nuget",
      "python",
      "raw",
      "rpm",
      "ruby",
      "swift",
      "terraform",
      "vagrant",
    ]);
  });

  [400, 404, 405, 422].forEach((statusCode) => {
    test(`${statusCode} is classified as a benign upstream format error`, () => {
      assert.strictEqual(
        isBenignUpstreamFormatError({ status: statusCode }),
        true
      );
    });
  });

  [401, 403, 407, 408, 429].forEach((statusCode) => {
    test(`${statusCode} is classified as a non-benign upstream format error`, () => {
      assert.strictEqual(
        isBenignUpstreamFormatError({ status: statusCode }),
        false
      );
    });
  });

  test("aggregates all-format upstream data and reuses the shared cache", async () => {
    const { context, updates } = createContext();
    const { checker, getRequestCount } = createResponseAwareChecker(context, {
      python: [
        { name: "PyPI", upstream_url: "https://pypi.org/simple/" },
        { name: "Internal mirror", upstream_url: "https://mirror.example/python" },
        { name: "Legacy", upstream_url: "https://legacy.example/python" },
      ],
      npm: [
        { name: "npmjs", upstream_url: "https://registry.npmjs.org/" },
        { name: "Disabled", upstream_url: "https://disabled.example/npm", is_active: false },
      ],
      docker: [
        { name: "Docker Hub", upstream_url: "https://registry-1.docker.io/" },
      ],
      conda: apiFailure("not_found", { status: 404 }),
    });

    const firstState = await checker.getAllUpstreamData("workspace-a", "repo-a");

    assert.strictEqual(getRequestCount(), SUPPORTED_UPSTREAM_FORMATS.length);
    assert.strictEqual(firstState.total, 6);
    assert.strictEqual(firstState.active, 5);
    assert.deepStrictEqual(firstState.failedFormats, []);
    assert.strictEqual(
      firstState.upstreams.filter((upstream) => upstream._format === "python").length,
      3
    );
    assert.strictEqual(
      firstState.upstreams.find((upstream) => upstream.name === "Docker Hub").format,
      "docker"
    );
    assert.strictEqual(updates.length, 1);
    assert.strictEqual(updates[0].key, "cloudsmith-upstreams:all:workspace-a:repo-a");

    const secondState = await checker.getAllUpstreamData("workspace-a", "repo-a");

    assert.strictEqual(getRequestCount(), SUPPORTED_UPSTREAM_FORMATS.length);
    assert.strictEqual(secondState.total, 6);
    assert.strictEqual(secondState.active, 5);
  });

  test("does not cache partial upstream data when any requested format fails", async () => {
    const { context, updates } = createContext();
    const { checker, getRequestCount } = createResponseAwareChecker(context, {
      python: [
        { name: "PyPI", upstream_url: "https://pypi.org/simple/" },
      ],
      npm: () => {
        return apiFailure("server_error", { status: 503 });
      },
    });

    const firstState = await checker.getUpstreamDataForFormats(
      "workspace-a",
      "repo-a",
      ["python", "npm"]
    );

    assert.deepStrictEqual(firstState.failedFormats, ["npm"]);
    assert.strictEqual(firstState.total, 1);
    assert.strictEqual(firstState.active, 1);
    assert.strictEqual(updates.length, 0);

    await checker.getUpstreamDataForFormats("workspace-a", "repo-a", ["python", "npm"]);

    assert.strictEqual(getRequestCount(), 4);
    assert.strictEqual(updates.length, 0);
  });

  test("evicts cached upstream data with an invalid timestamp before refetching", async () => {
    const { context, store, updates } = createContext();
    const { checker, getRequestCount } = createResponseAwareChecker(context, {});
    const cacheKey = "cloudsmith-upstreams:all:workspace-a:repo-a";

    store.set(cacheKey, createCachedEntry({ timestamp: "123" }));

    const state = await checker.getAllUpstreamData("workspace-a", "repo-a");

    assert.strictEqual(getRequestCount(), SUPPORTED_UPSTREAM_FORMATS.length);
    assert.strictEqual(state.total, 0);
    assert.strictEqual(updates[0].key, cacheKey);
    assert.strictEqual(updates[0].value, undefined);
  });

  test("evicts cached upstream data with an invalid upstream list before refetching", async () => {
    const { context, store, updates } = createContext();
    const { checker, getRequestCount } = createResponseAwareChecker(context, {});
    const cacheKey = "cloudsmith-upstreams:all:workspace-a:repo-a";

    store.set(cacheKey, createCachedEntry({ upstreams: {} }));

    const state = await checker.getAllUpstreamData("workspace-a", "repo-a");

    assert.strictEqual(getRequestCount(), SUPPORTED_UPSTREAM_FORMATS.length);
    assert.strictEqual(state.total, 0);
    assert.strictEqual(updates[0].key, cacheKey);
    assert.strictEqual(updates[0].value, undefined);
  });

  test("returns computed upstream data when cache persistence fails", async () => {
    const context = {
      globalState: {
        get() {
          return undefined;
        },
        async update() {
          throw new Error("quota exceeded");
        },
      },
    };
    const { checker, getRequestCount } = createResponseAwareChecker(context, {
      python: [
        { name: "PyPI", upstream_url: "https://pypi.org/simple/" },
      ],
    });

    const firstState = await checker.getUpstreamDataForFormats(
      "workspace-a",
      "repo-a",
      ["python"]
    );
    const secondState = await checker.getUpstreamDataForFormats(
      "workspace-a",
      "repo-a",
      ["python"]
    );

    assert.strictEqual(firstState.total, 1);
    assert.strictEqual(firstState.active, 1);
    assert.deepStrictEqual(firstState.failedFormats, []);
    assert.strictEqual(secondState.total, 1);
    assert.strictEqual(getRequestCount(), 2);
  });

  test("returns upstream data without an error when partial failures still yield upstreams", async () => {
    const checker = new UpstreamChecker({});
    checker.getAllUpstreamData = async () => ({
      upstreams: [{ name: "PyPI", _format: "python", upstream_url: "https://pypi.org/" }],
      active: 1,
      total: 1,
      failedFormats: ["alpine"],
      successfulFormats: 1,
    });

    const result = await checker.getAllUpstreams("acme", "example-repo");

    assert.strictEqual(result.error, null);
    assert.strictEqual(result.data.length, 1);
    assert.strictEqual(result.data[0].name, "PyPI");
  });

  test("returns an error when formats fail and no upstream data is available", async () => {
    const checker = new UpstreamChecker({});
    checker.getAllUpstreamData = async () => ({
      upstreams: [],
      active: 0,
      total: 0,
      failedFormats: ["python"],
      successfulFormats: 0,
    });

    const result = await checker.getAllUpstreams("acme", "empty-repo");

    assert.strictEqual(result.data.length, 0);
    assert.ok(result.error.includes("python"));
  });

  test("does not cache non-benign empty upstream results", async () => {
    const { context, updates } = createContext();
    const checker = new UpstreamChecker(context);

    checker.api.get = async () => apiFailure("unauthorized", { status: 401 });

    const result = await checker.getUpstreamDataForFormats("acme", "example-repo", ["python"]);

    assert.deepStrictEqual(result.failedFormats, ["python"]);
    assert.strictEqual(result.upstreams.length, 0);
    assert.strictEqual(updates.length, 0);
  });
});

suite("UpstreamChecker preview resolution", () => {
  test("previewResolution does not trigger policy fetches and still returns upstream data", async () => {
    const checker = new UpstreamChecker({});
    let policyFetchCount = 0;

    checker.existsLocally = async () => ({
      data: null,
      error: null,
    });
    checker.getUpstreamsForFormat = async () => ({
      data: [
        {
          name: "PyPI",
          upstream_url: "https://pypi.org/simple/",
          is_active: true,
        },
        {
          name: "Disabled mirror",
          upstream_url: "https://disabled.example/python",
          is_active: false,
        },
      ],
      error: null,
    });
    checker.api.getV2 = async () => {
      policyFetchCount += 1;
      return [];
    };

    const result = await checker.previewResolution("acme", "example-repo", "flask", "python");

    assert.strictEqual(policyFetchCount, 0);
    assert.strictEqual("policies" in result, false);
    assert.strictEqual(result.canResolveViaUpstream, true);
    assert.strictEqual(result.upstreams.data.total, 2);
    assert.strictEqual(result.upstreams.data.active, 1);
    assert.strictEqual(result.upstreams.data.configs[0].name, "PyPI");
  });
});

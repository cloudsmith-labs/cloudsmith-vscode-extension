const assert = require("assert");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { CredentialManager } = require("../util/credentialManager");
const {
  cacheErrorMessage,
  getActiveUpstreamCacheOperationCount,
  getUpstreamCacheKey,
  isBenignUpstreamFormatError,
  MAX_RUNTIME_UPSTREAMS_PER_FORMAT,
  SUPPORTED_UPSTREAM_FORMATS,
  UpstreamChecker,
  UPSTREAM_CACHE_SCHEMA_VERSION,
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

function deferred() {
  let resolve;
  const promise = new Promise(resolvePromise => { resolve = resolvePromise; });
  return { promise, resolve };
}

let accountState;
const connectionManager = {
  getState() { return { ...accountState }; },
  setState(next) { accountState = { ...accountState, ...next }; },
};

function resetAccount() {
  accountState = {
    activationId: "activation-a",
    accountEpoch: 1,
    sessionConnected: true,
  };
}

function createChecker(context, options = {}) {
  return new UpstreamChecker(context, { connectionManager, ...options });
}

suite("UpstreamChecker repository upstream cache", () => {
  let originalGet;
  let originalGetApiKey;
  let formatResponses;
  let requestCount;
  let store;
  let context;

  setup(() => {
    resetAccount();
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
      version: UPSTREAM_CACHE_SCHEMA_VERSION,
      activationId: "activation-a",
      accountEpoch: 1,
      timestamp: Date.now(),
      successfulFormats: 1,
      groupedUpstreams: {
        python: [
          { name: "PyPI", _format: "python", format: "python" },
        ],
      },
      ...overrides,
    };
  }

  async function assertInvalidCachedEntry(entry) {
    const checker = createChecker(context);
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
        {
          name: "PyPI",
          upstream_url: "https://user:path-secret@example.com/path-secret?token=query-secret",
          api_key: "never-persist",
          mode: "proxy_only",
          opaque_metadata: { nested_secret: "nested-secret" },
        },
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

    const checker = createChecker(context);
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
    const persisted = [...store.values()][0];
    assert.strictEqual(persisted.version, UPSTREAM_CACHE_SCHEMA_VERSION);
    assert.strictEqual(persisted.activationId, "activation-a");
    assert.strictEqual(persisted.accountEpoch, 1);
    assert.strictEqual(JSON.stringify(persisted).includes("never-persist"), false);
    assert.strictEqual(JSON.stringify(persisted).includes("path-secret"), false);
    assert.strictEqual(JSON.stringify(persisted).includes("query-secret"), false);
    assert.strictEqual(JSON.stringify(persisted).includes("nested-secret"), false);

    const secondState = await checker.getRepositoryUpstreamState("workspace-a", "repo-a");

    assert.strictEqual(requestCount, SUPPORTED_UPSTREAM_FORMATS.length);
    assert.strictEqual(secondState.total, 6);
    assert.strictEqual(secondState.active, 5);
    assert.strictEqual(secondState.groupedUpstreams.get("python")[0].name, "Internal mirror");
  });

  test("repository workflow inspection requests only the relevant formats", async () => {
    formatResponses = {
      npm: [{ name: "npmjs", upstream_url: "https://registry.npmjs.org/" }],
      python: [{ name: "PyPI", upstream_url: "https://pypi.org/" }],
    };
    const checker = createChecker({});

    const state = await checker.getRepositoryUpstreamStateForFormats(
      "workspace-a",
      "repo-a",
      ["npm"]
    );

    assert.strictEqual(requestCount, 1);
    assert.strictEqual(state.complete, true);
    assert.deepStrictEqual([...state.groupedUpstreams.keys()], ["npm"]);
    assert.deepStrictEqual(state.upstreams.map(upstream => upstream.name), ["npmjs"]);
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

    const checker = createChecker(context);
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

    const checker = createChecker(context);
    const state = await checker.getRepositoryUpstreamState("workspace-a", "repo-a");

    assert.strictEqual(state.active, 0);
    assert.strictEqual(state.total, 0);
    assert.ok(state.failedFormats.includes("python"));
    assert.strictEqual(store.size, 0);
  });

  test("rejects malformed active fields instead of treating them as active upstreams", async () => {
    formatResponses = { python: [{ name: "PyPI", is_active: "false" }] };

    const checker = createChecker(context);
    const state = await checker.getRepositoryUpstreamStateForFormats(
      "workspace-a",
      "repo-a",
      ["python"]
    );

    assert.strictEqual(state.complete, false);
    assert.strictEqual(state.active, 0);
    assert.strictEqual(state.total, 0);
    assert.deepStrictEqual(state.failedFormats, ["python"]);
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

  test("rejects poisoned nested values in a persisted repository envelope", async () => {
    await assertInvalidCachedEntry(createCachedEntry({
      groupedUpstreams: {
        python: [{ name: "PyPI", mode: { token: "nested-secret" } }],
      },
    }));
  });

  test("treats expired cached repository upstream state as invalid", () => {
    const checker = createChecker(context);
    const cacheKey = checker._getRepositoryUpstreamCacheKey("workspace-a", "repo-a");
    store.set(cacheKey, createCachedEntry({ timestamp: Date.now() - (11 * 60 * 1000) }));

    const cachedState = checker._getCachedRepositoryUpstreamState("workspace-a", "repo-a");

    assert.strictEqual(cachedState, null);
  });

  test("accepts a valid cached repository upstream state", () => {
    const checker = createChecker(context);
    const cacheKey = checker._getRepositoryUpstreamCacheKey("workspace-a", "repo-a");
    store.set(cacheKey, createCachedEntry({ successfulFormats: SUPPORTED_UPSTREAM_FORMATS.length }));

    const cachedState = checker._getCachedRepositoryUpstreamState("workspace-a", "repo-a");

    assert.ok(cachedState);
    assert.strictEqual(cachedState.successfulFormats, SUPPORTED_UPSTREAM_FORMATS.length);
    assert.strictEqual(cachedState.total, 1);
    assert.strictEqual(cachedState.active, 1);
    assert.strictEqual(cachedState.groupedUpstreams.get("python").length, 1);
  });

  test("evicts repository cache entries that do not prove every supported format was inspected", async () => {
    const checker = createChecker(context);
    const cacheKey = checker._getRepositoryUpstreamCacheKey("workspace-a", "repo-a");
    store.set(cacheKey, createCachedEntry({ successfulFormats: SUPPORTED_UPSTREAM_FORMATS.length - 1 }));

    assert.strictEqual(checker._getCachedRepositoryUpstreamState("workspace-a", "repo-a"), null);
    await Promise.resolve();
    assert.strictEqual(store.has(cacheKey), false);
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
      const checker = createChecker(context);
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
  setup(() => {
    resetAccount();
  });
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
      version: UPSTREAM_CACHE_SCHEMA_VERSION,
      activationId: "activation-a",
      accountEpoch: 1,
      timestamp: Date.now(),
      upstreams: [
        {
          name: "PyPI",
          _format: "python",
          format: "python",
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
    const checker = createChecker(context);

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
        {
          name: "PyPI",
          upstream_url: "https://user:url-secret@example.com/url-secret?token=url-secret",
          mode: "proxy_only",
          opaque_metadata: { token: "nested-secret" },
        },
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
    assert.strictEqual(
      updates[0].key,
      getUpstreamCacheKey("workspace-a", "repo-a")
    );
    assert.strictEqual(updates[0].value.version, UPSTREAM_CACHE_SCHEMA_VERSION);
    assert.strictEqual(updates[0].value.activationId, "activation-a");
    assert.strictEqual(updates[0].value.accountEpoch, 1);
    assert.strictEqual(JSON.stringify(updates[0].value).includes("url-secret"), false);
    assert.strictEqual(JSON.stringify(updates[0].value).includes("nested-secret"), false);

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

  test("uses collision-free encoded cache tuple keys", () => {
    assert.notStrictEqual(
      getUpstreamCacheKey("workspace:a", "repo"),
      getUpstreamCacheKey("workspace", "a:repo")
    );
    assert.notStrictEqual(
      getUpstreamCacheKey("workspace", "repo", ["python", "npm"]),
      getUpstreamCacheKey("workspace", "repo", ["python"])
    );
  });

  test("retires per-key operation authority after terminal settlement", async () => {
    const { context } = createContext();
    const response = deferred();
    const checker = createChecker(context, {
      cloudsmithAPI: { async get() { return response.promise; } },
    });

    const pending = checker.getUpstreamDataForFormats(
      "workspace-a",
      "repo-a",
      ["python"]
    );
    await new Promise(resolve => setImmediate(resolve));
    assert.strictEqual(getActiveUpstreamCacheOperationCount(context.globalState), 1);
    response.resolve(apiSuccess([]));
    await pending;

    assert.strictEqual(getActiveUpstreamCacheOperationCount(context.globalState), 0);
  });

  test("rejects over-count and over-limit runtime upstream responses before use", async () => {
    const { context, updates } = createContext();
    const checker = createChecker(context, {
      cloudsmithAPI: {
        async get(_endpoint, options) {
          const payload = Array.from(
            { length: MAX_RUNTIME_UPSTREAMS_PER_FORMAT + 1 },
            (_, index) => ({ name: `upstream-${index}` })
          );
          assert.strictEqual(options.validate(payload), false);
          return apiSuccess(payload);
        },
      },
    });

    const countResult = await checker.getUpstreamDataForFormats(
      "workspace-a",
      "repo-a",
      ["python"]
    );
    assert.deepStrictEqual(countResult.failedFormats, ["python"]);
    assert.strictEqual(countResult.total, 0);
    assert.strictEqual(updates.length, 0);

    checker.api.get = async (_endpoint, options) => {
      const payload = [{ name: "x".repeat(501) }];
      assert.strictEqual(options.validate(payload), false);
      return apiSuccess(payload);
    };
    const fieldResult = await checker.getUpstreamDataForFormats(
      "workspace-a",
      "repo-b",
      ["python"]
    );
    assert.deepStrictEqual(fieldResult.failedFormats, ["python"]);
    assert.strictEqual(fieldResult.total, 0);
    assert.strictEqual(updates.length, 0);
  });

  test("cache failure logs never include exception text or account identifiers", async () => {
    const secret = "secret-from-quota-exception";
    const warning = cacheErrorMessage("persist");
    assert.strictEqual(warning, "[UpstreamChecker] Failed to persist upstream cache.");
    assert.strictEqual(warning.includes(secret), false);
    assert.strictEqual(warning.includes("workspace-sensitive"), false);
    assert(warning.length < 100);
  });

  test("evicts cached upstream data with an invalid timestamp before refetching", async () => {
    const { context, store, updates } = createContext();
    const { checker, getRequestCount } = createResponseAwareChecker(context, {});
    const cacheKey = getUpstreamCacheKey("workspace-a", "repo-a");

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
    const cacheKey = getUpstreamCacheKey("workspace-a", "repo-a");

    store.set(cacheKey, createCachedEntry({ upstreams: {} }));

    const state = await checker.getAllUpstreamData("workspace-a", "repo-a");

    assert.strictEqual(getRequestCount(), SUPPORTED_UPSTREAM_FORMATS.length);
    assert.strictEqual(state.total, 0);
    assert.strictEqual(updates[0].key, cacheKey);
    assert.strictEqual(updates[0].value, undefined);
  });

  test("evicts flat cache entries whose completion count does not match the requested formats", async () => {
    const { context, store, updates } = createContext();
    const { checker, getRequestCount } = createResponseAwareChecker(context, {});
    const cacheKey = getUpstreamCacheKey("workspace-a", "repo-a", ["python", "npm"]);
    store.set(cacheKey, createCachedEntry({ successfulFormats: 1 }));

    const result = await checker.getUpstreamDataForFormats(
      "workspace-a",
      "repo-a",
      ["python", "npm"]
    );

    assert.strictEqual(getRequestCount(), 2);
    assert.strictEqual(result.complete, true);
    assert.strictEqual(updates[0].key, cacheKey);
    assert.strictEqual(updates[0].value, undefined);
  });

  test("bypassCache refetches runtime upstream details instead of serving a summary-only warm cache", async () => {
    const { context, store } = createContext();
    const { checker, getRequestCount } = createResponseAwareChecker(context, {
      python: [{ name: "PyPI", upstream_url: "https://pypi.org/simple/" }],
    });
    const cacheKey = getUpstreamCacheKey("workspace-a", "repo-a", ["python"]);
    store.set(cacheKey, createCachedEntry());

    const result = await checker.getUpstreamDataForFormats(
      "workspace-a",
      "repo-a",
      ["python"],
      { bypassCache: true }
    );

    assert.strictEqual(getRequestCount(), 1);
    assert.strictEqual(result.upstreams[0].upstream_url, "https://pypi.org/simple/");
  });

  test("evicts cached upstream summaries with duplicate, conflicting, or stale derived metadata", async () => {
    const { context, store, updates } = createContext();
    const { checker } = createResponseAwareChecker(context, {});
    const cacheKey = getUpstreamCacheKey("workspace-a", "repo-a", ["python"]);
    for (const poisoned of [
      createCachedEntry({
        upstreams: [
          { name: "PyPI", _format: "python", format: "python", is_active: true },
          { name: "PyPI", _format: "python", format: "python", is_active: true },
        ],
        active: 2,
        total: 2,
      }),
      createCachedEntry({
        upstreams: [{ name: "PyPI", _format: "python", format: "npm", is_active: true }],
      }),
      createCachedEntry({ active: 0 }),
    ]) {
      store.set(cacheKey, poisoned);
      await checker.getUpstreamDataForFormats("workspace-a", "repo-a", ["python"]);
      assert.strictEqual(updates[updates.length - 2].value, undefined);
    }
  });

  test("rejects duplicate and format-conflicting upstream records", async () => {
    const { checker } = createResponseAwareChecker(createContext().context, {
      python: [
        { name: "PyPI", format: "python" },
        { name: "PyPI", format: "python" },
      ],
      npm: [{ name: "npmjs", format: "python" }],
    });

    const duplicate = await checker.getUpstreamDataForFormats(
      "workspace-a",
      "repo-a",
      ["python"]
    );
    const conflicting = await checker.getUpstreamDataForFormats(
      "workspace-a",
      "repo-b",
      ["npm"]
    );

    assert.deepStrictEqual(duplicate.upstreams, []);
    assert.deepStrictEqual(duplicate.failedFormats, ["python"]);
    assert.strictEqual(duplicate.complete, false);
    assert.deepStrictEqual(conflicting.failedFormats, ["npm"]);
  });

  test("evicts a flat cache envelope containing nested secret-bearing fields", async () => {
    const { context, store, updates } = createContext();
    const { checker } = createResponseAwareChecker(context, {});
    const cacheKey = getUpstreamCacheKey("workspace-a", "repo-a");
    store.set(cacheKey, createCachedEntry({
      upstreams: [{
        name: "PyPI",
        _format: "python",
        format: "python",
        mode: { token: "nested-secret" },
        is_active: true,
      }],
    }));

    await checker.getAllUpstreamData("workspace-a", "repo-a");

    assert.strictEqual(updates[0].key, cacheKey);
    assert.strictEqual(updates[0].value, undefined);
  });

  test("evicts persisted strings beyond the strict field bound", async () => {
    const { context, store, updates } = createContext();
    const { checker } = createResponseAwareChecker(context, {});
    const cacheKey = getUpstreamCacheKey("workspace-a", "repo-a");
    store.set(cacheKey, createCachedEntry({
      upstreams: [{ name: "x".repeat(501), _format: "python", format: "python" }],
    }));

    await checker.getAllUpstreamData("workspace-a", "repo-a");

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
    const checker = createChecker({});
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
    const checker = createChecker({});
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
    const checker = createChecker(context);

    checker.api.get = async () => apiFailure("unauthorized", { status: 401 });

    const result = await checker.getUpstreamDataForFormats("acme", "example-repo", ["python"]);

    assert.deepStrictEqual(result.failedFormats, ["python"]);
    assert.strictEqual(result.upstreams.length, 0);
    assert.strictEqual(updates.length, 0);
  });

  test("does not publish or persist an upstream response after account supersession", async () => {
    const { context, updates } = createContext();
    let release;
    const response = new Promise(resolve => { release = resolve; });
    const checker = createChecker(context, {
      cloudsmithAPI: { async get() { return response; } },
    });
    const pending = checker.getUpstreamDataForFormats("acme", "repo", ["python"]);
    await new Promise(resolve => setImmediate(resolve));
    connectionManager.setState({ accountEpoch: 2 });
    release(apiSuccess([{ name: "Old PyPI", upstream_url: "https://old.example" }]));

    assert.strictEqual(await pending, null);
    assert.strictEqual(updates.length, 0);
  });
});

suite("UpstreamChecker preview resolution", () => {
  setup(() => resetAccount());

  test("local package lookup discovers later pages with strict bounded pagination", async () => {
    const calls = [];
    const firstPage = Array.from({ length: 100 }, (_value, index) => ({
      name: `other-${index}`,
      format: "python",
      namespace: "acme",
      repository: "example-repo",
      slug_perm: `other-${index}`,
    }));
    const checker = createChecker({}, {
      cloudsmithAPI: {
        async get(endpoint) {
          const pageNumber = Number(new URL(`https://example.test/${endpoint}`).searchParams.get("page"));
          calls.push(pageNumber);
          const data = pageNumber === 1 ? firstPage : [{
            name: "flask",
            format: "python",
            namespace: "acme",
            repository: "example-repo",
            slug_perm: "flask-1",
          }];
          return apiSuccess(data, {
            headers: {
              "x-pagination-page": String(pageNumber),
              "x-pagination-pagetotal": "2",
              "x-pagination-count": "101",
              "x-pagination-pagesize": "100",
            },
          });
        },
      },
    });

    const result = await checker.existsLocally(
      "acme",
      "example-repo",
      "flask",
      "python"
    );

    assert.strictEqual(result.data.slug_perm, "flask-1");
    assert.strictEqual(result.complete, true);
    assert.deepStrictEqual(calls, [1, 2]);
  });

  test("local package lookup short-circuits after a validated positive page", async () => {
    const calls = [];
    const firstPage = Array.from({ length: 100 }, (_value, index) => ({
      name: index === 0 ? "flask" : `other-${index}`,
      format: "python",
      namespace: "acme",
      repository: "example-repo",
      slug_perm: `package-${index}`,
    }));
    const checker = createChecker({}, {
      cloudsmithAPI: {
        async get(endpoint) {
          const pageNumber = Number(new URL(`https://example.test/${endpoint}`).searchParams.get("page"));
          calls.push(pageNumber);
          if (pageNumber === 2) return apiFailure("rate_limited", { status: 429 });
          return apiSuccess(firstPage, {
            headers: {
              "x-pagination-page": "1",
              "x-pagination-pagetotal": "2",
              "x-pagination-count": "200",
              "x-pagination-pagesize": "100",
            },
          });
        },
      },
    });

    const result = await checker.existsLocally(
      "acme",
      "example-repo",
      "flask",
      "python"
    );

    assert.strictEqual(result.data.slug_perm, "package-0");
    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.error, null);
    assert.deepStrictEqual(calls, [1]);
  });

  test("previewResolution does not trigger policy fetches and still returns upstream data", async () => {
    const checker = createChecker({});
    let policyFetchCount = 0;

    checker.existsLocally = async () => ({
      data: null,
      error: null,
      complete: true,
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

  test("previewResolution settles sibling failures and exposes only normalized error strings", async () => {
    const checker = createChecker({});
    checker.existsLocally = async () => {
      throw new Error("https://user:pass@example.com/private?token=secret\nprivate stack");
    };
    checker.getUpstreamsForFormat = async () => ({
      data: [{ name: "PyPI", upstream_url: "https://pypi.org/simple/", is_active: true }],
      error: null,
      complete: true,
    });

    const result = await checker.previewResolution("acme", "repo", "flask", "python");

    assert.strictEqual(result.local.errorMessage, "The local package collection could not be verified.");
    assert.strictEqual(typeof result.local.errorMessage, "string");
    assert.strictEqual(result.upstreams.data.total, 1);
    assert.strictEqual(result.canResolveViaUpstream, true);
    assert.ok(!JSON.stringify(result).includes("user:pass"));
    assert.ok(!JSON.stringify(result).includes("token=secret"));
  });

  test("previewResolution normalizes structured upstream failures", async () => {
    const checker = createChecker({});
    checker.existsLocally = async () => ({ data: null, error: null, complete: true });
    checker.getUpstreamsForFormat = async () => ({
      data: [],
      error: { message: "Upstream request failed", status: 500, body: "private body" },
      complete: false,
    });

    const result = await checker.previewResolution("acme", "repo", "flask", "python");
    assert.strictEqual(result.upstreams.errorMessage, "Upstream request failed");
    assert.strictEqual("error" in result.upstreams, false);
    assert.ok(!JSON.stringify(result).includes("private body"));
  });
});

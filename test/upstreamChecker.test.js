// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { CredentialManager } = require("../util/credentialManager");
const {
  sanitizeSafeInventoryUpstream,
  UpstreamChecker,
} = require("../util/upstreamChecker");
const {
  INSPECTABLE_UPSTREAM_FORMATS,
  SUPPORTED_UPSTREAM_FORMATS,
} = require("../util/upstreamFormats");
const { UpstreamOperationScheduler } = require("../util/upstreamOperationScheduler");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");

const MAX_RUNTIME_UPSTREAMS_PER_FORMAT = 500;
const UPSTREAM_CACHE_SCHEMA_VERSION = 5;

function getUpstreamCacheKey(workspace, repo, formats = SUPPORTED_UPSTREAM_FORMATS) {
  const normalizedFormats = [...new Set(formats.map(format => format.toLowerCase()))].sort();
  const canonicalAllFormats = [...SUPPORTED_UPSTREAM_FORMATS].sort();
  const isAllFormats = normalizedFormats.length === canonicalAllFormats.length
    && normalizedFormats.every((format, index) => format === canonicalAllFormats[index]);
  const tuple = isAllFormats
    ? ["all", workspace, repo]
    : ["formats", workspace, repo, normalizedFormats];
  return `cloudsmith-upstreams:v5:${encodeURIComponent(JSON.stringify(tuple))}`;
}

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
      const match = endpoint.match(/upstream\/([^/?]+)\/(?:\?.*)?$/);
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
    };

    const checker = createChecker(context);
    const firstState = await checker.getRepositoryUpstreamState("workspace-a", "repo-a");

    assert.strictEqual(requestCount, INSPECTABLE_UPSTREAM_FORMATS.length);
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

    assert.strictEqual(requestCount, INSPECTABLE_UPSTREAM_FORMATS.length);
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
    assert.strictEqual(firstState.total, null);
    assert.strictEqual(firstState.loadedCount, 1);
    assert.strictEqual(firstState.active, 1);
    assert.strictEqual(store.size, 0);

    await checker.getRepositoryUpstreamState("workspace-a", "repo-a");

    assert.strictEqual(requestCount, INSPECTABLE_UPSTREAM_FORMATS.length * 2);
    assert.strictEqual(store.size, 0);
  });

  test("rejects blank upstream records instead of reporting false active reachability", async () => {
    formatResponses = { python: [{}] };

    const checker = createChecker(context);
    const state = await checker.getRepositoryUpstreamState("workspace-a", "repo-a");

    assert.strictEqual(state.active, 0);
    assert.strictEqual(state.total, null);
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
    assert.strictEqual(state.total, null);
    assert.deepStrictEqual(state.failedFormats, ["python"]);
    assert.strictEqual(store.size, 0);
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
          origin: "https://pypi.org",
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
      const match = endpoint.match(/upstream\/([^/?]+)\/(?:\?.*)?$/);
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
    });

    const firstState = await checker.getAllUpstreamData("workspace-a", "repo-a");

    assert.strictEqual(getRequestCount(), INSPECTABLE_UPSTREAM_FORMATS.length);
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
    const redacted = updates[0].value.upstreams.find(upstream => upstream.name === "PyPI");
    assert.strictEqual(redacted.origin, "");

    const secondState = await checker.getAllUpstreamData("workspace-a", "repo-a");

    assert.strictEqual(getRequestCount(), INSPECTABLE_UPSTREAM_FORMATS.length);
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
    assert.strictEqual(firstState.total, null);
    assert.strictEqual(firstState.loadedCount, 1);
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
    assert.strictEqual(checker.cacheLifecycle.activeOperationCount, 1);
    response.resolve(apiSuccess([]));
    await pending;

    assert.strictEqual(checker.cacheLifecycle.activeOperationCount, 0);
  });

  test("bounds optional cache persistence and contains a late write failure", async () => {
    const { context } = createContext();
    let rejectUpdate;
    const update = new Promise((_resolve, reject) => {
      rejectUpdate = reject;
    });
    let updateCalls = 0;
    context.globalState.update = async () => {
      updateCalls += 1;
      return update;
    };
    const checker = createChecker(context, {
      cacheWriteWaitMs: 5,
      cloudsmithAPI: {
        async get() {
          return apiSuccess([]);
        },
      },
    });
    const originalWarn = console.warn;
    const warnings = [];
    console.warn = warning => warnings.push(warning);

    try {
      const state = await Promise.race([
        checker.getUpstreamDataForFormats("workspace-a", "repo-a", ["npm"]),
        new Promise((_resolve, reject) => {
          setTimeout(() => reject(new Error("optional cache write blocked the result")), 250);
        }),
      ]);

      assert.strictEqual(state.complete, true);
      assert.strictEqual(state.total, 0);
      assert.strictEqual(updateCalls, 1);
      assert.strictEqual(checker.cacheLifecycle.activeOperationCount, 0);

      rejectUpdate(new Error("late persistence secret"));
      await new Promise(resolve => setImmediate(resolve));
      assert.deepStrictEqual(warnings, []);
      assert.doesNotMatch(warnings.join(" "), /late persistence secret/);
    } finally {
      console.warn = originalWarn;
    }
  });

  test("caps the optional cache persistence wait configured by callers", () => {
    const checker = createChecker({}, { cacheWriteWaitMs: Number.MAX_SAFE_INTEGER });
    assert.strictEqual(checker._cacheWriteWaitMs, 1_000);
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
    assert.strictEqual(countResult.total, null);
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
    assert.strictEqual(fieldResult.total, null);
    assert.strictEqual(updates.length, 0);
  });

  test("evicts cached upstream data with an invalid timestamp before refetching", async () => {
    const { context, store, updates } = createContext();
    const { checker, getRequestCount } = createResponseAwareChecker(context, {});
    const cacheKey = getUpstreamCacheKey("workspace-a", "repo-a");

    store.set(cacheKey, createCachedEntry({ timestamp: "123" }));

    const state = await checker.getAllUpstreamData("workspace-a", "repo-a");

    assert.strictEqual(getRequestCount(), INSPECTABLE_UPSTREAM_FORMATS.length);
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

    assert.strictEqual(getRequestCount(), INSPECTABLE_UPSTREAM_FORMATS.length);
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
    assert.strictEqual(result.upstreams[0].upstream_url, undefined);
    assert.strictEqual(result.upstreams[0].origin, "https://pypi.org");
  });

  test("evicts cached upstream summaries with duplicate, conflicting, or stale derived metadata", async () => {
    const { context, store, updates } = createContext();
    const { checker } = createResponseAwareChecker(context, {});
    const cacheKey = getUpstreamCacheKey("workspace-a", "repo-a", ["python"]);
    for (const poisoned of [
      createCachedEntry({
        upstreams: [
          { name: "PyPI", _format: "python", format: "python", origin: "", is_active: true },
          { name: "PyPI", _format: "python", format: "python", origin: "", is_active: true },
        ],
        active: 2,
        total: 2,
      }),
      createCachedEntry({
        upstreams: [{ name: "PyPI", _format: "python", format: "npm", origin: "", is_active: true }],
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
        { name: "PyPI", format: "python", upstream_url: "https://pypi.org" },
        { name: "PyPI", format: "python", upstream_url: "https://pypi.org" },
      ],
      npm: [{ name: "npmjs", format: "python", upstream_url: "https://npmjs.org" }],
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

    assert.deepStrictEqual(duplicate.upstreams.map(upstream => upstream.name), ["PyPI"]);
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
        origin: "https://pypi.org",
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
      upstreams: [{
        name: "x".repeat(501), _format: "python", format: "python", origin: "",
      }],
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

  test("accepts documented nullable fields while keeping inventory entries secret-free", async () => {
    const { checker, getRequestCount } = createResponseAwareChecker({}, {
      python: [{
        name: "PyPI",
        slug_perm: "pypi",
        upstream_url: "https://user:password@pypi.org/simple?token=secret#signed",
        auth_username: null,
        auth_secret: null,
        extra_header_1: null,
        extra_value_1: null,
        index_package_count: null,
        index_status: null,
        is_active: true,
        verify_ssl: false,
        priority: 0,
        distro_versions: [],
      }],
    });

    const result = await checker.getUpstreamDataForFormats(
      "workspace-a", "repo-a", ["python"]
    );

    assert.strictEqual(getRequestCount(), 1);
    assert.strictEqual(result.complete, true);
    assert.strictEqual(result.configuredTotal, 1);
    assert.strictEqual(result.upstreams[0].slug_perm, "pypi");
    assert.strictEqual(result.upstreams[0].origin, "");
    const serialized = JSON.stringify(result);
    for (const secret of ["password", "token=secret", "auth_secret", "extra_value_1"]) {
      assert.strictEqual(serialized.includes(secret), false);
    }
  });

  test("creates fresh safe inventory projections from plain own data properties only", () => {
    const source = Object.assign(Object.create(null), {
      name: "PyPI",
      _format: "python",
      format: "python",
      origin: "",
      verify_ssl: false,
      priority: 0,
      distro_versions: ["3.12"],
    });
    const sanitized = sanitizeSafeInventoryUpstream(source, "python");

    assert.ok(sanitized);
    assert.notStrictEqual(sanitized, source);
    assert.strictEqual(Object.getPrototypeOf(sanitized), Object.prototype);
    assert.ok(Object.isFrozen(sanitized));
    assert.ok(Object.isFrozen(sanitized.distro_versions));
    assert.notStrictEqual(sanitized.distro_versions, source.distro_versions);
    assert.strictEqual(sanitized.origin, "");

    const inherited = Object.create(source);
    assert.strictEqual(sanitizeSafeInventoryUpstream(inherited, "python"), null);

    let getterReads = 0;
    const accessor = { ...source };
    Object.defineProperty(accessor, "name", {
      enumerable: true,
      get() {
        getterReads += 1;
        return "Accessor PyPI";
      },
    });
    assert.strictEqual(sanitizeSafeInventoryUpstream(accessor, "python"), null);
    assert.strictEqual(getterReads, 0);

    let proxyReads = 0;
    const proxy = new Proxy({ ...source }, {
      get(target, property, receiver) {
        proxyReads += 1;
        return Reflect.get(target, property, receiver);
      },
    });
    assert.strictEqual(sanitizeSafeInventoryUpstream(proxy, "python"), null);
    assert.strictEqual(proxyReads, 0);
  });

  test("validates canonical embedded formats without inventing an expected-format hint", () => {
    const canonical = {
      name: "npmjs",
      _format: "npm",
      format: "npm",
      origin: "https://registry.npmjs.org",
    };

    assert.deepStrictEqual(
      sanitizeSafeInventoryUpstream(canonical),
      canonical
    );
    for (const candidate of [
      { name: "mixed", _format: "npm", format: "python", origin: "" },
      { name: "mixed", _format: "python", format: "npm", origin: "" },
      { name: "missing internal format", format: "npm", origin: "" },
      { name: "missing public format", _format: "npm", origin: "" },
      { name: "unsupported", _format: "terraform", format: "terraform", origin: "" },
      { name: "unknown", _format: "not-a-format", format: "not-a-format", origin: "" },
    ]) {
      assert.strictEqual(sanitizeSafeInventoryUpstream(candidate), null, candidate.name);
    }
    assert.strictEqual(
      sanitizeSafeInventoryUpstream({ ...canonical, origin: "" }, "python"),
      null
    );
  });

  test("rejects inherited, accessor, and format-conflicting API upstream records", async () => {
    const inherited = Object.create({
      name: "Inherited",
      upstream_url: "https://inherited.example",
    });
    const accessor = { upstream_url: "https://accessor.example" };
    Object.defineProperty(accessor, "name", {
      enumerable: true,
      get() {
        throw new Error("Getter must not execute");
      },
    });
    for (const [repo, record] of [
      ["inherited", inherited],
      ["accessor", accessor],
      ["mismatch", {
        name: "Wrong format",
        format: "npm",
        _format: "npm",
        upstream_url: "https://mismatch.example",
      }],
    ]) {
      const { checker } = createResponseAwareChecker(createContext().context, {
        python: [record],
      });
      const result = await checker.getUpstreamDataForFormats(
        "workspace-a", repo, ["python"]
      );
      assert.deepStrictEqual(result.upstreams, [], repo);
      assert.deepStrictEqual(result.failedFormats, ["python"], repo);
      assert.strictEqual(result.failures[0].category, "invalid_response", repo);
    }
  });

  test("preserves the redacted origin sentinel across the v5 cache boundary", async () => {
    const { context, store } = createContext();
    const { checker, getRequestCount } = createResponseAwareChecker(context, {
      python: [{
        name: "Private PyPI",
        slug_perm: "private-pypi",
        upstream_url: "https://user:password@example.com/private?token=secret#signed",
        priority: "10",
        verify_ssl: false,
        index_package_count: 0,
      }],
    });

    const cold = await checker.getUpstreamDataForFormats(
      "workspace-a", "repo-a", ["python"]
    );
    const warm = await checker.getUpstreamDataForFormats(
      "workspace-a", "repo-a", ["PYTHON"]
    );

    assert.strictEqual(getRequestCount(), 1);
    assert.deepStrictEqual(warm.upstreams, cold.upstreams);
    assert.strictEqual(cold.upstreams[0].origin, "");
    assert.strictEqual(cold.upstreams[0].priority, "10");
    const persisted = [...store.values()][0];
    assert.strictEqual(persisted.version, UPSTREAM_CACHE_SCHEMA_VERSION);
    assert.strictEqual(persisted.upstreams[0].origin, "");
    assert.ok(!JSON.stringify(persisted).includes("password"));
    assert.ok(!JSON.stringify(persisted).includes("token=secret"));
  });

  test("evicts prior-schema and noncanonical-origin cache entries", async () => {
    const cases = [
      createCachedEntry({ version: 4 }),
      createCachedEntry({ upstreams: [{
        name: "PyPI", _format: "python", format: "python",
        origin: "https://user:password@example.com",
      }] }),
      createCachedEntry({ upstreams: [{
        name: "PyPI", _format: "python", format: "python",
        origin: "https://example.com/path?token=secret#fragment",
      }] }),
      createCachedEntry({ upstreams: [{
        name: "PyPI", _format: "python", format: "python", origin: " ",
      }] }),
      createCachedEntry({ upstreams: [{
        name: "PyPI", _format: "python", format: "python",
        origin: "", api_key: "secret",
      }] }),
    ];
    for (const [index, cached] of cases.entries()) {
      const { context, store, updates } = createContext();
      const { checker } = createResponseAwareChecker(context, {});
      const key = getUpstreamCacheKey("workspace-a", `repo-${index}`, ["python"]);
      store.set(key, cached);
      await checker.getUpstreamDataForFormats(
        "workspace-a", `repo-${index}`, ["python"]
      );
      assert.strictEqual(updates[0].value, undefined, `case ${index}`);
    }
  });

  test("repository-state format wrapper validates original identities before canonicalization", async () => {
    const checker = createChecker({});
    await assert.rejects(
      checker.getRepositoryUpstreamStateForFormats(
        "workspace-a", "repo-a", ["npm", "unknown"]
      ),
      /unrecognized format/
    );
    await assert.rejects(
      checker.getRepositoryUpstreamStateForFormats(
        "workspace-a", "repo-a", ["npm", null]
      ),
      /unrecognized format/
    );
  });

  test("does not issue requests for recognized formats without an upstream API", async () => {
    const { checker, getRequestCount } = createResponseAwareChecker({}, {});

    const result = await checker.getUpstreamDataForFormats(
      "workspace-a", "repo-a", ["cocoapods", "conan", "luarocks", "raw", "terraform", "vagrant"]
    );

    assert.strictEqual(getRequestCount(), 0);
    assert.deepStrictEqual(result.unsupportedFormats, [
      "cocoapods", "conan", "luarocks", "raw", "terraform", "vagrant",
    ]);
    assert.deepStrictEqual(result.failedFormats, []);
    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.configuredTotal, null);
    assert.strictEqual(result.state, "unsupported");
  });

  test("normalizes each transport failure category without treating 404 as empty", async () => {
    const cases = [
      ["unauthorized", 401, "authentication"],
      ["forbidden", 403, "permission"],
      ["not_found", 404, "not_found"],
      ["timeout", 408, "timeout"],
      ["rate_limited", 429, "rate_limit"],
      ["server_error", 503, "server"],
    ];
    for (const [kind, status, category] of cases) {
      const checker = createChecker({}, {
        cloudsmithAPI: {
          async get() {
            const result = apiFailure(kind, { status, requestId: `local-${status}` });
            result.serverRequestId = `server-${status}`;
            return result;
          },
        },
      });
      const result = await checker.getUpstreamDataForFormats(
        "workspace-a", `repo-${status}`, ["python"]
      );
      assert.strictEqual(result.complete, false);
      assert.strictEqual(result.configuredTotal, null);
      assert.strictEqual(result.failures[0].category, category);
      assert.strictEqual(result.failures[0].httpStatus, status);
      assert.strictEqual(result.failures[0].requestId, `local-${status}`);
      assert.strictEqual(result.failures[0].serverRequestId, `server-${status}`);
    }
  });

  test("collects every validated upstream page and rejects duplicate canonical identities", async () => {
    const calls = [];
    const checker = createChecker({}, {
      cloudsmithAPI: {
        async get(endpoint) {
          calls.push(endpoint);
          const page = Number(new URL(`https://api.cloudsmith.io/v1/${endpoint}`).searchParams.get("page"));
          const data = page === 1
            ? [{ name: "First", slug_perm: "first", upstream_url: "https://first.example/path" }]
            : [{ name: "Second", slug_perm: "second", upstream_url: "https://second.example/path" }];
          return apiSuccess(data, { headers: {
            "x-pagination-page": String(page),
            "x-pagination-pagetotal": "2",
            "x-pagination-count": "2",
            "x-pagination-pagesize": "1",
          } });
        },
      },
    });

    const complete = await checker.getUpstreamDataForFormats(
      "workspace-a", "repo-a", ["python"]
    );
    assert.strictEqual(calls.length, 2);
    assert.strictEqual(complete.complete, true);
    assert.deepStrictEqual(complete.upstreams.map(upstream => upstream.slug_perm), ["first", "second"]);

    checker.api.get = async () => apiSuccess([
      { name: "Duplicate", slug_perm: "same", upstream_url: "https://example.com" },
      { name: "Other label", slug_perm: "same", upstream_url: "https://example.org" },
    ]);
    const duplicate = await checker.getUpstreamDataForFormats(
      "workspace-a", "repo-b", ["python"], { bypassCache: true }
    );
    assert.deepStrictEqual(duplicate.failedFormats, ["python"]);
    assert.strictEqual(duplicate.configuredTotal, null);
  });

  test("keeps headerless non-empty data partial but accepts headerless empty as authoritative", async () => {
    const checker = createChecker({}, {
      cloudsmithAPI: {
        async get() {
          return apiSuccess(
            [{ name: "PyPI", slug_perm: "pypi", upstream_url: "https://pypi.org/simple" }],
            { headers: {} }
          );
        },
      },
    });
    const partial = await checker.getUpstreamDataForFormats(
      "workspace-a", "repo-a", ["python"]
    );
    assert.strictEqual(partial.state, "partial");
    assert.strictEqual(partial.loadedCount, 1);
    assert.strictEqual(partial.configuredTotal, null);

    checker.api.get = async () => apiSuccess([], { headers: {} });
    const empty = await checker.getUpstreamDataForFormats(
      "workspace-a", "repo-b", ["python"]
    );
    assert.strictEqual(empty.state, "empty");
    assert.strictEqual(empty.configuredTotal, 0);
  });

  test("bounds aggregate concurrency at four and settles the operation deadline", async () => {
    let active = 0;
    let maxActive = 0;
    const checker = createChecker({}, {
      cloudsmithAPI: {
        async get(_endpoint, options) {
          active += 1;
          maxActive = Math.max(maxActive, active);
          await new Promise(resolve => setImmediate(resolve));
          active -= 1;
          if (options.signal.aborted) return apiFailure("cancelled");
          return apiSuccess([]);
        },
      },
    });
    const complete = await checker.getAllUpstreamData("workspace-a", "repo-a");
    assert.strictEqual(complete.requestCount, INSPECTABLE_UPSTREAM_FORMATS.length);
    assert.ok(maxActive <= 4);

    checker.api.get = async (_endpoint, options) => new Promise((resolve) => {
      options.signal.addEventListener("abort", () => resolve(apiFailure("cancelled")), { once: true });
    });
    const timed = await checker.getUpstreamDataForFormats(
      "workspace-a", "repo-b", ["python", "npm"], { operationTimeoutMs: 5 }
    );
    assert.strictEqual(timed.complete, false);
    assert.deepStrictEqual([...timed.uninspectedFormats].sort(), ["npm", "python"]);
    assert.ok(timed.failures.every(failure => (
      failure.category === "timeout" && failure.retryable === true
    )));

    const controller = new AbortController();
    checker.api.get = async (_endpoint, options) => new Promise((resolve) => {
      options.signal.addEventListener("abort", () => resolve(apiFailure("cancelled")), { once: true });
    });
    const cancelledPromise = checker.getUpstreamDataForFormats(
      "workspace-a", "repo-c", ["python"], { signal: controller.signal }
    );
    controller.abort();
    const cancelled = await cancelledPromise;
    assert.strictEqual(cancelled.state, "cancelled");
    assert.strictEqual(cancelled.failures[0].category, "cancelled");
  });

  test("settles the operation deadline when an active transport ignores abort", async () => {
    let rejectLate;
    const unhandled = [];
    const onUnhandled = reason => unhandled.push(reason);
    process.on("unhandledRejection", onUnhandled);
    const checker = createChecker({}, {
      cloudsmithAPI: {
        async get() {
          return new Promise((_resolve, reject) => {
            rejectLate = reject;
          });
        },
      },
    });

    try {
      const timed = await Promise.race([
        checker.getUpstreamDataForFormats(
          "workspace-a", "repo-hung", ["npm"], { operationTimeoutMs: 5 }
        ),
        new Promise((_resolve, reject) => {
          setTimeout(() => reject(new Error("true deadline did not settle")), 250);
        }),
      ]);

      assert.strictEqual(timed.complete, false);
      assert.deepStrictEqual(timed.uninspectedFormats, ["npm"]);
      assert.strictEqual(timed.failures[0].category, "timeout");
      assert.strictEqual(timed.failures[0].retryable, true);

      const snapshot = JSON.stringify(timed);
      rejectLate(new Error("late transport failure"));
      await new Promise(resolve => setImmediate(resolve));
      await new Promise(resolve => setImmediate(resolve));
      assert.strictEqual(JSON.stringify(timed), snapshot);
      assert.deepStrictEqual(unhandled, []);
    } finally {
      process.removeListener("unhandledRejection", onUnhandled);
    }
  });

  test("external cancellation retires a non-cooperative shared-scheduler request", async () => {
    let rejectLate;
    const checker = createChecker({}, {
      cloudsmithAPI: {
        async get() {
          return new Promise((_resolve, reject) => {
            rejectLate = reject;
          });
        },
      },
    });
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 10 });
    const controller = new AbortController();
    const pending = checker.getUpstreamDataForFormats(
      "workspace-a",
      "repo-cancelled",
      ["npm"],
      { operationTimeoutMs: 1_000, scheduler, signal: controller.signal }
    );
    await new Promise(resolve => setImmediate(resolve));
    assert.strictEqual(scheduler.activeCount, 1);

    controller.abort();
    const cancelled = await Promise.race([
      pending,
      new Promise((_resolve, reject) => {
        setTimeout(() => reject(new Error("external cancellation did not settle")), 250);
      }),
    ]);

    assert.strictEqual(cancelled.state, "cancelled");
    assert.strictEqual(cancelled.failures[0].category, "cancelled");
    assert.strictEqual(scheduler.activeCount, 0);
    assert.strictEqual(scheduler.queuedCount, 0);
    assert.strictEqual(scheduler.stopped, false);

    rejectLate(new Error("late cancelled transport failure"));
    await new Promise(resolve => setImmediate(resolve));
  });

  test("rejects malformed repository and format scopes without claiming empty success", async () => {
    const checker = createChecker();
    await assert.rejects(
      checker.getUpstreamDataForFormats("", "repo-a", ["python"]),
      /repository identity/
    );
    await assert.rejects(
      checker.getUpstreamDataForFormats("w".repeat(501), "repo-a", ["python"]),
      /repository identity/
    );
    await assert.rejects(
      checker.getUpstreamDataForFormats("workspace-a", "repo-a", null),
      /formats must be an array/
    );
    await assert.rejects(
      checker.getUpstreamDataForFormats("workspace-a", "repo-a", ["unknown"]),
      /unrecognized format/
    );
    await assert.rejects(
      checker.getUpstreamDataForFormats("workspace-a", "repo-a", ["python", "unknown"]),
      /unrecognized format/
    );
    const deliberateEmpty = await checker.getUpstreamDataForFormats(
      "workspace-a", "repo-a", []
    );
    assert.strictEqual(deliberateEmpty.state, "empty");
    const unsupported = await checker.getUpstreamDataForFormats(
      "workspace-a", "repo-a", ["raw"]
    );
    assert.strictEqual(unsupported.state, "unsupported");
    assert.strictEqual(unsupported.complete, false);
  });

  test("rejects cross-page upstream pagination drift while retaining verified data", async () => {
    let page = 0;
    const checker = createChecker({}, {
      cloudsmithAPI: {
        async get() {
          page += 1;
          return apiSuccess([{
            name: `Mirror ${page}`,
            slug_perm: `mirror-${page}`,
            upstream_url: `https://mirror-${page}.example`,
          }], {
            headers: {
              "x-pagination-page": String(page),
              "x-pagination-pagetotal": String(page === 1 ? 2 : 3),
              "x-pagination-count": String(page === 1 ? 2 : 3),
              "x-pagination-pagesize": "1",
            },
          });
        },
      },
    });
    const result = await checker.getUpstreamDataForFormats(
      "workspace-a", "repo-a", ["python"]
    );
    assert.strictEqual(result.state, "partial");
    assert.strictEqual(result.loadedCount, 2);
    assert.strictEqual(result.failures[0].category, "invalid_response");
  });

  test("uses one canonical loader for safe and privileged projections", async () => {
    const endpoints = [];
    const checker = createChecker({}, {
      cloudsmithAPI: {
        async get(endpoint) {
          endpoints.push(endpoint);
          return apiSuccess([{
            name: "Private",
            slug_perm: "private",
            upstream_url: "https://user:password@example.com/private?token=secret",
            auth_username: "user",
            extra_value_1: "header-secret",
          }]);
        },
      },
    });
    const safe = await checker.getUpstreamDataForFormats(
      "workspace-a", "repo-a", ["python"], { bypassCache: true }
    );
    const privileged = await checker.getUpstreamDataForFormats(
      "workspace-a", "repo-a", ["python"], { bypassCache: true, projection: "privileged" }
    );
    assert.strictEqual(endpoints[0], endpoints[1]);
    assert.strictEqual(safe.upstreams[0].slug_perm, privileged.upstreams[0].slug_perm);
    assert.strictEqual(safe.upstreams[0].upstream_url, undefined);
    assert.strictEqual(privileged.upstreams[0].upstream_url.includes("password"), true);
    assert.strictEqual(privileged.upstreams[0].extra_value_1, "header-secret");
  });
});

suite("UpstreamChecker preview resolution", () => {
  setup(() => resetAccount());

  test("local package lookup discovers later pages with strict bounded pagination", async () => {
    const calls = [];
    const firstPage = Array.from({ length: 100 }, (_value, index) => ({
      name: `other-${index}`,
      version: "1.0.0",
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
            version: "1.0.0",
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
      version: "1.0.0",
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
          format: "python",
          _format: "python",
          origin: "https://pypi.org",
          is_active: true,
        },
        {
          name: "Disabled mirror",
          format: "python",
          _format: "python",
          origin: "https://disabled.example",
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
      data: [{
        name: "PyPI", format: "python", _format: "python",
        origin: "https://pypi.org", is_active: true,
      }],
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

  test("previewResolution canonicalizes identity and rejects mismatched configs", async () => {
    const checker = createChecker({});
    const formats = [];
    checker.existsLocally = async (_workspace, _repo, _name, format) => {
      formats.push(format);
      return { data: null, error: null, complete: true };
    };
    checker.getUpstreamsForFormat = async (_workspace, _repo, format) => {
      formats.push(format);
      return {
        data: [{
          name: "npmjs",
          format: "npm",
          _format: "npm",
          origin: "https://registry.npmjs.org",
          is_active: true,
        }],
        error: null,
        complete: true,
      };
    };

    const result = await checker.previewResolution(
      "acme", "repo", "flask", " Python "
    );

    assert.strictEqual(result.format, "python");
    assert.deepStrictEqual(formats, ["python", "python"]);
    assert.deepStrictEqual(result.upstreams.data.configs, []);
    assert.strictEqual(result.upstreams.data.total, 0);
    assert.strictEqual(result.upstreams.complete, false);
    assert.strictEqual(result.canResolveViaUpstream, false);
    assert.strictEqual(result.upstreams.errorMessage, "Cloudsmith returned invalid upstream data.");
  });
});

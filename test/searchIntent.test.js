const assert = require("assert");
const {
  evictPersistedUpstreamCaches,
  executeSearchIntent,
  resetAccountScopedState,
  searchDescriptorFromRecent,
} = require("../extension");

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, reject, resolve };
}

suite("search intent command boundary", () => {
  test("account reset invalidates every cache before independently settled projections", async () => {
    const order = [];
    const cleared = new Set();
    const clear = name => () => {
      order.push(name);
      cleared.add(name);
    };

    const outcome = await resetAccountScopedState({ globalState: {} }, {
      workspaceCache: { clear: clear("workspace") },
      searchProvider: { clear: clear("search") },
      filterState: { clear: clear("filter") },
      recentPackages: { clear: clear("recent") },
      clearVulnerabilityCache: clear("vulnerability"),
      dependencyHealthProvider: {
        async resetForAccountChange() {
          order.push("dependency");
          throw new Error("diagnostics failed");
        },
      },
      async projectHasMultipleWorkspaces(value) {
        order.push(`projection:${value}`);
        throw new Error("setContext failed");
      },
      async evictPersistedUpstreamCaches() {
        order.push("upstream");
        cleared.add("upstream");
      },
    });

    assert.deepStrictEqual(order.slice(0, 5), [
      "workspace",
      "search",
      "filter",
      "recent",
      "vulnerability",
    ]);
    assert.deepStrictEqual([...cleared].sort(), [
      "filter",
      "recent",
      "search",
      "upstream",
      "vulnerability",
      "workspace",
    ]);
    assert.deepStrictEqual(order.slice(5), ["dependency", "projection:false", "upstream"]);
    assert.deepStrictEqual(outcome.asyncResults.map(result => result.status), [
      "rejected",
      "rejected",
      "fulfilled",
    ]);
  });

  test("evicts persisted upstream state before account availability is known", async () => {
    const store = new Map([
      ["cloudsmith-upstreams:v3:stale", { version: 3 }],
      ["unrelated", { keep: true }],
    ]);
    const complete = await evictPersistedUpstreamCaches({
      globalState: {
        keys: () => [...store.keys()],
        async update(key, value) {
          if (value === undefined) store.delete(key);
        },
      },
    });

    assert.strictEqual(complete, true);
    assert.strictEqual(store.has("cloudsmith-upstreams:v3:stale"), false);
    assert.strictEqual(store.has("unrelated"), true);
  });

  test("owns and launches search before detached history persistence", async () => {
    const execution = deferred();
    const history = deferred();
    const calls = [];
    const provider = {
      beginSearch(descriptor) {
        calls.push("begin");
        return { descriptor };
      },
      executeSearch() {
        calls.push("execute");
        return execution.promise;
      },
    };
    const recentSearches = {
      add() {
        calls.push("history");
        return history.promise;
      },
    };

    const pending = executeSearchIntent(provider, {
      kind: "workspace",
      workspace: "workspace-a",
      query: "name:artifact",
      page: 1,
    }, { recentSearches, record: true });

    assert.deepStrictEqual(calls, ["begin", "execute"]);
    await Promise.resolve();
    assert.deepStrictEqual(calls, ["begin", "execute", "history"]);
    execution.resolve("searched");
    assert.strictEqual(await pending, "searched");
    history.resolve();
  });

  test("records and replays an exact single-repository descriptor", async () => {
    let recorded;
    const provider = {
      beginSearch(descriptor) { return { descriptor }; },
      async executeSearch() {},
    };
    await executeSearchIntent(provider, {
      kind: "repository",
      workspace: "workspace-a",
      repository: "repo-a",
      query: "name:artifact",
      page: 1,
    }, {
      record: true,
      recentSearches: { async add(value) { recorded = value; } },
    });
    await Promise.resolve();

    assert.deepStrictEqual(recorded, {
      workspace: "workspace-a",
      query: "name:artifact",
      scope: { kind: "repository", repository: "repo-a" },
    });
    assert.deepStrictEqual(searchDescriptorFromRecent(recorded), {
      kind: "repository",
      workspace: "workspace-a",
      repository: "repo-a",
      query: "name:artifact",
      page: 1,
    });
    assert.strictEqual(searchDescriptorFromRecent({
      ...recorded,
      scope: { kind: "repository", repository: "repo-a", extra: true },
    }), null);
  });

  test("handles detached history rejection without rejecting search", async () => {
    const result = await executeSearchIntent({
      beginSearch(descriptor) { return { descriptor }; },
      async executeSearch() { return "searched"; },
    }, {
      kind: "workspace",
      workspace: "workspace-a",
      query: "artifact",
    }, {
      record: true,
      recentSearches: { async add() { throw new Error("quota"); } },
    });
    await new Promise(resolve => setImmediate(resolve));

    assert.strictEqual(result, "searched");
  });

  test("persists the owned normalized descriptor instead of mutable caller input", async () => {
    const raw = {
      kind: "repository",
      workspace: " raw-workspace ",
      repository: " raw-repo ",
      query: "raw-query",
    };
    const owned = Object.freeze({
      kind: "repository",
      workspace: "workspace-a",
      repository: "repo-a",
      query: "normalized-query",
      page: 1,
    });
    let recorded;
    const pending = executeSearchIntent({
      beginSearch() { return Object.freeze({ descriptor: owned }); },
      async executeSearch() {},
    }, raw, {
      record: true,
      recentSearches: { async add(value) { recorded = value; } },
    });
    raw.workspace = "mutated-workspace";
    raw.repository = "mutated-repo";
    raw.query = "mutated-query";
    await pending;
    await Promise.resolve();

    assert.deepStrictEqual(recorded, {
      workspace: "workspace-a",
      query: "normalized-query",
      scope: { kind: "repository", repository: "repo-a" },
    });
  });
});

const assert = require("assert");
const vscode = require("vscode");
const {
  RecentSearches,
  STORAGE_KEY_PREFIX,
  STORAGE_VERSION,
} = require("../util/recentSearches");

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, reject, resolve };
}

suite("RecentSearches", () => {
  let originalGetConfiguration;
  let store;
  let updates;
  let context;
  let timestamp;

  setup(() => {
    originalGetConfiguration = vscode.workspace.getConfiguration;
    vscode.workspace.getConfiguration = () => ({ get: () => 10 });
    store = new Map();
    updates = [];
    context = {
      globalState: {
        get(key) { return store.get(key); },
        async update(key, value) {
          updates.push({ key, value });
          if (value === undefined) store.delete(key);
          else store.set(key, value);
        },
      },
    };
    timestamp = 1_000;
  });

  teardown(() => {
    vscode.workspace.getConfiguration = originalGetConfiguration;
  });

  function recent(workspace = "workspace-a") {
    return new RecentSearches(context, workspace, { now: () => timestamp++ });
  }

  function descriptor(overrides = {}) {
    return {
      workspace: "workspace-a",
      query: "name:flask",
      scope: { kind: "workspace" },
      ...overrides,
    };
  }

  test("stores only the exact versioned replay descriptor", async () => {
    const searches = recent();
    await searches.add(descriptor({ secret: "must-not-persist" }));

    const stored = store.get(`${STORAGE_KEY_PREFIX}:workspace-a`);
    assert.strictEqual(stored.version, STORAGE_VERSION);
    assert.deepStrictEqual(Object.keys(stored).sort(), ["items", "version"]);
    assert.deepStrictEqual(Object.keys(stored.items[0]).sort(), [
      "query", "scope", "timestamp", "workspace",
    ]);
    assert.strictEqual(JSON.stringify(stored).includes("must-not-persist"), false);
    assert.deepStrictEqual(await searches.getAll(), [
      descriptor({ timestamp: 1_000 }),
    ]);
  });

  test("deduplicates exact descriptors while retaining different scopes", async () => {
    const searches = recent();
    await searches.add(descriptor({ timestamp: 1_000 }));
    await searches.add(descriptor({
      timestamp: 2_000,
      scope: { kind: "repositories", repositories: ["repo-b", "repo-a", "repo-a"] },
    }));
    await searches.add(descriptor({ timestamp: 3_000 }));

    const all = await searches.getAll();
    assert.strictEqual(all.length, 2);
    assert.strictEqual(all[0].timestamp, 3_000);
    assert.deepStrictEqual(all[1].scope.repositories, ["repo-a", "repo-b"]);
  });

  test("stores, validates, and deduplicates exact single-repository scopes", async () => {
    const searches = recent();
    await searches.add(descriptor({
      timestamp: 1_000,
      scope: { kind: "repository", repository: "repo-a" },
    }));
    await searches.add(descriptor({
      timestamp: 2_000,
      scope: { kind: "repository", repository: "repo-b" },
    }));
    await searches.add(descriptor({
      timestamp: 3_000,
      scope: { kind: "repository", repository: "repo-a" },
    }));

    const all = await searches.getAll();
    assert.strictEqual(all.length, 2);
    assert.deepStrictEqual(all.map(item => item.scope), [
      { kind: "repository", repository: "repo-a" },
      { kind: "repository", repository: "repo-b" },
    ]);
    assert.deepStrictEqual(Object.keys(all[0].scope).sort(), ["kind", "repository"]);
  });

  test("rejects ambiguous or inexact repository identifiers", async () => {
    const searches = recent();
    await assert.rejects(searches.add(descriptor({
      scope: { kind: "repository", repository: " repo-a" },
    })), /descriptor is invalid/);
    await assert.rejects(searches.add(descriptor({
      scope: { kind: "repository", repository: "repo-a", repositories: ["repo-b"] },
    })), /descriptor is invalid/);
  });

  test("caps entries and keeps newest-first order", async () => {
    const searches = recent();
    for (let index = 0; index < 12; index += 1) {
      await searches.add(descriptor({ query: `query-${index}`, timestamp: index + 1 }));
    }
    const all = await searches.getAll();
    assert.strictEqual(all.length, 10);
    assert.strictEqual(all[0].query, "query-11");
    assert.strictEqual(all[9].query, "query-2");
  });

  test("isolates workspace storage keys", async () => {
    const first = recent("workspace-a");
    const second = recent("workspace-b");
    await Promise.all([
      first.add(descriptor()),
      second.add(descriptor({ workspace: "workspace-b", query: "name:django" })),
    ]);
    assert.strictEqual((await first.getAll())[0].query, "name:flask");
    assert.strictEqual((await second.getAll())[0].query, "name:django");
  });

  test("ignores and evicts malformed or unversioned state", async () => {
    const searches = recent();
    store.set(searches.storageKey, [descriptor({ timestamp: 1_000 })]);
    assert.deepStrictEqual(await searches.getAll(), []);
    assert.strictEqual(store.has(searches.storageKey), false);

    store.set(searches.storageKey, { version: 0, items: [] });
    assert.deepStrictEqual(await searches.getAll(), []);
    assert.strictEqual(store.has(searches.storageKey), false);
  });

  test("clear writes an empty versioned envelope and is awaited", async () => {
    const searches = recent();
    await searches.add(descriptor());
    await searches.clear();
    assert.deepStrictEqual(store.get(searches.storageKey), {
      version: STORAGE_VERSION,
      items: [],
    });
  });

  test("serializes updates across instances sharing the same Memento and key", async () => {
    const gate = deferred();
    let updateCount = 0;
    context.globalState.update = async (key, value) => {
      updateCount += 1;
      if (updateCount === 1) await gate.promise;
      store.set(key, value);
    };
    const first = recent();
    const second = recent();
    const firstAdd = first.add(descriptor({ query: "first", timestamp: 1 }));
    await new Promise(resolve => setImmediate(resolve));
    const secondAdd = second.add(descriptor({ query: "second", timestamp: 2 }));
    await new Promise(resolve => setImmediate(resolve));
    assert.strictEqual(updateCount, 1);
    gate.resolve();
    await Promise.all([firstAdd, secondAdd]);
    assert.deepStrictEqual((await first.getAll()).map(item => item.query), ["second", "first"]);
  });

  test("propagates persistence failure to the caller", async () => {
    context.globalState.update = async () => {
      throw new Error("quota exceeded");
    };
    await assert.rejects(recent().add(descriptor()), /quota exceeded/);
    await assert.rejects(recent().clear(), /quota exceeded/);
  });

  test("rejects ambiguous legacy scope strings", async () => {
    await assert.rejects(
      recent().add(descriptor({ scope: "workspace" })),
      /descriptor is invalid/
    );
  });
});

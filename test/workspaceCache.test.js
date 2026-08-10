const assert = require("assert");
const { WorkspaceCache } = require("../util/workspaceCache");

suite("WorkspaceCache", () => {
  let state;
  let now;
  let cache;

  setup(() => {
    state = { activationId: "activation-a", accountEpoch: 1, sessionConnected: true };
    now = 1_000;
    cache = new WorkspaceCache({ getState: () => ({ ...state }) }, {
      now: () => now,
      ttlMs: 100,
    });
  });

  test("stores only immutable workspace summaries and returns clones", () => {
    const source = [{ slug: "workspace-a", name: "Workspace A", secret: "omit" }];
    assert.strictEqual(cache.set(source, state), true);
    source[0].name = "mutated";
    const first = cache.get();
    assert.deepStrictEqual(first, [{ slug: "workspace-a", name: "Workspace A" }]);
    first[0].name = "also-mutated";
    assert.strictEqual(cache.get()[0].name, "Workspace A");
  });

  test("invalidates on account epoch, activation, disconnect, and expiry", () => {
    cache.set([{ slug: "workspace-a", name: "Workspace A" }], state);
    state.accountEpoch = 2;
    assert.strictEqual(cache.get(), null);

    state.accountEpoch = 1;
    cache.set([{ slug: "workspace-a", name: "Workspace A" }], state);
    state.activationId = "activation-b";
    assert.strictEqual(cache.get(), null);

    cache.set([{ slug: "workspace-a", name: "Workspace A" }], state);
    state.sessionConnected = false;
    assert.strictEqual(cache.get(), null);

    state.sessionConnected = true;
    cache.set([{ slug: "workspace-a", name: "Workspace A" }], state);
    now += 100;
    assert.strictEqual(cache.get(), null);
  });

  test("rejects malformed or stale writes", () => {
    assert.strictEqual(cache.set([{ slug: "workspace-a" }], state), false);
    assert.strictEqual(cache.set([], { ...state, accountEpoch: 2 }), false);
    assert.strictEqual(cache.get(), null);
  });
});

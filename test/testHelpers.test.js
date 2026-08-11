const assert = require("assert");
const { createCancellationSource, createManualClock, deferred } = require("./helpers/asyncControl");
const { FakeMemento } = require("./helpers/fakeMemento");
const { FakeSecretStorage } = require("./helpers/fakeSecretStorage");
const { ScriptedCloudsmithAPI, deepFreeze } = require("./helpers/scriptedCloudsmithAPI");

function success(data) {
  return {
    ok: true,
    data,
    status: 200,
    headers: {},
    requestId: "request-id",
    serverRequestId: null,
    attempts: 1,
    redirectCount: 0,
  };
}

suite("risk-based test helpers", () => {
  test("deferred settles exactly once", async () => {
    const control = deferred();
    assert.strictEqual(control.settled, false);
    assert.strictEqual(control.resolve("first"), true);
    assert.strictEqual(control.reject(new Error("late")), false);
    assert.strictEqual(control.settled, true);
    assert.strictEqual(await control.promise, "first");
  });

  test("manual clock runs equal-deadline work in FIFO order without sleeping", async () => {
    const clock = createManualClock(100);
    const order = [];
    const cancelled = clock.setTimeout(() => order.push("cancelled"), 5);
    clock.setTimeout(() => order.push("first"), 10);
    clock.setTimeout(() => order.push("second"), 10);
    clock.clearTimeout(cancelled);

    await clock.advanceBy(10);

    assert.deepStrictEqual(order, ["first", "second"]);
    assert.strictEqual(clock.now(), 110);
    assert.strictEqual(clock.pendingCount(), 0);
  });

  test("cancellation source links an AbortSignal and disposes listeners", () => {
    const source = createCancellationSource();
    let notifications = 0;
    const disposable = source.token.onCancellationRequested(() => { notifications += 1; });
    assert.strictEqual(source.listenerCount(), 1);
    disposable.dispose();
    assert.strictEqual(source.listenerCount(), 0);
    source.token.onCancellationRequested(() => { notifications += 1; });

    assert.strictEqual(source.cancel(), true);
    assert.strictEqual(source.signal.aborted, true);
    assert.strictEqual(source.token.isCancellationRequested, true);
    assert.strictEqual(source.listenerCount(), 0);
    assert.strictEqual(notifications, 1);
    assert.strictEqual(source.cancel(), false);
  });

  test("scripted API is FIFO, frozen, strict, and exhaustible", async () => {
    const result = success([{ slug: "workspace" }]);
    const api = new ScriptedCloudsmithAPI([{
      method: "GET",
      endpoint: "namespaces/",
      result,
    }]);

    const actual = await api.get("namespaces/", { responseType: "array" });

    assert.strictEqual(actual, result);
    assert.strictEqual(Object.isFrozen(actual), true);
    assert.strictEqual(Object.isFrozen(actual.data), true);
    assert.strictEqual(Object.isFrozen(api.calls), true);
    assert.strictEqual(api.calls.length, 1);
    assert.strictEqual(api.remaining(), 0);
    api.assertExhausted();
    await assert.rejects(api.get("unexpected/"), /unexpected request/);
  });

  test("scripted API mismatch errors do not echo request data", async () => {
    const secret = "credential-value-must-not-appear";
    const api = new ScriptedCloudsmithAPI([{
      method: "GET",
      endpoint: "expected/",
      result: success({}),
    }]);

    await assert.rejects(
      api.post(`unexpected/?token=${secret}`, { secret }),
      error => !error.message.includes(secret) && /did not match/.test(error.message),
    );
  });

  test("scripted API call snapshots retain shape without credential values", async () => {
    const secret = "credential-value-must-not-be-retained";
    const api = new ScriptedCloudsmithAPI([{
      method: "POST",
      endpoint: "packages/copy/",
      result: success({}),
    }]);

    await api.post("packages/copy/", { apiKey: secret, package: "fixture" }, {
      apiKey: secret,
      retry: "never",
    });

    assert.deepStrictEqual(api.calls, [{
      apiVersion: "v1",
      endpoint: { pathSegmentCount: 2, queryKeys: [] },
      jsonKeys: ["apiKey", "package"],
      method: "POST",
      optionKeys: ["retry"],
    }]);
    assert.strictEqual(JSON.stringify(api.calls).includes(secret), false);
  });

  test("scripted API matching endpoint snapshots retain query shape without values", async () => {
    const secret = "credential-in-matching-endpoint";
    const api = new ScriptedCloudsmithAPI([{
      method: "GET",
      endpoint: value => value.includes("token="),
      result: success({}),
    }]);

    await api.get(`packages/?page=2&token=${secret}`);

    assert.deepStrictEqual(api.calls[0].endpoint, {
      pathSegmentCount: 1,
      queryKeys: ["page", "token"],
    });
    assert.strictEqual(JSON.stringify(api.calls).includes(secret), false);
  });

  test("scripted API freezing rejects accessors and excessive nesting", () => {
    let getterCalls = 0;
    const accessor = {};
    Object.defineProperty(accessor, "secret", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return "must-not-run";
      },
    });
    assert.throws(() => deepFreeze(accessor), /data properties only/);
    assert.strictEqual(getterCalls, 0);

    let nested = {};
    for (let depth = 0; depth < 34; depth += 1) nested = { nested };
    assert.throws(() => deepFreeze(nested), /structural bounds/);
  });

  test("scripted API supports controlled out-of-order completion", async () => {
    const firstCompletion = deferred();
    const api = new ScriptedCloudsmithAPI([
      { method: "GET", endpoint: "first/", result: firstCompletion.promise },
      { method: "GET", endpoint: "second/", result: success({ order: 2 }) },
    ]);

    const first = api.get("first/");
    const second = await api.get("second/");
    assert.strictEqual(second.data.order, 2);
    firstCompletion.resolve(success({ order: 1 }));
    assert.strictEqual((await first).data.order, 1);
    api.assertExhausted();
  });

  test("fake Memento injects writes and failures without committing partial state", async () => {
    const state = new FakeMemento({ version: 1 });
    state.failNextUpdate();
    await assert.rejects(state.update("version", 2), /Injected Memento update failure/);
    assert.strictEqual(state.get("version"), 1);
    await state.update("version", 2);
    assert.strictEqual(state.get("version"), 2);
    assert.deepStrictEqual(state.updates, [
      { key: "version", deleted: false },
      { key: "version", deleted: false },
    ]);
  });

  test("fake SecretStorage emits external changes and injects sanitized failures", async () => {
    const secret = "secret-never-recorded-in-operations";
    const storage = new FakeSecretStorage({ token: "old" });
    const changed = [];
    const subscription = storage.onDidChange(event => changed.push(event.key));
    storage.failNext("store");

    await assert.rejects(
      storage.store("token", secret),
      error => !error.message.includes(secret) && /Injected SecretStorage store failure/.test(error.message),
    );
    assert.strictEqual(storage.peek("token"), "old");
    storage.externalSet("token", secret);
    assert.deepStrictEqual(changed, ["token"]);
    assert.deepStrictEqual(storage.operations, [{ operation: "store", key: "token" }]);
    subscription.dispose();
    assert.strictEqual(storage.listenerCount(), 0);
  });
});

// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const { UpstreamCacheLifecycle } = require("../util/upstreamCacheLifecycle");
const { UpstreamRuntime } = require("../util/upstreamRuntime");
const { apiSuccess } = require("./apiResultHelpers");

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function connectedState(accountEpoch = 1, overrides = {}) {
  return {
    activationId: "activation-a",
    accountEpoch,
    operationId: accountEpoch,
    status: "connected",
    sessionConnected: true,
    ...overrides,
  };
}

function createConnectionManager(initialState = connectedState()) {
  let state = { ...initialState };
  const listeners = new Set();
  return {
    getState() { return { ...state }; },
    onDidChange(listener) {
      listeners.add(listener);
      return { dispose() { listeners.delete(listener); } };
    },
    emit(next) {
      state = { ...next };
      for (const listener of [...listeners]) listener({ ...state });
    },
    get listenerCount() { return listeners.size; },
  };
}

function createGlobalState(initialEntries = []) {
  const store = new Map(initialEntries);
  const reads = [];
  const updates = [];
  return {
    store,
    reads,
    updates,
    globalState: {
      keys() { return [...store.keys()]; },
      get(key) {
        reads.push(key);
        return store.get(key);
      },
      async update(key, value) {
        updates.push({ key, value });
        if (value === undefined) store.delete(key);
        else store.set(key, value);
      },
    },
  };
}

function aggregate(upstreams = []) {
  return {
    upstreams,
    active: upstreams.filter(upstream => upstream.is_active !== false).length,
    total: upstreams.length,
    failedFormats: [],
    uninspectedFormats: [],
    successfulFormats: 1,
    complete: true,
  };
}

async function createReadyRuntime(options = {}) {
  const connectionManager = options.connectionManager || createConnectionManager();
  const state = createGlobalState();
  const checker = options.checker || {
    async getAllUpstreamData() { return aggregate(); },
    async getUpstreamDataForFormats() { return aggregate(); },
    async getRepositoryUpstreamStateForFormats() { return aggregate(); },
    async previewResolution() { return { canResolveViaUpstream: false }; },
  };
  const runtime = new UpstreamRuntime(
    { globalState: state.globalState },
    { connectionManager, checker, ...options.runtimeOptions }
  );
  await runtime.initialize();
  connectionManager.emit(connectionManager.getState());
  return { runtime, connectionManager, checker, state };
}

suite("UpstreamRuntime lifecycle", () => {
  test("owns the direct connection listener and cleans it up if subordinate construction fails", () => {
    const connectionManager = createConnectionManager();
    const state = createGlobalState();
    assert.throws(() => new UpstreamRuntime(
      { globalState: state.globalState },
      {
        connectionManager,
        beforeCheckerConstruction() { throw new Error("construction failed"); },
      }
    ), /construction failed/);
    assert.strictEqual(connectionManager.listenerCount, 0);
  });

  test("waits for exact-B persistence readiness and does not admit transient states", async () => {
    const oldKey = "cloudsmith-upstreams:v5:old";
    const state = createGlobalState([[oldKey, { stale: true }]]);
    const firstDelete = deferred();
    let updateCount = 0;
    state.globalState.update = async (key, value) => {
      state.updates.push({ key, value });
      updateCount += 1;
      if (updateCount === 1) await firstDelete.promise;
      state.store.delete(key);
    };
    const connectionManager = createConnectionManager({
      ...connectedState(1), status: "validating", sessionConnected: false,
    });
    let calls = 0;
    const checker = {
      async getAllUpstreamData() { calls += 1; return aggregate(); },
    };
    const runtime = new UpstreamRuntime(
      { globalState: state.globalState },
      { connectionManager, checker, persistenceWaitMs: 200 }
    );
    const initialization = runtime.initialize();
    const transient = await runtime.getAllUpstreamData("acme", "repo");
    assert.strictEqual(transient, null);

    connectionManager.emit(connectedState(2));
    const pendingB = runtime.getAllUpstreamData("acme", "repo", {
      account: { activationId: "activation-a", accountEpoch: 2 },
    });
    await new Promise(resolve => setImmediate(resolve));
    assert.strictEqual(calls, 0);
    firstDelete.resolve();
    await initialization;
    const result = await pendingB;
    assert.strictEqual(result.complete, true);
    assert.strictEqual(calls, 1);
    runtime.dispose();
  });

  test("account reset retires a non-cooperative operation and observes late rejection", async () => {
    const transport = deferred();
    let callCount = 0;
    const unhandled = [];
    const onUnhandled = reason => unhandled.push(reason);
    process.on("unhandledRejection", onUnhandled);
    const { runtime, connectionManager } = await createReadyRuntime({ checker: {
      async getAllUpstreamData() {
        callCount += 1;
        return callCount === 1 ? transport.promise : aggregate([{ name: "account-b" }]);
      },
    } });
    try {
      const pendingA = runtime.getAllUpstreamData("acme", "repo");
      await new Promise(resolve => setImmediate(resolve));
      connectionManager.emit(connectedState(2));
      assert.strictEqual(await pendingA, null);
      const resultB = await runtime.getAllUpstreamData("acme", "repo", {
        account: { activationId: "activation-a", accountEpoch: 2 },
      });
      assert.strictEqual(resultB.upstreams[0].name, "account-b");
      assert.strictEqual(runtime._operations.size, 0);
      assert.strictEqual(runtime._scopes.size, 0);
      transport.reject(new Error("late old-account failure"));
      await new Promise(resolve => setImmediate(resolve));
      assert.deepStrictEqual(unhandled, []);
    } finally {
      process.removeListener("unhandledRejection", onUnhandled);
      runtime.dispose();
    }
  });

  test("dispose retires late resolution and rejects all new work", async () => {
    const transport = deferred();
    const { runtime } = await createReadyRuntime({ checker: {
      async getAllUpstreamData() { return transport.promise; },
    } });
    const pending = runtime.getAllUpstreamData("acme", "repo");
    await new Promise(resolve => setImmediate(resolve));
    runtime.dispose();
    assert.strictEqual(await pending, null);
    assert.strictEqual(runtime._operations.size, 0);
    assert.strictEqual(runtime._scopes.size, 0);
    transport.resolve(aggregate([{ name: "late" }]));
    await assert.rejects(
      runtime.getAllUpstreamData("acme", "repo"),
      error => error?.kind === "disposed"
    );
  });

  test("keeps operation schedulers isolated until each top-level scope is disposed", async () => {
    const schedulers = [];
    const schedulerFactory = () => {
      const scheduler = {
        cancelled: false,
        run(task) { return task(); },
        cancel() { this.cancelled = true; },
      };
      schedulers.push(scheduler);
      return scheduler;
    };
    const seen = [];
    const { runtime } = await createReadyRuntime({
      checker: {
        async getRepositoryUpstreamStateForFormats(_workspace, _repo, _formats, options) {
          seen.push(options.scheduler);
          return aggregate();
        },
      },
      runtimeOptions: { schedulerFactory },
    });
    const scopeA = runtime.createOperationScope({ kind: "gap" });
    const scopeB = runtime.createOperationScope({ kind: "pull" });
    await runtime.getRepositoryUpstreamStateForFormats("acme", "one", ["npm"], {
      account: scopeA.account,
      operationScope: scopeA,
    });
    await runtime.getRepositoryUpstreamStateForFormats("acme", "two", ["npm"], {
      account: scopeB.account,
      operationScope: scopeB,
    });
    assert.notStrictEqual(seen[0], seen[1]);
    scopeA.dispose();
    assert.strictEqual(schedulers[0].cancelled, true);
    assert.strictEqual(schedulers[1].cancelled, false);
    scopeB.dispose();
    runtime.dispose();
  });

  test("does not let B readiness reopen C or admit a transient validating state", async () => {
    const readyB = deferred();
    const readyC = deferred();
    let resetCount = 0;
    const cacheLifecycle = {
      initialize: async () => true,
      reset() {
        resetCount += 1;
        return resetCount === 1 ? readyB.promise : readyC.promise;
      },
      dispose() {},
    };
    let calls = 0;
    const checker = {
      async getAllUpstreamData() { calls += 1; return aggregate(); },
    };
    const connectionManager = createConnectionManager();
    const runtime = new UpstreamRuntime(
      { globalState: createGlobalState().globalState },
      { connectionManager, checker, cacheLifecycle }
    );
    await runtime.initialize();
    connectionManager.emit(connectionManager.getState());

    connectionManager.emit(connectedState(2));
    const pendingB = runtime.getAllUpstreamData("acme", "repo", {
      account: { activationId: "activation-a", accountEpoch: 2 },
    });
    connectionManager.emit(connectedState(3));
    const pendingC = runtime.getAllUpstreamData("acme", "repo", {
      account: { activationId: "activation-a", accountEpoch: 3 },
    });
    readyB.resolve(true);
    assert.strictEqual(await pendingB, null);
    await new Promise(resolve => setImmediate(resolve));
    assert.strictEqual(calls, 0);

    connectionManager.emit({
      ...connectedState(3),
      operationId: 4,
      status: "validating",
      sessionConnected: false,
    });
    readyC.resolve(true);
    assert.strictEqual(await pendingC, null);
    assert.strictEqual(calls, 0);

    connectionManager.emit({ ...connectedState(3), operationId: 5 });
    const finalC = await runtime.getAllUpstreamData("acme", "repo");
    assert.strictEqual(finalC.complete, true);
    assert.strictEqual(calls, 1);
    runtime.dispose();
  });

  test("forces export account, privileged projection, and cache bypass while shaping the envelope", async () => {
    let received;
    const { runtime } = await createReadyRuntime({ checker: {
      async getAllUpstreamData(workspace, repo, options) {
        received = { workspace, repo, options };
        return {
          ...aggregate([{ name: "Private", upstream_url: "https://private.example/path" }]),
          failedFormats: ["alpine"],
          complete: false,
        };
      },
    } });
    const account = { activationId: "activation-a", accountEpoch: 1 };
    const result = await runtime.getPrivilegedRepositoryUpstreamsForExport("acme", "repo", {
      account,
    });
    assert.deepStrictEqual(received.options.account, account);
    assert.strictEqual(received.options.projection, "privileged");
    assert.strictEqual(received.options.bypassCache, true);
    assert.strictEqual(result.data[0].upstream_url, "https://private.example/path");
    assert.strictEqual(result.partial, true);
    runtime.dispose();
  });
});

suite("UpstreamRuntime cache isolation", () => {
  test("clears the touched-key ledger after a successful purge", async () => {
    const key = "cloudsmith-upstreams:v5:retired";
    const state = createGlobalState();
    const lifecycle = new UpstreamCacheLifecycle(state.globalState);
    assert.strictEqual(lifecycle.read(key), undefined);

    assert.strictEqual(await lifecycle.reset(), true);
    assert.deepStrictEqual(state.updates, [{ key, value: undefined }]);
    assert.strictEqual(await lifecycle.reset(), true);
    assert.deepStrictEqual(state.updates, [{ key, value: undefined }]);
    lifecycle.dispose();
  });

  test("orders reset deletion behind an old write so stale data cannot resurrect", async () => {
    const key = "cloudsmith-upstreams:v5:race";
    const state = createGlobalState();
    const oldWrite = deferred();
    const values = [];
    state.globalState.update = async (_key, value) => {
      values.push(value);
      if (value !== undefined) await oldWrite.promise;
      if (value === undefined) state.store.delete(key);
      else state.store.set(key, value);
    };
    const lifecycle = new UpstreamCacheLifecycle(state.globalState, { persistenceWaitMs: 200 });
    const token = lifecycle.begin(key);
    const write = lifecycle.persist(key, { accountEpoch: 1 }, token);
    await new Promise(resolve => setImmediate(resolve));
    const reset = lifecycle.reset();
    oldWrite.resolve();
    await Promise.all([write, reset]);
    assert.deepStrictEqual(values, [{ accountEpoch: 1 }, undefined]);
    assert.strictEqual(state.store.has(key), false);
    lifecycle.dispose();
  });

  test("serializes a two-runtime activation handoff through the shared physical queue", async () => {
    const key = "cloudsmith-upstreams:v5:handoff";
    const state = createGlobalState();
    const oldWrite = deferred();
    const values = [];
    state.globalState.update = async (_key, value) => {
      values.push(value);
      if (value !== undefined) await oldWrite.promise;
      if (value === undefined) state.store.delete(key);
      else state.store.set(key, value);
    };
    const oldLifecycle = new UpstreamCacheLifecycle(state.globalState, { persistenceWaitMs: 200 });
    const newLifecycle = new UpstreamCacheLifecycle(state.globalState, { persistenceWaitMs: 200 });
    const token = oldLifecycle.begin(key);
    const write = oldLifecycle.persist(key, { activationId: "old" }, token);
    await new Promise(resolve => setImmediate(resolve));
    const handoff = newLifecycle.initialize();
    oldWrite.resolve();
    await Promise.all([write, handoff]);
    assert.deepStrictEqual(values, [{ activationId: "old" }, undefined]);
    assert.strictEqual(state.store.has(key), false);
    oldLifecycle.dispose();
    newLifecycle.dispose();
  });

  test("globally quarantines persistence after a bounded hung-storage purge", async () => {
    const key = "cloudsmith-upstreams:v5:hung";
    const state = createGlobalState([[key, { stale: true }]]);
    state.globalState.update = async () => new Promise(() => {});
    const lifecycle = new UpstreamCacheLifecycle(state.globalState, { persistenceWaitMs: 5 });
    assert.strictEqual(await lifecycle.initialize(), false);
    assert.strictEqual(lifecycle.persistenceEnabled, false);
    assert.strictEqual(lifecycle.read(key), undefined);
    assert.strictEqual(lifecycle.read("cloudsmith-upstreams:v5:new-repo"), undefined);
    assert.strictEqual(lifecycle.begin("cloudsmith-upstreams:v5:new-repo"), null);
    lifecycle.dispose();
  });

  test("safe to privileged to safe performs zero privileged cache I/O and leaks no fields", async () => {
    const state = createGlobalState();
    const connectionManager = createConnectionManager();
    let apiCalls = 0;
    const runtime = new UpstreamRuntime(
      { globalState: state.globalState },
      {
        connectionManager,
        cloudsmithAPI: {
          async get() {
            apiCalls += 1;
            return apiSuccess([{
              name: "Private",
              slug_perm: "private",
              upstream_url: "https://user:password@example.com/private?token=secret",
              extra_value_1: "header-secret",
            }], { headers: {
              "x-pagination-page": "1",
              "x-pagination-pagetotal": "1",
              "x-pagination-count": "1",
              "x-pagination-pagesize": "1",
            } });
          },
        },
      }
    );
    await runtime.initialize();
    connectionManager.emit(connectionManager.getState());
    const safe = await runtime.getUpstreamDataForFormats("acme", "repo", ["python"]);
    assert.strictEqual(safe.upstreams[0].upstream_url, undefined);
    const beforePrivileged = {
      reads: state.reads.length,
      updates: state.updates.length,
    };
    const privileged = await runtime.getPrivilegedRepositoryUpstreamsForExport("acme", "repo");
    assert.ok(privileged.data[0].upstream_url.includes("password"));
    assert.strictEqual(state.reads.length, beforePrivileged.reads);
    assert.strictEqual(state.updates.length, beforePrivileged.updates);
    const callsAfterPrivileged = apiCalls;
    const safeAgain = await runtime.getUpstreamDataForFormats("acme", "repo", ["python"]);
    assert.strictEqual(apiCalls, callsAfterPrivileged);
    assert.strictEqual(safeAgain.upstreams[0].upstream_url, undefined);
    assert.strictEqual(JSON.stringify(safeAgain).includes("header-secret"), false);
    runtime.dispose();
  });
});

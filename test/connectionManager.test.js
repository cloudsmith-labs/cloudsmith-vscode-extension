const assert = require("assert");
const {
  AUTH_TOKEN_KEY,
  CONNECTION_STATUSES,
  ConnectionManager,
  bindConnectionManager,
  getAccountEpoch,
  getConnectionManager,
  unbindConnectionManager,
} = require("../util/connectionManager");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");
const { FakeSecretStorage } = require("./helpers/fakeSecretStorage");
const { decodeStoredCredential } = require("../util/credentialEnvelope");

function assertStoredAPIKey(stored, expected) {
  const decoded = decodeStoredCredential(stored);
  assert.strictEqual(decoded.ok, true);
  assert.strictEqual(decoded.credential.kind, "api-key");
  assert.strictEqual(decoded.credential.apiKey, expected);
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

async function nextTurn() {
  await new Promise(resolve => setImmediate(resolve));
}

function createHarness(initialCredential, validate) {
  const secrets = new FakeSecretStorage(
    initialCredential === null ? {} : { [AUTH_TOKEN_KEY]: initialCredential },
    { primaryKey: AUTH_TOKEN_KEY }
  );
  const projections = [];
  const context = { secrets };
  const manager = new ConnectionManager(context, {
    activationId: "test-activation",
    createCloudsmithAPI: () => ({
      get: (_endpoint, options) => validate(
        options.credential.kind === "api-key"
          ? options.credential.apiKey
          : options.credential.accessToken,
        options
      ),
    }),
    executeCommand: async (...args) => projections.push(args),
  });
  return { context, manager, projections, secrets };
}

suite("ConnectionManager Test Suite", () => {
  test("startup derives immutable connected state from the authoritative token", async () => {
    const calls = [];
    const { manager, projections, secrets } = createHarness("stored-key", async (candidate, options) => {
      calls.push([candidate, options]);
      return apiSuccess({ authenticated: true });
    });

    const result = await manager.initialize();

    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.status, CONNECTION_STATUSES.CONNECTED);
    assert.deepStrictEqual(manager.getState(), {
      activationId: "test-activation",
      status: CONNECTION_STATUSES.CONNECTED,
      operationId: 1,
      accountEpoch: 1,
      credentialPresent: true,
      sessionConnected: true,
      error: null,
    });
    assert.ok(Object.isFrozen(manager.getState()));
    assert.strictEqual(calls[0][0], "stored-key");
    assert.strictEqual(calls[0][1].credential.apiKey, "stored-key");
    assert.deepStrictEqual(projections.at(-1), ["setContext", "cloudsmith.connected", true]);
    assert.ok(secrets.deletedKeys.includes("cloudsmith-vsc.isConnected"));
  });

  test("a failed legacy-envelope rewrite leaves the validated raw API key usable", async () => {
    const { manager, secrets } = createHarness("legacy-key", async () => (
      apiSuccess({ authenticated: true })
    ));
    secrets.storeHook = async () => { throw new Error("migration write failed"); };

    const result = await manager.initialize();

    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.preserved, true);
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
    assert.strictEqual(manager.getState().sessionConnected, true);
    assert.strictEqual(secrets.value, "legacy-key");
    const authorization = await manager.getAuthorization();
    assert.strictEqual(authorization.headerName, "X-Api-Key");
    assert.strictEqual(authorization.headerValue, "legacy-key");
  });

  test("an event during the startup read prevents the pre-event snapshot from validating or publishing", async () => {
    const startupRead = deferred();
    const releaseStartupRead = deferred();
    const validated = [];
    const { manager, secrets } = createHarness("old-key", async candidate => {
      validated.push(candidate);
      return apiSuccess({ authenticated: true });
    });
    let authReads = 0;
    secrets.getHook = async (key, store) => {
      if (key !== AUTH_TOKEN_KEY) return null;
      authReads += 1;
      const captured = store.value;
      if (authReads === 1) {
        startupRead.resolve();
        await releaseStartupRead.promise;
      }
      return captured;
    };

    const pending = manager.initialize();
    await startupRead.promise;
    secrets.externalSet("new-key");
    releaseStartupRead.resolve();
    const result = await pending;
    await nextTurn();

    assert.strictEqual(result.status, "stale");
    assert.deepStrictEqual(validated, ["new-key"]);
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
    assert.strictEqual(manager.getState().operationId, 2);
  });

  test("an event during startup validation prevents the pre-event credential from publishing", async () => {
    const oldValidation = deferred();
    const { manager, secrets } = createHarness("old-key", candidate => (
      candidate === "old-key"
        ? oldValidation.promise
        : Promise.resolve(apiSuccess({ authenticated: true }))
    ));
    const states = [];
    manager.onDidChange(state => states.push(state));

    const pending = manager.initialize();
    await nextTurn();
    secrets.externalSet("new-key");
    oldValidation.resolve(apiSuccess({ authenticated: true }));
    const result = await pending;
    await nextTurn();

    assert.strictEqual(result.status, "stale");
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
    assert.strictEqual(manager.getState().operationId, 2);
    assert.strictEqual(
      states.some(state => state.status === CONNECTION_STATUSES.CONNECTED && state.operationId === 1),
      false
    );
  });

  test("a same-value external event is an idempotent no-op", async () => {
    let validations = 0;
    let rejectFurtherValidation = false;
    const { manager, projections, secrets } = createHarness("same-key", async () => {
      validations += 1;
      return rejectFurtherValidation
        ? apiFailure("unauthorized", { message: "must not run" })
        : apiSuccess({ authenticated: true });
    });
    await manager.initialize();
    const before = manager.getState();
    const projectionCount = projections.length;
    rejectFurtherValidation = true;

    secrets.externalSet("same-key");
    await nextTurn();
    await nextTurn();

    assert.strictEqual(validations, 1);
    assert.strictEqual(manager.getState(), before);
    assert.strictEqual(manager.getState().accountEpoch, before.accountEpoch);
    assert.strictEqual(projections.length, projectionCount);
  });

  test("a failed replacement preserves the prior connected session and secret", async () => {
    const { manager, secrets } = createHarness("old-key", async candidate => (
      candidate === "old-key"
        ? apiSuccess({ authenticated: true })
        : apiFailure("unauthorized", { message: "Rejected." })
    ));
    await manager.initialize();
    const epoch = manager.getState().accountEpoch;

    const result = await manager.replaceCredential("bad-key");

    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.preserved, true);
    assertStoredAPIKey(secrets.value, "old-key");
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
    assert.strictEqual(manager.getState().sessionConnected, true);
    assert.strictEqual(manager.getState().accountEpoch, epoch);
  });

  test("the newest replacement wins even when an older validation finishes later", async () => {
    const validations = new Map();
    const { manager, secrets } = createHarness("old-key", candidate => {
      if (candidate === "old-key") return Promise.resolve(apiSuccess({ authenticated: true }));
      const pending = deferred();
      validations.set(candidate, pending);
      return pending.promise;
    });
    await manager.initialize();

    const first = manager.replaceCredential("first-key");
    const second = manager.replaceCredential("second-key");
    validations.get("second-key").resolve(apiSuccess({ authenticated: true }));
    const secondResult = await second;
    validations.get("first-key").resolve(apiSuccess({ authenticated: true }));
    const firstResult = await first;

    assert.strictEqual(secondResult.ok, true);
    assert.strictEqual(firstResult.status, "stale");
    assertStoredAPIKey(secrets.value, "second-key");
    assert.strictEqual(manager.getState().sessionConnected, true);
    assert.strictEqual(manager.getState().accountEpoch, 2);
  });

  test("a completed older store becomes the baseline after a newer replacement fails", async () => {
    const storeStarted = deferred();
    const releaseStore = deferred();
    const { manager, secrets } = createHarness("old-key", async candidate => (
      candidate === "bad-newer-key"
        ? apiFailure("unauthorized", { message: "Rejected." })
        : apiSuccess({ authenticated: true })
    ));
    await manager.initialize();
    secrets.storeHook = async (key, value, store) => {
      store.value = value;
      store.emit(key);
      storeStarted.resolve();
      await releaseStore.promise;
    };

    const older = manager.replaceCredential("committed-key");
    await storeStarted.promise;
    const newer = await manager.replaceCredential("bad-newer-key");
    assert.strictEqual(newer.ok, false);
    releaseStore.resolve();
    const olderResult = await older;

    assert.strictEqual(olderResult.status, "stale");
    assertStoredAPIKey(secrets.value, "committed-key");
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
    assert.strictEqual(manager.getState().sessionConnected, true);
    assert.strictEqual(manager.getState().accountEpoch, 2);
  });

  test("a self SecretStorage event before store settlement does not cancel or double-advance", async () => {
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();

    const result = await manager.replaceCredential("  new-key  ");
    await nextTurn();

    assert.strictEqual(result.ok, true);
    assertStoredAPIKey(secrets.value, "new-key");
    assert.strictEqual(manager.getState().accountEpoch, 2);
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
  });

  test("a delayed self store event after settlement is ignored without double-advancing", async () => {
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();
    secrets.storeHook = async (_key, value, store) => {
      store.value = value;
    };

    const result = await manager.replaceCredential("new-key");
    const epoch = manager.getState().accountEpoch;
    secrets.emit(AUTH_TOKEN_KEY);
    await nextTurn();

    assert.strictEqual(result.ok, true);
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
    assert.strictEqual(manager.getState().accountEpoch, epoch);
  });

  test("an external replacement during an internal store is restored and the candidate never publishes", async () => {
    const storeStarted = deferred();
    const releaseStore = deferred();
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();
    const states = [];
    manager.onDidChange(state => states.push(state));
    let stores = 0;
    secrets.storeHook = async (key, value, store) => {
      stores += 1;
      if (stores === 1) {
        storeStarted.resolve();
        await releaseStore.promise;
      }
      store.value = value;
      store.emit(key);
    };

    const pending = manager.replaceCredential("internal-key");
    await storeStarted.promise;
    secrets.externalSet("external-key");
    releaseStore.resolve();
    const result = await pending;
    await nextTurn();

    assert.strictEqual(result.status, "superseded");
    assert.strictEqual(result.error.kind, "credential_changed");
    assert.ok(result.error.message.length > 0);
    assert.strictEqual(secrets.value, "external-key");
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
    assert.strictEqual(states.filter(state => state.status === CONNECTION_STATUSES.CONNECTED).length, 1);
  });

  test("restoration retires every raw external snapshot reference", async () => {
    const storeStarted = deferred();
    const releaseStore = deferred();
    const rawExternal = "external-secret-must-not-remain";
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();
    let stores = 0;
    secrets.storeHook = async (key, value, store) => {
      stores += 1;
      if (stores === 1) {
        storeStarted.resolve();
        await releaseStore.promise;
      }
      store.value = value;
      store.emit(key);
    };

    const pending = manager.replaceCredential("internal-key");
    await storeStarted.promise;
    secrets.externalSet(rawExternal);
    releaseStore.resolve();
    const result = await pending;

    assert.strictEqual(result.status, "superseded");
    assert.strictEqual(manager._expectedSecretIntent, null);
  });

  test("infrastructure errors containing a candidate never leak through state or results", async () => {
    const candidate = "candidate-secret-never-display";
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();
    secrets.storeHook = async () => {
      throw Object.assign(new Error(`storage failed for ${candidate}`), { kind: "storage_error" });
    };

    const result = await manager.replaceCredential(candidate);
    const publicSurface = JSON.stringify({ result, state: manager.getState() });

    assert.strictEqual(result.ok, false);
    assert.strictEqual(publicSurface.includes(candidate), false);
    assert.strictEqual(result.error.message, "Could not save credentials.");
    assert.strictEqual(manager._lastError, undefined);
  });

  test("typed SecretStorage delete errors never leak their message", async () => {
    const secret = "delete-error-secret-must-not-leak";
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();
    secrets.deleteHook = async key => {
      if (key === AUTH_TOKEN_KEY) {
        throw Object.assign(new Error(`delete failed for ${secret}`), { kind: "storage_error" });
      }
    };

    const result = await manager.disconnect();
    const publicSurface = JSON.stringify({ result, state: manager.getState() });

    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.error.message, "Could not delete credentials.");
    assert.strictEqual(publicSurface.includes(secret), false);
    assert.strictEqual(manager._lastError, undefined);
  });

  test("typed SecretStorage read errors fail closed without leaking their message", async () => {
    const secret = "read-error-secret-must-not-leak";
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    secrets.getHook = async () => {
      throw Object.assign(new Error(`read failed for ${secret}`), { kind: "storage_error" });
    };

    const result = await manager.initialize();
    const publicSurface = JSON.stringify({ result, state: manager.getState() });

    assert.strictEqual(result.status, CONNECTION_STATUSES.INDETERMINATE);
    assert.strictEqual(result.error.message, "Could not read stored credentials.");
    assert.strictEqual(publicSurface.includes(secret), false);
    assert.strictEqual(manager._lastError, undefined);
  });

  test("typed API failure messages are rebuilt and never retained internally", async () => {
    const secret = "api-error-secret-must-not-leak";
    const { manager } = createHarness(null, async () => (
      apiFailure("network_error", { message: `request failed for ${secret}` })
    ));

    const connectivity = await manager.checkConnectivity("candidate-key");

    assert.strictEqual(connectivity, "error");
    assert.strictEqual(manager._lastError, undefined);
    assert.strictEqual(JSON.stringify(manager.getState()).includes(secret), false);
  });

  test("an external deletion during an internal store remains authoritative", async () => {
    const storeStarted = deferred();
    const releaseStore = deferred();
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();
    let stores = 0;
    secrets.storeHook = async (key, value, store) => {
      stores += 1;
      if (stores === 1) {
        storeStarted.resolve();
        await releaseStore.promise;
      }
      store.value = value;
      store.emit(key);
    };

    const pending = manager.replaceCredential("internal-key");
    await storeStarted.promise;
    secrets.externalSet(null);
    releaseStore.resolve();
    const result = await pending;
    await nextTurn();

    assert.strictEqual(result.status, "superseded");
    assert.strictEqual(secrets.value, null);
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.ABSENT);
    assert.strictEqual(manager.getState().sessionConnected, false);
  });

  test("an external replacement during internal deletion is restored", async () => {
    const deleteStarted = deferred();
    const releaseDelete = deferred();
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();
    let authDeletes = 0;
    secrets.deleteHook = async (key, store) => {
      if (key !== AUTH_TOKEN_KEY) return;
      authDeletes += 1;
      if (authDeletes === 1) {
        deleteStarted.resolve();
        await releaseDelete.promise;
      }
      store.value = null;
      store.emit(key);
    };

    const pending = manager.disconnect();
    await deleteStarted.promise;
    secrets.externalSet("external-key");
    releaseDelete.resolve();
    const result = await pending;
    await nextTurn();

    assert.strictEqual(result.status, "superseded");
    assert.strictEqual(secrets.value, "external-key");
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
  });

  test("a delayed self delete event after settlement does not create a new operation", async () => {
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();
    secrets.deleteHook = async (key, store) => {
      if (key === AUTH_TOKEN_KEY) store.value = null;
    };

    const result = await manager.disconnect();
    const operationId = manager.getState().operationId;
    const epoch = manager.getState().accountEpoch;
    secrets.emit(AUTH_TOKEN_KEY);
    await nextTurn();

    assert.strictEqual(result.ok, true);
    assert.strictEqual(manager.getState().operationId, operationId);
    assert.strictEqual(manager.getState().accountEpoch, epoch);
  });

  test("a higher external event during restoration wins even if an older restore writes later", async () => {
    const storeStarted = deferred();
    const releaseStore = deferred();
    const restoreStarted = deferred();
    const releaseRestore = deferred();
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();
    let stores = 0;
    secrets.storeHook = async (key, value, store) => {
      stores += 1;
      if (stores === 1) {
        storeStarted.resolve();
        await releaseStore.promise;
      } else if (stores === 2) {
        restoreStarted.resolve();
        await releaseRestore.promise;
      }
      store.value = value;
      store.emit(key);
    };

    const pending = manager.replaceCredential("internal-key");
    await storeStarted.promise;
    secrets.externalSet("external-one");
    releaseStore.resolve();
    await restoreStarted.promise;
    secrets.externalSet("external-two");
    releaseRestore.resolve();
    const result = await pending;
    await nextTurn();

    assert.strictEqual(result.status, "superseded");
    assert.strictEqual(secrets.value, "external-two");
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
  });

  test("a consumed self fingerprint cannot swallow a later external event during restoration", async () => {
    const storeStarted = deferred();
    const releaseStore = deferred();
    const restoreStarted = deferred();
    const releaseRestore = deferred();
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();
    let stores = 0;
    secrets.storeHook = async (key, value, store) => {
      stores += 1;
      store.value = value;
      store.emit(key);
      if (stores === 1) {
        storeStarted.resolve();
        await releaseStore.promise;
      } else if (stores === 2) {
        restoreStarted.resolve();
        await releaseRestore.promise;
      }
    };

    const pending = manager.replaceCredential("internal-key");
    await storeStarted.promise;
    secrets.externalSet("external-one");
    releaseStore.resolve();
    await restoreStarted.promise;

    // The original internal-key self notification has already consumed its
    // one-shot expectation. This later event must therefore be external.
    secrets.externalSet("internal-key");
    releaseRestore.resolve();
    const result = await pending;
    await nextTurn();

    assert.strictEqual(result.status, "superseded");
    assertStoredAPIKey(secrets.value, "internal-key");
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
    assert.strictEqual(manager._expectedSecretIntent, null);
  });

  test("an event between the final restore barrier and publication is reconciled", async () => {
    const storeStarted = deferred();
    const releaseStore = deferred();
    const validated = [];
    const { manager, secrets } = createHarness("old-key", async candidate => {
      validated.push(candidate);
      return apiSuccess({ authenticated: true });
    });
    await manager.initialize();
    let stores = 0;
    let restoreWriteCompleted = false;
    let armBarrierInjection = false;
    let injected = false;
    secrets.storeHook = async (key, value, store) => {
      stores += 1;
      if (stores === 1) {
        storeStarted.resolve();
        await releaseStore.promise;
      }
      store.value = value;
      store.emit(key);
      if (stores === 2) restoreWriteCompleted = true;
    };
    secrets.getHook = async (key, store) => {
      if (key !== AUTH_TOKEN_KEY) return null;
      if (restoreWriteCompleted && !injected) armBarrierInjection = true;
      return store.value;
    };
    const originalBarrier = manager._awaitSecretEventBarrier.bind(manager);
    manager._awaitSecretEventBarrier = async () => {
      const sequence = await originalBarrier();
      if (armBarrierInjection && !injected) {
        injected = true;
        armBarrierInjection = false;
        queueMicrotask(() => secrets.externalSet("external-two"));
      }
      return sequence;
    };

    const pending = manager.replaceCredential("internal-key");
    await storeStarted.promise;
    secrets.externalSet("external-one");
    releaseStore.resolve();
    const result = await pending;
    await nextTurn();

    assert.strictEqual(result.status, "superseded");
    assert.strictEqual(secrets.value, "external-two");
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
    assert.ok(validated.includes("external-two"));
  });

  test("restoration publishes after a newer invalid operation ends", async () => {
    const storeStarted = deferred();
    const releaseStore = deferred();
    const restoreStarted = deferred();
    const releaseRestore = deferred();
    const { manager, secrets } = createHarness("old-key", async candidate => (
      candidate === "bad-newer-key"
        ? apiFailure("unauthorized", { message: "Rejected." })
        : apiSuccess({ authenticated: true })
    ));
    await manager.initialize();
    let stores = 0;
    secrets.storeHook = async (key, value, store) => {
      stores += 1;
      if (stores === 1) {
        storeStarted.resolve();
        await releaseStore.promise;
      } else if (stores === 2) {
        restoreStarted.resolve();
        await releaseRestore.promise;
      }
      store.value = value;
      store.emit(key);
    };

    const pending = manager.replaceCredential("internal-key");
    await storeStarted.promise;
    secrets.externalSet("external-key");
    releaseStore.resolve();
    await restoreStarted.promise;
    const newerResult = await manager.replaceCredential("bad-newer-key");
    assert.strictEqual(newerResult.ok, false);
    releaseRestore.resolve();
    await pending;

    assert.strictEqual(secrets.value, "external-key");
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
    assert.strictEqual(manager.getState().sessionConnected, true);
  });

  test("retired restoration fingerprints do not swallow later external rollback values", async () => {
    const storeStarted = deferred();
    const releaseStore = deferred();
    const validated = [];
    const { manager, secrets } = createHarness("old-key", async candidate => {
      validated.push(candidate);
      return apiSuccess({ authenticated: true });
    });
    await manager.initialize();
    let stores = 0;
    secrets.storeHook = async (key, value, store) => {
      stores += 1;
      if (stores === 1) {
        storeStarted.resolve();
        await releaseStore.promise;
      }
      store.value = value;
      store.emit(key);
    };

    const pending = manager.replaceCredential("internal-key");
    await storeStarted.promise;
    secrets.externalSet("external-key");
    releaseStore.resolve();
    await pending;
    const validationCount = validated.length;

    secrets.externalSet("internal-key");
    await nextTurn();
    await nextTurn();

    assert.strictEqual(validated.length, validationCount + 1);
    assert.strictEqual(validated.at(-1), "internal-key");
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
  });

  test("an external replacement during the final store reread prevents stale success", async () => {
    const finalReadStarted = deferred();
    const releaseFinalRead = deferred();
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();
    let authReads = 0;
    secrets.getHook = async (key, store) => {
      if (key !== AUTH_TOKEN_KEY) return null;
      authReads += 1;
      const captured = store.value;
      if (authReads === 2) {
        finalReadStarted.resolve();
        await releaseFinalRead.promise;
      }
      return captured;
    };

    const pending = manager.replaceCredential("internal-key");
    await finalReadStarted.promise;
    secrets.externalSet("external-key");
    releaseFinalRead.resolve();
    const result = await pending;
    await nextTurn();

    assert.strictEqual(result.status, "superseded");
    assert.strictEqual(secrets.value, "external-key");
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
  });

  test("an external replacement during the final delete reread prevents stale disconnect", async () => {
    const finalReadStarted = deferred();
    const releaseFinalRead = deferred();
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();
    let authReads = 0;
    secrets.getHook = async (key, store) => {
      if (key !== AUTH_TOKEN_KEY) return null;
      authReads += 1;
      const captured = store.value;
      if (authReads === 2) {
        finalReadStarted.resolve();
        await releaseFinalRead.promise;
      }
      return captured;
    };

    const pending = manager.disconnect();
    await finalReadStarted.promise;
    secrets.externalSet("external-key");
    releaseFinalRead.resolve();
    const result = await pending;
    await nextTurn();

    assert.strictEqual(result.status, "superseded");
    assert.strictEqual(secrets.value, "external-key");
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
  });

  test("a newer completed intent during the final store reread forces fresh reconciliation", async () => {
    const finalReadStarted = deferred();
    const releaseFinalRead = deferred();
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();
    let authReads = 0;
    secrets.getHook = async (key, store) => {
      if (key !== AUTH_TOKEN_KEY) return null;
      authReads += 1;
      const captured = store.value;
      if (authReads === 2) {
        finalReadStarted.resolve();
        await releaseFinalRead.promise;
      }
      return captured;
    };

    const pending = manager.replaceCredential("internal-key");
    await finalReadStarted.promise;
    const newer = manager.beginCredentialOperation();
    await manager.cancelCredentialOperation(newer);
    releaseFinalRead.resolve();
    const result = await pending;

    assert.strictEqual(result.status, "stale");
    assertStoredAPIKey(secrets.value, "internal-key");
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
    assert.ok(manager.getState().operationId > newer.id);
  });

  test("a newer completed intent during the final delete reread forces fresh reconciliation", async () => {
    const finalReadStarted = deferred();
    const releaseFinalRead = deferred();
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();
    let authReads = 0;
    secrets.getHook = async (key, store) => {
      if (key !== AUTH_TOKEN_KEY) return null;
      authReads += 1;
      const captured = store.value;
      if (authReads === 2) {
        finalReadStarted.resolve();
        await releaseFinalRead.promise;
      }
      return captured;
    };

    const pending = manager.disconnect();
    await finalReadStarted.promise;
    const newer = manager.beginCredentialOperation();
    await manager.cancelCredentialOperation(newer);
    releaseFinalRead.resolve();
    const result = await pending;

    assert.strictEqual(result.status, "stale");
    assert.strictEqual(secrets.value, null);
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.ABSENT);
    assert.ok(manager.getState().operationId > newer.id);
  });

  test("a store rejection is success when authoritative reread contains the candidate", async () => {
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();
    secrets.storeHook = async (key, value, store) => {
      store.value = value;
      store.emit(key);
      throw new Error("ambiguous store rejection");
    };

    const result = await manager.replaceCredential("new-key");

    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.committed, true);
    assert.strictEqual(manager.getState().accountEpoch, 2);
  });

  test("a store rejection that leaves the old token restores the old session", async () => {
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();
    secrets.storeHook = async () => {
      throw new Error("store failed");
    };

    const result = await manager.replaceCredential("new-key");

    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.preserved, true);
    assertStoredAPIKey(secrets.value, "old-key");
    assert.strictEqual(manager.getState().accountEpoch, 1);
  });

  test("a store that resolves without changing the secret reports a safe persistence mismatch", async () => {
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();
    secrets.storeHook = async () => {};

    const result = await manager.replaceCredential("new-key");

    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, "superseded");
    assert.strictEqual(result.error.kind, "persistence_mismatch");
    assert.ok(result.error.message.length > 0);
    assertStoredAPIKey(secrets.value, "old-key");
  });

  test("a delete that resolves without changing the secret reports a safe persistence mismatch", async () => {
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();
    secrets.deleteHook = async () => {};

    const result = await manager.disconnect();

    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, "superseded");
    assert.strictEqual(result.error.kind, "persistence_mismatch");
    assert.ok(result.error.message.length > 0);
    assertStoredAPIKey(secrets.value, "old-key");
  });

  test("an unreadable pre-write lock check fails closed without mutating account identity", async () => {
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();
    secrets.storeHook = async () => {
      throw new Error("write outcome unknown");
    };
    secrets.getHook = async () => {
      throw new Error("read failed");
    };

    const result = await manager.replaceCredential("new-key");

    assert.strictEqual(result.status, CONNECTION_STATUSES.INDETERMINATE);
    assert.strictEqual(manager.getState().sessionConnected, false);
    assert.strictEqual(manager.getState().credentialPresent, null);
    assert.strictEqual(manager.getState().accountEpoch, 1);
  });

  test("an external replacement supersedes an in-flight candidate", async () => {
    const pendingCandidate = deferred();
    const { manager, secrets } = createHarness("old-key", candidate => {
      if (candidate === "candidate-key") return pendingCandidate.promise;
      return Promise.resolve(apiSuccess({ authenticated: true }));
    });
    await manager.initialize();

    const replacement = manager.replaceCredential("candidate-key");
    secrets.externalSet("external-key");
    await nextTurn();
    pendingCandidate.resolve(apiSuccess({ authenticated: true }));
    const result = await replacement;
    await nextTurn();

    assert.strictEqual(result.status, "stale");
    assert.strictEqual(secrets.value, "external-key");
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
    assert.strictEqual(manager.getState().accountEpoch, 2);
  });

  test("external deletion invalidates the session once", async () => {
    const { manager, secrets } = createHarness("old-key", async () => apiSuccess({ authenticated: true }));
    await manager.initialize();

    secrets.externalSet(null);
    await nextTurn();
    await nextTurn();

    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.ABSENT);
    assert.strictEqual(manager.getState().sessionConnected, false);
    assert.strictEqual(manager.getState().accountEpoch, 2);
  });

  test("malformed stored credentials are present but fail closed", async () => {
    const { manager } = createHarness(" bad-key\n", async () => {
      throw new Error("malformed values must not reach the API");
    });

    const result = await manager.initialize();

    assert.strictEqual(result.ok, false);
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.FAILED);
    assert.strictEqual(manager.getState().credentialPresent, true);
    assert.strictEqual(manager.getState().sessionConnected, false);
  });

  test("registry access is activation-bound and fails closed after unbind", async () => {
    const { context, manager } = createHarness(null, async () => apiSuccess({ authenticated: true }));
    const binding = bindConnectionManager(context, manager, manager.activationId);
    await manager.initialize();

    assert.strictEqual(getConnectionManager(context), manager);
    assert.strictEqual(getConnectionManager(context, "wrong-activation"), null);
    assert.strictEqual(getAccountEpoch(context, manager.activationId), 1);
    binding.dispose();
    assert.strictEqual(getConnectionManager(context), null);
    assert.strictEqual(getAccountEpoch(context), null);
    assert.strictEqual(unbindConnectionManager(context), false);
  });

  test("context projection retries and reports partial success without changing authority", async () => {
    const projections = [];
    const secrets = new FakeSecretStorage({}, { primaryKey: AUTH_TOKEN_KEY });
    const manager = new ConnectionManager({ secrets }, {
      activationId: "projection-test",
      createCloudsmithAPI: () => ({ get: async () => apiSuccess({ authenticated: true }) }),
      executeCommand: async (...args) => {
        projections.push(args);
        throw new Error("projection unavailable");
      },
    });
    await manager.initialize();
    projections.length = 0;

    const result = await manager.replaceCredential("new-key");

    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.partial, true);
    assert.deepStrictEqual(
      { kind: result.error.kind, message: result.error.message },
      {
        kind: "unexpected",
        message: "Could not update the Cloudsmith connection indicator.",
      },
    );
    assert.ok(Object.isFrozen(result.error));
    assert.deepStrictEqual(projections, [
      ["setContext", "cloudsmith.connected", true],
      ["setContext", "cloudsmith.connected", true],
      ["setContext", "cloudsmith.connected", false],
      ["setContext", "cloudsmith.connected", false],
      ["setContext", "cloudsmith.connected", false],
      ["setContext", "cloudsmith.connected", false],
    ]);
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
    assert.strictEqual(manager.getState().sessionConnected, true);
  });

  test("disposal settles pending projection work and resets the connected context", async () => {
    const projectionStarted = deferred();
    const releaseProjection = deferred();
    const projections = [];
    const secrets = new FakeSecretStorage(
      { [AUTH_TOKEN_KEY]: "stored-key" },
      { primaryKey: AUTH_TOKEN_KEY }
    );
    let calls = 0;
    const manager = new ConnectionManager({ secrets }, {
      activationId: "projection-disposal",
      createCloudsmithAPI: () => ({ get: async () => apiSuccess({ authenticated: true }) }),
      executeCommand: async (...args) => {
        calls += 1;
        projections.push(args);
        if (calls === 1) {
          projectionStarted.resolve();
          await releaseProjection.promise;
        }
      },
    });

    const initialization = manager.initialize();
    await projectionStarted.promise;
    const disposal = manager.dispose();
    releaseProjection.resolve();
    await initialization;
    await disposal;

    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.DISPOSED);
    assert.deepStrictEqual(projections.at(-1), [
      "setContext",
      "cloudsmith.connected",
      false,
    ]);
  });

  test("an explicit API candidate bypasses stored credential lookup", async () => {
    let credentialReads = 0;
    const api = new CloudsmithAPI({
      secrets: new FakeSecretStorage(
        { [AUTH_TOKEN_KEY]: "stored-key" },
        { primaryKey: AUTH_TOKEN_KEY }
      ),
    }, {
      credentialManager: {
        async getApiKey() {
          credentialReads += 1;
          throw new Error("stored credentials must not be read");
        },
      },
      fetchImpl: async (_requestUrl, options) => {
        assert.strictEqual(options.headers["X-Api-Key"], "candidate-key");
        return new Response(JSON.stringify({ authenticated: true }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
      randomUUID: () => "request-id",
    });

    const result = await api.get("user/self", {
      credential: { version: 1, kind: "api-key", apiKey: "candidate-key" },
      responseType: "object",
      validate: value => value.authenticated === true,
    });

    assert.strictEqual(result.ok, true);
    assert.strictEqual(credentialReads, 0);
  });
});

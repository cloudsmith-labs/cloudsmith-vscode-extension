const assert = require("assert");
const credentialModule = require("../util/credentialManager");
const { CredentialManager } = credentialModule;

function deferred() {
  let resolve;
  const promise = new Promise(res => { resolve = res; });
  return { promise, resolve };
}

function createManagerHarness() {
  const calls = [];
  const listeners = new Set();
  let current = null;
  let nextId = 0;
  const connectionManager = {
    beginCredentialOperation() {
      calls.push("begin");
      current?.controller.abort();
      const controller = new AbortController();
      current = Object.freeze({ id: ++nextId, controller, signal: controller.signal });
      for (const listener of [...listeners]) listener();
      return current;
    },
    isOperationCurrent(token) {
      return Boolean(token && token === current && !token.signal.aborted);
    },
    cancelCredentialOperation(token) {
      calls.push(["cancel", token.id]);
      if (token !== current) return Object.freeze({ ok: false, status: "stale" });
      token.controller.abort();
      current = null;
      for (const listener of [...listeners]) listener();
      return Object.freeze({ ok: false, status: "cancelled" });
    },
    onDidChange(listener) {
      listeners.add(listener);
      return { dispose: () => listeners.delete(listener) };
    },
    async replaceCredential(value, token) {
      calls.push(["replace", value, token.id]);
      return Object.freeze({ ok: true, status: "connected", committed: true });
    },
    async disconnect(token) {
      calls.push(["disconnect", token.id]);
      return Object.freeze({ ok: true, status: "absent", committed: true });
    },
    getState() {
      return Object.freeze({ credentialPresent: true });
    },
  };
  return { calls, connectionManager, getCurrent: () => current };
}

suite("CredentialManager Test Suite", () => {
  test("manual input begins an auth operation before awaiting the secret prompt", async () => {
    const input = deferred();
    const { calls, connectionManager } = createManagerHarness();
    const manager = new CredentialManager({ secrets: {} }, {
      connectionManager,
      showInputBox: () => {
        calls.push("prompt");
        return input.promise;
      },
    });

    const pending = manager.storeApiKey();
    assert.deepStrictEqual(calls, ["begin", "prompt"]);
    input.resolve(" candidate-key ");
    const result = await pending;

    assert.strictEqual(result.ok, true);
    assert.deepStrictEqual(calls[2].slice(0, 2), ["replace", " candidate-key "]);
  });

  test("a supplied operation is reused instead of allocating a second token", async () => {
    const { calls, connectionManager } = createManagerHarness();
    const operation = connectionManager.beginCredentialOperation();
    calls.length = 0;
    const manager = new CredentialManager({ secrets: {} }, {
      connectionManager,
      showInputBox: async () => "candidate-key",
    });

    const result = await manager.storeApiKey(operation);

    assert.strictEqual(result.ok, true);
    assert.ok(!calls.includes("begin"));
    assert.deepStrictEqual(calls[0], ["replace", "candidate-key", operation.id]);
  });

  test("an operation-scoped prompt overrides the default input path", async () => {
    const { calls, connectionManager } = createManagerHarness();
    const operation = connectionManager.beginCredentialOperation();
    let defaultPrompts = 0;
    let scopedPrompts = 0;
    const manager = new CredentialManager({ secrets: {} }, {
      connectionManager,
      showInputBox: async () => {
        defaultPrompts += 1;
        return "wrong-key";
      },
    });

    const result = await manager.storeApiKey(operation, {
      async showInputBox(options) {
        scopedPrompts += 1;
        assert.strictEqual(options.password, true);
        return "candidate-key";
      },
    });

    assert.strictEqual(result.ok, true);
    assert.strictEqual(defaultPrompts, 0);
    assert.strictEqual(scopedPrompts, 1);
    assert.ok(calls.some(call => (
      Array.isArray(call)
      && call[0] === "replace"
      && call[1] === "candidate-key"
    )));
  });

  test("a superseding credential operation closes a pending secret prompt", async () => {
    const { calls, connectionManager } = createManagerHarness();
    let cancelled = false;
    const manager = new CredentialManager({ secrets: {} }, {
      connectionManager,
      showInputBox(_options, token) {
        return new Promise(resolve => {
          token.onCancellationRequested(() => {
            cancelled = true;
            resolve(undefined);
          });
        });
      },
    });

    const pending = manager.storeApiKey();
    const replacement = connectionManager.beginCredentialOperation();
    const result = await pending;

    assert.strictEqual(cancelled, true);
    assert.strictEqual(result.status, "stale");
    assert.strictEqual(connectionManager.isOperationCurrent(replacement), true);
    assert.strictEqual(calls.some(call => Array.isArray(call) && call[0] === "replace"), false);
  });

  test("cancelling manual input cancels the exact operation without storing", async () => {
    const { calls, connectionManager } = createManagerHarness();
    const manager = new CredentialManager({ secrets: {} }, {
      connectionManager,
      showInputBox: async () => undefined,
    });

    const result = await manager.storeApiKey();

    assert.strictEqual(result.status, "cancelled");
    assert.strictEqual(calls.some(call => Array.isArray(call) && call[0] === "replace"), false);
  });

  test("manual prompt failures return a fixed message without leaking typed error details", async () => {
    const secret = "prompt-error-secret-must-not-leak";
    const { calls, connectionManager, getCurrent } = createManagerHarness();
    const manager = new CredentialManager({ secrets: {} }, {
      connectionManager,
      showInputBox: async () => {
        throw Object.assign(new Error(`prompt failed for ${secret}`), { kind: "input_error" });
      },
    });

    const result = await manager.storeApiKey();

    assert.strictEqual(result.status, "failed");
    assert.strictEqual(result.error.message, "Could not read the API key. Try again.");
    assert.strictEqual(connectionManager.isOperationCurrent(getCurrent()), false);
    assert.strictEqual(JSON.stringify({ result, calls }).includes(secret), false);
  });

  test("confirmed clearing delegates deletion to the authoritative manager", async () => {
    const { calls, connectionManager } = createManagerHarness();
    const manager = new CredentialManager({ secrets: {} }, {
      connectionManager,
      showWarningMessage: async () => "Delete",
    });

    const result = await manager.clearCredentials();

    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.status, "absent");
    assert.ok(calls.some(call => Array.isArray(call) && call[0] === "disconnect"));
  });

  test("confirmation failures return a fixed message without leaking typed error details", async () => {
    const secret = "confirmation-error-secret-must-not-leak";
    const { calls, connectionManager, getCurrent } = createManagerHarness();
    const manager = new CredentialManager({ secrets: {} }, {
      connectionManager,
      showWarningMessage: async () => {
        throw Object.assign(new Error(`confirmation failed for ${secret}`), { kind: "ui_error" });
      },
    });

    const result = await manager.clearCredentials();

    assert.strictEqual(result.status, "failed");
    assert.strictEqual(result.error.message, "Could not confirm credential deletion. Try again.");
    assert.strictEqual(connectionManager.isOperationCurrent(getCurrent()), false);
    assert.strictEqual(JSON.stringify({ result, calls }).includes(secret), false);
  });

  test("raw reads remain available for authenticated API requests", async () => {
    const manager = new CredentialManager({
      secrets: { async get(key) { return key === "cloudsmith-vsc.authToken" ? "stored-key" : null; } },
    });

    assert.strictEqual(await manager.getApiKey(), "stored-key");
  });

  test("does not expose activation-time CLI credential auto-detection", () => {
    assert.strictEqual(Object.prototype.hasOwnProperty.call(credentialModule, "runCLIAutoDetect"), false);
  });
});

const assert = require("assert");
const { CredentialManager, runCLIAutoDetect } = require("../util/credentialManager");

function deferred() {
  let resolve;
  const promise = new Promise(res => { resolve = res; });
  return { promise, resolve };
}

function createManagerHarness() {
  const calls = [];
  let current = null;
  let nextId = 0;
  const connectionManager = {
    beginCredentialOperation() {
      calls.push("begin");
      const controller = new AbortController();
      current = Object.freeze({ id: ++nextId, controller, signal: controller.signal });
      return current;
    },
    isOperationCurrent(token) {
      return token === current && !token.signal.aborted;
    },
    cancelCredentialOperation(token) {
      calls.push(["cancel", token.id]);
      if (token === current) token.controller.abort();
      return Object.freeze({ ok: false, status: "cancelled" });
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

  test("CLI auto-detect owns the operation before reading and cannot supersede manual configure", async () => {
    const read = deferred();
    const { calls, connectionManager } = createManagerHarness();
    connectionManager.getState = () => Object.freeze({
      status: "absent",
      credentialPresent: false,
      sessionConnected: false,
    });
    let prompts = 0;
    const pending = runCLIAutoDetect({
      connectionManager,
      secrets: {
        get() {
          calls.push("read");
          return read.promise;
        },
      },
      ssoManager: {
        hasCLICredentials() { return true; },
        async importFromCLI() { throw new Error("must not import"); },
      },
      showInformationMessage: async () => {
        prompts += 1;
        return "Import";
      },
      handleAuthenticationResult: async () => {},
    });
    assert.deepStrictEqual(calls.slice(0, 2), ["begin", "read"]);

    const manualOperation = connectionManager.beginCredentialOperation();
    read.resolve(null);
    const result = await pending;

    assert.strictEqual(result.status, "stale");
    assert.strictEqual(prompts, 0);
    assert.strictEqual(connectionManager.isOperationCurrent(manualOperation), true);
  });

  test("CLI auto-detect cancels its operation when the stored credential read fails", async () => {
    const secret = "candidate-secret-must-not-leak";
    const { calls, connectionManager, getCurrent } = createManagerHarness();
    connectionManager.getState = () => Object.freeze({
      status: "absent",
      credentialPresent: false,
      sessionConnected: false,
    });

    const result = await runCLIAutoDetect({
      connectionManager,
      secrets: {
        async get() { throw new Error(`read failed for ${secret}`); },
      },
      ssoManager: {
        hasCLICredentials() { throw new Error("must not inspect CLI credentials"); },
      },
      showInformationMessage: async () => { throw new Error("must not prompt"); },
      handleAuthenticationResult: async () => {},
    });

    assert.strictEqual(result.status, "failed");
    assert.strictEqual(result.committed, false);
    assert.strictEqual(connectionManager.isOperationCurrent(getCurrent()), false);
    assert.deepStrictEqual(calls, ["begin", ["cancel", 1]]);
    assert.ok(!JSON.stringify(result).includes(secret));
  });
});

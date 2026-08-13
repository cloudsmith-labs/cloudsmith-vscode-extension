// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const { captureAccount, isAccountCurrent } = require("../util/accountOperation");

suite("account operation boundary", () => {
  function manager(initial) {
    let state = { ...initial };
    return {
      getState: () => Object.freeze({ ...state }),
      update: next => { state = { ...state, ...next }; },
    };
  }

  test("does not capture an unvalidated startup account", () => {
    const connectionManager = manager({
      activationId: "activation-a",
      accountEpoch: 1,
      credentialPresent: true,
      sessionConnected: false,
      status: "validating",
    });
    assert.strictEqual(captureAccount(connectionManager), null);
  });

  test("captures only a currently authorized account identity", () => {
    const connectionManager = manager({
      activationId: "activation-a",
      accountEpoch: 1,
      sessionConnected: true,
      status: "connected",
    });
    const account = captureAccount(connectionManager);
    assert.deepStrictEqual(account, { activationId: "activation-a", accountEpoch: 1 });
    assert.strictEqual(Object.isFrozen(account), true);
    assert.strictEqual(isAccountCurrent(connectionManager, account), true);

    connectionManager.update({ sessionConnected: false, status: "validating" });
    assert.strictEqual(isAccountCurrent(connectionManager, account), false);
    connectionManager.update({ sessionConnected: true, accountEpoch: 2, status: "connected" });
    assert.strictEqual(isAccountCurrent(connectionManager, account), false);
  });

  test("preserves capture of the old authorized session during candidate validation", () => {
    const connectionManager = manager({
      activationId: "activation-a",
      accountEpoch: 4,
      credentialPresent: true,
      sessionConnected: true,
      status: "validating",
    });
    assert.deepStrictEqual(captureAccount(connectionManager), {
      activationId: "activation-a",
      accountEpoch: 4,
    });
  });

  test("rejects malformed identity and every disconnected terminal state", () => {
    for (const state of [
      null,
      { activationId: "", accountEpoch: 1, sessionConnected: true },
      { activationId: "a", accountEpoch: null, sessionConnected: true },
      { activationId: "a", accountEpoch: 1, sessionConnected: false, status: "absent" },
      { activationId: "a", accountEpoch: 1, sessionConnected: false, status: "failed" },
      { activationId: "a", accountEpoch: 1, sessionConnected: false, status: "disposed" },
    ]) {
      assert.strictEqual(captureAccount({ getState: () => state }), null);
    }
  });
});

// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const {
  CONNECTION_PRESENTATIONS,
  connectionPresentation,
  connectionSetupAvailable,
} = require("../util/connectionPresentation");

suite("connection presentation", () => {
  const base = Object.freeze({
    activationId: "activation-a",
    accountEpoch: 1,
    credentialPresent: null,
    sessionConnected: false,
    error: null,
  });

  test("maps the authoritative lifecycle without treating uncertainty as absence", () => {
    const cases = [
      [{ ...base, status: "indeterminate" }, CONNECTION_PRESENTATIONS.CONNECTING],
      [{ ...base, status: "validating" }, CONNECTION_PRESENTATIONS.CONNECTING],
      [{ ...base, status: "absent", credentialPresent: false }, CONNECTION_PRESENTATIONS.ABSENT],
      [{ ...base, status: "failed", credentialPresent: true }, CONNECTION_PRESENTATIONS.FAILED],
      [{ ...base, status: "indeterminate", error: { message: "safe" } }, CONNECTION_PRESENTATIONS.UNAVAILABLE],
      [{ ...base, status: "disposed" }, CONNECTION_PRESENTATIONS.DISPOSED],
    ];
    for (const [state, expected] of cases) {
      assert.strictEqual(connectionPresentation(state), expected);
    }
  });

  test("keeps a previously authorized account connected during candidate validation", () => {
    assert.strictEqual(connectionPresentation({
      ...base,
      status: "validating",
      credentialPresent: true,
      sessionConnected: true,
    }), CONNECTION_PRESENTATIONS.CONNECTED);
  });

  test("requires coherent authoritative fields before presenting connected or absent", () => {
    for (const state of [
      { ...base, status: "connected", sessionConnected: false, credentialPresent: true },
      { ...base, status: "connected", sessionConnected: true, activationId: "" },
      { ...base, status: "connected", sessionConnected: true, accountEpoch: -1 },
      { ...base, status: "connected", sessionConnected: true, credentialPresent: false },
      { ...base, status: "absent", credentialPresent: null },
      { ...base, status: "failed", credentialPresent: false },
    ]) {
      assert.strictEqual(connectionPresentation(state), CONNECTION_PRESENTATIONS.UNAVAILABLE);
    }
    assert.strictEqual(connectionPresentation({
      ...base,
      status: "connected",
      credentialPresent: true,
      sessionConnected: true,
    }), CONNECTION_PRESENTATIONS.CONNECTED);
  });

  test("fails closed for omitted, malformed, and unknown input without reflecting errors", () => {
    const sensitiveError = Object.freeze({
      message: "SecretStorage /user/self csa_raw_secret https://key@example.test",
    });
    for (const state of [
      undefined,
      null,
      [],
      "connected",
      { ...base, status: "future-state" },
      { ...base, status: "indeterminate", error: sensitiveError },
    ]) {
      const result = connectionPresentation(state);
      assert.strictEqual(result, CONNECTION_PRESENTATIONS.UNAVAILABLE);
      assert.strictEqual(result.includes("SecretStorage"), false);
      assert.strictEqual(result.includes("csa_raw_secret"), false);
    }
  });

  test("allows setup actions only for authoritative absence or actionable failure", () => {
    const visible = [
      { ...base, status: "absent", credentialPresent: false },
      { ...base, status: "failed", credentialPresent: true },
    ];
    const hidden = [
      undefined,
      { ...base, status: "indeterminate" },
      { ...base, status: "validating", credentialPresent: true },
      { ...base, status: "indeterminate", error: { message: "safe" } },
      { ...base, status: "disposed" },
      {
        ...base,
        status: "connected",
        credentialPresent: true,
        sessionConnected: true,
      },
    ];
    for (const state of visible) assert.strictEqual(connectionSetupAvailable(state), true);
    for (const state of hidden) assert.strictEqual(connectionSetupAvailable(state), false);
  });
});

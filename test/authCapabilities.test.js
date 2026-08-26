// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const {
  PULL_THROUGH_API_KEY_MESSAGE,
  authenticationCapabilitiesFor,
  deriveAuthenticationCapabilities,
} = require("../domain/authCapabilities");

suite("Authentication capabilities", () => {
  test("only a connected API-key session grants pull-through", () => {
    const available = deriveAuthenticationCapabilities({
      credentialKind: "api-key",
      sessionConnected: true,
    });
    assert.deepStrictEqual(available, { pullThroughAvailable: true });
    assert.ok(Object.isFrozen(available));

    for (const input of [
      { credentialKind: "sso", sessionConnected: true },
      { credentialKind: "api-key", sessionConnected: false },
      { credentialKind: "unknown", sessionConnected: true },
      { credentialKind: { hostile: true }, sessionConnected: true },
      { credentialKind: "api-key", sessionConnected: "true" },
      null,
      undefined,
    ]) {
      assert.deepStrictEqual(
        deriveAuthenticationCapabilities(input),
        { pullThroughAvailable: false },
        JSON.stringify(input)
      );
    }
  });

  test("capability access fails closed for missing, malformed, and throwing sources", () => {
    for (const source of [
      null,
      {},
      { getAuthenticationCapabilities: () => null },
      { getAuthenticationCapabilities: () => ({ pullThroughAvailable: "true" }) },
      { getAuthenticationCapabilities() { throw new Error("secret state"); } },
    ]) {
      assert.deepStrictEqual(
        authenticationCapabilitiesFor(source),
        { pullThroughAvailable: false }
      );
    }

    assert.deepStrictEqual(authenticationCapabilitiesFor({
      getAuthenticationCapabilities: () => ({ pullThroughAvailable: true }),
    }), { pullThroughAvailable: true });
  });

  test("hostile accessors, proxies, symbols, and inherited grants fail closed", () => {
    const hostileInput = {};
    Object.defineProperty(hostileInput, "sessionConnected", {
      get() { throw new Error("must not invoke input accessors"); },
    });
    const inherited = Object.create({
      credentialKind: "api-key",
      sessionConnected: true,
    });
    const hostileProxy = new Proxy({}, {
      getOwnPropertyDescriptor() { throw new Error("hostile descriptor trap"); },
      get() { throw new Error("hostile read trap"); },
    });
    for (const input of [hostileInput, inherited, hostileProxy, Symbol("hostile")]) {
      assert.doesNotThrow(() => deriveAuthenticationCapabilities(input));
      assert.deepStrictEqual(
        deriveAuthenticationCapabilities(input),
        { pullThroughAvailable: false }
      );
    }

    const hostileSource = {};
    Object.defineProperty(hostileSource, "getAuthenticationCapabilities", {
      get() { throw new Error("must fail closed"); },
    });
    const hostileResult = {
      getAuthenticationCapabilities: () => new Proxy({}, {
        getOwnPropertyDescriptor() { throw new Error("hostile result"); },
        get() { throw new Error("hostile result"); },
      }),
    };
    for (const source of [hostileSource, hostileResult, hostileProxy, Symbol("hostile")]) {
      assert.doesNotThrow(() => authenticationCapabilitiesFor(source));
      assert.deepStrictEqual(
        authenticationCapabilitiesFor(source),
        { pullThroughAvailable: false }
      );
    }
  });

  test("the unavailable path owns one concise actionable message", () => {
    assert.strictEqual(
      PULL_THROUGH_API_KEY_MESSAGE,
      "Pull-through requires a Cloudsmith API key. Sign in with an API key to continue."
    );
  });
});

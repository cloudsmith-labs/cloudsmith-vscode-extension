// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const {
  PULL_THROUGH_API_KEY_MESSAGE,
  authenticationCapabilitiesFor,
  deriveAuthenticationCapabilities,
  isPullThroughAvailable,
} = require("../domain/authCapabilities");

suite("Authentication capabilities", () => {
  test("authentication methods expose the exact frozen customer choices", () => {
    const modulePath = require.resolve("../domain/authCapabilities");
    delete require.cache[modulePath];
    const reloaded = require(modulePath);

    assert.deepStrictEqual(reloaded.AUTHENTICATION_METHODS, [
      {
        id: "personal-api-key",
        label: "$(key) Enter API key",
        description: "Paste a personal API key",
        documentationLabel: "API key",
        method: "api-key",
      },
      {
        id: "service-account-api-key",
        label: "$(server) Enter service account API key",
        description: "Paste a service account API key",
        documentationLabel: "Service account API key",
        method: "api-key",
      },
      {
        id: "cloudsmith-cli",
        label: "$(folder-opened) Import API key from Cloudsmith CLI",
        description: "Import the [default] API key from a trusted credentials.ini",
        documentationLabel: "Import API key from Cloudsmith CLI",
        method: "import",
      },
      {
        id: "sso-browser",
        label: "$(globe) Sign in with SSO",
        description: "Sign in through your organization's identity provider",
        documentationLabel: "Sign in with SSO",
        method: "sso-browser",
      },
    ]);
    assert.strictEqual(Object.isFrozen(reloaded.AUTHENTICATION_METHODS), true);
    assert.strictEqual(
      reloaded.AUTHENTICATION_METHODS.every(method => Object.isFrozen(method)),
      true
    );
    assert.strictEqual(
      reloaded.PULL_THROUGH_API_KEY_MESSAGE,
      "Pull-through requires a Cloudsmith API key. Sign in with an API key to continue."
    );
    assert.deepStrictEqual(reloaded.deriveAuthenticationCapabilities({
      credentialKind: "api-key",
      sessionConnected: true,
    }), { pullThroughAvailable: true });
    assert.deepStrictEqual(
      reloaded.deriveAuthenticationCapabilities({ credentialKind: "sso", sessionConnected: true }),
      { pullThroughAvailable: false }
    );
    assert.deepStrictEqual(
      Object.keys(reloaded).sort(),
      [
        "AUTHENTICATION_METHODS",
        "PULL_THROUGH_API_KEY_MESSAGE",
        "authenticationCapabilitiesFor",
        "deriveAuthenticationCapabilities",
        "isPullThroughAvailable",
      ]
    );
  });

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

  test("own data properties grant while accessors and inherited state fail closed", () => {
    const nullPrototypeState = Object.create(null);
    Object.defineProperties(nullPrototypeState, {
      credentialKind: { value: "api-key" },
      sessionConnected: { value: true },
    });
    assert.deepStrictEqual(
      deriveAuthenticationCapabilities(nullPrototypeState),
      { pullThroughAvailable: true }
    );

    const functionState = function authenticationState() {};
    functionState.credentialKind = "api-key";
    functionState.sessionConnected = true;
    assert.deepStrictEqual(
      deriveAuthenticationCapabilities(functionState),
      { pullThroughAvailable: true }
    );

    const accessorState = {};
    Object.defineProperties(accessorState, {
      credentialKind: { get: () => "api-key" },
      sessionConnected: { get: () => true },
    });
    assert.deepStrictEqual(
      deriveAuthenticationCapabilities(accessorState),
      { pullThroughAvailable: false }
    );
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

    let forgedCallCount = 0;
    const forgedMethod = {
      call() {
        forgedCallCount += 1;
        return { pullThroughAvailable: true };
      },
    };
    assert.deepStrictEqual(authenticationCapabilitiesFor({
      getAuthenticationCapabilities: forgedMethod,
    }), { pullThroughAvailable: false });
    assert.strictEqual(forgedCallCount, 0);
  });

  test("capability lookup preserves receiver identity and accepts prototype methods", () => {
    class CapabilitySource {
      constructor() {
        this.expectedReceiver = this;
        this.calls = 0;
      }

      getAuthenticationCapabilities() {
        assert.strictEqual(this, this.expectedReceiver);
        this.calls += 1;
        const result = function capabilities() {};
        result.pullThroughAvailable = true;
        return result;
      }
    }
    const source = new CapabilitySource();

    assert.deepStrictEqual(
      authenticationCapabilitiesFor(source),
      { pullThroughAvailable: true }
    );
    assert.strictEqual(source.calls, 1);

    const inheritedGrant = Object.create({ pullThroughAvailable: true });
    assert.deepStrictEqual(authenticationCapabilitiesFor({
      getAuthenticationCapabilities: () => inheritedGrant,
    }), { pullThroughAvailable: false });
  });

  test("boolean helper mirrors exact capability truth on both paths", () => {
    const available = {
      getAuthenticationCapabilities: () => ({ pullThroughAvailable: true }),
    };
    const unavailable = {
      getAuthenticationCapabilities: () => ({ pullThroughAvailable: false }),
    };
    assert.strictEqual(isPullThroughAvailable(available), true);
    assert.strictEqual(isPullThroughAvailable(unavailable), false);
    assert.strictEqual(isPullThroughAvailable(null), false);
    assert.strictEqual(isPullThroughAvailable({
      getAuthenticationCapabilities() { throw new Error("unavailable"); },
    }), false);
  });

  test("capability results are canonical frozen singletons", () => {
    const availableState = { credentialKind: "api-key", sessionConnected: true };
    const unavailableState = { credentialKind: "sso", sessionConnected: true };
    const firstAvailable = deriveAuthenticationCapabilities(availableState);
    const secondAvailable = deriveAuthenticationCapabilities(availableState);
    const firstUnavailable = deriveAuthenticationCapabilities(unavailableState);
    const secondUnavailable = authenticationCapabilitiesFor(null);

    assert.strictEqual(firstAvailable, secondAvailable);
    assert.strictEqual(firstUnavailable, secondUnavailable);
    assert.strictEqual(Object.isFrozen(firstAvailable), true);
    assert.strictEqual(Object.isFrozen(firstUnavailable), true);
    assert.deepStrictEqual(firstAvailable, { pullThroughAvailable: true });
    assert.deepStrictEqual(firstUnavailable, { pullThroughAvailable: false });
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

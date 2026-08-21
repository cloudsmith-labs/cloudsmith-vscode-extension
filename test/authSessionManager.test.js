const assert = require("assert");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const {
  AUTH_TOKEN_KEY,
  CONNECTION_STATUSES,
  ConnectionManager,
} = require("../util/connectionManager");
const {
  createSSOCredential,
  decodeStoredCredential,
  serializeCredential,
} = require("../util/credentialEnvelope");
const { SSOAuthManager } = require("../util/ssoAuthManager");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");
const { FakeSecretStorage } = require("./helpers/fakeSecretStorage");

function deferred() {
  let resolve;
  const promise = new Promise(res => { resolve = res; });
  return { promise, resolve };
}

function sendCallback(target) {
  return new Promise((resolve, reject) => {
    const request = http.get(`http://127.0.0.1:12400${target}`, response => {
      response.resume();
      response.on("end", resolve);
    });
    request.on("error", reject);
  });
}

function managerBoundAPI(manager, fetchImpl) {
  return new CloudsmithAPI({}, {
    credentialManager: {
      getAuthorization: options => manager.getAuthorization(options),
      handleAuthorizationRejected: proof => manager.handleAuthorizationRejected(proof),
    },
    fetchImpl,
  });
}

function createSSOHarness(protocolClient, options = {}) {
  const now = options.now || (31 * 60 * 1000);
  const original = createSSOCredential("access-old", "refresh-old", {
    credentialId: "c".repeat(32),
    generation: 0,
    now: 0,
  });
  const secrets = new FakeSecretStorage({
    [AUTH_TOKEN_KEY]: serializeCredential(original),
  }, { primaryKey: AUTH_TOKEN_KEY });
  const context = { secrets };
  const manager = new ConnectionManager(context, {
    activationId: options.activationId || "sso-test",
    now: () => now,
    monotonicNow: options.monotonicNow || (() => now),
    protocolClient,
    mutationLock: options.mutationLock,
    createCloudsmithAPI: () => ({
      async get(endpoint, requestOptions) {
        assert.ok(["api-key", "sso"].includes(requestOptions.credential.kind));
        if (endpoint === "user/self") return apiSuccess({ authenticated: true, slug: "user-slug" });
        if (endpoint.startsWith("namespaces/")) return apiSuccess([{ slug: "workspace" }], {
          headers: {
            "x-pagination-page": "1",
            "x-pagination-pagetotal": "1",
            "x-pagination-count": "1",
            "x-pagination-pagesize": "500",
          },
        });
        throw new Error("unexpected endpoint");
      },
    }),
    executeCommand: async () => {},
  });
  return { manager, original, secrets };
}

suite("SSO session authority", () => {
  test("runs discovery, callback, validation, commit, ordinary bearer API, and refresh end to end", async () => {
    let wall = 0;
    let monotonic = 0;
    let refreshCalls = 0;
    const secrets = new FakeSecretStorage({}, { primaryKey: AUTH_TOKEN_KEY });
    const protocol = {
      async discover(workspace) {
        assert.strictEqual(workspace, "integrated-workspace");
        return { ok: true, redirectUrl: "https://idp.example/saml" };
      },
      async refresh(access, refresh) {
        refreshCalls += 1;
        assert.strictEqual(access, "integrated-access");
        assert.strictEqual(refresh, "integrated-refresh");
        return { ok: true, accessToken: "integrated-access-new", refreshToken: "integrated-refresh-new" };
      },
    };
    const manager = new ConnectionManager({ secrets }, {
      activationId: "integrated-sso",
      now: () => wall,
      monotonicNow: () => monotonic,
      protocolClient: protocol,
      createCloudsmithAPI: () => ({
        async get(endpoint, options) {
          if (endpoint === "user/self") {
            assert.strictEqual(options.credential.kind, "sso");
            return apiSuccess({ authenticated: true, slug: "integrated-principal" });
          }
          assert.strictEqual(endpoint, "namespaces/?page=1&page_size=500&sort=slug");
          return apiSuccess([{ slug: "integrated-workspace" }], {
            headers: {
              "x-pagination-page": "1",
              "x-pagination-pagetotal": "1",
              "x-pagination-count": "1",
              "x-pagination-pagesize": "500",
            },
          });
        },
      }),
      executeCommand: async () => {},
    });
    await manager.initialize();
    const sso = new SSOAuthManager({}, {
      connectionManager: manager,
      protocolClient: protocol,
      async openExternal() {
        await sendCallback("/?access_token=integrated-access&refresh_token=integrated-refresh");
        return true;
      },
      async showInformationMessage(_message, options) {
        return options && options.modal ? "Continue" : undefined;
      },
      showErrorMessage() {},
    });
    const login = await sso.loginViaBrowser("integrated-workspace");
    assert.strictEqual(login.ok, true);

    wall = 31 * 60 * 1000;
    monotonic = wall;
    const requests = [];
    const api = new CloudsmithAPI({}, {
      credentialManager: {
        getAuthorization: options => manager.getAuthorization(options),
        handleAuthorizationRejected: proof => manager.handleAuthorizationRejected(proof),
      },
      fetchImpl: async (_url, options) => {
        requests.push(options.headers);
        return new Response(JSON.stringify({ authenticated: true, slug: "integrated-principal" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    });
    const self = await api.get("user/self", { responseType: "object", retry: "never" });
    assert.strictEqual(self.ok, true);
    assert.strictEqual(refreshCalls, 1);
    assert.strictEqual(requests[0].Authorization, "Bearer integrated-access-new");
    assert.strictEqual(requests[0]["X-Api-Key"], undefined);
    const stored = decodeStoredCredential(secrets.value).credential;
    assert.strictEqual(stored.accessToken, "integrated-access-new");
    assert.strictEqual(stored.refreshToken, "integrated-refresh-new");
  });

  test("validates bearer identity and exact authenticated workspace access before confirmation or commit", async () => {
    const secrets = new FakeSecretStorage({}, { primaryKey: AUTH_TOKEN_KEY });
    const endpoints = [];
    const manager = new ConnectionManager({ secrets }, {
      activationId: "sso-candidate",
      createCloudsmithAPI: () => ({
        async get(endpoint, options) {
          endpoints.push(endpoint);
          assert.strictEqual(options.credential.kind, "sso");
          assert.strictEqual(Object.prototype.hasOwnProperty.call(options, "apiKey"), false);
          if (endpoint === "user/self") return apiSuccess({ authenticated: true, slug: "principal" });
          return apiSuccess([{ slug: "requested-workspace" }], {
            headers: {
              "x-pagination-page": "1",
              "x-pagination-pagetotal": "1",
              "x-pagination-count": "1",
              "x-pagination-pagesize": "500",
            },
          });
        },
      }),
      executeCommand: async () => {},
    });
    await manager.initialize();
    let confirmed = false;
    const candidate = createSSOCredential("candidate-access", "candidate-refresh", {
      credentialId: "d".repeat(32),
      now: 1000,
    });
    const result = await manager.replaceCredential(candidate, null, {
      workspaceSlug: "requested-workspace",
      beforeCommit: async identity => {
        assert.strictEqual(identity, "principal");
        assert.strictEqual(secrets.value, null);
        confirmed = true;
        return true;
      },
    });
    assert.strictEqual(result.ok, true);
    assert.strictEqual(confirmed, true);
    assert.deepStrictEqual(endpoints, [
      "user/self",
      "namespaces/?page=1&page_size=500&sort=slug",
    ]);
    assert.strictEqual(decodeStoredCredential(secrets.value).credential.kind, "sso");
  });

  test("fails closed when the bearer cannot prove membership in the requested workspace", async () => {
    const secrets = new FakeSecretStorage({}, { primaryKey: AUTH_TOKEN_KEY });
    const manager = new ConnectionManager({ secrets }, {
      activationId: "sso-workspace-reject",
      createCloudsmithAPI: () => ({
        async get(endpoint) {
          if (endpoint === "user/self") return apiSuccess({ authenticated: true, slug: "principal" });
          return apiSuccess([{ slug: "different-workspace" }], {
            headers: {
              "x-pagination-page": "1",
              "x-pagination-pagetotal": "1",
              "x-pagination-count": "1",
              "x-pagination-pagesize": "500",
            },
          });
        },
      }),
      executeCommand: async () => {},
    });
    await manager.initialize();
    const result = await manager.replaceCredential(
      createSSOCredential("candidate-access", "candidate-refresh", {
        credentialId: "e".repeat(32),
        now: 1000,
      }),
      null,
      { workspaceSlug: "requested-workspace", beforeCommit: async () => true }
    );
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.error.kind, "workspace_forbidden");
    assert.strictEqual(secrets.value, null);
  });

  test("fails closed when SSO self-validation cannot name a safe principal", async () => {
    const unsafeIdentities = [
      {},
      { slug: "   " },
      { slug: "principal\u202Eadmin" },
      { name: "display-name-only" },
    ];
    for (const identity of unsafeIdentities) {
      const secrets = new FakeSecretStorage({}, { primaryKey: AUTH_TOKEN_KEY });
      const manager = new ConnectionManager({ secrets }, {
        activationId: "sso-principal-reject",
        createCloudsmithAPI: () => ({
          async get() { return apiSuccess({ authenticated: true, ...identity }); },
        }),
        executeCommand: async () => {},
      });
      await manager.initialize();
      let confirmed = false;
      const result = await manager.replaceCredential(
        createSSOCredential("candidate-access", "candidate-refresh", {
          credentialId: "b".repeat(32),
          now: 1000,
        }),
        null,
        { beforeCommit: async () => { confirmed = true; return true; } }
      );
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.error.kind, "identity_unavailable");
      assert.strictEqual(confirmed, false);
      assert.strictEqual(secrets.value, null);
    }
  });

  test("uses a valid stable username when an earlier slug is unsafe", async () => {
    const secrets = new FakeSecretStorage({}, { primaryKey: AUTH_TOKEN_KEY });
    const manager = new ConnectionManager({ secrets }, {
      activationId: "sso-principal-username",
      createCloudsmithAPI: () => ({
        async get() {
          return apiSuccess({ authenticated: true, slug: "bad\u202Eslug", username: "safe-user" });
        },
      }),
      executeCommand: async () => {},
    });
    await manager.initialize();
    let confirmedIdentity = null;
    const result = await manager.replaceCredential(
      createSSOCredential("candidate-access", "candidate-refresh", {
        credentialId: "a".repeat(32),
        now: 1000,
      }),
      null,
      { beforeCommit: async identity => { confirmedIdentity = identity; return true; } }
    );
    assert.strictEqual(result.ok, true);
    assert.strictEqual(confirmedIdentity, "safe-user");
  });

  test("coalesces twenty due requests into one rotating refresh without changing account epoch", async () => {
    const pending = deferred();
    let refreshCalls = 0;
    const { manager, secrets } = createSSOHarness({
      async refresh(access, refresh) {
        refreshCalls += 1;
        assert.strictEqual(access, "access-old");
        assert.strictEqual(refresh, "refresh-old");
        return pending.promise;
      },
    });
    await manager.initialize();
    const epoch = manager.getState().accountEpoch;
    const requests = Array.from({ length: 20 }, () => manager.getAuthorization());
    await new Promise(resolve => setImmediate(resolve));
    assert.strictEqual(refreshCalls, 1);
    pending.resolve({ ok: true, accessToken: "access-new", refreshToken: "refresh-new" });
    const authorizations = await Promise.all(requests);
    assert.ok(authorizations.every(value => value.headerName === "Authorization"));
    assert.ok(authorizations.every(value => value.headerValue === "Bearer access-new"));
    const stored = decodeStoredCredential(secrets.value);
    assert.strictEqual(stored.credential.accessToken, "access-new");
    assert.strictEqual(stored.credential.refreshToken, "refresh-new");
    assert.strictEqual(stored.credential.generation, 1);
    assert.strictEqual(manager.getState().accountEpoch, epoch);
  });

  test("generation exhaustion fails closed without wrapping or replacing the stored session", async () => {
    const maximum = createSSOCredential("access-maximum", "refresh-maximum", {
      credentialId: "f".repeat(32),
      generation: Number.MAX_SAFE_INTEGER,
      now: 0,
    });
    const serialized = serializeCredential(maximum);
    const secrets = new FakeSecretStorage({ [AUTH_TOKEN_KEY]: serialized }, { primaryKey: AUTH_TOKEN_KEY });
    const manager = new ConnectionManager({ secrets }, {
      activationId: "sso-generation-maximum",
      now: () => 31 * 60 * 1000,
      monotonicNow: () => 31 * 60 * 1000,
      protocolClient: {
        async refresh() {
          return { ok: true, accessToken: "must-not-commit", refreshToken: "must-not-commit" };
        },
      },
      createCloudsmithAPI: () => ({
        async get() { return apiSuccess({ authenticated: true, slug: "user-slug" }); },
      }),
      executeCommand: async () => {},
    });
    await manager.initialize();
    const authorization = await manager.getAuthorization();
    assert.strictEqual(authorization.headerValue, "Bearer access-maximum");
    assert.strictEqual(secrets.value, serialized);
    assert.strictEqual(decodeStoredCredential(secrets.value).credential.generation, Number.MAX_SAFE_INTEGER);
    assert.strictEqual(manager._currentOperation, null);
  });

  test("a transient proactive failure preserves the old access token and throttles attempts", async () => {
    let calls = 0;
    let monotonic = 1000;
    const { manager, secrets } = createSSOHarness({
      async refresh() { calls += 1; return { ok: false, kind: "transient" }; },
    }, { monotonicNow: () => monotonic });
    await manager.initialize();
    const first = await manager.getAuthorization();
    const second = await manager.getAuthorization();
    assert.strictEqual(calls, 1);
    assert.strictEqual(first.headerValue, "Bearer access-old");
    assert.strictEqual(first.proactiveRefreshFailed, true);
    assert.strictEqual(second.headerValue, "Bearer access-old");
    assert.strictEqual(decodeStoredCredential(secrets.value).credential.accessToken, "access-old");
    monotonic += 6 * 60 * 1000;
    await manager.getAuthorization();
    assert.strictEqual(calls, 2);
  });

  test("a proactive refresh rejection preserves access until the ordinary bearer is also rejected", async () => {
    const { manager, secrets } = createSSOHarness({
      async refresh() { return { ok: false, kind: "invalid_session" }; },
    });
    await manager.initialize();
    const authorization = await manager.getAuthorization();
    assert.strictEqual(authorization.headerValue, "Bearer access-old");
    assert.strictEqual(authorization.proactiveRefreshStatus, "invalid_session");
    assert.strictEqual(decodeStoredCredential(secrets.value).credential.accessToken, "access-old");
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
    assert.strictEqual(manager.getState().sessionConnected, true);
  });

  test("a newer external generation never inherits an older proactive rejection", async () => {
    const { manager, secrets } = createSSOHarness({
      async refresh() { return { ok: false, kind: "refresh_rejected" }; },
    });
    await manager.initialize();
    const refresh = manager.refreshSSO.bind(manager);
    manager.refreshSSO = async options => {
      const result = await refresh(options);
      const attempted = decodeStoredCredential(secrets.value).credential;
      const newer = createSSOCredential("access-external", "refresh-external", {
        credentialId: attempted.credentialId,
        generation: attempted.generation + 1,
        now: 2000,
      });
      secrets.externalSet(serializeCredential(newer));
      await new Promise(resolve => setImmediate(resolve));
      await new Promise(resolve => setImmediate(resolve));
      return result;
    };
    const authorization = await manager.getAuthorization();
    assert.strictEqual(authorization.headerValue, "Bearer access-external");
    assert.strictEqual(authorization.generation, 2);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(authorization, "proactiveRefreshStatus"), false);
    assert.strictEqual(manager.getState().sessionConnected, true);
    assert.strictEqual(decodeStoredCredential(secrets.value).credential.generation, 2);
  });

  test("ordinary 401 plus forced refresh rejection clears the exact post-attempt generation", async () => {
    let refreshCalls = 0;
    let fetches = 0;
    const { manager, secrets } = createSSOHarness({
      async refresh() { refreshCalls += 1; return { ok: false, kind: "refresh_rejected" }; },
    }, { now: 1000, monotonicNow: () => 1000 });
    await manager.initialize();
    const api = managerBoundAPI(manager, async () => {
      fetches += 1;
      return new Response(JSON.stringify({ detail: "expired" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      });
    });
    const result = await api.get("user/self", { responseType: "object", retry: "never" });
    assert.strictEqual(result.status, 401);
    assert.strictEqual(refreshCalls, 1);
    assert.strictEqual(fetches, 1);
    assert.strictEqual(secrets.value, null);
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.ABSENT);
  });

  test("a newer external generation survives rejected-refresh disconnect handling", async () => {
    const { manager, secrets } = createSSOHarness({
      async refresh() { return { ok: false, kind: "refresh_rejected" }; },
    }, { now: 1000, monotonicNow: () => 1000 });
    await manager.initialize();
    let rejectionProof;
    const api = new CloudsmithAPI({}, {
      credentialManager: {
        getAuthorization: options => manager.getAuthorization(options),
        handleAuthorizationRejected: async proof => {
          rejectionProof = proof;
          const attempted = decodeStoredCredential(secrets.value).credential;
          const newer = createSSOCredential("access-newer", "refresh-newer", {
            credentialId: attempted.credentialId,
            generation: attempted.generation + 1,
            now: 1001,
          });
          secrets.externalSet(serializeCredential(newer));
          return manager.handleAuthorizationRejected(proof);
        },
      },
      fetchImpl: async () => new Response(JSON.stringify({ detail: "expired" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      }),
    });
    await api.get("user/self", { responseType: "object", retry: "never" });
    const stored = decodeStoredCredential(secrets.value).credential;
    assert.deepStrictEqual(rejectionProof, {
      credentialId: stored.credentialId,
      generation: stored.generation - 1,
    });
    assert.strictEqual(stored.accessToken, "access-newer");
    assert.strictEqual(stored.generation, 2);
  });

  test("proactive refresh rejection disconnects on ordinary 401 but preserves on ordinary 200", async () => {
    for (const status of [200, 401]) {
      let refreshCalls = 0;
      const { manager, secrets } = createSSOHarness({
        async refresh() { refreshCalls += 1; return { ok: false, kind: "refresh_rejected" }; },
      });
      await manager.initialize();
      const api = managerBoundAPI(manager, async () => new Response(
        JSON.stringify(status === 200 ? { authenticated: true } : { detail: "expired" }),
        { status, headers: { "content-type": "application/json" } }
      ));
      const result = await api.get("user/self", { responseType: "object", retry: "never" });
      assert.strictEqual(result.status, status);
      assert.strictEqual(refreshCalls, 1);
      if (status === 200) {
        assert.strictEqual(decodeStoredCredential(secrets.value).credential.accessToken, "access-old");
        assert.strictEqual(manager.getState().sessionConnected, true);
      } else {
        assert.strictEqual(secrets.value, null);
        assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.ABSENT);
      }
    }
  });

  test("a write 401 after proactive rejection disconnects without replaying the write", async () => {
    let refreshCalls = 0;
    let writes = 0;
    const { manager, secrets } = createSSOHarness({
      async refresh() { refreshCalls += 1; return { ok: false, kind: "refresh_rejected" }; },
    });
    await manager.initialize();
    const api = managerBoundAPI(manager, async () => {
      writes += 1;
      return new Response(JSON.stringify({ detail: "expired" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      });
    });
    const result = await api.post("packages/copy", { package: "value" }, {
      responseType: "object",
      retry: "never",
    });
    assert.strictEqual(result.status, 401);
    assert.notStrictEqual(result.outcomeUnknown, true);
    assert.strictEqual(refreshCalls, 1);
    assert.strictEqual(writes, 1);
    assert.strictEqual(secrets.value, null);
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.ABSENT);
  });

  test("a newer external generation survives write-401 proactive rejection handling", async () => {
    let writes = 0;
    const { manager, secrets } = createSSOHarness({
      async refresh() { return { ok: false, kind: "refresh_rejected" }; },
    });
    await manager.initialize();
    const api = new CloudsmithAPI({}, {
      credentialManager: {
        getAuthorization: options => manager.getAuthorization(options),
        handleAuthorizationRejected: async proof => {
          const attempted = decodeStoredCredential(secrets.value).credential;
          const newer = createSSOCredential("write-access-newer", "write-refresh-newer", {
            credentialId: attempted.credentialId,
            generation: attempted.generation + 1,
            now: attempted.refreshedAt + 1,
          });
          secrets.externalSet(serializeCredential(newer));
          return manager.handleAuthorizationRejected(proof);
        },
      },
      fetchImpl: async () => {
        writes += 1;
        return new Response(JSON.stringify({ detail: "expired" }), {
          status: 401,
          headers: { "content-type": "application/json" },
        });
      },
    });
    const result = await api.post("packages/copy", { package: "value" }, {
      responseType: "object",
      retry: "never",
    });
    assert.strictEqual(result.status, 401);
    assert.strictEqual(writes, 1);
    const stored = decodeStoredCredential(secrets.value).credential;
    assert.strictEqual(stored.accessToken, "write-access-newer");
    assert.strictEqual(stored.generation, 2);
  });

  test("transient cooldown suppresses repeated 401 refreshes before and after manager reload", async () => {
    let calls = 0;
    const { manager, secrets } = createSSOHarness({
      async refresh() { calls += 1; return { ok: false, kind: "transient" }; },
    });
    await manager.initialize();
    const rejected = async () => new Response(JSON.stringify({ detail: "expired" }), {
      status: 401,
      headers: { "content-type": "application/json" },
    });
    const api = managerBoundAPI(manager, rejected);
    await api.get("user/self", { responseType: "object", retry: "never" });
    await api.get("user/self", { responseType: "object", retry: "never" });
    assert.strictEqual(calls, 1);
    assert.strictEqual(manager.getState().sessionConnected, true);
    await manager.dispose();

    let reloadedCalls = 0;
    const reloaded = new ConnectionManager({ secrets }, {
      activationId: "reloaded-api-cooldown",
      now: () => 31 * 60 * 1000,
      monotonicNow: () => 10,
      protocolClient: {
        async refresh() { reloadedCalls += 1; return { ok: false, kind: "transient" }; },
      },
      createCloudsmithAPI: () => ({
        async get() { return apiSuccess({ authenticated: true, slug: "user-slug" }); },
      }),
      executeCommand: async () => {},
    });
    await reloaded.initialize();
    const reloadedAPI = managerBoundAPI(reloaded, rejected);
    await reloadedAPI.get("user/self", { responseType: "object", retry: "never" });
    await reloadedAPI.get("user/self", { responseType: "object", retry: "never" });
    assert.strictEqual(reloadedCalls, 0);
    assert.strictEqual(reloaded.getState().sessionConnected, true);
  });

  test("an expired stored access token refreshes and validates before startup reconnects", async () => {
    const original = createSSOCredential("access-expired", "refresh-valid", {
      credentialId: "a".repeat(32),
      generation: 4,
      now: 0,
    });
    const secrets = new FakeSecretStorage({
      [AUTH_TOKEN_KEY]: serializeCredential(original),
    }, { primaryKey: AUTH_TOKEN_KEY });
    const validated = [];
    const manager = new ConnectionManager({ secrets }, {
      activationId: "expired-startup",
      now: () => 31 * 60 * 1000,
      monotonicNow: () => 31 * 60 * 1000,
      protocolClient: {
        async refresh(access, refresh) {
          assert.strictEqual(access, "access-expired");
          assert.strictEqual(refresh, "refresh-valid");
          return { ok: true, accessToken: "access-recovered", refreshToken: "refresh-rotated" };
        },
      },
      createCloudsmithAPI: () => ({
        async get(endpoint, options) {
          assert.strictEqual(endpoint, "user/self");
          validated.push(options.credential.accessToken);
          return options.credential.accessToken === "access-expired"
            ? apiFailure("unauthorized", { status: 401 })
            : apiSuccess({ authenticated: true, slug: "recovered-principal" });
        },
      }),
      executeCommand: async () => {},
    });
    const result = await manager.initialize();
    assert.strictEqual(result.ok, true);
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.CONNECTED);
    assert.deepStrictEqual(validated, ["access-expired", "access-recovered"]);
    const stored = decodeStoredCredential(secrets.value).credential;
    assert.strictEqual(stored.accessToken, "access-recovered");
    assert.strictEqual(stored.refreshToken, "refresh-rotated");
    assert.strictEqual(stored.generation, 5);
  });

  test("a late refresh cannot abort or overwrite a newer API-key sign-in", async () => {
    const pending = deferred();
    const { manager, secrets } = createSSOHarness({
      async refresh() { return pending.promise; },
    });
    await manager.initialize();
    const refreshing = manager.getAuthorization();
    await new Promise(resolve => setImmediate(resolve));
    const operation = manager.beginCredentialOperation();
    const replacing = manager.replaceCredential("replacement-api-key", operation);
    pending.resolve({ ok: true, accessToken: "late-access", refreshToken: "late-refresh" });
    await refreshing;
    const replaced = await replacing;
    assert.strictEqual(replaced.ok, true);
    const stored = decodeStoredCredential(secrets.value).credential;
    assert.strictEqual(stored.kind, "api-key");
    assert.strictEqual(stored.apiKey, "replacement-api-key");
  });

  test("a late refresh cannot overwrite an external SecretStorage generation", async () => {
    const pending = deferred();
    const { manager, secrets } = createSSOHarness({
      async refresh() { return pending.promise; },
    });
    await manager.initialize();
    const refreshing = manager.getAuthorization();
    await new Promise(resolve => setImmediate(resolve));
    const external = createSSOCredential("external-access", "external-refresh", {
      credentialId: "f".repeat(32),
      generation: 9,
      now: 31 * 60 * 1000,
    });
    secrets.externalSet(serializeCredential(external));
    pending.resolve({ ok: true, accessToken: "late-access", refreshToken: "late-refresh" });
    await refreshing;
    await new Promise(resolve => setImmediate(resolve));
    const stored = decodeStoredCredential(secrets.value).credential;
    assert.strictEqual(stored.credentialId, external.credentialId);
    assert.strictEqual(stored.accessToken, "external-access");
  });

  test("a stale replayed 401 cannot clear a newer SSO session", async () => {
    const { manager, secrets, original } = createSSOHarness({
      async refresh() { throw new Error("refresh is not expected"); },
    });
    await manager.initialize();
    const newer = createSSOCredential("new-account-access", "new-account-refresh", {
      credentialId: "9".repeat(32),
      generation: 0,
      now: 31 * 60 * 1000,
    });
    const replaced = await manager.replaceCredential(newer);
    assert.strictEqual(replaced.ok, true);
    const rejected = await manager.handleAuthorizationRejected({
      credentialId: original.credentialId,
      generation: original.generation,
    });
    assert.strictEqual(rejected.status, "stale");
    const stored = decodeStoredCredential(secrets.value).credential;
    assert.strictEqual(stored.credentialId, newer.credentialId);
    assert.strictEqual(stored.accessToken, "new-account-access");
  });

  test("canceling one coalesced waiter does not cancel refresh for the other waiters", async () => {
    const pending = deferred();
    let calls = 0;
    const { manager } = createSSOHarness({
      async refresh() { calls += 1; return pending.promise; },
    });
    await manager.initialize();
    const cancelled = new AbortController();
    const first = manager.getAuthorization({ signal: cancelled.signal });
    const second = manager.getAuthorization();
    cancelled.abort();
    assert.strictEqual(await first, null);
    pending.resolve({ ok: true, accessToken: "shared-access", refreshToken: "shared-refresh" });
    const authorization = await second;
    assert.strictEqual(calls, 1);
    assert.strictEqual(authorization.headerValue, "Bearer shared-access");
  });

  test("persisted transient refresh metadata throttles the next manager after reload", async () => {
    let firstCalls = 0;
    const { manager, secrets } = createSSOHarness({
      async refresh() { firstCalls += 1; return { ok: false, kind: "transient" }; },
    });
    await manager.initialize();
    await manager.getAuthorization();
    assert.strictEqual(firstCalls, 1);
    await manager.dispose();

    let reloadedCalls = 0;
    const reloaded = new ConnectionManager({ secrets }, {
      activationId: "reloaded-cooldown",
      now: () => 31 * 60 * 1000,
      monotonicNow: () => 50,
      protocolClient: {
        async refresh() { reloadedCalls += 1; return { ok: false, kind: "transient" }; },
      },
      createCloudsmithAPI: () => ({
        async get() { return apiSuccess({ authenticated: true, slug: "user-slug" }); },
      }),
      executeCommand: async () => {},
    });
    await reloaded.initialize();
    const authorization = await reloaded.getAuthorization();
    assert.strictEqual(authorization.headerValue, "Bearer access-old");
    assert.strictEqual(reloadedCalls, 0);
  });

  test("two managers sharing SecretStorage perform only one rotating refresh transaction", async () => {
    const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), "cloudsmith-two-manager-"));
    const original = createSSOCredential("shared-old-access", "shared-old-refresh", {
      credentialId: "8".repeat(32),
      generation: 0,
      now: 0,
    });
    const secrets = new FakeSecretStorage({
      [AUTH_TOKEN_KEY]: serializeCredential(original),
    }, { primaryKey: AUTH_TOKEN_KEY });
    const pending = deferred();
    let calls = 0;
    const options = activationId => ({
      activationId,
      now: () => 31 * 60 * 1000,
      monotonicNow: () => 31 * 60 * 1000,
      protocolClient: {
        async refresh() { calls += 1; return pending.promise; },
      },
      createCloudsmithAPI: () => ({
        async get() { return apiSuccess({ authenticated: true, slug: "shared-user" }); },
      }),
      executeCommand: async () => {},
    });
    const context = { secrets, globalStorageUri: { fsPath: directory } };
    const first = new ConnectionManager(context, options("shared-first"));
    const second = new ConnectionManager(context, options("shared-second"));
    try {
      await first.initialize();
      await second.initialize();
      const one = first.getAuthorization();
      const two = second.getAuthorization();
      await new Promise(resolve => setTimeout(resolve, 75));
      assert.strictEqual(calls, 1);
      pending.resolve({ ok: true, accessToken: "shared-new-access", refreshToken: "shared-new-refresh" });
      const [oneAuthorization, twoAuthorization] = await Promise.all([one, two]);
      assert.strictEqual(calls, 1);
      assert.strictEqual(oneAuthorization.headerValue, "Bearer shared-new-access");
      assert.strictEqual(twoAuthorization.headerValue, "Bearer shared-new-access");
      const stored = decodeStoredCredential(secrets.value).credential;
      assert.strictEqual(stored.generation, 1);
      assert.strictEqual(stored.accessToken, "shared-new-access");
    } finally {
      await first.dispose();
      await second.dispose();
      await fs.promises.rm(directory, { recursive: true, force: true });
    }
  });

  test("two startup hosts serialize legacy API-key migration without losing the session", async () => {
    const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), "cloudsmith-two-legacy-"));
    const secrets = new FakeSecretStorage({
      [AUTH_TOKEN_KEY]: "legacy-shared-key",
    }, { primaryKey: AUTH_TOKEN_KEY });
    const context = { secrets, globalStorageUri: { fsPath: directory } };
    const options = activationId => ({
      activationId,
      createCloudsmithAPI: () => ({
        async get() { return apiSuccess({ authenticated: true }); },
      }),
      executeCommand: async () => {},
    });
    const first = new ConnectionManager(context, options("legacy-first"));
    const second = new ConnectionManager(context, options("legacy-second"));
    try {
      await Promise.all([first.initialize(), second.initialize()]);
      await new Promise(resolve => setImmediate(resolve));
      await new Promise(resolve => setImmediate(resolve));

      const stored = decodeStoredCredential(secrets.value);
      assert.strictEqual(stored.ok, true);
      assert.strictEqual(stored.credential.kind, "api-key");
      assert.strictEqual(stored.credential.apiKey, "legacy-shared-key");
      assert.strictEqual(first.getState().sessionConnected, true);
      assert.strictEqual(second.getState().sessionConnected, true);
    } finally {
      await first.dispose();
      await second.dispose();
      await fs.promises.rm(directory, { recursive: true, force: true });
    }
  });

  test("disconnect aborts an in-flight refresh and a late response cannot resurrect it", async () => {
    const pending = deferred();
    const { manager, secrets } = createSSOHarness({
      async refresh() { return pending.promise; },
    });
    await manager.initialize();
    const refreshing = manager.getAuthorization();
    await new Promise(resolve => setImmediate(resolve));
    const disconnecting = manager.disconnect();
    pending.resolve({ ok: true, accessToken: "late-access", refreshToken: "late-refresh" });
    await refreshing;
    await disconnecting;
    assert.strictEqual(secrets.value, null);
    assert.strictEqual(manager.getState().status, CONNECTION_STATUSES.ABSENT);
  });
});

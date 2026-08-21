const assert = require("assert");
const { createSSODiagnosticObserver } = require("../util/ssoDiagnostics");
const { SSOProtocolClient } = require("../util/ssoProtocolClient");

function jsonResponse(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

suite("Cloudsmith SSO protocol client", () => {
  test("discovers and returns the IdP from the exact current CLI endpoint", async () => {
    const calls = [];
    const client = new SSOProtocolClient({
      fetchImpl: async (url, options) => {
        calls.push({ url: url.toString(), options });
        return jsonResponse({ redirect_url: "https://idp.customer.example/saml?state=secret" });
      },
    });
    const result = await client.discover("workspace-a");
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.redirectUrl, "https://idp.customer.example/saml?state=secret");
    assert.strictEqual(
      calls[0].url,
      "https://api.cloudsmith.io/orgs/workspace-a/saml/?redirect_url=http%3A%2F%2Flocalhost%3A12400"
    );
    assert.strictEqual(calls[0].options.method, "GET");
    assert.strictEqual(calls[0].options.redirect, "manual");
    assert.ok(!Object.keys(calls[0].options.headers).some(name => /authorization|api-key/i.test(name)));
  });

  test("discovery diagnostics retain safe shape metadata without the redirect query", async () => {
    const lines = [];
    const client = new SSOProtocolClient({
      diagnosticObserver: createSSODiagnosticObserver({ appendLine(line) { lines.push(line); } }),
      fetchImpl: async () => jsonResponse({
        redirect_url: "https://idp.customer.example/saml?RelayState=synthetic-secret-marker",
      }),
    });

    const result = await client.discover("workspace-a");

    assert.strictEqual(result.ok, true);
    const output = lines.join("\n");
    assert.strictEqual(output.includes("synthetic-secret-marker"), false);
    assert.strictEqual(output.includes("RelayState"), false);
    assert.match(output, /"idpHostname":"idp\.customer\.example"/);
    assert.match(output, /"hasQuery":true/);
    assert.match(output, /"statusCode":200/);
  });

  test("discovery diagnostics classify a JSON HTTP failure without recording its body", async () => {
    const lines = [];
    const marker = "synthetic-secret-marker";
    const client = new SSOProtocolClient({
      diagnosticObserver: createSSODiagnosticObserver({ appendLine(line) { lines.push(line); } }),
      fetchImpl: async () => jsonResponse({ detail: marker }, 404),
    });

    const result = await client.discover("workspace-a");

    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.kind, "http_error");
    const output = lines.join("\n");
    assert.strictEqual(output.includes(marker), false);
    assert.match(output, /"jsonShapeValid":true/);
    assert.match(output, /"redirectUrlPresent":false/);
    assert.match(output, /"statusCode":404/);
    assert.match(output, /"errorKind":"discovery_http_error"/);
  });

  test("rejects discovery redirects and unsafe IdP URLs", async () => {
    const redirect = new SSOProtocolClient({
      fetchImpl: async () => new Response("", { status: 302, headers: { location: "https://idp.example" } }),
    });
    assert.strictEqual((await redirect.discover("workspace")).kind, "redirect_rejected");
    const unsafe = new SSOProtocolClient({
      fetchImpl: async () => jsonResponse({ redirect_url: "http://idp.example/saml" }),
    });
    assert.strictEqual((await unsafe.discover("workspace")).kind, "invalid_response");
  });

  test("rejects malformed, inherited, credentialed, controlled, and oversized discovery results", async () => {
    const payloads = [
      [],
      {},
      Object.create({ redirect_url: "https://idp.example/saml" }),
      { redirect_url: "not a URL" },
      { redirect_url: "https://user:password@idp.example/saml" },
      { redirect_url: "https://idp.example/saml\u0000" },
      { redirect_url: `https://idp.example/${"a".repeat(8192)}` },
    ];
    for (const payload of payloads) {
      const client = new SSOProtocolClient({ fetchImpl: async () => jsonResponse(payload) });
      assert.strictEqual((await client.discover("workspace")).kind, "invalid_response");
    }
    const oversized = new SSOProtocolClient({
      fetchImpl: async () => new Response(`{"redirect_url":"https://idp.example/${"a".repeat(64 * 1024)}"}`, {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    });
    assert.strictEqual((await oversized.discover("workspace")).kind, "response_too_large");
  });

  test("discovery classifies network, rate-limit, and server failures without changing origin", async () => {
    const network = new SSOProtocolClient({ fetchImpl: async () => { throw new Error("network secret"); } });
    assert.strictEqual((await network.discover("workspace")).kind, "network_error");
    for (const status of [429, 503]) {
      const client = new SSOProtocolClient({
        fetchImpl: async () => jsonResponse({ detail: "unavailable" }, status),
      });
      assert.strictEqual((await client.discover("workspace")).kind, "transient");
    }
  });

  test("performs exact two-factor and refresh exchanges without changing origins", async () => {
    const calls = [];
    const client = new SSOProtocolClient({
      fetchImpl: async (url, options) => {
        calls.push({ url: url.toString(), options });
        return jsonResponse({ access_token: "new-access", refresh_token: "new-refresh" });
      },
    });
    const twoFactor = await client.exchangeTwoFactor("two-factor", "123456");
    const refreshed = await client.refresh("old-access", "old-refresh");
    assert.strictEqual(twoFactor.ok, true);
    assert.strictEqual(refreshed.ok, true);
    assert.strictEqual(calls[0].url, "https://api.cloudsmith.io/user/two-factor/");
    assert.strictEqual(calls[0].options.headers.Authorization, "Bearer two-factor");
    assert.strictEqual(calls[0].options.body, "two_factor_token=two-factor&totp_token=123456");
    assert.strictEqual(calls[1].url, "https://api.cloudsmith.io/user/refresh-token/");
    assert.strictEqual(calls[1].options.headers.Authorization, "Bearer old-access");
    assert.strictEqual(calls[1].options.body, "refresh_token=old-refresh");
  });

  test("invalid exchange token pairs emit one final semantic diagnostic per request", async () => {
    const lines = [];
    const client = new SSOProtocolClient({
      diagnosticObserver: createSSODiagnosticObserver({ appendLine(line) { lines.push(line); } }),
      fetchImpl: async () => jsonResponse({ access_token: "", refresh_token: "refresh" }),
    });

    const twoFactor = await client.exchangeTwoFactor("two-factor", "123456");
    const refreshed = await client.refresh("old-access", "old-refresh");

    assert.strictEqual(twoFactor.kind, "invalid_response");
    assert.strictEqual(refreshed.kind, "invalid_response");
    const events = lines.map(line => JSON.parse(line.slice("[SSO] ".length)));
    assert.deepStrictEqual(events, [
      {
        stage: "sso.two-factor.exchange",
        errorKind: "invalid_response",
        hasRefreshToken: false,
        ok: false,
        statusCode: 200,
      },
      {
        stage: "sso.refresh.exchange",
        errorKind: "invalid_response",
        hasRefreshToken: false,
        ok: false,
        statusCode: 200,
      },
    ]);
  });

  test("preserves a session on refresh rejection until its ordinary bearer is also rejected", async () => {
    const definitive = new SSOProtocolClient({
      fetchImpl: async () => jsonResponse({ detail: "expired" }, 401),
    });
    assert.strictEqual((await definitive.refresh("access", "refresh")).kind, "refresh_rejected");
    const malformed = new SSOProtocolClient({
      fetchImpl: async () => new Response("not-json", { status: 401 }),
    });
    assert.strictEqual((await malformed.refresh("access", "refresh")).kind, "invalid_response");
    const transient = new SSOProtocolClient({
      fetchImpl: async () => jsonResponse({ detail: "busy" }, 503),
    });
    assert.strictEqual((await transient.refresh("access", "refresh")).kind, "transient");
    for (const status of [400, 403]) {
      const rejected = new SSOProtocolClient({
        fetchImpl: async () => jsonResponse({ detail: "refresh rejected" }, status),
      });
      assert.strictEqual((await rejected.refresh("access", "refresh")).kind, "refresh_rejected");
    }
  });

  test("the protocol deadline settles and cancels a response body that never yields", async () => {
    let fireTimeout = null;
    let cancelled = false;
    const client = new SSOProtocolClient({
      fetchImpl: async () => ({
        status: 200,
        ok: true,
        headers: { get() { return null; } },
        body: {
          getReader() {
            return {
              read() { return new Promise(() => {}); },
              cancel() { cancelled = true; return Promise.resolve(); },
              releaseLock() {},
            };
          },
        },
      }),
      setTimeout(callback) { fireTimeout = callback; return 1; },
      clearTimeout() {},
    });
    const pending = client.discover("workspace");
    await new Promise(resolve => setImmediate(resolve));
    fireTimeout();
    const result = await pending;
    assert.strictEqual(result.kind, "timeout");
    assert.strictEqual(cancelled, true);
  });
});

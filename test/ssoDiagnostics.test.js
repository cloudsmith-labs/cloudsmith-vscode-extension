const assert = require("assert");
const {
  createSSODiagnosticObserver,
  sanitizeSSODiagnostic,
} = require("../util/ssoDiagnostics");

suite("SSO diagnostics", () => {
  test("emits only bounded allowlisted metadata and drops synthetic secret markers", () => {
    const lines = [];
    const marker = "synthetic-secret-marker";
    const observe = createSSODiagnosticObserver({
      appendLine(line) { lines.push(line); },
    });

    observe("sso.callback.received", {
      authorization: `Bearer ${marker}`,
      callbackFamily: "ipv4",
      fullUrl: `https://idp.example/saml?RelayState=${marker}`,
      parameterNames: ["refresh_token", "access_token"],
      queryPairCount: 2,
      rawBody: marker,
      tokenValue: marker,
    });

    assert.strictEqual(lines.length, 1);
    assert.strictEqual(lines[0].includes(marker), false);
    assert.strictEqual(lines[0].includes("RelayState"), false);
    assert.strictEqual(lines[0].includes("Bearer"), false);
    assert.deepStrictEqual(JSON.parse(lines[0].slice("[SSO] ".length)), {
      stage: "sso.callback.received",
      callbackFamily: "ipv4",
      parameterNames: ["access_token", "refresh_token"],
      queryPairCount: 2,
    });
  });

  test("rejects unknown stages and unsafe hostname, field-name, and enum values", () => {
    assert.strictEqual(sanitizeSSODiagnostic("sso.unknown", {}), null);
    assert.deepStrictEqual(sanitizeSSODiagnostic("sso.discovery.accepted", {
      errorKind: "raw server error body",
      fieldNames: ["authenticated", "unsafe field"],
      idpHostname: "idp.example/control\n",
      ok: true,
      statusCode: 200,
    }), {
      stage: "sso.discovery.accepted",
      ok: true,
      statusCode: 200,
    });
  });

  test("never emits attacker-controlled callback parameter names", () => {
    const lines = [];
    const observe = createSSODiagnosticObserver({
      appendLine(line) { lines.push(line); },
    });

    observe("sso.callback.received", {
      parameterNames: ["csa_secret_key"],
      queryPairCount: 1,
    });

    assert.strictEqual(lines.length, 1);
    assert.strictEqual(lines[0].includes("csa_secret_key"), false);
    assert.deepStrictEqual(JSON.parse(lines[0].slice("[SSO] ".length)), {
      stage: "sso.callback.received",
      queryPairCount: 1,
    });
  });
});

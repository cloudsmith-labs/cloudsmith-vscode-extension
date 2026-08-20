const assert = require("assert");
const {
  ENVELOPE_PREFIX,
  authorizationForCredential,
  createSSOCredential,
  decodeStoredCredential,
  identityFingerprint,
  normalizeCredential,
  nextCredentialGeneration,
  serializeCredential,
  storageFingerprint,
} = require("../util/credentialEnvelope");

suite("credential envelope", () => {
  test("decodes a legacy API key without treating arbitrary JSON as structured state", () => {
    const result = decodeStoredCredential('{"kind":"sso"}');
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.legacy, true);
    assert.strictEqual(result.credential.kind, "api-key");
    assert.strictEqual(result.credential.apiKey, '{"kind":"sso"}');
  });

  test("uses a control sentinel that legacy API keys cannot contain", () => {
    const serialized = serializeCredential("api-key");
    assert.ok(serialized.startsWith(ENVELOPE_PREFIX));
    assert.strictEqual(ENVELOPE_PREFIX.charCodeAt(0), 0x1e);
    const decoded = decodeStoredCredential(serialized);
    assert.strictEqual(decoded.ok, true);
    assert.strictEqual(decoded.legacy, false);
    assert.strictEqual(decoded.credential.apiKey, "api-key");
  });

  test("fails closed after recognizing a malformed framed value", () => {
    const result = decodeStoredCredential(`${ENVELOPE_PREFIX}not+base64`);
    assert.strictEqual(result.ok, false);
    assert.ok(!Object.prototype.hasOwnProperty.call(result, "credential"));
  });

  test("projects exactly one auth scheme per credential kind", () => {
    assert.deepStrictEqual(authorizationForCredential(decodeStoredCredential("api-key").credential), {
      kind: "api-key",
      headerName: "X-Api-Key",
      headerValue: "api-key",
    });
    const sso = createSSOCredential("access-token", "refresh-token", {
      credentialId: "a".repeat(32),
      now: 1000,
    });
    assert.deepStrictEqual(authorizationForCredential(sso), {
      kind: "sso",
      headerName: "Authorization",
      headerValue: "Bearer access-token",
      credentialId: "a".repeat(32),
      generation: 0,
    });
  });

  test("rejects noncanonical, unsupported, oversized, and control-bearing envelopes", () => {
    const noncanonical = Buffer.from(JSON.stringify({
      version: 1,
      kind: "api-key",
      apiKey: "key",
    })).toString("base64url");
    assert.strictEqual(decodeStoredCredential(`${ENVELOPE_PREFIX}${noncanonical}`).ok, false);
    const unsupported = Buffer.from(JSON.stringify({
      apiKey: "key",
      kind: "api-key",
      version: 2,
    })).toString("base64url");
    assert.strictEqual(decodeStoredCredential(`${ENVELOPE_PREFIX}${unsupported}`).ok, false);
    assert.strictEqual(decodeStoredCredential(`${ENVELOPE_PREFIX}${"A".repeat(32768)}`).ok, false);
    assert.strictEqual(decodeStoredCredential("api\nkey").ok, false);
    assert.strictEqual(decodeStoredCredential(`${ENVELOPE_PREFIX}YQ==`).ok, false);
  });

  test("rejects invalid generations and clamps persisted future timestamps", () => {
    const base = createSSOCredential("access", "refresh", {
      credentialId: "d".repeat(32),
      generation: 1,
      now: 1000,
    });
    assert.strictEqual(normalizeCredential({ ...base, generation: -1 }, { now: 1000 }).ok, false);
    assert.strictEqual(normalizeCredential({ ...base, accessToken: `x\nsecret` }, { now: 1000 }).ok, false);
    const clamped = normalizeCredential({
      ...base,
      refreshedAt: 999999999,
      refreshAttemptedAt: 999999999,
    }, { now: 1000 });
    assert.strictEqual(clamped.ok, true);
    assert.strictEqual(clamped.credential.refreshedAt, 301000);
    assert.strictEqual(clamped.credential.refreshAttemptedAt, 301000);
    assert.throws(
      () => createSSOCredential("access", "refresh", { generation: Number.MAX_SAFE_INTEGER + 1 }),
      /generation is invalid/
    );
    assert.strictEqual(nextCredentialGeneration(Number.MAX_SAFE_INTEGER - 1), Number.MAX_SAFE_INTEGER);
    assert.throws(
      () => nextCredentialGeneration(Number.MAX_SAFE_INTEGER),
      /cannot be incremented safely/
    );
  });

  test("rotating SSO tokens changes storage generation without changing account identity", () => {
    const first = createSSOCredential("access-one", "refresh-one", {
      credentialId: "b".repeat(32), generation: 2, now: 1000,
    });
    const second = createSSOCredential("access-two", "refresh-two", {
      credentialId: "b".repeat(32), generation: 3, now: 2000,
    });
    assert.strictEqual(identityFingerprint(first), identityFingerprint(second));
    assert.notStrictEqual(storageFingerprint(serializeCredential(first)), storageFingerprint(serializeCredential(second)));
  });
});

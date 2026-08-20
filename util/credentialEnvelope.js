const crypto = require("crypto");

const ENVELOPE_PREFIX = "\u001eCLOUDSMITH_VSC_CREDENTIAL:1:";
const ENVELOPE_VERSION = 1;
const MAX_API_KEY_LENGTH = 4096;
const MAX_BEARER_TOKEN_LENGTH = 8192;
const MAX_SERIALIZED_LENGTH = 32768;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;
const BEARER_TOKEN_PATTERN = /^[A-Za-z0-9\-._~+/]+=*$/;
const CREDENTIAL_ID_PATTERN = /^[a-f0-9]{32}$/;

function normalizeAPIKey(value) {
  if (typeof value !== "string") return invalid("API key must be text.");
  const apiKey = value.trim();
  if (!apiKey) return invalid("API key cannot be empty.");
  if (apiKey.length > MAX_API_KEY_LENGTH) return invalid("API key is too long.");
  if (CONTROL_CHARACTER_PATTERN.test(apiKey)) return invalid("API key contains invalid characters.");
  return Object.freeze({ ok: true, value: apiKey });
}

function normalizeBearerToken(value, label) {
  if (typeof value !== "string" || !value || value.length > MAX_BEARER_TOKEN_LENGTH) {
    return invalid(`${label} is missing or invalid.`);
  }
  if (CONTROL_CHARACTER_PATTERN.test(value) || !BEARER_TOKEN_PATTERN.test(value)) {
    return invalid(`${label} is invalid.`);
  }
  return Object.freeze({ ok: true, value });
}

function normalizeCredential(candidate, options = {}) {
  if (typeof candidate === "string") {
    const normalized = normalizeAPIKey(candidate);
    if (!normalized.ok) return normalized;
    return Object.freeze({
      ok: true,
      credential: Object.freeze({ version: ENVELOPE_VERSION, kind: "api-key", apiKey: normalized.value }),
    });
  }
  if (!isPlainObject(candidate)) return invalid("Credential has an invalid shape.");
  if (candidate.kind === "api-key") {
    if (!hasExactKeys(candidate, ["apiKey", "kind", "version"])) return invalid("API key credential has an invalid shape.");
    if (candidate.version !== ENVELOPE_VERSION) return invalid("Credential version is not supported.");
    const normalized = normalizeAPIKey(candidate.apiKey);
    if (!normalized.ok) return normalized;
    return Object.freeze({
      ok: true,
      credential: Object.freeze({ version: ENVELOPE_VERSION, kind: "api-key", apiKey: normalized.value }),
    });
  }
  if (candidate.kind !== "sso") return invalid("Credential kind is not supported.");
  const required = [
    "accessToken",
    "credentialId",
    "generation",
    "kind",
    "refreshAttemptedAt",
    "refreshToken",
    "refreshedAt",
    "version",
  ];
  if (!hasExactKeys(candidate, required)) return invalid("SSO credential has an invalid shape.");
  if (candidate.version !== ENVELOPE_VERSION) return invalid("Credential version is not supported.");
  if (!CREDENTIAL_ID_PATTERN.test(candidate.credentialId || "")) return invalid("SSO credential identity is invalid.");
  if (!Number.isSafeInteger(candidate.generation) || candidate.generation < 0) return invalid("SSO credential generation is invalid.");
  const access = normalizeBearerToken(candidate.accessToken, "SSO access token");
  if (!access.ok) return access;
  const refresh = normalizeBearerToken(candidate.refreshToken, "SSO refresh token");
  if (!refresh.ok) return refresh;
  const now = Number.isFinite(options.now) ? Math.floor(options.now) : Date.now();
  const refreshedAt = normalizeTimestamp(candidate.refreshedAt, now);
  const refreshAttemptedAt = normalizeTimestamp(candidate.refreshAttemptedAt, now, true);
  if (refreshedAt === null || refreshAttemptedAt === undefined) return invalid("SSO refresh metadata is invalid.");
  return Object.freeze({
    ok: true,
    credential: Object.freeze({
      version: ENVELOPE_VERSION,
      kind: "sso",
      credentialId: candidate.credentialId,
      generation: candidate.generation,
      accessToken: access.value,
      refreshToken: refresh.value,
      refreshedAt,
      refreshAttemptedAt,
    }),
  });
}

function createAPIKeyCredential(apiKey) {
  const result = normalizeCredential(apiKey);
  if (!result.ok) throw new TypeError(result.reason);
  return result.credential;
}

function createSSOCredential(accessToken, refreshToken, options = {}) {
  const now = Number.isFinite(options.now) ? Math.floor(options.now) : Date.now();
  const generation = options.generation === undefined ? 0 : options.generation;
  if (!Number.isSafeInteger(generation) || generation < 0) {
    throw new TypeError("SSO credential generation is invalid.");
  }
  const credentialId = options.credentialId === undefined
    ? crypto.randomBytes(16).toString("hex")
    : options.credentialId;
  const candidate = {
    version: ENVELOPE_VERSION,
    kind: "sso",
    credentialId,
    generation,
    accessToken,
    refreshToken,
    refreshedAt: Number.isSafeInteger(options.refreshedAt) ? options.refreshedAt : now,
    refreshAttemptedAt: options.refreshAttemptedAt == null ? null : options.refreshAttemptedAt,
  };
  const result = normalizeCredential(candidate, { now });
  if (!result.ok) throw new TypeError(result.reason);
  return result.credential;
}

function nextCredentialGeneration(generation) {
  if (!Number.isSafeInteger(generation) || generation < 0 || generation >= Number.MAX_SAFE_INTEGER) {
    throw new TypeError("SSO credential generation cannot be incremented safely.");
  }
  return generation + 1;
}

function serializeCredential(candidate) {
  const normalized = normalizeCredential(candidate);
  if (!normalized.ok) throw new TypeError(normalized.reason);
  const json = JSON.stringify(canonicalObject(normalized.credential));
  const encoded = Buffer.from(json, "utf8").toString("base64url");
  const serialized = ENVELOPE_PREFIX + encoded;
  if (serialized.length > MAX_SERIALIZED_LENGTH) throw new TypeError("Credential envelope is too large.");
  return serialized;
}

function decodeStoredCredential(stored, options = {}) {
  if (typeof stored !== "string" || !stored) return Object.freeze({ ok: true, credential: null, legacy: false });
  if (!stored.startsWith(ENVELOPE_PREFIX)) {
    const normalized = normalizeAPIKey(stored);
    if (!normalized.ok || normalized.value !== stored) return invalid(normalized.reason || "Stored API key is not normalized.");
    return Object.freeze({
      ok: true,
      legacy: true,
      credential: Object.freeze({ version: ENVELOPE_VERSION, kind: "api-key", apiKey: normalized.value }),
    });
  }
  if (stored.length > MAX_SERIALIZED_LENGTH) return invalid("Credential envelope is too large.");
  const encoded = stored.slice(ENVELOPE_PREFIX.length);
  if (!encoded || !/^[A-Za-z0-9_-]+$/.test(encoded)) return invalid("Credential envelope encoding is invalid.");
  let parsed;
  try {
    const bytes = Buffer.from(encoded, "base64url");
    if (bytes.toString("base64url") !== encoded) return invalid("Credential envelope encoding is not canonical.");
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return invalid("Credential envelope could not be decoded.");
  }
  const normalized = normalizeCredential(parsed, options);
  if (!normalized.ok) return normalized;
  if (serializeCredential(normalized.credential) !== stored) return invalid("Credential envelope is not canonical.");
  return Object.freeze({ ok: true, credential: normalized.credential, legacy: false });
}

function authorizationForCredential(credential) {
  const normalized = normalizeCredential(credential);
  if (!normalized.ok) return null;
  return normalized.credential.kind === "sso"
    ? Object.freeze({
      kind: "sso",
      headerName: "Authorization",
      headerValue: `Bearer ${normalized.credential.accessToken}`,
      credentialId: normalized.credential.credentialId,
      generation: normalized.credential.generation,
    })
    : Object.freeze({ kind: "api-key", headerName: "X-Api-Key", headerValue: normalized.credential.apiKey });
}

function storageFingerprint(serialized) {
  if (typeof serialized !== "string" || !serialized) return null;
  return sha256(`storage\0${serialized}`);
}

function identityFingerprint(credential) {
  if (!credential) return null;
  const normalized = normalizeCredential(credential);
  if (!normalized.ok) return undefined;
  return normalized.credential.kind === "sso"
    ? sha256(`sso\0${normalized.credential.credentialId}`)
    : sha256(`api-key\0${normalized.credential.apiKey}`);
}

function credentialSecretValues(credential) {
  if (!credential) return [];
  return credential.kind === "sso"
    ? [credential.accessToken, credential.refreshToken]
    : [credential.apiKey];
}

function canonicalObject(credential) {
  if (credential.kind === "api-key") {
    return { apiKey: credential.apiKey, kind: "api-key", version: ENVELOPE_VERSION };
  }
  return {
    accessToken: credential.accessToken,
    credentialId: credential.credentialId,
    generation: credential.generation,
    kind: "sso",
    refreshAttemptedAt: credential.refreshAttemptedAt,
    refreshToken: credential.refreshToken,
    refreshedAt: credential.refreshedAt,
    version: ENVELOPE_VERSION,
  };
}

function normalizeTimestamp(value, now, nullable = false) {
  if (nullable && value === null) return null;
  if (!Number.isSafeInteger(value) || value < 0) return nullable ? undefined : null;
  return Math.min(value, now + 5 * 60 * 1000);
}

function hasExactKeys(value, expected) {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function invalid(reason) {
  return Object.freeze({ ok: false, reason });
}

function sha256(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

module.exports = {
  ENVELOPE_PREFIX,
  ENVELOPE_VERSION,
  MAX_API_KEY_LENGTH,
  MAX_BEARER_TOKEN_LENGTH,
  authorizationForCredential,
  createAPIKeyCredential,
  createSSOCredential,
  credentialSecretValues,
  decodeStoredCredential,
  identityFingerprint,
  normalizeAPIKey,
  normalizeBearerToken,
  normalizeCredential,
  nextCredentialGeneration,
  serializeCredential,
  storageFingerprint,
};

// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const API_ROOT = new URL("https://api.cloudsmith.io/v1/");
const MAX_SEGMENT_LENGTH = 1024;
const MAX_QUERY_VALUE_LENGTH = 8192;
const SECRET_QUERY_NAMES = new Set([
  "api-key",
  "api_key",
  "apikey",
  "x-api-key",
  "x_api_key",
  "xapikey",
  "access-token",
  "access_token",
  "accesstoken",
  "authorization",
  "bearer",
  "client-secret",
  "client_secret",
  "clientsecret",
  "credential",
  "credentials",
  "id-token",
  "id_token",
  "idtoken",
  "password",
  "passwd",
  "private-key",
  "private_key",
  "refresh-token",
  "refresh_token",
  "refreshtoken",
  "secret",
  "token",
]);

function decodeRepeated(value) {
  let decoded = value;
  for (let depth = 0; depth < 3; depth += 1) {
    let next;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      throw new Error("API path segment contains invalid percent encoding.");
    }
    if (next === decoded) {
      break;
    }
    decoded = next;
  }
  return decoded;
}

function encodeApiPathSegment(value) {
  const segment = typeof value === "number" && Number.isFinite(value)
    ? String(value)
    : value;
  if (typeof segment !== "string" || segment.length === 0 || segment.length > MAX_SEGMENT_LENGTH) {
    throw new Error("API path segment is missing or too long.");
  }
  if (segment !== segment.trim() || /[\u0000-\u001f\u007f\\/?#]/.test(segment)) {
    throw new Error("API path segment contains unsupported characters.");
  }

  const decoded = decodeRepeated(segment);
  if (
    decoded === "."
    || decoded === ".."
    || /[\u0000-\u001f\u007f\\/?#]/.test(decoded)
  ) {
    throw new Error("API path segment is unsafe.");
  }

  return encodeURIComponent(segment);
}

function isSecretQueryName(value) {
  let decoded;
  try {
    decoded = decodeRepeated(String(value));
  } catch {
    return true;
  }
  return SECRET_QUERY_NAMES.has(decoded.trim().toLowerCase());
}

function appendQueryValues(searchParams, query) {
  if (query == null) {
    return;
  }

  const entries = query instanceof URLSearchParams
    ? [...query.entries()]
    : Object.entries(query);
  for (const [rawName, rawValue] of entries) {
    const name = String(rawName);
    if (isSecretQueryName(name)) {
      throw new Error("Credentials are not permitted in API query parameters.");
    }
    if (rawValue === undefined || rawValue === null) {
      continue;
    }
    const value = typeof rawValue === "number"
      ? (Number.isFinite(rawValue) ? String(rawValue) : null)
      : typeof rawValue === "boolean" || typeof rawValue === "string"
        ? String(rawValue)
        : null;
    if (value === null || value.length > MAX_QUERY_VALUE_LENGTH || /[\u0000-\u001f\u007f]/.test(value)) {
      throw new Error("API query value is invalid or too long.");
    }
    searchParams.set(name, value);
  }
}

function apiEndpoint(segments, options = {}) {
  if (!Array.isArray(segments) || segments.length === 0) {
    throw new Error("API endpoint requires at least one path segment.");
  }
  const trailingSlash = options.trailingSlash !== false;
  const pathname = segments.map(encodeApiPathSegment).join("/") + (trailingSlash ? "/" : "");
  const searchParams = new URLSearchParams();
  appendQueryValues(searchParams, options.query);
  const queryString = searchParams.toString();
  return queryString ? `${pathname}?${queryString}` : pathname;
}

function appendApiQuery(endpoint, query) {
  if (
    typeof endpoint !== "string"
    || !endpoint
    || endpoint.length > MAX_QUERY_VALUE_LENGTH
    || /[\u0000-\u001f\u007f\\#]/.test(endpoint)
  ) {
    throw new Error("API endpoint is invalid.");
  }

  const parsed = new URL(endpoint, API_ROOT);
  if (parsed.origin !== API_ROOT.origin || !parsed.pathname.startsWith(API_ROOT.pathname)) {
    throw new Error("API endpoint escaped the Cloudsmith API root.");
  }
  for (const name of parsed.searchParams.keys()) {
    if (isSecretQueryName(name)) {
      throw new Error("Credentials are not permitted in API query parameters.");
    }
  }
  appendQueryValues(parsed.searchParams, query);
  return `${parsed.pathname.slice(API_ROOT.pathname.length)}${parsed.search}`;
}

module.exports = {
  apiEndpoint,
  appendApiQuery,
  encodeApiPathSegment,
  isSecretQueryName,
  SECRET_QUERY_NAMES,
};

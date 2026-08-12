// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const MAX_UPSTREAM_URL_LENGTH = 8192;
const MAX_DISPLAY_TEXT_LENGTH = 500;
const MAX_ERROR_MESSAGE_LENGTH = 256;
const MAX_FAILURE_ID_LENGTH = 128;
const MAX_RETRY_AFTER_MS = 24 * 60 * 60 * 1000;
const CONTROL_OR_BIDI = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u;
const DISPLAY_CONTROL_OR_BIDI = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/gu;
const DOT_PATH_SEGMENTS = new Set([".", "..", "%2e", ".%2e", "%2e.", "%2e%2e"]);
const FAILURE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/u;

const ERROR_COPY = Object.freeze({
  local: "The local package collection could not be verified.",
  upstream: "Upstream availability could not be determined.",
});

const PUBLIC_ERROR_MESSAGES = new Set([
  "Request failed",
  "Upstream request failed",
  "Upstream availability could not be determined.",
  "The local package collection could not be verified.",
  "The upstream request was cancelled.",
  "Cloudsmith could not authorize the upstream request.",
  "Cloudsmith returned invalid upstream data.",
  "Cloudsmith upstream data could not be reached.",
  "Cloudsmith rate limited the upstream request. Try again later.",
  "The upstream request timed out.",
]);

const ERROR_KIND_COPY = Object.freeze({
  cancelled: "The upstream request was cancelled.",
  forbidden: "Cloudsmith could not authorize the upstream request.",
  invalid_response: "Cloudsmith returned invalid upstream data.",
  network: "Cloudsmith upstream data could not be reached.",
  rate_limited: "Cloudsmith rate limited the upstream request. Try again later.",
  timeout: "The upstream request timed out.",
  unauthorized: "Cloudsmith could not authorize the upstream request.",
});

const FAILURE_CATEGORY_COPY = Object.freeze({
  authentication: "Authentication is required to inspect this format.",
  cancelled: "The upstream request was cancelled.",
  invalid_response: "Cloudsmith returned invalid upstream data.",
  network: "Cloudsmith could not be reached.",
  not_found: "The upstream configuration endpoint was not found.",
  permission: "You do not have permission to inspect this format.",
  rate_limit: "Cloudsmith rate limited the upstream request. Try again later.",
  request_limit: "The upstream inspection reached its request limit.",
  request_rejected: "The upstream request could not be completed.",
  server: "Cloudsmith could not complete the upstream request.",
  timeout: "The upstream request timed out.",
  uninspected: "This format was not inspected.",
  unknown: "Upstream availability could not be determined.",
});

const FAILURE_KIND_CATEGORY = Object.freeze({
  ABORT_ERR: "cancelled",
  AbortError: "cancelled",
  abort: "cancelled",
  auth: "authentication",
  authentication: "authentication",
  cancelled: "cancelled",
  canceled: "cancelled",
  forbidden: "permission",
  http_error: "request_rejected",
  incomplete_collection: "uninspected",
  invalid_request: "request_rejected",
  invalid_response: "invalid_response",
  network: "network",
  network_error: "network",
  not_found: "not_found",
  permission: "permission",
  rate_limit_circuit: "rate_limit",
  rate_limited: "rate_limit",
  redirect_rejected: "request_rejected",
  rejected: "request_rejected",
  request_failed: "request_rejected",
  request_limit: "request_limit",
  resource_limit: "request_limit",
  server_error: "server",
  timeout: "timeout",
  transport_error: "network",
  transport_failure: "network",
  unauthorized: "authentication",
  uninspected: "uninspected",
});

/**
 * Returns fixed public copy for a normalized failure category. Callers must not
 * substitute transport messages, exception text, or response bodies.
 */
function formatUpstreamFailureCategory(category) {
  return typeof category === "string"
    && Object.prototype.hasOwnProperty.call(FAILURE_CATEGORY_COPY, category)
    ? FAILURE_CATEGORY_COPY[category]
    : FAILURE_CATEGORY_COPY.unknown;
}

/**
 * Projects an arbitrary thrown value or transport result into a small public
 * diagnostic. Every property access can execute caller-owned code, so reads
 * are isolated and no arbitrary message, cause, stack, headers, diagnostic,
 * body, or URL is retained.
 */
function normalizeUpstreamFailure(value) {
  const result = isObjectLike(value) ? value : null;
  const nestedError = safeProperty(result, "error");
  const error = isObjectLike(nestedError) ? nestedError : result;

  const kind = boundedFailureKind(safeProperty(error, "kind"))
    || boundedFailureKind(safeProperty(error, "code"))
    || boundedFailureKind(safeProperty(error, "name"));
  const httpStatus = firstHttpStatus(
    safeProperty(error, "httpStatus"),
    safeProperty(error, "status"),
    safeProperty(result, "httpStatus"),
    safeProperty(result, "status")
  );
  const category = failureCategory(kind, httpStatus);
  const retryable = safeProperty(error, "retryable") === true;
  const retryAfterMs = normalizedRetryAfter(safeProperty(error, "retryAfterMs"));
  const requestId = normalizedFailureId(safeProperty(error, "requestId"))
    || normalizedFailureId(safeProperty(result, "requestId"));
  const serverRequestId = normalizedFailureId(safeProperty(result, "serverRequestId"))
    || normalizedFailureId(safeProperty(error, "serverRequestId"));

  return Object.freeze({
    category,
    message: formatUpstreamFailureCategory(category),
    httpStatus,
    retryable,
    retryAfterMs,
    requestId,
    serverRequestId,
  });
}

function failureCategory(kind, httpStatus) {
  if (httpStatus === 401) return "authentication";
  if (httpStatus === 403) return "permission";
  if (httpStatus === 404) return "not_found";
  if (httpStatus === 408) return "timeout";
  if (httpStatus === 429) return "rate_limit";
  if (httpStatus !== null && httpStatus >= 500) return "server";
  if (httpStatus !== null && httpStatus >= 400) return "request_rejected";
  return kind && Object.prototype.hasOwnProperty.call(FAILURE_KIND_CATEGORY, kind)
    ? FAILURE_KIND_CATEGORY[kind]
    : "unknown";
}

function isObjectLike(value) {
  return value !== null && (typeof value === "object" || typeof value === "function");
}

function safeProperty(value, property) {
  if (!isObjectLike(value)) return null;
  try {
    return value[property];
  } catch {
    return null;
  }
}

function boundedFailureKind(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 64
    ? value
    : null;
}

function firstHttpStatus(...values) {
  for (const value of values) {
    if (Number.isSafeInteger(value) && value >= 100 && value <= 599) return value;
  }
  return null;
}

function normalizedRetryAfter(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_RETRY_AFTER_MS
    ? value
    : null;
}

function normalizedFailureId(value) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= MAX_FAILURE_ID_LENGTH
    && FAILURE_ID.test(value)
    ? value
    : null;
}

/**
 * Converts an upstream-domain failure to bounded public copy. This intentionally
 * does not serialize unknown objects or expose arbitrary exception messages.
 */
function formatUpstreamError(error, context = "upstream") {
  const fallback = typeof context === "string"
    && context.length <= 16
    && Object.prototype.hasOwnProperty.call(ERROR_COPY, context)
    ? ERROR_COPY[context]
    : ERROR_COPY.upstream;
  if (error == null) return fallback;

  try {
    const kind = typeof error === "object" && typeof error.kind === "string"
      ? error.kind
      : null;
    if (
      kind
      && kind.length <= 64
      && Object.prototype.hasOwnProperty.call(ERROR_KIND_COPY, kind)
    ) {
      return ERROR_KIND_COPY[kind];
    }

    const status = typeof error === "object" ? error.status : null;
    if (status === 401 || status === 403) return ERROR_KIND_COPY.unauthorized;
    if (status === 429) return ERROR_KIND_COPY.rate_limited;

    const message = typeof error === "string"
      ? error
      : (typeof error === "object" && Object.prototype.hasOwnProperty.call(error, "message")
          && typeof error.message === "string" ? error.message : null);
    return message
      && message.length <= MAX_ERROR_MESSAGE_LENGTH
      && PUBLIC_ERROR_MESSAGES.has(message)
      ? message
      : fallback;
  } catch {
    return fallback;
  }
}

/**
 * Returns an origin-only display string. This is presentation logic, not an
 * outbound URL validator, and must never be used to authorize network access.
 */
function formatUpstreamOrigin(rawUrl) {
  const parsed = parseDisplayUrl(rawUrl);
  return parsed ? `${parsed.protocol}//${parsed.host}` : "Origin unavailable";
}

function formatUpstreamText(value, fallback = "") {
  if (typeof value !== "string") return fallback;
  return value.slice(0, MAX_DISPLAY_TEXT_LENGTH)
    .replace(DISPLAY_CONTROL_OR_BIDI, " ")
    .replace(/\s+/gu, " ")
    .trim()
    || fallback;
}

function parseDisplayUrl(rawUrl) {
  if (
    typeof rawUrl !== "string"
    || rawUrl.length === 0
    || rawUrl.length > MAX_UPSTREAM_URL_LENGTH
    || rawUrl !== rawUrl.trim()
    || CONTROL_OR_BIDI.test(rawUrl)
    || rawUrl.includes("\\")
    || !hasExactHttpAuthority(rawUrl)
  ) {
    return null;
  }

  try {
    const parsed = new URL(rawUrl);
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) return null;
    return parsed;
  } catch {
    return null;
  }
}

/**
 * Preserves operational path semantics for Terraform only when the raw URL has
 * no credential, query, fragment, slash-normalization, or control ambiguity.
 */
function getTerraformUpstreamUrl(rawUrl) {
  if (
    typeof rawUrl !== "string"
    || rawUrl.length === 0
    || rawUrl.length > MAX_UPSTREAM_URL_LENGTH
    || rawUrl !== rawUrl.trim()
    || CONTROL_OR_BIDI.test(rawUrl)
    || !(rawUrl.startsWith("https://") || rawUrl.startsWith("http://"))
    || rawUrl.includes("?")
    || rawUrl.includes("#")
    || rawUrl.includes("\\")
    || authorityContainsUserinfo(rawUrl)
    || hasDotPathSegment(rawUrl)
  ) {
    return null;
  }
  const parsed = parseDisplayUrl(rawUrl);
  if (!parsed || parsed.username || parsed.password || parsed.search || parsed.hash) return null;
  const pathStart = rawUrl.indexOf("/", rawUrl.indexOf("://") + 3);
  return pathStart === rawUrl.length - 1 ? rawUrl.slice(0, -1) : rawUrl;
}

function authorityContainsUserinfo(rawUrl) {
  const schemeEnd = rawUrl.indexOf("://");
  if (schemeEnd < 0) return false;
  const authorityStart = schemeEnd + 3;
  const pathStart = rawUrl.indexOf("/", authorityStart);
  const authorityEnd = pathStart < 0 ? rawUrl.length : pathStart;
  const authority = rawUrl.slice(authorityStart, authorityEnd);
  return authority.length === 0 || authority.includes("@");
}

function hasExactHttpAuthority(rawUrl) {
  if (!(rawUrl.startsWith("https://") || rawUrl.startsWith("http://"))) return false;
  const authorityStart = rawUrl.indexOf("://") + 3;
  const pathStart = rawUrl.indexOf("/", authorityStart);
  const authorityEnd = pathStart < 0 ? rawUrl.length : pathStart;
  return authorityEnd > authorityStart;
}

function hasDotPathSegment(rawUrl) {
  const authorityStart = rawUrl.indexOf("://") + 3;
  const pathStart = rawUrl.indexOf("/", authorityStart);
  if (pathStart < 0) return false;
  return rawUrl.slice(pathStart).split("/").some(segment => (
    DOT_PATH_SEGMENTS.has(segment.toLowerCase())
  ));
}

module.exports = {
  formatUpstreamError,
  formatUpstreamFailureCategory,
  formatUpstreamOrigin,
  formatUpstreamText,
  getTerraformUpstreamUrl,
  normalizeUpstreamFailure,
};

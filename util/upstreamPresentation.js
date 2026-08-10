// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const MAX_UPSTREAM_URL_LENGTH = 8192;
const MAX_DISPLAY_TEXT_LENGTH = 500;
const MAX_ERROR_MESSAGE_LENGTH = 256;
const CONTROL_OR_BIDI = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u;
const DISPLAY_CONTROL_OR_BIDI = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/gu;
const DOT_PATH_SEGMENTS = new Set([".", "..", "%2e", ".%2e", "%2e.", "%2e%2e"]);

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
  formatUpstreamOrigin,
  formatUpstreamText,
  getTerraformUpstreamUrl,
};

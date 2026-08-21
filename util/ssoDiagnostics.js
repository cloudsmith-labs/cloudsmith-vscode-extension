// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const STAGES = new Set([
  "sso.callback.accepted",
  "sso.callback.bound",
  "sso.callback.received",
  "sso.callback.rejected",
  "sso.callback.start",
  "sso.browser.open",
  "sso.connected",
  "sso.credential.commit",
  "sso.credential.constructed",
  "sso.credential.validate.start",
  "sso.discovery.accepted",
  "sso.discovery.rejected",
  "sso.discovery.response",
  "sso.discovery.start",
  "sso.failed",
  "sso.identity.confirmation",
  "sso.refresh.exchange",
  "sso.two-factor.exchange",
  "sso.two-factor.prompt",
  "sso.user-self.response",
  "sso.workspace-check.response",
]);

const ERROR_KINDS = new Set([
  "browser_open_failed",
  "browser_failed",
  "callback_duplicate",
  "callback_invalid_body",
  "callback_invalid_fields",
  "callback_invalid_method",
  "callback_invalid_path",
  "callback_invalid_token",
  "callback_timeout",
  "cancelled",
  "credential_commit_failed",
  "credential_invalid",
  "credential_lock_failed",
  "discovery_http_error",
  "discovery_invalid_response",
  "discovery_network_error",
  "discovery_redirect_rejected",
  "discovery_timeout",
  "http_error",
  "forbidden",
  "identity_provider_error",
  "identity_unavailable",
  "invalid_request",
  "invalid_candidate",
  "invalid_response",
  "listener_failed",
  "network_error",
  "port_in_use",
  "refresh_rejected",
  "response_too_large",
  "stale",
  "timeout",
  "transient",
  "two_factor_failed",
  "unauthorized",
  "workspace_check_failed",
  "workspace_forbidden",
]);

const BOOLEAN_FIELDS = new Set([
  "authenticated",
  "hasQuery",
  "hasRefreshToken",
  "jsonShapeValid",
  "ok",
  "redirectUrlPresent",
  "targetFound",
]);
const INTEGER_FIELDS = new Set([
  "elapsedMs",
  "pageNumber",
  "queryPairCount",
  "resultCount",
  "statusCode",
  "tokenLength",
  "urlLength",
]);
const ENUM_FIELDS = Object.freeze({
  callbackFamily: new Set(["ipv4", "ipv6"]),
  credentialKind: new Set(["api-key", "sso"]),
  errorKind: ERROR_KINDS,
  outcomeKind: new Set(["error", "tokens", "two_factor"]),
  tokenCharacterClass: new Set(["accepted", "rejected"]),
  urlProtocol: new Set(["https:"]),
});
const ARRAY_FIELDS = new Set(["fieldNames", "parameterNames"]);
const CALLBACK_PARAMETER_NAMES = new Set([
  "access_token",
  "error",
  "refresh_token",
  "two_factor_token",
]);
const SAFE_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
const HOSTNAME_PATTERN = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/;

function createSSODiagnosticObserver(outputChannel) {
  if (!outputChannel || typeof outputChannel.appendLine !== "function") return null;
  return (stage, metadata = {}) => {
    const event = sanitizeSSODiagnostic(stage, metadata);
    if (!event) return;
    try {
      outputChannel.appendLine(`[SSO] ${JSON.stringify(event)}`);
    } catch {
      // Diagnostics must never affect authentication behavior.
    }
  };
}

function sanitizeSSODiagnostic(stage, metadata = {}) {
  if (!STAGES.has(stage)) return null;
  const event = { stage };
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    return Object.freeze(event);
  }
  for (const [key, value] of Object.entries(metadata)) {
    if (BOOLEAN_FIELDS.has(key) && typeof value === "boolean") {
      event[key] = value;
      continue;
    }
    if (INTEGER_FIELDS.has(key) && Number.isSafeInteger(value) && value >= 0 && value <= 10 * 60 * 1000) {
      event[key] = value;
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(ENUM_FIELDS, key) && ENUM_FIELDS[key].has(value)) {
      event[key] = value;
      continue;
    }
    if (ARRAY_FIELDS.has(key) && Array.isArray(value) && value.length <= 16) {
      const names = value.filter(item => (
        typeof item === "string"
        && SAFE_NAME_PATTERN.test(item)
        && (key !== "parameterNames" || CALLBACK_PARAMETER_NAMES.has(item))
      ));
      if (names.length === value.length) event[key] = Object.freeze(names.slice().sort());
      continue;
    }
    if (key === "contentType" && typeof value === "string") {
      const contentType = value.split(";", 1)[0].trim().toLowerCase();
      if (/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(contentType)) event[key] = contentType;
      continue;
    }
    if (key === "idpHostname" && typeof value === "string" && HOSTNAME_PATTERN.test(value)) {
      event[key] = value.toLowerCase();
    }
  }
  return Object.freeze(event);
}

function recordSSODiagnostic(observer, stage, metadata) {
  if (typeof observer !== "function") return;
  try {
    observer(stage, metadata);
  } catch {
    // Diagnostics must never affect authentication behavior.
  }
}

module.exports = {
  createSSODiagnosticObserver,
  recordSSODiagnostic,
  sanitizeSSODiagnostic,
};

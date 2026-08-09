// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const { CredentialManager } = require("./credentialManager");
const { isSecretQueryName } = require("./apiEndpoint");
const extensionVersion = require("../package.json").version;
const vscodeVersion = require("vscode").version;

const API_ROOTS = Object.freeze({
  v1: new URL("https://api.cloudsmith.io/v1/"),
  v2: new URL("https://api.cloudsmith.io/v2/"),
});
const API_ORIGIN = "https://api.cloudsmith.io";
const DEFAULT_TIMEOUT_MS = 30 * 1000;
const MAX_TIMEOUT_MS = 2 * 60 * 1000;
const MAX_ENDPOINT_LENGTH = 16 * 1024;
const MAX_REQUEST_BODY_BYTES = 1024 * 1024;
const MAX_SUCCESS_BODY_BYTES = 5 * 1024 * 1024;
const MAX_ERROR_BODY_BYTES = 8 * 1024;
const MAX_HEADER_VALUE_LENGTH = 512;
const MAX_REDIRECTS = 1;
const MAX_READ_RETRIES = 2;
const MAX_AUTO_RETRY_DELAY_MS = 5 * 1000;
const MAX_REPORTED_RETRY_AFTER_MS = 24 * 60 * 60 * 1000;
const RETRYABLE_STATUS_CODES = new Set([429, 500, 502, 503, 504]);
const SUPPORTED_METHODS = new Set(["DELETE", "GET", "HEAD", "PATCH", "POST", "PUT"]);
const ALLOWED_CAUSE_CODES = new Set([
  "ECONNREFUSED",
  "ECONNRESET",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "ENOTFOUND",
  "ETIMEDOUT",
]);
const ALLOWED_RESPONSE_HEADERS = Object.freeze([
  "content-length",
  "content-type",
  "retry-after",
  "x-correlation-id",
  "x-pagination-count",
  "x-pagination-page",
  "x-pagination-pagesize",
  "x-pagination-pagetotal",
  "x-request-id",
  "cf-ray",
]);
const EMPTY_HEADERS = Object.freeze(Object.create(null));
const userAgent = `Cloudsmith-VSCode/${extensionVersion} (VS Code ${vscodeVersion})`;

function stripControls(value, maximum = MAX_HEADER_VALUE_LENGTH) {
  return String(value == null ? "" : value)
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .slice(0, maximum);
}

function redactKnownSecrets(value, keys) {
  let redacted = stripControls(value, 1024);
  for (const key of keys) {
    if (typeof key === "string" && key) {
      redacted = redacted.split(key).join("[REDACTED]");
      try {
        redacted = redacted.split(encodeURIComponent(key)).join("[REDACTED]");
      } catch {
        // The raw value replacement above still applies.
      }
    }
  }
  return redacted;
}

function safeHeaderValue(headers, name) {
  if (!headers || typeof headers.get !== "function") {
    return null;
  }
  try {
    const value = headers.get(name);
    return value == null ? null : stripControls(value);
  } catch {
    return null;
  }
}

function snapshotHeaders(headers, keys = []) {
  if (!headers || typeof headers.get !== "function") {
    return EMPTY_HEADERS;
  }
  const snapshot = Object.create(null);
  for (const name of ALLOWED_RESPONSE_HEADERS) {
    const value = safeHeaderValue(headers, name);
    if (value !== null) {
      snapshot[name] = redactKnownSecrets(value, keys);
    }
  }
  return Object.freeze(snapshot);
}

function serverRequestIdFrom(headers) {
  return headers["x-request-id"]
    || headers["x-correlation-id"]
    || headers["cf-ray"]
    || null;
}

function decodingLayers(value) {
  const layers = [String(value || "")];
  for (let depth = 0; depth < 3; depth += 1) {
    let next;
    try {
      next = decodeURIComponent(layers[layers.length - 1]);
    } catch {
      return null;
    }
    if (next === layers[layers.length - 1]) {
      break;
    }
    layers.push(next);
  }
  return layers;
}

function decodeRepeated(value) {
  const layers = decodingLayers(value);
  return layers === null ? null : layers[layers.length - 1];
}

function hasUnsafePathEncoding(rawPath) {
  for (const segment of String(rawPath || "").split("/")) {
    const decoded = decodeRepeated(segment);
    if (
      decoded === null
      || decoded === "."
      || decoded === ".."
      || /[\\/?#\u0000-\u001f\u007f]/.test(decoded)
    ) {
      return true;
    }
  }
  return false;
}

function containsKnownSecret(value, keys) {
  const candidates = decodingLayers(value);
  if (candidates === null) return true;
  return [...keys].some((key) => (
    typeof key === "string"
    && key
    && candidates.some((candidate) => candidate.includes(key))
  ));
}

function validateApiUrl(candidate, apiVersion, keys, options = {}) {
  const root = API_ROOTS[apiVersion];
  if (!root || typeof candidate !== "string" || !candidate || candidate.length > MAX_ENDPOINT_LENGTH) {
    return null;
  }
  if (candidate !== candidate.trim() || /[\\#\u0000-\u001f\u007f]/.test(candidate)) {
    return null;
  }
  if (!options.allowAbsolute && (/^[a-z][a-z\d+.-]*:/i.test(candidate) || candidate.startsWith("/"))) {
    return null;
  }

  const rawPath = candidate.split("?", 1)[0];
  if (hasUnsafePathEncoding(rawPath) || containsKnownSecret(candidate, keys)) {
    return null;
  }

  let url;
  try {
    url = options.allowAbsolute ? new URL(candidate, options.baseUrl || root) : new URL(candidate, root);
  } catch {
    return null;
  }
  if (
    url.origin !== API_ORIGIN
    || url.protocol !== "https:"
    || url.hostname !== "api.cloudsmith.io"
    || url.port !== ""
    || url.username !== ""
    || url.password !== ""
    || url.hash !== ""
    || !url.pathname.startsWith(root.pathname)
  ) {
    return null;
  }
  if (hasUnsafePathEncoding(url.pathname.slice(root.pathname.length))) {
    return null;
  }
  for (const [name, value] of url.searchParams.entries()) {
    if (
      /[\u0000-\u001f\u007f]/.test(name)
      || /[\u0000-\u001f\u007f]/.test(value)
      || isSecretQueryName(name)
      || containsKnownSecret(value, keys)
    ) {
      return null;
    }
  }
  if (containsKnownSecret(url.pathname, keys)) {
    return null;
  }
  return url;
}

function responseTypeAcceptsEmpty(responseType) {
  return responseType === "empty" || responseType === "json-or-empty";
}

function isJsonContentType(contentType) {
  const mediaType = String(contentType || "").split(";", 1)[0].trim().toLowerCase();
  return mediaType === "application/json" || mediaType.endsWith("+json");
}

function validateResponseShape(data, responseType) {
  switch (responseType) {
    case "array":
      return Array.isArray(data);
    case "object":
      return Boolean(data) && typeof data === "object" && !Array.isArray(data);
    case "json":
    case "json-or-empty":
      return true;
    case "empty":
      return data === null;
    default:
      return false;
  }
}

function errorKindForStatus(status) {
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status === 429) return "rate_limited";
  if (status >= 500) return "server_error";
  return "http_error";
}

function messageForError(kind, outcomeUnknown = false) {
  if (outcomeUnknown) {
    return "The request may have completed in Cloudsmith. Check the remote state before trying again.";
  }
  switch (kind) {
    case "unauthorized":
      return "Authentication failed. Check the API key.";
    case "forbidden":
      return "Could not access this resource. Check permissions.";
    case "not_found":
      return "Could not find the requested Cloudsmith resource.";
    case "rate_limited":
      return "Rate limited by the Cloudsmith API. Wait a moment and try again.";
    case "server_error":
      return "The Cloudsmith API returned an internal error. Try again later.";
    case "network_error":
      return "Could not reach the Cloudsmith API. Check the network connection.";
    case "timeout":
      return "The Cloudsmith API request timed out.";
    case "cancelled":
      return "The Cloudsmith API request was canceled.";
    case "invalid_response":
      return "Cloudsmith returned an unexpected response.";
    case "redirect_rejected":
      return "Cloudsmith returned an unsafe redirect, so the request was stopped.";
    case "invalid_request":
      return "The Cloudsmith request could not be constructed safely.";
    default:
      return "The Cloudsmith API request failed.";
  }
}

function parseRetryAfter(value, now) {
  if (!value) {
    return null;
  }
  const normalized = String(value).trim();
  if (/^\d+$/.test(normalized)) {
    const milliseconds = Number(normalized) * 1000;
    return Number.isSafeInteger(milliseconds) ? milliseconds : null;
  }
  const timestamp = Date.parse(normalized);
  if (!Number.isFinite(timestamp)) {
    return null;
  }
  return Math.max(0, timestamp - now);
}

function isReadMethod(method) {
  return method === "GET" || method === "HEAD";
}

function safeCauseCode(error) {
  try {
    const code = error && (error.code || (error.cause && error.cause.code));
    return ALLOWED_CAUSE_CODES.has(code) ? code : null;
  } catch {
    return null;
  }
}

function cancelResponseBody(response) {
  try {
    if (response && response.body && typeof response.body.cancel === "function") {
      Promise.resolve(response.body.cancel()).catch(() => {});
    }
  } catch {
    // Body cancellation is best-effort after the request outcome is known.
  }
}

async function readBoundedBody(response, limit, signal) {
  const lengthHeader = safeHeaderValue(response && response.headers, "content-length");
  const declaredLength = lengthHeader && /^\d+$/.test(lengthHeader) ? Number(lengthHeader) : null;
  if (declaredLength !== null && declaredLength > limit) {
    await cancelResponseBody(response);
    return { oversized: true, text: "", bytes: 0 };
  }

  if (response && response.body && typeof response.body.getReader === "function") {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let text = "";
    let bytes = 0;
    try {
      while (true) {
        if (signal.aborted) {
          cancelResponseReader(reader);
          return { aborted: true, text: "", bytes };
        }
        const chunkResult = await readStreamChunk(reader, signal);
        if (chunkResult.aborted) {
          return { aborted: true, text: "", bytes };
        }
        if (chunkResult.failed) {
          cancelResponseReader(reader);
          return { readFailed: true, text: "", bytes };
        }
        const chunk = chunkResult.value;
        if (chunk.done) {
          text += decoder.decode();
          return { text, bytes };
        }
        bytes += chunk.value.byteLength;
        if (bytes > limit) {
          cancelResponseReader(reader);
          return { oversized: true, text: "", bytes };
        }
        text += decoder.decode(chunk.value, { stream: true });
      }
    } catch {
      cancelResponseReader(reader);
      if (signal.aborted) {
        return { aborted: true, text: "", bytes };
      }
      return { readFailed: true, text: "", bytes };
    } finally {
      try { reader.releaseLock(); } catch { /* no-op */ }
    }
  }

  if (!response || !response.body) {
    return { text: "", bytes: 0 };
  }

  await cancelResponseBody(response);
  return { unsupported: true, text: "", bytes: 0 };
}

function cancelResponseReader(reader) {
  if (!reader || typeof reader.cancel !== "function") {
    return;
  }
  try {
    Promise.resolve(reader.cancel()).catch(() => {});
  } catch {
    // The stream may already be closed or detached.
  }
}

function readStreamChunk(reader, signal) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      resolve(result);
    };
    const onAbort = () => {
      cancelResponseReader(reader);
      finish({ aborted: true });
    };
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) {
      onAbort();
      return;
    }
    Promise.resolve()
      .then(() => reader.read())
      .then(value => finish({ value }), () => finish({ failed: true }));
    if (signal.aborted) {
      onAbort();
    }
  });
}

async function discardBoundedBody(response, limit, signal) {
  const result = await readBoundedBody(response, limit, signal);
  if (result.oversized) {
    await cancelResponseBody(response);
  }
  return result;
}

class CloudsmithAPI {
  constructor(context, options = {}) {
    this.context = context;
    this._fetch = options.fetchImpl || fetch;
    this._setTimeout = options.setTimeout || setTimeout;
    this._clearTimeout = options.clearTimeout || clearTimeout;
    this._now = options.now || Date.now;
    this._randomUUID = options.randomUUID || crypto.randomUUID;
    this._credentialManager = options.credentialManager || new CredentialManager(context);
  }

  async get(endpoint, options = {}) {
    return this.request(endpoint, { ...options, method: "GET", apiVersion: "v1" });
  }

  async getV2(endpoint, options = {}) {
    return this.request(endpoint, { ...options, method: "GET", apiVersion: "v2" });
  }

  async post(endpoint, json, options = {}) {
    return this.request(endpoint, {
      ...options,
      method: "POST",
      apiVersion: options.apiVersion || "v1",
      json,
      retry: "never",
    });
  }

  async request(endpoint, options = {}) {
    const requestId = this._randomUUID();
    const method = String(options.method || "GET").toUpperCase();
    const apiVersion = options.apiVersion || "v1";
    const responseType = options.responseType || "object";
    const retry = options.retry || "never";
    const timeoutMs = Number.isFinite(options.timeoutMs)
      ? Math.max(1, Math.min(Math.floor(options.timeoutMs), MAX_TIMEOUT_MS))
      : DEFAULT_TIMEOUT_MS;
    const externalSignal = options.signal || null;
    const cancellationToken = options.cancellationToken || null;
    const controller = new AbortController();
    let abortKind = null;
    let externalAbortListener = null;
    let cancellationDisposable = null;
    let timeoutHandle = null;
    let attempts = 0;
    let selectedKey = null;
    let storedKey = null;
    const keys = new Set();
    const deadline = this._now() + timeoutMs;

    const abort = (kind) => {
      if (abortKind !== null) {
        return false;
      }
      abortKind = kind;
      controller.abort();
      return true;
    };

    const diagnosticPath = () => {
      const root = API_ROOTS[apiVersion];
      const validated = root ? validateApiUrl(endpoint, apiVersion, keys) : null;
      if (!validated || !root) {
        return "";
      }
      return stripControls(validated.pathname.slice(root.pathname.length), 512);
    };

    const buildDiagnostic = (status = null, headers = EMPTY_HEADERS, bodyBytes = 0, causeCode = null) => Object.freeze({
      method,
      apiVersion: API_ROOTS[apiVersion] ? apiVersion : null,
      path: redactKnownSecrets(diagnosticPath(), keys),
      status: Number.isInteger(status) ? status : null,
      contentType: redactKnownSecrets(headers["content-type"] || "", keys),
      bodyBytes: Number.isSafeInteger(bodyBytes) && bodyBytes >= 0 ? bodyBytes : 0,
      causeCode: ALLOWED_CAUSE_CODES.has(causeCode) ? causeCode : null,
    });

    const failure = ({
      kind,
      status = null,
      headers = EMPTY_HEADERS,
      retryable = false,
      retryAfterMs = null,
      outcomeUnknown = false,
      bodyBytes = 0,
      causeCode = null,
    }) => {
      const serverRequestId = serverRequestIdFrom(headers);
      const error = Object.freeze({
        kind,
        status: Number.isInteger(status) ? status : null,
        retryable: Boolean(retryable),
        message: messageForError(kind, outcomeUnknown),
        requestId,
        retryAfterMs: Number.isFinite(retryAfterMs)
          ? Math.min(Math.max(0, retryAfterMs), MAX_REPORTED_RETRY_AFTER_MS)
          : null,
        outcomeUnknown: Boolean(outcomeUnknown),
        diagnostic: buildDiagnostic(status, headers, bodyBytes, causeCode),
      });
      return Object.freeze({
        ok: false,
        status: Number.isInteger(status) ? status : null,
        headers,
        requestId,
        serverRequestId,
        attempts,
        error,
      });
    };

    const cancelledFailure = () => failure({
      kind: abortKind === "timeout" ? "timeout" : "cancelled",
      retryable: false,
      outcomeUnknown: !isReadMethod(method) && attempts > 0,
    });

    try {
      if (externalSignal && typeof externalSignal.addEventListener === "function") {
        externalAbortListener = () => abort("cancelled");
        externalSignal.addEventListener("abort", externalAbortListener, { once: true });
        if (externalSignal.aborted) {
          abort("cancelled");
        }
      }
      if (cancellationToken && typeof cancellationToken.onCancellationRequested === "function") {
        cancellationDisposable = cancellationToken.onCancellationRequested(() => abort("cancelled"));
        if (cancellationToken.isCancellationRequested) {
          abort("cancelled");
        }
      }
      timeoutHandle = this._setTimeout(() => abort("timeout"), timeoutMs);
      if (abortKind !== null) {
        return cancelledFailure();
      }

      const credentialResult = await this._awaitAbortable(
        Promise.resolve().then(() => this._credentialManager.getApiKey()),
        controller.signal
      );
      if (credentialResult.aborted) {
        return cancelledFailure();
      }
      if (!credentialResult.ok) {
        return failure({ kind: "invalid_request" });
      }
      storedKey = credentialResult.value;
      if (typeof storedKey === "string" && storedKey) {
        keys.add(storedKey);
      }
      if (abortKind !== null || this._now() >= deadline) {
        if (abortKind === null) abort("timeout");
        return cancelledFailure();
      }

      const hasCandidateKey = Object.prototype.hasOwnProperty.call(options, "apiKey");
      if (hasCandidateKey) {
        if (typeof options.apiKey === "string" && options.apiKey) {
          selectedKey = options.apiKey;
          keys.add(selectedKey);
        }
      } else {
        selectedKey = storedKey;
      }
      if (
        typeof selectedKey !== "string"
        || !selectedKey
        || selectedKey.length > 4096
        || /[\u0000-\u001f\u007f]/.test(selectedKey)
      ) {
        return failure({ kind: "unauthorized", status: 401 });
      }

      const requestUrl = validateApiUrl(endpoint, apiVersion, keys);
      if (!requestUrl || !API_ROOTS[apiVersion]) {
        return failure({ kind: "invalid_request" });
      }
      if (!SUPPORTED_METHODS.has(method)) {
        return failure({ kind: "invalid_request" });
      }
      if (!["array", "empty", "json", "json-or-empty", "object"].includes(responseType)) {
        return failure({ kind: "invalid_request" });
      }
      if (!isReadMethod(method) && retry !== "never") {
        return failure({ kind: "invalid_request" });
      }
      if (retry !== "never" && retry !== "safe-read") {
        return failure({ kind: "invalid_request" });
      }
      if (isReadMethod(method) && Object.prototype.hasOwnProperty.call(options, "json")) {
        return failure({ kind: "invalid_request" });
      }

      let body;
      if (Object.prototype.hasOwnProperty.call(options, "json")) {
        try {
          body = JSON.stringify(options.json);
        } catch {
          return failure({ kind: "invalid_request" });
        }
        if (body === undefined || Buffer.byteLength(body, "utf8") > MAX_REQUEST_BODY_BYTES) {
          return failure({ kind: "invalid_request" });
        }
      }

      const maxAttempts = retry === "safe-read" && isReadMethod(method)
        ? MAX_READ_RETRIES + 1
        : 1;
      let currentFailure = null;

      while (attempts < maxAttempts) {
        if (abortKind !== null || this._now() >= deadline) {
          if (abortKind === null) abort("timeout");
          return cancelledFailure();
        }
        attempts += 1;

        const attemptResult = await this._performAttempt({
          requestUrl,
          method,
          body,
          selectedKey,
          apiVersion,
          responseType,
          validate: options.validate,
          signal: controller.signal,
          keys,
          abortKind: () => abortKind,
          deadline,
          now: this._now,
          abortTimeout: () => abort("timeout"),
        });
        if (abortKind !== null || this._now() >= deadline) {
          if (abortKind === null) abort("timeout");
          return cancelledFailure();
        }
        if (attemptResult.ok) {
          const serverRequestId = serverRequestIdFrom(attemptResult.headers);
          return Object.freeze({
            ok: true,
            data: attemptResult.data,
            status: attemptResult.status,
            headers: attemptResult.headers,
            requestId,
            serverRequestId,
            attempts,
            redirectCount: attemptResult.redirectCount,
          });
        }

        const unsafeWrite = !isReadMethod(method);
        const outcomeUnknown = unsafeWrite && attemptResult.dispatched && (
          attemptResult.status === null
          || attemptResult.status >= 500
          || (attemptResult.status >= 200 && attemptResult.status < 300)
        );
        currentFailure = failure({
          ...attemptResult,
          retryable: isReadMethod(method) && attemptResult.retryable,
          outcomeUnknown,
        });

        const shouldRetry = attempts < maxAttempts
          && retry === "safe-read"
          && attemptResult.retryable;
        if (!shouldRetry) {
          return currentFailure;
        }

        const retryAfterMs = attemptResult.retryAfterMs;
        const delayMs = retryAfterMs === null
          ? Math.min(250 * (2 ** (attempts - 1)), MAX_AUTO_RETRY_DELAY_MS)
          : retryAfterMs;
        const remaining = deadline - this._now();
        if (delayMs > MAX_AUTO_RETRY_DELAY_MS || delayMs >= remaining) {
          return currentFailure;
        }
        const completedDelay = await this._waitForRetry(delayMs, controller.signal);
        if (!completedDelay || abortKind !== null) {
          return cancelledFailure();
        }
      }

      return currentFailure || failure({ kind: "network_error" });
    } finally {
      if (timeoutHandle !== null) {
        this._clearTimeout(timeoutHandle);
      }
      if (externalSignal && externalAbortListener && typeof externalSignal.removeEventListener === "function") {
        externalSignal.removeEventListener("abort", externalAbortListener);
      }
      if (cancellationDisposable && typeof cancellationDisposable.dispose === "function") {
        cancellationDisposable.dispose();
      }
    }
  }

  async _performAttempt({
    requestUrl,
    method,
    body,
    selectedKey,
    apiVersion,
    responseType,
    validate,
    signal,
    keys,
    abortKind,
    deadline,
    now,
    abortTimeout,
  }) {
    let currentUrl = requestUrl;
    let redirectCount = 0;
    let dispatched = false;

    while (true) {
      if (signal.aborted || now() >= deadline) {
        if (!signal.aborted) abortTimeout();
        return { ok: false, kind: abortKind() || "cancelled", status: null, headers: EMPTY_HEADERS, dispatched };
      }
      let response;
      try {
        const headers = {
          Accept: "application/json",
          "User-Agent": userAgent,
          "X-Api-Key": selectedKey,
        };
        if (body !== undefined) {
          headers["Content-Type"] = "application/json";
        }
        dispatched = true;
        const fetchResult = await this._awaitAbortable(this._fetch(currentUrl, {
          method,
          headers,
          ...(body !== undefined ? { body } : {}),
          redirect: "manual",
          signal,
        }), signal, cancelResponseBody);
        if (fetchResult.aborted) {
          return { ok: false, kind: abortKind() || "cancelled", status: null, headers: EMPTY_HEADERS, dispatched };
        }
        if (!fetchResult.ok) {
          throw fetchResult.error;
        }
        response = fetchResult.value;
      } catch (error) {
        if (signal.aborted) {
          return { ok: false, kind: abortKind() || "cancelled", status: null, headers: EMPTY_HEADERS, dispatched };
        }
        return {
          ok: false,
          kind: "network_error",
          status: null,
          headers: EMPTY_HEADERS,
          retryable: true,
          retryAfterMs: null,
          bodyBytes: 0,
          causeCode: safeCauseCode(error),
          dispatched,
        };
      }

      if (signal.aborted || now() >= deadline) {
        if (!signal.aborted) abortTimeout();
        await cancelResponseBody(response);
        return { ok: false, kind: abortKind() || "cancelled", status: null, headers: EMPTY_HEADERS, dispatched };
      }

      if (response.status >= 300 && response.status < 400) {
        const location = safeHeaderValue(response.headers, "location");
        await cancelResponseBody(response);
        if (!isReadMethod(method) || redirectCount >= MAX_REDIRECTS || !location) {
          return {
            ok: false,
            kind: "redirect_rejected",
            status: response.status,
            headers: snapshotHeaders(response.headers, keys),
            retryable: false,
            retryAfterMs: null,
            bodyBytes: 0,
            dispatched,
          };
        }
        const redirectUrl = validateApiUrl(location, apiVersion, keys, {
          allowAbsolute: true,
          baseUrl: currentUrl,
        });
        if (!redirectUrl || redirectUrl.toString() === currentUrl.toString()) {
          return {
            ok: false,
            kind: "redirect_rejected",
            status: response.status,
            headers: snapshotHeaders(response.headers, keys),
            retryable: false,
            retryAfterMs: null,
            bodyBytes: 0,
            dispatched,
          };
        }
        currentUrl = redirectUrl;
        redirectCount += 1;
        continue;
      }

      const headers = snapshotHeaders(response.headers, keys);
      const status = Number.isInteger(response.status) ? response.status : null;
      if (!response.ok) {
        const discarded = await discardBoundedBody(response, MAX_ERROR_BODY_BYTES, signal);
        if (signal.aborted || discarded.aborted) {
          return { ok: false, kind: abortKind() || "cancelled", status: null, headers, dispatched };
        }
        const kind = errorKindForStatus(status);
        const retryAfterMs = parseRetryAfter(headers["retry-after"], this._now());
        return {
          ok: false,
          kind,
          status,
          headers,
          retryable: RETRYABLE_STATUS_CODES.has(status),
          retryAfterMs,
          bodyBytes: discarded.bytes || 0,
          dispatched,
        };
      }

      if (status === 204 || status === 205) {
        if (!responseTypeAcceptsEmpty(responseType)) {
          return {
            ok: false,
            kind: "invalid_response",
            status,
            headers,
            retryable: false,
            retryAfterMs: null,
            bodyBytes: 0,
            dispatched,
          };
        }
        return { ok: true, data: null, status, headers, redirectCount };
      }

      const bodyResult = await readBoundedBody(response, MAX_SUCCESS_BODY_BYTES, signal);
      if (signal.aborted || bodyResult.aborted || now() >= deadline) {
        if (!signal.aborted && now() >= deadline) abortTimeout();
        return { ok: false, kind: abortKind() || "cancelled", status: null, headers, dispatched };
      }
      if (bodyResult.readFailed) {
        return {
          ok: false,
          kind: "network_error",
          status,
          headers,
          retryable: true,
          retryAfterMs: null,
          bodyBytes: bodyResult.bytes || 0,
          dispatched,
        };
      }
      if (bodyResult.unsupported) {
        return {
          ok: false,
          kind: "invalid_response",
          status,
          headers,
          retryable: false,
          retryAfterMs: null,
          bodyBytes: 0,
          dispatched,
        };
      }
      if (bodyResult.oversized) {
        return {
          ok: false,
          kind: "invalid_response",
          status,
          headers,
          retryable: false,
          retryAfterMs: null,
          bodyBytes: bodyResult.bytes || 0,
          dispatched,
        };
      }

      if (bodyResult.text.length === 0) {
        if (!responseTypeAcceptsEmpty(responseType)) {
          return {
            ok: false,
            kind: "invalid_response",
            status,
            headers,
            retryable: false,
            retryAfterMs: null,
            bodyBytes: 0,
            dispatched,
          };
        }
        return { ok: true, data: null, status, headers, redirectCount };
      }
      if (responseType === "empty" || !isJsonContentType(headers["content-type"])) {
        return {
          ok: false,
          kind: "invalid_response",
          status,
          headers,
          retryable: false,
          retryAfterMs: null,
          bodyBytes: bodyResult.bytes,
          dispatched,
        };
      }

      let data;
      try {
        data = JSON.parse(bodyResult.text);
      } catch {
        return {
          ok: false,
          kind: "invalid_response",
          status,
          headers,
          retryable: false,
          retryAfterMs: null,
          bodyBytes: bodyResult.bytes,
          dispatched,
        };
      }
      if (!validateResponseShape(data, responseType)) {
        return {
          ok: false,
          kind: "invalid_response",
          status,
          headers,
          retryable: false,
          retryAfterMs: null,
          bodyBytes: bodyResult.bytes,
          dispatched,
        };
      }
      if (typeof validate === "function") {
        let valid = false;
        try {
          valid = validate(data) === true;
        } catch {
          valid = false;
        }
        if (!valid) {
          return {
            ok: false,
            kind: "invalid_response",
            status,
            headers,
            retryable: false,
            retryAfterMs: null,
            bodyBytes: bodyResult.bytes,
            dispatched,
          };
        }
      }
      return { ok: true, data, status, headers, redirectCount };
    }
  }

  _awaitAbortable(promise, signal, onLateValue = null) {
    return new Promise((resolve) => {
      let settled = false;
      const finish = (result) => {
        if (settled) return false;
        settled = true;
        signal.removeEventListener("abort", onAbort);
        resolve(result);
        return true;
      };
      const onAbort = () => finish({ aborted: true });
      signal.addEventListener("abort", onAbort, { once: true });
      if (signal.aborted) {
        onAbort();
      }
      Promise.resolve(promise).then(
        (value) => {
          if (!finish({ ok: true, value }) && typeof onLateValue === "function") {
            Promise.resolve(onLateValue(value)).catch(() => {});
          }
        },
        error => finish({ ok: false, error })
      );
      if (signal.aborted) {
        onAbort();
      }
    });
  }

  _waitForRetry(delayMs, signal) {
    return new Promise((resolve) => {
      let settled = false;
      let handle = null;
      const finish = (value) => {
        if (settled) return;
        settled = true;
        if (handle !== null) this._clearTimeout(handle);
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      };
      const onAbort = () => finish(false);
      signal.addEventListener("abort", onAbort, { once: true });
      if (signal.aborted) {
        finish(false);
        return;
      }
      handle = this._setTimeout(() => finish(true), delayMs);
      if (signal.aborted) {
        finish(false);
      }
    });
  }
}

function isApiResult(value) {
  return Boolean(value) && typeof value === "object" && typeof value.ok === "boolean";
}

module.exports = {
  CloudsmithAPI,
  DEFAULT_TIMEOUT_MS,
  isApiResult,
};

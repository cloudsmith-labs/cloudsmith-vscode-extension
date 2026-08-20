const { normalizeBearerToken } = require("./credentialEnvelope");

const API_ORIGIN = "https://api.cloudsmith.io";
const CALLBACK_URL = "http://localhost:12400";
const DISCOVERY_TIMEOUT_MS = 30000;
const EXCHANGE_TIMEOUT_MS = 30000;
const MAX_RESPONSE_BYTES = 64 * 1024;
const MAX_IDP_URL_BYTES = 8192;
const MAX_WORKSPACE_BYTES = 128;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;

class SSOProtocolClient {
  constructor(options = {}) {
    this._fetch = options.fetchImpl || fetch;
    this._setTimeout = options.setTimeout || setTimeout;
    this._clearTimeout = options.clearTimeout || clearTimeout;
  }

  async discover(workspace, options = {}) {
    if (!isValidWorkspace(workspace)) return failure("invalid_workspace");
    const endpoint = new URL(`/orgs/${encodeURIComponent(workspace)}/saml/`, API_ORIGIN);
    endpoint.searchParams.set("redirect_url", CALLBACK_URL);
    const result = await this._jsonRequest(endpoint, {
      method: "GET",
      signal: options.signal,
      timeoutMs: DISCOVERY_TIMEOUT_MS,
    });
    if (!result.ok) return result;
    if (
      !isPlainObject(result.data)
      || !Object.prototype.hasOwnProperty.call(result.data, "redirect_url")
      || typeof result.data.redirect_url !== "string"
    ) return failure("invalid_response", result.status);
    const redirectUrl = validateIdPURL(result.data.redirect_url);
    return redirectUrl
      ? Object.freeze({ ok: true, redirectUrl })
      : failure("invalid_response", result.status);
  }

  async exchangeTwoFactor(twoFactorToken, totpToken, options = {}) {
    const twoFactor = normalizeBearerToken(twoFactorToken, "Two-factor token");
    if (!twoFactor.ok || !/^[0-9]{6,10}$/.test(totpToken || "")) return failure("invalid_request");
    const body = new URLSearchParams({ two_factor_token: twoFactor.value, totp_token: totpToken }).toString();
    const result = await this._jsonRequest(new URL("/user/two-factor/", API_ORIGIN), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${twoFactor.value}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
      signal: options.signal,
      timeoutMs: EXCHANGE_TIMEOUT_MS,
    });
    return result.ok ? tokenPair(result.data, result.status, true) : result;
  }

  async refresh(accessToken, refreshToken, options = {}) {
    const access = normalizeBearerToken(accessToken, "SSO access token");
    const refresh = normalizeBearerToken(refreshToken, "SSO refresh token");
    if (!access.ok || !refresh.ok) return failure("invalid_request");
    const result = await this._jsonRequest(new URL("/user/refresh-token/", API_ORIGIN), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${access.value}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ refresh_token: refresh.value }).toString(),
      signal: options.signal,
      timeoutMs: EXCHANGE_TIMEOUT_MS,
      classifyInvalidSession: true,
    });
    return result.ok ? tokenPair(result.data, result.status, false) : result;
  }

  async _jsonRequest(url, options) {
    if (!(url instanceof URL) || url.origin !== API_ORIGIN || url.username || url.password || url.hash) {
      return failure("invalid_request");
    }
    const controller = new AbortController();
    const external = options.signal;
    let timeout = null;
    let abortListener = null;
    let timedOut = false;
    try {
      if (external) {
        abortListener = () => controller.abort();
        external.addEventListener("abort", abortListener, { once: true });
        if (external.aborted) controller.abort();
      }
      timeout = this._setTimeout(() => {
        timedOut = true;
        controller.abort();
      }, options.timeoutMs);
      let response;
      try {
        response = await this._fetch(url, {
          method: options.method,
          headers: {
            Accept: "application/json",
            "User-Agent": "cloudsmith-vscode",
            ...(options.headers || {}),
          },
          ...(options.body ? { body: options.body } : {}),
          redirect: "manual",
          signal: controller.signal,
        });
      } catch {
        if (controller.signal.aborted) return failure(timedOut ? "timeout" : "cancelled");
        return failure("network_error");
      }
      if (response.status >= 300 && response.status < 400) {
        await cancelBody(response);
        return failure("redirect_rejected", response.status);
      }
      const body = await readBounded(response, MAX_RESPONSE_BYTES, controller.signal);
      if (!body.ok) return failure(timedOut && body.kind === "cancelled" ? "timeout" : body.kind, response.status);
      let data;
      try {
        data = JSON.parse(body.text);
      } catch {
        return failure("invalid_response", response.status);
      }
      if (!response.ok) {
        const kind = classifyStatus(response.status, data, options.classifyInvalidSession);
        return failure(kind, response.status);
      }
      if (!isPlainObject(data)) return failure("invalid_response", response.status);
      return Object.freeze({ ok: true, data, status: response.status });
    } finally {
      if (timeout !== null) this._clearTimeout(timeout);
      if (external && abortListener) external.removeEventListener("abort", abortListener);
    }
  }
}

function tokenPair(data, status, requireRefresh) {
  if (!isPlainObject(data)) return failure("invalid_response", status);
  const access = normalizeBearerToken(data.access_token, "SSO access token");
  if (!access.ok) return failure("invalid_response", status);
  let refreshToken = null;
  if (Object.prototype.hasOwnProperty.call(data, "refresh_token") && data.refresh_token !== null) {
    const refresh = normalizeBearerToken(data.refresh_token, "SSO refresh token");
    if (!refresh.ok) return failure("invalid_response", status);
    refreshToken = refresh.value;
  }
  if (requireRefresh && !refreshToken) return failure("invalid_response", status);
  return Object.freeze({ ok: true, accessToken: access.value, refreshToken, status });
}

function validateIdPURL(value) {
  if (
    !value
    || Buffer.byteLength(value, "utf8") > MAX_IDP_URL_BYTES
    || CONTROL_CHARACTER_PATTERN.test(value)
  ) return null;
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password) return null;
    return parsed.toString();
  } catch {
    return null;
  }
}

function isValidWorkspace(value) {
  return typeof value === "string"
    && value !== "."
    && value !== ".."
    && Buffer.byteLength(value, "ascii") === value.length
    && value.length > 0
    && value.length <= MAX_WORKSPACE_BYTES
    && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value)
    && !CONTROL_CHARACTER_PATTERN.test(value);
}

function classifyStatus(status, data, classifyInvalidSession) {
  // The public protocol does not define a machine-readable revocation code.
  // Even a 401 here is not, by itself, enough evidence to erase an access
  // token: the ordinary authenticated API request must also reject that exact
  // credential generation before the session is cleared.
  if (classifyInvalidSession && [400, 401, 403].includes(status) && hasBoundedErrorShape(data)) {
    return "refresh_rejected";
  }
  if ([408, 425, 429].includes(status) || status >= 500) return "transient";
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  return "http_error";
}

function hasBoundedErrorShape(data) {
  if (!isPlainObject(data)) return false;
  return ["detail", "error", "message"].some(key => (
    Object.prototype.hasOwnProperty.call(data, key)
    && typeof data[key] === "string"
    && data[key].length > 0
    && data[key].length <= 1024
    && !CONTROL_CHARACTER_PATTERN.test(data[key])
  ));
}

async function readBounded(response, limit, signal) {
  const declared = response.headers && response.headers.get("content-length");
  if (declared && /^\d+$/.test(declared) && Number(declared) > limit) {
    await cancelBody(response);
    return failure("response_too_large");
  }
  if (!response.body || typeof response.body.getReader !== "function") return Object.freeze({ ok: true, text: "" });
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  let abortListener = null;
  const aborted = new Promise(resolve => {
    abortListener = () => {
      void Promise.resolve(reader.cancel()).catch(() => {});
      resolve({ aborted: true });
    };
    signal.addEventListener("abort", abortListener, { once: true });
    if (signal.aborted) abortListener();
  });
  try {
    while (true) {
      if (signal.aborted) return failure("cancelled");
      const item = await Promise.race([
        Promise.resolve(reader.read()).then(value => ({ value }), () => ({ readError: true })),
        aborted,
      ]);
      if (item.aborted || signal.aborted) return failure("cancelled");
      if (item.readError) return failure("network_error");
      const value = item.value;
      if (value.done) break;
      bytes += value.value.byteLength;
      if (bytes > limit) {
        await reader.cancel().catch(() => {});
        return failure("response_too_large");
      }
      chunks.push(Buffer.from(value.value));
    }
    try {
      return Object.freeze({
        ok: true,
        text: new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)),
      });
    } catch {
      return failure("invalid_response");
    }
  } catch {
    return failure(signal.aborted ? "cancelled" : "network_error");
  } finally {
    if (abortListener) signal.removeEventListener("abort", abortListener);
    try { reader.releaseLock(); } catch { /* already released */ }
  }
}

async function cancelBody(response) {
  try { await response.body?.cancel?.(); } catch { /* best effort */ }
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function failure(kind, status = null) {
  return Object.freeze({ ok: false, kind, status: Number.isInteger(status) ? status : null });
}

module.exports = {
  API_ORIGIN,
  CALLBACK_URL,
  SSOProtocolClient,
  isValidWorkspace,
  validateIdPURL,
};

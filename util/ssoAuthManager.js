const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");
const vscode = require("vscode");
const { createSSOCredential, normalizeAPIKey, normalizeBearerToken } = require("./credentialEnvelope");
const { SSOProtocolClient, isValidWorkspace } = require("./ssoProtocolClient");

const SAML_CALLBACK_PORT = 12400;
const MAX_CLI_CONFIG_BYTES = 64 * 1024;
const MAX_CALLBACK_TARGET_BYTES = 20 * 1024;
const MAX_CALLBACK_PAIRS = 8;
const CALLBACK_TIMEOUT_MS = 5 * 60 * 1000;
const RECOGNIZED_CALLBACK_FIELDS = new Set([
  "access_token",
  "refresh_token",
  "two_factor_token",
  "error",
]);

function failedResult(kind, message) {
  return Object.freeze({
    ok: false,
    status: kind === "stale" ? "stale" : "failed",
    committed: false,
    error: Object.freeze({ kind, message }),
  });
}

function unavailableResult() {
  return failedResult("unavailable", "Authentication is not ready. Reload the extension and try again.");
}

class SSOAuthManager {
  constructor(context, options = {}) {
    this.context = context;
    this._connectionManager = options.connectionManager || null;
    this._fs = options.fs || fs.promises;
    this._platform = options.platform || process.platform;
    this._env = options.env || process.env;
    this._home = options.home || os.homedir();
    this._findConfigPath = options.findCLIConfigPath || null;
    this._protocol = options.protocolClient || new SSOProtocolClient({
      fetchImpl: options.fetchImpl,
      setTimeout: options.setTimeout,
      clearTimeout: options.clearTimeout,
    });
    this._setTimeout = options.setTimeout || setTimeout;
    this._clearTimeout = options.clearTimeout || clearTimeout;
    this._createServer = options.createServer || http.createServer;
    this._serverFactoryInjected = Boolean(options.createServer);
    this._randomBytes = options.randomBytes || crypto.randomBytes;
    this._openExternal = options.openExternal || vscode.env.openExternal;
    this._showErrorMessage = options.showErrorMessage
      || vscode.window.showErrorMessage.bind(vscode.window);
    this._showInformationMessage = options.showInformationMessage
      || vscode.window.showInformationMessage.bind(vscode.window);
    this._showInputBox = options.showInputBox || vscode.window.showInputBox.bind(vscode.window);
  }

  async importFromCLI(operation = null) {
    const manager = this._getConnectionManager();
    if (!manager) return unavailableResult();
    const token = operation || manager.beginCredentialOperation();
    if (!manager.isOperationCurrent(token)) return failedResult("stale", "Authentication was superseded.");

    let candidates;
    try {
      if (this._findConfigPath) {
        const file = this._findConfigPath();
        candidates = file ? [{ root: path.dirname(file), file }] : [];
      } else {
        candidates = cliCredentialCandidates(this._platform, this._env, this._home);
      }
    } catch {
      candidates = [];
    }
    const found = [];
    for (const candidate of candidates) {
      let content;
      try {
        content = await readTrustedCredentialFile(candidate.root, candidate.file, this._fs);
      } catch (error) {
        if (error && error.code === "ENOENT") continue;
        if (manager.isOperationCurrent(token)) await manager.cancelCredentialOperation(token);
        const message = "Could not safely read Cloudsmith CLI credentials.ini.";
        this._showErrorMessage(message);
        return failedResult("config_read_failed", message);
      }
      if (!manager.isOperationCurrent(token)) return failedResult("stale", "Authentication was superseded.");
      const parsed = parseDefaultAPIKey(content);
      if (!parsed.ok) {
        await manager.cancelCredentialOperation(token);
        const message = "Cloudsmith CLI credentials.ini is ambiguous or malformed.";
        this._showErrorMessage(message);
        return failedResult("config_invalid", message);
      }
      if (parsed.apiKey) found.push(parsed.apiKey);
    }
    if (found.length !== 1) {
      await manager.cancelCredentialOperation(token);
      const message = found.length > 1
        ? "Multiple Cloudsmith CLI API keys were found. Choose one explicitly in the CLI first."
        : "No [default] API key was found in trusted Cloudsmith CLI credentials.ini files.";
      this._showErrorMessage(message);
      return failedResult(found.length > 1 ? "ambiguous_credentials" : "credential_missing", message);
    }
    return manager.replaceCredential(found[0], token);
  }

  async loginViaBrowser(workspaceSlug, operation = null) {
    const manager = this._getConnectionManager();
    if (!manager) return unavailableResult();
    const token = operation || manager.beginCredentialOperation();
    if (!this.isValidWorkspaceSlug(workspaceSlug)) {
      await manager.cancelCredentialOperation(token);
      return failedResult("invalid_workspace", "The Cloudsmith workspace slug is invalid.");
    }

    let callback = null;
    try {
      callback = await this._startCallbackServer(token.signal);
      if (!manager.isOperationCurrent(token)) return failedResult("stale", "Authentication was superseded.");
      const discovery = await this._protocol.discover(workspaceSlug, { signal: token.signal });
      if (!discovery.ok) throw publicFailure(discovery.kind);
      if (!manager.isOperationCurrent(token)) return failedResult("stale", "Authentication was superseded.");
      const listenerOutcome = callback.getSettledOutcome();
      if (listenerOutcome && ["cancelled", "timeout", "listener_failed"].includes(listenerOutcome.kind)) {
        throw publicFailure(listenerOutcome.kind);
      }

      const idpUri = vscode.Uri.parse(discovery.redirectUrl);
      let opened = false;
      try { opened = await this._openExternal(idpUri); } catch { opened = false; }
      if (opened === false) {
        const retry = await this._showErrorMessage(
          "Could not open the Cloudsmith identity provider in your browser.",
          "Retry",
          "Cancel"
        );
        if (!manager.isOperationCurrent(token)) return failedResult("stale", "Authentication was superseded.");
        if (retry !== "Retry") throw publicFailure("browser_open_failed", true);
        try { opened = await this._openExternal(idpUri); } catch { opened = false; }
        if (opened === false) throw publicFailure("browser_open_failed");
      }
      if (!manager.isOperationCurrent(token)) return failedResult("stale", "Authentication was superseded.");
      this._showInformationMessage("Cloudsmith browser sign-in started. Waiting for the callback...");

      const outcome = await callback.outcome;
      if (!manager.isOperationCurrent(token)) return failedResult("stale", "Authentication was superseded.");
      await callback.close();
      callback = null;
      if (outcome.kind === "error") throw publicFailure("identity_provider_error");
      if (["cancelled", "timeout", "listener_failed"].includes(outcome.kind)) {
        throw publicFailure(outcome.kind);
      }

      let accessToken;
      let refreshToken;
      if (outcome.kind === "two_factor") {
        const totp = await this._showInputBox({
          prompt: "Enter your Cloudsmith two-factor authentication code",
          password: true,
          ignoreFocusOut: true,
          validateInput: value => (/^[0-9]{6,10}$/.test(value || "") ? null : "Enter a valid code."),
        });
        if (!manager.isOperationCurrent(token)) return failedResult("stale", "Authentication was superseded.");
        if (!totp) return manager.cancelCredentialOperation(token);
        const exchange = await this._protocol.exchangeTwoFactor(outcome.twoFactorToken, totp, {
          signal: token.signal,
        });
        if (!exchange.ok || !exchange.refreshToken) throw publicFailure(exchange.kind || "two_factor_failed");
        accessToken = exchange.accessToken;
        refreshToken = exchange.refreshToken;
      } else if (outcome.kind === "tokens") {
        accessToken = outcome.accessToken;
        refreshToken = outcome.refreshToken;
      } else {
        throw publicFailure("invalid_callback");
      }

      const credential = createSSOCredential(accessToken, refreshToken);
      return manager.replaceCredential(credential, token, {
        workspaceSlug,
        beforeCommit: async identity => {
          const label = sanitizeDisplay(identity);
          if (!label) return false;
          const choice = await this._showInformationMessage(
            `Continue as ${label} for Cloudsmith workspace ${workspaceSlug}?`,
            { modal: true },
            "Continue"
          );
          return choice === "Continue";
        },
      });
    } catch (error) {
      if (manager.isOperationCurrent(token)) await manager.cancelCredentialOperation(token);
      const kind = error && error.kind ? error.kind : "browser_failed";
      const message = callbackErrorMessage(kind);
      if (!(error && error.reported)) this._showErrorMessage(message);
      return failedResult(kind, message);
    } finally {
      if (callback) await callback.close();
    }
  }

  async loginViaTerminal(_workspaceSlug, operation = null) {
    const manager = this._getConnectionManager();
    if (manager && operation && manager.isOperationCurrent(operation)) {
      await manager.cancelCredentialOperation(operation);
    }
    return failedResult(
      "unsupported_terminal_flow",
      "CLI SSO credentials remain in the CLI keyring and cannot be imported into VS Code."
    );
  }

  async _startCallbackServer(signal) {
    const sockets = new Set();
    let settle;
    let settled = false;
    let settledOutcome = null;
    let timeout = null;
    let closed = false;
    const outcome = new Promise(resolve => { settle = resolve; });
    const finish = (value) => {
      if (settled) return false;
      settled = true;
      settledOutcome = value;
      settle(value);
      return true;
    };
    const handler = (request, response) => this._handleCallbackRequest(request, response, finish);
    const server = this._serverFactoryInjected
      ? this._createServer(handler)
      : this._createServer({ maxHeaderSize: 16 * 1024 }, handler);
    server.headersTimeout = 5000;
    server.requestTimeout = 5000;
    server.keepAliveTimeout = 1000;
    server.maxRequestsPerSocket = 1;
    server.maxConnections = 8;
    server.on("connection", socket => {
      sockets.add(socket);
      socket.on("close", () => sockets.delete(socket));
    });
    const onAbort = () => finish({ kind: "cancelled" });
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();

    try {
      await new Promise((resolve, reject) => {
        const onError = (error) => {
          server.removeListener("listening", onListening);
          reject(publicFailure(error && error.code === "EADDRINUSE" ? "port_in_use" : "listener_failed"));
        };
        const onListening = () => {
          server.removeListener("error", onError);
          resolve();
        };
        server.once("error", onError);
        server.once("listening", onListening);
        server.listen(SAML_CALLBACK_PORT, "127.0.0.1");
      });
    } catch (error) {
      signal.removeEventListener("abort", onAbort);
      for (const socket of sockets) socket.destroy();
      try { server.close(); } catch { /* not listening */ }
      throw error;
    }
    const onRuntimeError = () => finish({ kind: "listener_failed" });
    server.on("error", onRuntimeError);
    timeout = this._setTimeout(() => finish({ kind: "timeout" }), CALLBACK_TIMEOUT_MS);
    const close = async () => {
      if (closed) return;
      closed = true;
      if (timeout !== null) this._clearTimeout(timeout);
      signal.removeEventListener("abort", onAbort);
      finish({ kind: "cancelled" });
      server.removeListener("error", onRuntimeError);
      server.closeIdleConnections?.();
      server.closeAllConnections?.();
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => {
        try { server.close(() => resolve()); } catch { resolve(); }
      });
      server.removeAllListeners("connection");
      server.removeAllListeners("error");
    };
    return Object.freeze({
      server,
      outcome,
      close,
      getSettledOutcome: () => settledOutcome,
    });
  }

  _handleCallbackRequest(request, response, finish) {
    const generic = (status, received = false, twoFactor = false) => {
      const nonce = this._randomBytes(18).toString("base64");
      response.writeHead(status, callbackHeaders(nonce));
      response.end(callbackHtml(nonce, received, twoFactor));
    };
    if (request.method !== "GET" || request.headers["transfer-encoding"] || Number(request.headers["content-length"] || 0) > 0) {
      generic(405);
      return;
    }
    if (typeof request.url !== "string" || Buffer.byteLength(request.url, "utf8") > MAX_CALLBACK_TARGET_BYTES || !request.url.startsWith("/")) {
      generic(400);
      return;
    }
    let parsed;
    try {
      parsed = new URL(request.url, "http://localhost");
    } catch {
      generic(400);
      return;
    }
    if (parsed.origin !== "http://localhost" || parsed.pathname !== "/" || parsed.hash) {
      generic(404);
      return;
    }
    const pairs = [...parsed.searchParams.entries()];
    if (pairs.length === 0 || pairs.length > MAX_CALLBACK_PAIRS || pairs.some(([name]) => !RECOGNIZED_CALLBACK_FIELDS.has(name))) {
      generic(400);
      return;
    }
    const values = Object.create(null);
    for (const [name, value] of pairs) {
      if (Object.prototype.hasOwnProperty.call(values, name) || !validCallbackValue(name, value)) {
        generic(400);
        return;
      }
      values[name] = value;
    }
    const has = name => Object.prototype.hasOwnProperty.call(values, name);
    if (has("error") && pairs.length === 1) {
      if (finish({ kind: "error" })) generic(200);
      else generic(409);
      return;
    }
    if (has("two_factor_token") && pairs.length === 1) {
      if (finish({ kind: "two_factor", twoFactorToken: values.two_factor_token })) generic(200, true, true);
      else generic(409);
      return;
    }
    if (has("access_token") && has("refresh_token") && pairs.length === 2) {
      if (finish({ kind: "tokens", accessToken: values.access_token, refreshToken: values.refresh_token })) generic(200, true);
      else generic(409);
      return;
    }
    generic(400);
  }

  isValidWorkspaceSlug(workspaceSlug) {
    return isValidWorkspace(workspaceSlug);
  }

  _getConnectionManager() {
    if (this._connectionManager) return this._connectionManager;
    const { getConnectionManager } = require("./connectionManager");
    return getConnectionManager(this.context);
  }
}

async function readTrustedCredentialFile(root, file, fileSystem) {
  const normalizedRoot = path.resolve(root);
  const normalizedFile = path.resolve(file);
  const relative = path.relative(normalizedRoot, normalizedFile);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) throw unsafeFile();
  const anchors = [];
  const rootStat = await fileSystem.lstat(normalizedRoot);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw unsafeFile();
  anchors.push({ target: normalizedRoot, stat: rootStat });
  let current = normalizedRoot;
  for (const part of relative.split(path.sep).slice(0, -1)) {
    current = path.join(current, part);
    const stat = await fileSystem.lstat(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw unsafeFile();
    anchors.push({ target: current, stat });
  }
  let handle;
  try {
    handle = await fileSystem.open(normalizedFile, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  } catch {
    throw unsafeFile();
  }
  try {
    const during = await handle.stat();
    const before = await fileSystem.lstat(normalizedFile);
    if (
      !during.isFile()
      || !before.isFile()
      || before.isSymbolicLink()
      || during.dev !== before.dev
      || during.ino !== before.ino
      || during.size > MAX_CLI_CONFIG_BYTES
    ) throw unsafeFile();
    const first = await readBoundedFileHandle(handle);
    const middle = await handle.stat();
    const second = await readBoundedFileHandle(handle);
    const after = await handle.stat();
    if (
      first.length > MAX_CLI_CONFIG_BYTES
      || !first.equals(second)
      || !sameFileStat(during, middle)
      || !sameFileStat(during, after)
    ) throw unsafeFile();
    for (const anchor of anchors) {
      const finalStat = await fileSystem.lstat(anchor.target);
      if (
        !finalStat.isDirectory()
        || finalStat.isSymbolicLink()
        || finalStat.dev !== anchor.stat.dev
        || finalStat.ino !== anchor.stat.ino
      ) throw unsafeFile();
    }
    const finalPathStat = await fileSystem.lstat(normalizedFile);
    if (
      !finalPathStat.isFile()
      || finalPathStat.isSymbolicLink()
      || !sameFileStat(during, finalPathStat)
    ) throw unsafeFile();
    return new TextDecoder("utf-8", { fatal: true }).decode(first);
  } finally {
    await handle.close();
  }
}

async function readBoundedFileHandle(handle) {
  const buffer = Buffer.alloc(MAX_CLI_CONFIG_BYTES + 1);
  let offset = 0;
  while (offset < buffer.length) {
    const result = await handle.read(buffer, offset, buffer.length - offset, offset);
    if (!result.bytesRead) break;
    offset += result.bytesRead;
  }
  return buffer.subarray(0, offset);
}

function sameFileStat(left, right) {
  return Boolean(
    left
    && right
    && left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs
  );
}

function cliCredentialCandidates(platform, env, home) {
  const platformPath = platform === "win32" ? path.win32 : path;
  const candidates = [];
  const add = (root) => {
    if (!root || !platformPath.isAbsolute(root)) return;
    const candidate = { root, file: platformPath.join(root, "cloudsmith", "credentials.ini") };
    if (!candidates.some(item => normalizedPath(item.file, platform) === normalizedPath(candidate.file, platform))) candidates.push(candidate);
  };
  if (platform === "darwin") add(platformPath.join(home, "Library", "Application Support"));
  else if (platform === "win32") add(env.APPDATA || home);
  else add(platformPath.isAbsolute(env.XDG_CONFIG_HOME || "") ? env.XDG_CONFIG_HOME : platformPath.join(home, ".config"));
  const legacyRoot = platformPath.join(home, ".cloudsmith");
  candidates.push({ root: legacyRoot, file: platformPath.join(legacyRoot, "credentials.ini") });
  return candidates;
}

function parseDefaultAPIKey(content) {
  if (typeof content !== "string" || Buffer.byteLength(content, "utf8") > MAX_CLI_CONFIG_BYTES) return { ok: false };
  const text = content.replace(/^\uFEFF/, "");
  let section = null;
  let defaultSeen = false;
  let apiKey = null;
  for (const rawLine of text.split(/\r?\n/)) {
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(rawLine)) return { ok: false };
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const header = line.match(/^\[([^\]]+)\]$/);
    if (header) {
      section = header[1];
      if (section === "default") {
        if (defaultSeen) return { ok: false };
        defaultSeen = true;
      }
      continue;
    }
    if (!section || !line.includes("=")) return { ok: false };
    if (section !== "default") continue;
    const index = line.indexOf("=");
    const key = line.slice(0, index).trim();
    let value = line.slice(index + 1).trim();
    if (key !== "api_key") continue;
    if (apiKey !== null) return { ok: false };
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    else if (value.startsWith('"') || value.endsWith('"') || value.startsWith("'") || value.endsWith("'")) return { ok: false };
    const normalized = normalizeAPIKey(value);
    if (!normalized.ok || normalized.value !== value) return { ok: false };
    apiKey = normalized.value;
  }
  return { ok: true, apiKey };
}

function validCallbackValue(name, value) {
  const max = name === "error" ? 1024 : 8192;
  if (!value || value.length > max || /[\u0000-\u001f\u007f]/.test(value)) return false;
  return name === "error" || normalizeBearerToken(value, name).ok;
}

function callbackHeaders(nonce) {
  return {
    "Cache-Control": "no-store, max-age=0",
    Pragma: "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Content-Type": "text/html; charset=utf-8",
    Connection: "close",
    "Content-Security-Policy": `default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; script-src 'nonce-${nonce}'`,
  };
}

function callbackHtml(nonce, received, twoFactor) {
  const heading = received ? "Sign-in received" : "Sign-in request not accepted";
  const detail = twoFactor
    ? "Return to VS Code to complete two-factor verification."
    : received
      ? "Return to VS Code while your session is verified."
      : "Return to VS Code and try again.";
  return `<!doctype html><html><head><meta charset="utf-8"><title>Cloudsmith sign-in</title></head><body><h1>${heading}</h1><p>${detail}</p><script nonce="${nonce}">history.replaceState(null,document.title,location.pathname)</script></body></html>`;
}

function callbackErrorMessage(kind) {
  const messages = {
    port_in_use: `Port ${SAML_CALLBACK_PORT} is already in use. Close the application using it and try again.`,
    browser_open_failed: "Could not open the Cloudsmith identity provider in your browser.",
    timeout: "Cloudsmith browser sign-in timed out.",
    identity_provider_error: "The identity provider did not complete Cloudsmith sign-in.",
    workspace_forbidden: "The authenticated account cannot access the requested Cloudsmith workspace.",
    listener_failed: "The local Cloudsmith sign-in listener stopped unexpectedly.",
  };
  return messages[kind] || "Cloudsmith browser sign-in could not be completed.";
}

function publicFailure(kind, reported = false) {
  const error = new Error("Cloudsmith browser sign-in failed.");
  error.kind = kind || "browser_failed";
  error.reported = Boolean(reported);
  return error;
}

function unsafeFile() {
  const error = new Error("Unsafe credentials file.");
  error.code = "UNSAFE_CREDENTIAL_FILE";
  return error;
}

function sanitizeDisplay(value) {
  return typeof value === "string" && value.length <= 256
    ? value.replace(/[\u0000-\u001f\u007f]/g, "").trim()
    : "";
}

function normalizedPath(value, platform) {
  const normalized = (platform === "win32" ? path.win32 : path).normalize(value);
  return platform === "win32" ? normalized.toLowerCase() : normalized;
}

module.exports = {
  SAML_CALLBACK_PORT,
  SSOAuthManager,
  cliCredentialCandidates,
  parseDefaultAPIKey,
  readTrustedCredentialFile,
};

const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");
const url = require("url");
const vscode = require("vscode");

const SAML_CALLBACK_PORT = 12400;
const CALLBACK_SUCCESS_PATH = "/authenticated";
const TOKEN_PARAM_NAMES = ["api_key", "token", "access_token", "key"];
const WORKSPACE_SLUG_PATTERN = /^[A-Za-z0-9._-]+$/;
const MAX_WORKSPACE_SLUG_LENGTH = 128;
const MAX_CLI_CONFIG_BYTES = 64 * 1024;

function configTooLargeError() {
  const error = new Error("Cloudsmith CLI configuration exceeds the supported size.");
  error.code = "CONFIG_TOO_LARGE";
  return error;
}

async function readBoundedTextFile(filePath) {
  const handle = await fs.promises.open(filePath, "r");
  try {
    const buffer = Buffer.alloc(MAX_CLI_CONFIG_BYTES + 1);
    let total = 0;
    while (total < buffer.length) {
      const { bytesRead } = await handle.read(buffer, total, buffer.length - total, total);
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    if (total > MAX_CLI_CONFIG_BYTES) throw configTooLargeError();
    return buffer.subarray(0, total).toString("utf8");
  } finally {
    await handle.close();
  }
}

function readBoundedTextFileSync(filePath) {
  const descriptor = fs.openSync(filePath, "r");
  try {
    const buffer = Buffer.alloc(MAX_CLI_CONFIG_BYTES + 1);
    let total = 0;
    while (total < buffer.length) {
      const bytesRead = fs.readSync(descriptor, buffer, total, buffer.length - total, total);
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    if (total > MAX_CLI_CONFIG_BYTES) throw configTooLargeError();
    return buffer.subarray(0, total).toString("utf8");
  } finally {
    fs.closeSync(descriptor);
  }
}

function failedResult(kind, message) {
  return Object.freeze({
    ok: false,
    status: "failed",
    committed: false,
    error: Object.freeze({ kind, message }),
  });
}

function unavailableResult() {
  return failedResult(
    "unavailable",
    "Authentication is not ready. Reload the extension and try again."
  );
}

class SSOAuthManager {
  constructor(context, options = {}) {
    this.context = context;
    this._connectionManager = options.connectionManager || null;
    this._readFile = options.readFile
      ? async filePath => {
        const content = await options.readFile(filePath, "utf8");
        if (Buffer.byteLength(content, "utf8") > MAX_CLI_CONFIG_BYTES) throw configTooLargeError();
        return content;
      }
      : readBoundedTextFile;
    this._readFileSync = options.readFileSync
      ? filePath => {
        const content = options.readFileSync(filePath, "utf8");
        if (Buffer.byteLength(content, "utf8") > MAX_CLI_CONFIG_BYTES) throw configTooLargeError();
        return content;
      }
      : readBoundedTextFileSync;
    this._accessSync = options.accessSync || fs.accessSync;
    this._findConfigPath = options.findCLIConfigPath || null;
    this._setTimeout = options.setTimeout || setTimeout;
    this._clearTimeout = options.clearTimeout || clearTimeout;
    this._createServer = options.createServer || http.createServer;
    this._randomBytes = options.randomBytes || crypto.randomBytes;
    this._openExternal = options.openExternal || vscode.env.openExternal;
    this._showErrorMessage = options.showErrorMessage
      || vscode.window.showErrorMessage.bind(vscode.window);
    this._showInformationMessage = options.showInformationMessage
      || vscode.window.showInformationMessage.bind(vscode.window);
    this._showWarningMessage = options.showWarningMessage
      || vscode.window.showWarningMessage.bind(vscode.window);
    this._createTerminal = options.createTerminal
      || vscode.window.createTerminal.bind(vscode.window);
    this._onDidCloseTerminal = options.onDidCloseTerminal
      || vscode.window.onDidCloseTerminal.bind(vscode.window);
  }

  async importFromCLI(operation = null) {
    const manager = this._getConnectionManager();
    if (!manager) return unavailableResult();
    const token = operation || manager.beginCredentialOperation();
    if (!manager.isOperationCurrent(token)) return failedResult("stale", "Authentication was superseded.");

    const configPath = this._findCLIConfigPath();
    if (!configPath) {
      await manager.cancelCredentialOperation(token);
      this._showErrorMessage(
        'Could not find Cloudsmith CLI configuration. Run "cloudsmith auth" in a terminal first.'
      );
      return failedResult("config_missing", "Cloudsmith CLI configuration was not found.");
    }

    let content;
    try {
      content = await this._readFile(configPath);
    } catch (error) {
      await manager.cancelCredentialOperation(token);
      const tooLarge = error && error.code === "CONFIG_TOO_LARGE";
      const publicMessage = tooLarge
        ? "Cloudsmith CLI config is too large to import."
        : "Could not read Cloudsmith CLI config. Check file permissions.";
      this._showErrorMessage(publicMessage);
      return failedResult(
        tooLarge ? "config_too_large" : "config_read_failed",
        publicMessage
      );
    }
    if (!manager.isOperationCurrent(token)) return failedResult("stale", "Authentication was superseded.");

    const apiKey = this._parseAPIKeyFromConfig(content);
    if (!apiKey) {
      await manager.cancelCredentialOperation(token);
      this._showErrorMessage(
        "No API key found in Cloudsmith CLI config. Run 'cloudsmith auth -o {workspace}' first."
      );
      return failedResult("credential_missing", "No API key was found in the CLI configuration.");
    }

    return manager.replaceCredential(apiKey, token);
  }

  hasCLICredentials() {
    const configPath = this._findCLIConfigPath();
    if (!configPath) return false;
    try {
      const content = this._readFileSync(configPath, "utf8");
      return Boolean(this._parseAPIKeyFromConfig(content));
    } catch {
      return false;
    }
  }

  _findCLIConfigPath() {
    if (this._findConfigPath) return this._findConfigPath();
    const home = os.homedir();
    const candidates = [
      path.join(home, ".cloudsmith", "config.ini"),
      path.join(process.env.XDG_CONFIG_HOME || path.join(home, ".config"), "cloudsmith", "config.ini"),
    ];
    if (process.platform === "darwin") {
      candidates.push(path.join(home, "Library", "Application Support", "cloudsmith", "config.ini"));
    }
    if (process.platform === "win32" && process.env.APPDATA) {
      candidates.push(path.join(process.env.APPDATA, "cloudsmith", "config.ini"));
    }
    for (const candidate of candidates) {
      try {
        this._accessSync(candidate, fs.constants.R_OK);
        return candidate;
      } catch {
        // Try the next platform-specific location.
      }
    }
    return null;
  }

  _parseAPIKeyFromConfig(content) {
    if (typeof content !== "string") return null;
    if (Buffer.byteLength(content, "utf8") > MAX_CLI_CONFIG_BYTES) return null;
    for (const line of content.split("\n")) {
      const match = line.trim().match(/^api_key\s*=\s*(.+)$/);
      if (match) {
        const key = match[1].trim();
        if (key) return key;
      }
    }
    return null;
  }

  async loginViaTerminal(workspaceSlug, operation = null) {
    const manager = this._getConnectionManager();
    if (!manager) return unavailableResult();
    const token = operation || manager.beginCredentialOperation();
    if (!this._isValidWorkspaceSlug(workspaceSlug)) {
      await manager.cancelCredentialOperation(token);
      this._showErrorMessage("Enter a valid Cloudsmith workspace slug.");
      return failedResult("invalid_workspace", "The Cloudsmith workspace slug is invalid.");
    }

    let terminal = null;
    let closeDisposable = null;
    let timeout = null;
    let abortListener = null;
    try {
      terminal = this._createTerminal("Cloudsmith SSO");
      terminal.show();
      terminal.sendText(`cloudsmith auth -o ${workspaceSlug}`);
      await new Promise((resolve) => {
        let done = false;
        const finish = () => {
          if (done) return;
          done = true;
          resolve();
        };
        closeDisposable = this._onDidCloseTerminal((closed) => {
          if (closed === terminal) finish();
        });
        timeout = this._setTimeout(finish, 10000);
        abortListener = finish;
        token.signal.addEventListener("abort", abortListener, { once: true });
        if (token.signal.aborted) finish();
      });

      if (!manager.isOperationCurrent(token)) {
        return failedResult("stale", "Authentication was superseded.");
      }
      const choice = await this._showInformationMessage(
        "Import credentials from the Cloudsmith CLI config?",
        "Import",
        "Not now"
      );
      if (!manager.isOperationCurrent(token)) {
        return failedResult("stale", "Authentication was superseded.");
      }
      if (choice === "Import") return this.importFromCLI(token);
      return manager.cancelCredentialOperation(token);
    } catch {
      if (manager.isOperationCurrent(token)) await manager.cancelCredentialOperation(token);
      return failedResult(
        "terminal_failed",
        "Could not start Cloudsmith CLI authentication."
      );
    } finally {
      if (timeout !== null) this._clearTimeout(timeout);
      if (closeDisposable && typeof closeDisposable.dispose === "function") closeDisposable.dispose();
      if (abortListener) token.signal.removeEventListener("abort", abortListener);
    }
  }

  async loginViaBrowser(workspaceSlug, operation = null) {
    const manager = this._getConnectionManager();
    if (!manager) return unavailableResult();
    const token = operation || manager.beginCredentialOperation();
    if (!this._isValidWorkspaceSlug(workspaceSlug)) {
      await manager.cancelCredentialOperation(token);
      this._showErrorMessage("Enter a valid Cloudsmith workspace slug.");
      return failedResult("invalid_workspace", "The Cloudsmith workspace slug is invalid.");
    }

    const callbackId = this._randomBytes(16).toString("hex");
    const callbackPath = `/callback/${callbackId}`;
    let server = null;
    try {
      const serverResult = await this._startCallbackServer(callbackPath);
      server = serverResult.server;
      if (!manager.isOperationCurrent(token)) return failedResult("stale", "Authentication was superseded.");

      const redirectUrl = `http://127.0.0.1:${SAML_CALLBACK_PORT}${callbackPath}`;
      const authUrl =
        `https://api.cloudsmith.io/orgs/${encodeURIComponent(workspaceSlug)}/saml/` +
        `?redirect_url=${encodeURIComponent(redirectUrl)}`;
      const tokenPromise = this._waitForCallbackToken(server, token.signal);
      await this._openExternal(vscode.Uri.parse(authUrl));
      if (!manager.isOperationCurrent(token)) return failedResult("stale", "Authentication was superseded.");
      this._showInformationMessage("Browser sign-in started. Waiting for authentication...");

      const candidate = await tokenPromise;
      if (!manager.isOperationCurrent(token)) return failedResult("stale", "Authentication was superseded.");
      if (candidate) return manager.replaceCredential(candidate, token);

      const choice = await this._showWarningMessage(
        "Browser-based SSO did not complete. Select a fallback method.",
        "Open Terminal",
        "Import from CLI",
        "Dismiss"
      );
      if (!manager.isOperationCurrent(token)) return failedResult("stale", "Authentication was superseded.");
      if (choice === "Open Terminal") return this.loginViaTerminal(workspaceSlug, token);
      if (choice === "Import from CLI") return this.importFromCLI(token);
      return manager.cancelCredentialOperation(token);
    } catch {
      if (manager.isOperationCurrent(token)) await manager.cancelCredentialOperation(token);
      const message = "Browser authentication could not start or complete.";
      this._showErrorMessage(
        `Could not complete browser SSO on port ${SAML_CALLBACK_PORT}. ${message}`
      );
      return failedResult("browser_failed", message);
    } finally {
      if (server) this._shutdownServer(server);
    }
  }

  _waitForCallbackToken(server, signal) {
    return new Promise((resolve) => {
      let settled = false;
      const finish = (candidate) => {
        if (settled) return;
        settled = true;
        if (server._timeout !== null) this._clearTimeout(server._timeout);
        server._timeout = null;
        signal.removeEventListener("abort", onAbort);
        server._resolveToken = null;
        resolve(candidate);
      };
      const onAbort = () => finish(null);
      server._resolveToken = finish;
      server._timeout = this._setTimeout(() => finish(null), 5 * 60 * 1000);
      signal.addEventListener("abort", onAbort, { once: true });
      if (signal.aborted) onAbort();
    });
  }

  _startCallbackServer(expectedPath) {
    return new Promise((resolve, reject) => {
      const server = this._createServer((req, res) => this._handleCallbackRequest(req, res, server));
      server._expectedPath = expectedPath;
      server._timeout = null;
      const onError = (error) => {
        const message = error.code === "EADDRINUSE"
          ? `Port ${SAML_CALLBACK_PORT} is already in use`
          : "Failed to start the callback server";
        reject(new Error(message));
      };
      server.once("error", onError);
      server.listen(SAML_CALLBACK_PORT, "127.0.0.1", () => {
        server.removeListener("error", onError);
        server.on("error", () => {
          if (server._resolveToken) server._resolveToken(null);
          this._shutdownServer(server);
        });
        resolve({ server, port: SAML_CALLBACK_PORT });
      });
    });
  }

  _handleCallbackRequest(req, res, server) {
    const parsed = url.parse(req.url, true);
    const params = parsed.query || {};
    const pathName = parsed.pathname || "/";
    if (req.method !== "GET") {
      res.writeHead(405, { "Content-Type": "text/plain" });
      res.end("Method Not Allowed");
      return;
    }
    if (pathName !== server._expectedPath) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not Found");
      return;
    }

    let token = null;
    for (const name of TOKEN_PARAM_NAMES) {
      if (typeof params[name] === "string" && params[name]) {
        token = params[name];
        break;
      }
    }
    if (server._resolveToken) server._resolveToken(token);
    if (token) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(this._buildCallbackHtml(true, CALLBACK_SUCCESS_PATH));
      return;
    }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(this._buildCallbackHtml(false));
  }

  _shutdownServer(server) {
    if (typeof server._resolveToken === "function") {
      server._resolveToken(null);
    } else if (server._timeout !== null) {
      this._clearTimeout(server._timeout);
      server._timeout = null;
    }
    server._resolveToken = null;
    try {
      server.close();
    } catch {
      // The server may already be closed.
    }
  }

  _isValidWorkspaceSlug(workspaceSlug) {
    return typeof workspaceSlug === "string"
      && workspaceSlug.length > 0
      && workspaceSlug.length <= MAX_WORKSPACE_SLUG_LENGTH
      && WORKSPACE_SLUG_PATTERN.test(workspaceSlug);
  }

  _buildCallbackHtml(success, replacePath) {
    const heading = success ? "\u2705 Credentials received" : "\u274C Credentials not received";
    const message = success
      ? "Return to VS Code while the credentials are validated and saved."
      : "No credentials were found in the redirect. Try the terminal flow or CLI import.";
    const script = replacePath
      ? `<script>if (window.history && window.history.replaceState) { window.history.replaceState(null, "", "${replacePath}"); }</script>`
      : "";
    return "<html><body style=\"font-family:sans-serif;text-align:center;padding:40px\">" +
      `<h2>${heading}</h2><p>${message}</p>${script}</body></html>`;
  }

  _getConnectionManager() {
    if (this._connectionManager) return this._connectionManager;
    const { getConnectionManager } = require("./connectionManager");
    return getConnectionManager(this.context);
  }
}

module.exports = { SSOAuthManager };

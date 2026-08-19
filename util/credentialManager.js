const vscode = require("vscode");

const AUTH_TOKEN_KEY = "cloudsmith-vsc.authToken";

function unavailableResult() {
  return Object.freeze({
    ok: false,
    status: "unavailable",
    committed: false,
    error: Object.freeze({
      kind: "unavailable",
      message: "Authentication is not ready. Reload the extension and try again.",
    }),
  });
}

async function runCLIAutoDetect(options) {
  const {
    connectionManager,
    secrets,
    ssoManager,
    showInformationMessage,
    handleAuthenticationResult,
  } = options;
  const stableState = connectionManager.getState();
  if (
    stableState.status !== "absent"
    || stableState.credentialPresent !== false
    || stableState.sessionConnected
  ) {
    return Object.freeze({ ok: false, status: "not_applicable" });
  }

  const operation = connectionManager.beginCredentialOperation();
  let currentKey;
  try {
    currentKey = await secrets.get(AUTH_TOKEN_KEY);
  } catch {
    if (connectionManager.isOperationCurrent(operation)) {
      await connectionManager.cancelCredentialOperation(operation);
    }
    return Object.freeze({
      ok: false,
      status: "failed",
      committed: false,
      error: Object.freeze({
        kind: "credential_read_failed",
        message: "Could not check stored Cloudsmith credentials. Try again.",
      }),
    });
  }
  if (!connectionManager.isOperationCurrent(operation)) {
    return Object.freeze({ ok: false, status: "stale" });
  }
  if (currentKey) {
    return connectionManager.initialize();
  }
  if (ssoManager.hasCLICredentials()) {
    const choice = await showInformationMessage(
      "Cloudsmith CLI credentials detected. Import them?",
      "Import",
      "Dismiss"
    );
    if (!connectionManager.isOperationCurrent(operation)) {
      return Object.freeze({ ok: false, status: "stale" });
    }
    if (choice === "Import") {
      const result = await ssoManager.importFromCLI(operation);
      await handleAuthenticationResult(result);
      return result;
    }
  }
  return connectionManager.cancelCredentialOperation(operation);
}

class CredentialManager {
  constructor(context, options = {}) {
    this.context = context;
    this._connectionManager = options.connectionManager || null;
    this._showInputBox = options.showInputBox || vscode.window.showInputBox;
    this._showWarningMessage = options.showWarningMessage || vscode.window.showWarningMessage;
  }

  async getApiKey() {
    const apiKey = await this.context.secrets.get(AUTH_TOKEN_KEY);
    return typeof apiKey === "string" && apiKey ? apiKey : null;
  }

  async storeApiKey(operation = null, options = {}) {
    const manager = this._getConnectionManager();
    if (!manager) return unavailableResult();

    const token = operation || manager.beginCredentialOperation();
    if (!manager.isOperationCurrent(token)) {
      return Object.freeze({ ok: false, status: "stale", committed: false, state: manager.getState() });
    }
    let apiKey;
    const CancellationTokenSource = options?.CancellationTokenSource
      || vscode.CancellationTokenSource;
    const inputCancellation = typeof CancellationTokenSource === "function"
      ? new CancellationTokenSource()
      : null;
    const operationSubscription = typeof manager.onDidChange === "function"
      ? manager.onDidChange(() => {
        if (!manager.isOperationCurrent(token)) inputCancellation?.cancel();
      })
      : null;
    try {
      const showInputBox = typeof options?.showInputBox === "function"
        ? options.showInputBox
        : this._showInputBox;
      apiKey = await showInputBox({
        prompt: "Enter a Cloudsmith API key",
        password: true,
        ignoreFocusOut: true,
      }, inputCancellation?.token);
    } catch {
      if (!manager.isOperationCurrent(token)) {
        return Object.freeze({
          ok: false,
          status: "stale",
          committed: false,
          state: manager.getState(),
        });
      }
      await manager.cancelCredentialOperation(token);
      return Object.freeze({
        ok: false,
        status: "failed",
        committed: false,
        error: Object.freeze({
          kind: "input_failed",
          message: "Could not read the API key. Try again.",
        }),
      });
    } finally {
      operationSubscription?.dispose?.();
      inputCancellation?.dispose?.();
    }

    if (typeof apiKey !== "string") {
      return manager.cancelCredentialOperation(token);
    }
    return manager.replaceCredential(apiKey, token);
  }

  async saveApiKey(apiKey, operation = null) {
    const manager = this._getConnectionManager();
    if (!manager) return unavailableResult();
    return manager.replaceCredential(apiKey, operation || manager.beginCredentialOperation());
  }

  async clearCredentials(operation = null) {
    const manager = this._getConnectionManager();
    if (!manager) return unavailableResult();

    const token = operation || manager.beginCredentialOperation();
    if (!manager.isOperationCurrent(token)) {
      return Object.freeze({ ok: false, status: "stale", committed: false, state: manager.getState() });
    }
    const state = manager.getState();
    if (state.credentialPresent === false) {
      await manager.cancelCredentialOperation(token);
      await this._showWarningMessage("No credentials found.");
      return Object.freeze({ ok: false, status: "absent", committed: false, state: manager.getState() });
    }

    let selection;
    try {
      selection = await this._showWarningMessage(
        "Delete the stored API key?",
        { modal: true },
        "Delete"
      );
    } catch {
      await manager.cancelCredentialOperation(token);
      return Object.freeze({
        ok: false,
        status: "failed",
        committed: false,
        error: Object.freeze({
          kind: "confirmation_failed",
          message: "Could not confirm credential deletion. Try again.",
        }),
      });
    }

    if (selection !== "Delete") {
      return manager.cancelCredentialOperation(token);
    }
    return manager.disconnect(token);
  }

  _getConnectionManager() {
    if (this._connectionManager) return this._connectionManager;
    // Lazy loading avoids a circular dependency while preserving fail-closed lookup.
    const { getConnectionManager } = require("./connectionManager");
    return getConnectionManager(this.context);
  }
}

module.exports = { AUTH_TOKEN_KEY, CredentialManager, runCLIAutoDetect };

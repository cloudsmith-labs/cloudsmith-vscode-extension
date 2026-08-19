// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { registerCommands } = require("./registrar");

function registerAuthenticationCommands(deps) {
  const {
    registerCommand,
    vscode,
    connectionManager,
    credentialManager,
    ssoManager,
    handleAuthenticationResult,
  } = deps;

  async function showCredentialPrompt(operation, method, ...args) {
    if (!connectionManager.isOperationCurrent(operation)) return null;
    const cancellation = typeof vscode.CancellationTokenSource === "function"
      ? new vscode.CancellationTokenSource()
      : null;
    const subscription = connectionManager.onDidChange?.(() => {
      if (!connectionManager.isOperationCurrent(operation)) cancellation?.cancel();
    }) || null;
    try {
      const result = method === "showInputBox"
        ? await vscode.window.showInputBox(args[0], cancellation?.token)
        : await vscode.window.showQuickPick(args[0], args[1], cancellation?.token);
      return connectionManager.isOperationCurrent(operation) ? (result || null) : null;
    } finally {
      subscription?.dispose?.();
      cancellation?.dispose?.();
    }
  }

  async function clearCredentials() {
    const result = await credentialManager.clearCredentials();
    await handleAuthenticationResult(result, { offerDefault: false });
  }

  async function ssoLogin(suppliedOperation = null) {
    const operation = suppliedOperation || connectionManager.beginCredentialOperation();
    if (!connectionManager.isOperationCurrent(operation)) return;
    const workspaceInput = await showCredentialPrompt(operation, "showInputBox", {
      placeHolder: "my-org",
      prompt: "Enter the Cloudsmith workspace slug for SSO",
      ignoreFocusOut: true,
      validateInput: value => (
        typeof value === "string"
        && typeof ssoManager.isValidWorkspaceSlug === "function"
        && !ssoManager.isValidWorkspaceSlug(value.trim())
          ? "Enter a valid Cloudsmith workspace slug."
          : null
      ),
    });
    const workspaceSlug = typeof workspaceInput === "string"
      ? workspaceInput.trim()
      : "";
    if (!workspaceSlug) {
      await connectionManager.cancelCredentialOperation(operation);
      return;
    }
    if (!connectionManager.isOperationCurrent(operation)) return;
    const useExperimental = vscode.workspace
      .getConfiguration("cloudsmith-vsc")
      .get("experimentalSSOBrowser");
    const result = useExperimental
      ? await ssoManager.loginViaBrowser(workspaceSlug.trim(), operation)
      : await ssoManager.loginViaTerminal(workspaceSlug.trim(), operation);
    await handleAuthenticationResult(result);
  }

  async function importCLICredentials(suppliedOperation = null) {
    const operation = suppliedOperation || connectionManager.beginCredentialOperation();
    if (!connectionManager.isOperationCurrent(operation)) return;
    const result = await ssoManager.importFromCLI(operation);
    await handleAuthenticationResult(result);
  }

  async function configureCredentials() {
    const operation = connectionManager.beginCredentialOperation();
    const selected = await showCredentialPrompt(operation, "showQuickPick", [
      { label: "$(key) Enter API key", description: "Paste a personal API key", method: "apikey" },
      { label: "$(server) Enter service account API key", description: "Paste a service account API key", method: "apikey" },
      { label: "$(folder-opened) Import from Cloudsmith CLI", description: "Import credentials from CLI config (~/.cloudsmith/config.ini)", method: "import" },
      { label: "$(terminal) Sign in with SSO", description: "Run 'cloudsmith auth' in an integrated terminal", method: "sso-terminal" },
    ], { placeHolder: "Select an authentication method" });
    if (!selected) {
      await connectionManager.cancelCredentialOperation(operation);
      return;
    }
    if (!connectionManager.isOperationCurrent(operation)) return;
    if (selected.method === "sso-terminal") {
      await ssoLogin(operation);
    } else if (selected.method === "import") {
      await importCLICredentials(operation);
    } else {
      const result = await credentialManager.storeApiKey(operation, {
        showInputBox: options => showCredentialPrompt(
          operation,
          "showInputBox",
          options
        ),
      });
      await handleAuthenticationResult(result);
    }
  }

  async function connectCloudsmith() {
    const result = await connectionManager.initialize();
    await handleAuthenticationResult(result);
  }

  return registerCommands(registerCommand, [
    ["cloudsmith-vsc.clearCredentials", clearCredentials],
    ["cloudsmith-vsc.configureCredentials", configureCredentials],
    ["cloudsmith-vsc.connectCloudsmith", connectCloudsmith],
    ["cloudsmith-vsc.ssoLogin", ssoLogin],
    ["cloudsmith-vsc.importCLICredentials", importCLICredentials],
  ], deps);
}

module.exports = { registerAuthenticationCommands };

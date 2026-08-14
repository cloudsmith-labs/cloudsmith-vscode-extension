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

  async function clearCredentials() {
    const result = await credentialManager.clearCredentials();
    await handleAuthenticationResult(result, { offerDefault: false });
  }

  async function ssoLogin(suppliedOperation = null) {
    const operation = suppliedOperation || connectionManager.beginCredentialOperation();
    if (!connectionManager.isOperationCurrent(operation)) return;
    const workspaceSlug = await vscode.window.showInputBox({
      placeHolder: "my-org",
      prompt: "Enter the Cloudsmith workspace slug for SSO",
      ignoreFocusOut: true,
    });
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
    const selected = await vscode.window.showQuickPick([
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
      const result = await credentialManager.storeApiKey(operation);
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

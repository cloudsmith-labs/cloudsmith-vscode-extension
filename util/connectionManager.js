// This class handles the connection to Cloudsmith.
// A connection session is not actually running since we are just making API calls adhoc when needed. 
// This mostly just handles verification and if connection can be made. 

const vscode = require("vscode");
const { CredentialManager } = require("./credentialManager");
const { formatApiError } = require("./errorFormatter");

class ConnectionManager {
  constructor(context) {
    this.context = context;
  }

  // Check response to API for authentication - basic workflow for now
  async checkConnectivity(apiKey) {
    const { CloudsmithAPI } = require("./cloudsmithAPI");
    let checkPassed = "false";
    const cloudsmithAPI = new CloudsmithAPI(this.context);
    const result = await cloudsmithAPI.get("user/self", {
      apiKey,
      responseType: "object",
      validate: value => typeof value.authenticated === "boolean",
      retry: "never",
    });

    if (!result.ok || !result.data.authenticated) {
      this._lastError = result.ok ? null : result.error;
      if (!result.ok) {
        checkPassed = "error";
      } else {
        checkPassed = "false";
      }
      await this.context.secrets.store("cloudsmith-vsc.isConnected", checkPassed);
      await vscode.commands.executeCommand("setContext", "cloudsmith.connected", false);
    } else {
      checkPassed = "true";
      await this.context.secrets.store("cloudsmith-vsc.isConnected", checkPassed);
      await vscode.commands.executeCommand("setContext", "cloudsmith.connected", true);
    }

    return checkPassed;
  }

  // Check if currently connected 
  async isConnected() {
    const isConnected = await this.context.secrets.get("cloudsmith-vsc.isConnected");
    return isConnected

  }

  // Connect to Cloudsmith
  async connect(options = {}) {
    const context = this.context;
    const { promptOnMissingCredentials = true } = options;
    let showConnectMsg = true; // controls whether to show connected notification. Used for refresh.
    let currentConnectionStatus = await this.isConnected();
    let connectionStatus = "";

    const credentialManager = new CredentialManager(context);
    const apiKey = await credentialManager.getApiKey();

    checkCreds: if (!apiKey) {
      await vscode.commands.executeCommand("setContext", "cloudsmith.connected", false);
      if (promptOnMissingCredentials) {
        vscode.window
          .showWarningMessage("No credentials configured!", "Configure", "Cancel")
          .then((selection) => {
            select: if (selection === "Configure") {
              vscode.commands.executeCommand("cloudsmith-vsc.configureCredentials");
              break select;
            }
          });
      }
      return "false";
    } else {
      connectionStatus = await this.checkConnectivity(apiKey);

      if (currentConnectionStatus === connectionStatus) { //if current = new status, no need to show notification
        showConnectMsg = false;
      }

      if (connectionStatus === "false" || connectionStatus === "error") {
        const errorMsg = this._lastError
          ? formatApiError(this._lastError)
          : "Could not connect to Cloudsmith. Check the credentials and try again.";
        vscode.window
          .showErrorMessage(
            errorMsg,
            "Configure",
            "Cancel"
          )
          .then((selection) => {
            select: if (selection === "Configure") {
              vscode.commands.executeCommand("cloudsmith-vsc.configureCredentials");
              break select;
            }
          });
        return connectionStatus;
      } else { // connection status = true
        if (showConnectMsg) {
          vscode.window.showInformationMessage("Connected to Cloudsmith.");
        }
        // checkConnectivity() already stored "cloudsmith-vsc.isConnected"
      }
      return connectionStatus;
    }

  }
}

module.exports = { ConnectionManager };

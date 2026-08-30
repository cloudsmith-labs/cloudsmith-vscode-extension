// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { registerCommands } = require("./registrar");
const {
  captureCommandAccount,
  isCommandAccountCurrent,
  resolveCommandWorkspace,
} = require("./support");

function registerSettingsHelpCommands(deps) {
  const {
    registerCommand,
    vscode,
    treeView,
    cloudsmithProvider,
    helpLinks,
    openExternalWithFeedback,
  } = deps;

  async function setDefaultWorkspace() {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return;
    const selected = await resolveCommandWorkspace(deps, account, {
      allowClear: true,
      forcePrompt: true,
      ignoreDefault: true,
      placeHolder: "Select a default workspace",
    });
    if (!isCommandAccountCurrent(account)) return;
    if (!selected) return;

    const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
    if (selected.clear) {
      if (!isCommandAccountCurrent(account)) return;
      await config.update("defaultWorkspace", "", vscode.ConfigurationTarget.Global);
      if (!isCommandAccountCurrent(account)) return;
      await deps.updateDefaultWorkspaceContext();
      if (!isCommandAccountCurrent(account)) return;
      treeView.title = "Workspaces";
      treeView.description = "";
    } else {
      if (!isCommandAccountCurrent(account)) return;
      await config.update(
        "defaultWorkspace",
        selected.slug,
        vscode.ConfigurationTarget.Global
      );
      if (!isCommandAccountCurrent(account)) return;
      await deps.updateDefaultWorkspaceContext();
      if (!isCommandAccountCurrent(account)) return;
      treeView.title = "Repositories";
      treeView.description = selected.slug;
    }
    if (!isCommandAccountCurrent(account)) return;
    cloudsmithProvider.refresh();
  }

  function openSettings() {
    return vscode.commands.executeCommand(
      "workbench.action.openSettings",
      "@ext:Cloudsmith.cloudsmith-vsc"
    );
  }

  async function openHelpLink(linkId, failureMessage = "Could not open this help link.") {
    const documentation = Array.isArray(helpLinks)
      ? helpLinks.find(link => link?.id === linkId)
      : null;
    if (!documentation || typeof documentation.url !== "string") {
      await vscode.window.showWarningMessage(failureMessage);
      return false;
    }
    return openExternalWithFeedback({
      target: vscode.Uri.parse(documentation.url),
      openExternal: target => vscode.env.openExternal(target),
      showWarningMessage: message => vscode.window.showWarningMessage(message),
      failureMessage,
    });
  }

  function openDocumentation(linkId = "extensionDocs") {
    const failureMessage = linkId === "extensionDocs"
      ? "Could not open the extension documentation."
      : "Could not open this help link.";
    return openHelpLink(linkId, failureMessage);
  }

  return registerCommands(registerCommand, [
    ["cloudsmith-vsc.setDefaultWorkspace", setDefaultWorkspace],
    ["cloudsmith-vsc.openSettings", openSettings],
    ["cloudsmith-vscode-extension.cloudsmithDocs", openDocumentation],
  ], deps);
}

module.exports = { registerSettingsHelpCommands };

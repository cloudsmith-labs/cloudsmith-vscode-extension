// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { registerCommands } = require("./registrar");
const { captureCommandAccount, getWorkspaces } = require("./support");

function registerSettingsHelpCommands(deps) {
  const { registerCommand, vscode, treeView, cloudsmithProvider } = deps;

  async function setDefaultWorkspace() {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return;
    const workspaces = await getWorkspaces(deps.workspaceAccess);
    if (!account.isCurrent()) return;
    if (!workspaces) return;
    if (workspaces.items.length === 0) {
      if (workspaces.complete) {
        vscode.window.showErrorMessage("No workspaces found. Connect to Cloudsmith first.");
      }
      return;
    }

    const items = [
      { label: "$(close) Clear default workspace", description: "Show all workspaces", clear: true },
    ];
    if (!workspaces.complete) {
      items.push({ label: "Workspace list incomplete", kind: vscode.QuickPickItemKind.Separator });
    }
    for (const workspace of workspaces.items) {
      items.push({ label: workspace.name, description: workspace.slug, clear: false });
    }

    const selected = await vscode.window.showQuickPick(items, {
      placeHolder: "Select a default workspace",
    });
    if (!account.isCurrent()) return;
    if (!selected) return;

    const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
    if (selected.clear) {
      if (!account.isCurrent()) return;
      await config.update("defaultWorkspace", "", vscode.ConfigurationTarget.Global);
      if (!account.isCurrent()) return;
      await deps.updateDefaultWorkspaceContext();
      if (!account.isCurrent()) return;
      treeView.title = "Workspaces";
      treeView.description = "";
    } else {
      if (!account.isCurrent()) return;
      await config.update(
        "defaultWorkspace",
        selected.description,
        vscode.ConfigurationTarget.Global
      );
      if (!account.isCurrent()) return;
      await deps.updateDefaultWorkspaceContext();
      if (!account.isCurrent()) return;
      treeView.title = "Repositories";
      treeView.description = selected.description;
    }
    if (!account.isCurrent()) return;
    cloudsmithProvider.refresh();
  }

  function openSettings() {
    return vscode.commands.executeCommand(
      "workbench.action.openSettings",
      "@ext:Cloudsmith.cloudsmith-vsc"
    );
  }

  function openDocumentation() {
    return vscode.env.openExternal(vscode.Uri.parse("https://docs.cloudsmith.com/"));
  }

  return registerCommands(registerCommand, [
    ["cloudsmith-vsc.setDefaultWorkspace", setDefaultWorkspace],
    ["cloudsmith-vsc.openSettings", openSettings],
    ["cloudsmith-vscode-extension.cloudsmithDocs", openDocumentation],
  ], deps);
}

module.exports = { registerSettingsHelpCommands };

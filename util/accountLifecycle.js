// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const recentPackages = require("./recentPackages");
const filterState = require("./filterState");
const { clearVulnerabilityCache } = require("./dependencyVulnEnricher");

function createAuthenticationResultHandler(deps) {
  const {
    vscode,
    connectionManager,
    treeView,
    cloudsmithProvider,
    updateDefaultWorkspaceContext,
    getDefaultWorkspace,
    getWorkspaces,
    captureAccount,
    isAccountCurrent,
  } = deps;
  return async function handleAuthenticationResult(result, options = {}) {
    if (
      !result
      || result.status === "stale"
      || result.status === "cancelled"
      || result.error?.kind === "stale"
    ) {
      return result;
    }
    const state = connectionManager.getState();
    if (result.partial && result.committed) {
      const outcome = state.credentialPresent === false
        ? "Credentials were cleared"
        : "Credentials were saved and validated";
      const detail = result.error && result.error.message ? ` ${result.error.message}` : "";
      vscode.window.showWarningMessage(
        `${outcome}, but the connection indicator could not be updated.${detail}`
      );
      return result;
    }
    if (!result.ok || !state.sessionConnected) {
      if (result.committed && state.credentialPresent === false) {
        vscode.window.showInformationMessage("Credentials cleared.");
      } else if (options.reportFailure !== false && result.error && result.error.message) {
        if (state.sessionConnected) {
          vscode.window.showWarningMessage(result.error.message);
        } else {
          vscode.window.showErrorMessage(result.error.message);
        }
      }
      return result;
    }
    if (options.showSuccess !== false) {
      vscode.window.showInformationMessage("Connected to Cloudsmith.");
    }
    if (options.offerDefault !== false && !getDefaultWorkspace()) {
      const account = captureAccount(connectionManager);
      if (!account || !isAccountCurrent(connectionManager, account)) return result;
      const workspaces = await getWorkspaces();
      if (!isAccountCurrent(connectionManager, account)) return result;
      if (workspaces && workspaces.complete && workspaces.items.length === 1) {
        const workspace = workspaces.items[0];
        const choice = await vscode.window.showInformationMessage(
          `One workspace available: ${workspace.name}. Set as default?`,
          "Set as default",
          "Dismiss"
        );
        if (!isAccountCurrent(connectionManager, account)) return result;
        if (choice === "Set as default") {
          // Another operation may have verified or selected a default while
          // this prompt was open. Never overwrite that newer decision.
          if (getDefaultWorkspace()) return result;
          if (!isAccountCurrent(connectionManager, account)) return result;
          await vscode.workspace.getConfiguration("cloudsmith-vsc").update(
            "defaultWorkspace",
            workspace.slug,
            vscode.ConfigurationTarget.Global
          );
          if (!isAccountCurrent(connectionManager, account)) return result;
          await updateDefaultWorkspaceContext();
          if (!isAccountCurrent(connectionManager, account)) return result;
          treeView.title = "Repositories";
          treeView.description = workspace.slug;
          cloudsmithProvider.refresh();
        }
      }
    }
    return result;
  };
}

function beginAccountScopedStateReset(options = {}) {
  const invalidators = [
    () => options.workspaceCache?.clear?.(),
    () => options.searchProvider?.clear?.(),
    () => (options.filterState || filterState).clear(),
    () => (options.recentPackages || recentPackages).clear(),
    () => (options.clearVulnerabilityCache || clearVulnerabilityCache)(),
    () => options.vulnerabilityStateService?.clear?.(),
    () => options.vulnerabilityProvider?.resetForAccountChange?.(),
    () => options.quarantineExplainProvider?.resetForAccountChange?.(),
    () => options.upstreamPreviewProvider?.resetForAccountChange?.(),
    () => options.upstreamDetailProvider?.resetForAccountChange?.(),
    () => options.promotionProvider?.resetForAccountChange?.(),
  ];
  const syncFailures = [];
  for (const invalidate of invalidators) {
    try {
      invalidate();
    } catch (error) {
      syncFailures.push(error);
    }
  }
  return Object.freeze({ syncFailures });
}

async function completeAccountScopedStateReset(context, options, reset) {
  const invalidators = [
    () => options.dependencyHealthProvider?.resetForAccountChange?.(options.accountState),
    () => options.projectHasMultipleWorkspaces?.(false),
  ];
  const pending = invalidators.map(invalidate => {
    try {
      return Promise.resolve(invalidate());
    } catch (error) {
      return Promise.reject(error);
    }
  });
  const asyncResults = await Promise.allSettled(pending);
  try {
    options.cloudsmithProvider?.completeAccountReset?.(options.accountState);
  } catch (error) {
    reset.syncFailures.push(error);
  }
  return Object.freeze({
    syncFailures: Object.freeze([...reset.syncFailures]),
    asyncResults: Object.freeze(asyncResults),
  });
}

module.exports = {
  beginAccountScopedStateReset,
  completeAccountScopedStateReset,
  createAuthenticationResultHandler,
};

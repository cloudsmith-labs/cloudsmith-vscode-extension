// Copyright 2026 Cloudsmith Ltd. All rights reserved.

function firstCollectionFailureMessage(result, formatApiError) {
  const error = result && result.failures && result.failures[0] && result.failures[0].error;
  return error ? ` ${formatApiError(error)}` : "";
}

async function getWorkspaces(deps) {
  const {
    context,
    connectionManager,
    workspaceContextProjector,
    captureAccount,
    isAccountCurrent,
    createCloudsmithAPI,
    fetchWorkspaces,
    normalizedWorkspaceName,
    replaceCollectionItems,
    setHasMultipleWorkspacesContext,
    formatApiError,
    vscode,
  } = deps;
  const account = captureAccount(connectionManager);
  if (!account) {
    await setHasMultipleWorkspacesContext(false);
    return null;
  }
  const projection = workspaceContextProjector.begin({
    isCurrent: () => isAccountCurrent(connectionManager, account),
  });
  const result = await fetchWorkspaces(context, {
    account,
    cloudsmithAPI: createCloudsmithAPI(),
    connectionManager,
    retry: "safe-read",
  });
  if (!isAccountCurrent(connectionManager, account)) {
    await workspaceContextProjector.project(true, { operation: projection });
    return null;
  }
  const workspaces = result.items.map(workspace => ({
    ...workspace,
    name: normalizedWorkspaceName(workspace),
  }));
  const normalizedResult = replaceCollectionItems(result, workspaces);
  await workspaceContextProjector.project(
    !normalizedResult.complete || workspaces.length > 1,
    { operation: projection }
  );
  if (!isAccountCurrent(connectionManager, account)) {
    await workspaceContextProjector.project(true, { operation: projection });
    return null;
  }
  if (!normalizedResult.complete) {
    const detail = firstCollectionFailureMessage(normalizedResult, formatApiError);
    if (workspaces.length === 0) {
      vscode.window.showErrorMessage(`Failed to load workspaces completely.${detail}`);
    } else {
      vscode.window.showWarningMessage(
        `Workspace choices are incomplete; later workspaces may be unavailable.${detail}`
      );
    }
  }
  return normalizedResult;
}

async function getWorkspaceRepositories(deps, workspace, options = {}) {
  const account = deps.captureAccount(deps.connectionManager);
  if (!account) return null;
  const result = await deps.fetchWorkspaceRepositories(deps.context, workspace, {
    account,
    connectionManager: deps.connectionManager,
    retry: "safe-read",
    ...options,
  });
  if (
    result?.stale
    || !deps.isAccountCurrent(deps.connectionManager, account)
  ) {
    return null;
  }
  if (!result.complete) {
    const detail = firstCollectionFailureMessage(result, deps.formatApiError);
    if (result.items.length === 0) {
      deps.vscode.window.showErrorMessage(`Could not load repositories completely.${detail}`);
    } else {
      deps.vscode.window.showWarningMessage(
        `Repository choices are incomplete; later repositories may be unavailable.${detail}`
      );
    }
  }
  return result;
}

module.exports = {
  firstCollectionFailureMessage,
  getWorkspaces,
  getWorkspaceRepositories,
};

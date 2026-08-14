// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { aggregateDisposables, registerCommands } = require("./registrar");
const {
  captureCommandAccount,
  collectionQuickPickItems,
  getDefaultWorkspace,
  getWorkspaces,
  getWorkspaceRepositories,
} = require("./support");

function registerUpstreamCommands(deps) {
  const {
    registerCommand,
    vscode,
    context,
    upstreamDetailProvider,
    upstreamPreviewProvider,
    CloudsmithAPI,
    apiEndpoint,
    fetchRepositoryUpstreams,
    generateTerraformConfig,
    UpstreamChecker,
    FORMAT_OPTIONS,
    packageAdapters,
    packageDomain,
  } = deps;
  let exportAbortController = null;
  const cancellation = Object.freeze({
    dispose() {
      if (exportAbortController) {
        exportAbortController.abort();
        exportAbortController = null;
      }
    },
  });

  async function inspectUpstreams(item) {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return;
    let repository;
    try {
      repository = packageAdapters.fromRepositoryNode(item);
    } catch {
      vscode.window.showWarningMessage(item ? "Could not determine repository details." : "No repository selected.");
      return;
    }
    if (!account.isCurrent()) return;
    await upstreamDetailProvider.show(
      repository.workspace,
      repository.repository,
      repository.name
    );
  }

  async function preferredDocumentLanguage() {
    const languages = new Set(await vscode.languages.getLanguages());
    if (languages.has("terraform")) return "terraform";
    if (languages.has("hcl")) return "hcl";
    return "plaintext";
  }

  async function exportTerraform(item) {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return;
    let repository;
    try {
      repository = packageAdapters.fromRepositoryNode(item);
    } catch {
      vscode.window.showWarningMessage(item ? "Could not determine repository details." : "No repository selected.");
      return;
    }
    if (!account.isCurrent()) return;
    if (exportAbortController) exportAbortController.abort();
    const abortController = new AbortController();
    exportAbortController = abortController;
    const cloudsmithAPI = new CloudsmithAPI(context);
    let repoEndpoint;
    let retentionEndpoint;
    try {
      repoEndpoint = apiEndpoint(["repos", repository.workspace, repository.repository]);
      retentionEndpoint = apiEndpoint([
        "repos",
        repository.workspace,
        repository.repository,
        "retention",
      ]);
    } catch {
      if (exportAbortController === abortController) exportAbortController = null;
      if (account.isCurrent()) {
        vscode.window.showErrorMessage(
          "Could not export the repository because its identity was invalid."
        );
      }
      return;
    }

    if (!account.isCurrent()) return;
    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: "Generating Terraform configuration...",
      cancellable: true,
    }, async (_progress, token) => {
      const subscription = token.onCancellationRequested(() => abortController.abort());
      try {
        const [repoResult, retentionResult, upstreamResult] = await Promise.all([
          cloudsmithAPI.get(repoEndpoint, {
            responseType: "object",
            validate: value => Boolean(value) && typeof value === "object" && !Array.isArray(value),
            retry: "safe-read",
            signal: abortController.signal,
          }),
          cloudsmithAPI.get(retentionEndpoint, {
            responseType: "object",
            validate: value => Boolean(value) && typeof value === "object" && !Array.isArray(value),
            retry: "safe-read",
            signal: abortController.signal,
          }),
          fetchRepositoryUpstreams(
            context,
            repository.workspace,
            repository.repository,
            { signal: abortController.signal }
          ),
        ]);
        if (!account.isCurrent()) {
          abortController.abort();
          return;
        }
        if (abortController.signal.aborted || upstreamResult === null) return;
        if (!repoResult.ok) {
          if (repoResult.error.kind === "cancelled") return;
          vscode.window.showErrorMessage(
            `Could not export repository. ${deps.formatApiError(repoResult.error)}`
          );
          return;
        }
        const upstreamLoadFailed = Boolean(
          upstreamResult.error
          && (!Array.isArray(upstreamResult.data) || upstreamResult.data.length === 0)
        );
        const unavailableFormats = [...new Set([
          ...(upstreamResult.failedFormats || []),
          ...(upstreamResult.uninspectedFormats || []),
        ])];
        const content = generateTerraformConfig({
          repo: repoResult.data,
          workspace: repository.workspace,
          upstreams: Array.isArray(upstreamResult.data) ? upstreamResult.data : [],
          retention: retentionResult.ok ? retentionResult.data : null,
          exportedAt: new Date().toISOString(),
          upstreamLoadFailed,
          upstreamLoadPartial: upstreamResult.complete !== true,
          upstreamFailedFormats: unavailableFormats,
        });
        const language = await preferredDocumentLanguage();
        if (!account.isCurrent() || abortController.signal.aborted) return;
        const document = await vscode.workspace.openTextDocument({
          content,
          language,
        });
        if (!account.isCurrent() || abortController.signal.aborted) return;
        await vscode.window.showTextDocument(document);
      } catch {
        if (!abortController.signal.aborted && account.isCurrent()) {
          vscode.window.showErrorMessage(
            "Could not export repository because an unexpected error occurred."
          );
        }
      } finally {
        subscription.dispose();
        if (exportAbortController === abortController) exportAbortController = null;
      }
    });
  }

  async function previewUpstreamResolution(item) {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return;
    let packageName;
    let packageFormat;
    if (
      item
      && typeof item.name === "string"
      && item.name
      && typeof item.format === "string"
      && item.format
    ) {
      packageName = item.name;
      packageFormat = item.format;
    } else {
      packageName = await vscode.window.showInputBox({
        placeHolder: "flask",
        prompt: "Enter the package name",
      });
      if (!account.isCurrent()) return;
      if (!packageName) return;
      const formatPick = await vscode.window.showQuickPick(
        FORMAT_OPTIONS.map(format => ({ label: format })),
        { placeHolder: "Select a package format" }
      );
      if (!account.isCurrent()) return;
      if (!formatPick) return;
      packageFormat = formatPick.label;
    }

    let workspace = getDefaultWorkspace(vscode);
    if (!workspace) {
      const workspaces = await getWorkspaces(deps.workspaceAccess);
      if (!account.isCurrent()) return;
      if (!workspaces) return;
      if (workspaces.items.length === 0) {
        if (workspaces.complete) vscode.window.showErrorMessage("No workspaces found.");
        return;
      }
      const selected = await vscode.window.showQuickPick(
        collectionQuickPickItems(
          vscode,
          workspaces,
          entry => ({ label: entry.name, description: entry.slug }),
          "Workspace list incomplete"
        ),
        { placeHolder: "Select a workspace" }
      );
      if (!account.isCurrent()) return;
      if (!selected) return;
      workspace = selected.description;
    }
    const repositories = await getWorkspaceRepositories(deps.workspaceAccess, workspace);
    if (!account.isCurrent()) return;
    if (!repositories) return;
    if (repositories.items.length === 0) {
      if (repositories.complete) vscode.window.showErrorMessage("No repositories found.");
      return;
    }
    const selectedRepo = await vscode.window.showQuickPick(
      collectionQuickPickItems(
        vscode,
        repositories,
        entry => ({ label: entry.name, description: entry.slug }),
        "Repository list incomplete"
      ),
      { placeHolder: "Select target repository" }
    );
    if (!account.isCurrent()) return;
    if (!selectedRepo) return;
    let resolution;
    try {
      resolution = packageDomain.createPackageResolutionInput({
        workspace,
        repository: selectedRepo.description,
        name: packageName,
        format: packageFormat,
      });
    } catch {
      vscode.window.showWarningMessage("Could not determine package details.");
      return;
    }
    const checker = new UpstreamChecker(context);
    if (!account.isCurrent()) return;
    const result = await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: "Checking upstream resolution...",
    }, () => checker.previewResolution(
      resolution.workspace,
      resolution.repository,
      resolution.name,
      resolution.format
    ));
    if (!account.isCurrent()) return;
    if (result) upstreamPreviewProvider.show(result);
  }

  let commands;
  try {
    commands = registerCommands(registerCommand, [
      ["cloudsmith-vsc.inspectUpstreams", inspectUpstreams],
      ["cloudsmith-vsc.exportTerraform", exportTerraform],
      ["cloudsmith-vsc.previewUpstreamResolution", previewUpstreamResolution],
    ], deps);
  } catch (error) {
    cancellation.dispose();
    throw error;
  }
  return aggregateDisposables([cancellation, commands], deps);
}

module.exports = { registerUpstreamCommands };

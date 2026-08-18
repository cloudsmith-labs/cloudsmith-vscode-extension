// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { aggregateDisposables, registerCommands } = require("./registrar");
const {
  captureCommandAccount,
  isCommandAccountCurrent,
  resolveCommandRepository,
  resolveCommandWorkspace,
  showAccountInputBox,
  showAccountQuickPick,
} = require("./support");

const MAX_PACKAGE_NAME_LENGTH = 2048;
const DEPENDENCY_PREVIEW_CONTEXTS = new Set([
  "dependencyHealthMissing",
  "dependencyHealthUpstreamReachable",
  "dependencyHealthUpstreamUnreachable",
]);

function validPackageName(value) {
  return typeof value === "string"
    && value.trim().length > 0
    && value.length <= MAX_PACKAGE_NAME_LENGTH
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function registerUpstreamCommands(deps) {
  const {
    registerCommand,
    vscode,
    context,
    upstreamDetailProvider,
    upstreamPreviewProvider,
    CloudsmithAPI,
    apiEndpoint,
    upstreamPreview,
    upstreamExport,
    generateTerraformConfig,
    FORMAT_OPTIONS,
    packageAdapters,
    packageDomain,
    dependencyHealthProvider,
  } = deps;
  if (!upstreamPreview || typeof upstreamPreview.previewResolution !== "function") {
    throw new TypeError("Upstream commands require an upstream preview facade.");
  }
  if (
    !upstreamExport
    || typeof upstreamExport.getPrivilegedRepositoryUpstreamsForExport !== "function"
  ) {
    throw new TypeError("Upstream commands require an upstream export facade.");
  }
  let exportAbortController = null;
  let previewOperation = null;
  let previewOperationId = 0;
  const cancellation = Object.freeze({
    dispose() {
      if (exportAbortController) {
        exportAbortController.abort();
        exportAbortController = null;
      }
      if (previewOperation) {
        previewOperation.controller.abort();
        previewOperation = null;
      }
      previewOperationId += 1;
    },
  });

  function beginPreviewOperation(account) {
    previewOperation?.controller.abort();
    const operation = Object.freeze({
      id: ++previewOperationId,
      account,
      controller: new AbortController(),
    });
    previewOperation = operation;
    return operation;
  }

  function isPreviewCurrent(operation) {
    return Boolean(
      previewOperation === operation
      && operation.id === previewOperationId
      && !operation.controller.signal.aborted
      && operation.account.isCurrent()
    );
  }

  async function inspectUpstreams(item) {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return;
    if (item && deps.isCurrentRepositorySelection?.(item) !== true) return;
    const repository = await resolveCommandRepository(deps, account, {
      explicitItem: item || null,
      currentSelection: candidate => deps.isCurrentRepositorySelection?.(candidate) === true,
      invalidMessage: "Could not determine repository details.",
      placeHolder: "Select a repository to inspect",
    });
    if (!isCommandAccountCurrent(account) || !repository) return;
    await upstreamDetailProvider.show(
      repository.workspace,
      repository.slug,
      repository.name,
      { account: account.account }
    );
    if (!isCommandAccountCurrent(account)) return;
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
    if (item && deps.isCurrentRepositorySelection?.(item) !== true) return;
    const repository = await resolveCommandRepository(deps, account, {
      explicitItem: item || null,
      currentSelection: candidate => deps.isCurrentRepositorySelection?.(candidate) === true,
      invalidMessage: "Could not determine repository details.",
      placeHolder: "Select a repository to export",
    });
    if (!isCommandAccountCurrent(account) || !repository) return;
    if (exportAbortController) exportAbortController.abort();
    const abortController = new AbortController();
    exportAbortController = abortController;
    const cloudsmithAPI = new CloudsmithAPI(context);
    let repoEndpoint;
    let retentionEndpoint;
    try {
      repoEndpoint = apiEndpoint(["repos", repository.workspace, repository.slug]);
      retentionEndpoint = apiEndpoint([
        "repos",
        repository.workspace,
        repository.slug,
        "retention",
      ]);
    } catch {
      if (exportAbortController === abortController) exportAbortController = null;
      if (isCommandAccountCurrent(account)) {
        vscode.window.showErrorMessage(
          "Could not export the repository because its identity was invalid."
        );
      }
      return;
    }

    if (!isCommandAccountCurrent(account)) {
      abortController.abort();
      if (exportAbortController === abortController) exportAbortController = null;
      return;
    }
    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: "Generating Terraform configuration...",
      cancellable: true,
    }, async (_progress, token) => {
      const subscription = typeof token?.onCancellationRequested === "function"
        ? token.onCancellationRequested(() => abortController.abort())
        : { dispose() {} };
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
          upstreamExport.getPrivilegedRepositoryUpstreamsForExport(
            repository.workspace,
            repository.slug,
            { account: account.account, signal: abortController.signal }
          ),
        ]);
        if (!isCommandAccountCurrent(account)) {
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
        if (!retentionResult.ok) {
          if (retentionResult.error.kind === "cancelled") return;
          vscode.window.showErrorMessage(
            `Could not export repository retention settings. ${deps.formatApiError(retentionResult.error)}`
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
          retention: retentionResult.data,
          exportedAt: new Date().toISOString(),
          upstreamLoadFailed,
          upstreamLoadPartial: upstreamResult.complete !== true,
          upstreamFailedFormats: unavailableFormats,
        });
        const language = await preferredDocumentLanguage();
        if (!isCommandAccountCurrent(account) || abortController.signal.aborted) return;
        const document = await vscode.workspace.openTextDocument({
          content,
          language,
        });
        if (!isCommandAccountCurrent(account) || abortController.signal.aborted) return;
        await vscode.window.showTextDocument(document);
      } catch {
        if (!abortController.signal.aborted && isCommandAccountCurrent(account)) {
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
    const operation = beginPreviewOperation(account);
    try {
      let packageName;
      let packageFormat;
      let scanScope = null;
      if (item) {
        if (deps.isCurrentDependencySelection?.(item) !== true) return;
        let contextValue;
        try {
          contextValue = item?.getTreeItem?.().contextValue;
        } catch {
          return;
        }
        if (!DEPENDENCY_PREVIEW_CONTEXTS.has(contextValue)) return;
        if (!validPackageName(item.name) || !FORMAT_OPTIONS.includes(item.format)) {
          vscode.window.showWarningMessage("Could not determine package details.");
          return;
        }
        packageName = item.name;
        packageFormat = item.format;
        scanScope = dependencyHealthProvider?.getLastSuccessfulScope?.() || null;
        if (!scanScope || typeof scanScope.workspace !== "string") {
          vscode.window.showInformationMessage(
            "Run a successful dependency scan before previewing this dependency."
          );
          return;
        }
        try {
          const coordinate = packageAdapters.fromDependencyHealthNode(item, {
            workspace: scanScope.workspace,
            repository: scanScope.repository,
          });
          packageName = coordinate.name;
          packageFormat = coordinate.format;
        } catch {
          vscode.window.showWarningMessage("Could not determine package details.");
          return;
        }
      } else {
        packageName = await showAccountInputBox(deps, account, {
          placeHolder: "flask",
          prompt: "Enter the package name",
          validateInput(value) {
            if (value.length > MAX_PACKAGE_NAME_LENGTH) {
              return `Package names must be ${MAX_PACKAGE_NAME_LENGTH} characters or fewer.`;
            }
            if (/[\u0000-\u001f\u007f]/.test(value)) {
              return "Package names cannot contain control characters.";
            }
            return null;
          },
        });
        if (!isPreviewCurrent(operation)) return;
        if (!validPackageName(packageName)) return;
        const formatItems = FORMAT_OPTIONS.map(format => ({ label: format, format }));
        const formatPick = await showAccountQuickPick(
          deps,
          account,
          formatItems,
          { placeHolder: "Select a package format" }
        );
        if (!isPreviewCurrent(operation)) return;
        if (!formatPick || !formatItems.includes(formatPick)) return;
        packageFormat = formatPick.format;
      }
      const isSourceCurrent = () => {
        if (!isPreviewCurrent(operation)) return false;
        if (!item) return true;
        if (deps.isCurrentDependencySelection?.(item) !== true) return false;
        const currentScope = dependencyHealthProvider?.getLastSuccessfulScope?.();
        return Boolean(
          currentScope
          && currentScope.workspace === scanScope.workspace
          && (currentScope.repository || null) === (scanScope.repository || null)
        );
      };
      if (!validPackageName(packageName) || !FORMAT_OPTIONS.includes(packageFormat)) {
        vscode.window.showWarningMessage("Could not determine package details.");
        return;
      }

      let workspace;
      let repository;
      if (scanScope) {
        workspace = scanScope.workspace;
        repository = scanScope.repository || null;
        if (!repository) {
          const selectedRepository = await resolveCommandRepository(deps, account, {
            workspace: { slug: workspace, name: workspace },
            placeHolder: "Select target repository",
          });
          if (!isSourceCurrent() || !selectedRepository) return;
          repository = selectedRepository.slug;
        }
      } else {
        const selectedWorkspace = await resolveCommandWorkspace(deps, account, {
          placeHolder: "Select a workspace",
        });
        if (!isSourceCurrent() || !selectedWorkspace) return;
        workspace = selectedWorkspace.slug;
        const selectedRepository = await resolveCommandRepository(deps, account, {
          workspace: selectedWorkspace,
          placeHolder: "Select target repository",
        });
        if (!isSourceCurrent() || !selectedRepository) return;
        repository = selectedRepository.slug;
      }
      let resolution;
      try {
        resolution = packageDomain.createPackageResolutionInput({
          workspace,
          repository,
          name: packageName,
          format: packageFormat,
        });
      } catch {
        vscode.window.showWarningMessage("Could not determine package details.");
        return;
      }
      if (!isSourceCurrent()) return;
      const result = await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Checking upstream resolution...",
        cancellable: true,
      }, async (_progress, token) => {
        const subscription = typeof token?.onCancellationRequested === "function"
          ? token.onCancellationRequested(() => operation.controller.abort())
          : { dispose() {} };
        try {
          return await upstreamPreview.previewResolution(
            resolution.workspace,
            resolution.repository,
            resolution.name,
            resolution.format,
            { account: account.account, signal: operation.controller.signal }
          );
        } finally {
          subscription.dispose();
        }
      });
      if (!isSourceCurrent()) return;
      if (result) upstreamPreviewProvider.show(result);
    } finally {
      operation.controller.abort();
      if (previewOperation === operation) previewOperation = null;
    }
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

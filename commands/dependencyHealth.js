// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { aggregateDisposables, registerCommands } = require("./registrar");
const { runDependencyScan } = require("../util/dependencyScanOrchestration");
const {
  captureCommandAccount,
  isCommandAccountCurrent,
  resolveCommandRepository,
  resolveCommandWorkspace,
  showAccountQuickPick,
} = require("./support");

function createDependencyPickerItem(label, description, action, value, active) {
  return {
    label: `${active ? "$(check)" : "$(circle-large-outline)"} ${label}`,
    description,
    action,
    value,
  };
}

function buildDependencySortFilterItems(vscode, provider, filterModes, sortModes) {
  const currentSort = provider.getSortMode();
  const currentFilter = provider.getFilterMode();
  return [
    { label: "Sort", kind: vscode.QuickPickItemKind.Separator },
    createDependencyPickerItem(
      "Alphabetical", "Default ordering", "sort", sortModes.ALPHABETICAL,
      currentSort === sortModes.ALPHABETICAL
    ),
    createDependencyPickerItem(
      "Severity", "Most severe first", "sort", sortModes.SEVERITY,
      currentSort === sortModes.SEVERITY
    ),
    createDependencyPickerItem(
      "Coverage", "Not found first", "sort", sortModes.COVERAGE,
      currentSort === sortModes.COVERAGE
    ),
    { label: "Filters", kind: vscode.QuickPickItemKind.Separator },
    createDependencyPickerItem(
      "Vulnerable only", "Toggle vulnerable dependencies", "filter", filterModes.VULNERABLE,
      currentFilter === filterModes.VULNERABLE
    ),
    createDependencyPickerItem(
      "Not in Cloudsmith", "Toggle uncovered dependencies", "filter", filterModes.UNCOVERED,
      currentFilter === filterModes.UNCOVERED
    ),
    createDependencyPickerItem(
      "Restrictive licenses", "Toggle restrictive or weak copyleft results", "filter",
      filterModes.RESTRICTIVE_LICENSE,
      currentFilter === filterModes.RESTRICTIVE_LICENSE
    ),
    createDependencyPickerItem(
      "Policy violations", "Toggle policy failures", "filter", filterModes.POLICY_VIOLATION,
      currentFilter === filterModes.POLICY_VIOLATION
    ),
    createDependencyPickerItem(
      "Show all dependencies", "Clear active dependency filters", "filter", null,
      currentFilter === null
    ),
  ];
}

async function showDependencySortFilterPicker(
  deps,
  activePickers,
  account,
  isApplicable
) {
  const { vscode, dependencyHealthProvider, FILTER_MODES, SORT_MODES } = deps;
  if (!account?.isCurrent() || !isApplicable()) return;
  await new Promise(resolve => {
    const quickPick = vscode.window.createQuickPick();
    const disposables = [];
    let closed = false;
    const close = (hide) => {
      if (closed) return;
      closed = true;
      activePickers.delete(session);
      if (hide) {
        try {
          quickPick.hide();
        } catch {
          // Continue disposing transient resources.
        }
      }
      for (const disposable of disposables.splice(0).reverse()) {
        try {
          disposable.dispose();
        } catch {
          // Transient picker cleanup remains best-effort.
        }
      }
      try {
        quickPick.dispose();
      } catch {
        // The picker may already have been disposed by VS Code.
      }
      resolve();
    };
    const session = Object.freeze({ dispose: () => close(true) });
    activePickers.add(session);
    const refreshItems = () => {
      quickPick.items = buildDependencySortFilterItems(
        vscode,
        dependencyHealthProvider,
        FILTER_MODES,
        SORT_MODES
      );
    };

    quickPick.title = "Sort & filter dependencies";
    quickPick.matchOnDescription = true;
    quickPick.ignoreFocusOut = true;
    refreshItems();
    disposables.push(quickPick.onDidAccept(async () => {
      if (closed || !account.isCurrent() || !isApplicable()) {
        close(true);
        return;
      }
      const selected = quickPick.selectedItems[0];
      if (!selected || !selected.action) {
        quickPick.hide();
        return;
      }
      quickPick.busy = true;
      try {
        if (!account.isCurrent() || !isApplicable()) {
          close(true);
          return;
        }
        if (selected.action === "sort") {
          dependencyHealthProvider.setSortMode(selected.value);
        } else if (
          selected.value === null
          || dependencyHealthProvider.getFilterMode() === selected.value
        ) {
          await dependencyHealthProvider.clearFilter();
        } else {
          await dependencyHealthProvider.setFilterMode(selected.value);
        }
        if (closed || !account.isCurrent() || !isApplicable()) {
          close(true);
          return;
        }
        refreshItems();
      } finally {
        if (!closed) quickPick.busy = false;
      }
    }));
    disposables.push(quickPick.onDidHide(() => close(false)));
    if (typeof deps.workspaceAccess?.connectionManager?.onDidChange === "function") {
      disposables.push(deps.workspaceAccess.connectionManager.onDidChange(() => {
        if (!account.isCurrent() || !isApplicable()) close(true);
      }));
    }
    try {
      quickPick.show();
    } catch (error) {
      close(false);
      throw error;
    }
  });
}

function registerDependencyHealthCommands(deps) {
  const {
    registerCommand,
    vscode,
    dependencyHealthProvider,
    complianceReportProvider,
    packageAdapters,
  } = deps;
  const activePickers = new Set();
  const pickerOwner = Object.freeze({
    dispose() {
      for (const picker of [...activePickers].reverse()) picker.dispose();
    },
  });

  const isDependencyCommandApplicable = () => Boolean(
    dependencyHealthProvider.hasSuccessfulScan?.()
    && dependencyHealthProvider.isScanRunning?.() !== true
    && dependencyHealthProvider.isDependencyOperationRunning?.() !== true
  );

  const captureApplicableAccount = () => {
    const account = captureCommandAccount(deps.workspaceAccess);
    return account && isDependencyCommandApplicable() ? account : null;
  };

  const runApplicableMutation = async (mutation) => {
    const account = captureApplicableAccount();
    if (!account) return undefined;
    if (!isCommandAccountCurrent(account) || !isDependencyCommandApplicable()) return undefined;
    return mutation(account);
  };

  const getOpenProjectFolders = () => (vscode.workspace.workspaceFolders || [])
    .map(folder => ({
      label: folder.name || folder.uri?.fsPath,
      description: folder.uri?.fsPath,
      folderPath: folder.uri?.fsPath,
    }))
    .filter(item => typeof item.folderPath === "string" && item.folderPath.length > 0);

  async function browseForProjectFolder(account, openLabel) {
    if (!isCommandAccountCurrent(account)) return null;
    const picked = await vscode.window.showOpenDialog({
      canSelectFolders: true,
      canSelectFiles: false,
      canSelectMany: false,
      openLabel,
    });
    if (!isCommandAccountCurrent(account)) return null;
    return picked && picked[0] && typeof picked[0].fsPath === "string"
      ? picked[0].fsPath
      : null;
  }

  async function resolveInitialProjectFolder(account) {
    if (!isCommandAccountCurrent(account)) return null;
    const folders = getOpenProjectFolders();
    if (folders.length === 1) return folders[0].folderPath;

    if (folders.length === 0) {
      const recovery = await showAccountQuickPick(deps, account, [
        {
          label: "$(folder-opened) Select a folder to scan",
          description: "Browse for a project folder",
          action: "browse",
        },
        {
          label: "$(folder) Open a project folder",
          description: "Open a folder in VS Code",
          action: "open",
        },
      ], { placeHolder: "No workspace folder is open. Select a project folder to scan." });
      if (!isCommandAccountCurrent(account) || !recovery) return null;
      if (recovery.action === "open") {
        await vscode.commands?.executeCommand?.("vscode.openFolder");
        return null;
      }
      if (recovery.action !== "browse") return null;
      return browseForProjectFolder(account, "Scan dependencies");
    }

    const selected = await showAccountQuickPick(deps, account, [
      ...folders,
      {
        label: "$(folder-opened) Browse for a project folder",
        description: "Select a folder outside the open workspace",
        browse: true,
      },
    ], { placeHolder: "Select a project folder to scan" });
    if (!isCommandAccountCurrent(account) || !selected) return null;
    return selected.browse
      ? browseForProjectFolder(account, "Select project folder")
      : selected.folderPath || null;
  }

  async function selectProjectFolderForScopeChange(account) {
    const folders = getOpenProjectFolders();
    const selected = await showAccountQuickPick(deps, account, [
      ...folders,
      {
        label: "$(folder-opened) Browse for a project folder",
        description: "Select a project folder",
        browse: true,
      },
    ], { placeHolder: "Select a project folder to scan" });
    if (!isCommandAccountCurrent(account) || !selected) return null;
    return selected.browse
      ? browseForProjectFolder(account, "Select project folder")
      : selected.folderPath || null;
  }

  async function resolveDependencyScanTarget(options = {}, account) {
    if (!isCommandAccountCurrent(account)) return null;
    const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
    const configuredWorkspace = options.forcePrompt
      ? null
      : config.get("dependencyScanWorkspace");
    const configuredRepository = options.forcePrompt
      ? null
      : config.get("dependencyScanRepo");
    const workspace = await resolveCommandWorkspace(deps, account, {
      forcePrompt: false,
      ignoreDefault: options.forcePrompt === true,
      preferredWorkspace: configuredWorkspace || null,
      placeHolder: "Select a Cloudsmith workspace for the scan",
    });
    if (!isCommandAccountCurrent(account) || !workspace) return null;

    if (workspace.source === "preferred") {
      if (!configuredRepository) {
        return Object.freeze({ scanWorkspace: workspace.slug, scanRepo: null });
      }
      const configuredScope = await resolveCommandRepository(deps, account, {
        workspace,
        preferredRepository: configuredRepository,
        allowAll: true,
        placeHolder: `Select a scan scope in ${workspace.slug}`,
      });
      if (!isCommandAccountCurrent(account) || !configuredScope) return null;
      return Object.freeze({
        scanWorkspace: workspace.slug,
        scanRepo: configuredScope.all ? null : configuredScope.slug,
      });
    }
    if (workspace.source === "default" && options.forcePrompt !== true) {
      return Object.freeze({ scanWorkspace: workspace.slug, scanRepo: null });
    }

    const scopeItems = [
      {
        label: "All repositories",
        description: "Search across the entire workspace",
        scope: "all",
      },
      {
        label: "Select a specific repository",
        description: "Search one repository",
        scope: "repository",
      },
    ];
    const selectedScope = await showAccountQuickPick(deps, account, scopeItems, {
      placeHolder: "Select a scan scope",
    });
    if (!isCommandAccountCurrent(account) || !selectedScope) return null;
    if (selectedScope.scope === "all") {
      return Object.freeze({ scanWorkspace: workspace.slug, scanRepo: null });
    }
    if (selectedScope.scope !== "repository") return null;
    const repository = await resolveCommandRepository(deps, account, {
      workspace,
      placeHolder: "Select a repository",
    });
    if (!isCommandAccountCurrent(account) || !repository) return null;
    return Object.freeze({ scanWorkspace: workspace.slug, scanRepo: repository.slug });
  }

  const scanDependencies = () => {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return undefined;
    return runDependencyScan(
      dependencyHealthProvider,
      () => resolveDependencyScanTarget({}, account),
      account.isCurrent,
      () => resolveInitialProjectFolder(account)
    );
  };
  const changeDependencyScanScope = async () => {
    const account = captureApplicableAccount();
    if (!account) return;
    const scanTarget = await resolveDependencyScanTarget({ forcePrompt: true }, account);
    if (!isCommandAccountCurrent(account) || !isDependencyCommandApplicable()) return;
    if (!scanTarget) return;
    const projectFolder = await selectProjectFolderForScopeChange(account);
    if (!isCommandAccountCurrent(account) || !isDependencyCommandApplicable()) return;
    if (!projectFolder) return;
    if (!isCommandAccountCurrent(account) || !isDependencyCommandApplicable()) return;
    await dependencyHealthProvider.scan(
      scanTarget.scanWorkspace,
      scanTarget.scanRepo,
      projectFolder
    );
    if (!isCommandAccountCurrent(account)) return;
  };
  const cycleDepView = () => runApplicableMutation(
    () => dependencyHealthProvider.cycleViewMode()
  );
  const sortFilter = () => {
    const account = captureApplicableAccount();
    if (!account) return undefined;
    return showDependencySortFilterPicker(
      deps,
      activePickers,
      account,
      isDependencyCommandApplicable
    );
  };
  const pullSingleDependency = async (item) => {
    const account = captureApplicableAccount();
    if (!account || deps.isCurrentDependencySelection?.(item) !== true) return;
    let coordinate;
    let scope;
    try {
      scope = dependencyHealthProvider.getLastSuccessfulScope();
      if (!scope || typeof scope.workspace !== "string") {
        throw new TypeError("A successful dependency scan is required.");
      }
      coordinate = packageAdapters.fromDependencyHealthNode(item, {
        workspace: scope.workspace,
        repository: scope.repository,
      });
      if (
        coordinate.identityState !== "coordinate"
        || coordinate.workspace !== scope.workspace
        || coordinate.repository !== (scope.repository || null)
      ) {
        throw new TypeError("Only unresolved dependency coordinates can be pulled.");
      }
    } catch {
      vscode.window.showWarningMessage("Could not determine dependency details.");
      return;
    }
    const isCurrent = () => {
      if (
        !isCommandAccountCurrent(account)
        || deps.isCurrentDependencySelection?.(item) !== true
      ) return false;
      const currentScope = dependencyHealthProvider.getLastSuccessfulScope();
      return Boolean(
        currentScope
        && currentScope.workspace === scope.workspace
        && (currentScope.repository || null) === (scope.repository || null)
        && (currentScope.projectFolder || null) === (scope.projectFolder || null)
      );
    };
    if (!isCurrent()) return;
    await dependencyHealthProvider.pullSingleDependency(coordinate, { isCurrent });
    if (!isCommandAccountCurrent(account)) return;
  };
  const viewComplianceReport = async () => {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return;
    const reportData = dependencyHealthProvider.getReportData();
    if (!reportData) {
      vscode.window.showInformationMessage("Run a dependency scan before opening the report.");
      return;
    }
    if (!isCommandAccountCurrent(account)) return;
    complianceReportProvider.show(reportData);
  };

  let commands;
  try {
    commands = registerCommands(registerCommand, [
      ["cloudsmith-vsc.scanDependencies", scanDependencies],
    ["cloudsmith-vsc.scanDependenciesPending", scanDependencies],
    ["cloudsmith-vsc.scanDependenciesComplete", scanDependencies],
    ["cloudsmith-vsc.rescanDependencies", scanDependencies],
    ["cloudsmith-vsc.changeDependencyScanScope", changeDependencyScanScope],
    ["cloudsmith-vsc.pullDependencies", () => runApplicableMutation(
      () => dependencyHealthProvider.pullDependencies()
    )],
    ["cloudsmith-vsc.pullSingleDependency", pullSingleDependency],
    ["cloudsmith-vsc.cycleDepView", cycleDepView],
    ["cloudsmith-vsc.cycleDepViewDirect", cycleDepView],
    ["cloudsmith-vsc.cycleDepViewFlat", cycleDepView],
    ["cloudsmith-vsc.cycleDepViewTree", cycleDepView],
    ["cloudsmith-vsc.depViewDirect", () => runApplicableMutation(
      () => dependencyHealthProvider.setViewMode("direct")
    )],
    ["cloudsmith-vsc.depViewFlat", () => runApplicableMutation(
      () => dependencyHealthProvider.setViewMode("flat")
    )],
    ["cloudsmith-vsc.depViewTree", () => runApplicableMutation(
      () => dependencyHealthProvider.setViewMode("tree")
    )],
    ["cloudsmith-vsc.depFilterVulnerable", () => runApplicableMutation(() => (
      dependencyHealthProvider.setFilterMode(deps.FILTER_MODES.VULNERABLE)
    ))],
    ["cloudsmith-vsc.depFilterUncovered", () => runApplicableMutation(() => (
      dependencyHealthProvider.setFilterMode(deps.FILTER_MODES.UNCOVERED)
    ))],
    ["cloudsmith-vsc.depFilterRestrictiveLicense", () => runApplicableMutation(() => (
      dependencyHealthProvider.setFilterMode(deps.FILTER_MODES.RESTRICTIVE_LICENSE)
    ))],
    ["cloudsmith-vsc.depFilterPolicyViolation", () => runApplicableMutation(() => (
      dependencyHealthProvider.setFilterMode(deps.FILTER_MODES.POLICY_VIOLATION)
    ))],
    ["cloudsmith-vsc.depFilterClear", () => runApplicableMutation(
      () => dependencyHealthProvider.clearFilter()
    )],
    ["cloudsmith-vsc.depSortFilter", sortFilter],
    ["cloudsmith-vsc.depSortFilterActive", sortFilter],
      ["cloudsmith-vsc.viewComplianceReport", viewComplianceReport],
    ], deps);
  } catch (error) {
    pickerOwner.dispose();
    throw error;
  }
  return aggregateDisposables([pickerOwner, commands], deps);
}

module.exports = { registerDependencyHealthCommands };

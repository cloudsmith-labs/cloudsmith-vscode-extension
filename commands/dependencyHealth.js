// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { aggregateDisposables, registerCommands } = require("./registrar");
const { runDependencyScan } = require("../util/dependencyScanOrchestration");
const {
  captureCommandAccount,
  collectionQuickPickItems,
  getDefaultWorkspace,
  getWorkspaces,
  getWorkspaceRepositories,
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

async function showDependencySortFilterPicker(deps, activePickers, account) {
  const { vscode, dependencyHealthProvider, FILTER_MODES, SORT_MODES } = deps;
  if (!account?.isCurrent()) return;
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
      if (closed || !account.isCurrent()) {
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
        if (closed || !account.isCurrent()) {
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
        if (!account.isCurrent()) close(true);
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

  async function resolveDependencyScanTarget(options = {}, account) {
    if (!account?.isCurrent()) return null;
    const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
    let scanWorkspace = options.forcePrompt ? null : config.get("dependencyScanWorkspace");
    let scanRepo = options.forcePrompt ? null : (config.get("dependencyScanRepo") || null);
    if (!scanWorkspace && !options.forcePrompt) {
      scanWorkspace = getDefaultWorkspace(vscode);
      if (scanWorkspace) scanRepo = null;
    }
    if (scanWorkspace) {
      return account.isCurrent() ? { scanWorkspace, scanRepo } : null;
    }

    const workspaces = await getWorkspaces(deps.workspaceAccess);
    if (!account.isCurrent()) return null;
    if (!workspaces) return null;
    if (workspaces.items.length === 0) {
      if (workspaces.complete) {
        vscode.window.showErrorMessage("No workspaces found. Connect to Cloudsmith first.");
      }
      return null;
    }
    const selectedWorkspace = await vscode.window.showQuickPick(
      collectionQuickPickItems(
        vscode,
        workspaces,
        workspace => ({ label: workspace.name, description: workspace.slug }),
        "Workspace list incomplete"
      ),
      { placeHolder: "Select a Cloudsmith workspace for the scan" }
    );
    if (!account.isCurrent()) return null;
    if (!selectedWorkspace) return null;
    scanWorkspace = selectedWorkspace.description;

    const selectedScope = await vscode.window.showQuickPick([
      { label: "All repositories", description: "Search across the entire workspace", all: true },
      { label: "Select a specific repository", description: "Search one repository", all: false },
    ], { placeHolder: "Select a scan scope" });
    if (!account.isCurrent()) return null;
    if (!selectedScope) return null;

    if (selectedScope.all) {
      scanRepo = null;
    } else {
      const repositories = await getWorkspaceRepositories(deps.workspaceAccess, scanWorkspace);
      if (!account.isCurrent()) return null;
      if (!repositories) return null;
      if (repositories.items.length > 0) {
        const selectedRepo = await vscode.window.showQuickPick(
          collectionQuickPickItems(
            vscode,
            repositories,
            repository => ({ label: repository.name, description: repository.slug }),
            "Repository list incomplete"
          ),
          { placeHolder: "Select a repository" }
        );
        if (!account.isCurrent()) return null;
        if (!selectedRepo) return null;
        scanRepo = selectedRepo.description;
      } else if (repositories.complete) {
        vscode.window.showInformationMessage("No repositories were found in this workspace.");
        return null;
      } else {
        return null;
      }
    }
    return account.isCurrent() ? { scanWorkspace, scanRepo } : null;
  }

  const scanDependencies = () => {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return undefined;
    return runDependencyScan(
      dependencyHealthProvider,
      () => resolveDependencyScanTarget({}, account),
      account.isCurrent
    );
  };
  const changeDependencyScanScope = async () => {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return;
    const scanTarget = await resolveDependencyScanTarget({ forcePrompt: true }, account);
    if (!account.isCurrent()) return;
    if (!scanTarget) return;
    const projectFolder = await dependencyHealthProvider.selectProjectFolder();
    if (!account.isCurrent()) return;
    if (!projectFolder) return;
    if (!account.isCurrent()) return;
    await dependencyHealthProvider.scan(
      scanTarget.scanWorkspace,
      scanTarget.scanRepo,
      projectFolder
    );
  };
  const cycleDepView = () => dependencyHealthProvider.cycleViewMode();
  const sortFilter = () => {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return undefined;
    return showDependencySortFilterPicker(deps, activePickers, account);
  };
  const pullSingleDependency = async (item) => {
    let coordinate;
    try {
      const scope = dependencyHealthProvider.getLastSuccessfulScope();
      coordinate = packageAdapters.fromDependencyHealthNode(item, {
        workspace: scope?.workspace,
        repository: scope?.repository,
      });
      if (coordinate.identityState !== "coordinate") {
        throw new TypeError("Only unresolved dependency coordinates can be pulled.");
      }
    } catch {
      vscode.window.showWarningMessage("Could not determine dependency details.");
      return;
    }
    await dependencyHealthProvider.pullSingleDependency(coordinate);
  };
  const viewComplianceReport = async () => {
    const reportData = dependencyHealthProvider.getReportData();
    if (!reportData) {
      vscode.window.showInformationMessage("Run a dependency scan before opening the report.");
      return;
    }
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
    ["cloudsmith-vsc.pullDependencies", () => dependencyHealthProvider.pullDependencies()],
    ["cloudsmith-vsc.pullSingleDependency", pullSingleDependency],
    ["cloudsmith-vsc.cycleDepView", cycleDepView],
    ["cloudsmith-vsc.cycleDepViewDirect", cycleDepView],
    ["cloudsmith-vsc.cycleDepViewFlat", cycleDepView],
    ["cloudsmith-vsc.cycleDepViewTree", cycleDepView],
    ["cloudsmith-vsc.depViewDirect", () => dependencyHealthProvider.setViewMode("direct")],
    ["cloudsmith-vsc.depViewFlat", () => dependencyHealthProvider.setViewMode("flat")],
    ["cloudsmith-vsc.depViewTree", () => dependencyHealthProvider.setViewMode("tree")],
    ["cloudsmith-vsc.depFilterVulnerable", () => (
      dependencyHealthProvider.setFilterMode(deps.FILTER_MODES.VULNERABLE)
    )],
    ["cloudsmith-vsc.depFilterUncovered", () => (
      dependencyHealthProvider.setFilterMode(deps.FILTER_MODES.UNCOVERED)
    )],
    ["cloudsmith-vsc.depFilterRestrictiveLicense", () => (
      dependencyHealthProvider.setFilterMode(deps.FILTER_MODES.RESTRICTIVE_LICENSE)
    )],
    ["cloudsmith-vsc.depFilterPolicyViolation", () => (
      dependencyHealthProvider.setFilterMode(deps.FILTER_MODES.POLICY_VIOLATION)
    )],
    ["cloudsmith-vsc.depFilterClear", () => dependencyHealthProvider.clearFilter()],
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

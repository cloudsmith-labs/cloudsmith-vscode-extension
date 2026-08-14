// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { registerCommands } = require("./registrar");
const {
  executeSearchIntent,
  searchDescriptorFromRecent,
} = require("../util/searchIntent");
const {
  buildPresetQuery,
  buildRawSearchQuery,
  captureCommandAccount,
  collectionQuickPickItems,
  createFilterPresets,
  getDefaultWorkspace,
  getWorkspaces,
  getWorkspaceRepositories,
} = require("./support");

function registerSearchCommands(deps) {
  const {
    registerCommand,
    vscode,
    searchProvider,
    RecentSearches,
    SearchQueryBuilder,
    LicenseClassifier,
    FORMAT_OPTIONS,
    packageAdapters,
  } = deps;
  const filterPresets = createFilterPresets(LicenseClassifier);

  async function chooseWorkspace(placeHolder, account) {
    if (!account?.isCurrent()) return null;
    const defaultWorkspace = getDefaultWorkspace(vscode);
    if (defaultWorkspace) return defaultWorkspace;
    const workspaces = await getWorkspaces(deps.workspaceAccess);
    if (!account.isCurrent()) return null;
    if (!workspaces) return null;
    if (workspaces.items.length === 0) {
      if (workspaces.complete) {
        vscode.window.showErrorMessage("No workspaces found. Connect to Cloudsmith first.");
      }
      return null;
    }
    const selected = await vscode.window.showQuickPick(
      collectionQuickPickItems(
        vscode,
        workspaces,
        workspace => ({ label: workspace.name, description: workspace.slug }),
        "Workspace list incomplete"
      ),
      { placeHolder }
    );
    if (!account.isCurrent()) return null;
    return selected ? selected.description : null;
  }

  async function replayOrPrompt(workspace, recentSearches, options, account) {
    if (!account?.isCurrent()) return null;
    const recent = await recentSearches.getAll();
    if (!account.isCurrent()) return null;
    if (recent.length === 0) return false;
    const items = [{ label: "Recent searches", kind: vscode.QuickPickItemKind.Separator }];
    for (const entry of recent) {
      items.push({
        label: `$(history) ${entry.query}`,
        description: entry.workspace,
        recent: entry,
      });
    }
    items.push({ label: options.separatorLabel, kind: vscode.QuickPickItemKind.Separator });
    items.push({ label: options.actionLabel, createNew: true });
    const selected = await vscode.window.showQuickPick(items, {
      placeHolder: options.placeHolder,
    });
    if (!account.isCurrent()) return null;
    if (!selected) return null;
    if (selected.recent) {
      const descriptor = searchDescriptorFromRecent(selected.recent);
      if (descriptor && account.isCurrent()) {
        await executeSearchIntent(searchProvider, descriptor);
      }
      return true;
    }
    return false;
  }

  async function searchPackages() {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return;
    const workspace = await chooseWorkspace("Select a workspace", account);
    if (!account.isCurrent()) return;
    if (!workspace) return;
    const recentSearches = new RecentSearches(deps.context, workspace);
    const replayed = await replayOrPrompt(workspace, recentSearches, {
      separatorLabel: "New search",
      actionLabel: `$(search) New search in ${workspace}`,
      placeHolder: `Search packages in ${workspace}`,
    }, account);
    if (!account.isCurrent()) return;
    if (replayed === null || replayed === true) return;
    const query = await vscode.window.showInputBox({
      placeHolder: "Search packages (e.g., name:flask, format:python)",
      prompt: `Search packages in ${workspace}`,
    });
    if (!account.isCurrent()) return;
    if (!query) return;
    if (!account.isCurrent()) return;
    await executeSearchIntent(searchProvider, {
      kind: "workspace",
      workspace,
      query: buildRawSearchQuery(SearchQueryBuilder, query),
      page: 1,
    }, { recentSearches, record: true, isCurrent: account.isCurrent });
  }

  async function searchInWorkspace(item) {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return;
    const workspace = item && (item.slug || item.name)
      ? (item.slug || item.name)
      : getDefaultWorkspace(vscode);
    if (!workspace) {
      vscode.window.showWarningMessage(
        "Could not determine the workspace. Set a default workspace in settings."
      );
      return;
    }
    const query = await vscode.window.showInputBox({
      placeHolder: "Search packages (e.g., name:flask, format:python)",
      prompt: `Search packages in ${workspace}`,
    });
    if (!account.isCurrent()) return;
    if (!query) return;
    const recentSearches = new RecentSearches(deps.context, workspace);
    if (!account.isCurrent()) return;
    await executeSearchIntent(searchProvider, {
      kind: "workspace",
      workspace,
      query: buildRawSearchQuery(SearchQueryBuilder, query),
      page: 1,
    }, { recentSearches, record: true, isCurrent: account.isCurrent });
  }

  async function guidedSearch() {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return;
    const workspace = await chooseWorkspace("Step 1: Select a workspace", account);
    if (!account.isCurrent()) return;
    if (!workspace) return;
    const recentSearches = new RecentSearches(deps.context, workspace);
    const replayed = await replayOrPrompt(workspace, recentSearches, {
      separatorLabel: "Continue guided search",
      actionLabel: `$(search) Continue guided search in ${workspace}`,
      placeHolder: `Recent searches in ${workspace}`,
    }, account);
    if (!account.isCurrent()) return;
    if (replayed === null || replayed === true) return;

    const selectedScope = await vscode.window.showQuickPick([
      { label: "All repositories", description: "Search across the entire workspace" },
      { label: "Select specific repositories", description: "Choose one or more repositories" },
    ], { placeHolder: "Step 2: Select a search scope" });
    if (!account.isCurrent()) return;
    if (!selectedScope) return;

    let selectedRepos = null;
    if (selectedScope.label === "Select specific repositories") {
      const repositories = await getWorkspaceRepositories(deps.workspaceAccess, workspace);
      if (!account.isCurrent()) return;
      if (!repositories) return;
      if (repositories.items.length === 0) {
        if (repositories.complete) {
          vscode.window.showErrorMessage("No repositories found in this workspace.");
        }
        return;
      }
      const picked = await vscode.window.showQuickPick(
        collectionQuickPickItems(
          vscode,
          repositories,
          repository => ({ label: repository.name, description: repository.slug }),
          "Repository list incomplete"
        ),
        { placeHolder: "Select repositories to search", canPickMany: true }
      );
      if (!account.isCurrent()) return;
      if (!picked || picked.length === 0) return;
      selectedRepos = picked.map(repository => repository.description);
    }

    const selectedFilter = await vscode.window.showQuickPick(
      filterPresets.map(preset => ({ label: preset.label, preset })),
      { placeHolder: "Step 3: Select a filter" }
    );
    if (!account.isCurrent()) return;
    if (!selectedFilter) return;
    const queryParts = [];
    if (selectedFilter.preset.applyBuilder === null) {
      const custom = await vscode.window.showInputBox({
        placeHolder: "Enter Cloudsmith search query",
        prompt: "Custom search query",
      });
      if (!account.isCurrent()) return;
      if (!custom) return;
      queryParts.push(buildPresetQuery(SearchQueryBuilder, selectedFilter.preset, custom));
    } else {
      const presetQuery = buildPresetQuery(SearchQueryBuilder, selectedFilter.preset);
      if (presetQuery) queryParts.push(presetQuery);
    }

    const selectedFormats = await vscode.window.showQuickPick([
      { label: "All formats", description: "No format filter", all: true },
      ...FORMAT_OPTIONS.map(format => ({ label: format, all: false })),
    ], { placeHolder: "Step 4: Filter by format (optional)", canPickMany: true });
    if (!account.isCurrent()) return;
    if (selectedFormats && selectedFormats.length > 0 && !selectedFormats.some(format => format.all)) {
      const formatQuery = selectedFormats
        .map(format => new SearchQueryBuilder().format(format.label).build())
        .join(" OR ");
      queryParts.push(`(${formatQuery})`);
    }
    const builder = new SearchQueryBuilder();
    for (const part of queryParts) builder.raw(part);
    if (!account.isCurrent()) return;
    await executeSearchIntent(searchProvider, {
      kind: selectedRepos ? "repositories" : "workspace",
      workspace,
      query: builder.build() || "*",
      page: 1,
      ...(selectedRepos ? { repositories: selectedRepos } : {}),
    }, { recentSearches, record: true, isCurrent: account.isCurrent });
  }

  async function searchByLicense() {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return;
    const workspace = await chooseWorkspace("Select a workspace to search", account);
    if (!account.isCurrent()) return;
    if (!workspace) return;
    const selected = await vscode.window.showQuickPick(
      LicenseClassifier.getSearchQuickPickItems(),
      { placeHolder: "Select a license to search for" }
    );
    if (!account.isCurrent()) return;
    if (!selected) return;
    const query = selected.query || LicenseClassifier.buildLicenseQuery(selected.label);
    const recentSearches = new RecentSearches(deps.context, workspace);
    if (!account.isCurrent()) return;
    await executeSearchIntent(searchProvider, {
      kind: "workspace", workspace, query, page: 1,
    }, { recentSearches, record: true, isCurrent: account.isCurrent });
  }

  async function filterVulnerable(item) {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return;
    let repository;
    try {
      repository = packageAdapters.fromRepositoryNode(item);
    } catch {
      vscode.window.showWarningMessage("Could not determine repository details.");
      return;
    }
    await searchProvider.search(
      repository.workspace,
      "vulnerabilities:>0",
      1,
      repository.repository
    );
    if (!account.isCurrent()) return;
    await vscode.commands.executeCommand("cloudsmithSearchView.focus");
  }

  async function filterVulnerableWorkspace(item) {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return;
    if (!item || !item.slug) {
      vscode.window.showWarningMessage("Could not determine workspace details.");
      return;
    }
    await searchProvider.search(item.slug, "vulnerabilities:>0");
    if (!account.isCurrent()) return;
    await vscode.commands.executeCommand("cloudsmithSearchView.focus");
  }

  return registerCommands(registerCommand, [
    ["cloudsmith-vsc.searchPackages", searchPackages],
    ["cloudsmith-vsc.clearSearch", () => searchProvider.clear()],
    ["cloudsmith-vsc.searchNextPage", () => searchProvider.loadNextPage()],
    ["cloudsmith-vsc.searchInWorkspace", searchInWorkspace],
    ["cloudsmith-vsc.guidedSearch", guidedSearch],
    ["cloudsmith-vsc.filterVulnerable", filterVulnerable],
    ["cloudsmith-vsc.filterVulnerableWorkspace", filterVulnerableWorkspace],
    ["cloudsmith-vsc.searchByLicense", searchByLicense],
  ], deps);
}

module.exports = { registerSearchCommands };

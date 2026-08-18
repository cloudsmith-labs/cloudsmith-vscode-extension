// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { registerCommands } = require("./registrar");
const {
  executeSearchIntent,
  searchDescriptorFromRecent,
} = require("../util/searchIntent");
const {
  buildPresetQuery,
  buildRawSearchQuery,
  canonicalRepository,
  captureCommandAccount,
  createFilterPresets,
  getWorkspaceRepositories,
  isCommandAccountCurrent,
  resolveCommandRepository,
  resolveCommandWorkspace,
  safeDisplayName,
  showAccountInputBox,
  showAccountQuickPick,
} = require("./support");

const MAX_SEARCH_INPUT_LENGTH = 2048;

function searchInputOptions(options) {
  return {
    ...options,
    validateInput(value) {
      if (value.length > MAX_SEARCH_INPUT_LENGTH) {
        return `Search queries must be ${MAX_SEARCH_INPUT_LENGTH} characters or fewer.`;
      }
      if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)) {
        return "Search queries cannot contain control characters.";
      }
      return null;
    },
  };
}

function validSearchInput(value) {
  return typeof value === "string"
    && value.trim().length > 0
    && value.length <= MAX_SEARCH_INPUT_LENGTH
    && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
}

function registerSearchCommands(deps) {
  const {
    registerCommand,
    vscode,
    searchProvider,
    RecentSearches,
    SearchQueryBuilder,
    LicenseClassifier,
    FORMAT_OPTIONS,
  } = deps;
  const filterPresets = createFilterPresets(LicenseClassifier);

  async function chooseWorkspace(placeHolder, account) {
    const workspace = await resolveCommandWorkspace(deps, account, { placeHolder });
    return isCommandAccountCurrent(account) && workspace ? workspace.slug : null;
  }

  async function replayOrPrompt(workspace, recentSearches, options, account) {
    if (!isCommandAccountCurrent(account)) return null;
    const recent = await recentSearches.getAll();
    if (!isCommandAccountCurrent(account)) return null;
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
    const selected = await showAccountQuickPick(deps, account, items, {
      placeHolder: options.placeHolder,
    });
    if (!isCommandAccountCurrent(account)) return null;
    if (!selected) return null;
    if (selected.recent) {
      const descriptor = searchDescriptorFromRecent(selected.recent);
      if (descriptor && isCommandAccountCurrent(account)) {
        await executeSearchIntent(searchProvider, descriptor);
        if (!isCommandAccountCurrent(account)) return null;
      }
      return true;
    }
    return false;
  }

  async function searchPackages() {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return;
    const workspace = await chooseWorkspace("Select a workspace", account);
    if (!isCommandAccountCurrent(account)) return;
    if (!workspace) return;
    const recentSearches = new RecentSearches(deps.context, workspace);
    const replayed = await replayOrPrompt(workspace, recentSearches, {
      separatorLabel: "New search",
      actionLabel: `$(search) New search in ${workspace}`,
      placeHolder: `Search packages in ${workspace}`,
    }, account);
    if (!isCommandAccountCurrent(account)) return;
    if (replayed === null || replayed === true) return;
    const query = await showAccountInputBox(deps, account, searchInputOptions({
      placeHolder: "Search packages (e.g., name:flask, format:python)",
      prompt: `Search packages in ${workspace}`,
    }));
    if (!isCommandAccountCurrent(account) || !validSearchInput(query)) return;
    await executeSearchIntent(searchProvider, {
      kind: "workspace",
      workspace,
      query: buildRawSearchQuery(SearchQueryBuilder, query),
      page: 1,
    }, { recentSearches, record: true, isCurrent: account.isCurrent });
    if (!isCommandAccountCurrent(account)) return;
  }

  async function searchInWorkspace(item) {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (
      !account
      || !item
      || deps.isCurrentWorkspaceSelection?.(item) !== true
    ) return;
    const isCurrent = () => Boolean(
      isCommandAccountCurrent(account)
      && deps.isCurrentWorkspaceSelection?.(item) === true
    );
    const resolvedWorkspace = await resolveCommandWorkspace(deps, account, {
      explicitItem: item,
      currentSelection: candidate => deps.isCurrentWorkspaceSelection?.(candidate) === true,
      invalidMessage: "Could not determine workspace details.",
    });
    if (!isCurrent() || !resolvedWorkspace) return;
    const workspace = resolvedWorkspace.slug;
    const query = await showAccountInputBox(deps, account, searchInputOptions({
      placeHolder: "Search packages (e.g., name:flask, format:python)",
      prompt: `Search packages in ${workspace}`,
    }));
    if (!isCurrent() || !validSearchInput(query)) return;
    const recentSearches = new RecentSearches(deps.context, workspace);
    if (!isCurrent()) return;
    await executeSearchIntent(searchProvider, {
      kind: "workspace",
      workspace,
      query: buildRawSearchQuery(SearchQueryBuilder, query),
      page: 1,
    }, { recentSearches, record: true, isCurrent });
    if (!isCurrent()) return;
  }

  async function guidedSearch() {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return;
    const workspace = await chooseWorkspace("Step 1: Select a workspace", account);
    if (!isCommandAccountCurrent(account)) return;
    if (!workspace) return;
    const recentSearches = new RecentSearches(deps.context, workspace);
    const replayed = await replayOrPrompt(workspace, recentSearches, {
      separatorLabel: "Continue guided search",
      actionLabel: `$(search) Continue guided search in ${workspace}`,
      placeHolder: `Recent searches in ${workspace}`,
    }, account);
    if (!isCommandAccountCurrent(account)) return;
    if (replayed === null || replayed === true) return;

    const selectedScope = await showAccountQuickPick(deps, account, [
      {
        label: "All repositories",
        description: "Search across the entire workspace",
        scope: "all",
      },
      {
        label: "Select specific repositories",
        description: "Choose one or more repositories",
        scope: "repositories",
      },
    ], { placeHolder: "Step 2: Select a search scope" });
    if (!isCommandAccountCurrent(account)) return;
    if (!selectedScope) return;
    if (selectedScope.scope !== "all" && selectedScope.scope !== "repositories") return;

    let selectedRepos = null;
    if (selectedScope.scope === "repositories") {
      let retryCount = 0;
      while (isCommandAccountCurrent(account)) {
        const repositories = await getWorkspaceRepositories(deps.workspaceAccess, workspace);
        if (!isCommandAccountCurrent(account) || !repositories) return;
        const verifiedRepositories = repositories.items
          .map(repository => canonicalRepository(repository, { slug: workspace }))
          .filter(Boolean);
        const repositoryCollectionComplete = repositories.complete === true
          && verifiedRepositories.length === repositories.items.length;
        if (repositoryCollectionComplete && verifiedRepositories.length === 0) {
          vscode.window.showInformationMessage("No repositories were found in this workspace.");
          return;
        }
        const repositoryItems = verifiedRepositories.map(repository => ({
          label: safeDisplayName(repository.name, repository.slug, 2048),
          description: `${workspace}/${safeDisplayName(
            repository.slug,
            "unknown-repository",
            512
          )}`,
          repository: Object.freeze({ workspace, slug: repository.slug }),
        }));
        if (!repositoryCollectionComplete) {
          repositoryItems.unshift({
            label: "Some repositories could not be loaded",
            kind: vscode.QuickPickItemKind.Separator,
          });
          if (retryCount === 0) {
            repositoryItems.push({
              label: "$(refresh) Retry loading repositories",
              description: "Try to load the repository list again",
              retry: true,
            });
          }
        }
        const picked = await showAccountQuickPick(deps, account, repositoryItems, {
          placeHolder: "Select repositories to search",
          canPickMany: true,
        });
        if (!isCommandAccountCurrent(account) || !Array.isArray(picked)) return;
        if (picked.some(entry => entry.retry)) {
          retryCount += 1;
          continue;
        }
        const selected = picked
          .filter(entry => entry.repository)
          .map(entry => entry.repository.slug);
        if (selected.length === 0) return;
        selectedRepos = selected;
        break;
      }
    }

    const selectedFilter = await showAccountQuickPick(
      deps,
      account,
      filterPresets.map(preset => ({ label: preset.label, preset })),
      { placeHolder: "Step 3: Select a filter" }
    );
    if (!isCommandAccountCurrent(account)) return;
    if (!selectedFilter) return;
    const queryParts = [];
    if (selectedFilter.preset.applyBuilder === null) {
      const custom = await showAccountInputBox(deps, account, searchInputOptions({
        placeHolder: "Enter Cloudsmith search query",
        prompt: "Custom search query",
      }));
      if (!isCommandAccountCurrent(account) || !validSearchInput(custom)) return;
      queryParts.push(buildPresetQuery(SearchQueryBuilder, selectedFilter.preset, custom));
    } else {
      const presetQuery = buildPresetQuery(SearchQueryBuilder, selectedFilter.preset);
      if (presetQuery) queryParts.push(presetQuery);
    }

    const selectedFormats = await showAccountQuickPick(deps, account, [
      { label: "All formats", description: "No format filter", all: true },
      ...FORMAT_OPTIONS.map(format => ({ label: format, all: false })),
    ], { placeHolder: "Step 4: Filter by format (optional)", canPickMany: true });
    if (!isCommandAccountCurrent(account) || !Array.isArray(selectedFormats)) return;
    if (selectedFormats.length > 0 && !selectedFormats.some(format => format.all)) {
      const formatQuery = selectedFormats
        .map(format => new SearchQueryBuilder().format(format.label).build())
        .join(" OR ");
      queryParts.push(`(${formatQuery})`);
    }
    const builder = new SearchQueryBuilder();
    for (const part of queryParts) builder.raw(part);
    if (!isCommandAccountCurrent(account)) return;
    await executeSearchIntent(searchProvider, {
      kind: selectedRepos ? "repositories" : "workspace",
      workspace,
      query: builder.build() || "*",
      page: 1,
      ...(selectedRepos ? { repositories: selectedRepos } : {}),
    }, { recentSearches, record: true, isCurrent: account.isCurrent });
    if (!isCommandAccountCurrent(account)) return;
  }

  async function searchByLicense() {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return;
    const workspace = await chooseWorkspace("Select a workspace to search", account);
    if (!isCommandAccountCurrent(account)) return;
    if (!workspace) return;
    const selected = await showAccountQuickPick(
      deps,
      account,
      LicenseClassifier.getSearchQuickPickItems(),
      { placeHolder: "Select a license to search for" }
    );
    if (!isCommandAccountCurrent(account)) return;
    if (!selected) return;
    const query = selected.query || LicenseClassifier.buildLicenseQuery(selected.label);
    const recentSearches = new RecentSearches(deps.context, workspace);
    if (!isCommandAccountCurrent(account)) return;
    await executeSearchIntent(searchProvider, {
      kind: "workspace", workspace, query, page: 1,
    }, { recentSearches, record: true, isCurrent: account.isCurrent });
    if (!isCommandAccountCurrent(account)) return;
  }

  async function filterVulnerable(item) {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account) return;
    if (deps.isCurrentRepositorySelection?.(item) !== true) return;
    const isCurrent = () => Boolean(
      isCommandAccountCurrent(account)
      && deps.isCurrentRepositorySelection?.(item) === true
    );
    const repository = await resolveCommandRepository(deps, account, {
      explicitItem: item,
      currentSelection: candidate => deps.isCurrentRepositorySelection?.(candidate) === true,
      invalidMessage: "Could not determine repository details.",
    });
    if (!isCurrent() || !repository) return;
    await searchProvider.search(
      repository.workspace,
      "vulnerabilities:>0",
      1,
      repository.slug
    );
    if (!isCurrent()) return;
    await vscode.commands.executeCommand("cloudsmithSearchView.focus");
    if (!isCurrent()) return;
  }

  async function filterVulnerableWorkspace(item) {
    const account = captureCommandAccount(deps.workspaceAccess);
    if (!account || !item || deps.isCurrentWorkspaceSelection?.(item) !== true) return;
    const isCurrent = () => Boolean(
      isCommandAccountCurrent(account)
      && deps.isCurrentWorkspaceSelection?.(item) === true
    );
    const workspace = await resolveCommandWorkspace(deps, account, {
      explicitItem: item,
      currentSelection: candidate => deps.isCurrentWorkspaceSelection?.(candidate) === true,
      invalidMessage: "Could not determine workspace details.",
    });
    if (!isCurrent() || !workspace) return;
    await searchProvider.search(workspace.slug, "vulnerabilities:>0");
    if (!isCurrent()) return;
    await vscode.commands.executeCommand("cloudsmithSearchView.focus");
    if (!isCurrent()) return;
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

// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const {
  firstCollectionFailureMessage,
  getWorkspaces,
  getWorkspaceRepositories,
} = require("../util/workspaceAccess");

const DISPLAY_CONTROL_OR_BIDI = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/gu;
const IDENTITY_CONTROL_OR_BIDI = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u;

function getDefaultWorkspace(vscode) {
  return vscode.workspace.getConfiguration("cloudsmith-vsc").get("defaultWorkspace") || "";
}

function captureCommandAccount(workspaceAccess) {
  if (
    !workspaceAccess
    || typeof workspaceAccess.captureAccount !== "function"
    || typeof workspaceAccess.isAccountCurrent !== "function"
  ) {
    return null;
  }
  const account = workspaceAccess.captureAccount(workspaceAccess.connectionManager);
  if (!account) return null;
  return Object.freeze({
    account,
    connectionManager: workspaceAccess.connectionManager,
    isCurrent: () => workspaceAccess.isAccountCurrent(
      workspaceAccess.connectionManager,
      account
    ),
  });
}

function isCommandAccountCurrent(accountScope) {
  return Boolean(accountScope && accountScope.isCurrent());
}

function promptCancellation(deps, accountScope) {
  const CancellationTokenSource = deps.vscode && deps.vscode.CancellationTokenSource;
  const source = typeof CancellationTokenSource === "function"
    ? new CancellationTokenSource()
    : null;
  const connectionManager = accountScope?.connectionManager
    || deps.workspaceAccess?.connectionManager
    || null;
  const subscription = typeof connectionManager?.onDidChange === "function"
    ? connectionManager.onDidChange(() => {
      if (!isCommandAccountCurrent(accountScope)) source?.cancel();
    })
    : null;
  return Object.freeze({
    token: source?.token,
    dispose() {
      subscription?.dispose?.();
      source?.dispose?.();
    },
  });
}

async function showAccountQuickPick(deps, accountScope, items, options = {}) {
  if (!isCommandAccountCurrent(accountScope)) return null;
  const cancellation = promptCancellation(deps, accountScope);
  try {
    const selected = await deps.vscode.window.showQuickPick(
      items,
      options,
      cancellation.token
    );
    return isCommandAccountCurrent(accountScope) ? (selected || null) : null;
  } finally {
    cancellation.dispose();
  }
}

async function showAccountInputBox(deps, accountScope, options = {}) {
  if (!isCommandAccountCurrent(accountScope)) return null;
  const cancellation = promptCancellation(deps, accountScope);
  try {
    const value = await deps.vscode.window.showInputBox(options, cancellation.token);
    return isCommandAccountCurrent(accountScope) ? (value || null) : null;
  } finally {
    cancellation.dispose();
  }
}

function validIdentity(value, maximumLength = 512) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= maximumLength
    && value.trim() === value
    && !IDENTITY_CONTROL_OR_BIDI.test(value)
    && !/[\\/?#]/.test(value);
}

function safeDisplayName(value, fallback, maximumLength) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximumLength) {
    return fallback;
  }
  return value
    .replace(DISPLAY_CONTROL_OR_BIDI, " ")
    .replace(/\s+/gu, " ")
    .trim()
    || fallback;
}

function canonicalWorkspace(value, source = null) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const nested = value.workspace;
  const record = nested && typeof nested === "object" && !Array.isArray(nested)
    ? nested
    : value;
  const slug = record.slug;
  if (!validIdentity(slug)) return null;
  const name = safeDisplayName(record.name, slug, 512);
  return Object.freeze({ slug, name, ...(source ? { source } : {}) });
}

function canonicalRepository(value, workspace = null, source = null) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const nested = value.repository;
  const record = nested && typeof nested === "object" && !Array.isArray(nested)
    ? nested
    : value;
  const workspaceSlug = workspace?.slug
    || record.workspace
    || value.workspace;
  const slug = record.slug;
  if (!validIdentity(workspaceSlug) || !validIdentity(slug)) return null;
  const name = safeDisplayName(record.name, slug, 2048);
  return Object.freeze({
    workspace: workspaceSlug,
    slug,
    name,
    ...(source ? { source } : {}),
  });
}

function configuredIdentity(value) {
  return validIdentity(value) ? value : null;
}

function incompleteSeparator(vscode, label) {
  return {
    label,
    kind: vscode.QuickPickItemKind.Separator,
  };
}

function retryItem(kind) {
  return {
    label: `$(refresh) Retry loading ${kind}`,
    description: `Try to load the ${kind} list again`,
    retry: true,
  };
}

async function resolveCommandWorkspace(deps, accountScope, options = {}) {
  if (!isCommandAccountCurrent(accountScope)) return null;
  if (options.explicitItem) {
    if (
      typeof options.currentSelection !== "function"
      || !options.currentSelection(options.explicitItem)
    ) {
      return null;
    }
    const candidate = canonicalWorkspace(options.explicitItem);
    if (!candidate) {
      deps.vscode.window.showWarningMessage(
        options.invalidMessage || "Could not determine workspace details."
      );
      return null;
    }
    const maximumRetries = Number.isInteger(options.maxRetries)
      ? Math.max(0, Math.min(options.maxRetries, 2))
      : 1;
    let attempt = 0;
    while (isCommandAccountCurrent(accountScope)) {
      const result = await getWorkspaces(deps.workspaceAccess);
      if (!isCommandAccountCurrent(accountScope) || !result) return null;
      const workspaces = result.items.map(item => canonicalWorkspace(item)).filter(Boolean);
      const match = workspaces.find(workspace => workspace.slug === candidate.slug);
      if (match) return Object.freeze({ ...match, source: "explicit" });
      if (result.complete === true) {
        deps.vscode.window.showWarningMessage(
          options.invalidMessage || "Could not determine workspace details."
        );
        return null;
      }
      if (workspaces.length === 0 && attempt >= maximumRetries) {
        deps.vscode.window.showWarningMessage(
          "Workspace choices are incomplete; the selected workspace could not be verified."
        );
        return null;
      }
      const items = [incompleteSeparator(
        deps.vscode,
        "The selected workspace could not be verified because choices are incomplete"
      )];
      items.push(...workspaces.map(workspace => ({
        label: workspace.name,
        description: workspace.slug,
        workspace,
      })));
      if (attempt < maximumRetries) items.push(retryItem("workspaces"));
      const selected = await showAccountQuickPick(deps, accountScope, items, {
        placeHolder: "Retry or select a verified workspace",
      });
      if (!isCommandAccountCurrent(accountScope) || !selected) return null;
      if (selected.retry) {
        attempt += 1;
        continue;
      }
      if (!items.includes(selected) || !selected.workspace) return null;
      return Object.freeze({ ...selected.workspace, source: "picker" });
    }
    return null;
  }

  const maximumRetries = Number.isInteger(options.maxRetries)
    ? Math.max(0, Math.min(options.maxRetries, 2))
    : 1;
  let attempt = 0;
  while (isCommandAccountCurrent(accountScope)) {
    const result = await getWorkspaces(deps.workspaceAccess);
    if (!isCommandAccountCurrent(accountScope) || !result) return null;
    const workspaces = result.items
      .map(item => canonicalWorkspace(item))
      .filter(Boolean);
    const complete = result.complete === true && workspaces.length === result.items.length;
    const preferred = configuredIdentity(options.preferredWorkspace);
    const configuredDefault = options.ignoreDefault
      ? null
      : configuredIdentity(getDefaultWorkspace(deps.vscode));
    const preferredMatch = preferred
      ? workspaces.find(workspace => workspace.slug === preferred)
      : null;
    const defaultMatch = !preferred && configuredDefault
      ? workspaces.find(workspace => workspace.slug === configuredDefault)
      : null;

    if (!options.forcePrompt && preferredMatch) {
      return Object.freeze({ ...preferredMatch, source: "preferred" });
    }
    if (!options.forcePrompt && defaultMatch) {
      return Object.freeze({ ...defaultMatch, source: "default" });
    }
    if (!options.forcePrompt && complete && workspaces.length === 1) {
      return Object.freeze({ ...workspaces[0], source: "single" });
    }
    if (complete && workspaces.length === 0 && !options.allowClear) {
      deps.vscode.window.showInformationMessage(
        options.emptyMessage || "No Cloudsmith workspaces are available for this account."
      );
      return null;
    }

    const items = [];
    if (options.allowClear) {
      items.push({
        label: "$(close) Clear default workspace",
        description: "Show all workspaces",
        clear: true,
      });
    }
    if (!complete) {
      items.push(incompleteSeparator(
        deps.vscode,
        options.incompleteLabel || "Some workspaces could not be loaded"
      ));
    }
    items.push(...workspaces.map(workspace => ({
      label: workspace.name,
      description: workspace.slug,
      workspace,
    })));
    if (!complete && attempt < maximumRetries) items.push(retryItem("workspaces"));

    const selected = await showAccountQuickPick(deps, accountScope, items, {
      placeHolder: options.placeHolder || "Select a Cloudsmith workspace",
    });
    if (!isCommandAccountCurrent(accountScope) || !selected) return null;
    if (selected.retry) {
      attempt += 1;
      continue;
    }
    if (selected.clear && options.allowClear) return Object.freeze({ clear: true });
    if (!items.includes(selected) || !selected.workspace) return null;
    return Object.freeze({ ...selected.workspace, source: "picker" });
  }
  return null;
}

async function loadCommandRepositories(deps, accountScope, workspace) {
  const access = deps.workspaceAccess;
  if (typeof access?.fetchWorkspaceRepositories !== "function") {
    return getWorkspaceRepositories(access, workspace.slug);
  }
  const result = await access.fetchWorkspaceRepositories(access.context, workspace.slug, {
    account: accountScope.account,
    connectionManager: access.connectionManager,
    retry: "safe-read",
  });
  if (
    !isCommandAccountCurrent(accountScope)
    || result?.stale
    || result?.cancelled
  ) {
    return null;
  }
  return result;
}

async function resolveCommandRepository(deps, accountScope, options = {}) {
  if (!isCommandAccountCurrent(accountScope)) return null;
  if (options.explicitItem) {
    if (
      typeof options.currentSelection !== "function"
      || !options.currentSelection(options.explicitItem)
    ) {
      return null;
    }
    let adapted;
    try {
      adapted = deps.packageAdapters.fromRepositoryNode(options.explicitItem);
    } catch {
      deps.vscode.window.showWarningMessage(
        options.invalidMessage || "Could not determine repository details."
      );
      return null;
    }
    const candidate = canonicalRepository({
      workspace: adapted.workspace,
      slug: adapted.repository,
      name: adapted.name,
    });
    if (!candidate) {
      deps.vscode.window.showWarningMessage(
        options.invalidMessage || "Could not determine repository details."
      );
      return null;
    }
    const maximumRetries = Number.isInteger(options.maxRetries)
      ? Math.max(0, Math.min(options.maxRetries, 2))
      : 1;
    let workspace = null;
    let workspaceAttempt = 0;
    while (isCommandAccountCurrent(accountScope) && !workspace) {
      const workspaceResult = await getWorkspaces(deps.workspaceAccess);
      if (!isCommandAccountCurrent(accountScope) || !workspaceResult) return null;
      workspace = workspaceResult.items
        .map(item => canonicalWorkspace(item))
        .filter(Boolean)
        .find(item => item.slug === candidate.workspace) || null;
      if (workspace) break;
      if (workspaceResult.complete === true) {
        deps.vscode.window.showWarningMessage(
          options.invalidMessage || "Could not determine repository details."
        );
        return null;
      }
      if (workspaceAttempt >= maximumRetries) {
        deps.vscode.window.showWarningMessage(
          "Workspace choices are incomplete; the selected repository's workspace could not be verified."
        );
        return null;
      }
      const retry = retryItem("workspaces");
      const selected = await showAccountQuickPick(deps, accountScope, [
        incompleteSeparator(
          deps.vscode,
          "The repository workspace could not be verified because choices are incomplete"
        ),
        retry,
      ], { placeHolder: "Retry loading workspaces" });
      if (!isCommandAccountCurrent(accountScope) || !selected) return null;
      if (selected !== retry) return null;
      workspaceAttempt += 1;
    }

    let repositoryAttempt = 0;
    while (isCommandAccountCurrent(accountScope)) {
      const repositoryResult = await loadCommandRepositories(deps, accountScope, workspace);
      if (!isCommandAccountCurrent(accountScope) || !repositoryResult) return null;
      const repositories = repositoryResult.items
        .map(item => canonicalRepository(item, workspace))
        .filter(Boolean);
      const repository = repositories.find(item => item.slug === candidate.slug);
      if (repository) return Object.freeze({ ...repository, source: "explicit" });
      if (repositoryResult.complete === true) {
        deps.vscode.window.showWarningMessage(
          options.invalidMessage || "Could not determine repository details."
        );
        return null;
      }
      if (repositories.length === 0 && repositoryAttempt >= maximumRetries) {
        deps.vscode.window.showWarningMessage(
          "Repository choices are incomplete; the selected repository could not be verified."
        );
        return null;
      }
      const items = [incompleteSeparator(
        deps.vscode,
        "The selected repository could not be verified because choices are incomplete"
      )];
      items.push(...repositories.map(item => ({
        label: item.name,
        description: `${item.workspace}/${item.slug}`,
        repository: item,
      })));
      if (repositoryAttempt < maximumRetries) items.push(retryItem("repositories"));
      const selected = await showAccountQuickPick(deps, accountScope, items, {
        placeHolder: "Retry or select a verified repository",
      });
      if (!isCommandAccountCurrent(accountScope) || !selected) return null;
      if (selected.retry) {
        repositoryAttempt += 1;
        continue;
      }
      if (!items.includes(selected) || !selected.repository) return null;
      return Object.freeze({ ...selected.repository, source: "picker" });
    }
    return null;
  }

  let workspace = canonicalWorkspace(options.workspace);
  if (!workspace) {
    workspace = await resolveCommandWorkspace(
      deps,
      accountScope,
      options.workspaceOptions || {}
    );
  }
  if (!workspace || workspace.clear || !isCommandAccountCurrent(accountScope)) return null;

  const maximumRetries = Number.isInteger(options.maxRetries)
    ? Math.max(0, Math.min(options.maxRetries, 2))
    : 1;
  let attempt = 0;
  while (isCommandAccountCurrent(accountScope)) {
    const result = await loadCommandRepositories(deps, accountScope, workspace);
    if (!isCommandAccountCurrent(accountScope) || !result) return null;
    const repositories = result.items
      .map(item => canonicalRepository(item, workspace))
      .filter(Boolean);
    const complete = result.complete === true && repositories.length === result.items.length;
    const preferred = configuredIdentity(options.preferredRepository);
    const preferredMatch = preferred
      ? repositories.find(repository => repository.slug === preferred)
      : null;
    if (!options.forcePrompt && preferredMatch) {
      return Object.freeze({ ...preferredMatch, source: "preferred" });
    }
    if (
      !options.forcePrompt
      && !options.allowAll
      && !preferred
      && complete
      && repositories.length === 1
    ) {
      return Object.freeze({ ...repositories[0], source: "single" });
    }
    if (complete && repositories.length === 0 && !options.allowAll) {
      deps.vscode.window.showInformationMessage(
        options.emptyMessage
          || `No repositories are available in ${workspace.slug}.`
      );
      return null;
    }

    const items = [];
    if (options.allowAll) {
      items.push({
        label: "All repositories",
        description: `Search across ${workspace.slug}`,
        all: true,
      });
    }
    if (!complete) {
      items.push(incompleteSeparator(
        deps.vscode,
        options.incompleteLabel || "Some repositories could not be loaded"
      ));
    }
    items.push(...repositories.map(repository => ({
      label: repository.name,
      description: `${repository.workspace}/${repository.slug}`,
      repository,
    })));
    if (!complete && attempt < maximumRetries) items.push(retryItem("repositories"));

    const selected = await showAccountQuickPick(deps, accountScope, items, {
      placeHolder: options.placeHolder || `Select a repository in ${workspace.slug}`,
    });
    if (!isCommandAccountCurrent(accountScope) || !selected) return null;
    if (selected.retry) {
      attempt += 1;
      continue;
    }
    if (selected.all && options.allowAll) {
      return Object.freeze({ all: true, workspace: workspace.slug, source: "picker" });
    }
    if (!items.includes(selected) || !selected.repository) return null;
    return Object.freeze({ ...selected.repository, source: "picker" });
  }
  return null;
}

function collectionQuickPickItems(vscode, result, mapper, incompleteLabel) {
  const items = result.items.map(mapper);
  if (!result.complete) {
    items.unshift({
      label: incompleteLabel,
      kind: vscode.QuickPickItemKind.Separator,
    });
  }
  return items;
}

function adaptPackageSelection(packageAdapters, value) {
  try {
    return packageAdapters.fromPackageSelection(value);
  } catch {
    return null;
  }
}

function adaptRepositoryResolutionSelection(
  packageAdapters,
  packageDomain,
  value,
  options = {}
) {
  const adapted = packageAdapters.fromExactPackageSelectionIfPresent(value);
  const exactPackage = adapted ? packageDomain.assertExactPackage(adapted) : null;
  return Object.freeze({
    exactPackage,
    resolution: packageAdapters.fromPackageResolutionSelection(
      exactPackage || value,
      options
    ),
  });
}

function adaptInstallSelection(packageAdapters, packageDomain, value) {
  const adapted = packageAdapters.fromExactPackageSelectionIfPresent(value);
  if (adapted) {
    const exactPackage = packageDomain.assertExactPackage(adapted);
    return Object.freeze({ exactPackage, package: exactPackage });
  }
  const coordinate = packageAdapters.fromRepositoryPackageSelection(value, {
    defaultVersion: "latest",
  });
  return Object.freeze({ exactPackage: null, package: coordinate });
}

async function pickRecentPackage(deps, options = {}) {
  const predicate = typeof options.predicate === "function" ? options.predicate : () => true;
  const currentSelection = typeof options.currentSelection === "function"
    ? options.currentSelection
    : () => false;
  const accountScope = options.accountScope
    || captureCommandAccount(deps.workspaceAccess);
  if (!isCommandAccountCurrent(accountScope)) return null;
  const recent = deps.recentPackages.getAll().filter(pkg => (
    predicate(pkg) && currentSelection(pkg)
  ));
  if (recent.length === 0) {
    deps.vscode.window.showInformationMessage(
      options.emptyMessage
        || "No recent packages are available. Open or inspect a package, then try again."
    );
    return null;
  }
  const items = recent.map(pkg => ({
    label: `${safeDisplayName(pkg.name, "Package", 2048)} ${safeDisplayName(
      pkg.version,
      "Unknown version",
      2048
    )}`,
    description: `${safeDisplayName(pkg.format, "unknown", 64)} — ${safeDisplayName(
      pkg.workspace,
      "unknown-workspace",
      512
    )}/${safeDisplayName(pkg.repository, "unknown-repository", 512)}`,
    package: pkg,
  }));
  const selected = await showAccountQuickPick(
    deps,
    accountScope,
    items,
    { placeHolder: options.placeHolder || "Select a package" }
  );
  if (
    !isCommandAccountCurrent(accountScope)
    || !selected
    || !items.includes(selected)
    || !selected.package
    || !predicate(selected.package)
    || !currentSelection(selected.package)
  ) {
    return null;
  }
  return selected.package;
}

function isQuarantinedPackage(pkg) {
  return Boolean(pkg) && pkg.status === "Quarantined";
}

function installOptions(vscode, pkg) {
  const options = {};
  if (pkg.tags && (pkg.tags.info.length > 0 || pkg.tags.version.length > 0)) {
    options.tags = pkg.tags;
  }
  if (
    vscode.workspace.getConfiguration("cloudsmith-vsc").get("showDockerDigestCommand", false)
  ) {
    if (pkg.checksumSha256) options.checksumSha256 = pkg.checksumSha256;
    if (pkg.versionDigest) options.versionDigest = pkg.versionDigest;
  }
  if (pkg.cdnUrl) options.cdnUrl = pkg.cdnUrl;
  if (pkg.filename) options.filename = pkg.filename;
  return options;
}

function buildInstallCommand(deps, pkg) {
  try {
    return deps.InstallCommandBuilder.build(
      pkg.format,
      pkg.name,
      pkg.version || "latest",
      pkg.workspace,
      pkg.repository,
      installOptions(deps.vscode, pkg)
    );
  } catch (error) {
    if (error instanceof deps.InstallCommandValidationError) {
      deps.vscode.window.showErrorMessage(
        `Could not safely generate install command: ${error.message}`
      );
      return null;
    }
    throw error;
  }
}

async function pickInstallCommandVariant(deps, result, options = {}) {
  if (!result.alternatives || result.alternatives.length === 0) {
    return result.command;
  }
  const picks = [
    {
      label: "$(arrow-right) Primary",
      description: deps.InstallCommandBuilder.toClipboardCommand(result.command),
      command: result.command,
    },
    ...result.alternatives.map(alternative => ({
      label: `$(arrow-right) ${alternative.label}`,
      description: deps.InstallCommandBuilder.toClipboardCommand(alternative.command),
      command: alternative.command,
    })),
  ];
  const promptOptions = { placeHolder: "Select an install command" };
  const selected = options.accountScope
    ? await showAccountQuickPick(deps, options.accountScope, picks, promptOptions)
    : await deps.vscode.window.showQuickPick(picks, promptOptions);
  return selected ? selected.command : null;
}

function commentCommandNote(note) {
  return String(note)
    .split(/\r?\n/)
    .map(line => `# ${line}`)
    .join("\n");
}

function buildAdvancedSearchQuery(SearchQueryBuilder, query) {
  if (query == null || query === "") return "";
  return new SearchQueryBuilder().advanced(query).build();
}

function buildPresetQuery(SearchQueryBuilder, preset, customQuery) {
  if (!preset) return "";
  if (preset.applyBuilder === null) {
    return buildAdvancedSearchQuery(SearchQueryBuilder, customQuery || "");
  }
  const builder = new SearchQueryBuilder();
  const maybeString = preset.applyBuilder(builder);
  return typeof maybeString === "string" ? maybeString : builder.build();
}

function createFilterPresets(LicenseClassifier) {
  return Object.freeze([
    { label: "All packages", applyBuilder: () => "" },
    {
      label: "Available packages",
      applyBuilder: builder => builder
        .raw("NOT status:quarantined")
        .raw("deny_policy_violated:false"),
    },
    { label: "Quarantined packages", applyBuilder: builder => builder.status("quarantined") },
    {
      label: "Packages with policy violations",
      applyBuilder: builder => builder.raw("policy_violated:true"),
    },
    {
      label: "$(shield) Vulnerable packages",
      description: "Packages with known vulnerabilities",
      applyBuilder: builder => builder.raw("vulnerabilities:>0"),
    },
    {
      label: "Packages with vulnerability violations",
      applyBuilder: builder => builder.raw("vulnerability_policy_violated:true"),
    },
    {
      label: "Packages with license violations",
      applyBuilder: builder => builder.raw("license_policy_violated:true"),
    },
    {
      label: "Packages with restrictive licenses",
      applyBuilder: builder => builder.raw(LicenseClassifier.buildRestrictiveQuery()),
    },
    { label: "Custom query", applyBuilder: null },
  ]);
}

module.exports = {
  adaptInstallSelection,
  adaptPackageSelection,
  adaptRepositoryResolutionSelection,
  buildInstallCommand,
  buildPresetQuery,
  buildAdvancedSearchQuery,
  canonicalRepository,
  captureCommandAccount,
  isCommandAccountCurrent,
  collectionQuickPickItems,
  commentCommandNote,
  createFilterPresets,
  firstCollectionFailureMessage,
  getDefaultWorkspace,
  getWorkspaces,
  getWorkspaceRepositories,
  isQuarantinedPackage,
  pickInstallCommandVariant,
  pickRecentPackage,
  resolveCommandRepository,
  resolveCommandWorkspace,
  safeDisplayName,
  showAccountInputBox,
  showAccountQuickPick,
};

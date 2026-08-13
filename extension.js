const vscode = require("vscode");
const { CloudsmithProvider } = require("./views/cloudsmithProvider");
const { helpProvider } = require("./views/helpProvider");
const { SearchProvider } = require("./views/searchProvider");
const { CloudsmithAPI } = require("./util/cloudsmithAPI");
const { apiEndpoint } = require("./util/apiEndpoint");
const { CredentialManager, runCLIAutoDetect } = require("./util/credentialManager");
const {
  ConnectionManager,
  bindConnectionManager,
  getConnectionManager,
} = require("./util/connectionManager");
const { RecentSearches } = require("./util/recentSearches");
const { RemediationHelper } = require("./util/remediationHelper");
const {
  DependencyHealthProvider,
  FILTER_MODES,
  SORT_MODES,
} = require("./views/dependencyHealthProvider");
const {
  InstallCommandBuilder,
  InstallCommandValidationError,
} = require("./util/installCommandBuilder");
const { VulnerabilityProvider } = require("./views/vulnerabilityProvider");
const { ComplianceReportProvider } = require("./views/complianceReportProvider");
const { QuarantineExplainProvider } = require("./views/quarantineExplainProvider");
const { DiagnosticsPublisher } = require("./util/diagnosticsPublisher");
const { SSOAuthManager } = require("./util/ssoAuthManager");
const { UpstreamChecker } = require("./util/upstreamChecker");
const { UpstreamPreviewProvider } = require("./views/upstreamPreviewProvider");
const { UpstreamDetailProvider } = require("./views/upstreamDetailProvider");
const { PromotionProvider } = require("./views/promotionProvider");
const { normalizePackageQueryIdentity } = require("./util/promotionContracts");
const { SearchQueryBuilder } = require("./util/searchQueryBuilder");
const { formatApiError } = require("./util/errorFormatter");
const { LicenseClassifier } = require("./util/licenseClassifier");
const { fetchRepositoryUpstreams, generateTerraformConfig } = require("./util/terraformExporter");
const { SUPPORTED_UPSTREAM_FORMATS } = require("./util/upstreamFormats");
const { buildPackageGroupUrl, buildPackageUrl } = require("./util/webAppUrls");
const recentPackages = require("./util/recentPackages");
const filterState = require("./util/filterState");
const { clearVulnerabilityCache } = require("./util/dependencyVulnEnricher");
const { VulnerabilityStateService } = require("./util/vulnerabilityStateService");
const { WorkspaceCache } = require("./util/workspaceCache");
const { getWorkspaceContextProjector } = require("./util/workspaceContextProjector");
const { captureAccount, isAccountCurrent } = require("./util/accountOperation");
const { fetchWorkspaces, normalizedWorkspaceName } = require("./util/workspaceFetcher");
const { fetchWorkspaceRepositories } = require("./util/workspaceRepositoryFetcher");
const { PaginatedFetch, replaceCollectionItems } = require("./util/paginatedFetch");
const { packageCollectionIdentity } = require("./util/collectionIdentity");
const {
  connectionSetupAvailable,
} = require("./util/connectionPresentation");

let exportTerraformAbortController = null;
let activeActivationOwner = null;

class ActivationOwner {
  constructor(reportFailure = () => {
    console.warn("[Cloudsmith] An activation resource could not be disposed cleanly.");
  }) {
    this._resources = [];
    this._pending = [];
    this._disposed = false;
    this._reportFailure = reportFailure;
  }

  add(...resources) {
    for (const resource of resources) {
      if (!resource || typeof resource.dispose !== "function") {
        throw new TypeError("Activation resources must be disposable.");
      }
      if (this._disposed) {
        this._disposeResource(resource);
      } else {
        this._resources.push(resource);
      }
    }
  }

  dispose() {
    if (this._disposed) return;
    this._disposed = true;
    for (const resource of this._resources.splice(0).reverse()) {
      this._disposeResource(resource);
    }
  }

  async settle() {
    const pending = this._pending.splice(0);
    if (pending.length > 0) {
      const results = await Promise.allSettled(pending);
      if (results.some(result => result.status === "rejected")) {
        this._reportFailure();
      }
    }
  }

  _disposeResource(resource) {
    try {
      const result = resource.dispose();
      if (result && typeof result.then === "function") {
        this._pending.push(Promise.resolve(result));
      }
    } catch {
      this._reportFailure();
    }
  }
}

/**
 * Helper: unwrap a property that may be stored as:
 *   - a raw string: "value"
 *   - a single-wrapped object: { id: "Name", value: "value" }
 *   - a double-wrapped object (from the getChildren double-wrap bug):
 *     { id: "Name", value: { id: "Name", value: "value" } }
 * Returns the raw string value in all cases.
 */
function unwrapValue(prop) {
  if (prop == null) {
    return null;
  }
  if (typeof prop === "string") {
    return prop;
  }
  if (typeof prop === "object" && prop.value != null) {
    // Could be double-wrapped: { value: { value: "str" } }
    if (typeof prop.value === "object" && prop.value.value != null) {
      return String(prop.value.value);
    }
    return String(prop.value);
  }
  return String(prop);
}

/**
 * Helper: extract package properties from different node types.
 * Handles PackageNode (double-wrapped from tree), SearchResultNode (single-wrapped),
 * and DependencyHealthNode (mixed). Uses unwrapValue for safe extraction.
 */
function extractPackageInfo(item) {
  return {
    name: item.name,
    format: item.format,
    version: unwrapValue(item.version) || (item.declaredVersion || null),
    workspace: item.namespace || null,
    repo: item.repository || null,
    slugPerm: unwrapValue(item.slug_perm),
    slug: unwrapValue(item.slug),
  };
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function getNestedInstallField(item, fieldName) {
  if (!item || typeof item !== "object") {
    return null;
  }
  if (item[fieldName] != null) {
    return item[fieldName];
  }
  if (item.cloudsmithMatch && item.cloudsmithMatch[fieldName] != null) {
    return item.cloudsmithMatch[fieldName];
  }
  return null;
}

function isInspectedPackageArray(value, workspace, repository, name) {
  return Array.isArray(value) && value.every(pkg => (
    pkg
    && typeof pkg === "object"
    && !Array.isArray(pkg)
    && pkg.namespace === workspace
    && pkg.repository === repository
    && pkg.name === name
    && typeof pkg.slug_perm === "string"
    && pkg.slug_perm.length > 0
    && pkg.slug_perm.length <= 512
  ));
}

function isQuarantinedPackage(item) {
  const status = unwrapValue(item && item.status_str) ||
    (item && item.status_str_raw) ||
    getNestedInstallField(item, "status_str");
  return status === "Quarantined";
}

function getInstallTags(item) {
  if (!item || typeof item !== "object") {
    return null;
  }

  if (item.tags_raw && typeof item.tags_raw === "object" && !Array.isArray(item.tags_raw)) {
    return item.tags_raw;
  }

  if (item.tags && typeof item.tags === "object" && !Array.isArray(item.tags)) {
    if (!(item.tags.id && Object.prototype.hasOwnProperty.call(item.tags, "value"))) {
      return item.tags;
    }
  }

  if (item.cloudsmithMatch && item.cloudsmithMatch.tags && typeof item.cloudsmithMatch.tags === "object") {
    return item.cloudsmithMatch.tags;
  }

  return null;
}

function getInstallOptions(item) {
  const installOpts = {};
  const tags = getInstallTags(item);
  if (tags) {
    installOpts.tags = tags;
  }

  const showDigest = vscode.workspace.getConfiguration("cloudsmith-vsc").get("showDockerDigestCommand", false);
  if (showDigest) {
    const checksumSha256 = getNestedInstallField(item, "checksum_sha256");
    if (checksumSha256) {
      installOpts.checksumSha256 = checksumSha256;
    }

    const versionDigest = getNestedInstallField(item, "version_digest");
    if (versionDigest) {
      installOpts.versionDigest = versionDigest;
    }
  }

  const cdnUrl = getNestedInstallField(item, "cdn_url");
  if (cdnUrl) {
    installOpts.cdnUrl = cdnUrl;
  }

  const filename = getNestedInstallField(item, "filename");
  if (filename) {
    installOpts.filename = filename;
  }

  return installOpts;
}

function buildInstallCommand(format, name, version, workspace, repo, item) {
  try {
    return InstallCommandBuilder.build(
      format,
      name,
      version,
      workspace,
      repo,
      getInstallOptions(item)
    );
  } catch (error) {
    if (error instanceof InstallCommandValidationError) {
      vscode.window.showErrorMessage(`Could not safely generate install command: ${error.message}`);
      return null;
    }
    throw error;
  }
}

function commentCommandNote(note) {
  return String(note)
    .split(/\r?\n/)
    .map(line => `# ${line}`)
    .join("\n");
}

async function pickInstallCommandVariant(result) {
  if (!result.alternatives || result.alternatives.length === 0) {
    return result.command;
  }

  const picks = [
    {
      label: "$(arrow-right) Primary",
      description: InstallCommandBuilder.toClipboardCommand(result.command),
      _cmd: result.command,
    },
    ...result.alternatives.map(a => ({
      label: `$(arrow-right) ${a.label}`,
      description: InstallCommandBuilder.toClipboardCommand(a.command),
      _cmd: a.command,
    })),
  ];

  const pick = await vscode.window.showQuickPick(picks, {
    placeHolder: "Select an install command",
  });
  return pick ? pick._cmd : null;
}

/**
 * Prompt user to select from recently interacted packages.
 * Returns a package-like object or null if no selection made.
 */
async function pickRecentPackage(options = {}) {
  const predicate = typeof options.predicate === "function" ? options.predicate : () => true;
  const recent = recentPackages.getAll().filter(predicate);
  if (recent.length === 0) {
    vscode.window.showInformationMessage(
      options.emptyMessage || "No recent packages. Run this command from a package context menu."
    );
    return null;
  }
  const selected = await vscode.window.showQuickPick(
    recent.map(p => ({
      label: p.name,
      description: `${p.version || ""} — ${p.repository || ""}`,
      _pkg: p,
    })),
    { placeHolder: options.placeHolder || "Select a package" }
  );
  if (!selected) {
    return null;
  }
  return selected._pkg;
}

const FILTER_PRESETS = [
    {
      label: "All packages",
      applyBuilder: () => "",
    },
    {
      label: "Available packages",
      applyBuilder: (builder) => builder
        .raw("NOT status:quarantined")
        .raw("deny_policy_violated:false"),
    },
    {
      label: "Quarantined packages",
      applyBuilder: (builder) => builder.status("quarantined"),
    },
    {
      label: "Packages with policy violations",
      applyBuilder: (builder) => builder.raw("policy_violated:true"),
    },
    {
      label: "$(shield) Vulnerable packages",
      description: "Packages with known vulnerabilities",
      applyBuilder: (builder) => builder.raw("vulnerabilities:>0"),
    },
    {
      label: "Packages with vulnerability violations",
      applyBuilder: (builder) => builder.raw("vulnerability_policy_violated:true"),
    },
    {
      label: "Packages with license violations",
      applyBuilder: (builder) => builder.raw("license_policy_violated:true"),
    },
    {
      label: "Packages with restrictive licenses",
      applyBuilder: (builder) => builder.raw(LicenseClassifier.buildRestrictiveQuery()),
    },
    {
      label: "Custom query",
      applyBuilder: null,
    },
];

const FORMAT_OPTIONS = SUPPORTED_UPSTREAM_FORMATS;

/**
 * Helper: read the defaultWorkspace setting.
 * Returns the slug string if set, or empty string if not.
 */
function getDefaultWorkspace() {
  const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
  return config.get("defaultWorkspace") || "";
}

async function setHasMultipleWorkspacesContext(context, hasMultipleWorkspaces, options = {}) {
  const projector = options.workspaceContextProjector
    || getWorkspaceContextProjector(context);
  return projector.project(hasMultipleWorkspaces, options);
}

async function evictPersistedUpstreamCaches(context) {
  const accountCacheKeys = typeof context?.globalState?.keys === "function"
    ? context.globalState.keys().filter(key => key.startsWith("cloudsmith-upstreams:"))
    : [];
  const evictions = await Promise.allSettled(
    accountCacheKeys.map(key => context.globalState.update(key, undefined))
  );
  const complete = evictions.every(result => result.status === "fulfilled");
  if (!complete) {
    console.warn("[Cloudsmith] Some stale account cache entries could not be evicted.");
  }
  return complete;
}

async function resetAccountScopedState(context, options = {}) {
  const reset = beginAccountScopedStateReset(options);
  return completeAccountScopedStateReset(context, options, reset);
}

function beginAccountScopedStateReset(options = {}) {
  const synchronousInvalidators = [
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
  for (const invalidate of synchronousInvalidators) {
    try {
      invalidate();
    } catch (error) {
      syncFailures.push(error);
    }
  }

  return Object.freeze({ syncFailures });
}

async function completeAccountScopedStateReset(context, options, reset) {
  // Start each fallible authority projection independently. A rejected tree or
  // context update must not retain another cache from the previous account.
  const asynchronousInvalidators = [
    () => options.dependencyHealthProvider?.resetForAccountChange?.(options.accountState),
    () => (options.projectHasMultipleWorkspaces
      ? options.projectHasMultipleWorkspaces(false)
      : setHasMultipleWorkspacesContext(context, false, {
        workspaceContextProjector: options.workspaceContextProjector,
      })),
    () => (options.evictPersistedUpstreamCaches || evictPersistedUpstreamCaches)(context),
  ];
  const pending = asynchronousInvalidators.map(invalidate => {
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

async function updateDefaultWorkspaceContext() {
  await vscode.commands.executeCommand(
    "setContext",
    "cloudsmith.hasDefaultWorkspace",
    Boolean(getDefaultWorkspace())
  );
}

async function getWorkspaces(context, options = {}) {
    const connectionManager = options.connectionManager || getConnectionManager(context);
    const workspaceContextProjector = options.workspaceContextProjector
      || getWorkspaceContextProjector(context);
    const account = captureAccount(connectionManager);
    if (!account) {
        await setHasMultipleWorkspacesContext(context, false, { workspaceContextProjector });
        return null;
    }
    const projection = workspaceContextProjector.begin({
      isCurrent: () => isAccountCurrent(connectionManager, account),
    });
    const cloudsmithAPI = options.createCloudsmithAPI
      ? options.createCloudsmithAPI()
      : new CloudsmithAPI(context);
    const workspaceFetcher = options.fetchWorkspaces || fetchWorkspaces;
    const result = await workspaceFetcher(context, {
        account,
        cloudsmithAPI,
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
      const detail = firstCollectionFailureMessage(normalizedResult);
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

async function getWorkspaceRepositories(context, workspace, options = {}) {
  const connectionManager = options.connectionManager || getConnectionManager(context);
  const result = await fetchWorkspaceRepositories(context, workspace, {
    connectionManager,
    retry: "safe-read",
    ...options,
  });
  if (!result.complete) {
    const detail = firstCollectionFailureMessage(result);
    if (result.items.length === 0) {
      vscode.window.showErrorMessage(`Could not load repositories completely.${detail}`);
    } else {
      vscode.window.showWarningMessage(
        `Repository choices are incomplete; later repositories may be unavailable.${detail}`
      );
    }
  }
  return result;
}

function firstCollectionFailureMessage(result) {
  const error = result && result.failures && result.failures[0] && result.failures[0].error;
  return error ? ` ${formatApiError(error)}` : "";
}

function collectionQuickPickItems(result, mapper, incompleteLabel) {
  const items = result.items.map(mapper);
  if (!result.complete) {
    items.unshift({
      label: incompleteLabel,
      kind: vscode.QuickPickItemKind.Separator,
    });
  }
  return items;
}

async function getPreferredTextDocumentLanguage() {
  const availableLanguages = new Set(await vscode.languages.getLanguages());
  if (availableLanguages.has("terraform")) {
    return "terraform";
  }
  if (availableLanguages.has("hcl")) {
    return "hcl";
  }
  return "plaintext";
}

function buildRawSearchQuery(query) {
  return new SearchQueryBuilder().raw(query).build();
}

function buildPresetQuery(preset, customQuery) {
  if (!preset) {
    return "";
  }
  if (preset.applyBuilder === null) {
    return buildRawSearchQuery(customQuery || "");
  }
  const builder = new SearchQueryBuilder();
  const maybeString = preset.applyBuilder(builder);
  if (typeof maybeString === "string") {
    return maybeString;
  }
  return builder.build();
}

function searchDescriptorFromRecent(entry) {
  const scope = entry && entry.scope;
  if (!scope || typeof scope !== "object" || Array.isArray(scope)) return null;
  const scopeKeys = Object.keys(scope).sort().join(",");
  if (
    scope.kind === "repository"
    && scopeKeys === "kind,repository"
    && typeof scope.repository === "string"
  ) {
    return {
      kind: "repository",
      workspace: entry.workspace,
      repository: scope.repository,
      query: entry.query,
      page: 1,
    };
  }
  if (
    scope.kind === "repositories"
    && scopeKeys === "kind,repositories"
    && Array.isArray(scope.repositories)
  ) {
    return {
      kind: "repositories",
      workspace: entry.workspace,
      repositories: scope.repositories,
      query: entry.query,
      page: 1,
    };
  }
  return scope.kind === "workspace" && scopeKeys === "kind"
    ? {
      kind: "workspace",
      workspace: entry.workspace,
      query: entry.query,
      page: 1,
    }
    : null;
}

async function executeSearchIntent(searchProvider, descriptor, options = {}) {
  const operation = searchProvider.beginSearch(descriptor);
  const execution = searchProvider.executeSearch(operation);
  if (options.recentSearches && options.record) {
    const ownedDescriptor = operation.descriptor;
    let scope = { kind: "workspace" };
    if (ownedDescriptor.kind === "repository") {
      scope = { kind: "repository", repository: ownedDescriptor.repository };
    } else if (ownedDescriptor.kind === "repositories") {
      scope = { kind: "repositories", repositories: ownedDescriptor.repositories };
    }
    // History persistence is deliberately detached: it must never delay or
    // supersede execution of the synchronously owned search operation.
    Promise.resolve().then(() => options.recentSearches.add({
      workspace: ownedDescriptor.workspace,
      query: ownedDescriptor.query,
      scope,
    })).catch(() => {
      console.warn("[Cloudsmith] Could not save the recent search.");
    });
  }
  return execution;
}

async function resolveDependencyScanTarget(context, options = {}) {
  const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
  let scanWorkspace = options.forcePrompt ? null : config.get("dependencyScanWorkspace");
  let scanRepo = options.forcePrompt ? null : (config.get("dependencyScanRepo") || null);

  if (!scanWorkspace && !options.forcePrompt) {
    scanWorkspace = getDefaultWorkspace();
  }

  if (scanWorkspace) {
    return {
      scanWorkspace,
      scanRepo,
    };
  }

  const workspaceResult = await getWorkspaces(context);
  if (!workspaceResult) {
    return null;
  }
  if (workspaceResult.items.length === 0) {
    if (workspaceResult.complete) {
      vscode.window.showErrorMessage("No workspaces found. Connect to Cloudsmith first.");
    }
    return null;
  }

  const selectedWorkspace = await vscode.window.showQuickPick(
    collectionQuickPickItems(
      workspaceResult,
      workspace => ({ label: workspace.name, description: workspace.slug }),
      "Workspace list incomplete"
    ),
    {
      placeHolder: "Select a Cloudsmith workspace for the scan",
    }
  );

  if (!selectedWorkspace) {
    return null;
  }

  scanWorkspace = selectedWorkspace.description;

  const selectedScope = await vscode.window.showQuickPick(
    [
      {
        label: "All repositories",
        description: "Search across the entire workspace",
        _all: true,
      },
      {
        label: "Select a specific repository",
        description: "Search one repository",
        _all: false,
      },
    ],
    {
      placeHolder: "Select a scan scope",
    }
  );

  if (!selectedScope) {
    return null;
  }

  if (!selectedScope._all) {
    const repositories = await getWorkspaceRepositories(context, scanWorkspace);
    if (repositories.items.length > 0) {
      const selectedRepo = await vscode.window.showQuickPick(
        collectionQuickPickItems(
          repositories,
          repository => ({ label: repository.name, description: repository.slug }),
          "Repository list incomplete"
        ),
        {
          placeHolder: "Select a repository",
        }
      );

      if (selectedRepo) {
        scanRepo = selectedRepo.description;
      }
    } else if (repositories.complete) {
      vscode.window.showInformationMessage("No repositories were found in this workspace.");
      return null;
    } else {
      return null;
    }
  }

  return {
    scanWorkspace,
    scanRepo,
  };
}

async function runDependencyScan(provider, resolveInitialTarget) {
  const initialScan = async () => {
    const scanTarget = await resolveInitialTarget();
    if (!scanTarget) {
      return null;
    }

    return provider.scan(scanTarget.scanWorkspace, scanTarget.scanRepo);
  };

  if (provider.hasSuccessfulScan()) {
    return provider.rescan(initialScan);
  }

  return initialScan();
}

function buildDependencySortFilterItems(provider) {
  const currentSort = provider.getSortMode();
  const currentFilter = provider.getFilterMode();
  return [
    {
      label: "Sort",
      kind: vscode.QuickPickItemKind.Separator,
    },
    createDependencyPickerItem(
      "Alphabetical",
      "Default ordering",
      "sort",
      SORT_MODES.ALPHABETICAL,
      currentSort === SORT_MODES.ALPHABETICAL
    ),
    createDependencyPickerItem(
      "Severity",
      "Most severe first",
      "sort",
      SORT_MODES.SEVERITY,
      currentSort === SORT_MODES.SEVERITY
    ),
    createDependencyPickerItem(
      "Coverage",
      "Not found first",
      "sort",
      SORT_MODES.COVERAGE,
      currentSort === SORT_MODES.COVERAGE
    ),
    {
      label: "Filters",
      kind: vscode.QuickPickItemKind.Separator,
    },
    createDependencyPickerItem(
      "Vulnerable only",
      "Toggle vulnerable dependencies",
      "filter",
      FILTER_MODES.VULNERABLE,
      currentFilter === FILTER_MODES.VULNERABLE
    ),
    createDependencyPickerItem(
      "Not in Cloudsmith",
      "Toggle uncovered dependencies",
      "filter",
      FILTER_MODES.UNCOVERED,
      currentFilter === FILTER_MODES.UNCOVERED
    ),
    createDependencyPickerItem(
      "Restrictive licenses",
      "Toggle restrictive or weak copyleft results",
      "filter",
      FILTER_MODES.RESTRICTIVE_LICENSE,
      currentFilter === FILTER_MODES.RESTRICTIVE_LICENSE
    ),
    createDependencyPickerItem(
      "Policy violations",
      "Toggle policy failures",
      "filter",
      FILTER_MODES.POLICY_VIOLATION,
      currentFilter === FILTER_MODES.POLICY_VIOLATION
    ),
    createDependencyPickerItem(
      "Show all dependencies",
      "Clear active dependency filters",
      "filter",
      null,
      currentFilter === null
    ),
  ];
}

function createDependencyPickerItem(label, description, action, value, active) {
  return {
    label: `${active ? "$(check)" : "$(circle-large-outline)"} ${label}`,
    description,
    _action: action,
    _value: value,
  };
}

async function showDependencySortFilterPicker(provider) {
  await new Promise((resolve) => {
    const quickPick = vscode.window.createQuickPick();
    const disposables = [];

    const refreshItems = () => {
      quickPick.items = buildDependencySortFilterItems(provider);
    };

    quickPick.title = "Sort & filter dependencies";
    quickPick.matchOnDescription = true;
    quickPick.ignoreFocusOut = true;
    refreshItems();

    disposables.push(quickPick.onDidAccept(async () => {
      const selected = quickPick.selectedItems[0];
      if (!selected || !selected._action) {
        quickPick.hide();
        return;
      }

      quickPick.busy = true;
      try {
        if (selected._action === "sort") {
          provider.setSortMode(selected._value);
        } else if (selected._value === null || provider.getFilterMode() === selected._value) {
          await provider.clearFilter();
        } else {
          await provider.setFilterMode(selected._value);
        }
        refreshItems();
      } finally {
        quickPick.busy = false;
      }
    }));

    disposables.push(quickPick.onDidHide(() => {
      quickPick.dispose();
      for (const disposable of disposables) {
        disposable.dispose();
      }
      resolve();
    }));

    quickPick.show();
  });
}


/**
 * @param {vscode.ExtensionContext} context
 */
async function activate(context) {
  await deactivate();
  const owner = new ActivationOwner();
  activeActivationOwner = owner;
  context.subscriptions.push(owner);
  const own = (...resources) => owner.add(...resources);
  try {
    return await activateOwned(context, own);
  } catch (error) {
    owner.dispose();
    await owner.settle();
    if (activeActivationOwner === owner) activeActivationOwner = null;
    throw error;
  }
}

async function activateOwned(context, own) {
  const connectionManager = new ConnectionManager(context);
  const connectionBinding = bindConnectionManager(context, connectionManager);
  own(connectionBinding, connectionManager);
  const inspectOutputChannel = vscode.window.createOutputChannel("Cloudsmith");
  own(inspectOutputChannel);
  own({
    dispose() {
      if (exportTerraformAbortController) {
        exportTerraformAbortController.abort();
        exportTerraformAbortController = null;
      }
    },
  });

  // Persisted upstream summaries are account-bound. Purge them before the
  // initial SecretStorage read so an indeterminate startup cannot retain data
  // from a prior activation or account.
  await evictPersistedUpstreamCaches(context);
  const workspaceContextProjector = getWorkspaceContextProjector(context);
  own(workspaceContextProjector);
  await setHasMultipleWorkspacesContext(context, false, { workspaceContextProjector });
  await updateDefaultWorkspaceContext();

  // Define main view provider which populates with data
  const workspaceCache = new WorkspaceCache(connectionManager);
  const vulnerabilityStateService = new VulnerabilityStateService(context, {
    connectionManager,
  });
  own(vulnerabilityStateService);
  const cloudsmithProvider = new CloudsmithProvider(context, {
    connectionManager,
    workspaceCache,
    workspaceContextProjector,
    vulnerabilityStateService,
    accountResetOrchestrated: true,
  });
  own({ dispose: () => cloudsmithProvider.dispose() });
  const treeView = vscode.window.createTreeView("cloudsmithView", {
    treeDataProvider: cloudsmithProvider,
    showCollapseAll: true,
  });
  own(treeView);
  cloudsmithProvider.setTreeView(treeView);
  cloudsmithProvider.setDefaultWorkspaceFallbackHandler((slug) => {
    treeView.title = "Workspaces";
    treeView.description = "";
    vscode.window.showWarningMessage(
      `Could not verify the repository list for workspace "${slug}". Showing all workspaces.`
    );
  });

  // Set tree view title and description from default workspace setting
  const defaultWs = getDefaultWorkspace();
  if (defaultWs) {
    treeView.title = "Repositories";
    treeView.description = defaultWs;
  }

  // Listen for configuration changes to refresh tree when defaultWorkspace changes
  own(
    vscode.workspace.onDidChangeConfiguration(async e => {
      if (e.affectsConfiguration("cloudsmith-vsc.defaultWorkspace")) {
        await updateDefaultWorkspaceContext();
        const newDefault = getDefaultWorkspace();
        treeView.title = newDefault ? "Repositories" : "Workspaces";
        treeView.description = newDefault || "";
        cloudsmithProvider.refresh();
      }
    })
  );

  // Set Help & Feedback view.
  const provider = new helpProvider();
  own(vscode.window.registerTreeDataProvider("helpView", provider));

  // Set Package Search view.
  const searchProvider = new SearchProvider(context, {
    connectionManager,
    vulnerabilityStateService,
  });
  const searchTreeView = vscode.window.createTreeView("cloudsmithSearchView", {
    treeDataProvider: searchProvider,
    showCollapseAll: true,
  });
  own(searchTreeView);
  searchProvider.setTreeView(searchTreeView);

  // Set Dependency Health view with diagnostics publisher.
  const diagnosticsPublisher = new DiagnosticsPublisher();
  own(diagnosticsPublisher);
  const dependencyHealthProvider = new DependencyHealthProvider(context, diagnosticsPublisher, {
    connectionManager,
    vulnerabilityStateService,
    accountResetOrchestrated: true,
  });
  own(
    { dispose: () => searchProvider.dispose() },
    { dispose: () => dependencyHealthProvider.dispose() }
  );
  const dependencyTreeView = vscode.window.createTreeView("cloudsmithDependencyHealthView", {
    treeDataProvider: dependencyHealthProvider,
    showCollapseAll: false,
  });
  own(dependencyTreeView);
  dependencyHealthProvider.setTreeView(dependencyTreeView);

  let projectedAccountIdentity = connectionManager.getState();
  let accountResetQueue = Promise.resolve();
  own({ dispose: () => accountResetQueue });
  let promotionProvider = null;
  let vulnerabilityProvider = null;
  let quarantineExplainProvider = null;
  let upstreamPreviewProvider = null;
  let upstreamDetailProvider = null;
  let connectionPresentationProjection = Promise.resolve();
  let connectionPresentationProjectionDisposed = false;
  own({ dispose: () => { connectionPresentationProjectionDisposed = true; } });
  const projectConnectionPresentation = (state) => {
    const setupAvailable = connectionSetupAvailable(state);
    const project = async () => {
      if (connectionPresentationProjectionDisposed) return;
      await vscode.commands.executeCommand(
        "setContext",
        "cloudsmith.connectionSetupAvailable",
        setupAvailable
      );
    };
    const run = connectionPresentationProjection.then(project, project);
    connectionPresentationProjection = run.catch(() => {
      console.warn("[Cloudsmith] Could not update the connection presentation indicator.");
    });
    return run;
  };
  const connectionSubscription = connectionManager.onDidChange(state => {
    void projectConnectionPresentation(state).catch(() => {});
    if (
      state.accountEpoch !== projectedAccountIdentity.accountEpoch
      || state.activationId !== projectedAccountIdentity.activationId
    ) {
      projectedAccountIdentity = state;
      const resetOptions = {
        workspaceCache,
        cloudsmithProvider,
        accountState: state,
        promotionProvider,
        dependencyHealthProvider,
        workspaceContextProjector,
        vulnerabilityStateService,
        vulnerabilityProvider,
        quarantineExplainProvider,
        upstreamPreviewProvider,
        upstreamDetailProvider,
      };
      const reset = beginAccountScopedStateReset(resetOptions);
      const complete = () => completeAccountScopedStateReset(context, resetOptions, reset);
      const run = accountResetQueue.then(complete, complete);
      accountResetQueue = run.catch(() => {
        console.warn("[Cloudsmith] Could not refresh all account-scoped state.");
      });
    }
  });
  own(connectionSubscription);
  void projectConnectionPresentation(connectionManager.getState()).catch(() => {});

  // Create vulnerability WebView provider
  vulnerabilityProvider = new VulnerabilityProvider(context, {
    connectionManager,
    vulnerabilityStateService,
  });
  own({ dispose: () => vulnerabilityProvider.dispose() });

  // Create compliance report WebView provider
  const complianceReportProvider = new ComplianceReportProvider(context);
  own({ dispose: () => complianceReportProvider.dispose() });

  // Create quarantine explanation WebView provider
  quarantineExplainProvider = new QuarantineExplainProvider(context, { connectionManager });
  own({ dispose: () => quarantineExplainProvider.dispose() });

  // Create upstream preview WebView provider
  upstreamPreviewProvider = new UpstreamPreviewProvider(context);
  own({ dispose: () => upstreamPreviewProvider.dispose() });

  // Create upstream detail WebView provider
  upstreamDetailProvider = new UpstreamDetailProvider(context);
  own({ dispose: () => upstreamDetailProvider.dispose() });

  const credentialManager = new CredentialManager(context, { connectionManager });
  // Create promotion provider
  promotionProvider = new PromotionProvider(context, { connectionManager, credentialManager });
  own({ dispose: () => promotionProvider.dispose() });

  const ssoManager = new SSOAuthManager(context, { connectionManager });

  async function handleAuthenticationResult(result, options = {}) {
    if (!result || result.status === "stale" || result.status === "cancelled") {
      return result;
    }

    const state = connectionManager.getState();
    if (result.partial && result.committed) {
      const outcome = state.credentialPresent === false
        ? "Credentials were cleared"
        : "Credentials were saved and validated";
      const detail = result.error && result.error.message
        ? ` ${result.error.message}`
        : "";
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
    // If connected and no default workspace, offer to set the single workspace as default.
    if (options.offerDefault !== false && !getDefaultWorkspace()) {
      const workspaces = await getWorkspaces(context);
      if (workspaces && workspaces.complete && workspaces.items.length === 1) {
        const ws = workspaces.items[0];
        const choice = await vscode.window.showInformationMessage(
          `One workspace available: ${ws.name}. Set as default?`,
          "Set as default", "Dismiss"
        );
        if (choice === "Set as default") {
          const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
          await config.update("defaultWorkspace", ws.slug, vscode.ConfigurationTarget.Global);
          await updateDefaultWorkspaceContext();
          treeView.title = "Repositories";
          treeView.description = ws.slug;
          cloudsmithProvider.refresh();
        }
      }
    }
    return result;
  }

  let initializationFollowUpDisposed = false;
  let cliAutoDetectTimer = null;
  own({
    dispose() {
      initializationFollowUpDisposed = true;
      if (cliAutoDetectTimer) clearTimeout(cliAutoDetectTimer);
    },
  });
  const initialization = connectionManager.initialize();
  void initialization.then(async result => {
    await handleAuthenticationResult(result, {
      showSuccess: false,
      offerDefault: false,
      reportFailure: false,
    });
    if (initializationFollowUpDisposed) return;

    // Auto-detect Cloudsmith CLI credentials after the initial stored state settles.
    cliAutoDetectTimer = setTimeout(() => {
      if (initializationFollowUpDisposed) return;
      void runCLIAutoDetect({
        connectionManager,
        secrets: context.secrets,
        ssoManager,
        showInformationMessage: (...args) => vscode.window.showInformationMessage(...args),
        handleAuthenticationResult,
      }).catch(() => {
        console.warn("[Cloudsmith] CLI credential auto-detection failed.");
      });
    }, 3000);
  }).catch(() => {
    console.warn("[Cloudsmith] Connection initialization did not complete cleanly.");
  });

  // register general commands. Will move this over to command Manager in future release.
  own(
    // Register command to clear credentials
    vscode.commands.registerCommand("cloudsmith-vsc.clearCredentials", async () => {
      const result = await credentialManager.clearCredentials();
      await handleAuthenticationResult(result, { offerDefault: false });
    }),

    // Register command to set credentials — QuickPick with four auth methods
    vscode.commands.registerCommand("cloudsmith-vsc.configureCredentials", async () => {
      const operation = connectionManager.beginCredentialOperation();
      const authOptions = [
        { label: "$(key) Enter API key", description: "Paste a personal API key", _method: "apikey" },
        { label: "$(server) Enter service account API key", description: "Paste a service account API key", _method: "apikey" },
        { label: "$(folder-opened) Import from Cloudsmith CLI", description: "Import credentials from CLI config (~/.cloudsmith/config.ini)", _method: "import" },
        { label: "$(terminal) Sign in with SSO", description: "Run 'cloudsmith auth' in an integrated terminal", _method: "sso-terminal" },
      ];

      const selected = await vscode.window.showQuickPick(authOptions, {
        placeHolder: "Select an authentication method",
      });
      if (!selected) {
        await connectionManager.cancelCredentialOperation(operation);
        return;
      }

      if (selected._method === "sso-terminal") {
        await vscode.commands.executeCommand("cloudsmith-vsc.ssoLogin", operation);
      } else if (selected._method === "import") {
        await vscode.commands.executeCommand("cloudsmith-vsc.importCLICredentials", operation);
      } else {
        const result = await credentialManager.storeApiKey(operation);
        await handleAuthenticationResult(result);
      }
    }),

    // Register command to connect to Cloudsmith
    vscode.commands.registerCommand("cloudsmith-vsc.connectCloudsmith", async () => {
      const result = await connectionManager.initialize();
      await handleAuthenticationResult(result);
    }),

    // Register set default workspace command
    vscode.commands.registerCommand("cloudsmith-vsc.setDefaultWorkspace", async () => {
      const workspaces = await getWorkspaces(context);
      if (!workspaces) {
        return;
      }
      if (workspaces.items.length === 0) {
        if (workspaces.complete) {
          vscode.window.showErrorMessage("No workspaces found. Connect to Cloudsmith first.");
        }
        return;
      }

      const items = [
        { label: "$(close) Clear default workspace", description: "Show all workspaces", _clear: true },
      ];
      if (!workspaces.complete) {
        items.push({ label: "Workspace list incomplete", kind: vscode.QuickPickItemKind.Separator });
      }
      for (const ws of workspaces.items) {
        items.push({ label: ws.name, description: ws.slug });
      }

      const selected = await vscode.window.showQuickPick(items, {
        placeHolder: "Select a default workspace",
      });
      if (!selected) {
        return;
      }

      const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
      if (selected._clear) {
        await config.update("defaultWorkspace", "", vscode.ConfigurationTarget.Global);
        await updateDefaultWorkspaceContext();
        treeView.title = "Workspaces";
        treeView.description = "";
      } else {
        await config.update("defaultWorkspace", selected.description, vscode.ConfigurationTarget.Global);
        await updateDefaultWorkspaceContext();
        treeView.title = "Repositories";
        treeView.description = selected.description;
      }
      cloudsmithProvider.refresh();
    }),

    // Register refresh command for main view
    vscode.commands.registerCommand("cloudsmith-vsc.refreshView", () => {
      cloudsmithProvider.refresh();
      searchProvider.refresh();
      dependencyHealthProvider.refresh();
    }),

    // Register the copy-to-clipboard command
    vscode.commands.registerCommand("cloudsmith-vsc.copySelected", async (item) => {
      // Handle the structured argument from PackageDetailsNode command
      let value;
      if (item && item._detailId !== undefined) {
        value = item._detailValue;
      } else if (item && item.label && item.label.id !== undefined) {
        // Legacy double-wrapped format
        value = item.label.value;
      } else if (typeof item === "string") {
        value = item;
      } else {
        vscode.window.showWarningMessage("Run this command from a package context menu.");
        return;
      }
      if (value != null) {
        await vscode.env.clipboard.writeText(String(value));
        vscode.window.showInformationMessage("Value copied.");
      } else {
        vscode.window.showWarningMessage("Run this command from a package context menu.");
      }
    }),

    // Register the inspect package command
    vscode.commands.registerCommand(
      "cloudsmith-vsc.inspectPackage",
      async (item) => {
        if (!item) {
          item = await pickRecentPackage();
          if (!item) return;
        }
        recentPackages.add(item);
        const cloudsmithAPI = new CloudsmithAPI(context);

        const name = typeof item === "string" ? item : item.name;
        const workspace = typeof item === "string" ? item : item.namespace;
        const identifier = unwrapValue(item.slug_perm);
        const repo = typeof item === "string" ? item : item.repository;


        if (identifier) {
          let endpoint;
          try {
            endpoint = apiEndpoint(["packages", workspace, repo, identifier]);
          } catch {
            vscode.window.showErrorMessage("Could not inspect the package because its identifier was invalid.");
            return;
          }
          const result = await cloudsmithAPI.get(endpoint, {
            responseType: "object",
            validate: isRecord,
            retry: "safe-read",
          });
          if (!result.ok) {
            vscode.window.showErrorMessage(formatApiError(result.error));
            return;
          }
          const jsonContent = JSON.stringify(result.data, null, 2);

          const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
          const inspectOutput = await config.get("inspectOutput");

          if (inspectOutput) {
            const doc = await vscode.workspace.openTextDocument({
              language: "json",
              content: jsonContent,
            });
            await vscode.window.showTextDocument(doc, { preview: true });
          } else {
            inspectOutputChannel.clear();
            inspectOutputChannel.show(true);
            inspectOutputChannel.append(jsonContent);
          }

          vscode.window.showInformationMessage(
            `Inspecting package ${name} in repository ${repo}.`
          );
        } else {
          vscode.window.showWarningMessage("Run this command from a package context menu.");
        }
      }
    ),

    // Register the inspect package group command
    vscode.commands.registerCommand(
      "cloudsmith-vsc.inspectPackageGroup",
      async (item) => {
        if (!item) {
          vscode.window.showWarningMessage("Run this command from a package context menu.");
          return;
        }
        const cloudsmithAPI = new CloudsmithAPI(context);
        const name = typeof item === "string" ? item : item.name;
        const workspace = typeof item === "string" ? item : item.workspace;
        const repo = typeof item === "string" ? item : item.repo;

        if (name) {
          let endpoint;
          let query;
          try {
            query = new SearchQueryBuilder().name(name).build();
            endpoint = apiEndpoint(["packages", workspace, repo], { query: { sort: "-version" } });
          } catch {
            vscode.window.showErrorMessage("Could not inspect the package group because its identity was invalid.");
            return;
          }
          const result = await new PaginatedFetch(cloudsmithAPI).fetchCollection(endpoint, {
            pageSize: 100,
            maxPages: 20,
            maxRequests: 20,
            maxItems: 2000,
            query,
            descriptor: `inspect-package-group:${workspace}:${repo}:${name}`,
            canonicalIdentity: packageCollectionIdentity,
            validate: value => isInspectedPackageArray(value, workspace, repo, name),
            retry: "safe-read",
          });
          if (!result.complete && result.items.length === 0) {
            vscode.window.showErrorMessage(
              firstCollectionFailureMessage(result) || "Could not inspect the package group completely."
            );
            return;
          }
          const jsonContent = JSON.stringify({
            items: result.items,
            complete: result.complete,
            loadedCount: result.items.length,
            totalCount: result.pagination?.countAuthoritative ? result.pagination.count : null,
            termination: result.termination,
            failureCount: result.failureCount,
          }, null, 2);

          const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
          const inspectOutput = await config.get("inspectOutput");

          if (inspectOutput) {
            const doc = await vscode.workspace.openTextDocument({
              language: "json",
              content: jsonContent,
            });
            await vscode.window.showTextDocument(doc, { preview: true });
          } else {
            inspectOutputChannel.clear();
            inspectOutputChannel.show(true);
            inspectOutputChannel.append(jsonContent);
          }

          if (result.complete) {
            vscode.window.showInformationMessage(`Inspecting package group ${name}.`);
          } else {
            vscode.window.showWarningMessage(
              `Inspecting an incomplete package-group result (${result.items.length} packages loaded).`
            );
          }
        } else {
          vscode.window.showWarningMessage("Run this command from a package context menu.");
        }
      }
    ),

    // Register the open package command
    vscode.commands.registerCommand("cloudsmith-vsc.openPackage", async (item) => {
      if (!item) {
        item = await pickRecentPackage();
        if (!item) return;
      }
      recentPackages.add(item);
      const workspace = typeof item === "string" ? item : item.namespace;
      const repo = typeof item === "string" ? item : item.repository;
      const format = typeof item === "string" ? item : item.format;
      const name = typeof item === "string" ? item : item.name;
      const version = unwrapValue(item.version);
      const identifier = unwrapValue(item.slug_perm);

      const url = buildPackageUrl(workspace, repo, format, name, version, identifier);
      if (url) {
        vscode.env.openExternal(vscode.Uri.parse(url));
      } else {
        vscode.window.showWarningMessage("Run this command from a package context menu.");
      }
    }),

     // Register the open package group command
    vscode.commands.registerCommand("cloudsmith-vsc.openPackageGroup", async (item) => {
      if (!item) {
        vscode.window.showWarningMessage("Run this command from a package context menu.");
        return;
      }
      const workspace = typeof item === "string" ? item : item.workspace;
      const repo = typeof item === "string" ? item : item.repo;
      const name = typeof item === "string" ? item : item.name;

      if (name) {
        const url = buildPackageGroupUrl(workspace, repo, name);
        if (url) {
          vscode.env.openExternal(vscode.Uri.parse(url));
          return;
        }
        vscode.window.showWarningMessage("Please use this command from the package context menu.");
      } else {
        vscode.window.showWarningMessage("Run this command from a package context menu.");
      }
    }),

    // Register command to open extension settings
    vscode.commands.registerCommand("cloudsmith-vsc.openSettings", () => {
      vscode.commands.executeCommand(
        "workbench.action.openSettings",
        "@ext:Cloudsmith.cloudsmith-vsc"
      );
    }),

    vscode.commands.registerCommand("cloudsmith-vscode-extension.cloudsmithDocs", () => {
      vscode.env.openExternal(vscode.Uri.parse("https://docs.cloudsmith.com/"));
    }),

    // Register search packages command
    vscode.commands.registerCommand("cloudsmith-vsc.searchPackages", async () => {
      const defaultWsSlug = getDefaultWorkspace();
      let workspaceSlug = defaultWsSlug;
      let recentSearches = workspaceSlug ? new RecentSearches(context, workspaceSlug) : null;

      if (!workspaceSlug) {
        const workspaces = await getWorkspaces(context);
        if (!workspaces) {
          return;
        }
        if (workspaces.items.length === 0) {
          if (workspaces.complete) {
            vscode.window.showErrorMessage("No workspaces found. Connect to Cloudsmith first.");
          }
          return;
        }

        const items = collectionQuickPickItems(
          workspaces,
          ws => ({ label: ws.name, description: ws.slug }),
          "Workspace list incomplete"
        );

        const selected = await vscode.window.showQuickPick(items, {
          placeHolder: "Select a workspace",
        });
        if (!selected) {
          return;
        }
        workspaceSlug = selected.description;
        recentSearches = new RecentSearches(context, workspaceSlug);
      }

      const recent = await recentSearches.getAll();
      if (recent.length > 0) {
        const items = [
          { label: "Recent searches", kind: vscode.QuickPickItemKind.Separator },
        ];
        for (const r of recent) {
          items.push({
            label: `$(history) ${r.query}`,
            description: r.workspace,
            _recent: r,
          });
        }
        items.push({ label: "New search", kind: vscode.QuickPickItemKind.Separator });
        items.push({ label: `$(search) New search in ${workspaceSlug}`, _new: true });

        const selected = await vscode.window.showQuickPick(items, {
          placeHolder: `Search packages in ${workspaceSlug}`,
        });
        if (!selected) {
          return;
        }
        if (selected._recent) {
          await executeSearchIntent(
            searchProvider,
            searchDescriptorFromRecent(selected._recent)
          );
          return;
        }
      }

      // Show search input
      const query = await vscode.window.showInputBox({
        placeHolder: "Search packages (e.g., name:flask, format:python)",
        prompt: `Search packages in ${workspaceSlug}`,
      });
      if (!query) {
        return;
      }

      const builtQuery = buildRawSearchQuery(query);
      await executeSearchIntent(searchProvider, {
        kind: "workspace",
        workspace: workspaceSlug,
        query: builtQuery,
        page: 1,
      }, { recentSearches, record: true });
    }),

    // Register clear search command
    vscode.commands.registerCommand("cloudsmith-vsc.clearSearch", () => {
      searchProvider.clear();
    }),

    // Register load next page command
    vscode.commands.registerCommand("cloudsmith-vsc.searchNextPage", async () => {
      await searchProvider.loadNextPage();
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.loadMoreRepositoryPackages", async (item) => {
      if (item && typeof item.loadMorePackages === "function") {
        await item.loadMorePackages();
      }
    }),

    // Register search in workspace (from workspace context menu or view title)
    vscode.commands.registerCommand("cloudsmith-vsc.searchInWorkspace", async (item) => {
      let workspace;
      if (item && (item.slug || item.name)) {
        workspace = item.slug || item.name;
      } else {
        // Called from view/title with no item — use default workspace
        workspace = getDefaultWorkspace();
      }
      if (!workspace) {
        vscode.window.showWarningMessage("Could not determine the workspace. Set a default workspace in settings.");
        return;
      }

      const query = await vscode.window.showInputBox({
        placeHolder: "Search packages (e.g., name:flask, format:python)",
        prompt: `Search packages in ${workspace}`,
      });
      if (!query) {
        return;
      }

      const recentSearches = new RecentSearches(context, workspace);
      const builtQuery = buildRawSearchQuery(query);
      await executeSearchIntent(searchProvider, {
        kind: "workspace",
        workspace,
        query: builtQuery,
        page: 1,
      }, { recentSearches, record: true });
    }),

    // Register guided search command
    vscode.commands.registerCommand("cloudsmith-vsc.guidedSearch", async () => {
      const defaultWsSlug = getDefaultWorkspace();
      let workspaceSlug = defaultWsSlug;
      let recentSearches = workspaceSlug ? new RecentSearches(context, workspaceSlug) : null;

      if (!workspaceSlug) {
        const workspaces = await getWorkspaces(context);
        if (!workspaces) {
          return;
        }
        if (workspaces.items.length === 0) {
          if (workspaces.complete) {
            vscode.window.showErrorMessage("No workspaces found. Connect to Cloudsmith first.");
          }
          return;
        }

        // Step 1: Select workspace
        const wsItems = collectionQuickPickItems(
          workspaces,
          ws => ({ label: ws.name, description: ws.slug }),
          "Workspace list incomplete"
        );

        const selectedWs = await vscode.window.showQuickPick(wsItems, {
          placeHolder: "Step 1: Select a workspace",
        });
        if (!selectedWs) {
          return;
        }
        workspaceSlug = selectedWs.description;
        recentSearches = new RecentSearches(context, workspaceSlug);
      }

      const recent = await recentSearches.getAll();
      if (recent.length > 0) {
        const recentItems = [
          { label: "Recent searches", kind: vscode.QuickPickItemKind.Separator },
        ];
        for (const r of recent) {
          recentItems.push({
            label: `$(history) ${r.query}`,
            description: r.workspace,
            _recent: r,
          });
        }
        recentItems.push({ label: "Continue guided search", kind: vscode.QuickPickItemKind.Separator });
        recentItems.push({ label: `$(search) Continue guided search in ${workspaceSlug}`, _new: true });

        const selectedRecent = await vscode.window.showQuickPick(recentItems, {
          placeHolder: `Recent searches in ${workspaceSlug}`,
        });
        if (!selectedRecent) {
          return;
        }
        if (selectedRecent._recent) {
          await executeSearchIntent(
            searchProvider,
            searchDescriptorFromRecent(selectedRecent._recent)
          );
          return;
        }
      }

      // Step 2: Select scope
      const scopeItems = [
        { label: "All repositories", description: "Search across the entire workspace" },
        { label: "Select specific repositories", description: "Choose one or more repositories" },
      ];
      const selectedScope = await vscode.window.showQuickPick(scopeItems, {
        placeHolder: "Step 2: Select a search scope",
      });
      if (!selectedScope) {
        return;
      }

      let selectedRepos = null;
      if (selectedScope.label === "Select specific repositories") {
        const repositories = await getWorkspaceRepositories(context, workspaceSlug);
        if (repositories.items.length === 0) {
          if (repositories.complete) {
            vscode.window.showErrorMessage("No repositories found in this workspace.");
          }
          return;
        }
        const repoItems = collectionQuickPickItems(
          repositories,
          repository => ({ label: repository.name, description: repository.slug }),
          "Repository list incomplete"
        );
        const picked = await vscode.window.showQuickPick(repoItems, {
          placeHolder: "Select repositories to search",
          canPickMany: true,
        });
        if (!picked || picked.length === 0) {
          return;
        }
        selectedRepos = picked.map(r => r.description);
      }

      // Step 3: Select filter preset
      const filterItems = FILTER_PRESETS.map(f => ({
        label: f.label,
        _preset: f,
      }));
      const selectedFilter = await vscode.window.showQuickPick(filterItems, {
        placeHolder: "Step 3: Select a filter",
      });
      if (!selectedFilter) {
        return;
      }

      let queryParts = [];
      if (selectedFilter._preset.applyBuilder === null) {
        // Custom query
        const custom = await vscode.window.showInputBox({
          placeHolder: "Enter Cloudsmith search query",
          prompt: "Custom search query",
        });
        if (!custom) {
          return;
        }
        queryParts.push(buildPresetQuery(selectedFilter._preset, custom));
      } else {
        const presetQuery = buildPresetQuery(selectedFilter._preset);
        if (presetQuery) {
          queryParts.push(presetQuery);
        }
      }

      // Step 4: Optional format filter
      const formatItems = [
        { label: "All formats", description: "No format filter", _all: true },
        ...FORMAT_OPTIONS.map(f => ({ label: f })),
      ];
      const selectedFormats = await vscode.window.showQuickPick(formatItems, {
        placeHolder: "Step 4: Filter by format (optional)",
        canPickMany: true,
      });

      if (selectedFormats && selectedFormats.length > 0) {
        const hasAll = selectedFormats.some(f => f._all);
        if (!hasAll) {
          const formatQuery = selectedFormats
            .map(f => new SearchQueryBuilder().format(f.label).build())
            .join(' OR ');
          queryParts.push(`(${formatQuery})`);
        }
      }

      const finalBuilder = new SearchQueryBuilder();
      for (const part of queryParts) {
        finalBuilder.raw(part);
      }
      const finalQuery = finalBuilder.build() || '*';

      await executeSearchIntent(searchProvider, {
        kind: selectedRepos ? "repositories" : "workspace",
        workspace: workspaceSlug,
        query: finalQuery,
        page: 1,
        ...(selectedRepos ? { repositories: selectedRepos } : {}),
      }, { recentSearches, record: true });
    }),

    // Register filter packages command (right-click repo in main tree)
    vscode.commands.registerCommand("cloudsmith-vsc.filterPackages", async (item) => {
      if (!item) {
        vscode.window.showWarningMessage("No repository selected.");
        return;
      }

      const filterItems = FILTER_PRESETS.map(f => ({
        label: f.label,
        _preset: f,
      }));
      const selectedFilter = await vscode.window.showQuickPick(filterItems, {
        placeHolder: `Filter packages in ${item.name}`,
      });
      if (!selectedFilter) {
        return;
      }

      let query;
      if (selectedFilter._preset.applyBuilder === null) {
        query = await vscode.window.showInputBox({
          placeHolder: "Enter filter query",
          prompt: `Filter packages in ${item.name}`,
        });
        if (!query) {
          return;
        }
        query = buildPresetQuery(selectedFilter._preset, query);
      } else {
        query = buildPresetQuery(selectedFilter._preset);
      }

      // Store the filter in the module singleton so it survives tree rebuilds
      const { activeFilters } = require("./util/filterState");
      const filterKey = `${item.workspace}/${item.slug}`;
      const filterLabel = selectedFilter._preset.applyBuilder === null
        ? "Custom query"
        : selectedFilter._preset.label;
      if (query) {
        activeFilters.set(filterKey, { query, label: filterLabel });
      } else {
        activeFilters.delete(filterKey);
      }
      cloudsmithProvider.refresh();
    }),

    // Register clear filter command
    vscode.commands.registerCommand("cloudsmith-vsc.clearFilter", async (item) => {
      if (!item) {
        return;
      }
      const { activeFilters } = require("./util/filterState");
      const filterKey = `${item.workspace}/${item.slug}`;
      activeFilters.delete(filterKey);
      cloudsmithProvider.refresh();
    }),

    // Register change filter command — re-opens filter picker for a filtered repo
    vscode.commands.registerCommand("cloudsmith-vsc.changeFilter", async (item) => {
      vscode.commands.executeCommand("cloudsmith-vsc.filterPackages", item);
    }),

    // Show vulnerable packages in a specific repo
    vscode.commands.registerCommand("cloudsmith-vsc.filterVulnerable", async (item) => {
      if (!item || !item.workspace || !item.slug) {
        vscode.window.showWarningMessage("Could not determine repository details.");
        return;
      }
      await searchProvider.search(item.workspace, "vulnerabilities:>0", 1, item.slug);
      vscode.commands.executeCommand("cloudsmithSearchView.focus");
    }),

    // Show vulnerable packages across an entire workspace
    vscode.commands.registerCommand("cloudsmith-vsc.filterVulnerableWorkspace", async (item) => {
      if (!item || !item.slug) {
        vscode.window.showWarningMessage("Could not determine workspace details.");
        return;
      }
      await searchProvider.search(item.slug, "vulnerabilities:>0");
      vscode.commands.executeCommand("cloudsmithSearchView.focus");
    }),

    // Register find safe version command
    vscode.commands.registerCommand("cloudsmith-vsc.findSafeVersion", async (item) => {
      if (!item) {
        item = await pickRecentPackage();
        if (!item) return;
      }
      recentPackages.add(item);

      // Use extractPackageInfo for safe unwrapping across node types
      const info = extractPackageInfo(item);
      // DependencyHealthNode stores workspace/repo differently
      const workspace = info.workspace || item.cloudsmithWorkspace || item.workspace;
      const repo = info.repo || item.cloudsmithRepo || item.repository;
      const name = info.name || item.name;
      const format = info.format || item.format;

      if (!workspace || !repo || !name || !format) {
        vscode.window.showWarningMessage("Could not determine package details.");
        return;
      }

      const cloudsmithAPI = new CloudsmithAPI(context);
      const helper = new RemediationHelper(cloudsmithAPI);

      // Try current repo first
      let result = await helper.findSafeVersions(workspace, repo, name, format);
      let crossRepo = false;

      if (!result.success) {
        vscode.window.showErrorMessage(`Could not find safe versions. ${formatApiError(result.error)}`);
        return;
      }

      if (result.versions.length === 0) {
        // Try workspace-wide
        result = await helper.findSafeVersionsAcrossRepos(workspace, name, format);
        crossRepo = true;

        if (!result.success) {
          vscode.window.showErrorMessage(`Could not find safe versions. ${formatApiError(result.error)}`);
          return;
        }
      }

      if (result.versions.length === 0) {
        if (result.absenceProven) {
          vscode.window.showInformationMessage(
            `No safe versions found for "${name}" in ${crossRepo ? "the workspace" : repo}.`
          );
        } else {
          vscode.window.showWarningMessage(
            `Safe-version results were incomplete; no absence claim can be made for "${name}".`
          );
        }
        return;
      }

      const quickPickItems = result.versions.map(pkg => {
        const policyIcon = pkg.policy_violated ? "$(warning)" : "$(check)";
        const repoLabel = crossRepo ? ` [${pkg.repository}]` : "";
        // Build richer detail line
        let detail = "No policy violations";
        if (pkg.policy_violated) {
          detail = "Policy violations found";
        }
        if (pkg.num_vulnerabilities > 0) {
          detail = `${pkg.num_vulnerabilities} vulnerabilit${pkg.num_vulnerabilities === 1 ? "y" : "ies"} (${pkg.max_severity || "Unknown"})`;
        }
        return {
          label: `${policyIcon} ${name} ${pkg.version}`,
          description: `${pkg.repository || repo} \u2014 ${pkg.status_str}${repoLabel}`,
          detail: detail,
          _pkg: pkg,
        };
      });

      if (!result.complete) {
        const countDetail = result.totalCount === null
          ? `${result.versions.length} loaded`
          : `showing newest ${result.versions.length} of ${result.totalCount}`;
        quickPickItems.unshift({
          label: `Safe-version preview incomplete (${countDetail})`,
          kind: vscode.QuickPickItemKind.Separator,
        });
      }

      const title = crossRepo
        ? `Newest safe versions of "${name}" (${format}) in the workspace`
        : `Newest safe versions of "${name}" (${format}) in ${repo}`;

      const selected = await vscode.window.showQuickPick(quickPickItems, {
        placeHolder: title,
      });

      if (selected) {
        const pkg = selected._pkg;
        const pkgRepo = crossRepo ? pkg.repository : repo;

        // Show follow-up actions instead of just copying install command
        const action = await vscode.window.showQuickPick([
          { label: "$(clippy) Copy install command", id: "install" },
          { label: "$(shield) Show vulnerabilities", id: "vulns" },
          { label: "$(globe) View in Cloudsmith", id: "open" },
          { label: "$(json) Inspect package", id: "inspect" },
          { label: "$(copy) Copy version", id: "copy" },
        ], {
          placeHolder: `Select an action for ${name} ${pkg.version}`,
        });

        if (!action) return;

        if (action.id === "install") {
          const installResult = buildInstallCommand(
            format,
            name,
            pkg.version,
            workspace,
            pkgRepo,
            pkg
          );
          if (!installResult) return;
          const chosenCommand = await pickInstallCommandVariant(installResult);
          if (!chosenCommand) return;
          await vscode.env.clipboard.writeText(InstallCommandBuilder.toClipboardCommand(chosenCommand));
          let msg = crossRepo
            ? `Install command copied for ${name} ${pkg.version} from ${pkgRepo}.`
            : `Install command copied for ${name} ${pkg.version}.`;
          if (installResult.note) msg += ` Note: ${installResult.note}`;
          vscode.window.showInformationMessage(msg);
        } else if (action.id === "vulns") {
          const vulnItem = {
            name: name,
            namespace: workspace,
            repository: pkgRepo,
            slug_perm_raw: pkg.slug_perm,
            version: pkg.version,
            format: format,
            status_reason: pkg.status_reason || null,
          };
          vscode.commands.executeCommand("cloudsmith-vsc.showVulnerabilities", vulnItem);
        } else if (action.id === "open") {
          const packageUrl = buildPackageUrl(
            workspace,
            pkgRepo,
            format,
            name,
            pkg.version,
            pkg.slug_perm
          );
          if (packageUrl) {
            await vscode.env.openExternal(vscode.Uri.parse(packageUrl));
          } else {
            vscode.window.showInformationMessage("Could not open this package in Cloudsmith.");
          }
        } else if (action.id === "inspect") {
          const inspectItem = {
            name: name,
            namespace: workspace,
            repository: pkgRepo,
            slug_perm_raw: pkg.slug_perm,
            version: pkg.version,
            format: format,
          };
          vscode.commands.executeCommand("cloudsmith-vsc.inspectPackage", inspectItem);
        } else if (action.id === "copy") {
          await vscode.env.clipboard.writeText(pkg.version);
          vscode.window.showInformationMessage(`Version copied: ${pkg.version}.`);
        }
      }
    }),

    // Register open CVE command
    vscode.commands.registerCommand("cloudsmith-vsc.openCVE", async (item) => {
      if (!item || !item.cveId) {
        vscode.window.showWarningMessage("No vulnerability selected.");
        return;
      }

      let url;
      if (item.cveId.startsWith("GHSA")) {
        url = `https://github.com/advisories/${item.cveId}`;
      } else {
        url = `https://nvd.nist.gov/vuln/detail/${item.cveId}`;
      }
      vscode.env.openExternal(vscode.Uri.parse(url));
    }),

    // Register show vulnerabilities command — opens WebView panel with full CVE report
    vscode.commands.registerCommand("cloudsmith-vsc.showVulnerabilities", async (item) => {
      if (!item) {
        item = await pickRecentPackage();
        if (!item) return;
      }
      recentPackages.add(item);
      await vulnerabilityProvider.show(item);
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.showDepVulnerabilities", async (item) => {
      await vscode.commands.executeCommand("cloudsmith-vsc.showVulnerabilities", item);
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.findDepSafeVersion", async (item) => {
      await vscode.commands.executeCommand("cloudsmith-vsc.findSafeVersion", item);
    }),

    // Register vulnerability filter command — updates a summary node in-place
    vscode.commands.registerCommand("cloudsmith-vsc.filterVulnerabilities", async (vulnSummaryNode) => {
      if (!vulnSummaryNode ||
          typeof vulnSummaryNode.setSeverityFilter !== "function" ||
          typeof vulnSummaryNode.setCvssThreshold !== "function") {
        vscode.window.showWarningMessage("No vulnerability summary selected.");
        return;
      }

      const filterType = await vscode.window.showQuickPick([
        { label: "$(filter) Filter by severity", value: "severity" },
        { label: "$(dashboard) Filter by CVSS threshold", value: "cvss" },
        { label: "$(clear-all) Clear filters", value: "clear" },
      ], {
        placeHolder: "Filter vulnerabilities",
      });

      if (!filterType) {
        return;
      }

      if (filterType.value === "severity") {
        const severities = await vscode.window.showQuickPick([
          { label: "Critical", picked: true },
          { label: "High", picked: true },
          { label: "Medium", picked: false },
          { label: "Low", picked: false },
        ], {
          canPickMany: true,
          placeHolder: "Select severity levels to show",
        });

        if (!severities || severities.length === 0) {
          return;
        }

        vulnSummaryNode.setSeverityFilter(severities.map(item => item.label.toLowerCase()));
      } else if (filterType.value === "cvss") {
        const thresholdPick = await vscode.window.showQuickPick([
          { label: "CVSS >= 9.0 (Critical)", value: 9.0 },
          { label: "CVSS >= 7.0 (High+)", value: 7.0 },
          { label: "CVSS >= 4.0 (Medium+)", value: 4.0 },
          { label: "Custom threshold", value: "custom" },
        ], {
          placeHolder: "Select minimum CVSS score",
        });

        if (!thresholdPick) {
          return;
        }

        let cvssValue = thresholdPick.value;
        if (cvssValue === "custom") {
          const input = await vscode.window.showInputBox({
            prompt: "Enter a minimum CVSS score (0.0 - 10.0)",
            placeHolder: "7.0",
            validateInput: (value) => {
              const parsed = Number.parseFloat(value);
              return Number.isNaN(parsed) || parsed < 0 || parsed > 10
                ? "Enter a number between 0.0 and 10.0."
                : null;
            },
          });
          if (!input) {
            return;
          }
          cvssValue = Number.parseFloat(input);
        }

        vulnSummaryNode.setCvssThreshold(cvssValue);
      } else {
        vulnSummaryNode.setSeverityFilter(null);
        vulnSummaryNode.setCvssThreshold(null);
      }

      cloudsmithProvider._onDidChangeTreeData.fire(vulnSummaryNode);
      searchProvider._onDidChangeTreeData.fire(vulnSummaryNode);
      dependencyHealthProvider._onDidChangeTreeData.fire(vulnSummaryNode);
    }),

    // Register explain quarantine command — opens WebView panel with policy trace
    vscode.commands.registerCommand("cloudsmith-vsc.explainQuarantine", async (item) => {
      if (!item) {
        item = await pickRecentPackage({
          predicate: isQuarantinedPackage,
          emptyMessage: "No recent quarantined packages. Run this command from a quarantined package context menu.",
          placeHolder: "Select a quarantined package",
        });
        if (!item) return;
      }
      recentPackages.add(item);
      await quarantineExplainProvider.show(item);
    }),

    // Register scan dependencies command
    vscode.commands.registerCommand("cloudsmith-vsc.scanDependencies", async () => {
      await runDependencyScan(
        dependencyHealthProvider,
        () => resolveDependencyScanTarget(context)
      );
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.scanDependenciesPending", async () => {
      await vscode.commands.executeCommand("cloudsmith-vsc.scanDependencies");
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.scanDependenciesComplete", async () => {
      await vscode.commands.executeCommand("cloudsmith-vsc.scanDependencies");
    }),

    // Historical command IDs remain callable but use the same first-run/refresh behavior.
    vscode.commands.registerCommand("cloudsmith-vsc.rescanDependencies", async () => {
      await vscode.commands.executeCommand("cloudsmith-vsc.scanDependencies");
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.changeDependencyScanScope", async () => {
      const scanTarget = await resolveDependencyScanTarget(context, { forcePrompt: true });
      if (!scanTarget) {
        return;
      }

      const projectFolder = await dependencyHealthProvider.selectProjectFolder();
      if (!projectFolder) {
        return;
      }

      await dependencyHealthProvider.scan(
        scanTarget.scanWorkspace,
        scanTarget.scanRepo,
        projectFolder
      );
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.pullDependencies", async () => {
      await dependencyHealthProvider.pullDependencies();
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.pullSingleDependency", async (item) => {
      await dependencyHealthProvider.pullSingleDependency(item);
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.cycleDepView", async () => {
      await dependencyHealthProvider.cycleViewMode();
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.cycleDepViewDirect", async () => {
      await vscode.commands.executeCommand("cloudsmith-vsc.cycleDepView");
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.cycleDepViewFlat", async () => {
      await vscode.commands.executeCommand("cloudsmith-vsc.cycleDepView");
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.cycleDepViewTree", async () => {
      await vscode.commands.executeCommand("cloudsmith-vsc.cycleDepView");
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.depViewDirect", async () => {
      await dependencyHealthProvider.setViewMode("direct");
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.depViewFlat", async () => {
      await dependencyHealthProvider.setViewMode("flat");
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.depViewTree", async () => {
      await dependencyHealthProvider.setViewMode("tree");
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.depFilterVulnerable", async () => {
      await dependencyHealthProvider.setFilterMode(FILTER_MODES.VULNERABLE);
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.depFilterUncovered", async () => {
      await dependencyHealthProvider.setFilterMode(FILTER_MODES.UNCOVERED);
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.depFilterRestrictiveLicense", async () => {
      await dependencyHealthProvider.setFilterMode(FILTER_MODES.RESTRICTIVE_LICENSE);
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.depFilterPolicyViolation", async () => {
      await dependencyHealthProvider.setFilterMode(FILTER_MODES.POLICY_VIOLATION);
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.depFilterClear", async () => {
      await dependencyHealthProvider.clearFilter();
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.depSortFilter", async () => {
      await showDependencySortFilterPicker(dependencyHealthProvider);
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.depSortFilterActive", async () => {
      await vscode.commands.executeCommand("cloudsmith-vsc.depSortFilter");
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.viewComplianceReport", async () => {
      const reportData = dependencyHealthProvider.getReportData();
      if (!reportData) {
        vscode.window.showInformationMessage("Run a dependency scan before opening the report.");
        return;
      }

      complianceReportProvider.show(reportData);
    }),

    // Register copy install command
    vscode.commands.registerCommand("cloudsmith-vsc.copyInstallCommand", async (item) => {
      if (!item) {
        item = await pickRecentPackage();
        if (!item) return;
      }
      if (isQuarantinedPackage(item)) {
        vscode.window.showWarningMessage("Install commands are not available for quarantined packages.");
        return;
      }
      recentPackages.add(item);
      const info = extractPackageInfo(item);
      if (!info.name || !info.format || !info.workspace || !info.repo) {
        vscode.window.showWarningMessage("Could not determine package details for install command.");
        return;
      }
      const result = buildInstallCommand(
        info.format, info.name, info.version || "latest", info.workspace, info.repo, item
      );
      if (!result) return;
      const chosenCommand = await pickInstallCommandVariant(result);
      if (!chosenCommand) return;
      await vscode.env.clipboard.writeText(InstallCommandBuilder.toClipboardCommand(chosenCommand));
      let msg = `Install command copied for ${info.name}`;
      if (result.note) {
        msg += `. Note: ${result.note}`;
      } else {
        msg += ".";
      }
      vscode.window.showInformationMessage(msg);
    }),

    // Register search by license command
    vscode.commands.registerCommand("cloudsmith-vsc.searchByLicense", async () => {
      const defaultWsSlug = getDefaultWorkspace();
      let workspaceSlug;

      if (defaultWsSlug) {
        workspaceSlug = defaultWsSlug;
      } else {
        const workspaces = await getWorkspaces(context);
        if (!workspaces) {
          return;
        }
        if (workspaces.items.length === 0) {
          if (workspaces.complete) {
            vscode.window.showErrorMessage("No workspaces found. Connect to Cloudsmith first.");
          }
          return;
        }

        const wsItems = collectionQuickPickItems(
          workspaces,
          ws => ({ label: ws.name, description: ws.slug }),
          "Workspace list incomplete"
        );
        const selectedWs = await vscode.window.showQuickPick(wsItems, {
          placeHolder: "Select a workspace to search",
        });
        if (!selectedWs) {
          return;
        }
        workspaceSlug = selectedWs.description;
      }

      // Select license tier/type
      const licenseItems = LicenseClassifier.getSearchQuickPickItems();

      const selectedLicense = await vscode.window.showQuickPick(licenseItems, {
        placeHolder: "Select a license to search for",
      });
      if (!selectedLicense) {
        return;
      }

      const query = selectedLicense.query || LicenseClassifier.buildLicenseQuery(selectedLicense.label);
      const recentSearches = new RecentSearches(context, workspaceSlug);
      await executeSearchIntent(searchProvider, {
        kind: "workspace",
        workspace: workspaceSlug,
        query,
        page: 1,
      }, { recentSearches, record: true });
    }),

    // Register open license URL command
    vscode.commands.registerCommand("cloudsmith-vsc.openLicenseUrl", async (item) => {
      const licenseInfo = item && item.licenseInfo ? item.licenseInfo : LicenseClassifier.inspect(item);
      const licenseUrl = licenseInfo ? (licenseInfo.licenseUrl || (item && item.licenseUrl) || null) : null;

      if (!item || !licenseUrl) {
        vscode.window.showWarningMessage("No license URL available.");
        return;
      }
      let parsedUrl;
      try {
        parsedUrl = new URL(licenseUrl);
      } catch (err) { // eslint-disable-line no-unused-vars
        vscode.window.showWarningMessage("Invalid license URL.");
        return;
      }

      if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
        vscode.window.showWarningMessage("Could not open the license URL. Unsupported protocol.");
        return;
      }

      await vscode.env.openExternal(vscode.Uri.parse(parsedUrl.toString()));
    }),

    // Register SSO login command — uses terminal flow by default,
    // experimental browser flow if the setting is enabled
    vscode.commands.registerCommand("cloudsmith-vsc.ssoLogin", async (suppliedOperation = null) => {
      const operation = suppliedOperation || connectionManager.beginCredentialOperation();
      if (!connectionManager.isOperationCurrent(operation)) {
        return;
      }
      const workspaceSlug = await vscode.window.showInputBox({
        placeHolder: "my-org",
        prompt: "Enter the Cloudsmith workspace slug for SSO",
        ignoreFocusOut: true,
      });
      if (!workspaceSlug) {
        await connectionManager.cancelCredentialOperation(operation);
        return;
      }

      const ssoConfig = vscode.workspace.getConfiguration("cloudsmith-vsc");
      const useExperimental = ssoConfig.get("experimentalSSOBrowser");

      let result;
      if (useExperimental) {
        result = await ssoManager.loginViaBrowser(workspaceSlug.trim(), operation);
      } else {
        result = await ssoManager.loginViaTerminal(workspaceSlug.trim(), operation);
      }
      await handleAuthenticationResult(result);
    }),

    // Register import CLI credentials command
    vscode.commands.registerCommand("cloudsmith-vsc.importCLICredentials", async (suppliedOperation = null) => {
      const operation = suppliedOperation || connectionManager.beginCredentialOperation();
      const result = await ssoManager.importFromCLI(operation);
      await handleAuthenticationResult(result);
    }),

    // Register show install command (opens in new document)
    vscode.commands.registerCommand("cloudsmith-vsc.showInstallCommand", async (item) => {
      if (!item) {
        item = await pickRecentPackage();
        if (!item) return;
      }
      if (isQuarantinedPackage(item)) {
        vscode.window.showWarningMessage("Install commands are not available for quarantined packages.");
        return;
      }
      recentPackages.add(item);
      const info = extractPackageInfo(item);
      if (!info.name || !info.format || !info.workspace || !info.repo) {
        vscode.window.showWarningMessage("Could not determine package details for install command.");
        return;
      }
      const result = buildInstallCommand(
        info.format, info.name, info.version || "latest", info.workspace, info.repo, item
      );
      if (!result) return;
      let content = result.command;
      if (result.alternatives && result.alternatives.length > 0) {
        for (const alt of result.alternatives) {
          content += `\n\n# Alternative: ${alt.label}\n${alt.command}`;
        }
      }
      if (result.note) {
        content += "\n\n# Note\n" + commentCommandNote(result.note);
      }
      const doc = await vscode.workspace.openTextDocument({
        language: info.format === "maven" ? "xml" : "shellscript",
        content: content,
      });
      await vscode.window.showTextDocument(doc, { preview: true });
    }),

    // PR 6: Inspect repository upstreams
    vscode.commands.registerCommand("cloudsmith-vsc.inspectUpstreams", async (item) => {
      if (!item) {
        vscode.window.showWarningMessage("No repository selected.");
        return;
      }

      const workspace = item.workspace;
      const repoSlug = item.slug;
      const repoName = item.name;

      if (!workspace || !repoSlug || !repoName) {
        vscode.window.showWarningMessage("Could not determine repository details.");
        return;
      }

      await upstreamDetailProvider.show(workspace, repoSlug, repoName);
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.exportTerraform", async (item) => {
      if (!item) {
        vscode.window.showWarningMessage("No repository selected.");
        return;
      }

      const workspace = item.workspace;
      const repoSlug = item.slug || item.slug_perm;
      const repoName = item.name;

      if (!workspace || !repoSlug || !repoName) {
        vscode.window.showWarningMessage("Could not determine repository details.");
        return;
      }

      if (exportTerraformAbortController) {
        exportTerraformAbortController.abort();
      }

      const abortController = new AbortController();
      exportTerraformAbortController = abortController;
      const cloudsmithAPI = new CloudsmithAPI(context);
      let repoEndpoint;
      let retentionEndpoint;
      try {
        repoEndpoint = apiEndpoint(["repos", workspace, repoSlug]);
        retentionEndpoint = apiEndpoint(["repos", workspace, repoSlug, "retention"]);
      } catch {
        if (exportTerraformAbortController === abortController) {
          exportTerraformAbortController = null;
        }
        vscode.window.showErrorMessage("Could not export the repository because its identity was invalid.");
        return;
      }

      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "Generating Terraform configuration...",
          cancellable: true,
        },
        async (_progress, token) => {
          const cancellationSubscription = token.onCancellationRequested(() => abortController.abort());
          try {
            const [repoResult, retentionResult, upstreamResult] = await Promise.all([
              cloudsmithAPI.get(repoEndpoint, {
                responseType: "object",
                validate: isRecord,
                retry: "safe-read",
                signal: abortController.signal,
              }),
              cloudsmithAPI.get(retentionEndpoint, {
                responseType: "object",
                validate: isRecord,
                retry: "safe-read",
                signal: abortController.signal,
              }),
              fetchRepositoryUpstreams(context, workspace, repoSlug, {
                signal: abortController.signal,
              }),
            ]);

            if (abortController.signal.aborted || upstreamResult === null) {
              return;
            }

            if (!repoResult.ok) {
              if (repoResult.error.kind === "cancelled") {
                return;
              }
              vscode.window.showErrorMessage(
                `Could not export repository. ${formatApiError(repoResult.error)}`
              );
              return;
            }

            const upstreamLoadFailed = Boolean(
              upstreamResult
              && upstreamResult.error
              && (!Array.isArray(upstreamResult.data) || upstreamResult.data.length === 0)
            );
            const upstreamUnavailableFormats = [...new Set([
              ...(upstreamResult.failedFormats || []),
              ...(upstreamResult.uninspectedFormats || []),
            ])];
            const retentionRules = retentionResult.ok ? retentionResult.data : null;

            const hclContent = generateTerraformConfig({
              repo: repoResult.data,
              workspace,
              upstreams: Array.isArray(upstreamResult.data) ? upstreamResult.data : [],
              retention: retentionRules,
              exportedAt: new Date().toISOString(),
              upstreamLoadFailed,
              upstreamLoadPartial: upstreamResult.complete !== true,
              upstreamFailedFormats: upstreamUnavailableFormats,
            });

            const doc = await vscode.workspace.openTextDocument({
              content: hclContent,
              language: await getPreferredTextDocumentLanguage(),
            });

            if (abortController.signal.aborted) {
              return;
            }

            await vscode.window.showTextDocument(doc);
          } catch {
            if (abortController.signal.aborted) {
              return;
            }

            vscode.window.showErrorMessage(
              "Could not export repository because an unexpected error occurred."
            );
          } finally {
            cancellationSubscription.dispose();
            if (exportTerraformAbortController === abortController) {
              exportTerraformAbortController = null;
            }
          }
        }
      );
    }),

    // Phase 9: Preview upstream resolution
    vscode.commands.registerCommand("cloudsmith-vsc.previewUpstreamResolution", async (item) => {
      const defaultWsSlug = getDefaultWorkspace();

      let pkgName, pkgFormat, targetRepo;

      // If triggered from a dependency health node
      if (item && item.name && item.format) {
        pkgName = item.name;
        pkgFormat = item.format;
      } else {
        pkgName = await vscode.window.showInputBox({
          placeHolder: "flask",
          prompt: "Enter the package name",
        });
        if (!pkgName) return;

        const formatPick = await vscode.window.showQuickPick(
          FORMAT_OPTIONS.map(f => ({ label: f })),
          { placeHolder: "Select a package format" }
        );
        if (!formatPick) return;
        pkgFormat = formatPick.label;
      }

      // Select workspace
      let wsSlug = defaultWsSlug;
      if (!wsSlug) {
        const workspaces = await getWorkspaces(context);
        if (!workspaces) {
          return;
        }
        if (workspaces.items.length === 0) {
          if (workspaces.complete) {
            vscode.window.showErrorMessage("No workspaces found.");
          }
          return;
        }
        const wsPick = await vscode.window.showQuickPick(
          collectionQuickPickItems(
            workspaces,
            ws => ({ label: ws.name, description: ws.slug }),
            "Workspace list incomplete"
          ),
          { placeHolder: "Select a workspace" }
        );
        if (!wsPick) return;
        wsSlug = wsPick.description;
      }

      // Select repo
      const repositories = await getWorkspaceRepositories(context, wsSlug);
      if (repositories.items.length === 0) {
        if (repositories.complete) vscode.window.showErrorMessage("No repositories found.");
        return;
      }
      const repoPick = await vscode.window.showQuickPick(
        collectionQuickPickItems(
          repositories,
          repository => ({ label: repository.name, description: repository.slug }),
          "Repository list incomplete"
        ),
        { placeHolder: "Select target repository" }
      );
      if (!repoPick) return;
      targetRepo = repoPick.description;

      const checker = new UpstreamChecker(context);
      const result = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: "Checking upstream resolution..." },
        () => checker.previewResolution(wsSlug, targetRepo, pkgName, pkgFormat)
      );
      if (result) {
        upstreamPreviewProvider.show(result);
      }
    }),

    // Phase 10: Show promotion status
    vscode.commands.registerCommand("cloudsmith-vsc.showPromotionStatus", async (item) => {
      if (!item || !item.name) {
        item = await pickRecentPackage();
        if (!item) return;
      }
      recentPackages.add(item);

      const info = extractPackageInfo(item);
      let promotionIdentity;
      try {
        promotionIdentity = normalizePackageQueryIdentity(
          info.workspace,
          info.name,
          info.version,
          info.format
        );
      } catch {
        vscode.window.showWarningMessage("Could not determine package details.");
        return;
      }

      const pipeline = promotionProvider.getPipeline();
      if (pipeline.length > 0) {
        // Pipeline mode: show status across configured repos
        const statusResult = await promotionProvider.getPromotionStatus(
          promotionIdentity.workspace,
          promotionIdentity.name,
          promotionIdentity.version,
          promotionIdentity.format
        );

        if (statusResult.error) {
          vscode.window.showErrorMessage(
            `Could not load promotion status. ${formatApiError(statusResult.error)}`
          );
          return;
        }
        const status = statusResult.items;

        if (status.length === 0) {
          vscode.window.showInformationMessage("No pipeline repositories found.");
          return;
        }

        const lines = status.map(s => {
          const icon = s.found === null
            ? "?"
            : !s.found
              ? "\u2014"
              : (s.quarantined ? "\u274C" : (s.policyViolated ? "\u26A0\uFE0F" : "\u2705"));
          return `${icon} ${s.repo}: ${s.status}`;
        });
        const completeness = statusResult.complete ? "" : " (package-location search incomplete)";
        vscode.window.showInformationMessage(
          `Pipeline for ${promotionIdentity.name} ${promotionIdentity.version}: ${lines.join(" \u2192 ")}${completeness}`
        );
      } else {
        const results = await promotionProvider.getPackageLocations(
          promotionIdentity.workspace,
          promotionIdentity.name,
          promotionIdentity.version,
          promotionIdentity.format
        );
        if (results.items.length === 0 && results.failureCount > 0 && results.pageCount === 0) {
          vscode.window.showErrorMessage(
            `Could not load package locations.${firstCollectionFailureMessage(results)}`
          );
          return;
        }
        const exactPackages = results.items;
        if (exactPackages.length === 0) {
          if (results.complete) {
            vscode.window.showInformationMessage(
              `${promotionIdentity.name} ${promotionIdentity.version} was not found in any other repository.`
            );
          } else {
            vscode.window.showWarningMessage(
              `Package locations are incomplete; ${promotionIdentity.name} ${promotionIdentity.version} may exist in another repository.`
            );
          }
          return;
        }

        const lines = exactPackages.map(pkg => {
          const icon = pkg.status_str === "Quarantined" ? "\u274C" : (pkg.policy_violated ? "\u26A0\uFE0F" : "\u2705");
          return `${icon} ${pkg.repository}: ${pkg.status_str || "Unknown"}`;
        });
        const completeness = results.complete ? "" : " (additional locations may be unavailable)";
        vscode.window.showInformationMessage(
          `${promotionIdentity.name} ${promotionIdentity.version} found in: ${lines.join(", ")}${completeness}`
        );
      }
    }),

    // Phase 10: Promote package
    vscode.commands.registerCommand("cloudsmith-vsc.promotePackage", async (item) => {
      if (!item) {
        item = await pickRecentPackage();
        if (!item) return;
      }
      await promotionProvider.runPromotionWorkflow(item, {
        refresh: () => cloudsmithProvider.refresh(),
      });
    }),

    // Phase 12: Copy entitlement token
    vscode.commands.registerCommand("cloudsmith-vsc.copyEntitlementToken", async (item) => {
      if (!item || !item.token) {
        vscode.window.showWarningMessage("No token available to copy.");
        return;
      }
      const choice = await vscode.window.showWarningMessage(
        "Copy the entitlement token to the clipboard? Entitlement tokens are sensitive.",
        "Copy",
        "Cancel"
      );
      if (choice !== "Copy") {
        return;
      }
      // VS Code does not provide a clipboard auto-clear API, so we require explicit confirmation.
      await vscode.env.clipboard.writeText(item.token);
      vscode.window.showInformationMessage(`Entitlement token "${item.tokenName}" copied.`);
    }),

  );
}

// This method is called when your extension is deactivated
async function deactivate() {
  const owner = activeActivationOwner;
  activeActivationOwner = null;
  if (owner) {
    owner.dispose();
    await owner.settle();
  }
  if (exportTerraformAbortController) {
    exportTerraformAbortController.abort();
    exportTerraformAbortController = null;
  }
}

module.exports = {
  ActivationOwner,
  activate,
  deactivate,
  evictPersistedUpstreamCaches,
  executeSearchIntent,
  FORMAT_OPTIONS,
  getWorkspaces,
  resetAccountScopedState,
  runDependencyScan,
  searchDescriptorFromRecent,
};

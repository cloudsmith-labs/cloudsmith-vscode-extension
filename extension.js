const vscode = require("vscode");
const { CloudsmithProvider } = require("./views/cloudsmithProvider");
const { helpProvider } = require("./views/helpProvider");
const { SearchProvider } = require("./views/searchProvider");
const { CloudsmithAPI } = require("./util/cloudsmithAPI");
const { CredentialManager } = require("./util/credentialManager");
const { RecentSearches } = require("./util/recentSearches");
const { RemediationHelper } = require("./util/remediationHelper");
const {
  DependencyHealthProvider,
  FILTER_MODES,
  SORT_MODES,
} = require("./views/dependencyHealthProvider");
const { InstallCommandBuilder } = require("./util/installCommandBuilder");
const { VulnerabilityProvider } = require("./views/vulnerabilityProvider");
const { ComplianceReportProvider } = require("./views/complianceReportProvider");
const { QuarantineExplainProvider } = require("./views/quarantineExplainProvider");
const { DiagnosticsPublisher } = require("./util/diagnosticsPublisher");
const { SSOAuthManager } = require("./util/ssoAuthManager");
const { UpstreamChecker } = require("./util/upstreamChecker");
const { UpstreamPreviewProvider } = require("./views/upstreamPreviewProvider");
const { UpstreamDetailProvider } = require("./views/upstreamDetailProvider");
const { PromotionProvider } = require("./views/promotionProvider");
const { SearchQueryBuilder } = require("./util/searchQueryBuilder");
const { formatApiError } = require("./util/errorFormatter");
const { LicenseClassifier } = require("./util/licenseClassifier");
const { fetchRepositoryUpstreams, generateTerraformConfig } = require("./util/terraformExporter");
const { SUPPORTED_UPSTREAM_FORMATS } = require("./util/upstreamFormats");
const recentPackages = require("./util/recentPackages");

let exportTerraformAbortController = null;

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
async function pickRecentPackage() {
  const recent = recentPackages.getAll();
  if (recent.length === 0) {
    vscode.window.showInformationMessage("No recent packages. Run this command from a package context menu.");
    return null;
  }
  const selected = await vscode.window.showQuickPick(
    recent.map(p => ({
      label: p.name,
      description: `${p.version || ""} — ${p.repository || ""}`,
      _pkg: p,
    })),
    { placeHolder: "Select a package" }
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
 * Helper: get workspaces from cache or fetch fresh.
 */
const WORKSPACE_CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes

/**
 * Helper: read the defaultWorkspace setting.
 * Returns the slug string if set, or empty string if not.
 */
function getDefaultWorkspace() {
  const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
  return config.get("defaultWorkspace") || "";
}

async function setConnectedContext(isConnected) {
  await vscode.commands.executeCommand("setContext", "cloudsmith.connected", Boolean(isConnected));
}

async function setHasMultipleWorkspacesContext(hasMultipleWorkspaces) {
  await vscode.commands.executeCommand(
    "setContext",
    "cloudsmith.hasMultipleWorkspaces",
    Boolean(hasMultipleWorkspaces)
  );
}

async function updateDefaultWorkspaceContext() {
  await vscode.commands.executeCommand(
    "setContext",
    "cloudsmith.hasDefaultWorkspace",
    Boolean(getDefaultWorkspace())
  );
}

async function getWorkspaces(context) {
    const cache = context.globalState.get('CloudsmithCache');
    if (cache && cache.name === 'Workspaces' && cache.workspaces) {
        // Check TTL — treat as stale if older than 30 minutes
        if (cache.lastSync && (Date.now() - cache.lastSync) < WORKSPACE_CACHE_TTL_MS) {
            await setHasMultipleWorkspacesContext(cache.workspaces.length > 1);
            return cache.workspaces;
        }
    }
    const cloudsmithAPI = new CloudsmithAPI(context);
    const result = await cloudsmithAPI.get("namespaces/?sort=slug");
    if (typeof result === 'string') {
        await setHasMultipleWorkspacesContext(false);
        vscode.window.showErrorMessage("Failed to load workspaces: " + result);
        return null;
    }
    if (!result || result.length === 0) {
        await setHasMultipleWorkspacesContext(false);
        return [];
    }
    await setHasMultipleWorkspacesContext(result.length > 1);
    return result;
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

async function resolveDependencyScanTarget(context) {
  const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
  let scanWorkspace = config.get("dependencyScanWorkspace");
  let scanRepo = config.get("dependencyScanRepo") || null;

  if (!scanWorkspace) {
    scanWorkspace = getDefaultWorkspace();
  }

  if (scanWorkspace) {
    return {
      scanWorkspace,
      scanRepo,
    };
  }

  const workspaces = await getWorkspaces(context);
  if (!workspaces) {
    return null;
  }
  if (workspaces.length === 0) {
    vscode.window.showErrorMessage("No workspaces found. Connect to Cloudsmith first.");
    return null;
  }

  const selectedWorkspace = await vscode.window.showQuickPick(
    workspaces.map((workspace) => ({
      label: workspace.name,
      description: workspace.slug,
    })),
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
    const cloudsmithAPI = new CloudsmithAPI(context);
    const repos = await cloudsmithAPI.get(`repos/${scanWorkspace}/?sort=name`);
    if (typeof repos !== "string" && Array.isArray(repos) && repos.length > 0) {
      const selectedRepo = await vscode.window.showQuickPick(
        repos.map((repository) => ({
          label: repository.name,
          description: repository.slug,
        })),
        {
          placeHolder: "Select a repository",
        }
      );

      if (selectedRepo) {
        scanRepo = selectedRepo.description;
      }
    }
  }

  return {
    scanWorkspace,
    scanRepo,
  };
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

  await context.secrets.store("cloudsmith-vsc.isConnected", "false");
  await setConnectedContext(false);
  await setHasMultipleWorkspacesContext(false);
  await updateDefaultWorkspaceContext();


  // Define main view provider which populates with data
  const cloudsmithProvider = new CloudsmithProvider(context);
  const treeView = vscode.window.createTreeView("cloudsmithView", {
    treeDataProvider: cloudsmithProvider,
    showCollapseAll: true,
  });
  cloudsmithProvider.setTreeView(treeView);
  cloudsmithProvider.setDefaultWorkspaceFallbackHandler((slug) => {
    treeView.title = "Workspaces";
    treeView.description = "";
    vscode.window.showWarningMessage(
      `Could not access workspace "${slug}". Showing all workspaces.`
    );
  });

  // Set tree view title and description from default workspace setting
  const defaultWs = getDefaultWorkspace();
  if (defaultWs) {
    treeView.title = "Repositories";
    treeView.description = defaultWs;
  }

  // Listen for configuration changes to refresh tree when defaultWorkspace changes
  context.subscriptions.push(
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
  vscode.window.registerTreeDataProvider("helpView", provider);

  // Set Package Search view.
  const searchProvider = new SearchProvider(context);
  vscode.window.createTreeView("cloudsmithSearchView", {
    treeDataProvider: searchProvider,
    showCollapseAll: true,
  });

  // Set Dependency Health view with diagnostics publisher.
  const diagnosticsPublisher = new DiagnosticsPublisher();
  context.subscriptions.push(diagnosticsPublisher);
  const dependencyHealthProvider = new DependencyHealthProvider(context, diagnosticsPublisher);
  vscode.window.createTreeView("cloudsmithDependencyHealthView", {
    treeDataProvider: dependencyHealthProvider,
    showCollapseAll: false,
  });

  context.subscriptions.push(
    context.secrets.onDidChange(async (e) => {
      if (e.key !== "cloudsmith-vsc.authToken") {
        return;
      }

      const apiKey = await context.secrets.get("cloudsmith-vsc.authToken");
      if (apiKey) {
        return;
      }

      await context.secrets.store("cloudsmith-vsc.isConnected", "false");
      await setConnectedContext(false);
      await setHasMultipleWorkspacesContext(false);
      cloudsmithProvider.refresh({ suppressMissingCredentialsWarning: true });
      searchProvider.refresh();
      dependencyHealthProvider.refresh();
    })
  );

  // Create vulnerability WebView provider
  const vulnerabilityProvider = new VulnerabilityProvider(context);
  context.subscriptions.push({ dispose: () => vulnerabilityProvider.dispose() });

  // Create compliance report WebView provider
  const complianceReportProvider = new ComplianceReportProvider(context);
  context.subscriptions.push({ dispose: () => complianceReportProvider.dispose() });

  // Create quarantine explanation WebView provider
  const quarantineExplainProvider = new QuarantineExplainProvider(context);
  context.subscriptions.push({ dispose: () => quarantineExplainProvider.dispose() });

  // Create upstream preview WebView provider
  const upstreamPreviewProvider = new UpstreamPreviewProvider(context);
  context.subscriptions.push({ dispose: () => upstreamPreviewProvider.dispose() });

  // Create upstream detail WebView provider
  const upstreamDetailProvider = new UpstreamDetailProvider(context);
  context.subscriptions.push({ dispose: () => upstreamDetailProvider.dispose() });

  // Create promotion provider
  const promotionProvider = new PromotionProvider(context);

  const initializeConnectionContext = async () => {
    const credentialManager = new CredentialManager(context);
    const apiKey = await credentialManager.getApiKey();
    if (!apiKey) {
      return;
    }

    try {
      const { ConnectionManager } = require("./util/connectionManager");
      const connectionManager = new ConnectionManager(context);
      await connectionManager.checkConnectivity(apiKey);
    } catch {
      await context.secrets.store("cloudsmith-vsc.isConnected", "false");
      await setConnectedContext(false);
    }
  };

  void initializeConnectionContext();


  // Shared post-authentication handler: connect, refresh all views, and prompt
  // to set default workspace if only one workspace is available.
  async function postAuthSuccess() {
    const { ConnectionManager } = require("./util/connectionManager");
    const connectionManager = new ConnectionManager(context);
    const status = await connectionManager.connect();

    // Refresh all three sidebar views
    cloudsmithProvider.refresh();
    searchProvider.refresh();
    dependencyHealthProvider.refresh();

    // If connected and no default workspace, offer to set the single workspace as default
    if (status === "true" && !getDefaultWorkspace()) {
      const workspaces = await getWorkspaces(context);
      if (Array.isArray(workspaces) && workspaces.length === 1) {
        const ws = workspaces[0];
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

    return status;
  }

  // Auto-detect Cloudsmith CLI credentials on activation.
  // If no API key is stored but CLI credentials exist, offer to import them.
  setTimeout(async () => {
    const existingKey = await context.secrets.get("cloudsmith-vsc.authToken");
    if (!existingKey) {
      const ssoManager = new SSOAuthManager(context);
      if (ssoManager.hasCLICredentials()) {
        const choice = await vscode.window.showInformationMessage(
          "Cloudsmith CLI credentials detected. Import them?",
          "Import", "Dismiss"
        );
        if (choice === "Import") {
          const success = await ssoManager.importFromCLI();
          if (success) {
            await postAuthSuccess();
          }
        }
      }
    }
  }, 3000);

  // register general commands. Will move this over to command Manager in future release.
  context.subscriptions.push(
    // Register command to clear credentials
    vscode.commands.registerCommand("cloudsmith-vsc.clearCredentials", () => {
      
      const credentialManager = new CredentialManager(context);
      credentialManager.clearCredentials();
    }),

    // Register command to set credentials — QuickPick with four auth methods
    vscode.commands.registerCommand("cloudsmith-vsc.configureCredentials", async () => {
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
        return;
      }

      if (selected._method === "sso-terminal") {
        await vscode.commands.executeCommand("cloudsmith-vsc.ssoLogin");
      } else if (selected._method === "import") {
        await vscode.commands.executeCommand("cloudsmith-vsc.importCLICredentials");
      } else {
        const credentialManager = new CredentialManager(context);
        const stored = await credentialManager.storeApiKey();
        if (stored) {
          await postAuthSuccess();
        }
      }
    }),

    // Register command to connect to Cloudsmith
    vscode.commands.registerCommand("cloudsmith-vsc.connectCloudsmith", async () => {
      await postAuthSuccess();
    }),

    // Register set default workspace command
    vscode.commands.registerCommand("cloudsmith-vsc.setDefaultWorkspace", async () => {
      const workspaces = await getWorkspaces(context);
      if (!workspaces) {
        return;
      }
      if (workspaces.length === 0) {
        vscode.window.showErrorMessage("No workspaces found. Connect to Cloudsmith first.");
        return;
      }

      const items = [
        { label: "$(close) Clear default workspace", description: "Show all workspaces", _clear: true },
      ];
      for (const ws of workspaces) {
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
          const result = await cloudsmithAPI.get(
            `packages/${workspace}/${repo}/${identifier}`
          );
          if (typeof result === "string") {
            vscode.window.showErrorMessage(formatApiError(result));
            return;
          }
          const jsonContent = JSON.stringify(result, null, 2);

          const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
          const inspectOutput = await config.get("inspectOutput");

          if (inspectOutput) {
            const doc = await vscode.workspace.openTextDocument({
              language: "json",
              content: jsonContent,
            });
            await vscode.window.showTextDocument(doc, { preview: true });
          } else {
            const outputChannel =
              vscode.window.createOutputChannel("Cloudsmith");
            outputChannel.clear();
            outputChannel.show(true);
            outputChannel.append(jsonContent);
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
          const result = await cloudsmithAPI.get(
            `packages/${workspace}/${repo}/?query=name:"${name}"`
          );
          if (typeof result === "string") {
            vscode.window.showErrorMessage(formatApiError(result));
            return;
          }
          const jsonContent = JSON.stringify(result, null, 2);

          const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
          const inspectOutput = await config.get("inspectOutput");

          if (inspectOutput) {
            const doc = await vscode.workspace.openTextDocument({
              language: "json",
              content: jsonContent,
            });
            await vscode.window.showTextDocument(doc, { preview: true });
          } else {
            const outputChannel =
              vscode.window.createOutputChannel("Cloudsmith");
            outputChannel.clear();
            outputChannel.show(true);
            outputChannel.append(jsonContent);
          }

          vscode.window.showInformationMessage(
            `Inspecting package group ${name}.`
          );
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

      //need to replace '/' in name as UI URL replaces these with _
      const pkg = name.replaceAll("/", "_");

      const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
      const useLegacyApp = await config.get("useLegacyWebApp");


      if (identifier) {
        if (useLegacyApp) {
          const url = `https://cloudsmith.io/~${workspace}/repos/${repo}/packages/detail/${format}/${pkg}/${version}`;
          vscode.env.openExternal(vscode.Uri.parse(url));
        } else {
          const url = `https://app.cloudsmith.com/${workspace}/${repo}/${format}/${pkg}/${version}/${identifier}`;
          vscode.env.openExternal(vscode.Uri.parse(url));
        }
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
        // Encode special characters for URL
        const encodedName = name.replaceAll("/", "%2F").replaceAll(":", "%3A");
        const url = `https://app.cloudsmith.com/${workspace}/${repo}?page=1&query=name:${encodedName}&sort=name`;
        vscode.env.openExternal(vscode.Uri.parse(url));
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
        if (workspaces.length === 0) {
          vscode.window.showErrorMessage("No workspaces found. Connect to Cloudsmith first.");
          return;
        }

        const items = [];
        for (const ws of workspaces) {
          items.push({ label: ws.name, description: ws.slug });
        }

        const selected = await vscode.window.showQuickPick(items, {
          placeHolder: "Select a workspace",
        });
        if (!selected) {
          return;
        }
        workspaceSlug = selected.description;
        recentSearches = new RecentSearches(context, workspaceSlug);
      }

      const recent = recentSearches.getAll();
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
          await searchProvider.search(selected._recent.workspace, selected._recent.query);
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
      recentSearches.add({ workspace: workspaceSlug, query: builtQuery, scope: 'workspace' });
      await searchProvider.search(workspaceSlug, builtQuery);
    }),

    // Register clear search command
    vscode.commands.registerCommand("cloudsmith-vsc.clearSearch", () => {
      searchProvider.clear();
      diagnosticsPublisher.clear();
    }),

    // Register load next page command
    vscode.commands.registerCommand("cloudsmith-vsc.searchNextPage", async () => {
      await searchProvider.loadNextPage();
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
      recentSearches.add({ workspace: workspace, query: builtQuery, scope: 'workspace' });
      await searchProvider.search(workspace, builtQuery);
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
        if (workspaces.length === 0) {
          vscode.window.showErrorMessage("No workspaces found. Connect to Cloudsmith first.");
          return;
        }

        // Step 1: Select workspace
        const wsItems = [];
        for (const ws of workspaces) {
          wsItems.push({ label: ws.name, description: ws.slug });
        }

        const selectedWs = await vscode.window.showQuickPick(wsItems, {
          placeHolder: "Step 1: Select a workspace",
        });
        if (!selectedWs) {
          return;
        }
        workspaceSlug = selectedWs.description;
        recentSearches = new RecentSearches(context, workspaceSlug);
      }

      const recent = recentSearches.getAll();
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
          await searchProvider.search(selectedRecent._recent.workspace, selectedRecent._recent.query);
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
        const cloudsmithAPI = new CloudsmithAPI(context);
        const repos = await cloudsmithAPI.get(`repos/${workspaceSlug}/?sort=name`);
        if (typeof repos === 'string' || !repos || repos.length === 0) {
          vscode.window.showErrorMessage("No repositories found in this workspace.");
          return;
        }
        const repoItems = repos.map(r => ({ label: r.name, description: r.slug }));
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

      // Save to recent searches
      recentSearches.add({
        workspace: workspaceSlug,
        query: finalQuery,
        scope: selectedRepos ? 'repository' : 'workspace',
      });

      // Execute search
      if (selectedRepos) {
        await searchProvider.searchRepos(workspaceSlug, selectedRepos, finalQuery);
      } else {
        await searchProvider.search(workspaceSlug, finalQuery);
      }
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
        vscode.window.showInformationMessage(`No safe versions found for "${name}" in ${crossRepo ? "the workspace" : repo}.`);
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

      const title = crossRepo
        ? `Safe versions of "${name}" (${format}) in the workspace`
        : `Safe versions of "${name}" (${format}) in ${repo}`;

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
          const installResult = InstallCommandBuilder.build(
            format,
            name,
            pkg.version,
            workspace,
            pkgRepo,
            getInstallOptions(pkg)
          );
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
          if (pkg.self_webapp_url) {
            vscode.env.openExternal(vscode.Uri.parse(pkg.self_webapp_url));
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
        item = await pickRecentPackage();
        if (!item) return;
      }
      recentPackages.add(item);
      await quarantineExplainProvider.show(item);
    }),

    // Register scan dependencies command
    vscode.commands.registerCommand("cloudsmith-vsc.scanDependencies", async () => {
      if (dependencyHealthProvider.lastWorkspace) {
        await dependencyHealthProvider.rescan();
        return;
      }

      const scanTarget = await resolveDependencyScanTarget(context);
      if (!scanTarget) {
        return;
      }

      await dependencyHealthProvider.scan(scanTarget.scanWorkspace, scanTarget.scanRepo);
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.scanDependenciesPending", async () => {
      await vscode.commands.executeCommand("cloudsmith-vsc.scanDependencies");
    }),

    vscode.commands.registerCommand("cloudsmith-vsc.scanDependenciesComplete", async () => {
      await vscode.commands.executeCommand("cloudsmith-vsc.scanDependencies");
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
      const result = InstallCommandBuilder.build(
        info.format, info.name, info.version || "latest", info.workspace, info.repo, getInstallOptions(item)
      );
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
        if (workspaces.length === 0) {
          vscode.window.showErrorMessage("No workspaces found. Connect to Cloudsmith first.");
          return;
        }

        const wsItems = workspaces.map(ws => ({ label: ws.name, description: ws.slug }));
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
      recentSearches.add({ workspace: workspaceSlug, query: query, scope: "workspace" });
      await searchProvider.search(workspaceSlug, query);
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
    vscode.commands.registerCommand("cloudsmith-vsc.ssoLogin", async () => {
      const workspaceSlug = await vscode.window.showInputBox({
        placeHolder: "my-org",
        prompt: "Enter the Cloudsmith workspace slug for SSO",
        ignoreFocusOut: true,
      });
      if (!workspaceSlug) {
        return;
      }

      const ssoManager = new SSOAuthManager(context);
      const ssoConfig = vscode.workspace.getConfiguration("cloudsmith-vsc");
      const useExperimental = ssoConfig.get("experimentalSSOBrowser");

      let success;
      if (useExperimental) {
        success = await ssoManager.loginViaBrowser(workspaceSlug.trim());
      } else {
        success = await ssoManager.loginViaTerminal(workspaceSlug.trim());
      }

      if (success) {
        await postAuthSuccess();
      }
    }),

    // Register import CLI credentials command
    vscode.commands.registerCommand("cloudsmith-vsc.importCLICredentials", async () => {
      const ssoManager = new SSOAuthManager(context);
      const success = await ssoManager.importFromCLI();
      if (success) {
        await postAuthSuccess();
      }
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
      const result = InstallCommandBuilder.build(
        info.format, info.name, info.version || "latest", info.workspace, info.repo, getInstallOptions(item)
      );
      let content = result.command;
      if (result.alternatives && result.alternatives.length > 0) {
        for (const alt of result.alternatives) {
          content += `\n\n# Alternative: ${alt.label}\n${alt.command}`;
        }
      }
      if (result.note) {
        content += "\n\n# Note: " + result.note;
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

      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "Generating Terraform configuration...",
        },
        async () => {
          try {
            const [repoResult, retentionResult, upstreamResult] = await Promise.all([
              cloudsmithAPI.get(`repos/${workspace}/${repoSlug}`),
              cloudsmithAPI.get(`repos/${workspace}/${repoSlug}/retention`),
              fetchRepositoryUpstreams(context, workspace, repoSlug, {
                signal: abortController.signal,
              }),
            ]);

            if (abortController.signal.aborted || upstreamResult === null) {
              return;
            }

            if (typeof repoResult === "string") {
              vscode.window.showErrorMessage(
                `Could not export repository. ${formatApiError(repoResult)}`
              );
              return;
            }

            const upstreamLoadFailed = Boolean(upstreamResult && upstreamResult.error);
            const retentionRules = (
              typeof retentionResult === "string" ||
              !retentionResult ||
              typeof retentionResult !== "object"
            )
              ? null
              : retentionResult;

            const hclContent = generateTerraformConfig({
              repo: repoResult,
              workspace,
              upstreams: upstreamLoadFailed ? [] : upstreamResult.data,
              retention: retentionRules,
              exportedAt: new Date().toISOString(),
              upstreamLoadFailed,
            });

            const doc = await vscode.workspace.openTextDocument({
              content: hclContent,
              language: await getPreferredTextDocumentLanguage(),
            });

            if (abortController.signal.aborted) {
              return;
            }

            await vscode.window.showTextDocument(doc);
          } catch (error) {
            if (abortController.signal.aborted) {
              return;
            }

            const message = error && error.message ? error.message : String(error);
            vscode.window.showErrorMessage(
              `Could not export repository. ${formatApiError(message)}`
            );
          } finally {
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
        if (workspaces.length === 0) {
          vscode.window.showErrorMessage("No workspaces found.");
          return;
        }
        const wsPick = await vscode.window.showQuickPick(
          workspaces.map(ws => ({ label: ws.name, description: ws.slug })),
          { placeHolder: "Select a workspace" }
        );
        if (!wsPick) return;
        wsSlug = wsPick.description;
      }

      // Select repo
      const cloudsmithAPI = new CloudsmithAPI(context);
      const repos = await cloudsmithAPI.get(`repos/${wsSlug}/?sort=name`);
      if (typeof repos === "string" || !repos || repos.length === 0) {
        vscode.window.showErrorMessage("No repositories found.");
        return;
      }
      const repoPick = await vscode.window.showQuickPick(
        repos.map(r => ({ label: r.name, description: r.slug })),
        { placeHolder: "Select target repository" }
      );
      if (!repoPick) return;
      targetRepo = repoPick.description;

      const checker = new UpstreamChecker(context);
      const result = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: "Checking upstream resolution..." },
        () => checker.previewResolution(wsSlug, targetRepo, pkgName, pkgFormat)
      );
      upstreamPreviewProvider.show(result);
    }),

    // Phase 10: Show promotion status
    vscode.commands.registerCommand("cloudsmith-vsc.showPromotionStatus", async (item) => {
      if (!item || !item.name) {
        item = await pickRecentPackage();
        if (!item) return;
      }
      recentPackages.add(item);

      const info = extractPackageInfo(item);
      if (!info.workspace || !info.name || !info.version) {
        vscode.window.showWarningMessage("Could not determine package details.");
        return;
      }

      const pipeline = promotionProvider.getPipeline();
      if (pipeline.length > 0) {
        // Pipeline mode: show status across configured repos
        const status = await promotionProvider.getPromotionStatus(
          info.workspace, info.name, info.version, info.format
        );

        if (status.length === 0) {
          vscode.window.showInformationMessage("No pipeline repositories found.");
          return;
        }

        const lines = status.map(s => {
          const icon = !s.found ? "\u2014" : (s.quarantined ? "\u274C" : (s.policyViolated ? "\u26A0\uFE0F" : "\u2705"));
          return `${icon} ${s.repo}: ${s.status}`;
        });
        vscode.window.showInformationMessage(
          `Pipeline for ${info.name} ${info.version}: ${lines.join(" \u2192 ")}`
        );
      } else {
        // No pipeline: search workspace-wide for this package name+version
        const cloudsmithAPI = new CloudsmithAPI(context);
        const query = encodeURIComponent(`name:^${info.name}$ AND version:${info.version}`);
        const results = await cloudsmithAPI.get(
          `packages/${info.workspace}/?query=${query}&page_size=100`
        );

        if (typeof results === "string" || !Array.isArray(results) || results.length === 0) {
          vscode.window.showInformationMessage(`${info.name} ${info.version} was not found in any other repository.`);
          return;
        }

        const lines = results.map(pkg => {
          const icon = pkg.status_str === "Quarantined" ? "\u274C" : (pkg.policy_violated ? "\u26A0\uFE0F" : "\u2705");
          return `${icon} ${pkg.repository}: ${pkg.status_str || "Unknown"}`;
        });
        vscode.window.showInformationMessage(
          `${info.name} ${info.version} found in: ${lines.join(", ")}`
        );
      }
    }),

    // Phase 10: Promote package
    vscode.commands.registerCommand("cloudsmith-vsc.promotePackage", async (item) => {
      if (!item) {
        item = await pickRecentPackage();
        if (!item) return;
      }
      recentPackages.add(item);

      const info = extractPackageInfo(item);
      if (!info.workspace || !info.repo || !info.slugPerm) {
        vscode.window.showWarningMessage("Could not determine package details.");
        return;
      }

      // Check is_copyable upfront to avoid a wasted API round-trip
      if (item.is_copyable === false) {
        vscode.window.showWarningMessage(
          "This package cannot be promoted. Write access to the target repository may be required."
        );
        return;
      }

      const pipeline = promotionProvider.getPipeline();
      const cloudsmithAPI = new CloudsmithAPI(context);
      let targetItems = [];

      if (pipeline.length > 0) {
        // Pipeline mode: suggest next eligible repo(s)
        const currentIdx = pipeline.indexOf(info.repo);
        const eligibleTargets = currentIdx >= 0
          ? pipeline.slice(currentIdx + 1)
          : pipeline.filter(r => r !== info.repo);

        if (eligibleTargets.length === 0) {
          vscode.window.showInformationMessage("Package is already in the last pipeline stage.");
          return;
        }

        targetItems = eligibleTargets.map(r => ({ label: r, description: r, _slug: r }));
      } else {
        // No pipeline: show all workspace repos except the source
        const repos = await cloudsmithAPI.get(`repos/${info.workspace}/?sort=name`);
        if (typeof repos === "string" || !Array.isArray(repos) || repos.length === 0) {
          vscode.window.showErrorMessage("Could not fetch workspace repositories.");
          return;
        }

        targetItems = repos
          .filter(r => r.slug !== info.repo)
          .map(r => ({ label: r.name, description: r.slug, _slug: r.slug }));
      }

      // Check for recent promotion history and prepend
      const historyKey = "cloudsmith-promotionHistory";
      const history = context.globalState.get(historyKey) || {};
      const recentTargets = (history[info.repo] || []).slice(0, 5);

      // Check where this package already exists (workspace-wide search)
      let existingRepoMap = {};
      if (info.name && info.version) {
        const query = encodeURIComponent(`name:^${info.name}$ AND version:${info.version}`);
        const existingResults = await cloudsmithAPI.get(
          `packages/${info.workspace}/?query=${query}&page_size=100`
        );
        if (Array.isArray(existingResults)) {
          for (const pkg of existingResults) {
            existingRepoMap[pkg.repository] = pkg.status_str || "Unknown";
          }
        }
      }

      // Annotate target items with existence status
      for (const ti of targetItems) {
        const existingStatus = existingRepoMap[ti._slug];
        if (existingStatus) {
          ti.description = `${ti._slug} — already exists (${existingStatus})`;
        } else {
          ti.description = `${ti._slug} — not present`;
        }
      }

      // Build final QuickPick items with recent history at the top
      const finalItems = [];
      if (recentTargets.length > 0) {
        finalItems.push({ label: "Recent", kind: vscode.QuickPickItemKind.Separator });
        for (const recentSlug of recentTargets) {
          const matching = targetItems.find(t => t._slug === recentSlug);
          if (matching) {
            finalItems.push({
              label: `$(history) ${matching.label}`,
              description: matching.description,
              _slug: matching._slug,
            });
          }
        }
        finalItems.push({ label: "All repositories", kind: vscode.QuickPickItemKind.Separator });
      }
      for (const ti of targetItems) {
        // Skip duplicates already in recent section
        if (!recentTargets.includes(ti._slug)) {
          finalItems.push(ti);
        }
      }

      const targetPick = await vscode.window.showQuickPick(finalItems, {
        placeHolder: `Select a target repository for ${info.name} ${info.version}`,
      });
      if (!targetPick || !targetPick._slug) return;

      const result = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: `Promoting package to ${targetPick._slug}...` },
        () => promotionProvider.promote(info.workspace, info.repo, info.slugPerm, targetPick._slug)
      );

      if (result && result.success) {
        // Store in promotion history
        const updatedHistory = context.globalState.get(historyKey) || {};
        const repoHistory = updatedHistory[info.repo] || [];
        // Add to front, dedupe, cap at 5
        const updated = [targetPick._slug, ...repoHistory.filter(r => r !== targetPick._slug)].slice(0, 5);
        updatedHistory[info.repo] = updated;
        await context.globalState.update(historyKey, updatedHistory);

        vscode.window.showInformationMessage(
          `Package "${info.name}" promoted from ${info.repo} to ${targetPick._slug}.`
        );
        cloudsmithProvider.refresh();
      } else {
        const reason = (result && result.error) ? formatApiError(result.error) : "Unknown error";
        vscode.window.showErrorMessage(
          `Could not promote ${info.name} to ${targetPick._slug}. ${reason}`
        );
      }
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
function deactivate() {}

module.exports = {
  activate,
  deactivate,
  FORMAT_OPTIONS,
};

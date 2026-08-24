const vscode = require("vscode");
const { CloudsmithProvider } = require("./views/cloudsmithProvider");
const { helpProvider } = require("./views/helpProvider");
const { SearchProvider } = require("./views/searchProvider");
const { CloudsmithAPI } = require("./util/cloudsmithAPI");
const { apiEndpoint } = require("./util/apiEndpoint");
const { CredentialManager } = require("./util/credentialManager");
const {
  ConnectionManager,
  bindConnectionManager,
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
const { UpstreamRuntime } = require("./util/upstreamRuntime");
const { UpstreamPullService } = require("./util/upstreamPullService");
const { UpstreamPreviewProvider } = require("./views/upstreamPreviewProvider");
const { UpstreamDetailProvider } = require("./views/upstreamDetailProvider");
const { PromotionProvider } = require("./views/promotionProvider");
const { normalizePackageQueryIdentity } = require("./util/promotionContracts");
const { SearchQueryBuilder } = require("./util/searchQueryBuilder");
const { formatApiError } = require("./util/errorFormatter");
const { normalizeCvssScore } = require("./util/vulnerabilitySeverity");
const { LicenseClassifier } = require("./util/licenseClassifier");
const { generateTerraformConfig } = require("./util/terraformExporter");
const { SUPPORTED_UPSTREAM_FORMATS } = require("./util/upstreamFormats");
const { buildPackageGroupUrl, buildPackageUrl } = require("./util/webAppUrls");
const recentPackages = require("./util/recentPackages");
const filterState = require("./util/filterState");
const { VulnerabilityStateService } = require("./util/vulnerabilityStateService");
const { WorkspaceCache } = require("./util/workspaceCache");
const { ContextKeyProjector } = require("./util/contextKeyProjector");
const { getWorkspaceContextProjector } = require("./util/workspaceContextProjector");
const { captureAccount, isAccountCurrent } = require("./util/accountOperation");
const { fetchWorkspaces, normalizedWorkspaceName } = require("./util/workspaceFetcher");
const { fetchWorkspaceRepositories } = require("./util/workspaceRepositoryFetcher");
const { PaginatedFetch, replaceCollectionItems } = require("./util/paginatedFetch");
const { packageCollectionIdentity } = require("./util/collectionIdentity");
const {
  serializePackageCollectionInspection,
  serializePackageInspection,
} = require("./util/packageInspection");
const { isSelectionCurrent } = require("./util/selectionProvenance");
const {
  connectionSetupAvailable,
} = require("./util/connectionPresentation");
const packageAdapters = require("./domain/packageAdapters");
const packageDomain = require("./domain/package");
const { authenticationCapabilitiesFor } = require("./domain/authCapabilities");
const { registerAuthenticationCommands } = require("./commands/authentication");
const { registerSettingsHelpCommands } = require("./commands/settingsHelp");
const { registerPackageCommands } = require("./commands/packages");
const { registerSearchCommands } = require("./commands/search");
const { registerDependencyHealthCommands } = require("./commands/dependencyHealth");
const { registerVulnerabilityCommands } = require("./commands/vulnerabilities");
const { registerPromotionCommands } = require("./commands/promotion");
const { registerUpstreamCommands } = require("./commands/upstream");
const { createCommandRegistration } = require("./commands/registrar");
const { getWorkspaces: loadAuthenticatedWorkspaces } = require("./util/workspaceAccess");
const { ActivationOwner } = require("./util/activationOwner");
const { createSSODiagnosticObserver } = require("./util/ssoDiagnostics");
const {
  beginAccountScopedStateReset,
  completeAccountScopedStateReset,
  createAuthenticationResultHandler,
} = require("./util/accountLifecycle");

let activeActivationOwner = null;

const FORMAT_OPTIONS = SUPPORTED_UPSTREAM_FORMATS;

function createExtensionContextBinding(options) {
  const {
    connectionManager,
    contextProjector,
    getDefaultWorkspace: readDefaultWorkspace,
    connectionSetupAvailable: readConnectionSetupAvailable = connectionSetupAvailable,
  } = options;
  const project = (state = connectionManager.getState()) => contextProjector.project({
    "cloudsmith.hasDefaultWorkspace": Boolean(readDefaultWorkspace()),
    "cloudsmith.connectionSetupAvailable": readConnectionSetupAvailable(state),
    "cloudsmith.credentialsPresent": state?.credentialPresent === true,
    "cloudsmith.pullThroughAvailable": authenticationCapabilitiesFor(
      connectionManager
    ).pullThroughAvailable,
  });
  const subscription = connectionManager.onDidChange(state => {
    void Promise.resolve(project(state)).catch(() => {});
  });
  return Object.freeze({
    project,
    dispose() { subscription?.dispose?.(); },
  });
}

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

async function activate(context) {
  await deactivate();
  const owner = new ActivationOwner();
  activeActivationOwner = owner;
  context.subscriptions.push(owner);
  const own = (...resources) => owner.add(...resources);
  const observe = (...args) => owner.observe(...args);
  try {
    return activateOwned(context, own, observe);
  } catch (error) {
    owner.dispose();
    await owner.settle();
    if (activeActivationOwner === owner) activeActivationOwner = null;
    throw error;
  }
}

function activateOwned(context, own, observe) {
  const activationReset = beginAccountScopedStateReset();
  if (activationReset.syncFailures.length > 0) {
    console.warn("[Cloudsmith] Some account-scoped singleton state could not be cleared.");
  }
  const inspectOutputChannel = vscode.window.createOutputChannel("Cloudsmith");
  own(inspectOutputChannel);
  const ssoDiagnosticObserver = createSSODiagnosticObserver(inspectOutputChannel);
  const connectionManager = new ConnectionManager(context, {
    diagnosticObserver: ssoDiagnosticObserver,
  });
  const connectionBinding = bindConnectionManager(context, connectionManager);
  own(connectionBinding, connectionManager);
  const extensionContextProjector = new ContextKeyProjector({
    defaults: {
      "cloudsmith.hasDefaultWorkspace": false,
      "cloudsmith.connectionSetupAvailable": false,
      "cloudsmith.credentialsPresent": false,
      "cloudsmith.pullThroughAvailable": false,
    },
    authorityScope: context,
  });
  own(extensionContextProjector);
  const extensionContextBinding = createExtensionContextBinding({
    connectionManager,
    contextProjector: extensionContextProjector,
    getDefaultWorkspace,
  });
  own(extensionContextBinding);
  const updateDefaultWorkspaceContext = () => extensionContextBinding.project(
    connectionManager.getState()
  );
  const upstreamRuntime = new UpstreamRuntime(context, { connectionManager });
  own(upstreamRuntime);
  const repositoryUpstreamInventory = Object.freeze({
    getAllUpstreamData: (...args) => upstreamRuntime.getAllUpstreamData(...args),
  });
  const detailUpstreamInventory = Object.freeze({
    getAllUpstreamData: (...args) => upstreamRuntime.getAllUpstreamData(...args),
    getUpstreamDataForFormats: (...args) => upstreamRuntime.getUpstreamDataForFormats(...args),
  });
  const upstreamPreview = Object.freeze({
    previewResolution: (...args) => upstreamRuntime.previewResolution(...args),
  });
  const gapAndPullUpstream = Object.freeze({
    getRepositoryUpstreamStateForFormats: (...args) => (
      upstreamRuntime.getRepositoryUpstreamStateForFormats(...args)
    ),
    createOperationScope: (...args) => upstreamRuntime.createOperationScope(...args),
  });
  const exportUpstream = Object.freeze({
    getPrivilegedRepositoryUpstreamsForExport: (...args) => (
      upstreamRuntime.getPrivilegedRepositoryUpstreamsForExport(...args)
    ),
  });
  const workspaceContextProjector = getWorkspaceContextProjector(context);
  own(workspaceContextProjector);

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
    upstreamInventory: repositoryUpstreamInventory,
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
    deferInitialContextProjection: true,
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
  const upstreamPullService = new UpstreamPullService(context, {
    connectionManager,
    upstreamRuntime: gapAndPullUpstream,
  });
  const dependencyHealthProvider = new DependencyHealthProvider(context, diagnosticsPublisher, {
    connectionManager,
    vulnerabilityStateService,
    upstreamGapRuntime: gapAndPullUpstream,
    upstreamPullService,
    accountResetOrchestrated: true,
    deferInitialContextProjection: true,
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
  const projectConnectionPresentation = state => extensionContextBinding.project(state);
  const connectionSubscription = connectionManager.onDidChange(state => {
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
        projectHasMultipleWorkspaces: value => setHasMultipleWorkspacesContext(
          context,
          value,
          { workspaceContextProjector }
        ),
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
  upstreamDetailProvider = new UpstreamDetailProvider(context, {
    connectionManager,
    upstreamInventory: detailUpstreamInventory,
  });
  own({ dispose: () => upstreamDetailProvider.dispose() });

  const credentialManager = new CredentialManager(context, { connectionManager });
  // Create promotion provider
  promotionProvider = new PromotionProvider(context, { connectionManager, credentialManager });
  own({ dispose: () => promotionProvider.dispose() });

  const ssoManager = new SSOAuthManager(context, {
    connectionManager,
    diagnosticObserver: ssoDiagnosticObserver,
  });


  const registerCommand = createCommandRegistration(vscode.commands);
  const commandOptions = {
    reportDisposalFailure() {
      console.warn("[Cloudsmith] A command registration could not be disposed cleanly.");
    },
  };
  const workspaceAccess = {
    context,
    vscode,
    connectionManager,
    workspaceContextProjector,
    captureAccount,
    isAccountCurrent,
    createCloudsmithAPI: () => new CloudsmithAPI(context),
    fetchWorkspaces,
    normalizedWorkspaceName,
    replaceCollectionItems,
    setHasMultipleWorkspacesContext: value => setHasMultipleWorkspacesContext(
      context,
      value,
      { workspaceContextProjector }
    ),
    fetchWorkspaceRepositories,
    formatApiError,
  };
  const sharedCommandDependencies = {
    ...commandOptions,
    registerCommand,
    vscode,
    context,
    workspaceAccess,
    packageAdapters,
    packageDomain,
    recentPackages,
    cloudsmithProvider,
    searchProvider,
    dependencyHealthProvider,
    vulnerabilityStateService,
    treeView,
    connectionManager,
    CloudsmithAPI,
    apiEndpoint,
    formatApiError,
    normalizeCvssScore,
    isCurrentSelection: selection => Boolean(
      isSelectionCurrent(selection)
      && (
        cloudsmithProvider.ownsSelection(selection)
        || searchProvider.ownsSelection(selection)
        || dependencyHealthProvider.ownsSelection(selection)
      )
    ),
    isCurrentPackageSelection: selection => Boolean(
      recentPackages.getAll().includes(selection)
      || cloudsmithProvider.ownsPackageSelection(selection)
      || searchProvider.ownsPackageSelection(selection)
      || dependencyHealthProvider.ownsDependencySelection(selection)
    ),
    isCurrentPackageGroupSelection: selection => cloudsmithProvider.ownsSelection(selection),
    isCurrentRepositorySelection: selection => (
      cloudsmithProvider.ownsRepositoryContextSelection(selection)
    ),
    isCurrentWorkspaceSelection: selection => cloudsmithProvider.ownsWorkspaceSelection(selection),
    isCurrentDependencySelection: selection => dependencyHealthProvider.ownsDependencySelection(selection),
    isCurrentEntitlementSelection: selection => Boolean(
      isSelectionCurrent(selection)
      && cloudsmithProvider.ownsEntitlementSelection(selection)
    ),
  };

  const handleAuthenticationResult = createAuthenticationResultHandler({
    vscode,
    connectionManager,
    treeView,
    cloudsmithProvider,
    updateDefaultWorkspaceContext,
    getDefaultWorkspace,
    getWorkspaces: () => loadAuthenticatedWorkspaces(workspaceAccess),
    captureAccount,
    isAccountCurrent,
  });
  own(registerAuthenticationCommands({
    ...sharedCommandDependencies,
    credentialManager,
    ssoManager,
    handleAuthenticationResult,
  }));
  own(registerSettingsHelpCommands({
    ...sharedCommandDependencies,
    updateDefaultWorkspaceContext,
  }));
  own(registerPackageCommands({
    ...sharedCommandDependencies,
    inspectOutputChannel,
    PaginatedFetch,
    packageCollectionIdentity,
    SearchQueryBuilder,
    LicenseClassifier,
    InstallCommandBuilder,
    InstallCommandValidationError,
    buildPackageUrl,
    buildPackageGroupUrl,
    filterState,
    formatApiError,
    serializePackageCollectionInspection,
    serializePackageInspection,
  }));
  own(registerSearchCommands({
    ...sharedCommandDependencies,
    RecentSearches,
    SearchQueryBuilder,
    LicenseClassifier,
    FORMAT_OPTIONS,
  }));
  own(registerDependencyHealthCommands({
    ...sharedCommandDependencies,
    complianceReportProvider,
    FILTER_MODES,
    SORT_MODES,
  }));
  own(registerVulnerabilityCommands({
    ...sharedCommandDependencies,
    RemediationHelper,
    InstallCommandBuilder,
    InstallCommandValidationError,
    buildPackageUrl,
    vulnerabilityProvider,
    quarantineExplainProvider,
  }));
  own(registerPromotionCommands({
    ...sharedCommandDependencies,
    promotionProvider,
    normalizePackageQueryIdentity,
  }));
  own(registerUpstreamCommands({
    ...sharedCommandDependencies,
    upstreamDetailProvider,
    upstreamPreviewProvider,
    upstreamPreview,
    upstreamExport: exportUpstream,
    generateTerraformConfig,
    FORMAT_OPTIONS,
  }));

  // Commands and their authoritative runtime guards are available before
  // startup storage, cache, context, credential validation, migration, or
  // refresh work begins. Each startup promise is activation-owned and
  // observed; owned resources revoke publication on deactivation without
  // making reload wait.
  observe(
    Promise.resolve().then(() => searchProvider.projectCurrentContext()),
    () => console.warn("[Cloudsmith] Search presentation initialization did not complete cleanly.")
  );
  observe(
    Promise.resolve().then(() => dependencyHealthProvider.projectCurrentContext()),
    () => console.warn("[Cloudsmith] Dependency presentation initialization did not complete cleanly.")
  );
  observe(
    Promise.resolve().then(() => setHasMultipleWorkspacesContext(
      context,
      false,
      { workspaceContextProjector }
    )),
    () => console.warn("[Cloudsmith] Workspace presentation initialization did not complete cleanly.")
  );
  observe(
    Promise.resolve().then(() => connectionManager.projectCurrentConnectionContext()),
    () => console.warn("[Cloudsmith] Connection indicator initialization did not complete cleanly.")
  );
  observe(
    Promise.resolve().then(() => projectConnectionPresentation(connectionManager.getState())),
    () => console.warn("[Cloudsmith] Connection presentation initialization did not complete cleanly.")
  );
  observe(
    Promise.resolve().then(() => upstreamRuntime.initialize()),
    () => console.warn("[Cloudsmith] Upstream runtime initialization did not complete cleanly.")
  );
  observe(
    Promise.resolve()
      .then(() => connectionManager.initialize())
      .then(result => handleAuthenticationResult(result, {
        showSuccess: false,
        offerDefault: false,
        reportFailure: false,
      })),
    () => console.warn("[Cloudsmith] Connection initialization did not complete cleanly.")
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
}

module.exports = { activate, createExtensionContextBinding, deactivate };

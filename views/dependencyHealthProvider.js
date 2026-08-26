// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const vscode = require("vscode");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { vulnerabilitySeverityRank } = require("../util/vulnerabilitySeverity");
const { apiEndpoint, appendApiQuery } = require("../util/apiEndpoint");
const {
  ADAPTER_RESULT_STATUSES,
  createDefaultDependencyAdapterRegistry,
  createSafeAdapterError,
  createSafeAdapterWarning,
} = require("../util/dependencyAdapterRegistry");
const {
  DEPENDENCY_QUALIFIER_KEYS,
  DEPENDENCY_VERSION_STATES,
  getDependencyArtifactKey,
  getDependencyConcreteVersion: getCanonicalDependencyConcreteVersion,
  getDependencyOccurrenceKey,
  isDependencyLookupEligible,
} = require("../util/dependencyRecord");
const { assertWorkspacePackageCoordinate } = require("../domain/package");
const {
  MAX_DIAGNOSTIC_OCCURRENCES,
  createDiagnosticCandidate,
} = require("../util/diagnosticsPublisher");
const { fetchWorkspaceRepositories } = require("../util/workspaceRepositoryFetcher");
const { SearchQueryBuilder } = require("../util/searchQueryBuilder");
const {
  packageCandidateEvidenceShapeIsValid,
  qualifierEvidenceIsIncomplete,
} = require("../util/exactPackageEvidence");
const {
  dockerCandidateMatchesPlatform,
  dockerDigestMatches,
  mavenArtifactFileName,
  normalizeNuGetVersion,
  rubyCandidateMatchesPlatform,
} = require("../util/registryEndpoints");
const { LicenseClassifier } = require("../util/licenseClassifier");
const {
  canonicalFormat,
  getCloudsmithPackageLookupKeys,
  getPackageLookupKeys,
  normalizePackageName,
  normalizeSwiftIdentity,
  sanitizePackageNameInput,
} = require("../util/packageNameNormalizer");
const {
  enrichVulnerabilities,
} = require("../util/dependencyVulnEnricher");
const {
  REPORT_VULNERABILITY_STATES,
  projectVulnerabilityForReport,
} = require("../util/vulnerabilityReportProjection");
const {
  getPackagePolicyFlags,
  getPackageVulnerabilityState,
} = require("../util/packageVulnerabilities");
const { enrichLicenses } = require("../util/dependencyLicenseEnricher");
const { getFoundDependencyKey } = require("../util/foundDependencyKey");
const { enrichPolicies } = require("../util/dependencyPolicyEnricher");
const {
  analyzeUpstreamGaps,
  getUncoveredDependencyKey,
} = require("../util/upstreamGapAnalyzer");
const {
  PULL_STATUS,
  buildPullSummaryMessage,
} = require("../util/upstreamPullService");
const DependencyHealthNode = require("../models/dependencyHealthNode");
const DependencySourceGroupNode = require("../models/dependencySourceGroupNode");
const DependencySummaryNode = require("../models/dependencySummaryNode");
const InfoNode = require("../models/infoNode");
const { createConnectionStatusNode } = require("../models/connectionStatusNode");
const { getConnectionManager } = require("../util/connectionManager");
const {
  CONNECTION_PRESENTATIONS,
  connectionPresentation,
} = require("../util/connectionPresentation");
const { packageCollectionIdentity } = require("../util/collectionIdentity");
const { fromApiPackageRecord } = require("../domain/packageAdapters");
const {
  PULL_THROUGH_API_KEY_MESSAGE,
  isPullThroughAvailable,
} = require("../domain/authCapabilities");
const { captureAccount, isAccountCurrent } = require("../util/accountOperation");
const { ContextKeyProjector } = require("../util/contextKeyProjector");

const DEFAULT_MAX_DEPENDENCIES_TO_SCAN = 10000;
const LOOKUP_PAGE_SIZE = 100;
const LOOKUP_MAX_PAGES = 100;
const LOOKUP_CONCURRENCY = 8;
const LOOKUP_MAX_REQUESTS_PER_RESOLUTION = 2000;
const LOOKUP_MAX_PACKAGE_NAME_LENGTH = 2048;
const LOOKUP_MAX_PACKAGE_FORMAT_LENGTH = 100;
const LOOKUP_MAX_PACKAGE_VERSION_LENGTH = 2048;
const COVERAGE_MATCH_BATCH_SIZE = 50;
const ENRICHMENT_PROGRESS_DEBOUNCE_MS = 500;
const LOOKUP_CONTROL_OR_BIDI = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u;
const UPSTREAM_COVERAGE_INCOMPLETE_WARNING = "Upstream coverage is incomplete. Positive matches are shown; missing coverage remains unknown.";

const CLOUDSMITH_COVERAGE_STATUS = Object.freeze({
  CHECKING: "CHECKING",
  FOUND: "FOUND",
  ABSENT: "ABSENT",
  UNRESOLVED: "UNRESOLVED",
  LOOKUP_FAILED: "LOOKUP_FAILED",
  LOOKUP_INCOMPLETE: "LOOKUP_INCOMPLETE",
  RATE_LIMITED: "RATE_LIMITED",
  NOT_APPLICABLE: "NOT_APPLICABLE",
});

const FILTER_MODES = Object.freeze({
  VULNERABLE: "vulnerable",
  UNCOVERED: "uncovered",
  RESTRICTIVE_LICENSE: "restrictive_license",
  POLICY_VIOLATION: "policy_violation",
});

const SORT_MODES = Object.freeze({
  ALPHABETICAL: "alphabetical",
  SEVERITY: "severity",
  COVERAGE: "coverage",
});

const VIEW_MODES = ["direct", "flat", "tree"];

const SCAN_STATES = Object.freeze({
  IDLE: "idle",
  SELECTING: "selecting",
  RUNNING: "running",
  SUCCEEDED: "succeeded",
  FAILED: "failed",
  CANCELLED: "cancelled",
});

class DependencyHealthProvider {
  constructor(context, diagnosticsPublisher, options = {}) {
    if (
      !options.upstreamGapRuntime
      || typeof options.upstreamGapRuntime.getRepositoryUpstreamStateForFormats !== "function"
      || typeof options.upstreamGapRuntime.createOperationScope !== "function"
    ) {
      throw new TypeError("DependencyHealthProvider requires an upstream gap facade.");
    }
    if (
      !options.upstreamPullService
      || typeof options.upstreamPullService.run !== "function"
      || typeof options.upstreamPullService.prepareSingle !== "function"
      || typeof options.upstreamPullService.execute !== "function"
    ) {
      throw new TypeError("DependencyHealthProvider requires an upstream pull service.");
    }
    this.context = context;
    this._diagnosticsPublisher = diagnosticsPublisher || null;
    this._connectionManager = options.connectionManager || getConnectionManager(context);
    this._vulnerabilityStateService = options.vulnerabilityStateService || null;
    this._vulnerabilitySummaries = new Map();
    this._treeParents = new WeakMap();
    this._dependencySourceGroups = new WeakMap();
    this._vulnerabilityRefreshTimers = new Map();
    this._treeView = null;
    this._expandedVulnerabilitySummaries = new WeakSet();
    this._treeExpansionSubscriptions = [];
    this._vulnerabilityTreeGeneration = 0;
    this._vulnerabilityStateSubscription = this._vulnerabilityStateService?.onDidChange?.(
      event => this._publishVulnerabilityState(event)
    ) || null;
    this._services = {
      enrichVulnerabilities: options.enrichVulnerabilities || enrichVulnerabilities,
      enrichLicenses: options.enrichLicenses || enrichLicenses,
      enrichPolicies: options.enrichPolicies || enrichPolicies,
      analyzeUpstreamGaps: options.analyzeUpstreamGaps || analyzeUpstreamGaps,
      fetchRepositories: options.fetchRepositories || null,
      upstreamGapRuntime: options.upstreamGapRuntime,
      upstreamPullService: options.upstreamPullService,
      createCloudsmithAPI: options.createCloudsmithAPI || (() => new CloudsmithAPI(this.context)),
    };
    this._dependencyAdapters = options.dependencyAdapters || createDefaultDependencyAdapterRegistry();
    this._lookupRequestLimit = Number.isInteger(options.lookupRequestLimit)
      && options.lookupRequestLimit > 0
      ? Math.min(options.lookupRequestLimit, LOOKUP_MAX_REQUESTS_PER_RESOLUTION)
      : LOOKUP_MAX_REQUESTS_PER_RESOLUTION;
    this._reportDateFactory = typeof options.reportDateFactory === "function"
      ? options.reportDateFactory
      : () => new Date();
    this._scheduler = normalizeScheduler(options.scheduler);
    this._createCancellationSource = typeof options.createCancellationSource === "function"
      ? options.createCancellationSource
      : () => new vscode.CancellationTokenSource();
    this._userInteraction = normalizeUserInteraction(options.userInteraction);
    this._workspace = options.workspace || vscode.workspace;
    this._projectFolderExists = typeof options.projectFolderExists === "function"
      ? options.projectFolderExists
      : async (folderPath) => {
        try {
          const stat = await this._workspace.fs.stat(vscode.Uri.file(folderPath));
          return Boolean(stat.type & vscode.FileType.Directory);
        } catch {
          return false;
        }
      };
    this._executeCommand = options.executeCommand
      || vscode.commands.executeCommand.bind(vscode.commands);
    this._contextProjector = options.contextKeyProjector || new ContextKeyProjector({
      defaults: {
        "cloudsmith.depView": "flat",
        "cloudsmith.depViewMode": "flat",
        "cloudsmith.depFilterActive": false,
        "cloudsmith.depScanComplete": false,
        "cloudsmith.depScanSucceeded": false,
        "cloudsmith.depScanRunning": false,
        "cloudsmith.depOperationRunning": false,
        "cloudsmith.depRepoSelected": false,
        "cloudsmith.depReportAvailable": false,
      },
      executeCommand: this._executeCommand,
      authorityScope: options.contextAuthorityScope || context,
    });
    this._contextDisposal = null;
    this._debouncedEnrichmentHandlers = new Set();
    this._disposed = false;
    this._onDidChangeTreeData = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    this.dependencies = [];
    this.lastWorkspace = null;
    this.lastRepo = null;
    this._warnings = [];
    this._lastManifests = [];
    this._projectFolderPath = null;
    this._noManifestsFolder = null;
    this._fullTrees = [];
    this._displayTrees = [];
    this._summary = emptySummary();
    this._viewMode = this._getInitialViewMode();
    this._sortMode = SORT_MODES.ALPHABETICAL;
    this._filterMode = null;
    this._reportData = null;
    this._lastScanTimestamp = null;
    this._nextScanOperationId = 0;
    this._activeScanCancellation = null;
    this._activeDependencyCancellation = null;
    this._nextDependencyOperationId = 0;
    this._activeDependencyOperation = null;
    this._scanOperation = createScanOperation(SCAN_STATES.IDLE, 0);
    this._hasSuccessfulScan = false;
    this._selectionGeneration = 0;
    this._dependencySelections = new WeakMap();
    this._accountResetOrchestrated = options.accountResetOrchestrated === true;
    this._accountIdentity = accountIdentity(this._connectionManager?.getState?.());
    this._pendingAccountIdentity = null;
    this._connectionPresentation = connectionPresentation(
      this._connectionManager?.getState?.()
    );
    this._connectionSubscription = this._connectionManager?.onDidChange?.(state => {
      const nextIdentity = accountIdentity(state);
      const identityChanged = !sameAccountIdentity(nextIdentity, this._accountIdentity);
      const nextPresentation = connectionPresentation(state);
      const presentationChanged = nextPresentation !== this._connectionPresentation;
      this._accountIdentity = nextIdentity;
      this._connectionPresentation = nextPresentation;
      if (identityChanged && this._accountResetOrchestrated) {
        this._pendingAccountIdentity = nextIdentity;
        this._invalidateAccountState();
        this.refresh();
        return;
      }
      if (identityChanged) {
        void this.resetForAccountChange(state).catch(() => {});
        return;
      }
      if (presentationChanged) this.refresh();
    }) || null;

    if (options.deferInitialContextProjection !== true) {
      void this._updateContexts().catch(() => {});
    }
  }

  _captureAccountEpoch() {
    const state = this._connectionManager && this._connectionManager.getState();
    return state && state.sessionConnected && Number.isInteger(state.accountEpoch)
      ? state.accountEpoch
      : null;
  }

  _isAccountCurrent(accountEpoch) {
    const state = this._connectionManager && this._connectionManager.getState();
    return Boolean(
      !this._disposed
      && Number.isInteger(accountEpoch)
      && state
      && state.sessionConnected
      && state.accountEpoch === accountEpoch
    );
  }

  _isDependencyOperationRunning() {
    return this._activeDependencyOperation !== null;
  }

  isDependencyOperationRunning() {
    return this._isDependencyOperationRunning();
  }

  _beginDependencyOperation(account) {
    if (!account || this._activeDependencyOperation) return null;
    const operation = Object.freeze({
      id: ++this._nextDependencyOperationId,
      account,
    });
    this._activeDependencyOperation = operation;
    return operation;
  }

  _ownsDependencyOperation(operation) {
    return Boolean(
      !this._disposed
      && operation
      && this._activeDependencyOperation === operation
      && operation.id === this._nextDependencyOperationId
      && isAccountCurrent(this._connectionManager, operation.account)
    );
  }

  _detachDependencyOperation() {
    this._nextDependencyOperationId += 1;
    this._activeDependencyOperation = null;
  }

  _getInitialViewMode() {
    const config = this._workspace.getConfiguration("cloudsmith-vsc");
    const configuredDefault = String(config.get("dependencyTreeDefaultView") || "flat");
    const storedView = this.context && this.context.workspaceState
      ? this.context.workspaceState.get("cloudsmith-vsc.dependencyTreeView")
      : null;
    const candidate = String(storedView || configuredDefault || "flat");
    return ["direct", "flat", "tree"].includes(candidate) ? candidate : "flat";
  }

  async _updateContexts() {
    if (this._disposed) return false;
    const connected = Boolean(captureAccount(this._connectionManager))
      && !this._pendingAccountIdentity;
    const scanRunning = this.isScanRunning();
    const result = await this._contextProjector.project({
      "cloudsmith.depView": this._viewMode,
      "cloudsmith.depViewMode": this._viewMode,
      "cloudsmith.depFilterActive": Boolean(this._filterMode),
      "cloudsmith.depScanComplete": connected && this._hasSuccessfulScan,
      "cloudsmith.depScanSucceeded": connected && this._hasSuccessfulScan,
      "cloudsmith.depScanRunning": connected && scanRunning,
      "cloudsmith.depOperationRunning": connected && (
        scanRunning || this._isDependencyOperationRunning()
      ),
      "cloudsmith.depRepoSelected": connected && Boolean(this.lastRepo),
      "cloudsmith.depReportAvailable": connected && Boolean(this._reportData),
    });
    if (result.error) throw result.error;
    return result.applied;
  }

  projectCurrentContext() {
    return this._updateContexts();
  }

  hasSuccessfulScan() {
    return this._hasSuccessfulScan;
  }

  isScanRunning() {
    return this._scanOperation.status === SCAN_STATES.SELECTING
      || this._scanOperation.status === SCAN_STATES.RUNNING;
  }

  getScanState() {
    const operation = { ...this._scanOperation };
    delete operation.accountEpoch;
    return {
      ...operation,
      hasSuccessfulScan: this._hasSuccessfulScan,
      successfulScope: this.getLastSuccessfulScope(),
    };
  }

  getLastSuccessfulScope() {
    if (!this._hasSuccessfulScan) {
      return null;
    }

    return {
      workspace: this.lastWorkspace,
      repository: this.lastRepo,
      projectFolder: this._projectFolderPath,
    };
  }

  _invalidateAccountState() {
    this._selectionGeneration += 1;
    this._nextScanOperationId += 1;
    if (this._activeScanCancellation) {
      this._activeScanCancellation.cancel();
    }
    if (this._activeDependencyCancellation) {
      this._activeDependencyCancellation.cancel();
      this._activeDependencyCancellation = null;
    }
    this._detachDependencyOperation();
    this.dependencies = [];
    this.lastWorkspace = null;
    this.lastRepo = null;
    this._warnings = [];
    this._lastManifests = [];
    this._projectFolderPath = null;
    this._noManifestsFolder = null;
    this._fullTrees = [];
    this._displayTrees = [];
    this._summary = emptySummary();
    this._reportData = null;
    this._lastScanTimestamp = null;
    this._hasSuccessfulScan = false;
    this._scanOperation = createScanOperation(SCAN_STATES.IDLE, this._nextScanOperationId);
    if (this._diagnosticsPublisher) {
      this._diagnosticsPublisher.clear();
    }
  }

  async resetForAccountChange(expectedState = null) {
    const expectedIdentity = accountIdentity(expectedState);
    if (
      this._accountResetOrchestrated
      && !sameAccountIdentity(expectedIdentity, this._pendingAccountIdentity)
    ) {
      return;
    }
    const alreadyInvalidated = this._accountResetOrchestrated
      && sameAccountIdentity(expectedIdentity, this._pendingAccountIdentity);
    if (!alreadyInvalidated) this._invalidateAccountState();
    try {
      await this._updateContexts();
    } finally {
      if (this._accountResetOrchestrated) {
        const currentIdentity = accountIdentity(this._connectionManager?.getState?.());
        if (
          sameAccountIdentity(expectedIdentity, currentIdentity)
          && sameAccountIdentity(this._pendingAccountIdentity, currentIdentity)
        ) {
          this._pendingAccountIdentity = null;
          this.refresh();
        }
      } else {
        this.refresh();
      }
    }
  }

  async setViewMode(mode) {
    if (!VIEW_MODES.includes(mode)) {
      return;
    }

    if (this.context && this.context.workspaceState && typeof this.context.workspaceState.update === "function") {
      await this.context.workspaceState.update("cloudsmith-vsc.dependencyTreeView", mode);
    }
    this._viewMode = mode;
    await this._updateContexts();
    this._rebuildSummary();
    this.refresh();
  }

  getViewMode() {
    return this._viewMode;
  }

  async cycleViewMode() {
    const currentIndex = VIEW_MODES.indexOf(this._viewMode);
    const nextMode = VIEW_MODES[(currentIndex + 1) % VIEW_MODES.length];
    await this.setViewMode(nextMode);
    return nextMode;
  }

  async setFilterMode(mode) {
    this._filterMode = mode || null;
    await this._updateContexts();
    this._rebuildSummary();
    this.refresh();
  }

  getFilterMode() {
    return this._filterMode;
  }

  async clearFilter() {
    await this.setFilterMode(null);
  }

  setSortMode(mode) {
    if (!Object.values(SORT_MODES).includes(mode)) {
      return;
    }

    this._sortMode = mode;
    this._rebuildSummary();
    this.refresh();
  }

  getSortMode() {
    return this._sortMode;
  }

  getReportData() {
    return this._reportData;
  }

  async _storeReportData(scanDate) {
    this._lastScanTimestamp = normalizeReportTimestamp(scanDate);
    this._reportData = this._buildComplianceReportData(this._lastScanTimestamp);
    await this._updateContexts();
  }

  _buildComplianceReportData(scanDate) {
    return buildComplianceReportData(
      path.basename(this.getProjectFolder() || "workspace"),
      this._fullTrees.flatMap((tree) => tree.dependencies),
      {
        scanDate,
        vulnerabilityStateFor: dependency => {
          const pkg = dependency && dependency.cloudsmithPackage;
          if (!pkg || !this._vulnerabilityStateService) return null;
          try {
            return this._vulnerabilityStateService.prime(pkg);
          } catch {
            return null;
          }
        },
      }
    );
  }

  getProjectFolder() {
    return this._projectFolderPath;
  }

  async isProjectFolderAvailableForRescan(folderPath) {
    if (typeof folderPath !== "string" || folderPath.length === 0) return false;
    const resolvedPath = path.resolve(folderPath);
    const isOpen = (this._workspace.workspaceFolders || []).some(folder => (
      typeof folder.uri?.fsPath === "string"
      && path.resolve(folder.uri.fsPath) === resolvedPath
    ));
    if (!isOpen) return false;
    try {
      return await this._projectFolderExists(folderPath) === true;
    } catch {
      return false;
    }
  }

  async promptForFolder() {
    const choice = await this._userInteraction.showQuickPick(
      [
        {
          label: "$(folder-opened) Select a folder to scan",
          description: "Browse for a project folder",
          _action: "pick",
        },
        {
          label: "$(folder) Open a project folder",
          description: "Open a folder in VS Code",
          _action: "open",
        },
      ],
      { placeHolder: "No workspace folder is open. Select a project folder to scan." }
    );

    if (!choice) {
      return null;
    }

    if (choice._action === "open") {
      await this._executeCommand("vscode.openFolder");
      return null;
    }

    const selected = await this._userInteraction.showOpenDialog({
      canSelectFolders: true,
      canSelectFiles: false,
      canSelectMany: false,
      openLabel: "Scan dependencies",
    });

    if (!selected || selected.length === 0) {
      return null;
    }

    return selected[0].fsPath;
  }

  async selectProjectFolder() {
    const foldersByPath = new Map();
    for (const folder of this._workspace.workspaceFolders || []) {
      foldersByPath.set(folder.uri.fsPath, {
        label: folder.name || path.basename(folder.uri.fsPath),
        description: folder.uri.fsPath,
        folderPath: folder.uri.fsPath,
      });
    }

    const selected = await this._userInteraction.showQuickPick(
      [
        ...foldersByPath.values(),
        {
          label: "$(folder-opened) Browse for a project folder",
          description: "Select a folder outside the open workspace",
          browse: true,
        },
      ],
      { placeHolder: "Select a project folder to scan" }
    );

    if (!selected) {
      return null;
    }
    if (!selected.browse) {
      return selected.folderPath;
    }

    const pickedFolders = await this._userInteraction.showOpenDialog({
      canSelectFolders: true,
      canSelectFiles: false,
      canSelectMany: false,
      openLabel: "Select project folder",
    });
    return pickedFolders && pickedFolders[0] ? pickedFolders[0].fsPath : null;
  }

  async scan(cloudsmithWorkspace, cloudsmithRepo, projectFolder) {
    if (this._disposed) return { status: "blocked" };
    if (this._pendingAccountIdentity) return { status: "blocked" };
    if (this._isDependencyOperationRunning()) {
      this._userInteraction.showWarningMessage("Wait for the current dependency operation to finish.");
      return { status: "blocked" };
    }

    const accountEpoch = this._captureAccountEpoch();
    if (accountEpoch === null) {
      this._userInteraction.showWarningMessage("Connect to Cloudsmith before scanning dependencies.");
      return { status: "blocked" };
    }

    const operationId = ++this._nextScanOperationId;
    const previousCancellation = this._activeScanCancellation;
    if (previousCancellation) {
      previousCancellation.cancel();
    }

    this._scanOperation = createScanOperation(SCAN_STATES.SELECTING, operationId, {
      startedAt: this._scheduler.now(),
      accountEpoch,
      scope: {
        workspace: cloudsmithWorkspace,
        repository: cloudsmithRepo || null,
        projectFolder: projectFolder || null,
      },
    });
    await this._updateContexts();
    this.refresh();

    let folderPath = projectFolder || null;
    if (!folderPath) {
      const openFolders = (this._workspace.workspaceFolders || [])
        .map(folder => folder.uri?.fsPath)
        .filter(candidate => typeof candidate === "string" && candidate.length > 0);
      if (openFolders.length === 1) {
        [folderPath] = openFolders;
      } else if (openFolders.length > 1) {
        folderPath = await this.selectProjectFolder();
      } else {
        folderPath = await this.promptForFolder();
      }
      if (!this._isCurrentScan(operationId, accountEpoch)) {
        return { status: "superseded" };
      }
      if (!folderPath) {
        await this._finishCancelledScan(operationId);
        return { status: SCAN_STATES.CANCELLED };
      }
    }

    const scope = {
      workspace: cloudsmithWorkspace,
      repository: cloudsmithRepo || null,
      projectFolder: folderPath,
    };
    this._scanOperation = createScanOperation(SCAN_STATES.RUNNING, operationId, {
      startedAt: this._scanOperation.startedAt,
      accountEpoch,
      scope,
    });
    await this._updateContexts();
    this.refresh();

    const cancellationSource = this._createCancellationSource();
    this._activeScanCancellation = cancellationSource;
    const scanWorker = this._createScanWorker(scope);

    try {
      const result = await this._userInteraction.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "Scanning dependencies",
          cancellable: true,
        },
        async (progress, token) => {
          const subscription = token.onCancellationRequested(() => cancellationSource.cancel());
          try {
            return await scanWorker._performScan(
              cloudsmithWorkspace,
              cloudsmithRepo,
              folderPath,
              progress,
              cancellationSource.token
            );
          } finally {
            subscription.dispose();
          }
        }
      );

      if (!this._isCurrentScan(operationId, accountEpoch)) {
        return { status: "superseded" };
      }

      if ((result && result.canceled) || cancellationSource.token.isCancellationRequested) {
        await this._finishCancelledScan(operationId);
        return { status: SCAN_STATES.CANCELLED };
      }

      const preparedDiagnostics = await this._prepareDiagnostics(
        scanWorker,
        cancellationSource.token
      );
      if (!this._isCurrentScan(operationId, accountEpoch)) {
        return { status: "superseded" };
      }

      if (cancellationSource.token.isCancellationRequested) {
        await this._finishCancelledScan(operationId);
        return { status: SCAN_STATES.CANCELLED };
      }

      if (this._diagnosticsPublisher) {
        this._diagnosticsPublisher.replace(preparedDiagnostics.entries);
      }
      this._commitSuccessfulScan(scanWorker, scope, operationId, accountEpoch);
      await this._updateContexts();
      this.refresh();
      return { status: SCAN_STATES.SUCCEEDED };
    } catch (error) {
      if (!this._isCurrentScan(operationId, accountEpoch)) {
        return { status: "superseded" };
      }

      if (cancellationSource.token.isCancellationRequested) {
        await this._finishCancelledScan(operationId);
        return { status: SCAN_STATES.CANCELLED };
      }

      const reason = safeScanFailureReason(error);
      const message = this._hasSuccessfulScan
        ? `Dependency refresh failed. Previous scan results are still available. ${reason}`
        : `Dependency scan failed. ${reason}`;
      this._scanOperation = createScanOperation(SCAN_STATES.FAILED, operationId, {
        startedAt: this._scanOperation.startedAt,
        accountEpoch,
        completedAt: this._scheduler.now(),
        failureMessage: message,
        scope,
      });
      await this._updateContexts();
      this.refresh();
      if (this._hasSuccessfulScan) {
        this._userInteraction.showWarningMessage(message);
      } else {
        this._userInteraction.showErrorMessage(message);
      }
      return { status: SCAN_STATES.FAILED, error };
    } finally {
      cancellationSource.dispose();
      if (this._activeScanCancellation === cancellationSource) {
        this._activeScanCancellation = null;
      }
    }
  }

  _isCurrentScan(operationId, accountEpoch = this._scanOperation.accountEpoch) {
    return !this._disposed
      && this._scanOperation.id === operationId
      && this._isAccountCurrent(accountEpoch);
  }

  _createScanWorker(scope) {
    // Reuse the scan pipeline while giving the operation its own mutable result fields.
    // Nothing copied from this worker becomes visible until _commitSuccessfulScan runs.
    const worker = Object.create(this);
    worker.dependencies = [];
    worker.lastWorkspace = scope.workspace;
    worker.lastRepo = scope.repository;
    worker._warnings = [];
    worker._lastManifests = [];
    worker._projectFolderPath = scope.projectFolder;
    worker._noManifestsFolder = null;
    worker._fullTrees = [];
    worker._displayTrees = [];
    worker._summary = emptySummary();
    worker._reportData = null;
    worker._lastScanTimestamp = null;
    worker._statusMessage = "Parsing lockfiles...";
    worker._diagnosticsPublisher = null;
    worker._updateContexts = async () => {};
    worker.refresh = () => {};
    return worker;
  }

  async _finishCancelledScan(operationId) {
    if (!this._isCurrentScan(operationId)) {
      return;
    }

    const currentOperation = this._scanOperation;
    this._scanOperation = createScanOperation(SCAN_STATES.CANCELLED, operationId, {
      startedAt: currentOperation.startedAt,
      accountEpoch: currentOperation.accountEpoch,
      completedAt: this._scheduler.now(),
      scope: currentOperation.scope,
      message: this._hasSuccessfulScan
        ? "Dependency refresh canceled. Previous scan results are shown."
        : "Dependency scan canceled.",
    });
    await this._updateContexts();
    this.refresh();
  }

  _commitSuccessfulScan(scanWorker, scope, operationId, accountEpoch) {
    if (!this._isCurrentScan(operationId, accountEpoch)) {
      return;
    }
    // Selection authority follows committed scan snapshots. Presentation-only
    // refreshes keep the prior rows visible and must not make their actions inert.
    this._selectionGeneration += 1;
    this.lastWorkspace = scope.workspace;
    this.lastRepo = scope.repository;
    this._warnings = scanWorker._warnings;
    this._lastManifests = scanWorker._lastManifests;
    this._projectFolderPath = scope.projectFolder;
    this._noManifestsFolder = scanWorker._noManifestsFolder;
    this._fullTrees = scanWorker._fullTrees;
    this._displayTrees = scanWorker._displayTrees;
    this._reportData = scanWorker._reportData;
    this._lastScanTimestamp = scanWorker._lastScanTimestamp;
    this._rebuildSummary();
    this._hasSuccessfulScan = true;
    this._scanOperation = createScanOperation(SCAN_STATES.SUCCEEDED, operationId, {
      startedAt: this._scanOperation.startedAt,
      accountEpoch,
      completedAt: this._scheduler.now(),
      scope,
    });
  }

  async _prepareDiagnostics(scanState, cancellationToken) {
    if (!this._diagnosticsPublisher) {
      return { entries: [], warnings: [], stats: null };
    }

    const candidates = [];
    let examinedDirectDependencies = 0;
    let candidateLimitReached = false;
    outer: for (const tree of scanState._fullTrees) {
      for (const dependency of Array.isArray(tree.dependencies) ? tree.dependencies : []) {
        if (!dependency || dependency.isDirect !== true) {
          continue;
        }
        if (examinedDirectDependencies >= MAX_DIAGNOSTIC_OCCURRENCES) {
          candidateLimitReached = true;
          break outer;
        }
        examinedDirectDependencies += 1;
        const healthNode = new DependencyHealthNode(dependency, null, this.context, {
          connectionManager: this._connectionManager,
          ...this._vulnerabilityNodeOptions(),
        });
        if (!["quarantined", "violated", "not_found"].includes(healthNode.state)) {
          continue;
        }
        candidates.push(createDiagnosticCandidate(dependency, {
          state: healthNode.state,
          displayVersion: healthNode.declaredVersion || null,
          cloudsmithPackage: healthNode.package || null,
        }));
      }
    }
    if (candidateLimitReached) {
      appendUniqueWarning(
        scanState._warnings,
        "Dependency diagnostic evaluation reached its safety limit; dependency health results remain complete."
      );
    }

    const prepared = await this._diagnosticsPublisher.prepare({
      workspaceFolder: scanState._projectFolderPath,
      candidates,
      cancellationToken,
    });
    for (const warning of prepared.warnings) {
      appendUniqueWarning(scanState._warnings, warning);
    }
    return prepared;
  }

  _getMaxDependenciesToScan() {
    const configuredValue = Number(this._workspace.getConfiguration("cloudsmith-vsc").get("maxDependenciesToScan"));
    if (!Number.isFinite(configuredValue) || configuredValue < 1) {
      return DEFAULT_MAX_DEPENDENCIES_TO_SCAN;
    }
    return Math.floor(configuredValue);
  }

  async _performScan(cloudsmithWorkspace, cloudsmithRepo, folderPath, progress, token) {
    progress.report({ message: "Parsing lockfiles..." });
    const warnings = [];
    const parserErrors = [];
    this._lastManifests = await this._dependencyAdapters.detectManifests(folderPath, {
      cancellationToken: token,
    });
    if (typeof this._dependencyAdapters.getDiscoveryWarnings === "function") {
      for (const warning of this._dependencyAdapters.getDiscoveryWarnings()) {
        appendUniqueWarning(warnings, safeDiscoveryWarning(warning));
      }
    }
    if (token.isCancellationRequested) {
      return { canceled: true };
    }

    const resolveTransitives = this._workspace.getConfiguration("cloudsmith-vsc").get("resolveTransitiveDependencies") !== false;
    const trees = [];
    const coveredManifestPaths = new Set();

    if (resolveTransitives) {
      const detections = await this._dependencyAdapters.detect(folderPath, {
        cancellationToken: token,
      });
      if (typeof this._dependencyAdapters.getDiscoveryWarnings === "function") {
        for (const warning of this._dependencyAdapters.getDiscoveryWarnings()) {
          const safeWarning = safeDiscoveryWarning(warning);
          if (!warnings.includes(safeWarning)) {
            warnings.push(safeWarning);
          }
        }
      }
      if (token.isCancellationRequested) {
        return { canceled: true };
      }
      for (const detection of detections) {
        if (token.isCancellationRequested) {
          return { canceled: true };
        }
        const result = await this._dependencyAdapters.parse(detection, {
          workspaceFolder: folderPath,
          maxDependenciesToScan: this._getMaxDependenciesToScan(),
          cancellationToken: token,
        });
        if (result.status === ADAPTER_RESULT_STATUSES.ERROR) {
          const message = createSafeAdapterError(result.error).message;
          warnings.push(message);
          parserErrors.push(message);
          continue;
        }
        if (
          result.status === ADAPTER_RESULT_STATUSES.SUCCESS
          || result.status === ADAPTER_RESULT_STATUSES.PARTIAL
        ) {
          trees.push({
            adapterId: result.adapterId,
            ecosystem: result.ecosystem,
            sourceFile: result.sourceFile,
            source: result.source,
            dependencies: result.dependencies,
            dependencyGraph: result.dependencyGraph || null,
            warnings: result.warnings,
          });
          const sourceManifestPath = result.source
            && result.source.manifest
            && result.source.manifest.filePath;
          if (sourceManifestPath) {
            coveredManifestPaths.add(path.resolve(sourceManifestPath));
          }
          if (result.warnings.length > 0) {
            for (const warning of result.warnings) {
              warnings.push(createSafeAdapterWarning(warning));
            }
          }
        }
      }
    }

    const uncoveredManifests = this._lastManifests.filter((manifest) => (
      !coveredManifestPaths.has(path.resolve(manifest.filePath))
    ));
    const fallbackTrees = await this._buildManifestFallbackTrees(
      uncoveredManifests,
      warnings,
      parserErrors,
      token
    );
    if (token.isCancellationRequested) {
      return { canceled: true };
    }
    trees.push(...fallbackTrees);

    if (trees.length === 0) {
      if (parserErrors.length > 0) {
        throw new Error(
          `Dependency files were detected, but parsing did not complete. ${parserErrors[0]}`
        );
      }
      this._displayTrees = [];
      this._fullTrees = [];
      this._summary = emptySummary();
      this._statusMessage = null;
      this._warnings = warnings.slice();
      if (this._lastManifests.length === 0) {
        this._noManifestsFolder = path.basename(folderPath);
      }
      await this._storeReportData(this._reportDateFactory());
      return { canceled: false };
    }

    const normalizedTrees = trees
      .map(normalizeTree)
      .filter((tree) => Array.isArray(tree.dependencies) && tree.dependencies.length > 0);

    if (normalizedTrees.length === 0) {
      if (parserErrors.length > 0) {
        throw new Error(
          `Dependency files were detected, but parsing did not complete. ${parserErrors[0]}`
        );
      }
      this._displayTrees = [];
      this._fullTrees = [];
      this._summary = emptySummary();
      this._statusMessage = null;
      this._warnings = warnings.slice();
      await this._storeReportData(this._reportDateFactory());
      return { canceled: false };
    }

    this._noManifestsFolder = null;
    this._fullTrees = markTreesAsChecking(normalizedTrees);

    const limited = limitDisplayTrees(this._fullTrees, this._getMaxDependenciesToScan());
    this._displayTrees = limited.trees;
    this._warnings = warnings.slice();
    if (limited.truncated) {
      const warning = "Dependency display reached its configured safety limit; "
        + "the complete resolved inventory remains available to the scan pipeline.";
      appendUniqueWarning(this._warnings, warning);
    }
    this._statusMessage = null;
    this._rebuildSummary();
    this.refresh();

    const totalCoverageDependencies = countCoverageDependencies(this._fullTrees);
    progress.report({
      message: `Found ${limited.totalDependencies} dependencies. Fetching package index...`,
    });

    await this._runCoverageChecks(
      cloudsmithWorkspace,
      cloudsmithRepo,
      totalCoverageDependencies,
      progress,
      token
    );

    if (token.isCancellationRequested) {
      return { canceled: true };
    }

    progress.report({
      message: "Enriching vulnerabilities, licenses, policy, and upstream availability...",
    });

    await this._runEnrichmentPasses(cloudsmithWorkspace, cloudsmithRepo, progress, token);

    if (token.isCancellationRequested) {
      return { canceled: true };
    }

    this._rebuildSummary();
    await this._storeReportData(this._reportDateFactory());
    return { canceled: false };
  }

  async _buildManifestFallbackTrees(manifests, warnings = [], parserErrors = [], token = null) {
    const trees = [];
    for (const manifest of manifests) {
      if (token && token.isCancellationRequested) break;
      const result = await this._dependencyAdapters.parseManifest(manifest, {
        cancellationToken: token,
      });
      if (
        result.status === ADAPTER_RESULT_STATUSES.ERROR
        || result.status === ADAPTER_RESULT_STATUSES.UNSUPPORTED
      ) {
        const message = createSafeAdapterError(result.error).message;
        warnings.push(message);
        parserErrors.push(message);
        continue;
      }
      for (const warning of result.warnings || []) {
        const safeWarning = createSafeAdapterWarning(warning);
        warnings.push(safeWarning);
      }
      if (
        ![
          ADAPTER_RESULT_STATUSES.SUCCESS,
          ADAPTER_RESULT_STATUSES.PARTIAL,
        ].includes(result.status)
        || result.dependencies.length === 0
      ) {
        continue;
      }
      trees.push({
        adapterId: result.adapterId,
        ecosystem: result.ecosystem,
        sourceFile: result.sourceFile || path.basename(manifest.filePath),
        source: result.source,
        dependencies: result.dependencies,
        warnings: result.warnings,
      });
    }
    return trees;
  }

  async _runCoverageChecks(cloudsmithWorkspace, cloudsmithRepo, totalDependencies, progress, token) {
    const dependenciesByFormat = groupDependenciesByFormat(this._fullTrees);
    await this._runCoverageResolution(
      cloudsmithWorkspace,
      cloudsmithRepo,
      dependenciesByFormat,
      totalDependencies,
      progress,
      token,
      {
        packageIndexFailureVerb: "fetch",
        progressLabel: "Matching coverage",
      }
    );
  }

  async _runCoverageResolution(
    cloudsmithWorkspace,
    cloudsmithRepo,
    dependenciesByFormat,
    totalDependencies,
    progress,
    token,
    options = {}
  ) {
    const formats = Object.keys(dependenciesByFormat);
    const progressLabel = options.progressLabel || "Matching coverage";

    if (formats.length === 0 || totalDependencies === 0) {
      return 0;
    }

    let completed = 0;
    const requestBudget = createLookupRequestBudget(this._lookupRequestLimit);
    for (const format of formats) {
      if (token.isCancellationRequested) {
        return completed;
      }

      completed = await this._resolveCoverageWithExactQueries(
        cloudsmithWorkspace,
        cloudsmithRepo,
        format,
        uniqueDependenciesForCoverage(dependenciesByFormat[format]),
        completed,
        totalDependencies,
        progress,
        token,
        progressLabel,
        requestBudget,
        options.verificationReceipt || null,
        options.verificationReceipts || null
      );
    }

    return completed;
  }

  async _flushCoverageMatchBatch(pendingMatches, completed, totalDependencies, progress, progressLabel) {
    if (pendingMatches.length === 0) {
      return completed;
    }

    this._applyCoverageMatchBatch(pendingMatches);

    const batchSize = pendingMatches.length;
    pendingMatches.length = 0;
    completed += batchSize;

    this._rebuildSummary();
    progress.report({
      message: `${progressLabel}... ${completed}/${totalDependencies}`,
      increment: totalDependencies > 0 ? (batchSize * 100) / totalDependencies : 100,
    });
    this.refresh();
    await this._scheduler.yield();

    return completed;
  }

  _applyCoverageMatchBatch(matches) {
    if (!Array.isArray(matches) || matches.length === 0) {
      return;
    }

    const matchMap = new Map();
    for (const { dependency, result } of matches) {
      matchMap.set(coverageLookupKey(dependency), {
        cloudsmithStatus: result.status,
        cloudsmithPackage: result.package || null,
        cloudsmithLookupDetail: result.detail || null,
        ...(result.status === CLOUDSMITH_COVERAGE_STATUS.FOUND
          ? { upstreamStatus: null, upstreamDetail: null }
          : {}),
      });
    }

    this._fullTrees = applyCoverageMatchBatchToTrees(this._fullTrees, matchMap);
    this._displayTrees = applyCoverageMatchBatchToTrees(this._displayTrees, matchMap);
  }

  _createDebouncedEnrichmentHandler(patchApplier) {
    let pendingPatchMaps = [];
    let flushTimeout = null;
    let disposed = false;

    const flush = () => {
      if (flushTimeout) {
        this._scheduler.clearTimeout(flushTimeout);
        flushTimeout = null;
      }

      if (disposed || pendingPatchMaps.length === 0) {
        return;
      }

      const mergedPatchMap = mergePatchMaps(pendingPatchMaps);
      pendingPatchMaps = [];

      patchApplier(mergedPatchMap);
      this._rebuildSummary();
      this.refresh();
    };

    const handler = {
      onProgress: (patchMap) => {
        if (disposed || !(patchMap instanceof Map) || patchMap.size === 0) {
          return;
        }

        pendingPatchMaps.push(patchMap);
        if (!flushTimeout) {
          flushTimeout = this._scheduler.setTimeout(() => {
            flushTimeout = null;
            flush();
          }, ENRICHMENT_PROGRESS_DEBOUNCE_MS);
        }
      },
      flush,
      dispose: () => {
        if (disposed) return;
        disposed = true;
        pendingPatchMaps = [];
        if (flushTimeout) {
          this._scheduler.clearTimeout(flushTimeout);
          flushTimeout = null;
        }
        this._debouncedEnrichmentHandlers.delete(handler);
      },
    };
    this._debouncedEnrichmentHandlers.add(handler);
    return handler;
  }

  async _resolveCoverageWithExactQueries(
    cloudsmithWorkspace,
    cloudsmithRepo,
    format,
    dependencies,
    completed,
    totalDependencies,
    progress,
    token,
    progressLabel = "Matching coverage",
    requestBudget = null,
    verificationReceipt = null,
    verificationReceipts = null
  ) {
    const uniqueDependencies = dependencies.slice();
    const api = uniqueDependencies.some((dependency) => getConcreteDependencyVersion(dependency))
      ? this._services.createCloudsmithAPI()
      : null;
    const statusCounts = new Map();

    for (let index = 0; index < uniqueDependencies.length; index += COVERAGE_MATCH_BATCH_SIZE) {
      if (token.isCancellationRequested) {
        return completed;
      }

      const dependencyBatch = uniqueDependencies.slice(index, index + COVERAGE_MATCH_BATCH_SIZE);
      const pendingMatches = [];

      await runPromisePool(dependencyBatch, LOOKUP_CONCURRENCY, async (dependency) => {
        if (token.isCancellationRequested) {
          return;
        }

        let result;
        try {
          const dependencyVerificationReceipt = verificationReceipts instanceof Map
            ? verificationReceipts.get(getDependencyArtifactKey(dependency)) || null
            : verificationReceipt;
          result = await lookupExactDependency({
            api,
            cloudsmithWorkspace,
            cloudsmithRepo,
            dependency,
            token,
            requestBudget,
            verificationReceipt: dependencyVerificationReceipt,
          });
        } catch {
          result = createCoverageLookupResult(
            CLOUDSMITH_COVERAGE_STATUS.LOOKUP_FAILED,
            null,
            "The Cloudsmith lookup failed unexpectedly without proving package absence."
          );
        }
        statusCounts.set(result.status, (statusCounts.get(result.status) || 0) + 1);
        pendingMatches.push({ dependency, result });
      });

      completed = await this._flushCoverageMatchBatch(
        pendingMatches,
        completed,
        totalDependencies,
        progress,
        progressLabel
      );

      if (token.isCancellationRequested) {
        return completed;
      }
    }

    appendCoverageLookupWarnings(this._warnings, format, statusCounts);
    return completed;
  }

  async _runEnrichmentPasses(cloudsmithWorkspace, cloudsmithRepo, progress, token) {
    const dependencies = this._fullTrees.flatMap((tree) => tree.dependencies);
    const lookupEligibleDependencies = dependencies.filter(isLookupEligibleForConsumer);
    const tasks = [
      this._runVulnerabilityEnrichment(lookupEligibleDependencies, cloudsmithWorkspace, progress, token),
      this._runLicenseEnrichment(lookupEligibleDependencies, token),
      this._runPolicyEnrichment(lookupEligibleDependencies, token),
    ];

    const uncoveredDependencies = dependencies.filter((dependency) => isAbsentCoverageStatus(dependency.cloudsmithStatus));
    if (uncoveredDependencies.length > 0) {
      tasks.push(this._runUpstreamGapAnalysis(uncoveredDependencies, cloudsmithWorkspace, cloudsmithRepo, progress, token));
    }

    const results = await Promise.allSettled(tasks);
    for (const result of results) {
      if (result.status !== "rejected") {
        continue;
      }

      appendUniqueWarning(
        this._warnings,
        safeEnrichmentFailureMessage()
      );
    }
  }

  async _runVulnerabilityEnrichment(dependencies, workspace, progress, token) {
    const handler = this._createDebouncedEnrichmentHandler((patchMap) => {
      this._fullTrees = applyFoundOverlayPatch(this._fullTrees, patchMap, (dependency, vulnerabilities) => ({
        ...dependency,
        vulnerabilities,
      }));
      this._displayTrees = applyFoundOverlayPatch(this._displayTrees, patchMap, (dependency, vulnerabilities) => ({
        ...dependency,
        vulnerabilities,
      }));
    });

    try {
      await this._services.enrichVulnerabilities(dependencies, workspace, {
        context: this.context,
        cancellationToken: token,
        onProgress: (patchMap, meta = {}) => {
          if (meta.total > 0) {
            progress.report({
              message: `Loading vulnerability details... ${meta.completed}/${meta.total}`,
            });
          }
          handler.onProgress(patchMap);
        },
      });
    } finally {
      handler.flush();
      handler.dispose();
    }
  }

  async _runLicenseEnrichment(dependencies, token) {
    const handler = this._createDebouncedEnrichmentHandler((patchMap) => {
      this._fullTrees = applyFoundOverlayPatch(this._fullTrees, patchMap, (dependency, license) => ({
        ...dependency,
        license,
      }));
      this._displayTrees = applyFoundOverlayPatch(this._displayTrees, patchMap, (dependency, license) => ({
        ...dependency,
        license,
      }));
    });

    try {
      await this._services.enrichLicenses(dependencies, {
        cancellationToken: token,
        onProgress: (patchMap) => {
          handler.onProgress(patchMap);
        },
      });
    } finally {
      handler.flush();
      handler.dispose();
    }
  }

  async _runPolicyEnrichment(dependencies, token) {
    const handler = this._createDebouncedEnrichmentHandler((patchMap) => {
      this._fullTrees = applyFoundOverlayPatch(this._fullTrees, patchMap, (dependency, policy) => ({
        ...dependency,
        policy,
      }));
      this._displayTrees = applyFoundOverlayPatch(this._displayTrees, patchMap, (dependency, policy) => ({
        ...dependency,
        policy,
      }));
    });

    try {
      await this._services.enrichPolicies(dependencies, {
        cancellationToken: token,
        onProgress: (patchMap) => {
          handler.onProgress(patchMap);
        },
      });
    } finally {
      handler.flush();
      handler.dispose();
    }
  }

  async _runUpstreamGapAnalysis(uncoveredDependencies, workspace, repo, progress, token) {
    const account = captureAccount(this._connectionManager);
    if (!account) return;
    const repositoryCollection = repo
      ? { items: [repo], complete: true, incomplete: false, partial: false }
      : await (this._services.fetchRepositories
        ? this._services.fetchRepositories(workspace, token)
        : this._fetchWorkspaceRepositories(workspace, token));
    const normalizedRepositories = normalizeRepositoryCollection(repositoryCollection);
    if (!normalizedRepositories.complete) {
      appendUniqueWarning(
        this._warnings,
        UPSTREAM_COVERAGE_INCOMPLETE_WARNING
      );
    }

    const handler = this._createDebouncedEnrichmentHandler((patchMap) => {
      this._fullTrees = applyUncoveredOverlayPatch(this._fullTrees, patchMap, (dependency, gap) => ({
        ...dependency,
        upstreamStatus: gap.upstreamStatus,
        upstreamDetail: gap.upstreamDetail,
      }));
      this._displayTrees = applyUncoveredOverlayPatch(this._displayTrees, patchMap, (dependency, gap) => ({
        ...dependency,
        upstreamStatus: gap.upstreamStatus,
        upstreamDetail: gap.upstreamDetail,
      }));
    });

    try {
      const legacyCompatibleDependencies = uncoveredDependencies.map((dependency) => ({
        ...dependency,
        cloudsmithStatus: "NOT_FOUND",
      }));
      await this._services.analyzeUpstreamGaps(
        legacyCompatibleDependencies,
        workspace,
        normalizedRepositories.items,
        {
          upstreamRuntime: this._services.upstreamGapRuntime,
          account,
          cancellationToken: token,
          repositoriesComplete: normalizedRepositories.complete,
          onProgress: (patchMap, meta = {}) => {
            if (meta.terminal === true && meta.outcome === "cancelled") {
              return;
            }
            if (meta.total > 0) {
              const terminalPartial = meta.terminal === true && meta.outcome === "partial";
              const inspected = Number.isFinite(meta.inspected)
                ? meta.inspected
                : meta.completed;
              progress.report({
                message: meta.terminal === true
                  ? terminalPartial
                    ? `Upstream coverage incomplete: ${inspected}/${meta.total} repositories checked`
                    : `Upstream coverage checked: ${meta.completed}/${meta.total}`
                  : `Checking upstream coverage... ${meta.completed}/${meta.total}`,
              });
              if (terminalPartial) {
                appendUniqueWarning(this._warnings, UPSTREAM_COVERAGE_INCOMPLETE_WARNING);
              }
            }
            handler.onProgress(patchMap);
          },
        }
      );
    } finally {
      handler.flush();
      handler.dispose();
    }
  }

  async _fetchWorkspaceRepositories(workspace, token) {
    const result = await fetchWorkspaceRepositories(this.context, workspace, {
      connectionManager: this._connectionManager,
      cloudsmithAPI: this._services.createCloudsmithAPI(),
      cancellationToken: token,
      retry: "never",
      withProgress: async (_options, task) => task({ report() {} }),
    });
    const items = Array.isArray(result?.items) ? result.items : [];
    return {
      ...result,
      items: [...new Set(items.map(repository => repository?.slug).filter(Boolean))],
      complete: result?.complete === true,
    };
  }

  async _publishDiagnostics(cancellationToken) {
    if (!this._diagnosticsPublisher) {
      return;
    }

    const prepared = await this._prepareDiagnostics(this, cancellationToken);
    if (cancellationToken && cancellationToken.isCancellationRequested) {
      return;
    }
    this._diagnosticsPublisher.replace(prepared.entries);
  }

  buildDependencyNodesForTree(tree) {
    const group = this._dependencySourceGroups.get(tree) || null;
    if (this._viewMode === "tree") {
      return this._buildTreeModeNodes(tree, group);
    }

    return this._buildListModeNodes(tree, group);
  }

  _buildListModeNodes(tree, group = null) {
    const visibleDependencies = this._viewMode === "direct"
      ? tree.dependencies.filter((dependency) => dependency.isDirect)
      : tree.dependencies.slice();

    return visibleDependencies
      .filter((dependency) => matchesFilter(dependency, this._filterMode))
      .sort((left, right) => compareDependencies(left, right, this._sortMode, true))
      .map((dependency) => {
        const node = new DependencyHealthNode(
          dependency,
          null,
          this.context,
          {
            childMode: "details",
            connectionManager: this._connectionManager,
            ...this._vulnerabilityNodeOptions(),
          }
        );
        if (group) this._treeParents.set(node, group);
        return this._ownDependencySelection(node);
      });
  }

  _buildTreeModeNodes(tree, group = null) {
    let duplicateAwareRoots;
    if (tree.dependencyGraph?.kind === "package-lock") {
      const rendered = buildPackageLockGraphWrappers(tree, this._filterMode, this._sortMode);
      duplicateAwareRoots = rendered.wrappers;
      const warning = "Some dependency relationships could not be displayed. Use list view to inspect the bounded dependency inventory.";
      if (rendered.truncated && !this._warnings.includes(warning)) {
        this._warnings.push(warning);
        queueMicrotask(() => this.refresh());
      }
    } else {
      duplicateAwareRoots = buildLegacyTreeWrappers(tree, this._filterMode, this._sortMode);
    }
    return duplicateAwareRoots.map(wrapper => this._createTreeDependencyNode(wrapper, group));
  }

  _createTreeDependencyNode(wrapper, parent = null) {
    let node;
    node = new DependencyHealthNode(
      wrapper.dependency,
      null,
      this.context,
      {
        connectionManager: this._connectionManager,
        ...this._vulnerabilityNodeOptions(),
        childMode: "tree",
        treeChildren: wrapper.children,
        duplicateReference: wrapper.duplicate,
        firstOccurrencePath: wrapper.firstOccurrencePath,
        dimmedForFilter: wrapper.dimmedForFilter,
        treeChildFactory: (children) => children.map(child => (
          this._createTreeDependencyNode(child, node)
        )),
      }
    );
    if (parent) this._treeParents.set(node, parent);
    return this._ownDependencySelection(node);
  }

  async buildReport() {
    if (this._fullTrees.length === 0) {
      return null;
    }

    const dependencies = this._fullTrees.flatMap((tree) => tree.dependencies);
    const projectName = path.basename(this.getProjectFolder() || "workspace");
    return buildDependencyHealthReport(
      projectName,
      dependencies,
      this._summary,
      formatReportDate(this._reportDateFactory())
    );
  }

  async pullDependencies() {
    if (this._disposed) return;
    if (!await this._requirePullThroughCapability()) return;
    if (this._pendingAccountIdentity) return;
    if (this.isScanRunning() || this._isDependencyOperationRunning()) {
      this._userInteraction.showWarningMessage("Wait for the current dependency operation to finish.");
      return;
    }

    const account = captureAccount(this._connectionManager);
    if (!account) {
      return;
    }

    if (!this._hasSuccessfulScan || !this.lastWorkspace) {
      this._userInteraction.showInformationMessage("Run a dependency scan before pulling dependencies.");
      return;
    }

    const dependencies = this._fullTrees.flatMap((tree) => tree.dependencies);
    if (dependencies.length === 0) {
      this._userInteraction.showInformationMessage("Run a dependency scan before pulling dependencies.");
      return;
    }

    const operation = this._beginDependencyOperation(account);
    if (!operation) return;
    const cancellationSource = this._createCancellationSource();
    this._activeDependencyCancellation = cancellationSource;

    try {
      await this._updateContexts();
      const result = await this._userInteraction.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "Pulling dependencies",
          cancellable: true,
        },
        async (progress, token) => {
          const subscription = token.onCancellationRequested(() => cancellationSource.cancel());
          try {
            progress.report({ message: "Preparing pull-through request..." });
            const execution = await this._services.upstreamPullService.run({
              workspace: this.lastWorkspace,
              repositoryHint: this.lastRepo,
              dependencies,
              progress,
              token: cancellationSource.token,
              account,
            });

            if (!execution || execution.canceled) {
              return execution || { canceled: true };
            }

            if (!this._ownsDependencyOperation(operation)) {
              return { canceled: true };
            }

            progress.report({ message: "Refreshing Cloudsmith coverage..." });
            await this._refreshCoverageAfterPull(
              execution.workspace,
              execution.repository.slug,
              progress,
              cancellationSource.token,
              { verificationReceipts: execution.verificationReceipts }
            );

            if (cancellationSource.token.isCancellationRequested) {
              return { canceled: true };
            }

            return execution;
          } finally {
            subscription.dispose();
          }
        }
      );

      if (!result) {
        return;
      }

      if (!this._ownsDependencyOperation(operation)) {
        return;
      }

      if (result.canceled) {
        return;
      }

      if (result.pullResult) {
        this._userInteraction.showInformationMessage(
          buildPullSummaryMessage(result.pullResult, result.plan.skippedDependencies.length)
        );
      }
    } finally {
      cancellationSource.dispose();
      if (this._activeDependencyOperation === operation) {
        this._activeDependencyOperation = null;
      }
      if (
        this._activeDependencyOperation === null
        && this._activeDependencyCancellation === cancellationSource
      ) {
        this._activeDependencyCancellation = null;
        await this._updateContexts();
        this.refresh();
      }
    }
  }

  async pullSingleDependency(value, options = {}) {
    if (this._disposed) return;
    if (!await this._requirePullThroughCapability()) return;
    if (this._pendingAccountIdentity) return;
    if (this.isScanRunning() || this._isDependencyOperationRunning()) {
      this._userInteraction.showWarningMessage("Wait for the current dependency operation to finish.");
      return;
    }

    const account = captureAccount(this._connectionManager);
    if (!account) {
      return;
    }

    if (!this._hasSuccessfulScan || !this.lastWorkspace) {
      this._userInteraction.showInformationMessage("Run a dependency scan before pulling dependencies.");
      return;
    }

    let coordinate;
    try {
      coordinate = assertWorkspacePackageCoordinate(value);
    } catch {
      this._userInteraction.showWarningMessage("Could not determine the dependency details.");
      return;
    }
    if (
      coordinate.workspace !== this.lastWorkspace
      || coordinate.repository !== this.lastRepo
    ) {
      this._userInteraction.showWarningMessage(
        "The dependency selection is stale. Select it again and retry."
      );
      return;
    }
    const dependency = resolveSingleDependencyPullTarget(coordinate, this._fullTrees);
    if (!dependency) {
      this._userInteraction.showWarningMessage("Could not determine the dependency details.");
      return;
    }
    const successfulScope = this.getLastSuccessfulScope();
    const invocationIsCurrent = typeof options.isCurrent === "function"
      ? options.isCurrent
      : () => true;
    const scopeIsCurrent = () => {
      if (!invocationIsCurrent()) return false;
      const currentScope = this.getLastSuccessfulScope();
      return Boolean(
        currentScope
        && successfulScope
        && currentScope.workspace === successfulScope.workspace
        && (currentScope.repository || null) === (successfulScope.repository || null)
        && (currentScope.projectFolder || null) === (successfulScope.projectFolder || null)
      );
    };
    if (!scopeIsCurrent()) return;

    const operation = this._beginDependencyOperation(account);
    if (!operation) return;
    const cancellationSource = this._createCancellationSource();
    this._activeDependencyCancellation = cancellationSource;
    let prepared = null;

    try {
      await this._updateContexts();
      const result = await this._userInteraction.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: `Preparing upstream pull for ${formatSingleDependencyLabel(dependency)}...`,
          cancellable: true,
        },
        async (progress, token) => {
          const subscription = token.onCancellationRequested(() => cancellationSource.cancel());
          try {
            progress.report({ message: "Inspecting repository upstreams..." });
            prepared = await this._services.upstreamPullService.prepareSingle({
              workspace: this.lastWorkspace,
              repositoryHint: this.lastRepo,
              dependency,
              cancellationToken: cancellationSource.token,
              account,
            });
            if (
              !prepared
              || cancellationSource.token.isCancellationRequested
              || !this._ownsDependencyOperation(operation)
              || !scopeIsCurrent()
            ) {
              return cancellationSource.token.isCancellationRequested
                ? { canceled: true }
                : null;
            }

            const repositorySlug = String(prepared.repository?.slug || "").trim();
            if (!repositorySlug) return null;
            const confirmed = await this._userInteraction.showWarningMessage(
              `Pull ${formatSingleDependencyLabel(prepared.dependency)} into ${prepared.workspace}/${repositorySlug}? This may use upstream credentials and write a package to Cloudsmith.`,
              { modal: true },
              "Pull dependency"
            );
            if (
              confirmed !== "Pull dependency"
              || cancellationSource.token.isCancellationRequested
              || !this._ownsDependencyOperation(operation)
              || !scopeIsCurrent()
            ) {
              return { canceled: true };
            }

            progress.report({ message: "Triggering upstream pull..." });
            const execution = await this._services.upstreamPullService.execute(prepared, {
              progress,
              token: cancellationSource.token,
            });

            if (!execution || execution.canceled) {
              return execution || { canceled: true };
            }

            if (!this._ownsDependencyOperation(operation)) {
              return { canceled: true };
            }

            if (!scopeIsCurrent()) return { canceled: true };

            const pullDetail = getSingleDependencyPullDetail(execution.pullResult);
            if (isSuccessfulSingleDependencyPull(pullDetail)) {
              progress.report({ message: "Refreshing Cloudsmith coverage..." });
              const verificationReceipt = execution.verificationReceipts instanceof Map
                ? execution.verificationReceipts.get(getDependencyArtifactKey(prepared.dependency))
                : null;
              await this._refreshSingleDependencyAfterPull(
                prepared.workspace,
                prepared.repository.slug,
                prepared.dependency,
                progress,
                cancellationSource.token,
                { verificationReceipt }
              );
            }

            return {
              ...prepared,
              ...execution,
            };
          } finally {
            subscription.dispose();
          }
        }
      );

      if (!result) {
        return;
      }

      if (!this._ownsDependencyOperation(operation)) {
        return;
      }

      if (result.canceled) {
        return;
      }

      const notification = buildSingleDependencyPullNotification(
        prepared.dependency,
        prepared.repository.slug,
        getSingleDependencyPullDetail(result.pullResult)
      );
      if (notification.level === "error") {
        this._userInteraction.showErrorMessage(notification.message);
      } else {
        this._userInteraction.showInformationMessage(notification.message);
      }
    } finally {
      cancellationSource.dispose();
      if (this._activeDependencyOperation === operation) {
        this._activeDependencyOperation = null;
      }
      if (
        this._activeDependencyOperation === null
        && this._activeDependencyCancellation === cancellationSource
      ) {
        this._activeDependencyCancellation = null;
        await this._updateContexts();
        this.refresh();
      }
    }
  }

  async _requirePullThroughCapability() {
    if (isPullThroughAvailable(this._connectionManager)) return true;
    await this._userInteraction.showErrorMessage(PULL_THROUGH_API_KEY_MESSAGE);
    return false;
  }

  async _refreshCoverageAfterPull(
    cloudsmithWorkspace,
    cloudsmithRepo,
    progress,
    token,
    options = {}
  ) {
    await this._refreshCoverageForDependencies(
      cloudsmithWorkspace,
      cloudsmithRepo,
      null,
      progress,
      token,
      {
        refreshRemainingUpstream: true,
        verificationReceipts: options.verificationReceipts || null,
      }
    );
  }

  async _refreshSingleDependencyAfterPull(
    cloudsmithWorkspace,
    cloudsmithRepo,
    dependency,
    progress,
    token,
    options = {}
  ) {
    await this._refreshCoverageForDependencies(
      cloudsmithWorkspace,
      cloudsmithRepo,
      [dependency],
      progress,
      token,
      { verificationReceipt: options.verificationReceipt || null }
    );
  }

  async _refreshCoverageForDependencies(
    cloudsmithWorkspace,
    cloudsmithRepo,
    targetDependencies,
    progress,
    token,
    options = {}
  ) {
    const targetKeys = new Set(
      (Array.isArray(targetDependencies) ? targetDependencies : [])
        .map((dependency) => coverageLookupKey(dependency))
        .filter(Boolean)
    );
    const unresolvedDependencies = uniqueDependenciesForCoverage(
      this._fullTrees
        .flatMap((tree) => tree.dependencies)
        .filter((dependency) => (
          isAbsentCoverageStatus(dependency.cloudsmithStatus)
          && (targetKeys.size === 0 || targetKeys.has(coverageLookupKey(dependency)))
        ))
    );
    const totalDependencies = unresolvedDependencies.length;

    if (totalDependencies === 0) {
      await this._publishDiagnostics(token);
      this._rebuildSummary();
      await this._storeReportData(this._reportDateFactory());
      return [];
    }

    const previousFoundKeys = new Set(
      this._fullTrees
        .flatMap((tree) => tree.dependencies)
        .filter((dependency) => (
          dependency.cloudsmithStatus === "FOUND"
          && (targetKeys.size === 0 || targetKeys.has(coverageLookupKey(dependency)))
        ))
        .map((dependency) => coverageLookupKey(dependency))
        .filter(Boolean)
    );

    const dependenciesByFormat = groupDependenciesByFormat([{ dependencies: unresolvedDependencies }]);
    await this._runCoverageResolution(
      cloudsmithWorkspace,
      cloudsmithRepo,
      dependenciesByFormat,
      totalDependencies,
      progress,
      token,
      {
        packageIndexFailureVerb: "refresh",
        progressLabel: "Refreshing Cloudsmith coverage",
        verificationReceipt: options.verificationReceipt || null,
        verificationReceipts: options.verificationReceipts || null,
      }
    );

    const newlyFoundDependencies = uniqueDependenciesForCoverage(
      this._fullTrees
        .flatMap((tree) => tree.dependencies)
        .filter((dependency) => {
          const key = coverageLookupKey(dependency);
          return dependency.cloudsmithStatus === "FOUND"
            && Boolean(key)
            && !previousFoundKeys.has(key)
            && (targetKeys.size === 0 || targetKeys.has(key));
        })
    );

    if (newlyFoundDependencies.length > 0) {
      progress.report({
        message: targetKeys.size > 0
          ? "Enriching pulled dependency..."
          : "Enriching newly covered dependencies...",
      });
      const enrichmentResults = await Promise.allSettled([
        this._runVulnerabilityEnrichment(newlyFoundDependencies, cloudsmithWorkspace, progress, token),
        this._runLicenseEnrichment(newlyFoundDependencies, token),
        this._runPolicyEnrichment(newlyFoundDependencies, token),
      ]);
      for (const result of enrichmentResults) {
        if (result.status === "rejected") {
          appendUniqueWarning(
            this._warnings,
            safeEnrichmentFailureMessage()
          );
        }
      }
    }

    if (options.refreshRemainingUpstream) {
      const remainingUncovered = this._fullTrees
        .flatMap((tree) => tree.dependencies)
        .filter((dependency) => isAbsentCoverageStatus(dependency.cloudsmithStatus));
      if (remainingUncovered.length > 0) {
        progress.report({ message: "Refreshing upstream availability..." });
        await this._runUpstreamGapAnalysis(
          remainingUncovered,
          cloudsmithWorkspace,
          cloudsmithRepo,
          progress,
          token
        );
      }
    }

    await this._publishDiagnostics(token);
    this._rebuildSummary();
    await this._storeReportData(this._reportDateFactory());
    this.refresh();

    return newlyFoundDependencies;
  }

  async rescan(initialScan, isCurrent = () => true) {
    if (!isCurrent()) return null;
    const scope = this.getLastSuccessfulScope();
    if (!scope) {
      return typeof initialScan === "function"
        ? initialScan()
        : { status: "needs-initial-scan" };
    }
    const projectFolderAvailable = await this.isProjectFolderAvailableForRescan(
      scope.projectFolder
    );
    if (!isCurrent()) return null;
    if (!projectFolderAvailable) {
      return typeof initialScan === "function"
        ? initialScan()
        : { status: "needs-initial-scan" };
    }
    if (!isCurrent()) return null;
    return this.scan(scope.workspace, scope.repository, scope.projectFolder);
  }

  getTreeItem(element) {
    return element.getTreeItem();
  }

    getParent(element) {
    return this._treeParents.get(element) || null;
  }

  async getChildren(element) {
    if (this._disposed) return [];
    if (this._pendingAccountIdentity) {
      if (element) return [];
      return [createConnectionStatusNode(CONNECTION_PRESENTATIONS.CONNECTING)];
    }
    const presentation = connectionPresentation(this._connectionManager?.getState?.());
    if (presentation !== CONNECTION_PRESENTATIONS.CONNECTED) {
      if (element || presentation === CONNECTION_PRESENTATIONS.DISPOSED) return [];
      const node = createConnectionStatusNode(presentation);
      return node ? [node] : [];
    }

    if (element) {
      const children = await element.getChildren();
      if (Array.isArray(children)) {
        for (const child of children) {
          if (child && typeof child === "object") this._treeParents.set(child, element);
        }
      }
      return children;
    }

    const operationNode = this._getScanOperationNode();
    if (operationNode && !this._hasSuccessfulScan) {
      return [operationNode];
    }

    const nodes = [];
    if (operationNode) {
      nodes.push(operationNode);
    }

    if (this._noManifestsFolder) {
      nodes.push(
        new InfoNode(
          "No dependency manifests or lockfiles found",
          this._noManifestsFolder,
          "Supported formats include npm, Python, Maven, Gradle, Go, Cargo, Ruby, Docker, NuGet, Dart, Composer, Helm, Swift, and Hex.",
          "warning",
          "infoNode"
        )
      );
      return nodes;
    }

    if (this._displayTrees.length > 0) {
      nodes.push(new DependencySummaryNode(this._summary));
      if (this._warnings.length > 0) {
        nodes.push(new InfoNode(
          this._warnings[0],
          "",
          this._warnings.join("\n"),
          "warning",
          "statusMessage"
        ));
      }
      nodes.push(...this._displayTrees.map((tree) => {
        let group = this._dependencySourceGroups.get(tree);
        if (!group) {
          group = new DependencySourceGroupNode(tree, this);
          this._dependencySourceGroups.set(tree, group);
        }
        return group;
      }));
      return nodes;
    }

    if (
      !this._hasSuccessfulScan
      && this._scanOperation.status === SCAN_STATES.IDLE
      && this._warnings.length === 0
    ) {
      return [
        new InfoNode(
          "Scan dependencies",
          "Run Scan dependencies from the view toolbar.",
          "Scans lockfiles and manifests, resolves direct and transitive dependencies, and checks each one against Cloudsmith.",
          "folder",
          "dependencyHealthWelcome"
        ),
      ];
    }

    if (this._warnings.length > 0) {
      nodes.push(new InfoNode(
        this._warnings[0],
        "",
        this._warnings.join("\n"),
        "warning",
        "statusMessage"
      ));
    }
    nodes.push(new InfoNode(
      "No dependencies found",
      "",
      "The detected dependency files did not contain any dependencies to scan.",
      "info",
      "infoNode"
    ));
    return nodes;
  }

  _getScanOperationNode() {
    const status = this._scanOperation.status;
    if (status === SCAN_STATES.SELECTING || status === SCAN_STATES.RUNNING) {
      const refreshing = this._hasSuccessfulScan;
      const label = refreshing ? "Refreshing dependencies" : "Scanning dependencies";
      const detail = refreshing
        ? "Previous scan results are shown until the refresh finishes."
        : "Dependency health results will appear when the scan finishes.";
      return new InfoNode(label, detail, detail, "loading~spin", "statusMessage");
    }

    if (status === SCAN_STATES.FAILED) {
      const refreshing = this._hasSuccessfulScan;
      const label = refreshing ? "Dependency refresh failed" : "Dependency scan failed";
      const detail = refreshing
        ? "Previous scan results are shown. Run Scan dependencies to retry."
        : "Run Scan dependencies to retry.";
      return new InfoNode(
        label,
        detail,
        this._scanOperation.failureMessage || detail,
        "error",
        "statusMessage"
      );
    }

    if (status === SCAN_STATES.CANCELLED) {
      const refreshing = this._hasSuccessfulScan;
      const label = refreshing ? "Dependency refresh canceled" : "Dependency scan canceled";
      const detail = refreshing
        ? "Previous scan results are shown."
        : "Run Scan dependencies to try again.";
      return new InfoNode(label, detail, this._scanOperation.message || detail, "info", "statusMessage");
    }

    return null;
  }

  refresh() {
    if (this._disposed) return;
    this._vulnerabilityTreeGeneration += 1;
    this._vulnerabilitySummaries.clear();
    this._clearVulnerabilityRefreshTimers();
    void this._updateContexts().catch(() => {});
    this._onDidChangeTreeData.fire();
  }

  refreshNode(element) {
    if (this._disposed || !element) return false;
    if (!this.ownsSelection(element)) return false;
    this._onDidChangeTreeData.fire(element);
    return true;
  }

  ownsSelection(selection) {
    if (this._disposed || !selection || typeof selection !== "object") return false;
    let candidate = selection;
    const visited = new Set();
    while (candidate && !visited.has(candidate) && visited.size < 24) {
      visited.add(candidate);
      if (this.ownsDependencySelection(candidate)) return true;
      candidate = this._treeParents.get(candidate) || null;
    }
    return false;
  }

  ownsDependencySelection(selection) {
    if (this._disposed || !selection || typeof selection !== "object") return false;
    const ownership = this._dependencySelections.get(selection);
    return Boolean(
      ownership
      && ownership.generation === this._selectionGeneration
      && isAccountCurrent(this._connectionManager, ownership.account)
    );
  }

  _ownDependencySelection(selection) {
    const account = captureAccount(this._connectionManager);
    if (!account || !selection || typeof selection !== "object") return selection;
    this._dependencySelections.set(selection, Object.freeze({
      generation: this._selectionGeneration,
      account,
    }));
    return selection;
  }

  setTreeView(treeView) {
    for (const subscription of this._treeExpansionSubscriptions) subscription.dispose?.();
    this._treeExpansionSubscriptions = [];
    this._treeView = treeView;
    const expanded = treeView?.onDidExpandElement?.(({ element }) => {
      if (element?.getTreeItem?.().contextValue === "vulnerabilitySummary") {
        this._expandedVulnerabilitySummaries.add(element);
      }
    });
    const collapsed = treeView?.onDidCollapseElement?.(({ element }) => {
      this._expandedVulnerabilitySummaries.delete(element);
    });
    if (expanded) this._treeExpansionSubscriptions.push(expanded);
    if (collapsed) this._treeExpansionSubscriptions.push(collapsed);
  }

  _vulnerabilityNodeOptions() {
    const generation = this._vulnerabilityTreeGeneration;
    return {
      vulnerabilityStateService: this._vulnerabilityStateService,
      registerVulnerabilitySummary: (identity, element, owner) => {
        if (typeof identity !== "string" || !element || !owner) return;
        let entries = this._vulnerabilitySummaries.get(identity);
        if (!entries) {
          entries = new Set();
          this._vulnerabilitySummaries.set(identity, entries);
        }
        entries.add(Object.freeze({ element, owner, generation }));
        this._treeParents.set(element, owner);
      },
    };
  }

  _publishVulnerabilityState(event) {
    if (
      !this._disposed
      && this._reportData
      && event?.state?.status !== REPORT_VULNERABILITY_STATES.LOADING
    ) {
      this._reportData = this._buildComplianceReportData(this._lastScanTimestamp);
    }
    const identity = typeof event?.identity === "string" ? event.identity : null;
    const entries = identity ? this._vulnerabilitySummaries.get(identity) : null;
    if (!entries || this._disposed) return;
    for (const entry of [...entries]) {
      if (entry.generation !== this._vulnerabilityTreeGeneration) {
        entries.delete(entry);
        continue;
      }
      if (event.presentation) {
        entry.element.acceptVulnerabilityPresentation?.(event.presentation);
      }
      if (event.state?.status !== "loading") {
        const generation = entry.generation;
        this._scheduleVulnerabilityRefresh(entry.element, () => (
          !this._disposed && generation === this._vulnerabilityTreeGeneration
        ));
      }
    }
    if (entries.size === 0) this._vulnerabilitySummaries.delete(identity);
  }

  _scheduleVulnerabilityRefresh(element, isCurrent) {
    const current = this._vulnerabilityRefreshTimers.get(element);
    if (current) clearTimeout(current);
    const timer = setTimeout(() => {
      this._vulnerabilityRefreshTimers.delete(element);
      if (!isCurrent()) return;
      const wasExpanded = this._expandedVulnerabilitySummaries.has(element);
      this._onDidChangeTreeData.fire(element);
      if (wasExpanded) {
        void this._treeView?.reveal?.(element, { expand: true, focus: false, select: false })
          ?.catch?.(() => {});
      }
    }, 0);
    this._vulnerabilityRefreshTimers.set(element, timer);
  }

  _clearVulnerabilityRefreshTimers() {
    for (const timer of this._vulnerabilityRefreshTimers.values()) clearTimeout(timer);
    this._vulnerabilityRefreshTimers.clear();
  }

  dispose() {
    if (this._disposed) return this._contextDisposal || Promise.resolve();
    this._disposed = true;
    this._selectionGeneration += 1;
    this._vulnerabilityStateSubscription?.dispose?.();
    this._connectionSubscription?.dispose?.();
    for (const subscription of this._treeExpansionSubscriptions) subscription.dispose?.();
    this._vulnerabilitySummaries.clear();
    this._clearVulnerabilityRefreshTimers();
    const disposedOperationId = ++this._nextScanOperationId;
    this._scanOperation = createScanOperation(SCAN_STATES.CANCELLED, disposedOperationId, {
      startedAt: this._scanOperation.startedAt,
      accountEpoch: this._scanOperation.accountEpoch,
      completedAt: this._scheduler.now(),
      scope: this._scanOperation.scope,
      message: "Dependency provider disposed.",
    });
    for (const handler of [...this._debouncedEnrichmentHandlers]) {
      handler.dispose();
    }
    if (this._activeScanCancellation) {
      this._activeScanCancellation.cancel();
      this._activeScanCancellation.dispose();
      this._activeScanCancellation = null;
    }
    if (this._activeDependencyCancellation) {
      this._activeDependencyCancellation.cancel();
      this._activeDependencyCancellation.dispose();
      this._activeDependencyCancellation = null;
    }
    this._detachDependencyOperation();
    this._onDidChangeTreeData.dispose();
    this._contextDisposal = this._contextProjector.dispose();
    return this._contextDisposal;
  }

  _rebuildSummary() {
    this._summary = buildDependencySummary(this._fullTrees, this._displayTrees, {
      filterMode: this._filterMode,
    });
    this.dependencies = this._displayTrees.flatMap((tree) => tree.dependencies);
  }
}

function accountIdentity(state) {
  if (
    !state
    || typeof state.activationId !== "string"
    || state.activationId.length === 0
    || !Number.isSafeInteger(state.accountEpoch)
    || state.accountEpoch < 0
  ) {
    return null;
  }
  return Object.freeze({
    activationId: state.activationId,
    accountEpoch: state.accountEpoch,
  });
}

function sameAccountIdentity(left, right) {
  return Boolean(
    left
    && right
    && left.activationId === right.activationId
    && left.accountEpoch === right.accountEpoch
  ) || (!left && !right);
}

function normalizeRepositoryCollection(value) {
  const collection = value && typeof value === "object" && !Array.isArray(value)
    ? value
    : { items: [], complete: false };
  const rawItems = Array.isArray(collection.items) ? collection.items : [];
  const items = [...new Set(rawItems.map(repository => (
    typeof repository === "string" ? repository.trim() : repository?.slug
  )).filter(Boolean))];
  return {
    items,
    complete: collection.complete === true && collection.stale !== true,
  };
}

function createScanOperation(status, id, values = {}) {
  return {
    status,
    id,
    accountEpoch: Number.isInteger(values.accountEpoch) ? values.accountEpoch : null,
    startedAt: values.startedAt || null,
    completedAt: values.completedAt || null,
    scope: values.scope || null,
    message: values.message || null,
    failureMessage: values.failureMessage || null,
  };
}

function appendUniqueWarning(warnings, warning) {
  if (!Array.isArray(warnings) || typeof warning !== "string" || !warning || warnings.includes(warning)) {
    return;
  }
  warnings.push(warning);
}

function safeScanFailureReason(error) {
  const code = String(error && error.code || "");
  if (/cancel(?:led|ed|lation)/i.test(code)) {
    return "The scan was canceled.";
  }
  if (/outside_workspace|symlink_escape/i.test(code)) {
    return "A dependency file is outside the selected workspace. Check the dependency paths and retry.";
  }
  if (/file_(?:missing|unreadable|not_regular|changed)/i.test(code)) {
    return "A dependency file could not be read. Check file access and retry.";
  }
  if (/file_too_large/i.test(code)) {
    return "A dependency file could not be scanned because of its size. Check the file and retry.";
  }
  return "Check the dependency files and Cloudsmith connection, then retry.";
}

function safeEnrichmentFailureMessage() {
  return "Some dependency details could not be loaded. Retry the dependency scan.";
}

function safeDiscoveryWarning() {
  return "Some nested dependency projects could not be scanned. Select a more specific project folder and retry.";
}

function getConcreteDependencyVersion(dependency) {
  if (!dependency || typeof dependency !== "object") {
    return null;
  }

  const canonicalVersion = getCanonicalDependencyConcreteVersion(dependency);
  if (canonicalVersion) {
    return canonicalVersion;
  }
  const versionState = String(dependency.versionState || "").trim();
  if (versionState === DEPENDENCY_VERSION_STATES.RESOLVED) {
    return nonEmptyString(dependency.resolvedVersion);
  }
  if (versionState === DEPENDENCY_VERSION_STATES.EXACT_DECLARATION) {
    const compatibilityVersion = nonEmptyString(
      Object.prototype.hasOwnProperty.call(dependency, "legacyVersion")
        ? dependency.legacyVersion
        : dependency.version
    );
    return compatibilityVersion || exactVersionFromDeclaredConstraint(
      dependency.declaredConstraint,
      dependency.format || dependency.ecosystem
    );
  }
  if (versionState) {
    return null;
  }

  return nonEmptyString(dependency.resolvedVersion);
}

function exactVersionFromDeclaredConstraint(constraint, ecosystemOrFormat) {
  const value = nonEmptyString(constraint);
  if (!value) {
    return null;
  }
  const format = canonicalFormat(ecosystemOrFormat);
  if (format === "python") {
    return nonEmptyString(value.replace(/^={2,3}\s*/, ""));
  }
  if (format === "npm" || format === "cargo") {
    return nonEmptyString(value.replace(/^=\s*/, ""));
  }
  if (format === "nuget") {
    const singleton = value.match(/^\[\s*([^,\]]+)\s*]$/);
    return singleton ? nonEmptyString(singleton[1]) : null;
  }
  return value.includes("${") ? null : value;
}

function nonEmptyString(value) {
  const normalized = String(value == null ? "" : value).trim();
  return normalized || null;
}

function createCoverageLookupResult(status, pkg, detail, pagesFetched = 0) {
  return {
    status,
    package: pkg || null,
    detail: detail || null,
    pagesFetched,
  };
}

function createLookupRequestBudget(limit) {
  const maximum = Number.isInteger(limit) && limit > 0 ? limit : 0;
  let consumed = 0;
  return {
    tryConsume() {
      if (consumed >= maximum) {
        return false;
      }
      consumed += 1;
      return true;
    },
  };
}

async function lookupExactDependency({
  api,
  cloudsmithWorkspace,
  cloudsmithRepo,
  dependency,
  token,
  requestBudget = null,
  verificationReceipt = null,
}) {
  if (dependency && dependency.lookupEligibility
    && dependency.lookupEligibility.state === "unresolved") {
    return createCoverageLookupResult(
      CLOUDSMITH_COVERAGE_STATUS.UNRESOLVED,
      null,
      "No concrete dependency version is supported by the available resolution evidence."
    );
  }
  if (!isLookupEligibleForConsumer(dependency)) {
    return createCoverageLookupResult(
      CLOUDSMITH_COVERAGE_STATUS.NOT_APPLICABLE,
      null,
      formatLookupNotApplicableDetail(dependency)
    );
  }
  const concreteVersion = getConcreteDependencyVersion(dependency);
  if (!concreteVersion) {
    return createCoverageLookupResult(
      CLOUDSMITH_COVERAGE_STATUS.UNRESOLVED,
      null,
      "No concrete dependency version is supported by the available resolution evidence."
    );
  }

  const endpoint = buildPackageLookupEndpoint(cloudsmithWorkspace, cloudsmithRepo);
  const lookupNames = getDependencyLookupNames(dependency);
  const format = canonicalFormat(dependency && (dependency.format || dependency.ecosystem));
  const lookupVersion = format === "nuget"
    ? normalizeNuGetVersion(concreteVersion)
    : concreteVersion;
  if (
    !endpoint
    || !boundedExactLookupString(format, LOOKUP_MAX_PACKAGE_FORMAT_LENGTH)
    || !boundedExactLookupString(lookupVersion, LOOKUP_MAX_PACKAGE_VERSION_LENGTH)
    || lookupNames.length === 0
    || !api
    || typeof api.get !== "function"
  ) {
    return createCoverageLookupResult(
      CLOUDSMITH_COVERAGE_STATUS.LOOKUP_FAILED,
      null,
      "The Cloudsmith package identity could not be constructed safely."
    );
  }

  let pagesFetched = 0;
  let incompleteQualifierEvidence = false;
  for (const lookupName of lookupNames) {
    const queryBuilder = new SearchQueryBuilder()
      .format(format)
      .name(lookupName);
    if (format !== "docker") {
      queryBuilder.version(lookupVersion);
    }
    let query;
    try {
      query = queryBuilder.build();
    } catch {
      return createCoverageLookupResult(
        CLOUDSMITH_COVERAGE_STATUS.LOOKUP_FAILED,
        null,
        "The Cloudsmith package identity exceeded the safe query boundary.",
        pagesFetched
      );
    }
    let page = 1;
    let paginationAnchor = null;
    const seenPackageIdentities = new Set();
    const accumulatedCandidates = [];

    while (true) {
      if (token && token.isCancellationRequested) {
        return createCoverageLookupResult(
          CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE,
          null,
          "The Cloudsmith lookup was canceled before it completed.",
          pagesFetched
        );
      }
      if (pagesFetched >= LOOKUP_MAX_PAGES) {
        return createCoverageLookupResult(
          CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE,
          null,
          "The Cloudsmith lookup exceeded its pagination safety limit.",
          pagesFetched
        );
      }
      if (requestBudget && !requestBudget.tryConsume()) {
        return createCoverageLookupResult(
          CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE,
          null,
          "The scan-wide Cloudsmith lookup request budget was exhausted.",
          pagesFetched
        );
      }

      let requestEndpoint;
      try {
        requestEndpoint = appendApiQuery(endpoint, {
          page,
          page_size: LOOKUP_PAGE_SIZE,
          query,
        });
      } catch {
        return createCoverageLookupResult(
          pagesFetched > 0
            ? CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE
            : CLOUDSMITH_COVERAGE_STATUS.LOOKUP_FAILED,
          null,
          "The Cloudsmith lookup endpoint could not be constructed safely.",
          pagesFetched
        );
      }
      const response = await api.get(requestEndpoint, {
        responseType: "array",
        validate: value => isPackageCandidateArray(
          value,
          cloudsmithWorkspace,
          cloudsmithRepo
        ),
        retry: "never",
        cancellationToken: token,
      });
      if (token && token.isCancellationRequested) {
        return createCoverageLookupResult(
          CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE,
          null,
          "The Cloudsmith lookup was canceled before it completed.",
          pagesFetched
        );
      }
      if (!response.ok) {
        const status = response.error.kind === "rate_limited"
          ? CLOUDSMITH_COVERAGE_STATUS.RATE_LIMITED
          : pagesFetched > 0
            ? CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE
            : CLOUDSMITH_COVERAGE_STATUS.LOOKUP_FAILED;
        return createCoverageLookupResult(
          status,
          null,
          status === CLOUDSMITH_COVERAGE_STATUS.RATE_LIMITED
            ? "Cloudsmith rate limited the dependency lookup."
            : "The Cloudsmith lookup did not complete successfully.",
          pagesFetched
        );
      }
      if (!isPackageCandidateArray(response.data, cloudsmithWorkspace, cloudsmithRepo)) {
        return createCoverageLookupResult(
          pagesFetched > 0
            ? CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE
            : CLOUDSMITH_COVERAGE_STATUS.LOOKUP_FAILED,
          null,
          "Cloudsmith returned package records outside the requested lookup scope.",
          pagesFetched
        );
      }
      const pageIdentities = response.data.map(packageCandidateIdentity);
      if (
        new Set(pageIdentities).size !== pageIdentities.length
        || pageIdentities.some(identity => seenPackageIdentities.has(identity))
      ) {
        return createCoverageLookupResult(
          CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE,
          null,
          "Cloudsmith repeated package records before the lookup completed.",
          pagesFetched
        );
      }
      for (const identity of pageIdentities) seenPackageIdentities.add(identity);
      pagesFetched += 1;
      accumulatedCandidates.push(...response.data);
      if (accumulatedCandidates.some(candidate => (
        coverageCandidateEvidenceIsIncomplete(candidate, dependency, format, lookupVersion)
      ))) {
        incompleteQualifierEvidence = true;
      }
      const match = matchCoverageCandidates(
        accumulatedCandidates,
        dependency,
        lookupVersion,
        verificationReceipt
      );
      if (match) {
        let canonicalMatch;
        try {
          canonicalMatch = fromApiPackageRecord(match, {
            expectedWorkspace: cloudsmithWorkspace,
            expectedRepository: cloudsmithRepo,
            coordinateName: dependency.name,
            coordinateQualifiers: dependency.qualifiers,
          });
        } catch {
          return createCoverageLookupResult(
            CLOUDSMITH_COVERAGE_STATUS.LOOKUP_FAILED,
            null,
            "Cloudsmith returned an invalid exact package match.",
            pagesFetched
          );
        }
        return createCoverageLookupResult(
          CLOUDSMITH_COVERAGE_STATUS.FOUND,
          canonicalMatch,
          null,
          pagesFetched
        );
      }

      const paginationState = getLookupPaginationState(
        normalizeLookupHeaders(response.headers),
        page,
        response.data.length,
        LOOKUP_PAGE_SIZE,
        paginationAnchor
      );
      const pagination = paginationState.directive;
      paginationAnchor = paginationState.anchor;
      if (pagination === "incomplete") {
        return createCoverageLookupResult(
          CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE,
          null,
          "Cloudsmith did not provide enough pagination evidence to prove package absence.",
          pagesFetched
        );
      }
      if (pagination === "exhausted") {
        break;
      }
      page += 1;
    }
  }

  if (incompleteQualifierEvidence) {
    return createCoverageLookupResult(
      CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE,
      null,
      "Cloudsmith did not return enough artifact evidence to prove package absence.",
      pagesFetched
    );
  }

  return createCoverageLookupResult(
    CLOUDSMITH_COVERAGE_STATUS.ABSENT,
    null,
    null,
    pagesFetched
  );
}

function buildPackageLookupEndpoint(cloudsmithWorkspace, cloudsmithRepo) {
  const workspace = nonEmptyString(cloudsmithWorkspace);
  const repo = nonEmptyString(cloudsmithRepo);
  if (!workspace || workspace === "." || workspace === ".." || repo === "." || repo === "..") {
    return null;
  }

  try {
    return repo
      ? apiEndpoint(["packages", workspace, repo])
      : apiEndpoint(["packages", workspace]);
  } catch {
    return null;
  }
}

function getDependencyLookupNames(dependency) {
  const format = canonicalFormat(dependency && (dependency.format || dependency.ecosystem));
  const names = getCaseAwarePackageLookupKeys(
    dependency && dependency.name,
    format,
    dependency && dependency.qualifiers
  )
    .filter((name) => boundedExactLookupString(name, LOOKUP_MAX_PACKAGE_NAME_LENGTH));
  if (format !== "maven") {
    return names;
  }

  return names.slice().sort((left, right) => {
    const leftQualified = left.includes(":");
    const rightQualified = right.includes(":");
    return Number(rightQualified) - Number(leftQualified);
  });
}

function packageIdentityName(name, ecosystemOrFormat) {
  const format = canonicalFormat(ecosystemOrFormat);
  const rawName = sanitizePackageNameInput(name);
  if (!rawName) {
    return "";
  }
  return ["maven", "go"].includes(format)
    ? rawName
    : normalizePackageName(rawName, format);
}

function getCaseAwarePackageLookupKeys(name, ecosystemOrFormat, identifiers) {
  const format = canonicalFormat(ecosystemOrFormat);
  const rawName = sanitizePackageNameInput(name);
  if (!rawName) {
    return [];
  }
  if (format === "maven") {
    const separator = rawName.indexOf(":");
    const artifact = separator === -1 ? rawName : rawName.slice(separator + 1);
    return [...new Set([rawName, artifact].filter(Boolean))];
  }
  if (format === "go") {
    return [rawName];
  }
  return getPackageLookupKeys(rawName, format, identifiers);
}

function getCaseAwareCloudsmithPackageLookupKeys(candidate, ecosystemOrFormat) {
  if (!candidate || typeof candidate !== "object") {
    return [];
  }
  const format = canonicalFormat(ecosystemOrFormat || candidate.format || candidate.ecosystem);
  const rawName = sanitizePackageNameInput(candidate.name);
  if (!rawName) {
    return [];
  }
  if (format === "maven") {
    const keys = [rawName];
    const identifiers = candidate.identifiers && typeof candidate.identifiers === "object"
      ? candidate.identifiers
      : {};
    const groupId = sanitizePackageNameInput(identifiers.group_id);
    if (groupId) {
      keys.push(`${groupId}:${rawName}`);
    }
    return [...new Set(keys)];
  }
  if (format === "go") {
    return [rawName];
  }
  return getCloudsmithPackageLookupKeys(candidate, format);
}

function getLookupPaginationState(
  headers,
  requestedPage,
  itemCount,
  requestedPageSize,
  anchor = null
) {
  const metadata = headers && typeof headers === "object" ? headers : {};
  const currentPage = parseOptionalNonNegativeInteger(metadata.page);
  if (currentPage.present && (!currentPage.valid || currentPage.value !== requestedPage)) {
    return { directive: "incomplete", anchor };
  }

  const pageTotal = parseOptionalNonNegativeInteger(metadata.pageTotal);
  const count = parseOptionalNonNegativeInteger(metadata.count);
  const responsePageSize = parseOptionalNonNegativeInteger(metadata.pageSize);
  if (count.present && (!count.valid || count.value < itemCount)) {
    return { directive: "incomplete", anchor };
  }
  if (responsePageSize.present && (!responsePageSize.valid || responsePageSize.value < 1)) {
    return { directive: "incomplete", anchor };
  }
  const effectivePageSize = responsePageSize.present
    ? responsePageSize.value
    : requestedPageSize;
  if (itemCount > effectivePageSize) {
    return { directive: "incomplete", anchor };
  }
  const nextAnchor = {
    pageTotal: pageTotal.present && pageTotal.valid ? pageTotal.value : null,
    pageTotalAuthoritative: pageTotal.present,
    count: count.present && count.valid ? count.value : null,
    countAuthoritative: count.present,
    pageSize: effectivePageSize,
    pageSizeAuthoritative: responsePageSize.present,
  };
  if (
    (pageTotal.present && !pageTotal.valid)
    || (count.present && !count.valid)
    || (
      anchor
      && (
        anchor.pageTotal !== nextAnchor.pageTotal
        || anchor.pageTotalAuthoritative !== nextAnchor.pageTotalAuthoritative
        || anchor.count !== nextAnchor.count
        || anchor.countAuthoritative !== nextAnchor.countAuthoritative
        || anchor.pageSize !== nextAnchor.pageSize
        || anchor.pageSizeAuthoritative !== nextAnchor.pageSizeAuthoritative
      )
    )
  ) {
    return { directive: "incomplete", anchor };
  }
  const stableAnchor = anchor || nextAnchor;
  if (count.present) {
    const expectedItemCount = Math.min(
      effectivePageSize,
      Math.max(0, count.value - ((requestedPage - 1) * effectivePageSize))
    );
    if (itemCount !== expectedItemCount) {
      return { directive: "incomplete", anchor: stableAnchor };
    }
  }

  if (pageTotal.present) {
    if (!pageTotal.valid || pageTotal.value < requestedPage) {
      return pageTotal.valid && pageTotal.value === 0 && itemCount === 0
        ? { directive: "exhausted", anchor: stableAnchor }
        : { directive: "incomplete", anchor: stableAnchor };
    }
    if (count.present) {
      const calculatedTotal = count.value === 0
        ? 1
        : Math.ceil(count.value / effectivePageSize);
      if (
        (count.value === 0 && itemCount !== 0)
        || (count.value === 0 && pageTotal.value > 1)
        || (count.value > 0 && calculatedTotal !== pageTotal.value)
      ) {
        return { directive: "incomplete", anchor: stableAnchor };
      }
    }
    if (requestedPage < pageTotal.value && itemCount !== effectivePageSize) {
      return { directive: "incomplete", anchor: stableAnchor };
    }
    return {
      directive: requestedPage >= pageTotal.value ? "exhausted" : "next",
      anchor: stableAnchor,
    };
  }

  if (count.present) {
    const calculatedTotal = Math.ceil(count.value / effectivePageSize);
    if (calculatedTotal < requestedPage) {
      return count.value === 0 && itemCount === 0 && requestedPage === 1
        ? { directive: "exhausted", anchor: stableAnchor }
        : { directive: "incomplete", anchor: stableAnchor };
    }
    return {
      directive: requestedPage >= calculatedTotal ? "exhausted" : "next",
      anchor: stableAnchor,
    };
  }

  return { directive: "incomplete", anchor: stableAnchor };
}

function getLookupPaginationDirective(headers, requestedPage, itemCount, requestedPageSize) {
  return getLookupPaginationState(
    headers,
    requestedPage,
    itemCount,
    requestedPageSize
  ).directive;
}

function parseOptionalNonNegativeInteger(value) {
  if (value == null || value === "") {
    return { present: false, valid: false, value: null };
  }
  const normalized = typeof value === "number"
    ? value
    : typeof value === "string" && /^(0|[1-9]\d*)$/.test(value)
      ? Number(value)
      : NaN;
  return {
    present: true,
    valid: Number.isSafeInteger(normalized) && normalized >= 0,
    value: normalized,
  };
}

function normalizeLookupHeaders(headers) {
  return {
    page: headers && headers["x-pagination-page"],
    pageTotal: headers && headers["x-pagination-pagetotal"],
    count: headers && headers["x-pagination-count"],
    pageSize: headers && headers["x-pagination-pagesize"],
  };
}

function isPackageCandidateArray(value, expectedWorkspace, expectedRepository) {
  return Array.isArray(value)
    && value.length <= LOOKUP_PAGE_SIZE
    && value.every(candidate => (
      candidate
      && typeof candidate === "object"
      && !Array.isArray(candidate)
      && boundedExactLookupString(candidate.name, LOOKUP_MAX_PACKAGE_NAME_LENGTH)
      && boundedExactLookupString(candidate.format, LOOKUP_MAX_PACKAGE_FORMAT_LENGTH)
      && boundedExactLookupString(candidate.version, LOOKUP_MAX_PACKAGE_VERSION_LENGTH)
      && candidate.namespace === expectedWorkspace
      && (!expectedRepository || candidate.repository === expectedRepository)
      && packageCandidateEvidenceShapeIsValid(candidate)
      && Boolean(getPackagePolicyFlags(candidate))
      && Boolean(packageCandidateIdentity(candidate))
    ));
}

function packageCandidateIdentity(candidate) {
  try {
    return packageCollectionIdentity(fromApiPackageRecord(candidate));
  } catch {
    return null;
  }
}

function boundedExactLookupString(value, maxLength) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= maxLength
    && value.trim() === value
    && !LOOKUP_CONTROL_OR_BIDI.test(value);
}

function isLookupEligibleForConsumer(dependency) {
  if (!dependency || typeof dependency !== "object") return false;
  const sourceKind = String(
    dependency.packageSource && dependency.packageSource.kind || ""
  ).trim().toLowerCase();
  return sourceKind === "registry" && isDependencyLookupEligible(dependency);
}

function isCoverageCandidate(dependency) {
  if (!dependency || typeof dependency !== "object") return false;
  const sourceKind = String(
    dependency.packageSource && dependency.packageSource.kind || ""
  ).trim().toLowerCase();
  const eligibility = dependency.lookupEligibility;
  return sourceKind === "registry" && (
    isDependencyLookupEligible(dependency)
    || Boolean(eligibility && eligibility.state === "unresolved")
  );
}

function getInitialCoverageStatus(dependency) {
  const eligibility = dependency && dependency.lookupEligibility;
  if (eligibility && eligibility.state === "unresolved") {
    return CLOUDSMITH_COVERAGE_STATUS.UNRESOLVED;
  }
  return isLookupEligibleForConsumer(dependency)
    ? CLOUDSMITH_COVERAGE_STATUS.CHECKING
    : CLOUDSMITH_COVERAGE_STATUS.NOT_APPLICABLE;
}

function formatLookupNotApplicableDetail(dependency) {
  const reason = dependency && dependency.lookupEligibility
    && dependency.lookupEligibility.reason;
  const labels = {
    "local-source": "Local dependency; Cloudsmith package lookup is not applicable.",
    "path-source": "Path dependency; Cloudsmith package lookup is not applicable.",
    "git-source": "Git dependency; Cloudsmith package lookup is not applicable.",
    "scm-source": "Source-control dependency; Cloudsmith package lookup is not applicable.",
    "sdk-source": "SDK dependency; Cloudsmith package lookup is not applicable.",
    "system-source": "System dependency; Cloudsmith package lookup is not applicable.",
    "unknown-source": "Dependency source is unknown; Cloudsmith package lookup was skipped.",
    "unsafe-identity": "Dependency identity is unsafe or exceeds lookup limits; Cloudsmith package lookup was skipped.",
  };
  return labels[reason] || "Cloudsmith package lookup is not applicable for this dependency source.";
}

function isAbsentCoverageStatus(status) {
  return status === CLOUDSMITH_COVERAGE_STATUS.ABSENT || status === "NOT_FOUND";
}

function appendCoverageLookupWarnings(warnings, format, statusCounts) {
  const unresolved = statusCounts.get(CLOUDSMITH_COVERAGE_STATUS.UNRESOLVED) || 0;
  const failed = statusCounts.get(CLOUDSMITH_COVERAGE_STATUS.LOOKUP_FAILED) || 0;
  const incomplete = statusCounts.get(CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE) || 0;
  const rateLimited = statusCounts.get(CLOUDSMITH_COVERAGE_STATUS.RATE_LIMITED) || 0;

  if (unresolved > 0) {
    warnings.push(`${unresolved} ${format} dependencies were not checked because no concrete version was resolved.`);
  }
  if (failed > 0) {
    warnings.push(`${failed} ${format} dependency lookups failed without proving package absence.`);
  }
  if (incomplete > 0) {
    warnings.push(`${incomplete} ${format} dependency lookups were incomplete and were not reported as absent.`);
  }
  if (rateLimited > 0) {
    warnings.push(`${rateLimited} ${format} dependency lookups were rate limited and were not reported as absent.`);
  }
}

function normalizeTree(tree) {
  const sourceFile = tree && tree.source && (
    tree.source.resolution && tree.source.resolution.label
    || tree.source.manifest && tree.source.manifest.label
  ) || tree.sourceFile;
  return {
    ...tree,
    ecosystem: tree.ecosystem,
    sourceFile,
    dependencies: deduplicateDependenciesWithStatus(
      (tree.dependencies || []).map((dependency) => normalizeDependency(dependency, tree))
    ),
    warnings: Array.isArray(tree.warnings) ? tree.warnings.slice() : [],
  };
}

function normalizeDependency(dependency, tree) {
  const ecosystem = dependency.ecosystem || tree.ecosystem;
  const format = dependency.format || canonicalFormat(ecosystem);
  const compatibilityVersion = Object.prototype.hasOwnProperty.call(dependency, "legacyVersion")
    ? dependency.legacyVersion
    : dependency.version;
  return {
    ...dependency,
    ecosystem,
    format,
    version: String(compatibilityVersion || ""),
    sourceFile: dependency.sourceFile || tree.sourceFile,
    parent: dependency.parent || null,
    parentChain: Array.isArray(dependency.parentChain) ? dependency.parentChain.slice() : [],
    transitives: Array.isArray(dependency.transitives)
      ? dependency.transitives.map((child) => normalizeDependency(child, tree))
      : [],
    cloudsmithStatus: dependency.cloudsmithStatus || null,
    cloudsmithPackage: dependency.cloudsmithPackage || null,
    cloudsmithLookupDetail: dependency.cloudsmithLookupDetail || null,
    devDependency: Boolean(dependency.devDependency || dependency.isDevelopmentDependency),
    isDevelopmentDependency: Boolean(dependency.isDevelopmentDependency || dependency.devDependency),
    vulnerabilities: dependency.vulnerabilities || null,
    license: dependency.license || null,
    policy: dependency.policy || null,
    upstreamStatus: dependency.upstreamStatus || null,
    upstreamDetail: dependency.upstreamDetail || null,
  };
}

function deduplicateDependenciesWithStatus(dependencies) {
  const seen = new Map();
  const results = [];

  for (const dependency of dependencies) {
    const key = displayDependencyKey(dependency);
    const existing = seen.get(key);
    if (!existing) {
      seen.set(key, dependency);
      results.push(dependency);
      continue;
    }

    if (!existing.isDirect && dependency.isDirect) {
      const index = results.indexOf(existing);
      if (index !== -1) {
        results[index] = dependency;
      }
      seen.set(key, dependency);
    }
  }

  return results;
}

function displayDependencyKey(dependency) {
  return getDependencyOccurrenceKey(dependency);
}

function coverageLookupKey(dependency) {
  return getDependencyArtifactKey(dependency);
}

function groupDependenciesByFormat(trees) {
  const byFormat = {};
  for (const tree of trees) {
    for (const dependency of tree.dependencies) {
      if (!isCoverageCandidate(dependency)) {
        continue;
      }
      if (!byFormat[dependency.format]) {
        byFormat[dependency.format] = [];
      }
      byFormat[dependency.format].push(dependency);
    }
  }
  return byFormat;
}

function uniqueDependenciesForCoverage(dependencies) {
  const seen = new Set();
  const unique = [];
  for (const dependency of dependencies) {
    if (!isCoverageCandidate(dependency)) {
      continue;
    }
    const key = coverageLookupKey(dependency);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(dependency);
  }
  return unique;
}

function countCoverageDependencies(trees) {
  return Object.values(groupDependenciesByFormat(trees))
    .reduce((count, dependencies) => count + uniqueDependenciesForCoverage(dependencies).length, 0);
}

function buildPackageIndex(packages, format) {
  const index = new Map();
  const normalizedFormat = canonicalFormat(format);
  for (const pkg of packages) {
    const versionKeys = new Set([String(pkg.version || "").trim()]);
    if (normalizedFormat === "nuget") {
      const normalizedVersion = normalizeNuGetVersion(pkg.version);
      if (normalizedVersion) versionKeys.add(normalizedVersion);
    }
    if (normalizedFormat === "docker" && Array.isArray(pkg?.tags?.version)) {
      for (const tag of pkg.tags.version) {
        const normalizedTag = String(tag || "").trim();
        if (normalizedTag) versionKeys.add(normalizedTag);
      }
    }
    for (const nameKey of getCaseAwareCloudsmithPackageLookupKeys(pkg, format)) {
      if (!index.has(nameKey)) {
        index.set(nameKey, new Map());
      }
      const versionMap = index.get(nameKey);
      for (const versionKey of versionKeys) {
        if (!versionKey) continue;
        if (!versionMap.has(versionKey)) {
          versionMap.set(versionKey, []);
        }
        versionMap.get(versionKey).push(pkg);
      }
    }
  }
  return index;
}

function findCoverageMatch(packageIndex, dependency) {
  const concreteVersion = getConcreteDependencyVersion(dependency);
  if (!concreteVersion) {
    return null;
  }

  for (const lookupKey of getCaseAwarePackageLookupKeys(dependency.name, dependency.format)) {
    const versions = packageIndex.get(lookupKey);
    if (!versions) {
      continue;
    }
    const versionKey = canonicalFormat(dependency.format || dependency.ecosystem) === "nuget"
      ? normalizeNuGetVersion(concreteVersion)
      : concreteVersion;
    if (versions.has(versionKey)) {
      const match = matchCoverageCandidates(versions.get(versionKey), dependency, concreteVersion);
      if (match) {
        return match;
      }
    }
  }
  return null;
}

function matchCoverageCandidates(
  candidates,
  dependency,
  expectedVersion = getConcreteDependencyVersion(dependency),
  verificationReceipt = null
) {
  if (!expectedVersion) {
    return null;
  }

  const dependencyFormat = canonicalFormat(
    dependency && (dependency.format || dependency.ecosystem)
  );
  const normalizedExpectedVersion = dependencyFormat === "nuget"
    ? normalizeNuGetVersion(expectedVersion)
    : String(expectedVersion).trim();
  const candidateList = Array.isArray(candidates) ? candidates : [];
  const requestedDockerPlatform = dependencyFormat === "docker"
    ? String(dependency && dependency.qualifiers && dependency.qualifiers.platform || "").trim()
    : "";

  for (const candidate of candidateList) {
    const candidateFormat = canonicalFormat(candidate && (candidate.format || candidate.ecosystem));
    if (!dependencyFormat || candidateFormat !== dependencyFormat) {
      continue;
    }
    const nameMatches = packageNameMatchesDependency(candidate, dependency)
      || (
        dependencyFormat === "swift"
        && verificationReceipt?.swiftScopeVerified === true
        && coverageCandidateBaseNameMatches(candidate, dependency, dependencyFormat)
      );
    if (!nameMatches) {
      continue;
    }
    if (
      requestedDockerPlatform
      && verificationReceipt?.dockerPlatformVerified !== true
      && !dockerCandidateMatchesPlatform(candidate, requestedDockerPlatform)
    ) {
      continue;
    }
    const dockerTags = dependencyFormat === "docker" && Array.isArray(candidate?.tags?.version)
      ? candidate.tags.version
      : [];
    const requestedDigest = dependencyFormat === "docker"
      ? String(dependency?.qualifiers?.digest || dependency?.digest || "").trim().toLowerCase()
      : "";
    const observedVersion = String(candidate.version || "").trim();
    const versionMatches = dependencyFormat === "nuget"
      ? normalizeNuGetVersion(observedVersion) === normalizedExpectedVersion
      : observedVersion === normalizedExpectedVersion;
    const digestMatches = requestedDigest
      && dockerDigestMatches(observedVersion, requestedDigest);
    const tagMatches = dockerTags.some(tag => String(tag) === normalizedExpectedVersion);
    if (dependencyFormat === "docker" ? (requestedDigest ? digestMatches : tagMatches) : versionMatches) {
      return candidate;
    }
  }
  return null;
}

function coverageCandidateEvidenceIsIncomplete(candidate, dependency, format, expectedVersion) {
  if (!coverageCandidateBaseNameMatches(candidate, dependency, format)) return false;
  if (format === "docker") {
    if (qualifierEvidenceIsIncomplete(candidate, dependency, format)) return true;
    const requestedPlatform = String(
      dependency && dependency.qualifiers && dependency.qualifiers.platform || ""
    ).trim();
    if (!requestedPlatform) return false;
    const dockerTags = Array.isArray(candidate && candidate.tags && candidate.tags.version)
      ? candidate.tags.version
      : [];
    const requestedDigest = String(
      dependency && dependency.qualifiers && dependency.qualifiers.digest
      || dependency && dependency.digest
      || ""
    ).trim();
    const identityMatches = requestedDigest
      ? dockerDigestMatches(candidate && candidate.version, requestedDigest)
      : dockerTags.some(tag => String(tag) === String(expectedVersion));
    return identityMatches && !dockerCandidateMatchesPlatform(candidate, requestedPlatform);
  }
  const versionMatches = format === "nuget"
    ? normalizeNuGetVersion(candidate.version) === normalizeNuGetVersion(expectedVersion)
    : String(candidate.version || "").trim() === String(expectedVersion || "").trim();
  return versionMatches && qualifierEvidenceIsIncomplete(candidate, dependency, format);
}

function coverageCandidateBaseNameMatches(candidate, dependency, format) {
  if (canonicalFormat(candidate && (candidate.format || candidate.ecosystem)) !== format) {
    return false;
  }
  const dependencyName = packageIdentityName(dependency && dependency.name, format);
  if (!dependencyName) return false;
  if (format === "maven" && dependencyName.includes(":")) {
    return getCaseAwareCloudsmithPackageLookupKeys(candidate, format)
      .some(key => key.includes(":") && key === dependencyName);
  }
  const expectedKeys = new Set(getCaseAwarePackageLookupKeys(
    dependency && dependency.name,
    format,
    dependency && dependency.qualifiers
  ));
  return getCaseAwareCloudsmithPackageLookupKeys(candidate, format)
    .some(key => expectedKeys.has(key));
}

function packageNameMatchesDependency(candidate, dependency) {
  const format = canonicalFormat(dependency && (dependency.format || dependency.ecosystem));
  const dependencyName = packageIdentityName(dependency && dependency.name, format);
  if (!dependencyName) {
    return false;
  }

  if (format === "maven" && dependencyName.includes(":")) {
    const candidateKeys = getCaseAwareCloudsmithPackageLookupKeys(candidate, format);
    return candidateKeys.some((key) => key.includes(":") && key === dependencyName)
      && mavenCandidateContainsRequestedArtifact(candidate, dependency);
  }

  if (format === "swift") {
    const dependencyIdentity = normalizeSwiftIdentity(
      dependency && dependency.name,
      dependency && dependency.qualifiers && dependency.qualifiers.scope
    );
    const candidateIdentifiers = candidate && candidate.identifiers
      && typeof candidate.identifiers === "object"
      ? candidate.identifiers
      : {};
    const candidateIdentity = normalizeSwiftIdentity(
      candidate && candidate.name,
      candidate && (candidate.scope || candidateIdentifiers.scope)
    );
    return Boolean(dependencyIdentity && candidateIdentity && dependencyIdentity === candidateIdentity);
  }

  if (
    format === "ruby"
    && !rubyCandidateMatchesPlatform(candidate, dependency?.qualifiers?.platform)
  ) {
    return false;
  }

  const dependencyKeys = getCaseAwarePackageLookupKeys(dependency && dependency.name, format);
  const candidateKeys = new Set(getCaseAwareCloudsmithPackageLookupKeys(candidate, format));
  return dependencyKeys.some((key) => candidateKeys.has(key));
}

function mavenCandidateContainsRequestedArtifact(candidate, dependency) {
  const expectedFileName = mavenArtifactFileName(
    dependency,
    getConcreteDependencyVersion(dependency)
  );
  if (!expectedFileName || !Array.isArray(candidate?.files)) return false;
  return candidate.files.some(file => (
    file
    && typeof file === "object"
    && String(file.filename || file.name || file.path || "").split("/").pop() === expectedFileName
  ));
}

function applyCoverageMatchBatchToTrees(trees, matchMap) {
  return applyPatchMapToTrees(trees, coverageLookupKey, matchMap, (dependency, patch) => ({
    ...dependency,
    cloudsmithStatus: patch.cloudsmithStatus,
    cloudsmithPackage: patch.cloudsmithPackage,
    cloudsmithLookupDetail: patch.cloudsmithLookupDetail,
    upstreamStatus: Object.prototype.hasOwnProperty.call(patch, "upstreamStatus")
      ? patch.upstreamStatus
      : dependency.upstreamStatus,
    upstreamDetail: Object.prototype.hasOwnProperty.call(patch, "upstreamDetail")
      ? patch.upstreamDetail
      : dependency.upstreamDetail,
  }));
}

function applyFoundOverlayPatch(trees, patchMap, mergeFn) {
  return applyPatchMapToTrees(trees, getFoundDependencyKey, patchMap, mergeFn);
}

function applyUncoveredOverlayPatch(trees, patchMap, mergeFn) {
  return applyPatchMapToTrees(trees, getUncoveredDependencyKey, patchMap, mergeFn);
}

function applyPatchMapToTrees(trees, getKey, patchMap, mergeFn) {
  if (!(patchMap instanceof Map) || patchMap.size === 0) {
    return trees;
  }

  return trees.map((tree) => ({
    ...tree,
    dependencies: tree.dependencies.map((dependency) => applyRecursiveDependencyPatch(
      dependency,
      getKey,
      patchMap,
      mergeFn
    )),
  }));
}

function applyRecursiveDependencyPatch(dependency, getKey, patchMap, mergeFn) {
  const key = getKey(dependency);
  const hasPatch = Boolean(key) && patchMap.has(key);
  const mergedDependency = hasPatch ? mergeFn(dependency, patchMap.get(key), key) : dependency;
  const originalChildren = Array.isArray(mergedDependency.transitives) ? mergedDependency.transitives : [];
  const nextChildren = originalChildren.map((child) => applyRecursiveDependencyPatch(child, getKey, patchMap, mergeFn));
  if (originalChildren === nextChildren || arraysEqualByReference(originalChildren, nextChildren)) {
    return mergedDependency;
  }
  return {
    ...mergedDependency,
    transitives: nextChildren,
  };
}

function applyRecursiveDependencyUpdate(dependency, predicate, mergeFn) {
  const mergedDependency = predicate(dependency) ? mergeFn(dependency) : dependency;
  const originalChildren = Array.isArray(mergedDependency.transitives) ? mergedDependency.transitives : [];
  const nextChildren = originalChildren.map((child) => applyRecursiveDependencyUpdate(child, predicate, mergeFn));
  if (originalChildren === nextChildren || arraysEqualByReference(originalChildren, nextChildren)) {
    return mergedDependency;
  }
  return {
    ...mergedDependency,
    transitives: nextChildren,
  };
}

function arraysEqualByReference(left, right) {
  if (left.length !== right.length) {
    return false;
  }
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      return false;
    }
  }
  return true;
}

function markTreesAsChecking(trees) {
  return trees.map((tree) => ({
    ...tree,
    dependencies: tree.dependencies.map((dependency) => applyRecursiveDependencyUpdate(
      dependency,
      () => true,
      (candidate) => ({
        ...candidate,
        cloudsmithStatus: getInitialCoverageStatus(candidate),
        cloudsmithPackage: null,
        cloudsmithLookupDetail: getInitialCoverageStatus(candidate)
          === CLOUDSMITH_COVERAGE_STATUS.NOT_APPLICABLE
          ? formatLookupNotApplicableDetail(candidate)
          : null,
        vulnerabilities: null,
        license: null,
        policy: null,
        upstreamStatus: null,
        upstreamDetail: null,
      })
    )),
  }));
}

function limitDisplayTrees(trees, maxDependencies) {
  const allDependencies = [];
  for (const tree of trees) {
    for (const dependency of tree.dependencies) {
      allDependencies.push(dependency);
    }
  }

  if (allDependencies.length <= maxDependencies) {
    return {
      trees: trees.map((tree) => ({
        ...tree,
        dependencies: tree.dependencies.slice().sort((left, right) => compareDependencies(left, right, SORT_MODES.ALPHABETICAL, true)),
      })),
      truncated: false,
      totalDependencies: allDependencies.length,
    };
  }

  const allowedKeys = new Set(
    allDependencies
      .slice()
      .sort(compareDependenciesForLimit)
      .slice(0, maxDependencies)
      .map(displayDependencyKey)
  );

  const limitedTrees = trees
    .map((tree) => {
      const dependencies = tree.dependencies
        .filter((dependency) => allowedKeys.has(displayDependencyKey(dependency)))
        .map((dependency) => pruneDependencyTree(dependency, allowedKeys))
        .sort((left, right) => compareDependencies(left, right, SORT_MODES.ALPHABETICAL, true));
      return {
        ...tree,
        dependencies,
        dependencyGraph: limitPackageLockGraph(tree.dependencyGraph, dependencies),
      };
    })
    .filter((tree) => tree.dependencies.length > 0);

  return {
    trees: limitedTrees,
    truncated: true,
    totalDependencies: allDependencies.length,
  };
}

function limitPackageLockGraph(graph, dependencies) {
  if (!graph || graph.kind !== "package-lock") {
    return graph || null;
  }
  const allowedResolved = new Set();
  const allowedUnresolved = new Set();
  const allowedDirectDeclarations = new Set();
  for (const dependency of dependencies) {
    const concreteVersion = getConcreteDependencyVersion(dependency);
    if (concreteVersion) {
      allowedResolved.add(graphPackageIdentity(dependency.name, concreteVersion));
    } else {
      allowedUnresolved.add(String(dependency.name || "").trim().toLowerCase());
    }
    if (dependency.isDirect) {
      allowedDirectDeclarations.add(String(
        dependency.declarationName || dependency.name || ""
      ).trim().toLowerCase());
    }
  }

  const sourceEntries = new Map(graph.entries.map((entry) => [entry.key, entry]));
  const entryAllowed = (entry) => Boolean(entry) && allowedResolved.has(
    graphPackageIdentity(entry.name, entry.version)
  );
  const entries = graph.entries
    .filter(entryAllowed)
    .map((entry) => Object.freeze({
      ...entry,
      edges: Object.freeze(entry.edges.filter((edge) => {
        if (!edge.childKey) {
          return allowedUnresolved.has(String(edge.declaredName || "").trim().toLowerCase());
        }
        return entryAllowed(sourceEntries.get(edge.childKey));
      })),
    }));
  const roots = graph.roots.filter((root) => {
    const declarationAllowed = allowedDirectDeclarations.has(
      String(root.declaredName || "").trim().toLowerCase()
    );
    if (!declarationAllowed) {
      return false;
    }
    if (root.entryKey) {
      const entry = sourceEntries.get(root.entryKey);
      return !entry || entryAllowed(entry);
    }
    return allowedUnresolved.has(String(root.declaredName || "").trim().toLowerCase());
  });

  return Object.freeze({
    ...graph,
    entries: Object.freeze(entries),
    roots: Object.freeze(roots),
  });
}

function pruneDependencyTree(dependency, allowedKeys) {
  const transitives = Array.isArray(dependency.transitives)
    ? dependency.transitives
      .filter((child) => allowedKeys.has(displayDependencyKey(child)))
      .map((child) => pruneDependencyTree(child, allowedKeys))
    : [];

  return {
    ...dependency,
    transitives,
  };
}

function compareDependenciesForLimit(left, right) {
  if (left.isDirect !== right.isDirect) {
    return left.isDirect ? -1 : 1;
  }
  return compareDependencies(left, right, SORT_MODES.ALPHABETICAL, false);
}

function compareDependencies(left, right, sortMode, preferDirect) {
  if (preferDirect && left.isDirect !== right.isDirect) {
    return left.isDirect ? -1 : 1;
  }

  if (sortMode === SORT_MODES.SEVERITY) {
    const severityDelta = dependencySeveritySortGroup(left) - dependencySeveritySortGroup(right);
    if (severityDelta !== 0) {
      return severityDelta;
    }
  }

  if (sortMode === SORT_MODES.COVERAGE) {
    const coverageDelta = dependencyCoverageSortGroup(left) - dependencyCoverageSortGroup(right);
    if (coverageDelta !== 0) {
      return coverageDelta;
    }
  }

  const leftName = String(left.name || "").toLowerCase();
  const rightName = String(right.name || "").toLowerCase();
  if (leftName !== rightName) {
    return leftName.localeCompare(rightName);
  }

  return String(left.version || "").localeCompare(String(right.version || ""));
}

function dependencyCoverageSortGroup(dependency) {
  if (isAbsentCoverageStatus(dependency.cloudsmithStatus)) {
    return 0;
  }
  if (dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.CHECKING) {
    return 2;
  }
  return 1;
}

function dependencySeveritySortGroup(dependency) {
  if (dependency.cloudsmithStatus !== CLOUDSMITH_COVERAGE_STATUS.FOUND) {
    return isAbsentCoverageStatus(dependency.cloudsmithStatus) ? 5 : 6;
  }

  const policy = getDependencyPolicyData(dependency);
  const vulnerabilities = getDependencyVulnerabilityData(dependency);
  const licenseClassification = getDependencyLicenseClassification(dependency);

  if (policy && (policy.quarantined || policy.denied)) {
    return 0;
  }

  if (hasDetectedVulnerabilities(vulnerabilities)) {
    if (vulnerabilities.maxSeverity === "Critical") {
      return 1;
    }
    if (vulnerabilities.maxSeverity === "High") {
      return 2;
    }
    return 3;
  }

  if (licenseClassification === "restrictive") {
    return 2;
  }

  if (licenseClassification === "weak_copyleft" || (policy && policy.violated)) {
    return 3;
  }

  return 4;
}

function getTreeRootDependencies(tree) {
  return (tree.dependencies || []).filter((dependency) => {
    const hasParentChain = Array.isArray(dependency.parentChain) && dependency.parentChain.length > 0;
    return !dependency.parent && !hasParentChain;
  });
}

function buildLegacyTreeWrappers(tree, filterMode, sortMode) {
  const roots = getTreeRootDependencies(tree)
    .sort((left, right) => compareDependencies(left, right, sortMode, false));
  const filteredRoots = roots
    .map((dependency) => buildFilteredTreeWrapper(dependency, filterMode, sortMode))
    .filter(Boolean);
  return annotateDuplicateWrappers(filteredRoots, new Map(), []);
}

function buildPackageLockGraphWrappers(tree, filterMode, sortMode) {
  const graph = tree.dependencyGraph;
  const baseDependencies = buildGraphDependencyIndex(tree.dependencies);
  const entryMap = new Map(graph.entries
    .filter((entry) => baseDependencies.has(graphPackageIdentity(entry.name, entry.version)))
    .map((entry) => [entry.key, entry]));
  const directDependencies = new Map(
    tree.dependencies
      .filter((dependency) => dependency.isDirect)
      .map((dependency) => [
        String(dependency.declarationName || dependency.name || "").toLowerCase(),
        dependency,
      ])
  );
  const entryDependencies = new Map();
  for (const entry of graph.entries) {
    entryDependencies.set(entry.key, graphDependencyForEntry(
      entry,
      entry.installedName,
      [],
      false,
      entry.isDevelopmentDependency,
      baseDependencies,
      directDependencies
    ));
  }
  const reachableMatches = computeGraphFilterReachability(
    graph,
    entryDependencies,
    filterMode
  );
  const seen = new Map();
  const presentation = {
    materialized: 0,
    maxNodes: graph.maxNodes || 50000,
    truncated: false,
  };

  const roots = graph.roots
    .filter((root) => directDependencies.has(String(root.declaredName || "").toLowerCase()))
    .map((root) => ({
      root,
      dependency: graphDependencyForRoot(
        root,
        entryMap,
        baseDependencies,
        directDependencies
      ),
    }))
    .sort((left, right) => compareDependencies(
      left.dependency,
      right.dependency,
      sortMode,
      false
    ));

  const wrappers = roots.map(({ root, dependency }) => materializeGraphWrapper({
    root,
    dependency,
    entryMap,
    baseDependencies,
    directDependencies,
    reachableMatches,
    filterMode,
    sortMode,
    seen,
    ancestry: [],
    visiting: new Set(),
    presentation,
    maxDepth: graph.maxDepth || 128,
  })).filter(Boolean);
  return { wrappers, truncated: presentation.truncated };
}

function buildGraphDependencyIndex(dependencies) {
  const index = new Map();
  for (const dependency of dependencies || []) {
    const key = graphPackageIdentity(dependency.name, dependency.version);
    if (!index.has(key) || (!index.get(key).isDirect && dependency.isDirect)) {
      index.set(key, dependency);
    }
  }
  return index;
}

function graphDependencyForRoot(root, entryMap, baseDependencies, directDependencies) {
  const direct = directDependencies.get(String(root.declaredName || "").toLowerCase());
  if (!root.entryKey) {
    return direct || graphUnresolvedDependency(root.declaredName, [], true, root.isDevelopmentDependency);
  }
  if (!entryMap.has(root.entryKey)) {
    // A non-null missing key means the parser knew the resolved occurrence but
    // omitted its adjacency at the graph bound. Preserve the authoritative
    // direct record as a leaf instead of mislabelling it as unresolved.
    return direct || graphUnresolvedDependency(root.declaredName, [], true, root.isDevelopmentDependency);
  }
  return graphDependencyForEntry(
    entryMap.get(root.entryKey),
    root.declaredName,
    [],
    true,
    root.isDevelopmentDependency,
    baseDependencies,
    directDependencies
  );
}

function graphDependencyForEntry(
  entry,
  declaredName,
  parentChain,
  isDirect,
  inheritedDevelopment,
  baseDependencies,
  directDependencies
) {
  const direct = isDirect
    ? directDependencies.get(String(declaredName || "").toLowerCase())
    : null;
  const base = direct || baseDependencies.get(graphPackageIdentity(entry.name, entry.version));
  const parent = parentChain[parentChain.length - 1] || null;
  return {
    ...(base || {}),
    ecosystem: base?.ecosystem || "npm",
    format: base?.format || "npm",
    name: entry.name,
    normalizedName: base?.normalizedName || entry.name.toLowerCase(),
    declarationName: declaredName || entry.installedName || entry.name,
    resolvedVersion: base?.resolvedVersion || entry.version,
    version: base?.version || entry.version,
    legacyVersion: base?.legacyVersion || entry.version,
    versionState: base?.versionState || "resolved",
    isDirect,
    isDevelopmentDependency: Boolean(
      inheritedDevelopment || entry.isDevelopmentDependency
    ),
    devDependency: Boolean(inheritedDevelopment || entry.isDevelopmentDependency),
    parent,
    parentChain: parentChain.slice(),
    transitives: [],
    declaredConstraint: isDirect ? direct?.declaredConstraint || null : null,
    environmentMarker: isDirect ? direct?.environmentMarker || null : null,
    sourceManifest: isDirect ? direct?.sourceManifest || null : null,
  };
}

function graphUnresolvedDependency(declaredName, parentChain, isDirect, inheritedDevelopment, base) {
  const parent = parentChain[parentChain.length - 1] || null;
  return {
    ...(base || {}),
    ecosystem: base?.ecosystem || "npm",
    format: base?.format || "npm",
    name: base?.name || declaredName,
    normalizedName: base?.normalizedName || String(declaredName || "").toLowerCase(),
    declarationName: declaredName,
    resolvedVersion: null,
    version: "",
    legacyVersion: "",
    versionState: base?.versionState || "incomplete",
    isDirect,
    isDevelopmentDependency: Boolean(inheritedDevelopment),
    devDependency: Boolean(inheritedDevelopment),
    parent,
    parentChain: parentChain.slice(),
    transitives: [],
    sourceManifest: isDirect ? base?.sourceManifest || null : null,
  };
}

function computeGraphFilterReachability(graph, entryDependencies, filterMode) {
  const reachable = new Map();
  const reverseEdges = new Map();
  const queue = [];
  for (const entry of graph.entries) {
    const matches = !filterMode || matchesFilter(entryDependencies.get(entry.key), filterMode);
    reachable.set(entry.key, matches);
    if (matches) {
      queue.push(entry.key);
    }
    for (const edge of entry.edges) {
      if (!edge.childKey) {
        continue;
      }
      if (!reverseEdges.has(edge.childKey)) {
        reverseEdges.set(edge.childKey, []);
      }
      reverseEdges.get(edge.childKey).push(entry.key);
    }
  }
  if (!filterMode) {
    return reachable;
  }

  for (let index = 0; index < queue.length; index += 1) {
    for (const parentKey of reverseEdges.get(queue[index]) || []) {
      if (reachable.get(parentKey)) {
        continue;
      }
      reachable.set(parentKey, true);
      queue.push(parentKey);
    }
  }
  return reachable;
}

function materializeGraphWrapper(context) {
  const {
    root,
    dependency,
    entryMap,
    baseDependencies,
    directDependencies,
    reachableMatches,
    filterMode,
    sortMode,
    seen,
    ancestry,
    visiting,
    presentation,
    maxDepth,
  } = context;
  if (presentation.materialized >= presentation.maxNodes) {
    presentation.truncated = true;
    return null;
  }

  const entryKey = root.entryKey;
  const entry = entryKey ? entryMap.get(entryKey) : null;
  const selfMatches = matchesFilter(dependency, filterMode);
  if (filterMode && !selfMatches && (!entryKey || !reachableMatches.get(entryKey))) {
    return null;
  }
  if (entryKey && visiting.has(entryKey)) {
    return null;
  }

  presentation.materialized += 1;
  const pathLabel = ancestry.concat(dependency.name).join(" > ");
  const duplicateKey = buildDuplicateKey(dependency);
  if (duplicateKey && seen.has(duplicateKey)) {
    return {
      dependency,
      children: [],
      duplicate: true,
      firstOccurrencePath: seen.get(duplicateKey),
      dimmedForFilter: Boolean(filterMode) && !selfMatches,
    };
  }
  if (duplicateKey) {
    seen.set(duplicateKey, pathLabel);
  }

  if (!entry) {
    return {
      dependency,
      children: [],
      duplicate: false,
      firstOccurrencePath: null,
      dimmedForFilter: Boolean(filterMode) && !selfMatches,
    };
  }

  if (dependency.parentChain.length >= maxDepth && entry.edges.length > 0) {
    presentation.truncated = true;
    return {
      dependency,
      children: [],
      duplicate: false,
      firstOccurrencePath: null,
      dimmedForFilter: Boolean(filterMode) && !selfMatches,
    };
  }

  const nextVisiting = new Set(visiting);
  nextVisiting.add(entry.key);
  const nextParentChain = dependency.parentChain.concat(dependency.name);
  const childCandidates = entry.edges.map((edge) => {
    // A non-null key missing from the bounded structural graph represents an
    // omitted resolved relationship. The parser warning already qualifies the
    // result; do not fabricate an unresolved dependency for that edge.
    if (edge.childKey && !entryMap.has(edge.childKey)) {
      return null;
    }
    const childEntry = edge.childKey ? entryMap.get(edge.childKey) : null;
    const childDependency = childEntry
      ? graphDependencyForEntry(
        childEntry,
        edge.declaredName,
        nextParentChain,
        false,
        dependency.isDevelopmentDependency,
        baseDependencies,
        directDependencies
      )
      : graphUnresolvedDependency(
        edge.declaredName,
        nextParentChain,
        false,
        dependency.isDevelopmentDependency
      );
    return {
      root: {
        declaredName: edge.declaredName,
        entryKey: childEntry ? childEntry.key : null,
        isDevelopmentDependency: dependency.isDevelopmentDependency,
      },
      dependency: childDependency,
    };
  }).filter(Boolean).filter(({ root: childRoot, dependency: child }) => (
    !filterMode
    || matchesFilter(child, filterMode)
    || (childRoot.entryKey && reachableMatches.get(childRoot.entryKey))
  )).sort((left, right) => compareDependencies(
    left.dependency,
    right.dependency,
    sortMode,
    false
  ));

  const children = childCandidates.map(({ root: childRoot, dependency: child }) => (
    materializeGraphWrapper({
      root: childRoot,
      dependency: child,
      entryMap,
      baseDependencies,
      directDependencies,
      reachableMatches,
      filterMode,
      sortMode,
      seen,
      ancestry: ancestry.concat(dependency.name),
      visiting: nextVisiting,
      presentation,
      maxDepth,
    })
  )).filter(Boolean);

  return {
    dependency,
    children,
    duplicate: false,
    firstOccurrencePath: null,
    dimmedForFilter: Boolean(filterMode) && !selfMatches,
  };
}

function graphPackageIdentity(name, version) {
  return JSON.stringify([
    String(name || "").trim().toLowerCase(),
    String(version || "").trim(),
  ]);
}

function buildFilteredTreeWrapper(dependency, filterMode, sortMode) {
  const children = Array.isArray(dependency.transitives)
    ? dependency.transitives
      .slice()
      .sort((left, right) => compareDependencies(left, right, sortMode, false))
      .map((child) => buildFilteredTreeWrapper(child, filterMode, sortMode))
      .filter(Boolean)
    : [];
  const matches = matchesFilter(dependency, filterMode);

  if (filterMode && !matches && children.length === 0) {
    return null;
  }

  return {
    dependency,
    children,
    duplicate: false,
    firstOccurrencePath: null,
    dimmedForFilter: Boolean(filterMode) && !matches,
  };
}

function annotateDuplicateWrappers(wrappers, seen, ancestry) {
  return wrappers.map((wrapper) => {
    const pathLabel = ancestry.concat(wrapper.dependency.name).join(" > ");
    const duplicateKey = buildDuplicateKey(wrapper.dependency);
    if (duplicateKey && seen.has(duplicateKey)) {
      return {
        ...wrapper,
        duplicate: true,
        firstOccurrencePath: seen.get(duplicateKey),
        children: [],
      };
    }

    if (duplicateKey) {
      seen.set(duplicateKey, pathLabel);
    }

    return {
      ...wrapper,
      children: annotateDuplicateWrappers(wrapper.children, seen, ancestry.concat(wrapper.dependency.name)),
    };
  });
}

function buildDuplicateKey(dependency) {
  const format = canonicalFormat(dependency.format || dependency.ecosystem);
  const name = packageIdentityName(dependency.name, format);
  const version = String(dependency.version || "").trim();
  if (!name) {
    return null;
  }
  return `${format}:${name}:${version}`;
}

function matchesFilter(dependency, filterMode) {
  const vulnerabilities = getDependencyVulnerabilityData(dependency);
  const policy = getDependencyPolicyData(dependency);
  const licenseClassification = getDependencyLicenseClassification(dependency);

  if (!filterMode) {
    return true;
  }

  switch (filterMode) {
    case FILTER_MODES.VULNERABLE:
      return hasDetectedVulnerabilities(vulnerabilities);
    case FILTER_MODES.UNCOVERED:
      return isAbsentCoverageStatus(dependency.cloudsmithStatus);
    case FILTER_MODES.RESTRICTIVE_LICENSE:
      return licenseClassification === "restrictive";
    case FILTER_MODES.POLICY_VIOLATION:
      return Boolean(policy && policy.violated);
    default:
      return true;
  }
}

function getFilterLabel(filterMode) {
  switch (filterMode) {
    case FILTER_MODES.VULNERABLE:
      return "vulnerable only";
    case FILTER_MODES.UNCOVERED:
      return "not in Cloudsmith";
    case FILTER_MODES.RESTRICTIVE_LICENSE:
      return "restrictive licenses";
    case FILTER_MODES.POLICY_VIOLATION:
      return "policy violations";
    default:
      return null;
  }
}

function dedupeDependenciesByArtifact(dependencies) {
  const artifacts = new Map();
  for (const dependency of Array.isArray(dependencies) ? dependencies : []) {
    const sourceDiscriminator = dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.NOT_APPLICABLE
      ? dependency.packageSource && dependency.packageSource.kind || "unknown"
      : "lookup";
    const key = JSON.stringify([getDependencyArtifactKey(dependency), sourceDiscriminator]);
    const existing = artifacts.get(key);
    if (!existing) {
      artifacts.set(key, dependency);
      continue;
    }
    artifacts.set(key, mergeComplianceDependency(existing, dependency));
  }
  return [...artifacts.values()];
}

function buildDependencySummary(fullTrees, displayTrees, options = {}) {
  const fullDependencies = fullTrees.flatMap((tree) => tree.dependencies);
  const displayDependencies = displayTrees.flatMap((tree) => tree.dependencies);
  const occurrenceDependencies = fullDependencies.length > 0 ? fullDependencies : displayDependencies;
  const summaryDependencies = dedupeDependenciesByArtifact(occurrenceDependencies);
  const applicableDependencies = summaryDependencies.filter((dependency) => (
    dependency.cloudsmithStatus !== CLOUDSMITH_COVERAGE_STATUS.NOT_APPLICABLE
  ));
  const direct = fullDependencies.filter((dependency) => dependency.isDirect).length;
  const ecosystems = {};

  for (const tree of fullTrees) {
    ecosystems[tree.ecosystem] = (ecosystems[tree.ecosystem] || 0) + tree.dependencies.length;
  }

  const found = summaryDependencies.filter((dependency) => dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.FOUND).length;
  const notFound = summaryDependencies.filter((dependency) => isAbsentCoverageStatus(dependency.cloudsmithStatus)).length;
  const checking = summaryDependencies.filter((dependency) => dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.CHECKING).length;
  const unresolved = summaryDependencies.filter((dependency) => dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.UNRESOLVED).length;
  const lookupFailed = summaryDependencies.filter((dependency) => dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.LOOKUP_FAILED).length;
  const lookupIncomplete = summaryDependencies.filter((dependency) => (
    dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE
    || dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.RATE_LIMITED
  )).length;
  const rateLimited = summaryDependencies.filter((dependency) => dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.RATE_LIMITED).length;
  const notApplicable = summaryDependencies.filter((dependency) => (
    dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.NOT_APPLICABLE
  )).length;
  const reachableViaUpstream = summaryDependencies.filter((dependency) => (
    isAbsentCoverageStatus(dependency.cloudsmithStatus) && dependency.upstreamStatus === "reachable"
  )).length;
  const unreachableViaUpstream = summaryDependencies.filter((dependency) => (
    isAbsentCoverageStatus(dependency.cloudsmithStatus)
    && (dependency.upstreamStatus === "no_proxy" || dependency.upstreamStatus === "unreachable")
  )).length;
  const vulnerable = summaryDependencies.filter((dependency) => {
    const vulnerabilities = getDependencyVulnerabilityData(dependency);
    return dependency.cloudsmithStatus === "FOUND" && hasDetectedVulnerabilities(vulnerabilities);
  }).length;
  const severityCounts = {};
  for (const dependency of summaryDependencies) {
    const vulnerabilities = getDependencyVulnerabilityData(dependency);
    if (
      dependency.cloudsmithStatus === "FOUND"
      && hasDetectedVulnerabilities(vulnerabilities)
      && vulnerabilities.maxSeverity
      && vulnerabilities.maxSeverity !== "Unknown"
    ) {
      severityCounts[vulnerabilities.maxSeverity] = (severityCounts[vulnerabilities.maxSeverity] || 0) + 1;
    }
  }

  const permissiveLicenses = summaryDependencies.filter((dependency) => (
    dependency.cloudsmithStatus === "FOUND"
    && getDependencyLicenseClassification(dependency) === "permissive"
  )).length;
  const weakCopyleftLicenses = summaryDependencies.filter((dependency) => (
    dependency.cloudsmithStatus === "FOUND"
    && getDependencyLicenseClassification(dependency) === "weak_copyleft"
  )).length;
  const restrictiveLicenses = summaryDependencies.filter((dependency) => (
    dependency.cloudsmithStatus === "FOUND"
    && getDependencyLicenseClassification(dependency) === "restrictive"
  )).length;
  const unknownLicenses = summaryDependencies.filter((dependency) => (
    dependency.cloudsmithStatus === "FOUND"
    && getDependencyLicenseClassification(dependency) === "unknown"
  )).length;
  const policyViolations = summaryDependencies.filter((dependency) => {
    const policy = getDependencyPolicyData(dependency);
    return dependency.cloudsmithStatus === "FOUND" && policy && policy.violated;
  }).length;
  const quarantined = summaryDependencies.filter((dependency) => {
    const policy = getDependencyPolicyData(dependency);
    return dependency.cloudsmithStatus === "FOUND" && policy && (policy.quarantined || policy.denied);
  }).length;

  const filterMode = options.filterMode || null;
  const filterLabel = getFilterLabel(filterMode);
  const filteredCount = filterMode
    ? summaryDependencies.filter((dependency) => matchesFilter(dependency, filterMode)).length
    : 0;

  return {
    total: fullDependencies.length,
    artifacts: summaryDependencies.length,
    applicableArtifacts: applicableDependencies.length,
    notApplicable,
    direct,
    transitive: fullDependencies.length - direct,
    found,
    notFound,
    unresolved,
    lookupFailed,
    lookupIncomplete,
    rateLimited,
    reachableViaUpstream,
    unreachableViaUpstream,
    ecosystems,
    coveragePercent: applicableDependencies.length === 0
      ? 0
      : Math.round((found / applicableDependencies.length) * 100),
    checking,
    vulnerable,
    severityCounts,
    restrictiveLicenses,
    weakCopyleftLicenses,
    permissiveLicenses,
    unknownLicenses,
    policyViolations,
    quarantined,
    filterMode,
    filterLabel,
    filteredCount,
  };
}

function emptySummary() {
  return {
    total: 0,
    artifacts: 0,
    applicableArtifacts: 0,
    notApplicable: 0,
    direct: 0,
    transitive: 0,
    found: 0,
    notFound: 0,
    unresolved: 0,
    lookupFailed: 0,
    lookupIncomplete: 0,
    rateLimited: 0,
    reachableViaUpstream: 0,
    unreachableViaUpstream: 0,
    ecosystems: {},
    coveragePercent: 0,
    checking: 0,
    vulnerable: 0,
    severityCounts: {},
    restrictiveLicenses: 0,
    weakCopyleftLicenses: 0,
    permissiveLicenses: 0,
    unknownLicenses: 0,
    policyViolations: 0,
    quarantined: 0,
    filterMode: null,
    filterLabel: null,
    filteredCount: 0,
  };
}

async function runPromisePool(items, concurrency, worker) {
  const workers = [];
  let index = 0;
  const size = Math.max(1, Math.min(concurrency, items.length || 1));

  for (let workerIndex = 0; workerIndex < size; workerIndex += 1) {
    workers.push((async () => {
      while (index < items.length) {
        const item = items[index];
        index += 1;
        if (item === undefined) {
          break;
        }
        await worker(item);
      }
    })());
  }

  await Promise.allSettled(workers);
}

function mergePatchMaps(patchMaps) {
  const mergedPatchMap = new Map();

  for (const patchMap of patchMaps) {
    if (!(patchMap instanceof Map)) {
      continue;
    }

    for (const [key, value] of patchMap.entries()) {
      mergedPatchMap.set(key, value);
    }
  }

  return mergedPatchMap;
}

function yieldToEventLoop() {
  return new Promise((resolve) => {
    if (typeof setImmediate === "function") {
      setImmediate(resolve);
      return;
    }

    setTimeout(resolve, 0);
  });
}

function normalizeScheduler(scheduler) {
  if (scheduler === undefined) {
    return Object.freeze({
      now: Date.now,
      setTimeout,
      clearTimeout,
      yield: yieldToEventLoop,
    });
  }
  if (!scheduler || typeof scheduler !== "object" || Array.isArray(scheduler)) {
    throw new TypeError("Dependency scheduler must be an object.");
  }
  for (const method of ["now", "setTimeout", "clearTimeout", "yield"]) {
    if (typeof scheduler[method] !== "function") {
      throw new TypeError(`Dependency scheduler is missing ${method}().`);
    }
  }
  return Object.freeze({
    now: scheduler.now.bind(scheduler),
    setTimeout: scheduler.setTimeout.bind(scheduler),
    clearTimeout: scheduler.clearTimeout.bind(scheduler),
    yield: scheduler.yield.bind(scheduler),
  });
}

function normalizeUserInteraction(userInteraction) {
  if (userInteraction === undefined) {
    return Object.freeze({
      withProgress: vscode.window.withProgress.bind(vscode.window),
      showQuickPick: vscode.window.showQuickPick.bind(vscode.window),
      showOpenDialog: vscode.window.showOpenDialog.bind(vscode.window),
      showInformationMessage: vscode.window.showInformationMessage.bind(vscode.window),
      showWarningMessage: vscode.window.showWarningMessage.bind(vscode.window),
      showErrorMessage: vscode.window.showErrorMessage.bind(vscode.window),
    });
  }
  if (!userInteraction || typeof userInteraction !== "object" || Array.isArray(userInteraction)) {
    throw new TypeError("Dependency user interaction must be an object.");
  }
  const methods = [
    "withProgress",
    "showQuickPick",
    "showOpenDialog",
    "showInformationMessage",
    "showWarningMessage",
    "showErrorMessage",
  ];
  const normalized = {};
  for (const method of methods) {
    if (typeof userInteraction[method] !== "function") {
      throw new TypeError(`Dependency user interaction is missing ${method}().`);
    }
    normalized[method] = userInteraction[method].bind(userInteraction);
  }
  return Object.freeze(normalized);
}

function resolveSingleDependencyPullTarget(coordinate, trees) {
  const expectedQualifierIdentity = dependencyPullQualifierIdentity(coordinate);
  const matches = (Array.isArray(trees) ? trees : [])
    .flatMap(tree => Array.isArray(tree?.dependencies) ? tree.dependencies : [])
    .filter(dependency => (
      dependency
      && dependency.name === coordinate.name
      && getConcreteDependencyVersion(dependency) === coordinate.version
      && canonicalFormat(dependency.format || dependency.ecosystem) === coordinate.format
      && dependencyPullQualifierIdentity(dependency) === expectedQualifierIdentity
      && isAbsentCoverageStatus(dependency.cloudsmithStatus)
    ));
  if (matches.length === 0) return null;
  const artifactKeys = new Set(matches.map(coverageLookupKey));
  if (artifactKeys.size !== 1 || artifactKeys.has(null)) return null;
  const dependency = matches[0];
  return {
    ...dependency,
    name: coordinate.name,
    version: coordinate.version,
    format: coordinate.format,
    ecosystem: dependency.ecosystem || coordinate.format,
  };
}

function dependencyPullQualifierIdentity(dependency) {
  const qualifiers = dependency && dependency.qualifiers;
  if (!qualifiers || typeof qualifiers !== "object" || Array.isArray(qualifiers)) {
    return JSON.stringify([]);
  }
  return JSON.stringify(DEPENDENCY_QUALIFIER_KEYS
    .filter(key => Object.prototype.hasOwnProperty.call(qualifiers, key))
    .map(key => [key, qualifiers[key]]));
}

function formatSingleDependencyLabel(dependency) {
  const name = String(dependency && dependency.name || "").trim() || "dependency";
  const version = String(dependency && dependency.version || "").trim();
  return version ? `${name}@${version}` : name;
}

function getSingleDependencyPullDetail(pullResult) {
  return pullResult && Array.isArray(pullResult.details) ? (pullResult.details[0] || null) : null;
}

function isSuccessfulSingleDependencyPull(detail) {
  return Boolean(
    detail
    && (detail.status === PULL_STATUS.CACHED || detail.status === PULL_STATUS.ALREADY_EXISTS)
  );
}

function buildSingleDependencyPullNotification(dependency, repositorySlug, detail) {
  const dependencyLabel = formatSingleDependencyLabel(dependency);
  if (!detail) {
    return {
      level: "error",
      message: `Could not pull ${dependencyLabel}.`,
    };
  }

  switch (detail.status) {
    case PULL_STATUS.CACHED:
    case PULL_STATUS.ALREADY_EXISTS:
      return {
        level: "info",
        message: `${dependencyLabel} cached in ${repositorySlug}`,
      };
    case PULL_STATUS.NOT_FOUND:
      return {
        level: "info",
        message: `${dependencyLabel} not found on the upstream source.`,
      };
    case PULL_STATUS.AUTH_FAILED:
      return {
        level: "error",
        message: "Authentication failed. Check Cloudsmith authentication in Settings and retry.",
      };
    default:
      return {
        level: "error",
        message: detail.errorMessage
          ? `Could not pull ${dependencyLabel}. ${detail.errorMessage}`
          : `Could not pull ${dependencyLabel}.`,
      };
  }
}

function formatReportDate(date) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) {
    return new Date().toISOString().slice(0, 10);
  }
  return date.toISOString().slice(0, 10);
}

function normalizeReportTimestamp(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) {
    return new Date().toISOString();
  }
  return date.toISOString();
}

function vulnerabilityStateForReport(options, dependency) {
  if (!options || typeof options.vulnerabilityStateFor !== "function") return null;
  try {
    return options.vulnerabilityStateFor(dependency) || null;
  } catch {
    return null;
  }
}

function buildComplianceReportData(projectName, dependencies, options = {}) {
  const uniqueDependencies = dedupeComplianceDependencies(dependencies);
  const occurrenceTotal = Array.isArray(dependencies) ? dependencies.length : 0;
  const ecosystemBreakdown = {};

  for (const dependency of uniqueDependencies) {
    const ecosystem = String(dependency.format || dependency.ecosystem || "unknown").toLowerCase();
    ecosystemBreakdown[ecosystem] = (ecosystemBreakdown[ecosystem] || 0) + 1;
  }

  const vulnerabilityEvidence = uniqueDependencies
    .filter((dependency) => dependency.cloudsmithStatus === "FOUND")
    .map((dependency) => ({
      dependency,
      evidence: projectVulnerabilityForReport(
        getDependencyVulnerabilityData(dependency),
        vulnerabilityStateForReport(options, dependency)
      ),
    }));

  const vulnerableDeps = vulnerabilityEvidence
    .map(({ dependency, evidence }) => {
      if (evidence.state === REPORT_VULNERABILITY_STATES.COMPLETE_CLEAN) return null;

      return {
        ...complianceRowProvenance(dependency),
        name: dependency.name,
        version: dependency.version || "",
        isDirect: Boolean(dependency.isDirect),
        maxSeverity: evidence.maxSeverity,
        cveCount: evidence.countKnown ? evidence.count : null,
        vulnerabilityStatus: evidence.detected ? "Detected" : "Unknown",
        vulnerabilityState: evidence.state,
        fixAvailability: evidence.fixAvailability,
        hasFixAvailable: evidence.hasFixAvailable,
      };
    })
    .filter(Boolean)
    .sort(compareComplianceVulnerabilityRows);

  const detectedVulnerableDeps = vulnerableDeps.filter((dependency) => (
    dependency.vulnerabilityStatus === "Detected"
  ));
  const severityCounts = {};
  for (const dependency of detectedVulnerableDeps) {
    const severity = dependency.maxSeverity || "Unknown";
    severityCounts[severity] = (severityCounts[severity] || 0) + 1;
  }
  const allApplicableDependenciesFound = uniqueDependencies.every((dependency) => (
    dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.FOUND
    || dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.NOT_APPLICABLE
  ));
  const vulnerabilityCoverageComplete = vulnerabilityEvidence.length > 0
    && allApplicableDependenciesFound
    && vulnerabilityEvidence.every(({ evidence }) => evidence.complete === true);
  const vulnIncompleteCount = vulnerabilityEvidence.filter(({ evidence }) => (
    evidence.complete !== true
  )).length;

  const restrictiveLicenseDeps = uniqueDependencies
    .filter((dependency) => dependency.cloudsmithStatus === "FOUND")
    .map((dependency) => {
      const classification = getDependencyLicenseClassification(dependency);
      if (!["restrictive", "weak_copyleft"].includes(classification)) {
        return null;
      }

      const licenseData = dependency.license || null;
      const inspection = dependency.cloudsmithPackage
        ? LicenseClassifier.inspect(dependency.cloudsmithPackage)
        : LicenseClassifier.inspect(null);
      const spdx = licenseData && licenseData.spdx
        ? licenseData.spdx
        : dependency.spdx_license
          ? dependency.spdx_license
          : inspection.spdxLicense || inspection.displayValue || "";

      return {
        ...complianceRowProvenance(dependency),
        name: dependency.name,
        version: dependency.version || "",
        spdx,
        classification: humanizeLicenseClassification(classification),
      };
    })
    .filter(Boolean)
    .sort(compareNamedRows);

  const policyViolationDeps = uniqueDependencies
    .filter((dependency) => dependency.cloudsmithStatus === "FOUND")
    .map((dependency) => {
      const policy = getDependencyPolicyData(dependency);
      if (!policy || !policy.violated) {
        return null;
      }

      return {
        ...complianceRowProvenance(dependency),
        name: dependency.name,
        version: dependency.version || "",
        status: humanizePolicyStatus(policy),
        detail: policy.statusReason || defaultPolicyDetail(policy),
      };
    })
    .filter(Boolean)
    .sort(compareCompliancePolicyRows);

  const uncoveredDeps = uniqueDependencies
    .filter((dependency) => isAbsentCoverageStatus(dependency.cloudsmithStatus))
    .map((dependency) => ({
      ...complianceRowProvenance(dependency),
      name: dependency.name,
      version: dependency.version || "",
      ecosystem: dependency.format || dependency.ecosystem || "",
      upstreamStatus: dependency.upstreamStatus || "unknown",
      upstreamDetail: dependency.upstreamDetail || defaultUpstreamDetail(dependency.upstreamStatus),
    }))
    .sort(compareComplianceUncoveredRows);

  const notApplicableDeps = uniqueDependencies
    .filter((dependency) => dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.NOT_APPLICABLE)
    .map((dependency) => ({
      ...complianceRowProvenance(dependency),
      name: dependency.name,
      version: dependency.version || "",
      ecosystem: dependency.format || dependency.ecosystem || "",
      sourceKind: dependency.packageSource && dependency.packageSource.kind || "unknown",
      detail: dependency.cloudsmithLookupDetail || formatLookupNotApplicableDetail(dependency),
    }))
    .sort(compareNamedRows);

  const total = uniqueDependencies.length;
  const direct = uniqueDependencies.filter((dependency) => dependency.isDirect).length;
  const found = uniqueDependencies.filter((dependency) => dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.FOUND).length;
  const notFound = uniqueDependencies.filter((dependency) => isAbsentCoverageStatus(dependency.cloudsmithStatus)).length;
  const unresolved = uniqueDependencies.filter((dependency) => dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.UNRESOLVED).length;
  const lookupFailed = uniqueDependencies.filter((dependency) => dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.LOOKUP_FAILED).length;
  const lookupIncomplete = uniqueDependencies.filter((dependency) => (
    dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE
    || dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.RATE_LIMITED
  )).length;
  const notApplicable = notApplicableDeps.length;
  const coverageDenominator = Math.max(total - notApplicable, 0);
  const upstreamReachable = uncoveredDeps.filter((dependency) => dependency.upstreamStatus === "reachable").length;
  const upstreamNoProxy = uncoveredDeps.filter((dependency) => dependency.upstreamStatus === "no_proxy").length;
  const upstreamUnreachable = uncoveredDeps.filter((dependency) => dependency.upstreamStatus === "unreachable").length;

  return {
    projectName: projectName || "workspace",
    scanDate: normalizeReportTimestamp(options.scanDate),
    summary: {
      total,
      occurrences: occurrenceTotal,
      notApplicable,
      direct,
      transitive: Math.max(total - direct, 0),
      found,
      notFound,
      unresolved,
      lookupFailed,
      lookupIncomplete,
      coveragePct: coverageDenominator === 0 ? 0 : Math.round((found / coverageDenominator) * 100),
      vulnCount: detectedVulnerableDeps.length,
      vulnUnknownCount: vulnerableDeps.length - detectedVulnerableDeps.length,
      vulnDetectedUnknownSeverityCount: severityCounts.Unknown || 0,
      vulnIncompleteCount,
      vulnerabilityCoverageComplete,
      criticalCount: severityCounts.Critical || 0,
      highCount: severityCounts.High || 0,
      mediumCount: severityCounts.Medium || 0,
      lowCount: severityCounts.Low || 0,
      restrictiveLicenseCount: restrictiveLicenseDeps.length,
      policyViolationCount: policyViolationDeps.length,
      upstreamReachable,
      upstreamNoProxy,
      upstreamUnreachable,
    },
    ecosystemBreakdown,
    vulnerableDeps,
    restrictiveLicenseDeps,
    policyViolationDeps,
    uncoveredDeps,
    notApplicableDeps,
  };
}

function dedupeComplianceDependencies(dependencies) {
  const uniqueDependencies = new Map();

  for (const dependency of Array.isArray(dependencies) ? dependencies : []) {
    const key = complianceDependencyKey(dependency);
    if (!uniqueDependencies.has(key)) {
      uniqueDependencies.set(key, {
        ...dependency,
        occurrenceCount: 1,
        reportProvenance: [createComplianceProvenance(dependency)],
      });
      continue;
    }

    uniqueDependencies.set(key, mergeComplianceDependency(uniqueDependencies.get(key), dependency));
  }

  return [...uniqueDependencies.values()];
}

function complianceDependencyKey(dependency) {
  const hasCanonicalArtifactContract = Boolean(
    dependency
    && dependency.packageSource
    && dependency.qualifiers
    && Object.prototype.hasOwnProperty.call(dependency, "lookupEligibility")
  );
  if (!hasCanonicalArtifactContract) {
    return JSON.stringify([
      getDependencyArtifactKey(dependency),
      getDependencyOccurrenceKey(dependency),
    ]);
  }
  return JSON.stringify([
    getDependencyArtifactKey(dependency),
    dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.NOT_APPLICABLE
      ? dependency.packageSource && dependency.packageSource.kind || "unknown"
      : "lookup",
  ]);
}

function createComplianceProvenance(dependency) {
  return {
    source: dependency && dependency.sourceManifest && dependency.sourceManifest.label
      || dependency && dependency.sourceFile
      || null,
    resolutionSource: dependency && dependency.resolutionSource && dependency.resolutionSource.label
      || null,
    qualifiers: dependency && dependency.qualifiers || {},
    packageSource: dependency && dependency.packageSource || null,
    parentChain: Array.isArray(dependency && dependency.parentChain)
      ? dependency.parentChain.slice(0, 128)
      : [],
  };
}

function mergeComplianceProvenance(left, right) {
  const merged = new Map();
  for (const entry of [...(left || []), ...(right || [])]) {
    const key = JSON.stringify(entry);
    if (!merged.has(key) && merged.size < 64) merged.set(key, entry);
  }
  return [...merged.values()];
}

function complianceRowProvenance(dependency) {
  return {
    occurrenceCount: dependency.occurrenceCount || 1,
    qualifiers: dependency.qualifiers || {},
    packageSource: dependency.packageSource || null,
    provenance: Array.isArray(dependency.reportProvenance)
      ? dependency.reportProvenance.slice()
      : [createComplianceProvenance(dependency)],
  };
}

function mergeComplianceDependency(existing, candidate) {
  const cloudsmithStatus = pickBetterCoverageStatus(
    existing.cloudsmithStatus,
    candidate.cloudsmithStatus
  );
  return {
    ...existing,
    occurrenceCount: (existing.occurrenceCount || 1) + (candidate.occurrenceCount || 1),
    reportProvenance: mergeComplianceProvenance(
      existing.reportProvenance,
      candidate.reportProvenance || [createComplianceProvenance(candidate)]
    ),
    isDirect: Boolean(existing.isDirect || candidate.isDirect),
    cloudsmithStatus,
    cloudsmithPackage: cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.FOUND
      ? existing.cloudsmithPackage || candidate.cloudsmithPackage || null
      : null,
    vulnerabilities: pickRicherVulnerabilityData(existing.vulnerabilities, candidate.vulnerabilities),
    license: existing.license || candidate.license || null,
    policy: pickRicherPolicyData(existing.policy, candidate.policy),
    upstreamStatus: existing.upstreamStatus || candidate.upstreamStatus || null,
    upstreamDetail: existing.upstreamDetail || candidate.upstreamDetail || null,
  };
}

function pickBetterCoverageStatus(left, right) {
  const priorities = {
    FOUND: 8,
    RATE_LIMITED: 7,
    LOOKUP_INCOMPLETE: 6,
    LOOKUP_FAILED: 5,
    UNRESOLVED: 4,
    NOT_APPLICABLE: 4,
    CHECKING: 3,
    ABSENT: 2,
    NOT_FOUND: 2,
  };
  const leftPriority = priorities[left] || 0;
  const rightPriority = priorities[right] || 0;
  return rightPriority > leftPriority ? right : left;
}

function pickRicherVulnerabilityData(left, right) {
  if (!left) {
    return right || null;
  }
  if (!right) {
    return left;
  }
  if (Boolean(right.detailsLoaded) !== Boolean(left.detailsLoaded)) {
    return right.detailsLoaded ? right : left;
  }
  return (right.count || 0) > (left.count || 0) ? right : left;
}

function pickRicherPolicyData(left, right) {
  if (!left) {
    return right || null;
  }
  if (!right) {
    return left;
  }
  if (Boolean(right.denied || right.quarantined) !== Boolean(left.denied || left.quarantined)) {
    return right.denied || right.quarantined ? right : left;
  }
  if (Boolean(right.statusReason) !== Boolean(left.statusReason)) {
    return right.statusReason ? right : left;
  }
  return right.violated ? right : left;
}

function compareComplianceVulnerabilityRows(left, right) {
  const severityDelta = severitySortWeight(left.maxSeverity) - severitySortWeight(right.maxSeverity);
  if (severityDelta !== 0) {
    return severityDelta;
  }

  if (left.isDirect !== right.isDirect) {
    return left.isDirect ? -1 : 1;
  }

  return compareNamedRows(left, right);
}

function compareCompliancePolicyRows(left, right) {
  const statusDelta = policyStatusSortWeight(left.status) - policyStatusSortWeight(right.status);
  if (statusDelta !== 0) {
    return statusDelta;
  }
  return compareNamedRows(left, right);
}

function compareComplianceUncoveredRows(left, right) {
  const statusDelta = upstreamStatusSortWeight(left.upstreamStatus) - upstreamStatusSortWeight(right.upstreamStatus);
  if (statusDelta !== 0) {
    return statusDelta;
  }
  return compareNamedRows(left, right);
}

function compareNamedRows(left, right) {
  const nameDelta = String(left.name || "").localeCompare(String(right.name || ""), undefined, { sensitivity: "base" });
  if (nameDelta !== 0) {
    return nameDelta;
  }
  return String(left.version || "").localeCompare(String(right.version || ""), undefined, { sensitivity: "base" });
}

function severitySortWeight(severity) {
  return 4 - vulnerabilitySeverityRank(severity);
}

function upstreamStatusSortWeight(status) {
  switch (status) {
    case "reachable":
      return 0;
    case "no_proxy":
      return 1;
    case "unreachable":
      return 2;
    default:
      return 3;
  }
}

function policyStatusSortWeight(status) {
  switch (status) {
    case "Quarantined":
      return 0;
    case "Denied":
      return 1;
    case "Policy violation":
      return 2;
    default:
      return 3;
  }
}

function humanizeLicenseClassification(classification) {
  switch (classification) {
    case "restrictive":
      return "Restrictive";
    case "weak_copyleft":
      return "Weak copyleft";
    default:
      return "Unclassified";
  }
}

function humanizePolicyStatus(policy) {
  if (policy.quarantined) {
    return "Quarantined";
  }
  if (policy.denied) {
    return "Denied";
  }
  if (policy.status && policy.status !== "Completed") {
    return policy.status;
  }
  return "Policy violation";
}

function defaultPolicyDetail(policy) {
  if (policy.denied || policy.quarantined) {
    return "Blocked by Cloudsmith policy.";
  }
  return "Policy requirements were not met.";
}

function defaultUpstreamDetail(status) {
  switch (status) {
    case "reachable":
      return "Available via an upstream proxy.";
    case "no_proxy":
      return "No upstream proxy is configured for this ecosystem.";
    case "unreachable":
      return "Configured upstreams could not serve this package.";
    default:
      return "Not found in Cloudsmith.";
  }
}

function buildDependencyHealthReport(projectName, dependencies, summary, generatedDate) {
  const reportDependencies = dedupeComplianceDependencies(dependencies);
  const vulnerableDependencies = reportDependencies
    .filter((dependency) => {
      const vulnerabilities = getDependencyVulnerabilityData(dependency);
      return hasDetectedVulnerabilities(vulnerabilities) || vulnerabilities?.unknown === true;
    })
    .sort((left, right) => compareDependencies(left, right, SORT_MODES.SEVERITY, false));
  const uncoveredDependencies = reportDependencies
    .filter((dependency) => isAbsentCoverageStatus(dependency.cloudsmithStatus))
    .sort((left, right) => compareDependencies(left, right, SORT_MODES.COVERAGE, false));
  const policyViolations = reportDependencies
    .filter((dependency) => dependency.policy && dependency.policy.violated)
    .sort((left, right) => compareDependencies(left, right, SORT_MODES.SEVERITY, false));

  const lines = [
    `# Dependency Health Report — ${projectName}`,
    `Generated: ${generatedDate}`,
    "",
    "## Summary",
    `- ${summary.total} dependency occurrences (${summary.direct} direct, ${summary.transitive} transitive)`,
    `- ${summary.artifacts} unique artifacts (${summary.applicableArtifacts} applicable to registry lookup)`,
    `- ${summary.found} served by Cloudsmith (${summary.coveragePercent}% coverage)`,
  ];

  if (summary.notFound > 0) {
    lines.push(`- ${summary.notFound} not found in Cloudsmith`);
  }

  if (summary.notApplicable > 0) {
    lines.push(`- ${summary.notApplicable} artifacts not applicable to Cloudsmith registry lookup`);
  }

  if (summary.vulnerable > 0) {
    const severityParts = ["Critical", "High", "Medium", "Low"]
      .filter((severity) => summary.severityCounts[severity] > 0)
      .map((severity) => `${summary.severityCounts[severity]} ${severity}`);
    lines.push(
      `- ${summary.vulnerable} with detected vulnerabilities${severityParts.length > 0 ? ` (${severityParts.join(", ")})` : ""}`
    );
  }

  lines.push("");
  lines.push("## Dependency Vulnerability Status");
  if (vulnerableDependencies.length === 0) {
    lines.push("None");
  } else {
    lines.push("| Package | Version | Type | Severity | CVEs | Fix Available |");
    lines.push("|---------|---------|------|----------|------|---------------|");
    for (const dependency of vulnerableDependencies) {
      const vulnerabilities = getDependencyVulnerabilityData(dependency);
      const fixEntry = (vulnerabilities.entries || []).find((entry) => entry.fixVersion);
      const fixCell = fixEntry
        ? `Yes (${fixEntry.fixVersion})`
        : vulnerabilities.hasFixAvailable
          ? "Yes"
          : "No";
      const status = vulnerabilities.unknown && !hasDetectedVulnerabilities(vulnerabilities)
        ? "Unknown"
        : "Detected";
      const cves = vulnerabilities.countKnown === true
        ? (vulnerabilities.cveIds || []).join(", ") || String(vulnerabilities.count)
        : status;
      lines.push(`| ${dependency.name} | ${dependency.version || "—"} | ${dependency.isDirect ? "Direct" : "Transitive"} | ${vulnerabilities.maxSeverity || "Unknown"} | ${cves} | ${fixCell} |`);
    }
  }

  const licenseTotals = summary.permissiveLicenses + summary.weakCopyleftLicenses + summary.restrictiveLicenses + summary.unknownLicenses;
  if (licenseTotals > 0) {
    lines.push("");
    lines.push("## License Summary");
    lines.push(`- ${summary.permissiveLicenses} permissive`);
    lines.push(`- ${summary.weakCopyleftLicenses} weak copyleft`);
    lines.push(`- ${summary.restrictiveLicenses} restrictive`);
    lines.push(`- ${summary.unknownLicenses} unknown`);
  }

  if (policyViolations.length > 0) {
    lines.push("");
    lines.push("## Policy Compliance");
    for (const dependency of policyViolations) {
      const reason = dependency.policy.denied ? "deny policy violated" : "policy violated";
      lines.push(`- ${dependency.name} ${dependency.version || ""} — ${reason}`.trim());
    }
  }

  if (uncoveredDependencies.length > 0) {
    lines.push("");
    lines.push("## Uncovered Dependencies");
    lines.push("| Package | Version | Ecosystem | Upstream Status | Detail |");
    lines.push("|---------|---------|-----------|-----------------|--------|");
    for (const dependency of uncoveredDependencies) {
      lines.push(`| ${dependency.name} | ${dependency.version || "—"} | ${dependency.format || dependency.ecosystem || "—"} | ${formatUpstreamStatus(dependency.upstreamStatus)} | ${dependency.upstreamDetail || "—"} |`);
    }
  }


  const notApplicableDependencies = reportDependencies.filter((dependency) => (
    dependency.cloudsmithStatus === CLOUDSMITH_COVERAGE_STATUS.NOT_APPLICABLE
  ));
  if (notApplicableDependencies.length > 0) {
    lines.push("");
    lines.push("## Registry Lookup Not Applicable");
    lines.push("| Package | Version | Source Kind | Detail |");
    lines.push("|---------|---------|-------------|--------|");
    for (const dependency of notApplicableDependencies) {
      lines.push(`| ${dependency.name} | ${dependency.version || "—"} | ${dependency.packageSource && dependency.packageSource.kind || "unknown"} | ${dependency.cloudsmithLookupDetail || formatLookupNotApplicableDetail(dependency)} |`);
    }
  }

  return lines.join("\n");
}

function formatUpstreamStatus(status) {
  switch (status) {
    case "reachable":
      return "Reachable";
    case "no_proxy":
      return "No proxy";
    case "unreachable":
      return "Unreachable";
    default:
      return "Unknown";
  }
}

function getDependencyVulnerabilityData(dependency) {
  if (dependency.vulnerabilities) {
    return dependency.vulnerabilities;
  }

  const cloudsmithPackage = dependency.cloudsmithPackage;
  if (!cloudsmithPackage) {
    return null;
  }

  const state = getPackageVulnerabilityState(cloudsmithPackage);
  if (state.count === 0 && !state.detected && !state.unknown) {
    return null;
  }

  return {
    count: state.count !== null ? state.count : (state.candidateCount || 0),
    countKnown: state.count !== null,
    detected: state.detected,
    unknown: state.unknown,
    maxSeverity: cloudsmithPackage.max_severity || null,
  };
}

function hasDetectedVulnerabilities(vulnerabilities) {
  return Boolean(vulnerabilities && (
    vulnerabilities.detected === true
    || (vulnerabilities.countKnown !== false && vulnerabilities.count > 0)
  ));
}

function getDependencyPolicyData(dependency) {
  if (dependency.policy) {
    return dependency.policy;
  }

  const cloudsmithPackage = dependency.cloudsmithPackage;
  if (!cloudsmithPackage) {
    return null;
  }

  const status = String(cloudsmithPackage.status_str || "").trim() || null;
  const quarantined = status === "Quarantined";
  const denied = quarantined || Boolean(cloudsmithPackage.deny_policy_violated);
  const violated = denied
    || Boolean(cloudsmithPackage.policy_violated)
    || Boolean(cloudsmithPackage.license_policy_violated)
    || Boolean(cloudsmithPackage.vulnerability_policy_violated);

  return {
    violated,
    denied,
    quarantined,
    status,
    statusReason: String(cloudsmithPackage.status_reason || "").trim() || null,
  };
}

function getDependencyLicenseClassification(dependency) {
  if (dependency.license && dependency.license.classification) {
    return dependency.license.classification;
  }

  if (!dependency.cloudsmithPackage) {
    return "unknown";
  }

  const inspection = LicenseClassifier.inspect(dependency.cloudsmithPackage);
  switch (inspection.tier) {
    case "permissive":
      return "permissive";
    case "cautious":
      return "weak_copyleft";
    case "restrictive":
      return "restrictive";
    default:
      return "unknown";
  }
}

module.exports = {
  CLOUDSMITH_COVERAGE_STATUS,
  DependencyHealthProvider,
  FILTER_MODES,
  SCAN_STATES,
  SORT_MODES,
  buildComplianceReportData,
  buildDependencyHealthReport,
  buildDependencySummary,
  buildFilteredTreeWrapper,
  buildPackageIndex,
  findCoverageMatch,
  getConcreteDependencyVersion,
  getFilterLabel,
  getLookupPaginationDirective,
  lookupExactDependency,
  matchesFilter,
  matchCoverageCandidates,
  packageNameMatchesDependency,
};

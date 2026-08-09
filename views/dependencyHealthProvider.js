// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const vscode = require("vscode");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const {
  ADAPTER_RESULT_STATUSES,
  createDefaultDependencyAdapterRegistry,
} = require("../util/dependencyAdapterRegistry");
const { PaginatedFetch } = require("../util/paginatedFetch");
const { SearchQueryBuilder } = require("../util/searchQueryBuilder");
const { LicenseClassifier } = require("../util/licenseClassifier");
const {
  canonicalFormat,
  getCloudsmithPackageLookupKeys,
  getPackageLookupKeys,
  normalizePackageName,
} = require("../util/packageNameNormalizer");
const {
  enrichVulnerabilities,
} = require("../util/dependencyVulnEnricher");
const { enrichLicenses } = require("../util/dependencyLicenseEnricher");
const { getFoundDependencyKey } = require("../util/foundDependencyKey");
const { enrichPolicies } = require("../util/dependencyPolicyEnricher");
const {
  analyzeUpstreamGaps,
  getUncoveredDependencyKey,
} = require("../util/upstreamGapAnalyzer");
const {
  PULL_STATUS,
  UpstreamPullService,
  buildPullSummaryMessage,
} = require("../util/upstreamPullService");
const DependencyHealthNode = require("../models/dependencyHealthNode");
const DependencySourceGroupNode = require("../models/dependencySourceGroupNode");
const DependencySummaryNode = require("../models/dependencySummaryNode");
const InfoNode = require("../models/infoNode");

const DEFAULT_MAX_DEPENDENCIES_TO_SCAN = 10000;
const PACKAGE_INDEX_TTL_MS = 10 * 60 * 1000;
const PACKAGE_INDEX_CACHE_MAX_SIZE = 5000;
const PACKAGE_INDEX_PAGE_SIZE = 500;
const PACKAGE_INDEX_FALLBACK_THRESHOLD = 10000;
const FALLBACK_QUERY_PAGE_SIZE = 25;
const FALLBACK_QUERY_CONCURRENCY = 8;
const WORKSPACE_REPOSITORY_PAGE_SIZE = 500;
const COVERAGE_MATCH_BATCH_SIZE = 50;
const ENRICHMENT_PROGRESS_DEBOUNCE_MS = 500;

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
    this.context = context;
    this._diagnosticsPublisher = diagnosticsPublisher || null;
    this._services = {
      enrichVulnerabilities: options.enrichVulnerabilities || enrichVulnerabilities,
      enrichLicenses: options.enrichLicenses || enrichLicenses,
      enrichPolicies: options.enrichPolicies || enrichPolicies,
      analyzeUpstreamGaps: options.analyzeUpstreamGaps || analyzeUpstreamGaps,
      fetchRepositories: options.fetchRepositories || null,
      upstreamPullService: options.upstreamPullService || new UpstreamPullService(context),
    };
    this._dependencyAdapters = options.dependencyAdapters || createDefaultDependencyAdapterRegistry();
    this._reportDateFactory = typeof options.reportDateFactory === "function"
      ? options.reportDateFactory
      : () => new Date();
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
    this._dependencyOperationRunning = false;
    this._scanOperation = createScanOperation(SCAN_STATES.IDLE, 0);
    this._hasSuccessfulScan = false;

    if (this.context && this.context.secrets && typeof this.context.secrets.onDidChange === "function") {
      this.context.secrets.onDidChange((event) => {
        if (event.key === "cloudsmith-vsc.isConnected") {
          this.refresh();
        }
      });
    }

    this._updateContexts();
  }

  _getInitialViewMode() {
    const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
    const configuredDefault = String(config.get("dependencyTreeDefaultView") || "flat");
    const storedView = this.context && this.context.workspaceState
      ? this.context.workspaceState.get("cloudsmith-vsc.dependencyTreeView")
      : null;
    const candidate = String(storedView || configuredDefault || "flat");
    return ["direct", "flat", "tree"].includes(candidate) ? candidate : "flat";
  }

  async _updateContexts() {
    const scanRunning = this.isScanRunning();
    await vscode.commands.executeCommand("setContext", "cloudsmith.depView", this._viewMode);
    await vscode.commands.executeCommand("setContext", "cloudsmith.depViewMode", this._viewMode);
    await vscode.commands.executeCommand("setContext", "cloudsmith.depFilterActive", Boolean(this._filterMode));
    await vscode.commands.executeCommand("setContext", "cloudsmith.depScanComplete", this._hasSuccessfulScan);
    await vscode.commands.executeCommand("setContext", "cloudsmith.depScanSucceeded", this._hasSuccessfulScan);
    await vscode.commands.executeCommand("setContext", "cloudsmith.depScanRunning", scanRunning);
    await vscode.commands.executeCommand(
      "setContext",
      "cloudsmith.depOperationRunning",
      scanRunning || this._dependencyOperationRunning
    );
    await vscode.commands.executeCommand("setContext", "cloudsmith.depRepoSelected", Boolean(this.lastRepo));
  }

  hasSuccessfulScan() {
    return this._hasSuccessfulScan;
  }

  isScanRunning() {
    return this._scanOperation.status === SCAN_STATES.SELECTING
      || this._scanOperation.status === SCAN_STATES.RUNNING;
  }

  getScanState() {
    return {
      ...this._scanOperation,
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

  async setViewMode(mode) {
    if (!VIEW_MODES.includes(mode)) {
      return;
    }

    this._viewMode = mode;
    if (this.context && this.context.workspaceState && typeof this.context.workspaceState.update === "function") {
      await this.context.workspaceState.update("cloudsmith-vsc.dependencyTreeView", mode);
    }
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
    this._reportData = buildComplianceReportData(
      path.basename(this.getProjectFolder() || "workspace"),
      this._fullTrees.flatMap((tree) => tree.dependencies),
      { scanDate: this._lastScanTimestamp }
    );
    await this._updateContexts();
  }

  getProjectFolder() {
    if (this._projectFolderPath) {
      return this._projectFolderPath;
    }
    const folders = vscode.workspace.workspaceFolders;
    return folders && folders[0] ? folders[0].uri.fsPath : null;
  }

  async promptForFolder() {
    const choice = await vscode.window.showQuickPick(
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
      await vscode.commands.executeCommand("vscode.openFolder");
      return null;
    }

    const selected = await vscode.window.showOpenDialog({
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
    for (const folder of vscode.workspace.workspaceFolders || []) {
      foldersByPath.set(folder.uri.fsPath, {
        label: folder.name || path.basename(folder.uri.fsPath),
        description: folder.uri.fsPath,
        folderPath: folder.uri.fsPath,
      });
    }

    if (this._projectFolderPath && !foldersByPath.has(this._projectFolderPath)) {
      foldersByPath.set(this._projectFolderPath, {
        label: path.basename(this._projectFolderPath),
        description: this._projectFolderPath,
        folderPath: this._projectFolderPath,
      });
    }

    const selected = await vscode.window.showQuickPick(
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

    const pickedFolders = await vscode.window.showOpenDialog({
      canSelectFolders: true,
      canSelectFiles: false,
      canSelectMany: false,
      openLabel: "Select project folder",
    });
    return pickedFolders && pickedFolders[0] ? pickedFolders[0].fsPath : null;
  }

  async scan(cloudsmithWorkspace, cloudsmithRepo, projectFolder) {
    if (this._dependencyOperationRunning) {
      vscode.window.showWarningMessage("Wait for the current dependency operation to finish.");
      return { status: "blocked" };
    }

    const operationId = ++this._nextScanOperationId;
    const previousCancellation = this._activeScanCancellation;
    if (previousCancellation) {
      previousCancellation.cancel();
    }

    this._scanOperation = createScanOperation(SCAN_STATES.SELECTING, operationId, {
      startedAt: Date.now(),
      scope: {
        workspace: cloudsmithWorkspace,
        repository: cloudsmithRepo || null,
        projectFolder: projectFolder || null,
      },
    });
    await this._updateContexts();
    this.refresh();

    let folderPath = projectFolder || this.getProjectFolder();
    if (!folderPath) {
      folderPath = await this.promptForFolder();
      if (!this._isCurrentScan(operationId)) {
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
      scope,
    });
    await this._updateContexts();
    this.refresh();

    const cancellationSource = new vscode.CancellationTokenSource();
    this._activeScanCancellation = cancellationSource;
    const scanWorker = this._createScanWorker(scope);

    try {
      const result = await vscode.window.withProgress(
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

      if (!this._isCurrentScan(operationId)) {
        return { status: "superseded" };
      }

      if ((result && result.canceled) || cancellationSource.token.isCancellationRequested) {
        await this._finishCancelledScan(operationId);
        vscode.window.showInformationMessage("Dependency scan canceled.");
        return { status: SCAN_STATES.CANCELLED };
      }

      const preparedDiagnostics = await this._prepareDiagnostics(scanWorker);
      if (!this._isCurrentScan(operationId)) {
        return { status: "superseded" };
      }

      if (cancellationSource.token.isCancellationRequested) {
        await this._finishCancelledScan(operationId);
        vscode.window.showInformationMessage("Dependency scan canceled.");
        return { status: SCAN_STATES.CANCELLED };
      }

      if (this._diagnosticsPublisher) {
        this._diagnosticsPublisher.replace(preparedDiagnostics);
      }
      this._commitSuccessfulScan(scanWorker, scope, operationId);
      await this._updateContexts();
      this.refresh();
      return { status: SCAN_STATES.SUCCEEDED };
    } catch (error) {
      if (!this._isCurrentScan(operationId)) {
        return { status: "superseded" };
      }

      if (cancellationSource.token.isCancellationRequested) {
        await this._finishCancelledScan(operationId);
        vscode.window.showInformationMessage("Dependency scan canceled.");
        return { status: SCAN_STATES.CANCELLED };
      }

      const reason = error && error.message ? error.message : "Check the Cloudsmith connection.";
      const message = this._hasSuccessfulScan
        ? `Dependency refresh failed. Previous scan results are still available. ${reason}`
        : `Dependency scan failed. ${reason}`;
      this._scanOperation = createScanOperation(SCAN_STATES.FAILED, operationId, {
        startedAt: this._scanOperation.startedAt,
        completedAt: Date.now(),
        failureMessage: message,
        scope,
      });
      await this._updateContexts();
      this.refresh();
      if (this._hasSuccessfulScan) {
        vscode.window.showWarningMessage(message);
      } else {
        vscode.window.showErrorMessage(message);
      }
      return { status: SCAN_STATES.FAILED, error };
    } finally {
      cancellationSource.dispose();
      if (this._activeScanCancellation === cancellationSource) {
        this._activeScanCancellation = null;
      }
    }
  }

  _isCurrentScan(operationId) {
    return this._scanOperation.id === operationId;
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
      completedAt: Date.now(),
      scope: currentOperation.scope,
      message: this._hasSuccessfulScan
        ? "Dependency refresh canceled. Previous scan results are shown."
        : "Dependency scan canceled.",
    });
    await this._updateContexts();
    this.refresh();
  }

  _commitSuccessfulScan(scanWorker, scope, operationId) {
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
      completedAt: Date.now(),
      scope,
    });
  }

  async _prepareDiagnostics(scanState) {
    if (!this._diagnosticsPublisher) {
      return [];
    }

    const diagnosticNodes = scanState._fullTrees
      .flatMap((tree) => tree.dependencies)
      .filter((dependency) => dependency.isDirect)
      .map((dependency) => new DependencyHealthNode(dependency, null, this.context));

    return this._diagnosticsPublisher.prepare(scanState._lastManifests, diagnosticNodes);
  }

  _getMaxDependenciesToScan() {
    const configuredValue = Number(vscode.workspace.getConfiguration("cloudsmith-vsc").get("maxDependenciesToScan"));
    if (!Number.isFinite(configuredValue) || configuredValue < 1) {
      return DEFAULT_MAX_DEPENDENCIES_TO_SCAN;
    }
    return Math.floor(configuredValue);
  }

  async _performScan(cloudsmithWorkspace, cloudsmithRepo, folderPath, progress, token) {
    progress.report({ message: "Parsing lockfiles..." });
    this._lastManifests = await this._dependencyAdapters.detectManifests(folderPath);
    if (token.isCancellationRequested) {
      return { canceled: true };
    }

    const resolveTransitives = vscode.workspace.getConfiguration("cloudsmith-vsc").get("resolveTransitiveDependencies") !== false;
    const trees = [];
    const warnings = [];

    if (resolveTransitives) {
      const detections = await this._dependencyAdapters.detect(folderPath);
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
        });
        if (result.status === ADAPTER_RESULT_STATUSES.ERROR) {
          warnings.push(result.error && result.error.message
            ? result.error.message
            : "A dependency adapter failed.");
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
            warnings: result.warnings,
          });
          if (result.warnings.length > 0) {
            warnings.push(...result.warnings);
          }
        }
      }
    }

    if (trees.length === 0) {
      const fallbackTrees = await this._buildManifestFallbackTrees(this._lastManifests);
      if (token.isCancellationRequested) {
        return { canceled: true };
      }
      trees.push(...fallbackTrees);
    }

    if (trees.length === 0) {
      this._displayTrees = [];
      this._fullTrees = [];
      this._summary = emptySummary();
      this._statusMessage = null;
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
      this._displayTrees = [];
      this._fullTrees = [];
      this._summary = emptySummary();
      this._statusMessage = null;
      await this._storeReportData(this._reportDateFactory());
      return { canceled: false };
    }

    this._noManifestsFolder = null;
    this._fullTrees = markTreesAsChecking(normalizedTrees);

    const limited = limitDisplayTrees(this._fullTrees, this._getMaxDependenciesToScan());
    this._displayTrees = limited.trees;
    this._warnings = warnings.slice();
    if (limited.truncated) {
      const warning = `Dependency display is capped at ${this._getMaxDependenciesToScan()} items `
        + `out of ${limited.totalDependencies} resolved dependencies.`;
      this._warnings.push(warning);
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

    await this._publishDiagnostics();
    this._rebuildSummary();
    await this._storeReportData(this._reportDateFactory());
    return { canceled: false };
  }

  async _buildManifestFallbackTrees(manifests) {
    const trees = [];
    for (const manifest of manifests) {
      const result = await this._dependencyAdapters.parseManifest(manifest);
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
    const packageIndexFailureVerb = options.packageIndexFailureVerb || "fetch";

    if (formats.length === 0 || totalDependencies === 0) {
      return 0;
    }

    const indexEntries = await Promise.all(
      formats.map(async (format) => ({
        format,
        dependencies: uniqueDependenciesForCoverage(dependenciesByFormat[format]),
        packageIndex: await this._fetchPackageIndex(cloudsmithWorkspace, cloudsmithRepo, format),
      }))
    );

    let completed = 0;
    for (const { format, dependencies, packageIndex } of indexEntries) {
      if (token.isCancellationRequested) {
        return completed;
      }

      if (packageIndex.error) {
        this._warnings.push(`Could not ${packageIndexFailureVerb} the ${format} package index. ${packageIndex.error}`);
      }

      if (packageIndex.tooLarge || packageIndex.error) {
        completed = await this._resolveCoverageWithFallbackQueries(
          cloudsmithWorkspace,
          cloudsmithRepo,
          format,
          dependencies,
          completed,
          totalDependencies,
          progress,
          token,
          progressLabel
        );
        continue;
      }

      completed = await this._matchCoverageBatch(
        dependencies,
        packageIndex.index,
        completed,
        totalDependencies,
        progress,
        token,
        progressLabel
      );
    }

    return completed;
  }

  async _matchCoverageBatch(dependencies, packageIndex, completed, totalDependencies, progress, token, progressLabel) {
    const pendingMatches = [];

    for (let index = 0; index < dependencies.length; index += 1) {
      if (token.isCancellationRequested) {
        return completed;
      }

      const dependency = dependencies[index];
      pendingMatches.push({
        dependency,
        match: findCoverageMatch(packageIndex, dependency),
      });

      if (pendingMatches.length < COVERAGE_MATCH_BATCH_SIZE && index < dependencies.length - 1) {
        continue;
      }

      completed = await this._flushCoverageMatchBatch(
        pendingMatches,
        completed,
        totalDependencies,
        progress,
        progressLabel
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
    await yieldToEventLoop();

    return completed;
  }

  _applyCoverageMatchBatch(matches) {
    if (!Array.isArray(matches) || matches.length === 0) {
      return;
    }

    const matchMap = new Map();
    for (const { dependency, match } of matches) {
      matchMap.set(coverageLookupKey(dependency), {
        cloudsmithStatus: match ? "FOUND" : "NOT_FOUND",
        cloudsmithPackage: match || null,
        ...(match ? { upstreamStatus: null, upstreamDetail: null } : {}),
      });
    }

    this._fullTrees = applyCoverageMatchBatchToTrees(this._fullTrees, matchMap);
    this._displayTrees = applyCoverageMatchBatchToTrees(this._displayTrees, matchMap);
  }

  _createDebouncedEnrichmentHandler(patchApplier) {
    let pendingPatchMaps = [];
    let flushTimeout = null;

    const flush = () => {
      if (flushTimeout) {
        clearTimeout(flushTimeout);
        flushTimeout = null;
      }

      if (pendingPatchMaps.length === 0) {
        return;
      }

      const mergedPatchMap = mergePatchMaps(pendingPatchMaps);
      pendingPatchMaps = [];

      patchApplier(mergedPatchMap);
      this._rebuildSummary();
      this.refresh();
    };

    return {
      onProgress: (patchMap) => {
        if (!(patchMap instanceof Map) || patchMap.size === 0) {
          return;
        }

        pendingPatchMaps.push(patchMap);
        if (!flushTimeout) {
          flushTimeout = setTimeout(() => {
            flushTimeout = null;
            flush();
          }, ENRICHMENT_PROGRESS_DEBOUNCE_MS);
        }
      },
      flush,
    };
  }

  async _resolveCoverageWithFallbackQueries(
    cloudsmithWorkspace,
    cloudsmithRepo,
    format,
    dependencies,
    completed,
    totalDependencies,
    progress,
    token,
    progressLabel = "Matching coverage"
  ) {
    const api = new CloudsmithAPI(this.context);
    const endpoint = cloudsmithRepo
      ? `packages/${cloudsmithWorkspace}/${cloudsmithRepo}/`
      : `packages/${cloudsmithWorkspace}/`;
    const uniqueDependencies = dependencies.slice();

    for (let index = 0; index < uniqueDependencies.length; index += COVERAGE_MATCH_BATCH_SIZE) {
      if (token.isCancellationRequested) {
        return completed;
      }

      const dependencyBatch = uniqueDependencies.slice(index, index + COVERAGE_MATCH_BATCH_SIZE);
      const pendingMatches = [];

      await runPromisePool(dependencyBatch, FALLBACK_QUERY_CONCURRENCY, async (dependency) => {
        if (token.isCancellationRequested) {
          return;
        }

        let match = null;
        for (const lookupName of getPackageLookupKeys(dependency.name, dependency.format)) {
          const query = new SearchQueryBuilder()
            .format(dependency.format)
            .name(lookupName)
            .build();
          const result = await api.get(`${endpoint}?query=${encodeURIComponent(query)}&page_size=${FALLBACK_QUERY_PAGE_SIZE}`);
          if (typeof result === "string") {
            this._warnings.push(`Coverage lookup failed for ${dependency.name}. ${result}`);
            continue;
          }
          if (Array.isArray(result) && result.length > 0) {
            match = matchCoverageCandidates(result, dependency);
            if (match) {
              break;
            }
          }
        }

        pendingMatches.push({ dependency, match });
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

    return completed;
  }

  async _fetchPackageIndex(cloudsmithWorkspace, cloudsmithRepo, format) {
    const cacheKey = `${String(cloudsmithWorkspace || "").toLowerCase()}:${String(cloudsmithRepo || "<all>").toLowerCase()}:${format}`;
    const cachedValue = getCachedPackageIndexValue(cacheKey);
    if (cachedValue) {
      return cachedValue;
    }

    const firstPage = await this._fetchSinglePage(
      cloudsmithWorkspace,
      cloudsmithRepo,
      format,
      1,
      PACKAGE_INDEX_PAGE_SIZE
    );
    if (firstPage.error) {
      const value = { error: firstPage.error, tooLarge: false, index: new Map() };
      setCachedPackageIndexValue(cacheKey, value);
      return value;
    }

    const totalCount = firstPage.pagination.count || firstPage.data.length;
    if (totalCount > PACKAGE_INDEX_FALLBACK_THRESHOLD) {
      const value = { error: null, tooLarge: true, index: new Map(), totalCount };
      setCachedPackageIndexValue(cacheKey, value);
      return value;
    }

    const packages = [...firstPage.data];
    const pageTotal = firstPage.pagination && firstPage.pagination.pageTotal
      ? firstPage.pagination.pageTotal
      : Math.ceil(totalCount / PACKAGE_INDEX_PAGE_SIZE) || 1;

    if (pageTotal > 1) {
      const remainingPages = await Promise.all(
        Array.from({ length: pageTotal - 1 }, (_, index) => this._fetchSinglePage(
          cloudsmithWorkspace,
          cloudsmithRepo,
          format,
          index + 2,
          PACKAGE_INDEX_PAGE_SIZE
        ))
      );

      for (const nextPage of remainingPages) {
        if (nextPage.error) {
          const value = { error: nextPage.error, tooLarge: false, index: new Map() };
          setCachedPackageIndexValue(cacheKey, value);
          return value;
        }
        packages.push(...nextPage.data);
      }
    }

    const value = {
      error: null,
      tooLarge: false,
      index: buildPackageIndex(packages, format),
      totalCount,
    };
    setCachedPackageIndexValue(cacheKey, value);
    return value;
  }

  async _fetchSinglePage(cloudsmithWorkspace, cloudsmithRepo, format, page, pageSize) {
    const api = new CloudsmithAPI(this.context);
    const paginatedFetch = new PaginatedFetch(api);
    const endpoint = cloudsmithRepo
      ? `packages/${cloudsmithWorkspace}/${cloudsmithRepo}/`
      : `packages/${cloudsmithWorkspace}/`;

    return paginatedFetch.fetchPage(endpoint, page, pageSize, `format:${format}`);
  }

  async _runEnrichmentPasses(cloudsmithWorkspace, cloudsmithRepo, progress, token) {
    const dependencies = this._fullTrees.flatMap((tree) => tree.dependencies);
    const tasks = [
      this._runVulnerabilityEnrichment(dependencies, cloudsmithWorkspace, progress, token),
      this._runLicenseEnrichment(dependencies, token),
      this._runPolicyEnrichment(dependencies, token),
    ];

    const uncoveredDependencies = dependencies.filter((dependency) => dependency.cloudsmithStatus === "NOT_FOUND");
    if (uncoveredDependencies.length > 0) {
      tasks.push(this._runUpstreamGapAnalysis(uncoveredDependencies, cloudsmithWorkspace, cloudsmithRepo, progress, token));
    }

    const results = await Promise.allSettled(tasks);
    for (const result of results) {
      if (result.status !== "rejected") {
        continue;
      }

      const message = result.reason && result.reason.message
        ? result.reason.message
        : String(result.reason || "An enrichment step failed.");
      this._warnings.push(message);
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
    }
  }

  async _runUpstreamGapAnalysis(uncoveredDependencies, workspace, repo, progress, token) {
    const repositories = repo
      ? [repo]
      : await (this._services.fetchRepositories
        ? this._services.fetchRepositories(workspace, token)
        : this._fetchWorkspaceRepositories(workspace, token));

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
      await this._services.analyzeUpstreamGaps(uncoveredDependencies, workspace, repositories, {
        context: this.context,
        cancellationToken: token,
        onProgress: (patchMap, meta = {}) => {
          if (meta.total > 0) {
            progress.report({
              message: `Checking upstream coverage... ${meta.completed}/${meta.total}`,
            });
          }
          handler.onProgress(patchMap);
        },
      });
    } finally {
      handler.flush();
    }
  }

  async _fetchWorkspaceRepositories(workspace, token) {
    const api = new CloudsmithAPI(this.context);
    const paginatedFetch = new PaginatedFetch(api);
    const endpoint = `repos/${workspace}/?sort=name`;
    const repositories = [];
    let page = 1;

    while (!token || !token.isCancellationRequested) {
      const result = await paginatedFetch.fetchPage(endpoint, page, WORKSPACE_REPOSITORY_PAGE_SIZE);
      if (result.error) {
        this._warnings.push(`Could not load repositories for upstream analysis. ${result.error}`);
        break;
      }

      for (const repository of Array.isArray(result.data) ? result.data : []) {
        if (repository && repository.slug) {
          repositories.push(repository.slug);
        }
      }

      const pageTotal = result.pagination && result.pagination.pageTotal
        ? result.pagination.pageTotal
        : 1;
      if (page >= pageTotal) {
        break;
      }
      page += 1;
    }

    return [...new Set(repositories)];
  }

  async _publishDiagnostics() {
    if (!this._diagnosticsPublisher) {
      return;
    }

    const diagnosticNodes = this._fullTrees
      .flatMap((tree) => tree.dependencies)
      .filter((dependency) => dependency.isDirect)
      .map((dependency) => new DependencyHealthNode(dependency, null, this.context));

    await this._diagnosticsPublisher.publish(this._lastManifests, diagnosticNodes);
  }

  buildDependencyNodesForTree(tree) {
    if (this._viewMode === "tree") {
      return this._buildTreeModeNodes(tree);
    }

    return this._buildListModeNodes(tree);
  }

  _buildListModeNodes(tree) {
    const visibleDependencies = this._viewMode === "direct"
      ? tree.dependencies.filter((dependency) => dependency.isDirect)
      : tree.dependencies.slice();

    return visibleDependencies
      .filter((dependency) => matchesFilter(dependency, this._filterMode))
      .sort((left, right) => compareDependencies(left, right, this._sortMode, true))
      .map((dependency) => new DependencyHealthNode(
        dependency,
        null,
        this.context,
        { childMode: "details" }
      ));
  }

  _buildTreeModeNodes(tree) {
    const roots = getTreeRootDependencies(tree)
      .sort((left, right) => compareDependencies(left, right, this._sortMode, false));

    const filteredRoots = roots
      .map((dependency) => buildFilteredTreeWrapper(dependency, this._filterMode, this._sortMode))
      .filter(Boolean);

    const duplicateAwareRoots = annotateDuplicateWrappers(filteredRoots, new Map(), []);
    return duplicateAwareRoots.map((wrapper) => this._createTreeDependencyNode(wrapper));
  }

  _createTreeDependencyNode(wrapper) {
    return new DependencyHealthNode(
      wrapper.dependency,
      null,
      this.context,
      {
        childMode: "tree",
        treeChildren: wrapper.children,
        duplicateReference: wrapper.duplicate,
        firstOccurrencePath: wrapper.firstOccurrencePath,
        dimmedForFilter: wrapper.dimmedForFilter,
        treeChildFactory: (children) => children.map((child) => this._createTreeDependencyNode(child)),
      }
    );
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
    if (this.isScanRunning() || this._dependencyOperationRunning) {
      vscode.window.showWarningMessage("Wait for the current dependency operation to finish.");
      return;
    }

    if (!this.lastWorkspace) {
      vscode.window.showInformationMessage("Run a dependency scan before pulling dependencies.");
      return;
    }

    const dependencies = this._fullTrees.flatMap((tree) => tree.dependencies);
    if (dependencies.length === 0) {
      vscode.window.showInformationMessage("Run a dependency scan before pulling dependencies.");
      return;
    }

    const cancellationSource = new vscode.CancellationTokenSource();
    this._dependencyOperationRunning = true;
    await this._updateContexts();

    try {
      const result = await vscode.window.withProgress(
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
            });

            if (!execution || execution.canceled) {
              return execution || { canceled: true };
            }

            this.lastRepo = execution.repository.slug;
            await this._updateContexts();

            progress.report({ message: "Refreshing Cloudsmith coverage..." });
            await this._refreshCoverageAfterPull(
              execution.workspace,
              execution.repository.slug,
              progress,
              cancellationSource.token
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

      if (result.canceled) {
        vscode.window.showInformationMessage("Dependency pull canceled.");
        return;
      }

      if (result.pullResult) {
        vscode.window.showInformationMessage(
          buildPullSummaryMessage(result.pullResult, result.plan.skippedDependencies.length)
        );
      }
    } finally {
      cancellationSource.dispose();
      this._dependencyOperationRunning = false;
      await this._updateContexts();
      this.refresh();
    }
  }

  async pullSingleDependency(item) {
    if (this.isScanRunning() || this._dependencyOperationRunning) {
      vscode.window.showWarningMessage("Wait for the current dependency operation to finish.");
      return;
    }

    if (!this.lastWorkspace) {
      vscode.window.showInformationMessage("Run a dependency scan before pulling dependencies.");
      return;
    }

    const dependency = createSingleDependencyPullTarget(item);
    if (!dependency) {
      vscode.window.showWarningMessage("Could not determine the dependency details.");
      return;
    }

    const prepared = await this._services.upstreamPullService.prepareSingle({
      workspace: this.lastWorkspace,
      repositoryHint: this.lastRepo,
      dependency,
    });
    if (!prepared) {
      return;
    }

    const cancellationSource = new vscode.CancellationTokenSource();
    this._dependencyOperationRunning = true;
    await this._updateContexts();

    try {
      const result = await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: `Pulling ${formatSingleDependencyLabel(prepared.dependency)} through ${prepared.repository.slug}...`,
          cancellable: true,
        },
        async (progress, token) => {
          const subscription = token.onCancellationRequested(() => cancellationSource.cancel());
          try {
            progress.report({ message: "Triggering upstream pull..." });
            const execution = await this._services.upstreamPullService.execute(prepared, {
              progress,
              token: cancellationSource.token,
            });

            if (!execution || execution.canceled) {
              return execution || { canceled: true };
            }

            this.lastRepo = prepared.repository.slug;
            await this._updateContexts();

            const pullDetail = getSingleDependencyPullDetail(execution.pullResult);
            if (isSuccessfulSingleDependencyPull(pullDetail)) {
              progress.report({ message: "Refreshing Cloudsmith coverage..." });
              await this._refreshSingleDependencyAfterPull(
                prepared.workspace,
                prepared.repository.slug,
                prepared.dependency,
                progress,
                cancellationSource.token
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

      if (result.canceled) {
        vscode.window.showInformationMessage("Dependency pull canceled.");
        return;
      }

      const notification = buildSingleDependencyPullNotification(
        prepared.dependency,
        prepared.repository.slug,
        getSingleDependencyPullDetail(result.pullResult)
      );
      if (notification.level === "error") {
        vscode.window.showErrorMessage(notification.message);
      } else {
        vscode.window.showInformationMessage(notification.message);
      }
    } finally {
      cancellationSource.dispose();
      this._dependencyOperationRunning = false;
      await this._updateContexts();
      this.refresh();
    }
  }

  async _refreshCoverageAfterPull(cloudsmithWorkspace, cloudsmithRepo, progress, token) {
    clearPackageIndexCache(cloudsmithWorkspace, cloudsmithRepo);
    await this._refreshCoverageForDependencies(
      cloudsmithWorkspace,
      cloudsmithRepo,
      null,
      progress,
      token,
      { refreshRemainingUpstream: true }
    );
  }

  async _refreshSingleDependencyAfterPull(cloudsmithWorkspace, cloudsmithRepo, dependency, progress, token) {
    clearPackageIndexCache(cloudsmithWorkspace, cloudsmithRepo, dependency.format || dependency.ecosystem);
    await this._refreshCoverageForDependencies(
      cloudsmithWorkspace,
      cloudsmithRepo,
      [dependency],
      progress,
      token
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
          dependency.cloudsmithStatus !== "FOUND"
          && (targetKeys.size === 0 || targetKeys.has(coverageLookupKey(dependency)))
        ))
    );
    const totalDependencies = unresolvedDependencies.length;

    if (totalDependencies === 0) {
      await this._publishDiagnostics();
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
      await Promise.all([
        this._runVulnerabilityEnrichment(newlyFoundDependencies, cloudsmithWorkspace, progress, token),
        this._runLicenseEnrichment(newlyFoundDependencies, token),
        this._runPolicyEnrichment(newlyFoundDependencies, token),
      ]);
    }

    if (options.refreshRemainingUpstream) {
      const remainingUncovered = this._fullTrees
        .flatMap((tree) => tree.dependencies)
        .filter((dependency) => dependency.cloudsmithStatus === "NOT_FOUND");
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

    await this._publishDiagnostics();
    this._rebuildSummary();
    await this._storeReportData(this._reportDateFactory());
    this.refresh();

    return newlyFoundDependencies;
  }

  async rescan(initialScan) {
    const scope = this.getLastSuccessfulScope();
    if (!scope) {
      return typeof initialScan === "function"
        ? initialScan()
        : { status: "needs-initial-scan" };
    }
    return this.scan(scope.workspace, scope.repository, scope.projectFolder);
  }

  getTreeItem(element) {
    return element.getTreeItem();
  }

  async getChildren(element) {
    if (element) {
      return element.getChildren();
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
      nodes.push(...this._displayTrees.map((tree) => new DependencySourceGroupNode(tree, this)));
      return nodes;
    }

    if (!this._hasSuccessfulScan && this._scanOperation.status === SCAN_STATES.IDLE) {
      const isConnected = this.context && this.context.secrets
        ? await this.context.secrets.get("cloudsmith-vsc.isConnected")
        : "false";
      if (isConnected !== "true") {
        return [
          new InfoNode(
            "Connect to Cloudsmith",
            "Use the key icon above to set up authentication.",
            "Set up Cloudsmith authentication to get started.",
            "plug",
            undefined,
            { command: "cloudsmith-vsc.configureCredentials", title: "Set up authentication" }
          ),
        ];
      }

      return [
        new InfoNode(
          "Scan dependencies",
          "Select the play button above to start.",
          "Scans lockfiles and manifests, resolves direct and transitive dependencies, and checks each one against Cloudsmith.",
          "folder",
          "dependencyHealthWelcome"
        ),
      ];
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
    this._onDidChangeTreeData.fire();
  }

  _rebuildSummary() {
    this._summary = buildDependencySummary(this._fullTrees, this._displayTrees, {
      filterMode: this._filterMode,
    });
    this.dependencies = this._displayTrees.flatMap((tree) => tree.dependencies);
  }
}

function createScanOperation(status, id, values = {}) {
  return {
    status,
    id,
    startedAt: values.startedAt || null,
    completedAt: values.completedAt || null,
    scope: values.scope || null,
    message: values.message || null,
    failureMessage: values.failureMessage || null,
  };
}

DependencyHealthProvider.packageIndexCache = new Map();

function pruneExpiredPackageIndexCache(now = Date.now()) {
  for (const [cacheKey, cacheEntry] of DependencyHealthProvider.packageIndexCache.entries()) {
    if (!cacheEntry || cacheEntry.expiresAt <= now) {
      DependencyHealthProvider.packageIndexCache.delete(cacheKey);
    }
  }
}

function getCachedPackageIndexValue(cacheKey) {
  const cached = DependencyHealthProvider.packageIndexCache.get(cacheKey);
  if (!cached) {
    return null;
  }

  if (cached.expiresAt > Date.now()) {
    return cached.value;
  }

  DependencyHealthProvider.packageIndexCache.delete(cacheKey);
  return null;
}

function setCachedPackageIndexValue(cacheKey, value) {
  if (DependencyHealthProvider.packageIndexCache.size >= PACKAGE_INDEX_CACHE_MAX_SIZE) {
    pruneExpiredPackageIndexCache();
  }

  DependencyHealthProvider.packageIndexCache.set(cacheKey, {
    expiresAt: Date.now() + PACKAGE_INDEX_TTL_MS,
    value,
  });
}

function normalizeTree(tree) {
  return {
    ...tree,
    ecosystem: tree.ecosystem,
    sourceFile: tree.sourceFile,
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
  return [
    dependency.sourceFile || "",
    dependency.format || "",
    dependency.name || "",
    dependency.version || "",
    dependency.isDirect ? "direct" : "transitive",
    (dependency.parentChain || []).join(">"),
  ].join(":").toLowerCase();
}

function coverageLookupKey(dependency) {
  return [
    canonicalFormat(dependency.format || dependency.ecosystem),
    normalizePackageName(dependency.name, dependency.format || dependency.ecosystem),
    String(dependency.version || "").toLowerCase(),
  ].join(":");
}

function groupDependenciesByFormat(trees) {
  const byFormat = {};
  for (const tree of trees) {
    for (const dependency of tree.dependencies) {
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

function clearPackageIndexCache(workspace, repo, format) {
  const workspaceKey = String(workspace || "").toLowerCase();
  const repoKey = String(repo || "<all>").toLowerCase();
  const formatKey = format ? String(canonicalFormat(format) || format).toLowerCase() : null;

  for (const cacheKey of DependencyHealthProvider.packageIndexCache.keys()) {
    if (!cacheKey.startsWith(`${workspaceKey}:${repoKey}:`)) {
      continue;
    }

    if (formatKey && !cacheKey.endsWith(`:${formatKey}`)) {
      continue;
    }

    DependencyHealthProvider.packageIndexCache.delete(cacheKey);
  }
}

function buildPackageIndex(packages, format) {
  const index = new Map();
  for (const pkg of packages) {
    const versionKey = String(pkg.version || "").toLowerCase();
    for (const nameKey of getCloudsmithPackageLookupKeys(pkg, format)) {
      if (!index.has(nameKey)) {
        index.set(nameKey, new Map());
      }
      const versionMap = index.get(nameKey);
      if (!versionMap.has(versionKey)) {
        versionMap.set(versionKey, []);
      }
      versionMap.get(versionKey).push(pkg);
    }
  }
  return index;
}

function findCoverageMatch(packageIndex, dependency) {
  for (const lookupKey of getPackageLookupKeys(dependency.name, dependency.format)) {
    const versions = packageIndex.get(lookupKey);
    if (!versions) {
      continue;
    }
    const versionKey = String(dependency.version || "").toLowerCase();
    if (versionKey && versions.has(versionKey)) {
      return versions.get(versionKey)[0] || null;
    }
    const firstMatch = [...versions.values()][0];
    if (firstMatch && firstMatch[0]) {
      return firstMatch[0];
    }
  }
  return null;
}

function matchCoverageCandidates(candidates, dependency) {
  const dependencyKeys = getPackageLookupKeys(dependency.name, dependency.format);
  let nameMatch = null;

  for (const candidate of candidates) {
    const candidateKeys = new Set(getCloudsmithPackageLookupKeys(candidate, dependency.format));
    const nameMatches = dependencyKeys.some((key) => candidateKeys.has(key));
    if (!nameMatches) {
      continue;
    }
    if (!dependency.version || candidate.version === dependency.version) {
      return candidate;
    }
    if (!nameMatch) {
      nameMatch = candidate;
    }
  }
  return nameMatch;
}

function applyCoverageMatchBatchToTrees(trees, matchMap) {
  return applyPatchMapToTrees(trees, coverageLookupKey, matchMap, (dependency, patch) => ({
    ...dependency,
    cloudsmithStatus: patch.cloudsmithStatus,
    cloudsmithPackage: patch.cloudsmithPackage,
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
        cloudsmithStatus: "CHECKING",
        cloudsmithPackage: null,
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
    .map((tree) => ({
      ...tree,
      dependencies: tree.dependencies
        .filter((dependency) => allowedKeys.has(displayDependencyKey(dependency)))
        .map((dependency) => pruneDependencyTree(dependency, allowedKeys))
        .sort((left, right) => compareDependencies(left, right, SORT_MODES.ALPHABETICAL, true)),
    }))
    .filter((tree) => tree.dependencies.length > 0);

  return {
    trees: limitedTrees,
    truncated: true,
    totalDependencies: allDependencies.length,
  };
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
  if (dependency.cloudsmithStatus === "NOT_FOUND") {
    return 0;
  }
  if (dependency.cloudsmithStatus === "CHECKING") {
    return 2;
  }
  return 1;
}

function dependencySeveritySortGroup(dependency) {
  if (dependency.cloudsmithStatus !== "FOUND") {
    return dependency.cloudsmithStatus === "NOT_FOUND" ? 5 : 6;
  }

  const policy = getDependencyPolicyData(dependency);
  const vulnerabilities = getDependencyVulnerabilityData(dependency);
  const licenseClassification = getDependencyLicenseClassification(dependency);

  if (policy && (policy.quarantined || policy.denied)) {
    return 0;
  }

  if (vulnerabilities && vulnerabilities.count > 0) {
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
  const name = String(dependency.name || "").trim().toLowerCase();
  const version = String(dependency.version || "").trim().toLowerCase();
  if (!name) {
    return null;
  }
  return `${name}:${version}`;
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
      return Boolean(vulnerabilities && vulnerabilities.count > 0);
    case FILTER_MODES.UNCOVERED:
      return dependency.cloudsmithStatus === "NOT_FOUND";
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

function buildDependencySummary(fullTrees, displayTrees, options = {}) {
  const fullDependencies = fullTrees.flatMap((tree) => tree.dependencies);
  const displayDependencies = displayTrees.flatMap((tree) => tree.dependencies);
  const summaryDependencies = fullDependencies.length > 0 ? fullDependencies : displayDependencies;
  const direct = fullDependencies.filter((dependency) => dependency.isDirect).length;
  const ecosystems = {};

  for (const tree of fullTrees) {
    ecosystems[tree.ecosystem] = (ecosystems[tree.ecosystem] || 0) + tree.dependencies.length;
  }

  const found = summaryDependencies.filter((dependency) => dependency.cloudsmithStatus === "FOUND").length;
  const notFound = summaryDependencies.filter((dependency) => dependency.cloudsmithStatus === "NOT_FOUND").length;
  const checking = summaryDependencies.filter((dependency) => dependency.cloudsmithStatus === "CHECKING").length;
  const reachableViaUpstream = summaryDependencies.filter((dependency) => (
    dependency.cloudsmithStatus === "NOT_FOUND" && dependency.upstreamStatus === "reachable"
  )).length;
  const unreachableViaUpstream = summaryDependencies.filter((dependency) => (
    dependency.cloudsmithStatus === "NOT_FOUND"
    && (dependency.upstreamStatus === "no_proxy" || dependency.upstreamStatus === "unreachable")
  )).length;
  const vulnerable = summaryDependencies.filter((dependency) => {
    const vulnerabilities = getDependencyVulnerabilityData(dependency);
    return dependency.cloudsmithStatus === "FOUND" && vulnerabilities && vulnerabilities.count > 0;
  }).length;
  const severityCounts = {};
  for (const dependency of summaryDependencies) {
    const vulnerabilities = getDependencyVulnerabilityData(dependency);
    if (dependency.cloudsmithStatus === "FOUND" && vulnerabilities && vulnerabilities.count > 0 && vulnerabilities.maxSeverity) {
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
    direct,
    transitive: fullDependencies.length - direct,
    found,
    notFound,
    reachableViaUpstream,
    unreachableViaUpstream,
    ecosystems,
    coveragePercent: summaryDependencies.length === 0
      ? 0
      : Math.round((found / summaryDependencies.length) * 100),
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
    direct: 0,
    transitive: 0,
    found: 0,
    notFound: 0,
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

  await Promise.all(workers);
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

function createSingleDependencyPullTarget(item) {
  if (!item || typeof item !== "object") {
    return null;
  }

  const name = String(item.name || "").trim();
  const format = canonicalFormat(item.format || item.ecosystem);
  if (!name || !format) {
    return null;
  }

  const versionValue = typeof item.declaredVersion === "string"
    ? item.declaredVersion
    : (typeof item.version === "string" ? item.version : "");

  return {
    ...item,
    name,
    version: versionValue || "",
    format,
    ecosystem: item.ecosystem || format,
  };
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
        message: "Authentication failed. Check your API key in Cloudsmith settings.",
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

function buildComplianceReportData(projectName, dependencies, options = {}) {
  const uniqueDependencies = dedupeComplianceDependencies(dependencies);
  const ecosystemBreakdown = {};

  for (const dependency of uniqueDependencies) {
    const ecosystem = String(dependency.format || dependency.ecosystem || "unknown").toLowerCase();
    ecosystemBreakdown[ecosystem] = (ecosystemBreakdown[ecosystem] || 0) + 1;
  }

  const vulnerableDeps = uniqueDependencies
    .filter((dependency) => dependency.cloudsmithStatus === "FOUND")
    .map((dependency) => {
      const vulnerabilities = getDependencyVulnerabilityData(dependency);
      if (!vulnerabilities || vulnerabilities.count <= 0) {
        return null;
      }

      const fixEntry = Array.isArray(vulnerabilities.entries)
        ? vulnerabilities.entries.find((entry) => entry && entry.fixVersion)
        : null;

      return {
        name: dependency.name,
        version: dependency.version || "",
        isDirect: Boolean(dependency.isDirect),
        maxSeverity: vulnerabilities.maxSeverity || null,
        cveCount: vulnerabilities.count || 0,
        hasFixAvailable: Boolean(fixEntry || vulnerabilities.hasFixAvailable),
      };
    })
    .filter(Boolean)
    .sort(compareComplianceVulnerabilityRows);

  const severityCounts = {};
  for (const dependency of vulnerableDeps) {
    const severity = dependency.maxSeverity || "Unknown";
    severityCounts[severity] = (severityCounts[severity] || 0) + 1;
  }

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
        name: dependency.name,
        version: dependency.version || "",
        status: humanizePolicyStatus(policy),
        detail: policy.statusReason || defaultPolicyDetail(policy),
      };
    })
    .filter(Boolean)
    .sort(compareCompliancePolicyRows);

  const uncoveredDeps = uniqueDependencies
    .filter((dependency) => dependency.cloudsmithStatus === "NOT_FOUND")
    .map((dependency) => ({
      name: dependency.name,
      version: dependency.version || "",
      ecosystem: dependency.format || dependency.ecosystem || "",
      upstreamStatus: dependency.upstreamStatus || "unknown",
      upstreamDetail: dependency.upstreamDetail || defaultUpstreamDetail(dependency.upstreamStatus),
    }))
    .sort(compareComplianceUncoveredRows);

  const total = uniqueDependencies.length;
  const direct = uniqueDependencies.filter((dependency) => dependency.isDirect).length;
  const found = uniqueDependencies.filter((dependency) => dependency.cloudsmithStatus === "FOUND").length;
  const notFound = uniqueDependencies.filter((dependency) => dependency.cloudsmithStatus === "NOT_FOUND").length;
  const upstreamReachable = uncoveredDeps.filter((dependency) => dependency.upstreamStatus === "reachable").length;
  const upstreamNoProxy = uncoveredDeps.filter((dependency) => dependency.upstreamStatus === "no_proxy").length;
  const upstreamUnreachable = uncoveredDeps.filter((dependency) => dependency.upstreamStatus === "unreachable").length;

  return {
    projectName: projectName || "workspace",
    scanDate: normalizeReportTimestamp(options.scanDate),
    summary: {
      total,
      direct,
      transitive: Math.max(total - direct, 0),
      found,
      notFound,
      coveragePct: total === 0 ? 0 : Math.round((found / total) * 100),
      vulnCount: vulnerableDeps.length,
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
  };
}

function dedupeComplianceDependencies(dependencies) {
  const uniqueDependencies = new Map();

  for (const dependency of Array.isArray(dependencies) ? dependencies : []) {
    const key = complianceDependencyKey(dependency);
    if (!uniqueDependencies.has(key)) {
      uniqueDependencies.set(key, { ...dependency });
      continue;
    }

    uniqueDependencies.set(key, mergeComplianceDependency(uniqueDependencies.get(key), dependency));
  }

  return [...uniqueDependencies.values()];
}

function complianceDependencyKey(dependency) {
  return [
    String(dependency.format || dependency.ecosystem || "").toLowerCase(),
    String(dependency.name || "").toLowerCase(),
    String(dependency.version || "").toLowerCase(),
  ].join(":");
}

function mergeComplianceDependency(existing, candidate) {
  return {
    ...existing,
    isDirect: Boolean(existing.isDirect || candidate.isDirect),
    cloudsmithStatus: pickBetterCoverageStatus(existing.cloudsmithStatus, candidate.cloudsmithStatus),
    cloudsmithPackage: existing.cloudsmithPackage || candidate.cloudsmithPackage || null,
    vulnerabilities: pickRicherVulnerabilityData(existing.vulnerabilities, candidate.vulnerabilities),
    license: existing.license || candidate.license || null,
    policy: pickRicherPolicyData(existing.policy, candidate.policy),
    upstreamStatus: existing.upstreamStatus || candidate.upstreamStatus || null,
    upstreamDetail: existing.upstreamDetail || candidate.upstreamDetail || null,
  };
}

function pickBetterCoverageStatus(left, right) {
  const priorities = {
    FOUND: 3,
    NOT_FOUND: 2,
    CHECKING: 1,
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
  switch (severity) {
    case "Critical":
      return 0;
    case "High":
      return 1;
    case "Medium":
      return 2;
    case "Low":
      return 3;
    default:
      return 4;
  }
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
  const vulnerableDependencies = dependencies
    .filter((dependency) => dependency.vulnerabilities && dependency.vulnerabilities.count > 0)
    .sort((left, right) => compareDependencies(left, right, SORT_MODES.SEVERITY, false));
  const uncoveredDependencies = dependencies
    .filter((dependency) => dependency.cloudsmithStatus === "NOT_FOUND")
    .sort((left, right) => compareDependencies(left, right, SORT_MODES.COVERAGE, false));
  const policyViolations = dependencies
    .filter((dependency) => dependency.policy && dependency.policy.violated)
    .sort((left, right) => compareDependencies(left, right, SORT_MODES.SEVERITY, false));

  const lines = [
    `# Dependency Health Report — ${projectName}`,
    `Generated: ${generatedDate}`,
    "",
    "## Summary",
    `- ${summary.total} total dependencies (${summary.direct} direct, ${summary.transitive} transitive)`,
    `- ${summary.found} served by Cloudsmith (${summary.coveragePercent}% coverage)`,
  ];

  if (summary.notFound > 0) {
    lines.push(`- ${summary.notFound} not found in Cloudsmith`);
  }

  if (summary.vulnerable > 0) {
    const severityParts = ["Critical", "High", "Medium", "Low"]
      .filter((severity) => summary.severityCounts[severity] > 0)
      .map((severity) => `${summary.severityCounts[severity]} ${severity}`);
    lines.push(`- ${summary.vulnerable} with known vulnerabilities (${severityParts.join(", ")})`);
  }

  lines.push("");
  lines.push("## Vulnerable Dependencies");
  if (vulnerableDependencies.length === 0) {
    lines.push("None");
  } else {
    lines.push("| Package | Version | Type | Severity | CVEs | Fix Available |");
    lines.push("|---------|---------|------|----------|------|---------------|");
    for (const dependency of vulnerableDependencies) {
      const fixEntry = (dependency.vulnerabilities.entries || []).find((entry) => entry.fixVersion);
      const fixCell = fixEntry
        ? `Yes (${fixEntry.fixVersion})`
        : dependency.vulnerabilities.hasFixAvailable
          ? "Yes"
          : "No";
      lines.push(`| ${dependency.name} | ${dependency.version || "—"} | ${dependency.isDirect ? "Direct" : "Transitive"} | ${dependency.vulnerabilities.maxSeverity || "Unknown"} | ${(dependency.vulnerabilities.cveIds || []).join(", ") || "—"} | ${fixCell} |`);
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

  const count = Number(
    cloudsmithPackage.vulnerability_scan_results_count
    || cloudsmithPackage.num_vulnerabilities
    || 0
  );
  if (!Number.isFinite(count) || count <= 0) {
    return null;
  }

  return {
    count,
    maxSeverity: cloudsmithPackage.max_severity || null,
  };
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
  getFilterLabel,
  matchesFilter,
  matchCoverageCandidates,
};

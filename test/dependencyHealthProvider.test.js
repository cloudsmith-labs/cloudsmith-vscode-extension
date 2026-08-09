const assert = require("assert");
const path = require("path");
const vscode = require("vscode");
const {
  CLOUDSMITH_COVERAGE_STATUS,
  DependencyHealthProvider,
  SCAN_STATES,
  buildComplianceReportData,
  getConcreteDependencyVersion,
  lookupExactDependency,
  matchCoverageCandidates,
} = require("../views/dependencyHealthProvider");
const {
  ADAPTER_RESULT_STATUSES,
  createDefaultDependencyAdapterRegistry,
} = require("../util/dependencyAdapterRegistry");
const DependencyHealthNode = require("../models/dependencyHealthNode");
const {
  DEPENDENCY_VERSION_STATES,
  RESOLUTION_SOURCE_KINDS,
  createDependencyRecord,
  createDependencySource,
} = require("../util/dependencyRecord");

suite("DependencyHealthProvider Test Suite", () => {
  let originalWithProgress;
  let originalShowInformationMessage;
  let originalShowWarningMessage;
  let originalShowErrorMessage;

  function createContext(isConnected = "true") {
    return {
      secrets: {
        onDidChange() {},
        async get(key) {
          if (key === "cloudsmith-vsc.isConnected") {
            return isConnected;
          }
          return null;
        },
      },
      workspaceState: {
        get() {
          return null;
        },
        async update() {},
      },
    };
  }

  function createDependency(name, version, format = "npm") {
    return {
      name,
      version,
      legacyVersion: version,
      declaredConstraint: version,
      resolvedVersion: null,
      versionState: DEPENDENCY_VERSION_STATES.EXACT_DECLARATION,
      format,
      ecosystem: format,
      isDirect: true,
      parent: null,
      parentChain: [],
      transitives: [],
      cloudsmithStatus: "CHECKING",
      cloudsmithPackage: null,
      sourceFile: "package-lock.json",
      isDevelopmentDependency: false,
    };
  }

  function createFoundDependency(name, version) {
    return {
      ...createDependency(name, version),
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: {
        namespace: "workspace",
        repository: "repo",
        slug_perm: `${name}/${version}`,
      },
    };
  }

  function cloneTrees(trees) {
    return JSON.parse(JSON.stringify(trees));
  }

  function deferred() {
    let resolve;
    let reject;
    const promise = new Promise((resolvePromise, rejectPromise) => {
      resolve = resolvePromise;
      reject = rejectPromise;
    });
    return { promise, resolve, reject };
  }

  async function waitForTurn() {
    await new Promise((resolve) => setImmediate(resolve));
  }

  function createDiagnosticsPublisher() {
    return {
      current: ["existing-diagnostic"],
      prepared: [],
      replacements: [],
      async prepare(manifests, nodes) {
        const snapshot = {
          manifests: manifests.map((manifest) => manifest.filePath),
          dependencies: nodes.map((node) => node.name),
        };
        this.prepared.push(snapshot);
        return snapshot;
      },
      replace(snapshot) {
        this.current = snapshot;
        this.replacements.push(snapshot);
      },
    };
  }

  function installScanSteps(provider, steps) {
    let nextStep = 0;
    provider._performScan = async function () {
      const step = steps[nextStep];
      nextStep += 1;
      if (!step) {
        throw new Error("Missing scan test step");
      }

      if (step.started) {
        step.started.resolve();
      }
      if (step.gate) {
        await step.gate.promise;
      }

      const dependency = createFoundDependency(step.name || "dependency", step.version || "1.0.0");
      const trees = [{
        ecosystem: "npm",
        sourceFile: `${step.name || "dependency"}.json`,
        dependencies: [dependency],
      }];
      this._lastManifests = [{
        filePath: `/${step.name || "dependency"}.json`,
        format: "npm",
      }];
      this._fullTrees = cloneTrees(trees);
      this._displayTrees = cloneTrees(trees);
      this._warnings = step.warnings ? step.warnings.slice() : [];
      this._rebuildSummary();
      await this._storeReportData(new Date("2026-08-07T12:00:00.000Z"));

      if (step.error) {
        throw step.error;
      }
      if (step.canceled) {
        return { canceled: true };
      }
      return { canceled: false };
    };
  }

  function createLookupApi(handler) {
    return {
      calls: [],
      async getWithHeaders(endpoint) {
        this.calls.push(endpoint);
        return handler(endpoint, this.calls.length);
      },
    };
  }

  function lookupPage(data, page = 1, pageTotal = 1, count = data.length, pageSize = 100) {
    return {
      data,
      headers: {
        page: String(page),
        pageTotal: String(pageTotal),
        count: String(count),
        pageSize: String(pageSize),
      },
    };
  }

  async function runFixtureThroughLookupAndNode(ecosystem, fixtureName, dependencyName, candidate) {
    const workspace = path.join(__dirname, "fixtures", fixtureName);
    const registry = createDefaultDependencyAdapterRegistry();
    const detections = await registry.detect(workspace);
    const detection = detections.find((entry) => entry.ecosystem === ecosystem);
    assert.ok(detection, `expected a ${ecosystem} adapter detection`);
    const adapterResult = await registry.parse(detection, {
      workspaceFolder: workspace,
      maxDependenciesToScan: 10000,
    });
    assert.ok([
      ADAPTER_RESULT_STATUSES.SUCCESS,
      ADAPTER_RESULT_STATUSES.PARTIAL,
    ].includes(adapterResult.status));
    const dependency = adapterResult.dependencies.find((entry) => entry.name === dependencyName);
    assert.ok(dependency, `expected ${dependencyName} in the canonical adapter result`);

    const lookup = await lookupExactDependency({
      api: createLookupApi(() => lookupPage([candidate])),
      cloudsmithWorkspace: "workspace",
      cloudsmithRepo: "repository",
      dependency,
    });
    assert.strictEqual(lookup.status, CLOUDSMITH_COVERAGE_STATUS.FOUND);

    const node = new DependencyHealthNode({
      ...dependency,
      cloudsmithStatus: lookup.status,
      cloudsmithPackage: lookup.package,
      cloudsmithLookupDetail: lookup.detail,
    }, {});
    assert.strictEqual(node.state, "available");
    assert.strictEqual(node.version.value, candidate.version);
    return { adapterResult, dependency, lookup, node };
  }

  setup(() => {
    originalWithProgress = vscode.window.withProgress;
    originalShowInformationMessage = vscode.window.showInformationMessage;
    originalShowWarningMessage = vscode.window.showWarningMessage;
    originalShowErrorMessage = vscode.window.showErrorMessage;

    vscode.window.withProgress = async (_options, task) => task(
      { report() {} },
      {
        onCancellationRequested() {
          return { dispose() {} };
        },
      }
    );
    vscode.window.showInformationMessage = async () => undefined;
    vscode.window.showWarningMessage = async () => undefined;
    vscode.window.showErrorMessage = async () => undefined;
  });

  teardown(() => {
    vscode.window.withProgress = originalWithProgress;
    vscode.window.showInformationMessage = originalShowInformationMessage;
    vscode.window.showWarningMessage = originalShowWarningMessage;
    vscode.window.showErrorMessage = originalShowErrorMessage;
  });

  test("starts idle with no successful scan and rescan can fall back to first-scan behavior", async () => {
    const provider = new DependencyHealthProvider(createContext());
    let fallbackCalls = 0;

    assert.deepStrictEqual(provider.getScanState(), {
      status: SCAN_STATES.IDLE,
      id: 0,
      startedAt: null,
      completedAt: null,
      scope: null,
      message: null,
      failureMessage: null,
      hasSuccessfulScan: false,
      successfulScope: null,
    });

    const result = await provider.rescan(async () => {
      fallbackCalls += 1;
      return "first-scan";
    });

    assert.strictEqual(result, "first-scan");
    assert.strictEqual(fallbackCalls, 1);
  });

  test("first successful scan atomically commits results, scope, report data, and diagnostics", async () => {
    const diagnostics = createDiagnosticsPublisher();
    const provider = new DependencyHealthProvider(createContext(), diagnostics);
    installScanSteps(provider, [{ name: "first-result" }]);

    const result = await provider.scan("workspace-a", "repo-a", "/project-a");

    assert.strictEqual(result.status, SCAN_STATES.SUCCEEDED);
    assert.strictEqual(provider.dependencies[0].name, "first-result");
    assert.deepStrictEqual(provider.getLastSuccessfulScope(), {
      workspace: "workspace-a",
      repository: "repo-a",
      projectFolder: "/project-a",
    });
    assert.ok(provider.getReportData());
    assert.strictEqual(provider.getScanState().failureMessage, null);
    assert.deepStrictEqual(diagnostics.current.dependencies, ["first-result"]);
    assert.strictEqual(diagnostics.replacements.length, 1);
  });

  test("first scan failure publishes neither partial results nor diagnostics", async () => {
    const diagnostics = createDiagnosticsPublisher();
    const provider = new DependencyHealthProvider(createContext(), diagnostics);
    installScanSteps(provider, [{ name: "partial-result", error: new Error("index unavailable") }]);

    const result = await provider.scan("workspace-a", null, "/project-a");

    assert.strictEqual(result.status, SCAN_STATES.FAILED);
    assert.strictEqual(provider.dependencies.length, 0);
    assert.strictEqual(provider.hasSuccessfulScan(), false);
    assert.strictEqual(provider.getLastSuccessfulScope(), null);
    assert.deepStrictEqual(diagnostics.current, ["existing-diagnostic"]);
    assert.strictEqual(diagnostics.replacements.length, 0);
    const nodes = await provider.getChildren();
    assert.strictEqual(nodes[0].getTreeItem().label, "Dependency scan failed");
  });

  test("first scan cancellation publishes neither partial results nor diagnostics", async () => {
    const diagnostics = createDiagnosticsPublisher();
    const provider = new DependencyHealthProvider(createContext(), diagnostics);
    installScanSteps(provider, [{ name: "partial-result", canceled: true }]);

    const result = await provider.scan("workspace-a", null, "/project-a");

    assert.strictEqual(result.status, SCAN_STATES.CANCELLED);
    assert.strictEqual(provider.dependencies.length, 0);
    assert.strictEqual(provider.hasSuccessfulScan(), false);
    assert.deepStrictEqual(diagnostics.current, ["existing-diagnostic"]);
    const nodes = await provider.getChildren();
    assert.strictEqual(nodes[0].getTreeItem().label, "Dependency scan canceled");
  });

  test("successful rescan leaves prior results visible while running and replaces them on commit", async () => {
    const diagnostics = createDiagnosticsPublisher();
    const provider = new DependencyHealthProvider(createContext(), diagnostics);
    const refreshStarted = deferred();
    const refreshGate = deferred();
    installScanSteps(provider, [
      { name: "old-result" },
      { name: "new-result", started: refreshStarted, gate: refreshGate },
    ]);

    await provider.scan("workspace-a", "repo-a", "/project-a");
    const refreshPromise = provider.rescan();
    await refreshStarted.promise;

    assert.strictEqual(provider.dependencies[0].name, "old-result");
    assert.strictEqual(provider.getScanState().status, SCAN_STATES.RUNNING);
    const runningNodes = await provider.getChildren();
    assert.strictEqual(runningNodes[0].getTreeItem().label, "Refreshing dependencies");
    assert.strictEqual(diagnostics.current.dependencies[0], "old-result");

    refreshGate.resolve();
    const result = await refreshPromise;

    assert.strictEqual(result.status, SCAN_STATES.SUCCEEDED);
    assert.strictEqual(provider.dependencies[0].name, "new-result");
    assert.strictEqual(diagnostics.current.dependencies[0], "new-result");
    assert.strictEqual(provider.isScanRunning(), false);
  });

  test("failed rescan preserves prior results, diagnostics, and successful scope", async () => {
    const diagnostics = createDiagnosticsPublisher();
    const provider = new DependencyHealthProvider(createContext(), diagnostics);
    installScanSteps(provider, [
      { name: "known-good" },
      { name: "partial-replacement", error: new Error("refresh failed") },
    ]);

    await provider.scan("workspace-a", "repo-a", "/project-a");
    const priorDiagnostics = diagnostics.current;
    const result = await provider.scan("workspace-b", "repo-b", "/project-b");

    assert.strictEqual(result.status, SCAN_STATES.FAILED);
    assert.strictEqual(provider.dependencies[0].name, "known-good");
    assert.deepStrictEqual(provider.getLastSuccessfulScope(), {
      workspace: "workspace-a",
      repository: "repo-a",
      projectFolder: "/project-a",
    });
    assert.strictEqual(diagnostics.current, priorDiagnostics);
    assert.strictEqual(diagnostics.replacements.length, 1);
    const nodes = await provider.getChildren();
    assert.strictEqual(nodes[0].getTreeItem().label, "Dependency refresh failed");
    assert.ok(nodes.length > 1);
    assert.strictEqual(provider.isScanRunning(), false);
  });

  test("scope change can select a different project folder without mutating successful scope", async () => {
    const originalShowQuickPick = vscode.window.showQuickPick;
    const originalShowOpenDialog = vscode.window.showOpenDialog;
    vscode.window.showQuickPick = async (items) => items.find((item) => item.browse);
    vscode.window.showOpenDialog = async () => [{ fsPath: "/project-b" }];

    try {
      const provider = new DependencyHealthProvider(createContext(), createDiagnosticsPublisher());
      installScanSteps(provider, [{ name: "known-good" }]);
      await provider.scan("workspace-a", "repo-a", "/project-a");

      const selectedFolder = await provider.selectProjectFolder();

      assert.strictEqual(selectedFolder, "/project-b");
      assert.strictEqual(provider.getLastSuccessfulScope().projectFolder, "/project-a");
    } finally {
      vscode.window.showQuickPick = originalShowQuickPick;
      vscode.window.showOpenDialog = originalShowOpenDialog;
    }
  });

  test("cancelled rescan preserves prior results and diagnostics", async () => {
    const diagnostics = createDiagnosticsPublisher();
    const provider = new DependencyHealthProvider(createContext(), diagnostics);
    installScanSteps(provider, [
      { name: "known-good" },
      { name: "partial-replacement", canceled: true },
    ]);

    await provider.scan("workspace-a", "repo-a", "/project-a");
    const priorDiagnostics = diagnostics.current;
    const result = await provider.rescan();

    assert.strictEqual(result.status, SCAN_STATES.CANCELLED);
    assert.strictEqual(provider.dependencies[0].name, "known-good");
    assert.strictEqual(diagnostics.current, priorDiagnostics);
    assert.strictEqual(diagnostics.replacements.length, 1);
    assert.strictEqual(provider.isScanRunning(), false);
  });

  test("successful retry clears the failed operation state", async () => {
    const provider = new DependencyHealthProvider(createContext(), createDiagnosticsPublisher());
    installScanSteps(provider, [
      { name: "partial", error: new Error("temporary failure") },
      { name: "retry-result" },
    ]);

    await provider.scan("workspace-a", null, "/project-a");
    assert.strictEqual(provider.getScanState().status, SCAN_STATES.FAILED);
    assert.match(provider.getScanState().failureMessage, /temporary failure/);

    await provider.scan("workspace-a", null, "/project-a");

    assert.strictEqual(provider.getScanState().status, SCAN_STATES.SUCCEEDED);
    assert.strictEqual(provider.getScanState().failureMessage, null);
    assert.strictEqual(provider.dependencies[0].name, "retry-result");
  });

  test("a superseded scan cannot overwrite a newer scan that finishes first", async () => {
    const diagnostics = createDiagnosticsPublisher();
    const provider = new DependencyHealthProvider(createContext(), diagnostics);
    const firstStarted = deferred();
    const firstGate = deferred();
    const secondStarted = deferred();
    const secondGate = deferred();
    installScanSteps(provider, [
      { name: "scan-a", started: firstStarted, gate: firstGate },
      { name: "scan-b", started: secondStarted, gate: secondGate },
    ]);

    const firstPromise = provider.scan("workspace-a", "repo-a", "/project-a");
    await firstStarted.promise;
    const secondPromise = provider.scan("workspace-b", "repo-b", "/project-b");
    await secondStarted.promise;

    secondGate.resolve();
    assert.strictEqual((await secondPromise).status, SCAN_STATES.SUCCEEDED);
    firstGate.resolve();
    assert.strictEqual((await firstPromise).status, "superseded");

    assert.strictEqual(provider.dependencies[0].name, "scan-b");
    assert.strictEqual(provider.lastWorkspace, "workspace-b");
    assert.deepStrictEqual(diagnostics.current.dependencies, ["scan-b"]);
    assert.strictEqual(diagnostics.replacements.length, 1);
  });

  test("a superseded scan that finishes first cannot publish before the active scan", async () => {
    const diagnostics = createDiagnosticsPublisher();
    const provider = new DependencyHealthProvider(createContext(), diagnostics);
    const firstStarted = deferred();
    const firstGate = deferred();
    const secondStarted = deferred();
    const secondGate = deferred();
    installScanSteps(provider, [
      { name: "scan-a", started: firstStarted, gate: firstGate },
      { name: "scan-b", started: secondStarted, gate: secondGate },
    ]);

    const firstPromise = provider.scan("workspace-a", "repo-a", "/project-a");
    await firstStarted.promise;
    const secondPromise = provider.scan("workspace-b", "repo-b", "/project-b");
    await secondStarted.promise;

    firstGate.resolve();
    assert.strictEqual((await firstPromise).status, "superseded");
    assert.strictEqual(diagnostics.replacements.length, 0);
    assert.strictEqual(provider.dependencies.length, 0);

    secondGate.resolve();
    assert.strictEqual((await secondPromise).status, SCAN_STATES.SUCCEEDED);
    assert.strictEqual(provider.dependencies[0].name, "scan-b");
    assert.deepStrictEqual(diagnostics.current.dependencies, ["scan-b"]);
  });

  test("scan context keys expose running and successful state without impossible combinations", async () => {
    const originalExecuteCommand = vscode.commands.executeCommand;
    const contextValues = new Map();
    const scanStarted = deferred();
    const scanGate = deferred();
    vscode.commands.executeCommand = async (command, key, value) => {
      if (command === "setContext") {
        contextValues.set(key, value);
      }
    };

    try {
      const provider = new DependencyHealthProvider(createContext(), createDiagnosticsPublisher());
      installScanSteps(provider, [{ name: "result", started: scanStarted, gate: scanGate }]);
      await provider._updateContexts();
      assert.strictEqual(contextValues.get("cloudsmith.depScanRunning"), false);
      assert.strictEqual(contextValues.get("cloudsmith.depScanSucceeded"), false);

      const scanPromise = provider.scan("workspace-a", null, "/project-a");
      await scanStarted.promise;
      assert.strictEqual(contextValues.get("cloudsmith.depScanRunning"), true);
      assert.strictEqual(contextValues.get("cloudsmith.depScanSucceeded"), false);

      scanGate.resolve();
      await scanPromise;
      await waitForTurn();
      assert.strictEqual(contextValues.get("cloudsmith.depScanRunning"), false);
      assert.strictEqual(contextValues.get("cloudsmith.depScanSucceeded"), true);
      assert.strictEqual(contextValues.get("cloudsmith.depScanComplete"), true);
    } finally {
      vscode.commands.executeCommand = originalExecuteCommand;
    }
  });

  test("getChildren() shows the signed-out state when disconnected before the first scan", async () => {
    const provider = new DependencyHealthProvider(createContext("false"));
    const nodes = await provider.getChildren();

    assert.strictEqual(nodes.length, 1);
    assert.strictEqual(nodes[0].getTreeItem().label, "Connect to Cloudsmith");
  });

  test("_performScan projects canonical adapter records into the compatibility tree", async () => {
    const originalGetConfiguration = vscode.workspace.getConfiguration;
    const manifestSource = createDependencySource({
      kind: RESOLUTION_SOURCE_KINDS.MANIFEST,
      filePath: "/project/package.json",
      type: "package.json",
    });
    const dependency = createDependencyRecord({
      ecosystem: "npm",
      format: "npm",
      name: "left-pad",
      declaredConstraint: "^1.0.0",
      resolvedVersion: null,
      versionState: DEPENDENCY_VERSION_STATES.RANGE,
      sourceManifest: manifestSource,
      isDirect: true,
      legacyVersion: "1.0.0",
    });
    const dependencyAdapters = {
      async detectManifests() {
        return [{
          adapterId: "npmParser",
          filePath: "/project/package.json",
          format: "npm",
          manifestType: "package.json",
        }];
      },
      async detect() {
        return [];
      },
      async parseManifest() {
        return {
          status: ADAPTER_RESULT_STATUSES.SUCCESS,
          adapterId: "npmParser",
          ecosystem: "npm",
          sourceFile: "package.json",
          source: { manifest: manifestSource, resolution: null },
          dependencies: [dependency],
          warnings: [],
          error: null,
        };
      },
    };

    vscode.workspace.getConfiguration = () => ({
      get(key) {
        return key === "resolveTransitiveDependencies" ? false : 10000;
      },
    });

    try {
      const provider = new DependencyHealthProvider(createContext(), null, { dependencyAdapters });
      provider._runCoverageChecks = async () => {};
      provider._runEnrichmentPasses = async () => {};
      provider._publishDiagnostics = async () => {};
      provider._storeReportData = async () => {};
      provider.refresh = () => {};

      const result = await provider._performScan(
        "workspace-a",
        "repo-a",
        "/project",
        { report() {} },
        { isCancellationRequested: false }
      );
      const projected = provider._fullTrees[0].dependencies[0];

      assert.deepStrictEqual(result, { canceled: false });
      assert.strictEqual(projected.version, "1.0.0");
      assert.strictEqual(projected.declaredConstraint, "^1.0.0");
      assert.strictEqual(projected.resolvedVersion, null);
      assert.strictEqual(projected.sourceManifest.filePath, "/project/package.json");
      assert.strictEqual(projected.cloudsmithStatus, "CHECKING");
    } finally {
      vscode.workspace.getConfiguration = originalGetConfiguration;
    }
  });

  test("_performScan does not treat an all-parser failure as a valid empty project", async () => {
    const originalGetConfiguration = vscode.workspace.getConfiguration;
    vscode.workspace.getConfiguration = () => ({
      get(key) {
        return key === "resolveTransitiveDependencies" ? false : 10000;
      },
    });
    const dependencyAdapters = {
      async detectManifests() {
        return [{
          adapterId: "npmParser",
          filePath: "/project/package.json",
          format: "npm",
          manifestType: "package.json",
        }];
      },
      getDiscoveryWarnings() {
        return [];
      },
      async parseManifest() {
        return {
          status: ADAPTER_RESULT_STATUSES.ERROR,
          adapterId: "npmParser",
          ecosystem: "npm",
          sourceFile: "package.json",
          dependencies: [],
          warnings: [],
          error: { code: "parse-error", message: "Malformed package.json." },
        };
      },
    };

    try {
      const provider = new DependencyHealthProvider(createContext(), null, { dependencyAdapters });
      await assert.rejects(
        () => provider._performScan(
          "workspace-a",
          "repo-a",
          "/project",
          { report() {} },
          { isCancellationRequested: false }
        ),
        /parsing did not complete.*Malformed package\.json/
      );
      assert.deepStrictEqual(provider._fullTrees, []);
      assert.deepStrictEqual(provider._displayTrees, []);
    } finally {
      vscode.workspace.getConfiguration = originalGetConfiguration;
    }
  });

  test("_performScan treats an empty requirements.txt as a valid empty project", async () => {
    const originalGetConfiguration = vscode.workspace.getConfiguration;
    vscode.workspace.getConfiguration = () => ({
      get(key) {
        return key === "resolveTransitiveDependencies" ? false : 10000;
      },
    });
    const dependencyAdapters = {
      async detectManifests() {
        return [{
          adapterId: "pythonParser",
          filePath: "/project/requirements.txt",
          format: "python",
          manifestType: "requirements.txt",
        }];
      },
      getDiscoveryWarnings() {
        return [];
      },
      async parseManifest() {
        return {
          status: ADAPTER_RESULT_STATUSES.PARTIAL,
          adapterId: "pythonParser",
          ecosystem: "python",
          sourceFile: "requirements.txt",
          dependencies: [],
          warnings: [
            "requirements.txt does not encode transitive dependencies. Showing direct requirements only.",
          ],
          error: null,
        };
      },
    };

    try {
      const provider = new DependencyHealthProvider(createContext(), null, { dependencyAdapters });
      provider._storeReportData = async () => {};

      const result = await provider._performScan(
        "workspace-a",
        "repo-a",
        "/project",
        { report() {} },
        { isCancellationRequested: false }
      );

      assert.deepStrictEqual(result, { canceled: false });
      assert.deepStrictEqual(provider._fullTrees, []);
      assert.deepStrictEqual(provider._displayTrees, []);
    } finally {
      vscode.workspace.getConfiguration = originalGetConfiguration;
    }
  });

  test("_performScan composes lock-backed and uncovered manifest-only projects", async () => {
    const originalGetConfiguration = vscode.workspace.getConfiguration;
    vscode.workspace.getConfiguration = () => ({ get: () => 10000 });
    const rootSource = createDependencySource({
      kind: RESOLUTION_SOURCE_KINDS.MANIFEST,
      filePath: "/project/package.json",
      type: "package.json",
    });
    const nestedSource = createDependencySource({
      kind: RESOLUTION_SOURCE_KINDS.MANIFEST,
      filePath: "/project/packages/tool/requirements.txt",
      type: "requirements.txt",
    });
    const rootDependency = createDependencyRecord({
      ecosystem: "npm",
      format: "npm",
      name: "root-package",
      declaredConstraint: "^1.0.0",
      resolvedVersion: "1.4.0",
      versionState: DEPENDENCY_VERSION_STATES.RESOLVED,
      resolutionSource: createDependencySource({
        kind: RESOLUTION_SOURCE_KINDS.LOCKFILE,
        filePath: "/project/package-lock.json",
        type: "package-lock.json",
      }),
      sourceManifest: rootSource,
      isDirect: true,
      legacyVersion: "1.4.0",
    });
    const nestedDependency = createDependencyRecord({
      ecosystem: "python",
      format: "python",
      name: "nested-package",
      declaredConstraint: ">=2",
      resolvedVersion: null,
      versionState: DEPENDENCY_VERSION_STATES.RANGE,
      sourceManifest: nestedSource,
      isDirect: true,
      legacyVersion: "2",
    });
    const parsedManifestPaths = [];
    const dependencyAdapters = {
      async detectManifests() {
        return [
          { filePath: rootSource.filePath, format: "npm", manifestType: "package.json" },
          { filePath: nestedSource.filePath, format: "python", manifestType: "requirements.txt" },
        ];
      },
      getDiscoveryWarnings() { return []; },
      async detect() {
        return [{ adapterId: "npmParser", sourceFile: "package-lock.json" }];
      },
      async parse() {
        return {
          status: ADAPTER_RESULT_STATUSES.SUCCESS,
          adapterId: "npmParser",
          ecosystem: "npm",
          sourceFile: "package-lock.json",
          source: { manifest: rootSource },
          dependencies: [rootDependency],
          warnings: [],
        };
      },
      async parseManifest(manifest) {
        parsedManifestPaths.push(manifest.filePath);
        return {
          status: ADAPTER_RESULT_STATUSES.SUCCESS,
          adapterId: "pythonParser",
          ecosystem: "python",
          sourceFile: "requirements.txt",
          source: { manifest: nestedSource },
          dependencies: [nestedDependency],
          warnings: [],
        };
      },
    };

    try {
      const provider = new DependencyHealthProvider(createContext(), null, { dependencyAdapters });
      provider._runCoverageChecks = async () => {};
      provider._runEnrichmentPasses = async () => {};
      provider._publishDiagnostics = async () => {};
      provider._storeReportData = async () => {};
      provider.refresh = () => {};

      await provider._performScan(
        "workspace-a",
        "repo-a",
        "/project",
        { report() {} },
        { isCancellationRequested: false }
      );

      assert.deepStrictEqual(parsedManifestPaths, [nestedSource.filePath]);
      assert.deepStrictEqual(
        provider._fullTrees.flatMap((tree) => tree.dependencies).map((dependency) => dependency.name).sort(),
        ["nested-package", "root-package"]
      );
    } finally {
      vscode.workspace.getConfiguration = originalGetConfiguration;
    }
  });

  test("_performScan retains an uncovered manifest failure beside successful results", async () => {
    const originalGetConfiguration = vscode.workspace.getConfiguration;
    vscode.workspace.getConfiguration = () => ({ get: () => 10000 });
    const sourceManifest = createDependencySource({
      kind: RESOLUTION_SOURCE_KINDS.MANIFEST,
      filePath: "/project/package.json",
      type: "package.json",
    });
    const dependencyAdapters = {
      async detectManifests() {
        return [
          { filePath: sourceManifest.filePath, format: "npm" },
          { filePath: "/project/nested/pyproject.toml", format: "python" },
        ];
      },
      getDiscoveryWarnings() { return []; },
      async detect() { return [{ adapterId: "npmParser" }]; },
      async parse() {
        return {
          status: ADAPTER_RESULT_STATUSES.SUCCESS,
          adapterId: "npmParser",
          ecosystem: "npm",
          sourceFile: "package-lock.json",
          source: { manifest: sourceManifest },
          dependencies: [createDependencyRecord({
            ecosystem: "npm",
            format: "npm",
            name: "root-package",
            resolvedVersion: "1.0.0",
            versionState: DEPENDENCY_VERSION_STATES.RESOLVED,
            resolutionSource: createDependencySource({
              kind: RESOLUTION_SOURCE_KINDS.LOCKFILE,
              filePath: "/project/package-lock.json",
              type: "package-lock.json",
            }),
            sourceManifest,
            isDirect: true,
            legacyVersion: "1.0.0",
          })],
          warnings: [],
        };
      },
      async parseManifest() {
        return {
          status: ADAPTER_RESULT_STATUSES.ERROR,
          adapterId: "pythonParser",
          ecosystem: "python",
          sourceFile: "pyproject.toml",
          dependencies: [],
          warnings: [],
          error: { message: "Malformed nested pyproject.toml." },
        };
      },
    };

    try {
      const provider = new DependencyHealthProvider(createContext(), null, { dependencyAdapters });
      provider._runCoverageChecks = async () => {};
      provider._runEnrichmentPasses = async () => {};
      provider._publishDiagnostics = async () => {};
      provider._storeReportData = async () => {};
      provider.refresh = () => {};

      await provider._performScan(
        "workspace-a",
        "repo-a",
        "/project",
        { report() {} },
        { isCancellationRequested: false }
      );

      assert.strictEqual(provider._fullTrees[0].dependencies[0].name, "root-package");
      assert.ok(provider._warnings.includes("Malformed nested pyproject.toml."));
    } finally {
      vscode.workspace.getConfiguration = originalGetConfiguration;
    }
  });

  test("_performScan does not treat an unsupported-only manifest as empty", async () => {
    const originalGetConfiguration = vscode.workspace.getConfiguration;
    vscode.workspace.getConfiguration = () => ({
      get(key) { return key === "resolveTransitiveDependencies" ? false : 10000; },
    });
    const dependencyAdapters = {
      async detectManifests() {
        return [{ filePath: "/project/build.gradle", format: "gradle" }];
      },
      getDiscoveryWarnings() { return []; },
      async parseManifest() {
        return {
          status: ADAPTER_RESULT_STATUSES.UNSUPPORTED,
          adapterId: "gradleParser",
          ecosystem: "gradle",
          sourceFile: "build.gradle",
          dependencies: [],
          warnings: [],
          error: { message: "No direct manifest parser supports build.gradle." },
        };
      },
    };

    try {
      const provider = new DependencyHealthProvider(createContext(), null, { dependencyAdapters });
      await assert.rejects(
        () => provider._performScan(
          "workspace-a",
          "repo-a",
          "/project",
          { report() {} },
          { isCancellationRequested: false }
        ),
        /parsing did not complete.*No direct manifest parser supports build\.gradle/
      );
    } finally {
      vscode.workspace.getConfiguration = originalGetConfiguration;
    }
  });

  test("_runCoverageChecks batches tree rebuilds and refreshes while preserving matches", async () => {
    const provider = new DependencyHealthProvider(createContext());
    const dependencies = Array.from({ length: 51 }, (_, index) => createDependency(`package-${index}`, "1.0.0"));
    const trees = [{
      ecosystem: "npm",
      sourceFile: "package-lock.json",
      dependencies,
    }];

    provider._fullTrees = cloneTrees(trees);
    provider._displayTrees = cloneTrees(trees);

    let rebuildCount = 0;
    let refreshCount = 0;
    const progressUpdates = [];

    provider._rebuildSummary = () => {
      rebuildCount += 1;
    };
    provider.refresh = () => {
      refreshCount += 1;
    };
    provider._services.createCloudsmithAPI = () => createLookupApi((endpoint) => {
      const query = new URL(endpoint, "https://api.cloudsmith.io/v1/").searchParams.get("query");
      const normalizedQuery = query.replace(/\\/g, "");
      const queriedName = normalizedQuery
        .split(" AND ")
        .find((term) => term.startsWith("name:"))
        .slice("name:".length);
      const dependency = dependencies.find((candidate) => candidate.name === queriedName);
      return lookupPage([{
        name: dependency.name,
        version: dependency.version,
        format: dependency.format,
      }]);
    });

    await provider._runCoverageChecks(
      "workspace",
      "repo",
      dependencies.length,
      {
        report(update) {
          progressUpdates.push(update);
        },
      },
      { isCancellationRequested: false }
    );

    assert.strictEqual(rebuildCount, 2);
    assert.strictEqual(refreshCount, 2);
    assert.strictEqual(progressUpdates.length, 2);
    assert.strictEqual(progressUpdates[0].message, "Matching coverage... 50/51");
    assert.strictEqual(progressUpdates[1].message, "Matching coverage... 51/51");
    assert.strictEqual(
      provider._fullTrees[0].dependencies.every((dependency) => dependency.cloudsmithStatus === "FOUND"),
      true
    );
    assert.strictEqual(
      provider._displayTrees[0].dependencies.every((dependency) => dependency.cloudsmithStatus === "FOUND"),
      true
    );
  });

  test("_runCoverageChecks bounds exact lookup concurrency", async () => {
    const provider = new DependencyHealthProvider(createContext());
    const dependencies = Array.from({ length: 20 }, (_, index) => (
      createDependency(`package-${index}`, "1.0.0", "npm")
    ));
    provider._fullTrees = [{
      ecosystem: "npm",
      sourceFile: "package-lock.json",
      dependencies,
    }];
    provider._displayTrees = cloneTrees(provider._fullTrees);

    let inFlight = 0;
    let maxInFlight = 0;
    provider._rebuildSummary = () => {};
    provider.refresh = () => {};
    provider._services.createCloudsmithAPI = () => createLookupApi(async (endpoint) => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((resolve) => setImmediate(resolve));
      inFlight -= 1;
      const query = new URL(endpoint, "https://api.cloudsmith.io/v1/").searchParams.get("query");
      const normalizedQuery = query.replace(/\\/g, "");
      const dependency = dependencies.find((candidate) =>
        normalizedQuery.includes(`name:${candidate.name}`)
      );
      return lookupPage([{ name: dependency.name, version: dependency.version, format: "npm" }]);
    });

    await provider._runCoverageChecks(
      "workspace",
      "repo",
      dependencies.length,
      { report() {} },
      { isCancellationRequested: false }
    );

    assert.strictEqual(maxInFlight, 8);
  });

  test("scan-wide lookup budget counts pages across formats and marks remaining work incomplete", async () => {
    const npmDependency = createDependency("first-package", "1.0.0", "npm");
    const pythonDependency = createDependency("second-package", "2.0.0", "python");
    const api = createLookupApi((endpoint) => {
      const url = new URL(endpoint, "https://api.cloudsmith.io/v1/");
      const query = url.searchParams.get("query").replace(/\\/g, "");
      const page = Number(url.searchParams.get("page"));
      if (!query.includes("name:first-package")) {
        throw new Error("the exhausted scan-wide budget must prevent later format requests");
      }
      return page === 1
        ? lookupPage([{ name: "other", version: "1.0.0", format: "npm" }], 1, 2, 2, 1)
        : lookupPage([{
          name: npmDependency.name,
          version: npmDependency.version,
          format: npmDependency.format,
        }], 2, 2, 2, 1);
    });
    const provider = new DependencyHealthProvider(createContext(), null, {
      createCloudsmithAPI: () => api,
      lookupRequestLimit: 2,
    });
    provider._fullTrees = [
      { ecosystem: "npm", sourceFile: "package-lock.json", dependencies: [npmDependency] },
      { ecosystem: "python", sourceFile: "requirements.txt", dependencies: [pythonDependency] },
    ];
    provider._displayTrees = cloneTrees(provider._fullTrees);
    provider.refresh = () => {};

    await provider._runCoverageChecks(
      "workspace",
      "repo",
      2,
      { report() {} },
      { isCancellationRequested: false }
    );

    assert.strictEqual(api.calls.length, 2);
    assert.strictEqual(
      provider._fullTrees[0].dependencies[0].cloudsmithStatus,
      CLOUDSMITH_COVERAGE_STATUS.FOUND
    );
    assert.strictEqual(
      provider._fullTrees[1].dependencies[0].cloudsmithStatus,
      CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE
    );
    assert.match(
      provider._fullTrees[1].dependencies[0].cloudsmithLookupDetail,
      /request budget was exhausted/
    );
  });

  test("exact lookup finds a package on the first page with escaped name and version terms", async () => {
    const expectedPackage = { name: "@scope/pkg", version: "1.0.0", format: "npm" };
    const api = createLookupApi(() => lookupPage([expectedPackage]));

    const result = await lookupExactDependency({
      api,
      cloudsmithWorkspace: "workspace",
      cloudsmithRepo: "repo",
      dependency: createDependency("@scope/pkg", "1.0.0"),
      token: { isCancellationRequested: false },
    });

    assert.strictEqual(result.status, CLOUDSMITH_COVERAGE_STATUS.FOUND);
    assert.strictEqual(result.package, expectedPackage);
    assert.strictEqual(result.pagesFetched, 1);
    const query = new URL(api.calls[0], "https://api.cloudsmith.io/v1/").searchParams.get("query");
    assert.ok(query.includes("name:@scope\\/pkg"));
    assert.ok(query.includes("version:1.0.0"));
  });

  test("exact lookup follows pagination until a later-page match is found", async () => {
    const expectedPackage = { name: "left-pad", version: "1.0.0", format: "npm" };
    const api = createLookupApi((endpoint) => {
      const page = Number(new URL(endpoint, "https://api.cloudsmith.io/v1/").searchParams.get("page"));
      return page === 1
        ? lookupPage([{ name: "left-pad", version: "9.0.0", format: "npm" }], 1, 2, 2, 1)
        : lookupPage([expectedPackage], 2, 2, 2, 1);
    });

    const result = await lookupExactDependency({
      api,
      cloudsmithWorkspace: "workspace",
      cloudsmithRepo: null,
      dependency: createDependency("left-pad", "1.0.0"),
      token: { isCancellationRequested: false },
    });

    assert.strictEqual(result.status, CLOUDSMITH_COVERAGE_STATUS.FOUND);
    assert.strictEqual(result.package, expectedPackage);
    assert.strictEqual(result.pagesFetched, 2);
    assert.deepStrictEqual(
      api.calls.map((endpoint) => Number(new URL(endpoint, "https://api.cloudsmith.io/v1/").searchParams.get("page"))),
      [1, 2]
    );
  });

  test("exact lookup reports absence only after pagination is conclusively exhausted", async () => {
    const api = createLookupApi((endpoint) => {
      const page = Number(new URL(endpoint, "https://api.cloudsmith.io/v1/").searchParams.get("page"));
      return page === 1
        ? lookupPage([{ name: "other-package", version: "1.0.0", format: "npm" }], 1, 2, 2, 1)
        : lookupPage([{ name: "another-package", version: "2.0.0", format: "npm" }], 2, 2, 2, 1);
    });

    const result = await lookupExactDependency({
      api,
      cloudsmithWorkspace: "workspace",
      cloudsmithRepo: "repo",
      dependency: createDependency("left-pad", "1.0.0"),
      token: { isCancellationRequested: false },
    });

    assert.strictEqual(result.status, CLOUDSMITH_COVERAGE_STATUS.ABSENT);
    assert.strictEqual(result.package, null);
    assert.strictEqual(result.pagesFetched, 2);
  });

  test("lookup failure and partial failure remain distinct from package absence", async () => {
    const failed = await lookupExactDependency({
      api: createLookupApi(() => "Response status: 503 - Service Unavailable"),
      cloudsmithWorkspace: "workspace",
      cloudsmithRepo: "repo",
      dependency: createDependency("left-pad", "1.0.0"),
      token: { isCancellationRequested: false },
    });
    const partialApi = createLookupApi((_endpoint, callCount) => (
      callCount === 1
        ? lookupPage([{ name: "other", version: "1.0.0" }], 1, 2, 2, 1)
        : "Response status: 503 - Service Unavailable"
    ));
    const incomplete = await lookupExactDependency({
      api: partialApi,
      cloudsmithWorkspace: "workspace",
      cloudsmithRepo: "repo",
      dependency: createDependency("left-pad", "1.0.0"),
      token: { isCancellationRequested: false },
    });

    assert.strictEqual(failed.status, CLOUDSMITH_COVERAGE_STATUS.LOOKUP_FAILED);
    assert.strictEqual(incomplete.status, CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE);
  });

  test("rejected lookup requests remain explicit failures", async () => {
    const result = await lookupExactDependency({
      api: createLookupApi(() => Promise.reject(new Error("network unavailable"))),
      cloudsmithWorkspace: "workspace",
      cloudsmithRepo: "repo",
      dependency: createDependency("left-pad", "1.0.0"),
      token: { isCancellationRequested: false },
    });

    assert.strictEqual(result.status, CLOUDSMITH_COVERAGE_STATUS.LOOKUP_FAILED);
  });

  test("inconsistent pagination metadata cannot prove package absence", async () => {
    const result = await lookupExactDependency({
      api: createLookupApi(() => ({
        data: [{ name: "other", version: "1.0.0", format: "npm" }],
        headers: { page: "1", count: "0", pageSize: "100" },
      })),
      cloudsmithWorkspace: "workspace",
      cloudsmithRepo: "repo",
      dependency: createDependency("left-pad", "1.0.0"),
      token: { isCancellationRequested: false },
    });

    assert.strictEqual(result.status, CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE);
  });

  test("contradictory page totals and counts cannot prove package absence", async () => {
    const result = await lookupExactDependency({
      api: createLookupApi(() => ({
        data: [{ name: "other", version: "1.0.0", format: "npm" }],
        headers: {
          page: "1",
          pageTotal: "1",
          count: "200",
          pageSize: "100",
        },
      })),
      cloudsmithWorkspace: "workspace",
      cloudsmithRepo: "repo",
      dependency: createDependency("left-pad", "1.0.0"),
      token: { isCancellationRequested: false },
    });

    assert.strictEqual(result.status, CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE);
  });

  test("a response omitting count-backed page items cannot prove package absence", async () => {
    const result = await lookupExactDependency({
      api: createLookupApi(() => ({
        data: [],
        headers: {
          page: "1",
          pageTotal: "1",
          count: "50",
          pageSize: "100",
        },
      })),
      cloudsmithWorkspace: "workspace",
      cloudsmithRepo: "repo",
      dependency: createDependency("left-pad", "1.0.0"),
      token: { isCancellationRequested: false },
    });

    assert.strictEqual(result.status, CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE);
  });

  test("full pages without continuation metadata produce an incomplete lookup", async () => {
    const fullPage = Array.from({ length: 100 }, (_, index) => ({
      name: `other-${index}`,
      version: "1.0.0",
      format: "npm",
    }));
    const result = await lookupExactDependency({
      api: createLookupApi(() => ({ data: fullPage, headers: {} })),
      cloudsmithWorkspace: "workspace",
      cloudsmithRepo: "repo",
      dependency: createDependency("left-pad", "1.0.0"),
      token: { isCancellationRequested: false },
    });

    assert.strictEqual(result.status, CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE);
  });

  test("short and empty pages without continuation metadata remain incomplete", async () => {
    for (const data of [
      [],
      [{ name: "other", version: "1.0.0", format: "npm" }],
    ]) {
      const result = await lookupExactDependency({
        api: createLookupApi(() => ({ data, headers: {} })),
        cloudsmithWorkspace: "workspace",
        cloudsmithRepo: "repo",
        dependency: createDependency("left-pad", "1.0.0"),
        token: { isCancellationRequested: false },
      });

      assert.strictEqual(result.status, CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE);
    }
  });

  test("rate limiting is explicit and is not converted to absence", async () => {
    const result = await lookupExactDependency({
      api: createLookupApi(() => "Response status: 429 - Too Many Requests"),
      cloudsmithWorkspace: "workspace",
      cloudsmithRepo: "repo",
      dependency: createDependency("left-pad", "1.0.0"),
      token: { isCancellationRequested: false },
    });

    assert.strictEqual(result.status, CLOUDSMITH_COVERAGE_STATUS.RATE_LIMITED);
  });

  test("range-only dependencies remain unresolved without issuing an API request", async () => {
    const dependency = createDependencyRecord({
      ecosystem: "npm",
      format: "npm",
      name: "left-pad",
      declaredConstraint: "^1.0.0",
      resolvedVersion: null,
      versionState: DEPENDENCY_VERSION_STATES.RANGE,
      isDirect: true,
      legacyVersion: "1.0.0",
    });
    const api = createLookupApi(() => {
      throw new Error("unresolved dependencies must not be queried");
    });

    const result = await lookupExactDependency({
      api,
      cloudsmithWorkspace: "workspace",
      cloudsmithRepo: "repo",
      dependency,
      token: { isCancellationRequested: false },
    });

    assert.strictEqual(getConcreteDependencyVersion(dependency), null);
    assert.strictEqual(result.status, CLOUDSMITH_COVERAGE_STATUS.UNRESOLVED);
    assert.strictEqual(api.calls.length, 0);
  });

  test("legacy plain versions without evidence remain unresolved", async () => {
    const dependency = {
      name: "left-pad",
      version: "1.0.0",
      format: "npm",
      ecosystem: "npm",
    };
    const api = createLookupApi(() => {
      throw new Error("an unevidenced legacy version must not be queried");
    });

    const result = await lookupExactDependency({
      api,
      cloudsmithWorkspace: "workspace",
      cloudsmithRepo: "repo",
      dependency,
      token: { isCancellationRequested: false },
    });

    assert.strictEqual(getConcreteDependencyVersion(dependency), null);
    assert.strictEqual(result.status, CLOUDSMITH_COVERAGE_STATUS.UNRESOLVED);
    assert.strictEqual(api.calls.length, 0);
  });

  test("provider coverage keeps unresolved dependencies out of absent and upstream analysis", async () => {
    const dependency = createDependencyRecord({
      ecosystem: "npm",
      format: "npm",
      name: "left-pad",
      declaredConstraint: ">=1.0.0 <2.0.0",
      resolvedVersion: null,
      versionState: DEPENDENCY_VERSION_STATES.RANGE,
      isDirect: true,
      legacyVersion: "1.0.0 <2.0.0",
    });
    let upstreamCalls = 0;
    const provider = new DependencyHealthProvider(createContext(), null, {
      createCloudsmithAPI() {
        throw new Error("unresolved dependencies must not create an API client");
      },
      async analyzeUpstreamGaps() {
        upstreamCalls += 1;
        return [];
      },
    });
    provider._fullTrees = [{ ecosystem: "npm", sourceFile: "package.json", dependencies: [dependency] }];
    provider._displayTrees = provider._fullTrees;
    provider.refresh = () => {};

    await provider._runCoverageChecks(
      "workspace",
      "repo",
      1,
      { report() {} },
      { isCancellationRequested: false }
    );
    await provider._runEnrichmentPasses(
      "workspace",
      "repo",
      { report() {} },
      { isCancellationRequested: false }
    );

    assert.strictEqual(provider._fullTrees[0].dependencies[0].cloudsmithStatus, "UNRESOLVED");
    assert.strictEqual(provider._summary.notFound, 0);
    assert.strictEqual(provider._summary.unresolved, 1);
    assert.strictEqual(upstreamCalls, 0);
  });

  test("an exact manifest declaration can be evaluated without pretending it was lockfile-resolved", async () => {
    const dependency = createDependencyRecord({
      ecosystem: "npm",
      format: "npm",
      name: "left-pad",
      declaredConstraint: "1.0.0",
      resolvedVersion: null,
      versionState: DEPENDENCY_VERSION_STATES.EXACT_DECLARATION,
      isDirect: true,
      legacyVersion: "1.0.0",
    });
    const api = createLookupApi(() => lookupPage([{ name: "left-pad", version: "1.0.0", format: "npm" }]));

    const result = await lookupExactDependency({
      api,
      cloudsmithWorkspace: "workspace",
      cloudsmithRepo: "repo",
      dependency,
      token: { isCancellationRequested: false },
    });

    assert.strictEqual(dependency.resolvedVersion, null);
    assert.strictEqual(getConcreteDependencyVersion(dependency), "1.0.0");
    assert.strictEqual(result.status, CLOUDSMITH_COVERAGE_STATUS.FOUND);
  });

  test("an exact declaration can use its ecosystem-specific constraint when compatibility is empty", () => {
    const dependency = createDependencyRecord({
      ecosystem: "python",
      format: "python",
      name: "requests",
      declaredConstraint: "==2.32.3",
      resolvedVersion: null,
      versionState: DEPENDENCY_VERSION_STATES.EXACT_DECLARATION,
      isDirect: true,
      legacyVersion: "",
    });

    assert.strictEqual(getConcreteDependencyVersion(dependency), "2.32.3");
  });

  test("Maven matching requires group and artifact identity, not artifact name alone", async () => {
    const correct = {
      name: "shared-artifact",
      version: "1.0.0",
      format: "maven",
      identifiers: { group_id: "com.expected" },
    };
    const api = createLookupApi((endpoint) => {
      const page = Number(new URL(endpoint, "https://api.cloudsmith.io/v1/").searchParams.get("page"));
      return page === 1
        ? lookupPage([{
          name: "shared-artifact",
          version: "1.0.0",
          format: "maven",
          identifiers: { group_id: "com.wrong" },
        }], 1, 2, 2, 1)
        : lookupPage([correct], 2, 2, 2, 1);
    });

    const result = await lookupExactDependency({
      api,
      cloudsmithWorkspace: "workspace",
      cloudsmithRepo: "repo",
      dependency: createDependency("com.expected:shared-artifact", "1.0.0", "maven"),
      token: { isCancellationRequested: false },
    });

    assert.strictEqual(result.status, CLOUDSMITH_COVERAGE_STATUS.FOUND);
    assert.strictEqual(result.package, correct);
    const firstQuery = new URL(
      api.calls[0],
      "https://api.cloudsmith.io/v1/"
    ).searchParams.get("query").replace(/\\/g, "");
    assert.ok(firstQuery.includes("name:com.expected:shared-artifact"));
  });

  test("Maven and Go package identities preserve case", async () => {
    const mavenMatch = matchCoverageCandidates(
      [{
        name: "Library",
        version: "1.0.0",
        format: "maven",
        identifiers: { group_id: "com.example" },
      }],
      createDependency("com.Example:Library", "1.0.0", "maven")
    );
    assert.strictEqual(mavenMatch, null);

    const dependencies = [
      createDependency("Example.com/Org/Module", "v1.0.0", "go"),
      createDependency("example.com/org/module", "v1.0.0", "go"),
    ];
    const api = createLookupApi((endpoint) => {
      const query = new URL(endpoint, "https://api.cloudsmith.io/v1/")
        .searchParams.get("query")
        .replace(/\\/g, "");
      const dependency = dependencies.find((candidate) => query.includes(`name:${candidate.name}`));
      return lookupPage([{
        name: dependency.name,
        version: dependency.version,
        format: "go",
      }]);
    });
    const provider = new DependencyHealthProvider(createContext(), null, {
      createCloudsmithAPI: () => api,
    });
    provider._fullTrees = [{ ecosystem: "go", sourceFile: "go.mod", dependencies }];
    provider._displayTrees = cloneTrees(provider._fullTrees);
    provider.refresh = () => {};

    await provider._runCoverageChecks(
      "workspace",
      "repo",
      dependencies.length,
      { report() {} },
      { isCancellationRequested: false }
    );

    assert.strictEqual(api.calls.length, 2);
    assert.deepStrictEqual(
      provider._fullTrees[0].dependencies.map((dependency) => dependency.cloudsmithStatus),
      [CLOUDSMITH_COVERAGE_STATUS.FOUND, CLOUDSMITH_COVERAGE_STATUS.FOUND]
    );
  });

  test("multiple resolved versions remain distinct and a popular package cannot starve another dependency", async () => {
    const dependencies = [
      createDependency("popular", "1.0.0"),
      createDependency("popular", "2.0.0"),
      createDependency("other", "3.0.0"),
    ];
    const api = createLookupApi((endpoint) => {
      const url = new URL(endpoint, "https://api.cloudsmith.io/v1/");
      const query = url.searchParams.get("query");
      const page = Number(url.searchParams.get("page"));
      const dependency = dependencies.find((candidate) => (
        query.includes(`name:${candidate.name}`) && query.includes(`version:${candidate.version}`)
      ));
      if (dependency.name === "popular" && dependency.version === "1.0.0" && page === 1) {
        return lookupPage(Array.from({ length: 100 }, (_, index) => ({
          name: "popular",
          version: `9.0.${index}`,
          format: "npm",
        })), 1, 2, 101);
      }
      return lookupPage([{
        name: dependency.name,
        version: dependency.version,
        format: "npm",
        slug_perm: `${dependency.name}-${dependency.version}`,
      }], page, page, page === 2 ? 101 : 1, 100);
    });
    const provider = new DependencyHealthProvider(createContext(), null, {
      createCloudsmithAPI: () => api,
    });
    provider._fullTrees = [{ ecosystem: "npm", sourceFile: "package-lock.json", dependencies }];
    provider._displayTrees = cloneTrees(provider._fullTrees);
    provider.refresh = () => {};

    await provider._runCoverageChecks(
      "workspace",
      "repo",
      dependencies.length,
      { report() {} },
      { isCancellationRequested: false }
    );

    const evaluated = provider._fullTrees[0].dependencies;
    assert.deepStrictEqual(
      evaluated.map((dependency) => `${dependency.name}@${dependency.version}:${dependency.cloudsmithStatus}`),
      ["popular@1.0.0:FOUND", "popular@2.0.0:FOUND", "other@3.0.0:FOUND"]
    );
    assert.deepStrictEqual(
      evaluated.map((dependency) => dependency.cloudsmithPackage.version),
      ["1.0.0", "2.0.0", "3.0.0"]
    );
  });

  test("pagination terminates at the safety limit and remains incomplete", async () => {
    const api = createLookupApi((endpoint) => {
      const page = Number(new URL(endpoint, "https://api.cloudsmith.io/v1/").searchParams.get("page"));
      return lookupPage([{ name: "other", version: "1.0.0" }], page, 101, 101, 1);
    });

    const result = await lookupExactDependency({
      api,
      cloudsmithWorkspace: "workspace",
      cloudsmithRepo: "repo",
      dependency: createDependency("left-pad", "1.0.0"),
      token: { isCancellationRequested: false },
    });

    assert.strictEqual(result.status, CLOUDSMITH_COVERAGE_STATUS.LOOKUP_INCOMPLETE);
    assert.strictEqual(result.pagesFetched, 100);
    assert.strictEqual(api.calls.length, 100);
  });

  test("matchCoverageCandidates returns null when fallback results do not match the dependency name", () => {
    const match = matchCoverageCandidates(
      [
        { name: "left-pad-plus", version: "1.0.0", format: "npm" },
        { name: "pad-left", version: "1.0.0", format: "npm" },
      ],
      createDependency("left-pad", "1.0.0")
    );

    assert.strictEqual(match, null);
  });

  test("matchCoverageCandidates refuses a name-only fallback when versions differ", () => {
    const nameOnlyMatch = { name: "left-pad", version: "1.1.0", format: "npm" };
    const match = matchCoverageCandidates(
      [
        { name: "left-pad-plus", version: "1.0.0", format: "npm" },
        nameOnlyMatch,
      ],
      createDependency("left-pad", "1.0.0")
    );

    assert.strictEqual(match, null);
  });

  test("matchCoverageCandidates rejects an exact name and version from another format", () => {
    const match = matchCoverageCandidates(
      [{ name: "left-pad", version: "1.0.0", format: "python" }],
      createDependency("left-pad", "1.0.0", "npm")
    );

    assert.strictEqual(match, null);
  });

  test("compliance dedup preserves occurrences and uncertainty over absence", () => {
    const sourceA = { kind: "manifest", uri: "file:///workspace/a/package.json", range: null };
    const sourceB = { kind: "manifest", uri: "file:///workspace/b/package.json", range: null };
    const base = {
      name: "left-pad",
      version: "1.0.0",
      legacyVersion: "1.0.0",
      declaredConstraint: "^1.0.0",
      resolvedVersion: null,
      versionState: DEPENDENCY_VERSION_STATES.RANGE,
      format: "npm",
      ecosystem: "npm",
      isDirect: true,
      sourceManifest: sourceA,
    };
    const report = buildComplianceReportData("workspace", [
      { ...base, cloudsmithStatus: CLOUDSMITH_COVERAGE_STATUS.ABSENT },
      { ...base, cloudsmithStatus: CLOUDSMITH_COVERAGE_STATUS.UNRESOLVED },
      {
        ...base,
        sourceManifest: sourceB,
        cloudsmithStatus: CLOUDSMITH_COVERAGE_STATUS.ABSENT,
      },
    ], { scanDate: "2026-08-09T00:00:00.000Z" });

    assert.strictEqual(report.summary.total, 2);
    assert.strictEqual(report.summary.unresolved, 1);
    assert.strictEqual(report.summary.notFound, 1);
  });

  test("npm fixture flows from adapter resolution through exact lookup to health node", async () => {
    const result = await runFixtureThroughLookupAndNode(
      "npm",
      "npm",
      "express",
      {
        name: "express",
        version: "4.18.2",
        format: "npm",
        namespace: "workspace",
        repository: "repository",
        slug_perm: "express/4.18.2",
        status_str: "Completed",
      }
    );

    assert.strictEqual(result.dependency.declaredConstraint, "^4.18.2");
    assert.strictEqual(result.dependency.resolvedVersion, "4.18.2");
    assert.strictEqual(result.node.declaredVersion, "4.18.2");
  });

  test("Python fixture flows from lock resolution through exact lookup to health node", async () => {
    const result = await runFixtureThroughLookupAndNode(
      "python",
      "python",
      "fastapi",
      {
        name: "fastapi",
        version: "0.111.0",
        format: "python",
        namespace: "workspace",
        repository: "repository",
        slug_perm: "fastapi/0.111.0",
        status_str: "Completed",
      }
    );

    assert.strictEqual(result.dependency.resolvedVersion, "0.111.0");
    assert.strictEqual(result.node.declaredVersion, "0.111.0");
  });

  test("Maven fixture flows from dependency-tree resolution through exact lookup to health node", async () => {
    const result = await runFixtureThroughLookupAndNode(
      "maven",
      "maven",
      "org.springframework.boot:spring-boot-starter-web",
      {
        name: "spring-boot-starter-web",
        version: "3.2.0",
        format: "maven",
        namespace: "workspace",
        repository: "repository",
        slug_perm: "spring-boot-starter-web/3.2.0",
        status_str: "Completed",
        identifiers: { group_id: "org.springframework.boot" },
      }
    );

    assert.strictEqual(result.dependency.declaredConstraint, "3.2.0");
    assert.strictEqual(result.dependency.resolvedVersion, "3.2.0");
  });

  test("range-only Python fixture flows to an unresolved health node without lookup", async () => {
    const workspace = path.join(__dirname, "fixtures", "python-unresolved");
    const registry = createDefaultDependencyAdapterRegistry();
    const detection = (await registry.detect(workspace)).find((entry) => entry.ecosystem === "python");
    const adapterResult = await registry.parse(detection, { workspaceFolder: workspace });
    const dependency = adapterResult.dependencies.find((entry) => entry.name === "requests");

    assert.ok(dependency);
    assert.strictEqual(dependency.declaredConstraint, ">=2.0,<3.0");
    assert.strictEqual(dependency.resolvedVersion, null);
    const lookup = await lookupExactDependency({
      api: { async getWithHeaders() { throw new Error("range-only dependency must not be queried"); } },
      cloudsmithWorkspace: "workspace",
      cloudsmithRepo: "repository",
      dependency,
    });
    const node = new DependencyHealthNode({
      ...dependency,
      cloudsmithStatus: lookup.status,
      cloudsmithPackage: lookup.package,
    }, {});

    assert.strictEqual(lookup.status, CLOUDSMITH_COVERAGE_STATUS.UNRESOLVED);
    assert.strictEqual(node.state, "unresolved");
  });

  test("_runLicenseEnrichment flushes multiple progress patches in one refresh", async () => {
    const provider = new DependencyHealthProvider(createContext(), null, {
      enrichLicenses: async (_dependencies, options = {}) => {
        options.onProgress(new Map([
          ["workspace:repo:left-pad/1.0.0", { spdx: "MIT" }],
        ]));
        options.onProgress(new Map([
          ["workspace:repo:left-pad/1.0.0", { spdx: "Apache-2.0" }],
        ]));
      },
    });

    const trees = [{
      ecosystem: "npm",
      sourceFile: "package-lock.json",
      dependencies: [createFoundDependency("left-pad", "1.0.0")],
    }];
    provider._fullTrees = cloneTrees(trees);
    provider._displayTrees = cloneTrees(trees);

    let rebuildCount = 0;
    let refreshCount = 0;
    provider._rebuildSummary = () => {
      rebuildCount += 1;
    };
    provider.refresh = () => {
      refreshCount += 1;
    };

    await provider._runLicenseEnrichment(provider._fullTrees[0].dependencies, { isCancellationRequested: false });

    assert.strictEqual(rebuildCount, 1);
    assert.strictEqual(refreshCount, 1);
    assert.strictEqual(provider._fullTrees[0].dependencies[0].license.spdx, "Apache-2.0");
    assert.strictEqual(provider._displayTrees[0].dependencies[0].license.spdx, "Apache-2.0");
  });

  test("pullSingleDependency refreshes coverage after a successful single-package pull", async () => {
    const originalWithProgress = vscode.window.withProgress;
    const originalShowInformationMessage = vscode.window.showInformationMessage;
    const originalShowErrorMessage = vscode.window.showErrorMessage;
    const notifications = [];
    let refreshArgs = null;

    vscode.window.withProgress = async (_options, task) => task(
      { report() {} },
      {
        onCancellationRequested() {
          return { dispose() {} };
        },
      }
    );
    vscode.window.showInformationMessage = async (message) => {
      notifications.push(message);
    };
    vscode.window.showErrorMessage = async (message) => {
      notifications.push(`error:${message}`);
    };

    try {
      const provider = new DependencyHealthProvider(createContext(), null, {
        upstreamPullService: {
          async prepareSingle({ dependency }) {
            return {
              workspace: "workspace-a",
              repository: { slug: "repo-b" },
              dependency,
              plan: { skippedDependencies: [] },
            };
          },
          async execute() {
            return {
              canceled: false,
              pullResult: {
                total: 1,
                cached: 1,
                alreadyExisted: 0,
                notFound: 0,
                formatMismatched: 0,
                errors: 0,
                networkErrors: 0,
                authFailed: 0,
                skipped: 0,
                details: [{
                  status: "cached",
                  dependency: {
                    name: "requests",
                    version: "2.31.0",
                    format: "python",
                  },
                }],
              },
            };
          },
        },
      });

      provider.lastWorkspace = "workspace-a";
      provider.lastRepo = "repo-a";
      provider._updateContexts = async () => {};
      provider.refresh = () => {};
      provider._refreshSingleDependencyAfterPull = async (workspace, repo, dependency) => {
        refreshArgs = { workspace, repo, dependency };
      };

      await provider.pullSingleDependency({
        name: "requests",
        version: "2.31.0",
        format: "python",
        ecosystem: "python",
      });

      assert.deepStrictEqual(refreshArgs, {
        workspace: "workspace-a",
        repo: "repo-b",
        dependency: {
          name: "requests",
          version: "2.31.0",
          format: "python",
          ecosystem: "python",
        },
      });
      assert.deepStrictEqual(notifications, ["requests@2.31.0 cached in repo-b"]);
    } finally {
      vscode.window.withProgress = originalWithProgress;
      vscode.window.showInformationMessage = originalShowInformationMessage;
      vscode.window.showErrorMessage = originalShowErrorMessage;
    }
  });
});

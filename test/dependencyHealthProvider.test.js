const assert = require("assert");
const vscode = require("vscode");
const {
  DependencyHealthProvider,
  SCAN_STATES,
  matchCoverageCandidates,
} = require("../views/dependencyHealthProvider");
const { normalizePackageName } = require("../util/packageNameNormalizer");

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

  function buildCoverageIndex(dependencies) {
    const index = new Map();

    for (const dependency of dependencies) {
      const nameKey = normalizePackageName(dependency.name, dependency.format);
      const versionKey = dependency.version.toLowerCase();
      if (!index.has(nameKey)) {
        index.set(nameKey, new Map());
      }
      index.get(nameKey).set(versionKey, [{
        name: dependency.name,
        version: dependency.version,
      }]);
    }

    return index;
  }

  setup(() => {
    DependencyHealthProvider.packageIndexCache.clear();
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
    provider._fetchPackageIndex = async () => ({
      error: null,
      tooLarge: false,
      index: buildCoverageIndex(dependencies),
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

  test("_runCoverageChecks fetches package indices for multiple formats in parallel", async () => {
    const provider = new DependencyHealthProvider(createContext());
    const npmDependency = createDependency("left-pad", "1.0.0", "npm");
    const pythonDependency = createDependency("requests", "2.31.0", "python");

    provider._fullTrees = [
      {
        ecosystem: "npm",
        sourceFile: "package-lock.json",
        dependencies: [npmDependency],
      },
      {
        ecosystem: "python",
        sourceFile: "requirements.txt",
        dependencies: [pythonDependency],
      },
    ];
    provider._displayTrees = cloneTrees(provider._fullTrees);

    const resolvers = new Map();
    let inFlight = 0;
    let maxInFlight = 0;

    provider._rebuildSummary = () => {};
    provider.refresh = () => {};
    provider._fetchPackageIndex = async (_workspace, _repo, format) => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);

      return new Promise((resolve) => {
        resolvers.set(format, () => {
          inFlight -= 1;
          const dependency = format === "npm" ? npmDependency : pythonDependency;
          resolve({
            error: null,
            tooLarge: false,
            index: buildCoverageIndex([dependency]),
          });
        });
      });
    };

    const runPromise = provider._runCoverageChecks(
      "workspace",
      "repo",
      2,
      { report() {} },
      { isCancellationRequested: false }
    );

    await new Promise((resolve) => setImmediate(resolve));
    assert.strictEqual(maxInFlight, 2);

    resolvers.get("npm")();
    resolvers.get("python")();
    await runPromise;
  });

  test("_fetchPackageIndex fetches remaining pages concurrently after page one", async () => {
    const provider = new DependencyHealthProvider(createContext());
    const requestedPages = [];
    const pageResolvers = new Map();

    provider._fetchSinglePage = async (_workspace, _repo, _format, page) => {
      requestedPages.push(page);
      if (page === 1) {
        return {
          error: null,
          pagination: {
            count: 3,
            pageTotal: 3,
          },
          data: [{
            name: "page-one",
            version: "1.0.0",
          }],
        };
      }

      return new Promise((resolve) => {
        pageResolvers.set(page, resolve);
      });
    };

    const fetchPromise = provider._fetchPackageIndex("workspace", "repo", "npm");
    await new Promise((resolve) => setImmediate(resolve));

    assert.deepStrictEqual(requestedPages, [1, 2, 3]);

    pageResolvers.get(2)({
      error: null,
      data: [{
        name: "page-two",
        version: "1.0.0",
      }],
    });
    pageResolvers.get(3)({
      error: null,
      data: [{
        name: "page-three",
        version: "1.0.0",
      }],
    });

    const result = await fetchPromise;
    assert.strictEqual(result.error, null);
    assert.strictEqual(result.totalCount, 3);
    assert.strictEqual(result.index.get("page-two").has("1.0.0"), true);
    assert.strictEqual(result.index.get("page-three").has("1.0.0"), true);
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

  test("matchCoverageCandidates falls back to a name match when versions differ", () => {
    const nameOnlyMatch = { name: "left-pad", version: "1.1.0", format: "npm" };
    const match = matchCoverageCandidates(
      [
        { name: "left-pad-plus", version: "1.0.0", format: "npm" },
        nameOnlyMatch,
      ],
      createDependency("left-pad", "1.0.0")
    );

    assert.strictEqual(match, nameOnlyMatch);
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

// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const { registerDependencyHealthCommands } = require("../commands/dependencyHealth");

function deferred() {
  let resolve;
  const promise = new Promise(resolvePromise => { resolve = resolvePromise; });
  return { promise, resolve };
}

class FakeCancellationTokenSource {
  constructor() {
    const listeners = new Set();
    this.token = {
      isCancellationRequested: false,
      onCancellationRequested(listener) {
        listeners.add(listener);
        return { dispose() { listeners.delete(listener); } };
      },
    };
    this._listeners = listeners;
  }

  cancel() {
    if (this.token.isCancellationRequested) return;
    this.token.isCancellationRequested = true;
    for (const listener of [...this._listeners]) listener();
  }

  dispose() {
    this._listeners.clear();
  }
}

function createHarness(options = {}) {
  const handlers = new Map();
  const connectionListeners = new Set();
  let current = options.connected !== false;
  const connectionManager = {
    onDidChange(listener) {
      connectionListeners.add(listener);
      return { dispose() { connectionListeners.delete(listener); } };
    },
  };
  const account = Object.freeze({ activationId: "activation-a", accountEpoch: 1 });
  const workspaceAccess = {
    context: {},
    connectionManager,
    workspaceContextProjector: {
      begin: () => ({}),
      project: async () => {},
    },
    captureAccount: () => (current ? account : null),
    isAccountCurrent: () => current,
    createCloudsmithAPI: () => ({}),
    fetchWorkspaces: async () => ({
      items: [{ slug: "workspace-a", name: "Workspace A" }],
      complete: true,
    }),
    normalizedWorkspaceName: workspace => workspace.name,
    replaceCollectionItems: (result, items) => ({ ...result, items }),
    setHasMultipleWorkspacesContext: async () => {},
    fetchWorkspaceRepositories: async () => ({
      items: [{ slug: "repo-a", name: "Repo A" }],
      complete: true,
      stale: false,
    }),
    formatApiError: error => error.message,
    vscode: {
      window: { showErrorMessage() {}, showWarningMessage() {} },
      QuickPickItemKind: { Separator: 1 },
    },
  };
  const scans = [];
  const mutations = [];
  let successful = options.successful === true;
  let scanRunning = options.scanRunning === true;
  let dependencyOperationRunning = options.dependencyOperationRunning === true;
  const provider = {
    hasSuccessfulScan: () => successful,
    isScanRunning: () => scanRunning,
    isDependencyOperationRunning: () => dependencyOperationRunning,
    async rescan(initialScan) { return initialScan(); },
    async scan(workspace, repository, projectFolder) {
      scans.push({ workspace, repository, projectFolder });
    },
    cycleViewMode() { mutations.push("cycle"); },
    setViewMode(value) { mutations.push(`view:${value}`); },
    setFilterMode(value) { mutations.push(`filter:${value}`); },
    clearFilter() { mutations.push("filter:clear"); },
    pullDependencies() { mutations.push("pull:all"); },
    getLastSuccessfulScope: () => ({
      workspace: "workspace-a",
      repository: "repo-a",
      projectFolder: "/project-a",
    }),
    getReportData: () => null,
  };
  const quickPick = options.showQuickPick || (async items => items[0]);
  const vscode = {
    CancellationTokenSource: FakeCancellationTokenSource,
    QuickPickItemKind: { Separator: 1 },
    commands: { async executeCommand() {} },
    workspace: {
      workspaceFolders: (options.folders || []).map(folderPath => ({
        name: folderPath.split("/").pop(),
        uri: { fsPath: folderPath },
      })),
      getConfiguration: () => ({
        get(key) {
          if (key === "defaultWorkspace") return "workspace-a";
          return null;
        },
      }),
    },
    window: {
      showQuickPick: quickPick,
      showOpenDialog: options.showOpenDialog || (async () => null),
      showWarningMessage() {},
      showInformationMessage() {},
      showErrorMessage() {},
      createQuickPick: options.createQuickPick,
    },
  };
  const disposable = registerDependencyHealthCommands({
    registerCommand(id, handler) {
      handlers.set(id, handler);
      return { dispose() { handlers.delete(id); } };
    },
    vscode,
    workspaceAccess,
    dependencyHealthProvider: provider,
    complianceReportProvider: { show() {} },
    packageAdapters: {},
    isCurrentDependencySelection: () => true,
    FILTER_MODES: {
      VULNERABLE: "vulnerable",
      UNCOVERED: "uncovered",
      RESTRICTIVE_LICENSE: "restrictive",
      POLICY_VIOLATION: "policy",
    },
    SORT_MODES: {
      ALPHABETICAL: "alphabetical",
      SEVERITY: "severity",
      COVERAGE: "coverage",
    },
  });
  return {
    handlers,
    scans,
    mutations,
    provider,
    workspaceAccess,
    dispose: () => disposable.dispose(),
    setSuccessful(value) { successful = value; },
    setScanRunning(value) { scanRunning = value; },
    setDependencyOperationRunning(value) { dependencyOperationRunning = value; },
    stale() {
      current = false;
      for (const listener of [...connectionListeners]) listener({});
    },
  };
}

suite("Dependency command runtime state", () => {
  test("initial scan resolves zero, one, and multiple project folders without first-folder ambiguity", async () => {
    const zero = createHarness({
      folders: [],
      showQuickPick: async items => items.find(item => item.action === "browse") || items[0],
      showOpenDialog: async () => [{ fsPath: "/fresh-project" }],
    });
    await zero.handlers.get("cloudsmith-vsc.scanDependencies")();
    assert.deepStrictEqual(zero.scans, [{
      workspace: "workspace-a",
      repository: null,
      projectFolder: "/fresh-project",
    }]);
    zero.dispose();

    const one = createHarness({ folders: ["/only-project"] });
    await one.handlers.get("cloudsmith-vsc.scanDependencies")();
    assert.deepStrictEqual(one.scans, [{
      workspace: "workspace-a",
      repository: null,
      projectFolder: "/only-project",
    }]);
    one.dispose();

    const multi = createHarness({
      folders: ["/project-a", "/project-b"],
      showQuickPick: async items => items.find(item => item.folderPath === "/project-b") || items[0],
    });
    await multi.handlers.get("cloudsmith-vsc.scanDependencies")();
    assert.deepStrictEqual(multi.scans, [{
      workspace: "workspace-a",
      repository: null,
      projectFolder: "/project-b",
    }]);
    multi.dispose();
  });

  test("multiple-folder selection cancels silently when the account changes", async () => {
    const pickerStarted = deferred();
    let projectPickerToken = null;
    const harness = createHarness({
      folders: ["/project-a", "/project-b"],
      showQuickPick: async (items, options, token) => {
        if (options?.placeHolder === "Select a project folder to scan") {
          projectPickerToken = token;
          pickerStarted.resolve();
          return new Promise(resolve => {
            token.onCancellationRequested(() => resolve(items[1]));
          });
        }
        return items[0];
      },
    });

    const pending = harness.handlers.get("cloudsmith-vsc.scanDependencies")();
    await pickerStarted.promise;
    harness.stale();
    await pending;

    assert.strictEqual(projectPickerToken.isCancellationRequested, true);
    assert.deepStrictEqual(harness.scans, []);
    harness.dispose();
  });

  test("scope change rejects disconnected, scanless, scanning, and dependency-operation states", async () => {
    const cases = [
      { connected: false, successful: true },
      { connected: true, successful: false },
      { connected: true, successful: true, scanRunning: true },
      { connected: true, successful: true, dependencyOperationRunning: true },
    ];
    for (const testCase of cases) {
      const harness = createHarness({ ...testCase, folders: ["/project-a"] });
      await harness.handlers.get("cloudsmith-vsc.changeDependencyScanScope")();
      assert.deepStrictEqual(harness.scans, [], JSON.stringify(testCase));
      harness.dispose();
    }
  });

  test("scope-change folder selection cancels on account change and rechecks operation authority", async () => {
    const pickerStarted = deferred();
    let folderToken = null;
    const staleHarness = createHarness({
      successful: true,
      folders: ["/project-a"],
      showQuickPick: async (items, options, token) => {
        if (options?.placeHolder === "Select a project folder to scan") {
          folderToken = token;
          pickerStarted.resolve();
          return new Promise(resolve => {
            token.onCancellationRequested(() => resolve(items[0]));
          });
        }
        if (options?.placeHolder === "Select a scan scope") {
          return items.find(item => item.scope === "all");
        }
        return items[0];
      },
    });
    const pending = staleHarness.handlers.get("cloudsmith-vsc.changeDependencyScanScope")();
    await pickerStarted.promise;
    staleHarness.stale();
    await pending;
    assert.strictEqual(folderToken.isCancellationRequested, true);
    assert.deepStrictEqual(staleHarness.scans, []);
    staleHarness.dispose();

    let operationHarness;
    operationHarness = createHarness({
      successful: true,
      folders: ["/project-a"],
      showQuickPick: async (items, options) => {
        if (options?.placeHolder === "Select a scan scope") {
          return items.find(item => item.scope === "all");
        }
        if (options?.placeHolder === "Select a project folder to scan") {
          operationHarness.setDependencyOperationRunning(true);
          return items[0];
        }
        return items[0];
      },
    });
    await operationHarness.handlers.get("cloudsmith-vsc.changeDependencyScanScope")();
    assert.deepStrictEqual(operationHarness.scans, []);
    operationHarness.dispose();
  });

  test("view, filter, cycle, sort, and pull mutations reject inapplicable direct invocation", async () => {
    const commandIds = [
      "cloudsmith-vsc.pullDependencies",
      "cloudsmith-vsc.cycleDepView",
      "cloudsmith-vsc.cycleDepViewDirect",
      "cloudsmith-vsc.cycleDepViewFlat",
      "cloudsmith-vsc.cycleDepViewTree",
      "cloudsmith-vsc.depViewDirect",
      "cloudsmith-vsc.depViewFlat",
      "cloudsmith-vsc.depViewTree",
      "cloudsmith-vsc.depFilterVulnerable",
      "cloudsmith-vsc.depFilterUncovered",
      "cloudsmith-vsc.depFilterRestrictiveLicense",
      "cloudsmith-vsc.depFilterPolicyViolation",
      "cloudsmith-vsc.depFilterClear",
      "cloudsmith-vsc.depSortFilter",
      "cloudsmith-vsc.depSortFilterActive",
    ];
    for (const state of [
      { connected: false, successful: true },
      { connected: true, successful: false },
      { connected: true, successful: true, scanRunning: true },
      { connected: true, successful: true, dependencyOperationRunning: true },
    ]) {
      const harness = createHarness(state);
      for (const commandId of commandIds) {
        await harness.handlers.get(commandId)();
      }
      assert.deepStrictEqual(harness.mutations, [], JSON.stringify(state));
      harness.dispose();
    }
  });

  test("sort and filter picker ignores a second accept while the first mutation is pending", async () => {
    const acceptListeners = new Set();
    const hideListeners = new Set();
    const subscribe = listeners => listener => {
      listeners.add(listener);
      return { dispose() { listeners.delete(listener); } };
    };
    const quickPick = {
      items: [],
      selectedItems: [],
      busy: false,
      onDidAccept: subscribe(acceptListeners),
      onDidHide: subscribe(hideListeners),
      show() {},
      hide() { for (const listener of [...hideListeners]) listener(); },
      dispose() {},
    };
    const harness = createHarness({
      successful: true,
      createQuickPick: () => quickPick,
    });
    const mutation = deferred();
    let filterMode = null;
    let setCalls = 0;
    let clearCalls = 0;
    harness.provider.getSortMode = () => "alphabetical";
    harness.provider.getFilterMode = () => filterMode;
    harness.provider.setFilterMode = async value => {
      setCalls += 1;
      filterMode = value;
      await mutation.promise;
    };
    harness.provider.clearFilter = async () => { clearCalls += 1; };

    const picker = harness.handlers.get("cloudsmith-vsc.depSortFilter")();
    await Promise.resolve();
    quickPick.selectedItems = [quickPick.items.find(item => (
      item.action === "filter" && item.value === "vulnerable"
    ))];
    const accept = [...acceptListeners][0];
    const first = accept();
    await Promise.resolve();
    const second = accept();
    mutation.resolve();
    await Promise.all([first, second]);

    assert.strictEqual(setCalls, 1);
    assert.strictEqual(clearCalls, 0);
    assert.strictEqual(filterMode, "vulnerable");
    assert.strictEqual(quickPick.busy, false);
    quickPick.hide();
    await picker;
    harness.dispose();
  });
});

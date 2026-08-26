const assert = require("assert");
const vscode = require("vscode");
const { CloudsmithProvider } = require("../views/cloudsmithProvider");
const { getWorkspaces } = require("../util/workspaceAccess");
const { captureAccount, isAccountCurrent } = require("../util/accountOperation");
const { formatApiError } = require("../util/errorFormatter");
const { replaceCollectionItems } = require("../util/paginatedFetch");
const { fetchWorkspaces, normalizedWorkspaceName } = require("../util/workspaceFetcher");
const { getWorkspaceContextProjector } = require("../util/workspaceContextProjector");
const { RepositoryTerminalNode } = require("../models/repositoryTerminalNode");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");
const { registerOwnedOpenPackageCommand } = require("./helpers/registeredPackageAction");

function workspaceSuccess(items) {
  return apiSuccess(items, {
    headers: {
      "x-pagination-page": "1",
      "x-pagination-pagetotal": "1",
      "x-pagination-pagesize": "500",
      "x-pagination-count": String(items.length),
    },
  });
}

function collectionResult(items, options = {}) {
  const complete = options.complete !== false;
  const failures = options.failures || [];
  return {
    items,
    complete,
    incomplete: !complete,
    partial: !complete && items.length > 0,
    cancelled: options.cancelled === true,
    continuation: null,
    failures,
    failureCount: failures.length,
    termination: complete ? "exhausted" : (options.termination || "request_failed"),
    pageCount: options.pageCount ?? (items.length > 0 ? 1 : 0),
    requestCount: options.requestCount ?? (items.length > 0 ? 1 : failures.length),
    duplicateCount: 0,
    pagination: null,
    stale: false,
  };
}

function deferred() {
  let resolve;
  const promise = new Promise(res => { resolve = res; });
  return { promise, resolve };
}

function createConnectionManager(overrides = {}) {
  const listeners = new Set();
  let state = {
    activationId: "activation-a",
    accountEpoch: 1,
    credentialPresent: true,
    sessionConnected: true,
    status: "connected",
    error: null,
    ...overrides,
  };
  return {
    getState() { return Object.freeze({ ...state }); },
    setState(next) {
      state = { ...state, ...next };
      for (const listener of listeners) listener(Object.freeze({ ...state }));
    },
    onDidChange(listener) {
      listeners.add(listener);
      return { dispose() { listeners.delete(listener); } };
    },
  };
}

function createVulnerabilityStateService() {
  const listeners = new Set();
  const unknown = Object.freeze({ status: "unknown", records: [], count: null, detected: true });
  return {
    prime() { return unknown; },
    peek() { return unknown; },
    onDidChange(listener) {
      listeners.add(listener);
      return { dispose() { listeners.delete(listener); } };
    },
    emit(identity, status = "unknown") {
      const state = status === "complete-vulnerable"
        ? Object.freeze({ status, records: Object.freeze([{}]), count: 1, complete: true })
        : Object.freeze({ ...unknown, status });
      const event = Object.freeze({ identity, state });
      for (const listener of [...listeners]) listener(event);
    },
  };
}

suite("CloudsmithProvider", () => {
  let originalExecuteCommand;
  let originalGetConfiguration;
  let originalShowWarningMessage;
  let commands;
  let defaultWorkspace;
  let manager;

  test("same-context projection replaces a disposed projector and settles in-flight work", async () => {
    const context = {};
    const started = deferred();
    const release = deferred();
    const applied = [];
    const first = getWorkspaceContextProjector(context, {
      async executeCommand(_command, _key, value) {
        applied.push(`first:${value}`);
        started.resolve();
        await release.promise;
      },
    });
    const projection = first.project(true);
    await started.promise;

    let disposalSettled = false;
    const disposal = first.dispose().then(() => { disposalSettled = true; });
    await Promise.resolve();
    assert.strictEqual(disposalSettled, false);

    const second = getWorkspaceContextProjector(context, {
      async executeCommand(_command, _key, value) {
        applied.push(`second:${value}`);
      },
    });
    assert.notStrictEqual(second, first);
    release.resolve();
    assert.strictEqual(await projection, false);
    await disposal;
    assert.strictEqual(disposalSettled, true);
    assert.strictEqual(await second.project(false), true);
    assert.deepStrictEqual(applied, ["first:true", "second:false"]);
    await second.dispose();
  });
  let context;

  setup(() => {
    originalExecuteCommand = vscode.commands.executeCommand;
    originalGetConfiguration = vscode.workspace.getConfiguration;
    originalShowWarningMessage = vscode.window.showWarningMessage;
    commands = [];
    defaultWorkspace = "";
    manager = createConnectionManager();
    context = {
      globalState: {
        get() { return undefined; },
        async update() { throw new Error("main-tree workspace data must not persist"); },
      },
    };
    vscode.commands.executeCommand = async (...args) => { commands.push(args); };
    vscode.workspace.getConfiguration = () => ({
      get(key) { return key === "defaultWorkspace" ? defaultWorkspace : ""; },
    });
    vscode.window.showWarningMessage = async () => undefined;
  });

  teardown(() => {
    vscode.commands.executeCommand = originalExecuteCommand;
    vscode.workspace.getConfiguration = originalGetConfiguration;
    vscode.window.showWarningMessage = originalShowWarningMessage;
  });

  function createProvider(apiGet, options = {}) {
    return new CloudsmithProvider(context, {
      connectionManager: manager,
      createCloudsmithAPI: () => ({ get: apiGet }),
      upstreamInventory: { getAllUpstreamData: async () => null },
      ...options,
    });
  }

  test("requires and shares one narrow upstream inventory facade", () => {
    assert.throws(
      () => new CloudsmithProvider(context, { connectionManager: manager }),
      /upstream inventory facade/
    );
    const upstreamInventory = { getAllUpstreamData: async () => null };
    const provider = createProvider(async () => apiSuccess([]), { upstreamInventory });
    const node = provider._createRepositoryNode(
      { slug: "repo", slug_perm: "repo", name: "Repo" },
      "workspace"
    );
    assert.strictEqual(node._upstreamInventory, upstreamInventory);
    provider.dispose();
  });

  test("fails closed to the signed-out root without making an API request", async () => {
    manager.setState({
      credentialPresent: false,
      sessionConnected: false,
      status: "absent",
    });
    let requests = 0;
    const provider = createProvider(async () => { requests += 1; });
    const treeView = { message: "old" };
    provider.setTreeView(treeView);

    const nodes = await provider.getChildren();

    assert.strictEqual(requests, 0);
    assert.strictEqual(nodes.length, 1);
    assert.strictEqual(nodes[0].getTreeItem().label, "Connect to Cloudsmith");
    assert.ok(commands.some(call => (
      call[0] === "setContext"
      && call[1] === "cloudsmith.hasMultipleWorkspaces"
      && call[2] === false
    )));
  });

  test("projects startup and terminal connection states without API work", async () => {
    manager.setState({
      credentialPresent: null,
      sessionConnected: false,
      status: "indeterminate",
      error: null,
    });
    let apiCalls = 0;
    const provider = createProvider(async () => {
      apiCalls += 1;
      return apiSuccess([]);
    });
    assert.deepStrictEqual(
      await provider.getChildren({ getChildren: () => ["private result"] }),
      []
    );
    const cases = [
      [{ status: "indeterminate", credentialPresent: null, error: null }, "Connecting to Cloudsmith...", null],
      [{ status: "validating", credentialPresent: true, error: null }, "Connecting to Cloudsmith...", null],
      [{ status: "absent", credentialPresent: false, error: null }, "Connect to Cloudsmith", "cloudsmith-vsc.configureCredentials"],
      [{ status: "failed", credentialPresent: true, error: { message: "unsafe raw detail" } }, "Connection failed", "cloudsmith-vsc.configureCredentials"],
      [{ status: "indeterminate", credentialPresent: null, error: { message: "SecretStorage csa_secret" } }, "Could not check the connection", "cloudsmith-vsc.connectCloudsmith"],
    ];
    for (const [state, label, command] of cases) {
      manager.setState({ ...state, sessionConnected: false });
      const item = (await provider.getChildren())[0].getTreeItem();
      assert.strictEqual(item.label, label);
      assert.strictEqual(item.command?.command || null, command);
      if (label !== "Connect to Cloudsmith") {
        assert.strictEqual(JSON.stringify(item).includes("Set up Cloudsmith authentication"), false);
      }
      assert.strictEqual(JSON.stringify(item).includes("csa_secret"), false);
    }
    manager.setState({ status: "disposed", credentialPresent: null, sessionConnected: false });
    assert.deepStrictEqual(await provider.getChildren(), []);
    assert.strictEqual(apiCalls, 0);
    provider.dispose();
    assert.deepStrictEqual(await provider.getChildren(), []);
  });

  test("refreshes from validating to connected and only then starts workspace loading", async () => {
    manager.setState({ status: "validating", credentialPresent: true, sessionConnected: false });
    let fetches = 0;
    const provider = createProvider(async () => apiSuccess([]), {
      fetchWorkspaces: async () => {
        fetches += 1;
        return collectionResult([]);
      },
    });
    let refreshes = 0;
    provider.onDidChangeTreeData(() => { refreshes += 1; });

    assert.strictEqual((await provider.getChildren())[0].getTreeItem().label, "Connecting to Cloudsmith...");
    assert.strictEqual(fetches, 0);
    manager.setState({ status: "connected", credentialPresent: true, sessionConnected: true });
    assert.strictEqual(refreshes, 1);
    await provider.getChildren();
    assert.strictEqual(fetches, 1);
    provider.dispose();
    manager.setState({ status: "absent", credentialPresent: false, sessionConnected: false });
    assert.strictEqual(refreshes, 1);
    assert.deepStrictEqual(await provider.getChildren(), []);
  });

  test("waits for an orchestrated account reset before refreshing connected Account B", async () => {
    const fetchedEpochs = [];
    const provider = createProvider(async () => { throw new Error("not used"); }, {
      accountResetOrchestrated: true,
      fetchWorkspaces: async () => {
        const epoch = manager.getState().accountEpoch;
        fetchedEpochs.push(epoch);
        return collectionResult([{
          slug: `workspace-${epoch}`,
          name: `Workspace ${epoch}`,
        }]);
      },
    });
    let refreshes = 0;
    provider.onDidChangeTreeData(() => { refreshes += 1; });

    const accountANodes = await provider.getWorkspaces();
    assert.strictEqual(accountANodes[0].workspace, "workspace-1");
    manager.setState({ accountEpoch: 2 });
    assert.strictEqual(refreshes, 1, "Account A must disappear immediately");
    assert.strictEqual(
      (await provider.getChildren())[0].getTreeItem().label,
      "Connecting to Cloudsmith..."
    );
    assert.deepStrictEqual(fetchedEpochs, [1], "Account B must not load before reset");

    provider._workspaceCache.clear();
    assert.strictEqual(provider.completeAccountReset(manager.getState()), true);
    assert.strictEqual(refreshes, 2);
    const accountBNodes = await provider.getWorkspaces();
    assert.strictEqual(accountBNodes[0].workspace, "workspace-2");
    assert.deepStrictEqual(fetchedEpochs, [1, 2]);
  });

  test("an Account A fetch cannot publish after an orchestrated Account B switch", async () => {
    const accountA = deferred();
    let fetchStarted = false;
    const provider = createProvider(async () => { throw new Error("not used"); }, {
      accountResetOrchestrated: true,
      fetchWorkspaces: async () => {
        fetchStarted = true;
        return accountA.promise;
      },
    });
    const pending = provider.getWorkspaces();
    while (!fetchStarted) await new Promise(resolve => setImmediate(resolve));

    manager.setState({ accountEpoch: 2 });
    accountA.resolve(collectionResult([{ slug: "account-a", name: "Account A" }]));

    assert.deepStrictEqual(await pending, []);
    assert.strictEqual(
      (await provider.getChildren())[0].getTreeItem().label,
      "Connecting to Cloudsmith..."
    );
  });

  test("refreshes an account identity change when no external reset orchestrator is used", () => {
    const provider = createProvider(async () => workspaceSuccess([]));
    let refreshes = 0;
    provider.onDidChangeTreeData(() => { refreshes += 1; });

    manager.setState({ accountEpoch: 2 });

    assert.strictEqual(refreshes, 1);
  });

  test("connection roots supersede loading ownership for connecting, absent, and failed", async () => {
    const cases = [
      [{ status: "validating", credentialPresent: true }, "Connecting to Cloudsmith..."],
      [{ status: "absent", credentialPresent: false }, "Connect to Cloudsmith"],
      [{ status: "failed", credentialPresent: true }, "Connection failed"],
    ];
    for (const [state, expectedLabel] of cases) {
      manager = createConnectionManager();
      const response = deferred();
      const provider = createProvider(async () => { throw new Error("not used"); }, {
        fetchWorkspaces: async () => response.promise,
      });
      const treeView = {};
      provider.setTreeView(treeView);
      const oldLoad = provider.getWorkspaces();
      assert.strictEqual(treeView.message, "Loading...");

      manager.setState({ ...state, sessionConnected: false });
      assert.strictEqual(treeView.message, undefined);
      assert.strictEqual(provider._loadingOperationId, null);
      assert.strictEqual((await provider.getChildren())[0].getTreeItem().label, expectedLabel);

      response.resolve(collectionResult([{ slug: "old", name: "Old" }]));
      assert.deepStrictEqual(await oldLoad, []);
      assert.strictEqual(treeView.message, undefined);
      assert.strictEqual(provider._loadingOperationId, null);
      provider.dispose();
    }
  });

  test("a stale operation finally cannot clear a newer loading operation", async () => {
    const accountA = deferred();
    const accountB = deferred();
    let fetches = 0;
    const provider = createProvider(async () => { throw new Error("not used"); }, {
      fetchWorkspaces: async () => {
        fetches += 1;
        return fetches === 1 ? accountA.promise : accountB.promise;
      },
    });
    const treeView = {};
    provider.setTreeView(treeView);
    const operationA = provider.getWorkspaces();
    assert.strictEqual(treeView.message, "Loading...");
    while (fetches === 0) await new Promise(resolve => setImmediate(resolve));

    manager.setState({ status: "validating", sessionConnected: false });
    assert.strictEqual(treeView.message, undefined);
    manager.setState({ status: "connected", sessionConnected: true });
    const operationB = provider.getWorkspaces();
    const operationBLoadingId = provider._loadingOperationId;
    assert.strictEqual(treeView.message, "Loading...");

    accountA.resolve(collectionResult([{ slug: "account-a", name: "Account A" }]));
    assert.deepStrictEqual(await operationA, []);
    assert.strictEqual(provider._loadingOperationId, operationBLoadingId);
    assert.strictEqual(treeView.message, "Loading...");

    accountB.resolve(collectionResult([{ slug: "account-b", name: "Account B" }]));
    const nodes = await operationB;
    assert.strictEqual(nodes[0].workspace, "account-b");
    assert.strictEqual(provider._loadingOperationId, null);
    assert.strictEqual(treeView.message, undefined);
  });

  test("reports malformed workspace payloads as load failures", async () => {
    const provider = createProvider(async (_endpoint, options) => {
      const malformed = [{ name: "Missing stable slug" }];
      assert.strictEqual(options.validate(malformed), false);
      return apiFailure("invalid_response", { status: 200 });
    });

    const nodes = await provider.getWorkspaces();

    assert.strictEqual(nodes.length, 1);
    assert.strictEqual(nodes[0].getTreeItem().label, "Could not load workspaces");
  });

  test("always clears Loading when the workspace API factory throws", async () => {
    const provider = createProvider(async () => workspaceSuccess([]), {
      createCloudsmithAPI() {
        throw new Error("unexpected factory failure");
      },
    });
    const treeView = {};
    provider.setTreeView(treeView);

    const nodes = await provider.getWorkspaces();

    assert.strictEqual(nodes[0].getTreeItem().label, "Could not load workspaces");
    assert.strictEqual(treeView.message, undefined);
  });

  test("always clears Loading when workspace projection rejects", async () => {
    const workspaceContextProjector = {
      begin() { return Object.freeze({}); },
      async project() { throw new Error("projection failed"); },
    };
    const provider = createProvider(async () => workspaceSuccess([
      { slug: "workspace-a", name: "Workspace A" },
      { slug: "workspace-b", name: "Workspace B" },
    ]), { workspaceContextProjector });
    const treeView = {};
    provider.setTreeView(treeView);

    const nodes = await provider.getWorkspaces();

    assert.strictEqual(nodes[0].getTreeItem().label, "Could not load workspaces");
    assert.strictEqual(treeView.message, undefined);
  });

  test("always clears Loading when the repository fetcher throws", async () => {
    const provider = createProvider(async () => apiSuccess({ usage: {} }), {
      fetchWorkspaceRepositories: async () => {
        throw new Error("unexpected repository failure");
      },
    });
    const treeView = {};
    provider.setTreeView(treeView);

    const nodes = await provider.getRepositories("workspace-a");

    assert.strictEqual(nodes[0].getTreeItem().label, "Could not load repositories");
    assert.strictEqual(treeView.message, undefined);
  });

  test("keeps workspace multiplicity conservative while enumeration is pending", async () => {
    const pending = deferred();
    const provider = createProvider(async () => { throw new Error("not used"); }, {
      fetchWorkspaces: async () => pending.promise,
    });

    const resultPromise = provider.getWorkspaces();
    while (!commands.some(call => (
      call[1] === "cloudsmith.hasMultipleWorkspaces" && call[2] === true
    ))) {
      await new Promise(resolve => setImmediate(resolve));
    }
    assert.strictEqual(commands.some(call => call[2] === false), false);

    pending.resolve(collectionResult([{ slug: "workspace-a", name: "Workspace A" }]));
    const nodes = await resultPromise;
    assert.strictEqual(nodes.length, 1);
    assert.strictEqual(commands.at(-1)[2], false);
  });

  test("keeps workspace multiplicity conservative after enumeration failure", async () => {
    const provider = createProvider(async () => { throw new Error("not used"); }, {
      fetchWorkspaces: async () => { throw new Error("workspace fetch failed"); },
    });

    const nodes = await provider.getWorkspaces();

    assert.strictEqual(nodes[0].getTreeItem().label, "Could not load workspaces");
    assert.strictEqual(commands.at(-1)[2], true);
  });

  test("refresh projects conservative multiplicity while connected", async () => {
    const provider = createProvider(async () => workspaceSuccess([]));

    provider.refresh();
    await provider._workspaceContextProjector.whenIdle();

    assert.strictEqual(commands.at(-1)[2], true);
  });

  test("publishes validated workspace nodes from an account-scoped memory cache", async () => {
    let requests = 0;
    const provider = createProvider(async (_endpoint, options) => {
      requests += 1;
      const payload = [{ slug: "workspace-a", name: "Workspace A", api_key: "not persisted" }];
      assert.strictEqual(options.validate(payload), true);
      return workspaceSuccess(payload);
    });

    const first = await provider.getWorkspaces();
    const second = await provider.getWorkspaces();

    assert.strictEqual(requests, 1);
    assert.strictEqual(first[0].workspace, "workspace-a");
    assert.strictEqual(second[0].workspace, "workspace-a");
  });

  test("discards a workspace response completed after the account changes", async () => {
    const pending = deferred();
    const provider = createProvider(async () => pending.promise);
    const resultPromise = provider.getWorkspaces();
    await new Promise(resolve => setImmediate(resolve));
    manager.setState({ accountEpoch: 2 });
    pending.resolve(workspaceSuccess([{ slug: "old-account", name: "Old Account" }]));

    assert.deepStrictEqual(await resultPromise, []);
    assert.strictEqual(commands.some(call => call[2] === true), true);
  });

  test("guards repository and quota publication with one captured account", async () => {
    defaultWorkspace = "workspace-a";
    const quota = deferred();
    const provider = createProvider(async () => quota.promise, {
      fetchWorkspaceRepositories: async () => ({
        ...collectionResult([{ slug: "repo-a", name: "Repo A" }]),
        stale: false,
      }),
    });
    const resultPromise = provider.getChildren();
    await new Promise(resolve => setImmediate(resolve));
    manager.setState({ accountEpoch: 2 });
    quota.resolve(apiSuccess({ usage: {} }));

    assert.deepStrictEqual(await resultPromise, []);
  });

  test("serializes context projection and clears Loading after a stale completion", async () => {
    let releaseTrue;
    const trueProjection = new Promise(resolve => { releaseTrue = resolve; });
    const applied = [];
    vscode.commands.executeCommand = async (_command, key, value) => {
      if (key === "cloudsmith.hasMultipleWorkspaces" && value === true) {
        await trueProjection;
      }
      applied.push(value);
    };
    const provider = createProvider(async () => workspaceSuccess([
      { slug: "workspace-a", name: "Workspace A" },
      { slug: "workspace-b", name: "Workspace B" },
    ]));
    const treeView = {};
    provider.setTreeView(treeView);
    const pending = provider.getWorkspaces();
    while (treeView.message !== "Loading...") {
      await new Promise(resolve => setImmediate(resolve));
    }
    await new Promise(resolve => setImmediate(resolve));
    manager.setState({ accountEpoch: 2 });
    provider.refresh();
    releaseTrue();

    assert.deepStrictEqual(await pending, []);
    await provider._workspaceContextProjector.whenIdle();
    assert.strictEqual(applied.at(-1), true);
    assert.strictEqual(treeView.message, undefined);
  });

  test("shares projection ordering with command helpers across an account change", async () => {
    const trueStarted = deferred();
    const releaseTrue = deferred();
    const applied = [];
    vscode.commands.executeCommand = async (_command, key, value) => {
      if (key === "cloudsmith.hasMultipleWorkspaces" && value === true) {
        trueStarted.resolve();
        await releaseTrue.promise;
      }
      applied.push(value);
    };
    const workspaceContextProjector = getWorkspaceContextProjector(context);
    const provider = createProvider(async () => apiSuccess([]), {
      workspaceContextProjector,
    });
    const pending = getWorkspaces({
      context,
      vscode,
      connectionManager: manager,
      workspaceContextProjector,
      captureAccount,
      isAccountCurrent,
      createCloudsmithAPI: () => ({
        get: async () => apiSuccess([
          { slug: "old-a", name: "Old A" },
          { slug: "old-b", name: "Old B" },
        ]),
      }),
      fetchWorkspaces,
      normalizedWorkspaceName,
      replaceCollectionItems,
      setHasMultipleWorkspacesContext: value => workspaceContextProjector.project(value),
      formatApiError,
    });

    await trueStarted.promise;
    manager.setState({ accountEpoch: 2 });
    provider.refresh();
    releaseTrue.resolve();

    assert.strictEqual(await pending, null);
    await workspaceContextProjector.whenIdle();
    assert.deepStrictEqual(applied, [true, true]);
    assert.strictEqual(applied.at(-1), true);
  });

  test("publishes partial workspaces truthfully and does not cache them", async () => {
    let fetches = 0;
    const provider = createProvider(async () => { throw new Error("not used"); }, {
      fetchWorkspaces: async () => {
        fetches += 1;
        return collectionResult(
          [{ slug: "workspace-a", name: "Workspace A" }],
          {
            complete: false,
            failures: [{ error: { message: "Page 2 failed." } }],
            requestCount: 2,
          }
        );
      },
    });

    const first = await provider.getWorkspaces();
    const second = await provider.getWorkspaces();

    assert.strictEqual(fetches, 2);
    assert.strictEqual(first[0].workspace, "workspace-a");
    assert.strictEqual(first[1].getTreeItem().label, "Workspaces are incomplete");
    assert.strictEqual(second[1].getTreeItem().description, "1 loaded");
    assert.ok(commands.some(call => call[2] === true));
  });

  test("keeps partial default-workspace repositories and appends an incomplete marker", async () => {
    defaultWorkspace = "workspace-a";
    const provider = createProvider(async () => apiSuccess({ usage: {} }), {
      fetchWorkspaceRepositories: async () => collectionResult(
        [{ slug: "repo-a", name: "Repo A" }],
        {
          complete: false,
          failures: [{ error: { message: "Page 2 failed." } }],
          requestCount: 2,
        }
      ),
    });

    const children = await provider.getRepositories("workspace-a");

    assert.strictEqual(children[0].getTreeItem().contextValue, "workspaceInfo");
    assert.strictEqual(children[1].name, "Repo A");
    assert.strictEqual(children[2].getTreeItem().label, "Repositories are incomplete");
  });

  test("falls back when a default workspace returns zero unproven repositories", async () => {
    defaultWorkspace = "workspace-a";
    let fallback;
    const provider = createProvider(async () => workspaceSuccess([
      { slug: "workspace-b", name: "Workspace B" },
    ]), {
      fetchWorkspaceRepositories: async () => collectionResult([], {
        complete: false,
        failures: [{ error: { message: "Page 1 failed." } }],
        requestCount: 1,
      }),
    });
    provider.setDefaultWorkspaceFallbackHandler(value => { fallback = value; });

    const children = await provider.getRepositories("workspace-a");

    assert.strictEqual(fallback, "workspace-a");
    assert.strictEqual(children[0].workspace, "workspace-b");
  });

  test("targeted and root refresh retain the node until authoritative replacement", async () => {
    const provider = createProvider(async () => workspaceSuccess([]));
    const node = provider._createRepositoryNode(
      { slug: "repo-a", slug_perm: "repo-a", name: "Repo A" },
      "workspace-a"
    );
    const events = [];
    const subscription = provider.onDidChangeTreeData(element => events.push(element));

    provider.refreshNode(node);
    assert.strictEqual(events[0], node);
    assert.strictEqual(node._disposed, false);

    provider.refresh();
    assert.strictEqual(node._disposed, false);

    await provider.getWorkspaces();
    assert.strictEqual(node._disposed, true);
    subscription.dispose();
  });

  test("registered Explorer package action remains live until refreshed root replacement", async function () {
    this.timeout(2000);
    defaultWorkspace = "workspace-a";
    const replacement = deferred();
    const provider = createProvider(async () => apiSuccess({ usage: {} }), {
      fetchWorkspaceRepositories: async () => replacement.promise,
      createPaginatedFetch: () => ({
        async fetchCollection() {
          return collectionResult([{
            namespace: "workspace-a",
            repository: "repo-a",
            name: "package-a",
            format: "npm",
            slug: "package-a",
            slug_perm: "package-a",
            version: "1.0.0",
            status_str: "Completed",
            is_copyable: true,
            uploaded_at: "2026-08-26T12:00:00Z",
          }]);
        },
      }),
      upstreamInventory: {
        async getAllUpstreamData() {
          return {
            upstreams: [],
            failedFormats: [],
            failures: [],
            unsupportedFormats: [],
            uninspectedFormats: [],
            state: "complete",
            complete: true,
          };
        },
      },
    });
    const repository = provider._createRepositoryNode(
      { slug: "repo-a", slug_perm: "repo-a", name: "Repo A" },
      "workspace-a"
    );
    const published = await provider.getChildren(repository);
    const packageNode = published.find(child => repository.ownsPackageSelection(child));
    assert.ok(packageNode, "the Explorer fixture must publish a package row");

    const openedUrls = [];
    const command = registerOwnedOpenPackageCommand({
      cloudsmithProvider: provider,
      connectionManager: manager,
      opened: openedUrls,
      targetUrl: "https://cloudsmith.example/packages/package-a",
    });
    let rootPublication;
    const replacementResult = collectionResult([
      { slug: "repo-b", slug_perm: "repo-b", name: "Repo B" },
    ]);

    try {
      provider.refresh();
      rootPublication = provider.getChildren();
      await new Promise(resolve => setImmediate(resolve));

      assert.strictEqual(provider.ownsPackageSelection(packageNode), true);
      await originalExecuteCommand(command.id, packageNode);
      assert.deepStrictEqual(
        openedUrls,
        ["https://cloudsmith.example/packages/package-a"],
        "a still-visible package action must remain live while root replacement is pending"
      );
      assert.strictEqual(provider.ownsPackageSelection(packageNode), true);

      replacement.resolve(replacementResult);
      const replacementRows = await rootPublication;
      const replacementRepository = replacementRows.find(row => row?.slug === "repo-b");
      assert.ok(replacementRepository, "the replacement repository must publish");
      assert.strictEqual(provider.ownsPackageSelection(packageNode), false);
      assert.strictEqual(provider.ownsRepositorySelection(replacementRepository), true);

      await originalExecuteCommand(command.id, packageNode);
      assert.strictEqual(openedUrls.length, 1, "replaced package rows must be rejected");

      manager.setState({ accountEpoch: 2 });
      assert.strictEqual(
        provider.ownsRepositorySelection(replacementRepository),
        false,
        "account replacement must revoke the currently published repository"
      );
    } finally {
      replacement.resolve(replacementResult);
      if (rootPublication) await rootPublication.catch(() => {});
      command.dispose();
      provider.dispose();
    }
  });

  test("invalid tree elements fail at provider validation without weak-state mutation", () => {
    const provider = createProvider(async () => workspaceSuccess([]));
    const invalidElements = [undefined, null, "string", 42, false, Object.freeze({})];

    for (const element of invalidElements) {
      assert.throws(
        () => provider.getTreeItem(element),
        error => (
          error instanceof TypeError
          && error.message === "Invalid tree item projection."
        )
      );
      assert.strictEqual(provider.getParent(element), undefined);
      assert.strictEqual(provider._treeItemFallbacks.has(element), false);
    }
  });

  test("stale package projection errors cannot repopulate repository fallback state", async () => {
    const provider = createProvider(async () => workspaceSuccess([]));
    const repository = provider._createRepositoryNode(
      { slug: "repo-a", slug_perm: "repo-a", name: "Repo A" },
      "workspace-a"
    );
    let projectionError = null;
    const packageNode = {
      getTreeItem() {
        if (projectionError) throw projectionError;
        return new vscode.TreeItem("package-a");
      },
      getChildren() { return []; },
    };
    repository._packageState = Object.freeze({
      ...repository._packageState,
      initialized: true,
      nodes: Object.freeze([packageNode]),
    });
    repository.getChildren = async () => [packageNode];

    assert.deepStrictEqual(await provider.getChildren(repository), [packageNode]);
    projectionError = new Error("stale package projection");
    provider.refresh();
    await provider.getWorkspaces();

    assert.strictEqual(provider.getParent(packageNode), repository);
    assert.throws(() => provider.getTreeItem(packageNode), error => error === projectionError);
    assert.strictEqual(provider._treeItemFallbacks.has(packageNode), false);
    assert.strictEqual(provider._repositoryProjectionState.has(repository), false);
  });

  test("repository publication rethrows unrelated child projection errors", async () => {
    const provider = createProvider(async () => workspaceSuccess([]));
    const repository = provider._createRepositoryNode(
      { slug: "repo-a", slug_perm: "repo-a", name: "Repo A" },
      "workspace-a"
    );
    const projectionError = new Error("unrelated metadata projection");
    const metadataNode = {
      getTreeItem() { throw projectionError; },
      getChildren() { return []; },
    };
    repository.getChildren = async () => [metadataNode];

    await assert.rejects(
      provider.getChildren(repository),
      error => error === projectionError
    );
    assert.strictEqual(provider._treeItemFallbacks.has(metadataNode), false);
    assert.strictEqual(provider._repositoryProjectionState.has(repository), false);
  });

  test("repository publication rejects malformed child values", async () => {
    const provider = createProvider(async () => workspaceSuccess([]));
    const repository = provider._createRepositoryNode(
      { slug: "repo-a", slug_perm: "repo-a", name: "Repo A" },
      "workspace-a"
    );
    repository.getChildren = async () => [null, 42];

    await assert.rejects(
      provider.getChildren(repository),
      error => (
        error instanceof TypeError
        && error.message === "Invalid repository child projection."
      )
    );
    assert.strictEqual(provider._repositoryProjectionState.has(repository), false);
  });

  test("FUX-002 contains current repository child rejection with a retryable terminal outcome", async () => {
    const provider = createProvider(async () => workspaceSuccess([]));
    const repository = provider._createRepositoryNode(
      { slug: "repo-a", slug_perm: "repo-a", name: "Repo A" },
      "workspace-a"
    );
    repository.getChildren = async () => {
      throw new Error("private upstream response detail");
    };

    const children = await provider.getChildren(repository);
    assert.strictEqual(children.length, 1);
    const item = provider.getTreeItem(children[0]);
    assert.strictEqual(item.contextValue, "repositoryPackagesFailed");
    assert.strictEqual(item.description, "Retry");
    assert.strictEqual(item.command.command, "cloudsmith-vsc.refreshView");
    assert.strictEqual(JSON.stringify(item).includes("private upstream response detail"), false);

    provider.refresh();
    await provider.getWorkspaces();
    assert.deepStrictEqual(
      await provider.getChildren(repository),
      [],
      "an invalidated repository must not publish a stale terminal row"
    );
  });

  test("FUX-002 contains package projection rejection and preserves valid package rows", async () => {
    const provider = createProvider(async () => workspaceSuccess([]));
    const repository = provider._createRepositoryNode(
      { slug: "repo-a", slug_perm: "repo-a", name: "Repo A" },
      "workspace-a"
    );
    const metadata = {
      getTreeItem() { return new vscode.TreeItem("Upstreams: 1 active"); },
      getChildren() { return []; },
    };
    const validPackage = {
      name: "valid-package",
      getTreeItem() { return new vscode.TreeItem("valid-package"); },
      getChildren() { return []; },
    };
    const rejectedPackage = {
      name: "rejected-package",
      getTreeItem() { throw new Error("private package projection detail"); },
      getChildren() { return []; },
    };
    repository._packageState = Object.freeze({
      ...repository._packageState,
      initialized: true,
      nodes: Object.freeze([validPackage, rejectedPackage]),
    });
    repository.getChildren = async () => [metadata, validPackage, rejectedPackage];

    const children = await provider.getChildren(repository);
    assert.ok(children.includes(metadata));
    assert.ok(children.includes(validPackage));
    assert.strictEqual(children.includes(rejectedPackage), false);
    const items = children.map(child => provider.getTreeItem(child));
    assert.ok(items.some(item => item.label === "valid-package"));
    const terminal = items.find(item => item.contextValue === "repositoryPackagesPartial");
    assert.ok(terminal, "one rejected package projection must publish partial state");
    assert.strictEqual(
      items[0],
      terminal,
      "partial package authority must precede supplementary repository metadata"
    );
    assert.strictEqual(terminal.description, "Retry");
    assert.strictEqual(JSON.stringify(terminal).includes("private package projection detail"), false);

    const allRejected = provider._createRepositoryNode(
      { slug: "repo-b", slug_perm: "repo-b", name: "Repo B" },
      "workspace-a"
    );
    const rejectedOnly = {
      getTreeItem() { return { label: "" }; },
      getChildren() { return []; },
    };
    allRejected._packageState = Object.freeze({
      ...allRejected._packageState,
      initialized: true,
      nodes: Object.freeze([rejectedOnly]),
    });
    allRejected.getChildren = async () => [
      metadata,
      rejectedOnly,
      new RepositoryTerminalNode("partial", allRejected),
    ];

    const contained = await provider.getChildren(allRejected);
    assert.ok(contained.includes(metadata), "valid metadata remains visible");
    assert.strictEqual(contained.includes(rejectedOnly), false);
    assert.strictEqual(
      provider.getTreeItem(contained[0]).contextValue,
      "repositoryPackagesFailed",
      "failed package authority must precede supplementary repository metadata"
    );
    assert.ok(contained.some(child => (
      provider.getTreeItem(child).contextValue === "repositoryPackagesFailed"
    )), "metadata-only publication must gain a failed package terminal row");
    assert.strictEqual(
      contained.some(child => (
        provider.getTreeItem(child).contextValue === "repositoryPackagesPartial"
      )),
      false,
      "zero projected packages cannot retain copy claiming loaded packages are shown"
    );
  });

  test("FUX-002 active zero-row load-more publishes loading without a false failure", async () => {
    const provider = createProvider(async () => workspaceSuccess([]));
    const repository = provider._createRepositoryNode(
      { slug: "repo-a", slug_perm: "repo-a", name: "Repo A" },
      "workspace-a"
    );
    const loading = {
      getTreeItem() {
        return new vscode.TreeItem("Loading more packages...");
      },
      getChildren() { return []; },
    };
    repository.getChildren = async () => [loading];
    repository.isPackageLoadActive = () => true;

    const children = await provider.getChildren(repository);
    const items = children.map(child => provider.getTreeItem(child));

    assert.deepStrictEqual(items.map(item => item.label), ["Loading more packages..."]);
    assert.strictEqual(items.some(item => (
      item.contextValue === "repositoryPackagesFailed"
    )), false);
  });

  test("FUX-002 real Extension Host tree publication ledger cannot settle blank", async () => {
    assert.match(vscode.version, /^\d+\.\d+\.\d+/);
    const provider = createProvider(async () => workspaceSuccess([]));
    const repository = provider._createRepositoryNode(
      { slug: "ledger-repo", slug_perm: "ledger-repo", name: "Ledger Repo" },
      "workspace-a"
    );
    const collectedPackage = {
      name: "collected-package",
      getTreeItem() { return new vscode.TreeItem("collected-package"); },
      getChildren() { return []; },
    };
    repository._packageState = Object.freeze({
      ...repository._packageState,
      initialized: true,
      nodes: Object.freeze([collectedPackage]),
      complete: true,
      termination: "exhausted",
    });
    assert.strictEqual(repository.ownsPackageSelection(collectedPackage), true);
    // Simulate the audited boundary: a successful package collection was
    // retained by the model, but its provider child publication was suppressed.
    repository.getChildren = async () => [];
    const ledger = [];
    const treeDataProvider = {
      getChildren(element) {
        if (!element) {
          ledger.push({ phase: "root", count: 1 });
          return [repository];
        }
        return Promise.resolve(provider.getChildren(element)).then((children) => {
          ledger.push({ phase: "children", count: children.length });
          return children;
        });
      },
      getTreeItem(element) {
        const item = provider.getTreeItem(element);
        ledger.push({
          phase: "treeItem",
          label: typeof item.label === "string" ? item.label : item.label?.label,
          contextValue: item.contextValue || null,
        });
        return item;
      },
    };

    try {
      const roots = await treeDataProvider.getChildren();
      roots.forEach(element => treeDataProvider.getTreeItem(element));
      const children = await treeDataProvider.getChildren(repository);
      children.forEach(element => treeDataProvider.getTreeItem(element));
      const childResolution = ledger.find(entry => entry.phase === "children");
      assert.ok(childResolution, `production tree adapter did not request children: ${JSON.stringify(ledger)}`);
      assert.strictEqual(childResolution.count, 1);
      assert.ok(ledger.some(entry => (
        entry.phase === "treeItem"
        && entry.contextValue === "repositoryPackagesFailed"
      )), `real TreeView did not publish the terminal item: ${JSON.stringify(ledger)}`);
    } finally {
      provider.dispose();
    }
  });

  test("real Extension Host publishes package content before repository metadata", async function () {
    this.timeout(3000);
    assert.match(vscode.version, /^\d+\.\d+\.\d+/);
    const metadataGate = deferred();
    let packageRequests = 0;
    const packageResult = collectionResult([{
      namespace: "workspace-a",
      repository: "repo-a",
      name: "package-a",
      format: "npm",
      slug: "package-a",
      slug_perm: "package-a",
      version: "1.0.0",
      status_str: "Completed",
      is_copyable: true,
    }], {
      complete: false,
      failures: [{ error: new Error("page 2 unavailable") }],
      termination: "request_failed",
      pageCount: 1,
      requestCount: 2,
    });
    const metadataResult = {
      upstreams: [],
      failedFormats: [],
      failures: [],
      unsupportedFormats: [],
      uninspectedFormats: [],
      state: "complete",
      complete: true,
    };
    const provider = createProvider(async () => apiSuccess({ usage: {} }), {
      createPaginatedFetch: () => ({
        async fetchCollection() {
          packageRequests += 1;
          return packageResult;
        },
      }),
      upstreamInventory: {
        getAllUpstreamData() {
          return metadataGate.promise;
        },
      },
    });
    const repository = provider._createRepositoryNode(
      {
        slug: "repo-a",
        slug_perm: "repo-a",
        name: "Repo A",
        storage_region: "us-ohio",
      },
      "workspace-a"
    );
    const childPublications = [];
    const publishRepository = async () => {
      const children = await provider.getChildren(repository);
      childPublications.push(children);
      children.forEach(child => provider.getTreeItem(child));
      return children;
    };
    const providerEvents = provider.onDidChangeTreeData(element => {
      if (element === repository) void publishRepository();
    });

    try {
      await Promise.race([
        publishRepository(),
        new Promise((_resolve, reject) => setTimeout(
          () => reject(new Error("package publication waited for supplementary metadata")),
          500
        )),
      ]);

      assert.ok(childPublications.length > 0, "production provider did not publish repository children");
      const primaryPublication = childPublications.at(-1);
      const packageIndex = primaryPublication.findIndex(
        child => repository.ownsPackageSelection(child)
      );
      const terminalIndex = primaryPublication.findIndex(child => (
        child?.terminalOutcome?.kind === "partial"
      ));
      const metadataIndex = primaryPublication.findIndex(child => (
        !repository.ownsPackageSelection(child) && !child.terminalOutcome
      ));
      assert.ok(packageIndex >= 0, "the actual package collection did not reach host publication");
      assert.ok(terminalIndex >= 0, "partial package truth did not reach host publication");
      assert.ok(
        terminalIndex < packageIndex,
        "partial package truth must precede retained package rows"
      );
      assert.strictEqual(
        metadataIndex,
        -1,
        "deferred supplementary metadata must not hold or contaminate primary publication"
      );
      assert.strictEqual(packageRequests, 1);

      const publicationCount = childPublications.length;
      metadataGate.resolve(metadataResult);
      for (let turn = 0; turn < 40 && childPublications.length === publicationCount; turn += 1) {
        await new Promise(resolve => setTimeout(resolve, 25));
      }
      assert.ok(
        childPublications.length > publicationCount,
        "metadata settlement did not refresh the real TreeView"
      );
      const enrichedPublication = childPublications.at(-1);
      assert.ok(enrichedPublication.some(child => (
        !repository.ownsPackageSelection(child) && !child.terminalOutcome
      )), "settled metadata did not reach host publication");
      assert.strictEqual(packageRequests, 1, "metadata refresh must reuse package authority");
    } finally {
      metadataGate.resolve(metadataResult);
      providerEvents.dispose();
      provider.dispose();
    }
  });

  test("vulnerability publication refreshes only the owned stable summary", async () => {
    const service = createVulnerabilityStateService();
    const provider = createProvider(async () => workspaceSuccess([]), {
      vulnerabilityStateService: service,
    });
    const repository = provider._createRepositoryNode(
      { slug: "repo-a", slug_perm: "repo-a", name: "Repo A" },
      "workspace-a"
    );
    const packageNode = repository._createPackageNode({
      namespace: "workspace-a",
      repository: "repo-a",
      name: "package-a",
      format: "npm",
      slug: "package-a",
      slug_perm: "package-a",
      version: "1.0.0",
      status_str: "Completed",
      num_vulnerabilities: 1,
    }, "packages");
    repository._packageState = Object.freeze({
      ...repository._packageState,
      nodes: Object.freeze([packageNode]),
    });
    const firstChildren = packageNode.getChildren();
    const summary = firstChildren.find(child => child.getTreeItem().contextValue === "vulnerabilitySummary");
    assert.strictEqual(summary, packageNode.getChildren().find(
      child => child.getTreeItem().contextValue === "vulnerabilitySummary"
    ));
    const events = [];
    const reveals = [];
    let onExpand;
    let onCollapse;
    provider.setTreeView({
      onDidExpandElement(listener) { onExpand = listener; return { dispose() {} }; },
      onDidCollapseElement(listener) { onCollapse = listener; return { dispose() {} }; },
      async reveal(...args) { reveals.push(args); },
    });
    const subscription = provider.onDidChangeTreeData(element => events.push(element));
    onExpand({ element: summary });
    assert.strictEqual(provider.getParent(summary), packageNode);
    assert.strictEqual(provider.getParent(packageNode), repository);

    service.emit('["workspace-a","repo-a","package-a"]', "loading");
    await new Promise(resolve => setTimeout(resolve, 0));
    assert.deepStrictEqual(events, []);

    service.emit('["workspace-a","repo-a","package-a"]', "complete-vulnerable");
    service.emit('["workspace-a","repo-a","package-a"]', "complete-vulnerable");
    assert.deepStrictEqual(events, []);
    await new Promise(resolve => setTimeout(resolve, 0));

    assert.deepStrictEqual(events, [summary]);
    assert.deepStrictEqual(reveals, [[summary, { expand: true, focus: false, select: false }]]);
    assert.strictEqual(repository._disposed, false);

    onCollapse({ element: summary });
    events.length = 0;
    service.emit('["workspace-a","repo-a","package-a"]', "complete-vulnerable");
    await new Promise(resolve => setTimeout(resolve, 0));
    assert.deepStrictEqual(events, [summary]);
    assert.strictEqual(reveals.length, 1);

    events.length = 0;
    service.emit('["workspace-a","repo-a","package-a"]', "complete-vulnerable");
    provider.refresh();
    await provider.getWorkspaces();
    events.length = 0;
    await new Promise(resolve => setTimeout(resolve, 0));
    assert.deepStrictEqual(events, []);
    subscription.dispose();
  });

  test("cancelled default-workspace loading does not fall back or request quota", async () => {
    let apiCalls = 0;
    let workspaceFetches = 0;
    let fallback;
    const provider = createProvider(async () => {
      apiCalls += 1;
      return apiSuccess({ usage: {} });
    }, {
      fetchWorkspaces: async () => {
        workspaceFetches += 1;
        return collectionResult([], { complete: true });
      },
      fetchWorkspaceRepositories: async (_context, _workspace, options) => {
        assert.strictEqual(options.signal.aborted, false);
        return collectionResult([], {
          complete: false,
          cancelled: true,
          termination: "cancelled",
          requestCount: 1,
        });
      },
    });
    provider.setDefaultWorkspaceFallbackHandler(workspace => { fallback = workspace; });

    const children = await provider.getRepositories("workspace-a");

    assert.strictEqual(children.length, 1);
    assert.strictEqual(children[0].getTreeItem().label, "Repository loading cancelled");
    assert.strictEqual(fallback, undefined);
    assert.strictEqual(workspaceFetches, 0);
    assert.strictEqual(apiCalls, 0);
  });

  test("cancelled partial repositories survive without a quota request", async () => {
    let apiCalls = 0;
    const provider = createProvider(async () => {
      apiCalls += 1;
      return apiSuccess({ usage: {} });
    }, {
      fetchWorkspaceRepositories: async () => collectionResult(
        [{ slug: "repo-a", name: "Repo A" }],
        { complete: false, cancelled: true, termination: "cancelled", requestCount: 2 }
      ),
    });

    const children = await provider.getRepositories("workspace-a");

    assert.strictEqual(children[1].name, "Repo A");
    assert.strictEqual(children[2].getTreeItem().label, "Repositories are incomplete");
    assert.strictEqual(apiCalls, 0);
  });

  test("refresh aborts an in-flight default-workspace collection", async () => {
    const pending = deferred();
    let capturedSignal;
    let apiCalls = 0;
    const provider = createProvider(async () => {
      apiCalls += 1;
      return apiSuccess({ usage: {} });
    }, {
      fetchWorkspaceRepositories: async (_context, _workspace, options) => {
        capturedSignal = options.signal;
        return pending.promise;
      },
    });
    const resultPromise = provider.getRepositories("workspace-a");
    await new Promise(resolve => setImmediate(resolve));

    provider.refresh();
    assert.strictEqual(capturedSignal.aborted, true);
    pending.resolve(collectionResult([], {
      complete: false,
      cancelled: true,
      termination: "cancelled",
      requestCount: 1,
    }));

    assert.deepStrictEqual(await resultPromise, []);
    assert.strictEqual(apiCalls, 0);
  });

  test("refresh aborts an in-flight default-workspace quota request", async () => {
    const quota = deferred();
    let quotaSignal;
    const provider = createProvider(async (_endpoint, options) => {
      quotaSignal = options.signal;
      return quota.promise;
    }, {
      fetchWorkspaceRepositories: async () => collectionResult([
        { slug: "repo-a", name: "Repo A" },
      ]),
    });
    const resultPromise = provider.getRepositories("workspace-a");
    while (!quotaSignal) {
      await new Promise(resolve => setImmediate(resolve));
    }

    provider.refresh();
    assert.strictEqual(quotaSignal.aborted, true);
    quota.resolve(apiFailure("cancelled"));

    assert.deepStrictEqual(await resultPromise, []);
  });
});

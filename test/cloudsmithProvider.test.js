const assert = require("assert");
const vscode = require("vscode");
const { CloudsmithProvider } = require("../views/cloudsmithProvider");
const { getWorkspaces } = require("../extension");
const { getWorkspaceContextProjector } = require("../util/workspaceContextProjector");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");

function deferred() {
  let resolve;
  const promise = new Promise(res => { resolve = res; });
  return { promise, resolve };
}

function createConnectionManager(overrides = {}) {
  let state = {
    activationId: "activation-a",
    accountEpoch: 1,
    sessionConnected: true,
    ...overrides,
  };
  return {
    getState() { return Object.freeze({ ...state }); },
    setState(next) { state = { ...state, ...next }; },
  };
}

suite("CloudsmithProvider", () => {
  let originalExecuteCommand;
  let originalGetConfiguration;
  let originalShowWarningMessage;
  let commands;
  let defaultWorkspace;
  let manager;
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
      ...options,
    });
  }

  test("fails closed to the signed-out root without making an API request", async () => {
    manager.setState({ sessionConnected: false });
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
    const provider = createProvider(async () => apiSuccess([]), {
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
    const provider = createProvider(async () => apiSuccess([
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

  test("publishes validated workspace nodes from an account-scoped memory cache", async () => {
    let requests = 0;
    const provider = createProvider(async (_endpoint, options) => {
      requests += 1;
      const payload = [{ slug: "workspace-a", name: "Workspace A", api_key: "not persisted" }];
      assert.strictEqual(options.validate(payload), true);
      return apiSuccess(payload);
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
    pending.resolve(apiSuccess([{ slug: "old-account", name: "Old Account" }]));

    assert.deepStrictEqual(await resultPromise, []);
    assert.strictEqual(commands.some(call => call[2] === true), false);
  });

  test("guards repository and quota publication with one captured account", async () => {
    defaultWorkspace = "workspace-a";
    const quota = deferred();
    const provider = createProvider(async () => quota.promise, {
      fetchWorkspaceRepositories: async () => ({
        repositories: [{ slug: "repo-a", name: "Repo A" }],
        error: null,
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
    const provider = createProvider(async () => apiSuccess([
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
    assert.strictEqual(applied.at(-1), false);
    assert.strictEqual(treeView.message, undefined);
  });

  test("shares projection ordering with extension helpers across an account change", async () => {
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
    const pending = getWorkspaces(context, {
      connectionManager: manager,
      workspaceContextProjector,
      createCloudsmithAPI: () => ({
        get: async () => apiSuccess([
          { slug: "old-a", name: "Old A" },
          { slug: "old-b", name: "Old B" },
        ]),
      }),
    });

    await trueStarted.promise;
    manager.setState({ accountEpoch: 2 });
    provider.refresh();
    releaseTrue.resolve();

    assert.strictEqual(await pending, null);
    await workspaceContextProjector.whenIdle();
    assert.deepStrictEqual(applied, [true, false]);
    assert.strictEqual(applied.at(-1), false);
  });
});

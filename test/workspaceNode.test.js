const assert = require("assert");
const WorkspaceNode = require("../models/workspaceNode");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");

function createManager() {
  let state = { activationId: "activation-a", accountEpoch: 1, sessionConnected: true };
  return {
    getState() { return { ...state }; },
    setState(next) { state = { ...state, ...next }; },
  };
}

suite("WorkspaceNode", () => {
  let manager;
  let updates;
  let context;

  setup(() => {
    manager = createManager();
    updates = [];
    context = {
      globalState: {
        async update(key, value) { updates.push({ key, value }); },
      },
    };
  });

  function createNode(fetchWorkspaceRepositories, apiGet = async () => (
    apiFailure("forbidden", { status: 403 })
  )) {
    return new WorkspaceNode({ name: "Workspace A", slug: "workspace-a" }, context, {
      connectionManager: manager,
      createCloudsmithAPI: () => ({ get: apiGet }),
      fetchWorkspaceRepositories,
      createRepositoryNode: repo => ({ ...repo }),
    });
  }

  test("shows an error child when the first repository page fails", async () => {
    const node = createNode(async () => ({
      items: [],
      complete: false,
      incomplete: true,
      partial: false,
      failures: [{ error: apiFailure("server_error", { status: 500 }).error }],
      stale: false,
    }));

    const children = await node.getChildren();

    assert.strictEqual(children.length, 2);
    assert.strictEqual(children[1]._label, "Failed to load repositories");
    assert.strictEqual(updates.length, 0);
  });

  test("keeps fetched repositories in memory and never writes CloudsmithCache", async () => {
    const node = createNode(async () => ({
      items: [
        { name: "repo-a", slug: "repo-a" },
        { name: "repo-b", slug: "repo-b" },
      ],
      complete: true,
      incomplete: false,
      partial: false,
      failures: [],
      stale: false,
    }));

    const repos = await node.getRepositories();

    assert.deepStrictEqual(repos.map(repo => repo.name), ["repo-a", "repo-b"]);
    assert.strictEqual(updates.length, 0);
  });

  test("does not publish repositories completed after an account change", async () => {
    let release;
    const pendingFetch = new Promise(resolve => { release = resolve; });
    const node = createNode(async () => pendingFetch);
    const resultPromise = node.getRepositories();
    manager.setState({ accountEpoch: 2 });
    release({
      items: [{ name: "old", slug: "old" }],
      complete: true,
      failures: [],
      stale: false,
    });
    assert.deepStrictEqual(await resultPromise, []);
  });

  test("does not publish quota or repository children after an account change", async () => {
    let releaseQuota;
    const pendingQuota = new Promise(resolve => { releaseQuota = resolve; });
    let repositoryFetches = 0;
    const node = createNode(async () => {
      repositoryFetches += 1;
      return { items: [], complete: true, failures: [], stale: false };
    }, async () => pendingQuota);
    const resultPromise = node.getChildren();
    manager.setState({ accountEpoch: 2 });
    releaseQuota(apiSuccess({ usage: { storage: 1 } }));

    assert.deepStrictEqual(await resultPromise, []);
    assert.strictEqual(repositoryFetches, 0);
  });

  test("preserves repositories from successful pages and labels the collection incomplete", async () => {
    const created = [];
    const node = new WorkspaceNode({ name: "Workspace A", slug: "workspace-a" }, context, {
      connectionManager: manager,
      createCloudsmithAPI: () => ({ get: async () => apiFailure("forbidden", { status: 403 }) }),
      fetchWorkspaceRepositories: async () => ({
        items: [{ name: "repo-a", slug: "repo-a" }],
        complete: false,
        incomplete: true,
        partial: true,
        failures: [{ error: apiFailure("rate_limited", { status: 429 }).error }],
        stale: false,
      }),
      createRepositoryNode: (repo, workspace) => {
        const value = { ...repo, workspace };
        created.push(value);
        return value;
      },
    });

    const repositories = await node.getRepositories();

    assert.deepStrictEqual(created, [{ name: "repo-a", slug: "repo-a", workspace: "workspace-a" }]);
    assert.strictEqual(repositories[0].name, "repo-a");
    assert.strictEqual(repositories[1].getTreeItem().label, "Repository list is incomplete");
  });

  test("propagates its provider lifecycle signal to quota and repository requests", async () => {
    const controller = new AbortController();
    let quotaSignal;
    let repositorySignal;
    const node = new WorkspaceNode({ name: "Workspace A", slug: "workspace-a" }, context, {
      connectionManager: manager,
      signal: controller.signal,
      createCloudsmithAPI: () => ({
        get: async (_endpoint, options) => {
          quotaSignal = options.signal;
          return apiSuccess({ usage: {} });
        },
      }),
      fetchWorkspaceRepositories: async (_context, _workspace, options) => {
        repositorySignal = options.signal;
        return {
          items: [], complete: true, incomplete: false, partial: false, failures: [], stale: false,
        };
      },
    });

    await node.getChildren();
    assert.strictEqual(quotaSignal, controller.signal);
    assert.strictEqual(repositorySignal, controller.signal);
    controller.abort();
    assert.strictEqual(quotaSignal.aborted, true);
    assert.strictEqual(repositorySignal.aborted, true);
  });
});

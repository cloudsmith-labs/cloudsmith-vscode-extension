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
    });
  }

  test("shows an error child when the first repository page fails", async () => {
    const node = createNode(async () => ({
      repositories: [],
      error: apiFailure("server_error", { status: 500 }).error,
      warning: null,
      partial: false,
      stale: false,
    }));

    const children = await node.getChildren();

    assert.strictEqual(children.length, 2);
    assert.strictEqual(children[1]._label, "Failed to load repositories");
    assert.strictEqual(updates.length, 0);
  });

  test("keeps fetched repositories in memory and never writes CloudsmithCache", async () => {
    const node = createNode(async () => ({
      repositories: [
        { name: "repo-a", slug: "repo-a" },
        { name: "repo-b", slug: "repo-b" },
      ],
      error: null,
      warning: null,
      partial: false,
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
      repositories: [{ name: "old", slug: "old" }],
      error: null,
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
      return { repositories: [], error: null, stale: false };
    }, async () => pendingQuota);
    const resultPromise = node.getChildren();
    manager.setState({ accountEpoch: 2 });
    releaseQuota(apiSuccess({ usage: { storage: 1 } }));

    assert.deepStrictEqual(await resultPromise, []);
    assert.strictEqual(repositoryFetches, 0);
  });
});

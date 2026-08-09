const assert = require("assert");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const workspaceRepositoryFetcher = require("../util/workspaceRepositoryFetcher");
const WorkspaceNode = require("../models/workspaceNode");
const { apiFailure } = require("./apiResultHelpers");

suite("WorkspaceNode Test Suite", () => {
  let originalGet;
  let originalFetchWorkspaceRepositories;
  let cacheUpdates;
  let context;

  setup(() => {
    originalGet = CloudsmithAPI.prototype.get;
    originalFetchWorkspaceRepositories =
      workspaceRepositoryFetcher.fetchWorkspaceRepositories;
    cacheUpdates = [];
    context = {
      globalState: {
        update(key, value) {
          cacheUpdates.push({ key, value });
        },
      },
    };

    CloudsmithAPI.prototype.get = async () => apiFailure("forbidden", { status: 403 });
  });

  teardown(() => {
    CloudsmithAPI.prototype.get = originalGet;
    workspaceRepositoryFetcher.fetchWorkspaceRepositories =
      originalFetchWorkspaceRepositories;
  });

  test("shows an error child when the first repository page fails", async () => {
    workspaceRepositoryFetcher.fetchWorkspaceRepositories = async () => ({
      repositories: [],
      error: apiFailure("server_error", { status: 500 }).error,
      warning: null,
      partial: false,
    });

    const node = new WorkspaceNode(
      { name: "Workspace A", slug: "workspace-a" },
      context
    );

    const children = await node.getChildren();

    assert.strictEqual(children.length, 2);
    assert.strictEqual(children[1]._label, "Failed to load repositories");
    assert.strictEqual(cacheUpdates.length, 0);
  });

  test("updates the repository cache with fetched repositories", async () => {
    workspaceRepositoryFetcher.fetchWorkspaceRepositories = async () => ({
      repositories: [
        { name: "repo-a", slug: "repo-a" },
        { name: "repo-b", slug: "repo-b" },
      ],
      error: null,
      warning: null,
      partial: false,
    });

    const node = new WorkspaceNode(
      { name: "Workspace A", slug: "workspace-a" },
      context
    );

    const repos = await node.getRepositories();

    assert.strictEqual(repos.length, 2);
    assert.strictEqual(repos[0].name, "repo-a");
    assert.strictEqual(cacheUpdates.length, 1);
    assert.strictEqual(cacheUpdates[0].key, "CloudsmithCache");
    assert.deepStrictEqual(
      cacheUpdates[0].value.workspaces.map(repo => repo.slug),
      ["repo-a", "repo-b"]
    );
  });
});

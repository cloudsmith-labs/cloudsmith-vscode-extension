const assert = require("assert");
const vscode = require("vscode");
const { SearchProvider } = require("../views/searchProvider");
const { PaginatedFetch } = require("../util/paginatedFetch");

suite("SearchProvider Test Suite", () => {
  let originalWithProgress;
  let originalShowErrorMessage;
  let originalShowInformationMessage;
  let originalShowWarningMessage;
  let originalGetConfiguration;
  let originalFetchPage;
  let provider;

  const context = {
    secrets: {
      onDidChange() {},
      async get() {
        return "true";
      },
    },
  };

  setup(() => {
    provider = new SearchProvider(context);

    originalWithProgress = vscode.window.withProgress;
    originalShowErrorMessage = vscode.window.showErrorMessage;
    originalShowInformationMessage = vscode.window.showInformationMessage;
    originalShowWarningMessage = vscode.window.showWarningMessage;
    originalGetConfiguration = vscode.workspace.getConfiguration;
    originalFetchPage = PaginatedFetch.prototype.fetchPage;

    vscode.window.withProgress = async (_options, task) => task();
    vscode.window.showErrorMessage = async () => {};
    vscode.window.showInformationMessage = async () => {};
    vscode.window.showWarningMessage = async () => {};
    vscode.workspace.getConfiguration = () => ({
      get() {
        return 50;
      },
    });
    PaginatedFetch.prototype.fetchPage = async () => ({
      data: [{
        name: "artifact",
        format: "raw",
        repository: "repo-a",
        namespace: "workspace-a",
        status_str: "Completed",
        slug: "artifact-1",
        slug_perm: "artifact-1-perm",
        downloads: 0,
        version: "1.0.0",
        uploaded_at: "2026-03-25T00:00:00Z",
      }],
      pagination: {
        page: 1,
        pageTotal: 1,
        count: 1,
      },
    });
  });

  teardown(() => {
    vscode.window.withProgress = originalWithProgress;
    vscode.window.showErrorMessage = originalShowErrorMessage;
    vscode.window.showInformationMessage = originalShowInformationMessage;
    vscode.window.showWarningMessage = originalShowWarningMessage;
    vscode.workspace.getConfiguration = originalGetConfiguration;
    PaginatedFetch.prototype.fetchPage = originalFetchPage;
  });

  test("search() clears repo scope when repo is omitted", async () => {
    provider.currentRepo = "repo-a";
    await provider.search("workspace-a", "vulnerabilities:>0");
    assert.strictEqual(provider.currentRepo, null);
  });

  test("searchRepos() clears stale repo scope", async () => {
    provider.currentRepo = "repo-a";
    await provider.searchRepos("workspace-a", ["repo-a", "repo-b"], "vulnerabilities:>0");
    assert.strictEqual(provider.currentRepo, null);
  });

  test("search cancellation reaches pagination and preserves the prior result snapshot", async () => {
    const priorResults = [{ marker: "prior" }];
    const token = { isCancellationRequested: true };
    let progressOptions;
    let requestOptions;
    provider.searchResults = priorResults;
    provider.currentWorkspace = "workspace-before";
    provider.currentQuery = "before";

    vscode.window.withProgress = async (options, task) => {
      progressOptions = options;
      return task({ report() {} }, token);
    };
    PaginatedFetch.prototype.fetchPage = async (_endpoint, _page, _pageSize, _query, options) => {
      requestOptions = options;
      return {
        data: [],
        pagination: null,
        error: { kind: "cancelled", message: "The request was canceled." },
      };
    };

    await provider.search("workspace-a", "name:artifact");

    assert.strictEqual(progressOptions.cancellable, true);
    assert.strictEqual(requestOptions.cancellationToken, token);
    assert.strictEqual(provider.searchResults, priorResults);
    assert.strictEqual(provider.currentWorkspace, "workspace-before");
    assert.strictEqual(provider.currentQuery, "before");
  });

  test("getChildren() shows the signed-out state when disconnected and idle", async () => {
    provider = new SearchProvider({
      secrets: {
        onDidChange() {},
        async get(key) {
          if (key === "cloudsmith-vsc.isConnected") {
            return "false";
          }
          return null;
        },
      },
    });

    const nodes = await provider.getChildren();

    assert.strictEqual(nodes.length, 1);
    assert.strictEqual(nodes[0].getTreeItem().label, "Connect to Cloudsmith");
  });
});

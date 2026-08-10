const assert = require("assert");
const vscode = require("vscode");
const { PaginatedFetch } = require("../util/paginatedFetch");
const workspaceRepositoryFetcher = require("../util/workspaceRepositoryFetcher");
const { apiFailure } = require("./apiResultHelpers");

suite("WorkspaceRepositoryFetcher", () => {
  let originalWithProgress;
  let originalFetchPage;
  let manager;

  setup(() => {
    originalWithProgress = vscode.window.withProgress;
    originalFetchPage = PaginatedFetch.prototype.fetchPage;
    vscode.window.withProgress = async (_options, task) => task({ report() {} }, {
      isCancellationRequested: false,
    });
    let state = connectedState(1);
    manager = {
      getState: () => ({ ...state }),
      setState: next => { state = { ...state, ...next }; },
    };
    managerForHelper = manager;
  });

  teardown(() => {
    vscode.window.withProgress = originalWithProgress;
    PaginatedFetch.prototype.fetchPage = originalFetchPage;
  });

  test("discovers and stably sorts 1,000 repositories across pages", async () => {
    const repositories = buildRepositories(1000);
    const calls = [];
    PaginatedFetch.prototype.fetchPage = async (_endpoint, page) => {
      calls.push(page);
      const data = repositories.slice((page - 1) * 500, page * 500);
      return fetchedPage(data, page, 2, 1000, 500);
    };

    const result = await fetchRepositories();

    assert.strictEqual(result.complete, true);
    assert.strictEqual(result.partial, false);
    assert.strictEqual(result.items.length, 1000);
    assert.deepStrictEqual(calls, [1, 2]);
    assert.strictEqual(result.items[0].slug, "repo-0000");
    assert.strictEqual(result.items[999].slug, "repo-0999");
  });

  test("accepts a stable server-lowered page size", async () => {
    const repositories = buildRepositories(500);
    PaginatedFetch.prototype.fetchPage = async (_endpoint, page) => fetchedPage(
      repositories.slice((page - 1) * 250, page * 250),
      page,
      2,
      500,
      250
    );

    const result = await fetchRepositories();

    assert.strictEqual(result.complete, true);
    assert.strictEqual(result.items.length, 500);
    assert.strictEqual(result.pageCount, 2);
  });

  test("retains successful repositories after a later rate limit", async () => {
    PaginatedFetch.prototype.fetchPage = async (_endpoint, page) => {
      if (page === 2) {
        return {
          data: [],
          pagination: pagination(2, 2, 501, 500),
          error: apiFailure("rate_limited", { status: 429 }).error,
        };
      }
      return fetchedPage(buildRepositories(500), 1, 2, 501, 500);
    };

    const result = await fetchRepositories();

    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.partial, true);
    assert.strictEqual(result.items.length, 500);
    assert.strictEqual(result.failureCount, 1);
    assert.strictEqual(result.failures[0].error.kind, "rate_limited");
    assert.strictEqual(result.continuation.nextPage, 2);
  });

  test("rejects a short non-final page and metadata drift", async () => {
    PaginatedFetch.prototype.fetchPage = async () => fetchedPage(
      [{ name: "Repo", slug: "repo" }],
      1,
      2,
      2,
      2
    );
    const short = await fetchRepositories();
    assert.strictEqual(short.complete, false);
    assert.strictEqual(short.termination, "invalid_pagination");
    assert.deepStrictEqual(short.items, []);

    PaginatedFetch.prototype.fetchPage = async (_endpoint, page) => page === 1
      ? fetchedPage(buildRepositories(500), 1, 2, 1000, 500)
      : fetchedPage(buildRepositories(500, 500), 2, 3, 1500, 500);
    const drift = await fetchRepositories();
    assert.strictEqual(drift.complete, false);
    assert.strictEqual(drift.termination, "invalid_pagination");
    assert.strictEqual(drift.items.length, 500);
    assert.strictEqual(drift.continuation, null);
  });

  test("duplicate slugs fail closed without duplicate publication", async () => {
    PaginatedFetch.prototype.fetchPage = async () => fetchedPage([
      { name: "One", slug: "duplicate" },
      { name: "Two", slug: "duplicate" },
    ], 1, 1, 2, 500);

    const result = await fetchRepositories();

    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.termination, "duplicate_or_invalid_identity");
    assert.strictEqual(result.duplicateCount, 1);
    assert.deepStrictEqual(result.items, []);
  });

  test("stops at the cumulative page ceiling without a bypass continuation", async () => {
    let calls = 0;
    PaginatedFetch.prototype.fetchPage = async (_endpoint, page) => {
      calls += 1;
      return fetchedPage(
        Array.from({ length: 500 }, (_, index) => ({
          name: `Repo ${page}-${index}`,
          slug: `repo-${page}-${index}`,
        })),
        page,
        21,
        10500,
        500
      );
    };

    const result = await fetchRepositories();

    assert.strictEqual(calls, workspaceRepositoryFetcher.MAX_WORKSPACE_REPOSITORY_PAGES);
    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.termination, "page_limit");
    assert.strictEqual(result.items.length, workspaceRepositoryFetcher.MAX_WORKSPACE_REPOSITORIES);
    assert.strictEqual(result.continuation, null);
  });

  test("discards accumulated repositories after account replacement", async () => {
    let releaseSecondPage;
    const secondPage = new Promise(resolve => { releaseSecondPage = resolve; });
    PaginatedFetch.prototype.fetchPage = async (_endpoint, page) => page === 1
      ? fetchedPage([{ name: "Old", slug: "old" }], 1, 2, 2, 1)
      : secondPage;

    const pending = fetchRepositories();
    await new Promise(resolve => setImmediate(resolve));
    manager.setState({ accountEpoch: 2 });
    releaseSecondPage(fetchedPage([{ name: "Old 2", slug: "old-2" }], 2, 2, 2, 1));
    const result = await pending;

    assert.strictEqual(result.stale, true);
    assert.strictEqual(result.termination, "stale_account");
    assert.deepStrictEqual(result.items, []);
  });
});

function fetchRepositories(options = {}) {
  return workspaceRepositoryFetcher.fetchWorkspaceRepositories({}, "workspace-a", {
    connectionManager: managerForHelper,
    ...options,
  });
}

let managerForHelper;

function connectedState(accountEpoch) {
  return {
    activationId: "activation-a",
    accountEpoch,
    sessionConnected: true,
  };
}

function buildRepositories(count, offset = 0) {
  return Array.from({ length: count }, (_, index) => {
    const suffix = String(index + offset).padStart(4, "0");
    return { name: `Repo ${suffix}`, slug: `repo-${suffix}` };
  }).reverse();
}

function pagination(page, pageTotal, count, pageSize) {
  return { page, pageTotal, count, countAuthoritative: true, pageSize };
}

function fetchedPage(data, page, pageTotal, count, pageSize) {
  return { data, pagination: pagination(page, pageTotal, count, pageSize), error: null };
}

const assert = require("assert");
const vscode = require("vscode");
const { PaginatedFetch } = require("../util/paginatedFetch");
const workspaceRepositoryFetcher = require("../util/workspaceRepositoryFetcher");
const { apiFailure } = require("./apiResultHelpers");

suite("WorkspaceRepositoryFetcher Test Suite", () => {
  let originalConsole;
  let originalWithProgress;
  let originalFetchPage;
  let progressOptions;
  let progressReports;
  let warnCalls;
  let manager;

  setup(() => {
    originalConsole = global.console;
    originalWithProgress = vscode.window.withProgress;
    originalFetchPage = PaginatedFetch.prototype.fetchPage;
    progressOptions = null;
    progressReports = [];
    warnCalls = [];
    let state = {
      activationId: "activation-a",
      accountEpoch: 1,
      sessionConnected: true,
    };
    manager = {
      getState() { return { ...state }; },
      setState(next) { state = { ...state, ...next }; },
    };

    global.console = new Proxy(originalConsole, {
      get(target, property) {
        if (property === "warn") {
          return (...args) => {
            warnCalls.push(args);
          };
        }

        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });

    vscode.window.withProgress = async (options, task) => {
      progressOptions = options;
      progressReports = [];
      return task({
        report(update) {
          progressReports.push(update);
        },
      });
    };
  });

  teardown(() => {
    global.console = originalConsole;
    vscode.window.withProgress = originalWithProgress;
    PaginatedFetch.prototype.fetchPage = originalFetchPage;
  });

  function buildRepositories(start, end) {
    const repositories = [];

    for (let index = start; index >= end; index -= 1) {
      const suffix = String(index).padStart(3, "0");
      repositories.push({
        name: `repo-${suffix}`,
        slug: `repo-${suffix}`,
      });
    }

    return repositories;
  }

  function fetchRepositories(options = {}) {
    return workspaceRepositoryFetcher.fetchWorkspaceRepositories({}, "workspace-a", {
      connectionManager: manager,
      ...options,
    });
  }

  test("stubs console.warn during test setup", () => {
    console.warn("warning-path");

    assert.deepStrictEqual(warnCalls, [["warning-path"]]);
  });

  test("fetches and sorts repositories across multiple pages", async () => {
    const calls = [];
    const firstPageData = buildRepositories(500, 1);

    PaginatedFetch.prototype.fetchPage = async (endpoint, page, pageSize) => {
      calls.push({ endpoint, page, pageSize });

      if (page === 1) {
        return {
          data: firstPageData,
          pagination: { page: 1, pageTotal: 2, count: 501, pageSize },
        };
      }

      return {
        data: [{ name: "repo-000", slug: "repo-000" }],
        pagination: { page: 2, pageTotal: 2, count: 501, pageSize },
      };
    };

    const result = await fetchRepositories();

    assert.strictEqual(progressOptions.title, "Loading repositories for workspace-a...");
    assert.deepStrictEqual(
      progressReports.map(report => report.message),
      ["Page 1", "Page 2 of 2"]
    );
    assert.deepStrictEqual(
      calls,
      [
        { endpoint: "repos/workspace-a/?sort=name", page: 1, pageSize: 500 },
        { endpoint: "repos/workspace-a/?sort=name", page: 2, pageSize: 500 },
      ]
    );
    assert.strictEqual(result.error, null);
    assert.strictEqual(result.partial, false);
    assert.strictEqual(result.repositories.length, 501);
    assert.strictEqual(result.repositories[0].name, "repo-000");
    assert.strictEqual(result.repositories[1].name, "repo-001");
    assert.strictEqual(result.repositories[500].name, "repo-500");
  });

  test("continues fetching when the API caps page size below the requested size", async () => {
    const calls = [];
    const firstPageData = buildRepositories(250, 1);
    const secondPageData = buildRepositories(500, 251);

    PaginatedFetch.prototype.fetchPage = async (endpoint, page, pageSize) => {
      calls.push({ endpoint, page, pageSize });

      if (page === 1) {
        return {
          data: firstPageData,
          pagination: { page: 1, pageTotal: 2, count: 500, pageSize: 250 },
        };
      }

      return {
        data: secondPageData,
        pagination: { page: 2, pageTotal: 2, count: 500, pageSize: 250 },
      };
    };

    const result = await fetchRepositories();

    assert.deepStrictEqual(
      calls,
      [
        { endpoint: "repos/workspace-a/?sort=name", page: 1, pageSize: 500 },
        { endpoint: "repos/workspace-a/?sort=name", page: 2, pageSize: 500 },
      ]
    );
    assert.strictEqual(result.error, null);
    assert.strictEqual(result.partial, false);
    assert.strictEqual(result.repositories.length, 500);
    assert.strictEqual(result.repositories[0].name, "repo-001");
    assert.strictEqual(result.repositories[499].name, "repo-500");
  });

  test("stops when the current page reaches pageTotal even if the page is full", async () => {
    const calls = [];

    PaginatedFetch.prototype.fetchPage = async (_endpoint, page) => {
      calls.push(page);

      if (page === 1) {
        return {
          data: [
            { name: "repo-d", slug: "repo-d" },
            { name: "repo-c", slug: "repo-c" },
          ],
          pagination: { page: 1, pageTotal: 2, count: 4, pageSize: 2 },
        };
      }

      return {
        data: [
          { name: "repo-b", slug: "repo-b" },
          { name: "repo-a", slug: "repo-a" },
        ],
        pagination: { page: 2, pageTotal: 2, count: 4, pageSize: 2 },
      };
    };

    const result = await fetchRepositories();

    assert.deepStrictEqual(calls, [1, 2]);
    assert.strictEqual(result.error, null);
    assert.strictEqual(result.partial, false);
    assert.deepStrictEqual(
      result.repositories.map(repository => repository.name),
      ["repo-a", "repo-b", "repo-c", "repo-d"]
    );
  });

  test("returns an error when the first page fails", async () => {
    const failure = apiFailure("server_error", {
      status: 500,
      message: "The Cloudsmith API returned an internal error.",
    }).error;
    PaginatedFetch.prototype.fetchPage = async () => ({
      data: [],
      pagination: { page: 1, pageTotal: 1, count: 0, pageSize: 500 },
      error: failure,
    });

    const result = await fetchRepositories();

    assert.strictEqual(result.error, failure);
    assert.strictEqual(result.partial, false);
    assert.deepStrictEqual(result.repositories, []);
  });

  test("returns partial repositories and logs a warning when a later page fails", async () => {
    const firstPageData = buildRepositories(500, 1);

    PaginatedFetch.prototype.fetchPage = async (_endpoint, page, pageSize) => {
      if (page === 1) {
        return {
          data: firstPageData,
          pagination: { page: 1, pageTotal: 2, count: 600, pageSize },
        };
      }

      return {
        data: [],
        pagination: { page: 2, pageTotal: 2, count: 600, pageSize },
        error: apiFailure("server_error", {
          status: 502,
          message: "The Cloudsmith API returned an internal error.",
        }).error,
      };
    };

    const result = await fetchRepositories();

    assert.strictEqual(result.error, null);
    assert.strictEqual(result.partial, true);
    assert.strictEqual(result.warning.kind, "server_error");
    assert.strictEqual(result.repositories.length, 500);
    assert.strictEqual(result.repositories[0].name, "repo-001");
    assert.strictEqual(result.repositories[499].name, "repo-500");
    assert.deepStrictEqual(warnCalls, [
      [
        "[WorkspaceRepositories] Failed to load an additional repository page: The Cloudsmith API returned an internal error.",
      ],
    ]);
  });

  test("returns an error when the first page has a non-array repository payload", async () => {
    PaginatedFetch.prototype.fetchPage = async () => ({
      data: { items: [] },
      pagination: { page: 1, pageTotal: 1, count: 0, pageSize: 500 },
    });

    const result = await fetchRepositories();

    assert.strictEqual(
      result.error,
      workspaceRepositoryFetcher.UNEXPECTED_RESPONSE_FORMAT_ERROR
    );
    assert.strictEqual(result.warning, null);
    assert.strictEqual(result.partial, false);
    assert.deepStrictEqual(result.repositories, []);
    assert.deepStrictEqual(warnCalls, []);
  });

  test("returns partial repositories when a later page has a non-array repository payload", async () => {
    PaginatedFetch.prototype.fetchPage = async (_endpoint, page) => {
      if (page === 1) {
        return {
          data: [
            { name: "repo-c", slug: "repo-c" },
            { name: "repo-a", slug: "repo-a" },
          ],
          pagination: { page: 1, pageTotal: 3, count: 6, pageSize: 2 },
        };
      }

      return {
        data: { items: [] },
        pagination: { page: 2, pageTotal: 3, count: 6, pageSize: 2 },
      };
    };

    const result = await fetchRepositories();

    assert.strictEqual(result.error, null);
    assert.strictEqual(
      result.warning,
      workspaceRepositoryFetcher.UNEXPECTED_RESPONSE_FORMAT_ERROR
    );
    assert.strictEqual(result.partial, true);
    assert.deepStrictEqual(
      result.repositories.map(repository => repository.name),
      ["repo-a", "repo-c"]
    );
    assert.deepStrictEqual(warnCalls, [
      [
        "[WorkspaceRepositories] Failed to load additional repositories for workspace-a on page 2: Unexpected repository response format",
      ],
    ]);
  });

  test("discards all partial repositories when the account changes between pages", async () => {
    let releaseSecondPage;
    const secondPage = new Promise(resolve => { releaseSecondPage = resolve; });
    PaginatedFetch.prototype.fetchPage = async (_endpoint, page) => {
      if (page === 1) {
        return {
          data: [{ name: "old-repo", slug: "old-repo" }],
          pagination: { page: 1, pageTotal: 2, count: 2, pageSize: 1 },
        };
      }
      return secondPage;
    };
    const pending = fetchRepositories();
    await new Promise(resolve => setImmediate(resolve));
    manager.setState({ accountEpoch: 2 });
    releaseSecondPage({
      data: [{ name: "also-old", slug: "also-old" }],
      pagination: { page: 2, pageTotal: 2, count: 2, pageSize: 1 },
    });

    const result = await pending;
    assert.strictEqual(result.stale, true);
    assert.deepStrictEqual(result.repositories, []);
    assert.strictEqual(result.error.kind, "stale_account");
  });
});

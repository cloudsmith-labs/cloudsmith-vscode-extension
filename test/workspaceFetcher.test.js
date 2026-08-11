const assert = require("assert");
const { PaginatedFetch } = require("../util/paginatedFetch");
const { fetchWorkspaces } = require("../util/workspaceFetcher");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");
const { ScriptedCloudsmithAPI } = require("./helpers/scriptedCloudsmithAPI");

suite("WorkspaceFetcher", () => {
  test("discovers and stably sorts 1,000 workspaces across pages", async () => {
    const workspaces = Array.from({ length: 1000 }, (_, index) => ({
      slug: `workspace-${String(index).padStart(4, "0")}`,
      name: index === 999 ? "A workspace" : `Workspace ${index}`,
    }));
    const calls = [];
    const api = {
      async get(endpoint) {
        const page = requestedPage(endpoint);
        calls.push(page);
        const items = workspaces.slice((page - 1) * 500, page * 500);
        return pageResult(items, page, 2, 1000, 500);
      },
    };

    const result = await fetchWorkspaces({}, fetchOptions(api));

    assert.strictEqual(result.complete, true);
    assert.strictEqual(result.items.length, 1000);
    assert.strictEqual(result.items[0].slug, "workspace-0999");
    assert.deepStrictEqual(calls, [1, 2]);
  });

  test("retains a successful page and reports a later rate limit as incomplete", async () => {
    const api = new ScriptedCloudsmithAPI([
      {
        method: "GET",
        endpoint: endpoint => requestedPage(endpoint) === 1,
        result: pageResult(
          Array.from({ length: 500 }, (_, index) => ({
            slug: `workspace-${index}`,
            name: `Workspace ${index}`,
          })),
          1,
          2,
          501,
          500
        ),
      },
      {
        method: "GET",
        endpoint: endpoint => requestedPage(endpoint) === 2,
        result: apiFailure("rate_limited", { status: 429 }),
      },
    ]);

    const result = await fetchWorkspaces({}, fetchOptions(api));

    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.partial, true);
    assert.strictEqual(result.items.length, 500);
    assert.strictEqual(result.failureCount, 1);
    assert.strictEqual(result.failures[0].error.kind, "rate_limited");
    api.assertExhausted();
  });

  test("duplicate workspace slugs fail closed and are not published twice", async () => {
    const api = {
      async get() {
        return pageResult(
          [{ slug: "duplicate", name: "One" }, { slug: "duplicate", name: "Two" }],
          1,
          1,
          2,
          500
        );
      },
    };

    const result = await fetchWorkspaces({}, fetchOptions(api));

    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.termination, "duplicate_or_invalid_identity");
    assert.deepStrictEqual(result.items, []);
  });

  test("account replacement discards a stale completion", async () => {
    let state = connectedState(1);
    let resolveRequest;
    const api = {
      async get() {
        return new Promise(resolve => { resolveRequest = resolve; });
      },
    };
    const promise = fetchWorkspaces({}, fetchOptions(api, () => state));
    await new Promise(resolve => setImmediate(resolve));
    state = connectedState(2);
    resolveRequest(pageResult([], 1, 1, 0, 500));

    const result = await promise;

    assert.strictEqual(result.stale, true);
    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.termination, "stale_account");
  });
});

function fetchOptions(api, getState = () => connectedState(1)) {
  return {
    cloudsmithAPI: api,
    paginatedFetch: new PaginatedFetch(api),
    connectionManager: { getState },
  };
}

function connectedState(accountEpoch) {
  return {
    sessionConnected: true,
    accountEpoch,
    activationId: "activation",
  };
}

function requestedPage(endpoint) {
  return Number(new URL(`https://example.test/${endpoint}`).searchParams.get("page"));
}

function pageResult(items, page, pageTotal, count, pageSize) {
  return apiSuccess(items, {
    headers: {
      "x-pagination-page": String(page),
      "x-pagination-pagetotal": String(pageTotal),
      "x-pagination-count": String(count),
      "x-pagination-pagesize": String(pageSize),
    },
  });
}

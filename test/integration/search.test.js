const assert = require("assert");
const { createAPI, liveFixture } = require("./setup");
const { apiEndpoint } = require("../../util/apiEndpoint");
const { CloudsmithAPI } = require("../../util/cloudsmithAPI");
const { PaginatedFetch } = require("../../util/paginatedFetch");
const { SearchQueryBuilder } = require("../../util/searchQueryBuilder");
const { SearchProvider } = require("../../views/searchProvider");

suite("Live integration: controlled package search", function () {
  this.timeout(15000);

  let api;
  setup(() => { api = createAPI(); });

  test("finds the configured package in the configured repository", async () => {
    const result = await api.get(apiEndpoint([
      "packages", liveFixture.workspace, liveFixture.repository,
    ], {
      query: {
        query: new SearchQueryBuilder().name(liveFixture.packageName).build(),
        page_size: 10,
      },
    }), { credential: liveFixture.credential, responseType: "array" });

    assert.strictEqual(result.ok, true, result.error && result.error.message);
    assert.ok(result.data.some(pkg => pkg.name === liveFixture.packageName));
  });

  test("finds the configured quarantined package without account assumptions", async () => {
    const result = await api.get(apiEndpoint([
      "packages", liveFixture.workspace, liveFixture.repository,
    ], {
      query: {
        query: new SearchQueryBuilder()
          .name(liveFixture.quarantinedPackageName)
          .status("quarantined")
          .build(),
        page_size: 10,
      },
    }), { credential: liveFixture.credential, responseType: "array" });

    assert.strictEqual(result.ok, true, result.error && result.error.message);
    const fixture = result.data.find(pkg => pkg.name === liveFixture.quarantinedPackageName);
    assert.ok(fixture, "Configured quarantined package was not found");
    assert.strictEqual(fixture.status_str, "Quarantined");
  });

  test("quarantined filter returns only quarantined packages", async () => {
    const result = await api.get(apiEndpoint([
      "packages", liveFixture.workspace, liveFixture.repository,
    ], {
      query: { query: "status:quarantined", page_size: 10 },
    }), { credential: liveFixture.credential, responseType: "array" });

    assert.strictEqual(result.ok, true, result.error && result.error.message);
    assert.ok(result.data.length > 0, "Controlled repository has no quarantined fixture");
    for (const pkg of result.data) assert.strictEqual(pkg.status_str, "Quarantined");
  });

  test("broad workspace search commits one bounded production page", async function () {
    this.timeout(45000);
    const query = liveSearchQuery();
    let dispatchCount = 0;
    const typedApi = new CloudsmithAPI({}, {
      credentialManager: { async getApiKey() { return liveFixture.apiKey; } },
      fetchImpl: (url, options) => {
        dispatchCount += 1;
        return fetch(url, options);
      },
    });
    const provider = new SearchProvider({}, {
      connectionManager: connectedManager(),
      createCloudsmithAPI: () => typedApi,
      createPaginatedFetch: currentApi => new PaginatedFetch(currentApi),
      withProgress: (_options, task) => task(
        { report() {} },
        { isCancellationRequested: false, onCancellationRequested() { return { dispose() {} }; } }
      ),
      notifications: { error() {}, information() {}, warning() {} },
    });

    try {
      await provider.search(liveFixture.workspace, query);
      assert.strictEqual(provider.state.failure, null);
      assert(provider.state.committed, "Broad workspace page did not commit");
      assert.strictEqual(provider.state.committed.descriptor.query, query);
      assert.strictEqual(provider.state.committed.pagination.page, 1);
      assert.strictEqual(provider.state.committed.pagination.pageSize, 10);
      assert(provider.searchResults.length > 0 && provider.searchResults.length <= 10);
      assert.strictEqual(provider.state.committed.diagnostics.requestCount, 1);
      assert(dispatchCount >= 1 && dispatchCount <= 2);
      assert.strictEqual(new Set(provider.state.committed.resultKeys).size, provider.searchResults.length);
      if (provider.state.committed.pageable) {
        const firstKeys = new Set(provider.state.committed.resultKeys);
        const dispatchesBeforePageTwo = dispatchCount;
        const first = provider.loadNextPage();
        const duplicate = provider.loadNextPage();
        assert.strictEqual(first, duplicate);
        await first;
        assert.strictEqual(provider.state.failure, null);
        assert.strictEqual(provider.state.committed.pagination.page, 2);
        assert.strictEqual(provider.state.committed.diagnostics.requestCount, 2);
        assert(dispatchCount - dispatchesBeforePageTwo >= 1);
        assert(dispatchCount - dispatchesBeforePageTwo <= 2);
        assert.strictEqual(new Set(provider.state.committed.resultKeys).size, provider.searchResults.length);
        assert(provider.state.committed.resultKeys.some(key => !firstKeys.has(key)));
      }
    } finally {
      provider.dispose();
    }
  });
});

function connectedManager() {
  const state = Object.freeze({
    activationId: "live-search",
    accountEpoch: 1,
    sessionConnected: true,
    status: "connected",
  });
  return {
    getState: () => state,
    onDidChange: () => ({ dispose() {} }),
  };
}

function liveSearchQuery() {
  const value = process.env.CLOUDSMITH_TEST_SEARCH_QUERY || "format:python";
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > 2048
    || /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error("CLOUDSMITH_TEST_SEARCH_QUERY is invalid");
  }
  return value;
}

const assert = require("assert");
const { createAPI, liveFixture } = require("./setup");
const { apiEndpoint } = require("../../util/apiEndpoint");
const { SearchQueryBuilder } = require("../../util/searchQueryBuilder");

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
    }), { apiKey: liveFixture.apiKey, responseType: "array" });

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
    }), { apiKey: liveFixture.apiKey, responseType: "array" });

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
    }), { apiKey: liveFixture.apiKey, responseType: "array" });

    assert.strictEqual(result.ok, true, result.error && result.error.message);
    assert.ok(result.data.length > 0, "Controlled repository has no quarantined fixture");
    for (const pkg of result.data) assert.strictEqual(pkg.status_str, "Quarantined");
  });
});

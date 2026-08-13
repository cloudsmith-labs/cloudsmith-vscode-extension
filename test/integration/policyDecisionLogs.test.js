const assert = require("assert");
const { apiEndpoint } = require("../../util/apiEndpoint");
const {
  fetchPackageDecisionLogs,
  selectCausalDecision,
} = require("../../util/policyDecisionLogs");
const { SearchQueryBuilder } = require("../../util/searchQueryBuilder");
const { createAPI, liveFixture } = require("./setup");

suite("Live integration: policy decision trace", function () {
  this.timeout(30000);

  test("retrieves a bounded exact trace for the controlled quarantined package", async function () {
    const api = createAPI();
    const packageResult = await api.get(apiEndpoint([
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
    assert.strictEqual(packageResult.ok, true, packageResult.error && packageResult.error.message);
    const pkg = packageResult.data.find(value => (
      value.name === liveFixture.quarantinedPackageName
      && value.status_str === "Quarantined"
    ));
    assert.ok(pkg, "Configured quarantined package was not found");
    assert.strictEqual(typeof pkg.slug_perm, "string");
    assert.strictEqual(typeof pkg.uploaded_at, "string");

    let requests = 0;
    const authenticated = {
      async getV2(endpoint, options) {
        requests += 1;
        return api.getV2(endpoint, { ...options, apiKey: liveFixture.apiKey });
      },
    };
    const locator = {
      workspace: liveFixture.workspace,
      repository: liveFixture.repository,
      packageSlugPerm: pkg.slug_perm,
    };
    const collection = await fetchPackageDecisionLogs(
      authenticated,
      locator,
      pkg.uploaded_at
    );
    assert(requests > 0 && requests <= 20, "Decision-log request count escaped its bound");
    assert.strictEqual(collection.failures.length, 0);
    for (const entry of collection.items) {
      assert.strictEqual(entry.packageSlugPerm, pkg.slug_perm);
      assert.strictEqual(entry.repositorySlug, liveFixture.repository);
    }
    if (collection.items.length === 0) {
      this.skip();
      return;
    }
    const selected = selectCausalDecision(collection.items);
    if (!selected) {
      this.skip();
      return;
    }
    assert.strictEqual(selected.match, true);
    assert.strictEqual(typeof selected.policySlugPerm, "string");
    assert.strictEqual(selected.action, "Quarantined");
  });
});

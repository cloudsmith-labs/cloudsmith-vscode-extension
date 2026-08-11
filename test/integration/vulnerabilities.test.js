const assert = require("assert");
const { createAPI, liveFixture } = require("./setup");
const { extractVulnerabilityResults } = require("../../util/packageVulnerabilities");
const { apiEndpoint } = require("../../util/apiEndpoint");

suite("Live integration: controlled vulnerability fixture", function () {
  this.timeout(15000);

  test("loads a configured vulnerable package scan and validates its CVE contract", async () => {
    const api = createAPI();
    const scansResult = await api.get(apiEndpoint([
      "vulnerabilities",
      liveFixture.workspace,
      liveFixture.repository,
      liveFixture.vulnerablePackageSlug,
    ]), { apiKey: liveFixture.apiKey, responseType: "array" });
    assert.strictEqual(scansResult.ok, true, scansResult.error && scansResult.error.message);
    assert.ok(scansResult.data.length > 0, "Configured vulnerable package has no scans");

    const scan = scansResult.data.find(candidate => candidate.has_vulnerabilities);
    assert.ok(scan && typeof scan.identifier === "string", "Configured package has no vulnerable scan");
    assert.ok(scan.identifier.length > 0);
    assert.strictEqual(typeof scan.num_vulnerabilities, "number");

    const detailResult = await api.get(apiEndpoint([
      "vulnerabilities",
      liveFixture.workspace,
      liveFixture.repository,
      liveFixture.vulnerablePackageSlug,
      scan.identifier,
    ]), { apiKey: liveFixture.apiKey, responseType: "object" });
    assert.strictEqual(detailResult.ok, true, detailResult.error && detailResult.error.message);

    const results = extractVulnerabilityResults(detailResult.data);
    assert.ok(results.length > 0, "Configured vulnerable scan contains no CVE results");
    for (const vulnerability of results) {
      assert.match(vulnerability.vulnerability_id, /^(?:CVE-|GHSA-)/);
      assert.strictEqual(typeof vulnerability.severity, "string");
    }
  });
});

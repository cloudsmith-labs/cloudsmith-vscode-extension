const assert = require('assert');
const { apiKey, workspace, testRepo, testPackageSlug, createAPI, skipIfNoKey } = require('./setup');
const { extractVulnerabilityResults } = require('../../util/packageVulnerabilities');
const { apiEndpoint } = require('../../util/apiEndpoint');

suite('Integration: Vulnerabilities', function () {
  this.timeout(15000);

  let api;
  let scanId;
  let scanDetail;

  setup(function () {
    skipIfNoKey.call(this);
    api = createAPI();
  });

  test('step 1: list scans for a package returns scan entries', async function () {
    const result = await api.get(
      apiEndpoint(['vulnerabilities', workspace, testRepo, testPackageSlug]),
      { apiKey, responseType: 'array' }
    );
    assert.strictEqual(result.ok, true, result.error && result.error.message);
    const scans = result.data;
    assert.ok(scans.length > 0, 'Expected at least one scan result');

    const scan = scans.find((s) => s.has_vulnerabilities) || scans[0];
    assert.ok(scan.identifier, 'Scan should have an identifier');
    assert.ok(typeof scan.num_vulnerabilities === 'number', 'num_vulnerabilities should be a number');

    // Store for step 2
    scanId = scan.identifier;
  });

  test('step 2: read scan detail returns CVE data', async function () {
    if (!scanId) {
      this.skip();
      return;
    }

    const result = await api.get(
      apiEndpoint(['vulnerabilities', workspace, testRepo, testPackageSlug, scanId]),
      { apiKey, responseType: 'object' }
    );
    assert.strictEqual(result.ok, true, result.error && result.error.message);
    scanDetail = result.data;
    assert.ok(scanDetail, 'Expected scan detail response');
    assert.ok(scanDetail.scan && typeof scanDetail.scan === 'object', 'Expected scan object in response');
    assert.ok(Array.isArray(scanDetail.scan.results), 'Expected results array in scan response');
    assert.ok(scanDetail.scan.results.length > 0, 'Expected at least one CVE result');
  });

  test('CVE data has expected structure', function () {
    const results = extractVulnerabilityResults(scanDetail);
    if (results.length === 0) {
      this.skip();
      return;
    }

    const cve = results[0];
    assert.ok(cve.vulnerability_id, 'CVE should have vulnerability_id');
    assert.ok(
      cve.vulnerability_id.startsWith('CVE-') || cve.vulnerability_id.startsWith('GHSA-'),
      `vulnerability_id should start with CVE- or GHSA-, got: ${cve.vulnerability_id}`
    );
    assert.ok(typeof cve.severity === 'string', 'severity should be a string');
    assert.ok(
      cve.fixed_version || cve.affected_version,
      'Should have either fixed_version or affected_version'
    );
  });

  test('fix version extraction works when available', function () {
    const results = extractVulnerabilityResults(scanDetail);
    if (results.length === 0) {
      this.skip();
      return;
    }

    const withFix = results.find((r) => r.fixed_version);
    if (!withFix) {
      // No fix available for any CVE — skip rather than fail
      this.skip();
      return;
    }

    const fix = withFix.fixed_version;
    assert.ok(
      fix.version || fix.raw_version,
      'fixed_version should have a version or raw_version string'
    );
  });
});

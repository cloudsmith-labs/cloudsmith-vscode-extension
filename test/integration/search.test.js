const assert = require('assert');
const { apiKey, workspace, testRepo, createAPI, skipIfNoKey } = require('./setup');
const { apiEndpoint } = require('../../util/apiEndpoint');

suite('Integration: Search', function () {
  this.timeout(15000);

  let api;

  setup(function () {
    skipIfNoKey.call(this);
    api = createAPI();
  });

  test('searching for "spotipy" returns results', async function () {
    const result = await api.get(apiEndpoint(['packages', workspace, testRepo], {
      query: { query: 'name:spotipy', page_size: 10 },
    }), { apiKey, responseType: 'array' });
    assert.strictEqual(result.ok, true, result.error && result.error.message);
    assert.ok(result.data.length > 0, 'Expected at least one result');
    assert.strictEqual(result.data[0].name, 'spotipy');
  });

  test('search results include a quarantined or policy-violated package', async function () {
    const result = await api.get(apiEndpoint(['packages', workspace, testRepo], {
      query: { query: 'name:spotipy', page_size: 10 },
    }), { apiKey, responseType: 'array' });
    assert.strictEqual(result.ok, true, result.error && result.error.message);
    const flagged = result.data.find(
      (pkg) => pkg.status_str === 'Quarantined' || pkg.policy_violated === true
    );
    assert.ok(flagged, 'Expected at least one quarantined or policy-violated package');
  });

  test('status:quarantined filter returns only quarantined packages', async function () {
    const result = await api.get(apiEndpoint(['packages', workspace, testRepo], {
      query: { query: 'status:quarantined', page_size: 10 },
    }), { apiKey, responseType: 'array' });
    assert.strictEqual(result.ok, true, result.error && result.error.message);
    for (const pkg of result.data) {
      assert.strictEqual(pkg.status_str, 'Quarantined',
        `Expected all results to be Quarantined, got: ${pkg.status_str}`);
    }
  });
});

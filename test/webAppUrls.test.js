const assert = require("assert");
const {
  WEB_APP_BASE_URL,
  buildPackageGroupUrl,
  buildPackageUrl,
  buildRepositoryUrl,
} = require("../util/webAppUrls");

suite("Web app URL helpers", () => {
  test("buildRepositoryUrl always uses the app domain", () => {
    assert.strictEqual(
      buildRepositoryUrl("my-org", "my-repo"),
      `${WEB_APP_BASE_URL}/my-org/my-repo`
    );
  });

  test("buildPackageUrl always uses the app domain and package slug path", () => {
    assert.strictEqual(
      buildPackageUrl("my-org", "my-repo", "npm", "@scope/pkg", "1.0.0", "pkg-id"),
      `${WEB_APP_BASE_URL}/my-org/my-repo/npm/@scope_pkg/1.0.0/pkg-id`
    );
  });

  test("buildPackageGroupUrl always uses the app domain and repo search path", () => {
    assert.strictEqual(
      buildPackageGroupUrl("my-org", "my-repo", "group/name:latest"),
      `${WEB_APP_BASE_URL}/my-org/my-repo?page=1&query=name:group%2Fname%3Alatest&sort=name`
    );
  });

  test("URL helpers encode reserved characters in path and query values", () => {
    assert.strictEqual(
      buildRepositoryUrl("my org", "repo#one"),
      `${WEB_APP_BASE_URL}/my%20org/repo%23one`
    );
    assert.strictEqual(
      buildPackageUrl("my org", "repo#one", "npm", "@scope/pkg", "1.0.0+build", "pkg?id"),
      `${WEB_APP_BASE_URL}/my%20org/repo%23one/npm/@scope_pkg/1.0.0%2Bbuild/pkg%3Fid`
    );
    assert.strictEqual(
      buildPackageGroupUrl("my org", "repo#one", "group & name"),
      `${WEB_APP_BASE_URL}/my%20org/repo%23one?page=1&query=name:group%20%26%20name&sort=name`
    );
  });
});

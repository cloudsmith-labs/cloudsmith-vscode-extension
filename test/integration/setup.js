// Shared setup for optional tests against explicitly controlled Cloudsmith fixtures.
// Required opt-in and fixture coordinates are validated by scripts/run-vscode-tests.js.

const { CloudsmithAPI } = require("../../util/cloudsmithAPI");
const { LIVE_REQUIRED_ENV } = require("../testInventories");

if (process.env.CLOUDSMITH_LIVE_TESTS !== "1") {
  throw new Error("Live tests require explicit CLOUDSMITH_LIVE_TESTS=1 opt-in");
}
for (const name of LIVE_REQUIRED_ENV) {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0 || value !== value.trim()
    || value.length > 4096 || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(`Live test environment value is missing or invalid: ${name}`);
  }
}

const liveFixture = Object.freeze({
  apiKey: process.env.CLOUDSMITH_TEST_API_KEY,
  packageName: process.env.CLOUDSMITH_TEST_PACKAGE_NAME,
  quarantinedPackageName: process.env.CLOUDSMITH_TEST_QUARANTINED_PACKAGE_NAME,
  repository: process.env.CLOUDSMITH_TEST_REPOSITORY,
  vulnerablePackageSlug: process.env.CLOUDSMITH_TEST_VULNERABLE_PACKAGE_SLUG,
  workspace: process.env.CLOUDSMITH_TEST_WORKSPACE,
});

const mockContext = Object.freeze({
  secrets: Object.freeze({ get: async () => null, store: async () => {} }),
  globalState: Object.freeze({ get: () => undefined, update: async () => {} }),
});

function createAPI() {
  return new CloudsmithAPI(mockContext);
}

module.exports = { createAPI, liveFixture, mockContext };

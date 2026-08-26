const assert = require("assert");
const fs = require("fs");
const path = require("path");
const {
  CREDENTIAL_BOUNDARY_EXCLUDED_TESTS,
  CREDENTIAL_BOUNDARY_SKIP_REASON,
  QUALIFICATION_REQUIRED_ENV,
  STANDALONE_NODE_TESTS,
  VSCODE_CORE_TESTS,
  VSCODE_SMOKE_TESTS,
  assertCredentialFreeRequiredEnvironment,
} = require("./testInventories");

const root = path.resolve(__dirname, "..");
const MAX_TEST_TRAVERSAL_DEPTH = 8;
const MAX_TEST_TRAVERSAL_ENTRIES = 512;
const inventories = Object.freeze({
  credentialBoundaryExcluded: CREDENTIAL_BOUNDARY_EXCLUDED_TESTS,
  node: STANDALONE_NODE_TESTS,
  smoke: VSCODE_SMOKE_TESTS,
  vscode: VSCODE_CORE_TESTS,
});

function discoverTests(directory, depth = 0, state = { entries: 0 }) {
  assert.ok(depth <= MAX_TEST_TRAVERSAL_DEPTH, "Test discovery exceeds its depth bound");
  const found = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    state.entries += 1;
    assert.ok(state.entries <= MAX_TEST_TRAVERSAL_ENTRIES, "Test discovery exceeds its entry bound");
    const fullPath = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) throw new Error(`Test discovery rejects symlinks: ${entry.name}`);
    if (entry.isDirectory()) found.push(...discoverTests(fullPath, depth + 1, state));
    else if (entry.isFile() && entry.name.endsWith(".test.js")) {
      found.push(path.relative(root, fullPath).split(path.sep).join("/"));
    }
  }
  return found.sort();
}

suite("test runner inventories", () => {
  test("every test belongs to exactly one explicit inventory", () => {
    const allocated = Object.values(inventories).flat();
    assert.deepStrictEqual([...new Set(allocated)].sort(), allocated.slice().sort(), "Test inventories contain a duplicate");
    assert.deepStrictEqual(allocated.slice().sort(), discoverTests(path.join(root, "test")));
  });

  test("every inventory is frozen and references a readable regular file", () => {
    for (const inventory of Object.values(inventories)) {
      assert.strictEqual(Object.isFrozen(inventory), true);
      assert.ok(inventory.length > 0);
      for (const relativePath of inventory) {
        assert.match(relativePath, /^test\/[A-Za-z0-9_./-]+\.test\.js$/);
        const stat = fs.lstatSync(path.join(root, relativePath));
        assert.strictEqual(stat.isSymbolicLink(), false);
        assert.strictEqual(stat.isFile(), true);
      }
    }
  });

  test("runner configuration consumes the shared inventories", () => {
    const vscodeConfig = fs.readFileSync(path.join(root, ".vscode-test.mjs"), "utf8");
    const nodeRunner = fs.readFileSync(path.join(root, "scripts", "run-node-tests.js"), "utf8");
    assert.match(vscodeConfig, /VSCODE_CORE_TESTS/);
    assert.match(vscodeConfig, /VSCODE_SMOKE_TESTS/);
    assert.doesNotMatch(vscodeConfig, /LIVE_TESTS|SSO_LIVE_TESTS|label: "live"|label: "sso-live"/);
    assert.match(vscodeConfig, /"1\.134\.0"/);
    assert.match(nodeRunner, /STANDALONE_NODE_TESTS/);
    const combinedRunner = fs.readFileSync(path.join(root, "scripts", "run-tests.js"), "utf8");
    assert.match(combinedRunner, /CREDENTIAL_BOUNDARY_SKIP_REASON/);
    const vscodeRunner = fs.readFileSync(path.join(root, "scripts", "run-vscode-tests.js"), "utf8");
    assert.match(vscodeRunner, /process\.execve/);
    assert.match(vscodeRunner, /stdio: "pipe"/);
    assert.doesNotMatch(vscodeRunner, /CLOUDSMITH_TEST_API_KEY|CLOUDSMITH_SSO_LIVE_TESTS/);
    assert.ok(CREDENTIAL_BOUNDARY_SKIP_REASON.length > 80);
    assert.deepStrictEqual(QUALIFICATION_REQUIRED_ENV, []);
  });

  test("qualification rejects credential-like required environment inputs", () => {
    for (const name of [
      "CLOUDSMITH_TEST_API_KEY",
      "ACCESS_TOKEN",
      "ACCOUNT_PASSWORD",
      "MFA_PASSCODE",
      "CLI_CREDENTIAL_FILE",
      "MACOS_KEYCHAIN_ITEM",
      "SSH_PRIVATE_KEY",
    ]) {
      assert.throws(
        () => assertCredentialFreeRequiredEnvironment(["SAFE_WORKSPACE", name]),
        /cannot require credential-like environment input/
      );
    }
    assert.deepStrictEqual(
      assertCredentialFreeRequiredEnvironment(["SAFE_WORKSPACE", "SAFE_REPOSITORY"]),
      ["SAFE_WORKSPACE", "SAFE_REPOSITORY"]
    );
    assert.throws(
      () => assertCredentialFreeRequiredEnvironment(["unsafe-name"]),
      /cannot require credential-like environment input/
    );
  });

  test("credential-bearing live suites are inventoried only as excluded inputs", () => {
    assert.deepStrictEqual(CREDENTIAL_BOUNDARY_EXCLUDED_TESTS, [
      "test/integration/policyDecisionLogs.test.js",
      "test/integration/search.test.js",
      "test/integration/upstreams.test.js",
      "test/integration/vulnerabilities.test.js",
      "test/integration/ssoAuthentication.test.js",
    ]);
    const runnable = [
      ...STANDALONE_NODE_TESTS,
      ...VSCODE_CORE_TESTS,
      ...VSCODE_SMOKE_TESTS,
    ];
    assert.strictEqual(
      CREDENTIAL_BOUNDARY_EXCLUDED_TESTS.some(file => runnable.includes(file)),
      false
    );
    const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    assert.strictEqual(
      manifest.scripts["test:live"],
      "node scripts/run-vscode-tests.js --label live"
    );
    assert.strictEqual(
      manifest.scripts["test:sso-live"],
      "node scripts/run-vscode-tests.js --label sso-live"
    );
    assert.match(
      fs.readFileSync(path.join(root, "scripts", "run-vscode-tests.js"), "utf8"),
      /!\["core", "smoke"\]\.includes\(label\)[\s\S]*credential-bearing live automation is excluded/
    );
  });

  test("official Extension Host tests install only an inert credential-free harness", () => {
    const config = fs.readFileSync(path.join(root, ".vscode-test.mjs"), "utf8");
    assert.match(
      config,
      /TEST_HARNESS_EXTENSION_PATH = path\.join\(repositoryRoot, "test", "harness-extension"\)/
    );
    assert.match(config, /extensionDevelopmentPath: TEST_HARNESS_EXTENSION_PATH/);
    assert.doesNotMatch(config, /extensionDevelopmentPath: repositoryRoot/);
    assert.match(config, /skipExtensionDependencies: true/);
    assert.doesNotMatch(config, /installExtensions\s*:/);

    const harnessRoot = path.join(root, "test", "harness-extension");
    assert.notStrictEqual(fs.realpathSync(harnessRoot), fs.realpathSync(root));
    const manifest = JSON.parse(fs.readFileSync(path.join(harnessRoot, "package.json"), "utf8"));
    assert.deepStrictEqual(manifest.activationEvents, []);
    assert.strictEqual(manifest.contributes, undefined);
    assert.strictEqual(manifest.extensionDependencies, undefined);
    assert.strictEqual(manifest.extensionPack, undefined);

    const harness = require("./harness-extension/extension");
    const forbiddenContext = new Proxy({}, {
      get(_target, property) {
        throw new Error(`Credential-free harness read forbidden context property ${String(property)}`);
      },
    });
    const activation = harness.activate(forbiddenContext);
    assert.deepStrictEqual(activation, { kind: "credential-free-test-harness" });
    assert.strictEqual(Object.isFrozen(activation), true);
    assert.strictEqual(harness.deactivate(), undefined);
  });

  test("the standalone runner pins strict Mocha behavior", () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    assert.strictEqual(manifest.devDependencies["@vscode/test-cli"], "0.0.15");
    assert.strictEqual(manifest.scripts.test, "node scripts/run-tests.js");
    assert.strictEqual(manifest.scripts["test:zero-guard"], "node scripts/run-tests.js --zero-probe");
    const runner = fs.readFileSync(path.join(root, "scripts", "run-node-tests.js"), "utf8");
    assert.match(runner, /--fail-zero/);
    assert.match(runner, /--forbid-only/);
    assert.match(runner, /--forbid-pending/);
    assert.match(runner, /PINNED_MOCHA_VERSION = "11\.8\.0"/);
    assert.match(runner, /PINNED_OWNER_VERSION = "0\.0\.15"/);
    assert.match(runner, /PINNED_OWNER_MOCHA_RANGE = "\^11\.7\.6"/);
    const lockfile = JSON.parse(fs.readFileSync(path.join(root, "package-lock.json"), "utf8"));
    assert.strictEqual(lockfile.packages["node_modules/@vscode/test-cli"].version, "0.0.15");
    assert.strictEqual(
      lockfile.packages["node_modules/@vscode/test-cli"].dependencies.mocha,
      "^11.7.6"
    );
    assert.strictEqual(lockfile.packages["node_modules/mocha"].version, "11.8.0");
  });
});

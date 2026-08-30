const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  CREDENTIAL_BOUNDARY_EXCLUDED_TESTS,
  CREDENTIAL_BOUNDARY_SKIP_REASON,
  HOST_NODE_TESTS,
  QUALIFICATION_REQUIRED_ENV,
  STANDALONE_NODE_TESTS,
  VSCODE_CORE_TESTS,
  VSCODE_SMOKE_TESTS,
  assertCredentialFreeRequiredEnvironment,
  createIsolatedQualificationRoot,
  exportIsolatedQualificationRoot,
  removeIsolatedQualificationRoot,
  sanitizeQualificationEnvironment,
} = require("./testInventories");
const { testPlan } = require("../scripts/run-tests");

const root = path.resolve(__dirname, "..");
const MAX_TEST_TRAVERSAL_DEPTH = 8;
const MAX_TEST_TRAVERSAL_ENTRIES = 512;
const inventories = Object.freeze({
  credentialBoundaryExcluded: CREDENTIAL_BOUNDARY_EXCLUDED_TESTS,
  host: HOST_NODE_TESTS,
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
    assert.match(nodeRunner, /HOST_NODE_TESTS/);
    assert.match(nodeRunner, /STANDALONE_NODE_TESTS/);
    const combinedRunner = fs.readFileSync(path.join(root, "scripts", "run-tests.js"), "utf8");
    assert.match(combinedRunner, /CREDENTIAL_BOUNDARY_SKIP_REASON/);
    const plan = (label, zeroProbe, nodeTestMode) => testPlan({
      label,
      zeroProbe,
      nodeTestMode,
    }).map(step => [step.script, [...step.args]]);
    assert.deepStrictEqual(plan("core", false, "full"), [
      ["run-node-tests.js", []],
      ["run-vscode-tests.js", ["--label", "core"]],
    ]);
    assert.deepStrictEqual(plan("smoke", false, "none"), [
      ["run-vscode-tests.js", ["--label", "smoke"]],
    ]);
    assert.deepStrictEqual(plan("smoke", false, "host"), [
      ["run-node-tests.js", ["--host"]],
      ["run-vscode-tests.js", ["--label", "smoke"]],
    ]);
    assert.deepStrictEqual(plan("core", true, "full"), [
      ["run-node-tests.js", ["--zero-probe"]],
      ["run-vscode-tests.js", ["--label", "core", "--zero-probe"]],
    ]);
    assert.deepStrictEqual(plan("smoke", true, "none"), [
      ["run-vscode-tests.js", ["--label", "smoke", "--zero-probe"]],
    ]);
    assert.deepStrictEqual(plan("smoke", true, "host"), [
      ["run-node-tests.js", ["--host", "--zero-probe"]],
      ["run-vscode-tests.js", ["--label", "smoke", "--zero-probe"]],
    ]);
    assert.throws(
      () => testPlan({ label: "smoke", nodeTestMode: "true" }),
      /nodeTestMode must be full, host, or none/u,
    );
    const vscodeRunner = fs.readFileSync(path.join(root, "scripts", "run-vscode-tests.js"), "utf8");
    assert.match(vscodeRunner, /process\.execve/);
    assert.match(vscodeRunner, /exportIsolatedQualificationRoot/);
    assert.match(vscodeRunner, /cleanupLauncherHome/);
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

  test("qualification child environment drops ambient credentials and isolates home paths", () => {
    const isolatedHome = path.join(root, ".quality", "synthetic-host-home");
    const sanitized = sanitizeQualificationEnvironment({
      PATH: "/safe/bin",
      LANG: "en_US.UTF-8",
      DISPLAY: ":99",
      VSCODE_TEST_VERSION: "1.99.0",
      CLOUDSMITH_QUALITY_TEST_EVIDENCE: "1",
      CLOUDSMITH_QUALITY_SOURCE_SHA: "a".repeat(40),
      CLOUDSMITH_QUALITY_SOURCE_FINGERPRINT: "b".repeat(64),
      CLOUDSMITH_QUALITY_TEST_SUITE: "extension-host-core",
      LC_CTYPE: "en_US.UTF-8",
      LC_API_KEY: "synthetic-secret",
      LC_TOKEN: "synthetic-token",
      CLOUDSMITH_API_KEY: "synthetic-secret",
      ACCESS_TOKEN: "synthetic-secret",
      SSH_AUTH_SOCK: "/private/synthetic-agent.sock",
      HOME: "/private/synthetic-real-home",
      USERPROFILE: "C:\\Users\\synthetic-real-home",
      NODE_OPTIONS: "--require=/private/synthetic-hook.js",
    }, isolatedHome);

    assert.deepStrictEqual(
      {
        PATH: sanitized.PATH,
        LANG: sanitized.LANG,
        DISPLAY: sanitized.DISPLAY,
        VSCODE_TEST_VERSION: sanitized.VSCODE_TEST_VERSION,
        CLOUDSMITH_QUALITY_TEST_EVIDENCE: sanitized.CLOUDSMITH_QUALITY_TEST_EVIDENCE,
        CLOUDSMITH_QUALITY_SOURCE_SHA: sanitized.CLOUDSMITH_QUALITY_SOURCE_SHA,
        CLOUDSMITH_QUALITY_SOURCE_FINGERPRINT: sanitized.CLOUDSMITH_QUALITY_SOURCE_FINGERPRINT,
        CLOUDSMITH_QUALITY_TEST_SUITE: sanitized.CLOUDSMITH_QUALITY_TEST_SUITE,
        LC_CTYPE: sanitized.LC_CTYPE,
      },
      {
        PATH: "/safe/bin",
        LANG: "en_US.UTF-8",
        DISPLAY: ":99",
        VSCODE_TEST_VERSION: "1.99.0",
        CLOUDSMITH_QUALITY_TEST_EVIDENCE: "1",
        CLOUDSMITH_QUALITY_SOURCE_SHA: "a".repeat(40),
        CLOUDSMITH_QUALITY_SOURCE_FINGERPRINT: "b".repeat(64),
        CLOUDSMITH_QUALITY_TEST_SUITE: "extension-host-core",
        LC_CTYPE: "en_US.UTF-8",
      }
    );
    for (const name of [
      "CLOUDSMITH_API_KEY",
      "ACCESS_TOKEN",
      "LC_API_KEY",
      "LC_TOKEN",
      "SSH_AUTH_SOCK",
      "NODE_OPTIONS",
    ]) {
      assert.strictEqual(Object.hasOwn(sanitized, name), false);
    }
    assert.strictEqual(sanitized.HOME, isolatedHome);
    assert.strictEqual(sanitized.USERPROFILE, isolatedHome);
    assert.strictEqual(sanitized.XDG_CONFIG_HOME, path.join(isolatedHome, ".config"));
    assert.strictEqual(sanitized.APPDATA, path.join(isolatedHome, "AppData", "Roaming"));
    assert.strictEqual(
      Object.values(sanitized).includes("synthetic-secret"),
      false
    );
  });

  test("qualification metadata cannot be shadowed by mixed-case environment collisions", () => {
    const isolatedHome = path.join(root, ".quality", "synthetic-collision-home");
    const canonical = {
      VSCODE_TEST_VERSION: "1.134.0",
      CLOUDSMITH_QUALITY_TEST_EVIDENCE: ".quality/test-results/core.json",
      CLOUDSMITH_QUALITY_SOURCE_SHA: "a".repeat(40),
      CLOUDSMITH_QUALITY_SOURCE_FINGERPRINT: "b".repeat(64),
      CLOUDSMITH_QUALITY_TEST_SUITE: "extension-host-core",
    };
    const collision = {
      vscode_test_version: "1.99.0",
      cloudsmith_quality_test_evidence: "/private/forged.json",
      cloudsmith_quality_source_sha: "0".repeat(40),
      cloudsmith_quality_source_fingerprint: "0".repeat(64),
      cloudsmith_quality_test_suite: "forged-suite",
      ...canonical,
    };

    const posix = sanitizeQualificationEnvironment(collision, isolatedHome, {
      platform: "darwin",
    });
    for (const [name, value] of Object.entries(canonical)) {
      assert.strictEqual(posix[name], value);
    }
    assert.throws(
      () => sanitizeQualificationEnvironment(collision, isolatedHome, {
        platform: "win32",
      }),
      /case-colliding key/u
    );
  });

  test("qualification host roots are atomic, private, unique, and exactly cleaned", () => {
    const temporaryParent = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-host-root-test-"));
    try {
      const predictableRoot = path.join(temporaryParent, `cloudsmith-vsc-core-${process.pid}`);
      const rogueExtension = path.join(predictableRoot, "extensions", "rogue", "package.json");
      fs.mkdirSync(path.dirname(rogueExtension), { recursive: true });
      fs.writeFileSync(rogueExtension, "{}\n");

      const runRoot = createIsolatedQualificationRoot("core", temporaryParent);
      const secondRunRoot = createIsolatedQualificationRoot("core", temporaryParent);
      assert.notStrictEqual(runRoot, secondRunRoot);
      assert.notStrictEqual(runRoot, predictableRoot);
      assert.strictEqual(path.dirname(runRoot), fs.realpathSync(temporaryParent));
      assert.match(path.basename(runRoot), /^csv-c-[A-Za-z0-9]{6}$/);
      assert.ok(runRoot.length <= fs.realpathSync(temporaryParent).length + 13);
      assert.deepStrictEqual(fs.readdirSync(runRoot), []);
      const stat = fs.lstatSync(runRoot);
      assert.strictEqual(stat.isDirectory(), true);
      assert.strictEqual(stat.isSymbolicLink(), false);
      if (process.platform !== "win32") assert.strictEqual(stat.mode & 0o077, 0);

      assert.throws(
        () => removeIsolatedQualificationRoot(predictableRoot),
        /refuses a directory it did not create/
      );
      const heldRoot = `${runRoot}-held`;
      fs.renameSync(runRoot, heldRoot);
      fs.mkdirSync(runRoot, { mode: 0o700 });
      assert.throws(
        () => removeIsolatedQualificationRoot(runRoot),
        /refuses a replaced host root/
      );
      fs.rmSync(runRoot, { force: true, recursive: true });
      fs.renameSync(heldRoot, runRoot);
      removeIsolatedQualificationRoot(runRoot);
      removeIsolatedQualificationRoot(secondRunRoot);
      assert.strictEqual(fs.existsSync(runRoot), false);
      assert.strictEqual(fs.existsSync(rogueExtension), true);
    } finally {
      fs.rmSync(temporaryParent, { force: true, recursive: true });
    }
  });

  test("qualification launcher roots require an exact one-use ownership handoff", () => {
    const temporaryParent = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-host-transfer-test-"));
    const runRoot = createIsolatedQualificationRoot("smoke", temporaryParent);
    try {
      const proof = exportIsolatedQualificationRoot(runRoot);
      const inventoryModule = require.resolve("./testInventories");
      delete require.cache[inventoryModule];
      const transferredInventory = require("./testInventories");
      assert.throws(
        () => transferredInventory.adoptIsolatedQualificationRoot(
          runRoot,
          "0".repeat(64),
          "smoke",
          temporaryParent
        ),
        /ownership proof does not match/u
      );
      assert.throws(
        () => transferredInventory.adoptIsolatedQualificationRoot(
          runRoot,
          proof,
          "core",
          temporaryParent
        ),
        /exact temporary namespace/u
      );
      assert.throws(
        () => exportIsolatedQualificationRoot(runRoot),
        /EEXIST/u
      );
      assert.strictEqual(
        transferredInventory.adoptIsolatedQualificationRoot(
          runRoot,
          proof,
          "smoke",
          temporaryParent
        ),
        runRoot
      );
      transferredInventory.removeIsolatedQualificationRoot(runRoot);
      assert.strictEqual(fs.existsSync(runRoot), false);
    } finally {
      fs.rmSync(temporaryParent, { force: true, recursive: true });
    }
  });

  test("qualification host roots preserve the macOS IPC socket length budget", () => {
    const runRoot = createIsolatedQualificationRoot("smoke", os.tmpdir());
    try {
      assert.ok(Buffer.byteLength(
        path.join(runRoot, "user-data", "1.13-main.sock"),
        "utf8"
      ) <= 103);
    } finally {
      removeIsolatedQualificationRoot(runRoot);
    }
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
    for (const extensionId of [
      "vscode.git",
      "vscode.github",
      "vscode.github-authentication",
      "vscode.microsoft-authentication",
      "GitHub.copilot",
      "GitHub.copilot-chat",
      "TypeScriptTeam.jsts-chat-features",
      "vscode.mermaid-markdown-features",
    ]) {
      assert.match(
        config,
        new RegExp(`--disable-extension=${extensionId.replaceAll(".", "\\.")}`),
        `Credential-capable built-in extension remains enabled: ${extensionId}`
      );
    }
    assert.match(config, /"chat\.disableAIFeatures": true/);
    assert.match(config, /"chat\.enabled": false/);
    assert.match(config, /createIsolatedQualificationRoot\(label, os\.tmpdir\(\)\)/);
    assert.match(config, /process\.once\("exit", \(\) => removeIsolatedQualificationRoot\(runRoot\)\)/);
    assert.doesNotMatch(config, /cloudsmith-vsc-\$\{label\}-\$\{process\.pid\}/);

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

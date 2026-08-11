const assert = require("assert");
const fs = require("fs");
const path = require("path");
const {
  LIVE_TEST_SKIP_REASON,
  LIVE_TESTS,
  STANDALONE_NODE_TESTS,
  VSCODE_CORE_TESTS,
  VSCODE_SMOKE_TESTS,
} = require("./testInventories");

const root = path.resolve(__dirname, "..");
const MAX_TEST_TRAVERSAL_DEPTH = 8;
const MAX_TEST_TRAVERSAL_ENTRIES = 512;
const inventories = Object.freeze({
  live: LIVE_TESTS,
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
    assert.match(vscodeConfig, /LIVE_TESTS/);
    assert.match(nodeRunner, /STANDALONE_NODE_TESTS/);
    const combinedRunner = fs.readFileSync(path.join(root, "scripts", "run-tests.js"), "utf8");
    assert.match(combinedRunner, /LIVE_TEST_SKIP_REASON/);
    const vscodeRunner = fs.readFileSync(path.join(root, "scripts", "run-vscode-tests.js"), "utf8");
    assert.match(vscodeRunner, /process\.execve/);
    assert.match(vscodeRunner, /stdio: "pipe"/);
    assert.ok(LIVE_TEST_SKIP_REASON.length > 40);
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

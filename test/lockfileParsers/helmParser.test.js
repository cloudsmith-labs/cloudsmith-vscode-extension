const assert = require("assert");
const path = require("path");
const helmParser = require("../../util/lockfileParsers/helmParser");
const {
  makeTempWorkspace,
  removeDirectory,
  writeTextFile,
} = require("../helpers/fixtureWorkspace");

suite("helmParser Test Suite", () => {
  const tempDirs = [];
  async function createWorkspace() {
    const workspace = await makeTempWorkspace("cloudsmith-helm-parser-");
    tempDirs.push(workspace);
    return workspace;
  }
  suiteTeardown(async () => Promise.all(tempDirs.map((tempDir) => removeDirectory(tempDir))));

  test("accepts canonical Helm indentation and preserves repository and manifest alias", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "Chart.yaml");
    const lockfilePath = path.join(workspace, "Chart.lock");
    await writeTextFile(manifestPath, [
      "apiVersion: v2", "name: fixture", "version: 0.1.0", "dependencies:",
      "- name: redis", "  version: 19.6.0", "  repository: https://charts.example.invalid", "  alias: cache", "",
    ].join("\n"));
    await writeTextFile(lockfilePath, [
      "dependencies:", "- name: redis", "  repository: https://charts.example.invalid", "  version: 19.6.0", "",
    ].join("\n"));

    const tree = await helmParser.resolve({ lockfilePath, manifestPath, workspaceFolder: workspace });

    assert.strictEqual(tree.dependencies.length, 1);
    assert.strictEqual(tree.dependencies[0].name, "redis");
    assert.strictEqual(tree.dependencies[0].version, "19.6.0");
    assert.strictEqual(tree.dependencies[0].qualifiers.repository, "https://charts.example.invalid");
    assert.strictEqual(tree.dependencies[0].qualifiers.alias, "cache");
  });

  test("classifies file repositories as local path dependencies", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "Chart.lock");
    await writeTextFile(lockfilePath, [
      "dependencies:", "- name: local", "  repository: file://../local", "  version: 1.0.0", "",
    ].join("\n"));

    const tree = await helmParser.resolve({ lockfilePath, workspaceFolder: workspace });

    assert.strictEqual(tree.dependencies[0].packageSource.kind, "path");
  });

  test("classifies explicit Git repositories as source-control dependencies", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "Chart.lock");
    await writeTextFile(lockfilePath, [
      "dependencies:", "- name: source-chart", "  repository: git+https://example.invalid/chart.git", "  version: 1.0.0", "",
    ].join("\n"));

    const tree = await helmParser.resolve({ lockfilePath, workspaceFolder: workspace });

    assert.strictEqual(tree.dependencies[0].packageSource.kind, "git");
    assert.strictEqual(tree.dependencies[0].packageSource.location, "git+https://example.invalid/chart.git");
  });
});

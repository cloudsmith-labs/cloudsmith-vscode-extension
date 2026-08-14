const assert = require("assert");
const path = require("path");
const dartParser = require("../../util/lockfileParsers/dartParser");
const {
  makeTempWorkspace,
  removeDirectory,
  writeTextFile,
} = require("../helpers/fixtureWorkspace");

suite("dartParser Test Suite", () => {
  const tempDirs = [];
  async function createWorkspace() {
    const workspace = await makeTempWorkspace("cloudsmith-dart-parser-");
    tempDirs.push(workspace);
    return workspace;
  }
  suiteTeardown(async () => Promise.all(tempDirs.map((tempDir) => removeDirectory(tempDir))));

  test("preserves hosted, path, git, and SDK source kinds", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "pubspec.lock");
    await writeTextFile(lockfilePath, [
      "packages:",
      "  hosted_dep:", '    dependency: "direct main"', "    source: hosted", '    version: "1.0.0"',
      "  local_dep:", "    dependency: transitive", "    description:", "      path: ../local", "    source: path", '    version: "2.0.0"',
      "  git_dep:", "    dependency: transitive", "    description:", "      ref: main", "      resolved-ref: deadbeef", "      url: https://user:secret@example.invalid/repo.git", "    source: git", '    version: "3.0.0"',
      "  sdk_dep:", "    dependency: transitive", "    source: sdk", '    version: "4.0.0"',
      "",
    ].join("\n"));

    const tree = await dartParser.resolve({ lockfilePath, workspaceFolder: workspace });

    assert.deepStrictEqual(tree.dependencies.map((dependency) => dependency.packageSource.kind), [
      "registry", "path", "git", "sdk",
    ]);
    assert.strictEqual(tree.dependencies[2].packageSource.location.includes("secret"), false);
    assert.strictEqual(tree.dependencies[2].packageSource.branch, "main");
    assert.strictEqual(tree.dependencies[2].packageSource.revision, "deadbeef");
  });
});

const assert = require("assert");
const path = require("path");
const rubyParser = require("../../util/lockfileParsers/rubyParser");
const {
  makeTempWorkspace,
  removeDirectory,
  writeTextFile,
} = require("../helpers/fixtureWorkspace");

suite("rubyParser Test Suite", () => {
  const tempDirs = [];

  async function createWorkspace() {
    const workspace = await makeTempWorkspace("cloudsmith-ruby-parser-");
    tempDirs.push(workspace);
    return workspace;
  }

  suiteTeardown(async () => {
    await Promise.all(tempDirs.map((tempDir) => removeDirectory(tempDir)));
  });

  test("preserves the full platform-qualified lock union and development-only closure", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "Gemfile");
    const lockfilePath = path.join(workspace, "Gemfile.lock");
    await writeTextFile(manifestPath, [
      'source "https://rubygems.org"',
      'gem "app", "1.0.0"',
      "group :development, :test do",
      '  gem "devtool", "2.0.0"',
      "end",
      "",
    ].join("\n"));
    await writeTextFile(lockfilePath, [
      "GEM",
      "  remote: https://rubygems.org/",
      "  specs:",
      "    app (1.0.0)",
      "      native",
      "    native (1.2.3)",
      "    native (1.2.3-arm64-darwin)",
      "    devtool (2.0.0)",
      "      devchild",
      "    devchild (3.0.0)",
      "",
      "DEPENDENCIES",
      "  app (= 1.0.0)",
      "  devtool (= 2.0.0)",
      "",
    ].join("\n"));

    const tree = await rubyParser.resolve({
      lockfilePath,
      manifestPath,
      workspaceFolder: workspace,
    });

    assert.strictEqual(tree.dependencies.length, 5);
    assert.deepStrictEqual(
      tree.dependencies.filter((dependency) => dependency.name === "native")
        .map((dependency) => [dependency.version, dependency.qualifiers.platform]),
      [["1.2.3", "ruby"], ["1.2.3", "arm64-darwin"]]
    );
    assert.deepStrictEqual(
      tree.dependencies.filter((dependency) => dependency.isDevelopmentDependency)
        .map((dependency) => dependency.name).sort(),
      ["devchild", "devtool"]
    );
    assert.strictEqual(tree.dependencies.find((dependency) => dependency.name === "devtool").isDirect, true);
  });

  test("preserves complete inventory when the relationship graph shares children", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "Gemfile");
    const lockfilePath = path.join(workspace, "Gemfile.lock");
    await writeTextFile(manifestPath, ['gem "a"', 'gem "b"', ""].join("\n"));
    await writeTextFile(lockfilePath, [
      "GEM", "  specs:", "    a (1.0.0)", "      shared", "    b (1.0.0)",
      "      shared", "    shared (1.0.0)", "", "DEPENDENCIES", "  a", "  b", "",
    ].join("\n"));

    const tree = await rubyParser.resolve({ lockfilePath, manifestPath, workspaceFolder: workspace });

    assert.strictEqual(tree.dependencies.length, 3);
    assert.strictEqual(new Set(tree.dependencies.map((dependency) => dependency.name)).size, 3);
  });

  test("honors cancellation before parsing lock inventory", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "Gemfile.lock");
    await writeTextFile(lockfilePath, ["GEM", "  specs:", "    a (1.0.0)", ""].join("\n"));

    await assert.rejects(
      rubyParser.resolve({
        lockfilePath,
        workspaceFolder: workspace,
        options: { cancellationToken: { isCancellationRequested: true } },
      }),
      (error) => error && error.code === "ERR_DEPENDENCY_TRAVERSAL_CANCELLED"
    );
  });
});

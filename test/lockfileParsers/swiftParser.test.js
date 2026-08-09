const assert = require("assert");
const path = require("path");
const swiftParser = require("../../util/lockfileParsers/swiftParser");
const {
  makeTempWorkspace,
  removeDirectory,
  writeTextFile,
} = require("../helpers/fixtureWorkspace");

suite("swiftParser Test Suite", () => {
  const tempDirs = [];

  async function createWorkspace() {
    const workspace = await makeTempWorkspace("cloudsmith-swift-parser-");
    tempDirs.push(workspace);
    return workspace;
  }

  suiteTeardown(async () => {
    await Promise.all(tempDirs.map((tempDir) => removeDirectory(tempDir)));
  });

  test("does not reinterpret a resolved branch revision as a package version", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "Package.swift");
    const lockfilePath = path.join(workspace, "Package.resolved");
    await writeTextFile(manifestPath, [
      "// swift-tools-version: 5.9",
      "import PackageDescription",
      "let package = Package(",
      '  name: "Fixture",',
      "  dependencies: [",
      '    .package(url: "https://github.com/example/BranchPackage.git", branch: "main")',
      "  ]",
      ")",
      "",
    ].join("\n"));
    await writeTextFile(lockfilePath, JSON.stringify({
      pins: [{
        identity: "branchpackage",
        location: "https://github.com/example/BranchPackage.git",
        state: {
          branch: "main",
          revision: "abcdef1234567890",
        },
      }],
      version: 2,
    }, null, 2));

    const tree = await swiftParser.resolve({
      lockfilePath,
      manifestPath,
      workspaceFolder: workspace,
    });
    const dependency = tree.dependencies[0];

    assert.strictEqual(dependency.name, "branchpackage");
    assert.strictEqual(dependency.version, "");
    assert.strictEqual(dependency.sourceBranch, "main");
    assert.strictEqual(dependency.sourceRevision, "abcdef1234567890");
  });
});

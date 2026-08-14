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
    assert.deepStrictEqual(dependency.packageSource, {
      kind: "scm",
      location: "https://github.com/example/BranchPackage.git",
      branch: "main",
      revision: "abcdef1234567890",
    });
    assert.strictEqual(dependency.isDirect, true);
  });

  test("preserves registry scope, SCM provenance, local origin, and directness", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "Package.swift");
    const lockfilePath = path.join(workspace, "Package.resolved");
    await writeTextFile(manifestPath, [
      "// swift-tools-version: 6.0",
      "import PackageDescription",
      "let package = Package(",
      '  name: "Fixture",',
      "  dependencies: [",
      '    .package(id: "Acme.Logging", exact: "1.2.3"),',
      '    .package(url: "https://github.com/example/Remote.git", exact: "2.0.0"),',
      '    .package(path: "../LocalPackage")',
      "  ]",
      ")",
      "",
    ].join("\n"));
    await writeTextFile(lockfilePath, JSON.stringify({
      pins: [
        {
          identity: "Acme.Logging",
          kind: "registry",
          location: "https://swift.example/acme.logging",
          state: { version: "1.2.3" },
        },
        {
          identity: "remote",
          kind: "remoteSourceControl",
          location: "https://github.com/example/Remote.git",
          state: { version: "2.0.0", revision: "remote-revision" },
        },
        {
          identity: "localpackage",
          kind: "localSourceControl",
          location: "../LocalPackage",
          state: { revision: "local-revision" },
        },
        {
          identity: "transitive",
          kind: "remoteSourceControl",
          location: "https://github.com/example/Transitive.git",
          state: { version: "3.0.0", revision: "transitive-revision" },
        },
      ],
      version: 2,
    }, null, 2));

    const tree = await swiftParser.resolve({
      lockfilePath,
      manifestPath,
      workspaceFolder: workspace,
    });
    const byName = new Map(tree.dependencies.map((dependency) => [dependency.name, dependency]));

    assert.strictEqual(byName.get("acme.logging").version, "1.2.3");
    assert.strictEqual(byName.get("acme.logging").swiftScope, "acme");
    assert.deepStrictEqual(byName.get("acme.logging").qualifiers, { scope: "acme" });
    assert.strictEqual(byName.get("acme.logging").packageSource.kind, "registry");
    assert.strictEqual(byName.get("acme.logging").isDirect, true);
    assert.deepStrictEqual(byName.get("remote").packageSource, {
      kind: "scm",
      location: "https://github.com/example/Remote.git",
      revision: "remote-revision",
    });
    assert.strictEqual(byName.get("remote").isDirect, true);
    assert.strictEqual(byName.get("localpackage").version, "");
    assert.deepStrictEqual(byName.get("localpackage").packageSource, {
      kind: "path",
      location: "../LocalPackage",
    });
    assert.strictEqual(byName.get("localpackage").isDirect, true);
    assert.strictEqual(byName.get("transitive").isDirect, false);
  });

  test("does not collapse or basename-match SCM pins from different origins", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "Package.swift");
    const lockfilePath = path.join(workspace, "Package.resolved");
    await writeTextFile(manifestPath, [
      "// swift-tools-version: 6.0",
      "import PackageDescription",
      "let package = Package(",
      '  name: "Fixture",',
      "  dependencies: [",
      '    .package(url: "https://github.com/first/Shared.git", exact: "1.0.0")',
      "  ]",
      ")",
      "",
    ].join("\n"));
    await writeTextFile(lockfilePath, JSON.stringify({
      pins: [
        {
          identity: "shared",
          kind: "remoteSourceControl",
          location: "https://github.com/first/Shared.git",
          state: { version: "1.0.0", revision: "first-revision" },
        },
        {
          identity: "shared",
          kind: "remoteSourceControl",
          location: "https://github.com/second/Shared.git",
          state: { version: "1.0.0", revision: "second-revision" },
        },
      ],
      version: 2,
    }, null, 2));

    const tree = await swiftParser.resolve({
      lockfilePath,
      manifestPath,
      workspaceFolder: workspace,
    });

    assert.strictEqual(tree.dependencies.length, 2);
    assert.strictEqual(tree.dependencies.filter((dependency) => dependency.isDirect).length, 1);
    assert.strictEqual(
      tree.dependencies.find((dependency) => dependency.isDirect).swiftLocation,
      "https://github.com/first/Shared.git"
    );
    assert.strictEqual(
      tree.dependencies.find((dependency) => !dependency.isDirect).swiftLocation,
      "https://github.com/second/Shared.git"
    );
    assert.ok(tree.dependencies.every((dependency) => dependency.packageSource.kind === "scm"));
  });
});

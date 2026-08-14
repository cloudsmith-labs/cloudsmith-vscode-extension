const assert = require("assert");
const path = require("path");
const goParser = require("../../util/lockfileParsers/goParser");
const {
  makeTempWorkspace,
  removeDirectory,
  writeTextFile,
} = require("../helpers/fixtureWorkspace");

suite("goParser Test Suite", () => {
  const tempDirs = [];

  async function createWorkspace() {
    const workspace = await makeTempWorkspace("cloudsmith-go-parser-");
    tempDirs.push(workspace);
    return workspace;
  }

  suiteTeardown(async () => {
    await Promise.all(tempDirs.map((tempDir) => removeDirectory(tempDir)));
  });

  test("treats indirect modules as transitive rather than development dependencies", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "go.mod");
    await writeTextFile(manifestPath, [
      "module example.com/fixture",
      "",
      "go 1.21",
      "",
      "require (",
      "  github.com/example/direct v1.2.3",
      "  github.com/example/indirect v2.3.4 // indirect",
      ")",
      "",
    ].join("\n"));

    const tree = await goParser.resolve({
      manifestPath,
      workspaceFolder: workspace,
    });
    const indirect = tree.dependencies.find((dependency) => dependency.name.endsWith("/indirect"));

    assert.ok(indirect);
    assert.strictEqual(indirect.version, "v2.3.4");
    assert.strictEqual(indirect.isDirect, false);
    assert.strictEqual(indirect.isDevelopmentDependency, false);
    assert.deepStrictEqual(indirect.packageSource, { kind: "registry" });
  });

  test("keeps locally replaced modules unresolved instead of trusting the required version", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "go.mod");
    await writeTextFile(manifestPath, [
      "module example.com/fixture",
      "",
      "go 1.21",
      "",
      "require example.com/original v1.2.3",
      "replace example.com/original => ../local-original",
      "",
    ].join("\n"));

    const tree = await goParser.resolve({ manifestPath, workspaceFolder: workspace });
    const dependency = tree.dependencies[0];

    assert.strictEqual(dependency.name, "example.com/original");
    assert.strictEqual(dependency.declarationName, "example.com/original");
    assert.strictEqual(dependency.version, "");
    assert.strictEqual(dependency.declaredConstraint, "path:../local-original");
    assert.strictEqual(dependency.versionState, "incomplete");
    assert.strictEqual(dependency.hasResolutionEvidence, false);
    assert.deepStrictEqual(dependency.packageSource, {
      kind: "path",
      location: "../local-original",
    });
  });

  test("uses an exact module replacement identity and version", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "go.mod");
    await writeTextFile(manifestPath, [
      "module example.com/fixture",
      "",
      "go 1.21",
      "",
      "require example.com/original v1.2.3",
      "replace example.com/original v1.2.3 => example.com/fork v1.9.4",
      "",
    ].join("\n"));

    const tree = await goParser.resolve({ manifestPath, workspaceFolder: workspace });
    const dependency = tree.dependencies[0];

    assert.strictEqual(dependency.name, "example.com/fork");
    assert.strictEqual(dependency.declarationName, "example.com/original");
    assert.strictEqual(dependency.version, "v1.9.4");
    assert.strictEqual(dependency.declaredConstraint, "v1.9.4");
    assert.strictEqual(dependency.versionState, "exact-declaration");
    assert.strictEqual(dependency.requiredVersion, "v1.2.3");
    assert.strictEqual(dependency.replacementFor, "example.com/original");
    assert.deepStrictEqual(dependency.packageSource, { kind: "registry" });
  });

  test("applies replacement blocks and prefers version-specific replacement evidence", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "go.mod");
    await writeTextFile(manifestPath, [
      "module example.com/fixture",
      "",
      "go 1.21",
      "",
      "require (",
      "  example.com/first v1.0.0",
      "  example.com/second v2.0.0",
      ")",
      "",
      "replace (",
      "  example.com/first => example.com/first-fork v1.4.0",
      "  example.com/second => example.com/general-fork v2.1.0",
      "  example.com/second v2.0.0 => example.com/specific-fork v2.2.0",
      ")",
      "",
    ].join("\n"));

    const tree = await goParser.resolve({ manifestPath, workspaceFolder: workspace });
    const byDeclaration = new Map(
      tree.dependencies.map((dependency) => [dependency.declarationName, dependency])
    );

    assert.strictEqual(byDeclaration.get("example.com/first").name, "example.com/first-fork");
    assert.strictEqual(byDeclaration.get("example.com/first").version, "v1.4.0");
    assert.strictEqual(byDeclaration.get("example.com/second").name, "example.com/specific-fork");
    assert.strictEqual(byDeclaration.get("example.com/second").version, "v2.2.0");
  });

  test("keeps unsupported and duplicate replacement declarations unresolved", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "go.mod");
    await writeTextFile(manifestPath, [
      "module example.com/fixture",
      "",
      "go 1.21",
      "",
      "require (",
      "  example.com/unversioned v1.0.0",
      "  example.com/duplicate v1.0.0",
      ")",
      "",
      "replace example.com/unversioned => example.com/fork",
      "replace example.com/duplicate => example.com/fork-a v1.1.0",
      "replace example.com/duplicate => example.com/fork-b v1.2.0",
      "",
    ].join("\n"));

    const tree = await goParser.resolve({ manifestPath, workspaceFolder: workspace });
    const byName = new Map(tree.dependencies.map((dependency) => [dependency.name, dependency]));

    assert.strictEqual(byName.get("example.com/unversioned").version, "");
    assert.strictEqual(byName.get("example.com/unversioned").versionState, "incomplete");
    assert.match(byName.get("example.com/unversioned").declaredConstraint, /^replace:/);
    assert.strictEqual(byName.get("example.com/duplicate").version, "");
    assert.strictEqual(byName.get("example.com/duplicate").versionState, "incomplete");
    assert.match(byName.get("example.com/duplicate").declaredConstraint, /^replace:/);
  });

  test("preserves case-distinct Go module identities", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "go.mod");
    await writeTextFile(manifestPath, [
      "module example.com/fixture",
      "",
      "go 1.21",
      "",
      "require (",
      "  example.com/Org/library v1.2.3",
      "  example.com/org/library v1.2.3",
      ")",
      "",
    ].join("\n"));

    const tree = await goParser.resolve({ manifestPath, workspaceFolder: workspace });

    assert.strictEqual(tree.dependencies.length, 2);
    assert.deepStrictEqual(
      new Set(tree.dependencies.map((dependency) => dependency.name)),
      new Set(["example.com/Org/library", "example.com/org/library"])
    );
    assert.ok(tree.dependencies.every((dependency) => dependency.version === "v1.2.3"));
  });

  test("retains exactly one leading v for semantic and pseudo versions", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "go.mod");
    await writeTextFile(manifestPath, [
      "module example.com/fixture",
      "",
      "go 1.21",
      "",
      "require (",
      "  example.com/semantic v1.2.3",
      "  example.com/pseudo v0.0.0-20240102123456-abcdef123456",
      ")",
      "",
    ].join("\n"));

    const tree = await goParser.resolve({ manifestPath, workspaceFolder: workspace });

    assert.deepStrictEqual(
      tree.dependencies.map((dependency) => dependency.version),
      ["v1.2.3", "v0.0.0-20240102123456-abcdef123456"]
    );
    assert.ok(tree.dependencies.every((dependency) => /^v[^v]/.test(dependency.version)));
  });
});

const assert = require("assert");
const path = require("path");
const cargoParser = require("../../util/lockfileParsers/cargoParser");
const {
  makeTempWorkspace,
  removeDirectory,
  writeTextFile,
} = require("../helpers/fixtureWorkspace");

suite("cargoParser Test Suite", () => {
  const fixtureDir = path.join(__dirname, "..", "fixtures", "cargo");
  const tempDirs = [];

  async function createWorkspace() {
    const workspace = await makeTempWorkspace("cloudsmith-cargo-parser-");
    tempDirs.push(workspace);
    return workspace;
  }

  suiteTeardown(async () => {
    await Promise.all(tempDirs.map((tempDir) => removeDirectory(tempDir)));
  });

  test("resolves Cargo.lock uniquely, skips the root package, and marks direct dependencies from Cargo.toml", async () => {
    const tree = await cargoParser.resolve({
      lockfilePath: path.join(fixtureDir, "Cargo.lock"),
      manifestPath: path.join(fixtureDir, "Cargo.toml"),
    });

    assert.strictEqual(tree.sourceFile, "Cargo.lock");
    assert.strictEqual(tree.dependencies.length, 3);
    assert.strictEqual(tree.dependencies.some((dependency) => dependency.name === "fixture-cargo"), false);

    const serde = tree.dependencies.find((dependency) => dependency.name === "serde");
    const tokio = tree.dependencies.find((dependency) => dependency.name === "tokio");
    const bytes = tree.dependencies.find((dependency) => dependency.name === "bytes");

    assert.ok(serde);
    assert.ok(tokio);
    assert.ok(bytes);
    assert.strictEqual(serde.isDirect, true);
    assert.strictEqual(tokio.isDirect, true);
    assert.strictEqual(bytes.isDirect, false);
    assert.strictEqual(serde.isDevelopmentDependency, false);
    assert.strictEqual(tokio.isDevelopmentDependency, true);
    assert.strictEqual(bytes.isDevelopmentDependency, true);
    assert.deepStrictEqual(bytes.parentChain, ["tokio"]);
  });

  test("preserves Cargo constraints without treating default caret requirements as exact", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "Cargo.toml");
    await writeTextFile(manifestPath, [
      "[package]",
      'name = "fixture-cargo"',
      'version = "0.1.0"',
      "",
      "[dependencies]",
      'ranged = "1.2.3"',
      'exact = "=2.0.0"',
      'local-package = { version = "1.0.0", path = "../local-package" }',
      "",
    ].join("\n"));

    const tree = await cargoParser.resolve({ manifestPath });
    const byName = new Map(tree.dependencies.map((dependency) => [dependency.name, dependency]));

    assert.strictEqual(byName.get("ranged").declaredConstraint, "1.2.3");
    assert.strictEqual(byName.get("ranged").versionState, "range");
    assert.strictEqual(byName.get("exact").declaredConstraint, "=2.0.0");
    assert.strictEqual(byName.get("exact").versionState, "exact-declaration");
    assert.strictEqual(byName.get("local-package").version, "");
    assert.strictEqual(byName.get("local-package").declaredConstraint, "path:../local-package");
    assert.strictEqual(byName.get("local-package").versionState, "incomplete");
  });

  test("uses Cargo.lock root edges to join the correct direct version and preserves another version", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "Cargo.toml");
    const lockfilePath = path.join(workspace, "Cargo.lock");
    const registrySource = "registry+https://github.com/rust-lang/crates.io-index";
    await writeTextFile(manifestPath, [
      "[package]",
      'name = "fixture-cargo"',
      'version = "0.1.0"',
      "",
      "[dependencies]",
      'shared = "1"',
      "",
    ].join("\n"));
    await writeTextFile(lockfilePath, [
      "[[package]]",
      'name = "fixture-cargo"',
      'version = "0.1.0"',
      'dependencies = ["shared 1.9.0"]',
      "",
      "[[package]]",
      'name = "shared"',
      'version = "1.9.0"',
      `source = "${registrySource}"`,
      "",
      "[[package]]",
      'name = "shared"',
      'version = "2.1.0"',
      `source = "${registrySource}"`,
      "",
    ].join("\n"));

    const tree = await cargoParser.resolve({ lockfilePath, manifestPath });
    const shared = tree.dependencies.filter((dependency) => dependency.name === "shared");

    assert.deepStrictEqual(shared.map((dependency) => dependency.version).sort(), ["1.9.0", "2.1.0"]);
    assert.strictEqual(shared.find((dependency) => dependency.version === "1.9.0").isDirect, true);
    assert.strictEqual(shared.find((dependency) => dependency.version === "1.9.0").declaredConstraint, "1");
    assert.strictEqual(shared.find((dependency) => dependency.version === "2.1.0").isDirect, false);
  });

  test("keeps an ambiguous direct Cargo declaration unresolved when root-edge evidence is absent", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "Cargo.toml");
    const lockfilePath = path.join(workspace, "Cargo.lock");
    const registrySource = "registry+https://github.com/rust-lang/crates.io-index";
    await writeTextFile(manifestPath, [
      "[dependencies]",
      'shared = "1"',
      "",
    ].join("\n"));
    await writeTextFile(lockfilePath, [
      "[[package]]",
      'name = "shared"',
      'version = "1.9.0"',
      `source = "${registrySource}"`,
      "",
      "[[package]]",
      'name = "shared"',
      'version = "2.1.0"',
      `source = "${registrySource}"`,
      "",
    ].join("\n"));

    const tree = await cargoParser.resolve({ lockfilePath, manifestPath });
    const shared = tree.dependencies.filter((dependency) => dependency.name === "shared");
    const declaration = shared.find((dependency) => dependency.isDirect);

    assert.ok(declaration);
    assert.strictEqual(declaration.version, "");
    assert.strictEqual(declaration.declaredConstraint, "1");
    assert.strictEqual(declaration.versionState, "range");
    assert.strictEqual(shared.filter((dependency) => dependency.version).every((dependency) => !dependency.isDirect), true);
  });

  test("preserves Cargo versions whose prerelease identifiers differ only by case", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "Cargo.toml");
    const lockfilePath = path.join(workspace, "Cargo.lock");
    const registrySource = "registry+https://github.com/rust-lang/crates.io-index";
    await writeTextFile(manifestPath, [
      "[package]",
      'name = "fixture-cargo"',
      'version = "0.1.0"',
      "",
      "[dependencies]",
      'root = "1"',
      "",
    ].join("\n"));
    await writeTextFile(lockfilePath, [
      "[[package]]",
      'name = "fixture-cargo"',
      'version = "0.1.0"',
      'dependencies = ["root 1.0.0"]',
      "",
      "[[package]]",
      'name = "root"',
      'version = "1.0.0"',
      `source = "${registrySource}"`,
      'dependencies = ["shared 1.0.0-RC1", "shared 1.0.0-rc1"]',
      "",
      "[[package]]",
      'name = "shared"',
      'version = "1.0.0-RC1"',
      `source = "${registrySource}"`,
      "",
      "[[package]]",
      'name = "shared"',
      'version = "1.0.0-rc1"',
      `source = "${registrySource}"`,
      "",
    ].join("\n"));

    const tree = await cargoParser.resolve({ lockfilePath, manifestPath, workspaceFolder: workspace });
    const sharedVersions = tree.dependencies
      .filter((dependency) => dependency.name === "shared")
      .map((dependency) => dependency.version);

    assert.deepStrictEqual(new Set(sharedVersions), new Set(["1.0.0-RC1", "1.0.0-rc1"]));
  });

  test("detect returns no matches when Cargo files are missing", async () => {
    const workspace = await createWorkspace();

    const matches = await cargoParser.detect(workspace);

    assert.deepStrictEqual(matches, []);
    assert.strictEqual(await cargoParser.canResolve(workspace), false);
  });

  test("throws for malformed Cargo.lock files", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "Cargo.lock");
    const manifestPath = path.join(workspace, "Cargo.toml");
    await writeTextFile(lockfilePath, "[[package]]\nname = \"broken\"\n");
    await writeTextFile(manifestPath, "[dependencies]\nserde = \"1.0.0\"\n");

    await assert.rejects(
      () => cargoParser.resolve({ lockfilePath, manifestPath }),
      /Malformed Cargo\.lock: no package entries found/
    );
  });

  test("deduplicates large Cargo graphs down to unique packages", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "Cargo.lock");
    const manifestPath = path.join(workspace, "Cargo.toml");
    const packageCount = 300;
    const registrySource = "registry+https://github.com/rust-lang/crates.io-index";

    const manifestLines = [
      "[package]",
      'name = "fixture-cargo"',
      'version = "0.1.0"',
      "",
      "[dependencies]",
      'crate-000 = "1.0.0"',
    ];

    const lockEntries = [];
    for (let index = 0; index < packageCount; index += 1) {
      const currentName = `crate-${String(index).padStart(3, "0")}`;
      const nextName = index + 1 < packageCount
        ? `crate-${String(index + 1).padStart(3, "0")}`
        : null;
      lockEntries.push(
        [
          "[[package]]",
          `name = "${currentName}"`,
          'version = "1.0.0"',
          `source = "${registrySource}"`,
          nextName
            ? `dependencies = ["${nextName} 1.0.0"]`
            : "",
          "",
        ].filter(Boolean).join("\n")
      );
    }

    await writeTextFile(manifestPath, manifestLines.join("\n"));
    await writeTextFile(lockfilePath, lockEntries.join("\n"));

    const tree = await cargoParser.resolve({
      lockfilePath,
      manifestPath,
    });

    assert.strictEqual(tree.dependencies.length, packageCount);
    assert.strictEqual(
      new Set(tree.dependencies.map((dependency) => `${dependency.name}@${dependency.version}`)).size,
      packageCount
    );
    assert.match(tree.warnings[0], /maximum depth of 128/);
  });

  test("bounds Cargo graph depth and reports partial traversal structurally", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "Cargo.lock");
    const manifestPath = path.join(workspace, "Cargo.toml");
    const packageCount = 20;
    const registrySource = "registry+https://github.com/rust-lang/crates.io-index";
    const lockEntries = [];

    for (let index = 0; index < packageCount; index += 1) {
      const currentName = `depth-${String(index).padStart(2, "0")}`;
      const nextName = index + 1 < packageCount
        ? `depth-${String(index + 1).padStart(2, "0")}`
        : null;
      lockEntries.push([
        "[[package]]",
        `name = "${currentName}"`,
        'version = "1.0.0"',
        `source = "${registrySource}"`,
        nextName ? `dependencies = ["${nextName} 1.0.0"]` : "",
        "",
      ].filter(Boolean).join("\n"));
    }

    await writeTextFile(manifestPath, '[dependencies]\ndepth-00 = "1"\n');
    await writeTextFile(lockfilePath, lockEntries.join("\n"));

    const tree = await cargoParser.resolve({
      lockfilePath,
      manifestPath,
      options: { cargoGraphMaxDepth: 8 },
    });

    assert.match(tree.warnings[0], /maximum depth of 8/);
    const pending = tree.dependencies.slice();
    let deepestParentChain = 0;
    while (pending.length > 0) {
      const dependency = pending.pop();
      deepestParentChain = Math.max(deepestParentChain, dependency.parentChain.length);
      pending.push(...dependency.transitives);
    }
    assert.strictEqual(deepestParentChain, 8);
  });

  test("bounds Cargo graph node expansion and reports incomplete results", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "Cargo.lock");
    const manifestPath = path.join(workspace, "Cargo.toml");
    const packageCount = 30;
    const registrySource = "registry+https://github.com/rust-lang/crates.io-index";
    const dependencyReferences = [];
    const lockEntries = [];

    for (let index = 0; index < packageCount; index += 1) {
      const name = `wide-${String(index).padStart(2, "0")}`;
      dependencyReferences.push(`"${name} 1.0.0"`);
      lockEntries.push([
        "[[package]]",
        `name = "${name}"`,
        'version = "1.0.0"',
        `source = "${registrySource}"`,
        "",
      ].join("\n"));
    }
    lockEntries.unshift([
      "[[package]]",
      'name = "fixture-cargo"',
      'version = "0.1.0"',
      `dependencies = [${dependencyReferences.join(", ")}]`,
      "",
    ].join("\n"));

    await writeTextFile(manifestPath, [
      "[package]",
      'name = "fixture-cargo"',
      'version = "0.1.0"',
      "",
      "[dependencies]",
      'wide-00 = "1"',
      "",
    ].join("\n"));
    await writeTextFile(lockfilePath, lockEntries.join("\n"));

    const tree = await cargoParser.resolve({
      lockfilePath,
      manifestPath,
      options: { cargoGraphMaxNodes: 10 },
    });

    assert.strictEqual(tree.dependencies.length, 10);
    assert.match(tree.warnings[0], /maximum expansion of 10 nodes/);
  });
});

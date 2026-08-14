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
    assert.strictEqual(bytes.isDevelopmentDependency, false);
    assert.deepStrictEqual(bytes.parentChain, ["tokio"]);
    assert.deepStrictEqual(serde.packageSource, {
      kind: "registry",
      location: "https://github.com/rust-lang/crates.io-index",
    });
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
    assert.deepStrictEqual(byName.get("local-package").packageSource, {
      kind: "path",
      location: "../local-package",
    });
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
    assert.strictEqual(
      tree.warnings[0],
      "Some Cargo dependency relationships were omitted to keep the scan responsive. Package inventory remains complete."
    );
  });

  test("retains the canonical 653 package, 59 direct, and seven development inventory contract", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "Cargo.lock");
    const manifestPath = path.join(workspace, "Cargo.toml");
    const registrySource = "registry+https://github.com/rust-lang/crates.io-index";
    const packageCount = 653;
    const directCount = 59;
    const developmentCount = 7;
    const names = Array.from(
      { length: packageCount },
      (_, index) => `crate-${String(index).padStart(3, "0")}`
    );
    const directNames = names.slice(0, directCount);
    const transitiveNames = names.slice(directCount);
    await writeTextFile(manifestPath, [
      "[package]",
      'name = "fixture-cargo"',
      'version = "0.1.0"',
      "",
      "[dependencies]",
      ...directNames.slice(0, directCount - developmentCount).map((name) => `${name} = "1"`),
      "",
      "[dev-dependencies]",
      ...directNames.slice(directCount - developmentCount).map((name) => `${name} = "1"`),
      "",
    ].join("\n"));
    const sharedReferences = transitiveNames.map((name) => `"${name} 1.0.0"`).join(", ");
    await writeTextFile(lockfilePath, [
      "[[package]]",
      'name = "fixture-cargo"',
      'version = "0.1.0"',
      `dependencies = [${directNames.map((name) => `"${name} 1.0.0"`).join(", ")}]`,
      "",
      ...names.flatMap((name, index) => [
        "[[package]]",
        `name = "${name}"`,
        'version = "1.0.0"',
        `source = "${registrySource}"`,
        index < directCount ? `dependencies = [${sharedReferences}]` : "",
        "",
      ]),
    ].join("\n"));

    const tree = await cargoParser.resolve({
      lockfilePath,
      manifestPath,
      workspaceFolder: workspace,
    });

    assert.strictEqual(tree.dependencies.length, 653);
    assert.strictEqual(tree.dependencies.filter((dependency) => dependency.isDirect).length, 59);
    assert.strictEqual(tree.dependencies.filter((dependency) => !dependency.isDirect).length, 594);
    assert.strictEqual(
      tree.dependencies.filter((dependency) => dependency.isDevelopmentDependency).length,
      7
    );
    assert.deepStrictEqual(tree.warnings, []);
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

    assert.match(tree.warnings[0], /Package inventory remains complete/);
    assert.doesNotMatch(tree.warnings[0], /\b8\b|maximum|limit/i);
    const pending = tree.dependencies.slice();
    let deepestParentChain = 0;
    while (pending.length > 0) {
      const dependency = pending.pop();
      deepestParentChain = Math.max(deepestParentChain, dependency.parentChain.length);
      pending.push(...dependency.transitives);
    }
    assert.strictEqual(deepestParentChain, 8);
  });

  test("does not apply relationship bounds to Cargo package inventory", async () => {
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

    assert.strictEqual(tree.dependencies.length, packageCount);
    assert.deepStrictEqual(tree.warnings, []);
  });

  test("keeps every direct and development root when a shared graph exceeds relationship bounds", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "Cargo.lock");
    const manifestPath = path.join(workspace, "Cargo.toml");
    const registrySource = "registry+https://github.com/rust-lang/crates.io-index";
    const directCount = 12;
    const directNames = Array.from(
      { length: directCount },
      (_, index) => `root-${String(index).padStart(2, "0")}`
    );
    await writeTextFile(manifestPath, [
      "[package]",
      'name = "fixture-cargo"',
      'version = "0.1.0"',
      "",
      "[dependencies]",
      ...directNames.slice(0, -1).map((name) => `${name} = "1"`),
      "",
      "[dev-dependencies]",
      `${directNames[directNames.length - 1]} = "1"`,
      "",
    ].join("\n"));
    await writeTextFile(lockfilePath, [
      "[[package]]",
      'name = "fixture-cargo"',
      'version = "0.1.0"',
      `dependencies = [${directNames.map((name) => `"${name} 1.0.0"`).join(", ")}]`,
      "",
      ...directNames.flatMap((name) => [
        "[[package]]",
        `name = "${name}"`,
        'version = "1.0.0"',
        `source = "${registrySource}"`,
        'dependencies = ["shared 1.0.0"]',
        "",
      ]),
      "[[package]]",
      'name = "shared"',
      'version = "1.0.0"',
      `source = "${registrySource}"`,
      "",
    ].join("\n"));

    const tree = await cargoParser.resolve({
      lockfilePath,
      manifestPath,
      workspaceFolder: workspace,
      options: { cargoGraphMaxNodes: 5, cargoGraphMaxEdges: 5 },
    });

    assert.strictEqual(tree.dependencies.length, directCount + 1);
    assert.strictEqual(tree.dependencies.filter((dependency) => dependency.isDirect).length, directCount);
    assert.strictEqual(
      tree.dependencies.filter((dependency) => dependency.isDevelopmentDependency).length,
      1
    );
    assert.strictEqual(tree.dependencies.find((dependency) => dependency.name === "shared").isDirect, false);
    assert.match(tree.warnings[0], /Package inventory remains complete/);
  });

  test("honors cancellation while building bounded Cargo relationships", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "Cargo.lock");
    const manifestPath = path.join(workspace, "Cargo.toml");
    const registrySource = "registry+https://github.com/rust-lang/crates.io-index";
    const packageCount = 30;
    await writeTextFile(manifestPath, '[dependencies]\ncrate-00 = "1"\n');
    await writeTextFile(lockfilePath, Array.from({ length: packageCount }, (_, index) => [
      "[[package]]",
      `name = "crate-${String(index).padStart(2, "0")}"`,
      'version = "1.0.0"',
      `source = "${registrySource}"`,
      index + 1 < packageCount
        ? `dependencies = ["crate-${String(index + 1).padStart(2, "0")} 1.0.0"]`
        : "",
      "",
    ].filter(Boolean).join("\n")).join("\n"));
    let checks = 0;
    const cancellationToken = {
      get isCancellationRequested() {
        checks += 1;
        return checks > 40;
      },
    };

    await assert.rejects(
      () => cargoParser.resolve({
        lockfilePath,
        manifestPath,
        workspaceFolder: workspace,
        options: { cancellationToken },
      }),
      (error) => error.code === "dependency-scan-cancelled"
        && error.message === "Cargo dependency parsing was canceled."
    );
    assert.ok(checks > 40);
  });
});

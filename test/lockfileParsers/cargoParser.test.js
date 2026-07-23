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
    assert.deepStrictEqual(bytes.parentChain, ["tokio"]);
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
  });
});

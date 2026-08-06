const assert = require("assert");
const path = require("path");
const npmParser = require("../../util/lockfileParsers/npmParser");
const {
  makeTempWorkspace,
  removeDirectory,
  writeTextFile,
} = require("../helpers/fixtureWorkspace");

suite("npmParser Test Suite", () => {
  const fixtureDir = path.join(__dirname, "..", "fixtures", "npm");
  const tempDirs = [];

  async function createWorkspace() {
    const workspace = await makeTempWorkspace("cloudsmith-npm-parser-");
    tempDirs.push(workspace);
    return workspace;
  }

  suiteTeardown(async () => {
    await Promise.all(tempDirs.map((tempDir) => removeDirectory(tempDir)));
  });

  test("resolves package-lock.json with deduplication, scoped packages, and root skipping", async () => {
    const tree = await npmParser.resolve({
      lockfilePath: path.join(fixtureDir, "package-lock.json"),
      manifestPath: path.join(fixtureDir, "package.json"),
      options: { maxDependenciesToScan: 10000 },
    });

    assert.strictEqual(tree.sourceFile, "package-lock.json");
    assert.strictEqual(tree.dependencies.length, 3);
    assert.strictEqual(tree.dependencies.some((dependency) => dependency.name === "fixture-app"), false);

    const express = tree.dependencies.find((dependency) => dependency.name === "express");
    const accepts = tree.dependencies.find((dependency) => dependency.name === "accepts");
    const scoped = tree.dependencies.find((dependency) => dependency.name === "@scope/pkg");

    assert.ok(express);
    assert.ok(accepts);
    assert.ok(scoped);
    assert.strictEqual(express.isDirect, true);
    assert.strictEqual(accepts.isDirect, false);
    assert.deepStrictEqual(accepts.parentChain, ["express"]);
    assert.strictEqual(scoped.version, "1.0.0");
  });

  test("resolves yarn.lock fixtures", async () => {
    const tree = await npmParser.resolve({
      lockfilePath: path.join(fixtureDir, "yarn.lock"),
      manifestPath: path.join(fixtureDir, "package.json"),
      options: { maxDependenciesToScan: 10000 },
    });

    assert.strictEqual(tree.sourceFile, "yarn.lock");
    assert.strictEqual(tree.dependencies.length, 3);
    assert.ok(tree.dependencies.some((dependency) => dependency.name === "@scope/pkg"));
  });

  test("preserves multiple resolved versions for the same yarn package", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "yarn.lock");
    const manifestPath = path.join(workspace, "package.json");

    await writeTextFile(manifestPath, JSON.stringify({
      name: "fixture-app",
      version: "1.0.0",
      dependencies: {
        "package-a": "^1.0.0",
        "package-b": "^1.0.0",
      },
    }, null, 2));

    await writeTextFile(lockfilePath, [
      "package-a@^1.0.0:",
      '  version "1.0.0"',
      "  dependencies:",
      '    left-pad "^1.0.0"',
      "",
      "package-b@^1.0.0:",
      '  version "1.0.0"',
      "  dependencies:",
      '    left-pad "^2.0.0"',
      "",
      "left-pad@^1.0.0:",
      '  version "1.0.1"',
      "",
      "left-pad@^2.0.0:",
      '  version "2.0.0"',
      "",
    ].join("\n"));

    const tree = await npmParser.resolve({
      lockfilePath,
      manifestPath,
      options: { maxDependenciesToScan: 10000 },
    });

    const packageKeys = tree.dependencies.map((dependency) => `${dependency.name}@${dependency.version}`);
    const packageA = tree.dependencies.find((dependency) => dependency.name === "package-a");
    const packageB = tree.dependencies.find((dependency) => dependency.name === "package-b");

    assert.ok(packageA);
    assert.ok(packageB);
    assert.strictEqual(packageA.transitives[0].version, "1.0.1");
    assert.strictEqual(packageB.transitives[0].version, "2.0.0");
    assert.ok(packageKeys.includes("left-pad@1.0.1"));
    assert.ok(packageKeys.includes("left-pad@2.0.0"));
    assert.strictEqual(packageKeys.filter((key) => key.startsWith("left-pad@")).length, 2);
  });

  test("resolves pnpm-lock.yaml fixtures", async () => {
    const tree = await npmParser.resolve({
      lockfilePath: path.join(fixtureDir, "pnpm-lock.yaml"),
      manifestPath: path.join(fixtureDir, "package.json"),
      options: { maxDependenciesToScan: 10000 },
    });

    assert.strictEqual(tree.sourceFile, "pnpm-lock.yaml");
    assert.strictEqual(tree.dependencies.length, 3);
    assert.ok(tree.dependencies.some((dependency) => dependency.name === "accepts"));
  });

  test("detect returns no matches when npm lockfiles are missing", async () => {
    const workspace = await createWorkspace();

    const matches = await npmParser.detect(workspace);

    assert.deepStrictEqual(matches, []);
    assert.strictEqual(await npmParser.canResolve(workspace), false);
  });

  test("resolve ignores manifests outside the provided workspace folder", async () => {
    const workspace = await createWorkspace();
    const outsideWorkspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "package-lock.json");
    const manifestPath = path.join(outsideWorkspace, "package.json");

    await writeTextFile(lockfilePath, JSON.stringify({
      name: "fixture-app",
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/express": {
          version: "4.18.2",
        },
      },
    }, null, 2));
    await writeTextFile(manifestPath, JSON.stringify({
      dependencies: {
        express: "^4.18.0",
      },
    }, null, 2));

    const tree = await npmParser.resolve({
      workspaceFolder: workspace,
      lockfilePath,
      manifestPath,
      options: { maxDependenciesToScan: 10000 },
    });

    const express = tree.dependencies.find((dependency) => dependency.name === "express");

    assert.ok(express);
    assert.strictEqual(
      express.isDirect,
      false,
      "out-of-workspace manifests should not influence direct dependency classification"
    );
  });

  test("throws for malformed package-lock.json files", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "package-lock.json");
    const manifestPath = path.join(workspace, "package.json");
    await writeTextFile(lockfilePath, "{\n  \"name\": \"broken\"\n}\n");
    await writeTextFile(manifestPath, "{\n  \"dependencies\": {}\n}\n");

    await assert.rejects(
      () => npmParser.resolve({
        lockfilePath,
        manifestPath,
        options: { maxDependenciesToScan: 10000 },
      }),
      /missing packages object/
    );
  });

  test("adds a warning when the unique dependency count exceeds the scan cap", async () => {
    const tree = await npmParser.resolve({
      lockfilePath: path.join(fixtureDir, "package-lock.json"),
      manifestPath: path.join(fixtureDir, "package.json"),
      options: { maxDependenciesToScan: 2 },
    });

    assert.strictEqual(tree.warnings.length, 1);
    assert.match(tree.warnings[0], /Display is capped at 2 dependencies/);
  });

  test("includes orphaned package-lock entries once even when duplicate package records share a key", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "package-lock.json");
    const manifestPath = path.join(workspace, "package.json");

    await writeTextFile(manifestPath, JSON.stringify({
      name: "fixture-app",
      version: "1.0.0",
      dependencies: {
        express: "1.0.0",
      },
    }, null, 2));

    await writeTextFile(lockfilePath, JSON.stringify({
      name: "fixture-app",
      version: "1.0.0",
      lockfileVersion: 3,
      packages: {
        "": {
          dependencies: {
            express: "1.0.0",
          },
        },
        "node_modules/express": {
          version: "1.0.0",
          dependencies: {
            accepts: "1.0.0",
            shared: "1.0.0",
          },
        },
        "node_modules/accepts": {
          version: "1.0.0",
        },
        "node_modules/shared": {
          version: "1.0.0",
        },
        "node_modules/express/node_modules/shared": {
          version: "1.0.0",
        },
        "node_modules/orphan": {
          version: "2.0.0",
        },
      },
    }, null, 2));

    const tree = await npmParser.resolve({
      lockfilePath,
      manifestPath,
      options: { maxDependenciesToScan: 10000 },
    });

    const packageKeys = tree.dependencies.map((dependency) => `${dependency.name}@${dependency.version}`);

    assert.strictEqual(packageKeys.filter((key) => key === "shared@1.0.0").length, 1);
    assert.strictEqual(packageKeys.filter((key) => key === "orphan@2.0.0").length, 1);
    assert.ok(packageKeys.includes("express@1.0.0"));
    assert.ok(packageKeys.includes("accepts@1.0.0"));
  });
});

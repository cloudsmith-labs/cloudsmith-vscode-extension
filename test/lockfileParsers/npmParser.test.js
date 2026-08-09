const assert = require("assert");
const path = require("path");
const { createDefaultDependencyAdapterRegistry } = require("../../util/dependencyAdapterRegistry");
const { DEPENDENCY_VERSION_STATES } = require("../../util/dependencyRecord");
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

  test("uses concrete package-lock versions for exact and ranged declarations", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "package.json");
    const lockfilePath = path.join(workspace, "package-lock.json");
    const declarations = {
      exact: "1.2.3",
      caret: "^1.2.3",
      tilde: "~2.1.0",
      comparison: ">=3.0.0 <4.0.0",
      wildcard: "4.x",
    };
    const resolutions = {
      exact: "1.2.3",
      caret: "1.9.0",
      tilde: "2.1.9",
      comparison: "3.8.0",
      wildcard: "4.7.0",
      "dev-tool": "5.2.0",
    };

    await writeTextFile(manifestPath, JSON.stringify({
      dependencies: declarations,
      devDependencies: { "dev-tool": "^5.0.0" },
    }, null, 2));
    await writeTextFile(lockfilePath, JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { dependencies: declarations, devDependencies: { "dev-tool": "^5.0.0" } },
        ...Object.fromEntries(Object.entries(resolutions).map(([name, version]) => [
          `node_modules/${name}`,
          { version, ...(name === "dev-tool" ? { dev: true } : {}) },
        ])),
      },
    }, null, 2));

    const result = await createDefaultDependencyAdapterRegistry().parse({
      adapterId: "npmParser",
      workspaceFolder: workspace,
      lockfilePath,
      manifestPath,
      sourceFile: "package-lock.json",
    });

    for (const [name, declaredConstraint] of Object.entries(declarations)) {
      const dependency = result.dependencies.find((candidate) => candidate.name === name);
      assert.ok(dependency, `expected ${name}`);
      assert.strictEqual(dependency.declaredConstraint, declaredConstraint);
      assert.strictEqual(dependency.resolvedVersion, resolutions[name]);
      assert.strictEqual(dependency.versionState, DEPENDENCY_VERSION_STATES.RESOLVED);
    }
    const devTool = result.dependencies.find((dependency) => dependency.name === "dev-tool");
    assert.strictEqual(devTool.resolvedVersion, "5.2.0");
    assert.strictEqual(devTool.isDevelopmentDependency, true);
  });

  test("joins package-lock dependencies by installed path and preserves multiple versions", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "package.json");
    const lockfilePath = path.join(workspace, "package-lock.json");
    await writeTextFile(manifestPath, JSON.stringify({
      dependencies: {
        "package-a": "^1.0.0",
        "package-b": "^1.0.0",
        "legacy-pad": "npm:left-pad@^2.0.0",
      },
    }, null, 2));
    await writeTextFile(lockfilePath, JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { dependencies: { "package-a": "^1.0.0", "package-b": "^1.0.0", "legacy-pad": "npm:left-pad@^2.0.0" } },
        "node_modules/package-a": { version: "1.0.0", dependencies: { "left-pad": "^1.0.0" } },
        "node_modules/package-a/node_modules/left-pad": { version: "1.1.0" },
        "node_modules/package-b": { version: "1.0.0", dependencies: { "left-pad": "^2.0.0" } },
        "node_modules/left-pad": { version: "2.2.0" },
        "node_modules/legacy-pad": { name: "left-pad", version: "2.2.0" },
      },
    }, null, 2));

    const tree = await npmParser.resolve({ lockfilePath, manifestPath, workspaceFolder: workspace, options: {} });
    const packageA = tree.dependencies.find((dependency) => dependency.name === "package-a");
    const packageB = tree.dependencies.find((dependency) => dependency.name === "package-b");
    const leftPadVersions = new Set(
      tree.dependencies
        .filter((dependency) => dependency.name === "left-pad")
        .map((dependency) => dependency.version)
    );

    assert.strictEqual(packageA.transitives[0].version, "1.1.0");
    assert.strictEqual(packageB.transitives[0].version, "2.2.0");
    assert.deepStrictEqual([...leftPadVersions].sort(), ["1.1.0", "2.2.0"]);
    assert.ok(tree.dependencies.some((dependency) => (
      dependency.name === "left-pad"
      && dependency.declaredName === "legacy-pad"
      && dependency.isDirect
    )));
  });

  test("preserves npm versions that differ only by prerelease identifier case", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "package.json");
    const lockfilePath = path.join(workspace, "package-lock.json");
    await writeTextFile(manifestPath, JSON.stringify({
      dependencies: {
        "package-a": "1.0.0",
        "package-b": "1.0.0",
      },
    }));
    await writeTextFile(lockfilePath, JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { dependencies: { "package-a": "1.0.0", "package-b": "1.0.0" } },
        "node_modules/package-a": {
          version: "1.0.0",
          dependencies: { "shared-package": "1.0.0-alpha" },
        },
        "node_modules/package-a/node_modules/shared-package": { version: "1.0.0-alpha" },
        "node_modules/package-b": {
          version: "1.0.0",
          dependencies: { "shared-package": "1.0.0-ALPHA" },
        },
        "node_modules/shared-package": { version: "1.0.0-ALPHA" },
      },
    }));

    const tree = await npmParser.resolve({
      lockfilePath,
      manifestPath,
      workspaceFolder: workspace,
      options: {},
    });
    const versions = tree.dependencies
      .filter((dependency) => dependency.name === "shared-package")
      .map((dependency) => dependency.version)
      .sort();

    assert.deepStrictEqual(versions, ["1.0.0-ALPHA", "1.0.0-alpha"]);
  });

  test("keeps local workspace links unresolved", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "package.json");
    const lockfilePath = path.join(workspace, "package-lock.json");
    await writeTextFile(manifestPath, JSON.stringify({
      workspaces: ["packages/*"],
      dependencies: { "local-package": "workspace:*" },
    }, null, 2));
    await writeTextFile(lockfilePath, JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { dependencies: { "local-package": "workspace:*" } },
        "node_modules/local-package": { resolved: "packages/local-package", link: true },
        "packages/local-package": { name: "local-package", version: "9.9.9" },
      },
    }, null, 2));

    const result = await createDefaultDependencyAdapterRegistry().parse({
      adapterId: "npmParser",
      workspaceFolder: workspace,
      lockfilePath,
      manifestPath,
    });
    const localPackage = result.dependencies.find((dependency) => dependency.name === "local-package");

    assert.ok(localPackage);
    assert.strictEqual(localPackage.declaredConstraint, "workspace:*");
    assert.strictEqual(localPackage.resolvedVersion, null);
    assert.strictEqual(localPackage.versionState, DEPENDENCY_VERSION_STATES.INCOMPLETE);
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

  test("selects yarn resolutions using the raw declared selector", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "yarn.lock");
    const manifestPath = path.join(workspace, "package.json");
    await writeTextFile(manifestPath, JSON.stringify({ dependencies: { "left-pad": "^2.0.0" } }));
    await writeTextFile(lockfilePath, [
      "left-pad@^1.0.0:",
      '  version "1.1.0"',
      "",
      "left-pad@^2.0.0:",
      '  version "2.2.0"',
      "",
    ].join("\n"));

    const tree = await npmParser.resolve({ lockfilePath, manifestPath, workspaceFolder: workspace, options: {} });
    const direct = tree.dependencies.find((dependency) => dependency.isDirect);

    assert.strictEqual(direct.name, "left-pad");
    assert.strictEqual(direct.version, "2.2.0");
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

  test("resolves pnpm aliases to the registry package identity", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "pnpm-lock.yaml");
    const manifestPath = path.join(workspace, "package.json");
    await writeTextFile(manifestPath, JSON.stringify({
      dependencies: { "legacy-pad": "npm:left-pad@^2.0.0" },
    }));
    await writeTextFile(lockfilePath, [
      "lockfileVersion: '9.0'",
      "importers:",
      "  .:",
      "    dependencies:",
      "      legacy-pad:",
      "        specifier: npm:left-pad@^2.0.0",
      "        version: left-pad@2.2.0",
      "packages:",
      "  left-pad@2.2.0:",
      "    resolution:",
      "      integrity: sha512-abc",
      "",
    ].join("\n"));

    const tree = await npmParser.resolve({ lockfilePath, manifestPath, workspaceFolder: workspace, options: {} });
    const direct = tree.dependencies.find((dependency) => dependency.isDirect);

    assert.strictEqual(direct.name, "left-pad");
    assert.strictEqual(direct.version, "2.2.0");
    assert.strictEqual(direct.declaredName, "legacy-pad");
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

  test("rejects a malformed package.json even when package-lock.json is valid", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "package-lock.json");
    const manifestPath = path.join(workspace, "package.json");
    await writeTextFile(lockfilePath, JSON.stringify({
      lockfileVersion: 3,
      packages: { "": {} },
    }));
    await writeTextFile(manifestPath, "{ not valid JSON\n");

    await assert.rejects(
      () => npmParser.resolve({
        lockfilePath,
        manifestPath,
        workspaceFolder: workspace,
        options: { maxDependenciesToScan: 10000 },
      }),
      /Malformed package\.json: invalid JSON/
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

  test("bounds package-lock dependency graph expansion by depth", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "package-lock.json");
    const manifestPath = path.join(workspace, "package.json");
    const packageCount = 140;
    const packages = {
      "": { dependencies: { "package-0": "1.0.0" } },
    };
    for (let index = 0; index < packageCount; index += 1) {
      packages[`node_modules/package-${index}`] = {
        version: "1.0.0",
        ...(index + 1 < packageCount
          ? { dependencies: { [`package-${index + 1}`]: "1.0.0" } }
          : {}),
      };
    }
    await writeTextFile(manifestPath, JSON.stringify({
      dependencies: { "package-0": "^1.0.0" },
    }));
    await writeTextFile(lockfilePath, JSON.stringify({ lockfileVersion: 3, packages }));

    const tree = await npmParser.resolve({
      lockfilePath,
      manifestPath,
      workspaceFolder: workspace,
      options: { maxDependenciesToScan: 10000 },
    });

    assert.ok(tree.warnings.some((warning) => /graph expansion reached its bounded limit/.test(warning)));
    assert.ok(Math.max(...tree.dependencies.map((dependency) => dependency.parentChain.length)) <= 128);
  });
});

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

  async function resolveGeneratedPackageLock(manifest, packages, options = {}) {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "package.json");
    const lockfilePath = path.join(workspace, "package-lock.json");
    let metrics = null;

    await writeTextFile(manifestPath, JSON.stringify(manifest));
    await writeTextFile(lockfilePath, JSON.stringify({ lockfileVersion: 3, packages }));
    const tree = await npmParser.resolve({
      lockfilePath,
      manifestPath,
      workspaceFolder: workspace,
      options: {
        ...options,
        onNpmGraphMetrics(snapshot) {
          metrics = snapshot;
        },
      },
    });

    return { tree, metrics };
  }

  function dependencyKeys(tree) {
    return tree.dependencies.map((dependency) => `${dependency.name}@${dependency.version}`);
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

  test("reads pnpm v9 snapshot edges and inherits development state", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "pnpm-lock.yaml");
    const manifestPath = path.join(workspace, "package.json");
    await writeTextFile(manifestPath, JSON.stringify({
      dependencies: { express: "^4.18.2" },
      devDependencies: { mocha: "^10.0.0" },
    }));
    await writeTextFile(lockfilePath, [
      "lockfileVersion: '9.0'",
      "importers:",
      "  .:",
      "    dependencies:",
      "      express:",
      "        specifier: ^4.18.2",
      "        version: 4.18.2",
      "    devDependencies:",
      "      mocha:",
      "        specifier: ^10.0.0",
      "        version: 10.0.0",
      "packages:",
      "  express@4.18.2:",
      "    resolution: {integrity: sha512-express}",
      "  accepts@1.3.8:",
      "    resolution: {integrity: sha512-accepts}",
      "  mocha@10.0.0:",
      "    resolution: {integrity: sha512-mocha}",
      "  he@1.2.0:",
      "    resolution: {integrity: sha512-he}",
      "snapshots:",
      "  express@4.18.2:",
      "    dependencies:",
      "      accepts: 1.3.8",
      "  accepts@1.3.8: {}",
      "  mocha@10.0.0:",
      "    dependencies:",
      "      he: 1.2.0",
      "  he@1.2.0: {}",
    ].join("\n"));

    const tree = await npmParser.resolve({
      lockfilePath,
      manifestPath,
      workspaceFolder: workspace,
      options: {},
    });
    const express = tree.dependencies.find((dependency) => dependency.name === "express");
    const accepts = tree.dependencies.find((dependency) => dependency.name === "accepts");
    const mocha = tree.dependencies.find((dependency) => dependency.name === "mocha");
    const he = tree.dependencies.find((dependency) => dependency.name === "he");

    assert.strictEqual(tree.dependencies.length, 4);
    assert.deepStrictEqual(express.transitives.map((dependency) => dependency.name), ["accepts"]);
    assert.deepStrictEqual(accepts.parentChain, ["express"]);
    assert.strictEqual(mocha.isDirect, true);
    assert.strictEqual(mocha.isDevelopmentDependency, true);
    assert.deepStrictEqual(mocha.transitives.map((dependency) => dependency.name), ["he"]);
    assert.strictEqual(he.isDevelopmentDependency, true);
    assert.deepStrictEqual(he.parentChain, ["mocha"]);
  });

  test("keeps complete Yarn and pnpm inventories when relationship bounds are reached", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "package.json");
    await writeTextFile(manifestPath, JSON.stringify({ dependencies: { root: "1.0.0" } }));

    const yarnPath = path.join(workspace, "yarn.lock");
    await writeTextFile(yarnPath, [
      "root@1.0.0:",
      '  version "1.0.0"',
      "  dependencies:",
      '    child "1.0.0"',
      "",
      "child@1.0.0:",
      '  version "1.0.0"',
      "  dependencies:",
      '    leaf "1.0.0"',
      "",
      "leaf@1.0.0:",
      '  version "1.0.0"',
    ].join("\n"));
    const yarnTree = await npmParser.resolve({
      lockfilePath: yarnPath,
      manifestPath,
      workspaceFolder: workspace,
      options: { npmGraphMaxDepth: 1 },
    });
    assert.deepStrictEqual(new Set(dependencyKeys(yarnTree)), new Set([
      "root@1.0.0", "child@1.0.0", "leaf@1.0.0",
    ]));
    assert.match(yarnTree.warnings[0], /relationships could not be fully analyzed/i);

    const pnpmPath = path.join(workspace, "pnpm-lock.yaml");
    await writeTextFile(pnpmPath, [
      "lockfileVersion: '9.0'",
      "importers:",
      "  .:",
      "    dependencies:",
      "      root:",
      "        specifier: 1.0.0",
      "        version: 1.0.0",
      "packages:",
      "  root@1.0.0: {}",
      "  child@1.0.0: {}",
      "  leaf@1.0.0: {}",
      "snapshots:",
      "  root@1.0.0:",
      "    dependencies:",
      "      child: 1.0.0",
      "  child@1.0.0:",
      "    dependencies:",
      "      leaf: 1.0.0",
      "  leaf@1.0.0: {}",
    ].join("\n"));
    const pnpmTree = await npmParser.resolve({
      lockfilePath: pnpmPath,
      manifestPath,
      workspaceFolder: workspace,
      options: { npmGraphMaxDepth: 1 },
    });
    assert.deepStrictEqual(new Set(dependencyKeys(pnpmTree)), new Set([
      "root@1.0.0", "child@1.0.0", "leaf@1.0.0",
    ]));
    assert.match(pnpmTree.warnings[0], /relationships could not be fully analyzed/i);
  });

  test("honors parser cancellation before traversing npm lock data", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "package.json");
    const lockfilePath = path.join(workspace, "pnpm-lock.yaml");
    await writeTextFile(manifestPath, JSON.stringify({ dependencies: { root: "1.0.0" } }));
    await writeTextFile(lockfilePath, [
      "lockfileVersion: '9.0'",
      "packages:",
      "  root@1.0.0: {}",
    ].join("\n"));

    await assert.rejects(
      () => npmParser.resolve({
        lockfilePath,
        manifestPath,
        workspaceFolder: workspace,
        options: { cancellationToken: { isCancellationRequested: true } },
      }),
      (error) => error && error.code === "ERR_DEPENDENCY_PARSING_CANCELLED"
    );
  });

  test("marks local, file, and git npm resolutions as non-registry sources", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "package.json");
    const lockfilePath = path.join(workspace, "package-lock.json");
    await writeTextFile(manifestPath, JSON.stringify({
      dependencies: {
        "file-package": "file:../file-package",
        "git-package": "git+https://example.invalid/repo.git#abc123",
      },
    }));
    await writeTextFile(lockfilePath, JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": {
          dependencies: {
            "file-package": "file:../file-package",
            "git-package": "git+https://example.invalid/repo.git#abc123",
          },
        },
        "node_modules/file-package": {
          version: "1.0.0",
          resolved: "file:../file-package",
        },
        "node_modules/git-package": {
          version: "2.0.0",
          resolved: "git+https://example.invalid/repo.git#abc123",
        },
      },
    }));

    const result = await createDefaultDependencyAdapterRegistry().parse({
      adapterId: "npmParser",
      workspaceFolder: workspace,
      lockfilePath,
      manifestPath,
    });
    const filePackage = result.dependencies.find((dependency) => dependency.name === "file-package");
    const gitPackage = result.dependencies.find((dependency) => dependency.name === "git-package");

    assert.strictEqual(filePackage.packageSource.kind, "path");
    assert.strictEqual(filePackage.resolvedVersion, null);
    assert.strictEqual(filePackage.lookupEligibility.state, "not-applicable");
    assert.strictEqual(gitPackage.packageSource.kind, "git");
    assert.strictEqual(gitPackage.resolvedVersion, null);
    assert.strictEqual(gitPackage.lookupEligibility.state, "not-applicable");
  });

  test("never treats arbitrary npm tarball URLs as registry lookup evidence", async () => {
    const cases = [
      {
        name: "package-lock",
        lockfile: "package-lock.json",
        content: JSON.stringify({
          lockfileVersion: 3,
          packages: {
            "": { dependencies: { foo: "https://private.example/foo.tgz" } },
            "node_modules/foo": {
              version: "1.0.0",
              resolved: "https://private.example/foo.tgz",
            },
          },
        }),
      },
      {
        name: "Yarn",
        lockfile: "yarn.lock",
        content: [
          'foo@https://private.example/foo.tgz:',
          '  version "1.0.0"',
          '  resolved "https://private.example/foo.tgz"',
        ].join("\n"),
      },
      {
        name: "pnpm",
        lockfile: "pnpm-lock.yaml",
        content: [
          "lockfileVersion: '9.0'",
          "importers:",
          "  .:",
          "    dependencies:",
          "      foo:",
          "        specifier: https://private.example/foo.tgz",
          "        version: https://private.example/foo.tgz",
          "packages:",
          "  foo@1.0.0:",
          "    resolution:",
          "      tarball: https://private.example/foo.tgz",
        ].join("\n"),
      },
    ];

    for (const fixture of cases) {
      const workspace = await createWorkspace();
      const manifestPath = path.join(workspace, "package.json");
      const lockfilePath = path.join(workspace, fixture.lockfile);
      await writeTextFile(manifestPath, JSON.stringify({
        dependencies: { foo: "https://private.example/foo.tgz" },
      }));
      await writeTextFile(lockfilePath, fixture.content);

      const result = await createDefaultDependencyAdapterRegistry().parse({
        adapterId: "npmParser",
        workspaceFolder: workspace,
        lockfilePath,
        manifestPath,
      });
      const foo = result.dependencies.find((dependency) => dependency.name === "foo");

      assert.ok(foo, `${fixture.name} should retain foo in its dependency inventory`);
      assert.notStrictEqual(foo.packageSource.kind, "registry", fixture.name);
      assert.strictEqual(foo.resolvedVersion, null, fixture.name);
      assert.strictEqual(foo.lookupEligibility.state, "not-applicable", fixture.name);
    }
  });

  test("keeps direct manifest URLs non-registry when lock metadata looks registry-resolved", async () => {
    const directUrl = "https://private.example/foo.tgz";
    const cases = [
      {
        name: "package-lock",
        lockfile: "package-lock.json",
        content: JSON.stringify({
          lockfileVersion: 3,
          packages: {
            "": { dependencies: { foo: "^1.0.0" } },
            "node_modules/foo": { version: "1.0.0", resolved: directUrl },
          },
        }),
      },
      {
        name: "Yarn",
        lockfile: "yarn.lock",
        content: [
          "foo@^1.0.0:",
          '  version "1.0.0"',
          `  resolved "${directUrl}"`,
        ].join("\n"),
      },
      {
        name: "pnpm",
        lockfile: "pnpm-lock.yaml",
        content: [
          "lockfileVersion: '9.0'",
          "importers:",
          "  .:",
          "    dependencies:",
          "      foo:",
          "        specifier: ^1.0.0",
          "        version: 1.0.0",
          "packages:",
          "  foo@1.0.0:",
          "    resolution:",
          `      tarball: ${directUrl}`,
        ].join("\n"),
      },
    ];

    for (const fixture of cases) {
      const workspace = await createWorkspace();
      const manifestPath = path.join(workspace, "package.json");
      const lockfilePath = path.join(workspace, fixture.lockfile);
      await writeTextFile(manifestPath, JSON.stringify({ dependencies: { foo: directUrl } }));
      await writeTextFile(lockfilePath, fixture.content);

      const result = await createDefaultDependencyAdapterRegistry().parse({
        adapterId: "npmParser",
        workspaceFolder: workspace,
        lockfilePath,
        manifestPath,
      });
      const foo = result.dependencies.find((dependency) => dependency.name === "foo");

      assert.ok(foo, `${fixture.name} should retain foo in its dependency inventory`);
      assert.notStrictEqual(foo.packageSource.kind, "registry", fixture.name);
      assert.strictEqual(foo.resolvedVersion, null, fixture.name);
      assert.strictEqual(foo.lookupEligibility.state, "not-applicable", fixture.name);
    }
  });

  test("retains private-registry tarball resolutions as registry evidence", async () => {
    const privateTarball = "https://npm.cloudsmith.io/acme/repository/foo/-/foo-1.0.0.tgz";
    const cases = [
      {
        name: "package-lock",
        lockfile: "package-lock.json",
        content: JSON.stringify({
          lockfileVersion: 3,
          packages: {
            "": { dependencies: { foo: "^1.0.0" } },
            "node_modules/foo": {
              version: "1.0.0",
              resolved: privateTarball,
            },
          },
        }),
      },
      {
        name: "Yarn",
        lockfile: "yarn.lock",
        content: [
          "foo@^1.0.0:",
          '  version "1.0.0"',
          `  resolved "${privateTarball}"`,
        ].join("\n"),
      },
      {
        name: "pnpm",
        lockfile: "pnpm-lock.yaml",
        content: [
          "lockfileVersion: '9.0'",
          "importers:",
          "  .:",
          "    dependencies:",
          "      foo:",
          "        specifier: ^1.0.0",
          "        version: 1.0.0",
          "packages:",
          "  foo@1.0.0:",
          "    resolution:",
          `      tarball: ${privateTarball}`,
        ].join("\n"),
      },
    ];

    for (const fixture of cases) {
      const workspace = await createWorkspace();
      const manifestPath = path.join(workspace, "package.json");
      const lockfilePath = path.join(workspace, fixture.lockfile);
      await writeTextFile(manifestPath, JSON.stringify({ dependencies: { foo: "^1.0.0" } }));
      await writeTextFile(lockfilePath, fixture.content);

      const result = await createDefaultDependencyAdapterRegistry().parse({
        adapterId: "npmParser",
        workspaceFolder: workspace,
        lockfilePath,
        manifestPath,
      });
      const foo = result.dependencies.find((dependency) => dependency.name === "foo");

      assert.ok(foo, `${fixture.name} should retain foo in its dependency inventory`);
      assert.strictEqual(foo.packageSource.kind, "registry", fixture.name);
      assert.strictEqual(foo.resolvedVersion, "1.0.0", fixture.name);
      assert.strictEqual(foo.lookupEligibility.state, "eligible", fixture.name);
    }
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

  test("adds a customer-safe warning when the configured display setting hides dependencies", async () => {
    const tree = await npmParser.resolve({
      lockfilePath: path.join(fixtureDir, "package-lock.json"),
      manifestPath: path.join(fixtureDir, "package.json"),
      options: { maxDependenciesToScan: 2 },
    });

    assert.strictEqual(tree.warnings.length, 1);
    assert.strictEqual(
      tree.warnings[0],
      "Some dependencies are hidden by the configured display setting. Package inventory remains complete."
    );
    assert.strictEqual(tree.warnings[0].includes("2"), false);
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

  test("expands a shared package-lock DAG once per structural occurrence", async () => {
    const rootCount = 16;
    const sharedCount = 12;
    const dependencies = {};
    const packages = { "": { dependencies } };

    for (let index = 0; index < rootCount; index += 1) {
      const name = `root-${String(index).padStart(2, "0")}`;
      dependencies[name] = "1.0.0";
      packages[`node_modules/${name}`] = {
        version: "1.0.0",
        dependencies: { "shared-00": "1.0.0" },
      };
    }
    for (let index = 0; index < sharedCount; index += 1) {
      const name = `shared-${String(index).padStart(2, "0")}`;
      const nextName = index + 1 < sharedCount
        ? `shared-${String(index + 1).padStart(2, "0")}`
        : null;
      packages[`node_modules/${name}`] = {
        version: "1.0.0",
        ...(nextName ? { dependencies: { [nextName]: "1.0.0" } } : {}),
      };
    }

    const { tree, metrics } = await resolveGeneratedPackageLock(
      { dependencies },
      packages
    );
    const structuralNodes = rootCount + sharedCount;
    const structuralEdges = rootCount + sharedCount - 1;
    const lastShared = tree.dependencies.find((dependency) => dependency.name === "shared-11");

    assert.strictEqual(tree.dependencies.length, structuralNodes);
    assert.strictEqual(tree.dependencies.filter((dependency) => dependency.isDirect).length, rootCount);
    assert.deepStrictEqual(
      tree.dependencies.find((dependency) => dependency.name === "shared-00").parentChain,
      ["root-00"]
    );
    assert.strictEqual(lastShared.parentChain.length, sharedCount);
    assert.strictEqual(lastShared.parentChain[0], "root-00");
    assert.deepStrictEqual(tree.warnings, []);
    assert.strictEqual(metrics.indexedOccurrences, structuralNodes);
    assert.ok(metrics.structuralOccurrencesExpanded <= structuralNodes);
    assert.strictEqual(metrics.structuralEdgesExamined, structuralEdges);
    assert.ok(metrics.repeatedOccurrenceEncounters >= rootCount - 1);
    assert.ok(metrics.dependencyRecordsMaterialized <= structuralNodes + structuralEdges);
  });

  test("keeps same-version package-lock occurrences structurally distinct by installed path", async () => {
    const { tree, metrics } = await resolveGeneratedPackageLock({
      dependencies: { a: "1.0.0", b: "1.0.0" },
    }, {
      "": { dependencies: { a: "1.0.0", b: "1.0.0" } },
      "node_modules/a": { version: "1.0.0", dependencies: { shared: "1.0.0" } },
      "node_modules/a/node_modules/shared": {
        version: "1.0.0",
        dependencies: { "nested-leaf": "1.0.0" },
      },
      "node_modules/a/node_modules/nested-leaf": { version: "1.0.0" },
      "node_modules/b": { version: "1.0.0", dependencies: { shared: "1.0.0" } },
      "node_modules/shared": {
        version: "1.0.0",
        dependencies: { "hoisted-leaf": "1.0.0" },
      },
      "node_modules/hoisted-leaf": { version: "1.0.0" },
    });
    const a = tree.dependencies.find((dependency) => dependency.name === "a");
    const b = tree.dependencies.find((dependency) => dependency.name === "b");
    const shared = tree.dependencies.find((dependency) => dependency.name === "shared");

    assert.deepStrictEqual(new Set(dependencyKeys(tree)), new Set([
      "a@1.0.0",
      "b@1.0.0",
      "shared@1.0.0",
      "nested-leaf@1.0.0",
      "hoisted-leaf@1.0.0",
    ]));
    assert.deepStrictEqual(shared.parentChain, ["a"]);
    assert.strictEqual(a.transitives[0].transitives[0].name, "nested-leaf");
    assert.strictEqual(b.transitives[0].transitives[0].name, "hoisted-leaf");
    assert.strictEqual(metrics.indexedOccurrences, 6);
    assert.strictEqual(metrics.structuralOccurrencesExpanded, 6);
    assert.strictEqual(metrics.structuralEdgesExamined, 4);
  });

  test("preserves inherited development state on repeated structural references", async () => {
    const { tree, metrics } = await resolveGeneratedPackageLock({
      dependencies: { prod: "1.0.0" },
      devDependencies: { dev: "1.0.0" },
    }, {
      "": {
        dependencies: { prod: "1.0.0" },
        devDependencies: { dev: "1.0.0" },
      },
      "node_modules/prod": { version: "1.0.0", dependencies: { shared: "1.0.0" } },
      "node_modules/dev": { version: "1.0.0", dev: true, dependencies: { shared: "1.0.0" } },
      "node_modules/shared": { version: "1.0.0", dependencies: { leaf: "1.0.0" } },
      "node_modules/leaf": { version: "1.0.0" },
    });
    const dev = tree.dependencies.find((dependency) => dependency.name === "dev");
    const shared = tree.dependencies.find((dependency) => dependency.name === "shared");
    const leaf = tree.dependencies.find((dependency) => dependency.name === "leaf");

    assert.strictEqual(dev.isDirect, true);
    assert.strictEqual(dev.isDevelopmentDependency, true);
    assert.strictEqual(dev.transitives[0].name, "shared");
    assert.strictEqual(dev.transitives[0].isDevelopmentDependency, true);
    assert.strictEqual(shared.isDevelopmentDependency, false);
    assert.strictEqual(leaf.isDevelopmentDependency, false);
    assert.deepStrictEqual(shared.parentChain, ["prod"]);
    assert.strictEqual(metrics.structuralOccurrencesExpanded, 4);
    assert.strictEqual(metrics.repeatedOccurrenceEncounters, 1);
  });

  test("classifies package-lock artifacts from occurrence evidence independent of name collisions and entry order", async () => {
    const manifest = {
      dependencies: { runtime: "1.0.0" },
      devDependencies: { types: "2.0.0" },
    };
    const rootEntry = {
      dependencies: { runtime: "1.0.0" },
      devDependencies: { types: "2.0.0" },
    };
    const entries = [
      ["node_modules/runtime", {
        version: "1.0.0",
        dependencies: { types: "1.0.0", shared: "1.0.0" },
      }],
      ["node_modules/runtime/node_modules/types", {
        version: "1.0.0",
        dependencies: { "prod-child": "1.0.0" },
      }],
      ["node_modules/prod-child", { version: "1.0.0" }],
      ["node_modules/types", {
        version: "2.0.0",
        dev: true,
        dependencies: { "dev-child": "1.0.0", shared: "1.0.0" },
      }],
      ["node_modules/dev-child", { version: "1.0.0", dev: true }],
      ["node_modules/shared", { version: "1.0.0" }],
    ];
    const classifications = [];

    for (const orderedEntries of [entries, entries.slice().reverse()]) {
      const { tree } = await resolveGeneratedPackageLock(manifest, {
        "": rootEntry,
        ...Object.fromEntries(orderedEntries),
      });
      const byKey = new Map(tree.dependencies.map((dependency) => [
        `${dependency.name}@${dependency.version}`,
        dependency,
      ]));
      classifications.push(Object.fromEntries([...byKey].map(([key, dependency]) => [
        key,
        dependency.isDevelopmentDependency,
      ])));

      assert.strictEqual(byKey.get("runtime@1.0.0").isDevelopmentDependency, false);
      assert.strictEqual(byKey.get("types@1.0.0").isDevelopmentDependency, false);
      assert.strictEqual(byKey.get("prod-child@1.0.0").isDevelopmentDependency, false);
      assert.strictEqual(byKey.get("types@2.0.0").isDevelopmentDependency, true);
      assert.strictEqual(byKey.get("dev-child@1.0.0").isDevelopmentDependency, true);
      assert.strictEqual(byKey.get("shared@1.0.0").isDevelopmentDependency, false);

      const runtime = byKey.get("runtime@1.0.0");
      const productionTypes = runtime.transitives.find((dependency) => dependency.name === "types");
      const developmentTypes = byKey.get("types@2.0.0");
      assert.strictEqual(productionTypes.isDevelopmentDependency, false);
      assert.strictEqual(productionTypes.transitives[0].isDevelopmentDependency, false);
      assert.strictEqual(developmentTypes.transitives.find(
        (dependency) => dependency.name === "shared"
      ).isDevelopmentDependency, true);
    }

    assert.deepStrictEqual(classifications[0], classifications[1]);
  });

  test("terminates package-lock cycles without dropping acyclic siblings", async () => {
    const cases = [
      {
        manifest: { dependencies: { self: "1.0.0" } },
        packages: {
          "": { dependencies: { self: "1.0.0" } },
          "node_modules/self": { version: "1.0.0", dependencies: { self: "1.0.0" } },
        },
        keys: ["self@1.0.0"],
        chains: { self: [] },
      },
      {
        manifest: { dependencies: { a: "1.0.0" } },
        packages: {
          "": { dependencies: { a: "1.0.0" } },
          "node_modules/a": { version: "1.0.0", dependencies: { b: "1.0.0" } },
          "node_modules/b": { version: "1.0.0", dependencies: { a: "1.0.0" } },
        },
        keys: ["a@1.0.0", "b@1.0.0"],
        chains: { a: [], b: ["a"] },
      },
      {
        manifest: { dependencies: { a: "1.0.0" } },
        packages: {
          "": { dependencies: { a: "1.0.0" } },
          "node_modules/a": { version: "1.0.0", dependencies: { b: "1.0.0" } },
          "node_modules/b": { version: "1.0.0", dependencies: { c: "1.0.0" } },
          "node_modules/c": {
            version: "1.0.0",
            dependencies: { a: "1.0.0", tail: "1.0.0" },
          },
          "node_modules/tail": { version: "1.0.0" },
        },
        keys: ["a@1.0.0", "b@1.0.0", "c@1.0.0", "tail@1.0.0"],
        chains: { a: [], b: ["a"], c: ["a", "b"], tail: ["a", "b", "c"] },
      },
    ];

    for (const fixture of cases) {
      const { tree, metrics } = await resolveGeneratedPackageLock(
        fixture.manifest,
        fixture.packages
      );
      assert.deepStrictEqual(new Set(dependencyKeys(tree)), new Set(fixture.keys));
      for (const [name, parentChain] of Object.entries(fixture.chains)) {
        assert.deepStrictEqual(
          tree.dependencies.find((dependency) => dependency.name === name).parentChain,
          parentChain
        );
      }
      assert.strictEqual(metrics.cycleEdgesSkipped, 1);
      assert.deepStrictEqual(tree.warnings, []);
    }
  });

  test("keeps direct representatives free of transitive parent chains", async () => {
    const { tree } = await resolveGeneratedPackageLock({
      dependencies: { direct: "1.0.0", root: "1.0.0" },
    }, {
      "": { dependencies: { direct: "1.0.0", root: "1.0.0" } },
      "node_modules/direct": { version: "1.0.0" },
      "node_modules/root": { version: "1.0.0", dependencies: { shared: "1.0.0" } },
      "node_modules/shared": { version: "1.0.0", dependencies: { direct: "1.0.0" } },
    });
    const direct = tree.dependencies.find((dependency) => dependency.name === "direct");

    assert.strictEqual(direct.isDirect, true);
    assert.strictEqual(direct.parent, null);
    assert.deepStrictEqual(direct.parentChain, []);
  });

  test("supports lower-only package-lock depth and node bounds with semantic warnings", async () => {
    const createChain = (count) => {
      const packages = { "": { dependencies: { "bound-00": "1.0.0" } } };
      for (let index = 0; index < count; index += 1) {
        const name = `bound-${String(index).padStart(2, "0")}`;
        const nextName = index + 1 < count
          ? `bound-${String(index + 1).padStart(2, "0")}`
          : null;
        packages[`node_modules/${name}`] = {
          version: "1.0.0",
          ...(nextName ? { dependencies: { [nextName]: "1.0.0" } } : {}),
        };
      }
      return packages;
    };
    const manifest = { dependencies: { "bound-00": "1.0.0" } };
    const depthResult = await resolveGeneratedPackageLock(manifest, createChain(12), {
      npmGraphMaxDepth: 4,
    });

    assert.strictEqual(depthResult.tree.dependencies.length, 12);
    assert.deepStrictEqual(depthResult.tree.warnings, [
      "Some dependency relationships could not be fully analyzed.",
    ]);
    assert.strictEqual(depthResult.metrics.maxDepth, 4);
    assert.strictEqual(depthResult.metrics.depthLimitReached, true);
    assert.strictEqual(depthResult.metrics.nodeLimitReached, false);
    assert.ok(Math.max(...depthResult.tree.dependencies.map(
      (dependency) => dependency.parentChain.length
    )) <= 4);

    const nodeResult = await resolveGeneratedPackageLock(manifest, createChain(8), {
      npmGraphMaxNodes: 6,
    });
    assert.strictEqual(nodeResult.tree.dependencies.length, 8);
    assert.deepStrictEqual(nodeResult.tree.warnings, [
      "Some dependency relationships could not be fully analyzed.",
    ]);
    assert.strictEqual(nodeResult.metrics.maxNodes, 6);
    assert.strictEqual(nodeResult.metrics.nodeLimitReached, true);

    const clampedResult = await resolveGeneratedPackageLock(manifest, createChain(1), {
      npmGraphMaxDepth: Number.MAX_SAFE_INTEGER,
      npmGraphMaxNodes: Number.MAX_SAFE_INTEGER,
    });
    assert.strictEqual(clampedResult.metrics.maxDepth, 128);
    assert.strictEqual(clampedResult.metrics.maxNodes, 50000);
    assert.strictEqual(clampedResult.metrics.maxEdges, 500000);
    assert.deepStrictEqual(clampedResult.tree.warnings, []);
  });

  test("retains late direct roots when relationship materialization reaches its bound", async () => {
    const { tree } = await resolveGeneratedPackageLock({
      dependencies: { first: "1.0.0", second: "1.0.0" },
    }, {
      "": { dependencies: { first: "1.0.0", second: "1.0.0" } },
      "node_modules/first": { version: "1.0.0", dependencies: { child: "1.0.0" } },
      "node_modules/child": { version: "1.0.0" },
      "node_modules/second": { version: "1.0.0" },
    }, {
      npmGraphMaxNodes: 1,
    });
    const second = tree.dependencies.find((dependency) => dependency.name === "second");
    const secondRoot = tree.dependencyGraph.roots.find((root) => root.declaredName === "second");

    assert.ok(second);
    assert.strictEqual(second.isDirect, true);
    assert.deepStrictEqual(second.parentChain, []);
    assert.strictEqual(secondRoot.entryKey, "node_modules/second");
    assert.ok(!tree.dependencyGraph.entries.some((entry) => entry.key === secondRoot.entryKey));
    assert.ok(tree.warnings.includes("Some dependency relationships could not be fully analyzed."));
  });

  test("bounds structural edge discovery before adapting the graph", async () => {
    const dependencies = {};
    const packages = {
      "": { dependencies: { root: "1.0.0" } },
      "node_modules/root": { version: "1.0.0", dependencies },
    };
    for (let index = 0; index < 5; index += 1) {
      const name = `edge-${index}`;
      dependencies[name] = "1.0.0";
      packages[`node_modules/${name}`] = { version: "1.0.0" };
    }

    const { tree, metrics } = await resolveGeneratedPackageLock(
      { dependencies: { root: "1.0.0" } },
      packages,
      { npmGraphMaxEdges: 2 }
    );

    assert.strictEqual(tree.dependencies.length, 6);
    assert.strictEqual(tree.dependencyGraph.entries.flatMap((entry) => entry.edges).length, 2);
    assert.strictEqual(metrics.structuralEdgesExamined, 2);
    assert.strictEqual(metrics.edgeLimitReached, true);
    assert.strictEqual(metrics.maxEdges, 2);
    assert.ok(tree.warnings.includes("Some dependency relationships could not be fully analyzed."));
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

    assert.ok(tree.warnings.includes("Some dependency relationships could not be fully analyzed."));
    assert.ok(Math.max(...tree.dependencies.map((dependency) => dependency.parentChain.length)) <= 128);
  });
});

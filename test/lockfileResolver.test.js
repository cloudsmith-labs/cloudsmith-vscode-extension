const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { LockfileResolver } = require("../util/lockfileResolver");
const { deduplicateDeps } = require("../util/lockfileParsers/shared");
const { buildPackageIndex, findCoverageMatch } = require("../views/dependencyHealthProvider");
const {
  copyFixtureDir,
  makeTempWorkspace,
  removeDirectory,
  writeTextFile,
} = require("./helpers/fixtureWorkspace");

suite("LockfileResolver Test Suite", () => {
  const tempDirs = [];

  async function createWorkspace() {
    const workspace = await makeTempWorkspace();
    tempDirs.push(workspace);
    return workspace;
  }

  suiteTeardown(async () => {
    await Promise.all(tempDirs.map((tempDir) => removeDirectory(tempDir)));
  });

  test("detectResolvers finds multiple ecosystems in one workspace", async () => {
    const workspace = await createWorkspace();
    await copyFixtureDir("npm", workspace);
    await copyFixtureDir("docker", workspace);
    await copyFixtureDir("ruby", workspace);

    const resolvers = await LockfileResolver.detectResolvers(workspace);
    const resolverKeys = new Set(resolvers.map((resolver) => `${resolver.resolverName}:${resolver.sourceFile}`));

    assert.ok(resolverKeys.has("npmParser:package-lock.json"));
    assert.ok(resolverKeys.has("dockerParser:Dockerfile"));
    assert.ok(resolverKeys.has("dockerParser:docker-compose.yml"));
    assert.ok(resolverKeys.has("rubyParser:Gemfile.lock"));
  });

  test("resolveAll returns separate dependency trees grouped by source file", async () => {
    const workspace = await createWorkspace();
    await copyFixtureDir("npm", workspace);
    await copyFixtureDir("docker", workspace);

    const trees = await LockfileResolver.resolveAll(workspace, { maxDependenciesToScan: 10000 });
    const bySource = new Map(trees.map((tree) => [tree.sourceFile, tree]));

    assert.strictEqual(trees.length, 3);
    assert.ok(bySource.has("package-lock.json"));
    assert.ok(bySource.has("Dockerfile"));
    assert.ok(bySource.has("docker-compose.yml"));
    assert.strictEqual(bySource.get("package-lock.json").ecosystem, "npm");
    assert.strictEqual(bySource.get("Dockerfile").ecosystem, "docker");
    assert.strictEqual(bySource.get("docker-compose.yml").ecosystem, "docker");
  });

  test("deduplicateDeps keeps a single package and prefers direct dependencies", () => {
    const dependencies = [
      {
        ecosystem: "npm",
        name: "accepts",
        version: "1.3.8",
        isDirect: false,
        parent: "express",
        parentChain: ["express"],
      },
      {
        ecosystem: "npm",
        name: "accepts",
        version: "1.3.8",
        isDirect: true,
        parent: null,
        parentChain: [],
      },
      {
        ecosystem: "npm",
        name: "express",
        version: "4.18.2",
        isDirect: true,
        parent: null,
        parentChain: [],
      },
    ];

    const deduplicated = deduplicateDeps(dependencies);

    assert.strictEqual(deduplicated.length, 2);
    const accepts = deduplicated.find((dependency) => dependency.name === "accepts");
    assert.ok(accepts);
    assert.strictEqual(accepts.isDirect, true);
    assert.deepStrictEqual(accepts.parentChain, []);
  });

  test("coverage matching normalizes Python package names", () => {
    const cloudsmithPackage = {
      name: "scikit-learn",
      version: "1.4.0",
      format: "python",
    };
    const index = buildPackageIndex([cloudsmithPackage], "python");

    const match = findCoverageMatch(index, {
      name: "scikit_learn",
      version: "1.4.0",
      format: "python",
    });

    assert.strictEqual(match, cloudsmithPackage);
  });

  test("coverage matching normalizes Python case, hyphen, underscore, and dot variants", () => {
    const cloudsmithPackage = {
      name: "Requests-HTML",
      version: "0.10.0",
      format: "python",
    };
    const index = buildPackageIndex([cloudsmithPackage], "python");
    const variants = [
      "requests_html",
      "requests.html",
      "REQUESTS-HTML",
    ];

    for (const variant of variants) {
      const match = findCoverageMatch(index, {
        name: variant,
        version: "0.10.0",
        format: "python",
      });
      assert.strictEqual(match, cloudsmithPackage);
    }
  });

  test("coverage matching indexes Maven packages by groupId and artifactId", () => {
    const cloudsmithPackage = {
      name: "spring-boot-starter",
      version: "3.2.0",
      format: "maven",
      identifiers: {
        group_id: "org.springframework.boot",
      },
    };
    const index = buildPackageIndex([cloudsmithPackage], "maven");

    const match = findCoverageMatch(index, {
      name: "org.springframework.boot:spring-boot-starter",
      version: "3.2.0",
      format: "maven",
    });

    assert.strictEqual(match, cloudsmithPackage);
  });

  test("secondary parser fixtures can be resolved through the registry", async () => {
    const fixtureNames = [
      "gradle",
      "go",
      "nuget",
      "dart",
      "composer",
      "helm",
      "swift",
      "hex",
    ];

    for (const fixtureName of fixtureNames) {
      const workspace = await createWorkspace();
      await copyFixtureDir(fixtureName, workspace);

      const trees = await LockfileResolver.resolveAll(workspace, { maxDependenciesToScan: 10000 });

      assert.strictEqual(trees.length, 1, `${fixtureName} should resolve to exactly one tree`);
      assert.ok(trees[0].dependencies.length > 0, `${fixtureName} should resolve at least one dependency`);
    }
  });

  test("detectResolvers ignores symlinked lockfiles that point outside the workspace", async () => {
    const workspace = await createWorkspace();
    const outsideDir = await createWorkspace();
    const outsideLockfile = path.join(outsideDir, "package-lock.json");
    const workspaceLockfile = path.join(workspace, "package-lock.json");

    await writeTextFile(
      outsideLockfile,
      JSON.stringify({
        packages: {
          "": {
            dependencies: {},
          },
        },
      })
    );
    await fs.promises.symlink(outsideLockfile, workspaceLockfile);

    const resolvers = await LockfileResolver.detectResolvers(workspace);

    assert.strictEqual(
      resolvers.some((resolver) => resolver.resolverName === "npmParser"),
      false
    );
  });
});

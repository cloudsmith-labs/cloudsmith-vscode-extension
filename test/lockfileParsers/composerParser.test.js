const assert = require("assert");
const path = require("path");
const composerParser = require("../../util/lockfileParsers/composerParser");
const {
  makeTempWorkspace,
  removeDirectory,
  writeTextFile,
} = require("../helpers/fixtureWorkspace");

suite("composerParser Test Suite", () => {
  const tempDirs = [];
  async function createWorkspace() {
    const workspace = await makeTempWorkspace("cloudsmith-composer-parser-");
    tempDirs.push(workspace);
    return workspace;
  }
  suiteTeardown(async () => Promise.all(tempDirs.map((tempDir) => removeDirectory(tempDir))));

  test("preserves require-dev closure and non-registry package source", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "composer.json");
    const lockfilePath = path.join(workspace, "composer.lock");
    await writeTextFile(manifestPath, JSON.stringify({
      require: { "acme/runtime": "^1" },
      "require-dev": { "acme/tester": "^2" },
    }));
    await writeTextFile(lockfilePath, JSON.stringify({
      packages: [{
        name: "acme/runtime", version: "1.2.0", require: { "acme/shared": "^3" },
      }, { name: "acme/shared", version: "3.0.0" }],
      "packages-dev": [{
        name: "acme/tester", version: "2.1.0", require: { "acme/dev-child": "^4" },
      }, {
        name: "acme/dev-child", version: "4.0.0", dist: { type: "path", url: "../dev-child" },
      }],
    }));

    const tree = await composerParser.resolve({ lockfilePath, manifestPath, workspaceFolder: workspace });

    assert.deepStrictEqual(
      tree.dependencies.filter((dependency) => dependency.isDevelopmentDependency)
        .map((dependency) => dependency.name).sort(),
      ["acme/dev-child", "acme/tester"]
    );
    assert.strictEqual(tree.dependencies.find((dependency) => dependency.name === "acme/dev-child").packageSource.kind, "path");
    assert.strictEqual(tree.dependencies.find((dependency) => dependency.name === "acme/shared").isDirect, false);
  });

  test("fails with safe copy for malformed composer manifest", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "composer.json");
    await writeTextFile(manifestPath, '{"repositories":"token=super-secret"');

    await assert.rejects(
      composerParser.resolve({ manifestPath, workspaceFolder: workspace }),
      (error) => error.message === "The Composer manifest is not valid JSON."
        && !error.message.includes("super-secret")
    );
  });
});

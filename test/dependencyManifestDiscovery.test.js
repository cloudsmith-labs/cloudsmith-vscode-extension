const assert = require("assert");
const fs = require("fs");
const path = require("path");
const {
  MAX_DISCOVERED_MANIFESTS,
  discoverDependencyManifests,
} = require("../util/dependencyManifestDiscovery");
const {
  makeTempWorkspace,
  removeDirectory,
  writeTextFile,
} = require("./helpers/fixtureWorkspace");

suite("dependencyManifestDiscovery", () => {
  const tempDirs = [];

  teardown(async () => {
    await Promise.all(tempDirs.splice(0).map((tempDir) => removeDirectory(tempDir)));
  });

  test("discovers nested supported manifests and excludes dependency and build directories", async () => {
    const workspace = await makeTempWorkspace("cloudsmith-manifest-discovery-");
    tempDirs.push(workspace);
    const expected = [
      path.join(workspace, "package.json"),
      path.join(workspace, "packages", "api", "pyproject.toml"),
      path.join(workspace, "services", "container", "Dockerfile"),
      path.join(workspace, "services", "worker", "pom.xml"),
    ];
    for (const filePath of expected) {
      await writeTextFile(filePath, "\n");
    }
    await writeTextFile(path.join(workspace, "node_modules", "hidden", "package.json"), "{}\n");
    await writeTextFile(path.join(workspace, "services", "worker", "target", "package.json"), "{}\n");
    await writeTextFile(path.join(workspace, ".git", "package.json"), "{}\n");

    const result = await discoverDependencyManifests(workspace);
    const realWorkspace = await fs.promises.realpath(workspace);
    const expectedRealPaths = expected.map((filePath) => (
      path.join(realWorkspace, path.relative(workspace, filePath))
    ));

    assert.deepStrictEqual(result.manifests.map((manifest) => manifest.filePath), expectedRealPaths.sort());
    assert.deepStrictEqual(result.warnings, []);
  });

  test("caps unusually large manifest sets and reports incomplete discovery", async () => {
    const workspace = await makeTempWorkspace("cloudsmith-manifest-cap-");
    tempDirs.push(workspace);
    await Promise.all(Array.from({ length: MAX_DISCOVERED_MANIFESTS + 5 }, (_, index) => (
      writeTextFile(path.join(workspace, "packages", String(index).padStart(3, "0"), "package.json"), "{}\n")
    )));

    const result = await discoverDependencyManifests(workspace);

    assert.strictEqual(result.manifests.length, MAX_DISCOVERED_MANIFESTS);
    assert.strictEqual(result.warnings.length, 1);
    assert.match(result.warnings[0], /bounded scan limit/);
  });
});

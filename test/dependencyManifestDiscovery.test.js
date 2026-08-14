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
      path.join(workspace, "packages", "worker", "Pipfile"),
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

  test("honors cancellation before traversing workspace directories", async () => {
    const workspace = await makeTempWorkspace("cloudsmith-manifest-cancel-");
    tempDirs.push(workspace);
    await writeTextFile(path.join(workspace, "package.json"), "{}\n");

    await assert.rejects(
      () => discoverDependencyManifests(workspace, {
        cancellationToken: { isCancellationRequested: true },
      }),
      (error) => error && error.code === "ERR_DEPENDENCY_DISCOVERY_CANCELLED"
    );
  });

  test("does not swallow cancellation requested during directory enumeration", async () => {
    const workspace = await makeTempWorkspace("cloudsmith-manifest-mid-cancel-");
    tempDirs.push(workspace);
    await writeTextFile(path.join(workspace, "package.json"), "{}\n");
    const token = { isCancellationRequested: false };
    const originalOpendir = fs.promises.opendir;
    fs.promises.opendir = async (...args) => {
      const directory = await originalOpendir(...args);
      return {
        async *[Symbol.asyncIterator]() {
          for await (const entry of directory) {
            token.isCancellationRequested = true;
            yield entry;
          }
        },
      };
    };

    try {
      await assert.rejects(
        () => discoverDependencyManifests(workspace, { cancellationToken: token }),
        (error) => error.code === "ERR_DEPENDENCY_DISCOVERY_CANCELLED"
      );
    } finally {
      fs.promises.opendir = originalOpendir;
    }
  });

  test("does not enumerate a queued directory replaced with an outside symlink", async () => {
    const workspace = await makeTempWorkspace("cloudsmith-discovery-race-");
    const outsideWorkspace = await makeTempWorkspace("cloudsmith-discovery-race-target-");
    tempDirs.push(workspace, outsideWorkspace);
    const controlledDirectory = path.join(workspace, "controlled");
    const movedDirectory = path.join(workspace, "controlled-original");
    await writeTextFile(path.join(controlledDirectory, "inside.txt"), "inside\n");
    await writeTextFile(path.join(outsideWorkspace, "package.json"), "{}\n");
    const safeControlledPath = await fs.promises.realpath(controlledDirectory);

    const originalOpendir = fs.promises.opendir;
    let moved = false;
    let symlinkCreated = false;
    fs.promises.opendir = async (openedPath, ...args) => {
      if (!moved && openedPath === safeControlledPath) {
        await fs.promises.rename(controlledDirectory, movedDirectory);
        moved = true;
        await fs.promises.symlink(outsideWorkspace, controlledDirectory, "dir");
        symlinkCreated = true;
      }
      return originalOpendir(openedPath, ...args);
    };

    try {
      const result = await discoverDependencyManifests(workspace);
      assert.deepStrictEqual(result.manifests, []);
      assert.deepStrictEqual(result.warnings, [
        "Dependency manifest discovery could not safely scan every directory; some nested projects may not have been scanned.",
      ]);
    } finally {
      fs.promises.opendir = originalOpendir;
      if (symlinkCreated) await fs.promises.unlink(controlledDirectory);
      if (moved) await fs.promises.rename(movedDirectory, controlledDirectory);
    }
  });
});

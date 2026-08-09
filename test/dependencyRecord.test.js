const assert = require("assert");
const path = require("path");
const {
  DEPENDENCY_VERSION_STATES,
  RESOLUTION_SOURCE_KINDS,
  createDependencyRecord,
  createDependencySource,
  getDependencyOccurrenceKey,
} = require("../util/dependencyRecord");

suite("dependencyRecord", () => {
  function createManifestSource(fileName = "package.json", range) {
    return createDependencySource({
      kind: RESOLUTION_SOURCE_KINDS.MANIFEST,
      filePath: path.resolve("test", "fixtures", "npm", fileName),
      type: fileName,
      range,
    });
  }

  test("creates immutable dependency sources with URI, path, type, kind, and range", () => {
    const range = {
      start: { line: 3, character: 4 },
      end: { line: 3, character: 11 },
    };
    const source = createManifestSource("package.json", range);

    assert.strictEqual(Object.getPrototypeOf(source), Object.prototype);
    assert.strictEqual(Object.isFrozen(source), true);
    assert.strictEqual(source.kind, RESOLUTION_SOURCE_KINDS.MANIFEST);
    assert.strictEqual(source.filePath, path.resolve("test", "fixtures", "npm", "package.json"));
    assert.strictEqual(source.type, "package.json");
    assert.match(source.uri, /^file:/);
    assert.deepStrictEqual(source.range, range);
    assert.notStrictEqual(source.range, range);
    assert.strictEqual(Object.isFrozen(source.range), true);
    assert.strictEqual(Object.isFrozen(source.range.start), true);
    assert.strictEqual(Object.isFrozen(source.range.end), true);
  });

  test("preserves declared constraints separately from resolved versions", () => {
    const manifestSource = createManifestSource();
    const lockfileSource = createDependencySource({
      kind: RESOLUTION_SOURCE_KINDS.LOCKFILE,
      filePath: path.resolve("test", "fixtures", "npm", "package-lock.json"),
      type: "package-lock.json",
    });
    const parentChain = ["fixture-app"];
    const transitives = [{ name: "child-package" }];
    const dependency = createDependencyRecord({
      ecosystem: "npm",
      format: "npm",
      name: "package-a",
      declaredConstraint: "^1.2.3",
      resolvedVersion: "1.7.4",
      versionState: DEPENDENCY_VERSION_STATES.RESOLVED,
      resolutionSource: lockfileSource,
      sourceManifest: manifestSource,
      isDirect: true,
      isDevelopmentDependency: false,
      parent: "fixture-app",
      parentChain,
      transitives,
      legacyVersion: "1.7.4",
    });

    parentChain.push("mutated-parent");
    transitives.push({ name: "mutated-child" });

    assert.strictEqual(Object.isFrozen(dependency), true);
    assert.strictEqual(dependency.ecosystem, "npm");
    assert.strictEqual(dependency.format, "npm");
    assert.strictEqual(dependency.name, "package-a");
    assert.strictEqual(dependency.normalizedName, "package-a");
    assert.strictEqual(dependency.declaredConstraint, "^1.2.3");
    assert.strictEqual(dependency.resolvedVersion, "1.7.4");
    assert.strictEqual(dependency.versionState, DEPENDENCY_VERSION_STATES.RESOLVED);
    assert.strictEqual(dependency.resolutionSource.kind, RESOLUTION_SOURCE_KINDS.LOCKFILE);
    assert.strictEqual(dependency.sourceManifest.kind, RESOLUTION_SOURCE_KINDS.MANIFEST);
    assert.strictEqual(dependency.isDirect, true);
    assert.strictEqual(dependency.isDevelopmentDependency, false);
    assert.strictEqual(dependency.parent, "fixture-app");
    assert.deepStrictEqual(dependency.parentChain, ["fixture-app"]);
    assert.deepStrictEqual(dependency.transitives, [{ name: "child-package" }]);
    assert.strictEqual(dependency.legacyVersion, "1.7.4");
    assert.strictEqual(Object.isFrozen(dependency.parentChain), true);
    assert.strictEqual(Object.isFrozen(dependency.transitives), true);
  });

  test("represents an unresolved range without inventing a resolved version", () => {
    const dependency = createDependencyRecord({
      ecosystem: "python",
      format: "python",
      name: "requests",
      declaredConstraint: ">=1.0,<2",
      resolvedVersion: null,
      versionState: DEPENDENCY_VERSION_STATES.RANGE,
      resolutionSource: createManifestSource("requirements.txt"),
      sourceManifest: createManifestSource("requirements.txt"),
      isDirect: true,
      legacyVersion: "1.0",
    });

    assert.strictEqual(dependency.declaredConstraint, ">=1.0,<2");
    assert.strictEqual(dependency.resolvedVersion, null);
    assert.strictEqual(dependency.versionState, DEPENDENCY_VERSION_STATES.RANGE);
  });

  test("rejects contradictory resolved-version states", () => {
    assert.throws(() => createDependencyRecord({
      ecosystem: "npm",
      name: "package-a",
      resolvedVersion: "1.2.3",
      versionState: DEPENDENCY_VERSION_STATES.RANGE,
    }), /must use the resolved version state/);
    assert.throws(() => createDependencyRecord({
      ecosystem: "npm",
      name: "package-a",
      resolvedVersion: null,
      versionState: DEPENDENCY_VERSION_STATES.RESOLVED,
    }), /require a resolved version/);
  });

  test("keeps multiple resolved versions and provenance-distinct occurrences separate", () => {
    const firstManifest = createManifestSource("package.json");
    const secondManifest = createDependencySource({
      kind: RESOLUTION_SOURCE_KINDS.MANIFEST,
      filePath: path.resolve("test", "fixtures", "npm", "nested", "package.json"),
      type: "package.json",
    });
    const resolutionSource = createDependencySource({
      kind: RESOLUTION_SOURCE_KINDS.LOCKFILE,
      filePath: path.resolve("test", "fixtures", "npm", "package-lock.json"),
      type: "package-lock.json",
    });
    const createPackageA = (resolvedVersion, sourceManifest) => createDependencyRecord({
      ecosystem: "npm",
      format: "npm",
      name: "package-a",
      declaredConstraint: `^${resolvedVersion}`,
      resolvedVersion,
      versionState: DEPENDENCY_VERSION_STATES.RESOLVED,
      resolutionSource,
      sourceManifest,
      isDirect: true,
      legacyVersion: resolvedVersion,
    });

    const versionOne = createPackageA("1.0.0", firstManifest);
    const versionTwo = createPackageA("2.0.0", firstManifest);
    const secondManifestVersionOne = createPackageA("1.0.0", secondManifest);
    const occurrences = new Set([
      getDependencyOccurrenceKey(versionOne),
      getDependencyOccurrenceKey(versionTwo),
      getDependencyOccurrenceKey(secondManifestVersionOne),
    ]);

    assert.strictEqual(occurrences.size, 3);
    assert.deepStrictEqual(
      [versionOne, versionTwo].map((dependency) => dependency.resolvedVersion),
      ["1.0.0", "2.0.0"]
    );
    assert.notStrictEqual(versionOne.sourceManifest.uri, secondManifestVersionOne.sourceManifest.uri);
  });

  test("includes declaration ranges, resolution sources, and parent paths in occurrence identity", () => {
    const firstManifest = createManifestSource("package.json", {
      start: { line: 1, character: 2 },
      end: { line: 1, character: 10 },
    });
    const secondManifest = createManifestSource("package.json", {
      start: { line: 2, character: 2 },
      end: { line: 2, character: 10 },
    });
    const firstLockfile = createDependencySource({
      kind: RESOLUTION_SOURCE_KINDS.LOCKFILE,
      filePath: path.resolve("test", "fixtures", "npm", "package-lock.json"),
      type: "package-lock.json",
    });
    const secondLockfile = createDependencySource({
      kind: RESOLUTION_SOURCE_KINDS.LOCKFILE,
      filePath: path.resolve("test", "fixtures", "npm", "nested", "package-lock.json"),
      type: "package-lock.json",
    });
    const createOccurrence = (sourceManifest, resolutionSource, parentChain) => createDependencyRecord({
      ecosystem: "npm",
      name: "package-a",
      declaredConstraint: "^1.0.0",
      resolvedVersion: "1.2.0",
      versionState: DEPENDENCY_VERSION_STATES.RESOLVED,
      sourceManifest,
      resolutionSource,
      isDirect: false,
      parent: parentChain[parentChain.length - 1],
      parentChain,
      legacyVersion: "1.2.0",
    });
    const keys = new Set([
      getDependencyOccurrenceKey(createOccurrence(firstManifest, firstLockfile, ["parent-a"])),
      getDependencyOccurrenceKey(createOccurrence(secondManifest, firstLockfile, ["parent-a"])),
      getDependencyOccurrenceKey(createOccurrence(firstManifest, secondLockfile, ["parent-a"])),
      getDependencyOccurrenceKey(createOccurrence(firstManifest, firstLockfile, ["parent-b"])),
    ]);

    assert.strictEqual(keys.size, 4);
  });
});

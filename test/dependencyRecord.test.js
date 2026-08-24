const assert = require("assert");
const path = require("path");
const {
  DEPENDENCY_VERSION_STATES,
  RESOLUTION_SOURCE_KINDS,
  createDependencyRecord,
  createDependencySource,
  getDependencyArtifactKey,
  getDependencyOccurrenceKey,
  getDependencyPackageSourceDisplayLocation,
  getDependencyPackageSourceDisplayRef,
  isDependencyLookupEligible,
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
    const transitive = createDependencyRecord({
      ecosystem: "npm",
      name: "child-package",
      resolvedVersion: "1.0.0",
      versionState: DEPENDENCY_VERSION_STATES.RESOLVED,
      parent: "package-a",
      parentChain: ["package-a"],
      legacyVersion: "1.0.0",
    });
    const transitives = [transitive];
    const dependency = createDependencyRecord({
      ecosystem: "npm",
      format: "npm",
      name: "package-a",
      declarationName: "package-alias",
      declaredConstraint: "^1.2.3",
      resolvedVersion: "1.7.4",
      versionState: DEPENDENCY_VERSION_STATES.RESOLVED,
      resolutionSource: lockfileSource,
      sourceManifest: manifestSource,
      environmentMarker: "node_version >= '20'",
      isDirect: true,
      isDevelopmentDependency: false,
      parent: "fixture-app",
      parentChain,
      transitives,
      legacyVersion: "1.7.4",
    });

    parentChain.push("mutated-parent");
    transitives.push(createDependencyRecord({
      ecosystem: "npm",
      name: "mutated-child",
    }));

    assert.strictEqual(Object.isFrozen(dependency), true);
    assert.strictEqual(dependency.ecosystem, "npm");
    assert.strictEqual(dependency.format, "npm");
    assert.strictEqual(dependency.name, "package-a");
    assert.strictEqual(dependency.normalizedName, "package-a");
    assert.strictEqual(dependency.declarationName, "package-alias");
    assert.strictEqual(dependency.declaredConstraint, "^1.2.3");
    assert.strictEqual(dependency.resolvedVersion, "1.7.4");
    assert.strictEqual(dependency.versionState, DEPENDENCY_VERSION_STATES.RESOLVED);
    assert.strictEqual(dependency.resolutionSource.kind, RESOLUTION_SOURCE_KINDS.LOCKFILE);
    assert.strictEqual(dependency.sourceManifest.kind, RESOLUTION_SOURCE_KINDS.MANIFEST);
    assert.strictEqual(dependency.environmentMarker, "node_version >= '20'");
    assert.strictEqual(dependency.isDirect, true);
    assert.strictEqual(dependency.isDevelopmentDependency, false);
    assert.strictEqual(dependency.parent, "fixture-app");
    assert.deepStrictEqual(dependency.parentChain, ["fixture-app"]);
    assert.deepStrictEqual(dependency.transitives, [transitive]);
    assert.strictEqual(dependency.legacyVersion, "1.7.4");
    assert.strictEqual(Object.isFrozen(dependency.parentChain), true);
    assert.strictEqual(Object.isFrozen(dependency.transitives), true);
    assert.strictEqual(Object.isFrozen(dependency.transitives[0]), true);
  });

  test("canonicalizes nested transitive inputs without mutating caller-owned objects", () => {
    const grandchildInput = {
      ecosystem: "npm",
      name: "grandchild-package",
      resolvedVersion: "3.0.0",
      versionState: DEPENDENCY_VERSION_STATES.RESOLVED,
      parent: "child-package",
      parentChain: ["root-package", "child-package"],
      transitives: [],
      legacyVersion: "3.0.0",
    };
    const childParentChain = ["root-package"];
    const childTransitives = [grandchildInput];
    const childInput = {
      ecosystem: "npm",
      name: "child-package",
      resolvedVersion: "2.0.0",
      versionState: DEPENDENCY_VERSION_STATES.RESOLVED,
      parent: "root-package",
      parentChain: childParentChain,
      transitives: childTransitives,
      legacyVersion: "2.0.0",
    };
    const dependency = createDependencyRecord({
      ecosystem: "npm",
      name: "root-package",
      resolvedVersion: "1.0.0",
      versionState: DEPENDENCY_VERSION_STATES.RESOLVED,
      transitives: [childInput],
      legacyVersion: "1.0.0",
    });
    const child = dependency.transitives[0];
    const grandchild = child.transitives[0];

    assert.notStrictEqual(child, childInput);
    assert.notStrictEqual(grandchild, grandchildInput);
    assert.strictEqual(Object.isFrozen(dependency.transitives), true);
    assert.strictEqual(Object.isFrozen(child), true);
    assert.strictEqual(Object.isFrozen(child.parentChain), true);
    assert.strictEqual(Object.isFrozen(child.transitives), true);
    assert.strictEqual(Object.isFrozen(grandchild), true);
    assert.strictEqual(Object.isFrozen(grandchild.parentChain), true);
    assert.strictEqual(Object.isFrozen(grandchild.transitives), true);

    childInput.name = "mutated-child";
    childParentChain.push("mutated-parent");
    grandchildInput.name = "mutated-grandchild";
    childTransitives.push({ name: "mutated-entry" });
    child.name = "mutated-canonical-child";

    assert.strictEqual(child.name, "child-package");
    assert.deepStrictEqual(child.parentChain, ["root-package"]);
    assert.strictEqual(child.transitives.length, 1);
    assert.strictEqual(grandchild.name, "grandchild-package");
    assert.strictEqual(Object.isFrozen(childInput), false);
    assert.strictEqual(Object.isFrozen(childParentChain), false);
    assert.strictEqual(Object.isFrozen(childTransitives), false);
    assert.strictEqual(Object.isFrozen(grandchildInput), false);
    assert.throws(() => dependency.transitives.push(child), TypeError);
    assert.throws(() => child.parentChain.push("another-parent"), TypeError);
  });

  test("rejects cyclic transitive input without recursive overflow", () => {
    const cyclicInput = {
      ecosystem: "npm",
      name: "cyclic-package",
      versionState: DEPENDENCY_VERSION_STATES.UNRESOLVED,
      transitives: [],
    };
    cyclicInput.transitives.push(cyclicInput);

    assert.throws(
      () => createDependencyRecord(cyclicInput),
      /Dependency transitive graphs must not contain cycles\./
    );
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

  test("preserves case-sensitive Maven and Go occurrence identities", () => {
    const upperGo = createDependencyRecord({
      ecosystem: "go",
      name: "example.com/Owner/Module",
      declaredConstraint: "v1.0.0",
      versionState: DEPENDENCY_VERSION_STATES.EXACT_DECLARATION,
      legacyVersion: "v1.0.0",
    });
    const lowerGo = createDependencyRecord({
      ecosystem: "go",
      name: "example.com/owner/module",
      declaredConstraint: "v1.0.0",
      versionState: DEPENDENCY_VERSION_STATES.EXACT_DECLARATION,
      legacyVersion: "v1.0.0",
    });
    const upperMaven = createDependencyRecord({
      ecosystem: "maven",
      name: "Com.Example:Library",
      declaredConstraint: "1.0.0",
      versionState: DEPENDENCY_VERSION_STATES.EXACT_DECLARATION,
      legacyVersion: "1.0.0",
    });

    assert.strictEqual(upperGo.normalizedName, "example.com/Owner/Module");
    assert.strictEqual(upperMaven.normalizedName, "Com.Example:Library");
    assert.notStrictEqual(
      getDependencyOccurrenceKey(upperGo),
      getDependencyOccurrenceKey(lowerGo)
    );
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

  test("keeps bounded qualifiers and package-source eligibility immutable and fail closed", () => {
    const registry = createDependencyRecord({
      ecosystem: "nuget",
      name: "Example.Package",
      versionState: DEPENDENCY_VERSION_STATES.EXACT_DECLARATION,
      legacyVersion: "1.2.3",
      qualifiers: { targetFramework: "net8.0" },
      packageSource: { kind: "registry", location: "https://api.nuget.org/v3/index.json" },
    });
    const local = createDependencyRecord({
      ecosystem: "nuget",
      name: "Example.Package",
      versionState: DEPENDENCY_VERSION_STATES.EXACT_DECLARATION,
      legacyVersion: "1.2.3",
      qualifiers: { targetFramework: "net8.0" },
      packageSource: { kind: "path", location: "../Example.Package" },
    });

    assert.strictEqual(isDependencyLookupEligible(registry), true);
    assert.deepStrictEqual(local.lookupEligibility, {
      state: "not-applicable",
      reason: "path-source",
    });
    const omittedSource = createDependencyRecord({
      ecosystem: "nuget",
      name: "Unproven.Package",
      versionState: DEPENDENCY_VERSION_STATES.EXACT_DECLARATION,
      legacyVersion: "1.2.3",
    });
    assert.deepStrictEqual(omittedSource.lookupEligibility, {
      state: "not-applicable",
      reason: "unknown-source",
    });
    assert.strictEqual(Object.isFrozen(registry.qualifiers), true);
    assert.strictEqual(Object.isFrozen(registry.packageSource), true);
    assert.strictEqual(Object.isFrozen(registry.lookupEligibility), true);
    assert.throws(() => createDependencyRecord({
      ecosystem: "nuget",
      name: "unsafe",
      qualifiers: { targetFramework: "net8.0", unexpected: "value" },
    }), /unsupported property/);
    assert.throws(() => createDependencyRecord({
      ecosystem: "nuget",
      name: "unsafe",
      packageSource: { kind: "registry", eligible: true },
    }), /unsupported property/);
  });

  test("separates occurrence identity from ecosystem-aware artifact identity", () => {
    const createNuget = (targetFramework) => createDependencyRecord({
      ecosystem: "nuget",
      name: "Example.Package",
      resolvedVersion: "4.5.6",
      versionState: DEPENDENCY_VERSION_STATES.RESOLVED,
      legacyVersion: "4.5.6",
      qualifiers: { targetFramework },
      packageSource: { kind: "registry" },
    });
    const netEight = createNuget("net8.0");
    const netStandard = createNuget("netstandard2.0");
    assert.notStrictEqual(
      getDependencyOccurrenceKey(netEight),
      getDependencyOccurrenceKey(netStandard)
    );
    assert.strictEqual(
      getDependencyArtifactKey(netEight),
      getDependencyArtifactKey(netStandard)
    );

    const createRuby = (platform) => createDependencyRecord({
      ecosystem: "ruby",
      name: "nokogiri",
      resolvedVersion: "1.18.0",
      versionState: DEPENDENCY_VERSION_STATES.RESOLVED,
      legacyVersion: "1.18.0",
      qualifiers: { platform },
      packageSource: { kind: "registry" },
    });
    assert.notStrictEqual(
      getDependencyArtifactKey(createRuby("ruby")),
      getDependencyArtifactKey(createRuby("x86_64-linux"))
    );

    const createMaven = qualifiers => createDependencyRecord({
      ecosystem: "maven",
      name: "com.example:demo",
      resolvedVersion: "1.2.3",
      versionState: DEPENDENCY_VERSION_STATES.RESOLVED,
      legacyVersion: "1.2.3",
      qualifiers,
      packageSource: { kind: "registry" },
    });
    assert.strictEqual(
      getDependencyArtifactKey(createMaven({})),
      getDependencyArtifactKey(createMaven({ type: "jar" }))
    );
    assert.strictEqual(
      getDependencyArtifactKey(createMaven({ type: "test-jar" })),
      getDependencyArtifactKey(createMaven({ type: "jar", classifier: "tests" }))
    );

    const createDocker = platform => createDependencyRecord({
      ecosystem: "docker",
      name: "alpine",
      resolvedVersion: "3.20.3",
      versionState: DEPENDENCY_VERSION_STATES.RESOLVED,
      legacyVersion: "3.20.3",
      qualifiers: { tag: "3.20.3", platform },
      packageSource: { kind: "registry" },
    });
    assert.strictEqual(
      getDependencyArtifactKey(createDocker("linux/x86_64")),
      getDependencyArtifactKey(createDocker("linux/amd64"))
    );
    assert.strictEqual(
      getDependencyArtifactKey(createDocker("linux/aarch64/v8")),
      getDependencyArtifactKey(createDocker("linux/arm64"))
    );
    const dockerDigestBase = {
      ecosystem: "docker",
      name: "alpine",
      resolvedVersion: `sha256:${"a".repeat(64)}`,
      versionState: DEPENDENCY_VERSION_STATES.RESOLVED,
      legacyVersion: `sha256:${"a".repeat(64)}`,
      packageSource: { kind: "registry" },
    };
    assert.strictEqual(
      getDependencyArtifactKey(createDependencyRecord({
        ...dockerDigestBase,
        qualifiers: { digest: `SHA256:${"A".repeat(64)}` },
      })),
      getDependencyArtifactKey(createDependencyRecord({
        ...dockerDigestBase,
        qualifiers: { digest: `sha256:${"a".repeat(64)}` },
      }))
    );

    const createNugetVersion = version => createDependencyRecord({
      ecosystem: "nuget",
      name: "Example.Package",
      resolvedVersion: version,
      versionState: DEPENDENCY_VERSION_STATES.RESOLVED,
      legacyVersion: version,
      packageSource: { kind: "registry" },
    });
    assert.strictEqual(
      getDependencyArtifactKey(createNugetVersion("01.02.003.0-BETA+build.7")),
      getDependencyArtifactKey(createNugetVersion("1.2.3-beta"))
    );
  });

  test("derives workspace-relative source labels", () => {
    const workspaceFolder = path.resolve("test", "fixtures");
    const source = createDependencySource({
      kind: RESOLUTION_SOURCE_KINDS.MANIFEST,
      filePath: path.join(workspaceFolder, "npm", "package.json"),
      workspaceFolder,
    });
    assert.strictEqual(source.label, "npm/package.json");
  });

  test("bounds canonical values, parent chains, and transitive graph depth", () => {
    const base = { ecosystem: "npm", name: "bounded-package" };
    for (const [field, value] of [
      ["declaredConstraint", "x".repeat(8193)],
      ["resolvedVersion", "x".repeat(8193)],
      ["environmentMarker", "x".repeat(8193)],
      ["legacyVersion", "x".repeat(8193)],
      ["parent", "x".repeat(4097)],
    ]) {
      assert.throws(
        () => createDependencyRecord({ ...base, [field]: value }),
        /invalid or exceeds the supported bound/
      );
    }
    assert.throws(
      () => createDependencyRecord({
        ...base,
        parentChain: Array.from({ length: 129 }, (_, index) => `parent-${index}`),
      }),
      /parent chain exceeds the supported length/
    );
    assert.throws(
      () => createDependencyRecord({ ...base, parentChain: ["valid", "bad\nparent"] }),
      /parent chain entry is invalid/
    );

    let nested = { ecosystem: "npm", name: "leaf" };
    for (let index = 0; index < 129; index += 1) {
      nested = { ecosystem: "npm", name: `node-${index}`, transitives: [nested] };
    }
    assert.throws(
      () => createDependencyRecord(nested),
      /transitive graphs exceed the supported depth/
    );
  });

  test("sanitizes source-location display without erasing canonical provenance", () => {
    const remote = createDependencyRecord({
      ecosystem: "cargo",
      name: "remote-package",
      packageSource: {
        kind: "git",
        location: "https://user:secret@example.com/team/repo.git?token=hidden#main",
      },
    });
    const local = createDependencyRecord({
      ecosystem: "maven",
      name: "com.example:local-package",
      packageSource: {
        kind: "path",
        location: "/Users/private-user/workspace/libs/local-package.jar",
      },
    });

    assert.strictEqual(
      remote.packageSource.location,
      "https://user:secret@example.com/team/repo.git?token=hidden#main"
    );
    assert.strictEqual(
      getDependencyPackageSourceDisplayLocation(remote.packageSource),
      "https://example.com/team/repo.git"
    );
    assert.strictEqual(
      getDependencyPackageSourceDisplayLocation(local.packageSource),
      "local-package.jar"
    );
    assert.strictEqual(
      getDependencyPackageSourceDisplayLocation({
        kind: "path",
        location: "file:///Users/private-user/workspace/%E0%A4%A-secret.tgz",
      }),
      "%E0%A4%A-secret.tgz"
    );
    assert.strictEqual(
      getDependencyPackageSourceDisplayLocation({
        kind: "path",
        location: "\\\\server\\share\\Users\\private-user\\secret.jar",
      }),
      "secret.jar"
    );
    assert.strictEqual(
      getDependencyPackageSourceDisplayLocation({
        kind: "path",
        location: "\\\\?\\C:\\Users\\private-user\\extended-secret.jar",
      }),
      "extended-secret.jar"
    );
    for (const [kind, unsafeLocation] of [
      ["path", "file://[bad/Users/private-user/private/secret.jar"],
      ["path", "path:///Users/private-user/private/secret.jar"],
      ["local", "local:///Users/private-user/private/secret.jar"],
      ["path", "file:%2F%2F%2FUsers%2Fprivate-user%2Fprivate%2Fsecret.jar"],
      ["path", "file:%2FC:%5CUsers%5Cprivate-user%5Cprivate%5Csecret.jar"],
      ["path", "file%3A%2F%2F%2FUsers%2Fprivate-user%2Fprivate%2Fsecret.jar"],
      ["path", "path%3A%2F%2F%2FUsers%2Fprivate-user%2Fprivate%2Fsecret.jar"],
    ]) {
      assert.strictEqual(
        getDependencyPackageSourceDisplayLocation({ kind, location: unsafeLocation }),
        "secret.jar"
      );
    }
    assert.strictEqual(
      getDependencyPackageSourceDisplayLocation({
        kind: "path",
        location: "file%253A%252F%252F%252FUsers%252Fprivate-user%252Fprivate%252Fsecret.jar",
      }),
      "local source"
    );
    assert.strictEqual(
      getDependencyPackageSourceDisplayLocation({
        kind: "git",
        location: encodeURIComponent(encodeURIComponent(
          "https://user:secret@example.com/repo.git?token=hidden#main"
        )),
      }),
      "source"
    );
    assert.strictEqual(
      getDependencyPackageSourceDisplayLocation({
        kind: "git",
        location: "https%3A%2F%2Fexample.com%2Frepo.git%3Ftoken%3Dhidden%ZZ",
      }),
      "source"
    );
    assert.strictEqual(
      getDependencyPackageSourceDisplayLocation({
        kind: "git",
        location: "https://example.com/team/my%20repo.git?token=hidden",
      }),
      "https://example.com/team/my%20repo.git"
    );
    for (const unsafeLocation of [
      "ssh://user:secret@host:path",
      "https://user:secret@example.com:bad/path",
      "git+ssh://user:secret@example.com:bad/repo.git",
      "https://user:secret@[::1",
      "user:secret@host:path",
      "file://user:secret@localhost/Users/private-user/private.tgz",
      "ssh:/user:secret@host/path/repo.git",
      "ssh:///user:secret@host/path",
      "git+ssh:/user:secret@host/path/repo.git",
      "ssh:/user@domain:secret@host/path/repo.git",
      "user@domain:secret@host:path",
      "ssh:%2Fuser%3Asecret%40host/path/repo.git",
      "https://user%3Asecret%40example.com/path",
      "%68%74%74%70%73%3A%2F%2Fuser%3Asecret%40example.com%2Fpath%3Ftoken%3Dhidden",
    ]) {
      const display = getDependencyPackageSourceDisplayLocation({
        kind: "git",
        location: unsafeLocation,
      });
      assert.doesNotMatch(display, /user|secret|private-user/);
    }
    assert.strictEqual(
      getDependencyPackageSourceDisplayRef("https://user:secret@example.com/ref?token=hidden"),
      "https://example.com/ref"
    );
    assert.strictEqual(
      getDependencyPackageSourceDisplayRef("/Users/private-user/private/revision.txt"),
      "revision.txt"
    );
    const encodeRepeatedly = (value, count) => {
      let encoded = value;
      for (let index = 0; index < count; index += 1) {
        encoded = encodeURIComponent(encoded);
      }
      return encoded;
    };
    const overBudgetLocator =
      "https://user:placeholder@example.invalid/repo.tgz?token=placeholder#frag";
    for (const layers of [5, 6]) {
      const display = getDependencyPackageSourceDisplayLocation({
        kind: "git",
        location: encodeRepeatedly(overBudgetLocator, layers),
      });
      assert.strictEqual(display, "source");
      assert.doesNotMatch(display, /user|placeholder|token|frag/);
    }
  });

  test("rejects control-bearing canonical identities and oversized source positions", () => {
    for (const values of [
      { ecosystem: "np\nm", name: "package" },
      { ecosystem: "npm", name: "pack\tage" },
      { ecosystem: "npm", format: "np\rm", name: "package" },
    ]) {
      assert.throws(
        () => createDependencyRecord(values),
        /require an ecosystem, format, and package name/
      );
    }
    assert.throws(
      () => createManifestSource("package.json", {
        start: { line: 0, character: 0 },
        end: { line: Number.MAX_SAFE_INTEGER, character: 0 },
      }),
      /non-negative integers/
    );
  });

  test("rejects root, source, range, and indexed array accessors without invoking them", () => {
    let accessorCalls = 0;
    const root = { ecosystem: "npm" };
    Object.defineProperty(root, "name", {
      enumerable: true,
      get() {
        accessorCalls += 1;
        return "package";
      },
    });
    assert.throws(() => createDependencyRecord(root), /only data properties/);

    const sourceValues = {
      kind: RESOLUTION_SOURCE_KINDS.MANIFEST,
      filePath: path.resolve("package.json"),
    };
    Object.defineProperty(sourceValues, "type", {
      enumerable: true,
      get() {
        accessorCalls += 1;
        return "package.json";
      },
    });
    assert.throws(() => createDependencySource(sourceValues), /only data properties/);

    const range = { end: { line: 0, character: 1 } };
    Object.defineProperty(range, "start", {
      enumerable: true,
      get() {
        accessorCalls += 1;
        return { line: 0, character: 0 };
      },
    });
    assert.throws(
      () => createManifestSource("package.json", range),
      /only data properties/
    );

    const parentChain = ["parent"];
    Object.defineProperty(parentChain, "0", {
      enumerable: true,
      configurable: true,
      get() {
        accessorCalls += 1;
        return "parent";
      },
    });
    assert.throws(
      () => createDependencyRecord({
        ecosystem: "npm",
        name: "package",
        parentChain,
      }),
      /only indexed data properties/
    );

    const configurations = ["runtime"];
    Object.defineProperty(configurations, "0", {
      enumerable: true,
      configurable: true,
      get() {
        accessorCalls += 1;
        return "runtime";
      },
    });
    assert.throws(
      () => createDependencyRecord({
        ecosystem: "gradle",
        name: "group:artifact",
        qualifiers: { configurations },
      }),
      /only indexed data properties/
    );

    const transitives = [{ ecosystem: "npm", name: "child" }];
    Object.defineProperty(transitives, "0", {
      enumerable: true,
      configurable: true,
      get() {
        accessorCalls += 1;
        return { ecosystem: "npm", name: "child" };
      },
    });
    assert.throws(
      () => createDependencyRecord({
        ecosystem: "npm",
        name: "package",
        transitives,
      }),
      /only indexed data properties/
    );
    assert.strictEqual(accessorCalls, 0);
  });
});

// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const {
  PackageDomainError,
  assertRepositoryPackageCoordinate,
  assertWorkspacePackageCoordinate,
  createExactPackage,
  createPackageCoordinate,
  createPackageResolutionInput,
  exactPackageIdentity,
  exactPackageRef,
  isExactPackage,
  isPackageCoordinate,
  packageCoordinateFromExact,
} = require("../domain/package");
const {
  PackageAdapterError,
  fromApiPackageRecord,
  fromDependencyHealthNode,
  fromExactPackageSelectionIfPresent,
  fromPackageDetailNode,
  fromPackageGroupNode,
  fromPackageNode,
  fromPackageResolutionSelection,
  fromPackageSelection,
  fromRecentPackageRecord,
  fromRepositoryNode,
  fromRepositoryPackageSelection,
  fromSearchResultNode,
} = require("../domain/packageAdapters");
const {
  serializePackageCollectionInspection,
  serializePackageInspection,
} = require("../util/packageInspection");
const { InstallCommandBuilder } = require("../util/installCommandBuilder");

suite("Canonical package domain", () => {
  function apiRecord(overrides = {}) {
    return {
      namespace: "Workspace",
      repository: "Repository",
      slug_perm: "Package-ID",
      slug: "package",
      name: "@scope/Package",
      version: "1.2.3",
      format: "npm",
      status_str: "Completed",
      downloads: 7,
      tags: {
        info: ["upstream"],
        version: "latest",
      },
      policy_violated: false,
      deny_policy_violated: false,
      license_policy_violated: false,
      vulnerability_policy_violated: false,
      num_vulnerabilities: 0,
      security_scan_status: "Scan Detected No Vulnerabilities",
      spdx_license: "MIT",
      license: "MIT License",
      raw_license: "MIT",
      license_url: "https://spdx.org/licenses/MIT.html",
      ...overrides,
    };
  }

  test("creates a deeply immutable exact package without retaining caller-owned data", () => {
    const input = apiRecord();
    const pkg = fromApiPackageRecord(input);

    input.tags.info[0] = "changed";
    assert.strictEqual(pkg.kind, "package");
    assert.strictEqual(pkg.identityState, "exact");
    assert.deepStrictEqual(pkg.tags, { info: ["upstream"], version: ["latest"] });
    assert.deepStrictEqual(pkg.policy, {
      violated: false,
      denyViolated: false,
      licenseViolated: false,
      vulnerabilityViolated: false,
    });
    assert.deepStrictEqual(pkg.vulnerability, {
      evidence: "clean",
      detected: false,
      count: 0,
      maxSeverity: null,
      scanStatus: "Scan Detected No Vulnerabilities",
    });
    assert.ok(Object.isFrozen(pkg));
    assert.ok(Object.isFrozen(pkg.tags));
    assert.ok(Object.isFrozen(pkg.tags.info));
    assert.ok(Object.isFrozen(pkg.policy));
    assert.ok(Object.isFrozen(pkg.vulnerability));
    assert.ok(Object.isFrozen(pkg.license));
    assert.ok(isExactPackage(pkg));
  });

  test("normalizes reflection failures into trusted adapter errors", () => {
    let hostileThrownValue;
    hostileThrownValue = new Proxy({}, {
      getPrototypeOf() {
        throw hostileThrownValue;
      },
      ownKeys() {
        throw hostileThrownValue;
      },
    });
    for (const hostile of [
      new Proxy({}, {
        getPrototypeOf() {
          throw new Error("untrusted getPrototypeOf trap");
        },
      }),
      new Proxy({}, {
        ownKeys() {
          throw new Error("untrusted ownKeys trap");
        },
      }),
      new Proxy({}, {
        getPrototypeOf() {
          throw hostileThrownValue;
        },
      }),
    ]) {
      assert.throws(() => fromApiPackageRecord(hostile), error => (
        error instanceof PackageAdapterError
        && !Object.prototype.hasOwnProperty.call(error, "cause")
      ));
      assert.throws(() => fromDependencyHealthNode({
        cloudsmithPackage: hostile,
      }), error => (
        error instanceof PackageAdapterError
        && !Object.prototype.hasOwnProperty.call(error, "cause")
      ));
    }

    const unstableTarget = apiRecord();
    const targetPropertyCount = Reflect.ownKeys(unstableTarget).length;
    let descriptorReads = 0;
    const falsyThrow = new Proxy(unstableTarget, {
      getOwnPropertyDescriptor(target, field) {
        descriptorReads += 1;
        if (descriptorReads > targetPropertyCount) throw undefined;
        return Reflect.getOwnPropertyDescriptor(target, field);
      },
    });
    assert.throws(() => fromApiPackageRecord(falsyThrow), error => (
      error instanceof PackageAdapterError
      && error.unexpected === true
      && !Object.prototype.hasOwnProperty.call(error, "cause")
    ));

    const forgedDomainError = Object.create(PackageDomainError.prototype);
    Object.defineProperties(forgedDomainError, {
      code: { value: "forged" },
      field: { value: "forged" },
      message: { value: "secret-bearing forged domain failure" },
    });
    const forgedTarget = apiRecord();
    const forgedTargetPropertyCount = Reflect.ownKeys(forgedTarget).length;
    let forgedDescriptorReads = 0;
    const forgedThrow = new Proxy(forgedTarget, {
      getOwnPropertyDescriptor(target, field) {
        forgedDescriptorReads += 1;
        if (forgedDescriptorReads > forgedTargetPropertyCount) throw forgedDomainError;
        return Reflect.getOwnPropertyDescriptor(target, field);
      },
    });
    assert.throws(() => fromApiPackageRecord(forgedThrow), error => (
      error instanceof PackageAdapterError
      && error.unexpected === true
      && error.code === "invalid_api_package"
      && !error.message.includes("secret-bearing")
    ));

    const unexpectedSelectionTarget = apiRecord();
    let ownKeysCalls = 0;
    let innerDescriptorReadsRemaining = null;
    const unexpectedSelection = new Proxy(unexpectedSelectionTarget, {
      ownKeys(target) {
        ownKeysCalls += 1;
        const keys = Reflect.ownKeys(target);
        if (ownKeysCalls === 4) innerDescriptorReadsRemaining = keys.length;
        return keys;
      },
      getOwnPropertyDescriptor(target, field) {
        if (innerDescriptorReadsRemaining === 0) throw undefined;
        if (innerDescriptorReadsRemaining !== null) innerDescriptorReadsRemaining -= 1;
        return Reflect.getOwnPropertyDescriptor(target, field);
      },
    });
    assert.throws(() => fromPackageSelection(unexpectedSelection), error => (
      error instanceof PackageAdapterError
      && error.code === "malformed_applicable_adapter"
      && error.unexpected === true
    ));

    const exact = fromApiPackageRecord(apiRecord());
    const hostileOptions = new Proxy({}, {
      getOwnPropertyDescriptor() {
        throw undefined;
      },
    });
    assert.throws(() => fromApiPackageRecord(exact, hostileOptions), error => (
      error instanceof PackageAdapterError
      && error.code === "invalid_api_package"
      && error.unexpected === true
      && !Object.prototype.hasOwnProperty.call(error, "cause")
    ));
  });

  test("uses one exact, case-sensitive, delimiter-safe identity and immutable ref", () => {
    const upper = fromApiPackageRecord(apiRecord());
    const lower = fromApiPackageRecord(apiRecord({
      namespace: "workspace",
      repository: "repository",
      slug_perm: "package-id",
    }));

    assert.strictEqual(
      exactPackageIdentity(upper),
      JSON.stringify(["Workspace", "Repository", "Package-ID"])
    );
    assert.notStrictEqual(exactPackageIdentity(upper), exactPackageIdentity(lower));
    assert.deepStrictEqual(exactPackageRef(upper), {
      workspace: "Workspace",
      repository: "Repository",
      packageIdentifier: "Package-ID",
    });
    assert.ok(Object.isFrozen(exactPackageRef(upper)));
  });

  test("keeps pre-identity coordinates distinct from exact packages", () => {
    const coordinate = createPackageCoordinate({
      workspace: "workspace",
      repository: null,
      name: "artifact",
      version: "1.0.0",
      format: "npm",
    });

    assert.ok(isPackageCoordinate(coordinate));
    assert.strictEqual(coordinate.packageIdentifier, null);
    assert.throws(() => exactPackageIdentity(coordinate), PackageDomainError);
    assert.strictEqual(assertWorkspacePackageCoordinate(coordinate), coordinate);
    assert.throws(() => assertRepositoryPackageCoordinate(coordinate), PackageDomainError);

    const repositoryCoordinate = packageCoordinateFromExact(fromApiPackageRecord(apiRecord()));
    assert.strictEqual(assertRepositoryPackageCoordinate(repositoryCoordinate), repositoryCoordinate);
    assert.strictEqual(repositoryCoordinate.repository, "Repository");
    assert.deepStrictEqual(repositoryCoordinate.qualifiers, {});
    assert.ok(Object.isFrozen(repositoryCoordinate.qualifiers));
  });

  test("Maven API identity survives exact-package to native-coordinate round trip", () => {
    const exact = fromApiPackageRecord(apiRecord({
      name: "guava",
      format: "maven",
      version: "33.4.0-jre",
      identifiers: { group_id: "com.google.guava" },
    }));
    const coordinate = packageCoordinateFromExact(exact);

    assert.strictEqual(coordinate.name, "com.google.guava:guava");
    assert.strictEqual(coordinate.version, "33.4.0-jre");
    assert.strictEqual(coordinate.format, "maven");
  });

  test("API-native qualifiers survive exact-package and install-guidance round trips", () => {
    const cases = [
      {
        record: apiRecord({
          name: "demo",
          format: "maven",
          version: "1.2.3",
          extension: ".jar",
          filename: "demo-1.2.3-tests.jar",
          identifiers: { group_id: "com.example", classifier: "tests" },
        }),
        assertCoordinate(coordinate) {
          assert.strictEqual(coordinate.name, "com.example:demo");
          assert.deepStrictEqual(coordinate.qualifiers, {
            classifier: "tests",
            type: "jar",
          });
          const result = InstallCommandBuilder.build(
            coordinate.format,
            coordinate.name,
            coordinate.version,
            coordinate.workspace,
            coordinate.repository,
            { qualifiers: coordinate.qualifiers }
          );
          assert.match(result.command, /<type>jar<\/type>/);
          assert.match(result.command, /<classifier>tests<\/classifier>/);
        },
      },
      {
        record: apiRecord({
          name: "numpy",
          format: "conda",
          version: "1.24.0",
          filename: "numpy-1.24.0-py311h123_0.conda",
          cdn_url: "https://dl.cloudsmith.io/public/Workspace/Repository/conda/linux-64/numpy-1.24.0-py311h123_0.conda",
          identifiers: { build_string: "py311h123_0", subdir: "linux-64" },
        }),
        assertCoordinate(coordinate) {
          assert.deepStrictEqual(coordinate.qualifiers, {
            build: "py311h123_0",
            subdir: "linux-64",
          });
          const result = InstallCommandBuilder.build(
            coordinate.format,
            coordinate.name,
            coordinate.version,
            coordinate.workspace,
            coordinate.repository,
            { qualifiers: coordinate.qualifiers }
          );
          assert.doesNotMatch(result.command, /--platform/u);
          assert.match(result.command, /numpy==1\.24\.0=py311h123_0\[subdir=linux-64\]/);
        },
      },
      {
        record: apiRecord({
          name: "cloudsmith-redhat-example",
          format: "rpm",
          version: "1.0.17592050512201-1",
          release: "1",
          epoch: null,
          architectures: [{ name: "noarch", description: null }],
          filename: "cloudsmith-redhat-example-1.0.17592050512201-1.noarch.rpm",
          identifiers: { architecture: "noarch" },
        }),
        assertCoordinate(coordinate) {
          assert.strictEqual(coordinate.version, "1.0.17592050512201-1");
          assert.deepStrictEqual(coordinate.qualifiers, {
            architecture: "noarch",
            nativeVersion: "1.0.17592050512201",
            release: "1",
          });
          const result = InstallCommandBuilder.build(
            coordinate.format,
            coordinate.name,
            coordinate.version,
            coordinate.workspace,
            coordinate.repository,
            { qualifiers: coordinate.qualifiers }
          );
          assert.match(
            result.command,
            /cloudsmith-redhat-example-1\.0\.17592050512201-1\.noarch/
          );
          assert.doesNotMatch(result.command, /-1-1\.noarch/);
        },
      },
      {
        record: apiRecord({
          name: "native-gem",
          format: "ruby",
          version: "1.0.0",
          architectures: [{ name: "x86_64-linux", description: null }],
          identifiers: { ruby_platform: "x86_64-linux" },
        }),
        assertCoordinate(coordinate) {
          assert.deepStrictEqual(coordinate.qualifiers, { platform: "x86_64-linux" });
        },
      },
    ];

    for (const { record, assertCoordinate } of cases) {
      const coordinate = packageCoordinateFromExact(fromApiPackageRecord(record));
      assertCoordinate(coordinate);
    }
  });

  test("public Raw and versionless Generic API records retain authoritative CDN identity", () => {
    const raw = fromApiPackageRecord(apiRecord({
      format: "raw",
      name: "artifact.tar.gz",
      version: "1.0.0",
      cdn_url: "https://dl.cloudsmith.io/public/Workspace/Repository/raw/versions/1.0.0/artifact.tar.gz",
    }));
    const generic = fromApiPackageRecord(apiRecord({
      format: "generic",
      name: null,
      version: null,
      filepath: "releases/stable/artifact.bin",
      cdn_url: "https://dl.cloudsmith.io/public/Workspace/Repository/generic/files/artifact.bin",
    }));

    assert.strictEqual(generic.version, "");
    assert.strictEqual(generic.coordinateName, "releases/stable/artifact.bin");
    for (const pkg of [raw, generic]) {
      const coordinate = packageCoordinateFromExact(pkg);
      const result = InstallCommandBuilder.build(
        coordinate.format,
        coordinate.name,
        coordinate.version,
        coordinate.workspace,
        coordinate.repository,
        { cdnUrl: pkg.cdnUrl, qualifiers: coordinate.qualifiers }
      );
      assert.match(result.command, /^# Verify package details before running\ncurl -fL -O /);
      assert.match(result.command, /\/public\/Workspace\/Repository\//);
    }
  });

  test("Generic and Raw API records derive an omitted name from file metadata", () => {
    const fixtures = [
      { format: "generic", filepath: "releases/stable/artifact.bin" },
      { format: "raw", filename: "artifact.tar.gz" },
    ];

    for (const fixture of fixtures) {
      const record = apiRecord({
        format: fixture.format,
        version: null,
        ...fixture,
      });
      delete record.name;

      const pkg = fromApiPackageRecord(record);
      const expectedName = fixture.filepath || fixture.filename;
      assert.strictEqual(pkg.name, expectedName);
      assert.strictEqual(pkg.coordinateName, expectedName);
      assert.strictEqual(
        exactPackageIdentity(fromPackageSelection(record)),
        exactPackageIdentity(pkg)
      );

      const recentRecord = {
        cloudsmithWorkspace: "Workspace",
        cloudsmithRepo: "Repository",
        slug_perm_raw: `recent-${fixture.format}`,
        format: fixture.format,
        ...fixture,
      };
      const recent = fromRecentPackageRecord(recentRecord);
      assert.strictEqual(recent.name, expectedName);
      assert.strictEqual(recent.version, "");
      assert.strictEqual(
        exactPackageIdentity(fromPackageSelection(recentRecord)),
        exactPackageIdentity(recent)
      );
    }

    const nullNamed = apiRecord({
      format: "generic",
      name: null,
      version: null,
      filepath: "releases/null-name/artifact.bin",
    });
    assert.strictEqual(
      exactPackageIdentity(fromPackageSelection(nullNamed)),
      exactPackageIdentity(fromApiPackageRecord(nullNamed))
    );

    const undefinedNamed = {
      ...nullNamed,
      name: undefined,
    };
    assert.throws(() => fromApiPackageRecord(undefinedNamed), PackageAdapterError);
    assert.throws(() => fromPackageSelection(undefinedNamed), PackageAdapterError);
    assert.throws(() => fromRecentPackageRecord({
      cloudsmithWorkspace: "Workspace",
      cloudsmithRepo: "Repository",
      slug_perm_raw: "recent-undefined-name",
      format: "generic",
      name: undefined,
      filepath: "releases/undefined-name/artifact.bin",
    }), PackageAdapterError);

    const declaredRecent = fromRecentPackageRecord({
      cloudsmithWorkspace: "Workspace",
      cloudsmithRepo: "Repository",
      slug_perm_raw: "recent-declared-version",
      format: "generic",
      filepath: "releases/declared-version/artifact.bin",
      declaredVersion: "2.0.0",
    });
    assert.strictEqual(declaredRecent.version, "2.0.0");
  });

  test("dependency coordinate context enriches an already exact API package", () => {
    const exact = fromApiPackageRecord(apiRecord({
      name: "demo",
      format: "maven",
      version: "1.2.3",
    }));
    const enriched = fromApiPackageRecord(exact, {
      coordinateName: "com.example:demo",
      coordinateQualifiers: { type: "test-jar", classifier: "tests", scope: "test" },
    });
    const coordinate = packageCoordinateFromExact(enriched);

    assert.strictEqual(coordinate.name, "com.example:demo");
    assert.deepStrictEqual(coordinate.qualifiers, {
      classifier: "tests",
      scope: "test",
      type: "test-jar",
    });
  });

  test("Maven extension defaults do not overwrite authoritative dependency type", () => {
    const raw = apiRecord({
      name: "demo",
      format: "maven",
      version: "1.2.3",
      extension: ".jar",
      filename: "demo-1.2.3-tests.jar",
      identifiers: { group_id: "com.example", classifier: "tests" },
    });
    const enriched = fromApiPackageRecord(raw, {
      coordinateQualifiers: { type: "test-jar", classifier: "tests", scope: "test" },
    });
    assert.deepStrictEqual(enriched.qualifiers, {
      classifier: "tests",
      scope: "test",
      type: "test-jar",
    });

    const exact = fromApiPackageRecord(apiRecord({
      qualifiers: { type: "jar" },
    }));
    const subset = fromApiPackageRecord(exact, {
      coordinateQualifiers: { type: "jar", scope: "test" },
    });
    assert.deepStrictEqual(subset.qualifiers, { scope: "test", type: "jar" });
  });

  test("unbranded Maven coordinates require native API identity consensus", () => {
    const mavenRecord = overrides => apiRecord({
      name: "demo",
      format: "maven",
      version: "1.2.3",
      identifiers: { group_id: "com.example" },
      ...overrides,
    });
    for (const [record, options] of [
      [mavenRecord({ coordinateName: "org.other:demo" }), undefined],
      [mavenRecord({ coordinateName: "com.example:other" }), undefined],
      [mavenRecord({}), { coordinateName: "org.other:demo" }],
      [mavenRecord({}), { coordinateName: "com.example:other" }],
      [mavenRecord({ name: "org.other:demo" }), undefined],
    ]) {
      assert.throws(() => fromApiPackageRecord(record, options), error => (
        error instanceof PackageAdapterError
        && error.code === "conflicting_aliases"
        && error.field === "coordinateName"
      ));
    }

    assert.strictEqual(
      fromApiPackageRecord(mavenRecord({ coordinateName: "com.example:demo" })).coordinateName,
      "com.example:demo"
    );
    assert.strictEqual(
      fromApiPackageRecord(mavenRecord({}), {
        coordinateName: "com.example:demo",
      }).coordinateName,
      "com.example:demo"
    );
    const withoutApiGroup = mavenRecord({ coordinateName: "persisted.example:demo" });
    delete withoutApiGroup.identifiers;
    assert.strictEqual(
      fromApiPackageRecord(withoutApiGroup).coordinateName,
      "persisted.example:demo"
    );
  });

  test("Maven classifier context requires exact API artifact consensus", () => {
    const mavenRecord = overrides => apiRecord({
      name: "demo",
      format: "maven",
      version: "1.2.3",
      extension: ".jar",
      filename: "demo-1.2.3-tests.jar",
      identifiers: { group_id: "com.example", classifier: "tests" },
      ...overrides,
    });
    for (const [record, options] of [
      [mavenRecord({ qualifiers: { classifier: "sources" } }), undefined],
      [mavenRecord({}), {
        coordinateQualifiers: { type: "test-jar", classifier: "sources" },
      }],
      [mavenRecord({
        qualifiers: { classifier: "sources" },
        identifiers: { group_id: "com.example" },
      }), undefined],
      [mavenRecord({
        name: "com.example:demo",
        qualifiers: { classifier: "sources" },
        identifiers: { group_id: "com.example" },
      }), undefined],
      [mavenRecord({
        filename: "demo-1.2.3.jar",
        identifiers: { group_id: "com.example" },
      }), {
        coordinateQualifiers: { type: "test-jar", classifier: "tests" },
      }],
      [mavenRecord({
        name: "com.example:demo",
        filename: "demo-1.2.3.jar",
        identifiers: { group_id: "com.example" },
      }), {
        coordinateQualifiers: { type: "test-jar", classifier: "tests" },
      }],
    ]) {
      assert.throws(() => fromApiPackageRecord(record, options), error => (
        error instanceof PackageAdapterError
        && error.code === "conflicting_aliases"
        && error.field === "qualifiers"
      ));
    }

    const matched = fromApiPackageRecord(mavenRecord({}), {
      coordinateQualifiers: { type: "test-jar", classifier: "tests", scope: "test" },
    });
    assert.deepStrictEqual(matched.qualifiers, {
      classifier: "tests",
      scope: "test",
      type: "test-jar",
    });

    const qualified = fromApiPackageRecord(mavenRecord({
      name: "com.example:demo",
      identifiers: { group_id: "com.example" },
    }), {
      coordinateQualifiers: { type: "test-jar", classifier: "tests", scope: "test" },
    });
    assert.strictEqual(qualified.coordinateName, "com.example:demo");
    assert.deepStrictEqual(qualified.qualifiers, {
      classifier: "tests",
      scope: "test",
      type: "test-jar",
    });

    const mainArtifact = fromApiPackageRecord(mavenRecord({
      filename: "demo-1.2.3.jar",
      identifiers: { group_id: "com.example" },
    }));
    assert.deepStrictEqual(mainArtifact.qualifiers, { type: "jar" });
  });

  test("Conda CDN qualifier derivation uses the exact selected scope", () => {
    const scoped = fromApiPackageRecord(apiRecord({
      namespace: "conda",
      repository: "conda",
      name: "numpy",
      format: "conda",
      version: "1.24.0",
      filename: "numpy-1.24.0-build_0.conda",
      cdn_url: "https://dl.cloudsmith.io/public/conda/conda/conda/linux-64/numpy-1.24.0-build_0.conda",
      identifiers: { build_string: "build_0" },
    }));
    assert.deepStrictEqual(scoped.qualifiers, { build: "build_0", subdir: "linux-64" });

    assert.throws(() => fromApiPackageRecord(apiRecord({
      name: "numpy",
      format: "conda",
      version: "1.24.0",
      filename: "numpy-1.24.0-build_0.conda",
      cdn_url: "https://dl.cloudsmith.io/public/Other/Repository/conda/linux-64/numpy-1.24.0-build_0.conda",
      identifiers: { build_string: "build_0" },
    })), PackageAdapterError);
  });

  test("dependency context cannot replace authoritative exact-package coordinates", () => {
    const exact = fromApiPackageRecord(apiRecord({
      name: "artifact",
      coordinateName: "com.trusted:artifact",
      format: "maven",
      version: "1.2.3",
      qualifiers: { type: "test-jar", classifier: "trusted", scope: "test" },
    }));

    assert.throws(() => fromApiPackageRecord(exact, {
      coordinateName: "com.other:artifact",
    }), error => (
      error instanceof PackageAdapterError
      && error.code === "conflicting_aliases"
      && error.field === "coordinateName"
    ));
    assert.throws(() => fromApiPackageRecord(exact, {
      coordinateName: "com.trusted:artifact",
      coordinateQualifiers: { type: "test-jar", classifier: "other", scope: "test" },
    }), error => (
      error instanceof PackageAdapterError
      && error.code === "conflicting_aliases"
      && error.field === "qualifiers"
    ));

    const same = fromApiPackageRecord(exact, {
      coordinateName: "com.trusted:artifact",
      coordinateQualifiers: { scope: "test", classifier: "trusted", type: "test-jar" },
    });
    assert.strictEqual(same, exact);
  });

  test("snapshots bounded dependency qualifiers into canonical pull coordinates", () => {
    const configurations = ["compile", "runtime"];
    const qualifiers = {
      alias: "declared-alias",
      architecture: "x86_64",
      build: "build_0",
      classifier: "sources",
      configurations,
      digest: "sha256:abcdef",
      environment: "production",
      epoch: "1",
      nativeVersion: "1.0",
      platform: "x86_64-linux",
      pullPolicy: "always",
      release: "2.el9",
      repository: "registry.example.test",
      scope: "com.example",
      section: "dependencies",
      service: "api",
      stage: "builder",
      subdir: "linux-64",
      tag: "latest",
      targetFramework: "net8.0",
      type: "jar",
    };
    const coordinate = createPackageCoordinate({
      workspace: "workspace",
      repository: "repository",
      name: "artifact",
      version: "1.0.0",
      format: "maven",
      qualifiers,
    });

    qualifiers.classifier = "javadoc";
    configurations.push("test");
    assert.deepStrictEqual(coordinate.qualifiers, {
      alias: "declared-alias",
      architecture: "x86_64",
      build: "build_0",
      classifier: "sources",
      configurations: ["compile", "runtime"],
      digest: "sha256:abcdef",
      environment: "production",
      epoch: "1",
      nativeVersion: "1.0",
      platform: "x86_64-linux",
      pullPolicy: "always",
      release: "2.el9",
      repository: "registry.example.test",
      scope: "com.example",
      section: "dependencies",
      service: "api",
      stage: "builder",
      subdir: "linux-64",
      tag: "latest",
      targetFramework: "net8.0",
      type: "jar",
    });
    assert.ok(Object.isFrozen(coordinate.qualifiers));
    assert.ok(Object.isFrozen(coordinate.qualifiers.configurations));

    assert.throws(() => createPackageCoordinate({
      workspace: "workspace",
      repository: "repository",
      name: "artifact",
      version: "1.0.0",
      format: "maven",
      qualifiers: { unsupported: "identity" },
    }), error => (
      error instanceof PackageDomainError
      && error.code === "unknown_field"
      && error.field === "qualifiers.unsupported"
    ));
  });

  test("provides a dedicated versionless upstream-resolution input", () => {
    const input = createPackageResolutionInput({
      workspace: "workspace",
      repository: "repository",
      name: "@scope/artifact",
      format: "npm",
    });
    assert.deepStrictEqual(input, {
      workspace: "workspace",
      repository: "repository",
      name: "@scope/artifact",
      format: "npm",
    });
    assert.ok(Object.isFrozen(input));
    assert.throws(() => createPackageResolutionInput({
      workspace: "workspace",
      repository: "../repository",
      name: "artifact",
      format: "npm",
    }), PackageDomainError);
  });

  test("adapts bounded repository operation selections without retaining legacy shapes", () => {
    const versionless = {
      namespace: { value: "workspace" },
      cloudsmithRepo: { value: { value: "repository" } },
      name: { value: "artifact" },
      format: "npm",
    };
    const resolution = fromPackageResolutionSelection(versionless);
    assert.deepStrictEqual(resolution, {
      workspace: "workspace",
      repository: "repository",
      name: "artifact",
      format: "npm",
    });
    assert.ok(Object.isFrozen(resolution));
    assert.strictEqual(fromExactPackageSelectionIfPresent(versionless), null);
    assert.ok(isExactPackage(fromExactPackageSelectionIfPresent(apiRecord())));
    assert.throws(
      () => fromRepositoryPackageSelection(versionless),
      PackageAdapterError
    );

    const coordinate = fromRepositoryPackageSelection(versionless, {
      defaultVersion: "latest",
    });
    assert.ok(isPackageCoordinate(coordinate));
    assert.strictEqual(assertRepositoryPackageCoordinate(coordinate), coordinate);
    assert.strictEqual(coordinate.version, "latest");

    assert.throws(() => fromPackageResolutionSelection({
      ...versionless,
      workspace: "other-workspace",
    }), PackageAdapterError);
    assert.throws(() => fromPackageResolutionSelection({
      ...versionless,
      namespace: { value: { value: { value: "too-deep" } } },
    }), PackageAdapterError);
    assert.throws(() => fromRepositoryPackageSelection({
      ...versionless,
      version: "1.0.0",
      declaredVersion: "2.0.0",
    }), PackageAdapterError);
    assert.throws(() => fromPackageResolutionSelection({
      ...versionless,
      version: "1.0.0",
      declaredVersion: "2.0.0",
    }), PackageAdapterError);
    assert.throws(() => fromRepositoryPackageSelection({
      ...versionless,
      version: "",
    }, { defaultVersion: "latest" }), PackageAdapterError);
    assert.throws(() => fromPackageResolutionSelection({
      ...versionless,
      version: "",
    }), PackageAdapterError);
    for (const field of ["packageIdentifier", "slug_perm"]) {
      assert.throws(() => fromPackageResolutionSelection({
        ...versionless,
        [field]: "",
      }), PackageAdapterError);
      assert.throws(() => fromRepositoryPackageSelection({
        ...versionless,
        [field]: "",
      }, { defaultVersion: "latest" }), PackageAdapterError);
    }
  });

  test("adapts API records with omitted options and validates expected scope when provided", () => {
    const omitted = fromApiPackageRecord(apiRecord());
    const scoped = fromApiPackageRecord(apiRecord(), {
      expectedWorkspace: "Workspace",
      expectedRepository: "Repository",
    });

    assert.strictEqual(omitted, fromApiPackageRecord(omitted));
    assert.strictEqual(exactPackageIdentity(omitted), exactPackageIdentity(scoped));
    assert.throws(
      () => fromApiPackageRecord(apiRecord(), { expectedRepository: "Other" }),
      error => error instanceof PackageAdapterError && error.code === "unexpected_scope"
    );
  });

  test("maps textual API status without treating numeric transport status as an alias", () => {
    const rawApiRecord = apiRecord({
      status: 2,
      status_str: "Completed",
      status_str_raw: "Completed",
    });
    const api = fromApiPackageRecord(rawApiRecord);
    const selected = fromPackageSelection(rawApiRecord);
    const dependency = fromDependencyHealthNode({
      name: "declared-name",
      version: "^1.0.0",
      format: "npm",
      cloudsmithMatch: apiRecord({
        status: 3,
        status_str: "Quarantined",
        status_str_raw: "Quarantined",
      }),
    });

    assert.strictEqual(api.status, "Completed");
    assert.strictEqual(selected.status, "Completed");
    assert.strictEqual(exactPackageIdentity(selected), exactPackageIdentity(api));
    assert.strictEqual(dependency.status, "Quarantined");
    const conflictingStatus = apiRecord({
      status: 2,
      status_str: "Completed",
      status_str_raw: "Quarantined",
    });
    assert.throws(() => fromApiPackageRecord(conflictingStatus), PackageAdapterError);
    assert.throws(() => fromPackageSelection(conflictingStatus), PackageAdapterError);
    assert.throws(() => fromPackageNode({
      workspace: "Workspace",
      repository: "Repository",
      packageIdentifier: "Package-ID",
      name: "Package",
      version: "1.2.3",
      format: "npm",
      status: 2,
      status_str: "Completed",
    }), PackageAdapterError);
  });

  test("produces identical exact identity from API, package, search, dependency, and recent shapes", () => {
    const api = fromApiPackageRecord(apiRecord());
    const presentation = {
      namespace: "Workspace",
      repository: "Repository",
      slug_perm: { id: "Slug", value: { value: "Package-ID" } },
      slug_perm_raw: "Package-ID",
      slug: { id: "Slug", value: "package" },
      name: "@scope/Package",
      version: { id: "Version", value: "1.2.3" },
      format: "npm",
      status_str: { id: "Status", value: "Completed" },
      status_str_raw: "Completed",
      downloads: { id: "Downloads", value: "7" },
      tags_raw: { info: ["upstream"], version: ["latest"] },
      num_vulnerabilities: 0,
      security_scan_status: "Scan Detected No Vulnerabilities",
      spdx_license: "MIT",
      license: "MIT License",
      raw_license: "MIT",
      license_url: "https://spdx.org/licenses/MIT.html",
    };
    const dependency = {
      name: "declared-name",
      version: "^1.0.0",
      format: "npm",
      cloudsmithMatch: apiRecord(),
    };

    for (const pkg of [
      fromPackageNode(presentation),
      fromSearchResultNode(presentation),
      fromDependencyHealthNode(dependency),
      fromRecentPackageRecord(presentation),
      fromPackageSelection(presentation),
    ]) {
      assert.strictEqual(exactPackageIdentity(pkg), exactPackageIdentity(api));
    }
  });

  test("fails closed on conflicting aliases instead of choosing by precedence", () => {
    for (const conflict of [
      { namespace: "Other" },
      { cloudsmithRepo: "Other" },
      { slug_perm_raw: "Other" },
    ]) {
      assert.throws(
        () => fromPackageSelection({
          ...apiRecord(),
          workspace: "Workspace",
          cloudsmithWorkspace: "Workspace",
          cloudsmithRepo: "Repository",
          slug_perm_raw: "Package-ID",
          ...conflict,
        }),
        error => error instanceof PackageAdapterError
      );
    }
  });

  test("bounds wrapper depth and never invokes accessors or object coercion", () => {
    let getterCalls = 0;
    let coercionCalls = 0;
    const accessorRecord = apiRecord();
    Object.defineProperty(accessorRecord, "slug_perm_raw", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return "Package-ID";
      },
    });
    assert.throws(() => fromPackageSelection(accessorRecord), PackageAdapterError);
    assert.strictEqual(getterCalls, 0);

    assert.throws(() => fromPackageSelection({
      ...apiRecord(),
      slug_perm: { value: { value: { value: "Package-ID" } } },
    }), PackageAdapterError);

    assert.throws(() => fromPackageSelection({
      ...apiRecord(),
      version: {
        toString() {
          coercionCalls += 1;
          return "1.2.3";
        },
      },
    }), PackageAdapterError);
    assert.strictEqual(coercionCalls, 0);
  });

  test("requires exact identity and rejects unsafe encoded path identities", () => {
    assert.throws(
      () => fromApiPackageRecord(apiRecord({ slug_perm: undefined })),
      error => error instanceof PackageAdapterError && error.unexpected === false
    );
    for (const packageIdentifier of [
      "../package",
      "package%2fid",
      "package%255cid",
      "package%252525252fidentifier",
    ]) {
      assert.throws(
        () => fromApiPackageRecord(apiRecord({ slug_perm: packageIdentifier })),
        PackageAdapterError
      );
    }
  });

  test("does not turn absent vulnerability evidence into a clean package", () => {
    const record = apiRecord({
      num_vulnerabilities: undefined,
      security_scan_status: undefined,
    });
    const pkg = fromApiPackageRecord(record);

    assert.deepStrictEqual(pkg.vulnerability, {
      evidence: "unknown",
      detected: false,
      count: null,
      maxSeverity: null,
      scanStatus: null,
    });
  });

  test("canonical package evidence cannot be overwritten by stale presentation aliases", () => {
    const pkg = fromApiPackageRecord(apiRecord());
    assert.strictEqual(fromPackageSelection({ package: pkg }), pkg);
    for (const conflict of [
      { slug_perm_raw: "Other" },
      { version: { value: "9.9.9" } },
      { status_str: { value: "Quarantined" }, status_str_raw: "Quarantined" },
    ]) {
      assert.throws(
        () => fromPackageSelection({ package: pkg, ...conflict }),
        error => error instanceof PackageAdapterError
      );
    }
  });

  test("selection dispatch requires full consensus across overlapping legacy shapes", () => {
    const agreeing = apiRecord({ cloudsmithMatch: apiRecord() });
    assert.strictEqual(
      exactPackageIdentity(fromPackageSelection(agreeing)),
      JSON.stringify(["Workspace", "Repository", "Package-ID"])
    );

    for (const nestedConflict of [
      { name: "different-name" },
      { version: "9.9.9" },
      { checksum_sha256: "different-checksum" },
    ]) {
      assert.throws(
        () => fromPackageSelection(apiRecord({
          checksum_sha256: "checksum",
          cloudsmithMatch: apiRecord({ checksum_sha256: "checksum", ...nestedConflict }),
        })),
        error => error instanceof PackageAdapterError
          && error.code === "ambiguous_package_selection"
      );
    }
  });

  test("dependency match metadata is authoritative and declared projections may differ", () => {
    const pkg = fromApiPackageRecord(apiRecord());
    assert.strictEqual(fromDependencyHealthNode(pkg, {
      workspace: pkg.workspace,
      repository: pkg.repository,
    }), pkg);
    assert.throws(() => fromDependencyHealthNode(pkg, {
      workspace: "other",
      repository: pkg.repository,
    }), PackageAdapterError);

    const matchedNode = {
      package: pkg,
      cloudsmithMatch: pkg,
      declarationName: "declared-alias",
      name: "declared-alias",
      version: { id: "Version", value: pkg.version },
      declaredVersion: "^1.0.0",
      format: "yarn",
      namespace: pkg.workspace,
      repository: pkg.repository,
      slug_perm_raw: pkg.packageIdentifier,
    };
    assert.strictEqual(fromDependencyHealthNode(matchedNode), pkg);
    assert.strictEqual(fromPackageSelection(matchedNode), pkg);
    assert.strictEqual(fromExactPackageSelectionIfPresent(matchedNode), pkg);

    const coordinate = fromDependencyHealthNode({
      name: "declared-alias",
      resolvedVersion: "1.0.0",
      format: "npm",
    }, {
      workspace: "workspace",
      repository: "repository",
    });
    assert.ok(isPackageCoordinate(coordinate));
    assert.strictEqual(coordinate.workspace, "workspace");
    assert.deepStrictEqual(coordinate.qualifiers, {});
    const unmatchedResolution = fromPackageResolutionSelection({
      declarationName: "declared-alias",
      name: "normalized-name",
      declaredVersion: "^1.0.0",
      resolvedVersion: "1.5.0",
      versionState: "resolved",
      cloudsmithStatus: "NOT_FOUND",
      format: "npm",
    }, {
      workspace: "workspace",
      repository: "repository",
    });
    assert.deepStrictEqual(unmatchedResolution, {
      workspace: "workspace",
      repository: "repository",
      name: "normalized-name",
      format: "npm",
    });
    assert.throws(() => fromDependencyHealthNode({
      workspace: "other",
      name: "declared-alias",
      version: "1.0.0",
      format: "npm",
    }, { workspace: "workspace" }), PackageAdapterError);
  });

  test("preserves dependency node qualifiers when adapting unresolved pull coordinates", () => {
    const coordinate = fromDependencyHealthNode({
      name: "com.example:artifact",
      resolvedVersion: "1.0.0",
      format: "maven",
      qualifiers: {
        type: "test-jar",
        classifier: "tests",
        platform: "java",
        tag: "release",
        digest: "sha256:abcdef",
        targetFramework: "net8.0",
      },
    }, {
      workspace: "workspace",
      repository: "repository",
    });

    assert.ok(isPackageCoordinate(coordinate));
    assert.deepStrictEqual(coordinate.qualifiers, {
      classifier: "tests",
      digest: "sha256:abcdef",
      platform: "java",
      tag: "release",
      targetFramework: "net8.0",
      type: "test-jar",
    });
    assert.ok(Object.isFrozen(coordinate.qualifiers));
  });

  test("duplicate dependency and recent match aliases require full canonical consensus", () => {
    const conflicting = apiRecord({ version: "9.9.9" });
    assert.throws(() => fromDependencyHealthNode({
      name: "declared",
      version: "1.0.0",
      format: "npm",
      cloudsmithMatch: apiRecord(),
      cloudsmithPackage: conflicting,
    }), PackageAdapterError);
    assert.throws(() => fromRecentPackageRecord({
      cloudsmithMatch: apiRecord(),
      cloudsmithPackage: conflicting,
    }), PackageAdapterError);

    const canonical = fromApiPackageRecord(apiRecord());
    assert.throws(() => fromDependencyHealthNode({
      package: canonical,
      cloudsmithMatch: conflicting,
    }), PackageAdapterError);
    assert.throws(() => fromRecentPackageRecord({
      package: canonical,
      cloudsmithPackage: conflicting,
    }), PackageAdapterError);
    const coordinate = createPackageCoordinate({
      workspace: "Workspace",
      repository: "Repository",
      name: "declared",
      version: "1.0.0",
      format: "npm",
    });
    assert.throws(() => fromDependencyHealthNode({
      package: coordinate,
      cloudsmithMatch: apiRecord(),
    }), PackageAdapterError);
  });

  test("adapts bounded immutable repository, package-group, and detail boundaries", () => {
    const repository = fromRepositoryNode({
      workspace: "workspace",
      slug: "repository",
      name: "Repository",
    });
    const group = fromPackageGroupNode({
      workspace: "workspace",
      repo: "repository",
      name: "artifact",
    });
    const detail = fromPackageDetailNode({
      _detailId: "Version",
      _detailValue: "1.2.3",
      label: { id: "Version", value: "1.2.3" },
    });

    assert.deepStrictEqual(repository, {
      workspace: "workspace",
      repository: "repository",
      name: "Repository",
    });
    assert.deepStrictEqual(group, {
      workspace: "workspace",
      repository: "repository",
      name: "artifact",
      format: null,
    });
    assert.deepStrictEqual(detail, { id: "Version", value: "1.2.3" });
    assert.ok(Object.isFrozen(repository));
    assert.ok(Object.isFrozen(group));
    assert.ok(Object.isFrozen(detail));
    assert.throws(() => fromRepositoryNode({
      workspace: "workspace",
      slug_perm: "legacy-only",
      name: "Repository",
    }), PackageAdapterError);
    assert.throws(() => fromRepositoryNode({
      workspace: "workspace",
      slug: "repository%252525252fescape",
      name: "Repository",
    }), PackageAdapterError);
    assert.throws(() => fromPackageDetailNode({
      _detailId: "Version",
      _detailValue: "1.2.3",
      label: { id: "Version", value: "2.0.0" },
    }), PackageAdapterError);
  });

  test("rejects symbol-keyed and inherited semantic properties without invoking getters", () => {
    let getterCalls = 0;
    const inheritedPrototype = Object.defineProperty({}, "namespace", {
      get() {
        getterCalls += 1;
        return "Workspace";
      },
    });
    const inherited = apiRecord();
    delete inherited.namespace;
    Object.setPrototypeOf(inherited, inheritedPrototype);
    assert.throws(() => fromPackageSelection(inherited), PackageAdapterError);
    assert.strictEqual(getterCalls, 0);

    const symbolRecord = apiRecord();
    symbolRecord[Symbol("secret")] = "not-canonical";
    assert.throws(() => fromApiPackageRecord(symbolRecord), PackageAdapterError);

    const unknownAccessor = apiRecord();
    Object.defineProperty(unknownAccessor, "unknown_api_field", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return "ignored";
      },
    });
    assert.throws(() => fromApiPackageRecord(unknownAccessor), PackageAdapterError);
    assert.strictEqual(getterCalls, 0);

    const nestedSymbol = apiRecord();
    nestedSymbol.tags[Symbol("hidden")] = "tag";
    assert.throws(() => fromApiPackageRecord(nestedSymbol), PackageAdapterError);

    const inheritedNested = apiRecord({
      policy_violated: undefined,
      policy: Object.create({ violated: false }),
    });
    assert.throws(() => fromPackageSelection(inheritedNested), PackageAdapterError);
  });

  test("rejects oversized tag arrays before enumerating their indexes", () => {
    let ownKeysCalls = 0;
    let indexDescriptorReads = 0;
    const oversized = new Proxy(new Array(1_000_000), {
      ownKeys() {
        ownKeysCalls += 1;
        return Reflect.ownKeys(new Array(1_000_000));
      },
      getOwnPropertyDescriptor(target, property) {
        if (property !== "length") indexDescriptorReads += 1;
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
    });
    const record = apiRecord({ tags: { info: oversized, version: [] } });

    assert.throws(() => fromApiPackageRecord(record), PackageAdapterError);
    assert.strictEqual(ownKeysCalls, 0);
    assert.strictEqual(indexDescriptorReads, 0);
  });

  test("deeply frozen nested values reject mutation attempts", () => {
    const pkg = fromApiPackageRecord(apiRecord());
    assert.throws(() => pkg.tags.info.push("mutated"), TypeError);
    assert.throws(() => Object.defineProperty(pkg.policy, "violated", { value: true }), TypeError);
    assert.throws(() => Object.defineProperty(pkg.license, "raw", { value: "changed" }), TypeError);
    assert.throws(
      () => Object.defineProperty(pkg.vulnerability, "evidence", { value: "detected" }),
      TypeError
    );
  });

  test("structural clones are revalidated instead of being trusted as canonical brands", () => {
    const pkg = fromApiPackageRecord(apiRecord());
    const clone = { ...pkg };

    assert.strictEqual(isExactPackage(clone), false);
    const adapted = fromPackageSelection(clone);
    assert.ok(isExactPackage(adapted));
    assert.strictEqual(exactPackageIdentity(adapted), exactPackageIdentity(pkg));
  });

  test("preserves positive vulnerability truth under contradictory evidence", () => {
    const pkg = fromApiPackageRecord(apiRecord({
      num_vulnerabilities: 0,
      has_vulnerabilities: true,
    }));
    assert.deepStrictEqual(pkg.vulnerability, {
      evidence: "unknown",
      detected: true,
      count: null,
      maxSeverity: null,
      scanStatus: null,
    });
  });

  test("keeps clean vulnerability evidence free of positive severity metadata", () => {
    const conflict = fromApiPackageRecord(apiRecord({ max_severity: "High" }));
    assert.deepStrictEqual(conflict.vulnerability, {
      evidence: "unknown",
      detected: true,
      count: null,
      maxSeverity: "High",
      scanStatus: null,
    });
    assert.throws(() => createExactPackage({
      workspace: "workspace",
      repository: "repository",
      packageIdentifier: "package",
      name: "artifact",
      version: "1.0.0",
      format: "npm",
      vulnerability: {
        evidence: "clean",
        detected: false,
        count: 0,
        maxSeverity: "High",
      },
    }), error => (
      error instanceof PackageDomainError
      && error.code === "contradictory_vulnerability_metadata"
    ));
    assert.throws(() => createExactPackage({
      workspace: "workspace",
      repository: "repository",
      packageIdentifier: "package",
      name: "artifact",
      version: "1.0.0",
      format: "npm",
      vulnerability: {
        evidence: "unknown",
        detected: false,
        count: null,
        maxSeverity: "Critical",
      },
    }), error => (
      error instanceof PackageDomainError
      && error.code === "contradictory_vulnerability_metadata"
    ));
  });

  test("rejects malformed copyability", () => {
    assert.throws(() => fromApiPackageRecord(apiRecord({ is_copyable: "false" })), PackageAdapterError);
  });

  test("accepts an explicit finite numeric API version without general object coercion", () => {
    const pkg = fromApiPackageRecord(apiRecord({ version: 12 }));
    assert.strictEqual(pkg.version, "12");
  });

  test("does not expose a direct factory escape hatch for malformed nested metadata", () => {
    assert.throws(() => createExactPackage({
      workspace: "workspace",
      repository: "repository",
      packageIdentifier: "package",
      name: "artifact",
      version: "1.0.0",
      format: "npm",
      tags: {
        get info() {
          throw new Error("must not run");
        },
      },
    }), error => error instanceof PackageDomainError && error.code === "accessor_property");
  });

  test("serializes only the bounded non-delivery package inspection surface", () => {
    const pkg = fromApiPackageRecord(apiRecord({
      cdn_url: "https://cdn.example.invalid/private?token=secret",
      license_url: "https://example.invalid/license?credential=secret",
      entitlement_token: "must-not-appear",
    }));

    const output = serializePackageInspection(pkg);
    const inspection = JSON.parse(output);

    assert.strictEqual(inspection.workspace, "Workspace");
    assert.strictEqual(inspection.packageIdentifier, "Package-ID");
    assert.strictEqual(Object.hasOwn(inspection, "cdnUrl"), false);
    assert.strictEqual(Object.hasOwn(inspection.license, "url"), false);
    assert.doesNotMatch(output, /token=secret|credential=secret|must-not-appear/);
    assert.ok(Buffer.byteLength(output, "utf8") <= 256 * 1024);
  });

  test("bounds collection inspection and truthfully reports omitted packages", () => {
    const packages = Array.from({ length: 501 }, (_, index) => fromApiPackageRecord(apiRecord({
      slug_perm: `package-${index}`,
      name: `package-${index}`,
    })));

    const output = serializePackageCollectionInspection(packages, {
      complete: true,
      totalCount: 501,
      termination: "complete",
    });
    const inspection = JSON.parse(output);

    assert.strictEqual(inspection.loadedCount, 501);
    assert.ok(inspection.displayedCount <= 500);
    assert.strictEqual(inspection.omittedCount, 501 - inspection.displayedCount);
    assert.strictEqual(inspection.complete, false);
    assert.strictEqual(inspection.totalCount, 501);
    assert.ok(Buffer.byteLength(output, "utf8") <= 256 * 1024);
  });
});

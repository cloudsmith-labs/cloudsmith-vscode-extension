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

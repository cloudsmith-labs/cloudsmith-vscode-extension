const assert = require("assert");
const {
  PromotionContractError,
  createOutcome,
  createSourceLocator,
  createStage,
  createTagPlan,
  isPackageLocationArray,
  normalizeFreshSource,
  normalizePackageQueryIdentity,
  normalizePipeline,
  normalizeTargetPackage,
  preflightFingerprint,
} = require("../util/promotionContracts");

suite("Promotion contracts", () => {
  const locator = Object.freeze({
    workspace: "workspace",
    repository: "source",
    packageIdentifier: "source-package-id",
  });

  function sourceRecord(overrides = {}) {
    return {
      namespace: "workspace",
      repository: "source",
      slug_perm: "source-package-id",
      name: "artifact",
      version: "1.0.0",
      format: "npm",
      is_copyable: true,
      checksum_sha256: "checksum-a",
      tags: { info: [] },
      ...overrides,
    };
  }

  function locationRecord(overrides = {}) {
    return {
      namespace: "workspace",
      repository: "source",
      slug_perm: "package-id",
      name: "artifact",
      version: "1.0.0",
      format: "npm",
      ...overrides,
    };
  }

  test("builds the same scalar locator from package, search, dependency, and recent shapes", () => {
    const shapes = [
      { namespace: "workspace", repository: "source", slug_perm: { id: "Slug", value: "source-package-id" } },
      { namespace: "workspace", repository: "source", slug_perm_raw: "source-package-id" },
      { cloudsmithWorkspace: "workspace", cloudsmithRepo: "source", slug_perm: "source-package-id" },
      { cloudsmithMatch: { namespace: "workspace", repository: "source", slug_perm: "source-package-id" } },
    ];
    for (const shape of shapes) {
      assert.deepStrictEqual(createSourceLocator(shape), locator);
    }
  });

  test("accepts agreeing aliases and rejects conflicting or malformed aliases", () => {
    const matching = createSourceLocator({
      namespace: "workspace",
      cloudsmithWorkspace: "workspace",
      repository: "source",
      cloudsmithRepo: "source",
      slug_perm: { value: "source-package-id" },
      slug_perm_raw: "source-package-id",
    });
    assert.deepStrictEqual(matching, locator);

    for (const item of [
      { namespace: "workspace", cloudsmithWorkspace: "other", repository: "source", slug_perm: "source-package-id" },
      { namespace: "workspace", repository: "source", slug_perm: "source-package-id", slug_perm_raw: "other-id" },
      { namespace: "workspace", repository: "source", slug_perm: { value: {} }, slug_perm_raw: "source-package-id" },
      { namespace: "workspace", repository: "source", slug: "source-package-id" },
    ]) {
      assert.throws(() => createSourceLocator(item), PromotionContractError);
    }
  });

  test("rejects unsafe path identities before they can become endpoints", () => {
    for (const unsafe of [
      "../source",
      "a/b",
      "a\\b",
      "%252f",
      " source",
      "source\u0000",
      "source\u061ctarget",
      "source\u202etarget",
    ]) {
      assert.throws(() => createSourceLocator({
        namespace: "workspace",
        repository: unsafe,
        slug_perm: "source-package-id",
      }), PromotionContractError);
    }
  });

  test("package-location arrays require complete canonical string identities", () => {
    assert.strictEqual(isPackageLocationArray([locationRecord()]), true);
    assert.strictEqual(
      isPackageLocationArray([locationRecord({ slug_perm_raw: "package-id" })]),
      true
    );

    const malformed = [
      locationRecord({ name: "" }),
      locationRecord({ name: "   " }),
      locationRecord({ name: "artifact\u0000" }),
      locationRecord({ version: "" }),
      locationRecord({ version: "   " }),
      locationRecord({ version: 1 }),
      locationRecord({ version: Number.NaN }),
      locationRecord({ version: Number.POSITIVE_INFINITY }),
      locationRecord({ version: Number.NEGATIVE_INFINITY }),
      locationRecord({ format: "" }),
      locationRecord({ format: "   " }),
      locationRecord({ format: "np\u202em" }),
      locationRecord({ namespace: "" }),
      locationRecord({ namespace: "   " }),
      locationRecord({ namespace: "../workspace" }),
      locationRecord({ namespace: "workspace%2fother" }),
      locationRecord({ namespace: "workspace%252fother" }),
      locationRecord({ repository: "" }),
      locationRecord({ repository: "   " }),
      locationRecord({ repository: "../source" }),
      locationRecord({ repository: "source/other" }),
      locationRecord({ slug_perm: "" }),
      locationRecord({ slug_perm: "   " }),
      locationRecord({ slug_perm: "../package-id" }),
      locationRecord({ slug_perm: "package%5cid" }),
      locationRecord({ slug_perm: "package%255cid" }),
      locationRecord({ slug_perm_raw: "other-package-id" }),
      locationRecord({ policy_violated: "false" }),
      locationRecord({ namespace: undefined }),
      locationRecord({ repository: undefined }),
      locationRecord({ slug_perm: undefined }),
    ];
    for (const record of malformed) {
      assert.doesNotThrow(() => isPackageLocationArray([record]));
      assert.strictEqual(isPackageLocationArray([record]), false);
    }
    assert.strictEqual(
      isPackageLocationArray([locationRecord(), locationRecord({ repository: " " })]),
      false
    );
    assert.strictEqual(isPackageLocationArray({}), false);
  });

  test("promotion query identity is normalized once and rejects ambiguous inputs", () => {
    const identity = normalizePackageQueryIdentity("workspace", "artifact", "1.0.0", "npm");
    assert.deepStrictEqual(identity, {
      workspace: "workspace",
      name: "artifact",
      version: "1.0.0",
      format: "npm",
    });
    assert(Object.isFrozen(identity));

    const invalid = [
      ["", "artifact", "1.0.0", "npm"],
      ["   ", "artifact", "1.0.0", "npm"],
      ["../workspace", "artifact", "1.0.0", "npm"],
      ["workspace%252fother", "artifact", "1.0.0", "npm"],
      ["workspace", "", "1.0.0", "npm"],
      ["workspace", "   ", "1.0.0", "npm"],
      ["workspace", "artifact", "", "npm"],
      ["workspace", "artifact", "   ", "npm"],
      ["workspace", "artifact", 1, "npm"],
      ["workspace", "artifact", Number.NaN, "npm"],
      ["workspace", "artifact", Number.POSITIVE_INFINITY, "npm"],
      ["workspace", "artifact", Number.NEGATIVE_INFINITY, "npm"],
      ["workspace", "artifact", "1.0.0", ""],
      ["workspace", "artifact", "1.0.0", "   "],
    ];
    for (const args of invalid) {
      assert.throws(() => normalizePackageQueryIdentity(...args), PromotionContractError);
    }
  });

  test("fresh source is the only authority for identity and strict copyability", () => {
    const source = normalizeFreshSource(sourceRecord(), locator);
    assert.strictEqual(source.copyable, true);
    assert(Object.isFrozen(source));
    assert(Object.isFrozen(source.fingerprint));
    assert(Object.isFrozen(source.tags));

    for (const is_copyable of ["true", "false", 0, 1, null, undefined]) {
      assert.throws(
        () => normalizeFreshSource(sourceRecord({ is_copyable }), locator),
        PromotionContractError
      );
    }
    assert.strictEqual(normalizeFreshSource(sourceRecord({ is_copyable: false }), locator).copyable, false);
  });

  test("rejects fresh identity mismatch, malformed versions, and missing immutable evidence", () => {
    for (const record of [
      sourceRecord({ slug_perm: "different" }),
      sourceRecord({ slug_perm: "" }),
      sourceRecord({ slug_perm: "   " }),
      sourceRecord({ namespace: "other" }),
      sourceRecord({ namespace: "" }),
      sourceRecord({ namespace: "   " }),
      sourceRecord({ repository: "other" }),
      sourceRecord({ repository: "" }),
      sourceRecord({ repository: "   " }),
      sourceRecord({ name: "" }),
      sourceRecord({ name: "   " }),
      sourceRecord({ version: "" }),
      sourceRecord({ version: "   " }),
      sourceRecord({ version: 1 }),
      sourceRecord({ version: Number.NaN }),
      sourceRecord({ version: Number.POSITIVE_INFINITY }),
      sourceRecord({ version: Number.NEGATIVE_INFINITY }),
      sourceRecord({ version: {} }),
      sourceRecord({ format: "" }),
      sourceRecord({ format: "   " }),
      sourceRecord({ checksum_sha256: null, version_digest: null }),
    ]) {
      assert.throws(() => normalizeFreshSource(record, locator), PromotionContractError);
    }
  });

  test("target package derives every field from one validated target record", () => {
    const source = normalizeFreshSource(sourceRecord(), locator);
    const target = Object.freeze({ workspace: "workspace", repository: "target" });
    const packageRecord = {
      ...sourceRecord(),
      repository: "target",
      slug_perm: "target-package-id",
    };
    const normalized = normalizeTargetPackage(packageRecord, source, target);
    assert.strictEqual(normalized.packageIdentifier, "target-package-id");
    assert.strictEqual(normalized.repository, "target");
    assert(Object.isFrozen(normalized));

    assert.throws(
      () => normalizeTargetPackage({ ...packageRecord, slug_perm: "source-package-id" }, source, target),
      PromotionContractError
    );
    assert.throws(
      () => normalizeTargetPackage({ ...packageRecord, checksum_sha256: "different" }, source, target),
      PromotionContractError
    );
    const sourceWithBoth = normalizeFreshSource(
      sourceRecord({ version_digest: "digest-a" }),
      locator
    );
    assert.throws(
      () => normalizeTargetPackage({
        ...packageRecord,
        version_digest: "digest-b",
      }, sourceWithBoth, target),
      PromotionContractError
    );

    for (const record of [
      { ...packageRecord, namespace: "" },
      { ...packageRecord, namespace: "   " },
      { ...packageRecord, repository: "" },
      { ...packageRecord, repository: "   " },
      { ...packageRecord, slug_perm: "" },
      { ...packageRecord, slug_perm: "   " },
      { ...packageRecord, name: "" },
      { ...packageRecord, name: "   " },
      { ...packageRecord, version: "" },
      { ...packageRecord, version: "   " },
      { ...packageRecord, version: 1 },
      { ...packageRecord, version: Number.NaN },
      { ...packageRecord, version: Number.POSITIVE_INFINITY },
      { ...packageRecord, version: Number.NEGATIVE_INFINITY },
      { ...packageRecord, format: "" },
      { ...packageRecord, format: "   " },
    ]) {
      assert.throws(
        () => normalizeTargetPackage(record, source, target),
        PromotionContractError
      );
    }
  });

  test("pipeline and expanded tag plans are bounded, unique, and frozen", () => {
    assert.deepStrictEqual(normalizePipeline(["source", "target"]), ["source", "target"]);
    assert.deepStrictEqual(normalizePipeline(undefined), []);
    assert.throws(() => normalizePipeline(["source", "source"]), PromotionContractError);
    assert.throws(() => normalizePipeline("source"), PromotionContractError);
    assert.throws(() => normalizePipeline(null), PromotionContractError);

    assert.throws(
      () => normalizeFreshSource(sourceRecord({
        tags: { info: Array.from({ length: 1001 }, (_, index) => `tag-${index}`) },
      }), locator),
      PromotionContractError
    );

    const plan = createTagPlan({
      onPromote: ["promoted-to-{target}", "promoted-to-{target}"],
      onReceive: ["promoted-from-{source}-{date}"],
    }, "source", "target", "2026-08-09");
    assert.deepStrictEqual(plan.source, ["promoted-to-target"]);
    assert.deepStrictEqual(plan.target, ["promoted-from-source-2026-08-09"]);
    assert(Object.isFrozen(plan));
    assert.throws(() => createTagPlan({ onPromote: ["{unknown}"], onReceive: [] }, "source", "target", "2026-08-09"));
  });

  test("preflight fingerprint includes account and frozen tag plan", () => {
    const source = normalizeFreshSource(sourceRecord(), locator);
    const preflight = Object.freeze({
      source,
      target: Object.freeze({ workspace: "workspace", repository: "target" }),
      targetPackageState: "absent",
      targetPackageCount: 0,
    });
    const account = Object.freeze({ activationId: "activation", accountEpoch: 1 });
    const first = createTagPlan({ onPromote: [], onReceive: [] }, "source", "target", "2026-08-09");
    const second = createTagPlan({ onPromote: ["tag"], onReceive: [] }, "source", "target", "2026-08-09");
    assert.notStrictEqual(
      preflightFingerprint(preflight, account, first),
      preflightFingerprint(preflight, account, second)
    );
  });

  test("structured outcomes and nested stages cannot be mutated", () => {
    const source = normalizeFreshSource(sourceRecord(), locator);
    const target = Object.freeze({ workspace: "workspace", repository: "target", name: "Target" });
    const outcome = createOutcome({
      source,
      target,
      preflight: createStage("succeeded", { evidence: "fresh_read" }),
      confirmation: createStage("succeeded", { evidence: "user_confirmation" }),
      copy: createStage("succeeded", { required: true, attempted: true }),
      sourceTag: createStage("not_required"),
      targetTag: createStage("not_required"),
      reconciliation: createStage("succeeded", { evidence: "fresh_read" }),
      overall: "succeeded",
      remoteState: "changed",
    });
    assert(Object.isFrozen(outcome));
    assert(Object.isFrozen(outcome.copy));
    assert.strictEqual(outcome.copy.status, "succeeded");
    assert.throws(() => createOutcome({
      ...outcome,
      confirmation: createStage("not_attempted"),
    }), PromotionContractError);
    assert.throws(() => createStage("maybe"), PromotionContractError);
    assert.throws(() => createStage("failed", { attempted: "true" }), PromotionContractError);
    assert.throws(() => createOutcome({ overall: true }), PromotionContractError);
    assert.throws(() => createOutcome({ overall: "succeeded" }), PromotionContractError);
    assert.throws(() => createOutcome({
      overall: "succeeded",
      copy: { status: "succeeded", required: "true", attempted: true },
      reconciliation: createStage("succeeded"),
      remoteState: "changed",
    }), PromotionContractError);
    assert.throws(() => createOutcome({
      overall: "partial",
      copy: createStage("succeeded", { required: true, attempted: true }),
      sourceTag: createStage("failed", { required: true }),
      targetTag: createStage("ambiguous", { required: true, attempted: true }),
      reconciliation: createStage("succeeded"),
      remoteState: "changed",
    }), PromotionContractError);
    assert.throws(() => createOutcome({
      overall: "ambiguous",
      reconciliation: createStage("ambiguous"),
      remoteState: "possibly_changed",
    }), PromotionContractError);
    const attemptedFailure = {
      source,
      target,
      preflight: createStage("succeeded", { evidence: "fresh_read" }),
      confirmation: createStage("succeeded", { evidence: "user_confirmation" }),
      copy: createStage("failed", { required: true, attempted: true }),
      overall: "failed",
      errorCode: "copy_failed",
      remoteState: "unchanged",
    };
    assert.throws(() => createOutcome({
      ...attemptedFailure,
      confirmation: createStage("not_attempted"),
    }), PromotionContractError);
    assert.throws(() => createOutcome({
      ...attemptedFailure,
      source: { ...source, copyable: false },
    }), PromotionContractError);
    assert.throws(() => createOutcome({
      ...attemptedFailure,
      target: { ...target, repository: source.repository },
    }), PromotionContractError);
    assert.throws(() => createOutcome({
      ...attemptedFailure,
      target: { ...target, workspace: "another-workspace" },
    }), PromotionContractError);
    assert.throws(() => createOutcome({
      ...attemptedFailure,
      copy: createStage("failed", { required: false, attempted: true }),
    }), PromotionContractError);
    assert.throws(() => createOutcome({
      overall: "failed",
      remoteState: "",
    }), PromotionContractError);
    assert.throws(
      () => createOutcome({ overall: "failed", errorCode: "raw API diagnostic" }),
      PromotionContractError
    );
  });
});

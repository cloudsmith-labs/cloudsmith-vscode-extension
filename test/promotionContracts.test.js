const assert = require("assert");
const {
  PromotionContractError,
  createOutcome,
  createSourceLocator,
  createStage,
  createTagPlan,
  normalizeFreshSource,
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
      sourceRecord({ namespace: "other" }),
      sourceRecord({ repository: "other" }),
      sourceRecord({ version: Number.NaN }),
      sourceRecord({ version: Number.POSITIVE_INFINITY }),
      sourceRecord({ version: {} }),
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

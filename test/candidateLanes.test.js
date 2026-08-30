const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  artifactIdentityFromCandidateBinding,
  createCandidateLaneReceipt,
  createCandidateLaneStore,
  executionContextFromCandidateBinding,
  validateCandidateLaneReceipt,
  validateCandidateLaneStore,
  validateInheritanceBundle,
} = require("../scripts/quality/candidate-lanes");
const { candidateBindingFromReceipt } = require("../scripts/quality/candidate-binding");
const { fingerprint } = require("../scripts/quality/evidence");
const {
  appendLaneReceipt,
  authenticatedObservation,
  captureAuthenticatedObservation,
  parseArguments: parseCandidateLaneArguments,
  priorReceiptsForCandidate,
} = require("../scripts/quality/aggregate-candidate-lanes");

const SOURCE = Object.freeze({
  sha: "1".repeat(40),
  fingerprint: "2".repeat(64),
});
const VSIX_SHA = "3".repeat(64);
const FIRST_CAPTURE = "2026-08-30T12:00:00.000Z";
const SECOND_CAPTURE = "2026-08-30T12:01:00.000Z";
const THIRD_CAPTURE = "2026-08-30T12:02:00.000Z";

function candidateBinding(overrides = {}) {
  return {
    developmentPath: false,
    extensionId: "Cloudsmith.cloudsmith-vsc",
    extensionVersion: "2.3.0",
    installedExtensionId: "Cloudsmith.cloudsmith-vsc",
    installedExtensionVersion: "2.3.0",
    profileMode: "ci",
    profileRootIdentity: "4".repeat(64),
    receiptFingerprint: "5".repeat(64),
    sourceFingerprint: SOURCE.fingerprint,
    sourceSha: SOURCE.sha,
    vscodeVersion: "1.134.0",
    vsixSha256: VSIX_SHA,
    ...overrides,
  };
}

function evidence(name = "lane") {
  return [{
    path: `internal_docs/quality/${name}.json`,
    sha256: crypto.createHash("sha256").update(name).digest("hex"),
  }];
}

function laneReceipt({
  lane = "signed-out-packaged-ui",
  attempt = 1,
  capturedAt = FIRST_CAPTURE,
  binding = candidateBinding(),
  previousReceiptFingerprint = null,
  status = "passed",
  reasonCode = null,
} = {}) {
  return createCandidateLaneReceipt({
    lane,
    attempt,
    capturedAt,
    candidateBinding: binding,
    previousReceiptFingerprint,
    status,
    reasonCode,
    evidence: evidence(`${lane}-${attempt}`),
  });
}

function validateStore(store, artifactIdentity, heads = store.heads) {
  return validateCandidateLaneStore(store, {
    expectedArtifactIdentity: artifactIdentity,
    expectedHeads: heads,
    expectedFingerprint: store.fingerprint,
  });
}

suite("candidate lane evidence", () => {
  test("accepts only an ignored authenticated evidence input", () => {
    assert.deepStrictEqual(parseCandidateLaneArguments([
      "--authenticated-evidence",
      "internal_docs/quality/current-authenticated-continuity.json",
    ]), {
      authenticatedEvidence: "internal_docs/quality/current-authenticated-continuity.json",
    });
    assert.throws(
      () => parseCandidateLaneArguments(["--authenticated-evidence", ".quality/secret.txt"]),
      /Usage/u,
    );
  });

  test("rejects stale or candidate-crossed authenticated producer evidence", () => {
    const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "auth-lane-")));
    fs.mkdirSync(path.join(root, "internal_docs", "quality"), { recursive: true });
    const evidencePath = "internal_docs/quality/auth-detail.json";
    const evidenceBytes = Buffer.from("{\"status\":\"passed\"}\n");
    fs.writeFileSync(path.join(root, evidencePath), evidenceBytes);
    const observationPath = "internal_docs/quality/auth-observation.json";
    const value = {
      schemaVersion: 1,
      lane: "authenticated-local",
      status: "passed",
      capturedAt: FIRST_CAPTURE,
      candidateReceiptFingerprint: "5".repeat(64),
      reasonCode: null,
      evidence: [{
        path: evidencePath,
        sha256: crypto.createHash("sha256").update(evidenceBytes).digest("hex"),
      }],
    };
    fs.writeFileSync(path.join(root, observationPath), `${JSON.stringify(value, null, 2)}\n`);
    const candidate = { receiptFingerprint: "5".repeat(64), capturedAt: FIRST_CAPTURE };
    assert.strictEqual(authenticatedObservation(
      observationPath,
      candidate,
      root,
      Date.parse(SECOND_CAPTURE),
    ).status, "passed");
    assert.throws(() => authenticatedObservation(
      observationPath,
      candidate,
      root,
      Date.parse("2026-09-01T12:00:01.000Z"),
    ), /Authenticated lane observation is/u);
    value.candidateReceiptFingerprint = "6".repeat(64);
    fs.writeFileSync(path.join(root, observationPath), `${JSON.stringify(value, null, 2)}\n`);
    assert.throws(() => authenticatedObservation(
      observationPath,
      candidate,
      root,
      Date.parse(SECOND_CAPTURE),
    ), /Authenticated lane observation is/u);
  });

  test("binds authenticated observation semantics and receipt hash to one stable capture", () => {
    const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "auth-capture-")));
    fs.mkdirSync(path.join(root, "internal_docs", "quality"), { recursive: true });
    const evidencePath = "internal_docs/quality/auth-detail.json";
    const evidenceBytes = Buffer.from("{\"status\":\"passed\"}\n");
    fs.writeFileSync(path.join(root, evidencePath), evidenceBytes);
    const observationPath = "internal_docs/quality/auth-observation.json";
    const value = {
      schemaVersion: 1,
      lane: "authenticated-local",
      status: "passed",
      capturedAt: FIRST_CAPTURE,
      candidateReceiptFingerprint: "5".repeat(64),
      reasonCode: null,
      evidence: [{
        path: evidencePath,
        sha256: crypto.createHash("sha256").update(evidenceBytes).digest("hex"),
      }],
    };
    fs.writeFileSync(path.join(root, observationPath), `${JSON.stringify(value, null, 2)}\n`);
    const candidate = { receiptFingerprint: "5".repeat(64), capturedAt: FIRST_CAPTURE };
    const replacement = { ...value, status: "failed", reasonCode: "AUTH_FAILED" };
    assert.throws(() => captureAuthenticatedObservation(
      observationPath,
      candidate,
      root,
      Date.parse(SECOND_CAPTURE),
      { afterCapture(target) {
        const staged = `${target}.replacement`;
        fs.writeFileSync(staged, `${JSON.stringify(replacement, null, 2)}\n`);
        fs.renameSync(staged, target);
      } },
    ), /unsafe or changed/u);
  });
  test("separates immutable artifact identity from lane execution context", () => {
    const binding = candidateBinding();
    const identity = artifactIdentityFromCandidateBinding(binding);
    const context = executionContextFromCandidateBinding(binding);

    assert.deepStrictEqual(identity, {
      extensionId: binding.extensionId,
      extensionVersion: binding.extensionVersion,
      sourceFingerprint: binding.sourceFingerprint,
      sourceSha: binding.sourceSha,
      vsixSha256: binding.vsixSha256,
    });
    assert.strictEqual(Object.hasOwn(identity, "vscodeVersion"), false);
    assert.strictEqual(Object.hasOwn(identity, "receiptFingerprint"), false);
    assert.strictEqual(context.vscodeVersion, binding.vscodeVersion);
    assert.strictEqual(context.candidateReceiptFingerprint, binding.receiptFingerprint);
    assert.strictEqual(Object.hasOwn(context, "vsixSha256"), false);
  });

  test("keeps independent signed-out and authenticated lane receipts content-addressed", () => {
    const signedOut = laneReceipt();
    const authenticated = laneReceipt({
      lane: "authenticated-local",
      binding: candidateBinding({
        profileMode: "local",
        profileRootIdentity: "6".repeat(64),
        receiptFingerprint: "7".repeat(64),
        vscodeVersion: "1.133.0",
      }),
    });
    const identity = artifactIdentityFromCandidateBinding(candidateBinding());
    const store = createCandidateLaneStore([signedOut, authenticated], identity);
    const summary = validateStore(store, identity);

    assert.notStrictEqual(signedOut.fingerprint, authenticated.fingerprint);
    assert.deepStrictEqual(summary.lanes.map(lane => [lane.lane, lane.status]), [
      ["authenticated-local", "passed"],
      ["signed-out-packaged-ui", "passed"],
    ]);
    assert.strictEqual(Object.keys(store.receipts).length, 2);
    assert.strictEqual(store.heads["signed-out-packaged-ui"], signedOut.fingerprint);
    assert.strictEqual(store.heads["authenticated-local"], authenticated.fingerprint);
  });

  test("never resets an invalid same-candidate lane store", () => {
    const first = laneReceipt();
    const identity = first.artifactIdentity;
    const store = createCandidateLaneStore([first], identity);
    assert.strictEqual(priorReceiptsForCandidate(store, identity, store.fingerprint).length, 1);

    const differentIdentity = {
      ...identity,
      sourceFingerprint: "8".repeat(64),
      sourceSha: "9".repeat(40),
    };
    assert.deepStrictEqual(priorReceiptsForCandidate(
      store,
      differentIdentity,
      store.fingerprint,
    ), []);

    const tampered = JSON.parse(JSON.stringify(store));
    tampered.receipts[first.fingerprint].status = "failed";
    assert.throws(
      () => priorReceiptsForCandidate(tampered, identity, store.fingerprint),
      /Candidate lane (?:receipt|receipt store) is invalid/u,
    );
    assert.throws(
      () => priorReceiptsForCandidate(store, identity),
      /prior-store fingerprint anchor is required/u,
    );
  });

  test("rejects replay of a valid older same-candidate lane store", () => {
    const first = laneReceipt();
    const identity = first.artifactIdentity;
    const oldStore = createCandidateLaneStore([first], identity);
    const failure = laneReceipt({
      attempt: 2,
      capturedAt: SECOND_CAPTURE,
      previousReceiptFingerprint: first.fingerprint,
      status: "failed",
      reasonCode: "VISIBLE_ACTION_FAILED",
    });
    const currentStore = createCandidateLaneStore([first, failure], identity);

    assert.throws(
      () => priorReceiptsForCandidate(oldStore, identity, currentStore.fingerprint),
      /Candidate lane receipt store is invalid/u,
    );
    assert.strictEqual(priorReceiptsForCandidate(
      currentStore,
      identity,
      currentStore.fingerprint,
    ).length, 2);
  });

  test("uses the latest authoritative same-lane attempt for pass then fail", () => {
    const first = laneReceipt();
    const second = laneReceipt({
      attempt: 2,
      capturedAt: SECOND_CAPTURE,
      previousReceiptFingerprint: first.fingerprint,
      status: "failed",
      reasonCode: "VISIBLE_ACTION_FAILED",
    });
    const identity = first.artifactIdentity;
    const store = createCandidateLaneStore([first, second], identity);
    const summary = validateStore(store, identity);

    assert.strictEqual(summary.lanes[0].attempt, 2);
    assert.strictEqual(summary.lanes[0].status, "failed");
    assert.strictEqual(summary.lanes[0].reasonCode, "VISIBLE_ACTION_FAILED");
    assert.strictEqual(summary.lanes[0].receiptFingerprint, second.fingerprint);
  });

  test("the producer appends pass, failure, and clean rerun without resetting lane history", () => {
    const receipts = [];
    const binding = candidateBinding();
    const first = appendLaneReceipt(receipts, {
      lane: "signed-out-packaged-ui",
      capturedAt: FIRST_CAPTURE,
      candidateBinding: binding,
      status: "passed",
      reasonCode: null,
      evidence: evidence("producer-pass"),
    });
    const failed = appendLaneReceipt(receipts, {
      lane: "signed-out-packaged-ui",
      capturedAt: SECOND_CAPTURE,
      candidateBinding: binding,
      status: "failed",
      reasonCode: "VISIBLE_ACTION_FAILED",
      evidence: evidence("producer-fail"),
    });
    const clean = appendLaneReceipt(receipts, {
      lane: "signed-out-packaged-ui",
      capturedAt: THIRD_CAPTURE,
      candidateBinding: binding,
      status: "passed",
      reasonCode: null,
      evidence: evidence("producer-clean"),
    });
    assert.deepStrictEqual(receipts.map(receipt => receipt.attempt), [1, 2, 3]);
    assert.strictEqual(failed.previousReceiptFingerprint, first.fingerprint);
    assert.strictEqual(clean.previousReceiptFingerprint, failed.fingerprint);
    const store = createCandidateLaneStore(receipts, first.artifactIdentity);
    assert.strictEqual(validateStore(store, first.artifactIdentity).lanes[0].status, "passed");
  });

  test("allows a clean rerun to supersede an earlier same-lane failure", () => {
    const first = laneReceipt({ status: "failed", reasonCode: "TRANSIENT_FAILURE" });
    const second = laneReceipt({
      attempt: 2,
      capturedAt: SECOND_CAPTURE,
      previousReceiptFingerprint: first.fingerprint,
    });
    const third = laneReceipt({
      attempt: 3,
      capturedAt: THIRD_CAPTURE,
      previousReceiptFingerprint: second.fingerprint,
    });
    const store = createCandidateLaneStore([first, second, third], first.artifactIdentity);
    const summary = validateStore(store, first.artifactIdentity);

    assert.strictEqual(summary.lanes[0].attempt, 3);
    assert.strictEqual(summary.lanes[0].status, "passed");
    assert.strictEqual(summary.lanes[0].receiptFingerprint, third.fingerprint);
  });

  test("rejects different source SHA, fingerprint, VSIX bytes, and same-version different bytes", () => {
    const expected = artifactIdentityFromCandidateBinding(candidateBinding());
    for (const overrides of [
      { sourceSha: "8".repeat(40) },
      { sourceFingerprint: "9".repeat(64) },
      { vsixSha256: "a".repeat(64) },
    ]) {
      const receipt = laneReceipt({ binding: candidateBinding(overrides) });
      assert.throws(
        () => createCandidateLaneStore([receipt], expected),
        /artifact identity|stale|tampered/u,
      );
    }
    const sameVersionDifferentBytes = laneReceipt({
      binding: candidateBinding({ vsixSha256: "b".repeat(64) }),
    });
    assert.strictEqual(
      sameVersionDifferentBytes.artifactIdentity.extensionVersion,
      expected.extensionVersion,
    );
    assert.throws(
      () => createCandidateLaneStore([sameVersionDifferentBytes], expected),
      /artifact identity|stale|tampered/u,
    );
  });

  test("rejects replay, forks, stale heads, and tampered receipt content", () => {
    const first = laneReceipt();
    const second = laneReceipt({
      attempt: 2,
      capturedAt: SECOND_CAPTURE,
      previousReceiptFingerprint: first.fingerprint,
    });
    const identity = first.artifactIdentity;
    assert.throws(
      () => createCandidateLaneStore([first, first], identity),
      /replay or duplicate/u,
    );
    assert.throws(
      () => createCandidateLaneStore([
        first,
        laneReceipt({
          attempt: 2,
          capturedAt: SECOND_CAPTURE,
          previousReceiptFingerprint: "c".repeat(64),
        }),
      ], identity),
      /incomplete, forked, or replayed/u,
    );

    const oldStore = createCandidateLaneStore([first], identity);
    assert.throws(
      () => validateCandidateLaneStore(oldStore, {
        expectedArtifactIdentity: identity,
        expectedHeads: { "signed-out-packaged-ui": second.fingerprint },
        expectedFingerprint: oldStore.fingerprint,
      }),
      /stale, or tampered/u,
    );

    const tampered = JSON.parse(JSON.stringify(first));
    tampered.result.status = "failed";
    tampered.result.reasonCode = "REPLAYED_RESULT";
    assert.throws(
      () => validateCandidateLaneReceipt(tampered, {
        expectedArtifactIdentity: identity,
        expectedFingerprint: first.fingerprint,
      }),
      /stale, or tampered/u,
    );
    const resealed = JSON.parse(JSON.stringify(tampered));
    delete resealed.fingerprint;
    resealed.fingerprint = fingerprint(resealed);
    assert.throws(
      () => validateCandidateLaneReceipt(resealed, {
        expectedArtifactIdentity: identity,
        expectedFingerprint: first.fingerprint,
      }),
      /stale, or tampered/u,
    );
  });
});

suite("candidate inheritance bundle", () => {
  test("requires and validates exact original receipt, artifact, attestation row, evidence, policy, and review", () => {
    const fixture = inheritanceFixture();
    const result = validateInheritanceBundle(
      fixture.bundle,
      fixture.content,
      fixture.options,
    );

    assert.strictEqual(result.workflowId, "WF-AUTH-STATE");
    assert.strictEqual(result.layer, "live-protocol");
    assert.strictEqual(result.reviewerId, "independent-reviewer");
    assert.deepStrictEqual(result.historicalArtifactIdentity, fixture.historicalIdentity);
    assert.deepStrictEqual(result.currentArtifactIdentity, fixture.currentIdentity);
  });

  test("fails closed when any inheritance authority byte source is missing", () => {
    const fixture = inheritanceFixture();
    for (const pathName of fixture.content.keys()) {
      const incomplete = new Map(fixture.content);
      incomplete.delete(pathName);
      assert.throws(
        () => validateInheritanceBundle(fixture.bundle, incomplete, fixture.options),
        /incomplete, stale, or mismatched/u,
        pathName,
      );
    }
  });

  test("rejects mismatched artifact bytes, tampered original receipt, row, policy, and review", () => {
    const fixture = inheritanceFixture();
    for (const [pathName, replacement] of [
      [fixture.paths.artifact, Buffer.from("same-version-different-bytes")],
      [fixture.paths.receipt, Buffer.from("{}")],
      [fixture.paths.attestation, Buffer.from("{}")],
      [fixture.paths.evidence, Buffer.from("changed evidence")],
      [fixture.paths.policy, Buffer.from("changed policy")],
      [fixture.paths.review, Buffer.from("{}")],
    ]) {
      const tampered = new Map(fixture.content);
      tampered.set(pathName, replacement);
      assert.throws(
        () => validateInheritanceBundle(fixture.bundle, tampered, fixture.options),
        /incomplete, stale, or mismatched/u,
        pathName,
      );
    }
  });

  test("rejects a fully resealed non-PASS historical row and non-independent review", () => {
    const failedRowFixture = inheritanceFixture({ rowStatus: "FAIL" });
    assert.throws(
      () => validateInheritanceBundle(
        failedRowFixture.bundle,
        failedRowFixture.content,
        failedRowFixture.options,
      ),
      /incomplete, stale, or mismatched/u,
    );

    const selfReviewFixture = inheritanceFixture({ reviewerId: "qualification-operator" });
    assert.throws(
      () => validateInheritanceBundle(
        selfReviewFixture.bundle,
        selfReviewFixture.content,
        selfReviewFixture.options,
      ),
      /incomplete, stale, or mismatched/u,
    );
  });
});

function inheritanceFixture(options = {}) {
  const artifactBytes = Buffer.from("historical candidate bytes");
  const artifactSha = sha256(artifactBytes);
  const receiptBase = {
    schemaVersion: 3,
    status: "passed",
    capturedAt: FIRST_CAPTURE,
    source: SOURCE,
    repository: {
      branch: "test/release-quality-harness",
      dirty: false,
      status: "clean",
    },
    toolchain: {
      nodeVersion: "v22.23.2",
      npmVersion: "10.9.8",
      npmInstallationSha256: "d".repeat(64),
      platform: process.platform,
    },
    extension: {
      id: "Cloudsmith.cloudsmith-vsc",
      publisher: "Cloudsmith",
      name: "cloudsmith-vsc",
      version: "2.3.0",
    },
    vscode: {
      version: "1.134.0",
      executable: path.resolve(".quality/inheritance/code"),
      cli: path.resolve(".quality/inheritance/cli"),
    },
    profile: {
      mode: "ci",
      persistent: false,
      root: path.resolve(".quality/inheritance/profile"),
      testResourcesDir: path.resolve(".quality/inheritance/profile"),
      userDataDir: path.resolve(".quality/inheritance/profile/settings"),
      extensionsDir: path.resolve(".quality/inheritance/profile/extensions"),
    },
    artifact: {
      vsixPath: "out/development/cloudsmith-vsc-2.3.0.vsix",
      absoluteVsixPath: path.resolve("out/development/cloudsmith-vsc-2.3.0.vsix"),
      sha256: artifactSha,
      archiveBytes: artifactBytes.length,
      entryCount: 1,
      sourceSha: SOURCE.sha,
      sourceFingerprint: SOURCE.fingerprint,
    },
    installation: {
      status: "passed",
      id: "Cloudsmith.cloudsmith-vsc",
      version: "2.3.0",
    },
    launch: { status: "not-requested", developmentPath: false },
  };
  const receipt = { ...receiptBase, fingerprint: fingerprint(receiptBase) };
  const historicalBinding = candidateBindingFromReceipt(receipt);
  const historicalIdentity = artifactIdentityFromCandidateBinding(historicalBinding);
  const currentIdentity = artifactIdentityFromCandidateBinding(candidateBinding({
    sourceSha: "e".repeat(40),
    sourceFingerprint: "f".repeat(64),
    vsixSha256: "0".repeat(64),
  }));
  const paths = {
    receipt: ".quality/inheritance/historical-candidate.json",
    artifact: ".quality/inheritance/historical-candidate.vsix",
    attestation: "internal_docs/quality/historical-attestation.json",
    evidence: "internal_docs/quality/historical-evidence.md",
    policy: ".quality/inheritance/readiness-policy.json",
    review: "internal_docs/quality/inheritance-review.json",
  };
  const content = new Map();
  const put = (pathName, bytes) => {
    const value = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes, "utf8");
    content.set(pathName, value);
    return { path: pathName, sha256: sha256(value) };
  };
  const receiptReference = put(paths.receipt, JSON.stringify(receipt));
  const artifactReference = put(paths.artifact, artifactBytes);
  const evidenceReference = put(paths.evidence, "authoritative historical evidence\n");
  const row = {
    id: "WF-AUTH-STATE",
    status: options.rowStatus || "PASS",
    authoritativeOutcomeObserved: true,
    candidateReceiptFingerprint: historicalBinding.receiptFingerprint,
    evidence: [{ ...evidenceReference, capturedAt: FIRST_CAPTURE }],
    candidateProvenance: "verified",
    outcomeDisposition: options.rowStatus === "FAIL" ? "failed" : "complete",
  };
  const attestation = {
    schemaVersion: 6,
    source: SOURCE,
    candidate: historicalBinding,
    workflowResults: [row],
  };
  const attestationReference = put(paths.attestation, JSON.stringify(attestation));
  const policyReference = put(paths.policy, JSON.stringify({
    schemaVersion: 1,
    readinessTarget: "team-test",
    workflowId: "WF-AUTH-STATE",
    requiredLayers: ["live-protocol"],
  }));
  const decision = {
    workflowId: "WF-AUTH-STATE",
    layer: "live-protocol",
    operatorId: "qualification-operator",
    historicalArtifactIdentity: historicalIdentity,
    currentArtifactIdentity: currentIdentity,
    sourceReceipt: receiptReference,
    sourceArtifact: artifactReference,
    sourceAttestation: attestationReference,
    rowFingerprint: fingerprint(row),
    evidence: [evidenceReference],
    policy: policyReference,
    policyFingerprint: policyReference.sha256,
  };
  const review = {
    schemaVersion: 1,
    status: "approved",
    operatorId: decision.operatorId,
    reviewerId: options.reviewerId || "independent-reviewer",
    reviewedAt: THIRD_CAPTURE,
    decisionFingerprint: fingerprint(decision),
  };
  const reviewReference = put(paths.review, JSON.stringify(review));
  const bundleBase = { schemaVersion: 1, decision, review: reviewReference };
  const bundle = { ...bundleBase, fingerprint: fingerprint(bundleBase) };
  return {
    bundle,
    content,
    currentIdentity,
    historicalIdentity,
    paths,
    options: {
      expectedHistoricalArtifactIdentity: historicalIdentity,
      expectedCurrentArtifactIdentity: currentIdentity,
      expectedPolicyFingerprint: policyReference.sha256,
      expectedFingerprint: bundle.fingerprint,
    },
  };
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

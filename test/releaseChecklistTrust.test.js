// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  attestationReviewDigest,
  evaluateLiveQualification,
  runChecklist,
} = require("../scripts/quality/release-checklist");

const SOURCE = Object.freeze({
  sha: "1".repeat(40),
  fingerprint: "2".repeat(64),
});
const NOW = new Date(Math.floor(Date.now() / 1000) * 1000);
const timestampBeforeNow = milliseconds => new Date(NOW.getTime() - milliseconds).toISOString();
const CAPTURED_AT = timestampBeforeNow(3 * 60 * 1000);
const COMPLETED_AT = timestampBeforeNow(2 * 60 * 1000);
const REVIEWED_AT = timestampBeforeNow(60 * 1000);
const WORKFLOWS = Object.freeze({
  workflows: Object.freeze([Object.freeze({
    id: "critical-live-workflow",
    requiredLayers: Object.freeze(["live-protocol"]),
  })]),
});

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function writeEvidence(root, filename, content, capturedAt) {
  const relativePath = `internal_docs/quality/${filename}`;
  const target = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
  return {
    path: relativePath,
    sha256: crypto.createHash("sha256").update(content).digest("hex"),
    capturedAt,
  };
}

function createFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "release-checklist-trust-"));
  fs.mkdirSync(path.join(root, "quality"), { recursive: true });
  for (const filename of [
    "critical-workflows.json",
    "defect-taxonomy.json",
    "finding.schema.json",
  ]) {
    fs.copyFileSync(
      path.join(__dirname, "..", "quality", filename),
      path.join(root, "quality", filename)
    );
  }
  const qualificationEvidence = writeEvidence(
    root,
    "qualification.md",
    "sanitized authoritative outcome\n",
    CAPTURED_AT,
  );
  const reviewEvidence = writeEvidence(
    root,
    "independent-review.md",
    "independent review of the exact candidate\n",
    REVIEWED_AT,
  );
  const findingsEvidence = writeEvidence(
    root,
    "findings.jsonl",
    `${JSON.stringify({
      id: "QH-900",
      severity: "P3",
      status: "deferred",
      surface: "fixture",
      workflowContract: "WF-AUTH-STATE",
      failureClasses: ["false-green-test"],
      customerImpact: "Fixture-only non-blocking impact.",
      reproductionConfidence: "strong-static-evidence",
      authoritativeExpectedOutcome: "The fixture ledger validates strictly.",
      observedOutcome: "No live customer defect is claimed by this fixture.",
      firstKnownBadSha: null,
      evidence: [{ kind: "protocol", location: "fixture", summary: "Synthetic fixture." }],
      rootCauseStatus: "suspected",
      testLayerThatShouldHaveCaughtIt: "live-protocol",
      whyItEscaped: "This is a schema-valid trust fixture.",
      regressionTest: null,
      mutationProof: { status: "not-started", summary: "Not applicable to the fixture." },
      fixedSha: null,
      liveVerification: { status: "blocked", summary: "Fixture only." },
      releaseBlocking: false,
    })}\n`,
    CAPTURED_AT,
  );
  const document = {
    schemaVersion: 3,
    source: SOURCE,
    status: "passed",
    authenticatedAcceptance: true,
    checklistConfirmed: true,
    operatorId: "qualification-operator",
    completedAt: COMPLETED_AT,
    verdict: "TEAM-TEST READY WITH KNOWN NON-BLOCKING RISKS",
    evidence: [qualificationEvidence, findingsEvidence],
    findingsFingerprint: findingsEvidence.sha256,
    openReleaseBlockerCount: 0,
    workflowResults: [{
      id: "critical-live-workflow",
      status: "passed",
      authoritativeOutcomeObserved: true,
      evidence: [qualificationEvidence],
    }],
    visibleEnabledActions: {
      status: "passed",
      silentNoOpCount: 0,
      evidence: [qualificationEvidence],
    },
  };
  document.independentReview = {
    status: "passed",
    reviewerId: "independent-reviewer",
    source: SOURCE,
    reviewedAt: REVIEWED_AT,
    attestationSha256: attestationReviewDigest(document),
    evidence: [reviewEvidence],
  };
  return { document, qualificationEvidence, reviewEvidence, root };
}

function evaluate(fixture, document = fixture.document) {
  return evaluateLiveQualification({
    attestationFingerprint: crypto.createHash("sha256")
      .update(JSON.stringify(document))
      .digest("hex"),
    document,
    now: NOW,
    root: fixture.root,
    source: SOURCE,
    workflows: WORKFLOWS,
  });
}

suite("Release checklist trust receipts", () => {
  let fixture;

  setup(() => {
    fixture = createFixture();
  });

  teardown(() => {
    fs.rmSync(fixture.root, { force: true, recursive: true });
  });

  test("accepts a source-bound receipt with exact hashed evidence", () => {
    const result = evaluate(fixture);

    assert.strictEqual(result.status, "passed");
    assert.strictEqual(result.authenticatedAcceptance, "recorded");
    assert.deepStrictEqual(result.missingWorkflowIds, []);
    assert.match(result.attestationFingerprint, /^[a-f0-9]{64}$/u);
    assert.deepStrictEqual(
      result.evidenceManifest.map(entry => entry.path),
      [
        "internal_docs/quality/findings.jsonl",
        "internal_docs/quality/independent-review.md",
        "internal_docs/quality/qualification.md",
      ]
    );
  });

  test("carries the exact attestation bytes and evidence hashes into the derived status", () => {
    const inputPath = "internal_docs/quality/live-qualification.json";
    const bytes = Buffer.from(`${JSON.stringify(fixture.document, null, 2)}\n`);
    fs.writeFileSync(path.join(fixture.root, inputPath), bytes);

    const result = runChecklist({
      inputPath,
      now: NOW,
      outputPath: ".quality/live-status.json",
      root: fixture.root,
      source: SOURCE,
      workflows: WORKFLOWS,
    });

    assert.strictEqual(result.status, "passed");
    assert.strictEqual(
      result.attestationFingerprint,
      crypto.createHash("sha256").update(bytes).digest("hex")
    );
    assert.deepStrictEqual(
      result.evidenceManifest.find(entry => entry.path === fixture.qualificationEvidence.path),
      {
        path: fixture.qualificationEvidence.path,
        sha256: fixture.qualificationEvidence.sha256,
      }
    );
  });

  test("rejects a disk attestation containing malformed UTF-8", () => {
    const inputPath = "internal_docs/quality/live-qualification.json";
    const prefix = Buffer.from('{"schemaVersion":3,"operatorId":"');
    const suffix = Buffer.from('"}\n');
    fs.writeFileSync(
      path.join(fixture.root, inputPath),
      Buffer.concat([prefix, Buffer.from([0xc3, 0x28]), suffix])
    );

    assert.throws(() => runChecklist({
      inputPath,
      now: NOW,
      outputPath: ".quality/live-status.json",
      root: fixture.root,
      source: SOURCE,
      workflows: WORKFLOWS,
    }), /Live qualification input is not valid UTF-8/u);
  });

  test("rejects findings-ledger removal, blocker drift, and invalid bytes", () => {
    const findingsPath = path.join(fixture.root, "internal_docs/quality/findings.jsonl");
    fs.writeFileSync(
      findingsPath,
      `${JSON.stringify({ status: "blocked", releaseBlocking: true })}\n`
    );
    const blocker = evaluate(fixture);
    assert.strictEqual(blocker.status, "failed");
    assert.ok(blocker.errors.some(error => /findings ledger bytes|blocker count/u.test(error)));

    fs.writeFileSync(findingsPath, "");
    const removed = evaluate(fixture);
    assert.strictEqual(removed.status, "failed");
    assert.ok(removed.errors.some(error => /findings ledger is empty/u.test(error)));

    fs.writeFileSync(findingsPath, "{not-json}\n");
    const invalid = evaluate(fixture);
    assert.strictEqual(invalid.status, "failed");
    assert.ok(invalid.errors.some(error => /findings ledger is invalid/u.test(error)));

    fs.writeFileSync(findingsPath, Buffer.from([0xc3, 0x28]));
    const malformedUtf8 = evaluate(fixture);
    assert.strictEqual(malformedUtf8.status, "failed");
    assert.ok(malformedUtf8.errors.some(error => /not valid UTF-8/u.test(error)));
  });

  test("rejects a schema-invalid ledger even when the attestation binds its exact bytes", () => {
    const content = `${JSON.stringify({
      id: "QH-901",
      severity: "P0",
      status: "fixed",
      releaseBlocking: false,
    })}\n`;
    const sha256 = crypto.createHash("sha256").update(content).digest("hex");
    fs.writeFileSync(
      path.join(fixture.root, "internal_docs/quality/findings.jsonl"),
      content
    );
    const document = clone(fixture.document);
    document.evidence = document.evidence.map(reference => (
      reference.path === "internal_docs/quality/findings.jsonl"
        ? { ...reference, sha256 }
        : reference
    ));
    document.findingsFingerprint = sha256;
    document.independentReview.attestationSha256 = attestationReviewDigest(document);

    const result = evaluate(fixture, document);

    assert.strictEqual(result.status, "failed");
    assert.ok(result.errors.some(error => /findings ledger is invalid/u.test(error)));
    assert.strictEqual(result.openReleaseBlockerCount, null);
  });

  test("rejects forged hashes and unsafe or missing evidence paths", () => {
    const wrongHash = clone(fixture.document);
    wrongHash.evidence[0].sha256 = "f".repeat(64);
    wrongHash.independentReview.attestationSha256 = attestationReviewDigest(wrongHash);
    const wrongHashResult = evaluate(fixture, wrongHash);
    assert.ok(wrongHashResult.errors.some(error => /SHA-256 does not match/.test(error)));
    assert.strictEqual(wrongHashResult.status, "failed");
    assert.deepStrictEqual(wrongHashResult.passedWorkflowIds, []);
    assert.deepStrictEqual(
      wrongHashResult.missingWorkflowIds,
      wrongHashResult.requiredWorkflowIds
    );

    const traversal = clone(fixture.document);
    traversal.evidence[0] = {
      ...traversal.evidence[0],
      path: "internal_docs/quality/../forged.md",
    };
    traversal.independentReview.attestationSha256 = attestationReviewDigest(traversal);
    const traversalResult = evaluate(fixture, traversal);
    assert.ok(traversalResult.errors.some(error => /normalized ignored evidence path/.test(error)));

    const missing = clone(fixture.document);
    missing.evidence[0] = {
      ...missing.evidence[0],
      path: "internal_docs/quality/missing.md",
    };
    missing.independentReview.attestationSha256 = attestationReviewDigest(missing);
    const missingResult = evaluate(fixture, missing);
    assert.ok(missingResult.errors.some(error => /missing or unreadable/.test(error)));
  });

  test("rejects evidence reached through a symbolic link", function () {
    if (process.platform === "win32") this.skip();
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "release-checklist-outside-"));
    try {
      const content = "outside evidence must not be followed\n";
      const outsidePath = path.join(outside, "outside.md");
      fs.writeFileSync(outsidePath, content);
      const relativePath = "internal_docs/quality/linked.md";
      fs.symlinkSync(outsidePath, path.join(fixture.root, relativePath));
      const symlinked = clone(fixture.document);
      symlinked.evidence[0] = {
        path: relativePath,
        sha256: crypto.createHash("sha256").update(content).digest("hex"),
        capturedAt: CAPTURED_AT,
      };
      symlinked.independentReview.attestationSha256 = attestationReviewDigest(symlinked);

      const result = evaluate(fixture, symlinked);

      assert.ok(result.errors.some(error => /crosses a symbolic link/.test(error)));
    } finally {
      fs.rmSync(outside, { force: true, recursive: true });
    }
  });

  test("rejects a qualification input redirected through a symbolic link", function () {
    if (process.platform === "win32") this.skip();
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "release-input-outside-"));
    try {
      const outsidePath = path.join(outside, "attestation.json");
      fs.writeFileSync(outsidePath, JSON.stringify(fixture.document));
      const inputPath = "internal_docs/quality/live-qualification.json";
      fs.symlinkSync(outsidePath, path.join(fixture.root, inputPath));

      assert.throws(
        () => runChecklist({
          inputPath,
          now: NOW,
          outputPath: ".quality/live-status.json",
          root: fixture.root,
          source: SOURCE,
          workflows: WORKFLOWS,
        }),
        /input path crosses a symbolic link|Repository file must be a real regular file/,
      );
    } finally {
      fs.rmSync(outside, { force: true, recursive: true });
    }
  });

  test("rejects future, noncanonical, and misordered receipt timestamps", () => {
    const future = clone(fixture.document);
    future.completedAt = new Date(NOW.getTime() + 60 * 1000).toISOString();
    future.independentReview.attestationSha256 = attestationReviewDigest(future);
    const futureResult = evaluate(fixture, future);
    assert.ok(futureResult.errors.some(error => /completion timestamp is in the future/.test(error)));

    const noncanonical = clone(fixture.document);
    noncanonical.evidence[0].capturedAt = CAPTURED_AT.replace(".000Z", "Z");
    noncanonical.independentReview.attestationSha256 = attestationReviewDigest(noncanonical);
    const noncanonicalResult = evaluate(fixture, noncanonical);
    assert.ok(noncanonicalResult.errors.some(error => /canonical UTC ISO-8601/.test(error)));

    const earlyReview = clone(fixture.document);
    earlyReview.independentReview.reviewedAt = timestampBeforeNow(4 * 60 * 1000);
    const earlyReviewResult = evaluate(fixture, earlyReview);
    assert.ok(earlyReviewResult.errors.some(error => /review timestamp predates/.test(error)));

    const stale = clone(fixture.document);
    stale.completedAt = timestampBeforeNow(49 * 60 * 60 * 1000);
    stale.independentReview.reviewedAt = timestampBeforeNow(49 * 60 * 60 * 1000 - 60 * 1000);
    stale.independentReview.attestationSha256 = attestationReviewDigest(stale);
    const staleResult = evaluate(fixture, stale);
    assert.ok(staleResult.errors.some(error => /older than the 24-hour release window/.test(error)));
  });

  test("rejects self-review, source drift, payload drift, and reused review evidence", () => {
    const selfReview = clone(fixture.document);
    selfReview.independentReview.reviewerId = selfReview.operatorId;
    const selfReviewResult = evaluate(fixture, selfReview);
    assert.ok(selfReviewResult.errors.some(error => /reviewer must differ/.test(error)));

    const staleReview = clone(fixture.document);
    staleReview.independentReview.source.sha = "3".repeat(40);
    const staleReviewResult = evaluate(fixture, staleReview);
    assert.ok(staleReviewResult.errors.some(error => /does not bind the current candidate source/.test(error)));

    const payloadDrift = clone(fixture.document);
    payloadDrift.verdict = "TEAM-TEST READY";
    const payloadDriftResult = evaluate(fixture, payloadDrift);
    assert.ok(payloadDriftResult.errors.some(error => /exact qualification attestation/.test(error)));
    assert.ok(payloadDriftResult.errors.some(error => /open non-blocking findings/.test(error)));

    const reusedEvidence = clone(fixture.document);
    reusedEvidence.independentReview.evidence = [fixture.qualificationEvidence];
    const reusedEvidenceResult = evaluate(fixture, reusedEvidence);
    assert.ok(reusedEvidenceResult.errors.some(error => /separate review evidence/.test(error)));
  });
});

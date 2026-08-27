// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const crypto = require("crypto");
const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { fingerprint } = require("../scripts/quality/evidence");
const {
  AUTHENTICATED_CANDIDATE_ARTIFACT,
  AUTHENTICATED_CANDIDATE_RECEIPT,
  LIVE_CANDIDATE_ARTIFACT,
  LIVE_CANDIDATE_RECEIPT,
  candidateBindingFromReceipt,
} = require("../scripts/quality/candidate-binding");
const {
  attestationReviewDigest,
  evaluateLiveQualification,
  requiredLiveWorkflowIds,
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
    id: "WF-AUTH-STATE",
    requiredLayers: Object.freeze(["live-protocol"]),
    liveFixture: Object.freeze({ required: true }),
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
  const root = fs.realpathSync(fs.mkdtempSync(path.join(
    os.tmpdir(),
    "release-checklist-trust-",
  )));
  assert.strictEqual(spawnSync("git", ["init", "-b", "test/release-quality-harness"], {
    cwd: root,
    stdio: "ignore",
  }).status, 0);
  fs.writeFileSync(path.join(root, ".gitignore"), ".quality/\ninternal_docs/\n");
  fs.mkdirSync(path.join(root, "quality"), { recursive: true });
  fs.writeFileSync(path.join(root, "package.json"), `${JSON.stringify({
    publisher: "Cloudsmith",
    name: "cloudsmith-vsc",
    version: "2.3.0",
  })}\n`);
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
      domain: "product",
      status: "deferred",
      deterministicStatus: "failing",
      liveStatus: "blocked",
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
      liveVerification: { summary: "Fixture only." },
      releaseBlocking: false,
    })}\n`,
    CAPTURED_AT,
  );
  const candidateBytes = Buffer.from("x");
  const qualificationHomeDirectory = path.join(root, "qualification-home");
  fs.mkdirSync(qualificationHomeDirectory);
  const localProfileRoot = path.join(
    qualificationHomeDirectory,
    ".cloudsmith-vscode-qualification",
  );
  const repositoryArtifactPath = path.join(
    root,
    "out",
    "development",
    "cloudsmith-vsc-2.3.0.vsix",
  );
  fs.mkdirSync(path.dirname(repositoryArtifactPath), { recursive: true });
  fs.writeFileSync(repositoryArtifactPath, candidateBytes);
  const candidateBase = {
    schemaVersion: 2,
    status: "passed",
    capturedAt: CAPTURED_AT,
    source: SOURCE,
    repository: {
      branch: "test/release-quality-harness",
      dirty: true,
      status: "dirty",
    },
    extension: {
      id: "Cloudsmith.cloudsmith-vsc",
      publisher: "Cloudsmith",
      name: "cloudsmith-vsc",
      version: "2.3.0",
    },
    vscode: { version: "1.134.0", executable: "/bounded/code", cli: "/bounded/cli" },
    profile: {
      mode: "local",
      persistent: true,
      root: localProfileRoot,
      testResourcesDir: localProfileRoot,
      userDataDir: path.join(localProfileRoot, "user-data"),
      extensionsDir: path.join(localProfileRoot, "extensions"),
    },
    artifact: {
      vsixPath: "out/development/cloudsmith-vsc-2.3.0.vsix",
      absoluteVsixPath: repositoryArtifactPath,
      sha256: crypto.createHash("sha256").update(candidateBytes).digest("hex"),
      archiveBytes: candidateBytes.length,
      entryCount: 1,
      sourceSha: SOURCE.sha,
      sourceFingerprint: SOURCE.fingerprint,
    },
    installation: { status: "passed", id: "Cloudsmith.cloudsmith-vsc", version: "2.3.0" },
    launch: { status: "not-requested", developmentPath: false },
  };
  const candidateReceipt = { ...candidateBase, fingerprint: fingerprint(candidateBase) };
  const authenticatedCandidateBase = {
    ...candidateBase,
    profile: {
      mode: "ci",
      persistent: false,
      root: "/bounded/authenticated-ci-profile",
      testResourcesDir: "/bounded/authenticated-ci-profile",
      userDataDir: "/bounded/authenticated-ci-profile/settings",
      extensionsDir: "/bounded/authenticated-ci-profile/extensions",
    },
  };
  const authenticatedCandidateReceipt = {
    ...authenticatedCandidateBase,
    fingerprint: fingerprint(authenticatedCandidateBase),
  };
  const proofDirectory = path.join(root, ".quality", "qualification");
  fs.mkdirSync(proofDirectory, { recursive: true });
  const candidateArtifactPath = path.join(root, LIVE_CANDIDATE_ARTIFACT);
  fs.writeFileSync(candidateArtifactPath, candidateBytes);
  fs.writeFileSync(
    path.join(root, LIVE_CANDIDATE_RECEIPT),
    `${JSON.stringify(candidateReceipt, null, 2)}\n`
  );
  const authenticatedCandidateArtifactPath = path.join(
    root,
    AUTHENTICATED_CANDIDATE_ARTIFACT,
  );
  fs.writeFileSync(authenticatedCandidateArtifactPath, candidateBytes);
  fs.writeFileSync(
    path.join(root, AUTHENTICATED_CANDIDATE_RECEIPT),
    `${JSON.stringify(authenticatedCandidateReceipt, null, 2)}\n`,
  );
  const candidate = candidateBindingFromReceipt(candidateReceipt, {
    root,
    source: SOURCE,
    artifactPath: candidateArtifactPath,
    homeDirectory: qualificationHomeDirectory,
  });
  const authenticatedCandidate = candidateBindingFromReceipt(authenticatedCandidateReceipt, {
    root,
    source: SOURCE,
    artifactPath: authenticatedCandidateArtifactPath,
  });
  const authenticatedBase = {
    schemaVersion: 2,
    status: "passed",
    reasonCode: null,
    source: SOURCE,
    workspace: {
      expected: "dl-technology-consulting",
      observed: "dl-technology-consulting",
      surface: "production-connected-workspace",
    },
    candidate: authenticatedCandidate,
    credentialBoundary: {
      storageKey: "cloudsmith-vsc.authToken",
      transport: "creator-bound-0700-0600-handoff",
      valueRecorded: false,
      digestRecorded: false,
    },
    phases: {
      candidate: "prepared",
      handoff: "consumed-before-store-completion",
      seed: "passed",
      productionWorkspaceCheck: "passed",
      secretStorageCleanup: "passed",
      profileCleanup: "passed",
      outputBoundary: "passed",
    },
  };
  const authenticatedReceipt = {
    ...authenticatedBase,
    fingerprint: fingerprint(authenticatedBase),
  };
  fs.writeFileSync(
    path.join(proofDirectory, "authenticated-ci.json"),
    `${JSON.stringify(authenticatedReceipt, null, 2)}\n`
  );
  const authenticatedExposureBase = {
    schemaVersion: 1,
    status: "passed",
    sourceSha: SOURCE.sha,
    candidateReceiptFingerprint: authenticatedCandidateReceipt.fingerprint,
    scanner: {
      name: "gitleaks",
      version: "8.30.1",
      secretBearingFieldsPersisted: false,
    },
    credentialBoundary: {
      profileContentRead: false,
      secretStorageRead: false,
      keychainRead: false,
      credentialValueRecorded: false,
      credentialDigestRecorded: false,
    },
    findingCount: 0,
    components: [
      {
        id: "authenticated-generated-evidence",
        status: "scanned",
        fileCount: 2,
        findingCount: 0,
      },
      {
        id: `vsix:${authenticatedCandidateReceipt.artifact.vsixPath}`,
        status: "scanned",
        fileCount: 2,
        findingCount: 0,
      },
      {
        id: "authenticated-runtime-logs",
        status: "not-present",
        fileCount: 0,
        findingCount: 0,
      },
      {
        id: "profile-boundary-metadata-only",
        status: "scanned",
        fileCount: 4,
        findingCount: 0,
      },
    ],
  };
  const authenticatedExposureReceipt = {
    ...authenticatedExposureBase,
    fingerprint: fingerprint(authenticatedExposureBase),
  };
  const secretsDirectory = path.join(root, ".quality", "secrets");
  fs.mkdirSync(secretsDirectory, { recursive: true });
  fs.writeFileSync(
    path.join(secretsDirectory, "authenticated-ci.json"),
    `${JSON.stringify(authenticatedExposureReceipt, null, 2)}\n`,
  );
  const document = {
    schemaVersion: 5,
    source: SOURCE,
    candidate,
    status: "passed",
    summary: null,
    authenticatedAcceptance: true,
    checklistConfirmed: true,
    operatorId: "qualification-operator",
    completedAt: COMPLETED_AT,
    verdict: "TEAM-TEST READY WITH KNOWN NON-BLOCKING RISKS",
    evidence: [qualificationEvidence, findingsEvidence],
    findingsFingerprint: findingsEvidence.sha256,
    openReleaseBlockerCount: 0,
    workflowResults: [{
      id: "WF-AUTH-STATE",
      status: "PASS",
      authoritativeOutcomeObserved: true,
      candidateReceiptFingerprint: candidate.receiptFingerprint,
      evidence: [qualificationEvidence],
    }],
    visibleEnabledActions: {
      status: "passed",
      candidateReceiptFingerprint: candidate.receiptFingerprint,
      silentNoOpCount: 0,
      evidence: [qualificationEvidence],
    },
  };
  document.independentReview = {
    status: "passed",
    candidateReceiptFingerprint: candidate.receiptFingerprint,
    reviewerId: "independent-reviewer",
    source: SOURCE,
    reviewedAt: REVIEWED_AT,
    attestationSha256: attestationReviewDigest(document),
    evidence: [reviewEvidence],
  };
  return {
    authenticatedReceipt,
    authenticatedExposureReceipt,
    authenticatedCandidate,
    authenticatedCandidateArtifactPath,
    authenticatedCandidateReceipt,
    candidateArtifactPath,
    candidateReceipt,
    document,
    qualificationEvidence,
    qualificationHomeDirectory,
    reviewEvidence,
    root,
  };
}

function evaluate(fixture, document = fixture.document, overrides = {}) {
  return evaluateLiveQualification({
    attestationFingerprint: crypto.createHash("sha256")
      .update(JSON.stringify(document))
      .digest("hex"),
    document,
    now: NOW,
    root: fixture.root,
    source: SOURCE,
    workflows: WORKFLOWS,
    liveCandidateReceipt: fixture.candidateReceipt,
    liveCandidateArtifactPath: fixture.candidateArtifactPath,
    authenticatedReceipt: fixture.authenticatedReceipt,
    authenticatedExposureReceipt: fixture.authenticatedExposureReceipt,
    authenticatedCandidateReceipt: fixture.authenticatedCandidateReceipt,
    authenticatedCandidateArtifactPath: fixture.authenticatedCandidateArtifactPath,
    qualificationHomeDirectory: fixture.qualificationHomeDirectory,
    ...overrides,
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
    assert.deepStrictEqual(result.candidate, fixture.document.candidate);
    assert.strictEqual(fixture.document.candidate.profileMode, "local");
    assert.strictEqual(fixture.authenticatedCandidate.profileMode, "ci");
    assert.notStrictEqual(
      fixture.document.candidate.receiptFingerprint,
      fixture.authenticatedCandidate.receiptFingerprint,
    );
    assert.notStrictEqual(
      fixture.document.candidate.profileRootIdentity,
      fixture.authenticatedCandidate.profileRootIdentity,
    );
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

  test("rejects a local receipt outside the producer's canonical profile root", () => {
    const redirectedRoot = path.join(
      fixture.qualificationHomeDirectory,
      "other-qualification-profile",
    );
    const redirectedBase = {
      ...fixture.candidateReceipt,
      profile: {
        ...fixture.candidateReceipt.profile,
        root: redirectedRoot,
        testResourcesDir: redirectedRoot,
        userDataDir: path.join(redirectedRoot, "user-data"),
        extensionsDir: path.join(redirectedRoot, "extensions"),
      },
    };
    delete redirectedBase.fingerprint;
    const result = evaluate(fixture, fixture.document, {
      liveCandidateReceipt: {
        ...redirectedBase,
        fingerprint: fingerprint(redirectedBase),
      },
    });

    assert.strictEqual(result.status, "failed");
    assert.ok(result.errors.some(error => /local profile root is not canonical/u.test(error)));
  });

  test("rejects missing, crossed, and stale candidate proof for every live PASS", () => {
    const missing = clone(fixture.document);
    missing.candidate = null;
    missing.workflowResults[0].candidateReceiptFingerprint = null;
    missing.visibleEnabledActions.candidateReceiptFingerprint = null;
    missing.independentReview.candidateReceiptFingerprint = null;
    missing.independentReview.attestationSha256 = attestationReviewDigest(missing);
    const missingResult = evaluate(fixture, missing);
    assert.strictEqual(missingResult.status, "failed");
    assert.ok(missingResult.errors.some(error => /Every live PASS must bind/u.test(error)));

    const crossed = clone(fixture.document);
    crossed.workflowResults[0].candidateReceiptFingerprint = "f".repeat(64);
    crossed.independentReview.attestationSha256 = attestationReviewDigest(crossed);
    const crossedResult = evaluate(fixture, crossed);
    assert.strictEqual(crossedResult.status, "failed");
    assert.ok(crossedResult.errors.some(error => /does not bind the exact candidate receipt/u.test(error)));

    fs.writeFileSync(fixture.candidateArtifactPath, "stale bytes");
    const staleResult = evaluate(fixture);
    assert.strictEqual(staleResult.status, "failed");
    assert.ok(staleResult.errors.some(error => /VSIX proof is stale or mismatched/u.test(error)));
  });

  test("requires a passed authenticated verifier receipt for candidate-bound PASS rows", () => {
    const authenticationFailed = clone(fixture.authenticatedReceipt);
    authenticationFailed.status = "failed";
    authenticationFailed.reasonCode = "connected-workspace-mismatch";
    delete authenticationFailed.fingerprint;
    authenticationFailed.fingerprint = fingerprint(authenticationFailed);

    const result = evaluate(fixture, fixture.document, {
      authenticatedReceipt: authenticationFailed,
    });

    assert.strictEqual(result.status, "failed");
    assert.ok(result.errors.some(error => /not passed/u.test(error)));
    assert.strictEqual(result.authenticatedAcceptance, "not-recorded");
  });

  test("requires the exact passed authenticated exposure receipt for final PASS", () => {
    const missing = evaluate(fixture, fixture.document, {
      authenticatedExposureReceipt: null,
    });
    assert.strictEqual(missing.status, "failed");
    assert.strictEqual(missing.authenticatedAcceptance, "not-recorded");
    assert.ok(missing.errors.some(error => /exposure receipt is missing/u.test(error)));

    const crossed = clone(fixture.authenticatedExposureReceipt);
    crossed.components[1].id = "vsix:out/development/unbound-candidate.vsix";
    delete crossed.fingerprint;
    crossed.fingerprint = fingerprint(crossed);
    const mismatched = evaluate(fixture, fixture.document, {
      authenticatedExposureReceipt: crossed,
    });
    assert.strictEqual(mismatched.status, "failed");
    assert.ok(mismatched.errors.some(error => /exact value-blind components/u.test(error)));
  });

  test("rejects a valid authenticated-CI proof for a different VSIX artifact", () => {
    const crossedBytes = Buffer.from("y");
    const crossedReceipt = clone(fixture.authenticatedCandidateReceipt);
    crossedReceipt.artifact.vsixPath = "out/release/cloudsmith-vsc-2.3.0.vsix";
    crossedReceipt.artifact.absoluteVsixPath = path.join(
      fixture.root,
      crossedReceipt.artifact.vsixPath,
    );
    crossedReceipt.artifact.sha256 = crypto.createHash("sha256")
      .update(crossedBytes)
      .digest("hex");
    crossedReceipt.artifact.archiveBytes = crossedBytes.length;
    delete crossedReceipt.fingerprint;
    crossedReceipt.fingerprint = fingerprint(crossedReceipt);
    fs.mkdirSync(path.dirname(crossedReceipt.artifact.absoluteVsixPath), { recursive: true });
    fs.writeFileSync(crossedReceipt.artifact.absoluteVsixPath, crossedBytes);
    fs.writeFileSync(fixture.authenticatedCandidateArtifactPath, crossedBytes);
    const crossedCandidate = candidateBindingFromReceipt(crossedReceipt, {
      root: fixture.root,
      source: SOURCE,
      artifactPath: fixture.authenticatedCandidateArtifactPath,
    });
    const crossedAuthentication = clone(fixture.authenticatedReceipt);
    crossedAuthentication.candidate = crossedCandidate;
    delete crossedAuthentication.fingerprint;
    crossedAuthentication.fingerprint = fingerprint(crossedAuthentication);

    const result = evaluate(fixture, fixture.document, {
      authenticatedCandidateReceipt: crossedReceipt,
      authenticatedReceipt: crossedAuthentication,
    });

    assert.strictEqual(result.status, "failed");
    assert.ok(result.errors.some(error => /same immutable product artifact/u.test(error)));
  });

  test("rejects authenticated-CI candidate proof crossed from another source", () => {
    const crossedReceipt = clone(fixture.authenticatedCandidateReceipt);
    crossedReceipt.source = {
      sha: "a".repeat(40),
      fingerprint: "b".repeat(64),
    };
    crossedReceipt.artifact.sourceSha = crossedReceipt.source.sha;
    crossedReceipt.artifact.sourceFingerprint = crossedReceipt.source.fingerprint;
    delete crossedReceipt.fingerprint;
    crossedReceipt.fingerprint = fingerprint(crossedReceipt);

    const result = evaluate(fixture, fixture.document, {
      authenticatedCandidateReceipt: crossedReceipt,
    });

    assert.strictEqual(result.status, "failed");
    assert.ok(result.errors.some(error => /source is stale or mismatched/u.test(error)));
  });

  test("rejects a candidate captured after or more than 24 hours before completion", () => {
    for (const capturedAt of [
      timestampBeforeNow(60 * 1000),
      new Date(Date.parse(COMPLETED_AT) - (24 * 60 * 60 * 1000) - 1).toISOString(),
    ]) {
      const changed = clone(fixture.candidateReceipt);
      changed.capturedAt = capturedAt;
      delete changed.fingerprint;
      changed.fingerprint = fingerprint(changed);
      const result = evaluate(fixture, fixture.document, {
        liveCandidateReceipt: changed,
      });
      assert.strictEqual(result.status, "failed");
      assert.ok(result.errors.some(error => /capture does not precede completion/u.test(error)));
    }
  });

  test("requires every declared live fixture and retains a partial workflow row", () => {
    assert.deepStrictEqual(requiredLiveWorkflowIds({
      workflows: [
        { id: "WF-NO-LIVE-LAYER", requiredLayers: ["black-box-ui"], liveFixture: { required: true } },
        { id: "WF-LIVE-LAYER", requiredLayers: ["live-protocol"], liveFixture: { required: true } },
        { id: "WF-OPTIONAL", requiredLayers: ["live-protocol"], liveFixture: { required: false } },
      ],
    }), ["WF-LIVE-LAYER", "WF-NO-LIVE-LAYER"]);

    const partial = clone(fixture.document);
    partial.status = "partial";
    partial.summary = "The authoritative outcome was only partially observed.";
    partial.authenticatedAcceptance = false;
    partial.checklistConfirmed = false;
    partial.verdict = null;
    partial.workflowResults[0].status = "PARTIAL";
    partial.workflowResults[0].authoritativeOutcomeObserved = false;

    const result = evaluate(fixture, partial);

    assert.strictEqual(result.status, "partial");
    assert.strictEqual(result.authenticatedAcceptance, "not-recorded");
    assert.strictEqual(result.verdict, null);
    assert.deepStrictEqual(result.workflowMatrix, [{
      id: "WF-AUTH-STATE",
      status: "PARTIAL",
    }]);
    assert.deepStrictEqual(result.missingWorkflowIds, ["WF-AUTH-STATE"]);
  });

  test("retains exact local PASS evidence in non-passing attestations without CI proof", () => {
    const workflows = {
      workflows: [
        ...WORKFLOWS.workflows,
        {
          id: "WF-SECOND-LIVE",
          requiredLayers: ["live-protocol"],
          liveFixture: { required: true },
        },
      ],
    };

    for (const [declaredStatus, rowStatus] of [
      ["partial", "PARTIAL"],
      ["blocked", "BLOCKED"],
    ]) {
      const document = clone(fixture.document);
      document.status = declaredStatus;
      document.summary = `The second live workflow is ${rowStatus.toLowerCase()}.`;
      document.authenticatedAcceptance = false;
      document.checklistConfirmed = false;
      document.verdict = null;
      document.workflowResults.push({
        id: "WF-SECOND-LIVE",
        status: rowStatus,
        authoritativeOutcomeObserved: false,
        candidateReceiptFingerprint: null,
        evidence: [fixture.qualificationEvidence],
      });

      const result = evaluate(fixture, document, {
        authenticatedReceipt: null,
        authenticatedCandidateReceipt: null,
        authenticatedCandidateArtifactPath: null,
        workflows,
      });

      assert.strictEqual(result.status, declaredStatus);
      assert.deepStrictEqual(result.candidate, fixture.document.candidate);
      assert.deepStrictEqual(result.passedWorkflowIds, ["WF-AUTH-STATE"]);
      assert.deepStrictEqual(result.missingWorkflowIds, ["WF-SECOND-LIVE"]);
      assert.deepStrictEqual(result.errors, []);
    }
  });

  test("keeps local PASS binding fail-closed without weakening passed CI acceptance", () => {
    const workflows = {
      workflows: [
        ...WORKFLOWS.workflows,
        {
          id: "WF-SECOND-LIVE",
          requiredLayers: ["live-protocol"],
          liveFixture: { required: true },
        },
      ],
    };
    const partial = clone(fixture.document);
    partial.status = "partial";
    partial.summary = "The live result is incomplete.";
    partial.authenticatedAcceptance = false;
    partial.checklistConfirmed = false;
    partial.verdict = null;
    partial.workflowResults[0].candidateReceiptFingerprint = "f".repeat(64);
    partial.workflowResults.push({
      id: "WF-SECOND-LIVE",
      status: "PARTIAL",
      authoritativeOutcomeObserved: false,
      candidateReceiptFingerprint: null,
      evidence: [fixture.qualificationEvidence],
    });
    const crossed = evaluate(fixture, partial, {
      authenticatedReceipt: null,
      authenticatedCandidateReceipt: null,
      authenticatedCandidateArtifactPath: null,
      workflows,
    });
    assert.strictEqual(crossed.status, "failed");
    assert.ok(crossed.errors.some(error => /does not bind the exact candidate receipt/u.test(error)));

    const passed = evaluate(fixture, fixture.document, {
      authenticatedReceipt: null,
      authenticatedCandidateReceipt: null,
      authenticatedCandidateArtifactPath: null,
    });
    assert.strictEqual(passed.status, "failed");
    assert.strictEqual(passed.authenticatedAcceptance, "not-recorded");
    assert.ok(passed.errors.some(error => /Authenticated-CI candidate receipt is missing/u.test(error)));
  });

  test("keeps passed workflow rows blocked, not failed, when only a derived finding remains open", () => {
    const document = clone(fixture.document);
    document.openReleaseBlockerCount = 1;
    document.independentReview.attestationSha256 = attestationReviewDigest(document);

    const result = evaluateLiveQualification({
      attestationFingerprint: "a".repeat(64),
      document,
      findingsState: {
        fingerprint: document.findingsFingerprint,
        openReleaseBlockerCount: 1,
        openNonBlockingRiskCount: 1,
        errors: [],
      },
      now: NOW,
      root: fixture.root,
      source: SOURCE,
      workflows: WORKFLOWS,
      liveCandidateReceipt: fixture.candidateReceipt,
      liveCandidateArtifactPath: fixture.candidateArtifactPath,
      authenticatedReceipt: fixture.authenticatedReceipt,
      authenticatedExposureReceipt: fixture.authenticatedExposureReceipt,
      authenticatedCandidateReceipt: fixture.authenticatedCandidateReceipt,
      authenticatedCandidateArtifactPath: fixture.authenticatedCandidateArtifactPath,
      qualificationHomeDirectory: fixture.qualificationHomeDirectory,
    });

    assert.strictEqual(result.status, "blocked");
    assert.strictEqual(result.authenticatedAcceptance, "not-recorded");
    assert.strictEqual(result.verdict, null);
    assert.deepStrictEqual(result.workflowMatrix, [{ id: "WF-AUTH-STATE", status: "PASS" }]);
    assert.deepStrictEqual(result.passedWorkflowIds, ["WF-AUTH-STATE"]);
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
      qualificationHomeDirectory: fixture.qualificationHomeDirectory,
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

  test("does not load stale authenticated proof for a non-authenticated partial disk result", () => {
    const inputPath = "internal_docs/quality/live-qualification.json";
    const partial = clone(fixture.document);
    partial.status = "partial";
    partial.summary = "The authoritative outcome was only partially observed.";
    partial.authenticatedAcceptance = false;
    partial.checklistConfirmed = false;
    partial.verdict = null;
    partial.workflowResults[0].status = "PARTIAL";
    partial.workflowResults[0].authoritativeOutcomeObserved = false;
    fs.writeFileSync(path.join(fixture.root, inputPath), `${JSON.stringify(partial, null, 2)}\n`);
    fs.writeFileSync(
      path.join(fixture.root, AUTHENTICATED_CANDIDATE_RECEIPT),
      "{stale-auth-proof}\n",
    );

    const result = runChecklist({
      inputPath,
      now: NOW,
      outputPath: ".quality/live-status.json",
      root: fixture.root,
      source: SOURCE,
      workflows: WORKFLOWS,
      qualificationHomeDirectory: fixture.qualificationHomeDirectory,
    });

    assert.strictEqual(result.status, "partial");
    assert.deepStrictEqual(result.candidate, fixture.document.candidate);
  });

  test("rejects a disk attestation containing malformed UTF-8", () => {
    const inputPath = "internal_docs/quality/live-qualification.json";
    const prefix = Buffer.from('{"schemaVersion":5,"operatorId":"');
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
    assert.deepStrictEqual(wrongHashResult.passedWorkflowIds, ["WF-AUTH-STATE"]);
    assert.deepStrictEqual(wrongHashResult.missingWorkflowIds, []);
    assert.deepStrictEqual(wrongHashResult.workflowMatrix, [{
      id: "WF-AUTH-STATE",
      status: "PASS",
    }]);

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

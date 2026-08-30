// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const crypto = require("crypto");
const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { writeJson } = require("../scripts/quality/common");
const { fingerprint } = require("../scripts/quality/evidence");
const {
  artifactFingerprintForStep,
  getGatePlan,
  receiptPath,
} = require("../scripts/quality/gate");
const TEST_INVENTORIES = require("./testInventories");
const {
  AUTHENTICATED_CANDIDATE_ARTIFACT,
  AUTHENTICATED_CANDIDATE_RECEIPT,
  LIVE_CANDIDATE_ARTIFACT,
  LIVE_CANDIDATE_RECEIPT,
  UI_CANDIDATE_ARTIFACT,
  UI_CANDIDATE_RECEIPT,
  candidateBindingFromReceipt,
} = require("../scripts/quality/candidate-binding");
const {
  ACCEPTANCE_BOUNDARY_DRIFT_REASON,
  attestationReviewDigest,
  evaluateLiveQualification,
  qualificationEvidenceManifest,
  requiredLiveWorkflowIds,
  runChecklist,
} = require("../scripts/quality/release-checklist");
const {
  RELEASE_EXPOSURE_RESULT,
  buildReleaseExposureResult,
  captureGeneratedEvidenceManifest,
} = require("../scripts/quality/release-exposure-scan");
const { UI_RESULT } = require("../scripts/quality/verify-ui-evidence");

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
    requiredLayers: Object.freeze(["live-protocol", "black-box-ui"]),
    evidence: Object.freeze([Object.freeze({
      layer: "black-box-ui",
      testNames: Object.freeze(["fixture signed-out UI"]),
    })]),
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
  fs.writeFileSync(path.join(root, ".node-version"), "22.23.2\n");
  fs.writeFileSync(path.join(root, ".npm-version"), "10.9.8\n");
  fs.writeFileSync(path.join(root, ".npm-integrity"), `${JSON.stringify({
    posix: "4".repeat(64),
    win32: "4".repeat(64),
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
      requiredEvidenceLayers: ["live-protocol"],
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
    schemaVersion: 3,
    status: "passed",
    capturedAt: CAPTURED_AT,
    source: SOURCE,
    repository: {
      branch: "test/release-quality-harness",
      dirty: true,
      status: "dirty",
    },
    toolchain: {
      nodeVersion: "v22.23.2",
      npmVersion: "10.9.8",
      npmInstallationSha256: "4".repeat(64),
      platform: "darwin",
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
    schemaVersion: 2,
    status: "passed",
    sourceSha: SOURCE.sha,
    candidateReceiptFingerprint: authenticatedCandidateReceipt.fingerprint,
    vsixSha256: authenticatedCandidateReceipt.artifact.sha256,
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
        id: `vsix:${AUTHENTICATED_CANDIDATE_ARTIFACT}`,
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
    schemaVersion: 6,
    source: SOURCE,
    candidate,
    status: "passed",
    summary: null,
    authenticatedAcceptance: true,
    checklistConfirmed: true,
    operatorId: "qualification-operator",
    completedAt: COMPLETED_AT,
    verdict: "TEAM-TEST READY WITH RISKS",
    evidence: [qualificationEvidence, findingsEvidence],
    findingsFingerprint: findingsEvidence.sha256,
    openReleaseBlockerCount: 0,
    workflowResults: [{
      id: "WF-AUTH-STATE",
      status: "PASS",
      authoritativeOutcomeObserved: true,
      candidateProvenance: "verified",
      candidateReceiptFingerprint: candidate.receiptFingerprint,
      outcomeDisposition: "complete",
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

function writeReleaseProgressAtSecretScan(root, source) {
  const plan = getGatePlan("release");
  const inventoryByStep = {
    "standalone-tests": [
      ...TEST_INVENTORIES.STANDALONE_NODE_TESTS,
      ...TEST_INVENTORIES.HOST_NODE_TESTS,
    ],
    "extension-host-core": TEST_INVENTORIES.VSCODE_CORE_TESTS,
    "extension-host-smoke": TEST_INVENTORIES.VSCODE_SMOKE_TESTS,
  };
  let reachedExposureScan = false;
  for (const step of plan) {
    if (step.id === "secret-release") reachedExposureScan = true;
    let receipt = {
      schemaVersion: 1,
      profile: "release",
      sequence: step.sequence,
      stepId: step.id,
      category: step.category,
      command: step.command,
      source,
      status: "not-run",
      exitCode: null,
      signal: null,
      reason: "not-started",
      testCounts: null,
      artifactFingerprint: null,
    };
    if (!reachedExposureScan) {
      let testEvidence = null;
      let testEvidenceFingerprint = null;
      if (step.evidencePath) {
        const tests = inventoryByStep[step.id].map(file => ({
          file,
          title: `synthetic ${file}`,
          fullTitle: `synthetic suite ${file}`,
          status: "passed",
        }));
        testEvidence = {
          schemaVersion: 1,
          source,
          suite: step.id,
          counts: { passed: tests.length, failed: 0, pending: 0 },
          tests,
        };
        writeJson(step.evidencePath, testEvidence, root, {
          subtree: ".quality/test-results",
        });
        testEvidenceFingerprint = crypto.createHash("sha256")
          .update(`${JSON.stringify(testEvidence, null, 2)}\n`)
          .digest("hex");
      }
      for (const artifactPath of [
        ...(step.artifactPaths || []),
        ...(step.artifactPath ? [step.artifactPath] : []),
      ]) {
        const target = path.join(root, ...artifactPath.split("/"));
        if (!fs.existsSync(target)) {
          fs.mkdirSync(path.dirname(target), { recursive: true });
          fs.writeFileSync(target, `synthetic ${step.id} artifact\n`);
        }
      }
      receipt = {
        ...receipt,
        status: "passed",
        exitCode: 0,
        reason: null,
        outputFingerprint: crypto.createHash("sha256").update("").digest("hex"),
        testEvidence,
        testEvidenceFingerprint,
        artifactFingerprint: artifactFingerprintForStep(step, root),
      };
    }
    writeJson(receiptPath(receipt), receipt, root, {
      subtree: ".quality/gates/release",
    });
  }
  return plan;
}

function completeReleaseStep(root, plan, stepId, status = "passed") {
  const step = plan.find(candidate => candidate.id === stepId);
  const relativePath = receiptPath({
    profile: "release",
    sequence: step.sequence,
    stepId: step.id,
  });
  const receipt = JSON.parse(fs.readFileSync(
    path.join(root, ...relativePath.split("/")),
    "utf8",
  ));
  writeJson(relativePath, {
    ...receipt,
    status,
    exitCode: status === "blocked" ? 2 : 0,
    reason: null,
    outputFingerprint: crypto.createHash("sha256").update("").digest("hex"),
    testEvidence: null,
    testEvidenceFingerprint: null,
    artifactFingerprint: artifactFingerprintForStep(step, root),
  }, root, { subtree: ".quality/gates/release" });
}

function writeReleaseExposureFixture(fixture, document, inputPath, overrides = {}) {
  const uiCandidateBytes = fs.readFileSync(fixture.authenticatedCandidateArtifactPath);
  const uiCandidateBase = clone(fixture.authenticatedCandidateReceipt);
  delete uiCandidateBase.fingerprint;
  uiCandidateBase.vscode.version = "1.131.0";
  const uiCandidateReceipt = {
    ...uiCandidateBase,
    fingerprint: fingerprint(uiCandidateBase),
  };
  const uiCandidateArtifactPath = path.join(fixture.root, UI_CANDIDATE_ARTIFACT);
  fs.writeFileSync(uiCandidateArtifactPath, uiCandidateBytes);
  fs.writeFileSync(
    path.join(fixture.root, UI_CANDIDATE_RECEIPT),
    `${JSON.stringify(uiCandidateReceipt, null, 2)}\n`,
  );
  const uiResultBytes = Buffer.from(`${JSON.stringify({
    schemaVersion: 2,
    status: "passed",
    source: SOURCE,
    sourceSha: SOURCE.sha,
    tool: "vscode-extension-tester",
    toolVersion: "8.24.0",
    vscodeVersion: uiCandidateReceipt.vscode.version,
    platform: process.platform === "win32" ? "win32" : process.platform,
    architecture: process.arch === "arm64" ? "arm64" : "x64",
    launchAttempted: true,
    tests: ["fixture signed-out UI"],
    results: [{ name: "fixture signed-out UI", status: "passed" }],
    candidate: {
      candidateReceiptFingerprint: uiCandidateReceipt.fingerprint,
      extensionId: uiCandidateReceipt.extension.id,
      extensionVersion: uiCandidateReceipt.extension.version,
      profileMode: uiCandidateReceipt.profile.mode,
      sourceFingerprint: uiCandidateReceipt.source.fingerprint,
      sourceSha: uiCandidateReceipt.source.sha,
      vscodeVersion: uiCandidateReceipt.vscode.version,
      vsixSha256: uiCandidateReceipt.artifact.sha256,
    },
    reason: null,
  }, null, 2)}\n`);
  fs.mkdirSync(path.join(fixture.root, path.dirname(UI_RESULT)), { recursive: true });
  fs.writeFileSync(path.join(fixture.root, UI_RESULT), uiResultBytes);
  const attestationBytes = fs.readFileSync(path.join(fixture.root, inputPath));
  const evidenceManifest = Object.prototype.hasOwnProperty.call(
    overrides,
    "evidenceManifest",
  ) ? overrides.evidenceManifest : qualificationEvidenceManifest(document);
  if (typeof overrides.beforeCaptureGeneratedEvidence === "function") {
    overrides.beforeCaptureGeneratedEvidence({ fixture, uiResultBytes });
  }
  const generatedEvidence = captureGeneratedEvidenceManifest(fixture.root, null, {
    source: SOURCE,
  });
  const receipt = buildReleaseExposureResult({
    source: SOURCE,
    candidateReceiptFingerprint: overrides.candidateReceiptFingerprint
      || uiCandidateReceipt.fingerprint,
    vsixSha256: uiCandidateReceipt.artifact.sha256,
    uiResultSha256: crypto.createHash("sha256").update(uiResultBytes).digest("hex"),
    attestationPath: inputPath,
    attestationSha256: crypto.createHash("sha256").update(attestationBytes).digest("hex"),
    generatedEvidence,
    evidenceManifest,
    components: [
      {
        id: "post-ui-generated-quality-evidence",
        status: "scanned",
        fileCount: generatedEvidence.files.length,
        findings: [],
      },
      {
        id: `vsix:${UI_CANDIDATE_ARTIFACT}`,
        status: "scanned",
        fileCount: 2,
        findings: [],
      },
      {
        id: "accepted-live-evidence",
        status: "scanned",
        fileCount: new Set([
          inputPath,
          ...evidenceManifest.map(reference => reference.path),
        ]).size,
        findings: [],
      },
    ],
    now: NOW,
  });
  fs.writeFileSync(
    path.join(fixture.root, RELEASE_EXPOSURE_RESULT),
    `${JSON.stringify(receipt, null, 2)}\n`,
  );
  return receipt;
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
    crossed.components[1].id = "vsix:.quality/qualification/unbound-candidate.vsix";
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
    partial.workflowResults[0].outcomeDisposition = "partial-evidence";

    const result = evaluate(fixture, partial);

    assert.strictEqual(result.status, "partial");
    assert.strictEqual(result.authenticatedAcceptance, "not-recorded");
    assert.strictEqual(result.verdict, null);
    assert.deepStrictEqual(result.workflowMatrix, [{
      id: "WF-AUTH-STATE",
      status: "PARTIAL",
      outcomeDisposition: "partial-evidence",
      candidateProvenance: "verified",
    }]);
    assert.deepStrictEqual(result.missingWorkflowIds, ["WF-AUTH-STATE"]);
  });

  test("retains exact candidate provenance for PARTIAL and precondition-confirmed BLOCKED rows", () => {
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
        candidateProvenance: "verified",
        candidateReceiptFingerprint: fixture.candidateReceipt.fingerprint,
        outcomeDisposition: rowStatus === "PARTIAL" ? "partial-evidence" : "not-authorized",
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
      const second = result.workflowMatrix.find(row => row.id === "WF-SECOND-LIVE");
      assert.strictEqual(second.candidateProvenance, "verified");
      assert.strictEqual(
        second.outcomeDisposition,
        rowStatus === "PARTIAL" ? "partial-evidence" : "not-authorized"
      );
      assert.deepStrictEqual(result.errors, []);
    }
  });

  test("rejects a wrong candidate receipt for PARTIAL and candidate-bound BLOCKED rows", () => {
    for (const [declaredStatus, rowStatus, outcomeDisposition] of [
      ["partial", "PARTIAL", "partial-evidence"],
      ["blocked", "BLOCKED", "not-authorized"],
    ]) {
      const document = clone(fixture.document);
      document.status = declaredStatus;
      document.summary = `The candidate-bound ${rowStatus.toLowerCase()} row has crossed provenance.`;
      document.authenticatedAcceptance = false;
      document.checklistConfirmed = false;
      document.verdict = null;
      document.workflowResults[0] = {
        ...document.workflowResults[0],
        status: rowStatus,
        authoritativeOutcomeObserved: false,
        candidateProvenance: "verified",
        candidateReceiptFingerprint: "f".repeat(64),
        outcomeDisposition,
      };

      const result = evaluate(fixture, document);

      assert.strictEqual(result.status, "failed");
      assert.ok(result.errors.some(error => (
        /does not bind the exact candidate receipt/u.test(error)
      )));
    }
  });

  test("rejects candidate-bound workflow evidence captured before the candidate receipt", () => {
    const document = clone(fixture.document);
    document.workflowResults[0].evidence[0].capturedAt = timestampBeforeNow(4 * 60 * 1000);

    const result = evaluate(fixture, document);

    assert.strictEqual(result.status, "failed");
    assert.ok(result.errors.some(error => /timestamp predates the required event/u.test(error)));
  });

  test("rejects candidate-bound visible-action evidence captured before the candidate receipt", () => {
    const document = clone(fixture.document);
    document.visibleEnabledActions.evidence[0].capturedAt = timestampBeforeNow(4 * 60 * 1000);

    const result = evaluate(fixture, document);

    assert.strictEqual(result.status, "failed");
    assert.ok(result.errors.some(error => /timestamp predates the required event/u.test(error)));
  });

  test("retains null provenance only for a workflow that was not executed", () => {
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
    const document = clone(fixture.document);
    document.status = "blocked";
    document.summary = "The second workflow was not executed.";
    document.authenticatedAcceptance = false;
    document.checklistConfirmed = false;
    document.verdict = null;
    document.workflowResults.push({
      id: "WF-SECOND-LIVE",
      status: "BLOCKED",
      authoritativeOutcomeObserved: false,
      candidateProvenance: "not-observed",
      candidateReceiptFingerprint: null,
      outcomeDisposition: "not-executed",
      evidence: [fixture.qualificationEvidence],
    });

    const result = evaluate(fixture, document, {
      authenticatedReceipt: null,
      authenticatedCandidateReceipt: null,
      authenticatedCandidateArtifactPath: null,
      workflows,
    });

    assert.strictEqual(result.status, "blocked");
    assert.deepStrictEqual(result.workflowMatrix.find(row => (
      row.id === "WF-SECOND-LIVE"
    )), {
      id: "WF-SECOND-LIVE",
      status: "BLOCKED",
      outcomeDisposition: "not-executed",
      candidateProvenance: "not-observed",
    });
    assert.deepStrictEqual(result.errors, []);
  });

  test("rejects null, wrong, and contradictory provenance independently of outcome", () => {
    for (const mutate of [
      document => {
        document.workflowResults[0].candidateReceiptFingerprint = null;
      },
      document => {
        document.workflowResults[0].candidateReceiptFingerprint = "f".repeat(64);
      },
      document => {
        document.workflowResults[0].candidateProvenance = "not-observed";
      },
      document => {
        document.workflowResults[0].candidateProvenance = "not-observed";
        document.workflowResults[0].candidateReceiptFingerprint = null;
      },
    ]) {
      const document = clone(fixture.document);
      document.status = "partial";
      document.summary = "Candidate provenance regression fixture.";
      document.authenticatedAcceptance = false;
      document.checklistConfirmed = false;
      document.verdict = null;
      document.workflowResults[0].status = "PARTIAL";
      document.workflowResults[0].authoritativeOutcomeObserved = false;
      document.workflowResults[0].outcomeDisposition = "partial-evidence";
      mutate(document);

      const result = evaluate(fixture, document, {
        authenticatedReceipt: null,
        authenticatedCandidateReceipt: null,
        authenticatedCandidateArtifactPath: null,
      });
      assert.strictEqual(result.status, "failed");
      assert.ok(result.errors.some(error => /provenance|receipt|exact candidate/u.test(error)));
    }
  });

  test("rejects unobserved provenance for a not-authorized candidate preflight", () => {
    const document = clone(fixture.document);
    document.status = "blocked";
    document.summary = "The write was not authorized after candidate preflight.";
    document.authenticatedAcceptance = false;
    document.checklistConfirmed = false;
    document.verdict = null;
    document.workflowResults[0] = {
      ...document.workflowResults[0],
      status: "BLOCKED",
      authoritativeOutcomeObserved: false,
      candidateProvenance: "not-observed",
      candidateReceiptFingerprint: null,
      outcomeDisposition: "not-authorized",
    };

    const result = evaluate(fixture, document, {
      authenticatedReceipt: null,
      authenticatedCandidateReceipt: null,
      authenticatedCandidateArtifactPath: null,
    });

    assert.strictEqual(result.status, "failed");
    assert.ok(result.errors.some(error => /not-authorized preflight lacks candidate provenance/u.test(error)));
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
      candidateProvenance: "verified",
      candidateReceiptFingerprint: fixture.candidateReceipt.fingerprint,
      outcomeDisposition: "partial-evidence",
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
    assert.deepStrictEqual(result.workflowMatrix, [{
      id: "WF-AUTH-STATE",
      status: "PASS",
      outcomeDisposition: "complete",
      candidateProvenance: "verified",
    }]);
    assert.deepStrictEqual(result.passedWorkflowIds, ["WF-AUTH-STATE"]);
  });

  test("carries the exact attestation bytes and evidence hashes into the derived status", () => {
    const inputPath = "internal_docs/quality/live-qualification.json";
    const bytes = Buffer.from(`${JSON.stringify(fixture.document, null, 2)}\n`);
    fs.writeFileSync(path.join(fixture.root, inputPath), bytes);
    writeReleaseExposureFixture(fixture, fixture.document, inputPath);

    const result = runChecklist({
      inputPath,
      now: NOW,
      outputPath: ".quality/gates/live-qualification-status.json",
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

  test("persists its exact result while the parent release receipt is still pending", () => {
    const inputPath = "internal_docs/quality/live-qualification.json";
    const outputPath = ".quality/gates/live-qualification-status.json";
    fs.writeFileSync(
      path.join(fixture.root, inputPath),
      `${JSON.stringify(fixture.document, null, 2)}\n`,
    );
    let releasePlan;
    writeReleaseExposureFixture(fixture, fixture.document, inputPath, {
      beforeCaptureGeneratedEvidence() {
        releasePlan = writeReleaseProgressAtSecretScan(fixture.root, SOURCE);
      },
    });
    completeReleaseStep(fixture.root, releasePlan, "secret-release");

    const result = runChecklist({
      inputPath,
      now: NOW,
      outputPath,
      root: fixture.root,
      source: SOURCE,
      workflows: WORKFLOWS,
      qualificationHomeDirectory: fixture.qualificationHomeDirectory,
    });
    const persisted = JSON.parse(fs.readFileSync(
      path.join(fixture.root, outputPath),
      "utf8",
    ));

    assert.strictEqual(result.status, "passed");
    assert.notStrictEqual(result.reason, ACCEPTANCE_BOUNDARY_DRIFT_REASON);
    assert.deepStrictEqual(persisted, result);
    completeReleaseStep(fixture.root, releasePlan, "release-checklist");
  });

  test("rejects missing, crossed, and omitted disk release-exposure proof", () => {
    const inputPath = "internal_docs/quality/live-qualification.json";
    fs.writeFileSync(
      path.join(fixture.root, inputPath),
      `${JSON.stringify(fixture.document, null, 2)}\n`,
    );
    writeReleaseExposureFixture(fixture, fixture.document, inputPath);
    fs.rmSync(path.join(fixture.root, RELEASE_EXPOSURE_RESULT));

    const missing = runChecklist({
      inputPath,
      now: NOW,
      outputPath: ".quality/gates/live-qualification-status.json",
      root: fixture.root,
      source: SOURCE,
      workflows: WORKFLOWS,
      qualificationHomeDirectory: fixture.qualificationHomeDirectory,
    });
    assert.strictEqual(missing.status, "failed");
    assert.ok(missing.errors.some(error => /Release exposure proof is missing/u.test(error)));

    writeReleaseExposureFixture(fixture, fixture.document, inputPath, {
      candidateReceiptFingerprint: "9".repeat(64),
    });
    const crossed = runChecklist({
      inputPath,
      now: NOW,
      outputPath: ".quality/gates/live-qualification-status.json",
      root: fixture.root,
      source: SOURCE,
      workflows: WORKFLOWS,
      qualificationHomeDirectory: fixture.qualificationHomeDirectory,
    });
    assert.strictEqual(crossed.status, "failed");
    assert.ok(crossed.errors.some(error => /Release exposure proof is invalid/u.test(error)));

    writeReleaseExposureFixture(fixture, fixture.document, inputPath, {
      evidenceManifest: [],
    });
    const omitted = runChecklist({
      inputPath,
      now: NOW,
      outputPath: ".quality/gates/live-qualification-status.json",
      root: fixture.root,
      source: SOURCE,
      workflows: WORKFLOWS,
      qualificationHomeDirectory: fixture.qualificationHomeDirectory,
    });
    assert.strictEqual(omitted.status, "failed");
    assert.ok(omitted.errors.some(error => /Release exposure proof is invalid/u.test(error)));
  });

  test("rejects generated-evidence add, change, delete, and identity-replacement drift", () => {
    const mutations = {
      add(rowFixture) {
        fs.writeFileSync(
          path.join(rowFixture.root, ".quality", "qualification", "late-proof.txt"),
          "late generated proof\n",
        );
      },
      change(rowFixture, markerPath) {
        fs.writeFileSync(markerPath, "changed generated proof\n");
      },
      delete(_rowFixture, markerPath) {
        fs.rmSync(markerPath);
      },
      replace(rowFixture, markerPath, markerBytes) {
        const replacement = path.join(
          rowFixture.root,
          ".quality",
          "qualification",
          "replacement-proof.txt",
        );
        fs.writeFileSync(replacement, markerBytes);
        fs.renameSync(replacement, markerPath);
      },
    };
    for (const [name, mutate] of Object.entries(mutations)) {
      const rowFixture = createFixture();
      try {
        const inputPath = "internal_docs/quality/live-qualification.json";
        fs.writeFileSync(
          path.join(rowFixture.root, inputPath),
          `${JSON.stringify(rowFixture.document, null, 2)}\n`,
        );
        const markerPath = path.join(
          rowFixture.root,
          ".quality",
          "qualification",
          "stable-generated-proof.txt",
        );
        const markerBytes = Buffer.from("stable generated proof\n");
        fs.writeFileSync(markerPath, markerBytes);
        writeReleaseExposureFixture(rowFixture, rowFixture.document, inputPath);
        mutate(rowFixture, markerPath, markerBytes);

        const result = runChecklist({
          inputPath,
          now: NOW,
          outputPath: ".quality/gates/live-qualification-status.json",
          root: rowFixture.root,
          source: SOURCE,
          workflows: WORKFLOWS,
          qualificationHomeDirectory: rowFixture.qualificationHomeDirectory,
        });
        assert.strictEqual(result.status, "failed", name);
        assert.strictEqual(result.reason, "Release exposure verification failed closed.", name);
        assert.ok(result.errors.some(error => (
          /generated release evidence changed across the pre-acceptance boundary/iu.test(error)
        )), name);
      } finally {
        fs.rmSync(rowFixture.root, { force: true, recursive: true });
      }
    }
  });

  test("revalidates generated evidence after evaluation and before persisting acceptance", () => {
    const inputPath = "internal_docs/quality/live-qualification.json";
    fs.writeFileSync(
      path.join(fixture.root, inputPath),
      `${JSON.stringify(fixture.document, null, 2)}\n`,
    );
    writeReleaseExposureFixture(fixture, fixture.document, inputPath);

    const result = runChecklist({
      inputPath,
      now: NOW,
      outputPath: ".quality/gates/live-qualification-status.json",
      root: fixture.root,
      source: SOURCE,
      workflows: WORKFLOWS,
      qualificationHomeDirectory: fixture.qualificationHomeDirectory,
      beforePersist({ root }) {
        fs.writeFileSync(
          path.join(root, ".quality", "qualification", "acceptance-race.txt"),
          "post-evaluation generated proof\n",
        );
      },
    });

    assert.strictEqual(result.status, "failed");
    assert.strictEqual(result.reason, "Release exposure verification failed closed.");
    assert.ok(result.errors.some(error => (
      /generated release evidence changed across the pre-acceptance boundary/iu.test(error)
    )));
  });

  test("downgrades writer-boundary UI and generated-evidence races after atomic persistence", () => {
    const mutations = {
      "ui-change"({ uiArtifactPath }) {
        fs.writeFileSync(uiArtifactPath, "UI-CANDIDATE-CHANGED-DURING-PERSISTENCE\n");
      },
      "ui-delete"({ uiArtifactPath }) {
        fs.rmSync(uiArtifactPath);
      },
      "ui-same-byte-replacement"({ uiArtifactBytes, uiArtifactPath }) {
        const replacement = `${uiArtifactPath}.replacement`;
        fs.writeFileSync(replacement, uiArtifactBytes);
        fs.renameSync(replacement, uiArtifactPath);
      },
      "generated-add"({ rowFixture }) {
        fs.writeFileSync(
          path.join(rowFixture.root, ".quality", "qualification", "late-proof.txt"),
          "GENERATED-EVIDENCE-ADDED-DURING-PERSISTENCE\n",
        );
      },
      "generated-change"({ generatedMarkerPath }) {
        fs.writeFileSync(
          generatedMarkerPath,
          "GENERATED-EVIDENCE-CHANGED-DURING-PERSISTENCE\n",
        );
      },
      "generated-delete"({ generatedMarkerPath }) {
        fs.rmSync(generatedMarkerPath);
      },
      "generated-same-byte-replacement"({ generatedMarkerBytes, generatedMarkerPath }) {
        const replacement = `${generatedMarkerPath}.replacement`;
        fs.writeFileSync(replacement, generatedMarkerBytes);
        fs.renameSync(replacement, generatedMarkerPath);
      },
      "checklist-same-byte-replacement"({ rowFixture }) {
        const checklistPath = path.join(
          rowFixture.root,
          ".quality",
          "gates",
          "live-qualification-status.json",
        );
        const replacement = `${checklistPath}.replacement`;
        fs.writeFileSync(replacement, fs.readFileSync(checklistPath));
        fs.renameSync(replacement, checklistPath);
      },
    };

    for (const [name, mutate] of Object.entries(mutations)) {
      const rowFixture = createFixture();
      try {
        const inputPath = "internal_docs/quality/live-qualification.json";
        const outputPath = ".quality/gates/live-qualification-status.json";
        fs.writeFileSync(
          path.join(rowFixture.root, inputPath),
          `${JSON.stringify(rowFixture.document, null, 2)}\n`,
        );
        const generatedMarkerPath = path.join(
          rowFixture.root,
          ".quality",
          "qualification",
          "stable-generated-proof.txt",
        );
        const generatedMarkerBytes = Buffer.from("stable generated proof\n");
        fs.writeFileSync(generatedMarkerPath, generatedMarkerBytes);
        writeReleaseExposureFixture(rowFixture, rowFixture.document, inputPath);
        const uiArtifactPath = path.join(rowFixture.root, UI_CANDIDATE_ARTIFACT);
        const uiArtifactBytes = fs.readFileSync(uiArtifactPath);
        let hookObserved = false;
        let hookPersisted = null;
        let hookWritten = null;

        const result = runChecklist({
          inputPath,
          now: NOW,
          outputPath,
          root: rowFixture.root,
          source: SOURCE,
          workflows: WORKFLOWS,
          qualificationHomeDirectory: rowFixture.qualificationHomeDirectory,
          afterPersist({ result: written }) {
            hookObserved = true;
            hookWritten = written;
            hookPersisted = JSON.parse(fs.readFileSync(
              path.join(rowFixture.root, outputPath),
              "utf8",
            ));
            mutate({
              generatedMarkerBytes,
              generatedMarkerPath,
              rowFixture,
              uiArtifactBytes,
              uiArtifactPath,
            });
          },
        });
        const persisted = JSON.parse(fs.readFileSync(
          path.join(rowFixture.root, outputPath),
          "utf8",
        ));

        assert.strictEqual(hookObserved, true, name);
        assert.strictEqual(hookWritten.status, "passed", name);
        assert.deepStrictEqual(hookPersisted, hookWritten, name);
        assert.deepStrictEqual(persisted, result, name);
        assert.strictEqual(result.status, "failed", name);
        assert.strictEqual(result.authenticatedAcceptance, "not-recorded", name);
        assert.strictEqual(result.reason, ACCEPTANCE_BOUNDARY_DRIFT_REASON, name);
        assert.deepStrictEqual(result.errors, [ACCEPTANCE_BOUNDARY_DRIFT_REASON], name);
        assert.strictEqual(result.candidate, null, name);
        assert.strictEqual(result.attestationFingerprint, null, name);
        assert.deepStrictEqual(result.evidenceManifest, [], name);
        assert.doesNotMatch(
          JSON.stringify(persisted),
          /(?:UI-CANDIDATE|GENERATED-EVIDENCE)-.+DURING-PERSISTENCE/u,
          name,
        );
      } finally {
        fs.rmSync(rowFixture.root, { force: true, recursive: true });
      }
    }
  });

  test("replaces rejected attestation summary text with fixed fail-closed status copy", () => {
    const inputPath = "internal_docs/quality/live-qualification.json";
    const outputPath = ".quality/gates/live-qualification-status.json";
    const sentinel = "ATTESTATION-CONTROLLED-SUMMARY-MUST-NOT-PERSIST";
    const partial = clone(fixture.document);
    partial.status = "partial";
    partial.summary = sentinel;
    partial.authenticatedAcceptance = false;
    partial.checklistConfirmed = false;
    partial.verdict = null;
    partial.workflowResults[0].status = "PARTIAL";
    partial.workflowResults[0].authoritativeOutcomeObserved = false;
    partial.workflowResults[0].outcomeDisposition = "partial-evidence";
    fs.writeFileSync(path.join(fixture.root, inputPath), `${JSON.stringify(partial, null, 2)}\n`);
    writeReleaseExposureFixture(fixture, partial, inputPath);
    fs.mkdirSync(path.join(fixture.root, ".quality", "gates"), { recursive: true });
    fs.writeFileSync(
      path.join(fixture.root, outputPath),
      `${JSON.stringify({ reason: sentinel })}\n`,
    );
    fs.writeFileSync(
      path.join(fixture.root, RELEASE_EXPOSURE_RESULT),
      "{unreadable-release-exposure-proof}\n",
    );

    const result = runChecklist({
      inputPath,
      now: NOW,
      outputPath,
      root: fixture.root,
      source: SOURCE,
      workflows: WORKFLOWS,
      qualificationHomeDirectory: fixture.qualificationHomeDirectory,
    });
    const persisted = fs.readFileSync(path.join(fixture.root, outputPath), "utf8");

    assert.strictEqual(result.status, "failed");
    assert.strictEqual(result.reason, "Release exposure verification failed closed.");
    assert.doesNotMatch(JSON.stringify(result), new RegExp(sentinel, "u"));
    assert.doesNotMatch(persisted, new RegExp(sentinel, "u"));
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
    partial.workflowResults[0].outcomeDisposition = "partial-evidence";
    fs.writeFileSync(path.join(fixture.root, inputPath), `${JSON.stringify(partial, null, 2)}\n`);
    fs.writeFileSync(
      path.join(fixture.root, AUTHENTICATED_CANDIDATE_RECEIPT),
      "{stale-auth-proof}\n",
    );
    writeReleaseExposureFixture(fixture, partial, inputPath);

    const result = runChecklist({
      inputPath,
      now: NOW,
      outputPath: ".quality/gates/live-qualification-status.json",
      root: fixture.root,
      source: SOURCE,
      workflows: WORKFLOWS,
      qualificationHomeDirectory: fixture.qualificationHomeDirectory,
    });

    assert.strictEqual(result.status, "partial");
    assert.strictEqual(
      result.reason,
      "Authenticated live qualification is declared partial.",
    );
    assert.doesNotMatch(JSON.stringify(result), /authoritative outcome was only partially/iu);
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
      outputPath: ".quality/gates/live-qualification-status.json",
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
      outcomeDisposition: "complete",
      candidateProvenance: "verified",
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
          outputPath: ".quality/gates/live-qualification-status.json",
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

  test("rejects hard-linked live, qualification, evidence, and artifact proofs", () => {
    const evidenceTarget = path.join(fixture.root, fixture.qualificationEvidence.path);
    const evidenceLink = path.join(fixture.root, "hard-linked-evidence.md");
    fs.linkSync(evidenceTarget, evidenceLink);
    try {
      const evidenceResult = evaluate(fixture);
      assert.strictEqual(evidenceResult.status, "failed");
      assert.ok(evidenceResult.errors.some(error => (
        /evidence file is missing, unsafe, changed, or unreadable/u.test(error)
      )));
    } finally {
      fs.rmSync(evidenceLink);
    }

    const artifactLink = path.join(fixture.root, "hard-linked-candidate.vsix");
    fs.linkSync(fixture.candidateArtifactPath, artifactLink);
    try {
      const artifactResult = evaluate(fixture);
      assert.strictEqual(artifactResult.status, "failed");
      assert.ok(artifactResult.errors.some(error => /candidate proof is invalid/iu.test(error)));
    } finally {
      fs.rmSync(artifactLink);
    }

    const inputPath = "internal_docs/quality/live-qualification.json";
    const inputTarget = path.join(fixture.root, inputPath);
    const inputLink = path.join(fixture.root, "hard-linked-live-qualification.json");
    fs.writeFileSync(inputTarget, `${JSON.stringify(fixture.document, null, 2)}\n`);
    fs.linkSync(inputTarget, inputLink);
    try {
      assert.throws(() => runChecklist({
        inputPath,
        now: NOW,
        outputPath: ".quality/gates/live-qualification-status.json",
        root: fixture.root,
        source: SOURCE,
        workflows: WORKFLOWS,
      }), /exact bounded single-link JSON file/u);
    } finally {
      fs.rmSync(inputLink);
    }

    writeReleaseExposureFixture(fixture, fixture.document, inputPath);
    const uiReceiptTarget = path.join(fixture.root, UI_CANDIDATE_RECEIPT);
    const uiReceiptLink = path.join(fixture.root, "hard-linked-ui-candidate.json");
    fs.linkSync(uiReceiptTarget, uiReceiptLink);
    try {
      assert.throws(() => runChecklist({
        inputPath,
        now: NOW,
        outputPath: ".quality/gates/live-qualification-status.json",
        root: fixture.root,
        source: SOURCE,
        workflows: WORKFLOWS,
        qualificationHomeDirectory: fixture.qualificationHomeDirectory,
      }), /Qualification proof is not an exact bounded single-link JSON file/u);
    } finally {
      fs.rmSync(uiReceiptLink);
    }
  });

  test("rejects pre-read live-input symlink and FIFO swaps without reading them", function () {
    if (process.platform === "win32") this.skip();
    for (const replacementKind of ["symlink", "fifo"]) {
      const rowFixture = createFixture();
      const inputPath = "internal_docs/quality/live-qualification.json";
      const inputTarget = path.join(rowFixture.root, inputPath);
      const displacedInput = `${inputTarget}.descriptor-proven`;
      const replacement = path.join(rowFixture.root, `pre-read-${replacementKind}`);
      const outside = path.join(rowFixture.root, `outside-${replacementKind}.json`);
      fs.writeFileSync(inputTarget, `${JSON.stringify(rowFixture.document, null, 2)}\n`);
      if (replacementKind === "symlink") {
        fs.writeFileSync(outside, "synthetic unauthorized symlink bytes\n");
      } else {
        assert.strictEqual(spawnSync("mkfifo", [replacement], { encoding: "utf8" }).status, 0);
      }
      const fileSystem = Object.create(fs);
      let swapped = false;
      let descriptorReads = 0;
      fileSystem.openSync = (...arguments_) => {
        if (!swapped && arguments_[0] === inputTarget) {
          swapped = true;
          fs.renameSync(inputTarget, displacedInput);
          if (replacementKind === "symlink") fs.symlinkSync(outside, inputTarget);
          else fs.renameSync(replacement, inputTarget);
        }
        return fs.openSync(...arguments_);
      };
      fileSystem.readSync = (...arguments_) => {
        descriptorReads += 1;
        return fs.readSync(...arguments_);
      };
      try {
        assert.throws(() => runChecklist({
          fileSystem,
          inputPath,
          now: NOW,
          outputPath: ".quality/gates/live-qualification-status.json",
          root: rowFixture.root,
          source: SOURCE,
          workflows: WORKFLOWS,
        }), /exact bounded single-link JSON file/u, replacementKind);
        assert.strictEqual(swapped, true, replacementKind);
        assert.strictEqual(descriptorReads, 0, replacementKind);
        if (replacementKind === "symlink") {
          assert.strictEqual(
            fs.readFileSync(outside, "utf8"),
            "synthetic unauthorized symlink bytes\n",
          );
        }
      } finally {
        fs.rmSync(rowFixture.root, { force: true, recursive: true });
      }
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

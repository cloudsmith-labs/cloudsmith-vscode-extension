// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const Mocha = require("mocha");
const yaml = require("js-yaml");
const {
  gitVisibleFiles,
  uniqueSorted,
  writeJson,
} = require("../scripts/quality/common");
const {
  ImpactAnalysisError,
  analyzeImpact,
  collectGitChanges,
  explicitChanges,
  impactFingerprint,
  parseArguments: parseImpactArguments,
  parseNameStatus,
  requireMappedRuntime,
} = require("../scripts/quality/impact");
const {
  artifactFingerprintForStep,
  completedReceipt,
  executeCommand,
  gatePlanFingerprint,
  getGatePlan,
  receiptPath,
  runGate,
  validateArtifactBinding,
} = require("../scripts/quality/gate");
const { aggregateStatuses, fingerprint, sourceIdentity } = require("../scripts/quality/evidence");
const {
  CREDENTIAL_LIKE_ENVIRONMENT_NAME,
  NON_AUTH_QUALITY_ENVIRONMENT_ALLOWLIST,
  NON_AUTH_QUALITY_OVERRIDE_NAMES,
  buildNonAuthQualityEnvironment,
} = require("../scripts/quality/non-auth-environment");
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
  assertValidMutationBaseline,
  assertMutationTestOwners,
  assertCanonicalMutationRuntime,
  assertMutationGateArguments,
  changedMutationTargets,
  deriveMutationEvidence,
  filterMutationReport,
  fullMutationSelection,
  gitChangedFiles,
  perFileCounts,
  receipt: mutationReceipt,
  validateMutationSummary,
  validateMutationTestOwnership,
  workingTreeFingerprint,
} = require("../scripts/quality/run-mutation");
const {
  isAncestorCommit,
  validateMutationBaseline,
} = require("../scripts/quality/mutation-baseline");
const { validateMutationToolchain } = require("../scripts/quality/mutation-toolchain");
const {
  attestationReviewDigest,
  evaluateDiskLiveQualification,
  evaluateLiveQualification,
  parseArguments: parseChecklistArguments,
  qualificationEvidenceManifest,
  requiredLiveWorkflowIds,
} = require("../scripts/quality/release-checklist");
const {
  AUTHENTICATED_EXPOSURE_RESULT,
  assertExposureReceipt,
} = require("../scripts/quality/authenticated-exposure-scan");
const {
  RELEASE_EXPOSURE_RESULT,
  buildReleaseExposureResult,
} = require("../scripts/quality/release-exposure-scan");
const { UI_RESULT } = require("../scripts/quality/verify-ui-evidence");
const {
  discoverUiArtifacts,
  expectedBlackBoxUiTests,
  generateReport,
  hasDeterministicReportFailure,
  renderMarkdown,
  validateFindingRecord,
  validateFindings,
  validateImpactArtifact,
  writeReport,
} = require("../scripts/quality/report");
const { verifyQualityContracts } = require("../scripts/quality/verify-workflows");
const { verifyEvidenceHandoff } = require("../scripts/quality/verify-handoff");
const {
  validateMutationEvidenceArtifacts,
} = require("../scripts/quality/verify-mutation-handoff");
const TEST_INVENTORIES = require("./testInventories");

const root = path.resolve(__dirname, "..");
const SOURCE_SHA = "1111111111111111111111111111111111111111";
const BASE_SHA = "2222222222222222222222222222222222222222";
const SOURCE_IDENTITY = Object.freeze({
  sha: SOURCE_SHA,
  fingerprint: "a".repeat(64),
});
const LIVE_FIXTURE_NOW = new Date("2026-08-26T00:03:00.000Z");
const QUALITY_FIXTURE_HOME = fs.realpathSync(os.tmpdir());

function analyzeFiles(files) {
  const changeSet = explicitChanges(files, {
    root,
    sourceSha: SOURCE_SHA,
    base: "fixture-base",
    baseSha: BASE_SHA,
  });
  return analyzeImpact({
    root,
    changeSet,
    fileStates: Object.fromEntries(
      changeSet.files.map(file => [file, `fixture:${file}`])
    ),
  });
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function passedReceipt(step, source = SOURCE_IDENTITY) {
  const artifactFingerprints = {
    "change-impact": mutationArtifactFingerprint(validImpact()),
    "secret-current": mutationArtifactFingerprint(validSecretReceipt("current")),
    "secret-artifacts": mutationArtifactFingerprint(validSecretReceipt("artifacts")),
    "secret-history": mutationArtifactFingerprint(validSecretReceipt("history")),
    "secret-release": "9".repeat(64),
    "changed-mutation": mutationArtifactFingerprint(validMutationSummary()),
    "black-box-ui-smoke": mutationArtifactFingerprint(validUiResult()),
    "release-checklist": mutationArtifactFingerprint(validLiveStatus()),
    "quality-report": "e".repeat(64),
  };
  return {
    stepId: step.id,
    category: step.category,
    command: step.command,
    status: "passed",
    exitCode: 0,
    signal: null,
    reason: null,
    testCounts: null,
    testEvidence: step.evidencePath ? testEvidence(step, source) : null,
    artifactFingerprint: step.artifactPath || step.artifactPaths
      ? artifactFingerprints[step.id]
      : null,
    source,
  };
}

function testEvidence(step, source = SOURCE_IDENTITY) {
  const inventory = {
    "standalone-tests": TEST_INVENTORIES.STANDALONE_NODE_TESTS,
    "extension-host-core": TEST_INVENTORIES.VSCODE_CORE_TESTS,
    "extension-host-smoke": TEST_INVENTORIES.VSCODE_SMOKE_TESTS,
  }[step.id] || ["test/placeholder.test.js"];
  const tests = inventory.map(file => ({
    file,
    title: `fixture for ${file}`,
    fullTitle: `fixture suite fixture for ${file}`,
    status: "passed",
  }));
  return {
    schemaVersion: 1,
    tool: {
      core: "@stryker-mutator/core",
      version: "10.0.0",
      runner: "@stryker-mutator/mocha-runner",
      runnerVersion: "10.0.0",
      engine: "mocha",
      engineVersion: "11.8.0",
    },
    source,
    suite: step.id,
    counts: { passed: tests.length, failed: 0, pending: 0 },
    tests,
  };
}

function validLiveStatus(overrides = {}) {
  const qualificationProfileRoot = path.join(
    QUALITY_FIXTURE_HOME,
    ".cloudsmith-vscode-qualification",
  );
  const localCandidateReceipt = validCandidateReceipt({
    vscode: { version: "1.134.0", executable: "/bounded/code", cli: "/bounded/cli" },
    profile: {
      mode: "local",
      persistent: true,
      root: qualificationProfileRoot,
      testResourcesDir: qualificationProfileRoot,
      userDataDir: path.join(qualificationProfileRoot, "user-data"),
      extensionsDir: path.join(qualificationProfileRoot, "extensions"),
    },
  });
  const value = {
    schemaVersion: 3,
    source: SOURCE_IDENTITY,
    candidate: candidateBindingFromReceipt(localCandidateReceipt, {
      source: SOURCE_IDENTITY,
      homeDirectory: QUALITY_FIXTURE_HOME,
    }),
    inputPath: "internal_docs/quality/live-qualification.json",
    status: "passed",
    authenticatedAcceptance: "recorded",
    verdict: "TEAM-TEST READY",
    requiredWorkflowIds: [],
    passedWorkflowIds: [],
    missingWorkflowIds: [],
    attestationFingerprint: "c".repeat(64),
    evidenceManifest: [{
      path: "internal_docs/quality/findings.jsonl",
      sha256: crypto.createHash("sha256").update("[]").digest("hex"),
    }],
    findingsFingerprint: crypto.createHash("sha256").update("[]").digest("hex"),
    openReleaseBlockerCount: 0,
    visibleEnabledActions: { status: "passed", silentNoOpCount: 0 },
    reason: null,
    errors: [],
    ...overrides,
  };
  if (!Object.prototype.hasOwnProperty.call(overrides, "workflowMatrix")) {
    const passed = new Set(value.passedWorkflowIds);
    value.workflowMatrix = value.requiredWorkflowIds.map(id => ({
      id,
      status: passed.has(id) ? "PASS" : "BLOCKED",
    }));
  }
  return value;
}

function validCandidateReceipt(overrides = {}) {
  const base = {
    schemaVersion: 2,
    status: "passed",
    capturedAt: "2026-08-27T00:00:00.000Z",
    source: SOURCE_IDENTITY,
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
    vscode: {
      version: "1.131.0",
      executable: "/bounded/code",
      cli: "/bounded/cli",
    },
    profile: {
      mode: "ci",
      persistent: false,
      root: "/bounded/profile",
      testResourcesDir: "/bounded/profile",
      userDataDir: "/bounded/profile/settings",
      extensionsDir: "/bounded/profile/extensions",
    },
    artifact: {
      vsixPath: "out/development/cloudsmith-vsc-2.3.0.vsix",
      absoluteVsixPath: "/bounded/out/development/cloudsmith-vsc-2.3.0.vsix",
      sha256: "3".repeat(64),
      archiveBytes: 1,
      entryCount: 1,
      sourceSha: SOURCE_SHA,
      sourceFingerprint: SOURCE_IDENTITY.fingerprint,
    },
    installation: {
      status: "passed",
      id: "Cloudsmith.cloudsmith-vsc",
      version: "2.3.0",
    },
    launch: { status: "not-requested", developmentPath: false },
    ...overrides,
  };
  return { ...base, fingerprint: fingerprint(base) };
}

function validUiResult(tests = ["fixture"], overrides = {}) {
  const sortedTests = uniqueSorted(tests);
  const candidateReceipt = validCandidateReceipt();
  return {
    schemaVersion: 2,
    status: "passed",
    source: SOURCE_IDENTITY,
    sourceSha: SOURCE_SHA,
    tool: "vscode-extension-tester",
    toolVersion: "8.24.0",
    vscodeVersion: "1.131.0",
    platform: "darwin",
    architecture: "arm64",
    launchAttempted: true,
    tests: sortedTests,
    results: sortedTests.map(name => ({ name, status: "passed" })),
    candidate: {
      candidateReceiptFingerprint: candidateReceipt.fingerprint,
      extensionId: candidateReceipt.extension.id,
      extensionVersion: candidateReceipt.extension.version,
      profileMode: candidateReceipt.profile.mode,
      sourceFingerprint: candidateReceipt.source.fingerprint,
      sourceSha: candidateReceipt.source.sha,
      vscodeVersion: candidateReceipt.vscode.version,
      vsixSha256: candidateReceipt.artifact.sha256,
    },
    reason: null,
    ...overrides,
  };
}

function blockedUiResult(overrides = {}) {
  return {
    schemaVersion: 2,
    status: "blocked",
    source: SOURCE_IDENTITY,
    sourceSha: SOURCE_SHA,
    tool: null,
    toolVersion: null,
    vscodeVersion: null,
    platform: null,
    architecture: null,
    launchAttempted: false,
    tests: [],
    results: [],
    candidate: null,
    reason: "Black-box UI qualification is blocked by the current host environment.",
    ...overrides,
  };
}

function validSecretReceipt(mode) {
  return {
    schemaVersion: 1,
    scanner: {
      name: "gitleaks",
      version: "8.30.1",
      redactionPercent: 100,
      secretBearingFieldsPersisted: false,
    },
    mode,
    status: "passed",
    sourceSha: SOURCE_SHA,
    capturedAt: "2026-08-26T00:00:00.000Z",
    findingCount: 0,
    components: [],
    findings: [],
  };
}

function blackBoxFixtureWorkflows() {
  return {
    workflows: [{
      id: "WF-BLACK-BOX-FIXTURE",
      criticality: "release-critical",
      surface: "fixture",
      authoritativeOutcome: "fixture",
      requiredLayers: ["black-box-ui"],
      evidence: [{
        layer: "black-box-ui",
        interactionMode: "rendered-dom-activation",
        testFile: "ui-test/smoke.test.js",
        testNames: ["fixture"],
      }],
    }],
  };
}

function passedLiveAttestation(source = SOURCE_IDENTITY, now = LIVE_FIXTURE_NOW) {
  const workflows = require("../quality/critical-workflows.json");
  const fixtureRoot = fs.realpathSync(fs.mkdtempSync(path.join(
    os.tmpdir(),
    "cloudsmith-live-receipt-",
  )));
  const qualificationHomeDirectory = fixtureRoot;
  const qualificationProfileRoot = path.join(
    qualificationHomeDirectory,
    ".cloudsmith-vscode-qualification",
  );
  assert.strictEqual(require("child_process").spawnSync(
    "git",
    ["init", "-b", "test/release-quality-harness"],
    { cwd: fixtureRoot, stdio: "ignore" },
  ).status, 0);
  fs.writeFileSync(path.join(fixtureRoot, ".gitignore"), ".quality/\ninternal_docs/\n");
  fs.mkdirSync(path.join(fixtureRoot, "quality"), { recursive: true });
  fs.copyFileSync(path.join(root, "package.json"), path.join(fixtureRoot, "package.json"));
  for (const filename of [
    "critical-workflows.json",
    "defect-taxonomy.json",
    "finding.schema.json",
  ]) {
    fs.copyFileSync(
      path.join(root, "quality", filename),
      path.join(fixtureRoot, "quality", filename)
    );
  }
  const capturedAt = new Date(now.getTime() - 3 * 60 * 1000).toISOString();
  const completedAt = new Date(now.getTime() - 2 * 60 * 1000).toISOString();
  const reviewedAt = new Date(now.getTime() - 60 * 1000).toISOString();
  const evidenceReference = (relativePath, content, timestamp) => {
    const target = path.join(fixtureRoot, relativePath);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, content);
    return {
      path: relativePath,
      sha256: require("crypto").createHash("sha256").update(content).digest("hex"),
      capturedAt: timestamp,
    };
  };
  const qualificationEvidence = evidenceReference(
    "internal_docs/quality/e2e-evidence.md",
    "sanitized authoritative outcome fixture\n",
    capturedAt
  );
  const reviewEvidence = evidenceReference(
    "internal_docs/quality/release-readiness.md",
    "independent review fixture\n",
    reviewedAt
  );
  const findingsEvidence = evidenceReference(
    "internal_docs/quality/findings.jsonl",
    `${JSON.stringify({
      id: "QH-900",
      severity: "P3",
      domain: "documentation",
      status: "deferred",
      deterministicStatus: "not-applicable",
      liveStatus: "not-required",
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
      mutationProof: { status: "not-applicable", summary: "Not applicable to the fixture." },
      fixedSha: null,
      liveVerification: { summary: "No live verification is required for this fixture." },
      releaseBlocking: false,
    })}\n`,
    capturedAt
  );
  const candidateBytes = Buffer.from("live candidate fixture");
  const candidateBase = {
    schemaVersion: 2,
    status: "passed",
    capturedAt,
    source,
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
      root: qualificationProfileRoot,
      testResourcesDir: qualificationProfileRoot,
      userDataDir: path.join(qualificationProfileRoot, "user-data"),
      extensionsDir: path.join(qualificationProfileRoot, "extensions"),
    },
    artifact: {
      vsixPath: "out/development/cloudsmith-vsc-2.3.0.vsix",
      absoluteVsixPath: path.join(
        fixtureRoot,
        "out/development/cloudsmith-vsc-2.3.0.vsix",
      ),
      sha256: crypto.createHash("sha256").update(candidateBytes).digest("hex"),
      archiveBytes: candidateBytes.length,
      entryCount: 1,
      sourceSha: source.sha,
      sourceFingerprint: source.fingerprint,
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
  const candidateArtifactPath = path.join(fixtureRoot, LIVE_CANDIDATE_ARTIFACT);
  fs.mkdirSync(path.dirname(candidateArtifactPath), { recursive: true });
  fs.writeFileSync(candidateArtifactPath, candidateBytes);
  fs.writeFileSync(
    path.join(fixtureRoot, LIVE_CANDIDATE_RECEIPT),
    `${JSON.stringify(candidateReceipt, null, 2)}\n`
  );
  const authenticatedCandidateArtifactPath = path.join(
    fixtureRoot,
    AUTHENTICATED_CANDIDATE_ARTIFACT,
  );
  fs.writeFileSync(authenticatedCandidateArtifactPath, candidateBytes);
  fs.writeFileSync(
    path.join(fixtureRoot, AUTHENTICATED_CANDIDATE_RECEIPT),
    `${JSON.stringify(authenticatedCandidateReceipt, null, 2)}\n`,
  );
  const candidate = candidateBindingFromReceipt(candidateReceipt, {
    root: fixtureRoot,
    source,
    artifactPath: candidateArtifactPath,
    homeDirectory: qualificationHomeDirectory,
  });
  const authenticatedCandidate = candidateBindingFromReceipt(authenticatedCandidateReceipt, {
    root: fixtureRoot,
    source,
    artifactPath: authenticatedCandidateArtifactPath,
  });
  const authenticatedBase = {
    schemaVersion: 2,
    status: "passed",
    reasonCode: null,
    source,
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
    path.join(fixtureRoot, ".quality/qualification/authenticated-ci.json"),
    `${JSON.stringify(authenticatedReceipt, null, 2)}\n`
  );
  const authenticatedExposureBase = {
    schemaVersion: 2,
    status: "passed",
    sourceSha: source.sha,
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
  const authenticatedExposureReceipt = assertExposureReceipt({
    ...authenticatedExposureBase,
    fingerprint: fingerprint(authenticatedExposureBase),
  });
  fs.mkdirSync(path.join(fixtureRoot, ".quality/secrets"), { recursive: true });
  fs.writeFileSync(
    path.join(fixtureRoot, AUTHENTICATED_EXPOSURE_RESULT),
    `${JSON.stringify(authenticatedExposureReceipt, null, 2)}\n`,
  );
  const document = {
    schemaVersion: 5,
    source,
    candidate,
    status: "passed",
    authenticatedAcceptance: true,
    checklistConfirmed: true,
    operatorId: "fixture-qualification-operator",
    completedAt,
    summary: null,
    verdict: "TEAM-TEST READY WITH KNOWN NON-BLOCKING RISKS",
    evidence: [qualificationEvidence, findingsEvidence],
    findingsFingerprint: findingsEvidence.sha256,
    openReleaseBlockerCount: 0,
    workflowResults: requiredLiveWorkflowIds(workflows).map(id => ({
      id,
      status: "PASS",
      authoritativeOutcomeObserved: true,
      candidateReceiptFingerprint: candidate.receiptFingerprint,
      evidence: [qualificationEvidence],
    })),
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
    reviewerId: "fixture-independent-reviewer",
    source,
    reviewedAt,
    attestationSha256: attestationReviewDigest(document),
    evidence: [reviewEvidence],
  };
  return {
    cleanup: () => fs.rmSync(fixtureRoot, { force: true, recursive: true }),
    authenticatedExposureReceipt,
    authenticatedReceipt,
    authenticatedCandidateArtifactPath,
    authenticatedCandidateReceipt,
    candidateArtifactPath,
    candidateReceipt,
    document,
    attestationFingerprint: mutationArtifactFingerprint(document),
    qualificationHomeDirectory,
    root: fixtureRoot,
  };
}

function writeReleaseExposureFixture(fixture, document, inputPath) {
  const uiCandidateBytes = fs.readFileSync(fixture.authenticatedCandidateArtifactPath);
  const uiCandidateBase = clone(fixture.authenticatedCandidateReceipt);
  delete uiCandidateBase.fingerprint;
  uiCandidateBase.vscode.version = "1.131.0";
  const uiCandidateReceipt = {
    ...uiCandidateBase,
    fingerprint: fingerprint(uiCandidateBase),
  };
  fs.writeFileSync(path.join(fixture.root, UI_CANDIDATE_ARTIFACT), uiCandidateBytes);
  fs.writeFileSync(
    path.join(fixture.root, UI_CANDIDATE_RECEIPT),
    `${JSON.stringify(uiCandidateReceipt, null, 2)}\n`,
  );
  const tests = expectedBlackBoxUiTests(require("../quality/critical-workflows.json"));
  const uiResultBytes = Buffer.from(`${JSON.stringify({
    schemaVersion: 2,
    status: "passed",
    source: SOURCE_IDENTITY,
    sourceSha: SOURCE_IDENTITY.sha,
    tool: "vscode-extension-tester",
    toolVersion: "8.24.0",
    vscodeVersion: uiCandidateReceipt.vscode.version,
    platform: process.platform === "win32" ? "win32" : process.platform,
    architecture: process.arch === "arm64" ? "arm64" : "x64",
    launchAttempted: true,
    tests,
    results: tests.map(name => ({ name, status: "passed" })),
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
  const evidenceManifest = qualificationEvidenceManifest(document);
  const receipt = buildReleaseExposureResult({
    source: SOURCE_IDENTITY,
    candidateReceiptFingerprint: uiCandidateReceipt.fingerprint,
    vsixSha256: uiCandidateReceipt.artifact.sha256,
    uiResultSha256: crypto.createHash("sha256").update(uiResultBytes).digest("hex"),
    attestationPath: inputPath,
    attestationSha256: crypto.createHash("sha256").update(attestationBytes).digest("hex"),
    evidenceManifest,
    components: [
      {
        id: "post-ui-generated-quality-evidence",
        status: "scanned",
        fileCount: 3,
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
    now: LIVE_FIXTURE_NOW,
  });
  fs.writeFileSync(
    path.join(fixture.root, RELEASE_EXPOSURE_RESULT),
    `${JSON.stringify(receipt, null, 2)}\n`,
  );
}

function liveCandidateProof(fixture) {
  return {
    liveCandidateReceipt: fixture.candidateReceipt,
    liveCandidateArtifactPath: fixture.candidateArtifactPath,
    authenticatedReceipt: fixture.authenticatedReceipt,
    authenticatedExposureReceipt: fixture.authenticatedExposureReceipt,
    authenticatedCandidateReceipt: fixture.authenticatedCandidateReceipt,
    authenticatedCandidateArtifactPath: fixture.authenticatedCandidateArtifactPath,
    qualificationHomeDirectory: fixture.qualificationHomeDirectory,
  };
}

function validMutationSummary(overrides = {}) {
  return {
    status: "passed",
    mode: "changed",
    source: SOURCE_IDENTITY,
    sourceSha: SOURCE_SHA,
    targets: ["domain/packageActionCapabilities.js"],
    mutants: 10,
    killed: 9,
    survived: 1,
    timeout: 0,
    runtimeError: 0,
    compileError: 0,
    noCoverage: 0,
    ignored: 0,
    score: 90,
    files: {
      "domain/packageActionCapabilities.js": validMutationFile(90),
    },
    survivors: mutationSurvivors(1),
    ...overrides,
  };
}

function validMutationFile(score, overrides = {}) {
  return {
    mutants: 10,
    killed: 9,
    survived: 1,
    timeout: 0,
    runtimeError: 0,
    compileError: 0,
    noCoverage: 0,
    ignored: 0,
    score,
    ...overrides,
  };
}

function mutationSurvivors(
  count,
  target = "domain/packageActionCapabilities.js"
) {
  return Array.from({ length: count }, (_value, index) => ({
    fingerprint: index.toString(16).padStart(64, "0"),
    target,
    file: target.replace(/:\d+(?::\d+)?-\d+(?::\d+)?$/u, ""),
    line: index + 1,
    mutator: "FixtureMutator",
  }));
}

function mutationSummaryAt80(overrides = {}) {
  return validMutationSummary({
    killed: 8,
    survived: 2,
    score: 80,
    files: {
      "domain/packageActionCapabilities.js": validMutationFile(80, {
        killed: 8,
        survived: 2,
      }),
    },
    survivors: mutationSurvivors(2),
    ...overrides,
  });
}

function validMutationBaseline() {
  return {
    thresholds: { break: 90 },
    files: {
      "domain/packageActionCapabilities.js": { mutants: 10, score: 90 },
    },
  };
}

function validTrackedMutationBaseline() {
  const firstTarget = "domain/authCapabilities.js";
  const secondTarget = "util/externalNavigation.js";
  return {
    schemaVersion: 1,
    tool: {
      core: "@stryker-mutator/core",
      version: "10.0.0",
      runner: "@stryker-mutator/mocha-runner",
      runnerVersion: "10.0.0",
      engine: "mocha",
      engineVersion: "11.8.0",
      nodeVersion: "22.23.2",
    },
    measuredAtSha: SOURCE_SHA,
    scope: [firstTarget, secondTarget],
    metrics: {
      mutants: 4,
      killed: 2,
      survived: 2,
      timeout: 0,
      noCoverage: 0,
      runtimeError: 0,
      compileError: 0,
      ignored: 0,
      score: 50,
    },
    files: {
      [firstTarget]: {
        testFiles: ["test/authCapabilities.test.js"],
        mutants: 2,
        killed: 1,
        survived: 1,
        timeout: 0,
        noCoverage: 0,
        runtimeError: 0,
        compileError: 0,
        ignored: 0,
        score: 50,
      },
      [secondTarget]: {
        testFiles: ["test/externalNavigation.test.js"],
        mutants: 2,
        killed: 1,
        survived: 1,
        timeout: 0,
        noCoverage: 0,
        runtimeError: 0,
        compileError: 0,
        ignored: 0,
        score: 50,
      },
    },
    equivalentSurvivorClasses: [{
      class: "fixture-equivalent",
      count: 2,
      reason: "The fixture survivors are observably equivalent.",
    }],
    survivorClassifications: [
      { fingerprint: "a".repeat(64), class: "fixture-equivalent" },
      { fingerprint: "b".repeat(64), class: "fixture-equivalent" },
    ],
    meaningfulSurvivors: [],
    thresholds: { high: 95, low: 90, break: 50 },
  };
}

function rawMutationReport(baseline, targets, values) {
  const owners = uniqueSorted(baseline.scope.flatMap(
    target => baseline.files[target].testFiles
  ));
  const thresholds = {
    high: baseline.thresholds.high,
    low: baseline.thresholds.low,
    break: 0,
  };
  const report = {
    schemaVersion: "1.0",
    projectRoot: root,
    thresholds,
    framework: {
      name: "StrykerJS",
      version: baseline.tool.version,
      dependencies: {
        [baseline.tool.engine]: baseline.tool.engineVersion,
        [baseline.tool.runner]: baseline.tool.runnerVersion,
      },
    },
    config: {
      allowConsoleColors: true,
      appendPlugins: [],
      checkerNodeArgs: [],
      checkers: [],
      cleanTempDir: "always",
      clearTextReporter: {},
      commandRunner: { command: "npm test" },
      concurrency: 4,
      configFile: "stryker.config.mjs",
      mutate: [...targets],
      testRunner: "mocha",
      testFiles: owners,
      mochaOptions: {
        ui: "tdd",
        spec: owners,
        "no-config": true,
        "no-package": true,
        "no-opts": true,
      },
      coverageAnalysis: "perTest",
      dashboard: {},
      disableBail: false,
      disableTypeChecks: true,
      dryRunOnly: false,
      dryRunTimeoutMinutes: 5,
      eventReporter: {},
      fileLogLevel: "off",
      force: false,
      htmlReporter: { fileName: ".quality/mutation/mutation.html" },
      ignorePatterns: [
        ".vscode-test",
        ".quality",
        "internal_docs",
        "out",
        "coverage",
        "*.vsix",
      ],
      ignoreStatic: true,
      ignorers: [],
      inPlace: false,
      incremental: false,
      incrementalFile: ".quality/mutation/stryker-incremental.json",
      jsonReporter: { fileName: ".quality/mutation/mutation.json" },
      logLevel: "info",
      maxConcurrentTestRunners: Number.MAX_SAFE_INTEGER,
      maxTestRunnerReuse: 0,
      mutator: { plugins: null, excludedMutations: [] },
      plugins: ["@stryker-mutator/*"],
      reporters: ["clear-text", "progress", "json", "html"],
      symlinkNodeModules: true,
      tempDirName: ".stryker-tmp",
      testRunnerNodeArgs: [],
      allowEmpty: false,
      thresholds,
      timeoutFactor: 1.5,
      timeoutMS: 10_000,
      tsconfigFile: "tsconfig.json",
      warnings: true,
    },
    ...values,
  };
  for (const [file, value] of Object.entries(report.files || {})) {
    value.source ||= fs.readFileSync(path.join(root, file), "utf8");
    for (const mutant of value.mutants || []) {
      mutant.static ??= mutant.status === "Ignored";
      mutant.coveredBy ||= [];
      if (mutant.status === "Killed") {
        mutant.statusReason ||= "The mutation was rejected by its exact owner test.";
        mutant.testsCompleted ??= Math.max(1, mutant.killedBy?.length || 0);
      } else if (mutant.status === "Survived") {
        mutant.testsCompleted ??= mutant.coveredBy.length;
      } else if (mutant.status === "Ignored") {
        mutant.statusReason ||= "Static mutant (and \"ignoreStatic\" was enabled)";
      }
    }
  }
  for (const [file, value] of Object.entries(report.testFiles || {})) {
    value.source ||= fs.readFileSync(path.join(root, file), "utf8");
  }
  return report;
}

function mutationHandoffFixture(options = {}) {
  const mode = options.mode || "changed";
  const applicable = options.applicable !== false;
  const measured = require("../quality/mutation-baseline.json");
  const target = measured.scope[0];
  const sourceFile = target.replace(/:\d+-\d+$/u, "");
  const owner = measured.files[target].testFiles[0];
  const baseline = {
    tool: clone(measured.tool),
    scope: [target],
    files: {
      [target]: {
        testFiles: [owner],
        mutants: 1,
        killed: 1,
        survived: 0,
        timeout: 0,
        noCoverage: 0,
        runtimeError: 0,
        compileError: 0,
        ignored: 0,
        score: 100,
      },
    },
    survivorClassifications: [],
    equivalentSurvivorClasses: [],
    meaningfulSurvivors: [],
    thresholds: { high: 95, low: 90, break: 100 },
  };
  const source = sourceIdentity(root);
  const changedFiles = applicable ? [sourceFile] : ["README.md"];
  const selection = mode === "core" ? fullMutationSelection(root) : {
    mode: "explicit-files",
    base: null,
    baseSha: null,
    mergeBaseSha: null,
    changedFiles,
    fingerprint: workingTreeFingerprint(root, changedFiles),
  };
  if (!applicable) {
    const summary = mutationReceipt(mode, [], {
      status: "not-applicable",
      reason: "no-configured-mutation-target-changed",
      mutants: 0,
      killed: 0,
      survived: 0,
      timeout: 0,
      noCoverage: 0,
      runtimeError: 0,
      compileError: 0,
      ignored: 0,
      score: null,
      files: {},
      survivors: [],
      strykerExitCode: null,
    }, { source, selection, rawReportFingerprint: null });
    return { baseline, rawReportArtifact: null, selection, source, summary, target };
  }
  const rawReport = rawMutationReport(baseline, [target], {
    testFiles: { [owner]: { tests: [{ id: "mutation-owner-test" }] } },
    files: {
      [sourceFile]: {
        mutants: [{
          id: "mutation-handoff-mutant",
          status: "Killed",
          mutatorName: "StringLiteral",
          replacement: "\"handoff\"",
          static: false,
          statusReason: "The exact owner test rejected the mutation.",
          testsCompleted: 1,
          coveredBy: ["mutation-owner-test"],
          killedBy: ["mutation-owner-test"],
          location: {
            start: { line: 1, column: 0 },
            end: { line: 1, column: 1 },
          },
        }],
      },
    },
  });
  rawReport.config.incremental = mode === "changed";
  rawReport.config.force = mode === "changed";
  const rawReportArtifact = mutationRawArtifact(rawReport);
  const rawFingerprint = rawReportArtifact.fingerprint;
  const summary = mutationReceipt(mode, [target], {
    status: "passed",
    ...deriveMutationEvidence(rawReport, [target]),
    strykerExitCode: 0,
  }, { source, selection, rawReportFingerprint: rawFingerprint });
  return { baseline, rawReportArtifact, selection, source, summary, target };
}

function mutationRawArtifact(value) {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
  return {
    bytes,
    fingerprint: crypto.createHash("sha256").update(bytes).digest("hex"),
    value,
  };
}

function mutationArtifactFingerprint(value) {
  return crypto.createHash("sha256")
    .update(`${JSON.stringify(value, null, 2)}\n`)
    .digest("hex");
}

function validMutationEvidence(overrides = {}) {
  const mutation = validMutationSummary(overrides);
  return {
    mutation,
    mutationArtifactFingerprint: mutationArtifactFingerprint(mutation),
    mutationBaseline: validMutationBaseline(),
  };
}

function validImpactEvidence(overrides = {}) {
  const impact = validImpact(overrides);
  return {
    impact,
    impactArtifactFingerprint: mutationArtifactFingerprint(impact),
  };
}

function validImpact(overrides = {}) {
  const value = {
    schemaVersion: 1,
    source: {
      mode: "git",
      sha: SOURCE_SHA,
      fingerprint: SOURCE_IDENTITY.fingerprint,
      base: "origin/main",
      baseSha: BASE_SHA,
    },
    analysisScope: "complete-working-tree",
    changes: [],
    changedFiles: [],
    fileStates: [],
    runtimeFiles: [],
    testFiles: [],
    manifestFiles: [],
    workflows: [],
    workflowMappings: [],
    actions: [],
    requiredLayers: [],
    commands: [],
    workflowRiskClasses: [],
    riskCategories: [],
    unmappedRuntimeFiles: [],
    ok: true,
    ...overrides,
  };
  value.key = { sha: value.source.sha, fingerprint: impactFingerprint(value) };
  value.analysisKey = `${value.source.sha}:${value.key.fingerprint}`;
  return value;
}

function validFinding(overrides = {}) {
  return {
    id: "QH-900",
    severity: "P1",
    domain: "product",
    status: "open",
    deterministicStatus: "failing",
    liveStatus: "pending",
    surface: "Package Search",
    workflowContract: "WF-SEARCH-FIRST-PAGE",
    failureClasses: ["terminal-state"],
    customerImpact: "The current search may not publish a truthful terminal.",
    reproductionConfidence: "confirmed-repeatable",
    authoritativeExpectedOutcome: "The current query owns a terminal result.",
    observedOutcome: "The surface remained non-terminal.",
    firstKnownBadSha: null,
    evidence: [{
      kind: "test",
      location: "test/searchProvider.test.js",
      summary: "The authoritative assertion failed.",
    }],
    rootCauseStatus: "unknown",
    testLayerThatShouldHaveCaughtIt: "extension-host",
    whyItEscaped: "The old test stopped at dispatch.",
    regressionTest: null,
    mutationProof: { status: "not-started", summary: "Not run." },
    fixedSha: null,
    liveVerification: { summary: "Live verification is pending." },
    releaseBlocking: true,
    ...overrides,
  };
}

function createEvidenceHandoffFixture(options = {}) {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-handoff-"));
  const profile = "fast";
  const source = SOURCE_IDENTITY;
  const plan = getGatePlan(profile);
  fs.mkdirSync(path.join(fixtureRoot, "quality"), { recursive: true });
  fs.mkdirSync(path.join(fixtureRoot, "test"), { recursive: true });
  fs.copyFileSync(path.join(root, "package.json"), path.join(fixtureRoot, "package.json"));
  for (const filename of ["critical-workflows.json", "mutation-baseline.json"]) {
    fs.copyFileSync(
      path.join(root, "quality", filename),
      path.join(fixtureRoot, "quality", filename)
    );
  }
  fs.writeFileSync(
    path.join(fixtureRoot, "test", "testInventories.js"),
    `module.exports = ${JSON.stringify(TEST_INVENTORIES)};\n`
  );
  const impact = validImpact();
  writeJson(".quality/impact.json", impact, fixtureRoot);
  const impactArtifactFingerprint = mutationArtifactFingerprint(impact);
  const secretCurrent = validSecretReceipt("current");
  writeJson(".quality/secrets/current.json", secretCurrent, fixtureRoot);
  const secretCurrentArtifactFingerprint = mutationArtifactFingerprint(secretCurrent);
  let blocker = null;
  const receipts = plan.map(step => {
    if (blocker && !step.runWhenBlocked) {
      return {
        schemaVersion: 1,
        profile,
        sequence: step.sequence,
        stepId: step.id,
        category: step.category,
        command: step.command,
        source,
        status: "not-run",
        exitCode: null,
        signal: null,
        reason: `blocked-by:${blocker}`,
        testCounts: null,
        artifactFingerprint: null,
      };
    }
    const failed = options.failedStep === step.id;
    if (failed) blocker = step.id;
    return {
      schemaVersion: 1,
      profile,
      sequence: step.sequence,
      stepId: step.id,
      category: step.category,
      command: step.command,
      source,
      status: failed ? "failed" : "passed",
      exitCode: failed ? 1 : 0,
      signal: null,
      reason: null,
      testCounts: null,
      outputFingerprint: "d".repeat(64),
      testEvidence: step.evidencePath ? testEvidence(step) : null,
      artifactFingerprint: step.id === "change-impact"
        ? impactArtifactFingerprint
        : step.id === "secret-current"
          ? secretCurrentArtifactFingerprint
          : null,
    };
  });
  const workflows = require("../quality/critical-workflows.json");
  const report = generateReport({
    source,
    profile,
    plan,
    receipts,
    impact,
    impactArtifactFingerprint,
    mutationBaseline: require("../quality/mutation-baseline.json"),
    findings: [],
    findingsStatus: "not-run",
    workflows,
    inventories: TEST_INVENTORIES,
  });
  writeReport(report, { root: fixtureRoot });
  const reportStep = plan.find(step => step.id === "quality-report");
  const reportReceipt = receipts.find(receipt => receipt.stepId === "quality-report");
  reportReceipt.status = hasDeterministicReportFailure(report) ? "failed" : "passed";
  reportReceipt.exitCode = hasDeterministicReportFailure(report) ? 1 : 0;
  reportReceipt.artifactFingerprint = artifactFingerprintForStep(reportStep, fixtureRoot);
  for (const receipt of receipts) writeJson(receiptPath(receipt), receipt, fixtureRoot);
  const summary = {
    schemaVersion: 1,
    profile,
    source,
    status: aggregateStatuses(receipts.map(receipt => receipt.status)),
    planFingerprint: gatePlanFingerprint(plan),
    steps: receipts,
  };
  summary.key = { sha: source.sha, fingerprint: fingerprint(summary) };
  writeJson(`.quality/gates/${profile}.json`, summary, fixtureRoot);
  return {
    cleanup: () => fs.rmSync(fixtureRoot, { force: true, recursive: true }),
    profile,
    report,
    root: fixtureRoot,
    source,
    summary,
  };
}

suite("Quality change-impact analyzer", () => {
  test("uses the CI comparison SHA only as the default impact base", () => {
    const previous = process.env.QUALITY_BASE;
    process.env.QUALITY_BASE = "ci-before-sha";
    try {
      assert.strictEqual(parseImpactArguments([]).base, "ci-before-sha");
      assert.strictEqual(
        parseImpactArguments(["--base", "explicit-base"]).base,
        "explicit-base"
      );
    } finally {
      if (previous === undefined) delete process.env.QUALITY_BASE;
      else process.env.QUALITY_BASE = previous;
    }
  });

  test("maps Search production changes to search, pagination, action, and install contracts", () => {
    const report = analyzeFiles(["views/searchProvider.js"]);

    assert.strictEqual(report.ok, true);
    assert.deepStrictEqual(
      report.workflows.filter(id => id.startsWith("WF-SEARCH-")),
      ["WF-SEARCH-FIRST-PAGE", "WF-SEARCH-PAGINATION", "WF-SEARCH-SUPERSESSION"]
    );
    assert.ok(report.workflows.includes("WF-INSTALL-GUIDANCE"));
    assert.ok(report.actions.includes("ACT-SEARCH-INSPECT-PACKAGE"));
    assert.ok(report.actions.includes("ACT-SEARCH-SHOW-INSTALL"));
    assert.ok(report.requiredLayers.includes("extension-host"));
    assert.ok(report.requiredLayers.includes("live-protocol"));
    assert.ok(report.commands.includes("npm run test:vscode"));
    assert.ok(report.riskCategories.includes("query-construction"));
    assert.ok(report.riskCategories.includes("pagination"));
    assert.ok(report.riskCategories.includes("install-commands"));
  });

  test("maps connection-status presentation changes to authentication-state evidence", () => {
    const report = analyzeFiles(["models/connectionStatusNode.js"]);

    assert.strictEqual(report.ok, true);
    assert.ok(report.workflows.includes("WF-AUTH-STATE"));
    assert.ok(report.requiredLayers.includes("extension-host"));
    assert.ok(report.requiredLayers.includes("live-protocol"));
    assert.ok(report.commands.includes("npm run test:vscode"));
  });

  test("maps a scripted WebView provider to reciprocal cross-WebView action contracts", () => {
    const report = analyzeFiles(["views/quarantineExplainProvider.js"]);

    assert.strictEqual(report.ok, true);
    assert.ok(report.workflows.includes("WF-QUARANTINE-EXPLANATION"));
    assert.ok(report.workflows.includes("WF-QUARANTINE-TO-VULNERABILITIES"));
    assert.ok(report.workflows.includes("WF-VULNERABILITY-TO-QUARANTINE"));
    assert.ok(report.actions.includes("ACT-QUARANTINE-SHOW-VULNERABILITIES"));
    assert.ok(report.actions.includes("ACT-VULNERABILITY-EXPLAIN-QUARANTINE"));
    assert.ok(report.riskCategories.includes("webviews"));
    assert.ok(report.riskCategories.includes("url-redirect-handling"));
  });

  test("treats package.json as command, action, menu, settings, and UI impact", () => {
    const report = analyzeFiles(["package.json"]);

    assert.strictEqual(report.ok, true);
    assert.ok(report.workflows.includes("WF-ACTIVATION-STARTUP"));
    assert.ok(report.workflows.includes("WF-SETTINGS"));
    assert.ok(report.workflows.includes("WF-HELP-NAVIGATION"));
    assert.ok(report.actions.includes("ACT-SETTINGS-OPEN"));
    assert.ok(report.actions.includes("ACT-HELP-DOCUMENTATION"));
    assert.ok(report.actions.includes("ACT-QUARANTINE-SHOW-VULNERABILITIES"));
    assert.ok(report.requiredLayers.includes("black-box-ui"));
    assert.ok(report.commands.includes("npm run test:ui:smoke"));
    assert.ok(report.riskCategories.includes("commands"));
    assert.ok(report.riskCategories.includes("context-value-menu-when"));
  });

  test("hard-fails an unmapped runtime file while retaining deterministic evidence", () => {
    const first = analyzeFiles(["util/newUnmappedRuntime.js"]);
    const second = analyzeFiles(["util/newUnmappedRuntime.js"]);

    assert.strictEqual(first.ok, false);
    assert.deepStrictEqual(first.unmappedRuntimeFiles, ["util/newUnmappedRuntime.js"]);
    assert.strictEqual(first.analysisKey, second.analysisKey);
    assert.strictEqual(first.key.sha, SOURCE_SHA);
    assert.match(first.key.fingerprint, /^[a-f0-9]{64}$/);
    assert.throws(
      () => requireMappedRuntime(first),
      error => error instanceof ImpactAnalysisError
        && /no workflow mapping/.test(error.message)
        && error.report === first
    );
  });

  test("test-only Search changes select owning evidence without a live gate", () => {
    const report = analyzeFiles(["test/searchProvider.test.js"]);

    assert.strictEqual(report.ok, true);
    assert.deepStrictEqual(report.workflows, [
      "WF-SEARCH-FIRST-PAGE",
      "WF-SEARCH-PAGINATION",
      "WF-SEARCH-SUPERSESSION",
    ]);
    assert.ok(report.requiredLayers.includes("extension-host"));
    assert.ok(!report.requiredLayers.includes("live-protocol"));
    assert.deepStrictEqual(report.commands, ["npm run test:vscode"]);
    assert.ok(!report.commands.includes("npm run test:live"));
  });

  test("maps shared WebView helpers to their Extension Host evidence owners", () => {
    const report = analyzeFiles(["test/helpers/webviewPanelHarness.js"]);

    assert.strictEqual(report.ok, true);
    assert.ok(report.workflows.includes("WF-QUARANTINE-EXPLANATION"));
    assert.ok(report.workflows.includes("WF-VULNERABILITY-TRUTH"));
    assert.deepStrictEqual(report.requiredLayers, ["contract", "extension-host"]);
    assert.deepStrictEqual(report.commands, ["npm run test:vscode"]);
  });

  test("parses deleted and renamed git records without losing either rename path", () => {
    const records = parseNameStatus(
      "D\0util/deleted.js\0R100\0views/oldProvider.js\0views/newProvider.js\0",
      "fixture"
    );

    assert.deepStrictEqual(records, [
      { source: "fixture", status: "D", path: "util/deleted.js" },
      {
        source: "fixture",
        status: "R100",
        oldPath: "views/oldProvider.js",
        newPath: "views/newProvider.js",
      },
    ]);
  });

  test("unions committed, staged, unstaged, and untracked git paths", () => {
    const outputs = new Map([
      ["rev-parse --verify HEAD", `${SOURCE_SHA}\n`],
      ["merge-base fixture-base HEAD", `${BASE_SHA}\n`],
      [
        "diff --name-status -z --find-renames fixture-base...HEAD",
        "M\0views/searchProvider.js\0",
      ],
      [
        "diff --cached --name-status -z --find-renames",
        "D\0util/deleted.js\0",
      ],
      [
        "diff --name-status -z --find-renames",
        "R100\0views/oldProvider.js\0views/newProvider.js\0",
      ],
      [
        "ls-files --others --exclude-standard -z",
        "commands/untracked.js\0",
      ],
    ]);
    const spawnSync = (_command, args) => ({
      status: 0,
      signal: null,
      stdout: outputs.get(args.join(" ")) || "",
      stderr: "",
    });

    const changes = collectGitChanges({ root, base: "fixture-base", spawnSync });

    assert.deepStrictEqual(changes.files, [
      "commands/untracked.js",
      "util/deleted.js",
      "views/newProvider.js",
      "views/oldProvider.js",
      "views/searchProvider.js",
    ]);
    assert.deepStrictEqual(
      [...new Set(changes.records.map(record => record.source))].sort(),
      ["committed", "staged", "unstaged", "untracked"]
    );
  });

  test("carries mapped ownership across a production rename", () => {
    const oldPath = "views/legacySearchProvider.js";
    const newPath = "views/searchProvider.js";
    const report = analyzeImpact({
      root,
      changeSet: {
        mode: "explicit",
        base: "fixture-base",
        baseSha: BASE_SHA,
        sourceSha: SOURCE_SHA,
        records: [{
          source: "fixture",
          status: "R100",
          oldPath,
          newPath,
        }],
        files: [oldPath, newPath],
      },
      fileStates: {
        [oldPath]: "missing",
        [newPath]: "fixture:new-search-provider",
      },
    });

    assert.strictEqual(report.ok, true);
    assert.deepStrictEqual(report.unmappedRuntimeFiles, []);
    const firstPage = report.workflowMappings.find(
      workflow => workflow.id === "WF-SEARCH-FIRST-PAGE"
    );
    assert.deepStrictEqual(firstPage.productionFiles, [oldPath, newPath]);
  });
});

suite("Quality gate runner", () => {
  test("non-auth process environment uses a credential-free closed allowlist", () => {
    assert.strictEqual(
      [...NON_AUTH_QUALITY_ENVIRONMENT_ALLOWLIST, ...NON_AUTH_QUALITY_OVERRIDE_NAMES]
        .some(name => CREDENTIAL_LIKE_ENVIRONMENT_NAME.test(name)),
      false
    );
    const sanitized = buildNonAuthQualityEnvironment({
      PATH: "/fixture/bin",
      QUALITY_BASE: "fixture-base",
      CLOUDSMITH_API_KEY: "synthetic-qh141-helper-sentinel",
      NODE_OPTIONS: "--require=synthetic-untrusted-hook",
      HOME: "/untrusted/profile",
    }, {
      CLOUDSMITH_QUALITY_TEST_SUITE: "fixture-suite",
    });
    assert.deepStrictEqual(sanitized, {
      PATH: "/fixture/bin",
      QUALITY_BASE: "fixture-base",
      CLOUDSMITH_QUALITY_TEST_SUITE: "fixture-suite",
    });
    assert.strictEqual(Object.isFrozen(sanitized), true);
    assert.throws(
      () => buildNonAuthQualityEnvironment({}, {
        CLOUDSMITH_API_KEY: "synthetic-qh141-rejected-override",
      }),
      /override is unsafe/u
    );
    assert.throws(
      () => buildNonAuthQualityEnvironment({
        PATH: "/fixture/one",
        Path: "/fixture/two",
      }, {}, { platform: "win32" }),
      /case-colliding key/u
    );

    const gitChildEnvironments = [];
    const identity = sourceIdentity(root, (_command, arguments_, options) => {
      gitChildEnvironments.push(options.env);
      return {
        status: 0,
        signal: null,
        error: null,
        stdout: arguments_[0] === "rev-parse" ? `${SOURCE_SHA}\n` : Buffer.alloc(0),
        stderr: options.encoding === null ? Buffer.alloc(0) : "",
      };
    }, {
      PATH: "/fixture/bin",
      CLOUDSMITH_API_KEY: "synthetic-qh141-source-sentinel",
    });
    assert.strictEqual(identity.sha, SOURCE_SHA);
    assert.deepStrictEqual(gitChildEnvironments, [
      { PATH: "/fixture/bin" },
      { PATH: "/fixture/bin" },
      { PATH: "/fixture/bin" },
    ]);
    assert.strictEqual(
      JSON.stringify(identity).includes("synthetic-qh141-source-sentinel"),
      false
    );
  });

  test("composes fast, full, and release plans without hiding either Extension Host label", () => {
    const fast = getGatePlan("fast");
    const full = getGatePlan("full");
    const release = getGatePlan("release");
    const fastIds = fast.map(step => step.id);
    const fullWithoutReport = full.filter(step => step.id !== "quality-report");
    const releaseWithoutFinalizers = release.filter(step => ![
      "black-box-ui-smoke",
      "secret-release",
      "release-checklist",
      "secret-history",
      "quality-report",
    ].includes(step.id));

    assert.deepStrictEqual(fastIds, [
      "quality-contract-verifier",
      "secret-current",
      "change-impact",
      "repository-check",
      "standalone-tests",
      "quality-report",
    ]);
    assert.deepStrictEqual(
      fullWithoutReport.slice(0, fast.length - 1).map(step => step.id),
      fastIds.slice(0, -1)
    );
    assert.deepStrictEqual(
      releaseWithoutFinalizers.map(step => step.id),
      fullWithoutReport.map(step => step.id)
    );
    assert.deepStrictEqual(
      full.find(step => step.id === "extension-host-core").args.slice(-2),
      ["--label", "core"]
    );
    assert.deepStrictEqual(
      full.find(step => step.id === "extension-host-smoke").args.slice(-2),
      ["--label", "smoke"]
    );
    for (const id of [
      "runtime-audit",
      "development-audit",
      "zero-test-guard",
      "changed-mutation",
      "package-build",
      "package-verify",
      "package-list",
      "secret-artifacts",
    ]) assert.ok(full.some(step => step.id === id), `missing full gate step ${id}`);
    assert.deepStrictEqual(release.slice(-5).map(step => step.id), [
      "black-box-ui-smoke",
      "secret-release",
      "release-checklist",
      "secret-history",
      "quality-report",
    ]);
    assert.strictEqual(
      release.find(step => step.id === "release-checklist").artifactPath,
      ".quality/gates/live-qualification-status.json"
    );
  });

  test("writes receipts and cannot turn a nonzero command into a passing gate", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-quality-gate-"));
    try {
      const staleReceipt = path.join(
        temporaryRoot,
        ".quality/gates/fast/99-obsolete-plan-receipt.json"
      );
      fs.mkdirSync(path.dirname(staleReceipt), { recursive: true });
      fs.writeFileSync(staleReceipt, "stale receipt\n");
      const summary = runGate({
        root: temporaryRoot,
        profile: "fast",
        source: SOURCE_IDENTITY,
        execute(step) {
          return {
            status: step.id === "repository-check" ? 7 : 0,
            signal: null,
            stdout: step.id === "repository-check" ? "1 failing\n" : "2 passing\n",
            stderr: "",
            testEvidence: step.evidencePath ? testEvidence(step) : null,
            artifactFingerprint: step.artifactPath || step.artifactPaths
              ? "b".repeat(64)
              : null,
          };
        },
      });

      assert.strictEqual(summary.status, "failed");
      const failed = summary.steps.find(step => step.stepId === "repository-check");
      assert.strictEqual(failed.status, "failed");
      assert.strictEqual(
        summary.steps.find(step => step.stepId === "standalone-tests").status,
        "not-run"
      );
      const target = path.join(temporaryRoot, receiptPath(failed));
      assert.strictEqual(JSON.parse(fs.readFileSync(target, "utf8")).exitCode, 7);
      assert.strictEqual(fs.existsSync(staleReceipt), false);
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("removes stale mutation artifacts and receipts the exact replacement bytes", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-artifact-gate-"));
    const artifactPath = ".quality/mutation/summary-changed.json";
    const target = path.join(temporaryRoot, artifactPath);
    const step = {
      id: "changed-mutation",
      category: "mutation",
      executable: "node",
      args: ["-e", "process.exit(0)"],
      command: "node fixture",
      artifactPath,
      blockedExitCodes: [],
      sequence: 1,
    };
    try {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, "stale artifact\n");
      const missing = executeCommand(step, {
        root: temporaryRoot,
        source: SOURCE_IDENTITY,
      });
      assert.match(missing.error.message, /missing-or-invalid-artifact/u);
      assert.strictEqual(fs.existsSync(target), false);
      assert.strictEqual(
        completedReceipt("full", step, SOURCE_IDENTITY, missing).status,
        "failed"
      );

      const bytes = "fresh mutation summary\n";
      const produced = executeCommand({
        ...step,
        args: [
          "-e",
          `require("fs").mkdirSync(".quality/mutation", { recursive: true }); require("fs").writeFileSync(${JSON.stringify(artifactPath)}, ${JSON.stringify(bytes)});`,
        ],
      }, {
        root: temporaryRoot,
        source: SOURCE_IDENTITY,
      });
      assert.strictEqual(
        produced.artifactFingerprint,
        crypto.createHash("sha256").update(bytes).digest("hex")
      );
      assert.strictEqual(
        completedReceipt("full", step, SOURCE_IDENTITY, produced).status,
        "passed"
      );
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("non-auth gate children cannot inherit credential-shaped ambient values", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-gate-env-"));
    const syntheticNames = [
      "CLOUDSMITH_API_KEY",
      "ARBITRARY_ACCESS_TOKEN",
      "FIXTURE_PASSWORD",
    ];
    const previous = Object.fromEntries(syntheticNames.map(name => [name, process.env[name]]));
    const step = {
      id: "fixture-environment-boundary",
      category: "security",
      executable: "node",
      args: [
        "-e",
        `const forbidden = ${JSON.stringify(syntheticNames)}; process.stdout.write(forbidden.some(name => Object.prototype.hasOwnProperty.call(process.env, name)) ? "unsafe-child-environment" : "safe-child-environment");`,
      ],
      command: "node credential-boundary-probe",
      blockedExitCodes: [],
      sequence: 1,
    };
    try {
      syntheticNames.forEach((name, index) => {
        process.env[name] = `synthetic-qh141-sentinel-${index}`;
      });
      const execution = executeCommand(step, {
        root: temporaryRoot,
        source: SOURCE_IDENTITY,
      });
      const receipt = completedReceipt("fast", step, SOURCE_IDENTITY, execution);
      assert.strictEqual(execution.stdout, "safe-child-environment");
      assert.strictEqual(receipt.status, "passed");
      assert.strictEqual(
        receipt.outputFingerprint,
        crypto.createHash("sha256").update("safe-child-environment").digest("hex")
      );
      for (const name of syntheticNames) {
        assert.strictEqual(JSON.stringify(execution).includes(process.env[name]), false);
        assert.strictEqual(JSON.stringify(receipt).includes(process.env[name]), false);
      }
    } finally {
      for (const name of syntheticNames) {
        if (previous[name] === undefined) delete process.env[name];
        else process.env[name] = previous[name];
      }
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("binds exact report JSON and Markdown bytes for handoff verification", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-report-bundle-"));
    const plan = getGatePlan("full");
    const reportStep = plan.find(step => step.id === "quality-report");
    const report = generateReport({
      source: SOURCE_IDENTITY,
      profile: "full",
      plan,
      receipts: plan.map(step => passedReceipt(step)),
      ...validImpactEvidence(),
      ...validMutationEvidence(),
      liveQualification: null,
      findings: [],
      findingsStatus: "not-run",
      workflows: { workflows: [] },
      inventories: TEST_INVENTORIES,
    });
    try {
      writeReport(report, { root: temporaryRoot });
      const artifactFingerprint = artifactFingerprintForStep(reportStep, temporaryRoot);
      const receipt = { artifactFingerprint };
      assert.strictEqual(validateArtifactBinding(receipt, reportStep, temporaryRoot), null);

      fs.appendFileSync(path.join(temporaryRoot, ".quality/report.json"), " ");
      assert.strictEqual(
        validateArtifactBinding(receipt, reportStep, temporaryRoot),
        "artifact-fingerprint-mismatch"
      );

      writeReport(report, { root: temporaryRoot });
      fs.appendFileSync(path.join(temporaryRoot, ".quality/report.md"), " ");
      assert.strictEqual(
        validateArtifactBinding(receipt, reportStep, temporaryRoot),
        "artifact-fingerprint-mismatch"
      );
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("verifies exact passing and trusted-failure evidence handoffs", () => {
    for (const failedStep of [null, "repository-check"]) {
      const fixture = createEvidenceHandoffFixture({ failedStep });
      try {
        const result = verifyEvidenceHandoff({
          root: fixture.root,
          profile: fixture.profile,
          source: fixture.source,
          readSource: () => fixture.source,
        });
        assert.strictEqual(
          result.summary.status,
          failedStep ? "failed" : "passed",
          JSON.stringify(fixture.report.releaseReadiness)
        );
      } finally {
        fixture.cleanup();
      }
    }
  });

  test("rejects one-byte report changes and missing report bundle members", () => {
    const fixture = createEvidenceHandoffFixture();
    try {
      fs.appendFileSync(path.join(fixture.root, ".quality/report.json"), " ");
      assert.throws(
        () => verifyEvidenceHandoff({
          root: fixture.root,
          profile: fixture.profile,
          source: fixture.source,
          readSource: () => fixture.source,
        }),
        /artifact quality-report is untrusted|report bundle is untrusted|canonical form/u
      );

      writeReport(fixture.report, { root: fixture.root });
      fs.appendFileSync(path.join(fixture.root, ".quality/report.md"), " ");
      assert.throws(
        () => verifyEvidenceHandoff({
          root: fixture.root,
          profile: fixture.profile,
          source: fixture.source,
          readSource: () => fixture.source,
        }),
        /artifact quality-report is untrusted|report bundle is untrusted|Markdown/u
      );

      writeReport(fixture.report, { root: fixture.root });
      fs.rmSync(path.join(fixture.root, ".quality/report.md"));
      assert.throws(
        () => verifyEvidenceHandoff({
          root: fixture.root,
          profile: fixture.profile,
          source: fixture.source,
          readSource: () => fixture.source,
        }),
        /artifact quality-report is untrusted|report bundle is untrusted|missing/u
      );
    } finally {
      fixture.cleanup();
    }
  });

  test("rejects stale, crossed, extra, and summary-divergent receipt evidence", () => {
    const attacks = [
      fixture => {
        fixture.summary.key.fingerprint = "0".repeat(64);
        writeJson(".quality/gates/fast.json", fixture.summary, fixture.root);
      },
      fixture => {
        const first = fixture.summary.steps[0];
        const second = fixture.summary.steps[1];
        writeJson(receiptPath(first), second, fixture.root);
        writeJson(receiptPath(second), first, fixture.root);
      },
      fixture => writeJson(
        ".quality/gates/fast/99-extra.json",
        { unexpected: true },
        fixture.root
      ),
    ];
    for (const attack of attacks) {
      const fixture = createEvidenceHandoffFixture();
      try {
        attack(fixture);
        assert.throws(() => verifyEvidenceHandoff({
          root: fixture.root,
          profile: fixture.profile,
          source: fixture.source,
          readSource: () => fixture.source,
        }), /summary key|receipt files|differs from the signed summary/u);
      } finally {
        fixture.cleanup();
      }
    }

    const stale = createEvidenceHandoffFixture();
    try {
      assert.throws(() => verifyEvidenceHandoff({
        root: stale.root,
        profile: stale.profile,
        readSource: () => ({ ...stale.source, fingerprint: "f".repeat(64) }),
      }), /current repository source/u);
    } finally {
      stale.cleanup();
    }
  });

  test("rejects a report exit tuple that contradicts regenerated failure evidence", () => {
    const fixture = createEvidenceHandoffFixture({ failedStep: "repository-check" });
    try {
      const reportReceipt = fixture.summary.steps.find(receipt => (
        receipt.stepId === "quality-report"
      ));
      reportReceipt.status = "passed";
      reportReceipt.exitCode = 0;
      fixture.summary.status = aggregateStatuses(
        fixture.summary.steps.map(receipt => receipt.status)
      );
      const unsigned = { ...fixture.summary };
      delete unsigned.key;
      fixture.summary.key = {
        sha: fixture.source.sha,
        fingerprint: fingerprint(unsigned),
      };
      writeJson(receiptPath(reportReceipt), reportReceipt, fixture.root);
      writeJson(".quality/gates/fast.json", fixture.summary, fixture.root);

      assert.throws(() => verifyEvidenceHandoff({
        root: fixture.root,
        profile: fixture.profile,
        source: fixture.source,
        readSource: () => fixture.source,
      }), /does not match the report's deterministic outcome/u);
    } finally {
      fixture.cleanup();
    }
  });

  test("binds the gate summary key to complete receipt evidence", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-summary-key-"));
    const plan = [{
      id: "fixture-step",
      category: "fixture",
      executable: "node",
      args: ["fixture"],
      command: "node fixture",
      blockedExitCodes: [],
      sequence: 1,
    }];
    try {
      const run = stdout => runGate({
        root: temporaryRoot,
        profile: "fast",
        plan,
        source: SOURCE_IDENTITY,
        execute: () => ({ status: 0, signal: null, stdout, stderr: "" }),
      });
      const first = run("first output");
      const second = run("second output");
      assert.notStrictEqual(first.steps[0].outputFingerprint, second.steps[0].outputFingerprint);
      assert.notStrictEqual(first.key.fingerprint, second.key.fingerprint);
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("fails closed when repository source changes during a gate step", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-quality-drift-"));
    let reads = 0;
    try {
      const summary = runGate({
        root: temporaryRoot,
        profile: "fast",
        source: SOURCE_IDENTITY,
        readSource() {
          reads += 1;
          return reads < 2
            ? SOURCE_IDENTITY
            : { ...SOURCE_IDENTITY, fingerprint: "b".repeat(64) };
        },
        execute() {
          return { status: 0, signal: null, stdout: "2 passing\n", stderr: "" };
        },
      });

      assert.strictEqual(summary.status, "failed");
      assert.strictEqual(summary.steps[0].status, "failed");
      assert.strictEqual(summary.steps[0].reason, "source-changed-during-step");
      assert.strictEqual(summary.steps[1].status, "not-run");
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("runs a required finalizer but fails its receipt after source drift", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-finalizer-drift-"));
    let reads = 0;
    let executions = 0;
    const plan = [{
      id: "fixture-finalizer",
      category: "report",
      command: "node fixture-finalizer.js",
      executable: "node",
      args: ["fixture-finalizer.js"],
      blockedExitCodes: [],
      runWhenBlocked: true,
      sequence: 1,
    }];
    try {
      const summary = runGate({
        root: temporaryRoot,
        profile: "full",
        plan,
        source: SOURCE_IDENTITY,
        readSource() {
          reads += 1;
          return { ...SOURCE_IDENTITY, fingerprint: "b".repeat(64) };
        },
        execute() {
          executions += 1;
          return { status: 0, signal: null, stdout: "", stderr: "" };
        },
      });

      assert.ok(reads >= 2);
      assert.strictEqual(executions, 1);
      assert.strictEqual(summary.steps[0].status, "failed");
      assert.strictEqual(summary.steps[0].reason, "source-changed-before-step");
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("runs checklist and report finalizers after a blocked UI smoke", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-quality-release-"));
    const called = [];
    try {
      const summary = runGate({
        root: temporaryRoot,
        profile: "release",
        source: SOURCE_IDENTITY,
        execute(step) {
          called.push(step.id);
          const blocked = ["black-box-ui-smoke", "release-checklist"].includes(step.id);
          return {
            status: blocked ? 2 : 0,
            signal: null,
            stdout: "",
            stderr: "",
            testEvidence: step.evidencePath ? testEvidence(step) : null,
            artifactFingerprint: step.artifactPath || step.artifactPaths
              ? "b".repeat(64)
              : null,
          };
        },
      });

      assert.strictEqual(summary.status, "blocked");
      assert.strictEqual(
        summary.steps.find(step => step.stepId === "black-box-ui-smoke").status,
        "blocked"
      );
      assert.ok(called.includes("release-checklist"));
      assert.ok(called.includes("quality-report"));
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });
});

suite("Quality mutation and UI harness boundaries", () => {
  test("keeps generated mutation sandboxes outside candidate-source linting", async () => {
    const { ESLint } = await import("eslint");
    const eslint = new ESLint({ cwd: root });

    assert.strictEqual(
      await eslint.isPathIgnored(path.join(root, ".stryker-tmp", "sandbox", "fixture.js")),
      true
    );
  });

  test("accepts a fully reconciled and source-reachable tracked mutation baseline", () => {
    let checkedSha = null;
    const result = validateMutationBaseline(validTrackedMutationBaseline(), {
      root,
      commitIsAncestor: sha => {
        checkedSha = sha;
        return true;
      },
    });

    assert.deepStrictEqual(result.errors, []);
    assert.strictEqual(checkedSha, SOURCE_SHA);
  });

  test("binds measured mutation tool versions to both package manifests", () => {
    const baseline = validTrackedMutationBaseline();
    const manifest = require("../package.json");
    const lockfile = require("../package-lock.json");
    assert.deepStrictEqual(validateMutationToolchain(baseline, manifest, lockfile), []);

    const packageDrift = clone(manifest);
    packageDrift.devDependencies[baseline.tool.core] = "10.0.1";
    assert.ok(validateMutationToolchain(baseline, packageDrift, lockfile).includes(
      "Mutation baseline @stryker-mutator/core version must match package.json exactly."
    ));

    const lockDrift = clone(lockfile);
    lockDrift.packages[`node_modules/${baseline.tool.runner}`].version = "10.0.1";
    assert.ok(validateMutationToolchain(baseline, manifest, lockDrift).includes(
      "Mutation baseline @stryker-mutator/mocha-runner version must match package-lock.json exactly."
    ));

    const measured = require("../quality/mutation-baseline.json");
    assert.doesNotThrow(() => assertCanonicalMutationRuntime(
      measured,
      root,
      { version: `v${measured.tool.nodeVersion}` }
    ));
    assert.throws(
      () => assertCanonicalMutationRuntime(measured, root, { version: "v99.0.0" }),
      /requires exact Node/u
    );
    const nodeDrift = clone(measured);
    nodeDrift.tool.nodeVersion = "22.23.1";
    assert.throws(
      () => assertCanonicalMutationRuntime(nodeDrift, root, { version: "v22.23.1" }),
      /from \.node-version/u
    );
  });

  test("derives Stryker targets and both test inventories from the measured baseline", async () => {
    const baseline = require("../quality/mutation-baseline.json");
    const config = (await import("../stryker.config.mjs")).default;
    const expectedOwners = uniqueSorted(baseline.scope.flatMap(
      target => baseline.files[target].testFiles
    ));

    assert.deepStrictEqual(config.mutate, baseline.scope);
    assert.deepStrictEqual([...config.testFiles], expectedOwners);
    assert.strictEqual(config.testFiles, config.mochaOptions.spec);
    assert.strictEqual(Object.isFrozen(config.testFiles), true);
  });

  test("direct mutation ownership validation rejects empty and mismatched baselines", () => {
    const empty = { scope: [], files: {} };
    assert.throws(
      () => assertMutationTestOwners(empty, root),
      /nonempty scope/u
    );

    const missing = validTrackedMutationBaseline();
    delete missing.files[missing.scope[0]];
    assert.throws(
      () => assertMutationTestOwners(missing, root),
      /exact target parity/u
    );

    const extra = validTrackedMutationBaseline();
    extra.files["domain/invented.js"] = clone(extra.files[extra.scope[0]]);
    assert.throws(
      () => assertMutationTestOwners(extra, root),
      /exact target parity/u
    );

    const duplicateOwner = validTrackedMutationBaseline();
    duplicateOwner.files[duplicateOwner.scope[0]].testFiles.push(
      duplicateOwner.files[duplicateOwner.scope[0]].testFiles[0]
    );
    assert.throws(
      () => assertMutationTestOwners(duplicateOwner, root),
      /unique test owners/u
    );
  });

  test("direct mutation entrypoints enforce complete baseline provenance", () => {
    const baseline = require("../quality/mutation-baseline.json");
    assert.doesNotThrow(() => assertValidMutationBaseline(baseline, root));

    const thresholdDrift = clone(baseline);
    thresholdDrift.thresholds.break = null;
    assert.throws(
      () => assertValidMutationBaseline(thresholdDrift, root),
      /break threshold must equal/u
    );

    const missingThreshold = clone(baseline);
    delete missingThreshold.thresholds.high;
    assert.throws(
      () => assertValidMutationBaseline(missingThreshold, root),
      /high and low thresholds/u
    );

    const unreachable = clone(baseline);
    unreachable.measuredAtSha = "0".repeat(40);
    assert.throws(
      () => assertValidMutationBaseline(unreachable, root),
      /reachable from current HEAD/u
    );
  });

  test("reconciles canonical mutation owners with raw per-test Stryker coverage", () => {
    const baseline = validTrackedMutationBaseline();
    const [firstTarget, secondTarget] = baseline.scope;
    const [firstOwner] = baseline.files[firstTarget].testFiles;
    const [secondOwner] = baseline.files[secondTarget].testFiles;
    const report = rawMutationReport(baseline, baseline.scope, {
      testFiles: {
        [firstOwner]: { tests: [{ id: "first-owner-test" }] },
        [secondOwner]: { tests: [{ id: "second-owner-test" }] },
      },
      files: {
        [firstTarget]: {
          mutants: [{
            id: "first-mutant",
            status: "Killed",
            mutatorName: "StringLiteral",
            replacement: "\"first\"",
            coveredBy: ["first-owner-test"],
            killedBy: ["first-owner-test"],
            location: { start: { line: 1, column: 0 }, end: { line: 1, column: 1 } },
          }],
        },
        [secondTarget]: {
          mutants: [{
            id: "second-mutant",
            status: "Killed",
            mutatorName: "StringLiteral",
            replacement: "\"second\"",
            coveredBy: ["second-owner-test"],
            killedBy: ["second-owner-test"],
            location: { start: { line: 1, column: 0 }, end: { line: 1, column: 1 } },
          }],
        },
      },
    });
    assert.doesNotThrow(() => validateMutationTestOwnership(
      report,
      baseline.scope,
      baseline
    ));

    const swapped = clone(baseline);
    swapped.files[firstTarget].testFiles = [secondOwner];
    swapped.files[secondTarget].testFiles = [firstOwner];
    assert.throws(
      () => validateMutationTestOwnership(report, swapped.scope, swapped),
      /observed test ownership/u
    );

    const unknown = clone(report);
    unknown.files[firstTarget].mutants[0].coveredBy = ["unknown-test-id"];
    unknown.files[firstTarget].mutants[0].killedBy = ["unknown-test-id"];
    assert.throws(
      () => validateMutationTestOwnership(unknown, baseline.scope, baseline),
      /unknown Stryker test ID/u
    );

    const impossibleLocation = clone(report);
    impossibleLocation.files[firstTarget].mutants[0].location.start.line = 999_999;
    impossibleLocation.files[firstTarget].mutants[0].location.end.line = 999_999;
    assert.throws(
      () => validateMutationTestOwnership(impossibleLocation, baseline.scope, baseline),
      /outside its declared range/u
    );

    const forgedFramework = clone(report);
    forgedFramework.framework.version = "99.0.0";
    assert.throws(
      () => validateMutationTestOwnership(forgedFramework, baseline.scope, baseline),
      /report provenance/u
    );

    const forgedScope = clone(report);
    forgedScope.config.mutate = ["domain/invented.js"];
    assert.throws(
      () => validateMutationTestOwnership(forgedScope, baseline.scope, baseline),
      /report provenance/u
    );

    const forgedEngine = clone(report);
    forgedEngine.framework.dependencies.mocha = "99.0.0";
    assert.throws(
      () => validateMutationTestOwnership(forgedEngine, baseline.scope, baseline),
      /report provenance/u
    );

    const hostileHook = clone(report);
    hostileHook.config.mochaOptions.require = ["test/hostile-hook.js"];
    assert.throws(
      () => validateMutationTestOwnership(hostileHook, baseline.scope, baseline),
      /report provenance/u
    );

    const incrementalCore = clone(report);
    incrementalCore.config.incremental = true;
    incrementalCore.config.force = true;
    assert.throws(
      () => validateMutationTestOwnership(incrementalCore, baseline.scope, baseline),
      /report provenance/u
    );
    assert.doesNotThrow(() => validateMutationTestOwnership(
      incrementalCore,
      baseline.scope,
      baseline,
      root,
      "changed"
    ));

    const duplicateMutant = clone(report);
    duplicateMutant.files[firstTarget].mutants.push({
      ...clone(duplicateMutant.files[firstTarget].mutants[0]),
    });
    assert.throws(
      () => validateMutationTestOwnership(duplicateMutant, baseline.scope, baseline),
      /duplicate raw mutant ID/u
    );

    duplicateMutant.files[firstTarget].mutants[1].id = "distinct-mutant-id";
    const duplicateLocation = duplicateMutant.files[firstTarget].mutants[1].location;
    duplicateMutant.files[firstTarget].mutants[1].location = {
      end: {
        column: duplicateLocation.end.column,
        line: duplicateLocation.end.line,
      },
      start: {
        column: duplicateLocation.start.column,
        line: duplicateLocation.start.line,
      },
    };
    assert.throws(
      () => validateMutationTestOwnership(duplicateMutant, baseline.scope, baseline),
      /duplicate raw mutant semantics/u
    );

    const hybridKilled = clone(report);
    hybridKilled.files[firstTarget].mutants[0].static = true;
    assert.doesNotThrow(() => validateMutationTestOwnership(
      hybridKilled,
      baseline.scope,
      baseline
    ));

    const killedWithoutProof = clone(report);
    delete killedWithoutProof.files[firstTarget].mutants[0].killedBy;
    assert.throws(
      () => validateMutationTestOwnership(killedWithoutProof, baseline.scope, baseline),
      /status-specific raw mutant evidence/u
    );
  });

  test("binds ranged mutation targets to raw mutant locations", () => {
    const target = "util/upstreamOperationScheduler.js:141-219";
    const owner = "test/upstreamOperationScheduler.test.js";
    const baseline = {
      tool: {
        core: "@stryker-mutator/core",
        version: "10.0.0",
        runner: "@stryker-mutator/mocha-runner",
        runnerVersion: "10.0.0",
        engine: "mocha",
        engineVersion: "11.8.0",
        nodeVersion: "22.23.2",
      },
      scope: [target],
      files: { [target]: { testFiles: [owner] } },
      thresholds: { high: 95, low: 90 },
    };
    const report = rawMutationReport(baseline, [target], {
      testFiles: { [owner]: { tests: [{ id: "range-owner" }] } },
      files: {
        "util/upstreamOperationScheduler.js": {
          mutants: [{
            id: "range-mutant",
            status: "Killed",
            mutatorName: "StringLiteral",
            replacement: "\"range\"",
            coveredBy: ["range-owner"],
            killedBy: ["range-owner"],
            location: {
              start: { line: 141, column: 0 },
              end: { line: 219, column: 1 },
            },
          }],
        },
      },
    });
    assert.doesNotThrow(() => validateMutationTestOwnership(report, [target], baseline));

    const endLine = fs.readFileSync(
      path.join(root, "util/upstreamOperationScheduler.js"),
      "utf8"
    ).split("\n")[218];
    const onePastEnd = clone(report);
    onePastEnd.files["util/upstreamOperationScheduler.js"]
      .mutants[0].location.end.column = endLine.length + 1;
    assert.doesNotThrow(() => validateMutationTestOwnership(
      onePastEnd,
      [target],
      baseline
    ));
    onePastEnd.files["util/upstreamOperationScheduler.js"]
      .mutants[0].location.end.column = endLine.length + 2;
    assert.throws(
      () => validateMutationTestOwnership(onePastEnd, [target], baseline),
      /outside its declared range/u
    );

    const outside = clone(report);
    outside.files["util/upstreamOperationScheduler.js"].mutants[0].location.start.line = 1;
    assert.throws(
      () => validateMutationTestOwnership(outside, [target], baseline),
      /outside its declared range/u
    );
  });

  test("rejects column-qualified mutation ranges instead of discarding their columns", () => {
    const baseline = validTrackedMutationBaseline();
    const original = baseline.scope[0];
    const columnTarget = `${original}:1:2-1:8`;
    baseline.scope[0] = columnTarget;
    baseline.files[columnTarget] = baseline.files[original];
    delete baseline.files[original];

    assert.ok(validateMutationBaseline(baseline, {
      root,
      commitIsAncestor: () => true,
    }).errors.some(error => /invalid target/u.test(error)));
    assert.throws(
      () => assertMutationTestOwners(baseline, root),
      /must exist as a Git-visible regular source file/u
    );

    for (const invalidRange of [`${original}:0-10`, `${original}:20-10`]) {
      const invalid = validTrackedMutationBaseline();
      invalid.scope[0] = invalidRange;
      invalid.files[invalidRange] = invalid.files[original];
      delete invalid.files[original];
      assert.ok(validateMutationBaseline(invalid, {
        root,
        commitIsAncestor: () => true,
      }).errors.some(error => /invalid target/u.test(error)));
    }

    const traversal = validTrackedMutationBaseline();
    const traversalTarget = "domain/../../outside.js";
    traversal.scope[0] = traversalTarget;
    traversal.files[traversalTarget] = traversal.files[original];
    delete traversal.files[original];
    assert.throws(
      () => assertMutationTestOwners(traversal, root),
      /Git-visible regular source file/u
    );
  });

  test("rejects missing, abbreviated, and unreachable baseline provenance", () => {
    for (const measuredAtSha of [null, SOURCE_SHA.slice(0, 12)]) {
      const baseline = validTrackedMutationBaseline();
      baseline.measuredAtSha = measuredAtSha;
      const result = validateMutationBaseline(baseline, {
        root,
        commitIsAncestor: () => true,
      });
      assert.ok(result.errors.includes(
        "Mutation baseline measuredAtSha must be a full 40-hex commit."
      ));
    }

    const unreachable = validateMutationBaseline(validTrackedMutationBaseline(), {
      root,
      commitIsAncestor: () => false,
    });
    assert.ok(unreachable.errors.includes(
      "Mutation baseline measuredAtSha must name a commit reachable from current HEAD."
    ));
  });

  test("checks baseline provenance against the real current Git history", () => {
    const currentSha = require("child_process").spawnSync(
      "git",
      ["rev-parse", "HEAD"],
      { cwd: root, encoding: "utf8" }
    ).stdout.trim();

    assert.strictEqual(isAncestorCommit(currentSha, root), true);
    assert.strictEqual(isAncestorCommit("0".repeat(40), root), false);
  });

  test("rejects mutation scope/file drift and unreconciled counts or scores", () => {
    const scopeDrift = validTrackedMutationBaseline();
    scopeDrift.scope.pop();
    assert.ok(validateMutationBaseline(scopeDrift, {
      root,
      commitIsAncestor: () => true,
    }).errors.includes(
      "Mutation baseline scope and files must have exact target parity."
    ));

    const countDrift = validTrackedMutationBaseline();
    const target = countDrift.scope[0];
    Object.assign(countDrift.files[target], { killed: 0, survived: 2, score: 0 });
    const countErrors = validateMutationBaseline(countDrift, {
      root,
      commitIsAncestor: () => true,
    }).errors;
    assert.ok(countErrors.includes(
      "Mutation baseline aggregate killed does not equal its file totals."
    ));
    assert.ok(countErrors.includes(
      "Mutation baseline aggregate survived does not equal its file totals."
    ));

    const scoreDrift = validTrackedMutationBaseline();
    scoreDrift.files[scoreDrift.scope[0]].score = 51;
    assert.ok(validateMutationBaseline(scoreDrift, {
      root,
      commitIsAncestor: () => true,
    }).errors.includes(
      `Mutation baseline target ${scoreDrift.scope[0]} mutation score does not match its counts.`
    ));

    const floorDrift = validTrackedMutationBaseline();
    floorDrift.thresholds.break = 49;
    assert.ok(validateMutationBaseline(floorDrift, {
      root,
      commitIsAncestor: () => true,
    }).errors.includes(
      "Mutation baseline break threshold must equal its measured aggregate score."
    ));
  });

  test("rejects a stale mutation target after its source file is renamed", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-mutation-rename-"));
    const baseline = validTrackedMutationBaseline();
    try {
      fs.mkdirSync(path.join(temporaryRoot, "domain"), { recursive: true });
      fs.mkdirSync(path.join(temporaryRoot, "util"), { recursive: true });
      fs.writeFileSync(path.join(temporaryRoot, "domain", "renamedAuthCapabilities.js"), "// renamed\n");
      fs.writeFileSync(path.join(temporaryRoot, "util", "externalNavigation.js"), "// unchanged\n");

      assert.ok(validateMutationBaseline(baseline, {
        root: temporaryRoot,
        commitIsAncestor: () => true,
      }).errors.includes(
        "Mutation baseline target domain/authCapabilities.js must exist as a regular repository file."
      ));
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("rejects a missing or non-Git-visible mutation test owner", () => {
    const baseline = validTrackedMutationBaseline();
    const target = baseline.scope[0];
    baseline.files[target].testFiles = ["test/removedOwner.test.js"];
    assert.ok(validateMutationBaseline(baseline, {
      root,
      commitIsAncestor: () => true,
    }).errors.includes(
      `Mutation baseline target ${target} test owner test/removedOwner.test.js `
      + "must exist as a Git-visible regular test file."
    ));
    assert.throws(
      () => assertMutationTestOwners(baseline, root),
      /test owner test\/removedOwner\.test\.js must exist as a Git-visible regular test file/u
    );
  });

  test("rejects missing, duplicate, extra, and miscounted survivor classifications", () => {
    const missing = validTrackedMutationBaseline();
    missing.survivorClassifications.pop();
    assert.ok(validateMutationBaseline(missing, {
      root,
      commitIsAncestor: () => true,
    }).errors.includes(
      "Mutation baseline must classify every surviving fingerprint exactly once."
    ));

    const duplicate = validTrackedMutationBaseline();
    duplicate.survivorClassifications[1] = clone(duplicate.survivorClassifications[0]);
    assert.ok(validateMutationBaseline(duplicate, {
      root,
      commitIsAncestor: () => true,
    }).errors.includes(
      `Mutation baseline has duplicate survivor fingerprint ${"a".repeat(64)}.`
    ));

    const extra = validTrackedMutationBaseline();
    extra.survivorClassifications.push({
      fingerprint: "c".repeat(64),
      class: "fixture-equivalent",
    });
    assert.ok(validateMutationBaseline(extra, {
      root,
      commitIsAncestor: () => true,
    }).errors.includes(
      "Mutation baseline must classify every surviving fingerprint exactly once."
    ));

    const miscounted = validTrackedMutationBaseline();
    miscounted.equivalentSurvivorClasses[0].count = 1;
    const classErrors = validateMutationBaseline(miscounted, {
      root,
      commitIsAncestor: () => true,
    }).errors;
    assert.ok(classErrors.includes(
      "Mutation baseline equivalent class counts do not equal its surviving mutant count."
    ));
    assert.ok(classErrors.includes(
      "Mutation baseline equivalent class fixture-equivalent count does not match its classifications."
    ));
  });

  test("rejects an unknown equivalent class and any meaningful survivor", () => {
    const unknown = validTrackedMutationBaseline();
    unknown.survivorClassifications[0].class = "invented-class";
    assert.ok(validateMutationBaseline(unknown, {
      root,
      commitIsAncestor: () => true,
    }).errors.some(error => /uses unknown equivalent class invented-class/u.test(error)));

    const meaningful = validTrackedMutationBaseline();
    meaningful.meaningfulSurvivors.push(meaningful.survivorClassifications[0].fingerprint);
    assert.ok(validateMutationBaseline(meaningful, {
      root,
      commitIsAncestor: () => true,
    }).errors.includes(
      "Mutation baseline cannot be accepted with meaningful survivors."
    ));
  });

  test("selects explicit mutation files exactly without invoking Git", () => {
    assert.deepStrictEqual(
      changedMutationTargets(
        ["domain/a.js", "domain/b.js", "domain/c.js"],
        ["--files", "domain/c.js,domain/a.js,other.js"]
      ),
      ["domain/a.js", "domain/c.js"]
    );
  });

  test("does not let the changed mutation gate trust caller-authored file selection", () => {
    assert.doesNotThrow(() => assertMutationGateArguments("changed", []));
    assert.doesNotThrow(() => assertMutationGateArguments("changed", ["--base", "origin/main"]));
    assert.throws(
      () => assertMutationGateArguments("changed", ["--files", "README.md"]),
      /does not accept caller-authored --files selection/u
    );
  });

  test("selects a ranged mutation target when its source file changes", () => {
    assert.deepStrictEqual(
      changedMutationTargets(
        ["util/a.js:10-20", "util/b.js"],
        ["--files", "util/a.js"],
        {
          "util/a.js:10-20": { testFiles: ["test/a.test.js"], score: 90 },
          "util/b.js": { testFiles: ["test/b.test.js"], score: 90 },
        }
      ),
      ["util/a.js:10-20"]
    );
  });

  test("keeps the configured source side of a staged rename in changed mutation selection", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-mutation-git-rename-"));
    const source = "domain/owned.js";
    const destination = "domain/renamed.js";
    const runGit = argumentsList => require("child_process").spawnSync(
      "git",
      argumentsList,
      { cwd: temporaryRoot, encoding: "utf8", stdio: "ignore" }
    );
    try {
      assert.strictEqual(runGit(["init"]).status, 0);
      fs.mkdirSync(path.join(temporaryRoot, "domain"), { recursive: true });
      fs.writeFileSync(path.join(temporaryRoot, source), "export const owned = true;\n");
      assert.strictEqual(runGit(["add", source]).status, 0);
      assert.strictEqual(runGit([
        "-c", "user.name=Quality Fixture",
        "-c", "user.email=quality@example.invalid",
        "commit", "-m", "fixture",
      ]).status, 0);
      fs.renameSync(path.join(temporaryRoot, source), path.join(temporaryRoot, destination));
      assert.strictEqual(runGit(["add", "--all"]).status, 0);

      const changed = gitChangedFiles("HEAD", temporaryRoot);
      assert.deepStrictEqual(changed, [source, destination]);
      assert.deepStrictEqual(
        changedMutationTargets([source], ["--files", changed.join(",")], {
          [source]: { testFiles: ["test/owned.test.js"] },
        }),
        [source]
      );
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("includes staged Git type changes in mutation selection", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-mutation-type-"));
    const runGit = argumentsList => require("child_process").spawnSync(
      "git",
      argumentsList,
      { cwd: temporaryRoot, encoding: "utf8", stdio: "ignore" }
    );
    try {
      assert.strictEqual(runGit(["init"]).status, 0);
      fs.writeFileSync(path.join(temporaryRoot, "stryker.config.mjs"), "export default {};\n");
      fs.writeFileSync(path.join(temporaryRoot, "target.mjs"), "export default {};\n");
      assert.strictEqual(runGit(["add", "stryker.config.mjs", "target.mjs"]).status, 0);
      assert.strictEqual(runGit([
        "-c", "user.name=Quality Fixture",
        "-c", "user.email=quality@example.invalid",
        "commit", "-m", "fixture",
      ]).status, 0);
      fs.rmSync(path.join(temporaryRoot, "stryker.config.mjs"));
      fs.symlinkSync("target.mjs", path.join(temporaryRoot, "stryker.config.mjs"));
      assert.strictEqual(runGit(["add", "stryker.config.mjs"]).status, 0);

      assert.deepStrictEqual(gitChangedFiles("HEAD", temporaryRoot), ["stryker.config.mjs"]);
      assert.deepStrictEqual(
        changedMutationTargets(
          ["domain/a.js", "domain/b.js"],
          ["--files", "stryker.config.mjs"],
          {}
        ),
        ["domain/a.js", "domain/b.js"]
      );
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("filters incremental mutation reports to the selected target", () => {
    const mutant = status => ({ status });
    const report = {
      files: {
        "domain/a.js": { mutants: [mutant("Killed")] },
        "domain/b.js": { mutants: [mutant("Survived")] },
      },
    };
    const scoped = filterMutationReport(report, ["domain/a.js"]);
    assert.deepStrictEqual(Object.keys(scoped.files), ["domain/a.js"]);
    assert.deepStrictEqual(perFileCounts(scoped, ["domain/a.js"])["domain/a.js"], {
      mutants: 1,
      killed: 1,
      survived: 0,
      timeout: 0,
      noCoverage: 0,
      runtimeError: 0,
      compileError: 0,
      ignored: 0,
      score: 100,
    });
  });

  test("mutates an owner when its tests or mutation policy change", () => {
    const scope = ["domain/a.js", "domain/b.js"];
    const files = {
      "domain/a.js": { testFiles: ["test/a.test.js"] },
      "domain/b.js": { testFiles: ["test/b.test.js"] },
    };
    assert.deepStrictEqual(
      changedMutationTargets(scope, ["--files", "test/a.test.js"], files),
      ["domain/a.js"]
    );
    assert.deepStrictEqual(
      changedMutationTargets(scope, ["--files", "stryker.config.mjs"], files),
      scope
    );
    for (const owner of [
      ".github/workflows/deep-quality.yml",
      ".github/workflows/main.yml",
      ".node-version",
      "package.json",
      "package-lock.json",
      "scripts/quality/common.js",
      "scripts/quality/evidence.js",
      "scripts/quality/mutation-baseline.js",
      "scripts/quality/mutation-toolchain.js",
      "scripts/quality/verify-mutation-handoff.js",
      "scripts/quality/verify-workflows.js",
      "domain/package.js",
      "util/accountOperation.js",
      "util/packageVulnerabilities.js",
      "util/vulnerabilitySeverity.js",
      "commands/support.js",
    ]) {
      assert.deepStrictEqual(changedMutationTargets(scope, ["--files", owner], files), scope);
    }
    assert.throws(
      () => changedMutationTargets(scope, ["--files", ""], files),
      /requires at least one/
    );
  });

  test("fingerprints changed file content, not only its path", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-mutation-fingerprint-"));
    const target = path.join(temporaryRoot, "target.js");
    try {
      fs.writeFileSync(target, "first\n");
      const first = workingTreeFingerprint(temporaryRoot, ["target.js"]);
      fs.writeFileSync(target, "second\n");
      const second = workingTreeFingerprint(temporaryRoot, ["target.js"]);
      assert.notStrictEqual(first, second);
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("verifies exact changed, core, and not-applicable mutation handoffs", () => {
    for (const mode of ["changed", "core"]) {
      const fixture = mutationHandoffFixture({ mode });
      const result = validateMutationEvidenceArtifacts({
        ...fixture,
        expectedExitCode: 0,
        expectedRunOutcome: "success",
        expectedSourceSha: fixture.source.sha,
        mode,
        root,
      });
      assert.strictEqual(result.status, "passed");
      assert.deepStrictEqual(result.targets, [fixture.target]);
    }

    const notApplicable = mutationHandoffFixture({ applicable: false });
    assert.strictEqual(validateMutationEvidenceArtifacts({
      ...notApplicable,
      expectedExitCode: 0,
      expectedRunOutcome: "success",
      expectedSourceSha: notApplicable.source.sha,
      root,
    }).status, "not-applicable");
  });

  test("rejects stale, crossed, source-forged, status-forged, and exit-forged mutation evidence", () => {
    const fixture = mutationHandoffFixture();
    const stale = mutationHandoffFixture({ applicable: false });
    assert.throws(
      () => validateMutationEvidenceArtifacts({
        ...stale,
        rawReportArtifact: fixture.rawReportArtifact,
        root,
      }),
      /must not retain a raw report/u
    );

    const crossedBytes = {
      ...fixture.rawReportArtifact,
      bytes: Buffer.concat([fixture.rawReportArtifact.bytes, Buffer.from(" ")]),
    };
    assert.throws(
      () => validateMutationEvidenceArtifacts({
        ...fixture,
        rawReportArtifact: crossedBytes,
        root,
      }),
      /exact raw report bytes/u
    );

    const sourceForgedReport = clone(fixture.rawReportArtifact.value);
    const sourceFile = fixture.target.replace(/:\d+-\d+$/u, "");
    sourceForgedReport.files[sourceFile].source += "// forged\n";
    const sourceForgedArtifact = mutationRawArtifact(sourceForgedReport);
    const sourceForgedSummary = mutationReceipt("changed", [fixture.target], {
      status: "passed",
      ...deriveMutationEvidence(sourceForgedReport, [fixture.target]),
      strykerExitCode: 0,
    }, {
      source: fixture.source,
      selection: fixture.selection,
      rawReportFingerprint: sourceForgedArtifact.fingerprint,
    });
    assert.throws(
      () => validateMutationEvidenceArtifacts({
        ...fixture,
        rawReportArtifact: sourceForgedArtifact,
        summary: sourceForgedSummary,
        root,
      }),
      /does not bind current source bytes/u
    );

    const statusForgedReport = clone(fixture.rawReportArtifact.value);
    const mutant = statusForgedReport.files[sourceFile].mutants[0];
    mutant.status = "Survived";
    delete mutant.killedBy;
    delete mutant.statusReason;
    mutant.testsCompleted = mutant.coveredBy.length;
    const statusForgedArtifact = mutationRawArtifact(statusForgedReport);
    const statusForgedSummary = mutationReceipt("changed", [fixture.target], {
      status: "passed",
      ...deriveMutationEvidence(statusForgedReport, [fixture.target]),
      strykerExitCode: 0,
    }, {
      source: fixture.source,
      selection: fixture.selection,
      rawReportFingerprint: statusForgedArtifact.fingerprint,
    });
    assert.throws(
      () => validateMutationEvidenceArtifacts({
        ...fixture,
        expectedExitCode: 0,
        expectedRunOutcome: "success",
        rawReportArtifact: statusForgedArtifact,
        summary: statusForgedSummary,
        root,
      }),
      /independently derived handoff evidence/u
    );

    assert.throws(
      () => validateMutationEvidenceArtifacts({
        ...fixture,
        expectedExitCode: 42,
        expectedRunOutcome: "success",
        root,
      }),
      /independently captured process exit code/u
    );
  });

  test("accepts only exactly reconciled trusted mutation failures", () => {
    const fixture = mutationHandoffFixture();
    const derived = deriveMutationEvidence(
      fixture.rawReportArtifact.value,
      [fixture.target]
    );
    const strykerFailure = mutationReceipt("changed", [fixture.target], {
      status: "failed",
      ...derived,
      strykerExitCode: 7,
      reason: "Stryker exited 7.",
    }, {
      source: fixture.source,
      selection: fixture.selection,
      rawReportFingerprint: fixture.rawReportArtifact.fingerprint,
    });
    assert.strictEqual(validateMutationEvidenceArtifacts({
      ...fixture,
      expectedExitCode: 7,
      expectedRunOutcome: "failure",
      root,
      summary: strykerFailure,
    }).status, "failed");
    assert.throws(
      () => validateMutationEvidenceArtifacts({
        ...fixture,
        expectedExitCode: 8,
        expectedRunOutcome: "failure",
        root,
        summary: strykerFailure,
      }),
      /independently captured process exit code/u
    );

    const regressedBaseline = clone(fixture.baseline);
    Object.assign(regressedBaseline.files[fixture.target], {
      killed: 0,
      survived: 1,
      score: 0,
    });
    const policyReason = `Mutation target ${fixture.target} killed population drifted from 0 to 1; `
      + "remeasure the explicit mutation baseline.";
    const policyFailure = mutationReceipt("changed", [fixture.target], {
      status: "failed",
      ...derived,
      strykerExitCode: 0,
      reason: policyReason,
    }, {
      source: fixture.source,
      selection: fixture.selection,
      rawReportFingerprint: fixture.rawReportArtifact.fingerprint,
    });
    assert.strictEqual(validateMutationEvidenceArtifacts({
      ...fixture,
      baseline: regressedBaseline,
      expectedExitCode: 1,
      expectedRunOutcome: "failure",
      root,
      summary: policyFailure,
    }).status, "failed");
  });

  test("does not invent a mutation floor when the baseline threshold is null", () => {
    assert.doesNotThrow(() => validateMutationSummary(
      validMutationSummary({
        killed: 0,
        survived: 10,
        score: 0,
        files: {
          "domain/packageActionCapabilities.js": validMutationFile(0, {
            killed: 0,
            survived: 10,
          }),
        },
        survivors: mutationSurvivors(10),
      }),
      {
        thresholds: { break: null },
        files: { "domain/packageActionCapabilities.js": { mutants: 10, score: 0 } },
      },
      "changed"
    ));
  });

  test("enforces explicit global and per-file mutation regressions", () => {
    assert.throws(
      () => validateMutationSummary(
        mutationSummaryAt80({ mode: "core" }),
        {
          thresholds: { break: 81 },
          files: { "domain/packageActionCapabilities.js": { mutants: 10, score: 90 } },
        },
        "core"
      ),
      /below the baseline floor 81/
    );
    assert.throws(
      () => validateMutationSummary(
        mutationSummaryAt80(),
        {
          thresholds: { break: null },
          files: { "domain/packageActionCapabilities.js": { mutants: 10, score: 81 } },
        },
        "changed"
      ),
      /regressed below 81/
    );
    assert.doesNotThrow(() => validateMutationSummary(
      mutationSummaryAt80(),
      {
        thresholds: { break: 95 },
        files: { "domain/packageActionCapabilities.js": { mutants: 10, score: 80 } },
      },
      "changed"
    ));
  });

  test("rejects invalid mutation modes and duplicate or crossed survivor identities", () => {
    assert.throws(
      () => validateMutationSummary(
        validMutationSummary({ mode: "forged" }),
        validMutationBaseline(),
        "forged"
      ),
      /invalid mutation mode/u
    );

    const duplicatedSurvivor = mutationSurvivors(2)[0];
    const duplicateSummary = validMutationSummary({
      mutants: 10,
      killed: 8,
      survived: 2,
      score: 80,
      files: {
        "domain/packageActionCapabilities.js": validMutationFile(80, {
          killed: 8,
          survived: 2,
        }),
      },
      survivors: [duplicatedSurvivor, clone(duplicatedSurvivor)],
    });
    assert.throws(
      () => validateMutationSummary(
        duplicateSummary,
        {
          thresholds: { break: 80 },
          files: { "domain/packageActionCapabilities.js": { mutants: 10, score: 80 } },
        },
        "changed"
      ),
      /duplicate survivor fingerprints/u
    );

    const crossedSummary = clone(validMutationSummary());
    crossedSummary.survivors[0].file = "util/externalNavigation.js";
    assert.throws(
      () => validateMutationSummary(
        crossedSummary,
        validMutationBaseline(),
        "changed"
      ),
      /incomplete survivor fingerprints/u
    );
  });

  test("rejects a perfect-score mutation run when the measured target population collapses", () => {
    const target = "domain/authCapabilities.js";
    const collapsed = validMutationSummary({
      targets: [target],
      mutants: 1,
      killed: 1,
      survived: 0,
      score: 100,
      files: {
        [target]: validMutationFile(100, {
          mutants: 1,
          killed: 1,
          survived: 0,
        }),
      },
      survivors: [],
    });

    assert.throws(
      () => validateMutationSummary(
        collapsed,
        {
          thresholds: { break: 90 },
          files: { [target]: { mutants: 80, score: 90 } },
        },
        "changed"
      ),
      /produced 1 mutants; measured baseline requires exactly 80/u
    );

    const ignoredCollapse = validMutationSummary({
      targets: [target],
      mutants: 10,
      killed: 1,
      survived: 0,
      ignored: 9,
      score: 100,
      files: {
        [target]: validMutationFile(100, {
          mutants: 10,
          killed: 1,
          survived: 0,
          ignored: 9,
        }),
      },
      survivors: [],
    });
    assert.throws(
      () => validateMutationSummary(
        ignoredCollapse,
        {
          thresholds: { break: 90 },
          files: { [target]: { mutants: 10, ignored: 0, score: 90 } },
        },
        "changed"
      ),
      /ignored population drifted from 0 to 9/u
    );
  });

  test("rejects zero-mutant, timeout, and uncovered mutation runs", () => {
    assert.throws(
      () => validateMutationSummary(
        validMutationSummary({
          mode: "core",
          mutants: 0,
          killed: 0,
          survived: 0,
          score: null,
          ignored: 0,
          survivors: [],
        }),
        { thresholds: { break: null }, files: {} },
        "core"
      ),
      /without producing a mutant/
    );
    assert.throws(
      () => validateMutationSummary(
        mutationSummaryAt80({
          mode: "core", timeout: 1, noCoverage: 0, killed: 8, survived: 1,
        }),
        { thresholds: { break: null }, files: {} },
        "core"
      ),
      /1 timeout mutants/
    );
    assert.throws(
      () => validateMutationSummary(
        mutationSummaryAt80({
          mode: "core", noCoverage: 1, timeout: 0, killed: 8, survived: 1,
        }),
        { thresholds: { break: null }, files: {} },
        "core"
      ),
      /1 noCoverage mutants/
    );
  });

  test("rejects unbound or semantically forged black-box UI results", function () {
    this.timeout(30000);
    const plan = getGatePlan("release");
    const liveFingerprint = mutationArtifactFingerprint(validLiveStatus());
    const common = {
      source: SOURCE_IDENTITY,
      profile: "release",
      plan,
      receipts: plan.map(step => passedReceipt(step)),
      ...validImpactEvidence(),
      ...validMutationEvidence(),
      candidateReceipt: validCandidateReceipt(),
      liveQualification: validLiveStatus(),
      liveQualificationArtifactFingerprint: liveFingerprint,
      findings: [],
      findingsStatus: "passed",
      workflows: blackBoxFixtureWorkflows(),
      inventories: require("./testInventories"),
    };
    const forgedUi = {
      schemaVersion: 0,
      status: "passed",
      source: SOURCE_IDENTITY,
      sourceSha: SOURCE_SHA,
      launchAttempted: false,
      tests: [],
    };
    const forgedFingerprint = mutationArtifactFingerprint(forgedUi);
    const forgedReceipts = plan.map(step => passedReceipt(step));
    forgedReceipts.find(receipt => receipt.stepId === "black-box-ui-smoke")
      .artifactFingerprint = forgedFingerprint;
    const forged = generateReport({
      ...common,
      receipts: forgedReceipts,
      ui: forgedUi,
      uiArtifactFingerprint: forgedFingerprint,
    });
    assert.strictEqual(forged.blackBoxUi.status, "failed");
    assert.strictEqual(forged.releaseReadiness.verdict, null);
    assert.strictEqual(forged.status, "failed");

    const tampered = generateReport({
      ...common,
      ui: validUiResult(),
      uiArtifactFingerprint: "d".repeat(64),
    });
    assert.strictEqual(tampered.blackBoxUi.status, "failed");
    assert.match(tampered.blackBoxUi.reason, /exact result artifact/u);
  });

  test("rejects traversal and symlinked quality outputs before any outside write", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-quality-path-"));
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-quality-outside-"));
    try {
      fs.symlinkSync(outside, path.join(temporaryRoot, ".quality"), "dir");
      assert.throws(
        () => writeJson(".quality/result.json", { status: "forged" }, temporaryRoot),
        /symlink|real repository director/i
      );
      assert.strictEqual(fs.existsSync(path.join(outside, "result.json")), false);
      fs.rmSync(path.join(temporaryRoot, ".quality"));
      fs.mkdirSync(path.join(temporaryRoot, ".quality", "test-results"), {
        recursive: true,
      });
      assert.throws(
        () => writeJson(
          ".quality/test-results/../escaped.json",
          { status: "forged" },
          temporaryRoot,
          { subtree: ".quality/test-results" }
        ),
        /normalized|subtree|traversal/i
      );
      assert.strictEqual(fs.existsSync(path.join(outside, "escaped.json")), false);
    } finally {
      fs.rmSync(temporaryRoot, { force: true, recursive: true });
      fs.rmSync(outside, { force: true, recursive: true });
    }
  });

  test("rejects a poison symlink before discovering UI artifacts", function () {
    if (process.platform === "win32") this.skip();
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-ui-artifacts-"));
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-ui-poison-"));
    try {
      fs.writeFileSync(path.join(outside, "forged.png"), "not real UI evidence\n");
      fs.mkdirSync(path.join(temporaryRoot, ".quality"));
      fs.symlinkSync(outside, path.join(temporaryRoot, ".quality", "ui"), "dir");

      assert.throws(
        () => discoverUiArtifacts(temporaryRoot),
        /real repository directories|symbolic link/i
      );
    } finally {
      fs.rmSync(temporaryRoot, { force: true, recursive: true });
      fs.rmSync(outside, { force: true, recursive: true });
    }
  });

  test("passes active zero, focus, and pending guards to programmatic UI Mocha", () => {
    const config = JSON.parse(fs.readFileSync(
      path.join(root, "ui-test", "mocha.config.json"),
      "utf8"
    ));
    const mocha = new Mocha(config);
    assert.strictEqual(mocha.options.failZero, true);
    assert.strictEqual(mocha.options.forbidOnly, true);
    assert.strictEqual(mocha.options.forbidPending, true);
    for (const inactive of ["fail-zero", "forbid-only", "forbid-pending"]) {
      assert.strictEqual(Object.prototype.hasOwnProperty.call(config, inactive), false);
    }
  });
});

suite("Release checklist and deterministic quality report", () => {
  const workflows = require("../quality/critical-workflows.json");
  const inventories = require("./testInventories");

  test("keeps missing live qualification explicitly not-run", () => {
    const result = evaluateLiveQualification({
      source: SOURCE_IDENTITY,
      workflows,
      document: null,
      findingsState: {
        fingerprint: "f".repeat(64),
        openReleaseBlockerCount: 0,
        openNonBlockingRiskCount: 0,
        errors: [],
      },
    });

    assert.strictEqual(result.status, "not-run");
    assert.strictEqual(result.authenticatedAcceptance, "not-recorded");
    assert.ok(result.missingWorkflowIds.length > 0);
  });

  test("rejects stale live evidence and accepts a complete source-matching attestation", () => {
    const staleFixture = passedLiveAttestation({
      sha: BASE_SHA,
      fingerprint: SOURCE_IDENTITY.fingerprint,
    });
    const passedFixture = passedLiveAttestation();
    try {
      const staleResult = evaluateLiveQualification({
        root: staleFixture.root,
        now: LIVE_FIXTURE_NOW,
        source: SOURCE_IDENTITY,
        workflows,
        document: staleFixture.document,
        attestationFingerprint: staleFixture.attestationFingerprint,
        ...liveCandidateProof(staleFixture),
      });
      const passed = evaluateLiveQualification({
        root: passedFixture.root,
        now: LIVE_FIXTURE_NOW,
        source: SOURCE_IDENTITY,
        workflows,
        document: passedFixture.document,
        attestationFingerprint: passedFixture.attestationFingerprint,
        ...liveCandidateProof(passedFixture),
      });

      assert.strictEqual(staleResult.status, "failed");
      assert.ok(staleResult.errors.some(error => /source SHA/.test(error)));
      assert.deepStrictEqual(
        staleResult.passedWorkflowIds,
        requiredLiveWorkflowIds(workflows)
      );
      assert.strictEqual(passed.status, "passed");
      assert.strictEqual(passed.authenticatedAcceptance, "recorded");
      assert.deepStrictEqual(passed.missingWorkflowIds, []);
    } finally {
      staleFixture.cleanup();
      passedFixture.cleanup();
    }
  });

  test("restricts checklist attestations to normalized ignored JSON paths", () => {
    assert.deepStrictEqual(
      parseChecklistArguments(["--input", "internal_docs/quality/candidate.json"]),
      { inputPath: "internal_docs/quality/candidate.json" }
    );
    for (const unsafe of [
      "../candidate.json",
      "internal_docs/quality/../candidate.json",
      "internal_docs\\quality\\candidate.json",
      "internal_docs/quality/sub/candidate.json",
      "internal_docs/quality/candidate.txt",
      "internal_docs/quality/candidate.json\nignored",
    ]) {
      assert.throws(
        () => parseChecklistArguments(["--input", unsafe]),
        /normalized internal_docs\/quality\/\*\.json path/
      );
    }
  });

  test("fails a receipt that claims pass after a nonzero command result", () => {
    const plan = getGatePlan("full");
    const receipts = plan.map(step => passedReceipt(step));
    receipts.find(receipt => receipt.stepId === "standalone-tests").exitCode = 9;
    const liveFixture = passedLiveAttestation();
    try {
      const report = generateReport({
        source: SOURCE_IDENTITY,
        profile: "full",
        plan,
        receipts,
        ...validImpactEvidence(),
        ...validMutationEvidence(),
        liveQualification: evaluateLiveQualification({
          root: liveFixture.root,
          now: LIVE_FIXTURE_NOW,
          source: SOURCE_IDENTITY,
          workflows,
          document: liveFixture.document,
          attestationFingerprint: liveFixture.attestationFingerprint,
          ...liveCandidateProof(liveFixture),
        }),
        findings: [],
        findingsStatus: "passed",
        workflows: { workflows: [] },
        inventories,
      });

      assert.strictEqual(report.deterministicGates.status, "failed");
      assert.strictEqual(report.testResults.standalone.status, "failed");
      assert.strictEqual(report.status, "failed");
    } finally {
      liveFixture.cleanup();
    }
  });

  test("rejects command receipts that self-exempt or contradict their execution", () => {
    const plan = getGatePlan("full");
    const common = {
      source: SOURCE_IDENTITY,
      profile: "full",
      plan,
      ...validImpactEvidence(),
      ...validMutationEvidence(),
      liveQualification: validLiveStatus(),
      findings: [],
      findingsStatus: "passed",
      workflows: { workflows: [] },
      inventories,
    };
    const selfExemptingReceipts = plan.map(step => ({
      ...passedReceipt(step),
      status: "not-applicable",
      exitCode: null,
      signal: null,
      reason: "self-exempted",
      testEvidence: null,
      artifactFingerprint: null,
    }));
    const selfExempting = generateReport({ ...common, receipts: selfExemptingReceipts });
    assert.strictEqual(selfExempting.status, "failed");
    assert.strictEqual(hasDeterministicReportFailure(selfExempting), true);
    assert.ok(selfExempting.deterministicGates.steps.every(step => (
      step.status === "failed"
        && /not-applicable-command-status/u.test(step.reason)
    )));

    const contradictoryReceipts = plan.map(step => passedReceipt(step));
    const repositoryReceipt = contradictoryReceipts.find(receipt => (
      receipt.stepId === "repository-check"
    ));
    repositoryReceipt.signal = "SIGTERM";
    repositoryReceipt.reason = "terminated";
    const contradictory = generateReport({ ...common, receipts: contradictoryReceipts });
    const repositoryStep = contradictory.deterministicGates.steps.find(step => (
      step.stepId === "repository-check"
    ));
    assert.strictEqual(repositoryStep.status, "failed");
    assert.match(repositoryStep.reason, /signaled-command-claimed-pass/u);

    const invalidBlockedReceipts = plan.map(step => passedReceipt(step));
    const invalidBlocked = invalidBlockedReceipts.find(receipt => (
      receipt.stepId === "repository-check"
    ));
    invalidBlocked.status = "blocked";
    invalidBlocked.exitCode = 2;
    const blockedReport = generateReport({ ...common, receipts: invalidBlockedReceipts });
    const blockedStep = blockedReport.deterministicGates.steps.find(step => (
      step.stepId === "repository-check"
    ));
    assert.strictEqual(blockedStep.status, "failed");
    assert.match(blockedStep.reason, /invalid-blocked-exit-code/u);
  });

  test("rejects wrong-suite and nonpassing structured Mocha receipts", () => {
    const plan = getGatePlan("fast");
    const baseOptions = {
      source: SOURCE_IDENTITY,
      profile: "fast",
      plan,
      ...validImpactEvidence(),
      liveQualification: null,
      findings: [],
      findingsStatus: "passed",
      workflows: { workflows: [] },
      inventories,
    };
    const wrongSuiteReceipts = plan.map(step => passedReceipt(step));
    wrongSuiteReceipts.find(receipt => receipt.stepId === "standalone-tests")
      .testEvidence.suite = "extension-host-core";
    const wrongSuite = generateReport({
      ...baseOptions,
      receipts: wrongSuiteReceipts,
    });
    const wrongSuiteStep = wrongSuite.deterministicGates.steps.find(step => (
      step.stepId === "standalone-tests"
    ));
    assert.strictEqual(wrongSuiteStep.status, "failed");
    assert.match(wrongSuiteStep.reason, /test-evidence:suite-mismatch/u);

    const failedRecordReceipts = plan.map(step => passedReceipt(step));
    const failedEvidence = failedRecordReceipts.find(receipt => (
      receipt.stepId === "standalone-tests"
    )).testEvidence;
    failedEvidence.tests[0].status = "failed";
    failedEvidence.counts = {
      passed: failedEvidence.tests.length - 1,
      failed: 1,
      pending: 0,
    };
    const failedRecord = generateReport({
      ...baseOptions,
      receipts: failedRecordReceipts,
    });
    const failedRecordStep = failedRecord.deterministicGates.steps.find(step => (
      step.stepId === "standalone-tests"
    ));
    assert.strictEqual(failedRecordStep.status, "failed");
    assert.match(failedRecordStep.reason, /test-evidence:nonpassing-test-record/u);

    const fullPlan = getGatePlan("full");
    const crossedReceipts = fullPlan.map(step => passedReceipt(step));
    const coreEvidence = crossedReceipts.find(receipt => (
      receipt.stepId === "extension-host-core"
    )).testEvidence;
    coreEvidence.tests = [{
      file: "test/activation.test.js",
      title: "smoke-only fixture",
      fullTitle: "smoke-only fixture",
      status: "passed",
    }];
    coreEvidence.counts = { passed: 1, failed: 0, pending: 0 };
    const crossed = generateReport({
      ...baseOptions,
      profile: "full",
      plan: fullPlan,
      receipts: crossedReceipts,
      ...validMutationEvidence(),
    });
    const coreStep = crossed.deterministicGates.steps.find(step => (
      step.stepId === "extension-host-core"
    ));
    assert.strictEqual(coreStep.status, "failed");
    assert.match(coreStep.reason, /test-evidence:suite-inventory-mismatch/u);

    for (const suiteId of ["standalone-tests", "extension-host-core"]) {
      const reorderedReceipts = fullPlan.map(step => passedReceipt(step));
      reorderedReceipts.find(receipt => receipt.stepId === suiteId).testEvidence.tests.reverse();
      const reordered = generateReport({
        ...baseOptions,
        profile: "full",
        plan: fullPlan,
        receipts: reorderedReceipts,
        ...validMutationEvidence(),
      });
      const reorderedStep = reordered.deterministicGates.steps.find(step => (
        step.stepId === suiteId
      ));
      assert.strictEqual(reorderedStep.status, "failed");
      assert.match(reorderedStep.reason, /test-evidence:suite-inventory-mismatch/u);
    }
  });

  test("binds the exact mutation artifact and independently rejects invalid summaries", () => {
    const plan = getGatePlan("full");
    const mutation = validMutationSummary();
    const fingerprint = mutationArtifactFingerprint(mutation);
    const receipts = plan.map(step => passedReceipt(step));
    receipts.find(receipt => receipt.stepId === "changed-mutation")
      .artifactFingerprint = fingerprint;
    const common = {
      source: SOURCE_IDENTITY,
      profile: "full",
      plan,
      receipts,
      ...validImpactEvidence(),
      mutation,
      mutationBaseline: validMutationBaseline(),
      liveQualification: null,
      findings: [],
      findingsStatus: "passed",
      workflows: { workflows: [] },
      inventories,
    };

    const missing = generateReport(common);
    assert.strictEqual(missing.mutation.status, "failed");
    assert.match(missing.mutation.reason, /without a readable summary artifact fingerprint/u);

    const tampered = generateReport({
      ...common,
      mutationArtifactFingerprint: "d".repeat(64),
    });
    assert.strictEqual(tampered.mutation.status, "failed");
    assert.match(tampered.mutation.reason, /does not match the gate receipt/u);

    const invalidMutation = validMutationSummary({
      killed: 8,
      survived: 1,
      noCoverage: 1,
      score: 80,
      files: {
        "domain/packageActionCapabilities.js": validMutationFile(80, {
          killed: 8,
          survived: 1,
          noCoverage: 1,
        }),
      },
    });
    const invalidFingerprint = mutationArtifactFingerprint(invalidMutation);
    const invalidReceipts = plan.map(step => passedReceipt(step));
    invalidReceipts.find(receipt => receipt.stepId === "changed-mutation")
      .artifactFingerprint = invalidFingerprint;
    const invalid = generateReport({
      ...common,
      receipts: invalidReceipts,
      mutation: invalidMutation,
      mutationArtifactFingerprint: invalidFingerprint,
    });
    assert.strictEqual(invalid.mutation.status, "failed");
    assert.match(invalid.mutation.reason, /1 noCoverage mutants/u);

    const wrongModeMutation = validMutationSummary({ mode: "core" });
    const wrongModeFingerprint = mutationArtifactFingerprint(wrongModeMutation);
    const wrongModeReceipts = plan.map(step => passedReceipt(step));
    wrongModeReceipts.find(receipt => receipt.stepId === "changed-mutation")
      .artifactFingerprint = wrongModeFingerprint;
    const wrongMode = generateReport({
      ...common,
      receipts: wrongModeReceipts,
      mutation: wrongModeMutation,
      mutationArtifactFingerprint: wrongModeFingerprint,
    });
    assert.strictEqual(wrongMode.mutation.status, "failed");
    assert.match(wrongMode.mutation.reason, /changed-mode evidence/u);

    const matching = generateReport({
      ...common,
      mutationArtifactFingerprint: fingerprint,
    });
    assert.strictEqual(matching.mutation.status, "passed");
  });

  test("failed live qualification cannot pass workflows and fails report execution", () => {
    const workflowId = "WF-LIVE-ATTESTATION-FIXTURE";
    const plan = getGatePlan("fast");
    const report = generateReport({
      source: SOURCE_IDENTITY,
      profile: "fast",
      plan,
      receipts: plan.map(step => passedReceipt(step)),
      ...validImpactEvidence(),
      liveQualification: {
        status: "failed",
        source: SOURCE_IDENTITY,
        authenticatedAcceptance: "not-recorded",
        requiredWorkflowIds: [workflowId],
        passedWorkflowIds: [workflowId],
        missingWorkflowIds: [],
        errors: ["forged attestation"],
      },
      findings: [],
      findingsStatus: "passed",
      workflows: {
        workflows: [{
          id: workflowId,
          criticality: "release-critical",
          surface: "fixture",
          authoritativeOutcome: "fixture",
          requiredLayers: ["live-protocol"],
          evidence: [],
          liveFixture: { required: true },
        }],
      },
      inventories,
    });

    assert.deepStrictEqual(report.liveQualification.passedWorkflowIds, [workflowId]);
    assert.deepStrictEqual(report.liveQualification.missingWorkflowIds, []);
    assert.strictEqual(report.workflowCoverage[0].layerStatuses["live-protocol"], "not-run");
    assert.strictEqual(report.status, "failed");
    assert.strictEqual(hasDeterministicReportFailure(report), true);
  });

  test("rejects a stale passed live status when the release checklist receipt failed", function () {
    this.timeout(30000);
    const plan = getGatePlan("release");
    const receipts = plan.map(step => passedReceipt(step));
    const checklistReceipt = receipts.find(receipt => receipt.stepId === "release-checklist");
    checklistReceipt.status = "failed";
    checklistReceipt.exitCode = 1;
    checklistReceipt.reason = "fixture checklist failure";
    const report = generateReport({
      source: SOURCE_IDENTITY,
      profile: "release",
      plan,
      receipts,
      ...validImpactEvidence(),
      ...validMutationEvidence(),
      candidateReceipt: validCandidateReceipt(),
      ui: validUiResult(),
      uiArtifactFingerprint: mutationArtifactFingerprint(validUiResult()),
      liveQualification: validLiveStatus(),
      findings: [],
      findingsStatus: "passed",
      workflows: blackBoxFixtureWorkflows(),
      inventories,
    });

    const checklistStep = report.deterministicGates.steps.find(step => (
      step.stepId === "release-checklist"
    ));
    assert.strictEqual(checklistStep, undefined);
    assert.strictEqual(report.deterministicGates.status, "passed");
    assert.strictEqual(report.liveQualification.status, "failed");
    assert.strictEqual(report.liveQualification.authenticatedAcceptance, "not-recorded");
    assert.strictEqual(report.releaseReadiness.verdict, null);
    assert.strictEqual(report.status, "failed");
    assert.strictEqual(hasDeterministicReportFailure(report), true);
  });

  test("rejects stale live status after a source-bound release checklist receipt passed", function () {
    this.timeout(30000);
    const plan = getGatePlan("release");
    const liveQualification = validLiveStatus();
    const common = {
      source: SOURCE_IDENTITY,
      profile: "release",
      plan,
      receipts: plan.map(step => passedReceipt(step)),
      ...validImpactEvidence(),
      ...validMutationEvidence(),
      candidateReceipt: validCandidateReceipt(),
      ui: validUiResult(),
      uiArtifactFingerprint: mutationArtifactFingerprint(validUiResult()),
      findings: [],
      findingsStatus: "passed",
      workflows: blackBoxFixtureWorkflows(),
      inventories,
      liveQualificationArtifactFingerprint: mutationArtifactFingerprint(validLiveStatus()),
    };
    const matching = generateReport({ ...common, liveQualification });
    const mismatchedBytes = generateReport({
      ...common,
      liveQualification,
      liveQualificationArtifactFingerprint: "c".repeat(64),
    });
    const invalidSchema = generateReport({
      ...common,
      liveQualification: { ...liveQualification, schemaVersion: 0 },
    });
    const stale = generateReport({
      ...common,
      liveQualification: {
        ...liveQualification,
        source: { sha: BASE_SHA, fingerprint: SOURCE_IDENTITY.fingerprint },
      },
    });
    const changedFindings = generateReport({
      ...common,
      liveQualification,
      findings: [{ id: "QH-LEDGER-DRIFT", status: "fixed", releaseBlocking: false }],
      findingsFingerprint: "d".repeat(64),
    });
    const alternateInput = generateReport({
      ...common,
      liveQualification: {
        ...liveQualification,
        inputPath: "internal_docs/quality/alternate.json",
      },
    });

    assert.strictEqual(matching.liveQualification.status, "failed");
    assert.match(
      matching.liveQualification.errors.join("\n"),
      /fresh evaluation of its disk attestation/u
    );
    assert.strictEqual(mismatchedBytes.liveQualification.status, "failed");
    assert.strictEqual(mismatchedBytes.releaseReadiness.verdict, null);
    assert.strictEqual(invalidSchema.liveQualification.status, "failed");
    assert.strictEqual(invalidSchema.releaseReadiness.verdict, null);
    assert.strictEqual(stale.liveQualification.status, "failed");
    assert.strictEqual(stale.liveQualification.authenticatedAcceptance, "not-recorded");
    assert.strictEqual(stale.releaseReadiness.verdict, null);
    assert.strictEqual(stale.status, "failed");
    assert.strictEqual(changedFindings.liveQualification.status, "failed");
    assert.match(changedFindings.liveQualification.errors.join("\n"), /current findings ledger/u);
    assert.strictEqual(changedFindings.releaseReadiness.verdict, null);
    assert.strictEqual(alternateInput.liveQualification.status, "failed");
    assert.match(alternateInput.liveQualification.errors.join("\n"), /exact default attestation/u);
    assert.strictEqual(hasDeterministicReportFailure(stale), true);
  });

  test("requires fresh disk revalidation before a release report can trust live acceptance", () => {
    const fixtureNow = new Date();
    const fixture = passedLiveAttestation(SOURCE_IDENTITY, fixtureNow);
    const inputPath = "internal_docs/quality/live-qualification.json";
    const workflows = require("../quality/critical-workflows.json");
    const plan = getGatePlan("release");
    try {
      fs.writeFileSync(
        path.join(fixture.root, inputPath),
        `${JSON.stringify(fixture.document, null, 2)}\n`
      );
      writeReleaseExposureFixture(fixture, fixture.document, inputPath);
      const status = evaluateDiskLiveQualification({
        root: fixture.root,
        source: SOURCE_IDENTITY,
        workflows,
        inputPath,
        now: fixtureNow,
        qualificationHomeDirectory: fixture.qualificationHomeDirectory,
      });
      const findingsBytes = fs.readFileSync(path.join(
        fixture.root,
        "internal_docs/quality/findings.jsonl"
      ));
      const findings = findingsBytes.toString("utf8").trim().split("\n").map(JSON.parse);
      const uiTests = uniqueSorted(workflows.workflows.flatMap(workflow => (
        (workflow.evidence || [])
          .filter(evidence => evidence.layer === "black-box-ui")
          .flatMap(evidence => evidence.testNames || [])
      )));
      const ui = validUiResult(uiTests);
      const liveFingerprint = mutationArtifactFingerprint(status);
      const receipts = plan.map(step => passedReceipt(step));
      receipts.find(receipt => receipt.stepId === "release-checklist").artifactFingerprint
        = liveFingerprint;
      receipts.find(receipt => receipt.stepId === "black-box-ui-smoke").artifactFingerprint
        = mutationArtifactFingerprint(ui);
      const common = {
        root: fixture.root,
        source: SOURCE_IDENTITY,
        profile: "release",
        plan,
        receipts,
        ...validImpactEvidence(),
        ...validMutationEvidence(),
        candidateReceipt: validCandidateReceipt(),
        ui,
        uiArtifactFingerprint: mutationArtifactFingerprint(ui),
        liveQualification: status,
        liveQualificationArtifactFingerprint: liveFingerprint,
        findings,
        findingsFingerprint: status.findingsFingerprint,
        findingsStatus: "passed",
        workflows,
        inventories,
        qualificationHomeDirectory: fixture.qualificationHomeDirectory,
      };

      const intact = generateReport(common);
      assert.strictEqual(intact.liveQualification.status, "passed");
      assert.strictEqual(intact.liveQualification.verdict, status.verdict);
      const rendered = renderMarkdown(intact);
      assert.match(rendered, new RegExp(status.candidate.receiptFingerprint, "u"));
      assert.match(rendered, new RegExp(status.candidate.profileRootIdentity, "u"));
      assert.strictEqual(
        rendered.includes(path.join(
          fixture.qualificationHomeDirectory,
          ".cloudsmith-vscode-qualification",
        )),
        false,
      );

      fs.rmSync(path.join(fixture.root, "internal_docs/quality/e2e-evidence.md"));
      fs.rmSync(path.join(fixture.root, "internal_docs/quality/release-readiness.md"));
      const detached = evaluateDiskLiveQualification({
        root: fixture.root,
        source: SOURCE_IDENTITY,
        workflows,
        inputPath,
        now: fixtureNow,
        qualificationHomeDirectory: fixture.qualificationHomeDirectory,
      });
      const report = generateReport(common);
      assert.strictEqual(detached.status, "failed");
      assert.strictEqual(report.liveQualification.status, "failed");
      assert.match(
        report.liveQualification.errors.join("\n"),
        /fresh evaluation of its disk attestation/u
      );
      assert.strictEqual(report.releaseReadiness.verdict, null);
    } finally {
      fixture.cleanup();
    }
  });

  test("rejects crossed live workflow sets even when exact artifact bytes are receipt-bound", function () {
    this.timeout(30000);
    const actualWorkflowId = "WF-ACTUAL-LIVE-FIXTURE";
    const unrelatedWorkflowId = "WF-UNRELATED-LIVE-FIXTURE";
    const plan = getGatePlan("release");
    const liveQualification = validLiveStatus({
      requiredWorkflowIds: [unrelatedWorkflowId],
      passedWorkflowIds: [actualWorkflowId],
      missingWorkflowIds: [unrelatedWorkflowId],
    });
    const receipts = plan.map(step => passedReceipt(step));
    const liveFingerprint = mutationArtifactFingerprint(liveQualification);
    receipts.find(receipt => receipt.stepId === "release-checklist").artifactFingerprint
      = liveFingerprint;
    const report = generateReport({
      source: SOURCE_IDENTITY,
      profile: "release",
      plan,
      receipts,
      ...validImpactEvidence(),
      ...validMutationEvidence(),
      candidateReceipt: validCandidateReceipt(),
      ui: validUiResult(),
      uiArtifactFingerprint: mutationArtifactFingerprint(validUiResult()),
      liveQualification,
      liveQualificationArtifactFingerprint: liveFingerprint,
      findings: [],
      findingsStatus: "passed",
      workflows: {
        workflows: [{
          id: actualWorkflowId,
          criticality: "release-critical",
          surface: "fixture",
          authoritativeOutcome: "fixture",
          requiredLayers: ["live-protocol", "black-box-ui"],
          liveFixture: { required: true },
          evidence: [{
            layer: "black-box-ui",
            interactionMode: "rendered-dom-activation",
            testFile: "ui-test/smoke.test.js",
            testNames: ["fixture"],
          }],
        }],
      },
      inventories,
    });

    assert.strictEqual(report.liveQualification.status, "failed");
    assert.deepStrictEqual(report.liveQualification.passedWorkflowIds, [actualWorkflowId]);
    assert.match(report.liveQualification.errors.join("\n"), /workflow manifest|subset/u);
    assert.strictEqual(report.workflowCoverage[0].layerStatuses["live-protocol"], "not-run");
    assert.strictEqual(report.releaseReadiness.verdict, null);
    assert.strictEqual(report.status, "failed");
  });

  test("rejects truncated, explicit, and stale-fingerprint impact evidence", () => {
    assert.ok(validateImpactArtifact({ key: { sha: SOURCE_SHA } }).length > 0);
    const explicit = validImpact({
      analysisScope: "explicit-files",
      source: {
        mode: "explicit",
        sha: SOURCE_SHA,
        fingerprint: SOURCE_IDENTITY.fingerprint,
        base: null,
        baseSha: null,
      },
    });
    assert.ok(validateImpactArtifact(explicit).some(error => /complete Git/.test(error)));

    const originalImpact = validImpact({ workflows: ["WF-IMPACT-FIXTURE"] });
    const tamperedImpact = clone(originalImpact);
    tamperedImpact.workflows = [];
    tamperedImpact.key.fingerprint = impactFingerprint(tamperedImpact);
    tamperedImpact.analysisKey = `${SOURCE_SHA}:${tamperedImpact.key.fingerprint}`;
    const tamperPlan = getGatePlan("fast");
    const tamperReceipts = tamperPlan.map(step => passedReceipt(step));
    tamperReceipts.find(receipt => receipt.stepId === "change-impact").artifactFingerprint
      = mutationArtifactFingerprint(originalImpact);
    const tamperedReport = generateReport({
      source: SOURCE_IDENTITY,
      profile: "fast",
      plan: tamperPlan,
      receipts: tamperReceipts,
      impact: tamperedImpact,
      impactArtifactFingerprint: mutationArtifactFingerprint(tamperedImpact),
      liveQualification: null,
      findings: [],
      findingsStatus: "passed",
      workflows: { workflows: [] },
      inventories,
    });
    assert.strictEqual(tamperedReport.impact.status, "failed");
    assert.match(tamperedReport.impact.errors.join("\n"), /exact artifact/u);

    const plan = getGatePlan("full");
    const stale = validImpact({
      source: {
        mode: "git",
        sha: SOURCE_SHA,
        fingerprint: "b".repeat(64),
        base: "origin/main",
        baseSha: BASE_SHA,
      },
    });
    const staleFingerprint = mutationArtifactFingerprint(stale);
    const receipts = plan.map(step => passedReceipt(step));
    receipts.find(receipt => receipt.stepId === "change-impact").artifactFingerprint
      = staleFingerprint;
    const report = generateReport({
      source: SOURCE_IDENTITY,
      profile: "full",
      plan,
      receipts,
      impact: stale,
      impactArtifactFingerprint: staleFingerprint,
      ...validMutationEvidence(),
      liveQualification: null,
      findings: [],
      findingsStatus: "not-run",
      workflows: { workflows: [] },
      inventories,
    });
    assert.strictEqual(report.impact.status, "blocked");
  });

  test("produces stable JSON and Markdown fingerprints while preserving not-run live truth", () => {
    const plan = getGatePlan("full");
    const options = {
      source: SOURCE_IDENTITY,
      profile: "full",
      plan,
      receipts: plan.map(step => passedReceipt(step)),
      ...validImpactEvidence(),
      ...validMutationEvidence(),
      liveQualification: null,
      findings: [],
      findingsStatus: "not-run",
      workflows: { workflows: [] },
      inventories,
    };
    const first = generateReport(options);
    const second = generateReport(clone(options));

    assert.strictEqual(first.key.fingerprint, second.key.fingerprint);
    assert.strictEqual(renderMarkdown(first), renderMarkdown(second));
    assert.strictEqual(first.liveQualification.status, "not-run");
    assert.strictEqual(first.releaseReadiness.authenticatedAcceptance, "not-recorded");
    assert.strictEqual(first.status, "blocked");
  });

  test("accepts direct matching mutation evidence but blocks stale mutation evidence", () => {
    const plan = getGatePlan("full");
    const receipts = plan
      .filter(step => step.id !== "changed-mutation")
      .map(step => passedReceipt(step));
    const common = {
      source: SOURCE_IDENTITY,
      profile: "full",
      plan,
      receipts,
      ...validImpactEvidence(),
      liveQualification: null,
      findings: [],
      findingsStatus: "not-run",
      workflows: { workflows: [] },
      inventories,
      mutationBaseline: validMutationBaseline(),
    };
    const matching = generateReport({ ...common, mutation: validMutationSummary() });
    const stale = generateReport({
      ...common,
      mutation: validMutationSummary({
        source: { sha: BASE_SHA, fingerprint: SOURCE_IDENTITY.fingerprint },
        sourceSha: BASE_SHA,
      }),
    });

    assert.strictEqual(matching.mutation.status, "passed");
    assert.strictEqual(stale.mutation.status, "blocked");
  });

  test("report execution fails deterministic evidence gaps but permits a truthful live-only block", () => {
    const liveOnlyBlocked = {
      status: "blocked",
      gateProfile: "full",
      impact: { status: "passed" },
      mutation: { status: "passed" },
      deterministicGates: { status: "passed" },
      findings: { status: "passed" },
    };
    assert.strictEqual(hasDeterministicReportFailure(liveOnlyBlocked), false);

    for (const report of [
      { ...liveOnlyBlocked, impact: { status: "blocked" } },
      { ...liveOnlyBlocked, mutation: { status: "not-run" } },
      { ...liveOnlyBlocked, deterministicGates: { status: "blocked" } },
      { ...liveOnlyBlocked, findings: { status: "failed" } },
      { ...liveOnlyBlocked, status: "failed" },
    ]) {
      assert.strictEqual(hasDeterministicReportFailure(report), true);
    }
    assert.strictEqual(hasDeterministicReportFailure({
      ...liveOnlyBlocked,
      gateProfile: "fast",
      mutation: { status: "not-run" },
    }), false);
  });

  test("rejects malformed and duplicate ignored finding records", () => {
    const schema = require("../quality/finding.schema.json");
    const taxonomy = require("../quality/defect-taxonomy.json");
    const malformed = validFinding({
      unexpected: true,
      severity: "P9",
      failureClasses: ["not-a-real-class"],
      mutationProof: { status: "invented", summary: "Invalid." },
    });
    const recordErrors = validateFindingRecord(malformed, schema, taxonomy);
    const duplicateErrors = validateFindings(
      [validFinding(), validFinding()],
      schema,
      taxonomy
    );

    assert.ok(recordErrors.some(error => /unknown field unexpected/.test(error)));
    assert.ok(recordErrors.some(error => /invalid severity P9/.test(error)));
    assert.ok(recordErrors.some(error => /invalid failure class/.test(error)));
    assert.ok(recordErrors.some(error => /invalid mutation proof/.test(error)));
    assert.ok(duplicateErrors.includes("Duplicate finding ID: QH-900."));

    const unknownWorkflow = validateFindingRecord(validFinding({
      workflowContract: "WF-NOT-REAL",
    }), schema, taxonomy);
    assert.ok(unknownWorkflow.some(error => /references unknown workflow contract/u.test(error)));

    const hiddenCoreP2 = validateFindingRecord(validFinding({
      severity: "P2",
      releaseBlocking: false,
    }), schema, taxonomy);
    assert.ok(hiddenCoreP2.some(error => (
      /releaseBlocking must match policy-derived value true/u.test(error)
    )));

    const unrecordedCause = validateFindingRecord(validFinding({
      rootCause: null,
      rootCauseStatus: "proven",
    }), schema, taxonomy);
    assert.ok(unrecordedCause.some(error => /requires a nonempty rootCause/u.test(error)));

    const unprovenNonIssue = validateFindingRecord(validFinding({
      status: "closed-non-issue",
      releaseBlocking: false,
    }), schema, taxonomy);
    assert.ok(unprovenNonIssue.some(error => /requires a proven disposition/u.test(error)));
    assert.ok(unprovenNonIssue.some(error => /protecting regression test/u.test(error)));
    assert.ok(unprovenNonIssue.some(error => /completed mutation disposition/u.test(error)));
    assert.ok(unprovenNonIssue.some(error => /completed live disposition/u.test(error)));
  });

  test("resolves finding evidence through the repository path boundary", function () {
    if (process.platform === "win32") this.skip();
    const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-finding-path-"));
    const outsideRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-finding-outside-"));
    const schema = require("../quality/finding.schema.json");
    const taxonomy = require("../quality/defect-taxonomy.json");
    try {
      fs.mkdirSync(path.join(fixtureRoot, "test"));
      fs.writeFileSync(path.join(outsideRoot, "evidence.test.js"), "outside\n");
      fs.symlinkSync(
        path.join(outsideRoot, "evidence.test.js"),
        path.join(fixtureRoot, "test", "linked.test.js")
      );

      const symlinkErrors = validateFindingRecord(validFinding({
        evidence: [{
          kind: "test",
          location: "test/linked.test.js:1",
          summary: "A symbolic-link evidence target must not be trusted.",
        }],
      }), schema, taxonomy, 1, fixtureRoot);
      const traversalErrors = validateFindingRecord(validFinding({
        evidence: [{
          kind: "test",
          location: "test/../outside.test.js:1",
          summary: "A traversal evidence target must not be trusted.",
        }],
      }), schema, taxonomy, 1, fixtureRoot);

      assert.ok(symlinkErrors.some(error => /evidence path is missing or unsafe/u.test(error)));
      assert.ok(traversalErrors.some(error => /evidence path is missing or unsafe/u.test(error)));
    } finally {
      fs.rmSync(fixtureRoot, { force: true, recursive: true });
      fs.rmSync(outsideRoot, { force: true, recursive: true });
    }
  });

  test("cannot hide an unverified fixed P0 behind caller-controlled flags", () => {
    const schema = require("../quality/finding.schema.json");
    const taxonomy = require("../quality/defect-taxonomy.json");
    const errors = validateFindingRecord(validFinding({
      severity: "P0",
      status: "open",
      deterministicStatus: "fixed",
      liveStatus: "blocked",
      customerImpact: 7,
      evidence: "not-an-evidence-array",
      rootCauseStatus: "suspected",
      regressionTest: null,
      mutationProof: { status: "not-started", summary: "Not proven." },
      fixedSha: SOURCE_SHA,
      liveVerification: { summary: "Not verified." },
      releaseBlocking: false,
    }), schema, taxonomy);

    assert.ok(errors.some(error => /customerImpact has invalid type/.test(error)));
    assert.ok(errors.some(error => /evidence has invalid type/.test(error)));
    assert.ok(errors.some(error => /requires a regression test/.test(error)));
    assert.ok(errors.some(error => /completed mutation proof/.test(error)));
    assert.ok(errors.some(error => /releaseBlocking must match policy-derived value true/.test(error)));
    assert.ok(errors.some(error => /not an ancestor/.test(error)));
  });

  test("cannot close a core product blocker through a not-applicable disposition", () => {
    const schema = require("../quality/finding.schema.json");
    const taxonomy = require("../quality/defect-taxonomy.json");
    for (const severity of ["P0", "P1", "P2"]) {
      const errors = validateFindingRecord(validFinding({
        severity,
        status: "closed",
        deterministicStatus: "not-applicable",
        liveStatus: "verified",
        rootCauseStatus: "unknown",
        regressionTest: null,
        mutationProof: { status: "not-applicable", summary: "No fix was claimed." },
        fixedSha: null,
        liveVerification: { summary: "The fixture claims a completed live disposition." },
        releaseBlocking: false,
      }), schema, taxonomy);

      assert.ok(errors.some(error => (
        /cannot close a release-critical product defect without a deterministic fix/u.test(error)
      )), `${severity} closure bypass must fail`);
      assert.ok(errors.some(error => (
        /deterministic non-applicability requires a proven disposition/u.test(error)
      )), `${severity} non-applicability must require proof`);
    }
  });

  test("permits a proof-bearing non-code closure without inventing a product fix", () => {
    const schema = require("../quality/finding.schema.json");
    const taxonomy = require("../quality/defect-taxonomy.json");
    const errors = validateFindingRecord(validFinding({
      severity: "P0",
      domain: "security-environment",
      status: "closed",
      deterministicStatus: "not-applicable",
      liveStatus: "verified",
      rootCauseStatus: "proven",
      rootCause: "The external security disposition is independently evidenced.",
      regressionTest: null,
      mutationProof: { status: "not-applicable", summary: "No repository code fix applies." },
      fixedSha: null,
      liveVerification: { summary: "The external closure evidence was verified." },
      releaseBlocking: false,
    }), schema, taxonomy);

    assert.deepStrictEqual(errors, []);
  });

  test("keeps every open P1 release-blocking after deterministic and live proof", () => {
    const schema = require("../quality/finding.schema.json");
    const taxonomy = require("../quality/defect-taxonomy.json");
    const errors = validateFindingRecord(validFinding({
      deterministicStatus: "fixed",
      liveStatus: "verified",
      rootCauseStatus: "proven",
      regressionTest: "test/searchProvider.test.js",
      mutationProof: { status: "mutation-killed", summary: "The regression killed the mutant." },
      fixedSha: SOURCE_SHA,
      liveVerification: { summary: "The exact candidate passed live verification." },
      releaseBlocking: false,
    }), schema, taxonomy);

    assert.ok(errors.some(error => /releaseBlocking must match policy-derived value true/.test(error)));
  });
});

suite("Quality contract verifier fixtures", function () {
  this.timeout(10_000);
  test("rejects whole-object replacements of deterministic release jobs", () => {
    const workflowPath = ".github/workflows/main.yml";
    const workflow = yaml.load(
      fs.readFileSync(path.join(root, workflowPath), "utf8"),
      { schema: yaml.CORE_SCHEMA }
    );
    const replacements = [
      {
        jobId: "extension-tests",
        error: "CI must execute the exact extension-test matrix and zero-test guard.",
        job: {
          name: "Extension tests",
          "runs-on": "ubuntu-24.04",
          steps: [{ name: "Skip extension tests", run: "echo skipped" }],
        },
      },
      {
        jobId: "package",
        error: "CI must build, verify, scan, and upload the exact reproducible VSIX inputs.",
        job: {
          name: "Package",
          "runs-on": "ubuntu-24.04",
          steps: [{
            name: "Upload README instead of a candidate",
            uses: "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            with: { name: "not-a-candidate", path: "README.md" },
          }],
        },
      },
      {
        jobId: "build-candidate",
        error: "CI build-candidate must require every deterministic input to succeed.",
        job: {
          name: "Deterministic build candidate",
          "runs-on": "ubuntu-24.04",
          steps: [{ name: "Claim success", run: "echo success" }],
        },
      },
    ];

    for (const replacement of replacements) {
      const changed = clone(workflow);
      changed.jobs[replacement.jobId] = replacement.job;
      const result = verifyQualityContracts({
        root,
        sourceOverrides: {
          [workflowPath]: yaml.dump(changed, { lineWidth: -1, noRefs: true }),
        },
      });
      assert.ok(
        result.errors.includes(replacement.error),
        `${replacement.jobId} whole-object replacement was accepted: ${result.errors.join("\n")}`
      );
    }
  });

  test("rejects aliases redirected away from exact CI entrypoints", function () {
    this.timeout(30_000);
    const redirects = [
      ["build", "npm run syntax"],
      ["check", "npm run build"],
      ["lint", "npm run build"],
      ["test", "npm run test:node"],
      ["package", "npm run package:verify"],
      ["package:list", "npm run package:verify"],
      ["package:verify", "npm run package"],
      ["pretest", "npm run build"],
      ["quality:fast", "npm run quality:full"],
      ["quality:full", "npm run quality:fast"],
      ["quality:release", "npm run quality:full"],
      ["syntax", "npm run build"],
      ["test:node", "npm run test:zero-guard"],
      ["test:ui:smoke", "npm test"],
      ["verify:polish", "npm run verify:version"],
      ["verify:version", "npm run verify:polish"],
      ["vscode:prepublish", "npm run build"],
    ];

    for (const [name, redirected] of redirects) {
      const manifest = clone(require("../package.json"));
      manifest.scripts[name] = redirected;
      const result = verifyQualityContracts({ root, manifest });
      assert.ok(
        result.errors.includes(
          `Package script ${name} must expose its exact reviewed quality entrypoint.`
        ),
        `${name} alias redirection was accepted: ${result.errors.join("\n")}`
      );
    }
  });

  test("rejects local qualification aliases redirected from exact entrypoints", () => {
    const redirects = [
      ["quality:qualification:prepare", "npm run build"],
      ["quality:qualification:launch", "npm run quality:qualification:prepare"],
      ["quality:qualification:reset", "npm run quality:qualification:launch"],
    ];

    for (const [name, redirected] of redirects) {
      const manifest = clone(require("../package.json"));
      manifest.scripts[name] = redirected;
      const result = verifyQualityContracts({ root, manifest });
      assert.ok(
        result.errors.includes(
          `Package script ${name} must expose its exact reviewed quality entrypoint.`
        ),
        `${name} local qualification redirect was accepted: ${result.errors.join("\n")}`
      );
    }
  });

  test("requires the exact handoff verifier immediately before CI evidence upload", () => {
    const workflowPath = ".github/workflows/main.yml";
    const workflow = fs.readFileSync(path.join(root, workflowPath), "utf8");
    const unconditional = verifyQualityContracts({
      root,
      sourceOverrides: {
        [workflowPath]: workflow.replace(
          "if: ${{ always() && steps.quality_evidence_handoff.outcome == 'success' && steps.quality_evidence_secret_scan.outcome == 'success' }}",
          "if: ${{ always() }}"
        ),
      },
    });
    assert.ok(unconditional.errors.includes(
      "CI must verify the exact fast-gate evidence immediately before a verifier-gated upload."
    ));

    const rewriteAfterReceipt = verifyQualityContracts({
      root,
      sourceOverrides: {
        [workflowPath]: workflow.replace(
          "run: npm run quality:verify-evidence -- --gate-profile fast",
          "run: npm run quality:report -- --gate-profile fast"
        ),
      },
    });
    assert.ok(rewriteAfterReceipt.errors.includes(
      "CI must verify the exact fast-gate evidence immediately before a verifier-gated upload."
    ));
  });

  test("rejects bypasses around changed and core mutation evidence handoffs", () => {
    const workflowPath = ".github/workflows/main.yml";
    const deepWorkflowPath = ".github/workflows/deep-quality.yml";
    const workflow = fs.readFileSync(path.join(root, workflowPath), "utf8");
    const deepWorkflow = fs.readFileSync(path.join(root, deepWorkflowPath), "utf8");
    const changedError =
      "CI must verify the exact changed-mutation evidence immediately before a verifier-gated upload.";
    const changedMutations = [
      workflow.replace(
        "if: ${{ always() && steps.mutation_evidence_handoff.outcome == 'success' }}",
        "if: ${{ always() }}"
      ),
      workflow.replace(
        "      - name: Run changed high-risk mutation gate",
        "      - name: Premature mutation upload\n"
        + "        uses: actions/upload-artifact@invented\n\n"
        + "      - name: Run changed high-risk mutation gate"
      ),
      workflow.replace("  pull_request:\n    branches: [main]\n", ""),
      workflow.replace(
        "  pull_request:\n    branches: [main]\n",
        "  pull_request:\n    branches: [main]\n    paths: [\"docs/**\"]\n"
      ),
      workflow.replace(
        "  pull_request:\n    branches: [main]\n",
        "  pull_request:\n    branches: [main]\n    types: [closed]\n"
      ),
      workflow.replace("  mutation:\n", "  mutation:\n    if: ${{ github.event_name == 'push' }}\n"),
      workflow.replace("  mutation:\n", "  mutation:\n    continue-on-error: true\n"),
    ];
    for (const changed of changedMutations) {
      assert.ok(verifyQualityContracts({
        root,
        sourceOverrides: { [workflowPath]: changed },
      }).errors.includes(changedError));
    }

    const deepError =
      "Deep CI must verify exact core-mutation evidence before a verifier-gated upload.";
    for (const changed of [
      deepWorkflow.replace(
        "if: ${{ always() && steps.mutation_evidence_handoff.outcome == 'success' }}",
        "if: ${{ always() }}"
      ),
      deepWorkflow.replace(
        "  core-mutation:\n",
        "  core-mutation:\n    continue-on-error: true\n"
      ),
      deepWorkflow.replace(
        "      - name: Set up the pinned secret scanner after mutation evidence\n        if: ${{ always() }}",
        "      - name: Set up the pinned secret scanner after mutation evidence"
      ),
      deepWorkflow.replace(
        "run: npm run quality:secrets:history",
        "run: npm run quality:secrets:current"
      ),
      deepWorkflow.replace(
        "      - name: Upload only the value-blind history receipt\n        if: ${{ always() }}",
        "      - name: Upload only the value-blind history receipt\n        if: ${{ steps.history_secret_scan.outcome == 'success' }}"
      ),
      deepWorkflow.replace(
        "          path: .quality/secrets/history.json",
        "          path: .quality/secrets"
      ),
    ]) {
      assert.ok(verifyQualityContracts({
        root,
        sourceOverrides: { [deepWorkflowPath]: changed },
      }).errors.includes(deepError));
    }
  });

  test("rejects signed-out UI workflow bypasses and profile uploads", () => {
    const deepWorkflowPath = ".github/workflows/deep-quality.yml";
    const deepWorkflow = fs.readFileSync(path.join(root, deepWorkflowPath), "utf8");
    const uiError =
      "Deep CI must bind and secret-scan signed-out packaged UI evidence before upload.";
    const mutations = [
      deepWorkflow.replace(
        "run: xvfb-run -a npm run test:ui:smoke",
        "run: npm run test:ui:smoke"
      ),
      deepWorkflow.replace(
        "run: node scripts/quality/verify-ui-evidence.js",
        "run: npm run quality:report"
      ),
      deepWorkflow.replace(
        "run: npm run quality:secrets:evidence",
        "run: npm run quality:secrets:current"
      ),
      deepWorkflow.replace(
        "if: ${{ always() && steps.ui_evidence_handoff.outcome == 'success' && steps.ui_evidence_secret_scan.outcome == 'success' }}",
        "if: ${{ always() }}"
      ),
      deepWorkflow.replace(
        "            .quality/secrets/evidence.json\n",
        "            .quality/secrets/evidence.json\n            .quality/qualification-profile\n"
      ),
      deepWorkflow.replace(
        "  signed-out-black-box-ui:\n    name: Signed-out packaged black-box UI\n    runs-on: ubuntu-24.04\n    timeout-minutes: 30\n    steps:\n      - name: Checkout exact source\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          fetch-depth: 0\n          persist-credentials: false",
        "  signed-out-black-box-ui:\n    name: Signed-out packaged black-box UI\n    runs-on: ubuntu-24.04\n    timeout-minutes: 30\n    steps:\n      - name: Checkout exact source\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          persist-credentials: false"
      ),
    ];
    for (const changed of mutations) {
      assert.ok(verifyQualityContracts({
        root,
        sourceOverrides: { [deepWorkflowPath]: changed },
      }).errors.includes(uiError));
    }
  });

  test("rejects authenticated production UI bypasses and credential/profile uploads", () => {
    const deepWorkflowPath = ".github/workflows/deep-quality.yml";
    const deepWorkflow = fs.readFileSync(path.join(root, deepWorkflowPath), "utf8");
    const authenticatedError =
      "Deep CI must verify production authenticated UI through the value-blind bootstrap boundary.";
    const mutations = [
      deepWorkflow.replace(
        "    environment: cloudsmith-release-qualification\n",
        ""
      ),
      deepWorkflow.replace(
        "CLOUDSMITH_QUALIFICATION_API_KEY: ${{ secrets.CLOUDSMITH_QUALIFICATION_API_KEY }}",
        "CLOUDSMITH_QUALIFICATION_API_KEY: unsafe-literal"
      ),
      deepWorkflow.replace(
        "run: xvfb-run -a node scripts/quality/run-authenticated-ci.js",
        "run: xvfb-run -a npm run quality:qualification:authenticated-ci"
      ),
      deepWorkflow.replace(
        "        id: authenticated_qualification\n        timeout-minutes: 15",
        "        id: authenticated_qualification"
      ),
      deepWorkflow.replace(
        "      - name: Prepare and validate exact authenticated candidate without credentials\n        run: npm run quality:qualification:prepare-authenticated-ci",
        "      - name: Prepare and validate exact authenticated candidate without credentials\n        env:\n          CLOUDSMITH_QUALIFICATION_API_KEY: unsafe-literal\n        run: npm run quality:qualification:prepare-authenticated-ci"
      ),
      deepWorkflow.replace(
        "        id: authenticated_profile_cleanup\n        if: ${{ always() }}",
        "        id: authenticated_profile_cleanup"
      ),
      deepWorkflow.replace(
        "run: npm run quality:verify-authenticated-evidence",
        "run: npm run quality:report"
      ),
      deepWorkflow.replace(
        "if: ${{ always() && steps.authenticated_evidence_handoff.outcome == 'success' && steps.authenticated_evidence_secret_scan.outcome == 'success' }}",
        "if: ${{ always() }}"
      ),
      deepWorkflow.replace(
        "            .quality/secrets/authenticated-ci.json\n            .quality/secrets/evidence.json\n",
        "            .quality/secrets/authenticated-ci.json\n            .quality/secrets/evidence.json\n            /tmp/authenticated-profile\n"
      ),
    ];
    for (const changed of mutations) {
      assert.ok(verifyQualityContracts({
        root,
        sourceOverrides: { [deepWorkflowPath]: changed },
      }).errors.includes(authenticatedError));
    }
  });

  test("rejects drift in the reviewed pinned secret scanner setup", () => {
    const actionPath = ".github/actions/setup-gitleaks/action.yml";
    const action = fs.readFileSync(path.join(root, actionPath), "utf8");
    const result = verifyQualityContracts({
      root,
      sourceOverrides: {
        [actionPath]: action.replace("8.30.1", "8.30.2"),
      },
    });
    assert.ok(result.errors.includes(
      "CI secret scanning must use the exact reviewed Gitleaks release and archive digest."
    ));
  });

  test("rejects required CI text hidden in inert YAML values", () => {
    const workflowPath = ".github/workflows/main.yml";
    const deepWorkflowPath = ".github/workflows/deep-quality.yml";
    const workflow = fs.readFileSync(path.join(root, workflowPath), "utf8");
    const deepWorkflow = fs.readFileSync(path.join(root, deepWorkflowPath), "utf8");
    const mainDocument = yaml.load(workflow, { schema: yaml.CORE_SCHEMA });
    const deepDocument = yaml.load(deepWorkflow, { schema: yaml.CORE_SCHEMA });
    const originalMutation = clone(mainDocument.jobs.mutation);
    const originalQuality = clone(mainDocument.jobs.quality);
    const originalCore = clone(deepDocument.jobs["core-mutation"]);
    const originalSignedOutUi = clone(deepDocument.jobs["signed-out-black-box-ui"]);
    const originalAuthenticatedUi = clone(deepDocument.jobs["authenticated-production-ui"]);

    mainDocument.jobs.mutation = {
      name: yaml.dump(originalMutation),
      "runs-on": "ubuntu-24.04",
      steps: [{
        name: "Unverified upload",
        uses: "actions/upload-artifact@v4",
        with: { name: "forged", path: "README.md", "if-no-files-found": "error" },
      }],
    };
    const inertMutation = verifyQualityContracts({
      root,
      sourceOverrides: {
        [workflowPath]: yaml.dump(mainDocument, { lineWidth: -1, noRefs: true }),
      },
    });
    assert.ok(inertMutation.errors.includes(
      "CI must verify the exact changed-mutation evidence immediately before a verifier-gated upload."
    ));

    mainDocument.jobs.mutation = originalMutation;
    mainDocument.jobs.quality = {
      name: yaml.dump(originalQuality),
      "runs-on": "ubuntu-24.04",
      steps: [{
        name: "Unverified upload",
        uses: "actions/upload-artifact@v4",
        with: { name: "forged", path: "README.md", "if-no-files-found": "error" },
      }],
    };
    const inertFast = verifyQualityContracts({
      root,
      sourceOverrides: {
        [workflowPath]: yaml.dump(mainDocument, { lineWidth: -1, noRefs: true }),
      },
    });
    assert.ok(inertFast.errors.includes(
      "CI must verify the exact fast-gate evidence immediately before a verifier-gated upload."
    ));

    deepDocument.jobs["core-mutation"] = {
      name: yaml.dump(originalCore),
      "runs-on": "ubuntu-24.04",
      steps: [{
        name: "Unverified upload",
        uses: "actions/upload-artifact@v4",
        with: { name: "forged", path: "README.md", "if-no-files-found": "error" },
      }],
    };
    const inertCore = verifyQualityContracts({
      root,
      sourceOverrides: {
        [deepWorkflowPath]: yaml.dump(deepDocument, { lineWidth: -1, noRefs: true }),
      },
    });
    assert.ok(inertCore.errors.includes(
      "Deep CI must verify exact core-mutation evidence before a verifier-gated upload."
    ));

    deepDocument.jobs["core-mutation"] = originalCore;
    deepDocument.jobs["signed-out-black-box-ui"] = {
      name: yaml.dump(originalSignedOutUi),
      "runs-on": "ubuntu-24.04",
      steps: [{
        name: "Unverified upload",
        uses: "actions/upload-artifact@v4",
        with: { name: "forged", path: ".quality", "if-no-files-found": "error" },
      }],
    };
    const inertSignedOutUi = verifyQualityContracts({
      root,
      sourceOverrides: {
        [deepWorkflowPath]: yaml.dump(deepDocument, { lineWidth: -1, noRefs: true }),
      },
    });
    assert.ok(inertSignedOutUi.errors.includes(
      "Deep CI must bind and secret-scan signed-out packaged UI evidence before upload."
    ));

    deepDocument.jobs["signed-out-black-box-ui"] = originalSignedOutUi;
    deepDocument.jobs["authenticated-production-ui"] = {
      name: yaml.dump(originalAuthenticatedUi),
      "runs-on": "ubuntu-24.04",
      steps: [{
        name: "Unverified upload",
        uses: "actions/upload-artifact@v4",
        with: { name: "forged", path: ".quality", "if-no-files-found": "error" },
      }],
    };
    const inertAuthenticatedUi = verifyQualityContracts({
      root,
      sourceOverrides: {
        [deepWorkflowPath]: yaml.dump(deepDocument, { lineWidth: -1, noRefs: true }),
      },
    });
    assert.ok(inertAuthenticatedUi.errors.includes(
      "Deep CI must verify production authenticated UI through the value-blind bootstrap boundary."
    ));
  });

  test("rejects an unmeasured mutation baseline", () => {
    const mutationBaseline = clone(require("../quality/mutation-baseline.json"));
    mutationBaseline.measuredAtSha = null;

    assert.ok(verifyQualityContracts({ root, mutationBaseline }).errors.includes(
      "Mutation baseline measuredAtSha must be a full 40-hex commit."
    ));
  });

  test("accepts the manifests with a strict source-reachable mutation fixture", () => {
    assert.deepStrictEqual(verifyQualityContracts({
      root,
      mutationBaseline: validTrackedMutationBaseline(),
      mutationBaselineCommitIsAncestor: () => true,
    }).errors, []);
  });

  test("rejects workflow evidence whose declared layer contradicts its runner inventory", () => {
    const workflows = clone(require("../quality/critical-workflows.json"));
    const workflow = workflows.workflows.find(candidate => (
      candidate.id === "WF-INSTALL-GUIDANCE"
    ));
    const evidence = workflow.evidence.find(item => (
      item.testFile === "test/commandFreshness.test.js"
    ));
    evidence.layer = "extension-host";

    const result = verifyQualityContracts({ root, workflows });

    assert.ok(result.errors.includes(
      "Workflow WF-INSTALL-GUIDANCE evidence test/commandFreshness.test.js declares extension-host but belongs to standalone."
    ));
  });

  test("rejects a duplicate workflow identity", () => {
    const workflows = clone(require("../quality/critical-workflows.json"));
    workflows.workflows.push(clone(workflows.workflows[0]));

    const result = verifyQualityContracts({ root, workflows });

    assert.ok(result.errors.includes(
      `Duplicate workflow ID: ${workflows.workflows[0].id}.`
    ));
  });

  test("rejects an action consumer that does not accept producer provenance", () => {
    const actions = clone(require("../quality/action-contracts.json"));
    const action = actions.actions.find(candidate => (
      candidate.producer.provenance !== "context-free"
    ));
    action.consumer.acceptedProvenance = ["context-free"];

    const result = verifyQualityContracts({ root, actions });

    assert.ok(result.errors.includes(
      `Action ${action.id} producer provenance ${action.producer.provenance} is rejected by its consumer.`
    ));
  });

  test("rejects a workflow with no authoritative outcome", () => {
    const workflows = clone(require("../quality/critical-workflows.json"));
    const workflow = workflows.workflows[0];
    workflow.authoritativeOutcome = "";

    const result = verifyQualityContracts({ root, workflows });

    assert.ok(result.errors.includes(
      `Workflow ${workflow.id} is missing an authoritative outcome.`
    ));
  });

  test("rejects a release-critical workflow with zero automated evidence", () => {
    const workflows = clone(require("../quality/critical-workflows.json"));
    const workflow = workflows.workflows[0];
    workflow.evidence = [];
    workflow.testFiles = [];

    const result = verifyQualityContracts({ root, workflows });

    assert.ok(result.errors.includes(
      `Release-critical workflow ${workflow.id} has no automated evidence.`
    ));
  });

  test("rejects a missing declared test file", () => {
    const workflows = clone(require("../quality/critical-workflows.json"));
    const workflow = workflows.workflows[0];
    const evidence = workflow.evidence[0];
    evidence.testFile = "test/does-not-exist.test.js";
    workflow.testFiles = uniqueSorted(workflow.evidence.map(item => item.testFile));

    const result = verifyQualityContracts({ root, workflows });

    assert.ok(result.errors.includes(
      `Workflow ${workflow.id} test file is not a normalized Git-visible regular file: test/does-not-exist.test.js.`
    ));
  });

  test("rejects traversal and non-Git-visible manifest targets without reading them", () => {
    const workflows = clone(require("../quality/critical-workflows.json"));
    const workflow = workflows.workflows[0];
    const evidence = workflow.evidence[0];
    const repositoryFiles = gitVisibleFiles(root);
    const originalFile = evidence.testFile;

    evidence.testFile = "../outside.test.js";
    workflow.testFiles = uniqueSorted(workflow.evidence.map(item => item.testFile));
    const traversal = verifyQualityContracts({
      root,
      workflows,
      repositoryFiles: [...repositoryFiles, "../outside.test.js"],
    });
    assert.ok(traversal.errors.some(error => (
      error.includes(`Workflow ${workflow.id}`) && /normalized Git-visible regular file/.test(error)
    )));

    evidence.testFile = originalFile;
    workflow.testFiles = uniqueSorted(workflow.evidence.map(item => item.testFile));
    const nonGitVisible = verifyQualityContracts({
      root,
      workflows,
      repositoryFiles: repositoryFiles.filter(file => file !== originalFile),
    });
    assert.ok(nonGitVisible.errors.some(error => (
      error.includes(originalFile) && /normalized Git-visible regular file/.test(error)
    )));
  });

  test("rejects symlinked manifest targets even when the inventory claims visibility", () => {
    const workflows = clone(require("../quality/critical-workflows.json"));
    const workflow = workflows.workflows[0];
    const evidence = workflow.evidence[0];
    const repositoryFiles = gitVisibleFiles(root);
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-quality-source-"));
    const outsideFile = path.join(outside, "linked.test.js");
    const relativeLink = `test/quality-linked-${process.pid}.test.js`;
    const link = path.join(root, relativeLink);
    try {
      fs.writeFileSync(outsideFile, `test(${JSON.stringify(evidence.testNames[0])}, () => {});\n`);
      fs.symlinkSync(outsideFile, link, "file");
      evidence.testFile = relativeLink;
      workflow.testFiles = uniqueSorted(workflow.evidence.map(item => item.testFile));

      const result = verifyQualityContracts({
        root,
        workflows,
        repositoryFiles: [...repositoryFiles, relativeLink],
      });

      assert.ok(result.errors.some(error => (
        error.includes(relativeLink) && /normalized Git-visible regular file/.test(error)
      )));
    } finally {
      fs.rmSync(link, { force: true });
      fs.rmSync(outside, { force: true, recursive: true });
    }
  });

  test("rejects a fictional producer action with no production wiring", () => {
    const actions = clone(require("../quality/action-contracts.json"));
    const action = actions.actions.find(candidate => (
      !candidate.producer.actionId.startsWith("cloudsmith-")
    ));
    action.producer.actionId = "fictionalAction";

    const result = verifyQualityContracts({ root, actions });

    assert.ok(result.errors.some(error => (
      error.includes(`Action ${action.id} producer action fictionalAction`)
    )));
  });

  test("does not accept a test title that exists only in a comment", () => {
    const workflows = clone(require("../quality/critical-workflows.json"));
    const workflow = workflows.workflows[0];
    const evidence = workflow.evidence[0];
    const invented = "comment-only authoritative test";
    evidence.testNames = [invented];
    const source = `${fs.readFileSync(path.join(root, evidence.testFile), "utf8")}\n// test(\"${invented}\", () => {});\n`;

    const result = verifyQualityContracts({
      root,
      workflows,
      sourceOverrides: { [evidence.testFile]: source },
    });

    assert.ok(result.errors.some(error => error.includes(invented)));
  });

  test("rejects a rendered WebView data-command with no declared handler", () => {
    const provider = "views/quarantineExplainProvider.js";
    const source = fs.readFileSync(path.join(root, provider), "utf8");
    const result = verifyQualityContracts({
      root,
      sourceOverrides: {
        [provider]: `${source}\nconst unhandledFixture = 'data-command="unhandledFixture"';\n`,
      },
    });

    assert.ok(result.errors.includes(
      "WebView WEBVIEW-QUARANTINE renders unhandled data-command unhandledFixture."
    ));
  });

  test("classifies synthetic WebView host messages as Extension Host wiring only", () => {
    const workflows = clone(require("../quality/critical-workflows.json"));
    const workflow = workflows.workflows.find(candidate => (
      candidate.evidence.some(item => item.testFile === "test/webviewPackageActionFlow.test.js")
    ));
    const evidence = workflow.evidence.find(item => (
      item.testFile === "test/webviewPackageActionFlow.test.js"
    ));
    evidence.layer = "black-box-ui";
    evidence.interactionMode = "synthetic-host-message";

    const result = verifyQualityContracts({ root, workflows });

    assert.ok(result.errors.includes(
      `Workflow ${workflow.id} synthetic host-message evidence must be classified as extension-host wiring.`
    ));
  });

  test("rejects host-managed production activation and credential-reading harness code", function () {
    this.timeout(5000);
    const configPath = ".vscode-test.mjs";
    const entrypointPath = "test/harness-extension/extension.js";
    const configSource = fs.readFileSync(path.join(root, configPath), "utf8");
    const entrypointSource = fs.readFileSync(path.join(root, entrypointPath), "utf8");
    const hostManaged = verifyQualityContracts({
      root,
      sourceOverrides: {
        [configPath]: configSource.replace(
          "extensionDevelopmentPath: TEST_HARNESS_EXTENSION_PATH",
          "extensionDevelopmentPath: repositoryRoot"
        ),
      },
    });
    assert.ok(hostManaged.errors.includes(
      "VS Code test configuration must install only the tracked credential-free harness extension."
    ));

    const sharedExtensions = verifyQualityContracts({
      root,
      sourceOverrides: {
        [configPath]: configSource.replace("--extensions-dir=", "--extension-cache="),
      },
    });
    assert.ok(sharedExtensions.errors.includes(
      "VS Code test configuration must isolate the installed-extension directory per run."
    ));

    const reusableHostRoot = verifyQualityContracts({
      root,
      sourceOverrides: {
        [configPath]: configSource
          .replace(
            "createIsolatedQualificationRoot(label, os.tmpdir())",
            "path.join(os.tmpdir(), `cloudsmith-vsc-${label}-${process.pid}`)"
          )
          .replace(
            "process.once(\"exit\", () => removeIsolatedQualificationRoot(runRoot));",
            ""
          ),
      },
    });
    assert.ok(reusableHostRoot.errors.includes(
      "VS Code test configuration must atomically create and exactly clean private per-run host roots."
    ));

    const credentialReading = verifyQualityContracts({
      root,
      sourceOverrides: {
        [entrypointPath]: `${entrypointSource}\nvoid context.secrets;\n`,
      },
    });
    assert.ok(credentialReading.errors.includes(
      "Credential-free test harness entrypoint may not read credentials or load production code."
    ));

    const workflows = clone(require("../quality/critical-workflows.json"));
    const activation = workflows.workflows.find(workflow => (
      workflow.id === "WF-ACTIVATION-STARTUP"
    ));
    activation.evidence.find(item => item.testFile === "test/activation.test.js")
      .executionMode = "host-managed-product-activation";
    const mislabeled = verifyQualityContracts({ root, workflows });
    assert.ok(mislabeled.errors.some(error => (
      /activation evidence must describe manual production composition/.test(error)
    )));
  });

  test("reports synthetic host-message composition separately from blocked DOM interaction", () => {
    const workflows = require("../quality/critical-workflows.json");
    const plan = getGatePlan("release");
    const receipts = plan.map(step => {
      const receipt = passedReceipt(step);
      if (step.id === "black-box-ui-smoke") {
        receipt.status = "blocked";
        receipt.exitCode = 2;
        receipt.artifactFingerprint = mutationArtifactFingerprint(blockedUiResult());
      }
      return receipt;
    });
    const report = generateReport({
      source: SOURCE_IDENTITY,
      profile: "release",
      plan,
      receipts,
      ...validImpactEvidence(),
      ...validMutationEvidence(),
      liveQualification: null,
      findings: [],
      findingsStatus: "passed",
      workflows,
      inventories: require("./testInventories"),
      ui: blockedUiResult(),
      uiArtifactFingerprint: mutationArtifactFingerprint(blockedUiResult()),
    });

    assert.strictEqual(
      report.webviewInteractionEvidence.syntheticHostMessage.classification,
      "extension-host-wiring"
    );
    assert.strictEqual(
      report.webviewInteractionEvidence.syntheticHostMessage.provesVisibleInteraction,
      false
    );
    assert.strictEqual(
      report.webviewInteractionEvidence.renderedDomActivation.status,
      "blocked"
    );
    assert.deepStrictEqual(report.extensionHostExecutionEvidence, {
      classification: "manual-production-composition",
      host: "real-vscode-extension-host",
      hostManagedProductActivation: false,
      credentialBoundary: "explicit-in-memory-context",
      status: "failed",
    });
    assert.match(renderMarkdown(report), /Synthetic host-message composition: Extension Host wiring only/);
    assert.match(renderMarkdown(report), /Rendered DOM activation: BLOCKED/);
    assert.match(
      renderMarkdown(report),
      /manual-production-composition in a real VS Code host\. Packaged-candidate activation is independently covered by the signed-out black-box UI lane\./
    );
  });
});

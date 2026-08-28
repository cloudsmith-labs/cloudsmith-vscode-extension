// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const Mocha = require("mocha");
const yaml = require("js-yaml");
const { withExpectedCleanupTaint } = require("./helpers/expectedCleanupTaint");
const {
  ROOT,
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
  exactRuntimeExecutable,
  executeCommand,
  gateChildEnvironment,
  gatePlanFingerprint,
  getGatePlan,
  receiptPath,
  runGate: runGateWithoutFixturePin,
  stepArtifactPaths,
  testEvidenceProofForStep,
  validateArtifactBinding,
  validateTestEvidenceBinding,
} = require("../scripts/quality/gate");
const {
  npmInstallationFingerprint,
} = require("../scripts/quality/canonical-node-runtime");
const { aggregateStatuses, fingerprint, sourceIdentity } = require("../scripts/quality/evidence");
const {
  CREDENTIAL_LIKE_ENVIRONMENT_NAME,
  NON_AUTH_AMBIENT_CAPABILITY_NAMES,
  NON_AUTH_CLEANUP_TAINT_ENV,
  NON_AUTH_QUALITY_ENVIRONMENT_ALLOWLIST,
  NON_AUTH_QUALITY_OVERRIDE_NAMES,
  assertActiveNonAuthQualityBoundary,
  buildNonAuthQualityEnvironment,
  cleanupNonAuthQualityEnvironment,
  createNonAuthQualityEnvironment,
  emptyExactOwnedDirectory,
  preserveNonAuthCleanupSubtree,
  removeExactOwnedDirectoryTree,
  withNonAuthQualityEnvironment,
} = require("../scripts/quality/non-auth-environment");
const {
  AUTHENTICATED_CANDIDATE_ARTIFACT,
  AUTHENTICATED_CANDIDATE_RECEIPT,
  LIVE_CANDIDATE_ARTIFACT,
  LIVE_CANDIDATE_RECEIPT,
  UI_CANDIDATE_ARTIFACT,
  UI_CANDIDATE_RECEIPT,
  candidateBindingFromReceipt,
  withStableSingleLinkFile,
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
  MUTATION_GLOBAL_OWNERS,
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
  assertExactReleaseGateTree,
  buildReleaseExposureResult,
  captureGeneratedEvidenceManifest,
  generatedEvidenceInventory,
} = require("../scripts/quality/release-exposure-scan");
const { UI_RESULT } = require("../scripts/quality/verify-ui-evidence");
const {
  discoverUiArtifacts,
  expectedBlackBoxUiTests,
  generateReport,
  hasDeterministicReportFailure,
  loadReportInputs,
  renderMarkdown,
  validateFindingRecord,
  validateFindings,
  validateImpactArtifact,
  writeReport,
} = require("../scripts/quality/report");
const { readBoundedFindingsBytes } = require("../scripts/quality/findings");
const { verifyQualityContracts } = require("../scripts/quality/verify-workflows");
const { verifyEvidenceHandoff } = require("../scripts/quality/verify-handoff");
const {
  validateMutationEvidenceArtifacts,
} = require("../scripts/quality/verify-mutation-handoff");
const TEST_INVENTORIES = require("./testInventories");
const NPM_INTEGRITY = JSON.parse(fs.readFileSync(path.join(__dirname, "../.npm-integrity"), "utf8"));

const root = path.resolve(__dirname, "..");
const SOURCE_SHA = "1111111111111111111111111111111111111111";
const BASE_SHA = "2222222222222222222222222222222222222222";
const SOURCE_IDENTITY = Object.freeze({
  sha: SOURCE_SHA,
  fingerprint: "a".repeat(64),
});
const LIVE_FIXTURE_NOW = new Date("2026-08-26T00:03:00.000Z");
const QUALITY_FIXTURE_HOME = fs.realpathSync(os.tmpdir());

function runGate(options = {}) {
  const fixtureOptions = options.root
    ? { ...options, root: fs.realpathSync(options.root) }
    : options;
  if (fixtureOptions.root) {
    const pin = path.join(fixtureOptions.root, ".node-version");
    if (!fs.existsSync(pin)) fs.writeFileSync(pin, `${process.versions.node}\n`);
  }
  return runGateWithoutFixturePin(fixtureOptions);
}

function writeCanonicalNpmFixture(fixtureRoot, options = {}) {
  const version = options.version || "10.9.8";
  const platform = options.platform || "linux";
  const nodeExecutable = options.nodeExecutable
    || path.join(fixtureRoot, "runtime", "bin", "node");
  fs.mkdirSync(path.dirname(nodeExecutable), { recursive: true });
  if (!fs.existsSync(nodeExecutable)) {
    fs.writeFileSync(nodeExecutable, "synthetic exact node runtime\n", { mode: 0o700 });
  }
  const packageRoot = platform === "win32"
    ? path.join(path.dirname(nodeExecutable), "node_modules", "npm")
    : path.join(path.dirname(path.dirname(nodeExecutable)), "lib", "node_modules", "npm");
  const cliPath = path.join(packageRoot, "bin", "npm-cli.js");
  fs.mkdirSync(path.dirname(cliPath), { recursive: true });
  fs.mkdirSync(path.join(packageRoot, "lib"), { recursive: true });
  fs.writeFileSync(path.join(fixtureRoot, ".npm-version"), `${version}\n`);
  const newline = platform === "win32" ? "\r\n" : "\n";
  fs.writeFileSync(
    cliPath,
    `#!/usr/bin/env node${newline}require('../lib/cli.js')(process)${newline}`,
  );
  fs.writeFileSync(path.join(packageRoot, "lib", "cli.js"), "module.exports = () => {}\n");
  fs.writeFileSync(path.join(packageRoot, "package.json"), `${JSON.stringify({
    name: "npm",
    version,
    main: "./index.js",
    bin: { npm: "bin/npm-cli.js", npx: "bin/npx-cli.js" },
    engines: { node: "^18.17.0 || >=20.5.0" },
  }, null, 2)}\n`);
  const installation = npmInstallationFingerprint(packageRoot, { platform });
  fs.writeFileSync(path.join(fixtureRoot, ".npm-integrity"), `${JSON.stringify({
    posix: installation.sha256,
    win32: installation.sha256,
  })}\n`);
  return { cliPath, nodeExecutable, packageRoot, platform, version };
}

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
  const evidence = step.evidencePath ? testEvidence(step, source) : null;
  return {
    stepId: step.id,
    category: step.category,
    command: step.command,
    status: "passed",
    exitCode: 0,
    signal: null,
    reason: null,
    testCounts: null,
    testEvidence: evidence,
    testEvidenceFingerprint: evidence ? testEvidenceFileFingerprint(evidence) : null,
    artifactFingerprint: step.artifactPath || step.artifactPaths
      ? artifactFingerprints[step.id]
      : null,
    source,
  };
}

function testEvidenceFileBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
}

function alternateTestEvidenceFileBytes(value) {
  return Buffer.from(`${JSON.stringify(value)} \n`);
}

function testEvidenceFileFingerprint(value) {
  return crypto.createHash("sha256").update(testEvidenceFileBytes(value)).digest("hex");
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

function materializeStepArtifacts(step, fixtureRoot, suffix = "initial") {
  const paths = stepArtifactPaths(step);
  if (paths.length === 0) return null;
  for (const relativePath of paths) {
    const target = path.join(fixtureRoot, ...relativePath.split("/"));
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, `${step.id}:${relativePath}:${suffix}\n`);
  }
  return artifactFingerprintForStep(step, fixtureRoot);
}

function materializeStepTestEvidence(step, fixtureRoot) {
  if (!step.evidencePath) return { fingerprint: null, value: null };
  const value = testEvidence(step);
  writeJson(step.evidencePath, value, fixtureRoot, {
    subtree: ".quality/test-results",
  });
  return {
    fingerprint: testEvidenceFileFingerprint(value),
    value,
  };
}

function fixtureArtifactStep() {
  return {
    id: "fixture-artifact",
    category: "fixture",
    executable: "node",
    args: ["fixture"],
    command: "node fixture",
    artifactPath: ".quality/fixture/artifact.json",
    artifactSubtree: ".quality/fixture",
    blockedExitCodes: [],
    sequence: 1,
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
    schemaVersion: 3,
    status: "passed",
    capturedAt: "2026-08-27T00:00:00.000Z",
    source: SOURCE_IDENTITY,
    repository: {
      branch: "test/release-quality-harness",
      dirty: true,
      status: "dirty",
    },
    toolchain: {
      nodeVersion: "v22.23.2",
      npmVersion: "10.9.8",
      npmInstallationSha256: NPM_INTEGRITY[process.platform === "win32" ? "win32" : "posix"],
      platform: process.platform,
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
  for (const filename of [".node-version", ".npm-version", ".npm-integrity"]) {
    fs.copyFileSync(path.join(root, filename), path.join(fixtureRoot, filename));
  }
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
    schemaVersion: 3,
    status: "passed",
    capturedAt,
    source,
    repository: {
      branch: "test/release-quality-harness",
      dirty: true,
      status: "dirty",
    },
    toolchain: {
      nodeVersion: "v22.23.2",
      npmVersion: "10.9.8",
      npmInstallationSha256: NPM_INTEGRITY[
        process.platform === "win32" ? "win32" : "posix"
      ],
      platform: process.platform,
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
  const generatedEvidence = captureGeneratedEvidenceManifest(fixture.root);
  const receipt = buildReleaseExposureResult({
    source: SOURCE_IDENTITY,
    candidateReceiptFingerprint: uiCandidateReceipt.fingerprint,
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
    const evidence = step.evidencePath ? testEvidence(step) : null;
    if (evidence) writeJson(step.evidencePath, evidence, fixtureRoot, {
      subtree: ".quality/test-results",
    });
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
      testEvidence: evidence,
      testEvidenceFingerprint: evidence ? testEvidenceFileFingerprint(evidence) : null,
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

  test("toolchain pins select verifier, packaging, Node, UI, and mutation evidence", () => {
    for (const file of [".node-version", ".npm-version", ".npm-integrity"]) {
      const report = analyzeFiles([file]);
      assert.strictEqual(report.ok, true, file);
      assert.deepStrictEqual(report.manifestFiles, [file]);
      assert.deepStrictEqual(report.requiredLayers, ["black-box-ui", "contract", "unit"]);
      for (const command of [
        "node scripts/quality/verify.js",
        "npm run package",
        "npm run test:mutation:core",
        "npm run test:node",
        "npm run test:ui:smoke",
      ]) {
        assert.ok(report.commands.includes(command), `${file}: ${command}`);
      }
    }
  });

  test("toolchain implementation owners force verifier, package, UI, and mutation evidence", () => {
    for (const file of [
      "scripts/quality/candidate-binding.js",
      "scripts/quality/canonical-node-runtime.js",
      "scripts/quality/gate.js",
      "scripts/quality/non-auth-environment.js",
      "scripts/quality/prepare-qualification.js",
      "scripts/quality/run-mutation.js",
      "scripts/quality/run-ui-smoke.js",
      "scripts/quality/verify-ui-evidence.js",
      "scripts/release/package-vsix.js",
      "scripts/release/verify-vsix.js",
    ]) {
      const report = analyzeFiles([file]);
      assert.strictEqual(report.ok, true, file);
      assert.deepStrictEqual(report.requiredLayers, ["black-box-ui", "contract", "unit"], file);
      for (const command of [
        "node scripts/quality/verify.js",
        "npm run package",
        "npm run test:mutation:core",
        "npm run test:node",
        "npm run test:ui:smoke",
      ]) {
        assert.ok(report.commands.includes(command), `${file}: ${command}`);
      }
    }
  });

  test("mutation toolchain owners force the core mutation gate", () => {
    const report = analyzeFiles(["scripts/quality/mutation-toolchain.js"]);
    assert.strictEqual(report.ok, true);
    assert.ok(report.requiredLayers.includes("unit"));
    assert.ok(report.commands.includes("npm run test:node"));
    assert.ok(report.commands.includes("npm run test:mutation:core"));
  });

  test("test inventory dependencies retain their mapped owner commands", () => {
    const report = analyzeFiles(["test/testInventories.js"]);
    assert.strictEqual(report.ok, true);
    assert.ok(report.requiredLayers.includes("unit"));
    assert.ok(report.commands.includes("npm run test:node"));
  });

  test("impact and mutation selection share every global mutation owner", () => {
    for (const file of MUTATION_GLOBAL_OWNERS) {
      const report = analyzeFiles([file]);
      assert.strictEqual(report.ok, true, file);
      assert.ok(report.requiredLayers.includes("unit"), file);
      assert.ok(report.commands.includes("npm run test:node"), file);
      assert.ok(report.commands.includes("npm run test:mutation:core"), file);
    }
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
    assert.strictEqual(
      [...NON_AUTH_QUALITY_ENVIRONMENT_ALLOWLIST, ...NON_AUTH_QUALITY_OVERRIDE_NAMES]
        .some(name => NON_AUTH_AMBIENT_CAPABILITY_NAMES.includes(name)),
      false
    );
    const sanitized = buildNonAuthQualityEnvironment({
      PATH: "/fixture/bin",
      QUALITY_BASE: "fixture-base",
      CLOUDSMITH_API_KEY: "synthetic-qh141-helper-sentinel",
      NODE_OPTIONS: "--require=synthetic-untrusted-hook",
      HOME: "/untrusted/profile",
      DISPLAY: ":synthetic-host-display",
      WAYLAND_DISPLAY: "synthetic-host-wayland",
      XAUTHORITY: "/synthetic/host-xauthority",
      XDG_RUNTIME_DIR: "/synthetic/host-runtime",
      DBUS_SESSION_BUS_ADDRESS: "unix:path=/synthetic/host-session-bus",
      SSH_AUTH_SOCK: "/synthetic/host-agent.sock",
      GPG_AGENT_INFO: "/synthetic/host-gpg-agent",
      KRB5CCNAME: "/synthetic/host-credential-cache",
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
    assert.strictEqual(gitChildEnvironments.length, 3);
    const sourceBoundaryRoot = path.dirname(gitChildEnvironments[0].HOME);
    for (const environment of gitChildEnvironments) {
      assert.strictEqual(environment.PATH, "/fixture/bin");
      assert.strictEqual(path.dirname(environment.HOME), sourceBoundaryRoot);
      assert.strictEqual(environment.HOME, environment.USERPROFILE);
      assert.strictEqual(environment.GIT_CONFIG_NOSYSTEM, "1");
      assert.strictEqual(environment.GIT_CONFIG_COUNT, "0");
      assert.strictEqual(environment.GIT_CONFIG_GLOBAL.startsWith(
        `${sourceBoundaryRoot}${path.sep}`
      ), true);
      assert.strictEqual(
        JSON.stringify(environment).includes("synthetic-qh141-source-sentinel"),
        false
      );
    }
    assert.strictEqual(fs.existsSync(sourceBoundaryRoot), false);
    assert.strictEqual(
      JSON.stringify(identity).includes("synthetic-qh141-source-sentinel"),
      false
    );
    let failedSourceBoundaryRoot;
    assert.throws(() => sourceIdentity(root, (_command, _arguments, options) => {
      failedSourceBoundaryRoot = path.dirname(options.env.HOME);
      throw new Error("synthetic source Git failure");
    }, {
      PATH: "/fixture/bin",
      GIT_CONFIG_GLOBAL: "/untrusted/config",
    }), /synthetic source Git failure/u);
    assert.strictEqual(fs.existsSync(failedSourceBoundaryRoot), false);
  });

  test("private non-auth homes block OS config fallback and clean every outcome", () => {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-non-auth-test-"));
    const ambientHome = path.join(scratch, "ambient-home");
    fs.mkdirSync(ambientHome, { mode: 0o700 });
    const ambientNpmConfig = path.join(ambientHome, ".npmrc");
    const ambientGitConfig = path.join(ambientHome, ".gitconfig");
    fs.writeFileSync(ambientNpmConfig, "qh146-untrusted-npm-config\n", { mode: 0o600 });
    fs.writeFileSync(ambientGitConfig, "qh146-untrusted-git-config\n", { mode: 0o600 });
    const hostileEnvironment = {
      PATH: "/fixture/bin",
      HOME: ambientHome,
      USERPROFILE: ambientHome,
      XDG_CONFIG_HOME: ambientHome,
      APPDATA: ambientHome,
      LOCALAPPDATA: ambientHome,
      NPM_CONFIG_USERCONFIG: ambientNpmConfig,
      GIT_CONFIG_GLOBAL: ambientGitConfig,
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "credential.helper",
      GIT_CONFIG_VALUE_0: "synthetic-helper",
      CLOUDSMITH_API_KEY: "synthetic-qh146-ambient-sentinel",
      NODE_OPTIONS: "--require=synthetic-untrusted-hook",
      DISPLAY: ":synthetic-host-display",
      WAYLAND_DISPLAY: "synthetic-host-wayland",
      XAUTHORITY: "/synthetic/host-xauthority",
      XDG_RUNTIME_DIR: "/synthetic/host-runtime",
      DBUS_SESSION_BUS_ADDRESS: "unix:path=/synthetic/host-session-bus",
      SSH_AUTH_SOCK: "/synthetic/host-agent.sock",
      GPG_AGENT_INFO: "/synthetic/host-gpg-agent",
      KRB5CCNAME: "/synthetic/host-credential-cache",
    };
    let successRoot;
    let failureRoot;
    try {
      const value = withNonAuthQualityEnvironment({
        environment: hostileEnvironment,
        temporaryParent: scratch,
      }, (environment, boundary) => {
        successRoot = boundary.root;
        assert.notStrictEqual(environment.HOME, ambientHome);
        assert.strictEqual(environment.HOME, environment.USERPROFILE);
        if (process.platform !== "win32") {
          assert.strictEqual(fs.lstatSync(boundary.root).mode & 0o077, 0);
        }
        for (const name of [
          "HOME", "USERPROFILE", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
          "XDG_DATA_HOME", "XDG_STATE_HOME", "APPDATA", "LOCALAPPDATA",
          "TMPDIR", "TMP", "TEMP", "NPM_CONFIG_CACHE",
        ]) {
          assert.strictEqual(environment[name].startsWith(`${boundary.root}${path.sep}`), true);
          assert.strictEqual(fs.lstatSync(environment[name]).isDirectory(), true);
          if (process.platform !== "win32") {
            assert.strictEqual(fs.lstatSync(environment[name]).mode & 0o077, 0);
          }
        }
        for (const name of [
          "NPM_CONFIG_USERCONFIG", "NPM_CONFIG_GLOBALCONFIG", "GIT_CONFIG_GLOBAL",
        ]) {
          assert.strictEqual(environment[name].startsWith(`${boundary.root}${path.sep}`), true);
          assert.strictEqual(fs.readFileSync(environment[name], "utf8"), "");
          if (process.platform !== "win32") {
            assert.strictEqual(fs.lstatSync(environment[name]).mode & 0o077, 0);
          }
        }
        assert.strictEqual(environment.GIT_CONFIG_NOSYSTEM, "1");
        assert.strictEqual(environment.GIT_CONFIG_COUNT, "0");
        assert.strictEqual(environment.GIT_TERMINAL_PROMPT, "0");
        assert.strictEqual(environment.GCM_INTERACTIVE, "never");
        assert.strictEqual(JSON.stringify(environment).includes(ambientHome), false);
        assert.strictEqual(
          JSON.stringify(environment).includes(hostileEnvironment.CLOUDSMITH_API_KEY),
          false
        );
        for (const name of NON_AUTH_AMBIENT_CAPABILITY_NAMES) {
          assert.strictEqual(Object.prototype.hasOwnProperty.call(environment, name), false);
        }
        return "boundary-result";
      });
      assert.strictEqual(value, "boundary-result");
      assert.strictEqual(fs.existsSync(successRoot), false);

      assert.throws(() => withNonAuthQualityEnvironment({
        environment: hostileEnvironment,
        temporaryParent: scratch,
      }, (_environment, boundary) => {
        failureRoot = boundary.root;
        throw new Error("synthetic child failure");
      }), /synthetic child failure/u);
      assert.strictEqual(fs.existsSync(failureRoot), false);

      let dualFailureRoot;
      withExpectedCleanupTaint(() => {
        assert.throws(() => withNonAuthQualityEnvironment({
          environment: hostileEnvironment,
          temporaryParent: scratch,
        }, (_environment, boundary) => {
          dualFailureRoot = boundary.root;
          fs.writeFileSync(
            path.join(boundary.root, "unexpected-cleanup-entry"),
            "synthetic refused cleanup bytes\n",
          );
          throw new Error("synthetic callback and cleanup failure");
        }), error => {
          assert.strictEqual(error instanceof AggregateError, true);
          assert.strictEqual(error.errors.length, 2);
          assert.match(error.errors[0].message, /synthetic callback and cleanup failure/u);
          assert.match(error.errors[1].message, /unsafe or changed tree/u);
          return true;
        });
      });
      const dualFailureQuarantine = fs.readdirSync(scratch).find(
        name => name.startsWith(`.${path.basename(dualFailureRoot)}.cleanup-`),
      );
      assert.strictEqual(typeof dualFailureQuarantine, "string");
      assert.strictEqual(fs.readFileSync(path.join(
        scratch,
        dualFailureQuarantine,
        "unexpected-cleanup-entry",
      ), "utf8"), "synthetic refused cleanup bytes\n");
      fs.rmSync(path.join(scratch, dualFailureQuarantine), { recursive: true, force: true });

      let windowsBoundaryRoot;
      const windowsResult = withNonAuthQualityEnvironment({
        environment: {
          Path: "/fixture/windows-bin",
          hOmE: ambientHome,
          UserProfile: ambientHome,
          Npm_Config_UserConfig: ambientNpmConfig,
          Git_Config_Global: ambientGitConfig,
          Cloudsmith_Api_Key: "synthetic-qh146-mixed-case-sentinel",
        },
        platform: "win32",
        temporaryParent: scratch,
      }, (environment, boundary) => {
        windowsBoundaryRoot = boundary.root;
        assert.strictEqual(environment.PATH, "/fixture/windows-bin");
        assert.strictEqual(environment.HOME, environment.USERPROFILE);
        assert.notStrictEqual(environment.HOME, ambientHome);
        assert.strictEqual(
          JSON.stringify(environment).includes("synthetic-qh146-mixed-case-sentinel"),
          false
        );
        return "windows-boundary-result";
      });
      assert.strictEqual(windowsResult, "windows-boundary-result");
      assert.strictEqual(fs.existsSync(windowsBoundaryRoot), false);

      const owned = createNonAuthQualityEnvironment({
        environment: { PATH: "/fixture/bin" },
        temporaryParent: scratch,
      });
      assert.strictEqual(
        assertActiveNonAuthQualityBoundary(owned, owned.environment),
        owned,
      );
      assert.throws(
        () => assertActiveNonAuthQualityBoundary({ ...owned }, owned.environment),
        /unknown boundary/u,
      );
      assert.throws(
        () => assertActiveNonAuthQualityBoundary(owned, { ...owned.environment }),
        /exact active environment/u,
      );
      withExpectedCleanupTaint(() => {
        assert.throws(
          () => cleanupNonAuthQualityEnvironment({ root: owned.root }),
          /unknown boundary/u
        );
      });
      assert.strictEqual(fs.existsSync(owned.root), true);
      assert.strictEqual(cleanupNonAuthQualityEnvironment(owned), true);
      assert.strictEqual(fs.existsSync(owned.root), false);
      assert.throws(
        () => cleanupNonAuthQualityEnvironment(owned),
        /unknown boundary/u
      );

      const unreadableHostileEnvironment = { PATH: "/fixture/bin" };
      for (const name of ["HOME", "NPM_CONFIG_USERCONFIG", "CLOUDSMITH_API_KEY"]) {
        Object.defineProperty(unreadableHostileEnvironment, name, {
          enumerable: true,
          get() {
            throw new Error("hostile ambient value was inspected");
          },
        });
      }
      assert.strictEqual(withNonAuthQualityEnvironment({
        environment: unreadableHostileEnvironment,
        temporaryParent: scratch,
      }, environment => environment.PATH), "/fixture/bin");

      assert.throws(() => withNonAuthQualityEnvironment({
        environment: { PATH: "/fixture/one", Path: "/fixture/two" },
        platform: "win32",
        temporaryParent: scratch,
      }, () => null), /case-colliding key/u);
      assert.deepStrictEqual(
        fs.readdirSync(scratch).sort(),
        ["ambient-home"]
      );
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });

  test("private non-auth cleanup quarantines the owned inode before entry-bounded removal", () => {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-non-auth-cleanup-race-",
    )));
    if (process.platform !== "win32") fs.chmodSync(scratch, 0o700);
    const boundary = createNonAuthQualityEnvironment({
      environment: { PATH: "/fixture/bin" },
      temporaryParent: scratch,
    });
    const ownedIdentity = fs.lstatSync(boundary.root);
    const victim = path.join(scratch, "synthetic-victim");
    fs.mkdirSync(victim, { mode: 0o700 });
    fs.writeFileSync(path.join(victim, "preserve.txt"), "synthetic victim survives\n");
    const originalRmdir = fs.rmdirSync;
    const originalRename = fs.renameSync;
    let quarantinedRoot = null;
    let substituted = false;
    try {
      fs.rmdirSync = function interceptedFinalRemoval(target, options) {
        if (!substituted
          && typeof target === "string"
          && path.dirname(target) === scratch
          && path.basename(target).includes(".cleanup-")) {
          quarantinedRoot = target;
          const movedIdentity = fs.lstatSync(target);
          assert.notStrictEqual(target, boundary.root);
          assert.strictEqual(movedIdentity.dev, ownedIdentity.dev);
          assert.strictEqual(movedIdentity.ino, ownedIdentity.ino);
          assert.strictEqual(fs.existsSync(boundary.root), false);
          originalRename.call(fs, victim, boundary.root);
          substituted = true;
        }
        return originalRmdir.call(fs, target, options);
      };
      withExpectedCleanupTaint(() => {
        assert.throws(
          () => cleanupNonAuthQualityEnvironment(boundary),
          /path was reoccupied/u,
        );
      });
    } finally {
      fs.rmdirSync = originalRmdir;
    }
    try {
      assert.strictEqual(substituted, true);
      assert.strictEqual(fs.existsSync(quarantinedRoot), false);
      assert.strictEqual(
        fs.readFileSync(path.join(boundary.root, "preserve.txt"), "utf8"),
        "synthetic victim survives\n",
      );
      assert.strictEqual(
        fs.existsSync(path.join(boundary.root, ".cloudsmith-non-auth-owner.json")),
        false,
      );
      assert.throws(
        () => cleanupNonAuthQualityEnvironment(boundary),
        /unknown boundary/u,
      );
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });

  test("a registered unsafe subtree taints outer cleanup across a later rename", () => {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-non-auth-preserved-rename-",
    )));
    if (process.platform !== "win32") fs.chmodSync(scratch, 0o700);
    const boundary = createNonAuthQualityEnvironment({
      environment: { PATH: "/fixture/bin" },
      temporaryParent: scratch,
    });
    const original = path.join(boundary.paths.temporary, "tainted-launcher");
    const renamed = path.join(boundary.paths.temporary, "renamed-launcher");
    fs.mkdirSync(original);
    fs.writeFileSync(path.join(original, "preserve.txt"), "renamed bytes survive\n");
    withExpectedCleanupTaint(() => {
      assert.strictEqual(preserveNonAuthCleanupSubtree(original), true);
    });
    fs.renameSync(original, renamed);
    withExpectedCleanupTaint(() => {
      assert.throws(
        () => cleanupNonAuthQualityEnvironment(boundary),
        /preserved an unsafe or changed tree/u,
      );
    });
    const quarantineName = fs.readdirSync(scratch).find(
      name => name.startsWith(`.${path.basename(boundary.root)}.cleanup-`),
    );
    try {
      assert.strictEqual(typeof quarantineName, "string");
      assert.strictEqual(fs.readFileSync(path.join(
        scratch,
        quarantineName,
        "tmp",
        "renamed-launcher",
        "preserve.txt",
      ), "utf8"), "renamed bytes survive\n");
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });

  test("an unsafe subtree renamed before registration still taints outer cleanup", () => {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-non-auth-preserved-prerename-",
    )));
    if (process.platform !== "win32") fs.chmodSync(scratch, 0o700);
    const boundary = createNonAuthQualityEnvironment({
      environment: { PATH: "/fixture/bin" },
      temporaryParent: scratch,
    });
    const original = path.join(boundary.paths.temporary, "tainted-launcher");
    const renamed = path.join(boundary.paths.temporary, "renamed-launcher");
    fs.mkdirSync(original);
    fs.writeFileSync(path.join(original, "preserve.txt"), "pre-renamed bytes survive\n");
    fs.renameSync(original, renamed);
    withExpectedCleanupTaint(() => {
      assert.strictEqual(preserveNonAuthCleanupSubtree(original), true);
    });
    withExpectedCleanupTaint(() => {
      assert.throws(
        () => cleanupNonAuthQualityEnvironment(boundary),
        /preserved an unsafe or changed tree/u,
      );
    });
    const quarantineName = fs.readdirSync(scratch).find(
      name => name.startsWith(`.${path.basename(boundary.root)}.cleanup-`),
    );
    try {
      assert.strictEqual(typeof quarantineName, "string");
      assert.strictEqual(fs.readFileSync(path.join(
        scratch,
        quarantineName,
        "tmp",
        "renamed-launcher",
        "preserve.txt",
      ), "utf8"), "pre-renamed bytes survive\n");
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });

  test("a preserved subtree taints every containing active cleanup boundary", () => {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-non-auth-preserved-nested-",
    )));
    if (process.platform !== "win32") fs.chmodSync(scratch, 0o700);
    const outer = createNonAuthQualityEnvironment({
      environment: { PATH: "/fixture/bin" },
      temporaryParent: scratch,
    });
    const inner = createNonAuthQualityEnvironment({
      environment: { PATH: "/fixture/bin" },
      temporaryParent: outer.paths.temporary,
    });
    const preserved = path.join(inner.paths.temporary, "tainted-launcher");
    fs.mkdirSync(preserved);
    fs.writeFileSync(path.join(preserved, "preserve.txt"), "nested bytes survive\n");
    withExpectedCleanupTaint(() => {
      assert.strictEqual(preserveNonAuthCleanupSubtree(preserved), true);
    });
    withExpectedCleanupTaint(() => {
      assert.throws(
        () => cleanupNonAuthQualityEnvironment(inner),
        /preserved an unsafe or changed tree/u,
      );
    });
    const innerQuarantineName = fs.readdirSync(outer.paths.temporary).find(
      name => name.startsWith(`.${path.basename(inner.root)}.cleanup-`),
    );
    assert.strictEqual(typeof innerQuarantineName, "string");
    withExpectedCleanupTaint(() => {
      assert.throws(
        () => cleanupNonAuthQualityEnvironment(outer),
        /preserved an unsafe or changed tree/u,
      );
    });
    const outerQuarantineName = fs.readdirSync(scratch).find(
      name => name.startsWith(`.${path.basename(outer.root)}.cleanup-`),
    );
    try {
      assert.strictEqual(typeof outerQuarantineName, "string");
      assert.strictEqual(fs.readFileSync(path.join(
        scratch,
        outerQuarantineName,
        "tmp",
        innerQuarantineName,
        "tmp",
        "tainted-launcher",
        "preserve.txt",
      ), "utf8"), "nested bytes survive\n");
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });

  test("an inner cleanup refusal taints every containing active boundary", () => {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-non-auth-refused-nested-",
    )));
    if (process.platform !== "win32") fs.chmodSync(scratch, 0o700);
    const outer = createNonAuthQualityEnvironment({
      environment: { PATH: "/fixture/bin" },
      temporaryParent: scratch,
    });
    const inner = createNonAuthQualityEnvironment({
      environment: { PATH: "/fixture/bin" },
      temporaryParent: outer.paths.temporary,
    });
    const displacedHome = path.join(scratch, "displaced-inner-home");
    const victim = path.join(scratch, "synthetic-victim");
    fs.mkdirSync(victim, { mode: 0o700 });
    fs.writeFileSync(path.join(victim, "preserve.txt"), "refused bytes survive\n");
    fs.renameSync(inner.paths.home, displacedHome);
    fs.renameSync(victim, inner.paths.home);

    withExpectedCleanupTaint(() => {
      assert.throws(
        () => cleanupNonAuthQualityEnvironment(inner),
        /exact creator-owned private directory/u,
      );
    });
    assert.strictEqual(fs.existsSync(inner.root), true);
    withExpectedCleanupTaint(() => {
      assert.throws(
        () => cleanupNonAuthQualityEnvironment(outer),
        /preserved an unsafe or changed tree/u,
      );
    });
    const outerQuarantineName = fs.readdirSync(scratch).find(
      name => name.startsWith(`.${path.basename(outer.root)}.cleanup-`),
    );
    try {
      assert.strictEqual(typeof outerQuarantineName, "string");
      assert.strictEqual(fs.readFileSync(path.join(
        scratch,
        outerQuarantineName,
        "tmp",
        path.basename(inner.root),
        "home",
        "preserve.txt",
      ), "utf8"), "refused bytes survive\n");
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });

  test("a refused inner creation rollback taints every containing active boundary", () => {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-non-auth-create-refused-nested-",
    )));
    if (process.platform !== "win32") fs.chmodSync(scratch, 0o700);
    const outer = createNonAuthQualityEnvironment({
      environment: { PATH: "/fixture/bin" },
      temporaryParent: scratch,
    });
    const victim = path.join(scratch, "synthetic-victim");
    fs.mkdirSync(victim, { mode: 0o700 });
    fs.writeFileSync(path.join(victim, "preserve.txt"), "rollback bytes survive\n");
    const originalWriteFile = fs.writeFileSync;
    let partialRoot = null;
    withExpectedCleanupTaint(() => {
      try {
        fs.writeFileSync = function interceptOwnershipMarker(target, ...args) {
          if (!partialRoot
            && typeof target === "string"
            && path.basename(target) === ".cloudsmith-non-auth-owner.json"
            && path.dirname(path.dirname(target)) === outer.paths.temporary) {
            partialRoot = path.dirname(target);
            fs.renameSync(victim, path.join(partialRoot, "unexpected-victim"));
            throw new Error("synthetic marker creation failure");
          }
          return originalWriteFile.call(fs, target, ...args);
        };
        assert.throws(
          () => createNonAuthQualityEnvironment({
            environment: { PATH: "/fixture/bin" },
            temporaryParent: outer.paths.temporary,
          }),
          /unsafe or changed tree/u,
        );
      } finally {
        fs.writeFileSync = originalWriteFile;
      }
    });
    const innerQuarantineName = fs.readdirSync(outer.paths.temporary).find(
      name => name.startsWith(`.${path.basename(partialRoot)}.cleanup-`),
    );
    assert.strictEqual(typeof innerQuarantineName, "string");
    withExpectedCleanupTaint(() => {
      assert.throws(
        () => cleanupNonAuthQualityEnvironment(outer),
        /preserved an unsafe or changed tree/u,
      );
    });
    const outerQuarantineName = fs.readdirSync(scratch).find(
      name => name.startsWith(`.${path.basename(outer.root)}.cleanup-`),
    );
    try {
      assert.strictEqual(typeof outerQuarantineName, "string");
      assert.strictEqual(fs.readFileSync(path.join(
        scratch,
        outerQuarantineName,
        "tmp",
        innerQuarantineName,
        "unexpected-victim",
        "preserve.txt",
      ), "utf8"), "rollback bytes survive\n");
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });

  test("a reoccupied inner creation rollback taints every containing active boundary", () => {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-non-auth-create-reoccupied-nested-",
    )));
    if (process.platform !== "win32") fs.chmodSync(scratch, 0o700);
    const outer = createNonAuthQualityEnvironment({
      environment: { PATH: "/fixture/bin" },
      temporaryParent: scratch,
    });
    const victim = path.join(scratch, "synthetic-victim");
    fs.mkdirSync(victim, { mode: 0o700 });
    fs.writeFileSync(path.join(victim, "preserve.txt"), "reoccupied bytes survive\n");
    const originalWriteFile = fs.writeFileSync;
    const originalRename = fs.renameSync;
    let partialRoot = null;
    let reoccupied = false;
    withExpectedCleanupTaint(() => {
      try {
        fs.writeFileSync = function interceptOwnershipMarker(target, ...args) {
          if (!partialRoot
            && typeof target === "string"
            && path.basename(target) === ".cloudsmith-non-auth-owner.json"
            && path.dirname(path.dirname(target)) === outer.paths.temporary) {
            partialRoot = path.dirname(target);
            throw new Error("synthetic marker creation failure");
          }
          return originalWriteFile.call(fs, target, ...args);
        };
        fs.renameSync = function interceptRollbackQuarantine(source, destination) {
          originalRename.call(fs, source, destination);
          if (!reoccupied
            && source === partialRoot
            && path.dirname(destination) === outer.paths.temporary
            && path.basename(destination).startsWith(`.${path.basename(partialRoot)}.cleanup-`)) {
            originalRename.call(fs, victim, partialRoot);
            reoccupied = true;
          }
        };
        assert.throws(
          () => createNonAuthQualityEnvironment({
            environment: { PATH: "/fixture/bin" },
            temporaryParent: outer.paths.temporary,
          }),
          /reoccupied during creation rollback/u,
        );
      } finally {
        fs.writeFileSync = originalWriteFile;
        fs.renameSync = originalRename;
      }
    });
    assert.strictEqual(reoccupied, true);
    assert.strictEqual(fs.existsSync(partialRoot), true);
    withExpectedCleanupTaint(() => {
      assert.throws(
        () => cleanupNonAuthQualityEnvironment(outer),
        /preserved an unsafe or changed tree/u,
      );
    });
    const outerQuarantineName = fs.readdirSync(scratch).find(
      name => name.startsWith(`.${path.basename(outer.root)}.cleanup-`),
    );
    try {
      assert.strictEqual(typeof outerQuarantineName, "string");
      assert.strictEqual(fs.readFileSync(path.join(
        scratch,
        outerQuarantineName,
        "tmp",
        path.basename(partialRoot),
        "preserve.txt",
      ), "utf8"), "reoccupied bytes survive\n");
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });

  test("exact sub-cleanup refusals taint their active outer boundary", () => {
    for (const [label, cleanup] of [
      ["remove", removeExactOwnedDirectoryTree],
      ["empty", emptyExactOwnedDirectory],
    ]) {
      const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
        os.tmpdir(),
        `cloudsmith-non-auth-${label}-refused-`,
      )));
      if (process.platform !== "win32") fs.chmodSync(scratch, 0o700);
      const outer = createNonAuthQualityEnvironment({
        environment: { PATH: "/fixture/bin" },
        temporaryParent: scratch,
      });
      const exactRoot = path.join(outer.paths.temporary, `${label}-scratch`);
      fs.mkdirSync(exactRoot, { mode: 0o700 });
      const rootIdentity = fs.lstatSync(exactRoot);
      const victim = path.join(scratch, `${label}-victim`);
      fs.mkdirSync(victim, { mode: 0o700 });
      fs.writeFileSync(path.join(victim, "preserve.txt"), `${label} bytes survive\n`);
      fs.renameSync(victim, path.join(exactRoot, "unexpected-victim"));

      withExpectedCleanupTaint(() => {
        assert.throws(
          () => cleanup(exactRoot, {
            errorMessage: `Synthetic ${label} cleanup refused an unsafe tree.`,
            expectedRootEntries: [],
            expectedRootIdentity: rootIdentity,
          }),
          new RegExp(`Synthetic ${label} cleanup refused an unsafe tree\\.`, "u"),
        );
      });
      withExpectedCleanupTaint(() => {
        assert.throws(
          () => cleanupNonAuthQualityEnvironment(outer),
          /preserved an unsafe or changed tree/u,
        );
      });
      const outerQuarantineName = fs.readdirSync(scratch).find(
        name => name.startsWith(`.${path.basename(outer.root)}.cleanup-`),
      );
      try {
        assert.strictEqual(typeof outerQuarantineName, "string");
        assert.strictEqual(fs.readFileSync(path.join(
          scratch,
          outerQuarantineName,
          "tmp",
          path.basename(exactRoot),
          "unexpected-victim",
          "preserve.txt",
        ), "utf8"), `${label} bytes survive\n`);
      } finally {
        fs.rmSync(scratch, { recursive: true, force: true });
      }
    }
  });

  test("a child cleanup refusal durably taints its parent process boundary", () => {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-non-auth-cross-process-refused-",
    )));
    if (process.platform !== "win32") fs.chmodSync(scratch, 0o700);
    const outer = createNonAuthQualityEnvironment({
      environment: { PATH: process.env.PATH || "/usr/bin:/bin" },
      temporaryParent: scratch,
    });
    const childScript = [
      "const fs=require('fs');",
      "const path=require('path');",
      `const boundaryModule=require(${JSON.stringify(path.join(
        ROOT,
        "scripts/quality/non-auth-environment.js",
      ))});`,
      "const inner=boundaryModule.createNonAuthQualityEnvironment({",
      "environment:process.env,temporaryParent:process.env.TMPDIR});",
      "const target=path.join(inner.paths.temporary,'tainted-launcher');",
      "fs.mkdirSync(target);",
      "fs.writeFileSync(path.join(target,'preserve.txt'),'child bytes survive\\n');",
      "boundaryModule.preserveNonAuthCleanupSubtree(target);",
      "try{boundaryModule.cleanupNonAuthQualityEnvironment(inner);}catch{}",
    ].join("");
    const child = spawnSync(process.execPath, ["-e", childScript], {
      cwd: ROOT,
      encoding: "utf8",
      env: outer.environment,
    });
    assert.strictEqual(child.status, 0, child.stderr);
    assert.strictEqual(child.stdout, "");
    const innerQuarantineName = fs.readdirSync(outer.paths.temporary).find(
      name => name.startsWith(".cloudsmith-non-auth-") && name.includes(".cleanup-"),
    );
    assert.strictEqual(typeof innerQuarantineName, "string");

    withExpectedCleanupTaint(() => {
      assert.throws(
        () => cleanupNonAuthQualityEnvironment(outer),
        /unsafe or changed tree/u,
      );
    });
    const outerQuarantineName = fs.readdirSync(scratch).find(
      name => name.startsWith(`.${path.basename(outer.root)}.cleanup-`),
    );
    try {
      assert.strictEqual(typeof outerQuarantineName, "string");
      assert.strictEqual(fs.readFileSync(path.join(
        scratch,
        outerQuarantineName,
        "tmp",
        innerQuarantineName,
        "tmp",
        "tainted-launcher",
        "preserve.txt",
      ), "utf8"), "child bytes survive\n");
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });

  test("cross-process taint writes only the verified receipt after root substitution", () => {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-non-auth-cross-process-substitution-",
    )));
    if (process.platform !== "win32") fs.chmodSync(scratch, 0o700);
    const outer = createNonAuthQualityEnvironment({
      environment: { PATH: process.env.PATH || "/usr/bin:/bin" },
      temporaryParent: scratch,
    });
    const displacedRoot = path.join(scratch, "displaced-owned-root");
    const victim = path.join(scratch, "synthetic-victim");
    fs.mkdirSync(victim, { mode: 0o700 });
    fs.writeFileSync(path.join(victim, "keep.txt"), "foreign bytes remain exact\n");
    const originalWrite = fs.writeSync;
    const hadCapability = Object.prototype.hasOwnProperty.call(
      process.env,
      NON_AUTH_CLEANUP_TAINT_ENV,
    );
    const priorCapability = process.env[NON_AUTH_CLEANUP_TAINT_ENV];
    let substituted = false;
    try {
      process.env[NON_AUTH_CLEANUP_TAINT_ENV] = outer.environment[NON_AUTH_CLEANUP_TAINT_ENV];
      fs.writeSync = function interceptVerifiedReceiptWrite(descriptor, ...args) {
        if (!substituted) {
          fs.renameSync(outer.root, displacedRoot);
          fs.renameSync(victim, outer.root);
          substituted = true;
        }
        return originalWrite.call(fs, descriptor, ...args);
      };
      assert.strictEqual(
        preserveNonAuthCleanupSubtree(path.join(outer.paths.temporary, "future-refusal")),
        true,
      );
    } finally {
      fs.writeSync = originalWrite;
      if (hadCapability) {
        process.env[NON_AUTH_CLEANUP_TAINT_ENV] = priorCapability;
      } else {
        delete process.env[NON_AUTH_CLEANUP_TAINT_ENV];
      }
    }
    try {
      assert.strictEqual(substituted, true);
      assert.deepStrictEqual(fs.readdirSync(outer.root), ["keep.txt"]);
      assert.strictEqual(
        fs.readFileSync(path.join(outer.root, "keep.txt"), "utf8"),
        "foreign bytes remain exact\n",
      );
      assert.strictEqual(
        fs.lstatSync(path.join(displacedRoot, path.basename(outer.paths.cleanupTaint))).size,
        1,
      );
      withExpectedCleanupTaint(() => {
        assert.throws(
          () => cleanupNonAuthQualityEnvironment(outer),
          /exact creator-owned private directory/u,
        );
      });
      assert.deepStrictEqual(fs.readdirSync(outer.root), ["keep.txt"]);
      assert.strictEqual(
        fs.readFileSync(path.join(outer.root, "keep.txt"), "utf8"),
        "foreign bytes remain exact\n",
      );
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });

  test("private non-auth cleanup fails closed on final quarantine substitution", () => {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-non-auth-cleanup-final-swap-",
    )));
    if (process.platform !== "win32") fs.chmodSync(scratch, 0o700);
    const boundary = createNonAuthQualityEnvironment({
      environment: { PATH: "/fixture/bin" },
      temporaryParent: scratch,
    });
    fs.mkdirSync(path.join(boundary.paths.temporary, "nested"));
    fs.writeFileSync(
      path.join(boundary.paths.temporary, "nested", "owned.txt"),
      "synthetic owned cleanup bytes\n",
    );
    const victim = path.join(scratch, "synthetic-victim");
    fs.mkdirSync(victim, { mode: 0o700 });
    fs.writeFileSync(path.join(victim, "preserve.txt"), "synthetic victim survives\n");
    const originalRename = fs.renameSync;
    const originalRmdir = fs.rmdirSync;
    let displacedOwnedRoot;
    let substitutedRoot;
    try {
      fs.rmdirSync = function interceptFinalQuarantineRemoval(target, options) {
        if (!substitutedRoot
          && typeof target === "string"
          && path.dirname(target) === scratch
          && path.basename(target).includes(".cleanup-")) {
          substitutedRoot = target;
          displacedOwnedRoot = `${target}.owned-displaced`;
          originalRename.call(fs, target, displacedOwnedRoot);
          originalRename.call(fs, victim, target);
        }
        return originalRmdir.call(fs, target, options);
      };
      withExpectedCleanupTaint(() => {
        assert.throws(
          () => cleanupNonAuthQualityEnvironment(boundary),
          /unsafe or changed tree/u,
        );
      });
    } finally {
      fs.rmdirSync = originalRmdir;
    }
    try {
      assert.strictEqual(typeof substitutedRoot, "string");
      assert.strictEqual(fs.existsSync(displacedOwnedRoot), true);
      assert.strictEqual(
        fs.readFileSync(path.join(substitutedRoot, "preserve.txt"), "utf8"),
        "synthetic victim survives\n",
      );
      assert.strictEqual(fs.existsSync(boundary.root), false);
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });

  test("entry-bounded cleanup rejects an entry injected after its exact inventory", () => {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-exact-cleanup-injected-entry-",
    )));
    if (process.platform !== "win32") fs.chmodSync(scratch, 0o700);
    const root = path.join(scratch, "owned-root");
    fs.mkdirSync(root, { mode: 0o700 });
    const rootIdentity = fs.lstatSync(root);
    const originalRmdir = fs.rmdirSync;
    let injected = false;
    try {
      fs.rmdirSync = function injectEntryAtFinalRemoval(target, options) {
        if (!injected && target === root) {
          fs.writeFileSync(path.join(root, "late-entry"), "synthetic late bytes\n");
          injected = true;
        }
        return originalRmdir.call(fs, target, options);
      };
      withExpectedCleanupTaint(() => {
        assert.throws(
          () => removeExactOwnedDirectoryTree(root, {
            errorMessage: "Synthetic exact cleanup rejected tree drift.",
            expectedRootEntries: [],
            expectedRootIdentity: rootIdentity,
          }),
          /rejected tree drift/u,
        );
      });
    } finally {
      fs.rmdirSync = originalRmdir;
    }
    try {
      assert.strictEqual(injected, true);
      assert.strictEqual(
        fs.readFileSync(path.join(root, "late-entry"), "utf8"),
        "synthetic late bytes\n",
      );
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });

  test("entry-bounded cleanup unlinks only its inventoried hard-link name", () => {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-exact-cleanup-hard-link-",
    )));
    if (process.platform !== "win32") fs.chmodSync(scratch, 0o700);
    const root = path.join(scratch, "owned-root");
    const outside = path.join(scratch, "outside-file");
    const linked = path.join(root, "linked-file");
    fs.mkdirSync(root, { mode: 0o700 });
    fs.writeFileSync(outside, "synthetic hard-link bytes\n");
    fs.linkSync(outside, linked);
    try {
      assert.strictEqual(removeExactOwnedDirectoryTree(root, {
        allowAdditionalRootEntries: true,
        errorMessage: "Synthetic exact cleanup rejected unsafe entry type.",
        expectedRootEntries: [],
        expectedRootIdentity: fs.lstatSync(root),
      }), true);
      assert.strictEqual(fs.existsSync(linked), false);
      assert.strictEqual(fs.existsSync(root), false);
      assert.strictEqual(fs.readFileSync(outside, "utf8"), "synthetic hard-link bytes\n");
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });

  test("QH-168 production cleanup paths forbid recursive pathname deletion", () => {
    for (const relative of [
      "scripts/quality/authenticated-candidate-session.js",
      "scripts/quality/authenticated-exposure-scan.js",
      "scripts/quality/prepare-qualification.js",
      "scripts/quality/qualification-profile.js",
    ]) {
      const source = fs.readFileSync(path.join(ROOT, relative), "utf8");
      assert.doesNotMatch(
        source,
        /\bfs\.rm(?:Sync)?\s*\([^;]*?\brecursive\s*:\s*true\b/gsu,
        `${relative} must use exact entry-bounded cleanup`,
      );
    }
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
          const artifactFingerprint = materializeStepArtifacts(step, temporaryRoot);
          const evidence = materializeStepTestEvidence(step, temporaryRoot);
          return {
            status: step.id === "repository-check" ? 7 : 0,
            signal: null,
            stdout: step.id === "repository-check" ? "1 failing\n" : "2 passing\n",
            stderr: "",
            testEvidence: evidence.value,
            testEvidenceFingerprint: evidence.fingerprint,
            artifactFingerprint,
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

  test("an empty execution Error cannot produce a passing gate", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-empty-error-gate-"));
    const step = {
      id: "fixture-empty-execution-error",
      category: "fixture",
      executable: "node",
      args: ["fixture"],
      command: "node fixture",
      blockedExitCodes: [],
      sequence: 1,
    };
    try {
      const summary = runGate({
        root: temporaryRoot,
        profile: "fast",
        plan: [step],
        source: SOURCE_IDENTITY,
        execute: () => ({
          status: 0,
          signal: null,
          error: new Error(""),
          stdout: "",
          stderr: "",
        }),
      });
      const diskReceipt = JSON.parse(fs.readFileSync(
        path.join(temporaryRoot, receiptPath(summary.steps[0])),
        "utf8",
      ));
      assert.strictEqual(summary.status, "failed");
      assert.strictEqual(summary.steps[0].status, "failed");
      assert.strictEqual(summary.steps[0].reason, "execution-error");
      assert.strictEqual(diskReceipt.status, "failed");
      assert.strictEqual(diskReceipt.reason, "execution-error");
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("execution errors persist a fixed reason without inspecting hostile messages", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-hostile-error-gate-"));
    const step = {
      id: "fixture-hostile-execution-error",
      category: "fixture",
      executable: "node",
      args: ["fixture"],
      command: "node fixture",
      blockedExitCodes: [],
      sequence: 1,
    };
    let getterCalls = 0;
    let reflectionCalls = 0;
    const accessorError = Object.create(null);
    Object.defineProperty(accessorError, "message", {
      configurable: false,
      enumerable: true,
      get() {
        getterCalls += 1;
        throw new Error("execution error message getter must not run");
      },
    });
    const hostileError = new Proxy(Object.create(null), {
      get() {
        getterCalls += 1;
        throw new Error("execution error property trap must not run");
      },
      getOwnPropertyDescriptor() {
        reflectionCalls += 1;
        throw new Error("execution error descriptor trap must not run");
      },
      getPrototypeOf() {
        reflectionCalls += 1;
        throw new Error("execution error prototype trap must not run");
      },
      ownKeys() {
        reflectionCalls += 1;
        throw new Error("execution error key trap must not run");
      },
    });
    const execution = error => ({
      status: 0,
      signal: null,
      error,
      stdout: "",
      stderr: "",
    });
    try {
      for (const error of [{ message: 17 }, accessorError, hostileError]) {
        const receipt = completedReceipt(
          "fast",
          step,
          SOURCE_IDENTITY,
          execution(error),
        );
        assert.strictEqual(receipt.status, "failed");
        assert.strictEqual(receipt.reason, "execution-error");
      }
      const summary = runGate({
        root: temporaryRoot,
        profile: "fast",
        plan: [step],
        source: SOURCE_IDENTITY,
        execute: () => execution(hostileError),
      });
      const diskReceipt = JSON.parse(fs.readFileSync(
        path.join(temporaryRoot, receiptPath(summary.steps[0])),
        "utf8",
      ));
      assert.strictEqual(summary.status, "failed");
      assert.strictEqual(summary.steps[0].reason, "execution-error");
      assert.strictEqual(diskReceipt.reason, "execution-error");
      assert.strictEqual(getterCalls, 0);
      assert.strictEqual(reflectionCalls, 0);
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("structured-evidence binding preserves an accessor execution error without invoking it", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-evidence-execution-error-",
    )));
    const step = {
      id: "fixture-evidence-execution-error",
      category: "tests",
      executable: "node",
      args: ["fixture"],
      command: "node fixture",
      evidencePath: ".quality/test-results/execution-error.json",
      blockedExitCodes: [],
      sequence: 1,
    };
    let getterCalls = 0;
    try {
      const summary = runGate({
        root: temporaryRoot,
        profile: "fast",
        plan: [step],
        source: SOURCE_IDENTITY,
        execute() {
          const evidence = testEvidence(step);
          writeJson(step.evidencePath, evidence, temporaryRoot, {
            subtree: ".quality/test-results",
          });
          const execution = {
            status: 0,
            signal: null,
            stdout: "",
            stderr: "",
            testEvidenceFingerprint: testEvidenceFileFingerprint(evidence),
          };
          Object.defineProperty(execution, "error", {
            configurable: false,
            enumerable: true,
            get() {
              getterCalls += 1;
              return undefined;
            },
          });
          return execution;
        },
      });
      const diskReceipt = JSON.parse(fs.readFileSync(
        path.join(temporaryRoot, receiptPath(summary.steps[0])),
        "utf8",
      ));
      assert.strictEqual(summary.status, "failed");
      assert.strictEqual(summary.steps[0].status, "failed");
      assert.strictEqual(summary.steps[0].reason, "execution-error");
      assert.strictEqual(diskReceipt.reason, "execution-error");
      assert.strictEqual(getterCalls, 0);
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("command execution preserves inherited and uninspectable error presence", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-command-execution-error-",
    )));
    const step = {
      id: "fixture-command-execution-error",
      category: "fixture",
      executable: "node",
      args: ["fixture"],
      command: "node fixture",
      blockedExitCodes: [],
      sequence: 1,
    };
    let reflectionCalls = 0;
    const inheritedError = { error: new Error("") };
    const uninspectableError = new Proxy(Object.create(null), {
      getOwnPropertyDescriptor(_target, propertyName) {
        if (propertyName === "error") {
          reflectionCalls += 1;
          throw new Error("execution error descriptor is uninspectable");
        }
        return undefined;
      },
      getPrototypeOf() {
        return null;
      },
    });
    try {
      for (const prototype of [inheritedError, uninspectableError]) {
        const rawResult = Object.assign(Object.create(prototype), {
          status: 0,
          signal: null,
          stdout: "",
          stderr: "",
        });
        const execution = executeCommand(step, {
          root: temporaryRoot,
          temporaryParent: temporaryRoot,
          spawnSync: () => rawResult,
        });
        const receipt = completedReceipt(
          "fast",
          step,
          SOURCE_IDENTITY,
          execution,
        );
        assert.strictEqual(receipt.status, "failed");
        assert.strictEqual(receipt.reason, "execution-error");
      }
      assert.strictEqual(reflectionCalls, 0);
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("command execution rejects hostile expected fields and invalid signals", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-command-field-shape-",
    )));
    const step = {
      id: "fixture-command-field-shape",
      category: "fixture",
      executable: "node",
      args: ["fixture"],
      command: "node fixture",
      blockedExitCodes: [],
      sequence: 1,
    };
    const validFields = {
      artifactFingerprint: null,
      error: null,
      signal: null,
      status: 0,
      stderr: "",
      stdout: "",
      testEvidence: null,
      testEvidenceFingerprint: null,
    };
    let getterCalls = 0;
    let reflectionCalls = 0;
    const accessorResult = propertyName => {
      const result = { ...validFields };
      delete result[propertyName];
      Object.defineProperty(result, propertyName, {
        configurable: false,
        enumerable: true,
        get() {
          getterCalls += 1;
          throw new Error(`${propertyName} getter must not run`);
        },
      });
      return result;
    };
    const throwingSignalPrototype = new Proxy(Object.create(null), {
      getOwnPropertyDescriptor(_target, propertyName) {
        if (propertyName === "signal") {
          reflectionCalls += 1;
          throw new Error("signal descriptor trap must not run");
        }
        return undefined;
      },
      getPrototypeOf() {
        reflectionCalls += 1;
        throw new Error("signal prototype trap must not run");
      },
    });
    const proxySignalResult = Object.assign(
      Object.create(throwingSignalPrototype),
      validFields,
    );
    delete proxySignalResult.signal;
    const emptySignalResult = { ...validFields, signal: "" };
    try {
      for (const rawResult of [
        accessorResult("signal"),
        proxySignalResult,
        emptySignalResult,
        accessorResult("status"),
        accessorResult("stdout"),
        accessorResult("stderr"),
      ]) {
        const execution = executeCommand(step, {
          root: temporaryRoot,
          temporaryParent: temporaryRoot,
          spawnSync: () => rawResult,
        });
        const receipt = completedReceipt(
          "fast",
          step,
          SOURCE_IDENTITY,
          execution,
        );
        assert.strictEqual(receipt.status, "failed");
        assert.strictEqual(receipt.reason, "execution-error");
      }
      assert.strictEqual(getterCalls, 0);
      assert.strictEqual(reflectionCalls, 0);

      const inheritedExecution = executeCommand(step, {
        root: temporaryRoot,
        temporaryParent: temporaryRoot,
        spawnSync: () => Object.create(validFields),
      });
      assert.strictEqual(
        completedReceipt("fast", step, SOURCE_IDENTITY, inheritedExecution).status,
        "passed",
      );
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("injected gate execution rejects hostile status, output, signal, and evidence fields", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-injected-field-shape-",
    )));
    const step = {
      id: "fixture-injected-field-shape",
      category: "tests",
      executable: "node",
      args: ["fixture"],
      command: "node fixture",
      evidencePath: ".quality/test-results/injected-field-shape.json",
      blockedExitCodes: [],
      sequence: 1,
    };
    let getterCalls = 0;
    let reflectionCalls = 0;
    const cases = [
      { kind: "accessor", propertyName: "signal" },
      { kind: "proxy-signal" },
      { kind: "empty-signal" },
      { kind: "accessor", propertyName: "status" },
      { kind: "accessor", propertyName: "stdout" },
      { kind: "accessor", propertyName: "stderr" },
      { kind: "accessor", propertyName: "testEvidence" },
      { kind: "accessor", propertyName: "testEvidenceFingerprint" },
    ];
    try {
      for (const testCase of cases) {
        const summary = runGate({
          root: temporaryRoot,
          profile: "fast",
          plan: [step],
          source: SOURCE_IDENTITY,
          execute() {
            const evidence = testEvidence(step);
            const evidenceFingerprint = testEvidenceFileFingerprint(evidence);
            writeJson(step.evidencePath, evidence, temporaryRoot, {
              subtree: ".quality/test-results",
            });
            const fields = {
              artifactFingerprint: null,
              error: null,
              signal: null,
              status: 0,
              stderr: "",
              stdout: "",
              testEvidence: evidence,
              testEvidenceFingerprint: evidenceFingerprint,
            };
            if (testCase.kind === "empty-signal") return { ...fields, signal: "" };
            if (testCase.kind === "proxy-signal") {
              delete fields.signal;
              const prototype = new Proxy(Object.create(null), {
                getOwnPropertyDescriptor(_target, propertyName) {
                  if (propertyName === "signal") {
                    reflectionCalls += 1;
                    throw new Error("signal descriptor trap must not run");
                  }
                  return undefined;
                },
                getPrototypeOf() {
                  reflectionCalls += 1;
                  throw new Error("signal prototype trap must not run");
                },
              });
              return Object.assign(Object.create(prototype), fields);
            }
            const propertyName = testCase.propertyName;
            delete fields[propertyName];
            Object.defineProperty(fields, propertyName, {
              configurable: false,
              enumerable: true,
              get() {
                getterCalls += 1;
                throw new Error(`${propertyName} getter must not run`);
              },
            });
            return fields;
          },
        });
        assert.strictEqual(summary.status, "failed");
        assert.strictEqual(summary.steps[0].status, "failed");
        assert.strictEqual(summary.steps[0].reason, "execution-error");
      }
      assert.strictEqual(getterCalls, 0);
      assert.strictEqual(reflectionCalls, 0);
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

  test("rejects hard-linked gate artifacts before fingerprint acceptance", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-artifact-link-"));
    const step = fixtureArtifactStep();
    const target = path.join(temporaryRoot, step.artifactPath);
    const outside = path.join(temporaryRoot, "outside-artifact.json");
    try {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(outside, "synthetic shared artifact bytes\n");
      fs.linkSync(outside, target);
      assert.throws(
        () => artifactFingerprintForStep(step, temporaryRoot),
        /unsafe or changed/u,
      );
      assert.strictEqual(fs.readFileSync(outside, "utf8"), "synthetic shared artifact bytes\n");
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("fails a gate artifact changed after its command fingerprint", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-artifact-drift-"));
    const step = fixtureArtifactStep();
    const target = path.join(temporaryRoot, step.artifactPath);
    let sourceReads = 0;
    try {
      const summary = runGate({
        root: temporaryRoot,
        profile: "fast",
        plan: [step],
        source: SOURCE_IDENTITY,
        readSource() {
          sourceReads += 1;
          if (sourceReads === 2) fs.appendFileSync(target, "synthetic post-fingerprint drift\n");
          return SOURCE_IDENTITY;
        },
        execute(currentStep) {
          return {
            status: 0,
            signal: null,
            stdout: "",
            stderr: "",
            artifactFingerprint: materializeStepArtifacts(currentStep, temporaryRoot),
          };
        },
      });
      assert.strictEqual(summary.status, "failed");
      assert.strictEqual(summary.steps[0].status, "failed");
      assert.strictEqual(summary.steps[0].reason, "artifact-changed-before-receipt");
      assert.strictEqual(
        JSON.parse(fs.readFileSync(
          path.join(temporaryRoot, receiptPath(summary.steps[0])),
          "utf8",
        )).status,
        "failed",
      );
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("downgrades an artifact changed during receipt persistence", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-artifact-receipt-drift-",
    )));
    const step = fixtureArtifactStep();
    const target = path.join(temporaryRoot, step.artifactPath);
    const receiptTarget = path.join(temporaryRoot, `.quality/gates/fast/01-${step.id}.json`);
    const originalRename = fs.renameSync;
    let armed = false;
    let drifted = false;
    try {
      fs.renameSync = function interceptReceiptPersistence(source, destination) {
        const result = originalRename.call(fs, source, destination);
        if (armed && destination === receiptTarget) {
          fs.appendFileSync(target, "synthetic receipt-persistence drift\n");
          armed = false;
          drifted = true;
        }
        return result;
      };
      const summary = runGate({
        root: temporaryRoot,
        profile: "fast",
        plan: [step],
        source: SOURCE_IDENTITY,
        execute(currentStep) {
          const artifactFingerprint = materializeStepArtifacts(currentStep, temporaryRoot);
          armed = true;
          return { status: 0, signal: null, stdout: "", stderr: "", artifactFingerprint };
        },
      });
      assert.strictEqual(drifted, true);
      assert.strictEqual(summary.status, "failed");
      assert.strictEqual(
        summary.steps[0].reason,
        "artifact-changed-during-receipt-persistence",
      );
    } finally {
      fs.renameSync = originalRename;
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("invalidates a passed receipt before a failing downgrade write", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-artifact-receipt-write-failure-",
    )));
    const step = fixtureArtifactStep();
    const target = path.join(temporaryRoot, step.artifactPath);
    const receiptTarget = path.join(temporaryRoot, `.quality/gates/fast/01-${step.id}.json`);
    const originalRename = fs.renameSync;
    let armed = false;
    let receiptWrites = 0;
    try {
      fs.renameSync = function interceptReceiptDowngrade(source, destination) {
        if (armed && destination === receiptTarget) {
          receiptWrites += 1;
          if (receiptWrites === 2) {
            const error = new Error("synthetic receipt downgrade write failure");
            error.code = "EIO";
            throw error;
          }
          const result = originalRename.call(fs, source, destination);
          fs.appendFileSync(target, "synthetic receipt drift before failed downgrade\n");
          return result;
        }
        return originalRename.call(fs, source, destination);
      };
      assert.throws(() => runGate({
        root: temporaryRoot,
        profile: "fast",
        plan: [step],
        source: SOURCE_IDENTITY,
        execute(currentStep) {
          const artifactFingerprint = materializeStepArtifacts(currentStep, temporaryRoot);
          armed = true;
          return { status: 0, signal: null, stdout: "", stderr: "", artifactFingerprint };
        },
      }), /synthetic receipt downgrade write failure/u);
      assert.strictEqual(receiptWrites, 2);
      assert.strictEqual(fs.existsSync(receiptTarget), false);
    } finally {
      fs.renameSync = originalRename;
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("downgrades an artifact changed during summary persistence", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-artifact-summary-drift-",
    )));
    const step = fixtureArtifactStep();
    const target = path.join(temporaryRoot, step.artifactPath);
    const summaryTarget = path.join(temporaryRoot, ".quality/gates/fast.json");
    const originalRename = fs.renameSync;
    let armed = false;
    let drifted = false;
    try {
      fs.renameSync = function interceptSummaryPersistence(source, destination) {
        const result = originalRename.call(fs, source, destination);
        if (armed && destination === summaryTarget) {
          fs.appendFileSync(target, "synthetic summary-persistence drift\n");
          armed = false;
          drifted = true;
        }
        return result;
      };
      const summary = runGate({
        root: temporaryRoot,
        profile: "fast",
        plan: [step],
        source: SOURCE_IDENTITY,
        execute(currentStep) {
          const artifactFingerprint = materializeStepArtifacts(currentStep, temporaryRoot);
          armed = true;
          return { status: 0, signal: null, stdout: "", stderr: "", artifactFingerprint };
        },
      });
      assert.strictEqual(drifted, true);
      assert.strictEqual(summary.status, "failed");
      assert.strictEqual(
        summary.steps[0].reason,
        "artifact-changed-during-summary-persistence",
      );
      assert.strictEqual(
        JSON.parse(fs.readFileSync(summaryTarget, "utf8")).status,
        "failed",
      );
    } finally {
      fs.renameSync = originalRename;
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("invalidates a passed summary before a failing downgrade write", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-artifact-summary-write-failure-",
    )));
    const step = fixtureArtifactStep();
    const target = path.join(temporaryRoot, step.artifactPath);
    const summaryTarget = path.join(temporaryRoot, ".quality/gates/fast.json");
    const originalRename = fs.renameSync;
    let armed = false;
    let summaryWrites = 0;
    try {
      fs.renameSync = function interceptSummaryDowngrade(source, destination) {
        if (armed && destination === summaryTarget) {
          summaryWrites += 1;
          if (summaryWrites === 2) {
            const error = new Error("synthetic summary downgrade write failure");
            error.code = "EIO";
            throw error;
          }
          const result = originalRename.call(fs, source, destination);
          fs.appendFileSync(target, "synthetic summary drift before failed downgrade\n");
          return result;
        }
        return originalRename.call(fs, source, destination);
      };
      assert.throws(() => runGate({
        root: temporaryRoot,
        profile: "fast",
        plan: [step],
        source: SOURCE_IDENTITY,
        execute(currentStep) {
          const artifactFingerprint = materializeStepArtifacts(currentStep, temporaryRoot);
          armed = true;
          return { status: 0, signal: null, stdout: "", stderr: "", artifactFingerprint };
        },
      }), /synthetic summary downgrade write failure/u);
      assert.strictEqual(summaryWrites, 2);
      assert.strictEqual(fs.existsSync(summaryTarget), false);
    } finally {
      fs.renameSync = originalRename;
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("rejects hard-linked and oversized structured test evidence", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-evidence-bound-"));
    const evidencePath = ".quality/test-results/fixture-evidence.json";
    const evidenceTarget = path.join(temporaryRoot, evidencePath);
    const outside = path.join(temporaryRoot, "outside-evidence.json");
    const step = {
      id: "fixture-evidence",
      category: "tests",
      executable: "node",
      args: ["fixture"],
      command: "node fixture",
      evidencePath,
      blockedExitCodes: [],
      sequence: 1,
    };
    try {
      const linked = executeCommand(step, {
        root: temporaryRoot,
        source: SOURCE_IDENTITY,
        temporaryParent: temporaryRoot,
        spawnSync() {
          fs.mkdirSync(path.dirname(evidenceTarget), { recursive: true });
          fs.writeFileSync(outside, `${JSON.stringify(testEvidence(step))}\n`);
          fs.linkSync(outside, evidenceTarget);
          return { status: 0, signal: null, error: null, stdout: "", stderr: "" };
        },
      });
      assert.match(linked.error.message, /Structured test evidence is unsafe or changed/u);

      fs.unlinkSync(evidenceTarget);
      fs.unlinkSync(outside);
      const oversized = executeCommand(step, {
        root: temporaryRoot,
        source: SOURCE_IDENTITY,
        temporaryParent: temporaryRoot,
        spawnSync() {
          fs.mkdirSync(path.dirname(evidenceTarget), { recursive: true });
          const descriptor = fs.openSync(evidenceTarget, "w");
          try {
            fs.writeSync(descriptor, testEvidenceFileBytes(testEvidence(step)));
            const spaces = Buffer.alloc(64 * 1024, 0x20);
            for (let index = 0; index < 1024; index += 1) {
              fs.writeSync(descriptor, spaces);
            }
          } finally {
            fs.closeSync(descriptor);
          }
          return { status: 0, signal: null, error: null, stdout: "", stderr: "" };
        },
      });
      assert.match(oversized.error.message, /Structured test evidence is unsafe or changed/u);
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("caps structured-evidence reads at the opened size and rejects growth", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-evidence-growth-",
    )));
    const step = {
      id: "fixture-growth",
      evidencePath: ".quality/test-results/fixture-growth.json",
    };
    const target = path.join(temporaryRoot, step.evidencePath);
    const value = testEvidence(step);
    writeJson(step.evidencePath, value, temporaryRoot, {
      subtree: ".quality/test-results",
    });
    const openedBytes = fs.lstatSync(target).size;
    const fileSystem = Object.create(fs);
    const originalRead = fs.readSync;
    let grew = false;
    let requestedBytes = 0;
    fileSystem.readSync = function growDuringRead(descriptor, buffer, offset, length, position) {
      requestedBytes += length;
      if (!grew) {
        fs.appendFileSync(target, "synthetic post-open growth\n");
        grew = true;
      }
      return originalRead.call(fs, descriptor, buffer, offset, length, position);
    };
    try {
      assert.throws(
        () => testEvidenceProofForStep(step, temporaryRoot, { fileSystem }),
        /unsafe or changed/u,
      );
      assert.strictEqual(grew, true);
      assert.ok(requestedBytes <= openedBytes, `${requestedBytes} exceeded ${openedBytes}`);
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("binds structured evidence through receipt persistence", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-evidence-lifecycle-",
    )));
    const step = {
      id: "fixture-evidence-lifecycle",
      category: "tests",
      executable: "node",
      args: ["fixture"],
      command: "node fixture",
      evidencePath: ".quality/test-results/fixture-lifecycle.json",
      blockedExitCodes: [],
      sequence: 1,
    };
    const target = path.join(temporaryRoot, step.evidencePath);
    let sourceReads = 0;
    try {
      const summary = runGate({
        root: temporaryRoot,
        profile: "fast",
        plan: [step],
        source: SOURCE_IDENTITY,
        readSource() {
          sourceReads += 1;
          if (sourceReads === 2) {
            fs.writeFileSync(target, alternateTestEvidenceFileBytes(testEvidence(step)));
          }
          return SOURCE_IDENTITY;
        },
        execute(currentStep, context) {
          return executeCommand(currentStep, {
            ...context,
            temporaryParent: temporaryRoot,
            spawnSync() {
              writeJson(currentStep.evidencePath, testEvidence(currentStep), temporaryRoot, {
                subtree: ".quality/test-results",
              });
              return { status: 0, signal: null, error: null, stdout: "", stderr: "" };
            },
          });
        },
      });
      assert.strictEqual(summary.status, "failed");
      assert.strictEqual(summary.steps[0].reason, "test-evidence-changed-before-receipt");
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("downgrades structured evidence changed during receipt persistence", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-evidence-receipt-drift-",
    )));
    const step = {
      id: "fixture-evidence-receipt-drift",
      category: "tests",
      executable: "node",
      args: ["fixture"],
      command: "node fixture",
      evidencePath: ".quality/test-results/fixture-receipt-drift.json",
      blockedExitCodes: [],
      sequence: 1,
    };
    const evidenceTarget = path.join(temporaryRoot, step.evidencePath);
    const receiptTarget = path.join(temporaryRoot, `.quality/gates/fast/01-${step.id}.json`);
    const originalRename = fs.renameSync;
    let armed = false;
    try {
      fs.renameSync = function interceptEvidenceReceipt(source, destination) {
        const result = originalRename.call(fs, source, destination);
        if (armed && destination === receiptTarget) {
          fs.writeFileSync(
            evidenceTarget,
            alternateTestEvidenceFileBytes(testEvidence(step)),
          );
          armed = false;
        }
        return result;
      };
      const summary = runGate({
        root: temporaryRoot,
        profile: "fast",
        plan: [step],
        source: SOURCE_IDENTITY,
        execute(currentStep, context) {
          const execution = executeCommand(currentStep, {
            ...context,
            temporaryParent: temporaryRoot,
            spawnSync() {
              writeJson(currentStep.evidencePath, testEvidence(currentStep), temporaryRoot, {
                subtree: ".quality/test-results",
              });
              return { status: 0, signal: null, error: null, stdout: "", stderr: "" };
            },
          });
          armed = true;
          return execution;
        },
      });
      assert.strictEqual(summary.status, "failed");
      assert.strictEqual(
        summary.steps[0].reason,
        "test-evidence-changed-during-receipt-persistence",
      );
    } finally {
      fs.renameSync = originalRename;
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("downgrades structured evidence changed during summary persistence", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-evidence-summary-drift-",
    )));
    const step = {
      id: "fixture-evidence-summary-drift",
      category: "tests",
      executable: "node",
      args: ["fixture"],
      command: "node fixture",
      evidencePath: ".quality/test-results/fixture-summary-drift.json",
      blockedExitCodes: [],
      sequence: 1,
    };
    const evidenceTarget = path.join(temporaryRoot, step.evidencePath);
    const summaryTarget = path.join(temporaryRoot, ".quality/gates/fast.json");
    const originalRename = fs.renameSync;
    let armed = false;
    try {
      fs.renameSync = function interceptEvidenceSummary(source, destination) {
        const result = originalRename.call(fs, source, destination);
        if (armed && destination === summaryTarget) {
          fs.writeFileSync(
            evidenceTarget,
            alternateTestEvidenceFileBytes(testEvidence(step)),
          );
          armed = false;
        }
        return result;
      };
      const summary = runGate({
        root: temporaryRoot,
        profile: "fast",
        plan: [step],
        source: SOURCE_IDENTITY,
        execute(currentStep, context) {
          const execution = executeCommand(currentStep, {
            ...context,
            temporaryParent: temporaryRoot,
            spawnSync() {
              writeJson(currentStep.evidencePath, testEvidence(currentStep), temporaryRoot, {
                subtree: ".quality/test-results",
              });
              return { status: 0, signal: null, error: null, stdout: "", stderr: "" };
            },
          });
          armed = true;
          return execution;
        },
      });
      assert.strictEqual(summary.status, "failed");
      assert.strictEqual(
        summary.steps[0].reason,
        "test-evidence-changed-during-summary-persistence",
      );
      assert.strictEqual(JSON.parse(fs.readFileSync(summaryTarget, "utf8")).status, "failed");
    } finally {
      fs.renameSync = originalRename;
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("injected gate execution cannot bypass the structured-evidence proof", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-evidence-injected-",
    )));
    const step = {
      id: "fixture-injected-evidence",
      category: "tests",
      executable: "node",
      args: ["fixture"],
      command: "node fixture",
      evidencePath: ".quality/test-results/injected.json",
      blockedExitCodes: [],
      sequence: 1,
    };
    try {
      const missingProof = runGate({
        root: temporaryRoot,
        profile: "fast",
        plan: [step],
        source: SOURCE_IDENTITY,
        execute: () => ({
          status: 0,
          signal: null,
          stdout: "",
          stderr: "",
          testEvidence: testEvidence(step),
        }),
      });
      assert.strictEqual(missingProof.status, "failed");
      assert.strictEqual(
        missingProof.steps[0].reason,
        "missing-or-invalid-test-evidence-fingerprint",
      );

      const forgedProof = runGate({
        root: temporaryRoot,
        profile: "fast",
        plan: [step],
        source: SOURCE_IDENTITY,
        execute() {
          writeJson(step.evidencePath, testEvidence(step), temporaryRoot, {
            subtree: ".quality/test-results",
          });
          return {
            status: 0,
            signal: null,
            stdout: "",
            stderr: "",
            testEvidence: testEvidence(step),
            testEvidenceFingerprint: "b".repeat(64),
          };
        },
      });
      assert.strictEqual(forgedProof.status, "failed");
      assert.strictEqual(forgedProof.steps[0].reason, "test-evidence-changed-before-receipt");
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("normalizes structured evidence to its exact durable JSON value", () => {
    const negativeZeroRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-evidence-negative-zero-",
    )));
    const negativeZeroStep = {
      id: "fixture-negative-zero",
      category: "tests",
      executable: "node",
      args: ["fixture"],
      command: "node fixture",
      evidencePath: ".quality/test-results/negative-zero.json",
      blockedExitCodes: [],
      sequence: 1,
    };
    const negativeZeroValue = testEvidence(negativeZeroStep);
    const negativeZeroBytes = Buffer.from(`${JSON.stringify(negativeZeroValue)
      .replace("\"failed\":0", "\"failed\":-0")
      .replace("\"pending\":0", "\"pending\":-0")}\n`);
    const negativeZeroTarget = path.join(negativeZeroRoot, negativeZeroStep.evidencePath);
    try {
      assert.strictEqual(
        Object.is(JSON.parse(negativeZeroBytes.toString("utf8")).counts.failed, -0),
        true,
      );
      const summary = runGate({
        root: negativeZeroRoot,
        profile: "fast",
        plan: [negativeZeroStep],
        source: SOURCE_IDENTITY,
        execute(currentStep, context) {
          return executeCommand(currentStep, {
            ...context,
            temporaryParent: negativeZeroRoot,
            spawnSync() {
              fs.mkdirSync(path.dirname(negativeZeroTarget), { recursive: true });
              fs.writeFileSync(negativeZeroTarget, negativeZeroBytes);
              return { status: 0, signal: null, error: null, stdout: "", stderr: "" };
            },
          });
        },
      });
      const diskReceipt = JSON.parse(fs.readFileSync(
        path.join(negativeZeroRoot, receiptPath(summary.steps[0])),
        "utf8",
      ));
      assert.strictEqual(summary.status, "passed");
      assert.strictEqual(Object.is(summary.steps[0].testEvidence.counts.failed, -0), false);
      assert.strictEqual(Object.is(diskReceipt.testEvidence.counts.failed, -0), false);
      assert.strictEqual(
        summary.steps[0].testEvidenceFingerprint,
        crypto.createHash("sha256").update(negativeZeroBytes).digest("hex"),
      );
      assert.strictEqual(
        validateTestEvidenceBinding(diskReceipt, negativeZeroStep, negativeZeroRoot),
        null,
      );
    } finally {
      fs.rmSync(negativeZeroRoot, { recursive: true, force: true });
    }

    const hostileRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-evidence-hostile-json-",
    )));
    const hostileStep = {
      ...negativeZeroStep,
      id: "fixture-hostile-json",
      evidencePath: ".quality/test-results/hostile-json.json",
    };
    const durableEvidence = testEvidence(hostileStep);
    const durableBytes = testEvidenceFileBytes(durableEvidence);
    const hostileEvidence = JSON.parse(JSON.stringify(durableEvidence));
    let hostileSerializationCalls = 0;
    Object.defineProperty(hostileEvidence, "toJSON", {
      enumerable: false,
      value() {
        hostileSerializationCalls += 1;
        return { ...durableEvidence, suite: "forged-suite" };
      },
    });
    const hostileTarget = path.join(hostileRoot, hostileStep.evidencePath);
    try {
      const summary = runGate({
        root: hostileRoot,
        profile: "fast",
        plan: [hostileStep],
        source: SOURCE_IDENTITY,
        execute() {
          fs.mkdirSync(path.dirname(hostileTarget), { recursive: true });
          fs.writeFileSync(hostileTarget, durableBytes);
          return {
            status: 0,
            signal: null,
            stdout: "",
            stderr: "",
            testEvidence: hostileEvidence,
            testEvidenceFingerprint: crypto.createHash("sha256")
              .update(durableBytes)
              .digest("hex"),
          };
        },
      });
      const diskReceipt = JSON.parse(fs.readFileSync(
        path.join(hostileRoot, receiptPath(summary.steps[0])),
        "utf8",
      ));
      assert.strictEqual(summary.status, "passed");
      assert.strictEqual(hostileSerializationCalls, 0);
      assert.strictEqual(diskReceipt.testEvidence.suite, hostileStep.id);
      assert.strictEqual(
        validateTestEvidenceBinding(diskReceipt, hostileStep, hostileRoot),
        null,
      );
    } finally {
      fs.rmSync(hostileRoot, { recursive: true, force: true });
    }

    const inheritedRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-evidence-inherited-json-",
    )));
    const inheritedStep = {
      ...negativeZeroStep,
      id: "fixture-inherited-json",
      evidencePath: ".quality/test-results/inherited-json.json",
    };
    const inheritedEvidence = testEvidence(inheritedStep);
    const inheritedEvidenceBytes = testEvidenceFileBytes(inheritedEvidence);
    const inheritedTarget = path.join(inheritedRoot, inheritedStep.evidencePath);
    const previousToJson = Object.getOwnPropertyDescriptor(Object.prototype, "toJSON");
    let inheritedSerializationCalls = 0;
    let persistedSummary;
    let persistedReceipt;
    try {
      fs.mkdirSync(path.dirname(inheritedTarget), { recursive: true });
      fs.writeFileSync(inheritedTarget, inheritedEvidenceBytes);
      Object.defineProperty(Object.prototype, "toJSON", {
        configurable: true,
        enumerable: false,
        value() {
          inheritedSerializationCalls += 1;
          return { injected: true };
        },
      });
      const proof = testEvidenceProofForStep(inheritedStep, inheritedRoot);
      assert.strictEqual(inheritedSerializationCalls, 0);
      assert.deepStrictEqual(proof.value, inheritedEvidence);
      assert.strictEqual(Object.isFrozen(proof.value), true);
      assert.strictEqual(Object.isFrozen(proof.value.counts), true);
      assert.strictEqual(validateTestEvidenceBinding({
        testEvidence: proof.value,
        testEvidenceFingerprint: proof.sha256,
      }, inheritedStep, inheritedRoot), null);
      assert.strictEqual(inheritedSerializationCalls, 0);

      const summary = runGate({
        root: inheritedRoot,
        profile: "fast",
        plan: [inheritedStep],
        source: SOURCE_IDENTITY,
        execute() {
          fs.mkdirSync(path.dirname(inheritedTarget), { recursive: true });
          fs.writeFileSync(inheritedTarget, inheritedEvidenceBytes);
          return {
            status: 0,
            signal: null,
            stdout: "",
            stderr: "",
            testEvidence: inheritedEvidence,
            testEvidenceFingerprint: proof.sha256,
          };
        },
      });
      persistedReceipt = JSON.parse(fs.readFileSync(
        path.join(inheritedRoot, receiptPath(summary.steps[0])),
        "utf8",
      ));
      persistedSummary = JSON.parse(fs.readFileSync(
        path.join(inheritedRoot, ".quality/gates/fast.json"),
        "utf8",
      ));
      assert.strictEqual(summary.status, "passed");
      assert.strictEqual(persistedReceipt.status, "passed");
      assert.strictEqual(persistedSummary.status, "passed");
      assert.strictEqual(Object.hasOwn(persistedReceipt, "injected"), false);
      assert.strictEqual(Object.hasOwn(persistedSummary, "injected"), false);
      assert.strictEqual(inheritedSerializationCalls, 0);
    } finally {
      if (previousToJson) {
        Object.defineProperty(Object.prototype, "toJSON", previousToJson);
      } else {
        delete Object.prototype.toJSON;
      }
      fs.rmSync(inheritedRoot, { recursive: true, force: true });
    }
    const { key: persistedKey, ...persistedSummaryBase } = persistedSummary;
    assert.strictEqual(persistedKey.fingerprint, fingerprint(persistedSummaryBase));
    assert.strictEqual(
      validateTestEvidenceBinding(persistedReceipt, inheritedStep, inheritedRoot),
      "missing-or-invalid-test-evidence",
    );
  });

  test("rejects a FIFO substituted at the structured-evidence open boundary", function () {
    if (process.platform === "win32") this.skip();
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-evidence-fifo-",
    )));
    const gatePath = path.join(root, "scripts/quality/gate.js");
    const fifoEvidence = `${JSON.stringify(testEvidence({ id: "fifo" }))}\n`;
    const script = `
      const fs = require("fs");
      const path = require("path");
      const { spawnSync: systemSpawn } = require("child_process");
      const { executeCommand } = require(${JSON.stringify(gatePath)});
      const fixtureRoot = ${JSON.stringify(temporaryRoot)};
      const relative = ".quality/test-results/fifo.json";
      const target = path.join(fixtureRoot, relative);
      const step = { id: "fifo", category: "tests", executable: "node", args: ["fixture"], command: "node fixture", evidencePath: relative, blockedExitCodes: [], sequence: 1 };
      const source = { sha: ${JSON.stringify(SOURCE_SHA)}, fingerprint: ${JSON.stringify("a".repeat(64))} };
      const originalOpen = fs.openSync;
      let swapped = false;
      try {
        fs.openSync = function swapAtOpen(file, flags, ...rest) {
          if (!swapped && file === target) {
            fs.unlinkSync(target);
            const made = systemSpawn("mkfifo", [target], { encoding: "utf8" });
            if (made.status !== 0) throw new Error("synthetic FIFO creation failed");
            swapped = true;
          }
          return originalOpen.call(fs, file, flags, ...rest);
        };
        const result = executeCommand(step, {
          root: fixtureRoot,
          source,
          temporaryParent: fixtureRoot,
          spawnSync() {
            fs.mkdirSync(path.dirname(target), { recursive: true });
            const descriptor = originalOpen.call(
              fs,
              target,
              fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
              0o600,
            );
            try {
              fs.writeSync(descriptor, ${JSON.stringify(fifoEvidence)});
            } finally {
              fs.closeSync(descriptor);
            }
            return { status: 0, signal: null, error: null, stdout: "", stderr: "" };
          },
        });
        process.exitCode = swapped
          && result.error
          && result.error.message.includes("Structured test evidence is unsafe or changed.")
          ? 0 : 1;
      } finally {
        fs.openSync = originalOpen;
      }
    `;
    try {
      const result = spawnSync(process.execPath, ["-e", script], {
        encoding: "utf8",
        timeout: 5000,
      });
      assert.ifError(result.error);
      assert.strictEqual(result.signal, null, result.stderr);
      assert.strictEqual(result.status, 0, result.stderr);
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("rejects a live FIFO independently of EOF and minimum-size checks", function () {
    if (process.platform === "win32") this.skip();
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-evidence-live-fifo-",
    )));
    const target = path.join(temporaryRoot, "evidence.fifo");
    let writer;
    try {
      const made = spawnSync("mkfifo", [target], { encoding: "utf8" });
      assert.strictEqual(made.status, 0, made.stderr);
      writer = fs.openSync(
        target,
        fs.constants.O_RDWR | (fs.constants.O_NONBLOCK || 0),
      );
      fs.writeSync(writer, testEvidenceFileBytes(testEvidence({ id: "live-fifo" })));
      let consumed = false;
      assert.throws(() => withStableSingleLinkFile(target, {
        errorMessage: "Synthetic FIFO must not be accepted as structured evidence.",
        maximumBytes: 1024 * 1024,
        minimumBytes: 0,
      }, () => {
        consumed = true;
        return "accepted";
      }), /must not be accepted/u);
      assert.strictEqual(consumed, false);
    } finally {
      if (writer !== undefined) fs.closeSync(writer);
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("non-auth gate children cannot inherit credential-shaped ambient values", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-gate-env-"));
    const ambientHome = path.join(temporaryRoot, "ambient-home");
    fs.mkdirSync(ambientHome, { mode: 0o700 });
    const ambientNpmConfig = path.join(ambientHome, ".npmrc");
    const ambientGitConfig = path.join(ambientHome, ".gitconfig");
    fs.writeFileSync(ambientNpmConfig, "qh146_marker=ambient\n", { mode: 0o600 });
    fs.writeFileSync(
      ambientGitConfig,
      "[qh146]\n\tmarker = ambient\n",
      { mode: 0o600 }
    );
    const syntheticNames = [
      "CLOUDSMITH_API_KEY",
      "ARBITRARY_ACCESS_TOKEN",
      "FIXTURE_PASSWORD",
      ...NON_AUTH_AMBIENT_CAPABILITY_NAMES,
    ];
    const syntheticEnvironment = {
      PATH: process.env.PATH || "/usr/bin:/bin",
      HOME: ambientHome,
      USERPROFILE: ambientHome,
      NPM_CONFIG_USERCONFIG: ambientNpmConfig,
      GIT_CONFIG_GLOBAL: ambientGitConfig,
      CLOUDSMITH_API_KEY: "synthetic-qh146-gate-api-sentinel",
      ARBITRARY_ACCESS_TOKEN: "synthetic-qh146-gate-token-sentinel",
      FIXTURE_PASSWORD: "synthetic-qh146-gate-password-sentinel",
      DISPLAY: ":synthetic-host-display",
      WAYLAND_DISPLAY: "synthetic-host-wayland",
      XAUTHORITY: "/synthetic/host-xauthority",
      XDG_RUNTIME_DIR: "/synthetic/host-runtime",
      DBUS_SESSION_BUS_ADDRESS: "unix:path=/synthetic/host-session-bus",
      SSH_AUTH_SOCK: "/synthetic/host-agent.sock",
      SSH_AGENT_PID: "12345",
      GPG_AGENT_INFO: "/synthetic/host-gpg-agent",
      KRB5CCNAME: "/synthetic/host-credential-cache",
      SECURITYSESSIONID: "synthetic-host-security-session",
    };
    const step = {
      id: "fixture-environment-boundary",
      category: "security",
      executable: "node",
      args: [
        "-e",
        `const fs=require("fs"); const os=require("os"); const {spawnSync}=require("child_process"); const forbidden=${JSON.stringify(syntheticNames)}; const directories=["HOME","USERPROFILE","XDG_CONFIG_HOME","XDG_CACHE_HOME","XDG_DATA_HOME","XDG_STATE_HOME","APPDATA","LOCALAPPDATA","TMPDIR","TMP","TEMP","NPM_CONFIG_CACHE"]; const configs=["NPM_CONFIG_USERCONFIG","NPM_CONFIG_GLOBALCONFIG","GIT_CONFIG_GLOBAL"]; const git=spawnSync("git",["config","--global","--get","qh146.marker"],{encoding:"utf8"}); const npm=spawnSync(process.platform==="win32"?"npm.cmd":"npm",["config","get","userconfig"],{encoding:"utf8"}); const unsafe=forbidden.some(name=>Object.prototype.hasOwnProperty.call(process.env,name))||os.homedir()!==process.env.HOME||os.homedir()===${JSON.stringify(ambientHome)}||directories.some(name=>!process.env[name]||!fs.lstatSync(process.env[name]).isDirectory())||configs.some(name=>!process.env[name]||fs.readFileSync(process.env[name],"utf8")!=="")||process.env.GIT_CONFIG_NOSYSTEM!=="1"||process.env.GIT_CONFIG_COUNT!=="0"||git.status!==1||git.stdout.trim()!==""||npm.status!==0||npm.stdout.trim()!==process.env.NPM_CONFIG_USERCONFIG; process.stdout.write(unsafe?"unsafe-child-environment":"safe-child-environment");`,
      ],
      command: "node credential-boundary-probe",
      blockedExitCodes: [],
      sequence: 1,
    };
    try {
      const execution = executeCommand(step, {
        root: temporaryRoot,
        source: SOURCE_IDENTITY,
        environment: syntheticEnvironment,
        temporaryParent: temporaryRoot,
      });
      const receipt = completedReceipt("fast", step, SOURCE_IDENTITY, execution);
      assert.strictEqual(execution.stdout, "safe-child-environment");
      assert.strictEqual(receipt.status, "passed");
      assert.strictEqual(
        receipt.outputFingerprint,
        crypto.createHash("sha256").update("safe-child-environment").digest("hex")
      );
      for (const name of syntheticNames) {
        assert.strictEqual(JSON.stringify(execution).includes(syntheticEnvironment[name]), false);
        assert.strictEqual(JSON.stringify(receipt).includes(syntheticEnvironment[name]), false);
      }
      assert.strictEqual(
        fs.readdirSync(temporaryRoot).some(name => name.startsWith("cloudsmith-non-auth-")),
        false
      );
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("default non-auth temp boundaries preserve the macOS IPC socket budget", () => {
    const boundary = createNonAuthQualityEnvironment({
      environment: { PATH: process.env.PATH || "/usr/bin:/bin" },
    });
    try {
      const expectedParent = fs.realpathSync(
        process.platform === "darwin" ? "/tmp" : os.tmpdir()
      );
      assert.strictEqual(path.dirname(boundary.root), expectedParent);
      assert.strictEqual(
        boundary.paths.temporary.startsWith(`${boundary.root}${path.sep}`),
        true
      );
      if (process.platform === "darwin") {
        const socketPath = path.join(
          boundary.paths.temporary,
          "csv-s-xxxxxx",
          "user-data",
          "1.13-main.sock",
        );
        assert.ok(Buffer.byteLength(socketPath, "utf8") <= 103);
      }
    } finally {
      cleanupNonAuthQualityEnvironment(boundary);
    }
  });

  test("non-auth cleanup narrowly admits single-link Unix sockets and still rejects FIFOs", function () {
    if (process.platform === "win32") this.skip();
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      process.platform === "darwin" ? fs.realpathSync("/tmp") : os.tmpdir(),
      "qh199-a-",
    )));
    if (process.platform !== "win32") fs.chmodSync(scratch, 0o700);
    try {
    const boundary = createNonAuthQualityEnvironment({
      environment: { PATH: "/fixture/bin" },
      temporaryParent: scratch,
    });
    const socketRoot = path.join(boundary.paths.temporary, "s");
    const socket = path.join(socketRoot, "g.sock");
    fs.mkdirSync(socketRoot, { mode: 0o700 });
    if (process.platform === "darwin") {
      assert.ok(Buffer.byteLength(socket, "utf8") <= 103);
    }
    const socketProcess = spawnSync(process.execPath, [
      "-e",
      "const net=require('net');const server=net.createServer();"
        + "server.listen(process.argv[1],()=>process.kill(process.pid,'SIGKILL'));",
      socket,
    ], { encoding: "utf8", env: {}, timeout: 5_000 });
    assert.strictEqual(socketProcess.status, null, socketProcess.stderr);
    assert.strictEqual(socketProcess.signal, "SIGKILL", socketProcess.stderr);
    const socketStat = fs.lstatSync(socket);
    assert.strictEqual(socketStat.isSocket(), true);
    assert.strictEqual(socketStat.nlink, 1);
      withExpectedCleanupTaint(() => {
        assert.throws(
          () => removeExactOwnedDirectoryTree(socketRoot, {
            allowAdditionalRootEntries: true,
            errorMessage: "Synthetic generic cleanup rejected an unscoped Unix socket.",
            expectedRootEntries: [],
            expectedRootIdentity: fs.lstatSync(socketRoot),
          }),
          /rejected an unscoped Unix socket/u,
        );
      });
      withExpectedCleanupTaint(() => {
        assert.throws(
          () => cleanupNonAuthQualityEnvironment(boundary),
          /preserved an unsafe or changed tree/u,
        );
      });
      assert.strictEqual(fs.existsSync(boundary.root), false);

      const allowedBoundary = createNonAuthQualityEnvironment({
        environment: { PATH: "/fixture/bin" },
        temporaryParent: scratch,
      });
      const allowedSocketRoot = path.join(allowedBoundary.paths.temporary, "s");
      const allowedSocket = path.join(allowedSocketRoot, "g.sock");
      fs.mkdirSync(allowedSocketRoot, { mode: 0o700 });
      const allowedSocketProcess = spawnSync(process.execPath, [
        "-e",
        "const net=require('net');const server=net.createServer();"
          + "server.listen(process.argv[1],()=>process.kill(process.pid,'SIGKILL'));",
        allowedSocket,
      ], { encoding: "utf8", env: {}, timeout: 5_000 });
      assert.strictEqual(allowedSocketProcess.status, null, allowedSocketProcess.stderr);
      assert.strictEqual(allowedSocketProcess.signal, "SIGKILL", allowedSocketProcess.stderr);
      assert.strictEqual(fs.lstatSync(allowedSocket).isSocket(), true);
      assert.strictEqual(cleanupNonAuthQualityEnvironment(allowedBoundary), true);
      assert.strictEqual(fs.existsSync(allowedBoundary.root), false);

      const fifoRoot = path.join(scratch, "f");
      const fifo = path.join(fifoRoot, "x.fifo");
      fs.mkdirSync(fifoRoot, { mode: 0o700 });
      assert.strictEqual(spawnSync("mkfifo", [fifo], { encoding: "utf8" }).status, 0);
      withExpectedCleanupTaint(() => {
        assert.throws(
          () => removeExactOwnedDirectoryTree(fifoRoot, {
            allowAdditionalRootEntries: true,
            allowSingleLinkUnixSockets: true,
            errorMessage: "Synthetic socket-enabled cleanup rejected an unsafe entry type.",
            expectedRootEntries: [],
            expectedRootIdentity: fs.lstatSync(fifoRoot),
          }),
          /rejected an unsafe entry type/u,
        );
      });
      assert.strictEqual(fs.lstatSync(fifo).isFIFO(), true);
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });

  test("socket-enabled cleanup rejects an identity replacement before unlink", function () {
    if (process.platform === "win32") this.skip();
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      process.platform === "darwin" ? fs.realpathSync("/tmp") : os.tmpdir(),
      "qh199-b-",
    )));
    if (process.platform !== "win32") fs.chmodSync(scratch, 0o700);
    try {
    const root = path.join(scratch, "r");
    const socket = path.join(root, "a.sock");
    const replacement = path.join(scratch, "b.sock");
    const displaced = path.join(scratch, "c.sock");
    fs.mkdirSync(root, { mode: 0o700 });
    for (const target of [socket, replacement]) {
      if (process.platform === "darwin") {
        assert.ok(Buffer.byteLength(target, "utf8") <= 103);
      }
      const socketProcess = spawnSync(process.execPath, [
        "-e",
        "const net=require('net');const server=net.createServer();"
          + "server.listen(process.argv[1],()=>process.kill(process.pid,'SIGKILL'));",
        target,
      ], { encoding: "utf8", env: {}, timeout: 5_000 });
      assert.strictEqual(socketProcess.status, null, socketProcess.stderr);
      assert.strictEqual(socketProcess.signal, "SIGKILL", socketProcess.stderr);
    }
    const originalLstat = fs.lstatSync;
    let socketObservations = 0;
    let substituted = false;
    try {
      fs.lstatSync = function replaceSocketBeforeFinalIdentityCheck(target, options) {
        if (target === socket && ++socketObservations === 2) {
          fs.renameSync(socket, displaced);
          fs.renameSync(replacement, socket);
          substituted = true;
        }
        return originalLstat.call(fs, target, options);
      };
      withExpectedCleanupTaint(() => {
        assert.throws(
          () => removeExactOwnedDirectoryTree(root, {
            allowAdditionalRootEntries: true,
            allowSingleLinkUnixSockets: true,
            errorMessage: "Synthetic exact cleanup rejected socket identity drift.",
            expectedRootEntries: [],
            expectedRootIdentity: originalLstat.call(fs, root),
          }),
          /rejected socket identity drift/u,
        );
      });
    } finally {
      fs.lstatSync = originalLstat;
    }
      assert.strictEqual(substituted, true);
      assert.strictEqual(fs.lstatSync(socket).isSocket(), true);
      assert.strictEqual(fs.lstatSync(displaced).isSocket(), true);
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });

  test("socket unlink substitution cannot follow a link outside the owned tree", function () {
    if (process.platform === "win32") this.skip();
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      process.platform === "darwin" ? fs.realpathSync("/tmp") : os.tmpdir(),
      "qh199-c-",
    )));
    if (process.platform !== "win32") fs.chmodSync(scratch, 0o700);
    try {
    const root = path.join(scratch, "r");
    const socket = path.join(root, "a.sock");
    const displaced = path.join(scratch, "b.sock");
    const outside = path.join(scratch, "o.txt");
    fs.mkdirSync(root, { mode: 0o700 });
    fs.writeFileSync(outside, "synthetic outside bytes survive\n");
    if (process.platform === "darwin") {
      assert.ok(Buffer.byteLength(socket, "utf8") <= 103);
    }
    const socketProcess = spawnSync(process.execPath, [
      "-e",
      "const net=require('net');const server=net.createServer();"
        + "server.listen(process.argv[1],()=>process.kill(process.pid,'SIGKILL'));",
      socket,
    ], { encoding: "utf8", env: {}, timeout: 5_000 });
    assert.strictEqual(socketProcess.status, null, socketProcess.stderr);
    assert.strictEqual(socketProcess.signal, "SIGKILL", socketProcess.stderr);
    const originalUnlink = fs.unlinkSync;
    let substituted = false;
    try {
      fs.unlinkSync = function replaceSocketAtUnlink(target) {
        if (!substituted && target === socket) {
          fs.renameSync(socket, displaced);
          fs.symlinkSync(outside, socket);
          substituted = true;
        }
        return originalUnlink.call(fs, target);
      };
      assert.strictEqual(removeExactOwnedDirectoryTree(root, {
        allowAdditionalRootEntries: true,
        allowSingleLinkUnixSockets: true,
        errorMessage: "Synthetic socket cleanup refused its exact tree.",
        expectedRootEntries: [],
        expectedRootIdentity: fs.lstatSync(root),
      }), true);
    } finally {
      fs.unlinkSync = originalUnlink;
    }
      assert.strictEqual(substituted, true);
      assert.strictEqual(fs.existsSync(root), false);
      assert.strictEqual(
        fs.readFileSync(outside, "utf8"),
        "synthetic outside bytes survive\n",
      );
      assert.strictEqual(fs.lstatSync(displaced).isSocket(), true);
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
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

  test("report receipt loading rejects symlink and FIFO substitutions at open", function () {
    const substitutions = process.platform === "win32"
      ? ["symlink"]
      : ["symlink", "fifo"];
    for (const kind of substitutions) {
      const fixture = createEvidenceHandoffFixture();
      const relative = receiptPath(fixture.summary.steps[0]);
      const fixtureRoot = fs.realpathSync(fixture.root);
      const target = path.join(fixtureRoot, relative);
      const displaced = `${target}.original`;
      const replacement = `${target}.${kind}`;
      const outside = path.join(fixtureRoot, `outside-${kind}.json`);
      const fileSystem = Object.create(fs);
      const originalOpen = fs.openSync;
      const originalRead = fs.readSync;
      let swapped = false;
      let readCalls = 0;
      try {
        if (kind === "symlink") {
          fs.writeFileSync(outside, fs.readFileSync(target));
          fs.symlinkSync(outside, replacement);
        } else {
          const made = spawnSync("mkfifo", [replacement], { encoding: "utf8" });
          assert.strictEqual(made.status, 0, made.stderr);
        }
        fileSystem.openSync = function substituteReceiptAtOpen(file, flags, ...rest) {
          if (!swapped && file === target) {
            fs.renameSync(target, displaced);
            fs.renameSync(replacement, target);
            swapped = true;
          }
          return originalOpen.call(fs, file, flags, ...rest);
        };
        fileSystem.readSync = function countReceiptReads(...arguments_) {
          readCalls += 1;
          return originalRead.call(fs, ...arguments_);
        };
        assert.throws(
          () => loadReportInputs({
            fileSystem,
            profile: fixture.profile,
            root: fixture.root,
            source: fixture.source,
          }),
          /Quality report input is unsafe or changed/u,
        );
        assert.strictEqual(swapped, true, `${kind} substitution did not run`);
        assert.strictEqual(readCalls, 0, `${kind} replacement was read`);
      } finally {
        fixture.cleanup();
      }
    }
  });

  test("report artifact loading caps reads at the opened size and rejects growth", () => {
    const fixture = createEvidenceHandoffFixture();
    const target = path.join(fs.realpathSync(fixture.root), ".quality/impact.json");
    const openedBytes = fs.lstatSync(target).size;
    const fileSystem = Object.create(fs);
    const originalOpen = fs.openSync;
    const originalRead = fs.readSync;
    let targetDescriptor;
    let grew = false;
    let requestedBytes = 0;
    fileSystem.openSync = function rememberImpactDescriptor(file, flags, ...rest) {
      const descriptor = originalOpen.call(fs, file, flags, ...rest);
      if (file === target) targetDescriptor = descriptor;
      return descriptor;
    };
    fileSystem.readSync = function growImpactDuringRead(
      descriptor,
      buffer,
      offset,
      length,
      position,
    ) {
      if (descriptor === targetDescriptor) {
        requestedBytes += length;
        if (!grew) {
          fs.appendFileSync(target, "synthetic post-open growth\n");
          grew = true;
        }
      }
      return originalRead.call(fs, descriptor, buffer, offset, length, position);
    };
    try {
      assert.throws(
        () => loadReportInputs({
          fileSystem,
          profile: fixture.profile,
          root: fixture.root,
          source: fixture.source,
        }),
        /Quality report input is unsafe or changed: \.quality\/impact\.json/u,
      );
      assert.strictEqual(grew, true);
      assert.ok(requestedBytes <= openedBytes, `${requestedBytes} exceeded ${openedBytes}`);
    } finally {
      fixture.cleanup();
    }
  });

  test("evidence handoff rejects a same-byte gate summary replacement at open", () => {
    const fixture = createEvidenceHandoffFixture();
    const target = path.join(
      fs.realpathSync(fixture.root),
      `.quality/gates/${fixture.profile}.json`,
    );
    const displaced = `${target}.original`;
    const replacement = `${target}.replacement`;
    fs.copyFileSync(target, replacement);
    const fileSystem = Object.create(fs);
    const originalOpen = fs.openSync;
    const originalRead = fs.readSync;
    let swapped = false;
    let readCalls = 0;
    fileSystem.openSync = function substituteSummaryAtOpen(file, flags, ...rest) {
      if (!swapped && file === target) {
        fs.renameSync(target, displaced);
        fs.renameSync(replacement, target);
        swapped = true;
      }
      return originalOpen.call(fs, file, flags, ...rest);
    };
    fileSystem.readSync = function countSummaryReads(...arguments_) {
      readCalls += 1;
      return originalRead.call(fs, ...arguments_);
    };
    try {
      assert.throws(
        () => verifyEvidenceHandoff({
          fileSystem,
          profile: fixture.profile,
          readSource: () => fixture.source,
          root: fixture.root,
          source: fixture.source,
        }),
        /Evidence file is unsafe or changed: \.quality\/gates\/fast\.json/u,
      );
      assert.strictEqual(swapped, true);
      assert.strictEqual(readCalls, 0);
    } finally {
      fixture.cleanup();
    }
  });

  test("evidence handoff rejects a coherent report-generation swap after initial validation", () => {
    const fixture = createEvidenceHandoffFixture();
    const fixtureRoot = fs.realpathSync(fixture.root);
    const evidenceReceipt = fixture.summary.steps.find(receipt => (
      receipt.stepId === "standalone-tests"
    ));
    const evidencePath = path.join(
      fixtureRoot,
      ...getGatePlan(fixture.profile)
        .find(step => step.id === "standalone-tests")
        .evidencePath.split("/"),
    );
    const receiptFile = path.join(fixtureRoot, ...receiptPath(evidenceReceipt).split("/"));
    const reportJson = path.join(fixtureRoot, ".quality/report.json");
    const reportMarkdown = path.join(fixtureRoot, ".quality/report.md");
    const targets = [evidencePath, receiptFile, reportJson, reportMarkdown];
    const generationA = new Map(targets.map(target => [target, fs.readFileSync(target)]));
    const generationB = new Map();
    const fileSystem = Object.create(fs);
    const originalLstat = fs.lstatSync;
    let swapped = false;
    try {
      const replacementEvidence = clone(evidenceReceipt.testEvidence);
      replacementEvidence.tests[0].title = "generation B title";
      replacementEvidence.tests[0].fullTitle = "generation B full title";
      const replacementEvidenceBytes = testEvidenceFileBytes(replacementEvidence);
      fs.writeFileSync(evidencePath, replacementEvidenceBytes);
      const replacementReceipt = clone(evidenceReceipt);
      replacementReceipt.testEvidence = replacementEvidence;
      replacementReceipt.testEvidenceFingerprint = crypto.createHash("sha256")
        .update(replacementEvidenceBytes)
        .digest("hex");
      writeJson(receiptPath(replacementReceipt), replacementReceipt, fixtureRoot);
      const replacementReport = generateReport(loadReportInputs({
        profile: fixture.profile,
        root: fixture.root,
        source: fixture.source,
      }));
      writeReport(replacementReport, { root: fixture.root });
      for (const target of targets) generationB.set(target, fs.readFileSync(target));
      assert.strictEqual(generationB.get(reportJson).equals(generationA.get(reportJson)), false);
      for (const target of targets) fs.writeFileSync(target, generationA.get(target));

      fileSystem.lstatSync = function swapGenerationAtReportRead(target, ...arguments_) {
        if (!swapped && target === reportJson) {
          for (const candidate of targets) {
            fs.writeFileSync(candidate, generationB.get(candidate));
          }
          swapped = true;
        }
        return originalLstat.call(fs, target, ...arguments_);
      };
      assert.throws(
        () => verifyEvidenceHandoff({
          fileSystem,
          profile: fixture.profile,
          readSource: () => fixture.source,
          root: fixture.root,
          source: fixture.source,
        }),
        /bundle bytes do not match|Gate receipts changed|generation changed/u,
      );
      assert.strictEqual(swapped, true);
    } finally {
      fixture.cleanup();
    }
  });

  test("findings loading rejects symlinks and growth without over-reading", () => {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-findings-boundary-",
    )));
    const target = path.join(scratch, "findings.jsonl");
    const linked = path.join(scratch, "findings-link.jsonl");
    const bytes = Buffer.from("{\"synthetic\":true}\n");
    fs.writeFileSync(target, bytes);
    fs.symlinkSync(target, linked);
    try {
      assert.throws(
        () => readBoundedFindingsBytes(linked),
        /bounded single-link regular file/u,
      );

      const openedBytes = fs.lstatSync(target).size;
      const fileSystem = Object.create(fs);
      const originalRead = fs.readSync;
      let grew = false;
      let requestedBytes = 0;
      fileSystem.readSync = function growFindingsDuringRead(
        descriptor,
        buffer,
        offset,
        length,
        position,
      ) {
        requestedBytes += length;
        if (!grew) {
          fs.appendFileSync(target, "synthetic post-open growth\n");
          grew = true;
        }
        return originalRead.call(fs, descriptor, buffer, offset, length, position);
      };
      assert.throws(
        () => readBoundedFindingsBytes(target, { fileSystem }),
        /bounded single-link regular file/u,
      );
      assert.strictEqual(grew, true);
      assert.ok(requestedBytes <= openedBytes, `${requestedBytes} exceeded ${openedBytes}`);
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
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
          const artifactFingerprint = materializeStepArtifacts(step, temporaryRoot);
          const evidence = materializeStepTestEvidence(step, temporaryRoot);
          return {
            status: blocked ? 2 : 0,
            signal: null,
            stdout: "",
            stderr: "",
            testEvidence: evidence.value,
            testEvidenceFingerprint: evidence.fingerprint,
            artifactFingerprint,
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
      ".npm-integrity",
      ".npm-version",
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

  test("checks each unique fixed finding SHA once per ledger validation", () => {
    const schema = require("../quality/finding.schema.json");
    const taxonomy = require("../quality/defect-taxonomy.json");
    const fixedSha = "a".repeat(40);
    const fixed = {
      severity: "P2",
      domain: "test-harness",
      status: "closed",
      deterministicStatus: "fixed",
      liveStatus: "not-required",
      rootCauseStatus: "proven",
      rootCause: "Repeated findings referenced one already validated commit.",
      regressionTest: "checks each unique fixed finding SHA once per ledger validation",
      mutationProof: { status: "not-applicable", summary: "Not applicable." },
      fixedSha,
      releaseBlocking: false,
    };
    let ancestryChecks = 0;
    const errors = validateFindings(
      [
        validFinding({ ...fixed, id: "QH-901" }),
        validFinding({ ...fixed, id: "QH-902" }),
      ],
      schema,
      taxonomy,
      root,
      (candidateRoot, candidateSha) => {
        ancestryChecks += 1;
        assert.strictEqual(candidateRoot, root);
        assert.strictEqual(candidateSha, fixedSha);
        return true;
      }
    );

    assert.deepStrictEqual(errors, []);
    assert.strictEqual(ancestryChecks, 1);
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
    const exactUiUploadPaths = [
      "          path: |-",
      "            .quality/upload/signed-out-ui/evidence.json",
      "            .quality/upload/signed-out-ui/result.json",
      "            .quality/upload/signed-out-ui/ui-candidate.json",
      "            .quality/upload/signed-out-ui/ui-candidate.vsix",
    ].join("\n");
    const uiError =
      "Deep CI must bind and secret-scan signed-out packaged UI evidence before upload.";
    const mutations = [
      deepWorkflow.replace(
        "run: npm run test:ui:smoke",
        "run: xvfb-run -a npm run test:ui:smoke"
      ),
      deepWorkflow.replace(
        "run: node scripts/quality/verify-ui-evidence.js",
        "run: npm run quality:report"
      ),
      deepWorkflow.replace(
        "run: npm run quality:secrets:signed-out-evidence",
        "run: npm run quality:secrets:current"
      ),
      deepWorkflow.replace(
        "run: node scripts/quality/verify-ui-evidence.js --bundle .quality/upload/signed-out-ui",
        "run: node scripts/quality/verify-ui-evidence.js"
      ),
      deepWorkflow.replace(
        "        env:\n          EXPECTED_SOURCE_SHA: ${{ github.sha }}\n        run: node scripts/quality/verify-ui-evidence.js --bundle .quality/upload/signed-out-ui",
        "        env:\n          EXPECTED_SOURCE_SHA: invented\n        run: node scripts/quality/verify-ui-evidence.js --bundle .quality/upload/signed-out-ui"
      ),
      deepWorkflow.replace(
        "if: ${{ always() && steps.ui_evidence_handoff.outcome == 'success' && steps.ui_evidence_secret_scan.outcome == 'success' && steps.ui_evidence_bundle.outcome == 'success' }}",
        "if: ${{ always() }}"
      ),
      deepWorkflow.replace(exactUiUploadPaths, "          path: .quality/upload/signed-out-ui"),
      deepWorkflow.replace(exactUiUploadPaths, "          path: .quality/qualification/ui-candidate.vsix"),
      deepWorkflow.replace(
        exactUiUploadPaths,
        `${exactUiUploadPaths}\n            .quality/upload/signed-out-ui/unexpected.txt`,
      ),
      deepWorkflow.replace(
        "  signed-out-black-box-ui:\n    name: Signed-out packaged black-box UI\n    runs-on: ubuntu-24.04\n    timeout-minutes: 30\n    steps:\n      - name: Checkout exact source\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          fetch-depth: 0\n          persist-credentials: false",
        "  signed-out-black-box-ui:\n    name: Signed-out packaged black-box UI\n    runs-on: ubuntu-24.04\n    timeout-minutes: 30\n    steps:\n      - name: Checkout exact source\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          persist-credentials: false"
      ),
    ];
    for (const [index, changed] of mutations.entries()) {
      assert.ok(verifyQualityContracts({
        root,
        sourceOverrides: { [deepWorkflowPath]: changed },
      }).errors.includes(uiError), `signed-out workflow mutation ${index}`);
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
    // Keep the transient adversarial link outside the runnable test inventory
    // so concurrent qualification processes cannot discover one another's fixture.
    const relativeLink = `quality/quality-linked-${crypto.randomBytes(16).toString("hex")}.test.js`;
    const link = path.join(root, relativeLink);
    let linkIdentity = null;
    const errors = [];
    try {
      fs.writeFileSync(outsideFile, `test(${JSON.stringify(evidence.testNames[0])}, () => {});\n`);
      fs.symlinkSync(outsideFile, link, "file");
      const linkStat = fs.lstatSync(link, { bigint: true });
      assert.strictEqual(linkStat.isSymbolicLink(), true);
      linkIdentity = Object.freeze(Object.fromEntries([
        "ctimeNs", "dev", "ino", "mode", "mtimeNs", "nlink", "size",
      ].map(key => [key, String(linkStat[key])])));
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
    } catch (error) {
      errors.push(error);
    }
    if (linkIdentity) {
      try {
        const linkStat = fs.lstatSync(link, { bigint: true });
        const currentIdentity = Object.fromEntries([
          "ctimeNs", "dev", "ino", "mode", "mtimeNs", "nlink", "size",
        ].map(key => [key, String(linkStat[key])]));
        if (!linkStat.isSymbolicLink()
          || Object.keys(linkIdentity).some(
            key => currentIdentity[key] !== linkIdentity[key],
          )) {
          throw new Error("Synthetic quality symlink fixture changed before cleanup.");
        }
        fs.unlinkSync(link);
        assert.throws(
          () => fs.lstatSync(link),
          error => error?.code === "ENOENT",
        );
      } catch (error) {
        errors.push(error);
      }
    }
    try {
      fs.rmSync(outside, { force: true, recursive: true });
    } catch (error) {
      errors.push(error);
    }
    if (errors.length === 1) throw errors[0];
    if (errors.length > 1) {
      throw new AggregateError(errors, "Synthetic quality symlink fixture failed and could not clean safely.");
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

  test("fast, full, and release profiles preserve exact current prior receipt trees", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-release-gate-lifecycle-",
    )));
    const execute = step => {
      const artifactFingerprint = materializeStepArtifacts(step, temporaryRoot);
      const evidence = materializeStepTestEvidence(step, temporaryRoot);
      return {
        status: 0,
        signal: null,
        stdout: "1 passing\n",
        stderr: "",
        testEvidence: evidence.value,
        testEvidenceFingerprint: evidence.fingerprint,
        artifactFingerprint,
      };
    };
    const preservedPaths = ["fast", "full"].flatMap(profile => [
      `.quality/gates/${profile}.json`,
      ...getGatePlan(profile).map(step => receiptPath({
        profile,
        sequence: step.sequence,
        stepId: step.id,
      })),
    ]);
    const snapshot = () => Object.fromEntries(preservedPaths.map(relativePath => {
      const target = path.join(temporaryRoot, ...relativePath.split("/"));
      const stat = fs.lstatSync(target, { bigint: true });
      return [relativePath, {
        bytes: fs.readFileSync(target),
        identity: [stat.dev, stat.ino, stat.ctimeNs, stat.mtimeNs, stat.size].map(String),
      }];
    }));
    try {
      assert.strictEqual(runGate({
        root: temporaryRoot,
        profile: "fast",
        source: SOURCE_IDENTITY,
        execute,
      }).status, "passed");
      assert.strictEqual(runGate({
        root: temporaryRoot,
        profile: "full",
        source: SOURCE_IDENTITY,
        execute,
      }).status, "passed");
      assert.strictEqual(assertExactReleaseGateTree(
        temporaryRoot,
        { source: SOURCE_IDENTITY },
      ), true);
      const beforeRelease = snapshot();
      let releaseExecutions = 0;
      const summary = runGate({
        root: temporaryRoot,
        profile: "release",
        source: SOURCE_IDENTITY,
        execute(step) {
          releaseExecutions += 1;
          if (step.id === "secret-release") {
            assert.strictEqual(assertExactReleaseGateTree(
              temporaryRoot,
              { source: SOURCE_IDENTITY },
            ), true);
          }
          const duringRelease = snapshot();
          for (const relativePath of preservedPaths) {
            assert.deepStrictEqual(
              duringRelease[relativePath].identity,
              beforeRelease[relativePath].identity,
              relativePath,
            );
            assert.deepStrictEqual(
              duringRelease[relativePath].bytes,
              beforeRelease[relativePath].bytes,
              relativePath,
            );
          }
          return execute(step);
        },
      });

      assert.strictEqual(releaseExecutions, getGatePlan("release").length);
      assert.strictEqual(summary.status, "passed");
      assert.strictEqual(assertExactReleaseGateTree(
        temporaryRoot,
        { source: SOURCE_IDENTITY },
      ), true);
      const afterRelease = snapshot();
      for (const relativePath of preservedPaths) {
        assert.deepStrictEqual(
          afterRelease[relativePath].identity,
          beforeRelease[relativePath].identity,
          relativePath,
        );
        assert.deepStrictEqual(
          afterRelease[relativePath].bytes,
          beforeRelease[relativePath].bytes,
          relativePath,
        );
      }

      const staleSummaryPath = path.join(temporaryRoot, ".quality", "gates", "fast.json");
      const staleSummary = JSON.parse(fs.readFileSync(staleSummaryPath, "utf8"));
      staleSummary.source = { ...SOURCE_IDENTITY, fingerprint: "b".repeat(64) };
      fs.writeFileSync(staleSummaryPath, `${JSON.stringify(staleSummary, null, 2)}\n`);
      assert.throws(
        () => assertExactReleaseGateTree(temporaryRoot, { source: SOURCE_IDENTITY }),
        /unexpected, stale, or unsafe entry/u,
      );
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("failed fast receipts with null artifact claims can be superseded by full", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-failed-fast-supersession-",
    )));
    const executePassing = step => {
      const artifactFingerprint = materializeStepArtifacts(step, temporaryRoot);
      const evidence = materializeStepTestEvidence(step, temporaryRoot);
      return {
        status: 0,
        signal: null,
        stdout: "1 passing\n",
        stderr: "",
        testEvidence: evidence.value,
        testEvidenceFingerprint: evidence.fingerprint,
        artifactFingerprint,
      };
    };
    try {
      const failed = runGate({
        root: temporaryRoot,
        profile: "fast",
        source: SOURCE_IDENTITY,
        execute(step) {
          if (step.sequence === 1) {
            return { status: 1, signal: null, stdout: "", stderr: "synthetic failure\n" };
          }
          return executePassing(step);
        },
      });
      assert.strictEqual(failed.status, "failed");
      assert.strictEqual(runGate({
        root: temporaryRoot,
        profile: "full",
        source: SOURCE_IDENTITY,
        execute: executePassing,
      }).status, "passed");
      assert.strictEqual(assertExactReleaseGateTree(
        temporaryRoot,
        { source: SOURCE_IDENTITY },
      ), true);
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("failed full receipts remain valid when release reaches its exposure scan", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-failed-full-supersession-",
    )));
    const executePassing = step => {
      const artifactFingerprint = materializeStepArtifacts(step, temporaryRoot);
      const evidence = materializeStepTestEvidence(step, temporaryRoot);
      return {
        status: 0,
        signal: null,
        stdout: "1 passing\n",
        stderr: "",
        testEvidence: evidence.value,
        testEvidenceFingerprint: evidence.fingerprint,
        artifactFingerprint,
      };
    };
    try {
      const failed = runGate({
        root: temporaryRoot,
        profile: "full",
        source: SOURCE_IDENTITY,
        execute(step) {
          if (step.sequence === 1) {
            return { status: 1, signal: null, stdout: "", stderr: "synthetic failure\n" };
          }
          return executePassing(step);
        },
      });
      assert.strictEqual(failed.status, "failed");
      let reachedExposureScan = false;
      const release = runGate({
        root: temporaryRoot,
        profile: "release",
        source: SOURCE_IDENTITY,
        execute(step) {
          if (step.id === "secret-release") {
            reachedExposureScan = true;
            assert.strictEqual(assertExactReleaseGateTree(
              temporaryRoot,
              { source: SOURCE_IDENTITY },
            ), true);
          }
          return executePassing(step);
        },
      });
      assert.strictEqual(reachedExposureScan, true);
      assert.strictEqual(release.status, "passed");
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("preserved gate trees reject self-consistent execution and binding forgeries", () => {
    const cases = [
      {
        name: "passed-nonzero",
        profile: "fast",
        supersededByFull: true,
        stepId: "quality-contract-verifier",
        mutate(receipt) {
          receipt.exitCode = 7;
        },
      },
      {
        name: "not-run-with-completion",
        stepId: "quality-contract-verifier",
        mutate(receipt) {
          receipt.status = "not-run";
          receipt.exitCode = null;
          receipt.reason = "not-started";
        },
      },
      {
        name: "broken-blocker-order",
        stepId: "quality-contract-verifier",
        mutate(receipt) {
          receipt.status = "failed";
          receipt.exitCode = 1;
        },
      },
      {
        name: "forged-artifact-binding",
        stepId: "change-impact",
        mutate(receipt) {
          receipt.artifactFingerprint = "f".repeat(64);
        },
      },
      {
        name: "forged-superseded-artifact-binding",
        profile: "fast",
        supersededByFull: true,
        stepId: "change-impact",
        mutate(receipt) {
          receipt.artifactFingerprint = "f".repeat(64);
        },
      },
      {
        name: "forged-test-evidence-binding",
        stepId: "standalone-tests",
        mutate(receipt) {
          receipt.testEvidenceFingerprint = "f".repeat(64);
        },
      },
    ];
    for (const fixture of cases) {
      const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
        os.tmpdir(),
        `cloudsmith-preserved-forgery-${fixture.name}-`,
      )));
      try {
        const execute = step => {
            const artifactFingerprint = materializeStepArtifacts(step, temporaryRoot);
            const evidence = materializeStepTestEvidence(step, temporaryRoot);
            return {
              status: 0,
              signal: null,
              stdout: "1 passing\n",
              stderr: "",
              testEvidence: evidence.value,
              testEvidenceFingerprint: evidence.fingerprint,
              artifactFingerprint,
            };
        };
        const profile = fixture.profile || "full";
        const summary = runGate({
          root: temporaryRoot,
          profile,
          source: SOURCE_IDENTITY,
          execute,
        });
        if (fixture.supersededByFull) runGate({
          root: temporaryRoot,
          profile: "full",
          source: SOURCE_IDENTITY,
          execute,
        });
        assert.strictEqual(summary.status, "passed", fixture.name);
        const summaryPath = path.join(
          temporaryRoot,
          ".quality",
          "gates",
          `${profile}.json`,
        );
        const forgedSummary = JSON.parse(fs.readFileSync(summaryPath, "utf8"));
        const receiptIndex = forgedSummary.steps.findIndex(receipt => (
          receipt.stepId === fixture.stepId
        ));
        const forgedReceipt = forgedSummary.steps[receiptIndex];
        fixture.mutate(forgedReceipt);
        forgedSummary.status = aggregateStatuses(
          forgedSummary.steps.map(receipt => receipt.status),
        );
        const unsigned = { ...forgedSummary };
        delete unsigned.key;
        forgedSummary.key = {
          sha: forgedSummary.source.sha,
          fingerprint: fingerprint(unsigned),
        };
        writeJson(receiptPath(forgedReceipt), forgedReceipt, temporaryRoot, {
          subtree: `.quality/gates/${profile}`,
        });
        writeJson(`.quality/gates/${profile}.json`, forgedSummary, temporaryRoot, {
          subtree: ".quality/gates",
        });

        assert.throws(
          () => assertExactReleaseGateTree(temporaryRoot, { source: SOURCE_IDENTITY }),
          /unexpected, stale, or unsafe entry/u,
          fixture.name,
        );
      } finally {
        fs.rmSync(temporaryRoot, { recursive: true, force: true });
      }
    }
  });

  test("preserved gate validation rejects a same-byte receipt path swap", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-preserved-path-swap-",
    )));
    try {
      runGate({
        root: temporaryRoot,
        profile: "full",
        source: SOURCE_IDENTITY,
        execute(step) {
          const artifactFingerprint = materializeStepArtifacts(step, temporaryRoot);
          const evidence = materializeStepTestEvidence(step, temporaryRoot);
          return {
            status: 0,
            signal: null,
            stdout: "1 passing\n",
            stderr: "",
            testEvidence: evidence.value,
            testEvidenceFingerprint: evidence.fingerprint,
            artifactFingerprint,
          };
        },
      });
      const firstStep = getGatePlan("full")[0];
      const target = path.join(temporaryRoot, receiptPath({
        profile: "full",
        sequence: firstStep.sequence,
        stepId: firstStep.id,
      }));
      const original = path.join(temporaryRoot, "original-preserved-receipt.json");
      const bytes = fs.readFileSync(target);
      const fileSystem = Object.create(fs);
      let targetStats = 0;
      let swapped = false;
      fileSystem.lstatSync = (...arguments_) => {
        if (arguments_[0] === target && ++targetStats === 5) {
          fs.renameSync(target, original);
          fs.writeFileSync(target, bytes);
          swapped = true;
        }
        return fs.lstatSync(...arguments_);
      };
      assert.throws(
        () => generatedEvidenceInventory(temporaryRoot, {
          fileSystem,
          source: SOURCE_IDENTITY,
        }),
        /unexpected, stale, or unsafe entry/u,
      );
      assert.strictEqual(swapped, true);
      assert.strictEqual(fs.readFileSync(target).equals(bytes), true);
      assert.strictEqual(fs.readFileSync(original).equals(bytes), true);
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("own-profile cleanup rejects a nested file before unlinking any receipt", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-gate-nested-cleanup-",
    )));
    const summaryPath = path.join(temporaryRoot, ".quality", "gates", "fast.json");
    const nestedPath = path.join(
      temporaryRoot,
      ".quality",
      "gates",
      "fast",
      "unexpected-directory",
      "nested-proof.json",
    );
    try {
      fs.mkdirSync(path.dirname(nestedPath), { recursive: true });
      fs.writeFileSync(summaryPath, "synthetic prior summary\n");
      fs.writeFileSync(nestedPath, "synthetic nested proof\n");
      let executions = 0;
      assert.throws(() => runGate({
        root: temporaryRoot,
        profile: "fast",
        plan: [fixtureArtifactStep()],
        source: SOURCE_IDENTITY,
        execute() {
          executions += 1;
          return { status: 0, signal: null, stdout: "", stderr: "" };
        },
      }), /cleanup refused an unsafe or changed tree/u);
      assert.strictEqual(executions, 0);
      assert.strictEqual(fs.readFileSync(summaryPath, "utf8"), "synthetic prior summary\n");
      assert.strictEqual(fs.readFileSync(nestedPath, "utf8"), "synthetic nested proof\n");
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("own-profile cleanup fails closed when a receipt is substituted after inventory", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-gate-substitution-cleanup-",
    )));
    const summaryPath = path.join(temporaryRoot, ".quality", "gates", "fast.json");
    const receipt = path.join(temporaryRoot, ".quality", "gates", "fast", "01-fixture.json");
    const displaced = path.join(temporaryRoot, "displaced-original.json");
    const originalLstat = fs.lstatSync;
    let receiptStats = 0;
    try {
      fs.mkdirSync(path.dirname(receipt), { recursive: true });
      fs.writeFileSync(summaryPath, "synthetic prior summary\n");
      fs.writeFileSync(receipt, "inventoried receipt\n");
      fs.lstatSync = function substituteAfterInventory(target, ...args) {
        if (target === receipt && ++receiptStats === 2) {
          fs.renameSync(receipt, displaced);
          fs.writeFileSync(receipt, "concurrent replacement\n");
        }
        return originalLstat.call(fs, target, ...args);
      };
      let executions = 0;
      withExpectedCleanupTaint(() => {
        assert.throws(() => runGate({
          root: temporaryRoot,
          profile: "fast",
          plan: [fixtureArtifactStep()],
          source: SOURCE_IDENTITY,
          execute() {
            executions += 1;
            return { status: 0, signal: null, stdout: "", stderr: "" };
          },
        }), /cleanup refused an unsafe or changed tree/u);
      });
      assert.strictEqual(executions, 0);
      assert.strictEqual(fs.readFileSync(summaryPath, "utf8"), "synthetic prior summary\n");
      assert.strictEqual(fs.readFileSync(receipt, "utf8"), "concurrent replacement\n");
      assert.strictEqual(fs.readFileSync(displaced, "utf8"), "inventoried receipt\n");
    } finally {
      fs.lstatSync = originalLstat;
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("own-profile cleanup rejects a same-inode same-size receipt rewrite", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-gate-receipt-rewrite-",
    )));
    const summaryPath = path.join(temporaryRoot, ".quality", "gates", "fast.json");
    const receipt = path.join(temporaryRoot, ".quality", "gates", "fast", "01-fixture.json");
    const originalReceipt = Buffer.from("inventoried receipt\n");
    const rewrittenReceipt = Buffer.alloc(originalReceipt.length, 0x78);
    const originalLstat = fs.lstatSync;
    let receiptStats = 0;
    try {
      fs.mkdirSync(path.dirname(receipt), { recursive: true });
      fs.writeFileSync(summaryPath, "synthetic prior summary\n");
      fs.writeFileSync(receipt, originalReceipt);
      const originalIdentity = originalLstat.call(fs, receipt, { bigint: true });
      fs.lstatSync = function rewriteAfterInventory(target, ...args) {
        if (target === receipt && ++receiptStats === 2) {
          fs.writeFileSync(receipt, rewrittenReceipt);
        }
        return originalLstat.call(fs, target, ...args);
      };
      let executions = 0;
      withExpectedCleanupTaint(() => {
        assert.throws(() => runGate({
          root: temporaryRoot,
          profile: "fast",
          plan: [fixtureArtifactStep()],
          source: SOURCE_IDENTITY,
          execute() {
            executions += 1;
            return { status: 0, signal: null, stdout: "", stderr: "" };
          },
        }), /cleanup refused an unsafe or changed tree/u);
      });
      const rewrittenIdentity = originalLstat.call(fs, receipt, { bigint: true });
      assert.strictEqual(executions, 0);
      assert.strictEqual(String(rewrittenIdentity.ino), String(originalIdentity.ino));
      assert.strictEqual(String(rewrittenIdentity.size), String(originalIdentity.size));
      assert.notStrictEqual(String(rewrittenIdentity.ctimeNs), String(originalIdentity.ctimeNs));
      assert.deepStrictEqual(fs.readFileSync(receipt), rewrittenReceipt);
    } finally {
      fs.lstatSync = originalLstat;
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("own-profile cleanup rejects a same-inode same-size summary rewrite", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-gate-summary-rewrite-",
    )));
    const summaryPath = path.join(temporaryRoot, ".quality", "gates", "fast.json");
    const receipt = path.join(temporaryRoot, ".quality", "gates", "fast", "01-fixture.json");
    const originalSummary = Buffer.from("inventoried summary\n");
    const rewrittenSummary = Buffer.alloc(originalSummary.length, 0x79);
    const originalLstat = fs.lstatSync;
    let summaryStats = 0;
    try {
      fs.mkdirSync(path.dirname(receipt), { recursive: true });
      fs.writeFileSync(summaryPath, originalSummary);
      fs.writeFileSync(receipt, "inventoried receipt\n");
      const originalIdentity = originalLstat.call(fs, summaryPath, { bigint: true });
      fs.lstatSync = function rewriteAfterInventory(target, ...args) {
        if (target === summaryPath && ++summaryStats === 2) {
          fs.writeFileSync(summaryPath, rewrittenSummary);
        }
        return originalLstat.call(fs, target, ...args);
      };
      let executions = 0;
      assert.throws(() => runGate({
        root: temporaryRoot,
        profile: "fast",
        plan: [fixtureArtifactStep()],
        source: SOURCE_IDENTITY,
        execute() {
          executions += 1;
          return { status: 0, signal: null, stdout: "", stderr: "" };
        },
      }), /cleanup refused an unsafe or changed tree/u);
      const rewrittenIdentity = originalLstat.call(fs, summaryPath, { bigint: true });
      assert.strictEqual(executions, 0);
      assert.strictEqual(String(rewrittenIdentity.ino), String(originalIdentity.ino));
      assert.strictEqual(String(rewrittenIdentity.size), String(originalIdentity.size));
      assert.notStrictEqual(String(rewrittenIdentity.ctimeNs), String(originalIdentity.ctimeNs));
      assert.deepStrictEqual(fs.readFileSync(summaryPath), rewrittenSummary);
    } finally {
      fs.lstatSync = originalLstat;
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("own-profile cleanup never deletes a final-summary substitution", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-gate-summary-substitution-",
    )));
    const summaryPath = path.join(temporaryRoot, ".quality", "gates", "fast.json");
    const receipt = path.join(temporaryRoot, ".quality", "gates", "fast", "01-fixture.json");
    const displaced = path.join(temporaryRoot, "displaced-summary.json");
    const originalRename = fs.renameSync;
    let swapped = false;
    try {
      fs.mkdirSync(path.dirname(receipt), { recursive: true });
      fs.writeFileSync(summaryPath, "inventoried summary\n");
      fs.writeFileSync(receipt, "inventoried receipt\n");
      fs.renameSync = function substituteFinalSummary(source, destination) {
        if (!swapped && source === summaryPath
          && path.basename(path.dirname(destination)).startsWith(".gate-summary-cleanup-fast-")) {
          originalRename.call(fs, summaryPath, displaced);
          fs.writeFileSync(summaryPath, "concurrent summary replacement\n");
          swapped = true;
        }
        return originalRename.call(fs, source, destination);
      };
      let executions = 0;
      withExpectedCleanupTaint(() => {
        assert.throws(() => runGate({
          root: temporaryRoot,
          profile: "fast",
          plan: [fixtureArtifactStep()],
          source: SOURCE_IDENTITY,
          execute() {
            executions += 1;
            return { status: 0, signal: null, stdout: "", stderr: "" };
          },
        }), /cleanup refused an unsafe or changed tree/u);
      });
      assert.strictEqual(swapped, true);
      assert.strictEqual(executions, 0);
      assert.strictEqual(fs.existsSync(summaryPath), false);
      const quarantineNames = fs.readdirSync(path.dirname(summaryPath)).filter(name => (
        name.startsWith(".gate-summary-cleanup-fast-")
      ));
      assert.strictEqual(quarantineNames.length, 1);
      assert.strictEqual(fs.readFileSync(path.join(
        path.dirname(summaryPath),
        quarantineNames[0],
        "summary.json",
      ), "utf8"), "concurrent summary replacement\n");
      assert.strictEqual(fs.readFileSync(displaced, "utf8"), "inventoried summary\n");
    } finally {
      fs.renameSync = originalRename;
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("wrong runtime rejects seeded gate and step outputs without mutation", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-gate-wrong-runtime-",
    )));
    const seeded = {
      ".quality/gates/fast.json": "seeded summary\n",
      ".quality/gates/fast/01-fixture-artifact.json": "seeded receipt\n",
      ".quality/fixture/artifact.json": "seeded step artifact\n",
    };
    try {
      fs.writeFileSync(path.join(temporaryRoot, ".node-version"), "22.23.2\n");
      for (const [relativePath, bytes] of Object.entries(seeded)) {
        const target = path.join(temporaryRoot, ...relativePath.split("/"));
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, bytes);
      }
      let executions = 0;
      assert.throws(() => runGateWithoutFixturePin({
        root: temporaryRoot,
        assertCanonicalNodeRuntime() {
          throw new Error("Canonical Node.js runtime does not match the exact version pin");
        },
        profile: "fast",
        plan: [fixtureArtifactStep()],
        source: SOURCE_IDENTITY,
        execute() {
          executions += 1;
          return { status: 0, signal: null, stdout: "", stderr: "" };
        },
      }), /Canonical Node\.js runtime does not match the exact version pin/u);
      assert.strictEqual(executions, 0);
      for (const [relativePath, bytes] of Object.entries(seeded)) {
        assert.strictEqual(
          fs.readFileSync(path.join(temporaryRoot, ...relativePath.split("/")), "utf8"),
          bytes,
          relativePath,
        );
      }
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("npm gate children use a hard-linked node-only runtime ahead of conflicting PATH", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-gate-child-runtime-",
    )));
    const runtime = path.join(temporaryRoot, "runtime", "bin", "node");
    const runtimeLink = path.join(temporaryRoot, "runtime-node-hard-link");
    const conflictingPath = path.join(temporaryRoot, "conflicting", "bin");
    let spawned = null;
    let launcherDirectory = null;
    try {
      fs.mkdirSync(path.dirname(runtime), { recursive: true });
      fs.mkdirSync(conflictingPath, { recursive: true });
      fs.writeFileSync(runtime, "synthetic exact node runtime\n");
      fs.linkSync(runtime, runtimeLink);
      const npmFixture = writeCanonicalNpmFixture(temporaryRoot, { nodeExecutable: runtime });
      assert.strictEqual(fs.existsSync(path.join(path.dirname(runtime), "npm")), false);
      assert.strictEqual(fs.lstatSync(runtime).nlink, 2);
      assert.strictEqual(exactRuntimeExecutable(runtime), runtime);

      const result = executeCommand({
        id: "fixture-npm-runtime",
        category: "fixture",
        executable: "npm",
        args: ["run", "fixture"],
        command: "npm run fixture",
        blockedExitCodes: [],
        sequence: 1,
      }, {
        root: temporaryRoot,
        runtimeExecutable: runtime,
        npmExecPath: npmFixture.cliPath,
        temporaryParent: temporaryRoot,
        environment: { PATH: conflictingPath },
        spawnSync(executable, args, options) {
          spawned = { executable, args, environment: options.env };
          launcherDirectory = options.env.PATH.split(path.delimiter)[0];
          assert.strictEqual(fs.lstatSync(path.join(launcherDirectory, "node")).isFile(), true);
          assert.strictEqual(fs.lstatSync(path.join(launcherDirectory, "npm")).isFile(), true);
          return { status: 0, signal: null, stdout: "", stderr: "" };
        },
      });
      assert.strictEqual(result.status, 0);
      assert.strictEqual(spawned.executable, runtime);
      assert.deepStrictEqual(spawned.args.slice(1), ["run", "fixture"]);
      assert.strictEqual(
        spawned.args[0],
        path.join(launcherDirectory, "npm-runtime", "bin", "npm-cli.js"),
      );
      assert.strictEqual(
        spawned.environment.PATH.split(path.delimiter)[0],
        launcherDirectory,
      );
      assert.strictEqual(
        spawned.environment.PATH.split(path.delimiter)[1],
        path.dirname(runtime),
      );
      assert.strictEqual(
        spawned.environment.PATH.split(path.delimiter)[2],
        conflictingPath,
      );
      assert.strictEqual(
        gateChildEnvironment({ PATH: conflictingPath }, runtime).PATH,
        [path.dirname(runtime), conflictingPath].join(path.delimiter),
      );
      assert.strictEqual(fs.existsSync(launcherDirectory), false);
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("npm gate children reject local toolchain shadowing before step output mutation", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-gate-shadowed-runtime-",
    )));
    const seededArtifact = path.join(temporaryRoot, ".quality", "fixture", "artifact.json");
    let spawns = 0;
    try {
      const npmFixture = writeCanonicalNpmFixture(temporaryRoot);
      const shadow = path.join(temporaryRoot, "node_modules", ".bin", "npm");
      fs.mkdirSync(path.dirname(shadow), { recursive: true });
      fs.writeFileSync(shadow, "#!/bin/sh\nexit 99\n", { mode: 0o700 });
      fs.mkdirSync(path.dirname(seededArtifact), { recursive: true });
      fs.writeFileSync(seededArtifact, "seeded artifact\n");
      assert.throws(() => executeCommand({
        id: "fixture-npm-shadow",
        category: "fixture",
        executable: "npm",
        args: ["run", "fixture"],
        command: "npm run fixture",
        artifactPath: ".quality/fixture/artifact.json",
        artifactSubtree: ".quality/fixture",
        blockedExitCodes: [],
        sequence: 1,
      }, {
        root: temporaryRoot,
        runtimeExecutable: npmFixture.nodeExecutable,
        npmExecPath: npmFixture.cliPath,
        environment: { PATH: path.dirname(npmFixture.nodeExecutable) },
        spawnSync() {
          spawns += 1;
          return { status: 0, signal: null, stdout: "", stderr: "" };
        },
      }), /toolchain command resolution is unsafe or invalid/u);
      assert.strictEqual(spawns, 0);
      assert.strictEqual(fs.readFileSync(seededArtifact, "utf8"), "seeded artifact\n");
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("forged npm CLI is rejected before seeded gate and step outputs are mutated", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-gate-forged-npm-",
    )));
    const npmCli = path.join(temporaryRoot, "npm-cli.js");
    const seeded = {
      ".quality/gates/fast.json": "seeded summary\n",
      ".quality/gates/fast/01-fixture-artifact.json": "seeded receipt\n",
      ".quality/fixture/artifact.json": "seeded step artifact\n",
    };
    try {
      fs.writeFileSync(path.join(temporaryRoot, ".node-version"), `${process.versions.node}\n`);
      fs.writeFileSync(path.join(temporaryRoot, ".npm-version"), "10.9.8\n");
      fs.writeFileSync(npmCli, "process.exit(0)\n");
      for (const [relativePath, bytes] of Object.entries(seeded)) {
        const target = path.join(temporaryRoot, ...relativePath.split("/"));
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, bytes);
      }
      assert.throws(() => runGateWithoutFixturePin({
        root: temporaryRoot,
        profile: "fast",
        plan: [{
          id: "fixture-artifact",
          category: "fixture",
          executable: "npm",
          args: ["run", "fixture"],
          command: "npm run fixture",
          artifactPath: ".quality/fixture/artifact.json",
          artifactSubtree: ".quality/fixture",
          blockedExitCodes: [],
          sequence: 1,
        }],
        source: SOURCE_IDENTITY,
        npmExecPath: npmCli,
      }), /Canonical npm runtime is unsafe or invalid/u);
      for (const [relativePath, bytes] of Object.entries(seeded)) {
        assert.strictEqual(
          fs.readFileSync(path.join(temporaryRoot, ...relativePath.split("/")), "utf8"),
          bytes,
          relativePath,
        );
      }
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  test("Windows PATH case collision is rejected before gate output mutation", () => {
    const temporaryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-gate-path-collision-",
    )));
    const seededSummary = path.join(temporaryRoot, ".quality", "gates", "fast.json");
    try {
      fs.writeFileSync(path.join(temporaryRoot, ".node-version"), `${process.versions.node}\n`);
      fs.mkdirSync(path.dirname(seededSummary), { recursive: true });
      fs.writeFileSync(seededSummary, "seeded summary\n");
      assert.throws(() => runGateWithoutFixturePin({
        root: temporaryRoot,
        profile: "fast",
        plan: [{
          id: "fixture-npm-runtime",
          category: "fixture",
          executable: "npm",
          args: ["run", "fixture"],
          command: "npm run fixture",
          blockedExitCodes: [],
          sequence: 1,
        }],
        source: SOURCE_IDENTITY,
        platform: "win32",
        environment: { PATH: "first", Path: "second" },
      }), /PATH has case-colliding keys/u);
      assert.strictEqual(fs.readFileSync(seededSummary, "utf8"), "seeded summary\n");
    } finally {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });
});

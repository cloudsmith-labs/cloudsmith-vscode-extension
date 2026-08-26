// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const Mocha = require("mocha");
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
  completedReceipt,
  executeCommand,
  getGatePlan,
  receiptPath,
  runGate,
} = require("../scripts/quality/gate");
const {
  changedMutationTargets,
  filterMutationReport,
  perFileCounts,
  validateMutationSummary,
  workingTreeFingerprint,
} = require("../scripts/quality/run-mutation");
const {
  isAncestorCommit,
  validateMutationBaseline,
} = require("../scripts/quality/mutation-baseline");
const {
  attestationReviewDigest,
  evaluateLiveQualification,
  parseArguments: parseChecklistArguments,
  requiredLiveWorkflowIds,
} = require("../scripts/quality/release-checklist");
const {
  discoverUiArtifacts,
  generateReport,
  hasDeterministicReportFailure,
  renderMarkdown,
  validateFindingRecord,
  validateFindings,
  validateImpactArtifact,
} = require("../scripts/quality/report");
const { verifyQualityContracts } = require("../scripts/quality/verify-workflows");

const root = path.resolve(__dirname, "..");
const SOURCE_SHA = "1111111111111111111111111111111111111111";
const BASE_SHA = "2222222222222222222222222222222222222222";
const SOURCE_IDENTITY = Object.freeze({
  sha: SOURCE_SHA,
  fingerprint: "a".repeat(64),
});
const LIVE_FIXTURE_NOW = new Date("2026-08-26T00:03:00.000Z");

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
  return {
    stepId: step.id,
    category: step.category,
    command: step.command,
    status: "passed",
    exitCode: 0,
    signal: null,
    testCounts: null,
    testEvidence: step.evidencePath ? testEvidence(step, source) : null,
    artifactFingerprint: step.artifactPath
      ? mutationArtifactFingerprint(validMutationSummary())
      : null,
    source,
  };
}

function testEvidence(step, source = SOURCE_IDENTITY) {
  return {
    schemaVersion: 1,
    source,
    suite: step.id,
    counts: { passed: 1, failed: 0, pending: 0 },
    tests: [{
      file: "test/placeholder.test.js",
      title: "placeholder",
      fullTitle: "placeholder",
      status: "passed",
    }],
  };
}

function passedLiveAttestation(source = SOURCE_IDENTITY) {
  const workflows = require("../quality/critical-workflows.json");
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-live-receipt-"));
  const capturedAt = "2026-08-26T00:00:00.000Z";
  const completedAt = "2026-08-26T00:01:00.000Z";
  const reviewedAt = "2026-08-26T00:02:00.000Z";
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
  const document = {
    schemaVersion: 2,
    source,
    status: "passed",
    authenticatedAcceptance: true,
    checklistConfirmed: true,
    operatorId: "fixture-qualification-operator",
    completedAt,
    verdict: "TEAM-TEST READY",
    evidence: [qualificationEvidence],
    openReleaseBlockerCount: 0,
    workflowResults: requiredLiveWorkflowIds(workflows).map(id => ({
      id,
      status: "passed",
      authoritativeOutcomeObserved: true,
      evidence: [qualificationEvidence],
    })),
    visibleEnabledActions: {
      status: "passed",
      silentNoOpCount: 0,
      evidence: [qualificationEvidence],
    },
  };
  document.independentReview = {
    status: "passed",
    reviewerId: "fixture-independent-reviewer",
    source,
    reviewedAt,
    attestationSha256: attestationReviewDigest(document),
    evidence: [reviewEvidence],
  };
  return {
    cleanup: () => fs.rmSync(fixtureRoot, { force: true, recursive: true }),
    document,
    root: fixtureRoot,
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
    survivors: [{ fingerprint: "c".repeat(64) }],
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

function mutationSurvivors(count) {
  return Array.from({ length: count }, (_value, index) => ({
    fingerprint: index.toString(16).padStart(64, "0"),
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
      "domain/packageActionCapabilities.js": { score: 90 },
    },
  };
}

function validTrackedMutationBaseline() {
  const firstTarget = "domain/authCapabilities.js";
  const secondTarget = "util/externalNavigation.js";
  return {
    schemaVersion: 1,
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
    status: "open",
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
    liveVerification: { status: "not-started", summary: "Not run." },
    releaseBlocking: true,
    ...overrides,
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
  test("composes fast, full, and release plans without hiding either Extension Host label", () => {
    const fast = getGatePlan("fast");
    const full = getGatePlan("full");
    const release = getGatePlan("release");
    const fastIds = fast.map(step => step.id);
    const fullWithoutReport = full.filter(step => step.id !== "quality-report");
    const releaseWithoutFinalizers = release.filter(step => ![
      "black-box-ui-smoke",
      "release-checklist",
      "quality-report",
    ].includes(step.id));

    assert.deepStrictEqual(fastIds, [
      "quality-contract-verifier",
      "change-impact",
      "repository-check",
      "standalone-tests",
    ]);
    assert.deepStrictEqual(full.slice(0, fast.length).map(step => step.id), fastIds);
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
    ]) assert.ok(full.some(step => step.id === id), `missing full gate step ${id}`);
    assert.deepStrictEqual(release.slice(-3).map(step => step.id), [
      "black-box-ui-smoke",
      "release-checklist",
      "quality-report",
    ]);
  });

  test("writes receipts and cannot turn a nonzero command into a passing gate", () => {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-quality-gate-"));
    try {
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
            artifactFingerprint: step.artifactPath ? "b".repeat(64) : null,
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
        ["--base", "must-not-be-used", "--files", "domain/c.js,domain/a.js,other.js"]
      ),
      ["domain/a.js", "domain/c.js"]
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
        files: { "domain/packageActionCapabilities.js": { score: 0 } },
      },
      "changed"
    ));
  });

  test("enforces explicit global and per-file mutation regressions", () => {
    assert.throws(
      () => validateMutationSummary(
        mutationSummaryAt80(),
        {
          thresholds: { break: 81 },
          files: { "domain/packageActionCapabilities.js": { score: 90 } },
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
          files: { "domain/packageActionCapabilities.js": { score: 81 } },
        },
        "changed"
      ),
      /regressed below 81/
    );
    assert.doesNotThrow(() => validateMutationSummary(
      mutationSummaryAt80(),
      {
        thresholds: { break: 95 },
        files: { "domain/packageActionCapabilities.js": { score: 80 } },
      },
      "changed"
    ));
  });

  test("rejects zero-mutant, timeout, and uncovered mutation runs", () => {
    assert.throws(
      () => validateMutationSummary(
        validMutationSummary({
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
        mutationSummaryAt80({ timeout: 1, noCoverage: 0, killed: 8, survived: 1 }),
        { thresholds: { break: null }, files: {} },
        "core"
      ),
      /1 timeout mutants/
    );
    assert.throws(
      () => validateMutationSummary(
        mutationSummaryAt80({ noCoverage: 1, timeout: 0, killed: 8, survived: 1 }),
        { thresholds: { break: null }, files: {} },
        "core"
      ),
      /1 noCoverage mutants/
    );
  });

  test("blocks UI smoke before packaging even with the former acknowledgement", async () => {
    require("../scripts/quality/evidence");
    const childProcess = require("child_process");
    const originalSpawnSync = childProcess.spawnSync;
    const previousAck = process.env.CLOUDSMITH_UI_SECRET_BOUNDARY_ACK;
    const modulePath = require.resolve("../scripts/quality/run-ui-smoke");
    const resultPath = path.join(root, ".quality", "ui", "result.json");
    const originalResult = fs.existsSync(resultPath) ? fs.readFileSync(resultPath) : null;
    const runsPath = path.join(root, ".quality", "ui", "runs");
    const originalRuns = fs.existsSync(runsPath) ? new Set(fs.readdirSync(runsPath)) : new Set();
    let packageCalls = 0;
    childProcess.spawnSync = (command, args, options) => {
      if ((args || []).includes("scripts/release/package-vsix.js")) {
        packageCalls += 1;
        return { status: 70, signal: null, stdout: "", stderr: "packaging was reached" };
      }
      return originalSpawnSync(command, args, options);
    };
    process.env.CLOUDSMITH_UI_SECRET_BOUNDARY_ACK = "isolated-empty-profile";
    delete require.cache[modulePath];
    try {
      const { runUiSmoke } = require(modulePath);
      await assert.rejects(
        () => runUiSmoke(),
        error => error.code === "UI_SECRET_BOUNDARY_BLOCKED"
      );
      assert.strictEqual(packageCalls, 0, "UI boundary must settle before package creation");
      const receipt = JSON.parse(fs.readFileSync(resultPath, "utf8"));
      assert.strictEqual(receipt.status, "blocked");
      assert.strictEqual(receipt.launchAttempted, false);
      assert.strictEqual(receipt.tool, null);
      assert.match(receipt.reason, /SecretStorage.*not authorized/i);
      assert.doesNotMatch(
        fs.readFileSync(path.join(root, "scripts", "quality", "run-ui-smoke.js"), "utf8"),
        /CLOUDSMITH_UI_SECRET_BOUNDARY_ACK|isolated-empty-profile/
      );
      assert.doesNotMatch(
        fs.readFileSync(path.join(root, "ui-test", "smoke.test.js"), "utf8"),
        /CLOUDSMITH_UI_SECRET_BOUNDARY_ACK|isolated-empty-profile/
      );
    } finally {
      childProcess.spawnSync = originalSpawnSync;
      if (previousAck === undefined) delete process.env.CLOUDSMITH_UI_SECRET_BOUNDARY_ACK;
      else process.env.CLOUDSMITH_UI_SECRET_BOUNDARY_ACK = previousAck;
      delete require.cache[modulePath];
      if (originalResult) {
        fs.mkdirSync(path.dirname(resultPath), { recursive: true });
        fs.writeFileSync(resultPath, originalResult);
      } else {
        fs.rmSync(resultPath, { force: true });
      }
      if (fs.existsSync(runsPath)) {
        for (const entry of fs.readdirSync(runsPath)) {
          if (!originalRuns.has(entry)) {
            fs.rmSync(path.join(runsPath, entry), { force: true, recursive: true });
          }
        }
      }
    }
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
      });
      const passed = evaluateLiveQualification({
        root: passedFixture.root,
        now: LIVE_FIXTURE_NOW,
        source: SOURCE_IDENTITY,
        workflows,
        document: passedFixture.document,
      });

      assert.strictEqual(staleResult.status, "failed");
      assert.ok(staleResult.errors.some(error => /source SHA/.test(error)));
      assert.deepStrictEqual(staleResult.passedWorkflowIds, []);
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
        impact: validImpact(),
        ...validMutationEvidence(),
        liveQualification: evaluateLiveQualification({
          root: liveFixture.root,
          now: LIVE_FIXTURE_NOW,
          source: SOURCE_IDENTITY,
          workflows,
          document: liveFixture.document,
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

  test("rejects wrong-suite and nonpassing structured Mocha receipts", () => {
    const plan = getGatePlan("fast");
    const baseOptions = {
      source: SOURCE_IDENTITY,
      profile: "fast",
      plan,
      impact: validImpact(),
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
    failedEvidence.counts = { passed: 0, failed: 1, pending: 0 };
    const failedRecord = generateReport({
      ...baseOptions,
      receipts: failedRecordReceipts,
    });
    const failedRecordStep = failedRecord.deterministicGates.steps.find(step => (
      step.stepId === "standalone-tests"
    ));
    assert.strictEqual(failedRecordStep.status, "failed");
    assert.match(failedRecordStep.reason, /test-evidence:nonpassing-test-record/u);
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
      impact: validImpact(),
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
      impact: validImpact(),
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
        }],
      },
      inventories,
    });

    assert.deepStrictEqual(report.liveQualification.passedWorkflowIds, []);
    assert.deepStrictEqual(report.liveQualification.missingWorkflowIds, [workflowId]);
    assert.strictEqual(report.workflowCoverage[0].layerStatuses["live-protocol"], "failed");
    assert.strictEqual(report.status, "failed");
    assert.strictEqual(hasDeterministicReportFailure(report), true);
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
    const report = generateReport({
      source: SOURCE_IDENTITY,
      profile: "full",
      plan,
      receipts: plan.map(step => passedReceipt(step)),
      impact: stale,
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
      impact: validImpact(),
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
      impact: validImpact(),
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
      status: "fixed",
      customerImpact: 7,
      evidence: "not-an-evidence-array",
      rootCauseStatus: "suspected",
      regressionTest: null,
      mutationProof: { status: "not-started", summary: "Not proven." },
      fixedSha: SOURCE_SHA,
      liveVerification: { status: "blocked", summary: "Not verified." },
      releaseBlocking: false,
    }), schema, taxonomy);

    assert.ok(errors.some(error => /customerImpact has invalid type/.test(error)));
    assert.ok(errors.some(error => /evidence has invalid type/.test(error)));
    assert.ok(errors.some(error => /requires a regression test/.test(error)));
    assert.ok(errors.some(error => /completed mutation proof/.test(error)));
    assert.ok(errors.some(error => /completed live verification/.test(error)));
    assert.ok(errors.some(error => /not an ancestor/.test(error)));
  });
});

suite("Quality contract verifier fixtures", () => {
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
      }
      return receipt;
    });
    const report = generateReport({
      source: SOURCE_IDENTITY,
      profile: "release",
      plan,
      receipts,
      impact: validImpact(),
      ...validMutationEvidence(),
      liveQualification: null,
      findings: [],
      findingsStatus: "passed",
      workflows,
      inventories: require("./testInventories"),
      ui: { status: "blocked", source: SOURCE_IDENTITY, sourceSha: SOURCE_SHA },
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
      /manual-production-composition in a real VS Code host; the production manifest is not host-managed/
    );
  });
});

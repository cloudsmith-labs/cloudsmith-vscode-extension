// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { isDeepStrictEqual } = require("util");
const {
  ROOT,
  discoverRepositoryOutputFiles,
  isPlainObject,
  readJson,
  requireNonEmptyString,
  resolveOptionalRepositoryFile,
  uniqueSorted,
  writeJson,
  writeText,
} = require("./common");
const {
  EVIDENCE_STATUSES,
  aggregateStatuses,
  fingerprint,
  sourceIdentity,
} = require("./evidence");
const { getGatePlan, receiptPath, validateTestEvidence } = require("./gate");
const { impactFingerprint } = require("./impact");
const {
  decodeFindingsBytes,
  deriveReleaseBlocking,
  isClosedFinding,
  parseFindingsJsonl,
  readBoundedFindingsBytes,
  validateFindingRecord,
  validateFindings,
} = require("./findings");
const {
  DEFAULT_INPUT: DEFAULT_LIVE_INPUT,
  evaluateDiskLiveQualification,
  requiredLiveWorkflowIds,
} = require("./release-checklist");
const { validateMutationSummary } = require("./run-mutation");
const { validateCandidateBinding } = require("./candidate-binding");

const DEFAULT_JSON_OUTPUT = ".quality/report.json";
const DEFAULT_MARKDOWN_OUTPUT = ".quality/report.md";
const DEFAULT_FINDINGS = "internal_docs/quality/findings.jsonl";
const DEFAULT_LIVE_STATUS = ".quality/gates/live-qualification-status.json";
const DEFAULT_UI_RESULT = ".quality/ui/result.json";
const DEFAULT_CANDIDATE_RECEIPT = ".quality/qualification/candidate.json";
const DEFAULT_EXTENSION_VERSION = require("../../package.json").version;
const UI_BLOCKED_REASON = "Black-box UI qualification is blocked by the current host environment.";
const FINDING_DOMAINS = Object.freeze([
  "product", "test-harness", "ci", "release-evidence", "security-environment",
  "documentation", "external-platform",
]);
const FINDING_SEVERITIES = Object.freeze(["P0", "P1", "P2", "P3"]);
const DETERMINISTIC_FINDING_STATUSES = Object.freeze(["failing", "fixed", "not-applicable"]);
const LIVE_FINDING_STATUSES = Object.freeze([
  "not-required", "pending", "blocked", "verified", "failed",
]);

function generateReport(options = {}) {
  const source = options.source;
  const profile = options.profile || "full";
  const plan = options.plan || getGatePlan(profile);
  const receipts = normalizeGateReceipts(options.receipts || [], plan, source);
  const receiptById = new Map(receipts.map(receipt => [receipt.stepId, receipt]));
  const impact = summarizeImpact(
    receiptById.get("change-impact"),
    options.impact,
    source,
    options.impactArtifactFingerprint
  );
  const mutation = summarizeMutation(
    receiptById.get("changed-mutation"),
    options.mutation,
    source,
    options.mutationArtifactFingerprint,
    options.mutationBaseline || readJson("quality/mutation-baseline.json")
  );
  const blackBoxUi = summarizeUi(
    receiptById.get("black-box-ui-smoke"),
    options.ui,
    source,
    options.uiArtifacts || [],
    {
      artifactFingerprint: options.uiArtifactFingerprint,
      candidateReceipt: options.candidateReceipt,
      expectedTests: expectedBlackBoxUiTests(options.workflows),
      extensionId: options.extensionId || "Cloudsmith.cloudsmith-vsc",
      extensionVersion: options.extensionVersion || DEFAULT_EXTENSION_VERSION,
    }
  );
  const deterministicReceipts = receipts.filter(receipt => ![
    "quality-report",
    "release-checklist",
  ].includes(receipt.stepId));
  const deterministicStatuses = deterministicReceipts.map(receipt => receipt.status);
  if (deterministicReceipts.some(receipt => receipt.stepId === "black-box-ui-smoke")) {
    deterministicStatuses.push(blackBoxUi.status);
  }
  const deterministicStatus = aggregateStatuses(deterministicStatuses);
  const findings = summarizeFindings(
    options.findings || [],
    options.findingsStatus || "passed",
    options.findingsErrors || [],
    options.workflows
  );
  const findingsState = {
    fingerprint: options.findingsFingerprint || fingerprint(options.findings || []),
    openReleaseBlockerCount: findings.releaseBlocking,
  };
  const liveQualificationRevalidation = profile === "release" && options.liveQualification
    ? revalidateLiveQualificationForReport(options, source)
    : null;
  const liveQualification = summarizeLiveQualification(options.liveQualification, source, {
    artifactFingerprint: options.liveQualificationArtifactFingerprint,
    requireChecklistReceipt: profile === "release",
    checklistReceipt: receiptById.get("release-checklist"),
    requiredWorkflowIds: requiredLiveWorkflowIds(options.workflows),
    findingsState,
    revalidation: liveQualificationRevalidation,
  });
  const testResults = summarizeTestResults(receiptById);
  const workflowCoverage = summarizeWorkflowCoverage({
    workflows: options.workflows,
    impact,
    receiptById,
    blackBoxUi,
    liveQualification,
    inventories: options.inventories,
  });
  const webviewInteractionEvidence = summarizeWebviewInteractionEvidence(
    options.workflows,
    workflowCoverage,
    blackBoxUi
  );
  const extensionHostExecutionEvidence = summarizeExtensionHostExecutionEvidence(
    options.workflows,
    workflowCoverage
  );
  const categories = summarizeCategories(receiptById, mutation);
  const releaseReadiness = releaseReadinessStatus({
    deterministicStatus,
    impact,
    mutation,
    blackBoxUi,
    liveQualification,
    findings,
    workflowCoverage,
    profile,
  });
  const report = {
    schemaVersion: 2,
    source,
    gateProfile: profile,
    status: releaseReadiness.status,
    releaseReadiness,
    impact,
    deterministicGates: {
      status: deterministicStatus,
      steps: deterministicReceipts,
    },
    testResults,
    mutation,
    blackBoxUi,
    liveQualification,
    categories,
    workflowCoverage,
    webviewInteractionEvidence,
    extensionHostExecutionEvidence,
    findings,
  };
  report.key = {
    sha: source.sha,
    fingerprint: fingerprint(report),
  };
  return report;
}

function revalidateLiveQualificationForReport(options, source) {
  try {
    return {
      status: evaluateDiskLiveQualification({
        root: options.root || ROOT,
        source,
        workflows: options.workflows,
        inputPath: options.liveQualification?.inputPath,
        qualificationHomeDirectory: options.qualificationHomeDirectory,
      }),
      error: null,
    };
  } catch (error) {
    return { status: null, error: error.message };
  }
}

function normalizeGateReceipts(receipts, plan, source) {
  const byId = new Map(receipts.map(receipt => [receipt?.stepId, receipt]));
  return plan.map(step => normalizeGateReceipt(byId.get(step.id), step, source));
}

function normalizeGateReceipt(receipt, step, source) {
  const base = {
    stepId: step.id,
    category: step.category,
    command: step.command,
    status: "not-run",
    exitCode: null,
    signal: null,
    testCounts: null,
    artifactFingerprint: null,
    reason: "missing-receipt",
    present: false,
  };
  if (!receipt) return base;
  const integrityErrors = validateReceiptExecution(receipt, step);
  if (receipt.command !== step.command) integrityErrors.push("command-mismatch");
  if (receipt.source?.sha !== source.sha
    || receipt.source?.fingerprint !== source.fingerprint) {
    integrityErrors.push("source-mismatch");
  }
  const requiresTestEvidence = [
    "standalone-tests",
    "extension-host-core",
    "extension-host-smoke",
  ].includes(step.id);
  if (receipt.status === "passed" && requiresTestEvidence) {
    const evidenceError = validateTestEvidence(receipt.testEvidence, step, source);
    if (evidenceError) integrityErrors.push(`test-evidence:${evidenceError}`);
  }
  if (["passed", "blocked"].includes(receipt.status) && stepRequiresArtifacts(step)
    && !/^[a-f0-9]{64}$/u.test(receipt.artifactFingerprint || "")) {
    integrityErrors.push("missing-or-invalid-artifact-fingerprint");
  }
  const evidenceCounts = requiresTestEvidence && receipt.testEvidence?.counts;
  const testCounts = evidenceCounts ? {
    passing: evidenceCounts.passed,
    failing: evidenceCounts.failed,
    pending: evidenceCounts.pending,
  } : receipt.testCounts || null;
  return {
    stepId: step.id,
    category: step.category,
    command: step.command,
    status: integrityErrors.length > 0 ? "failed" : receipt.status,
    exitCode: Number.isInteger(receipt.exitCode) ? receipt.exitCode : null,
    signal: receipt.signal || null,
    testCounts,
    testEvidence: receipt.testEvidence || null,
    artifactFingerprint: receipt.artifactFingerprint || null,
    reason: integrityErrors.length > 0
      ? `receipt-integrity:${integrityErrors.join(",")}`
      : receipt.reason || null,
    present: true,
  };
}

function validateReceiptExecution(receipt, step) {
  const errors = [];
  const status = receipt?.status;
  if (!["passed", "failed", "blocked", "not-run"].includes(status)) {
    return [status === "not-applicable"
      ? "not-applicable-command-status"
      : "invalid-command-status"];
  }
  if (!(receipt.exitCode === null || Number.isInteger(receipt.exitCode))) {
    errors.push("invalid-exit-code");
  }
  if (!(receipt.signal === null
    || (typeof receipt.signal === "string" && receipt.signal.length > 0))) {
    errors.push("invalid-signal");
  }
  if (!(receipt.reason === null
    || (typeof receipt.reason === "string" && receipt.reason.length > 0))) {
    errors.push("invalid-reason");
  }
  if (status === "passed") {
    if (receipt.exitCode !== 0) errors.push("nonzero-command-claimed-pass");
    if (receipt.signal !== null) errors.push("signaled-command-claimed-pass");
    if (receipt.reason !== null) errors.push("reasoned-command-claimed-pass");
  } else if (status === "blocked") {
    if (!(step.blockedExitCodes || []).includes(receipt.exitCode)) {
      errors.push("invalid-blocked-exit-code");
    }
    if (receipt.signal !== null) errors.push("signaled-command-claimed-blocked");
    if (receipt.reason !== null) errors.push("reasoned-command-claimed-blocked");
  } else if (status === "not-run") {
    if (receipt.exitCode !== null || receipt.signal !== null
      || typeof receipt.reason !== "string" || receipt.reason.length === 0) {
      errors.push("invalid-not-run-execution");
    }
  } else if (!(Number.isInteger(receipt.exitCode) && receipt.exitCode !== 0)
    && receipt.signal === null
    && !(typeof receipt.reason === "string" && receipt.reason.length > 0)) {
    errors.push("failed-command-lacks-failure-evidence");
  }
  return errors;
}

function stepRequiresArtifacts(step) {
  return Boolean(step?.artifactPath)
    || (Array.isArray(step?.artifactPaths) && step.artifactPaths.length > 0);
}

function summarizeImpact(gateReceipt, impact, source, artifactFingerprint) {
  if (gateReceipt?.present && gateReceipt.status !== "passed") {
    return emptyImpact(gateReceipt.status);
  }
  if (!impact) {
    return emptyImpact(
      gateReceipt?.present ? "failed" : "not-run",
      gateReceipt?.present ? "Impact command passed without an artifact." : null
    );
  }
  const errors = validateImpactArtifact(impact);
  let status = errors.length > 0 || impact.ok === false ? "failed" : "passed";
  if (impact.source?.sha !== source.sha
    || impact.source?.fingerprint !== source.fingerprint) status = "blocked";
  if (gateReceipt?.present && gateReceipt.status === "passed"
    && (!/^[a-f0-9]{64}$/u.test(artifactFingerprint || "")
      || gateReceipt.artifactFingerprint !== artifactFingerprint)) {
    status = "failed";
    errors.push("Impact gate receipt does not bind the exact artifact.");
  }
  return {
    status,
    workflows: uniqueSorted(impact.workflows || []),
    actions: uniqueSorted(impact.actions || []),
    requiredLayers: uniqueSorted(impact.requiredLayers || []),
    commands: uniqueSorted(impact.commands || []),
    riskCategories: uniqueSorted(impact.riskCategories || []),
    unmappedRuntimeFiles: uniqueSorted(impact.unmappedRuntimeFiles || []),
    analysisKey: impact.analysisKey || null,
    artifactFingerprint: artifactFingerprint || null,
    errors: uniqueSorted(errors),
  };
}

function emptyImpact(status, reason = null) {
  return {
    status,
    workflows: [],
    actions: [],
    requiredLayers: [],
    commands: [],
    riskCategories: [],
    unmappedRuntimeFiles: [],
    analysisKey: null,
    artifactFingerprint: null,
    errors: reason ? [reason] : [],
  };
}

function validateImpactArtifact(impact) {
  if (!isPlainObject(impact)) return ["impact artifact must be an object"];
  const errors = [];
  if (impact.schemaVersion !== 1) errors.push("unsupported schemaVersion");
  if (impact.analysisScope !== "complete-working-tree" || impact.source?.mode !== "git") {
    errors.push("impact analysis is not a complete Git working-tree analysis");
  }
  if (!/^[a-f0-9]{40}$/u.test(impact.source?.sha || "")) errors.push("invalid source SHA");
  if (!/^[a-f0-9]{64}$/u.test(impact.source?.fingerprint || "")) {
    errors.push("missing source fingerprint");
  }
  if (!requireNonEmptyString(impact.source?.base)
    || !/^[a-f0-9]{40}$/u.test(impact.source?.baseSha || "")) {
    errors.push("invalid comparison base");
  }
  for (const field of [
    "changes",
    "changedFiles",
    "fileStates",
    "runtimeFiles",
    "testFiles",
    "manifestFiles",
    "workflows",
    "workflowMappings",
    "actions",
    "requiredLayers",
    "commands",
    "workflowRiskClasses",
    "riskCategories",
    "unmappedRuntimeFiles",
  ]) {
    if (!Array.isArray(impact[field])) errors.push(`missing array ${field}`);
  }
  if (typeof impact.ok !== "boolean") errors.push("missing boolean ok");
  if (impact.key?.sha !== impact.source?.sha
    || !/^[a-f0-9]{64}$/u.test(impact.key?.fingerprint || "")
    || impact.key?.fingerprint !== impactFingerprint(impact)
    || impact.analysisKey !== `${impact.source?.sha}:${impact.key?.fingerprint}`) {
    errors.push("invalid analysis key");
  }
  if (impact.ok === true && (impact.unmappedRuntimeFiles || []).length > 0) {
    errors.push("ok impact artifact contains unmapped runtime files");
  }
  return uniqueSorted(errors);
}

function summarizeMutation(gateReceipt, mutation, source, artifactFingerprint, baseline) {
  if (gateReceipt?.present && gateReceipt.status !== "passed") {
    return emptyMutation(gateReceipt.status);
  }
  if (!mutation) {
    return gateReceipt?.present
      ? emptyMutation("failed", "Mutation command passed without a summary artifact.")
      : emptyMutation("not-run");
  }
  let status = mutation.status;
  let reason = null;
  if (!EVIDENCE_STATUSES.includes(status)) status = "failed";
  if (mutation.source?.sha !== source.sha
    || mutation.source?.fingerprint !== source.fingerprint) status = "blocked";
  if (gateReceipt?.present && gateReceipt.status === "passed") {
    if (!/^[a-f0-9]{64}$/u.test(artifactFingerprint || "")) {
      status = "failed";
      reason = "Mutation command passed without a readable summary artifact fingerprint.";
    } else if (gateReceipt.artifactFingerprint !== artifactFingerprint) {
      status = "failed";
      reason = "Mutation summary artifact does not match the gate receipt.";
    }
  }
  if (status === "passed" && gateReceipt?.present && mutation.mode !== "changed") {
    status = "failed";
    reason = "Changed-mutation receipt does not contain changed-mode evidence.";
  }
  if (status === "passed") {
    try {
      validateMutationSummary(mutation, baseline, mutation.mode || "changed");
    } catch (error) {
      status = "failed";
      reason = `Invalid mutation summary: ${error.message}`;
    }
  }
  return {
    status,
    mode: mutation.mode || "changed",
    targets: uniqueSorted(mutation.targets || []),
    mutants: integerOrNull(mutation.mutants),
    killed: integerOrNull(mutation.killed),
    survived: integerOrNull(mutation.survived),
    timeout: integerOrNull(mutation.timeout),
    noCoverage: integerOrNull(mutation.noCoverage),
    score: Number.isFinite(mutation.score) ? mutation.score : null,
    artifactFingerprint: artifactFingerprint || null,
    reason,
  };
}

function emptyMutation(status, reason = null) {
  return {
    status,
    mode: "changed",
    targets: [],
    mutants: null,
    killed: null,
    survived: null,
    timeout: null,
    noCoverage: null,
    score: null,
    artifactFingerprint: null,
    reason,
  };
}

function summarizeUi(gateReceipt, ui, source, artifacts, options = {}) {
  if (!gateReceipt) return emptyUi("not-run", artifacts);
  if (!["passed", "blocked"].includes(gateReceipt.status)) {
    return {
      ...emptyUi(gateReceipt.status, artifacts),
      reason: ui?.reason || gateReceipt.reason || null,
    };
  }
  if (!ui) return emptyUi("failed", artifacts, "UI command completed without a result artifact.");
  const errors = validateUiResult(ui, source, options.expectedTests || [], options);
  if (!/^[a-f0-9]{64}$/u.test(options.artifactFingerprint || "")
    || gateReceipt.artifactFingerprint !== options.artifactFingerprint) {
    errors.push("UI gate receipt does not bind the exact result artifact.");
  }
  if (ui.status !== gateReceipt.status) {
    errors.push("UI result status does not match its gate receipt.");
  }
  if (errors.length > 0) return emptyUi("failed", artifacts, uniqueSorted(errors).join(" "));
  if (ui.status === "blocked") {
    return { ...emptyUi("blocked", artifacts), reason: ui.reason };
  }
  return {
    status: "passed",
    tool: ui.tool,
    toolVersion: ui.toolVersion,
    vscodeVersion: ui.vscodeVersion,
    platform: ui.platform,
    architecture: ui.architecture,
    candidate: ui.candidate,
    declaredTests: [...ui.tests],
    failureArtifacts: [],
    reason: null,
  };
}

function expectedBlackBoxUiTests(workflows) {
  return uniqueSorted((workflows?.workflows || []).flatMap(workflow => (
    (workflow.evidence || [])
      .filter(item => item.layer === "black-box-ui")
      .flatMap(item => item.testNames || [])
  )));
}

function validateUiResult(value, source, expectedTests, options = {}) {
  const errors = [];
  const exactKeys = [
    "architecture", "candidate", "launchAttempted", "platform", "reason",
    "results", "schemaVersion", "source", "sourceSha", "status", "tests",
    "tool", "toolVersion", "vscodeVersion",
  ];
  if (!isPlainObject(value)) return ["UI result artifact must be an object."];
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(exactKeys)) {
    errors.push("UI result artifact fields do not match schemaVersion 2.");
  }
  if (value.schemaVersion !== 2) errors.push("UI result artifact schemaVersion must be 2.");
  if (!isPlainObject(value.source)
    || JSON.stringify(Object.keys(value.source).sort()) !== JSON.stringify(["fingerprint", "sha"])
    || value.source.sha !== source.sha
    || value.source.fingerprint !== source.fingerprint
    || value.sourceSha !== source.sha) {
    errors.push("UI result artifact does not bind the current source.");
  }
  if (!["passed", "blocked"].includes(value.status)) {
    errors.push("UI result artifact has an invalid status.");
  }
  if (!Array.isArray(value.tests)
    || value.tests.some(test => !requireNonEmptyString(test))
    || JSON.stringify(value.tests) !== JSON.stringify(uniqueSorted(value.tests))
    || !Array.isArray(value.results)) {
    errors.push("UI result artifact has invalid test inventories.");
  }
  if (value.status === "passed") {
    if (value.tool !== "vscode-extension-tester"
      || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(value.toolVersion || "")
      || !/^\d+\.\d+\.\d+$/u.test(value.vscodeVersion || "")
      || !new Set(["darwin", "linux", "win32"]).has(value.platform)
      || !new Set(["arm64", "x64"]).has(value.architecture)
      || value.launchAttempted !== true
      || expectedTests.length === 0
      || JSON.stringify(value.tests) !== JSON.stringify(expectedTests)
      || value.reason !== null) {
      errors.push("Passed UI result artifact has invalid execution metadata or test inventory.");
    }
    errors.push(...validateUiCandidate(value.candidate, value, source, options));
    const resultNames = [];
    for (const result of value.results || []) {
      if (!isPlainObject(result)
        || JSON.stringify(Object.keys(result).sort()) !== JSON.stringify(["name", "status"])
        || result.status !== "passed"
        || typeof result.name !== "string") {
        errors.push("Passed UI result artifact has an invalid test result.");
        continue;
      }
      resultNames.push(result.name);
    }
    if (JSON.stringify(resultNames) !== JSON.stringify(expectedTests)) {
      errors.push("Passed UI result artifact does not prove every declared UI test.");
    }
  } else if (value.candidate !== null
    || value.launchAttempted !== false
    || value.tool !== null
    || value.toolVersion !== null
    || value.vscodeVersion !== null
    || value.platform !== null
    || value.architecture !== null
    || JSON.stringify(value.tests) !== "[]"
    || JSON.stringify(value.results) !== "[]"
    || value.reason !== UI_BLOCKED_REASON) {
    errors.push("Blocked UI result artifact is not the strict value-blind blocked shape.");
  }
  return uniqueSorted(errors);
}

function validateUiCandidate(candidate, ui, source, options = {}) {
  const errors = [];
  const exactKeys = [
    "candidateReceiptFingerprint", "extensionId", "extensionVersion", "profileMode",
    "sourceFingerprint", "sourceSha", "vscodeVersion", "vsixSha256",
  ];
  if (!isPlainObject(candidate)
    || JSON.stringify(Object.keys(candidate).sort()) !== JSON.stringify(exactKeys)) {
    return ["UI result candidate binding does not match the public schema."];
  }
  if (!/^[a-f0-9]{64}$/u.test(candidate.candidateReceiptFingerprint || "")
    || !/^[a-f0-9]{64}$/u.test(candidate.sourceFingerprint || "")
    || !/^[a-f0-9]{64}$/u.test(candidate.vsixSha256 || "")
    || !/^[a-f0-9]{40,64}$/u.test(candidate.sourceSha || "")
    || candidate.extensionId !== (options.extensionId || "Cloudsmith.cloudsmith-vsc")
    || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(candidate.extensionVersion || "")
    || (options.extensionVersion && candidate.extensionVersion !== options.extensionVersion)
    || candidate.profileMode !== "ci"
    || candidate.sourceSha !== source.sha
    || candidate.sourceFingerprint !== source.fingerprint
    || candidate.vscodeVersion !== ui.vscodeVersion) {
    errors.push("UI result candidate binding is invalid or stale.");
  }
  const receipt = options.candidateReceipt;
  if (!isPlainObject(receipt)
    || receipt.schemaVersion !== 2
    || receipt.status !== "passed"
    || receipt.fingerprint !== candidate.candidateReceiptFingerprint
    || receipt.source?.sha !== candidate.sourceSha
    || receipt.source?.fingerprint !== candidate.sourceFingerprint
    || receipt.artifact?.sourceSha !== candidate.sourceSha
    || receipt.artifact?.sourceFingerprint !== candidate.sourceFingerprint
    || receipt.artifact?.sha256 !== candidate.vsixSha256
    || receipt.extension?.id !== candidate.extensionId
    || receipt.extension?.version !== candidate.extensionVersion
    || receipt.vscode?.version !== candidate.vscodeVersion
    || receipt.profile?.mode !== candidate.profileMode
    || receipt.profile?.persistent !== false
    || receipt.installation?.status !== "passed"
    || receipt.installation?.id !== candidate.extensionId
    || receipt.installation?.version !== candidate.extensionVersion
    || receipt.launch?.developmentPath !== false) {
    errors.push("UI result does not bind the exact verified candidate receipt.");
  } else {
    const { fingerprint: declaredFingerprint, ...receiptBase } = receipt;
    if (declaredFingerprint !== fingerprint(receiptBase)) {
      errors.push("UI candidate receipt fingerprint does not match its exact contents.");
    }
  }
  return errors;
}

function emptyUi(status, artifacts = [], reason = null) {
  return {
    status,
    tool: null,
    toolVersion: null,
    vscodeVersion: null,
    platform: null,
    architecture: null,
    candidate: null,
    declaredTests: [],
    failureArtifacts: status === "passed" ? [] : uniqueSorted(artifacts),
    reason,
  };
}

function summarizeLiveQualification(value, source, options = {}) {
  let summary;
  if (!value) {
    summary = emptyLiveQualification(
      "not-run",
      options.findingsState,
      options.requiredWorkflowIds || []
    );
  } else {
    const artifactErrors = validateDerivedLiveStatus(
      value,
      options.requiredWorkflowIds || [],
      options.findingsState
    );
    let status = [...EVIDENCE_STATUSES, "partial"].includes(value.status)
      ? value.status
      : "failed";
    if (artifactErrors.length > 0) status = "failed";
    else if (value.source?.sha !== source.sha
      || value.source?.fingerprint !== source.fingerprint) status = "blocked";
    const passedWorkflowIds = uniqueSorted(value.passedWorkflowIds || []);
    const requiredWorkflowIds = uniqueSorted(value.requiredWorkflowIds || []);
    summary = {
      status,
      candidate: safeLiveCandidate(value.candidate),
      authenticatedAcceptance: status === "passed"
        ? value.authenticatedAcceptance
        : "not-recorded",
      verdict: status === "passed" ? value.verdict : null,
      requiredWorkflowIds,
      passedWorkflowIds,
      missingWorkflowIds: requiredWorkflowIds.filter(id => !passedWorkflowIds.includes(id)),
      workflowMatrix: Array.isArray(value.workflowMatrix) ? value.workflowMatrix : [],
      attestationFingerprint: value.attestationFingerprint || null,
      evidenceManifest: Array.isArray(value.evidenceManifest) ? value.evidenceManifest : [],
      findingsFingerprint: value.findingsFingerprint || null,
      openReleaseBlockerCount: Number.isInteger(value.openReleaseBlockerCount)
        ? value.openReleaseBlockerCount
        : null,
      visibleEnabledActions: value.visibleEnabledActions || {
        status: "not-run",
        silentNoOpCount: null,
      },
      errors: uniqueSorted([...(value.errors || []), ...artifactErrors]),
    };
  }
  if (!options.requireChecklistReceipt) return summary;
  if (value) {
    if (value.inputPath !== DEFAULT_LIVE_INPUT) {
      summary = rejectUnboundLiveQualification(
        summary,
        "failed",
        "Release gate live status does not use the exact default attestation input."
      );
    }
    const revalidation = options.revalidation;
    if (!isPlainObject(revalidation)
      || JSON.stringify(Object.keys(revalidation).sort())
        !== JSON.stringify(["error", "status"])) {
      summary = rejectUnboundLiveQualification(
        summary,
        "failed",
        "Live qualification was not independently revalidated from its disk attestation."
      );
    } else if (revalidation.error !== null) {
      summary = rejectUnboundLiveQualification(
        summary,
        "failed",
        `Live qualification disk revalidation failed: ${String(revalidation.error)}`
      );
    } else if (!isDeepStrictEqual(value, revalidation.status)) {
      summary = rejectUnboundLiveQualification(
        summary,
        "failed",
        "Live qualification status does not match a fresh evaluation of its disk attestation."
      );
    }
  }
  return bindLiveQualificationToChecklist(
    summary,
    options.checklistReceipt,
    options.artifactFingerprint
  );
}

function validateDerivedLiveStatus(value, requiredWorkflowIds = [], findingsState = {}) {
  const errors = [];
  const exactKeys = [
    "attestationFingerprint", "authenticatedAcceptance", "candidate", "errors", "evidenceManifest",
    "findingsFingerprint", "inputPath", "missingWorkflowIds", "openReleaseBlockerCount",
    "passedWorkflowIds", "reason", "requiredWorkflowIds", "schemaVersion", "source",
    "status", "verdict", "visibleEnabledActions", "workflowMatrix",
  ];
  if (!isPlainObject(value)) return ["Live status artifact must be an object."];
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(exactKeys)) {
    errors.push("Live status artifact fields do not match schemaVersion 3.");
  }
  if (value.schemaVersion !== 3) errors.push("Live status artifact schemaVersion must be 3.");
  if (!isPlainObject(value.source)
    || JSON.stringify(Object.keys(value.source).sort()) !== JSON.stringify(["fingerprint", "sha"])
    || !/^[a-f0-9]{40,64}$/u.test(value.source?.sha || "")
    || !/^[a-f0-9]{64}$/u.test(value.source?.fingerprint || "")) {
    errors.push("Live status artifact has invalid source identity.");
  }
  if (typeof value.inputPath !== "string"
    || !/^internal_docs\/quality\/[A-Za-z0-9._-]+\.json$/u.test(value.inputPath)) {
    errors.push("Live status artifact has an invalid input path.");
  }
  if (!(value.attestationFingerprint === null
    || /^[a-f0-9]{64}$/u.test(value.attestationFingerprint || ""))) {
    errors.push("Live status artifact has an invalid attestation fingerprint.");
  }
  if (value.candidate !== null) {
    try {
      validateCandidateBinding(value.candidate);
      if (value.candidate.sourceSha !== value.source?.sha
        || value.candidate.sourceFingerprint !== value.source?.fingerprint) {
        errors.push("Live status artifact candidate does not bind its source identity.");
      }
      if (value.candidate.profileMode !== "local") {
        errors.push("Live status artifact candidate does not bind the dedicated local profile.");
      }
    } catch {
      errors.push("Live status artifact has an invalid candidate binding.");
    }
  }
  if (!validLiveEvidenceManifest(value.evidenceManifest)) {
    errors.push("Live status artifact has an invalid evidence manifest.");
  } else if ((value.evidenceManifest || []).find(entry => entry.path === DEFAULT_FINDINGS)
    ?.sha256 !== value.findingsFingerprint) {
    errors.push("Live status artifact evidence manifest does not bind the findings ledger.");
  }
  if (!/^[a-f0-9]{64}$/u.test(value.findingsFingerprint || "")
    || !Number.isInteger(value.openReleaseBlockerCount)
    || value.openReleaseBlockerCount < 0) {
    errors.push("Live status artifact has invalid findings provenance.");
  }
  if (value.findingsFingerprint !== findingsState?.fingerprint
    || value.openReleaseBlockerCount !== findingsState?.openReleaseBlockerCount) {
    errors.push("Live status artifact does not bind the current findings ledger.");
  }
  if (!["passed", "failed", "partial", "blocked", "not-run"].includes(value.status)) {
    errors.push("Live status artifact has an invalid status.");
  }
  for (const field of ["requiredWorkflowIds", "passedWorkflowIds", "missingWorkflowIds"]) {
    if (!Array.isArray(value[field])
      || value[field].some(id => !/^WF-[A-Z0-9-]+$/u.test(id))
      || JSON.stringify(value[field]) !== JSON.stringify(uniqueSorted(value[field]))) {
      errors.push(`Live status artifact has invalid ${field}.`);
    }
  }
  if (JSON.stringify(value.requiredWorkflowIds) !== JSON.stringify(requiredWorkflowIds)) {
    errors.push("Live status artifact requiredWorkflowIds do not match the workflow manifest.");
  }
  const declaredRequired = new Set(value.requiredWorkflowIds || []);
  if ((value.passedWorkflowIds || []).some(id => !declaredRequired.has(id))) {
    errors.push("Live status artifact passedWorkflowIds are not a subset of requiredWorkflowIds.");
  }
  const expectedMissing = (value.requiredWorkflowIds || [])
    .filter(id => !(value.passedWorkflowIds || []).includes(id));
  if (JSON.stringify(value.missingWorkflowIds) !== JSON.stringify(expectedMissing)) {
    errors.push("Live status artifact missingWorkflowIds do not reconcile.");
  }
  if ((value.passedWorkflowIds || []).length > 0 && value.candidate === null) {
    errors.push("Live status PASS rows do not bind a qualification candidate.");
  }
  if (!Array.isArray(value.workflowMatrix)
    || value.workflowMatrix.length !== requiredWorkflowIds.length) {
    errors.push("Live status artifact must contain one workflow-matrix row per requirement.");
  } else {
    const matrixIds = [];
    const matrixPassed = [];
    for (const row of value.workflowMatrix) {
      if (!isPlainObject(row)
        || JSON.stringify(Object.keys(row).sort()) !== JSON.stringify(["id", "status"])
        || !/^WF-[A-Z0-9-]+$/u.test(row.id || "")
        || !["PASS", "FAIL", "PARTIAL", "BLOCKED"].includes(row.status)) {
        errors.push("Live status artifact has an invalid workflow-matrix row.");
        continue;
      }
      matrixIds.push(row.id);
      if (row.status === "PASS") matrixPassed.push(row.id);
    }
    if (JSON.stringify(matrixIds) !== JSON.stringify(requiredWorkflowIds)
      || JSON.stringify(matrixPassed) !== JSON.stringify(value.passedWorkflowIds)) {
      errors.push("Live status artifact workflow matrix does not reconcile with its inventories.");
    }
  }
  if (!isPlainObject(value.visibleEnabledActions)
    || JSON.stringify(Object.keys(value.visibleEnabledActions).sort())
      !== JSON.stringify(["silentNoOpCount", "status"])
    || !["passed", "failed", "blocked", "not-run"].includes(
      value.visibleEnabledActions?.status
    )
    || !(value.visibleEnabledActions?.silentNoOpCount === null
      || (Number.isInteger(value.visibleEnabledActions?.silentNoOpCount)
        && value.visibleEnabledActions.silentNoOpCount >= 0))) {
    errors.push("Live status artifact has invalid visibleEnabledActions.");
  }
  if (!(value.reason === null || (typeof value.reason === "string" && value.reason.length > 0))
    || !Array.isArray(value.errors)
    || value.errors.some(error => typeof error !== "string" || error.length === 0)) {
    errors.push("Live status artifact has invalid reason or errors.");
  }
  if (value.status === "passed") {
    if (value.authenticatedAcceptance !== "recorded"
      || !new Set([
        "TEAM-TEST READY",
        "TEAM-TEST READY WITH KNOWN NON-BLOCKING RISKS",
      ]).has(value.verdict)
      || JSON.stringify(value.passedWorkflowIds) !== JSON.stringify(value.requiredWorkflowIds)
      || (value.workflowMatrix || []).some(row => row.status !== "PASS")
      || (value.missingWorkflowIds || []).length !== 0
      || !/^[a-f0-9]{64}$/u.test(value.attestationFingerprint || "")
      || (value.evidenceManifest || []).length === 0
      || value.openReleaseBlockerCount !== 0
      || value.visibleEnabledActions?.status !== "passed"
      || value.visibleEnabledActions?.silentNoOpCount !== 0
      || value.reason !== null
      || (value.errors || []).length !== 0) {
      errors.push("Passed live status artifact is internally inconsistent.");
    }
    if (value.candidate === null) {
      errors.push("Passed live status artifact does not bind a qualification candidate.");
    }
  } else if (value.authenticatedAcceptance !== "not-recorded"
    || value.verdict !== null) {
    errors.push("Non-passing live status artifact claims authenticated acceptance.");
  }
  return uniqueSorted(errors);
}

function validLiveEvidenceManifest(value) {
  if (!Array.isArray(value)) return false;
  const paths = [];
  for (const entry of value) {
    if (!isPlainObject(entry)
      || JSON.stringify(Object.keys(entry).sort()) !== JSON.stringify(["path", "sha256"])
      || !/^internal_docs\/quality\/[A-Za-z0-9][A-Za-z0-9._-]*\.(?:json|jsonl|md|png|txt|webp)$/u
        .test(entry.path || "")
      || !/^[a-f0-9]{64}$/u.test(entry.sha256 || "")) {
      return false;
    }
    paths.push(entry.path);
  }
  return paths.length === new Set(paths).size
    && JSON.stringify(paths) === JSON.stringify(uniqueSorted(paths));
}

function safeLiveCandidate(value) {
  try {
    validateCandidateBinding(value);
    return { ...value };
  } catch {
    return null;
  }
}

function emptyLiveQualification(status, findingsState = {}, requiredWorkflowIds = []) {
  const required = uniqueSorted(requiredWorkflowIds);
  return {
    status,
    candidate: null,
    authenticatedAcceptance: "not-recorded",
    verdict: null,
    requiredWorkflowIds: required,
    passedWorkflowIds: [],
    missingWorkflowIds: required,
    workflowMatrix: required.map(id => ({ id, status: "BLOCKED" })),
    attestationFingerprint: null,
    evidenceManifest: [],
    findingsFingerprint: findingsState?.fingerprint || null,
    openReleaseBlockerCount: Number.isInteger(findingsState?.openReleaseBlockerCount)
      ? findingsState.openReleaseBlockerCount
      : null,
    visibleEnabledActions: { status: "not-run", silentNoOpCount: null },
    errors: [],
  };
}

function bindLiveQualificationToChecklist(summary, receipt, artifactFingerprint) {
  if (receipt?.present && ["passed", "blocked"].includes(receipt.status)) {
    if (!/^[a-f0-9]{64}$/u.test(artifactFingerprint || "")
      || receipt.artifactFingerprint !== artifactFingerprint) {
      return rejectUnboundLiveQualification(
        summary,
        "failed",
        "Release checklist receipt does not bind the exact live-status artifact."
      );
    }
  }
  if (receipt?.present && receipt.status === "passed") {
    if (summary.status === "passed") return summary;
    return rejectUnboundLiveQualification(
      summary,
      "failed",
      `Release checklist passed but its live-status evidence is ${summary.status}.`
    );
  }
  const status = receipt?.present && receipt.status === "blocked" ? "blocked" : "failed";
  const receiptStatus = receipt?.present ? receipt.status : "missing";
  const detail = receipt?.reason ? ` (${receipt.reason})` : "";
  return rejectUnboundLiveQualification(
    summary,
    status,
    `Release checklist receipt is ${receiptStatus}${detail}; live-status evidence is not trusted.`
  );
}

function rejectUnboundLiveQualification(summary, status, error) {
  return {
    ...summary,
    status,
    authenticatedAcceptance: "not-recorded",
    verdict: null,
    visibleEnabledActions: { status: "not-run", silentNoOpCount: null },
    errors: uniqueSorted([...summary.errors, error]),
  };
}

function summarizeFindings(findings, inputStatus, errors = [], workflows = {}) {
  const workflowById = new Map((workflows?.workflows || []).map(workflow => [
    workflow.id,
    workflow,
  ]));
  const policyErrors = [];
  const normalized = findings.map(finding => {
    const releaseBlocking = deriveReleaseBlocking(
      finding,
      workflowById.get(finding.workflowContract)
    );
    if (typeof finding.releaseBlocking !== "boolean"
      || finding.releaseBlocking !== releaseBlocking) {
      policyErrors.push(
        `Finding ${String(finding.id)} releaseBlocking does not match derived policy.`
      );
    }
    return {
      id: finding.id,
      severity: finding.severity,
      domain: finding.domain,
      status: finding.status,
      deterministicStatus: finding.deterministicStatus,
      liveStatus: finding.liveStatus,
      workflowContract: finding.workflowContract,
      surface: finding.surface,
      releaseBlocking,
    };
  }).sort((left, right) => String(left.id).localeCompare(String(right.id)));
  const open = normalized.filter(finding => !isClosedFinding(finding));
  const blockers = open.filter(finding => finding.releaseBlocking);
  const deterministicBlockers = blockers.filter(finding => (
    finding.deterministicStatus === "failing"
  ));
  const liveBlockers = blockers.filter(finding => (
    ["pending", "blocked", "failed"].includes(finding.liveStatus)
  ));
  const findingErrors = uniqueSorted([...errors, ...policyErrors]);
  return {
    status: findingErrors.length > 0 ? "failed" : inputStatus,
    total: normalized.length,
    open: open.length,
    closed: normalized.length - open.length,
    counts: {
      byDomain: countFindingsBy(normalized, "domain", FINDING_DOMAINS),
      bySeverity: countFindingsBy(normalized, "severity", FINDING_SEVERITIES),
      byDeterministicStatus: countFindingsBy(
        normalized,
        "deterministicStatus",
        DETERMINISTIC_FINDING_STATUSES
      ),
      byLiveStatus: countFindingsBy(normalized, "liveStatus", LIVE_FINDING_STATUSES),
    },
    releaseBlocking: blockers.length,
    deterministicReleaseBlocking: deterministicBlockers.length,
    liveReleaseBlocking: liveBlockers.length,
    releaseBlockers: blockers,
    errors: findingErrors,
  };
}

function countFindingsBy(findings, field, values) {
  return Object.fromEntries(values.map(value => [
    value,
    findings.filter(finding => finding[field] === value).length,
  ]));
}

function summarizeTestResults(receiptById) {
  const standalone = receiptById.get("standalone-tests");
  const core = receiptById.get("extension-host-core");
  const smoke = receiptById.get("extension-host-smoke");
  return {
    standalone: testResult(standalone),
    extensionHost: {
      status: aggregateStatuses([core?.status || "not-run", smoke?.status || "not-run"]),
      core: testResult(core),
      smoke: testResult(smoke),
    },
  };
}

function testResult(receipt) {
  return {
    status: receipt?.status || "not-run",
    count: Number.isInteger(receipt?.testCounts?.passing)
      ? receipt.testCounts.passing
      : null,
    failing: Number.isInteger(receipt?.testCounts?.failing)
      ? receipt.testCounts.failing
      : null,
    pending: Number.isInteger(receipt?.testCounts?.pending)
      ? receipt.testCounts.pending
      : null,
  };
}

function summarizeWorkflowCoverage(options) {
  const impacted = new Set(options.impact.workflows);
  const liveMatrix = new Map((options.liveQualification.workflowMatrix || []).map(row => [
    row.id,
    row.status,
  ]));
  const inventories = options.inventories || {};
  return (options.workflows?.workflows || []).map(workflow => {
    const layers = Object.fromEntries((workflow.requiredLayers || []).map(layer => [
      layer,
      workflowLayerStatus(workflow, layer, options, inventories, liveMatrix),
    ]));
    const authenticatedRequired = workflow.liveFixture?.required === true;
    const authenticatedStatus = authenticatedRequired
      ? liveMatrix.get(workflow.id) || "BLOCKED"
      : "NOT-REQUIRED";
    const deterministicStatus = aggregateStatuses(Object.entries(layers)
      .filter(([layer]) => layer !== "live-protocol")
      .map(([, status]) => status));
    const authenticatedEvidenceStatus = authenticatedStatus === "PASS"
      ? "passed"
      : authenticatedStatus === "FAIL"
        ? "failed"
        : authenticatedRequired ? "blocked" : "not-applicable";
    return {
      id: workflow.id,
      criticality: workflow.criticality,
      surface: workflow.surface,
      impacted: impacted.has(workflow.id),
      authoritativeOutcome: workflow.authoritativeOutcome,
      requiredLayers: [...(workflow.requiredLayers || [])],
      layerStatuses: layers,
      deterministicStatus,
      authenticatedRequired,
      authenticatedStatus,
      status: aggregateStatuses([deterministicStatus, authenticatedEvidenceStatus]),
    };
  }).sort((left, right) => left.id.localeCompare(right.id));
}

function workflowLayerStatus(workflow, layer, options, inventories, liveMatrix) {
  if (layer === "live-protocol") {
    const status = liveMatrix.get(workflow.id);
    if (status === "PASS") return "passed";
    if (status === "FAIL") return "failed";
    if (["PARTIAL", "BLOCKED"].includes(status)) return "blocked";
    return "not-run";
  }
  if (layer === "black-box-ui") return options.blackBoxUi.status;
  const evidence = (workflow.evidence || []).filter(item => item.layer === layer);
  if (evidence.length === 0) return "not-run";
  const statuses = evidence.map(item => evidenceItemStatus(
    item,
    options.receiptById,
    inventories
  ));
  if (layer === "contract") {
    statuses.push(options.receiptById.get("quality-contract-verifier")?.status || "not-run");
  }
  return aggregateStatuses(statuses);
}

function evidenceItemStatus(item, receiptById, inventories) {
  const file = item.testFile;
  let receipt = null;
  if ((inventories.STANDALONE_NODE_TESTS || []).includes(file)) {
    receipt = receiptById.get("standalone-tests");
  } else if ((inventories.VSCODE_SMOKE_TESTS || []).includes(file)) {
    receipt = receiptById.get("extension-host-smoke");
  } else if ((inventories.VSCODE_CORE_TESTS || []).includes(file)) {
    receipt = receiptById.get("extension-host-core");
  }
  if ((inventories.CREDENTIAL_BOUNDARY_EXCLUDED_TESTS || []).includes(file)) return "not-run";
  if (String(file).startsWith("ui-test/")) {
    return receiptById.get("black-box-ui-smoke")?.status || "not-run";
  }
  if (!receipt || receipt.status !== "passed") return receipt?.status || "not-run";
  const recorded = receipt.testEvidence?.tests || [];
  return (item.testNames || []).every(title => recorded.some(test => (
    test.file === file && test.title === title && test.status === "passed"
  ))) ? "passed" : "failed";
}

function summarizeWebviewInteractionEvidence(workflows, workflowCoverage, blackBoxUi) {
  const coverageById = new Map(workflowCoverage.map(workflow => [workflow.id, workflow]));
  const syntheticWorkflowIds = [];
  const renderedWorkflowIds = [];
  const syntheticStatuses = [];
  for (const workflow of workflows?.workflows || []) {
    const modes = new Set((workflow.evidence || []).map(item => item.interactionMode).filter(Boolean));
    if (modes.has("synthetic-host-message")) {
      syntheticWorkflowIds.push(workflow.id);
      syntheticStatuses.push(
        coverageById.get(workflow.id)?.layerStatuses?.["extension-host"] || "not-run"
      );
    }
    if (modes.has("rendered-dom-activation")) renderedWorkflowIds.push(workflow.id);
  }
  return {
    syntheticHostMessage: {
      classification: "extension-host-wiring",
      provesVisibleInteraction: false,
      status: aggregateStatuses(syntheticStatuses),
      workflowIds: uniqueSorted(syntheticWorkflowIds),
    },
    renderedDomActivation: {
      classification: "black-box-visible-interaction",
      provesVisibleInteraction: true,
      status: blackBoxUi.status,
      workflowIds: uniqueSorted(renderedWorkflowIds),
    },
  };
}

function summarizeExtensionHostExecutionEvidence(workflows, workflowCoverage) {
  const activation = (workflows?.workflows || []).find(workflow => (
    workflow.id === "WF-ACTIVATION-STARTUP"
  ));
  const manuallyComposed = (activation?.evidence || []).some(item => (
    item.testFile === "test/activation.test.js"
      && item.layer === "extension-host"
      && item.executionMode === "manual-production-composition"
  ));
  const coverage = workflowCoverage.find(workflow => workflow.id === activation?.id);
  return {
    classification: manuallyComposed
      ? "manual-production-composition"
      : "unclassified",
    host: "real-vscode-extension-host",
    hostManagedProductActivation: false,
    credentialBoundary: "explicit-in-memory-context",
    status: coverage?.layerStatuses?.["extension-host"] || "not-run",
  };
}

function summarizeCategories(receiptById, mutation) {
  return {
    contracts: receiptStatus(receiptById, ["quality-contract-verifier"]),
    architecturePolishVersion: receiptStatus(receiptById, ["repository-check"]),
    audits: receiptStatus(receiptById, ["runtime-audit", "development-audit"]),
    zeroTestGuard: receiptStatus(receiptById, ["zero-test-guard"]),
    mutation: mutation.status,
    package: receiptStatus(receiptById, ["package-build", "package-verify", "package-list"]),
  };
}

function receiptStatus(receiptById, ids) {
  return aggregateStatuses(ids.map(id => receiptById.get(id)?.status || "not-run"));
}

function releaseReadinessStatus(values) {
  const reasons = [];
  const workflowStatus = aggregateStatuses(values.workflowCoverage
    .filter(workflow => workflow.criticality === "release-critical")
    .map(workflow => workflow.deterministicStatus));
  const requiredAuthenticated = values.workflowCoverage.filter(workflow => (
    workflow.authenticatedRequired
  ));
  const allAuthenticatedPassed = requiredAuthenticated.length > 0
    && requiredAuthenticated.every(workflow => workflow.authenticatedStatus === "PASS");
  for (const [label, status] of [
    ["deterministic gates", values.deterministicStatus],
    ["impact analysis", values.impact.status],
    ["changed mutation", values.mutation.status],
    ["critical workflow evidence", workflowStatus],
  ]) {
    if (!["passed", "not-applicable"].includes(status)) reasons.push(`${label}: ${status}`);
  }
  if (values.profile === "release" && values.blackBoxUi.status !== "passed") {
    reasons.push(`black-box UI: ${values.blackBoxUi.status}`);
  }
  if (values.liveQualification.status !== "passed" || !allAuthenticatedPassed) {
    reasons.push(`authenticated live qualification: ${values.liveQualification.status}`);
  }
  if (values.findings.status === "failed") reasons.push("finding input: failed");
  if (values.profile === "release" && values.findings.status !== "passed") {
    reasons.push(`finding input: ${values.findings.status}`);
  }
  if (values.findings.releaseBlocking > 0) {
    reasons.push(`open release-blocking findings: ${values.findings.releaseBlocking}`);
  }
  if (values.findings.deterministicReleaseBlocking > 0) {
    reasons.push(
      `deterministic release-blocking findings: ${values.findings.deterministicReleaseBlocking}`
    );
  }

  const authenticatedLaneStatus = values.findings.liveReleaseBlocking > 0
    && values.workflowCoverage.some(workflow => workflow.authenticatedStatus === "FAIL")
    ? "failed"
    : values.findings.liveReleaseBlocking > 0
      && values.liveQualification.status === "passed"
      ? "blocked"
      : values.liveQualification.status;

  const hardStatuses = [
    values.deterministicStatus,
    values.impact.status,
    values.mutation.status,
    values.profile === "fast" ? "not-applicable" : workflowStatus,
    values.profile === "release" ? values.blackBoxUi.status : "not-applicable",
    values.liveQualification.status === "failed" ? "failed" : "not-applicable",
    values.findings.status,
    values.findings.deterministicReleaseBlocking > 0 ? "failed" : "not-applicable",
    authenticatedLaneStatus === "failed" ? "failed" : "not-applicable",
  ];
  let status = hardStatuses.includes("failed") ? "failed" : "passed";
  if (status === "passed" && (
    reasons.length > 0
    || values.liveQualification.status !== "passed"
    || !allAuthenticatedPassed
  )) {
    status = "blocked";
  }
  return {
    status,
    deterministicStatus: values.deterministicStatus,
    criticalWorkflowStatus: workflowStatus,
    deterministicLane: {
      status: aggregateStatuses([
        values.deterministicStatus,
        values.impact.status,
        values.mutation.status,
        values.profile === "fast" ? "not-applicable" : workflowStatus,
        values.findings.status,
        values.findings.deterministicReleaseBlocking > 0 ? "failed" : "not-applicable",
      ]),
      signedOutBlackBoxUi: values.profile === "release"
        ? values.blackBoxUi.status
        : "not-applicable",
    },
    authenticatedLiveLane: {
      status: authenticatedLaneStatus,
      requiredWorkflowCount: requiredAuthenticated.length,
      passedWorkflowCount: requiredAuthenticated.filter(workflow => (
        workflow.authenticatedStatus === "PASS"
      )).length,
      allRequiredPassed: allAuthenticatedPassed,
    },
    authenticatedAcceptance: values.liveQualification.authenticatedAcceptance,
    verdict: status === "passed" ? values.liveQualification.verdict : null,
    reasons: uniqueSorted(reasons),
  };
}

function loadReportInputs(options = {}) {
  const root = options.root || ROOT;
  const profile = options.profile || "full";
  const source = options.source || sourceIdentity(root);
  const manifest = readJson("package.json", root);
  const plan = getGatePlan(profile);
  const workflows = readJson("quality/critical-workflows.json", root);
  const receipts = plan.map(step => readOptionalRepositoryJson(receiptPath({
    profile,
    sequence: step.sequence,
    stepId: step.id,
  }), root, ".quality/gates")).filter(Boolean);
  const findingsPath = options.findingsPath || DEFAULT_FINDINGS;
  let findings = [];
  let findingsStatus = "not-run";
  let findingsErrors = [];
  let findingsTarget = null;
  let findingsFingerprint = null;
  try {
    findingsTarget = resolveOptionalRepositoryFile(findingsPath, root, {
      subtree: "internal_docs/quality",
    });
  } catch (error) {
    findingsStatus = "failed";
    findingsErrors = [error.message];
  }
  if (findingsTarget) {
    try {
      const findingsBytes = readBoundedFindingsBytes(findingsTarget);
      findingsFingerprint = crypto.createHash("sha256").update(findingsBytes).digest("hex");
      findings = parseFindingsJsonl(decodeFindingsBytes(findingsBytes));
      if (findings.length === 0) throw new Error("Findings ledger must not be empty.");
      findingsErrors = validateFindings(
        findings,
        readJson("quality/finding.schema.json", root),
        readJson("quality/defect-taxonomy.json", root),
        root
      );
      findingsStatus = findingsErrors.length === 0 ? "passed" : "failed";
    } catch (error) {
      findingsStatus = "failed";
      findingsErrors = [error.message];
    }
  }
  const mutationArtifact = readOptionalRepositoryJsonArtifact(
    ".quality/mutation/summary-changed.json",
    root,
    ".quality/mutation"
  ) || readOptionalRepositoryJsonArtifact(
    ".quality/mutation/summary-core.json",
    root,
    ".quality/mutation"
  );
  const liveArtifact = profile === "release"
    ? readOptionalRepositoryJsonArtifact(
      DEFAULT_LIVE_STATUS,
      root,
      ".quality/gates"
    )
    : null;
  const uiArtifact = profile === "release"
    ? readOptionalRepositoryJsonArtifact(
      DEFAULT_UI_RESULT,
      root,
      ".quality/ui"
    )
    : null;
  const candidateArtifact = profile === "release"
    ? readOptionalRepositoryJsonArtifact(
      DEFAULT_CANDIDATE_RECEIPT,
      root,
      ".quality/qualification"
    )
    : null;
  const impactArtifact = readOptionalRepositoryJsonArtifact(
    ".quality/impact.json",
    root,
    ".quality"
  );
  return {
    root,
    source,
    profile,
    plan,
    receipts,
    impact: impactArtifact?.value || null,
    impactArtifactFingerprint: impactArtifact?.fingerprint || null,
    mutation: mutationArtifact?.value || null,
    mutationArtifactFingerprint: mutationArtifact?.fingerprint || null,
    mutationBaseline: readJson("quality/mutation-baseline.json", root),
    ui: uiArtifact?.value || null,
    uiArtifactFingerprint: uiArtifact?.fingerprint || null,
    uiArtifacts: profile === "release" ? discoverUiArtifacts(root) : [],
    candidateReceipt: candidateArtifact?.value || null,
    extensionId: `${manifest.publisher}.${manifest.name}`,
    extensionVersion: manifest.version,
    liveQualification: liveArtifact?.value || null,
    liveQualificationArtifactFingerprint: liveArtifact?.fingerprint || null,
    findings,
    findingsFingerprint,
    findingsStatus,
    findingsErrors,
    workflows,
    inventories: require(path.join(root, "test", "testInventories.js")),
  };
}

function readOptionalRepositoryJson(relativePath, root, subtree) {
  const target = resolveOptionalRepositoryFile(relativePath, root, { subtree });
  return target ? JSON.parse(fs.readFileSync(target, "utf8")) : null;
}

function readOptionalRepositoryJsonArtifact(relativePath, root, subtree) {
  const target = resolveOptionalRepositoryFile(relativePath, root, { subtree });
  if (!target) return null;
  const bytes = fs.readFileSync(target);
  return {
    value: JSON.parse(bytes.toString("utf8")),
    fingerprint: crypto.createHash("sha256").update(bytes).digest("hex"),
  };
}

function discoverUiArtifacts(root) {
  return discoverRepositoryOutputFiles(".quality/ui", root, { subtree: ".quality/ui" })
    .filter(file => file !== DEFAULT_UI_RESULT);
}

function writeReport(report, options = {}) {
  const root = options.root || ROOT;
  const jsonOutput = options.jsonOutput || DEFAULT_JSON_OUTPUT;
  const markdownOutput = options.markdownOutput || DEFAULT_MARKDOWN_OUTPUT;
  writeJson(jsonOutput, report, root);
  writeText(markdownOutput, renderMarkdown(report), root);
  return { jsonOutput, markdownOutput };
}

function renderMarkdown(report) {
  const liveCandidate = report.liveQualification.candidate;
  const lines = [
    "# Quality report",
    "",
    `Source SHA: \`${report.source.sha}\`  `,
    `Source fingerprint: \`${report.source.fingerprint}\`  `,
    `Report fingerprint: \`${report.key.fingerprint}\``,
    "",
    "## Release readiness",
    "",
    `Status: **${report.releaseReadiness.status.toUpperCase()}**  `,
    `Deterministic lane: **${report.releaseReadiness.deterministicLane.status.toUpperCase()}**  `,
    `Authenticated live lane: **${report.releaseReadiness.authenticatedLiveLane.status.toUpperCase()}**  `,
    `Authenticated acceptance: **${report.releaseReadiness.authenticatedAcceptance}**  `,
    `Verdict: ${report.releaseReadiness.verdict || "none"}`,
    "",
  ];
  if (report.releaseReadiness.reasons.length > 0) {
    lines.push(...report.releaseReadiness.reasons.map(reason => `- ${reason}`), "");
  }
  lines.push(
    "## Impact",
    "",
    `Status: **${report.impact.status.toUpperCase()}**`,
    "",
    `Impacted workflows: ${report.impact.workflows.join(", ") || "none recorded"}  `,
    `Risk categories: ${report.impact.riskCategories.join(", ") || "none recorded"}`,
    "",
    "## Critical workflow evidence",
    "",
    "| Workflow | Impacted | Deterministic | Authenticated | Required layers |",
    "| --- | --- | --- | --- | --- |",
    ...report.workflowCoverage.map(workflow => (
      `| ${workflow.id} | ${workflow.impacted ? "yes" : "no"} | ${workflow.deterministicStatus} | ${workflow.authenticatedStatus} | ${workflow.requiredLayers.join(", ")} |`
    )),
    "",
    "## WebView interaction evidence",
    "",
    `Synthetic host-message composition: Extension Host wiring only (${report.webviewInteractionEvidence.syntheticHostMessage.status}); it does not prove visible interaction.  `,
    `Rendered DOM activation: ${report.webviewInteractionEvidence.renderedDomActivation.status.toUpperCase()} (black-box visible interaction).`,
    "",
    "## Extension Host execution evidence",
    "",
    `Deterministic host composition: ${report.extensionHostExecutionEvidence.classification} in a real VS Code host. Packaged-candidate activation is independently covered by the signed-out black-box UI lane.  `,
    `Credential boundary: ${report.extensionHostExecutionEvidence.credentialBoundary}.`,
    "",
    "## Gate receipts",
    "",
    "| Step | Category | Status | Passing count |",
    "| --- | --- | --- | ---: |",
    ...report.deterministicGates.steps.map(step => (
      `| ${step.stepId} | ${step.category} | ${step.status} | ${step.testCounts?.passing ?? "—"} |`
    )),
    "",
    "## Mutation",
    "",
    `Status: **${report.mutation.status.toUpperCase()}**  `,
    `Targets: ${report.mutation.targets.join(", ") || "none"}  `,
    `Killed / survived / timeout: ${formatCount(report.mutation.killed)} / ${formatCount(report.mutation.survived)} / ${formatCount(report.mutation.timeout)}  `,
    `Score: ${report.mutation.score === null ? "not recorded" : `${report.mutation.score}%`}`,
    "",
    "## Black-box UI",
    "",
    `Status: **${report.blackBoxUi.status.toUpperCase()}**  `,
    `VS Code: ${report.blackBoxUi.vscodeVersion || "not recorded"}  `,
    `Failure artifacts: ${report.blackBoxUi.failureArtifacts.join(", ") || "none"}`,
    "",
    "## Authenticated candidate binding",
    "",
    `Receipt fingerprint: ${liveCandidate?.receiptFingerprint || "not recorded"}  `,
    `VSIX SHA-256: ${liveCandidate?.vsixSha256 || "not recorded"}  `,
    `Extension: ${liveCandidate
      ? `${liveCandidate.extensionId}@${liveCandidate.extensionVersion}`
      : "not recorded"}  `,
    `Installed identity: ${liveCandidate
      ? `${liveCandidate.installedExtensionId}@${liveCandidate.installedExtensionVersion}`
      : "not recorded"}  `,
    `Source: ${liveCandidate
      ? `${liveCandidate.sourceSha}/${liveCandidate.sourceFingerprint}`
      : "not recorded"}  `,
    `Profile identity: ${liveCandidate
      ? `${liveCandidate.profileMode}/${liveCandidate.profileRootIdentity}`
      : "not recorded"}`,
    "",
    "## Authenticated live workflow matrix",
    "",
    "| Workflow | Status |",
    "| --- | --- |",
    ...report.liveQualification.workflowMatrix.map(row => `| ${row.id} | ${row.status} |`),
    "",
    "## Findings",
    "",
    `Input status: **${report.findings.status.toUpperCase()}**  `,
    `Open: ${report.findings.open}  `,
    `Closed: ${report.findings.closed}  `,
    `Release-blocking: ${report.findings.releaseBlocking}  `,
    `Deterministic blockers: ${report.findings.deterministicReleaseBlocking}  `,
    `Authenticated-live blockers: ${report.findings.liveReleaseBlocking}`,
    "",
    `By domain: ${formatCounts(report.findings.counts.byDomain)}  `,
    `By severity: ${formatCounts(report.findings.counts.bySeverity)}  `,
    `By deterministic status: ${formatCounts(report.findings.counts.byDeterministicStatus)}  `,
    `By live status: ${formatCounts(report.findings.counts.byLiveStatus)}`,
    "",
  );
  for (const error of report.findings.errors) lines.push(`- Finding input error: ${error}`);
  if (report.findings.errors.length > 0) lines.push("");
  for (const finding of report.findings.releaseBlockers) {
    lines.push(`- ${finding.id}: ${finding.severity} ${finding.surface} (${finding.status})`);
  }
  if (report.findings.releaseBlockers.length > 0) lines.push("");
  return `${lines.join("\n")}\n`;
}

function formatCount(value) {
  return value === null ? "not recorded" : String(value);
}

function formatCounts(value) {
  return Object.entries(value || {}).map(([key, count]) => `${key}=${count}`).join(", ");
}

function integerOrNull(value) {
  return Number.isInteger(value) ? value : null;
}

function parseArguments(argv) {
  const options = { profile: "full" };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--gate-profile") options.profile = argv[++index];
    else if (argument.startsWith("--gate-profile=")) options.profile = argument.slice(15);
    else if (argument === "--findings") options.findingsPath = argv[++index];
    else if (argument.startsWith("--findings=")) options.findingsPath = argument.slice(11);
    else throw new Error(`Unknown quality-report option: ${String(argument)}`);
  }
  if (!["fast", "full", "release"].includes(options.profile)) {
    throw new Error("Report gate profile must be fast, full, or release.");
  }
  return options;
}

function main() {
  try {
    const arguments_ = parseArguments(process.argv.slice(2));
    const inputs = loadReportInputs(arguments_);
    const report = generateReport(inputs);
    writeReport(report, { root: inputs.root });
    console.log(`Quality report: ${report.status} (${report.key.fingerprint}).`);
    if (hasDeterministicReportFailure(report)) process.exitCode = 1;
  } catch (error) {
    console.error(`quality:report: ${error.message}`);
    process.exitCode = 1;
  }
}

function hasDeterministicReportFailure(report) {
  if (report.status === "failed") return true;
  if (!["passed", "not-applicable"].includes(report.impact?.status)) return true;
  if (report.gateProfile !== "fast"
    && !["passed", "not-applicable"].includes(report.mutation?.status)) return true;
  if (["failed", "blocked", "not-run"].includes(report.deterministicGates?.status)) return true;
  if (report.findings?.status === "failed") return true;
  if ((report.findings?.deterministicReleaseBlocking || 0) > 0) return true;
  return false;
}

if (require.main === module) main();

module.exports = {
  DEFAULT_FINDINGS,
  DEFAULT_JSON_OUTPUT,
  DEFAULT_MARKDOWN_OUTPUT,
  UI_BLOCKED_REASON,
  discoverUiArtifacts,
  expectedBlackBoxUiTests,
  generateReport,
  hasDeterministicReportFailure,
  loadReportInputs,
  normalizeGateReceipt,
  parseArguments,
  parseFindingsJsonl,
  renderMarkdown,
  summarizeFindings,
  validateUiResult,
  validateImpactArtifact,
  validateFindingRecord,
  validateFindings,
  writeReport,
};

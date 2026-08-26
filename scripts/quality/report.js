// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const {
  ROOT,
  discoverRepositoryOutputFiles,
  isPlainObject,
  readJson,
  requireNonEmptyString,
  resolveExistingRepositoryFile,
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
const { validateMutationSummary } = require("./run-mutation");

const DEFAULT_JSON_OUTPUT = ".quality/report.json";
const DEFAULT_MARKDOWN_OUTPUT = ".quality/report.md";
const DEFAULT_FINDINGS = "internal_docs/quality/findings.jsonl";
const DEFAULT_LIVE_STATUS = ".quality/gates/live-qualification-status.json";
const DEFAULT_UI_RESULT = ".quality/ui/result.json";
const TERMINAL_FINDING_STATUSES = new Set(["fixed", "closed-non-issue"]);

function generateReport(options = {}) {
  const source = options.source;
  const profile = options.profile || "full";
  const plan = options.plan || getGatePlan(profile);
  const receipts = normalizeGateReceipts(options.receipts || [], plan, source);
  const receiptById = new Map(receipts.map(receipt => [receipt.stepId, receipt]));
  const deterministicReceipts = receipts.filter(receipt => ![
    "black-box-ui-smoke",
    "quality-report",
    "release-checklist",
  ].includes(receipt.stepId));
  const deterministicStatus = aggregateStatuses(
    deterministicReceipts.map(receipt => receipt.status)
  );
  const impact = summarizeImpact(options.impact, source);
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
    options.uiArtifacts || []
  );
  const liveQualification = summarizeLiveQualification(options.liveQualification, source, {
    artifactFingerprint: options.liveQualificationArtifactFingerprint,
    requireChecklistReceipt: profile === "release",
    checklistReceipt: receiptById.get("release-checklist"),
  });
  const findings = summarizeFindings(
    options.findings || [],
    options.findingsStatus || "passed",
    options.findingsErrors || []
  );
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
    schemaVersion: 1,
    source,
    gateProfile: profile,
    status: releaseReadiness.status,
    releaseReadiness,
    impact,
    deterministicGates: {
      status: deterministicStatus,
      steps: receipts.filter(receipt => receipt.stepId !== "quality-report"),
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
  const integrityErrors = [];
  if (!EVIDENCE_STATUSES.includes(receipt.status)) integrityErrors.push("invalid-status");
  if (receipt.command !== step.command) integrityErrors.push("command-mismatch");
  if (receipt.source?.sha !== source.sha
    || receipt.source?.fingerprint !== source.fingerprint) {
    integrityErrors.push("source-mismatch");
  }
  if (receipt.status === "passed" && receipt.exitCode !== 0) {
    integrityErrors.push("nonzero-command-claimed-pass");
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
  if (["passed", "blocked"].includes(receipt.status) && step.artifactPath
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

function summarizeImpact(impact, source) {
  if (!impact) {
    return {
      status: "not-run",
      workflows: [],
      actions: [],
      requiredLayers: [],
      commands: [],
      riskCategories: [],
      unmappedRuntimeFiles: [],
      analysisKey: null,
    };
  }
  const errors = validateImpactArtifact(impact);
  let status = errors.length > 0 || impact.ok === false ? "failed" : "passed";
  if (impact.source?.sha !== source.sha
    || impact.source?.fingerprint !== source.fingerprint) status = "blocked";
  return {
    status,
    workflows: uniqueSorted(impact.workflows || []),
    actions: uniqueSorted(impact.actions || []),
    requiredLayers: uniqueSorted(impact.requiredLayers || []),
    commands: uniqueSorted(impact.commands || []),
    riskCategories: uniqueSorted(impact.riskCategories || []),
    unmappedRuntimeFiles: uniqueSorted(impact.unmappedRuntimeFiles || []),
    analysisKey: impact.analysisKey || null,
    errors,
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

function summarizeUi(gateReceipt, ui, source, artifacts) {
  if (!gateReceipt) return emptyUi("not-run", artifacts);
  if (ui?.status === "blocked" && gateReceipt.status === "blocked") {
    return {
      ...emptyUi("blocked", artifacts),
      reason: ui.reason || gateReceipt.reason || null,
    };
  }
  if (gateReceipt.status !== "passed") {
    return {
      ...emptyUi(gateReceipt.status, artifacts),
      reason: ui?.reason || gateReceipt.reason || null,
    };
  }
  if (!ui) return emptyUi("failed", artifacts, "UI command passed without a result artifact.");
  let status = EVIDENCE_STATUSES.includes(ui.status) ? ui.status : "failed";
  if (ui.source?.sha !== source.sha
    || ui.source?.fingerprint !== source.fingerprint) status = "blocked";
  return {
    status,
    tool: ui.tool || null,
    toolVersion: ui.toolVersion || null,
    vscodeVersion: ui.vscodeVersion || null,
    platform: ui.platform || null,
    architecture: ui.architecture || null,
    declaredTests: uniqueSorted(ui.tests || []),
    failureArtifacts: status === "passed" ? [] : uniqueSorted(artifacts),
    reason: ui.reason || null,
  };
}

function emptyUi(status, artifacts = [], reason = null) {
  return {
    status,
    tool: null,
    toolVersion: null,
    vscodeVersion: null,
    platform: null,
    architecture: null,
    declaredTests: [],
    failureArtifacts: status === "passed" ? [] : uniqueSorted(artifacts),
    reason,
  };
}

function summarizeLiveQualification(value, source, options = {}) {
  let summary;
  if (!value) {
    summary = emptyLiveQualification("not-run");
  } else {
    const artifactErrors = validateDerivedLiveStatus(value);
    let status = EVIDENCE_STATUSES.includes(value.status) ? value.status : "failed";
    if (artifactErrors.length > 0) status = "failed";
    else if (value.source?.sha !== source.sha
      || value.source?.fingerprint !== source.fingerprint) status = "blocked";
    const passedWorkflowIds = status === "passed"
      ? uniqueSorted(value.passedWorkflowIds || [])
      : [];
    const requiredWorkflowIds = uniqueSorted(value.requiredWorkflowIds || []);
    summary = {
      status,
      authenticatedAcceptance: status === "passed"
        ? value.authenticatedAcceptance
        : "not-recorded",
      verdict: status === "passed" ? value.verdict : null,
      requiredWorkflowIds,
      passedWorkflowIds,
      missingWorkflowIds: requiredWorkflowIds.filter(id => !passedWorkflowIds.includes(id)),
      visibleEnabledActions: value.visibleEnabledActions || {
        status: "not-run",
        silentNoOpCount: null,
      },
      errors: uniqueSorted([...(value.errors || []), ...artifactErrors]),
    };
  }
  if (!options.requireChecklistReceipt) return summary;
  return bindLiveQualificationToChecklist(
    summary,
    options.checklistReceipt,
    options.artifactFingerprint
  );
}

function validateDerivedLiveStatus(value) {
  const errors = [];
  const exactKeys = [
    "authenticatedAcceptance", "errors", "inputPath", "missingWorkflowIds",
    "passedWorkflowIds", "reason", "requiredWorkflowIds", "schemaVersion",
    "source", "status", "verdict", "visibleEnabledActions",
  ];
  if (!isPlainObject(value)) return ["Live status artifact must be an object."];
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(exactKeys)) {
    errors.push("Live status artifact fields do not match schemaVersion 1.");
  }
  if (value.schemaVersion !== 1) errors.push("Live status artifact schemaVersion must be 1.");
  if (!isPlainObject(value.source)
    || JSON.stringify(Object.keys(value.source).sort()) !== JSON.stringify(["fingerprint", "sha"])
    || !/^[a-f0-9]{40}$/u.test(value.source?.sha || "")
    || !/^[a-f0-9]{64}$/u.test(value.source?.fingerprint || "")) {
    errors.push("Live status artifact has invalid source identity.");
  }
  if (typeof value.inputPath !== "string"
    || !/^internal_docs\/quality\/[A-Za-z0-9._-]+\.json$/u.test(value.inputPath)) {
    errors.push("Live status artifact has an invalid input path.");
  }
  if (!["passed", "failed", "blocked", "not-run"].includes(value.status)) {
    errors.push("Live status artifact has an invalid status.");
  }
  for (const field of ["requiredWorkflowIds", "passedWorkflowIds", "missingWorkflowIds"]) {
    if (!Array.isArray(value[field])
      || value[field].some(id => !/^WF-[A-Z0-9-]+$/u.test(id))
      || JSON.stringify(value[field]) !== JSON.stringify(uniqueSorted(value[field]))) {
      errors.push(`Live status artifact has invalid ${field}.`);
    }
  }
  const expectedMissing = (value.requiredWorkflowIds || [])
    .filter(id => !(value.passedWorkflowIds || []).includes(id));
  if (JSON.stringify(value.missingWorkflowIds) !== JSON.stringify(expectedMissing)) {
    errors.push("Live status artifact missingWorkflowIds do not reconcile.");
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
      || (value.passedWorkflowIds || []).length !== (value.requiredWorkflowIds || []).length
      || value.visibleEnabledActions?.status !== "passed"
      || value.visibleEnabledActions?.silentNoOpCount !== 0
      || (value.errors || []).length !== 0) {
      errors.push("Passed live status artifact is internally inconsistent.");
    }
  } else if (value.authenticatedAcceptance !== "not-recorded"
    || value.verdict !== null || (value.passedWorkflowIds || []).length !== 0) {
    errors.push("Non-passing live status artifact claims authenticated acceptance.");
  }
  return uniqueSorted(errors);
}

function emptyLiveQualification(status) {
  return {
    status,
    authenticatedAcceptance: "not-recorded",
    verdict: null,
    requiredWorkflowIds: [],
    passedWorkflowIds: [],
    missingWorkflowIds: [],
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
    passedWorkflowIds: [],
    missingWorkflowIds: [...summary.requiredWorkflowIds],
    visibleEnabledActions: { status: "not-run", silentNoOpCount: null },
    errors: uniqueSorted([...summary.errors, error]),
  };
}

function summarizeFindings(findings, inputStatus, errors = []) {
  const normalized = findings.map(finding => ({
    id: finding.id,
    severity: finding.severity,
    status: finding.status,
    workflowContract: finding.workflowContract,
    surface: finding.surface,
    releaseBlocking: finding.releaseBlocking === true,
  })).sort((left, right) => String(left.id).localeCompare(String(right.id)));
  const open = normalized.filter(finding => !TERMINAL_FINDING_STATUSES.has(finding.status));
  const blockers = open.filter(finding => finding.releaseBlocking);
  return {
    status: inputStatus,
    total: normalized.length,
    open: open.length,
    releaseBlocking: blockers.length,
    releaseBlockers: blockers,
    errors: uniqueSorted(errors),
  };
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
  const livePassed = new Set(options.liveQualification.status === "passed"
    ? options.liveQualification.passedWorkflowIds
    : []);
  const inventories = options.inventories || {};
  return (options.workflows?.workflows || []).map(workflow => {
    const layers = Object.fromEntries((workflow.requiredLayers || []).map(layer => [
      layer,
      workflowLayerStatus(workflow, layer, options, inventories, livePassed),
    ]));
    return {
      id: workflow.id,
      criticality: workflow.criticality,
      surface: workflow.surface,
      impacted: impacted.has(workflow.id),
      authoritativeOutcome: workflow.authoritativeOutcome,
      requiredLayers: [...(workflow.requiredLayers || [])],
      layerStatuses: layers,
      status: aggregateStatuses(Object.values(layers)),
    };
  }).sort((left, right) => left.id.localeCompare(right.id));
}

function workflowLayerStatus(workflow, layer, options, inventories, livePassed) {
  if (layer === "live-protocol") {
    if (livePassed.has(workflow.id)) return "passed";
    return options.liveQualification.status === "passed"
      ? "failed"
      : options.liveQualification.status;
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
    .map(workflow => workflow.status));
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
  if (values.liveQualification.status !== "passed") {
    reasons.push(`authenticated live qualification: ${values.liveQualification.status}`);
  }
  if (values.findings.status === "failed") reasons.push("finding input: failed");
  if (values.profile === "release" && values.findings.status !== "passed") {
    reasons.push(`finding input: ${values.findings.status}`);
  }
  if (values.findings.releaseBlocking > 0) {
    reasons.push(`open release-blocking findings: ${values.findings.releaseBlocking}`);
  }

  const hardStatuses = [
    values.deterministicStatus,
    values.impact.status,
    values.mutation.status,
    workflowStatus,
    values.profile === "release" ? values.blackBoxUi.status : "not-applicable",
    values.liveQualification.status === "failed" ? "failed" : "not-applicable",
    values.findings.status,
  ];
  let status = hardStatuses.includes("failed") ? "failed" : "passed";
  if (status === "passed" && (reasons.length > 0 || values.liveQualification.status !== "passed")) {
    status = "blocked";
  }
  return {
    status,
    deterministicStatus: values.deterministicStatus,
    criticalWorkflowStatus: workflowStatus,
    authenticatedAcceptance: values.liveQualification.authenticatedAcceptance,
    verdict: status === "passed" ? values.liveQualification.verdict : null,
    reasons: uniqueSorted(reasons),
  };
}

function loadReportInputs(options = {}) {
  const root = options.root || ROOT;
  const profile = options.profile || "full";
  const source = options.source || sourceIdentity(root);
  const plan = getGatePlan(profile);
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
      findings = parseFindingsJsonl(fs.readFileSync(findingsTarget, "utf8"));
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
  const liveArtifact = readOptionalRepositoryJsonArtifact(
    DEFAULT_LIVE_STATUS,
    root,
    ".quality/gates"
  );
  return {
    root,
    source,
    profile,
    plan,
    receipts,
    impact: readOptionalRepositoryJson(".quality/impact.json", root, ".quality"),
    mutation: mutationArtifact?.value || null,
    mutationArtifactFingerprint: mutationArtifact?.fingerprint || null,
    mutationBaseline: readJson("quality/mutation-baseline.json", root),
    ui: readOptionalRepositoryJson(DEFAULT_UI_RESULT, root, ".quality/ui"),
    uiArtifacts: discoverUiArtifacts(root),
    liveQualification: liveArtifact?.value || null,
    liveQualificationArtifactFingerprint: liveArtifact?.fingerprint || null,
    findings,
    findingsStatus,
    findingsErrors,
    workflows: readJson("quality/critical-workflows.json", root),
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

function parseFindingsJsonl(source) {
  const findings = [];
  const lines = String(source).split(/\r?\n/u);
  for (let index = 0; index < lines.length; index += 1) {
    if (!lines[index].trim()) continue;
    try {
      findings.push(JSON.parse(lines[index]));
    } catch (error) {
      throw new Error(`Invalid finding JSON on line ${index + 1}: ${error.message}`);
    }
  }
  return findings;
}

function validateFindings(findings, schema, taxonomy, root = ROOT) {
  const errors = [];
  const ids = new Set();
  findings.forEach((finding, index) => {
    errors.push(...validateFindingRecord(finding, schema, taxonomy, index + 1, root));
    if (!requireNonEmptyString(finding?.id)) return;
    if (ids.has(finding.id)) errors.push(`Duplicate finding ID: ${finding.id}.`);
    ids.add(finding.id);
  });
  return uniqueSorted(errors);
}

function validateFindingRecord(finding, schema, taxonomy, line = 1, root = ROOT) {
  const errors = [];
  const label = requireNonEmptyString(finding?.id) ? finding.id : `line ${line}`;
  if (!isPlainObject(finding)) return [`Finding ${label} must be an object.`];
  validateSchemaValue(finding, schema, `Finding ${label}`, errors);
  const allowed = new Set(Object.keys(schema?.properties || {}));
  for (const key of Object.keys(finding)) {
    if (!allowed.has(key)) errors.push(`Finding ${label} has unknown field ${key}.`);
  }
  for (const key of schema?.required || []) {
    if (!Object.prototype.hasOwnProperty.call(finding, key)) {
      errors.push(`Finding ${label} is missing required field ${key}.`);
    }
  }
  if (!(new RegExp(taxonomy?.idPattern || "a^")).test(finding.id || "")) {
    errors.push(`Finding ${label} has an invalid ID.`);
  }
  if (!Object.prototype.hasOwnProperty.call(taxonomy?.severities || {}, finding.severity)) {
    errors.push(`Finding ${label} has invalid severity ${String(finding.severity)}.`);
  }
  if (!(taxonomy?.statuses || []).includes(finding.status)) {
    errors.push(`Finding ${label} has invalid status ${String(finding.status)}.`);
  }
  if (!Array.isArray(finding.failureClasses)
    || finding.failureClasses.length === 0
    || new Set(finding.failureClasses).size !== finding.failureClasses.length) {
    errors.push(`Finding ${label} must declare unique failure classes.`);
  } else {
    for (const failureClass of finding.failureClasses) {
      if (!(taxonomy?.failureClasses || []).includes(failureClass)) {
        errors.push(`Finding ${label} has invalid failure class ${String(failureClass)}.`);
      }
    }
  }
  validateNestedEvidenceStatus(
    finding.mutationProof,
    schema?.properties?.mutationProof?.properties?.status?.enum,
    "mutation proof",
    label,
    errors
  );
  validateNestedEvidenceStatus(
    finding.liveVerification,
    schema?.properties?.liveVerification?.properties?.status?.enum,
    "live verification",
    label,
    errors
  );
  if (typeof finding.releaseBlocking !== "boolean") {
    errors.push(`Finding ${label} must declare boolean releaseBlocking.`);
  }
  const terminalFix = finding.status === "fixed";
  const pendingFix = finding.status === "fixed-pending-verification";
  if (["P0", "P1"].includes(finding.severity)
    && !terminalFix
    && finding.status !== "closed-non-issue"
    && finding.releaseBlocking !== true) {
    errors.push(`Finding ${label} ${finding.severity} must remain release blocking until fixed.`);
  }
  if (finding.severity === "P3" && finding.releaseBlocking !== false) {
    errors.push(`Finding ${label} P3 must not be release blocking.`);
  }
  if (terminalFix || pendingFix) {
    if (!requireNonEmptyString(finding.regressionTest)) {
      errors.push(`Finding ${label} fixed lifecycle requires a regression test.`);
    }
    if (finding.rootCauseStatus !== "proven") {
      errors.push(`Finding ${label} fixed lifecycle requires proven root cause.`);
    }
    if (!/^[a-f0-9]{7,40}$/u.test(finding.fixedSha || "")) {
      errors.push(`Finding ${label} fixed lifecycle requires a fixed SHA.`);
    } else if (!isAncestorCommit(root, finding.fixedSha)) {
      errors.push(`Finding ${label} fixed SHA is not an ancestor of the current candidate.`);
    }
    if (!["mutation-killed", "not-applicable"].includes(finding.mutationProof?.status)) {
      errors.push(`Finding ${label} fixed lifecycle requires completed mutation proof.`);
    }
  }
  if (terminalFix) {
    if (!["live-pass", "not-applicable"].includes(finding.liveVerification?.status)) {
      errors.push(`Finding ${label} cannot be fixed without completed live verification.`);
    }
    if (finding.releaseBlocking !== false) {
      errors.push(`Finding ${label} fixed lifecycle must clear releaseBlocking.`);
    }
  }
  for (const evidence of finding.evidence || []) {
    if (!["test", "source", "log", "screenshot"].includes(evidence?.kind)) continue;
    const reference = String(evidence.location || "").replace(/:(?:\d+)(?::\d+)?$/u, "");
    if (!safeExistingEvidencePath(root, reference)) {
      errors.push(`Finding ${label} evidence path is missing or unsafe: ${String(evidence.location)}.`);
    }
  }
  return errors;
}

function validateSchemaValue(value, schema, label, errors) {
  if (!isPlainObject(schema)) {
    errors.push(`${label} has no valid schema.`);
    return;
  }
  const types = Array.isArray(schema.type) ? schema.type : schema.type ? [schema.type] : [];
  if (types.length > 0 && !types.some(type => schemaTypeMatches(value, type))) {
    errors.push(`${label} has invalid type.`);
    return;
  }
  if (Array.isArray(schema.enum)
    && !schema.enum.some(candidate => JSON.stringify(candidate) === JSON.stringify(value))) {
    errors.push(`${label} must match its declared enum.`);
  }
  if (typeof value === "string") {
    if (Number.isInteger(schema.minLength) && value.length < schema.minLength) {
      errors.push(`${label} is shorter than ${schema.minLength}.`);
    }
    if (Number.isInteger(schema.maxLength) && value.length > schema.maxLength) {
      errors.push(`${label} is longer than ${schema.maxLength}.`);
    }
    if (schema.pattern && !(new RegExp(schema.pattern, "u")).test(value)) {
      errors.push(`${label} does not match its declared pattern.`);
    }
  }
  if (Array.isArray(value)) {
    if (Number.isInteger(schema.minItems) && value.length < schema.minItems) {
      errors.push(`${label} has fewer than ${schema.minItems} items.`);
    }
    if (schema.uniqueItems === true
      && new Set(value.map(item => JSON.stringify(item))).size !== value.length) {
      errors.push(`${label} must contain unique items.`);
    }
    if (schema.items) {
      value.forEach((item, index) => validateSchemaValue(item, schema.items, `${label}[${index}]`, errors));
    }
  }
  if (isPlainObject(value)) {
    const properties = schema.properties || {};
    for (const key of schema.required || []) {
      if (!Object.prototype.hasOwnProperty.call(value, key)) {
        errors.push(`${label} is missing required field ${key}.`);
      }
    }
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!Object.prototype.hasOwnProperty.call(properties, key)) {
          errors.push(`${label} has unknown field ${key}.`);
        }
      }
    }
    for (const [key, child] of Object.entries(properties)) {
      if (Object.prototype.hasOwnProperty.call(value, key)) {
        validateSchemaValue(value[key], child, `${label}.${key}`, errors);
      }
    }
  }
}

function schemaTypeMatches(value, type) {
  if (type === "null") return value === null;
  if (type === "object") return isPlainObject(value);
  if (type === "array") return Array.isArray(value);
  if (type === "string") return typeof value === "string";
  if (type === "boolean") return typeof value === "boolean";
  if (type === "integer") return Number.isInteger(value);
  if (type === "number") return Number.isFinite(value);
  return false;
}

function isAncestorCommit(root, sha) {
  const exists = spawnSync("git", ["cat-file", "-e", `${sha}^{commit}`], { cwd: root });
  if (exists.error || exists.signal || exists.status !== 0) return false;
  const ancestor = spawnSync("git", ["merge-base", "--is-ancestor", sha, "HEAD"], { cwd: root });
  return !ancestor.error && !ancestor.signal && ancestor.status === 0;
}

function safeExistingEvidencePath(root, reference) {
  if (!requireNonEmptyString(reference)) return false;
  try {
    resolveExistingRepositoryFile(reference, root);
    return true;
  } catch {
    return false;
  }
}

function validateNestedEvidenceStatus(value, allowedStatuses, field, label, errors) {
  if (!isPlainObject(value)
    || !(allowedStatuses || []).includes(value.status)
    || typeof value.summary !== "string") {
    errors.push(`Finding ${label} has invalid ${field}.`);
  }
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
    "| Workflow | Impacted | Status | Required layers |",
    "| --- | --- | --- | --- |",
    ...report.workflowCoverage.map(workflow => (
      `| ${workflow.id} | ${workflow.impacted ? "yes" : "no"} | ${workflow.status} | ${workflow.requiredLayers.join(", ")} |`
    )),
    "",
    "## WebView interaction evidence",
    "",
    `Synthetic host-message composition: Extension Host wiring only (${report.webviewInteractionEvidence.syntheticHostMessage.status}); it does not prove visible interaction.  `,
    `Rendered DOM activation: ${report.webviewInteractionEvidence.renderedDomActivation.status.toUpperCase()} (black-box visible interaction).`,
    "",
    "## Extension Host execution evidence",
    "",
    `Production activation: ${report.extensionHostExecutionEvidence.classification} in a real VS Code host; the production manifest is not host-managed or installed by qualification.  `,
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
    "## Findings",
    "",
    `Input status: **${report.findings.status.toUpperCase()}**  `,
    `Open: ${report.findings.open}  `,
    `Release-blocking: ${report.findings.releaseBlocking}`,
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
  return false;
}

if (require.main === module) main();

module.exports = {
  DEFAULT_FINDINGS,
  DEFAULT_JSON_OUTPUT,
  DEFAULT_MARKDOWN_OUTPUT,
  discoverUiArtifacts,
  generateReport,
  hasDeterministicReportFailure,
  loadReportInputs,
  normalizeGateReceipt,
  parseArguments,
  parseFindingsJsonl,
  renderMarkdown,
  summarizeFindings,
  validateImpactArtifact,
  validateFindingRecord,
  validateFindings,
  writeReport,
};

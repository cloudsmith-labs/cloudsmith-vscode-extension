// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const {
  ROOT,
  readJson,
  resolveOptionalRepositoryFile,
  uniqueSorted,
  writeJson,
} = require("./common");
const { sourceIdentity } = require("./evidence");
const {
  decodeFindingsBytes,
  decodeUtf8Bytes,
  deriveReleaseBlocking,
  isClosedFinding,
  parseFindingsJsonl,
  readBoundedFindingsBytes,
  validateFindings,
} = require("./findings");
const {
  AUTHENTICATED_CANDIDATE_ARTIFACT,
  AUTHENTICATED_CANDIDATE_RECEIPT,
  LIVE_CANDIDATE_ARTIFACT,
  LIVE_CANDIDATE_RECEIPT,
  candidateBindingFromReceipt,
  validateAuthenticatedExecutionReceipt,
  validateCandidateBinding,
  validateEquivalentCandidateProduct,
} = require("./candidate-binding");
const { captureRepositoryState } = require("./prepare-qualification");
const {
  AUTHENTICATED_EXPOSURE_RESULT,
  validateAuthenticatedExposureProof,
} = require("./authenticated-exposure-scan");

const DEFAULT_INPUT = "internal_docs/quality/live-qualification.json";
const DEFAULT_OUTPUT = ".quality/gates/live-qualification-status.json";
const DEFAULT_FINDINGS = "internal_docs/quality/findings.jsonl";
const DEFAULT_AUTHENTICATED_RECEIPT = ".quality/qualification/authenticated-ci.json";
const READY_VERDICTS = new Set([
  "TEAM-TEST READY",
  "TEAM-TEST READY WITH KNOWN NON-BLOCKING RISKS",
]);
const DECLARED_STATUSES = new Set(["passed", "failed", "partial", "blocked", "not-run"]);
const WORKFLOW_RESULT_STATUSES = new Set(["PASS", "FAIL", "PARTIAL", "BLOCKED"]);
const EVIDENCE_PATH_PATTERN = /^internal_docs\/quality\/[A-Za-z0-9][A-Za-z0-9._-]*\.(?:json|jsonl|md|png|txt|webp)$/u;
const EVIDENCE_MAX_BYTES = 16 * 1024 * 1024;
const MAX_QUALIFICATION_AGE_MS = 24 * 60 * 60 * 1000;
const OPEN_BLOCKER_ERROR = "Live qualification must explicitly record zero open release blockers.";

function requiredLiveWorkflowIds(workflowsDocument) {
  return uniqueSorted((workflowsDocument?.workflows || [])
    .filter(workflow => workflow.liveFixture?.required === true)
    .map(workflow => workflow.id));
}

function evaluateLiveQualification(options = {}) {
  const source = options.source;
  const workflows = options.workflows;
  const requiredIds = requiredLiveWorkflowIds(workflows);
  const document = options.document;
  const inputPath = options.inputPath || DEFAULT_INPUT;
  const attestationFingerprint = document
    ? options.attestationFingerprint || null
    : null;
  const findingsState = options.findingsState || readFindingsState(
    options.root || ROOT,
    options.findingsPath || DEFAULT_FINDINGS
  );
  const evidenceManifest = document
    ? qualificationEvidenceManifest(document)
    : /^[a-f0-9]{64}$/u.test(findingsState.fingerprint || "")
      ? [{ path: DEFAULT_FINDINGS, sha256: findingsState.fingerprint }]
      : [];
  const workflowMatrix = normalizedWorkflowMatrix(document?.workflowResults, requiredIds);
  const validationContext = createValidationContext({ ...options, findingsState });
  if (!document) {
    return statusDocument({
      source,
      inputPath,
      status: findingsState.errors.length === 0 ? "not-run" : "failed",
      requiredIds,
      workflowMatrix,
      findingsState,
      attestationFingerprint,
      evidenceManifest,
      reason: "No ignored authenticated live-qualification attestation was supplied.",
      errors: findingsState.errors,
    });
  }

  const declaredStatus = document.status;
  if (!DECLARED_STATUSES.has(declaredStatus)) {
    return statusDocument({
      source,
      inputPath,
      status: "failed",
      requiredIds,
      workflowMatrix,
      findingsState,
      attestationFingerprint,
      evidenceManifest,
      errors: ["Live qualification status must be passed, failed, partial, blocked, or not-run."],
    });
  }
  if (declaredStatus !== "passed") {
    const candidateValidation = validateAttestationCandidate(
      document,
      source,
      validationContext
    );
    const errors = validateNonPassingAttestation(
      document,
      source,
      workflows,
      requiredIds,
      validationContext,
      candidateValidation,
    );
    return statusDocument({
      source,
      inputPath,
      status: errors.length === 0 ? declaredStatus : "failed",
      requiredIds,
      workflowMatrix,
      findingsState,
      attestationFingerprint,
      evidenceManifest,
      candidate: candidateValidation.binding,
      errors,
      reason: nonEmpty(document.summary)
        ? document.summary
        : `Authenticated live qualification is declared ${declaredStatus}.`,
    });
  }

  const candidateValidation = validateAttestationCandidate(
    document,
    source,
    validationContext
  );
  const errors = validatePassedAttestation(
    document,
    source,
    workflows,
    requiredIds,
    validationContext,
    candidateValidation,
  );
  const results = Array.isArray(document.workflowResults) ? document.workflowResults : [];
  const passedIds = uniqueSorted(results
    .filter(result => result.status === "PASS"
      && result.authoritativeOutcomeObserved === true
      && evidenceReferenceArray(result.evidence))
    .map(result => result.id));
  const blockedByOpenFindings = errors.length === 1 && errors[0] === OPEN_BLOCKER_ERROR;
  return statusDocument({
    source,
    inputPath,
    status: errors.length === 0 ? "passed" : blockedByOpenFindings ? "blocked" : "failed",
    requiredIds,
    workflowMatrix,
    passedIds,
    errors,
    verdict: errors.length === 0 ? document.verdict : null,
    authenticatedAcceptance: errors.length === 0 ? "recorded" : "not-recorded",
    findingsState,
    attestationFingerprint,
    evidenceManifest,
    candidate: candidateValidation.binding,
    visibleEnabledActions: {
      status: document.visibleEnabledActions?.status || "not-run",
      silentNoOpCount: Number.isInteger(document.visibleEnabledActions?.silentNoOpCount)
        ? document.visibleEnabledActions.silentNoOpCount
        : null,
    },
    reason: blockedByOpenFindings
      ? "Open release blockers prevent authenticated acceptance."
      : null,
  });
}

function validateNonPassingAttestation(
  document,
  source,
  workflows,
  requiredIds,
  context,
  candidateValidation = validateAttestationCandidate(document, source, context),
) {
  const errors = [...candidateValidation.errors];
  validateAttestationEnvelope(document, source, errors, context);
  if (!nonEmpty(document.summary)) {
    errors.push("A non-passing live qualification must include a sanitized summary.");
  }
  if (document.authenticatedAcceptance !== false) {
    errors.push("A non-passing live qualification cannot attest authenticated acceptance.");
  }
  if (typeof document.checklistConfirmed !== "boolean") {
    errors.push("A non-passing live qualification must explicitly record checklist confirmation.");
  }
  if (document.verdict !== null) {
    errors.push("A non-passing live qualification cannot declare a release verdict.");
  }
  const completedAt = validateTimestamp(
    document.completedAt,
    "Live qualification completion",
    errors,
    { now: context.nowMs }
  );
  if (Number.isFinite(completedAt)
    && context.nowMs - completedAt > MAX_QUALIFICATION_AGE_MS) {
    errors.push("Live qualification completion is older than the 24-hour release window.");
  }
  const evidenceNotBefore = Number.isFinite(completedAt)
    ? completedAt - MAX_QUALIFICATION_AGE_MS
    : null;
  const evidencePaths = validateEvidenceReferences(
    document.evidence,
    "Live qualification",
    errors,
    context,
    { notAfter: completedAt, notBefore: evidenceNotBefore }
  );
  if (!evidencePaths.has(DEFAULT_FINDINGS)) {
    errors.push("Live qualification evidence must include the exact findings ledger.");
  }
  validateWorkflowResults(
    document.workflowResults,
    workflows,
    requiredIds,
    errors,
    context,
    completedAt,
    evidenceNotBefore,
    evidencePaths,
    { requirePass: false }
  );
  for (const [label, references] of [
    ["Visible enabled action qualification", document.visibleEnabledActions?.evidence],
    ["Independent release review", document.independentReview?.evidence],
  ]) {
    if (references === undefined) continue;
    const optionalPaths = validateEvidenceReferences(
      references,
      label,
      errors,
      context,
      { notAfter: context.nowMs, notBefore: evidenceNotBefore }
    );
    for (const evidencePath of optionalPaths) evidencePaths.add(evidencePath);
  }
  for (const error of context.findingsState.errors) errors.push(error);
  if (document.findingsFingerprint !== context.findingsState.fingerprint) {
    errors.push("Live qualification does not bind the exact findings ledger bytes.");
  }
  if (document.openReleaseBlockerCount !== context.findingsState.openReleaseBlockerCount) {
    errors.push("Live qualification release-blocker count does not match the findings ledger.");
  }
  const expectedStatus = derivedDeclaredStatus(document.workflowResults, requiredIds);
  if (document.status !== expectedStatus) {
    errors.push(`Live qualification status must reconcile to ${expectedStatus} from its workflow matrix.`);
  }
  return uniqueSorted(errors);
}

function validateAttestationCandidate(document, source, context) {
  const errors = [];
  const passResults = Array.isArray(document?.workflowResults)
    ? document.workflowResults.filter(result => result?.status === "PASS")
    : [];
  const candidateRequired = document?.status === "passed"
    || document?.authenticatedAcceptance === true
    || passResults.length > 0
    || document?.visibleEnabledActions?.status === "passed"
    || document?.independentReview?.status === "passed";
  if (document?.candidate === null || document?.candidate === undefined) {
    if (candidateRequired) {
      errors.push("Every live PASS must bind the exact qualification candidate.");
    }
    for (const result of passResults) {
      if (result?.candidateReceiptFingerprint !== null) {
        errors.push(`Live workflow ${String(result?.id)} has an unbound candidate receipt.`);
      }
    }
    return { binding: null, errors: uniqueSorted(errors) };
  }

  let binding = null;
  let expected = null;
  try {
    validateCandidateBinding(document.candidate);
    if (!context.liveCandidateReceipt) {
      throw new Error("Dedicated live candidate receipt is missing.");
    }
    if (!context.liveCandidateArtifactPath) {
      throw new Error("Dedicated live candidate VSIX proof is missing.");
    }
    expected = candidateBindingFromReceipt(context.liveCandidateReceipt, {
      root: context.root,
      source,
      artifactPath: context.liveCandidateArtifactPath,
      repositoryState: context.repositoryState,
      homeDirectory: context.qualificationHomeDirectory,
    });
    if (expected.profileMode !== "local") {
      throw new Error("Live attestation candidate must use the dedicated local profile.");
    }
    validateCandidateCaptureWindow(context.liveCandidateReceipt, document);
    validateCandidateBinding(document.candidate, expected);
    binding = Object.freeze({ ...expected });
  } catch (error) {
    errors.push(`Live qualification candidate proof is invalid: ${error.message}`);
  }

  const authenticatedProofRequired = document.status === "passed"
    || document.authenticatedAcceptance === true;
  if (authenticatedProofRequired && binding) {
    try {
      if (!context.authenticatedCandidateReceipt) {
        throw new Error("Authenticated-CI candidate receipt is missing.");
      }
      if (!context.authenticatedCandidateArtifactPath) {
        throw new Error("Authenticated-CI candidate VSIX proof is missing.");
      }
      const authenticatedCandidate = candidateBindingFromReceipt(
        context.authenticatedCandidateReceipt,
        {
          root: context.root,
          source,
          artifactPath: context.authenticatedCandidateArtifactPath,
        },
      );
      if (authenticatedCandidate.profileMode !== "ci") {
        throw new Error("Authenticated qualification candidate must use an ephemeral CI profile.");
      }
      validateCandidateCaptureWindow(context.authenticatedCandidateReceipt, document);
      validateEquivalentCandidateProduct(expected, authenticatedCandidate);
      if (!context.authenticatedReceipt) {
        throw new Error("Authenticated qualification receipt is missing.");
      }
      validateAuthenticatedExecutionReceipt(
        context.authenticatedReceipt,
        authenticatedCandidate,
        source,
      );
      if (!context.authenticatedExposureReceipt) {
        throw new Error("Authenticated exposure receipt is missing.");
      }
      validateAuthenticatedExposureProof(
        context.authenticatedExposureReceipt,
        context.authenticatedCandidateReceipt,
        source,
      );
    } catch (error) {
      errors.push(`Live qualification candidate proof is invalid: ${error.message}`);
    }
  }

  const receiptFingerprint = document.candidate?.receiptFingerprint;
  for (const result of document.workflowResults || []) {
    if (result?.status === "PASS"
      && result.candidateReceiptFingerprint !== receiptFingerprint) {
      errors.push(`Live workflow ${String(result?.id)} does not bind the exact candidate receipt.`);
    }
  }
  for (const [label, value] of [
    ["Visible enabled action qualification", document.visibleEnabledActions],
    ["Independent release review", document.independentReview],
  ]) {
    if (value?.status === "passed"
      && value.candidateReceiptFingerprint !== receiptFingerprint) {
      errors.push(`${label} does not bind the exact candidate receipt.`);
    }
  }
  return { binding, errors: uniqueSorted(errors) };
}

function validateCandidateCaptureWindow(receipt, document) {
  const candidateCapturedAt = Date.parse(receipt.capturedAt);
  const qualificationCompletedAt = Date.parse(document.completedAt);
  if (Number.isFinite(qualificationCompletedAt)
    && (candidateCapturedAt > qualificationCompletedAt
      || qualificationCompletedAt - candidateCapturedAt > MAX_QUALIFICATION_AGE_MS)) {
    throw new Error(
      "Qualification candidate capture does not precede completion within the 24-hour window."
    );
  }
}

function validateAttestationEnvelope(document, source, errors, context) {
  const exactKeys = [
    "authenticatedAcceptance", "candidate", "checklistConfirmed", "completedAt", "evidence",
    "findingsFingerprint", "independentReview", "openReleaseBlockerCount", "operatorId",
    "schemaVersion", "source", "status", "summary", "verdict", "visibleEnabledActions",
    "workflowResults",
  ];
  if (!isPlainObject(document)
    || JSON.stringify(Object.keys(document).sort()) !== JSON.stringify(exactKeys)) {
    errors.push("Live qualification fields do not match schemaVersion 5.");
  }
  if (document.schemaVersion !== 5) errors.push("Live qualification schemaVersion must be 5.");
  if (!isPlainObject(document.source)
    || JSON.stringify(Object.keys(document.source).sort())
      !== JSON.stringify(["fingerprint", "sha"])) {
    errors.push("Live qualification source identity fields are invalid.");
  }
  if (!(document.visibleEnabledActions === null
    || (isPlainObject(document.visibleEnabledActions)
      && Object.keys(document.visibleEnabledActions).sort().join(",")
        === "candidateReceiptFingerprint,evidence,silentNoOpCount,status"))) {
    errors.push("Live qualification visible-action fields are not value-blind.");
  }
  if (!(document.independentReview === null
    || (isPlainObject(document.independentReview)
      && Object.keys(document.independentReview).sort().join(",")
        === "attestationSha256,candidateReceiptFingerprint,evidence,reviewedAt,reviewerId,source,status"))) {
    errors.push("Live qualification independent-review fields are not value-blind.");
  }
  if (document.source?.sha !== source.sha) {
    errors.push("Live qualification source SHA does not match the current candidate.");
  }
  if (document.source?.fingerprint !== source.fingerprint) {
    errors.push("Live qualification source fingerprint does not match the current candidate.");
  }
  if (!validIdentity(document.operatorId)) {
    errors.push("Live qualification must identify the qualification operator.");
  }
  if (!Number.isFinite(context.nowMs)) errors.push("Live qualification validation time is invalid.");
}

function validatePassedAttestation(
  document,
  source,
  workflows,
  requiredIds,
  context = createValidationContext(),
  candidateValidation = validateAttestationCandidate(document, source, context),
) {
  const errors = [...candidateValidation.errors];
  validateAttestationEnvelope(document, source, errors, context);
  if (document.authenticatedAcceptance !== true) {
    errors.push("Authenticated acceptance was not explicitly attested.");
  }
  if (document.checklistConfirmed !== true) {
    errors.push("The release checklist was not explicitly confirmed.");
  }
  if (document.summary !== null) {
    errors.push("A passed live qualification must not carry a non-passing summary.");
  }
  const completedAt = validateTimestamp(
    document.completedAt,
    "Live qualification completion",
    errors,
    { now: context.nowMs },
  );
  if (Number.isFinite(completedAt)
    && context.nowMs - completedAt > MAX_QUALIFICATION_AGE_MS) {
    errors.push("Live qualification completion is older than the 24-hour release window.");
  }
  const evidenceNotBefore = Number.isFinite(completedAt)
    ? completedAt - MAX_QUALIFICATION_AGE_MS
    : null;
  if (!READY_VERDICTS.has(document.verdict)) {
    errors.push("Live qualification has no allowed team-test readiness verdict.");
  }
  if (Number.isInteger(context.findingsState.openNonBlockingRiskCount)) {
    const expectedVerdict = context.findingsState.openNonBlockingRiskCount > 0
      ? "TEAM-TEST READY WITH KNOWN NON-BLOCKING RISKS"
      : "TEAM-TEST READY";
    if (document.verdict !== expectedVerdict) {
      errors.push(
        "Live qualification verdict does not match the current open non-blocking findings."
      );
    }
  }
  const evidencePaths = validateEvidenceReferences(
    document.evidence,
    "Live qualification",
    errors,
    context,
    { notAfter: completedAt, notBefore: evidenceNotBefore },
  );
  if (!evidencePaths.has(DEFAULT_FINDINGS)) {
    errors.push("Live qualification evidence must include the exact findings ledger.");
  }
  for (const error of context.findingsState.errors) errors.push(error);
  if (document.findingsFingerprint !== context.findingsState.fingerprint) {
    errors.push("Live qualification does not bind the exact findings ledger bytes.");
  }
  if (document.openReleaseBlockerCount !== context.findingsState.openReleaseBlockerCount) {
    errors.push("Live qualification release-blocker count does not match the findings ledger.");
  }
  if (document.openReleaseBlockerCount !== 0) {
    errors.push(OPEN_BLOCKER_ERROR);
  }
  validateWorkflowResults(
    document.workflowResults,
    workflows,
    requiredIds,
    errors,
    context,
    completedAt,
    evidenceNotBefore,
    evidencePaths,
    { requirePass: true },
  );
  validateVisibleActions(
    document.visibleEnabledActions,
    errors,
    context,
    completedAt,
    evidenceNotBefore,
    evidencePaths,
  );
  validateIndependentReview(
    document.independentReview,
    document,
    source,
    errors,
    context,
    completedAt,
    evidencePaths,
  );
  return uniqueSorted(errors);
}

function validateWorkflowResults(
  results,
  workflows,
  requiredIds,
  errors,
  context,
  completedAt,
  evidenceNotBefore,
  evidencePaths,
  options = {},
) {
  if (!Array.isArray(results)) {
    errors.push("Live qualification must contain workflowResults.");
    return;
  }
  const knownIds = new Set((workflows?.workflows || []).map(workflow => workflow.id));
  const required = new Set(requiredIds);
  const seen = new Set();
  for (const result of results) {
    if (!knownIds.has(result?.id)) errors.push(`Live qualification references unknown workflow ${String(result?.id)}.`);
    else if (!required.has(result?.id)) {
      errors.push(`Live qualification includes non-required workflow ${String(result?.id)}.`);
    }
    if (seen.has(result?.id)) errors.push(`Live qualification repeats workflow ${String(result?.id)}.`);
    seen.add(result?.id);
    if (!isPlainObject(result)
      || Object.keys(result).sort().join(",")
        !== "authoritativeOutcomeObserved,candidateReceiptFingerprint,evidence,id,status") {
      errors.push(`Live workflow ${String(result?.id)} fields do not match the workflow-result schema.`);
    }
    if (!WORKFLOW_RESULT_STATUSES.has(result?.status)) {
      errors.push(`Live workflow ${String(result?.id)} has an invalid matrix status.`);
    }
    if (options.requirePass && result?.status !== "PASS") {
      errors.push(`Live workflow ${String(result?.id)} is not PASS.`);
    }
    if (result?.status === "PASS" && result?.authoritativeOutcomeObserved !== true) {
      errors.push(`Live workflow ${String(result?.id)} lacks an authoritative-outcome attestation.`);
    }
    if (typeof result?.authoritativeOutcomeObserved !== "boolean") {
      errors.push(`Live workflow ${String(result?.id)} must record authoritativeOutcomeObserved.`);
    }
    if (!(result?.candidateReceiptFingerprint === null
      || /^[a-f0-9]{64}$/u.test(result?.candidateReceiptFingerprint || ""))) {
      errors.push(`Live workflow ${String(result?.id)} has an invalid candidate receipt fingerprint.`);
    }
    const resultPaths = validateEvidenceReferences(
      result?.evidence,
      `Live workflow ${String(result?.id)}`,
      errors,
      context,
      { notAfter: completedAt, notBefore: evidenceNotBefore },
    );
    for (const evidencePath of resultPaths) evidencePaths.add(evidencePath);
  }
  for (const id of requiredIds) {
    if (!seen.has(id)) errors.push(`Required live workflow ${id} has no qualification result.`);
  }
}

function normalizedWorkflowMatrix(results, requiredIds) {
  const byId = new Map();
  if (Array.isArray(results)) {
    for (const result of results) {
      if (!requiredIds.includes(result?.id) || byId.has(result.id)) continue;
      byId.set(result.id, WORKFLOW_RESULT_STATUSES.has(result.status) ? result.status : "BLOCKED");
    }
  }
  return requiredIds.map(id => Object.freeze({
    id,
    status: byId.get(id) || "BLOCKED",
  }));
}

function derivedDeclaredStatus(results, requiredIds) {
  const statuses = normalizedWorkflowMatrix(results, requiredIds).map(result => result.status);
  if (statuses.includes("FAIL")) return "failed";
  if (statuses.includes("PARTIAL")) return "partial";
  if (statuses.includes("BLOCKED")) return "blocked";
  return "passed";
}

function validateVisibleActions(
  value,
  errors,
  context,
  completedAt,
  evidenceNotBefore,
  evidencePaths,
) {
  if (!isPlainObject(value)
    || Object.keys(value).sort().join(",")
      !== "candidateReceiptFingerprint,evidence,silentNoOpCount,status") {
    errors.push("Visible enabled action fields do not match the evidence schema.");
  }
  if (value?.status !== "passed") {
    errors.push("Visible enabled actions were not completely qualified.");
  }
  if (value?.silentNoOpCount !== 0) {
    errors.push("Visible enabled actions do not explicitly record zero silent no-ops.");
  }
  if (!/^[a-f0-9]{64}$/u.test(value?.candidateReceiptFingerprint || "")) {
    errors.push("Visible enabled actions do not bind a candidate receipt.");
  }
  const actionPaths = validateEvidenceReferences(
    value?.evidence,
    "Visible enabled action qualification",
    errors,
    context,
    { notAfter: completedAt, notBefore: evidenceNotBefore },
  );
  for (const evidencePath of actionPaths) evidencePaths.add(evidencePath);
}

function validateIndependentReview(
  value,
  document,
  source,
  errors,
  context,
  completedAt,
  qualificationEvidencePaths,
) {
  if (!isPlainObject(value)
    || Object.keys(value).sort().join(",")
      !== "attestationSha256,candidateReceiptFingerprint,evidence,reviewedAt,reviewerId,source,status") {
    errors.push("Independent release review fields do not match the evidence schema.");
  }
  if (value?.status !== "passed") errors.push("Independent release review is not passed.");
  if (!/^[a-f0-9]{64}$/u.test(value?.candidateReceiptFingerprint || "")) {
    errors.push("Independent release review does not bind a candidate receipt.");
  }
  if (!validIdentity(value?.reviewerId)) {
    errors.push("Independent release review must identify its reviewer.");
  } else if (validIdentity(document.operatorId)
    && value.reviewerId.trim().toLowerCase() === document.operatorId.trim().toLowerCase()) {
    errors.push("Independent release reviewer must differ from the qualification operator.");
  }
  if (!isPlainObject(value?.source)
    || Object.keys(value.source).sort().join(",") !== "fingerprint,sha"
    || value.source.sha !== source.sha
    || value.source.fingerprint !== source.fingerprint) {
    errors.push("Independent release review does not bind the current candidate source.");
  }
  const reviewedAt = validateTimestamp(
    value?.reviewedAt,
    "Independent release review",
    errors,
    { now: context.nowMs, notBefore: completedAt },
  );
  if (value?.attestationSha256 !== attestationReviewDigest(document)) {
    errors.push("Independent release review does not bind the exact qualification attestation.");
  }
  const reviewEvidencePaths = validateEvidenceReferences(
    value?.evidence,
    "Independent release review",
    errors,
    context,
    { notBefore: completedAt, notAfter: reviewedAt },
  );
  if ([...reviewEvidencePaths].every(evidencePath => qualificationEvidencePaths.has(evidencePath))) {
    errors.push("Independent release review must reference separate review evidence.");
  }
}

function statusDocument(values) {
  const requiredIds = values.requiredIds || [];
  const workflowMatrix = values.workflowMatrix || normalizedWorkflowMatrix([], requiredIds);
  const passedIds = values.passedIds || workflowMatrix
    .filter(result => result.status === "PASS")
    .map(result => result.id);
  return {
    schemaVersion: 3,
    source: values.source,
    candidate: values.candidate || null,
    inputPath: values.inputPath,
    status: values.status,
    authenticatedAcceptance: values.authenticatedAcceptance || "not-recorded",
    verdict: values.verdict || null,
    requiredWorkflowIds: requiredIds,
    passedWorkflowIds: passedIds,
    missingWorkflowIds: requiredIds.filter(id => !passedIds.includes(id)),
    workflowMatrix,
    attestationFingerprint: values.attestationFingerprint || null,
    evidenceManifest: values.evidenceManifest || [],
    findingsFingerprint: values.findingsState?.fingerprint || null,
    openReleaseBlockerCount: Number.isInteger(values.findingsState?.openReleaseBlockerCount)
      ? values.findingsState.openReleaseBlockerCount
      : null,
    visibleEnabledActions: values.visibleEnabledActions || {
      status: "not-run",
      silentNoOpCount: null,
    },
    reason: values.reason || null,
    errors: values.errors || [],
  };
}

function nonEmpty(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function evidenceReferenceArray(value) {
  return Array.isArray(value)
    && value.length > 0
    && value.every(reference => isPlainObject(reference));
}

function isPlainObject(value) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function validIdentity(value) {
  return typeof value === "string"
    && value === value.trim()
    && value.length > 0
    && value.length <= 200
    && !/[\u0000-\u001f\u007f]/u.test(value);
}

function createValidationContext(options = {}) {
  const now = options.now || new Date();
  const nowMs = now instanceof Date ? now.getTime() : Number.NaN;
  if (!Number.isFinite(nowMs)) throw new Error("Release-checklist validation time is invalid.");
  return {
    root: path.resolve(options.root || ROOT),
    nowMs,
    ignoredPathCache: new Map(),
    liveCandidateReceipt: options.liveCandidateReceipt || null,
    liveCandidateArtifactPath: options.liveCandidateArtifactPath || null,
    authenticatedReceipt: options.authenticatedReceipt || null,
    authenticatedExposureReceipt: options.authenticatedExposureReceipt || null,
    authenticatedCandidateReceipt: options.authenticatedCandidateReceipt || null,
    authenticatedCandidateArtifactPath: options.authenticatedCandidateArtifactPath || null,
    qualificationHomeDirectory: options.qualificationHomeDirectory,
    repositoryState: options.repositoryState || null,
    findingsState: options.findingsState || readFindingsState(
      options.root || ROOT,
      options.findingsPath || DEFAULT_FINDINGS
    ),
  };
}

function readFindingsState(root = ROOT, findingsPath = DEFAULT_FINDINGS) {
  let target;
  try {
    target = resolveOptionalRepositoryFile(findingsPath, root, {
      subtree: "internal_docs/quality",
    });
  } catch (error) {
    return {
      fingerprint: null,
      openReleaseBlockerCount: null,
      openNonBlockingRiskCount: null,
      errors: [error.message],
    };
  }
  if (!target) {
    return {
      fingerprint: null,
      openReleaseBlockerCount: null,
      openNonBlockingRiskCount: null,
      errors: ["The ignored findings ledger is missing."],
    };
  }
  let bytes;
  try {
    bytes = readBoundedFindingsBytes(target);
  } catch (error) {
    return {
      fingerprint: null,
      openReleaseBlockerCount: null,
      openNonBlockingRiskCount: null,
      errors: [error.message],
    };
  }
  const fingerprint = crypto.createHash("sha256").update(bytes).digest("hex");
  try {
    const records = parseFindingsJsonl(decodeFindingsBytes(bytes));
    if (records.length === 0) throw new Error("The ignored findings ledger is empty.");
    const validationErrors = validateFindings(
      records,
      readJson("quality/finding.schema.json", root),
      readJson("quality/defect-taxonomy.json", root),
      root
    );
    if (validationErrors.length > 0) {
      return {
        fingerprint,
        openReleaseBlockerCount: null,
        openNonBlockingRiskCount: null,
        errors: validationErrors.map(error => `The ignored findings ledger is invalid: ${error}`),
      };
    }
    const workflows = readJson("quality/critical-workflows.json", root);
    const workflowById = new Map((workflows?.workflows || []).map(workflow => [
      workflow.id,
      workflow,
    ]));
    const openRecords = records.filter(record => !isClosedFinding(record));
    return {
      fingerprint,
      openReleaseBlockerCount: openRecords.filter(record => (
        deriveReleaseBlocking(record, workflowById.get(record.workflowContract))
      )).length,
      openNonBlockingRiskCount: openRecords.filter(record => (
        !deriveReleaseBlocking(record, workflowById.get(record.workflowContract))
      )).length,
      errors: [],
    };
  } catch (error) {
    return {
      fingerprint,
      openReleaseBlockerCount: null,
      openNonBlockingRiskCount: null,
      errors: [`The ignored findings ledger is invalid: ${error.message}`],
    };
  }
}

function validateTimestamp(value, label, errors, bounds = {}) {
  const parsed = typeof value === "string" ? Date.parse(value) : Number.NaN;
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    errors.push(`${label} timestamp must be a canonical UTC ISO-8601 instant.`);
    return null;
  }
  if (Number.isFinite(bounds.now) && parsed > bounds.now) {
    errors.push(`${label} timestamp is in the future.`);
  }
  if (Number.isFinite(bounds.notBefore) && parsed < bounds.notBefore) {
    errors.push(`${label} timestamp predates the required event.`);
  }
  if (Number.isFinite(bounds.notAfter) && parsed > bounds.notAfter) {
    errors.push(`${label} timestamp postdates the required event.`);
  }
  return parsed;
}

function validateEvidenceReferences(value, label, errors, context, timeBounds = {}) {
  const paths = new Set();
  if (!Array.isArray(value) || value.length === 0) {
    errors.push(`${label} lacks hashed evidence references.`);
    return paths;
  }
  for (const [index, reference] of value.entries()) {
    const referenceLabel = `${label} evidence ${index + 1}`;
    if (!isPlainObject(reference)) {
      errors.push(`${referenceLabel} must be an evidence object.`);
      continue;
    }
    const fields = Object.keys(reference).sort();
    if (fields.join(",") !== "capturedAt,path,sha256") {
      errors.push(`${referenceLabel} fields do not match the evidence schema.`);
      continue;
    }
    validateTimestamp(reference.capturedAt, referenceLabel, errors, {
      now: context.nowMs,
      ...timeBounds,
    });
    if (!EVIDENCE_PATH_PATTERN.test(reference.path || "")
      || path.posix.normalize(reference.path) !== reference.path) {
      errors.push(`${referenceLabel} path is not a normalized ignored evidence path.`);
      continue;
    }
    if (paths.has(reference.path)) {
      errors.push(`${referenceLabel} repeats an evidence path.`);
      continue;
    }
    paths.add(reference.path);
    if (!/^[0-9a-f]{64}$/.test(reference.sha256 || "")) {
      errors.push(`${referenceLabel} has an invalid SHA-256.`);
      continue;
    }
    const target = validateEvidenceFile(reference.path, referenceLabel, errors, context);
    if (!target) continue;
    const actual = crypto.createHash("sha256").update(fs.readFileSync(target)).digest("hex");
    if (actual !== reference.sha256) {
      errors.push(`${referenceLabel} SHA-256 does not match the evidence file.`);
    }
  }
  return paths;
}

function validateEvidenceFile(relativePath, label, errors, context) {
  const segments = relativePath.split("/");
  let current = context.root;
  try {
    for (let index = 0; index < segments.length; index += 1) {
      current = path.join(current, segments[index]);
      const stats = fs.lstatSync(current);
      if (stats.isSymbolicLink()) {
        errors.push(`${label} path crosses a symbolic link.`);
        return null;
      }
      if (index < segments.length - 1 && !stats.isDirectory()) {
        errors.push(`${label} path has a non-directory ancestor.`);
        return null;
      }
      if (index === segments.length - 1
        && (!stats.isFile() || stats.size > EVIDENCE_MAX_BYTES)) {
        errors.push(`${label} is not a bounded regular evidence file.`);
        return null;
      }
    }
  } catch {
    errors.push(`${label} evidence file is missing or unreadable.`);
    return null;
  }

  const evidenceRoot = fs.realpathSync(path.join(context.root, "internal_docs", "quality"));
  const realTarget = fs.realpathSync(current);
  if (path.dirname(realTarget) !== evidenceRoot) {
    errors.push(`${label} path escapes the evidence directory.`);
    return null;
  }
  if (!isIgnoredEvidencePath(relativePath, context)) {
    errors.push(`${label} path is not ignored by Git.`);
    return null;
  }
  return realTarget;
}

function isIgnoredEvidencePath(relativePath, context) {
  if (!fs.existsSync(path.join(context.root, ".git"))) return true;
  if (context.ignoredPathCache.has(relativePath)) {
    return context.ignoredPathCache.get(relativePath);
  }
  const result = spawnSync("git", ["check-ignore", "--quiet", "--", relativePath], {
    cwd: context.root,
    stdio: "ignore",
  });
  const ignored = !result.error && !result.signal && result.status === 0;
  context.ignoredPathCache.set(relativePath, ignored);
  return ignored;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (isPlainObject(value)) {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]));
  }
  return value;
}

function attestationReviewDigest(document) {
  const payload = Object.fromEntries(
    Object.entries(document || {}).filter(([key]) => key !== "independentReview")
  );
  return crypto.createHash("sha256")
    .update(JSON.stringify(canonicalize(payload)))
    .digest("hex");
}

function qualificationEvidenceManifest(document) {
  const references = [
    ...(document?.evidence || []),
    ...(document?.workflowResults || []).flatMap(result => result?.evidence || []),
    ...(document?.visibleEnabledActions?.evidence || []),
    ...(document?.independentReview?.evidence || []),
  ];
  const byPath = new Map();
  for (const reference of references) {
    if (EVIDENCE_PATH_PATTERN.test(reference?.path || "")
      && /^[a-f0-9]{64}$/u.test(reference?.sha256 || "")) {
      byPath.set(reference.path, Object.freeze({
        path: reference.path,
        sha256: reference.sha256,
      }));
    }
  }
  return [...byPath.values()].sort((left, right) => left.path.localeCompare(right.path));
}

function loadLiveQualification(root, inputPath) {
  const target = resolveOptionalRepositoryFile(inputPath, root, {
    subtree: "internal_docs/quality",
  });
  if (!target) return null;
  const errors = [];
  const validatedTarget = validateEvidenceFile(
    inputPath,
    "Live qualification input",
    errors,
    createValidationContext({ root }),
  );
  if (!validatedTarget) {
    throw new Error(errors.join(" ") || "Live qualification input path is unsafe.");
  }
  if (validatedTarget !== target) {
    throw new Error("Live qualification input changed during path validation.");
  }
  const bytes = fs.readFileSync(target);
  return {
    document: JSON.parse(decodeUtf8Bytes(bytes, "Live qualification input")),
    fingerprint: crypto.createHash("sha256").update(bytes).digest("hex"),
  };
}

function loadQualificationJson(root, relativePath, subtree = ".quality/qualification") {
  const target = resolveOptionalRepositoryFile(relativePath, root, {
    subtree,
  });
  if (!target) return null;
  const stat = fs.lstatSync(target);
  if (stat.size <= 0 || stat.size > 1024 * 1024) {
    throw new Error(`Qualification proof is not a bounded regular file: ${relativePath}`);
  }
  return JSON.parse(decodeUtf8Bytes(fs.readFileSync(target), "Qualification proof"));
}

function evaluateDiskLiveQualification(options = {}) {
  const root = options.root || ROOT;
  const inputPath = options.inputPath || DEFAULT_INPUT;
  validateInputPath(inputPath);
  const loaded = loadLiveQualification(root, inputPath);
  const authenticatedProofRequired = loaded
    && (loaded.document?.status === "passed"
      || loaded.document?.authenticatedAcceptance === true);
  const liveCandidateReceipt = loaded
    ? loadQualificationJson(root, LIVE_CANDIDATE_RECEIPT)
    : null;
  const authenticatedReceipt = authenticatedProofRequired
    ? loadQualificationJson(root, DEFAULT_AUTHENTICATED_RECEIPT)
    : null;
  const authenticatedExposureReceipt = authenticatedProofRequired
    ? loadQualificationJson(root, AUTHENTICATED_EXPOSURE_RESULT, ".quality/secrets")
    : null;
  const authenticatedCandidateReceipt = authenticatedProofRequired
    ? loadQualificationJson(root, AUTHENTICATED_CANDIDATE_RECEIPT)
    : null;
  const liveCandidateArtifactPath = loaded
    ? resolveOptionalRepositoryFile(LIVE_CANDIDATE_ARTIFACT, root, {
      subtree: ".quality/qualification",
    })
    : null;
  const authenticatedCandidateArtifactPath = authenticatedProofRequired
    ? resolveOptionalRepositoryFile(AUTHENTICATED_CANDIDATE_ARTIFACT, root, {
      subtree: ".quality/qualification",
    })
    : null;
  const repositoryState = loaded
    ? captureRepositoryState(root, spawnSync, process.env)
    : null;
  return evaluateLiveQualification({
    source: options.source || sourceIdentity(root),
    workflows: options.workflows || readJson("quality/critical-workflows.json", root),
    document: loaded?.document || null,
    attestationFingerprint: loaded?.fingerprint || null,
    inputPath,
    now: options.now,
    root,
    liveCandidateReceipt,
    liveCandidateArtifactPath,
    authenticatedReceipt,
    authenticatedExposureReceipt,
    authenticatedCandidateReceipt,
    authenticatedCandidateArtifactPath,
    qualificationHomeDirectory: options.qualificationHomeDirectory,
    repositoryState,
  });
}

function runChecklist(options = {}) {
  const root = options.root || ROOT;
  const inputPath = options.inputPath || DEFAULT_INPUT;
  validateInputPath(inputPath);
  const outputPath = options.outputPath || DEFAULT_OUTPUT;
  if (Object.prototype.hasOwnProperty.call(options, "document")) {
    throw new Error("Release-checklist output requires an exact disk-backed attestation.");
  }
  const result = evaluateDiskLiveQualification({
    inputPath,
    now: options.now,
    source: options.source,
    workflows: options.workflows,
    qualificationHomeDirectory: options.qualificationHomeDirectory,
    root,
  });
  writeJson(outputPath, result, root);
  return result;
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--input") {
      if (index + 1 >= argv.length) throw new Error("--input requires a path.");
      options.inputPath = argv[++index];
    }
    else if (argv[index].startsWith("--input=")) options.inputPath = argv[index].slice(8);
    else throw new Error(`Unknown release-checklist option: ${String(argv[index])}`);
  }
  if (options.inputPath) validateInputPath(options.inputPath);
  return options;
}

function validateInputPath(inputPath) {
  if (typeof inputPath !== "string"
    || /[\u0000-\u001f\u007f\\]/u.test(inputPath)
    || path.posix.normalize(inputPath) !== inputPath
    || !/^internal_docs\/quality\/[A-Za-z0-9._-]+\.json$/u.test(inputPath)) {
    throw new Error(
      "Release-checklist input must be a normalized internal_docs/quality/*.json path."
    );
  }
  return inputPath;
}

function main() {
  try {
    const result = runChecklist(parseArguments(process.argv.slice(2)));
    console.log(`Authenticated live qualification: ${result.status}.`);
    if (["blocked", "partial", "not-run"].includes(result.status)) process.exitCode = 2;
    else if (result.status !== "passed") process.exitCode = 1;
  } catch (error) {
    console.error(`quality:release-checklist: ${error.message}`);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  DEFAULT_AUTHENTICATED_RECEIPT,
  AUTHENTICATED_EXPOSURE_RESULT,
  DEFAULT_FINDINGS,
  DEFAULT_INPUT,
  DEFAULT_OUTPUT,
  attestationReviewDigest,
  evaluateDiskLiveQualification,
  evaluateLiveQualification,
  parseArguments,
  readFindingsState,
  qualificationEvidenceManifest,
  requiredLiveWorkflowIds,
  runChecklist,
  normalizedWorkflowMatrix,
  validateInputPath,
  validateAttestationCandidate,
  validatePassedAttestation,
};

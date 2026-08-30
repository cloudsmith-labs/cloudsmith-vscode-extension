// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { fingerprint } = require("./evidence");

const TARGETS = new Set(["team-test", "release"]);
const DISPOSITIONS = new Set([
  "observed-current",
  "observed-historical",
  "inherited-unchanged",
  "verified-deterministic",
  "verified-extension-host",
  "verified-black-box",
  "verified-live",
  "not-required",
  "not-observable-with-current-fixtures",
  "not-authorized",
  "failed",
  "blocked",
]);
const SATISFYING_DISPOSITIONS = new Set([
  "observed-current",
  "inherited-unchanged",
  "verified-deterministic",
  "verified-extension-host",
  "verified-black-box",
  "verified-live",
]);
const INCOMPLETE_DISPOSITIONS = new Set([
  "not-observable-with-current-fixtures",
  "not-authorized",
]);

function policyFingerprint(policy) {
  return fingerprint(policy);
}

function buildTargetPolicy(trackedPolicy, workflowsDocument, target) {
  if (!TARGETS.has(target) || !trackedPolicy?.targets?.[target]) {
    throw new Error("Readiness target policy is unavailable.");
  }
  const targetPolicy = trackedPolicy.targets[target];
  const workflowRules = Object.fromEntries((workflowsDocument?.workflows || []).map(workflow => {
    const allowedIncompleteDispositions = [];
    if (target === "team-test" && workflow.id === trackedPolicy.pullThroughNotAuthorized?.workflowId) {
      allowedIncompleteDispositions.push({
        layer: "live-protocol",
        disposition: trackedPolicy.pullThroughNotAuthorized.disposition,
      });
    }
    if (target === "team-test" && workflow.id === "WF-INSTALL-GUIDANCE") {
      allowedIncompleteDispositions.push({
        layer: "live-protocol",
        disposition: trackedPolicy.fixtureUnavailable?.disposition,
      });
    }
    return [workflow.id, {
      requiredLayers: [...(workflow.requiredLayers || [])],
      formatContracts: (workflow.formatContracts || []).map(contract => contract.format).sort(),
      allowedIncompleteDispositions,
    }];
  }));
  return {
    target,
    trackedPolicyFingerprint: policyFingerprint(trackedPolicy),
    requiredLanes: [...targetPolicy.requiredLanes],
    waiverResult: targetPolicy.waiverResult,
    workflowRules,
  };
}

function validInheritance(claim) {
  // A caller-authored summary is never inheritance authority. The strict
  // content-addressed validator lives in candidate-lanes.js; schema v7 rejects
  // inherited claims until its independently anchored bundle is supplied at
  // the outer acceptance boundary.
  void claim;
  return false;
}

function sha256(value) {
  return /^[a-f0-9]{64}$/u.test(value || "");
}

function canonicalTimestamp(value) {
  const milliseconds = Date.parse(value);
  return typeof value === "string"
    && Number.isFinite(milliseconds)
    && new Date(milliseconds).toISOString() === value;
}

function validLaneCapture(capturedAt, completedAt, candidateCapturedAt = null) {
  if (!canonicalTimestamp(capturedAt) || !canonicalTimestamp(completedAt)) return false;
  const captured = Date.parse(capturedAt);
  const completed = Date.parse(completedAt);
  return captured <= completed
    && completed - captured <= 24 * 60 * 60 * 1000
    && (candidateCapturedAt === null || captured >= Date.parse(candidateCapturedAt));
}

function validWaiverProof(claim, bounds = {}) {
  const proof = claim?.waiverProof;
  if (!proof || proof.independentlyVerified !== true) return false;
  if (claim.disposition === "not-authorized") {
    return proof.kind === "candidate-bound-preflight"
      && sha256(proof.candidateReceiptFingerprint)
      && sha256(proof.preflightEvidenceSha256)
      && sha256(proof.finalConfirmationEvidenceSha256);
  }
  if (claim.disposition === "not-observable-with-current-fixtures") {
    const completedAt = Date.parse(bounds.completedAt);
    const expectedFormats = [...(bounds.requiredFormats || [])].sort();
    const submittedFormats = Array.isArray(proof.formats)
      ? proof.formats.map(item => item?.format).sort()
      : [];
    return proof.kind === "fixture-unavailable"
      && proof.authoritativeLowerLayersVerified === true
      && expectedFormats.length > 0
      && JSON.stringify(submittedFormats) === JSON.stringify(expectedFormats)
      && new Set(submittedFormats).size === submittedFormats.length
      && proof.formats.some(item => (
        item?.disposition === "not-observable-with-current-fixtures"
      ))
      && proof.formats.every(item => (
        item?.disposition === "observed-current"
          ? JSON.stringify(Object.keys(item).sort()) === JSON.stringify([
            "candidateReceiptFingerprint", "capturedAt", "disposition", "evidenceSha256",
            "format",
          ])
            && item.candidateReceiptFingerprint === claim.currentCandidateReceiptFingerprint
            && sha256(item.candidateReceiptFingerprint)
            && sha256(item.evidenceSha256)
            && validLaneCapture(
              item.capturedAt,
              bounds.completedAt,
              bounds.candidateCapturedAt || null,
            )
          : item?.disposition === "not-observable-with-current-fixtures"
            ? JSON.stringify(Object.keys(item).sort()) === JSON.stringify([
              "boundedCaptureAt", "disposition", "fixtureInventorySha256", "format", "query",
              "repository", "serviceAccess", "workspace",
            ])
              && typeof item.workspace === "string" && item.workspace.length > 0
              && typeof item.repository === "string" && item.repository.length > 0
              && typeof item.query === "string" && item.query.length > 0
              && item.serviceAccess === "verified"
              && canonicalTimestamp(item.boundedCaptureAt)
              && Number.isFinite(completedAt)
              && Date.parse(item.boundedCaptureAt) <= completedAt
              && completedAt - Date.parse(item.boundedCaptureAt) <= 24 * 60 * 60 * 1000
              && sha256(item.fixtureInventorySha256)
            : false
      ));
  }
  return false;
}

function reconcileWorkflowRow(result, rule, candidateReceiptFingerprint) {
  const errors = [];
  const requiredClaims = (rule?.requiredLayers || []).map(layer => (
    (result?.layerEvidence || []).find(claim => claim?.layer === layer)
  )).filter(Boolean);
  const incomplete = requiredClaims.filter(claim => INCOMPLETE_DISPOSITIONS.has(
    claim.disposition,
  ));
  const failed = requiredClaims.some(claim => claim.disposition === "failed");
  const blocked = requiredClaims.some(claim => claim.disposition === "blocked");
  const currentCandidateClaim = requiredClaims.some(claim => [
    "observed-current", "verified-black-box", "verified-live",
  ].includes(claim.disposition));

  if (incomplete.length > 0) {
    const expectedDisposition = incomplete[0].disposition === "not-authorized"
      ? "not-authorized"
      : "not-observable-with-current-fixtures";
    if (result.status !== "PARTIAL"
      || result.outcomeDisposition !== expectedDisposition
      || result.authoritativeOutcomeObserved !== false
      || result.candidateProvenance !== "verified"
      || result.candidateReceiptFingerprint !== candidateReceiptFingerprint) {
      errors.push(`Workflow ${result.id} contradicts its incomplete evidence disposition.`);
    }
  } else if (failed) {
    if (result.status !== "FAIL" || result.outcomeDisposition !== "failed"
      || result.authoritativeOutcomeObserved !== true
      || result.candidateProvenance !== "verified"
      || result.candidateReceiptFingerprint !== candidateReceiptFingerprint) {
      errors.push(`Workflow ${result.id} contradicts its failed evidence disposition.`);
    }
  } else if (blocked) {
    if (result.status !== "BLOCKED"
      || result.outcomeDisposition !== "blocked-by-defect"
      || result.authoritativeOutcomeObserved !== false) {
      errors.push(`Workflow ${result.id} contradicts its blocked evidence disposition.`);
    }
  } else if (requiredClaims.length === (rule?.requiredLayers || []).length) {
    if (result.status !== "PASS"
      || result.outcomeDisposition !== "complete"
      || result.authoritativeOutcomeObserved !== true) {
      errors.push(`Workflow ${result.id} contradicts its satisfying layer evidence.`);
    }
    if (currentCandidateClaim && (result.candidateProvenance !== "verified"
      || result.candidateReceiptFingerprint !== candidateReceiptFingerprint)) {
      errors.push(`Workflow ${result.id} has current evidence without current candidate provenance.`);
    }
  }
  return errors;
}

function evaluateAcceptance(input) {
  const errors = [];
  const gaps = [];
  const target = input?.target;
  const policy = input?.policy;
  if (!TARGETS.has(target) || policy?.target !== target) {
    errors.push("Acceptance target does not match its tracked target policy.");
  }

  const lanes = new Map();
  for (const lane of input?.lanes || []) {
    if (!lane?.id || lanes.has(lane.id)) {
      errors.push(`Acceptance lane ${String(lane?.id)} is invalid or repeated.`);
      continue;
    }
    lanes.set(lane.id, lane);
  }
  for (const laneId of policy?.requiredLanes || []) {
    const lane = lanes.get(laneId);
    if (lane && lane.validated !== true) {
      errors.push(`Required lane ${laneId} is not independently validated.`);
    } else if (!lane || lane.status !== "passed") {
      gaps.push(`required lane ${laneId} is ${lane?.status || "missing"}`);
    }
  }

  const workflows = new Map();
  for (const workflow of input?.workflows || []) {
    if (!workflow?.id || workflows.has(workflow.id)) {
      errors.push(`Acceptance workflow ${String(workflow?.id)} is invalid or repeated.`);
      continue;
    }
    workflows.set(workflow.id, workflow);
  }
  let usedIncompleteWaiver = false;
  for (const [workflowId, rule] of Object.entries(policy?.workflowRules || {})) {
    const workflow = workflows.get(workflowId);
    if (!workflow) {
      gaps.push(`required workflow ${workflowId} is missing`);
      continue;
    }
    const claimsByLayer = new Map();
    for (const claim of workflow.layerEvidence || []) {
      if (!claim?.layer || claimsByLayer.has(claim.layer)) {
        errors.push(`Workflow ${workflowId} has invalid or repeated layer evidence.`);
        continue;
      }
      if (!DISPOSITIONS.has(claim.disposition)) {
        errors.push(`Workflow ${workflowId} has invalid evidence disposition.`);
      }
      if (claim.disposition === "observed-historical" && claim.currentCandidateReceiptFingerprint) {
        errors.push(`Workflow ${workflowId} relabels historical evidence as current.`);
      }
      if (claim.disposition === "inherited-unchanged" && !validInheritance(claim)) {
        errors.push(`Workflow ${workflowId} has invalid inherited evidence.`);
      }
      if (INCOMPLETE_DISPOSITIONS.has(claim.disposition)
        && claim.authoritativeOutcomeObserved === true) {
        errors.push(`Workflow ${workflowId} launders an incomplete disposition as PASS.`);
      }
      claimsByLayer.set(claim.layer, claim);
    }
    for (const layer of rule.requiredLayers || []) {
      const claim = claimsByLayer.get(layer);
      if (!claim) {
        gaps.push(`workflow ${workflowId} lacks required ${layer} evidence`);
        continue;
      }
      if (claim.disposition === "failed") {
        errors.push(`Workflow ${workflowId} failed required ${layer} evidence.`);
      } else if (claim.disposition === "blocked") {
        gaps.push(`workflow ${workflowId} is blocked at ${layer}`);
      } else if (INCOMPLETE_DISPOSITIONS.has(claim.disposition)) {
        const waiver = (rule.allowedIncompleteDispositions || []).find(item => (
          item.disposition === claim.disposition && item.layer === layer
        ));
        const lowerLayersVerified = claim.disposition
          !== "not-observable-with-current-fixtures"
          || [...claimsByLayer.entries()].every(([otherLayer, otherClaim]) => (
            otherLayer === layer || !rule.requiredLayers.includes(otherLayer)
              || SATISFYING_DISPOSITIONS.has(otherClaim.disposition)
          ));
        if (waiver && (!validWaiverProof(claim, {
          completedAt: input.completedAt,
          candidateCapturedAt: input.candidateCapturedAt,
          requiredFormats: rule.formatContracts,
        })
          || !lowerLayersVerified)) {
          errors.push(`Workflow ${workflowId} has invalid ${claim.disposition} proof.`);
        } else if (!waiver) {
          gaps.push(`workflow ${workflowId} has incomplete required ${layer} evidence`);
        } else {
          usedIncompleteWaiver = true;
        }
      } else if (!SATISFYING_DISPOSITIONS.has(claim.disposition)) {
        gaps.push(`workflow ${workflowId} does not satisfy required ${layer} evidence`);
      }
    }
  }

  if (!Number.isInteger(input?.openReleaseBlockerCount)
    || input.openReleaseBlockerCount < 0) {
    errors.push("Acceptance release-blocker count is invalid.");
  } else if (input.openReleaseBlockerCount > 0) {
    gaps.push(`open release-blocking findings: ${input.openReleaseBlockerCount}`);
  }
  const status = errors.length > 0 ? "failed" : gaps.length > 0 ? "blocked" : "passed";
  const hasRisk = input.openNonBlockingRiskCount > 0 || usedIncompleteWaiver;
  return {
    status,
    verdict: target === "release" && status === "passed"
      ? null
      : status === "passed"
        ? (hasRisk ? "TEAM-TEST READY WITH RISKS" : "TEAM-TEST READY")
        : "NOT TEAM-TEST READY",
    errors: [...new Set(errors)].sort(),
    gaps: [...new Set(gaps)].sort(),
  };
}

module.exports = {
  DISPOSITIONS,
  buildTargetPolicy,
  evaluateAcceptance,
  policyFingerprint,
  reconcileWorkflowRow,
  validLaneCapture,
  validInheritance,
};

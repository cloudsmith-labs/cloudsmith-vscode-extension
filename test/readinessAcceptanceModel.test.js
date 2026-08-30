// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const {
  evaluateAcceptance,
  reconcileWorkflowRow,
  validLaneCapture,
  validInheritance,
} = require("../scripts/quality/readiness-acceptance");
const { releaseReadinessStatus } = require("../scripts/quality/report");

function acceptance(overrides = {}) {
  return {
    target: "team-test",
    policy: {
      target: "team-test",
      requiredLanes: ["remote-ci", "codeql", "authenticated-local"],
      workflowRules: {
        "WF-CONTRACT": {
          requiredLayers: ["contract", "extension-host"],
          allowedIncompleteDispositions: [],
        },
      },
    },
    lanes: [
      { id: "remote-ci", status: "passed", validated: true },
      { id: "codeql", status: "passed", validated: true },
      { id: "authenticated-local", status: "passed", validated: true },
    ],
    workflows: [{
      id: "WF-CONTRACT",
      layerEvidence: [
        { layer: "contract", disposition: "verified-deterministic" },
        { layer: "extension-host", disposition: "verified-extension-host" },
      ],
    }],
    openReleaseBlockerCount: 0,
    openNonBlockingRiskCount: 0,
    candidateCapturedAt: "2026-08-30T11:00:00.000Z",
    completedAt: "2026-08-30T13:00:00.000Z",
    ...overrides,
  };
}

suite("target-bound readiness acceptance", () => {
  test("rejects stale, future, and pre-candidate lane observations", () => {
    const completedAt = "2026-08-30T13:00:00.000Z";
    assert.strictEqual(validLaneCapture("2026-08-30T12:00:00.000Z", completedAt), true);
    assert.strictEqual(validLaneCapture("2026-08-29T12:59:59.000Z", completedAt), false);
    assert.strictEqual(validLaneCapture("2026-08-30T14:00:00.000Z", completedAt), false);
    assert.strictEqual(validLaneCapture(
      "2026-08-30T12:00:00.000Z",
      completedAt,
      "2026-08-30T12:01:00.000Z",
    ), false);
  });
  test("does not require every workflow to be current live PASS", () => {
    const result = evaluateAcceptance(acceptance());

    assert.strictEqual(result.status, "passed");
  });

  test("rejects historical evidence relabelled as current", () => {
    const value = acceptance();
    value.workflows[0].layerEvidence[0] = {
      layer: "contract",
      disposition: "observed-historical",
      currentCandidateReceiptFingerprint: "a".repeat(64),
    };
    const result = evaluateAcceptance(value);
    assert.strictEqual(result.status, "failed");
    assert.ok(result.errors.some(error => /relabels historical/u.test(error)));
  });

  test("fails closed when runtime-impact inheritance is allowed", () => {
    const inherited = {
      status: "verified",
      historicalBundleSha256: "1".repeat(64),
      historicalCandidate: "2".repeat(64),
      currentCandidate: "3".repeat(64),
      deltaProofSha256: "4".repeat(64),
      workflowImpactProofSha256: "5".repeat(64),
      targetPolicyFingerprint: "6".repeat(64),
      independentReviewSha256: "7".repeat(64),
      runtimeImpactChanged: true,
      registrationChanged: false,
      ownershipChanged: false,
      requiredLayersChanged: false,
      workflowReopened: false,
      volatileClaimFresh: true,
    };
    assert.strictEqual(validInheritance({ inheritance: inherited }), false);
    const value = acceptance();
    value.workflows[0].layerEvidence[0] = {
      layer: "contract",
      disposition: "inherited-unchanged",
      inheritance: inherited,
    };
    assert.strictEqual(evaluateAcceptance(value).status, "failed");
  });

  test("rejects shallow self-asserted inheritance even when every boolean says safe", () => {
    const inherited = {
      status: "verified",
      historicalBundleSha256: "1".repeat(64),
      historicalCandidate: "2".repeat(64),
      currentCandidate: "3".repeat(64),
      deltaProofSha256: "4".repeat(64),
      workflowImpactProofSha256: "5".repeat(64),
      targetPolicyFingerprint: "6".repeat(64),
      independentReviewSha256: "7".repeat(64),
      runtimeImpactChanged: false,
      registrationChanged: false,
      ownershipChanged: false,
      requiredLayersChanged: false,
      workflowReopened: false,
      volatileClaimFresh: true,
    };
    assert.strictEqual(validInheritance({ inheritance: inherited }), false);
  });

  test("rejects an unvalidated caller-declared lane PASS", () => {
    const value = acceptance();
    delete value.lanes[0].validated;
    const result = evaluateAcceptance(value);
    assert.strictEqual(result.status, "failed");
    assert.ok(result.errors.some(error => /not independently validated/u.test(error)));
  });

  test("does not relabel not-authorized as PASS or product failure", () => {
    const value = acceptance({
      policy: {
        target: "team-test",
        requiredLanes: ["remote-ci", "codeql", "authenticated-local"],
        workflowRules: {
          "WF-PULL": {
            requiredLayers: ["live-protocol"],
            allowedIncompleteDispositions: [{
              layer: "live-protocol",
              disposition: "not-authorized",
            }],
          },
        },
      },
      workflows: [{
        id: "WF-PULL",
        layerEvidence: [{
          layer: "live-protocol",
          disposition: "not-authorized",
          authoritativeOutcomeObserved: false,
          waiverProof: {
            kind: "candidate-bound-preflight",
            candidateReceiptFingerprint: "8".repeat(64),
            preflightEvidenceSha256: "9".repeat(64),
            finalConfirmationEvidenceSha256: "a".repeat(64),
            independentlyVerified: true,
          },
        }],
      }],
    });
    const result = evaluateAcceptance(value);
    assert.strictEqual(result.status, "passed");
    assert.strictEqual(result.verdict, "TEAM-TEST READY WITH RISKS");
    value.workflows[0].layerEvidence[0].authoritativeOutcomeObserved = true;
    assert.strictEqual(evaluateAcceptance(value).status, "failed");
    value.workflows[0].layerEvidence[0].authoritativeOutcomeObserved = false;
    value.workflows[0].layerEvidence[0].waiverProof = null;
    assert.strictEqual(evaluateAcceptance(value).status, "failed");
  });

  test("rejects workflow rows that launder incomplete evidence as PASS", () => {
    const receipt = "8".repeat(64);
    const result = {
      id: "WF-PULL",
      status: "PASS",
      outcomeDisposition: "complete",
      authoritativeOutcomeObserved: true,
      candidateProvenance: "verified",
      candidateReceiptFingerprint: receipt,
      layerEvidence: [{ layer: "live-protocol", disposition: "not-authorized" }],
    };
    const rule = { requiredLayers: ["live-protocol"] };
    assert.ok(reconcileWorkflowRow(result, rule, receipt).length > 0);
    Object.assign(result, {
      status: "PARTIAL",
      outcomeDisposition: "not-authorized",
      authoritativeOutcomeObserved: false,
    });
    assert.deepStrictEqual(reconcileWorkflowRow(result, rule, receipt), []);
  });

  test("treats independently waived fixture absence as nonfailure but never implicit satisfaction", () => {
    const workflow = {
      id: "WF-INSTALL",
      layerEvidence: [{
        layer: "live-protocol",
        disposition: "not-observable-with-current-fixtures",
        authoritativeOutcomeObserved: false,
        currentCandidateReceiptFingerprint: "8".repeat(64),
        waiverProof: {
          kind: "fixture-unavailable",
          independentlyVerified: true,
          authoritativeLowerLayersVerified: true,
          formats: [{
            format: "nuget",
            disposition: "not-observable-with-current-fixtures",
            workspace: "fixture-workspace",
            repository: "fixture-repository",
            query: "format:nuget",
            serviceAccess: "verified",
            boundedCaptureAt: "2026-08-30T12:00:00.000Z",
            fixtureInventorySha256: "b".repeat(64),
          }],
        },
      }],
    };
    const basePolicy = {
      target: "team-test",
      requiredLanes: [],
      workflowRules: {
        "WF-INSTALL": {
          requiredLayers: ["live-protocol"],
          formatContracts: ["nuget"],
          allowedIncompleteDispositions: [],
        },
      },
    };
    assert.strictEqual(evaluateAcceptance(acceptance({
      policy: basePolicy,
      lanes: [],
      workflows: [workflow],
    })).status, "blocked");
    basePolicy.workflowRules["WF-INSTALL"].allowedIncompleteDispositions = [{
      layer: "live-protocol",
      disposition: "not-observable-with-current-fixtures",
    }];
    assert.strictEqual(evaluateAcceptance(acceptance({
      policy: basePolicy,
      lanes: [],
      workflows: [workflow],
    })).verdict, "TEAM-TEST READY WITH RISKS");
    basePolicy.workflowRules["WF-INSTALL"].formatContracts = ["npm", "nuget"];
    assert.strictEqual(evaluateAcceptance(acceptance({
      policy: basePolicy,
      lanes: [],
      workflows: [workflow],
    })).status, "failed");
    basePolicy.workflowRules["WF-INSTALL"].formatContracts = ["nuget"];
    workflow.layerEvidence[0].waiverProof.formats[0].boundedCaptureAt
      = "2026-08-29T12:59:59.000Z";
    assert.strictEqual(evaluateAcceptance(acceptance({
      policy: basePolicy,
      lanes: [],
      workflows: [workflow],
    })).status, "failed");
    workflow.layerEvidence[0].waiverProof.formats[0].boundedCaptureAt
      = "2026-08-30T12:00:00.000Z";
    workflow.layerEvidence[0].waiverProof.formats = [];
    assert.strictEqual(evaluateAcceptance(acceptance({
      policy: basePolicy,
      lanes: [],
      workflows: [workflow],
    })).status, "failed");
  });

  test("rejects a fixture-waiver positive format captured before the candidate", () => {
    const workflow = {
      id: "WF-INSTALL",
      layerEvidence: [{
        layer: "live-protocol",
        disposition: "not-observable-with-current-fixtures",
        authoritativeOutcomeObserved: false,
        currentCandidateReceiptFingerprint: "8".repeat(64),
        waiverProof: {
          kind: "fixture-unavailable",
          independentlyVerified: true,
          authoritativeLowerLayersVerified: true,
          formats: [{
            format: "npm",
            disposition: "observed-current",
            candidateReceiptFingerprint: "8".repeat(64),
            capturedAt: "2026-08-30T11:59:59.000Z",
            evidenceSha256: "a".repeat(64),
          }, {
            format: "nuget",
            disposition: "not-observable-with-current-fixtures",
            workspace: "fixture-workspace",
            repository: "fixture-repository",
            query: "format:nuget",
            serviceAccess: "verified",
            boundedCaptureAt: "2026-08-30T12:10:00.000Z",
            fixtureInventorySha256: "b".repeat(64),
          }],
        },
      }],
    };
    const policy = {
      target: "team-test",
      requiredLanes: [],
      workflowRules: {
        "WF-INSTALL": {
          requiredLayers: ["live-protocol"],
          formatContracts: ["npm", "nuget"],
          allowedIncompleteDispositions: [{
            layer: "live-protocol",
            disposition: "not-observable-with-current-fixtures",
          }],
        },
      },
    };
    assert.strictEqual(evaluateAcceptance(acceptance({
      candidateCapturedAt: "2026-08-30T12:00:00.000Z",
      policy,
      lanes: [],
      workflows: [workflow],
    })).status, "failed");
    workflow.layerEvidence[0].waiverProof.formats[0].capturedAt
      = "2026-08-30T12:00:01.000Z";
    assert.strictEqual(evaluateAcceptance(acceptance({
      candidateCapturedAt: "2026-08-30T12:00:00.000Z",
      policy,
      lanes: [],
      workflows: [workflow],
    })).verdict, "TEAM-TEST READY WITH RISKS");
  });

  test("does not require authenticated CI for team-test when local auth is authoritative", () => {
    const result = evaluateAcceptance(acceptance());
    assert.strictEqual(result.status, "passed");
    assert.ok(!result.gaps.some(gap => /authenticated-ci/u.test(gap)));
  });

  test("keeps real missing required evidence and blockers closed", () => {
    const value = acceptance({ openReleaseBlockerCount: 1 });
    value.workflows[0].layerEvidence.pop();
    const result = evaluateAcceptance(value);
    assert.strictEqual(result.status, "blocked");
    assert.ok(result.gaps.some(gap => /extension-host/u.test(gap)));
    assert.ok(result.gaps.some(gap => /open release-blocking/u.test(gap)));
  });

  test("keeps authenticated CI release-required", () => {
    const value = acceptance({
      target: "release",
      policy: {
        target: "release",
        requiredLanes: ["remote-ci", "codeql", "signed-out-ui", "authenticated-local", "authenticated-ci"],
        workflowRules: acceptance().policy.workflowRules,
      },
    });
    const result = evaluateAcceptance(value);
    assert.strictEqual(result.status, "blocked");
    assert.ok(result.gaps.includes("required lane authenticated-ci is missing"));
  });

  test("does not emit a TEAM-TEST verdict for the release target", () => {
    const value = acceptance({ target: "release" });
    value.policy = { ...value.policy, target: "release" };
    const result = evaluateAcceptance(value);
    assert.strictEqual(result.status, "passed");
    assert.strictEqual(result.verdict, null);
  });

  test("report readiness trusts a validated target-bound acceptance with incomplete waived rows", () => {
    const result = releaseReadinessStatus({
      profile: "release",
      deterministicStatus: "passed",
      impact: { status: "passed" },
      mutation: { status: "passed" },
      blackBoxUi: { status: "failed" },
      remoteCi: {
        status: "passed",
        completedAt: "2026-08-30T10:00:00.000Z",
        signedOutUiArtifact: { artifactId: 1 },
      },
      liveQualification: {
        status: "passed",
        completedAt: "2026-08-30T11:00:00.000Z",
        authenticatedAcceptance: "recorded",
        verdict: "TEAM-TEST READY WITH RISKS",
        readinessTarget: "team-test",
        targetPolicyFingerprint: "c".repeat(64),
      },
      findings: {
        status: "passed",
        releaseBlocking: 0,
        deterministicReleaseBlocking: 0,
        liveReleaseBlocking: 0,
      },
      workflowCoverage: [{
        criticality: "release-critical",
        deterministicStatus: "passed",
        authenticatedRequired: true,
        authenticatedStatus: "BLOCKED",
      }],
    });
    assert.strictEqual(result.status, "passed");
    assert.strictEqual(result.verdict, "TEAM-TEST READY WITH RISKS");
    assert.strictEqual(result.authenticatedLiveLane.allRequiredPassed, false);
    assert.strictEqual(result.authenticatedLiveLane.targetPolicySatisfied, true);
    assert.strictEqual(result.deterministicLane.signedOutBlackBoxUi, "passed");
  });
});

// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { spawnSync } = require("child_process");
const path = require("path");
const { ROOT, readJson } = require("./common");
const { sourceIdentity } = require("./evidence");
const {
  AUTHENTICATED_CANDIDATE_ARTIFACT,
  AUTHENTICATED_CANDIDATE_RECEIPT,
  candidateBindingFromReceipt,
  validateAuthenticatedExecutionReceipt,
} = require("./candidate-binding");
const { assertSourceIdentity } = require("./prepare-qualification");
const { AUTHENTICATED_RESULT } = require("./run-authenticated-ci");
const {
  AUTHENTICATED_EXPOSURE_RESULT,
  validateAuthenticatedExposureProof,
} = require("./authenticated-exposure-scan");

function verifyAuthenticatedEvidence(options = {}) {
  const root = options.root || ROOT;
  if (root !== ROOT) throw new Error("Authenticated evidence verifier requires the exact repository root.");
  const identifySource = options.sourceIdentity || sourceIdentity;
  const source = assertSourceIdentity(identifySource(root, options.gitSpawn || spawnSync));
  const expectedSourceSha = options.expectedSourceSha
    || options.environment?.EXPECTED_SOURCE_SHA
    || process.env.EXPECTED_SOURCE_SHA;
  if (expectedSourceSha !== undefined
    && (!/^[0-9a-f]{40,64}$/u.test(expectedSourceSha)
      || expectedSourceSha !== source.sha)) {
    throw new Error("Authenticated evidence does not match the expected workflow source.");
  }
  const read = options.readJson || readJson;
  const candidate = read(AUTHENTICATED_CANDIDATE_RECEIPT, root);
  const bindCandidate = options.candidateBindingFromReceipt || candidateBindingFromReceipt;
  const binding = bindCandidate(candidate, {
    root,
    source,
    artifactPath: path.join(root, AUTHENTICATED_CANDIDATE_ARTIFACT),
  });
  const authenticated = read(AUTHENTICATED_RESULT, root);
  validateAuthenticatedExecutionReceipt(authenticated, binding, source);
  validateAuthenticatedExposureProof(
    read(AUTHENTICATED_EXPOSURE_RESULT, root),
    candidate,
    source,
  );
  return Object.freeze({
    status: "passed",
    sourceSha: source.sha,
    candidateReceiptFingerprint: binding.receiptFingerprint,
    workspace: authenticated.workspace.observed,
    developmentPath: false,
  });
}

if (require.main === module) {
  try {
    const result = verifyAuthenticatedEvidence();
    process.stdout.write(
      `Authenticated evidence verified for ${result.workspace} with the exact production candidate.\n`,
    );
  } catch {
    process.exitCode = 1;
  }
}

module.exports = {
  AUTHENTICATED_CANDIDATE_ARTIFACT,
  AUTHENTICATED_CANDIDATE_RECEIPT,
  verifyAuthenticatedEvidence,
};

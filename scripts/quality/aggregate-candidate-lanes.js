// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const fs = require("fs");
const crypto = require("crypto");
const path = require("path");
const {
  ROOT,
  readJson,
  resolveExistingRepositoryFile,
  resolveOptionalRepositoryFile,
  writeJson,
} = require("./common");
const { sourceIdentity } = require("./evidence");
const {
  LIVE_CANDIDATE_ARTIFACT,
  LIVE_CANDIDATE_RECEIPT,
  candidateBindingFromReceipt,
  digestStableSingleLinkFile,
  withStableSingleLinkFile,
} = require("./candidate-binding");
const {
  artifactIdentityFromCandidateBinding,
  createCandidateLaneReceipt,
  createCandidateLaneStore,
  validateCandidateLaneStore,
} = require("./candidate-lanes");
const { verifyDetachedSignedOutUiBundle } = require("./verify-ui-evidence");
const { verifyStagedBundleMatchesArchive } = require("./remote-signed-out-artifact");

const OUTPUT = "internal_docs/quality/current-candidate-lanes.json";
const REMOTE_CI = "internal_docs/quality/remote-ci.json";
const REMOTE_ARCHIVE = ".quality/remote-ci/signed-out-ui.zip";
const REMOTE_BUNDLE = ".quality/remote-ci/signed-out-ui";
const MAX_EVIDENCE_BYTES = 16 * 1024 * 1024;
const USAGE = "Usage: aggregate-candidate-lanes.js --authenticated-evidence internal_docs/quality/FILE [--expected-prior-store-fingerprint SHA256]";

function parseArguments(argv) {
  if (![2, 4].includes(argv.length) || argv[0] !== "--authenticated-evidence"
    || !/^internal_docs\/quality\/[A-Za-z0-9][A-Za-z0-9._-]*\.json$/u
      .test(argv[1] || "")
    || (argv.length === 4 && (argv[2] !== "--expected-prior-store-fingerprint"
      || !/^[a-f0-9]{64}$/u.test(argv[3] || "")))) {
    throw new Error(USAGE);
  }
  return {
    authenticatedEvidence: argv[1],
    ...(argv.length === 4 ? { expectedPriorStoreFingerprint: argv[3] } : {}),
  };
}

function canonicalTimestamp(value) {
  const milliseconds = Date.parse(value);
  return typeof value === "string"
    && Number.isFinite(milliseconds)
    && new Date(milliseconds).toISOString() === value;
}

function captureAuthenticatedObservation(
  relativePath,
  candidate,
  root = ROOT,
  now = Date.now(),
  options = {},
) {
  const target = resolveExistingRepositoryFile(relativePath, root, {
    subtree: "internal_docs/quality",
  });
  return withStableSingleLinkFile(target, {
    errorMessage: "Authenticated lane observation is unsafe or changed.",
    maximumBytes: 1024 * 1024,
    minimumBytes: 1,
  }, bytes => {
    let value;
    try {
      value = JSON.parse(bytes.toString("utf8"));
    } catch {
      throw new Error("Authenticated lane observation is invalid JSON.");
    }
  const keys = [
    "candidateReceiptFingerprint", "capturedAt", "evidence", "lane", "reasonCode",
    "schemaVersion", "status",
  ];
  if (!value || typeof value !== "object" || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(keys)
    || value.schemaVersion !== 1
    || value.lane !== "authenticated-local"
    || !["passed", "failed"].includes(value.status)
    || value.candidateReceiptFingerprint !== candidate.receiptFingerprint
    || !canonicalTimestamp(value.capturedAt)
    || Date.parse(value.capturedAt) < Date.parse(candidate.capturedAt || value.capturedAt)
    || Date.parse(value.capturedAt) > now
    || now - Date.parse(value.capturedAt) > 24 * 60 * 60 * 1000
    || (value.status === "passed" && value.reasonCode !== null)
    || (value.status === "failed" && !/^[A-Z][A-Z0-9_]{0,63}$/u.test(value.reasonCode || ""))
    || !Array.isArray(value.evidence) || value.evidence.length === 0) {
    throw new Error("Authenticated lane observation is invalid, stale, or candidate-mismatched.");
  }
  for (const reference of value.evidence) {
    if (!reference || typeof reference !== "object" || Array.isArray(reference)
      || JSON.stringify(Object.keys(reference).sort()) !== JSON.stringify(["path", "sha256"])
      || evidenceReference(reference.path, root).sha256 !== reference.sha256) {
      throw new Error("Authenticated lane observation evidence is invalid or changed.");
    }
  }
    if (typeof options.afterCapture === "function") options.afterCapture(target);
    return Object.freeze({
      observation: value,
      reference: Object.freeze({
        path: relativePath,
        sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
      }),
    });
  });
}

function authenticatedObservation(relativePath, candidate, root = ROOT, now = Date.now(), options) {
  return captureAuthenticatedObservation(relativePath, candidate, root, now, options).observation;
}

function evidenceReference(relativePath, root = ROOT) {
  const target = resolveExistingRepositoryFile(relativePath, root, {
    subtree: relativePath.startsWith(".quality/") ? ".quality" : "internal_docs/quality",
  });
  const proof = digestStableSingleLinkFile(target, {
    errorMessage: "Candidate lane evidence is unsafe or changed.",
    maximumBytes: MAX_EVIDENCE_BYTES,
    minimumBytes: 1,
  });
  return { path: relativePath, sha256: proof.sha256 };
}

function archiveDigest(root = ROOT) {
  const target = resolveExistingRepositoryFile(REMOTE_ARCHIVE, root, {
    subtree: ".quality/remote-ci",
  });
  return digestStableSingleLinkFile(target, {
    errorMessage: "Remote signed-out archive is unsafe or changed.",
    maximumBytes: MAX_EVIDENCE_BYTES,
    minimumBytes: 1,
  }).sha256;
}

function appendLaneReceipt(receipts, values) {
  const existing = receipts
    .filter(receipt => receipt.lane === values.lane)
    .sort((left, right) => left.attempt - right.attempt);
  const previous = existing.at(-1) || null;
  const receipt = createCandidateLaneReceipt({
    ...values,
    attempt: (previous?.attempt || 0) + 1,
    previousReceiptFingerprint: previous?.fingerprint || null,
  });
  receipts.push(receipt);
  return receipt;
}

function priorReceiptsForCandidate(prior, expectedIdentity, expectedPriorStoreFingerprint) {
  if (!prior) {
    if (expectedPriorStoreFingerprint !== undefined) {
      throw new Error("Candidate lane prior-store anchor is unexpected.");
    }
    return [];
  }
  if (!/^[a-f0-9]{64}$/u.test(expectedPriorStoreFingerprint || "")) {
    throw new Error("Candidate lane prior-store fingerprint anchor is required.");
  }
  const validated = validateCandidateLaneStore(prior, {
    expectedArtifactIdentity: prior.artifactIdentity,
    expectedHeads: prior.heads,
    expectedFingerprint: expectedPriorStoreFingerprint,
  });
  if (JSON.stringify(validated.artifactIdentity) !== JSON.stringify(expectedIdentity)) return [];
  return Object.values(prior.receipts);
}

function aggregateCandidateLanes(options = {}) {
  const root = options.root || ROOT;
  const source = options.source || sourceIdentity(root);
  const authenticatedEvidence = options.authenticatedEvidence;
  const liveReceipt = readJson(LIVE_CANDIDATE_RECEIPT, root);
  const liveArtifactPath = resolveExistingRepositoryFile(LIVE_CANDIDATE_ARTIFACT, root, {
    subtree: ".quality/qualification",
  });
  const authenticatedCandidate = candidateBindingFromReceipt(liveReceipt, {
    root,
    source,
    artifactPath: liveArtifactPath,
  });
  if (authenticatedCandidate.profileMode !== "local") {
    throw new Error("Authenticated candidate lane does not use the persistent local profile.");
  }
  const authenticatedCapture = captureAuthenticatedObservation(
    authenticatedEvidence,
    { ...authenticatedCandidate, capturedAt: liveReceipt.capturedAt },
    root,
    options.nowMs || Date.now(),
  );
  const authenticatedObservationValue = authenticatedCapture.observation;
  const remoteCi = readJson(REMOTE_CI, root);
  const archiveSha256 = archiveDigest(root);
  if (`sha256:${archiveSha256}` !== remoteCi.signedOutUiArtifact?.digest) {
    throw new Error("Remote signed-out archive does not match GitHub artifact metadata.");
  }
  const expectedMemberDigests = verifyStagedBundleMatchesArchive({
    archivePath: path.join(root, REMOTE_ARCHIVE),
    bundleRoot: path.join(root, REMOTE_BUNDLE),
    expectedDigest: remoteCi.signedOutUiArtifact.digest,
  });
  const signedOut = verifyDetachedSignedOutUiBundle({
    bundleRoot: path.join(root, REMOTE_BUNDLE),
    contractRoot: root,
    expectedMemberDigests,
    expectedSourceSha: source.sha,
  });
  const expectedIdentity = artifactIdentityFromCandidateBinding(authenticatedCandidate);
  if (JSON.stringify(artifactIdentityFromCandidateBinding(signedOut.candidate))
    !== JSON.stringify(expectedIdentity)) {
    throw new Error("Signed-out and authenticated lanes do not bind the same exact candidate.");
  }
  let priorReceipts = [];
  const priorPath = resolveOptionalRepositoryFile(OUTPUT, root, {
    subtree: "internal_docs/quality",
  });
  if (priorPath) {
    const prior = JSON.parse(fs.readFileSync(priorPath, "utf8"));
    priorReceipts = priorReceiptsForCandidate(
      prior,
      expectedIdentity,
      options.expectedPriorStoreFingerprint,
    );
  }
  appendLaneReceipt(priorReceipts, {
    lane: "authenticated-local",
    capturedAt: authenticatedObservationValue.capturedAt,
    candidateBinding: authenticatedCandidate,
    status: authenticatedObservationValue.status,
    reasonCode: authenticatedObservationValue.reasonCode,
    evidence: [
      authenticatedCapture.reference,
      ...authenticatedObservationValue.evidence,
    ].sort((left, right) => left.path.localeCompare(right.path)),
  });
  appendLaneReceipt(priorReceipts, {
    lane: "signed-out-packaged-ui",
    capturedAt: remoteCi.signedOutUiArtifact.updatedAt,
    candidateBinding: signedOut.candidate,
    status: "passed",
    reasonCode: null,
    evidence: [evidenceReference(REMOTE_CI, root)],
  });
  const store = createCandidateLaneStore(priorReceipts, expectedIdentity);
  writeJson(OUTPUT, store, root, { subtree: "internal_docs/quality" });
  return store;
}

function main(argv = process.argv.slice(2)) {
  try {
    const args = parseArguments(argv);
    const store = aggregateCandidateLanes(args);
    console.log(`Candidate lanes aggregated: ${store.fingerprint}.`);
  } catch (error) {
    console.error(`quality:candidate-lanes: ${error.message}`);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  aggregateCandidateLanes,
  appendLaneReceipt,
  archiveDigest,
  authenticatedObservation,
  captureAuthenticatedObservation,
  evidenceReference,
  parseArguments,
  priorReceiptsForCandidate,
};

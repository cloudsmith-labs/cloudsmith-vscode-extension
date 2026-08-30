// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const {
  CANDIDATE_BINDING_KEYS,
  candidateBindingFromReceipt,
  validateCandidateBinding,
} = require("./candidate-binding");
const { fingerprint } = require("./evidence");

const CANDIDATE_LANES = Object.freeze([
  "authenticated-local",
  "signed-out-packaged-ui",
]);
const LANE_PROFILE_MODES = Object.freeze({
  "authenticated-local": "local",
  "signed-out-packaged-ui": "ci",
});
const ARTIFACT_IDENTITY_KEYS = Object.freeze([
  "extensionId",
  "extensionVersion",
  "sourceFingerprint",
  "sourceSha",
  "vsixSha256",
]);
const EXECUTION_CONTEXT_KEYS = Object.freeze([
  "candidateReceiptFingerprint",
  "developmentPath",
  "installedExtensionId",
  "installedExtensionVersion",
  "profileMode",
  "profileRootIdentity",
  "vscodeVersion",
]);
const LANE_RECEIPT_KEYS = Object.freeze([
  "artifactIdentity",
  "attempt",
  "capturedAt",
  "evidence",
  "executionContext",
  "fingerprint",
  "lane",
  "previousReceiptFingerprint",
  "result",
  "schemaVersion",
]);
const CONTENT_REFERENCE_KEYS = Object.freeze(["path", "sha256"]);
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const SOURCE_SHA_PATTERN = /^[a-f0-9]{40,64}$/u;
const MAX_LANE_RECEIPTS = 128;
const MAX_EVIDENCE_REFERENCES = 64;
const MAX_CONTENT_BYTES = 16 * 1024 * 1024;
const ALLOWED_REFERENCE_PATH = /^(?:\.quality|internal_docs\/quality)\/[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$/u;

function exactDataObject(value, keys, errorMessage) {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || Object.getOwnPropertySymbols(value).length !== 0) {
      throw new Error(errorMessage);
    }
    const names = Object.getOwnPropertyNames(value).sort();
    if (JSON.stringify(names) !== JSON.stringify([...keys].sort())) {
      throw new Error(errorMessage);
    }
    const normalized = {};
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor)) throw new Error(errorMessage);
      normalized[key] = descriptor.value;
    }
    return normalized;
  } catch {
    throw new Error(errorMessage);
  }
}

function exactArray(value, maximum, errorMessage) {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
      || value.length > maximum || Object.getOwnPropertySymbols(value).length !== 0) {
      throw new Error(errorMessage);
    }
    const expectedNames = [
      ...Array.from({ length: value.length }, (_, index) => String(index)),
      "length",
    ].sort();
    const actualNames = Object.getOwnPropertyNames(value).sort();
    if (JSON.stringify(actualNames) !== JSON.stringify(expectedNames)) {
      throw new Error(errorMessage);
    }
    return Array.from({ length: value.length }, (_, index) => String(index)).map(name => {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (!descriptor || !("value" in descriptor)) throw new Error(errorMessage);
      return descriptor.value;
    });
  } catch {
    throw new Error(errorMessage);
  }
}

function canonicalTimestamp(value) {
  if (typeof value !== "string") return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function normalizeCandidateBinding(value) {
  const normalized = exactDataObject(
    value,
    CANDIDATE_BINDING_KEYS,
    "Candidate lane binding is invalid.",
  );
  validateCandidateBinding(normalized);
  return normalized;
}

function normalizeArtifactIdentity(value, errorMessage = "Candidate artifact identity is invalid.") {
  const normalized = exactDataObject(value, ARTIFACT_IDENTITY_KEYS, errorMessage);
  if (!/^[A-Za-z0-9][A-Za-z0-9.-]*$/u.test(normalized.extensionId || "")
    || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(normalized.extensionVersion || "")
    || !SHA256_PATTERN.test(normalized.sourceFingerprint || "")
    || !SOURCE_SHA_PATTERN.test(normalized.sourceSha || "")
    || !SHA256_PATTERN.test(normalized.vsixSha256 || "")) {
    throw new Error(errorMessage);
  }
  return normalized;
}

function sameArtifactIdentity(left, right) {
  return ARTIFACT_IDENTITY_KEYS.every(key => left[key] === right[key]);
}

function artifactIdentityFromCandidateBinding(value) {
  const candidate = normalizeCandidateBinding(value);
  return Object.freeze({
    extensionId: candidate.extensionId,
    extensionVersion: candidate.extensionVersion,
    sourceFingerprint: candidate.sourceFingerprint,
    sourceSha: candidate.sourceSha,
    vsixSha256: candidate.vsixSha256,
  });
}

function executionContextFromCandidateBinding(value) {
  const candidate = normalizeCandidateBinding(value);
  return Object.freeze({
    candidateReceiptFingerprint: candidate.receiptFingerprint,
    developmentPath: candidate.developmentPath,
    installedExtensionId: candidate.installedExtensionId,
    installedExtensionVersion: candidate.installedExtensionVersion,
    profileMode: candidate.profileMode,
    profileRootIdentity: candidate.profileRootIdentity,
    vscodeVersion: candidate.vscodeVersion,
  });
}

function normalizeExecutionContext(value, lane) {
  const errorMessage = "Candidate lane execution context is invalid.";
  const normalized = exactDataObject(value, EXECUTION_CONTEXT_KEYS, errorMessage);
  if (!SHA256_PATTERN.test(normalized.candidateReceiptFingerprint || "")
    || normalized.developmentPath !== false
    || !/^[A-Za-z0-9][A-Za-z0-9.-]*$/u.test(normalized.installedExtensionId || "")
    || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u
      .test(normalized.installedExtensionVersion || "")
    || normalized.profileMode !== LANE_PROFILE_MODES[lane]
    || !SHA256_PATTERN.test(normalized.profileRootIdentity || "")
    || !/^\d+\.\d+\.\d+$/u.test(normalized.vscodeVersion || "")) {
    throw new Error(errorMessage);
  }
  return normalized;
}

function normalizeContentReference(value, errorMessage = "Evidence reference is invalid.") {
  const normalized = exactDataObject(value, CONTENT_REFERENCE_KEYS, errorMessage);
  if (typeof normalized.path !== "string"
    || !ALLOWED_REFERENCE_PATH.test(normalized.path)
    || normalized.path.includes("//")
    || normalized.path.split("/").some(part => part === "." || part === "..")
    || !SHA256_PATTERN.test(normalized.sha256 || "")) {
    throw new Error(errorMessage);
  }
  return normalized;
}

function normalizeEvidence(value) {
  const entries = exactArray(
    value,
    MAX_EVIDENCE_REFERENCES,
    "Candidate lane evidence inventory is invalid.",
  ).map(entry => normalizeContentReference(
    entry,
    "Candidate lane evidence reference is invalid.",
  ));
  if (entries.length === 0
    || new Set(entries.map(entry => entry.path)).size !== entries.length
    || JSON.stringify(entries.map(entry => entry.path))
      !== JSON.stringify(entries.map(entry => entry.path).sort())) {
    throw new Error("Candidate lane evidence inventory is invalid.");
  }
  return entries;
}

function createCandidateLaneReceipt(values) {
  const input = exactDataObject(values, [
    "attempt",
    "candidateBinding",
    "capturedAt",
    "evidence",
    "lane",
    "previousReceiptFingerprint",
    "reasonCode",
    "status",
  ], "Candidate lane receipt input is invalid.");
  const lane = input.lane;
  if (!CANDIDATE_LANES.includes(lane)
    || !Number.isSafeInteger(input.attempt) || input.attempt < 1
    || !canonicalTimestamp(input.capturedAt)
    || !new Set(["passed", "failed"]).has(input.status)
    || (input.status === "passed" && input.reasonCode !== null)
    || (input.status === "failed"
      && !/^[A-Z][A-Z0-9_]{0,63}$/u.test(input.reasonCode || ""))
    || (input.attempt === 1 && input.previousReceiptFingerprint !== null)
    || (input.attempt > 1
      && !SHA256_PATTERN.test(input.previousReceiptFingerprint || ""))) {
    throw new Error("Candidate lane receipt input is invalid.");
  }
  const candidate = normalizeCandidateBinding(input.candidateBinding);
  const artifactIdentity = artifactIdentityFromCandidateBinding(candidate);
  const executionContext = executionContextFromCandidateBinding(candidate);
  if (executionContext.profileMode !== LANE_PROFILE_MODES[lane]) {
    throw new Error("Candidate lane profile does not match the lane authority.");
  }
  const base = {
    schemaVersion: 1,
    lane,
    attempt: input.attempt,
    capturedAt: input.capturedAt,
    previousReceiptFingerprint: input.previousReceiptFingerprint,
    artifactIdentity,
    executionContext,
    result: {
      authoritative: true,
      status: input.status,
      reasonCode: input.reasonCode,
    },
    evidence: normalizeEvidence(input.evidence),
  };
  return deepFreeze({ ...base, fingerprint: fingerprint(base) });
}

function validateCandidateLaneReceipt(value, options = {}) {
  const errorMessage = "Candidate lane receipt is invalid, stale, or tampered.";
  const receipt = exactDataObject(value, LANE_RECEIPT_KEYS, errorMessage);
  if (receipt.schemaVersion !== 1
    || !CANDIDATE_LANES.includes(receipt.lane)
    || !Number.isSafeInteger(receipt.attempt) || receipt.attempt < 1
    || !canonicalTimestamp(receipt.capturedAt)
    || !SHA256_PATTERN.test(receipt.fingerprint || "")
    || (receipt.attempt === 1 && receipt.previousReceiptFingerprint !== null)
    || (receipt.attempt > 1
      && !SHA256_PATTERN.test(receipt.previousReceiptFingerprint || ""))) {
    throw new Error(errorMessage);
  }
  const artifactIdentity = normalizeArtifactIdentity(receipt.artifactIdentity, errorMessage);
  const executionContext = normalizeExecutionContext(receipt.executionContext, receipt.lane);
  if (executionContext.installedExtensionId !== artifactIdentity.extensionId
    || executionContext.installedExtensionVersion !== artifactIdentity.extensionVersion) {
    throw new Error(errorMessage);
  }
  const result = exactDataObject(
    receipt.result,
    ["authoritative", "reasonCode", "status"],
    errorMessage,
  );
  if (result.authoritative !== true
    || !new Set(["passed", "failed"]).has(result.status)
    || (result.status === "passed" && result.reasonCode !== null)
    || (result.status === "failed"
      && !/^[A-Z][A-Z0-9_]{0,63}$/u.test(result.reasonCode || ""))) {
    throw new Error(errorMessage);
  }
  const normalized = {
    schemaVersion: 1,
    lane: receipt.lane,
    attempt: receipt.attempt,
    capturedAt: receipt.capturedAt,
    previousReceiptFingerprint: receipt.previousReceiptFingerprint,
    artifactIdentity,
    executionContext,
    result,
    evidence: normalizeEvidence(receipt.evidence),
  };
  if (fingerprint(normalized) !== receipt.fingerprint
    || (options.expectedFingerprint
      && receipt.fingerprint !== options.expectedFingerprint)
    || (options.expectedLane && receipt.lane !== options.expectedLane)) {
    throw new Error(errorMessage);
  }
  if (options.expectedArtifactIdentity) {
    const expected = normalizeArtifactIdentity(options.expectedArtifactIdentity, errorMessage);
    if (!sameArtifactIdentity(artifactIdentity, expected)) throw new Error(errorMessage);
  }
  return deepFreeze({ ...normalized, fingerprint: receipt.fingerprint });
}

function createCandidateLaneStore(receipts, expectedArtifactIdentity) {
  const expected = normalizeArtifactIdentity(expectedArtifactIdentity);
  const normalized = exactArray(
    receipts,
    MAX_LANE_RECEIPTS,
    "Candidate lane receipt store input is invalid.",
  ).map(receipt => validateCandidateLaneReceipt(receipt, {
    expectedArtifactIdentity: expected,
  }));
  if (normalized.length === 0) throw new Error("Candidate lane receipt store input is invalid.");
  const built = buildLaneStore(normalized, expected);
  return deepFreeze({ ...built, fingerprint: fingerprint(built) });
}

function buildLaneStore(receipts, artifactIdentity) {
  const byFingerprint = {};
  const heads = {};
  for (const receipt of receipts) {
    if (Object.prototype.hasOwnProperty.call(byFingerprint, receipt.fingerprint)) {
      throw new Error("Candidate lane receipt replay or duplicate was detected.");
    }
    byFingerprint[receipt.fingerprint] = receipt;
  }
  for (const lane of CANDIDATE_LANES) {
    const laneReceipts = receipts
      .filter(receipt => receipt.lane === lane)
      .sort((left, right) => left.attempt - right.attempt);
    if (laneReceipts.length === 0) continue;
    for (let index = 0; index < laneReceipts.length; index += 1) {
      const current = laneReceipts[index];
      const previous = laneReceipts[index - 1];
      if (current.attempt !== index + 1
        || current.previousReceiptFingerprint !== (previous?.fingerprint || null)
        || (previous && Date.parse(current.capturedAt) < Date.parse(previous.capturedAt))) {
        throw new Error("Candidate lane receipt chain is incomplete, forked, or replayed.");
      }
    }
    heads[lane] = laneReceipts[laneReceipts.length - 1].fingerprint;
  }
  return {
    schemaVersion: 1,
    artifactIdentity,
    heads: Object.fromEntries(Object.entries(heads).sort(([left], [right]) => left.localeCompare(right))),
    receipts: Object.fromEntries(
      Object.entries(byFingerprint).sort(([left], [right]) => left.localeCompare(right)),
    ),
  };
}

function validateCandidateLaneStore(value, options = {}) {
  const errorMessage = "Candidate lane receipt store is invalid, stale, or tampered.";
  if (!options.expectedArtifactIdentity || !options.expectedHeads) {
    throw new Error("Candidate lane receipt store requires independent identity and head anchors.");
  }
  const store = exactDataObject(
    value,
    ["artifactIdentity", "fingerprint", "heads", "receipts", "schemaVersion"],
    errorMessage,
  );
  const expectedArtifact = normalizeArtifactIdentity(options.expectedArtifactIdentity, errorMessage);
  const artifactIdentity = normalizeArtifactIdentity(store.artifactIdentity, errorMessage);
  if (store.schemaVersion !== 1
    || !SHA256_PATTERN.test(store.fingerprint || "")
    || !sameArtifactIdentity(artifactIdentity, expectedArtifact)) {
    throw new Error(errorMessage);
  }
  const receiptObject = normalizeDynamicObject(store.receipts, errorMessage);
  const receiptEntries = Object.entries(receiptObject);
  if (receiptEntries.length === 0 || receiptEntries.length > MAX_LANE_RECEIPTS) {
    throw new Error(errorMessage);
  }
  const receipts = receiptEntries.map(([address, receipt]) => {
    if (!SHA256_PATTERN.test(address)) throw new Error(errorMessage);
    return validateCandidateLaneReceipt(receipt, {
      expectedArtifactIdentity: artifactIdentity,
      expectedFingerprint: address,
    });
  });
  const rebuilt = buildLaneStore(receipts, artifactIdentity);
  const declaredHeads = normalizeHeads(store.heads, errorMessage);
  const expectedHeads = normalizeHeads(options.expectedHeads, errorMessage);
  if (JSON.stringify(declaredHeads) !== JSON.stringify(rebuilt.heads)
    || JSON.stringify(declaredHeads) !== JSON.stringify(expectedHeads)
    || fingerprint(rebuilt) !== store.fingerprint
    || (options.expectedFingerprint && options.expectedFingerprint !== store.fingerprint)) {
    throw new Error(errorMessage);
  }
  return deepFreeze({
    artifactIdentity,
    fingerprint: store.fingerprint,
    lanes: Object.entries(declaredHeads).map(([lane, receiptFingerprint]) => {
      const receipt = rebuilt.receipts[receiptFingerprint];
      return {
        lane,
        receiptFingerprint,
        attempt: receipt.attempt,
        capturedAt: receipt.capturedAt,
        status: receipt.result.status,
        reasonCode: receipt.result.reasonCode,
        executionContext: receipt.executionContext,
        evidence: receipt.evidence,
      };
    }),
  });
}

function normalizeDynamicObject(value, errorMessage) {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || Object.getOwnPropertySymbols(value).length !== 0) {
      throw new Error(errorMessage);
    }
    const normalized = Object.create(null);
    for (const name of Object.getOwnPropertyNames(value).sort()) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (!descriptor || !("value" in descriptor)) throw new Error(errorMessage);
      normalized[name] = descriptor.value;
    }
    return normalized;
  } catch {
    throw new Error(errorMessage);
  }
}

function normalizeHeads(value, errorMessage) {
  const normalized = normalizeDynamicObject(value, errorMessage);
  for (const [lane, receiptFingerprint] of Object.entries(normalized)) {
    if (!CANDIDATE_LANES.includes(lane) || !SHA256_PATTERN.test(receiptFingerprint || "")) {
      throw new Error(errorMessage);
    }
  }
  return normalized;
}

function validateInheritanceBundle(value, contentByPath, options = {}) {
  // This validates the immutable historical-byte sub-bundle only. Schema v7
  // deliberately does not treat it as inheritance authority without a future
  // outer boundary for exact delta, ownership/registration impact, reopened
  // findings, and volatile-fact freshness.
  const errorMessage = "Candidate inheritance bundle is incomplete, stale, or mismatched.";
  if (!(contentByPath instanceof Map) || Object.getPrototypeOf(contentByPath) !== Map.prototype
    || Reflect.ownKeys(contentByPath).length !== 0
    || !options.expectedHistoricalArtifactIdentity
    || !options.expectedCurrentArtifactIdentity
    || !SHA256_PATTERN.test(options.expectedPolicyFingerprint || "")
    || !SHA256_PATTERN.test(options.expectedFingerprint || "")) {
    throw new Error(errorMessage);
  }
  const bundle = exactDataObject(
    value,
    ["decision", "fingerprint", "review", "schemaVersion"],
    errorMessage,
  );
  const decision = normalizeInheritanceDecision(bundle.decision, errorMessage);
  const reviewReference = normalizeContentReference(bundle.review, errorMessage);
  const normalizedBase = { schemaVersion: bundle.schemaVersion, decision, review: reviewReference };
  if (bundle.schemaVersion !== 1
    || !SHA256_PATTERN.test(bundle.fingerprint || "")
    || fingerprint(normalizedBase) !== bundle.fingerprint
    || bundle.fingerprint !== options.expectedFingerprint) {
    throw new Error(errorMessage);
  }
  const expectedHistorical = normalizeArtifactIdentity(
    options.expectedHistoricalArtifactIdentity,
    errorMessage,
  );
  const expectedCurrent = normalizeArtifactIdentity(
    options.expectedCurrentArtifactIdentity,
    errorMessage,
  );
  if (!sameArtifactIdentity(decision.historicalArtifactIdentity, expectedHistorical)
    || !sameArtifactIdentity(decision.currentArtifactIdentity, expectedCurrent)
    || decision.policyFingerprint !== options.expectedPolicyFingerprint
    || decision.policy.sha256 !== options.expectedPolicyFingerprint) {
    throw new Error(errorMessage);
  }

  const receiptBytes = referencedBytes(decision.sourceReceipt, contentByPath, errorMessage);
  const artifactBytes = referencedBytes(decision.sourceArtifact, contentByPath, errorMessage);
  const attestationBytes = referencedBytes(decision.sourceAttestation, contentByPath, errorMessage);
  const policyBytes = referencedBytes(decision.policy, contentByPath, errorMessage);
  if (sha256(policyBytes) !== decision.policyFingerprint) throw new Error(errorMessage);
  for (const reference of decision.evidence) {
    referencedBytes(reference, contentByPath, errorMessage);
  }

  const sourceReceipt = parseJsonObject(receiptBytes, errorMessage);
  let historicalBinding;
  try {
    historicalBinding = candidateBindingFromReceipt(sourceReceipt);
  } catch {
    throw new Error(errorMessage);
  }
  const receiptArtifactIdentity = artifactIdentityFromCandidateBinding(historicalBinding);
  if (!sameArtifactIdentity(receiptArtifactIdentity, decision.historicalArtifactIdentity)
    || artifactBytes.length !== sourceReceipt.artifact?.archiveBytes
    || sha256(artifactBytes) !== sourceReceipt.artifact?.sha256) {
    throw new Error(errorMessage);
  }

  const attestation = parseJsonObject(attestationBytes, errorMessage);
  let attestationCandidate;
  try {
    attestationCandidate = normalizeCandidateBinding(attestation.candidate);
  } catch {
    throw new Error(errorMessage);
  }
  if (!sameArtifactIdentity(
    artifactIdentityFromCandidateBinding(attestationCandidate),
    decision.historicalArtifactIdentity,
  ) || attestationCandidate.receiptFingerprint !== historicalBinding.receiptFingerprint
    || attestation.source?.sha !== decision.historicalArtifactIdentity.sourceSha
    || attestation.source?.fingerprint !== decision.historicalArtifactIdentity.sourceFingerprint) {
    throw new Error(errorMessage);
  }
  const workflowResults = exactArray(
    attestation.workflowResults,
    256,
    errorMessage,
  );
  const matchingRows = workflowResults.filter(row => row?.id === decision.workflowId);
  if (matchingRows.length !== 1) throw new Error(errorMessage);
  const row = matchingRows[0];
  const rowEvidence = exactArray(row?.evidence, MAX_EVIDENCE_REFERENCES, errorMessage)
    .map(entry => normalizeContentReference({ path: entry?.path, sha256: entry?.sha256 }, errorMessage));
  if (row?.status !== "PASS"
    || row?.authoritativeOutcomeObserved !== true
    || row?.candidateProvenance !== "verified"
    || row?.candidateReceiptFingerprint !== historicalBinding.receiptFingerprint
    || fingerprint(row) !== decision.rowFingerprint
    || JSON.stringify(rowEvidence) !== JSON.stringify(decision.evidence)) {
    throw new Error(errorMessage);
  }

  const review = parseJsonObject(
    referencedBytes(reviewReference, contentByPath, errorMessage),
    errorMessage,
  );
  const normalizedReview = exactDataObject(review, [
    "decisionFingerprint",
    "operatorId",
    "reviewedAt",
    "reviewerId",
    "schemaVersion",
    "status",
  ], errorMessage);
  if (normalizedReview.schemaVersion !== 1
    || normalizedReview.status !== "approved"
    || !canonicalTimestamp(normalizedReview.reviewedAt)
    || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(normalizedReview.operatorId || "")
    || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(normalizedReview.reviewerId || "")
    || normalizedReview.operatorId !== decision.operatorId
    || normalizedReview.reviewerId === normalizedReview.operatorId
    || normalizedReview.decisionFingerprint !== fingerprint(decision)) {
    throw new Error(errorMessage);
  }
  return deepFreeze({
    fingerprint: bundle.fingerprint,
    workflowId: decision.workflowId,
    layer: decision.layer,
    historicalArtifactIdentity: decision.historicalArtifactIdentity,
    currentArtifactIdentity: decision.currentArtifactIdentity,
    reviewerId: normalizedReview.reviewerId,
  });
}

function normalizeInheritanceDecision(value, errorMessage) {
  const decision = exactDataObject(value, [
    "currentArtifactIdentity",
    "evidence",
    "historicalArtifactIdentity",
    "layer",
    "operatorId",
    "policy",
    "policyFingerprint",
    "rowFingerprint",
    "sourceArtifact",
    "sourceAttestation",
    "sourceReceipt",
    "workflowId",
  ], errorMessage);
  const normalized = {
    workflowId: decision.workflowId,
    layer: decision.layer,
    operatorId: decision.operatorId,
    historicalArtifactIdentity: normalizeArtifactIdentity(
      decision.historicalArtifactIdentity,
      errorMessage,
    ),
    currentArtifactIdentity: normalizeArtifactIdentity(
      decision.currentArtifactIdentity,
      errorMessage,
    ),
    sourceReceipt: normalizeContentReference(decision.sourceReceipt, errorMessage),
    sourceArtifact: normalizeContentReference(decision.sourceArtifact, errorMessage),
    sourceAttestation: normalizeContentReference(decision.sourceAttestation, errorMessage),
    rowFingerprint: decision.rowFingerprint,
    evidence: normalizeEvidence(decision.evidence),
    policy: normalizeContentReference(decision.policy, errorMessage),
    policyFingerprint: decision.policyFingerprint,
  };
  if (!/^WF-[A-Z0-9-]+$/u.test(normalized.workflowId || "")
    || !/^[a-z][a-z0-9-]{1,63}$/u.test(normalized.layer || "")
    || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(normalized.operatorId || "")
    || !SHA256_PATTERN.test(normalized.rowFingerprint || "")
    || !SHA256_PATTERN.test(normalized.policyFingerprint || "")) {
    throw new Error(errorMessage);
  }
  const references = [
    normalized.sourceReceipt,
    normalized.sourceArtifact,
    normalized.sourceAttestation,
    normalized.policy,
    ...normalized.evidence,
  ];
  if (new Set(references.map(reference => reference.path)).size !== references.length) {
    throw new Error(errorMessage);
  }
  return normalized;
}

function referencedBytes(reference, contentByPath, errorMessage) {
  if (!Map.prototype.has.call(contentByPath, reference.path)) throw new Error(errorMessage);
  const value = Map.prototype.get.call(contentByPath, reference.path);
  if ((Buffer.isBuffer(value) && value.length > MAX_CONTENT_BYTES)
    || (typeof value === "string" && Buffer.byteLength(value) > MAX_CONTENT_BYTES)) {
    throw new Error(errorMessage);
  }
  const bytes = Buffer.isBuffer(value) ? Buffer.from(value)
    : typeof value === "string" ? Buffer.from(value, "utf8") : null;
  if (!bytes || bytes.length === 0 || bytes.length > MAX_CONTENT_BYTES
    || sha256(bytes) !== reference.sha256) {
    throw new Error(errorMessage);
  }
  return bytes;
}

function parseJsonObject(bytes, errorMessage) {
  try {
    const parsed = JSON.parse(bytes.toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)
      || Object.getPrototypeOf(parsed) !== Object.prototype) {
      throw new Error(errorMessage);
    }
    return parsed;
  } catch {
    throw new Error(errorMessage);
  }
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

module.exports = {
  artifactIdentityFromCandidateBinding,
  createCandidateLaneReceipt,
  createCandidateLaneStore,
  executionContextFromCandidateBinding,
  validateCandidateLaneReceipt,
  validateCandidateLaneStore,
  validateInheritanceBundle,
};

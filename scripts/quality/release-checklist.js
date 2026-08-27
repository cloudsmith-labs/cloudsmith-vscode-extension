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
  parseFindingsJsonl,
  readBoundedFindingsBytes,
  validateFindings,
} = require("./findings");

const DEFAULT_INPUT = "internal_docs/quality/live-qualification.json";
const DEFAULT_OUTPUT = ".quality/gates/live-qualification-status.json";
const DEFAULT_FINDINGS = "internal_docs/quality/findings.jsonl";
const READY_VERDICTS = new Set([
  "TEAM-TEST READY",
  "TEAM-TEST READY WITH KNOWN NON-BLOCKING RISKS",
]);
const DECLARED_STATUSES = new Set(["passed", "failed", "blocked", "not-run"]);
const EVIDENCE_PATH_PATTERN = /^internal_docs\/quality\/[A-Za-z0-9][A-Za-z0-9._-]*\.(?:json|jsonl|md|png|txt|webp)$/u;
const EVIDENCE_MAX_BYTES = 16 * 1024 * 1024;
const MAX_QUALIFICATION_AGE_MS = 24 * 60 * 60 * 1000;

function requiredLiveWorkflowIds(workflowsDocument) {
  return uniqueSorted((workflowsDocument?.workflows || [])
    .filter(workflow => workflow.requiredLayers?.includes("live-protocol"))
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
  const evidenceManifest = document ? qualificationEvidenceManifest(document) : [];
  const findingsState = options.findingsState || readFindingsState(
    options.root || ROOT,
    options.findingsPath || DEFAULT_FINDINGS
  );
  if (!document) {
    return statusDocument({
      source,
      inputPath,
      status: "not-run",
      requiredIds,
      findingsState,
      attestationFingerprint,
      evidenceManifest,
      reason: "No ignored authenticated live-qualification attestation was supplied.",
    });
  }

  const declaredStatus = document.status;
  if (!DECLARED_STATUSES.has(declaredStatus)) {
    return statusDocument({
      source,
      inputPath,
      status: "failed",
      requiredIds,
      findingsState,
      attestationFingerprint,
      evidenceManifest,
      errors: ["Live qualification status must be passed, failed, blocked, or not-run."],
    });
  }
  if (declaredStatus !== "passed") {
    return statusDocument({
      source,
      inputPath,
      status: declaredStatus,
      requiredIds,
      findingsState,
      attestationFingerprint,
      evidenceManifest,
      reason: nonEmpty(document.summary)
        ? document.summary
        : `Authenticated live qualification is declared ${declaredStatus}.`,
    });
  }

  const validationContext = createValidationContext({ ...options, findingsState });
  const errors = validatePassedAttestation(
    document,
    source,
    workflows,
    requiredIds,
    validationContext,
  );
  const results = Array.isArray(document.workflowResults) ? document.workflowResults : [];
  const passedIds = uniqueSorted(results
    .filter(result => result.status === "passed"
      && result.authoritativeOutcomeObserved === true
      && evidenceReferenceArray(result.evidence))
    .map(result => result.id));
  return statusDocument({
    source,
    inputPath,
    status: errors.length === 0 ? "passed" : "failed",
    requiredIds,
    passedIds: errors.length === 0 ? passedIds : [],
    errors,
    verdict: errors.length === 0 ? document.verdict : null,
    authenticatedAcceptance: errors.length === 0 ? "recorded" : "not-recorded",
    findingsState,
    attestationFingerprint,
    evidenceManifest,
    visibleEnabledActions: {
      status: document.visibleEnabledActions?.status || "not-run",
      silentNoOpCount: Number.isInteger(document.visibleEnabledActions?.silentNoOpCount)
        ? document.visibleEnabledActions.silentNoOpCount
        : null,
    },
  });
}

function validatePassedAttestation(document, source, workflows, requiredIds, context = createValidationContext()) {
  const errors = [];
  if (document.schemaVersion !== 3) errors.push("Live qualification schemaVersion must be 3.");
  if (document.source?.sha !== source.sha) {
    errors.push("Live qualification source SHA does not match the current candidate.");
  }
  if (document.source?.fingerprint !== source.fingerprint) {
    errors.push("Live qualification source fingerprint does not match the current candidate.");
  }
  if (document.authenticatedAcceptance !== true) {
    errors.push("Authenticated acceptance was not explicitly attested.");
  }
  if (document.checklistConfirmed !== true) {
    errors.push("The release checklist was not explicitly confirmed.");
  }
  if (!validIdentity(document.operatorId)) {
    errors.push("Live qualification must identify the qualification operator.");
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
    errors.push("Live qualification must explicitly record zero open release blockers.");
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
) {
  if (!Array.isArray(results)) {
    errors.push("Live qualification must contain workflowResults.");
    return;
  }
  const knownIds = new Set((workflows?.workflows || []).map(workflow => workflow.id));
  const seen = new Set();
  for (const result of results) {
    if (!knownIds.has(result?.id)) errors.push(`Live qualification references unknown workflow ${String(result?.id)}.`);
    if (seen.has(result?.id)) errors.push(`Live qualification repeats workflow ${String(result?.id)}.`);
    seen.add(result?.id);
    if (result?.status !== "passed") {
      errors.push(`Live workflow ${String(result?.id)} is not passed.`);
    }
    if (result?.authoritativeOutcomeObserved !== true) {
      errors.push(`Live workflow ${String(result?.id)} lacks an authoritative-outcome attestation.`);
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

function validateVisibleActions(
  value,
  errors,
  context,
  completedAt,
  evidenceNotBefore,
  evidencePaths,
) {
  if (value?.status !== "passed") {
    errors.push("Visible enabled actions were not completely qualified.");
  }
  if (value?.silentNoOpCount !== 0) {
    errors.push("Visible enabled actions do not explicitly record zero silent no-ops.");
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
  if (value?.status !== "passed") errors.push("Independent release review is not passed.");
  if (!validIdentity(value?.reviewerId)) {
    errors.push("Independent release review must identify its reviewer.");
  } else if (validIdentity(document.operatorId)
    && value.reviewerId.trim().toLowerCase() === document.operatorId.trim().toLowerCase()) {
    errors.push("Independent release reviewer must differ from the qualification operator.");
  }
  if (value?.source?.sha !== source.sha || value?.source?.fingerprint !== source.fingerprint) {
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
  const passedIds = values.passedIds || [];
  return {
    schemaVersion: 1,
    source: values.source,
    inputPath: values.inputPath,
    status: values.status,
    authenticatedAcceptance: values.authenticatedAcceptance || "not-recorded",
    verdict: values.verdict || null,
    requiredWorkflowIds: requiredIds,
    passedWorkflowIds: passedIds,
    missingWorkflowIds: requiredIds.filter(id => !passedIds.includes(id)),
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
    const terminal = new Set(["fixed", "closed-non-issue"]);
    const openRecords = records.filter(record => !terminal.has(record?.status));
    return {
      fingerprint,
      openReleaseBlockerCount: openRecords.filter(record => (
        record?.releaseBlocking === true
      )).length,
      openNonBlockingRiskCount: openRecords.filter(record => (
        record?.releaseBlocking === false
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

function evaluateDiskLiveQualification(options = {}) {
  const root = options.root || ROOT;
  const inputPath = options.inputPath || DEFAULT_INPUT;
  validateInputPath(inputPath);
  const loaded = loadLiveQualification(root, inputPath);
  return evaluateLiveQualification({
    source: options.source || sourceIdentity(root),
    workflows: options.workflows || readJson("quality/critical-workflows.json", root),
    document: loaded?.document || null,
    attestationFingerprint: loaded?.fingerprint || null,
    inputPath,
    now: options.now,
    root,
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
    source: options.source,
    workflows: options.workflows,
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
    if (["blocked", "not-run"].includes(result.status)) process.exitCode = 2;
    else if (result.status !== "passed") process.exitCode = 1;
  } catch (error) {
    console.error(`quality:release-checklist: ${error.message}`);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
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
  validateInputPath,
  validatePassedAttestation,
};

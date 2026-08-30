// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const { isDeepStrictEqual } = require("util");
const {
  ROOT,
  discoverRepositoryOutputFiles,
  resolveExistingRepositoryFile,
  resolveOptionalRepositoryFile,
} = require("./common");
const {
  aggregateStatuses,
  fingerprint,
  sourceIdentity,
} = require("./evidence");
const {
  gatePlanFingerprint,
  getGatePlan,
  receiptPath,
  sameSource,
  stepArtifactPaths,
  validateArtifactBinding,
  validateTestEvidenceBinding,
} = require("./gate");
const { withStableSingleLinkFile } = require("./candidate-binding");
const {
  generateReport,
  hasDeterministicReportFailure,
  loadReportInputs,
  normalizeGateReceipt,
  renderMarkdown,
} = require("./report");

const MAX_EVIDENCE_BYTES = 64 * 1024 * 1024;

function verifyEvidenceHandoff(options = {}) {
  const root = options.root || ROOT;
  const profile = options.profile || "fast";
  const plan = getGatePlan(profile);
  const readSource = options.readSource || (() => sourceIdentity(root));
  const source = options.source || readSource();
  const summaryPath = `.quality/gates/${profile}.json`;
  const generationContext = {
    fileSystem: options.fileSystem,
    summaryPath,
    profile,
    plan,
    root,
    source,
  };
  const initialGeneration = readValidatedGateGeneration(generationContext);
  const summary = initialGeneration.summary;

  const reportStep = plan.find(step => step.id === "quality-report");
  const reportReceipt = summary.steps.find(receipt => receipt.stepId === "quality-report");
  if (!reportStep || !reportReceipt) {
    throw new Error("Evidence handoff requires the quality-report finalizer and receipt.");
  }
  const bindingError = validateArtifactBinding(reportReceipt, reportStep, root);
  if (bindingError) throw new Error(`Quality report bundle is untrusted: ${bindingError}.`);

  const reportRecord = readCanonicalJson(".quality/report.json", root, ".quality", {
    fileSystem: options.fileSystem,
  });
  const markdownBytes = readEvidenceBytes(".quality/report.md", root, ".quality", {
    fileSystem: options.fileSystem,
  });
  validateReportBundleBytes(reportReceipt, reportStep, reportRecord.bytes, markdownBytes);
  const reportInputs = loadReportInputs({
    fileSystem: options.fileSystem,
    root,
    profile,
    source,
  });
  if (!isDeepStrictEqual(reportInputs.receipts, summary.steps)) {
    throw new Error("Gate receipts changed while the quality report was regenerated.");
  }
  const expectedReport = generateReport(reportInputs);
  const expectedJson = Buffer.from(`${JSON.stringify(expectedReport, null, 2)}\n`);
  const expectedMarkdown = Buffer.from(renderMarkdown(expectedReport));
  if (!reportRecord.bytes.equals(expectedJson)) {
    throw new Error("Quality report JSON does not match independently regenerated evidence.");
  }
  if (!markdownBytes.equals(expectedMarkdown)) {
    throw new Error("Quality report Markdown does not match independently regenerated evidence.");
  }
  validateReportExecution(reportReceipt, expectedReport);

  const finalGeneration = readValidatedGateGeneration(generationContext);
  if (!finalGeneration.bytes.equals(initialGeneration.bytes)
    || !isDeepStrictEqual(finalGeneration.summary, summary)) {
    throw new Error("Gate evidence generation changed during handoff verification.");
  }
  const finalReportRecord = readCanonicalJson(".quality/report.json", root, ".quality", {
    fileSystem: options.fileSystem,
  });
  const finalMarkdownBytes = readEvidenceBytes(".quality/report.md", root, ".quality", {
    fileSystem: options.fileSystem,
  });
  if (!finalReportRecord.bytes.equals(reportRecord.bytes)
    || !finalMarkdownBytes.equals(markdownBytes)) {
    throw new Error("Quality report bundle changed during handoff verification.");
  }
  validateReportBundleBytes(
    reportReceipt,
    reportStep,
    finalReportRecord.bytes,
    finalMarkdownBytes,
  );

  const finalSource = readSource();
  if (!sameSource(finalSource, source)) {
    throw new Error("Repository source changed during evidence handoff verification.");
  }
  return { profile, report: expectedReport, source, summary };
}

function readValidatedGateGeneration(context) {
  const record = readCanonicalJson(
    context.summaryPath,
    context.root,
    ".quality/gates",
    { fileSystem: context.fileSystem },
  );
  const summary = record.value;
  validateSummary(summary, context);
  validateReceiptFiles(summary, context);
  validateReceiptSequence(summary.steps, context.plan);
  return Object.freeze({
    bytes: Buffer.from(record.bytes),
    summary,
  });
}

function validateGateGenerationSemantics(summary, context) {
  validateSummary(summary, context);
  for (let index = 0; index < context.plan.length; index += 1) {
    validateReceipt(summary.steps[index], context.plan[index], context);
  }
  validateReceiptSequence(summary.steps, context.plan);
  return true;
}

function validateGateGenerationProgress(receipts, context) {
  if (!Array.isArray(receipts) || receipts.length !== context.plan.length) {
    throw new Error("Gate receipt progress does not match the exact gate plan.");
  }
  for (let index = 0; index < context.plan.length; index += 1) {
    validateReceipt(receipts[index], context.plan[index], context);
  }
  let blocker = null;
  let pending = false;
  for (let index = 0; index < context.plan.length; index += 1) {
    const step = context.plan[index];
    const receipt = receipts[index];
    if (blocker && !step.runWhenBlocked) {
      if (receipt.status !== "not-run" || receipt.reason !== `blocked-by:${blocker}`) {
        throw new Error(`Gate receipt ${step.id} does not preserve blocker ordering.`);
      }
      continue;
    }
    if (receipt.status === "not-run") {
      if (receipt.reason !== "not-started") {
        throw new Error(`Gate receipt ${step.id} has invalid pending execution evidence.`);
      }
      pending = true;
      continue;
    }
    if (pending) {
      throw new Error(`Gate receipt ${step.id} completed after a pending plan slot.`);
    }
    if (!blocker && ["failed", "blocked"].includes(receipt.status)) blocker = step.id;
  }
  return true;
}

function validateGateStepArtifactClaim(receipt, step) {
  const artifactPaths = stepArtifactPaths(step);
  if (artifactPaths.length === 0) {
    if (receipt.artifactFingerprint !== null) {
      throw new Error(`Gate receipt ${step.id} claims an undeclared artifact.`);
    }
    return true;
  }
  if (receipt.artifactFingerprint !== null
    && !/^[a-f0-9]{64}$/u.test(receipt.artifactFingerprint || "")) {
    throw new Error(`Gate receipt ${step.id} has an invalid artifact fingerprint.`);
  }
  return true;
}

function validateReportBundleBytes(receipt, step, jsonBytes, markdownBytes) {
  const bytesByPath = new Map([
    [".quality/report.json", jsonBytes],
    [".quality/report.md", markdownBytes],
  ]);
  const artifactPaths = stepArtifactPaths(step);
  if (artifactPaths.length !== bytesByPath.size
    || artifactPaths.some(relativePath => !bytesByPath.has(relativePath))) {
    throw new Error("Quality report bundle declaration is invalid.");
  }
  let actualFingerprint;
  if (artifactPaths.length === 1) {
    actualFingerprint = crypto.createHash("sha256")
      .update(bytesByPath.get(artifactPaths[0]))
      .digest("hex");
  } else {
    const hash = crypto.createHash("sha256");
    hash.update("cloudsmith-quality-artifact-bundle-v1\0");
    for (const relativePath of artifactPaths) {
      const bytes = bytesByPath.get(relativePath);
      hash.update(`${relativePath}\0${bytes.length}\0`);
      hash.update(bytes);
      hash.update("\0");
    }
    actualFingerprint = hash.digest("hex");
  }
  if (actualFingerprint !== receipt.artifactFingerprint) {
    throw new Error("Quality report bundle bytes do not match the gate receipt.");
  }
}

function validateSummary(summary, context) {
  assertExactKeys(
    summary,
    ["key", "planFingerprint", "profile", "schemaVersion", "source", "status", "steps"],
    "Gate summary"
  );
  assertExactKeys(summary.source, ["fingerprint", "sha"], "Gate summary source");
  assertExactKeys(summary.key, ["fingerprint", "sha"], "Gate summary key");
  if (summary.schemaVersion !== 1 || summary.profile !== context.profile) {
    throw new Error("Gate summary schema or profile does not match the requested handoff.");
  }
  if (!/^[a-f0-9]{40}$/u.test(summary.source.sha || "")
    || !/^[a-f0-9]{64}$/u.test(summary.source.fingerprint || "")
    || !sameSource(summary.source, context.source)) {
    throw new Error("Gate summary does not bind the current repository source.");
  }
  if (summary.planFingerprint !== gatePlanFingerprint(context.plan)) {
    throw new Error("Gate summary does not bind the current exact gate plan.");
  }
  if (!Array.isArray(summary.steps) || summary.steps.length !== context.plan.length) {
    throw new Error("Gate summary step inventory does not match the exact gate plan.");
  }
  if (summary.status !== aggregateStatuses(summary.steps.map(receipt => receipt?.status))) {
    throw new Error("Gate summary status does not reconcile with its receipts.");
  }
  const unsigned = { ...summary };
  delete unsigned.key;
  if (summary.key.sha !== summary.source.sha
    || summary.key.fingerprint !== fingerprint(unsigned)) {
    throw new Error("Gate summary key does not bind the complete summary.");
  }
}

function validateReceiptFiles(summary, context) {
  const expectedPaths = context.plan.map(step => receiptPath({
    profile: context.profile,
    sequence: step.sequence,
    stepId: step.id,
  })).sort();
  const receiptDirectory = `.quality/gates/${context.profile}`;
  const actualPaths = discoverRepositoryOutputFiles(receiptDirectory, context.root, {
    subtree: receiptDirectory,
  });
  if (!isDeepStrictEqual(actualPaths, expectedPaths)) {
    throw new Error("Gate receipt files do not exactly match the current gate plan.");
  }

  for (let index = 0; index < context.plan.length; index += 1) {
    const step = context.plan[index];
    const summaryReceipt = summary.steps[index];
    const diskReceipt = readCanonicalJson(
      receiptPath(summaryReceipt),
      context.root,
      receiptDirectory,
      { fileSystem: context.fileSystem },
    ).value;
    if (!isDeepStrictEqual(diskReceipt, summaryReceipt)) {
      throw new Error(`Gate receipt ${step.id} differs from the signed summary.`);
    }
    validateReceipt(summaryReceipt, step, context);
    validateStepArtifacts(summaryReceipt, step, context.root);
    validateStepTestEvidence(summaryReceipt, step, context.root);
  }
}

function validateReceipt(receipt, step, context) {
  const requiredKeys = [
    "artifactFingerprint",
    "category",
    "command",
    "exitCode",
    "profile",
    "reason",
    "schemaVersion",
    "sequence",
    "signal",
    "source",
    "status",
    "stepId",
    "testCounts",
  ];
  const allowedKeys = new Set([
    ...requiredKeys,
    "outputFingerprint",
    "testEvidence",
    "testEvidenceFingerprint",
  ]);
  const keys = Object.keys(receipt || {});
  if (!requiredKeys.every(key => keys.includes(key))
    || keys.some(key => !allowedKeys.has(key))) {
    throw new Error(`Gate receipt ${step.id} fields do not match schemaVersion 1.`);
  }
  assertExactKeys(receipt.source, ["fingerprint", "sha"], `Gate receipt ${step.id} source`);
  if (receipt.schemaVersion !== 1
    || receipt.profile !== context.profile
    || receipt.sequence !== step.sequence
    || receipt.stepId !== step.id
    || receipt.category !== step.category
    || receipt.command !== step.command
    || !sameSource(receipt.source, context.source)) {
    throw new Error(`Gate receipt ${step.id} does not match its exact plan slot.`);
  }
  const normalized = normalizeGateReceipt(receipt, step, context.source);
  if (normalized.status !== receipt.status
    || String(normalized.reason || "").startsWith("receipt-integrity:")) {
    throw new Error(`Gate receipt ${step.id} has invalid execution evidence.`);
  }
  if (Object.prototype.hasOwnProperty.call(receipt, "outputFingerprint")
    && !/^[a-f0-9]{64}$/u.test(receipt.outputFingerprint || "")) {
    throw new Error(`Gate receipt ${step.id} has an invalid output fingerprint.`);
  }
  const completionFields = ["outputFingerprint", "testEvidence", "testEvidenceFingerprint"];
  const completedFieldCount = completionFields.filter(key => (
    Object.prototype.hasOwnProperty.call(receipt, key)
  )).length;
  const completedKeys = completedFieldCount === completionFields.length;
  if ((completedFieldCount > 0 && !completedKeys)
    || (receipt.status === "not-run" && completedKeys)
    || (receipt.status !== "not-run" && !completedKeys)) {
    throw new Error(`Gate receipt ${step.id} completion fields are inconsistent.`);
  }
  if (receipt.testCounts !== null
    && (!receipt.testCounts
      || typeof receipt.testCounts !== "object"
      || Array.isArray(receipt.testCounts)
      || Object.keys(receipt.testCounts).some(key => !["failing", "passing", "pending"].includes(key))
      || Object.values(receipt.testCounts).some(value => !Number.isInteger(value) || value < 0))) {
    throw new Error(`Gate receipt ${step.id} has invalid parsed test counts.`);
  }
}

function validateStepTestEvidence(receipt, step, root) {
  if (receipt.status === "not-run"
    && !Object.prototype.hasOwnProperty.call(receipt, "testEvidenceFingerprint")) {
    return;
  }
  if (!step.evidencePath) {
    if (receipt.testEvidenceFingerprint !== null) {
      throw new Error(`Gate receipt ${step.id} claims undeclared structured evidence.`);
    }
    return;
  }
  if (receipt.status !== "passed" && receipt.testEvidenceFingerprint === null) return;
  const bindingError = validateTestEvidenceBinding(receipt, step, root);
  if (bindingError) {
    throw new Error(`Gate test evidence ${step.id} is untrusted: ${bindingError}.`);
  }
}

function validateReceiptSequence(receipts, plan) {
  let blocker = null;
  for (let index = 0; index < plan.length; index += 1) {
    const step = plan[index];
    const receipt = receipts[index];
    if (blocker && !step.runWhenBlocked) {
      if (receipt.status !== "not-run" || receipt.reason !== `blocked-by:${blocker}`) {
        throw new Error(`Gate receipt ${step.id} does not preserve blocker ordering.`);
      }
    } else if (receipt.status === "not-run") {
      throw new Error(`Gate receipt ${step.id} remained not-run without a prior blocker.`);
    }
    if (!blocker && ["failed", "blocked"].includes(receipt.status)) blocker = step.id;
  }
}

function validateStepArtifacts(receipt, step, root) {
  const artifactPaths = stepArtifactPaths(step);
  if (artifactPaths.length === 0) {
    if (receipt.artifactFingerprint !== null) {
      throw new Error(`Gate receipt ${step.id} claims an undeclared artifact.`);
    }
    return;
  }
  const hasFingerprint = /^[a-f0-9]{64}$/u.test(receipt.artifactFingerprint || "");
  if (hasFingerprint) {
    const bindingError = validateArtifactBinding(receipt, step, root);
    if (bindingError) throw new Error(`Gate artifact ${step.id} is untrusted: ${bindingError}.`);
    return;
  }
  if (receipt.artifactFingerprint !== null) {
    throw new Error(`Gate receipt ${step.id} has an invalid artifact fingerprint.`);
  }
  for (const artifactPath of artifactPaths) {
    const target = resolveOptionalRepositoryFile(artifactPath, root, {
      subtree: step.artifactSubtree || ".quality/mutation",
    });
    if (target) throw new Error(`Unreceipted gate artifact exists: ${artifactPath}.`);
  }
}

function validateReportExecution(receipt, report) {
  const failed = hasDeterministicReportFailure(report);
  const expectedStatus = failed ? "failed" : "passed";
  const expectedExitCode = failed ? 1 : 0;
  if (receipt.status !== expectedStatus
    || receipt.exitCode !== expectedExitCode
    || receipt.signal !== null
    || receipt.reason !== null) {
    throw new Error("Quality report receipt does not match the report's deterministic outcome.");
  }
}

function readCanonicalJson(relativePath, root, subtree, options = {}) {
  const bytes = readEvidenceBytes(relativePath, root, subtree, options);
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw new Error(`Evidence JSON is invalid at ${relativePath}: ${error.message}`);
  }
  const canonicalBytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  if (!bytes.equals(canonicalBytes)) {
    throw new Error(`Evidence JSON is not in its exact canonical form: ${relativePath}.`);
  }
  return { bytes, value };
}

function readEvidenceBytes(relativePath, root, subtree, options = {}) {
  const target = resolveExistingRepositoryFile(relativePath, root, { subtree });
  return withStableSingleLinkFile(target, {
    errorMessage: `Evidence file is unsafe or changed: ${relativePath}.`,
    fileSystem: options.fileSystem,
    maximumBytes: MAX_EVIDENCE_BYTES,
    minimumBytes: 0,
  }, bytes => Buffer.from(bytes));
}

function assertExactKeys(value, expected, label) {
  const actual = value && typeof value === "object" && !Array.isArray(value)
    ? Object.keys(value).sort()
    : [];
  if (!isDeepStrictEqual(actual, [...expected].sort())) {
    throw new Error(`${label} fields do not match schemaVersion 1.`);
  }
}

function parseArguments(argv) {
  let profile = "fast";
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--gate-profile") profile = argv[++index];
    else if (argument.startsWith("--gate-profile=")) profile = argument.slice(15);
    else throw new Error(`Unknown evidence-handoff option: ${String(argument)}`);
  }
  if (!["fast", "full", "release"].includes(profile)) {
    throw new Error("Evidence handoff profile must be fast, full, or release.");
  }
  return { profile };
}

function main() {
  try {
    const result = verifyEvidenceHandoff(parseArguments(process.argv.slice(2)));
    console.log(
      `Quality evidence handoff: trusted (${result.summary.key.fingerprint}).`
    );
  } catch (error) {
    console.error(`quality:verify-evidence: ${error.message}`);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  parseArguments,
  readCanonicalJson,
  validateGateGenerationProgress,
  validateGateGenerationSemantics,
  validateGateStepArtifactClaim,
  validateStepArtifacts,
  validateStepTestEvidence,
  validateReportExecution,
  verifyEvidenceHandoff,
};

// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const { TextDecoder } = require("util");
const {
  ROOT,
  isPlainObject,
  readJson,
  resolveExistingRepositoryFile,
  resolveOptionalRepositoryFile,
  uniqueSorted,
} = require("./common");
const { fingerprint, sourceIdentity } = require("./evidence");
const {
  assertMutationTestOwners,
  assertValidMutationBaseline,
  assertCanonicalMutationRuntime,
  bindMutationSummaryKey,
  deriveMutationEvidence,
  fullMutationSelection,
  readMutationReportArtifact,
  receipt,
  resolveMutationSelection,
  selectMutationTargets,
  validateMutationSummary,
  validateMutationTestOwnership,
  workingTreeFingerprint,
} = require("./run-mutation");

const RAW_REPORT = ".quality/mutation/mutation.json";

function parseArguments(argumentsList = process.argv.slice(2), environment = process.env) {
  const options = {
    base: environment.QUALITY_BASE || "origin/main",
    expectedExitCode: environment.EXPECTED_MUTATION_EXIT_CODE || null,
    expectedRunOutcome: environment.EXPECTED_MUTATION_OUTCOME || null,
    expectedSourceSha: environment.EXPECTED_SOURCE_SHA || null,
    mode: "changed",
  };
  const seen = new Set();
  for (let index = 0; index < argumentsList.length; index += 1) {
    const argument = argumentsList[index];
    let name;
    let value;
    if (["--base", "--expected-exit-code", "--expected-run-outcome", "--expected-source-sha", "--mode"].includes(argument)) {
      name = argument.slice(2);
      value = argumentsList[++index];
    } else if (/^--(?:base|expected-exit-code|expected-run-outcome|expected-source-sha|mode)=/u.test(argument)) {
      const separator = argument.indexOf("=");
      name = argument.slice(2, separator);
      value = argument.slice(separator + 1);
    } else {
      throw new Error(`Unknown mutation handoff option: ${String(argument)}`);
    }
    if (typeof value !== "string" || value.length === 0 || value !== value.trim()) {
      throw new Error(`--${name} requires one nonempty canonical value.`);
    }
    if (seen.has(name)) throw new Error(`--${name} may be specified only once.`);
    seen.add(name);
    const property = name.replace(/-([a-z])/gu, (_match, letter) => letter.toUpperCase());
    options[property] = value;
  }
  if (options.expectedSourceSha !== null
    && !/^[a-f0-9]{40}$/u.test(options.expectedSourceSha)) {
    throw new Error("Expected mutation source SHA must be a full lowercase commit SHA.");
  }
  if (options.expectedRunOutcome !== null
    && !new Set(["success", "failure"]).has(options.expectedRunOutcome)) {
    throw new Error("Expected mutation run outcome must be success or failure.");
  }
  if (options.expectedExitCode !== null) {
    if (!/^(?:0|[1-9]\d{0,2})$/u.test(options.expectedExitCode)
      || Number(options.expectedExitCode) > 255) {
      throw new Error("Expected mutation process exit code must be an integer from 0 through 255.");
    }
    options.expectedExitCode = Number(options.expectedExitCode);
  }
  if (!new Set(["changed", "core"]).has(options.mode)) {
    throw new Error("Mutation handoff mode must be changed or core.");
  }
  return options;
}

function readCanonicalJsonArtifact(relativePath, root = ROOT, maximumBytes = 4 * 1024 * 1024) {
  const target = resolveExistingRepositoryFile(relativePath, root, {
    subtree: ".quality/mutation",
  });
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
  let descriptor = null;
  try {
    descriptor = fs.openSync(target, flags);
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.size <= 0 || stat.size > maximumBytes) {
      throw new Error(`${relativePath} must be a bounded nonempty regular file.`);
    }
    const bytes = fs.readFileSync(descriptor);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const value = JSON.parse(text);
    if (!isPlainObject(value)) throw new Error(`${relativePath} must contain one JSON object.`);
    const canonical = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    if (!bytes.equals(canonical)) {
      throw new Error(`${relativePath} is not the exact canonical JSON serialization.`);
    }
    return { bytes, value };
  } finally {
    if (descriptor !== null) fs.closeSync(descriptor);
  }
}

function exactValue(left, right) {
  return fingerprint(left) === fingerprint(right);
}

function expectedApplicableSummary({
  baseline,
  exitCode,
  mode,
  rawFingerprint,
  rawReport,
  root,
  selection,
  source,
  targets,
}) {
  validateMutationTestOwnership(rawReport, targets, baseline, root, mode);
  const candidate = receipt(mode, targets, {
    status: "passed",
    ...deriveMutationEvidence(rawReport, targets),
    strykerExitCode: exitCode,
  }, {
    source,
    selection,
    rawReportFingerprint: rawFingerprint,
  });
  try {
    if (!Number.isInteger(exitCode) || exitCode < 0) {
      throw new Error("Mutation summary has no canonical Stryker exit code.");
    }
    if (exitCode !== 0) throw new Error(`Stryker exited ${String(exitCode)}.`);
    validateMutationSummary(candidate, baseline, mode);
    return candidate;
  } catch (error) {
    const failed = { ...candidate, status: "failed", reason: error.message };
    delete failed.key;
    return bindMutationSummaryKey(failed);
  }
}

function validateMutationEvidenceArtifacts(options) {
  const {
    baseline,
    expectedExitCode = null,
    expectedRunOutcome = null,
    expectedSourceSha = null,
    rawReportArtifact,
    root = ROOT,
    selection,
    source,
    summary,
    mode = "changed",
  } = options;
  if (!new Set(["changed", "core"]).has(mode)) {
    throw new Error("Mutation evidence has an invalid handoff mode.");
  }
  if (!exactValue(summary?.source, source)
    || summary?.sourceSha !== source.sha
    || !exactValue(summary?.selection, selection)
    || summary?.workingTreeFingerprint !== selection.fingerprint
    || selection.fingerprint !== workingTreeFingerprint(root, selection.changedFiles)) {
    throw new Error("Mutation summary does not bind the current source and exact target selection.");
  }
  if (expectedSourceSha !== null && source.sha !== expectedSourceSha) {
    throw new Error("Mutation evidence source does not match the expected CI checkout SHA.");
  }
  const targets = mode === "core"
    ? uniqueSorted(baseline.scope)
    : selectMutationTargets(baseline.scope, selection.changedFiles, baseline.files);
  let expected;
  if (targets.length === 0) {
    if (rawReportArtifact !== null) {
      throw new Error("Not-applicable mutation evidence must not retain a raw report.");
    }
    expected = receipt(mode, [], {
      status: "not-applicable",
      reason: "no-configured-mutation-target-changed",
      mutants: 0,
      killed: 0,
      survived: 0,
      timeout: 0,
      noCoverage: 0,
      runtimeError: 0,
      compileError: 0,
      ignored: 0,
      score: null,
      files: {},
      survivors: [],
      strykerExitCode: null,
    }, { source, selection, rawReportFingerprint: null });
  } else {
    if (rawReportArtifact === null) {
      throw new Error("Applicable mutation evidence is missing its exact raw report.");
    }
    const rawFingerprint = crypto.createHash("sha256")
      .update(rawReportArtifact.bytes)
      .digest("hex");
    if (summary.rawReportFingerprint !== rawFingerprint
      || rawReportArtifact.fingerprint !== rawFingerprint) {
      throw new Error("Mutation summary does not bind the exact raw report bytes.");
    }
    expected = expectedApplicableSummary({
      baseline,
      exitCode: summary.strykerExitCode,
      mode,
      rawFingerprint,
      rawReport: rawReportArtifact.value,
      root,
      selection,
      source,
      targets,
    });
  }
  if (!exactValue(summary, expected)) {
    throw new Error("Mutation summary is not the exact independently derived handoff evidence.");
  }
  if (expectedRunOutcome === "success"
    && !new Set(["passed", "not-applicable"]).has(summary.status)) {
    throw new Error("Successful mutation execution produced failure evidence.");
  }
  if (expectedRunOutcome === "failure" && summary.status !== "failed") {
    throw new Error("Failed mutation execution did not produce exact trusted-failure evidence.");
  }
  if (expectedExitCode !== null) {
    const derivedProcessExitCode = summary.status === "failed"
      ? (summary.strykerExitCode === 0 ? 1 : summary.strykerExitCode)
      : 0;
    if (expectedExitCode !== derivedProcessExitCode) {
      throw new Error("Mutation summary does not match the independently captured process exit code.");
    }
  }
  return { source, selection, status: summary.status, targets };
}

function verifyMutationEvidenceHandoff(options = {}) {
  const root = options.root || ROOT;
  const base = options.base || "origin/main";
  const mode = options.mode || "changed";
  const sourceBefore = sourceIdentity(root);
  const baseline = readJson("quality/mutation-baseline.json", root);
  assertCanonicalMutationRuntime(baseline, root);
  assertValidMutationBaseline(baseline, root);
  assertMutationTestOwners(baseline, root);
  const selection = mode === "core"
    ? fullMutationSelection(root)
    : resolveMutationSelection(["--base", base], root);
  const sourceAfterSelection = sourceIdentity(root);
  if (!exactValue(sourceBefore, sourceAfterSelection)) {
    throw new Error("Mutation source changed while resolving its comparison set.");
  }
  const summary = readCanonicalJsonArtifact(
    `.quality/mutation/summary-${mode}.json`,
    root
  ).value;
  const rawPath = resolveOptionalRepositoryFile(RAW_REPORT, root, {
    subtree: ".quality/mutation",
  });
  const rawReportArtifact = rawPath ? readMutationReportArtifact(root) : null;
  const result = validateMutationEvidenceArtifacts({
    baseline,
    expectedExitCode: options.expectedExitCode ?? null,
    expectedRunOutcome: options.expectedRunOutcome || null,
    expectedSourceSha: options.expectedSourceSha || null,
    mode,
    rawReportArtifact,
    root,
    selection,
    source: sourceBefore,
    summary,
  });
  const sourceAfter = sourceIdentity(root);
  const finalSelection = mode === "core"
    ? fullMutationSelection(root)
    : resolveMutationSelection(["--base", base], root);
  const sourceFinal = sourceIdentity(root);
  if (!exactValue(sourceBefore, sourceAfter)
    || !exactValue(sourceAfter, sourceFinal)
    || !exactValue(selection, finalSelection)) {
    throw new Error("Mutation source or target selection changed during handoff verification.");
  }
  return { ...result, mode };
}

function main() {
  const options = parseArguments();
  const result = verifyMutationEvidenceHandoff(options);
  console.log(
    `Verified exact ${result.status} ${result.mode} mutation evidence for ${result.source.sha} `
    + `(${result.targets.length} target${result.targets.length === 1 ? "" : "s"}).`
  );
}

module.exports = {
  parseArguments,
  readCanonicalJsonArtifact,
  validateMutationEvidenceArtifacts,
  verifyMutationEvidenceHandoff,
};

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(`quality:verify-mutation-evidence: ${error.message}`);
    process.exitCode = 1;
  }
}

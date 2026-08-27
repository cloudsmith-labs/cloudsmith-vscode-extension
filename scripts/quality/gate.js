// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const { spawnSync } = require("child_process");
const {
  ROOT,
  discoverRepositoryOutputFiles,
  removeOutputFile,
  resolveExistingRepositoryFile,
  writeJson,
} = require("./common");
const { aggregateStatuses, fingerprint, sourceIdentity } = require("./evidence");
const { buildNonAuthQualityEnvironment } = require("./non-auth-environment");
const {
  STANDALONE_NODE_TESTS,
  VSCODE_CORE_TESTS,
  VSCODE_SMOKE_TESTS,
} = require("../../test/testInventories");

const TEST_INVENTORIES_BY_SUITE = Object.freeze({
  "standalone-tests": STANDALONE_NODE_TESTS,
  "extension-host-core": VSCODE_CORE_TESTS,
  "extension-host-smoke": VSCODE_SMOKE_TESTS,
});

const PHASE_STEPS = Object.freeze({
  fast: Object.freeze([
    "quality-contract-verifier",
    "secret-current",
    "change-impact",
    "repository-check",
    "standalone-tests",
  ]),
  full: Object.freeze([
    "extension-host-core",
    "extension-host-smoke",
    "runtime-audit",
    "development-audit",
    "zero-test-guard",
    "changed-mutation",
    "package-build",
    "package-verify",
    "package-list",
    "secret-artifacts",
  ]),
  release: Object.freeze([
    "black-box-ui-smoke",
    "secret-release",
    "release-checklist",
    "secret-history",
  ]),
});

const STEP_CATALOG = Object.freeze({
  "quality-contract-verifier": commandStep(
    "quality-contract-verifier",
    "contracts",
    "node",
    ["scripts/quality/verify.js"]
  ),
  "secret-current": Object.freeze({
    ...commandStep(
      "secret-current",
      "security",
      "node",
      ["scripts/quality/secret-scan.js", "current"]
    ),
    artifactPath: ".quality/secrets/current.json",
    artifactSubtree: ".quality/secrets",
  }),
  "change-impact": Object.freeze({
    ...commandStep(
      "change-impact",
      "impact",
      "node",
      ["scripts/quality/impact.js"]
    ),
    artifactPath: ".quality/impact.json",
    artifactSubtree: ".quality",
  }),
  "repository-check": commandStep(
    "repository-check",
    "architecture-polish-version",
    "npm",
    ["run", "check"]
  ),
  "standalone-tests": evidenceStep(commandStep(
    "standalone-tests",
    "tests",
    "npm",
    ["run", "test:node"]
  )),
  "extension-host-core": evidenceStep(commandStep(
    "extension-host-core",
    "tests",
    "node",
    ["scripts/run-vscode-tests.js", "--label", "core"]
  )),
  "extension-host-smoke": evidenceStep(commandStep(
    "extension-host-smoke",
    "tests",
    "node",
    ["scripts/run-vscode-tests.js", "--label", "smoke"]
  )),
  "runtime-audit": commandStep(
    "runtime-audit",
    "audit",
    "npm",
    ["run", "audit:runtime"]
  ),
  "development-audit": commandStep(
    "development-audit",
    "audit",
    "npm",
    ["run", "audit:dev"]
  ),
  "zero-test-guard": commandStep(
    "zero-test-guard",
    "test-effectiveness",
    "npm",
    ["run", "test:zero-guard"]
  ),
  "changed-mutation": Object.freeze({
    ...commandStep(
      "changed-mutation",
      "mutation",
      "node",
      ["scripts/quality/run-mutation.js", "changed"]
    ),
    artifactPath: ".quality/mutation/summary-changed.json",
  }),
  "package-build": commandStep(
    "package-build",
    "package",
    "npm",
    ["run", "package"]
  ),
  "package-verify": commandStep(
    "package-verify",
    "package",
    "npm",
    ["run", "package:verify"]
  ),
  "package-list": commandStep(
    "package-list",
    "package",
    "npm",
    ["run", "package:list"]
  ),
  "secret-artifacts": Object.freeze({
    ...commandStep(
      "secret-artifacts",
      "security",
      "node",
      ["scripts/quality/secret-scan.js", "artifacts"]
    ),
    artifactPath: ".quality/secrets/artifacts.json",
    artifactSubtree: ".quality/secrets",
  }),
  "black-box-ui-smoke": Object.freeze({
    ...commandStep(
      "black-box-ui-smoke",
      "tests",
      "node",
      ["scripts/quality/run-ui-smoke.js"]
    ),
    artifactPath: ".quality/ui/result.json",
    artifactSubtree: ".quality/ui",
    blockedExitCodes: Object.freeze([2]),
  }),
  "secret-release": Object.freeze({
    ...commandStep(
      "secret-release",
      "security",
      "node",
      ["scripts/quality/release-exposure-scan.js"]
    ),
    artifactPath: ".quality/secrets/release.json",
    artifactSubtree: ".quality/secrets",
  }),
  "release-checklist": Object.freeze({
    ...commandStep(
      "release-checklist",
      "live-qualification",
      "node",
      ["scripts/quality/release-checklist.js"]
    ),
    artifactPath: ".quality/gates/live-qualification-status.json",
    artifactSubtree: ".quality/gates",
    blockedExitCodes: Object.freeze([2]),
    runWhenBlocked: true,
  }),
  "secret-history": Object.freeze({
    ...commandStep(
      "secret-history",
      "security",
      "node",
      ["scripts/quality/secret-scan.js", "history"]
    ),
    artifactPath: ".quality/secrets/history.json",
    artifactSubtree: ".quality/secrets",
    runWhenBlocked: true,
  }),
});

function commandStep(id, category, executable, args) {
  return Object.freeze({
    id,
    category,
    executable,
    args: Object.freeze([...args]),
    command: [executable, ...args].join(" "),
  });
}

function evidenceStep(step) {
  return Object.freeze({
    ...step,
    evidencePath: `.quality/test-results/${step.id}.json`,
  });
}

function reportStep(profile) {
  return {
    ...commandStep(
      "quality-report",
      "report",
      "node",
      ["scripts/quality/report.js", "--gate-profile", profile]
    ),
    artifactPaths: Object.freeze([
      ".quality/report.json",
      ".quality/report.md",
    ]),
    artifactSubtree: ".quality",
    runWhenBlocked: true,
  };
}

function getGatePlan(profile) {
  if (!Object.prototype.hasOwnProperty.call(PHASE_STEPS, profile)) {
    throw new Error(`Quality gate profile must be fast, full, or release; received ${String(profile)}.`);
  }
  const phases = profile === "fast"
    ? ["fast"]
    : profile === "full"
      ? ["fast", "full"]
      : ["fast", "full", "release"];
  const steps = phases.flatMap(phase => PHASE_STEPS[phase].map(id => STEP_CATALOG[id]));
  steps.push(reportStep(profile));
  return steps.map((step, index) => ({
    ...step,
    args: [...step.args],
    blockedExitCodes: [...(step.blockedExitCodes || [])],
    sequence: index + 1,
  }));
}

function runGate(options = {}) {
  const root = options.root || ROOT;
  const profile = options.profile || "fast";
  const plan = options.plan || getGatePlan(profile);
  const readSource = options.readSource
    || (options.source ? () => options.source : () => sourceIdentity(root));
  const source = options.source || readSource();
  const execute = options.execute || executeCommand;
  clearGateReceipts(root, profile);
  for (const step of plan) clearStepOutputs(step, root);
  const receipts = plan.map(step => plannedReceipt(profile, step, source));
  for (const receipt of receipts) writeReceipt(root, receipt);

  let priorBlocker = null;
  for (let index = 0; index < plan.length; index += 1) {
    const step = plan[index];
    if (priorBlocker && !step.runWhenBlocked) {
      receipts[index] = {
        ...receipts[index],
        reason: `blocked-by:${priorBlocker}`,
      };
      writeReceipt(root, receipts[index]);
      continue;
    }
    const before = readSource();
    const sourceChangedBefore = !sameSource(before, source);
    if (sourceChangedBefore && !step.runWhenBlocked) {
      receipts[index] = {
        ...receipts[index],
        status: "failed",
        reason: "source-changed-before-step",
      };
      writeReceipt(root, receipts[index]);
      if (!priorBlocker) priorBlocker = step.id;
      continue;
    }
    const execution = execute(step, { root, profile, source });
    receipts[index] = completedReceipt(profile, step, source, execution);
    const after = readSource();
    if (sourceChangedBefore) {
      receipts[index] = {
        ...receipts[index],
        status: "failed",
        reason: "source-changed-before-step",
      };
    } else if (!sameSource(after, source)) {
      receipts[index] = {
        ...receipts[index],
        status: "failed",
        reason: "source-changed-during-step",
      };
    }
    writeReceipt(root, receipts[index]);
    if (["failed", "blocked"].includes(receipts[index].status) && !priorBlocker) {
      priorBlocker = step.id;
    }
  }

  const status = aggregateStatuses(receipts.map(receipt => receipt.status));
  const summary = {
    schemaVersion: 1,
    profile,
    source,
    status,
    planFingerprint: gatePlanFingerprint(plan),
    steps: receipts,
  };
  summary.key = {
    sha: source.sha,
    fingerprint: fingerprint(summary),
  };
  writeJson(`.quality/gates/${profile}.json`, summary, root);
  return summary;
}

function gatePlanFingerprint(plan) {
  return fingerprint(plan.map(step => ({
    id: step.id,
    category: step.category,
    command: step.command,
    artifactPath: step.artifactPath || null,
    artifactPaths: [...(step.artifactPaths || [])],
    artifactSubtree: step.artifactSubtree || null,
    blockedExitCodes: [...(step.blockedExitCodes || [])],
    evidencePath: step.evidencePath || null,
    runWhenBlocked: step.runWhenBlocked === true,
  })));
}

function clearGateReceipts(root, profile) {
  removeOutputFile(`.quality/gates/${profile}.json`, root, {
    subtree: ".quality/gates",
  });
  const directory = `.quality/gates/${profile}`;
  for (const relativePath of discoverRepositoryOutputFiles(directory, root, {
    subtree: directory,
  })) {
    removeOutputFile(relativePath, root, { subtree: directory });
  }
}

function sameSource(left, right) {
  return left?.sha === right?.sha && left?.fingerprint === right?.fingerprint;
}

function plannedReceipt(profile, step, source) {
  return {
    schemaVersion: 1,
    profile,
    sequence: step.sequence,
    stepId: step.id,
    category: step.category,
    command: step.command,
    source,
    status: "not-run",
    exitCode: null,
    signal: null,
    reason: "not-started",
    testCounts: null,
    artifactFingerprint: null,
  };
}

function completedReceipt(profile, step, source, execution = {}) {
  const exitCode = Number.isInteger(execution.status) ? execution.status : null;
  const signal = execution.signal || null;
  const error = execution.error?.message || null;
  let status = "failed";
  if (!error && !signal && exitCode === 0) status = "passed";
  else if (!error && !signal && step.blockedExitCodes.includes(exitCode)) status = "blocked";
  const evidenceError = status === "passed" && step.evidencePath
    ? validateTestEvidence(execution.testEvidence, step, source)
    : null;
  const artifactError = ["passed", "blocked"].includes(status) && stepArtifactPaths(step).length > 0
    && !/^[a-f0-9]{64}$/u.test(execution.artifactFingerprint || "")
    ? "missing-or-invalid-artifact-fingerprint"
    : null;
  if (evidenceError || artifactError) status = "failed";
  const output = `${execution.stdout || ""}${execution.stderr || ""}`;
  return {
    schemaVersion: 1,
    profile,
    sequence: step.sequence,
    stepId: step.id,
    category: step.category,
    command: step.command,
    source,
    status,
    exitCode,
    signal,
    reason: error || (signal ? `terminated-by:${signal}` : evidenceError || artifactError),
    testCounts: parseTestCounts(output),
    outputFingerprint: crypto.createHash("sha256").update(output).digest("hex"),
    testEvidence: execution.testEvidence || null,
    artifactFingerprint: execution.artifactFingerprint || null,
  };
}

function executeCommand(step, context = {}) {
  const root = context.root || ROOT;
  const executable = resolveExecutable(step.executable);
  const spawn = context.spawnSync || spawnSync;
  clearStepOutputs(step, root);
  const evidenceEnvironment = step.evidencePath ? {
    CLOUDSMITH_QUALITY_SOURCE_SHA: context.source?.sha || "",
    CLOUDSMITH_QUALITY_SOURCE_FINGERPRINT: context.source?.fingerprint || "",
    CLOUDSMITH_QUALITY_TEST_EVIDENCE: step.evidencePath,
    CLOUDSMITH_QUALITY_TEST_SUITE: step.id,
  } : {};
  const environment = buildNonAuthQualityEnvironment(
    context.environment || process.env,
    evidenceEnvironment,
    { platform: context.platform }
  );
  const result = spawn(executable, step.args, {
    cwd: root,
    encoding: "utf8",
    env: environment,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  let artifactFingerprint = null;
  let artifactError = null;
  if (stepArtifactPaths(step).length > 0) {
    try {
      artifactFingerprint = artifactFingerprintForStep(step, root);
    } catch (error) {
      artifactError = `missing-or-invalid-artifact:${error.message}`;
    }
  }
  if (!step.evidencePath) {
    if (result.status === 0 && artifactError) {
      return { ...result, error: new Error(artifactError), artifactFingerprint };
    }
    return { ...result, artifactFingerprint };
  }
  let testEvidence = null;
  let evidenceError = null;
  try {
    testEvidence = JSON.parse(fs.readFileSync(
      resolveExistingRepositoryFile(step.evidencePath, root),
      "utf8"
    ));
    evidenceError = validateTestEvidence(testEvidence, step, context.source);
  } catch (error) {
    evidenceError = `missing-or-invalid-test-evidence:${error.message}`;
  }
  if (result.status === 0 && (evidenceError || artifactError)) {
    return {
      ...result,
      error: new Error(evidenceError || artifactError),
      testEvidence,
      artifactFingerprint,
    };
  }
  return { ...result, testEvidence, artifactFingerprint };
}

function clearStepOutputs(step, root) {
  if (step.evidencePath) removeOutputFile(step.evidencePath, root, {
    subtree: ".quality/test-results",
  });
  for (const artifactPath of stepArtifactPaths(step)) {
    removeOutputFile(artifactPath, root, {
      subtree: step.artifactSubtree || ".quality/mutation",
    });
  }
}

function stepArtifactPaths(step) {
  const declared = Array.isArray(step?.artifactPaths)
    ? step.artifactPaths
    : step?.artifactPath
      ? [step.artifactPath]
      : [];
  if (declared.length !== new Set(declared).size) {
    throw new Error(`Quality step ${String(step?.id)} declares duplicate artifact paths.`);
  }
  return declared;
}

function artifactFingerprintForStep(step, root = ROOT) {
  const artifactPaths = stepArtifactPaths(step);
  if (artifactPaths.length === 0) return null;
  const subtree = step.artifactSubtree || ".quality/mutation";
  const artifacts = artifactPaths.map(relativePath => ({
    relativePath,
    bytes: fs.readFileSync(resolveExistingRepositoryFile(relativePath, root, { subtree })),
  }));
  if (artifacts.length === 1) {
    return crypto.createHash("sha256").update(artifacts[0].bytes).digest("hex");
  }
  const hash = crypto.createHash("sha256");
  hash.update("cloudsmith-quality-artifact-bundle-v1\0");
  for (const artifact of artifacts) {
    hash.update(`${artifact.relativePath}\0${artifact.bytes.length}\0`);
    hash.update(artifact.bytes);
    hash.update("\0");
  }
  return hash.digest("hex");
}

function validateArtifactBinding(receipt, step, root = ROOT) {
  if (!/^[a-f0-9]{64}$/u.test(receipt?.artifactFingerprint || "")) {
    return "missing-or-invalid-artifact-fingerprint";
  }
  try {
    return artifactFingerprintForStep(step, root) === receipt.artifactFingerprint
      ? null
      : "artifact-fingerprint-mismatch";
  } catch (error) {
    return `missing-or-invalid-artifact:${error.message}`;
  }
}

function validateTestEvidence(value, step, source) {
  if (value?.schemaVersion !== 1) return "invalid-schema";
  if (value?.source?.sha !== source?.sha
    || value?.source?.fingerprint !== source?.fingerprint) return "source-mismatch";
  if (value?.suite !== step.id) return "suite-mismatch";
  if (!Array.isArray(value.tests) || value.tests.length === 0) return "zero-tests";
  const seen = new Set();
  const seenFiles = new Set();
  for (const test of value.tests) {
    if (!/^test\/[A-Za-z0-9_./-]+\.test\.js$/u.test(test?.file || "")
      || typeof test?.title !== "string"
      || test.title.length === 0
      || typeof test?.fullTitle !== "string"
      || test.fullTitle.length === 0
      || !["passed", "failed", "pending"].includes(test?.status)) return "invalid-test-record";
    const key = `${test.file}\0${test.fullTitle}`;
    if (seen.has(key)) return "duplicate-test-record";
    seen.add(key);
    seenFiles.add(test.file);
  }
  const counted = {
    passed: value.tests.filter(test => test.status === "passed").length,
    failed: value.tests.filter(test => test.status === "failed").length,
    pending: value.tests.filter(test => test.status === "pending").length,
  };
  for (const name of Object.keys(counted)) {
    if (value.counts?.[name] !== counted[name]) return "count-mismatch";
  }
  const expectedFiles = TEST_INVENTORIES_BY_SUITE[step.id];
  if (expectedFiles && JSON.stringify([...seenFiles])
    !== JSON.stringify(expectedFiles)) return "suite-inventory-mismatch";
  if (counted.failed > 0 || counted.pending > 0) return "nonpassing-test-record";
  return null;
}

function resolveExecutable(executable) {
  if (executable === "node") return process.execPath;
  if (executable === "npm" && process.platform === "win32") return "npm.cmd";
  return executable;
}

function parseTestCounts(output) {
  const counts = {};
  for (const [name, expression] of [
    ["passing", /(?:^|\s)(\d+) passing\b/u],
    ["failing", /(?:^|\s)(\d+) failing\b/u],
    ["pending", /(?:^|\s)(\d+) pending\b/u],
  ]) {
    const matches = [...String(output).matchAll(new RegExp(expression.source, "gu"))];
    if (matches.length > 0) counts[name] = Number(matches[matches.length - 1][1]);
  }
  return Object.keys(counts).length > 0 ? counts : null;
}

function receiptPath(receipt) {
  const order = String(receipt.sequence).padStart(2, "0");
  return `.quality/gates/${receipt.profile}/${order}-${receipt.stepId}.json`;
}

function writeReceipt(root, receipt) {
  return writeJson(receiptPath(receipt), receipt, root);
}

function parseArguments(argv) {
  if (argv.length !== 1 || !["fast", "full", "release"].includes(argv[0])) {
    throw new Error("Usage: node scripts/quality/gate.js <fast|full|release>");
  }
  return { profile: argv[0] };
}

function main() {
  try {
    const summary = runGate(parseArguments(process.argv.slice(2)));
    console.log(`Quality ${summary.profile} gate: ${summary.status}.`);
    if (summary.status !== "passed") process.exitCode = 1;
  } catch (error) {
    console.error(`quality:gate: ${error.message}`);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  PHASE_STEPS,
  STEP_CATALOG,
  artifactFingerprintForStep,
  completedReceipt,
  executeCommand,
  gatePlanFingerprint,
  getGatePlan,
  parseArguments,
  parseTestCounts,
  receiptPath,
  runGate,
  sameSource,
  stepArtifactPaths,
  validateArtifactBinding,
  validateTestEvidence,
};

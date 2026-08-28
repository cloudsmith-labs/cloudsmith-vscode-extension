// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const { isDeepStrictEqual, types } = require("util");
const {
  ROOT,
  assertRealRepositoryRoot,
  removeOutputFile,
  resolveExistingRepositoryFile,
  writeJson,
} = require("./common");
const {
  withStableSingleLinkFile,
} = require("./candidate-binding");
const { aggregateStatuses, fingerprint, sourceIdentity } = require("./evidence");
const {
  removeExactOwnedDirectoryTree,
  withNonAuthQualityEnvironment,
} = require("./non-auth-environment");
const {
  assertCanonicalNpmRuntime,
  assertCanonicalNodeRuntime,
  assertExactNodeExecutable,
  assertNoNpmToolchainShadowing,
  canonicalToolchainEnvironment,
  withCanonicalNpmLauncher,
} = require("./canonical-node-runtime");
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

const MAX_GATE_ARTIFACT_BYTES = 64 * 1024 * 1024;
const MAX_GATE_TEST_EVIDENCE_BYTES = 64 * 1024 * 1024;
const GATE_RECEIPT_FILENAME = /^\d{2,}-[a-z0-9][a-z0-9-]*\.json$/u;
const EXECUTION_ERROR_REASON = "execution-error";
const EXECUTION_RESULT_FIELDS = Object.freeze([
  "artifactFingerprint",
  "signal",
  "status",
  "stderr",
  "stdout",
  "testEvidence",
  "testEvidenceFingerprint",
]);

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
  const root = assertRealRepositoryRoot(options.root || ROOT);
  const validateRuntime = options.assertCanonicalNodeRuntime || assertCanonicalNodeRuntime;
  validateRuntime(root, process.version);
  const profile = options.profile || "fast";
  if (!Object.prototype.hasOwnProperty.call(PHASE_STEPS, profile)) {
    throw new Error("Quality gate profile must be fast, full, or release.");
  }
  const plan = options.plan || getGatePlan(profile);
  assertGateReceiptPlan(profile, plan);
  const execute = options.execute || executeCommand;
  const runtimeExecutable = process.execPath;
  const npmExecPath = options.npmExecPath ?? process.env.npm_execpath;
  let npm;
  if (execute === executeCommand) {
    assertExactNodeExecutable(runtimeExecutable, { platform: options.platform });
    canonicalToolchainEnvironment(options.environment || process.env, {
      nodeExecutable: runtimeExecutable,
      platform: options.platform,
    });
    if (plan.some(step => step.executable === "npm")) {
      npm = assertCanonicalNpmRuntime(root, npmExecPath, {
        nodeExecutable: runtimeExecutable,
        platform: options.platform,
      });
      assertNoNpmToolchainShadowing(root, { platform: options.platform });
    }
    for (const step of plan) resolveGateExecution(step, {
      npm,
      npmExecPath,
      platform: options.platform,
      root,
      runtimeExecutable,
    });
  }
  const readSource = options.readSource
    || (options.source ? () => options.source : () => sourceIdentity(root));
  const source = options.source || readSource();
  if (npm) {
    npm = assertCanonicalNpmRuntime(root, npm.cliPath, {
      nodeExecutable: runtimeExecutable,
      platform: options.platform,
    });
    assertNoNpmToolchainShadowing(root, { platform: options.platform });
  }
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
    const execution = bindExecutionTestEvidence(
      execute(step, {
        environment: options.environment,
        npm,
        npmExecPath,
        platform: options.platform,
        profile,
        root,
        runtimeExecutable,
        source,
        spawnSync: options.spawnSync,
        temporaryParent: options.temporaryParent,
      }),
      step,
      root,
    );
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
    receipts[index] = revalidateArtifactReceipt(
      receipts[index],
      step,
      root,
      "artifact-changed-before-receipt",
    );
    receipts[index] = revalidateTestEvidenceReceipt(
      receipts[index],
      step,
      root,
      "test-evidence-changed-before-receipt",
    );
    writeReceipt(root, receipts[index]);
    let persistedReceipt = revalidateArtifactReceipt(
      receipts[index],
      step,
      root,
      "artifact-changed-during-receipt-persistence",
    );
    persistedReceipt = revalidateTestEvidenceReceipt(
      persistedReceipt,
      step,
      root,
      "test-evidence-changed-during-receipt-persistence",
    );
    if (persistedReceipt !== receipts[index]) {
      receipts[index] = persistedReceipt;
      invalidateReceipt(root, receipts[index]);
      writeReceipt(root, receipts[index]);
    }
    if (["failed", "blocked"].includes(receipts[index].status) && !priorBlocker) {
      priorBlocker = step.id;
    }
  }

  return persistStableGateSummary(root, profile, source, plan, receipts);
}

function assertGateReceiptPlan(profile, plan) {
  if (!Array.isArray(plan) || plan.length === 0) {
    throw new Error("Quality gate plan cannot produce a safe exact receipt tree.");
  }
  const paths = plan.map(step => receiptPath({
    profile,
    sequence: step?.sequence,
    stepId: step?.id,
  }));
  if (paths.length !== new Set(paths).size || paths.some(relativePath => (
    path.posix.normalize(relativePath) !== relativePath
    || path.posix.dirname(relativePath) !== `.quality/gates/${profile}`
    || !GATE_RECEIPT_FILENAME.test(path.posix.basename(relativePath))
  ))) {
    throw new Error("Quality gate plan cannot produce a safe exact receipt tree.");
  }
  return true;
}

function revalidateArtifactReceipt(receipt, step, root, reason) {
  if (!["passed", "blocked"].includes(receipt.status)
    || stepArtifactPaths(step).length === 0) {
    return receipt;
  }
  if (validateArtifactBinding(receipt, step, root) === null) return receipt;
  return {
    ...receipt,
    status: "failed",
    reason,
  };
}

function revalidateTestEvidenceReceipt(receipt, step, root, reason) {
  if (receipt.status !== "passed" || !step.evidencePath) return receipt;
  if (validateTestEvidenceBinding(receipt, step, root) === null) return receipt;
  return {
    ...receipt,
    status: "failed",
    reason,
  };
}

function revalidateReceiptBindings(receipts, plan, root, reasons) {
  const changed = [];
  for (let index = 0; index < receipts.length; index += 1) {
    let next = revalidateArtifactReceipt(
      receipts[index],
      plan[index],
      root,
      reasons.artifact,
    );
    next = revalidateTestEvidenceReceipt(
      next,
      plan[index],
      root,
      reasons.testEvidence,
    );
    if (next !== receipts[index]) {
      receipts[index] = next;
      changed.push(index);
    }
  }
  return changed;
}

function gateSummary(profile, source, plan, receipts) {
  const summary = {
    schemaVersion: 1,
    profile,
    source,
    status: aggregateStatuses(receipts.map(receipt => receipt.status)),
    planFingerprint: gatePlanFingerprint(plan),
    steps: receipts,
  };
  summary.key = {
    sha: source.sha,
    fingerprint: fingerprint(serializationSafeGateValue(summary)),
  };
  return summary;
}

function persistStableGateSummary(root, profile, source, plan, receipts) {
  const summaryPath = `.quality/gates/${profile}.json`;
  const maximumAttempts = plan.filter(step => (
    stepArtifactPaths(step).length > 0 || step.evidencePath
  )).length + 1;
  for (let attempt = 0; attempt < maximumAttempts; attempt += 1) {
    const changedBefore = revalidateReceiptBindings(
      receipts,
      plan,
      root,
      {
        artifact: "artifact-changed-before-summary",
        testEvidence: "test-evidence-changed-before-summary",
      },
    );
    for (const index of changedBefore) {
      invalidateReceipt(root, receipts[index]);
      writeReceipt(root, receipts[index]);
    }
    const summary = gateSummary(profile, source, plan, receipts);
    writeJson(summaryPath, serializationSafeGateValue(summary), root);
    const changedAfter = revalidateReceiptBindings(
      receipts,
      plan,
      root,
      {
        artifact: "artifact-changed-during-summary-persistence",
        testEvidence: "test-evidence-changed-during-summary-persistence",
      },
    );
    if (changedAfter.length === 0) return summary;
    invalidateSummary(root, profile);
    for (const index of changedAfter) invalidateReceipt(root, receipts[index]);
    for (const index of changedAfter) writeReceipt(root, receipts[index]);
  }
  throw new Error("Quality gate artifacts did not stabilize through summary persistence.");
}

function invalidateReceipt(root, receipt) {
  return removeOutputFile(receiptPath(receipt), root, {
    subtree: `.quality/gates/${receipt.profile}`,
  });
}

function invalidateSummary(root, profile) {
  return removeOutputFile(`.quality/gates/${profile}.json`, root, {
    subtree: ".quality/gates",
  });
}

function gatePlanFingerprint(plan) {
  return fingerprint(serializationSafeGateValue(plan.map(step => ({
    id: step.id,
    category: step.category,
    command: step.command,
    artifactPath: step.artifactPath || null,
    artifactPaths: [...(step.artifactPaths || [])],
    artifactSubtree: step.artifactSubtree || null,
    blockedExitCodes: [...(step.blockedExitCodes || [])],
    evidencePath: step.evidencePath || null,
    runWhenBlocked: step.runWhenBlocked === true,
  }))));
}

function clearGateReceipts(root, profile) {
  const repositoryRoot = assertRealRepositoryRoot(root);
  const directory = path.join(repositoryRoot, ".quality", "gates", profile);
  const summaryPath = path.join(repositoryRoot, ".quality", "gates", `${profile}.json`);
  const errorMessage = "Quality gate receipt cleanup refused an unsafe or changed tree.";
  let summaryIdentity = null;
  let directoryStat = null;
  try {
    try {
      const summaryStat = fs.lstatSync(summaryPath, { bigint: true });
      if (summaryStat.isSymbolicLink() || !summaryStat.isFile()
        || summaryStat.nlink !== 1n || summaryStat.size < 1n
        || summaryStat.size > BigInt(MAX_GATE_ARTIFACT_BYTES)
        || fs.realpathSync(summaryPath) !== summaryPath) {
        throw new Error(errorMessage);
      }
      summaryIdentity = gateCleanupIdentity(summaryStat);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    try {
      directoryStat = fs.lstatSync(directory, { bigint: true });
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    if (directoryStat && (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()
      || fs.realpathSync(directory) !== directory)) {
      throw new Error(errorMessage);
    }
    if (directoryStat) {
      const names = fs.readdirSync(directory).sort();
      const expectedRootEntries = names.map(name => {
        if (!GATE_RECEIPT_FILENAME.test(name)) throw new Error(errorMessage);
        const target = path.join(directory, name);
        const entry = fs.lstatSync(target, { bigint: true });
        if (entry.isSymbolicLink() || !entry.isFile() || entry.nlink !== 1n
          || entry.size < 1n || entry.size > BigInt(MAX_GATE_ARTIFACT_BYTES)
          || fs.realpathSync(target) !== target) {
          throw new Error(errorMessage);
        }
        return Object.freeze({
          name,
          kind: "file",
          identity: gateCleanupIdentity(entry),
        });
      });
      if (summaryIdentity) assertGateCleanupIdentity(summaryPath, summaryIdentity, errorMessage);
      removeExactOwnedDirectoryTree(directory, {
        errorMessage,
        expectedRootEntries,
        expectedRootIdentity: gateCleanupIdentity(directoryStat),
      });
    }
    if (summaryIdentity) {
      removeExactGateSummary(
        repositoryRoot,
        summaryPath,
        summaryIdentity,
        profile,
        errorMessage,
      );
    }
  } catch {
    throw new Error(errorMessage);
  }
  return Boolean(directoryStat || summaryIdentity);
}

function gateCleanupIdentity(stat) {
  return Object.freeze({
    changedNanoseconds: String(stat.ctimeNs),
    dev: String(stat.dev),
    ino: String(stat.ino),
    mode: String(stat.mode),
    modifiedNanoseconds: String(stat.mtimeNs),
    nlink: String(stat.nlink),
    size: String(stat.size),
  });
}

function assertGateCleanupIdentity(target, expected, errorMessage) {
  const stat = fs.lstatSync(target, { bigint: true });
  const current = gateCleanupIdentity(stat);
  if (stat.isSymbolicLink() || !stat.isFile()
    || fs.realpathSync(target) !== target
    || Object.keys(expected).some(key => expected[key] !== current[key])) {
    throw new Error(errorMessage);
  }
  return true;
}

function gateCleanupRenameIdentity(target, expected, errorMessage) {
  const stat = fs.lstatSync(target, { bigint: true });
  const current = gateCleanupIdentity(stat);
  const stableKeys = Object.keys(expected).filter(key => key !== "changedNanoseconds");
  if (stat.isSymbolicLink() || !stat.isFile()
    || fs.realpathSync(target) !== target
    || stableKeys.some(key => expected[key] !== current[key])) {
    throw new Error(errorMessage);
  }
  return current;
}

function removeExactGateSummary(
  repositoryRoot,
  summaryPath,
  summaryIdentity,
  profile,
  errorMessage,
) {
  const gateRoot = path.join(repositoryRoot, ".quality", "gates");
  const quarantine = path.join(
    gateRoot,
    `.gate-summary-cleanup-${profile}-${crypto.randomBytes(16).toString("hex")}`,
  );
  const movedSummary = path.join(quarantine, "summary.json");
  let quarantineIdentity = null;
  let movedSummaryIdentity = null;
  try {
    fs.mkdirSync(quarantine, { mode: 0o700 });
    const quarantineStat = fs.lstatSync(quarantine, { bigint: true });
    if (!quarantineStat.isDirectory() || quarantineStat.isSymbolicLink()
      || fs.realpathSync(quarantine) !== quarantine) {
      throw new Error(errorMessage);
    }
    quarantineIdentity = gateCleanupIdentity(quarantineStat);
    assertGateCleanupIdentity(summaryPath, summaryIdentity, errorMessage);
    fs.renameSync(summaryPath, movedSummary);
    movedSummaryIdentity = gateCleanupRenameIdentity(movedSummary, summaryIdentity, errorMessage);
    removeExactOwnedDirectoryTree(quarantine, {
      errorMessage,
      expectedRootEntries: [{
        name: "summary.json",
        kind: "file",
        identity: movedSummaryIdentity,
      }],
      expectedRootIdentity: quarantineIdentity,
    });
    return true;
  } catch {
    if (quarantineIdentity) {
      try {
        removeExactOwnedDirectoryTree(quarantine, {
          errorMessage,
          expectedRootEntries: [],
          expectedRootIdentity: quarantineIdentity,
        });
      } catch {
        // Preserve a reoccupied quarantine rather than moving or deleting an
        // unexpected entry through another non-atomic path transition.
      }
    }
    throw new Error(errorMessage);
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

function inspectExecutionProperty(execution, propertyName) {
  let current = execution;
  const visited = new Set();
  try {
    while ((typeof current === "object" && current !== null)
      || typeof current === "function") {
      if (types.isProxy(current) || visited.has(current)) {
        return Object.freeze({ state: "uninspectable", value: undefined });
      }
      visited.add(current);
      const descriptor = Object.getOwnPropertyDescriptor(current, propertyName);
      if (descriptor) {
        if (!Object.prototype.hasOwnProperty.call(descriptor, "value")) {
          return Object.freeze({ state: "accessor", value: undefined });
        }
        return Object.freeze({ state: "data", value: descriptor.value });
      }
      current = Object.getPrototypeOf(current);
    }
  } catch {
    return Object.freeze({ state: "uninspectable", value: undefined });
  }
  return Object.freeze({ state: "absent", value: undefined });
}

function validExecutionFieldValue(name, value) {
  if (value === null || value === undefined) return true;
  if ((typeof value === "object" || typeof value === "function") && types.isProxy(value)) {
    return false;
  }
  if (name === "status") return Number.isInteger(value);
  if (name === "signal") return typeof value === "string" && /^SIG[A-Z0-9]+$/u.test(value);
  if (name === "stdout" || name === "stderr") {
    return typeof value === "string" || Buffer.isBuffer(value);
  }
  if (name === "artifactFingerprint" || name === "testEvidenceFingerprint") {
    return typeof value === "string";
  }
  if (name === "testEvidence") return typeof value === "object";
  return false;
}

function inspectExecution(execution) {
  const errorProperty = inspectExecutionProperty(execution, "error");
  let executionError = errorProperty.state === "accessor"
    || errorProperty.state === "uninspectable"
    || (errorProperty.state === "data"
      && errorProperty.value !== null
      && errorProperty.value !== undefined);
  const values = Object.create(null);
  for (const name of EXECUTION_RESULT_FIELDS) {
    const property = inspectExecutionProperty(execution, name);
    if (property.state === "accessor"
      || property.state === "uninspectable"
      || (property.state === "data" && !validExecutionFieldValue(name, property.value))) {
      executionError = true;
      values[name] = undefined;
    } else {
      values[name] = property.state === "data" ? property.value : undefined;
    }
  }
  return Object.freeze({
    executionError,
    values: Object.freeze(values),
  });
}

function composeExecution(execution, overrides = {}, options = {}) {
  const snapshot = options.snapshot || inspectExecution(execution);
  const executionError = snapshot.executionError || options.forceError === true;
  const values = Object.create(null);
  for (const name of EXECUTION_RESULT_FIELDS) values[name] = snapshot.values[name];
  for (const [name, value] of Object.entries(overrides)) values[name] = value;
  const composed = {};
  Object.defineProperty(composed, "error", {
    configurable: false,
    enumerable: true,
    value: executionError ? (options.errorValue || true) : null,
    writable: false,
  });
  for (const [name, value] of Object.entries(values)) {
    Object.defineProperty(composed, name, {
      configurable: false,
      enumerable: true,
      value,
      writable: false,
    });
  }
  return composed;
}

function completedReceipt(profile, step, source, execution = {}) {
  const normalizedExecution = composeExecution(execution);
  const exitCode = Number.isInteger(normalizedExecution.status)
    ? normalizedExecution.status
    : null;
  const signal = normalizedExecution.signal === undefined ? null : normalizedExecution.signal;
  const executionError = normalizedExecution.error !== null;
  let status = "failed";
  if (!executionError && !signal && exitCode === 0) status = "passed";
  else if (!executionError && !signal && step.blockedExitCodes.includes(exitCode)) {
    status = "blocked";
  }
  const evidenceError = status === "passed" && step.evidencePath
    ? validateTestEvidence(normalizedExecution.testEvidence, step, source)
    : null;
  const evidenceProofError = status === "passed" && step.evidencePath
    && !/^[a-f0-9]{64}$/u.test(normalizedExecution.testEvidenceFingerprint || "")
    ? "missing-or-invalid-test-evidence-fingerprint"
    : null;
  const artifactError = ["passed", "blocked"].includes(status) && stepArtifactPaths(step).length > 0
    && !/^[a-f0-9]{64}$/u.test(normalizedExecution.artifactFingerprint || "")
    ? "missing-or-invalid-artifact-fingerprint"
    : null;
  if (evidenceError || evidenceProofError || artifactError) status = "failed";
  const output = `${normalizedExecution.stdout || ""}${normalizedExecution.stderr || ""}`;
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
    reason: (executionError ? EXECUTION_ERROR_REASON : null) || (signal
      ? `terminated-by:${signal}`
      : evidenceProofError || evidenceError || artifactError),
    testCounts: parseTestCounts(output),
    outputFingerprint: crypto.createHash("sha256").update(output).digest("hex"),
    testEvidence: normalizedExecution.testEvidence || null,
    testEvidenceFingerprint: normalizedExecution.testEvidenceFingerprint || null,
    artifactFingerprint: normalizedExecution.artifactFingerprint || null,
  };
}

function bindExecutionTestEvidence(execution, step, root) {
  const snapshot = inspectExecution(execution);
  if (!step?.evidencePath) {
    return composeExecution(execution, {}, { snapshot });
  }
  const claimedFingerprint = snapshot.values.testEvidenceFingerprint;
  let durableValue = null;
  try {
    durableValue = testEvidenceProofForStep(step, root).value;
  } catch {
    durableValue = null;
  }
  return composeExecution(execution, {
    testEvidence: durableValue,
    testEvidenceFingerprint: claimedFingerprint || null,
  }, { snapshot });
}

function executeCommand(step, context = {}) {
  const root = context.root || ROOT;
  const runtimeExecutable = context.runtimeExecutable || process.execPath;
  const execution = resolveGateExecution(step, {
    root,
    runtimeExecutable,
    npm: context.npm,
    npmExecPath: context.npmExecPath ?? process.env.npm_execpath,
    platform: context.platform,
  });
  const spawn = context.spawnSync || spawnSync;
  if (execution.npm) {
    assertNoNpmToolchainShadowing(root, { platform: context.platform });
  }
  clearStepOutputs(step, root);
  const evidenceEnvironment = step.evidencePath ? {
    CLOUDSMITH_QUALITY_SOURCE_SHA: context.source?.sha || "",
    CLOUDSMITH_QUALITY_SOURCE_FINGERPRINT: context.source?.fingerprint || "",
    CLOUDSMITH_QUALITY_TEST_EVIDENCE: step.evidencePath,
    CLOUDSMITH_QUALITY_TEST_SUITE: step.id,
  } : {};
  const rawResult = withNonAuthQualityEnvironment({
    environment: context.environment || process.env,
    overrides: evidenceEnvironment,
    platform: context.platform,
    temporaryParent: context.temporaryParent,
  }, (environment, boundary) => {
    const spawnChild = launcher => spawn(execution.executable, execution.npm
      ? [launcher.npmCliPath, ...execution.args.slice(1)]
      : execution.args, {
      cwd: root,
      encoding: "utf8",
      env: canonicalToolchainEnvironment(environment, {
        launcherDirectory: launcher?.directory,
        nodeExecutable: runtimeExecutable,
        platform: context.platform,
        scriptShell: launcher?.scriptShell,
      }),
      maxBuffer: 64 * 1024 * 1024,
    });
    if (!execution.npm) return spawnChild(null);
    assertNoNpmToolchainShadowing(root, { platform: context.platform });
    return withCanonicalNpmLauncher({
      nodeExecutable: runtimeExecutable,
      npm: execution.npm,
      platform: context.platform,
      temporaryParent: boundary.paths.temporary,
    }, launcher => spawnChild(launcher));
  });
  const result = composeExecution(rawResult);
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
      return composeExecution(result, { artifactFingerprint }, {
        errorValue: new Error(artifactError),
        forceError: true,
      });
    }
    return composeExecution(result, { artifactFingerprint });
  }
  let testEvidence = null;
  let testEvidenceFingerprint = null;
  let evidenceError = null;
  try {
    const proof = testEvidenceProofForStep(step, root);
    testEvidence = proof.value;
    testEvidenceFingerprint = proof.sha256;
    evidenceError = validateTestEvidence(testEvidence, step, context.source);
  } catch (error) {
    evidenceError = `missing-or-invalid-test-evidence:${error.message}`;
  }
  if (result.status === 0 && (evidenceError || artifactError)) {
    return composeExecution(result, {
      testEvidence,
      testEvidenceFingerprint,
      artifactFingerprint,
    }, {
      errorValue: new Error(evidenceError || artifactError),
      forceError: true,
    });
  }
  return composeExecution(result, {
    testEvidence,
    testEvidenceFingerprint,
    artifactFingerprint,
  });
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

function normalizeParsedJsonForPersistence(value) {
  if (Object.is(value, -0)) return 0;
  if (value === null || typeof value !== "object") return value;

  const pending = [value];
  const containers = [];
  while (pending.length > 0) {
    const current = pending.pop();
    containers.push(current);
    if (Array.isArray(current)) {
      for (let index = 0; index < current.length; index += 1) {
        const child = current[index];
        if (Object.is(child, -0)) {
          current[index] = 0;
        } else if (child !== null && typeof child === "object") {
          pending.push(child);
        }
      }
    } else {
      for (const key of Object.keys(current)) {
        const child = current[key];
        if (Object.is(child, -0)) {
          current[key] = 0;
        } else if (child !== null && typeof child === "object") {
          pending.push(child);
        }
      }
    }
  }
  for (let index = containers.length - 1; index >= 0; index -= 1) {
    Object.freeze(containers[index]);
  }
  return value;
}

function serializationSafeGateValue(value) {
  const copyScalar = current => {
    if (current === null || typeof current === "string" || typeof current === "boolean") {
      return current;
    }
    if (typeof current === "number" && Number.isFinite(current)) {
      return Object.is(current, -0) ? 0 : current;
    }
    if (typeof current !== "object") {
      throw new Error("Gate evidence contains a non-JSON persistence value.");
    }
    return undefined;
  };
  const scalar = copyScalar(value);
  if (scalar !== undefined || value === null) return scalar;

  const copies = new Map();
  const containers = [];
  const createContainer = source => {
    const prototype = Object.getPrototypeOf(source);
    let target;
    if (Array.isArray(source)) {
      target = [];
      Object.defineProperty(target, "toJSON", {
        configurable: false,
        enumerable: false,
        value: undefined,
        writable: false,
      });
    } else if (prototype === Object.prototype || prototype === null) {
      target = Object.create(null);
    } else {
      throw new Error("Gate evidence contains a non-JSON persistence object.");
    }
    copies.set(source, target);
    containers.push(target);
    return target;
  };
  const rootCopy = createContainer(value);
  const pending = [{ source: value, target: rootCopy }];
  const assign = (target, key, current) => {
    const primitive = copyScalar(current);
    if (primitive !== undefined || current === null) {
      target[key] = primitive;
      return;
    }
    let child = copies.get(current);
    if (!child) {
      child = createContainer(current);
      pending.push({ source: current, target: child });
    }
    target[key] = child;
  };
  while (pending.length > 0) {
    const { source, target } = pending.pop();
    if (Array.isArray(source)) {
      const lengthDescriptor = Object.getOwnPropertyDescriptor(source, "length");
      if (!lengthDescriptor || !Number.isSafeInteger(lengthDescriptor.value)) {
        throw new Error("Gate evidence contains an invalid JSON array.");
      }
      for (let index = 0; index < lengthDescriptor.value; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(source, String(index));
        if (!descriptor) {
          target[index] = null;
        } else if (!Object.prototype.hasOwnProperty.call(descriptor, "value")) {
          throw new Error("Gate evidence contains an accessor persistence value.");
        } else {
          assign(target, index, descriptor.value);
        }
      }
      continue;
    }
    for (const key of Object.keys(source)) {
      const descriptor = Object.getOwnPropertyDescriptor(source, key);
      if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
        throw new Error("Gate evidence contains an accessor persistence value.");
      }
      assign(target, key, descriptor.value);
    }
  }
  for (let index = containers.length - 1; index >= 0; index -= 1) {
    Object.freeze(containers[index]);
  }
  return rootCopy;
}

function testEvidenceProofForStep(step, root = ROOT, options = {}) {
  if (typeof step?.evidencePath !== "string") {
    throw new Error("Quality step does not declare structured test evidence.");
  }
  const evidencePath = resolveExistingRepositoryFile(
    step.evidencePath,
    root,
    { subtree: ".quality/test-results" },
  );
  return withStableSingleLinkFile(evidencePath, {
    errorMessage: "Structured test evidence is unsafe or changed.",
    fileSystem: options.fileSystem,
    maximumBytes: MAX_GATE_TEST_EVIDENCE_BYTES,
    minimumBytes: 1,
  }, bytes => {
    const parsed = JSON.parse(bytes.toString("utf8"));
    const durableValue = normalizeParsedJsonForPersistence(parsed);
    return Object.freeze({
      sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
      value: durableValue,
    });
  });
}

function validateTestEvidenceBinding(receipt, step, root = ROOT, options = {}) {
  if (!step?.evidencePath) {
    return receipt?.testEvidenceFingerprint === null
      ? null
      : "unexpected-test-evidence-fingerprint";
  }
  if (!/^[a-f0-9]{64}$/u.test(receipt?.testEvidenceFingerprint || "")) {
    return "missing-or-invalid-test-evidence-fingerprint";
  }
  try {
    const proof = testEvidenceProofForStep(step, root, options);
    if (proof.sha256 !== receipt.testEvidenceFingerprint
      || !isDeepStrictEqual(proof.value, receipt.testEvidence)) {
      return "test-evidence-fingerprint-mismatch";
    }
    return null;
  } catch {
    return "missing-or-invalid-test-evidence";
  }
}

function artifactFingerprintForStep(step, root = ROOT) {
  const artifactPaths = stepArtifactPaths(step);
  if (artifactPaths.length === 0) return null;
  const subtree = step.artifactSubtree || ".quality/mutation";
  const artifacts = artifactPaths.map(relativePath => ({
    relativePath,
    absolutePath: resolveExistingRepositoryFile(relativePath, root, { subtree }),
  }));
  const exactOptions = {
    errorMessage: "Quality step artifact is unsafe or changed.",
    maximumBytes: MAX_GATE_ARTIFACT_BYTES,
    minimumBytes: 0,
  };
  if (artifacts.length === 1) {
    return withStableSingleLinkFile(
      artifacts[0].absolutePath,
      exactOptions,
      bytes => crypto.createHash("sha256").update(bytes).digest("hex"),
    );
  }
  const hash = crypto.createHash("sha256");
  hash.update("cloudsmith-quality-artifact-bundle-v1\0");
  for (const artifact of artifacts) {
    withStableSingleLinkFile(artifact.absolutePath, exactOptions, bytes => {
      hash.update(`${artifact.relativePath}\0${bytes.length}\0`);
      hash.update(bytes);
      hash.update("\0");
    });
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
  const seenFileOrder = [...seenFiles];
  if (expectedFiles && (seenFileOrder.length !== expectedFiles.length
    || expectedFiles.some((file, index) => seenFileOrder[index] !== file))) {
    return "suite-inventory-mismatch";
  }
  if (counted.failed > 0 || counted.pending > 0) return "nonpassing-test-record";
  return null;
}

function exactRuntimeExecutable(executable = process.execPath) {
  try {
    return assertExactNodeExecutable(executable);
  } catch {
    throw new Error("Canonical gate runtime executable is unsafe or invalid.");
  }
}

function resolveGateExecution(step, options = {}) {
  if (step.executable === "node") {
    return Object.freeze({
      executable: exactRuntimeExecutable(options.runtimeExecutable),
      args: Object.freeze([...step.args]),
    });
  }
  if (step.executable === "npm") {
    const runtime = exactRuntimeExecutable(options.runtimeExecutable);
    const claimedNpmCli = options.npm?.cliPath ?? options.npmExecPath;
    const npm = assertCanonicalNpmRuntime(options.root || ROOT, claimedNpmCli, {
      nodeExecutable: runtime,
      platform: options.platform,
    });
    return Object.freeze({
      executable: runtime,
      args: Object.freeze([npm.cliPath, ...step.args]),
      npm,
    });
  }
  return Object.freeze({
    executable: step.executable,
    args: Object.freeze([...step.args]),
  });
}

function gateChildEnvironment(environment, runtimeExecutable = process.execPath, platform) {
  return canonicalToolchainEnvironment(environment, {
    nodeExecutable: exactRuntimeExecutable(runtimeExecutable),
    platform,
  });
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
  return writeJson(receiptPath(receipt), serializationSafeGateValue(receipt), root);
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
  exactRuntimeExecutable,
  executeCommand,
  gateChildEnvironment,
  gatePlanFingerprint,
  getGatePlan,
  parseArguments,
  parseTestCounts,
  receiptPath,
  resolveGateExecution,
  runGate,
  sameSource,
  stepArtifactPaths,
  testEvidenceProofForStep,
  validateArtifactBinding,
  validateTestEvidenceBinding,
  validateTestEvidence,
};

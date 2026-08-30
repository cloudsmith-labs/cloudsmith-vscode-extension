// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const fs = require("fs");
const path = require("path");
const { spawn, spawnSync } = require("child_process");
const {
  ROOT,
  readJson,
  removeOutputFile,
  writeJson,
} = require("./common");
const { fingerprint, sourceIdentity } = require("./evidence");
const {
  candidateBindingFromReceipt,
  validateCandidateBinding,
} = require("./candidate-binding");
const {
  assertSourceIdentity,
  currentExtensionHostVersion,
  qualificationEnvironment,
  qualificationLaunchArguments,
} = require("./prepare-qualification");
const { validateCandidate } = require("./run-ui-smoke");
const { HOST_REQUEST_ENV } = require("./auth-bootstrap-host");
const {
  assertProfileMetadataBoundary,
  createRuntimeLogRoot,
  destroyRuntimeLogRoot,
  runAuthenticatedExposureScan,
} = require("./authenticated-exposure-scan");
const { verifyConnectedWorkspace } = require("./authenticated-product-verifier");
const { scanCurrentWorktreeValueBlind } = require("./secret-scan");
const {
  ProcessTreeCleanupError,
  terminateProcessTree,
} = require("./process-tree");
const {
  createCredentialHandoff,
  destroyCredentialHandoff,
} = require("../../test/auth-bootstrap/handoff");
const {
  loadPreparedAuthenticatedCandidate,
} = require("./authenticated-candidate-session");

const AUTHENTICATED_RESULT = ".quality/qualification/authenticated-ci.json";
const AUTH_TOKEN_KEY = "cloudsmith-vsc.authToken";
const CURRENT_VSCODE_VERSION = currentExtensionHostVersion(ROOT);
const DESIGNATED_WORKSPACE = "dl-technology-consulting";
const ROOT_MANIFEST = readJson("package.json", ROOT);
const EXTENSION_ID = `${ROOT_MANIFEST.publisher}.${ROOT_MANIFEST.name}`;
const EXTENSION_VERSION = ROOT_MANIFEST.version;
const SECRET_ENV = "CLOUDSMITH_QUALIFICATION_API_KEY";
const SURFACE = "production-connected-workspace";
const FIXTURE_WORKFLOW_IDS = Object.freeze([
  "WF-EXPLORER-PUBLICATION",
  "WF-SEARCH-FIRST-PAGE",
]);
const SAFE_REASON_CODES = new Set([
  "candidate-unavailable",
  "candidate-invalid",
  "connected-workspace-mismatch",
  "credential-cleanup-failed",
  "credential-handoff-failed",
  "credential-missing",
  "credential-seed-failed",
  "exposure-scan-failed",
  "no-production-verifier",
  "output-boundary-failed",
  "process-tree-cleanup-failed",
  "profile-cleanup-failed",
  "source-drift",
  "workspace-not-designated",
]);
const FAILURE_PRIORITY = Object.freeze({
  "candidate-unavailable": 10,
  "candidate-invalid": 20,
  "connected-workspace-mismatch": 30,
  "no-production-verifier": 30,
  "credential-missing": 30,
  "workspace-not-designated": 40,
  "credential-seed-failed": 50,
  "source-drift": 60,
  "exposure-scan-failed": 70,
  "output-boundary-failed": 80,
  "profile-cleanup-failed": 90,
  "credential-handoff-failed": 100,
  "credential-cleanup-failed": 110,
  "process-tree-cleanup-failed": 120,
});

class AuthenticatedCiOutcome extends Error {
  constructor(status, reasonCode) {
    super(reasonCode);
    this.name = "AuthenticatedCiOutcome";
    this.status = status;
    this.reasonCode = reasonCode;
  }
}

function outcome(status, reasonCode) {
  return new AuthenticatedCiOutcome(status, reasonCode);
}

function sameSource(left, right) {
  return Boolean(left && right
    && left.sha === right.sha
    && left.fingerprint === right.fingerprint
    && /^[0-9a-f]{40,64}$/u.test(left.sha || "")
    && /^[0-9a-f]{64}$/u.test(left.fingerprint || ""));
}

function assertExactRepositoryRoot(root = ROOT) {
  if (root !== ROOT || !path.isAbsolute(root) || path.resolve(root) !== root
    || path.normalize(root) !== root) {
    throw outcome("failed", "candidate-invalid");
  }
  const stat = fs.lstatSync(root);
  if (stat.isSymbolicLink() || !stat.isDirectory() || fs.realpathSync(root) !== root) {
    throw outcome("failed", "candidate-invalid");
  }
  return root;
}

function designatedFixtureWorkspace(root = ROOT) {
  const workflows = readJson("quality/critical-workflows.json", root).workflows;
  if (!Array.isArray(workflows)) throw outcome("failed", "workspace-not-designated");
  for (const id of FIXTURE_WORKFLOW_IDS) {
    const workflow = workflows.find(item => item?.id === id);
    const fixture = workflow?.liveFixture;
    if (!fixture || fixture.required !== true || fixture.destructive !== false
      || typeof fixture.description !== "string"
      || !new RegExp(`(?:^|[^a-z0-9-])${DESIGNATED_WORKSPACE}(?:[^a-z0-9-]|$)`, "u")
        .test(fixture.description)) {
      throw outcome("failed", "workspace-not-designated");
    }
  }
  return DESIGNATED_WORKSPACE;
}

function consumeStepCredential(environment, workspaceIsValid) {
  if (!environment || typeof environment !== "object" || Array.isArray(environment)) {
    throw outcome("blocked", "credential-missing");
  }
  if (!workspaceIsValid) {
    delete environment[SECRET_ENV];
    throw outcome("failed", "workspace-not-designated");
  }
  const present = Object.prototype.hasOwnProperty.call(environment, SECRET_ENV);
  const credential = present ? environment[SECRET_ENV] : undefined;
  delete environment[SECRET_ENV];
  if (!present || typeof credential !== "string" || credential.length === 0) {
    throw outcome("blocked", "credential-missing");
  }
  return credential;
}

async function prepareCurrentCode(context, adapters = {}) {
  if (context.vscodeVersion !== CURRENT_VSCODE_VERSION
    || context.profile.mode !== "ci" || context.profile.persistent !== false) {
    throw new Error("Authenticated CI requires the exact current VS Code lane.");
  }
  const electron = adapters.electron || require("@vscode/test-electron");
  const cachePath = path.join(context.profile.root, "app");
  fs.mkdirSync(cachePath, { mode: 0o700 });
  if (process.platform !== "win32") fs.chmodSync(cachePath, 0o700);
  const executable = await electron.downloadAndUnzipVSCode({
    version: CURRENT_VSCODE_VERSION,
    cachePath,
    reporter: new electron.SilentReporter(),
  });
  return Object.freeze({
    executable,
    cli: electron.resolveCliPathFromVSCodeExecutablePath(executable),
  });
}

function validateCurrentCandidate(candidate, context = {}) {
  const validate = context.validateCandidate || validateCandidate;
  const binding = validate(candidate, {
    root: context.root || ROOT,
    source: context.source,
    tool: { vscodeVersion: CURRENT_VSCODE_VERSION },
    platform: context.platform || process.platform,
    architecture: context.architecture || process.arch,
  });
  if (candidate.receipt.vscode.version !== CURRENT_VSCODE_VERSION
    || candidate.profile.vscodeVersion !== CURRENT_VSCODE_VERSION
    || candidate.receipt.profile.mode !== "ci"
    || candidate.receipt.profile.persistent !== false
    || candidate.receipt.launch.status !== "not-requested"
    || candidate.receipt.launch.developmentPath !== false) {
    throw outcome("failed", "candidate-invalid");
  }
  const manifest = readJson("package.json", context.root || ROOT);
  if (!binding || typeof binding !== "object" || Array.isArray(binding)
    || Object.keys(binding).sort().join(",") !== [
      "candidateReceiptFingerprint", "extensionId", "extensionVersion", "vsixSha256",
    ].sort().join(",")
    || !/^[a-f0-9]{64}$/u.test(binding.candidateReceiptFingerprint || "")
    || binding.extensionId !== `${manifest.publisher}.${manifest.name}`
    || binding.extensionVersion !== manifest.version
    || !/^[a-f0-9]{64}$/u.test(binding.vsixSha256 || "")) {
    throw outcome("failed", "candidate-invalid");
  }
  let exactBinding;
  try {
    exactBinding = candidateBindingFromReceipt(candidate.receipt, {
      root: context.root || ROOT,
      source: context.source,
    });
    if (exactBinding.receiptFingerprint !== binding.candidateReceiptFingerprint
      || exactBinding.extensionId !== binding.extensionId
      || exactBinding.extensionVersion !== binding.extensionVersion
      || exactBinding.vsixSha256 !== binding.vsixSha256
      || exactBinding.profileMode !== "ci") {
      throw new Error("Candidate validator and exact receipt disagree.");
    }
  } catch {
    throw outcome("failed", "candidate-invalid");
  }
  return exactBinding;
}

function hostRequest(candidate, commandRequest) {
  return Object.freeze({
    schemaVersion: 1,
    repositoryRoot: ROOT,
    profileRoot: candidate.profile.root,
    userDataDir: candidate.profile.userDataDir,
    extensionsDir: candidate.profile.extensionsDir,
    vscodeExecutable: candidate.profile.executable,
    commandRequest,
  });
}

function waitForChildOutcome(child, timeout) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve({ code: child.exitCode, signal: child.signalCode });
  }
  return new Promise(resolve => {
    let settled = false;
    const finish = value => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const timer = setTimeout(() => finish({ timedOut: true }), timeout);
    child.once("error", () => finish({ startFailed: true }));
    child.once("exit", (code, signal) => finish({ code, signal }));
  });
}

function valueBlindChunkLength(chunk) {
  if (Buffer.isBuffer(chunk)) return chunk.length;
  if (typeof chunk === "string") return Buffer.byteLength(chunk);
  if (ArrayBuffer.isView(chunk) && Number.isSafeInteger(chunk.byteLength)) {
    return chunk.byteLength;
  }
  // Any unexpected chunk shape is still output, without coercing or inspecting it.
  return 1;
}

async function invokeBootstrapHost(candidate, commandRequest, options = {}) {
  const launch = options.spawn || spawn;
  const terminate = options.terminateProcessTree || terminateProcessTree;
  const environment = qualificationEnvironment(options.environment || process.env, candidate.profile);
  if (Object.prototype.hasOwnProperty.call(environment, SECRET_ENV)) {
    throw outcome("failed", "output-boundary-failed");
  }
  const childEnvironment = {
    ...environment,
    [HOST_REQUEST_ENV]: JSON.stringify(hostRequest(candidate, commandRequest)),
  };
  let child;
  try {
    child = launch(
      process.execPath,
      [path.join(ROOT, "scripts", "quality", "auth-bootstrap-host.js")],
      {
        cwd: ROOT,
        env: childEnvironment,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
        detached: process.platform !== "win32",
      },
    );
  } catch {
    throw outcome("failed", commandRequest.operation === "cleanup"
      ? "credential-cleanup-failed"
      : "credential-seed-failed");
  }
  if (!child || typeof child.once !== "function" || !child.stdout || !child.stderr) {
    try {
      await terminate(child, options);
    } catch {
      // The normalized process-tree outcome below is authoritative.
    }
    throw outcome("failed", "process-tree-cleanup-failed");
  }
  let stdoutBytes = 0;
  let stderrBytes = 0;
  child.stdout.on("data", chunk => {
    stdoutBytes = Math.min(65_536, stdoutBytes + valueBlindChunkLength(chunk));
  });
  child.stderr.on("data", chunk => {
    stderrBytes = Math.min(65_536, stderrBytes + valueBlindChunkLength(chunk));
  });
  const result = await waitForChildOutcome(child, options.timeout || 180_000);
  let terminated = false;
  try {
    terminated = await terminate(child, options);
  } catch {
    throw outcome("failed", "process-tree-cleanup-failed");
  }
  if (!terminated) throw outcome("failed", "process-tree-cleanup-failed");
  if (stdoutBytes !== 0 || stderrBytes !== 0) {
    throw outcome("failed", "output-boundary-failed");
  }
  if (result.startFailed || result.timedOut || result.signal || result.code !== 0) {
    throw outcome("failed", commandRequest.operation === "cleanup"
      ? "credential-cleanup-failed"
      : "credential-seed-failed");
  }
  return true;
}

function captureContentFreeWorktreeState(root = ROOT, spawnGit = spawnSync) {
  const result = spawnGit("git", [
    "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none",
  ], {
    cwd: root,
    encoding: null,
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (result.error || result.signal || result.status !== 0
    || !Buffer.isBuffer(result.stdout) || result.stdout.length > 64 * 1024 * 1024) {
    throw new Error("Content-free worktree state was unavailable.");
  }
  return Buffer.from(result.stdout);
}

function connectedWorkspaceContext(candidate, source, binding, environment, runtimeLogRoot) {
  const profile = Object.freeze({
    mode: "ci",
    persistent: false,
    root: candidate.profile.root,
    testResourcesDir: candidate.profile.testResourcesDir,
    homeDir: candidate.profile.homeDir,
    userDataDir: candidate.profile.userDataDir,
    extensionsDir: candidate.profile.extensionsDir,
    executable: candidate.profile.executable,
    cli: candidate.profile.cli,
    vscodeVersion: candidate.profile.vscodeVersion,
  });
  const launchArguments = qualificationLaunchArguments(profile, { workspacePath: ROOT });
  return Object.freeze({
    root: ROOT,
    source: Object.freeze({ ...source }),
    expectedWorkspace: DESIGNATED_WORKSPACE,
    candidateReceiptFingerprint: binding.receiptFingerprint,
    extensionId: binding.extensionId,
    extensionVersion: binding.extensionVersion,
    vsixSha256: binding.vsixSha256,
    profile,
    launchArguments,
    environment: qualificationEnvironment(environment, profile),
    runtimeLogRoot,
  });
}

function validateConnectedWorkspaceResult(result, source, candidateFingerprint) {
  if (!result || typeof result !== "object" || Array.isArray(result)
    || Object.keys(result).sort().join(",") !== [
      "candidateReceiptFingerprint", "developmentPath", "source", "status", "surface", "workspace",
    ].sort().join(",")
    || result.status !== "passed"
    || result.surface !== SURFACE
    || result.workspace !== DESIGNATED_WORKSPACE
    || result.developmentPath !== false
    || result.candidateReceiptFingerprint !== candidateFingerprint
    || !sameSource(result.source, source)) {
    throw outcome("failed", "connected-workspace-mismatch");
  }
  return true;
}

function receiptBase(values) {
  return {
    schemaVersion: 2,
    status: values.status,
    reasonCode: values.reasonCode,
    source: values.source,
    workspace: {
      expected: DESIGNATED_WORKSPACE,
      observed: values.connected ? DESIGNATED_WORKSPACE : null,
      surface: values.connected ? SURFACE : null,
    },
    candidate: values.binding ? { ...values.binding } : null,
    credentialBoundary: {
      storageKey: AUTH_TOKEN_KEY,
      transport: "creator-bound-0700-0600-handoff",
      valueRecorded: false,
      digestRecorded: false,
    },
    phases: { ...values.phases },
  };
}

function assertValueBlindReceipt(receipt) {
  const unsigned = { ...receipt };
  delete unsigned.fingerprint;
  const sourceIsSafe = receipt?.source === null || (
    receipt.source && typeof receipt.source === "object" && !Array.isArray(receipt.source)
    && Object.keys(receipt.source).sort().join(",") === "fingerprint,sha"
    && /^[0-9a-f]{40,64}$/u.test(receipt.source.sha || "")
    && /^[a-f0-9]{64}$/u.test(receipt.source.fingerprint || "")
  );
  let candidateIsSafe = receipt?.candidate === null;
  if (!candidateIsSafe) {
    try {
      validateCandidateBinding(receipt.candidate);
      candidateIsSafe = receipt.candidate.extensionId === EXTENSION_ID
        && receipt.candidate.extensionVersion === EXTENSION_VERSION
        && receipt.candidate.vscodeVersion === CURRENT_VSCODE_VERSION
        && receipt.candidate.profileMode === "ci";
    } catch {
      candidateIsSafe = false;
    }
  }
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)
    || Object.keys(receipt).sort().join(",") !== [
      "candidate", "credentialBoundary", "fingerprint", "phases", "reasonCode",
      "schemaVersion", "source", "status", "workspace",
    ].sort().join(",")
    || receipt.schemaVersion !== 2
    || !new Set(["passed", "blocked", "failed"]).has(receipt.status)
    || (receipt.status === "passed" ? receipt.reasonCode !== null
      : !SAFE_REASON_CODES.has(receipt.reasonCode))
    || !sourceIsSafe || !candidateIsSafe
    || !receipt.workspace || Object.keys(receipt.workspace).sort().join(",")
      !== "expected,observed,surface"
    || receipt.workspace.expected !== DESIGNATED_WORKSPACE
    || !new Set([null, DESIGNATED_WORKSPACE]).has(receipt.workspace.observed)
    || !new Set([null, SURFACE]).has(receipt.workspace.surface)
    || !receipt.credentialBoundary
    || Object.keys(receipt.credentialBoundary).sort().join(",")
      !== "digestRecorded,storageKey,transport,valueRecorded"
    || receipt.credentialBoundary.storageKey !== AUTH_TOKEN_KEY
    || receipt.credentialBoundary.transport !== "creator-bound-0700-0600-handoff"
    || receipt.credentialBoundary.valueRecorded !== false
    || receipt.credentialBoundary.digestRecorded !== false
    || fingerprint(unsigned) !== receipt.fingerprint) {
    throw outcome("failed", "output-boundary-failed");
  }
  return receipt;
}

async function runAuthenticatedCi(options = {}) {
  const root = options.root || ROOT;
  const environment = options.environment || process.env;
  const identifySource = options.sourceIdentity || sourceIdentity;
  const captureWorktreeState = options.captureContentFreeWorktreeState
    || captureContentFreeWorktreeState;
  const scanCurrentWorktree = options.scanCurrentWorktree
    || scanCurrentWorktreeValueBlind;
  const prepareCandidate = options.prepareQualificationCandidate
    || (() => loadPreparedAuthenticatedCandidate(root));
  const createHandoff = options.createCredentialHandoff || createCredentialHandoff;
  const destroyHandoff = options.destroyCredentialHandoff || destroyCredentialHandoff;
  const invokeHost = options.invokeBootstrapHost || invokeBootstrapHost;
  const checkConnectedWorkspace = Object.prototype.hasOwnProperty.call(
    options,
    "checkConnectedWorkspace",
  ) ? options.checkConnectedWorkspace : verifyConnectedWorkspace;
  const createLogs = options.createRuntimeLogRoot || createRuntimeLogRoot;
  const destroyLogs = options.destroyRuntimeLogRoot || destroyRuntimeLogRoot;
  const scanExposure = options.runAuthenticatedExposureScan
    || runAuthenticatedExposureScan;
  const writeReceipt = options.writeReceipt || ((receipt) => writeJson(
    AUTHENTICATED_RESULT, receipt, root, { subtree: ".quality/qualification" }
  ));
  const removeReceipt = options.removeReceipt || (() => removeOutputFile(
    AUTHENTICATED_RESULT, root, { subtree: ".quality/qualification" }
  ));

  let status = "passed";
  let reasonCode = null;
  let source = null;
  let credential;
  let handoff = null;
  let runtimeLogs = null;
  let candidate = null;
  let binding = null;
  let seedAttempted = false;
  let connected = false;
  let exposureBoundaryAttempted = false;
  let exposureBoundaryPassed = true;
  let preAuthWorktreeState = null;
  let processTreeCleanupFailed = false;
  let profileBoundaryProof = null;
  let profileCleanedEarly = false;
  const phases = {
    candidate: "not-run",
    handoff: "not-created",
    seed: "not-run",
    productionWorkspaceCheck: "not-run",
    secretStorageCleanup: "not-run",
    profileCleanup: "not-run",
    outputBoundary: "not-run",
  };
  const recordFailure = (nextReason, nextStatus = "failed") => {
    if (nextReason === "process-tree-cleanup-failed") {
      processTreeCleanupFailed = true;
      exposureBoundaryAttempted = true;
      exposureBoundaryPassed = false;
    }
    const currentPriority = reasonCode ? FAILURE_PRIORITY[reasonCode] || 0 : -1;
    const nextPriority = FAILURE_PRIORITY[nextReason] || 0;
    if (nextPriority >= currentPriority) reasonCode = nextReason;
    if (nextStatus === "failed" || status === "passed") status = nextStatus;
  };
  const attemptProfileCleanup = async () => {
    if (!candidate) return false;
    let cleaned = false;
    const profileRoot = candidate.profile?.root;
    try {
      cleaned = await candidate.cleanup();
    } catch {
      cleaned = false;
    }
    if (cleaned === true && typeof profileRoot === "string" && !fs.existsSync(profileRoot)) {
      phases.profileCleanup = "passed";
      return true;
    }
    recordFailure("profile-cleanup-failed");
    phases.profileCleanup = "failed";
    return false;
  };

  try {
    assertExactRepositoryRoot(root);
    removeReceipt();
    const designated = designatedFixtureWorkspace(root);
    const requestedWorkspace = options.expectedWorkspace || DESIGNATED_WORKSPACE;
    const workspaceIsValid = designated === DESIGNATED_WORKSPACE
      && requestedWorkspace === DESIGNATED_WORKSPACE;
    credential = consumeStepCredential(environment, workspaceIsValid);

    try {
      source = assertSourceIdentity(identifySource(root, options.gitSpawn || spawnSync));
    } catch {
      source = null;
      throw outcome("failed", "candidate-invalid");
    }
    try {
      candidate = await prepareCandidate({
        root,
        mode: "ci",
        qualificationLane: "current",
        launch: false,
        environment,
        prepareCode: options.prepareCode || (context => prepareCurrentCode(context, {
          electron: options.electron,
        })),
        adapters: options.candidateAdapters,
      });
      phases.candidate = "prepared";
    } catch {
      throw outcome("blocked", "candidate-unavailable");
    }
    try {
      binding = validateCurrentCandidate(candidate, {
        root,
        source,
        validateCandidate: options.validateCandidate,
        platform: options.platform,
        architecture: options.architecture,
      });
    } catch (error) {
      if (error instanceof AuthenticatedCiOutcome) throw error;
      throw outcome("failed", "candidate-invalid");
    }
    try {
      preAuthWorktreeState = captureWorktreeState(root, options.gitSpawn || spawnSync);
      if (!Buffer.isBuffer(preAuthWorktreeState)) throw new Error("Invalid worktree state.");
    } catch {
      throw outcome("failed", "candidate-invalid");
    }

    try {
      runtimeLogs = createLogs({ temporaryParent: options.temporaryParent });
    } catch {
      exposureBoundaryAttempted = true;
      exposureBoundaryPassed = false;
      throw outcome("failed", "output-boundary-failed");
    }
    try {
      handoff = createHandoff({
        credential,
        workspace: DESIGNATED_WORKSPACE,
        temporaryParent: options.temporaryParent,
        randomBytes: options.randomBytes,
      });
      phases.handoff = "created";
    } catch {
      throw outcome("failed", "credential-handoff-failed");
    } finally {
      credential = undefined;
    }
    seedAttempted = true;
    await invokeHost(candidate, Object.freeze({ operation: "seed", capability: handoff }), {
      environment,
      spawn: options.spawn,
      terminateProcessTree: options.terminateProcessTree,
      timeout: options.hostTimeout,
    });
    phases.seed = "passed";
    if (fs.existsSync(handoff.root)) {
      throw outcome("failed", "credential-handoff-failed");
    }
    try {
      destroyHandoff(handoff);
    } catch {
      throw outcome("failed", "credential-handoff-failed");
    }
    handoff = null;
    phases.handoff = "consumed-before-store-completion";

    if (typeof checkConnectedWorkspace !== "function") {
      phases.productionWorkspaceCheck = "blocked";
      throw outcome("blocked", "no-production-verifier");
    }
    let checkResult;
    try {
      checkResult = await checkConnectedWorkspace(
        connectedWorkspaceContext(
          candidate,
          source,
          binding,
          environment,
          runtimeLogs.root,
        )
      );
    } catch (error) {
      if (error instanceof ProcessTreeCleanupError) {
        throw outcome("failed", "process-tree-cleanup-failed");
      }
      throw outcome("failed", "connected-workspace-mismatch");
    }
    validateConnectedWorkspaceResult(checkResult, source, binding.receiptFingerprint);
    connected = true;
    phases.productionWorkspaceCheck = "passed";
  } catch (error) {
    const safe = error instanceof AuthenticatedCiOutcome
      ? error
      : outcome("failed", "candidate-invalid");
    recordFailure(safe.reasonCode, safe.status);
    if (phases.seed === "not-run" && seedAttempted) phases.seed = "failed";
    if (phases.productionWorkspaceCheck === "not-run"
      && reasonCode === "connected-workspace-mismatch") {
      phases.productionWorkspaceCheck = "failed";
    }
  } finally {
    // Defensive deletion also covers malformed repository configuration and adapters
    // that attempt to reintroduce the step-scoped input before a cleanup child.
    delete environment[SECRET_ENV];
    credential = undefined;
    if (candidate && seedAttempted) {
      try {
        await invokeHost(candidate, Object.freeze({ operation: "cleanup" }), {
          environment,
          spawn: options.spawn,
          terminateProcessTree: options.terminateProcessTree,
          timeout: options.hostTimeout,
        });
        phases.secretStorageCleanup = "passed";
      } catch (error) {
        recordFailure(
          error instanceof AuthenticatedCiOutcome
            && error.reasonCode === "process-tree-cleanup-failed"
            ? "process-tree-cleanup-failed"
            : "credential-cleanup-failed",
        );
        phases.secretStorageCleanup = "failed";
      }
    }
    if (handoff) {
      try {
        const removed = destroyHandoff(handoff);
        phases.handoff = removed ? "removed" : "consumed";
        handoff = null;
      } catch {
        recordFailure("credential-handoff-failed");
        phases.handoff = "cleanup-failed";
      }
    }
    if (candidate) {
      const processExitState = processTreeCleanupFailed ? "unproven" : "proven";
      let processExitStatePersisted = false;
      try {
        if (typeof candidate.markProcessTreeExit === "function") {
          const marked = await candidate.markProcessTreeExit(processExitState);
          processExitStatePersisted = marked === true
            || marked?.processTreeExit === processExitState;
        }
      } catch { // handled below with the same value-blind failure
        processExitStatePersisted = false;
      }
      if (!processExitStatePersisted) {
        recordFailure("output-boundary-failed");
      }
    }
    if (candidate && phases.secretStorageCleanup === "failed" && !processTreeCleanupFailed) {
      try {
        profileBoundaryProof = assertProfileMetadataBoundary(candidate.profile);
      } catch {
        profileBoundaryProof = null;
      }
      profileCleanedEarly = await attemptProfileCleanup();
      if (!profileCleanedEarly) profileBoundaryProof = null;
    }
    if (source && seedAttempted) {
      exposureBoundaryAttempted = true;
      let postAuthContentSafe = false;
      try {
        const currentScan = await scanCurrentWorktree(root, {
          execute: options.secretScanExecute,
          executeGit: options.secretScanGitExecute,
          environment,
        });
        postAuthContentSafe = currentScan?.status === "passed"
          && currentScan.findingCount === 0;
      } catch {
        postAuthContentSafe = false;
      }
      if (!postAuthContentSafe) {
        exposureBoundaryPassed = false;
        recordFailure("exposure-scan-failed");
      } else if (!processTreeCleanupFailed) {
        let finalWorktreeState = null;
        try {
          finalWorktreeState = captureWorktreeState(root, options.gitSpawn || spawnSync);
        } catch {
          finalWorktreeState = null;
        }
        if (!Buffer.isBuffer(preAuthWorktreeState)
          || !Buffer.isBuffer(finalWorktreeState)
          || !preAuthWorktreeState.equals(finalWorktreeState)) {
          recordFailure("source-drift");
        } else {
          let finalSource = null;
          try {
            finalSource = identifySource(root, options.gitSpawn || spawnSync);
          } catch {
            finalSource = null;
          }
          if (!sameSource(source, finalSource)) recordFailure("source-drift");
        }
      }
    }
    if (candidate && runtimeLogs) {
      exposureBoundaryAttempted = true;
      try {
        const exposure = await scanExposure({
          root,
          source,
          candidate,
          candidateReceiptFingerprint: binding?.receiptFingerprint
            || candidate.receipt?.fingerprint,
          runtimeLogRoot: runtimeLogs.root,
          profileBoundaryProof,
          environment: qualificationEnvironment(environment, candidate.profile),
        }, { execute: options.secretScanExecute });
        exposureBoundaryPassed = exposureBoundaryPassed && exposure?.status === "passed";
      } catch {
        exposureBoundaryPassed = false;
      }
      if (!exposureBoundaryPassed) {
        recordFailure("exposure-scan-failed");
      }
      try {
        const removed = destroyLogs(runtimeLogs);
        if (removed === true) runtimeLogs = null;
        else {
          exposureBoundaryPassed = false;
          recordFailure("output-boundary-failed");
        }
      } catch {
        exposureBoundaryPassed = false;
        recordFailure("output-boundary-failed");
      }
    }
    // A surviving owned process can retain or recreate the profile after an
    // instantaneous deletion check. Preserve the authenticated session receipt
    // so the workflow's always-run cleanup step retains retry ownership.
    if (candidate && !profileCleanedEarly && !processTreeCleanupFailed) {
      await attemptProfileCleanup();
    }
  }

  phases.outputBoundary = exposureBoundaryAttempted && !exposureBoundaryPassed
    ? "failed"
    : "passed";
  if (status === "passed" && (!connected
    || phases.secretStorageCleanup !== "passed"
    || phases.profileCleanup !== "passed")) {
    recordFailure("output-boundary-failed");
  }
  const base = receiptBase({ status, reasonCode, source, connected, binding, phases });
  const receipt = assertValueBlindReceipt({ ...base, fingerprint: fingerprint(base) });
  try {
    writeReceipt(receipt);
  } catch {
    throw outcome("failed", "output-boundary-failed");
  }
  return Object.freeze(receipt);
}

function parseCli(arguments_) {
  if (arguments_.length !== 0) {
    throw new Error("Authenticated CI qualification accepts no CLI arguments.");
  }
  return Object.freeze({});
}

if (require.main === module) {
  let options;
  try {
    options = parseCli(process.argv.slice(2));
  } catch {
    process.exitCode = 1;
  }
  if (options) {
    runAuthenticatedCi(options)
      .then(receipt => {
        process.stdout.write(`${JSON.stringify(receipt)}\n`);
        process.exitCode = receipt.status === "passed" ? 0 : receipt.status === "blocked" ? 2 : 1;
      })
      .catch(() => {
        process.exitCode = 1;
      });
  }
}

module.exports = {
  AUTHENTICATED_RESULT,
  AUTH_TOKEN_KEY,
  CURRENT_VSCODE_VERSION,
  DESIGNATED_WORKSPACE,
  SECRET_ENV,
  SURFACE,
  assertExactRepositoryRoot,
  assertValueBlindReceipt,
  connectedWorkspaceContext,
  consumeStepCredential,
  designatedFixtureWorkspace,
  hostRequest,
  invokeBootstrapHost,
  parseCli,
  prepareCurrentCode,
  receiptBase,
  runAuthenticatedCi,
  sameSource,
  validateConnectedWorkspaceResult,
  validateCurrentCandidate,
};

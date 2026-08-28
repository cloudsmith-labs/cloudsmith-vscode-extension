// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { TextDecoder } = require("util");
const { spawnSync } = require("child_process");
const {
  ROOT,
  assertRepositoryRelativePath,
  isPlainObject,
  readJson,
  removeOutputFile,
  resolveExistingRepositoryFile,
  testSourceContains,
  uniqueSorted,
  writeJson,
} = require("./common");
const { fingerprint, sourceIdentity } = require("./evidence");
const {
  cleanupNonAuthQualityEnvironment,
  createNonAuthQualityEnvironment,
} = require("./non-auth-environment");
const { sanitizeQualificationEnvironment } = require("../../test/testInventories");

const RESULT_PATH = ".quality/ui/result.json";
const CONFIG_PATH = "extester.config.json";
const SETTINGS_PATH = "ui-test/settings.json";
const MOCHA_CONFIG_PATH = "ui-test/mocha.config.json";
const DIRECT_ENTRY_SENTINEL = "ui-test/RUN_THROUGH_QUALITY_RUNNER";
const PROBE_FILE = "ui-test/false-green-probe.test.js";
const SUITE_FILE = "ui-test/smoke.test.js";
const WORKFLOWS_PATH = "quality/critical-workflows.json";
const NODE_VERSION = "22.23.2";
const VSCODE_VERSION = "1.131.0";
const PROBE_TEST = "rejects a fresh intentionally incorrect Activity Bar selector";
const SUITE_TESTS = Object.freeze([
  "installs, activates, and exposes the Cloudsmith Activity Bar container",
  "opens every extension-owned view without a blank container",
  "publishes the exact signed-out command set in the real Command Palette",
  "moves keyboard focus through the rendered Help tree",
  "opens Cloudsmith settings through the real Command Palette action",
]);
const DECLARED_TESTS = Object.freeze(uniqueSorted(SUITE_TESTS));
const DIRECT_ENTRY_SENTINEL_TEXT = "This regular-file sentinel makes direct ExTester entry fail before launch.\n"
  + "Use `npm run test:ui:smoke` so the quality runner supplies fresh owned paths.\n";
const MAX_EVIDENCE_BYTES = 64 * 1024;
const MAX_VSIX_BYTES = 12 * 1024 * 1024;
const MAX_VSIX_ENTRIES = 1250;
const PRIVATE_NON_AUTH_TOOL_ENVIRONMENT_NAMES = Object.freeze([
  "NPM_CONFIG_USERCONFIG",
  "NPM_CONFIG_GLOBALCONFIG",
  "NPM_CONFIG_CACHE",
  "NPM_CONFIG_UPDATE_NOTIFIER",
  "NPM_CONFIG_FUND",
  "GIT_CONFIG_NOSYSTEM",
  "GIT_CONFIG_GLOBAL",
  "GIT_CONFIG_COUNT",
  "GIT_ATTR_NOSYSTEM",
  "GIT_TERMINAL_PROMPT",
  "GCM_INTERACTIVE",
]);
const SAFE_FAILURE_MESSAGES = Object.freeze({
  UI_CANDIDATE_INVALID: "The black-box UI candidate failed closed before launch.",
  UI_DRIVER_INVALID: "The black-box UI driver setup failed closed before launch.",
  UI_INVENTORY_INVALID: "The black-box UI declared inventory is invalid.",
  UI_PROFILE_CLEANUP_FAILED: "The black-box UI profile cleanup failed closed.",
  UI_PROFILE_RESET_FAILED: "The black-box UI profile reset failed closed between phases.",
  UI_PROBE_INVALID: "The black-box UI false-green probe did not fail in the exact expected way.",
  UI_SMOKE_FAILED: "The black-box UI smoke did not produce authoritative passed evidence.",
  UI_SOURCE_DRIFT: "The black-box UI source changed during qualification.",
  UI_SUITE_INVALID: "The black-box UI suite did not produce exact passed evidence.",
  UI_TOOL_UNSUPPORTED: "The pinned black-box UI tool and VS Code versions are incompatible.",
});

async function runUiSmoke(options = {}) {
  const root = options.root || ROOT;
  const platform = options.platform || process.platform;
  const architecture = options.architecture || process.arch;
  const spawn = options.spawnSync || spawnSync;
  const readSource = options.sourceIdentity || sourceIdentity;
  let nonAuthBoundary;
  try {
    nonAuthBoundary = createNonAuthQualityEnvironment({
      environment: options.environment || process.env,
      platform,
      temporaryParent: options.temporaryParent,
    });
  } catch {
    throw safeFailure("UI_SMOKE_FAILED");
  }
  // Linux phases invoke xvfb-run below. The complete direct runner lifecycle
  // owns one private home, temporary tree, and empty npm/Git configuration;
  // only a fresh per-phase Xvfb capability reaches an individual UI child.
  const bootstrapEnvironment = nonAuthBoundary.environment;
  let candidate = null;
  let result = null;
  let failure = null;
  let safeStageCode = "UI_SMOKE_FAILED";

  try {
    removeOutputFile(RESULT_PATH, root, { subtree: ".quality/ui" });
    const candidateApi = options.prepareQualificationCandidate
      && options.qualificationLaunchArguments ? null : loadCandidateApi();
    const prepareCandidate = options.prepareQualificationCandidate
      || candidateApi.prepareQualificationCandidate;
    const launchArguments = options.qualificationLaunchArguments
      || candidateApi.qualificationLaunchArguments;
    const resetUserData = options.resetCiQualificationUserData
      || loadProfileApi().resetCiQualificationUserData;
    const tool = validateToolContract(
      root,
      options.toolPackage,
      options.nodeVersion || process.versions.node
    );
    const xvfb = resolveXvfb(platform, bootstrapEnvironment, options.xvfbPath);
    const extestCli = options.extestCli || resolveExtestCli(root);
    validateDeclaredInventory(root);
    safeStageCode = "UI_CANDIDATE_INVALID";
    candidate = await prepareCandidate({
      root,
      mode: "ci",
      launch: false,
      environment: bootstrapEnvironment,
      nonAuthBoundary,
      prepareCode: options.prepareCode || (context => prepareExTesterCode(context, {
        spawn,
        extestCli,
        timeout: options.codeTimeout || 300_000,
      })),
      adapters: options.candidateAdapters,
    });
    const source = readSource(root, options.gitSpawn || spawn, bootstrapEnvironment);
    const binding = validateCandidate(candidate, { root, source, tool, platform, architecture });
    validateLaunchArguments(launchArguments(candidate.profile), candidate.profile);
    const baseEnvironment = buildUiEnvironment(
      bootstrapEnvironment,
      candidate.profile,
      source,
      platform
    );

    safeStageCode = "UI_DRIVER_INVALID";
    prepareExTesterDriver({
      root,
      profile: candidate.profile,
      vscodeVersion: tool.vscodeVersion,
      environment: baseEnvironment,
      platform,
      architecture,
    }, {
      spawn,
      extestCli,
      timeout: options.driverTimeout || 300_000,
    });

    safeStageCode = "UI_PROBE_INVALID";
    const probe = runTestPhase({
      phase: "probe",
      testFile: PROBE_FILE,
      expectedStatus: 1,
      root,
      source,
      profile: candidate.profile,
      tool,
      spawn,
      extestCli,
      xvfb,
      baseEnvironment,
      randomBytes: options.randomBytes || crypto.randomBytes,
      timeout: options.testTimeout || 180_000,
    });
    validateProbeEvidence(probe.evidence, source, probe.nonce);
    safeStageCode = "UI_PROFILE_RESET_FAILED";
    await resetUserData(candidate.profile);
    assertRealDirectoryInside(candidate.profile.userDataDir, candidate.profile.root);

    safeStageCode = "UI_SUITE_INVALID";
    const suite = runTestPhase({
      phase: "suite",
      testFile: SUITE_FILE,
      expectedStatus: 0,
      root,
      source,
      profile: candidate.profile,
      tool,
      spawn,
      extestCli,
      xvfb,
      baseEnvironment,
      randomBytes: options.randomBytes || crypto.randomBytes,
      timeout: options.testTimeout || 180_000,
    });
    validateSuiteEvidence(suite.evidence, source, suite.nonce);
    safeStageCode = "UI_SOURCE_DRIFT";
    const finalSource = readSource(root, options.gitSpawn || spawn, bootstrapEnvironment);
    if (!sameSource(finalSource, source)) throw safeFailure("UI_SOURCE_DRIFT");

    result = passedReceipt(source, tool, binding, platform, architecture);
  } catch (error) {
    failure = normalizeFailure(error, safeStageCode);
  }

  try {
    const cleanupCandidate = candidate?.cleanup;
    if (cleanupCandidate) {
      const profileRoot = candidate.profile?.root;
      const cleaned = await cleanupCandidate.call(candidate);
      if (cleaned !== true || typeof profileRoot !== "string" || fs.existsSync(profileRoot)) {
        throw safeFailure("UI_PROFILE_CLEANUP_FAILED");
      }
    }
  } catch {
    failure = safeFailure("UI_PROFILE_CLEANUP_FAILED");
  }

  try {
    cleanupNonAuthQualityEnvironment(nonAuthBoundary);
  } catch {
    failure = safeFailure("UI_SMOKE_FAILED");
  }

  if (failure) {
    try {
      removeOutputFile(RESULT_PATH, root, { subtree: ".quality/ui" });
    } catch {
      // The safe failure below never includes the raw filesystem error.
    }
    throw failure;
  }
  try {
    writeJson(RESULT_PATH, result, root, { subtree: ".quality/ui" });
  } catch {
    throw safeFailure("UI_SMOKE_FAILED");
  }
  return result;
}

function prepareExTesterCode(context, options = {}) {
  runChild({
    spawn: options.spawn || spawnSync,
    command: process.execPath,
    args: [
      options.extestCli || resolveExtestCli(context.root),
      "get-vscode",
      "--storage", context.profile.testResourcesDir,
      "--code_version", context.vscodeVersion,
      "--type", "stable",
      "--config", path.join(context.root, CONFIG_PATH),
    ],
    cwd: context.root,
    environment: context.environment,
    timeout: options.timeout || 300_000,
    expectedStatus: 0,
    failureCode: "UI_TOOL_UNSUPPORTED",
  });
  const { ExTester, ReleaseQuality } = require(resolveExtesterMain(context.root));
  const tester = new ExTester(
    context.profile.testResourcesDir,
    ReleaseQuality.Stable,
    context.profile.extensionsDir
  );
  return Object.freeze({
    executable: tester.code.getExecutablePath(),
    appRoot: tester.code.getCodeFolder(),
  });
}

function prepareExTesterDriver(context, options = {}) {
  runChild({
    spawn: options.spawn || spawnSync,
    command: process.execPath,
    args: [
      options.extestCli || resolveExtestCli(context.root),
      "get-chromedriver",
      "--storage", context.profile.testResourcesDir,
      "--code_version", context.vscodeVersion,
      "--type", "stable",
      "--config", path.join(context.root, CONFIG_PATH),
    ],
    cwd: context.root,
    environment: context.environment,
    timeout: options.timeout || 300_000,
    expectedStatus: 0,
    failureCode: "UI_DRIVER_INVALID",
  });
  validateDriver(context.profile, context.platform, context.architecture);
  return true;
}

function passedReceipt(source, tool, binding, platform, architecture) {
  return {
    schemaVersion: 2,
    status: "passed",
    source,
    sourceSha: source.sha,
    candidate: {
      candidateReceiptFingerprint: binding.candidateReceiptFingerprint,
      extensionId: binding.extensionId,
      extensionVersion: binding.extensionVersion,
      profileMode: "ci",
      sourceFingerprint: source.fingerprint,
      sourceSha: source.sha,
      vscodeVersion: tool.vscodeVersion,
      vsixSha256: binding.vsixSha256,
    },
    tool: "vscode-extension-tester",
    toolVersion: tool.toolVersion,
    vscodeVersion: tool.vscodeVersion,
    platform,
    architecture,
    launchAttempted: true,
    tests: [...DECLARED_TESTS],
    results: DECLARED_TESTS.map(name => ({ name, status: "passed" })),
    reason: null,
  };
}

function validateToolContract(root, toolOverride, nodeVersion = process.versions.node) {
  const config = readJson(CONFIG_PATH, root);
  const settings = readJson(SETTINGS_PATH, root);
  const mocha = readJson(MOCHA_CONFIG_PATH, root);
  if (!hasExactKeys(config, ["$schema", "run", "setup"])
    || !hasExactKeys(config.setup, [
      "extensionsDir", "installDependencies", "noCache", "packageOptions", "storage",
      "type", "vscodeVersion",
    ])
    || !hasExactKeys(config.setup.packageOptions, ["followSymlinks", "useYarn"])
    || !hasExactKeys(config.run, [
      "cleanup", "coverage", "extensionsDir", "locale", "logLevel", "mochaConfig",
      "offline", "resources", "settings", "storage", "testFiles", "type", "vscodeVersion",
    ])
    || config.setup.vscodeVersion !== VSCODE_VERSION
    || config.run.vscodeVersion !== VSCODE_VERSION
    || config.setup.type !== "stable" || config.run.type !== "stable"
    || config.setup.storage !== `./${DIRECT_ENTRY_SENTINEL}`
    || config.setup.extensionsDir !== `./${DIRECT_ENTRY_SENTINEL}`
    || config.run.storage !== `./${DIRECT_ENTRY_SENTINEL}`
    || config.run.extensionsDir !== `./${DIRECT_ENTRY_SENTINEL}`
    || JSON.stringify(config.run.testFiles) !== JSON.stringify([`./${SUITE_FILE}`])
    || config.run.settings !== `./${SETTINGS_PATH}`
    || config.run.mochaConfig !== `./${MOCHA_CONFIG_PATH}`
    || config.setup.installDependencies !== false
    || config.setup.noCache !== false
    || config.setup.packageOptions.useYarn !== false
    || config.setup.packageOptions.followSymlinks !== false
    || config.run.cleanup !== false
    || config.run.logLevel !== "Info"
    || config.run.offline !== true
    || config.run.coverage !== false
    || JSON.stringify(config.run.resources) !== "[]"
    || config.run.locale !== ""
    || !hasExactKeys(mocha, [
      "failZero", "forbidOnly", "forbidPending", "reporter", "timeout", "ui",
    ])
    || mocha.ui !== "tdd" || mocha.timeout !== 45_000
    || mocha.failZero !== true || mocha.forbidOnly !== true || mocha.forbidPending !== true
    || mocha.reporter !== "./ui-test/evidence-reporter.js"
    || !hasExactKeys(settings, [
      "chat.disableAIFeatures", "chat.enabled", "extensions.autoCheckUpdates",
      "extensions.autoUpdate", "extensions.ignoreRecommendations",
      "security.workspace.trust.enabled", "telemetry.telemetryLevel", "update.mode",
      "workbench.enableExperiments", "workbench.startupEditor",
    ])
    || settings["security.workspace.trust.enabled"] !== false
    || settings["telemetry.telemetryLevel"] !== "off"
    || settings["update.mode"] !== "none"
    || settings["extensions.autoCheckUpdates"] !== false
    || settings["extensions.autoUpdate"] !== false
    || settings["extensions.ignoreRecommendations"] !== true
    || settings["chat.disableAIFeatures"] !== true
    || settings["chat.enabled"] !== false
    || settings["workbench.enableExperiments"] !== false
    || settings["workbench.startupEditor"] !== "none") {
    throw safeFailure("UI_TOOL_UNSUPPORTED");
  }
  const sentinel = resolveExistingRepositoryFile(DIRECT_ENTRY_SENTINEL, root);
  if (fs.readFileSync(sentinel, "utf8") !== DIRECT_ENTRY_SENTINEL_TEXT) {
    throw safeFailure("UI_TOOL_UNSUPPORTED");
  }
  const toolPackage = toolOverride || require(resolveExtesterPackage(root));
  if (nodeVersion !== NODE_VERSION
    || toolPackage.name !== "vscode-extension-tester"
    || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(toolPackage.version || "")
    || !isPlainObject(toolPackage.supportedVersions)
    || compareVersions(VSCODE_VERSION, toolPackage.supportedVersions["vscode-min"]) < 0
    || compareVersions(VSCODE_VERSION, toolPackage.supportedVersions["vscode-max"]) > 0) {
    throw safeFailure("UI_TOOL_UNSUPPORTED");
  }
  return Object.freeze({ toolVersion: toolPackage.version, vscodeVersion: VSCODE_VERSION });
}

function validateDeclaredInventory(root) {
  const workflows = readJson(WORKFLOWS_PATH, root);
  const declared = uniqueSorted((workflows.workflows || []).flatMap(workflow => (
    (workflow.evidence || [])
      .filter(item => item.layer === "black-box-ui")
      .flatMap(item => item.testNames || [])
  )));
  if (JSON.stringify(declared) !== JSON.stringify(DECLARED_TESTS)
    || SUITE_TESTS.some(name => !testSourceContains(root, SUITE_FILE, name))
    || !testSourceContains(root, PROBE_FILE, PROBE_TEST)) {
    throw safeFailure("UI_INVENTORY_INVALID");
  }
}

function validateCandidate(candidate, context) {
  const { root, source, tool, platform, architecture } = context;
  if (!isPlainObject(candidate)
    || !hasExactKeys(candidate, ["cleanup", "profile", "receipt"])
    || typeof candidate.cleanup !== "function"
    || !isPlainObject(candidate.profile)
    || !isPlainObject(candidate.receipt)) {
    throw safeFailure("UI_CANDIDATE_INVALID");
  }
  const receipt = candidate.receipt;
  if (!hasExactKeys(receipt, [
    "artifact", "capturedAt", "extension", "fingerprint", "installation", "launch",
    "profile", "repository", "schemaVersion", "source", "status", "vscode",
  ])
    || receipt.schemaVersion !== 2 || receipt.status !== "passed"
    || !canonicalTimestamp(receipt.capturedAt)
    || !hasExactKeys(receipt.repository, ["branch", "dirty", "status"])
    || !(receipt.repository.branch === null
      || (typeof receipt.repository.branch === "string"
        && receipt.repository.branch.length > 0
        && receipt.repository.branch.length <= 255
        && !/[\u0000-\u001f\u007f]/u.test(receipt.repository.branch)))
    || typeof receipt.repository.dirty !== "boolean"
    || receipt.repository.status !== (receipt.repository.dirty ? "dirty" : "clean")
    || !/^[a-f0-9]{64}$/u.test(receipt.fingerprint || "")) {
    throw safeFailure("UI_CANDIDATE_INVALID");
  }
  const unsignedReceipt = { ...receipt };
  delete unsignedReceipt.fingerprint;
  if (fingerprint(unsignedReceipt) !== receipt.fingerprint
    || !sameSource(receipt.source, source)) {
    throw safeFailure("UI_CANDIDATE_INVALID");
  }

  const manifest = readJson("package.json", root);
  const extensionId = `${manifest.publisher}.${manifest.name}`;
  if (!hasExactKeys(receipt.extension, ["id", "name", "publisher", "version"])
    || receipt.extension.id !== extensionId
    || receipt.extension.publisher !== manifest.publisher
    || receipt.extension.name !== manifest.name
    || receipt.extension.version !== manifest.version
    || !hasExactKeys(receipt.installation, ["id", "status", "version"])
    || receipt.installation.status !== "passed"
    || receipt.installation.id !== extensionId
    || receipt.installation.version !== manifest.version) {
    throw safeFailure("UI_CANDIDATE_INVALID");
  }
  validateCandidateProfile(candidate, platform, architecture);
  if (!hasExactKeys(receipt.vscode, ["cli", "executable", "version"])
    || receipt.vscode.version !== tool.vscodeVersion
    || receipt.vscode.executable !== candidate.profile.executable
    || receipt.vscode.cli !== candidate.profile.cli
    || !hasExactKeys(receipt.launch, ["developmentPath", "status"])
    || receipt.launch.status !== "not-requested"
    || receipt.launch.developmentPath !== false) {
    throw safeFailure("UI_CANDIDATE_INVALID");
  }
  assertRealFileInside(candidate.profile.executable, candidate.profile.root);
  assertRealFileInside(candidate.profile.cli, candidate.profile.root);

  const artifact = receipt.artifact;
  const artifactFilename = `${manifest.name}-${manifest.version}.vsix`;
  const allowedArtifactPaths = new Set([
    `out/development/${artifactFilename}`,
    `out/release/${artifactFilename}`,
  ]);
  if (!hasExactKeys(artifact, [
    "absoluteVsixPath", "archiveBytes", "entryCount", "sha256", "sourceFingerprint",
    "sourceSha", "vsixPath",
  ])
    || typeof artifact.vsixPath !== "string"
    || !allowedArtifactPaths.has(artifact.vsixPath)
    || assertRepositoryRelativePath(artifact.vsixPath) !== artifact.vsixPath
    || typeof artifact.absoluteVsixPath !== "string"
    || !/^[a-f0-9]{64}$/u.test(artifact.sha256 || "")
    || artifact.sourceSha !== source.sha
    || artifact.sourceFingerprint !== source.fingerprint
    || !Number.isSafeInteger(artifact.archiveBytes) || artifact.archiveBytes <= 0
    || artifact.archiveBytes > MAX_VSIX_BYTES
    || !Number.isSafeInteger(artifact.entryCount) || artifact.entryCount <= 0
    || artifact.entryCount > MAX_VSIX_ENTRIES) {
    throw safeFailure("UI_CANDIDATE_INVALID");
  }
  const artifactPath = resolveExistingRepositoryFile(artifact.vsixPath, root);
  const stat = fs.lstatSync(artifactPath);
  const digest = sha256File(artifactPath);
  if (artifact.absoluteVsixPath !== artifactPath
    || stat.size !== artifact.archiveBytes || digest !== artifact.sha256) {
    throw safeFailure("UI_CANDIDATE_INVALID");
  }
  return Object.freeze({
    candidateReceiptFingerprint: receipt.fingerprint,
    extensionId,
    extensionVersion: manifest.version,
    vsixSha256: artifact.sha256,
  });
}

function validateCandidateProfile(candidate, platform, architecture) {
  const receiptProfile = candidate.receipt.profile;
  const profile = candidate.profile;
  if (!hasExactKeys(receiptProfile, [
    "extensionsDir", "mode", "persistent", "root", "testResourcesDir", "userDataDir",
  ])
    || receiptProfile.mode !== "ci" || receiptProfile.persistent !== false
    || receiptProfile.root !== profile.root
    || receiptProfile.testResourcesDir !== profile.testResourcesDir
    || receiptProfile.userDataDir !== profile.userDataDir
    || receiptProfile.extensionsDir !== profile.extensionsDir
    || !path.isAbsolute(profile.root)
    || profile.testResourcesDir !== profile.root
    || profile.userDataDir !== path.join(profile.root, "settings")
    || profile.extensionsDir !== path.join(profile.root, "extensions")
    || profile.homeDir !== path.join(profile.root, "home")
    || !new Set(["darwin", "linux", "win32"]).has(platform)
    || !new Set(["arm64", "x64"]).has(architecture)
    || (platform === "win32" && architecture !== "x64")) {
    throw safeFailure("UI_CANDIDATE_INVALID");
  }
  assertPrivateRealDirectory(profile.root);
  for (const directory of [
    profile.testResourcesDir,
    profile.userDataDir,
    profile.extensionsDir,
    profile.homeDir,
  ]) assertRealDirectoryInside(directory, profile.root);
}

function validateLaunchArguments(args, profile) {
  const expected = [
    "--user-data-dir", profile.userDataDir,
    "--extensions-dir", profile.extensionsDir,
    "--disable-updates",
    "--skip-welcome",
    "--skip-release-notes",
    "--new-window",
  ];
  if (!Array.isArray(args) || JSON.stringify(args) !== JSON.stringify(expected)) {
    throw safeFailure("UI_CANDIDATE_INVALID");
  }
}

function buildUiEnvironment(environment, profile, source, platform) {
  const sanitized = {
    ...sanitizeQualificationEnvironment(environment, profile.homeDir, { platform }),
  };
  for (const name of Object.keys(sanitized)) {
    if (name.startsWith("CLOUDSMITH_QUALITY_")
      || name.startsWith("CLOUDSMITH_UI_")
      || name.startsWith("VSCODE_TEST_")) {
      delete sanitized[name];
    }
  }
  Object.assign(sanitized, {
    TEST_RESOURCES: profile.testResourcesDir,
    EXTENSIONS_FOLDER: profile.extensionsDir,
    CLOUDSMITH_QUALITY_SOURCE_SHA: source.sha,
    CLOUDSMITH_QUALITY_SOURCE_FINGERPRINT: source.fingerprint,
  });
  for (const name of PRIVATE_NON_AUTH_TOOL_ENVIRONMENT_NAMES) {
    if (typeof environment[name] !== "string") throw safeFailure("UI_DRIVER_INVALID");
    sanitized[name] = environment[name];
  }
  return Object.freeze(sanitized);
}

function runTestPhase(options) {
  const nonce = freshNonce(options.randomBytes);
  const evidenceDirectory = path.join(options.profile.root, "evidence");
  ensurePrivateDirectory(evidenceDirectory, options.profile.root);
  const evidencePath = path.join(evidenceDirectory, `${options.phase}-${nonce}.json`);
  const environment = {
    ...options.baseEnvironment,
    CLOUDSMITH_UI_EVIDENCE_ROOT: options.profile.root,
    CLOUDSMITH_UI_EVIDENCE_PATH: evidencePath,
    CLOUDSMITH_UI_EVIDENCE_PHASE: options.phase,
    CLOUDSMITH_UI_EVIDENCE_NONCE: nonce,
  };
  if (options.phase === "probe") {
    environment.CLOUDSMITH_UI_PROBE_SELECTOR = `Cloudsmith false-green ${nonce}`;
  }
  const extestArguments = [
    options.extestCli,
    "run-tests", `./${options.testFile}`,
    "--storage", options.profile.testResourcesDir,
    "--extensions_dir", options.profile.extensionsDir,
    "--code_version", options.tool.vscodeVersion,
    "--type", "stable",
    "--code_settings", path.join(options.root, SETTINGS_PATH),
    "--mocha_config", path.join(options.root, MOCHA_CONFIG_PATH),
    "--log_level", "Info",
    "--offline",
    "--config", path.join(options.root, CONFIG_PATH),
  ];
  const command = options.xvfb || process.execPath;
  const args = options.xvfb
    ? ["-a", process.execPath, ...extestArguments]
    : extestArguments;
  runChild({
    spawn: options.spawn,
    command,
    args,
    cwd: options.root,
    environment,
    timeout: options.timeout,
    expectedStatus: options.expectedStatus,
    failureCode: options.phase === "probe" ? "UI_PROBE_INVALID" : "UI_SUITE_INVALID",
  });
  const failureCode = options.phase === "probe" ? "UI_PROBE_INVALID" : "UI_SUITE_INVALID";
  return { evidence: readEvidence(evidencePath, failureCode), nonce };
}

function runChild(options) {
  const result = options.spawn(options.command, options.args, {
    cwd: options.cwd,
    env: options.environment,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
    shell: false,
    timeout: options.timeout,
    windowsHide: true,
  });
  if (!result || result.error || result.signal !== null
    || result.status !== options.expectedStatus) {
    throw safeFailure(options.failureCode);
  }
}

function validateProbeEvidence(value, source, nonce) {
  validateEvidenceEnvelope(value, "probe", source, nonce);
  if (JSON.stringify(value.totals) !== JSON.stringify({ passed: 0, failed: 1, pending: 0 })
    || value.records.length !== 1
    || !hasExactKeys(value.records[0], ["errorKind", "name", "status"])
    || value.records[0].name !== PROBE_TEST
    || value.records[0].status !== "failed"
    || value.records[0].errorKind !== "fresh-wrong-selector-rejected") {
    throw safeFailure("UI_PROBE_INVALID");
  }
}

function validateSuiteEvidence(value, source, nonce) {
  validateEvidenceEnvelope(value, "suite", source, nonce);
  const expectedRecords = SUITE_TESTS.map(name => ({ name, status: "passed", errorKind: null }));
  if (JSON.stringify(value.totals) !== JSON.stringify({ passed: 5, failed: 0, pending: 0 })
    || JSON.stringify(value.records) !== JSON.stringify(expectedRecords)) {
    throw safeFailure("UI_SUITE_INVALID");
  }
}

function validateEvidenceEnvelope(value, phase, source, nonce) {
  if (!isPlainObject(value)
    || !hasExactKeys(value, ["nonce", "phase", "records", "schemaVersion", "source", "totals"])
    || value.schemaVersion !== 1 || value.phase !== phase || value.nonce !== nonce
    || !sameSource(value.source, source)
    || !isPlainObject(value.totals)
    || !hasExactKeys(value.totals, ["failed", "passed", "pending"])
    || !Array.isArray(value.records)) {
    throw safeFailure(phase === "probe" ? "UI_PROBE_INVALID" : "UI_SUITE_INVALID");
  }
}

function readEvidence(target, failureCode = "UI_SMOKE_FAILED") {
  let stat;
  try {
    stat = fs.lstatSync(target);
  } catch {
    throw safeFailure(failureCode);
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0 || stat.size > MAX_EVIDENCE_BYTES) {
    throw safeFailure(failureCode);
  }
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(fs.readFileSync(target));
    return JSON.parse(text);
  } catch {
    throw safeFailure(failureCode);
  }
}

function validateDriver(profile, platform, architecture) {
  const platformName = platform === "darwin"
    ? `mac-${architecture}`
    : platform === "linux" ? "linux64" : "win64";
  const binary = platform === "win32" ? "chromedriver.exe" : "chromedriver";
  const target = path.join(profile.testResourcesDir, `chromedriver-${platformName}`, binary);
  try {
    assertRealFileInside(target, profile.root);
    const stat = fs.lstatSync(target);
    if (platform !== "win32" && (stat.mode & 0o111) === 0) {
      throw safeFailure("UI_DRIVER_INVALID");
    }
  } catch {
    throw safeFailure("UI_DRIVER_INVALID");
  }
}

function resolveXvfb(platform, environment, override) {
  if (platform !== "linux") return null;
  if (override) return assertExecutable(override);
  for (const directory of String(environment.PATH || "").split(path.delimiter).filter(Boolean)) {
    const candidate = path.join(directory, "xvfb-run");
    if (fs.existsSync(candidate)) {
      try {
        return assertExecutable(candidate);
      } catch {
        // Continue to the next PATH entry without exposing the rejected path.
      }
    }
  }
  throw safeFailure("UI_TOOL_UNSUPPORTED");
}

function assertExecutable(target) {
  const resolved = fs.realpathSync(target);
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o111) === 0) {
    throw safeFailure("UI_TOOL_UNSUPPORTED");
  }
  return resolved;
}

function assertPrivateRealDirectory(directory) {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()
    || (process.platform !== "win32" && (stat.mode & 0o077) !== 0)) {
    throw safeFailure("UI_CANDIDATE_INVALID");
  }
}

function assertRealDirectoryInside(directory, root) {
  const resolvedRoot = path.resolve(root);
  const resolvedDirectory = path.resolve(directory);
  if (!path.isAbsolute(directory)
    || (resolvedDirectory !== resolvedRoot && !isInside(resolvedRoot, resolvedDirectory))) {
    throw safeFailure("UI_CANDIDATE_INVALID");
  }
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw safeFailure("UI_CANDIDATE_INVALID");
  const realRoot = fs.realpathSync(root);
  const realDirectory = fs.realpathSync(directory);
  if (realDirectory !== realRoot && !isInside(realRoot, realDirectory)) {
    throw safeFailure("UI_CANDIDATE_INVALID");
  }
}

function assertRealFileInside(target, root) {
  if (!path.isAbsolute(target) || !isInside(root, target)) {
    throw safeFailure("UI_CANDIDATE_INVALID");
  }
  const stat = fs.lstatSync(target);
  if (!stat.isFile() || stat.isSymbolicLink()) throw safeFailure("UI_CANDIDATE_INVALID");
  const realTarget = fs.realpathSync(target);
  const realRoot = fs.realpathSync(root);
  if (!isInside(realRoot, realTarget)) throw safeFailure("UI_CANDIDATE_INVALID");
}

function ensurePrivateDirectory(directory, root) {
  if (!isInside(root, directory)) throw safeFailure("UI_CANDIDATE_INVALID");
  if (!fs.existsSync(directory)) fs.mkdirSync(directory, { mode: 0o700 });
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()
    || (process.platform !== "win32" && (stat.mode & 0o077) !== 0)) {
    throw safeFailure("UI_CANDIDATE_INVALID");
  }
}

function isInside(root, target) {
  const relative = path.relative(path.resolve(root), path.resolve(target));
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

function sha256File(target) {
  return crypto.createHash("sha256").update(fs.readFileSync(target)).digest("hex");
}

function freshNonce(randomBytes) {
  const value = randomBytes(32);
  if (!Buffer.isBuffer(value) || value.length !== 32) throw safeFailure("UI_SMOKE_FAILED");
  return value.toString("hex");
}

function sameSource(left, right) {
  return isPlainObject(left) && isPlainObject(right)
    && hasExactKeys(left, ["fingerprint", "sha"])
    && hasExactKeys(right, ["fingerprint", "sha"])
    && /^[a-f0-9]{40,64}$/u.test(left.sha || "")
    && /^[a-f0-9]{64}$/u.test(left.fingerprint || "")
    && left.sha === right.sha && left.fingerprint === right.fingerprint;
}

function hasExactKeys(value, keys) {
  return isPlainObject(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function canonicalTimestamp(value) {
  if (typeof value !== "string") return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function compareVersions(left, right) {
  if (!/^\d+\.\d+\.\d+$/u.test(left || "") || !/^\d+\.\d+\.\d+$/u.test(right || "")) {
    throw safeFailure("UI_TOOL_UNSUPPORTED");
  }
  const leftParts = left.split(".").map(Number);
  const rightParts = right.split(".").map(Number);
  for (let index = 0; index < 3; index += 1) {
    if (leftParts[index] !== rightParts[index]) return leftParts[index] - rightParts[index];
  }
  return 0;
}

function resolveExtesterPackage(root) {
  return require.resolve("vscode-extension-tester/package.json", { paths: [root] });
}

function resolveExtesterMain(root) {
  return require.resolve("vscode-extension-tester", { paths: [root] });
}

function resolveExtestCli(root) {
  return require.resolve("vscode-extension-tester/out/cli.js", { paths: [root] });
}

function loadCandidateApi() {
  return require("./prepare-qualification");
}

function loadProfileApi() {
  return require("./qualification-profile");
}

function safeFailure(code) {
  const error = new Error(SAFE_FAILURE_MESSAGES[code] || SAFE_FAILURE_MESSAGES.UI_SMOKE_FAILED);
  error.code = Object.prototype.hasOwnProperty.call(SAFE_FAILURE_MESSAGES, code)
    ? code
    : "UI_SMOKE_FAILED";
  error.uiSafe = true;
  return error;
}

function normalizeFailure(error, fallbackCode = "UI_SMOKE_FAILED") {
  return error?.uiSafe === true ? error : safeFailure(fallbackCode);
}

if (require.main === module) {
  runUiSmoke().catch(error => {
    const safe = normalizeFailure(error);
    console.error(`${safe.message} (${safe.code})`);
    process.exitCode = 1;
  });
}

module.exports = {
  DECLARED_TESTS,
  NODE_VERSION,
  PROBE_TEST,
  SUITE_TESTS,
  VSCODE_VERSION,
  buildUiEnvironment,
  compareVersions,
  passedReceipt,
  prepareExTesterCode,
  prepareExTesterDriver,
  runUiSmoke,
  validateCandidate,
  validateProbeEvidence,
  validateSuiteEvidence,
  validateToolContract,
};

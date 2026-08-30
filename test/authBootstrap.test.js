// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const { spawnSync } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const yaml = require("js-yaml");
const { withExpectedCleanupTaint } = require("./helpers/expectedCleanupTaint");
const { writeJson } = require("../scripts/quality/common");
const { fingerprint } = require("../scripts/quality/evidence");
const { isApprovedSourcePath } = require("../scripts/release/verify-vsix");
const {
  AUTHENTICATED_RESULT,
  CURRENT_VSCODE_VERSION,
  DESIGNATED_WORKSPACE,
  SECRET_ENV,
  SURFACE,
  invokeBootstrapHost,
  runAuthenticatedCi,
} = require("../scripts/quality/run-authenticated-ci");
const {
  COMMAND_LABEL,
  exactWorkspacePickerState,
  terminateOwnedProduct,
  verifyConnectedWorkspace,
} = require("../scripts/quality/authenticated-product-verifier");
const {
  assertExposureReceipt,
  assertProfileMetadataBoundary,
  assertStableAuthenticatedProof,
  captureAuthenticatedCandidateProof,
  createRuntimeLogRoot,
  destroyRuntimeLogRoot,
  runAuthenticatedExposureScan,
} = require("../scripts/quality/authenticated-exposure-scan");
const {
  verifyAuthenticatedEvidence,
} = require("../scripts/quality/verify-authenticated-evidence");
const {
  AUTHENTICATED_CANDIDATE_ARTIFACT,
  candidateBindingFromReceipt,
} = require("../scripts/quality/candidate-binding");
const {
  ProcessTreeCleanupError,
} = require("../scripts/quality/process-tree");
const {
  CI_PROFILE_PREFIX,
} = require("../scripts/quality/qualification-profile");
const {
  AUTHENTICATED_SESSION,
  cleanupPreparedAuthenticatedCandidate,
  canonicalApprovedTemporaryBase,
  markPreparedAuthenticatedCandidateProcessExit,
  prepareAuthenticatedCandidateSession,
  runAuthenticatedCandidateSessionCommand,
  sessionFromCandidate,
} = require("../scripts/quality/authenticated-candidate-session");
const {
  HOST_REQUEST_ENV,
  parseHostRequest,
  runBootstrapHost,
} = require("../scripts/quality/auth-bootstrap-host");
const {
  createCredentialHandoff,
  consumeCredentialHandoff,
  destroyCredentialHandoff,
} = require("./auth-bootstrap/handoff");
const {
  AUTH_TOKEN_KEY,
  cleanupCredential,
  seedCredential,
} = require("./auth-bootstrap/extension");
const {
  EXTENSION_ID,
  REQUEST_ENV,
  parseRequest,
  runWithVscode,
} = require("./auth-bootstrap/runner");

const ROOT = path.resolve(__dirname, "..");
const NPM_INTEGRITY = JSON.parse(fs.readFileSync(
  path.join(ROOT, ".npm-integrity"),
  "utf8",
));
const SYNTHETIC_SENTINEL = "SYNTHETIC_QUALIFICATION_SENTINEL";
const SOURCE = Object.freeze({ sha: "a".repeat(40), fingerprint: "b".repeat(64) });
const temporaryRoots = [];

function temporaryRoot(prefix = "cloudsmith-auth-bootstrap-test-") {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  if (process.platform !== "win32") fs.chmodSync(root, 0o700);
  temporaryRoots.push(root);
  return root;
}

function authenticatedRuntimeSnapshotRoot(parent) {
  const snapshots = fs.readdirSync(parent)
    .filter(name => name.startsWith("cloudsmith-authenticated-runtime-snapshot-"));
  assert.strictEqual(snapshots.length, 1);
  return path.join(parent, snapshots[0]);
}

function executable(target) {
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  fs.writeFileSync(target, "fixture\n", { mode: 0o700 });
  if (process.platform !== "win32") fs.chmodSync(target, 0o700);
  return target;
}

function candidateFixture(options = {}) {
  let processTreeExit = "pending";
  let root;
  if (options.temporaryParent) {
    root = fs.realpathSync(fs.mkdtempSync(path.join(
      options.temporaryParent,
      options.prefix || CI_PROFILE_PREFIX,
    )));
    if (process.platform !== "win32") fs.chmodSync(root, 0o700);
    temporaryRoots.push(root);
  } else {
    root = temporaryRoot(options.prefix || CI_PROFILE_PREFIX);
  }
  const homeDir = path.join(root, "home");
  const userDataDir = path.join(root, "settings");
  const extensionsDir = path.join(root, "extensions");
  for (const directory of [homeDir, userDataDir, extensionsDir]) {
    fs.mkdirSync(directory, { mode: 0o700 });
  }
  const code = executable(path.join(root, "app", "code"));
  const cli = executable(path.join(root, "app", "bin", "code"));
  const profile = {
    mode: "ci",
    persistent: false,
    root,
    testResourcesDir: root,
    homeDir,
    userDataDir,
    extensionsDir,
    executable: code,
    cli,
    vscodeVersion: CURRENT_VSCODE_VERSION,
  };
  const receiptBase = {
    schemaVersion: 3,
    status: "passed",
    capturedAt: "2026-08-27T00:00:00.000Z",
    source: SOURCE,
    repository: {
      branch: "test/release-quality-harness",
      dirty: true,
      status: "dirty",
    },
    toolchain: {
      nodeVersion: "v22.23.2",
      npmVersion: "10.9.8",
      npmInstallationSha256: NPM_INTEGRITY[
        process.platform === "win32" ? "win32" : "posix"
      ],
      platform: process.platform,
    },
    extension: {
      id: "Cloudsmith.cloudsmith-vsc",
      publisher: "Cloudsmith",
      name: "cloudsmith-vsc",
      version: "2.3.0",
    },
    vscode: { version: CURRENT_VSCODE_VERSION, executable: code, cli },
    profile: {
      mode: "ci",
      persistent: false,
      root,
      testResourcesDir: root,
      userDataDir,
      extensionsDir,
    },
    artifact: {
      vsixPath: "out/development/cloudsmith-vsc-2.3.0.vsix",
      absoluteVsixPath: path.join(ROOT, "out/development/cloudsmith-vsc-2.3.0.vsix"),
      sha256: "d".repeat(64),
      archiveBytes: 1,
      entryCount: 1,
      sourceSha: SOURCE.sha,
      sourceFingerprint: SOURCE.fingerprint,
    },
    installation: {
      status: "passed",
      id: "Cloudsmith.cloudsmith-vsc",
      version: "2.3.0",
    },
    launch: { status: "not-requested", developmentPath: false },
  };
  return {
    profile,
    receipt: { ...receiptBase, fingerprint: fingerprint(receiptBase) },
    markProcessTreeExit(value) {
      if (!new Set(["proven", "unproven"]).has(value)) {
        throw new Error("Synthetic process-tree state is invalid.");
      }
      processTreeExit = value;
      return true;
    },
    async cleanup() {
      if (processTreeExit !== "proven") {
        throw new Error("Synthetic candidate cleanup requires proven process-tree exit.");
      }
      fs.rmSync(root, { recursive: true, force: true });
      return true;
    },
  };
}

function lifecycleHarness(overrides = {}) {
  const environment = { [SECRET_ENV]: SYNTHETIC_SENTINEL, PATH: process.env.PATH || "" };
  const events = [];
  const context = {
    secrets: {
      async store(key) {
        assert.strictEqual(key, AUTH_TOKEN_KEY);
        events.push("stored");
      },
      async delete(key) {
        assert.strictEqual(key, AUTH_TOKEN_KEY);
        events.push("deleted");
      },
      async get() {
        throw new Error("Bootstrap must never inspect SecretStorage.");
      },
    },
  };
  let written = null;
  const candidate = candidateFixture();
  const options = {
    root: ROOT,
    environment,
    temporaryParent: temporaryRoot(),
    sourceIdentity: () => SOURCE,
    captureContentFreeWorktreeState: () => Buffer.from("stable-worktree-state"),
    scanCurrentWorktree: async () => ({ status: "passed", findingCount: 0 }),
    prepareQualificationCandidate: async () => candidate,
    validateCandidate: value => ({
      candidateReceiptFingerprint: value.receipt.fingerprint,
      extensionId: value.receipt.extension.id,
      extensionVersion: value.receipt.extension.version,
      vsixSha256: value.receipt.artifact.sha256,
    }),
    randomBytes: () => Buffer.alloc(32, 0xab),
    invokeBootstrapHost: async (_candidate, request) => {
      if (request.operation === "seed") {
        await seedCredential(context, request);
        events.push("seed-host-exited");
      } else {
        await cleanupCredential(context);
        events.push("cleanup-host-exited");
      }
      return true;
    },
    runAuthenticatedExposureScan: async () => {
      events.push("exposure-scan");
      return { status: "passed" };
    },
    removeReceipt: () => false,
    writeReceipt: receipt => {
      written = receipt;
    },
    checkConnectedWorkspace: async verification => {
      events.push("production-check");
      return {
        status: "passed",
        surface: SURFACE,
        workspace: DESIGNATED_WORKSPACE,
        developmentPath: false,
        source: verification.source,
        candidateReceiptFingerprint: verification.candidateReceiptFingerprint,
      };
    },
    ...overrides,
  };
  return { candidate, context, environment, events, getWritten: () => written, options };
}

suite("authenticated CI SecretStorage bootstrap", () => {
  teardown(() => {
    while (temporaryRoots.length > 0) {
      fs.rmSync(temporaryRoots.pop(), { recursive: true, force: true });
    }
  });

  test("same-ID companion consumes a private handoff before storing and deletes without reading", async () => {
    const production = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
    const bootstrap = JSON.parse(fs.readFileSync(
      path.join(ROOT, "test", "auth-bootstrap", "package.json"), "utf8"
    ));
    assert.strictEqual(`${bootstrap.publisher}.${bootstrap.name}`, `${production.publisher}.${production.name}`);
    assert.strictEqual(bootstrap.version, production.version);

    const handoff = createCredentialHandoff({
      credential: SYNTHETIC_SENTINEL,
      workspace: DESIGNATED_WORKSPACE,
      temporaryParent: temporaryRoot(),
      randomBytes: () => Buffer.alloc(32, 0xcd),
    });
    if (process.platform !== "win32") {
      assert.strictEqual(fs.lstatSync(handoff.root).mode & 0o077, 0);
      assert.strictEqual(fs.lstatSync(handoff.file).mode & 0o077, 0);
    }
    let stored = 0;
    let deleted = 0;
    const context = {
      secrets: {
        async store(key, envelope) {
          assert.strictEqual(fs.existsSync(handoff.root), false);
          assert.strictEqual(key, AUTH_TOKEN_KEY);
          assert.strictEqual(typeof envelope, "string");
          stored += 1;
        },
        async delete(key) {
          assert.strictEqual(key, AUTH_TOKEN_KEY);
          deleted += 1;
        },
        async get() {
          assert.fail("Bootstrap must never inspect SecretStorage.");
        },
      },
    };
    assert.deepStrictEqual(
      await seedCredential(context, { operation: "seed", capability: handoff }),
      { status: "stored" },
    );
    assert.deepStrictEqual(await cleanupCredential(context), { status: "deleted" });
    assert.strictEqual(stored, 1);
    assert.strictEqual(deleted, 1);
  });

  test("handoff rejects unsafe permissions and cleanup remains creator-bound", () => {
    const handoff = createCredentialHandoff({
      credential: SYNTHETIC_SENTINEL,
      workspace: DESIGNATED_WORKSPACE,
      temporaryParent: temporaryRoot(),
    });
    if (process.platform !== "win32") {
      fs.chmodSync(handoff.file, 0o644);
      assert.throws(() => consumeCredentialHandoff(handoff), /private file/u);
      assert.strictEqual(destroyCredentialHandoff(handoff), true);
    } else {
      const escaped = { ...handoff, file: path.join(path.dirname(handoff.root), "credential.handoff") };
      assert.throws(() => consumeCredentialHandoff(escaped), /escaped/u);
      assert.strictEqual(destroyCredentialHandoff(handoff), true);
    }
    assert.strictEqual(fs.existsSync(handoff.root), false);
    assert.throws(() => destroyCredentialHandoff(handoff), /unowned/u);
  });

  test("missing secret blocks before candidate preparation and removes stale output", async () => {
    let prepared = 0;
    let removed = 0;
    let receipt;
    const result = await runAuthenticatedCi({
      root: ROOT,
      environment: {},
      prepareQualificationCandidate: async () => {
        prepared += 1;
      },
      removeReceipt: () => {
        removed += 1;
      },
      writeReceipt: value => {
        receipt = value;
      },
    });
    assert.strictEqual(prepared, 0);
    assert.strictEqual(removed, 1);
    assert.strictEqual(result.status, "blocked");
    assert.strictEqual(result.reasonCode, "credential-missing");
    assert.strictEqual(receipt.fingerprint, result.fingerprint);
  });

  test("wrong fixture workspace deletes the step secret and fails before seeding", async () => {
    const environment = { [SECRET_ENV]: SYNTHETIC_SENTINEL };
    let prepared = 0;
    const result = await runAuthenticatedCi({
      root: ROOT,
      environment,
      expectedWorkspace: "wrong-workspace",
      prepareQualificationCandidate: async () => {
        prepared += 1;
      },
      removeReceipt: () => false,
      writeReceipt: () => {},
    });
    assert.strictEqual(Object.prototype.hasOwnProperty.call(environment, SECRET_ENV), false);
    assert.strictEqual(prepared, 0);
    assert.strictEqual(result.status, "failed");
    assert.strictEqual(result.reasonCode, "workspace-not-designated");
    assert.strictEqual(result.phases.seed, "not-run");
  });

  test("noncanonical repository execution deletes the secret and cannot prepare a candidate", async () => {
    const environment = { [SECRET_ENV]: SYNTHETIC_SENTINEL };
    let prepared = 0;
    const result = await runAuthenticatedCi({
      root: temporaryRoot(),
      environment,
      prepareQualificationCandidate: async () => {
        prepared += 1;
      },
      removeReceipt: () => false,
      writeReceipt: () => {},
    });
    assert.strictEqual(prepared, 0);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(environment, SECRET_ENV), false);
    assert.strictEqual(result.status, "failed");
    assert.strictEqual(result.reasonCode, "candidate-invalid");
  });

  test("connected production surface must prove the exact workspace and source before passing", async () => {
    const harness = lifecycleHarness();
    const result = await runAuthenticatedCi(harness.options);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(harness.environment, SECRET_ENV), false);
    assert.strictEqual(result.status, "passed");
    assert.strictEqual(result.schemaVersion, 2);
    assert.strictEqual(result.workspace.observed, DESIGNATED_WORKSPACE);
    assert.deepStrictEqual(harness.events, [
      "stored",
      "seed-host-exited",
      "production-check",
      "deleted",
      "cleanup-host-exited",
      "exposure-scan",
    ]);
    const serialized = JSON.stringify(harness.getWritten());
    assert.strictEqual(serialized.includes(SYNTHETIC_SENTINEL), false);
    assert.strictEqual(serialized.includes(harness.candidate.profile.root), false);
    assert.strictEqual(result.candidate.extensionId, "Cloudsmith.cloudsmith-vsc");
    assert.strictEqual(result.candidate.extensionVersion, "2.3.0");
    assert.strictEqual(result.candidate.installedExtensionId, result.candidate.extensionId);
    assert.strictEqual(
      result.candidate.installedExtensionVersion,
      result.candidate.extensionVersion
    );
    assert.strictEqual(result.candidate.sourceSha, SOURCE.sha);
    assert.strictEqual(result.candidate.sourceFingerprint, SOURCE.fingerprint);
    assert.strictEqual(result.candidate.profileMode, "ci");
    assert.match(result.candidate.profileRootIdentity, /^[a-f0-9]{64}$/u);
    assert.strictEqual(result.credentialBoundary.valueRecorded, false);
    assert.strictEqual(result.credentialBoundary.digestRecorded, false);
  });

  test("absent production verifier reports blocked after seed and still deletes the key", async () => {
    const harness = lifecycleHarness({ checkConnectedWorkspace: undefined });
    const result = await runAuthenticatedCi(harness.options);
    assert.strictEqual(result.status, "blocked");
    assert.strictEqual(result.reasonCode, "no-production-verifier");
    assert.strictEqual(result.workspace.observed, null);
    assert.deepStrictEqual(harness.events, [
      "stored",
      "seed-host-exited",
      "deleted",
      "cleanup-host-exited",
      "exposure-scan",
    ]);
    assert.strictEqual(result.phases.secretStorageCleanup, "passed");
    assert.strictEqual(result.phases.profileCleanup, "passed");
  });

  test("credential-to-workspace mismatch fails closed after connection and cleanup", async () => {
    const harness = lifecycleHarness({
      checkConnectedWorkspace: async verification => ({
        status: "passed",
        surface: SURFACE,
        workspace: "wrong-workspace",
        developmentPath: false,
        source: verification.source,
        candidateReceiptFingerprint: verification.candidateReceiptFingerprint,
      }),
    });
    const result = await runAuthenticatedCi(harness.options);
    assert.strictEqual(result.status, "failed");
    assert.strictEqual(result.reasonCode, "connected-workspace-mismatch");
    assert.strictEqual(result.workspace.observed, null);
    assert.deepStrictEqual(harness.events.slice(-3), [
      "deleted", "cleanup-host-exited", "exposure-scan",
    ]);
  });

  test("creates the credential handoff only after the candidate is exact and immediately before seed", async () => {
    const harness = lifecycleHarness();
    const order = [];
    const prepare = harness.options.prepareQualificationCandidate;
    const invoke = harness.options.invokeBootstrapHost;
    harness.options.prepareQualificationCandidate = async (...arguments_) => {
      const result = await prepare(...arguments_);
      order.push("candidate-prepared");
      return result;
    };
    harness.options.createCredentialHandoff = values => {
      order.push("handoff-created");
      return createCredentialHandoff(values);
    };
    harness.options.invokeBootstrapHost = async (candidate, request) => {
      if (request.operation === "seed") order.push("seed-started");
      return invoke(candidate, request);
    };
    const result = await runAuthenticatedCi(harness.options);
    assert.strictEqual(result.status, "passed");
    assert.deepStrictEqual(order, ["candidate-prepared", "handoff-created", "seed-started"]);
  });

  test("attempts every cleanup independently and prioritizes credential cleanup failure", async () => {
    const attempts = [];
    const harness = lifecycleHarness({
      invokeBootstrapHost: async (_candidate, request) => {
        if (request.operation === "seed") return true;
        attempts.push("secret-storage-cleanup");
        throw new Error("synthetic cleanup failure");
      },
      runAuthenticatedExposureScan: async () => {
        attempts.push("exposure-scan");
        throw new Error("synthetic exposure failure");
      },
      destroyRuntimeLogRoot: () => {
        attempts.push("runtime-log-cleanup");
        throw new Error("synthetic log cleanup failure");
      },
    });
    harness.candidate.cleanup = async () => {
      attempts.push("profile-cleanup");
      throw new Error("synthetic profile cleanup failure");
    };
    const result = await runAuthenticatedCi(harness.options);
    assert.deepStrictEqual(attempts, [
      "secret-storage-cleanup",
      "profile-cleanup",
      "exposure-scan",
      "runtime-log-cleanup",
      "profile-cleanup",
    ]);
    assert.strictEqual(result.status, "failed");
    assert.strictEqual(result.reasonCode, "credential-cleanup-failed");
  });

  test("credential deletion failure removes the profile before long external scans", async () => {
    const attempts = [];
    const harness = lifecycleHarness({
      invokeBootstrapHost: async (_candidate, request) => {
        if (request.operation === "seed") return true;
        attempts.push("secret-storage-cleanup");
        throw new Error("synthetic credential deletion failure");
      },
      runAuthenticatedExposureScan: async context => {
        attempts.push("exposure-scan");
        assert.ok(context.profileBoundaryProof);
        assert.strictEqual(fs.existsSync(harness.candidate.profile.root), false);
        return { status: "passed" };
      },
    });
    harness.candidate.cleanup = async () => {
      attempts.push("profile-cleanup");
      fs.rmSync(harness.candidate.profile.root, { recursive: true, force: true });
      return true;
    };
    const result = await runAuthenticatedCi(harness.options);
    assert.deepStrictEqual(attempts.slice(0, 3), [
      "secret-storage-cleanup",
      "profile-cleanup",
      "exposure-scan",
    ]);
    assert.strictEqual(attempts.filter(value => value === "profile-cleanup").length, 1);
    assert.strictEqual(result.reasonCode, "credential-cleanup-failed");
    assert.strictEqual(result.phases.profileCleanup, "passed");
  });

  test("value-blind current scan blocks a post-auth source fingerprint when it finds exposure", async () => {
    let sourceIdentityCalls = 0;
    const harness = lifecycleHarness({
      sourceIdentity: () => {
        sourceIdentityCalls += 1;
        if (sourceIdentityCalls > 1) {
          assert.fail("Possible post-auth exposure must never reach sourceIdentity.");
        }
        return SOURCE;
      },
      scanCurrentWorktree: async () => ({ status: "failed", findingCount: 1 }),
    });
    const result = await runAuthenticatedCi(harness.options);
    assert.strictEqual(sourceIdentityCalls, 1);
    assert.strictEqual(result.status, "failed");
    assert.strictEqual(result.reasonCode, "exposure-scan-failed");
  });

  test("content-free path/status drift blocks the post-auth source fingerprint", async () => {
    let sourceIdentityCalls = 0;
    let stateCalls = 0;
    const harness = lifecycleHarness({
      sourceIdentity: () => {
        sourceIdentityCalls += 1;
        if (sourceIdentityCalls > 1) {
          assert.fail("Drifted post-auth content must never reach sourceIdentity.");
        }
        return SOURCE;
      },
      captureContentFreeWorktreeState: () => {
        stateCalls += 1;
        return Buffer.from(stateCalls === 1 ? "before" : "after");
      },
    });
    const result = await runAuthenticatedCi(harness.options);
    assert.strictEqual(sourceIdentityCalls, 1);
    assert.strictEqual(result.status, "failed");
    assert.strictEqual(result.reasonCode, "source-drift");
  });

  test("direct product verifier drives only safe rendered UI booleans with zero child output", async () => {
    const candidate = candidateFixture();
    const logRoot = createRuntimeLogRoot({ temporaryParent: temporaryRoot() });
    const binding = {
      receiptFingerprint: candidate.receipt.fingerprint,
      extensionId: candidate.receipt.extension.id,
      extensionVersion: candidate.receipt.extension.version,
      vsixSha256: candidate.receipt.artifact.sha256,
    };
    const context = {
      root: ROOT,
      source: SOURCE,
      expectedWorkspace: DESIGNATED_WORKSPACE,
      candidateReceiptFingerprint: binding.receiptFingerprint,
      extensionId: binding.extensionId,
      extensionVersion: binding.extensionVersion,
      vsixSha256: binding.vsixSha256,
      profile: candidate.profile,
      launchArguments: [
        "--user-data-dir", candidate.profile.userDataDir,
        "--extensions-dir", candidate.profile.extensionsDir,
        "--disable-updates",
        "--skip-welcome",
        "--skip-release-notes",
        "--new-window",
        ROOT,
      ],
      environment: {
        PATH: process.env.PATH || "",
        HOME: candidate.profile.homeDir,
        USERPROFILE: candidate.profile.homeDir,
      },
      runtimeLogRoot: logRoot.root,
    };
    const { EventEmitter } = require("events");
    const child = new EventEmitter();
    child.pid = 43209;
    child.exitCode = null;
    child.signalCode = null;
    child.kill = () => {
      child.exitCode = 0;
      child.emit("exit", 0, null);
      return true;
    };
    const session = {
      async send(method) {
        if (method === "Runtime.evaluate") {
          return { result: { type: "boolean", value: true } };
        }
        if (method === "Browser.close") {
          child.exitCode = 0;
          child.emit("exit", 0, null);
        }
        return {};
      },
      close() {},
    };
    let launched;
    const result = await verifyConnectedWorkspace(context, {
      reserveLoopbackPort: async () => 9223,
      spawn(command, arguments_, options) {
        launched = { command, arguments_, options };
        return child;
      },
      readTargets: async () => [{
        type: "page",
        url: "vscode-file://vscode-app/workbench/workbench.html",
        webSocketDebuggerUrl: "ws://127.0.0.1:9223/devtools/page/workbench",
      }],
      connect: async () => session,
    });
    assert.strictEqual(result.workspace, DESIGNATED_WORKSPACE);
    assert.strictEqual(result.developmentPath, false);
    assert.strictEqual(launched.command, candidate.profile.executable);
    assert.strictEqual(launched.options.stdio, "ignore");
    assert.strictEqual(launched.options.detached, process.platform !== "win32");
    assert.strictEqual(
      launched.arguments_.includes(`--remote-debugging-port=9223`),
      true,
    );
    for (const safetyArgument of [
      "--disable-crash-reporter",
      "--disable-telemetry",
      "--no-cached-data",
      "--disable-workspace-trust",
    ]) {
      assert.strictEqual(launched.arguments_.includes(safetyArgument), true);
    }
    assert.strictEqual(launched.arguments_.includes("--no-sandbox"), false);
    assert.strictEqual(launched.arguments_.includes("--disable-gpu-sandbox"), false);
    assert.strictEqual(launched.arguments_.at(-1), ROOT);
    assert.strictEqual(launched.arguments_.includes("--extensionDevelopmentPath"), false);
    assert.strictEqual(launched.arguments_.includes(logRoot.root), true);
    assert.strictEqual(JSON.stringify(launched.options.env).includes(SYNTHETIC_SENTINEL), false);
    assert.strictEqual(destroyRuntimeLogRoot(logRoot), true);
    fs.rmSync(candidate.profile.root, { recursive: true, force: true });
  });

  test("product proof failure cannot mask a full process-tree cleanup failure", async () => {
    const candidate = candidateFixture();
    const logRoot = createRuntimeLogRoot({ temporaryParent: temporaryRoot() });
    const context = {
      root: ROOT,
      source: SOURCE,
      expectedWorkspace: DESIGNATED_WORKSPACE,
      candidateReceiptFingerprint: candidate.receipt.fingerprint,
      extensionId: candidate.receipt.extension.id,
      extensionVersion: candidate.receipt.extension.version,
      vsixSha256: candidate.receipt.artifact.sha256,
      profile: candidate.profile,
      launchArguments: [
        "--user-data-dir", candidate.profile.userDataDir,
        "--extensions-dir", candidate.profile.extensionsDir,
        "--disable-updates", "--skip-welcome", "--skip-release-notes", "--new-window", ROOT,
      ],
      environment: {
        PATH: process.env.PATH || "",
        HOME: candidate.profile.homeDir,
        USERPROFILE: candidate.profile.homeDir,
      },
      runtimeLogRoot: logRoot.root,
    };
    const { EventEmitter } = require("events");
    const child = new EventEmitter();
    child.pid = 43210;
    child.exitCode = null;
    child.signalCode = null;
    child.kill = () => {
      child.exitCode = 1;
      child.emit("exit", 1, null);
      return true;
    };
    const session = { async send() { return {}; }, close() {} };
    await assert.rejects(
      verifyConnectedWorkspace(context, {
        reserveLoopbackPort: async () => 9224,
        spawn: () => child,
        readTargets: async () => [{
          type: "page",
          url: "vscode-file://vscode-app/workbench/workbench.html",
          webSocketDebuggerUrl: "ws://127.0.0.1:9224/devtools/page/workbench",
        }],
        connect: async () => session,
        proveConnectedWorkspace: async () => {
          throw new Error("synthetic proof failure");
        },
        terminateProcessTree: async () => false,
      }),
      /process-tree cleanup did not complete/u,
    );
    assert.strictEqual(destroyRuntimeLogRoot(logRoot), true);
    fs.rmSync(candidate.profile.root, { recursive: true, force: true });
  });

  test("runtime-log cleanup fails closed on final root substitution", () => {
    const parent = temporaryRoot("cloudsmith-runtime-log-cleanup-swap-");
    const logRoot = createRuntimeLogRoot({ temporaryParent: parent });
    fs.writeFileSync(path.join(logRoot.root, "owned.log"), "synthetic owned log bytes\n");
    const victim = path.join(parent, "synthetic-log-victim");
    fs.mkdirSync(victim, { mode: 0o700 });
    fs.writeFileSync(path.join(victim, "preserve.txt"), "synthetic victim survives\n");
    const displaced = path.join(parent, "owned-log-root-displaced");
    const originalRename = fs.renameSync;
    const originalRmdir = fs.rmdirSync;
    let substituted = false;
    try {
      fs.rmdirSync = function interceptFinalRuntimeLogRemoval(target, options) {
        if (!substituted && target === logRoot.root) {
          originalRename.call(fs, target, displaced);
          originalRename.call(fs, victim, target);
          substituted = true;
        }
        return originalRmdir.call(fs, target, options);
      };
      withExpectedCleanupTaint(() => {
        assert.throws(
          () => destroyRuntimeLogRoot(logRoot),
          /unsafe or changed tree/u,
        );
      });
    } finally {
      fs.rmdirSync = originalRmdir;
    }
    assert.strictEqual(substituted, true);
    assert.strictEqual(fs.existsSync(displaced), true);
    assert.strictEqual(
      fs.readFileSync(path.join(logRoot.root, "preserve.txt"), "utf8"),
      "synthetic victim survives\n",
    );
  });

  test("production workspace proof requires an exact selectable workspace row", () => {
    const exact = {
      placeholder: "Select a default workspace",
      rows: [{
        label: "DL Technology Consulting",
        description: DESIGNATED_WORKSPACE,
        disabled: false,
      }],
    };
    assert.strictEqual(COMMAND_LABEL, "Cloudsmith: Set default workspace");
    assert.strictEqual(exactWorkspacePickerState(exact, DESIGNATED_WORKSPACE), true);
    assert.strictEqual(exactWorkspacePickerState({
      ...exact,
      input: DESIGNATED_WORKSPACE,
      message: DESIGNATED_WORKSPACE,
      rows: [],
    }, DESIGNATED_WORKSPACE), false);
    assert.strictEqual(exactWorkspacePickerState({
      ...exact,
      rows: [{ ...exact.rows[0], disabled: true }],
    }, DESIGNATED_WORKSPACE), false);
    assert.strictEqual(exactWorkspacePickerState({
      ...exact,
      placeholder: "Search packages in dl-technology-consulting",
    }, DESIGNATED_WORKSPACE), false);
    assert.strictEqual(exactWorkspacePickerState({
      ...exact,
      rows: [{
        ...exact.rows[0],
        description: `Unavailable: ${DESIGNATED_WORKSPACE}`,
      }],
    }, DESIGNATED_WORKSPACE), false);
  });

  test("product cleanup exceptions are normalized to the process-tree boundary", async () => {
    let sessionClosed = 0;
    await assert.rejects(
      terminateOwnedProduct(
        { pid: 43213 },
        { close() { sessionClosed += 1; } },
        {
          terminateProcessTree: async () => {
            throw new Error("synthetic tree adapter failure");
          },
        },
      ),
      error => error instanceof ProcessTreeCleanupError,
    );
    assert.strictEqual(sessionClosed, 1);
  });

  test("process-tree cleanup failure remains the lifecycle reason after every finalizer", async () => {
    const harness = lifecycleHarness({
      checkConnectedWorkspace: async () => {
        throw new ProcessTreeCleanupError();
      },
      runAuthenticatedExposureScan: async () => {
        throw new Error("synthetic exposure failure");
      },
    });
    harness.candidate.cleanup = async () => false;
    const result = await runAuthenticatedCi(harness.options);
    assert.strictEqual(result.status, "failed");
    assert.strictEqual(result.reasonCode, "process-tree-cleanup-failed");
    assert.strictEqual(result.phases.outputBoundary, "failed");
    assert.strictEqual(result.phases.secretStorageCleanup, "passed");
  });

  test("unproven process-tree exit preserves authenticated cleanup retry ownership", async () => {
    const harness = lifecycleHarness({
      checkConnectedWorkspace: async () => {
        throw new ProcessTreeCleanupError();
      },
    });
    const retryRoot = temporaryRoot("cloudsmith-authenticated-retry-test-");
    const retryDescriptor = path.join(retryRoot, AUTHENTICATED_SESSION);
    fs.mkdirSync(path.dirname(retryDescriptor), { recursive: true, mode: 0o700 });
    fs.writeFileSync(retryDescriptor, "{}\n", { mode: 0o600 });
    let cleanupCalls = 0;
    let persistedProcessExit = null;
    const persistProcessExit = harness.candidate.markProcessTreeExit;
    harness.candidate.markProcessTreeExit = value => {
      persistedProcessExit = value;
      return persistProcessExit(value);
    };
    harness.candidate.cleanup = async () => {
      cleanupCalls += 1;
      fs.rmSync(harness.candidate.profile.root, { recursive: true, force: true });
      fs.mkdirSync(harness.candidate.profile.root, { mode: 0o700 });
      fs.rmSync(retryDescriptor, { force: true });
      return true;
    };

    const result = await runAuthenticatedCi(harness.options);

    assert.strictEqual(result.status, "failed");
    assert.strictEqual(result.reasonCode, "process-tree-cleanup-failed");
    assert.strictEqual(result.phases.profileCleanup, "not-run");
    assert.strictEqual(persistedProcessExit, "unproven");
    assert.strictEqual(cleanupCalls, 0);
    assert.strictEqual(fs.existsSync(retryDescriptor), true);
  });

  test("authenticated exposure scan ignores mutable output and reads no profile content", async () => {
    const candidate = candidateFixture();
    const snapshotParent = temporaryRoot("cloudsmith-authenticated-stdin-test-");
    const logRoot = createRuntimeLogRoot({ temporaryParent: snapshotParent });
    const runtimeLogFixture = "bounded synthetic runtime-log receipt fixture\n";
    fs.writeFileSync(
      path.join(logRoot.root, "runtime.log"),
      runtimeLogFixture,
      { mode: 0o600 },
    );
    let persisted;
    const originalRead = fs.readFileSync;
    fs.readFileSync = function guardedRead(target, ...arguments_) {
      if (typeof target === "string"
        && (target === candidate.profile.root
          || target.startsWith(`${candidate.profile.root}${path.sep}`))) {
        assert.fail("Authenticated exposure scan must not read profile contents.");
      }
      return originalRead.call(this, target, ...arguments_);
    };
    const proofSnapshot = {
      artifactPath: AUTHENTICATED_CANDIDATE_ARTIFACT,
      candidateReceiptFingerprint: candidate.receipt.fingerprint,
      sourceFingerprint: SOURCE.fingerprint,
      sourceSha: SOURCE.sha,
      vsixSha256: candidate.receipt.artifact.sha256,
      identity: {
        device: "1",
        inode: "2",
        size: String(candidate.receipt.artifact.archiveBytes),
        modifiedNanoseconds: "3",
        changedNanoseconds: "4",
      },
    };
    let scannedArtifactPath;
    let scannedRuntimeLogPath;
    let scannedRuntimeLogInput;
    let scannedSnapshotRoot;
    let result;
    try {
      result = await runAuthenticatedExposureScan({
        root: ROOT,
        source: SOURCE,
        candidate,
        candidateReceiptFingerprint: candidate.receipt.fingerprint,
        runtimeLogRoot: logRoot.root,
        environment: { PATH: process.env.PATH || "" },
      }, {
        temporaryParent: snapshotParent,
        assertScannerVersion() {},
        scanGeneratedEvidence: () => ({
          id: "authenticated-generated-evidence",
          status: "scanned",
          fileCount: 2,
          findings: [],
        }),
        captureAuthenticatedCandidateProof: () => proofSnapshot,
        scanVsix: async (_root, relativePath) => {
          scannedArtifactPath = relativePath;
          return {
            id: `vsix:${relativePath}`,
            status: "scanned",
            fileCount: 3,
            findings: [],
          };
        },
        scanWithGitleaks(kind, target, options) {
          scannedRuntimeLogPath = target;
          scannedSnapshotRoot = authenticatedRuntimeSnapshotRoot(snapshotParent);
          assert.strictEqual(kind, "stdin");
          assert.strictEqual(target, "runtime.log");
          assert.strictEqual(path.isAbsolute(target), false);
          assert.strictEqual(options.logicalPath, target);
          assert.strictEqual(Object.hasOwn(options, "scanRoot"), false);
          assert.ok(Buffer.isBuffer(options.input));
          assert.deepStrictEqual(options.input, Buffer.from(runtimeLogFixture));
          scannedRuntimeLogInput = options.input;
          return [];
        },
        async writeReceipt(value) {
          await new Promise(resolve => setImmediate(resolve));
          assert.strictEqual(fs.existsSync(scannedSnapshotRoot), true);
          persisted = value;
        },
      });
    } finally {
      fs.readFileSync = originalRead;
    }
    assert.strictEqual(result.status, "passed");
    assert.strictEqual(result.schemaVersion, 2);
    assert.strictEqual(result.vsixSha256, candidate.receipt.artifact.sha256);
    assert.strictEqual(scannedArtifactPath, AUTHENTICATED_CANDIDATE_ARTIFACT);
    assert.strictEqual(
      result.components[1].id,
      `vsix:${AUTHENTICATED_CANDIDATE_ARTIFACT}`,
    );
    assert.strictEqual(result.components.length, 4);
    assert.strictEqual(result.components[2].status, "scanned");
    assert.strictEqual(result.components[2].fileCount, 1);
    assert.strictEqual(scannedRuntimeLogPath, "runtime.log");
    assert.ok(scannedRuntimeLogInput.every(byte => byte === 0));
    assert.ok(scannedSnapshotRoot);
    assert.strictEqual(fs.existsSync(scannedSnapshotRoot), false);
    assert.strictEqual(result.credentialBoundary.profileContentRead, false);
    assert.strictEqual(result.credentialBoundary.secretStorageRead, false);
    assert.strictEqual(result.credentialBoundary.keychainRead, false);
    assert.strictEqual(result.credentialBoundary.credentialValueRecorded, false);
    assert.strictEqual(result.credentialBoundary.credentialDigestRecorded, false);
    assert.strictEqual(JSON.stringify(result).includes(runtimeLogFixture.trim()), false);
    assert.strictEqual(persisted.fingerprint, result.fingerprint);
    assert.strictEqual(destroyRuntimeLogRoot(logRoot), true);
    fs.rmSync(candidate.profile.root, { recursive: true, force: true });
  });

  test("authenticated runtime logs remain descriptor-proven stdin when snapshot paths swap", async () => {
    const candidate = candidateFixture();
    const snapshotParent = temporaryRoot("cloudsmith-authenticated-path-swap-test-");
    const logRoot = createRuntimeLogRoot({ temporaryParent: snapshotParent });
    const sourceBytes = Buffer.from("bounded authenticated stdin fixture\n");
    fs.mkdirSync(path.join(logRoot.root, "nested"), { mode: 0o700 });
    fs.writeFileSync(
      path.join(logRoot.root, "nested", "runtime.log"),
      sourceBytes,
      { mode: 0o600 },
    );
    const proofSnapshot = {
      artifactPath: AUTHENTICATED_CANDIDATE_ARTIFACT,
      candidateReceiptFingerprint: candidate.receipt.fingerprint,
      sourceFingerprint: SOURCE.fingerprint,
      sourceSha: SOURCE.sha,
      vsixSha256: candidate.receipt.artifact.sha256,
      identity: {
        device: "1",
        inode: "2",
        size: String(candidate.receipt.artifact.archiveBytes),
        modifiedNanoseconds: "3",
        changedNanoseconds: "4",
      },
    };
    let scannerCalls = 0;
    try {
      await assert.rejects(runAuthenticatedExposureScan({
        root: ROOT,
        source: SOURCE,
        candidate,
        candidateReceiptFingerprint: candidate.receipt.fingerprint,
        runtimeLogRoot: logRoot.root,
        environment: { PATH: process.env.PATH || "" },
      }, {
        temporaryParent: snapshotParent,
        assertScannerVersion() {},
        scanGeneratedEvidence: () => ({
          id: "authenticated-generated-evidence",
          status: "scanned",
          fileCount: 2,
          findings: [],
        }),
        captureAuthenticatedCandidateProof: () => proofSnapshot,
        scanVsix: async (_root, relativePath) => ({
          id: `vsix:${relativePath}`,
          status: "scanned",
          fileCount: 3,
          findings: [],
        }),
        scanWithGitleaks(kind, target, options) {
          scannerCalls += 1;
          assert.strictEqual(kind, "stdin");
          assert.strictEqual(target, "nested/runtime.log");
          assert.strictEqual(options.logicalPath, target);
          assert.strictEqual(Object.hasOwn(options, "scanRoot"), false);
          const snapshotRoot = authenticatedRuntimeSnapshotRoot(snapshotParent);
          for (const value of Object.values(options)) {
            if (typeof value === "string") assert.notStrictEqual(value, snapshotRoot);
          }
          const snapshotFile = path.join(snapshotRoot, "nested", "runtime.log");
          const displaced = path.join(snapshotRoot, "nested", "runtime-original.log");
          fs.renameSync(snapshotFile, displaced);
          try {
            fs.writeFileSync(
              snapshotFile,
              "substituted path fixture\n",
            );
            assert.deepStrictEqual(options.input, sourceBytes);
          } finally {
            fs.unlinkSync(snapshotFile);
            fs.renameSync(displaced, snapshotFile);
          }
          return [];
        },
        writeReceipt() {},
      }), /runtime logs changed during snapshot or scanning/u);
      assert.strictEqual(scannerCalls, 1);
    } finally {
      sourceBytes.fill(0);
      if (fs.existsSync(logRoot.root)) destroyRuntimeLogRoot(logRoot);
      fs.rmSync(candidate.profile.root, { recursive: true, force: true });
    }
  });

  test("authenticated exposure scan rejects a pre-existing runtime-log hard link before scanning", async () => {
    const candidate = candidateFixture();
    const snapshotParent = temporaryRoot("cloudsmith-authenticated-hard-link-test-");
    const logRoot = createRuntimeLogRoot({ temporaryParent: snapshotParent });
    const logFile = path.join(logRoot.root, "runtime.log");
    const linkedLogFile = path.join(logRoot.root, "runtime-linked.log");
    fs.writeFileSync(logFile, "bounded synthetic hard-link fixture\n", { mode: 0o600 });
    fs.linkSync(logFile, linkedLogFile);
    assert.strictEqual(fs.statSync(logFile).nlink, 2);
    let scannerReached = false;
    let proofCaptureReached = false;
    let receiptPersistenceReached = false;

    try {
      await assert.rejects(runAuthenticatedExposureScan({
        root: ROOT,
        source: SOURCE,
        candidate,
        candidateReceiptFingerprint: candidate.receipt.fingerprint,
        runtimeLogRoot: logRoot.root,
        environment: { PATH: process.env.PATH || "" },
      }, {
        outputPath: ".quality/secrets/authenticated-hard-link-test.json",
        temporaryParent: snapshotParent,
        assertScannerVersion() {},
        scanGeneratedEvidence() {
          scannerReached = true;
          assert.fail("A hard-linked runtime log must fail before generated-evidence scanning.");
        },
        captureAuthenticatedCandidateProof() {
          proofCaptureReached = true;
          assert.fail("A hard-linked runtime log must fail before proof capture.");
        },
        scanVsix: async () => {
          scannerReached = true;
          assert.fail("A hard-linked runtime log must fail before VSIX scanning.");
        },
        scanWithGitleaks() {
          scannerReached = true;
          assert.fail("A hard-linked runtime log must fail before log scanning.");
        },
        writeReceipt() {
          receiptPersistenceReached = true;
          assert.fail("A hard-linked runtime log must never persist a receipt.");
        },
      }), /runtime log regular files must have exactly one hard link/iu);

      assert.strictEqual(scannerReached, false);
      assert.strictEqual(proofCaptureReached, false);
      assert.strictEqual(receiptPersistenceReached, false);
      assert.strictEqual(fs.existsSync(path.join(
        ROOT,
        ".quality",
        "secrets",
        "authenticated-hard-link-test.json",
      )), false);
      assert.deepStrictEqual(fs.readdirSync(snapshotParent), [path.basename(logRoot.root)]);
      assert.strictEqual(destroyRuntimeLogRoot(logRoot), true);
      assert.deepStrictEqual(fs.readdirSync(snapshotParent), []);
    } finally {
      if (fs.existsSync(logRoot.root)) destroyRuntimeLogRoot(logRoot);
      fs.rmSync(candidate.profile.root, { recursive: true, force: true });
    }
  });

  test("authenticated exposure scan rejects a FIFO replacement without reading it", async function () {
    if (process.platform === "win32") this.skip();
    const candidate = candidateFixture();
    const snapshotParent = temporaryRoot("cloudsmith-authenticated-fifo-test-");
    const logRoot = createRuntimeLogRoot({ temporaryParent: snapshotParent });
    const logFile = path.join(logRoot.root, "runtime.log");
    const displaced = path.join(logRoot.root, "runtime-original.log");
    fs.writeFileSync(logFile, Buffer.alloc(97, 0x66), { mode: 0o600 });
    const originalOpen = fs.openSync;
    const originalRead = fs.readSync;
    let fifoDescriptor;
    let replaced = false;
    let readAttempted = false;
    let scannerReached = false;
    try {
      fs.openSync = function replaceRuntimeLogWithFifo(target, flags, ...arguments_) {
        if (!replaced && target === logFile) {
          fs.renameSync(logFile, displaced);
          const fixture = spawnSync("mkfifo", [logFile], { stdio: "ignore" });
          if (fixture.status !== 0) {
            fs.renameSync(displaced, logFile);
            throw new Error("Synthetic FIFO fixture setup failed.");
          }
          replaced = true;
          assert.notStrictEqual(flags & fs.constants.O_NONBLOCK, 0);
        }
        const descriptor = originalOpen.call(fs, target, flags, ...arguments_);
        if (replaced && target === logFile) fifoDescriptor = descriptor;
        return descriptor;
      };
      fs.readSync = function rejectFifoRead(descriptor, ...arguments_) {
        if (descriptor === fifoDescriptor) {
          readAttempted = true;
          assert.fail("A substituted runtime-log FIFO must be rejected before reading.");
        }
        return originalRead.call(fs, descriptor, ...arguments_);
      };
      await assert.rejects(runAuthenticatedExposureScan({
        root: ROOT,
        source: SOURCE,
        candidate,
        candidateReceiptFingerprint: candidate.receipt.fingerprint,
        runtimeLogRoot: logRoot.root,
        environment: { PATH: process.env.PATH || "" },
      }, {
        temporaryParent: snapshotParent,
        assertScannerVersion() {},
        scanGeneratedEvidence() {
          scannerReached = true;
          assert.fail("A substituted runtime-log FIFO must fail before scanning.");
        },
        captureAuthenticatedCandidateProof() {
          scannerReached = true;
          assert.fail("A substituted runtime-log FIFO must fail before proof capture.");
        },
        scanVsix: async () => {
          scannerReached = true;
          assert.fail("A substituted runtime-log FIFO must fail before VSIX scanning.");
        },
        scanWithGitleaks() {
          scannerReached = true;
          assert.fail("A substituted runtime-log FIFO must fail before log scanning.");
        },
        writeReceipt() {
          assert.fail("A substituted runtime-log FIFO must never persist a receipt.");
        },
      }), error => {
        assert.strictEqual(
          error.message,
          "Authenticated runtime logs changed during snapshot or scanning.",
        );
        return true;
      });
    } finally {
      fs.readSync = originalRead;
      fs.openSync = originalOpen;
      if (replaced && fs.existsSync(logFile)) fs.unlinkSync(logFile);
      if (fs.existsSync(displaced)) fs.renameSync(displaced, logFile);
      if (fs.existsSync(logRoot.root)) destroyRuntimeLogRoot(logRoot);
      fs.rmSync(candidate.profile.root, { recursive: true, force: true });
    }
    assert.strictEqual(replaced, true);
    assert.strictEqual(readAttempted, false);
    assert.strictEqual(scannerReached, false);
  });

  test("authenticated runtime-log copy and comparison reject growth without over-reading", async () => {
    for (const growthPhase of ["copy", "comparison"]) {
      const candidate = candidateFixture();
      const snapshotParent = temporaryRoot(
        `cloudsmith-authenticated-growth-${growthPhase}-test-`,
      );
      const logRoot = createRuntimeLogRoot({ temporaryParent: snapshotParent });
      const logFile = path.join(logRoot.root, "runtime.log");
      const capturedBytes = 257;
      const originalBytes = Buffer.alloc(capturedBytes, 0x62);
      fs.writeFileSync(logFile, originalBytes, { mode: 0o600 });
      originalBytes.fill(0);
      const originalOpen = fs.openSync;
      const originalRead = fs.readSync;
      const targetOpen = growthPhase === "copy" ? 1 : 2;
      let exactOpenCount = 0;
      let watchedDescriptor;
      let grew = false;
      let requestedBytes = 0;
      let scannerReached = false;
      try {
        fs.openSync = function observeExactRuntimeLogOpen(target, flags, ...arguments_) {
          const descriptor = originalOpen.call(fs, target, flags, ...arguments_);
          if (target === logFile) {
            exactOpenCount += 1;
            assert.notStrictEqual(flags & fs.constants.O_NONBLOCK, 0);
            if (exactOpenCount === targetOpen) watchedDescriptor = descriptor;
          }
          return descriptor;
        };
        fs.readSync = function growWithinBoundedRead(
          descriptor,
          buffer,
          offset,
          length,
          position,
        ) {
          if (descriptor === watchedDescriptor) {
            requestedBytes += length;
            assert.ok(requestedBytes <= capturedBytes);
            if (!grew) {
              const growth = Buffer.alloc(193, 0x67);
              const growthDescriptor = originalOpen.call(
                fs,
                logFile,
                fs.constants.O_WRONLY | fs.constants.O_APPEND,
              );
              try {
                fs.writeSync(growthDescriptor, growth, 0, growth.length, null);
              } finally {
                growth.fill(0);
                fs.closeSync(growthDescriptor);
              }
              grew = true;
            }
          }
          return originalRead.call(fs, descriptor, buffer, offset, length, position);
        };
        await assert.rejects(runAuthenticatedExposureScan({
          root: ROOT,
          source: SOURCE,
          candidate,
          candidateReceiptFingerprint: candidate.receipt.fingerprint,
          runtimeLogRoot: logRoot.root,
          environment: { PATH: process.env.PATH || "" },
        }, {
          temporaryParent: snapshotParent,
          assertScannerVersion() {},
          scanGeneratedEvidence() {
            scannerReached = true;
            assert.fail("A growing runtime log must fail before scanning.");
          },
          captureAuthenticatedCandidateProof() {
            scannerReached = true;
            assert.fail("A growing runtime log must fail before proof capture.");
          },
          scanVsix: async () => {
            scannerReached = true;
            assert.fail("A growing runtime log must fail before VSIX scanning.");
          },
          scanWithGitleaks() {
            scannerReached = true;
            assert.fail("A growing runtime log must fail before log scanning.");
          },
          writeReceipt() {
            assert.fail("A growing runtime log must never persist a receipt.");
          },
        }), error => {
          assert.strictEqual(
            error.message,
            "Authenticated runtime logs changed during snapshot or scanning.",
          );
          return true;
        });
      } finally {
        fs.readSync = originalRead;
        fs.openSync = originalOpen;
        if (fs.existsSync(logRoot.root)) destroyRuntimeLogRoot(logRoot);
        fs.rmSync(candidate.profile.root, { recursive: true, force: true });
      }
      assert.strictEqual(grew, true);
      assert.strictEqual(requestedBytes, capturedBytes);
      assert.strictEqual(scannerReached, false);
    }
  });

  test("authenticated exposure scan rejects runtime-log add, change, delete, and same-byte replacement", async () => {
    const originalBytes = Buffer.from("bounded synthetic runtime-log fixture\n");
    for (const mutation of ["add", "change", "delete", "replace"]) {
      const candidate = candidateFixture();
      const snapshotParent = temporaryRoot(
        `cloudsmith-authenticated-runtime-${mutation}-test-`,
      );
      const logRoot = createRuntimeLogRoot({ temporaryParent: snapshotParent });
      const logFile = path.join(logRoot.root, "runtime.log");
      fs.writeFileSync(logFile, originalBytes, { mode: 0o600 });
      const proofSnapshot = {
        artifactPath: AUTHENTICATED_CANDIDATE_ARTIFACT,
        candidateReceiptFingerprint: candidate.receipt.fingerprint,
        sourceFingerprint: SOURCE.fingerprint,
        sourceSha: SOURCE.sha,
        vsixSha256: candidate.receipt.artifact.sha256,
        identity: {
          device: "1",
          inode: "2",
          size: String(candidate.receipt.artifact.archiveBytes),
          modifiedNanoseconds: "3",
          changedNanoseconds: "4",
        },
      };
      let scannedSnapshot;
      try {
        await assert.rejects(runAuthenticatedExposureScan({
          root: ROOT,
          source: SOURCE,
          candidate,
          candidateReceiptFingerprint: candidate.receipt.fingerprint,
          runtimeLogRoot: logRoot.root,
          environment: { PATH: process.env.PATH || "" },
        }, {
          temporaryParent: snapshotParent,
          assertScannerVersion() {},
          scanGeneratedEvidence: () => ({
            id: "authenticated-generated-evidence",
            status: "scanned",
            fileCount: 2,
            findings: [],
          }),
          captureAuthenticatedCandidateProof: () => proofSnapshot,
          scanVsix: async (_root, relativePath) => ({
            id: `vsix:${relativePath}`,
            status: "scanned",
            fileCount: 3,
            findings: [],
          }),
          scanWithGitleaks(kind, target, scanOptions) {
            scannedSnapshot = authenticatedRuntimeSnapshotRoot(snapshotParent);
            assert.strictEqual(kind, "stdin");
            assert.strictEqual(target, "runtime.log");
            assert.strictEqual(scanOptions.logicalPath, target);
            assert.strictEqual(Object.hasOwn(scanOptions, "scanRoot"), false);
            assert.deepStrictEqual(scanOptions.input, originalBytes);
            if (mutation === "add") {
              fs.writeFileSync(
                path.join(logRoot.root, "added.log"),
                "bounded added runtime-log fixture\n",
                { mode: 0o600 },
              );
            } else if (mutation === "change") {
              fs.writeFileSync(
                logFile,
                "bounded changed runtime-log fixture\n",
                { mode: 0o600 },
              );
            } else if (mutation === "delete") {
              fs.unlinkSync(logFile);
            } else {
              const replacement = path.join(logRoot.root, "replacement.log");
              fs.writeFileSync(replacement, originalBytes, { mode: 0o600 });
              fs.renameSync(replacement, logFile);
            }
            return [];
          },
          writeReceipt() {
            assert.fail("A drifted runtime-log scan must not persist a receipt.");
          },
        }), /runtime logs changed during snapshot or scanning/u);
        assert.ok(scannedSnapshot);
        assert.strictEqual(fs.existsSync(scannedSnapshot), false);
      } finally {
        if (fs.existsSync(logRoot.root)) destroyRuntimeLogRoot(logRoot);
        fs.rmSync(candidate.profile.root, { recursive: true, force: true });
      }
    }
  });

  test("authenticated exposure scan removes receipts when source or snapshot drifts during persistence", async () => {
    const originalBytes = Buffer.from("bounded synthetic persistence fixture\n");
    const mutations = [
      "add",
      "change",
      "delete",
      "different-byte-replacement",
      "same-byte-replacement",
    ];
    for (const targetKind of ["source", "snapshot"]) {
      for (const mutation of mutations) {
        const candidate = candidateFixture();
        const snapshotParent = temporaryRoot(
          `cloudsmith-authenticated-persistence-${targetKind}-${mutation}-test-`,
        );
        const logRoot = createRuntimeLogRoot({ temporaryParent: snapshotParent });
        const sourceLogFile = path.join(logRoot.root, "runtime.log");
        fs.writeFileSync(sourceLogFile, originalBytes, { mode: 0o600 });
        const outputPath = [
          ".quality/secrets/authenticated-runtime-persistence-",
          targetKind,
          "-",
          mutation,
          ".json",
        ].join("");
        const absoluteOutputPath = path.join(ROOT, ...outputPath.split("/"));
        const proofSnapshot = {
          artifactPath: AUTHENTICATED_CANDIDATE_ARTIFACT,
          candidateReceiptFingerprint: candidate.receipt.fingerprint,
          sourceFingerprint: SOURCE.fingerprint,
          sourceSha: SOURCE.sha,
          vsixSha256: candidate.receipt.artifact.sha256,
          identity: {
            device: "1",
            inode: "2",
            size: String(candidate.receipt.artifact.archiveBytes),
            modifiedNanoseconds: "3",
            changedNanoseconds: "4",
          },
        };
        let scannedSnapshot;
        let snapshotAliveDuringPersistence = false;
        try {
          await assert.rejects(runAuthenticatedExposureScan({
            root: ROOT,
            source: SOURCE,
            candidate,
            candidateReceiptFingerprint: candidate.receipt.fingerprint,
            runtimeLogRoot: logRoot.root,
            environment: { PATH: process.env.PATH || "" },
          }, {
            outputPath,
            temporaryParent: snapshotParent,
            assertScannerVersion() {},
            scanGeneratedEvidence: () => ({
              id: "authenticated-generated-evidence",
              status: "scanned",
              fileCount: 2,
              findings: [],
            }),
            captureAuthenticatedCandidateProof: () => proofSnapshot,
            scanVsix: async (_root, relativePath) => ({
              id: `vsix:${relativePath}`,
              status: "scanned",
              fileCount: 3,
              findings: [],
            }),
            scanWithGitleaks(kind, target, scanOptions) {
              scannedSnapshot = authenticatedRuntimeSnapshotRoot(snapshotParent);
              assert.strictEqual(kind, "stdin");
              assert.strictEqual(target, "runtime.log");
              assert.strictEqual(scanOptions.logicalPath, target);
              assert.strictEqual(Object.hasOwn(scanOptions, "scanRoot"), false);
              assert.ok(Buffer.isBuffer(scanOptions.input));
              return [];
            },
            async writeReceipt(value) {
              await new Promise(resolve => setImmediate(resolve));
              snapshotAliveDuringPersistence = fs.existsSync(scannedSnapshot);
              assert.strictEqual(snapshotAliveDuringPersistence, true);
              writeJson(outputPath, value, ROOT, { subtree: ".quality/secrets" });
              assert.strictEqual(fs.existsSync(absoluteOutputPath), true);
              const mutationRoot = targetKind === "source"
                ? logRoot.root
                : scannedSnapshot;
              const logFile = path.join(mutationRoot, "runtime.log");
              if (mutation === "add") {
                fs.writeFileSync(
                  path.join(mutationRoot, "added.log"),
                  "bounded synthetic added persistence fixture\n",
                  { mode: 0o600 },
                );
              } else if (mutation === "change") {
                fs.writeFileSync(
                  logFile,
                  "bounded synthetic changed persistence fixture\n",
                  { mode: 0o600 },
                );
              } else if (mutation === "delete") {
                fs.unlinkSync(logFile);
              } else {
                const replacement = path.join(mutationRoot, "replacement.log");
                fs.writeFileSync(
                  replacement,
                  mutation === "different-byte-replacement"
                    ? "bounded synthetic replacement persistence fixture\n"
                    : originalBytes,
                  { mode: 0o600 },
                );
                fs.renameSync(replacement, logFile);
              }
            },
          }), /runtime logs changed during snapshot or scanning/u);
          assert.strictEqual(snapshotAliveDuringPersistence, true);
          assert.ok(scannedSnapshot);
          assert.strictEqual(fs.existsSync(scannedSnapshot), false);
          assert.strictEqual(fs.existsSync(absoluteOutputPath), false);
          assert.deepStrictEqual(
            fs.readdirSync(snapshotParent),
            [path.basename(logRoot.root)],
          );
        } finally {
          fs.rmSync(absoluteOutputPath, { force: true });
          if (fs.existsSync(logRoot.root)) destroyRuntimeLogRoot(logRoot);
          fs.rmSync(candidate.profile.root, { recursive: true, force: true });
        }
      }
    }
  });

  test("authenticated exposure scan fails closed when proof identity changes during scanning", async () => {
    const candidate = candidateFixture();
    const logRoot = createRuntimeLogRoot({ temporaryParent: temporaryRoot() });
    let captures = 0;
    const captureAuthenticatedCandidateProof = () => ({
      artifactPath: AUTHENTICATED_CANDIDATE_ARTIFACT,
      candidateReceiptFingerprint: candidate.receipt.fingerprint,
      sourceFingerprint: SOURCE.fingerprint,
      sourceSha: SOURCE.sha,
      vsixSha256: candidate.receipt.artifact.sha256,
      identity: {
        device: "1",
        inode: String(++captures),
        size: String(candidate.receipt.artifact.archiveBytes),
        modifiedNanoseconds: "3",
        changedNanoseconds: "4",
      },
    });
    await assert.rejects(runAuthenticatedExposureScan({
      root: ROOT,
      source: SOURCE,
      candidate,
      candidateReceiptFingerprint: candidate.receipt.fingerprint,
      runtimeLogRoot: logRoot.root,
      environment: { PATH: process.env.PATH || "" },
    }, {
      assertScannerVersion() {},
      scanGeneratedEvidence: () => ({
        id: "authenticated-generated-evidence",
        status: "scanned",
        fileCount: 2,
        findings: [],
      }),
      captureAuthenticatedCandidateProof,
      scanVsix: async (_root, relativePath) => ({
        id: `vsix:${relativePath}`,
        status: "scanned",
        fileCount: 3,
        findings: [],
      }),
      writeReceipt() {},
    }), /proof identity or bytes changed during scanning/u);
    assert.strictEqual(destroyRuntimeLogRoot(logRoot), true);
    fs.rmSync(candidate.profile.root, { recursive: true, force: true });
  });

  test("authenticated exposure scan fails closed when proof bytes change during scanning", async () => {
    const candidate = candidateFixture();
    const logRoot = createRuntimeLogRoot({ temporaryParent: temporaryRoot() });
    let captures = 0;
    const captureAuthenticatedCandidateProof = () => ({
      artifactPath: AUTHENTICATED_CANDIDATE_ARTIFACT,
      candidateReceiptFingerprint: candidate.receipt.fingerprint,
      sourceFingerprint: SOURCE.fingerprint,
      sourceSha: SOURCE.sha,
      vsixSha256: captures++ === 0
        ? candidate.receipt.artifact.sha256
        : "e".repeat(64),
      identity: {
        device: "1",
        inode: "2",
        size: String(candidate.receipt.artifact.archiveBytes),
        modifiedNanoseconds: "3",
        changedNanoseconds: "4",
      },
    });
    await assert.rejects(runAuthenticatedExposureScan({
      root: ROOT,
      source: SOURCE,
      candidate,
      candidateReceiptFingerprint: candidate.receipt.fingerprint,
      runtimeLogRoot: logRoot.root,
      environment: { PATH: process.env.PATH || "" },
    }, {
      assertScannerVersion() {},
      scanGeneratedEvidence: () => ({
        id: "authenticated-generated-evidence",
        status: "scanned",
        fileCount: 2,
        findings: [],
      }),
      captureAuthenticatedCandidateProof,
      scanVsix: async (_root, relativePath) => ({
        id: `vsix:${relativePath}`,
        status: "scanned",
        fileCount: 3,
        findings: [],
      }),
      writeReceipt() {},
    }), /proof identity or bytes changed during scanning/u);
    assert.strictEqual(destroyRuntimeLogRoot(logRoot), true);
    fs.rmSync(candidate.profile.root, { recursive: true, force: true });
  });

  test("authenticated proof capture validates immutable bytes and detects same-byte replacement", () => {
    const fixtureRoot = temporaryRoot("cloudsmith-authenticated-proof-test-");
    const candidate = candidateFixture();
    const proofBytes = Buffer.from("synthetic-vsix-proof");
    const proofDirectory = path.join(fixtureRoot, ".quality", "qualification");
    const proofPath = path.join(proofDirectory, "authenticated-candidate.vsix");
    fs.mkdirSync(proofDirectory, { recursive: true });
    fs.writeFileSync(proofPath, proofBytes);
    fs.writeFileSync(path.join(fixtureRoot, "package.json"), JSON.stringify({
      publisher: "Cloudsmith",
      name: "cloudsmith-vsc",
      version: "2.3.0",
    }));
    for (const filename of [".node-version", ".npm-version", ".npm-integrity"]) {
      fs.copyFileSync(path.join(ROOT, filename), path.join(fixtureRoot, filename));
    }
    const receiptBase = { ...candidate.receipt };
    delete receiptBase.fingerprint;
    receiptBase.artifact = {
      ...receiptBase.artifact,
      absoluteVsixPath: path.join(
        fixtureRoot,
        ...receiptBase.artifact.vsixPath.split("/"),
      ),
      archiveBytes: proofBytes.length,
      sha256: crypto.createHash("sha256").update(proofBytes).digest("hex"),
    };
    const receipt = { ...receiptBase, fingerprint: fingerprint(receiptBase) };
    const before = captureAuthenticatedCandidateProof(fixtureRoot, receipt, SOURCE);
    assert.strictEqual(before.artifactPath, AUTHENTICATED_CANDIDATE_ARTIFACT);
    assert.strictEqual(before.candidateReceiptFingerprint, receipt.fingerprint);
    assert.strictEqual(before.vsixSha256, receipt.artifact.sha256);

    const replacement = path.join(proofDirectory, "replacement.vsix");
    fs.writeFileSync(replacement, proofBytes);
    fs.renameSync(replacement, proofPath);
    const afterReplacement = captureAuthenticatedCandidateProof(
      fixtureRoot,
      receipt,
      SOURCE,
    );
    assert.throws(
      () => assertStableAuthenticatedProof(before, afterReplacement),
      /proof identity or bytes changed during scanning/u,
    );

    fs.writeFileSync(proofPath, Buffer.from("changed-vsix-proof"));
    assert.throws(
      () => captureAuthenticatedCandidateProof(fixtureRoot, receipt, SOURCE),
      /VSIX proof is stale or mismatched/u,
    );
    fs.rmSync(candidate.profile.root, { recursive: true, force: true });
  });

  test("external exposure scan consumes a one-use pre-deletion profile metadata proof", async () => {
    const candidate = candidateFixture();
    const logRoot = createRuntimeLogRoot({ temporaryParent: temporaryRoot() });
    const profileBoundaryProof = assertProfileMetadataBoundary(candidate.profile);
    fs.rmSync(candidate.profile.root, { recursive: true, force: true });
    const context = {
      root: ROOT,
      source: SOURCE,
      candidate,
      candidateReceiptFingerprint: candidate.receipt.fingerprint,
      runtimeLogRoot: logRoot.root,
      profileBoundaryProof,
      environment: { PATH: process.env.PATH || "" },
    };
    const adapters = {
      assertScannerVersion() {},
      scanGeneratedEvidence: () => ({
        id: "authenticated-generated-evidence",
        status: "scanned",
        fileCount: 2,
        findings: [],
      }),
      captureAuthenticatedCandidateProof: () => ({
        artifactPath: AUTHENTICATED_CANDIDATE_ARTIFACT,
        candidateReceiptFingerprint: candidate.receipt.fingerprint,
        sourceFingerprint: SOURCE.fingerprint,
        sourceSha: SOURCE.sha,
        vsixSha256: candidate.receipt.artifact.sha256,
        identity: {
          device: "1",
          inode: "2",
          size: String(candidate.receipt.artifact.archiveBytes),
          modifiedNanoseconds: "3",
          changedNanoseconds: "4",
        },
      }),
      scanVsix: async (_root, relativePath) => ({
        id: `vsix:${relativePath}`,
        status: "scanned",
        fileCount: 3,
        findings: [],
      }),
      writeReceipt() {},
    };
    const result = await runAuthenticatedExposureScan(context, adapters);
    assert.strictEqual(result.status, "passed");
    await assert.rejects(
      runAuthenticatedExposureScan(context, adapters),
      /metadata proof is not owned/u,
    );
    assert.strictEqual(destroyRuntimeLogRoot(logRoot), true);
  });

  test("authenticated evidence verifier binds the passed production proof and value-blind scan", async () => {
    const harness = lifecycleHarness();
    const authenticated = await runAuthenticatedCi(harness.options);
    const candidate = harness.candidate.receipt;
    const exposureBase = {
      schemaVersion: 2,
      status: "passed",
      sourceSha: SOURCE.sha,
      candidateReceiptFingerprint: candidate.fingerprint,
      vsixSha256: candidate.artifact.sha256,
      scanner: {
        name: "gitleaks",
        version: "8.30.1",
        secretBearingFieldsPersisted: false,
      },
      credentialBoundary: {
        profileContentRead: false,
        secretStorageRead: false,
        keychainRead: false,
        credentialValueRecorded: false,
        credentialDigestRecorded: false,
      },
      findingCount: 0,
      components: [
        {
          id: "authenticated-generated-evidence",
          status: "scanned",
          fileCount: 2,
          findingCount: 0,
        },
        {
          id: `vsix:${AUTHENTICATED_CANDIDATE_ARTIFACT}`,
          status: "scanned",
          fileCount: 3,
          findingCount: 0,
        },
        {
          id: "authenticated-runtime-logs",
          status: "scanned",
          fileCount: 1,
          findingCount: 0,
        },
        {
          id: "profile-boundary-metadata-only",
          status: "scanned",
          fileCount: 4,
          findingCount: 0,
        },
      ],
    };
    const exposure = assertExposureReceipt({
      ...exposureBase,
      fingerprint: fingerprint(exposureBase),
    });
    const documents = {
      ".quality/qualification/authenticated-candidate.json": candidate,
      ".quality/qualification/authenticated-ci.json": authenticated,
      ".quality/secrets/authenticated-ci.json": exposure,
    };
    const result = verifyAuthenticatedEvidence({
      root: ROOT,
      sourceIdentity: () => SOURCE,
      expectedSourceSha: SOURCE.sha,
      readJson: relativePath => documents[relativePath],
      candidateBindingFromReceipt(receipt, options) {
        assert.strictEqual(
          options.artifactPath,
          path.join(ROOT, ".quality/qualification/authenticated-candidate.vsix"),
        );
        return candidateBindingFromReceipt(receipt, { root: ROOT, source: SOURCE });
      },
    });
    assert.deepStrictEqual(result, {
      status: "passed",
      sourceSha: SOURCE.sha,
      candidateReceiptFingerprint: candidate.fingerprint,
      workspace: DESIGNATED_WORKSPACE,
      developmentPath: false,
    });
    const crossedBase = JSON.parse(JSON.stringify(exposure));
    delete crossedBase.fingerprint;
    crossedBase.components[1].id = "vsix:.quality/qualification/unbound-candidate.vsix";
    documents[".quality/secrets/authenticated-ci.json"] = assertExposureReceipt({
      ...crossedBase,
      fingerprint: fingerprint(crossedBase),
    });
    assert.throws(() => verifyAuthenticatedEvidence({
      root: ROOT,
      sourceIdentity: () => SOURCE,
      expectedSourceSha: SOURCE.sha,
      readJson: relativePath => documents[relativePath],
      candidateBindingFromReceipt: (receipt) => candidateBindingFromReceipt(
        receipt,
        { root: ROOT, source: SOURCE },
      ),
    }), /exact value-blind components/u);

    const crossedDigestBase = JSON.parse(JSON.stringify(exposure));
    delete crossedDigestBase.fingerprint;
    crossedDigestBase.vsixSha256 = "e".repeat(64);
    documents[".quality/secrets/authenticated-ci.json"] = assertExposureReceipt({
      ...crossedDigestBase,
      fingerprint: fingerprint(crossedDigestBase),
    });
    assert.throws(() => verifyAuthenticatedEvidence({
      root: ROOT,
      sourceIdentity: () => SOURCE,
      expectedSourceSha: SOURCE.sha,
      readJson: relativePath => documents[relativePath],
      candidateBindingFromReceipt: receipt => candidateBindingFromReceipt(
        receipt,
        { root: ROOT, source: SOURCE },
      ),
    }), /exact value-blind components/u);
  });

  test("authenticated workflow isolates candidate preparation from the protected secret step", () => {
    const document = yaml.load(fs.readFileSync(
      path.join(ROOT, ".github", "workflows", "deep-quality.yml"),
      "utf8",
    ), { schema: yaml.CORE_SCHEMA });
    const job = document.jobs["authenticated-production-ui"];
    assert.strictEqual(job.environment, "cloudsmith-release-qualification");
    const prepare = job.steps.find(step => step.name
      === "Prepare and validate exact authenticated candidate without credentials");
    assert.ok(prepare);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(prepare, "env"), false);
    assert.strictEqual(
      prepare.run,
      "npm run quality:qualification:prepare-authenticated-ci",
    );
    const authenticated = job.steps.find(step => step.id === "authenticated_qualification");
    assert.deepStrictEqual(authenticated.env, {
      CLOUDSMITH_QUALIFICATION_API_KEY:
        "${{ secrets.CLOUDSMITH_QUALIFICATION_API_KEY }}",
    });
    assert.strictEqual(
      authenticated.run,
      "xvfb-run -a node scripts/quality/run-authenticated-ci.js",
    );
    assert.strictEqual(authenticated["timeout-minutes"], 15);
    assert.strictEqual(/\bnpm\b/u.test(authenticated.run), false);
    const cleanup = job.steps.find(step => step.id === "authenticated_profile_cleanup");
    assert.strictEqual(cleanup.if, "${{ always() }}");
    assert.strictEqual(cleanup.run, "node scripts/quality/authenticated-candidate-session.js cleanup");
  });

  test("credential-free candidate preparation rejects and deletes a secret environment input", async () => {
    const environment = { [SECRET_ENV]: SYNTHETIC_SENTINEL };
    let prepared = 0;
    await assert.rejects(
      prepareAuthenticatedCandidateSession({
        root: ROOT,
        environment,
        prepareQualificationCandidate: async () => {
          prepared += 1;
        },
      }),
      /Credential-bearing environments cannot prepare/u,
    );
    assert.strictEqual(prepared, 0);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(environment, SECRET_ENV), false);
  });

  test("candidate session persists only profile ownership metadata and product identity", () => {
    const temporaryParent = canonicalApprovedTemporaryBase();
    const candidate = candidateFixture({ temporaryParent });
    const session = sessionFromCandidate(candidate);
    assert.strictEqual(session.schemaVersion, 2);
    assert.strictEqual(session.status, "prepared");
    assert.strictEqual(session.processTreeExit, "pending");
    assert.strictEqual(session.candidateReceiptFingerprint, candidate.receipt.fingerprint);
    assert.strictEqual(session.profile.root, candidate.profile.root);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(session.profile, "cleanupProof"), false);
    assert.strictEqual(JSON.stringify(session).includes(SYNTHETIC_SENTINEL), false);
    fs.rmSync(candidate.profile.root, { recursive: true, force: true });
  });

  test("workflow cleanup retains an unproven profile and session receipt", async () => {
    const repositoryRoot = temporaryRoot("cloudsmith-authenticated-cleanup-repository-");
    const runnerTemp = temporaryRoot("cloudsmith-authenticated-cleanup-runner-");
    const environment = { RUNNER_TEMP: runnerTemp };
    const candidate = candidateFixture({ temporaryParent: runnerTemp });
    const session = sessionFromCandidate(candidate, { environment });
    writeJson(AUTHENTICATED_SESSION, session, repositoryRoot, {
      subtree: ".quality/qualification",
    });
    markPreparedAuthenticatedCandidateProcessExit(
      "unproven",
      repositoryRoot,
      { environment },
    );
    const descriptor = path.join(repositoryRoot, AUTHENTICATED_SESSION);

    await assert.rejects(
      runAuthenticatedCandidateSessionCommand(
        ["cleanup"],
        { root: repositoryRoot, environment },
      ),
      /independently proven process-tree exit/u,
    );
    assert.strictEqual(fs.existsSync(candidate.profile.root), true);
    assert.strictEqual(fs.existsSync(descriptor), true);

    markPreparedAuthenticatedCandidateProcessExit(
      "proven",
      repositoryRoot,
      { environment },
    );
    assert.strictEqual(
      cleanupPreparedAuthenticatedCandidate(repositoryRoot, { environment }),
      true,
    );
    assert.strictEqual(fs.existsSync(candidate.profile.root), false);
    assert.strictEqual(fs.existsSync(descriptor), false);
  });

  test("authenticated candidate cleanup fails closed on final profile substitution", () => {
    const repositoryRoot = temporaryRoot("cloudsmith-authenticated-cleanup-swap-repository-");
    const runnerTemp = temporaryRoot("cloudsmith-authenticated-cleanup-swap-runner-");
    const environment = { RUNNER_TEMP: runnerTemp };
    const candidate = candidateFixture({ temporaryParent: runnerTemp });
    const session = sessionFromCandidate(candidate, { environment });
    writeJson(AUTHENTICATED_SESSION, session, repositoryRoot, {
      subtree: ".quality/qualification",
    });
    markPreparedAuthenticatedCandidateProcessExit(
      "proven",
      repositoryRoot,
      { environment },
    );
    const descriptor = path.join(repositoryRoot, AUTHENTICATED_SESSION);
    const victim = path.join(runnerTemp, "synthetic-profile-victim");
    fs.mkdirSync(victim, { mode: 0o700 });
    fs.writeFileSync(path.join(victim, "preserve.txt"), "synthetic victim survives\n");
    const displaced = path.join(runnerTemp, "owned-profile-displaced");
    const originalRename = fs.renameSync;
    const originalRmdir = fs.rmdirSync;
    let substituted = false;
    try {
      fs.rmdirSync = function interceptFinalAuthenticatedProfileRemoval(target, options) {
        if (!substituted && target === candidate.profile.root) {
          originalRename.call(fs, target, displaced);
          originalRename.call(fs, victim, target);
          substituted = true;
        }
        return originalRmdir.call(fs, target, options);
      };
      withExpectedCleanupTaint(() => {
        assert.throws(
          () => cleanupPreparedAuthenticatedCandidate(repositoryRoot, { environment }),
          /unsafe or changed tree/u,
        );
      });
    } finally {
      fs.rmdirSync = originalRmdir;
    }
    assert.strictEqual(substituted, true);
    assert.strictEqual(fs.existsSync(displaced), true);
    assert.strictEqual(fs.existsSync(descriptor), true);
    assert.strictEqual(
      fs.readFileSync(path.join(candidate.profile.root, "preserve.txt"), "utf8"),
      "synthetic victim survives\n",
    );
  });

  test("candidate session rejects a self-fingerprinted arbitrary cleanup parent", () => {
    const arbitraryParent = temporaryRoot("cloudsmith-arbitrary-profile-parent-");
    const candidate = candidateFixture({ temporaryParent: arbitraryParent });
    assert.throws(
      () => sessionFromCandidate(candidate),
      /approved temporary base/u,
    );
  });

  test("candidate session binds an explicit canonical runner temporary base", () => {
    const runnerTemp = temporaryRoot("cloudsmith-runner-temp-");
    const candidate = candidateFixture({ temporaryParent: runnerTemp });
    const session = sessionFromCandidate(candidate, {
      environment: { RUNNER_TEMP: runnerTemp },
    });
    assert.strictEqual(session.ownership.parent, runnerTemp);
    assert.strictEqual(path.dirname(session.profile.root), runnerTemp);
    fs.rmSync(candidate.profile.root, { recursive: true, force: true });
  });

  test("host boundary rejects child output without propagating its value", async () => {
    const candidate = candidateFixture();
    let childEnvironment;
    await assert.rejects(
      invokeBootstrapHost(candidate, { operation: "cleanup" }, {
        environment: { [SECRET_ENV]: SYNTHETIC_SENTINEL, PATH: process.env.PATH || "" },
        spawn(_command, _arguments, options) {
          childEnvironment = options.env;
          const { EventEmitter } = require("events");
          const { PassThrough } = require("stream");
          const child = new EventEmitter();
          child.pid = 43211;
          child.exitCode = null;
          child.signalCode = null;
          child.stdout = new PassThrough();
          child.stderr = new PassThrough();
          setImmediate(() => {
            child.stdout.end(SYNTHETIC_SENTINEL);
            child.stderr.emit("data", {
              toString() {
                assert.fail("Output chunks must never be coerced into readable values.");
              },
            });
            child.stderr.end();
            child.exitCode = 0;
            child.emit("exit", 0, null);
          });
          return child;
        },
        terminateProcessTree: async () => true,
      }),
      error => error.message === "output-boundary-failed",
    );
    assert.strictEqual(Object.prototype.hasOwnProperty.call(childEnvironment, SECRET_ENV), false);
    assert.strictEqual(JSON.stringify(childEnvironment).includes(SYNTHETIC_SENTINEL), false);
    fs.rmSync(candidate.profile.root, { recursive: true, force: true });
  });

  test("bootstrap timeout terminates its full owned tree before returning", async () => {
    const candidate = candidateFixture();
    const { EventEmitter } = require("events");
    const { PassThrough } = require("stream");
    const child = new EventEmitter();
    child.pid = 43212;
    child.exitCode = null;
    child.signalCode = null;
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    let terminated = 0;
    await assert.rejects(
      invokeBootstrapHost(candidate, { operation: "seed" }, {
        environment: { PATH: process.env.PATH || "" },
        spawn: () => child,
        timeout: 1,
        terminateProcessTree: async () => {
          terminated += 1;
          return true;
        },
      }),
      error => error.message === "credential-seed-failed",
    );
    assert.strictEqual(terminated, 1);
    fs.rmSync(candidate.profile.root, { recursive: true, force: true });
  });

  test("bootstrap cleanup exceptions remain process-tree failures", async () => {
    const candidate = candidateFixture();
    const { EventEmitter } = require("events");
    const { PassThrough } = require("stream");
    const child = new EventEmitter();
    child.pid = 43214;
    child.exitCode = 0;
    child.signalCode = null;
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    await assert.rejects(
      invokeBootstrapHost(candidate, { operation: "cleanup" }, {
        environment: { PATH: process.env.PATH || "" },
        spawn: () => child,
        terminateProcessTree: async () => {
          throw new Error("synthetic tree adapter failure");
        },
      }),
      error => error.message === "process-tree-cleanup-failed",
    );
    fs.rmSync(candidate.profile.root, { recursive: true, force: true });
  });

  test("bootstrap host owns the actual sandboxed VS Code argv", async () => {
    const candidate = candidateFixture();
    const request = {
      schemaVersion: 1,
      repositoryRoot: ROOT,
      profileRoot: candidate.profile.root,
      userDataDir: candidate.profile.userDataDir,
      extensionsDir: candidate.profile.extensionsDir,
      vscodeExecutable: candidate.profile.executable,
      commandRequest: { operation: "cleanup" },
    };
    const { EventEmitter } = require("events");
    const child = new EventEmitter();
    child.pid = 43215;
    child.exitCode = null;
    child.signalCode = null;
    let launch;
    assert.strictEqual(await runBootstrapHost({
      request,
      electron: {
        async runTests() {
          assert.fail("Bootstrap must not delegate final argv to @vscode/test-electron.");
        },
      },
      spawn(command, arguments_, options) {
        launch = { command, arguments_, options };
        setImmediate(() => {
          child.exitCode = 0;
          child.emit("exit", 0, null);
        });
        return child;
      },
    }), true);
    assert.strictEqual(launch.command, candidate.profile.executable);
    assert.deepStrictEqual(launch.arguments_.slice(0, 3), [
      ROOT,
      `--user-data-dir=${candidate.profile.userDataDir}`,
      `--extensions-dir=${candidate.profile.extensionsDir}`,
    ]);
    assert.strictEqual(
      launch.arguments_.includes(
        `--extensionDevelopmentPath=${path.join(ROOT, "test", "auth-bootstrap")}`,
      ),
      true,
    );
    assert.strictEqual(
      launch.arguments_.includes(
        `--extensionTestsPath=${path.join(ROOT, "test", "auth-bootstrap", "runner.js")}`,
      ),
      true,
    );
    assert.strictEqual(launch.arguments_.includes("--no-sandbox"), false);
    assert.strictEqual(launch.arguments_.includes("--disable-gpu-sandbox"), false);
    assert.strictEqual(launch.options.stdio, "ignore");
    assert.strictEqual(launch.options.detached, false);
    assert.deepStrictEqual(JSON.parse(launch.options.env[REQUEST_ENV]), { operation: "cleanup" });
    assert.strictEqual(Object.prototype.hasOwnProperty.call(
      launch.options.env,
      HOST_REQUEST_ENV,
    ), false);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(
      launch.options.env,
      SECRET_ENV,
    ), false);
    fs.rmSync(candidate.profile.root, { recursive: true, force: true });
  });

  test("host and runner delete their scoped request variables before use", () => {
    const runnerEnvironment = { [REQUEST_ENV]: JSON.stringify({ operation: "cleanup" }) };
    assert.deepStrictEqual(parseRequest(runnerEnvironment), { operation: "cleanup" });
    assert.strictEqual(Object.prototype.hasOwnProperty.call(runnerEnvironment, REQUEST_ENV), false);

    const hostEnvironment = {
      [HOST_REQUEST_ENV]: "{}",
      [SECRET_ENV]: SYNTHETIC_SENTINEL,
    };
    assert.throws(() => parseHostRequest(hostEnvironment), /refuses a credential/u);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(hostEnvironment, SECRET_ENV), false);
  });

  test("runner refuses command execution unless the exact same-ID companion owns activation", async () => {
    let commands = 0;
    const vscode = {
      extensions: {
        getExtension(id) {
          assert.strictEqual(id, EXTENSION_ID);
          return {
            extensionPath: path.join(ROOT, "test", "auth-bootstrap"),
            packageJSON: { publisher: "Cloudsmith", name: "cloudsmith-vsc", version: "2.3.0" },
          };
        },
      },
      commands: {
        async executeCommand() {
          commands += 1;
          return { status: "deleted" };
        },
      },
    };
    await runWithVscode(vscode, { operation: "cleanup" });
    assert.strictEqual(commands, 1);
    vscode.extensions.getExtension = () => ({
      extensionPath: path.join(ROOT, "test"),
      packageJSON: { publisher: "Cloudsmith", name: "cloudsmith-vsc", version: "2.3.0" },
    });
    await assert.rejects(
      () => runWithVscode(vscode, { operation: "cleanup" }),
      /exact same-ID companion/u,
    );
    assert.strictEqual(commands, 1);
  });

  test("production VSIX inventory excludes every bootstrap source", () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
    assert.strictEqual(manifest.files.some(entry => entry === "test" || entry.startsWith("test/")), false);
    for (const source of [
      "test/auth-bootstrap/package.json",
      "test/auth-bootstrap/extension.js",
      "test/auth-bootstrap/handoff.js",
      "test/auth-bootstrap/runner.js",
      "scripts/quality/auth-bootstrap-host.js",
      "scripts/quality/authenticated-candidate-session.js",
      "scripts/quality/authenticated-exposure-scan.js",
      "scripts/quality/authenticated-product-verifier.js",
      "scripts/quality/process-tree.js",
      "scripts/quality/run-authenticated-ci.js",
      "scripts/quality/secret-scan.js",
    ]) {
      assert.strictEqual(isApprovedSourcePath(source), false, source);
    }
    assert.strictEqual(AUTHENTICATED_RESULT.startsWith(".quality/qualification/"), true);
  });
});

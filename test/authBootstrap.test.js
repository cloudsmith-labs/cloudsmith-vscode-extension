// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const yaml = require("js-yaml");
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
  createRuntimeLogRoot,
  destroyRuntimeLogRoot,
  runAuthenticatedExposureScan,
} = require("../scripts/quality/authenticated-exposure-scan");
const {
  verifyAuthenticatedEvidence,
} = require("../scripts/quality/verify-authenticated-evidence");
const {
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
const SYNTHETIC_SENTINEL = "SYNTHETIC_QUALIFICATION_SENTINEL";
const SOURCE = Object.freeze({ sha: "a".repeat(40), fingerprint: "b".repeat(64) });
const temporaryRoots = [];

function temporaryRoot(prefix = "cloudsmith-auth-bootstrap-test-") {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  if (process.platform !== "win32") fs.chmodSync(root, 0o700);
  temporaryRoots.push(root);
  return root;
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
    schemaVersion: 2,
    status: "passed",
    capturedAt: "2026-08-27T00:00:00.000Z",
    source: SOURCE,
    repository: {
      branch: "test/release-quality-harness",
      dirty: true,
      status: "dirty",
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

  test("authenticated exposure scan reads no profile content and persists counts only", async () => {
    const candidate = candidateFixture();
    const logRoot = createRuntimeLogRoot({ temporaryParent: temporaryRoot() });
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
        assertScannerVersion() {},
        scanGeneratedEvidence: () => ({
          id: "authenticated-generated-evidence",
          status: "scanned",
          fileCount: 2,
          findings: [],
        }),
        scanVsix: async () => ({
          id: `vsix:${candidate.receipt.artifact.vsixPath}`,
          status: "scanned",
          fileCount: 3,
          findings: [],
        }),
        writeReceipt(value) { persisted = value; },
      });
    } finally {
      fs.readFileSync = originalRead;
    }
    assert.strictEqual(result.status, "passed");
    assert.strictEqual(result.components.length, 4);
    assert.strictEqual(result.credentialBoundary.profileContentRead, false);
    assert.strictEqual(result.credentialBoundary.secretStorageRead, false);
    assert.strictEqual(result.credentialBoundary.keychainRead, false);
    assert.strictEqual(result.credentialBoundary.credentialValueRecorded, false);
    assert.strictEqual(result.credentialBoundary.credentialDigestRecorded, false);
    assert.strictEqual(persisted.fingerprint, result.fingerprint);
    assert.strictEqual(destroyRuntimeLogRoot(logRoot), true);
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
      scanVsix: async () => ({
        id: `vsix:${candidate.receipt.artifact.vsixPath}`,
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
      schemaVersion: 1,
      status: "passed",
      sourceSha: SOURCE.sha,
      candidateReceiptFingerprint: candidate.fingerprint,
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
          id: "vsix:out/development/cloudsmith-vsc-2.3.0.vsix",
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
    crossedBase.components[1].id = "vsix:out/development/unbound-candidate.vsix";
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
    const candidate = candidateFixture();
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

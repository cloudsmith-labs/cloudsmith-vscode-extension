// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { fingerprint } = require("../scripts/quality/evidence");
const {
  NON_AUTH_AMBIENT_CAPABILITY_NAMES,
} = require("../scripts/quality/non-auth-environment");
const {
  resetCiQualificationUserData,
} = require("../scripts/quality/qualification-profile");
const {
  DECLARED_TESTS,
  PROBE_TEST,
  SUITE_TESTS,
  VSCODE_VERSION,
  runUiSmoke,
  validateToolContract,
} = require("../scripts/quality/run-ui-smoke");
const {
  classifyFailure,
  clearExTesterDevelopmentPath,
} = require("../ui-test/evidence-reporter");

const SOURCE = Object.freeze({ sha: "a".repeat(40), fingerprint: "b".repeat(64) });
const TOOL_PACKAGE = Object.freeze({
  name: "vscode-extension-tester",
  version: "8.24.0",
  supportedVersions: Object.freeze({
    "vscode-min": "1.129.1",
    "vscode-max": "1.131.0",
  }),
});

function exactTestFileIdentity(file) {
  const stat = fs.statSync(file, { bigint: true });
  return {
    changedNanoseconds: String(stat.ctimeNs),
    device: String(stat.dev),
    inode: String(stat.ino),
    links: String(stat.nlink),
    mode: String(stat.mode),
    modifiedNanoseconds: String(stat.mtimeNs),
    size: String(stat.size),
  };
}

suite("signed-out black-box UI runner contract", function () {
  this.timeout(20_000);
  let repositories;

  setup(() => {
    repositories = [];
  });

  teardown(() => {
    for (const root of repositories) fs.rmSync(root, { recursive: true, force: true });
  });

  test("requires a fresh failing probe before exact declared-suite passed evidence", async () => {
    const harness = createHarness(repositories);
    const result = await harness.run();

    assert.strictEqual(result.schemaVersion, 2);
    assert.strictEqual(result.status, "passed");
    assert.strictEqual(result.vscodeVersion, VSCODE_VERSION);
    assert.deepStrictEqual(result.tests, [...DECLARED_TESTS]);
    assert.deepStrictEqual(
      result.results,
      DECLARED_TESTS.map(name => ({ name, status: "passed" }))
    );
    assert.deepStrictEqual(result.candidate, {
      candidateReceiptFingerprint: harness.candidate.receipt.fingerprint,
      extensionId: "Cloudsmith.cloudsmith-vsc",
      extensionVersion: "2.3.0",
      profileMode: "ci",
      sourceFingerprint: SOURCE.fingerprint,
      sourceSha: SOURCE.sha,
      vscodeVersion: VSCODE_VERSION,
      vsixSha256: harness.candidate.receipt.artifact.sha256,
    });
    assert.strictEqual(harness.cleanupCalls(), 1);
    assert.strictEqual(fs.existsSync(harness.profileRoot), false);
    assert.deepStrictEqual(
      harness.phases(),
      ["driver", "reset", "probe", "reset", "suite"],
    );
    const candidateEnvironment = harness.candidateEnvironment();
    const nonAuthBoundaryRoot = path.dirname(candidateEnvironment.HOME);
    assert.strictEqual(fs.existsSync(nonAuthBoundaryRoot), false);
    for (const name of [
      "HOME", "USERPROFILE", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
      "XDG_DATA_HOME", "XDG_STATE_HOME", "APPDATA", "LOCALAPPDATA",
      "TMPDIR", "TMP", "TEMP", "NPM_CONFIG_CACHE",
    ]) {
      assert.strictEqual(candidateEnvironment[name].startsWith(
        `${nonAuthBoundaryRoot}${path.sep}`
      ), true);
    }
    for (const name of [
      "NPM_CONFIG_USERCONFIG", "NPM_CONFIG_GLOBALCONFIG", "GIT_CONFIG_GLOBAL",
    ]) {
      assert.strictEqual(candidateEnvironment[name].startsWith(
        `${nonAuthBoundaryRoot}${path.sep}`
      ), true);
    }
    assert.strictEqual(candidateEnvironment.GIT_CONFIG_NOSYSTEM, "1");
    assert.strictEqual(candidateEnvironment.GIT_CONFIG_COUNT, "0");
    for (const environment of harness.childEnvironments()) {
      assert.strictEqual(environment.CLOUDSMITH_API_KEY, undefined);
      assert.strictEqual(environment.CLOUDSMITH_TOKEN, undefined);
      assert.strictEqual(environment.VSCODE_TEST_VERSION, undefined);
      assert.strictEqual(environment.HOME, path.join(harness.profileRoot, "home"));
      assert.strictEqual(environment.USERPROFILE, path.join(harness.profileRoot, "home"));
      assert.strictEqual(environment.EXTENSIONS_FOLDER, path.join(harness.profileRoot, "extensions"));
      assert.strictEqual(environment.TEST_RESOURCES, harness.profileRoot);
      for (const name of [
        "TMPDIR", "TMP", "TEMP", "NPM_CONFIG_CACHE", "NPM_CONFIG_USERCONFIG",
        "NPM_CONFIG_GLOBALCONFIG", "GIT_CONFIG_GLOBAL",
      ]) {
        assert.strictEqual(environment[name].startsWith(
          `${nonAuthBoundaryRoot}${path.sep}`
        ), true);
      }
      assert.strictEqual(environment.GIT_CONFIG_NOSYSTEM, "1");
      assert.strictEqual(environment.GIT_CONFIG_COUNT, "0");
      for (const name of NON_AUTH_AMBIENT_CAPABILITY_NAMES) {
        assert.strictEqual(Object.prototype.hasOwnProperty.call(environment, name), false);
      }
    }
    for (const name of NON_AUTH_AMBIENT_CAPABILITY_NAMES) {
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(harness.candidateEnvironment(), name),
        false,
      );
    }
    const persisted = JSON.parse(fs.readFileSync(
      path.join(harness.repositoryRoot, ".quality", "ui", "result.json"),
      "utf8"
    ));
    assert.deepStrictEqual(persisted, result);
    assert.doesNotMatch(JSON.stringify(persisted), /do-not-persist-this-value/u);
  });

  test("accepts the exact hash-bound canonical release artifact path", async () => {
    const harness = createHarness(repositories, { artifactKind: "release" });
    const result = await harness.run();
    assert.strictEqual(result.status, "passed");
    assert.strictEqual(
      result.candidate.vsixSha256,
      harness.candidate.receipt.artifact.sha256
    );
  });

  test("rejects a probe that unexpectedly passes and never starts the real suite", async () => {
    const harness = createHarness(repositories, { probeStatus: 0 });
    await assertSafeRejection(harness.run, "UI_PROBE_INVALID");
    assert.deepStrictEqual(harness.phases(), ["driver", "reset", "probe"]);
    assert.strictEqual(harness.cleanupCalls(), 1);
    assert.strictEqual(fs.existsSync(harness.resultPath), false);
    assert.strictEqual(fs.existsSync(harness.nonAuthBoundaryRoot()), false);
  });

  test("fails closed before probe launch when the preflight profile reset is rejected", async () => {
    const harness = createHarness(repositories, { resetFailureCall: 1 });
    await assertSafeRejection(harness.run, "UI_PROFILE_RESET_FAILED");
    assert.deepStrictEqual(harness.phases(), ["driver", "reset"]);
    assert.strictEqual(harness.cleanupCalls(), 1);
    assert.strictEqual(fs.existsSync(harness.resultPath), false);
    assert.strictEqual(fs.existsSync(harness.nonAuthBoundaryRoot()), false);
  });

  test("direct execution replaces ambient temp and tool configuration on every outcome", async () => {
    const harness = createHarness(repositories, { probeStatus: 0 });
    await assertSafeRejection(harness.run, "UI_PROBE_INVALID");

    const candidateEnvironment = harness.candidateEnvironment();
    const serialized = JSON.stringify({
      candidateEnvironment,
      childEnvironments: harness.childEnvironments(),
    });
    for (const sentinel of [
      "/operator/tmp",
      "/operator/npm-userconfig",
      "/operator/npm-globalconfig",
      "/operator/npm-cache",
      "/operator/git-global-config",
    ]) assert.strictEqual(serialized.includes(sentinel), false);
    assert.strictEqual(fs.existsSync(harness.nonAuthBoundaryRoot()), false);
  });

  test("real nested candidate preparation stays inside the authenticated private boundary", async () => {
    const harness = createRealNestedCandidateHarness(repositories);
    const result = await harness.run();

    assert.strictEqual(result.status, "passed");
    assert.deepStrictEqual(
      harness.phases(),
      ["driver", "reset", "probe", "reset", "suite"],
    );
    assert.strictEqual(harness.settingsReplacements(), 0);
    assert.ok(harness.boundaryRoot());
    assert.strictEqual(fs.existsSync(harness.boundaryRoot()), false);
    for (const target of harness.nestedTemporaryPaths()) {
      assert.strictEqual(
        target.startsWith(`${harness.boundaryTemporaryRoot()}${path.sep}`),
        true,
      );
      assert.strictEqual(fs.existsSync(target), false);
    }
    assert.deepStrictEqual(harness.toolConfigObservations(), {
      gitGlobalConfig: path.join(harness.boundaryRoot(), "git-global-config"),
      npmGlobalConfig: path.join(harness.boundaryRoot(), "npm-globalconfig"),
      npmUserConfig: path.join(harness.boundaryRoot(), "npm-userconfig"),
      observedEmptyEveryTime: true,
    });
    assert.strictEqual(
      harness.candidateEnvironments().every(environment => (
        environment.NPM_CONFIG_USERCONFIG
          === path.join(harness.boundaryRoot(), "npm-userconfig")
        && environment.NPM_CONFIG_GLOBALCONFIG
          === path.join(harness.boundaryRoot(), "npm-globalconfig")
        && environment.GIT_CONFIG_GLOBAL
          === path.join(harness.boundaryRoot(), "git-global-config")
        && environment.GIT_CONFIG_NOSYSTEM === "1"
        && environment.GIT_CONFIG_COUNT === "0"
      )),
      true,
    );
  });

  test("rejects forged probe semantics even when the process exits one", async () => {
    const harness = createHarness(repositories, { probeErrorKind: "unexpected-test-failure" });
    await assertSafeRejection(harness.run, "UI_PROBE_INVALID");
    assert.deepStrictEqual(harness.phases(), ["driver", "reset", "probe"]);
    assert.strictEqual(harness.cleanupCalls(), 1);
    assert.strictEqual(fs.existsSync(harness.resultPath), false);
  });

  test("rejects a candidate receipt whose bound VSIX hash was altered", async () => {
    const harness = createHarness(repositories);
    harness.candidate.receipt.artifact.sha256 = "0".repeat(64);
    await assertSafeRejection(harness.run, "UI_CANDIDATE_INVALID");
    assert.deepStrictEqual(harness.phases(), []);
    assert.strictEqual(harness.cleanupCalls(), 1);
    assert.strictEqual(fs.existsSync(harness.resultPath), false);
    assert.strictEqual(fs.existsSync(harness.nonAuthBoundaryRoot()), false);
  });

  test("rejects missing or extra suite execution evidence despite exit zero", async () => {
    for (const suiteRecords of [
      SUITE_TESTS.slice(0, 3),
      [...SUITE_TESTS, "undeclared false green"],
    ]) {
      const harness = createHarness(repositories, { suiteRecords });
      await assertSafeRejection(harness.run, "UI_SUITE_INVALID");
      assert.deepStrictEqual(
        harness.phases(),
        ["driver", "reset", "probe", "reset", "suite"],
      );
      assert.strictEqual(harness.cleanupCalls(), 1);
      assert.strictEqual(fs.existsSync(harness.resultPath), false);
    }
  });

  test("rejects source drift after exact UI evidence and removes stale passed output", async () => {
    const drifted = { sha: SOURCE.sha, fingerprint: "c".repeat(64) };
    const harness = createHarness(repositories, {
      sourceIdentities: [SOURCE, drifted],
      staleResult: { schemaVersion: 2, status: "passed", unsafe: true },
    });
    await assertSafeRejection(harness.run, "UI_SOURCE_DRIFT");
    assert.strictEqual(harness.cleanupCalls(), 1);
    assert.strictEqual(fs.existsSync(harness.resultPath), false);
  });

  test("refuses a passed receipt when the owned profile was not removed", async () => {
    const harness = createHarness(repositories, { cleanupNoop: true });
    await assertSafeRejection(harness.run, "UI_PROFILE_CLEANUP_FAILED");
    assert.strictEqual(harness.cleanupCalls(), 1);
    assert.strictEqual(fs.existsSync(harness.profileRoot), true);
    assert.strictEqual(fs.existsSync(harness.resultPath), false);
    assert.strictEqual(fs.existsSync(harness.nonAuthBoundaryRoot()), false);
  });

  test("rejects VS Code pins outside the installed ExTester compatibility range", () => {
    const harness = createHarness(repositories);
    assert.throws(
      () => validateToolContract(harness.repositoryRoot, {
        ...TOOL_PACKAGE,
        supportedVersions: { "vscode-min": "1.129.1", "vscode-max": "1.130.0" },
      }, "22.23.2"),
      error => error.code === "UI_TOOL_UNSUPPORTED"
    );
  });

  test("rejects UI candidate construction outside the canonical Node runtime", () => {
    const harness = createHarness(repositories);
    assert.throws(
      () => validateToolContract(harness.repositoryRoot, TOOL_PACKAGE, "22.23.1"),
      error => error.code === "UI_TOOL_UNSUPPORTED"
    );
  });

  test("runtime rejection preserves seeded UI evidence before creating a boundary", async () => {
    let boundaryCreations = 0;
    let runtimeValidations = 0;
    const harness = createHarness(repositories, {
      assertCanonicalNodeRuntime(root, version) {
        runtimeValidations += 1;
        assert.strictEqual(root, harness.repositoryRoot);
        assert.strictEqual(version, process.version);
        throw new Error("synthetic canonical runtime rejection");
      },
      createNonAuthQualityEnvironment() {
        boundaryCreations += 1;
        throw new Error("runtime validation must precede boundary creation");
      },
    });
    const seeded = new Map([
      [harness.resultPath, Buffer.from("seeded UI result evidence\n")],
      [
        path.join(harness.repositoryRoot, ".quality", "qualification", "ui-candidate.json"),
        Buffer.from("seeded UI candidate receipt\n"),
      ],
      [
        path.join(harness.repositoryRoot, ".quality", "qualification", "ui-candidate.vsix"),
        Buffer.from("seeded UI candidate archive\n"),
      ],
    ]);
    for (const [target, bytes] of seeded) {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, bytes);
    }

    await assertSafeRejection(harness.run, "UI_TOOL_UNSUPPORTED");

    assert.strictEqual(boundaryCreations, 0);
    assert.strictEqual(runtimeValidations, 1);
    assert.strictEqual(harness.cleanupCalls(), 0);
    assert.deepStrictEqual(harness.phases(), []);
    for (const [target, bytes] of seeded) {
      assert.deepStrictEqual(fs.readFileSync(target), bytes);
    }
  });

  test("npm provenance preflight rejection preserves seeded UI evidence", async () => {
    let preflights = 0;
    const harness = createHarness(repositories, {
      qualificationToolchainPreflight() {
        preflights += 1;
        throw new Error("synthetic npm provenance rejection");
      },
    });
    const seeded = Buffer.from("seeded UI result evidence\n");
    fs.mkdirSync(path.dirname(harness.resultPath), { recursive: true });
    fs.writeFileSync(harness.resultPath, seeded);

    await assertSafeRejection(harness.run, "UI_SMOKE_FAILED");

    assert.strictEqual(preflights, 1);
    assert.strictEqual(harness.cleanupCalls(), 0);
    assert.deepStrictEqual(harness.phases(), []);
    assert.deepStrictEqual(fs.readFileSync(harness.resultPath), seeded);
  });

  test("the UI reporter maps arbitrary raw errors to a fixed value-blind kind", () => {
    const kind = classifyFailure(
      { phase: "suite", nonce: "d".repeat(64) },
      { type: "test", title: "safe declared title" },
      new Error("do-not-persist-this-value")
    );
    assert.strictEqual(kind, "unexpected-test-failure");
    assert.doesNotMatch(JSON.stringify({ kind }), /do-not-persist-this-value/u);
  });

  test("the UI reporter clears only ExTester's inert development-path sentinel", () => {
    for (const sentinel of [undefined, "undefined"]) {
      const environment = { EXTENSION_DEV_PATH: sentinel, SAFE: "kept" };
      clearExTesterDevelopmentPath(environment);
      assert.deepStrictEqual(environment, { SAFE: "kept" });
    }
    assert.throws(
      () => clearExTesterDevelopmentPath({ EXTENSION_DEV_PATH: "/forged/development" }),
      /refuses extension development paths/u
    );
  });
});

function createHarness(repositories, options = {}) {
  const repositoryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
    os.tmpdir(),
    "ui-runner-repo-",
  )));
  fs.chmodSync(repositoryRoot, 0o700);
  repositories.push(repositoryRoot);
  writeRepositoryFixture(repositoryRoot);

  const profileRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ui-runner-profile-"));
  fs.chmodSync(profileRoot, 0o700);
  repositories.push(profileRoot);
  for (const name of ["home", "settings", "extensions"]) {
    fs.mkdirSync(path.join(profileRoot, name), { mode: 0o700 });
  }
  const executable = path.join(profileRoot, "Code");
  const cli = path.join(profileRoot, "code-cli");
  fs.writeFileSync(executable, "fixture executable\n", { mode: 0o700 });
  fs.writeFileSync(cli, "fixture cli\n", { mode: 0o700 });
  const profile = {
    mode: "ci",
    persistent: false,
    root: profileRoot,
    testResourcesDir: profileRoot,
    homeDir: path.join(profileRoot, "home"),
    userDataDir: path.join(profileRoot, "settings"),
    extensionsDir: path.join(profileRoot, "extensions"),
    executable,
    cli,
    vscodeVersion: VSCODE_VERSION,
    cleanupProof: "not-serialized",
  };
  const artifactKind = options.artifactKind || "development";
  const artifactRelative = `out/${artifactKind}/cloudsmith-vsc-2.3.0.vsix`;
  const artifactPath = path.join(repositoryRoot, ...artifactRelative.split("/"));
  fs.mkdirSync(path.dirname(artifactPath), { recursive: true, mode: 0o700 });
  const artifactBytes = Buffer.from("bound deterministic fixture VSIX bytes", "utf8");
  fs.writeFileSync(artifactPath, artifactBytes);
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
      npmInstallationSha256: "4".repeat(64),
      platform: process.platform,
    },
    extension: {
      id: "Cloudsmith.cloudsmith-vsc",
      publisher: "Cloudsmith",
      name: "cloudsmith-vsc",
      version: "2.3.0",
    },
    vscode: { version: VSCODE_VERSION, executable, cli },
    profile: {
      mode: "ci",
      persistent: false,
      root: profileRoot,
      testResourcesDir: profileRoot,
      userDataDir: path.join(profileRoot, "settings"),
      extensionsDir: path.join(profileRoot, "extensions"),
    },
    artifact: {
      vsixPath: artifactRelative,
      absoluteVsixPath: fs.realpathSync(artifactPath),
      sha256: crypto.createHash("sha256").update(artifactBytes).digest("hex"),
      archiveBytes: artifactBytes.length,
      entryCount: 12,
      sourceSha: SOURCE.sha,
      sourceFingerprint: SOURCE.fingerprint,
    },
    installation: { status: "passed", id: "Cloudsmith.cloudsmith-vsc", version: "2.3.0" },
    launch: { status: "not-requested", developmentPath: false },
  };
  const receipt = { ...receiptBase, fingerprint: fingerprint(receiptBase) };
  let cleanupCalls = 0;
  let resetCalls = 0;
  let candidateEnvironment = null;
  const candidate = {
    receipt,
    profile,
    cleanup() {
      cleanupCalls += 1;
      if (!options.cleanupNoop) fs.rmSync(profileRoot, { recursive: true, force: true });
      return !options.cleanupNoop;
    },
  };

  const phases = [];
  const childEnvironments = [];
  const sourceIdentities = options.sourceIdentities || [SOURCE, SOURCE];
  let sourceIndex = 0;
  let randomIndex = 0;
  const resultPath = path.join(repositoryRoot, ".quality", "ui", "result.json");
  if (options.staleResult) {
    fs.mkdirSync(path.dirname(resultPath), { recursive: true });
    fs.writeFileSync(resultPath, `${JSON.stringify(options.staleResult)}\n`);
  }

  const spawn = (_command, args, spawnOptions) => {
    childEnvironments.push({ ...spawnOptions.env });
    if (args.includes("get-chromedriver")) {
      phases.push("driver");
      const directory = path.join(profileRoot, "chromedriver-mac-arm64");
      fs.mkdirSync(directory, { mode: 0o700 });
      fs.writeFileSync(path.join(directory, "chromedriver"), "driver\n", { mode: 0o700 });
      return processResult(0);
    }
    const phase = spawnOptions.env.CLOUDSMITH_UI_EVIDENCE_PHASE;
    phases.push(phase);
    if (phase === "probe") {
      fs.writeFileSync(path.join(profile.userDataDir, "probe-state"), "must be reset\n");
      if (options.probeStatus !== 0) {
        writeEvidence(spawnOptions.env, [{
          name: PROBE_TEST,
          status: "failed",
          errorKind: options.probeErrorKind || "fresh-wrong-selector-rejected",
        }]);
      }
      return processResult(options.probeStatus === 0 ? 0 : 1);
    }
    const names = options.suiteRecords || SUITE_TESTS;
    assert.strictEqual(
      fs.existsSync(path.join(profile.userDataDir, "probe-state")),
      false,
      "the final suite must not inherit probe user data"
    );
    writeEvidence(spawnOptions.env, names.map(name => ({
      name,
      status: "passed",
      errorKind: null,
    })));
    return processResult(0);
  };

  return {
    repositoryRoot,
    profileRoot,
    resultPath,
    candidate,
    candidateEnvironment: () => ({ ...candidateEnvironment }),
    nonAuthBoundaryRoot: () => path.dirname(candidateEnvironment.HOME),
    cleanupCalls: () => cleanupCalls,
    phases: () => [...phases],
    childEnvironments: () => childEnvironments.map(value => ({ ...value })),
    run: () => runUiSmoke({
      root: repositoryRoot,
      platform: "darwin",
      architecture: "arm64",
      environment: {
        PATH: process.env.PATH || "/usr/bin",
        HOME: "/operator/profile",
        CLOUDSMITH_API_KEY: "do-not-persist-this-value",
        CLOUDSMITH_TOKEN: "do-not-persist-this-value",
        CLOUDSMITH_UI_EVIDENCE_NONCE: "ambient-forgery",
        VSCODE_TEST_VERSION: "9.9.9",
        TMPDIR: "/operator/tmp",
        TMP: "/operator/tmp",
        TEMP: "/operator/tmp",
        NPM_CONFIG_USERCONFIG: "/operator/npm-userconfig",
        NPM_CONFIG_GLOBALCONFIG: "/operator/npm-globalconfig",
        NPM_CONFIG_CACHE: "/operator/npm-cache",
        GIT_CONFIG_GLOBAL: "/operator/git-global-config",
        GIT_CONFIG_COUNT: "1",
        DISPLAY: ":synthetic-host-display",
        WAYLAND_DISPLAY: "synthetic-host-wayland",
        XAUTHORITY: "/synthetic/host-xauthority",
        XDG_RUNTIME_DIR: "/synthetic/host-runtime",
        DBUS_SESSION_BUS_ADDRESS: "unix:path=/synthetic/host-session-bus",
        SSH_AUTH_SOCK: "/synthetic/host-agent.sock",
        SSH_AGENT_PID: "12345",
        GPG_AGENT_INFO: "/synthetic/host-gpg-agent",
        KRB5CCNAME: "/synthetic/host-credential-cache",
        SECURITYSESSIONID: "synthetic-host-security-session",
      },
      toolPackage: TOOL_PACKAGE,
      assertCanonicalNodeRuntime: options.assertCanonicalNodeRuntime,
      qualificationToolchainPreflight: options.qualificationToolchainPreflight || (() => true),
      createNonAuthQualityEnvironment: options.createNonAuthQualityEnvironment,
      extestCli: path.join(repositoryRoot, "fixture-extest.js"),
      spawnSync: spawn,
      sourceIdentity: () => sourceIdentities[Math.min(sourceIndex++, sourceIdentities.length - 1)],
      randomBytes: size => Buffer.alloc(size, ++randomIndex),
      prepareQualificationCandidate: async context => {
        candidateEnvironment = context.environment;
        return candidate;
      },
      resetCiQualificationUserData: value => {
        phases.push("reset");
        resetCalls += 1;
        if (options.resetFailureCall === resetCalls) {
          throw new Error("synthetic exact reset rejection");
        }
        assert.strictEqual(value, profile);
        fs.rmSync(value.userDataDir, { recursive: true, force: true });
        fs.mkdirSync(value.userDataDir, { mode: 0o700 });
      },
      qualificationLaunchArguments: value => [
        "--user-data-dir", value.userDataDir,
        "--extensions-dir", value.extensionsDir,
        "--disable-updates",
        "--skip-welcome",
        "--skip-release-notes",
        "--new-window",
      ],
    }),
  };
}

function createRealNestedCandidateHarness(repositories) {
  const repositoryRoot = fs.realpathSync(fs.mkdtempSync(path.join(
    os.tmpdir(),
    "ui-runner-real-candidate-",
  )));
  if (process.platform !== "win32") fs.chmodSync(repositoryRoot, 0o700);
  repositories.push(repositoryRoot);
  writeRepositoryFixture(repositoryRoot);
  const temporaryParent = fs.realpathSync(fs.mkdtempSync(path.join(
    os.tmpdir(),
    "ui-runner-real-boundary-parent-",
  )));
  if (process.platform !== "win32") fs.chmodSync(temporaryParent, 0o700);
  repositories.push(temporaryParent);

  const artifactRelative = "out/development/cloudsmith-vsc-2.3.0.vsix";
  const artifactPath = path.join(repositoryRoot, ...artifactRelative.split("/"));
  const artifactBytes = Buffer.from("real nested deterministic fixture VSIX bytes", "utf8");
  const artifactSha = crypto.createHash("sha256").update(artifactBytes).digest("hex");
  let activeBoundaryRoot = null;
  let profileRoot = null;
  let packageScratch = null;
  let installScratch = null;
  let configPaths = null;
  let observedEmptyEveryTime = true;
  const candidateEnvironments = [];
  const phases = [];
  let settingsReplacements = 0;
  let randomIndex = 0;
  const npm = Object.freeze({
    cliPath: path.join(repositoryRoot, "fixture-npm-cli.js"),
    installation: Object.freeze({ sha256: "4".repeat(64) }),
    nodeExecutable: process.execPath,
    repositoryRoot,
    version: "10.9.8",
  });

  function observeCandidateEnvironment(environment) {
    assert.ok(environment && typeof environment === "object");
    candidateEnvironments.push({ ...environment });
    const currentConfigPaths = {
      npmUserConfig: environment.NPM_CONFIG_USERCONFIG,
      npmGlobalConfig: environment.NPM_CONFIG_GLOBALCONFIG,
      gitGlobalConfig: environment.GIT_CONFIG_GLOBAL,
    };
    const currentBoundaryRoot = path.dirname(currentConfigPaths.npmUserConfig);
    if (activeBoundaryRoot === null) activeBoundaryRoot = currentBoundaryRoot;
    assert.strictEqual(currentBoundaryRoot, activeBoundaryRoot);
    assert.strictEqual(path.dirname(currentConfigPaths.npmGlobalConfig), activeBoundaryRoot);
    assert.strictEqual(path.dirname(currentConfigPaths.gitGlobalConfig), activeBoundaryRoot);
    assert.strictEqual(environment.TMPDIR, path.join(activeBoundaryRoot, "tmp"));
    assert.strictEqual(environment.TMP, environment.TMPDIR);
    assert.strictEqual(environment.TEMP, environment.TMPDIR);
    assert.strictEqual(environment.NPM_CONFIG_CACHE, path.join(activeBoundaryRoot, "npm-cache"));
    assert.strictEqual(environment.GIT_CONFIG_NOSYSTEM, "1");
    assert.strictEqual(environment.GIT_CONFIG_COUNT, "0");
    if (configPaths === null) configPaths = currentConfigPaths;
    else assert.deepStrictEqual(currentConfigPaths, configPaths);
    for (const target of Object.values(currentConfigPaths)) {
      if (fs.readFileSync(target, "utf8") !== "") observedEmptyEveryTime = false;
    }
    for (const name of NON_AUTH_AMBIENT_CAPABILITY_NAMES) {
      assert.strictEqual(Object.prototype.hasOwnProperty.call(environment, name), false);
    }
  }

  const candidateSpawn = (command, arguments_, spawnOptions) => {
    observeCandidateEnvironment(spawnOptions.env);
    if (command === "git") {
      if (arguments_[0] === "branch") {
        return processResultWithOutput(0, "test/release-quality-harness\n");
      }
      if (arguments_[0] === "status") {
        return processResultWithOutput(0, " M bounded-fixture.js\n");
      }
      return processResultWithOutput(0, "");
    }
    if (command === process.execPath && arguments_[0] === npm.cliPath) {
      const npmArguments = arguments_.slice(1);
      if (JSON.stringify(npmArguments) === JSON.stringify(["run", "verify:polish"])) {
        return processResultWithOutput(0, "polish passed\n");
      }
      assert.deepStrictEqual(npmArguments.slice(0, 4), [
        "run", "package", "--", "--github-output",
      ]);
      const packageOutput = npmArguments[4];
      packageScratch = path.dirname(packageOutput);
      assert.strictEqual(packageScratch.startsWith(
        `${path.join(activeBoundaryRoot, "tmp")}${path.sep}`
      ), true);
      fs.mkdirSync(path.dirname(artifactPath), { recursive: true, mode: 0o700 });
      fs.writeFileSync(artifactPath, artifactBytes);
      fs.writeFileSync(`${artifactPath}.sha256`, "synthetic sidecar\n");
      fs.writeFileSync(`${artifactPath}.provenance.json`, JSON.stringify({
        sourceClean: false,
        sourceSha: SOURCE.sha,
      }));
      fs.appendFileSync(
        packageOutput,
        `vsix_path=${artifactRelative}\n`
          + `checksum_path=${artifactRelative}.sha256\n`
          + `provenance_path=${artifactRelative}.provenance.json\n`,
      );
      return processResultWithOutput(0, "packaged\n");
    }
    if (arguments_.includes("--version")) {
      return processResultWithOutput(0, `${VSCODE_VERSION}\nfixture\narm64\n`);
    }
    if (arguments_.includes("--list-extensions")) {
      return processResultWithOutput(0, "cloudsmith.cloudsmith-vsc@2.3.0\n");
    }
    const installIndex = arguments_.indexOf("--install-extension");
    assert.notStrictEqual(installIndex, -1);
    const installArtifact = arguments_[installIndex + 1];
    installScratch = path.dirname(installArtifact);
    assert.strictEqual(installScratch.startsWith(
      `${path.join(activeBoundaryRoot, "tmp")}${path.sep}`
    ), true);
    assert.deepStrictEqual(fs.readFileSync(installArtifact), artifactBytes);
    fs.mkdirSync(path.join(profileRoot, "settings", "User"), { recursive: true });
    return processResultWithOutput(0, "installed\n");
  };

  const uiSpawn = (_command, arguments_, spawnOptions) => {
    observeCandidateEnvironment(spawnOptions.env);
    if (arguments_.includes("get-chromedriver")) {
      phases.push("driver");
      const driver = path.join(profileRoot, "chromedriver-mac-arm64");
      fs.mkdirSync(driver, { mode: 0o700 });
      fs.writeFileSync(path.join(driver, "chromedriver"), "driver\n", { mode: 0o700 });
      return processResult(0);
    }
    const phase = spawnOptions.env.CLOUDSMITH_UI_EVIDENCE_PHASE;
    phases.push(phase);
    const settings = path.join(profileRoot, "settings");
    const userSettings = path.join(settings, "User");
    if (fs.existsSync(userSettings)) {
      fs.rmSync(settings, { recursive: true, force: true });
      fs.mkdirSync(settings, { mode: 0o755 });
      settingsReplacements += 1;
    }
    fs.mkdirSync(path.join(userSettings, "globalStorage"), { recursive: true });
    if (phase === "probe") {
      fs.writeFileSync(path.join(profileRoot, "settings", "probe-state"), "reset me\n");
      writeEvidence(spawnOptions.env, [{
        name: PROBE_TEST,
        status: "failed",
        errorKind: "fresh-wrong-selector-rejected",
      }]);
      return processResult(1);
    }
    assert.strictEqual(fs.existsSync(path.join(profileRoot, "settings", "probe-state")), false);
    writeEvidence(spawnOptions.env, SUITE_TESTS.map(name => ({
      name,
      status: "passed",
      errorKind: null,
    })));
    return processResult(0);
  };

  return {
    boundaryRoot: () => activeBoundaryRoot,
    boundaryTemporaryRoot: () => path.join(activeBoundaryRoot, "tmp"),
    candidateEnvironments: () => candidateEnvironments.map(value => ({ ...value })),
    nestedTemporaryPaths: () => [profileRoot, packageScratch, installScratch],
    phases: () => [...phases],
    settingsReplacements: () => settingsReplacements,
    toolConfigObservations: () => ({ ...configPaths, observedEmptyEveryTime }),
    run: () => runUiSmoke({
      root: repositoryRoot,
      platform: "darwin",
      architecture: "arm64",
      temporaryParent,
      environment: {
        PATH: process.env.PATH || "/usr/bin",
        HOME: "/operator/profile",
        CLOUDSMITH_API_KEY: "synthetic-real-nested-sentinel",
        TMPDIR: "/operator/tmp",
        NPM_CONFIG_USERCONFIG: "/operator/npm-userconfig",
        NPM_CONFIG_GLOBALCONFIG: "/operator/npm-globalconfig",
        NPM_CONFIG_CACHE: "/operator/npm-cache",
        GIT_CONFIG_GLOBAL: "/operator/git-global-config",
        GIT_CONFIG_COUNT: "1",
        DISPLAY: ":synthetic-host-display",
        XAUTHORITY: "/synthetic/host-xauthority",
        DBUS_SESSION_BUS_ADDRESS: "unix:path=/synthetic/host-session-bus",
      },
      toolPackage: TOOL_PACKAGE,
      extestCli: path.join(repositoryRoot, "fixture-extest.js"),
      spawnSync: uiSpawn,
      resetCiQualificationUserData: profile => {
        phases.push("reset");
        return resetCiQualificationUserData(profile);
      },
      sourceIdentity: () => SOURCE,
      randomBytes: size => Buffer.alloc(size, ++randomIndex),
      prepareCode: ({ profile, environment }) => {
        observeCandidateEnvironment(environment);
        profileRoot = profile.root;
        const executable = path.join(profile.root, "Code");
        const cli = path.join(profile.root, "bin", "code");
        fs.mkdirSync(path.dirname(cli), { recursive: true, mode: 0o700 });
        fs.writeFileSync(executable, "fixture executable\n", { mode: 0o700 });
        fs.writeFileSync(cli, "fixture cli\n", { mode: 0o700 });
        return { executable, cli };
      },
      candidateAdapters: {
        assertCanonicalNpmRuntime(root, _claimedCli, options) {
          assert.strictEqual(root, repositoryRoot);
          assert.strictEqual(options.nodeExecutable, process.execPath);
          assert.strictEqual(options.platform, process.platform);
          return npm;
        },
        assertNoNpmToolchainShadowing(root, options) {
          assert.strictEqual(root, repositoryRoot);
          assert.strictEqual(options.platform, process.platform);
          return true;
        },
        withCanonicalNpmLauncher(options, callback) {
          assert.strictEqual(options.nodeExecutable, process.execPath);
          assert.strictEqual(options.npm, npm);
          assert.strictEqual(options.platform, process.platform);
          return callback(Object.freeze({
            directory: path.join(repositoryRoot, "fixture-npm-launcher"),
            nodeCommand: process.platform === "win32" ? "node.cmd" : "node",
            npmCommand: process.platform === "win32" ? "npm.cmd" : "npm",
            npmCliPath: npm.cliPath,
            scriptShell: null,
          }));
        },
        spawnSync: candidateSpawn,
        sourceIdentity: (_root, _spawn, environment, sourceOptions) => {
          observeCandidateEnvironment(environment);
          assert.strictEqual(sourceOptions.temporaryParent, path.join(activeBoundaryRoot, "tmp"));
          return SOURCE;
        },
        now: () => new Date("2026-08-27T00:00:00.000Z"),
        verifyVsix: async file => {
          assert.strictEqual(file, artifactPath);
          return {
            artifactIdentity: exactTestFileIdentity(file),
            buffer: artifactBytes,
            sha256: artifactSha,
            archiveBytes: artifactBytes.length,
            entryCount: 12,
            totalUncompressedBytes: artifactBytes.length,
            manifest: { name: "cloudsmith-vsc", publisher: "Cloudsmith", version: "2.3.0" },
          };
        },
        validateSidecars: (file, verification, sidecarOptions) => {
          assert.strictEqual(file, artifactPath);
          assert.strictEqual(verification.sha256, artifactSha);
          assert.strictEqual(sidecarOptions.expectedSourceSha, SOURCE.sha);
          return {
            artifactIdentity: exactTestFileIdentity(file),
            checksumIdentity: exactTestFileIdentity(`${file}.sha256`),
            provenance: {},
            provenanceIdentity: exactTestFileIdentity(`${file}.provenance.json`),
          };
        },
      },
    }),
  };
}

function writeRepositoryFixture(root) {
  writeText(root, ".node-version", "22.23.2\n");
  writeJson(root, "package.json", {
    name: "cloudsmith-vsc",
    publisher: "Cloudsmith",
    version: "2.3.0",
  });
  writeJson(root, "package-lock.json", {
    name: "cloudsmith-vsc",
    version: "2.3.0",
    packages: { "": { name: "cloudsmith-vsc", version: "2.3.0" } },
  });
  writeText(
    root,
    "CHANGELOG.md",
    "## Unreleased\n\n## 2.3.0 - August 2026\n\n## 2.2.0 - August 2026\n",
  );
  writeJson(root, "extester.config.json", {
    $schema: "./node_modules/vscode-extension-tester/resources/extester.schema.json",
    setup: {
      vscodeVersion: VSCODE_VERSION,
      type: "stable",
      storage: "./ui-test/RUN_THROUGH_QUALITY_RUNNER",
      extensionsDir: "./ui-test/RUN_THROUGH_QUALITY_RUNNER",
      installDependencies: false,
      noCache: false,
      packageOptions: { useYarn: false, followSymlinks: false },
    },
    run: {
      testFiles: ["./ui-test/smoke.test.js"],
      vscodeVersion: VSCODE_VERSION,
      type: "stable",
      storage: "./ui-test/RUN_THROUGH_QUALITY_RUNNER",
      extensionsDir: "./ui-test/RUN_THROUGH_QUALITY_RUNNER",
      settings: "./ui-test/settings.json",
      cleanup: false,
      mochaConfig: "./ui-test/mocha.config.json",
      logLevel: "Info",
      offline: true,
      coverage: false,
      resources: [],
      locale: "",
    },
  });
  writeJson(root, "quality/critical-workflows.json", {
    workflows: [{ evidence: [{ layer: "black-box-ui", testNames: [...SUITE_TESTS] }] }],
  });
  writeText(root, "ui-test/smoke.test.js", SUITE_TESTS
    .map(name => `test(${JSON.stringify(name)}, () => {});`)
    .join("\n"));
  writeText(
    root,
    "ui-test/false-green-probe.test.js",
    `test(${JSON.stringify(PROBE_TEST)}, () => {});\n`
  );
  writeJson(root, "ui-test/settings.json", {
    "security.workspace.trust.enabled": false,
    "telemetry.telemetryLevel": "off",
    "update.mode": "none",
    "extensions.autoCheckUpdates": false,
    "extensions.autoUpdate": false,
    "extensions.ignoreRecommendations": true,
    "chat.disableAIFeatures": true,
    "chat.enabled": false,
    "workbench.enableExperiments": false,
    "workbench.startupEditor": "none",
  });
  writeJson(root, "ui-test/mocha.config.json", {
    ui: "tdd",
    timeout: 45000,
    failZero: true,
    forbidOnly: true,
    forbidPending: true,
    reporter: "./ui-test/evidence-reporter.js",
  });
  writeText(
    root,
    "ui-test/RUN_THROUGH_QUALITY_RUNNER",
    "This regular-file sentinel makes direct ExTester entry fail before launch.\n"
      + "Use `npm run test:ui:smoke` so the quality runner supplies fresh owned paths.\n"
  );
}

function writeEvidence(environment, records) {
  const totals = {
    passed: records.filter(item => item.status === "passed").length,
    failed: records.filter(item => item.status === "failed").length,
    pending: records.filter(item => item.status === "pending").length,
  };
  fs.writeFileSync(environment.CLOUDSMITH_UI_EVIDENCE_PATH, `${JSON.stringify({
    schemaVersion: 1,
    phase: environment.CLOUDSMITH_UI_EVIDENCE_PHASE,
    nonce: environment.CLOUDSMITH_UI_EVIDENCE_NONCE,
    source: {
      sha: environment.CLOUDSMITH_QUALITY_SOURCE_SHA,
      fingerprint: environment.CLOUDSMITH_QUALITY_SOURCE_FINGERPRINT,
    },
    totals,
    records,
  }, null, 2)}\n`);
}

function processResult(status) {
  return {
    status,
    signal: null,
    error: null,
    stdout: "",
    stderr: "do-not-persist-this-value",
  };
}

function processResultWithOutput(status, stdout) {
  return {
    ...processResult(status),
    stdout,
    stderr: "",
  };
}

async function assertSafeRejection(run, code) {
  await assert.rejects(run, error => {
    assert.strictEqual(error.code, code);
    assert.doesNotMatch(error.message, /do-not-persist-this-value/u);
    return true;
  });
}

function writeJson(root, relative, value) {
  writeText(root, relative, `${JSON.stringify(value, null, 2)}\n`);
}

function writeText(root, relative, value) {
  const target = path.join(root, ...relative.split("/"));
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  fs.writeFileSync(target, value);
}

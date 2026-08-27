// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { fingerprint } = require("../scripts/quality/evidence");
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
    assert.deepStrictEqual(harness.phases(), ["driver", "probe", "reset", "suite"]);
    for (const environment of harness.childEnvironments()) {
      assert.strictEqual(environment.CLOUDSMITH_API_KEY, undefined);
      assert.strictEqual(environment.CLOUDSMITH_TOKEN, undefined);
      assert.strictEqual(environment.VSCODE_TEST_VERSION, undefined);
      assert.strictEqual(environment.HOME, path.join(harness.profileRoot, "home"));
      assert.strictEqual(environment.USERPROFILE, path.join(harness.profileRoot, "home"));
      assert.strictEqual(environment.EXTENSIONS_FOLDER, path.join(harness.profileRoot, "extensions"));
      assert.strictEqual(environment.TEST_RESOURCES, harness.profileRoot);
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
    assert.deepStrictEqual(harness.phases(), ["driver", "probe"]);
    assert.strictEqual(harness.cleanupCalls(), 1);
    assert.strictEqual(fs.existsSync(harness.resultPath), false);
  });

  test("rejects forged probe semantics even when the process exits one", async () => {
    const harness = createHarness(repositories, { probeErrorKind: "unexpected-test-failure" });
    await assertSafeRejection(harness.run, "UI_PROBE_INVALID");
    assert.deepStrictEqual(harness.phases(), ["driver", "probe"]);
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
  });

  test("rejects missing or extra suite execution evidence despite exit zero", async () => {
    for (const suiteRecords of [
      SUITE_TESTS.slice(0, 3),
      [...SUITE_TESTS, "undeclared false green"],
    ]) {
      const harness = createHarness(repositories, { suiteRecords });
      await assertSafeRejection(harness.run, "UI_SUITE_INVALID");
      assert.deepStrictEqual(harness.phases(), ["driver", "probe", "reset", "suite"]);
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
  const repositoryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ui-runner-repo-"));
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
      },
      toolPackage: TOOL_PACKAGE,
      nodeVersion: "22.23.2",
      extestCli: path.join(repositoryRoot, "fixture-extest.js"),
      spawnSync: spawn,
      sourceIdentity: () => sourceIdentities[Math.min(sourceIndex++, sourceIdentities.length - 1)],
      randomBytes: size => Buffer.alloc(size, ++randomIndex),
      prepareQualificationCandidate: async () => candidate,
      resetCiQualificationUserData: value => {
        phases.push("reset");
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

function writeRepositoryFixture(root) {
  writeJson(root, "package.json", {
    name: "cloudsmith-vsc",
    publisher: "Cloudsmith",
    version: "2.3.0",
  });
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

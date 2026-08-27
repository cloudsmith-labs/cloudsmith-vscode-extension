// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { fingerprint } = require("../scripts/quality/evidence");
const {
  UI_CANDIDATE_ARTIFACT,
} = require("../scripts/quality/candidate-binding");
const {
  FORBIDDEN_REPORT_FIELDS,
  GITLEAKS_VERSION,
  REPORT_TEMPLATE,
  copyFileIntoSnapshot,
  parseArguments,
  parseSafeReport,
  resultDocument,
  scanWithGitleaks,
  scannerEnvironment,
  validateArchiveEntryPath,
} = require("../scripts/quality/secret-scan");
const {
  RELEASE_COMPONENT_IDS,
  buildReleaseExposureResult,
  executeReleaseExposureScan,
  validateReleaseExposureProof,
} = require("../scripts/quality/release-exposure-scan");

function createReleaseExposureFixture(root) {
  const source = Object.freeze({
    sha: "a".repeat(40),
    fingerprint: "b".repeat(64),
  });
  const candidateBytes = Buffer.from("synthetic-ui-candidate");
  fs.mkdirSync(path.join(root, ".quality", "qualification"), { recursive: true });
  fs.mkdirSync(path.join(root, ".quality", "ui"), { recursive: true });
  fs.mkdirSync(path.join(root, "quality"), { recursive: true });
  fs.mkdirSync(path.join(root, "internal_docs", "quality"), { recursive: true });
  fs.writeFileSync(path.join(root, "package.json"), `${JSON.stringify({
    publisher: "Cloudsmith",
    name: "cloudsmith-vsc",
    version: "2.3.0",
  })}\n`);
  fs.writeFileSync(path.join(root, "quality", "critical-workflows.json"), `${JSON.stringify({
    workflows: [{
      id: "WF-FIXTURE",
      evidence: [{ layer: "black-box-ui", testNames: ["fixture UI test"] }],
    }],
  })}\n`);
  const candidateArtifactPath = path.join(root, UI_CANDIDATE_ARTIFACT);
  fs.writeFileSync(candidateArtifactPath, candidateBytes);
  const outputPath = path.join(root, "out", "development", "cloudsmith-vsc-2.3.0.vsix");
  const receiptBase = {
    schemaVersion: 2,
    status: "passed",
    capturedAt: "2026-08-27T12:00:00.000Z",
    source,
    repository: { branch: "test/release-quality-harness", dirty: true, status: "dirty" },
    extension: {
      id: "Cloudsmith.cloudsmith-vsc",
      publisher: "Cloudsmith",
      name: "cloudsmith-vsc",
      version: "2.3.0",
    },
    vscode: {
      version: "1.131.0",
      executable: "/bounded/code",
      cli: "/bounded/cli",
    },
    profile: {
      mode: "ci",
      persistent: false,
      root: "/bounded/ui-profile",
      testResourcesDir: "/bounded/ui-profile",
      userDataDir: "/bounded/ui-profile/settings",
      extensionsDir: "/bounded/ui-profile/extensions",
    },
    artifact: {
      vsixPath: "out/development/cloudsmith-vsc-2.3.0.vsix",
      absoluteVsixPath: outputPath,
      sha256: crypto.createHash("sha256").update(candidateBytes).digest("hex"),
      archiveBytes: candidateBytes.length,
      entryCount: 1,
      sourceSha: source.sha,
      sourceFingerprint: source.fingerprint,
    },
    installation: {
      status: "passed",
      id: "Cloudsmith.cloudsmith-vsc",
      version: "2.3.0",
    },
    launch: { status: "not-requested", developmentPath: false },
  };
  const candidateReceipt = {
    ...receiptBase,
    fingerprint: fingerprint(receiptBase),
  };
  const ui = {
    schemaVersion: 2,
    status: "passed",
    source,
    sourceSha: source.sha,
    tool: "vscode-extension-tester",
    toolVersion: "8.24.0",
    vscodeVersion: "1.131.0",
    platform: "darwin",
    architecture: "arm64",
    launchAttempted: true,
    tests: ["fixture UI test"],
    results: [{ name: "fixture UI test", status: "passed" }],
    candidate: {
      candidateReceiptFingerprint: candidateReceipt.fingerprint,
      extensionId: "Cloudsmith.cloudsmith-vsc",
      extensionVersion: "2.3.0",
      profileMode: "ci",
      sourceFingerprint: source.fingerprint,
      sourceSha: source.sha,
      vscodeVersion: "1.131.0",
      vsixSha256: receiptBase.artifact.sha256,
    },
    reason: null,
  };
  const uiBytes = Buffer.from(JSON.stringify(ui));
  fs.writeFileSync(path.join(root, ".quality", "ui", "result.json"), uiBytes);
  const evidencePath = "internal_docs/quality/findings.jsonl";
  const evidenceBytes = Buffer.from("synthetic value-blind finding evidence\n");
  fs.writeFileSync(path.join(root, evidencePath), evidenceBytes);
  const attestationPath = "internal_docs/quality/live-qualification.json";
  const attestation = {
    evidence: [{
      path: evidencePath,
      sha256: crypto.createHash("sha256").update(evidenceBytes).digest("hex"),
    }],
    workflowResults: [],
  };
  const attestationBytes = Buffer.from(JSON.stringify(attestation));
  fs.writeFileSync(path.join(root, attestationPath), attestationBytes);
  const scanGeneratedEvidence = () => ({
    id: RELEASE_COMPONENT_IDS[0],
    status: "scanned",
    fileCount: 4,
    findings: [],
  });
  const scanAcceptedEvidence = (_root, paths) => ({
    id: RELEASE_COMPONENT_IDS[2],
    status: "scanned",
    fileCount: paths.length,
    findings: [],
    snapshot: Object.fromEntries(paths.map(relativePath => [
      relativePath,
      fs.readFileSync(path.join(root, relativePath)),
    ])),
  });
  return {
    attestation,
    attestationBytes,
    candidateArtifactPath,
    candidateBytes,
    candidateReceipt,
    evidencePath,
    scanAcceptedEvidence,
    scanGeneratedEvidence,
    source,
    ui,
    uiBytes,
  };
}

suite("secret exposure gate", () => {
  let scratch;

  setup(() => {
    scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-secret-gate-test-",
    )));
  });

  teardown(() => {
    fs.rmSync(scratch, { recursive: true, force: true });
  });

  test("defines explicit current, history, artifact, evidence, and all modes", () => {
    assert.deepStrictEqual(parseArguments([]), {
      mode: "current",
      includeLocalEvidence: false,
    });
    assert.deepStrictEqual(parseArguments(["all", "--include-local-evidence"]), {
      mode: "all",
      includeLocalEvidence: true,
    });
    assert.deepStrictEqual(parseArguments(["evidence"]), {
      mode: "evidence",
      includeLocalEvidence: false,
    });
    assert.throws(() => parseArguments(["history", "--include-local-evidence"]));
    assert.throws(() => parseArguments(["unknown"]));
  });

  test("passes only non-credential process environment names to the scanner", () => {
    const environment = scannerEnvironment({
      PATH: "/fixture/bin",
      LANG: "en_US.UTF-8",
      CLOUDSMITH_API_KEY: "non-secret-test-marker",
      ARBITRARY_TOKEN: "non-secret-test-marker",
    });
    assert.deepStrictEqual(environment, {
      PATH: "/fixture/bin",
      LANG: "en_US.UTF-8",
    });
  });

  test("safe report template cannot serialize secret-bearing finding fields", () => {
    const template = fs.readFileSync(path.resolve(__dirname, "..", REPORT_TEMPLATE), "utf8");
    assert.strictEqual(/\$finding\.(?:Secret|Match|Fingerprint|Entropy|Author|Email|Message)\b/u.test(template), false);
    assert.strictEqual(FORBIDDEN_REPORT_FIELDS.test(template), false);
    for (const field of ["RuleID", "File", "StartLine", "EndLine", "Commit"]) {
      assert.match(template, new RegExp(`\\$finding\\.${field}\\b`, "u"));
    }
  });

  test("rejects a scanner report before parsing if a forbidden field appears", () => {
    const reportPath = path.join(scratch, "unsafe.json");
    fs.writeFileSync(reportPath, '[{"Secret":null}]\n', { mode: 0o600 });
    assert.throws(
      () => parseSafeReport(reportPath, { scanRoot: scratch }),
      /forbidden secret-bearing report field/u,
    );
  });

  test("retains only bounded rule and location metadata from a finding", () => {
    const reportPath = path.join(scratch, "safe.json");
    fs.writeFileSync(reportPath, JSON.stringify([{
      ruleId: "fixture-rule",
      file: "quality/example.json",
      startLine: 4,
      endLine: 4,
      commit: "a".repeat(40),
    }]), { mode: 0o600 });
    assert.deepStrictEqual(parseSafeReport(reportPath, { scanRoot: scratch }), [{
      ruleId: "fixture-rule",
      path: "quality/example.json",
      startLine: 4,
      endLine: 4,
      commit: "a".repeat(40),
    }]);
  });

  test("does not propagate scanner stdout or stderr into finding evidence", () => {
    const target = path.join(scratch, "target");
    fs.mkdirSync(target);
    const execute = (_executable, args) => {
      const reportPath = args[args.indexOf("--report-path") + 1];
      fs.writeFileSync(reportPath, JSON.stringify([{
        ruleId: "fixture-rule",
        file: "fixture.txt",
        startLine: 1,
        endLine: 1,
        commit: "",
      }]), { mode: 0o600 });
      return {
        status: 1,
        signal: null,
        error: null,
        stdout: "scanner-output-must-not-propagate",
        stderr: "scanner-error-must-not-propagate",
      };
    };
    const findings = scanWithGitleaks("dir", target, {
      root: path.resolve(__dirname, ".."),
      scanRoot: target,
      execute,
    });
    assert.deepStrictEqual(findings, [{
      ruleId: "fixture-rule",
      path: "fixture.txt",
      startLine: 1,
      endLine: 1,
      commit: null,
    }]);
    assert.doesNotMatch(JSON.stringify(findings), /must-not-propagate/u);
  });

  test("runs the scanner with a separate private HOME and XDG boundary", () => {
    const target = path.join(scratch, "target-private-home");
    fs.mkdirSync(target);
    const forbiddenHome = path.join(scratch, "qualification-profile-home");
    fs.mkdirSync(forbiddenHome);
    let scannerHome;
    const findings = scanWithGitleaks("dir", target, {
      root: path.resolve(__dirname, ".."),
      scanRoot: target,
      environment: {
        PATH: process.env.PATH || "",
        HOME: forbiddenHome,
        XDG_CONFIG_HOME: path.join(forbiddenHome, ".config"),
      },
      execute(_executable, args, options) {
        scannerHome = options.env.HOME;
        assert.notStrictEqual(scannerHome, forbiddenHome);
        const homeStat = fs.lstatSync(scannerHome);
        assert.strictEqual(homeStat.isDirectory(), true);
        if (process.platform !== "win32") assert.strictEqual(homeStat.mode & 0o077, 0);
        for (const name of [
          "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
        ]) {
          assert.strictEqual(options.env[name].startsWith(`${scannerHome}${path.sep}`), true);
        }
        const reportPath = args[args.indexOf("--report-path") + 1];
        fs.writeFileSync(reportPath, "[]\n", { mode: 0o600 });
        return { status: 0, signal: null, error: null, stdout: "", stderr: "" };
      },
    });
    assert.deepStrictEqual(findings, []);
    assert.strictEqual(fs.existsSync(scannerHome), false);
  });

  test("fails closed when scanner exit status and safe report disagree", () => {
    const target = path.join(scratch, "target");
    fs.mkdirSync(target);
    const execute = (_executable, args) => {
      const reportPath = args[args.indexOf("--report-path") + 1];
      fs.writeFileSync(reportPath, "[]\n", { mode: 0o600 });
      return { status: 1, signal: null, error: null, stdout: "", stderr: "" };
    };
    assert.throws(
      () => scanWithGitleaks("dir", target, {
        root: path.resolve(__dirname, ".."),
        scanRoot: target,
        execute,
      }),
      /exit status disagrees/u,
    );
  });

  test("copies a tracked symbolic link as link metadata without following it", () => {
    const sourceRoot = path.join(scratch, "source");
    const snapshotRoot = path.join(scratch, "snapshot");
    fs.mkdirSync(sourceRoot);
    fs.mkdirSync(snapshotRoot);
    fs.writeFileSync(path.join(scratch, "outside.txt"), "outside-content\n");
    fs.symlinkSync("../outside.txt", path.join(sourceRoot, "linked.txt"));
    copyFileIntoSnapshot(path.join(sourceRoot, "linked.txt"), "linked.txt", snapshotRoot);
    const copied = path.join(snapshotRoot, "linked.txt");
    assert.strictEqual(fs.lstatSync(copied).isSymbolicLink(), false);
    assert.strictEqual(fs.readFileSync(copied, "utf8"), "../outside.txt");
  });

  test("rejects traversal and symbolic-link shaped VSIX entries", () => {
    assert.strictEqual(validateArchiveEntryPath("extension/package.json"), "extension/package.json");
    for (const candidate of ["../escape", "/absolute", "folder/../escape", "folder\\escape"]) {
      assert.throws(() => validateArchiveEntryPath(candidate));
    }
  });

  test("result receipts contain no secret-derived hash or scanner fingerprint", () => {
    const document = resultDocument("history", "b".repeat(40), [{
      id: "git-history-all-refs",
      status: "scanned",
      fileCount: null,
      findings: [{
        ruleId: "fixture-rule",
        path: "fixture.txt",
        startLine: 2,
        endLine: 2,
        commit: "a".repeat(40),
      }],
    }], new Date("2026-08-27T00:00:00.000Z"));
    assert.strictEqual(document.status, "failed");
    assert.strictEqual(document.findingCount, 1);
    assert.strictEqual(document.scanner.version, GITLEAKS_VERSION);
    assert.doesNotMatch(JSON.stringify(document), /(?:secretHash|fingerprint|match|entropy|author|email|message)/iu);
  });

  test("release exposure proof binds the exact post-UI candidate and accepted evidence", () => {
    const source = {
      sha: "a".repeat(40),
      fingerprint: "b".repeat(64),
    };
    const expected = {
      source,
      candidateReceiptFingerprint: "c".repeat(64),
      vsixSha256: "d".repeat(64),
      uiResultSha256: "e".repeat(64),
      attestationPath: "internal_docs/quality/live-qualification.json",
      attestationSha256: "f".repeat(64),
      evidenceManifest: [{
        path: "internal_docs/quality/findings.jsonl",
        sha256: "1".repeat(64),
      }],
    };
    const result = buildReleaseExposureResult({
      ...expected,
      components: [
        {
          id: RELEASE_COMPONENT_IDS[0],
          status: "scanned",
          fileCount: 8,
          findings: [],
        },
        {
          id: RELEASE_COMPONENT_IDS[1],
          status: "scanned",
          fileCount: 171,
          findings: [],
        },
        { id: "accepted-live-evidence", status: "scanned", fileCount: 2, findings: [] },
      ],
      now: new Date("2026-08-27T12:00:00.000Z"),
    });
    assert.strictEqual(validateReleaseExposureProof(result, expected), true);
    assert.strictEqual(result.status, "passed");
    assert.strictEqual(result.findingCount, 0);
    assert.strictEqual(result.scanner.secretBearingFieldsPersisted, false);

    for (const mutation of [
      { candidateReceiptFingerprint: "2".repeat(64) },
      { vsixSha256: "3".repeat(64) },
      { uiResultSha256: "4".repeat(64) },
      { attestationSha256: "5".repeat(64) },
      { evidenceManifest: [] },
    ]) {
      assert.throws(
        () => validateReleaseExposureProof(result, { ...expected, ...mutation }),
        /release exposure proof/iu,
      );
    }
  });

  test("release exposure proof rejects omitted evidence and self-consistent crossed receipts", () => {
    const source = {
      sha: "a".repeat(40),
      fingerprint: "b".repeat(64),
    };
    const expected = {
      source,
      candidateReceiptFingerprint: "c".repeat(64),
      vsixSha256: "d".repeat(64),
      uiResultSha256: "e".repeat(64),
      attestationPath: "internal_docs/quality/live-qualification.json",
      attestationSha256: "f".repeat(64),
      evidenceManifest: [
        { path: "internal_docs/quality/findings.jsonl", sha256: "1".repeat(64) },
        { path: "internal_docs/quality/workflow.md", sha256: "2".repeat(64) },
      ],
    };
    const crossed = buildReleaseExposureResult({
      ...expected,
      candidateReceiptFingerprint: "9".repeat(64),
      evidenceManifest: expected.evidenceManifest.slice(0, 1),
      components: [
        {
          id: RELEASE_COMPONENT_IDS[0],
          status: "scanned",
          fileCount: 8,
          findings: [],
        },
        {
          id: RELEASE_COMPONENT_IDS[1],
          status: "scanned",
          fileCount: 171,
          findings: [],
        },
        { id: "accepted-live-evidence", status: "scanned", fileCount: 2, findings: [] },
      ],
      now: new Date("2026-08-27T12:00:00.000Z"),
    });
    assert.throws(
      () => validateReleaseExposureProof(crossed, expected),
      /release exposure proof/iu,
    );
  });

  test("release exposure scan binds the scanned post-UI bytes and exact evidence snapshot", async () => {
    const fixture = createReleaseExposureFixture(scratch);
    const result = await executeReleaseExposureScan({
      root: scratch,
      source: fixture.source,
      candidateReceipt: fixture.candidateReceipt,
      candidateArtifactPath: fixture.candidateArtifactPath,
      ui: fixture.ui,
      attestation: fixture.attestation,
      attestationBytes: fixture.attestationBytes,
      assertScannerVersion() {},
      scanGeneratedEvidence: fixture.scanGeneratedEvidence,
      scanVsix: async (_root, relativePath) => ({
        id: `vsix:${relativePath}`,
        status: "scanned",
        fileCount: 2,
        findings: [],
      }),
      scanAcceptedEvidence: fixture.scanAcceptedEvidence,
      now: new Date("2026-08-27T12:05:00.000Z"),
    });
    assert.strictEqual(validateReleaseExposureProof(result, {
      source: fixture.source,
      candidateReceiptFingerprint: fixture.candidateReceipt.fingerprint,
      vsixSha256: fixture.candidateReceipt.artifact.sha256,
      uiResultSha256: crypto.createHash("sha256").update(fixture.uiBytes).digest("hex"),
      attestationPath: "internal_docs/quality/live-qualification.json",
      attestationSha256: crypto.createHash("sha256")
        .update(fixture.attestationBytes)
        .digest("hex"),
      evidenceManifest: fixture.attestation.evidence,
    }), true);
  });

  test("release exposure scan rejects same-byte candidate replacement during inspection", async () => {
    const fixture = createReleaseExposureFixture(scratch);
    await assert.rejects(() => executeReleaseExposureScan({
      root: scratch,
      source: fixture.source,
      candidateReceipt: fixture.candidateReceipt,
      candidateArtifactPath: fixture.candidateArtifactPath,
      ui: fixture.ui,
      attestation: fixture.attestation,
      attestationBytes: fixture.attestationBytes,
      assertScannerVersion() {},
      scanGeneratedEvidence: fixture.scanGeneratedEvidence,
      scanVsix: async (_root, relativePath) => {
        const replacement = path.join(scratch, ".quality", "qualification", "replacement.vsix");
        fs.writeFileSync(replacement, fixture.candidateBytes);
        fs.renameSync(replacement, fixture.candidateArtifactPath);
        return {
          id: `vsix:${relativePath}`,
          status: "scanned",
          fileCount: 2,
          findings: [],
        };
      },
      scanAcceptedEvidence: fixture.scanAcceptedEvidence,
    }), /candidate changed during release exposure scanning/u);
  });

  test("release exposure scan rejects accepted evidence changed after snapshot", async () => {
    const fixture = createReleaseExposureFixture(scratch);
    await assert.rejects(() => executeReleaseExposureScan({
      root: scratch,
      source: fixture.source,
      candidateReceipt: fixture.candidateReceipt,
      candidateArtifactPath: fixture.candidateArtifactPath,
      ui: fixture.ui,
      attestation: fixture.attestation,
      attestationBytes: fixture.attestationBytes,
      assertScannerVersion() {},
      scanGeneratedEvidence: fixture.scanGeneratedEvidence,
      scanVsix: async (_root, relativePath) => ({
        id: `vsix:${relativePath}`,
        status: "scanned",
        fileCount: 2,
        findings: [],
      }),
      scanAcceptedEvidence(root, paths) {
        const component = fixture.scanAcceptedEvidence(root, paths);
        fs.writeFileSync(
          path.join(scratch, fixture.evidencePath),
          "changed after evidence snapshot\n",
        );
        return component;
      },
    }), /evidence changed or does not match/u);
  });
});

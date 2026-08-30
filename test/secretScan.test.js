// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const { spawnSync } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const yazl = require("yazl");
const { writeJson } = require("../scripts/quality/common");
const { aggregateStatuses, fingerprint } = require("../scripts/quality/evidence");
const {
  artifactFingerprintForStep,
  gatePlanFingerprint,
  getGatePlan,
  receiptPath,
} = require("../scripts/quality/gate");
const TEST_INVENTORIES = require("./testInventories");
const {
  LIVE_CANDIDATE_ARTIFACT,
  UI_CANDIDATE_ARTIFACT,
  UI_CANDIDATE_RECEIPT,
  candidateBindingFromReceipt,
  digestStableSingleLinkFile,
  exactFileIdentity,
} = require("../scripts/quality/candidate-binding");
const {
  FORBIDDEN_REPORT_FIELDS,
  GITLEAKS_VERSION,
  MAX_TRACKED_FILE_BYTES,
  SCANNER_PROCESS_TIMEOUT_MS,
  REPORT_TEMPLATE,
  SIGNED_OUT_BUNDLE_DIRECTORY,
  SIGNED_OUT_BUNDLE_NAMES,
  SIGNED_OUT_UI_SCAN_EXCLUSIONS,
  UI_CANDIDATE_SCAN_EXCLUSIONS,
  executeScan,
  isReviewedSyntheticHistoryFinding,
  isReviewedSyntheticTrackedFinding,
  parseArguments,
  parseSafeReport,
  resultDocument,
  removePrivateSnapshotRoot,
  runScannerProcess,
  scanGeneratedEvidence,
  scanTracked,
  scanVsix,
  scanWithGitleaks,
  scannerEnvironment,
  validateArchiveEntryPath,
} = require("../scripts/quality/secret-scan");
const {
  verifyDetachedSignedOutUiBundle,
} = require("../scripts/quality/verify-ui-evidence");
const {
  GENERATED_EVIDENCE_BOUNDARY,
  GENERATED_EVIDENCE_CIRCULAR_OUTPUTS,
  GENERATED_EVIDENCE_EXCLUDED_FILES,
  GENERATED_EVIDENCE_EXCLUDED_PREFIXES,
  GENERATED_EVIDENCE_ROOT,
  LIVE_ATTESTATION,
  RELEASE_COMPONENT_IDS,
  RELEASE_GATE_CIRCULAR_PATHS,
  RELEASE_GATE_EXPECTED_PATHS,
  assertExactReleaseGateTree,
  buildReleaseExposureResult,
  captureGeneratedEvidenceManifest,
  executeReleaseExposureScan,
  generatedEvidenceInventory,
  readBoundedJson,
  validateGeneratedEvidenceAcceptance,
  validateReleaseExposureProof,
} = require("../scripts/quality/release-exposure-scan");

const ROOT = path.resolve(__dirname, "..");
const NODE_VERSION_BYTES = fs.readFileSync(path.join(ROOT, ".node-version"));
const NPM_VERSION_BYTES = fs.readFileSync(path.join(ROOT, ".npm-version"));
const NPM_INTEGRITY_BYTES = fs.readFileSync(path.join(ROOT, ".npm-integrity"));
const NODE_VERSION = NODE_VERSION_BYTES.toString("utf8").trim();
const NPM_VERSION = NPM_VERSION_BYTES.toString("utf8").trim();
const NPM_INTEGRITY = JSON.parse(NPM_INTEGRITY_BYTES.toString("utf8"));

function writeToolchainPins(root) {
  fs.writeFileSync(path.join(root, ".node-version"), NODE_VERSION_BYTES);
  fs.writeFileSync(path.join(root, ".npm-version"), NPM_VERSION_BYTES);
  fs.writeFileSync(path.join(root, ".npm-integrity"), NPM_INTEGRITY_BYTES);
}

function fixtureToolchain() {
  return {
    nodeVersion: `v${NODE_VERSION}`,
    npmVersion: NPM_VERSION,
    npmInstallationSha256: NPM_INTEGRITY[
      process.platform === "win32" ? "win32" : "posix"
    ],
    platform: process.platform,
  };
}

function syntheticGeneratedEvidence(count = 1) {
  return {
    boundary: {
      id: GENERATED_EVIDENCE_BOUNDARY,
      root: GENERATED_EVIDENCE_ROOT,
      excludedFiles: [...GENERATED_EVIDENCE_EXCLUDED_FILES],
      excludedPrefixes: [...GENERATED_EVIDENCE_EXCLUDED_PREFIXES],
    },
    files: Array.from({ length: count }, (_value, index) => ({
      path: `.quality/qualification/proof-${String(index).padStart(3, "0")}.json`,
      sha256: String((index % 9) + 1).repeat(64),
      identity: {
        changedNanoseconds: String(index + 1),
        device: "1",
        inode: String(index + 1),
        links: "1",
        mode: "33152",
        modifiedNanoseconds: String(index + 1),
        size: "1",
      },
    })),
  };
}

function syntheticGeneratedScanResult(options) {
  const inventory = options.expectedInventory || [];
  return {
    id: options.id,
    status: inventory.length === 0 ? "not-present" : "scanned",
    fileCount: inventory.length,
    findings: [],
    snapshotManifest: inventory.map(entry => ({
      path: entry.path,
      identity: entry.identity,
      sha256: "c".repeat(64),
    })),
  };
}

function writeZip(file, entries) {
  return new Promise((resolve, reject) => {
    const archive = new yazl.ZipFile();
    for (const [name, bytes] of entries) archive.addBuffer(Buffer.from(bytes), name);
    const output = fs.createWriteStream(file, { flags: "wx", mode: 0o600 });
    output.on("error", reject);
    output.on("close", resolve);
    archive.outputStream.on("error", reject);
    archive.outputStream.pipe(output);
    archive.end();
  });
}

async function createUiCandidateScanFixture(root) {
  const source = Object.freeze({
    sha: "a".repeat(40),
    fingerprint: "b".repeat(64),
  });
  fs.mkdirSync(path.join(root, ".quality", "qualification"), { recursive: true });
  fs.mkdirSync(path.join(root, ".quality", "ui"), { recursive: true });
  writeToolchainPins(root);
  fs.writeFileSync(path.join(root, "package.json"), `${JSON.stringify({
    publisher: "Cloudsmith",
    name: "cloudsmith-vsc",
    version: "2.3.0",
  })}\n`);
  fs.writeFileSync(
    path.join(root, ".quality", "ui", "result.json"),
    "{\"status\":\"synthetic-safe\"}\n",
  );
  const artifactPath = path.join(root, UI_CANDIDATE_ARTIFACT);
  await writeZip(artifactPath, [[
    "extension/safe.txt",
    "bounded synthetic candidate fixture\n",
  ]]);
  const artifactBytes = fs.readFileSync(artifactPath);
  const artifactSha256 = crypto.createHash("sha256").update(artifactBytes).digest("hex");
  const receiptBase = {
    schemaVersion: 3,
    status: "passed",
    capturedAt: "2026-08-27T12:00:00.000Z",
    source,
    repository: { branch: "test/release-quality-harness", dirty: true, status: "dirty" },
    toolchain: fixtureToolchain(),
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
      absoluteVsixPath: path.join(
        root,
        "out",
        "development",
        "cloudsmith-vsc-2.3.0.vsix",
      ),
      sha256: artifactSha256,
      archiveBytes: artifactBytes.length,
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
  const receipt = { ...receiptBase, fingerprint: fingerprint(receiptBase) };
  const receiptBytes = Buffer.from(`${JSON.stringify(receipt, null, 2)}\n`);
  const receiptPath = path.join(root, UI_CANDIDATE_RECEIPT);
  fs.writeFileSync(receiptPath, receiptBytes, { mode: 0o600 });
  return {
    source,
    receipt,
    receiptPath,
    receiptBytes,
    artifactPath,
    artifactBytes,
    artifactSha256,
  };
}

async function createSignedOutBundleFixture(root) {
  const fixture = await createUiCandidateScanFixture(root);
  const testName = "signed-out fixture proves packaged UI";
  fs.mkdirSync(path.join(root, "quality"), { recursive: true });
  fs.writeFileSync(path.join(root, "quality", "critical-workflows.json"), `${JSON.stringify({
    workflows: [{
      id: "WF-SIGNED-OUT-FIXTURE",
      evidence: [{ layer: "black-box-ui", testNames: [testName] }],
    }],
  }, null, 2)}\n`);
  const ui = {
    schemaVersion: 2,
    status: "passed",
    source: fixture.source,
    sourceSha: fixture.source.sha,
    tool: "vscode-extension-tester",
    toolVersion: "8.24.0",
    vscodeVersion: fixture.receipt.vscode.version,
    platform: "linux",
    architecture: "x64",
    launchAttempted: true,
    tests: [testName],
    results: [{ name: testName, status: "passed" }],
    candidate: {
      candidateReceiptFingerprint: fixture.receipt.fingerprint,
      extensionId: fixture.receipt.extension.id,
      extensionVersion: fixture.receipt.extension.version,
      profileMode: fixture.receipt.profile.mode,
      sourceFingerprint: fixture.source.fingerprint,
      sourceSha: fixture.source.sha,
      vscodeVersion: fixture.receipt.vscode.version,
      vsixSha256: fixture.artifactSha256,
    },
    reason: null,
  };
  const uiBytes = Buffer.from(`${JSON.stringify(ui, null, 2)}\n`);
  const uiPath = path.join(root, ".quality", "ui", "result.json");
  fs.writeFileSync(uiPath, uiBytes, { mode: 0o600 });
  return { ...fixture, testName, ui, uiBytes, uiPath };
}

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
  writeToolchainPins(root);
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
  const candidateIdentity = exactFileIdentity(fs.lstatSync(candidateArtifactPath, {
    bigint: true,
  }));
  const outputPath = path.join(root, "out", "development", "cloudsmith-vsc-2.3.0.vsix");
  const receiptBase = {
    schemaVersion: 3,
    status: "passed",
    capturedAt: "2026-08-27T12:00:00.000Z",
    source,
    repository: { branch: "test/release-quality-harness", dirty: true, status: "dirty" },
    toolchain: fixtureToolchain(),
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
  const generatedEvidencePath = ".quality/qualification/generated-proof.json";
  const generatedEvidenceBytes = Buffer.from("stable generated proof\n");
  fs.writeFileSync(path.join(root, generatedEvidencePath), generatedEvidenceBytes);
  const evidencePath = "internal_docs/quality/findings.jsonl";
  const evidenceBytes = Buffer.from("synthetic value-blind finding evidence\n");
  fs.writeFileSync(path.join(root, evidencePath), evidenceBytes);
  const attestationPath = LIVE_ATTESTATION;
  const attestation = {
    evidence: [{
      path: evidencePath,
      sha256: crypto.createHash("sha256").update(evidenceBytes).digest("hex"),
    }],
    workflowResults: [],
  };
  const attestationBytes = Buffer.from(JSON.stringify(attestation));
  fs.writeFileSync(path.join(root, attestationPath), attestationBytes);
  const scanGeneratedEvidence = scanRoot => {
    const manifest = captureGeneratedEvidenceManifest(scanRoot);
    return {
      id: RELEASE_COMPONENT_IDS[0],
      status: "scanned",
      fileCount: manifest.files.length,
      findings: [],
      snapshotManifest: manifest.files,
    };
  };
  const scanCandidate = async (_root, relativePath) => ({
    id: `vsix:${relativePath}`,
    status: "scanned",
    fileCount: 2,
    findings: [],
    snapshot: {
      path: relativePath,
      identity: candidateIdentity,
      sha256: receiptBase.artifact.sha256,
    },
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
    candidateIdentity,
    candidateReceipt,
    evidencePath,
    generatedEvidenceBytes,
    generatedEvidencePath,
    scanAcceptedEvidence,
    scanCandidate,
    scanGeneratedEvidence,
    source,
    ui,
    uiBytes,
  };
}

function writeReleaseProgressAtSecretScan(root, source) {
  const plan = getGatePlan("release");
  const inventoryByStep = {
    "standalone-tests": [
      ...TEST_INVENTORIES.STANDALONE_NODE_TESTS,
      ...TEST_INVENTORIES.HOST_NODE_TESTS,
    ],
    "extension-host-core": TEST_INVENTORIES.VSCODE_CORE_TESTS,
    "extension-host-smoke": TEST_INVENTORIES.VSCODE_SMOKE_TESTS,
  };
  let reachedExposureScan = false;
  for (const step of plan) {
    if (step.id === "secret-release") reachedExposureScan = true;
    let receipt = {
      profile: "release",
      schemaVersion: 1,
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
    if (!reachedExposureScan) {
      let testEvidence = null;
      let testEvidenceFingerprint = null;
      if (step.evidencePath) {
        const tests = inventoryByStep[step.id].map(file => ({
          file,
          title: `synthetic ${file}`,
          fullTitle: `synthetic suite ${file}`,
          status: "passed",
        }));
        testEvidence = {
          schemaVersion: 1,
          source,
          suite: step.id,
          counts: { passed: tests.length, failed: 0, pending: 0 },
          tests,
        };
        writeJson(step.evidencePath, testEvidence, root, {
          subtree: ".quality/test-results",
        });
        testEvidenceFingerprint = crypto.createHash("sha256")
          .update(`${JSON.stringify(testEvidence, null, 2)}\n`)
          .digest("hex");
      }
      for (const artifactPath of [
        ...(step.artifactPaths || []),
        ...(step.artifactPath ? [step.artifactPath] : []),
      ]) {
        const target = path.join(root, ...artifactPath.split("/"));
        if (!fs.existsSync(target)) {
          fs.mkdirSync(path.dirname(target), { recursive: true });
          fs.writeFileSync(target, `synthetic ${step.id} artifact\n`);
        }
      }
      receipt = {
        ...receipt,
        status: "passed",
        exitCode: 0,
        reason: null,
        outputFingerprint: crypto.createHash("sha256").update("").digest("hex"),
        testEvidence,
        testEvidenceFingerprint,
        artifactFingerprint: artifactFingerprintForStep(step, root),
      };
    }
    writeJson(receiptPath(receipt), receipt, root, {
      subtree: ".quality/gates/release",
    });
  }
  return plan;
}

function writePreservedFullGateFromRelease(root, source) {
  const releasePlan = getGatePlan("release");
  const releaseReceipts = new Map(releasePlan.map(step => {
    const relativePath = receiptPath({
      profile: "release",
      sequence: step.sequence,
      stepId: step.id,
    });
    return [
      step.id,
      JSON.parse(fs.readFileSync(path.join(root, ...relativePath.split("/")), "utf8")),
    ];
  }));
  const plan = getGatePlan("full");
  const receipts = plan.map(step => {
    const releaseReceipt = releaseReceipts.get(step.id);
    const completion = releaseReceipt.status === "not-run" ? {
      status: "passed",
      exitCode: 0,
      reason: null,
      outputFingerprint: crypto.createHash("sha256").update(step.id).digest("hex"),
      testEvidence: null,
      testEvidenceFingerprint: null,
      artifactFingerprint: step.artifactPath || step.artifactPaths
        ? crypto.createHash("sha256").update(`${step.id}-artifact`).digest("hex")
        : null,
    } : {};
    return {
      ...releaseReceipt,
      ...completion,
      profile: "full",
      sequence: step.sequence,
      stepId: step.id,
      category: step.category,
      command: step.command,
    };
  });
  for (const receipt of receipts) {
    writeJson(receiptPath(receipt), receipt, root, {
      subtree: ".quality/gates/full",
    });
  }
  const summary = {
    schemaVersion: 1,
    profile: "full",
    source,
    status: aggregateStatuses(receipts.map(receipt => receipt.status)),
    planFingerprint: gatePlanFingerprint(plan),
    steps: receipts,
  };
  summary.key = {
    sha: source.sha,
    fingerprint: fingerprint(summary),
  };
  writeJson(".quality/gates/full.json", summary, root, {
    subtree: ".quality/gates",
  });
  return { plan, receipts };
}

function makeTreeRemovable(root) {
  if (!fs.existsSync(root)) return;
  const pending = [root];
  while (pending.length > 0) {
    const directory = pending.pop();
    const stat = fs.lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink()) continue;
    if (process.platform !== "win32") fs.chmodSync(directory, 0o700);
    for (const name of fs.readdirSync(directory)) {
      const target = path.join(directory, name);
      const targetStat = fs.lstatSync(target);
      if (targetStat.isDirectory() && !targetStat.isSymbolicLink()) pending.push(target);
    }
  }
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
    makeTreeRemovable(scratch);
    fs.rmSync(scratch, { recursive: true, force: true });
  });

  test("defines explicit current, history, artifact, evidence, and all modes", () => {
    assert.deepStrictEqual(parseArguments([]), {
      mode: "current",
      includeLocalEvidence: false,
      signedOutBundle: false,
    });
    assert.deepStrictEqual(parseArguments(["all", "--include-local-evidence"]), {
      mode: "all",
      includeLocalEvidence: true,
      signedOutBundle: false,
    });
    assert.deepStrictEqual(parseArguments(["evidence"]), {
      mode: "evidence",
      includeLocalEvidence: false,
      signedOutBundle: false,
    });
    assert.deepStrictEqual(parseArguments(["evidence", "--signed-out-bundle"]), {
      mode: "evidence",
      includeLocalEvidence: false,
      signedOutBundle: true,
    });
    assert.throws(() => parseArguments(["history", "--include-local-evidence"]));
    assert.throws(() => parseArguments(["history", "--signed-out-bundle"]));
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

  test("retains only the safe stdout report and never propagates scanner stderr", () => {
    const target = path.join(scratch, "target");
    fs.mkdirSync(target);
    const execute = (_executable, args) => {
      assert.strictEqual(args[args.indexOf("--report-path") + 1], "-");
      return {
        status: 1,
        signal: null,
        error: null,
        stdout: JSON.stringify([{
        ruleId: "fixture-rule",
        file: "fixture.txt",
        startLine: 1,
        endLine: 1,
        commit: "",
        }]),
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
    assert.doesNotMatch(JSON.stringify(findings), /scanner-error/u);
  });

  test("stdin scanning hands off only exact bytes and remaps safe findings to the logical path", () => {
    const input = Buffer.from("bounded synthetic stdin bytes\n");
    const findings = scanWithGitleaks("stdin", "quality/logical-proof.txt", {
      root: path.resolve(__dirname, ".."),
      input,
      label: "synthetic-snapshot",
      execute(_executable, args, options) {
        assert.strictEqual(args[0], "stdin");
        assert.strictEqual(args.includes("quality/logical-proof.txt"), false);
        assert.strictEqual(args[args.indexOf("--report-path") + 1], "-");
        assert.deepStrictEqual(options.input, input);
        return {
          status: 1,
          signal: null,
          error: null,
          stdout: JSON.stringify([{
            ruleId: "synthetic-rule",
            file: "",
            startLine: 2,
            endLine: 2,
            commit: "",
          }]),
          stderr: "",
        };
      },
    });
    assert.deepStrictEqual(findings, [{
      ruleId: "synthetic-rule",
      path: "synthetic-snapshot/quality/logical-proof.txt",
      startLine: 2,
      endLine: 2,
      commit: null,
    }]);
  });

  test("classifies only the exact reviewed synthetic credential fixture", () => {
    const fixtureLine = "      CLOUDSMITH_API_KEY: \"synthetic-nonsecret-sentinel\",";
    const sourceAtFirstSlot = line => Buffer.from(`${"\n".repeat(1730)}${line}\n`);
    const sourceBytes = sourceAtFirstSlot(fixtureLine);
    const finding = {
      ruleId: "generic-api-key",
      path: "test/qualityHarness.test.js",
      startLine: 1731,
      endLine: 1731,
      commit: null,
    };
    assert.strictEqual(isReviewedSyntheticTrackedFinding(finding, sourceBytes), true);
    for (const candidate of [
      { ...finding, ruleId: "cloudsmith-api-key" },
      { ...finding, path: "test/another.test.js" },
      { ...finding, startLine: 1732, endLine: 1732 },
      { ...finding, endLine: 3567 },
      { ...finding, commit: "a".repeat(40) },
    ]) {
      assert.strictEqual(isReviewedSyntheticTrackedFinding(candidate, sourceBytes), false);
    }
    for (const line of [
      "      OTHER_API_KEY: \"synthetic-nonsecret-sentinel\",",
      "      CLOUDSMITH_API_KEY: \"ordinary-placeholder\",",
      "      CLOUDSMITH_API_KEY: 'synthetic-nonsecret-sentinel',",
      "      CLOUDSMITH_API_KEY: \"synthetic-nonsecret-sentinel\"",
      "      CLOUDSMITH_API_KEY: \"synthetic-sentinel\\\"escaped\",",
      "      CLOUDSMITH_API_KEY: \"ordinary-placeholder\", // synthetic-sentinel",
    ]) {
      const changedBytes = sourceAtFirstSlot(line);
      assert.strictEqual(isReviewedSyntheticTrackedFinding(finding, changedBytes), false);
      changedBytes.fill(0);
    }
    const originalEvery = Array.prototype.every;
    try {
      Array.prototype.every = function rejectDynamicEvery() {
        assert.fail("Reviewed fixture classification must not call a mutable Array method.");
      };
      assert.strictEqual(isReviewedSyntheticTrackedFinding(finding, sourceBytes), true);
    } finally {
      Array.prototype.every = originalEvery;
    }
    sourceBytes.fill(0);
  });

  test("tracked scanner classifies exactly two reviewed fixture slots and reports policy metadata", () => {
    const relativePath = "test/qualityHarness.test.js";
    const source = path.join(scratch, relativePath);
    fs.mkdirSync(path.dirname(source), { recursive: true });
    const lines = Array.from({ length: 3567 }, () => "// bounded filler");
    lines[1730] = "      CLOUDSMITH_API_KEY: \"synthetic-first-sentinel\",";
    lines[3566] = "      CLOUDSMITH_API_KEY: \"synthetic-second-sentinel\",";
    fs.writeFileSync(source, `${lines.join("\n")}\n`);
    const safeFinding = line => ({
      ruleId: "generic-api-key",
      path: relativePath,
      startLine: line,
      endLine: line,
      commit: null,
    });
    const component = scanTracked(scratch, {
      files: Object.freeze([relativePath]),
      scanWithGitleaks() {
        return [safeFinding(1731), safeFinding(3567)];
      },
    });
    assert.deepStrictEqual(component.findings, []);
    assert.strictEqual(component.reviewedFixtureFindingCount, 2);
    assert.strictEqual(
      component.reviewedFixturePolicyId,
      "qh-synthetic-cloudsmith-api-key-v2",
    );

    assert.throws(() => scanTracked(scratch, {
      files: Object.freeze([relativePath]),
      scanWithGitleaks() {
        return [safeFinding(1731)];
      },
    }), /reviewed synthetic tracked-finding policy is incomplete/iu);
    assert.throws(() => scanTracked(scratch, {
      files: Object.freeze([relativePath]),
      scanWithGitleaks() {
        return [safeFinding(1731), safeFinding(1731), safeFinding(3567)];
      },
    }), /reviewed synthetic tracked-finding policy is ambiguous/iu);

    fs.writeFileSync(source, `// shifted\n// shifted\n${lines.join("\n")}\n`);
    const shifted = scanTracked(scratch, {
      files: Object.freeze([relativePath]),
      scanWithGitleaks() {
        return [safeFinding(1733), safeFinding(3569)];
      },
    });
    assert.deepStrictEqual(shifted.findings, []);
    assert.strictEqual(shifted.reviewedFixtureFindingCount, 2);

    fs.writeFileSync(
      source,
      `// shifted\n// shifted\n${lines.join("\n")}\n${lines[1730]}\n`,
    );
    assert.throws(() => scanTracked(scratch, {
      files: Object.freeze([relativePath]),
      scanWithGitleaks() {
        return [safeFinding(1733), safeFinding(3569), safeFinding(3570)];
      },
    }), /reviewed synthetic tracked-finding policy is ambiguous/iu);
  });

  test("history classification removes only both immutable reviewed fixture slots", async () => {
    const reviewed = line => ({
      ruleId: "generic-api-key",
      file: "test/qualityHarness.test.js",
      startLine: line,
      endLine: line,
      commit: "8e54acd0430a7c1e9f6598d982e245afc5ef94a4",
    });
    const retained = {
      ruleId: "fixture-rule",
      file: "extension.js",
      startLine: 3,
      endLine: 3,
      commit: "5".repeat(40),
    };
    assert.strictEqual(isReviewedSyntheticHistoryFinding({
      ...reviewed(1731),
      path: reviewed(1731).file,
    }), true);
    const result = await executeScan({
      root: path.resolve(__dirname, ".."),
      mode: "history",
      assertScannerVersion() {},
      currentHead() {
        return "a".repeat(40);
      },
      execute() {
        return {
          status: 1,
          signal: null,
          error: null,
          stdout: JSON.stringify([reviewed(1731), reviewed(3567), retained]),
          stderr: "",
        };
      },
    });
    assert.strictEqual(result.findingCount, 1);
    assert.strictEqual(result.components[0].reviewedFixtureFindingCount, 2);
    assert.strictEqual(
      result.components[0].reviewedFixturePolicyId,
      "qh-synthetic-cloudsmith-api-key-v2",
    );
    assert.strictEqual(result.findings[0].path, "extension.js");
  });

  test("history classification recognizes only the exact reviewed legacy location set", async () => {
    const synthetic = line => ({
      ruleId: "generic-api-key",
      file: "test/qualityHarness.test.js",
      startLine: line,
      endLine: line,
      commit: "8e54acd0430a7c1e9f6598d982e245afc5ef94a4",
    });
    const legacy = [
      {
        ruleId: "generic-api-key",
        file: "extension.js",
        startLine: 3,
        endLine: 3,
        commit: "53877432410e6b2d0264ff8bc524d04841efe2f9",
      },
      {
        ruleId: "generic-api-key",
        file: "extension.js",
        startLine: 12,
        endLine: 12,
        commit: "7095cd8f31202971b3743cdf4ac7ee8db7915958",
      },
      {
        ruleId: "generic-api-key",
        file: "functions/cloudsmith_apis.js",
        startLine: 1,
        endLine: 1,
        commit: "961205b2351ce166d54bcc11941e29a906ae2a0d",
      },
    ];
    const run = findings => executeScan({
      root: path.resolve(__dirname, ".."),
      mode: "history",
      assertScannerVersion() {},
      currentHead() {
        return "a".repeat(40);
      },
      execute() {
        return {
          status: 1,
          signal: null,
          error: null,
          stdout: JSON.stringify([synthetic(1731), synthetic(3567), ...findings]),
          stderr: "",
        };
      },
    });
    const result = await run(legacy);
    assert.strictEqual(result.status, "passed");
    assert.strictEqual(result.findingCount, 0);
    assert.strictEqual(result.components[0].reviewedLegacyHistoryFindingCount, 3);
    assert.strictEqual(
      result.components[0].reviewedLegacyHistoryPolicyId,
      "reviewed-disposable-credential-history-v1",
    );
    await assert.rejects(
      () => run(legacy.slice(0, 2)),
      /reviewed legacy history-finding policy is incomplete/iu,
    );
    const shifted = legacy.map(item => ({ ...item }));
    shifted[2].startLine = 2;
    shifted[2].endLine = 2;
    await assert.rejects(
      () => run(shifted),
      /reviewed legacy history-finding policy is incomplete/iu,
    );
    await assert.rejects(
      () => run([...legacy, { ...legacy[0] }]),
      /reviewed legacy history-finding policy is ambiguous/iu,
    );
    const additional = {
      ruleId: "generic-api-key",
      file: "commands/packages.js",
      startLine: 50,
      endLine: 50,
      commit: "b".repeat(40),
    };
    const retained = await run([...legacy, additional]);
    assert.strictEqual(retained.status, "failed");
    assert.strictEqual(retained.findingCount, 1);
    assert.strictEqual(retained.findings[0].path, additional.file);
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
        assert.strictEqual(args[args.indexOf("--report-path") + 1], "-");
        return { status: 0, signal: null, error: null, stdout: "[]\n", stderr: "" };
      },
    });
    assert.deepStrictEqual(findings, []);
    assert.strictEqual(fs.existsSync(scannerHome), false);
  });

  test("scanner subprocesses have a host-enforced kill deadline", () => {
    const started = Date.now();
    const result = runScannerProcess(process.execPath, [
      "-e",
      "setInterval(() => {}, 1000)",
    ], {
      cwd: scratch,
      env: { PATH: process.env.PATH || "" },
      timeoutMilliseconds: 50,
    });
    assert.strictEqual(result.status, null);
    assert.strictEqual(result.signal, "SIGKILL");
    assert.strictEqual(result.error?.code, "ETIMEDOUT");
    assert.ok(Date.now() - started < 5_000);
    assert.strictEqual(SCANNER_PROCESS_TIMEOUT_MS, 60_000);
    assert.throws(
      () => runScannerProcess(process.execPath, ["--version"], {
        timeoutMilliseconds: SCANNER_PROCESS_TIMEOUT_MS + 1,
      }),
      /process timeout is invalid/u,
    );
    assert.throws(
      () => runScannerProcess(process.execPath, ["--version"], {
        extraFileDescriptor: -1,
      }),
      /inherited descriptor is invalid/u,
    );
    assert.throws(
      () => runScannerProcess(process.execPath, ["--version"], {
        extraFileDescriptor: 0,
        input: Buffer.alloc(0),
      }),
      /inherited descriptor is invalid/u,
    );
    const descriptorTarget = path.join(scratch, "inherited-descriptor.txt");
    fs.writeFileSync(descriptorTarget, "bounded descriptor fixture\n");
    const descriptor = fs.openSync(descriptorTarget, fs.constants.O_RDONLY);
    try {
      const inherited = runScannerProcess(process.execPath, [
        "-e",
        "const fs=require('fs');process.stdout.write(fs.fstatSync(3).isFile()?'file':'other')",
      ], {
        cwd: scratch,
        env: { PATH: process.env.PATH || "" },
        extraFileDescriptor: descriptor,
      });
      assert.strictEqual(inherited.status, 0);
      assert.strictEqual(inherited.signal, null);
      assert.strictEqual(inherited.error, undefined);
      assert.strictEqual(inherited.stdout, "file");
    } finally {
      fs.closeSync(descriptor);
    }
  });

  test("current mode scans every generated VSIX through the archive boundary", async () => {
    const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "current-vsix-")));
    const trackedPath = "tracked-proof.txt";
    fs.writeFileSync(path.join(caseRoot, trackedPath), "bounded tracked fixture\n");
    const qualification = path.join(caseRoot, ".quality", "qualification");
    fs.mkdirSync(qualification, { recursive: true });
    fs.writeFileSync(
      path.join(qualification, "live-candidate.json"),
      "{\"status\":\"synthetic\"}\n",
    );
    const secretReceipts = path.join(caseRoot, ".quality", "secrets");
    fs.mkdirSync(secretReceipts, { recursive: true });
    fs.writeFileSync(path.join(secretReceipts, "current.json"), "{\"owned\":true}\n");
    fs.writeFileSync(path.join(secretReceipts, "rogue.json"), "{\"owned\":false}\n");
    const vsixPaths = [
      ".quality/qualification/authenticated-candidate.vsix",
      ".quality/qualification/live-candidate.VSIX",
      ".quality/qualification/ui-candidate.vsix",
    ];
    for (const relativePath of vsixPaths) {
      fs.writeFileSync(
        path.join(caseRoot, ...relativePath.split("/")),
        "bounded archive fixture\n",
      );
    }
    const stdinTargets = [];
    const archiveTargets = [];
    let persisted;
    const result = await executeScan({
      root: caseRoot,
      mode: "current",
      files: Object.freeze([trackedPath]),
      excludedFiles: [".quality/qualification/live-candidate.json"],
      excludedPrefixes: [".quality"],
      assertScannerVersion() {},
      currentHead: () => "a".repeat(40),
      scanWithGitleaks(kind, logicalPath) {
        assert.strictEqual(kind, "stdin");
        assert.strictEqual(logicalPath.toLowerCase().endsWith(".vsix"), false);
        stdinTargets.push(logicalPath);
        return [];
      },
      async scanVsix(_root, relativePath, options) {
        archiveTargets.push(relativePath);
        const target = path.join(caseRoot, ...relativePath.split("/"));
        const identity = exactFileIdentity(fs.lstatSync(target, { bigint: true }));
        assert.deepStrictEqual(options.expectedVsixIdentity, identity);
        return {
          id: `vsix:${relativePath}`,
          status: "scanned",
          fileCount: 1,
          findings: [],
          snapshot: {
            path: relativePath,
            identity,
            sha256: "b".repeat(64),
          },
        };
      },
      writeReceipt(value) { persisted = value; },
    });

    assert.deepStrictEqual(archiveTargets, [...vsixPaths].sort());
    assert.deepStrictEqual(stdinTargets.sort(), [
      ".quality/qualification/live-candidate.json",
      ".quality/secrets/rogue.json",
      trackedPath,
    ]);
    assert.strictEqual(result.status, "passed");
    assert.strictEqual(persisted, result);
  });

  test("current mode rejects a generated candidate appearing during receipt persistence", async () => {
    const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "current-drift-")));
    const trackedPath = "tracked-proof.txt";
    fs.writeFileSync(path.join(caseRoot, trackedPath), "bounded tracked fixture\n");
    const qualification = path.join(caseRoot, ".quality", "qualification");
    fs.mkdirSync(qualification, { recursive: true });
    const relativePath = ".quality/qualification/live-candidate.vsix";
    fs.writeFileSync(
      path.join(caseRoot, ...relativePath.split("/")),
      "bounded archive fixture\n",
    );
    let writeCalls = 0;
    await assert.rejects(executeScan({
      root: caseRoot,
      mode: "current",
      files: Object.freeze([trackedPath]),
      assertScannerVersion() {},
      currentHead: () => "a".repeat(40),
      scanWithGitleaks() { return []; },
      async scanVsix(_root, scannedPath) {
        const target = path.join(caseRoot, ...scannedPath.split("/"));
        return {
          id: `vsix:${scannedPath}`,
          status: "scanned",
          fileCount: 1,
          findings: [],
          snapshot: {
            path: scannedPath,
            identity: exactFileIdentity(fs.lstatSync(target, { bigint: true })),
            sha256: "b".repeat(64),
          },
        };
      },
      writeReceipt() {
        writeCalls += 1;
        fs.writeFileSync(
          path.join(qualification, "appeared-candidate.vsix"),
          "late archive fixture\n",
        );
      },
    }), /generated qualification inventory changed/iu);
    assert.strictEqual(writeCalls, 1);
  });

  test("current mode rejects forged generated and VSIX adapter coverage", async () => {
    for (const mutation of ["generated-count", "vsix-identity", "vsix-count"]) {
      const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, `adapter-${mutation}-`)));
      const trackedPath = "tracked-proof.txt";
      fs.writeFileSync(path.join(caseRoot, trackedPath), "bounded tracked fixture\n");
      const qualification = path.join(caseRoot, ".quality", "qualification");
      fs.mkdirSync(qualification, { recursive: true });
      fs.writeFileSync(path.join(qualification, "proof.json"), "{\"status\":\"bounded\"}\n");
      const relativePath = ".quality/qualification/live-candidate.vsix";
      const candidatePath = path.join(caseRoot, ...relativePath.split("/"));
      fs.writeFileSync(candidatePath, "bounded archive fixture\n");
      await assert.rejects(executeScan({
        root: caseRoot,
        mode: "current",
        files: Object.freeze([trackedPath]),
        assertScannerVersion() {},
        currentHead: () => "a".repeat(40),
        scanWithGitleaks() { return []; },
        scanGeneratedEvidence(_root, _relativeDirectory, options) {
          const result = syntheticGeneratedScanResult(options);
          return mutation === "generated-count"
            ? { ...result, fileCount: result.fileCount + 1 }
            : result;
        },
        async scanVsix(_root, scannedPath) {
          const identity = exactFileIdentity(fs.lstatSync(candidatePath, { bigint: true }));
          return {
            id: `vsix:${scannedPath}`,
            status: "scanned",
            fileCount: mutation === "vsix-count" ? 10002 : 1,
            findings: [],
            snapshot: {
              path: scannedPath,
              identity: mutation === "vsix-identity"
                ? { ...identity, inode: `${identity.inode}-crossed` }
                : identity,
              sha256: "b".repeat(64),
            },
          };
        },
      }), /generated qualification scanner returned invalid findings/iu, mutation);
    }
  });

  test("current mode bounds the aggregate generated VSIX inventory", async () => {
    const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "vsix-bound-")));
    const trackedPath = "tracked-proof.txt";
    fs.writeFileSync(path.join(caseRoot, trackedPath), "bounded tracked fixture\n");
    const qualification = path.join(caseRoot, ".quality", "qualification");
    fs.mkdirSync(qualification, { recursive: true });
    for (let index = 0; index < 65; index += 1) {
      fs.writeFileSync(
        path.join(qualification, `candidate-${String(index).padStart(2, "0")}.vsix`),
        "bounded archive fixture\n",
      );
    }
    let candidateReached = false;
    await assert.rejects(executeScan({
      root: caseRoot,
      mode: "current",
      files: Object.freeze([trackedPath]),
      assertScannerVersion() {},
      currentHead: () => "a".repeat(40),
      scanWithGitleaks() { return []; },
      async scanVsix() { candidateReached = true; return null; },
    }), /VSIX inventory exceeds its safety bound/u);
    assert.strictEqual(candidateReached, false);
  });

  test("fails closed when scanner exit status and safe report disagree", () => {
    const target = path.join(scratch, "target");
    fs.mkdirSync(target);
    const execute = () => (
      { status: 1, signal: null, error: null, stdout: "[]\n", stderr: "" }
    );
    assert.throws(
      () => scanWithGitleaks("dir", target, {
        root: path.resolve(__dirname, ".."),
        scanRoot: target,
        execute,
      }),
      /exit status disagrees/u,
    );
  });

  test("keeps a clean scanner report fail-closed when stdin transport breaks", () => {
    assert.throws(
      () => scanWithGitleaks("stdin", "quality/large-proof.vsix", {
        root: path.resolve(__dirname, ".."),
        input: Buffer.alloc(1024 * 1024, 0x5a),
        execute() {
          return {
            status: 0,
            signal: null,
            error: Object.assign(new Error("synthetic transport break"), { code: "EPIPE" }),
            stdout: "[]\n",
            stderr: "",
          };
        },
      }),
      /failed closed before producing a trustworthy result/u,
    );
  });

  test("rejects missing, oversized, and unexpected scanner stdout without reflecting it", () => {
    const target = path.join(scratch, "stdout-target");
    fs.mkdirSync(target);
    const cases = [
      "",
      "SYNTHETIC_UNEXPECTED_OUTPUT[]\n",
      Buffer.alloc((2 * 1024 * 1024) + 1, 0x78),
    ];
    for (const stdout of cases) {
      assert.throws(
        () => scanWithGitleaks("dir", target, {
          root: path.resolve(__dirname, ".."),
          scanRoot: target,
          execute() {
            return { status: 0, signal: null, error: null, stdout, stderr: "" };
          },
        }),
        error => {
          assert.doesNotMatch(error.message, /SYNTHETIC_UNEXPECTED_OUTPUT/u);
          return /bounded safe metadata report|safe metadata report is invalid/u.test(error.message);
        },
      );
    }
  });

  test("scanner cleanup quarantines exact roots and refuses a substituted victim", () => {
    const target = path.join(scratch, "cleanup-target");
    fs.mkdirSync(target);
    let reportRoot;
    let displaced;
    const victimName = "synthetic-victim.txt";
    assert.throws(
      () => scanWithGitleaks("dir", target, {
        root: path.resolve(__dirname, ".."),
        scanRoot: target,
        execute(_executable, _args, options) {
          reportRoot = path.dirname(options.env.HOME);
          displaced = `${reportRoot}-owned`;
          fs.renameSync(reportRoot, displaced);
          fs.mkdirSync(reportRoot, { mode: 0o700 });
          fs.writeFileSync(path.join(reportRoot, victimName), "synthetic victim bytes\n");
          return { status: 0, signal: null, error: null, stdout: "[]\n", stderr: "" };
        },
      }),
      /cleanup refused an unsafe or changed root/u,
    );
    assert.strictEqual(
      fs.readFileSync(path.join(reportRoot, victimName), "utf8"),
      "synthetic victim bytes\n",
    );
    assert.strictEqual(fs.existsSync(displaced), true);

    fs.rmSync(reportRoot, { recursive: true, force: true });
    fs.renameSync(displaced, reportRoot);
    assert.strictEqual(removePrivateSnapshotRoot(
      reportRoot,
      undefined,
      "Synthetic scanner cleanup retry failed.",
    ), true);
    assert.strictEqual(fs.existsSync(reportRoot), false);
    assert.doesNotMatch(
      fs.readFileSync(path.resolve(__dirname, "..", "scripts", "quality", "secret-scan.js"), "utf8"),
      /\brmSync\s*\(/u,
    );
  });

  test("tracked capture rejects symbolic links without scanning", () => {
    const sourceRoot = path.join(scratch, "source");
    fs.mkdirSync(sourceRoot);
    fs.writeFileSync(path.join(scratch, "outside.txt"), "outside-content\n");
    fs.symlinkSync("../outside.txt", path.join(sourceRoot, "linked.txt"));
    let scannerReached = false;
    assert.throws(
      () => scanTracked(sourceRoot, {
        files: Object.freeze(["linked.txt"]),
        scanWithGitleaks() {
          scannerReached = true;
          return [];
        },
      }),
      /Tracked-file source changed or became unsafe/u,
    );
    assert.strictEqual(scannerReached, false);
  });

  test("tracked capture rejects hard links and oversized regular files", () => {
    const sourceRoot = path.join(scratch, "bounded-source");
    fs.mkdirSync(sourceRoot);

    const linked = path.join(sourceRoot, "linked.txt");
    fs.writeFileSync(linked, "bounded linked fixture\n");
    fs.linkSync(linked, path.join(sourceRoot, "linked-alias.txt"));
    assert.throws(
      () => scanTracked(sourceRoot, {
        files: Object.freeze(["linked.txt"]),
        scanWithGitleaks() {
          assert.fail("A hard-linked tracked source must not reach the scanner.");
        },
      }),
      /Tracked-file source changed or became unsafe/u,
    );

    const oversized = path.join(sourceRoot, "oversized.txt");
    fs.writeFileSync(oversized, "x");
    fs.truncateSync(oversized, MAX_TRACKED_FILE_BYTES + 1);
    assert.throws(
      () => scanTracked(sourceRoot, {
        files: Object.freeze(["oversized.txt"]),
        scanWithGitleaks() {
          assert.fail("An oversized tracked source must not reach the scanner.");
        },
      }),
      /Tracked-file source changed or became unsafe/u,
    );
  });

  test("tracked capture rejects a source swapped after identity capture", () => {
    const sourceRoot = path.join(scratch, "source-swap");
    fs.mkdirSync(sourceRoot);
    const source = path.join(sourceRoot, "proof.txt");
    const displaced = path.join(sourceRoot, "proof-original.txt");
    const replacement = path.join(sourceRoot, "proof-replacement.txt");
    fs.writeFileSync(source, "authorized tracked fixture\n");
    fs.writeFileSync(replacement, "substituted tracked fixture\n");
    const fileSystem = Object.create(fs);
    let swapped = false;
    fileSystem.lstatSync = function swapAfterTrackedIdentity(target, ...arguments_) {
      const stat = fs.lstatSync(target, ...arguments_);
      if (!swapped && target === source) {
        fs.renameSync(source, displaced);
        fs.renameSync(replacement, source);
        swapped = true;
      }
      return stat;
    };
    try {
      assert.throws(
        () => scanTracked(sourceRoot, {
          files: Object.freeze(["proof.txt"]),
          fileSystem,
          scanWithGitleaks() {
            assert.fail("A swapped tracked source must not reach the scanner.");
          },
        }),
        /Tracked-file source changed or became unsafe/u,
      );
    } finally {
      if (swapped) {
        fs.unlinkSync(source);
        fs.renameSync(displaced, source);
      }
    }
    assert.strictEqual(swapped, true);
  });

  test("tracked capture bounds descriptor reads, rejects growth, and clears read buffers", () => {
    const sourceRoot = path.join(scratch, "source-growth");
    fs.mkdirSync(sourceRoot);
    const source = path.join(sourceRoot, "proof.txt");
    const capturedBytes = 257;
    fs.writeFileSync(source, Buffer.alloc(capturedBytes, 0x73));
    let sourceDescriptor;
    let readBuffer;
    let grew = false;
    let requestedBytes = 0;
    const fileSystem = Object.create(fs);
    fileSystem.openSync = function captureSourceDescriptor(target, ...arguments_) {
      const descriptor = fs.openSync(target, ...arguments_);
      if (target === source) sourceDescriptor = descriptor;
      return descriptor;
    };
    fileSystem.readSync = function growDuringBoundedRead(
      descriptor,
      buffer,
      offset,
      length,
      position,
    ) {
      if (descriptor === sourceDescriptor) {
        readBuffer = buffer;
        requestedBytes += length;
        assert.ok(requestedBytes <= capturedBytes);
        if (!grew) {
          fs.appendFileSync(source, Buffer.alloc(193, 0x67));
          grew = true;
        }
      }
      return fs.readSync(descriptor, buffer, offset, length, position);
    };
    assert.throws(
      () => scanTracked(sourceRoot, {
        files: Object.freeze(["proof.txt"]),
        fileSystem,
        scanWithGitleaks() {
          assert.fail("A growing tracked source must not reach the scanner.");
        },
      }),
      /Tracked-file source changed or became unsafe/u,
    );
    assert.strictEqual(grew, true);
    assert.strictEqual(requestedBytes, capturedBytes);
    assert.ok(Buffer.isBuffer(readBuffer));
    assert.ok(readBuffer.every(byte => byte === 0));
  });

  test("tracked capture rejects FIFOs without opening or reading them", function () {
    if (process.platform === "win32") this.skip();
    const sourceRoot = path.join(scratch, "source-fifo");
    fs.mkdirSync(sourceRoot);
    const source = path.join(sourceRoot, "proof.pipe");
    const fixture = spawnSync("mkfifo", [source], {
      stdio: "ignore",
    });
    assert.strictEqual(fixture.status, 0);
    const fileSystem = Object.create(fs);
    fileSystem.openSync = function rejectFifoOpen() {
      assert.fail("A tracked FIFO must be rejected before opening.");
    };
    fileSystem.readSync = function rejectFifoRead() {
      assert.fail("A tracked FIFO must be rejected before reading.");
    };
    assert.throws(
      () => scanTracked(sourceRoot, {
        files: Object.freeze(["proof.pipe"]),
        fileSystem,
        scanWithGitleaks() {
          assert.fail("A tracked FIFO must not reach the scanner.");
        },
      }),
      /Tracked-file source changed or became unsafe/u,
    );
  });

  test("tracked capture opens a post-lstat FIFO replacement nonblocking and never reads it", function () {
    if (process.platform === "win32" || !fs.constants.O_NONBLOCK) this.skip();
    const sourceRoot = path.join(scratch, "source-fifo-swap");
    fs.mkdirSync(sourceRoot);
    const relativePath = "proof.txt";
    const source = path.join(sourceRoot, relativePath);
    const displaced = path.join(sourceRoot, "proof-original.txt");
    fs.writeFileSync(source, "synthetic tracked bytes\n");
    const fileSystem = Object.create(fs);
    let fifoDescriptor;
    let fifoFstatReached = false;
    let fifoObserved = false;
    let fifoStatus;
    let openFlags;
    let readCalls = 0;
    let scannerReached = false;
    let sourceLstats = 0;
    let swapped = false;
    fileSystem.lstatSync = function swapRegularFileForFifo(target, ...arguments_) {
      const stat = fs.lstatSync(target, ...arguments_);
      if (target === source) {
        sourceLstats += 1;
        if (sourceLstats === 2) {
          fs.renameSync(source, displaced);
          fifoStatus = spawnSync("mkfifo", [source], { stdio: "ignore" }).status;
          swapped = fifoStatus === 0;
        }
      }
      return stat;
    };
    fileSystem.openSync = function observeNonblockingFifoOpen(target, flags, ...arguments_) {
      if (target === source) {
        openFlags = flags;
        if ((flags & fs.constants.O_NONBLOCK) === 0) {
          throw new Error("Synthetic FIFO fixture refuses a potentially blocking open.");
        }
        fifoDescriptor = fs.openSync(target, flags, ...arguments_);
        return fifoDescriptor;
      }
      return fs.openSync(target, flags, ...arguments_);
    };
    fileSystem.fstatSync = function observeFifoRejection(descriptor, ...arguments_) {
      const stat = fs.fstatSync(descriptor, ...arguments_);
      if (descriptor === fifoDescriptor) {
        fifoFstatReached = true;
        fifoObserved = stat.isFIFO();
      }
      return stat;
    };
    fileSystem.readSync = function rejectFifoRead() {
      readCalls += 1;
      throw new Error("A post-lstat FIFO replacement must never be read.");
    };
    try {
      assert.throws(() => scanTracked(sourceRoot, {
        files: Object.freeze([relativePath]),
        fileSystem,
        scanWithGitleaks() {
          scannerReached = true;
          return [];
        },
      }), /Tracked-file source changed or became unsafe/u);
    } finally {
      if (swapped) fs.unlinkSync(source);
      if (fs.existsSync(displaced)) fs.renameSync(displaced, source);
    }
    assert.strictEqual(fifoStatus, 0);
    assert.strictEqual(swapped, true);
    assert.ok((openFlags & fs.constants.O_NONBLOCK) !== 0);
    assert.strictEqual(fifoFstatReached, true);
    assert.strictEqual(fifoObserved, true);
    assert.strictEqual(readCalls, 0);
    assert.strictEqual(scannerReached, false);
  });

  test("injected tracked inventories must be frozen plain dense primitive arrays", () => {
    const sourceRoot = path.join(scratch, "injected-inventory");
    const relativePath = "proof.txt";
    fs.mkdirSync(sourceRoot);
    fs.writeFileSync(path.join(sourceRoot, relativePath), "synthetic tracked bytes\n");
    let accessorCalls = 0;
    const sparse = [];
    sparse.length = 1;
    Object.freeze(sparse);
    const accessor = [];
    Object.defineProperty(accessor, "0", {
      configurable: false,
      enumerable: true,
      get() {
        accessorCalls += 1;
        return relativePath;
      },
    });
    Object.freeze(accessor);
    const customIterator = [relativePath];
    Object.defineProperty(customIterator, Symbol.iterator, {
      configurable: false,
      enumerable: false,
      value() {
        assert.fail("A custom tracked inventory iterator must never run.");
      },
      writable: false,
    });
    Object.freeze(customIterator);
    const customPrototype = [relativePath];
    Object.setPrototypeOf(customPrototype, Object.create(Array.prototype));
    Object.freeze(customPrototype);
    const extraProperty = [relativePath];
    Object.defineProperty(extraProperty, "extra", {
      configurable: false,
      enumerable: false,
      value: "synthetic-extra",
      writable: false,
    });
    Object.freeze(extraProperty);
    const invalid = [
      [relativePath],
      sparse,
      accessor,
      customIterator,
      customPrototype,
      Object.freeze([Object.freeze({ value: relativePath })]),
      extraProperty,
      new Proxy(Object.freeze([relativePath]), {}),
    ];
    for (let index = 0; index < invalid.length; index += 1) {
      let scannerReached = false;
      assert.throws(() => scanTracked(sourceRoot, {
        files: invalid[index],
        scanWithGitleaks() {
          scannerReached = true;
          return [];
        },
      }), /plain frozen dense array/u);
      assert.strictEqual(scannerReached, false);
    }
    assert.strictEqual(accessorCalls, 0);
  });

  test("rejects traversal and symbolic-link shaped VSIX entries", () => {
    assert.strictEqual(validateArchiveEntryPath("extension/package.json"), "extension/package.json");
    for (const candidate of ["../escape", "/absolute", "folder/../escape", "folder\\escape"]) {
      assert.throws(() => validateArchiveEntryPath(candidate));
    }
  });

  test("upload-eligible UI evidence binds one exact receipt/proof snapshot through persistence", async () => {
    const fixture = await createUiCandidateScanFixture(scratch);
    const liveCandidatePath = path.join(scratch, ...LIVE_CANDIDATE_ARTIFACT.split("/"));
    fs.writeFileSync(liveCandidatePath, "bounded auxiliary archive fixture\n");
    const scannedTargets = [];
    const auxiliaryTargets = [];
    const scanRoots = new Set();
    let persisted;
    const result = await executeScan({
      root: scratch,
      mode: "evidence",
      assertScannerVersion() {},
      currentHead: () => fixture.source.sha,
      scanGeneratedEvidence(_root, relativeDirectory, options) {
        assert.strictEqual(relativeDirectory, ".quality");
        assert.deepStrictEqual([...options.excludedPrefixes], []);
        assert.deepStrictEqual(
          [...options.excludedFiles].sort(),
          [
            ...UI_CANDIDATE_SCAN_EXCLUSIONS,
            ".quality/secrets/evidence.json",
            LIVE_CANDIDATE_ARTIFACT,
          ].sort(),
        );
        return syntheticGeneratedScanResult(options);
      },
      scanWithGitleaks(_kind, target, options) {
        if (_kind === "dir") {
          const artifactName = path.basename(UI_CANDIDATE_ARTIFACT);
          scannedTargets.push(artifactName);
          assert.strictEqual(path.basename(options.descriptorSourcePath), artifactName);
          scanRoots.add(path.dirname(options.descriptorSourcePath));
          assert.strictEqual(options.input, undefined);
          if (process.platform === "win32") {
            assert.strictEqual(target, options.descriptorSourcePath);
            assert.strictEqual(options.extraFileDescriptor, undefined);
          } else {
            assert.strictEqual(
              target,
              process.platform === "linux" ? "/proc/self/fd/3" : "/dev/fd/3",
            );
            assert.strictEqual(Number.isSafeInteger(options.extraFileDescriptor), true);
          }
          return [];
        }
        scannedTargets.push(target);
        scanRoots.add(options.scanRoot);
        assert.strictEqual(_kind, "stdin");
        assert.strictEqual(options.logicalPath, target);
        const expected = {
          [path.basename(UI_CANDIDATE_RECEIPT)]: fixture.receiptBytes,
          [path.basename(UI_CANDIDATE_ARTIFACT)]: fixture.artifactBytes,
          "extension/safe.txt": Buffer.from("bounded synthetic candidate fixture\n"),
        }[target];
        assert.ok(expected, target);
        assert.deepStrictEqual(options.input, expected);
        return [];
      },
      async scanVsix(_root, relativePath, options) {
        auxiliaryTargets.push(relativePath);
        const identity = exactFileIdentity(fs.lstatSync(liveCandidatePath, { bigint: true }));
        assert.strictEqual(relativePath, LIVE_CANDIDATE_ARTIFACT);
        assert.deepStrictEqual(options.expectedVsixIdentity, identity);
        return {
          id: `vsix:${relativePath}`,
          status: "scanned",
          fileCount: 1,
          findings: [],
          snapshot: {
            path: relativePath,
            identity,
            sha256: "b".repeat(64),
          },
        };
      },
      writeReceipt(value) { persisted = value; },
      now: new Date("2026-08-27T12:05:00.000Z"),
    });

    assert.deepStrictEqual(scannedTargets, [
      path.basename(UI_CANDIDATE_RECEIPT),
      path.basename(UI_CANDIDATE_ARTIFACT),
      "extension/safe.txt",
    ]);
    assert.ok([...scanRoots].every(scanRoot => !fs.existsSync(scanRoot)));
    assert.deepStrictEqual(result.components.map(component => component.id), [
      "generated-quality-evidence",
      `vsix:${UI_CANDIDATE_ARTIFACT}`,
    ]);
    assert.deepStrictEqual(auxiliaryTargets, [LIVE_CANDIDATE_ARTIFACT]);
    assert.deepStrictEqual(result.candidate, {
      receiptFingerprint: fixture.receipt.fingerprint,
      receiptSha256: crypto.createHash("sha256").update(fixture.receiptBytes).digest("hex"),
      vsixSha256: fixture.artifactSha256,
    });
    assert.strictEqual(persisted, result);
    assert.strictEqual(result.components[1].fileCount, 3);
  });

  test("upload-eligible UI candidate rejects add, change, delete, and byte/identity replacement races", async () => {
    for (const mutation of ["add", "change", "delete", "different", "same"]) {
      const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, `${mutation}-`)));
      const fixture = await createUiCandidateScanFixture(caseRoot);
      if (mutation === "add") {
        fs.unlinkSync(fixture.receiptPath);
        fs.unlinkSync(fixture.artifactPath);
      }
      let scanCalls = 0;
      let persisted = 0;
      let snapshotRoot;
      const outputPath = ".quality/secrets/evidence.json";
      await assert.rejects(executeScan({
        root: caseRoot,
        mode: "evidence",
        outputPath,
        assertScannerVersion() {},
        currentHead: () => fixture.source.sha,
        scanGeneratedEvidence(_root, _relativeDirectory, options) {
          assert.deepStrictEqual([...options.excludedPrefixes], []);
          assert.deepStrictEqual(
            [...options.excludedFiles].sort(),
            [
              ...UI_CANDIDATE_SCAN_EXCLUSIONS,
              ".quality/secrets/evidence.json",
            ].sort(),
          );
          if (mutation === "add") {
            fs.writeFileSync(fixture.receiptPath, fixture.receiptBytes, { mode: 0o600 });
            fs.writeFileSync(fixture.artifactPath, fixture.artifactBytes, { mode: 0o600 });
          }
          return syntheticGeneratedScanResult(options);
        },
        scanWithGitleaks(_kind, _target, options) {
          scanCalls += 1;
          if (scanCalls === 1) snapshotRoot = options.scanRoot;
          if (scanCalls === 1 && mutation === "change") {
            const changed = Buffer.from(fixture.receiptBytes);
            const whitespace = changed.indexOf(0x20);
            changed[whitespace] = 0x09;
            fs.writeFileSync(fixture.receiptPath, changed, { mode: 0o600 });
          } else if (scanCalls === 2 && mutation === "delete") {
            fs.unlinkSync(fixture.receiptPath);
          } else if (scanCalls === 1 && mutation === "different") {
            const replacement = path.join(
              path.dirname(fixture.artifactPath),
              "different-candidate.vsix",
            );
            fs.writeFileSync(replacement, "different bounded candidate bytes\n", {
              mode: 0o600,
            });
            fs.renameSync(replacement, fixture.artifactPath);
          }
          return [];
        },
        writeReceipt(value) {
          persisted += 1;
          writeJson(outputPath, value, caseRoot, { subtree: ".quality/secrets" });
          if (mutation === "same") {
            const replacement = path.join(
              path.dirname(fixture.artifactPath),
              "same-candidate.vsix",
            );
            fs.writeFileSync(replacement, fixture.artifactBytes, { mode: 0o600 });
            fs.renameSync(replacement, fixture.artifactPath);
          }
        },
      }), /upload-eligible UI candidate changed during secret scanning/iu, mutation);
      assert.strictEqual(persisted, mutation === "same" ? 1 : 0, mutation);
      assert.strictEqual(fs.existsSync(path.join(caseRoot, outputPath)), false, mutation);
      if (snapshotRoot) assert.strictEqual(fs.existsSync(snapshotRoot), false, mutation);
    }
  });

  test("signed-out evidence requires the complete candidate pair and UI result", async () => {
    for (const missing of ["receipt", "artifact", "pair", "ui"]) {
      const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, `missing-${missing}-`)));
      const fixture = await createSignedOutBundleFixture(caseRoot);
      if (missing === "receipt" || missing === "pair") fs.unlinkSync(fixture.receiptPath);
      if (missing === "artifact" || missing === "pair") fs.unlinkSync(fixture.artifactPath);
      if (missing === "ui") fs.unlinkSync(fixture.uiPath);
      let scanCalls = 0;
      await assert.rejects(executeScan({
        root: caseRoot,
        mode: "evidence",
        signedOutBundle: true,
        outputPath: ".quality/secrets/evidence.json",
        sourceIdentity: () => fixture.source,
        assertScannerVersion() {},
        currentHead: () => fixture.source.sha,
        scanGeneratedEvidence() { scanCalls += 1; },
        scanWithGitleaks() { scanCalls += 1; },
      }), /signed-out|candidate|path|file|ENOENT/iu, missing);
      assert.strictEqual(scanCalls, 0, missing);
      assert.strictEqual(fs.existsSync(path.join(
        caseRoot,
        ...SIGNED_OUT_BUNDLE_DIRECTORY.split("/"),
      )), false, missing);
    }
  });

  test("signed-out evidence scan stages and detached-verifies one exact four-file bundle", async () => {
    const fixture = await createSignedOutBundleFixture(scratch);
    const scannedTargets = [];
    const outputPath = ".quality/secrets/evidence.json";
    const result = await executeScan({
      root: scratch,
      mode: "evidence",
      signedOutBundle: true,
      outputPath,
      sourceIdentity: () => fixture.source,
      assertScannerVersion() {},
      currentHead: () => fixture.source.sha,
      scanGeneratedEvidence(_root, relativeDirectory, options) {
        assert.strictEqual(relativeDirectory, ".quality");
        assert.deepStrictEqual([...options.excludedPrefixes], []);
        assert.deepStrictEqual(
          [...options.excludedFiles].sort(),
          [
            ...SIGNED_OUT_UI_SCAN_EXCLUSIONS,
            ".quality/secrets/evidence.json",
            ...SIGNED_OUT_BUNDLE_NAMES.map(name => (
              `${SIGNED_OUT_BUNDLE_DIRECTORY}/${name}`
            )),
          ].sort(),
        );
        return syntheticGeneratedScanResult(options);
      },
      scanWithGitleaks(_kind, target, options) {
        if (_kind === "dir") {
          const artifactName = path.basename(UI_CANDIDATE_ARTIFACT);
          scannedTargets.push(artifactName);
          assert.strictEqual(path.basename(options.descriptorSourcePath), artifactName);
          assert.strictEqual(options.input, undefined);
          if (process.platform === "win32") {
            assert.strictEqual(target, options.descriptorSourcePath);
            assert.strictEqual(options.extraFileDescriptor, undefined);
          } else {
            assert.strictEqual(
              target,
              process.platform === "linux" ? "/proc/self/fd/3" : "/dev/fd/3",
            );
            assert.strictEqual(Number.isSafeInteger(options.extraFileDescriptor), true);
          }
          return [];
        }
        scannedTargets.push(target);
        assert.strictEqual(_kind, "stdin");
        const expected = {
          "result.json": fixture.uiBytes,
          "ui-candidate.json": fixture.receiptBytes,
          "ui-candidate.vsix": fixture.artifactBytes,
          "extension/safe.txt": Buffer.from("bounded synthetic candidate fixture\n"),
        }[target];
        assert.ok(expected, target);
        assert.deepStrictEqual(options.input, expected);
        return [];
      },
      now: new Date("2026-08-27T12:05:00.000Z"),
    });
    const stage = path.join(scratch, ...SIGNED_OUT_BUNDLE_DIRECTORY.split("/"));
    assert.deepStrictEqual(fs.readdirSync(stage).sort(), [...SIGNED_OUT_BUNDLE_NAMES]);
    assert.strictEqual(result.schemaVersion, 2);
    assert.strictEqual(result.status, "passed");
    assert.strictEqual(result.bundle.source.fingerprint, fixture.source.fingerprint);
    assert.strictEqual(result.bundle.receipt.bytes, fs.statSync(
      path.join(stage, "evidence.json"),
    ).size);
    assert.strictEqual(
      fs.readFileSync(path.join(stage, "ui-candidate.vsix")).equals(fixture.artifactBytes),
      true,
    );
    assert.deepStrictEqual(scannedTargets, [
      "result.json",
      "ui-candidate.json",
      "ui-candidate.vsix",
      "extension/safe.txt",
    ]);

    const detachedParent = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "detached-")));
    const detached = path.join(detachedParent, "bundle");
    fs.cpSync(stage, detached, { recursive: true });
    if (process.platform !== "win32") {
      for (const name of SIGNED_OUT_BUNDLE_NAMES) fs.chmodSync(path.join(detached, name), 0o400);
      fs.chmodSync(detached, 0o500);
    }
    const expectedMemberDigests = Object.fromEntries(SIGNED_OUT_BUNDLE_NAMES.map(name => [
      name,
      crypto.createHash("sha256").update(fs.readFileSync(path.join(detached, name))).digest("hex"),
    ]));
    const verified = verifyDetachedSignedOutUiBundle({
      bundleRoot: detached,
      contractRoot: scratch,
      expectedMemberDigests,
      expectedSourceSha: fixture.source.sha,
    });
    assert.deepStrictEqual(verified, {
      status: "passed",
      sourceSha: fixture.source.sha,
      testCount: 1,
      fingerprint: result.fingerprint,
      candidate: candidateBindingFromReceipt(fixture.receipt, { source: fixture.source }),
    });

    if (process.platform !== "win32") {
      fs.chmodSync(detached, 0o700);
      fs.chmodSync(path.join(detached, "result.json"), 0o600);
    }
    fs.appendFileSync(path.join(detached, "result.json"), " ");
    assert.throws(() => verifyDetachedSignedOutUiBundle({
      bundleRoot: detached,
      contractRoot: scratch,
      expectedMemberDigests,
      expectedSourceSha: fixture.source.sha,
    }), /does not match the authoritative archive/u);
  });

  test("signed-out staging cleans source, add, change, delete, and same-byte replacement drift", async () => {
    for (const mutation of ["source", "add", "change", "delete", "same", "generated"]) {
      const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, `stage-${mutation}-`)));
      const fixture = await createSignedOutBundleFixture(caseRoot);
      const outputPath = ".quality/secrets/evidence.json";
      const generatedProof = path.join(
        caseRoot,
        ".quality",
        "qualification",
        "auxiliary.json",
      );
      fs.writeFileSync(generatedProof, "{\"status\":\"bounded\"}\n");
      let sourceDrift = false;
      await assert.rejects(executeScan({
        root: caseRoot,
        mode: "evidence",
        signedOutBundle: true,
        outputPath,
        sourceIdentity: () => sourceDrift
          ? { ...fixture.source, fingerprint: "f".repeat(64) }
          : fixture.source,
        assertScannerVersion() {},
        currentHead: () => fixture.source.sha,
        scanWithGitleaks() { return []; },
        afterSignedOutBundleStage(stage) {
          if (process.platform !== "win32") fs.chmodSync(stage, 0o700);
          const resultPath = path.join(stage, "result.json");
          if (mutation === "source") {
            sourceDrift = true;
          } else if (mutation === "add") {
            fs.writeFileSync(path.join(stage, "unexpected.json"), "{}\n");
          } else if (mutation === "change") {
            fs.chmodSync(resultPath, 0o600);
            fs.writeFileSync(resultPath, `${JSON.stringify({ changed: true })}\n`);
          } else if (mutation === "delete") {
            fs.unlinkSync(resultPath);
          } else if (mutation === "same") {
            const replacement = path.join(stage, "replacement.json");
            fs.writeFileSync(replacement, fixture.uiBytes, { mode: 0o400 });
            fs.renameSync(replacement, resultPath);
          } else {
            fs.writeFileSync(generatedProof, "{\"status\":\"changed\"}\n");
          }
          if (process.platform !== "win32") fs.chmodSync(stage, 0o500);
        },
      }), /signed-out UI|staged signed-out|generated qualification inventory/iu, mutation);
      assert.strictEqual(fs.existsSync(path.join(caseRoot, outputPath)), false, mutation);
      assert.strictEqual(fs.existsSync(path.join(
        caseRoot,
        ...SIGNED_OUT_BUNDLE_DIRECTORY.split("/"),
      )), false, mutation);
    }
  });

  test("detached bundle verifier rejects inventory, byte, and in-flight identity drift", async () => {
    const fixture = await createSignedOutBundleFixture(scratch);
    await executeScan({
      root: scratch,
      mode: "evidence",
      signedOutBundle: true,
      outputPath: ".quality/secrets/evidence.json",
      sourceIdentity: () => fixture.source,
      assertScannerVersion() {},
      currentHead: () => fixture.source.sha,
      scanGeneratedEvidence(_root, _relativeDirectory, options) {
        return syntheticGeneratedScanResult(options);
      },
      scanWithGitleaks() { return []; },
    });
    const stage = path.join(scratch, ...SIGNED_OUT_BUNDLE_DIRECTORY.split("/"));
    const forgedParent = fs.realpathSync(fs.mkdtempSync(path.join(
      scratch,
      "verify-toolchain-",
    )));
    const forgedBundle = path.join(forgedParent, "bundle");
    fs.cpSync(stage, forgedBundle, { recursive: true });
    if (process.platform !== "win32") {
      fs.chmodSync(forgedBundle, 0o700);
      for (const name of SIGNED_OUT_BUNDLE_NAMES) {
        fs.chmodSync(path.join(forgedBundle, name), 0o600);
      }
    }
    const candidatePath = path.join(forgedBundle, "ui-candidate.json");
    const forgedCandidate = JSON.parse(fs.readFileSync(candidatePath, "utf8"));
    forgedCandidate.toolchain.npmInstallationSha256 = "0".repeat(64);
    const candidateUnsigned = { ...forgedCandidate };
    delete candidateUnsigned.fingerprint;
    forgedCandidate.fingerprint = fingerprint(candidateUnsigned);
    const forgedCandidateBytes = Buffer.from(`${JSON.stringify(forgedCandidate, null, 2)}\n`);
    fs.writeFileSync(candidatePath, forgedCandidateBytes);

    const evidencePath = path.join(forgedBundle, "evidence.json");
    const forgedEvidence = JSON.parse(fs.readFileSync(evidencePath, "utf8"));
    forgedEvidence.candidate.receiptFingerprint = forgedCandidate.fingerprint;
    forgedEvidence.candidate.receiptSha256 = crypto.createHash("sha256")
      .update(forgedCandidateBytes)
      .digest("hex");
    forgedEvidence.bundle.candidateReceiptFingerprint = forgedCandidate.fingerprint;
    const candidateFile = forgedEvidence.bundle.files.find(
      entry => entry.name === "ui-candidate.json",
    );
    candidateFile.bytes = forgedCandidateBytes.length;
    candidateFile.sha256 = forgedEvidence.candidate.receiptSha256;
    const evidenceUnsigned = { ...forgedEvidence };
    delete evidenceUnsigned.fingerprint;
    forgedEvidence.fingerprint = fingerprint(evidenceUnsigned);
    const forgedEvidenceBytes = Buffer.from(`${JSON.stringify(forgedEvidence, null, 2)}\n`);
    assert.strictEqual(forgedEvidenceBytes.length, forgedEvidence.bundle.receipt.bytes);
    fs.writeFileSync(evidencePath, forgedEvidenceBytes);
    if (process.platform !== "win32") {
      for (const name of SIGNED_OUT_BUNDLE_NAMES) {
        fs.chmodSync(path.join(forgedBundle, name), 0o400);
      }
      fs.chmodSync(forgedBundle, 0o500);
    }
    assert.throws(() => verifyDetachedSignedOutUiBundle({
      bundleRoot: forgedBundle,
      contractRoot: scratch,
      expectedSourceSha: fixture.source.sha,
    }), /toolchain provenance is stale or mismatched/u);

    for (const mutation of ["add", "change", "delete", "different", "same"]) {
      const parent = fs.realpathSync(fs.mkdtempSync(path.join(scratch, `verify-${mutation}-`)));
      const bundle = path.join(parent, "bundle");
      fs.cpSync(stage, bundle, { recursive: true });
      if (process.platform !== "win32") {
        for (const name of SIGNED_OUT_BUNDLE_NAMES) fs.chmodSync(path.join(bundle, name), 0o400);
        fs.chmodSync(bundle, 0o500);
      }
      assert.throws(() => verifyDetachedSignedOutUiBundle({
        bundleRoot: bundle,
        contractRoot: scratch,
        expectedSourceSha: fixture.source.sha,
        afterCapture(target) {
          if (process.platform !== "win32") fs.chmodSync(target, 0o700);
          const resultPath = path.join(target, "result.json");
          if (mutation === "add") {
            fs.writeFileSync(path.join(target, "unexpected.json"), "{}\n");
          } else if (mutation === "change") {
            fs.chmodSync(resultPath, 0o600);
            fs.writeFileSync(resultPath, "changed detached bytes\n");
          } else if (mutation === "delete") {
            fs.unlinkSync(resultPath);
          } else {
            const replacement = path.join(target, "replacement.json");
            fs.writeFileSync(
              replacement,
              mutation === "same" ? fixture.uiBytes : "different detached bytes\n",
              { mode: 0o400 },
            );
            fs.renameSync(replacement, resultPath);
          }
          if (process.platform !== "win32") fs.chmodSync(target, 0o500);
        },
      }), /detached signed-out UI bundle/iu, mutation);
    }
    for (const name of SIGNED_OUT_BUNDLE_NAMES) {
      const parent = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "verify-digest-")));
      const bundle = path.join(parent, "bundle");
      fs.cpSync(stage, bundle, { recursive: true });
      if (process.platform !== "win32") {
        fs.chmodSync(bundle, 0o700);
        fs.chmodSync(path.join(bundle, name), 0o600);
      }
      const changed = fs.readFileSync(path.join(bundle, name));
      changed[0] ^= 0x01;
      fs.writeFileSync(path.join(bundle, name), changed);
      changed.fill(0);
      if (process.platform !== "win32") {
        fs.chmodSync(path.join(bundle, name), 0o400);
        fs.chmodSync(bundle, 0o500);
      }
      assert.throws(() => verifyDetachedSignedOutUiBundle({
        bundleRoot: bundle,
        contractRoot: scratch,
        expectedSourceSha: fixture.source.sha,
      }), /detached signed-out UI/iu, name);
    }
    for (const unsafe of ["symlink", "hard-link"]) {
      const parent = fs.realpathSync(fs.mkdtempSync(path.join(scratch, `verify-${unsafe}-`)));
      const bundle = path.join(parent, "bundle");
      fs.cpSync(stage, bundle, { recursive: true });
      if (process.platform !== "win32") fs.chmodSync(bundle, 0o700);
      const target = path.join(bundle, "result.json");
      fs.unlinkSync(target);
      if (unsafe === "symlink") {
        fs.symlinkSync(fixture.uiPath, target);
      } else {
        const alias = path.join(parent, "result-alias.json");
        fs.writeFileSync(alias, fixture.uiBytes, { mode: 0o400 });
        fs.linkSync(alias, target);
      }
      if (process.platform !== "win32") fs.chmodSync(bundle, 0o500);
      assert.throws(() => verifyDetachedSignedOutUiBundle({
        bundleRoot: bundle,
        contractRoot: scratch,
        expectedSourceSha: fixture.source.sha,
      }), /detached signed-out UI bundle inventory/iu, unsafe);
    }
    assert.throws(() => verifyDetachedSignedOutUiBundle({
      bundleRoot: stage,
      contractRoot: scratch,
      expectedSourceSha: "f".repeat(40),
    }), /bundle receipt binding|not passed/iu);
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
      reviewedFixtureFindingCount: 2,
      reviewedFixturePolicyId: "qh-synthetic-cloudsmith-api-key-v2",
    }], new Date("2026-08-27T00:00:00.000Z"));
    assert.strictEqual(document.status, "failed");
    assert.strictEqual(document.findingCount, 1);
    assert.strictEqual(document.scanner.version, GITLEAKS_VERSION);
    assert.strictEqual(document.components[0].reviewedFixtureFindingCount, 2);
    assert.strictEqual(
      document.components[0].reviewedFixturePolicyId,
      "qh-synthetic-cloudsmith-api-key-v2",
    );
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
      attestationPath: LIVE_ATTESTATION,
      attestationSha256: "f".repeat(64),
      generatedEvidence: syntheticGeneratedEvidence(8),
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
      { generatedEvidence: syntheticGeneratedEvidence(7) },
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
      generatedEvidence: syntheticGeneratedEvidence(8),
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
      scanVsix: fixture.scanCandidate,
      scanAcceptedEvidence: fixture.scanAcceptedEvidence,
      now: new Date("2026-08-27T12:05:00.000Z"),
    });
    const expectedProof = {
      source: fixture.source,
      candidateReceiptFingerprint: fixture.candidateReceipt.fingerprint,
      vsixSha256: fixture.candidateReceipt.artifact.sha256,
      uiResultSha256: crypto.createHash("sha256").update(fixture.uiBytes).digest("hex"),
      attestationPath: LIVE_ATTESTATION,
      attestationSha256: crypto.createHash("sha256")
        .update(fixture.attestationBytes)
        .digest("hex"),
      evidenceManifest: fixture.attestation.evidence,
    };
    assert.strictEqual(validateReleaseExposureProof(result, expectedProof), true);
    assert.strictEqual(validateGeneratedEvidenceAcceptance(scratch, result.generatedEvidence), true);
    assert.deepStrictEqual(
      result.generatedEvidence.boundary.excludedFiles,
      [...GENERATED_EVIDENCE_EXCLUDED_FILES],
    );
    assert.deepStrictEqual(
      result.generatedEvidence.boundary.excludedPrefixes,
      [...GENERATED_EVIDENCE_EXCLUDED_PREFIXES],
    );
  });

  test("failed release exposure omits generated file digests", async () => {
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
      scanGeneratedEvidence(scanRoot) {
        return {
          ...fixture.scanGeneratedEvidence(scanRoot),
          findings: [{
            ruleId: "synthetic-rule",
            path: fixture.generatedEvidencePath,
            startLine: 1,
            endLine: 1,
          }],
        };
      },
      scanVsix: fixture.scanCandidate,
      scanAcceptedEvidence: fixture.scanAcceptedEvidence,
      now: new Date("2026-08-27T12:06:00.000Z"),
    });
    assert.strictEqual(result.status, "failed");
    assert.strictEqual(result.findingCount, 1);
    assert.strictEqual(result.generatedEvidence, null);
    assert.deepStrictEqual(result.candidate, {
      candidateReceiptFingerprint: null,
      uiResultSha256: null,
      vsixSha256: null,
    });
    assert.deepStrictEqual(result.attestation, {
      path: LIVE_ATTESTATION,
      sha256: null,
    });
    assert.deepStrictEqual(result.evidence, []);
    assert.strictEqual(Object.hasOwn(result.components[0], "snapshotManifest"), false);
  });

  test("bounded release receipt loader rejects growth without reading appended bytes", () => {
    const target = path.join(scratch, ...UI_CANDIDATE_RECEIPT.split("/"));
    const originalBytes = Buffer.from("{\"status\":\"synthetic\"}\n");
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, originalBytes);
    const fileSystem = Object.create(fs);
    let grew = false;
    let requestedBytes = 0;
    fileSystem.readSync = (...arguments_) => {
      requestedBytes += arguments_[3];
      const bytesRead = fs.readSync(...arguments_);
      if (!grew) {
        grew = true;
        fs.appendFileSync(target, Buffer.alloc(4096, 0x78));
      }
      return bytesRead;
    };

    assert.throws(
      () => readBoundedJson(
        UI_CANDIDATE_RECEIPT,
        scratch,
        ".quality/qualification",
        { fileSystem },
      ),
      /remain an exact bounded single-link file/u,
    );
    assert.strictEqual(grew, true);
    assert.strictEqual(requestedBytes, originalBytes.length);
  });

  test("bounded release UI loader rejects a final-path replacement after descriptor open", () => {
    const relativePath = ".quality/ui/result.json";
    const target = path.join(scratch, ...relativePath.split("/"));
    const displaced = path.join(scratch, ".quality", "ui", "displaced-result.json");
    const replacement = path.join(scratch, ".quality", "ui", "replacement-result.json");
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, "{\"status\":\"synthetic\"}\n");
    fs.writeFileSync(replacement, "{\"status\":\"replacement\"}\n");
    const fileSystem = Object.create(fs);
    let replaced = false;
    let descriptorReads = 0;
    fileSystem.openSync = (file, flags, mode) => {
      const descriptor = fs.openSync(file, flags, mode);
      if (file === target && !replaced) {
        replaced = true;
        fs.renameSync(target, displaced);
        fs.renameSync(replacement, target);
      }
      return descriptor;
    };
    fileSystem.readSync = (...arguments_) => {
      descriptorReads += 1;
      return fs.readSync(...arguments_);
    };

    assert.throws(
      () => readBoundedJson(relativePath, scratch, ".quality/ui", { fileSystem }),
      /remain an exact bounded single-link file/u,
    );
    assert.strictEqual(replaced, true);
    assert.strictEqual(descriptorReads, 0);
  });

  test("bounded release attestation loader rejects an ancestor replacement", () => {
    const relativePath = "internal_docs/quality/live-qualification.json";
    const qualityRoot = path.join(scratch, "internal_docs", "quality");
    const replacementRoot = path.join(scratch, "internal_docs", "replacement-quality");
    const displacedRoot = path.join(scratch, "internal_docs", "displaced-quality");
    const target = path.join(scratch, ...relativePath.split("/"));
    fs.mkdirSync(qualityRoot, { recursive: true });
    fs.mkdirSync(replacementRoot, { recursive: true });
    fs.writeFileSync(target, "{\"evidence\":[]}\n");
    fs.writeFileSync(
      path.join(replacementRoot, "live-qualification.json"),
      "{\"evidence\":[\"replacement\"]}\n",
    );
    const fileSystem = Object.create(fs);
    let replaced = false;
    let descriptorReads = 0;
    fileSystem.openSync = (file, flags, mode) => {
      const descriptor = fs.openSync(file, flags, mode);
      if (file === target && !replaced) {
        replaced = true;
        fs.renameSync(qualityRoot, displacedRoot);
        fs.renameSync(replacementRoot, qualityRoot);
      }
      return descriptor;
    };
    fileSystem.readSync = (...arguments_) => {
      descriptorReads += 1;
      return fs.readSync(...arguments_);
    };

    assert.throws(
      () => readBoundedJson(relativePath, scratch, "internal_docs/quality", { fileSystem }),
      /remain an exact bounded single-link file/u,
    );
    assert.strictEqual(replaced, true);
    assert.strictEqual(descriptorReads, 0);
  });

  test("bounded release JSON loader rejects same-byte replacement before parsing", () => {
    const relativePath = ".quality/ui/result.json";
    const target = path.join(scratch, ...relativePath.split("/"));
    const replacement = path.join(scratch, ".quality", "ui", "replacement-result.json");
    const originalBytes = Buffer.from("{\"status\":\"synthetic\"}\n");
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, originalBytes);
    fs.writeFileSync(replacement, originalBytes);
    const fileSystem = Object.create(fs);
    let replaced = false;
    let parseCalls = 0;
    fileSystem.readSync = (...arguments_) => {
      const bytesRead = fs.readSync(...arguments_);
      if (!replaced) {
        replaced = true;
        fs.renameSync(replacement, target);
      }
      return bytesRead;
    };
    const parseJson = JSON.parse;
    JSON.parse = (...arguments_) => {
      parseCalls += 1;
      return parseJson(...arguments_);
    };
    try {
      assert.throws(
        () => readBoundedJson(relativePath, scratch, ".quality/ui", { fileSystem }),
        /remain an exact bounded single-link file/u,
      );
    } finally {
      JSON.parse = parseJson;
    }
    assert.strictEqual(replaced, true);
    assert.strictEqual(parseCalls, 0);
  });

  test("release exposure scan rejects count-only generated and crossed VSIX proofs", async () => {
    const fixture = createReleaseExposureFixture(scratch);
    const base = {
      root: scratch,
      source: fixture.source,
      candidateReceipt: fixture.candidateReceipt,
      candidateArtifactPath: fixture.candidateArtifactPath,
      ui: fixture.ui,
      attestation: fixture.attestation,
      attestationBytes: fixture.attestationBytes,
      assertScannerVersion() {},
      scanAcceptedEvidence: fixture.scanAcceptedEvidence,
    };
    await assert.rejects(() => executeReleaseExposureScan({
      ...base,
      scanGeneratedEvidence(scanRoot) {
        return {
          id: RELEASE_COMPONENT_IDS[0],
          status: "scanned",
          fileCount: generatedEvidenceInventory(scanRoot).length,
          findings: [],
        };
      },
      scanVsix: fixture.scanCandidate,
    }), /exact snapshot manifest/iu);

    await assert.rejects(() => executeReleaseExposureScan({
      ...base,
      scanGeneratedEvidence: fixture.scanGeneratedEvidence,
      scanVsix: async (_root, relativePath) => ({
        ...(await fixture.scanCandidate(_root, relativePath)),
        snapshot: {
          ...(await fixture.scanCandidate(_root, relativePath)).snapshot,
          sha256: "9".repeat(64),
        },
      }),
    }), /accepted candidate snapshot/iu);
  });

  test("tracked scanner uses memory only and preserves file/deletion counts", () => {
    const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "tracked-memory-")));
    const relativePath = "tracked-proof.txt";
    const source = path.join(caseRoot, relativePath);
    const sourceBytes = Buffer.from("authorized tracked source bytes\n");
    fs.writeFileSync(source, sourceBytes);

    const originalCopyFileSync = fs.copyFileSync;
    const originalMkdirSync = fs.mkdirSync;
    const originalMkdtempSync = fs.mkdtempSync;
    const originalOpenSync = fs.openSync;
    const originalWriteFileSync = fs.writeFileSync;
    const originalWriteSync = fs.writeSync;
    let component;
    let observed;
    let openedSources = 0;
    let scannerBuffer;
    fs.copyFileSync = function rejectTrackedCopy() {
      assert.fail("Tracked-current must not create a copied destination.");
    };
    fs.mkdirSync = function rejectTrackedDirectory() {
      assert.fail("Tracked-current must not create a snapshot directory.");
    };
    fs.mkdtempSync = function rejectTrackedTemporaryRoot() {
      assert.fail("Tracked-current must not create a snapshot root.");
    };
    fs.openSync = function permitReadOnlySource(target, flags, ...arguments_) {
      assert.strictEqual(target, source);
      assert.strictEqual(
        flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT
          | fs.constants.O_EXCL | fs.constants.O_TRUNC | fs.constants.O_APPEND),
        0,
      );
      openedSources += 1;
      return originalOpenSync.call(fs, target, flags, ...arguments_);
    };
    fs.writeFileSync = function rejectTrackedWrite() {
      assert.fail("Tracked-current must not write captured bytes to disk.");
    };
    fs.writeSync = function rejectTrackedDescriptorWrite() {
      assert.fail("Tracked-current must not write through a descriptor.");
    };
    try {
      component = scanTracked(caseRoot, {
        files: Object.freeze([relativePath, "deleted-proof.txt"]),
        scanWithGitleaks(kind, logicalPath, options) {
          assert.strictEqual(kind, "stdin");
          assert.strictEqual(logicalPath, relativePath);
          assert.strictEqual(options.scanRoot, caseRoot);
          scannerBuffer = options.input;
          observed = Buffer.from(options.input);
          return [];
        },
      });
    } finally {
      fs.copyFileSync = originalCopyFileSync;
      fs.mkdirSync = originalMkdirSync;
      fs.mkdtempSync = originalMkdtempSync;
      fs.openSync = originalOpenSync;
      fs.writeFileSync = originalWriteFileSync;
      fs.writeSync = originalWriteSync;
    }

    assert.ok(openedSources >= 1);
    assert.deepStrictEqual(observed, sourceBytes);
    assert.ok(scannerBuffer.every(byte => byte === 0));
    assert.deepStrictEqual(component, {
      id: "tracked-current",
      status: "scanned",
      fileCount: 1,
      omittedDeletedFileCount: 1,
      findings: [],
    });
  });

  test("tracked scanner rejects added, removed, and renamed git inventory entries", () => {
    const mutations = [{
      name: "added",
      output: "tracked-proof.txt\0late-proof.txt\0",
      mutate(root) {
        fs.writeFileSync(path.join(root, "late-proof.txt"), "late tracked bytes\n");
      },
    }, {
      name: "removed",
      output: "",
      mutate(root) {
        fs.unlinkSync(path.join(root, "tracked-proof.txt"));
      },
    }, {
      name: "renamed",
      output: "renamed-proof.txt\0",
      mutate(root) {
        fs.renameSync(
          path.join(root, "tracked-proof.txt"),
          path.join(root, "renamed-proof.txt"),
        );
      },
    }];
    for (const mutation of mutations) {
      const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(
        scratch,
        `tracked-inventory-${mutation.name}-`,
      )));
      fs.writeFileSync(path.join(caseRoot, "tracked-proof.txt"), "tracked bytes\n");
      const descriptorBuffers = [];
      const fileSystem = Object.create(fs);
      fileSystem.readSync = function observeInventoryRead(
        descriptor,
        buffer,
        offset,
        length,
        position,
      ) {
        descriptorBuffers.push(buffer);
        return fs.readSync(descriptor, buffer, offset, length, position);
      };
      let inventoryCalls = 0;
      let scannerReached = false;
      assert.throws(() => scanTracked(caseRoot, {
        executeGit(executable, arguments_) {
          assert.strictEqual(executable, "git");
          assert.strictEqual(arguments_[0], "ls-files");
          inventoryCalls += 1;
          if (inventoryCalls === 2) mutation.mutate(caseRoot);
          return {
            error: null,
            signal: null,
            status: 0,
            stderr: "",
            stdout: inventoryCalls === 1
              ? "tracked-proof.txt\0"
              : mutation.output,
          };
        },
        fileSystem,
        scanWithGitleaks() {
          scannerReached = true;
          return [];
        },
      }), /Tracked-file source changed or became unsafe/u, mutation.name);
      assert.strictEqual(inventoryCalls, 2, mutation.name);
      assert.strictEqual(scannerReached, false, mutation.name);
      assert.ok(descriptorBuffers.length >= 1, mutation.name);
      assert.ok(
        descriptorBuffers.every(buffer => buffer.every(byte => byte === 0)),
        mutation.name,
      );
    }
  });

  test("tracked scanner never coerces a hostile final Git inventory result", () => {
    const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      scratch,
      "tracked-hostile-git-",
    )));
    const relativePath = "tracked-proof.txt";
    const latePath = path.join(caseRoot, "late-proof.txt");
    fs.writeFileSync(path.join(caseRoot, relativePath), "synthetic tracked bytes\n");
    let coercionCalls = 0;
    let inventoryCalls = 0;
    let scannerCalls = 0;
    assert.throws(() => scanTracked(caseRoot, {
      executeGit() {
        inventoryCalls += 1;
        const stdout = inventoryCalls === 3
          ? {
            toString() {
              coercionCalls += 1;
              fs.writeFileSync(latePath, "synthetic late bytes\n");
              return `${relativePath}\0`;
            },
          }
          : `${relativePath}\0`;
        return {
          error: null,
          signal: null,
          status: 0,
          stderr: "",
          stdout,
        };
      },
      scanWithGitleaks() {
        scannerCalls += 1;
        return [];
      },
    }), /Tracked-file source changed or became unsafe/u);
    assert.strictEqual(inventoryCalls, 3);
    assert.strictEqual(scannerCalls, 1);
    assert.strictEqual(coercionCalls, 0);
    assert.strictEqual(fs.existsSync(latePath), false);
  });

  test("a real late Git add after stale output is caught by the final inventory binding", () => {
    const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      scratch,
      "tracked-real-git-boundary-",
    )));
    const relativePath = "tracked-proof.txt";
    const lateRelativePath = "late-proof.txt";
    assert.strictEqual(spawnSync("git", ["init", "--quiet"], {
      cwd: caseRoot,
      stdio: "ignore",
    }).status, 0);
    fs.writeFileSync(path.join(caseRoot, relativePath), "synthetic tracked bytes\n");
    assert.strictEqual(spawnSync("git", ["add", "--", relativePath], {
      cwd: caseRoot,
      stdio: "ignore",
    }).status, 0);
    let inventoryCalls = 0;
    let scannerCalls = 0;
    assert.throws(() => scanTracked(caseRoot, {
      executeGit(executable, arguments_, options) {
        inventoryCalls += 1;
        const result = spawnSync(executable, arguments_, {
          ...options,
          encoding: "utf8",
          stdio: "pipe",
        });
        if (inventoryCalls === 3) {
          fs.writeFileSync(
            path.join(caseRoot, lateRelativePath),
            "synthetic late tracked bytes\n",
          );
          assert.strictEqual(spawnSync("git", ["add", "--", lateRelativePath], {
            cwd: caseRoot,
            env: options.env,
            stdio: "ignore",
          }).status, 0);
        }
        return result;
      },
      scanWithGitleaks() {
        scannerCalls += 1;
        return [];
      },
    }), /Tracked-file source changed or became unsafe/u);
    assert.strictEqual(inventoryCalls, 4);
    assert.strictEqual(scannerCalls, 1);
  });

  test("tracked findings are cloned into frozen exact value-blind metadata", () => {
    const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      scratch,
      "tracked-finding-normalization-",
    )));
    const relativePath = "tracked-proof.txt";
    fs.writeFileSync(path.join(caseRoot, relativePath), "synthetic tracked bytes\n");
    const suppliedFinding = {
      ruleId: "synthetic-rule",
      path: relativePath,
      startLine: 4,
      endLine: 4,
      commit: null,
    };
    const suppliedFindings = [suppliedFinding];
    const component = scanTracked(caseRoot, {
      files: Object.freeze([relativePath]),
      scanWithGitleaks() {
        return suppliedFindings;
      },
    });

    assert.notStrictEqual(component.findings, suppliedFindings);
    assert.notStrictEqual(component.findings[0], suppliedFinding);
    assert.strictEqual(Object.isFrozen(component.findings), true);
    assert.strictEqual(Object.isFrozen(component.findings[0]), true);
    assert.deepStrictEqual(component.findings, [suppliedFinding]);
  });

  test("tracked finding normalization rejects iterator, accessor, symbol, and prototype traps", () => {
    const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      scratch,
      "tracked-finding-traps-",
    )));
    const relativePath = "tracked-proof.txt";
    fs.writeFileSync(path.join(caseRoot, relativePath), "synthetic tracked bytes\n");
    const safeFinding = {
      ruleId: "synthetic-rule",
      path: relativePath,
      startLine: 1,
      endLine: 1,
      commit: null,
    };
    let accessorCalls = 0;
    let iteratorCalls = 0;
    const customIterator = [safeFinding];
    Object.defineProperty(customIterator, Symbol.iterator, {
      configurable: true,
      enumerable: false,
      value() {
        iteratorCalls += 1;
        return { next: () => ({ done: true }) };
      },
      writable: true,
    });
    const accessorArray = [];
    Object.defineProperty(accessorArray, "0", {
      configurable: true,
      enumerable: true,
      get() {
        accessorCalls += 1;
        return safeFinding;
      },
    });
    const customArrayPrototype = [safeFinding];
    Object.setPrototypeOf(customArrayPrototype, Object.create(Array.prototype));
    const accessorFinding = {
      ruleId: "synthetic-rule",
      startLine: 1,
      endLine: 1,
      commit: null,
    };
    Object.defineProperty(accessorFinding, "path", {
      configurable: true,
      enumerable: true,
      get() {
        accessorCalls += 1;
        return relativePath;
      },
    });
    const symbolFinding = { ...safeFinding };
    symbolFinding[Symbol("synthetic-finding")] = "synthetic-extra";
    const customFindingPrototype = { ...safeFinding };
    Object.setPrototypeOf(customFindingPrototype, Object.create(Object.prototype));
    const invalid = [
      customIterator,
      accessorArray,
      customArrayPrototype,
      new Proxy([safeFinding], {}),
      [accessorFinding],
      [symbolFinding],
      [customFindingPrototype],
      [new Proxy({ ...safeFinding }, {})],
    ];
    for (let index = 0; index < invalid.length; index += 1) {
      assert.throws(() => scanTracked(caseRoot, {
        files: Object.freeze([relativePath]),
        scanWithGitleaks() {
          return invalid[index];
        },
      }), /must return exact value-blind findings/u);
    }
    assert.strictEqual(accessorCalls, 0);
    assert.strictEqual(iteratorCalls, 0);
  });

  test("tracked buffers use intrinsic-safe wiping after scanner success and failure", () => {
    for (const outcome of ["success", "failure"]) {
      const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(
        scratch,
        `tracked-intrinsic-wipe-${outcome}-`,
      )));
      const relativePath = "tracked-proof.txt";
      fs.writeFileSync(path.join(caseRoot, relativePath), "synthetic tracked bytes\n");
      const descriptorBuffers = [];
      const fileSystem = Object.create(fs);
      fileSystem.readSync = function observeTrackedBuffer(
        descriptor,
        buffer,
        offset,
        length,
        position,
      ) {
        descriptorBuffers.push(buffer);
        return fs.readSync(descriptor, buffer, offset, length, position);
      };
      const bufferFill = Object.getOwnPropertyDescriptor(Buffer.prototype, "fill");
      const bufferFrom = Object.getOwnPropertyDescriptor(Buffer, "from");
      const bufferIsBuffer = Object.getOwnPropertyDescriptor(Buffer, "isBuffer");
      const uint8Fill = Object.getOwnPropertyDescriptor(Uint8Array.prototype, "fill");
      let component;
      let scannerBuffer;
      let thrown;
      try {
        component = scanTracked(caseRoot, {
          files: Object.freeze([relativePath]),
          fileSystem,
          scanWithGitleaks(_kind, _logicalPath, options) {
            scannerBuffer = options.input;
            Buffer.prototype.fill = function rejectDynamicBufferFill() {
              throw new Error("dynamic Buffer fill must not run");
            };
            Buffer.from = function rejectDynamicBufferCopy() {
              throw new Error("dynamic Buffer copy must not run");
            };
            Buffer.isBuffer = function rejectDynamicBufferCheck() {
              return false;
            };
            Uint8Array.prototype.fill = function rejectDynamicTypedArrayFill() {
              throw new Error("dynamic typed-array fill must not run");
            };
            if (outcome === "failure") throw new Error("synthetic scanner failure");
            return [];
          },
        });
      } catch (error) {
        thrown = error;
      } finally {
        Object.defineProperty(Buffer.prototype, "fill", bufferFill);
        Object.defineProperty(Buffer, "from", bufferFrom);
        Object.defineProperty(Buffer, "isBuffer", bufferIsBuffer);
        if (uint8Fill) Object.defineProperty(Uint8Array.prototype, "fill", uint8Fill);
        else delete Uint8Array.prototype.fill;
      }
      if (outcome === "success") {
        assert.strictEqual(thrown, undefined);
        assert.strictEqual(component.status, "scanned");
      } else {
        assert.match(thrown.message, /scanner failed closed on exact captured bytes/u);
      }
      assert.ok(Buffer.isBuffer(scannerBuffer));
      assert.ok(scannerBuffer.every(byte => byte === 0));
      assert.ok(descriptorBuffers.length >= 1);
      assert.ok(descriptorBuffers.every(buffer => buffer.every(byte => byte === 0)));
    }
  });

  test("tracked scanner consumes captured bytes then rejects a source path swap", () => {
    const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "tracked-swap-")));
    const relativePath = "tracked-proof.txt";
    const source = path.join(caseRoot, relativePath);
    const displaced = path.join(caseRoot, "tracked-proof-original.txt");
    const replacement = path.join(caseRoot, "tracked-proof-replacement.txt");
    const originalBytes = Buffer.from("authorized tracked bytes\n");
    const replacementBytes = Buffer.from("unauthorized tracked replacement\n");
    fs.writeFileSync(source, originalBytes);
    fs.writeFileSync(replacement, replacementBytes);
    const fileSystem = Object.create(fs);
    const descriptorBuffers = [];
    fileSystem.readSync = function observeTrackedRead(
      descriptor,
      buffer,
      offset,
      length,
      position,
    ) {
      descriptorBuffers.push(buffer);
      return fs.readSync(descriptor, buffer, offset, length, position);
    };
    let observed;
    let scannerBuffer;
    let swapped = false;
    try {
      assert.throws(() => scanTracked(caseRoot, {
        files: Object.freeze([relativePath]),
        fileSystem,
        scanWithGitleaks(kind, logicalPath, options) {
          assert.strictEqual(kind, "stdin");
          assert.strictEqual(logicalPath, relativePath);
          assert.strictEqual(options.scanRoot, caseRoot);
          fs.renameSync(source, displaced);
          fs.renameSync(replacement, source);
          swapped = true;
          scannerBuffer = options.input;
          observed = Buffer.from(options.input);
          return [];
        },
      }), /Tracked-file source changed or became unsafe/u);
    } finally {
      if (swapped) {
        fs.unlinkSync(source);
        fs.renameSync(displaced, source);
      }
    }
    assert.strictEqual(swapped, true);
    assert.deepStrictEqual(observed, originalBytes);
    assert.ok(scannerBuffer.every(byte => byte === 0));
    assert.ok(descriptorBuffers.length >= 1);
    assert.ok(descriptorBuffers.every(buffer => buffer.every(byte => byte === 0)));
  });

  test("tracked scanner rejects source growth after scanning only captured bytes", () => {
    const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "tracked-source-growth-")));
    const relativePath = "tracked-proof.txt";
    const originalBytes = Buffer.from("authorized tracked source bytes\n");
    const source = path.join(caseRoot, relativePath);
    fs.writeFileSync(source, originalBytes);
    let observed;
    let scannerBuffer;
    let scannerReached = false;
    assert.throws(() => scanTracked(caseRoot, {
      files: Object.freeze([relativePath]),
      scanWithGitleaks(kind, logicalPath, options) {
        scannerReached = true;
        assert.strictEqual(kind, "stdin");
        assert.strictEqual(logicalPath, relativePath);
        assert.strictEqual(options.scanRoot, caseRoot);
        scannerBuffer = options.input;
        observed = Buffer.from(options.input);
        fs.appendFileSync(source, "post-capture growth\n");
        return [];
      },
    }), /Tracked-file source changed or became unsafe/u);
    assert.strictEqual(scannerReached, true);
    assert.deepStrictEqual(observed, originalBytes);
    assert.ok(scannerBuffer.every(byte => byte === 0));
  });

  test("generated scanner never follows a swapped-and-restored snapshot pathname", () => {
    const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "generated-swap-")));
    const relativePath = ".quality/qualification/proof.json";
    const originalBytes = Buffer.from("authorized generated bytes\n");
    const replacementBytes = Buffer.from("unauthorized generated replacement\n");
    const source = path.join(caseRoot, ...relativePath.split("/"));
    fs.mkdirSync(path.dirname(source), { recursive: true });
    fs.writeFileSync(source, originalBytes);
    let observed;
    const component = scanGeneratedEvidence(caseRoot, ".quality", {
      scanWithGitleaks(kind, logicalPath, options) {
        assert.strictEqual(kind, "stdin");
        assert.strictEqual(logicalPath, relativePath);
        const scanRoot = options.scanRoot;
        const displaced = `${scanRoot}-displaced`;
        fs.renameSync(scanRoot, displaced);
        try {
          fs.mkdirSync(path.dirname(path.join(scanRoot, ...relativePath.split("/"))), {
            recursive: true,
          });
          fs.writeFileSync(
            path.join(scanRoot, ...relativePath.split("/")),
            replacementBytes,
          );
          assert.deepStrictEqual(
            fs.readFileSync(path.join(scanRoot, ...relativePath.split("/"))),
            replacementBytes,
          );
          observed = Buffer.from(options.input);
        } finally {
          fs.rmSync(scanRoot, { recursive: true, force: true });
          fs.renameSync(displaced, scanRoot);
        }
        return [];
      },
    });

    assert.deepStrictEqual(observed, originalBytes);
    assert.strictEqual(component.status, "scanned");
    assert.deepStrictEqual(component.findings, []);
  });

  test("generated scanner persists the exact descriptor snapshot manifest it inspected", () => {
    const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "generated-snapshot-")));
    const relativePath = ".quality/qualification/proof.json";
    const target = path.join(caseRoot, ...relativePath.split("/"));
    const originalBytes = Buffer.from("authorized synthetic proof\n");
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, originalBytes);
    const originalIdentity = exactFileIdentity(fs.lstatSync(target, { bigint: true }));
    let inspectedBytes;
    let inspectedRoot;
    const component = scanGeneratedEvidence(caseRoot, ".quality", {
      scanWithGitleaks(kind, logicalPath, options) {
        assert.strictEqual(kind, "stdin");
        assert.strictEqual(logicalPath, relativePath);
        inspectedRoot = options.scanRoot;
        inspectedBytes = Buffer.from(options.input);
        fs.writeFileSync(target, "later live bytes\n");
        return [];
      },
    });

    assert.deepStrictEqual(inspectedBytes, originalBytes);
    assert.strictEqual(fs.existsSync(inspectedRoot), false);
    assert.deepStrictEqual(component.snapshotManifest, [{
      path: relativePath,
      identity: originalIdentity,
      sha256: crypto.createHash("sha256").update(originalBytes).digest("hex"),
    }]);
  });

  test("generated VSIX evidence uses descriptor transport while adjacent text uses stdin", () => {
    const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "generated-vsix-")));
    const archivePath = ".quality/qualification/live-candidate.vsix";
    const textPath = ".quality/qualification/proof.json";
    const archiveBytes = Buffer.alloc(1_067_417, 0x5a);
    const textBytes = Buffer.from("{\"status\":\"synthetic\"}\n");
    fs.mkdirSync(path.join(caseRoot, ".quality", "qualification"), { recursive: true });
    fs.writeFileSync(path.join(caseRoot, ...archivePath.split("/")), archiveBytes);
    fs.writeFileSync(path.join(caseRoot, ...textPath.split("/")), textBytes);

    const transports = [];
    const component = scanGeneratedEvidence(caseRoot, ".quality", {
      scanWithGitleaks(kind, logicalPath, options) {
        if (kind === "stdin") {
          transports.push({ kind, path: logicalPath });
          assert.strictEqual(logicalPath, textPath);
          assert.deepStrictEqual(options.input, textBytes);
          return [];
        }
        assert.strictEqual(kind, "dir");
        assert.strictEqual(options.input, undefined);
        transports.push({ kind, path: archivePath });
        const scannedBytes = Number.isSafeInteger(options.extraFileDescriptor)
          ? fs.readFileSync(options.extraFileDescriptor)
          : fs.readFileSync(logicalPath);
        assert.deepStrictEqual(scannedBytes, archiveBytes);
        return [{
          commit: null,
          ruleId: "synthetic-descriptor-rule",
          path: Number.isSafeInteger(options.extraFileDescriptor)
            ? path.basename(logicalPath)
            : archivePath,
          startLine: 1,
          endLine: 1,
        }];
      },
    });

    assert.deepStrictEqual(transports, [
      { kind: "dir", path: archivePath },
      { kind: "stdin", path: textPath },
    ]);
    assert.deepStrictEqual(component.findings, [{
      commit: null,
      ruleId: "synthetic-descriptor-rule",
      path: archivePath,
      startLine: 1,
      endLine: 1,
    }]);
    assert.deepStrictEqual(
      component.snapshotManifest.map(entry => entry.path),
      [archivePath, textPath],
    );
  });

  test("generated VSIX descriptor transport rejects async output and path replacement", () => {
    for (const mutation of ["async-output", "path-replacement"]) {
      const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(
        scratch,
        `generated-vsix-${mutation}-`,
      )));
      const archivePath = ".quality/qualification/live-candidate.vsix";
      const target = path.join(caseRoot, ...archivePath.split("/"));
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, Buffer.alloc(128, 0x5a));

      assert.throws(() => scanGeneratedEvidence(caseRoot, ".quality", {
        scanWithGitleaks(kind, _logicalPath, options) {
          assert.strictEqual(kind, "dir");
          if (mutation === "async-output") return Promise.resolve([]);
          fs.renameSync(options.descriptorSourcePath, `${options.descriptorSourcePath}.original`);
          fs.writeFileSync(options.descriptorSourcePath, Buffer.alloc(128, 0x59));
          return [];
        },
      }), /must complete synchronously on exact snapshot bytes/u, mutation);
    }
  });

  test("VSIX raw and expanded scans use one private snapshot and report its exact digest", async () => {
    const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "vsix-snapshot-")));
    const relativePath = ".quality/qualification/ui-candidate.vsix";
    const target = path.join(caseRoot, ...relativePath.split("/"));
    fs.mkdirSync(path.dirname(target), { recursive: true });
    await writeZip(target, [["extension/safe.txt", "authorized archive bytes\n"]]);
    const candidateBytes = fs.readFileSync(target);
    const sourceIdentity = exactFileIdentity(fs.lstatSync(target, { bigint: true }));
    const scannedTargets = [];
    const component = await scanVsix(caseRoot, relativePath, {
      scanWithGitleaks(kind, logicalPath, options) {
        if (kind === "dir") {
          scannedTargets.push("candidate.vsix");
          if (Number.isSafeInteger(options.extraFileDescriptor)) {
            assert.match(logicalPath, /(?:\/dev\/fd|\/proc\/self\/fd)\/3$/u);
            assert.deepStrictEqual(fs.readFileSync(options.extraFileDescriptor), candidateBytes);
          } else {
            assert.strictEqual(process.platform, "win32");
            assert.deepStrictEqual(fs.readFileSync(logicalPath), candidateBytes);
          }
          return [{
            commit: null,
            ruleId: "synthetic-descriptor-rule",
            path: Number.isSafeInteger(options.extraFileDescriptor)
              ? path.basename(logicalPath)
              : "candidate.vsix",
            startLine: 1,
            endLine: 1,
          }];
        } else {
          assert.strictEqual(kind, "stdin");
          scannedTargets.push(logicalPath);
          assert.strictEqual(logicalPath, "extension/safe.txt");
          assert.deepStrictEqual(options.input, Buffer.from("authorized archive bytes\n"));
          return [];
        }
      },
    });

    assert.deepStrictEqual(scannedTargets, ["candidate.vsix", "extension/safe.txt"]);
    assert.deepStrictEqual(component.snapshot, {
      path: relativePath,
      identity: sourceIdentity,
      sha256: crypto.createHash("sha256").update(candidateBytes).digest("hex"),
    });
    assert.deepStrictEqual(component.findings, [{
      commit: null,
      ruleId: "synthetic-descriptor-rule",
      path: `${relativePath}::archive/candidate.vsix`,
      startLine: 1,
      endLine: 1,
    }]);
  });

  test("raw and expanded VSIX scans never follow swapped-and-restored snapshot paths", async () => {
    const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "vsix-swap-")));
    const relativePath = ".quality/qualification/ui-candidate.vsix";
    const target = path.join(caseRoot, ...relativePath.split("/"));
    const expandedBytes = Buffer.from("authorized expanded bytes\n");
    const rawReplacement = Buffer.from("unauthorized raw replacement\n");
    const expandedReplacement = Buffer.from("unauthorized expanded replacement\n");
    fs.mkdirSync(path.dirname(target), { recursive: true });
    await writeZip(target, [["extension/safe.txt", expandedBytes]]);
    const candidateBytes = fs.readFileSync(target);
    const observed = [];

    const component = await scanVsix(caseRoot, relativePath, {
      scanWithGitleaks(kind, logicalPath, options) {
        const raw = kind === "dir";
        if (!raw) assert.strictEqual(kind, "stdin");
        const descriptor = options.extraFileDescriptor;
        const scanRoot = raw && Number.isSafeInteger(descriptor)
          ? path.dirname(options.descriptorSourcePath)
          : raw
            ? path.dirname(logicalPath)
          : options.scanRoot;
        const windowsRawBytes = raw && !Number.isSafeInteger(descriptor)
          ? fs.readFileSync(logicalPath)
          : null;
        const displaced = `${scanRoot}-displaced`;
        const observedPath = raw ? "candidate.vsix" : logicalPath;
        const replacementBytes = raw
          ? rawReplacement
          : expandedReplacement;
        fs.renameSync(scanRoot, displaced);
        try {
          const replacementTarget = path.join(scanRoot, ...observedPath.split("/"));
          fs.mkdirSync(path.dirname(replacementTarget), { recursive: true });
          fs.writeFileSync(replacementTarget, replacementBytes);
          assert.deepStrictEqual(fs.readFileSync(replacementTarget), replacementBytes);
          observed.push({
            logicalPath: observedPath,
            bytes: raw && Number.isSafeInteger(descriptor)
              ? fs.readFileSync(descriptor)
              : raw ? windowsRawBytes : Buffer.from(options.input),
          });
        } finally {
          fs.rmSync(scanRoot, { recursive: true, force: true });
          fs.renameSync(displaced, scanRoot);
        }
        return [];
      },
    });

    assert.deepStrictEqual(observed, [
      { logicalPath: "candidate.vsix", bytes: candidateBytes },
      { logicalPath: "extension/safe.txt", bytes: expandedBytes },
    ]);
    assert.strictEqual(component.status, "scanned");
    assert.deepStrictEqual(component.findings, []);
  });

  test("live VSIX ancestor replacement cannot redirect raw or expanded snapshot reads", async () => {
    const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "vsix-ancestor-swap-")));
    const relativePath = ".quality/qualification/ui-candidate.vsix";
    const qualification = path.join(caseRoot, ".quality", "qualification");
    const replacement = path.join(caseRoot, ".quality", "replacement-qualification");
    const displaced = path.join(caseRoot, ".quality", "displaced-qualification");
    fs.mkdirSync(qualification, { recursive: true });
    fs.mkdirSync(replacement, { recursive: true });
    await writeZip(path.join(qualification, "ui-candidate.vsix"), [[
      "extension/safe.txt",
      "authorized archive bytes\n",
    ]]);
    await writeZip(path.join(replacement, "ui-candidate.vsix"), [[
      "extension/safe.txt",
      "unauthorized replacement bytes\n",
    ]]);
    let scanNumber = 0;
    await assert.rejects(() => scanVsix(caseRoot, relativePath, {
      scanWithGitleaks(_kind, logicalPath, options) {
        scanNumber += 1;
        if (scanNumber === 1) {
          if (Number.isSafeInteger(options.extraFileDescriptor)) {
            assert.match(logicalPath, /(?:\/dev\/fd|\/proc\/self\/fd)\/3$/u);
          } else {
            assert.strictEqual(process.platform, "win32");
          }
          fs.renameSync(qualification, displaced);
          fs.renameSync(replacement, qualification);
        } else {
          assert.strictEqual(logicalPath, "extension/safe.txt");
          assert.deepStrictEqual(options.input, Buffer.from("authorized archive bytes\n"));
        }
        return [];
      },
    }), /source changed or became unsafe/u);
    assert.strictEqual(scanNumber, 2);
  });

  test("release exposure scan rejects add, change, delete, and identity-replacement races", async () => {
    const mutations = {
      add(fixture, root) {
        fs.writeFileSync(
          path.join(root, ".quality", "qualification", "late-generated-proof.json"),
          "late generated proof\n",
        );
      },
      change(fixture, root) {
        fs.writeFileSync(path.join(root, fixture.generatedEvidencePath), "changed proof bytes\n");
      },
      delete(fixture, root) {
        fs.rmSync(path.join(root, fixture.generatedEvidencePath));
      },
      replace(fixture, root) {
        const replacement = path.join(root, ".quality", "qualification", "replacement-proof.json");
        fs.writeFileSync(replacement, fixture.generatedEvidenceBytes);
        fs.renameSync(replacement, path.join(root, fixture.generatedEvidencePath));
      },
    };
    for (const [name, mutate] of Object.entries(mutations)) {
      const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, `${name}-`)));
      const fixture = createReleaseExposureFixture(caseRoot);
      await assert.rejects(() => executeReleaseExposureScan({
        root: caseRoot,
        source: fixture.source,
        candidateReceipt: fixture.candidateReceipt,
        candidateArtifactPath: fixture.candidateArtifactPath,
        ui: fixture.ui,
        attestation: fixture.attestation,
        attestationBytes: fixture.attestationBytes,
        assertScannerVersion() {},
        scanGeneratedEvidence(scanRoot) {
          const component = fixture.scanGeneratedEvidence(scanRoot);
          mutate(fixture, scanRoot);
          return component;
        },
        scanVsix: fixture.scanCandidate,
        scanAcceptedEvidence: fixture.scanAcceptedEvidence,
      }), /generated release evidence changed across the pre-acceptance boundary/iu, name);
    }
  });

  test("generated evidence acceptance rejects add, change, delete, and same-byte replacement", () => {
    const mutations = {
      add(fixture, root) {
        fs.writeFileSync(
          path.join(root, ".quality", "qualification", "late-generated-proof.json"),
          "late generated proof\n",
        );
      },
      change(fixture, root) {
        fs.writeFileSync(path.join(root, fixture.generatedEvidencePath), "changed proof bytes\n");
      },
      delete(fixture, root) {
        fs.rmSync(path.join(root, fixture.generatedEvidencePath));
      },
      replace(fixture, root) {
        const replacement = path.join(root, ".quality", "qualification", "replacement-proof.json");
        fs.writeFileSync(replacement, fixture.generatedEvidenceBytes);
        fs.renameSync(replacement, path.join(root, fixture.generatedEvidencePath));
      },
    };
    for (const [name, mutate] of Object.entries(mutations)) {
      const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, `${name}-`)));
      const fixture = createReleaseExposureFixture(caseRoot);
      const manifest = captureGeneratedEvidenceManifest(caseRoot);
      assert.strictEqual(validateGeneratedEvidenceAcceptance(caseRoot, manifest), true, name);
      mutate(fixture, caseRoot);
      assert.throws(
        () => validateGeneratedEvidenceAcceptance(caseRoot, manifest),
        /generated release evidence changed across the pre-acceptance boundary/iu,
        name,
      );
    }
  });

  test("generated evidence rejects a pre-existing external hard-link alias", () => {
    const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "hard-link-")));
    const proofDirectory = path.join(caseRoot, ".quality", "qualification");
    const proof = path.join(proofDirectory, "proof.json");
    const alias = path.join(caseRoot, "outside-alias.json");
    fs.mkdirSync(proofDirectory, { recursive: true });
    fs.writeFileSync(proof, "synthetic generated proof\n");
    fs.linkSync(proof, alias);

    assert.throws(
      () => generatedEvidenceInventory(caseRoot),
      /bounded single-link|exact real file/u,
    );
  });

  test("generated evidence path replacement reads and hashes no replacement bytes", () => {
    const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "path-swap-")));
    const proofDirectory = path.join(caseRoot, ".quality", "qualification");
    const proof = path.join(proofDirectory, "proof.json");
    const original = path.join(caseRoot, "original-proof.json");
    const replacement = path.join(caseRoot, "replacement-proof.json");
    fs.mkdirSync(proofDirectory, { recursive: true });
    fs.writeFileSync(proof, "authorized synthetic proof\n");
    fs.writeFileSync(replacement, "unauthorized synthetic replacement\n");
    let replaced = false;
    let descriptorReads = 0;
    let digests = 0;
    const fileSystem = Object.create(fs);
    fileSystem.openSync = (target, flags, mode) => {
      if (target === proof && !replaced) {
        replaced = true;
        fs.renameSync(proof, original);
        fs.renameSync(replacement, proof);
      }
      return fs.openSync(target, flags, mode);
    };
    fileSystem.readFileSync = (...arguments_) => {
      if (typeof arguments_[0] === "number") descriptorReads += 1;
      return fs.readFileSync(...arguments_);
    };

    assert.throws(
      () => captureGeneratedEvidenceManifest(caseRoot, null, {
        fileSystem,
        digestBytes() {
          digests += 1;
          return "a".repeat(64);
        },
      }),
      /changed while its manifest was captured/u,
    );
    assert.strictEqual(replaced, true);
    assert.strictEqual(descriptorReads, 0);
    assert.strictEqual(digests, 0);
  });

  test("generated evidence scanner snapshot does not read a path-swap replacement", () => {
    const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "scan-path-swap-")));
    const proofDirectory = path.join(caseRoot, ".quality", "qualification");
    const proof = path.join(proofDirectory, "proof.json");
    const original = path.join(caseRoot, "original-proof.json");
    const replacement = path.join(caseRoot, "replacement-proof.json");
    fs.mkdirSync(proofDirectory, { recursive: true });
    fs.writeFileSync(proof, "authorized synthetic proof\n");
    fs.writeFileSync(replacement, "unauthorized synthetic replacement\n");
    let replaced = false;
    let descriptorReads = 0;
    const fileSystem = Object.create(fs);
    fileSystem.openSync = (target, flags, mode) => {
      const descriptor = fs.openSync(target, flags, mode);
      if (target === proof && !replaced) {
        replaced = true;
        fs.renameSync(proof, original);
        fs.renameSync(replacement, proof);
      }
      return descriptor;
    };
    fileSystem.readFileSync = (...arguments_) => {
      if (typeof arguments_[0] === "number") descriptorReads += 1;
      return fs.readFileSync(...arguments_);
    };

    assert.throws(
      () => scanGeneratedEvidence(caseRoot, ".quality", { fileSystem }),
      /changed or became unsafe/u,
    );
    assert.strictEqual(replaced, true);
    assert.strictEqual(descriptorReads, 0);
  });

  test("planned canonical release outputs preserve the exact pre-acceptance proof", () => {
    const fixture = createReleaseExposureFixture(scratch);
    const releasePlan = writeReleaseProgressAtSecretScan(scratch, fixture.source);
    const stableReceiptPaths = RELEASE_GATE_EXPECTED_PATHS.filter(relativePath => (
      !RELEASE_GATE_CIRCULAR_PATHS.includes(relativePath)
    ));
    const manifest = captureGeneratedEvidenceManifest(scratch, null, {
      source: fixture.source,
    });

    assert.strictEqual(validateGeneratedEvidenceAcceptance(
      scratch,
      manifest,
      { source: fixture.source },
    ), true);
    assert.deepStrictEqual(
      releasePlan.slice(releasePlan.findIndex(step => step.id === "secret-release"))
        .map(step => step.id),
      ["secret-release", "release-checklist", "secret-history", "quality-report"],
    );
    assert.deepStrictEqual(
      GENERATED_EVIDENCE_CIRCULAR_OUTPUTS.map(output => output.path),
      [
        ...RELEASE_GATE_CIRCULAR_PATHS,
        ".quality/report.json",
        ".quality/report.md",
        ".quality/secrets/history.json",
        ".quality/secrets/release.json",
      ],
    );
    assert.deepStrictEqual(
      GENERATED_EVIDENCE_EXCLUDED_FILES,
      GENERATED_EVIDENCE_CIRCULAR_OUTPUTS.map(output => output.path).sort(),
    );
    assert.deepStrictEqual(GENERATED_EVIDENCE_EXCLUDED_PREFIXES, []);
    assert.ok(GENERATED_EVIDENCE_CIRCULAR_OUTPUTS.every(output => (
      /^[a-z][a-z-]+$/u.test(output.owner)
      && typeof output.justification === "string"
      && output.justification.length > 40
    )));
    assert.ok(manifest.files.some(entry => entry.path === fixture.generatedEvidencePath));
    assert.ok(stableReceiptPaths.every(relativePath => (
      manifest.files.some(entry => entry.path === relativePath)
    )));
    assert.ok(manifest.files.every(entry => (
      !GENERATED_EVIDENCE_EXCLUDED_FILES.some(excluded => (
        entry.path === excluded || entry.path.startsWith(`${excluded}/`)
      ))
    )));
  });

  test("permits only the exact in-flight release-checklist self-output proof", () => {
    const fixture = createReleaseExposureFixture(scratch);
    const releasePlan = writeReleaseProgressAtSecretScan(scratch, fixture.source);
    writePreservedFullGateFromRelease(scratch, fixture.source);
    const manifest = captureGeneratedEvidenceManifest(scratch, null, {
      source: fixture.source,
    });
    const secretReleaseStep = releasePlan.find(step => step.id === "secret-release");
    const secretReleaseReceiptPath = receiptPath({
      profile: "release",
      sequence: secretReleaseStep.sequence,
      stepId: secretReleaseStep.id,
    });
    const secretReleaseOutput = { status: "synthetic-safe-release-exposure" };
    writeJson(secretReleaseStep.artifactPath, secretReleaseOutput, scratch, {
      subtree: ".quality/secrets",
    });
    const secretReleaseReceipt = JSON.parse(fs.readFileSync(
      path.join(scratch, ...secretReleaseReceiptPath.split("/")),
      "utf8",
    ));
    writeJson(secretReleaseReceiptPath, {
      ...secretReleaseReceipt,
      status: "passed",
      exitCode: 0,
      reason: null,
      outputFingerprint: crypto.createHash("sha256").update("").digest("hex"),
      testEvidence: null,
      testEvidenceFingerprint: null,
      artifactFingerprint: artifactFingerprintForStep(secretReleaseStep, scratch),
    }, scratch, { subtree: ".quality/gates/release" });
    const checklistStep = releasePlan.find(step => step.id === "release-checklist");
    const checklistOutputPath = checklistStep.artifactPath;
    const checklistTarget = path.join(scratch, ...checklistOutputPath.split("/"));
    const checklistBytes = Buffer.from(`${JSON.stringify({ status: "partial" }, null, 2)}\n`);
    fs.writeFileSync(checklistTarget, checklistBytes);
    const checklistDigest = digestStableSingleLinkFile(checklistTarget, {
      maximumBytes: 1024 * 1024,
      minimumBytes: 1,
    });
    const proof = {
      stepId: checklistStep.id,
      path: checklistOutputPath,
      sha256: checklistDigest.sha256,
      identity: checklistDigest.identity,
    };

    assert.throws(
      () => validateGeneratedEvidenceAcceptance(scratch, manifest, {
        source: fixture.source,
      }),
      /generated release evidence changed across the pre-acceptance boundary/iu,
    );
    assert.strictEqual(validateGeneratedEvidenceAcceptance(scratch, manifest, {
      releaseChecklistOutputProof: proof,
      source: fixture.source,
    }), true);
    for (const invalidProof of [
      { ...proof, stepId: "secret-history" },
      { ...proof, path: ".quality/gates/not-the-checklist.json" },
      { ...proof, sha256: "0".repeat(64) },
      { ...proof, unexpected: true },
    ]) {
      assert.throws(
        () => validateGeneratedEvidenceAcceptance(scratch, manifest, {
          releaseChecklistOutputProof: invalidProof,
          source: fixture.source,
        }),
        /generated release evidence changed across the pre-acceptance boundary/iu,
      );
    }

    const historyStep = releasePlan.find(step => step.id === "secret-history");
    const historyReceiptPath = receiptPath({
      profile: "release",
      sequence: historyStep.sequence,
      stepId: historyStep.id,
    });
    const plannedHistoryReceipt = JSON.parse(fs.readFileSync(
      path.join(scratch, ...historyReceiptPath.split("/")),
      "utf8",
    ));
    const historyTarget = path.join(scratch, ...historyStep.artifactPath.split("/"));
    fs.writeFileSync(historyTarget, "synthetic history artifact\n");
    writeJson(historyReceiptPath, {
      ...plannedHistoryReceipt,
      status: "passed",
      exitCode: 0,
      reason: null,
      outputFingerprint: crypto.createHash("sha256").update("").digest("hex"),
      testEvidence: null,
      testEvidenceFingerprint: null,
      artifactFingerprint: artifactFingerprintForStep(historyStep, scratch),
    }, scratch, { subtree: ".quality/gates/release" });
    assert.throws(
      () => validateGeneratedEvidenceAcceptance(scratch, manifest, {
        releaseChecklistOutputProof: proof,
        source: fixture.source,
      }),
      /generated release evidence changed across the pre-acceptance boundary/iu,
    );
    writeJson(historyReceiptPath, plannedHistoryReceipt, scratch, {
      subtree: ".quality/gates/release",
    });
    fs.rmSync(historyTarget);

    const replacement = path.join(scratch, ".quality", "gates", "replacement.json");
    fs.writeFileSync(replacement, checklistBytes);
    fs.renameSync(replacement, checklistTarget);
    assert.throws(
      () => validateGeneratedEvidenceAcceptance(scratch, manifest, {
        releaseChecklistOutputProof: proof,
        source: fixture.source,
      }),
      /generated release evidence changed across the pre-acceptance boundary/iu,
    );

    const currentDigest = digestStableSingleLinkFile(checklistTarget, {
      maximumBytes: 1024 * 1024,
      minimumBytes: 1,
    });
    const checklistReceiptPath = receiptPath({
      profile: "release",
      sequence: checklistStep.sequence,
      stepId: checklistStep.id,
    });
    const checklistReceipt = JSON.parse(fs.readFileSync(
      path.join(scratch, ...checklistReceiptPath.split("/")),
      "utf8",
    ));
    writeJson(checklistReceiptPath, {
      ...checklistReceipt,
      status: "blocked",
      exitCode: 2,
      reason: null,
      outputFingerprint: crypto.createHash("sha256").update("").digest("hex"),
      testEvidence: null,
      testEvidenceFingerprint: null,
      artifactFingerprint: currentDigest.sha256,
    }, scratch, { subtree: ".quality/gates/release" });
    assert.throws(
      () => validateGeneratedEvidenceAcceptance(scratch, manifest, {
        releaseChecklistOutputProof: {
          ...proof,
          sha256: currentDigest.sha256,
          identity: currentDigest.identity,
        },
        source: fixture.source,
      }),
      /generated release evidence changed across the pre-acceptance boundary/iu,
    );
    assert.strictEqual(validateGeneratedEvidenceAcceptance(scratch, manifest, {
      source: fixture.source,
    }), true);
    fs.writeFileSync(checklistTarget, "changed checklist output\n");
    assert.throws(
      () => validateGeneratedEvidenceAcceptance(scratch, manifest, {
        source: fixture.source,
      }),
      /generated release evidence changed across the pre-acceptance boundary/iu,
    );
  });

  test("release progress rejects forged receipts without preserved fast or full trees", () => {
    const fixture = createReleaseExposureFixture(scratch);
    const releasePlan = writeReleaseProgressAtSecretScan(scratch, fixture.source);
    const first = releasePlan[0];
    const relativePath = receiptPath({
      profile: "release",
      sequence: first.sequence,
      stepId: first.id,
    });
    const target = path.join(scratch, ...relativePath.split("/"));
    const forged = JSON.parse(fs.readFileSync(target, "utf8"));
    forged.exitCode = 7;
    writeJson(relativePath, forged, scratch, { subtree: ".quality/gates/release" });

    assert.throws(
      () => generatedEvidenceInventory(scratch, { source: fixture.source }),
      /unexpected, stale, or unsafe entry/u,
    );
  });

  test("preserved mutation reruns may vary without relaxing current or stable artifact binding", () => {
    for (const testCase of [
      { stepId: "changed-mutation", accepted: true },
      { stepId: "change-impact", accepted: false },
    ]) {
      const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(
        scratch,
        `${testCase.stepId}-variant-`,
      )));
      const fixture = createReleaseExposureFixture(caseRoot);
      const releasePlan = writeReleaseProgressAtSecretScan(caseRoot, fixture.source);
      const preserved = writePreservedFullGateFromRelease(caseRoot, fixture.source);
      const step = releasePlan.find(item => item.id === testCase.stepId);
      const preservedReceipt = preserved.receipts.find(item => item.stepId === testCase.stepId);
      const artifactTarget = path.join(caseRoot, ...step.artifactPath.split("/"));
      fs.writeFileSync(
        artifactTarget,
        `synthetic ${testCase.stepId} artifact from a distinct owner-bound rerun\n`,
      );
      const releaseReceiptPath = receiptPath({
        profile: "release",
        sequence: step.sequence,
        stepId: step.id,
      });
      const releaseReceipt = JSON.parse(fs.readFileSync(
        path.join(caseRoot, ...releaseReceiptPath.split("/")),
        "utf8",
      ));
      releaseReceipt.artifactFingerprint = artifactFingerprintForStep(step, caseRoot);
      writeJson(releaseReceiptPath, releaseReceipt, caseRoot, {
        subtree: ".quality/gates/release",
      });
      assert.strictEqual(preservedReceipt.status, "passed");
      assert.strictEqual(releaseReceipt.status, "passed");
      assert.notStrictEqual(
        preservedReceipt.artifactFingerprint,
        releaseReceipt.artifactFingerprint,
      );

      if (testCase.accepted) {
        assert.strictEqual(assertExactReleaseGateTree(
          caseRoot,
          { source: fixture.source },
        ), true);
        fs.writeFileSync(artifactTarget, "synthetic post-receipt owner tamper\n");
      }
      assert.throws(
        () => assertExactReleaseGateTree(caseRoot, { source: fixture.source }),
        /unexpected, stale, or unsafe entry/u,
      );
    }
  });

  test("exact circular report outputs cannot hide rogue descendants", () => {
    for (const relativePath of [
      ".quality/report.json",
      ".quality/secrets/release.json",
    ]) {
      const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "circular-tree-")));
      createReleaseExposureFixture(caseRoot);
      const target = path.join(caseRoot, ...relativePath.split("/"));
      fs.mkdirSync(target, { recursive: true });
      fs.writeFileSync(path.join(target, "rogue-child.txt"), "unowned generated bytes\n");

      assert.throws(
        () => generatedEvidenceInventory(caseRoot),
        /exact bounded single-link file/u,
        relativePath,
      );
    }
  });

  test("generated release evidence rejects every orphaned or unowned gate-tree entry", () => {
    for (const relativePath of [
      ".quality/gates/fast.json",
      ".quality/gates/release/99-unowned.json",
      ".quality/gates/unowned-directory/proof.json",
    ]) {
      const caseRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "gate-tree-")));
      createReleaseExposureFixture(caseRoot);
      const target = path.join(caseRoot, ...relativePath.split("/"));
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, "synthetic gate bytes\n");
      assert.throws(
        () => generatedEvidenceInventory(caseRoot),
        /unexpected, stale, or unsafe entry/u,
        relativePath,
      );
    }
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
          snapshot: {
            path: relativePath,
            identity: fixture.candidateIdentity,
            sha256: fixture.candidateReceipt.artifact.sha256,
          },
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
      scanVsix: fixture.scanCandidate,
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

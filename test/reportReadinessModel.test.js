// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { fingerprint } = require("../scripts/quality/evidence");
const {
  UI_CANDIDATE_ARTIFACT,
  candidateBindingFromReceipt,
} = require("../scripts/quality/candidate-binding");
const {
  generateReport,
  summarizeFindings,
  UI_BLOCKED_REASON,
  validateUiResult,
} = require("../scripts/quality/report");
const { verifyQualityContracts } = require("../scripts/quality/verify-workflows");
const {
  verifySignedOutUiEvidence,
} = require("../scripts/quality/verify-ui-evidence");

const SOURCE = Object.freeze({
  sha: "1".repeat(40),
  fingerprint: "2".repeat(64),
});
const NPM_INTEGRITY = JSON.parse(fs.readFileSync(path.join(__dirname, "../.npm-integrity"), "utf8"));

function candidateReceipt(overrides = {}) {
  const base = {
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
      npmInstallationSha256: NPM_INTEGRITY[process.platform === "win32" ? "win32" : "posix"],
      platform: process.platform,
    },
    extension: {
      id: "Cloudsmith.cloudsmith-vsc",
      publisher: "Cloudsmith",
      name: "cloudsmith-vsc",
      version: "2.3.0",
    },
    vscode: { version: "1.134.0", executable: "/bounded/code", cli: "/bounded/cli" },
    profile: {
      mode: "ci",
      persistent: false,
      root: "/bounded/profile",
      testResourcesDir: "/bounded/profile",
      userDataDir: "/bounded/profile/settings",
      extensionsDir: "/bounded/profile/extensions",
    },
    artifact: {
      vsixPath: "out/development/cloudsmith-vsc-2.3.0.vsix",
      absoluteVsixPath: "/bounded/out/development/cloudsmith-vsc-2.3.0.vsix",
      sha256: "3".repeat(64),
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
    ...overrides,
  };
  return { ...base, fingerprint: fingerprint(base) };
}

function validUiResult(receipt) {
  return {
    schemaVersion: 2,
    status: "passed",
    source: SOURCE,
    sourceSha: SOURCE.sha,
    launchAttempted: true,
    tool: "vscode-extension-tester",
    toolVersion: "8.24.0",
    vscodeVersion: "1.134.0",
    platform: "darwin",
    architecture: "arm64",
    tests: ["signed-out assertion"],
    results: [{ name: "signed-out assertion", status: "passed" }],
    candidate: {
      candidateReceiptFingerprint: receipt.fingerprint,
      extensionId: receipt.extension.id,
      extensionVersion: receipt.extension.version,
      profileMode: receipt.profile.mode,
      sourceFingerprint: receipt.source.fingerprint,
      sourceSha: receipt.source.sha,
      vscodeVersion: receipt.vscode.version,
      vsixSha256: receipt.artifact.sha256,
    },
    reason: null,
  };
}

suite("two-lane release-readiness model", () => {
  test("contract verification enforces taxonomy parity and required authenticated fixtures", () => {
    const root = path.resolve(__dirname, "..");
    const taxonomy = JSON.parse(JSON.stringify(require("../quality/defect-taxonomy.json")));
    const findingSchema = JSON.parse(JSON.stringify(require("../quality/finding.schema.json")));
    const workflows = JSON.parse(JSON.stringify(require("../quality/critical-workflows.json")));
    findingSchema.properties.domain.enum.pop();
    workflows.workflows[0].liveFixture.required = false;

    const result = verifyQualityContracts({ root, taxonomy, findingSchema, workflows });

    assert.ok(result.errors.some(error => /domain values do not match/u.test(error)));
    assert.ok(result.errors.some(error => /required, non-destructive authenticated live fixture/u.test(error)));
  });

  test("derives finding blockers and emits stable domain, severity, deterministic, and live counts", () => {
    const workflows = {
      workflows: [{ id: "WF-CORE", criticality: "release-critical" }],
    };
    const findings = [
      {
        id: "QH-900",
        severity: "P1",
        domain: "product",
        status: "open",
        deterministicStatus: "fixed",
        liveStatus: "pending",
        workflowContract: "WF-CORE",
        surface: "fixture",
        releaseBlocking: false,
      },
      {
        id: "QH-901",
        severity: "P1",
        domain: "test-harness",
        status: "open",
        deterministicStatus: "failing",
        liveStatus: "not-required",
        workflowContract: "WF-CORE",
        surface: "fixture",
        releaseBlocking: false,
      },
    ];

    const summary = summarizeFindings(findings, "passed", [], workflows);

    assert.strictEqual(summary.status, "failed");
    assert.strictEqual(summary.releaseBlocking, 2);
    assert.strictEqual(summary.deterministicReleaseBlocking, 1);
    assert.strictEqual(summary.liveReleaseBlocking, 1);
    assert.strictEqual(summary.releaseBlockers[0].releaseBlocking, true);
    assert.deepStrictEqual(summary.counts.byDomain, {
      product: 1,
      "test-harness": 1,
      ci: 0,
      "release-evidence": 0,
      "security-environment": 0,
      documentation: 0,
      "external-platform": 0,
    });
    assert.strictEqual(summary.counts.bySeverity.P1, 2);
    assert.strictEqual(summary.counts.byDeterministicStatus.fixed, 1);
    assert.strictEqual(summary.counts.byDeterministicStatus.failing, 1);
    assert.strictEqual(summary.counts.byLiveStatus.pending, 1);
  });

  test("keeps authenticated status for every required fixture separate from deterministic layers", () => {
    const qualificationHomeDirectory = fs.realpathSync(os.tmpdir());
    const qualificationProfileRoot = path.join(
      qualificationHomeDirectory,
      ".cloudsmith-vscode-qualification",
    );
    const workflows = {
      workflows: [
        {
          id: "WF-NO-LIVE-LAYER",
          criticality: "release-critical",
          surface: "fixture",
          authoritativeOutcome: "fixture",
          requiredLayers: ["black-box-ui"],
          evidence: [],
          liveFixture: { required: true },
        },
        {
          id: "WF-LIVE-LAYER",
          criticality: "release-critical",
          surface: "fixture",
          authoritativeOutcome: "fixture",
          requiredLayers: ["live-protocol"],
          evidence: [],
          liveFixture: { required: true },
        },
      ],
    };
    const findingsFingerprint = fingerprint([]);
    const localCandidateReceipt = candidateReceipt({
      profile: {
        mode: "local",
        persistent: true,
        root: qualificationProfileRoot,
        testResourcesDir: qualificationProfileRoot,
        userDataDir: path.join(qualificationProfileRoot, "user-data"),
        extensionsDir: path.join(qualificationProfileRoot, "extensions"),
      },
    });
    const liveQualification = {
      schemaVersion: 3,
      source: SOURCE,
      candidate: candidateBindingFromReceipt(localCandidateReceipt, {
        source: SOURCE,
        homeDirectory: qualificationHomeDirectory,
      }),
      inputPath: "internal_docs/quality/live-qualification.json",
      status: "partial",
      authenticatedAcceptance: "not-recorded",
      verdict: null,
      requiredWorkflowIds: ["WF-LIVE-LAYER", "WF-NO-LIVE-LAYER"],
      passedWorkflowIds: ["WF-NO-LIVE-LAYER"],
      missingWorkflowIds: ["WF-LIVE-LAYER"],
      workflowMatrix: [
        { id: "WF-LIVE-LAYER", status: "PARTIAL" },
        { id: "WF-NO-LIVE-LAYER", status: "PASS" },
      ],
      attestationFingerprint: "4".repeat(64),
      evidenceManifest: [{
        path: "internal_docs/quality/findings.jsonl",
        sha256: findingsFingerprint,
      }],
      findingsFingerprint,
      openReleaseBlockerCount: 0,
      visibleEnabledActions: { status: "not-run", silentNoOpCount: null },
      reason: "One workflow is partial.",
      errors: [],
    };

    const report = generateReport({
      source: SOURCE,
      profile: "full",
      plan: [],
      receipts: [],
      findings: [],
      findingsFingerprint,
      findingsStatus: "passed",
      liveQualification,
      workflows,
      inventories: {},
    });

    const noLiveLayer = report.workflowCoverage.find(workflow => (
      workflow.id === "WF-NO-LIVE-LAYER"
    ));
    const liveLayer = report.workflowCoverage.find(workflow => (
      workflow.id === "WF-LIVE-LAYER"
    ));
    assert.strictEqual(noLiveLayer.authenticatedRequired, true);
    assert.strictEqual(noLiveLayer.authenticatedStatus, "PASS");
    assert.strictEqual(noLiveLayer.deterministicStatus, "not-run");
    assert.strictEqual(liveLayer.authenticatedStatus, "PARTIAL");
    assert.strictEqual(liveLayer.layerStatuses["live-protocol"], "blocked");
    assert.deepStrictEqual(report.liveQualification.workflowMatrix, liveQualification.workflowMatrix);
    assert.strictEqual(report.releaseReadiness.verdict, null);
  });

  test("accepts UI evidence only when it binds the exact verified packaged candidate", () => {
    const receipt = candidateReceipt();
    const ui = validUiResult(receipt);
    const options = {
      candidateReceipt: receipt,
      extensionId: "Cloudsmith.cloudsmith-vsc",
      extensionVersion: "2.3.0",
    };

    assert.deepStrictEqual(
      validateUiResult(ui, SOURCE, ["signed-out assertion"], options),
      []
    );
    assert.ok(validateUiResult(ui, SOURCE, ["signed-out assertion"], {
      ...options,
      candidateReceipt: null,
    }).some(error => /exact verified candidate receipt/u.test(error)));
    assert.ok(validateUiResult({
      ...ui,
      candidate: { ...ui.candidate, vsixSha256: "5".repeat(64) },
    }, SOURCE, ["signed-out assertion"], options).some(error => /candidate/u.test(error)));
  });

  test("verifies the signed-out CI handoff only for the exact candidate-bound result", () => {
    const fixtureRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "cloudsmith-ui-handoff-",
    )));
    try {
      const developmentDir = path.join(fixtureRoot, "out", "development");
      const releaseDir = path.join(fixtureRoot, "out", "release");
      fs.mkdirSync(developmentDir, { recursive: true });
      fs.mkdirSync(releaseDir, { recursive: true });
      fs.writeFileSync(path.join(fixtureRoot, "package.json"), JSON.stringify({
        publisher: "Cloudsmith",
        name: "cloudsmith-vsc",
        version: "2.3.0",
      }));
      fs.writeFileSync(path.join(fixtureRoot, ".node-version"), "22.23.2\n");
      fs.writeFileSync(path.join(fixtureRoot, ".npm-version"), "10.9.8\n");
      fs.writeFileSync(
        path.join(fixtureRoot, ".npm-integrity"),
        `${JSON.stringify(NPM_INTEGRITY)}\n`,
      );
      const artifactBytes = Buffer.from("signed-out candidate A");
      const artifactPath = path.join(developmentDir, "cloudsmith-vsc-2.3.0.vsix");
      fs.writeFileSync(artifactPath, artifactBytes);
      const candidateArtifactPath = path.join(fixtureRoot, UI_CANDIDATE_ARTIFACT);
      fs.mkdirSync(path.dirname(candidateArtifactPath), { recursive: true });
      fs.writeFileSync(candidateArtifactPath, artifactBytes);
      const baseReceipt = candidateReceipt();
      const receipt = candidateReceipt({
        artifact: {
          ...baseReceipt.artifact,
          absoluteVsixPath: artifactPath,
          archiveBytes: artifactBytes.length,
          sha256: require("crypto").createHash("sha256").update(artifactBytes).digest("hex"),
        },
      });
      const ui = validUiResult(receipt);
      const options = {
        root: fixtureRoot,
        source: SOURCE,
        manifest: {
          publisher: "Cloudsmith",
          name: "cloudsmith-vsc",
          version: "2.3.0",
        },
        workflows: {
          workflows: [{
            id: "WF-SIGNED-OUT",
            evidence: [{
              layer: "black-box-ui",
              testNames: ["signed-out assertion"],
            }],
          }],
        },
        candidateReceipt: receipt,
        candidateArtifactPath,
        ui,
      };

      assert.deepStrictEqual(verifySignedOutUiEvidence(options), {
        status: "passed",
        sourceSha: SOURCE.sha,
        testCount: 1,
      });
      assert.throws(
        () => verifySignedOutUiEvidence({
          ...options,
          ui: {
            ...ui,
            candidate: { ...ui.candidate, vsixSha256: "5".repeat(64) },
          },
        }),
        /does not bind the exact verified candidate/u
      );

      fs.rmSync(candidateArtifactPath);
      assert.throws(
        () => verifySignedOutUiEvidence(options),
        /does not bind the exact verified candidate/u
      );

      fs.writeFileSync(candidateArtifactPath, Buffer.from("signed-out candidate B"));
      assert.throws(
        () => verifySignedOutUiEvidence(options),
        /does not bind the exact verified candidate/u
      );

      fs.writeFileSync(candidateArtifactPath, artifactBytes);
      fs.writeFileSync(artifactPath, Buffer.from("mutable output changed after proof capture"));
      assert.deepStrictEqual(verifySignedOutUiEvidence(options), {
        status: "passed",
        sourceSha: SOURCE.sha,
        testCount: 1,
      });

      const crossedBytes = Buffer.from("crossed release candidate");
      const crossedPath = path.join(releaseDir, "cloudsmith-vsc-2.3.0.vsix");
      fs.writeFileSync(crossedPath, crossedBytes);
      const crossedReceipt = candidateReceipt({
        artifact: {
          ...baseReceipt.artifact,
          vsixPath: "out/release/cloudsmith-vsc-2.3.0.vsix",
          absoluteVsixPath: crossedPath,
          archiveBytes: crossedBytes.length,
          sha256: require("crypto").createHash("sha256").update(crossedBytes).digest("hex"),
        },
      });
      assert.throws(
        () => verifySignedOutUiEvidence({ ...options, candidateReceipt: crossedReceipt }),
        /does not bind the exact verified candidate/u
      );
    } finally {
      fs.rmSync(fixtureRoot, { force: true, recursive: true });
    }
  });

  test("retains only the strict value-blind blocked UI shape", () => {
    const blocked = {
      schemaVersion: 2,
      status: "blocked",
      source: SOURCE,
      sourceSha: SOURCE.sha,
      launchAttempted: false,
      candidate: null,
      tool: null,
      toolVersion: null,
      vscodeVersion: null,
      platform: null,
      architecture: null,
      tests: [],
      results: [],
      reason: UI_BLOCKED_REASON,
    };

    assert.deepStrictEqual(validateUiResult(blocked, SOURCE, ["signed-out assertion"]), []);
    assert.ok(validateUiResult({
      ...blocked,
      reason: "unbounded environment detail",
    }, SOURCE, ["signed-out assertion"]).some(error => /value-blind blocked shape/u.test(error)));
  });
});

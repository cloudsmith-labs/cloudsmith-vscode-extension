// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const yazl = require("yazl");
const { fingerprint } = require("../scripts/quality/evidence");
const {
  UI_CANDIDATE_ARTIFACT,
  candidateBindingFromReceipt,
} = require("../scripts/quality/candidate-binding");
const {
  generateReport,
  releaseReadinessStatus,
  summarizeRemoteCi,
  summarizeFindings,
  UI_BLOCKED_REASON,
  validateDerivedLiveStatus,
  validateUiResult,
} = require("../scripts/quality/report");
const { verifyQualityContracts } = require("../scripts/quality/verify-workflows");
const { verifyStagedBundleMatchesArchive } = require("../scripts/quality/remote-signed-out-artifact");
const {
  buildReceipt,
  exactArtifactDigest,
  parseArguments: parseRemoteCiArguments,
  writeRemoteCiEvidence,
} = require("../scripts/quality/collect-remote-ci");
const {
  verifySignedOutUiEvidence,
} = require("../scripts/quality/verify-ui-evidence");
const {
  deriveReleaseBlocking,
  deriveRequiredEvidenceLayers,
  findingRequiresLiveVerification,
} = require("../scripts/quality/findings");
const TAXONOMY = require("../quality/defect-taxonomy.json");

const SOURCE = Object.freeze({
  sha: "1".repeat(40),
  fingerprint: "2".repeat(64),
});
const NPM_INTEGRITY = JSON.parse(fs.readFileSync(path.join(__dirname, "../.npm-integrity"), "utf8"));

function exactSignedOutZip(files) {
  return new Promise((resolve, reject) => {
    const zip = new yazl.ZipFile();
    const chunks = [];
    zip.outputStream.on("data", chunk => chunks.push(chunk));
    zip.outputStream.on("error", reject);
    zip.outputStream.on("end", () => resolve(Buffer.concat(chunks)));
    for (const [name, bytes] of Object.entries(files)) zip.addBuffer(bytes, name);
    zip.end();
  });
}

function remoteCiReceipt(overrides = {}) {
  const capturedAt = new Date().toISOString();
  const createdAt = new Date(Date.parse(capturedAt) - 5 * 60 * 1000).toISOString();
  const completedAt = new Date(Date.parse(capturedAt) - 4 * 60 * 1000).toISOString();
  const aggregateCompletedAt = new Date(Date.parse(capturedAt) - 3 * 60 * 1000).toISOString();
  let databaseId = 2000;
  const mainJobs = [
    ["quality", "Quality"],
    ["mutation", "Changed high-risk mutation gate"],
    ["extension-tests:ubuntu-24.04:1.99.0:core", "Extension tests (ubuntu-24.04, VS Code 1.99.0, core)"],
    ["extension-tests:ubuntu-24.04:1.99.0:smoke", "Extension tests (ubuntu-24.04, VS Code 1.99.0, smoke)"],
    ["extension-tests:ubuntu-24.04:1.134.0:core", "Extension tests (ubuntu-24.04, VS Code 1.134.0, core)"],
    ["extension-tests:windows-2025:1.134.0:smoke", "Extension tests (windows-2025, VS Code 1.134.0, smoke)"],
    ["extension-tests:macos-15:1.134.0:smoke", "Extension tests (macos-15, VS Code 1.134.0, smoke)"],
    ["package", "Reproducible VSIX"],
    ["core-mutation", "Core mutation"],
    ["signed-out-black-box-ui", "Signed-out packaged black-box UI"],
    ["build-candidate", "Deterministic build candidate"],
  ].map(([id, name]) => ({
    id,
    name,
    databaseId: ++databaseId,
    status: "completed",
    conclusion: "success",
    startedAt: createdAt,
    completedAt,
  }));
  const codeqlJobs = [
    ["analyze-actions", "Analyze (actions)"],
    ["analyze-javascript-typescript", "Analyze (javascript-typescript)"],
  ].map(([id, name]) => ({
    id,
    name,
    databaseId: ++databaseId,
    status: "completed",
    conclusion: "success",
    startedAt: createdAt,
    completedAt,
  }));
  return {
    schemaVersion: 2,
    repository: "cloudsmith-labs/cloudsmith-vscode-extension",
    branch: "test/release-quality-harness",
    sourceSha: SOURCE.sha,
    sourceFingerprint: SOURCE.fingerprint,
    capturedAt,
    pullRequest: {
      number: 42,
      draft: true,
      state: "open",
      baseRef: "main",
      headRef: "test/release-quality-harness",
      headSha: SOURCE.sha,
      url: "https://github.com/cloudsmith-labs/cloudsmith-vscode-extension/pull/42",
    },
    runs: [
      {
        workflowFile: ".github/workflows/main.yml",
        workflowName: "Deterministic build candidate",
        event: "pull_request",
        runId: 1001,
        runAttempt: 1,
        pullRequestNumber: 42,
        headSha: SOURCE.sha,
        status: "completed",
        conclusion: "success",
        createdAt,
        completedAt,
        url: "https://github.com/cloudsmith-labs/cloudsmith-vscode-extension/actions/runs/1001",
        jobs: mainJobs,
      },
      {
        workflowFile: "dynamic/github-code-scanning/codeql",
        workflowName: "PR #42",
        event: "dynamic",
        runId: 1002,
        runAttempt: 1,
        pullRequestNumber: 42,
        headSha: SOURCE.sha,
        status: "completed",
        conclusion: "success",
        createdAt,
        completedAt,
        url: "https://github.com/cloudsmith-labs/cloudsmith-vscode-extension/actions/runs/1002",
        jobs: codeqlJobs,
      },
    ],
    codeqlAggregate: {
      databaseId: 3001,
      name: "CodeQL",
      appSlug: "github-advanced-security",
      headSha: SOURCE.sha,
      status: "completed",
      conclusion: "success",
      startedAt: createdAt,
      completedAt: aggregateCompletedAt,
      annotationsCount: 0,
      title: "No new alerts in code changed by this pull request",
      url: "https://github.com/cloudsmith-labs/cloudsmith-vscode-extension/runs/3001",
    },
    signedOutUiArtifact: {
      artifactId: 4001,
      name: `signed-out-ui-evidence-${SOURCE.sha}-1`,
      digest: `sha256:${"b".repeat(64)}`,
      sizeBytes: 1024,
      expired: false,
      createdAt,
      updatedAt: completedAt,
      runId: 1001,
      runAttempt: 1,
      headSha: SOURCE.sha,
      branch: "test/release-quality-harness",
    },
    evidence: {
      path: "internal_docs/quality/remote-ci-api.json",
      sha256: "a".repeat(64),
    },
    ...overrides,
  };
}

function remoteCiApiEvidence(receipt) {
  const rawRun = run => ({
    id: run.runId,
    run_attempt: run.runAttempt,
    path: run.workflowFile,
    name: run.workflowName,
    event: run.event,
    head_sha: run.headSha,
    head_branch: run.workflowFile === "dynamic/github-code-scanning/codeql"
      ? `refs/pull/${String(receipt.pullRequest.number)}/head`
      : receipt.branch,
    head_repository: { full_name: receipt.repository },
    status: run.status,
    conclusion: run.conclusion,
    html_url: run.url,
    created_at: run.createdAt,
    updated_at: run.completedAt,
    pull_requests: run.workflowFile === "dynamic/github-code-scanning/codeql"
      ? []
      : [{ number: run.pullRequestNumber }],
  });
  const value = {
    schemaVersion: 1,
    repository: receipt.repository,
    capturedAt: receipt.capturedAt,
    pullRequest: {
      number: receipt.pullRequest.number,
      draft: receipt.pullRequest.draft,
      state: receipt.pullRequest.state,
      html_url: receipt.pullRequest.url,
      base: { ref: receipt.pullRequest.baseRef, repo: { id: 5001, full_name: receipt.repository } },
      head: {
        ref: receipt.pullRequest.headRef,
        sha: receipt.pullRequest.headSha,
        repo: { id: 5001, full_name: receipt.repository },
      },
    },
    runs: receipt.runs.map(rawRun),
    jobsByRunId: Object.fromEntries(receipt.runs.map(run => [String(run.runId), {
      jobs: run.jobs.map(job => ({
        id: job.databaseId,
        name: job.name,
        status: job.status,
        conclusion: job.conclusion,
        run_attempt: run.runAttempt,
        started_at: job.startedAt,
        completed_at: job.completedAt,
      })),
    }])),
    runListsByWorkflow: Object.fromEntries(receipt.runs.map(run => [run.workflowFile, {
      workflow_runs: [rawRun(run)],
    }])),
    checkRunsForRef: {
      check_runs: [{
        id: receipt.codeqlAggregate.databaseId,
        name: receipt.codeqlAggregate.name,
        app: { slug: receipt.codeqlAggregate.appSlug },
        head_sha: receipt.codeqlAggregate.headSha,
        status: receipt.codeqlAggregate.status,
        conclusion: receipt.codeqlAggregate.conclusion,
        started_at: receipt.codeqlAggregate.startedAt,
        completed_at: receipt.codeqlAggregate.completedAt,
        output: {
          annotations_count: receipt.codeqlAggregate.annotationsCount,
          title: receipt.codeqlAggregate.title,
        },
        html_url: receipt.codeqlAggregate.url,
        pull_requests: [{ number: receipt.pullRequest.number }],
      }],
    },
    artifactsByRunId: {
      [String(receipt.signedOutUiArtifact.runId)]: {
        artifacts: [{
          id: receipt.signedOutUiArtifact.artifactId,
          name: receipt.signedOutUiArtifact.name,
          digest: receipt.signedOutUiArtifact.digest,
          size_in_bytes: receipt.signedOutUiArtifact.sizeBytes,
          expired: receipt.signedOutUiArtifact.expired,
          created_at: receipt.signedOutUiArtifact.createdAt,
          updated_at: receipt.signedOutUiArtifact.updatedAt,
          workflow_run: {
            id: receipt.signedOutUiArtifact.runId,
            head_sha: receipt.signedOutUiArtifact.headSha,
            head_branch: receipt.signedOutUiArtifact.branch,
            repository_id: 5001,
            head_repository_id: 5001,
          },
        }],
      },
    },
  };
  return { value, fingerprint: receipt.evidence.sha256 };
}

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
  test("rejects a staged signed-out bundle swapped after the GitHub archive was captured", async () => {
    const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "remote-ui-archive-")));
    const bundle = path.join(root, "bundle");
    fs.mkdirSync(bundle, { mode: 0o700 });
    const files = Object.fromEntries([
      "evidence.json", "result.json", "ui-candidate.json", "ui-candidate.vsix",
    ].map(name => [name, Buffer.from(`authoritative ${name}`)]));
    const archiveBytes = await exactSignedOutZip(files);
    const archive = path.join(root, "artifact.zip");
    fs.writeFileSync(archive, archiveBytes);
    const archiveDescriptor = fs.openSync(archive, "r");
    fs.fsyncSync(archiveDescriptor);
    fs.closeSync(archiveDescriptor);
    for (const [name, bytes] of Object.entries(files)) fs.writeFileSync(path.join(bundle, name), bytes);
    const digest = `sha256:${require("crypto").createHash("sha256").update(archiveBytes).digest("hex")}`;
    assert.doesNotThrow(() => verifyStagedBundleMatchesArchive({
      archivePath: archive,
      bundleRoot: bundle,
      expectedDigest: digest,
    }));
    fs.writeFileSync(path.join(bundle, "result.json"), "different but self-consistent result");
    assert.throws(() => verifyStagedBundleMatchesArchive({
      archivePath: archive,
      bundleRoot: bundle,
      expectedDigest: digest,
    }), /staged member (?:is unsafe or changed|does not match the GitHub archive)/u);
  });
  test("rejects a downloaded signed-out artifact whose bytes differ from GitHub metadata", () => {
    const bytes = Buffer.from("exact-artifact");
    const digest = `sha256:${require("crypto").createHash("sha256").update(bytes).digest("hex")}`;
    assert.strictEqual(exactArtifactDigest(bytes, digest), digest.slice(7));
    assert.throws(
      () => exactArtifactDigest(Buffer.from("swapped-artifact"), digest),
      /does not match GitHub metadata/u,
    );
  });
  test("remote CI collection requires main and CodeQL run identities", () => {
    assert.deepStrictEqual(
      parseRemoteCiArguments([
        "--pr", "42", "--main-run", "1001", "--codeql-run", "1002",
      ]),
      { pr: 42, "main-run": 1001, "codeql-run": 1002 }
    );
    for (const invalid of [
      ["--pr", "42", "--main-run", "1001"],
      ["--pr", "42", "--codeql-run", "1002"],
      ["--pr", "42", "--main-run", "1001", "--codeql-run", "0"],
      ["--pr", "42", "--main-run", "1001", "--main-run", "1002", "--codeql-run", "1003"],
    ]) {
      assert.throws(() => parseRemoteCiArguments(invalid), /--codeql-run ID/u);
    }
  });

  test("remote CI collection writes only its exact ignored evidence targets", () => {
    const calls = [];
    const writer = (...args) => {
      calls.push(args);
      return "/synthetic/ignored-output.json";
    };
    const value = Object.freeze({ schemaVersion: 1 });
    assert.strictEqual(
      writeRemoteCiEvidence(
        "internal_docs/quality/remote-ci-api.json",
        value,
        "/synthetic/repository",
        writer,
      ),
      "/synthetic/ignored-output.json",
    );
    assert.strictEqual(
      writeRemoteCiEvidence(
        "internal_docs/quality/remote-ci.json",
        value,
        "/synthetic/repository",
        writer,
      ),
      "/synthetic/ignored-output.json",
    );
    assert.deepStrictEqual(calls, [
      [
        "internal_docs/quality/remote-ci-api.json",
        value,
        "/synthetic/repository",
        { subtree: "internal_docs/quality" },
      ],
      [
        "internal_docs/quality/remote-ci.json",
        value,
        "/synthetic/repository",
        { subtree: "internal_docs/quality" },
      ],
    ]);
    for (const unauthorized of [
      ".quality/remote-ci.json",
      "internal_docs/quality/alternate.json",
      "internal_docs/quality/../remote-ci.json",
      "internal_docs\\quality\\remote-ci.json",
    ]) {
      assert.throws(
        () => writeRemoteCiEvidence(
          unauthorized,
          value,
          "/synthetic/repository",
          writer,
        ),
        /not an authorized ignored path/u,
      );
    }
    assert.strictEqual(calls.length, 2);
  });

  test("remote CI collection canonicalizes GitHub timestamps", () => {
    const exact = remoteCiReceipt();
    const snapshot = remoteCiApiEvidence(exact).value;
    snapshot.runs[0].created_at = "2026-08-30T04:19:21Z";
    snapshot.runs[0].updated_at = "2026-08-30T04:38:43Z";
    for (const job of snapshot.jobsByRunId[String(exact.runs[0].runId)].jobs) {
      job.started_at = "2026-08-30T04:19:24Z";
      job.completed_at = "2026-08-30T04:35:56Z";
    }
    const uiArtifact = snapshot.artifactsByRunId[String(exact.runs[0].runId)].artifacts[0];
    uiArtifact.created_at = "2026-08-30T04:20:00Z";
    uiArtifact.updated_at = "2026-08-30T04:35:00Z";

    const receipt = buildReceipt(
      snapshot,
      SOURCE,
      exact.branch,
      exact.pullRequest.number,
      exact.runs.map(run => run.runId),
    );
    assert.strictEqual(receipt.runs[0].createdAt, "2026-08-30T04:19:21.000Z");
    assert.strictEqual(receipt.runs[0].completedAt, "2026-08-30T04:38:43.000Z");
    assert.deepStrictEqual(
      receipt.runs[0].jobs.map(job => [job.startedAt, job.completedAt]),
      exact.runs[0].jobs.map(() => [
        "2026-08-30T04:19:24.000Z",
        "2026-08-30T04:35:56.000Z",
      ]),
    );
    receipt.evidence = {
      path: "internal_docs/quality/remote-ci-api.json",
      sha256: "a".repeat(64),
    };
    const summary = summarizeRemoteCi(
      receipt,
      SOURCE,
      null,
      Date.now(),
      { apiEvidence: { value: snapshot, fingerprint: "a".repeat(64) } },
    );
    assert.strictEqual(summary.status, "passed", summary.errors.join("\n"));
  });

  test("remote CI collection fails closed on crossed or superseded exact-head evidence", () => {
    const exact = remoteCiReceipt();
    const runIds = exact.runs.map(run => run.runId);
    const rejects = (mutate, pattern) => {
      const snapshot = remoteCiApiEvidence(exact).value;
      mutate(snapshot);
      assert.throws(
        () => buildReceipt(
          snapshot,
          SOURCE,
          exact.branch,
          exact.pullRequest.number,
          runIds,
        ),
        pattern,
      );
    };

    rejects(snapshot => {
      snapshot.pullRequest.number += 1;
    }, /exact draft pull request/u);
    rejects(snapshot => {
      const codeql = snapshot.runs[1];
      snapshot.runListsByWorkflow[codeql.path].workflow_runs.unshift({
        ...codeql,
        id: codeql.id + 100,
        created_at: new Date(Date.parse(codeql.created_at) + 1000).toISOString(),
        updated_at: new Date(Date.parse(codeql.updated_at) + 1000).toISOString(),
      });
    }, /latest successful exact-head run/u);
    rejects(snapshot => {
      snapshot.jobsByRunId[String(exact.runs[1].runId)].jobs[0].conclusion = "failure";
    }, /job inventory is not exact and successful/u);
    rejects(snapshot => {
      const aggregate = snapshot.checkRunsForRef.check_runs[0];
      snapshot.checkRunsForRef.check_runs.unshift({
        ...aggregate,
        id: aggregate.id + 100,
        status: "in_progress",
        conclusion: null,
        started_at: new Date(Date.parse(aggregate.completed_at) + 1000).toISOString(),
        completed_at: null,
        pull_requests: [],
      });
    }, /aggregate check is missing or not successful/u);
    rejects(snapshot => {
      snapshot.artifactsByRunId[String(exact.runs[0].runId)]
        .artifacts[0].workflow_run.head_sha = "3".repeat(40);
    }, /artifact metadata does not bind the exact run attempt/u);
  });

  test("requires exact successful final-head remote CI before readiness", () => {
    const exact = remoteCiReceipt();
    const options = { apiEvidence: remoteCiApiEvidence(exact) };
    const exactSummary = summarizeRemoteCi(exact, SOURCE, null, Date.now(), options);
    assert.strictEqual(exactSummary.status, "passed", exactSummary.errors.join("\n"));
    assert.strictEqual(exactSummary.completedAt, exact.codeqlAggregate.completedAt);
    assert.strictEqual(summarizeRemoteCi(null, SOURCE).status, "not-run");
    assert.strictEqual(summarizeRemoteCi(exact, SOURCE).status, "failed");
    assert.strictEqual(summarizeRemoteCi(exact, SOURCE, null, Date.now(), {
      apiEvidence: { ...options.apiEvidence, fingerprint: "b".repeat(64) },
    }).status, "failed");
    assert.strictEqual(summarizeRemoteCi(exact, SOURCE, null, Date.now(), {
      ...options,
      requireSignedOutAuthority: true,
    }).status, "failed");
    const signedOutAuthority = {
      status: "passed",
      sourceSha: SOURCE.sha,
      artifactDigest: exact.signedOutUiArtifact.digest,
      archiveSha256: exact.signedOutUiArtifact.digest.slice(7),
      candidate: candidateBindingFromReceipt(candidateReceipt(), { source: SOURCE }),
    };
    assert.strictEqual(summarizeRemoteCi(exact, SOURCE, null, Date.now(), {
      ...options,
      requireSignedOutAuthority: true,
      signedOutAuthority,
    }).status, "passed");
    assert.strictEqual(summarizeRemoteCi(exact, SOURCE, null, Date.now(), {
      ...options,
      requireSignedOutAuthority: true,
      signedOutAuthority: { ...signedOutAuthority, archiveSha256: "c".repeat(64) },
    }).status, "failed");

    const mutations = [
      { ...exact, sourceSha: "3".repeat(40) },
      { ...exact, sourceFingerprint: "3".repeat(64) },
      { ...exact, capturedAt: new Date(Date.now() - (25 * 60 * 60 * 1000)).toISOString() },
      { ...exact, pullRequest: { ...exact.pullRequest, draft: false } },
      { ...exact, branch: "other-branch" },
      {
        ...exact,
        runs: exact.runs.map((run, index) => index === 0
          ? { ...run, conclusion: "failure" }
          : run),
      },
      {
        ...exact,
        runs: exact.runs.map((run, index) => index === 1
          ? { ...run, workflowFile: ".github/workflows/hostile.yml" }
          : run),
      },
      {
        ...exact,
        codeqlAggregate: { ...exact.codeqlAggregate, annotationsCount: 1 },
      },
      {
        ...exact,
        signedOutUiArtifact: {
          ...exact.signedOutUiArtifact,
          digest: `sha256:${"c".repeat(64)}`,
        },
      },
      {
        ...exact,
        runs: exact.runs.map((run, index) => index === 0
          ? { ...run, jobs: run.jobs.slice(1) }
          : run),
      },
      {
        ...exact,
        runs: exact.runs.map((run, index) => index === 0
          ? { ...run, completedAt: new Date(Date.parse(run.createdAt) - 1).toISOString() }
          : run),
      },
    ];
    for (const mutation of mutations) {
      assert.strictEqual(
        summarizeRemoteCi(mutation, SOURCE, null, Date.now(), options).status,
        "failed",
      );
    }
    const superseded = remoteCiApiEvidence(exact);
    superseded.value.runListsByWorkflow[exact.runs[0].workflowFile].workflow_runs.unshift({
      ...superseded.value.runs[0],
      id: exact.runs[0].runId + 100,
      run_attempt: 1,
      created_at: new Date(Date.parse(exact.runs[0].createdAt) + 1000).toISOString(),
    });
    assert.strictEqual(summarizeRemoteCi(exact, SOURCE, null, Date.now(), {
      apiEvidence: superseded,
    }).status, "failed");
    const suffixedPaths = remoteCiApiEvidence(exact);
    for (const run of suffixedPaths.value.runs.filter(item => item.path.startsWith(".github/"))) {
      run.path += "@refs/heads/test/release-quality-harness";
    }
    for (const run of exact.runs.filter(item => item.workflowFile.startsWith(".github/"))) {
      suffixedPaths.value.runListsByWorkflow[run.workflowFile].workflow_runs[0].path
        += "@refs/heads/test/release-quality-harness";
    }
    assert.strictEqual(summarizeRemoteCi(exact, SOURCE, null, Date.now(), {
      apiEvidence: suffixedPaths,
    }).status, "passed");
    const hostilePath = remoteCiApiEvidence(exact);
    hostilePath.value.runs[0].path += "@main@hostile";
    hostilePath.value.runListsByWorkflow[exact.runs[0].workflowFile].workflow_runs[0].path
      += "@main@hostile";
    assert.strictEqual(summarizeRemoteCi(exact, SOURCE, null, Date.now(), {
      apiEvidence: hostilePath,
    }).status, "failed");
    const crossedRepository = remoteCiApiEvidence(exact);
    crossedRepository.value.pullRequest.head.repo.full_name = "fork/repository";
    crossedRepository.value.runs[0].head_repository.full_name = "fork/repository";
    assert.strictEqual(summarizeRemoteCi(exact, SOURCE, null, Date.now(), {
      apiEvidence: crossedRepository,
    }).status, "failed");
    const crossedCodeql = remoteCiApiEvidence(exact);
    crossedCodeql.value.checkRunsForRef.check_runs[0].head_sha = "3".repeat(40);
    assert.strictEqual(summarizeRemoteCi(exact, SOURCE, null, Date.now(), {
      apiEvidence: crossedCodeql,
    }).status, "failed");
    const staticCodeql = remoteCiReceipt();
    staticCodeql.runs[1] = {
      ...staticCodeql.runs[1],
      workflowFile: ".github/workflows/codeql-analysis.yml",
      workflowName: "CodeQL",
      event: "pull_request",
    };
    assert.strictEqual(summarizeRemoteCi(
      staticCodeql,
      SOURCE,
      null,
      Date.now(),
      { apiEvidence: remoteCiApiEvidence(staticCodeql) },
    ).status, "passed");
    const crossedCodeqlAttempt = remoteCiApiEvidence(exact);
    crossedCodeqlAttempt.value.jobsByRunId[String(exact.runs[1].runId)]
      .jobs[0].run_attempt += 1;
    assert.strictEqual(summarizeRemoteCi(exact, SOURCE, null, Date.now(), {
      apiEvidence: crossedCodeqlAttempt,
    }).status, "failed");
    const extraCodeqlJob = remoteCiApiEvidence(exact);
    extraCodeqlJob.value.jobsByRunId[String(exact.runs[1].runId)].jobs.push({
      ...extraCodeqlJob.value.jobsByRunId[String(exact.runs[1].runId)].jobs[0],
      id: 9999,
      name: "Unexpected analysis",
    });
    assert.strictEqual(summarizeRemoteCi(exact, SOURCE, null, Date.now(), {
      apiEvidence: extraCodeqlJob,
    }).status, "failed");
    const supersededCodeqlAggregate = remoteCiApiEvidence(exact);
    supersededCodeqlAggregate.value.checkRunsForRef.check_runs.unshift({
      ...supersededCodeqlAggregate.value.checkRunsForRef.check_runs[0],
      id: exact.codeqlAggregate.databaseId + 1,
      completed_at: new Date(Date.parse(exact.codeqlAggregate.completedAt) + 1000).toISOString(),
    });
    assert.strictEqual(summarizeRemoteCi(exact, SOURCE, null, Date.now(), {
      apiEvidence: supersededCodeqlAggregate,
    }).status, "failed");
    const newerInProgressCodeqlAggregate = remoteCiApiEvidence(exact);
    newerInProgressCodeqlAggregate.value.checkRunsForRef.check_runs.unshift({
      ...newerInProgressCodeqlAggregate.value.checkRunsForRef.check_runs[0],
      id: exact.codeqlAggregate.databaseId + 2,
      status: "in_progress",
      conclusion: null,
      started_at: new Date(Date.parse(exact.codeqlAggregate.completedAt) + 1000).toISOString(),
      completed_at: null,
      pull_requests: [],
    });
    assert.strictEqual(summarizeRemoteCi(exact, SOURCE, null, Date.now(), {
      apiEvidence: newerInProgressCodeqlAggregate,
    }).status, "failed");
    const staleCodeqlRun = remoteCiApiEvidence(exact);
    staleCodeqlRun.value.runListsByWorkflow[exact.runs[1].workflowFile].workflow_runs.unshift({
      ...staleCodeqlRun.value.runs[1],
      id: exact.runs[1].runId + 100,
      updated_at: new Date(Date.parse(exact.runs[1].completedAt) + 1000).toISOString(),
    });
    assert.strictEqual(summarizeRemoteCi(exact, SOURCE, null, Date.now(), {
      apiEvidence: staleCodeqlRun,
    }).status, "failed");
    const crossedArtifact = remoteCiApiEvidence(exact);
    crossedArtifact.value.artifactsByRunId[String(exact.runs[0].runId)]
      .artifacts[0].workflow_run.head_sha = "3".repeat(40);
    assert.strictEqual(summarizeRemoteCi(exact, SOURCE, null, Date.now(), {
      apiEvidence: crossedArtifact,
    }).status, "failed");
    const duplicateArtifact = remoteCiApiEvidence(exact);
    duplicateArtifact.value.artifactsByRunId[String(exact.runs[0].runId)]
      .artifacts.push({
        ...duplicateArtifact.value.artifactsByRunId[String(exact.runs[0].runId)].artifacts[0],
        id: exact.signedOutUiArtifact.artifactId + 1,
      });
    assert.strictEqual(summarizeRemoteCi(exact, SOURCE, null, Date.now(), {
      apiEvidence: duplicateArtifact,
    }).status, "failed");
    const olderHighAttemptReceipt = remoteCiReceipt();
    olderHighAttemptReceipt.runs[0].runAttempt = 2;
    const newerFailed = remoteCiApiEvidence(olderHighAttemptReceipt);
    newerFailed.value.runListsByWorkflow[olderHighAttemptReceipt.runs[0].workflowFile]
      .workflow_runs.unshift({
        ...newerFailed.value.runs[0],
        id: olderHighAttemptReceipt.runs[0].runId + 1,
        run_attempt: 1,
        conclusion: "failure",
        created_at: new Date(
          Date.parse(olderHighAttemptReceipt.runs[0].createdAt) + 1000
        ).toISOString(),
        updated_at: new Date(
          Date.parse(olderHighAttemptReceipt.runs[0].completedAt) + 1000
        ).toISOString(),
      });
    assert.strictEqual(summarizeRemoteCi(
      olderHighAttemptReceipt,
      SOURCE,
      null,
      Date.now(),
      { apiEvidence: newerFailed },
    ).status, "failed");
    const olderRetried = remoteCiApiEvidence(exact);
    olderRetried.value.runListsByWorkflow[exact.runs[0].workflowFile].workflow_runs.push({
      ...olderRetried.value.runs[0],
      id: exact.runs[0].runId - 100,
      run_attempt: exact.runs[0].runAttempt + 1,
      created_at: new Date(Date.parse(exact.runs[0].createdAt) - 1000).toISOString(),
    });
    assert.strictEqual(summarizeRemoteCi(exact, SOURCE, null, Date.now(), {
      apiEvidence: olderRetried,
    }).status, "passed");
  });

  test("remote CI absence and failure block or fail an otherwise ready release", () => {
    const readyInputs = {
      profile: "release",
      deterministicStatus: "passed",
      impact: { status: "passed" },
      mutation: { status: "passed" },
      blackBoxUi: { status: "passed" },
      liveQualification: {
        status: "passed",
        completedAt: "2026-08-29T21:00:00.000Z",
        authenticatedAcceptance: "recorded",
        verdict: "TEAM-TEST READY",
        readinessTarget: "team-test",
        targetPolicyFingerprint: "c".repeat(64),
      },
      findings: {
        status: "passed",
        releaseBlocking: 0,
        deterministicReleaseBlocking: 0,
        liveReleaseBlocking: 0,
      },
      workflowCoverage: [{
        criticality: "release-critical",
        deterministicStatus: "passed",
        authenticatedRequired: true,
        authenticatedStatus: "PASS",
      }],
    };

    const missingCi = releaseReadinessStatus({
      ...readyInputs,
      remoteCi: { status: "not-run" },
    });
    assert.strictEqual(missingCi.status, "blocked");
    assert.strictEqual(missingCi.verdict, "NOT TEAM-TEST READY");
    const failedCi = releaseReadinessStatus({
      ...readyInputs,
      remoteCi: { status: "failed" },
    });
    assert.strictEqual(failedCi.status, "failed");
    assert.strictEqual(failedCi.verdict, "NOT TEAM-TEST READY");
    const passed = releaseReadinessStatus({
      ...readyInputs,
      remoteCi: { status: "passed", completedAt: "2026-08-29T20:00:00.000Z" },
    });
    assert.strictEqual(passed.status, "passed");
    assert.strictEqual(passed.verdict, "TEAM-TEST READY");
    const predatesCi = releaseReadinessStatus({
      ...readyInputs,
      remoteCi: { status: "passed", completedAt: "2026-08-29T22:00:00.000Z" },
    });
    assert.strictEqual(predatesCi.status, "blocked");
    assert.strictEqual(predatesCi.verdict, "NOT TEAM-TEST READY");
  });

  test("derived status rejects unobserved PARTIAL and not-authorized rows", () => {
    const base = {
      schemaVersion: 4,
      source: SOURCE,
      candidate: null,
      inputPath: "internal_docs/quality/live-qualification.json",
      status: "partial",
      authenticatedAcceptance: "not-recorded",
      verdict: null,
      readinessTarget: null,
      targetPolicyFingerprint: null,
      readinessTarget: null,
      targetPolicyFingerprint: null,
      requiredWorkflowIds: ["WF-LIVE"],
      passedWorkflowIds: [],
      missingWorkflowIds: ["WF-LIVE"],
      workflowMatrix: [{
        id: "WF-LIVE",
        status: "PARTIAL",
        outcomeDisposition: "partial-evidence",
        candidateProvenance: "not-observed",
      }],
      attestationFingerprint: null,
      evidenceManifest: [{
        path: "internal_docs/quality/findings.jsonl",
        sha256: "4".repeat(64),
        capturedAt: new Date().toISOString(),
      }],
      findingsFingerprint: "4".repeat(64),
      openReleaseBlockerCount: 1,
      visibleEnabledActions: { status: "not-run", silentNoOpCount: null },
      reason: null,
      errors: [],
    };
    const findingsState = { fingerprint: "4".repeat(64), openReleaseBlockerCount: 1 };
    assert.ok(validateDerivedLiveStatus(base, ["WF-LIVE"], findingsState)
      .some(error => /outcome semantics/u.test(error)));

    const blocked = {
      ...base,
      status: "blocked",
      workflowMatrix: [{
        ...base.workflowMatrix[0],
        status: "BLOCKED",
        outcomeDisposition: "not-authorized",
      }],
    };
    assert.ok(validateDerivedLiveStatus(blocked, ["WF-LIVE"], findingsState)
      .some(error => /outcome semantics/u.test(error)));
  });

  test("derives finding closure layers independently of stale live status", () => {
    const deterministicFinding = {
      id: "QH-900",
      severity: "P2",
      domain: "product",
      status: "open",
      deterministicStatus: "fixed",
      liveStatus: "blocked",
      requiredEvidenceLayers: ["contract"],
      testLayerThatShouldHaveCaughtIt: "contract",
    };
    const liveFinding = {
      ...deterministicFinding,
      id: "QH-901",
      requiredEvidenceLayers: ["live-protocol"],
      testLayerThatShouldHaveCaughtIt: "live-protocol",
    };
    const workflow = { criticality: "release-critical" };

    assert.deepStrictEqual(
      deriveRequiredEvidenceLayers(deterministicFinding, TAXONOMY),
      ["contract"]
    );
    assert.strictEqual(findingRequiresLiveVerification(deterministicFinding, TAXONOMY), false);
    assert.strictEqual(deriveReleaseBlocking(deterministicFinding, workflow, TAXONOMY), false);
    assert.strictEqual(findingRequiresLiveVerification(liveFinding, TAXONOMY), true);
    assert.strictEqual(deriveReleaseBlocking(liveFinding, workflow, TAXONOMY), true);
  });

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

  test("contract verification binds the remote CI schema to its reviewed API evidence model", () => {
    const schemaPath = "quality/remote-ci.schema.json";
    const schema = fs.readFileSync(path.join(__dirname, "..", schemaPath), "utf8");
    const errors = verifyQualityContracts({
      sourceOverrides: {
        [schemaPath]: schema.replace("remote-ci-receipt-v2", "remote-ci-receipt-v1"),
      },
    }).errors;

    assert.ok(errors.includes(
      "Final-head remote CI schema must match the reviewed GitHub API evidence contract."
    ));
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
        requiredEvidenceLayers: ["live-protocol"],
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
        requiredEvidenceLayers: ["contract"],
        workflowContract: "WF-CORE",
        surface: "fixture",
        releaseBlocking: false,
      },
    ];

    const summary = summarizeFindings(findings, "passed", [], workflows, TAXONOMY);

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
      schemaVersion: 4,
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
        {
          id: "WF-LIVE-LAYER",
          status: "PARTIAL",
          outcomeDisposition: "partial-evidence",
          candidateProvenance: "verified",
        },
        {
          id: "WF-NO-LIVE-LAYER",
          status: "PASS",
          outcomeDisposition: "complete",
          candidateProvenance: "verified",
        },
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
    assert.strictEqual(report.releaseReadiness.verdict, "NOT TEAM-TEST READY");
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

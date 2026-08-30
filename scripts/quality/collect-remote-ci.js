// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const yauzl = require("yauzl");
const { ROOT, writeJson } = require("./common");
const { sourceIdentity } = require("./evidence");
const { verifyStagedBundleMatchesArchive } = require("./remote-signed-out-artifact");

const REPOSITORY = "cloudsmith-labs/cloudsmith-vscode-extension";
const API_OUTPUT = "internal_docs/quality/remote-ci-api.json";
const RECEIPT_OUTPUT = "internal_docs/quality/remote-ci.json";
const OUTPUTS = new Set([API_OUTPUT, RECEIPT_OUTPUT]);
const OUTPUT_OPTIONS = Object.freeze({ subtree: "internal_docs/quality" });
const MAX_API_BYTES = 16 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024;
const REMOTE_ARTIFACT_ROOT = ".quality/remote-ci";
const REMOTE_ARTIFACT_ARCHIVE = `${REMOTE_ARTIFACT_ROOT}/signed-out-ui.zip`;
const REMOTE_ARTIFACT_BUNDLE = `${REMOTE_ARTIFACT_ROOT}/signed-out-ui`;
const SIGNED_OUT_BUNDLE_NAMES = Object.freeze([
  "evidence.json", "result.json", "ui-candidate.json", "ui-candidate.vsix",
]);
const CODEQL_WORKFLOW_FILES = Object.freeze([
  ".github/workflows/codeql-analysis.yml",
  "dynamic/github-code-scanning/codeql",
]);
const WORKFLOWS = Object.freeze([
  Object.freeze({
    argument: "main-run",
    path: ".github/workflows/main.yml",
    event: "pull_request",
    name: "Deterministic build candidate",
    jobs: Object.freeze([
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
    ]),
  }),
  Object.freeze({
    argument: "codeql-run",
    paths: CODEQL_WORKFLOW_FILES,
    jobs: Object.freeze([
      ["analyze-actions", "Analyze (actions)"],
      ["analyze-javascript-typescript", "Analyze (javascript-typescript)"],
    ]),
  }),
]);

const USAGE = "Usage: collect-remote-ci.js --pr N --main-run ID --codeql-run ID";

function parseArguments(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!/^--(?:pr|main-run|codeql-run)$/u.test(name || "")
      || !/^[1-9][0-9]*$/u.test(value || "")
      || Object.prototype.hasOwnProperty.call(values, name.slice(2))) {
      throw new Error(USAGE);
    }
    values[name.slice(2)] = Number(value);
  }
  if (!Number.isSafeInteger(values.pr)
    || !Number.isSafeInteger(values["main-run"])
    || !Number.isSafeInteger(values["codeql-run"])) {
    throw new Error(USAGE);
  }
  return values;
}

function commandJson(command, args) {
  const output = execFileSync(command, args, {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: MAX_API_BYTES,
    stdio: ["ignore", "pipe", "inherit"],
  });
  if (Buffer.byteLength(output) > MAX_API_BYTES) throw new Error("GitHub API output is oversized.");
  return JSON.parse(output);
}

function commandBytes(command, args) {
  const output = execFileSync(command, args, {
    cwd: ROOT,
    encoding: null,
    maxBuffer: MAX_ARTIFACT_BYTES,
    stdio: ["ignore", "pipe", "inherit"],
  });
  if (!Buffer.isBuffer(output) || output.length === 0 || output.length > MAX_ARTIFACT_BYTES) {
    throw new Error("GitHub artifact archive is empty or oversized.");
  }
  return output;
}

function exactArtifactDigest(bytes, expectedDigest) {
  const actual = `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
  if (actual !== expectedDigest) {
    throw new Error("Downloaded signed-out UI artifact digest does not match GitHub metadata.");
  }
  return actual.slice("sha256:".length);
}

function extractArtifactArchive(bytes, destination) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(bytes, { lazyEntries: true, validateEntrySizes: true }, (openError, zip) => {
      if (openError || !zip) {
        reject(new Error("Downloaded signed-out UI artifact archive is invalid."));
        return;
      }
      const captured = new Map();
      let totalBytes = 0;
      const fail = error => {
        try { zip.close(); } catch {}
        reject(error instanceof Error ? error : new Error(String(error)));
      };
      zip.on("error", () => fail(new Error("Downloaded signed-out UI artifact archive is invalid.")));
      zip.on("entry", entry => {
        if (!SIGNED_OUT_BUNDLE_NAMES.includes(entry.fileName)
          || entry.fileName.includes("/")
          || captured.has(entry.fileName)
          || !Number.isSafeInteger(entry.uncompressedSize)
          || entry.uncompressedSize < 1
          || entry.uncompressedSize > MAX_ARTIFACT_BYTES) {
          fail(new Error("Downloaded signed-out UI artifact inventory is invalid."));
          return;
        }
        zip.openReadStream(entry, (streamError, stream) => {
          if (streamError || !stream) {
            fail(new Error("Downloaded signed-out UI artifact entry is unreadable."));
            return;
          }
          const chunks = [];
          let size = 0;
          stream.on("data", chunk => {
            size += chunk.length;
            if (size > entry.uncompressedSize || totalBytes + size > MAX_ARTIFACT_BYTES) {
              stream.destroy(new Error("Downloaded signed-out UI artifact is oversized."));
            } else chunks.push(chunk);
          });
          stream.on("error", () => fail(new Error("Downloaded signed-out UI artifact entry is invalid.")));
          stream.on("end", () => {
            if (size !== entry.uncompressedSize) {
              fail(new Error("Downloaded signed-out UI artifact entry size is invalid."));
              return;
            }
            totalBytes += size;
            captured.set(entry.fileName, Buffer.concat(chunks));
            zip.readEntry();
          });
        });
      });
      zip.on("end", () => {
        if (JSON.stringify([...captured.keys()].sort()) !== JSON.stringify(SIGNED_OUT_BUNDLE_NAMES)) {
          fail(new Error("Downloaded signed-out UI artifact inventory is incomplete."));
          return;
        }
        try {
          fs.mkdirSync(destination, { recursive: false, mode: 0o700 });
          for (const name of SIGNED_OUT_BUNDLE_NAMES) {
            fs.writeFileSync(path.join(destination, name), captured.get(name), {
              flag: "wx",
              mode: 0o600,
            });
          }
          resolve();
        } catch {
          fail(new Error("Downloaded signed-out UI artifact could not be staged safely."));
        } finally {
          for (const value of captured.values()) value.fill(0);
        }
      });
      zip.readEntry();
    });
  });
}

async function downloadSignedOutArtifact(artifact, source) {
  const bytes = commandBytes("gh", [
    "api", "--method", "GET",
    `repos/${REPOSITORY}/actions/artifacts/${String(artifact.artifactId)}/zip`,
  ]);
  try {
    const archiveSha256 = exactArtifactDigest(bytes, artifact.digest);
    const root = path.join(ROOT, REMOTE_ARTIFACT_ROOT);
    const archivePath = path.join(ROOT, REMOTE_ARTIFACT_ARCHIVE);
    const bundlePath = path.join(ROOT, REMOTE_ARTIFACT_BUNDLE);
    fs.mkdirSync(root, { recursive: true, mode: 0o700 });
    for (const target of [archivePath, bundlePath]) {
      if (!fs.existsSync(target)) continue;
      const stat = fs.lstatSync(target);
      if (stat.isSymbolicLink()) throw new Error("Remote signed-out evidence target is unsafe.");
      fs.rmSync(target, { recursive: stat.isDirectory(), force: false });
    }
    fs.writeFileSync(archivePath, bytes, { flag: "wx", mode: 0o600 });
    await extractArtifactArchive(bytes, bundlePath);
    const expectedMemberDigests = verifyStagedBundleMatchesArchive({
      archivePath,
      bundleRoot: bundlePath,
      expectedDigest: artifact.digest,
    });
    const { verifyDetachedSignedOutUiBundle } = require("./verify-ui-evidence");
    const verified = verifyDetachedSignedOutUiBundle({
      bundleRoot: bundlePath,
      contractRoot: ROOT,
      expectedMemberDigests,
      expectedSourceSha: source.sha,
    });
    return { archiveSha256, candidate: verified.candidate, fingerprint: verified.fingerprint };
  } finally {
    bytes.fill(0);
  }
}

function githubApi(endpoint, fields = []) {
  return commandJson("gh", [
    "api", "--method", "GET", endpoint,
    ...fields.flatMap(([name, value]) => ["-f", `${name}=${value}`]),
  ]);
}

function gitValue(args) {
  return execFileSync("git", args, {
    cwd: ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  }).trim();
}

function writeRemoteCiEvidence(relativePath, value, root = ROOT, writer = writeJson) {
  if (!OUTPUTS.has(relativePath)) {
    throw new Error("Remote CI evidence output is not an authorized ignored path.");
  }
  return writer(relativePath, value, root, OUTPUT_OPTIONS);
}

function canonicalRemoteTimestamp(value) {
  const milliseconds = Date.parse(value);
  if (typeof value !== "string" || !Number.isFinite(milliseconds)) {
    throw new Error("GitHub API returned an invalid timestamp.");
  }
  return new Date(milliseconds).toISOString();
}

function workflowPath(workflow, raw) {
  const value = raw?.path;
  if (workflow.path && value === workflow.path) return value;
  if (workflow.paths?.includes(value)) return value;
  throw new Error(`Unexpected ${workflow.argument} workflow path.`);
}

function workflowEvent(workflow, raw, pathValue) {
  if (workflow.event && raw?.event === workflow.event) return raw.event;
  if (workflow.argument === "codeql-run"
    && ((pathValue === "dynamic/github-code-scanning/codeql" && raw?.event === "dynamic")
      || (pathValue === ".github/workflows/codeql-analysis.yml"
        && raw?.event === "pull_request"))) {
    return raw.event;
  }
  throw new Error(`Unexpected ${workflow.argument} workflow event.`);
}

function latestByCompletion(values) {
  const timestamp = value => {
    const milliseconds = Date.parse(value);
    return Number.isFinite(milliseconds) ? milliseconds : Number.NEGATIVE_INFINITY;
  };
  return [...values].sort((left, right) => (
    (Math.max(timestamp(right.completed_at), timestamp(right.started_at))
      - Math.max(timestamp(left.completed_at), timestamp(left.started_at)))
    || (right.id - left.id)
  ))[0];
}

function latestWorkflowRun(values) {
  return [...values].sort((left, right) => (
    (Date.parse(right.updated_at) - Date.parse(left.updated_at))
    || (Date.parse(right.created_at) - Date.parse(left.created_at))
    || (right.id - left.id)
    || (right.run_attempt - left.run_attempt)
  ))[0];
}

function assertPullRequest(pull, source, branch, pullNumber) {
  if (pull?.number !== pullNumber
    || pull?.draft !== true
    || pull?.state !== "open"
    || pull?.base?.ref !== "main"
    || pull?.base?.repo?.full_name !== REPOSITORY
    || pull?.head?.ref !== branch
    || pull?.head?.sha !== source.sha
    || pull?.head?.repo?.full_name !== REPOSITORY
    || pull?.html_url !== `https://github.com/${REPOSITORY}/pull/${String(pull?.number)}`) {
    throw new Error("The GitHub API did not return the exact draft pull request.");
  }
}

function assertWorkflowRun(snapshot, workflow, raw, pathValue, source, branch, pull) {
  const dynamicCodeql = pathValue === "dynamic/github-code-scanning/codeql";
  const expectedHeadBranch = dynamicCodeql ? `refs/pull/${String(pull.number)}/head` : branch;
  const validName = workflow.name
    ? raw.name === workflow.name
    : dynamicCodeql
      ? raw.name === `PR #${String(pull.number)}`
      : typeof raw.name === "string"
        && raw.name.length > 0
        && raw.name.length <= 255
        && !/[\u0000-\u001f\u007f]/u.test(raw.name);
  const matching = (snapshot.runListsByWorkflow?.[pathValue]?.workflow_runs || []).filter(run => (
    run?.path === pathValue
      && run?.event === raw.event
      && run?.head_sha === source.sha
      && run?.head_branch === expectedHeadBranch
      && run?.head_repository?.full_name === REPOSITORY
  ));
  const latest = latestWorkflowRun(matching);
  const pullBound = dynamicCodeql
    ? (raw.pull_requests || []).length === 0
    : (raw.pull_requests || []).some(item => item?.number === pull.number);
  if (!validName
    || latest?.id !== raw.id
    || latest?.run_attempt !== raw.run_attempt
    || raw.head_sha !== source.sha
    || raw.head_branch !== expectedHeadBranch
    || raw.head_repository?.full_name !== REPOSITORY
    || raw.status !== "completed"
    || raw.conclusion !== "success"
    || !Number.isInteger(raw.run_attempt) || raw.run_attempt < 1
    || !pullBound
    || raw.html_url !== `https://github.com/${REPOSITORY}/actions/runs/${String(raw.id)}`) {
    throw new Error(`The ${workflow.argument} run is not the latest successful exact-head run.`);
  }
  const rawJobs = snapshot.jobsByRunId?.[String(raw.id)]?.jobs;
  if (!Array.isArray(rawJobs) || rawJobs.length !== workflow.jobs.length) {
    throw new Error(`The ${workflow.argument} job inventory is incomplete.`);
  }
  const expectedNames = new Set(workflow.jobs.map(([, name]) => name));
  if (rawJobs.some(job => !expectedNames.has(job?.name)
    || !Number.isSafeInteger(job?.id) || job.id < 1
    || job?.run_attempt !== raw.run_attempt
    || job?.status !== "completed"
    || job?.conclusion !== "success")
    || new Set(rawJobs.map(job => job.name)).size !== workflow.jobs.length) {
    throw new Error(`The ${workflow.argument} job inventory is not exact and successful.`);
  }
}

function codeqlAggregate(snapshot, source, pullNumber) {
  const matching = (snapshot.checkRunsForRef?.check_runs || []).filter(check => (
    check?.name === "CodeQL"
      && check?.app?.slug === "github-advanced-security"
      && check?.head_sha === source.sha
  ));
  const check = latestByCompletion(matching);
  if (!check
    || !Number.isSafeInteger(check.id) || check.id < 1
    || !(check.pull_requests || []).some(item => item?.number === pullNumber)
    || check.status !== "completed"
    || check.conclusion !== "success"
    || check.output?.annotations_count !== 0
    || check.output?.title !== "No new alerts in code changed by this pull request"
    || check.html_url !== `https://github.com/${REPOSITORY}/runs/${String(check.id)}`) {
    throw new Error("The exact-head CodeQL aggregate check is missing or not successful.");
  }
  return {
    databaseId: check.id,
    name: check.name,
    appSlug: check.app.slug,
    headSha: check.head_sha,
    status: check.status,
    conclusion: check.conclusion,
    startedAt: canonicalRemoteTimestamp(check.started_at),
    completedAt: canonicalRemoteTimestamp(check.completed_at),
    annotationsCount: check.output?.annotations_count,
    title: check.output?.title,
    url: check.html_url,
  };
}

function signedOutUiArtifact(snapshot, source, branch, mainRun) {
  const expectedName = `signed-out-ui-evidence-${source.sha}-${String(mainRun.run_attempt)}`;
  const matches = (snapshot.artifactsByRunId?.[String(mainRun.id)]?.artifacts || [])
    .filter(artifact => artifact?.name === expectedName);
  if (matches.length !== 1) {
    throw new Error("The exact signed-out UI artifact reference is missing or ambiguous.");
  }
  const artifact = matches[0];
  const repositoryId = snapshot.pullRequest?.head?.repo?.id;
  const uiJob = snapshot.jobsByRunId?.[String(mainRun.id)]?.jobs
    ?.find(job => job?.name === "Signed-out packaged black-box UI");
  if (!/^sha256:[a-f0-9]{64}$/u.test(artifact.digest || "")
    || !Number.isSafeInteger(artifact.id) || artifact.id < 1
    || !Number.isSafeInteger(artifact.size_in_bytes) || artifact.size_in_bytes < 1
    || artifact.expired !== false
    || artifact.workflow_run?.id !== mainRun.id
    || artifact.workflow_run?.head_sha !== source.sha
    || artifact.workflow_run?.head_branch !== branch
    || artifact.workflow_run?.repository_id !== repositoryId
    || artifact.workflow_run?.head_repository_id !== repositoryId
    || Date.parse(artifact.created_at) < Date.parse(uiJob?.started_at)
    || Date.parse(artifact.updated_at) > Date.parse(uiJob?.completed_at)) {
    throw new Error("The signed-out UI artifact metadata does not bind the exact run attempt.");
  }
  return {
    artifactId: artifact.id,
    name: artifact.name,
    digest: artifact.digest,
    sizeBytes: artifact.size_in_bytes,
    expired: artifact.expired,
    createdAt: canonicalRemoteTimestamp(artifact.created_at),
    updatedAt: canonicalRemoteTimestamp(artifact.updated_at),
    runId: mainRun.id,
    runAttempt: mainRun.run_attempt,
    headSha: source.sha,
    branch,
  };
}

function buildReceipt(snapshot, source, branch, pullNumber, runIds) {
  const pull = snapshot.pullRequest;
  assertPullRequest(pull, source, branch, pullNumber);
  const runs = WORKFLOWS.map((workflow, index) => {
    const raw = snapshot.runs[index];
    const rawJobs = snapshot.jobsByRunId[String(raw.id)]?.jobs || [];
    if (raw.id !== runIds[index]) throw new Error(`Unexpected ${workflow.argument} run ID.`);
    const pathValue = workflowPath(workflow, raw);
    workflowEvent(workflow, raw, pathValue);
    assertWorkflowRun(snapshot, workflow, raw, pathValue, source, branch, pull);
    return {
      workflowFile: pathValue,
      workflowName: workflow.name || raw.name,
      event: raw.event,
      runId: raw.id,
      runAttempt: raw.run_attempt,
      pullRequestNumber: pull.number,
      headSha: raw.head_sha,
      status: raw.status,
      conclusion: raw.conclusion,
      createdAt: canonicalRemoteTimestamp(raw.created_at),
      completedAt: canonicalRemoteTimestamp(raw.updated_at),
      url: raw.html_url,
      jobs: workflow.jobs.map(([id, name]) => {
        const job = rawJobs.find(item => item.name === name);
        if (!job) throw new Error(`GitHub run ${raw.id} is missing job ${name}.`);
        return {
          id,
          name,
          databaseId: job.id,
          status: job.status,
          conclusion: job.conclusion,
          startedAt: canonicalRemoteTimestamp(job.started_at),
          completedAt: canonicalRemoteTimestamp(job.completed_at),
        };
      }),
    };
  });
  return {
    schemaVersion: 2,
    repository: REPOSITORY,
    branch,
    sourceSha: source.sha,
    sourceFingerprint: source.fingerprint,
    capturedAt: snapshot.capturedAt,
    pullRequest: {
      number: pull.number,
      draft: pull.draft,
      state: pull.state,
      baseRef: pull.base?.ref,
      headRef: pull.head?.ref,
      headSha: pull.head?.sha,
      url: pull.html_url,
    },
    runs,
    codeqlAggregate: codeqlAggregate(snapshot, source, pull.number),
    signedOutUiArtifact: signedOutUiArtifact(snapshot, source, branch, snapshot.runs[0]),
    evidence: null,
  };
}

async function main(argv = process.argv.slice(2)) {
  const args = parseArguments(argv);
  if (gitValue(["status", "--porcelain", "--untracked-files=all"]) !== "") {
    throw new Error("Remote CI collection requires a clean tracked source tree.");
  }
  const source = sourceIdentity(ROOT);
  const branch = gitValue(["branch", "--show-current"]);
  const pullRequest = githubApi(`repos/${REPOSITORY}/pulls/${args.pr}`);
  const runs = WORKFLOWS.map(workflow => githubApi(
    `repos/${REPOSITORY}/actions/runs/${args[workflow.argument]}`,
  ));
  const jobsByRunId = Object.fromEntries(runs.map(run => [
    String(run.id),
    githubApi(`repos/${REPOSITORY}/actions/runs/${run.id}/jobs`, [["per_page", 100]]),
  ]));
  const workflowPaths = WORKFLOWS.map((workflow, index) => workflowPath(workflow, runs[index]));
  const runListsByWorkflow = Object.fromEntries(WORKFLOWS.map((workflow, index) => {
    const pathValue = workflowPaths[index];
    const endpoint = pathValue.startsWith(".github/workflows/")
      ? `repos/${REPOSITORY}/actions/workflows/${pathValue.split("/").pop()}/runs`
      : `repos/${REPOSITORY}/actions/runs`;
    const fields = [
      ["event", runs[index].event], ["head_sha", source.sha], ["per_page", 100],
    ];
    if (runs[index].event === "pull_request") fields.unshift(["branch", branch]);
    return [pathValue, githubApi(endpoint, fields)];
  }));
  const checkRunsForRef = githubApi(`repos/${REPOSITORY}/commits/${source.sha}/check-runs`, [
    ["filter", "latest"], ["per_page", 100],
  ]);
  const artifactsByRunId = {
    [String(runs[0].id)]: githubApi(
      `repos/${REPOSITORY}/actions/runs/${runs[0].id}/artifacts`,
      [["per_page", 100]],
    ),
  };
  const snapshot = {
    schemaVersion: 1,
    repository: REPOSITORY,
    capturedAt: new Date().toISOString(),
    pullRequest,
    runs,
    jobsByRunId,
    runListsByWorkflow,
    checkRunsForRef,
    artifactsByRunId,
  };
  writeRemoteCiEvidence(API_OUTPUT, snapshot, ROOT);
  const evidenceBytes = fs.readFileSync(`${ROOT}/${API_OUTPUT}`);
  if (evidenceBytes.length === 0 || evidenceBytes.length > MAX_API_BYTES) {
    throw new Error("GitHub API evidence capture is empty or oversized.");
  }
  const receipt = buildReceipt(
    snapshot,
    source,
    branch,
    args.pr,
    [args["main-run"], args["codeql-run"]],
  );
  receipt.evidence = {
    path: API_OUTPUT,
    sha256: crypto.createHash("sha256").update(evidenceBytes).digest("hex"),
  };
  await downloadSignedOutArtifact(receipt.signedOutUiArtifact, source);
  if (gitValue(["status", "--porcelain", "--untracked-files=all"]) !== "") {
    throw new Error("Tracked source changed while remote CI evidence was collected.");
  }
  writeRemoteCiEvidence(RECEIPT_OUTPUT, receipt, ROOT);
  console.log(`Captured authoritative remote CI for ${source.sha}.`);
}

if (require.main === module) {
  main().catch(error => {
    console.error(`quality:remote-ci:collect: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = {
  buildReceipt,
  downloadSignedOutArtifact,
  exactArtifactDigest,
  extractArtifactArchive,
  main,
  parseArguments,
  writeRemoteCiEvidence,
};

// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const { execFileSync } = require("child_process");
const { ROOT, writeJson } = require("./common");
const { sourceIdentity } = require("./evidence");

const REPOSITORY = "cloudsmith-labs/cloudsmith-vscode-extension";
const API_OUTPUT = "internal_docs/quality/remote-ci-api.json";
const RECEIPT_OUTPUT = "internal_docs/quality/remote-ci.json";
const MAX_API_BYTES = 16 * 1024 * 1024;
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
      ["build-candidate", "Deterministic build candidate"],
    ]),
  }),
  Object.freeze({
    argument: "deep-run",
    path: ".github/workflows/deep-quality.yml",
    event: "workflow_dispatch",
    name: "Manual deep quality",
    jobs: Object.freeze([
      ["core-mutation", "Core mutation"],
      ["signed-out-black-box-ui", "Signed-out packaged black-box UI"],
      ["authenticated-production-ui", "Authenticated packaged production UI"],
    ]),
  }),
]);

function parseArguments(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!/^--(?:pr|main-run|deep-run)$/u.test(name || "") || !/^[1-9][0-9]*$/u.test(value || "")) {
      throw new Error("Usage: collect-remote-ci.js --pr N --main-run ID --deep-run ID");
    }
    values[name.slice(2)] = Number(value);
  }
  if (!Number.isSafeInteger(values.pr)
    || !Number.isSafeInteger(values["main-run"])
    || !Number.isSafeInteger(values["deep-run"])) {
    throw new Error("Usage: collect-remote-ci.js --pr N --main-run ID --deep-run ID");
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

function buildReceipt(snapshot, source, branch, runIds) {
  const pull = snapshot.pullRequest;
  const runs = WORKFLOWS.map((workflow, index) => {
    const raw = snapshot.runs[index];
    const rawJobs = snapshot.jobsByRunId[String(raw.id)]?.jobs || [];
    if (raw.id !== runIds[index]) throw new Error(`Unexpected ${workflow.path} run ID.`);
    return {
      workflowFile: workflow.path,
      workflowName: workflow.name,
      event: workflow.event,
      runId: raw.id,
      runAttempt: raw.run_attempt,
      pullRequestNumber: index === 0 ? pull.number : null,
      headSha: raw.head_sha,
      status: raw.status,
      conclusion: raw.conclusion,
      createdAt: raw.created_at,
      completedAt: raw.updated_at,
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
          startedAt: job.started_at,
          completedAt: job.completed_at,
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
    evidence: null,
  };
}

function main(argv = process.argv.slice(2)) {
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
  const runListsByWorkflow = Object.fromEntries(WORKFLOWS.map(workflow => [
    workflow.path,
    githubApi(`repos/${REPOSITORY}/actions/workflows/${workflow.path.split("/").pop()}/runs`, [
      ["branch", branch], ["event", workflow.event], ["head_sha", source.sha], ["per_page", 100],
    ]),
  ]));
  const snapshot = {
    schemaVersion: 1,
    repository: REPOSITORY,
    capturedAt: new Date().toISOString(),
    pullRequest,
    runs,
    jobsByRunId,
    runListsByWorkflow,
  };
  writeJson(API_OUTPUT, snapshot, ROOT);
  const evidenceBytes = fs.readFileSync(`${ROOT}/${API_OUTPUT}`);
  const receipt = buildReceipt(
    snapshot,
    source,
    branch,
    [args["main-run"], args["deep-run"]],
  );
  receipt.evidence = {
    path: API_OUTPUT,
    sha256: crypto.createHash("sha256").update(evidenceBytes).digest("hex"),
  };
  if (gitValue(["status", "--porcelain", "--untracked-files=all"]) !== "") {
    throw new Error("Tracked source changed while remote CI evidence was collected.");
  }
  writeJson(RECEIPT_OUTPUT, receipt, ROOT);
  console.log(`Captured authoritative remote CI for ${source.sha}.`);
}

if (require.main === module) main();

module.exports = { buildReceipt, main, parseArguments };

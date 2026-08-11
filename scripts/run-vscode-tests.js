// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const { spawnSync } = require("child_process");

const root = path.resolve(__dirname, "..");
const isWindows = process.platform === "win32";
const cli = path.join(
  root,
  "node_modules",
  ".bin",
  isWindows ? "vscode-test.cmd" : "vscode-test",
);
const zeroProbe = process.argv.includes("--zero-probe");
const labelIndex = process.argv.indexOf("--label");
const label = labelIndex === -1 ? (process.env.VSCODE_TEST_LABEL || "core") : process.argv[labelIndex + 1];

if (!label || !["core", "smoke", "live"].includes(label)) {
  throw new Error("The VS Code test label must be core, smoke, or live");
}
if (label === "live" && !process.env.CLOUDSMITH_TEST_API_KEY) {
  throw new Error("CLOUDSMITH_TEST_API_KEY is required for the optional live test suite");
}

const cliArguments = [
  "--label",
  label,
  "--fail-zero",
  "--forbid-only",
  ...(label !== "live" ? ["--forbid-pending"] : []),
  ...(zeroProbe ? ["--grep", "__m9_zero_test_probe_no_match__"] : []),
];

let command = cli;
let commandArguments = cliArguments;
if (process.platform === "linux") {
  const preflight = spawnSync("xvfb-run", ["--help"], { encoding: "utf8" });
  if (preflight.error || preflight.status !== 0) {
    throw new Error("xvfb-run is required to execute VS Code extension tests on Linux");
  }
  command = "xvfb-run";
  commandArguments = ["-a", cli, ...cliArguments];
}

const result = spawnSync(command, commandArguments, {
  cwd: root,
  encoding: zeroProbe ? "utf8" : undefined,
  env: process.env,
  shell: isWindows,
  stdio: zeroProbe ? "pipe" : "inherit",
});

if (!zeroProbe) {
  if (result.error) {
    throw result.error;
  }
  if (result.signal) {
    console.error(`VS Code tests terminated by signal ${result.signal}`);
    process.exit(1);
  }
  process.exit(result.status ?? 1);
}

const output = `${result.stdout || ""}${result.stderr || ""}`;
process.stdout.write(output);
if (result.error || result.signal || result.status !== 1) {
  throw new Error("Zero-test probe did not produce Mocha's expected failure status");
}
if (!/\b0 passing\b/.test(output) || !/\b1 test failed\b/.test(output)) {
  throw new Error("Zero-test probe failed before reaching Mocha's fail-zero guard");
}
console.log("Confirmed that the real test entrypoint rejects a zero-test run.");

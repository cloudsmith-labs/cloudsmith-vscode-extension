// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const { spawnSync } = require("child_process");
const { LIVE_REQUIRED_ENV, SSO_LIVE_REQUIRED_ENV } = require("../test/testInventories");

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

if (!label || !["core", "smoke", "live", "sso-live"].includes(label)) {
  throw new Error("The VS Code test label must be core, smoke, live, or sso-live");
}
if (label === "sso-live") {
  const missing = SSO_LIVE_REQUIRED_ENV.filter(name => !process.env[name]);
  if (missing.length > 0) {
    throw new Error(`SSO live test configuration is incomplete; set: ${missing.join(", ")}`);
  }
}
if (label === "live") {
  if (process.env.CLOUDSMITH_LIVE_TESTS !== "1") {
    throw new Error("Set CLOUDSMITH_LIVE_TESTS=1 to explicitly opt in to the optional live test suite");
  }
  const missing = LIVE_REQUIRED_ENV.filter(name => !process.env[name]);
  if (missing.length > 0) {
    throw new Error(`Live test configuration is incomplete; set: ${missing.join(", ")}`);
  }
}

const cliArguments = [
  "--label",
  label,
  "--fail-zero",
  "--forbid-only",
  "--forbid-pending",
  ...(zeroProbe ? ["--grep", "__m9_zero_test_probe_no_match__"] : []),
];

let command = cli;
let commandArguments = cliArguments;
if (process.platform === "linux") {
  const preflight = spawnSync("sh", ["-c", "command -v xvfb-run"], { encoding: "utf8" });
  const xvfbRun = preflight.stdout?.trim();
  if (preflight.error || preflight.status !== 0 || !path.isAbsolute(xvfbRun)) {
    throw new Error("xvfb-run is required to execute VS Code extension tests on Linux");
  }
  command = xvfbRun;
  commandArguments = ["-a", cli, ...cliArguments];
}

if (!zeroProbe) {
  // Electron is unstable under an intermediate Node process on some macOS
  // hosts. Replace this launcher on POSIX so vscode-test owns the terminal and
  // signals directly. Windows has no execve support, so use the native .cmd
  // shim there.
  if (!isWindows) {
    process.chdir(root);
    process.execve(command, [command, ...commandArguments], process.env);
    throw new Error("Failed to replace the VS Code test launcher");
  }
  const result = spawnSync(command, commandArguments, {
    cwd: root,
    env: process.env,
    shell: true,
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.signal) {
    console.error(`VS Code tests terminated by signal ${result.signal}`);
    process.exit(1);
  }
  process.exit(result.status ?? 1);
}

const result = spawnSync(command, commandArguments, {
  cwd: root,
  encoding: "utf8",
  env: process.env,
  shell: isWindows,
  stdio: "pipe",
});
const output = `${result.stdout || ""}${result.stderr || ""}`;
process.stdout.write(output);
if (result.error || result.signal || result.status !== 1) {
  throw new Error("Zero-test probe did not produce Mocha's expected failure status");
}
if (!/\b0 passing\b/.test(output) || !/\b1 test failed\b/.test(output)) {
  throw new Error("Zero-test probe failed before reaching Mocha's fail-zero guard");
}
console.log("Confirmed that the real test entrypoint rejects a zero-test run.");

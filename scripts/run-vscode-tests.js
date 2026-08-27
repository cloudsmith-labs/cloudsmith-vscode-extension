// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const { spawnSync } = require("child_process");
const {
  QUALIFICATION_REQUIRED_ENV,
  assertCredentialFreeRequiredEnvironment,
  createIsolatedQualificationRoot,
  exportIsolatedQualificationRoot,
  removeIsolatedQualificationRoot,
  sanitizeQualificationEnvironment,
} = require("../test/testInventories");

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

if (!label || !["core", "smoke"].includes(label)) {
  throw new Error("The VS Code qualification label must be core or smoke; credential-bearing live automation is excluded");
}
assertCredentialFreeRequiredEnvironment(QUALIFICATION_REQUIRED_ENV);
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
  const preflight = spawnSync("/bin/sh", ["-c", "command -v xvfb-run"], {
    encoding: "utf8",
    env: { PATH: process.env.PATH || "/usr/local/bin:/usr/bin:/bin" },
  });
  const xvfbRun = preflight.stdout?.trim();
  if (preflight.error || preflight.status !== 0 || !path.isAbsolute(xvfbRun)) {
    throw new Error("xvfb-run is required to execute VS Code extension tests on Linux");
  }
  command = xvfbRun;
  commandArguments = ["-a", cli, ...cliArguments];
}

const isolatedHome = createIsolatedQualificationRoot(label);
let qualificationEnvironment;
try {
  const isolatedHomeProof = exportIsolatedQualificationRoot(isolatedHome);
  qualificationEnvironment = Object.freeze({
    ...sanitizeQualificationEnvironment(process.env, isolatedHome),
    VSCODE_TEST_LABEL: label,
    CLOUDSMITH_QUALITY_LAUNCHER_HOME: isolatedHome,
    CLOUDSMITH_QUALITY_LAUNCHER_PROOF: isolatedHomeProof,
  });
} catch (error) {
  removeIsolatedQualificationRoot(isolatedHome);
  throw error;
}

function cleanupLauncherHome() {
  removeIsolatedQualificationRoot(isolatedHome);
}

if (!zeroProbe) {
  // Electron is unstable under an intermediate Node process on some macOS
  // hosts. Replace this launcher on POSIX so vscode-test owns the terminal and
  // signals directly. Windows has no execve support, so use the native .cmd
  // shim there.
  if (!isWindows) {
    process.chdir(root);
    try {
      process.execve(command, [command, ...commandArguments], qualificationEnvironment);
      throw new Error("Failed to replace the VS Code test launcher");
    } finally {
      cleanupLauncherHome();
    }
  }
  let result;
  try {
    result = spawnSync(command, commandArguments, {
      cwd: root,
      env: qualificationEnvironment,
      shell: true,
      stdio: "inherit",
    });
  } finally {
    cleanupLauncherHome();
  }
  if (result.error) throw result.error;
  if (result.signal) {
    console.error(`VS Code tests terminated by signal ${result.signal}`);
    process.exit(1);
  }
  process.exit(result.status ?? 1);
}

let result;
try {
  result = spawnSync(command, commandArguments, {
    cwd: root,
    encoding: "utf8",
    env: qualificationEnvironment,
    shell: isWindows,
    stdio: "pipe",
  });
} finally {
  cleanupLauncherHome();
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

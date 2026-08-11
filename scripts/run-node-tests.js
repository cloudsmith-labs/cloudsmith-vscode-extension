// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const fs = require("fs");
const { spawnSync } = require("child_process");
const { STANDALONE_NODE_TESTS } = require("../test/testInventories");

const root = path.resolve(__dirname, "..");
const PINNED_MOCHA_VERSION = "11.8.0";
const PINNED_OWNER_VERSION = "0.0.15";
const PINNED_OWNER_MOCHA_RANGE = "^11.7.6";
const ownerManifest = JSON.parse(fs.readFileSync(
  path.join(root, "node_modules", "@vscode", "test-cli", "package.json"),
  "utf8"
));
if (
  ownerManifest.version !== PINNED_OWNER_VERSION
  || ownerManifest.dependencies?.mocha !== PINNED_OWNER_MOCHA_RANGE
) {
  throw new Error("The pinned VS Code test CLI no longer owns the expected Mocha dependency");
}
const mochaManifestPath = require.resolve("mocha/package.json", { paths: [root] });
const mochaManifest = require(mochaManifestPath);
if (mochaManifest.version !== PINNED_MOCHA_VERSION) {
  throw new Error(`Expected Mocha ${PINNED_MOCHA_VERSION}, found ${mochaManifest.version}`);
}
const mocha = path.join(path.dirname(mochaManifestPath), "bin", "mocha.js");
const zeroProbe = process.argv.includes("--zero-probe");
const args = [
  "--fail-zero",
  "--forbid-only",
  "--forbid-pending",
  "--ui", "tdd",
  "--timeout", "20000",
  ...(zeroProbe ? ["--grep", "__m10_node_zero_test_probe_no_match__"] : []),
  ...STANDALONE_NODE_TESTS,
];
const result = spawnSync(process.execPath, [mocha, ...args], {
  cwd: root,
  encoding: zeroProbe ? "utf8" : undefined,
  stdio: zeroProbe ? "pipe" : "inherit",
});

if (!zeroProbe) {
  if (result.error) throw result.error;
  if (result.signal) {
    console.error(`Node tests terminated by signal ${result.signal}`);
    process.exit(1);
  }
  process.exit(result.status ?? 1);
}

const output = `${result.stdout || ""}${result.stderr || ""}`;
process.stdout.write(output);
if (result.error || result.signal || result.status !== 1) {
  throw new Error("Node zero-test probe did not produce Mocha's expected failure status");
}
if (!/\b0 passing\b/.test(output)) {
  throw new Error("Node zero-test probe failed before reaching Mocha's fail-zero guard");
}
console.log("Confirmed that the standalone Node test entrypoint rejects a zero-test run.");

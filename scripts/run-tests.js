// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const { spawnSync } = require("child_process");
const { CREDENTIAL_BOUNDARY_SKIP_REASON } = require("../test/testInventories");

const root = path.resolve(__dirname, "..");
const label = process.env.VSCODE_TEST_LABEL || "core";
const zeroProbe = process.argv.includes("--zero-probe");
if (label === "live") {
  throw new Error("Use npm run test:live for the optional live Cloudsmith suite");
}
if (!new Set(["core", "smoke"]).has(label)) {
  throw new Error("VSCODE_TEST_LABEL must be core or smoke for the default test gate");
}

function run(script, args = []) {
  const result = spawnSync(process.execPath, [path.join(root, "scripts", script), ...args], {
    cwd: root,
    env: process.env,
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.signal) {
    console.error(`${script} terminated by signal ${result.signal}`);
    process.exit(1);
  }
  if (result.status !== 0) process.exit(result.status ?? 1);
}

run("run-node-tests.js", zeroProbe ? ["--zero-probe"] : []);
run("run-vscode-tests.js", ["--label", label, ...(zeroProbe ? ["--zero-probe"] : [])]);
if (!zeroProbe) console.log(`Live automation excluded: ${CREDENTIAL_BOUNDARY_SKIP_REASON}`);

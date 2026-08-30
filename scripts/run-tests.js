// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const { spawnSync } = require("child_process");
const { CREDENTIAL_BOUNDARY_SKIP_REASON } = require("../test/testInventories");

const root = path.resolve(__dirname, "..");

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

function testPlan({ label = "core", zeroProbe = false, nodeTestMode = "full" } = {}) {
  if (label === "live") {
    throw new Error("Use npm run test:live for the optional live Cloudsmith suite");
  }
  if (!new Set(["core", "smoke"]).has(label)) {
    throw new Error("VSCODE_TEST_LABEL must be core or smoke for the default test gate");
  }
  if (!new Set(["full", "host", "none"]).has(nodeTestMode)) {
    throw new Error("nodeTestMode must be full, host, or none");
  }
  const probeArguments = zeroProbe ? ["--zero-probe"] : [];
  return Object.freeze([
    ...(nodeTestMode !== "none"
      ? [Object.freeze({
        script: "run-node-tests.js",
        args: Object.freeze([
          ...(nodeTestMode === "host" ? ["--host"] : []),
          ...probeArguments,
        ]),
      })]
      : []),
    Object.freeze({
      script: "run-vscode-tests.js",
      args: Object.freeze(["--label", label, ...probeArguments]),
    }),
  ]);
}

if (require.main === module) {
  const label = process.env.VSCODE_TEST_LABEL || "core";
  const zeroProbe = process.argv.includes("--zero-probe");
  const extensionMatrix = process.argv.includes("--extension-matrix");
  const matrixNodeSetting = process.env.CLOUDSMITH_RUN_NODE_TESTS;
  if (extensionMatrix && !new Set(["true", "host", "false"]).has(matrixNodeSetting)) {
    throw new Error("The extension matrix must declare CLOUDSMITH_RUN_NODE_TESTS exactly");
  }
  const nodeTestMode = !extensionMatrix || matrixNodeSetting === "true"
    ? "full"
    : matrixNodeSetting === "host"
      ? "host"
      : "none";
  for (const step of testPlan({ label, zeroProbe, nodeTestMode })) {
    run(step.script, step.args);
  }
  if (!zeroProbe) {
    console.log(`Deterministic live-suite boundary: ${CREDENTIAL_BOUNDARY_SKIP_REASON}`);
  }
}

module.exports = { testPlan };

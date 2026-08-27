// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { ROOT, writeJson } = require("./common");
const { sourceIdentity } = require("./evidence");

const RESULT_PATH = ".quality/ui/result.json";
const BLOCKED_REASON = "Production activation reads VS Code SecretStorage; automated UI qualification is not authorized.";

function receipt(status, values = {}) {
  const source = sourceIdentity(ROOT);
  return {
    schemaVersion: 1,
    status,
    source,
    sourceSha: source.sha,
    tool: null,
    toolVersion: null,
    vscodeVersion: null,
    platform: null,
    architecture: null,
    launchAttempted: false,
    tests: [],
    results: [],
    reason: null,
    ...values,
  };
}

async function runUiSmoke() {
  const result = receipt("blocked", { reason: BLOCKED_REASON });
  writeJson(RESULT_PATH, result);
  const error = new Error(`UI smoke blocked: ${BLOCKED_REASON}`);
  error.code = "UI_SECRET_BOUNDARY_BLOCKED";
  throw error;
}

if (require.main === module) {
  runUiSmoke().catch(error => {
    console.error(error?.message || String(error));
    process.exitCode = error.code === "UI_SECRET_BOUNDARY_BLOCKED" ? 2 : 1;
  });
}

module.exports = { runUiSmoke };

// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const fs = require("fs");
const {
  ROOT,
  readJson,
  resolveExistingRepositoryFile,
} = require("./common");
const { sourceIdentity } = require("./evidence");
const {
  UI_CANDIDATE_ARTIFACT,
  UI_CANDIDATE_RECEIPT,
  candidateBindingFromReceipt,
} = require("./candidate-binding");
const {
  expectedBlackBoxUiTests,
  validateUiResult,
} = require("./report");

const CANDIDATE_RECEIPT = UI_CANDIDATE_RECEIPT;
const UI_RESULT = ".quality/ui/result.json";
const MAX_EVIDENCE_BYTES = 2 * 1024 * 1024;

function readBoundedJson(relativePath, root, subtree) {
  const target = resolveExistingRepositoryFile(relativePath, root, { subtree });
  const stat = fs.lstatSync(target);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_EVIDENCE_BYTES) {
    throw new Error("Signed-out UI evidence must be a bounded regular file.");
  }
  return JSON.parse(fs.readFileSync(target, "utf8"));
}

function verifySignedOutUiEvidence(options = {}) {
  const root = options.root || ROOT;
  const source = options.source || sourceIdentity(root);
  const manifest = options.manifest || readJson("package.json", root);
  const workflows = options.workflows || readJson("quality/critical-workflows.json", root);
  const candidateReceipt = options.candidateReceipt || readBoundedJson(
    CANDIDATE_RECEIPT,
    root,
    ".quality/qualification"
  );
  const ui = options.ui || readBoundedJson(UI_RESULT, root, ".quality/ui");
  try {
    const artifactPath = options.candidateArtifactPath || resolveExistingRepositoryFile(
      UI_CANDIDATE_ARTIFACT,
      root,
      { subtree: ".quality/qualification" }
    );
    candidateBindingFromReceipt(candidateReceipt, {
      root,
      source,
      artifactPath,
    });
  } catch {
    throw new Error("Signed-out UI evidence does not bind the exact verified candidate.");
  }
  const errors = validateUiResult(
    ui,
    source,
    expectedBlackBoxUiTests(workflows),
    {
      candidateReceipt,
      extensionId: `${manifest.publisher}.${manifest.name}`,
      extensionVersion: manifest.version,
    }
  );
  if (ui.status !== "passed" || errors.length > 0) {
    throw new Error("Signed-out UI evidence does not bind the exact verified candidate.");
  }
  return Object.freeze({
    status: "passed",
    sourceSha: source.sha,
    testCount: ui.results.length,
  });
}

function main() {
  try {
    const result = verifySignedOutUiEvidence();
    console.log(`Signed-out UI evidence verified: ${result.testCount} passed tests.`);
  } catch {
    console.error("Signed-out UI evidence verification failed closed.");
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  CANDIDATE_RECEIPT,
  UI_RESULT,
  verifySignedOutUiEvidence,
};

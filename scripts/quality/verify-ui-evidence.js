// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const fs = require("fs");
const crypto = require("crypto");
const path = require("path");
const { TextDecoder } = require("util");
const {
  ROOT,
  isPlainObject,
  readJson,
  resolveExistingRepositoryFile,
} = require("./common");
const { fingerprint, sourceIdentity } = require("./evidence");
const {
  UI_CANDIDATE_ARTIFACT,
  UI_CANDIDATE_RECEIPT,
  candidateBindingFromReceipt,
  digestStableSingleLinkFile,
  sameExactFileIdentity,
  withStableSingleLinkFile,
} = require("./candidate-binding");
const {
  expectedBlackBoxUiTests,
  validateUiResult,
} = require("./report");

const CANDIDATE_RECEIPT = UI_CANDIDATE_RECEIPT;
const UI_RESULT = ".quality/ui/result.json";
const MAX_EVIDENCE_BYTES = 2 * 1024 * 1024;
const MAX_VSIX_BYTES = 12 * 1024 * 1024;
const PINNED_GITLEAKS_VERSION = "8.30.1";
const SIGNED_OUT_BUNDLE_DIRECTORY = ".quality/upload/signed-out-ui";
const SIGNED_OUT_BUNDLE_NAMES = Object.freeze([
  "evidence.json",
  "result.json",
  "ui-candidate.json",
  "ui-candidate.vsix",
]);
const BUNDLE_INPUTS = Object.freeze([
  Object.freeze({ name: "result.json", role: "signed-out-ui-result", maximumBytes: MAX_EVIDENCE_BYTES }),
  Object.freeze({ name: "ui-candidate.json", role: "candidate-receipt", maximumBytes: MAX_EVIDENCE_BYTES }),
  Object.freeze({ name: "ui-candidate.vsix", role: "candidate-vsix", maximumBytes: MAX_VSIX_BYTES }),
]);

function readBoundedJson(relativePath, root, subtree) {
  const target = resolveExistingRepositoryFile(relativePath, root, { subtree });
  const bytes = withStableSingleLinkFile(target, {
    errorMessage: "Signed-out UI evidence must be a bounded stable single-link file.",
    maximumBytes: MAX_EVIDENCE_BYTES,
    minimumBytes: 1,
  }, value => Buffer.from(value));
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } finally {
    bytes.fill(0);
  }
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
      fileSystem: options.fileSystem,
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

function hasExactKeys(value, keys) {
  return isPlainObject(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function canonicalTimestamp(value) {
  if (typeof value !== "string") return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function exactPrivateBundleRoot(bundleRoot) {
  const resolved = path.resolve(bundleRoot);
  const stat = fs.lstatSync(resolved, { bigint: true });
  const expectedOwner = typeof process.getuid === "function"
    ? BigInt(process.getuid())
    : stat.uid;
  if (stat.isSymbolicLink() || !stat.isDirectory() || fs.realpathSync(resolved) !== resolved
    || stat.uid !== expectedOwner
    || (process.platform !== "win32" && (stat.mode & 0o077n) !== 0n)) {
    throw new Error("Detached signed-out UI bundle root must be creator-owned and private.");
  }
  return Object.freeze({
    root: resolved,
    identity: Object.freeze({ device: String(stat.dev), inode: String(stat.ino) }),
  });
}

function assertExactBundleInventory(bundle) {
  const current = exactPrivateBundleRoot(bundle.root);
  if (current.identity.device !== bundle.identity.device
    || current.identity.inode !== bundle.identity.inode
    || JSON.stringify(fs.readdirSync(bundle.root).sort())
      !== JSON.stringify(SIGNED_OUT_BUNDLE_NAMES)) {
    throw new Error("Detached signed-out UI bundle inventory changed or is unsafe.");
  }
  for (const name of SIGNED_OUT_BUNDLE_NAMES) {
    const stat = fs.lstatSync(path.join(bundle.root, name));
    if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1) {
      throw new Error("Detached signed-out UI bundle inventory changed or is unsafe.");
    }
  }
  return true;
}

function captureDetachedFile(bundle, name, maximumBytes) {
  const errorMessage = "Detached signed-out UI bundle file changed or is unsafe.";
  return withStableSingleLinkFile(path.join(bundle.root, name), {
    errorMessage,
    maximumBytes,
    minimumBytes: 1,
  }, (bytes, identity) => Object.freeze({
    bytes: Buffer.from(bytes),
    identity,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
  }));
}

function parseCanonicalJson(captured, errorMessage) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes);
    const value = JSON.parse(text);
    if (!captured.bytes.equals(Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8"))) {
      throw new Error(errorMessage);
    }
    return value;
  } catch {
    throw new Error(errorMessage);
  }
}

function validateBundleReceipt(receipt, captured, expectedSourceSha) {
  if (!hasExactKeys(receipt, [
    "bundle", "candidate", "capturedAt", "components", "findingCount", "findings",
    "fingerprint", "mode", "scanner", "schemaVersion", "sourceSha", "status",
  ])
    || receipt.schemaVersion !== 2
    || receipt.mode !== "evidence"
    || receipt.status !== "passed"
    || !canonicalTimestamp(receipt.capturedAt)
    || receipt.findingCount !== 0
    || !Array.isArray(receipt.findings) || receipt.findings.length !== 0
    || !/^[a-f0-9]{64}$/u.test(receipt.fingerprint || "")
    || !/^[a-f0-9]{40}$/u.test(expectedSourceSha || "")) {
    throw new Error("Detached signed-out UI evidence receipt is invalid or not passed.");
  }
  const unsigned = { ...receipt };
  delete unsigned.fingerprint;
  if (fingerprint(unsigned) !== receipt.fingerprint) {
    throw new Error("Detached signed-out UI evidence receipt fingerprint is invalid.");
  }
  if (!hasExactKeys(receipt.scanner, [
    "name", "redactionPercent", "secretBearingFieldsPersisted", "version",
  ])
    || receipt.scanner.name !== "gitleaks"
    || receipt.scanner.version !== PINNED_GITLEAKS_VERSION
    || receipt.scanner.redactionPercent !== 100
    || receipt.scanner.secretBearingFieldsPersisted !== false
    || !Array.isArray(receipt.components)
    || receipt.components.length !== 2
    || receipt.components.some(component => (
      !hasExactKeys(component, ["fileCount", "findingCount", "id", "status"])
      || component.findingCount !== 0
      || !Number.isSafeInteger(component.fileCount) || component.fileCount < 0
      || !new Set(["scanned", "not-present"]).has(component.status)
    ))
    || receipt.components[0].id !== "generated-quality-evidence"
    || receipt.components[1].id !== `vsix:${UI_CANDIDATE_ARTIFACT}`
    || receipt.components[1].status !== "scanned") {
    throw new Error("Detached signed-out UI evidence scan result is invalid.");
  }
  const bundle = receipt.bundle;
  if (!hasExactKeys(bundle, [
    "candidateReceiptFingerprint", "files", "kind", "receipt", "scanResult",
    "schemaVersion", "source",
  ])
    || bundle.schemaVersion !== 1
    || bundle.kind !== "signed-out-ui-evidence"
    || !hasExactKeys(bundle.source, ["fingerprint", "sha"])
    || bundle.source.sha !== expectedSourceSha
    || receipt.sourceSha !== expectedSourceSha
    || !/^[a-f0-9]{64}$/u.test(bundle.source.fingerprint || "")
    || !/^[a-f0-9]{64}$/u.test(bundle.candidateReceiptFingerprint || "")
    || !hasExactKeys(bundle.scanResult, ["findingCount", "mode", "status"])
    || bundle.scanResult.mode !== receipt.mode
    || bundle.scanResult.status !== receipt.status
    || bundle.scanResult.findingCount !== receipt.findingCount
    || !hasExactKeys(bundle.receipt, ["bytes", "integrity", "name", "role"])
    || bundle.receipt.name !== "evidence.json"
    || bundle.receipt.role !== "value-blind-secret-scan-receipt"
    || bundle.receipt.integrity !== "canonical-self-fingerprint"
    || bundle.receipt.bytes !== captured.get("evidence.json").bytes.length) {
    throw new Error("Detached signed-out UI bundle receipt binding is invalid.");
  }
  if (!Array.isArray(bundle.files) || bundle.files.length !== BUNDLE_INPUTS.length) {
    throw new Error("Detached signed-out UI bundle receipt file inventory is invalid.");
  }
  const expectedFiles = [...BUNDLE_INPUTS].sort((left, right) => left.name.localeCompare(right.name));
  for (let index = 0; index < expectedFiles.length; index += 1) {
    const expected = expectedFiles[index];
    const entry = bundle.files[index];
    const file = captured.get(expected.name);
    if (!hasExactKeys(entry, ["bytes", "name", "role", "sha256"])
      || entry.name !== expected.name
      || entry.role !== expected.role
      || entry.bytes !== file.bytes.length
      || entry.sha256 !== file.sha256) {
      throw new Error("Detached signed-out UI bundle receipt file digest is invalid.");
    }
  }
  if (!hasExactKeys(receipt.candidate, [
    "receiptFingerprint", "receiptSha256", "vsixSha256",
  ])
    || receipt.candidate.receiptFingerprint !== bundle.candidateReceiptFingerprint
    || receipt.candidate.receiptSha256 !== captured.get("ui-candidate.json").sha256
    || receipt.candidate.vsixSha256 !== captured.get("ui-candidate.vsix").sha256) {
    throw new Error("Detached signed-out UI candidate scan binding is invalid.");
  }
  return bundle;
}

function verifyDetachedSignedOutUiBundle(options = {}) {
  const bundle = exactPrivateBundleRoot(options.bundleRoot || path.join(
    ROOT,
    ...SIGNED_OUT_BUNDLE_DIRECTORY.split("/"),
  ));
  assertExactBundleInventory(bundle);
  const captured = new Map();
  try {
    for (const input of BUNDLE_INPUTS) {
      captured.set(input.name, captureDetachedFile(bundle, input.name, input.maximumBytes));
    }
    captured.set("evidence.json", captureDetachedFile(
      bundle,
      "evidence.json",
      MAX_EVIDENCE_BYTES,
    ));
    const receipt = parseCanonicalJson(
      captured.get("evidence.json"),
      "Detached signed-out UI evidence receipt is not canonical JSON.",
    );
    const expectedSourceSha = options.expectedSourceSha || process.env.EXPECTED_SOURCE_SHA;
    const binding = validateBundleReceipt(receipt, captured, expectedSourceSha);
    const candidateReceipt = parseCanonicalJson(
      captured.get("ui-candidate.json"),
      "Detached signed-out UI candidate receipt is not canonical JSON.",
    );
    const ui = parseCanonicalJson(
      captured.get("result.json"),
      "Detached signed-out UI result is not canonical JSON.",
    );
    const candidate = candidateBindingFromReceipt(candidateReceipt, {
      source: binding.source,
      artifactPath: path.join(bundle.root, "ui-candidate.vsix"),
    });
    if (candidate.receiptFingerprint !== binding.candidateReceiptFingerprint
      || candidate.vsixSha256 !== captured.get("ui-candidate.vsix").sha256) {
      throw new Error("Detached signed-out UI candidate proof is stale or mismatched.");
    }
    const contractRoot = options.contractRoot || ROOT;
    const manifest = options.manifest || readJson("package.json", contractRoot);
    const workflows = options.workflows || readJson("quality/critical-workflows.json", contractRoot);
    const errors = validateUiResult(ui, binding.source, expectedBlackBoxUiTests(workflows), {
      candidateReceipt,
      extensionId: `${manifest.publisher}.${manifest.name}`,
      extensionVersion: manifest.version,
    });
    if (ui.status !== "passed" || errors.length > 0) {
      throw new Error("Detached signed-out UI result semantics are invalid.");
    }
    if (typeof options.afterCapture === "function") options.afterCapture(bundle.root);
    assertExactBundleInventory(bundle);
    for (const [name, file] of captured) {
      const proof = digestStableSingleLinkFile(path.join(bundle.root, name), {
        errorMessage: "Detached signed-out UI bundle changed during verification.",
        expectedBytes: file.bytes.length,
        expectedIdentity: file.identity,
        maximumBytes: name.endsWith(".vsix") ? MAX_VSIX_BYTES : MAX_EVIDENCE_BYTES,
        minimumBytes: 1,
      });
      if (proof.sha256 !== file.sha256
        || !sameExactFileIdentity(proof.identity, file.identity)) {
        throw new Error("Detached signed-out UI bundle changed during verification.");
      }
    }
    return Object.freeze({
      status: "passed",
      sourceSha: binding.source.sha,
      testCount: ui.results.length,
      fingerprint: receipt.fingerprint,
    });
  } finally {
    for (const file of captured.values()) file.bytes.fill(0);
  }
}

function main(argv = process.argv.slice(2)) {
  try {
    let result;
    if (argv.length === 0) result = verifySignedOutUiEvidence();
    else if (argv.length === 2 && argv[0] === "--bundle") {
      result = verifyDetachedSignedOutUiBundle({ bundleRoot: argv[1] });
    } else throw new Error("Signed-out UI evidence verifier arguments are invalid.");
    console.log(`Signed-out UI evidence verified: ${result.testCount} passed tests.`);
  } catch {
    console.error("Signed-out UI evidence verification failed closed.");
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  CANDIDATE_RECEIPT,
  SIGNED_OUT_BUNDLE_DIRECTORY,
  SIGNED_OUT_BUNDLE_NAMES,
  UI_RESULT,
  verifyDetachedSignedOutUiBundle,
  verifySignedOutUiEvidence,
};

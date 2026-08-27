// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  ROOT,
  assertRealRepositoryRoot,
  isPlainObject,
  removeOutputFile,
  resolveExistingRepositoryFile,
  resolveOptionalRepositoryFile,
  writeJson,
} = require("./common");
const { fingerprint, sourceIdentity } = require("./evidence");
const { decodeUtf8Bytes } = require("./findings");
const {
  UI_CANDIDATE_ARTIFACT,
  UI_CANDIDATE_RECEIPT,
  candidateBindingFromReceipt,
} = require("./candidate-binding");
const {
  GITLEAKS_VERSION,
  assertScannerVersion,
  copyFileIntoSnapshot,
  scanGeneratedEvidence,
  scanVsix,
  scanWithGitleaks,
} = require("./secret-scan");
const {
  UI_RESULT,
  verifySignedOutUiEvidence,
} = require("./verify-ui-evidence");

const RELEASE_EXPOSURE_RESULT = ".quality/secrets/release.json";
const LIVE_ATTESTATION = "internal_docs/quality/live-qualification.json";
const OUTPUT_ROOT = ".quality/secrets";
const EVIDENCE_PATH_PATTERN = /^internal_docs\/quality\/[A-Za-z0-9][A-Za-z0-9._-]*\.(?:json|jsonl|md|png|txt|webp)$/u;
const MAX_JSON_BYTES = 2 * 1024 * 1024;
const MAX_EVIDENCE_BYTES = 16 * 1024 * 1024;
const RELEASE_COMPONENT_IDS = Object.freeze([
  "post-ui-generated-quality-evidence",
  `vsix:${UI_CANDIDATE_ARTIFACT}`,
  "accepted-live-evidence",
]);

function hasExactKeys(value, keys) {
  return isPlainObject(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function exactSource(value) {
  return hasExactKeys(value, ["fingerprint", "sha"])
    && /^[a-f0-9]{40,64}$/u.test(value.sha || "")
    && /^[a-f0-9]{64}$/u.test(value.fingerprint || "");
}

function canonicalTimestamp(value) {
  if (typeof value !== "string") return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function exactFileIdentity(filePath) {
  const stat = fs.lstatSync(filePath, { bigint: true });
  const realPath = fs.realpathSync(filePath);
  if (stat.isSymbolicLink() || !stat.isFile() || realPath !== filePath) {
    throw new Error("Release exposure candidate proof must be an exact real file.");
  }
  return Object.freeze({
    changedNanoseconds: String(stat.ctimeNs),
    device: String(stat.dev),
    inode: String(stat.ino),
    modifiedNanoseconds: String(stat.mtimeNs),
    size: String(stat.size),
  });
}

function sameFileIdentity(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function readBoundedBytes(relativePath, root, subtree, maximumBytes) {
  const target = resolveExistingRepositoryFile(relativePath, root, { subtree });
  const stat = fs.lstatSync(target);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.size <= 0 || stat.size > maximumBytes) {
    throw new Error("Release exposure input must be a bounded regular file.");
  }
  return Object.freeze({ target, bytes: fs.readFileSync(target) });
}

function readBoundedJson(relativePath, root, subtree) {
  const loaded = readBoundedBytes(relativePath, root, subtree, MAX_JSON_BYTES);
  return Object.freeze({
    ...loaded,
    document: JSON.parse(decodeUtf8Bytes(loaded.bytes, "Release exposure input")),
  });
}

function releaseEvidenceManifest(document) {
  const references = [
    ...(document?.evidence || []),
    ...(document?.workflowResults || []).flatMap(result => result?.evidence || []),
    ...(document?.visibleEnabledActions?.evidence || []),
    ...(document?.independentReview?.evidence || []),
  ];
  const byPath = new Map();
  for (const reference of references) {
    if (EVIDENCE_PATH_PATTERN.test(reference?.path || "")
      && /^[a-f0-9]{64}$/u.test(reference?.sha256 || "")) {
      byPath.set(reference.path, Object.freeze({
        path: reference.path,
        sha256: reference.sha256,
      }));
    }
  }
  return [...byPath.values()].sort((left, right) => left.path.localeCompare(right.path));
}

function validateEvidenceSource(relativePath, root) {
  if (!EVIDENCE_PATH_PATTERN.test(relativePath)
    || path.posix.normalize(relativePath) !== relativePath) {
    throw new Error("Release exposure evidence path is invalid.");
  }
  const target = resolveExistingRepositoryFile(relativePath, root, {
    subtree: "internal_docs/quality",
  });
  const stat = fs.lstatSync(target);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.size <= 0 || stat.size > MAX_EVIDENCE_BYTES) {
    throw new Error("Release exposure evidence must be a bounded regular file.");
  }
  return target;
}

function scanAcceptedEvidence(root, paths, options = {}) {
  if (paths.length === 0) {
    return {
      id: "accepted-live-evidence",
      status: "not-present",
      fileCount: 0,
      findings: [],
      snapshot: null,
    };
  }
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-release-evidence-"));
  fs.chmodSync(scratch, 0o700);
  const snapshot = path.join(scratch, "evidence");
  fs.mkdirSync(snapshot, { mode: 0o700 });
  try {
    for (const relativePath of paths) {
      copyFileIntoSnapshot(validateEvidenceSource(relativePath, root), relativePath, snapshot);
    }
    const findings = scanWithGitleaks("dir", snapshot, {
      ...options,
      root,
      scanRoot: snapshot,
      label: "accepted-live-evidence",
    });
    const snapshotBytes = Object.fromEntries(paths.map(relativePath => [
      relativePath,
      fs.readFileSync(path.join(snapshot, ...relativePath.split("/"))),
    ]));
    return {
      id: "accepted-live-evidence",
      status: "scanned",
      fileCount: paths.length,
      findings,
      snapshot: snapshotBytes,
    };
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

function normalizeComponent(component) {
  return {
    id: component.id,
    status: component.status,
    fileCount: component.fileCount,
    findingCount: component.findings.length,
  };
}

function buildReleaseExposureResult(options = {}) {
  const components = options.components || [];
  const findings = components.flatMap(component => component.findings.map(finding => ({
    component: component.id,
    ...finding,
  })));
  const status = findings.length === 0 ? "passed" : "failed";
  const base = {
    schemaVersion: 1,
    status,
    source: options.source,
    scanner: {
      name: "gitleaks",
      version: GITLEAKS_VERSION,
      redactionPercent: 100,
      secretBearingFieldsPersisted: false,
    },
    capturedAt: (options.now || new Date()).toISOString(),
    candidate: {
      candidateReceiptFingerprint: options.candidateReceiptFingerprint || null,
      uiResultSha256: options.uiResultSha256 || null,
      vsixSha256: options.vsixSha256 || null,
    },
    attestation: options.attestationPath ? {
      path: options.attestationPath,
      sha256: options.attestationSha256 || null,
    } : null,
    evidence: [...(options.evidenceManifest || [])],
    findingCount: findings.length,
    components: components.map(normalizeComponent),
    findings,
  };
  return Object.freeze({ ...base, fingerprint: fingerprint(base) });
}

function failReleaseExposureProof() {
  throw new Error("Release exposure proof is missing, stale, or invalid.");
}

function validateReleaseExposureProof(value, expected = {}) {
  try {
    const expectedEvidenceFileCount = expected.attestationPath
      ? new Set([
        expected.attestationPath,
        ...(expected.evidenceManifest || []).map(reference => reference.path),
      ]).size
      : 0;
    if (!hasExactKeys(value, [
      "attestation", "candidate", "capturedAt", "components", "evidence", "findingCount",
      "findings", "fingerprint", "scanner", "schemaVersion", "source", "status",
    ])
      || value.schemaVersion !== 1
      || value.status !== "passed"
      || value.findingCount !== 0
      || !Array.isArray(value.findings) || value.findings.length !== 0
      || !canonicalTimestamp(value.capturedAt)
      || !exactSource(value.source)
      || value.source.sha !== expected.source?.sha
      || value.source.fingerprint !== expected.source?.fingerprint
      || !hasExactKeys(value.scanner, [
        "name", "redactionPercent", "secretBearingFieldsPersisted", "version",
      ])
      || value.scanner.name !== "gitleaks"
      || value.scanner.version !== GITLEAKS_VERSION
      || value.scanner.redactionPercent !== 100
      || value.scanner.secretBearingFieldsPersisted !== false
      || !hasExactKeys(value.candidate, [
        "candidateReceiptFingerprint", "uiResultSha256", "vsixSha256",
      ])
      || value.candidate.candidateReceiptFingerprint !== expected.candidateReceiptFingerprint
      || value.candidate.vsixSha256 !== expected.vsixSha256
      || value.candidate.uiResultSha256 !== expected.uiResultSha256
      || !/^[a-f0-9]{64}$/u.test(value.candidate.candidateReceiptFingerprint || "")
      || !/^[a-f0-9]{64}$/u.test(value.candidate.vsixSha256 || "")
      || !/^[a-f0-9]{64}$/u.test(value.candidate.uiResultSha256 || "")
      || !Array.isArray(value.components)
      || value.components.some(component => !hasExactKeys(component, [
        "fileCount", "findingCount", "id", "status",
      ]) || component.findingCount !== 0 || !new Set(["scanned", "not-present"]).has(component.status))
      || JSON.stringify(value.components.map(component => component.id))
        !== JSON.stringify(RELEASE_COMPONENT_IDS)
      || value.components[0].status !== "scanned"
      || !Number.isInteger(value.components[0].fileCount)
      || value.components[0].fileCount < 1
      || value.components[1].status !== "scanned"
      || !Number.isInteger(value.components[1].fileCount)
      || value.components[1].fileCount < 2
      || value.components[2].status !== (expected.attestationPath ? "scanned" : "not-present")
      || value.components[2].fileCount !== expectedEvidenceFileCount
      || JSON.stringify(value.evidence) !== JSON.stringify(expected.evidenceManifest || [])) {
      failReleaseExposureProof();
    }
    const unsigned = { ...value };
    delete unsigned.fingerprint;
    if (!/^[a-f0-9]{64}$/u.test(value.fingerprint || "")
      || fingerprint(unsigned) !== value.fingerprint) {
      failReleaseExposureProof();
    }
    if (expected.attestationPath) {
      if (!hasExactKeys(value.attestation, ["path", "sha256"])
        || value.attestation.path !== expected.attestationPath
        || value.attestation.sha256 !== expected.attestationSha256
        || !/^[a-f0-9]{64}$/u.test(value.attestation.sha256 || "")) {
        failReleaseExposureProof();
      }
    } else if (value.attestation !== null || value.evidence.length !== 0) {
      failReleaseExposureProof();
    }
    return true;
  } catch (error) {
    if (error?.message === "Release exposure proof is missing, stale, or invalid.") throw error;
    failReleaseExposureProof();
  }
}

function assertStableEvidence(root, evidenceManifest, attestation, snapshot) {
  const expected = new Map([
    [attestation.path, attestation.sha256],
    ...evidenceManifest.map(reference => [reference.path, reference.sha256]),
  ]);
  for (const [relativePath, expectedSha256] of expected) {
    const original = fs.readFileSync(validateEvidenceSource(relativePath, root));
    const copied = snapshot?.[relativePath];
    if (!Buffer.isBuffer(copied)
      || !original.equals(copied)
      || sha256(copied) !== expectedSha256) {
      throw new Error("Accepted release evidence changed or does not match its attestation.");
    }
  }
}

async function executeReleaseExposureScan(options = {}) {
  const root = assertRealRepositoryRoot(options.root || ROOT);
  const source = options.source || sourceIdentity(root);
  const candidateLoaded = options.candidateReceipt
    ? { document: options.candidateReceipt }
    : readBoundedJson(UI_CANDIDATE_RECEIPT, root, ".quality/qualification");
  const candidateArtifactPath = options.candidateArtifactPath
    || resolveExistingRepositoryFile(UI_CANDIDATE_ARTIFACT, root, {
      subtree: ".quality/qualification",
    });
  const candidateIdentityBefore = exactFileIdentity(candidateArtifactPath);
  const uiLoaded = options.ui
    ? { document: options.ui, bytes: Buffer.from(JSON.stringify(options.ui)) }
    : readBoundedJson(UI_RESULT, root, ".quality/ui");
  const candidateBinding = candidateBindingFromReceipt(candidateLoaded.document, {
    root,
    source,
    artifactPath: candidateArtifactPath,
  });
  verifySignedOutUiEvidence({
    root,
    source,
    candidateReceipt: candidateLoaded.document,
    candidateArtifactPath,
    ui: uiLoaded.document,
  });

  const optionalAttestation = options.attestation === null
    ? null
    : options.attestation
      ? {
        path: options.attestationPath || LIVE_ATTESTATION,
        document: options.attestation,
        bytes: options.attestationBytes || Buffer.from(JSON.stringify(options.attestation)),
      }
      : (() => {
        const target = resolveOptionalRepositoryFile(LIVE_ATTESTATION, root, {
          subtree: "internal_docs/quality",
        });
        if (!target) return null;
        const loaded = readBoundedJson(LIVE_ATTESTATION, root, "internal_docs/quality");
        return { path: LIVE_ATTESTATION, ...loaded };
      })();
  const evidenceManifest = optionalAttestation
    ? releaseEvidenceManifest(optionalAttestation.document)
    : [];
  const evidencePaths = optionalAttestation
    ? [...new Set([optionalAttestation.path, ...evidenceManifest.map(reference => reference.path)])].sort()
    : [];

  (options.assertScannerVersion || assertScannerVersion)({ ...options, root });
  const generatedComponent = (options.scanGeneratedEvidence || scanGeneratedEvidence)(
    root,
    ".quality",
    {
      ...options,
      id: "post-ui-generated-quality-evidence",
      excludedPrefixes: [OUTPUT_ROOT],
    }
  );
  const candidateComponent = await (options.scanVsix || scanVsix)(
    root,
    UI_CANDIDATE_ARTIFACT,
    options
  );
  const evidenceComponent = options.scanAcceptedEvidence
    ? options.scanAcceptedEvidence(root, evidencePaths, options)
    : scanAcceptedEvidence(root, evidencePaths, options);
  const components = [generatedComponent, candidateComponent, evidenceComponent];
  const findingCount = components.reduce(
    (total, component) => total + component.findings.length,
    0
  );

  let attestationSha256 = null;
  let uiResultSha256 = null;
  if (findingCount === 0) {
    const finalCandidate = candidateBindingFromReceipt(candidateLoaded.document, {
      root,
      source,
      artifactPath: candidateArtifactPath,
    });
    if (finalCandidate.receiptFingerprint !== candidateBinding.receiptFingerprint
      || finalCandidate.vsixSha256 !== candidateBinding.vsixSha256
      || !sameFileIdentity(candidateIdentityBefore, exactFileIdentity(candidateArtifactPath))) {
      throw new Error("Signed-out candidate changed during release exposure scanning.");
    }
    const currentUi = fs.readFileSync(resolveExistingRepositoryFile(UI_RESULT, root, {
      subtree: ".quality/ui",
    }));
    if (uiLoaded.bytes && !currentUi.equals(uiLoaded.bytes)) {
      throw new Error("Signed-out UI evidence changed during release exposure scanning.");
    }
    uiResultSha256 = sha256(currentUi);
    if (optionalAttestation) {
      attestationSha256 = sha256(optionalAttestation.bytes);
      assertStableEvidence(
        root,
        evidenceManifest,
        { path: optionalAttestation.path, sha256: attestationSha256 },
        evidenceComponent.snapshot,
      );
    }
  }
  return buildReleaseExposureResult({
    source,
    candidateReceiptFingerprint: candidateBinding.receiptFingerprint,
    vsixSha256: candidateBinding.vsixSha256,
    uiResultSha256,
    attestationPath: optionalAttestation?.path || null,
    attestationSha256,
    evidenceManifest,
    components,
    now: options.now || new Date(),
  });
}

async function main() {
  try {
    removeOutputFile(RELEASE_EXPOSURE_RESULT, ROOT, { subtree: OUTPUT_ROOT });
    const result = await executeReleaseExposureScan();
    writeJson(RELEASE_EXPOSURE_RESULT, result, ROOT, { subtree: OUTPUT_ROOT });
    console.log(
      `Release exposure gate ${result.status}: ${result.findingCount} finding(s) across `
      + `${result.components.length} scanned component(s).`
    );
    if (result.status !== "passed") process.exitCode = 1;
  } catch (error) {
    console.error(`Release exposure gate failed closed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  LIVE_ATTESTATION,
  RELEASE_COMPONENT_IDS,
  RELEASE_EXPOSURE_RESULT,
  buildReleaseExposureResult,
  executeReleaseExposureScan,
  releaseEvidenceManifest,
  scanAcceptedEvidence,
  validateReleaseExposureProof,
};

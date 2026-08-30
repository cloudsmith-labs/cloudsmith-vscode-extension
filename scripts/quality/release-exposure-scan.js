// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { isDeepStrictEqual } = require("util");
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
  EXACT_FILE_IDENTITY_KEYS,
  UI_CANDIDATE_ARTIFACT,
  UI_CANDIDATE_RECEIPT,
  candidateBindingFromReceipt,
  digestStableSingleLinkFile,
  exactFileIdentity: descriptorFileIdentity,
  readStableSingleLinkFile,
  sameExactFileIdentity,
} = require("./candidate-binding");
const {
  GITLEAKS_VERSION,
  MAX_GENERATED_FILE_BYTES,
  assertScannerVersion,
  scanGeneratedEvidence,
  scanVsix,
  scanWithGitleaks,
  walkGeneratedFiles,
} = require("./secret-scan");
const {
  getGatePlan,
  receiptPath,
} = require("./gate");
const {
  UI_RESULT,
  verifySignedOutUiEvidence,
} = require("./verify-ui-evidence");
const {
  validateGateGenerationProgress,
  validateGateGenerationSemantics,
  validateGateStepArtifactClaim,
  validateStepArtifacts,
  validateStepTestEvidence,
} = require("./verify-handoff");

const RELEASE_EXPOSURE_RESULT = ".quality/secrets/release.json";
const LIVE_ATTESTATION = "internal_docs/quality/current-candidate-acceptance.json";
const OUTPUT_ROOT = ".quality/secrets";
const GENERATED_EVIDENCE_ROOT = ".quality";
const GENERATED_EVIDENCE_BOUNDARY = "immutable-pre-acceptance-v1";
const RELEASE_GATE_PLAN = Object.freeze(getGatePlan("release"));
const RELEASE_GATE_RECEIPT_PATHS = Object.freeze(RELEASE_GATE_PLAN.map(step => receiptPath({
  profile: "release",
  sequence: step.sequence,
  stepId: step.id,
})));
const SECRET_RELEASE_PLAN_INDEX = RELEASE_GATE_PLAN.findIndex(step => (
  step.id === "secret-release"
));
if (SECRET_RELEASE_PLAN_INDEX < 0) {
  throw new Error("Canonical release gate plan is missing secret-release.");
}
const RELEASE_CHECKLIST_STEP_ID = "release-checklist";
const RELEASE_CHECKLIST_PLAN_INDEX = RELEASE_GATE_PLAN.findIndex(step => (
  step.id === RELEASE_CHECKLIST_STEP_ID
));
const RELEASE_CHECKLIST_ARTIFACT_PATH = ".quality/gates/live-qualification-status.json";
if (RELEASE_CHECKLIST_PLAN_INDEX < 0
  || RELEASE_GATE_PLAN[RELEASE_CHECKLIST_PLAN_INDEX].artifactPath
    !== RELEASE_CHECKLIST_ARTIFACT_PATH
  || RELEASE_GATE_PLAN[RELEASE_CHECKLIST_PLAN_INDEX].artifactPaths) {
  throw new Error("Canonical release gate plan has an invalid release-checklist artifact.");
}
const RELEASE_GATE_CIRCULAR_PATHS = Object.freeze([
  ...RELEASE_GATE_RECEIPT_PATHS.slice(SECRET_RELEASE_PLAN_INDEX),
  ".quality/gates/live-qualification-status.json",
  ".quality/gates/release.json",
]);
const RELEASE_GATE_EXPECTED_PATHS = Object.freeze([
  ...RELEASE_GATE_RECEIPT_PATHS,
  ".quality/gates/live-qualification-status.json",
  ".quality/gates/release.json",
]);
const PRESERVED_GATE_PROFILES = Object.freeze(["fast", "full"]);
const PRESERVED_GATE_PLANS = Object.freeze(Object.fromEntries(
  PRESERVED_GATE_PROFILES.map(profile => [profile, Object.freeze(getGatePlan(profile))]),
));
const PRESERVED_GATE_RECEIPT_PATHS = Object.freeze(Object.fromEntries(
  PRESERVED_GATE_PROFILES.map(profile => [profile, Object.freeze(
    PRESERVED_GATE_PLANS[profile].map(step => receiptPath({
      profile,
      sequence: step.sequence,
      stepId: step.id,
    })),
  )]),
));
const PRESERVED_GATE_EXPECTED_PATHS = Object.freeze(PRESERVED_GATE_PROFILES.flatMap(profile => [
  `.quality/gates/${profile}.json`,
  ...PRESERVED_GATE_RECEIPT_PATHS[profile],
]));
const INTENTIONALLY_VARIANT_SUPERSEDED_ARTIFACT_STEPS = new Set([
  // Stryker emits concurrently completed mutant results in run-dependent order.
  // The summary intentionally binds those exact raw report bytes, so repeated
  // valid runs can differ while the latest owner remains exact-byte validated.
  "changed-mutation",
  "quality-report",
  "secret-artifacts",
  "secret-current",
]);
const GENERATED_EVIDENCE_CIRCULAR_OUTPUTS = Object.freeze([
  ...RELEASE_GATE_CIRCULAR_PATHS.map(outputPath => Object.freeze({
    path: outputPath,
    owner: "release-gate",
    justification: "This exact canonical release-gate output is planned before scanning or written after exposure acceptance.",
  })),
  Object.freeze({
    path: ".quality/report.json",
    owner: "quality-report",
    justification: "The final report revalidates release evidence before it writes its own JSON bytes.",
  }),
  Object.freeze({
    path: ".quality/report.md",
    owner: "quality-report",
    justification: "The final report revalidates release evidence before it writes its own Markdown bytes.",
  }),
  Object.freeze({
    path: ".quality/secrets/history.json",
    owner: "secret-history",
    justification: "The canonical history scan runs after release exposure and before the final report.",
  }),
  Object.freeze({
    path: RELEASE_EXPOSURE_RESULT,
    owner: "secret-release",
    justification: "The release-exposure receipt cannot include its own bytes without a circular digest.",
  }),
]);
const GENERATED_EVIDENCE_EXCLUDED_FILES = Object.freeze(
  GENERATED_EVIDENCE_CIRCULAR_OUTPUTS.map(output => output.path).sort(),
);
const GENERATED_EVIDENCE_EXCLUDED_PREFIXES = Object.freeze([]);
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

function exactFileIdentity(
  filePath,
  label = "Release exposure candidate proof",
  fileSystem = fs,
) {
  const stat = fileSystem.lstatSync(filePath, { bigint: true });
  const realPath = fileSystem.realpathSync(filePath);
  if (stat.isSymbolicLink() || !stat.isFile() || realPath !== filePath
    || stat.nlink !== 1n || stat.size > BigInt(MAX_GENERATED_FILE_BYTES)) {
    throw new Error(`${label} must be an exact real file.`);
  }
  return descriptorFileIdentity(stat);
}

function sameFileIdentity(left, right) {
  return sameExactFileIdentity(left, right);
}

function assertExactCircularOutputFiles(root, options = {}) {
  const fileSystem = options.fileSystem || fs;
  const failure = () => {
    throw new Error("Circular release output must be absent or an exact bounded single-link file.");
  };
  for (const relativePath of GENERATED_EVIDENCE_EXCLUDED_FILES) {
    const target = path.join(root, ...relativePath.split("/"));
    let stat;
    try {
      stat = fileSystem.lstatSync(target, { bigint: true });
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    if (stat.isSymbolicLink() || !stat.isFile()
      || stat.nlink !== 1n || stat.size <= 0n
      || stat.size > BigInt(MAX_GENERATED_FILE_BYTES)
      || fileSystem.realpathSync(target) !== target) {
      failure();
    }
  }
  return true;
}

function failReleaseGateTree() {
  throw new Error("Release gate output tree contains an unexpected, stale, or unsafe entry.");
}

function optionalPathStat(target, fileSystem = fs) {
  try {
    return fileSystem.lstatSync(target);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

function assertCanonicalGateJson(loaded) {
  const canonical = Buffer.from(`${JSON.stringify(loaded.document, null, 2)}\n`);
  if (!loaded.bytes.equals(canonical)) failReleaseGateTree();
  return loaded.document;
}

function validatePreservedGateProfile(root, profile, source, options = {}) {
  const fileSystem = options.fileSystem || fs;
  const summaryPath = `.quality/gates/${profile}.json`;
  const directoryPath = `.quality/gates/${profile}`;
  const summaryTarget = path.join(root, ...summaryPath.split("/"));
  const directoryTarget = path.join(root, ...directoryPath.split("/"));
  const summaryStat = optionalPathStat(summaryTarget, fileSystem);
  const directoryStat = optionalPathStat(directoryTarget, fileSystem);
  if (!summaryStat && !directoryStat) return null;
  if (!summaryStat || !directoryStat) failReleaseGateTree();

  const plan = PRESERVED_GATE_PLANS[profile];
  const loadedSummary = readBoundedJson(summaryPath, root, ".quality/gates", options);
  const summary = assertCanonicalGateJson(loadedSummary);
  const context = { fileSystem, plan, profile, root, source };
  try {
    validateGateGenerationSemantics(summary, context);
  } catch {
    failReleaseGateTree();
  }

  const identities = [{ path: summaryPath, identity: loadedSummary.identity }];
  for (let index = 0; index < plan.length; index += 1) {
    const expectedPath = PRESERVED_GATE_RECEIPT_PATHS[profile][index];
    const loadedReceipt = readBoundedJson(
      expectedPath,
      root,
      `.quality/gates/${profile}`,
      options,
    );
    const receipt = assertCanonicalGateJson(loadedReceipt);
    if (!isDeepStrictEqual(receipt, summary.steps[index])) {
      failReleaseGateTree();
    }
    identities.push({ path: expectedPath, identity: loadedReceipt.identity });
  }
  return Object.freeze({
    context: Object.freeze(context),
    identities: Object.freeze(identities.map(entry => Object.freeze(entry))),
    receipts: summary.steps,
  });
}

function validateReleaseGateOwner(root, source, options = {}) {
  const fileSystem = options.fileSystem || fs;
  const profile = "release";
  const plan = RELEASE_GATE_PLAN;
  const context = { fileSystem, plan, profile, root, source };
  const receipts = [];
  const identities = [];
  for (let index = 0; index < plan.length; index += 1) {
    const relativePath = RELEASE_GATE_RECEIPT_PATHS[index];
    const loaded = readBoundedJson(
      relativePath,
      root,
      ".quality/gates/release",
      options,
    );
    receipts.push(assertCanonicalGateJson(loaded));
    identities.push(Object.freeze({ path: relativePath, identity: loaded.identity }));
  }
  const summaryPath = ".quality/gates/release.json";
  const summaryTarget = path.join(root, ".quality", "gates", "release.json");
  const hasSummary = Boolean(optionalPathStat(summaryTarget, fileSystem));
  if (hasSummary) {
    if (options.releaseChecklistOutputProof) failReleaseGateTree();
    const loadedSummary = readBoundedJson(summaryPath, root, ".quality/gates", options);
    const summary = assertCanonicalGateJson(loadedSummary);
    validateGateGenerationSemantics(summary, context);
    if (!isDeepStrictEqual(receipts, summary.steps)) failReleaseGateTree();
    identities.unshift(Object.freeze({ path: summaryPath, identity: loadedSummary.identity }));
  } else {
    validateGateGenerationProgress(receipts, context);
  }
  const releaseChecklistOutputProof = validateReleaseChecklistOutputProof(
    receipts,
    context,
    options.releaseChecklistOutputProof,
  );
  for (let index = 0; index < plan.length; index += 1) {
    validateGateStepArtifactClaim(receipts[index], plan[index]);
    const provisionalIdentity = validateOwnerStepArtifacts(
      receipts[index],
      plan[index],
      context,
      releaseChecklistOutputProof,
    );
    if (provisionalIdentity) {
      identities.push(Object.freeze({
        path: RELEASE_CHECKLIST_ARTIFACT_PATH,
        identity: provisionalIdentity,
      }));
    }
    validateStepTestEvidence(receipts[index], plan[index], root);
  }
  return Object.freeze({
    context: Object.freeze(context),
    identities: Object.freeze(identities),
    releaseChecklistOutputProof,
    receipts: Object.freeze(receipts),
  });
}

function validateReleaseChecklistOutputProof(receipts, context, proof) {
  if (!proof) return null;
  const step = context.plan[RELEASE_CHECKLIST_PLAN_INDEX];
  const receipt = receipts[RELEASE_CHECKLIST_PLAN_INDEX];
  const firstPendingIndex = receipts.findIndex(candidate => (
    candidate.status === "not-run" && candidate.reason === "not-started"
  ));
  if (!hasExactKeys(proof, ["identity", "path", "sha256", "stepId"])
    || proof.stepId !== RELEASE_CHECKLIST_STEP_ID
    || proof.path !== RELEASE_CHECKLIST_ARTIFACT_PATH
    || !/^[a-f0-9]{64}$/u.test(proof.sha256 || "")
    || !hasExactKeys(proof.identity, EXACT_FILE_IDENTITY_KEYS)
    || firstPendingIndex !== RELEASE_CHECKLIST_PLAN_INDEX
    || step.id !== RELEASE_CHECKLIST_STEP_ID
    || step.artifactPath !== RELEASE_CHECKLIST_ARTIFACT_PATH
    || step.artifactPaths
    || receipt.status !== "not-run"
    || receipt.reason !== "not-started"
    || receipt.exitCode !== null
    || receipt.signal !== null
    || receipt.testCounts !== null
    || receipt.artifactFingerprint !== null
    || Object.prototype.hasOwnProperty.call(receipt, "outputFingerprint")
    || Object.prototype.hasOwnProperty.call(receipt, "testEvidence")
    || Object.prototype.hasOwnProperty.call(receipt, "testEvidenceFingerprint")
    || !RELEASE_GATE_CIRCULAR_PATHS.includes(RELEASE_CHECKLIST_ARTIFACT_PATH)) {
    failReleaseGateTree();
  }
  validateProvisionalReleaseChecklistArtifact(context, proof);
  return Object.freeze({
    identity: Object.freeze({ ...proof.identity }),
    path: proof.path,
    sha256: proof.sha256,
    stepId: proof.stepId,
  });
}

function validateProvisionalReleaseChecklistArtifact(context, proof) {
  const target = resolveExistingRepositoryFile(
    RELEASE_CHECKLIST_ARTIFACT_PATH,
    context.root,
    { subtree: ".quality/gates" },
  );
  const current = digestStableSingleLinkFile(target, {
    errorMessage: "Provisional release-checklist output is unsafe or changed.",
    expectedIdentity: proof.identity,
    fileSystem: context.fileSystem,
    maximumBytes: MAX_GENERATED_FILE_BYTES,
    minimumBytes: 1,
  });
  if (current.sha256 !== proof.sha256
    || !sameFileIdentity(current.identity, proof.identity)) {
    failReleaseGateTree();
  }
  return current.identity;
}

function validateOwnerStepArtifacts(receipt, step, context, releaseChecklistOutputProof) {
  if (releaseChecklistOutputProof && step.id === RELEASE_CHECKLIST_STEP_ID) {
    return validateProvisionalReleaseChecklistArtifact(
      context,
      releaseChecklistOutputProof,
    );
  }
  validateStepArtifacts(receipt, step, context.root);
  return null;
}

function validatePreservedGateBindings(generations, owner) {
  try {
    // Gate profiles intentionally reuse artifact paths. Only the latest exact
    // canonical generation (release progress, otherwise full, otherwise fast)
    // owns those current bytes. Historical claims retain strict declaration
    // semantics; structured test evidence remains current-path bound because
    // its canonical bytes are stable across profile reruns.
    const ownerByStep = new Map(owner.context.plan.map((step, index) => (
      [step.id, owner.receipts[index]]
    )));
    for (const generation of generations) {
      for (let index = 0; index < generation.context.plan.length; index += 1) {
        const step = generation.context.plan[index];
        const receipt = generation.receipts[index];
        validateGateStepArtifactClaim(
          receipt,
          step,
        );
        validateStepTestEvidence(
          receipt,
          step,
          generation.context.root,
        );
        const ownerReceipt = ownerByStep.get(step.id);
        if (generation !== owner
          && step.artifactPath
          && receipt.artifactFingerprint !== null
          && !INTENTIONALLY_VARIANT_SUPERSEDED_ARTIFACT_STEPS.has(step.id)
          && (!ownerReceipt
            || receipt.artifactFingerprint !== ownerReceipt.artifactFingerprint)) {
          failReleaseGateTree();
        }
      }
    }
    for (let index = 0; index < owner.context.plan.length; index += 1) {
      validateOwnerStepArtifacts(
        owner.receipts[index],
        owner.context.plan[index],
        owner.context,
        owner.releaseChecklistOutputProof,
      );
    }
  } catch {
    failReleaseGateTree();
  }
  return true;
}

function exactReleaseGateTreeSnapshot(root, options = {}) {
  const fileSystem = options.fileSystem || fs;
  const gateRoot = path.join(root, ".quality", "gates");
  let rootStat;
  try {
    rootStat = fileSystem.lstatSync(gateRoot);
  } catch (error) {
    if (error.code === "ENOENT") {
      return Object.freeze({ preservedIdentities: [], semanticIdentities: [] });
    }
    throw error;
  }
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()
    || fileSystem.realpathSync(gateRoot) !== gateRoot) failReleaseGateTree();
  const allowedFiles = new Set([
    ...RELEASE_GATE_EXPECTED_PATHS,
    ...PRESERVED_GATE_EXPECTED_PATHS,
  ]);
  const allowedDirectories = new Set([
    ".quality/gates",
    ".quality/gates/release",
    ...PRESERVED_GATE_PROFILES.map(profile => `.quality/gates/${profile}`),
  ]);
  const pending = [gateRoot];
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const name of fileSystem.readdirSync(directory)) {
      const absolute = path.join(directory, name);
      const relative = path.relative(root, absolute).split(path.sep).join("/");
      const stat = fileSystem.lstatSync(absolute);
      if (stat.isSymbolicLink()) failReleaseGateTree();
      if (stat.isDirectory()) {
        if (!allowedDirectories.has(relative)
          || fileSystem.realpathSync(absolute) !== absolute) failReleaseGateTree();
        pending.push(absolute);
      } else if (stat.isFile()) {
        if (!allowedFiles.has(relative) || stat.nlink !== 1
          || stat.size > MAX_GENERATED_FILE_BYTES
          || fileSystem.realpathSync(absolute) !== absolute) failReleaseGateTree();
      } else {
        failReleaseGateTree();
      }
    }
  }
  let expectedSource = options.source || null;
  const preservedIdentities = [];
  const semanticIdentities = [];
  const preservedGenerations = [];
  for (const profile of PRESERVED_GATE_PROFILES) {
    const summaryTarget = path.join(root, ".quality", "gates", `${profile}.json`);
    const directoryTarget = path.join(root, ".quality", "gates", profile);
    const hasSummary = Boolean(optionalPathStat(summaryTarget, fileSystem));
    const hasDirectory = Boolean(optionalPathStat(directoryTarget, fileSystem));
    if (hasSummary !== hasDirectory) failReleaseGateTree();
    if (hasSummary) {
      if (!expectedSource) expectedSource = sourceIdentity(root);
      let generation;
      try {
        generation = validatePreservedGateProfile(root, profile, expectedSource, options);
      } catch {
        failReleaseGateTree();
      }
      preservedGenerations.push(generation);
      preservedIdentities.push(...generation.identities);
      semanticIdentities.push(...generation.identities);
    }
  }
  const releaseSummary = path.join(root, ".quality", "gates", "release.json");
  const releaseDirectory = path.join(root, ".quality", "gates", "release");
  const hasReleaseSummary = Boolean(optionalPathStat(releaseSummary, fileSystem));
  const hasReleaseDirectory = Boolean(optionalPathStat(releaseDirectory, fileSystem));
  if (hasReleaseSummary && !hasReleaseDirectory) failReleaseGateTree();
  let releaseOwner = null;
  if (hasReleaseDirectory) {
    if (!expectedSource) expectedSource = sourceIdentity(root);
    try {
      releaseOwner = validateReleaseGateOwner(root, expectedSource, options);
    } catch {
      failReleaseGateTree();
    }
    semanticIdentities.push(...releaseOwner.identities);
  }
  if (preservedGenerations.length > 0) {
    const owner = releaseOwner || preservedGenerations[preservedGenerations.length - 1];
    validatePreservedGateBindings(preservedGenerations, owner);
  }
  return Object.freeze({
    preservedIdentities: Object.freeze(preservedIdentities),
    semanticIdentities: Object.freeze(semanticIdentities),
  });
}

function assertExactReleaseGateTree(root, options = {}) {
  exactReleaseGateTreeSnapshot(root, options);
  return true;
}

function generatedEvidenceInventory(root, options = {}) {
  const repositoryRoot = assertRealRepositoryRoot(root);
  const gateTreeBefore = exactReleaseGateTreeSnapshot(repositoryRoot, options);
  assertExactCircularOutputFiles(repositoryRoot, options);
  const excludedFiles = new Set(GENERATED_EVIDENCE_EXCLUDED_FILES);
  const inventory = walkGeneratedFiles(repositoryRoot, GENERATED_EVIDENCE_ROOT, {
    excludedPrefixes: GENERATED_EVIDENCE_EXCLUDED_PREFIXES,
    excludedFiles: GENERATED_EVIDENCE_EXCLUDED_FILES,
  }).filter(relativePath => !excludedFiles.has(relativePath)).map(relativePath => Object.freeze({
    path: relativePath,
    identity: exactFileIdentity(
      path.join(repositoryRoot, ...relativePath.split("/")),
      "Generated release evidence",
      options.fileSystem,
    ),
  }));
  const gateTreeAfter = exactReleaseGateTreeSnapshot(repositoryRoot, options);
  const byPath = new Map(inventory.map(entry => [entry.path, entry.identity]));
  const afterSemantic = new Map(gateTreeAfter.semanticIdentities.map(entry => (
    [entry.path, entry.identity]
  )));
  const preservedPaths = new Set(gateTreeBefore.preservedIdentities.map(entry => entry.path));
  if (gateTreeBefore.semanticIdentities.length !== gateTreeAfter.semanticIdentities.length) {
    failReleaseGateTree();
  }
  for (const before of gateTreeBefore.semanticIdentities) {
    if (!sameFileIdentity(before.identity, afterSemantic.get(before.path))
      || (preservedPaths.has(before.path)
        && !sameFileIdentity(before.identity, byPath.get(before.path)))) {
      failReleaseGateTree();
    }
  }
  return inventory;
}

function sameGeneratedEvidenceInventory(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function assertExpectedGeneratedEvidenceInventory(root, expected, options = {}) {
  const current = generatedEvidenceInventory(root, options);
  if (!sameGeneratedEvidenceInventory(current, expected)) {
    throw new Error("Generated release evidence changed across the pre-acceptance boundary.");
  }
  return current;
}

function captureGeneratedEvidenceManifest(root, expectedInventory = null, options = {}) {
  const repositoryRoot = assertRealRepositoryRoot(root);
  const inventory = expectedInventory || generatedEvidenceInventory(repositoryRoot, options);
  assertExpectedGeneratedEvidenceInventory(repositoryRoot, inventory, options);
  const files = inventory.map(entry => {
    const target = path.join(repositoryRoot, ...entry.path.split("/"));
    let proof;
    try {
      proof = digestStableSingleLinkFile(target, {
        digestBytes: options.digestBytes,
        errorMessage: "Generated release evidence changed while its manifest was captured.",
        expectedIdentity: entry.identity,
        fileSystem: options.fileSystem,
        maximumBytes: MAX_GENERATED_FILE_BYTES,
        minimumBytes: 0,
      });
    } catch {
      throw new Error("Generated release evidence changed while its manifest was captured.");
    }
    return Object.freeze({
      path: entry.path,
      sha256: proof.sha256,
      identity: entry.identity,
    });
  });
  assertExpectedGeneratedEvidenceInventory(repositoryRoot, inventory, options);
  return Object.freeze({
    boundary: Object.freeze({
      id: GENERATED_EVIDENCE_BOUNDARY,
      root: GENERATED_EVIDENCE_ROOT,
      excludedFiles: [...GENERATED_EVIDENCE_EXCLUDED_FILES],
      excludedPrefixes: [...GENERATED_EVIDENCE_EXCLUDED_PREFIXES],
    }),
    files,
  });
}

function readBoundedBytes(relativePath, root, subtree, maximumBytes, options = {}) {
  const target = resolveExistingRepositoryFile(relativePath, root, { subtree });
  const errorMessage = "Release exposure input must remain an exact bounded single-link file.";
  try {
    const proof = readStableSingleLinkFile(target, {
      errorMessage,
      fileSystem: options.fileSystem,
      maximumBytes,
      minimumBytes: 1,
    });
    return Object.freeze({
      target,
      bytes: proof.bytes,
      identity: proof.identity,
    });
  } catch {
    throw new Error(errorMessage);
  }
}

function readBoundedJson(relativePath, root, subtree, options = {}) {
  const loaded = readBoundedBytes(relativePath, root, subtree, MAX_JSON_BYTES, options);
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

function readBoundedEvidenceBytes(relativePath, root, options = {}) {
  if (!EVIDENCE_PATH_PATTERN.test(relativePath)
    || path.posix.normalize(relativePath) !== relativePath) {
    throw new Error("Release exposure evidence path is invalid.");
  }
  return readBoundedBytes(
    relativePath,
    root,
    "internal_docs/quality",
    MAX_EVIDENCE_BYTES,
    options,
  );
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
  const scan = options.scanWithGitleaks || scanWithGitleaks;
  const snapshotBytes = {};
  const findings = [];
  let completed = false;
  try {
    for (const relativePath of paths) {
      let loadedBytes;
      let scannerBytes;
      try {
        const loaded = readBoundedEvidenceBytes(relativePath, root, options);
        loadedBytes = loaded.bytes;
        snapshotBytes[relativePath] = Buffer.from(loadedBytes);
        scannerBytes = Buffer.from(loadedBytes);
        const scanned = scan("stdin", relativePath, {
          ...options,
          root,
          input: scannerBytes,
          logicalPath: relativePath,
          scanRoot: root,
          label: "accepted-live-evidence",
        });
        if (scanned && typeof scanned.then === "function") {
          throw new Error("Accepted release evidence scanner must complete synchronously.");
        }
        if (!Array.isArray(scanned)) {
          throw new Error("Accepted release evidence scanner returned an invalid result.");
        }
        findings.push(...scanned);
      } finally {
        if (Buffer.isBuffer(scannerBytes)) scannerBytes.fill(0);
        if (Buffer.isBuffer(loadedBytes)) loadedBytes.fill(0);
      }
    }
    completed = true;
    return {
      id: "accepted-live-evidence",
      status: "scanned",
      fileCount: paths.length,
      findings,
      snapshot: snapshotBytes,
    };
  } finally {
    if (!completed) {
      for (const bytes of Object.values(snapshotBytes)) bytes.fill(0);
    }
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

function validateGeneratedEvidenceManifest(value) {
  if (!hasExactKeys(value, ["boundary", "files"])
    || !hasExactKeys(value.boundary, ["excludedFiles", "excludedPrefixes", "id", "root"])
    || value.boundary.id !== GENERATED_EVIDENCE_BOUNDARY
    || value.boundary.root !== GENERATED_EVIDENCE_ROOT
    || JSON.stringify(value.boundary.excludedPrefixes)
      !== JSON.stringify(GENERATED_EVIDENCE_EXCLUDED_PREFIXES)
    || JSON.stringify(value.boundary.excludedFiles)
      !== JSON.stringify(GENERATED_EVIDENCE_EXCLUDED_FILES)
    || !Array.isArray(value.files)
    || value.files.length < 1) {
    failReleaseExposureProof();
  }
  const paths = [];
  for (const entry of value.files) {
    if (!hasExactKeys(entry, ["identity", "path", "sha256"])
      || typeof entry.path !== "string"
      || path.posix.normalize(entry.path) !== entry.path
      || !entry.path.startsWith(`${GENERATED_EVIDENCE_ROOT}/`)
      || GENERATED_EVIDENCE_EXCLUDED_FILES.some(excluded => (
        entry.path === excluded || entry.path.startsWith(`${excluded}/`)
      ))
      || GENERATED_EVIDENCE_EXCLUDED_PREFIXES.some(prefix => (
        entry.path === prefix || entry.path.startsWith(`${prefix}/`)
      ))
      || !/^[a-f0-9]{64}$/u.test(entry.sha256 || "")
      || !hasExactKeys(entry.identity, EXACT_FILE_IDENTITY_KEYS)
      || entry.identity.links !== "1"
      || Object.values(entry.identity).some(valuePart => (
        typeof valuePart !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(valuePart)
      ))) {
      failReleaseExposureProof();
    }
    paths.push(entry.path);
  }
  if (JSON.stringify(paths) !== JSON.stringify([...new Set(paths)].sort())) {
    failReleaseExposureProof();
  }
  return true;
}

function generatedEvidenceFromScan(component, expectedInventory) {
  if (component?.status !== "scanned"
    || !Number.isInteger(component.fileCount)
    || !Array.isArray(component.snapshotManifest)
    || component.fileCount !== component.snapshotManifest.length) {
    throw new Error("Generated release evidence scan did not return its exact snapshot manifest.");
  }
  const manifest = Object.freeze({
    boundary: Object.freeze({
      id: GENERATED_EVIDENCE_BOUNDARY,
      root: GENERATED_EVIDENCE_ROOT,
      excludedFiles: [...GENERATED_EVIDENCE_EXCLUDED_FILES],
      excludedPrefixes: [...GENERATED_EVIDENCE_EXCLUDED_PREFIXES],
    }),
    files: component.snapshotManifest.map(entry => Object.freeze({
      path: entry?.path,
      identity: isPlainObject(entry?.identity)
        ? Object.freeze({ ...entry.identity })
        : entry?.identity,
      sha256: entry?.sha256,
    })),
  });
  try {
    validateGeneratedEvidenceManifest(manifest);
  } catch {
    throw new Error("Generated release evidence scan did not return its exact snapshot manifest.");
  }
  const scannedInventory = manifest.files.map(entry => ({
    path: entry.path,
    identity: entry.identity,
  }));
  if (!sameGeneratedEvidenceInventory(scannedInventory, expectedInventory)) {
    throw new Error("Generated release evidence scan did not cover the exact manifest boundary.");
  }
  return manifest;
}

function validateCandidateSnapshotComponent(component, expectedIdentity, expectedSha256) {
  const snapshot = component?.snapshot;
  if (component?.status !== "scanned"
    || !Number.isInteger(component.fileCount) || component.fileCount < 2
    || !hasExactKeys(snapshot, ["identity", "path", "sha256"])
    || snapshot.path !== UI_CANDIDATE_ARTIFACT
    || snapshot.sha256 !== expectedSha256
    || !hasExactKeys(snapshot.identity, EXACT_FILE_IDENTITY_KEYS)
    || snapshot.identity.links !== "1"
    || !sameFileIdentity(snapshot.identity, expectedIdentity)) {
    throw new Error("VSIX release exposure scan did not bind the accepted candidate snapshot.");
  }
  return true;
}

function validateGeneratedEvidenceAcceptance(root, generatedEvidence, options = {}) {
  validateGeneratedEvidenceManifest(generatedEvidence);
  const repositoryRoot = assertRealRepositoryRoot(root);
  const expectedInventory = generatedEvidence.files.map(entry => ({
    path: entry.path,
    identity: entry.identity,
  }));
  try {
    assertExpectedGeneratedEvidenceInventory(repositoryRoot, expectedInventory, options);
    for (const entry of generatedEvidence.files) {
      const target = path.join(repositoryRoot, ...entry.path.split("/"));
      const proof = digestStableSingleLinkFile(target, {
        digestBytes: options.digestBytes,
        errorMessage: "Generated release evidence changed across the pre-acceptance boundary.",
        expectedIdentity: entry.identity,
        fileSystem: options.fileSystem,
        maximumBytes: MAX_GENERATED_FILE_BYTES,
        minimumBytes: 0,
      });
      if (proof.sha256 !== entry.sha256
        || !sameFileIdentity(entry.identity, proof.identity)) {
        throw new Error("Generated release evidence changed across the pre-acceptance boundary.");
      }
    }
    assertExpectedGeneratedEvidenceInventory(repositoryRoot, expectedInventory, options);
    return true;
  } catch {
    throw new Error("Generated release evidence changed across the pre-acceptance boundary.");
  }
}

function buildReleaseExposureResult(options = {}) {
  const components = options.components || [];
  const findings = components.flatMap(component => component.findings.map(finding => ({
    component: component.id,
    ...finding,
  })));
  const status = findings.length === 0 ? "passed" : "failed";
  const base = {
    schemaVersion: 2,
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
      candidateReceiptFingerprint: status === "passed"
        ? options.candidateReceiptFingerprint || null
        : null,
      uiResultSha256: status === "passed" ? options.uiResultSha256 || null : null,
      vsixSha256: status === "passed" ? options.vsixSha256 || null : null,
    },
    attestation: options.attestationPath ? {
      path: options.attestationPath,
      sha256: status === "passed" ? options.attestationSha256 || null : null,
    } : null,
    generatedEvidence: status === "passed" ? options.generatedEvidence || null : null,
    evidence: status === "passed" ? [...(options.evidenceManifest || [])] : [],
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
      "findings", "fingerprint", "generatedEvidence", "scanner", "schemaVersion", "source",
      "status",
    ])
      || value.schemaVersion !== 2
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
      || !isPlainObject(value.generatedEvidence)
      || value.components[0].fileCount !== value.generatedEvidence.files?.length
      || value.components[1].status !== "scanned"
      || !Number.isInteger(value.components[1].fileCount)
      || value.components[1].fileCount < 2
      || value.components[2].status !== (expected.attestationPath ? "scanned" : "not-present")
      || value.components[2].fileCount !== expectedEvidenceFileCount
      || JSON.stringify(value.evidence) !== JSON.stringify(expected.evidenceManifest || [])) {
      failReleaseExposureProof();
    }
    validateGeneratedEvidenceManifest(value.generatedEvidence);
    if (expected.generatedEvidence
      && JSON.stringify(value.generatedEvidence) !== JSON.stringify(expected.generatedEvidence)) {
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

function assertStableEvidence(root, evidenceManifest, attestation, snapshot, options = {}) {
  const expected = new Map([
    [attestation.path, attestation.sha256],
    ...evidenceManifest.map(reference => [reference.path, reference.sha256]),
  ]);
  for (const [relativePath, expectedSha256] of expected) {
    const original = readBoundedEvidenceBytes(relativePath, root, options).bytes;
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
    : readBoundedJson(UI_CANDIDATE_RECEIPT, root, ".quality/qualification", options);
  const candidateArtifactPath = options.candidateArtifactPath
    || resolveExistingRepositoryFile(UI_CANDIDATE_ARTIFACT, root, {
      subtree: ".quality/qualification",
    });
  const candidateIdentityBefore = exactFileIdentity(candidateArtifactPath);
  const uiLoaded = options.ui
    ? { document: options.ui, bytes: Buffer.from(JSON.stringify(options.ui)) }
    : readBoundedJson(UI_RESULT, root, ".quality/ui", options);
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
        const loaded = readBoundedJson(
          LIVE_ATTESTATION,
          root,
          "internal_docs/quality",
          options,
        );
        return { path: LIVE_ATTESTATION, ...loaded };
      })();
  const evidenceManifest = optionalAttestation
    ? releaseEvidenceManifest(optionalAttestation.document)
    : [];
  const evidencePaths = optionalAttestation
    ? [...new Set([optionalAttestation.path, ...evidenceManifest.map(reference => reference.path)])].sort()
    : [];

  const boundaryOptions = { ...options, source };
  const generatedInventoryBefore = generatedEvidenceInventory(root, boundaryOptions);
  (options.assertScannerVersion || assertScannerVersion)({ ...options, root });
  const generatedComponent = (options.scanGeneratedEvidence || scanGeneratedEvidence)(
    root,
    ".quality",
    {
      ...options,
      id: "post-ui-generated-quality-evidence",
      excludedFiles: GENERATED_EVIDENCE_EXCLUDED_FILES,
      excludedPrefixes: GENERATED_EVIDENCE_EXCLUDED_PREFIXES,
      expectedInventory: generatedInventoryBefore,
    }
  );
  const generatedEvidence = generatedEvidenceFromScan(
    generatedComponent,
    generatedInventoryBefore,
  );
  const candidateComponent = await (options.scanVsix || scanVsix)(
    root,
    UI_CANDIDATE_ARTIFACT,
    {
      ...options,
      expectedVsixIdentity: candidateIdentityBefore,
      expectedVsixSha256: candidateBinding.vsixSha256,
    }
  );
  validateCandidateSnapshotComponent(
    candidateComponent,
    candidateIdentityBefore,
    candidateBinding.vsixSha256,
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
    const currentUi = readBoundedBytes(
      UI_RESULT,
      root,
      ".quality/ui",
      MAX_JSON_BYTES,
      options,
    ).bytes;
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
        options,
      );
    }
    assertExpectedGeneratedEvidenceInventory(root, generatedInventoryBefore, boundaryOptions);
    validateGeneratedEvidenceAcceptance(root, generatedEvidence, boundaryOptions);
  }
  return buildReleaseExposureResult({
    source,
    candidateReceiptFingerprint: candidateBinding.receiptFingerprint,
    vsixSha256: candidateBinding.vsixSha256,
    uiResultSha256,
    attestationPath: optionalAttestation?.path || null,
    attestationSha256,
    generatedEvidence,
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
  GENERATED_EVIDENCE_BOUNDARY,
  GENERATED_EVIDENCE_CIRCULAR_OUTPUTS,
  GENERATED_EVIDENCE_EXCLUDED_FILES,
  GENERATED_EVIDENCE_EXCLUDED_PREFIXES,
  GENERATED_EVIDENCE_ROOT,
  LIVE_ATTESTATION,
  RELEASE_COMPONENT_IDS,
  RELEASE_EXPOSURE_RESULT,
  RELEASE_GATE_CIRCULAR_PATHS,
  RELEASE_GATE_EXPECTED_PATHS,
  assertExactReleaseGateTree,
  buildReleaseExposureResult,
  captureGeneratedEvidenceManifest,
  executeReleaseExposureScan,
  generatedEvidenceInventory,
  releaseEvidenceManifest,
  readBoundedBytes,
  readBoundedJson,
  scanAcceptedEvidence,
  validateGeneratedEvidenceAcceptance,
  validateReleaseExposureProof,
};

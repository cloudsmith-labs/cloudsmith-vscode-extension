// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { getDependencyArtifactKey } = require("./dependencyRecord");
const { isExactPackage } = require("../domain/package");

const BULK_SCAN_ABSENCE_EVIDENCE = new WeakMap();
const BULK_PREFLIGHT_PRESENCE_EVIDENCE = new WeakMap();

function isPlainRecord(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isBoundedEvidenceString(value) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= 4096
    && value.trim() === value
    && !/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u.test(value);
}

function optionalEvidenceStringIsValid(value) {
  return value == null || value === "" || isBoundedEvidenceString(value);
}

function packageCandidateEvidenceShapeIsValid(candidate) {
  if (!isPlainRecord(candidate)) return false;
  const identifiers = candidate.identifiers;
  if (identifiers != null && !isPlainRecord(identifiers)) return false;
  for (const value of [
    candidate.packageIdentifier,
    candidate.slug_perm,
    candidate.slug_perm_raw,
    candidate.scope,
    candidate.architecture,
    candidate.platform,
    candidate.platform_os,
    candidate.os,
    candidate.variant,
    identifiers && identifiers.group_id,
    identifiers && identifiers.scope,
    identifiers && identifiers.architecture,
    identifiers && identifiers.platform,
    identifiers && identifiers.docker_platform_os,
    identifiers && identifiers.docker_platform_variant,
  ]) {
    if (!optionalEvidenceStringIsValid(value)) return false;
  }
  const tags = candidate.tags;
  if (tags != null) {
    if (!isPlainRecord(tags)) return false;
    if (
      tags.version != null
      && (!Array.isArray(tags.version)
        || tags.version.length > 256
        || tags.version.some(tag => !isBoundedEvidenceString(tag)))
    ) {
      return false;
    }
  }
  if (
    candidate.architectures != null
    && (!Array.isArray(candidate.architectures)
      || candidate.architectures.length > 256
      || candidate.architectures.some(architecture => {
        if (typeof architecture === "string") return !isBoundedEvidenceString(architecture);
        if (!isPlainRecord(architecture)) return true;
        const values = [architecture.name, architecture.slug, architecture.identifier]
          .filter(value => value != null);
        return values.length === 0 || values.some(value => !isBoundedEvidenceString(value));
      }))
  ) {
    return false;
  }
  if (
    candidate.files != null
    && (!Array.isArray(candidate.files)
      || candidate.files.length > 1024
      || candidate.files.some(file => {
        if (!isPlainRecord(file)) return true;
        const values = [file.filename, file.name, file.path].filter(value => value != null);
        return values.length === 0 || values.some(value => !isBoundedEvidenceString(value));
      }))
  ) {
    return false;
  }
  return true;
}

function qualifierEvidenceIsIncomplete(candidate, dependency, format) {
  const qualifiers = dependency && dependency.qualifiers;
  const safeQualifiers = qualifiers && typeof qualifiers === "object" && !Array.isArray(qualifiers)
    ? qualifiers
    : {};
  if (format === "maven") {
    return !Array.isArray(candidate && candidate.files);
  }
  if (format === "ruby" && String(safeQualifiers.platform || "").trim()) {
    const identifiers = isPlainRecord(candidate && candidate.identifiers)
      ? candidate.identifiers
      : {};
    return ![
      candidate && candidate.architectures,
      candidate && candidate.architecture,
      candidate && candidate.platform,
      identifiers.architecture,
      identifiers.platform,
    ].some(value => value != null);
  }
  if (format === "swift" && String(safeQualifiers.scope || "").trim()) {
    const scope = String(safeQualifiers.scope).trim().toLowerCase();
    const identifiers = isPlainRecord(candidate && candidate.identifiers)
      ? candidate.identifiers
      : {};
    const observedScope = String(candidate && (candidate.scope || identifiers.scope) || "")
      .trim()
      .toLowerCase();
    const observedName = String(candidate && candidate.name || "").trim().toLowerCase();
    return !observedScope
      && !observedName.startsWith(`${scope}.`)
      && !observedName.startsWith(`${scope}/`);
  }
  if (format === "docker") {
    const requestedDigest = String(
      safeQualifiers.digest || dependency && dependency.digest || ""
    ).trim();
    return !requestedDigest && !isPlainRecord(candidate && candidate.tags);
  }
  return false;
}

function createBulkScanAbsenceEvidence({
  account,
  workspace,
  repository = null,
  projectFolder,
  scanId,
  selectionGeneration,
  operationId,
  cancellationToken,
  dependencies,
}) {
  const normalizedAccount = normalizeEvidenceAccount(account);
  const normalizedWorkspace = normalizeEvidenceScopePart(workspace);
  const normalizedRepository = repository == null
    ? null
    : normalizeEvidenceScopePart(repository);
  const normalizedProjectFolder = normalizeEvidenceProjectFolder(projectFolder);
  if (
    !normalizedAccount
    || !normalizedWorkspace
    || (repository != null && !normalizedRepository)
    || !normalizedProjectFolder
    || !Number.isSafeInteger(scanId)
    || scanId <= 0
    || !Number.isSafeInteger(selectionGeneration)
    || selectionGeneration <= 0
    || !Number.isSafeInteger(operationId)
    || operationId <= 0
    || !cancellationToken
    || typeof cancellationToken !== "object"
    || !Array.isArray(dependencies)
  ) {
    return null;
  }

  const artifactKeys = new Set();
  for (const dependency of dependencies) {
    if (!dependency || dependency.cloudsmithStatus !== "ABSENT") continue;
    const artifactKey = getDependencyArtifactKey(dependency);
    if (isBoundedEvidenceString(artifactKey)) artifactKeys.add(artifactKey);
  }
  if (artifactKeys.size === 0) return null;

  const evidence = Object.freeze({
    kind: "bulk-scan-absence",
    schemaVersion: 1,
    account: Object.freeze({ ...normalizedAccount }),
    workspace: normalizedWorkspace,
    repository: normalizedRepository,
    projectFolder: normalizedProjectFolder,
    scanId,
    selectionGeneration,
    operationId,
    artifactCount: artifactKeys.size,
  });
  BULK_SCAN_ABSENCE_EVIDENCE.set(evidence, Object.freeze({
    ...normalizedAccount,
    workspace: normalizedWorkspace,
    repository: normalizedRepository,
    projectFolder: normalizedProjectFolder,
    scanId,
    selectionGeneration,
    operationId,
    cancellationToken,
    artifactKeys,
  }));
  return evidence;
}

function getReusableBulkScanAbsenceProof(evidence, {
  account,
  workspace,
  repository,
  projectFolder,
  dependency,
  cancellationToken,
}) {
  const stored = evidence && BULK_SCAN_ABSENCE_EVIDENCE.get(evidence);
  const expectedAccount = normalizeEvidenceAccount(account);
  const expectedWorkspace = normalizeEvidenceScopePart(workspace);
  const expectedRepository = normalizeEvidenceScopePart(repository);
  const expectedProjectFolder = normalizeEvidenceProjectFolder(projectFolder);
  const artifactKey = dependency ? getDependencyArtifactKey(dependency) : null;
  if (
    !stored
    || !expectedAccount
    || !expectedWorkspace
    || !expectedRepository
    || !expectedProjectFolder
    || !isBoundedEvidenceString(artifactKey)
    || stored.activationId !== expectedAccount.activationId
    || stored.accountEpoch !== expectedAccount.accountEpoch
    || stored.workspace !== expectedWorkspace
    || (stored.repository !== null && stored.repository !== expectedRepository)
    || stored.projectFolder !== expectedProjectFolder
    || stored.cancellationToken !== cancellationToken
    || cancellationToken?.isCancellationRequested === true
    || !stored.artifactKeys.has(artifactKey)
  ) {
    return null;
  }
  return Object.freeze({ artifactKey, observedIdentities: Object.freeze([]) });
}

function createBulkPreflightPresenceEvidence({
  account,
  workspace,
  repository,
  projectFolder,
  cancellationToken,
  packagesByArtifactKey,
}) {
  const normalizedAccount = normalizeEvidenceAccount(account);
  const normalizedWorkspace = normalizeEvidenceScopePart(workspace);
  const normalizedRepository = normalizeEvidenceScopePart(repository);
  const normalizedProjectFolder = normalizeEvidenceProjectFolder(projectFolder);
  if (
    !normalizedAccount
    || !normalizedWorkspace
    || !normalizedRepository
    || !normalizedProjectFolder
    || !cancellationToken
    || typeof cancellationToken !== "object"
    || !(packagesByArtifactKey instanceof Map)
  ) return null;

  const packages = new Map();
  for (const [artifactKey, pkg] of packagesByArtifactKey) {
    if (
      !isBoundedEvidenceString(artifactKey)
      || !isExactPackage(pkg)
      || pkg.workspace !== normalizedWorkspace
      || pkg.repository !== normalizedRepository
    ) continue;
    packages.set(artifactKey, pkg);
  }
  if (packages.size === 0) return null;

  const evidence = Object.freeze({
    kind: "bulk-preflight-presence",
    schemaVersion: 1,
    packageCount: packages.size,
  });
  BULK_PREFLIGHT_PRESENCE_EVIDENCE.set(evidence, Object.freeze({
    ...normalizedAccount,
    workspace: normalizedWorkspace,
    repository: normalizedRepository,
    projectFolder: normalizedProjectFolder,
    cancellationToken,
    packages,
  }));
  return evidence;
}

function getReusableBulkPreflightPresencePackage(evidence, {
  account,
  workspace,
  repository,
  projectFolder,
  cancellationToken,
  dependency,
}) {
  const stored = evidence && BULK_PREFLIGHT_PRESENCE_EVIDENCE.get(evidence);
  const expectedAccount = normalizeEvidenceAccount(account);
  const expectedWorkspace = normalizeEvidenceScopePart(workspace);
  const expectedRepository = normalizeEvidenceScopePart(repository);
  const expectedProjectFolder = normalizeEvidenceProjectFolder(projectFolder);
  const artifactKey = dependency ? getDependencyArtifactKey(dependency) : null;
  if (
    !stored
    || !expectedAccount
    || !expectedWorkspace
    || !expectedRepository
    || !expectedProjectFolder
    || !isBoundedEvidenceString(artifactKey)
    || stored.activationId !== expectedAccount.activationId
    || stored.accountEpoch !== expectedAccount.accountEpoch
    || stored.workspace !== expectedWorkspace
    || stored.repository !== expectedRepository
    || stored.projectFolder !== expectedProjectFolder
    || stored.cancellationToken !== cancellationToken
    || cancellationToken?.isCancellationRequested === true
  ) return null;
  return stored.packages.get(artifactKey) || null;
}

function normalizeEvidenceAccount(account) {
  if (!account || typeof account !== "object" || Array.isArray(account)) return null;
  const activationId = String(account.activationId || "").trim();
  const accountEpoch = account.accountEpoch;
  if (
    !isBoundedEvidenceString(activationId)
    || !Number.isSafeInteger(accountEpoch)
    || accountEpoch < 0
  ) return null;
  return { activationId, accountEpoch };
}

function normalizeEvidenceScopePart(value) {
  const normalized = String(value == null ? "" : value).trim();
  if (
    !isBoundedEvidenceString(normalized)
    || /[\\/?#]/u.test(normalized)
    || normalized === "."
    || normalized === ".."
  ) return null;
  return normalized;
}

function normalizeEvidenceProjectFolder(value) {
  const normalized = String(value == null ? "" : value).trim();
  return isBoundedEvidenceString(normalized) ? normalized : null;
}

module.exports = {
  createBulkPreflightPresenceEvidence,
  createBulkScanAbsenceEvidence,
  getReusableBulkPreflightPresencePackage,
  getReusableBulkScanAbsenceProof,
  packageCandidateEvidenceShapeIsValid,
  qualifierEvidenceIsIncomplete,
};

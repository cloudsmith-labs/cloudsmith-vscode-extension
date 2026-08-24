// Copyright 2026 Cloudsmith Ltd. All rights reserved.

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

module.exports = {
  packageCandidateEvidenceShapeIsValid,
  qualifierEvidenceIsIncomplete,
};

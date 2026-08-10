// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { encodeApiPathSegment } = require("./apiEndpoint");

const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;
const DISPLAY_CONTROL_PATTERN = /[\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/;
const ENCODED_SEPARATOR_PATTERN = /%(?:2f|5c)/i;
const UNKNOWN_PLACEHOLDER_PATTERN = /\{[^{}]*\}/;
const MAX_WORKSPACE_LENGTH = 256;
const MAX_REPOSITORY_LENGTH = 256;
const MAX_PACKAGE_IDENTIFIER_LENGTH = 512;
const MAX_PACKAGE_NAME_LENGTH = 512;
const MAX_PACKAGE_VERSION_LENGTH = 512;
const MAX_PACKAGE_FORMAT_LENGTH = 64;
const MAX_FINGERPRINT_LENGTH = 1024;
const MAX_PIPELINE_STAGES = 50;
const MAX_TAGS_PER_STAGE = 20;
const MAX_PACKAGE_TAGS = 1000;
const MAX_TAG_TEMPLATE_LENGTH = 256;
const MAX_TAG_LENGTH = 256;
const STAGE_STATUSES = new Set([
  "not_attempted",
  "not_required",
  "succeeded",
  "failed",
  "ambiguous",
  "cancelled",
]);
const OVERALL_STATUSES = new Set(["succeeded", "failed", "partial", "ambiguous", "cancelled"]);
const REMOTE_STATES = new Set(["unchanged", "changed", "possibly_changed", "present"]);
const EVIDENCE_VALUES = new Set([
  "none",
  "fresh_read",
  "write_response",
  "write_dispatched",
  "malformed_write_response",
  "target_state_only",
  "user_confirmation",
]);

const DEFAULT_TAG_TEMPLATES = Object.freeze({
  onPromote: Object.freeze(["promoted-to-{target}", "approved-{date}"]),
  onReceive: Object.freeze(["promoted-from-{source}"]),
});

class PromotionContractError extends Error {
  constructor(code) {
    super(code);
    this.name = "PromotionContractError";
    this.code = code;
  }
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function unwrapLegacyValue(value) {
  let current = value;
  for (let depth = 0; depth < 2; depth += 1) {
    if (!isRecord(current) || !Object.prototype.hasOwnProperty.call(current, "value")) break;
    current = current.value;
  }
  if (isRecord(current)) throw new PromotionContractError("malformed_source_locator");
  return current;
}

function scalarString(value, maximumLength, code) {
  const normalized = value;
  if (
    typeof normalized !== "string"
    || normalized.length === 0
    || normalized.length > maximumLength
    || normalized !== normalized.trim()
    || CONTROL_CHARACTER_PATTERN.test(normalized)
    || DISPLAY_CONTROL_PATTERN.test(normalized)
  ) {
    throw new PromotionContractError(code);
  }
  return normalized;
}

function pathIdentity(value, maximumLength, code) {
  const normalized = scalarString(value, maximumLength, code);
  if (
    normalized === "."
    || normalized === ".."
    || normalized.includes("/")
    || normalized.includes("\\")
    || ENCODED_SEPARATOR_PATTERN.test(normalized)
  ) {
    throw new PromotionContractError(code);
  }
  try {
    encodeApiPathSegment(normalized);
  } catch {
    throw new PromotionContractError(code);
  }
  return normalized;
}

function collectLegacyAliases(values, normalizer, code) {
  const normalized = [];
  for (const value of values) {
    if (value === undefined || value === null) continue;
    let candidate;
    try {
      candidate = normalizer(unwrapLegacyValue(value));
    } catch {
      throw new PromotionContractError(code);
    }
    normalized.push(candidate);
  }
  if (normalized.length === 0 || normalized.some(value => value !== normalized[0])) {
    throw new PromotionContractError(code);
  }
  return normalized[0];
}

function createSourceLocator(item) {
  if (!isRecord(item)) throw new PromotionContractError("malformed_source_locator");
  const match = isRecord(item.cloudsmithMatch) ? item.cloudsmithMatch : {};
  const workspace = collectLegacyAliases(
    [item.namespace, item.cloudsmithWorkspace, match.namespace],
    value => pathIdentity(value, MAX_WORKSPACE_LENGTH, "malformed_source_workspace"),
    "conflicting_source_workspace"
  );
  const repository = collectLegacyAliases(
    [item.repository, item.cloudsmithRepo, match.repository],
    value => pathIdentity(value, MAX_REPOSITORY_LENGTH, "malformed_source_repository"),
    "conflicting_source_repository"
  );
  const packageIdentifier = collectLegacyAliases(
    [item.slug_perm, item.slug_perm_raw, match.slug_perm, match.slug_perm_raw],
    value => pathIdentity(value, MAX_PACKAGE_IDENTIFIER_LENGTH, "malformed_source_identifier"),
    "conflicting_source_identifier"
  );
  return deepFreeze({ workspace, repository, packageIdentifier });
}

function freshIdentifier(record, code) {
  const candidates = [];
  for (const field of ["slug_perm", "slug_perm_raw"]) {
    if (!Object.prototype.hasOwnProperty.call(record, field) || record[field] == null) continue;
    candidates.push(pathIdentity(record[field], MAX_PACKAGE_IDENTIFIER_LENGTH, code));
  }
  if (candidates.length === 0 || candidates.some(value => value !== candidates[0])) {
    throw new PromotionContractError(code);
  }
  return candidates[0];
}

function canonicalTags(value) {
  if (value == null) return Object.freeze([]);
  if (!isRecord(value)) throw new PromotionContractError("malformed_package_tags");
  const tags = [];
  for (const field of ["info", "version"]) {
    if (!Object.prototype.hasOwnProperty.call(value, field) || value[field] == null) continue;
    const fieldValue = Array.isArray(value[field]) ? value[field] : [value[field]];
    for (const tag of fieldValue) {
      if (tags.length >= MAX_PACKAGE_TAGS) {
        throw new PromotionContractError("malformed_package_tags");
      }
      tags.push(scalarString(tag, MAX_TAG_LENGTH, "malformed_package_tags"));
    }
  }
  return Object.freeze([...new Set(tags)]);
}

function immutableFingerprint(record) {
  const checksum = record.checksum_sha256 == null
    ? null
    : scalarString(record.checksum_sha256, MAX_FINGERPRINT_LENGTH, "malformed_package_fingerprint");
  const versionDigest = record.version_digest == null
    ? null
    : scalarString(record.version_digest, MAX_FINGERPRINT_LENGTH, "malformed_package_fingerprint");
  if (!checksum && !versionDigest) throw new PromotionContractError("missing_package_fingerprint");
  return deepFreeze({ checksum, versionDigest });
}

function normalizeFreshSource(record, locator) {
  if (!isRecord(record) || !locator) throw new PromotionContractError("malformed_source_package");
  const packageIdentifier = freshIdentifier(record, "malformed_source_identifier");
  const workspace = pathIdentity(record.namespace, MAX_WORKSPACE_LENGTH, "malformed_source_workspace");
  const repository = pathIdentity(record.repository, MAX_REPOSITORY_LENGTH, "malformed_source_repository");
  if (
    packageIdentifier !== locator.packageIdentifier
    || workspace !== locator.workspace
    || repository !== locator.repository
  ) {
    throw new PromotionContractError("source_identity_changed");
  }
  if (typeof record.is_copyable !== "boolean") {
    throw new PromotionContractError("malformed_copyability");
  }
  return deepFreeze({
    workspace,
    repository,
    packageIdentifier,
    name: scalarString(record.name, MAX_PACKAGE_NAME_LENGTH, "malformed_source_package"),
    version: scalarString(
      record.version,
      MAX_PACKAGE_VERSION_LENGTH,
      "malformed_source_package"
    ),
    format: scalarString(record.format, MAX_PACKAGE_FORMAT_LENGTH, "malformed_source_package"),
    copyable: record.is_copyable,
    fingerprint: immutableFingerprint(record),
    tags: canonicalTags(record.tags),
  });
}

function normalizeTargetRepository(record, workspace, selectedRepository) {
  if (!isRecord(record)) throw new PromotionContractError("malformed_target_repository");
  const repository = pathIdentity(record.slug, MAX_REPOSITORY_LENGTH, "malformed_target_repository");
  if (repository !== selectedRepository) throw new PromotionContractError("target_identity_changed");
  if (record.namespace != null) {
    const returnedWorkspace = pathIdentity(
      typeof record.namespace === "string" ? record.namespace : record.namespace.slug,
      MAX_WORKSPACE_LENGTH,
      "malformed_target_repository"
    );
    if (returnedWorkspace !== workspace) throw new PromotionContractError("target_identity_changed");
  }
  return deepFreeze({
    workspace,
    repository,
    name: scalarString(record.name, MAX_REPOSITORY_LENGTH, "malformed_target_repository"),
  });
}

function fingerprintsMatch(source, target) {
  const comparable = [
    [source.checksum, target.checksum],
    [source.versionDigest, target.versionDigest],
  ].filter(([left, right]) => left && right);
  return comparable.length > 0 && comparable.every(([left, right]) => left === right);
}

function normalizeTargetPackage(record, source, target) {
  if (!isRecord(record)) throw new PromotionContractError("malformed_target_package");
  const workspace = pathIdentity(record.namespace, MAX_WORKSPACE_LENGTH, "malformed_target_package");
  const repository = pathIdentity(record.repository, MAX_REPOSITORY_LENGTH, "malformed_target_package");
  const packageIdentifier = freshIdentifier(record, "malformed_target_identifier");
  const name = scalarString(record.name, MAX_PACKAGE_NAME_LENGTH, "malformed_target_package");
  const version = scalarString(
    record.version,
    MAX_PACKAGE_VERSION_LENGTH,
    "malformed_target_package"
  );
  const format = scalarString(record.format, MAX_PACKAGE_FORMAT_LENGTH, "malformed_target_package");
  const fingerprint = immutableFingerprint(record);
  if (
    workspace !== target.workspace
    || repository !== target.repository
    || name !== source.name
    || version !== source.version
    || format !== source.format
    || packageIdentifier === source.packageIdentifier
    || !fingerprintsMatch(source.fingerprint, fingerprint)
  ) {
    throw new PromotionContractError("target_package_identity_mismatch");
  }
  return deepFreeze({
    workspace,
    repository,
    packageIdentifier,
    name,
    version,
    format,
    fingerprint,
    tags: canonicalTags(record.tags),
  });
}

function normalizePipeline(value) {
  if (value === undefined) return Object.freeze([]);
  if (!Array.isArray(value) || value.length > MAX_PIPELINE_STAGES) {
    throw new PromotionContractError("malformed_pipeline");
  }
  const pipeline = value.map(stage => pathIdentity(
    stage,
    MAX_REPOSITORY_LENGTH,
    "malformed_pipeline"
  ));
  if (new Set(pipeline).size !== pipeline.length) {
    throw new PromotionContractError("malformed_pipeline");
  }
  return Object.freeze(pipeline);
}

function normalizePackageQueryIdentity(workspace, name, version, format) {
  return deepFreeze({
    workspace: pathIdentity(workspace, MAX_WORKSPACE_LENGTH, "malformed_package_query"),
    name: scalarString(name, MAX_PACKAGE_NAME_LENGTH, "malformed_package_query"),
    version: scalarString(version, MAX_PACKAGE_VERSION_LENGTH, "malformed_package_query"),
    format: scalarString(format, MAX_PACKAGE_FORMAT_LENGTH, "malformed_package_query"),
  });
}

function isPackageLocationArray(value) {
  if (!Array.isArray(value)) return false;
  try {
    return value.every(record => {
      if (!isRecord(record)) return false;
      pathIdentity(record.namespace, MAX_WORKSPACE_LENGTH, "malformed_package_location");
      pathIdentity(record.repository, MAX_REPOSITORY_LENGTH, "malformed_package_location");
      scalarString(record.name, MAX_PACKAGE_NAME_LENGTH, "malformed_package_location");
      scalarString(record.version, MAX_PACKAGE_VERSION_LENGTH, "malformed_package_location");
      scalarString(record.format, MAX_PACKAGE_FORMAT_LENGTH, "malformed_package_location");
      const packageIdentifier = pathIdentity(
        record.slug_perm,
        MAX_PACKAGE_IDENTIFIER_LENGTH,
        "malformed_package_location"
      );
      if (
        record.slug_perm_raw != null
        && pathIdentity(
          record.slug_perm_raw,
          MAX_PACKAGE_IDENTIFIER_LENGTH,
          "malformed_package_location"
        ) !== packageIdentifier
      ) {
        return false;
      }
      return true;
    });
  } catch {
    return false;
  }
}

function normalizeTagTemplates(value) {
  const templates = value == null ? DEFAULT_TAG_TEMPLATES : value;
  if (!isRecord(templates)) throw new PromotionContractError("malformed_tag_configuration");
  const normalizeStage = field => {
    const list = templates[field];
    if (!Array.isArray(list) || list.length > MAX_TAGS_PER_STAGE) {
      throw new PromotionContractError("malformed_tag_configuration");
    }
    return list.map(template => scalarString(
      template,
      MAX_TAG_TEMPLATE_LENGTH,
      "malformed_tag_configuration"
    ));
  };
  return deepFreeze({ onPromote: normalizeStage("onPromote"), onReceive: normalizeStage("onReceive") });
}

function expandTag(template, sourceRepository, targetRepository, date) {
  const expanded = template
    .replace(/\{source\}/g, sourceRepository)
    .replace(/\{target\}/g, targetRepository)
    .replace(/\{date\}/g, date);
  if (UNKNOWN_PLACEHOLDER_PATTERN.test(expanded)) {
    throw new PromotionContractError("malformed_tag_configuration");
  }
  return scalarString(expanded, MAX_TAG_LENGTH, "malformed_tag_configuration");
}

function createTagPlan(value, sourceRepository, targetRepository, date) {
  const templates = normalizeTagTemplates(value);
  const expandStage = stage => Object.freeze([
    ...new Set(templates[stage].map(template => (
      expandTag(template, sourceRepository, targetRepository, date)
    ))),
  ]);
  return deepFreeze({
    source: expandStage("onPromote"),
    target: expandStage("onReceive"),
    date,
  });
}

function missingTags(existing, required) {
  const existingSet = new Set(existing);
  return Object.freeze(required.filter(tag => !existingSet.has(tag)));
}

function createStage(status, options = {}) {
  const evidence = options.evidence === undefined ? "none" : options.evidence;
  if (
    !STAGE_STATUSES.has(status)
    || !EVIDENCE_VALUES.has(evidence)
    || (Object.prototype.hasOwnProperty.call(options, "required") && typeof options.required !== "boolean")
    || (Object.prototype.hasOwnProperty.call(options, "attempted") && typeof options.attempted !== "boolean")
  ) {
    throw new PromotionContractError("malformed_promotion_outcome");
  }
  return deepFreeze({
    status,
    required: options.required === true,
    attempted: options.attempted === true,
    evidence,
    errorCode: safeErrorCode(options.errorCode),
  });
}

function createOutcome(value) {
  if (!isRecord(value) || !OVERALL_STATUSES.has(value.overall)) {
    throw new PromotionContractError("malformed_promotion_outcome");
  }
  const remoteState = value.remoteState === undefined ? "unchanged" : value.remoteState;
  if (!REMOTE_STATES.has(remoteState)) {
    throw new PromotionContractError("malformed_promotion_outcome");
  }
  const outcome = {
    source: normalizeOutcomeSource(value.source),
    target: normalizeOutcomeTarget(value.target),
    preflight: normalizeOutcomeStage(value.preflight, createStage("not_attempted")),
    confirmation: normalizeOutcomeStage(value.confirmation, createStage("not_attempted")),
    copy: normalizeOutcomeStage(value.copy, createStage("not_attempted", { required: true })),
    sourceTag: normalizeOutcomeStage(value.sourceTag, createStage("not_attempted")),
    targetTag: normalizeOutcomeStage(value.targetTag, createStage("not_attempted")),
    reconciliation: normalizeOutcomeStage(value.reconciliation, createStage("not_attempted")),
    overall: value.overall,
    errorCode: safeErrorCode(value.errorCode),
    remoteState,
  };
  validateOutcomeAggregation(outcome);
  return deepFreeze(outcome);
}

function normalizeOutcomeSource(value) {
  if (value === undefined || value === null) return null;
  if (!isRecord(value) || typeof value.copyable !== "boolean" || !Array.isArray(value.tags)) {
    throw new PromotionContractError("malformed_promotion_outcome");
  }
  if (!isRecord(value.fingerprint)) {
    throw new PromotionContractError("malformed_promotion_outcome");
  }
  const checksum = value.fingerprint.checksum == null
    ? null
    : scalarString(
      value.fingerprint.checksum,
      MAX_FINGERPRINT_LENGTH,
      "malformed_promotion_outcome"
    );
  const versionDigest = value.fingerprint.versionDigest == null
    ? null
    : scalarString(
      value.fingerprint.versionDigest,
      MAX_FINGERPRINT_LENGTH,
      "malformed_promotion_outcome"
    );
  if (!checksum && !versionDigest) {
    throw new PromotionContractError("malformed_promotion_outcome");
  }
  const fingerprint = deepFreeze({ checksum, versionDigest });
  if (value.tags.length > MAX_PACKAGE_TAGS) {
    throw new PromotionContractError("malformed_promotion_outcome");
  }
  const tags = value.tags.map(tag => (
    scalarString(tag, MAX_TAG_LENGTH, "malformed_promotion_outcome")
  ));
  return deepFreeze({
    workspace: pathIdentity(value.workspace, MAX_WORKSPACE_LENGTH, "malformed_promotion_outcome"),
    repository: pathIdentity(value.repository, MAX_REPOSITORY_LENGTH, "malformed_promotion_outcome"),
    packageIdentifier: pathIdentity(
      value.packageIdentifier,
      MAX_PACKAGE_IDENTIFIER_LENGTH,
      "malformed_promotion_outcome"
    ),
    name: scalarString(value.name, MAX_PACKAGE_NAME_LENGTH, "malformed_promotion_outcome"),
    version: scalarString(value.version, MAX_PACKAGE_VERSION_LENGTH, "malformed_promotion_outcome"),
    format: scalarString(value.format, MAX_PACKAGE_FORMAT_LENGTH, "malformed_promotion_outcome"),
    copyable: value.copyable,
    fingerprint,
    tags: Object.freeze([...new Set(tags)]),
  });
}

function normalizeOutcomeTarget(value) {
  if (value === undefined || value === null) return null;
  if (!isRecord(value)) throw new PromotionContractError("malformed_promotion_outcome");
  return deepFreeze({
    workspace: pathIdentity(value.workspace, MAX_WORKSPACE_LENGTH, "malformed_promotion_outcome"),
    repository: pathIdentity(value.repository, MAX_REPOSITORY_LENGTH, "malformed_promotion_outcome"),
    name: scalarString(value.name, MAX_REPOSITORY_LENGTH, "malformed_promotion_outcome"),
  });
}

function normalizeOutcomeStage(value, fallback) {
  if (value === undefined || value === null) return fallback;
  if (!isRecord(value)) throw new PromotionContractError("malformed_promotion_outcome");
  if (
    (Object.prototype.hasOwnProperty.call(value, "required") && typeof value.required !== "boolean")
    || (Object.prototype.hasOwnProperty.call(value, "attempted") && typeof value.attempted !== "boolean")
    || (Object.prototype.hasOwnProperty.call(value, "evidence") && typeof value.evidence !== "string")
  ) {
    throw new PromotionContractError("malformed_promotion_outcome");
  }
  return createStage(value.status, {
    required: value.required,
    attempted: value.attempted,
    evidence: value.evidence,
    errorCode: value.errorCode,
  });
}

function validateOutcomeAggregation(outcome) {
  const tagStages = [outcome.sourceTag, outcome.targetTag];
  const requiredTags = tagStages.filter(stage => stage.required);
  const remoteStages = [outcome.copy, ...tagStages, outcome.reconciliation];
  const hasAmbiguous = remoteStages.some(stage => stage.status === "ambiguous");
  const copySucceeded = outcome.copy.status === "succeeded";
  const hasWriteIdentity = Boolean(outcome.source && outcome.target);
  const validAttemptedCopy = !outcome.copy.attempted || (
    hasWriteIdentity
    && outcome.source.copyable === true
    && outcome.source.workspace === outcome.target.workspace
    && outcome.source.repository !== outcome.target.repository
    && outcome.copy.required
    && outcome.preflight.status === "succeeded"
    && outcome.preflight.evidence === "fresh_read"
    && outcome.confirmation.status === "succeeded"
    && outcome.confirmation.evidence === "user_confirmation"
  );
  if (!validAttemptedCopy) {
    throw new PromotionContractError("malformed_promotion_outcome");
  }
  const allTagsComplete = tagStages.every(stage => (
    stage.status === "succeeded" || stage.status === "not_required"
  ));
  const allTagsResolved = tagStages.every(stage => (
    stage.status === "succeeded" || stage.status === "not_required" || stage.status === "failed"
  ));
  let valid = false;
  if (outcome.overall === "succeeded") {
    valid = hasWriteIdentity
      && copySucceeded
      && outcome.copy.attempted
      && outcome.reconciliation.status === "succeeded"
      && allTagsComplete
      && outcome.remoteState !== "unchanged";
  } else if (outcome.overall === "partial") {
    valid = hasWriteIdentity
      && copySucceeded
      && outcome.copy.attempted
      && outcome.reconciliation.status === "succeeded"
      && requiredTags.some(stage => stage.status === "failed")
      && allTagsResolved
      && !hasAmbiguous
      && outcome.remoteState !== "unchanged";
  } else if (outcome.overall === "ambiguous") {
    valid = hasWriteIdentity
      && hasAmbiguous
      && outcome.copy.attempted
      && (outcome.copy.status === "succeeded" || outcome.copy.status === "ambiguous")
      && outcome.remoteState !== "unchanged";
  } else if (outcome.overall === "failed") {
    valid = !copySucceeded
      && !hasAmbiguous
      && tagStages.every(stage => (
        stage.status === "not_attempted" || stage.status === "not_required"
      ))
      && outcome.reconciliation.status === "not_attempted"
      && outcome.remoteState === "unchanged";
  } else if (outcome.overall === "cancelled") {
    valid = remoteStages.every(stage => (
      stage.status === "not_attempted" || stage.status === "not_required"
    )) && outcome.remoteState === "unchanged";
  }
  if (!valid) throw new PromotionContractError("malformed_promotion_outcome");
}

function safeErrorCode(value) {
  if (value == null) return null;
  if (typeof value !== "string" || !/^[a-z0-9_]{1,64}$/.test(value)) {
    throw new PromotionContractError("malformed_promotion_outcome");
  }
  return value;
}

function preflightFingerprint(preflight, account, tagPlan) {
  return JSON.stringify([
    preflight.source.workspace,
    preflight.source.repository,
    preflight.source.packageIdentifier,
    preflight.source.name,
    preflight.source.version,
    preflight.source.format,
    preflight.source.copyable,
    preflight.source.fingerprint.checksum,
    preflight.source.fingerprint.versionDigest,
    preflight.target.workspace,
    preflight.target.repository,
    preflight.targetPackageState,
    preflight.targetPackageCount,
    account.activationId,
    account.accountEpoch,
    tagPlan.source,
    tagPlan.target,
    tagPlan.date,
  ]);
}

module.exports = {
  PromotionContractError,
  createOutcome,
  createSourceLocator,
  createStage,
  createTagPlan,
  deepFreeze,
  fingerprintsMatch,
  isPackageLocationArray,
  missingTags,
  normalizeFreshSource,
  normalizePackageQueryIdentity,
  normalizePipeline,
  normalizeTargetPackage,
  normalizeTargetRepository,
  preflightFingerprint,
};

// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { apiEndpoint, encodeApiPathSegment } = require("./apiEndpoint");
const {
  PaginatedFetch,
  collectionFailureResult,
  replaceCollectionItems,
} = require("./paginatedFetch");
const { exactIdentityPart } = require("./collectionIdentity");

const POLICY_DECISION_LOG_PAGE_SIZE = 100;
const MAX_POLICY_DECISION_LOG_PAGES = 20;
const MAX_POLICY_DECISION_LOG_ITEMS = POLICY_DECISION_LOG_PAGE_SIZE * MAX_POLICY_DECISION_LOG_PAGES;
const MAX_POLICY_STATUS_REASON_LENGTH = 4096;
const MAX_DISPLAY_LENGTH = 4096;
const MAX_PATH_IDENTITY_LENGTH = 512;
const ULID_PATTERN = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CONTROL_PATTERN = /[\u0000-\u001f\u007f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/;
const DISPLAY_CONTROL_PATTERN = /[\u0000-\u001f\u007f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g;
const ENCODED_SEPARATOR_PATTERN = /%(?:2f|5c)/i;

function createQuarantineLocator(item) {
  if (!isObjectRecord(item)) return null;
  const nestedMatch = ownData(item, "cloudsmithMatch");
  const match = isObjectRecord(nestedMatch) ? nestedMatch : {};
  const workspace = canonicalAliases([
    ownData(item, "namespace"),
    ownData(item, "cloudsmithWorkspace"),
    ownData(match, "namespace"),
    ownData(match, "cloudsmithWorkspace"),
  ]);
  const repository = canonicalAliases([
    ownData(item, "repository"),
    ownData(item, "cloudsmithRepo"),
    ownData(match, "repository"),
    ownData(match, "cloudsmithRepo"),
  ]);
  const packageSlugPerm = canonicalAliases([
    ownData(item, "slug_perm_raw"),
    ownData(item, "slug_perm"),
    ownData(match, "slug_perm_raw"),
    ownData(match, "slug_perm"),
  ]);
  if (!workspace || !repository || !packageSlugPerm) return null;
  return Object.freeze({ workspace, repository, packageSlugPerm });
}

async function fetchPackageDecisionLogs(api, locator, createdAfter, options = {}) {
  if (!api || typeof api.getV2 !== "function" || !isLocator(locator)) {
    return failedCollection("The policy decision log identity was invalid.");
  }
  const createdAfterValue = canonicalDateTime(createdAfter);
  if (!createdAfterValue) {
    return failedCollection("The policy decision log time boundary was invalid.");
  }

  let endpoint;
  try {
    const query = {
      created_after: createdAfterValue,
      package_slug_perm: locator.packageSlugPerm,
      match: true,
      sort: "-id",
    };
    const policySlug = pathIdentity(options.policySlug);
    const repositorySlugPerm = pathIdentity(options.repositorySlugPerm);
    if (options.policySlug != null && !policySlug) {
      return failedCollection("The policy decision log policy identity was invalid.");
    }
    if (options.repositorySlugPerm != null && !repositorySlugPerm) {
      return failedCollection("The policy decision log repository identity was invalid.");
    }
    if (policySlug) query.policy_slug_perm = policySlug;
    if (repositorySlugPerm) query.repository_slug_perm = repositorySlugPerm;
    endpoint = apiEndpoint([
      "workspaces",
      locator.workspace,
      "policies",
      "decision-logs-v1",
    ], { query });
  } catch {
    return failedCollection("The policy decision log endpoint was invalid.");
  }

  const paginatedFetch = options.paginatedFetch || new PaginatedFetch({
    get: api.getV2.bind(api),
  });
  const collection = await paginatedFetch.fetchCollection(endpoint, {
    pageSize: POLICY_DECISION_LOG_PAGE_SIZE,
    maxPages: MAX_POLICY_DECISION_LOG_PAGES,
    maxRequests: MAX_POLICY_DECISION_LOG_PAGES,
    maxItems: MAX_POLICY_DECISION_LOG_ITEMS,
    canonicalIdentity: decisionLogIdentity,
    descriptor: "policy-decision-logs",
    responseType: "json",
    validateResponse: isDecisionLogResponse,
    extractItems: extractDecisionLogs,
    retry: "never",
    signal: options.signal,
    cancellationToken: options.cancellationToken,
  });

  return replaceCollectionItems(collection, collection.items.map(normalizeDecisionLog));
}

async function fetchDecisionLogDetail(api, locator, summary, options = {}) {
  if (
    !api
    || typeof api.getV2 !== "function"
    || !isLocator(locator)
    || !summary
    || !ULID_PATTERN.test(summary.id || "")
  ) {
    return null;
  }
  let endpoint;
  try {
    endpoint = apiEndpoint([
      "workspaces",
      locator.workspace,
      "policies",
      "decision-logs-v1",
      summary.id,
    ], {
      query: {
        fields: "id,correlation_id,policy,started_at,ended_at,policy_input,policy_output,parsed_actions",
      },
    });
  } catch {
    return null;
  }
  try {
    const result = await api.getV2(endpoint, {
      responseType: "object",
      validate: value => isDecisionLogDetail(value, locator, summary),
      retry: "never",
      signal: options.signal,
    });
    if (!result.ok) return null;
    return normalizeDecisionLogDetail(result.data, summary);
  } catch {
    return null;
  }
}

function selectCausalDecision(items, policySlug = null) {
  const exactPolicySlug = policySlug == null ? null : pathIdentity(policySlug);
  if (policySlug != null && !exactPolicySlug) return null;
  const candidates = (Array.isArray(items) ? items : []).filter(entry => (
    entry
    && entry.match === true
    && entry.action === "Quarantined"
    && (!exactPolicySlug || entry.policySlugPerm === exactPolicySlug)
  ));
  candidates.sort((left, right) => (left.id === right.id ? 0 : left.id < right.id ? 1 : -1));
  return candidates[0] || null;
}

function normalizeDecisionLog(entry) {
  return Object.freeze({
    id: entry.id,
    correlationId: entry.correlation_id,
    packageSlugPerm: entry.package_slug_perm,
    repositorySlug: entry.repository_slug,
    repositorySlugPerm: entry.repository_slug_perm,
    policySlugPerm: entry.policy_slug_perm,
    policyName: displayString(entry.policy_name, 512),
    policyPrecedence: entry.policy_precedence,
    policyIsTerminal: entry.policy_is_terminal,
    match: entry.match,
    action: hasQuarantineAction(entry.actions) ? "Quarantined" : null,
    startedAt: entry.started_at,
    endedAt: entry.ended_at,
  });
}

function normalizeDecisionLogDetail(entry, summary) {
  if (!hasQuarantineAction(entry.parsed_actions)) return null;
  const policyOutput = isRecord(entry.policy_output) ? entry.policy_output : null;
  const reason = policyOutput
    ? displayString(policyOutput.reason || policyOutput.message || policyOutput.detail, MAX_DISPLAY_LENGTH)
    : displayString(entry.policy_output, MAX_DISPLAY_LENGTH);
  return Object.freeze({
    id: summary.id,
    policySlugPerm: summary.policySlugPerm,
    policyName: summary.policyName,
    action: "Quarantined",
    reason,
    startedAt: summary.startedAt,
    endedAt: summary.endedAt,
  });
}

function normalizePolicyStatusReason(value) {
  if (typeof value !== "string") return null;
  const bounded = value.length <= MAX_POLICY_STATUS_REASON_LENGTH
    ? value
    : `${value.slice(0, MAX_POLICY_STATUS_REASON_LENGTH - 1)}…`;
  return bounded.replace(DISPLAY_CONTROL_PATTERN, " ").trim() || null;
}

function parsePolicyStatusReason(value) {
  const normalized = normalizePolicyStatusReason(value);
  if (!normalized) return null;
  const match = /^Quarantined by ([^.]+)\.\s*(.*?)(?:\s*\(Policy:\s*([^()]+)\))?$/.exec(normalized);
  if (!match) return Object.freeze({ raw: normalized });
  const policyName = displayString(match[1], 512);
  const description = displayString(match[2], MAX_POLICY_STATUS_REASON_LENGTH);
  const policySlug = match[3] ? pathIdentity(match[3].trim()) : null;
  return Object.freeze({ policyName, description, policySlug, raw: normalized });
}

function isDecisionLogResponse(value) {
  const items = extractDecisionLogs(value);
  return items !== null && items.every(isDecisionLogRecord);
}

function isDecisionLogRecord(value) {
  return isRecord(value)
    && ULID_PATTERN.test(value.id || "")
    && UUID_PATTERN.test(value.correlation_id || "")
    && typeof value.match === "boolean"
    && Boolean(pathIdentity(value.package_slug_perm))
    && Boolean(pathIdentity(value.repository_slug))
    && Boolean(pathIdentity(value.repository_slug_perm))
    && Boolean(pathIdentity(value.policy_slug_perm))
    && Boolean(displayString(value.policy_name, 512))
    && Number.isInteger(value.policy_precedence)
    && typeof value.policy_is_terminal === "boolean"
    && Boolean(canonicalDateTime(value.started_at))
    && Boolean(canonicalDateTime(value.ended_at))
    && isRecord(value.actions);
}

function isDecisionLogDetail(value, locator, summary) {
  if (!isRecord(value) || value.id !== summary.id || value.correlation_id !== summary.correlationId) {
    return false;
  }
  if (!isRecord(value.policy) || value.policy.slug_perm !== summary.policySlugPerm) return false;
  if (!isRecord(value.policy_input) || !isRecord(value.policy_input.v0)) return false;
  const input = value.policy_input.v0;
  const workspace = input.workspace;
  const repository = input.repository;
  const pkg = input.package;
  if (!isRecord(workspace) || !isRecord(repository) || !isRecord(pkg)) return false;
  if (workspace.slug !== locator.workspace) return false;
  if (repository.slug !== locator.repository || pkg.slug_perm !== locator.packageSlugPerm) return false;
  return canonicalDateTime(value.started_at) === summary.startedAt
    && canonicalDateTime(value.ended_at) === summary.endedAt
    && Object.prototype.hasOwnProperty.call(value, "policy_output")
    && Object.prototype.hasOwnProperty.call(value, "parsed_actions");
}

function hasQuarantineAction(value) {
  if (Array.isArray(value)) {
    return value.length <= 50 && value.some(entry => exactQuarantineAction(entry));
  }
  return exactQuarantineAction(value);
}

function exactQuarantineAction(value) {
  if (!isRecord(value)) return false;
  if (
    ownData(value, "action_type") === "SetPackageState"
    && ownData(value, "package_state") === "QUARANTINED"
  ) return true;
  const named = ownData(value, "SetPackageState");
  return isRecord(named) && ownData(named, "package_state") === "QUARANTINED";
}

function decisionLogIdentity(entry) {
  return entry && ULID_PATTERN.test(entry.id || "") ? entry.id : null;
}

function extractDecisionLogs(value) {
  return isRecord(value) && Array.isArray(value.results) ? value.results : null;
}

function canonicalAliases(values) {
  const supplied = values.filter(value => value !== undefined && value !== null);
  if (supplied.length === 0) return null;
  const normalized = supplied.map(value => pathIdentity(unwrapOwnValue(value)));
  return normalized.every(value => value && value === normalized[0]) ? normalized[0] : null;
}

function isLocator(locator) {
  return isRecord(locator)
    && pathIdentity(locator.workspace) === locator.workspace
    && pathIdentity(locator.repository) === locator.repository
    && pathIdentity(locator.packageSlugPerm) === locator.packageSlugPerm;
}

function pathIdentity(value) {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > MAX_PATH_IDENTITY_LENGTH
    || value.trim() !== value
    || CONTROL_PATTERN.test(value)
    || value.includes("/")
    || value.includes("\\")
    || ENCODED_SEPARATOR_PATTERN.test(value)
    || value === "."
    || value === ".."
  ) return null;
  try {
    encodeApiPathSegment(value);
    exactIdentityPart(value, "policy trace");
    return value;
  } catch {
    return null;
  }
}

function canonicalDateTime(value) {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > 128
    || value.trim() !== value
    || CONTROL_PATTERN.test(value)
    || !/^\d{4}-\d{2}-\d{2}T/.test(value)
    || !Number.isFinite(Date.parse(value))
  ) return null;
  return value;
}

function displayString(value, maxLength) {
  if (typeof value !== "string") return null;
  const normalized = value.replace(DISPLAY_CONTROL_PATTERN, " ").trim();
  if (!normalized) return null;
  return normalized.length <= maxLength ? normalized : `${normalized.slice(0, maxLength - 1)}…`;
}

function isRecord(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function isObjectRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function ownData(value, key) {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && Object.prototype.hasOwnProperty.call(descriptor, "value")
      ? descriptor.value
      : undefined;
  } catch {
    return undefined;
  }
}

function unwrapOwnValue(value) {
  let current = value;
  for (let depth = 0; depth < 4; depth += 1) {
    if (!isRecord(current)) return current;
    const descriptor = Object.getOwnPropertyDescriptor(current, "value");
    if (!descriptor) return null;
    if (!Object.prototype.hasOwnProperty.call(descriptor, "value")) return null;
    current = descriptor.value;
  }
  return isRecord(current) ? null : current;
}

function failedCollection(message) {
  const failure = Object.freeze({
    kind: "invalid_request",
    status: null,
    retryable: false,
    message,
    requestId: null,
    retryAfterMs: null,
    outcomeUnknown: false,
    diagnostic: Object.freeze({}),
  });
  return collectionFailureResult(failure, { termination: "invalid_request" });
}

module.exports = {
  MAX_POLICY_DECISION_LOG_ITEMS,
  MAX_POLICY_DECISION_LOG_PAGES,
  MAX_POLICY_STATUS_REASON_LENGTH,
  POLICY_DECISION_LOG_PAGE_SIZE,
  createQuarantineLocator,
  fetchDecisionLogDetail,
  fetchPackageDecisionLogs,
  hasQuarantineAction,
  isDecisionLogResponse,
  normalizePolicyStatusReason,
  parsePolicyStatusReason,
  selectCausalDecision,
};

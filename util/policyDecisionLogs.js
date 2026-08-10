// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { apiEndpoint } = require("./apiEndpoint");
const {
  PaginatedFetch,
  collectionFailureResult,
  replaceCollectionItems,
} = require("./paginatedFetch");
const {
  MAX_COLLECTION_IDENTITY_PART_LENGTH,
  exactIdentityPart,
} = require("./collectionIdentity");

const POLICY_DECISION_LOG_PAGE_SIZE = 100;
const MAX_POLICY_DECISION_LOG_PAGES = 20;
const MAX_POLICY_DECISION_LOG_ITEMS = POLICY_DECISION_LOG_PAGE_SIZE * MAX_POLICY_DECISION_LOG_PAGES;
const MAX_POLICY_PACKAGE_ID_LENGTH = MAX_COLLECTION_IDENTITY_PART_LENGTH;
const MAX_POLICY_STATUS_REASON_LENGTH = 4096;
const MAX_POLICY_LOG_DISPLAY_LENGTH = 4096;
const MAX_POLICY_ACTIONS = 50;

async function fetchPackageDecisionLogs(api, workspace, packageIdentifier, options = {}) {
  const normalizedPackageIdentifier = boundedString(packageIdentifier, MAX_POLICY_PACKAGE_ID_LENGTH);
  if (!api || typeof api.getV2 !== "function" || !normalizedPackageIdentifier) {
    return failedCollection("The policy decision log identity was invalid.");
  }

  let endpoint;
  try {
    endpoint = apiEndpoint(["workspaces", workspace, "policies", "decision", "logs"]);
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
    descriptor: `policy-decision-logs:${workspace}`,
    responseType: "json",
    validateResponse: isDecisionLogResponse,
    extractItems: extractDecisionLogs,
    retry: "never",
    signal: options.signal,
    cancellationToken: options.cancellationToken,
  });

  return replaceCollectionItems(
    collection,
    collection.items.filter(entry => (
      decisionLogMatchesPackage(entry, normalizedPackageIdentifier)
    )).map(normalizeDecisionLog)
  );
}

function normalizeDecisionLog(entry) {
  const normalized = {
    slug_perm: decisionLogIdentity(entry),
    package_slug_perm: decisionLogPackageReference(entry),
    policy_name: displayString(
      entry.policy_name || entry.name || (entry.policy && entry.policy.name),
      512
    ),
    matched: typeof entry.matched === "boolean" ? entry.matched : null,
    action: normalizeActions(entry.action, entry.actions_taken),
    reason: displayString(entry.reason, MAX_POLICY_LOG_DISPLAY_LENGTH),
    created_at: displayString(entry.created_at, 128),
  };
  return Object.freeze(normalized);
}

function normalizeActions(action, actionsTaken) {
  const direct = displayString(action, MAX_POLICY_LOG_DISPLAY_LENGTH);
  if (direct) return direct;
  if (!Array.isArray(actionsTaken)) return null;
  const summaries = actionsTaken.slice(0, MAX_POLICY_ACTIONS).map(value => {
    if (!isRecord(value)) return null;
    const type = displayString(value.action_type, 256);
    const state = displayString(value.package_state, 256);
    return [type, state].filter(Boolean).join(": ") || null;
  }).filter(Boolean);
  return summaries.length > 0 ? summaries.join("; ") : null;
}

function normalizePolicyStatusReason(value) {
  if (typeof value !== "string") return null;
  const bounded = value.length <= MAX_POLICY_STATUS_REASON_LENGTH
    ? value
    : `${value.slice(0, MAX_POLICY_STATUS_REASON_LENGTH - 1)}…`;
  const normalized = bounded.trim();
  if (!normalized) return null;
  return normalized;
}

function parsePolicyStatusReason(value) {
  const normalized = normalizePolicyStatusReason(value);
  if (!normalized) return null;

  const match = /^Quarantined by ([^.]+)\.\s*(.*?)(?:\s*\(Policy:\s*([^()]+)\))?$/.exec(normalized);
  if (!match) return { raw: normalized };
  return {
    policyName: match[1].trim(),
    description: match[2].trim(),
    policySlug: match[3] ? match[3].trim() : null,
  };
}

function decisionLogIdentity(entry) {
  try {
    return exactIdentityPart(entry && entry.slug_perm, "policy decision log");
  } catch {
    return null;
  }
}

function decisionLogMatchesPackage(entry, packageIdentifier) {
  return decisionLogPackageReference(entry) === packageIdentifier;
}

function isDecisionLogResponse(value) {
  const items = extractDecisionLogs(value);
  return items !== null && items.every(isDecisionLogRecord);
}

function extractDecisionLogs(value) {
  if (Array.isArray(value)) return value;
  if (!isRecord(value) || !Array.isArray(value.results)) return null;
  return value.results;
}

function isDecisionLogRecord(value) {
  return isRecord(value)
    && Boolean(decisionLogIdentity(value))
    && Boolean(decisionLogPackageReference(value))
    && (
      !Object.prototype.hasOwnProperty.call(value, "matched")
      || typeof value.matched === "boolean"
    );
}

function decisionLogPackageReference(entry) {
  if (!isRecord(entry)) return null;
  const aliases = [];

  if (Object.prototype.hasOwnProperty.call(entry, "package_slug_perm")) {
    aliases.push(entry.package_slug_perm);
  }
  if (
    isRecord(entry.package)
    && Object.prototype.hasOwnProperty.call(entry.package, "identifier")
  ) {
    aliases.push(entry.package.identifier);
  }
  if (aliases.length === 0) return null;

  try {
    const normalized = aliases.map(value => exactIdentityPart(value, "policy package"));
    return new Set(normalized).size === 1 ? normalized[0] : null;
  } catch {
    return null;
  }
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function boundedString(value, maxLength) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= maxLength
    && value.trim() === value
    ? value
    : null;
}

function displayString(value, maxLength) {
  if (typeof value !== "string") return null;
  const bounded = value.length <= maxLength ? value : `${value.slice(0, maxLength - 1)}…`;
  return bounded.trim() || null;
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
  decisionLogMatchesPackage,
  fetchPackageDecisionLogs,
  isDecisionLogResponse,
  normalizePolicyStatusReason,
  parsePolicyStatusReason,
};

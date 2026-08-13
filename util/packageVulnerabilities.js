// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { apiEndpoint, encodeApiPathSegment } = require("./apiEndpoint");
const { PaginatedFetch } = require("./paginatedFetch");
const { exactIdentityPart, unwrapIdentityValue } = require("./collectionIdentity");
const {
  deriveMaximumVulnerabilitySeverity,
  normalizeVulnerabilitySeverity,
} = require("./vulnerabilitySeverity");

const VULNERABILITIES_DETECTED_STATUS = "scan detected vulnerabilities";
const VULNERABILITIES_CLEAN_STATUS = "scan detected no vulnerabilities";
const VULNERABILITY_SCAN_PAGE_SIZE = 100;
const MAX_VULNERABILITY_SCAN_PAGES = 20;
const MAX_VULNERABILITY_SCANS = VULNERABILITY_SCAN_PAGE_SIZE * MAX_VULNERABILITY_SCAN_PAGES;
const MAX_VULNERABILITY_DETAILS = 5000;
const MAX_VULNERABILITY_IDENTIFIER_LENGTH = 512;
const MAX_VULNERABILITY_SEVERITY_LENGTH = 100;
const PACKAGE_POLICY_FIELDS = Object.freeze([
  "policy_violated",
  "deny_policy_violated",
  "license_policy_violated",
  "vulnerability_policy_violated",
]);

function unwrapValue(value) {
  return unwrapIdentityValue(value);
}

function normalizeCount(value) {
  const unwrapped = unwrapValue(value);
  if (unwrapped === null || unwrapped === undefined || unwrapped === "") {
    return null;
  }

  if (Number.isSafeInteger(unwrapped) && unwrapped >= 0) return unwrapped;
  if (typeof unwrapped !== "string" || !/^(0|[1-9]\d*)$/.test(unwrapped)) return null;
  const count = Number(unwrapped);
  return Number.isSafeInteger(count) ? count : null;
}

function normalizeBoolean(value) {
  const unwrapped = unwrapValue(value);
  if (unwrapped === true || unwrapped === false) {
    return unwrapped;
  }
  if (typeof unwrapped === "string") {
    const normalized = unwrapped.trim().toLowerCase();
    if (normalized === "true") return true;
    if (normalized === "false") return false;
  }
  return null;
}

/**
 * Return a numeric package vulnerability indicator.
 * Positive values are known counts, zero is an authoritative clean indicator,
 * -1 means vulnerabilities were detected without a trustworthy count, and null
 * means the available evidence cannot establish either detection or cleanliness.
 */
function getPackageVulnerabilityCount(pkg) {
  const indicator = getPackageVulnerabilityState(pkg);
  return indicator.count !== null
    ? indicator.count
    : indicator.detected ? -1 : indicator.unknown ? null : 0;
}

/**
 * Canonicalize security policy booleans without turning malformed present values
 * into negative evidence. Missing fields retain the API's legacy false default.
 */
function getPackagePolicyFlags(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const flags = {};
  for (const field of PACKAGE_POLICY_FIELDS) {
    if (
      Object.prototype.hasOwnProperty.call(value, field)
      && typeof value[field] !== "boolean"
    ) {
      return null;
    }
    flags[field] = value[field] === true;
  }
  return flags;
}

function extractResultsFromScan(scan) {
  if (!scan || typeof scan !== "object") {
    return [];
  }
  if (Array.isArray(scan.results)) {
    return scan.results;
  }
  if (Array.isArray(scan.vulnerabilities)) {
    return scan.vulnerabilities;
  }
  if (Array.isArray(scan.Vulnerabilities)) {
    return scan.Vulnerabilities;
  }
  return [];
}

/** Preserve raw vulnerability records while accepting documented and legacy envelopes. */
function extractVulnerabilityResults(payload) {
  if (!payload || typeof payload !== "object") {
    return [];
  }

  if (Array.isArray(payload.results)) {
    return payload.results;
  }
  if (Array.isArray(payload.vulnerabilities)) {
    return payload.vulnerabilities;
  }

  if (Array.isArray(payload.scan)) {
    return collectNestedVulnerabilityResults(payload.scan);
  }
  const documentedResults = extractResultsFromScan(payload.scan);
  if (documentedResults.length > 0) {
    return documentedResults;
  }

  if (Array.isArray(payload.scans)) {
    return collectNestedVulnerabilityResults(payload.scans);
  }

  return [];
}

function collectNestedVulnerabilityResults(scans) {
  if (!Array.isArray(scans) || scans.length > MAX_VULNERABILITY_DETAILS) return null;
  const results = [];
  for (const scan of scans) {
    const scanResults = extractResultsFromScan(scan);
    if (results.length + scanResults.length > MAX_VULNERABILITY_DETAILS) return null;
    results.push(...scanResults);
  }
  return results;
}

function scanReportsVulnerabilities(scan) {
  const indicator = getPackageVulnerabilityState(scan);
  return indicator.detected || indicator.unknown;
}

function getPackageVulnerabilityState(value) {
  const record = value && typeof value === "object" ? value : {};
  const countAliases = [
    "num_vulnerabilities",
    "vulnerability_scan_results_count",
    "vulnerabilityCount",
  ].filter(alias => (
    Object.prototype.hasOwnProperty.call(record, alias)
    && record[alias] !== undefined
    && record[alias] !== null
    && record[alias] !== ""
  ));
  const counts = countAliases.map(alias => normalizeCount(record[alias]));
  const invalidCount = counts.some(count => count === null);
  const validCounts = counts.filter(Number.isSafeInteger);
  const uniqueCounts = new Set(validCounts);
  const hasPresence = Object.prototype.hasOwnProperty.call(record, "has_vulnerabilities")
    && record.has_vulnerabilities !== undefined
    && record.has_vulnerabilities !== null
    && record.has_vulnerabilities !== "";
  const presence = hasPresence ? normalizeBoolean(record.has_vulnerabilities) : null;
  const invalidPresence = hasPresence && presence === null;
  const status = unwrapValue(record.security_scan_status);
  const hasStatus = status !== undefined && status !== null && status !== "";
  const validStatus = !hasStatus || (typeof status === "string" && status.length <= 256);
  const normalizedStatus = validStatus && typeof status === "string"
    ? status.trim().toLowerCase()
    : null;
  const detectedStatus = normalizedStatus === VULNERABILITIES_DETECTED_STATUS;
  const cleanStatus = normalizedStatus === VULNERABILITIES_CLEAN_STATUS;
  const recognizedStatus = !hasStatus || detectedStatus || cleanStatus;
  const positiveCount = validCounts.some(count => count > 0);
  const zeroCount = validCounts.some(count => count === 0);
  const detected = positiveCount || presence === true || detectedStatus;
  const conflict = uniqueCounts.size > 1
    || (detected && (zeroCount || presence === false || cleanStatus));
  const hasEvidence = countAliases.length > 0 || hasPresence || hasStatus;
  const unknown = !hasEvidence
    || invalidCount
    || invalidPresence
    || !validStatus
    || !recognizedStatus
    || conflict;
  const explicitClean = presence === false || cleanStatus;
  const count = !unknown && uniqueCounts.size === 1
    ? validCounts[0]
    : !unknown && explicitClean ? 0 : null;
  return {
    count,
    detected,
    unknown,
    candidateCount: validCounts.length > 0 ? Math.max(...validCounts) : null,
  };
}

function result(error, results = [], maxSeverity = "Unknown", numVulns = null, complete = error == null) {
  const authoritativeCount = error == null && complete ? numVulns : null;
  return {
    results,
    maxSeverity,
    numVulns: authoritativeCount === null ? -1 : authoritativeCount,
    error,
    complete,
    incomplete: !complete,
    partial: !complete && results.length > 0,
    cancelled: Boolean(error && typeof error === "object" && error.kind === "cancelled"),
  };
}

/**
 * Fetch the latest package scan and its vulnerability records from the v1 API.
 * API failures remain distinct from a successful zero-vulnerability response.
 */
async function fetchPackageVulnerabilities(api, workspace, repo, packageIdentifier, expectedCount = null, options = {}) {
  const fallbackCount = Number.isSafeInteger(expectedCount) && expectedCount > 0
    ? expectedCount
    : null;
  let scanListEndpoint;
  try {
    scanListEndpoint = apiEndpoint(["vulnerabilities", workspace, repo, packageIdentifier]);
  } catch (error) {
    return result(error, [], "Unknown", fallbackCount);
  }

  const paginatedFetch = options.paginatedFetch || new PaginatedFetch(api);
  const scanCollection = await paginatedFetch.fetchCollection(scanListEndpoint, {
    pageSize: VULNERABILITY_SCAN_PAGE_SIZE,
    maxPages: MAX_VULNERABILITY_SCAN_PAGES,
    maxRequests: MAX_VULNERABILITY_SCAN_PAGES,
    maxItems: MAX_VULNERABILITY_SCANS,
    canonicalIdentity: scanIdentity,
    descriptor: `vulnerability-scans:${workspace}:${repo}:${packageIdentifier}`,
    responseType: "array",
    validate: isScanRecordArray,
    retry: options.retry || "safe-read",
    signal: options.signal,
    cancellationToken: options.cancellationToken,
  });
  if (!scanCollection.complete) {
    return result(
      scanCollection.failures[0]?.error || incompleteScanHistoryError(),
      [],
      "Unknown",
      fallbackCount,
      false
    );
  }
  const scanList = scanCollection.items;
  if (scanList.length === 0) {
    return result(
      "No vulnerability scan details were returned for this package.",
      [],
      "Unknown",
      fallbackCount
    );
  }

  const targetScan = selectLatestScan(scanList);
  if (!targetScan) {
    return result(invalidScanHistoryError(), [], "Unknown", fallbackCount, false);
  }
  const scanIndicator = getPackageVulnerabilityState(targetScan);
  const declaredCount = scanIndicator.unknown ? null : scanIndicator.count;
  const reportedMaxSeverity = normalizeVulnerabilitySeverity(boundedString(
    unwrapValue(targetScan.max_severity),
    MAX_VULNERABILITY_SEVERITY_LENGTH
  ));
  const numVulns = declaredCount !== null
    ? declaredCount
    : (scanIndicator.detected || scanIndicator.unknown ? -1 : fallbackCount);
  const scanId = unwrapValue(targetScan.identifier);

  if (!scanId) {
    return result("The vulnerability scan did not include an identifier.", [], reportedMaxSeverity, numVulns);
  }

  if (
    scanIndicator.unknown === false
    && scanIndicator.detected === false
    && scanIndicator.count === 0
  ) {
    return result(null, [], "None", 0);
  }

  let scanDetailEndpoint;
  try {
    scanDetailEndpoint = apiEndpoint(["vulnerabilities", workspace, repo, packageIdentifier, scanId]);
  } catch {
    return result(
      new Error("The vulnerability scan identifier was invalid."),
      [],
      reportedMaxSeverity,
      numVulns
    );
  }

  const scanDetailResult = await api.get(
    scanDetailEndpoint,
    {
      responseType: "object",
      validate: isRecognizedVulnerabilityPayload,
      retry: options.retry || "safe-read",
      signal: options.signal,
      cancellationToken: options.cancellationToken,
    }
  );
  if (!scanDetailResult.ok) {
    return result(scanDetailResult.error, [], reportedMaxSeverity, numVulns);
  }
  const scanDetail = scanDetailResult.data;

  const extractedResults = extractVulnerabilityResults(scanDetail);
  if (!isVulnerabilityRecordArray(extractedResults)) {
    return result(invalidVulnerabilityDetailsError(), [], reportedMaxSeverity, numVulns, false);
  }
  const results = extractedResults.map(normalizeVulnerabilityRecord);
  if (results.length === 0 && (numVulns > 0 || scanReportsVulnerabilities(targetScan))) {
    return result(
      "The scan reports vulnerabilities, but no vulnerability detail records were returned.",
      [],
      reportedMaxSeverity,
      numVulns
    );
  }

  const expectedDetailCount = declaredCount !== null
    ? declaredCount
    : fallbackCount > 0 ? fallbackCount : null;
  if (expectedDetailCount !== null && results.length !== expectedDetailCount) {
    return result(
      invalidVulnerabilityDetailsError(),
      results,
      reportedMaxSeverity,
      numVulns,
      false
    );
  }

  return result(
    null,
    results,
    deriveMaximumVulnerabilitySeverity(results),
    results.length,
    true
  );
}

function scanIdentity(scan) {
  const identifier = unwrapValue(scan && scan.identifier);
  try {
    const identity = exactIdentityPart(identifier, "vulnerability scan");
    encodeApiPathSegment(identity);
    return identity;
  } catch {
    return null;
  }
}

function selectLatestScan(scans) {
  if (!Array.isArray(scans) || scans.length === 0) return null;
  if (scans.length === 1) return scans[0];

  const timestamps = scans.map(scanTimestamp);
  if (timestamps.every(Number.isFinite)) {
    const latestTimestamp = Math.max(...timestamps);
    const latest = scans.filter((_scan, index) => timestamps[index] === latestTimestamp);
    if (latest.length === 1) return latest[0];
    return selectBySafeScanId(latest);
  }
  return selectBySafeScanId(scans);
}

function selectBySafeScanId(scans) {
  const scanIds = scans.map(scan => scan && scan.scan_id);
  if (!scanIds.every(value => Number.isSafeInteger(value) && value >= 0)) return null;
  const maxScanId = Math.max(...scanIds);
  const latest = scans.filter((_scan, index) => scanIds[index] === maxScanId);
  return latest.length === 1 ? latest[0] : null;
}

function scanTimestamp(scan) {
  const value = scan && scan.created_at;
  if (typeof value !== "string" || value.length === 0 || value.length > 128) return NaN;
  return Date.parse(value);
}

function incompleteScanHistoryError() {
  return Object.freeze({
    kind: "pagination_incomplete",
    status: null,
    retryable: true,
    message: "Vulnerability scan history could not be loaded completely.",
    requestId: null,
    retryAfterMs: null,
    outcomeUnknown: false,
    diagnostic: Object.freeze({}),
  });
}

function invalidScanHistoryError() {
  return Object.freeze({
    kind: "invalid_response",
    status: null,
    retryable: false,
    message: "Vulnerability scan history did not provide an unambiguous latest scan.",
    requestId: null,
    retryAfterMs: null,
    outcomeUnknown: false,
    diagnostic: Object.freeze({}),
  });
}

function invalidVulnerabilityDetailsError() {
  return Object.freeze({
    kind: "invalid_response",
    status: null,
    retryable: false,
    message: "Vulnerability details did not match the authoritative scan summary.",
    requestId: null,
    retryAfterMs: null,
    outcomeUnknown: false,
    diagnostic: Object.freeze({}),
  });
}

function boundedString(value, maxLength) {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength
    ? value
    : null;
}

function isRecordArray(value) {
  return Array.isArray(value) && value.every(item => (
    Boolean(item) && typeof item === "object" && !Array.isArray(item)
  ));
}

function hasUsableScanIdentifier(value) {
  return Boolean(scanIdentity(value));
}

function isScanRecordArray(value) {
  return isRecordArray(value)
    && value.length <= VULNERABILITY_SCAN_PAGE_SIZE
    && value.every(hasUsableScanIdentifier);
}

function isVulnerabilityRecordArray(value) {
  if (
    !isRecordArray(value)
    || value.length > MAX_VULNERABILITY_DETAILS
    || !value.every(isVulnerabilityRecord)
  ) return false;
  const identities = value.map(vulnerabilityIdentity);
  return identities.every(Boolean) && new Set(identities).size === identities.length;
}

function vulnerabilityIdentifiers(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  return ["vulnerability_id", "identifier", "id", "name"]
    .filter(key => Object.prototype.hasOwnProperty.call(value, key))
    .map(key => value[key])
    .filter(candidate => candidate !== null && candidate !== undefined && candidate !== "")
    .map(candidate => typeof candidate === "string" ? candidate.trim() : null);
}

function vulnerabilityIdentifier(value) {
  const identifiers = vulnerabilityIdentifiers(value);
  if (
    identifiers.length === 0
    || identifiers.some(identifier => (
      !identifier
      || identifier.length > MAX_VULNERABILITY_IDENTIFIER_LENGTH
    ))
  ) return null;
  const canonical = new Set(identifiers.map(identifier => identifier.toLocaleLowerCase("en-US")));
  return canonical.size === 1 ? identifiers[0] : null;
}

function vulnerabilityIdentity(value) {
  const identifier = vulnerabilityIdentifier(value);
  return identifier ? identifier.toLocaleLowerCase("en-US") : null;
}

function isVulnerabilityRecord(value) {
  return Boolean(vulnerabilityIdentifier(value))
    && (
      value.severity === undefined
      || value.severity === null
      || (
        typeof value.severity === "string"
        && value.severity.length <= MAX_VULNERABILITY_SEVERITY_LENGTH
      )
    );
}

function normalizeVulnerabilityRecord(value) {
  return {
    ...value,
    vulnerability_id: typeof value.vulnerability_id === "string"
      && value.vulnerability_id.trim().length > 0
      ? value.vulnerability_id
      : vulnerabilityIdentifier(value),
    severity: normalizeVulnerabilitySeverity(value.severity),
  };
}

function hasRecognizedVulnerabilityArray(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  if (Object.prototype.hasOwnProperty.call(value, "results")) {
    return Array.isArray(value.results) && isVulnerabilityRecordArray(value.results);
  }
  if (Object.prototype.hasOwnProperty.call(value, "vulnerabilities")) {
    return Array.isArray(value.vulnerabilities) && isVulnerabilityRecordArray(value.vulnerabilities);
  }
  if (Object.prototype.hasOwnProperty.call(value, "Vulnerabilities")) {
    return Array.isArray(value.Vulnerabilities) && isVulnerabilityRecordArray(value.Vulnerabilities);
  }
  return false;
}

function isRecognizedVulnerabilityPayload(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  if (Object.prototype.hasOwnProperty.call(value, "results")) {
    return Array.isArray(value.results) && isVulnerabilityRecordArray(value.results);
  }
  if (Object.prototype.hasOwnProperty.call(value, "vulnerabilities")) {
    return Array.isArray(value.vulnerabilities) && isVulnerabilityRecordArray(value.vulnerabilities);
  }
  if (Array.isArray(value.scan)) {
    return isBoundedNestedVulnerabilityPayload(value.scan);
  }
  if (value.scan && typeof value.scan === "object") {
    return hasRecognizedVulnerabilityArray(value.scan);
  }
  return Array.isArray(value.scans) && isBoundedNestedVulnerabilityPayload(value.scans);
}

function isBoundedNestedVulnerabilityPayload(scans) {
  if (!Array.isArray(scans) || scans.length > MAX_VULNERABILITY_DETAILS) return false;
  let total = 0;
  for (const scan of scans) {
    if (!hasRecognizedVulnerabilityArray(scan)) return false;
    const results = extractResultsFromScan(scan);
    total += results.length;
    if (total > MAX_VULNERABILITY_DETAILS) return false;
  }
  return true;
}

module.exports = {
  MAX_VULNERABILITY_DETAILS,
  MAX_VULNERABILITY_SCAN_PAGES,
  VULNERABILITY_SCAN_PAGE_SIZE,
  extractVulnerabilityResults,
  fetchPackageVulnerabilities,
  getPackagePolicyFlags,
  getPackageVulnerabilityCount,
  getPackageVulnerabilityState,
};

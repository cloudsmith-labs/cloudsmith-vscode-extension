// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { apiEndpoint, encodeApiPathSegment } = require("./apiEndpoint");

const VULNERABILITIES_DETECTED_STATUS = "scan detected vulnerabilities";

function unwrapValue(value) {
  let current = value;
  while (current && typeof current === "object" && "value" in current) {
    current = current.value;
  }
  return current;
}

function normalizeCount(value) {
  const unwrapped = unwrapValue(value);
  if (unwrapped === null || unwrapped === undefined || unwrapped === "") {
    return null;
  }

  const count = Number(unwrapped);
  return Number.isInteger(count) && count >= 0 ? count : null;
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
 * Positive values are known counts, zero means clean/unknown, and -1 means
 * the package status confirms vulnerabilities but the list response omitted a count.
 */
function getPackageVulnerabilityCount(pkg) {
  const explicitCount = normalizeCount(pkg && pkg.num_vulnerabilities);
  if (explicitCount !== null) {
    return explicitCount;
  }

  const explicitPresence = normalizeBoolean(pkg && pkg.has_vulnerabilities);
  if (explicitPresence !== null) {
    return explicitPresence ? -1 : 0;
  }

  const scanStatus = String(unwrapValue(pkg && pkg.security_scan_status) || "")
    .trim()
    .toLowerCase();
  return scanStatus === VULNERABILITIES_DETECTED_STATUS ? -1 : 0;
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
    return payload.scan.flatMap(extractResultsFromScan);
  }
  const documentedResults = extractResultsFromScan(payload.scan);
  if (documentedResults.length > 0) {
    return documentedResults;
  }

  if (Array.isArray(payload.scans)) {
    return payload.scans.flatMap(extractResultsFromScan);
  }

  return [];
}

function scanReportsVulnerabilities(scan) {
  const presence = normalizeBoolean(scan && scan.has_vulnerabilities);
  if (presence !== null) {
    return presence;
  }
  const count = normalizeCount(scan && scan.num_vulnerabilities);
  return count !== null ? count > 0 : false;
}

function result(error, results = [], maxSeverity = "Unknown", numVulns = 0) {
  return { results, maxSeverity, numVulns, error };
}

/**
 * Fetch the latest package scan and its vulnerability records from the v1 API.
 * API failures remain distinct from a successful zero-vulnerability response.
 */
async function fetchPackageVulnerabilities(api, workspace, repo, packageIdentifier, expectedCount = 0, options = {}) {
  const fallbackCount = expectedCount > 0 ? expectedCount : 0;
  let scanListEndpoint;
  try {
    scanListEndpoint = apiEndpoint(["vulnerabilities", workspace, repo, packageIdentifier]);
  } catch (error) {
    return result(error, [], "Unknown", fallbackCount);
  }

  const scanListResult = await api.get(scanListEndpoint, {
    responseType: "array",
    validate: isScanRecordArray,
    retry: options.retry || "safe-read",
    signal: options.signal,
    cancellationToken: options.cancellationToken,
  });
  if (!scanListResult.ok) {
    return result(scanListResult.error, [], "Unknown", fallbackCount);
  }
  const scanList = scanListResult.data;
  if (scanList.length === 0) {
    if (fallbackCount > 0 || expectedCount < 0) {
      return result("No vulnerability scan details were returned for this package.", [], "Unknown", fallbackCount);
    }
    return result(null);
  }

  const targetScan = scanList.find(scanReportsVulnerabilities) || scanList[0];
  const declaredCount = normalizeCount(targetScan.num_vulnerabilities);
  const maxSeverity = targetScan.max_severity || "Unknown";
  const numVulns = declaredCount !== null
    ? declaredCount
    : (scanReportsVulnerabilities(targetScan) ? -1 : fallbackCount);
  const scanId = unwrapValue(targetScan.identifier);

  if (!scanId) {
    return result("The vulnerability scan did not include an identifier.", [], maxSeverity, numVulns);
  }

  if (normalizeBoolean(targetScan.has_vulnerabilities) === false && numVulns === 0) {
    return result(null, [], maxSeverity, 0);
  }

  let scanDetailEndpoint;
  try {
    scanDetailEndpoint = apiEndpoint(["vulnerabilities", workspace, repo, packageIdentifier, scanId]);
  } catch {
    return result(
      new Error("The vulnerability scan identifier was invalid."),
      [],
      maxSeverity,
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
    return result(scanDetailResult.error, [], maxSeverity, numVulns);
  }
  const scanDetail = scanDetailResult.data;

  const results = extractVulnerabilityResults(scanDetail).map(normalizeVulnerabilityRecord);
  if (results.length === 0 && (numVulns > 0 || scanReportsVulnerabilities(targetScan))) {
    return result(
      "The scan reports vulnerabilities, but no vulnerability detail records were returned.",
      [],
      maxSeverity,
      numVulns
    );
  }

  return result(null, results, maxSeverity, results.length || numVulns);
}

function isRecordArray(value) {
  return Array.isArray(value) && value.every(item => (
    Boolean(item) && typeof item === "object" && !Array.isArray(item)
  ));
}

function hasUsableScanIdentifier(value) {
  const identifier = unwrapValue(value && value.identifier);
  if (typeof identifier !== "string" || identifier.length === 0) {
    return false;
  }
  try {
    encodeApiPathSegment(identifier);
    return true;
  } catch {
    return false;
  }
}

function isScanRecordArray(value) {
  return isRecordArray(value) && value.every(hasUsableScanIdentifier);
}

function isVulnerabilityRecordArray(value) {
  return isRecordArray(value) && value.every(isVulnerabilityRecord);
}

function vulnerabilityIdentifier(value) {
  const candidate = value && (
    value.vulnerability_id
    || value.identifier
    || value.id
    || value.name
  );
  return typeof candidate === "string" && candidate.trim().length > 0
    ? candidate.trim()
    : null;
}

function isVulnerabilityRecord(value) {
  return Boolean(vulnerabilityIdentifier(value))
    && (value.severity === undefined || value.severity === null || typeof value.severity === "string");
}

function normalizeVulnerabilityRecord(value) {
  return typeof value.vulnerability_id === "string" && value.vulnerability_id.trim().length > 0
    ? value
    : { ...value, vulnerability_id: vulnerabilityIdentifier(value) };
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
    return value.scan.every(hasRecognizedVulnerabilityArray);
  }
  if (value.scan && typeof value.scan === "object") {
    return hasRecognizedVulnerabilityArray(value.scan);
  }
  return Array.isArray(value.scans) && value.scans.every(scan => (
    hasRecognizedVulnerabilityArray(scan)
  ));
}

module.exports = {
  extractVulnerabilityResults,
  fetchPackageVulnerabilities,
  getPackageVulnerabilityCount,
};

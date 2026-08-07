// Copyright 2026 Cloudsmith Ltd. All rights reserved.

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
async function fetchPackageVulnerabilities(api, workspace, repo, packageIdentifier, expectedCount = 0) {
  const fallbackCount = expectedCount > 0 ? expectedCount : 0;
  const path = [workspace, repo, packageIdentifier]
    .map(value => encodeURIComponent(String(value || "").trim()))
    .join("/");

  const scanList = await api.get(`vulnerabilities/${path}/`);
  if (typeof scanList === "string") {
    return result(scanList, [], "Unknown", fallbackCount);
  }
  if (!Array.isArray(scanList)) {
    return result("The Cloudsmith API returned an invalid vulnerability scan list.", [], "Unknown", fallbackCount);
  }
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

  const scanDetail = await api.get(
    `vulnerabilities/${path}/${encodeURIComponent(String(scanId))}/`
  );
  if (typeof scanDetail === "string") {
    return result(scanDetail, [], maxSeverity, numVulns);
  }
  if (!scanDetail || typeof scanDetail !== "object") {
    return result("The Cloudsmith API returned invalid vulnerability scan details.", [], maxSeverity, numVulns);
  }

  const results = extractVulnerabilityResults(scanDetail);
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

module.exports = {
  extractVulnerabilityResults,
  fetchPackageVulnerabilities,
  getPackageVulnerabilityCount,
};

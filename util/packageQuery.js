// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const MAX_IDENTITY_VALUE_LENGTH = 4096;

function normalizeIdentityValue(value) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return String(value);
  }
  return typeof value === "string" ? value : null;
}

function escapeExactQueryValue(value) {
  const normalized = normalizeIdentityValue(value);
  if (
    normalized === null
    || normalized.length === 0
    || normalized.length > MAX_IDENTITY_VALUE_LENGTH
    || /[\u0000-\u001f\u007f]/.test(normalized)
  ) {
    throw new Error("Package identity contains an invalid query value.");
  }

  return normalized.replace(/[\\+\-!(){}\[\]^"~*?:/|&]/g, "\\$&");
}

function buildExactPackageQuery(name, version, format = null) {
  const clauses = [
    `name:"${escapeExactQueryValue(name)}"`,
    `version:"${escapeExactQueryValue(version)}"`,
  ];
  if (format !== null && format !== undefined && format !== "") {
    clauses.push(`format:"${escapeExactQueryValue(format)}"`);
  }
  return clauses.join(" AND ");
}

function packageMatchesExactIdentity(pkg, expected) {
  if (!pkg || typeof pkg !== "object" || Array.isArray(pkg) || !expected) {
    return false;
  }
  const expectedName = normalizeIdentityValue(expected.name);
  const expectedVersion = normalizeIdentityValue(expected.version);
  const expectedFormat = normalizeIdentityValue(expected.format);
  if (
    normalizeIdentityValue(pkg.name) !== expectedName
    || normalizeIdentityValue(pkg.version) !== expectedVersion
  ) {
    return false;
  }
  return expectedFormat === null || expectedFormat === ""
    ? true
    : normalizeIdentityValue(pkg.format) === expectedFormat;
}

module.exports = {
  buildExactPackageQuery,
  packageMatchesExactIdentity,
};

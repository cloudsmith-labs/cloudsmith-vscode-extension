// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const MAX_SCOPE_LENGTH = 256;
const MAX_PACKAGE_IDENTIFIER_LENGTH = 512;
const MAX_NAME_LENGTH = 2048;
const MAX_VERSION_LENGTH = 2048;
const MAX_FORMAT_LENGTH = 100;
const MAX_METADATA_LENGTH = 4096;
const MAX_URL_LENGTH = 8192;
const MAX_TAGS_PER_FIELD = 100;
const MAX_TAG_LENGTH = 500;
const MAX_COORDINATE_QUALIFIER_VALUE_LENGTH = 4096;
const MAX_COORDINATE_QUALIFIER_ARRAY_LENGTH = 64;

const PACKAGE_COORDINATE_QUALIFIER_KEYS = Object.freeze([
  "alias",
  "classifier",
  "configurations",
  "digest",
  "environment",
  "platform",
  "pullPolicy",
  "repository",
  "scope",
  "section",
  "service",
  "stage",
  "tag",
  "targetFramework",
  "type",
]);
const PACKAGE_COORDINATE_QUALIFIER_KEY_SET = new Set(PACKAGE_COORDINATE_QUALIFIER_KEYS);

const CONTROL_OR_BIDI_PATTERN = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/;
const UNSAFE_PATH_PATTERN = /[\\/?#]/;
const EXACT_PACKAGES = new WeakSet();
const PACKAGE_COORDINATES = new WeakSet();
const PACKAGE_DOMAIN_ERRORS = new WeakSet();
const SEMANTIC_FIELDS = Object.freeze([
  "kind",
  "identityState",
  "workspace",
  "repository",
  "packageIdentifier",
  "name",
  "version",
  "format",
  "qualifiers",
  "slug",
  "status",
  "statusReason",
  "copyable",
  "downloads",
  "uploadedAt",
  "checksumSha256",
  "versionDigest",
  "cdnUrl",
  "filename",
  "tags",
  "policy",
  "vulnerability",
  "license",
  "info",
  "violated",
  "denyViolated",
  "licenseViolated",
  "vulnerabilityViolated",
  "evidence",
  "detected",
  "count",
  "maxSeverity",
  "scanStatus",
  "spdx",
  "declared",
  "raw",
  "url",
]);

class PackageDomainError extends TypeError {
  constructor(code, field, message) {
    super(message);
    this.name = "PackageDomainError";
    this.code = code;
    this.field = field;
    PACKAGE_DOMAIN_ERRORS.add(this);
  }

  static isTrusted(value) {
    return PACKAGE_DOMAIN_ERRORS.has(value);
  }
}

function createExactPackage(input) {
  if (isExactPackage(input)) return input;
  const source = requireRecord(input, "package");
  const value = {
    kind: "package",
    identityState: "exact",
    workspace: requiredPathPart(source, "workspace", MAX_SCOPE_LENGTH),
    repository: requiredPathPart(source, "repository", MAX_SCOPE_LENGTH),
    packageIdentifier: requiredPathPart(
      source,
      "packageIdentifier",
      MAX_PACKAGE_IDENTIFIER_LENGTH
    ),
    name: requiredString(source, "name", MAX_NAME_LENGTH, { trim: false }),
    version: requiredString(source, "version", MAX_VERSION_LENGTH, { trim: false }),
    format: requiredString(source, "format", MAX_FORMAT_LENGTH),
    slug: optionalString(source, "slug", MAX_PACKAGE_IDENTIFIER_LENGTH),
    status: optionalString(source, "status", MAX_METADATA_LENGTH),
    statusReason: optionalString(source, "statusReason", MAX_METADATA_LENGTH),
    copyable: optionalBoolean(source, "copyable"),
    downloads: optionalNonnegativeInteger(source, "downloads"),
    uploadedAt: optionalString(source, "uploadedAt", MAX_METADATA_LENGTH),
    checksumSha256: optionalString(source, "checksumSha256", MAX_METADATA_LENGTH),
    versionDigest: optionalString(source, "versionDigest", MAX_METADATA_LENGTH),
    cdnUrl: optionalString(source, "cdnUrl", MAX_URL_LENGTH),
    filename: optionalString(source, "filename", MAX_METADATA_LENGTH),
    tags: createTags(readOwn(source, "tags")),
    policy: createPolicy(readOwn(source, "policy")),
    vulnerability: createVulnerability(readOwn(source, "vulnerability")),
    license: createLicense(readOwn(source, "license")),
  };
  deepFreezeOwned(value);
  EXACT_PACKAGES.add(value);
  return value;
}

function createPackageCoordinate(input) {
  if (isPackageCoordinate(input)) return input;
  const source = requireRecord(input, "package coordinate");
  const repositoryValue = readOwn(source, "repository");
  const value = {
    kind: "package",
    identityState: "coordinate",
    workspace: requiredPathPart(source, "workspace", MAX_SCOPE_LENGTH),
    repository: repositoryValue == null
      ? null
      : validatePathPart(repositoryValue, "repository", MAX_SCOPE_LENGTH),
    packageIdentifier: null,
    name: requiredString(source, "name", MAX_NAME_LENGTH, { trim: false }),
    version: requiredString(source, "version", MAX_VERSION_LENGTH, { trim: false }),
    format: requiredString(source, "format", MAX_FORMAT_LENGTH),
    qualifiers: createPackageCoordinateQualifiers(readOwn(source, "qualifiers")),
  };
  Object.freeze(value);
  PACKAGE_COORDINATES.add(value);
  return value;
}

function createPackageResolutionInput(input) {
  const source = requireRecord(input, "package resolution input");
  return Object.freeze({
    workspace: requiredPathPart(source, "workspace", MAX_SCOPE_LENGTH),
    repository: requiredPathPart(source, "repository", MAX_SCOPE_LENGTH),
    name: requiredString(source, "name", MAX_NAME_LENGTH, { trim: false }),
    format: requiredString(source, "format", MAX_FORMAT_LENGTH),
  });
}

function isExactPackage(value) {
  return Boolean(value && typeof value === "object" && EXACT_PACKAGES.has(value));
}

function isPackageCoordinate(value) {
  return Boolean(value && typeof value === "object" && PACKAGE_COORDINATES.has(value));
}

function assertExactPackage(value) {
  if (!isExactPackage(value)) {
    throw domainError("not_exact_package", "package", "An exact canonical package is required.");
  }
  return value;
}

function exactPackageIdentity(value) {
  const pkg = assertExactPackage(value);
  return JSON.stringify([pkg.workspace, pkg.repository, pkg.packageIdentifier]);
}

function exactPackageRef(value) {
  const pkg = assertExactPackage(value);
  return Object.freeze({
    workspace: pkg.workspace,
    repository: pkg.repository,
    packageIdentifier: pkg.packageIdentifier,
  });
}

function assertWorkspacePackageCoordinate(value) {
  if (!isPackageCoordinate(value)) {
    throw domainError(
      "not_package_coordinate",
      "package",
      "A canonical workspace package coordinate is required."
    );
  }
  return value;
}

function assertRepositoryPackageCoordinate(value) {
  const coordinate = assertWorkspacePackageCoordinate(value);
  if (coordinate.repository === null) {
    throw domainError(
      "repository_required",
      "repository",
      "A repository package coordinate is required."
    );
  }
  return coordinate;
}

function packageCoordinateFromExact(value) {
  const pkg = assertExactPackage(value);
  return createPackageCoordinate({
    workspace: pkg.workspace,
    repository: pkg.repository,
    name: pkg.name,
    version: pkg.version,
    format: pkg.format,
  });
}

function createTags(value) {
  if (value == null) {
    return Object.freeze({ info: Object.freeze([]), version: Object.freeze([]) });
  }
  const source = requireRecord(value, "tags");
  return Object.freeze({
    info: createStringArray(readOwn(source, "info"), "tags.info"),
    version: createStringArray(readOwn(source, "version"), "tags.version"),
  });
}

function createPackageCoordinateQualifiers(value) {
  if (value == null) return Object.freeze({});
  const source = requireRecord(value, "package coordinate qualifiers");
  for (const key of Object.getOwnPropertyNames(source)) {
    if (!PACKAGE_COORDINATE_QUALIFIER_KEY_SET.has(key)) {
      throw domainError(
        "unknown_field",
        `qualifiers.${key}`,
        "The package coordinate qualifiers contain an unsupported field."
      );
    }
  }

  const qualifiers = {};
  for (const key of PACKAGE_COORDINATE_QUALIFIER_KEYS) {
    const qualifier = readOwn(source, key);
    if (qualifier === undefined || qualifier === null || qualifier === "") continue;
    if (key === "configurations") {
      Object.defineProperty(qualifiers, key, {
        value: createCoordinateQualifierArray(qualifier, `qualifiers.${key}`),
        enumerable: true,
        configurable: true,
        writable: true,
      });
      continue;
    }
    Object.defineProperty(qualifiers, key, {
      value: validateString(
        qualifier,
        `qualifiers.${key}`,
        MAX_COORDINATE_QUALIFIER_VALUE_LENGTH
      ),
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  return Object.freeze(qualifiers);
}

function createCoordinateQualifierArray(value, field) {
  if (!Array.isArray(value) || value.length > MAX_COORDINATE_QUALIFIER_ARRAY_LENGTH) {
    throw domainError("invalid_array", field, `The ${field} value is invalid.`);
  }
  assertNoSymbolProperties(value, field);
  assertNoOwnAccessors(value, field);
  if (Object.getPrototypeOf(value) !== Array.prototype) {
    throw domainError("invalid_array", field, `The ${field} value is invalid.`);
  }
  const result = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor)) {
      throw domainError("invalid_array", field, `The ${field} value is invalid.`);
    }
    result.push(validateString(
      descriptor.value,
      field,
      MAX_COORDINATE_QUALIFIER_VALUE_LENGTH
    ));
  }
  return Object.freeze(result);
}

function createStringArray(value, field) {
  if (value == null) return Object.freeze([]);
  if (!Array.isArray(value) || value.length > MAX_TAGS_PER_FIELD) {
    throw domainError("invalid_array", field, `The ${field} value is invalid.`);
  }
  assertNoSymbolProperties(value, field);
  assertNoOwnAccessors(value, field);
  if (Object.getPrototypeOf(value) !== Array.prototype) {
    throw domainError("invalid_array", field, `The ${field} value is invalid.`);
  }
  const result = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor)) {
      throw domainError("invalid_array", field, `The ${field} value is invalid.`);
    }
    result.push(validateString(descriptor.value, field, MAX_TAG_LENGTH, { trim: false }));
  }
  return Object.freeze(result);
}

function createPolicy(value) {
  if (value == null) {
    return Object.freeze({
      violated: false,
      denyViolated: false,
      licenseViolated: false,
      vulnerabilityViolated: false,
    });
  }
  const source = requireRecord(value, "policy");
  return Object.freeze({
    violated: defaultBoolean(source, "violated", false),
    denyViolated: defaultBoolean(source, "denyViolated", false),
    licenseViolated: defaultBoolean(source, "licenseViolated", false),
    vulnerabilityViolated: defaultBoolean(source, "vulnerabilityViolated", false),
  });
}

function createVulnerability(value) {
  if (value == null) {
    return Object.freeze({
      evidence: "unknown",
      detected: false,
      count: null,
      maxSeverity: null,
      scanStatus: null,
    });
  }
  const source = requireRecord(value, "vulnerability");
  const evidence = readOwn(source, "evidence") ?? "unknown";
  if (!new Set(["unknown", "clean", "detected"]).has(evidence)) {
    throw domainError(
      "invalid_vulnerability_evidence",
      "vulnerability.evidence",
      "The vulnerability evidence is invalid."
    );
  }
  let count = readOwn(source, "count");
  if (count === undefined || count === null) {
    count = evidence === "clean" ? 0 : null;
  } else if (!Number.isSafeInteger(count) || count < 0) {
    throw domainError(
      "invalid_integer",
      "vulnerability.count",
      "The vulnerability count is invalid."
    );
  }
  const detectedValue = readOwn(source, "detected");
  const detected = detectedValue === undefined
    ? evidence === "detected"
    : detectedValue;
  if (detected !== true && detected !== false) {
    throw domainError(
      "invalid_boolean",
      "vulnerability.detected",
      "The vulnerability detected value is invalid."
    );
  }
  if (
    (evidence === "unknown" && count !== null)
    || (evidence === "clean" && (detected || count !== 0))
    || (evidence === "detected" && (!detected || (count !== null && count < 1)))
  ) {
    throw domainError(
      "contradictory_vulnerability_evidence",
      "vulnerability",
      "The vulnerability evidence is contradictory."
    );
  }
  const maxSeverity = optionalString(source, "maxSeverity", MAX_METADATA_LENGTH);
  const scanStatus = optionalString(source, "scanStatus", MAX_METADATA_LENGTH);
  const normalizedMaxSeverity = maxSeverity?.trim().toLowerCase() || null;
  const positiveMaxSeverity = Boolean(
    normalizedMaxSeverity
    && normalizedMaxSeverity !== "none"
    && normalizedMaxSeverity !== "unknown"
  );
  const normalizedScanStatus = scanStatus?.trim().toLowerCase() || null;
  const scanDetected = normalizedScanStatus === "scan detected vulnerabilities";
  const scanClean = normalizedScanStatus === "scan detected no vulnerabilities";
  if (
    (evidence === "clean" && maxSeverity !== null)
    || (evidence === "detected" && normalizedMaxSeverity === "none")
    || (positiveMaxSeverity && !detected)
    || (evidence === "clean" && scanDetected)
    || (evidence === "detected" && scanClean)
    || (evidence === "unknown" && (scanDetected || scanClean))
  ) {
    throw domainError(
      "contradictory_vulnerability_metadata",
      "vulnerability",
      "The vulnerability metadata is contradictory."
    );
  }
  return Object.freeze({
    evidence,
    detected,
    count,
    maxSeverity,
    scanStatus,
  });
}

function createLicense(value) {
  if (value == null) {
    return Object.freeze({ spdx: null, declared: null, raw: null, url: null });
  }
  const source = requireRecord(value, "license");
  return Object.freeze({
    spdx: optionalString(source, "spdx", MAX_METADATA_LENGTH),
    declared: optionalString(source, "declared", MAX_METADATA_LENGTH),
    raw: optionalString(source, "raw", MAX_METADATA_LENGTH),
    url: optionalString(source, "url", MAX_URL_LENGTH),
  });
}

function requireRecord(value, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw domainError("invalid_record", field, `The ${field} value is invalid.`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw domainError("invalid_record", field, `The ${field} value is invalid.`);
  }
  assertNoSymbolProperties(value, field);
  assertNoOwnAccessors(value, field);
  assertNoInheritedSemanticProperties(value, field);
  return value;
}

function readOwn(record, field) {
  assertNoInheritedProperty(record, field);
  const descriptor = Object.getOwnPropertyDescriptor(record, field);
  if (!descriptor) return undefined;
  if (!("value" in descriptor)) {
    throw domainError("accessor_property", field, `The ${field} value must be a data property.`);
  }
  return descriptor.value;
}

function assertNoSymbolProperties(value, field) {
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw domainError("symbol_property", field, `The ${field} value is invalid.`);
  }
}

function assertNoOwnAccessors(value, field) {
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if (!("value" in descriptor)) {
      throw domainError("accessor_property", field, `The ${field} value is invalid.`);
    }
  }
}

function assertNoInheritedSemanticProperties(value, field) {
  for (const semanticField of SEMANTIC_FIELDS) {
    assertNoInheritedProperty(value, semanticField, field);
  }
}

function assertNoInheritedProperty(value, property, field = property) {
  let prototype = Object.getPrototypeOf(value);
  while (prototype) {
    if (Object.getOwnPropertyDescriptor(prototype, property)) {
      throw domainError(
        "inherited_property",
        field,
        `The ${field} value contains an inherited semantic property.`
      );
    }
    prototype = Object.getPrototypeOf(prototype);
  }
}

function requiredString(record, field, maxLength, options = {}) {
  const value = readOwn(record, field);
  if (value === undefined || value === null) {
    throw domainError("missing_field", field, `The ${field} value is required.`);
  }
  return validateString(value, field, maxLength, options);
}

function optionalString(record, field, maxLength) {
  const value = readOwn(record, field);
  if (value === undefined || value === null || value === "") return null;
  return validateString(value, field, maxLength, { trim: false });
}

function validateString(value, field, maxLength, options = {}) {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > maxLength
    || CONTROL_OR_BIDI_PATTERN.test(value)
    || (options.trim !== false && value !== value.trim())
  ) {
    throw domainError("invalid_string", field, `The ${field} value is invalid.`);
  }
  return value;
}

function requiredPathPart(record, field, maxLength) {
  return validatePathPart(readOwn(record, field), field, maxLength);
}

function validatePathPart(value, field, maxLength) {
  const validated = validateString(value, field, maxLength);
  let decoded = validated;
  const maximumDecodeDepth = Math.ceil(validated.length / 2) + 1;
  for (let depth = 0; depth < maximumDecodeDepth; depth += 1) {
    let next;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      throw domainError("invalid_path_part", field, `The ${field} value is invalid.`);
    }
    if (next === decoded) break;
    decoded = next;
  }
  if (
    decoded === "."
    || decoded === ".."
    || CONTROL_OR_BIDI_PATTERN.test(decoded)
    || UNSAFE_PATH_PATTERN.test(decoded)
  ) {
    throw domainError("invalid_path_part", field, `The ${field} value is unsafe.`);
  }
  return validated;
}

function optionalBoolean(record, field) {
  const value = readOwn(record, field);
  if (value === undefined || value === null) return null;
  if (value !== true && value !== false) {
    throw domainError("invalid_boolean", field, `The ${field} value is invalid.`);
  }
  return value;
}

function defaultBoolean(record, field, fallback) {
  const value = readOwn(record, field);
  if (value === undefined) return fallback;
  if (value !== true && value !== false) {
    throw domainError("invalid_boolean", field, `The ${field} value is invalid.`);
  }
  return value;
}

function optionalNonnegativeInteger(record, field) {
  const value = readOwn(record, field);
  if (value === undefined || value === null) return null;
  if (!Number.isSafeInteger(value) || value < 0) {
    throw domainError("invalid_integer", field, `The ${field} value is invalid.`);
  }
  return value;
}

function deepFreezeOwned(value) {
  for (const nested of Object.values(value)) {
    if (nested && typeof nested === "object" && !Object.isFrozen(nested)) {
      deepFreezeOwned(nested);
    }
  }
  Object.freeze(value);
  return value;
}

function domainError(code, field, message) {
  return new PackageDomainError(code, field, message);
}

module.exports = {
  PackageDomainError,
  assertRepositoryPackageCoordinate,
  assertExactPackage,
  assertWorkspacePackageCoordinate,
  createExactPackage,
  createPackageCoordinate,
  createPackageResolutionInput,
  exactPackageIdentity,
  exactPackageRef,
  isExactPackage,
  isPackageCoordinate,
  packageCoordinateFromExact,
};

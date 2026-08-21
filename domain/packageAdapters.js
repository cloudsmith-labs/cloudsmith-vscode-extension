// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const {
  PackageDomainError,
  assertRepositoryPackageCoordinate,
  createExactPackage,
  createPackageCoordinate,
  createPackageResolutionInput,
  isExactPackage,
  isPackageCoordinate,
  packageCoordinateFromExact,
} = require("./package");

const MAX_WRAPPER_DEPTH = 2;
const PACKAGE_ADAPTER_ERRORS = new WeakSet();
const DETECTED_STATUS = "scan detected vulnerabilities";
const CLEAN_STATUS = "scan detected no vulnerabilities";
const SEMANTIC_FIELDS = Object.freeze([
  "package",
  "workspace",
  "namespace",
  "cloudsmithWorkspace",
  "repository",
  "cloudsmithRepo",
  "repo",
  "packageIdentifier",
  "slug_perm",
  "slug_perm_raw",
  "slug",
  "name",
  "version",
  "declaredVersion",
  "resolvedVersion",
  "format",
  "qualifiers",
  "status",
  "status_str",
  "status_str_raw",
  "statusReason",
  "status_reason",
  "copyable",
  "is_copyable",
  "downloads",
  "uploadedAt",
  "uploaded_at",
  "checksumSha256",
  "checksum_sha256",
  "versionDigest",
  "version_digest",
  "cdnUrl",
  "cdn_url",
  "filename",
  "tags",
  "tags_raw",
  "policy",
  "vulnerability",
  "license",
  "cloudsmithMatch",
  "cloudsmithPackage",
  "value",
  "id",
  "label",
  "_detailId",
  "_detailValue",
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

class PackageAdapterError extends TypeError {
  constructor(code, field, message, unexpected = false) {
    super(message);
    this.name = "PackageAdapterError";
    this.code = code;
    this.field = field;
    this.unexpected = unexpected === true;
    PACKAGE_ADAPTER_ERRORS.add(this);
  }

  static isTrusted(value) {
    return PACKAGE_ADAPTER_ERRORS.has(value);
  }
}

function fromRepositoryNode(node) {
  requireRecord(node, "repository node");
  try {
    const workspace = boundaryPathPart(consensusString(
      node,
      ["workspace"],
      "workspace",
      { required: true, unwrapDepth: MAX_WRAPPER_DEPTH }
    ), "workspace", 256);
    const repository = boundaryPathPart(consensusString(
      node,
      ["slug"],
      "repository",
      { required: true, unwrapDepth: MAX_WRAPPER_DEPTH }
    ), "repository", 256);
    const name = boundaryString(consensusString(
      node,
      ["name"],
      "name",
      { required: true, unwrapDepth: MAX_WRAPPER_DEPTH }
    ), "name", 2048, { trim: false });
    return Object.freeze({ workspace, repository, name });
  } catch (error) {
    throw asAdapterError(error, "invalid_repository_node", "repository node");
  }
}

function fromPackageGroupNode(node) {
  requireRecord(node, "package group node");
  try {
    const workspace = boundaryPathPart(consensusString(
      node,
      ["workspace"],
      "workspace",
      { required: true, unwrapDepth: MAX_WRAPPER_DEPTH }
    ), "workspace", 256);
    const repository = boundaryPathPart(consensusString(
      node,
      ["repo"],
      "repository",
      { required: true, unwrapDepth: MAX_WRAPPER_DEPTH }
    ), "repository", 256);
    const name = boundaryString(consensusString(
      node,
      ["name"],
      "name",
      { required: true, unwrapDepth: MAX_WRAPPER_DEPTH }
    ), "name", 2048, { trim: false });
    const rawFormat = consensusString(node, ["format"], "format", {
      required: false,
      unwrapDepth: MAX_WRAPPER_DEPTH,
    });
    const format = rawFormat === null
      ? null
      : boundaryString(rawFormat, "format", 100);
    return Object.freeze({ workspace, repository, name, format });
  } catch (error) {
    throw asAdapterError(error, "invalid_package_group_node", "package group node");
  }
}

function fromPackageDetailNode(value) {
  try {
    if (typeof value === "string") {
      return createPackageDetail("Detail", value);
    }
    requireRecord(value, "package detail node");
    const candidates = [];
    const hasCommandDetail = hasOwnSuppliedValue(value, "_detailId")
      || hasOwnSuppliedValue(value, "_detailValue");
    if (hasCommandDetail) {
      candidates.push(createPackageDetail(
        consensusString(value, ["_detailId"], "detail id", {
          required: true,
          unwrapDepth: 0,
        }),
        consensusString(value, ["_detailValue"], "detail value", {
          required: true,
          unwrapDepth: 0,
        })
      ));
    }
    const directId = hasOwnSuppliedValue(value, "id");
    const directValue = hasOwnSuppliedValue(value, "value");
    if (directId || directValue) {
      candidates.push(createPackageDetail(
        consensusString(value, ["id"], "detail id", {
          required: true,
          unwrapDepth: 0,
        }),
        consensusString(value, ["value"], "detail value", {
          required: true,
          unwrapDepth: MAX_WRAPPER_DEPTH,
        })
      ));
    }
    const label = readOwn(value, "label");
    if (label !== undefined && label !== null) {
      if (typeof label === "string") {
        candidates.push(createPackageDetail("Detail", label));
      } else {
        requireRecord(label, "package detail label", { plain: true });
        candidates.push(createPackageDetail(
          consensusString(label, ["id"], "detail id", {
            required: true,
            unwrapDepth: 0,
          }),
          consensusString(label, ["value"], "detail value", {
            required: true,
            unwrapDepth: MAX_WRAPPER_DEPTH,
          })
        ));
      }
    }
    if (candidates.length === 0) {
      throw adapterError(
        "missing_package_detail",
        "package detail",
        "The package detail value is required."
      );
    }
    const serialized = candidates.map(candidate => JSON.stringify(candidate));
    if (serialized.some(candidate => candidate !== serialized[0])) {
      throw adapterError(
        "conflicting_aliases",
        "package detail",
        "The package detail values conflict."
      );
    }
    return candidates[0];
  } catch (error) {
    throw asAdapterError(error, "invalid_package_detail_node", "package detail node");
  }
}

function fromPackageResolutionSelection(value, options = {}) {
  try {
    requireRecord(options, "package resolution adapter options", { plain: true });
    if (isExactPackage(value) || isPackageCoordinate(value)) {
      return createPackageResolutionInput(value);
    }
    if (isDependencyHealthResolutionSelection(value)) {
      return createPackageResolutionInput(fromDependencyHealthNode(value, options));
    }
    const exactPackage = fromExactPackageSelectionIfPresent(value);
    if (exactPackage) return createPackageResolutionInput(exactPackage);
    requireRecord(value, "package resolution selection");
    consensusString(value, [
      "packageIdentifier",
      "slug_perm",
      "slug_perm_raw",
    ], "packageIdentifier", { required: false, unwrapDepth: MAX_WRAPPER_DEPTH });
    repositorySelectionVersion(value);
    return createPackageResolutionInput({
      workspace: consensusString(value, [
        "workspace",
        "namespace",
        "cloudsmithWorkspace",
      ], "workspace", { required: true, unwrapDepth: MAX_WRAPPER_DEPTH }),
      repository: consensusString(value, [
        "repository",
        "cloudsmithRepo",
      ], "repository", { required: true, unwrapDepth: MAX_WRAPPER_DEPTH }),
      name: consensusString(value, ["name"], "name", {
        required: true,
        unwrapDepth: MAX_WRAPPER_DEPTH,
      }),
      format: consensusString(value, ["format"], "format", {
        required: true,
        unwrapDepth: MAX_WRAPPER_DEPTH,
      }),
    });
  } catch (error) {
    throw asAdapterError(
      error,
      "invalid_package_resolution_selection",
      "package resolution selection"
    );
  }
}

function fromRepositoryPackageSelection(value, options = {}) {
  requireRecord(options, "repository package adapter options", { plain: true });
  try {
    if (isPackageCoordinate(value)) {
      return assertRepositoryPackageCoordinate(value);
    }
    const exactPackage = fromExactPackageSelectionIfPresent(value);
    if (exactPackage) return packageCoordinateFromExact(exactPackage);
    requireRecord(value, "repository package selection");
    const resolution = fromPackageResolutionSelection(value);
    const defaultVersion = readOwn(options, "defaultVersion");
    const version = repositorySelectionVersion(value) || defaultVersion;
    return assertRepositoryPackageCoordinate(createPackageCoordinate({
      ...resolution,
      version,
    }));
  } catch (error) {
    throw asAdapterError(
      error,
      "invalid_repository_package_selection",
      "repository package selection"
    );
  }
}

function fromExactPackageSelectionIfPresent(value) {
  try {
    if (isExactPackage(value)) return value;
    if (isPackageCoordinate(value)) return null;
    requireRecord(value, "package operation selection");
    if (isCanonicalDependencySelection(value)) {
      const dependencyPackage = fromDependencyHealthNode(value);
      return isExactPackage(dependencyPackage) ? dependencyPackage : null;
    }
    const canonical = readCanonicalPackage(value);
    if (canonical) return isExactPackage(canonical) ? canonical : null;
    const packageIdentifier = consensusString(value, [
      "packageIdentifier",
      "slug_perm",
      "slug_perm_raw",
    ], "packageIdentifier", { required: false, unwrapDepth: MAX_WRAPPER_DEPTH });
    if (packageIdentifier === null) return null;
    return requireExact(fromPackageSelection(value), "package operation selection");
  } catch (error) {
    throw asAdapterError(
      error,
      "invalid_exact_package_operation_selection",
      "package operation selection"
    );
  }
}

function fromApiPackageRecord(record, options = {}) {
  try {
    if (isExactPackage(record)) {
      validateExpectedScope(record, options);
      return record;
    }
    requireRecord(record, "API package", { plain: true });
    const result = adaptFlatExactRecord(record, {
      allowNumericVersion: true,
      allowWrappers: false,
      apiStatusTextOnly: true,
      downloadsDefault: null,
      source: "API package",
    });
    validateExpectedScope(result, options);
    return result;
  } catch (error) {
    throw asAdapterError(error, "invalid_api_package", "API package");
  }
}

function fromPackageNode(node) {
  return fromPresentationNode(node, "package node");
}

function fromSearchResultNode(node) {
  return fromPresentationNode(node, "search result node");
}

function fromDependencyHealthNode(node, options = {}) {
  try {
    requireRecord(node, "dependency health node");
    requireRecord(options, "dependency package adapter options", { plain: true });
    if (isExactPackage(node) || isPackageCoordinate(node)) {
      for (const field of ["workspace", "repository"]) {
        const expected = consensusString(options, [field], field, {
          required: false,
          unwrapDepth: 0,
        });
        if (expected !== null && expected !== node[field]) {
          throw adapterError(
            "unexpected_scope",
            field,
            `The dependency package ${field} is outside the requested scope.`
          );
        }
      }
      return node;
    }

    const canonical = readCanonicalPackage(node, { validateProjection: false });
    if (canonical) return canonical;

    const matches = ["cloudsmithMatch", "cloudsmithPackage"]
      .map(field => readOwn(node, field))
      .filter(value => value !== undefined && value !== null);
    if (matches.length > 0) {
      const packages = matches.map(match => adaptDependencyMatch(match));
      const serialized = packages.map(pkg => JSON.stringify(pkg));
      if (serialized.some(value => value !== serialized[0])) {
        throw adapterError(
          "conflicting_aliases",
          "cloudsmithMatch",
          "The dependency package matches conflict."
        );
      }
      validateIdentityConsensus(node, packages[0], true);
      return packages[0];
    }

    const nodeWorkspace = consensusString(node, [
      "workspace",
      "namespace",
      "cloudsmithWorkspace",
    ], "workspace", { required: false, unwrapDepth: MAX_WRAPPER_DEPTH });
    const optionWorkspace = consensusString(options, ["workspace"], "workspace", {
      required: false,
      unwrapDepth: 0,
    });
    const workspace = consensusPrimitive(
      [nodeWorkspace, optionWorkspace].filter(value => value !== null),
      "workspace"
    );
    if (workspace === null) {
      throw adapterError("missing_field", "workspace", "The workspace value is required.");
    }
    const nodeRepository = consensusString(node, [
      "repository",
      "cloudsmithRepo",
    ], "repository", { required: false, unwrapDepth: MAX_WRAPPER_DEPTH });
    const optionRepository = consensusString(options, ["repository"], "repository", {
      required: false,
      unwrapDepth: 0,
    });
    const repository = consensusPrimitive(
      [nodeRepository, optionRepository].filter(value => value !== null),
      "repository"
    );
    const name = consensusString(node, ["name"], "name", {
      required: true,
      unwrapDepth: MAX_WRAPPER_DEPTH,
    });
    const version = dependencyCoordinateVersion(node);
    const format = consensusString(node, ["format"], "format", {
      required: true,
      unwrapDepth: MAX_WRAPPER_DEPTH,
    });
    const qualifiers = readOwn(node, "qualifiers");
    return createPackageCoordinate({
      workspace,
      repository,
      name,
      version,
      format,
      qualifiers,
    });
  } catch (error) {
    throw asAdapterError(error, "invalid_dependency_package", "dependency package");
  }
}

function fromRecentPackageRecord(record) {
  if (isExactPackage(record)) return record;
  requireRecord(record, "recent package");
  try {
    const canonical = readCanonicalPackage(record);
    if (canonical) return requireExact(canonical, "recent package");
    const nestedValues = ["cloudsmithMatch", "cloudsmithPackage"]
      .map(field => readOwn(record, field))
      .filter(value => value !== undefined && value !== null);
    if (nestedValues.length > 0) {
      const packages = nestedValues.map(value => (
        isExactPackage(value) ? value : fromApiPackageRecord(value)
      ));
      const serialized = packages.map(pkg => JSON.stringify(pkg));
      if (serialized.some(value => value !== serialized[0])) {
        throw adapterError(
          "conflicting_aliases",
          "cloudsmithMatch",
          "The recent package matches conflict."
        );
      }
      const pkg = packages[0];
      validateIdentityConsensus(record, pkg, true);
      validateCanonicalProjection(record, pkg);
      return pkg;
    }
    return adaptFlatExactRecord(record, {
      allowNumericVersion: true,
      allowWrappers: true,
      declaredVersionFallback: true,
      downloadsDefault: null,
      source: "recent package",
    });
  } catch (error) {
    throw asAdapterError(error, "invalid_recent_package", "recent package");
  }
}

function fromPackageSelection(value) {
  if (isExactPackage(value)) return value;
  requireRecord(value, "package selection");
  try {
    if (isCanonicalDependencySelection(value)) {
      return requireExact(fromDependencyHealthNode(value), "package selection");
    }
    const canonical = readCanonicalPackage(value);
    if (canonical) return requireExact(canonical, "package selection");
    const candidates = [];
    const applicable = [];
    const apiSelection = isApiSelection(value);
    const hasNumericApiStatus = apiSelection
      && hasOwnDataValue(value, "status")
      && typeof readOwn(value, "status") === "number";
    if (isDependencySelection(value)) {
      applicable.push(["dependency health", () => requireExact(
        fromDependencyHealthNode(value),
        "package selection"
      )]);
    }
    if (isRecentSelection(value)) {
      applicable.push(["recent package", () => fromRecentPackageRecord(value)]);
    }
    if (apiSelection) {
      applicable.push(["API package", () => fromApiPackageRecord(value)]);
    }
    if (isFlatPresentationSelection(value) && !hasNumericApiStatus) {
      applicable.push(["package node", () => fromPackageNode(value)]);
      applicable.push(["search result node", () => fromSearchResultNode(value)]);
    }
    if (applicable.length === 0) {
      throw adapterError(
        "unsupported_package_selection",
        "package selection",
        "The package selection shape is unsupported."
      );
    }
    for (const [adapter, adapt] of applicable) {
      try {
        candidates.push({ adapter, package: adapt() });
      } catch (error) {
        throw adapterError(
          "malformed_applicable_adapter",
          "package selection",
          `The ${adapter} selection is malformed.`,
          isUnexpectedPackageAdapterError(error)
        );
      }
    }
    const serialized = candidates.map(candidate => JSON.stringify(candidate.package));
    if (serialized.some(value => value !== serialized[0])) {
      throw adapterError(
        "ambiguous_package_selection",
        "package selection",
        "The package selection shapes disagree."
      );
    }
    return candidates[0].package;
  } catch (error) {
    throw asAdapterError(error, "invalid_package_selection", "package selection");
  }
}

function fromPresentationNode(node, label) {
  if (isExactPackage(node)) return node;
  requireRecord(node, label);
  try {
    const canonical = readCanonicalPackage(node);
    if (canonical) return requireExact(canonical, label);
    return adaptFlatExactRecord(node, {
      allowNumericVersion: true,
      allowWrappers: true,
      declaredVersionFallback: true,
      downloadsDefault: null,
      source: label,
    });
  } catch (error) {
    throw asAdapterError(error, "invalid_presentation_package", label);
  }
}

function isDependencySelection(value) {
  return hasOwnDataValue(value, "cloudsmithMatch")
    || hasOwnDataValue(value, "cloudsmithPackage");
}

function isCanonicalDependencySelection(value) {
  return isDependencySelection(value) && hasOwnDataValue(value, "package");
}

function isDependencyHealthResolutionSelection(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (isCanonicalDependencySelection(value)) return true;
  return hasAnyOwnDataValue(value, [
    "declarationName",
    "declaredConstraint",
    "versionState",
    "cloudsmithStatus",
    "lookupEligibility",
    "packageSource",
    "sourceManifest",
  ]);
}

function repositorySelectionVersion(record) {
  return consensusString(
    record,
    ["version", "declaredVersion", "resolvedVersion"],
    "version",
    { required: false, unwrapDepth: MAX_WRAPPER_DEPTH, allowNumber: true }
  );
}

function isRecentSelection(value) {
  return [
    "cloudsmithWorkspace",
    "cloudsmithRepo",
    "slug_perm_raw",
    "tags_raw",
  ].some(field => hasOwnDataValue(value, field));
}

function isApiSelection(value) {
  const required = ["namespace", "repository", "slug_perm", "name", "version", "format"];
  if (!required.every(field => hasOwnDataValue(value, field))) return false;
  const slugPerm = readOwn(value, "slug_perm");
  const version = readOwn(value, "version");
  return typeof slugPerm === "string"
    && (typeof version === "string" || (typeof version === "number" && Number.isFinite(version)));
}

function isFlatPresentationSelection(value) {
  return hasAnyOwnDataValue(value, ["workspace", "namespace", "cloudsmithWorkspace"])
    && hasAnyOwnDataValue(value, ["repository", "cloudsmithRepo"])
    && hasAnyOwnDataValue(value, ["packageIdentifier", "slug_perm", "slug_perm_raw"])
    && hasOwnDataValue(value, "name")
    && hasAnyOwnDataValue(value, ["version", "declaredVersion"])
    && hasOwnDataValue(value, "format");
}

function hasAnyOwnDataValue(value, fields) {
  return fields.some(field => hasOwnDataValue(value, field));
}

function adaptDependencyMatch(match) {
  if (isExactPackage(match)) return match;
  requireRecord(match, "dependency package match", { plain: true });
  return adaptFlatExactRecord(match, {
    allowNumericVersion: true,
    allowWrappers: false,
    apiStatusTextOnly: true,
    downloadsDefault: null,
    source: "dependency package match",
  });
}

function adaptFlatExactRecord(record, options) {
  const unwrapDepth = options.allowWrappers ? MAX_WRAPPER_DEPTH : 0;
  const version = recordVersion(record, {
    allowNumber: options.allowNumericVersion,
    declaredVersionFallback: options.declaredVersionFallback,
    unwrapDepth,
  });
  return createExactPackage({
    workspace: consensusString(record, [
      "workspace",
      "namespace",
      "cloudsmithWorkspace",
    ], "workspace", { required: true, unwrapDepth }),
    repository: consensusString(record, [
      "repository",
      "cloudsmithRepo",
    ], "repository", { required: true, unwrapDepth }),
    packageIdentifier: consensusString(record, [
      "packageIdentifier",
      "slug_perm",
      "slug_perm_raw",
    ], "packageIdentifier", { required: true, unwrapDepth }),
    name: consensusString(record, ["name"], "name", { required: true, unwrapDepth }),
    version,
    format: consensusString(record, ["format"], "format", { required: true, unwrapDepth }),
    slug: consensusString(record, ["slug"], "slug", { required: false, unwrapDepth }),
    status: consensusString(
      record,
      options.apiStatusTextOnly
        ? ["status_str", "status_str_raw"]
        : ["status", "status_str", "status_str_raw"],
      "status",
      { required: false, unwrapDepth }
    ),
    statusReason: consensusString(record, [
      "statusReason",
      "status_reason",
    ], "statusReason", { required: false, unwrapDepth }),
    copyable: consensusBoolean(record, ["copyable", "is_copyable"], "copyable", {
      required: false,
      unwrapDepth,
    }),
    downloads: consensusInteger(record, ["downloads"], "downloads", {
      required: false,
      unwrapDepth,
      defaultValue: options.downloadsDefault,
    }),
    uploadedAt: consensusString(record, [
      "uploadedAt",
      "uploaded_at",
    ], "uploadedAt", { required: false, unwrapDepth }),
    checksumSha256: consensusString(record, [
      "checksumSha256",
      "checksum_sha256",
    ], "checksumSha256", { required: false, unwrapDepth }),
    versionDigest: consensusString(record, [
      "versionDigest",
      "version_digest",
    ], "versionDigest", { required: false, unwrapDepth }),
    cdnUrl: consensusString(record, ["cdnUrl", "cdn_url"], "cdnUrl", {
      required: false,
      unwrapDepth,
    }),
    filename: consensusString(record, ["filename"], "filename", {
      required: false,
      unwrapDepth,
    }),
    tags: adaptTags(record),
    policy: adaptPolicy(record),
    vulnerability: adaptVulnerability(record, { allowDetectedSentinel: options.allowWrappers }),
    license: adaptLicense(record),
  });
}

function readCanonicalPackage(record, options = {}) {
  const candidate = readOwn(record, "package");
  if (candidate === undefined || candidate === null) return null;
  if (!isExactPackage(candidate) && !isPackageCoordinate(candidate)) {
    throw adapterError(
      "unbranded_canonical_package",
      "package",
      "The canonical package value is invalid."
    );
  }
  if (isExactPackage(candidate)) {
    validateIdentityConsensus(record, candidate, false);
    if (options.validateProjection !== false) validateCanonicalProjection(record, candidate);
  }
  validateEmbeddedPackageEvidence(record, candidate);
  return candidate;
}

function validateEmbeddedPackageEvidence(record, canonical) {
  const values = ["cloudsmithMatch", "cloudsmithPackage"]
    .map(field => readOwn(record, field))
    .filter(value => value !== undefined && value !== null);
  if (values.length === 0) return;
  if (!isExactPackage(canonical)) {
    throw adapterError(
      "incompatible_package_evidence",
      "package",
      "An inexact package cannot contain exact match evidence."
    );
  }
  const serializedCanonical = JSON.stringify(canonical);
  for (const value of values) {
    const pkg = isExactPackage(value) ? value : fromApiPackageRecord(value);
    if (JSON.stringify(pkg) !== serializedCanonical) {
      throw adapterError(
        "conflicting_canonical_projection",
        "package",
        "The canonical package and embedded package evidence conflict."
      );
    }
  }
}

function validateCanonicalProjection(record, pkg) {
  // Only documented, authoritative projections participate in consensus. Fields
  // such as rendered license labels and display-defaulted downloads are derived
  // presentation values and are deliberately excluded from this boundary check.
  const stringFields = [
    ["name", ["name"]],
    ["version", ["version"]],
    ["format", ["format"]],
    ["slug", ["slug"]],
    ["status", ["status", "status_str", "status_str_raw"]],
    ["statusReason", ["statusReason", "status_reason"]],
    ["uploadedAt", ["uploadedAt", "uploaded_at"]],
    ["checksumSha256", ["checksumSha256", "checksum_sha256"]],
    ["versionDigest", ["versionDigest", "version_digest"]],
    ["cdnUrl", ["cdnUrl", "cdn_url"]],
    ["filename", ["filename"]],
  ];
  for (const [field, aliases] of stringFields) {
    const projected = consensusString(record, aliases, field, {
      required: false,
      unwrapDepth: MAX_WRAPPER_DEPTH,
      allowNumber: field === "version",
    });
    if (projected !== null && projected !== pkg[field]) {
      throw projectionConflict(field);
    }
  }
  if (hasAnyOwnDataValue(record, ["copyable", "is_copyable"])) {
    const copyable = consensusBoolean(record, ["copyable", "is_copyable"], "copyable", {
      required: true,
      unwrapDepth: MAX_WRAPPER_DEPTH,
    });
    if (copyable !== pkg.copyable) throw projectionConflict("copyable");
  }
  if (hasAnyOwnDataValue(record, ["tags_raw"])
    || (hasOwnDataValue(record, "tags") && !isPresentationWrapper(readOwn(record, "tags")))) {
    if (JSON.stringify(adaptTags(record)) !== JSON.stringify(pkg.tags)) {
      throw projectionConflict("tags");
    }
  }
  const policyFields = [
    ["violated", ["policy_violated"]],
    ["denyViolated", ["deny_policy_violated"]],
    ["licenseViolated", ["license_policy_violated"]],
    ["vulnerabilityViolated", ["vulnerability_policy_violated"]],
  ];
  if (policyFields.some(([, aliases]) => hasAnyOwnDataValue(record, aliases))) {
    const policy = adaptPolicy(record);
    for (const [field, aliases] of policyFields) {
      if (hasAnyOwnDataValue(record, aliases) && policy[field] !== pkg.policy[field]) {
        throw projectionConflict(`policy.${field}`);
      }
    }
  }
  const vulnerabilityEvidenceFields = [
    "num_vulnerabilities",
    "vulnerability_scan_results_count",
    "vulnerabilityCount",
    "has_vulnerabilities",
    "security_scan_status",
  ];
  const hasVulnerabilityEvidence = hasAnyOwnDataValue(record, vulnerabilityEvidenceFields);
  const hasMaxSeverity = hasOwnDataValue(record, "max_severity");
  if (hasVulnerabilityEvidence || hasMaxSeverity) {
    const vulnerability = adaptVulnerability(record, { allowDetectedSentinel: true });
    if (hasVulnerabilityEvidence && (
      vulnerability.evidence !== pkg.vulnerability.evidence
      || vulnerability.detected !== pkg.vulnerability.detected
      || vulnerability.count !== pkg.vulnerability.count
      || vulnerability.scanStatus !== pkg.vulnerability.scanStatus
    )) throw projectionConflict("vulnerability");
    if (hasMaxSeverity && vulnerability.maxSeverity !== pkg.vulnerability.maxSeverity) {
      throw projectionConflict("vulnerability.maxSeverity");
    }
  }
}

function projectionConflict(field) {
  return adapterError(
    "conflicting_canonical_projection",
    field,
    `The canonical package and outer ${field} projection conflict.`
  );
}

function validateIdentityConsensus(record, pkg, allowMissing) {
  const fields = [
    ["workspace", ["workspace", "namespace", "cloudsmithWorkspace"]],
    ["repository", ["repository", "cloudsmithRepo"]],
    ["packageIdentifier", ["packageIdentifier", "slug_perm", "slug_perm_raw"]],
  ];
  for (const [field, aliases] of fields) {
    const value = consensusString(record, aliases, field, {
      required: !allowMissing && aliases.some(alias => hasOwnSuppliedValue(record, alias)),
      unwrapDepth: MAX_WRAPPER_DEPTH,
    });
    if (value !== null && value !== pkg[field]) {
      throw adapterError(
        "conflicting_aliases",
        field,
        `The ${field} aliases conflict.`
      );
    }
  }
}

function validateExpectedScope(pkg, options) {
  if (options === undefined) return;
  requireRecord(options, "package adapter options", { plain: true });
  const expectedWorkspace = readOwn(options, "expectedWorkspace");
  const expectedRepository = readOwn(options, "expectedRepository");
  for (const [field, expected, actual] of [
    ["workspace", expectedWorkspace, pkg.workspace],
    ["repository", expectedRepository, pkg.repository],
  ]) {
    if (expected === undefined || expected === null) continue;
    if (typeof expected !== "string" || expected !== actual) {
      throw adapterError(
        "unexpected_scope",
        field,
        "The API package was returned outside the requested scope."
      );
    }
  }
}

function recordVersion(record, options) {
  const primary = readScalarAlias(record, "version", {
    allowEmpty: true,
    allowNumber: options.allowNumber,
    unwrapDepth: options.unwrapDepth,
  });
  if (primary.supplied && primary.value !== "") return primary.value;
  if (!options.declaredVersionFallback) {
    if (primary.supplied) {
      throw adapterError("invalid_string", "version", "The version value is invalid.");
    }
    throw adapterError("missing_field", "version", "The version value is required.");
  }
  return consensusString(record, ["declaredVersion"], "version", {
    required: true,
    unwrapDepth: options.unwrapDepth,
    allowNumber: options.allowNumber,
  });
}

function dependencyCoordinateVersion(record) {
  for (const field of ["resolvedVersion", "version", "declaredVersion"]) {
    const candidate = readScalarAlias(record, field, {
      allowEmpty: true,
      allowNumber: true,
      unwrapDepth: MAX_WRAPPER_DEPTH,
    });
    if (candidate.supplied && candidate.value) return candidate.value;
  }
  throw adapterError("missing_field", "version", "The dependency version is required.");
}

function adaptTags(record) {
  const candidates = [];
  for (const field of ["tags_raw", "tags"]) {
    const value = readOwn(record, field);
    if (value === undefined || value === null) continue;
    if (field === "tags" && isPresentationWrapper(value)) continue;
    candidates.push(normalizeTags(value));
  }
  const canonical = readNestedCanonical(record, "tags");
  if (canonical) candidates.push(normalizeTags(canonical));
  return consensusStructured(candidates, "tags", { info: [], version: [] });
}

function normalizeTags(value) {
  requireRecord(value, "tags", { plain: true });
  return {
    info: normalizeTagField(readOwn(value, "info"), "tags.info"),
    version: normalizeTagField(readOwn(value, "version"), "tags.version"),
  };
}

function normalizeTagField(value, field) {
  if (value === undefined || value === null) return [];
  const values = Array.isArray(value) ? readArrayData(value, field) : [value];
  if (values.length > 100 || values.some(item => typeof item !== "string")) {
    throw adapterError("invalid_tags", field, `The ${field} value is invalid.`);
  }
  return values;
}

function adaptPolicy(record) {
  const nested = readNestedCanonical(record, "policy");
  return {
    violated: consensusBooleanAcross(record, nested, ["policy_violated"], ["violated"]),
    denyViolated: consensusBooleanAcross(
      record,
      nested,
      ["deny_policy_violated"],
      ["denyViolated"]
    ),
    licenseViolated: consensusBooleanAcross(
      record,
      nested,
      ["license_policy_violated"],
      ["licenseViolated"]
    ),
    vulnerabilityViolated: consensusBooleanAcross(
      record,
      nested,
      ["vulnerability_policy_violated"],
      ["vulnerabilityViolated"]
    ),
  };
}

function consensusBooleanAcross(record, nested, aliases, nestedAliases) {
  const candidates = collectNormalized(record, aliases, normalizeLiteralBoolean, MAX_WRAPPER_DEPTH);
  if (nested) {
    candidates.push(...collectNormalized(nested, nestedAliases, normalizeLiteralBoolean, 0));
  }
  return consensusPrimitive(candidates, aliases[0]) ?? false;
}

function adaptVulnerability(record, options) {
  const nested = readNestedCanonical(record, "vulnerability");
  const countEvidence = collectEvidenceValues(
    record,
    ["num_vulnerabilities", "vulnerability_scan_results_count", "vulnerabilityCount"],
    value => normalizeCount(value, options.allowDetectedSentinel),
    MAX_WRAPPER_DEPTH
  );
  if (nested) {
    const nestedCounts = collectEvidenceValues(nested, ["count"], value => (
      value === null ? null : normalizeCount(value, false)
    ), 0);
    countEvidence.values.push(...nestedCounts.values);
    countEvidence.invalid ||= nestedCounts.invalid;
    countEvidence.supplied ||= nestedCounts.supplied;
  }
  let detectedWithoutCount = false;
  const actualCounts = [];
  for (const candidate of countEvidence.values) {
    if (candidate === -1) detectedWithoutCount = true;
    else if (candidate !== null) actualCounts.push(candidate);
  }
  const uniqueCounts = new Set(actualCounts);
  const presenceEvidence = collectEvidenceValues(
    record,
    ["has_vulnerabilities"],
    normalizeBoolean,
    MAX_WRAPPER_DEPTH
  );
  const statusEvidence = collectEvidenceValues(
    record,
    ["security_scan_status"],
    value => normalizeString(value, false),
    MAX_WRAPPER_DEPTH
  );
  if (nested) {
    const nestedPresence = collectEvidenceValues(
      nested,
      ["detected"],
      normalizeLiteralBoolean,
      0
    );
    presenceEvidence.values.push(...nestedPresence.values);
    presenceEvidence.invalid ||= nestedPresence.invalid;
    presenceEvidence.supplied ||= nestedPresence.supplied;
    const nestedStatuses = collectEvidenceValues(
      nested,
      ["scanStatus"],
      value => normalizeString(value, false),
      0
    );
    statusEvidence.values.push(...nestedStatuses.values);
    statusEvidence.invalid ||= nestedStatuses.invalid;
    statusEvidence.supplied ||= nestedStatuses.supplied;
  }
  const presenceTrue = presenceEvidence.values.some(value => value === true);
  const presenceFalse = presenceEvidence.values.some(value => value === false);
  const statusConflict = new Set(statusEvidence.values).size > 1;
  const scanStatus = statusEvidence.values[0] || null;
  const normalizedStatus = scanStatus ? scanStatus.trim().toLowerCase() : null;
  const statusDetected = normalizedStatus === DETECTED_STATUS;
  const statusClean = normalizedStatus === CLEAN_STATUS;
  const unrecognizedStatus = Boolean(scanStatus && !statusDetected && !statusClean);
  const rawMaxSeverity = consensusStringAcross(
    record,
    nested,
    ["max_severity"],
    ["maxSeverity"]
  );
  const normalizedMaxSeverity = rawMaxSeverity ? rawMaxSeverity.trim().toLowerCase() : null;
  const severityDetected = Boolean(
    normalizedMaxSeverity
    && normalizedMaxSeverity !== "none"
    && normalizedMaxSeverity !== "unknown"
  );
  const severityClean = normalizedMaxSeverity === "none";
  const positive = detectedWithoutCount || actualCounts.some(count => count > 0)
    || presenceTrue || statusDetected || severityDetected;
  const negative = actualCounts.some(count => count === 0)
    || presenceFalse || statusClean || severityClean;
  let nestedUnknown = false;
  if (nested) {
    const nestedEvidence = consensusString(nested, ["evidence"], "vulnerability.evidence", {
      required: false,
      unwrapDepth: 0,
    });
    nestedUnknown = nestedEvidence === "unknown";
    if (nestedEvidence && !["unknown", "clean", "detected"].includes(nestedEvidence)) {
      nestedUnknown = true;
    }
  }
  const hasEvidence = countEvidence.supplied || presenceEvidence.supplied
    || statusEvidence.supplied || severityDetected || severityClean || Boolean(nested);
  const unknown = !hasEvidence
    || countEvidence.invalid
    || presenceEvidence.invalid
    || statusEvidence.invalid
    || uniqueCounts.size > 1
    || statusConflict
    || unrecognizedStatus
    || (positive && negative)
    || nestedUnknown;
  const evidence = unknown ? "unknown" : positive ? "detected" : "clean";
  const canonicalCount = !unknown && uniqueCounts.size === 1
    ? actualCounts[0]
    : !unknown && negative ? 0 : null;
  return {
    evidence,
    detected: positive,
    count: canonicalCount,
    maxSeverity: evidence === "clean" || !severityDetected ? null : rawMaxSeverity,
    scanStatus: evidence === "unknown" ? null : scanStatus,
  };
}

function collectEvidenceValues(record, aliases, normalize, unwrapDepth) {
  const outcome = { values: [], invalid: false, supplied: false };
  for (const alias of aliases) {
    assertNoInheritedProperty(record, alias);
    const descriptor = Object.getOwnPropertyDescriptor(record, alias);
    if (!descriptor) continue;
    if (!("value" in descriptor)) {
      throw adapterError("accessor_property", alias, `The ${alias} value must be a data property.`);
    }
    if (descriptor.value === undefined || descriptor.value === null || descriptor.value === "") {
      continue;
    }
    outcome.supplied = true;
    const unwrapped = unwrapScalar(descriptor.value, alias, unwrapDepth);
    const normalized = normalize(unwrapped);
    if (normalized === null) outcome.invalid = true;
    else outcome.values.push(normalized);
  }
  return outcome;
}

function adaptLicense(record) {
  const nested = readNestedCanonical(record, "license");
  return {
    spdx: consensusStringAcross(record, nested, ["spdx_license"], ["spdx"]),
    declared: consensusStringAcross(
      record,
      nested,
      nested ? [] : ["license"],
      ["declared"]
    ),
    raw: consensusStringAcross(record, nested, ["raw_license"], ["raw"]),
    url: consensusStringAcross(record, nested, ["license_url"], ["url"]),
  };
}

function consensusStringAcross(record, nested, aliases, nestedAliases) {
  const candidates = collectNormalized(
    record,
    aliases,
    value => normalizeString(value, false),
    MAX_WRAPPER_DEPTH
  );
  if (nested) {
    candidates.push(...collectNormalized(
      nested,
      nestedAliases,
      value => normalizeString(value, false),
      0
    ));
  }
  return consensusPrimitive(candidates, aliases[0] || nestedAliases[0]);
}

function readNestedCanonical(record, field) {
  const value = readOwn(record, field);
  if (value === undefined || value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  if (isPresentationWrapper(value)) return null;
  return requireRecord(value, field, { plain: true });
}

function consensusString(record, aliases, field, options) {
  const candidates = collectNormalized(
    record,
    aliases,
    value => normalizeString(value, options.allowNumber),
    options.unwrapDepth
  );
  const value = consensusPrimitive(candidates, field);
  if (value === null && options.required) {
    throw adapterError("missing_field", field, `The ${field} value is required.`);
  }
  return value;
}

function consensusBoolean(record, aliases, field, options) {
  const candidates = collectNormalized(
    record,
    aliases,
    normalizeLiteralBoolean,
    options.unwrapDepth
  );
  const value = consensusPrimitive(candidates, field);
  if (value === null && options.required) {
    throw adapterError("missing_field", field, `The ${field} value is required.`);
  }
  return value;
}

function consensusInteger(record, aliases, field, options) {
  const candidates = collectNormalized(
    record,
    aliases,
    value => normalizeCount(value, false),
    options.unwrapDepth
  );
  const value = consensusPrimitive(candidates, field);
  if (value === null) {
    if (options.required) {
      throw adapterError("missing_field", field, `The ${field} value is required.`);
    }
    return options.defaultValue;
  }
  return value;
}

function collectNormalized(record, aliases, normalize, unwrapDepth) {
  const candidates = [];
  for (const alias of aliases) {
    const candidate = readScalarAlias(record, alias, {
      allowEmpty: false,
      normalize,
      unwrapDepth,
    });
    if (candidate.supplied) candidates.push(candidate.value);
  }
  return candidates;
}

function readScalarAlias(record, alias, options) {
  assertNoInheritedProperty(record, alias);
  const descriptor = Object.getOwnPropertyDescriptor(record, alias);
  if (!descriptor) return { supplied: false, value: null };
  if (!("value" in descriptor)) {
    throw adapterError("accessor_property", alias, `The ${alias} value must be a data property.`);
  }
  if (descriptor.value === undefined || descriptor.value === null) {
    return { supplied: false, value: null };
  }
  const unwrapped = unwrapScalar(descriptor.value, alias, options.unwrapDepth);
  let normalized;
  if (options.normalize) {
    normalized = options.normalize(unwrapped);
  } else {
    normalized = normalizeString(unwrapped, options.allowNumber);
  }
  if (options.allowEmpty && normalized === "") {
    return { supplied: true, value: "" };
  }
  if (normalized === null || normalized === "") {
    throw adapterError("invalid_alias", alias, `The ${alias} value is invalid.`);
  }
  return { supplied: true, value: normalized };
}

function unwrapScalar(value, field, maxDepth) {
  let current = value;
  for (let depth = 0; depth < maxDepth; depth += 1) {
    if (!current || typeof current !== "object" || Array.isArray(current)) break;
    assertNoSymbolProperties(current, field);
    assertNoOwnAccessors(current, field);
    assertNoInheritedProperty(current, "value", field);
    const descriptor = Object.getOwnPropertyDescriptor(current, "value");
    if (!descriptor) break;
    if (!("value" in descriptor)) {
      throw adapterError("accessor_property", field, `The ${field} wrapper is invalid.`);
    }
    current = descriptor.value;
  }
  if (current && typeof current === "object") {
    assertNoSymbolProperties(current, field);
    assertNoOwnAccessors(current, field);
    throw adapterError("wrapper_depth", field, `The ${field} wrapper is invalid.`);
  }
  return current;
}

function normalizeString(value, allowNumber) {
  if (typeof value === "string") return value;
  if (allowNumber && typeof value === "number" && Number.isFinite(value)) return String(value);
  return null;
}

function normalizeBoolean(value) {
  if (value === true || value === false) return value;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true") return true;
    if (normalized === "false") return false;
  }
  return null;
}

function normalizeLiteralBoolean(value) {
  return value === true || value === false ? value : null;
}

function normalizeCount(value, allowDetectedSentinel) {
  if (allowDetectedSentinel && value === -1) return -1;
  if (Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value !== "string" || !/^(0|[1-9]\d*)$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function consensusPrimitive(candidates, field) {
  if (candidates.length === 0) return null;
  if (candidates.some(value => value !== candidates[0])) {
    throw adapterError("conflicting_aliases", field, `The ${field} aliases conflict.`);
  }
  return candidates[0];
}

function consensusStructured(candidates, field, fallback) {
  if (candidates.length === 0) return fallback;
  const serialized = candidates.map(value => JSON.stringify(value));
  if (serialized.some(value => value !== serialized[0])) {
    throw adapterError("conflicting_aliases", field, `The ${field} aliases conflict.`);
  }
  return candidates[0];
}

function readArrayData(value, field) {
  assertNoSymbolProperties(value, field);
  assertNoOwnAccessors(value, field);
  if (Object.getPrototypeOf(value) !== Array.prototype) {
    throw adapterError("invalid_array", field, `The ${field} value is invalid.`);
  }
  const result = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor)) {
      throw adapterError("accessor_property", field, `The ${field} value is invalid.`);
    }
    result.push(descriptor.value);
  }
  return result;
}

function isPresentationWrapper(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  assertNoSymbolProperties(value, "wrapper");
  assertNoOwnAccessors(value, "wrapper");
  assertNoInheritedProperty(value, "value", "wrapper");
  assertNoInheritedProperty(value, "id", "wrapper");
  const valueDescriptor = Object.getOwnPropertyDescriptor(value, "value");
  const idDescriptor = Object.getOwnPropertyDescriptor(value, "id");
  return Boolean(valueDescriptor && "value" in valueDescriptor && idDescriptor && "value" in idDescriptor);
}

function hasOwnSuppliedValue(record, field) {
  assertNoInheritedProperty(record, field);
  const descriptor = Object.getOwnPropertyDescriptor(record, field);
  if (!descriptor) return false;
  if (!("value" in descriptor)) {
    throw adapterError("accessor_property", field, `The ${field} value must be a data property.`);
  }
  return descriptor.value !== undefined && descriptor.value !== null;
}

function hasOwnDataValue(record, field) {
  assertNoInheritedProperty(record, field);
  const descriptor = Object.getOwnPropertyDescriptor(record, field);
  if (!descriptor) return false;
  if (!("value" in descriptor)) {
    throw adapterError("accessor_property", field, `The ${field} value must be a data property.`);
  }
  return descriptor.value !== undefined && descriptor.value !== null;
}

function readOwn(record, field) {
  assertNoInheritedProperty(record, field);
  const descriptor = Object.getOwnPropertyDescriptor(record, field);
  if (!descriptor) return undefined;
  if (!("value" in descriptor)) {
    throw adapterError("accessor_property", field, `The ${field} value must be a data property.`);
  }
  return descriptor.value;
}

function requireRecord(value, field, options = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw adapterError("invalid_record", field, `The ${field} value is invalid.`);
  }
  try {
    if (options.plain) {
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) {
        throw adapterError("invalid_record", field, `The ${field} value is invalid.`);
      }
    }
    assertNoSymbolProperties(value, field);
    assertNoOwnAccessors(value, field);
    assertNoInheritedSemanticProperties(value, field);
  } catch (error) {
    if (PACKAGE_ADAPTER_ERRORS.has(error)) throw error;
    // Reflection traps are part of the untrusted record boundary. Normalize them
    // without retaining or inspecting the adversarial thrown value.
    throw adapterError("invalid_record", field, `The ${field} value is invalid.`);
  }
  return value;
}

function assertNoSymbolProperties(value, field) {
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw adapterError("symbol_property", field, `The ${field} value is invalid.`);
  }
}

function assertNoOwnAccessors(value, field) {
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if (!("value" in descriptor)) {
      throw adapterError("accessor_property", field, `The ${field} value is invalid.`);
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
      throw adapterError(
        "inherited_property",
        field,
        `The ${field} value contains an inherited semantic property.`
      );
    }
    prototype = Object.getPrototypeOf(prototype);
  }
}

function requireExact(value, field) {
  if (!isExactPackage(value)) {
    throw adapterError("exact_identity_required", field, "An exact package identity is required.");
  }
  return value;
}

function createPackageDetail(id, value) {
  return Object.freeze({
    id: boundaryString(id, "detail id", 256),
    value: boundaryString(value, "detail value", 8192, { trim: false }),
  });
}

function boundaryString(value, field, maxLength, options = {}) {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > maxLength
    || /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/.test(value)
    || (options.trim !== false && value !== value.trim())
  ) {
    throw adapterError("invalid_string", field, `The ${field} value is invalid.`);
  }
  return value;
}

function boundaryPathPart(value, field, maxLength) {
  const validated = boundaryString(value, field, maxLength);
  let decoded = validated;
  const maximumDecodeDepth = Math.ceil(validated.length / 2) + 1;
  for (let depth = 0; depth < maximumDecodeDepth; depth += 1) {
    let next;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      throw adapterError("invalid_path_part", field, `The ${field} value is invalid.`);
    }
    if (next === decoded) break;
    decoded = next;
  }
  if (decoded === "." || decoded === ".." || /[\\/?#]/.test(decoded)) {
    throw adapterError("invalid_path_part", field, `The ${field} value is unsafe.`);
  }
  return validated;
}

function adapterError(code, field, message, unexpected = false) {
  return new PackageAdapterError(code, field, message, unexpected);
}

function asAdapterError(error, code, field) {
  if (PACKAGE_ADAPTER_ERRORS.has(error)) return error;
  const domainError = snapshotPackageDomainError(error);
  if (domainError) {
    return adapterError(domainError.code, domainError.field, domainError.message);
  }
  return adapterError(code, field, `The ${field} value is invalid.`, true);
}

function isUnexpectedPackageAdapterError(error) {
  if (!PACKAGE_ADAPTER_ERRORS.has(error)) return true;
  try {
    const unexpected = Object.getOwnPropertyDescriptor(error, "unexpected");
    return Boolean(unexpected && "value" in unexpected && unexpected.value === true);
  } catch {
    return true;
  }
}

function snapshotPackageDomainError(error) {
  try {
    if (!PackageDomainError.isTrusted(error)) return null;
    const properties = Object.getOwnPropertyDescriptors(error);
    const code = properties.code?.value;
    const errorField = properties.field?.value;
    const message = properties.message?.value;
    if (![code, errorField, message].every(value => typeof value === "string")) return null;
    return { code, field: errorField, message };
  } catch {
    return null;
  }
}

module.exports = {
  PackageAdapterError,
  fromApiPackageRecord,
  fromDependencyHealthNode,
  fromExactPackageSelectionIfPresent,
  fromPackageDetailNode,
  fromPackageGroupNode,
  fromPackageNode,
  fromPackageResolutionSelection,
  fromPackageSelection,
  fromRecentPackageRecord,
  fromRepositoryNode,
  fromRepositoryPackageSelection,
  fromSearchResultNode,
};

// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const { URL, pathToFileURL } = require("url");
const {
  canonicalFormat,
  normalizePackageName,
  normalizeSwiftIdentity,
  sanitizePackageNameInput,
} = require("./packageNameNormalizer");

const DEPENDENCY_VERSION_STATES = Object.freeze({
  RESOLVED: "resolved",
  EXACT_DECLARATION: "exact-declaration",
  RANGE: "range",
  UNRESOLVED: "unresolved",
  INCOMPLETE: "incomplete",
});

const RESOLUTION_SOURCE_KINDS = Object.freeze({
  MANIFEST: "manifest",
  LOCKFILE: "lockfile",
  PACKAGE_MANAGER: "package-manager",
});

const DEPENDENCY_PACKAGE_SOURCE_KINDS = Object.freeze({
  REGISTRY: "registry",
  LOCAL: "local",
  PATH: "path",
  GIT: "git",
  SCM: "scm",
  SDK: "sdk",
  SYSTEM: "system",
  UNKNOWN: "unknown",
});

const DEPENDENCY_LOOKUP_ELIGIBILITY_STATES = Object.freeze({
  ELIGIBLE: "eligible",
  NOT_APPLICABLE: "not-applicable",
  UNRESOLVED: "unresolved",
});

const DEPENDENCY_QUALIFIER_KEYS = Object.freeze([
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

const MAX_LOOKUP_NAME_LENGTH = 2048;
const MAX_LOOKUP_VERSION_LENGTH = 2048;
const MAX_LOOKUP_FORMAT_LENGTH = 100;
const MAX_QUALIFIER_VALUE_LENGTH = 4096;
const MAX_QUALIFIER_ARRAY_LENGTH = 64;
const MAX_PACKAGE_SOURCE_LOCATION_LENGTH = 4096;
const MAX_PACKAGE_SOURCE_REF_LENGTH = 1024;
const MAX_PACKAGE_SOURCE_DISPLAY_LENGTH = 1024;
const MAX_CANONICAL_IDENTITY_LENGTH = 4096;
const MAX_CANONICAL_VALUE_LENGTH = 8192;
const MAX_PARENT_CHAIN_LENGTH = 128;
const MAX_TRANSITIVE_DEPTH = 128;
const MAX_TRANSITIVE_OCCURRENCES = 50000;
const MAX_SOURCE_POSITION_VALUE = 100000000;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;

const VERSION_STATE_VALUES = new Set(Object.values(DEPENDENCY_VERSION_STATES));
const SOURCE_KIND_VALUES = new Set(Object.values(RESOLUTION_SOURCE_KINDS));
const PACKAGE_SOURCE_KIND_VALUES = new Set(Object.values(DEPENDENCY_PACKAGE_SOURCE_KINDS));
const QUALIFIER_KEY_VALUES = new Set(DEPENDENCY_QUALIFIER_KEYS);
const CANONICAL_DEPENDENCY_RECORDS = new WeakSet();

/**
 * @typedef {{line: number, character: number}} DependencySourcePosition
 * @typedef {{start: DependencySourcePosition, end: DependencySourcePosition}} DependencySourceRange
 * @typedef {{
 *   kind: "manifest"|"lockfile"|"package-manager",
 *   filePath: string,
 *   uri: string,
 *   type: string,
 *   range: DependencySourceRange|null,
 * }} DependencySource
 * @typedef {{
 *   ecosystem: string,
 *   format: string,
 *   name: string,
 *   normalizedName: string,
 *   declarationName: string,
 *   declaredConstraint: string|null,
 *   resolvedVersion: string|null,
 *   versionState: "resolved"|"exact-declaration"|"range"|"unresolved"|"incomplete",
 *   resolutionSource: DependencySource|null,
 *   sourceManifest: DependencySource|null,
 *   environmentMarker: string|null,
 *   isDirect: boolean,
 *   isDevelopmentDependency: boolean,
 *   parent: string|null,
 *   parentChain: string[],
 *   transitives: DependencyRecord[],
 *   legacyVersion: string,
 * }} DependencyRecord
 */

/**
 * Create plain, immutable file provenance without introducing a VS Code API
 * dependency into the dependency domain.
 *
 * @param {{kind: string, filePath: string, type?: string, range?: object|null, workspaceFolder?: string}} values
 * @returns {DependencySource}
 */
function createDependencySource(values) {
  const properties = getStrictPlainDataProperties(values, "dependency source");
  const kind = boundedRequiredString(
    ownDataPropertyValue(properties, "kind"),
    "dependency source kind",
    32
  );
  if (!SOURCE_KIND_VALUES.has(kind)) {
    throw new TypeError(`Unsupported dependency source kind: ${kind || "<empty>"}`);
  }

  const filePath = boundedRequiredString(
    ownDataPropertyValue(properties, "filePath"),
    "dependency source path",
    MAX_CANONICAL_VALUE_LENGTH
  );
  if (!filePath || !path.isAbsolute(filePath)) {
    throw new TypeError("Dependency source paths must be absolute.");
  }

  const normalizedPath = path.normalize(filePath);
  const type = boundedOptionalSafeString(
    ownDataPropertyValue(properties, "type"),
    "dependency source type",
    256
  ) || path.basename(normalizedPath);
  if (!type) {
    throw new TypeError("Dependency sources must have a type.");
  }
  const label = ownDataPropertyValue(properties, "label");
  const workspaceFolder = boundedOptionalSafeString(
    ownDataPropertyValue(properties, "workspaceFolder"),
    "dependency source workspace folder",
    MAX_CANONICAL_VALUE_LENGTH
  );

  return Object.freeze({
    kind,
    filePath: normalizedPath,
    uri: pathToFileURL(normalizedPath).toString(),
    type,
    label: label != null
      ? validateSourceLabel(label)
      : createWorkspaceRelativeSourceLabel(normalizedPath, workspaceFolder),
    range: copySourceRange(ownDataPropertyValue(properties, "range")),
  });
}

/**
 * Create the canonical dependency-domain record. Cloudsmith scan state is
 * deliberately applied later so parser output cannot be mistaken for trusted
 * remote package data.
 *
 * @param {object} values
 * @returns {DependencyRecord}
 */
function createDependencyRecord(values) {
  return createDependencyRecordInternal(values, {
    ancestors: new WeakSet(),
    occurrences: 0,
  }, 0);
}

function createDependencyRecordInternal(values, graphState, depth) {
  if (depth > MAX_TRANSITIVE_DEPTH) {
    throw new TypeError("Dependency transitive graphs exceed the supported depth.");
  }
  graphState.occurrences += 1;
  if (graphState.occurrences > MAX_TRANSITIVE_OCCURRENCES) {
    throw new TypeError("Dependency transitive graphs exceed the supported occurrence count.");
  }
  const properties = getStrictPlainDataProperties(values, "dependency record");
  const input = values;
  if (graphState.ancestors.has(input)) {
    throw new TypeError("Dependency transitive graphs must not contain cycles.");
  }
  graphState.ancestors.add(input);

  try {
    const ecosystem = sanitizePackageNameInput(
      ownDataPropertyValue(properties, "ecosystem")
    ).toLowerCase();
    const format = canonicalFormat(
      ownDataPropertyValue(properties, "format") || ecosystem
    );
    const name = sanitizePackageNameInput(ownDataPropertyValue(properties, "name"));
    if (!ecosystem || !format || !name) {
      throw new TypeError("Dependency records require an ecosystem, format, and package name.");
    }

    const declaredConstraint = boundedCanonicalOptionalString(
      ownDataPropertyValue(properties, "declaredConstraint"),
      "dependency declared constraint"
    );
    const resolvedVersion = boundedCanonicalOptionalString(
      ownDataPropertyValue(properties, "resolvedVersion"),
      "dependency resolved version"
    );
    const versionState = boundedCanonicalRequiredString(
      ownDataPropertyValue(properties, "versionState")
        || (resolvedVersion
          ? DEPENDENCY_VERSION_STATES.RESOLVED
          : DEPENDENCY_VERSION_STATES.UNRESOLVED),
      "dependency version state",
      32
    );
    if (!VERSION_STATE_VALUES.has(versionState)) {
      throw new TypeError(`Unsupported dependency version state: ${versionState || "<empty>"}`);
    }
    if (versionState === DEPENDENCY_VERSION_STATES.RESOLVED && !resolvedVersion) {
      throw new TypeError("Resolved dependency records require a resolved version.");
    }
    if (resolvedVersion && versionState !== DEPENDENCY_VERSION_STATES.RESOLVED) {
      throw new TypeError("Dependencies with a resolved version must use the resolved version state.");
    }

    const sourceManifest = copyDependencySource(
      ownDataPropertyValue(properties, "sourceManifest")
    );
    if (sourceManifest && sourceManifest.kind !== RESOLUTION_SOURCE_KINDS.MANIFEST) {
      throw new TypeError("sourceManifest must use the manifest source kind.");
    }

    const hasExplicitPackageSource = Boolean(
      properties.packageSource
      && properties.packageSource.value != null
    );
    // The canonical boundary cannot infer registry provenance from omission.
    // Compatibility adapters must derive and pass registry explicitly when
    // ecosystem evidence justifies network lookup.
    const packageSource = copyPackageSource(
      hasExplicitPackageSource
        ? properties.packageSource.value
        : { kind: DEPENDENCY_PACKAGE_SOURCE_KINDS.UNKNOWN }
    );
    const qualifiers = copyQualifiers(ownDataPropertyValue(properties, "qualifiers"));
    const recordValues = {
      ecosystem,
      format,
      name,
      normalizedName: normalizePackageName(name, format),
      declarationName: boundedCanonicalOptionalString(
        ownDataPropertyValue(properties, "declarationName")
          || ownDataPropertyValue(properties, "declaredName"),
        "dependency declaration name",
        MAX_CANONICAL_IDENTITY_LENGTH
      ) || name,
      declaredConstraint,
      resolvedVersion,
      versionState,
      resolutionSource: copyDependencySource(
        ownDataPropertyValue(properties, "resolutionSource")
      ),
      sourceManifest,
      packageSource,
      qualifiers,
      environmentMarker: boundedCanonicalOptionalString(
        ownDataPropertyValue(properties, "environmentMarker"),
        "dependency environment marker"
      ),
      isDirect: ownDataPropertyValue(properties, "isDirect") === true,
      isDevelopmentDependency:
        ownDataPropertyValue(properties, "isDevelopmentDependency") === true,
      parent: boundedCanonicalOptionalString(
        ownDataPropertyValue(properties, "parent"),
        "dependency parent",
        MAX_CANONICAL_IDENTITY_LENGTH
      ),
      parentChain: Object.freeze(copyStringArray(
        ownDataPropertyValue(properties, "parentChain")
      )),
      transitives: copyTransitives(
        ownDataPropertyValue(properties, "transitives"),
        graphState,
        depth
      ),
      legacyVersion: boundedCanonicalOptionalString(
        ownDataPropertyValue(properties, "legacyVersion"),
        "dependency compatibility version"
      ) || "",
    };
    const record = Object.freeze({
      ...recordValues,
      lookupEligibility: createLookupEligibility(recordValues),
    });
    CANONICAL_DEPENDENCY_RECORDS.add(record);
    return record;
  } finally {
    graphState.ancestors.delete(input);
  }
}

/**
 * Build occurrence identity without collapsing distinct resolved versions,
 * manifests, or graph paths into package-name identity.
 *
 * @param {DependencyRecord} dependency
 * @returns {string}
 */
function getDependencyOccurrenceKey(dependency) {
  const format = canonicalFormat(dependency && (dependency.format || dependency.ecosystem));
  const caseSensitive = format === "maven" || format === "go";
  const normalizeIdentityPart = (value) => {
    const normalized = String(value || "");
    return caseSensitive ? normalized : normalized.toLowerCase();
  };
  return JSON.stringify([
    String(dependency && dependency.ecosystem || "").toLowerCase(),
    normalizeIdentityPart(
      dependency && dependency.normalizedName
      || normalizePackageName(dependency && dependency.name, format)
    ),
    normalizeIdentityPart(dependency && dependency.declarationName),
    String(dependency && dependency.resolvedVersion || ""),
    String(dependency && dependency.declaredConstraint || ""),
    String(dependency && dependency.legacyVersion || ""),
    sourceIdentity(dependency && dependency.sourceManifest),
    sourceIdentity(dependency && dependency.resolutionSource),
    packageSourceIdentity(dependency && dependency.packageSource),
    qualifierIdentity(dependency && dependency.qualifiers),
    String(dependency && dependency.environmentMarker || ""),
    dependency && dependency.isDirect ? "direct" : "transitive",
    dependency && dependency.isDevelopmentDependency ? "development" : "runtime",
    String(dependency && dependency.parent || ""),
    Array.isArray(dependency && dependency.parentChain) ? dependency.parentChain : [],
  ]);
}

/**
 * Build ecosystem-aware artifact identity for coverage and enrichment. Unlike
 * occurrence identity, this intentionally ignores graph and manifest
 * provenance. NuGet target frameworks therefore share one artifact identity,
 * while Ruby platform and Maven classifier/type artifacts remain distinct.
 */
function getDependencyArtifactKey(dependency) {
  const format = canonicalFormat(dependency && (dependency.format || dependency.ecosystem));
  const caseSensitive = format === "maven" || format === "go";
  const qualifiers = dependency && dependency.qualifiers || {};
  const identityName = format === "swift"
    ? normalizeSwiftIdentity(dependency && dependency.name, qualifiers.scope)
    : String(dependency && (dependency.normalizedName || dependency.name) || "");
  const artifactQualifiers = {};
  if (format === "ruby" && qualifiers.platform) {
    artifactQualifiers.platform = qualifiers.platform;
  }
  if (format === "maven") {
    if (qualifiers.type) artifactQualifiers.type = qualifiers.type;
    if (qualifiers.classifier) artifactQualifiers.classifier = qualifiers.classifier;
  }
  if (format === "docker") {
    if (qualifiers.tag) artifactQualifiers.tag = qualifiers.tag;
    if (qualifiers.digest) artifactQualifiers.digest = qualifiers.digest;
  }
  return JSON.stringify([
    format,
    caseSensitive ? identityName : identityName.toLowerCase(),
    getDependencyConcreteVersion(dependency) || "",
    artifactQualifiers,
  ]);
}

function getDependencyConcreteVersion(dependency) {
  if (!dependency || typeof dependency !== "object") {
    return null;
  }
  if (dependency.resolvedVersion) {
    return String(dependency.resolvedVersion).trim() || null;
  }
  if (dependency.versionState === DEPENDENCY_VERSION_STATES.EXACT_DECLARATION) {
    return String(dependency.legacyVersion || dependency.version || "").trim() || null;
  }
  return null;
}

function isDependencyLookupEligible(dependency) {
  return Boolean(
    dependency
    && dependency.lookupEligibility
    && dependency.lookupEligibility.state === DEPENDENCY_LOOKUP_ELIGIBILITY_STATES.ELIGIBLE
  );
}

function getDependencySourceLabel(dependency) {
  const source = dependency && (dependency.sourceManifest || dependency.resolutionSource);
  if (source && source.label) {
    return source.label;
  }
  const sourceFile = String(dependency && dependency.sourceFile || "").trim();
  return sourceFile && !path.isAbsolute(sourceFile) ? sourceFile : path.basename(sourceFile);
}

/**
 * Produce a customer-safe source location without mutating or replacing the
 * canonical provenance used by matching and diagnostics. URL credentials,
 * query strings, and fragments can contain secrets. Absolute local paths can
 * expose usernames or machine layout, so only their basename is displayed.
 */
function getDependencyPackageSourceDisplayLocation(packageSource) {
  const location = String(packageSource && packageSource.location || "").trim();
  if (!location) return null;
  const kind = String(packageSource && packageSource.kind || "").trim();
  const decodedLocation = decodeSourceLocatorForDisplay(location);
  if (decodedLocation == null) {
    return isLocalPackageSourceKind(kind) ? "local source" : "source";
  }
  let display = stripSourceLocatorUserInfo(decodedLocation);

  // Treat local pseudo-schemes as path locators even when their authority is
  // malformed. URL parsing is deliberately not required here: a broken
  // `file:` authority must not make a machine-local absolute path printable.
  if (
    isLocalPackageSourceKind(kind)
    || isLocalSourceScheme(display)
    || isAbsoluteDisplayPath(display)
  ) {
    display = basenameForDisplay(decodeLocalSourceLocator(display));
  } else {
    try {
      const parsed = new URL(display);
      if (parsed.protocol === "file:") {
        // A malformed percent escape must never fall back to displaying the
        // complete file URL. Decode only when valid and always reduce it to a
        // basename.
        let filePath = parsed.pathname;
        try {
          filePath = decodeURIComponent(filePath);
        } catch {
          // The encoded basename is still safe to display.
        }
        display = basenameForDisplay(filePath);
      } else {
        parsed.username = "";
        parsed.password = "";
        parsed.search = "";
        parsed.hash = "";
        display = parsed.toString();
      }
    } catch {
      display = display.replace(/[?#].*$/, "");
      display = stripSourceLocatorUserInfo(display);
      if (isAbsoluteDisplayPath(display)) {
        display = basenameForDisplay(display);
      }
    }
  }

  display = display.replace(/[\r\n\t\u0000-\u001f\u007f]+/g, " ").trim();
  if (!display) {
    return [
      DEPENDENCY_PACKAGE_SOURCE_KINDS.LOCAL,
      DEPENDENCY_PACKAGE_SOURCE_KINDS.PATH,
      DEPENDENCY_PACKAGE_SOURCE_KINDS.SDK,
      DEPENDENCY_PACKAGE_SOURCE_KINDS.SYSTEM,
    ].includes(kind) ? "local source" : "source";
  }
  return display.length <= MAX_PACKAGE_SOURCE_DISPLAY_LENGTH
    ? display
    : `${display.slice(0, MAX_PACKAGE_SOURCE_DISPLAY_LENGTH - 1)}…`;
}

function stripSourceLocatorUserInfo(value) {
  const input = String(value || "");
  // Strip userinfo conservatively at both an authority boundary and a path
  // boundary. The latter covers malformed one- or three-slash SSH locators
  // that WHATWG URL parsing either rejects or treats as opaque paths. The
  // pattern requires text before `@`, so scoped path segments such as
  // `/@scope/package` remain intact.
  let previous;
  // Decode only structural locator separators before scrubbing. This catches
  // encoded userinfo without decoding arbitrary path content into display.
  let stripped = input
    .replace(/%2f/ig, "/")
    .replace(/%5c/ig, "\\")
    .replace(/%40/ig, "@");
  do {
    previous = stripped;
    stripped = stripped.replace(/(^|[\\/])[^\\/?#@]+@/g, "$1");
  } while (stripped !== previous);
  return stripped;
}

function isLocalSourceScheme(value) {
  return /^(?:file|local|path):/i.test(String(value || ""));
}

function isLocalPackageSourceKind(kind) {
  return [
    DEPENDENCY_PACKAGE_SOURCE_KINDS.LOCAL,
    DEPENDENCY_PACKAGE_SOURCE_KINDS.PATH,
    DEPENDENCY_PACKAGE_SOURCE_KINDS.SDK,
    DEPENDENCY_PACKAGE_SOURCE_KINDS.SYSTEM,
  ].includes(kind);
}

function decodeSourceLocatorForDisplay(value) {
  let current = String(value || "");
  // Resolve repeated encoding only for customer presentation and with a hard
  // iteration bound. This exposes encoded schemes, path separators, userinfo,
  // query, and fragment delimiters to the ordinary fail-closed sanitizer.
  for (let index = 0; index < 4; index += 1) {
    let decoded;
    try {
      decoded = decodeURIComponent(current);
    } catch {
      decoded = current
        .replace(/%25/ig, "%")
        .replace(/%2f/ig, "/")
        .replace(/%5c/ig, "\\")
        .replace(/%3a/ig, ":")
        .replace(/%40/ig, "@")
        .replace(/%3f/ig, "?")
        .replace(/%23/ig, "#");
    }
    if (decoded === current) break;
    current = decoded;
  }
  // More encoding layers than the bounded presentation decoder can safely
  // inspect must not be echoed. Structural delimiters could still conceal
  // userinfo, an absolute path, query credentials, or a fragment.
  if (/%(?:25|2f|5c|3a|40|3f|23)/i.test(current)) {
    return null;
  }
  return current;
}

function decodeLocalSourceLocator(value) {
  try {
    return decodeURIComponent(String(value || ""));
  } catch {
    // Even with another malformed escape, structural path separators must be
    // decoded so basename reduction cannot expose an encoded absolute path.
    return String(value || "")
      .replace(/%2f/ig, "/")
      .replace(/%5c/ig, "\\")
      .replace(/%3a/ig, ":");
  }
}

function getDependencyPackageSourceDisplayRef(value) {
  if (typeof value !== "string" || !value.trim()) return null;
  const display = getDependencyPackageSourceDisplayLocation({
    kind: DEPENDENCY_PACKAGE_SOURCE_KINDS.UNKNOWN,
    location: value,
  });
  if (!display) return null;
  // Refs commonly contain `/` (for example `release/1.x`) and should remain
  // recognizable. Only absolute/path-like or credential-bearing locators are
  // reduced by the shared customer-safe location boundary.
  return display;
}

function getDependencyQualifierDisplayValue(key, value) {
  if (key === "repository") {
    return getDependencyPackageSourceDisplayLocation({
      kind: DEPENDENCY_PACKAGE_SOURCE_KINDS.REGISTRY,
      location: value,
    });
  }
  return Array.isArray(value) ? value.join(", ") : value;
}

function isAbsoluteDisplayPath(value) {
  return path.isAbsolute(value)
    || /^[A-Za-z]:[\\/]/.test(value)
    || /^\\\\(?:\?\\)?[^\\]/.test(value);
}

function basenameForDisplay(value) {
  const raw = String(value || "");
  const withoutSuffix = /^\\\\\?\\/.test(raw)
    ? raw.replace(/[\\/]+$/, "")
    : raw.replace(/[?#].*$/, "").replace(/[\\/]+$/, "");
  return withoutSuffix.split(/[\\/]/).filter(Boolean).pop() || "local source";
}

function sourceIdentity(source) {
  if (!source) {
    return null;
  }
  return [source.kind, source.uri, source.range];
}

function packageSourceIdentity(packageSource) {
  if (!packageSource) return null;
  return [
    packageSource.kind,
    packageSource.location,
    packageSource.branch,
    packageSource.revision,
  ];
}

function qualifierIdentity(qualifiers) {
  if (!qualifiers || typeof qualifiers !== "object") return null;
  return DEPENDENCY_QUALIFIER_KEYS
    .filter((key) => Object.prototype.hasOwnProperty.call(qualifiers, key))
    .map((key) => [key, qualifiers[key]]);
}

function copyDependencySource(source) {
  if (!source) {
    return null;
  }

  return createDependencySource(source);
}

function copyPackageSource(packageSource) {
  if (packageSource == null) {
    return Object.freeze({
      kind: DEPENDENCY_PACKAGE_SOURCE_KINDS.UNKNOWN,
      location: null,
      branch: null,
      revision: null,
    });
  }
  const properties = getStrictPlainDataProperties(packageSource, "dependency package source");
  rejectUnknownProperties(properties, new Set(["kind", "location", "branch", "revision"]), "dependency package source");
  const kind = boundedRequiredString(properties.kind && properties.kind.value, "dependency package source kind", 32);
  if (!PACKAGE_SOURCE_KIND_VALUES.has(kind)) {
    throw new TypeError(`Unsupported dependency package source kind: ${kind || "<empty>"}`);
  }
  return Object.freeze({
    kind,
    location: boundedOptionalSafeString(
      properties.location && properties.location.value,
      "dependency package source location",
      MAX_PACKAGE_SOURCE_LOCATION_LENGTH
    ),
    branch: boundedOptionalSafeString(
      properties.branch && properties.branch.value,
      "dependency package source branch",
      MAX_PACKAGE_SOURCE_REF_LENGTH
    ),
    revision: boundedOptionalSafeString(
      properties.revision && properties.revision.value,
      "dependency package source revision",
      MAX_PACKAGE_SOURCE_REF_LENGTH
    ),
  });
}

function createDependencyPackageSource(packageSource) {
  return copyPackageSource(packageSource);
}

function copyQualifiers(qualifiers) {
  if (qualifiers == null) return Object.freeze({});
  const properties = getStrictPlainDataProperties(qualifiers, "dependency qualifiers");
  rejectUnknownProperties(properties, QUALIFIER_KEY_VALUES, "dependency qualifiers");
  const result = {};
  for (const key of DEPENDENCY_QUALIFIER_KEYS) {
    if (!properties[key]) continue;
    const value = properties[key].value;
    if (key === "configurations") {
      const entries = getStrictArrayDataValues(
        value,
        `dependency qualifier ${key}`,
        MAX_QUALIFIER_ARRAY_LENGTH
      );
      result[key] = Object.freeze(entries.map((entry) => boundedRequiredString(
        entry,
        `dependency qualifier ${key}`,
        MAX_QUALIFIER_VALUE_LENGTH
      )));
      continue;
    }
    const normalized = boundedOptionalSafeString(
      value,
      `dependency qualifier ${key}`,
      MAX_QUALIFIER_VALUE_LENGTH
    );
    if (normalized != null) result[key] = normalized;
  }
  return Object.freeze(result);
}

function createDependencyQualifiers(qualifiers) {
  return copyQualifiers(qualifiers);
}

function createLookupEligibility(record) {
  const packageSourceKind = record.packageSource.kind;
  const concreteVersion = getDependencyConcreteVersion(record);
  if (!concreteVersion && packageSourceKind === DEPENDENCY_PACKAGE_SOURCE_KINDS.REGISTRY) {
    return Object.freeze({
      state: DEPENDENCY_LOOKUP_ELIGIBILITY_STATES.UNRESOLVED,
      reason: "unresolved-version",
    });
  }
  if (packageSourceKind !== DEPENDENCY_PACKAGE_SOURCE_KINDS.REGISTRY) {
    return Object.freeze({
      state: DEPENDENCY_LOOKUP_ELIGIBILITY_STATES.NOT_APPLICABLE,
      reason: `${packageSourceKind}-source`,
    });
  }
  if (
    !isSafeLookupString(record.format, MAX_LOOKUP_FORMAT_LENGTH)
    || !isSafeLookupString(record.normalizedName, MAX_LOOKUP_NAME_LENGTH)
    || !isSafeLookupString(concreteVersion, MAX_LOOKUP_VERSION_LENGTH)
  ) {
    return Object.freeze({
      state: DEPENDENCY_LOOKUP_ELIGIBILITY_STATES.NOT_APPLICABLE,
      reason: "unsafe-identity",
    });
  }
  return Object.freeze({
    state: DEPENDENCY_LOOKUP_ELIGIBILITY_STATES.ELIGIBLE,
    reason: null,
  });
}

function isSafeLookupString(value, maximumLength) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= maximumLength
    && value.trim() === value
    && !CONTROL_CHARACTER_PATTERN.test(value);
}

function createWorkspaceRelativeSourceLabel(filePath, workspaceFolder) {
  const workspaceRoot = String(workspaceFolder || "").trim();
  if (!workspaceRoot || !path.isAbsolute(workspaceRoot)) {
    return path.basename(filePath);
  }
  const relativePath = path.relative(path.resolve(workspaceRoot), filePath);
  if (
    !relativePath
    || relativePath === ".."
    || relativePath.startsWith(`..${path.sep}`)
    || path.isAbsolute(relativePath)
  ) {
    return path.basename(filePath);
  }
  return relativePath.split(path.sep).join("/");
}

function validateSourceLabel(value) {
  if (typeof value !== "string") {
    throw new TypeError("Dependency source labels must be strings.");
  }
  const normalized = value.trim().replace(/\\/g, "/");
  if (
    !normalized
    || normalized.length > 8192
    || normalized.startsWith("/")
    || /^[A-Za-z]:\//.test(normalized)
    || normalized.split("/").some((segment) => segment === "..")
    || CONTROL_CHARACTER_PATTERN.test(normalized)
  ) {
    throw new TypeError("Dependency source labels must be bounded workspace-relative paths.");
  }
  return normalized;
}

function getStrictPlainDataProperties(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be a plain object.`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${label} must be a plain object.`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const descriptor of Object.values(descriptors)) {
    if (!Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw new TypeError(`${label} must contain only data properties.`);
    }
  }
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw new TypeError(`${label} must not contain symbol properties.`);
  }
  return descriptors;
}

function ownDataPropertyValue(properties, key) {
  return properties[key] ? properties[key].value : undefined;
}

function getStrictArrayDataValues(value, label, maximumLength) {
  if (!Array.isArray(value)) {
    throw new TypeError(`${label} must be an array.`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Array.prototype && prototype !== null) {
    throw new TypeError(`${label} must be a plain array.`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw new TypeError(`${label} must not contain symbol properties.`);
  }
  const lengthDescriptor = descriptors.length;
  const length = lengthDescriptor && lengthDescriptor.value;
  if (!Number.isSafeInteger(length) || length < 0 || length > maximumLength) {
    throw new TypeError(`${label} exceeds the supported length.`);
  }
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (key === "length") continue;
    if (!/^(?:0|[1-9]\d*)$/.test(key) || Number(key) >= length) {
      throw new TypeError(`${label} must contain only indexed data properties.`);
    }
    if (!Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw new TypeError(`${label} must contain only indexed data properties.`);
    }
  }
  const result = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw new TypeError(`${label} must be a dense data array.`);
    }
    result.push(descriptor.value);
  }
  return result;
}

function rejectUnknownProperties(properties, allowedKeys, label) {
  for (const key of Object.keys(properties)) {
    if (!allowedKeys.has(key)) {
      throw new TypeError(`${label} contains unsupported property: ${key}`);
    }
  }
}

function boundedRequiredString(value, label, maximumLength) {
  const normalized = boundedOptionalSafeString(value, label, maximumLength);
  if (!normalized) throw new TypeError(`${label} must be a non-empty string.`);
  return normalized;
}

function boundedOptionalSafeString(value, label, maximumLength) {
  if (value == null || value === "") return null;
  if (typeof value !== "string") {
    throw new TypeError(`${label} must be a string.`);
  }
  const normalized = value.trim();
  if (
    !normalized
    || normalized.length > maximumLength
    || CONTROL_CHARACTER_PATTERN.test(normalized)
  ) {
    throw new TypeError(`${label} is invalid or exceeds the supported bound.`);
  }
  return normalized;
}

function copyTransitives(transitives, graphState, depth) {
  if (transitives == null) {
    return Object.freeze([]);
  }
  const children = getStrictArrayDataValues(
    transitives,
    "dependency record transitives",
    MAX_TRANSITIVE_OCCURRENCES
  );

  return Object.freeze(children.map((child) => {
    if (CANONICAL_DEPENDENCY_RECORDS.has(child)) {
      countCanonicalTransitiveGraph(child, graphState, depth + 1);
      return child;
    }
    if (!child || typeof child !== "object" || Array.isArray(child)) {
      throw new TypeError("Dependency transitives must contain dependency record objects.");
    }
    return createDependencyRecordInternal(child, graphState, depth + 1);
  }));
}

function countCanonicalTransitiveGraph(root, graphState, depth) {
  const stack = [{ dependency: root, depth }];
  while (stack.length > 0) {
    const current = stack.pop();
    if (current.depth > MAX_TRANSITIVE_DEPTH) {
      throw new TypeError("Dependency transitive graphs exceed the supported depth.");
    }
    graphState.occurrences += 1;
    if (graphState.occurrences > MAX_TRANSITIVE_OCCURRENCES) {
      throw new TypeError("Dependency transitive graphs exceed the supported occurrence count.");
    }
    for (let index = current.dependency.transitives.length - 1; index >= 0; index -= 1) {
      stack.push({
        dependency: current.dependency.transitives[index],
        depth: current.depth + 1,
      });
    }
  }
}

function copySourceRange(range) {
  if (range == null) {
    return null;
  }

  const properties = getStrictPlainDataProperties(range, "dependency source range");
  rejectUnknownProperties(
    properties,
    new Set(["start", "end"]),
    "dependency source range"
  );
  const start = copySourcePosition(
    ownDataPropertyValue(properties, "start"),
    "start"
  );
  const end = copySourcePosition(
    ownDataPropertyValue(properties, "end"),
    "end"
  );
  if (end.line < start.line || (end.line === start.line && end.character < start.character)) {
    throw new TypeError("Dependency source ranges must end after they start.");
  }

  return Object.freeze({ start, end });
}

function copySourcePosition(position, label) {
  const properties = getStrictPlainDataProperties(
    position,
    `dependency source ${label} position`
  );
  rejectUnknownProperties(
    properties,
    new Set(["line", "character"]),
    `dependency source ${label} position`
  );
  const line = ownDataPropertyValue(properties, "line");
  const character = ownDataPropertyValue(properties, "character");
  if (
    !Number.isSafeInteger(line)
    || line < 0
    || line > MAX_SOURCE_POSITION_VALUE
    || !Number.isSafeInteger(character)
    || character < 0
    || character > MAX_SOURCE_POSITION_VALUE
  ) {
    throw new TypeError(`Dependency source ${label} positions must use non-negative integers.`);
  }

  return Object.freeze({ line, character });
}

function copyStringArray(values) {
  if (values == null) return [];
  const entries = getStrictArrayDataValues(
    values,
    "dependency parent chain",
    MAX_PARENT_CHAIN_LENGTH
  );
  return entries.map((value) => boundedCanonicalRequiredString(
    value,
    "dependency parent chain entry",
    MAX_CANONICAL_IDENTITY_LENGTH
  ));
}

function boundedCanonicalRequiredString(value, label, maximumLength) {
  const normalized = boundedCanonicalOptionalString(value, label, maximumLength);
  if (!normalized) {
    throw new TypeError(`${label} must be a non-empty string.`);
  }
  return normalized;
}

function boundedCanonicalOptionalString(
  value,
  label,
  maximumLength = MAX_CANONICAL_VALUE_LENGTH
) {
  if (value == null || value === "") return null;
  if (typeof value !== "string") {
    throw new TypeError(`${label} must be a string.`);
  }
  const normalized = value.trim();
  if (!normalized) return null;
  if (
    normalized.length > maximumLength
    || CONTROL_CHARACTER_PATTERN.test(normalized)
  ) {
    throw new TypeError(`${label} is invalid or exceeds the supported bound.`);
  }
  return normalized;
}

module.exports = {
  DEPENDENCY_LOOKUP_ELIGIBILITY_STATES,
  DEPENDENCY_PACKAGE_SOURCE_KINDS,
  DEPENDENCY_QUALIFIER_KEYS,
  DEPENDENCY_VERSION_STATES,
  RESOLUTION_SOURCE_KINDS,
  createDependencyRecord,
  createDependencyPackageSource,
  createDependencyQualifiers,
  createDependencySource,
  getDependencyArtifactKey,
  getDependencyConcreteVersion,
  getDependencyOccurrenceKey,
  getDependencyPackageSourceDisplayLocation,
  getDependencyPackageSourceDisplayRef,
  getDependencyQualifierDisplayValue,
  getDependencySourceLabel,
  isDependencyLookupEligible,
};

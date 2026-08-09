// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const { pathToFileURL } = require("url");
const {
  canonicalFormat,
  normalizePackageName,
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

const VERSION_STATE_VALUES = new Set(Object.values(DEPENDENCY_VERSION_STATES));
const SOURCE_KIND_VALUES = new Set(Object.values(RESOLUTION_SOURCE_KINDS));
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
 * @param {{kind: string, filePath: string, type?: string, range?: object|null}} values
 * @returns {DependencySource}
 */
function createDependencySource(values) {
  const kind = String(values && values.kind || "").trim();
  if (!SOURCE_KIND_VALUES.has(kind)) {
    throw new TypeError(`Unsupported dependency source kind: ${kind || "<empty>"}`);
  }

  const filePath = String(values && values.filePath || "").trim();
  if (!filePath || !path.isAbsolute(filePath)) {
    throw new TypeError("Dependency source paths must be absolute.");
  }

  const normalizedPath = path.normalize(filePath);
  const type = String(values && values.type || path.basename(normalizedPath)).trim();
  if (!type) {
    throw new TypeError("Dependency sources must have a type.");
  }

  return Object.freeze({
    kind,
    filePath: normalizedPath,
    uri: pathToFileURL(normalizedPath).toString(),
    type,
    range: copySourceRange(values && values.range),
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
  return createDependencyRecordInternal(values, new WeakSet());
}

function createDependencyRecordInternal(values, ancestors) {
  const input = values && typeof values === "object" && !Array.isArray(values)
    ? values
    : null;
  if (input && ancestors.has(input)) {
    throw new TypeError("Dependency transitive graphs must not contain cycles.");
  }
  if (input) {
    ancestors.add(input);
  }

  try {
    const ecosystem = sanitizePackageNameInput(values && values.ecosystem).toLowerCase();
    const format = canonicalFormat(values && (values.format || ecosystem));
    const name = sanitizePackageNameInput(values && values.name);
    if (!ecosystem || !format || !name) {
      throw new TypeError("Dependency records require an ecosystem, format, and package name.");
    }

    const declaredConstraint = optionalString(values && values.declaredConstraint);
    const resolvedVersion = optionalString(values && values.resolvedVersion);
    const versionState = String(
      values && values.versionState
        || (resolvedVersion ? DEPENDENCY_VERSION_STATES.RESOLVED : DEPENDENCY_VERSION_STATES.UNRESOLVED)
    ).trim();
    if (!VERSION_STATE_VALUES.has(versionState)) {
      throw new TypeError(`Unsupported dependency version state: ${versionState || "<empty>"}`);
    }
    if (versionState === DEPENDENCY_VERSION_STATES.RESOLVED && !resolvedVersion) {
      throw new TypeError("Resolved dependency records require a resolved version.");
    }
    if (resolvedVersion && versionState !== DEPENDENCY_VERSION_STATES.RESOLVED) {
      throw new TypeError("Dependencies with a resolved version must use the resolved version state.");
    }

    const sourceManifest = copyDependencySource(values && values.sourceManifest);
    if (sourceManifest && sourceManifest.kind !== RESOLUTION_SOURCE_KINDS.MANIFEST) {
      throw new TypeError("sourceManifest must use the manifest source kind.");
    }

    const record = Object.freeze({
      ecosystem,
      format,
      name,
      normalizedName: normalizePackageName(name, format),
      declarationName: optionalString(values && (values.declarationName || values.declaredName)) || name,
      declaredConstraint,
      resolvedVersion,
      versionState,
      resolutionSource: copyDependencySource(values && values.resolutionSource),
      sourceManifest,
      environmentMarker: optionalString(values && values.environmentMarker),
      isDirect: Boolean(values && values.isDirect),
      isDevelopmentDependency: Boolean(values && values.isDevelopmentDependency),
      parent: optionalString(values && values.parent),
      parentChain: Object.freeze(copyStringArray(values && values.parentChain)),
      transitives: copyTransitives(values && values.transitives, ancestors),
      legacyVersion: String(values && values.legacyVersion || "").trim(),
    });
    CANONICAL_DEPENDENCY_RECORDS.add(record);
    return record;
  } finally {
    if (input) {
      ancestors.delete(input);
    }
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
    normalizeIdentityPart(dependency && dependency.normalizedName),
    normalizeIdentityPart(dependency && dependency.declarationName),
    String(dependency && dependency.resolvedVersion || ""),
    String(dependency && dependency.declaredConstraint || ""),
    String(dependency && dependency.legacyVersion || ""),
    sourceIdentity(dependency && dependency.sourceManifest),
    sourceIdentity(dependency && dependency.resolutionSource),
    String(dependency && dependency.environmentMarker || ""),
    dependency && dependency.isDirect ? "direct" : "transitive",
    dependency && dependency.isDevelopmentDependency ? "development" : "runtime",
    String(dependency && dependency.parent || ""),
    Array.isArray(dependency && dependency.parentChain) ? dependency.parentChain : [],
  ]);
}

function sourceIdentity(source) {
  if (!source) {
    return null;
  }
  return [source.kind, source.uri, source.range];
}

function copyDependencySource(source) {
  if (!source) {
    return null;
  }

  return createDependencySource({
    kind: source.kind,
    filePath: source.filePath,
    type: source.type,
    range: source.range,
  });
}

function copyTransitives(transitives, ancestors) {
  if (transitives == null) {
    return Object.freeze([]);
  }
  if (!Array.isArray(transitives)) {
    throw new TypeError("Dependency record transitives must be an array.");
  }

  return Object.freeze(transitives.map((child) => {
    if (CANONICAL_DEPENDENCY_RECORDS.has(child)) {
      return child;
    }
    if (!child || typeof child !== "object" || Array.isArray(child)) {
      throw new TypeError("Dependency transitives must contain dependency record objects.");
    }
    return createDependencyRecordInternal(child, ancestors);
  }));
}

function copySourceRange(range) {
  if (range == null) {
    return null;
  }

  const start = copySourcePosition(range.start, "start");
  const end = copySourcePosition(range.end, "end");
  if (end.line < start.line || (end.line === start.line && end.character < start.character)) {
    throw new TypeError("Dependency source ranges must end after they start.");
  }

  return Object.freeze({ start, end });
}

function copySourcePosition(position, label) {
  const line = position && position.line;
  const character = position && position.character;
  if (!Number.isInteger(line) || line < 0 || !Number.isInteger(character) || character < 0) {
    throw new TypeError(`Dependency source ${label} positions must use non-negative integers.`);
  }

  return Object.freeze({ line, character });
}

function copyStringArray(values) {
  return Array.isArray(values)
    ? values.map((value) => String(value || "").trim()).filter(Boolean)
    : [];
}

function optionalString(value) {
  if (value == null) {
    return null;
  }

  const normalized = String(value).trim();
  return normalized || null;
}

module.exports = {
  DEPENDENCY_VERSION_STATES,
  RESOLUTION_SOURCE_KINDS,
  createDependencyRecord,
  createDependencySource,
  getDependencyOccurrenceKey,
};

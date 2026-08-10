// Circular buffer of recently interacted-with packages.
// Module singleton — same instance everywhere via CommonJS caching.

const { InstallCommandBuilder } = require("./installCommandBuilder");

const MAX_RECENT = 10;
const _recent = [];

function unwrapValue(prop) {
  if (prop == null) {
    return null;
  }
  if (typeof prop === "string") {
    return prop;
  }
  if (typeof prop === "object" && prop.value != null) {
    if (typeof prop.value === "object" && prop.value.value != null) {
      return String(prop.value.value);
    }
    return String(prop.value);
  }
  return String(prop);
}

function getNestedField(pkg, fieldName) {
  if (!pkg || typeof pkg !== "object") {
    return null;
  }
  if (pkg[fieldName] != null) {
    return pkg[fieldName];
  }
  if (pkg.cloudsmithMatch && pkg.cloudsmithMatch[fieldName] != null) {
    return pkg.cloudsmithMatch[fieldName];
  }
  return null;
}

function getRawTags(pkg) {
  if (!pkg || typeof pkg !== "object") {
    return null;
  }
  if (pkg.tags_raw && typeof pkg.tags_raw === "object" && !Array.isArray(pkg.tags_raw)) {
    return pkg.tags_raw;
  }
  if (pkg.tags && typeof pkg.tags === "object" && !Array.isArray(pkg.tags)) {
    if (!(pkg.tags.id && Object.prototype.hasOwnProperty.call(pkg.tags, "value"))) {
      return pkg.tags;
    }
  }
  if (pkg.cloudsmithMatch && pkg.cloudsmithMatch.tags && typeof pkg.cloudsmithMatch.tags === "object") {
    return pkg.cloudsmithMatch.tags;
  }
  return null;
}

function canonicalVersionScalar(value) {
  if (value === undefined || value === null) {
    return { state: "absent", value: "" };
  }
  let current = value;
  for (let depth = 0; depth < 2; depth += 1) {
    if (
      !current
      || typeof current !== "object"
      || Array.isArray(current)
      || !Object.prototype.hasOwnProperty.call(current, "value")
    ) {
      break;
    }
    current = current.value;
  }
  if (typeof current === "string") {
    return { state: "valid", value: current };
  }
  if (typeof current === "number" && Number.isFinite(current)) {
    return { state: "valid", value: String(current) };
  }
  return { state: "invalid", value: "" };
}

function canonicalRecentVersion(pkg) {
  const version = canonicalVersionScalar(pkg.version);
  if (version.state === "invalid" || (version.state === "valid" && version.value.length > 0)) {
    return version;
  }
  const declaredVersion = canonicalVersionScalar(pkg.declaredVersion);
  return declaredVersion.state === "absent"
    ? { state: "valid", value: "" }
    : declaredVersion;
}

function normalizeRecentPackage(pkg) {
  const version = canonicalRecentVersion(pkg);
  return {
    name: pkg.name,
    workspace: canonicalAlias([pkg.cloudsmithWorkspace, pkg.namespace]),
    repository: canonicalAlias([pkg.cloudsmithRepo, pkg.repository]),
    packageIdentifier: canonicalAlias([pkg.slug_perm, pkg.slug_perm_raw]),
    version: version.value,
    versionValid: version.state === "valid",
  };
}

function recentPackageIdentity(normalized) {
  if (
    typeof normalized.name !== "string"
    || normalized.name.length === 0
    || typeof normalized.workspace !== "string"
    || typeof normalized.repository !== "string"
    || !normalized.versionValid
  ) {
    return null;
  }
  return JSON.stringify([
    normalized.workspace,
    normalized.name,
    normalized.version,
    normalized.repository,
  ]);
}

/**
 * Add a package to the recent list.
 * Workspace and repository may use their current or compatibility aliases. Only
 * records with a canonical workspace/repository/name/version tuple are deduplicated.
 * @param {Object} pkg Must have a non-empty name and a supported version shape.
 */
function add(pkg) {
  if (!pkg || typeof pkg.name !== "string" || pkg.name.length === 0) {
    return;
  }
  const normalized = normalizeRecentPackage(pkg);
  if (!normalized.versionValid) return;
  const key = recentPackageIdentity(normalized);
  if (key !== null) {
    for (let index = _recent.length - 1; index >= 0; index -= 1) {
      if (recentPackageIdentity(normalizeRecentPackage(_recent[index])) === key) {
        _recent.splice(index, 1);
      }
    }
  }
  const rawTags = getRawTags(pkg);
  _recent.unshift({
    name: normalized.name,
    format: pkg.format,
    version: normalized.version || null,
    namespace: normalized.workspace,
    repository: normalized.repository,
    slug_perm: normalized.packageIdentifier,
    slug_perm_raw: normalized.packageIdentifier,
    slug: unwrapValue(pkg.slug) || null,
    is_copyable: pkg.is_copyable === true
      ? true
      : pkg.is_copyable === false
        ? false
        : null,
    num_vulnerabilities: pkg.num_vulnerabilities || 0,
    max_severity: pkg.max_severity || null,
    checksum_sha256: getNestedField(pkg, "checksum_sha256") || null,
    version_digest: getNestedField(pkg, "version_digest") || null,
    docker_tag: InstallCommandBuilder.extractDockerTag(pkg),
    tags: rawTags,
    tags_raw: rawTags,
    cdn_url: getNestedField(pkg, "cdn_url") || null,
    filename: getNestedField(pkg, "filename") || null,
    status_str: unwrapValue(pkg.status_str) || pkg.status_str_raw || getNestedField(pkg, "status_str") || null,
    cloudsmithWorkspace: normalized.workspace,
    cloudsmithRepo: normalized.repository,
  });
  if (_recent.length > MAX_RECENT) {
    _recent.length = MAX_RECENT;
  }
}

function canonicalAlias(values) {
  const supplied = values.filter(value => value !== undefined && value !== null);
  const present = supplied.map(value => {
    let current = value;
    for (let depth = 0; depth < 2; depth += 1) {
      if (
        !current
        || typeof current !== "object"
        || Array.isArray(current)
        || !Object.prototype.hasOwnProperty.call(current, "value")
      ) {
        break;
      }
      current = current.value;
    }
    return typeof current === "string" && current.length > 0 ? current : null;
  });
  if (present.some(value => value === null)) return null;
  if (present.length === 0 || present.some(value => value !== present[0])) return null;
  return present[0];
}

/**
 * Get all recent packages (most recent first).
 * @returns {Array}
 */
function getAll() {
  return _recent.slice();
}

function clear() {
  _recent.length = 0;
}

module.exports = { add, clear, getAll };

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

/**
 * Add a package to the recent list.
 * @param {Object} pkg  Must have at least { name, format, namespace, repository }.
 */
function add(pkg) {
  if (!pkg || !pkg.name) {
    return;
  }
  const workspace = pkg.cloudsmithWorkspace || pkg.namespace || "";
  const version = unwrapValue(pkg.version) || pkg.declaredVersion || "";
  // Deduplicate by workspace + name + version + repository
  const key = `${workspace}:${pkg.name}:${version}:${pkg.repository || ""}`;
  const idx = _recent.findIndex(p =>
    `${p.cloudsmithWorkspace || p.namespace || ""}:${p.name}:${p.version || ""}:${p.repository || ""}` === key
  );
  if (idx >= 0) {
    _recent.splice(idx, 1);
  }
  const rawTags = getRawTags(pkg);
  _recent.unshift({
    name: pkg.name,
    format: pkg.format,
    version: version || null,
    namespace: pkg.namespace,
    repository: pkg.repository,
    slug_perm: unwrapValue(pkg.slug_perm),
    slug_perm_raw: pkg.slug_perm_raw || unwrapValue(pkg.slug_perm) || null,
    slug: unwrapValue(pkg.slug) || null,
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
    cloudsmithWorkspace: pkg.cloudsmithWorkspace || pkg.namespace || null,
    cloudsmithRepo: pkg.cloudsmithRepo || pkg.repository || null,
  });
  if (_recent.length > MAX_RECENT) {
    _recent.length = MAX_RECENT;
  }
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

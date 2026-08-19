// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { assertExactPackage } = require("../domain/package");

const MAX_INSPECTION_BYTES = 256 * 1024;
const MAX_INSPECTION_PACKAGES = 500;

/**
 * Project a canonical package into the bounded, non-secret inspection surface.
 * URL-bearing delivery fields and arbitrary API response properties are
 * intentionally excluded.
 */
function packageInspectionProjection(value) {
  const pkg = assertExactPackage(value);
  return Object.freeze({
    workspace: pkg.workspace,
    repository: pkg.repository,
    packageIdentifier: pkg.packageIdentifier,
    name: pkg.name,
    version: pkg.version,
    format: pkg.format,
    slug: pkg.slug,
    status: pkg.status,
    statusReason: pkg.statusReason,
    copyable: pkg.copyable,
    downloads: pkg.downloads,
    uploadedAt: pkg.uploadedAt,
    checksumSha256: pkg.checksumSha256,
    versionDigest: pkg.versionDigest,
    filename: pkg.filename,
    tags: pkg.tags,
    policy: pkg.policy,
    vulnerability: pkg.vulnerability,
    license: Object.freeze({
      spdx: pkg.license.spdx,
      declared: pkg.license.declared,
      raw: pkg.license.raw,
    }),
  });
}

function serializePackageInspection(value) {
  return boundedJson(packageInspectionProjection(value));
}

function serializePackageCollectionInspection(values, metadata = {}) {
  if (!Array.isArray(values)) {
    throw new TypeError("Package inspection values must be an array.");
  }
  const items = values
    .slice(0, MAX_INSPECTION_PACKAGES)
    .map(packageInspectionProjection);
  let omittedCount = values.length - items.length;
  let output;
  do {
    output = boundedJson({
      items,
      complete: metadata.complete === true && omittedCount === 0,
      loadedCount: values.length,
      displayedCount: items.length,
      omittedCount,
      totalCount: Number.isSafeInteger(metadata.totalCount) ? metadata.totalCount : null,
      termination: typeof metadata.termination === "string" ? metadata.termination : null,
      failureCount: Number.isSafeInteger(metadata.failureCount) ? metadata.failureCount : 0,
    }, { allowOversize: true });
    if (Buffer.byteLength(output, "utf8") <= MAX_INSPECTION_BYTES) return output;
    if (items.length === 0) break;
    items.pop();
    omittedCount += 1;
  } while (items.length >= 0);
  throw new RangeError("Package inspection output exceeded its safe size limit.");
}

function boundedJson(value, options = {}) {
  const output = JSON.stringify(value, null, 2);
  if (
    options.allowOversize !== true
    && Buffer.byteLength(output, "utf8") > MAX_INSPECTION_BYTES
  ) {
    throw new RangeError("Package inspection output exceeded its safe size limit.");
  }
  return output;
}

module.exports = {
  serializePackageCollectionInspection,
  serializePackageInspection,
};

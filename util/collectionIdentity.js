// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const MAX_COLLECTION_IDENTITY_PART_LENGTH = 512;
const MAX_IDENTITY_UNWRAP_DEPTH = 4;

function unwrapIdentityValue(value) {
  let current = value;
  for (let depth = 0; depth < MAX_IDENTITY_UNWRAP_DEPTH; depth += 1) {
    if (
      !current
      || typeof current !== "object"
      || Array.isArray(current)
      || !Object.prototype.hasOwnProperty.call(current, "value")
    ) {
      return current;
    }
    current = current.value;
  }
  return current && typeof current === "object" ? null : current;
}

function exactIdentityPart(value, label = "collection") {
  const unwrapped = unwrapIdentityValue(value);
  if (
    typeof unwrapped !== "string"
    || unwrapped.length === 0
    || unwrapped.length > MAX_COLLECTION_IDENTITY_PART_LENGTH
    || unwrapped.trim() !== unwrapped
  ) {
    throw new TypeError(`The ${label} identity was invalid.`);
  }
  return unwrapped;
}

function canonicalCollectionIdentity(parts, label = "collection") {
  if (!Array.isArray(parts) || parts.length === 0 || parts.length > 8) {
    throw new TypeError(`The ${label} identity was invalid.`);
  }
  return JSON.stringify(parts.map(part => exactIdentityPart(part, label)));
}

function workspaceCollectionIdentity(workspace) {
  return canonicalCollectionIdentity([workspace && workspace.slug], "workspace");
}

function repositoryCollectionIdentity(workspace, repository) {
  return canonicalCollectionIdentity(
    [workspace, repository && repository.slug],
    "repository"
  );
}

function packageCollectionIdentity(pkg) {
  return canonicalCollectionIdentity(
    [pkg && pkg.namespace, pkg && pkg.repository, pkg && pkg.slug_perm],
    "package"
  );
}

function packageGroupCollectionIdentity(workspace, repository, group) {
  return canonicalCollectionIdentity(
    [workspace, repository, group && group.format, group && group.name],
    "package group"
  );
}

function entitlementCollectionIdentity(workspace, repository, entitlement) {
  return canonicalCollectionIdentity(
    [workspace, repository, entitlement && entitlement.slug_perm],
    "entitlement"
  );
}

module.exports = {
  MAX_COLLECTION_IDENTITY_PART_LENGTH,
  canonicalCollectionIdentity,
  entitlementCollectionIdentity,
  exactIdentityPart,
  packageCollectionIdentity,
  packageGroupCollectionIdentity,
  repositoryCollectionIdentity,
  unwrapIdentityValue,
  workspaceCollectionIdentity,
};

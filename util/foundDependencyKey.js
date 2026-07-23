// Copyright 2026 Cloudsmith Ltd. All rights reserved.
function getFoundDependencyKey(dependency) {
  if (!dependency || !dependency.cloudsmithPackage) {
    return null;
  }

  const pkg = dependency.cloudsmithPackage;
  const workspace = String(pkg.namespace || "").trim().toLowerCase();
  const repo = String(pkg.repository || "").trim().toLowerCase();
  const slug = String(pkg.slug_perm || pkg.slugPerm || pkg.slug || pkg.identifier || "").trim().toLowerCase();

  if (!workspace || !repo || !slug) {
    return null;
  }

  return `${workspace}:${repo}:${slug}`;
}

module.exports = {
  getFoundDependencyKey,
};

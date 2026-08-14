// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { packageCollectionIdentity } = require("./collectionIdentity");
const { isExactPackage } = require("../domain/package");

function getFoundDependencyKey(dependency) {
  if (!dependency || !dependency.cloudsmithPackage) {
    return null;
  }

  return isExactPackage(dependency.cloudsmithPackage)
    ? packageCollectionIdentity(dependency.cloudsmithPackage)
    : null;
}

module.exports = {
  getFoundDependencyKey,
};

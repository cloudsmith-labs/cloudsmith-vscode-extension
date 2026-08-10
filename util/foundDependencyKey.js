// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { packageCollectionIdentity } = require("./collectionIdentity");

function getFoundDependencyKey(dependency) {
  if (!dependency || !dependency.cloudsmithPackage) {
    return null;
  }

  try {
    return packageCollectionIdentity(dependency.cloudsmithPackage);
  } catch {
    return null;
  }
}

module.exports = {
  getFoundDependencyKey,
};

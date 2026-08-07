// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const WEB_APP_BASE_URL = "https://app.cloudsmith.com";

function encodePathSegment(value) {
  return encodeURIComponent(String(value));
}

function buildRepositoryUrl(workspace, repo) {
  if (!workspace || !repo) {
    return null;
  }

  return `${WEB_APP_BASE_URL}/${encodePathSegment(workspace)}/${encodePathSegment(repo)}`;
}

function buildPackageUrl(workspace, repo, format, name, version, identifier) {
  if (!workspace || !repo || !format || !name || !version || !identifier) {
    return null;
  }

  const packageName = String(name).replaceAll("/", "_");
  const encodedPackageName = encodePathSegment(packageName).replaceAll("%40", "@");
  return `${WEB_APP_BASE_URL}/${encodePathSegment(workspace)}/${encodePathSegment(repo)}/${encodePathSegment(format)}/${encodedPackageName}/${encodePathSegment(version)}/${encodePathSegment(identifier)}`;
}

function buildPackageGroupUrl(workspace, repo, name) {
  const repositoryUrl = buildRepositoryUrl(workspace, repo);
  if (!repositoryUrl || !name) {
    return null;
  }

  const query = encodePathSegment(name);
  return `${repositoryUrl}?page=1&query=name:${query}&sort=name`;
}

module.exports = {
  WEB_APP_BASE_URL,
  buildRepositoryUrl,
  buildPackageUrl,
  buildPackageGroupUrl,
};

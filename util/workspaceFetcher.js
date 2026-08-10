// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { CloudsmithAPI } = require("./cloudsmithAPI");
const { apiEndpoint } = require("./apiEndpoint");
const {
  PaginatedFetch,
  collectionFailureResult,
  replaceCollectionItems,
} = require("./paginatedFetch");
const { workspaceCollectionIdentity } = require("./collectionIdentity");
const {
  captureAccount,
  isAccountCurrent,
  resolveConnectionManager,
} = require("./accountOperation");

const WORKSPACE_PAGE_SIZE = 500;
const MAX_WORKSPACE_PAGES = 20;
const MAX_WORKSPACES = 10000;
const STALE_WORKSPACE_ACCOUNT_ERROR = Object.freeze({
  kind: "stale_account",
  message: "The active Cloudsmith account changed while workspaces were loading.",
});

function staleResult() {
  return Object.freeze({
    ...collectionFailureResult(STALE_WORKSPACE_ACCOUNT_ERROR, { termination: "stale_account" }),
    stale: true,
  });
}

async function fetchWorkspaces(context, options = {}) {
  const {
    account: suppliedAccount,
    cloudsmithAPI: suppliedApi,
    connectionManager: suppliedManager,
    paginatedFetch: suppliedPagination,
    ...requestOptions
  } = options;
  const connectionManager = resolveConnectionManager(context, suppliedManager);
  const account = suppliedAccount || captureAccount(connectionManager);
  if (!account || !isAccountCurrent(connectionManager, account)) return staleResult();

  const cloudsmithAPI = suppliedApi || new CloudsmithAPI(context);
  const paginatedFetch = suppliedPagination || new PaginatedFetch(cloudsmithAPI);
  const endpoint = apiEndpoint(["namespaces"], { query: { sort: "slug" } });
  const result = await paginatedFetch.fetchCollection(endpoint, {
    ...requestOptions,
    pageSize: WORKSPACE_PAGE_SIZE,
    maxPages: MAX_WORKSPACE_PAGES,
    maxRequests: MAX_WORKSPACE_PAGES,
    maxItems: MAX_WORKSPACES,
    canonicalIdentity: workspaceCollectionIdentity,
    descriptor: `workspaces:${account.activationId}:${account.accountEpoch}`,
    validate: isWorkspaceArray,
  });
  if (!isAccountCurrent(connectionManager, account)) return staleResult();
  return Object.freeze({
    ...replaceCollectionItems(result, sortWorkspaces(result.items)),
    stale: false,
  });
}

function sortWorkspaces(workspaces) {
  return [...workspaces].sort((left, right) => {
    const leftName = normalizedWorkspaceName(left);
    const rightName = normalizedWorkspaceName(right);
    const byName = leftName.localeCompare(rightName, undefined, { sensitivity: "base" });
    if (byName !== 0) return byName;
    return left.slug.localeCompare(right.slug);
  });
}

function normalizedWorkspaceName(workspace) {
  return typeof workspace.name === "string" && workspace.name.length > 0
    ? workspace.name
    : workspace.slug;
}

function isWorkspaceArray(value) {
  return Array.isArray(value) && value.every(workspace => (
    workspace
    && typeof workspace === "object"
    && !Array.isArray(workspace)
    && typeof workspace.slug === "string"
    && workspace.slug.length > 0
    && workspace.slug.length <= 512
    && workspace.slug.trim() === workspace.slug
    && (
      workspace.name === undefined
      || (
        typeof workspace.name === "string"
        && workspace.name.length <= 512
      )
    )
  ));
}

module.exports = {
  MAX_WORKSPACES,
  MAX_WORKSPACE_PAGES,
  STALE_WORKSPACE_ACCOUNT_ERROR,
  WORKSPACE_PAGE_SIZE,
  fetchWorkspaces,
  isWorkspaceArray,
  normalizedWorkspaceName,
};

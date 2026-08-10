// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const vscode = require("vscode");
const { CloudsmithAPI } = require("./cloudsmithAPI");
const { apiEndpoint } = require("./apiEndpoint");
const { formatApiError } = require("./errorFormatter");
const {
  PaginatedFetch,
  collectionFailureResult,
  replaceCollectionItems,
} = require("./paginatedFetch");
const { repositoryCollectionIdentity } = require("./collectionIdentity");
const {
  captureAccount,
  isAccountCurrent,
  resolveConnectionManager,
} = require("./accountOperation");

const WORKSPACE_REPOSITORY_PAGE_SIZE = 500;
const MAX_WORKSPACE_REPOSITORY_PAGES = 20;
const MAX_WORKSPACE_REPOSITORIES = 10000;
const STALE_ACCOUNT_ERROR = Object.freeze({
  kind: "stale_account",
  message: "The active Cloudsmith account changed while repositories were loading.",
});

function staleResult() {
  return Object.freeze({
    ...collectionFailureResult(STALE_ACCOUNT_ERROR, { termination: "stale_account" }),
    stale: true,
  });
}

function sortRepositories(repositories) {
  return [...repositories].sort((left, right) => {
    const leftName = typeof left.name === "string" ? left.name : "";
    const rightName = typeof right.name === "string" ? right.name : "";
    const byName = leftName.localeCompare(rightName, undefined, { sensitivity: "base" });
    if (byName !== 0) return byName;
    return left.slug.localeCompare(right.slug);
  });
}

async function fetchWorkspaceRepositories(context, workspace, options = {}) {
  const {
    account: suppliedAccount,
    cloudsmithAPI: suppliedApi,
    connectionManager: suppliedManager,
    paginatedFetch: suppliedPagination,
    withProgress = vscode.window.withProgress.bind(vscode.window),
    ...requestOptions
  } = options;
  const connectionManager = resolveConnectionManager(context, suppliedManager);
  const account = suppliedAccount || captureAccount(connectionManager);
  if (!account || !isAccountCurrent(connectionManager, account)) return staleResult();

  let endpoint;
  try {
    endpoint = apiEndpoint(["repos", workspace], { query: { sort: "name" } });
  } catch {
    return Object.freeze({
      ...collectionFailureResult(
        Object.freeze({ kind: "invalid_request", message: "The workspace identifier is invalid." }),
        { termination: "invalid_request" }
      ),
      stale: false,
    });
  }

  const cloudsmithAPI = suppliedApi || new CloudsmithAPI(context);
  const paginatedFetch = suppliedPagination || new PaginatedFetch(cloudsmithAPI);
  return withProgress(
    {
      location: vscode.ProgressLocation.Window,
      title: `Loading repositories for ${workspace}...`,
      cancellable: true,
    },
    async (_progress, progressToken) => {
      if (!isAccountCurrent(connectionManager, account)) return staleResult();
      const result = await paginatedFetch.fetchCollection(endpoint, {
        ...requestOptions,
        pageSize: WORKSPACE_REPOSITORY_PAGE_SIZE,
        maxPages: MAX_WORKSPACE_REPOSITORY_PAGES,
        maxRequests: MAX_WORKSPACE_REPOSITORY_PAGES,
        maxItems: MAX_WORKSPACE_REPOSITORIES,
        canonicalIdentity: repository => repositoryCollectionIdentity(workspace, repository),
        descriptor: `workspace-repositories:${account.activationId}:${account.accountEpoch}:${workspace}`,
        validate: isRepositoryArray,
        cancellationToken: requestOptions.cancellationToken || progressToken,
      });
      if (!isAccountCurrent(connectionManager, account)) return staleResult();
      if (result.partial && result.failures.length > 0) {
        console.warn(
          `[WorkspaceRepositories] Repository enumeration is incomplete: ${formatApiError(result.failures[0].error)}`
        );
      }
      return Object.freeze({
        ...replaceCollectionItems(result, sortRepositories(result.items)),
        stale: false,
      });
    }
  );
}

function isRepositoryArray(value) {
  return Array.isArray(value) && value.every(repository => (
    repository
    && typeof repository === "object"
    && !Array.isArray(repository)
    && typeof repository.slug === "string"
    && repository.slug.length > 0
    && repository.slug.length <= 512
    && repository.slug.trim() === repository.slug
    && typeof repository.name === "string"
    && repository.name.length > 0
    && repository.name.length <= 512
  ));
}

module.exports = {
  MAX_WORKSPACE_REPOSITORIES,
  MAX_WORKSPACE_REPOSITORY_PAGES,
  STALE_ACCOUNT_ERROR,
  WORKSPACE_REPOSITORY_PAGE_SIZE,
  fetchWorkspaceRepositories,
};

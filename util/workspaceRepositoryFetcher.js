const vscode = require("vscode");
const { CloudsmithAPI } = require("./cloudsmithAPI");
const { apiEndpoint } = require("./apiEndpoint");
const { formatApiError } = require("./errorFormatter");
const { PaginatedFetch } = require("./paginatedFetch");
const {
  captureAccount,
  isAccountCurrent,
  resolveConnectionManager,
} = require("./accountOperation");

const WORKSPACE_REPOSITORY_PAGE_SIZE = 500;
const UNEXPECTED_RESPONSE_FORMAT_ERROR = "Unexpected repository response format";
const STALE_ACCOUNT_ERROR = Object.freeze({
  kind: "stale_account",
  message: "The active Cloudsmith account changed while repositories were loading.",
});

function staleResult() {
  return {
    repositories: [],
    error: STALE_ACCOUNT_ERROR,
    warning: null,
    partial: false,
    stale: true,
  };
}

function sortRepositories(repositories) {
  return [...repositories].sort((left, right) => {
    const leftName = typeof left.name === "string" ? left.name : "";
    const rightName = typeof right.name === "string" ? right.name : "";

    return leftName.localeCompare(rightName, undefined, {
      sensitivity: "base",
    });
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
  const cloudsmithAPI = suppliedApi || new CloudsmithAPI(context);
  const paginatedFetch = suppliedPagination || new PaginatedFetch(cloudsmithAPI);
  let endpoint;
  try {
    endpoint = apiEndpoint(["repos", workspace], { query: { sort: "name" } });
  } catch {
    return {
      repositories: [],
      error: Object.freeze({ kind: "invalid_request", message: "The workspace identifier is invalid." }),
      warning: null,
      partial: false,
      stale: false,
    };
  }

  return withProgress(
    {
      location: vscode.ProgressLocation.Window,
      title: `Loading repositories for ${workspace}...`,
    },
    async progress => {
      if (!isAccountCurrent(connectionManager, account)) return staleResult();
      const repositories = [];
      let page = 1;
      let knownPageTotal = null;

      while (true) {
        if (!isAccountCurrent(connectionManager, account)) return staleResult();
        progress.report({
          message: knownPageTotal ? `Page ${page} of ${knownPageTotal}` : `Page ${page}`,
        });

        const result = await paginatedFetch.fetchPage(
          endpoint,
          page,
          WORKSPACE_REPOSITORY_PAGE_SIZE,
          null,
          { ...requestOptions, validate: isRepositoryArray }
        );
        if (!isAccountCurrent(connectionManager, account)) return staleResult();

        if (result.error) {
          if (page === 1) {
            return {
              repositories: [],
              error: result.error,
              warning: null,
              partial: false,
              stale: false,
            };
          }

          console.warn(
            `[WorkspaceRepositories] Failed to load an additional repository page: ${formatApiError(result.error)}`
          );

          return {
            repositories: sortRepositories(repositories),
            error: null,
            warning: result.error,
            partial: true,
            stale: false,
          };
        }

        if (!Array.isArray(result.data)) {
          if (page === 1) {
            return {
              repositories: [],
              error: UNEXPECTED_RESPONSE_FORMAT_ERROR,
              warning: null,
              partial: false,
              stale: false,
            };
          }

          console.warn(
            `[WorkspaceRepositories] Failed to load additional repositories for ${workspace} on page ${page}: ${UNEXPECTED_RESPONSE_FORMAT_ERROR}`
          );

          return {
            repositories: sortRepositories(repositories),
            error: null,
            warning: UNEXPECTED_RESPONSE_FORMAT_ERROR,
            partial: true,
            stale: false,
          };
        }

        const pageData = result.data;
        const currentPage = result.pagination?.page || page;
        const pageTotal = result.pagination?.pageTotal || currentPage;
        const actualPageSize = result.pagination?.pageSize || WORKSPACE_REPOSITORY_PAGE_SIZE;

        knownPageTotal = pageTotal;
        repositories.push(...pageData);

        if (pageData.length < actualPageSize || currentPage >= pageTotal) {
          break;
        }

        page += 1;
      }

      return {
        repositories: sortRepositories(repositories),
        error: null,
        warning: null,
        partial: false,
        stale: false,
      };
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
    && typeof repository.name === "string"
    && repository.name.length > 0
  ));
}

module.exports = {
  UNEXPECTED_RESPONSE_FORMAT_ERROR,
  STALE_ACCOUNT_ERROR,
  WORKSPACE_REPOSITORY_PAGE_SIZE,
  fetchWorkspaceRepositories,
};

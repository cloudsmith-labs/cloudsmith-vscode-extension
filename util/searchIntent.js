// Copyright 2026 Cloudsmith Ltd. All rights reserved.

function searchDescriptorFromRecent(entry) {
  const scope = entry && entry.scope;
  if (!scope || typeof scope !== "object" || Array.isArray(scope)) return null;
  const scopeKeys = Object.keys(scope).sort().join(",");
  if (
    scope.kind === "repository"
    && scopeKeys === "kind,repository"
    && typeof scope.repository === "string"
  ) {
    return {
      kind: "repository",
      workspace: entry.workspace,
      repository: scope.repository,
      query: entry.query,
      page: 1,
    };
  }
  if (
    scope.kind === "repositories"
    && scopeKeys === "kind,repositories"
    && Array.isArray(scope.repositories)
  ) {
    return {
      kind: "repositories",
      workspace: entry.workspace,
      repositories: scope.repositories,
      query: entry.query,
      page: 1,
    };
  }
  return scope.kind === "workspace" && scopeKeys === "kind"
    ? { kind: "workspace", workspace: entry.workspace, query: entry.query, page: 1 }
    : null;
}

async function executeSearchIntent(searchProvider, descriptor, options = {}) {
  const operation = searchProvider.beginSearch(descriptor);
  const execution = searchProvider.executeSearch(operation);
  if (options.recentSearches && options.record) {
    const ownedDescriptor = operation.descriptor;
    let scope = { kind: "workspace" };
    if (ownedDescriptor.kind === "repository") {
      scope = { kind: "repository", repository: ownedDescriptor.repository };
    } else if (ownedDescriptor.kind === "repositories") {
      scope = { kind: "repositories", repositories: ownedDescriptor.repositories };
    }
    Promise.resolve().then(() => {
      if (options.isCurrent && !options.isCurrent()) return undefined;
      return options.recentSearches.add({
        workspace: ownedDescriptor.workspace,
        query: ownedDescriptor.query,
        scope,
      });
    }).catch(() => {
      console.warn("[Cloudsmith] Could not save the recent search.");
    });
  }
  return execution;
}

module.exports = { executeSearchIntent, searchDescriptorFromRecent };

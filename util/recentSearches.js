// Copyright 2026 Cloudsmith Ltd. All rights reserved.
// Versioned, bounded recent-search persistence.
// Searches are non-secret, but only the fields required to replay them are stored.

const { isValidAdvancedQuery } = require("./searchQueryBuilder");

const STORAGE_KEY_PREFIX = "cloudsmith-recentSearches:v2";
const STORAGE_VERSION = 2;
const DEFAULT_MAX = 10;
const HARD_MAX = 50;
const MAX_WORKSPACE_LENGTH = 200;
const MAX_QUERY_LENGTH = 2048;
const MAX_REPOSITORIES = 100;

// Multiple command handlers can construct RecentSearches for the same workspace.
// Serialize by the actual Memento object and storage key so those instances cannot
// read/modify/write over one another.
const writeQueues = new WeakMap();

function queueFor(globalState, storageKey, operation) {
  let queues = writeQueues.get(globalState);
  if (!queues) {
    queues = new Map();
    writeQueues.set(globalState, queues);
  }

  const previous = queues.get(storageKey) || Promise.resolve();
  const current = previous.catch(() => undefined).then(operation);
  queues.set(storageKey, current);

  return current.finally(() => {
    if (queues.get(storageKey) === current) {
      queues.delete(storageKey);
    }
  });
}

function isBoundedString(value, maxLength) {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength;
}

function normalizeRepositories(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_REPOSITORIES) {
    return null;
  }

  const repositories = [];
  for (const repository of value) {
    if (
      !isBoundedString(repository, MAX_WORKSPACE_LENGTH)
      || repository !== repository.trim()
    ) {
      return null;
    }
    repositories.push(repository);
  }

  return [...new Set(repositories)].sort((left, right) => left.localeCompare(right));
}

function normalizeScope(scope) {
  if (scope && typeof scope === "object" && !Array.isArray(scope)) {
    const keys = Object.keys(scope).sort().join(",");
    if (scope.kind === "workspace" && keys === "kind") {
      return Object.freeze({ kind: "workspace" });
    }
    if (
      scope.kind === "repository"
      && keys === "kind,repository"
      && isBoundedString(scope.repository, MAX_WORKSPACE_LENGTH)
      && scope.repository === scope.repository.trim()
    ) {
      return Object.freeze({ kind: "repository", repository: scope.repository });
    }
    if (scope.kind === "repositories" && keys === "kind,repositories") {
      const repositories = normalizeRepositories(scope.repositories);
      return repositories
        ? Object.freeze({ kind: "repositories", repositories: Object.freeze(repositories) })
        : null;
    }
  }
  return null;
}

function normalizeEntry(entry, expectedWorkspace, now) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    return null;
  }

  const workspace = entry.workspace;
  const query = entry.query;
  const scope = normalizeScope(entry.scope);
  if (
    !isBoundedString(workspace, MAX_WORKSPACE_LENGTH)
    || workspace !== workspace.trim()
    || !isBoundedString(query, MAX_QUERY_LENGTH)
    || !isValidAdvancedQuery(query)
    || !scope
    || (expectedWorkspace && workspace !== expectedWorkspace)
  ) {
    return null;
  }

  const suppliedTimestamp = entry.timestamp;
  const timestamp = Number.isFinite(suppliedTimestamp) && suppliedTimestamp > 0
    ? suppliedTimestamp
    : now();

  return Object.freeze({ workspace, query, scope, timestamp });
}

function isStoredEntry(value, expectedWorkspace) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const keys = Object.keys(value).sort();
  if (keys.join(",") !== "query,scope,timestamp,workspace") {
    return false;
  }
  if (
    !isBoundedString(value.workspace, MAX_WORKSPACE_LENGTH)
    || value.workspace !== value.workspace.trim()
    || !isBoundedString(value.query, MAX_QUERY_LENGTH)
    || !isValidAdvancedQuery(value.query)
    || (expectedWorkspace && value.workspace !== expectedWorkspace)
    || !Number.isFinite(value.timestamp)
    || value.timestamp <= 0
  ) {
    return false;
  }

  const scope = value.scope;
  if (!scope || typeof scope !== "object" || Array.isArray(scope)) {
    return false;
  }
  if (scope.kind === "workspace") {
    return Object.keys(scope).length === 1;
  }
  if (scope.kind === "repository") {
    return Object.keys(scope).sort().join(",") === "kind,repository"
      && isBoundedString(scope.repository, MAX_WORKSPACE_LENGTH)
      && scope.repository === scope.repository.trim();
  }
  if (scope.kind !== "repositories" || Object.keys(scope).sort().join(",") !== "kind,repositories") {
    return false;
  }
  const normalized = normalizeRepositories(scope.repositories);
  return Boolean(
    normalized
    && normalized.length === scope.repositories.length
    && normalized.every((repository, index) => repository === scope.repositories[index])
  );
}

function cloneEntry(entry) {
  let scope;
  if (entry.scope.kind === "repositories") {
    scope = Object.freeze({
      kind: "repositories",
      repositories: Object.freeze([...entry.scope.repositories]),
    });
  } else if (entry.scope.kind === "repository") {
    scope = Object.freeze({ kind: "repository", repository: entry.scope.repository });
  } else {
    scope = Object.freeze({ kind: "workspace" });
  }
  return Object.freeze({
    workspace: entry.workspace,
    query: entry.query,
    scope,
    timestamp: entry.timestamp,
  });
}

function parseEnvelope(value, expectedWorkspace, max) {
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.keys(value).sort().join(",") !== "items,version"
    || value.version !== STORAGE_VERSION
    || !Array.isArray(value.items)
    || value.items.length > HARD_MAX
    || !value.items.every(item => isStoredEntry(item, expectedWorkspace))
  ) {
    return null;
  }

  return value.items.slice(0, max).map(cloneEntry);
}

function entryKey(entry) {
  const scopeIdentity = entry.scope.kind === "repositories"
    ? entry.scope.repositories
    : (entry.scope.kind === "repository" ? entry.scope.repository : null);
  return JSON.stringify([
    entry.workspace,
    entry.query,
    entry.scope.kind,
    scopeIdentity,
  ]);
}

class RecentSearches {
  constructor(context, workspaceSlug, options = {}) {
    this.context = context;
    this.workspaceSlug = workspaceSlug || "";
    this._now = options.now || Date.now;
    this.storageKey = this.workspaceSlug
      ? `${STORAGE_KEY_PREFIX}:${encodeURIComponent(this.workspaceSlug)}`
      : STORAGE_KEY_PREFIX;
  }

  async add(entry) {
    const normalized = normalizeEntry(entry, this.workspaceSlug, this._now);
    if (!normalized) {
      throw new TypeError("Recent search descriptor is invalid.");
    }

    return queueFor(this.context.globalState, this.storageKey, async () => {
      const max = this._getMax();
      if (max === 0) {
        await this.context.globalState.update(this.storageKey, {
          version: STORAGE_VERSION,
          items: [],
        });
        return;
      }

      const stored = this.context.globalState.get(this.storageKey);
      const searches = parseEnvelope(stored, this.workspaceSlug, max) || [];
      const key = entryKey(normalized);
      const items = [normalized, ...searches.filter(search => entryKey(search) !== key)]
        .sort((left, right) => right.timestamp - left.timestamp)
        .slice(0, max)
        .map(cloneEntry);

      await this.context.globalState.update(this.storageKey, {
        version: STORAGE_VERSION,
        items,
      });
    });
  }

  async getAll() {
    return queueFor(this.context.globalState, this.storageKey, async () => {
      const max = this._getMax();
      if (max === 0) {
        return [];
      }

      const stored = this.context.globalState.get(this.storageKey);
      if (stored === undefined) {
        return [];
      }
      const parsed = parseEnvelope(stored, this.workspaceSlug, max);
      if (parsed) {
        return parsed;
      }

      // Old and malformed shapes are never replayed with broader authority.
      try {
        await this.context.globalState.update(this.storageKey, undefined);
      } catch {
        // The invalid value is still ignored even when best-effort eviction fails.
      }
      return [];
    });
  }

  async clear() {
    return queueFor(this.context.globalState, this.storageKey, async () => {
      await this.context.globalState.update(this.storageKey, {
        version: STORAGE_VERSION,
        items: [],
      });
    });
  }

  _getMax() {
    const vscode = require("vscode");
    const config = vscode.workspace.getConfiguration("cloudsmith-vsc");
    const configured = config.get("recentSearches");
    if (!Number.isInteger(configured)) {
      return DEFAULT_MAX;
    }
    return Math.max(0, Math.min(HARD_MAX, configured));
  }
}

module.exports = {
  HARD_MAX,
  RecentSearches,
  STORAGE_KEY_PREFIX,
  STORAGE_VERSION,
};

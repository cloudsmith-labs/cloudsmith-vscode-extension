// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const DEFAULT_TTL_MS = 30 * 60 * 1000;

function normalizeWorkspace(workspace) {
  if (
    !workspace
    || typeof workspace !== "object"
    || Array.isArray(workspace)
    || typeof workspace.slug !== "string"
    || workspace.slug.length === 0
    || typeof workspace.name !== "string"
    || workspace.name.length === 0
  ) {
    return null;
  }
  return Object.freeze({ slug: workspace.slug, name: workspace.name });
}

class WorkspaceCache {
  constructor(connectionManager, options = {}) {
    this.connectionManager = connectionManager;
    this.ttlMs = Number.isFinite(options.ttlMs) && options.ttlMs >= 0
      ? options.ttlMs
      : DEFAULT_TTL_MS;
    this.now = options.now || Date.now;
    this._entry = null;
  }

  get() {
    const state = this.connectionManager && this.connectionManager.getState();
    if (
      !this._entry
      || !state
      || !state.sessionConnected
      || state.accountEpoch !== this._entry.accountEpoch
      || state.activationId !== this._entry.activationId
      || this.now() - this._entry.createdAt >= this.ttlMs
    ) {
      this._entry = null;
      return null;
    }
    return this._entry.workspaces.map(workspace => ({ ...workspace }));
  }

  set(workspaces, account) {
    const state = this.connectionManager && this.connectionManager.getState();
    if (
      !Array.isArray(workspaces)
      || !account
      || !state
      || !state.sessionConnected
      || state.accountEpoch !== account.accountEpoch
      || state.activationId !== account.activationId
    ) {
      return false;
    }

    const normalized = workspaces.map(normalizeWorkspace);
    if (normalized.some(workspace => !workspace)) {
      return false;
    }
    this._entry = Object.freeze({
      accountEpoch: account.accountEpoch,
      activationId: account.activationId,
      createdAt: this.now(),
      workspaces: Object.freeze(normalized),
    });
    return true;
  }

  clear() {
    this._entry = null;
  }
}

module.exports = { DEFAULT_TTL_MS, WorkspaceCache };

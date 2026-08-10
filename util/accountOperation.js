// Copyright 2026 Cloudsmith Ltd. All rights reserved.

function resolveConnectionManager(context, connectionManager = null) {
  if (connectionManager && typeof connectionManager.getState === "function") {
    return connectionManager;
  }

  if (!context) {
    return null;
  }

  // Load lazily so this helper does not participate in the authentication
  // module's construction graph.
  const { getConnectionManager } = require("./connectionManager");
  return typeof getConnectionManager === "function"
    ? getConnectionManager(context)
    : null;
}

function captureAccount(connectionManager) {
  if (!connectionManager || typeof connectionManager.getState !== "function") {
    return null;
  }
  const state = connectionManager.getState();
  if (
    !state
    || !state.sessionConnected
    || !Number.isInteger(state.accountEpoch)
    || typeof state.activationId !== "string"
    || state.activationId.length === 0
  ) {
    return null;
  }
  return Object.freeze({
    accountEpoch: state.accountEpoch,
    activationId: state.activationId,
  });
}

function isAccountCurrent(connectionManager, account) {
  if (!account || !connectionManager || typeof connectionManager.getState !== "function") {
    return false;
  }
  const state = connectionManager.getState();
  return Boolean(
    state
    && state.sessionConnected
    && state.accountEpoch === account.accountEpoch
    && state.activationId === account.activationId
  );
}

function captureAccountForContext(context, connectionManager = null) {
  const manager = resolveConnectionManager(context, connectionManager);
  const account = captureAccount(manager);
  return account ? Object.freeze({ manager, account }) : null;
}

module.exports = {
  captureAccount,
  captureAccountForContext,
  isAccountCurrent,
  resolveConnectionManager,
};

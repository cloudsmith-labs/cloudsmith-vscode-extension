// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { captureAccount, isAccountCurrent } = require("./accountOperation");

const provenance = new WeakMap();

function markSelection(value, connectionManager) {
  if (!value || typeof value !== "object") return value;
  const account = captureAccount(connectionManager);
  if (account) provenance.set(value, Object.freeze({ account, connectionManager }));
  return value;
}

function inheritSelection(value, owner) {
  if (!value || typeof value !== "object" || !owner || typeof owner !== "object") {
    return value;
  }
  const inherited = provenance.get(owner);
  if (inherited) provenance.set(value, inherited);
  return value;
}

function isSelectionCurrent(value) {
  if (!value || typeof value !== "object") return false;
  const entry = provenance.get(value);
  return Boolean(
    entry
    && isAccountCurrent(entry.connectionManager, entry.account)
  );
}

module.exports = { inheritSelection, isSelectionCurrent, markSelection };

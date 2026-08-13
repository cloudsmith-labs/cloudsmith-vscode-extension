// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const CONNECTION_PRESENTATIONS = Object.freeze({
  CONNECTING: "connecting",
  CONNECTED: "connected",
  ABSENT: "absent",
  FAILED: "failed",
  UNAVAILABLE: "unavailable",
  DISPOSED: "disposed",
});

/**
 * Derive customer-facing connection presentation from one authoritative state snapshot.
 * This projection never authorizes account-scoped work.
 */
function connectionPresentation(state) {
  if (!state || typeof state !== "object" || Array.isArray(state)) {
    return CONNECTION_PRESENTATIONS.UNAVAILABLE;
  }

  const status = state.status;
  if (status === "disposed") {
    return CONNECTION_PRESENTATIONS.DISPOSED;
  }

  const hasAuthorizedAccount = state.sessionConnected === true
    && typeof state.activationId === "string"
    && state.activationId.length > 0
    && Number.isSafeInteger(state.accountEpoch)
    && state.accountEpoch >= 0
    && state.credentialPresent !== false;
  if (hasAuthorizedAccount && (status === "connected" || status === "validating")) {
    return CONNECTION_PRESENTATIONS.CONNECTED;
  }

  if (state.sessionConnected === true) {
    return CONNECTION_PRESENTATIONS.UNAVAILABLE;
  }

  if (status === "validating") {
    return CONNECTION_PRESENTATIONS.CONNECTING;
  }
  if (status === "indeterminate") {
    return state.error
      ? CONNECTION_PRESENTATIONS.UNAVAILABLE
      : CONNECTION_PRESENTATIONS.CONNECTING;
  }
  if (status === "absent" && state.credentialPresent === false) {
    return CONNECTION_PRESENTATIONS.ABSENT;
  }
  if (status === "failed" && state.credentialPresent === true) {
    return CONNECTION_PRESENTATIONS.FAILED;
  }

  return CONNECTION_PRESENTATIONS.UNAVAILABLE;
}

function connectionSetupAvailable(state) {
  const presentation = connectionPresentation(state);
  return presentation === CONNECTION_PRESENTATIONS.ABSENT
    || presentation === CONNECTION_PRESENTATIONS.FAILED;
}

module.exports = {
  CONNECTION_PRESENTATIONS,
  connectionPresentation,
  connectionSetupAvailable,
};

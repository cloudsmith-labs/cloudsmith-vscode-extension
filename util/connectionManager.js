const crypto = require("crypto");
const vscode = require("vscode");

const AUTH_TOKEN_KEY = "cloudsmith-vsc.authToken";
const LEGACY_CONNECTION_KEY = "cloudsmith-vsc.isConnected";
const CONNECTION_CONTEXT_KEY = "cloudsmith.connected";
const MAX_CREDENTIAL_LENGTH = 4096;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;
const SAFE_PUBLIC_ERROR = Symbol("safe-public-error");

const CONNECTION_STATUSES = Object.freeze({
  ABSENT: "absent",
  VALIDATING: "validating",
  CONNECTED: "connected",
  FAILED: "failed",
  INDETERMINATE: "indeterminate",
  DISPOSED: "disposed",
});

const managerRegistry = new WeakMap();

function publicError(error, fallbackMessage) {
  if (!error) return null;
  if (error[SAFE_PUBLIC_ERROR]) return error;
  return createPublicError("unexpected", fallbackMessage);
}

function fixedPublicError(kind, message) {
  return createPublicError(kind, message);
}

function createPublicError(kind, message) {
  const error = { kind, message };
  Object.defineProperty(error, SAFE_PUBLIC_ERROR, { value: true });
  return Object.freeze(error);
}

function validationAPIError(error) {
  const messages = {
    unauthorized: "Authentication failed. Check the API key.",
    forbidden: "The API key does not have permission to access Cloudsmith.",
    rate_limited: "Cloudsmith rate limited the authentication check. Try again shortly.",
    server_error: "Cloudsmith could not complete the authentication check. Try again later.",
    network_error: "Could not reach Cloudsmith. Check the network connection.",
    timeout: "The Cloudsmith authentication check timed out.",
    cancelled: "Authentication was cancelled.",
    invalid_response: "Cloudsmith returned an unexpected authentication response.",
    redirect_rejected: "Cloudsmith returned an unsafe redirect, so authentication was stopped.",
    invalid_request: "The authentication request could not be constructed safely.",
  };
  const kind = error && Object.prototype.hasOwnProperty.call(messages, error.kind)
    ? error.kind
    : "api_error";
  return fixedPublicError(kind, messages[kind] || "Could not validate the API key.");
}

function normalizeCandidate(candidate) {
  if (typeof candidate !== "string") {
    return Object.freeze({ ok: false, reason: "API key must be text." });
  }
  const value = candidate.trim();
  if (!value) {
    return Object.freeze({ ok: false, reason: "API key cannot be empty." });
  }
  if (value.length > MAX_CREDENTIAL_LENGTH) {
    return Object.freeze({ ok: false, reason: "API key is too long." });
  }
  if (CONTROL_CHARACTER_PATTERN.test(value)) {
    return Object.freeze({ ok: false, reason: "API key contains invalid characters." });
  }
  return Object.freeze({ ok: true, value });
}

function fingerprint(value) {
  if (typeof value !== "string" || !value) return null;
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function freezeState(state) {
  return Object.freeze({
    activationId: state.activationId,
    status: state.status,
    operationId: state.operationId,
    accountEpoch: state.accountEpoch,
    credentialPresent: state.credentialPresent,
    sessionConnected: Boolean(state.sessionConnected),
    error: state.error || null,
  });
}

function bindConnectionManager(context, manager, activationId = manager && manager.activationId) {
  if (!context || !manager || activationId !== manager.activationId) {
    throw new TypeError("A matching activation-owned ConnectionManager is required.");
  }
  const existing = managerRegistry.get(context);
  if (existing && existing.manager !== manager) {
    existing.manager.dispose();
  }
  const entry = Object.freeze({ manager, activationId });
  managerRegistry.set(context, entry);
  return Object.freeze({
    dispose() {
      const current = managerRegistry.get(context);
      if (current === entry) managerRegistry.delete(context);
    },
  });
}

function unbindConnectionManager(context, manager) {
  const entry = managerRegistry.get(context);
  if (entry && (!manager || entry.manager === manager)) {
    managerRegistry.delete(context);
    return true;
  }
  return false;
}

function getConnectionManager(context, activationId) {
  const entry = context && managerRegistry.get(context);
  if (!entry || (activationId && entry.activationId !== activationId)) return null;
  if (entry.manager.getState().status === CONNECTION_STATUSES.DISPOSED) return null;
  return entry.manager;
}

function getConnectionState(context, activationId) {
  const manager = getConnectionManager(context, activationId);
  return manager ? manager.getState() : null;
}

function getAccountEpoch(context, activationId) {
  const state = getConnectionState(context, activationId);
  return state && state.status !== CONNECTION_STATUSES.INDETERMINATE
    ? state.accountEpoch
    : null;
}

class ConnectionManager {
  constructor(context, options = {}) {
    if (!context || !context.secrets) {
      throw new TypeError("Extension context with SecretStorage is required.");
    }
    this.context = context;
    this.activationId = options.activationId || crypto.randomUUID();
    this._createCloudsmithAPI = options.createCloudsmithAPI || ((apiContext) => {
      const { CloudsmithAPI } = require("./cloudsmithAPI");
      return new CloudsmithAPI(apiContext);
    });
    this._executeCommand = options.executeCommand || vscode.commands.executeCommand;
    this._stateEmitter = new vscode.EventEmitter();
    this.onDidChange = this._stateEmitter.event;
    this._state = freezeState({
      activationId: this.activationId,
      status: CONNECTION_STATUSES.INDETERMINATE,
      operationId: 0,
      accountEpoch: 0,
      credentialPresent: null,
      sessionConnected: false,
      error: null,
    });
    this._stableState = this._state;
    this._knownFingerprint = undefined;
    this._operationCounter = 0;
    this._currentOperation = null;
    this._operationPublicationSequence = new WeakMap();
    this._mutationQueue = Promise.resolve();
    this._projectionQueue = Promise.resolve();
    this._secretEventSequence = 0;
    this._secretEventChain = Promise.resolve();
    this._expectedSecretIntent = null;
    this._disposed = false;

    const onDidChange = context.secrets.onDidChange;
    this._secretListener = typeof onDidChange === "function"
      ? onDidChange.call(context.secrets, event => this._onSecretChange(event))
      : null;
  }

  getState() {
    return this._state;
  }

  isOperationCurrent(token) {
    return !this._disposed && token === this._currentOperation && !token.signal.aborted;
  }

  _canPublishOperation(token) {
    return this.isOperationCurrent(token)
      && this._operationPublicationSequence.get(token) === this._secretEventSequence;
  }

  beginCredentialOperation() {
    return this._beginOperation(true);
  }

  async cancelCredentialOperation(token) {
    if (!this.isOperationCurrent(token)) {
      return Object.freeze({ ok: false, status: "stale", state: this._state });
    }
    token.controller.abort();
    this._currentOperation = null;
    this._setState({
      ...this._stableState,
      operationId: token.id,
      accountEpoch: this._state.accountEpoch,
    });
    const projectionError = await this._projectConnection(this._state.sessionConnected);
    return Object.freeze({
      ok: false,
      status: "cancelled",
      partial: Boolean(projectionError),
      projectionError,
      state: this._state,
    });
  }

  async initialize() {
    const token = this._beginOperation(true);
    await this._deleteLegacyStatus();
    let stored;
    let readError = null;
    try {
      stored = await this.context.secrets.get(AUTH_TOKEN_KEY);
    } catch (error) {
      readError = error;
    }
    await this._awaitSecretEventBarrier();
    if (!this._canPublishOperation(token)) return this._staleResult();
    if (readError) {
      return this._finishIndeterminate(token, readError, "Could not read stored credentials.");
    }
    return this._acceptStoredSnapshot(stored, token, { source: "startup" });
  }

  async replaceCredential(candidate, token = null) {
    const operation = token || this._beginOperation(true);
    if (!this.isOperationCurrent(operation)) return this._staleResult();

    const normalized = normalizeCandidate(candidate);
    if (!normalized.ok) {
      return this._finishReplacementFailure(
        operation,
        fixedPublicError("invalid_candidate", normalized.reason)
      );
    }

    const validation = await this._validateCandidate(normalized.value, operation.signal);
    await this._awaitSecretEventBarrier();
    if (!this._canPublishOperation(operation)) return this._staleResult();
    if (!validation.ok) {
      return this._finishReplacementFailure(operation, validation.error);
    }

    return this._enqueueMutation(() => this._commitCandidate(normalized.value, operation));
  }

  async disconnect(token = null) {
    const operation = token || this._beginOperation(true);
    if (!this.isOperationCurrent(operation)) return this._staleResult();
    return this._enqueueMutation(() => this._commitDelete(operation));
  }

  async checkConnectivity(apiKey) {
    const normalized = normalizeCandidate(apiKey);
    if (!normalized.ok) {
      return "false";
    }
    const validation = await this._validateCandidate(normalized.value);
    if (validation.ok) return "true";
    return validation.error && validation.error.kind === "unauthorized" ? "false" : "error";
  }

  async isConnected() {
    return this._state.sessionConnected ? "true" : "false";
  }

  async connect(options = {}) {
    const { promptOnMissingCredentials = true } = options;
    const result = await this.initialize();
    if (result.ok) {
      if (result.status === CONNECTION_STATUSES.CONNECTED) {
        vscode.window.showInformationMessage("Connected to Cloudsmith.");
        return "true";
      }
      if (promptOnMissingCredentials) {
        const selection = await vscode.window.showWarningMessage(
          "No credentials configured!",
          "Configure",
          "Cancel"
        );
        if (selection === "Configure") {
          await vscode.commands.executeCommand("cloudsmith-vsc.configureCredentials");
        }
      }
      return "false";
    }
    if (result.status === "stale") return this._state.sessionConnected ? "true" : "false";
    const errorMessage = result.error
      ? result.error.message
      : "Could not connect to Cloudsmith. Check the credentials and try again.";
    const selection = await vscode.window.showErrorMessage(errorMessage, "Configure", "Cancel");
    if (selection === "Configure") {
      await vscode.commands.executeCommand("cloudsmith-vsc.configureCredentials");
    }
    return result.status === CONNECTION_STATUSES.FAILED ? "false" : "error";
  }

  dispose() {
    if (this._disposed) return;
    this._disposed = true;
    if (this._currentOperation) this._currentOperation.controller.abort();
    this._currentOperation = null;
    if (this._secretListener && typeof this._secretListener.dispose === "function") {
      this._secretListener.dispose();
    }
    unbindConnectionManager(this.context, this);
    this._setState({
      ...this._state,
      status: CONNECTION_STATUSES.DISPOSED,
      sessionConnected: false,
      error: null,
    });
    this._stateEmitter.dispose();
  }

  _beginOperation(publish) {
    if (this._disposed) {
      const controller = new AbortController();
      controller.abort();
      return Object.freeze({ id: ++this._operationCounter, controller, signal: controller.signal });
    }
    if (this._currentOperation) this._currentOperation.controller.abort();
    const controller = new AbortController();
    const token = Object.freeze({
      id: ++this._operationCounter,
      controller,
      signal: controller.signal,
    });
    this._currentOperation = token;
    this._operationPublicationSequence.set(token, this._secretEventSequence);
    if (publish) {
      this._setState({
        status: CONNECTION_STATUSES.VALIDATING,
        operationId: token.id,
        accountEpoch: this._state.accountEpoch,
        credentialPresent: this._stableState.credentialPresent,
        sessionConnected: this._stableState.sessionConnected,
        error: null,
      });
    }
    return token;
  }

  async _validateCandidate(apiKey, signal) {
    if (signal && signal.aborted) {
      return Object.freeze({ ok: false, error: fixedPublicError("cancelled", "Authentication was cancelled.") });
    }
    try {
      const api = this._createCloudsmithAPI(this.context);
      const result = await api.get("user/self", {
        apiKey,
        signal,
        responseType: "object",
        validate: value => Boolean(value) && typeof value.authenticated === "boolean",
        retry: "never",
      });
      if (signal && signal.aborted) {
        return Object.freeze({ ok: false, error: fixedPublicError("cancelled", "Authentication was cancelled.") });
      }
      if (result && result.ok && result.data.authenticated) {
        return Object.freeze({ ok: true });
      }
      const error = result && !result.ok
        ? validationAPIError(result.error)
        : fixedPublicError("unauthorized", "The API key was not accepted by Cloudsmith.");
      return Object.freeze({ ok: false, error });
    } catch (error) {
      return Object.freeze({
        ok: false,
        error: publicError(error, "Could not validate the API key."),
      });
    }
  }

  async _commitCandidate(candidate, operation) {
    await this._awaitSecretEventBarrier();
    if (!this._canPublishOperation(operation)) return this._staleResult();
    const candidateFingerprint = fingerprint(candidate);
    const intent = this._createSecretIntent("store", candidateFingerprint, operation);
    this._expectedSecretIntent = intent;
    const expectedSelfEvent = this._expectSelfEvent(intent, candidateFingerprint);

    let writeError = null;
    try {
      await this.context.secrets.store(AUTH_TOKEN_KEY, candidate);
    } catch (error) {
      writeError = error;
    }
    await this._awaitSecretEventBarrier();
    this._closeSelfEventExpectation(intent, expectedSelfEvent);
    if (intent.highestExternal) {
      return this._restoreCapturedExternal(intent, writeError);
    }

    let finalRead;
    for (let attempt = 0; attempt < 8; attempt += 1) {
      finalRead = await this._readFinalAuthoritativeSnapshot(intent, operation);
      if (!finalRead.ok || finalRead.sequence === this._secretEventSequence) break;
    }
    if (finalRead.external) {
      return this._restoreCapturedExternal(intent, writeError);
    }
    if (!finalRead.ok) {
      const readError = finalRead.error;
      if (!this.isOperationCurrent(operation)) {
        this._recordIndeterminateBaseline(operation, writeError || readError);
        return this._staleResult();
      }
      return this._finishIndeterminate(
        operation,
        writeError || readError,
        "Credential storage outcome could not be determined.",
        true
      );
    }
    if (finalRead.sequence !== this._secretEventSequence) {
      return this._finishIndeterminate(
        operation,
        { kind: "unstable_secret_state", message: "Credentials changed during final verification." },
        "Credentials changed during final verification.",
        true
      );
    }
    const stored = finalRead.value;
    const operationOwned = finalRead.operationOwned && this._canPublishOperation(operation);
    const storedFingerprint = fingerprint(stored);
    if (storedFingerprint === candidateFingerprint) {
      intent.active = false;
      if (!operationOwned && !this._currentOperation) {
        await this._reconcileAfterLostOwnership(stored);
        return this._staleResult();
      }
      this._adoptFingerprint(storedFingerprint);
      const state = this._makeStableState(CONNECTION_STATUSES.CONNECTED, operation.id, true, true, null);
      this._stableState = state;
      if (!operationOwned) return this._staleResult();
      this._setState(state);
      this._currentOperation = null;
      const projectionError = await this._projectConnection(true);
      return Object.freeze({
        ok: true,
        status: CONNECTION_STATUSES.CONNECTED,
        committed: true,
        partial: Boolean(projectionError),
        error: projectionError,
        state: this._state,
      });
    }

    if (!operationOwned) return this._staleResult();

    if (writeError && storedFingerprint === this._knownFingerprint) {
      return this._finishReplacementFailure(operation, publicError(writeError, "Could not save credentials."));
    }

    this._expectedSecretIntent = null;
    return this._supersedeWithSnapshot(stored, operation, writeError);
  }

  async _commitDelete(operation) {
    await this._awaitSecretEventBarrier();
    if (!this._canPublishOperation(operation)) return this._staleResult();
    const intent = this._createSecretIntent("delete", null, operation);
    this._expectedSecretIntent = intent;
    const expectedSelfEvent = this._expectSelfEvent(intent, null);

    let writeError = null;
    try {
      await this.context.secrets.delete(AUTH_TOKEN_KEY);
    } catch (error) {
      writeError = error;
    }
    await this._awaitSecretEventBarrier();
    this._closeSelfEventExpectation(intent, expectedSelfEvent);
    if (intent.highestExternal) {
      await this._deleteLegacyStatus();
      return this._restoreCapturedExternal(intent, writeError);
    }
    await this._deleteLegacyStatus();

    let finalRead;
    for (let attempt = 0; attempt < 8; attempt += 1) {
      finalRead = await this._readFinalAuthoritativeSnapshot(intent, operation);
      if (!finalRead.ok || finalRead.sequence === this._secretEventSequence) break;
    }
    if (finalRead.external) {
      return this._restoreCapturedExternal(intent, writeError);
    }
    if (!finalRead.ok) {
      const readError = finalRead.error;
      if (!this.isOperationCurrent(operation)) {
        this._recordIndeterminateBaseline(operation, writeError || readError);
        return this._staleResult();
      }
      return this._finishIndeterminate(
        operation,
        writeError || readError,
        "Credential deletion outcome could not be determined.",
        true
      );
    }
    if (finalRead.sequence !== this._secretEventSequence) {
      return this._finishIndeterminate(
        operation,
        { kind: "unstable_secret_state", message: "Credentials changed during final verification." },
        "Credentials changed during final verification.",
        true
      );
    }
    const stored = finalRead.value;
    const operationOwned = finalRead.operationOwned && this._canPublishOperation(operation);
    if (typeof stored !== "string" || !stored) {
      intent.active = false;
      if (!operationOwned && !this._currentOperation) {
        await this._reconcileAfterLostOwnership(stored);
        return this._staleResult();
      }
      this._adoptFingerprint(null);
      const state = this._makeStableState(CONNECTION_STATUSES.ABSENT, operation.id, false, false, null);
      this._stableState = state;
      if (!operationOwned) return this._staleResult();
      this._setState(state);
      this._currentOperation = null;
      const projectionError = await this._projectConnection(false);
      return Object.freeze({
        ok: true,
        status: CONNECTION_STATUSES.ABSENT,
        committed: true,
        partial: Boolean(projectionError),
        error: projectionError,
        state: this._state,
      });
    }

    if (!operationOwned) return this._staleResult();

    if (writeError && fingerprint(stored) === this._knownFingerprint) {
      return this._finishReplacementFailure(operation, publicError(writeError, "Could not delete credentials."));
    }
    this._expectedSecretIntent = null;
    return this._supersedeWithSnapshot(stored, operation, writeError);
  }

  async _acceptStoredSnapshot(stored, operation, options = {}) {
    if (!this.isOperationCurrent(operation)) return this._staleResult();
    if (typeof stored !== "string" || !stored) {
      this._adoptFingerprint(null);
      const state = this._makeStableState(CONNECTION_STATUSES.ABSENT, operation.id, false, false, null);
      this._stableState = state;
      this._setState(state);
      this._currentOperation = null;
      const projectionError = await this._projectConnection(false);
      return Object.freeze({
        ok: true,
        status: CONNECTION_STATUSES.ABSENT,
        committed: false,
        partial: Boolean(projectionError),
        error: projectionError,
        state: this._state,
      });
    }

    const normalized = normalizeCandidate(stored);
    if (!normalized.ok || normalized.value !== stored) {
      this._adoptFingerprint(fingerprint(stored));
      const error = fixedPublicError(
        "invalid_candidate",
        normalized.ok ? "Stored credentials are not normalized." : normalized.reason
      );
      const state = this._makeStableState(CONNECTION_STATUSES.FAILED, operation.id, true, false, error);
      this._stableState = state;
      this._setState(state);
      this._currentOperation = null;
      const projectionError = await this._projectConnection(false);
      return Object.freeze({
        ok: false,
        status: CONNECTION_STATUSES.FAILED,
        committed: false,
        partial: Boolean(projectionError),
        error,
        projectionError,
        state: this._state,
        source: options.source || "external",
      });
    }

    const snapshotFingerprint = fingerprint(normalized.value);
    const identityChanged = this._knownFingerprint !== snapshotFingerprint;
    this._adoptFingerprint(snapshotFingerprint);
    if (identityChanged) {
      this._stableState = this._makeStableState(
        CONNECTION_STATUSES.FAILED,
        operation.id,
        true,
        false,
        null
      );
      this._setState({ ...this._state, sessionConnected: false, credentialPresent: true });
    }

    const validation = await this._validateCandidate(normalized.value, operation.signal);
    if (!this._canPublishOperation(operation)) return this._staleResult();
    if (!validation.ok) {
      const error = validation.error;
      const state = this._makeStableState(CONNECTION_STATUSES.FAILED, operation.id, true, false, error);
      this._stableState = state;
      this._setState(state);
      this._currentOperation = null;
      const projectionError = await this._projectConnection(false);
      return Object.freeze({
        ok: false,
        status: CONNECTION_STATUSES.FAILED,
        committed: false,
        partial: Boolean(projectionError),
        error,
        projectionError,
        state: this._state,
        source: options.source || "external",
      });
    }

    const state = this._makeStableState(CONNECTION_STATUSES.CONNECTED, operation.id, true, true, null);
    this._stableState = state;
    this._setState(state);
    this._currentOperation = null;
    const projectionError = await this._projectConnection(true);
    return Object.freeze({
      ok: true,
      status: CONNECTION_STATUSES.CONNECTED,
      committed: false,
      partial: Boolean(projectionError),
      error: projectionError,
      state: this._state,
      source: options.source || "external",
    });
  }

  async _supersedeWithSnapshot(stored, operation, writeError) {
    if (this.isOperationCurrent(operation)) operation.controller.abort();
    const token = this._beginOperation(true);
    const result = await this._acceptStoredSnapshot(stored, token, { source: "external" });
    return Object.freeze({
      ok: false,
      status: "superseded",
      committed: false,
      error: writeError
        ? publicError(writeError, "Credential persistence did not complete as requested.")
        : fixedPublicError(
          "persistence_mismatch",
          "Credential persistence did not complete as requested. The current credentials were reloaded."
        ),
      state: result.state || this._state,
    });
  }

  async _finishReplacementFailure(operation, error) {
    if (!this.isOperationCurrent(operation)) return this._staleResult();
    this._expectedSecretIntent = null;
    const safeError = publicError(error, "Could not validate credentials.");
    const restored = freezeState({
      ...this._stableState,
      operationId: operation.id,
      accountEpoch: this._state.accountEpoch,
      error: safeError,
    });
    this._stableState = restored;
    this._setState(restored);
    this._currentOperation = null;
    const projectionError = await this._projectConnection(restored.sessionConnected);
    return Object.freeze({
      ok: false,
      status: CONNECTION_STATUSES.FAILED,
      committed: false,
      preserved: restored.sessionConnected,
      partial: Boolean(projectionError),
      error: safeError,
      projectionError,
      state: this._state,
    });
  }

  async _finishIndeterminate(operation, error, fallbackMessage, advanceEpoch = false) {
    if (!this.isOperationCurrent(operation)) return this._staleResult();
    const intent = this._expectedSecretIntent;
    const observedAuthoritative = Boolean(
      intent
      && intent.observed
      && intent.observedFingerprint === this._knownFingerprint
    );
    if (advanceEpoch && !observedAuthoritative) {
      this._advanceIndeterminateEpoch();
    }
    const safeError = publicError(error, fallbackMessage);
    const state = freezeState({
      status: CONNECTION_STATUSES.INDETERMINATE,
      operationId: operation.id,
      accountEpoch: this._state.accountEpoch,
      credentialPresent: null,
      sessionConnected: false,
      error: safeError,
    });
    this._stableState = state;
    this._setState(state);
    this._currentOperation = null;
    const projectionError = await this._projectConnection(false);
    return Object.freeze({
      ok: false,
      status: CONNECTION_STATUSES.INDETERMINATE,
      committed: false,
      error: safeError,
      projectionError,
      state: this._state,
    });
  }

  _advanceIndeterminateEpoch() {
    this._knownFingerprint = undefined;
    this._setState({ ...this._state, accountEpoch: this._state.accountEpoch + 1 });
  }

  _recordIndeterminateBaseline(operation, error) {
    if (!(this._expectedSecretIntent && this._expectedSecretIntent.observed)) {
      this._advanceIndeterminateEpoch();
    }
    const safeError = publicError(error, "Credential storage outcome could not be determined.");
    this._stableState = freezeState({
      status: CONNECTION_STATUSES.INDETERMINATE,
      operationId: operation.id,
      accountEpoch: this._state.accountEpoch,
      credentialPresent: null,
      sessionConnected: false,
      error: safeError,
    });
    this._setState({
      ...this._state,
      accountEpoch: this._stableState.accountEpoch,
      credentialPresent: null,
      sessionConnected: false,
    });
    this._projectConnection(false);
  }

  _adoptFingerprint(nextFingerprint) {
    if (this._knownFingerprint !== nextFingerprint) {
      this._knownFingerprint = nextFingerprint;
      this._setState({ ...this._state, accountEpoch: this._state.accountEpoch + 1 });
      return true;
    }
    return false;
  }

  _makeStableState(status, operationId, credentialPresent, sessionConnected, error) {
    return freezeState({
      status,
      operationId,
      accountEpoch: this._state.accountEpoch,
      credentialPresent,
      sessionConnected,
      error: publicError(error, "Authentication failed."),
    });
  }

  _setState(next) {
    this._state = freezeState({ ...next, activationId: this.activationId });
    if (!this._disposed || this._state.status === CONNECTION_STATUSES.DISPOSED) {
      this._stateEmitter.fire(this._state);
    }
  }

  _enqueueMutation(task) {
    const run = this._mutationQueue.then(task, task);
    this._mutationQueue = run.then(() => undefined, () => undefined);
    return run;
  }

  async _awaitSecretEventBarrier() {
    while (true) {
      const chain = this._secretEventChain;
      await chain;
      if (chain === this._secretEventChain) return this._secretEventSequence;
    }
  }

  async _readFinalAuthoritativeSnapshot(intent, operation) {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const sequenceBeforeRead = this._secretEventSequence;
      let value;
      let error = null;
      try {
        value = await this.context.secrets.get(AUTH_TOKEN_KEY);
      } catch (readError) {
        error = readError;
      }

      const sequenceAfterBarrier = await this._awaitSecretEventBarrier();
      if (intent.highestExternal) {
        return Object.freeze({ ok: false, external: true });
      }
      if (sequenceAfterBarrier !== sequenceBeforeRead) continue;

      const operationOwned = this._canPublishOperation(operation)
        && this._operationCounter === operation.id;
      if (error) {
        return Object.freeze({ ok: false, external: false, error, operationOwned });
      }
      return Object.freeze({
        ok: true,
        external: false,
        value,
        operationOwned,
        sequence: sequenceAfterBarrier,
      });
    }

    return Object.freeze({
      ok: false,
      external: false,
      operationOwned: false,
      error: Object.freeze({
        kind: "unstable_secret_state",
        message: "Credentials kept changing while their final state was being verified.",
      }),
    });
  }

  async _reconcileAfterLostOwnership(stored) {
    if (this._currentOperation || this._disposed) return;
    const operation = this._beginOperation(true);
    await this._acceptStoredSnapshot(stored, operation, { source: "reconcile" });
  }

  _onSecretChange(event) {
    if (this._disposed || !event || event.key !== AUTH_TOKEN_KEY) return;
    const sequence = ++this._secretEventSequence;
    let snapshotPromise;
    try {
      // Invoke get() at notification time. Serializing the invocation itself would
      // allow a later write to erase the value associated with this event.
      snapshotPromise = Promise.resolve(this.context.secrets.get(AUTH_TOKEN_KEY));
    } catch (error) {
      snapshotPromise = Promise.reject(error);
    }
    const record = Object.freeze({ sequence, snapshotPromise });
    const handle = () => this._classifySecretEvent(record);
    this._secretEventChain = this._secretEventChain.then(handle, handle);
  }

  async _classifySecretEvent(record) {
    let stored;
    try {
      stored = await record.snapshotPromise;
    } catch (error) {
      if (this._disposed) return;
      const intent = this._expectedSecretIntent;
      if (intent && intent.active && record.sequence > intent.afterSequence) {
        this._captureExternalSnapshot(intent, {
          sequence: record.sequence,
          readable: false,
          error,
          value: null,
          fingerprint: undefined,
        });
        return;
      }
      const token = this._beginOperation(true);
      await this._finishIndeterminate(token, error, "Could not read changed credentials.", true);
      return;
    }
    if (this._disposed) return;

    const observedFingerprint = fingerprint(stored);
    const intent = this._expectedSecretIntent;
    const expectedSelfEvent = intent && intent.expectedSelfEvents.find(expected => (
      expected.active
      && !expected.consumed
      && expected.fingerprint === observedFingerprint
      && record.sequence > expected.afterSequence
      && record.sequence <= expected.throughSequence
    ));
    if (expectedSelfEvent) {
      expectedSelfEvent.active = false;
      expectedSelfEvent.consumed = true;
      intent.expectedSelfEvents = intent.expectedSelfEvents.filter(expected => expected.active);
      intent.observed = true;
      intent.observedFingerprint = observedFingerprint;
      if (this._currentOperation) {
        this._operationPublicationSequence.set(this._currentOperation, record.sequence);
      }
      this._adoptFingerprint(observedFingerprint);
      if (!intent.active && this._state.status === CONNECTION_STATUSES.INDETERMINATE) {
        this._expectedSecretIntent = null;
        const token = this._beginOperation(true);
        await this._acceptStoredSnapshot(stored, token, { source: "external" });
      }
      return;
    }

    if (intent && intent.active && record.sequence > intent.afterSequence) {
      this._captureExternalSnapshot(intent, {
        sequence: record.sequence,
        readable: true,
        error: null,
        value: stored,
        fingerprint: observedFingerprint,
      });
      return;
    }

    if (observedFingerprint === this._knownFingerprint) {
      if (this._currentOperation) {
        this._operationPublicationSequence.set(this._currentOperation, record.sequence);
      }
      return;
    }

    this._expectedSecretIntent = null;
    const token = this._beginOperation(true);
    await this._acceptStoredSnapshot(stored, token, { source: "external" });
  }

  _createSecretIntent(kind, expectedFingerprint, operation) {
    return {
      kind,
      fingerprint: expectedFingerprint,
      operation,
      afterSequence: this._secretEventSequence,
      observed: false,
      observedFingerprint: undefined,
      active: true,
      expectedSelfEvents: [],
      highestExternal: null,
      externalOperation: null,
    };
  }

  _expectSelfEvent(intent, expectedFingerprint) {
    const expected = {
      fingerprint: expectedFingerprint,
      afterSequence: this._secretEventSequence,
      throughSequence: Number.POSITIVE_INFINITY,
      active: true,
      consumed: false,
    };
    intent.expectedSelfEvents.push(expected);
    return expected;
  }

  _closeSelfEventExpectation(intent, expected) {
    if (!expected || expected.consumed) return;
    expected.throughSequence = this._secretEventSequence;
    expected.active = false;
    intent.expectedSelfEvents = intent.expectedSelfEvents.filter(item => item.active);
  }

  _captureExternalSnapshot(intent, snapshot) {
    if (intent.highestExternal && intent.highestExternal.sequence >= snapshot.sequence) return;
    intent.highestExternal = snapshot;
    const externalOperation = this._beginOperation(true);
    intent.externalOperation = externalOperation;

    if (!snapshot.readable) {
      this._advanceIndeterminateEpoch();
      const state = freezeState({
        status: CONNECTION_STATUSES.INDETERMINATE,
        operationId: externalOperation.id,
        accountEpoch: this._state.accountEpoch,
        credentialPresent: null,
        sessionConnected: false,
        error: publicError(snapshot.error, "Could not read changed credentials."),
      });
      this._stableState = state;
      this._setState(state);
      return;
    }

    this._adoptFingerprint(snapshot.fingerprint);
    const credentialPresent = typeof snapshot.value === "string" && snapshot.value.length > 0;
    this._stableState = this._makeStableState(
      credentialPresent ? CONNECTION_STATUSES.FAILED : CONNECTION_STATUSES.ABSENT,
      externalOperation.id,
      credentialPresent,
      false,
      null
    );
    this._setState({
      status: CONNECTION_STATUSES.VALIDATING,
      operationId: externalOperation.id,
      accountEpoch: this._state.accountEpoch,
      credentialPresent,
      sessionConnected: false,
      error: null,
    });
    this._projectConnection(false);
  }

  async _restoreCapturedExternal(intent, writeError) {
    restoreLoop:
    while (intent.highestExternal) {
      await this._awaitSecretEventBarrier();
      const target = intent.highestExternal;
      if (!target.readable) {
        const operation = intent.externalOperation;
        if (operation && this.isOperationCurrent(operation)) {
          await this._finishIndeterminate(
            operation,
            target.error || writeError,
            "Credential storage outcome could not be determined."
          );
        }
        const result = Object.freeze({
          ok: false,
          status: CONNECTION_STATUSES.INDETERMINATE,
          committed: false,
          error: publicError(target.error || writeError, "Credential storage outcome could not be determined."),
          state: this._state,
        });
        this._retireSecretIntent(intent);
        return result;
      }

      const expectedSelfEvent = this._expectSelfEvent(intent, target.fingerprint);
      let restoreError = null;
      try {
        if (target.fingerprint === null) {
          await this.context.secrets.delete(AUTH_TOKEN_KEY);
        } else {
          await this.context.secrets.store(AUTH_TOKEN_KEY, target.value);
        }
      } catch (error) {
        restoreError = error;
      }
      await this._awaitSecretEventBarrier();
      this._closeSelfEventExpectation(intent, expectedSelfEvent);
      if (intent.highestExternal.sequence > target.sequence) continue;

      let authoritative;
      let authoritativeSequence = null;
      let authoritativeStable = false;
      for (let attempt = 0; attempt < 8; attempt += 1) {
        const sequenceBeforeRead = this._secretEventSequence;
        try {
          authoritative = await this.context.secrets.get(AUTH_TOKEN_KEY);
        } catch (error) {
          const operation = intent.externalOperation;
          if (operation && this.isOperationCurrent(operation)) {
            await this._finishIndeterminate(
              operation,
              restoreError || error,
              "Credential restoration outcome could not be determined.",
              true
            );
          }
          const result = Object.freeze({
            ok: false,
            status: CONNECTION_STATUSES.INDETERMINATE,
            committed: false,
            error: publicError(restoreError || error, "Credential restoration outcome could not be determined."),
            state: this._state,
          });
          this._retireSecretIntent(intent);
          return result;
        }
        authoritativeSequence = await this._awaitSecretEventBarrier();
        if (intent.highestExternal.sequence > target.sequence) continue restoreLoop;
        if (
          sequenceBeforeRead === authoritativeSequence
          && authoritativeSequence === this._secretEventSequence
        ) {
          authoritativeStable = true;
          break;
        }
      }
      if (!authoritativeStable || authoritativeSequence !== this._secretEventSequence) continue;

      const authoritativeFingerprint = fingerprint(authoritative);
      if (authoritativeFingerprint !== target.fingerprint) {
        const sequence = ++this._secretEventSequence;
        this._captureExternalSnapshot(intent, {
          sequence,
          readable: true,
          error: null,
          value: authoritative,
          fingerprint: authoritativeFingerprint,
        });
        continue;
      }

      const externalOperation = intent.externalOperation;
      if (authoritativeSequence !== this._secretEventSequence) continue;
      if (externalOperation && this.isOperationCurrent(externalOperation)) {
        const accepted = await this._acceptStoredSnapshot(authoritative, externalOperation, { source: "external" });
        if (
          accepted.status === "stale"
          && intent.highestExternal.sequence === target.sequence
          && authoritativeSequence === this._secretEventSequence
        ) {
          await this._updateStableExternalBaseline(authoritative, target);
          if (!this._currentOperation && this._knownFingerprint === target.fingerprint) {
            await this._reconcileAfterLostOwnership(authoritative);
          }
        }
      } else if (!this._currentOperation) {
        await this._reconcileAfterLostOwnership(authoritative);
      } else {
        await this._updateStableExternalBaseline(authoritative, target);
        if (!this._currentOperation && this._knownFingerprint === target.fingerprint) {
          await this._reconcileAfterLostOwnership(authoritative);
        }
      }
      if (
        intent.highestExternal.sequence > target.sequence
        || authoritativeSequence !== this._secretEventSequence
      ) {
        continue;
      }
      const result = Object.freeze({
        ok: false,
        status: "superseded",
        committed: false,
        error: writeError
          ? publicError(writeError, "Credentials changed outside this operation.")
          : fixedPublicError(
            "credential_changed",
            "Credentials changed outside this operation. The latest value was restored."
          ),
        state: this._state,
      });
      this._retireSecretIntent(intent);
      return result;
    }
    this._retireSecretIntent(intent);
    return this._staleResult();
  }

  _retireSecretIntent(intent) {
    if (!intent) return;
    intent.active = false;
    intent.operation = null;
    intent.externalOperation = null;
    intent.highestExternal = null;
    intent.expectedSelfEvents = [];
    intent.observedFingerprint = undefined;
    if (this._expectedSecretIntent === intent) {
      this._expectedSecretIntent = null;
    }
  }

  async _updateStableExternalBaseline(stored, snapshot) {
    if (snapshot.fingerprint === null) {
      this._stableState = this._makeStableState(
        CONNECTION_STATUSES.ABSENT,
        this._state.operationId,
        false,
        false,
        null
      );
      return;
    }
    const normalized = normalizeCandidate(stored);
    if (!normalized.ok || normalized.value !== stored) {
      this._stableState = this._makeStableState(
        CONNECTION_STATUSES.FAILED,
        this._state.operationId,
        true,
        false,
        fixedPublicError(
          "invalid_candidate",
          normalized.ok ? "Stored credentials are not normalized." : normalized.reason
        )
      );
      return;
    }
    const validation = await this._validateCandidate(normalized.value);
    if (this._knownFingerprint !== snapshot.fingerprint) return;
    this._stableState = this._makeStableState(
      validation.ok ? CONNECTION_STATUSES.CONNECTED : CONNECTION_STATUSES.FAILED,
      this._state.operationId,
      true,
      validation.ok,
      validation.error
    );
  }

  _projectConnection(connected) {
    const project = async () => {
      let lastError = null;
      for (let attempt = 0; attempt < 2; attempt += 1) {
        try {
          await this._executeCommand("setContext", CONNECTION_CONTEXT_KEY, connected);
          return null;
        } catch (error) {
          lastError = error;
        }
      }
      return publicError(lastError, "Could not update the Cloudsmith connection indicator.");
    };
    const run = this._projectionQueue.then(project, project);
    this._projectionQueue = run.then(() => undefined, () => undefined);
    return run;
  }

  async _deleteLegacyStatus() {
    if (!this.context.secrets || typeof this.context.secrets.delete !== "function") return;
    try {
      await this.context.secrets.delete(LEGACY_CONNECTION_KEY);
    } catch {
      // The compatibility key is never authoritative; retry on the next initialization.
    }
  }

  _staleResult() {
    return Object.freeze({
      ok: false,
      status: "stale",
      committed: false,
      state: this._state,
    });
  }
}

module.exports = {
  AUTH_TOKEN_KEY,
  CONNECTION_STATUSES,
  ConnectionManager,
  bindConnectionManager,
  getAccountEpoch,
  getConnectionManager,
  getConnectionState,
  normalizeCandidate,
  unbindConnectionManager,
};

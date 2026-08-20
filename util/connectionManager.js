const crypto = require("crypto");
const vscode = require("vscode");
const { ContextKeyProjector } = require("./contextKeyProjector");
const { CredentialMutationLock } = require("./credentialMutationLock");
const {
  authorizationForCredential,
  createSSOCredential,
  decodeStoredCredential,
  identityFingerprint,
  normalizeAPIKey,
  normalizeCredential,
  nextCredentialGeneration,
  serializeCredential,
  storageFingerprint,
} = require("./credentialEnvelope");
const { SSOProtocolClient } = require("./ssoProtocolClient");

const AUTH_TOKEN_KEY = "cloudsmith-vsc.authToken";
const LEGACY_CONNECTION_KEY = "cloudsmith-vsc.isConnected";
const CONNECTION_CONTEXT_KEY = "cloudsmith.connected";
const SSO_REFRESH_INTERVAL_MS = 30 * 60 * 1000;
const SSO_REFRESH_COOLDOWN_MS = 5 * 60 * 1000;
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
    unauthorized: "Authentication failed. Sign in again or check the API key.",
    forbidden: "The credential does not have permission to access Cloudsmith.",
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
  return fixedPublicError(kind, messages[kind] || "Could not validate the credential.");
}

function normalizeCandidate(candidate) {
  return normalizeAPIKey(candidate);
}

function fingerprint(value) {
  return storageFingerprint(value);
}

function publicIdentity(value) {
  for (const key of ["slug", "username"]) {
    const candidate = value && value[key];
    if (
      typeof candidate === "string"
      && candidate.length <= 128
      && /^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$/.test(candidate)
    ) return candidate;
  }
  return null;
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
    this._createCloudsmithAPI = options.createCloudsmithAPI || ((apiContext, apiOptions = {}) => {
      const { CloudsmithAPI } = require("./cloudsmithAPI");
      return new CloudsmithAPI(apiContext, apiOptions);
    });
    this._now = options.now || Date.now;
    this._monotonicNow = options.monotonicNow || (() => Number(process.hrtime.bigint() / 1000000n));
    this._protocolClient = options.protocolClient || new SSOProtocolClient(options.protocolOptions);
    this._mutationLock = options.mutationLock || new CredentialMutationLock(context, options.mutationLockOptions);
    this._executeCommand = options.executeCommand || vscode.commands.executeCommand;
    this._connectionContextProjector = options.contextKeyProjector || new ContextKeyProjector({
      defaults: { [CONNECTION_CONTEXT_KEY]: false },
      executeCommand: this._executeCommand,
      attempts: 2,
    });
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
    this._knownIdentityFingerprint = undefined;
    this._credential = null;
    this._refreshPromise = null;
    this._refreshController = null;
    this._refreshDueAt = Number.POSITIVE_INFINITY;
    this._refreshCooldownUntil = 0;
    this._operationCounter = 0;
    this._currentOperation = null;
    this._operationPublicationSequence = new WeakMap();
    this._mutationQueue = Promise.resolve();
    this._disposal = null;
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
    // Interactive credential intent always wins over background refresh. The
    // refresh controller is manager-owned, so canceling one API waiter cannot
    // cancel refresh for other coalesced callers.
    if (this._refreshController) this._refreshController.abort();
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

  async replaceCredential(candidate, token = null, options = {}) {
    const operation = token || this.beginCredentialOperation();
    if (!this.isOperationCurrent(operation)) return this._staleResult();

    const normalized = normalizeCredential(candidate, { now: this._now() });
    if (!normalized.ok) {
      return this._finishReplacementFailure(
        operation,
        fixedPublicError("invalid_candidate", normalized.reason)
      );
    }

    const validation = await this._validateCandidate(normalized.credential, operation.signal, options);
    await this._awaitSecretEventBarrier();
    if (!this._canPublishOperation(operation)) return this._staleResult();
    if (!validation.ok) {
      return this._finishReplacementFailure(operation, validation.error);
    }
    if (typeof options.beforeCommit === "function") {
      let confirmed = false;
      try {
        confirmed = await options.beforeCommit(validation.identity || null);
      } catch {
        confirmed = false;
      }
      if (!this._canPublishOperation(operation)) return this._staleResult();
      if (!confirmed) {
        return this._finishReplacementFailure(
          operation,
          fixedPublicError("cancelled", "Authentication was cancelled.")
        );
      }
    }

    const serialized = serializeCredential(normalized.credential);
    return this._enqueueMutation(() => this._mutationLock.run(async () => {
      let authoritative;
      try {
        authoritative = await this.context.secrets.get(AUTH_TOKEN_KEY);
      } catch (error) {
        return this._finishIndeterminate(
          operation,
          error,
          "Could not verify current credential storage.",
          true
        );
      }
      await this._awaitSecretEventBarrier();
      if (!this._canPublishOperation(operation)) return this._staleResult();
      if (this._knownFingerprint !== undefined && fingerprint(authoritative) !== this._knownFingerprint) {
        return this._supersedeWithSnapshot(authoritative, operation);
      }
      return this._commitCandidate(serialized, operation);
    }, { signal: operation.signal })).catch(() => this._finishReplacementFailure(
      operation,
      fixedPublicError("credential_lock_failed", "Credential storage is busy. Try again.")
    ));
  }

  async disconnect(token = null) {
    const operation = token || this._beginOperation(true);
    if (!this.isOperationCurrent(operation)) return this._staleResult();
    if (this._refreshController) this._refreshController.abort();
    return this._enqueueMutation(() => this._mutationLock.run(async () => {
      let authoritative;
      try {
        authoritative = await this.context.secrets.get(AUTH_TOKEN_KEY);
      } catch (error) {
        return this._finishIndeterminate(
          operation,
          error,
          "Could not verify current credential storage.",
          true
        );
      }
      await this._awaitSecretEventBarrier();
      if (!this._canPublishOperation(operation)) return this._staleResult();
      if (this._knownFingerprint !== undefined && fingerprint(authoritative) !== this._knownFingerprint) {
        return this._supersedeWithSnapshot(authoritative, operation);
      }
      return this._commitDelete(operation);
    }, { signal: operation.signal })).catch(() => this._finishReplacementFailure(
      operation,
      fixedPublicError("credential_lock_failed", "Credential storage is busy. Try again.")
    ));
  }

  async checkConnectivity(apiKey) {
    const normalized = normalizeCandidate(apiKey);
    if (!normalized.ok) {
      return "false";
    }
    const validation = await this._validateCandidate({ version: 1, kind: "api-key", apiKey: normalized.value });
    if (validation.ok) return "true";
    return validation.error && validation.error.kind === "unauthorized" ? "false" : "error";
  }

  async isConnected() {
    return this._state.sessionConnected ? "true" : "false";
  }

  getCredentialKind() {
    return this._credential ? this._credential.kind : null;
  }

  async getAPIKeyForRegistry() {
    return this._credential && this._credential.kind === "api-key"
      ? this._credential.apiKey
      : null;
  }

  async handleAuthorizationRejected(expectedSession = null) {
    if (!this._credential || this._credential.kind !== "sso") return null;
    if (expectedSession && !this._matchesSessionProof(expectedSession, this._credential)) {
      return Object.freeze({ ok: false, status: "stale", state: this._state });
    }
    return this.disconnect();
  }

  async getAuthorization(options = {}) {
    if (this._disposed || !this._state.sessionConnected || !this._credential) return null;
    const startingIdentity = this._knownIdentityFingerprint;
    let proactiveRefreshStatus = null;
    let proactiveRefreshProof = null;
    if (this._credential.kind === "sso") {
      if (options.expectedSession && !this._matchesSessionProof(options.expectedSession, this._credential)) {
        return null;
      }
      const due = this._monotonicNow() >= this._refreshDueAt;
      if (options.forceRefresh || due) {
        const refreshed = await awaitForCaller(
          this.refreshSSO({ force: Boolean(options.forceRefresh) }),
          options.signal
        );
        if (refreshed === null) return null;
        if (!refreshed.ok && options.forceRefresh) {
          const proof = refreshed.rejectionProof || null;
          return options.returnRefreshResult
            ? Object.freeze({
              kind: "sso",
              refreshFailed: true,
              status: refreshed.status,
              ...(proof || {}),
            })
            : null;
        }
        proactiveRefreshStatus = !options.forceRefresh
          && !refreshed.ok
          && refreshed.status !== "stale"
          ? refreshed.status
          : null;
        proactiveRefreshProof = proactiveRefreshStatus
          ? (refreshed.rejectionProof || refreshed.failureProof || null)
          : null;
      }
    }
    if (
      this._disposed
      || !this._state.sessionConnected
      || !this._credential
      || this._knownIdentityFingerprint !== startingIdentity
    ) return null;
    const authorization = authorizationForCredential(this._credential);
    return proactiveRefreshStatus
      && proactiveRefreshProof
      && this._matchesSessionProof(proactiveRefreshProof, this._credential)
      && authorization
      ? Object.freeze({
        ...authorization,
        proactiveRefreshFailed: true,
        proactiveRefreshStatus,
      })
      : authorization;
  }

  async refreshSSO(options = {}) {
    if (this._refreshPromise) return this._refreshPromise;
    const force = Boolean(options.force);
    if (!this._credential || this._credential.kind !== "sso") {
      return Object.freeze({ ok: false, status: "not_sso" });
    }
    if (!force && this._monotonicNow() < this._refreshCooldownUntil) {
      return Object.freeze({
        ok: false,
        status: "cooldown",
        preserved: true,
        failureProof: Object.freeze({
          credentialId: this._credential.credentialId,
          generation: this._credential.generation,
        }),
      });
    }
    const starting = this._credential;
    const startingFingerprint = this._knownFingerprint;
    const startingOperationCounter = this._operationCounter;
    const controller = new AbortController();
    this._refreshController = controller;
    const refresh = this._mutationLock.run(async () => {
      const stored = await this.context.secrets.get(AUTH_TOKEN_KEY);
      const decoded = decodeStoredCredential(stored, { now: this._now() });
      if (
        !decoded.ok
        || !decoded.credential
        || decoded.credential.kind !== "sso"
        || fingerprint(stored) !== startingFingerprint
        || decoded.credential.credentialId !== starting.credentialId
        || decoded.credential.generation !== starting.generation
      ) return Object.freeze({ ok: false, status: "stale" });

      const result = await this._protocolClient.refresh(
        starting.accessToken,
        starting.refreshToken,
        { signal: controller.signal }
      );
      if (controller.signal.aborted || this._disposed) return Object.freeze({ ok: false, status: "cancelled" });

      // A network response is only a candidate. Re-read after it arrives and
      // refuse to publish if a login, logout, external SecretStorage update,
      // or another generation won while the refresh request was in flight.
      const authoritative = await this.context.secrets.get(AUTH_TOKEN_KEY);
      await this._awaitSecretEventBarrier();
      const current = decodeStoredCredential(authoritative, { now: this._now() });
      if (
        controller.signal.aborted
        || this._operationCounter !== startingOperationCounter
        || this._currentOperation
        || !current.ok
        || !current.credential
        || current.credential.kind !== "sso"
        || fingerprint(authoritative) !== startingFingerprint
        || current.credential.credentialId !== starting.credentialId
        || current.credential.generation !== starting.generation
      ) return Object.freeze({ ok: false, status: "stale" });

      let generation;
      try {
        generation = nextCredentialGeneration(starting.generation);
      } catch {
        return Object.freeze({ ok: false, status: "generation_exhausted", preserved: true });
      }
      const operation = this._beginOperation(false);
      if (result.ok) {
        const next = createSSOCredential(result.accessToken, result.refreshToken || starting.refreshToken, {
          credentialId: starting.credentialId,
          generation,
          now: this._now(),
          refreshAttemptedAt: this._now(),
        });
        const committed = await this._commitCandidate(serializeCredential(next), operation);
        return Object.freeze({ ...committed, refreshed: committed.ok });
      }
      this._refreshCooldownUntil = this._monotonicNow() + SSO_REFRESH_COOLDOWN_MS;
      const attempted = createSSOCredential(starting.accessToken, starting.refreshToken, {
        credentialId: starting.credentialId,
        generation,
        now: this._now(),
        refreshedAt: starting.refreshedAt,
        refreshAttemptedAt: this._now(),
      });
      const committed = await this._commitCandidate(serializeCredential(attempted), operation);
      return Object.freeze({
        ok: false,
        status: result.kind || "refresh_failed",
        preserved: committed.ok,
        rejectionProof: committed.ok && ["invalid_session", "refresh_rejected"].includes(result.kind)
          ? Object.freeze({ credentialId: attempted.credentialId, generation: attempted.generation })
          : null,
        failureProof: committed.ok
          ? Object.freeze({ credentialId: attempted.credentialId, generation: attempted.generation })
          : null,
      });
    }, { signal: controller.signal }).catch(error => Object.freeze({
      ok: false,
      status: error && error.kind === "cancelled" ? "cancelled" : "refresh_failed",
      preserved: true,
    })).finally(() => {
      if (this._refreshController === controller) this._refreshController = null;
      if (this._refreshPromise === refresh) this._refreshPromise = null;
    });
    this._refreshPromise = refresh;
    return refresh;
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
    if (this._disposed) return this._disposal || Promise.resolve();
    this._disposed = true;
    if (this._refreshController) this._refreshController.abort();
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
    this._disposal = this._connectionContextProjector.dispose();
    return this._disposal;
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

  async _validateCandidate(credential, signal, options = {}) {
    if (signal && signal.aborted) {
      return Object.freeze({ ok: false, error: fixedPublicError("cancelled", "Authentication was cancelled.") });
    }
    try {
      const api = this._createCloudsmithAPI(this.context);
      const requestCredential = { credential };
      const result = await api.get("user/self", {
        ...requestCredential,
        signal,
        responseType: "object",
        validate: value => Boolean(value) && typeof value.authenticated === "boolean",
        retry: "never",
      });
      if (signal && signal.aborted) {
        return Object.freeze({ ok: false, error: fixedPublicError("cancelled", "Authentication was cancelled.") });
      }
      if (result && result.ok && result.data.authenticated) {
        const identity = publicIdentity(result.data);
        if (credential.kind === "sso" && !identity) {
          return Object.freeze({
            ok: false,
            error: fixedPublicError(
              "identity_unavailable",
              "Cloudsmith did not return an account identity that can be confirmed safely."
            ),
          });
        }
        if (credential.kind === "sso" && options.workspaceSlug) {
          const workspace = await this._validateWorkspaceAccess(
            api,
            credential,
            options.workspaceSlug,
            signal
          );
          if (!workspace.ok) return workspace;
        }
        return Object.freeze({ ok: true, identity: identity || "Cloudsmith account" });
      }
      const error = result && !result.ok
        ? validationAPIError(result.error)
        : fixedPublicError("unauthorized", "The credential was not accepted by Cloudsmith.");
      return Object.freeze({ ok: false, error });
    } catch (error) {
      return Object.freeze({
        ok: false,
        error: publicError(error, "Could not validate the credential."),
      });
    }
  }

  async _validateWorkspaceAccess(api, credential, workspaceSlug, signal) {
    for (let page = 1; page <= 20; page += 1) {
      const endpoint = `namespaces/?page=${page}&page_size=500&sort=slug`;
      const result = await api.get(endpoint, {
        credential,
        signal,
        responseType: "array",
        retry: "never",
        validate: value => Array.isArray(value) && value.every(item => (
          item && typeof item === "object" && !Array.isArray(item)
          && typeof item.slug === "string" && item.slug.length <= 512
        )),
      });
      if (!result || !result.ok) {
        return Object.freeze({
          ok: false,
          error: result && result.error
            ? validationAPIError(result.error)
            : fixedPublicError("workspace_check_failed", "Could not verify access to the requested workspace."),
        });
      }
      if (result.data.some(item => item.slug === workspaceSlug)) return Object.freeze({ ok: true });
      const total = Number(result.headers && result.headers["x-pagination-pagetotal"]);
      if (!Number.isSafeInteger(total) || total < page || total > 20) {
        return Object.freeze({
          ok: false,
          error: fixedPublicError("workspace_check_failed", "Could not verify access to the requested workspace."),
        });
      }
      if (page === total) break;
    }
    return Object.freeze({
      ok: false,
      error: fixedPublicError(
        "workspace_forbidden",
        "The authenticated account does not have access to the requested Cloudsmith workspace."
      ),
    });
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
      this._adoptFingerprint(storedFingerprint, stored);
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
      this._adoptFingerprint(null, null);
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
      this._adoptFingerprint(null, null);
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

    const decoded = decodeStoredCredential(stored, { now: this._now() });
    if (!decoded.ok || !decoded.credential) {
      this._adoptFingerprint(fingerprint(stored), stored);
      const error = fixedPublicError(
        "invalid_candidate",
        decoded.ok ? "Stored credentials are invalid." : decoded.reason
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

    const snapshotFingerprint = fingerprint(stored);
    const nextIdentity = identityFingerprint(decoded.credential);
    const identityChanged = this._knownIdentityFingerprint !== nextIdentity;
    this._adoptFingerprint(snapshotFingerprint, stored);
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

    const validation = await this._validateCandidate(decoded.credential, operation.signal);
    if (!this._canPublishOperation(operation)) return this._staleResult();
    if (!validation.ok) {
      if (
        options.source === "startup"
        && decoded.credential.kind === "sso"
        && validation.error
        && validation.error.kind === "unauthorized"
      ) {
        const recovered = await this._recoverStoredSSO(
          decoded.credential,
          snapshotFingerprint,
          operation
        );
        if (recovered) return recovered;
        if (!this._canPublishOperation(operation)) return this._staleResult();
      }
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

    if (decoded.legacy && options.source === "startup") {
      // Migration is a storage-format improvement, not a new login. If the
      // canonical rewrite fails, retain the already validated legacy session.
      this._stableState = this._makeStableState(
        CONNECTION_STATUSES.CONNECTED,
        operation.id,
        true,
        true,
        null
      );
      return this._enqueueMutation(() => this._mutationLock.run(async () => {
        const authoritative = await this.context.secrets.get(AUTH_TOKEN_KEY);
        if (fingerprint(authoritative) !== snapshotFingerprint) {
          return this._supersedeWithSnapshot(authoritative, operation);
        }
        return this._commitCandidate(serializeCredential(decoded.credential), operation);
      }, { signal: operation.signal })).catch(() => this._finishReplacementFailure(
        operation,
        fixedPublicError("credential_lock_failed", "Credential storage is busy. Try again.")
      ));
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

  async _recoverStoredSSO(starting, startingFingerprint, operation) {
    try {
      return await this._mutationLock.run(async () => {
        const stored = await this.context.secrets.get(AUTH_TOKEN_KEY);
        const decoded = decodeStoredCredential(stored, { now: this._now() });
        if (
          !this._canPublishOperation(operation)
          || !decoded.ok
          || !decoded.credential
          || decoded.credential.kind !== "sso"
          || fingerprint(stored) !== startingFingerprint
          || decoded.credential.credentialId !== starting.credentialId
          || decoded.credential.generation !== starting.generation
        ) return null;

        const result = await this._protocolClient.refresh(
          starting.accessToken,
          starting.refreshToken,
          { signal: operation.signal }
        );
        if (!this._canPublishOperation(operation)) return null;

        const authoritative = await this.context.secrets.get(AUTH_TOKEN_KEY);
        await this._awaitSecretEventBarrier();
        const current = decodeStoredCredential(authoritative, { now: this._now() });
        if (
          !this._canPublishOperation(operation)
          || !current.ok
          || !current.credential
          || current.credential.kind !== "sso"
          || fingerprint(authoritative) !== startingFingerprint
          || current.credential.credentialId !== starting.credentialId
          || current.credential.generation !== starting.generation
        ) return null;

        if (result.ok) {
          let generation;
          try {
            generation = nextCredentialGeneration(starting.generation);
          } catch {
            return null;
          }
          const next = createSSOCredential(
            result.accessToken,
            result.refreshToken || starting.refreshToken,
            {
              credentialId: starting.credentialId,
              generation,
              now: this._now(),
              refreshAttemptedAt: this._now(),
            }
          );
          const validation = await this._validateCandidate(next, operation.signal);
          if (!validation.ok || !this._canPublishOperation(operation)) return null;
          return this._commitCandidate(serializeCredential(next), operation);
        }
        if (["invalid_session", "refresh_rejected"].includes(result.kind)) {
          return this._commitDelete(operation);
        }
        return null;
      }, { signal: operation.signal });
    } catch {
      return null;
    }
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
    this._knownIdentityFingerprint = undefined;
    this._credential = null;
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

  _adoptFingerprint(nextFingerprint, stored) {
    this._knownFingerprint = nextFingerprint;
    const decoded = stored
      ? decodeStoredCredential(stored, { now: this._now() })
      : Object.freeze({ ok: true, credential: null });
    const nextCredential = decoded.ok ? decoded.credential : null;
    const nextIdentity = decoded.ok ? identityFingerprint(nextCredential) : undefined;
    this._credential = nextCredential;
    this._seedRefreshDeadlines(nextCredential);
    if (this._knownIdentityFingerprint !== nextIdentity) {
      this._knownIdentityFingerprint = nextIdentity;
      this._setState({ ...this._state, accountEpoch: this._state.accountEpoch + 1 });
      return true;
    }
    return false;
  }

  _seedRefreshDeadlines(credential) {
    if (!credential || credential.kind !== "sso") {
      this._refreshDueAt = Number.POSITIVE_INFINITY;
      this._refreshCooldownUntil = 0;
      return;
    }
    const wallNow = this._now();
    const monotonicNow = this._monotonicNow();
    const dueRemaining = Math.max(
      0,
      Math.min(SSO_REFRESH_INTERVAL_MS, credential.refreshedAt + SSO_REFRESH_INTERVAL_MS - wallNow)
    );
    this._refreshDueAt = monotonicNow + dueRemaining;
    const attempted = credential.refreshAttemptedAt;
    const cooldownRemaining = attempted === null || attempted < credential.refreshedAt
      ? 0
      : Math.max(0, Math.min(SSO_REFRESH_COOLDOWN_MS, attempted + SSO_REFRESH_COOLDOWN_MS - wallNow));
    this._refreshCooldownUntil = monotonicNow + cooldownRemaining;
  }

  _matchesSessionProof(proof, credential = this._credential) {
    return Boolean(
      proof
      && credential
      && credential.kind === "sso"
      && proof.credentialId === credential.credentialId
      && proof.generation === credential.generation
    );
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
      this._adoptFingerprint(observedFingerprint, stored);
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

    const decoded = decodeStoredCredential(stored, { now: this._now() });
    if (
      decoded.ok
      && decoded.credential
      && decoded.credential.kind === "api-key"
      && this._credential
      && this._credential.kind === "api-key"
      && identityFingerprint(decoded.credential) === this._knownIdentityFingerprint
      && this._stableState.sessionConnected
    ) {
      this._knownFingerprint = observedFingerprint;
      this._credential = decoded.credential;
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

    this._adoptFingerprint(snapshot.fingerprint, snapshot.value);
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
    const decoded = decodeStoredCredential(stored, { now: this._now() });
    if (!decoded.ok || !decoded.credential) {
      this._stableState = this._makeStableState(
        CONNECTION_STATUSES.FAILED,
        this._state.operationId,
        true,
        false,
        fixedPublicError(
          "invalid_candidate",
          decoded.ok ? "Stored credentials are invalid." : decoded.reason
        )
      );
      return;
    }
    const validation = await this._validateCandidate(decoded.credential);
    if (this._knownFingerprint !== snapshot.fingerprint) return;
    this._stableState = this._makeStableState(
      validation.ok ? CONNECTION_STATUSES.CONNECTED : CONNECTION_STATUSES.FAILED,
      this._state.operationId,
      true,
      validation.ok,
      validation.error
    );
  }

  async _projectConnection(connected) {
    const result = await this._connectionContextProjector.project({
      [CONNECTION_CONTEXT_KEY]: Boolean(connected),
    });
    return result.error
      ? publicError(result.error, "Could not update the Cloudsmith connection indicator.")
      : null;
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

function awaitForCaller(promise, signal) {
  if (!signal) return promise;
  if (signal.aborted) return Promise.resolve(null);
  return new Promise(resolve => {
    let settled = false;
    const finish = value => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      resolve(value);
    };
    const onAbort = () => finish(null);
    signal.addEventListener("abort", onAbort, { once: true });
    Promise.resolve(promise).then(finish, () => finish(Object.freeze({ ok: false, status: "refresh_failed" })));
  });
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

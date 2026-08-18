// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { captureAccount, isAccountCurrent } = require("./accountOperation");
const { UpstreamCacheLifecycle } = require("./upstreamCacheLifecycle");
const { UpstreamChecker } = require("./upstreamChecker");
const { UpstreamOperationScheduler } = require("./upstreamOperationScheduler");

const CONNECTED_STATUS = "connected";
const OPERATION_SCOPE = Symbol("cloudsmith.upstreamOperationScope");

function sameAccount(left, right) {
  return Boolean(
    left
    && right
    && left.activationId === right.activationId
    && left.accountEpoch === right.accountEpoch
  );
}

function accountIdentity(value) {
  return value
    && typeof value.activationId === "string"
    && Number.isInteger(value.accountEpoch)
    ? `${value.activationId}\0${value.accountEpoch}`
    : null;
}

function isStableConnected(state) {
  return Boolean(state?.sessionConnected && state.status === CONNECTED_STATUS);
}

function stateSignature(state) {
  return state ? [
    state.activationId,
    state.accountEpoch,
    state.operationId,
    state.status,
    state.sessionConnected === true,
  ].join("\0") : "missing";
}

function disposedError() {
  const error = new Error("The upstream runtime has been disposed.");
  error.name = "UpstreamRuntimeError";
  error.kind = "disposed";
  return error;
}

function staleScopeError() {
  const error = new Error("The upstream operation scope is stale.");
  error.name = "UpstreamRuntimeError";
  error.kind = "stale";
  return error;
}

function isScheduler(value) {
  return Boolean(
    value
    && typeof value.run === "function"
    && typeof value.cancel === "function"
  );
}

function linkCancellation(controller, options = {}) {
  const signal = options.signal;
  const cancellationToken = options.cancellationToken;
  const abort = () => controller.abort();
  let cancellationDisposable = null;
  if (signal?.aborted) abort();
  else signal?.addEventListener?.("abort", abort, { once: true });
  if (cancellationToken?.isCancellationRequested) {
    abort();
  } else if (typeof cancellationToken?.onCancellationRequested === "function") {
    cancellationDisposable = cancellationToken.onCancellationRequested(abort);
  }
  return () => {
    signal?.removeEventListener?.("abort", abort);
    cancellationDisposable?.dispose?.();
  };
}

class UpstreamRuntime {
  constructor(context, options = {}) {
    const connectionManager = options.connectionManager;
    if (
      !connectionManager
      || typeof connectionManager.getState !== "function"
      || typeof connectionManager.onDidChange !== "function"
    ) {
      throw new TypeError("An activation-owned ConnectionManager is required.");
    }
    this.context = context;
    this.connectionManager = connectionManager;
    this._disposed = false;
    this._generation = 0;
    this._operationSequence = 0;
    this._operations = new Set();
    this._scopes = new Set();
    this._latestState = connectionManager.getState();
    this._lastIdentity = accountIdentity(this._latestState);
    this._lastStateSignature = null;
    this._readinessRevision = 0;
    this._readinessIdentity = null;
    this._cacheReadyIdentity = null;
    this._stableEventIdentity = null;
    this._readyAccount = null;
    this._readiness = Promise.resolve(false);
    this._schedulerFactory = options.schedulerFactory || (() => (
      new UpstreamOperationScheduler()
    ));
    this._cacheLifecycle = options.cacheLifecycle || new UpstreamCacheLifecycle(
      context?.globalState,
      { persistenceWaitMs: options.persistenceWaitMs }
    );

    // Subscribe before constructing the subordinate so no connection transition
    // can escape the activation-owned lifecycle authority.
    this._connectionSubscription = connectionManager.onDidChange(state => {
      this._processConnectionState(state);
    });
    try {
      options.beforeCheckerConstruction?.();
      this._checker = options.checker || new UpstreamChecker(context, {
        connectionManager,
        cacheLifecycle: this._cacheLifecycle,
        cloudsmithAPI: options.cloudsmithAPI,
        now: options.now,
        cacheWriteWaitMs: options.cacheWriteWaitMs,
      });
    } catch (error) {
      this._connectionSubscription?.dispose?.();
      this._connectionSubscription = null;
      this._cacheLifecycle.dispose();
      throw error;
    }
  }

  initialize() {
    if (this._disposed) return Promise.reject(disposedError());
    const state = this.connectionManager.getState();
    this._latestState = state;
    const identity = accountIdentity(state);
    this._lastIdentity = identity;
    if (this._readinessIdentity !== identity) {
      this._beginPersistenceReadiness(identity, true);
    }
    return this._readiness;
  }

  resetForAccountChange(state = this.connectionManager.getState()) {
    if (this._disposed) return Promise.reject(disposedError());
    const signature = stateSignature(state);
    if (signature === this._lastStateSignature) return this._readiness;
    return this._processConnectionState(state, { forceReset: true });
  }

  getAllUpstreamData(workspace, repo, options = {}) {
    return this._runSafe("getAllUpstreamData", [workspace, repo], options, {
      workspace,
      repo,
      formats: "all",
      kind: "safe-inventory-all",
    });
  }

  getUpstreamDataForFormats(workspace, repo, formats, options = {}) {
    return this._runSafe(
      "getUpstreamDataForFormats",
      [workspace, repo, formats],
      options,
      { workspace, repo, formats, kind: "safe-inventory-formats" }
    );
  }

  getRepositoryUpstreamStateForFormats(workspace, repo, formats, options = {}) {
    return this._runSafe(
      "getRepositoryUpstreamStateForFormats",
      [workspace, repo, formats],
      options,
      { workspace, repo, formats, kind: "repository-state-formats" }
    );
  }

  previewResolution(workspace, repo, name, format, options = {}) {
    return this._runSafe(
      "previewResolution",
      [workspace, repo, name, format],
      options,
      { workspace, repo, formats: [format], kind: "preview", packageName: name }
    );
  }

  async getPrivilegedRepositoryUpstreamsForExport(workspace, repo, options = {}) {
    const upstreamData = await this._runChecker(
      "getAllUpstreamData",
      [workspace, repo],
      options,
      {
        workspace,
        repo,
        formats: "all",
        projection: "privileged",
        kind: "terraform-export",
      },
      "privileged"
    );
    if (upstreamData === null) return null;
    const upstreams = Array.isArray(upstreamData.upstreams) ? upstreamData.upstreams : [];
    const failedFormats = Array.isArray(upstreamData.failedFormats)
      ? upstreamData.failedFormats
      : [];
    const uninspectedFormats = Array.isArray(upstreamData.uninspectedFormats)
      ? upstreamData.uninspectedFormats
      : [];
    const unavailableFormats = [...new Set([...failedFormats, ...uninspectedFormats])];
    const hasUsableUpstreams = upstreams.length > 0;
    if (unavailableFormats.length > 0 && !hasUsableUpstreams) {
      return {
        data: upstreams,
        error: `Could not load upstream data for: ${unavailableFormats.join(", ")}`,
        failedFormats,
        uninspectedFormats,
        complete: false,
        partial: false,
      };
    }
    return {
      data: upstreams,
      error: null,
      active: upstreamData.active,
      total: upstreamData.total,
      failedFormats,
      uninspectedFormats,
      complete: upstreamData.complete === true,
      partial: upstreamData.complete !== true && hasUsableUpstreams,
    };
  }

  createOperationScope(options = {}) {
    if (this._disposed) throw disposedError();
    if (typeof options.kind !== "string" || options.kind.length === 0) {
      throw new TypeError("An upstream operation scope kind is required.");
    }
    const account = options.account || captureAccount(this.connectionManager);
    if (!isAccountCurrent(this.connectionManager, account)) throw staleScopeError();
    const scheduler = options.scheduler || this._schedulerFactory({
      kind: options.kind,
      workspace: options.workspace,
      formats: options.formats,
    });
    if (!isScheduler(scheduler)) {
      throw new TypeError("An upstream operation scheduler is required.");
    }
    const controller = new AbortController();
    const unlink = linkCancellation(controller, options);
    const registration = {
      generation: this._generation,
      account,
      controller,
      scheduler,
      unlink,
      disposed: false,
      scope: null,
    };
    const dispose = () => this._disposeScope(registration);
    const scope = {
      scheduler,
      signal: controller.signal,
      account,
      dispose,
    };
    Object.defineProperty(scope, OPERATION_SCOPE, {
      value: Object.freeze({ owner: this, registration }),
    });
    registration.scope = Object.freeze(scope);
    this._scopes.add(registration);
    if (controller.signal.aborted) this._disposeScope(registration);
    return registration.scope;
  }

  dispose() {
    if (this._disposed) return;
    this._disposed = true;
    this._connectionSubscription?.dispose?.();
    this._connectionSubscription = null;
    this._closeAllOperations();
    this._cacheLifecycle.dispose();
    this._checker = null;
  }

  _runSafe(method, args, options, identity) {
    return this._runChecker(method, args, options, {
      ...identity,
      projection: "safe",
    }, "safe");
  }

  async _runChecker(method, args, suppliedOptions, identity, projection) {
    if (this._disposed) throw disposedError();
    const options = suppliedOptions && typeof suppliedOptions === "object"
      ? suppliedOptions
      : {};
    if (options.scheduler !== undefined) {
      throw new TypeError("Pass a runtime-created operationScope instead of a scheduler.");
    }
    const scopeRegistration = this._scopeRegistration(options.operationScope);
    const requestedAccount = options.account || scopeRegistration?.account || null;
    const account = await this._awaitAdmission(requestedAccount);
    if (!account) return null;
    if (scopeRegistration && (
      scopeRegistration.disposed
      || scopeRegistration.generation !== this._generation
      || !sameAccount(scopeRegistration.account, account)
    )) return null;

    const controller = new AbortController();
    const unlinkCaller = linkCancellation(controller, options);
    const unlinkScope = scopeRegistration
      ? linkCancellation(controller, { signal: scopeRegistration.controller.signal })
      : () => {};
    const generation = this._generation;
    const registration = {
      generation,
      account,
      controller,
      identity: Object.freeze({
        activationId: account.activationId,
        accountEpoch: account.accountEpoch,
        workspace: identity.workspace || null,
        repository: identity.repo || null,
        packageName: identity.packageName || null,
        formats: Array.isArray(identity.formats)
          ? Object.freeze(identity.formats.slice())
          : identity.formats,
        projection,
        kind: identity.kind || method,
        generation,
        token: ++this._operationSequence,
      }),
    };
    this._operations.add(registration);
    const checkerOptions = {
      account,
      signal: controller.signal,
      projection,
      bypassCache: projection === "privileged" || options.bypassCache === true,
    };
    if (options.cancellationToken) checkerOptions.cancellationToken = options.cancellationToken;
    if (options.operationTimeoutMs !== undefined) {
      checkerOptions.operationTimeoutMs = options.operationTimeoutMs;
    }
    if (scopeRegistration) checkerOptions.scheduler = scopeRegistration.scheduler;

    let resolveAbort;
    const abortBoundary = new Promise(resolve => { resolveAbort = resolve; });
    const onAbort = () => resolveAbort({ kind: "aborted" });
    if (controller.signal.aborted) onAbort();
    else controller.signal.addEventListener("abort", onAbort, { once: true });
    const checker = this._checker;
    const observed = Promise.resolve().then(() => checker[method](...args, checkerOptions)).then(
      value => ({ kind: "fulfilled", value }),
      error => ({ kind: "rejected", error })
    );
    try {
      const completion = await Promise.race([observed, abortBoundary]);
      if (
        completion.kind === "aborted"
        || this._disposed
        || generation !== this._generation
        || !isAccountCurrent(this.connectionManager, account)
      ) return null;
      if (completion.kind === "rejected") throw completion.error;
      return completion.value;
    } finally {
      controller.signal.removeEventListener("abort", onAbort);
      unlinkCaller();
      unlinkScope();
      this._operations.delete(registration);
    }
  }

  async _awaitAdmission(requestedAccount) {
    if (this._disposed) throw disposedError();
    if (this._readinessIdentity === null) await this.initialize();
    let current = captureAccount(this.connectionManager);
    if (!current || (requestedAccount && !sameAccount(current, requestedAccount))) return null;
    const identity = accountIdentity(current);
    if (!sameAccount(this._readyAccount, current)) {
      if (this._readinessIdentity !== identity) return null;
      await this._readiness;
    }
    if (this._disposed) throw disposedError();
    current = captureAccount(this.connectionManager);
    if (
      !current
      || (requestedAccount && !sameAccount(current, requestedAccount))
      || !sameAccount(this._readyAccount, current)
    ) return null;
    return current;
  }

  _scopeRegistration(scope) {
    if (scope == null) return null;
    const branded = scope[OPERATION_SCOPE];
    if (!branded || branded.owner !== this || branded.registration.scope !== scope) {
      throw new TypeError("The upstream operationScope was not created by this runtime.");
    }
    return branded.registration;
  }

  _processConnectionState(state, options = {}) {
    if (this._disposed) return this._readiness;
    const signature = stateSignature(state);
    if (!options.forceReset && signature === this._lastStateSignature) return this._readiness;
    this._lastStateSignature = signature;
    this._latestState = state;
    const identity = accountIdentity(state);
    const identityChanged = identity !== this._lastIdentity;
    if (identityChanged || !isStableConnected(state) || options.forceReset) {
      this._closeAllOperations();
      this._readyAccount = null;
    }
    this._stableEventIdentity = isStableConnected(state) ? identity : null;
    if (identityChanged || options.forceReset) {
      this._lastIdentity = identity;
      this._beginPersistenceReadiness(identity, false);
    } else {
      this._activateIfReady();
    }
    return this._readiness;
  }

  _beginPersistenceReadiness(identity, initialize) {
    const revision = ++this._readinessRevision;
    this._readinessIdentity = identity;
    this._cacheReadyIdentity = null;
    this._readyAccount = null;
    let purge;
    try {
      purge = initialize
        ? this._cacheLifecycle.initialize()
        : this._cacheLifecycle.reset();
    } catch {
      purge = Promise.resolve(false);
    }
    this._readiness = Promise.resolve(purge).then(
      complete => complete === true,
      () => false
    ).then((complete) => {
      if (!this._disposed && revision === this._readinessRevision) {
        this._cacheReadyIdentity = identity;
        this._activateIfReady();
      }
      return complete;
    });
  }

  _activateIfReady() {
    const state = this._latestState;
    const identity = accountIdentity(state);
    if (
      isStableConnected(state)
      && identity !== null
      && identity === this._cacheReadyIdentity
      && identity === this._readinessIdentity
      && identity === this._stableEventIdentity
    ) {
      this._readyAccount = Object.freeze({
        activationId: state.activationId,
        accountEpoch: state.accountEpoch,
      });
    }
  }

  _closeAllOperations() {
    this._generation += 1;
    for (const operation of this._operations) operation.controller.abort();
    this._operations.clear();
    for (const scope of this._scopes) {
      scope.disposed = true;
      scope.controller.abort();
      scope.scheduler.cancel();
      scope.unlink();
    }
    this._scopes.clear();
  }

  _disposeScope(registration) {
    if (registration.disposed) return;
    registration.disposed = true;
    registration.controller.abort();
    registration.scheduler.cancel();
    registration.unlink();
    this._scopes.delete(registration);
  }
}

module.exports = { UpstreamRuntime };

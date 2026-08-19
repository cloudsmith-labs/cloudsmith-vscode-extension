// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const vscode = require("vscode");

const SET_CONTEXT_COMMAND = "setContext";
const MAX_NEUTRALIZATION_PASSES = 2;

/**
 * Serialize complete snapshots for a fixed set of extension-owned context keys.
 * Context keys are presentation only, but a late presentation write must still
 * never outlive the authoritative state generation that produced it.
 */
class ContextKeyProjector {
  constructor(options = {}) {
    this._executeCommand = options.executeCommand
      || ((...args) => vscode.commands.executeCommand(...args));
    this._defaults = normalizeDefaults(options.defaults);
    this._keys = Object.keys(this._defaults);
    this._attempts = Number.isSafeInteger(options.attempts) && options.attempts > 0
      ? Math.min(options.attempts, 3)
      : 1;
    this._version = 0;
    this._queue = Promise.resolve();
    this._disposed = false;
    this._disposal = null;
  }

  begin(options = {}) {
    if (this._disposed) return null;
    return Object.freeze({
      projector: this,
      version: ++this._version,
      isCurrent: typeof options.isCurrent === "function" ? options.isCurrent : null,
    });
  }

  project(snapshot, options = {}) {
    if (this._disposed) return Promise.resolve(staleProjectionResult());
    const normalized = normalizeSnapshot(snapshot, this._keys);
    const operation = options.operation || this.begin(options);
    if (!operation || operation.projector !== this) {
      return Promise.resolve(staleProjectionResult());
    }
    return this._enqueue(operation, normalized, false);
  }

  whenIdle() {
    return this._queue;
  }

  isDisposed() {
    return this._disposed;
  }

  dispose() {
    if (this._disposal) return this._disposal;
    this._disposed = true;
    const operation = Object.freeze({
      projector: this,
      version: ++this._version,
      isCurrent: null,
    });
    this._disposal = this._enqueue(operation, this._defaults, true);
    return this._disposal;
  }

  _enqueue(operation, snapshot, disposal) {
    const apply = () => this._apply(operation, snapshot, disposal);
    const pending = this._queue.then(apply, apply);
    this._queue = pending.then(() => undefined, () => undefined);
    return pending;
  }

  async _apply(operation, snapshot, disposal) {
    if (!this._canApply(operation, disposal)) return staleProjectionResult();

    const current = operation.isCurrent;
    let target = snapshot;
    let reset = disposal;
    if (!disposal && current && !safeIsCurrent(current)) {
      target = this._defaults;
      reset = true;
    }

    const targetIsNeutral = sameSnapshot(target, this._defaults);
    const failNeutralOnError = !reset && !targetIsNeutral;
    const firstPass = await this._applySnapshot(
      operation,
      target,
      disposal,
      current && !reset,
      failNeutralOnError
    );
    if (firstPass.versionStale) return staleProjectionResult(firstPass.error);

    if (firstPass.accountStale && this._canApply(operation, disposal)) {
      const resetPass = await this._applyNeutralSnapshot(operation, disposal);
      if (resetPass.versionStale) return staleProjectionResult(resetPass.error);
      return projectionResult({
        applied: false,
        stale: true,
        reset: true,
        error: resetPass.error,
      });
    }

    if (failNeutralOnError && firstPass.error && this._canApply(operation, disposal)) {
      const resetPass = await this._applyNeutralSnapshot(operation, disposal);
      if (resetPass.versionStale) {
        return staleProjectionResult(firstPass.error || resetPass.error);
      }
      return projectionResult({
        applied: false,
        stale: false,
        reset: true,
        error: firstPass.error || resetPass.error,
      });
    }

    let finalPass = firstPass;
    if ((reset || targetIsNeutral) && firstPass.error) {
      finalPass = await this._applyNeutralSnapshot(operation, disposal, firstPass);
      if (finalPass.versionStale) return staleProjectionResult(finalPass.error);
    }

    return projectionResult({
      applied: !reset && !finalPass.error,
      stale: reset && !disposal,
      reset,
      error: finalPass.error,
    });
  }

  async _applyNeutralSnapshot(operation, disposal, initialPass = null) {
    let pass = initialPass;
    let passCount = initialPass ? 1 : 0;
    while (
      passCount < MAX_NEUTRALIZATION_PASSES
      && (!pass || pass.error)
      && this._canApply(operation, disposal)
    ) {
      pass = await this._applySnapshot(
        operation,
        this._defaults,
        disposal,
        false,
        false
      );
      passCount += 1;
      if (pass.versionStale) break;
    }
    return pass || { error: null, versionStale: true, accountStale: false };
  }

  async _applySnapshot(operation, snapshot, disposal, checkCurrent, stopOnError) {
    let firstError = null;
    for (const key of this._keys) {
      if (!this._canApply(operation, disposal)) {
        return { error: firstError, versionStale: true, accountStale: false };
      }
      if (checkCurrent && !safeIsCurrent(operation.isCurrent)) {
        return { error: firstError, versionStale: false, accountStale: true };
      }

      let keyError = null;
      for (let attempt = 0; attempt < this._attempts; attempt += 1) {
        try {
          await this._executeCommand(SET_CONTEXT_COMMAND, key, snapshot[key]);
          keyError = null;
          break;
        } catch (error) {
          keyError = error;
        }
      }
      if (!firstError && keyError) firstError = keyError;

      if (!this._canApply(operation, disposal)) {
        return { error: firstError, versionStale: true, accountStale: false };
      }
      if (checkCurrent && !safeIsCurrent(operation.isCurrent)) {
        return { error: firstError, versionStale: false, accountStale: true };
      }
      if (keyError && stopOnError) {
        return { error: firstError, versionStale: false, accountStale: false };
      }
    }
    return { error: firstError, versionStale: false, accountStale: false };
  }

  _canApply(operation, disposal) {
    return operation
      && operation.projector === this
      && operation.version === this._version
      && (disposal || !this._disposed);
  }
}

function normalizeDefaults(value) {
  if (!isPlainRecord(value)) {
    throw new TypeError("Context key defaults must be a plain object.");
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length === 0) {
    throw new TypeError("At least one context key default is required.");
  }
  const normalized = {};
  for (const key of keys) {
    if (!isOwnedContextKey(key)) {
      throw new TypeError("Context key names must be owned by the Cloudsmith extension.");
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor)) {
      throw new TypeError("Context key defaults must be data properties.");
    }
    normalized[key] = descriptor.value;
  }
  return Object.freeze(normalized);
}

function normalizeSnapshot(value, keys) {
  if (!isPlainRecord(value)) {
    throw new TypeError("A complete context key snapshot is required.");
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length
    || ownKeys.some(key => typeof key !== "string" || !keys.includes(key))
  ) {
    throw new TypeError("A context key snapshot must contain exactly the configured keys.");
  }
  const normalized = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor)) {
      throw new TypeError("Context key snapshots must use data properties.");
    }
    normalized[key] = descriptor.value;
  }
  return Object.freeze(normalized);
}

function isPlainRecord(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isOwnedContextKey(key) {
  return typeof key === "string"
    && key.startsWith("cloudsmith.")
    && key.length > "cloudsmith.".length;
}

function safeIsCurrent(isCurrent) {
  try {
    return isCurrent() === true;
  } catch {
    return false;
  }
}

function sameSnapshot(left, right) {
  const keys = Object.keys(right);
  return keys.every(key => Object.is(left[key], right[key]));
}

function projectionResult({ applied, stale, reset, error }) {
  return Object.freeze({
    applied: Boolean(applied),
    stale: Boolean(stale),
    reset: Boolean(reset),
    error: error || null,
  });
}

function staleProjectionResult(error = null) {
  return projectionResult({ applied: false, stale: true, reset: false, error });
}

module.exports = {
  ContextKeyProjector,
};

// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const DEFAULT_PERSISTENCE_WAIT_MS = 1_000;
const MAX_PERSISTENCE_WAIT_MS = 5_000;
const UPSTREAM_CACHE_PREFIX = "cloudsmith-upstreams:";

// Physical globalState writes have process-wide ordering semantics: two extension
// activations can briefly overlap while VS Code is replacing an extension host.
// This registry deliberately owns only per-key promise tails and pending keys.
// Account identities, cache values, operation tokens, and cancellation state stay
// on the activation-owned UpstreamCacheLifecycle instance.
const physicalWriteQueues = new WeakMap();

function physicalQueueFor(globalState) {
  let queue = physicalWriteQueues.get(globalState);
  if (!queue) {
    queue = { tails: new Map(), pendingKeys: new Set() };
    physicalWriteQueues.set(globalState, queue);
  }
  return queue;
}

function pendingPhysicalKeys(globalState) {
  return globalState ? [...(physicalWriteQueues.get(globalState)?.pendingKeys || [])] : [];
}

function queuePhysicalWrite(globalState, cacheKey, write) {
  if (!globalState || typeof globalState.update !== "function") return Promise.resolve();
  const queue = physicalQueueFor(globalState);
  queue.pendingKeys.add(cacheKey);
  const previous = queue.tails.get(cacheKey) || Promise.resolve();
  const pending = previous.then(write, write);
  const tail = pending.then(() => undefined, () => undefined);
  queue.tails.set(cacheKey, tail);
  tail.finally(() => {
    if (queue.tails.get(cacheKey) !== tail) return;
    queue.tails.delete(cacheKey);
    queue.pendingKeys.delete(cacheKey);
    if (queue.tails.size === 0) physicalWriteQueues.delete(globalState);
  });
  return pending;
}

function boundedWaitMs(value) {
  return Number.isSafeInteger(value) && value > 0
    ? Math.min(value, MAX_PERSISTENCE_WAIT_MS)
    : DEFAULT_PERSISTENCE_WAIT_MS;
}

async function settleWithin(promise, waitMs) {
  let timeoutHandle = null;
  const timeout = new Promise(resolve => {
    timeoutHandle = setTimeout(() => resolve(false), waitMs);
  });
  try {
    return await Promise.race([
      Promise.resolve(promise).then(() => true, () => true),
      timeout,
    ]);
  } finally {
    if (timeoutHandle !== null) clearTimeout(timeoutHandle);
  }
}

class UpstreamCacheLifecycle {
  constructor(globalState, options = {}) {
    this.globalState = globalState || null;
    this._waitMs = boundedWaitMs(options.persistenceWaitMs);
    this._generation = 0;
    this._operations = new Map();
    this._touchedKeys = new Set();
    this._quarantinedKeys = new Set();
    this._persistenceEnabled = true;
    this._disposed = false;
  }

  begin(cacheKey) {
    if (this._disposed || !this._persistenceEnabled) return null;
    this._touchedKeys.add(cacheKey);
    const token = Object.freeze({
      generation: this._generation,
      id: Symbol(cacheKey),
    });
    this._operations.set(cacheKey, token);
    return token;
  }

  isCurrent(cacheKey, token) {
    return Boolean(
      token
      && !this._disposed
      && token.generation === this._generation
      && this._operations.get(cacheKey) === token
      && this._persistenceEnabled
    );
  }

  finish(cacheKey, token) {
    if (token && this._operations.get(cacheKey) === token) {
      this._operations.delete(cacheKey);
    }
  }

  read(cacheKey) {
    if (
      this._disposed
      || !this._persistenceEnabled
      || !this.globalState
      || typeof this.globalState.get !== "function"
    ) return undefined;
    this._touchedKeys.add(cacheKey);
    return this.globalState.get(cacheKey);
  }

  persist(cacheKey, value, token, guard = () => true) {
    if (!this.isCurrent(cacheKey, token)) return Promise.resolve(false);
    this._touchedKeys.add(cacheKey);
    return queuePhysicalWrite(this.globalState, cacheKey, async () => {
      if (!this.isCurrent(cacheKey, token) || guard() !== true) return false;
      await this.globalState.update(cacheKey, value);
      return true;
    });
  }

  evict(cacheKey) {
    if (!this.globalState || typeof this.globalState.update !== "function") {
      return Promise.resolve(false);
    }
    this._touchedKeys.add(cacheKey);
    return queuePhysicalWrite(this.globalState, cacheKey, async () => {
      await this.globalState.update(cacheKey, undefined);
      return true;
    });
  }

  initialize() {
    return this._purge();
  }

  reset() {
    return this._purge();
  }

  dispose() {
    if (this._disposed) return;
    this._disposed = true;
    this._persistenceEnabled = false;
    this._generation += 1;
    this._operations.clear();
    const keys = this._cacheKeys();
    this._touchedKeys.clear();
    for (const cacheKey of keys) {
      // Deletion remains physically ordered behind any old write. Do not wait
      // for an uncooperative globalState implementation during deactivation.
      queuePhysicalWrite(this.globalState, cacheKey, async () => {
        try {
          await this.globalState.update(cacheKey, undefined);
        } catch {
          console.warn("[UpstreamRuntime] Failed to evict an upstream cache entry.");
        }
      });
    }
    this._quarantinedKeys.clear();
  }

  get activeOperationCount() {
    return this._operations.size;
  }

  get quarantinedKeyCount() {
    return this._quarantinedKeys.size;
  }

  get persistenceEnabled() {
    return !this._disposed && this._persistenceEnabled;
  }

  async _purge() {
    if (this._disposed) return false;
    this._generation += 1;
    this._persistenceEnabled = false;
    this._operations.clear();
    const purgeGeneration = this._generation;
    const keys = this._cacheKeys();
    if (keys.length === 0) {
      this._persistenceEnabled = true;
      return true;
    }
    for (const cacheKey of keys) this._quarantinedKeys.add(cacheKey);

    const deletions = keys.map(cacheKey => queuePhysicalWrite(
      this.globalState,
      cacheKey,
      async () => {
        try {
          await this.globalState.update(cacheKey, undefined);
        } catch (error) {
          console.warn("[UpstreamRuntime] Failed to evict an upstream cache entry.");
          throw error;
        }
      }
    ));
    const completion = Promise.all(deletions).then(
      () => {
        if (!this._disposed && this._generation === purgeGeneration) {
          this._touchedKeys.clear();
          this._quarantinedKeys.clear();
          this._persistenceEnabled = true;
        }
        return true;
      },
      () => false
    );
    const settled = await settleWithin(completion, this._waitMs);
    if (!settled) return false;
    const successful = await completion;
    if (!successful && !this._disposed && this._generation === purgeGeneration) {
      this._persistenceEnabled = false;
    }
    return successful;
  }

  _cacheKeys() {
    const keys = new Set([
      ...this._touchedKeys,
      ...pendingPhysicalKeys(this.globalState),
    ]);
    if (typeof this.globalState?.keys === "function") {
      let persistedKeys = [];
      try {
        persistedKeys = this.globalState.keys();
      } catch {
        persistedKeys = [];
      }
      if (Array.isArray(persistedKeys)) {
        for (const key of persistedKeys) {
          if (typeof key === "string" && key.startsWith(UPSTREAM_CACHE_PREFIX)) keys.add(key);
        }
      }
    }
    return [...keys].filter(key => (
      typeof key === "string" && key.startsWith(UPSTREAM_CACHE_PREFIX)
    ));
  }
}

module.exports = { UpstreamCacheLifecycle };

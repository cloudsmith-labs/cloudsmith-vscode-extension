// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const DEFAULT_UPSTREAM_CONCURRENCY = 4;
const DEFAULT_UPSTREAM_REQUEST_BUDGET = 1000;

class UpstreamOperationScheduler {
  constructor(options = {}) {
    this.concurrency = boundedPositiveInteger(
      options.concurrency,
      DEFAULT_UPSTREAM_CONCURRENCY,
      DEFAULT_UPSTREAM_CONCURRENCY
    );
    this.maxRequests = boundedPositiveInteger(
      options.maxRequests,
      DEFAULT_UPSTREAM_REQUEST_BUDGET,
      DEFAULT_UPSTREAM_REQUEST_BUDGET
    );
    this.requestCount = 0;
    this.acceptedCount = 0;
    this.activeCount = 0;
    this.maxActiveCount = 0;
    this._queue = [];
    this._activeEntries = new Set();
    this._signalRegistrations = new Map();
    this._circuitError = null;
    this._cancelled = false;
  }

  run(task, options = {}) {
    if (typeof task !== "function") {
      return Promise.reject(schedulerError("invalid_task", "The upstream request was invalid."));
    }
    if (this._cancelled || isCancelled(options)) {
      return Promise.reject(schedulerError("cancelled", "The upstream operation was cancelled."));
    }
    if (this._circuitError) {
      return Promise.reject(this._circuitError);
    }
    // Reserve budget when accepting work. This bounds both dispatched requests and the queue.
    if (this.acceptedCount >= this.maxRequests) {
      return Promise.reject(schedulerError(
        "request_limit",
        "The upstream operation reached its request budget."
      ));
    }
    this.acceptedCount += 1;

    return new Promise((resolve, reject) => {
      const entry = {
        task,
        options,
        resolve,
        reject,
        state: "queued",
        retired: false,
        signalRegistration: null,
        cancellationDisposable: null,
        completion: null,
      };
      this._queue.push(entry);
      this._watchCancellation(entry);
      this._drain();
    });
  }

  cancel() {
    if (this._cancelled) return;
    this._cancelled = true;
    const error = schedulerError("cancelled", "The upstream operation was cancelled.");
    this._rejectQueued(error);
    for (const entry of [...this._activeEntries]) this._retireActive(entry, false, error);
  }

  get queuedCount() {
    return this._queue.length;
  }

  get stopped() {
    return this._cancelled || Boolean(this._circuitError) || this.acceptedCount >= this.maxRequests;
  }

  _drain() {
    while (
      !this._cancelled
      && !this._circuitError
      && this.activeCount < this.concurrency
      && this._queue.length > 0
    ) {
      const entry = this._queue.shift();
      if (isCancelled(entry.options)) {
        this._retireQueued(
          entry,
          schedulerError("cancelled", "The upstream operation was cancelled.")
        );
        continue;
      }
      this._dispatch(entry);
    }
  }

  _dispatch(entry) {
    if (entry.retired) return;
    entry.state = "active";
    this._activeEntries.add(entry);
    this.activeCount += 1;
    this.requestCount += 1;
    this.maxActiveCount = Math.max(this.maxActiveCount, this.activeCount);
    let pending;
    try {
      if (this._cancelled || isCancelled(entry.options)) {
        throw schedulerError("cancelled", "The upstream operation was cancelled.");
      }
      pending = Promise.resolve(entry.task());
    } catch (error) {
      this._completeActive(entry, false, error);
      return;
    }
    if (entry.retired) {
      pending.then(() => undefined, () => undefined);
      return;
    }
    // Observe both branches even after cancellation retires the scheduler-visible
    // entry. A non-cooperative transport cannot retain a slot or create a late
    // unhandled rejection.
    const completion = { scheduler: this, entry };
    entry.completion = completion;
    pending.then(
      value => completeDispatchedEntry(completion, true, value),
      error => completeDispatchedEntry(completion, false, error)
    );
  }

  _completeActive(entry, fulfilled, value) {
    if (entry.retired) return;
    if (isRateLimited(value)) {
      this._openRateLimitCircuit(fulfilled ? value.error : value);
    }
    this._retireActive(entry, fulfilled, value);
  }

  _watchCancellation(entry) {
    const options = entry.options;
    const cancelEntry = () => this._cancelEntry(entry);
    if (typeof options.signal?.addEventListener === "function") {
      let registration = this._signalRegistrations.get(options.signal);
      if (!registration) {
        const signal = options.signal;
        registration = {
          entries: new Set(),
          listener: null,
          signal,
        };
        registration.listener = () => {
          for (const watchedEntry of [...registration.entries]) {
            this._cancelEntry(watchedEntry);
          }
        };
        this._signalRegistrations.set(signal, registration);
        signal.addEventListener("abort", registration.listener, { once: true });
      }
      registration.entries.add(entry);
      entry.signalRegistration = registration;
    }
    if (typeof options.cancellationToken?.onCancellationRequested === "function") {
      const disposable = options.cancellationToken.onCancellationRequested(cancelEntry);
      if (entry.retired) disposable?.dispose?.();
      else entry.cancellationDisposable = disposable;
    }
  }

  _cancelEntry(entry) {
    if (entry.retired) return;
    const error = schedulerError("cancelled", "The upstream operation was cancelled.");
    if (entry.state === "active") {
      this._retireActive(entry, false, error);
      return;
    }
    const index = this._queue.indexOf(entry);
    if (index !== -1) this._queue.splice(index, 1);
    this._retireQueued(entry, error);
  }

  _retireQueued(entry, error) {
    if (entry.retired) return;
    const reject = entry.reject;
    entry.retired = true;
    entry.state = "retired";
    this._disposeCancellation(entry);
    this._clearEntry(entry);
    reject(error);
  }

  _retireActive(entry, fulfilled, value) {
    if (entry.retired) return;
    const settle = fulfilled ? entry.resolve : entry.reject;
    entry.retired = true;
    entry.state = "retired";
    this._activeEntries.delete(entry);
    this.activeCount -= 1;
    this._disposeCancellation(entry);
    this._detachCompletion(entry);
    this._clearEntry(entry);
    settle(value);
    this._drain();
  }

  _disposeCancellation(entry) {
    if (entry.signalRegistration) {
      const registration = entry.signalRegistration;
      entry.signalRegistration = null;
      registration.entries.delete(entry);
      if (registration.entries.size === 0) {
        registration.signal.removeEventListener?.("abort", registration.listener);
        this._signalRegistrations.delete(registration.signal);
      }
    }
    entry.cancellationDisposable?.dispose?.();
    entry.cancellationDisposable = null;
  }

  _detachCompletion(entry) {
    if (!entry.completion) return;
    entry.completion.scheduler = null;
    entry.completion.entry = null;
    entry.completion = null;
  }

  _clearEntry(entry) {
    entry.task = null;
    entry.options = null;
    entry.resolve = null;
    entry.reject = null;
  }

  _openRateLimitCircuit(cause) {
    if (this._circuitError) return;
    this._circuitError = schedulerError(
      "rate_limit_circuit",
      "The upstream operation stopped after Cloudsmith rate limiting.",
      cause
    );
    this._rejectQueued(this._circuitError);
  }

  _rejectQueued(error) {
    const queued = this._queue.splice(0);
    for (const entry of queued) this._retireQueued(entry, error);
  }
}

function completeDispatchedEntry(completion, fulfilled, value) {
  const scheduler = completion.scheduler;
  const entry = completion.entry;
  if (!scheduler || !entry) return;
  scheduler._completeActive(entry, fulfilled, value);
}

function isCancelled(options = {}) {
  return Boolean(options.signal?.aborted || options.cancellationToken?.isCancellationRequested);
}

function isRateLimited(value) {
  const candidate = value && value.ok === false && value.error ? value.error : value;
  return Boolean(candidate) && (
    candidate.status === 429
    || candidate.kind === "rate_limited"
    || candidate.code === "rate_limited"
  );
}

function schedulerError(kind, message, cause = null) {
  const error = new Error(message);
  error.name = "UpstreamSchedulerError";
  error.kind = kind;
  error.status = kind === "rate_limit_circuit" ? 429 : null;
  error.cause = cause;
  return error;
}

function boundedPositiveInteger(value, fallback, maximum) {
  return Number.isSafeInteger(value) && value > 0
    ? Math.min(value, maximum)
    : fallback;
}

module.exports = {
  DEFAULT_UPSTREAM_CONCURRENCY,
  DEFAULT_UPSTREAM_REQUEST_BUDGET,
  UpstreamOperationScheduler,
};

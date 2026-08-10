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
      this._queue.push({ task, options, resolve, reject });
      this._drain();
    });
  }

  cancel() {
    if (this._cancelled) return;
    this._cancelled = true;
    this._rejectQueued(schedulerError("cancelled", "The upstream operation was cancelled."));
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
        entry.reject(schedulerError("cancelled", "The upstream operation was cancelled."));
        continue;
      }
      this._dispatch(entry);
    }
  }

  async _dispatch(entry) {
    this.activeCount += 1;
    this.requestCount += 1;
    this.maxActiveCount = Math.max(this.maxActiveCount, this.activeCount);
    try {
      if (this._cancelled || isCancelled(entry.options)) {
        throw schedulerError("cancelled", "The upstream operation was cancelled.");
      }
      const value = await entry.task();
      if (isRateLimited(value)) this._openRateLimitCircuit(value.error);
      entry.resolve(value);
    } catch (error) {
      if (isRateLimited(error)) this._openRateLimitCircuit(error);
      entry.reject(error);
    } finally {
      this.activeCount -= 1;
      this._drain();
    }
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
    for (const entry of queued) entry.reject(error);
  }
}

function isCancelled(options) {
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

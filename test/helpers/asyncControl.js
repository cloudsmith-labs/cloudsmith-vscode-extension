function deferred() {
  let resolvePromise;
  let rejectPromise;
  let settled = false;
  const promise = new Promise((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  return Object.freeze({
    promise,
    get settled() { return settled; },
    resolve(value) {
      if (settled) return false;
      settled = true;
      resolvePromise(value);
      return true;
    },
    reject(error) {
      if (settled) return false;
      settled = true;
      rejectPromise(error);
      return true;
    },
  });
}

function createManualClock(initialNow = 0) {
  if (!Number.isFinite(initialNow)) throw new TypeError("Manual clock start must be finite");
  let current = initialNow;
  let nextId = 0;
  let nextOrder = 0;
  const timers = new Map();

  function setTimeout(callback, delay = 0) {
    if (typeof callback !== "function") throw new TypeError("Timer callback must be a function");
    const normalizedDelay = Number.isFinite(delay) ? Math.max(0, delay) : 0;
    const handle = Object.freeze({ id: ++nextId });
    timers.set(handle, {
      callback,
      due: current + normalizedDelay,
      order: ++nextOrder,
    });
    return handle;
  }

  function clearTimeout(handle) {
    return timers.delete(handle);
  }

  function nextTimer(maximumDue = Infinity) {
    let selected = null;
    for (const [handle, timer] of timers) {
      if (timer.due > maximumDue) continue;
      if (!selected || timer.due < selected.timer.due
        || (timer.due === selected.timer.due && timer.order < selected.timer.order)) {
        selected = { handle, timer };
      }
    }
    return selected;
  }

  async function advanceTo(target) {
    if (!Number.isFinite(target) || target < current) {
      throw new RangeError("Manual clock cannot move backwards");
    }
    let selected = nextTimer(target);
    while (selected) {
      timers.delete(selected.handle);
      current = selected.timer.due;
      await selected.timer.callback();
      selected = nextTimer(target);
    }
    current = target;
  }

  return Object.freeze({
    now: () => current,
    setTimeout,
    clearTimeout,
    advanceBy: delay => advanceTo(current + delay),
    advanceTo,
    async runNext() {
      const selected = nextTimer();
      if (!selected) return false;
      await advanceTo(selected.timer.due);
      return true;
    },
    pendingCount: () => timers.size,
  });
}

function createCancellationSource() {
  const abortController = new AbortController();
  const listeners = new Set();
  let disposed = false;
  let cancelled = false;
  const token = {};
  Object.defineProperties(token, {
    isCancellationRequested: {
      enumerable: true,
      get: () => cancelled,
    },
    onCancellationRequested: {
      enumerable: true,
      value(listener) {
        if (typeof listener !== "function") {
          throw new TypeError("Cancellation listener must be a function");
        }
        if (disposed) return Object.freeze({ dispose() {} });
        if (cancelled) {
          listener();
          return Object.freeze({ dispose() {} });
        }
        listeners.add(listener);
        let active = true;
        return Object.freeze({
          dispose() {
            if (!active) return;
            active = false;
            listeners.delete(listener);
          },
        });
      },
    },
  });
  Object.freeze(token);

  return Object.freeze({
    token,
    signal: abortController.signal,
    cancel() {
      if (cancelled || disposed) return false;
      cancelled = true;
      abortController.abort();
      const current = [...listeners];
      listeners.clear();
      for (const listener of current) listener();
      return true;
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      listeners.clear();
    },
    listenerCount: () => listeners.size,
  });
}

module.exports = { createCancellationSource, createManualClock, deferred };

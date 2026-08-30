const assert = require("assert");
const { UpstreamOperationScheduler } = require("../util/upstreamOperationScheduler");

suite("UpstreamOperationScheduler", () => {
  function deferred() {
    let resolve;
    const promise = new Promise(settle => { resolve = settle; });
    return { promise, resolve };
  }

  async function settleWithin(promise, milliseconds = 250) {
    let timer;
    try {
      return await Promise.race([
        promise,
        new Promise((_resolve, reject) => {
          timer = setTimeout(() => reject(new Error("scheduler did not settle")), milliseconds);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  }

  test("bounds 100 repository-format requests to four active operations", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 4, maxRequests: 1000 });
    const gate = deferred();
    let active = 0;
    let maxActive = 0;
    const work = Array.from({ length: 100 }, (_, index) => scheduler.run(async () => {
      active += 1;
      maxActive = Math.max(maxActive, active);
      await gate.promise;
      active -= 1;
      return index;
    }));

    assert.strictEqual(scheduler.activeCount, 4);
    assert.strictEqual(scheduler.queuedCount, 96);
    gate.resolve();
    assert.deepStrictEqual(
      await settleWithin(Promise.all(work)),
      Array.from({ length: 100 }, (_, index) => index)
    );
    assert.strictEqual(maxActive, 4);
    assert.strictEqual(scheduler.maxActiveCount, 4);
    assert.strictEqual(scheduler.requestCount, 100);
    assert.strictEqual(scheduler.activeCount, 0);
  });

  test("shares one cancellation listener across a queued operation fan-out", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 100 });
    const gate = deferred();
    const listeners = new Set();
    let additions = 0;
    let removals = 0;
    const signal = {
      aborted: false,
      addEventListener(type, listener, options) {
        assert.strictEqual(type, "abort");
        assert.deepStrictEqual(options, { once: true });
        additions += 1;
        listeners.add(listener);
      },
      removeEventListener(type, listener) {
        assert.strictEqual(type, "abort");
        removals += 1;
        listeners.delete(listener);
      },
    };
    const work = Array.from({ length: 100 }, (_, index) => scheduler.run(async () => {
      await gate.promise;
      return index;
    }, { signal }));

    assert.strictEqual(additions, 1);
    assert.strictEqual(listeners.size, 1);
    gate.resolve();
    assert.deepStrictEqual(
      await settleWithin(Promise.all(work)),
      Array.from({ length: 100 }, (_, index) => index)
    );
    assert.strictEqual(removals, 1);
    assert.strictEqual(listeners.size, 0);
  });

  test("one shared abort listener cancels an entire active and queued fan-out", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 100 });
    const listeners = new Set();
    let additions = 0;
    let removals = 0;
    const signal = {
      aborted: false,
      addEventListener(type, listener, options) {
        assert.strictEqual(type, "abort");
        assert.deepStrictEqual(options, { once: true });
        additions += 1;
        listeners.add(listener);
      },
      removeEventListener(type, listener) {
        assert.strictEqual(type, "abort");
        removals += 1;
        listeners.delete(listener);
      },
    };
    const work = Array.from({ length: 100 }, () => scheduler.run(
      () => new Promise(() => undefined),
      { signal }
    ));

    assert.strictEqual(additions, 1);
    assert.strictEqual(listeners.size, 1);
    signal.aborted = true;
    for (const listener of [...listeners]) listener();
    const results = await settleWithin(Promise.allSettled(work));
    assert.ok(results.every(result => (
      result.status === "rejected" && result.reason.kind === "cancelled"
    )));
    assert.strictEqual(removals, 1);
    assert.strictEqual(listeners.size, 0);
    assert.strictEqual(scheduler.activeCount, 0);
    assert.strictEqual(scheduler.queuedCount, 0);
  });

  test("releases a slot after a thrown task and does not starve queued work", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 3 });
    const results = await settleWithin(Promise.allSettled([
      scheduler.run(async () => { throw new Error("request failed"); }),
      scheduler.run(async () => "second"),
      scheduler.run(async () => "third"),
    ]));

    assert.strictEqual(results[0].status, "rejected");
    assert.deepStrictEqual(results.slice(1).map(result => result.value), ["second", "third"]);
    assert.strictEqual(scheduler.activeCount, 0);
    assert.strictEqual(scheduler.requestCount, 3);
  });

  test("opens the rate-limit circuit and rejects queued requests without dispatch", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 1000 });
    const first = scheduler.run(async () => ({
      ok: false,
      error: { kind: "rate_limited", status: 429 },
    }));
    const queued = Array.from({ length: 20 }, () => scheduler.run(async () => ({ ok: true })));

    const [firstResult, ...queuedResults] = await settleWithin(
      Promise.allSettled([first, ...queued])
    );
    assert.strictEqual(firstResult.status, "fulfilled");
    assert.ok(queuedResults.every(result => (
      result.status === "rejected" && result.reason.kind === "rate_limit_circuit"
    )));
    assert.strictEqual(scheduler.requestCount, 1);
    assert.strictEqual(scheduler.activeCount, 0);
  });

  test("cancellation removes queued work and leaves no active slot", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 10 });
    const gate = deferred();
    const token = { isCancellationRequested: false };
    const active = scheduler.run(() => gate.promise);
    const queued = scheduler.run(async () => "must-not-run", { cancellationToken: token });
    token.isCancellationRequested = true;
    gate.resolve("done");

    assert.strictEqual(await settleWithin(active), "done");
    await assert.rejects(settleWithin(queued), error => error.kind === "cancelled");
    assert.strictEqual(scheduler.activeCount, 0);
    assert.strictEqual(scheduler.requestCount, 1);
  });

  test("abort retires non-cooperative active and queued work and observes late rejection", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 10 });
    const controller = new AbortController();
    let rejectLate;
    let queuedDispatched = false;
    const unhandled = [];
    const onUnhandled = reason => unhandled.push(reason);
    process.on("unhandledRejection", onUnhandled);

    try {
      const active = scheduler.run(() => new Promise((_resolve, reject) => {
        rejectLate = reject;
      }), { signal: controller.signal });
      const queued = scheduler.run(async () => {
        queuedDispatched = true;
        return "must-not-run";
      }, { signal: controller.signal });
      assert.strictEqual(scheduler.activeCount, 1);
      assert.strictEqual(scheduler.queuedCount, 1);

      controller.abort();
      const results = await settleWithin(Promise.allSettled([active, queued]));
      assert.ok(results.every(result => (
        result.status === "rejected" && result.reason.kind === "cancelled"
      )));
      assert.strictEqual(queuedDispatched, false);
      assert.strictEqual(scheduler.activeCount, 0);
      assert.strictEqual(scheduler.queuedCount, 0);

      rejectLate(new Error("late scheduler transport failure"));
      await new Promise(resolve => setImmediate(resolve));
      await new Promise(resolve => setImmediate(resolve));
      assert.deepStrictEqual(unhandled, []);
      assert.strictEqual(scheduler.activeCount, 0);
      assert.strictEqual(scheduler.queuedCount, 0);
    } finally {
      process.removeListener("unhandledRejection", onUnhandled);
    }
  });

  test("contains a token that invokes its cancellation callback during registration", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 10 });
    let disposed = 0;
    let dispatched = false;
    const token = {
      isCancellationRequested: false,
      onCancellationRequested(listener) {
        listener();
        return { dispose() { disposed += 1; } };
      },
    };

    await assert.rejects(
      settleWithin(scheduler.run(async () => {
        dispatched = true;
      }, { cancellationToken: token })),
      error => error.kind === "cancelled"
    );
    assert.strictEqual(dispatched, false);
    assert.strictEqual(disposed, 1);
    assert.strictEqual(scheduler.activeCount, 0);
    assert.strictEqual(scheduler.queuedCount, 0);
  });

  test("contains cancellation that becomes visible between acceptance and registration", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 10 });
    let reads = 0;
    let dispatched = false;
    const token = {
      get isCancellationRequested() {
        reads += 1;
        return reads > 1;
      },
    };

    await assert.rejects(
      settleWithin(scheduler.run(async () => {
        dispatched = true;
      }, { cancellationToken: token })),
      error => error.kind === "cancelled"
    );
    assert.strictEqual(dispatched, false);
    assert.ok(reads >= 2);
    assert.strictEqual(scheduler.activeCount, 0);
    assert.strictEqual(scheduler.queuedCount, 0);
  });

  test("disposes successful cancellation registrations and clears retained entry state", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 10 });
    const gate = deferred();
    let disposed = 0;
    const token = {
      isCancellationRequested: false,
      onCancellationRequested() {
        return { dispose() { disposed += 1; } };
      },
    };
    const pending = scheduler.run(() => gate.promise, { cancellationToken: token });
    const entry = [...scheduler._activeEntries][0];
    assert.ok(entry);
    assert.strictEqual(disposed, 0);

    gate.resolve("complete");
    assert.strictEqual(await settleWithin(pending), "complete");
    assert.strictEqual(disposed, 1);
    assert.strictEqual(entry.retired, true);
    assert.strictEqual(entry.state, "retired");
    assert.strictEqual(entry.task, null);
    assert.strictEqual(entry.options, null);
    assert.strictEqual(entry.resolve, null);
    assert.strictEqual(entry.reject, null);
    assert.strictEqual(entry.completion, null);
    assert.strictEqual(scheduler._activeEntries.size, 0);
  });

  test("optional cancellation cleanup tolerates missing disposable methods", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 10 });
    const signal = {
      aborted: false,
      addEventListener() {},
    };
    const token = {
      isCancellationRequested: false,
      onCancellationRequested() { return undefined; },
    };

    assert.strictEqual(
      await settleWithin(scheduler.run(async () => "complete", {
        signal,
        cancellationToken: token,
      })),
      "complete"
    );
    assert.strictEqual(scheduler._signalRegistrations.size, 0);
  });

  test("an active-only abort preserves unrelated queued work", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 10 });
    const controller = new AbortController();
    const active = scheduler.run(() => new Promise(() => undefined), {
      signal: controller.signal,
    });
    const queued = scheduler.run(async () => "queued-complete");

    controller.abort();
    await assert.rejects(
      settleWithin(active),
      error => error.kind === "cancelled"
        && error.message === "The upstream operation was cancelled."
    );
    assert.strictEqual(await settleWithin(queued), "queued-complete");
    assert.strictEqual(scheduler.activeCount, 0);
    assert.strictEqual(scheduler.queuedCount, 0);
  });

  test("queued cancellation clears the retired entry and preserves exact failure copy", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 10 });
    const gate = deferred();
    let cancelQueued;
    const active = scheduler.run(() => gate.promise);
    const queued = scheduler.run(async () => "must-not-run", {
      cancellationToken: {
        isCancellationRequested: false,
        onCancellationRequested(listener) {
          cancelQueued = listener;
          return { dispose() {} };
        },
      },
    });
    const entry = scheduler._queue[0];
    cancelQueued();
    const error = await settleWithin(queued.catch(value => value));

    assert.strictEqual(error.kind, "cancelled");
    assert.strictEqual(error.message, "The upstream operation was cancelled.");
    assert.strictEqual(entry.retired, true);
    assert.strictEqual(entry.state, "retired");
    assert.strictEqual(entry.task, null);
    assert.strictEqual(entry.options, null);
    assert.strictEqual(entry.resolve, null);
    assert.strictEqual(entry.reject, null);
    gate.resolve("active-complete");
    assert.strictEqual(await settleWithin(active), "active-complete");
  });

  test("removes the first canceled queued entry and drains the following request", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 10 });
    const gate = deferred();
    let cancelFirst;
    const active = scheduler.run(() => gate.promise);
    const canceled = scheduler.run(async () => "must-not-run", {
      cancellationToken: {
        isCancellationRequested: false,
        onCancellationRequested(listener) {
          cancelFirst = listener;
          return { dispose() {} };
        },
      },
    });
    const following = scheduler.run(async () => "following-complete");
    const [canceledEntry, followingEntry] = scheduler._queue;

    cancelFirst();
    await assert.rejects(
      settleWithin(canceled),
      error => error.kind === "cancelled"
    );
    assert.deepStrictEqual(scheduler._queue, [followingEntry]);
    assert.strictEqual(canceledEntry.retired, true);

    gate.resolve("active-complete");
    assert.deepStrictEqual(
      await settleWithin(Promise.all([active, following])),
      ["active-complete", "following-complete"]
    );
    assert.strictEqual(scheduler.requestCount, 2);
  });

  test("removes only a canceled second queued entry", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 10 });
    const gate = deferred();
    let cancelSecond;
    const active = scheduler.run(() => gate.promise);
    const first = scheduler.run(async () => "first-complete");
    const canceled = scheduler.run(async () => "must-not-run", {
      cancellationToken: {
        isCancellationRequested: false,
        onCancellationRequested(listener) {
          cancelSecond = listener;
          return { dispose() {} };
        },
      },
    });
    const [firstEntry, canceledEntry] = scheduler._queue;

    cancelSecond();
    await assert.rejects(
      settleWithin(canceled),
      error => error.kind === "cancelled"
    );
    assert.deepStrictEqual(scheduler._queue, [firstEntry]);
    assert.strictEqual(canceledEntry.retired, true);

    gate.resolve("active-complete");
    assert.deepStrictEqual(
      await settleWithin(Promise.all([active, first])),
      ["active-complete", "first-complete"]
    );
    assert.strictEqual(scheduler.requestCount, 2);
  });

  test("async token cancellation with a non-disposable result settles and drains", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 10 });
    let cancelActive;
    const active = scheduler.run(() => new Promise(() => undefined), {
      cancellationToken: {
        isCancellationRequested: false,
        onCancellationRequested(listener) {
          cancelActive = listener;
          return {};
        },
      },
    });
    const following = scheduler.run(async () => "following-complete");
    const callbackError = await new Promise(resolve => {
      setImmediate(() => {
        try {
          cancelActive();
          resolve(null);
        } catch (error) {
          resolve(error);
        }
      });
    });

    assert.strictEqual(callbackError, null);
    await assert.rejects(
      settleWithin(active),
      error => error.kind === "cancelled"
    );
    assert.strictEqual(await settleWithin(following), "following-complete");
    assert.strictEqual(scheduler.activeCount, 0);
    assert.strictEqual(scheduler.queuedCount, 0);
  });

  test("synchronous token cancellation tolerates a disposable with no dispose method", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 10 });
    const token = {
      isCancellationRequested: false,
      onCancellationRequested(listener) {
        listener();
        return {};
      },
    };
    await assert.rejects(
      settleWithin(scheduler.run(async () => "must-not-run", { cancellationToken: token })),
      error => error.kind === "cancelled"
    );
  });

  test("retirement guards make repeated internal settlement harmless", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 10 });
    const gate = deferred();
    const pending = scheduler.run(() => gate.promise);
    const entry = [...scheduler._activeEntries][0];
    gate.resolve("complete");
    await settleWithin(pending);

    assert.doesNotThrow(() => scheduler._retireActive(entry, true, "again"));
    assert.strictEqual(scheduler.activeCount, 0);
    assert.strictEqual(scheduler._activeEntries.size, 0);
  });

  test("rejects accepted work beyond the operation request budget", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 2 });
    assert.strictEqual(await settleWithin(scheduler.run(async () => "first")), "first");
    assert.strictEqual(await settleWithin(scheduler.run(async () => "second")), "second");
    await assert.rejects(
      settleWithin(scheduler.run(async () => "third")),
      error => error.kind === "request_limit"
    );
    assert.strictEqual(scheduler.requestCount, 2);
  });
});

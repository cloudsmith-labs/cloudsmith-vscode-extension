const assert = require("assert");
const { UpstreamOperationScheduler } = require("../util/upstreamOperationScheduler");

suite("UpstreamOperationScheduler", () => {
  function deferred() {
    let resolve;
    const promise = new Promise(settle => { resolve = settle; });
    return { promise, resolve };
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
    assert.deepStrictEqual(await Promise.all(work), Array.from({ length: 100 }, (_, index) => index));
    assert.strictEqual(maxActive, 4);
    assert.strictEqual(scheduler.maxActiveCount, 4);
    assert.strictEqual(scheduler.requestCount, 100);
    assert.strictEqual(scheduler.activeCount, 0);
  });

  test("releases a slot after a thrown task and does not starve queued work", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 3 });
    const results = await Promise.allSettled([
      scheduler.run(async () => { throw new Error("request failed"); }),
      scheduler.run(async () => "second"),
      scheduler.run(async () => "third"),
    ]);

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

    const [firstResult, ...queuedResults] = await Promise.allSettled([first, ...queued]);
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

    assert.strictEqual(await active, "done");
    await assert.rejects(queued, error => error.kind === "cancelled");
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
      const results = await Promise.allSettled([active, queued]);
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
      scheduler.run(async () => {
        dispatched = true;
      }, { cancellationToken: token }),
      error => error.kind === "cancelled"
    );
    assert.strictEqual(dispatched, false);
    assert.strictEqual(disposed, 1);
    assert.strictEqual(scheduler.activeCount, 0);
    assert.strictEqual(scheduler.queuedCount, 0);
  });

  test("rejects accepted work beyond the operation request budget", async () => {
    const scheduler = new UpstreamOperationScheduler({ concurrency: 1, maxRequests: 2 });
    assert.strictEqual(await scheduler.run(async () => "first"), "first");
    assert.strictEqual(await scheduler.run(async () => "second"), "second");
    await assert.rejects(
      scheduler.run(async () => "third"),
      error => error.kind === "request_limit"
    );
    assert.strictEqual(scheduler.requestCount, 2);
  });
});

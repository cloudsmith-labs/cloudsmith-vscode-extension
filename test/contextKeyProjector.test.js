// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const { ContextKeyProjector } = require("../util/contextKeyProjector");

suite("ContextKeyProjector", () => {
  test("requires complete Cloudsmith-owned data-property snapshots", async () => {
    const projector = createProjector(async () => {});

    assert.throws(
      () => projector.project({ "cloudsmith.testFirst": true }),
      /exactly the configured keys/
    );
    assert.throws(
      () => projector.project({
        "cloudsmith.testFirst": true,
        "cloudsmith.testSecond": false,
        "third.party": true,
      }),
      /exactly the configured keys/
    );
    const accessorSnapshot = { "cloudsmith.testFirst": true };
    Object.defineProperty(accessorSnapshot, "cloudsmith.testSecond", { get() { return true; } });
    assert.throws(() => projector.project(accessorSnapshot), /data properties/);

    await projector.dispose();
  });

  test("serializes full snapshots and lets only the newest generation finish", async () => {
    const firstStarted = deferred();
    const releaseFirst = deferred();
    const values = new Map();
    let calls = 0;
    const projector = createProjector(async (_command, key, value) => {
      calls += 1;
      if (calls === 1) {
        firstStarted.resolve();
        await releaseFirst.promise;
      }
      values.set(key, value);
    });

    const oldProjection = projector.project(snapshot(true, true));
    await firstStarted.promise;
    const newProjection = projector.project(snapshot(false, true));
    releaseFirst.resolve();

    assert.strictEqual((await oldProjection).stale, true);
    assert.strictEqual((await newProjection).applied, true);
    assert.deepStrictEqual([...values], [
      ["cloudsmith.testFirst", false],
      ["cloudsmith.testSecond", true],
    ]);
    await projector.dispose();
  });

  test("a replacement projector supersedes delayed cleanup from the prior activation", async () => {
    const cleanupStarted = deferred();
    const releaseCleanup = deferred();
    const values = new Map();
    let holdCleanup = false;
    const executeCommand = async (_command, key, value) => {
      if (holdCleanup && key === "cloudsmith.testFirst" && value === false) {
        cleanupStarted.resolve();
        await releaseCleanup.promise;
      }
      values.set(key, value);
    };
    const oldProjector = createProjector(executeCommand);
    await oldProjector.project(snapshot(true, true));
    holdCleanup = true;
    const oldCleanup = oldProjector.dispose();
    await cleanupStarted.promise;

    const replacement = createProjector(executeCommand);
    const replacementProjection = replacement.project(snapshot(true, true));
    releaseCleanup.resolve();

    await oldCleanup;
    assert.strictEqual((await replacementProjection).applied, true);
    assert.deepStrictEqual([...values], [
      ["cloudsmith.testFirst", true],
      ["cloudsmith.testSecond", true],
    ]);
    await replacement.dispose();
  });

  test("reprojects neutral values with bounded retries when authority changes during an await", async () => {
    const firstStarted = deferred();
    const releaseFirst = deferred();
    const values = new Map();
    let current = true;
    let positiveCalls = 0;
    let rejectedNeutralWrite = false;
    const calls = [];
    const projector = createProjector(async (_command, key, value) => {
      calls.push([key, value]);
      if (value === true) positiveCalls += 1;
      if (positiveCalls === 1 && value === true) {
        firstStarted.resolve();
        await releaseFirst.promise;
      }
      if (value === false && key === "cloudsmith.testFirst" && !rejectedNeutralWrite) {
        rejectedNeutralWrite = true;
        throw new Error("transient neutral write failure");
      }
      values.set(key, value);
    });
    const operation = projector.begin({ isCurrent: () => current });
    const projection = projector.project(snapshot(true, true), { operation });

    await firstStarted.promise;
    current = false;
    releaseFirst.resolve();

    const result = await projection;
    assert.strictEqual(result.applied, false);
    assert.strictEqual(result.stale, true);
    assert.strictEqual(result.reset, true);
    assert.strictEqual(result.error, null);
    assert.deepStrictEqual([...values], [
      ["cloudsmith.testFirst", false],
      ["cloudsmith.testSecond", false],
    ]);
    assert.deepStrictEqual(calls, [
      ["cloudsmith.testFirst", true],
      ["cloudsmith.testFirst", false],
      ["cloudsmith.testSecond", false],
      ["cloudsmith.testFirst", false],
      ["cloudsmith.testSecond", false],
    ]);
    await projector.dispose();
  });

  test("fails neutral when a positive write is rejected", async () => {
    const calls = [];
    const values = new Map();
    const rejection = new Error("positive write rejected");
    const projector = createProjector(async (_command, key, value) => {
      calls.push([key, value]);
      if (key === "cloudsmith.testSecond" && value === true) throw rejection;
      values.set(key, value);
    }, { attempts: 2 });

    const result = await projector.project(snapshot(true, true));

    assert.strictEqual(result.applied, false);
    assert.strictEqual(result.stale, false);
    assert.strictEqual(result.reset, true);
    assert.strictEqual(result.error, rejection);
    assert.deepStrictEqual(calls, [
      ["cloudsmith.testFirst", true],
      ["cloudsmith.testSecond", true],
      ["cloudsmith.testSecond", true],
      ["cloudsmith.testFirst", false],
      ["cloudsmith.testSecond", false],
    ]);
    assert.deepStrictEqual([...values], [
      ["cloudsmith.testFirst", false],
      ["cloudsmith.testSecond", false],
    ]);
    await projector.dispose();
  });

  test("retries a transient explicit neutral reset with the default attempt count", async () => {
    const calls = [];
    const values = new Map();
    let rejectReset = false;
    let resetFailures = 0;
    const projector = createProjector(async (_command, key, value) => {
      calls.push([key, value]);
      if (rejectReset && key === "cloudsmith.testFirst" && value === false && resetFailures === 0) {
        resetFailures += 1;
        throw new Error("transient reset failure");
      }
      values.set(key, value);
    });

    assert.strictEqual((await projector.project(snapshot(true, true))).applied, true);
    calls.length = 0;
    rejectReset = true;

    const result = await projector.project(snapshot(false, false));

    assert.strictEqual(result.applied, true);
    assert.strictEqual(result.error, null);
    assert.deepStrictEqual(calls, [
      ["cloudsmith.testFirst", false],
      ["cloudsmith.testSecond", false],
      ["cloudsmith.testFirst", false],
      ["cloudsmith.testSecond", false],
    ]);
    assert.deepStrictEqual([...values], [
      ["cloudsmith.testFirst", false],
      ["cloudsmith.testSecond", false],
    ]);
    await projector.dispose();
  });

  test("bounds a persistent explicit neutral reset failure and reports the stale key", async () => {
    const calls = [];
    const values = new Map();
    const persistentFailure = new Error("persistent reset failure");
    let rejectReset = false;
    const projector = createProjector(async (_command, key, value) => {
      calls.push([key, value]);
      if (rejectReset && key === "cloudsmith.testFirst" && value === false) {
        throw persistentFailure;
      }
      values.set(key, value);
    });

    assert.strictEqual((await projector.project(snapshot(true, true))).applied, true);
    calls.length = 0;
    rejectReset = true;

    const result = await projector.project(snapshot(false, false));

    assert.strictEqual(result.applied, false);
    assert.strictEqual(result.stale, false);
    assert.strictEqual(result.reset, false);
    assert.strictEqual(result.error, persistentFailure);
    assert.deepStrictEqual(calls, [
      ["cloudsmith.testFirst", false],
      ["cloudsmith.testSecond", false],
      ["cloudsmith.testFirst", false],
      ["cloudsmith.testSecond", false],
    ]);
    assert.deepStrictEqual([...values], [
      ["cloudsmith.testFirst", true],
      ["cloudsmith.testSecond", false],
    ]);

    rejectReset = false;
    await projector.dispose();
  });

  test("dispose invalidates pending work, resets every key, and is idempotent", async () => {
    const firstStarted = deferred();
    const releaseFirst = deferred();
    const values = new Map();
    const calls = [];
    let rejectedNeutralWrite = false;
    const projector = createProjector(async (_command, key, value) => {
      calls.push([key, value]);
      if (calls.length === 1) {
        firstStarted.resolve();
        await releaseFirst.promise;
      }
      if (value === false && key === "cloudsmith.testFirst" && !rejectedNeutralWrite) {
        rejectedNeutralWrite = true;
        throw new Error("transient disposal reset failure");
      }
      values.set(key, value);
    });
    const pending = projector.project(snapshot(true, true));
    await firstStarted.promise;
    const firstDisposal = projector.dispose();
    const secondDisposal = projector.dispose();
    assert.strictEqual(firstDisposal, secondDisposal);
    releaseFirst.resolve();

    assert.strictEqual((await pending).stale, true);
    const disposal = await firstDisposal;
    assert.strictEqual(disposal.reset, true);
    assert.strictEqual(disposal.error, null);
    assert.deepStrictEqual([...values], [
      ["cloudsmith.testFirst", false],
      ["cloudsmith.testSecond", false],
    ]);
    assert.deepStrictEqual(calls, [
      ["cloudsmith.testFirst", true],
      ["cloudsmith.testFirst", false],
      ["cloudsmith.testSecond", false],
      ["cloudsmith.testFirst", false],
      ["cloudsmith.testSecond", false],
    ]);
    assert.strictEqual(
      (await projector.project(snapshot(true, true))).stale,
      true
    );
  });
});

function createProjector(executeCommand, options = {}) {
  return new ContextKeyProjector({
    defaults: {
      "cloudsmith.testFirst": false,
      "cloudsmith.testSecond": false,
    },
    executeCommand,
    attempts: options.attempts,
  });
}

function snapshot(first, second) {
  return {
    "cloudsmith.testFirst": first,
    "cloudsmith.testSecond": second,
  };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

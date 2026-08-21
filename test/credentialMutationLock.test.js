const assert = require("assert");
const { spawn } = require("child_process");
const { EventEmitter } = require("events");
const net = require("net");
const { CredentialMutationLock, LOCK_HOST } = require("../util/credentialMutationLock");

function deferred() {
  let resolve;
  const promise = new Promise(res => { resolve = res; });
  return { promise, resolve };
}

function availablePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen({ host: LOCK_HOST, port: 0, exclusive: true }, () => {
      const port = server.address().port;
      server.close(error => error ? reject(error) : resolve(port));
    });
  });
}

function waitForChildLine(child, expected) {
  return new Promise((resolve, reject) => {
    let output = "";
    const timeout = setTimeout(() => reject(new Error("child lock-holder timed out")), 5000);
    child.stdout.on("data", chunk => {
      output += chunk.toString("utf8");
      if (output.includes(expected)) {
        clearTimeout(timeout);
        resolve();
      }
    });
    child.once("error", error => { clearTimeout(timeout); reject(error); });
    child.once("exit", code => {
      if (!output.includes(expected)) {
        clearTimeout(timeout);
        reject(new Error(`child lock-holder exited before readiness (${code})`));
      }
    });
  });
}

suite("cross-host credential mutation lock", () => {
  test("serializes the whole transaction across independent lock instances", async () => {
    const port = await availablePort();
    const first = new CredentialMutationLock(null, { enabled: true, port });
    const second = new CredentialMutationLock(null, { enabled: true, port });
    const release = deferred();
    const acquired = deferred();
    const order = [];
    const one = first.run(async () => {
      order.push("first-start");
      acquired.resolve();
      await release.promise;
      order.push("first-end");
    });
    await acquired.promise;
    const two = second.run(async () => { order.push("second"); });
    await new Promise(resolve => setTimeout(resolve, 75));
    assert.deepStrictEqual(order, ["first-start"]);
    release.resolve();
    await Promise.all([one, two]);
    assert.deepStrictEqual(order, ["first-start", "first-end", "second"]);
  });

  test("serializes a simultaneous multi-host contention burst", async () => {
    const port = await availablePort();
    let active = 0;
    let maximum = 0;
    const completions = await Promise.all(Array.from({ length: 12 }, (_, index) => (
      new CredentialMutationLock(null, { enabled: true, port }).run(async () => {
        active += 1;
        maximum = Math.max(maximum, active);
        await new Promise(resolve => setTimeout(resolve, 2));
        active -= 1;
        return index;
      })
    )));
    assert.strictEqual(maximum, 1);
    assert.deepStrictEqual(completions.sort((left, right) => left - right), [...Array(12).keys()]);
  });

  test("the kernel-owned mutex does not expire while its owner is suspended", async () => {
    const port = await availablePort();
    const first = new CredentialMutationLock(null, { enabled: true, port });
    const second = new CredentialMutationLock(null, { enabled: true, port });
    const lease = await first.acquire();
    let entered = false;
    const contender = second.run(async () => { entered = true; });
    await new Promise(resolve => setTimeout(resolve, 150));
    assert.strictEqual(entered, false);
    await lease.release();
    await contender;
    assert.strictEqual(entered, true);
  });

  test("a cancelled contender never enters and release is idempotent", async () => {
    const port = await availablePort();
    const first = new CredentialMutationLock(null, { enabled: true, port });
    const second = new CredentialMutationLock(null, { enabled: true, port });
    const lease = await first.acquire();
    const controller = new AbortController();
    const contender = second.run(async () => "must-not-run", { signal: controller.signal });
    await new Promise(resolve => setTimeout(resolve, 25));
    controller.abort();
    await assert.rejects(contender, error => error.kind === "cancelled");
    await lease.release();
    await lease.release();
    assert.strictEqual(await second.run(async () => "entered"), "entered");
  });

  test("rechecks cancellation after bind and before invoking the protected task", async () => {
    const controller = new AbortController();
    class FakeServer extends EventEmitter {
      constructor() { super(); this.listening = false; }
      listen() {
        this.listening = true;
        this.emit("listening");
        controller.abort();
      }
      close(callback) { this.listening = false; callback?.(); }
      unref() {}
    }
    let entered = false;
    const lock = new CredentialMutationLock(null, {
      enabled: true,
      createServer: () => new FakeServer(),
    });
    await assert.rejects(
      lock.run(async () => { entered = true; }, { signal: controller.signal }),
      error => error.kind === "cancelled"
    );
    assert.strictEqual(entered, false);
  });

  test("an occupied mutex fails closed and a throwing task still releases it", async () => {
    const port = await availablePort();
    const blocker = net.createServer();
    await new Promise((resolve, reject) => {
      blocker.once("error", reject);
      blocker.listen({ host: LOCK_HOST, port, exclusive: true }, resolve);
    });
    try {
      let entered = false;
      const blocked = new CredentialMutationLock(null, { enabled: true, port, waitMs: 25 });
      await assert.rejects(
        blocked.run(async () => { entered = true; }),
        error => error.kind === "credential_lock_failed"
      );
      assert.strictEqual(entered, false);
    } finally {
      await new Promise(resolve => blocker.close(resolve));
    }
    const lock = new CredentialMutationLock(null, { enabled: true, port });
    await assert.rejects(lock.run(async () => { throw new Error("task failed"); }), /task failed/);
    assert.strictEqual(await lock.run(async () => "reacquired"), "reacquired");
  });

  test("the operating system releases the mutex when an extension-host process exits", async () => {
    const port = await availablePort();
    const script = [
      "const http=require('http')",
      `const server=http.createServer((_q,r)=>r.end()).listen(${port},'${LOCK_HOST}',()=>process.stdout.write('ready\\n'))`,
      "setInterval(()=>{},1000)",
    ].join(";");
    const child = spawn(process.execPath, ["-e", script], { stdio: ["ignore", "pipe", "pipe"] });
    try {
      await waitForChildLine(child, "ready");
      child.kill();
      await new Promise(resolve => child.once("exit", resolve));
      const lock = new CredentialMutationLock(null, { enabled: true, port });
      assert.strictEqual(await lock.run(async () => "recovered"), "recovered");
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill();
    }
  });
});

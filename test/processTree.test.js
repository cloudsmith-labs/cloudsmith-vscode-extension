// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const { spawn } = require("child_process");
const { EventEmitter } = require("events");

suite("owned qualification process trees", () => {
  test("escalates across the entire owned tree and proves final exit", async () => {
    const { terminateProcessTree } = require("../scripts/quality/process-tree");
    const child = new EventEmitter();
    child.pid = 4242;
    child.exitCode = null;
    child.signalCode = null;
    const waits = [false, false, true];
    const signals = [];
    const result = await terminateProcessTree(child, {
      waitForTreeExit: async () => waits.shift(),
      signalTree: (_ownedChild, signal) => {
        signals.push(signal);
        return true;
      },
    });
    assert.strictEqual(result, true);
    assert.deepStrictEqual(signals, ["SIGTERM", "SIGKILL"]);
  });

  test("fails closed when descendants remain after forced termination", async () => {
    const { terminateProcessTree } = require("../scripts/quality/process-tree");
    const child = new EventEmitter();
    child.pid = 4243;
    child.exitCode = null;
    child.signalCode = null;
    const result = await terminateProcessTree(child, {
      waitForTreeExit: async () => false,
      signalTree: () => true,
    });
    assert.strictEqual(result, false);
  });

  test("terminates a real synthetic leader and hanging descendant as one POSIX group", async function () {
    if (process.platform === "win32") this.skip();
    const {
      defaultTreeAlive,
      terminateProcessTree,
    } = require("../scripts/quality/process-tree");
    const child = spawn(process.execPath, [
      "-e",
      [
        "const {spawn}=require('child_process');",
        "spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});",
        "setInterval(()=>{},1000);",
      ].join(""),
    ], { detached: true, stdio: "ignore" });
    await new Promise(resolve => setTimeout(resolve, 100));
    const result = await terminateProcessTree(child, {
      gracefulTimeout: 100,
      termTimeout: 2_000,
      killTimeout: 2_000,
    });
    assert.strictEqual(result, true);
    assert.strictEqual(defaultTreeAlive(child), false);
  });
});

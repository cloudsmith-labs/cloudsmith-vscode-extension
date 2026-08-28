// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const {
  NON_AUTH_CLEANUP_TAINT_ENV,
  cleanupNonAuthQualityEnvironment,
  createNonAuthQualityEnvironment,
  expectedExactCleanupTreeEntry,
  preserveNonAuthCleanupSubtree,
  removeExactOwnedDirectoryTree,
} = require("../scripts/quality/non-auth-environment");
const {
  withExpectedCleanupTaint,
} = require("./helpers/expectedCleanupTaint");

const ROOT = path.resolve(__dirname, "..");

function rootIdentity(target) {
  const stat = fs.lstatSync(target, { bigint: true });
  return Object.freeze({ dev: String(stat.dev), ino: String(stat.ino) });
}

function removeExactFixtureTree(target) {
  const identity = rootIdentity(target);
  const entries = fs.readdirSync(target).sort().map(name => (
    expectedExactCleanupTreeEntry(path.join(target, name), {
      errorMessage: "Expected cleanup taint fixture cleanup refused an unsafe tree.",
    })
  ));
  return removeExactOwnedDirectoryTree(target, {
    errorMessage: "Expected cleanup taint fixture cleanup refused an unsafe tree.",
    expectedRootEntries: entries,
    expectedRootIdentity: identity,
  });
}

function withOpaqueInheritedCapability(value, callback) {
  const saved = {
    present: Object.prototype.hasOwnProperty.call(process.env, NON_AUTH_CLEANUP_TAINT_ENV),
    value: process.env[NON_AUTH_CLEANUP_TAINT_ENV],
  };
  process.env[NON_AUTH_CLEANUP_TAINT_ENV] = value;
  try {
    return callback();
  } finally {
    if (saved.present) {
      process.env[NON_AUTH_CLEANUP_TAINT_ENV] = saved.value;
    } else {
      delete process.env[NON_AUTH_CLEANUP_TAINT_ENV];
    }
  }
}

suite("Expected cleanup taint test sink", () => {
  test("uses a private exact sink, latches the real protocol, and restores opaquely", () => {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "expected-cleanup-taint-private-",
    )));
    const inherited = "opaque-synthetic-parent-cleanup-capability";
    try {
      const value = withOpaqueInheritedCapability(inherited, () => {
        const scoped = withExpectedCleanupTaint(({ receipt, root }) => {
          const rootStat = fs.lstatSync(root, { bigint: true });
          const receiptStat = fs.lstatSync(receipt, { bigint: true });
          assert.strictEqual(rootStat.isDirectory(), true);
          assert.strictEqual(receiptStat.isFile(), true);
          assert.strictEqual(receiptStat.nlink, 1n);
          assert.strictEqual(receiptStat.size, 0n);
          if (process.platform !== "win32") {
            assert.strictEqual(rootStat.mode & 0o077n, 0n);
            assert.strictEqual(receiptStat.mode & 0o077n, 0n);
          }
          assert.strictEqual(
            preserveNonAuthCleanupSubtree(path.join(root, "expected-refusal")),
            false,
          );
          return "scoped-result";
        }, { temporaryParent: scratch });
        assert.strictEqual(process.env[NON_AUTH_CLEANUP_TAINT_ENV], inherited);
        return scoped;
      });
      assert.strictEqual(value, "scoped-result");
      assert.deepStrictEqual(fs.readdirSync(scratch), []);
    } finally {
      fs.rmdirSync(scratch);
    }
  });

  test("supports awaited callbacks while rejecting overlap and nesting", async () => {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "expected-cleanup-taint-async-",
    )));
    let release;
    let started;
    try {
      const pending = withExpectedCleanupTaint(async ({ root }) => {
        started = true;
        await new Promise(resolve => {
          release = resolve;
        });
        assert.throws(
          () => withExpectedCleanupTaint(() => null, { temporaryParent: scratch }),
          /already active/u,
        );
        preserveNonAuthCleanupSubtree(path.join(root, "expected-async-refusal"));
        return 42;
      }, { temporaryParent: scratch });
      assert.strictEqual(started, true);
      assert.throws(
        () => withExpectedCleanupTaint(() => null, { temporaryParent: scratch }),
        /already active/u,
      );
      release();
      assert.strictEqual(await pending, 42);
      assert.deepStrictEqual(fs.readdirSync(scratch), []);
    } finally {
      fs.rmdirSync(scratch);
    }
  });

  test("restores and exactly cleans on callback failure and missing taint", () => {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "expected-cleanup-taint-errors-",
    )));
    const marker = new Error("synthetic scoped callback failure");
    const inherited = "opaque-synthetic-restoration-capability";
    try {
      withOpaqueInheritedCapability(inherited, () => {
        assert.throws(
          () => withExpectedCleanupTaint(({ root }) => {
            preserveNonAuthCleanupSubtree(path.join(root, "expected-error-refusal"));
            throw marker;
          }, { temporaryParent: scratch }),
          error => error === marker,
        );
        assert.strictEqual(process.env[NON_AUTH_CLEANUP_TAINT_ENV], inherited);
        assert.throws(
          () => withExpectedCleanupTaint(() => "missing", { temporaryParent: scratch }),
          /was not latched/u,
        );
        assert.strictEqual(process.env[NON_AUTH_CLEANUP_TAINT_ENV], inherited);
      });
      assert.deepStrictEqual(fs.readdirSync(scratch), []);
    } finally {
      fs.rmdirSync(scratch);
    }
  });

  test("does not weaken a real unscoped child-to-parent cleanup refusal", () => {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "expected-cleanup-taint-propagation-",
    )));
    if (process.platform !== "win32") fs.chmodSync(scratch, 0o700);
    try {
      const cleanOuter = createNonAuthQualityEnvironment({
        environment: { PATH: process.env.PATH || "/usr/bin:/bin" },
        temporaryParent: scratch,
      });
      withExpectedCleanupTaint(({ root }) => {
        preserveNonAuthCleanupSubtree(path.join(root, "expected-local-refusal"));
      }, { temporaryParent: scratch });
      assert.strictEqual(cleanupNonAuthQualityEnvironment(cleanOuter), true);

      const taintedOuter = createNonAuthQualityEnvironment({
        environment: { PATH: process.env.PATH || "/usr/bin:/bin" },
        temporaryParent: scratch,
      });
      const childScript = [
        `const boundary=require(${JSON.stringify(path.join(
          ROOT,
          "scripts/quality/non-auth-environment.js",
        ))});`,
        "const path=require('path');",
        "const target=path.join(process.env.TMPDIR,'unscoped-child-refusal');",
        "process.exitCode=boundary.preserveNonAuthCleanupSubtree(target)===false?0:1;",
      ].join("");
      const child = spawnSync(process.execPath, ["-e", childScript], {
        cwd: ROOT,
        encoding: "utf8",
        env: taintedOuter.environment,
      });
      assert.strictEqual(child.status, 0, child.stderr);
      assert.strictEqual(child.stdout, "");
      withExpectedCleanupTaint(() => {
        assert.throws(
          () => cleanupNonAuthQualityEnvironment(taintedOuter),
          /preserved an unsafe or changed tree/u,
        );
      }, { temporaryParent: scratch });
    } finally {
      if (fs.existsSync(scratch)) removeExactFixtureTree(scratch);
    }
  });
});

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const {
  DEPENDENCY_FILE_ERROR_CODES,
  MAX_DEPENDENCY_FILE_BYTES,
  readBoundedDirectoryEntries,
  readJson,
  readUtf8,
} = require("../../util/lockfileParsers/shared");
const {
  makeTempWorkspace,
  removeDirectory,
  writeTextFile,
} = require("../helpers/fixtureWorkspace");

suite("Lockfile parser safety Test Suite", () => {
  const tempDirs = [];

  suiteTeardown(async () => {
    await Promise.all(tempDirs.map((tempDir) => removeDirectory(tempDir)));
  });

  async function createWorkspace(prefix) {
    const workspace = await makeTempWorkspace(prefix);
    tempDirs.push(workspace);
    return workspace;
  }

  test("reads a normal dependency file inside the workspace", async () => {
    const workspace = await createWorkspace("cloudsmith-normal-lockfile-");
    const lockfilePath = path.join(workspace, "package-lock.json");
    await writeTextFile(lockfilePath, '{"lockfileVersion":3}\n');

    assert.strictEqual(await readUtf8(lockfilePath, workspace), '{"lockfileVersion":3}\n');
  });

  test("distinguishes a missing dependency file", async () => {
    const workspace = await createWorkspace("cloudsmith-missing-lockfile-");

    await assert.rejects(
      () => readUtf8(path.join(workspace, "missing.lock"), workspace),
      (error) => error.code === DEPENDENCY_FILE_ERROR_CODES.MISSING
        && /does not exist/.test(error.message)
    );
  });

  test("rejects path traversal outside the workspace", async () => {
    const workspace = await createWorkspace("cloudsmith-traversal-lockfile-");

    await assert.rejects(
      () => readUtf8(path.join(workspace, "..", "outside.lock"), workspace),
      (error) => error.code === DEPENDENCY_FILE_ERROR_CODES.OUTSIDE_WORKSPACE
        && /outside the workspace folder/.test(error.message)
    );
  });

  test("rejects absolute paths outside the workspace", async () => {
    const workspace = await createWorkspace("cloudsmith-workspace-lockfile-");
    const outsideWorkspace = await createWorkspace("cloudsmith-outside-lockfile-");
    const outsidePath = path.join(outsideWorkspace, "package-lock.json");
    await writeTextFile(outsidePath, "{}\n");

    await assert.rejects(
      () => readUtf8(outsidePath, workspace),
      (error) => error.code === DEPENDENCY_FILE_ERROR_CODES.OUTSIDE_WORKSPACE
    );
  });

  test("allows an in-workspace symlink whose target stays in the workspace", async () => {
    const workspace = await createWorkspace("cloudsmith-inside-symlink-");
    const targetPath = path.join(workspace, "locks", "package-lock.json");
    const symlinkPath = path.join(workspace, "package-lock.json");
    await writeTextFile(targetPath, "{}\n");
    await fs.promises.symlink(targetPath, symlinkPath, "file");

    assert.strictEqual(await readUtf8(symlinkPath, workspace), "{}\n");
  });

  test("rejects an in-workspace symlink whose target escapes the workspace", async () => {
    const workspace = await createWorkspace("cloudsmith-escaping-symlink-");
    const outsideWorkspace = await createWorkspace("cloudsmith-symlink-target-");
    const outsidePath = path.join(outsideWorkspace, "package-lock.json");
    const symlinkPath = path.join(workspace, "package-lock.json");
    await writeTextFile(outsidePath, "{}\n");
    await fs.promises.symlink(outsidePath, symlinkPath, "file");

    await assert.rejects(
      () => readUtf8(symlinkPath, workspace),
      (error) => error.code === DEPENDENCY_FILE_ERROR_CODES.SYMLINK_ESCAPE
        && /symlink targets/.test(error.message)
    );
  });

  test("validates and reads through one file handle", async () => {
    const workspace = await createWorkspace("cloudsmith-file-handle-");
    const lockfilePath = path.join(workspace, "package-lock.json");
    const content = Buffer.from('{"lockfileVersion":3}\n');
    await writeTextFile(lockfilePath, content.toString("utf8"));

    const originalOpen = fs.promises.open;
    const originalReadFile = fs.promises.readFile;
    const safeLockfilePath = await fs.promises.realpath(lockfilePath);
    const calls = [];
    fs.promises.open = async (openedPath, flags) => {
      if (openedPath !== safeLockfilePath) {
        return originalOpen(openedPath, flags);
      }
      calls.push("open");
      if (Number.isInteger(fs.constants.O_NOFOLLOW)) {
        assert.strictEqual((flags & fs.constants.O_NOFOLLOW) !== 0, true);
      }
      const actualHandle = await originalOpen(openedPath, flags);
      return {
        async stat(options) {
          calls.push("stat");
          return actualHandle.stat(options);
        },
        async read(...args) {
          calls.push("read");
          return actualHandle.read(...args);
        },
        async close() {
          calls.push("close");
          return actualHandle.close();
        },
      };
    };
    fs.promises.readFile = async (readPath, ...args) => {
      if (readPath === safeLockfilePath) {
        throw new Error("readUtf8 must not reopen a validated pathname");
      }
      return originalReadFile(readPath, ...args);
    };

    try {
      assert.strictEqual(await readUtf8(lockfilePath, workspace), content.toString("utf8"));
      assert.deepStrictEqual(calls, ["open", "stat", "read", "read", "close"]);
    } finally {
      fs.promises.open = originalOpen;
      fs.promises.readFile = originalReadFile;
    }
  });

  test("rejects an ancestor replaced with an outside symlink during open", async () => {
    const workspace = await createWorkspace("cloudsmith-ancestor-race-");
    const outsideWorkspace = await createWorkspace("cloudsmith-ancestor-race-target-");
    const controlledDirectory = path.join(workspace, "controlled");
    const movedDirectory = path.join(workspace, "controlled-original");
    const lockfilePath = path.join(controlledDirectory, "package-lock.json");
    await writeTextFile(lockfilePath, "inside\n");
    await writeTextFile(path.join(outsideWorkspace, "package-lock.json"), "outside\n");
    const safeLockfilePath = await fs.promises.realpath(lockfilePath);

    const originalOpen = fs.promises.open;
    let moved = false;
    let symlinkCreated = false;
    fs.promises.open = async (openedPath, flags) => {
      if (!moved && openedPath === safeLockfilePath) {
        await fs.promises.rename(controlledDirectory, movedDirectory);
        moved = true;
        await fs.promises.symlink(outsideWorkspace, controlledDirectory, "dir");
        symlinkCreated = true;
      }
      return originalOpen(openedPath, flags);
    };

    try {
      await assert.rejects(
        () => readUtf8(lockfilePath, workspace),
        (error) => error.code === DEPENDENCY_FILE_ERROR_CODES.CHANGED
      );
    } finally {
      fs.promises.open = originalOpen;
      if (symlinkCreated) {
        await fs.promises.unlink(controlledDirectory);
      }
      if (moved) {
        await fs.promises.rename(movedDirectory, controlledDirectory);
      }
    }
  });

  test("rejects a final file replaced with a symlink during open", async () => {
    const workspace = await createWorkspace("cloudsmith-final-race-");
    const outsideWorkspace = await createWorkspace("cloudsmith-final-race-target-");
    const lockfilePath = path.join(workspace, "package-lock.json");
    const movedLockfilePath = path.join(workspace, "package-lock.original.json");
    const outsidePath = path.join(outsideWorkspace, "package-lock.json");
    await writeTextFile(lockfilePath, "inside\n");
    await writeTextFile(outsidePath, "outside\n");
    const safeLockfilePath = await fs.promises.realpath(lockfilePath);

    const originalOpen = fs.promises.open;
    let moved = false;
    let symlinkCreated = false;
    fs.promises.open = async (openedPath, flags) => {
      if (!moved && openedPath === safeLockfilePath) {
        await fs.promises.rename(lockfilePath, movedLockfilePath);
        moved = true;
        await fs.promises.symlink(outsidePath, lockfilePath, "file");
        symlinkCreated = true;
      }
      return originalOpen(openedPath, flags);
    };

    try {
      await assert.rejects(
        () => readUtf8(lockfilePath, workspace),
        (error) => error.code === DEPENDENCY_FILE_ERROR_CODES.CHANGED
      );
    } finally {
      fs.promises.open = originalOpen;
      if (symlinkCreated) {
        await fs.promises.unlink(lockfilePath);
      }
      if (moved) {
        await fs.promises.rename(movedLockfilePath, lockfilePath);
      }
    }
  });

  test("accepts a canonical target when the workspace root is a symlink", async () => {
    const parentWorkspace = await createWorkspace("cloudsmith-workspace-symlink-");
    const realWorkspace = path.join(parentWorkspace, "real-workspace");
    const symlinkWorkspace = path.join(parentWorkspace, "linked-workspace");
    const lockfilePath = path.join(realWorkspace, "package-lock.json");
    await writeTextFile(lockfilePath, "{}\n");
    await fs.promises.symlink(realWorkspace, symlinkWorkspace, "dir");

    assert.strictEqual(await readUtf8(lockfilePath, symlinkWorkspace), "{}\n");
  });

  test("accepts descendant names that begin with two dots", async () => {
    const workspace = await createWorkspace("cloudsmith-dot-prefix-");
    const lockfilePath = path.join(workspace, "..cache", "package-lock.json");
    await writeTextFile(lockfilePath, "{}\n");

    assert.strictEqual(await readUtf8(lockfilePath, workspace), "{}\n");
  });

  test("reports a close failure after an otherwise successful read", async () => {
    const workspace = await createWorkspace("cloudsmith-close-failure-");
    const lockfilePath = path.join(workspace, "package-lock.json");
    await writeTextFile(lockfilePath, "{}\n");
    const safeLockfilePath = await fs.promises.realpath(lockfilePath);
    const originalOpen = fs.promises.open;

    fs.promises.open = async (openedPath, flags) => {
      const actualHandle = await originalOpen(openedPath, flags);
      if (openedPath !== safeLockfilePath) {
        return actualHandle;
      }
      return {
        stat: (...args) => actualHandle.stat(...args),
        read: (...args) => actualHandle.read(...args),
        async close() {
          await actualHandle.close();
          const error = new Error("close failed");
          error.code = "EIO";
          throw error;
        },
      };
    };

    try {
      await assert.rejects(
        () => readUtf8(lockfilePath, workspace),
        (error) => error.code === DEPENDENCY_FILE_ERROR_CODES.UNREADABLE
          && error.cause && error.cause.message === "close failed"
      );
    } finally {
      fs.promises.open = originalOpen;
    }
  });

  test("does not let a close failure mask an existing read failure", async () => {
    const workspace = await createWorkspace("cloudsmith-read-close-failure-");
    const lockfilePath = path.join(workspace, "package-lock.json");
    await writeTextFile(lockfilePath, "{}\n");
    const safeLockfilePath = await fs.promises.realpath(lockfilePath);
    const originalOpen = fs.promises.open;
    const readFailure = new Error("read failed");
    readFailure.code = "EIO";

    fs.promises.open = async (openedPath, flags) => {
      const actualHandle = await originalOpen(openedPath, flags);
      if (openedPath !== safeLockfilePath) {
        return actualHandle;
      }
      return {
        stat: (...args) => actualHandle.stat(...args),
        async read() {
          throw readFailure;
        },
        async close() {
          await actualHandle.close();
          throw new Error("close failed");
        },
      };
    };

    try {
      await assert.rejects(
        () => readUtf8(lockfilePath, workspace),
        (error) => error.code === DEPENDENCY_FILE_ERROR_CODES.UNREADABLE
          && error.cause === readFailure
      );
    } finally {
      fs.promises.open = originalOpen;
    }
  });

  test("preserves JSON parse errors after a successful file read", async () => {
    const workspace = await createWorkspace("cloudsmith-invalid-json-");
    const lockfilePath = path.join(workspace, "package-lock.json");
    await writeTextFile(lockfilePath, "{invalid json\n");

    await assert.rejects(
      () => readJson(lockfilePath, workspace),
      (error) => error instanceof SyntaxError
    );
  });

  test("rejects dependency files above the structural size limit before reading", async () => {
    const workspace = await createWorkspace("cloudsmith-large-lockfile-");
    const lockfilePath = path.join(workspace, "package-lock.json");
    await writeTextFile(lockfilePath, "{}");
    await fs.promises.truncate(lockfilePath, MAX_DEPENDENCY_FILE_BYTES + 1);

    await assert.rejects(
      () => readUtf8(lockfilePath, workspace),
      new RegExp(`exceeds the ${MAX_DEPENDENCY_FILE_BYTES} byte parsing limit`)
    );
  });

  test("bounds directory enumeration structurally", async () => {
    const workspace = await makeTempWorkspace("cloudsmith-directory-cap-");
    tempDirs.push(workspace);
    await Promise.all([
      writeTextFile(path.join(workspace, "a.txt"), "a\n"),
      writeTextFile(path.join(workspace, "b.txt"), "b\n"),
      writeTextFile(path.join(workspace, "c.txt"), "c\n"),
    ]);

    const result = await readBoundedDirectoryEntries(workspace, 2);

    assert.strictEqual(result.entries.length, 2);
    assert.strictEqual(result.truncated, true);
  });
});

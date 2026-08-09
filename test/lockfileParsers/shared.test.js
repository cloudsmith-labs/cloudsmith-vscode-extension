const assert = require("assert");
const fs = require("fs");
const path = require("path");
const {
  MAX_DEPENDENCY_FILE_BYTES,
  readBoundedDirectoryEntries,
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

  test("rejects dependency files above the structural size limit before reading", async () => {
    const workspace = await makeTempWorkspace("cloudsmith-large-lockfile-");
    tempDirs.push(workspace);
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

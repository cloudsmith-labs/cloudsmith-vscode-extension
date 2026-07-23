const assert = require("assert");
const path = require("path");
const nugetParser = require("../../util/lockfileParsers/nugetParser");
const {
  makeTempWorkspace,
  removeDirectory,
} = require("../helpers/fixtureWorkspace");

suite("nugetParser Test Suite", () => {
  const tempDirs = [];

  async function createWorkspace() {
    const workspace = await makeTempWorkspace("cloudsmith-nuget-parser-");
    tempDirs.push(workspace);
    return workspace;
  }

  suiteTeardown(async () => {
    await Promise.all(tempDirs.map((tempDir) => removeDirectory(tempDir)));
  });

  test("detect returns no matches for invalid workspace roots", async () => {
    const workspace = await createWorkspace();
    const matches = await nugetParser.detect(path.join(workspace, "missing-workspace"));

    assert.deepStrictEqual(matches, []);
  });
});

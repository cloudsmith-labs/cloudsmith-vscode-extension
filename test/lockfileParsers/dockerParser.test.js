const assert = require("assert");
const path = require("path");
const dockerParser = require("../../util/lockfileParsers/dockerParser");
const {
  makeTempWorkspace,
  removeDirectory,
  writeTextFile,
} = require("../helpers/fixtureWorkspace");

suite("dockerParser Test Suite", () => {
  const fixtureDir = path.join(__dirname, "..", "fixtures", "docker");
  const tempDirs = [];

  async function createWorkspace() {
    const workspace = await makeTempWorkspace("cloudsmith-docker-parser-");
    tempDirs.push(workspace);
    return workspace;
  }

  suiteTeardown(async () => {
    await Promise.all(tempDirs.map((tempDir) => removeDirectory(tempDir)));
  });

  test("parses Dockerfile FROM instructions and skips scratch and stage references", async () => {
    const tree = await dockerParser.resolve({
      lockfilePath: path.join(fixtureDir, "Dockerfile"),
    });

    assert.strictEqual(tree.sourceFile, "Dockerfile");
    assert.deepStrictEqual(
      tree.dependencies.map((dependency) => `${dependency.name}:${dependency.version}`),
      ["python:3.11-slim", "alpine:3.19"]
    );
  });

  test("parses docker-compose images and skips build-only services", async () => {
    const tree = await dockerParser.resolve({
      lockfilePath: path.join(fixtureDir, "docker-compose.yml"),
    });

    assert.strictEqual(tree.sourceFile, "docker-compose.yml");
    assert.deepStrictEqual(
      tree.dependencies.map((dependency) => `${dependency.name}:${dependency.version}`),
      ["redis:7.2", "postgres:16"]
    );
  });

  test("detect returns no matches when Docker manifests are missing", async () => {
    const workspace = await createWorkspace();

    const matches = await dockerParser.detect(workspace);

    assert.deepStrictEqual(matches, []);
    assert.strictEqual(await dockerParser.canResolve(workspace), false);
  });

  test("detect returns no matches for invalid workspace roots", async () => {
    const workspace = await createWorkspace();
    const matches = await dockerParser.detect(path.join(workspace, "missing-workspace"));

    assert.deepStrictEqual(matches, []);
  });

  test("ignores malformed FROM lines that do not resolve to image references", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "Dockerfile");
    await writeTextFile(lockfilePath, [
      "ARG BASE_IMAGE",
      "FROM $BASE_IMAGE",
      "FROM scratch",
      "",
    ].join("\n"));

    const tree = await dockerParser.resolve({ lockfilePath });

    assert.strictEqual(tree.dependencies.length, 0);
  });
});

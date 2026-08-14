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

  test("resolves Compose defaults and applies build image pull-policy semantics", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "compose.yaml");
    await writeTextFile(lockfilePath, [
      "services:",
      "  default-pull:",
      "    build: .",
      "    image: example/api:1.2.3",
      "  output-only:",
      "    build: .",
      "    image: example/output:9",
      "    pull_policy: build",
      "  cached-input:",
      "    build: .",
      "    image: example/cache:4",
      "    pull_policy: never",
      "  interpolated:",
      '    image: "redis:${REDIS_TAG:-7.2}"',
      "",
    ].join("\n"));

    const tree = await dockerParser.resolve({ lockfilePath, workspaceFolder: workspace });

    assert.deepStrictEqual(
      tree.dependencies.map((dependency) => `${dependency.name}:${dependency.version}`),
      ["example/api:1.2.3", "example/cache:4", "redis:7.2"]
    );
    assert.deepStrictEqual(
      tree.dependencies.map((dependency) => dependency.qualifiers.service),
      ["default-pull", "cached-input", "interpolated"]
    );
    assert.strictEqual(tree.warnings.length, 0);
  });

  test("preserves Docker tag and digest evidence without inventing latest", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "Dockerfile");
    await writeTextFile(lockfilePath, [
      "FROM example/plain",
      "FROM example/tagged:2.0@sha256:abcdef0123456789",
      "",
    ].join("\n"));

    const tree = await dockerParser.resolve({ lockfilePath, workspaceFolder: workspace });

    assert.strictEqual(tree.dependencies[0].version, "");
    assert.strictEqual(tree.dependencies[0].hasResolutionEvidence, false);
    assert.strictEqual(tree.dependencies[1].version, "2.0");
    assert.strictEqual(tree.dependencies[1].qualifiers.tag, "2.0");
    assert.strictEqual(tree.dependencies[1].qualifiers.digest, "sha256:abcdef0123456789");
    assert.strictEqual(tree.dependencies[1].hasResolutionEvidence, true);
  });

  test("warns safely when Compose interpolation cannot be resolved", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "compose.yml");
    await writeTextFile(lockfilePath, [
      "services:",
      "  incomplete:",
      '    image: "example/${UI_R7_MISSING_IMAGE:?secret-bearing custom text}"',
      "",
    ].join("\n"));

    const tree = await dockerParser.resolve({ lockfilePath, workspaceFolder: workspace });

    assert.strictEqual(tree.dependencies.length, 0);
    assert.deepStrictEqual(tree.warnings, [
      "A Compose image reference could not be resolved, so dependency results are partial.",
    ]);
    assert.strictEqual(tree.warnings.join(" ").includes("secret-bearing"), false);
    assert.strictEqual(tree.warnings.join(" ").includes("UI_R7_MISSING_IMAGE"), false);
  });
});

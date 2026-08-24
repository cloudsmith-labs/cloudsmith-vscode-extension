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
    const digest = `sha256:${"a".repeat(64)}`;
    await writeTextFile(lockfilePath, [
      "FROM example/plain",
      `FROM example/tagged:2.0@${digest}`,
      "",
    ].join("\n"));

    const tree = await dockerParser.resolve({ lockfilePath, workspaceFolder: workspace });

    assert.strictEqual(tree.dependencies[0].version, "");
    assert.strictEqual(tree.dependencies[0].hasResolutionEvidence, false);
    assert.strictEqual(tree.dependencies[1].version, "2.0");
    assert.strictEqual(tree.dependencies[1].qualifiers.tag, "2.0");
    assert.strictEqual(tree.dependencies[1].qualifiers.digest, digest);
    assert.strictEqual(tree.dependencies[1].hasResolutionEvidence, true);
  });

  test("rejects malformed and undersized Docker digests", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "Dockerfile");
    await writeTextFile(lockfilePath, [
      `FROM example/short@sha256:${"a".repeat(32)}`,
      `FROM example/nonhex@sha256:${"z".repeat(64)}`,
      "",
    ].join("\n"));

    const tree = await dockerParser.resolve({ lockfilePath, workspaceFolder: workspace });

    assert.deepStrictEqual(tree.dependencies, []);
  });

  test("preserves explicit Dockerfile and Compose target platforms", async () => {
    const workspace = await createWorkspace();
    const dockerfilePath = path.join(workspace, "Dockerfile");
    await writeTextFile(dockerfilePath, [
      "FROM --platform=linux/arm64/v8 example/api:1.2.3",
      "",
    ].join("\n"));
    const dockerfileTree = await dockerParser.resolve({
      lockfilePath: dockerfilePath,
      workspaceFolder: workspace,
    });
    assert.strictEqual(dockerfileTree.dependencies[0].qualifiers.platform, "linux/arm64/v8");

    const composePath = path.join(workspace, "compose.yaml");
    await writeTextFile(composePath, [
      "services:",
      "  api:",
      "    image: example/api:1.2.3",
      "    platform: linux/arm64",
      "",
    ].join("\n"));
    const composeTree = await dockerParser.resolve({
      lockfilePath: composePath,
      workspaceFolder: workspace,
    });
    assert.strictEqual(composeTree.dependencies[0].qualifiers.platform, "linux/arm64");
  });

  test("marks unresolved Dockerfile target platforms as partial and unpullable", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "Dockerfile");
    await writeTextFile(lockfilePath, [
      "FROM --platform=$TARGETPLATFORM example/api:1.2.3",
      "",
    ].join("\n"));

    const tree = await dockerParser.resolve({ lockfilePath, workspaceFolder: workspace });

    assert.strictEqual(tree.dependencies.length, 1);
    assert.strictEqual(tree.dependencies[0].hasResolutionEvidence, false);
    assert.strictEqual(tree.dependencies[0].resolvedVersion, null);
    assert.strictEqual(tree.dependencies[0].versionState, "incomplete");
    assert.strictEqual(tree.dependencies[0].qualifiers.platform, undefined);
    assert.deepStrictEqual(tree.warnings, [
      "A Dockerfile target platform could not be resolved, so dependency results are partial.",
    ]);
  });

  test("reports one file-level warning for multiple unresolved Dockerfile target platforms", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "Dockerfile");
    await writeTextFile(lockfilePath, [
      "FROM --platform=$TARGETPLATFORM example/api:1.2.3 AS api",
      "FROM --platform=${SECOND_PLATFORM} example/worker:2.0 AS worker",
      "FROM --platform=$THIRD_PLATFORM example/jobs:3.0 AS jobs",
      "FROM api AS final",
      "",
    ].join("\n"));

    const tree = await dockerParser.resolve({ lockfilePath, workspaceFolder: workspace });

    assert.deepStrictEqual(
      tree.dependencies.map((dependency) => dependency.name),
      ["example/api", "example/worker", "example/jobs"]
    );
    assert.strictEqual(tree.dependencies.every((dependency) => (
      dependency.versionState === "incomplete"
      && dependency.hasResolutionEvidence === false
      && dependency.resolvedVersion === null
      && dependency.qualifiers.platform === undefined
    )), true);
    assert.deepStrictEqual(tree.warnings, [
      "A Dockerfile target platform could not be resolved, so dependency results are partial.",
    ]);
  });

  test("preserves per-dependency platform state for mixed Dockerfile stages", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "Dockerfile");
    await writeTextFile(lockfilePath, [
      "ARG RESOLVED_PLATFORM=linux/arm64/v8",
      "FROM --platform=$RESOLVED_PLATFORM example/resolved:1.0 AS resolved",
      "FROM --platform=$TARGETPLATFORM example/unresolved:2.0 AS unresolved",
      "FROM --platform=not-a-platform example/invalid:3.0 AS invalid",
      "FROM resolved AS final",
      "",
    ].join("\n"));

    const tree = await dockerParser.resolve({ lockfilePath, workspaceFolder: workspace });

    assert.deepStrictEqual(
      tree.dependencies.map((dependency) => ({
        name: dependency.name,
        platform: dependency.qualifiers.platform,
        versionState: dependency.versionState,
        hasResolutionEvidence: dependency.hasResolutionEvidence,
        resolvedVersion: dependency.resolvedVersion,
      })),
      [
        {
          name: "example/resolved",
          platform: "linux/arm64/v8",
          versionState: undefined,
          hasResolutionEvidence: true,
          resolvedVersion: "1.0",
        },
        {
          name: "example/unresolved",
          platform: undefined,
          versionState: "incomplete",
          hasResolutionEvidence: false,
          resolvedVersion: null,
        },
        {
          name: "example/invalid",
          platform: undefined,
          versionState: "incomplete",
          hasResolutionEvidence: false,
          resolvedVersion: null,
        },
      ]
    );
    assert.deepStrictEqual(tree.warnings, [
      "A Dockerfile target platform could not be resolved, so dependency results are partial.",
    ]);
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

  test("deduplicates generic Compose warnings per file while preserving distinct classes", async () => {
    const workspace = await createWorkspace();
    const firstPath = path.join(workspace, "compose.yml");
    await writeTextFile(firstPath, [
      "services:",
      "  missing-image-one:",
      "    image: example/${FIRST_IMAGE}",
      "  missing-image-two:",
      "    image: example/${SECOND_IMAGE}",
      "  missing-platform-one:",
      "    image: example/one:1.0",
      "    platform: ${FIRST_PLATFORM}",
      "  missing-platform-two:",
      "    image: example/two:2.0",
      "    platform: ${SECOND_PLATFORM}",
      "  invalid-platform-one:",
      "    image: example/three:3.0",
      "    platform: linux",
      "  invalid-platform-two:",
      "    image: example/four:4.0",
      "    platform: linux/amd64/extra/part",
      "  valid:",
      "    image: example/valid:5.0",
      "    platform: linux/amd64",
      "",
    ].join("\n"));

    const firstTree = await dockerParser.resolve({
      lockfilePath: firstPath,
      workspaceFolder: workspace,
    });

    assert.deepStrictEqual(
      firstTree.dependencies.map((dependency) => dependency.name),
      [
        "example/one",
        "example/two",
        "example/three",
        "example/four",
        "example/valid",
      ]
    );
    assert.strictEqual(firstTree.dependencies.slice(0, 4).every((dependency) => (
      dependency.versionState === "incomplete"
      && dependency.hasResolutionEvidence === false
      && dependency.resolvedVersion === null
      && dependency.qualifiers.platform === undefined
    )), true);
    assert.strictEqual(firstTree.dependencies[4].hasResolutionEvidence, true);
    assert.strictEqual(firstTree.dependencies[4].qualifiers.platform, "linux/amd64");
    assert.deepStrictEqual(firstTree.warnings, [
      "A Compose image reference could not be resolved, so dependency results are partial.",
      "A Compose image platform could not be resolved, so dependency results are partial.",
      "A Compose image platform was invalid and could not be checked.",
    ]);

    const secondPath = path.join(workspace, "compose.yaml");
    await writeTextFile(secondPath, [
      "services:",
      "  missing-again:",
      "    image: example/${THIRD_IMAGE}",
      "",
    ].join("\n"));
    const secondTree = await dockerParser.resolve({
      lockfilePath: secondPath,
      workspaceFolder: workspace,
    });

    assert.deepStrictEqual(secondTree.warnings, [
      "A Compose image reference could not be resolved, so dependency results are partial.",
    ]);
  });
});

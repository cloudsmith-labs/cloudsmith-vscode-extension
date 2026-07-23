const assert = require("assert");
const path = require("path");
const pythonParser = require("../../util/lockfileParsers/pythonParser");
const {
  makeTempWorkspace,
  removeDirectory,
  writeTextFile,
} = require("../helpers/fixtureWorkspace");

suite("pythonParser Test Suite", () => {
  const fixtureDir = path.join(__dirname, "..", "fixtures", "python");
  const tempDirs = [];

  async function createWorkspace() {
    const workspace = await makeTempWorkspace("cloudsmith-python-parser-");
    tempDirs.push(workspace);
    return workspace;
  }

  suiteTeardown(async () => {
    await Promise.all(tempDirs.map((tempDir) => removeDirectory(tempDir)));
  });

  test("resolves poetry.lock and keeps all package entries while marking directs from pyproject.toml", async () => {
    const tree = await pythonParser.resolve({
      lockfilePath: path.join(fixtureDir, "poetry.lock"),
      manifestPath: path.join(fixtureDir, "pyproject.toml"),
    });

    assert.strictEqual(tree.sourceFile, "poetry.lock");
    assert.strictEqual(tree.dependencies.length, 3);

    const flask = tree.dependencies.find((dependency) => dependency.name === "flask");
    const requests = tree.dependencies.find((dependency) => dependency.name === "requests");
    const click = tree.dependencies.find((dependency) => dependency.name === "click");

    assert.ok(flask);
    assert.ok(requests);
    assert.ok(click);
    assert.strictEqual(flask.isDirect, true);
    assert.strictEqual(requests.isDirect, true);
    assert.strictEqual(click.isDirect, false);
    assert.deepStrictEqual(click.parentChain, ["flask"]);
  });

  test("skips the editable uv root package and resolves its transitive dependencies", async () => {
    const tree = await pythonParser.resolve({
      lockfilePath: path.join(fixtureDir, "uv.lock"),
      manifestPath: path.join(fixtureDir, "pyproject.toml"),
    });

    assert.strictEqual(tree.sourceFile, "uv.lock");
    assert.strictEqual(tree.dependencies.some((dependency) => dependency.name === "fixture-python"), false);
    assert.strictEqual(tree.dependencies.length, 3);
    assert.ok(tree.dependencies.some((dependency) => dependency.name === "fastapi" && dependency.isDirect));
    assert.ok(tree.dependencies.some((dependency) => dependency.name === "starlette" && !dependency.isDirect));
    assert.ok(tree.dependencies.some((dependency) => dependency.name === "pydantic" && !dependency.isDirect));
  });

  test("warns when only requirements.txt is available", async () => {
    const tree = await pythonParser.resolve({
      lockfilePath: path.join(fixtureDir, "requirements.txt"),
    });

    assert.strictEqual(tree.sourceFile, "requirements.txt");
    assert.strictEqual(tree.dependencies.length, 2);
    assert.strictEqual(tree.dependencies.every((dependency) => dependency.isDirect), true);
    assert.strictEqual(tree.warnings.length, 1);
    assert.match(tree.warnings[0], /requirements\.txt does not encode transitive dependencies/i);
  });

  test("detect returns no matches when Python dependency files are missing", async () => {
    const workspace = await createWorkspace();

    const matches = await pythonParser.detect(workspace);

    assert.deepStrictEqual(matches, []);
    assert.strictEqual(await pythonParser.canResolve(workspace), false);
  });

  test("resolve rejects lockfiles outside the provided workspace folder", async () => {
    const workspace = await createWorkspace();
    const outsideWorkspace = await createWorkspace();
    const lockfilePath = path.join(outsideWorkspace, "requirements.txt");

    await writeTextFile(lockfilePath, "requests==2.31.0\n");

    await assert.rejects(
      () => pythonParser.resolve({
        workspaceFolder: workspace,
        lockfilePath,
      }),
      /Refusing to read files outside the workspace folder/
    );
  });

  test("throws for malformed poetry.lock files", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "poetry.lock");
    const manifestPath = path.join(workspace, "pyproject.toml");
    await writeTextFile(lockfilePath, "[metadata]\nlock-version = \"2.0\"\n");
    await writeTextFile(manifestPath, "[tool.poetry.dependencies]\nflask = \"^2.3.0\"\n");

    await assert.rejects(
      () => pythonParser.resolve({ lockfilePath, manifestPath }),
      /no package entries found/
    );
  });
});

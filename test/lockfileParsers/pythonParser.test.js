const assert = require("assert");
const fs = require("fs");
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

  test("accepts an empty requirements.txt as a valid empty dependency set", async () => {
    const workspace = await createWorkspace();
    const requirementsPath = path.join(workspace, "requirements.txt");
    await writeTextFile(requirementsPath, "# This project has no Python dependencies.\n\n");

    const tree = await pythonParser.resolve({
      lockfilePath: requirementsPath,
      workspaceFolder: workspace,
    });

    assert.deepStrictEqual(tree.dependencies, []);
    assert.match(tree.warnings[0], /does not encode transitive dependencies/i);
  });

  test("keeps Python specifiers unresolved unless the requirement is an exact pin", async () => {
    const workspace = await createWorkspace();
    const requirementsPath = path.join(workspace, "requirements.txt");
    await writeTextFile(requirementsPath, [
      "exact-package==1.2.3",
      "arbitrary-exact===build-7",
      "ranged-package>=2.0,<3.0",
      "compatible-package~=4.1",
      "wildcard-package==5.*",
      "bare-package",
      "conditional-package==6.0; python_version < '3.12'",
      "hashed-package==7.0 \\",
      "  --hash=sha256:abcdef",
    ].join("\n"));

    const tree = await pythonParser.resolve({
      lockfilePath: requirementsPath,
      workspaceFolder: workspace,
    });
    const versions = new Map(tree.dependencies.map((dependency) => [dependency.name, dependency.version]));

    assert.strictEqual(versions.get("exact-package"), "1.2.3");
    assert.strictEqual(versions.get("arbitrary-exact"), "build-7");
    assert.strictEqual(versions.get("ranged-package"), "");
    assert.strictEqual(versions.get("compatible-package"), "");
    assert.strictEqual(versions.get("wildcard-package"), "");
    assert.strictEqual(versions.get("bare-package"), "");
    assert.strictEqual(versions.get("conditional-package"), "");
    assert.strictEqual(versions.get("hashed-package"), "7.0");
    assert.strictEqual(
      tree.dependencies.find((dependency) => dependency.name === "ranged-package").declaredConstraint,
      ">=2.0,<3.0"
    );
    assert.strictEqual(
      tree.dependencies.find((dependency) => dependency.name === "conditional-package").environmentMarker,
      "python_version < '3.12'"
    );
    assert.match(tree.warnings[1], /environment markers were not evaluated/i);
  });

  test("resolves nested requirements includes within the workspace", async () => {
    const workspace = await createWorkspace();
    const requirementsPath = path.join(workspace, "requirements.txt");
    const basePath = path.join(workspace, "requirements", "base.txt");
    const developmentPath = path.join(workspace, "requirements", "development.txt");
    await writeTextFile(requirementsPath, "-r requirements/base.txt\nroot-package==1.0.0\n");
    await writeTextFile(basePath, "--requirement=development.txt\nbase-package>=2.0\n");
    await writeTextFile(developmentPath, "development-package==3.0.0\n");

    const tree = await pythonParser.resolve({
      lockfilePath: requirementsPath,
      workspaceFolder: workspace,
    });

    assert.deepStrictEqual(
      tree.dependencies.map((dependency) => dependency.name).sort(),
      ["base-package", "development-package", "root-package"]
    );
    assert.strictEqual(
      tree.dependencies.find((dependency) => dependency.name === "base-package").version,
      ""
    );
    assert.strictEqual(
      tree.dependencies.find((dependency) => dependency.name === "development-package").sourceFile,
      "development.txt"
    );
    assert.strictEqual(
      tree.dependencies.find((dependency) => dependency.name === "development-package").sourceManifestPath,
      await fs.promises.realpath(developmentPath)
    );
  });

  test("rejects circular requirements includes", async () => {
    const workspace = await createWorkspace();
    const requirementsPath = path.join(workspace, "requirements.txt");
    const basePath = path.join(workspace, "base.txt");
    await writeTextFile(requirementsPath, "-r base.txt\n");
    await writeTextFile(basePath, "-r requirements.txt\n");

    await assert.rejects(
      () => pythonParser.resolve({
        lockfilePath: requirementsPath,
        workspaceFolder: workspace,
      }),
      /Circular requirements\.txt include/
    );
  });

  test("rejects requirements includes outside the workspace", async () => {
    const workspace = await createWorkspace();
    const outsideWorkspace = await createWorkspace();
    const requirementsPath = path.join(workspace, "requirements.txt");
    const outsidePath = path.join(outsideWorkspace, "outside.txt");
    await writeTextFile(outsidePath, "outside-package==1.0.0\n");
    await writeTextFile(requirementsPath, `-r ${outsidePath}\n`);

    await assert.rejects(
      () => pythonParser.resolve({
        lockfilePath: requirementsPath,
        workspaceFolder: workspace,
      }),
      /include paths must stay within the workspace folder/
    );
  });

  test("rejects malformed requirements rather than returning a clean dependency set", async () => {
    const workspace = await createWorkspace();
    const requirementsPath = path.join(workspace, "requirements.txt");
    await writeTextFile(requirementsPath, "requests 1.2.3\n");

    await assert.rejects(
      () => pythonParser.resolve({
        lockfilePath: requirementsPath,
        workspaceFolder: workspace,
      }),
      /Malformed requirements\.txt entry/
    );
  });

  test("uses exact versions from Pipfile.lock and marks development dependencies", async () => {
    const tree = await pythonParser.resolve({
      lockfilePath: path.join(fixtureDir, "Pipfile.lock"),
    });

    assert.strictEqual(tree.dependencies.find((dependency) => dependency.name === "flask").version, "2.3.0");
    assert.strictEqual(tree.dependencies.find((dependency) => dependency.name === "flask").isDevelopmentDependency, false);
    assert.strictEqual(tree.dependencies.find((dependency) => dependency.name === "pytest").version, "8.2.0");
    assert.strictEqual(tree.dependencies.find((dependency) => dependency.name === "pytest").isDevelopmentDependency, true);
  });

  test("resolves multiline PEP 621 direct declarations and preserves multiple locked versions", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "pyproject.toml");
    const lockfilePath = path.join(workspace, "uv.lock");
    await writeTextFile(manifestPath, [
      "[project]",
      "name = \"fixture\"",
      "dependencies = [",
      "  \"requests[socks]>=2.0\",",
      "  \"app-dependency>=1.0,<2.0\",",
      "]",
      "",
      "[tool.poetry.group.test.dependencies]",
      "pytest = \"^8.0\"",
    ].join("\n"));
    await writeTextFile(lockfilePath, [
      "[[package]]",
      "name = \"fixture\"",
      "version = \"0.1.0\"",
      "source = { editable = \".\" }",
      "dependencies = [{ name = \"app-dependency\" }]",
      "",
      "[[package]]",
      "name = \"requests\"",
      "version = \"2.32.3\"",
      "",
      "[[package]]",
      "name = \"app-dependency\"",
      "version = \"1.5.0\"",
      "dependencies = [",
      "  { name = \"shared-dependency\", marker = \"python_version < '3.12'\" },",
      "]",
      "",
      "[[package]]",
      "name = \"shared-dependency\"",
      "version = \"1.0.0\"",
      "",
      "[[package]]",
      "name = \"shared-dependency\"",
      "version = \"2.0.0\"",
      "",
      "[[package]]",
      "name = \"pytest\"",
      "version = \"8.2.0\"",
    ].join("\n"));

    const tree = await pythonParser.resolve({
      lockfilePath,
      manifestPath,
      workspaceFolder: workspace,
    });
    const appDependency = tree.dependencies.find((dependency) => dependency.name === "app-dependency");
    const requests = tree.dependencies.find((dependency) => dependency.name === "requests");
    const sharedDependencies = tree.dependencies.filter((dependency) => dependency.name === "shared-dependency");
    const pytest = tree.dependencies.find((dependency) => dependency.name === "pytest");

    assert.ok(appDependency);
    assert.ok(requests);
    assert.strictEqual(requests.version, "2.32.3");
    assert.strictEqual(requests.isDirect, true);
    assert.strictEqual(appDependency.version, "1.5.0");
    assert.strictEqual(appDependency.isDirect, true);
    assert.deepStrictEqual(
      sharedDependencies.map((dependency) => dependency.version).sort(),
      ["1.0.0", "2.0.0"]
    );
    assert.strictEqual(sharedDependencies.every((dependency) => !dependency.isDirect), true);
    assert.strictEqual(appDependency.transitives.length, 2);
    assert.ok(pytest);
    assert.strictEqual(pytest.version, "8.2.0");
    assert.strictEqual(pytest.isDirect, true);
    assert.strictEqual(pytest.isDevelopmentDependency, true);
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

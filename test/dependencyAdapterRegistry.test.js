const assert = require("assert");
const fs = require("fs");
const path = require("path");
const {
  ADAPTER_ERROR_CODES,
  ADAPTER_RESULT_STATUSES,
  DependencyAdapterRegistry,
  createDefaultDependencyAdapterRegistry,
} = require("../util/dependencyAdapterRegistry");
const {
  DEPENDENCY_VERSION_STATES,
  RESOLUTION_SOURCE_KINDS,
} = require("../util/dependencyRecord");
const { MAX_DEPENDENCY_FILE_BYTES } = require("../util/lockfileParsers/shared");
const {
  makeTempWorkspace,
  removeDirectory,
  writeTextFile,
} = require("./helpers/fixtureWorkspace");

suite("dependencyAdapterRegistry", () => {
  const fixtureDir = path.join(__dirname, "fixtures", "npm");
  const tempDirs = [];

  async function createWorkspace() {
    const workspace = await makeTempWorkspace("cloudsmith-dependency-adapter-");
    tempDirs.push(workspace);
    return workspace;
  }

  function createContractAdapter(id, detect) {
    return {
      id,
      ecosystem: "npm",
      manifestTypes: [],
      detect,
      async parse() {
        return {
          status: ADAPTER_RESULT_STATUSES.SUCCESS,
          dependencies: [],
          warnings: [],
        };
      },
    };
  }

  suiteTeardown(async () => {
    await Promise.all(tempDirs.map((tempDir) => removeDirectory(tempDir)));
  });

  test("maps a known package.json manifest to the npm adapter", () => {
    const registry = createDefaultDependencyAdapterRegistry();
    const adapter = registry.getAdapterForManifest("package.json");

    assert.ok(registry instanceof DependencyAdapterRegistry);
    assert.ok(adapter);
    assert.strictEqual(adapter.id, "npmParser");
    assert.strictEqual(adapter.ecosystem, "npm");
  });

  test("accepts an empty adapter detection array", async () => {
    const registry = new DependencyAdapterRegistry([
      createContractAdapter("empty-detector", async () => []),
    ]);

    assert.deepStrictEqual(await registry.detect("/workspace"), []);
  });

  test("preserves valid adapter detections", async () => {
    const registry = new DependencyAdapterRegistry([
      createContractAdapter("valid-detector", async () => [{ sourceFile: "package.json" }]),
    ]);

    assert.deepStrictEqual(await registry.detect("/workspace"), [{
      sourceFile: "package.json",
      adapterId: "valid-detector",
      resolverName: "valid-detector",
      ecosystem: "npm",
      workspaceFolder: "/workspace",
    }]);
  });

  test("passes cancellation through detection and parser boundaries", async () => {
    const token = { isCancellationRequested: false };
    let detectOptions = null;
    let parseOptions = null;
    let manifestOptions = null;
    const adapter = createContractAdapter("cancellable-adapter", async (_root, options) => {
      detectOptions = options;
      return [];
    });
    adapter.manifestTypes = ["custom.json"];
    adapter.parse = async (_detection, options) => {
      parseOptions = options;
      return { status: ADAPTER_RESULT_STATUSES.SUCCESS, dependencies: [], warnings: [] };
    };
    adapter.parseManifest = async (_manifest, options) => {
      manifestOptions = options;
      return { status: ADAPTER_RESULT_STATUSES.SUCCESS, dependencies: [], warnings: [] };
    };
    const registry = new DependencyAdapterRegistry([adapter]);

    await registry.detect("/workspace", { cancellationToken: token });
    await registry.parse({ adapterId: adapter.id }, { cancellationToken: token });
    await registry.parseManifest(
      { filePath: "/workspace/custom.json" },
      { cancellationToken: token }
    );
    assert.strictEqual(detectOptions.cancellationToken, token);
    assert.strictEqual(parseOptions.cancellationToken, token);
    assert.strictEqual(manifestOptions.cancellationToken, token);
  });

  test("fails before invoking a parser when cancellation is already requested", async () => {
    let parseCalls = 0;
    const adapter = createContractAdapter("pre-cancelled-adapter", async () => []);
    adapter.parse = async () => {
      parseCalls += 1;
      return { status: ADAPTER_RESULT_STATUSES.SUCCESS, dependencies: [], warnings: [] };
    };
    const registry = new DependencyAdapterRegistry([adapter]);

    const result = await registry.parse(
      { adapterId: adapter.id },
      { cancellationToken: { isCancellationRequested: true } }
    );
    assert.strictEqual(result.status, ADAPTER_RESULT_STATUSES.ERROR);
    assert.strictEqual(result.error.code, ADAPTER_ERROR_CODES.CANCELLED);
    assert.strictEqual(parseCalls, 0);
  });

  for (const [label, invalidResult] of [
    ["null", null],
    ["undefined", undefined],
    ["an object", {}],
    ["a string", "package.json"],
  ]) {
    test(`rejects ${label} adapter detection output with an actionable contract error`, async () => {
      const adapterId = `invalid-${label.replace(/\s+/g, "-")}-detector`;
      const registry = new DependencyAdapterRegistry([
        createContractAdapter(adapterId, async () => invalidResult),
      ]);

      await assert.rejects(
        () => registry.detect("/workspace"),
        (error) => {
          assert.ok(error instanceof TypeError);
          assert.strictEqual(
            error.message,
            `Dependency adapter "${adapterId}" detect() must return an array.`
          );
          return true;
        }
      );
    });
  }

  test("rejects invalid parse result objects at equivalent adapter boundaries", async () => {
    const parseAdapter = createContractAdapter("invalid-parser", async () => []);
    parseAdapter.parse = async () => null;
    const parseRegistry = new DependencyAdapterRegistry([parseAdapter]);

    await assert.rejects(
      () => parseRegistry.parse({ adapterId: "invalid-parser" }),
      /Dependency adapter "invalid-parser" parse\(\) must return an adapter result object\./
    );

    const manifestAdapter = createContractAdapter("invalid-manifest-parser", async () => []);
    manifestAdapter.manifestTypes = ["package.json"];
    manifestAdapter.parseManifest = async () => "not-a-result";
    const manifestRegistry = new DependencyAdapterRegistry([manifestAdapter]);

    await assert.rejects(
      () => manifestRegistry.parseManifest({ manifestType: "package.json" }),
      /Dependency adapter "invalid-manifest-parser" parseManifest\(\) must return an adapter result object\./
    );
  });

  test("returns an explicit unsupported result for unknown manifests", async () => {
    const workspace = await createWorkspace();
    const filePath = path.join(workspace, "dependencies.custom");
    await writeTextFile(filePath, "package-a=1.0.0\n");

    const result = await createDefaultDependencyAdapterRegistry().parseManifest({
      filePath,
      format: "custom",
      workspaceFolder: workspace,
    });

    assert.strictEqual(result.status, ADAPTER_RESULT_STATUSES.UNSUPPORTED);
    assert.deepStrictEqual(result.dependencies, []);
    assert.ok(result.error);
    assert.strictEqual(result.error.code, "unsupported-manifest");
  });

  test("returns canonical records for supported manifest dependencies", async () => {
    const registry = createDefaultDependencyAdapterRegistry();
    const filePath = path.join(fixtureDir, "package.json");
    const result = await registry.parseManifest({
      filePath,
      format: "npm",
      workspaceFolder: fixtureDir,
    });
    const express = result.dependencies.find((dependency) => dependency.name === "express");

    assert.strictEqual(result.status, ADAPTER_RESULT_STATUSES.SUCCESS);
    assert.ok(express);
    assert.strictEqual(Object.isFrozen(express), true);
    assert.strictEqual(express.ecosystem, "npm");
    assert.strictEqual(express.format, "npm");
    assert.strictEqual(express.normalizedName, "express");
    assert.strictEqual(express.declaredConstraint, "^4.18.2");
    assert.strictEqual(express.resolvedVersion, null);
    assert.strictEqual(express.versionState, DEPENDENCY_VERSION_STATES.RANGE);
    assert.strictEqual(express.resolutionSource, null);
    assert.strictEqual(express.sourceManifest.kind, RESOLUTION_SOURCE_KINDS.MANIFEST);
    assert.strictEqual(express.sourceManifest.filePath, filePath);
    assert.strictEqual(express.sourceManifest.label, "package.json");
    assert.strictEqual(express.sourceManifest.type, "package.json");
    assert.strictEqual(express.isDirect, true);
    assert.strictEqual(express.legacyVersion, "4.18.2");
  });

  test("parses Pipfile declarations through the Python manifest adapter", async () => {
    const workspace = await createWorkspace();
    const filePath = path.join(workspace, "Pipfile");
    await writeTextFile(filePath, [
      "[packages]",
      'requests = "==2.32.3"',
      'local-lib = {path = "../local-lib"}',
      "[dev-packages]",
      'pytest = "==8.3.2"',
    ].join("\n"));

    const result = await createDefaultDependencyAdapterRegistry().parseManifest({
      filePath,
      format: "python",
      workspaceFolder: workspace,
    });
    const requests = result.dependencies.find((dependency) => dependency.name === "requests");
    const local = result.dependencies.find((dependency) => dependency.name === "local-lib");
    const pytest = result.dependencies.find((dependency) => dependency.name === "pytest");
    assert.notStrictEqual(result.status, ADAPTER_RESULT_STATUSES.UNSUPPORTED);
    assert.ok(requests);
    assert.strictEqual(requests.versionState, DEPENDENCY_VERSION_STATES.EXACT_DECLARATION);
    assert.strictEqual(requests.lookupEligibility.state, "eligible");
    assert.strictEqual(local.packageSource.kind, "path");
    assert.strictEqual(local.lookupEligibility.state, "not-applicable");
    assert.strictEqual(pytest.isDevelopmentDependency, true);
  });

  test("distinguishes malformed package.json from a valid empty manifest", async () => {
    const workspace = await createWorkspace();
    const validPath = path.join(workspace, "package.json");
    const malformedPath = path.join(workspace, "nested", "package.json");
    await writeTextFile(validPath, "{}\n");
    await writeTextFile(malformedPath, "{ not valid JSON\n");
    const registry = createDefaultDependencyAdapterRegistry();

    const valid = await registry.parseManifest({
      filePath: validPath,
      format: "npm",
      workspaceFolder: workspace,
    });
    const malformed = await registry.parseManifest({
      filePath: malformedPath,
      format: "npm",
      workspaceFolder: workspace,
    });

    assert.strictEqual(valid.status, ADAPTER_RESULT_STATUSES.SUCCESS);
    assert.deepStrictEqual(valid.dependencies, []);
    assert.strictEqual(valid.error, null);
    assert.strictEqual(malformed.status, ADAPTER_RESULT_STATUSES.ERROR);
    assert.deepStrictEqual(malformed.dependencies, []);
    assert.ok(malformed.error);
    assert.strictEqual(malformed.error.code, ADAPTER_ERROR_CODES.PARSE_ERROR);
    assert.strictEqual(
      malformed.error.message,
      "Dependency data could not be parsed. Check the dependency files and rescan."
    );
  });

  test("does not expose secret-bearing parser input in adapter errors", async () => {
    const workspace = await createWorkspace();
    const requirementsPath = path.join(workspace, "requirements.txt");
    const secret = "token=cloudsmith-secret-value";
    await writeTextFile(requirementsPath, `not a valid requirement ${secret}\n`);

    const result = await createDefaultDependencyAdapterRegistry().parseManifest({
      filePath: requirementsPath,
      format: "python",
      workspaceFolder: workspace,
    });

    assert.strictEqual(result.status, ADAPTER_RESULT_STATUSES.ERROR);
    assert.strictEqual(result.error.code, ADAPTER_ERROR_CODES.PARSE_ERROR);
    assert.strictEqual(
      result.error.message,
      "Dependency data could not be parsed. Check the dependency files and rescan."
    );
    assert.doesNotMatch(result.error.message, /cloudsmith-secret-value|token=|not a valid/i);
    assert.doesNotMatch(result.error.message, new RegExp(workspace.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  });

  test("maps dependency file size failures without exposing internal bounds", async () => {
    const workspace = await createWorkspace();
    const requirementsPath = path.join(workspace, "requirements.txt");
    await writeTextFile(requirementsPath, "placeholder==1.0.0\n");
    await fs.promises.truncate(requirementsPath, MAX_DEPENDENCY_FILE_BYTES + 1);

    const result = await createDefaultDependencyAdapterRegistry().parseManifest({
      filePath: requirementsPath,
      format: "python",
      workspaceFolder: workspace,
    });

    assert.strictEqual(result.status, ADAPTER_RESULT_STATUSES.ERROR);
    assert.strictEqual(result.error.code, ADAPTER_ERROR_CODES.DEPENDENCY_FILE_TOO_LARGE);
    assert.strictEqual(
      result.error.message,
      "A dependency file could not be scanned because of its size. Check the dependency file and rescan."
    );
    assert.doesNotMatch(result.error.message, /\d/);
  });

  test("maps parser cancellation onto a stable customer-safe category", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "package.json");
    const lockfilePath = path.join(workspace, "package-lock.json");
    await writeTextFile(manifestPath, JSON.stringify({ dependencies: { alpha: "1.0.0" } }));
    await writeTextFile(lockfilePath, JSON.stringify({ lockfileVersion: 3, packages: { "": {} } }));

    const result = await createDefaultDependencyAdapterRegistry().parse({
      adapterId: "npmParser",
      resolverName: "npmParser",
      ecosystem: "npm",
      workspaceFolder: workspace,
      lockfilePath,
      manifestPath,
      sourceFile: "package-lock.json",
    }, {
      workspaceFolder: workspace,
      cancellationToken: { isCancellationRequested: true },
    });

    assert.strictEqual(result.status, ADAPTER_RESULT_STATUSES.ERROR);
    assert.strictEqual(result.error.code, ADAPTER_ERROR_CODES.CANCELLED);
    assert.strictEqual(result.error.message, "Dependency scanning was canceled.");
  });

  test("surfaces a malformed npm manifest paired with a valid lockfile", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "package.json");
    const lockfilePath = path.join(workspace, "package-lock.json");
    await writeTextFile(manifestPath, "{ not valid JSON\n");
    await writeTextFile(lockfilePath, JSON.stringify({
      lockfileVersion: 3,
      packages: { "": {} },
    }));

    const result = await createDefaultDependencyAdapterRegistry().parse({
      adapterId: "npmParser",
      resolverName: "npmParser",
      ecosystem: "npm",
      workspaceFolder: workspace,
      lockfilePath,
      manifestPath,
      sourceFile: "package-lock.json",
    });

    assert.strictEqual(result.status, ADAPTER_RESULT_STATUSES.ERROR);
    assert.deepStrictEqual(result.dependencies, []);
    assert.strictEqual(result.error.code, ADAPTER_ERROR_CODES.PARSE_ERROR);
    assert.strictEqual(
      result.error.message,
      "Dependency data could not be parsed. Check the dependency files and rescan."
    );
  });

  test("surfaces a malformed Composer manifest paired with a valid lockfile", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "composer.json");
    const lockfilePath = path.join(workspace, "composer.lock");
    await writeTextFile(manifestPath, "{ not valid JSON\n");
    await writeTextFile(lockfilePath, JSON.stringify({ packages: [], "packages-dev": [] }));

    const result = await createDefaultDependencyAdapterRegistry().parse({
      adapterId: "composerParser",
      resolverName: "composerParser",
      ecosystem: "composer",
      workspaceFolder: workspace,
      lockfilePath,
      manifestPath,
      sourceFile: "composer.lock",
    });

    assert.strictEqual(result.status, ADAPTER_RESULT_STATUSES.ERROR);
    assert.deepStrictEqual(result.dependencies, []);
    assert.strictEqual(result.error.code, ADAPTER_ERROR_CODES.PARSE_ERROR);
    assert.strictEqual(
      result.error.message,
      "Dependency data could not be parsed. Check the dependency files and rescan."
    );
  });

  test("retains distinct provenance for same-ecosystem manifests", async () => {
    const workspace = await createWorkspace();
    const firstPath = path.join(workspace, "package.json");
    const secondPath = path.join(workspace, "packages", "nested", "package.json");
    const content = JSON.stringify({ dependencies: { "package-a": "^1.0.0" } });
    await writeTextFile(firstPath, content);
    await writeTextFile(secondPath, content);
    const registry = createDefaultDependencyAdapterRegistry();

    const first = await registry.parseManifest({
      filePath: firstPath,
      format: "npm",
      workspaceFolder: workspace,
    });
    const second = await registry.parseManifest({
      filePath: secondPath,
      format: "npm",
      workspaceFolder: workspace,
    });

    assert.strictEqual(first.status, ADAPTER_RESULT_STATUSES.SUCCESS);
    assert.strictEqual(second.status, ADAPTER_RESULT_STATUSES.SUCCESS);
    assert.strictEqual(first.dependencies[0].ecosystem, "npm");
    assert.strictEqual(second.dependencies[0].ecosystem, "npm");
    assert.strictEqual(first.dependencies[0].sourceManifest.filePath, await fs.promises.realpath(firstPath));
    assert.strictEqual(second.dependencies[0].sourceManifest.filePath, await fs.promises.realpath(secondPath));
    assert.notStrictEqual(
      first.dependencies[0].sourceManifest.uri,
      second.dependencies[0].sourceManifest.uri
    );
  });

  test("detects and parses a bounded nested npm project from the workspace root", async () => {
    const workspace = await createWorkspace();
    const projectRoot = path.join(workspace, "packages", "application");
    const manifestPath = path.join(projectRoot, "package.json");
    const lockfilePath = path.join(projectRoot, "package-lock.json");
    await writeTextFile(manifestPath, JSON.stringify({
      dependencies: { "package-a": "^1.0.0" },
    }, null, 2));
    await writeTextFile(lockfilePath, JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { dependencies: { "package-a": "^1.0.0" } },
        "node_modules/package-a": { version: "1.4.0" },
      },
    }, null, 2));
    const registry = createDefaultDependencyAdapterRegistry();

    const detections = await registry.detect(workspace);
    const detection = detections.find((candidate) => candidate.adapterId === "npmParser");
    const realWorkspace = await fs.promises.realpath(workspace);
    const realProjectRoot = path.join(realWorkspace, "packages", "application");
    assert.ok(detection);
    assert.strictEqual(detection.projectFolder, realProjectRoot);
    assert.strictEqual(detection.workspaceFolder, workspace);
    assert.strictEqual(detection.manifestPath, path.join(realProjectRoot, "package.json"));
    assert.strictEqual(detection.lockfilePath, path.join(realProjectRoot, "package-lock.json"));

    const result = await registry.parse(detection, { workspaceFolder: workspace });
    assert.strictEqual(result.status, ADAPTER_RESULT_STATUSES.SUCCESS);
    assert.strictEqual(result.dependencies[0].declaredConstraint, "^1.0.0");
    assert.strictEqual(result.dependencies[0].resolvedVersion, "1.4.0");
    assert.strictEqual(result.dependencies[0].sourceManifest.filePath, path.join(realProjectRoot, "package.json"));
  });

  test("adapts the npm fixture without losing its raw declaration or resolution provenance", async () => {
    const manifestPath = path.join(fixtureDir, "package.json");
    const lockfilePath = path.join(fixtureDir, "package-lock.json");
    const result = await createDefaultDependencyAdapterRegistry().parse({
      adapterId: "npmParser",
      resolverName: "npmParser",
      ecosystem: "npm",
      workspaceFolder: fixtureDir,
      lockfilePath,
      manifestPath,
      sourceFile: "package-lock.json",
    }, {
      maxDependenciesToScan: 10000,
    });
    const express = result.dependencies.find((dependency) => dependency.name === "express");

    assert.strictEqual(result.status, ADAPTER_RESULT_STATUSES.SUCCESS);
    assert.ok(express);
    assert.strictEqual(express.declaredConstraint, "^4.18.2");
    assert.strictEqual(express.resolvedVersion, "4.18.2");
    assert.strictEqual(express.versionState, DEPENDENCY_VERSION_STATES.RESOLVED);
    assert.strictEqual(express.legacyVersion, "4.18.2");
    assert.strictEqual(express.sourceManifest.kind, RESOLUTION_SOURCE_KINDS.MANIFEST);
    assert.strictEqual(express.sourceManifest.filePath, manifestPath);
    assert.strictEqual(express.resolutionSource.kind, RESOLUTION_SOURCE_KINDS.LOCKFILE);
    assert.strictEqual(express.resolutionSource.filePath, lockfilePath);
    assert.ok(result.dependencyGraph);
    assert.strictEqual(result.dependencyGraph.kind, "package-lock");
    assert.ok(result.dependencyGraph.entries.length > result.dependencies.length);
    assert.strictEqual(result.dependencyGraph.maxEdges, 500000);
    assert.deepStrictEqual(express.transitives, []);
  });

  test("classifies npm partial and wildcard declarations as ranges", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "package.json");
    await writeTextFile(manifestPath, JSON.stringify({
      dependencies: {
        major: "1",
        minor: "1.2",
        wildcard: "1.x",
        wildcardPatch: "1.2.X",
        exact: "1.2.3",
        prerelease: "1.2.3-beta.1",
      },
    }));

    const result = await createDefaultDependencyAdapterRegistry().parseManifest({
      filePath: manifestPath,
      format: "npm",
      workspaceFolder: workspace,
    });
    const states = new Map(result.dependencies.map((dependency) => [
      dependency.name,
      dependency.versionState,
    ]));

    assert.strictEqual(states.get("major"), DEPENDENCY_VERSION_STATES.RANGE);
    assert.strictEqual(states.get("minor"), DEPENDENCY_VERSION_STATES.RANGE);
    assert.strictEqual(states.get("wildcard"), DEPENDENCY_VERSION_STATES.RANGE);
    assert.strictEqual(states.get("wildcardPatch"), DEPENDENCY_VERSION_STATES.RANGE);
    assert.strictEqual(states.get("exact"), DEPENDENCY_VERSION_STATES.EXACT_DECLARATION);
    assert.strictEqual(states.get("prerelease"), DEPENDENCY_VERSION_STATES.EXACT_DECLARATION);
  });

  test("routes supported manifest-only Gradle parsing through its ecosystem adapter", async () => {
    const filePath = path.join(__dirname, "fixtures", "gradle", "build.gradle");
    const result = await createDefaultDependencyAdapterRegistry().parseManifest({
      filePath,
      format: "gradle",
      workspaceFolder: path.dirname(filePath),
    });

    assert.notStrictEqual(result.status, ADAPTER_RESULT_STATUSES.UNSUPPORTED);
    assert.ok(result.dependencies.length > 0);
    assert.strictEqual(result.dependencies.every((dependency) => dependency.resolvedVersion === null), true);
  });

  test("keeps local Go replacements incomplete through manifest-only parsing", async () => {
    const workspace = await createWorkspace();
    const filePath = path.join(workspace, "go.mod");
    await writeTextFile(filePath, [
      "module example.com/application",
      "go 1.22",
      "require example.com/Owner/Module v1.2.3",
      "replace example.com/Owner/Module => ../local-module",
    ].join("\n"));

    const result = await createDefaultDependencyAdapterRegistry().parseManifest({
      filePath,
      format: "go",
      workspaceFolder: workspace,
    });
    const dependency = result.dependencies.find((entry) => entry.name === "example.com/Owner/Module");

    assert.ok(dependency);
    assert.strictEqual(dependency.resolvedVersion, null);
    assert.strictEqual(dependency.versionState, DEPENDENCY_VERSION_STATES.INCOMPLETE);
  });

  test("retains Python include provenance and does not make ranges or markers concrete", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "requirements.txt");
    const includedPath = path.join(workspace, "requirements", "base.txt");
    await writeTextFile(manifestPath, [
      "-r requirements/base.txt",
      "requests>=2.0,<3",
      "conditional==4.5.6; python_version >= '3.12'",
      "",
    ].join("\n"));
    await writeTextFile(includedPath, "urllib3==2.2.2\n");

    const result = await createDefaultDependencyAdapterRegistry().parseManifest({
      filePath: manifestPath,
      format: "python",
      workspaceFolder: workspace,
    });
    const requests = result.dependencies.find((dependency) => dependency.name === "requests");
    const urllib3 = result.dependencies.find((dependency) => dependency.name === "urllib3");
    const conditional = result.dependencies.find((dependency) => dependency.name === "conditional");

    assert.strictEqual(result.status, ADAPTER_RESULT_STATUSES.PARTIAL);
    assert.strictEqual(requests.declaredConstraint, ">=2.0,<3");
    assert.strictEqual(requests.resolvedVersion, null);
    assert.strictEqual(requests.versionState, DEPENDENCY_VERSION_STATES.RANGE);
    assert.strictEqual(urllib3.declaredConstraint, "==2.2.2");
    assert.strictEqual(urllib3.resolvedVersion, null);
    assert.strictEqual(urllib3.versionState, DEPENDENCY_VERSION_STATES.EXACT_DECLARATION);
    assert.strictEqual(urllib3.legacyVersion, "2.2.2");
    assert.strictEqual(urllib3.sourceManifest.filePath, await fs.promises.realpath(includedPath));
    assert.strictEqual(conditional.resolvedVersion, null);
    assert.strictEqual(conditional.versionState, DEPENDENCY_VERSION_STATES.INCOMPLETE);
    assert.strictEqual(conditional.environmentMarker, "python_version >= '3.12'");
  });

  test("keeps conditional Poetry declarations unresolved", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "pyproject.toml");
    await writeTextFile(manifestPath, [
      "[tool.poetry.dependencies]",
      "requests = { version = \"2.32.3\", markers = \"python_version < '3.12'\" }",
    ].join("\n"));

    const result = await createDefaultDependencyAdapterRegistry().parseManifest({
      filePath: manifestPath,
      format: "python",
      workspaceFolder: workspace,
    });
    const requests = result.dependencies.find((dependency) => dependency.name === "requests");

    assert.ok(requests);
    assert.strictEqual(requests.declaredConstraint, "2.32.3");
    assert.strictEqual(requests.legacyVersion, "");
    assert.strictEqual(requests.versionState, DEPENDENCY_VERSION_STATES.INCOMPLETE);
    assert.strictEqual(requests.environmentMarker, "python_version < '3.12'");
  });

  test("keeps conditional exact PEP 621 declarations unresolved", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "pyproject.toml");
    await writeTextFile(manifestPath, [
      "[project]",
      "name = \"fixture\"",
      "dependencies = [",
      "  \"requests==2.32.3; python_version < '3.12'\",",
      "]",
    ].join("\n"));

    const result = await createDefaultDependencyAdapterRegistry().parseManifest({
      filePath: manifestPath,
      format: "python",
      workspaceFolder: workspace,
    });
    const requests = result.dependencies.find((dependency) => dependency.name === "requests");

    assert.ok(requests);
    assert.strictEqual(requests.declaredConstraint, "==2.32.3");
    assert.strictEqual(requests.resolvedVersion, null);
    assert.strictEqual(requests.legacyVersion, "");
    assert.strictEqual(requests.versionState, DEPENDENCY_VERSION_STATES.INCOMPLETE);
    assert.strictEqual(requests.environmentMarker, "python_version < '3.12'");
  });

  test("preserves conditional Poetry and PEP 621 declarations across lockfile joins", async () => {
    const cases = [
      {
        lockfileName: "uv.lock",
        manifestLines: [
          "[project]",
          "name = \"fixture\"",
          "dependencies = [\"requests==2.32.3; python_version < '3.12'\"]",
        ],
      },
      {
        lockfileName: "poetry.lock",
        manifestLines: [
          "[tool.poetry]",
          "name = \"fixture\"",
          "[tool.poetry.dependencies]",
          "requests = { version = \"2.32.3\", markers = \"python_version < '3.12'\" }",
        ],
      },
    ];

    for (const testCase of cases) {
      const workspace = await createWorkspace();
      const manifestPath = path.join(workspace, "pyproject.toml");
      const lockfilePath = path.join(workspace, testCase.lockfileName);
      await writeTextFile(manifestPath, testCase.manifestLines.join("\n"));
      await writeTextFile(lockfilePath, [
        "[[package]]",
        "name = \"requests\"",
        "version = \"2.32.3\"",
      ].join("\n"));

      const result = await createDefaultDependencyAdapterRegistry().parse({
        adapterId: "pythonParser",
        resolverName: "pythonParser",
        ecosystem: "python",
        workspaceFolder: workspace,
        lockfilePath,
        manifestPath,
        sourceFile: testCase.lockfileName,
      });
      const requests = result.dependencies.find((dependency) => dependency.name === "requests");

      assert.ok(requests, `${testCase.lockfileName} should retain the direct dependency`);
      assert.strictEqual(requests.isDirect, true);
      assert.strictEqual(requests.declaredConstraint, testCase.lockfileName === "uv.lock"
        ? "==2.32.3"
        : "2.32.3");
      assert.strictEqual(requests.resolvedVersion, null);
      assert.strictEqual(requests.resolutionSource, null);
      assert.strictEqual(requests.legacyVersion, "2.32.3");
      assert.strictEqual(requests.versionState, DEPENDENCY_VERSION_STATES.INCOMPLETE);
      assert.strictEqual(requests.environmentMarker, "python_version < '3.12'");
    }
  });

  test("uses bounded Maven manifest evidence without manufacturing property resolutions", async () => {
    const registry = createDefaultDependencyAdapterRegistry();
    const workspace = await createWorkspace();
    const filePath = path.join(workspace, "pom.xml");
    const fixturePath = path.join(__dirname, "fixtures", "maven", "resolution-semantics-pom.xml");
    await writeTextFile(filePath, await fs.promises.readFile(fixturePath, "utf8"));
    const result = await registry.parseManifest({
      filePath,
      format: "maven",
      workspaceFolder: workspace,
    });
    const literal = result.dependencies.find((dependency) => dependency.name === "org.literal:library");
    const localProperty = result.dependencies.find((dependency) => dependency.name === "org.property:library");
    const unknownProperty = result.dependencies.find((dependency) => dependency.name === "org.unknown:library");
    const managed = result.dependencies.find((dependency) => dependency.name === "org.managed:managed-core");

    assert.strictEqual(result.status, ADAPTER_RESULT_STATUSES.PARTIAL);
    assert.strictEqual(result.dependencies.some((dependency) => dependency.name === "org.managed:management-only"), false);
    assert.strictEqual(literal.declaredConstraint, "1.0.0");
    assert.strictEqual(literal.resolvedVersion, null);
    assert.strictEqual(literal.versionState, DEPENDENCY_VERSION_STATES.EXACT_DECLARATION);
    assert.strictEqual(localProperty.declaredConstraint, "${resolved.version}");
    assert.strictEqual(localProperty.legacyVersion, "6.1.2");
    assert.strictEqual(localProperty.resolvedVersion, null);
    assert.strictEqual(localProperty.versionState, DEPENDENCY_VERSION_STATES.EXACT_DECLARATION);
    assert.strictEqual(unknownProperty.declaredConstraint, "${missing.version}");
    assert.strictEqual(unknownProperty.resolvedVersion, null);
    assert.strictEqual(unknownProperty.versionState, DEPENDENCY_VERSION_STATES.UNRESOLVED);
    assert.strictEqual(managed.declaredConstraint, "${managed.version}");
    assert.strictEqual(managed.legacyVersion, "5.0.1");
    assert.strictEqual(managed.resolvedVersion, null);
    assert.strictEqual(managed.versionState, DEPENDENCY_VERSION_STATES.EXACT_DECLARATION);
  });

  test("preserves the workspace trust boundary on adapter detections", async () => {
    const workspace = await createWorkspace();
    const otherWorkspace = await createWorkspace();
    const nestedPath = path.join(workspace, "target", "dependency-tree.txt");
    await writeTextFile(path.join(workspace, "pom.xml"), "<project></project>\n");
    await writeTextFile(nestedPath, "\n");

    const detections = await createDefaultDependencyAdapterRegistry().detect(workspace);
    const mavenDetection = detections.find((detection) => detection.adapterId === "mavenParser");

    assert.ok(mavenDetection);
    assert.strictEqual(mavenDetection.workspaceFolder, workspace);
    assert.strictEqual(mavenDetection.lockfilePath, nestedPath);
    const result = await createDefaultDependencyAdapterRegistry().parse(mavenDetection);
    assert.notStrictEqual(result.status, ADAPTER_RESULT_STATUSES.ERROR);
    const rejected = await createDefaultDependencyAdapterRegistry().parse(mavenDetection, {
      workspaceFolder: otherWorkspace,
    });
    assert.strictEqual(rejected.status, ADAPTER_RESULT_STATUSES.ERROR);
    assert.strictEqual(
      rejected.error.code,
      ADAPTER_ERROR_CODES.DEPENDENCY_FILE_OUTSIDE_WORKSPACE
    );
    assert.strictEqual(
      rejected.error.message,
      "A dependency file is outside the selected workspace. Check the dependency paths and rescan."
    );
  });
});

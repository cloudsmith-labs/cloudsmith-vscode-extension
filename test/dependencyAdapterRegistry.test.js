const assert = require("assert");
const fs = require("fs");
const path = require("path");
const {
  ADAPTER_RESULT_STATUSES,
  DependencyAdapterRegistry,
  createDefaultDependencyAdapterRegistry,
} = require("../util/dependencyAdapterRegistry");
const {
  DEPENDENCY_VERSION_STATES,
  RESOLUTION_SOURCE_KINDS,
} = require("../util/dependencyRecord");
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
    assert.strictEqual(express.sourceManifest.type, "package.json");
    assert.strictEqual(express.isDirect, true);
    assert.strictEqual(express.legacyVersion, "4.18.2");
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
    assert.strictEqual(malformed.error.code, "parse-error");
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
    assert.match(rejected.error.message, /workspace folder/);
  });
});

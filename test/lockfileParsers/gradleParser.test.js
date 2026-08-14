const assert = require("assert");
const path = require("path");
const gradleParser = require("../../util/lockfileParsers/gradleParser");
const {
  makeTempWorkspace,
  removeDirectory,
  writeTextFile,
} = require("../helpers/fixtureWorkspace");

suite("gradleParser Test Suite", () => {
  const tempDirs = [];

  async function createWorkspace() {
    const workspace = await makeTempWorkspace("cloudsmith-gradle-parser-");
    tempDirs.push(workspace);
    return workspace;
  }

  suiteTeardown(async () => {
    await Promise.all(tempDirs.map((tempDir) => removeDirectory(tempDir)));
  });

  test("preserves manifest constraints and only marks lockfile-backed versions resolved", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "build.gradle");
    const lockfilePath = path.join(workspace, "gradle.lockfile");
    await writeTextFile(manifestPath, [
      "plugins {",
      '    id "java"',
      "}",
      "",
      "dependencies {",
      '    implementation "org.example:locked:1.+"',
      '    implementation "org.example:unlocked:[2.0,3.0)"',
      '    testImplementation "org.example:exact:4.0.0"',
      "}",
      "",
    ].join("\n"));
    await writeTextFile(lockfilePath, [
      "org.example:locked:1.7.4=compileClasspath",
      "org.example:exact:4.0.0=testCompileClasspath",
      "org.example:transitive:9.1.0=compileClasspath",
      "",
    ].join("\n"));

    const tree = await gradleParser.resolve({
      lockfilePath,
      manifestPath,
      workspaceFolder: workspace,
    });
    const byName = new Map(tree.dependencies.map((dependency) => [dependency.name, dependency]));

    assert.strictEqual(byName.get("org.example:locked").declaredConstraint, "1.+");
    assert.strictEqual(byName.get("org.example:locked").version, "1.7.4");
    assert.strictEqual(byName.get("org.example:locked").versionState, "resolved");
    assert.strictEqual(byName.get("org.example:locked").hasResolutionEvidence, true);

    assert.strictEqual(byName.get("org.example:unlocked").declaredConstraint, "[2.0,3.0)");
    assert.strictEqual(byName.get("org.example:unlocked").version, "");
    assert.strictEqual(byName.get("org.example:unlocked").versionState, "range");
    assert.strictEqual(byName.get("org.example:unlocked").hasResolutionEvidence, false);

    assert.strictEqual(byName.get("org.example:exact").version, "4.0.0");
    assert.strictEqual(byName.get("org.example:exact").isDevelopmentDependency, true);
    assert.deepStrictEqual(byName.get("org.example:exact").qualifiers, {
      configurations: ["testCompileClasspath"],
    });
    assert.strictEqual(byName.get("org.example:transitive").isDirect, false);
    assert.strictEqual(byName.get("org.example:transitive").hasResolutionEvidence, true);
    assert.deepStrictEqual(byName.get("org.example:transitive").packageSource, { kind: "registry" });
  });

  test("keeps a manifest-only dynamic Gradle version as a range", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "build.gradle");
    await writeTextFile(manifestPath, [
      "dependencies {",
      '    implementation "org.example:dynamic:2.+"',
      "}",
      "",
    ].join("\n"));

    const tree = await gradleParser.resolve({
      manifestPath,
      workspaceFolder: workspace,
    });
    const dependency = tree.dependencies[0];

    assert.strictEqual(dependency.declaredConstraint, "2.+");
    assert.strictEqual(dependency.version, "2.+");
    assert.strictEqual(dependency.versionState, "range");
    assert.strictEqual(dependency.hasResolutionEvidence, false);
  });

  test("preserves case-distinct Maven-format Gradle coordinates", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "build.gradle");
    const lockfilePath = path.join(workspace, "gradle.lockfile");
    await writeTextFile(manifestPath, [
      "dependencies {",
      '    implementation "Com.Example:Library:1.0.0"',
      '    implementation "com.example:Library:1.0.0"',
      "}",
      "",
    ].join("\n"));
    await writeTextFile(lockfilePath, [
      "Com.Example:Library:1.0.0=compileClasspath",
      "com.example:Library:1.0.0=compileClasspath",
      "",
    ].join("\n"));

    const tree = await gradleParser.resolve({
      lockfilePath,
      manifestPath,
      workspaceFolder: workspace,
    });

    assert.strictEqual(tree.dependencies.length, 2);
    assert.deepStrictEqual(
      new Set(tree.dependencies.map((dependency) => dependency.name)),
      new Set(["Com.Example:Library", "com.example:Library"])
    );
    assert.ok(tree.dependencies.every((dependency) => dependency.hasResolutionEvidence));
  });

  test("preserves case-distinct Maven-format coordinates without a lockfile", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "build.gradle");
    await writeTextFile(manifestPath, [
      "dependencies {",
      '    implementation "Com.Example:Library:1.0.0"',
      '    implementation "com.example:Library:1.0.0"',
      "}",
      "",
    ].join("\n"));

    const tree = await gradleParser.resolve({ manifestPath, workspaceFolder: workspace });

    assert.deepStrictEqual(
      tree.dependencies.map((dependency) => dependency.name),
      ["Com.Example:Library", "com.example:Library"]
    );
    assert.ok(tree.dependencies.every((dependency) => (
      dependency.versionState === "exact-declaration"
      && dependency.hasResolutionEvidence === false
    )));
  });

  test("preserves lock configuration membership and marks only test-only records development", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "build.gradle.kts");
    const lockfilePath = path.join(workspace, "gradle.lockfile");
    await writeTextFile(manifestPath, [
      "dependencies {",
      '    implementation("org.example:shared:1.0.0")',
      '    testImplementation("org.example:shared:1.0.0")',
      "}",
      "",
    ].join("\n"));
    await writeTextFile(lockfilePath, [
      "org.example:shared:1.0.0=compileClasspath,testCompileClasspath",
      "org.example:test-only:2.0.0=testCompileClasspath,testRuntimeClasspath",
      "org.example:mixed:3.0.0=compileClasspath,testRuntimeClasspath",
      "",
    ].join("\n"));

    const tree = await gradleParser.resolve({
      lockfilePath,
      manifestPath,
      workspaceFolder: workspace,
    });
    const shared = tree.dependencies.filter((dependency) => dependency.name === "org.example:shared");
    const testOnly = tree.dependencies.find((dependency) => dependency.name === "org.example:test-only");
    const mixed = tree.dependencies.find((dependency) => dependency.name === "org.example:mixed");

    assert.strictEqual(shared.length, 2);
    assert.strictEqual(shared.filter((dependency) => dependency.isDevelopmentDependency).length, 1);
    assert.deepStrictEqual(shared[0].gradleConfigurations, [
      "compileClasspath",
      "testCompileClasspath",
    ]);
    assert.strictEqual(testOnly.isDirect, false);
    assert.strictEqual(testOnly.isDevelopmentDependency, true);
    assert.deepStrictEqual(testOnly.qualifiers, {
      configurations: ["testCompileClasspath", "testRuntimeClasspath"],
    });
    assert.strictEqual(mixed.isDevelopmentDependency, false);
  });
});

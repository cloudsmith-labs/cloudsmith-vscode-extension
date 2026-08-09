const assert = require("assert");
const path = require("path");
const mavenParser = require("../../util/lockfileParsers/mavenParser");
const {
  makeTempWorkspace,
  removeDirectory,
  writeTextFile,
} = require("../helpers/fixtureWorkspace");

suite("mavenParser Test Suite", () => {
  const fixtureDir = path.join(__dirname, "..", "fixtures", "maven");
  const tempDirs = [];

  async function createWorkspace() {
    const workspace = await makeTempWorkspace("cloudsmith-maven-parser-");
    tempDirs.push(workspace);
    return workspace;
  }

  suiteTeardown(async () => {
    await Promise.all(tempDirs.map((tempDir) => removeDirectory(tempDir)));
  });

  test("hydrates direct dependencies from pom.xml and transitives from dependency-tree.txt", async () => {
    const tree = await mavenParser.resolve({
      lockfilePath: path.join(fixtureDir, "dependency-tree.txt"),
      manifestPath: path.join(fixtureDir, "pom.xml"),
    });

    assert.strictEqual(tree.sourceFile, "pom.xml");
    assert.strictEqual(tree.dependencies.length, 3);

    const starter = tree.dependencies.find((dependency) => (
      dependency.name === "org.springframework.boot:spring-boot-starter-web"
    ));
    const springCore = tree.dependencies.find((dependency) => dependency.name === "org.springframework:spring-core");
    const junit = tree.dependencies.find((dependency) => dependency.name === "junit:junit");

    assert.ok(starter);
    assert.ok(springCore);
    assert.ok(junit);
    assert.strictEqual(starter.isDirect, true);
    assert.strictEqual(starter.declaredConstraint, "3.2.0");
    assert.strictEqual(starter.resolvedVersion, "3.2.0");
    assert.strictEqual(starter.hasResolutionEvidence, true);
    assert.strictEqual(springCore.isDirect, false);
    assert.strictEqual(springCore.resolvedVersion, "6.1.0");
    assert.strictEqual(junit.version, "4.13.2");
    assert.strictEqual(junit.isDevelopmentDependency, true);
  });

  test("resolves bounded local POM semantics without treating dependency management as direct", async () => {
    const tree = await mavenParser.resolve({
      lockfilePath: null,
      manifestPath: path.join(fixtureDir, "resolution-semantics-pom.xml"),
    });
    const byName = new Map(tree.dependencies.map((dependency) => [dependency.name, dependency]));

    assert.strictEqual(tree.dependencies.length, 8);
    assert.strictEqual(byName.has("org.managed:management-only"), false);

    assert.strictEqual(byName.get("org.literal:library").version, "1.0.0");
    assert.strictEqual(byName.get("org.literal:library").versionState, "exact-declaration");
    assert.strictEqual(byName.get("org.literal:library").hasResolutionEvidence, false);

    assert.strictEqual(byName.get("org.property:library").version, "6.1.2");
    assert.strictEqual(byName.get("org.property:library").declaredConstraint, "${resolved.version}");
    assert.strictEqual(byName.get("org.property:library").versionState, "exact-declaration");

    assert.strictEqual(byName.get("org.project:library").version, "3.4.5");
    assert.strictEqual(byName.get("org.project:library").declaredConstraint, "${project.version}");

    assert.strictEqual(byName.get("org.managed:managed-core").version, "5.0.1");
    assert.strictEqual(byName.get("org.managed:managed-core").declaredConstraint, "${managed.version}");
    assert.strictEqual(byName.get("org.managed:managed-core").versionOrigin, "dependency-management");

    assert.strictEqual(byName.get("org.unknown:library").version, "");
    assert.strictEqual(byName.get("org.unknown:library").declaredConstraint, "${missing.version}");
    assert.strictEqual(byName.get("org.unknown:library").versionState, "unresolved");

    assert.strictEqual(byName.get("org.range:library").version, "");
    assert.strictEqual(byName.get("org.range:library").declaredConstraint, "[1.0,2.0)");
    assert.strictEqual(byName.get("org.range:library").versionState, "range");

    assert.ok(byName.has("org.same-group:first-artifact"));
    assert.ok(byName.has("org.same-group:second-artifact"));
    assert.ok(tree.warnings.some((warning) => warning.includes("org.unknown:library")));
  });

  test("uses dependency-tree versions, classifier identity, and preserves multiple versions", async () => {
    const tree = await mavenParser.resolve({
      lockfilePath: path.join(fixtureDir, "tree-semantics.txt"),
      manifestPath: path.join(fixtureDir, "tree-semantics-pom.xml"),
    });
    const rootA = tree.dependencies.find((dependency) => dependency.name === "com.example:root-a");
    const rootB = tree.dependencies.find((dependency) => dependency.name === "com.example:root-b");
    const classified = tree.dependencies.find((dependency) => dependency.name === "com.example:classified");
    const commonVersions = tree.dependencies
      .filter((dependency) => dependency.name === "com.example:common")
      .map((dependency) => dependency.version)
      .sort();

    assert.strictEqual(rootA.declaredConstraint, "[1.0,2.0)");
    assert.strictEqual(rootA.version, "1.5.0");
    assert.strictEqual(rootA.resolvedVersion, "1.5.0");
    assert.strictEqual(rootA.versionState, "resolved");
    assert.strictEqual(rootB.declaredConstraint, "1.0.0");
    assert.strictEqual(rootB.version, "1.1.0");
    assert.strictEqual(classified.version, "2.1.0");
    assert.strictEqual(classified.mavenClassifier, "tests");
    assert.strictEqual(classified.isDevelopmentDependency, true);
    assert.deepStrictEqual(commonVersions, ["1.0.0", "2.0.0"]);
  });

  test("preserves case-distinct Maven identities and exact version strings", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "pom.xml");
    const lockfilePath = path.join(workspace, "dependency-tree.txt");
    await writeTextFile(manifestPath, "<project><dependencies></dependencies></project>\n");
    await writeTextFile(lockfilePath, [
      "[INFO] +- Com.Example:Library:jar:1.0.0:compile",
      "[INFO]    \\- com.example:shared:jar:1.0-RC1:compile",
      "[INFO] +- com.example:Library:jar:1.0.0:compile",
      "[INFO]    \\- com.example:shared:jar:1.0-rc1:compile",
      "",
    ].join("\n"));

    const tree = await mavenParser.resolve({ lockfilePath, manifestPath, workspaceFolder: workspace });
    const libraryNames = tree.dependencies
      .filter((dependency) => dependency.name.toLowerCase() === "com.example:library")
      .map((dependency) => dependency.name);
    const sharedVersions = tree.dependencies
      .filter((dependency) => dependency.name === "com.example:shared")
      .map((dependency) => dependency.version);

    assert.deepStrictEqual(
      new Set(libraryNames),
      new Set(["Com.Example:Library", "com.example:Library"])
    );
    assert.deepStrictEqual(new Set(sharedVersions), new Set(["1.0-RC1", "1.0-rc1"]));
  });

  test("does not join a dependency-tree root with a different type or classifier", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "pom.xml");
    const lockfilePath = path.join(workspace, "dependency-tree.txt");
    await writeTextFile(manifestPath, [
      "<project>",
      "  <dependencies>",
      "    <dependency>",
      "      <groupId>com.example</groupId>",
      "      <artifactId>shared</artifactId>",
      "      <type>test-jar</type>",
      "      <classifier>tests</classifier>",
      "      <version>1.0.0</version>",
      "    </dependency>",
      "  </dependencies>",
      "</project>",
    ].join("\n"));
    await writeTextFile(lockfilePath, "[INFO] +- com.example:shared:jar:2.0.0:compile\n");

    const tree = await mavenParser.resolve({ lockfilePath, manifestPath, workspaceFolder: workspace });
    const declared = tree.dependencies.find((dependency) => dependency.mavenClassifier === "tests");
    const resolvedJar = tree.dependencies.find((dependency) => (
      dependency.mavenClassifier === "" && dependency.resolvedVersion === "2.0.0"
    ));

    assert.ok(declared);
    assert.strictEqual(declared.version, "1.0.0");
    assert.strictEqual(declared.hasResolutionEvidence, false);
    assert.ok(resolvedJar);
  });

  test("rejects dependency trees above the structural depth limit", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "pom.xml");
    const lockfilePath = path.join(workspace, "dependency-tree.txt");
    await writeTextFile(manifestPath, [
      "<project>",
      "  <dependencies>",
      "    <dependency><groupId>com.example</groupId><artifactId>root</artifactId><version>1.0.0</version></dependency>",
      "  </dependencies>",
      "</project>",
    ].join("\n"));
    const lines = Array.from({ length: 130 }, (_, depth) => (
      `${"   ".repeat(depth)}+- com.example:node-${depth}:jar:1.0.0:compile`
    ));
    await writeTextFile(lockfilePath, `${lines.join("\n")}\n`);

    await assert.rejects(
      () => mavenParser.resolve({ lockfilePath, manifestPath, workspaceFolder: workspace }),
      /exceeds depth 128/
    );
  });

  test("detect returns no matches when pom.xml is missing", async () => {
    const workspace = await createWorkspace();

    const matches = await mavenParser.detect(workspace);

    assert.deepStrictEqual(matches, []);
    assert.strictEqual(await mavenParser.canResolve(workspace), false);
  });

  test("ignores malformed dependency tree lines and still returns manifest dependencies", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "pom.xml");
    const lockfilePath = path.join(workspace, "dependency-tree.txt");
    await writeTextFile(manifestPath, [
      "<project>",
      "  <dependencies>",
      "    <dependency>",
      "      <groupId>org.springframework.boot</groupId>",
      "      <artifactId>spring-boot-starter</artifactId>",
      "      <version>3.2.0</version>",
      "    </dependency>",
      "  </dependencies>",
      "</project>",
      "",
    ].join("\n"));
    await writeTextFile(lockfilePath, "this is not a Maven dependency tree\n");

    const tree = await mavenParser.resolve({ lockfilePath, manifestPath });

    assert.strictEqual(tree.dependencies.length, 1);
    assert.strictEqual(tree.dependencies[0].name, "org.springframework.boot:spring-boot-starter");
    assert.strictEqual(tree.dependencies[0].isDirect, true);
    assert.strictEqual(tree.dependencies[0].hasResolutionEvidence, false);
    assert.ok(tree.warnings.some((warning) => warning.includes("no parseable dependency coordinates")));
  });

  test("rejects malformed POM structure instead of reporting a clean empty dependency set", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "pom.xml");
    await writeTextFile(manifestPath, [
      "<project>",
      "  <dependencies>",
      "    <dependency>",
      "      <groupId>com.example</groupId>",
      "      <artifactId>broken</artifactId>",
      "  </dependencies>",
      "</project>",
      "",
    ].join("\n"));

    await assert.rejects(
      () => mavenParser.resolve({ lockfilePath: null, manifestPath }),
      /Invalid Maven project|Invalid Maven dependencies/
    );
  });
});

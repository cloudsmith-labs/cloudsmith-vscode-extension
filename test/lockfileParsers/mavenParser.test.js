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
    assert.strictEqual(springCore.isDirect, false);
    assert.strictEqual(junit.version, "4.13.2");
    assert.strictEqual(junit.isDevelopmentDependency, true);
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
  });
});

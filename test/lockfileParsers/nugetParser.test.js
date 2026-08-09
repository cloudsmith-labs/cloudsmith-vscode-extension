const assert = require("assert");
const path = require("path");
const nugetParser = require("../../util/lockfileParsers/nugetParser");
const {
  makeTempWorkspace,
  removeDirectory,
  writeTextFile,
} = require("../helpers/fixtureWorkspace");

suite("nugetParser Test Suite", () => {
  const tempDirs = [];

  async function createWorkspace() {
    const workspace = await makeTempWorkspace("cloudsmith-nuget-parser-");
    tempDirs.push(workspace);
    return workspace;
  }

  suiteTeardown(async () => {
    await Promise.all(tempDirs.map((tempDir) => removeDirectory(tempDir)));
  });

  test("detect returns no matches for invalid workspace roots", async () => {
    const workspace = await createWorkspace();
    const matches = await nugetParser.detect(path.join(workspace, "missing-workspace"));

    assert.deepStrictEqual(matches, []);
  });

  test("preserves framework-specific resolved versions of the same package", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "Fixture.csproj");
    const lockfilePath = path.join(workspace, "packages.lock.json");
    await writeTextFile(manifestPath, [
      '<Project Sdk="Microsoft.NET.Sdk">',
      "  <ItemGroup>",
      '    <PackageReference Include="Shared.Package" Version="[1.0.0,3.0.0)" />',
      "  </ItemGroup>",
      "</Project>",
      "",
    ].join("\n"));
    await writeTextFile(lockfilePath, JSON.stringify({
      version: 1,
      dependencies: {
        "net8.0": {
          "Shared.Package": {
            type: "Direct",
            resolved: "1.5.0",
          },
        },
        "net9.0": {
          "Shared.Package": {
            type: "Direct",
            resolved: "2.1.0",
          },
        },
      },
    }, null, 2));

    const tree = await nugetParser.resolve({
      lockfilePath,
      manifestPath,
      workspaceFolder: workspace,
    });
    const sharedPackages = tree.dependencies.filter((dependency) => dependency.name === "Shared.Package");

    assert.deepStrictEqual(
      sharedPackages.map((dependency) => dependency.version).sort(),
      ["1.5.0", "2.1.0"]
    );
    assert.deepStrictEqual(
      sharedPackages.map((dependency) => dependency.targetFramework).sort(),
      ["net8.0", "net9.0"]
    );
    assert.strictEqual(sharedPackages.every((dependency) => dependency.isDirect), true);
  });
});

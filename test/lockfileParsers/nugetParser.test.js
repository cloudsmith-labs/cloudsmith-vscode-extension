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
    assert.ok(sharedPackages.every((dependency) => dependency.packageSource.kind === "registry"));
  });

  test("preserves same-version per-framework occurrences and trusts framework-local directness", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "Fixture.csproj");
    const lockfilePath = path.join(workspace, "packages.lock.json");
    await writeTextFile(manifestPath, [
      '<Project Sdk="Microsoft.NET.Sdk">',
      "  <ItemGroup>",
      '    <PackageReference Include="Shared.Package" Version="1.5.0" />',
      "  </ItemGroup>",
      "</Project>",
      "",
    ].join("\n"));
    await writeTextFile(lockfilePath, JSON.stringify({
      version: 1,
      dependencies: {
        "net8.0": {
          "Shared.Package": { type: "Direct", resolved: "1.5.0" },
        },
        "net9.0": {
          "Root.Package": {
            type: "Direct",
            resolved: "2.0.0",
            dependencies: { "Shared.Package": "1.5.0" },
          },
          "Shared.Package": { type: "Transitive", resolved: "1.5.0" },
        },
      },
    }, null, 2));

    const tree = await nugetParser.resolve({
      lockfilePath,
      manifestPath,
      workspaceFolder: workspace,
    });
    const sharedPackages = tree.dependencies.filter((dependency) => (
      dependency.name === "Shared.Package" && dependency.version === "1.5.0"
    ));

    assert.strictEqual(sharedPackages.length, 2);
    assert.deepStrictEqual(
      sharedPackages.map((dependency) => ({
        framework: dependency.targetFramework,
        direct: dependency.isDirect,
      })).sort((left, right) => left.framework.localeCompare(right.framework)),
      [
        { framework: "net8.0", direct: true },
        { framework: "net9.0", direct: false },
      ]
    );
    assert.deepStrictEqual(
      sharedPackages.find((dependency) => dependency.targetFramework === "net9.0").parentChain,
      ["Root.Package"]
    );
    assert.deepStrictEqual(
      sharedPackages.map((dependency) => dependency.qualifiers),
      [{ targetFramework: "net8.0" }, { targetFramework: "net9.0" }]
    );
  });

  test("bounds NuGet relationships without truncating framework inventory or exposing limits", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "packages.lock.json");
    const frameworkDependencies = {};
    for (let index = 0; index < 12; index += 1) {
      const name = `Package.${String(index).padStart(2, "0")}`;
      const nextName = index + 1 < 12 ? `Package.${String(index + 1).padStart(2, "0")}` : null;
      frameworkDependencies[name] = {
        type: index === 0 ? "Direct" : "Transitive",
        resolved: "1.0.0",
        ...(nextName ? { dependencies: { [nextName]: "1.0.0" } } : {}),
      };
    }
    await writeTextFile(lockfilePath, JSON.stringify({
      version: 1,
      dependencies: { "net8.0": frameworkDependencies },
    }, null, 2));

    const tree = await nugetParser.resolve({
      lockfilePath,
      workspaceFolder: workspace,
      options: { nugetGraphMaxDepth: 3 },
    });

    assert.strictEqual(tree.dependencies.length, 12);
    assert.strictEqual(tree.dependencies.filter((dependency) => dependency.isDirect).length, 1);
    assert.strictEqual(
      tree.warnings[0],
      "Some NuGet dependency relationships were omitted to keep the scan responsive. Package inventory remains complete."
    );
    assert.doesNotMatch(tree.warnings[0], /\b3\b|maximum|limit/i);
  });

  test("honors NuGet cancellation before parsing dependency files", async () => {
    const workspace = await createWorkspace();
    const lockfilePath = path.join(workspace, "packages.lock.json");
    await writeTextFile(lockfilePath, JSON.stringify({
      version: 1,
      dependencies: { "net8.0": {} },
    }));

    await assert.rejects(
      () => nugetParser.resolve({
        lockfilePath,
        workspaceFolder: workspace,
        options: { cancellationToken: { isCancellationRequested: true } },
      }),
      (error) => error.code === "dependency-scan-cancelled"
        && error.message === "NuGet dependency parsing was canceled."
    );
  });
});

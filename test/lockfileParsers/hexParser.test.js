const assert = require("assert");
const path = require("path");
const hexParser = require("../../util/lockfileParsers/hexParser");
const {
  makeTempWorkspace,
  removeDirectory,
  writeTextFile,
} = require("../helpers/fixtureWorkspace");

suite("hexParser Test Suite", () => {
  const tempDirs = [];
  async function createWorkspace() {
    const workspace = await makeTempWorkspace("cloudsmith-hex-parser-");
    tempDirs.push(workspace);
    return workspace;
  }
  suiteTeardown(async () => Promise.all(tempDirs.map((tempDir) => removeDirectory(tempDir))));

  test("preserves Mix lock edges and development-only closure", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "mix.exs");
    const lockfilePath = path.join(workspace, "mix.lock");
    await writeTextFile(manifestPath, [
      "defp deps do", "  [", '    {:jason, "~> 1.4"},',
      '    {:ex_doc, "~> 0.34", only: :dev}', "  ]", "end", "",
    ].join("\n"));
    await writeTextFile(lockfilePath, [
      "%{",
      '  "earmark_parser": {:hex, :earmark_parser, "1.4.39", "sum", [:mix], [], "hexpm", "sum"},',
      '  "ex_doc": {:hex, :ex_doc, "0.34.2", "sum", [:mix], [{:earmark_parser, "~> 1.4", [hex: :earmark_parser]}], "hexpm", "sum"},',
      '  "jason": {:hex, :jason, "1.4.1", "sum", [:mix], [], "hexpm", "sum"}',
      "}", "",
    ].join("\n"));

    const tree = await hexParser.resolve({ lockfilePath, manifestPath, workspaceFolder: workspace });

    assert.strictEqual(tree.dependencies.length, 3);
    assert.deepStrictEqual(
      tree.dependencies.filter((dependency) => dependency.isDevelopmentDependency)
        .map((dependency) => dependency.name).sort(),
      ["earmark_parser", "ex_doc"]
    );
    const child = tree.dependencies.find((dependency) => dependency.name === "earmark_parser");
    assert.strictEqual(child.parent, "ex_doc");
    assert.deepStrictEqual(child.parentChain, ["ex_doc"]);
  });

  test("keeps manifest-only path and git dependencies non-registry", async () => {
    const workspace = await createWorkspace();
    const manifestPath = path.join(workspace, "mix.exs");
    await writeTextFile(manifestPath, [
      "defp deps do", "  [", '    {:local_dep, path: "../local"},',
      '    {:git_dep, git: "https://user:secret@example.invalid/repo.git", only: :test}',
      "  ]", "end", "",
    ].join("\n"));

    const tree = await hexParser.resolve({ manifestPath, workspaceFolder: workspace });

    assert.deepStrictEqual(tree.dependencies.map((dependency) => dependency.packageSource.kind), ["path", "git"]);
    assert.strictEqual(tree.dependencies[1].packageSource.location.includes("secret"), false);
    assert.strictEqual(tree.dependencies[1].isDevelopmentDependency, true);
  });
});

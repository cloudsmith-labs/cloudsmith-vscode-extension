const assert = require("assert");
const vscode = require("vscode");
const { DiagnosticsPublisher } = require("../util/diagnosticsPublisher");
const { ManifestParser } = require("../util/manifestParser");

suite("DiagnosticsPublisher Test Suite", () => {
  let originalCreateDiagnosticCollection;
  let originalFindDependencyLocation;
  let collection;

  setup(() => {
    originalCreateDiagnosticCollection = vscode.languages.createDiagnosticCollection;
    originalFindDependencyLocation = ManifestParser.findDependencyLocation;
    collection = {
      setCalls: [],
      clearCalls: 0,
      set(entries) {
        this.setCalls.push(entries);
      },
      clear() {
        this.clearCalls += 1;
      },
      dispose() {},
    };
    vscode.languages.createDiagnosticCollection = () => collection;
  });

  teardown(() => {
    vscode.languages.createDiagnosticCollection = originalCreateDiagnosticCollection;
    ManifestParser.findDependencyLocation = originalFindDependencyLocation;
  });

  test("prepare builds a complete snapshot without clearing or publishing current diagnostics", async () => {
    ManifestParser.findDependencyLocation = async () => ({
      line: 1,
      startChar: 2,
      endChar: 10,
    });
    const publisher = new DiagnosticsPublisher();

    const entries = await publisher.prepare(
      [{ filePath: "/project/package.json", format: "npm" }],
      [{
        format: "npm",
        state: "not_found",
        name: "left-pad",
        declaredVersion: "1.0.0",
        cloudsmithMatch: null,
      }]
    );

    assert.strictEqual(collection.clearCalls, 0);
    assert.strictEqual(collection.setCalls.length, 0);
    assert.strictEqual(entries.length, 1);
    assert.strictEqual(entries[0][0].fsPath, "/project/package.json");
    assert.strictEqual(entries[0][1].length, 1);

    publisher.replace(entries);
    assert.strictEqual(collection.setCalls.length, 1);
    assert.strictEqual(collection.setCalls[0], entries);
  });

  test("a failed diagnostic build cannot publish a partial replacement", async () => {
    let locationCalls = 0;
    ManifestParser.findDependencyLocation = async () => {
      locationCalls += 1;
      if (locationCalls === 2) {
        throw new Error("manifest read failed");
      }
      return { line: 0, startChar: 0, endChar: 4 };
    };
    const publisher = new DiagnosticsPublisher();

    await assert.rejects(
      publisher.publish(
        [
          { filePath: "/project/package.json", format: "npm" },
          { filePath: "/project/other-package.json", format: "npm" },
        ],
        [{
          format: "npm",
          state: "not_found",
          name: "left-pad",
          declaredVersion: "1.0.0",
          cloudsmithMatch: null,
        }]
      ),
      /manifest read failed/
    );

    assert.strictEqual(collection.clearCalls, 0);
    assert.strictEqual(collection.setCalls.length, 0);
  });

  test("does not publish diagnostics for unresolved or incomplete lookups", async () => {
    let locationCalls = 0;
    ManifestParser.findDependencyLocation = async () => {
      locationCalls += 1;
      return { line: 0, startChar: 0, endChar: 4 };
    };
    const publisher = new DiagnosticsPublisher();
    const entries = await publisher.prepare(
      [{ filePath: "/project/package.json", format: "npm" }],
      [
        { format: "npm", state: "unresolved", name: "range-only", declaredVersion: "^1.0.0" },
        { format: "npm", state: "lookup_failed", name: "failed", declaredVersion: "1.0.0" },
        { format: "npm", state: "lookup_incomplete", name: "incomplete", declaredVersion: "1.0.0" },
        { format: "npm", state: "unknown", name: "unknown", declaredVersion: "1.0.0" },
      ]
    );

    assert.strictEqual(locationCalls, 0);
    assert.strictEqual(entries.length, 1);
    assert.deepStrictEqual(entries[0][1], []);
  });
});

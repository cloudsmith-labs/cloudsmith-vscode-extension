const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { pathToFileURL } = require("url");
const vscode = require("vscode");
const {
  DiagnosticsPublisher,
  createDiagnosticCandidate,
} = require("../util/diagnosticsPublisher");
const {
  DEPENDENCY_VERSION_STATES,
  RESOLUTION_SOURCE_KINDS,
  createDependencyRecord,
  createDependencySource,
} = require("../util/dependencyRecord");
const {
  ADAPTER_RESULT_STATUSES,
  createDefaultDependencyAdapterRegistry,
} = require("../util/dependencyAdapterRegistry");
const DependencyHealthNode = require("../models/dependencyHealthNode");
const {
  buildDependencyDeclarationIndex,
} = require("../util/dependencyDeclarationIndex");

suite("DiagnosticsPublisher Test Suite", () => {
  let originalCreateDiagnosticCollection;
  let collection;

  setup(() => {
    originalCreateDiagnosticCollection = vscode.languages.createDiagnosticCollection;
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
  });

  function source(filePath, type = path.basename(filePath), range = null) {
    return createDependencySource({
      kind: RESOLUTION_SOURCE_KINDS.MANIFEST,
      filePath,
      type,
      range,
    });
  }

  function candidate({
    name,
    declarationName = name,
    declaredConstraint = "1.0.0",
    resolvedVersion = null,
    ecosystem = "npm",
    manifest = null,
    state = "not_found",
    isDirect = true,
    isDevelopmentDependency = false,
    environmentMarker = null,
  }) {
    const dependency = createDependencyRecord({
      ecosystem,
      format: ecosystem,
      name,
      declarationName,
      declaredConstraint,
      resolvedVersion,
      versionState: resolvedVersion
        ? DEPENDENCY_VERSION_STATES.RESOLVED
        : DEPENDENCY_VERSION_STATES.EXACT_DECLARATION,
      sourceManifest: manifest,
      environmentMarker,
      isDirect,
      isDevelopmentDependency,
      parent: isDirect ? null : "parent-package",
      parentChain: isDirect ? [] : ["parent-package"],
      transitives: [],
      legacyVersion: resolvedVersion || declaredConstraint || "",
    });
    return createDiagnosticCandidate(dependency, {
      state,
      displayVersion: resolvedVersion || declaredConstraint || null,
      cloudsmithMatch: null,
    });
  }

  function createMemoryPublisher(files, options = {}) {
    const reads = [];
    const publisher = new DiagnosticsPublisher({
      ...options,
      async readSource(filePath, workspaceFolder) {
        reads.push({ filePath, workspaceFolder });
        if (!files.has(filePath)) {
          throw new Error("source read failed");
        }
        return files.get(filePath);
      },
    });
    return { publisher, reads };
  }

  function diagnosticsByPath(prepared) {
    return new Map(prepared.entries.map(([uri, diagnostics]) => [uri.fsPath, diagnostics]));
  }

  function highlightedText(content, diagnostic) {
    const lines = content.split(/\r\n|[\r\n]/);
    const range = diagnostic.range;
    assert.strictEqual(range.start.line, range.end.line);
    return lines[range.start.line].slice(range.start.character, range.end.character);
  }

  async function prepareFixtureDiagnostic(ecosystem, fixtureName, dependencyName) {
    const workspaceFolder = path.join(__dirname, "fixtures", fixtureName);
    const registry = createDefaultDependencyAdapterRegistry();
    const detection = (await registry.detect(workspaceFolder)).find((entry) => (
      entry.ecosystem === ecosystem
    ));
    assert.ok(detection, `expected ${ecosystem} fixture detection`);
    const adapterResult = await registry.parse(detection, {
      workspaceFolder,
      maxDependenciesToScan: 10000,
    });
    assert.ok([
      ADAPTER_RESULT_STATUSES.SUCCESS,
      ADAPTER_RESULT_STATUSES.PARTIAL,
    ].includes(adapterResult.status));
    const occurrence = adapterResult.dependencies.find((dependency) => (
      dependency.name === dependencyName
    ));
    assert.ok(occurrence, `expected ${dependencyName} in ${ecosystem} fixture`);
    const healthOccurrence = {
      ...occurrence,
      cloudsmithStatus: "ABSENT",
      cloudsmithPackage: null,
    };
    const healthNode = new DependencyHealthNode(healthOccurrence, {});
    assert.strictEqual(healthNode.state, "not_found");
    const publisher = new DiagnosticsPublisher();
    const prepared = await publisher.prepare({
      workspaceFolder,
      candidates: [createDiagnosticCandidate(healthOccurrence, {
        state: healthNode.state,
        displayVersion: healthNode.declaredVersion,
        cloudsmithMatch: healthNode.cloudsmithMatch,
      })],
    });
    return { occurrence, prepared };
  }

  test("uses npm provenance and never guesses across same-format manifests", async () => {
    const firstPath = "/project/app/package.json";
    const secondPath = "/project/tool/package.json";
    const firstContent = JSON.stringify({ dependencies: { alpha: "1.0.0" } }, null, 2);
    const secondContent = JSON.stringify({ dependencies: { beta: "2.0.0" } }, null, 2);
    const files = new Map([[firstPath, firstContent], [secondPath, secondContent]]);
    const { publisher, reads } = createMemoryPublisher(files);

    const prepared = await publisher.prepare({
      workspaceFolder: "/project",
      candidates: [
        candidate({ name: "alpha", manifest: source(firstPath), declaredConstraint: "1.0.0" }),
        candidate({ name: "beta", manifest: source(secondPath), declaredConstraint: "2.0.0" }),
      ],
    });
    const byPath = diagnosticsByPath(prepared);

    assert.strictEqual(reads.length, 2);
    assert.strictEqual(byPath.get(firstPath).length, 1);
    assert.strictEqual(byPath.get(secondPath).length, 1);
    assert.strictEqual(highlightedText(firstContent, byPath.get(firstPath)[0]), "alpha");
    assert.strictEqual(highlightedText(secondContent, byPath.get(secondPath)[0]), "beta");
  });

  test("maps exact JSON declarations correctly with CR-only line endings", async () => {
    const filePath = "/project/package.json";
    const content = [
      "{",
      '  "dependencies": {',
      '    "alpha": "1.0.0"',
      "  }",
      "}",
    ].join("\r");
    const { publisher } = createMemoryPublisher(new Map([[filePath, content]]));
    const prepared = await publisher.prepare({
      workspaceFolder: "/project",
      candidates: [candidate({ name: "alpha", manifest: source(filePath) })],
    });
    const diagnostic = prepared.entries[0][1][0];

    assert.deepStrictEqual(
      [
        diagnostic.range.start.line,
        diagnostic.range.start.character,
        diagnostic.range.end.line,
        diagnostic.range.end.character,
      ],
      [2, 5, 2, 10]
    );
    assert.strictEqual(highlightedText(content, diagnostic), "alpha");
  });

  test("keeps the same Python package and different constraints distinct across manifests", async () => {
    const firstPath = "/project/requirements.txt";
    const secondPath = "/project/services/api/constraints.txt";
    const files = new Map([
      [firstPath, "requests==2.31.0\nclean-package==1.0.0\n"],
      [secondPath, "requests==2.32.3\n"],
    ]);
    const { publisher, reads } = createMemoryPublisher(files);
    const prepared = await publisher.prepare({
      workspaceFolder: "/project",
      candidates: [
        candidate({
          ecosystem: "python",
          name: "requests",
          declaredConstraint: "==2.31.0",
          manifest: source(firstPath),
        }),
        candidate({
          ecosystem: "python",
          name: "requests",
          declaredConstraint: "==2.32.3",
          manifest: source(secondPath),
        }),
      ],
    });
    const byPath = diagnosticsByPath(prepared);

    assert.strictEqual(reads.length, 2);
    assert.strictEqual(prepared.stats.diagnostics, 2);
    assert.strictEqual(highlightedText(files.get(firstPath), byPath.get(firstPath)[0]), "requests");
    assert.strictEqual(highlightedText(files.get(secondPath), byPath.get(secondPath)[0]), "requests");
  });

  test("uses each Python declaration source when same-format manifests contain different packages", async () => {
    const firstPath = "/project/requirements.txt";
    const secondPath = "/project/services/api/requirements.txt";
    const firstContent = "requests==2.31.0\nclean-package==1.0.0\n";
    const secondContent = "fastapi==0.111.0\n";
    const { publisher, reads } = createMemoryPublisher(new Map([
      [firstPath, firstContent],
      [secondPath, secondContent],
    ]));
    const prepared = await publisher.prepare({
      workspaceFolder: "/project",
      candidates: [
        candidate({
          ecosystem: "python",
          name: "requests",
          declaredConstraint: "==2.31.0",
          manifest: source(firstPath),
        }),
        candidate({
          ecosystem: "python",
          name: "fastapi",
          declaredConstraint: "==0.111.0",
          manifest: source(secondPath),
        }),
      ],
    });
    const byPath = diagnosticsByPath(prepared);

    assert.deepStrictEqual(reads.map((entry) => entry.filePath).sort(), [firstPath, secondPath].sort());
    assert.strictEqual(byPath.get(firstPath).length, 1);
    assert.strictEqual(byPath.get(secondPath).length, 1);
    assert.strictEqual(highlightedText(firstContent, byPath.get(firstPath)[0]), "requests");
    assert.strictEqual(highlightedText(secondContent, byPath.get(secondPath)[0]), "fastapi");
  });

  test("highlights an npm alias declaration rather than the resolved package name or scripts", async () => {
    const filePath = "/project/package.json";
    const content = JSON.stringify({
      scripts: { "real-package": "echo unrelated" },
      dependencies: { "package-alias": "npm:real-package@1.0.0" },
    }, null, 2);
    const { publisher } = createMemoryPublisher(new Map([[filePath, content]]));
    const prepared = await publisher.prepare({
      workspaceFolder: "/project",
      candidates: [candidate({
        name: "real-package",
        declarationName: "package-alias",
        declaredConstraint: "npm:real-package@1.0.0",
        manifest: source(filePath),
      })],
    });

    assert.strictEqual(
      highlightedText(content, prepared.entries[0][1][0]),
      "package-alias"
    );
  });

  test("distinguishes runtime and development declarations of the same npm package", async () => {
    const filePath = "/project/package.json";
    const content = JSON.stringify({
      dependencies: { shared: "1.0.0" },
      devDependencies: { shared: "2.0.0" },
    }, null, 2);
    const { publisher } = createMemoryPublisher(new Map([[filePath, content]]));
    const prepared = await publisher.prepare({
      workspaceFolder: "/project",
      candidates: [
        candidate({ name: "shared", declaredConstraint: "1.0.0", manifest: source(filePath) }),
        candidate({
          name: "shared",
          declaredConstraint: "2.0.0",
          manifest: source(filePath),
          isDevelopmentDependency: true,
        }),
      ],
    });
    const diagnostics = prepared.entries[0][1];

    assert.strictEqual(diagnostics.length, 2);
    assert.deepStrictEqual(diagnostics.map((diagnostic) => diagnostic.range.start.line), [2, 5]);
  });

  test("falls back to the file when duplicate JSON keys make a precise range ambiguous", async () => {
    const filePath = "/project/package.json";
    const content = [
      "{",
      "  \"dependencies\": {",
      "    \"shared\": \"1.0.0\",",
      "    \"shared\": \"2.0.0\"",
      "  }",
      "}",
    ].join("\n");
    const { publisher } = createMemoryPublisher(new Map([[filePath, content]]));
    const prepared = await publisher.prepare({
      workspaceFolder: "/project",
      candidates: [candidate({
        name: "shared",
        declaredConstraint: "2.0.0",
        manifest: source(filePath),
      })],
    });
    const diagnostic = prepared.entries[0][1][0];

    assert.deepStrictEqual(
      [diagnostic.range.start.line, diagnostic.range.start.character, diagnostic.range.end.line],
      [0, 0, 0]
    );
    assert.strictEqual(prepared.stats.fileRanges, 1);
  });

  test("indexes a provenance-only included requirements source", async () => {
    const includedPath = "/project/requirements/base.txt";
    const content = "urllib3==2.2.2\n";
    const { publisher, reads } = createMemoryPublisher(new Map([[includedPath, content]]));
    const prepared = await publisher.prepare({
      workspaceFolder: "/project",
      candidates: [candidate({
        ecosystem: "python",
        name: "urllib3",
        declaredConstraint: "==2.2.2",
        manifest: source(includedPath),
      })],
    });

    assert.deepStrictEqual(reads.map((entry) => entry.filePath), [includedPath]);
    assert.strictEqual(prepared.entries[0][0].fsPath, includedPath);
    assert.strictEqual(highlightedText(content, prepared.entries[0][1][0]), "urllib3");
  });

  test("indexes Poetry and PEP 621 declarations structurally", async () => {
    const filePath = "/project/pyproject.toml";
    const content = [
      "[tool.poetry.dependencies]",
      "requests = { version = \"^2.31\", optional = true }",
      "",
      "[project]",
      "dependencies = [",
      "  \"fastapi==0.111.0\", # API",
      "]",
    ].join("\n");
    const { publisher } = createMemoryPublisher(new Map([[filePath, content]]));
    const prepared = await publisher.prepare({
      workspaceFolder: "/project",
      candidates: [
        candidate({
          ecosystem: "python",
          name: "requests",
          declaredConstraint: "^2.31",
          manifest: source(filePath, "pyproject.toml"),
        }),
        candidate({
          ecosystem: "python",
          name: "fastapi",
          declaredConstraint: "==0.111.0",
          manifest: source(filePath, "pyproject.toml"),
        }),
      ],
    });
    const diagnostics = prepared.entries[0][1];

    assert.strictEqual(highlightedText(content, diagnostics[0]), "requests");
    assert.strictEqual(highlightedText(content, diagnostics[1]), "fastapi");
  });

  test("requirements option scanning performs a bounded number of string slices", () => {
    const originalSlice = String.prototype.slice;
    let sliceCalls = 0;
    String.prototype.slice = function (...args) {
      sliceCalls += 1;
      return Reflect.apply(originalSlice, this, args);
    };
    try {
      const index = buildDependencyDeclarationIndex({
        content: `bounded-package==1.0.0${" ".repeat(100000)}--hash=sha256:abc`,
        sourceType: "requirements.txt",
        ecosystem: "python",
        wantedNames: ["bounded-package"],
      });

      assert.strictEqual(index.declarationCount, 1);
      assert.ok(sliceCalls < 50, `expected bounded slicing, observed ${sliceCalls} calls`);
    } finally {
      String.prototype.slice = originalSlice;
    }
  });

  test("rejects excessive JSON depth before allocating a parsed object graph", () => {
    const originalParse = JSON.parse;
    const content = `{"dependencies":${"[".repeat(129)}${"]".repeat(129)}}`;
    let documentParseCalled = false;
    JSON.parse = (value, ...args) => {
      if (value === content) {
        documentParseCalled = true;
      }
      return Reflect.apply(originalParse, JSON, [value, ...args]);
    };
    try {
      assert.throws(
        () => buildDependencyDeclarationIndex({
          content,
          sourceType: "package.json",
          ecosystem: "npm",
          wantedNames: ["bounded-package"],
        }),
        /nesting exceeds the indexing limit/
      );
      assert.strictEqual(documentParseCalled, false);
    } finally {
      JSON.parse = originalParse;
    }
  });

  test("matches Maven by direct full coordinates and excludes dependency management", async () => {
    const filePath = "/project/pom.xml";
    const content = [
      "<project>",
      "  <dependencyManagement><dependencies><dependency>",
      "    <groupId>wrong.group</groupId><artifactId>shared</artifactId><version>1.0.0</version>",
      "  </dependency></dependencies></dependencyManagement>",
      "  <dependencies>",
      "    <dependency>",
      "      <groupId>right.group</groupId>",
      "      <artifactId>shared</artifactId>",
      "      <version>1.0.0</version>",
      "    </dependency>",
      "  </dependencies>",
      "</project>",
    ].join("\n");
    const { publisher } = createMemoryPublisher(new Map([[filePath, content]]));
    const prepared = await publisher.prepare({
      workspaceFolder: "/project",
      candidates: [candidate({
        ecosystem: "maven",
        name: "right.group:shared",
        declaredConstraint: "1.0.0",
        manifest: source(filePath),
      })],
    });

    const diagnostic = prepared.entries[0][1][0];
    assert.strictEqual(diagnostic.range.start.line, 7);
    assert.strictEqual(highlightedText(content, diagnostic), "shared");
  });

  test("rejects repeated invalid Maven markup without rescanning token suffixes", () => {
    const originalSlice = String.prototype.slice;
    let sliceCalls = 0;
    String.prototype.slice = function (...args) {
      sliceCalls += 1;
      return Reflect.apply(originalSlice, this, args);
    };
    try {
      assert.throws(
        () => buildDependencyDeclarationIndex({
          content: `${"<!".repeat(100000)}>`,
          sourceType: "pom.xml",
          ecosystem: "maven",
          wantedNames: ["example:package"],
        }),
        /unsupported XML markup/
      );
      assert.ok(sliceCalls < 10, `expected bounded slicing, observed ${sliceCalls} calls`);
    } finally {
      String.prototype.slice = originalSlice;
    }
  });

  test("uses the Go require declaration instead of comments and replacements", async () => {
    const filePath = "/project/go.mod";
    const content = [
      "module example.com/app",
      "// example.com/original is discussed here",
      "require example.com/original v1.0.0",
      "replace example.com/original => example.com/replacement v1.2.0",
    ].join("\n");
    const { publisher } = createMemoryPublisher(new Map([[filePath, content]]));
    const prepared = await publisher.prepare({
      workspaceFolder: "/project",
      candidates: [candidate({
        ecosystem: "go",
        name: "example.com/replacement",
        declarationName: "example.com/original",
        declaredConstraint: "v1.2.0",
        manifest: source(filePath),
      })],
    });

    const diagnostic = prepared.entries[0][1][0];
    assert.strictEqual(diagnostic.range.start.line, 2);
    assert.strictEqual(highlightedText(content, diagnostic), "example.com/original");
  });

  test("uses validated provenance ranges and retains multiple resolved occurrences", async () => {
    const filePath = "/project/package.json";
    const content = "{\n  \"dependencies\": { \"shared\": \"1.0.0\" }\n}\n";
    const manifest = source(filePath, "package.json", {
      start: { line: 1, character: 21 },
      end: { line: 1, character: 27 },
    });
    const { publisher, reads } = createMemoryPublisher(new Map([[filePath, content]]));
    const prepared = await publisher.prepare({
      workspaceFolder: "/project",
      candidates: [
        candidate({ name: "shared", resolvedVersion: "1.0.0", manifest }),
        candidate({ name: "shared", resolvedVersion: "2.0.0", manifest }),
      ],
    });

    assert.strictEqual(reads.length, 1);
    assert.strictEqual(prepared.entries[0][1].length, 2);
    assert.deepStrictEqual(
      prepared.entries[0][1].map((diagnostic) => diagnostic.range.start.character),
      [21, 21]
    );
  });

  test("uses a correct file-level fallback for unsupported precise locations", async () => {
    const filePath = "/project/Cargo.toml";
    const content = "# serde in a comment\n[dependencies]\nserde = \"1.0.0\"\n";
    const { publisher } = createMemoryPublisher(new Map([[filePath, content]]));
    const prepared = await publisher.prepare({
      workspaceFolder: "/project",
      candidates: [candidate({
        ecosystem: "cargo",
        name: "serde",
        declaredConstraint: "1.0.0",
        manifest: source(filePath, "Cargo.toml"),
      })],
    });
    const range = prepared.entries[0][1][0].range;

    assert.deepStrictEqual(
      [range.start.line, range.start.character, range.end.line, range.end.character],
      [0, 0, 0, 0]
    );
    assert.strictEqual(prepared.stats.fileRanges, 1);
  });

  test("keeps Gradle coarse when source contains less-than operators", async () => {
    const filePath = "/project/build.gradle";
    const content = [
      "dependencies {",
      "  implementation 'org.example:library:1.0.0'",
      "}",
      "if (JavaVersion.current() < JavaVersion.VERSION_21) { println 'legacy' }",
    ].join("\n");
    const { publisher } = createMemoryPublisher(new Map([[filePath, content]]));
    const prepared = await publisher.prepare({
      workspaceFolder: "/project",
      candidates: [candidate({
        ecosystem: "gradle",
        name: "org.example:library",
        declaredConstraint: "1.0.0",
        manifest: source(filePath, "build.gradle"),
      })],
    });
    const range = prepared.entries[0][1][0].range;

    assert.deepStrictEqual(
      [range.start.line, range.start.character, range.end.line, range.end.character],
      [0, 0, 0, 0]
    );
    assert.strictEqual(prepared.stats.fileRanges, 1);
  });

  test("does not invent locations for transitive or missing-provenance dependencies", async () => {
    const { publisher, reads } = createMemoryPublisher(new Map());
    const prepared = await publisher.prepare({
      workspaceFolder: "/project",
      candidates: [
        candidate({ name: "transitive", manifest: null, isDirect: false }),
        candidate({ name: "missing-source", manifest: null, isDirect: true }),
      ],
    });

    assert.strictEqual(reads.length, 0);
    assert.strictEqual(prepared.entries.length, 0);
    assert.strictEqual(prepared.warnings.length, 1);
    assert.match(prepared.warnings[0], /manifest provenance was unavailable/);
  });

  test("deduplicates an exact occurrence without collapsing distinct declarations", async () => {
    const firstPath = "/project/a/package.json";
    const secondPath = "/project/b/package.json";
    const first = candidate({ name: "shared", manifest: source(firstPath) });
    const second = candidate({ name: "shared", manifest: source(secondPath) });
    const files = new Map([
      [firstPath, '{"dependencies":{"shared":"1.0.0"}}'],
      [secondPath, '{"dependencies":{"shared":"1.0.0"}}'],
    ]);
    const { publisher } = createMemoryPublisher(files);
    const prepared = await publisher.prepare({
      workspaceFolder: "/project",
      candidates: [first, first, second],
    });

    assert.strictEqual(prepared.stats.uniqueOccurrences, 2);
    assert.strictEqual(prepared.stats.diagnostics, 2);
  });

  test("reads and indexes one source once for one thousand dependencies", async () => {
    const filePath = "/project/package.json";
    const dependencies = {};
    const candidates = [];
    const manifest = source(filePath);
    for (let index = 0; index < 1000; index += 1) {
      const name = `package-${index}`;
      dependencies[name] = "1.0.0";
      candidates.push(candidate({ name, manifest }));
    }
    const content = JSON.stringify({ dependencies });
    const { publisher, reads } = createMemoryPublisher(new Map([[filePath, content]]));
    const prepared = await publisher.prepare({ workspaceFolder: "/project", candidates });

    assert.strictEqual(reads.length, 1);
    assert.strictEqual(prepared.stats.sourceReads, 1);
    assert.strictEqual(prepared.stats.indexedSources, 1);
    assert.strictEqual(prepared.stats.diagnostics, 1000);
  });

  test("scales structurally to one hundred sources and rebuilds indexes per scan", async () => {
    const files = new Map();
    const candidates = [];
    for (let sourceIndex = 0; sourceIndex < 100; sourceIndex += 1) {
      const filePath = `/project/service-${sourceIndex}/package.json`;
      const dependencies = {};
      const manifest = source(filePath);
      for (let dependencyIndex = 0; dependencyIndex < 10; dependencyIndex += 1) {
        const name = `package-${sourceIndex}-${dependencyIndex}`;
        dependencies[name] = "1.0.0";
        candidates.push(candidate({ name, manifest }));
      }
      files.set(filePath, JSON.stringify({ dependencies }));
    }
    const { publisher, reads } = createMemoryPublisher(files);

    const first = await publisher.prepare({ workspaceFolder: "/project", candidates });
    const second = await publisher.prepare({ workspaceFolder: "/project", candidates });

    assert.strictEqual(first.entries.length, 100);
    assert.strictEqual(first.stats.sourceReads, 100);
    assert.strictEqual(first.stats.diagnostics, 1000);
    assert.strictEqual(second.stats.sourceReads, 100);
    assert.strictEqual(reads.length, 200);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(first, "contents"), false);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(first, "indexes"), false);
  });

  test("caps output deterministically with an explicit warning", async () => {
    const filePath = "/project/package.json";
    const manifest = source(filePath);
    const dependencies = { alpha: "1.0.0", beta: "1.0.0", gamma: "1.0.0" };
    const { publisher } = createMemoryPublisher(
      new Map([[filePath, JSON.stringify({ dependencies })]]),
      { maxDiagnostics: 2 }
    );
    const prepared = await publisher.prepare({
      workspaceFolder: "/project",
      candidates: [
        candidate({ name: "alpha", manifest }),
        candidate({ name: "beta", manifest }),
        candidate({ name: "gamma", manifest }),
      ],
    });

    assert.strictEqual(prepared.stats.diagnostics, 2);
    assert.strictEqual(prepared.stats.truncated, true);
    assert.match(prepared.warnings[0], /capped at 2 occurrences/);
  });

  test("a truncated declaration index uses a coarse range and distinct warning", async () => {
    const filePath = "/project/requirements.txt";
    const content = Array.from(
      { length: 10001 },
      (_, index) => `repeated-package==${index}`
    ).join("\n");
    const { publisher, reads } = createMemoryPublisher(new Map([[filePath, content]]));
    const prepared = await publisher.prepare({
      workspaceFolder: "/project",
      candidates: [candidate({
        ecosystem: "python",
        name: "repeated-package",
        declaredConstraint: "==0",
        manifest: source(filePath, "requirements.txt"),
      })],
    });
    const range = prepared.entries[0][1][0].range;

    assert.strictEqual(reads.length, 1);
    assert.deepStrictEqual(
      [range.start.line, range.start.character, range.end.line, range.end.character],
      [0, 0, 0, 0]
    );
    assert.strictEqual(prepared.stats.truncatedSourceIndexes, 1);
    assert.strictEqual(prepared.stats.diagnosticOutputTruncated, false);
    assert.match(prepared.warnings[0], /source declaration index was capped/);
    assert.doesNotMatch(prepared.warnings[0], /diagnostics were capped/);
  });

  test("read and index failures cannot publish a partial replacement", async () => {
    const filePath = "/project/package.json";
    const { publisher } = createMemoryPublisher(new Map());
    await assert.rejects(
      publisher.publish({
        workspaceFolder: "/project",
        candidates: [candidate({ name: "alpha", manifest: source(filePath) })],
      }),
      /source read failed/
    );

    assert.strictEqual(collection.setCalls.length, 0);
    assert.strictEqual(collection.clearCalls, 0);
  });

  test("the production reader rejects provenance outside the scan workspace", async () => {
    const workspaceFolder = await fs.promises.mkdtemp(path.join(os.tmpdir(), "diagnostic-workspace-"));
    const outsideFolder = await fs.promises.mkdtemp(path.join(os.tmpdir(), "diagnostic-outside-"));
    const outsidePath = path.join(outsideFolder, "package.json");
    await fs.promises.writeFile(
      outsidePath,
      JSON.stringify({ dependencies: { escaped: "1.0.0" } }),
      "utf8"
    );
    try {
      const publisher = new DiagnosticsPublisher();
      await assert.rejects(
      () => publisher.prepare({
          workspaceFolder,
          candidates: [candidate({ name: "escaped", manifest: source(outsidePath) })],
        }),
        (error) => error && error.code === "ERR_DEPENDENCY_FILE_OUTSIDE_WORKSPACE"
      );
      assert.strictEqual(collection.setCalls.length, 0);
    } finally {
      await fs.promises.rm(workspaceFolder, { recursive: true, force: true });
      await fs.promises.rm(outsideFolder, { recursive: true, force: true });
    }
  });

  for (const fixture of [
    { ecosystem: "npm", fixtureName: "npm", dependencyName: "express", expected: "express" },
    { ecosystem: "python", fixtureName: "python", dependencyName: "fastapi", expected: "fastapi" },
    {
      ecosystem: "maven",
      fixtureName: "maven",
      dependencyName: "org.springframework.boot:spring-boot-starter-web",
      expected: "spring-boot-starter-web",
    },
  ]) {
    test(`${fixture.ecosystem} adapter occurrence flows through health and diagnostics`, async () => {
      const { occurrence, prepared } = await prepareFixtureDiagnostic(
        fixture.ecosystem,
        fixture.fixtureName,
        fixture.dependencyName
      );
      const fileContent = await fs.promises.readFile(occurrence.sourceManifest.filePath, "utf8");
      const diagnostic = prepared.entries[0][1][0];

      assert.strictEqual(prepared.entries[0][0].fsPath, occurrence.sourceManifest.filePath);
      assert.strictEqual(highlightedText(fileContent, diagnostic), fixture.expected);
    });
  }

  test("rejects malformed JSON instead of publishing an empty-success snapshot", async () => {
    const filePath = "/project/package.json";
    const { publisher } = createMemoryPublisher(new Map([[filePath, "{not-json"]]));
    await assert.rejects(
      publisher.prepare({
        workspaceFolder: "/project",
        candidates: [candidate({ name: "alpha", manifest: source(filePath) })],
      }),
      /JSON (?:source is malformed|structure is invalid)/
    );
  });

  test("rejects contradictory ecosystem and source indexing contracts", async () => {
    const filePath = "/project/package.json";
    const files = new Map([[filePath, '{"dependencies":{"alpha":"1.0.0","beta":"1.0.0"}}']]);
    const { publisher } = createMemoryPublisher(files);

    await assert.rejects(
      publisher.prepare({
        workspaceFolder: "/project",
        candidates: [
          candidate({ name: "alpha", manifest: source(filePath) }),
          candidate({ ecosystem: "composer", name: "beta", manifest: source(filePath) }),
        ],
      }),
      /disagree about their manifest source contract/
    );
    await assert.rejects(
      publisher.prepare({
        workspaceFolder: "/project",
        candidates: [candidate({ ecosystem: "maven", name: "alpha", manifest: source(filePath) })],
      }),
      /source type package\.json is incompatible with ecosystem maven/
    );
    assert.strictEqual(collection.setCalls.length, 0);
  });

  test("rejects accessor contracts and mismatched source URI/path provenance", async () => {
    const dependency = {
      ecosystem: "npm",
      format: "npm",
      name: "alpha",
      declarationName: "alpha",
      declaredConstraint: "1.0.0",
      resolvedVersion: null,
      versionState: DEPENDENCY_VERSION_STATES.EXACT_DECLARATION,
      resolutionSource: null,
      sourceManifest: null,
      environmentMarker: null,
      isDirect: true,
      isDevelopmentDependency: false,
      parent: null,
      parentChain: [],
      legacyVersion: "1.0.0",
    };
    Object.defineProperty(dependency, "sourceManifest", {
      enumerable: true,
      get() {
        return null;
      },
    });
    assert.throws(
      () => createDiagnosticCandidate(dependency, {
        state: "not_found",
        displayVersion: "1.0.0",
        cloudsmithMatch: null,
      }),
      /must not contain accessors/
    );

    const valid = source("/project/package.json");
    const forged = { ...valid, uri: pathToWrongFileUri("/project/other.json") };
    const forgedDependency = {
      ecosystem: "npm",
      format: "npm",
      name: "alpha",
      declarationName: "alpha",
      declaredConstraint: "1.0.0",
      resolvedVersion: null,
      versionState: DEPENDENCY_VERSION_STATES.EXACT_DECLARATION,
      resolutionSource: null,
      sourceManifest: forged,
      environmentMarker: null,
      isDirect: true,
      isDevelopmentDependency: false,
      parent: null,
      parentChain: [],
      legacyVersion: "1.0.0",
    };
    assert.throws(
      () => createDiagnosticCandidate(forgedDependency, {
        state: "not_found",
        displayVersion: "1.0.0",
        cloudsmithMatch: null,
      }),
      /URI and path must identify the same file/
    );
  });
});

function pathToWrongFileUri(filePath) {
  return pathToFileURL(filePath).toString();
}

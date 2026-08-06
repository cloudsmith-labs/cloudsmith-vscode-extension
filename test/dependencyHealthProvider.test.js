const assert = require("assert");
const vscode = require("vscode");
const {
  DependencyHealthProvider,
  matchCoverageCandidates,
} = require("../views/dependencyHealthProvider");
const { normalizePackageName } = require("../util/packageNameNormalizer");

suite("DependencyHealthProvider Test Suite", () => {
  function createContext(isConnected = "true") {
    return {
      secrets: {
        onDidChange() {},
        async get(key) {
          if (key === "cloudsmith-vsc.isConnected") {
            return isConnected;
          }
          return null;
        },
      },
      workspaceState: {
        get() {
          return null;
        },
        async update() {},
      },
    };
  }

  function createDependency(name, version, format = "npm") {
    return {
      name,
      version,
      format,
      ecosystem: format,
      isDirect: true,
      parent: null,
      parentChain: [],
      transitives: [],
      cloudsmithStatus: "CHECKING",
      cloudsmithPackage: null,
      sourceFile: "package-lock.json",
      isDevelopmentDependency: false,
    };
  }

  function createFoundDependency(name, version) {
    return {
      ...createDependency(name, version),
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: {
        namespace: "workspace",
        repository: "repo",
        slug_perm: `${name}/${version}`,
      },
    };
  }

  function cloneTrees(trees) {
    return JSON.parse(JSON.stringify(trees));
  }

  function buildCoverageIndex(dependencies) {
    const index = new Map();

    for (const dependency of dependencies) {
      const nameKey = normalizePackageName(dependency.name, dependency.format);
      const versionKey = dependency.version.toLowerCase();
      if (!index.has(nameKey)) {
        index.set(nameKey, new Map());
      }
      index.get(nameKey).set(versionKey, [{
        name: dependency.name,
        version: dependency.version,
      }]);
    }

    return index;
  }

  setup(() => {
    DependencyHealthProvider.packageIndexCache.clear();
  });

  test("getChildren() shows the signed-out state when disconnected before the first scan", async () => {
    const provider = new DependencyHealthProvider(createContext("false"));
    const nodes = await provider.getChildren();

    assert.strictEqual(nodes.length, 1);
    assert.strictEqual(nodes[0].getTreeItem().label, "Connect to Cloudsmith");
  });

  test("_runCoverageChecks batches tree rebuilds and refreshes while preserving matches", async () => {
    const provider = new DependencyHealthProvider(createContext());
    const dependencies = Array.from({ length: 51 }, (_, index) => createDependency(`package-${index}`, "1.0.0"));
    const trees = [{
      ecosystem: "npm",
      sourceFile: "package-lock.json",
      dependencies,
    }];

    provider._fullTrees = cloneTrees(trees);
    provider._displayTrees = cloneTrees(trees);

    let rebuildCount = 0;
    let refreshCount = 0;
    const progressUpdates = [];

    provider._rebuildSummary = () => {
      rebuildCount += 1;
    };
    provider.refresh = () => {
      refreshCount += 1;
    };
    provider._fetchPackageIndex = async () => ({
      error: null,
      tooLarge: false,
      index: buildCoverageIndex(dependencies),
    });

    await provider._runCoverageChecks(
      "workspace",
      "repo",
      dependencies.length,
      {
        report(update) {
          progressUpdates.push(update);
        },
      },
      { isCancellationRequested: false }
    );

    assert.strictEqual(rebuildCount, 2);
    assert.strictEqual(refreshCount, 2);
    assert.strictEqual(progressUpdates.length, 2);
    assert.strictEqual(progressUpdates[0].message, "Matching coverage... 50/51");
    assert.strictEqual(progressUpdates[1].message, "Matching coverage... 51/51");
    assert.strictEqual(
      provider._fullTrees[0].dependencies.every((dependency) => dependency.cloudsmithStatus === "FOUND"),
      true
    );
    assert.strictEqual(
      provider._displayTrees[0].dependencies.every((dependency) => dependency.cloudsmithStatus === "FOUND"),
      true
    );
  });

  test("_runCoverageChecks fetches package indices for multiple formats in parallel", async () => {
    const provider = new DependencyHealthProvider(createContext());
    const npmDependency = createDependency("left-pad", "1.0.0", "npm");
    const pythonDependency = createDependency("requests", "2.31.0", "python");

    provider._fullTrees = [
      {
        ecosystem: "npm",
        sourceFile: "package-lock.json",
        dependencies: [npmDependency],
      },
      {
        ecosystem: "python",
        sourceFile: "requirements.txt",
        dependencies: [pythonDependency],
      },
    ];
    provider._displayTrees = cloneTrees(provider._fullTrees);

    const resolvers = new Map();
    let inFlight = 0;
    let maxInFlight = 0;

    provider._rebuildSummary = () => {};
    provider.refresh = () => {};
    provider._fetchPackageIndex = async (_workspace, _repo, format) => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);

      return new Promise((resolve) => {
        resolvers.set(format, () => {
          inFlight -= 1;
          const dependency = format === "npm" ? npmDependency : pythonDependency;
          resolve({
            error: null,
            tooLarge: false,
            index: buildCoverageIndex([dependency]),
          });
        });
      });
    };

    const runPromise = provider._runCoverageChecks(
      "workspace",
      "repo",
      2,
      { report() {} },
      { isCancellationRequested: false }
    );

    await new Promise((resolve) => setImmediate(resolve));
    assert.strictEqual(maxInFlight, 2);

    resolvers.get("npm")();
    resolvers.get("python")();
    await runPromise;
  });

  test("_fetchPackageIndex fetches remaining pages concurrently after page one", async () => {
    const provider = new DependencyHealthProvider(createContext());
    const requestedPages = [];
    const pageResolvers = new Map();

    provider._fetchSinglePage = async (_workspace, _repo, _format, page) => {
      requestedPages.push(page);
      if (page === 1) {
        return {
          error: null,
          pagination: {
            count: 3,
            pageTotal: 3,
          },
          data: [{
            name: "page-one",
            version: "1.0.0",
          }],
        };
      }

      return new Promise((resolve) => {
        pageResolvers.set(page, resolve);
      });
    };

    const fetchPromise = provider._fetchPackageIndex("workspace", "repo", "npm");
    await new Promise((resolve) => setImmediate(resolve));

    assert.deepStrictEqual(requestedPages, [1, 2, 3]);

    pageResolvers.get(2)({
      error: null,
      data: [{
        name: "page-two",
        version: "1.0.0",
      }],
    });
    pageResolvers.get(3)({
      error: null,
      data: [{
        name: "page-three",
        version: "1.0.0",
      }],
    });

    const result = await fetchPromise;
    assert.strictEqual(result.error, null);
    assert.strictEqual(result.totalCount, 3);
    assert.strictEqual(result.index.get("page-two").has("1.0.0"), true);
    assert.strictEqual(result.index.get("page-three").has("1.0.0"), true);
  });

  test("matchCoverageCandidates returns null when fallback results do not match the dependency name", () => {
    const match = matchCoverageCandidates(
      [
        { name: "left-pad-plus", version: "1.0.0", format: "npm" },
        { name: "pad-left", version: "1.0.0", format: "npm" },
      ],
      createDependency("left-pad", "1.0.0")
    );

    assert.strictEqual(match, null);
  });

  test("matchCoverageCandidates falls back to a name match when versions differ", () => {
    const nameOnlyMatch = { name: "left-pad", version: "1.1.0", format: "npm" };
    const match = matchCoverageCandidates(
      [
        { name: "left-pad-plus", version: "1.0.0", format: "npm" },
        nameOnlyMatch,
      ],
      createDependency("left-pad", "1.0.0")
    );

    assert.strictEqual(match, nameOnlyMatch);
  });

  test("_runLicenseEnrichment flushes multiple progress patches in one refresh", async () => {
    const provider = new DependencyHealthProvider(createContext(), null, {
      enrichLicenses: async (_dependencies, options = {}) => {
        options.onProgress(new Map([
          ["workspace:repo:left-pad/1.0.0", { spdx: "MIT" }],
        ]));
        options.onProgress(new Map([
          ["workspace:repo:left-pad/1.0.0", { spdx: "Apache-2.0" }],
        ]));
      },
    });

    const trees = [{
      ecosystem: "npm",
      sourceFile: "package-lock.json",
      dependencies: [createFoundDependency("left-pad", "1.0.0")],
    }];
    provider._fullTrees = cloneTrees(trees);
    provider._displayTrees = cloneTrees(trees);

    let rebuildCount = 0;
    let refreshCount = 0;
    provider._rebuildSummary = () => {
      rebuildCount += 1;
    };
    provider.refresh = () => {
      refreshCount += 1;
    };

    await provider._runLicenseEnrichment(provider._fullTrees[0].dependencies, { isCancellationRequested: false });

    assert.strictEqual(rebuildCount, 1);
    assert.strictEqual(refreshCount, 1);
    assert.strictEqual(provider._fullTrees[0].dependencies[0].license.spdx, "Apache-2.0");
    assert.strictEqual(provider._displayTrees[0].dependencies[0].license.spdx, "Apache-2.0");
  });

  test("pullSingleDependency refreshes coverage after a successful single-package pull", async () => {
    const originalWithProgress = vscode.window.withProgress;
    const originalShowInformationMessage = vscode.window.showInformationMessage;
    const originalShowErrorMessage = vscode.window.showErrorMessage;
    const notifications = [];
    let refreshArgs = null;

    vscode.window.withProgress = async (_options, task) => task(
      { report() {} },
      {
        onCancellationRequested() {
          return { dispose() {} };
        },
      }
    );
    vscode.window.showInformationMessage = async (message) => {
      notifications.push(message);
    };
    vscode.window.showErrorMessage = async (message) => {
      notifications.push(`error:${message}`);
    };

    try {
      const provider = new DependencyHealthProvider(createContext(), null, {
        upstreamPullService: {
          async prepareSingle({ dependency }) {
            return {
              workspace: "workspace-a",
              repository: { slug: "repo-b" },
              dependency,
              plan: { skippedDependencies: [] },
            };
          },
          async execute() {
            return {
              canceled: false,
              pullResult: {
                total: 1,
                cached: 1,
                alreadyExisted: 0,
                notFound: 0,
                formatMismatched: 0,
                errors: 0,
                networkErrors: 0,
                authFailed: 0,
                skipped: 0,
                details: [{
                  status: "cached",
                  dependency: {
                    name: "requests",
                    version: "2.31.0",
                    format: "python",
                  },
                }],
              },
            };
          },
        },
      });

      provider.lastWorkspace = "workspace-a";
      provider.lastRepo = "repo-a";
      provider._updateContexts = async () => {};
      provider.refresh = () => {};
      provider._refreshSingleDependencyAfterPull = async (workspace, repo, dependency) => {
        refreshArgs = { workspace, repo, dependency };
      };

      await provider.pullSingleDependency({
        name: "requests",
        version: "2.31.0",
        format: "python",
        ecosystem: "python",
      });

      assert.deepStrictEqual(refreshArgs, {
        workspace: "workspace-a",
        repo: "repo-b",
        dependency: {
          name: "requests",
          version: "2.31.0",
          format: "python",
          ecosystem: "python",
        },
      });
      assert.deepStrictEqual(notifications, ["requests@2.31.0 cached in repo-b"]);
    } finally {
      vscode.window.withProgress = originalWithProgress;
      vscode.window.showInformationMessage = originalShowInformationMessage;
      vscode.window.showErrorMessage = originalShowErrorMessage;
    }
  });
});

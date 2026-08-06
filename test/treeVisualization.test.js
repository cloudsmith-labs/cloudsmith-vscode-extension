const assert = require("assert");
const vscode = require("vscode");
const {
  DependencyHealthProvider,
  FILTER_MODES,
  buildDependencyHealthReport,
  buildDependencySummary,
} = require("../views/dependencyHealthProvider");

suite("tree visualization", () => {
  let originalGetConfiguration;

  setup(() => {
    originalGetConfiguration = vscode.workspace.getConfiguration;
    vscode.workspace.getConfiguration = () => ({
      get(key) {
        if (key === "dependencyTreeDefaultView") {
          return "tree";
        }
        if (key === "showLicenseIndicators") {
          return true;
        }
        if (key === "flagRestrictiveLicenses") {
          return true;
        }
        return undefined;
      },
    });
  });

  teardown(() => {
    vscode.workspace.getConfiguration = originalGetConfiguration;
  });

  function createContext() {
    return {
      workspaceState: {
        get() {
          return null;
        },
        async update() {},
      },
      secrets: {
        onDidChange() {
          return { dispose() {} };
        },
        async get() {
          return "true";
        },
      },
    };
  }

  function createFoundPackage(slug) {
    return {
      namespace: "workspace-a",
      repository: "production-npm",
      slug_perm: slug,
      status_str: "Completed",
      version: "1.0.0",
      license: "MIT",
    };
  }

  function createTree() {
    const vulnerableLeaf = {
      name: "shared-lib",
      version: "1.0.0",
      format: "npm",
      ecosystem: "npm",
      isDirect: false,
      parent: "alpha",
      parentChain: ["alpha"],
      transitives: [],
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: createFoundPackage("shared"),
      vulnerabilities: {
        count: 1,
        maxSeverity: "High",
        cveIds: ["CVE-2024-1234"],
        hasFixAvailable: true,
        severityCounts: { High: 1 },
        entries: [{ cveId: "CVE-2024-1234", severity: "High", fixVersion: "1.0.1" }],
        detailsLoaded: true,
      },
      sourceFile: "package-lock.json",
    };

    const duplicateLeaf = {
      ...vulnerableLeaf,
      parent: "beta",
      parentChain: ["beta"],
    };

    const alpha = {
      name: "alpha",
      version: "2.0.0",
      format: "npm",
      ecosystem: "npm",
      isDirect: true,
      parent: null,
      parentChain: [],
      transitives: [vulnerableLeaf],
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: createFoundPackage("alpha"),
      sourceFile: "package-lock.json",
    };

    const beta = {
      name: "beta",
      version: "3.0.0",
      format: "npm",
      ecosystem: "npm",
      isDirect: true,
      parent: null,
      parentChain: [],
      transitives: [duplicateLeaf],
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: createFoundPackage("beta"),
      sourceFile: "package-lock.json",
    };

    return {
      ecosystem: "npm",
      sourceFile: "package-lock.json",
      dependencies: [alpha, beta, vulnerableLeaf],
    };
  }

  test("tree mode expands direct dependencies and collapses duplicate diamonds", () => {
    const provider = new DependencyHealthProvider(createContext(), null);
    const tree = createTree();
    provider._displayTrees = [tree];
    provider._fullTrees = [tree];
    provider._viewMode = "tree";
    provider._rebuildSummary();

    const rootNodes = provider.buildDependencyNodesForTree(tree);
    assert.strictEqual(rootNodes.length, 2);
    assert.strictEqual(rootNodes[0].getTreeItem().collapsibleState, vscode.TreeItemCollapsibleState.Collapsed);

    const alphaChildren = rootNodes[0].getChildren();
    assert.strictEqual(alphaChildren.length, 1);
    assert.strictEqual(alphaChildren[0].name, "shared-lib");
    assert.strictEqual(alphaChildren[0].getTreeItem().collapsibleState, vscode.TreeItemCollapsibleState.None);

    const betaChildren = rootNodes[1].getChildren();
    assert.strictEqual(betaChildren.length, 1);
    assert.match(betaChildren[0].getTreeItem().description, /see first occurrence/);
    assert.strictEqual(betaChildren[0].getTreeItem().collapsibleState, vscode.TreeItemCollapsibleState.None);
  });

  test("filtered tree keeps only the ancestor path to vulnerable dependencies", async () => {
    const provider = new DependencyHealthProvider(createContext(), null);
    const tree = createTree();
    tree.dependencies[1] = {
      ...tree.dependencies[1],
      transitives: [],
    };
    provider._displayTrees = [tree];
    provider._fullTrees = [tree];
    provider._viewMode = "tree";
    await provider.setFilterMode(FILTER_MODES.VULNERABLE);

    const rootNodes = provider.buildDependencyNodesForTree(tree);
    assert.strictEqual(rootNodes.length, 1);
    assert.strictEqual(rootNodes[0].name, "alpha");
    assert.match(rootNodes[0].getTreeItem().description, /context/);
    assert.strictEqual(rootNodes[0].getChildren()[0].name, "shared-lib");
  });

  test("dependency health report includes vulnerability and upstream sections", () => {
    const tree = createTree();
    const uncovered = {
      name: "missing-lib",
      version: "0.1.0",
      format: "npm",
      ecosystem: "npm",
      isDirect: true,
      parent: null,
      parentChain: [],
      transitives: [],
      cloudsmithStatus: "NOT_FOUND",
      upstreamStatus: "reachable",
      upstreamDetail: "npm proxy on production",
      sourceFile: "package-lock.json",
    };
    tree.dependencies.push(uncovered);

    const summary = buildDependencySummary([tree], [tree], {});
    const report = buildDependencyHealthReport("fixture-app", tree.dependencies, summary, "2026-04-05");

    assert.match(report, /## Vulnerable Dependencies/);
    assert.match(report, /\| shared-lib \| 1.0.0 \| Transitive \| High \| CVE-2024-1234 \| Yes \(1.0.1\) \|/);
    assert.match(report, /## Uncovered Dependencies/);
    assert.match(report, /\| missing-lib \| 0.1.0 \| npm \| Reachable \| npm proxy on production \|/);
  });
});

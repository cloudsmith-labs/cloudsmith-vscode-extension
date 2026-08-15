// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const vscode = require("vscode");
const {
  DependencyHealthProvider: DependencyHealthProviderImplementation,
  FILTER_MODES,
  buildDependencyHealthReport,
  buildDependencySummary,
} = require("../views/dependencyHealthProvider");
const { fromApiPackageRecord } = require("../domain/packageAdapters");

suite("tree visualization", () => {
  let originalGetConfiguration;

  class DependencyHealthProvider extends DependencyHealthProviderImplementation {
    constructor(context, diagnosticsPublisher = null, options = {}) {
      super(context, diagnosticsPublisher, {
        upstreamGapRuntime: {
          createOperationScope() {
            const controller = new AbortController();
            return {
              signal: controller.signal,
              dispose() { controller.abort(); },
            };
          },
          async getRepositoryUpstreamStateForFormats() { return null; },
        },
        upstreamPullService: {
          async run() { return null; },
          async prepareSingle() { return null; },
          async execute() { return null; },
        },
        ...options,
      });
    }
  }

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
    return fromApiPackageRecord({
      namespace: "workspace-a",
      repository: "production-npm",
      slug_perm: slug,
      name: slug,
      format: "npm",
      status_str: "Completed",
      version: "1.0.0",
      license: "MIT",
    });
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

  function createStructuralTree() {
    const tree = createTree();
    const shared = tree.dependencies.find((dependency) => dependency.name === "shared-lib");
    const leaf = {
      ...shared,
      name: "vulnerable-leaf",
      normalizedName: "vulnerable-leaf",
      parent: "shared-lib",
      parentChain: ["alpha", "shared-lib"],
      cloudsmithPackage: createFoundPackage("vulnerable-leaf"),
    };
    tree.dependencies = tree.dependencies.map((dependency) => ({
      ...dependency,
      transitives: [],
    }));
    tree.dependencies.push(leaf);
    tree.dependencyGraph = Object.freeze({
      kind: "package-lock",
      incomplete: false,
      roots: Object.freeze([
        Object.freeze({ declaredName: "beta", entryKey: "node_modules/beta", isDevelopmentDependency: false }),
        Object.freeze({ declaredName: "alpha", entryKey: "node_modules/alpha", isDevelopmentDependency: false }),
      ]),
      entries: Object.freeze([
        Object.freeze({
          key: "node_modules/beta",
          name: "beta",
          installedName: "beta",
          version: "3.0.0",
          isDevelopmentDependency: false,
          edges: Object.freeze([Object.freeze({ declaredName: "shared-lib", childKey: "node_modules/shared-lib" })]),
        }),
        Object.freeze({
          key: "node_modules/alpha",
          name: "alpha",
          installedName: "alpha",
          version: "2.0.0",
          isDevelopmentDependency: false,
          edges: Object.freeze([Object.freeze({ declaredName: "shared-lib", childKey: "node_modules/shared-lib" })]),
        }),
        Object.freeze({
          key: "node_modules/shared-lib",
          name: "shared-lib",
          installedName: "shared-lib",
          version: "1.0.0",
          isDevelopmentDependency: false,
          edges: Object.freeze([Object.freeze({ declaredName: "vulnerable-leaf", childKey: "node_modules/vulnerable-leaf" })]),
        }),
        Object.freeze({
          key: "node_modules/vulnerable-leaf",
          name: "vulnerable-leaf",
          installedName: "vulnerable-leaf",
          version: "1.0.0",
          isDevelopmentDependency: false,
          edges: Object.freeze([]),
        }),
      ]),
    });
    return tree;
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

  test("structural graph expands the first UI-sorted occurrence rather than parser order", () => {
    const provider = new DependencyHealthProvider(createContext(), null);
    const tree = createStructuralTree();
    provider._viewMode = "tree";

    const roots = provider.buildDependencyNodesForTree(tree);

    assert.deepStrictEqual(roots.map((root) => root.name), ["alpha", "beta"]);
    const alphaShared = roots[0].getChildren()[0];
    assert.strictEqual(alphaShared.name, "shared-lib");
    assert.strictEqual(alphaShared.getChildren()[0].name, "vulnerable-leaf");
    const betaShared = roots[1].getChildren()[0];
    assert.match(betaShared.getTreeItem().description, /see first occurrence/);
  });

  test("structural graph filtering retains every parent path to a shared match", async () => {
    const provider = new DependencyHealthProvider(createContext(), null);
    const tree = createStructuralTree();
    provider._viewMode = "tree";
    await provider.setFilterMode(FILTER_MODES.VULNERABLE);

    const roots = provider.buildDependencyNodesForTree(tree);

    assert.deepStrictEqual(roots.map((root) => root.name), ["alpha", "beta"]);
    assert.strictEqual(roots[0].getChildren()[0].getChildren()[0].name, "vulnerable-leaf");
    assert.match(roots[1].getChildren()[0].getTreeItem().description, /see first occurrence/);
  });

  test("structural tree cannot render packages removed by the display cap", () => {
    const provider = new DependencyHealthProvider(createContext(), null);
    const tree = createStructuralTree();
    tree.dependencies = tree.dependencies.filter(
      (dependency) => dependency.name !== "vulnerable-leaf"
    );
    provider._viewMode = "tree";

    const roots = provider.buildDependencyNodesForTree(tree);

    assert.deepStrictEqual(roots.map((root) => root.name), ["alpha", "beta"]);
    assert.deepStrictEqual(roots[0].getChildren()[0].getChildren(), []);
  });

  test("unresolved structural edges do not borrow enriched direct-package status", () => {
    const provider = new DependencyHealthProvider(createContext(), null);
    const directFoo = {
      ...createTree().dependencies.find((dependency) => dependency.name === "alpha"),
      name: "foo",
      normalizedName: "foo",
      declarationName: "foo",
      version: "1.0.0",
      resolvedVersion: "1.0.0",
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: createFoundPackage("foo"),
      vulnerabilities: { count: 1, maxSeverity: "High" },
    };
    const alpha = {
      ...createTree().dependencies.find((dependency) => dependency.name === "alpha"),
      transitives: [],
    };
    const tree = {
      ecosystem: "npm",
      sourceFile: "package-lock.json",
      warnings: [],
      dependencies: [alpha, directFoo],
      dependencyGraph: {
        kind: "package-lock",
        incomplete: false,
        maxDepth: 128,
        maxNodes: 50000,
        roots: [
          { declaredName: "alpha", entryKey: "node_modules/alpha", isDevelopmentDependency: false },
          { declaredName: "foo", entryKey: "node_modules/foo", isDevelopmentDependency: false },
        ],
        entries: [
          {
            key: "node_modules/alpha",
            name: "alpha",
            installedName: "alpha",
            version: "2.0.0",
            isDevelopmentDependency: false,
            edges: [{ declaredName: "foo", childKey: null }],
          },
          {
            key: "node_modules/foo",
            name: "foo",
            installedName: "foo",
            version: "1.0.0",
            isDevelopmentDependency: false,
            edges: [],
          },
        ],
      },
    };
    provider._viewMode = "tree";

    const roots = provider.buildDependencyNodesForTree(tree);
    const unresolvedFoo = roots[0].getChildren()[0];

    assert.strictEqual(unresolvedFoo.name, "foo");
    assert.strictEqual(unresolvedFoo.resolvedVersion, null);
    assert.strictEqual(unresolvedFoo.cloudsmithStatus, null);
    assert.strictEqual(unresolvedFoo.vulnerabilities, null);
    assert.strictEqual(roots[1].cloudsmithStatus, "FOUND");
  });

  test("resolved direct roots omitted from bounded adjacency remain resolved leaves", () => {
    const provider = new DependencyHealthProvider(createContext(), null);
    const direct = {
      ...createTree().dependencies.find((dependency) => dependency.name === "alpha"),
      resolvedVersion: "2.0.0",
      versionState: "resolved",
      transitives: [],
    };
    const tree = {
      ecosystem: "npm",
      sourceFile: "package-lock.json",
      warnings: [],
      dependencies: [direct],
      dependencyGraph: {
        kind: "package-lock",
        incomplete: true,
        maxDepth: 128,
        maxNodes: 1,
        roots: [{
          declaredName: "alpha",
          entryKey: "node_modules/alpha",
          isDevelopmentDependency: false,
        }],
        entries: [],
      },
    };
    provider._viewMode = "tree";

    const roots = provider.buildDependencyNodesForTree(tree);

    assert.strictEqual(roots.length, 1);
    assert.strictEqual(roots[0].name, "alpha");
    assert.strictEqual(roots[0].resolvedVersion, "2.0.0");
    assert.deepStrictEqual(roots[0].getChildren(), []);
  });

  test("structural presentation bounds add a customer-visible warning", async () => {
    const provider = new DependencyHealthProvider(createContext(), null);
    const tree = createStructuralTree();
    tree.dependencyGraph = { ...tree.dependencyGraph, maxDepth: 1, maxNodes: 50000 };
    provider._viewMode = "tree";

    const roots = provider.buildDependencyNodesForTree(tree);
    await Promise.resolve();

    assert.deepStrictEqual(roots[0].getChildren()[0].getChildren(), []);
    assert.ok(provider._warnings.some((warning) => /could not be displayed/.test(warning)));
  });

  test("structural node-count exhaustion adds the same customer-visible warning", async () => {
    const provider = new DependencyHealthProvider(createContext(), null);
    const tree = createStructuralTree();
    tree.dependencyGraph = { ...tree.dependencyGraph, maxDepth: 128, maxNodes: 1 };
    provider._viewMode = "tree";

    const roots = provider.buildDependencyNodesForTree(tree);
    await Promise.resolve();

    assert.strictEqual(roots.length, 1);
    assert.deepStrictEqual(roots[0].getChildren(), []);
    assert.ok(provider._warnings.some((warning) => /could not be displayed/.test(warning)));
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

    assert.match(report, /## Dependency Vulnerability Status/);
    assert.match(report, /\| shared-lib \| 1.0.0 \| Transitive \| High \| Detected \| Yes \(1.0.1\) \|/);
    assert.match(report, /## Uncovered Dependencies/);
    assert.match(report, /\| missing-lib \| 0.1.0 \| npm \| Reachable \| npm proxy on production \|/);
  });
});

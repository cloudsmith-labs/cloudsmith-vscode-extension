const assert = require("assert");
const vscode = require("vscode");
const { EntitlementSummaryNode } = require("../models/entitlementNode");
const UpstreamIndicatorNode = require("../models/upstreamIndicatorNode");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const {
  bindConnectionManager,
  unbindConnectionManager,
} = require("../util/connectionManager");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");
const { UpstreamChecker } = require("../util/upstreamChecker");

function makePackage(slug, overrides = {}) {
  return {
    namespace: "acme",
    repository: "packages",
    name: slug,
    format: "npm",
    slug,
    slug_perm: slug,
    version: "1.0.0",
    ...overrides,
  };
}

function makePagination(page, pageTotal, pageSize, count = null) {
  return {
    page,
    pageTotal,
    pageSize,
    count,
    countAuthoritative: count !== null,
  };
}

function makeContinuation(descriptor, options = {}) {
  const nextPage = options.nextPage || 2;
  return Object.freeze({
    nextPage,
    anchor: Object.freeze(options.anchor || makePagination(nextPage - 1, nextPage, 2, 3)),
    cumulative: Object.freeze({
      pageCount: options.pageCount ?? (nextPage - 1),
      requestCount: options.requestCount ?? (nextPage - 1),
      itemCount: options.itemCount ?? 2,
      duplicateCount: options.duplicateCount ?? 0,
      failureCount: options.failureCount ?? 0,
    }),
    descriptor,
    binding: "a".repeat(64),
  });
}

function makeCollectionResult(options = {}) {
  const items = options.items || [];
  const complete = options.complete === true;
  const failures = options.failures || [];
  return Object.freeze({
    items: Object.freeze(items),
    complete,
    incomplete: !complete,
    partial: !complete && (options.cumulativeItemCount ?? items.length) > 0,
    cancelled: options.cancelled === true,
    continuation: complete ? null : (options.continuation || null),
    failures: Object.freeze(failures),
    failureCount: options.failureCount ?? failures.length,
    termination: options.termination || (complete ? "exhausted" : "page_batch"),
    pageCount: options.pageCount ?? (items.length > 0 ? 1 : 0),
    requestCount: options.requestCount ?? (items.length > 0 ? 1 : 0),
    duplicateCount: options.duplicateCount || 0,
    pagination: options.pagination || null,
  });
}

function collectionFailure(page = 2, kind = "rate_limited") {
  return Object.freeze({
    page,
    error: Object.freeze({
      kind,
      status: kind === "rate_limited" ? 429 : null,
      retryable: kind === "rate_limited",
      message: "The page request failed.",
      requestId: "test-request-id",
      retryAfterMs: null,
      outcomeUnknown: false,
    }),
  });
}

function completeUpstreamState(upstreams = []) {
  return {
    upstreams,
    failedFormats: [],
    uninspectedFormats: [],
    complete: true,
  };
}

function safeUpstream(format, name, isActive = true, origin = "") {
  return {
    name,
    _format: format,
    format,
    origin,
    is_active: isActive,
  };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

suite("RepositoryNode Test Suite", () => {
  const repositoryNodePath = require.resolve("../models/repositoryNode");
  let originalGetConfiguration;
  let RepositoryNode;
  let RepositoryNodeImplementation;
  let upstreamInventory;
  let originalApiGet;
  let managerBinding;
  let accountState;

  const context = {
    globalState: {
      get() {
        return undefined;
      },
      async update() {},
    },
  };
  const connectionManager = {
    activationId: "activation-a",
    getState() {
      return { ...accountState };
    },
    setState(next) { accountState = { ...accountState, ...next }; },
  };

  function createProductionUpstreamInventory() {
    const checker = new UpstreamChecker(context, { connectionManager });
    return Object.freeze({
      getAllUpstreamData: (...args) => checker.getAllUpstreamData(...args),
    });
  }

  setup(() => {
    originalGetConfiguration = vscode.workspace.getConfiguration;
    delete require.cache[repositoryNodePath];
    RepositoryNodeImplementation = require(repositoryNodePath);
    upstreamInventory = {
      getAllUpstreamData: async () => completeUpstreamState(),
    };
    RepositoryNode = class extends RepositoryNodeImplementation {
      constructor(repo, workspace, nodeContext, options = {}) {
        super(repo, workspace, nodeContext, {
          upstreamInventory,
          ...options,
        });
      }
    };
    originalApiGet = CloudsmithAPI.prototype.get;
    accountState = {
      activationId: connectionManager.activationId,
      accountEpoch: 1,
      sessionConnected: true,
      status: "connected",
    };
    managerBinding = bindConnectionManager(context, connectionManager);

    vscode.workspace.getConfiguration = () => ({
      get(key) {
        if (key === "showEntitlements") {
          return false;
        }
        if (key === "showMaxPackages") {
          return 30;
        }
        return false;
      },
    });
  });

  test("requires a narrow upstream inventory facade", () => {
    assert.throws(
      () => new RepositoryNodeImplementation(
        { slug: "repo", slug_perm: "repo", name: "Repo" },
        "acme",
        context,
        { connectionManager }
      ),
      /upstream inventory facade/
    );
  });

  test("rejects privileged-shaped upstream records before retaining tree state", async () => {
    const repositoryNode = new RepositoryNodeImplementation(
      { slug: "repo", slug_perm: "repo", name: "Repo" },
      "acme",
      context,
      {
        connectionManager,
        upstreamInventory: {
          async getAllUpstreamData() {
            return completeUpstreamState([{
              name: "private",
              _format: "npm",
              format: "npm",
              origin: "https://registry.example",
              upstream_url: "https://token@example.invalid/private",
            }]);
          },
        },
      }
    );

    const state = await repositoryNode.getUpstreamState();
    assert.strictEqual(state.complete, false);
    assert.deepStrictEqual(state.upstreams, []);
  });

  test("rejects embedded format disagreement without deriving a hint from the record", async () => {
    const mismatched = {
      name: "mixed",
      _format: "npm",
      format: "python",
      origin: "",
      is_active: true,
    };
    const repositoryNode = new RepositoryNodeImplementation(
      { slug: "repo", slug_perm: "repo", name: "Repo" },
      "acme",
      context,
      {
        connectionManager,
        upstreamInventory: {
          async getAllUpstreamData() {
            return completeUpstreamState([mismatched]);
          },
        },
      }
    );
    repositoryNode.getPackages = async () => [];
    repositoryNode._packageState = { ...repositoryNode._packageState, pageCount: 1 };

    const state = await repositoryNode.getUpstreamState();
    assert.strictEqual(state.complete, false);
    assert.deepStrictEqual(state.upstreams, []);

    const children = await repositoryNode.getChildren();
    const indicator = children.find(child => child instanceof UpstreamIndicatorNode);
    assert.ok(indicator);
    assert.deepStrictEqual(indicator.upstreams, []);
    assert.strictEqual(indicator.getTreeItem().label.includes("configured"), false);
  });

  test("does not execute raw format accessors or Proxy traps before sanitization", async () => {
    let accessorReads = 0;
    const accessor = {
      name: "accessor",
      format: "npm",
      origin: "",
    };
    Object.defineProperty(accessor, "_format", {
      enumerable: true,
      get() {
        accessorReads += 1;
        return "npm";
      },
    });

    let proxyReads = 0;
    const proxy = new Proxy({
      name: "proxy",
      _format: "npm",
      format: "npm",
      origin: "",
    }, {
      get(target, property, receiver) {
        proxyReads += 1;
        return Reflect.get(target, property, receiver);
      },
    });

    for (const candidate of [accessor, proxy]) {
      const repositoryNode = new RepositoryNodeImplementation(
        { slug: "repo", slug_perm: "repo", name: "Repo" },
        "acme",
        context,
        {
          connectionManager,
          upstreamInventory: {
            async getAllUpstreamData() {
              return completeUpstreamState([candidate]);
            },
          },
        }
      );
      const state = await repositoryNode.getUpstreamState();
      assert.strictEqual(state.complete, false);
      assert.deepStrictEqual(state.upstreams, []);
    }

    assert.strictEqual(accessorReads, 0);
    assert.strictEqual(proxyReads, 0);
  });

  teardown(() => {
    vscode.workspace.getConfiguration = originalGetConfiguration;
    CloudsmithAPI.prototype.get = originalApiGet;
    managerBinding.dispose();
    unbindConnectionManager(context, connectionManager);
    delete require.cache[repositoryNodePath];
  });

  test("uses one repository-wide upstream fetch for configured totals", async () => {
    let allFormatCalls = 0;
    const targetedCalls = [];
    const partialUpstreams = [
      safeUpstream("docker", "Docker Hub", true, "https://index.docker.io"),
      safeUpstream("python", "PyPI", true, "https://pypi.org"),
      safeUpstream("ruby", "RubyGems", false, "https://rubygems.org"),
    ];
    const fullUpstreams = [
      ...partialUpstreams,
      safeUpstream("maven", "Maven Central", true, "https://repo.maven.apache.org"),
      safeUpstream("nuget", "NuGet", true, "https://api.nuget.org"),
      safeUpstream("npm", "npmjs", true, "https://registry.npmjs.org"),
    ];

    upstreamInventory.getAllUpstreamData = async () => {
      allFormatCalls += 1;
      return {
        upstreams: fullUpstreams,
        active: 5,
        total: 6,
        failedFormats: [],
        uninspectedFormats: [],
        successfulFormats: 6,
        complete: true,
      };
    };
    upstreamInventory.getUpstreamDataForFormats = async (workspace, repo, formats) => {
      targetedCalls.push({ workspace, repo, formats });
      return {
        upstreams: partialUpstreams,
        active: 2,
        total: 3,
        failedFormats: [],
        uninspectedFormats: [],
        successfulFormats: 2,
        complete: true,
      };
    };

    const repositoryNode = new RepositoryNode(
      { slug: "example-repo", slug_perm: "example-repo", name: "Example Repo" },
      "acme",
      context,
      { connectionManager }
    );

    const packages = [
      { format: "python" },
      { format: "python" },
      { formats: ["docker", "unknown"] },
    ];
    repositoryNode.getPackages = async () => packages;
    repositoryNode._packageState = {
      ...repositoryNode._packageState,
      initialized: true,
      nodes: packages,
      complete: true,
      termination: "exhausted",
      pageCount: 1,
    };

    const children = await repositoryNode.getChildren();

    assert.strictEqual(allFormatCalls, 1);
    assert.strictEqual(targetedCalls.length, 0);
    const indicator = children.find(child => child instanceof UpstreamIndicatorNode);
    assert.strictEqual(children[0], packages[0]);
    assert.ok(indicator);
    assert.strictEqual(indicator.upstreams.length, 6);
    assert.deepStrictEqual(
      new Set(indicator.upstreams.map(upstream => upstream.format)),
      new Set(["docker", "python", "ruby", "maven", "nuget", "npm"])
    );
    assert.strictEqual(indicator.getTreeItem().label, "Upstreams: 5 active of 6 configured");

  });

  test("falls back to the all-format fetch when no inferred formats are available", async () => {
    let allFormatCalls = 0;
    let targetedCalls = 0;

    upstreamInventory.getAllUpstreamData = async () => {
      allFormatCalls += 1;
      return {
        upstreams: [safeUpstream("docker", "Docker Hub", true, "https://index.docker.io")],
        failedFormats: [], uninspectedFormats: [], complete: true,
      };
    };
    upstreamInventory.getUpstreamDataForFormats = async () => {
      targetedCalls += 1;
      return completeUpstreamState();
    };

    const repositoryNode = new RepositoryNode(
      { slug: "grouped-repo", slug_perm: "grouped-repo", name: "Grouped Repo" },
      "acme",
      context,
      { connectionManager }
    );

    const upstreams = await repositoryNode.getUpstreams([{ name: "package-group-without-format" }]);

    assert.strictEqual(targetedCalls, 0);
    assert.strictEqual(allFormatCalls, 1);
    assert.strictEqual(upstreams.length, 1);
    assert.strictEqual(upstreams[0].name, "Docker Hub");
  });

  test("does not amplify upstream requests from package format hints", async () => {
    let allFormatCalls = 0;
    const targetedCalls = [];

    upstreamInventory.getAllUpstreamData = async () => {
      allFormatCalls += 1;
      return completeUpstreamState();
    };
    upstreamInventory.getUpstreamDataForFormats = async (workspace, repo, formats) => {
      targetedCalls.push({ workspace, repo, formats });
      return {
        upstreams: [safeUpstream("python", "PyPI", true, "https://pypi.org")],
        failedFormats: [], uninspectedFormats: [], complete: true,
      };
    };

    const repositoryNode = new RepositoryNode(
      { slug: "complete-repo", slug_perm: "complete-repo", name: "Complete Repo" },
      "acme",
      context,
      { connectionManager }
    );

    const upstreams = await repositoryNode.getUpstreams([{ formats: ["npm", "python"] }]);

    assert.strictEqual(allFormatCalls, 1);
    assert.strictEqual(targetedCalls.length, 0);
    assert.strictEqual(upstreams.length, 0);
  });

  test("adds the inline upstream indicator when upstreams are present", async () => {
    const repositoryNode = new RepositoryNode(
      { slug: "indicator-repo", slug_perm: "indicator-repo", name: "Indicator Repo" },
      "acme",
      context,
      { connectionManager }
    );

    const packageNode = { format: "python" };
    repositoryNode.getPackages = async () => [packageNode];
    repositoryNode._packageState = {
      ...repositoryNode._packageState,
      initialized: true,
      nodes: [packageNode],
      complete: true,
      termination: "exhausted",
      pageCount: 1,
    };
    repositoryNode.getUpstreamState = async () => completeUpstreamState([
      { name: "PyPI", upstream_url: "https://pypi.org/", is_active: true },
    ]);

    const children = await repositoryNode.getChildren();

    const indicator = children.find(child => child instanceof UpstreamIndicatorNode);
    assert.strictEqual(children[0], packageNode);
    assert.ok(indicator);
    assert.strictEqual(indicator.getTreeItem().label, "Upstreams: 1 active of 1 configured");
  });

  test("loads upstreams through the exact RepositoryNode production aggregation path", async () => {
    let upstreamRequests = 0;
    CloudsmithAPI.prototype.get = async (endpoint) => {
      if (!endpoint.includes("/upstream/")) {
        throw new Error("Unexpected non-upstream transport request");
      }
      upstreamRequests += 1;
      if (endpoint.includes("/upstream/python/")) {
        return apiSuccess([{
          name: "PyPI",
          slug_perm: "pypi",
          upstream_url: "https://pypi.org/simple",
          auth_username: null,
          index_package_count: null,
          is_active: true,
        }]);
      }
      return apiSuccess([]);
    };
    const repositoryNode = new RepositoryNode(
      { slug: "production-repo", slug_perm: "production-repo", name: "Production Repo" },
      "acme",
      context,
      { connectionManager, upstreamInventory: createProductionUpstreamInventory() }
    );
    const packageNode = { format: "python" };
    repositoryNode.getPackages = async () => [packageNode];
    repositoryNode._packageState = {
      ...repositoryNode._packageState,
      initialized: true,
      nodes: [packageNode],
      complete: true,
      termination: "exhausted",
      pageCount: 1,
    };

    const children = await repositoryNode.getChildren();

    assert.strictEqual(upstreamRequests, 20);
    const indicator = children.find(child => child instanceof UpstreamIndicatorNode);
    assert.strictEqual(children[0], packageNode);
    assert.ok(indicator);
    assert.strictEqual(indicator.complete, true);
    assert.strictEqual(indicator.upstreams.length, 1);
    assert.strictEqual(indicator.upstreams[0].slug_perm, "pypi");
    assert.strictEqual(indicator.upstreams[0].origin, "https://pypi.org");
  });

  test("retains production-path upstream data when another format fails", async () => {
    CloudsmithAPI.prototype.get = async (endpoint) => {
      if (endpoint.includes("/upstream/python/")) {
        return apiSuccess([{
          name: "PyPI",
          slug_perm: "pypi",
          upstream_url: "https://pypi.org/simple",
          is_active: true,
        }]);
      }
      if (endpoint.includes("/upstream/npm/")) {
        return apiFailure("permission", { status: 403 });
      }
      return apiSuccess([]);
    };
    const repositoryNode = new RepositoryNode(
      { slug: "partial-repo", slug_perm: "partial-repo", name: "Partial Repo" },
      "acme",
      context,
      { connectionManager, upstreamInventory: createProductionUpstreamInventory() }
    );
    repositoryNode.getPackages = async () => [{ format: "python" }];
    repositoryNode._packageState = { ...repositoryNode._packageState, pageCount: 1 };

    const children = await repositoryNode.getChildren();
    const indicator = children.find(child => child instanceof UpstreamIndicatorNode);

    assert.ok(indicator);
    assert.strictEqual(indicator.complete, false);
    assert.strictEqual(indicator.upstreams.length, 1);
    assert.strictEqual(indicator.failures[0].format, "npm");
    assert.strictEqual(indicator.failures[0].category, "permission");
    assert.ok(indicator.getTreeItem().label.includes("partial"));
    assert.ok(!indicator.getTreeItem().label.includes("configured"));
  });

  test("repository packages do not expose vulnerability nodes for clean npm and Python scans", async () => {
    const packageBase = {
      namespace: "acme",
      repository: "packages",
      status_str: "Completed",
      downloads: 0,
      uploaded_at: "2026-08-07T00:00:00Z",
    };

    CloudsmithAPI.prototype.get = async () => apiSuccess([
      {
        ...packageBase,
        name: "clean-npm",
        format: "npm",
        slug: "clean-npm",
        slug_perm: "clean-npm-perm",
        version: "1.0.0",
        num_vulnerabilities: 0,
        security_scan_status: "Scan Detected No Vulnerabilities",
      },
      {
        ...packageBase,
        name: "clean-python",
        format: "python",
        slug: "clean-python",
        slug_perm: "clean-python-perm",
        version: "2.0.0",
        num_vulnerabilities: "0",
        security_scan_status: "Scan Detected No Vulnerabilities",
      },
    ], {
      headers: {
        "x-pagination-page": "1",
        "x-pagination-pagetotal": "1",
        "x-pagination-pagesize": "30",
        "x-pagination-count": "2",
      },
    });

    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" },
      "acme",
      context,
      { connectionManager }
    );

    const packages = await repositoryNode.getPackages();

    assert.strictEqual(packages.length, 2);
    for (const packageNode of packages) {
      const children = packageNode.getChildren();
      const summary = children.find(child => (
        child.getTreeItem().contextValue === "vulnerabilitySummary"
      ));
      assert.ok(summary, `${packageNode.format} package did not expose its clean vulnerability state`);
      assert.strictEqual(summary.getTreeItem().label, "Vulnerabilities: 0 (None)");
      assert.strictEqual(summary.getTreeItem().tooltip, "0 vulnerabilities. Max severity: None.");
      assert.strictEqual(
        children.some(child => String(child.getTreeItem().label).includes("Vulnerabilities: detected")),
        false
      );
    }
  });

  test("a malformed package array cannot be published as an empty successful repository", async () => {
    CloudsmithAPI.prototype.get = async (_endpoint, options) => {
      const malformed = [{ name: "artifact" }, null];
      assert.strictEqual(options.validate(malformed), false);
      return apiFailure("invalid_response", { status: 200 });
    };
    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" },
      "acme",
      context,
      { connectionManager }
    );

    const packages = await repositoryNode.getPackages();

    assert.deepStrictEqual(packages, []);
    assert.strictEqual(repositoryNode._packageState.complete, false);
    assert.strictEqual(repositoryNode._packageState.failures.length, 1);
  });

  test("rejects malformed present package policy booleans instead of publishing false", async () => {
    CloudsmithAPI.prototype.get = async (_endpoint, options) => {
      const malformed = [makePackage("artifact", { policy_violated: "true" })];
      assert.strictEqual(options.validate(malformed), false);
      return apiFailure("invalid_response", { status: 200 });
    };
    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" },
      "acme",
      context,
      { connectionManager }
    );

    const packages = await repositoryNode.getPackages();

    assert.deepStrictEqual(packages, []);
    assert.strictEqual(repositoryNode._packageState.complete, false);
  });

  test("normalizes repository vulnerability evidence without making false-clean claims", async () => {
    const packages = [
      makePackage("no-evidence"),
      makePackage("malformed", { num_vulnerabilities: { value: "many" } }),
      makePackage("presence", { has_vulnerabilities: true }),
      makePackage("status", { security_scan_status: "Scan Detected Vulnerabilities" }),
      makePackage("zero", { num_vulnerabilities: 0 }),
      makePackage("positive", { num_vulnerabilities: "2" }),
    ];
    CloudsmithAPI.prototype.get = async () => apiSuccess(packages, {
      headers: {
        "x-pagination-page": "1",
        "x-pagination-pagetotal": "1",
        "x-pagination-pagesize": "30",
        "x-pagination-count": String(packages.length),
      },
    });
    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" },
      "acme",
      context,
      { connectionManager }
    );

    const nodes = await repositoryNode.getPackages();
    const vulnerabilityCounts = Object.fromEntries(nodes.map(node => [
      node.name,
      node.num_vulnerabilities,
    ]));

    assert.deepStrictEqual(vulnerabilityCounts, {
      "no-evidence": null,
      malformed: null,
      presence: -1,
      status: -1,
      zero: 0,
      positive: 2,
    });
    const cleanSummary = nodes.find(node => node.name === "zero").getChildren().find(child => (
      child.getTreeItem().contextValue === "vulnerabilitySummary"
    ));
    assert.ok(cleanSummary);
    assert.strictEqual(cleanSummary.getTreeItem().label, "Vulnerabilities: 0 (None)");
    for (const name of ["no-evidence", "malformed", "presence", "status", "positive"]) {
      assert.strictEqual(
        nodes.find(node => node.name === name).getChildren().some(child => (
          child.getTreeItem().contextValue === "vulnerabilitySummary"
        )),
        true,
        `${name} was incorrectly shown as clean`
      );
    }
  });

  test("group and entitlement validators reject blank records", async () => {
    vscode.workspace.getConfiguration = () => ({
      get(key) {
        if (key === "groupByPackageGroups") return true;
        if (key === "showMaxPackages") return 10;
        return false;
      },
    });
    let requestCount = 0;
    CloudsmithAPI.prototype.get = async (_endpoint, options) => {
      requestCount += 1;
      if (requestCount === 1) {
        assert.strictEqual(options.validate({ results: [{}] }), false);
        assert.strictEqual(options.validate({ results: [{ name: "artifact", format: "npm" }] }), true);
      } else {
        assert.strictEqual(options.validate([{}]), false);
        assert.strictEqual(options.validate([{ name: "token", slug_perm: "token", is_active: false }]), true);
      }
      return apiFailure("invalid_response", { status: 200 });
    };
    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" },
      "acme",
      context,
      { connectionManager }
    );

    assert.deepStrictEqual(await repositoryNode.getPackages(), []);
    await assert.rejects(
      () => repositoryNode.getEntitlements(),
      error => error && error.kind === "invalid_response"
    );
  });

  test("does not publish packages completed after an account change", async () => {
    let release;
    const response = new Promise(resolve => { release = resolve; });
    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" },
      "acme",
      context,
      {
        connectionManager,
        createCloudsmithAPI: () => ({ get: async () => response }),
      }
    );
    const pending = repositoryNode.getPackages();
    await new Promise(resolve => setImmediate(resolve));
    connectionManager.setState({ accountEpoch: 2 });
    release(apiSuccess([{
      namespace: "acme",
      repository: "packages",
      name: "old-package",
      format: "npm",
      slug: "old-package",
      slug_perm: "old-package",
      version: "1.0.0",
    }], {
      headers: {
        "x-pagination-page": "1",
        "x-pagination-pagetotal": "1",
        "x-pagination-pagesize": "30",
        "x-pagination-count": "1",
      },
    }));

    assert.deepStrictEqual(await pending, []);
  });

  test("does not reuse completed package state across account epochs", async () => {
    let calls = 0;
    const fake = {
      async fetchCollection() {
        calls += 1;
        return makeCollectionResult({
          items: [makePackage(calls === 1 ? "account-one" : "account-two")],
          complete: true,
          pagination: makePagination(1, 1, 30, 1),
        });
      },
    };
    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" }, "acme", context,
      { connectionManager, createPaginatedFetch: () => fake }
    );

    assert.deepStrictEqual((await repositoryNode.getPackages()).map(node => node.name), ["account-one"]);
    connectionManager.setState({ accountEpoch: 2 });
    assert.deepStrictEqual((await repositoryNode.getPackages()).map(node => node.name), ["account-two"]);
    assert.strictEqual(calls, 2);
  });

  test("loads one bounded package page and exposes an authoritative Load More node", async () => {
    vscode.workspace.getConfiguration = () => ({
      get(key) {
        if (key === "showMaxPackages") return 2;
        return false;
      },
    });
    const calls = [];
    const refreshes = [];
    const fake = {
      async fetchCollection(_endpoint, options) {
        calls.push(options);
        if (!options.resume) {
          return makeCollectionResult({
            items: [makePackage("one"), makePackage("two")],
            continuation: makeContinuation(options.descriptor),
            pagination: makePagination(1, 2, 2, 3),
          });
        }
        assert.strictEqual(options.knownIdentities.size, 2);
        return makeCollectionResult({
          items: [makePackage("three")],
          complete: true,
          pageCount: 2,
          requestCount: 2,
          pagination: makePagination(2, 2, 2, 3),
        });
      },
    };
    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" },
      "acme",
      context,
      {
        connectionManager,
        createPaginatedFetch: () => fake,
        upstreamInventory: {
          getAllUpstreamData: async () => completeUpstreamState(),
        },
        requestRefresh: node => refreshes.push(node),
        withProgress: async (_options, task) => task({ report() {} }, { isCancellationRequested: false }),
      }
    );

    let children = await repositoryNode.getChildren();
    const loadMore = children.find(child => child.getTreeItem().contextValue === "repositoryLoadMore");
    assert.ok(loadMore);
    assert.strictEqual(loadMore.getTreeItem().label, "Load more packages (showing 2 of 3)");
    assert.strictEqual(calls[0].pageBatchLimit, 1);
    assert.strictEqual(calls[0].maxPages, 20);
    assert.strictEqual(calls[0].maxRequests, 24);
    assert.strictEqual(calls[0].maxItems, 600);

    await repositoryNode.loadMorePackages();
    children = await repositoryNode.getChildren();
    assert.deepStrictEqual(repositoryNode._packageState.nodes.map(node => node.name), ["one", "two", "three"]);
    assert.strictEqual(children.some(child => (
      child.getTreeItem().contextValue === "repositoryLoadMore"
    )), false);
    assert.strictEqual(repositoryNode._packageState.complete, true);
    assert.strictEqual(refreshes.length, 2);
  });

  test("resumes the real shared collector at the exact next package page", async () => {
    vscode.workspace.getConfiguration = () => ({
      get(key) { return key === "showMaxPackages" ? 1 : false; },
    });
    const requests = [];
    const api = {
      async get(endpoint) {
        requests.push(endpoint);
        const page = Number(new URL(endpoint, "https://api.test/").searchParams.get("page"));
        const item = page === 1 ? makePackage("one") : makePackage("two");
        return apiSuccess([item], {
          headers: {
            "x-pagination-page": String(page),
            "x-pagination-pagetotal": "2",
            "x-pagination-pagesize": "1",
            "x-pagination-count": "2",
          },
        });
      },
    };
    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" }, "acme", context,
      {
        connectionManager,
        createCloudsmithAPI: () => api,
        withProgress: async (_options, task) => task({}, { isCancellationRequested: false }),
      }
    );

    await repositoryNode.getPackages();
    await repositoryNode.loadMorePackages();

    assert.deepStrictEqual(
      requests.map(endpoint => new URL(endpoint, "https://api.test/").searchParams.get("page")),
      ["1", "2"]
    );
    assert.deepStrictEqual(repositoryNode._packageState.nodes.map(node => node.name), ["one", "two"]);
    assert.strictEqual(repositoryNode._packageState.pageCount, 2);
    assert.strictEqual(repositoryNode._packageState.requestCount, 2);
    assert.strictEqual(repositoryNode._packageState.complete, true);
  });

  test("coalesces duplicate Load More invocations into one page request", async () => {
    vscode.workspace.getConfiguration = () => ({
      get(key) { return key === "showMaxPackages" ? 2 : false; },
    });
    const secondPage = deferred();
    let calls = 0;
    const fake = {
      async fetchCollection(_endpoint, options) {
        calls += 1;
        if (!options.resume) {
          return makeCollectionResult({
            items: [makePackage("one"), makePackage("two")],
            continuation: makeContinuation(options.descriptor),
            pagination: makePagination(1, 2, 2, 3),
          });
        }
        return secondPage.promise;
      },
    };
    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" }, "acme", context,
      {
        connectionManager,
        createPaginatedFetch: () => fake,
        withProgress: async (_options, task) => task({}, { isCancellationRequested: false }),
      }
    );
    await repositoryNode.getPackages();

    const first = repositoryNode.loadMorePackages();
    const second = repositoryNode.loadMorePackages();
    assert.strictEqual(first, second);
    await new Promise(resolve => setImmediate(resolve));
    assert.strictEqual(calls, 2);
    secondPage.resolve(makeCollectionResult({
      items: [makePackage("three")],
      complete: true,
      pageCount: 2,
      requestCount: 2,
      pagination: makePagination(2, 2, 2, 3),
    }));
    await Promise.all([first, second]);
    assert.strictEqual(calls, 2);
  });

  test("ignores a stale continuation completion after node invalidation", async () => {
    vscode.workspace.getConfiguration = () => ({
      get(key) { return key === "showMaxPackages" ? 2 : false; },
    });
    const secondPage = deferred();
    const refreshes = [];
    const fake = {
      async fetchCollection(_endpoint, options) {
        if (!options.resume) {
          return makeCollectionResult({
            items: [makePackage("one"), makePackage("two")],
            continuation: makeContinuation(options.descriptor),
            pagination: makePagination(1, 2, 2, 3),
          });
        }
        return secondPage.promise;
      },
    };
    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" }, "acme", context,
      {
        connectionManager,
        createPaginatedFetch: () => fake,
        requestRefresh: node => refreshes.push(node),
        withProgress: async (_options, task) => task({}, { isCancellationRequested: false }),
      }
    );
    await repositoryNode.getPackages();
    const pending = repositoryNode.loadMorePackages();
    await new Promise(resolve => setImmediate(resolve));
    repositoryNode.invalidate();
    secondPage.resolve(makeCollectionResult({
      items: [makePackage("stale")],
      complete: true,
      pageCount: 2,
      requestCount: 2,
      pagination: makePagination(2, 2, 2, 3),
    }));
    await pending;

    assert.deepStrictEqual(repositoryNode._packageState.nodes.map(node => node.name), ["one", "two"]);
    assert.strictEqual(refreshes.length, 1);
  });

  test("preserves loaded packages across a failed page retry and clears recovered failure state", async () => {
    vscode.workspace.getConfiguration = () => ({
      get(key) { return key === "showMaxPackages" ? 2 : false; },
    });
    let pageTwoAttempts = 0;
    const fake = {
      async fetchCollection(_endpoint, options) {
        if (!options.resume) {
          return makeCollectionResult({
            items: [makePackage("one"), makePackage("two")],
            continuation: makeContinuation(options.descriptor),
            pagination: makePagination(1, 2, 2, 3),
          });
        }
        pageTwoAttempts += 1;
        assert.strictEqual(options.knownIdentities.size, 2);
        if (pageTwoAttempts === 1) {
          const failure = collectionFailure();
          return makeCollectionResult({
            continuation: makeContinuation(options.descriptor, { requestCount: 2 }),
            failures: [failure],
            failureCount: 1,
            termination: "request_failed",
            pageCount: 1,
            requestCount: 2,
            pagination: makePagination(1, 2, 2, 3),
            cumulativeItemCount: 2,
          });
        }
        return makeCollectionResult({
          items: [makePackage("three")],
          complete: true,
          pageCount: 2,
          requestCount: 3,
          pagination: makePagination(2, 2, 2, 3),
        });
      },
    };
    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" }, "acme", context,
      {
        connectionManager,
        createPaginatedFetch: () => fake,
        withProgress: async (_options, task) => task({}, { isCancellationRequested: false }),
      }
    );
    await repositoryNode.getPackages();
    await repositoryNode.loadMorePackages();
    assert.strictEqual(repositoryNode._packageState.nodes.length, 2);
    assert.strictEqual(repositoryNode._packageState.failures.length, 1);
    assert.ok(repositoryNode._packageState.continuation);
    let children = await repositoryNode.getChildren();
    const partial = children.find(child => (
      child.getTreeItem().contextValue === "repositoryPackagesPartial"
    ));
    assert.ok(partial);
    assert.strictEqual(partial.getTreeItem().command.command, "cloudsmith-vsc.loadMoreRepositoryPackages");
    assert.strictEqual(children.filter(child => repositoryNode.ownsPackageSelection(child)).length, 2);
    assert.strictEqual(children.some(child => (
      child.getTreeItem().contextValue === "repositoryLoadMore"
    )), false);

    await repositoryNode.loadMorePackages();
    assert.strictEqual(repositoryNode._packageState.nodes.length, 3);
    assert.strictEqual(repositoryNode._packageState.failures.length, 0);
    assert.strictEqual(repositoryNode._packageState.complete, true);
    children = await repositoryNode.getChildren();
    assert.strictEqual(children.some(child => child.terminalOutcome), false);
  });

  test("fails closed on a duplicate cross-page identity", async () => {
    vscode.workspace.getConfiguration = () => ({
      get(key) { return key === "showMaxPackages" ? 1 : false; },
    });
    const fake = {
      async fetchCollection(_endpoint, options) {
        if (!options.resume) {
          return makeCollectionResult({
            items: [makePackage("same")],
            continuation: makeContinuation(options.descriptor, {
              anchor: makePagination(1, 2, 1, 2), itemCount: 1,
            }),
            pagination: makePagination(1, 2, 1, 2),
          });
        }
        return makeCollectionResult({
          items: [makePackage("same")],
          complete: true,
          pageCount: 2,
          requestCount: 2,
          pagination: makePagination(2, 2, 1, 2),
        });
      },
    };
    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" }, "acme", context,
      {
        connectionManager,
        createPaginatedFetch: () => fake,
        withProgress: async (_options, task) => task({}, { isCancellationRequested: false }),
      }
    );
    await repositoryNode.getPackages();
    await repositoryNode.loadMorePackages();

    assert.strictEqual(repositoryNode._packageState.nodes.length, 1);
    assert.strictEqual(repositoryNode._packageState.complete, false);
    assert.strictEqual(repositoryNode._packageState.continuation, null);
    assert.strictEqual(repositoryNode._packageState.termination, "duplicate_identity");
  });

  test("cancellation preserves items and advances the cumulative retry budget", async () => {
    vscode.workspace.getConfiguration = () => ({
      get(key) { return key === "showMaxPackages" ? 2 : false; },
    });
    let initialContinuation;
    const fake = {
      async fetchCollection(_endpoint, options) {
        if (!options.resume) {
          initialContinuation = makeContinuation(options.descriptor);
          return makeCollectionResult({
            items: [makePackage("one"), makePackage("two")],
            continuation: initialContinuation,
            pagination: makePagination(1, 2, 2, 3),
          });
        }
        assert.strictEqual(options.cancellationToken.isCancellationRequested, true);
        const cancelledContinuation = makeContinuation(options.descriptor, {
          nextPage: 2,
          anchor: makePagination(1, 2, 2, 3),
          pageCount: 1,
          requestCount: 2,
          itemCount: 2,
        });
        return makeCollectionResult({
          cancelled: true,
          continuation: cancelledContinuation,
          termination: "cancelled",
          pageCount: 1,
          requestCount: 2,
          pagination: makePagination(1, 2, 2, 3),
          cumulativeItemCount: 2,
        });
      },
    };
    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" }, "acme", context,
      {
        connectionManager,
        createPaginatedFetch: () => fake,
        withProgress: async (_options, task) => task({}, { isCancellationRequested: true }),
      }
    );
    await repositoryNode.getPackages();
    await repositoryNode.loadMorePackages();

    assert.notStrictEqual(repositoryNode._packageState.continuation, initialContinuation);
    assert.strictEqual(repositoryNode._packageState.continuation.cumulative.requestCount, 2);
    assert.strictEqual(repositoryNode._packageState.requestCount, 2);
    assert.deepStrictEqual(repositoryNode._packageState.nodes.map(node => node.name), ["one", "two"]);
  });

  test("never labels a cancelled initial collection as an empty repository", async () => {
    const fake = {
      async fetchCollection() {
        return makeCollectionResult({ cancelled: true, termination: "cancelled" });
      },
    };
    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" }, "acme", context,
      { connectionManager, createPaginatedFetch: () => fake }
    );

    const children = await repositoryNode.getChildren();
    const labels = children.map(child => child.getTreeItem().label);

    assert.ok(labels.includes("Package loading canceled"));
    assert.strictEqual(labels.includes("Repository is empty"), false);
    assert.strictEqual(repositoryNode._packageState.complete, false);
  });

  test("QH-001 publishes package rows while upstream metadata remains pending", async function () {
    this.timeout(2000);
    const metadataGate = deferred();
    const refreshes = [];
    const repositoryNode = new RepositoryNodeImplementation(
      { slug: "packages", slug_perm: "packages", name: "Packages" },
      "acme",
      context,
      {
        connectionManager,
        upstreamInventory: {
          getAllUpstreamData() { return metadataGate.promise; },
        },
        createPaginatedFetch: () => ({
          async fetchCollection() {
            const failure = collectionFailure(1, "timeout");
            return makeCollectionResult({
              items: [makePackage("authoritative-package")],
              failures: [failure],
              failureCount: 1,
              termination: "request_failed",
              pageCount: 1,
              requestCount: 1,
              pagination: makePagination(1, 1, 30, 1),
            });
          },
        }),
        requestRefresh: node => refreshes.push(node),
      }
    );
    let publication;

    try {
      publication = repositoryNode.getChildren();
      const outcome = await Promise.race([
        publication.then(children => ({ kind: "published", children })),
        new Promise(resolve => setTimeout(() => resolve({ kind: "timeout" }), 100)),
      ]);

      assert.strictEqual(
        outcome.kind,
        "published",
        "package authority must not await supplementary upstream metadata"
      );
      assert.deepStrictEqual(
        outcome.children
          .filter(child => repositoryNode.ownsPackageSelection(child))
          .map(child => child.name),
        ["authoritative-package"]
      );
      assert.strictEqual(
        outcome.children[0].getTreeItem().contextValue,
        "repositoryPackagesPartial",
        "typed package terminal truth must publish before retained rows and metadata"
      );
      assert.deepStrictEqual(outcome.children[0].terminalOutcome, {
        kind: "partial",
        scope: "repository",
        authoritative: false,
        action: "retry",
      });
      assert.strictEqual(
        outcome.children.some(child => child instanceof UpstreamIndicatorNode),
        false,
        "pending metadata must not be fabricated into the first publication"
      );

      metadataGate.resolve(completeUpstreamState([
        safeUpstream("npm", "npmjs", true, "https://registry.npmjs.org"),
      ]));
      await new Promise(resolve => setImmediate(resolve));
      assert.deepStrictEqual(refreshes, [repositoryNode]);

      const settledChildren = await repositoryNode.getChildren();
      assert.strictEqual(
        settledChildren.some(child => child instanceof UpstreamIndicatorNode),
        true,
        "settled supplementary metadata must publish through a safe refresh"
      );
    } finally {
      metadataGate.resolve(completeUpstreamState());
      if (publication) await publication.catch(() => {});
      repositoryNode.dispose();
    }
  });

  test("QH-001 publishes package rows while entitlement metadata remains pending", async function () {
    this.timeout(2000);
    vscode.workspace.getConfiguration = () => ({
      get(key) {
        if (key === "showEntitlements") return true;
        if (key === "showMaxPackages") return 30;
        return false;
      },
    });
    const entitlementGate = deferred();
    const refreshes = [];
    const repositoryNode = new RepositoryNodeImplementation(
      { slug: "packages", slug_perm: "packages", name: "Packages" },
      "acme",
      context,
      {
        connectionManager,
        upstreamInventory: {
          async getAllUpstreamData() { return completeUpstreamState(); },
        },
        createPaginatedFetch: () => ({
          async fetchCollection(endpoint) {
            if (endpoint.includes("entitlements/")) return entitlementGate.promise;
            return makeCollectionResult({
              items: [makePackage("authoritative-package")],
              complete: true,
              pageCount: 1,
              requestCount: 1,
              pagination: makePagination(1, 1, 30, 1),
            });
          },
        }),
        requestRefresh: node => refreshes.push(node),
      }
    );

    try {
      const firstChildren = await repositoryNode.getChildren();
      assert.deepStrictEqual(
        firstChildren
          .filter(child => repositoryNode.ownsPackageSelection(child))
          .map(child => child.name),
        ["authoritative-package"]
      );
      assert.strictEqual(
        firstChildren.some(child => child instanceof EntitlementSummaryNode),
        false
      );

      entitlementGate.resolve(makeCollectionResult({
        items: [{ name: "CI", slug_perm: "ci", is_active: true }],
        complete: true,
        pageCount: 1,
        requestCount: 1,
        pagination: makePagination(1, 1, 50, 1),
      }));
      await new Promise(resolve => setImmediate(resolve));
      assert.deepStrictEqual(refreshes, [repositoryNode]);

      const settledChildren = await repositoryNode.getChildren();
      assert.strictEqual(
        settledChildren.some(child => child instanceof EntitlementSummaryNode),
        true
      );
    } finally {
      entitlementGate.resolve(makeCollectionResult({ complete: true }));
      repositoryNode.dispose();
    }
  });

  test("QH-001 observes late metadata rejection without losing package authority", async function () {
    this.timeout(2000);
    const metadataGate = deferred();
    const refreshes = [];
    const unhandled = [];
    const onUnhandled = reason => unhandled.push(reason);
    process.on("unhandledRejection", onUnhandled);
    const repositoryNode = new RepositoryNodeImplementation(
      { slug: "packages", slug_perm: "packages", name: "Packages" },
      "acme",
      context,
      {
        connectionManager,
        upstreamInventory: {
          getAllUpstreamData() { return metadataGate.promise; },
        },
        createPaginatedFetch: () => ({
          async fetchCollection() {
            return makeCollectionResult({
              items: [makePackage("authoritative-package")],
              complete: true,
              pageCount: 1,
              requestCount: 1,
            });
          },
        }),
        requestRefresh: node => {
          refreshes.push(node);
          return Promise.reject(new Error("refresh observer rejected"));
        },
      }
    );

    try {
      const firstChildren = await repositoryNode.getChildren();
      assert.deepStrictEqual(
        firstChildren
          .filter(child => repositoryNode.ownsPackageSelection(child))
          .map(child => child.name),
        ["authoritative-package"]
      );

      metadataGate.reject(new Error("late upstream failure"));
      await new Promise(resolve => setImmediate(resolve));
      await new Promise(resolve => setImmediate(resolve));
      assert.deepStrictEqual(unhandled, []);
      assert.deepStrictEqual(refreshes, [repositoryNode]);

      const settledChildren = await repositoryNode.getChildren();
      assert.ok(settledChildren.some(child => (
        child.getTreeItem().label === "Upstreams: failed to load"
      )));
      assert.deepStrictEqual(
        settledChildren
          .filter(child => repositoryNode.ownsPackageSelection(child))
          .map(child => child.name),
        ["authoritative-package"]
      );
    } finally {
      process.removeListener("unhandledRejection", onUnhandled);
      metadataGate.resolve(completeUpstreamState());
      repositoryNode.dispose();
    }
  });

  test("QH-001 suppresses a stale metadata refresh after account replacement", async function () {
    this.timeout(2000);
    const metadataGate = deferred();
    const refreshes = [];
    const repositoryNode = new RepositoryNodeImplementation(
      { slug: "packages", slug_perm: "packages", name: "Packages" },
      "acme",
      context,
      {
        connectionManager,
        upstreamInventory: {
          getAllUpstreamData() { return metadataGate.promise; },
        },
        createPaginatedFetch: () => ({
          async fetchCollection() {
            return makeCollectionResult({
              items: [makePackage("authoritative-package")],
              complete: true,
              pageCount: 1,
              requestCount: 1,
            });
          },
        }),
        requestRefresh: node => refreshes.push(node),
      }
    );

    try {
      const firstChildren = await repositoryNode.getChildren();
      assert.strictEqual(
        firstChildren.filter(child => repositoryNode.ownsPackageSelection(child)).length,
        1
      );
      connectionManager.setState({ accountEpoch: 2 });
      metadataGate.resolve(completeUpstreamState([
        safeUpstream("npm", "stale", true, "https://registry.npmjs.org"),
      ]));
      await new Promise(resolve => setImmediate(resolve));
      await new Promise(resolve => setImmediate(resolve));

      assert.deepStrictEqual(refreshes, []);
      assert.strictEqual(repositoryNode._metadataLoaded, false);
    } finally {
      metadataGate.resolve(completeUpstreamState());
      repositoryNode.dispose();
    }
  });

  test("FUX-002 publishes machine-readable empty, failed, and cancelled package outcomes", async () => {
    const cases = [
      {
        name: "empty",
        result: makeCollectionResult({ complete: true }),
        contextValue: "repositoryPackagesEmpty",
        action: "none",
        authoritative: true,
      },
      {
        name: "failed",
        result: makeCollectionResult({
          failures: [collectionFailure(1, "timeout")],
          termination: "request_failed",
          requestCount: 1,
        }),
        contextValue: "repositoryPackagesFailed",
        action: "retry",
        authoritative: false,
      },
      {
        name: "cancelled",
        result: makeCollectionResult({
          cancelled: true,
          termination: "cancelled",
          requestCount: 1,
        }),
        contextValue: "repositoryPackagesCancelled",
        action: "retry",
        authoritative: false,
      },
    ];

    for (const expected of cases) {
      const repositoryNode = new RepositoryNode(
        {
          slug: `packages-${expected.name}`,
          slug_perm: `packages-${expected.name}`,
          name: "Packages",
          storage_region: "us-ohio",
        },
        "acme",
        context,
        {
          connectionManager,
          createPaginatedFetch: () => ({
            async fetchCollection() { return expected.result; },
          }),
        }
      );

      const children = await repositoryNode.getChildren();
      const terminal = children.find(child => (
        child.getTreeItem().contextValue === expected.contextValue
      ));
      assert.ok(terminal, `${expected.name} must publish an explicit terminal row`);
      assert.strictEqual(children[0], terminal, `${expected.name} truth must precede metadata`);
      assert.ok(
        children.some(child => child.getTreeItem().label === "Storage Region"),
        `${expected.name} fixture must exercise terminal publication beside metadata`
      );
      assert.deepStrictEqual(terminal.terminalOutcome, {
        kind: expected.name,
        scope: "repository",
        authoritative: expected.authoritative,
        action: expected.action,
      });
      assert.strictEqual(
        children.some(child => child.getTreeItem().contextValue === "repositoryPackagesEmpty"),
        expected.name === "empty",
        `${expected.name} must not become a false empty state`
      );
      const item = terminal.getTreeItem();
      if (expected.action === "retry") {
        assert.strictEqual(item.description, "Retry");
        assert.strictEqual(item.command.command, "cloudsmith-vsc.refreshView");
        assert.strictEqual(JSON.stringify(item).includes("The page request failed."), false);
      } else {
        assert.strictEqual(item.command, undefined);
      }
    }
  });

  test("FUX-002 preserves packages beside partial and cancelled package outcomes", async () => {
    const cases = [
      {
        name: "partial",
        result: makeCollectionResult({
          items: [makePackage("partial-package", { repository: "partial" })],
          failures: [collectionFailure(1, "timeout")],
          termination: "request_failed",
          pageCount: 1,
          requestCount: 1,
          pagination: makePagination(1, 1, 30, 1),
        }),
        contextValue: "repositoryPackagesPartial",
      },
      {
        name: "cancelled",
        result: makeCollectionResult({
          items: [makePackage("cancelled-package", { repository: "cancelled" })],
          cancelled: true,
          termination: "cancelled",
          pageCount: 1,
          requestCount: 1,
          pagination: makePagination(1, 1, 30, 1),
        }),
        contextValue: "repositoryPackagesCancelled",
      },
    ];

    for (const expected of cases) {
      const repositoryNode = new RepositoryNode(
        {
          slug: expected.name,
          slug_perm: expected.name,
          name: "Packages",
          storage_region: "us-ohio",
        },
        "acme",
        context,
        {
          connectionManager,
          createPaginatedFetch: () => ({
            async fetchCollection() { return expected.result; },
          }),
        }
      );

      const children = await repositoryNode.getChildren();
      const packageNodes = children.filter(child => repositoryNode.ownsPackageSelection(child));
      const terminal = children.find(child => (
        child.getTreeItem().contextValue === expected.contextValue
      ));
      assert.deepStrictEqual(packageNodes.map(node => node.name), [`${expected.name}-package`]);
      assert.ok(
        children.some(child => child instanceof UpstreamIndicatorNode),
        "metadata must coexist with retained package and terminal rows"
      );
      assert.ok(terminal, `${expected.name} must remain explicit beside retained packages`);
      const terminalIndex = children.indexOf(terminal);
      const packageIndex = children.indexOf(packageNodes[0]);
      const metadataIndex = children.findIndex(child => (
        child.getTreeItem().label === "Storage Region"
      ));
      assert.strictEqual(terminalIndex, 0, `${expected.name} truth must be immediately visible`);
      assert.ok(packageIndex > terminalIndex, "retained packages must follow terminal truth");
      assert.ok(metadataIndex > packageIndex, "metadata must follow package authority");
      assert.strictEqual(terminal.terminalOutcome.kind, expected.name);
      assert.strictEqual(terminal.terminalOutcome.authoritative, false);
      assert.strictEqual(terminal.getTreeItem().description, "Retry");
      assert.strictEqual(terminal.getTreeItem().command.command, "cloudsmith-vsc.refreshView");
    }
  });

  test("active continuation publishes retained packages and loading before metadata", async () => {
    vscode.workspace.getConfiguration = () => ({
      get(key) { return key === "showMaxPackages" ? 1 : false; },
    });
    const nextPage = deferred();
    const fake = {
      async fetchCollection(_endpoint, options) {
        if (!options.resume) {
          return makeCollectionResult({
            items: [makePackage("one")],
            continuation: makeContinuation(options.descriptor, {
              anchor: makePagination(1, 2, 1, 2),
              itemCount: 1,
            }),
            pagination: makePagination(1, 2, 1, 2),
          });
        }
        return nextPage.promise;
      },
    };
    const repositoryNode = new RepositoryNode(
      {
        slug: "packages",
        slug_perm: "packages",
        name: "Packages",
        storage_region: "us-ohio",
      },
      "acme",
      context,
      {
        connectionManager,
        createPaginatedFetch: () => fake,
        withProgress: async (_options, task) => task({}, { isCancellationRequested: false }),
      }
    );
    await repositoryNode.getPackages();

    const loading = repositoryNode.loadMorePackages();
    const children = await repositoryNode.getChildren();
    const packageIndex = children.findIndex(child => repositoryNode.ownsPackageSelection(child));
    const loadingIndex = children.findIndex(child => (
      child.getTreeItem().label === "Loading more packages..."
    ));
    const metadataIndex = children.findIndex(child => (
      child.getTreeItem().label === "Storage Region"
    ));
    assert.ok(packageIndex >= 0, "retained package authority must remain visible while loading");
    assert.ok(loadingIndex > packageIndex, "loading must follow retained package authority");
    assert.ok(metadataIndex > loadingIndex, "metadata must not obscure active loading truth");

    nextPage.resolve(makeCollectionResult({
      items: [makePackage("two")],
      complete: true,
      pageCount: 2,
      requestCount: 2,
      pagination: makePagination(2, 2, 1, 2),
    }));
    await loading;
  });

  test("stops exposing continuation at the cumulative page cap", async () => {
    vscode.workspace.getConfiguration = () => ({
      get(key) { return key === "showMaxPackages" ? 1 : false; },
    });
    let calls = 0;
    const fake = {
      async fetchCollection(_endpoint, options) {
        calls += 1;
        const page = options.resume?.nextPage || 1;
        assert.strictEqual(options.knownIdentities?.size || 0, page - 1);
        const pagination = makePagination(page, 21, 1);
        const continuation = page < 20
          ? makeContinuation(options.descriptor, {
            nextPage: page + 1,
            anchor: pagination,
            pageCount: page,
            requestCount: page,
            itemCount: page,
          })
          : null;
        return makeCollectionResult({
          items: [makePackage(`package-${page}`)],
          continuation,
          termination: continuation ? "page_batch" : "page_limit",
          pageCount: page,
          requestCount: page,
          pagination,
          cumulativeItemCount: page,
        });
      },
    };
    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" }, "acme", context,
      {
        connectionManager,
        createPaginatedFetch: () => fake,
        upstreamInventory: {
          getAllUpstreamData: async () => completeUpstreamState(),
        },
        withProgress: async (_options, task) => task({}, { isCancellationRequested: false }),
      }
    );
    await repositoryNode.getPackages();
    for (let page = 2; page <= 20; page += 1) {
      await repositoryNode.loadMorePackages();
    }
    const children = await repositoryNode.getChildren();

    assert.strictEqual(calls, 20);
    assert.strictEqual(repositoryNode._packageState.nodes.length, 20);
    assert.strictEqual(repositoryNode._packageState.capReached, true);
    assert.strictEqual(repositoryNode._packageState.continuation, null);
    const terminal = children.find(child => (
      child.getTreeItem().contextValue === "repositoryPackagesPartial"
    ));
    assert.strictEqual(terminal.getTreeItem().label, "Some packages are not shown");
    assert.strictEqual(terminal.terminalOutcome.action, "change-filter");
    assert.strictEqual(children.some(child => (
      child.getTreeItem().contextValue === "repositoryLoadMore"
    )), false);
  });

  test("loads package-group continuation with format-qualified canonical identities", async () => {
    vscode.workspace.getConfiguration = () => ({
      get(key) {
        if (key === "showMaxPackages") return 1;
        if (key === "groupByPackageGroups") return true;
        return false;
      },
    });
    let calls = 0;
    const fake = {
      async fetchCollection(endpoint, options) {
        calls += 1;
        assert.ok(endpoint.includes("/groups"));
        assert.strictEqual(options.responseType, "object");
        assert.strictEqual(options.validate([{ name: "shared", format: "npm" }]), true);
        assert.strictEqual(options.validateResponse({ results: [{ name: "shared", format: "npm" }] }), true);
        assert.deepStrictEqual(options.extractItems({ results: [{ name: "shared", format: "npm" }] }), [
          { name: "shared", format: "npm" },
        ]);
        if (!options.resume) {
          return makeCollectionResult({
            items: [{ name: "shared", format: "npm", count: 1 }],
            continuation: makeContinuation(options.descriptor, {
              anchor: makePagination(1, 2, 1, 2), itemCount: 1,
            }),
            pagination: makePagination(1, 2, 1, 2),
          });
        }
        assert.strictEqual(options.knownIdentities.size, 1);
        return makeCollectionResult({
          items: [{ name: "shared", format: "python", count: 1 }],
          complete: true,
          pageCount: 2,
          requestCount: 2,
          pagination: makePagination(2, 2, 1, 2),
        });
      },
    };
    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" }, "acme", context,
      {
        connectionManager,
        createPaginatedFetch: () => fake,
        withProgress: async (_options, task) => task({}, { isCancellationRequested: false }),
      }
    );
    await repositoryNode.getPackages();
    await repositoryNode.loadMorePackages();

    assert.strictEqual(calls, 2);
    assert.deepStrictEqual(
      repositoryNode._packageState.nodes.map(node => `${node.format}:${node.name}`),
      ["npm:shared", "python:shared"]
    );
    const children = await repositoryNode.getChildren();
    assert.deepStrictEqual(
      children
        .filter(child => repositoryNode.ownsPackageSelection(child))
        .map(child => child.getTreeItem().contextValue),
      ["packageGroup", "packageGroup"]
    );
    assert.strictEqual(children.some(child => child.terminalOutcome), false);
  });

  test("rejects contradictory continuation metadata without another request", async () => {
    vscode.workspace.getConfiguration = () => ({
      get(key) { return key === "showMaxPackages" ? 1 : false; },
    });
    let calls = 0;
    const fake = {
      async fetchCollection(_endpoint, options) {
        calls += 1;
        return makeCollectionResult({
          items: [makePackage("one")],
          continuation: makeContinuation(options.descriptor, {
            anchor: makePagination(2, 3, 1),
            itemCount: 1,
          }),
          pagination: makePagination(1, 3, 1),
        });
      },
    };
    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" }, "acme", context,
      { connectionManager, createPaginatedFetch: () => fake }
    );
    await repositoryNode.getPackages();
    await repositoryNode.loadMorePackages();

    assert.strictEqual(calls, 1);
    assert.strictEqual(repositoryNode._packageState.complete, false);
    assert.strictEqual(repositoryNode._packageState.continuation, null);
  });

  test("rejects continuation counters that do not match their pagination anchor", async () => {
    vscode.workspace.getConfiguration = () => ({
      get(key) { return key === "showMaxPackages" ? 1 : false; },
    });
    const cases = [
      {
        name: "page count differs from anchor page",
        continuation(descriptor) {
          return makeContinuation(descriptor, {
            anchor: makePagination(1, 3, 1),
            nextPage: 2,
            pageCount: 2,
            requestCount: 2,
            itemCount: 1,
          });
        },
        pageCount: 2,
        requestCount: 2,
        pagination: makePagination(1, 3, 1),
      },
      {
        name: "next page differs from cumulative page count",
        continuation(descriptor) {
          return makeContinuation(descriptor, {
            anchor: makePagination(2, 4, 1),
            nextPage: 3,
            pageCount: 1,
            requestCount: 1,
            itemCount: 1,
          });
        },
        pageCount: 1,
        requestCount: 1,
        pagination: makePagination(2, 4, 1),
      },
      {
        name: "null anchor carries committed page and item state",
        continuation(descriptor) {
          return Object.freeze({
            nextPage: 1,
            anchor: null,
            cumulative: Object.freeze({
              pageCount: 1,
              requestCount: 1,
              itemCount: 1,
              duplicateCount: 0,
              failureCount: 0,
            }),
            descriptor,
            binding: "a".repeat(64),
          });
        },
        pageCount: 1,
        requestCount: 1,
        pagination: null,
      },
      {
        name: "item count omits records from committed full pages",
        continuation(descriptor) {
          return makeContinuation(descriptor, {
            anchor: makePagination(1, 2, 2, 3),
            nextPage: 2,
            pageCount: 1,
            requestCount: 1,
            itemCount: 1,
          });
        },
        pageCount: 1,
        requestCount: 1,
        pagination: makePagination(1, 2, 2, 3),
      },
      {
        name: "request count is below committed page count",
        continuation(descriptor) {
          return makeContinuation(descriptor, {
            anchor: makePagination(2, 3, 1),
            nextPage: 3,
            pageCount: 2,
            requestCount: 1,
            itemCount: 1,
          });
        },
        pageCount: 2,
        requestCount: 1,
        pagination: makePagination(2, 3, 1),
        expectedTermination: "invalid_response",
      },
    ];

    for (const tampered of cases) {
      let calls = 0;
      const fake = {
        async fetchCollection(_endpoint, options) {
          calls += 1;
          return makeCollectionResult({
            items: [makePackage(`item-${calls}`)],
            continuation: tampered.continuation(options.descriptor),
            pageCount: tampered.pageCount,
            requestCount: tampered.requestCount,
            pagination: tampered.pagination,
          });
        },
      };
      const repositoryNode = new RepositoryNode(
        { slug: "packages", slug_perm: "packages", name: "Packages" }, "acme", context,
        { connectionManager, createPaginatedFetch: () => fake }
      );
      await repositoryNode.getPackages();
      await repositoryNode.loadMorePackages();
      assert.strictEqual(calls, 1, tampered.name);
      assert.strictEqual(repositoryNode._packageState.continuation, null, tampered.name);
      assert.strictEqual(
        repositoryNode._packageState.termination,
        tampered.expectedTermination || "invalid_continuation",
        tampered.name
      );
    }
  });

  test("paginates entitlements with the shared bounded collector and reports partial data", async () => {
    let captured;
    const failure = collectionFailure(2, "server_error");
    const fake = {
      async fetchCollection(endpoint, options) {
        captured = { endpoint, options };
        return makeCollectionResult({
          items: [{ name: "CI", slug_perm: "ci", is_active: true }],
          failures: [failure],
          failureCount: 1,
          termination: "request_failed",
          pageCount: 1,
          requestCount: 2,
          pagination: makePagination(1, 2, 50, 51),
          cumulativeItemCount: 1,
        });
      },
    };
    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" }, "acme", context,
      { connectionManager, createPaginatedFetch: () => fake }
    );
    const result = await repositoryNode.getEntitlementCollection();

    assert.strictEqual(result.items.length, 1);
    assert.strictEqual(result.partial, true);
    assert.ok(captured.endpoint.includes("entitlements/acme/packages"));
    assert.strictEqual(captured.options.pageSize, 50);
    assert.strictEqual(captured.options.maxPages, 20);
    assert.strictEqual(captured.options.maxRequests, 24);
    assert.strictEqual(captured.options.maxItems, 600);
  });

  test("preserves upstream failures in the indicator instead of claiming a configured total", async () => {
    const indicator = new UpstreamIndicatorNode(
      [{
        name: "PyPI",
        origin: "https://pypi.org",
        upstream_url: "https://user:pass@pypi.org/simple/?token=secret#fragment",
        is_active: true,
      }],
      {},
      context,
      {
        complete: false,
        failedFormats: ["npm"],
        unsupportedFormats: ["terraform"],
      }
    );
    const item = indicator.getTreeItem();
    assert.strictEqual(item.label, "Upstreams: 1 active among 1 loaded (partial)");
    assert.ok(item.tooltip.includes("Could not inspect:"));
    assert.ok(item.tooltip.includes("npm"));
    assert.ok(!item.tooltip.includes("Not applicable"));
    assert.ok(!item.tooltip.includes("terraform"));
    assert.ok(item.tooltip.includes("PyPI (https://pypi.org)"));
    assert.ok(!item.tooltip.includes("user:pass"));
    assert.ok(!item.tooltip.includes("/simple/"));
    assert.ok(!item.tooltip.includes("token=secret"));
    assert.ok(!item.tooltip.includes("#fragment"));

    const summaryCached = new UpstreamIndicatorNode(
      [{ name: "Summary-only PyPI", _format: "python", is_active: true }],
      {},
      context,
      { complete: true }
    ).getTreeItem();
    assert.strictEqual(summaryCached.tooltip, "Summary-only PyPI (Origin unavailable)");
    assert(!summaryCached.tooltip.includes("undefined"));
  });

  test("upstream tooltip handles missing and malformed URLs and caps displayed entries", () => {
    const upstreams = Array.from({ length: 21 }, (_, index) => ({
      name: `Mirror ${index}`,
      upstream_url: index === 0 ? undefined : (index === 1 ? "not a URL" : `https://m${index}.example/path`),
      is_active: true,
    }));
    const item = new UpstreamIndicatorNode(upstreams, {}, context, { complete: true }).getTreeItem();

    assert.ok(item.tooltip.includes("Mirror 0 (Origin unavailable)"));
    assert.ok(item.tooltip.includes("Mirror 1 (Origin unavailable)"));
    assert.ok(item.tooltip.includes("Showing 20 of 21 loaded upstreams."));
    assert.ok(!item.tooltip.includes("not a URL"));
    assert.ok(!item.tooltip.includes("Mirror 20"));
  });

  test("entitlement summaries distinguish authoritative totals from partial collections", () => {
    const partial = new EntitlementSummaryNode(
      [{ name: "CI", slug_perm: "ci", is_active: true }],
      context,
      { complete: false, totalCount: 51, failureCount: 1, termination: "request_failed" }
    );
    assert.strictEqual(
      partial.getTreeItem().label,
      "Entitlement tokens: 1 active among 1 loaded (partial)"
    );
    assert.ok(partial.getTreeItem().tooltip.includes("1 of 51"));
    assert.strictEqual(partial.getChildren()[0].getTreeItem().label, "Entitlement list is incomplete");

    const complete = new EntitlementSummaryNode([
      { name: "CI", slug_perm: "ci", is_active: true },
      { name: "Legacy", slug_perm: "legacy", is_active: false },
    ], context, { complete: true, totalCount: 2 });
    assert.strictEqual(complete.getTreeItem().label, "Entitlement tokens: 1 active of 2");
  });
});

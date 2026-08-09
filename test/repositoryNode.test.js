const assert = require("assert");
const vscode = require("vscode");
const UpstreamIndicatorNode = require("../models/upstreamIndicatorNode");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { SUPPORTED_UPSTREAM_FORMATS } = require("../util/upstreamFormats");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");

suite("RepositoryNode Test Suite", () => {
  const repositoryNodePath = require.resolve("../models/repositoryNode");
  const upstreamCheckerPath = require.resolve("../util/upstreamChecker");
  let originalGetConfiguration;
  let RepositoryNode;
  let upstreamChecker;
  let originalGetAllUpstreamData;
  let originalGetUpstreamDataForFormats;
  let originalApiGet;
  const terraformExporterPath = require.resolve("../util/terraformExporter");

  const context = {
    globalState: {
      get() {
        return undefined;
      },
      async update() {},
    },
  };

  setup(() => {
    originalGetConfiguration = vscode.workspace.getConfiguration;
    delete require.cache[terraformExporterPath];
    delete require.cache[repositoryNodePath];
    delete require.cache[upstreamCheckerPath];
    upstreamChecker = require(upstreamCheckerPath);
    RepositoryNode = require(repositoryNodePath);
    originalGetAllUpstreamData = upstreamChecker.getAllUpstreamData;
    originalGetUpstreamDataForFormats = upstreamChecker.getUpstreamDataForFormats;
    originalApiGet = CloudsmithAPI.prototype.get;

    vscode.workspace.getConfiguration = () => ({
      get(key) {
        if (key === "showEntitlements") {
          return false;
        }
        return false;
      },
    });
  });

  teardown(() => {
    vscode.workspace.getConfiguration = originalGetConfiguration;
    upstreamChecker.getAllUpstreamData = originalGetAllUpstreamData;
    upstreamChecker.getUpstreamDataForFormats = originalGetUpstreamDataForFormats;
    CloudsmithAPI.prototype.get = originalApiGet;
    delete require.cache[terraformExporterPath];
    delete require.cache[repositoryNodePath];
    delete require.cache[upstreamCheckerPath];
  });

  test("reconciles partial inferred-format results with the full repo upstream totals", async () => {
    let allFormatCalls = 0;
    const targetedCalls = [];
    const partialUpstreams = [
      { name: "Docker Hub", _format: "docker", upstream_url: "https://index.docker.io/", is_active: true },
      { name: "PyPI", _format: "python", upstream_url: "https://pypi.org/", is_active: true },
      { name: "RubyGems", _format: "ruby", upstream_url: "https://rubygems.org/", is_active: false },
    ];
    const fullUpstreams = [
      ...partialUpstreams,
      { name: "Maven Central", _format: "maven", upstream_url: "https://repo.maven.apache.org/", is_active: true },
      { name: "NuGet", _format: "nuget", upstream_url: "https://api.nuget.org/", is_active: true },
      { name: "npmjs", _format: "npm", upstream_url: "https://registry.npmjs.org/", is_active: true },
    ];

    upstreamChecker.getAllUpstreamData = async () => {
      allFormatCalls += 1;
      return {
        upstreams: fullUpstreams,
        active: 5,
        total: 6,
        failedFormats: [],
        successfulFormats: 6,
      };
    };
    upstreamChecker.getUpstreamDataForFormats = async (_context, workspace, repo, formats) => {
      targetedCalls.push({ workspace, repo, formats });
      return {
        upstreams: partialUpstreams,
        active: 2,
        total: 3,
        failedFormats: [],
        successfulFormats: 2,
      };
    };

    const repositoryNode = new RepositoryNode(
      { slug: "example-repo", slug_perm: "example-repo", name: "Example Repo" },
      "acme",
      context
    );

    repositoryNode.getPackages = async () => [
      { format: "python" },
      { format: "python" },
      { formats: ["docker", "unknown"] },
    ];

    const children = await repositoryNode.getChildren();

    assert.strictEqual(allFormatCalls, 1);
    assert.strictEqual(targetedCalls.length, 1);
    assert.deepStrictEqual(targetedCalls[0].formats, ["docker", "python"]);
    assert.ok(children[0] instanceof UpstreamIndicatorNode);
    assert.strictEqual(children[0].upstreams.length, 6);
    assert.strictEqual(children[0].getTreeItem().label, "Upstreams: 5 active of 6 configured");

    const { fetchRepositoryUpstreams } = require(terraformExporterPath);
    const exportResult = await fetchRepositoryUpstreams(context, "acme", "example-repo");
    assert.strictEqual(exportResult.active, 5);
    assert.strictEqual(exportResult.total, 6);
    assert.strictEqual(children[0].upstreams.length, exportResult.data.length);
  });

  test("falls back to the all-format fetch when no inferred formats are available", async () => {
    let allFormatCalls = 0;
    let targetedCalls = 0;

    upstreamChecker.getAllUpstreamData = async () => {
      allFormatCalls += 1;
      return {
        upstreams: [{ name: "Docker Hub", _format: "docker", upstream_url: "https://index.docker.io/" }],
      };
    };
    upstreamChecker.getUpstreamDataForFormats = async () => {
      targetedCalls += 1;
      return { upstreams: [] };
    };

    const repositoryNode = new RepositoryNode(
      { slug: "grouped-repo", slug_perm: "grouped-repo", name: "Grouped Repo" },
      "acme",
      context
    );

    const upstreams = await repositoryNode.getUpstreams([{ name: "package-group-without-format" }]);

    assert.strictEqual(targetedCalls, 0);
    assert.strictEqual(allFormatCalls, 1);
    assert.strictEqual(upstreams.length, 1);
    assert.strictEqual(upstreams[0].name, "Docker Hub");
  });

  test("keeps the inferred-format fast path when every supported upstream format is covered", async () => {
    let allFormatCalls = 0;
    const targetedCalls = [];

    upstreamChecker.getAllUpstreamData = async () => {
      allFormatCalls += 1;
      return { upstreams: [] };
    };
    upstreamChecker.getUpstreamDataForFormats = async (_context, workspace, repo, formats) => {
      targetedCalls.push({ workspace, repo, formats });
      return {
        upstreams: [{ name: "PyPI", _format: "python", upstream_url: "https://pypi.org/" }],
      };
    };

    const repositoryNode = new RepositoryNode(
      { slug: "complete-repo", slug_perm: "complete-repo", name: "Complete Repo" },
      "acme",
      context
    );

    const upstreams = await repositoryNode.getUpstreams([{ formats: SUPPORTED_UPSTREAM_FORMATS }]);

    assert.strictEqual(allFormatCalls, 0);
    assert.strictEqual(targetedCalls.length, 1);
    assert.deepStrictEqual(targetedCalls[0].formats, SUPPORTED_UPSTREAM_FORMATS);
    assert.strictEqual(upstreams.length, 1);
  });

  test("adds the inline upstream indicator when upstreams are present", async () => {
    const repositoryNode = new RepositoryNode(
      { slug: "indicator-repo", slug_perm: "indicator-repo", name: "Indicator Repo" },
      "acme",
      context
    );

    repositoryNode.getPackages = async () => [{ format: "python" }];
    repositoryNode.getUpstreams = async () => [
      { name: "PyPI", upstream_url: "https://pypi.org/", is_active: true },
    ];

    const children = await repositoryNode.getChildren();

    assert.ok(children[0] instanceof UpstreamIndicatorNode);
    assert.strictEqual(children[0].getTreeItem().label, "Upstreams: 1 active of 1 configured");
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
    ]);

    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" },
      "acme",
      context
    );

    const packages = await repositoryNode.getPackages();

    assert.strictEqual(packages.length, 2);
    for (const packageNode of packages) {
      const children = packageNode.getChildren();
      assert.strictEqual(
        children.some(child => child.getTreeItem().contextValue === "vulnerabilitySummary"),
        false,
        `${packageNode.format} package exposed a false vulnerability summary`
      );
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
      context
    );

    const packages = await repositoryNode.getPackages();

    assert.deepStrictEqual(packages, []);
    assert.strictEqual(repositoryNode._lastApiFailed, true);
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
        assert.strictEqual(options.validate([{ name: "token", is_active: false }]), true);
      }
      return apiFailure("invalid_response", { status: 200 });
    };
    const repositoryNode = new RepositoryNode(
      { slug: "packages", slug_perm: "packages", name: "Packages" },
      "acme",
      context
    );

    assert.deepStrictEqual(await repositoryNode.getPackages(), []);
    await assert.rejects(
      () => repositoryNode.getEntitlements(),
      error => error && error.kind === "invalid_response"
    );
  });
});

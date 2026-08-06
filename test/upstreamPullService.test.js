const assert = require("assert");
const {
  buildRegistryTriggerPlan,
} = require("../util/registryEndpoints");
const {
  UpstreamPullService,
} = require("../util/upstreamPullService");

function createResponse(status, body, headers = {}) {
  return {
    status,
    headers: {
      get(name) {
        const lowerName = String(name || "").toLowerCase();
        return headers[lowerName] || headers[name] || null;
      },
    },
    async text() {
      return body;
    },
  };
}

suite("UpstreamPullService", () => {
  test("builds canonical registry trigger URLs for supported formats", () => {
    const mavenPlan = buildRegistryTriggerPlan("workspace", "repo", {
      name: "com.example:demo-app",
      version: "1.2.3",
      format: "maven",
    });
    assert.strictEqual(
      mavenPlan.request.url,
      "https://dl.cloudsmith.io/basic/workspace/repo/maven/com/example/demo-app/1.2.3/demo-app-1.2.3.pom"
    );

    const npmPlan = buildRegistryTriggerPlan("workspace", "repo", {
      name: "@scope/widget",
      version: "4.5.6",
      format: "npm",
    });
    assert.strictEqual(
      npmPlan.request.url,
      "https://npm.cloudsmith.io/workspace/repo/%40scope/widget/-/widget-4.5.6.tgz"
    );

    const goPlan = buildRegistryTriggerPlan("workspace", "repo", {
      name: "github.com/MyOrg/MyModule",
      version: "v1.0.0",
      format: "go",
    });
    assert.strictEqual(
      goPlan.request.url,
      "https://golang.cloudsmith.io/workspace/repo/github.com/!my!org/!my!module/@v/v1.0.0.info"
    );

    const cargoPlan = buildRegistryTriggerPlan("workspace", "repo", {
      name: "serde",
      version: "1.0.0",
      format: "cargo",
    });
    assert.strictEqual(
      cargoPlan.request.url,
      "https://cargo.cloudsmith.io/workspace/repo/se/rd/serde"
    );
  });

  test("prepare builds a mixed-ecosystem confirmation with skipped formats", async () => {
    const warnings = [];
    const service = new UpstreamPullService({}, {
      fetchRepositories: async () => [{ slug: "repo", name: "Repo" }],
      upstreamChecker: {
        async getRepositoryUpstreamState() {
          return {
            groupedUpstreams: new Map([
              ["maven", [{ name: "Maven Central", is_active: true }]],
            ]),
          };
        },
      },
      showQuickPick: async (items) => items[0],
      showWarningMessage: async (message, _options, action) => {
        warnings.push(message);
        return action;
      },
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
    });

    const prepared = await service.prepare({
      workspace: "workspace",
      repositoryHint: "repo",
      dependencies: [
        {
          name: "com.example:demo-app",
          version: "1.2.3",
          format: "maven",
          cloudsmithStatus: "NOT_FOUND",
        },
        {
          name: "requests",
          version: "2.31.0",
          format: "python",
          cloudsmithStatus: "NOT_FOUND",
        },
      ],
    });

    assert.ok(prepared);
    assert.strictEqual(prepared.plan.pullableDependencies.length, 1);
    assert.strictEqual(prepared.plan.skippedDependencies.length, 1);
    assert.strictEqual(warnings.length, 1);
    assert.match(warnings[0], /Pull 1 of 2 dependencies through repo\?/);
    assert.match(warnings[0], /1 Maven will be pulled\./);
    assert.match(
      warnings[0],
      /1 Python will be skipped \(no matching upstream is configured on this repository\)\./
    );
  });

  test("pulls Python dependencies via same-host redirects using manual auth-preserving requests", async () => {
    const calls = [];
    const initialIndexUrl = "https://dl.cloudsmith.io/basic/workspace/repo/python/simple/requests/";
    const redirectedIndexUrl = "https://dl.cloudsmith.io/basic/workspace/repo/python/simple/requests/index.html";
    const artifactUrl = "https://dl.cloudsmith.io/basic/workspace/repo/python/packages/requests-2.31.0-py3-none-any.whl";
    const authorizationHeader = `Basic ${Buffer.from("token:api-key").toString("base64")}`;
    const service = new UpstreamPullService({}, {
      credentialManager: {
        async getApiKey() {
          return "api-key";
        },
      },
      fetchImpl: async (url, options) => {
        calls.push({ url, options });
        if (url === initialIndexUrl) {
          return createResponse(302, "", {
            location: redirectedIndexUrl,
          });
        }
        if (url === redirectedIndexUrl) {
          return createResponse(200, '<a href="../../packages/requests-2.31.0-py3-none-any.whl">requests</a>');
        }
        if (url === artifactUrl) {
          return createResponse(200, "");
        }
        throw new Error(`Unexpected URL: ${url}`);
      },
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
      showWarningMessage: async () => {},
    });

    const result = await service.execute({
      workspace: "workspace",
      repository: { slug: "repo" },
      plan: {
        pullableDependencies: [{
          name: "requests",
          version: "2.31.0",
          format: "python",
          cloudsmithStatus: "NOT_FOUND",
        }],
        skippedDependencies: [],
      },
    });

    assert.strictEqual(result.canceled, false);
    assert.strictEqual(result.pullResult.cached, 1);
    assert.strictEqual(calls.length, 3);
    assert.deepStrictEqual(
      calls.map((call) => call.url),
      [initialIndexUrl, redirectedIndexUrl, artifactUrl]
    );
    assert.strictEqual(calls.every((call) => call.options.redirect === "manual"), true);
    assert.strictEqual(
      calls.every((call) => call.options.headers.Authorization === authorizationHeader),
      true
    );
  });

  test("rejects redirects to untrusted hosts before forwarding credentials", async () => {
    const calls = [];
    const service = new UpstreamPullService({}, {
      credentialManager: {
        async getApiKey() {
          return "api-key";
        },
      },
      fetchImpl: async (url, options) => {
        calls.push({ url, options });
        return createResponse(302, "", {
          location: "https://example.com/requests-2.31.0.whl",
        });
      },
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
      showWarningMessage: async () => {},
    });

    const result = await service.execute({
      workspace: "workspace",
      repository: { slug: "repo" },
      plan: {
        pullableDependencies: [{
          name: "requests",
          version: "2.31.0",
          format: "python",
          cloudsmithStatus: "NOT_FOUND",
        }],
        skippedDependencies: [],
      },
    });

    assert.strictEqual(result.canceled, false);
    assert.strictEqual(result.pullResult.cached, 0);
    assert.strictEqual(result.pullResult.errors, 1);
    assert.strictEqual(calls.length, 1);
    assert.match(result.pullResult.details[0].errorMessage, /redirect target was rejected/i);
  });

  test("stops after three authentication failures before expanding concurrency", async () => {
    const calls = [];
    const errors = [];
    const service = new UpstreamPullService({}, {
      credentialManager: {
        async getApiKey() {
          return "api-key";
        },
      },
      fetchImpl: async (url) => {
        calls.push(url);
        return createResponse(401, "");
      },
      showErrorMessage: async (message) => {
        errors.push(message);
      },
      showInformationMessage: async () => {},
      showWarningMessage: async () => {},
    });

    const dependencies = Array.from({ length: 5 }, (_, index) => ({
      name: `package-${index}`,
      version: "1.0.0",
      format: "npm",
      cloudsmithStatus: "NOT_FOUND",
    }));

    const result = await service.execute({
      workspace: "workspace",
      repository: { slug: "repo" },
      plan: {
        pullableDependencies: dependencies,
        skippedDependencies: [],
      },
    });

    assert.strictEqual(calls.length, 3);
    assert.strictEqual(result.pullResult.errors, 5);
    assert.strictEqual(result.pullResult.authFailed, 5);
    assert.deepStrictEqual(errors, [
      "Authentication failed. Check your API key in Cloudsmith settings.",
    ]);
  });

  test("prepareSingle only offers repositories with a matching upstream", async () => {
    const quickPickCalls = [];
    let warningCalls = 0;
    const service = new UpstreamPullService({}, {
      fetchRepositories: async () => [
        { slug: "repo-a", name: "Repo A" },
        { slug: "repo-b", name: "Repo B" },
      ],
      upstreamChecker: {
        async getRepositoryUpstreamState(_workspace, repo) {
          return {
            groupedUpstreams: new Map([
              ["python", repo === "repo-b" ? [{ name: "PyPI", is_active: true }] : []],
            ]),
          };
        },
      },
      showQuickPick: async (items) => {
        quickPickCalls.push(items);
        return items[0];
      },
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
      showWarningMessage: async () => {
        warningCalls += 1;
      },
    });

    const prepared = await service.prepareSingle({
      workspace: "workspace",
      repositoryHint: "repo-b",
      dependency: {
        name: "requests",
        version: "2.31.0",
        format: "python",
        cloudsmithStatus: "NOT_FOUND",
      },
    });

    assert.ok(prepared);
    assert.strictEqual(prepared.repository.slug, "repo-b");
    assert.strictEqual(prepared.plan.pullableDependencies.length, 1);
    assert.strictEqual(quickPickCalls.length, 1);
    assert.strictEqual(quickPickCalls[0].length, 1);
    assert.strictEqual(quickPickCalls[0][0].label, "repo-b");
    assert.match(quickPickCalls[0][0].detail, /Python upstream \(PyPI\)/);
    assert.strictEqual(warningCalls, 0);
  });
});

const assert = require("assert");
const {
  buildRegistryTriggerPlan,
  findPythonDistributionUrl,
} = require("../util/registryEndpoints");
const {
  UpstreamPullService,
} = require("../util/upstreamPullService");

function createResponse(status, body, headers = {}) {
  return new Response(body, { status, headers });
}

function deferred() {
  let resolve;
  const promise = new Promise(resolvePromise => { resolve = resolvePromise; });
  return { promise, resolve };
}

function cancellationToken() {
  const listeners = new Set();
  return {
    isCancellationRequested: false,
    cancel() {
      this.isCancellationRequested = true;
      for (const listener of listeners) listener();
    },
    onCancellationRequested(listener) {
      listeners.add(listener);
      return { dispose() { listeners.delete(listener); } };
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

  test("rejects registry path traversal and query injection across ecosystems", () => {
    const hostileDependencies = [
      { format: "docker", name: "../../other/image", version: "1.0.0" },
      { format: "npm", name: "..", version: "1.0.0" },
      { format: "cargo", name: "..", version: "1.0.0" },
      { format: "swift", name: "../secret", version: "1.0.0" },
      { format: "go", name: "../../other/repo/pkg?admin=true", version: "v1.0.0" },
      { format: "composer", name: "../secret", version: "1.0.0" },
      { format: "maven", name: "com.example:..", version: "1.0.0" },
      { format: "ruby", name: "bad\\name", version: "1.0.0" },
      { format: "nuget", name: "bad\nname", version: "1.0.0" },
      { format: "python", name: "requests", version: "../other" },
      { format: "npm", name: "%ZZ", version: "1.0.0" },
      { format: "python", name: "a/b", version: "1.0.0" },
      { format: "cargo", name: "a/b", version: "1.0.0" },
      { format: "maven", name: "a.b:foo/bar", version: "1.0.0" },
    ];

    for (const dependency of hostileDependencies) {
      assert.strictEqual(
        buildRegistryTriggerPlan("workspace", "repo", dependency),
        null,
        `${dependency.format}:${dependency.name}`
      );
    }
    assert.strictEqual(
      buildRegistryTriggerPlan("..", "repo", { format: "npm", name: "safe", version: "1.0.0" }),
      null
    );
    assert.strictEqual(
      buildRegistryTriggerPlan("workspace", "repo?admin=true", { format: "npm", name: "safe", version: "1.0.0" }),
      null
    );
  });

  test("Python artifact discovery stays bounded on repeated incomplete anchors", () => {
    const hostileHtml = "<a ".repeat(150000);
    const startedAt = Date.now();
    const result = findPythonDistributionUrl(
      hostileHtml,
      "1.0.0",
      "https://dl.cloudsmith.io/basic/workspace/repo/python/simple/artifact/"
    );
    const elapsed = Date.now() - startedAt;

    assert.strictEqual(result, null);
    assert.ok(elapsed < 1000, `hostile anchor scan took ${elapsed}ms`);
  });

  test("prepare builds a mixed-ecosystem confirmation with skipped formats", async () => {
    const warnings = [];
    const service = new UpstreamPullService({}, {
      fetchRepositories: async () => ({
        items: [{ slug: "repo", name: "Repo" }],
        complete: true,
      }),
      upstreamChecker: {
        async getRepositoryUpstreamState() {
          return {
            groupedUpstreams: new Map([
              ["maven", [{ name: "Maven Central", is_active: true }]],
            ]),
            complete: true,
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

  test("prepare preserves exact versions that differ only by prerelease identifier case", async () => {
    const service = new UpstreamPullService({}, {
      fetchRepositories: async () => ({
        items: [{ slug: "repo", name: "Repo" }],
        complete: true,
      }),
      upstreamChecker: {
        async getRepositoryUpstreamState() {
          return {
            groupedUpstreams: new Map([
              ["npm", [{ name: "npm", is_active: true }]],
            ]),
            complete: true,
          };
        },
      },
      showQuickPick: async (items) => items[0],
      showWarningMessage: async (_message, _options, action) => action,
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
    });

    const prepared = await service.prepare({
      workspace: "workspace",
      repositoryHint: "repo",
      dependencies: [
        {
          name: "shared-package",
          version: "1.0.0-alpha",
          format: "npm",
          cloudsmithStatus: "ABSENT",
        },
        {
          name: "shared-package",
          version: "1.0.0-ALPHA",
          format: "npm",
          cloudsmithStatus: "ABSENT",
        },
      ],
    });

    assert.ok(prepared);
    assert.deepStrictEqual(
      prepared.plan.pullableDependencies.map((dependency) => dependency.version),
      ["1.0.0-alpha", "1.0.0-ALPHA"]
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

  test("registry requests ignore caller authorization overrides and drain artifact bodies", async () => {
    let capturedRequest;
    let bodyCanceled = false;
    let textRead = false;
    let bodyReads = 0;
    const service = new UpstreamPullService({}, {
      fetchImpl: async (_url, options) => {
        capturedRequest = options;
        return {
          status: 200,
          headers: { get() { return null; } },
          body: {
            getReader() {
              return {
                async read() {
                  bodyReads += 1;
                  return bodyReads === 1
                    ? { done: false, value: new Uint8Array([1, 2, 3]) }
                    : { done: true, value: undefined };
                },
                async cancel() { bodyCanceled = true; },
                releaseLock() {},
              };
            },
          },
          async text() { textRead = true; return "large artifact"; },
        };
      },
    });

    const result = await service._requestRegistry({
      method: "GET",
      url: "https://dl.cloudsmith.io/basic/workspace/repo/raw/file.bin",
      headers: { Authorization: "Bearer hostile", Accept: "application/octet-stream" },
    }, "api-key", null, { captureBody: false });

    assert.strictEqual(result.statusCode, 200);
    assert.strictEqual(
      capturedRequest.headers.Authorization,
      `Basic ${Buffer.from("token:api-key").toString("base64")}`
    );
    assert.strictEqual(capturedRequest.headers.Accept, "application/octet-stream");
    assert.strictEqual(bodyReads, 2);
    assert.strictEqual(bodyCanceled, false);
    assert.strictEqual(textRead, false);
  });

  test("registry metadata bodies are bounded before retention", async () => {
    let bodyCanceled = false;
    const service = new UpstreamPullService({}, {
      fetchImpl: async () => ({
        status: 200,
        headers: {
          get(name) {
            return String(name).toLowerCase() === "content-length"
              ? String(2 * 1024 * 1024)
              : null;
          },
        },
        body: { async cancel() { bodyCanceled = true; } },
      }),
    });

    const result = await service._requestRegistry({
      method: "GET",
      url: "https://dl.cloudsmith.io/basic/workspace/repo/python/simple/artifact/",
      headers: {},
    }, "api-key", null, { captureBody: true });

    assert.strictEqual(result.statusCode, 0);
    assert.match(result.errorMessage, /size limit/i);
    assert.strictEqual(bodyCanceled, true);
  });

  test("registry readers reject non-streaming bodies and unknown-length oversized chunks", async () => {
    let fallbackTextRead = false;
    let fallbackCanceled = false;
    const fallbackService = new UpstreamPullService({}, {
      fetchImpl: async () => ({
        status: 200,
        headers: { get() { return null; } },
        body: { async cancel() { fallbackCanceled = true; } },
        async text() { fallbackTextRead = true; return "unbounded"; },
      }),
    });
    const fallback = await fallbackService._requestRegistry({
      method: "GET",
      url: "https://dl.cloudsmith.io/basic/workspace/repo/python/simple/artifact/",
      headers: {},
    }, "api-key", null, { captureBody: true });
    assert.strictEqual(fallback.statusCode, 0);
    assert.strictEqual(fallbackTextRead, false);
    assert.strictEqual(fallbackCanceled, true);

    let oversizedCanceled = false;
    let reads = 0;
    const oversizedService = new UpstreamPullService({}, {
      fetchImpl: async () => ({
        status: 200,
        headers: { get() { return null; } },
        body: {
          getReader() {
            return {
              async read() {
                reads += 1;
                return { done: false, value: new Uint8Array((1024 * 1024) + 1) };
              },
              async cancel() { oversizedCanceled = true; },
              releaseLock() {},
            };
          },
        },
      }),
    });
    const oversized = await oversizedService._requestRegistry({
      method: "GET",
      url: "https://dl.cloudsmith.io/basic/workspace/repo/python/simple/artifact/",
      headers: {},
    }, "api-key", null, { captureBody: true });
    assert.strictEqual(oversized.statusCode, 0);
    assert.strictEqual(reads, 1);
    assert.strictEqual(oversizedCanceled, true);
  });

  test("registry timeout settles ignored fetch and body reads without awaiting cancellation", async () => {
    let timeoutCallback;
    let lateResolve;
    let lateCancelCalled = false;
    const lateService = new UpstreamPullService({}, {
      fetchImpl: async () => new Promise(resolve => { lateResolve = resolve; }),
      setTimeout(callback) { timeoutCallback = callback; return {}; },
      clearTimeout() {},
    });
    const latePending = lateService._requestRegistry({
      method: "GET",
      url: "https://dl.cloudsmith.io/basic/workspace/repo/raw/file.bin",
      headers: {},
    }, "api-key", null, { captureBody: false });
    await new Promise(resolve => setImmediate(resolve));
    timeoutCallback();
    const lateResult = await latePending;
    assert.strictEqual(lateResult.statusCode, 0);
    assert.match(lateResult.errorMessage, /timed out/i);
    lateResolve({
      status: 200,
      headers: { get() { return null; } },
      body: { cancel() { lateCancelCalled = true; return new Promise(() => {}); } },
    });
    await new Promise(resolve => setImmediate(resolve));
    assert.strictEqual(lateCancelCalled, true);

    let bodyTimeoutCallback;
    let readerCancelCalled = false;
    const bodyService = new UpstreamPullService({}, {
      fetchImpl: async () => ({
        status: 200,
        headers: { get() { return null; } },
        body: {
          getReader() {
            return {
              read() { return new Promise(() => {}); },
              cancel() { readerCancelCalled = true; return new Promise(() => {}); },
              releaseLock() {},
            };
          },
        },
      }),
      setTimeout(callback) { bodyTimeoutCallback = callback; return {}; },
      clearTimeout() {},
    });
    const bodyPending = bodyService._requestRegistry({
      method: "GET",
      url: "https://dl.cloudsmith.io/basic/workspace/repo/raw/file.bin",
      headers: {},
    }, "api-key", null, { captureBody: false });
    await new Promise(resolve => setImmediate(resolve));
    bodyTimeoutCallback();
    const bodyResult = await bodyPending;
    assert.strictEqual(bodyResult.statusCode, 0);
    assert.match(bodyResult.errorMessage, /timed out/i);
    assert.strictEqual(readerCancelCalled, true);
  });

  test("registry redirects cannot move credentials between allowed Cloudsmith hosts", async () => {
    let calls = 0;
    const service = new UpstreamPullService({}, {
      fetchImpl: async () => {
        calls += 1;
        return createResponse(302, "", {
          location: "https://npm.cloudsmith.io/workspace/repo/package.tgz",
        });
      },
    });

    const result = await service._requestRegistry({
      method: "GET",
      url: "https://dl.cloudsmith.io/basic/workspace/repo/python/simple/artifact/",
      headers: {},
    }, "api-key", null, { captureBody: true });

    assert.strictEqual(result.statusCode, 0);
    assert.match(result.errorMessage, /redirect target was rejected/i);
    assert.strictEqual(calls, 1);
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

  test("contains throwing status observers and drains every launched pull before returning", async () => {
    const gate = deferred();
    const threeStarted = deferred();
    let calls = 0;
    const service = new UpstreamPullService({}, {
      credentialManager: { async getApiKey() { return "api-key"; } },
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
      showWarningMessage: async () => {},
    });
    service._pullDependency = async (_workspace, _repo, dependency) => {
      calls += 1;
      if (calls === 3) threeStarted.resolve();
      if (dependency.name === "package-0") {
        throw new Error("worker failed");
      }
      await gate.promise;
      return {
        dependency,
        status: "cached",
        errorMessage: null,
        requestUrl: "https://npm.cloudsmith.io/workspace/repo/package",
        networkError: false,
      };
    };

    const dependencies = Array.from({ length: 8 }, (_, index) => ({
      name: `package-${index}`,
      version: "1.0.0",
      format: "npm",
      cloudsmithStatus: "NOT_FOUND",
    }));
    let returned = false;
    const pending = service.execute({
      workspace: "workspace",
      repository: { slug: "repo" },
      plan: { pullableDependencies: dependencies, skippedDependencies: [] },
    }, {
      onStatus() { throw new Error("observer failed"); },
      progress: { report() { throw new Error("progress observer failed"); } },
    }).then((value) => {
      returned = true;
      return value;
    });

    await threeStarted.promise;
    assert.strictEqual(returned, false);
    gate.resolve();
    const result = await pending;

    assert.strictEqual(calls, dependencies.length);
    assert.strictEqual(result.pullResult.details.length, dependencies.length);
    assert.strictEqual(result.pullResult.cached, dependencies.length - 1);
    assert.strictEqual(result.pullResult.errors, 1);
  });

  test("does not dispatch after the prepared account changes while loading credentials", async () => {
    let accountState = {
      activationId: "account-a",
      accountEpoch: 1,
      sessionConnected: true,
    };
    const apiKey = deferred();
    let pulls = 0;
    const service = new UpstreamPullService({}, {
      connectionManager: { getState() { return { ...accountState }; } },
      credentialManager: { async getApiKey() { return apiKey.promise; } },
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
      showWarningMessage: async () => {},
    });
    service._pullDependency = async () => {
      pulls += 1;
      throw new Error("must not dispatch");
    };

    const pending = service.execute({
      workspace: "workspace",
      repository: { slug: "repo" },
      account: { activationId: "account-a", accountEpoch: 1 },
      plan: {
        pullableDependencies: [{
          name: "package-a",
          version: "1.0.0",
          format: "npm",
          cloudsmithStatus: "NOT_FOUND",
        }],
        skippedDependencies: [],
      },
    });
    accountState = { ...accountState, activationId: "account-b", accountEpoch: 2 };
    apiKey.resolve("api-key");

    assert.deepStrictEqual(await pending, { canceled: true, stale: true });
    assert.strictEqual(pulls, 0);
  });

  test("does not issue an artifact request after the prepared account changes", async () => {
    let accountState = {
      activationId: "account-a",
      accountEpoch: 1,
      sessionConnected: true,
    };
    const calls = [];
    const service = new UpstreamPullService({}, {
      connectionManager: { getState() { return { ...accountState }; } },
      credentialManager: { async getApiKey() { return "api-key"; } },
      fetchImpl: async (url) => {
        calls.push(url);
        accountState = { ...accountState, activationId: "account-b", accountEpoch: 2 };
        return createResponse(
          200,
          '<a href="../../packages/requests-2.31.0-py3-none-any.whl">requests</a>'
        );
      },
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
      showWarningMessage: async () => {},
    });

    const result = await service.execute({
      workspace: "workspace",
      repository: { slug: "repo" },
      account: { activationId: "account-a", accountEpoch: 1 },
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

    assert.deepStrictEqual(result, { canceled: true, stale: true });
    assert.strictEqual(calls.length, 1);
  });

  test("prepareSingle only offers repositories with a matching upstream", async () => {
    const quickPickCalls = [];
    let warningCalls = 0;
    const service = new UpstreamPullService({}, {
      fetchRepositories: async () => ({
        items: [
          { slug: "repo-a", name: "Repo A" },
          { slug: "repo-b", name: "Repo B" },
        ],
        complete: true,
      }),
      upstreamChecker: {
        async getRepositoryUpstreamState(_workspace, repo) {
          return {
            groupedUpstreams: new Map([
              ["python", repo === "repo-b" ? [{ name: "PyPI", is_active: true }] : []],
            ]),
            complete: true,
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

  test("preparation reports a fixed repository error without exposing thrown detail", async () => {
    const errors = [];
    const service = new UpstreamPullService({}, {
      fetchRepositories: async () => {
        throw new Error("secret-token-and-internal-host");
      },
      showErrorMessage: async (message) => { errors.push(message); },
      showInformationMessage: async () => {},
      showWarningMessage: async () => {},
    });

    const prepared = await service.prepareSingle({
      workspace: "workspace",
      dependency: {
        name: "requests",
        version: "2.31.0",
        format: "python",
        cloudsmithStatus: "NOT_FOUND",
      },
    });

    assert.strictEqual(prepared, null);
    assert.deepStrictEqual(errors, ["Could not fetch workspace repositories."]);
    assert.doesNotMatch(errors[0], /secret|internal-host/i);
  });

  test("prepareSingle cancellation stops repository inspection from scheduling more work", async () => {
    const token = cancellationToken();
    const gate = deferred();
    let inspectionCalls = 0;
    let quickPickCalls = 0;
    const service = new UpstreamPullService({}, {
      fetchRepositories: async (_workspace, operation) => {
        assert.strictEqual(operation.cancellationToken, token);
        return {
          items: Array.from({ length: 1000 }, (_value, index) => ({ slug: `repo-${index}` })),
          complete: true,
        };
      },
      upstreamChecker: {
        async getRepositoryUpstreamStateForFormats(_workspace, _repo, _formats, options) {
          inspectionCalls += 1;
          assert.strictEqual(options.cancellationToken, token);
          await gate.promise;
          return {
            groupedUpstreams: new Map(),
            complete: false,
            failedFormats: [],
            uninspectedFormats: ["python"],
          };
        },
      },
      showQuickPick: async () => { quickPickCalls += 1; return null; },
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
      showWarningMessage: async () => {},
    });

    const pending = service.prepareSingle({
      workspace: "workspace",
      dependency: {
        name: "requests",
        version: "2.31.0",
        format: "python",
        cloudsmithStatus: "NOT_FOUND",
      },
      cancellationToken: token,
    });
    await new Promise(resolve => setImmediate(resolve));
    assert.strictEqual(inspectionCalls, 4);
    token.cancel();
    gate.resolve();

    assert.strictEqual(await pending, null);
    assert.strictEqual(inspectionCalls, 4);
    assert.strictEqual(quickPickCalls, 0);
  });

  test("prepareSingle discards repository results completed by a superseded account", async () => {
    let state = {
      activationId: "account-a",
      accountEpoch: 1,
      sessionConnected: true,
    };
    const repositories = deferred();
    let inspectionCalls = 0;
    const service = new UpstreamPullService({}, {
      connectionManager: { getState() { return { ...state }; } },
      fetchRepositories: async (_workspace, operation) => {
        assert.deepStrictEqual(operation.account, {
          activationId: "account-a",
          accountEpoch: 1,
        });
        return repositories.promise;
      },
      upstreamChecker: {
        async getRepositoryUpstreamStateForFormats() {
          inspectionCalls += 1;
          return { groupedUpstreams: new Map(), complete: true };
        },
      },
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
      showWarningMessage: async () => {},
    });

    const pending = service.prepareSingle({
      workspace: "workspace",
      dependency: {
        name: "requests",
        version: "2.31.0",
        format: "python",
        cloudsmithStatus: "NOT_FOUND",
      },
    });
    state = { ...state, activationId: "account-b", accountEpoch: 2 };
    repositories.resolve({ items: [{ slug: "repo" }], complete: true });

    assert.strictEqual(await pending, null);
    assert.strictEqual(inspectionCalls, 0);
  });

  test("does not offer uncertain dependencies for upstream pull", async () => {
    const warnings = [];
    const service = new UpstreamPullService({}, {
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
      showWarningMessage: async (message) => warnings.push(message),
    });

    for (const cloudsmithStatus of ["UNRESOLVED", "LOOKUP_FAILED", "LOOKUP_INCOMPLETE", "RATE_LIMITED"]) {
      const prepared = await service.prepareSingle({
        workspace: "workspace",
        dependency: {
          name: "requests",
          version: "2.31.0",
          format: "python",
          cloudsmithStatus,
        },
      });
      assert.strictEqual(prepared, null);
    }

    assert.strictEqual(warnings.length, 4);
    assert.ok(warnings.every((message) => /absence was not conclusively established/.test(message)));
  });
});

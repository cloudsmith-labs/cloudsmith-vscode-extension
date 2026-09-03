const assert = require("assert");
const {
  buildRegistryTriggerPlan,
  findPythonDistributionUrl,
} = require("../util/registryEndpoints");
const {
  PULL_STATUS,
  UpstreamPullService: UpstreamPullServiceImplementation,
} = require("../util/upstreamPullService");
const { UpstreamChecker } = require("../util/upstreamChecker");
const { UpstreamOperationScheduler } = require("../util/upstreamOperationScheduler");
const { getDependencyArtifactKey } = require("../util/dependencyRecord");
const {
  createBulkScanAbsenceEvidence,
  getReusableBulkScanAbsenceProof,
} = require("../util/exactPackageEvidence");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");

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

function safeUpstream(format, name, overrides = {}) {
  return {
    name,
    format,
    _format: format,
    origin: `https://${format}.example`,
    ...overrides,
  };
}

function completeRepositoryState(entriesByFormat) {
  const groupedUpstreams = new Map(Object.entries(entriesByFormat));
  const formats = [...groupedUpstreams.keys()];
  return {
    groupedUpstreams,
    complete: true,
    failedFormats: [],
    uninspectedFormats: [],
    unsupportedFormats: [],
    outcomes: formats.map(format => ({
      format,
      apiFormat: format,
      state: "success",
      authoritative: true,
    })),
  };
}

suite("UpstreamPullService", () => {
  function apiKeyCapabilities() {
    return { pullThroughAvailable: true };
  }

  function createRuntime(reader = null) {
    const upstreamReader = reader || {
      async getRepositoryUpstreamStateForFormats() {
        return completeRepositoryState({});
      },
    };
    return {
      createOperationScope(options = {}) {
        const controller = new AbortController();
        const scheduler = options.scheduler || new UpstreamOperationScheduler();
        const cancellationDisposable = typeof options.cancellationToken?.onCancellationRequested
          === "function"
          ? options.cancellationToken.onCancellationRequested(() => controller.abort())
          : null;
        return Object.freeze({
          scheduler,
          signal: controller.signal,
          account: options.account,
          dispose() {
            controller.abort();
            scheduler.cancel();
            cancellationDisposable?.dispose?.();
          },
        });
      },
      getRepositoryUpstreamStateForFormats(workspace, repo, formats, options = {}) {
        return upstreamReader.getRepositoryUpstreamStateForFormats(
          workspace,
          repo,
          formats,
          {
            ...options,
            signal: options.operationScope.signal,
            scheduler: options.operationScope.scheduler,
          }
        );
      },
    };
  }

  class UpstreamPullService extends UpstreamPullServiceImplementation {
    constructor(context, options = {}) {
      const upstreamRuntime = options.upstreamRuntime
        && typeof options.upstreamRuntime.createOperationScope === "function"
        ? options.upstreamRuntime
        : createRuntime(options.upstreamRuntime);
      const checkPackageAbsence = options.checkPackageAbsence || (async ({
        workspace,
        repository,
      }) => ({
        workspace,
        repository,
        absent: true,
        present: false,
        complete: true,
        stale: false,
      }));
      const connectionManager = options.connectionManager || {
        getAuthenticationCapabilities() {
          return { pullThroughAvailable: true };
        },
      };
      super(context, {
        ...options,
        connectionManager,
        upstreamRuntime,
        checkPackageAbsence,
      });
    }
  }

  test("requires an injected safe upstream runtime facade", () => {
    assert.throws(
      () => new UpstreamPullServiceImplementation({}, {}),
      /safe upstream runtime facade/
    );
  });

  test("an SSO session is never sent to an upstream registry", async () => {
    let fetches = 0;
    let absenceChecks = 0;
    const errors = [];
    const service = new UpstreamPullService({}, {
      connectionManager: {
        getAuthenticationCapabilities() { return { pullThroughAvailable: false }; },
      },
      credentialManager: {
        async getApiKey() { return null; },
        getCredentialKind() { return "sso"; },
      },
      checkPackageAbsence: async () => {
        absenceChecks += 1;
        return { absent: true, present: false, complete: true, stale: false };
      },
      fetchImpl: async () => { fetches += 1; throw new Error("registry request must not run"); },
      showErrorMessage: async message => { errors.push(message); },
      showInformationMessage: async () => {},
      showWarningMessage: async () => {},
    });
    const result = await service.execute({
      workspace: "workspace",
      repository: { slug: "repository" },
      plan: {
        pullableDependencies: [{
          name: "dependency",
          version: "1.0.0",
          format: "npm",
          cloudsmithStatus: "NOT_FOUND",
        }],
        skippedDependencies: [],
      },
    });
    assert.strictEqual(result, null);
    assert.strictEqual(fetches, 0);
    assert.strictEqual(absenceChecks, 0);
    assert.deepStrictEqual(errors, [
      "Pull-through requires a Cloudsmith API key. Sign in with an API key to continue.",
    ]);
  });

  test("final API-key retrieval blocks registry dispatch when the capability disappears", async () => {
    let pullThroughAvailable = true;
    let absenceChecks = 0;
    let credentialCalls = 0;
    let registryDispatches = 0;
    const errors = [];
    const service = new UpstreamPullService({}, {
      connectionManager: {
        getAuthenticationCapabilities() { return { pullThroughAvailable }; },
      },
      credentialManager: {
        async getApiKey() {
          credentialCalls += 1;
          pullThroughAvailable = false;
          return null;
        },
      },
      checkPackageAbsence: async ({ workspace, repository }) => {
        absenceChecks += 1;
        return {
          workspace,
          repository,
          absent: true,
          present: false,
          complete: true,
          stale: false,
        };
      },
      showErrorMessage: async message => { errors.push(message); },
      showInformationMessage: async () => {},
      showWarningMessage: async () => {},
    });
    service._pullDependency = async () => {
      registryDispatches += 1;
      throw new Error("registry dispatch must not run without the final API key");
    };

    const result = await service.execute({
      workspace: "workspace",
      repository: { slug: "repository" },
      plan: {
        pullableDependencies: [{
          name: "dependency",
          version: "1.0.0",
          format: "npm",
          cloudsmithStatus: "NOT_FOUND",
        }],
        skippedDependencies: [],
      },
    });

    assert.strictEqual(result, null);
    assert.strictEqual(absenceChecks, 1);
    assert.strictEqual(credentialCalls, 1);
    assert.strictEqual(registryDispatches, 0);
    assert.deepStrictEqual(errors, [
      "Pull-through requires a Cloudsmith API key. Sign in with an API key to continue.",
    ]);
  });

  test("SSO preparation rejects bulk and single pulls before every preflight", async () => {
    let repositoryFetches = 0;
    let upstreamInspections = 0;
    let absenceChecks = 0;
    let quickPicks = 0;
    const errors = [];
    const service = new UpstreamPullService({}, {
      connectionManager: {
        getAuthenticationCapabilities() { return { pullThroughAvailable: false }; },
      },
      fetchRepositories: async () => {
        repositoryFetches += 1;
        return { items: [{ slug: "repository" }], complete: true };
      },
      upstreamRuntime: {
        async getRepositoryUpstreamStateForFormats() {
          upstreamInspections += 1;
          return completeRepositoryState({ npm: [safeUpstream("npm", "npm-upstream")] });
        },
      },
      checkPackageAbsence: async () => {
        absenceChecks += 1;
        return { absent: true, present: false, complete: true, stale: false };
      },
      showQuickPick: async items => {
        quickPicks += 1;
        return items[0];
      },
      showErrorMessage: async message => { errors.push(message); },
      showInformationMessage: async () => {},
      showWarningMessage: async () => {},
    });
    const dependency = {
      name: "dependency",
      version: "1.0.0",
      format: "npm",
      cloudsmithStatus: "NOT_FOUND",
    };

    assert.strictEqual(await service.prepare({
      workspace: "workspace",
      dependencies: [dependency],
    }), null);
    assert.strictEqual(await service.prepareSingle({
      workspace: "workspace",
      dependency,
    }), null);
    assert.deepStrictEqual({
      absenceChecks,
      quickPicks,
      repositoryFetches,
      upstreamInspections,
    }, {
      absenceChecks: 0,
      quickPicks: 0,
      repositoryFetches: 0,
      upstreamInspections: 0,
    });
    assert.deepStrictEqual(errors, [
      "Pull-through requires a Cloudsmith API key. Sign in with an API key to continue.",
      "Pull-through requires a Cloudsmith API key. Sign in with an API key to continue.",
    ]);
  });

  test("builds canonical registry trigger URLs for supported formats", () => {
    const mavenPlan = buildRegistryTriggerPlan("workspace", "repo", {
      name: "com.example:demo-app",
      version: "1.2.3",
      format: "maven",
    });
    assert.strictEqual(
      mavenPlan.request.url,
      "https://dl.cloudsmith.io/basic/workspace/repo/maven/com/example/demo-app/1.2.3/demo-app-1.2.3.jar"
    );
    assert.strictEqual(mavenPlan.artifactRequest, undefined);

    const npmPlan = buildRegistryTriggerPlan("workspace", "repo", {
      name: "@scope/widget",
      version: "4.5.6",
      format: "npm",
    });
    assert.strictEqual(
      npmPlan.request.url,
      "https://npm.cloudsmith.io/workspace/repo/%40scope%2Fwidget/4.5.6"
    );

    const goPlan = buildRegistryTriggerPlan("workspace", "repo", {
      name: "github.com/MyOrg/MyModule",
      version: "v1.0.0",
      format: "go",
    });
    assert.strictEqual(
      goPlan.request.url,
      "https://golang.cloudsmith.io/workspace/repo/github.com/!my!org/!my!module/@v/v1.0.0.zip"
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
      "artifact",
      "1.0.0",
      "https://dl.cloudsmith.io/basic/workspace/repo/python/simple/artifact/"
    );
    const elapsed = Date.now() - startedAt;

    assert.strictEqual(result, null);
    assert.ok(elapsed < 1000, `hostile anchor scan took ${elapsed}ms`);
  });

  test("exact pull absence lookup exhausts every authoritative page and detects a late match", async () => {
    const calls = [];
    const candidate = (name, slug) => ({
      namespace: "workspace",
      repository: "repo-b",
      name,
      version: "1.0.0",
      format: "npm",
      slug_perm: slug,
    });
    const firstPage = Array.from(
      { length: 100 },
      (_value, index) => candidate(`other-${index}`, `other-${index}`)
    );
    const api = {
      async get(endpoint) {
        calls.push(endpoint);
        const page = new URL(endpoint, "https://api.cloudsmith.io").searchParams.get("page");
        const data = page === "1"
          ? firstPage
          : [candidate("target-package", "target-package-1")];
        return apiSuccess(data, {
          headers: {
            "x-pagination-page": page,
            "x-pagination-pagetotal": "2",
            "x-pagination-count": "101",
            "x-pagination-pagesize": "100",
          },
        });
      },
    };
    const service = new UpstreamPullService({}, { api });

    const result = await service._checkExactPackageAbsence({
      workspace: "workspace",
      repository: "repo-b",
      dependency: {
        name: "target-package",
        version: "1.0.0",
        format: "npm",
      },
    });

    assert.strictEqual(calls.length, 2);
    const { package: exactPackage, ...outcome } = result;
    assert.deepStrictEqual(outcome, {
      workspace: "workspace",
      repository: "repo-b",
      absent: false,
      present: true,
      complete: true,
      stale: false,
    });
    assert.strictEqual(exactPackage.workspace, "workspace");
    assert.strictEqual(exactPackage.repository, "repo-b");
    assert.strictEqual(exactPackage.packageIdentifier, "target-package-1");
  });

  test("exact pull absence lookup accepts only authoritative exhaustive absence", async () => {
    const service = new UpstreamPullService({}, {
      api: {
        async get() {
          return apiSuccess([], {
            headers: {
              "x-pagination-page": "1",
              "x-pagination-pagetotal": "1",
              "x-pagination-count": "0",
              "x-pagination-pagesize": "100",
            },
          });
        },
      },
    });

    const result = await service._checkExactPackageAbsence({
      workspace: "workspace",
      repository: "repo-b",
      dependency: { name: "target-package", version: "1.0.0", format: "npm" },
    });

    assert.deepStrictEqual(result, {
      workspace: "workspace",
      repository: "repo-b",
      absent: true,
      present: false,
      complete: true,
      stale: false,
      observedIdentities: [],
    });
  });

  test("exact pull presence lookup preserves scoped npm slash identity", async () => {
    let requestedQuery = "";
    const service = new UpstreamPullService({}, {
      api: {
        async get(endpoint) {
          requestedQuery = new URL(endpoint, "https://api.cloudsmith.io")
            .searchParams.get("query");
          return apiSuccess([{
            namespace: "workspace",
            repository: "repo-b",
            name: "@aws-sdk/client-s3",
            version: "3.600.0",
            format: "npm",
            slug_perm: "node-8-9-2",
          }]);
        },
      },
    });

    const result = await service._checkExactPackageAbsence({
      workspace: "workspace",
      repository: "repo-b",
      dependency: { name: "@aws-sdk/client-s3", version: "3.600.0", format: "npm" },
    });

    assert.match(requestedQuery, /name:@aws-sdk\/client-s3/);
    assert.doesNotMatch(requestedQuery, /@aws\\-sdk|client\\-s3|@aws-sdk\\\/client-s3/);
    assert.strictEqual(result.present, true);
    assert.strictEqual(result.absent, false);
    assert.strictEqual(result.complete, true);
  });

  test("leading modifier-like names cannot broaden exact pull presence", async () => {
    const queries = [];
    const service = new UpstreamPullService({}, {
      api: {
        async get(endpoint) {
          queries.push(new URL(endpoint, "https://api.cloudsmith.io")
            .searchParams.get("query"));
          return apiSuccess([{
            namespace: "workspace",
            repository: "repo-b",
            name: "target-package",
            version: "1.0.0",
            format: "npm",
            slug_perm: "different-package",
          }]);
        },
      },
    });

    const result = await service._checkExactPackageAbsence({
      workspace: "workspace",
      repository: "repo-b",
      dependency: { name: "+-target-package", version: "1.0.0", format: "npm" },
    });

    assert.ok(queries[0].includes("name:\\+\\-target-package"));
    assert.strictEqual(result.present, false);
    assert.strictEqual(result.absent, true);
    assert.strictEqual(result.complete, true);
  });

  test("leading modifier-like names still produce exact pull presence", async () => {
    const service = new UpstreamPullService({}, {
      api: {
        async get() {
          return apiSuccess([{
            namespace: "workspace",
            repository: "repo-b",
            name: "--target-package",
            version: "1.0.0-beta+build",
            format: "npm",
            slug_perm: "exact-package",
          }]);
        },
      },
    });

    const result = await service._checkExactPackageAbsence({
      workspace: "workspace",
      repository: "repo-b",
      dependency: {
        name: "--target-package",
        version: "1.0.0-beta+build",
        format: "npm",
      },
    });

    assert.strictEqual(result.present, true);
    assert.strictEqual(result.absent, false);
    assert.strictEqual(result.complete, true);
  });

  test("exact Docker presence matches the requested tag instead of the stored manifest digest", async () => {
    let requestedQuery = "";
    const service = new UpstreamPullService({}, {
      api: {
        async get(endpoint) {
          requestedQuery = new URL(endpoint, "https://api.cloudsmith.io")
            .searchParams.get("query");
          return apiSuccess([{
            namespace: "workspace",
            repository: "repo-b",
            name: "library/hello-world",
            version: "a".repeat(64),
            format: "docker",
            slug_perm: "hello-world-linux",
            tags: { version: ["linux"] },
          }]);
        },
      },
    });

    const result = await service._checkExactPackageAbsence({
      workspace: "workspace",
      repository: "repo-b",
      dependency: { name: "hello-world", version: "linux", format: "docker" },
    });

    assert.match(requestedQuery, /name:hello-world/);
    assert.doesNotMatch(requestedQuery, /version:linux/);
    assert.strictEqual(result.present, true);
    assert.strictEqual(result.absent, false);
    assert.strictEqual(result.complete, true);
  });

  test("exact Docker digest presence cannot be satisfied by the same tag on another digest", async () => {
    const service = new UpstreamPullService({}, {
      api: {
        async get() {
          return apiSuccess([{
            namespace: "workspace",
            repository: "repo-b",
            name: "library/example",
            version: "b".repeat(64),
            format: "docker",
            slug_perm: "example-stable",
            tags: { version: ["stable"] },
          }]);
        },
      },
    });

    const result = await service._checkExactPackageAbsence({
      workspace: "workspace",
      repository: "repo-b",
      dependency: {
        name: "example",
        version: "stable",
        format: "docker",
        qualifiers: { tag: "stable", digest: `sha256:${"a".repeat(64)}` },
      },
    });

    assert.strictEqual(result.present, false);
    assert.strictEqual(result.absent, true);
    assert.strictEqual(result.complete, true);
  });

  test("platform-qualified Docker presence rejects unlinked split-row evidence before and after pull", async () => {
    const tagCandidate = {
      namespace: "workspace",
      repository: "repo-b",
      name: "library/example",
      version: "a".repeat(64),
      format: "docker",
      slug_perm: "example-stable",
      tags: { version: ["stable"] },
    };
    const architectureCandidate = architecture => ({
      namespace: "workspace",
      repository: "repo-b",
      name: "library/example",
      version: `${architecture}-${"b".repeat(48)}`,
      format: "docker",
      slug_perm: `example-${architecture}`,
      architectures: [{ name: architecture }],
      identifiers: { architecture, docker_platform_os: "linux" },
    });
    const check = async (candidates, options = {}) => new UpstreamPullService({}, {
      api: { async get() { return apiSuccess(candidates); } },
    })._checkExactPackageAbsence({
      workspace: "workspace",
      repository: "repo-b",
      dependency: {
        name: "example",
        version: "stable",
        format: "docker",
        qualifiers: { tag: "stable", platform: "linux/arm64" },
      },
      ...options,
    });

    const wrongPlatform = await check([
      tagCandidate,
      architectureCandidate("amd64"),
    ]);
    assert.strictEqual(wrongPlatform.complete, false);
    const preexistingSplitShape = await check([
      tagCandidate,
      architectureCandidate("arm64"),
    ]);
    assert.strictEqual(preexistingSplitShape.complete, false);
    const postTriggerSplitShape = await check([
      tagCandidate,
      architectureCandidate("arm64"),
    ]);
    assert.strictEqual(postTriggerSplitShape.present, false);
    assert.strictEqual(postTriggerSplitShape.absent, false);
    assert.strictEqual(postTriggerSplitShape.complete, false);
    const verifiedRegistryManifest = await check([tagCandidate], {
      dockerPlatformVerified: true,
    });
    assert.strictEqual(verifiedRegistryManifest.present, true);
    assert.strictEqual(verifiedRegistryManifest.complete, true);
  });

  test("exact Docker digest presence preserves the digest algorithm when Cloudsmith supplies it", async () => {
    const hex = "a".repeat(64);
    const check = async observedVersion => new UpstreamPullService({}, {
      api: {
        async get() {
          return apiSuccess([{
            namespace: "workspace",
            repository: "repo-b",
            name: "library/example",
            version: observedVersion,
            format: "docker",
            slug_perm: "example-digest",
            tags: { info: ["upstream"] },
          }]);
        },
      },
    })._checkExactPackageAbsence({
      workspace: "workspace",
      repository: "repo-b",
      dependency: {
        name: "example",
        version: `sha256:${hex}`,
        format: "docker",
        qualifiers: { digest: `sha256:${hex}` },
      },
    });

    assert.strictEqual((await check(`sha512:${hex}`)).absent, true);
    assert.strictEqual((await check(`unknown:${hex}`)).absent, true);
    assert.strictEqual((await check(hex)).present, true);
  });

  test("exact Swift lookup uses the bare API name but fails closed without scope evidence", async () => {
    let requestedQuery = "";
    const service = new UpstreamPullService({}, {
      api: {
        async get(endpoint) {
          requestedQuery = new URL(endpoint, "https://api.cloudsmith.io/v1/")
            .searchParams.get("query");
          return apiSuccess([{
            namespace: "acme",
            repository: "repo-b",
            name: "logging",
            version: "1.2.3",
            format: "swift",
            slug_perm: "logging-1.2.3",
          }]);
        },
      },
    });

    const result = await service._checkExactPackageAbsence({
      workspace: "acme",
      repository: "repo-b",
      dependency: {
        name: "acme.logging",
        version: "1.2.3",
        format: "swift",
        qualifiers: { scope: "acme" },
      },
    });

    assert.match(requestedQuery, /name:logging/);
    assert.strictEqual(result.present, false);
    assert.strictEqual(result.absent, false);
    assert.strictEqual(result.complete, false);
  });

  test("exact Swift lookup accepts a newly observed bare row only after proven absence", async () => {
    const service = new UpstreamPullService({}, {
      api: {
        async get() {
          return apiSuccess([{
            namespace: "workspace",
            repository: "repo-b",
            name: "logging",
            version: "1.2.3",
            format: "swift",
            slug_perm: "logging-1.2.3",
          }]);
        },
      },
    });
    const result = await service._checkExactPackageAbsence({
      workspace: "workspace",
      repository: "repo-b",
      dependency: {
        name: "acme.logging",
        version: "1.2.3",
        format: "swift",
        qualifiers: { scope: "acme" },
      },
      baselineIdentities: new Set(),
    });

    assert.strictEqual(result.present, true);
    assert.strictEqual(result.absent, false);
    assert.strictEqual(result.complete, true);
  });

  test("exact Swift lookup accepts embedded dotted and slash scope evidence", async () => {
    for (const candidateName of ["acme.logging", "acme/logging"]) {
      const service = new UpstreamPullService({}, {
        api: {
          async get() {
            return apiSuccess([{
              namespace: "workspace",
              repository: "repo-b",
              name: candidateName,
              version: "1.2.3",
              format: "swift",
              slug_perm: `logging-${candidateName.includes(".") ? "dot" : "slash"}`,
            }]);
          },
        },
      });

      const result = await service._checkExactPackageAbsence({
        workspace: "workspace",
        repository: "repo-b",
        dependency: {
          name: "acme.logging",
          version: "1.2.3",
          format: "swift",
          qualifiers: { scope: "acme" },
        },
      });

      assert.strictEqual(result.present, true, candidateName);
      assert.strictEqual(result.absent, false, candidateName);
      assert.strictEqual(result.complete, true, candidateName);
    }
  });

  test("exact presence normalizes NuGet versions and verifies Maven and Ruby artifact qualifiers", async () => {
    async function check(dependency, candidate) {
      const service = new UpstreamPullService({}, {
        api: { async get() { return apiSuccess([candidate]); } },
      });
      return service._checkExactPackageAbsence({
        workspace: "workspace",
        repository: "repo-b",
        dependency,
      });
    }

    const nuget = await check({
      name: "Example.Package",
      version: "01.02.003.0-BETA+build.7",
      format: "nuget",
    }, {
      namespace: "workspace",
      repository: "repo-b",
      name: "Example.Package",
      version: "1.2.3-beta",
      format: "nuget",
      slug_perm: "nuget-example",
    });
    assert.strictEqual(nuget.present, true);

    const mavenWrongClassifier = await check({
      name: "com.example:demo",
      version: "1.2.3",
      format: "maven",
      qualifiers: { type: "test-jar", classifier: "tests" },
    }, {
      namespace: "workspace",
      repository: "repo-b",
      name: "demo",
      version: "1.2.3",
      format: "maven",
      slug_perm: "maven-demo",
      identifiers: { group_id: "com.example", name: "demo" },
      files: [{ filename: "demo-1.2.3.jar" }],
    });
    assert.strictEqual(mavenWrongClassifier.absent, true);

    const mavenExactClassifier = await check({
      name: "com.example:demo",
      version: "1.2.3",
      format: "maven",
      qualifiers: { type: "test-jar", classifier: "tests" },
    }, {
      namespace: "workspace",
      repository: "repo-b",
      name: "demo",
      version: "1.2.3",
      format: "maven",
      slug_perm: "maven-demo-tests",
      identifiers: { group_id: "com.example", name: "demo" },
      files: [{ filename: "demo-1.2.3-tests.jar" }],
    });
    assert.strictEqual(mavenExactClassifier.present, true);

    const mavenImplicitClassifier = await check({
      name: "com.example:demo",
      version: "1.2.3",
      format: "maven",
      qualifiers: { type: "test-jar" },
    }, {
      namespace: "workspace",
      repository: "repo-b",
      name: "demo",
      version: "1.2.3",
      format: "maven",
      slug_perm: "maven-demo-tests-implicit",
      identifiers: { group_id: "com.example", name: "demo" },
      files: [{ filename: "demo-1.2.3-tests.jar" }],
    });
    assert.strictEqual(mavenImplicitClassifier.present, true);

    const mavenDefaultJar = await check({
      name: "com.example:demo",
      version: "1.2.3",
      format: "maven",
    }, {
      namespace: "workspace",
      repository: "repo-b",
      name: "demo",
      version: "1.2.3",
      format: "maven",
      slug_perm: "maven-demo-default",
      identifiers: { group_id: "com.example", name: "demo" },
      files: [{ filename: "demo-1.2.3.jar" }],
    });
    assert.strictEqual(mavenDefaultJar.present, true);

    const mavenPomOnly = await check({
      name: "com.example:demo",
      version: "1.2.3",
      format: "maven",
    }, {
      namespace: "workspace",
      repository: "repo-b",
      name: "demo",
      version: "1.2.3",
      format: "maven",
      slug_perm: "maven-demo-pom-only",
      identifiers: { group_id: "com.example", name: "demo" },
      files: [{ filename: "demo-1.2.3.pom" }],
    });
    assert.strictEqual(mavenPomOnly.present, false);
    assert.strictEqual(mavenPomOnly.absent, true);

    const rubyMissingPlatform = await check({
      name: "native-gem",
      version: "1.0.0",
      format: "ruby",
      qualifiers: { platform: "x86_64-linux" },
    }, {
      namespace: "workspace",
      repository: "repo-b",
      name: "native-gem",
      version: "1.0.0",
      format: "ruby",
      slug_perm: "ruby-native-gem",
    });
    assert.strictEqual(rubyMissingPlatform.absent, false);
    assert.strictEqual(rubyMissingPlatform.complete, false);

    const rubyDefaultAgainstNative = await check({
      name: "native-gem",
      version: "1.0.0",
      format: "ruby",
    }, {
      namespace: "workspace",
      repository: "repo-b",
      name: "native-gem",
      version: "1.0.0",
      format: "ruby",
      slug_perm: "ruby-native-only",
      architectures: [{ name: "arm64-darwin" }],
    });
    assert.strictEqual(rubyDefaultAgainstNative.present, false);
    assert.strictEqual(rubyDefaultAgainstNative.absent, true);

    const rubyArchitectureArray = await check({
      name: "native-gem",
      version: "1.0.0",
      format: "ruby",
      qualifiers: { platform: "x86_64-linux" },
    }, {
      namespace: "workspace",
      repository: "repo-b",
      name: "native-gem",
      version: "1.0.0",
      format: "ruby",
      slug_perm: "ruby-native-gem-architecture-array",
      architectures: [{ name: "x86_64-linux" }],
    });
    assert.strictEqual(rubyArchitectureArray.present, true);
  });

  test("exact absence fails closed when qualifier evidence is omitted from a plausible row", async () => {
    async function check(dependency, candidate) {
      const service = new UpstreamPullService({}, {
        api: { async get() { return apiSuccess([candidate]); } },
      });
      return service._checkExactPackageAbsence({
        workspace: "workspace",
        repository: "repo-b",
        dependency,
      });
    }

    const maven = await check({
      name: "com.example:demo",
      version: "1.2.3",
      format: "maven",
      qualifiers: { type: "test-jar", classifier: "tests" },
    }, {
      namespace: "workspace",
      repository: "repo-b",
      name: "demo",
      version: "1.2.3",
      format: "maven",
      slug_perm: "demo-1.2.3",
      identifiers: { group_id: "com.example" },
    });
    assert.strictEqual(maven.complete, false);
    assert.strictEqual(maven.absent, false);

    const ruby = await check({
      name: "native-gem",
      version: "1.0.0",
      format: "ruby",
      qualifiers: { platform: "x86_64-linux" },
    }, {
      namespace: "workspace",
      repository: "repo-b",
      name: "native-gem",
      version: "1.0.0",
      format: "ruby",
      slug_perm: "native-gem-1.0.0",
    });
    assert.strictEqual(ruby.complete, false);
    assert.strictEqual(ruby.absent, false);
  });

  test("exact pull absence lookup fails closed on partial, error, and wrong-repository data", async () => {
    const cases = [
      {
        name: "partial pagination",
        response: apiSuccess([], {
          headers: {
            "x-pagination-page": "1",
            "x-pagination-pagetotal": "2",
            "x-pagination-count": "101",
            "x-pagination-pagesize": "100",
          },
        }),
      },
      {
        name: "request error",
        response: apiFailure("network", { retryable: false }),
      },
      {
        name: "wrong repository",
        response: apiSuccess([{
          namespace: "workspace",
          repository: "repo-a",
          name: "target-package",
          version: "1.0.0",
          format: "npm",
          slug_perm: "target-package-1",
        }]),
      },
      {
        name: "malformed stable identifier",
        response: apiSuccess([{
          namespace: "workspace",
          repository: "repo-b",
          name: "target-package",
          version: "1.0.0",
          format: "npm",
          slug_perm: "target-package\u202e",
        }]),
      },
      {
        name: "missing stable identifier",
        response: apiSuccess([{
          namespace: "workspace",
          repository: "repo-b",
          name: "target-package",
          version: "1.0.0",
          format: "npm",
        }]),
      },
      {
        name: "malformed consumed identifier evidence",
        response: apiSuccess([{
          namespace: "workspace",
          repository: "repo-b",
          name: "target-package",
          version: "1.0.0",
          format: "npm",
          slug_perm: "target-package-1",
          identifiers: { group_id: { hostile: true } },
        }]),
      },
      {
        name: "bidi-bearing primary identity",
        response: apiSuccess([{
          namespace: "workspace",
          repository: "repo-b",
          name: "target-package\u202e",
          version: "1.0.0",
          format: "npm",
          slug_perm: "target-package-1",
        }]),
      },
    ];

    for (const testCase of cases) {
      const service = new UpstreamPullService({}, {
        api: { async get() { return testCase.response; } },
      });
      const result = await service._checkExactPackageAbsence({
        workspace: "workspace",
        repository: "repo-b",
        dependency: { name: "target-package", version: "1.0.0", format: "npm" },
      });
      assert.strictEqual(result.absent, false, testCase.name);
      assert.strictEqual(result.complete, false, testCase.name);
    }
  });

  test("exact pull lookup accepts only canonical package identifier aliases", async () => {
    async function check(identifierFields) {
      const service = new UpstreamPullService({}, {
        api: {
          async get() {
            return apiSuccess([{
              namespace: "workspace",
              repository: "repo-b",
              name: "target-package",
              version: "1.0.0",
              format: "npm",
              ...identifierFields,
            }]);
          },
        },
      });
      return service._checkExactPackageAbsence({
        workspace: "workspace",
        repository: "repo-b",
        dependency: { name: "target-package", version: "1.0.0", format: "npm" },
      });
    }

    for (const identifierFields of [
      { packageIdentifier: "target-package-1" },
      { slug_perm_raw: "target-package-1" },
    ]) {
      assert.strictEqual((await check(identifierFields)).present, true);
    }
    for (const identifierFields of [
      { identifier: "target-package-1" },
      { slug_perm: "unsafe/identifier" },
      { slug_perm: "%252f" },
      { slug_perm: "target-package-1", slug_perm_raw: "conflict" },
    ]) {
      const result = await check(identifierFields);
      assert.strictEqual(result.present, false);
      assert.strictEqual(result.complete, false);
    }
  });

  test("exact pull absence lookup stops pagination when its account becomes stale", async () => {
    let state = {
      activationId: "account-a",
      accountEpoch: 1,
      sessionConnected: true,
    };
    let calls = 0;
    const service = new UpstreamPullService({}, {
      connectionManager: {
        getState() { return { ...state }; },
        getAuthenticationCapabilities: apiKeyCapabilities,
      },
      api: {
        async get() {
          calls += 1;
          state = { ...state, activationId: "account-b", accountEpoch: 2 };
          return apiSuccess(Array.from({ length: 100 }, (_value, index) => ({
            namespace: "workspace",
            repository: "repo-b",
            name: `other-${index}`,
            version: "1.0.0",
            format: "npm",
            slug_perm: `other-${index}`,
          })), {
            headers: {
              "x-pagination-page": "1",
              "x-pagination-pagetotal": "2",
              "x-pagination-count": "101",
              "x-pagination-pagesize": "100",
            },
          });
        },
      },
    });

    const result = await service._checkExactPackageAbsence({
      workspace: "workspace",
      repository: "repo-b",
      dependency: { name: "target-package", version: "1.0.0", format: "npm" },
      account: { activationId: "account-a", accountEpoch: 1 },
    });

    assert.strictEqual(calls, 1);
    assert.strictEqual(result.absent, false);
    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.stale, true);
  });

  test("pull-all establishes exact target absence once before confirmation and carries the proof into write", async () => {
    const absenceCalls = [];
    const confirmations = [];
    const events = [];
    const service = new UpstreamPullService({}, {
      credentialManager: {
        async getApiKey() {
          events.push("credential");
          return "api-key";
        },
      },
      fetchRepositories: async () => ({
        items: [{ slug: "repo-b", name: "Repo B" }],
        complete: true,
      }),
      upstreamRuntime: {
        async getRepositoryUpstreamStateForFormats() {
          return completeRepositoryState({
            npm: [safeUpstream("npm", "npm", { is_active: true })],
          });
        },
      },
      checkPackageAbsence: async ({ workspace, repository, dependency }) => {
        absenceCalls.push({ workspace, repository, name: dependency.name });
        events.push(`absence-${absenceCalls.length}`);
        return {
          workspace,
          repository,
          absent: true,
          present: false,
          complete: true,
          stale: false,
        };
      },
      showQuickPick: async items => {
        events.push("repository-pick");
        return items[0];
      },
      showWarningMessage: async (message, _options, action) => {
        confirmations.push(message);
        events.push("confirm");
        return action;
      },
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
    });
    service._pullDependency = async (_workspace, _repository, dependency) => {
      events.push("registry-write");
      return {
        dependency,
        status: "cached",
        errorMessage: null,
        networkError: false,
      };
    };

    const result = await service.run({
      workspace: "workspace",
      repositoryHint: "repo-a",
      dependencies: [{
        name: "target-package",
        version: "1.0.0",
        format: "npm",
        cloudsmithStatus: "ABSENT",
      }],
    });

    assert.ok(result);
    assert.strictEqual(result.pullResult.cached, 1);
    assert.deepStrictEqual(absenceCalls, [
      { workspace: "workspace", repository: "repo-b", name: "target-package" },
    ]);
    assert.strictEqual(confirmations.length, 1);
    assert.deepStrictEqual(events, [
      "repository-pick",
      "absence-1",
      "confirm",
      "credential",
      "registry-write",
    ]);
  });

  test("bulk preparation reuses 100 current authoritative scan absences without package lookups", async () => {
    const account = { activationId: "account-a", accountEpoch: 1 };
    const token = cancellationToken();
    const dependencies = Array.from({ length: 100 }, (_, index) => ({
      name: `package-${index}`,
      version: "1.0.0",
      format: "npm",
      cloudsmithStatus: "ABSENT",
    }));
    const absenceEvidence = createBulkScanAbsenceEvidence({
      account,
      workspace: "workspace",
      repository: null,
      projectFolder: "/project",
      scanId: 7,
      selectionGeneration: 3,
      operationId: 11,
      cancellationToken: token,
      dependencies,
    });
    let absenceLookups = 0;
    let confirmations = 0;
    const service = new UpstreamPullService({}, {
      connectionManager: {
        getState() { return { ...account, sessionConnected: true }; },
        getAuthenticationCapabilities: apiKeyCapabilities,
      },
      fetchRepositories: async () => ({
        items: [{ slug: "repo", name: "Repo" }],
        complete: true,
      }),
      upstreamRuntime: {
        async getRepositoryUpstreamStateForFormats() {
          return completeRepositoryState({
            npm: [safeUpstream("npm", "npm", { is_active: true })],
          });
        },
      },
      checkPackageAbsence: async () => {
        absenceLookups += 1;
        throw new Error("current scan evidence should own this absence");
      },
      showQuickPick: async items => items[0],
      showWarningMessage: async (_message, _options, action) => {
        confirmations += 1;
        return action;
      },
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
    });

    const prepared = await service.prepare({
      workspace: "workspace",
      dependencies,
      cancellationToken: token,
      account,
      absenceEvidence,
      isCurrent: () => true,
      projectFolder: "/project",
    });

    assert.ok(prepared);
    assert.strictEqual(absenceLookups, 0);
    assert.strictEqual(confirmations, 1);
    assert.strictEqual(prepared.plan.pullableDependencies.length, 100);
  });

  test("bulk scan absence evidence fails closed across status, account, scope, project, and operation token", () => {
    const account = { activationId: "account-a", accountEpoch: 1 };
    const token = cancellationToken();
    const absent = {
      name: "absent-package",
      version: "1.0.0",
      format: "npm",
      cloudsmithStatus: "ABSENT",
    };
    const unknown = {
      name: "unknown-package",
      version: "1.0.0",
      format: "npm",
      cloudsmithStatus: "UNKNOWN",
    };
    const evidence = createBulkScanAbsenceEvidence({
      account,
      workspace: "workspace",
      repository: "repo",
      projectFolder: "/project",
      scanId: 7,
      selectionGeneration: 3,
      operationId: 11,
      cancellationToken: token,
      dependencies: [absent, unknown],
    });
    const expected = {
      account,
      workspace: "workspace",
      repository: "repo",
      projectFolder: "/project",
      dependency: absent,
      cancellationToken: token,
    };

    assert.ok(getReusableBulkScanAbsenceProof(evidence, expected));
    assert.strictEqual(getReusableBulkScanAbsenceProof(evidence, {
      ...expected,
      dependency: unknown,
    }), null);
    assert.strictEqual(getReusableBulkScanAbsenceProof(evidence, {
      ...expected,
      account: { activationId: "account-b", accountEpoch: 2 },
    }), null);
    assert.strictEqual(getReusableBulkScanAbsenceProof(evidence, {
      ...expected,
      repository: "other-repo",
    }), null);
    assert.strictEqual(getReusableBulkScanAbsenceProof(evidence, {
      ...expected,
      projectFolder: "/other-project",
    }), null);
    assert.strictEqual(getReusableBulkScanAbsenceProof(evidence, {
      ...expected,
      cancellationToken: cancellationToken(),
    }), null);
    token.cancel();
    assert.strictEqual(getReusableBulkScanAbsenceProof(evidence, expected), null);
  });

  test("bulk preparation verifies only missing scan evidence with eight bounded workers", async () => {
    const account = { activationId: "account-a", accountEpoch: 1 };
    const token = cancellationToken();
    const dependencies = Array.from({ length: 100 }, (_, index) => ({
      name: `package-${index}`,
      version: "1.0.0",
      format: "npm",
      cloudsmithStatus: "ABSENT",
    }));
    const absenceEvidence = createBulkScanAbsenceEvidence({
      account,
      workspace: "workspace",
      repository: "repo",
      projectFolder: "/project",
      scanId: 7,
      selectionGeneration: 3,
      operationId: 11,
      cancellationToken: token,
      dependencies: dependencies.slice(0, 87),
    });
    const gate = deferred();
    let lookups = 0;
    let active = 0;
    let maxActive = 0;
    const service = new UpstreamPullService({}, {
      connectionManager: {
        getState() { return { ...account, sessionConnected: true }; },
        getAuthenticationCapabilities: apiKeyCapabilities,
      },
      fetchRepositories: async () => ({
        items: [{ slug: "repo", name: "Repo" }],
        complete: true,
      }),
      upstreamRuntime: {
        async getRepositoryUpstreamStateForFormats() {
          return completeRepositoryState({
            npm: [safeUpstream("npm", "npm", { is_active: true })],
          });
        },
      },
      checkPackageAbsence: async ({ workspace, repository }) => {
        lookups += 1;
        active += 1;
        maxActive = Math.max(maxActive, active);
        await gate.promise;
        active -= 1;
        return {
          workspace,
          repository,
          absent: true,
          present: false,
          complete: true,
          stale: false,
        };
      },
      showQuickPick: async items => items[0],
      showWarningMessage: async (_message, _options, action) => action,
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
    });

    const pending = service.prepare({
      workspace: "workspace",
      dependencies,
      cancellationToken: token,
      account,
      absenceEvidence,
      projectFolder: "/project",
      isCurrent: () => true,
    });
    await new Promise(resolve => setImmediate(resolve));
    await new Promise(resolve => setImmediate(resolve));
    assert.strictEqual(lookups, 8);
    gate.resolve();
    const prepared = await pending;

    assert.ok(prepared);
    assert.strictEqual(lookups, 13);
    assert.strictEqual(maxActive, 8);
  });

  test("pull-all and pull-single repository picks bound and neutralize hostile names", async () => {
    const unsafeDisplay = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u;
    const hostileName = `Repo\u0000\u061c\u200b\u202e\u2067\ufeff Display ${"x".repeat(800)}`;
    const hostileUpstreamName = `Registry\u0000\u061c\u200b\u202e\u2067\ufeff Source ${"y".repeat(475)}`;
    const dependency = {
      name: "target-package",
      version: "1.0.0",
      format: "npm",
      cloudsmithStatus: "ABSENT",
    };

    for (const method of ["prepare", "prepareSingle"]) {
      const quickPicks = [];
      const service = new UpstreamPullService({}, {
        fetchRepositories: async () => ({
          items: [{ slug: "safe-repo", name: hostileName }],
          complete: true,
        }),
        upstreamRuntime: {
          async getRepositoryUpstreamStateForFormats() {
            return completeRepositoryState({
              npm: [safeUpstream("npm", hostileUpstreamName, { is_active: true })],
            });
          },
        },
        showQuickPick: async items => {
          quickPicks.push(items);
          return items[0];
        },
        showWarningMessage: async (_message, _options, action) => action,
        showErrorMessage: async () => {},
        showInformationMessage: async () => {},
      });

      const prepared = method === "prepare"
        ? await service.prepare({ workspace: "workspace", dependencies: [dependency] })
        : await service.prepareSingle({ workspace: "workspace", dependency });

      assert.ok(prepared, method);
      assert.strictEqual(quickPicks.length, 1, method);
      assert.strictEqual(quickPicks[0].length, 1, method);
      const pick = quickPicks[0][0];
      assert.strictEqual(pick.label, "safe-repo", method);
      assert.ok(pick.description.startsWith("Repo Display "), method);
      assert.ok(pick.description.length <= 500, method);
      assert.doesNotMatch(pick.label, unsafeDisplay, method);
      assert.doesNotMatch(pick.description, unsafeDisplay, method);
      assert.doesNotMatch(pick.detail, unsafeDisplay, method);
      assert.ok(pick.detail.length <= 500, method);
      if (method === "prepareSingle") {
        assert.ok(pick.detail.startsWith("npm upstream (Registry Source "), method);
      } else {
        assert.strictEqual(pick.detail, "npm upstream configured", method);
      }
      assert.strictEqual(prepared.repository.name, pick.description, method);
      assert.doesNotMatch(prepared.repository.name, unsafeDisplay, method);
    }
  });

  test("pull-single repository detail uses a fixed fallback for display-unsafe upstream names", async () => {
    const quickPicks = [];
    const service = new UpstreamPullService({}, {
      fetchRepositories: async () => ({
        items: [{ slug: "safe-repo", name: "Safe repository" }],
        complete: true,
      }),
      upstreamRuntime: {
        async getRepositoryUpstreamStateForFormats() {
          return completeRepositoryState({
            npm: [safeUpstream("npm", "\u0000\u061c\u200b\u202e\u2067\ufeff", { is_active: true })],
          });
        },
      },
      showQuickPick: async items => {
        quickPicks.push(items);
        return items[0];
      },
      showWarningMessage: async () => {},
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
    });

    const prepared = await service.prepareSingle({
      workspace: "workspace",
      dependency: {
        name: "target-package",
        version: "1.0.0",
        format: "npm",
        cloudsmithStatus: "ABSENT",
      },
    });

    assert.ok(prepared);
    assert.strictEqual(quickPicks.length, 1);
    assert.strictEqual(quickPicks[0][0].detail, "npm upstream (npm)");
  });

  test("pull-all and pull-single reject hostile repository slugs before service mutation", async () => {
    const unsafeDisplay = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u;
    const dependency = {
      name: "target-package",
      version: "1.0.0",
      format: "npm",
      cloudsmithStatus: "ABSENT",
    };

    for (const method of ["run", "prepareSingle"]) {
      let inspectionCalls = 0;
      let quickPickCalls = 0;
      let absenceCalls = 0;
      let credentialCalls = 0;
      let pullCalls = 0;
      const messages = [];
      const service = new UpstreamPullService({}, {
        credentialManager: {
          async getApiKey() {
            credentialCalls += 1;
            return "api-key";
          },
        },
        fetchRepositories: async () => ({
          items: [{ slug: "repo\u0000\u061c\u200b\u202e\u2067\ufeff-unsafe", name: "Hostile" }],
          complete: true,
        }),
        upstreamRuntime: {
          async getRepositoryUpstreamStateForFormats() {
            inspectionCalls += 1;
            return completeRepositoryState({
              npm: [safeUpstream("npm", "npm", { is_active: true })],
            });
          },
        },
        checkPackageAbsence: async () => {
          absenceCalls += 1;
          throw new Error("unsafe repository must not reach absence lookup");
        },
        showQuickPick: async items => {
          quickPickCalls += 1;
          return items[0];
        },
        showWarningMessage: async message => { messages.push(message); },
        showErrorMessage: async message => { messages.push(message); },
        showInformationMessage: async message => { messages.push(message); },
      });
      service._pullDependency = async () => {
        pullCalls += 1;
        throw new Error("unsafe repository must not reach a registry write");
      };

      const result = method === "run"
        ? await service.run({ workspace: "workspace", dependencies: [dependency] })
        : await service.prepareSingle({ workspace: "workspace", dependency });

      assert.strictEqual(result, null, method);
      assert.strictEqual(inspectionCalls, 0, method);
      assert.strictEqual(quickPickCalls, 0, method);
      assert.strictEqual(absenceCalls, 0, method);
      assert.strictEqual(credentialCalls, 0, method);
      assert.strictEqual(pullCalls, 0, method);
      assert.ok(messages.length > 0, method);
      assert.strictEqual(messages.every(message => !unsafeDisplay.test(message)), true, method);
    }
  });

  test("single and all pull preparation fail closed before confirmation on uncertain target absence", async () => {
    const cases = [
      {
        name: "present",
        result: ({ workspace, repository }) => ({
          workspace,
          repository,
          absent: false,
          present: true,
          complete: true,
          stale: false,
        }),
      },
      {
        name: "partial",
        result: ({ workspace, repository }) => ({
          workspace,
          repository,
          absent: false,
          present: false,
          complete: false,
          stale: false,
        }),
      },
      {
        name: "wrong repository",
        result: ({ workspace }) => ({
          workspace,
          repository: "repo-a",
          absent: true,
          present: false,
          complete: true,
          stale: false,
        }),
      },
      {
        name: "error",
        result: () => { throw new Error("private lookup failure"); },
      },
    ];

    for (const testCase of cases) {
      for (const method of ["prepare", "prepareSingle"]) {
        let confirmationCalls = 0;
        const service = new UpstreamPullService({}, {
          fetchRepositories: async () => ({
            items: [{ slug: "repo-b", name: "Repo B" }],
            complete: true,
          }),
          upstreamRuntime: {
            async getRepositoryUpstreamStateForFormats() {
              return completeRepositoryState({
                npm: [safeUpstream("npm", "npm", { is_active: true })],
              });
            },
          },
          checkPackageAbsence: async args => testCase.result(args),
          showQuickPick: async items => items[0],
          showWarningMessage: async (message, options, action) => {
            if (options?.modal || action) confirmationCalls += 1;
            return action;
          },
          showErrorMessage: async () => {},
          showInformationMessage: async () => {},
        });
        const dependency = {
          name: "target-package",
          version: "1.0.0",
          format: "npm",
          cloudsmithStatus: "ABSENT",
        };
        const prepared = method === "prepare"
          ? await service.prepare({ workspace: "workspace", dependencies: [dependency] })
          : await service.prepareSingle({ workspace: "workspace", dependency });
        if (testCase.name === "present" && method === "prepare") {
          assert.ok(prepared, `${testCase.name}:${method}`);
          assert.strictEqual(prepared.plan.pullableDependencies.length, 0);
          assert.strictEqual(prepared.plan.alreadyExistingDependencies.length, 1);
        } else {
          assert.strictEqual(prepared, null, `${testCase.name}:${method}`);
        }
        assert.strictEqual(confirmationCalls, 0, `${testCase.name}:${method}`);
      }
    }
  });

  test("a package appearing after single-package preparation becomes already-exists without a registry write", async () => {
    let absenceChecks = 0;
    let pullCalls = 0;
    const service = new UpstreamPullService({}, {
      credentialManager: { async getApiKey() { return "api-key"; } },
      fetchRepositories: async () => ({
        items: [{ slug: "repo-b", name: "Repo B" }],
        complete: true,
      }),
      upstreamRuntime: {
        async getRepositoryUpstreamStateForFormats() {
          return completeRepositoryState({
            npm: [safeUpstream("npm", "npm", { is_active: true })],
          });
        },
      },
      checkPackageAbsence: async ({ workspace, repository }) => {
        absenceChecks += 1;
        return {
          workspace,
          repository,
          absent: absenceChecks === 1,
          present: absenceChecks > 1,
          complete: true,
          stale: false,
        };
      },
      showQuickPick: async items => items[0],
      showWarningMessage: async (_message, _options, action) => action,
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
    });
    service._pullDependency = async () => {
      pullCalls += 1;
      throw new Error("must not write");
    };

    const prepared = await service.prepareSingle({
      workspace: "workspace",
      dependency: {
        name: "target-package",
        version: "1.0.0",
        format: "npm",
        cloudsmithStatus: "ABSENT",
      },
    });
    const result = await service.execute(prepared);

    assert.strictEqual(absenceChecks, 2);
    assert.strictEqual(pullCalls, 0);
    assert.strictEqual(result.canceled, false);
    assert.strictEqual(result.pullResult.cached, 0);
    assert.strictEqual(result.pullResult.alreadyExisted, 1);
    assert.strictEqual(result.pullResult.details[0].status, "exists");
  });

  test("single-package execution preflight reports already-exists before credentials or registry access", async () => {
    let credentialCalls = 0;
    let registryCalls = 0;
    const statuses = [];
    const service = new UpstreamPullService({}, {
      credentialManager: {
        async getApiKey() {
          credentialCalls += 1;
          return "api-key";
        },
      },
      checkPackageAbsence: async ({ workspace, repository }) => ({
        workspace,
        repository,
        absent: false,
        present: true,
        complete: true,
        stale: false,
      }),
      fetchImpl: async () => {
        registryCalls += 1;
        throw new Error("registry request must not run");
      },
    });

    const result = await service.execute({
      workspace: "workspace",
      repository: { slug: "repo" },
      plan: {
        pullableDependencies: [{
          name: "target-package",
          version: "1.0.0",
          format: "ruby",
          cloudsmithStatus: "NOT_FOUND",
        }],
        skippedDependencies: [],
      },
    }, {
      onStatus(detail) { statuses.push(detail.status); },
    });

    assert.strictEqual(result.canceled, false);
    assert.strictEqual(result.pullResult.cached, 0);
    assert.strictEqual(result.pullResult.alreadyExisted, 1);
    assert.strictEqual(credentialCalls, 0);
    assert.strictEqual(registryCalls, 0);
    assert.deepStrictEqual(statuses, ["exists"]);
  });

  test("2xx, 304, and 409 registry responses wait for delayed exact presence before cached", async () => {
    for (const statusCode of [200, 204, 304, 409]) {
      let exactChecks = 0;
      let registryCalls = 0;
      const delays = [];
      const statuses = [];
      const service = new UpstreamPullService({}, {
        credentialManager: { async getApiKey() { return "api-key"; } },
        checkPackageAbsence: async ({ workspace, repository }) => {
          exactChecks += 1;
          if (exactChecks < 3) {
            assert.strictEqual(statuses.includes("cached"), false, String(statusCode));
          }
          return {
            workspace,
            repository,
            absent: exactChecks < 3,
            present: exactChecks >= 3,
            complete: true,
            stale: false,
          };
        },
        postTriggerPollDelaysMs: [0, 17],
        postTriggerDelay: async delayMs => { delays.push(delayMs); },
        fetchImpl: async () => {
          registryCalls += 1;
          return new Response(null, { status: statusCode });
        },
      });

      const result = await service.execute({
        workspace: "workspace",
        repository: { slug: "repo" },
        plan: {
          pullableDependencies: [{
            name: "target-package",
            version: "1.0.0",
            format: "ruby",
            cloudsmithStatus: "NOT_FOUND",
          }],
          skippedDependencies: [],
        },
      }, {
        onStatus(detail) { statuses.push(detail.status); },
      });

      assert.strictEqual(result.canceled, false, String(statusCode));
      assert.strictEqual(result.pullResult.cached, 1, String(statusCode));
      assert.strictEqual(result.pullResult.alreadyExisted, 0, String(statusCode));
      assert.strictEqual(exactChecks, 3, String(statusCode));
      assert.strictEqual(registryCalls, 1, String(statusCode));
      assert.deepStrictEqual(delays, [17], String(statusCode));
      assert.deepStrictEqual(statuses, ["pulling", "cached"], String(statusCode));
    }
  });

  test("scoped Swift execution emits exact-scope verification evidence", async () => {
    let exactChecks = 0;
    const service = new UpstreamPullService({}, {
      credentialManager: { async getApiKey() { return "api-key"; } },
      checkPackageAbsence: async ({ workspace, repository }) => {
        exactChecks += 1;
        return {
          workspace,
          repository,
          absent: exactChecks === 1,
          present: exactChecks > 1,
          complete: true,
          stale: false,
        };
      },
      fetchImpl: async () => new Response(null, { status: 200 }),
    });
    const dependency = {
      name: "acme.logging",
      version: "1.2.3",
      format: "swift",
      qualifiers: { scope: "acme" },
      cloudsmithStatus: "NOT_FOUND",
    };

    const result = await service.execute({
      workspace: "workspace",
      repository: { slug: "repo" },
      plan: { pullableDependencies: [dependency], skippedDependencies: [] },
    });

    assert.strictEqual(result.pullResult.cached, 1);
    assert.strictEqual(exactChecks, 2);
    assert.deepStrictEqual([...result.verificationReceipts.entries()], [[
      getDependencyArtifactKey(dependency),
      { swiftScopeVerified: true },
    ]]);
  });

  test("successful registry trigger with permanent exact absence returns a non-cached error", async () => {
    let exactChecks = 0;
    let registryCalls = 0;
    const delays = [];
    const statuses = [];
    const service = new UpstreamPullService({}, {
      credentialManager: { async getApiKey() { return "api-key"; } },
      checkPackageAbsence: async ({ workspace, repository }) => {
        exactChecks += 1;
        return {
          workspace,
          repository,
          absent: true,
          present: false,
          complete: true,
          stale: false,
        };
      },
      postTriggerPollDelaysMs: [0, 5, 10],
      postTriggerDelay: async delayMs => { delays.push(delayMs); },
      fetchImpl: async () => {
        registryCalls += 1;
        return createResponse(200, "");
      },
    });

    const result = await service.execute({
      workspace: "workspace",
      repository: { slug: "repo" },
      plan: {
        pullableDependencies: [{
          name: "target-package",
          version: "1.0.0",
          format: "ruby",
          cloudsmithStatus: "NOT_FOUND",
        }],
        skippedDependencies: [],
      },
    }, {
      onStatus(detail) { statuses.push(detail.status); },
    });

    assert.strictEqual(result.canceled, false);
    assert.strictEqual(result.pullResult.cached, 0);
    assert.strictEqual(result.pullResult.alreadyExisted, 0);
    assert.strictEqual(result.pullResult.errors, 1);
    assert.match(result.pullResult.details[0].errorMessage, /did not confirm the package/i);
    assert.strictEqual(exactChecks, 4);
    assert.strictEqual(registryCalls, 1);
    assert.deepStrictEqual(delays, [5, 10]);
    assert.deepStrictEqual(statuses, ["pulling", "error"]);
  });

  test("post-trigger polling cancellation cannot publish stale cached success", async () => {
    const token = cancellationToken();
    let exactChecks = 0;
    const statuses = [];
    const service = new UpstreamPullService({}, {
      credentialManager: { async getApiKey() { return "api-key"; } },
      checkPackageAbsence: async ({ workspace, repository }) => {
        exactChecks += 1;
        return {
          workspace,
          repository,
          absent: true,
          present: false,
          complete: true,
          stale: false,
        };
      },
      postTriggerPollDelaysMs: [0, 1],
      postTriggerDelay: async () => { token.cancel(); },
      fetchImpl: async () => createResponse(200, ""),
    });

    const result = await service.execute({
      workspace: "workspace",
      repository: { slug: "repo" },
      plan: {
        pullableDependencies: [{
          name: "target-package",
          version: "1.0.0",
          format: "ruby",
          cloudsmithStatus: "NOT_FOUND",
        }],
        skippedDependencies: [],
      },
    }, {
      token,
      onStatus(detail) { statuses.push(detail.status); },
    });

    assert.deepStrictEqual(result, { canceled: true });
    assert.strictEqual(exactChecks, 2);
    assert.deepStrictEqual(statuses, ["pulling"]);
  });

  test("post-trigger polling account supersession cannot publish stale cached success", async () => {
    let accountState = {
      activationId: "account-a",
      accountEpoch: 1,
      sessionConnected: true,
    };
    let exactChecks = 0;
    const statuses = [];
    const service = new UpstreamPullService({}, {
      connectionManager: {
        getState() { return { ...accountState }; },
        getAuthenticationCapabilities: apiKeyCapabilities,
      },
      credentialManager: { async getApiKey() { return "api-key"; } },
      checkPackageAbsence: async ({ workspace, repository }) => {
        exactChecks += 1;
        return {
          workspace,
          repository,
          absent: true,
          present: false,
          complete: true,
          stale: false,
        };
      },
      postTriggerPollDelaysMs: [0, 1],
      postTriggerDelay: async () => {
        accountState = { ...accountState, activationId: "account-b", accountEpoch: 2 };
      },
      fetchImpl: async () => createResponse(200, ""),
    });

    const result = await service.execute({
      workspace: "workspace",
      repository: { slug: "repo" },
      account: { activationId: "account-a", accountEpoch: 1 },
      plan: {
        pullableDependencies: [{
          name: "target-package",
          version: "1.0.0",
          format: "ruby",
          cloudsmithStatus: "NOT_FOUND",
        }],
        skippedDependencies: [],
      },
    }, {
      onStatus(detail) { statuses.push(detail.status); },
    });

    assert.deepStrictEqual(result, { canceled: true, stale: true });
    assert.strictEqual(exactChecks, 2);
    assert.deepStrictEqual(statuses, ["pulling"]);
  });

  test("prepare builds a mixed-ecosystem confirmation with skipped formats", async () => {
    const warnings = [];
    const service = new UpstreamPullService({}, {
      credentialManager: { async getApiKey() { return "api-key"; } },
      fetchRepositories: async () => ({
        items: [{ slug: "repo", name: "Repo" }],
        complete: true,
      }),
      upstreamRuntime: {
        async getRepositoryUpstreamStateForFormats() {
          return completeRepositoryState({
            maven: [safeUpstream("maven", "Maven Central", { is_active: true })],
            python: [],
          });
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
    service._pullDependency = async (_workspace, _repository, dependency) => ({
      dependency,
      status: PULL_STATUS.CACHED,
      errorMessage: null,
      networkError: false,
    });
    const execution = await service.execute(prepared);
    assert.strictEqual(execution.pullResult.total, 2);
    assert.strictEqual(execution.pullResult.cached, 1);
    assert.strictEqual(execution.pullResult.skipped, 1);
    assert.strictEqual(
      execution.pullResult.details.find(detail => detail.dependency.name === "requests").status,
      PULL_STATUS.SKIPPED
    );
  });

  test("prepare preserves exact versions that differ only by prerelease identifier case", async () => {
    const service = new UpstreamPullService({}, {
      fetchRepositories: async () => ({
        items: [{ slug: "repo", name: "Repo" }],
        complete: true,
      }),
      upstreamRuntime: {
        async getRepositoryUpstreamStateForFormats() {
          return completeRepositoryState({
            npm: [safeUpstream("npm", "npm", { is_active: true })],
          });
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

  test("prepare preserves same-version pull targets with distinct artifact qualifiers", async () => {
    const service = new UpstreamPullService({}, {
      fetchRepositories: async () => ({
        items: [{ slug: "repo", name: "Repo" }],
        complete: true,
      }),
      upstreamRuntime: {
        async getRepositoryUpstreamStateForFormats() {
          return completeRepositoryState({
            maven: [safeUpstream("maven", "maven", { is_active: true })],
          });
        },
      },
      showQuickPick: async items => items[0],
      showWarningMessage: async (_message, _options, action) => action,
    });
    const dependency = {
      name: "com.example:demo",
      version: "1.2.3",
      format: "maven",
      cloudsmithStatus: "ABSENT",
    };

    const prepared = await service.prepare({
      workspace: "workspace",
      repositoryHint: "repo",
      dependencies: [
        { ...dependency, qualifiers: { type: "jar", classifier: "javadoc" } },
        { ...dependency, qualifiers: { type: "jar", classifier: "javadoc", scope: "test" } },
        { ...dependency, qualifiers: { type: "javadoc" } },
        { ...dependency, qualifiers: { type: "test-jar" } },
        { ...dependency, qualifiers: { type: "test-jar", scope: "runtime" } },
        { ...dependency, qualifiers: { type: "jar", classifier: "tests" } },
      ],
    });

    assert.ok(prepared);
    assert.deepStrictEqual(
      prepared.plan.pullableDependencies.map(item => (
        buildRegistryTriggerPlan("workspace", "repo", item).request.url
      )),
      [
        "https://dl.cloudsmith.io/basic/workspace/repo/maven/com/example/demo/1.2.3/demo-1.2.3-javadoc.jar",
        "https://dl.cloudsmith.io/basic/workspace/repo/maven/com/example/demo/1.2.3/demo-1.2.3-tests.jar",
      ]
    );
  });

  test("pulls Python dependencies via same-host redirects using manual auth-preserving requests", async () => {
    const calls = [];
    let exactChecks = 0;
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
      checkPackageAbsence: async ({ workspace, repository }) => {
        exactChecks += 1;
        return {
          workspace,
          repository,
          absent: exactChecks === 1,
          present: exactChecks > 1,
          complete: true,
          stale: false,
        };
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
    assert.strictEqual(exactChecks, 2);
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

  test("pulls an exact scoped npm prerelease through its packument tarball", async () => {
    const calls = [];
    let exactChecks = 0;
    const packumentUrl = "https://npm.cloudsmith.io/workspace/repo/%40scope%2Fwidget-name/1.2.3-beta.1";
    const tarballUrl = "https://npm.cloudsmith.io/workspace/repo/@scope/widget-name/-/content-addressed.tgz";
    const service = new UpstreamPullService({}, {
      credentialManager: { async getApiKey() { return "api-key"; } },
      checkPackageAbsence: async ({ workspace, repository }) => {
        exactChecks += 1;
        return {
          workspace,
          repository,
          absent: exactChecks === 1,
          present: exactChecks > 1,
          complete: true,
          stale: false,
        };
      },
      fetchImpl: async (url) => {
        calls.push(url);
        if (url === packumentUrl) {
          return createResponse(200, JSON.stringify({
            name: "@scope/widget-name",
            version: "1.2.3-beta.1",
            dist: { tarball: tarballUrl },
          }));
        }
        if (url === tarballUrl) return createResponse(200, "artifact");
        throw new Error(`Unexpected URL: ${url}`);
      },
    });

    const result = await service.execute({
      workspace: "workspace",
      repository: { slug: "repo" },
      plan: {
        pullableDependencies: [{
          name: "@scope/widget-name",
          version: "1.2.3-beta.1",
          format: "npm",
          cloudsmithStatus: "NOT_FOUND",
        }],
        skippedDependencies: [],
      },
    });

    assert.strictEqual(result.pullResult.cached, 1);
    assert.strictEqual(exactChecks, 2);
    assert.deepStrictEqual(calls, [packumentUrl, tarballUrl]);
  });

  test("maps npm packument 404 and 401/403 without attempting a tarball", async () => {
    for (const [statusCode, expectedStatus] of [[404, "not_found"], [401, "auth_failed"], [403, "auth_failed"]]) {
      let registryCalls = 0;
      const service = new UpstreamPullService({}, {
        credentialManager: { async getApiKey() { return "api-key"; } },
        fetchImpl: async () => {
          registryCalls += 1;
          return createResponse(statusCode, "");
        },
        showErrorMessage: async () => {},
      });

      const result = await service.execute({
        workspace: "workspace",
        repository: { slug: "repo" },
        plan: {
          pullableDependencies: [{
            name: "package-with-hyphens",
            version: "1.2.3",
            format: "npm",
            cloudsmithStatus: "NOT_FOUND",
          }],
          skippedDependencies: [],
        },
      });

      assert.strictEqual(result.pullResult.details[0].status, expectedStatus, String(statusCode));
      assert.strictEqual(result.pullResult.cached, 0, String(statusCode));
      assert.strictEqual(registryCalls, 1, String(statusCode));
    }
  });

  test("pulls an exact NuGet package through its advertised v3 package base", async () => {
    const calls = [];
    let exactChecks = 0;
    const indexUrl = "https://nuget.cloudsmith.io/workspace/repo/v3/index.json";
    const packageBase = "https://nuget.cloudsmith.io/workspace/repo/v3/flat/";
    const packageUrl = `${packageBase}serilog/3.1.1/serilog.3.1.1.nupkg`;
    const service = new UpstreamPullService({}, {
      credentialManager: { async getApiKey() { return "api-key"; } },
      checkPackageAbsence: async ({ workspace, repository }) => {
        exactChecks += 1;
        return {
          workspace,
          repository,
          absent: exactChecks === 1,
          present: exactChecks > 1,
          complete: true,
          stale: false,
        };
      },
      fetchImpl: async (url) => {
        calls.push(url);
        if (url === indexUrl) {
          return createResponse(200, JSON.stringify({
            resources: [{
              "@id": packageBase,
              "@type": "PackageBaseAddress/3.0.0",
            }],
          }));
        }
        if (url === packageUrl) return createResponse(200, "package");
        throw new Error(`Unexpected URL: ${url}`);
      },
    });

    const result = await service.execute({
      workspace: "workspace",
      repository: { slug: "repo" },
      plan: {
        pullableDependencies: [{
          name: "Serilog",
          version: "3.1.1",
          format: "nuget",
          cloudsmithStatus: "NOT_FOUND",
        }],
        skippedDependencies: [],
      },
    });

    assert.strictEqual(result.pullResult.cached, 1);
    assert.strictEqual(exactChecks, 2);
    assert.deepStrictEqual(calls, [indexUrl, packageUrl]);
  });

  test("pulls an exact Cargo crate through sparse index and config metadata", async () => {
    const calls = [];
    let exactChecks = 0;
    const checksum = "a".repeat(64);
    const indexUrl = "https://cargo.cloudsmith.io/workspace/repo/se/rd/serde";
    const configUrl = "https://cargo.cloudsmith.io/workspace/repo/config.json";
    const artifactUrl = `https://cargo.cloudsmith.io/workspace/repo/api/v1/crates/serde/1.0.200/${checksum}/download`;
    const service = new UpstreamPullService({}, {
      credentialManager: { async getApiKey() { return "api-key"; } },
      checkPackageAbsence: async ({ workspace, repository }) => {
        exactChecks += 1;
        return {
          workspace,
          repository,
          absent: exactChecks === 1,
          present: exactChecks > 1,
          complete: true,
          stale: false,
        };
      },
      fetchImpl: async (url) => {
        calls.push(url);
        if (url === indexUrl) {
          return createResponse(200, JSON.stringify({
            name: "serde",
            vers: "1.0.200",
            cksum: checksum,
          }));
        }
        if (url === configUrl) {
          return createResponse(200, JSON.stringify({
            dl: "https://cargo.cloudsmith.io/workspace/repo/api/v1/crates/{crate}/{version}/{sha256-checksum}/download",
          }));
        }
        if (url === artifactUrl) return createResponse(200, "artifact");
        throw new Error(`Unexpected URL: ${url}`);
      },
    });

    const result = await service.execute({
      workspace: "workspace",
      repository: { slug: "repo" },
      plan: {
        pullableDependencies: [{
          name: "serde",
          version: "1.0.200",
          format: "cargo",
          cloudsmithStatus: "NOT_FOUND",
        }],
        skippedDependencies: [],
      },
    });

    assert.strictEqual(result.pullResult.cached, 1);
    assert.strictEqual(exactChecks, 2);
    assert.deepStrictEqual(calls, [indexUrl, configUrl, artifactUrl]);
  });

  test("pulls only the qualifier-selected Maven artifact", async () => {
    const calls = [];
    let exactChecks = 0;
    const jarUrl = "https://dl.cloudsmith.io/basic/workspace/repo/maven/com/example/demo/1.2.3/demo-1.2.3-tests.jar";
    const service = new UpstreamPullService({}, {
      credentialManager: { async getApiKey() { return "api-key"; } },
      checkPackageAbsence: async ({ workspace, repository }) => {
        exactChecks += 1;
        return {
          workspace,
          repository,
          absent: exactChecks === 1,
          present: exactChecks > 1,
          complete: true,
          stale: false,
        };
      },
      fetchImpl: async (url) => {
        calls.push(url);
        if (url === jarUrl) return createResponse(200, "artifact");
        throw new Error(`Unexpected URL: ${url}`);
      },
    });

    const result = await service.execute({
      workspace: "workspace",
      repository: { slug: "repo" },
      plan: {
        pullableDependencies: [{
          name: "com.example:demo",
          version: "1.2.3",
          format: "maven",
          qualifiers: { type: "test-jar", classifier: "tests" },
          cloudsmithStatus: "NOT_FOUND",
        }],
        skippedDependencies: [],
      },
    });

    assert.strictEqual(result.pullResult.cached, 1);
    assert.strictEqual(exactChecks, 2);
    assert.deepStrictEqual(calls, [jarUrl]);
  });

  test("pulls a Docker platform manifest and every referenced image blob", async () => {
    const calls = [];
    const requestTimeouts = [];
    let exactChecks = 0;
    const platformReceipts = [];
    const manifestDigest = `sha256:${"a".repeat(64)}`;
    const configDigest = `sha256:${"b".repeat(64)}`;
    const layerDigest = `sha256:${"c".repeat(64)}`;
    const baseUrl = "https://docker.cloudsmith.io/v2/workspace/repo/library/redis";
    const tagUrl = `${baseUrl}/manifests/7.2`;
    const manifestUrl = `${baseUrl}/manifests/${encodeURIComponent(manifestDigest)}`;
    const configUrl = `${baseUrl}/blobs/${encodeURIComponent(configDigest)}`;
    const layerUrl = `${baseUrl}/blobs/${encodeURIComponent(layerDigest)}`;
    const service = new UpstreamPullService({}, {
      credentialManager: { async getApiKey() { return "api-key"; } },
      checkPackageAbsence: async ({ workspace, repository, dockerPlatformVerified }) => {
        exactChecks += 1;
        platformReceipts.push(dockerPlatformVerified === true);
        return {
          workspace,
          repository,
          absent: exactChecks === 1,
          present: exactChecks > 1,
          complete: true,
          stale: false,
        };
      },
      fetchImpl: async (url) => {
        calls.push(url);
        if (url === tagUrl) {
          return createResponse(200, JSON.stringify({
            schemaVersion: 2,
            manifests: [{
              digest: manifestDigest,
              platform: { os: "linux", architecture: "amd64" },
            }],
          }));
        }
        if (url === manifestUrl) {
          return createResponse(200, JSON.stringify({
            schemaVersion: 2,
            config: { digest: configDigest },
            layers: [{ digest: layerDigest }],
          }));
        }
        if (url === configUrl || url === layerUrl) return createResponse(200, "blob");
        throw new Error(`Unexpected URL: ${url}`);
      },
      setTimeout(_callback, delay) {
        requestTimeouts.push(delay);
        return {};
      },
      clearTimeout() {},
    });

    const result = await service.execute({
      workspace: "workspace",
      repository: { slug: "repo" },
      plan: {
        pullableDependencies: [{
          name: "redis",
          version: "7.2",
          format: "docker",
          qualifiers: { tag: "7.2", platform: "linux/amd64" },
          cloudsmithStatus: "NOT_FOUND",
        }],
        skippedDependencies: [],
      },
    });

    assert.strictEqual(result.pullResult.cached, 1);
    assert.strictEqual(exactChecks, 2);
    assert.deepStrictEqual(platformReceipts, [false, true]);
    assert.deepStrictEqual([...result.verificationReceipts.values()], [{
      dockerPlatformVerified: true,
    }]);
    assert.deepStrictEqual(calls, [tagUrl, manifestUrl, configUrl, layerUrl]);
    assert.deepStrictEqual(requestTimeouts, [30000, 30000, 120000, 120000]);
  });

  test("Docker blob redirects strip credentials before following safe storage URLs", async () => {
    const calls = [];
    const blobUrl = "https://docker.cloudsmith.io/v2/workspace/repo/library/demo/blobs/sha256%3Aabc";
    const storageUrl = "https://distribution.cloudfront.net/object?signature=value";
    const service = new UpstreamPullService({}, {
      fetchImpl: async (url, options) => {
        calls.push({ url, options });
        return url === blobUrl
          ? createResponse(307, "", { location: storageUrl })
          : createResponse(200, "blob");
      },
    });

    const result = await service._requestRegistry({
      method: "GET",
      url: blobUrl,
      redirectPolicy: "docker-blob",
      headers: {},
    }, "api-key", null, { captureBody: false });

    assert.strictEqual(result.statusCode, 200);
    assert.strictEqual(calls.length, 2);
    assert.match(calls[0].options.headers.Authorization, /^Basic /);
    assert.strictEqual(calls[1].url, storageUrl);
    assert.strictEqual(calls[1].options.headers.Authorization, undefined);

    const ordinaryService = new UpstreamPullService({}, {
      fetchImpl: async () => createResponse(307, "", { location: storageUrl }),
    });
    const rejected = await ordinaryService._requestRegistry({
      method: "GET",
      url: blobUrl,
      headers: {},
    }, "api-key", null, { captureBody: false });
    assert.strictEqual(rejected.statusCode, 0);
    assert.match(rejected.errorMessage, /redirect target was rejected/i);
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

  test("Dart registry metadata and archives use hosted Pub bearer authentication", async () => {
    const calls = [];
    let exactChecks = 0;
    const metadataUrl = "https://dart.cloudsmith.io/workspace/repo/api/packages/collection";
    const archiveUrl = "https://dart.cloudsmith.io/workspace/repo/packages/collection-1.19.0.tar.gz";
    const service = new UpstreamPullService({}, {
      credentialManager: { async getApiKey() { return "api-key"; } },
      checkPackageAbsence: async ({ workspace, repository }) => {
        exactChecks += 1;
        return {
          workspace,
          repository,
          absent: exactChecks === 1,
          present: exactChecks > 1,
          complete: true,
          stale: false,
        };
      },
      fetchImpl: async (url, options) => {
        calls.push({ url, authorization: options.headers.Authorization });
        if (url === metadataUrl) {
          return createResponse(200, JSON.stringify({
            name: "collection",
            versions: [{ version: "1.19.0", archive_url: archiveUrl }],
          }));
        }
        if (url === archiveUrl) return createResponse(200, "archive");
        throw new Error(`Unexpected URL: ${url}`);
      },
    });

    const result = await service.execute({
      workspace: "workspace",
      repository: { slug: "repo" },
      plan: {
        pullableDependencies: [{
          name: "collection",
          version: "1.19.0",
          format: "dart",
          cloudsmithStatus: "NOT_FOUND",
        }],
        skippedDependencies: [],
      },
    });

    assert.strictEqual(result.pullResult.cached, 1);
    assert.deepStrictEqual(calls, [
      { url: metadataUrl, authorization: "Bearer api-key" },
      { url: archiveUrl, authorization: "Bearer api-key" },
    ]);
  });

  test("Go and platform-qualified Ruby pulls dispatch their exact native artifacts", async () => {
    const cases = [
      {
        dependency: {
          name: "github.com/MyOrg/MyModule",
          version: "v1.2.3-RC1",
          format: "go",
          cloudsmithStatus: "NOT_FOUND",
        },
        expectedUrl: "https://golang.cloudsmith.io/workspace/repo/github.com/!my!org/!my!module/@v/v1.2.3-!r!c1.zip",
      },
      {
        dependency: {
          name: "nokogiri",
          version: "1.16.5",
          format: "ruby",
          qualifiers: { platform: "x86_64-linux" },
          cloudsmithStatus: "NOT_FOUND",
        },
        expectedUrl: "https://dl.cloudsmith.io/basic/workspace/repo/ruby/gems/nokogiri-1.16.5-x86_64-linux.gem",
      },
    ];

    for (const testCase of cases) {
      const calls = [];
      let exactChecks = 0;
      const service = new UpstreamPullService({}, {
        credentialManager: { async getApiKey() { return "api-key"; } },
        checkPackageAbsence: async ({ workspace, repository }) => {
          exactChecks += 1;
          return {
            workspace,
            repository,
            absent: exactChecks === 1,
            present: exactChecks > 1,
            complete: true,
            stale: false,
          };
        },
        fetchImpl: async (url, options) => {
          calls.push({ url, authorization: options.headers.Authorization });
          return createResponse(200, "artifact");
        },
      });
      const result = await service.execute({
        workspace: "workspace",
        repository: { slug: "repo" },
        plan: { pullableDependencies: [testCase.dependency], skippedDependencies: [] },
      });

      assert.strictEqual(result.pullResult.cached, 1);
      assert.deepStrictEqual(calls, [{
        url: testCase.expectedUrl,
        authorization: `Basic ${Buffer.from("token:api-key").toString("base64")}`,
      }]);
    }
  });

  test("an external AbortSignal cancels in-flight registry metadata before artifact dispatch", async () => {
    const controller = new AbortController();
    let fetchCalls = 0;
    let requestSignal = null;
    let fetchStarted;
    const started = new Promise(resolve => { fetchStarted = resolve; });
    const service = new UpstreamPullService({}, {
      credentialManager: { async getApiKey() { return "api-key"; } },
      checkPackageAbsence: async ({ workspace, repository }) => ({
        workspace,
        repository,
        absent: true,
        present: false,
        complete: true,
        stale: false,
      }),
      fetchImpl: async (_url, options) => {
        fetchCalls += 1;
        requestSignal = options.signal;
        fetchStarted();
        return new Promise(() => {});
      },
    });

    const pending = service.execute({
      workspace: "workspace",
      repository: { slug: "repo" },
      plan: {
        pullableDependencies: [{
          name: "left-pad",
          version: "1.3.0",
          format: "npm",
          cloudsmithStatus: "NOT_FOUND",
        }],
        skippedDependencies: [],
      },
    }, { signal: controller.signal });
    await started;
    controller.abort();
    const result = await pending;

    assert.strictEqual(result.canceled, true);
    assert.strictEqual(fetchCalls, 1);
    assert.strictEqual(requestSignal.aborted, true);
  });

  test("registry request timeouts are bounded and allow longer Docker blob transfers", async () => {
    let scheduledDelay = null;
    const service = new UpstreamPullService({}, {
      fetchImpl: async () => createResponse(200, "blob"),
      setTimeout(_callback, delay) {
        scheduledDelay = delay;
        return {};
      },
      clearTimeout() {},
    });

    const result = await service._requestRegistry({
      method: "GET",
      url: "https://docker.cloudsmith.io/v2/workspace/repo/library/example/blobs/sha256%3Aabc",
      headers: {},
    }, "api-key", null, { captureBody: false, timeoutMs: 10 * 60 * 1000 });

    assert.strictEqual(result.statusCode, 200);
    assert.strictEqual(scheduledDelay, 120000);
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

  test("registry redirects preserve credentials only across trusted hosts in the same repository", async () => {
    const calls = [];
    const authorizationHeader = `Basic ${Buffer.from("token:api-key").toString("base64")}`;
    const service = new UpstreamPullService({}, {
      fetchImpl: async (url, options) => {
        calls.push({ url, options });
        if (calls.length === 1) {
          return createResponse(302, "", {
            location: "https://npm.cloudsmith.io/workspace/repo/package.tgz?redirect=registry",
          });
        }
        return createResponse(200, "metadata");
      },
    });

    const result = await service._requestRegistry({
      method: "GET",
      url: "https://dl.cloudsmith.io/basic/workspace/repo/python/simple/artifact/",
      headers: {},
    }, "api-key", null, { captureBody: true });

    assert.strictEqual(result.statusCode, 200);
    assert.strictEqual(result.body, "metadata");
    assert.strictEqual(calls.length, 2);
    assert.strictEqual(calls[1].options.headers.Authorization, authorizationHeader);
    assert.strictEqual(
      calls[1].url,
      "https://npm.cloudsmith.io/workspace/repo/package.tgz?redirect=registry"
    );

    let crossRepositoryCalls = 0;
    const crossRepositoryService = new UpstreamPullService({}, {
      fetchImpl: async () => {
        crossRepositoryCalls += 1;
        return createResponse(302, "", {
          location: "https://npm.cloudsmith.io/workspace/other-repo/package.tgz",
        });
      },
    });
    const rejected = await crossRepositoryService._requestRegistry({
      method: "GET",
      url: "https://dl.cloudsmith.io/basic/workspace/repo/python/simple/artifact/",
      headers: {},
    }, "api-key", null, { captureBody: true });

    assert.strictEqual(rejected.statusCode, 0);
    assert.match(rejected.errorMessage, /redirect target was rejected/i);
    assert.strictEqual(crossRepositoryCalls, 1);
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
    assert.strictEqual(result.pullResult.errors, 3);
    assert.strictEqual(result.pullResult.authFailed, 3);
    assert.strictEqual(result.pullResult.skipped, 2);
    assert.deepStrictEqual(errors, [
      "Authentication failed. Check Cloudsmith authentication in Settings and retry.",
    ]);
  });

  test("bulk trigger workers release before package visibility and start dependency six", async () => {
    const visibility = deferred();
    const threeTriggersStarted = deferred();
    const triggeredKeys = new Set();
    const triggerStarts = [];
    let activeTriggers = 0;
    let maxActiveTriggers = 0;
    const dependencies = Array.from({ length: 100 }, (_, index) => ({
      name: `package-${index}`,
      version: "1.0.0",
      format: "npm",
      cloudsmithStatus: "ABSENT",
    }));
    const service = new UpstreamPullService({}, {
      credentialManager: { async getApiKey() { return "api-key"; } },
      fetchRepositories: async () => ({
        items: [{ slug: "repo", name: "Repo" }],
        complete: true,
      }),
      upstreamRuntime: {
        async getRepositoryUpstreamStateForFormats() {
          return completeRepositoryState({
            npm: [safeUpstream("npm", "npm", { is_active: true })],
          });
        },
      },
      checkPackageAbsence: async ({ workspace, repository, dependency }) => {
        if (!triggeredKeys.has(getDependencyArtifactKey(dependency))) {
          return {
            workspace,
            repository,
            absent: true,
            present: false,
            complete: true,
            stale: false,
          };
        }
        await visibility.promise;
        return {
          workspace,
          repository,
          absent: false,
          present: true,
          complete: true,
          stale: false,
        };
      },
      showQuickPick: async items => items[0],
      showWarningMessage: async (_message, _options, action) => action,
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
    });
    service._pullDependency = async (_workspace, _repository, dependency) => {
      activeTriggers += 1;
      maxActiveTriggers = Math.max(maxActiveTriggers, activeTriggers);
      triggerStarts.push(dependency.name);
      triggeredKeys.add(getDependencyArtifactKey(dependency));
      if (triggerStarts.length === 3) threeTriggersStarted.resolve();
      await Promise.resolve();
      activeTriggers -= 1;
      return {
        dependency,
        status: "pending",
        errorMessage: null,
        networkError: false,
        triggerSucceeded: true,
      };
    };

    const pending = service.run({
      workspace: "workspace",
      dependencies,
    });
    await threeTriggersStarted.promise;
    await new Promise(resolve => setImmediate(resolve));
    await new Promise(resolve => setImmediate(resolve));
    const sixthStartedBeforeVisibility = triggerStarts.includes("package-5");
    visibility.resolve();
    const result = await pending;

    assert.strictEqual(sixthStartedBeforeVisibility, true);
    assert.ok(maxActiveTriggers <= 5);
    assert.strictEqual(result.pullResult.cached, 0);
    assert.strictEqual(result.pullResult.triggeredUnconfirmed, 100);
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

  test("never exposes registry request URLs through status or terminal details", async () => {
    const statuses = [];
    const dependency = {
      name: "private-package",
      version: "1.0.0",
      format: "npm",
      cloudsmithStatus: "NOT_FOUND",
    };
    const service = new UpstreamPullService({}, {
      credentialManager: { async getApiKey() { return "api-key"; } },
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
      showWarningMessage: async () => {},
    });
    service._pullDependency = async () => ({
      dependency,
      status: "cached",
      errorMessage: null,
      requestUrl: "https://user:pass@npm.cloudsmith.io/private/repo/package?token=secret#fragment",
      networkError: false,
    });

    const result = await service.execute({
      workspace: "private-workspace",
      repository: { slug: "private-repo" },
      plan: { pullableDependencies: [dependency], skippedDependencies: [] },
    }, {
      onStatus(detail) { statuses.push(detail); },
    });

    assert.ok(statuses.length >= 2);
    assert.ok(statuses.every(detail => !("requestUrl" in detail)));
    assert.ok(result.pullResult.details.every(detail => !("requestUrl" in detail)));
    assert.ok(!JSON.stringify(statuses).includes("token=secret"));
    assert.ok(!JSON.stringify(result.pullResult).includes("private-workspace"));
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
      connectionManager: {
        getState() { return { ...accountState }; },
        getAuthenticationCapabilities: apiKeyCapabilities,
      },
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
      connectionManager: {
        getState() { return { ...accountState }; },
        getAuthenticationCapabilities: apiKeyCapabilities,
      },
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

  test("prepare and prepareSingle contain runtime scope supersession without UI publication", async () => {
    const cases = [
      { method: "prepare", kind: "stale", transitionAccount: true },
      { method: "prepareSingle", kind: "stale", transitionAccount: true },
      { method: "prepare", kind: "disposed", transitionAccount: false },
      { method: "prepareSingle", kind: "disposed", transitionAccount: false },
    ];

    for (const testCase of cases) {
      let state = {
        activationId: "account-a",
        accountEpoch: 1,
        sessionConnected: true,
      };
      let scopeCalls = 0;
      let inspectionCalls = 0;
      const uiCalls = [];
      const service = new UpstreamPullService({}, {
        connectionManager: {
          getState() { return { ...state }; },
          getAuthenticationCapabilities: apiKeyCapabilities,
        },
        fetchRepositories: async () => ({
          items: [{ slug: "repo", name: "Repo" }],
          complete: true,
        }),
        upstreamRuntime: {
          createOperationScope(options) {
            scopeCalls += 1;
            assert.deepStrictEqual(options.account, {
              activationId: "account-a",
              accountEpoch: 1,
            });
            if (testCase.transitionAccount) {
              state = {
                activationId: "account-b",
                accountEpoch: 2,
                sessionConnected: true,
              };
            }
            const error = new Error(`runtime ${testCase.kind}`);
            error.name = "UpstreamRuntimeError";
            error.kind = testCase.kind;
            throw error;
          },
          async getRepositoryUpstreamStateForFormats() {
            inspectionCalls += 1;
            throw new Error("inspection must not start");
          },
        },
        showQuickPick: async () => { uiCalls.push("quick-pick"); return null; },
        showErrorMessage: async () => { uiCalls.push("error"); },
        showInformationMessage: async () => { uiCalls.push("information"); },
        showWarningMessage: async () => { uiCalls.push("warning"); },
      });
      const dependency = {
        name: "requests",
        version: "2.31.0",
        format: "python",
        cloudsmithStatus: "NOT_FOUND",
      };
      const prepared = testCase.method === "prepare"
        ? await service.prepare({ workspace: "workspace", dependencies: [dependency] })
        : await service.prepareSingle({ workspace: "workspace", dependency });

      assert.strictEqual(prepared, null, `${testCase.method}:${testCase.kind}`);
      assert.strictEqual(scopeCalls, 1, `${testCase.method}:${testCase.kind}`);
      assert.strictEqual(inspectionCalls, 0, `${testCase.method}:${testCase.kind}`);
      assert.deepStrictEqual(uiCalls, [], `${testCase.method}:${testCase.kind}`);
    }
  });

  test("scope acquisition still rejects programming and unrelated runtime errors", async () => {
    const programmingError = new TypeError("invalid scope contract");
    programmingError.name = "UpstreamRuntimeError";
    programmingError.kind = "stale";
    const unrelatedError = new Error("unrelated runtime failure");
    unrelatedError.name = "UpstreamRuntimeError";
    unrelatedError.kind = "failed";
    const foreignStaleError = new Error("foreign stale failure");
    foreignStaleError.kind = "stale";

    for (const expectedError of [programmingError, unrelatedError, foreignStaleError]) {
      const uiCalls = [];
      const service = new UpstreamPullService({}, {
        fetchRepositories: async () => ({ items: [{ slug: "repo" }], complete: true }),
        upstreamRuntime: {
          createOperationScope() {
            throw expectedError;
          },
          async getRepositoryUpstreamStateForFormats() {
            throw new Error("inspection must not start");
          },
        },
        showQuickPick: async () => { uiCalls.push("quick-pick"); return null; },
        showErrorMessage: async () => { uiCalls.push("error"); },
        showInformationMessage: async () => { uiCalls.push("information"); },
        showWarningMessage: async () => { uiCalls.push("warning"); },
      });

      await assert.rejects(
        service.prepareSingle({
          workspace: "workspace",
          dependency: {
            name: "requests",
            version: "2.31.0",
            format: "python",
            cloudsmithStatus: "NOT_FOUND",
          },
        }),
        error => error === expectedError
      );
      assert.deepStrictEqual(uiCalls, []);
    }
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
      upstreamRuntime: {
        async getRepositoryUpstreamStateForFormats(_workspace, repo) {
          return completeRepositoryState({
            python: repo === "repo-b"
              ? [safeUpstream("python", "PyPI", { is_active: true })]
              : [],
          });
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
      upstreamRuntime: {
        async getRepositoryUpstreamStateForFormats(_workspace, _repo, _formats, options) {
          inspectionCalls += 1;
          assert.strictEqual(options.signal.aborted, false);
          await gate.promise;
          return {
            groupedUpstreams: new Map(),
            complete: false,
            failedFormats: [],
            uninspectedFormats: ["python"],
            unsupportedFormats: [],
            outcomes: [{
              format: "python",
              apiFormat: "python",
              state: "cancelled",
              authoritative: false,
            }],
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
      connectionManager: {
        getState() { return { ...state }; },
        getAuthenticationCapabilities: apiKeyCapabilities,
      },
      fetchRepositories: async (_workspace, operation) => {
        assert.deepStrictEqual(operation.account, {
          activationId: "account-a",
          accountEpoch: 1,
        });
        return repositories.promise;
      },
      upstreamRuntime: {
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

  test("repository QuickPick cancels immediately when the captured account changes", async () => {
    let state = {
      activationId: "account-a",
      accountEpoch: 1,
      sessionConnected: true,
    };
    const listeners = new Set();
    const pickerStarted = deferred();
    const connectionManager = {
      getState() { return { ...state }; },
      getAuthenticationCapabilities: apiKeyCapabilities,
      onDidChange(listener) {
        listeners.add(listener);
        return { dispose() { listeners.delete(listener); } };
      },
      switchAccount() {
        state = { ...state, activationId: "account-b", accountEpoch: 2 };
        for (const listener of [...listeners]) listener(this.getState());
      },
    };
    let pickerToken = null;
    const service = new UpstreamPullService({}, {
      connectionManager,
      fetchRepositories: async () => ({
        items: [{ slug: "repo-b", name: "Repo B" }],
        complete: true,
      }),
      upstreamRuntime: {
        async getRepositoryUpstreamStateForFormats() {
          return completeRepositoryState({
            npm: [safeUpstream("npm", "npm", { is_active: true })],
          });
        },
      },
      showQuickPick: async (_items, _options, token) => {
        pickerToken = token;
        pickerStarted.resolve();
        return new Promise(() => {});
      },
      showWarningMessage: async () => {},
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
    });

    const pending = service.prepareSingle({
      workspace: "workspace",
      dependency: {
        name: "target-package",
        version: "1.0.0",
        format: "npm",
        cloudsmithStatus: "ABSENT",
      },
    });
    await pickerStarted.promise;
    connectionManager.switchAccount();

    assert.strictEqual(await pending, null);
    assert.strictEqual(pickerToken.isCancellationRequested, true);
    assert.strictEqual(listeners.size, 0);
  });

  test("target absence completed by a superseded account cannot reach confirmation", async () => {
    let state = {
      activationId: "account-a",
      accountEpoch: 1,
      sessionConnected: true,
    };
    const absence = deferred();
    let confirmations = 0;
    const service = new UpstreamPullService({}, {
      connectionManager: {
        getState() { return { ...state }; },
        getAuthenticationCapabilities: apiKeyCapabilities,
      },
      fetchRepositories: async () => ({
        items: [{ slug: "repo-b", name: "Repo B" }],
        complete: true,
      }),
      upstreamRuntime: {
        async getRepositoryUpstreamStateForFormats() {
          return completeRepositoryState({
            npm: [safeUpstream("npm", "npm", { is_active: true })],
          });
        },
      },
      checkPackageAbsence: async () => absence.promise,
      showQuickPick: async items => items[0],
      showWarningMessage: async () => { confirmations += 1; },
      showErrorMessage: async () => {},
      showInformationMessage: async () => {},
    });

    const pending = service.prepare({
      workspace: "workspace",
      dependencies: [{
        name: "target-package",
        version: "1.0.0",
        format: "npm",
        cloudsmithStatus: "ABSENT",
      }],
    });
    await new Promise(resolve => setImmediate(resolve));
    state = { ...state, activationId: "account-b", accountEpoch: 2 };
    absence.resolve({
      workspace: "workspace",
      repository: "repo-b",
      absent: true,
      present: false,
      complete: true,
      stale: false,
    });

    assert.strictEqual(await pending, null);
    assert.strictEqual(confirmations, 0);
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

  test("uses real canonical outcomes for mixed inspectable and non-inspectable pull preparation", async () => {
    const requests = [];
    const warnings = [];
    let repositoryFetches = 0;
    const account = {
      getState() {
        return { activationId: "account-a", accountEpoch: 1, sessionConnected: true };
      },
      getAuthenticationCapabilities: apiKeyCapabilities,
    };
    const checker = new UpstreamChecker({}, {
      connectionManager: account,
      cloudsmithAPI: {
        async get(endpoint) {
          requests.push(endpoint);
          return apiSuccess([{
            name: "npmjs",
            slug_perm: "npmjs",
            upstream_url: "https://registry.npmjs.org/",
            is_active: true,
          }]);
        },
      },
    });
    const service = new UpstreamPullService({}, {
      connectionManager: account,
      upstreamRuntime: checker,
      fetchRepositories: async () => {
        repositoryFetches += 1;
        return { items: [{ slug: "repo", name: "Repo" }], complete: true };
      },
      showQuickPick: async items => items[0],
      showWarningMessage: async (message, _options, action) => {
        warnings.push(message);
        return action;
      },
      showInformationMessage: async () => {},
      showErrorMessage: async () => {},
    });

    const prepared = await service.prepare({
      workspace: "workspace",
      dependencies: [
        { name: "package-a", version: "1.0.0", format: "NPM", cloudsmithStatus: "ABSENT" },
        { name: "archive", version: "1.0.0", format: "raw", cloudsmithStatus: "ABSENT" },
      ],
    });

    assert.ok(prepared);
    assert.strictEqual(repositoryFetches, 1);
    assert.strictEqual(requests.length, 1);
    assert.match(requests[0], /upstream\/npm\//);
    assert.doesNotMatch(requests[0], /upstream\/raw\//);
    assert.strictEqual(prepared.repositorySearchComplete, true);
    assert.deepStrictEqual(prepared.plan.pullableDependencies.map(item => item.format), ["NPM"]);
    assert.strictEqual(prepared.plan.skippedDependencies.length, 1);
    assert.strictEqual(prepared.plan.skippedDependencies[0].reason, "no_pull_support");
    assert.ok(warnings.every(message => !/inspection was incomplete/i.test(message)));
    assert.match(warnings[0], /1 Raw will be skipped/);
  });

  test("short-circuits zero executable formats before repository enumeration", async () => {
    for (const format of ["raw", "terraform", "alpine"]) {
      let repositoryFetches = 0;
      const messages = [];
      const service = new UpstreamPullService({}, {
        fetchRepositories: async () => {
          repositoryFetches += 1;
          return { items: [{ slug: "repo" }], complete: true };
        },
        showInformationMessage: async message => messages.push(message),
        showWarningMessage: async () => {},
        showErrorMessage: async () => {},
      });
      const prepared = await service.prepare({
        workspace: "workspace",
        dependencies: [{
          name: "package-a", version: "1.0.0", format, cloudsmithStatus: "ABSENT",
        }],
      });
      assert.strictEqual(prepared, null, format);
      assert.strictEqual(repositoryFetches, 0, format);
      assert.match(messages[0], /Pull-through caching is not available/i, format);
      assert.doesNotMatch(messages[0], /incomplete/i, format);
    }
  });

  test("prepareSingle reports a recognized non-inspectable format as unavailable", async () => {
    let repositoryFetches = 0;
    const messages = [];
    const service = new UpstreamPullService({}, {
      fetchRepositories: async () => {
        repositoryFetches += 1;
        return { items: [{ slug: "repo" }], complete: true };
      },
      showInformationMessage: async message => messages.push(message),
      showWarningMessage: async () => {},
      showErrorMessage: async () => {},
    });
    const prepared = await service.prepareSingle({
      workspace: "workspace",
      dependency: {
        name: "archive", version: "1.0.0", format: "raw", cloudsmithStatus: "ABSENT",
      },
    });
    assert.strictEqual(prepared, null);
    assert.strictEqual(repositoryFetches, 0);
    assert.match(messages[0], /not available for Raw dependencies/i);
    assert.doesNotMatch(messages[0], /incomplete|failed/i);
  });

  test("proves pull inspection completeness from canonical authoritative outcomes", async () => {
    const cases = [
      {
        name: "inspectable success",
        formats: [" NPM "],
        state: completeRepositoryState({ npm: [] }),
        expected: true,
      },
      {
        name: "inspectable failure",
        formats: ["npm"],
        state: {
          groupedUpstreams: new Map(), complete: false,
          failedFormats: ["npm"], uninspectedFormats: [], unsupportedFormats: [],
          outcomes: [{ format: "npm", apiFormat: "npm", state: "failed", authoritative: false }],
        },
        expected: false,
      },
      {
        name: "mixed inspectable and neutral",
        formats: ["NPM", "raw"],
        state: {
          ...completeRepositoryState({ npm: [] }),
          complete: true,
          unsupportedFormats: ["raw"],
          outcomes: [
            { format: "npm", apiFormat: "npm", state: "success", authoritative: true },
            { format: "raw", apiFormat: null, state: "unsupported", authoritative: true },
          ],
        },
        expected: true,
      },
      {
        name: "neutral only",
        formats: ["raw", "terraform"],
        state: {
          groupedUpstreams: new Map(), complete: false,
          failedFormats: [], uninspectedFormats: [], unsupportedFormats: ["raw", "terraform"],
          outcomes: [
            { format: "raw", apiFormat: null, state: "unsupported", authoritative: true },
            { format: "terraform", apiFormat: null, state: "unsupported", authoritative: true },
          ],
        },
        expected: true,
      },
      {
        name: "unknown",
        formats: ["unknown"],
        state: completeRepositoryState({ npm: [] }),
        expected: false,
      },
      {
        name: "empty",
        formats: [],
        state: completeRepositoryState({ npm: [] }),
        expected: false,
      },
      {
        name: "missing outcome",
        formats: ["npm"],
        state: {
          groupedUpstreams: new Map(), complete: true,
          failedFormats: [], uninspectedFormats: [], unsupportedFormats: [], outcomes: [],
        },
        expected: false,
      },
      {
        name: "duplicate outcome",
        formats: ["npm"],
        state: {
          groupedUpstreams: new Map(), complete: true,
          failedFormats: [], uninspectedFormats: [], unsupportedFormats: [],
          outcomes: [
            { format: "npm", apiFormat: "npm", state: "success", authoritative: true },
            { format: "npm", apiFormat: "npm", state: "success", authoritative: true },
          ],
        },
        expected: false,
      },
      {
        name: "inspectable mislabeled unsupported",
        formats: ["npm"],
        state: {
          groupedUpstreams: new Map(), complete: false,
          failedFormats: [], uninspectedFormats: [], unsupportedFormats: ["npm"], outcomes: [],
        },
        expected: false,
      },
      {
        name: "success contradicts failed list",
        formats: ["npm"],
        state: {
          ...completeRepositoryState({ npm: [] }),
          failedFormats: ["npm"],
        },
        expected: false,
      },
      {
        name: "requested subset succeeds while another inspected format explains incompleteness",
        formats: ["npm"],
        state: {
          groupedUpstreams: new Map(), complete: false, incomplete: true,
          failedFormats: ["python"], uninspectedFormats: [], unsupportedFormats: [],
          outcomes: [
            { format: "npm", apiFormat: "npm", state: "success", authoritative: true },
            { format: "python", apiFormat: "python", state: "failed", authoritative: false },
          ],
        },
        expected: true,
      },
      {
        name: "authoritative outcome contradicts incomplete aggregate",
        formats: ["npm"],
        state: {
          ...completeRepositoryState({ npm: [] }),
          complete: false,
        },
        expected: false,
      },
    ];

    for (const testCase of cases) {
      const service = new UpstreamPullService({}, {
        upstreamRuntime: {
          async getRepositoryUpstreamStateForFormats() { return testCase.state; },
        },
      });
      const result = await service._findMatchingRepositories(
        "workspace", [{ slug: "repo" }], testCase.formats,
        service._createPreparationOperation(null, null)
      );
      assert.strictEqual(result.complete, testCase.expected, testCase.name);
    }
  });

  test("requires canonical requested grouped data while retaining safe positive matches", async () => {
    const valid = safeUpstream("npm", "npmjs", { is_active: true });
    const missingOrigin = { ...valid };
    delete missingOrigin.origin;
    const cases = [
      ["missing origin", [valid, missingOrigin], 1],
      ["privileged field", [valid, { ...valid, upstream_url: "https://secret.example/path" }], 1],
      ["wrong format", [valid, safeUpstream("python", "PyPI")], 1],
      ["malformed record", [valid, {}], 1],
      ["non-array format entry", { ...valid }, 0],
    ];

    for (const [name, groupedValue, expectedMatches] of cases) {
      const state = completeRepositoryState({ npm: [] });
      state.groupedUpstreams.set("npm", groupedValue);
      const service = new UpstreamPullService({}, {
        upstreamRuntime: {
          async getRepositoryUpstreamStateForFormats() { return state; },
        },
      });
      const result = await service._findMatchingRepositories(
        "workspace", [{ slug: "repo" }], ["npm"],
        service._createPreparationOperation(null, null)
      );
      assert.strictEqual(result.complete, false, name);
      assert.strictEqual(result.matches.length, expectedMatches, name);
      if (expectedMatches > 0) {
        assert.deepStrictEqual(result.matches[0].activeUpstreamsByFormat.get("npm"), [valid], name);
      }
    }
  });

  test("treats absent and empty requested grouped entries as valid verified absence", async () => {
    for (const [name, groupedUpstreams] of [
      ["absent", new Map()],
      ["empty", new Map([["npm", []]])],
    ]) {
      const state = completeRepositoryState({ npm: [] });
      state.groupedUpstreams = groupedUpstreams;
      const service = new UpstreamPullService({}, {
        upstreamRuntime: {
          async getRepositoryUpstreamStateForFormats() { return state; },
        },
      });
      const result = await service._findMatchingRepositories(
        "workspace", [{ slug: "repo" }], ["npm"],
        service._createPreparationOperation(null, null)
      );
      assert.strictEqual(result.complete, true, name);
      assert.deepStrictEqual(result.matches, [], name);
    }
  });
});

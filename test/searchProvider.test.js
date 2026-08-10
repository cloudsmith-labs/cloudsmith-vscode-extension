const assert = require("assert");
const { SearchProvider } = require("../views/searchProvider");

suite("SearchProvider atomic search state", () => {
  let providers;

  setup(() => {
    providers = [];
  });

  teardown(() => {
    for (const provider of providers) {
      provider.dispose();
    }
  });

  test("commits one deeply frozen canonical snapshot", async () => {
    const { provider } = createProvider({
      fetchPage: async () => page([pkg("artifact")]),
    });

    await provider.search("workspace-a", "name:artifact");

    assert.strictEqual(provider.currentWorkspace, "workspace-a");
    assert.strictEqual(provider.currentQuery, "name:artifact");
    assert.strictEqual(provider.currentRepo, null);
    assert.strictEqual(provider.searchResults.length, 1);
    assert(Object.isFrozen(provider.state));
    assert(Object.isFrozen(provider.state.committed));
    assert(Object.isFrozen(provider.state.committed.descriptor));
    assert(Object.isFrozen(provider.state.committed.results));
    assert(Object.isFrozen(provider.state.committed.results[0]));
    assert(Object.isFrozen(provider.state.committed.diagnostics));
  });

  test("preserves an unknown total for page-total-only single-scope search", async () => {
    const { provider } = createProvider({
      pageSize: 2,
      fetchPage: async () => page([pkg("one"), pkg("two")], {
        pageSize: 2,
        pageTotal: 2,
        count: null,
        countAuthoritative: false,
      }),
    });

    await provider.search("workspace-a", "name:artifact");

    assert.strictEqual(provider.state.committed.totalCount, null);
    const items = (await provider.getChildren()).map(node => node.getTreeItem());
    assert.match(items[0].description, /2 packages loaded \(more available\)/);
    const loadMore = items.find(item => item.label.startsWith("Load more results"));
    assert.strictEqual(loadMore.label, "Load more results (2 loaded; page 1 of 2)");
    assert(!JSON.stringify(items).includes("null total"));
  });

  test("freezes the node snapshot without freezing its injected connection manager", async () => {
    const connectionManager = createConnectionManager();
    connectionManager.callerOwned = { mutable: true };
    const { provider } = createProvider({
      connectionManager,
      fetchPage: async () => page([pkg("artifact")]),
    });

    await provider.search("workspace-a", "artifact");

    const committedNode = provider.searchResults[0];
    assert.strictEqual(Object.isFrozen(committedNode), true);
    assert.strictEqual(committedNode._connectionManager, connectionManager);
    assert.strictEqual(Object.isFrozen(connectionManager), false);
    assert.strictEqual(Object.isFrozen(connectionManager.callerOwned), false);
    connectionManager.callerOwned.mutable = false;
    connectionManager.additionalCallerState = "still mutable";
    assert.strictEqual(connectionManager.callerOwned.mutable, false);
    assert.strictEqual(connectionManager.additionalCallerState, "still mutable");
  });

  test("canonicalizes every retained field without freezing the API response", async () => {
    const responsePackage = pkg("artifact", {
      is_copyable: true,
      tags: { info: ["upstream"], nested: { source: "api" } },
      license: "MIT",
      licenseInfo: { metadata: { label: "caller-owned", nested: { secret: true } } },
      status_str: { nested: { value: "Quarantined" } },
      slug: { nested: "caller-owned" },
      uploaded_at: { nested: "caller-owned" },
      status_reason: { nested: "caller-owned" },
      policy_violated: true,
      max_severity: { nested: "Critical" },
      vulnerability_scan_results_url: { nested: "https://example.invalid" },
      cdn_url: { nested: "https://example.invalid" },
    });
    const { provider } = createProvider({
      fetchPage: async () => page([responsePackage]),
    });

    await provider.search("workspace-a", "artifact");

    const committedNode = provider.searchResults[0];
    assert.notStrictEqual(committedNode.tags_raw, responsePackage.tags);
    assert.notStrictEqual(committedNode.licenseInfo, responsePackage.licenseInfo);
    assert.deepStrictEqual(committedNode.tags_raw, { info: ["upstream"] });
    assert.strictEqual(committedNode.tags_raw.nested, undefined);
    assert.strictEqual(Object.isFrozen(committedNode.licenseInfo.metadata), true);
    assert.strictEqual(committedNode.licenseInfo.metadata.label, "Permissive");
    assert.strictEqual(committedNode.status_str.value, null);
    assert.strictEqual(committedNode.slug.value, null);
    assert.strictEqual(committedNode.uploaded_at.value, null);
    assert.strictEqual(committedNode.status_reason, null);
    assert.strictEqual(committedNode.policy_violated, true);
    assert.strictEqual(committedNode.max_severity, null);
    assert.strictEqual(committedNode.vulnerability_scan_results_url, null);
    assert.strictEqual(committedNode.cdn_url, null);
    assert.strictEqual(committedNode.is_copyable, true);
    assert.strictEqual(Object.isFrozen(responsePackage), false);
    assert.strictEqual(Object.isFrozen(responsePackage.tags), false);
    assert.strictEqual(Object.isFrozen(responsePackage.tags.info), false);
    assert.strictEqual(Object.isFrozen(responsePackage.licenseInfo), false);
    assert.strictEqual(Object.isFrozen(responsePackage.status_str.nested), false);
    responsePackage.tags.info.push("caller-remains-mutable");
    responsePackage.licenseInfo.metadata.label = "mutated";
    responsePackage.status_str.nested.value = "mutated";
    assert.deepStrictEqual(committedNode.tags_raw.info, ["upstream"]);
    assert.strictEqual(committedNode.status_str.value, null);
  });

  test("uses the shared vulnerability indicator contract for retained packages", async () => {
    const packages = [
      pkg("no-evidence"),
      pkg("known-clean", { num_vulnerabilities: "0" }),
      pkg("detected", { has_vulnerabilities: true }),
      pkg("conflicting", {
        num_vulnerabilities: 0,
        vulnerability_scan_results_count: 2,
      }),
    ];
    const { provider } = createProvider({
      fetchPage: async () => page(packages),
    });

    await provider.search("workspace-a", "artifact");

    assert.deepStrictEqual(
      provider.searchResults.map(node => node.num_vulnerabilities),
      [null, 0, -1, -1]
    );
  });

  test("beginSearch synchronously supersedes the prior intent before either executes", async () => {
    let fetchCount = 0;
    const { provider } = createProvider({
      fetchPage: async () => {
        fetchCount += 1;
        return page([pkg("artifact")]);
      },
    });
    const first = provider.beginSearch({ kind: "workspace", workspace: "workspace-a", query: "first" });
    const second = provider.beginSearch({ kind: "workspace", workspace: "workspace-a", query: "second" });

    await provider.executeSearch(first);
    await provider.executeSearch(second);

    assert.strictEqual(fetchCount, 1);
    assert.strictEqual(provider.currentQuery, "second");
  });

  test("a stale root success cannot replace or refresh over the latest result", async () => {
    const slow = deferred();
    const fast = deferred();
    const { provider, messages } = createProvider({
      fetchPage: async (_endpoint, _page, _size, query) => (
        query === "slow" ? slow.promise : fast.promise
      ),
    });
    let changeCount = 0;
    provider.onDidChangeTreeData(() => { changeCount += 1; });

    const slowSearch = provider.search("workspace-a", "slow");
    const fastSearch = provider.search("workspace-a", "fast");
    fast.resolve(page([pkg("new-result")]));
    await fastSearch;
    const changesAfterLatestCommit = changeCount;
    slow.resolve(page([pkg("old-result")]));
    await slowSearch;

    assert.strictEqual(provider.currentQuery, "fast");
    assert.strictEqual(provider.searchResults[0].name, "new-result");
    assert.deepStrictEqual(messages.error, []);
    assert.strictEqual(changeCount, changesAfterLatestCommit);
  });

  test("a stale root failure publishes no notification or failure state", async () => {
    const slow = deferred();
    const { provider, messages } = createProvider({
      fetchPage: async (_endpoint, _page, _size, query) => {
        if (query === "slow") {
          return slow.promise;
        }
        return page([pkg("new-result")]);
      },
    });

    const slowSearch = provider.search("workspace-a", "slow");
    await provider.search("workspace-a", "fast");
    slow.resolve(failedPage("forbidden"));
    await slowSearch;

    assert.strictEqual(provider.currentQuery, "fast");
    assert.strictEqual(provider.state.failure, null);
    assert.deepStrictEqual(messages.error, []);
  });

  test("unexpected search exceptions never reach user-facing diagnostics", async () => {
    const secret = "csa_secret-value-from-thrown-exception";
    const { provider, messages } = createProvider({
      fetchPage: async () => { throw new Error(`${secret}${"x".repeat(10000)}`); },
    });

    await provider.search("workspace-a", "artifact");

    assert.strictEqual(messages.error.length, 1);
    assert.strictEqual(messages.error[0].includes(secret), false);
    assert(messages.error[0].length < 200);
    assert.strictEqual(provider.state.failure.message, messages.error[0]);
  });

  test("current failure preserves the previously committed session", async () => {
    let shouldFail = false;
    const { provider, messages } = createProvider({
      fetchPage: async () => shouldFail ? failedPage("rate_limited") : page([pkg("prior")]),
    });
    await provider.search("workspace-a", "prior");
    const prior = provider.state.committed;
    shouldFail = true;

    await provider.search("workspace-a", "replacement");

    assert.strictEqual(provider.state.committed, prior);
    assert.strictEqual(provider.state.failure.descriptor.query, "replacement");
    assert.strictEqual(messages.error.length, 1);
    const children = await provider.getChildren();
    assert(children.some(node => node.getTreeItem().label === "Search failed"));
  });

  test("cancellation preserves the committed snapshot without a failure notification", async () => {
    let cancelled = false;
    const { provider, messages } = createProvider({
      fetchPage: async () => cancelled ? failedPage("cancelled") : page([pkg("prior")]),
    });
    await provider.search("workspace-a", "prior");
    const prior = provider.state.committed;
    cancelled = true;

    await provider.search("workspace-a", "cancelled");

    assert.strictEqual(provider.state.committed, prior);
    assert.strictEqual(provider.state.failure, null);
    assert.deepStrictEqual(messages.error, []);
  });

  test("account epoch change aborts and clears in-flight account data", async () => {
    const pending = deferred();
    const connectionManager = createConnectionManager();
    const { provider } = createProvider({
      connectionManager,
      fetchPage: async () => pending.promise,
    });
    const search = provider.search("workspace-a", "slow");

    connectionManager.update({ accountEpoch: 1, sessionConnected: true });
    pending.resolve(page([pkg("stale")]));
    await search;

    assert.strictEqual(provider.state.committed, null);
    assert.strictEqual(provider.state.pending, null);
  });

  test("a same-epoch session disconnect aborts and suppresses root publication", async () => {
    const pending = deferred();
    const connectionManager = createConnectionManager();
    const { provider } = createProvider({
      connectionManager,
      fetchPage: async () => pending.promise,
    });
    const search = provider.search("workspace-a", "slow");

    connectionManager.update({ sessionConnected: false, status: "absent" });
    pending.resolve(page([pkg("stale")]));
    await search;

    assert.strictEqual(provider.state.committed, null);
    assert.strictEqual(provider.state.pending, null);
    assert.deepStrictEqual(provider.searchResults, []);
    const nodes = await provider.getChildren();
    assert.strictEqual(nodes[0].getTreeItem().label, "Connect to Cloudsmith");
  });

  test("candidate validation with the same connected session preserves in-flight work", async () => {
    const pending = deferred();
    const connectionManager = createConnectionManager();
    const { provider } = createProvider({
      connectionManager,
      fetchPage: async () => pending.promise,
    });
    const search = provider.search("workspace-a", "slow");

    connectionManager.update({ sessionConnected: true, status: "validating" });
    connectionManager.update({ sessionConnected: true, status: "connected" });
    pending.resolve(page([pkg("preserved")]));
    await search;

    assert.strictEqual(provider.state.committed.descriptor.query, "slow");
    assert.deepStrictEqual(provider.searchResults.map(node => node.name), ["preserved"]);
  });

  test("an activation change with the same epoch invalidates a pending page", async () => {
    const secondPage = deferred();
    const connectionManager = createConnectionManager();
    const { provider } = createProvider({
      connectionManager,
      pageSize: 2,
      fetchPage: async (_endpoint, requestedPage) => (
        requestedPage === 1
          ? page([pkg("one"), pkg("two")], { pageTotal: 2, count: 3, pageSize: 2 })
          : secondPage.promise
      ),
    });
    await provider.search("workspace-a", "artifact");
    const loading = provider.loadNextPage();

    connectionManager.update({ activationId: "activation-b" });
    secondPage.resolve(page([pkg("stale")], {
      requestedPage: 2,
      pageTotal: 2,
      count: 3,
      pageSize: 2,
    }));
    await loading;

    assert.strictEqual(provider.state.committed, null);
    assert.deepStrictEqual(provider.searchResults, []);
  });

  test("does not dispatch a search while disconnected", async () => {
    let fetches = 0;
    const connectionManager = createConnectionManager({
      sessionConnected: false,
      status: "absent",
    });
    const { provider } = createProvider({
      connectionManager,
      fetchPage: async () => {
        fetches += 1;
        return page([]);
      },
    });

    await provider.search("workspace-a", "artifact");

    assert.strictEqual(fetches, 0);
    assert.strictEqual(provider.state.pending, null);
  });

  test("requires an exact namespace and repository response scope", async () => {
    const { provider, messages } = createProvider({
      fetchPage: async () => page([pkg("wrong", { repository: "repo-b" })]),
    });

    await provider.search("workspace-a", "name:wrong", 1, "repo-a");

    assert.strictEqual(provider.state.committed, null);
    assert.strictEqual(provider.state.failure.kind, "invalid_response");
    assert.match(messages.error[0], /outside the requested scope/);
  });

  test("rejects non-canonical slug_perm records before committing", async () => {
    const malformed = pkg("artifact");
    malformed.slug_perm = { value: "artifact-perm" };
    const { provider } = createProvider({
      fetchPage: async () => page([malformed]),
    });

    await provider.search("workspace-a", "name:artifact");

    assert.strictEqual(provider.state.committed, null);
    assert.strictEqual(provider.state.failure.kind, "invalid_response");
  });

  test("rejects malformed present package policy booleans", async () => {
    const { provider } = createProvider({
      fetchPage: async () => page([pkg("artifact", { deny_policy_violated: "true" })]),
    });

    await provider.search("workspace-a", "name:artifact");

    assert.strictEqual(provider.state.committed, null);
    assert.strictEqual(provider.state.failure.kind, "invalid_response");
  });

  test("invalid repository counts fail currently and perform no fetch", async () => {
    let fetchCount = 0;
    const { provider, messages } = createProvider({
      fetchPage: async () => {
        fetchCount += 1;
        return page([]);
      },
    });

    await provider.searchRepos("workspace-a", [], "name:artifact");
    await provider.searchRepos(
      "workspace-a",
      Array.from({ length: 1001 }, (_, index) => `repo-${index}`),
      "name:artifact"
    );

    assert.strictEqual(fetchCount, 0);
    assert.strictEqual(provider.state.failure.kind, "invalid_request");
    assert.match(messages.error.at(-1), /between 1 and 1,000/);
  });

  test("rejects over-limit descriptor and package identity strings", async () => {
    let fetchCount = 0;
    const { provider } = createProvider({
      fetchPage: async () => {
        fetchCount += 1;
        return page([]);
      },
    });

    await provider.search("w".repeat(201), "artifact");
    await provider.search("workspace-a", "q".repeat(2049));
    await provider.search("workspace-a", "artifact", 1, "r".repeat(201));

    assert.strictEqual(fetchCount, 0);
    assert.strictEqual(provider.state.failure.kind, "invalid_request");

    const oversized = pkg("x".repeat(2049));
    const { provider: responseProvider } = createProvider({
      fetchPage: async () => page([oversized]),
    });
    await responseProvider.search("workspace-a", "artifact");

    assert.strictEqual(responseProvider.state.committed, null);
    assert.strictEqual(responseProvider.state.failure.kind, "invalid_response");
  });

  test("100 repositories are searched completely with exactly four bounded workers", async () => {
    let calls = 0;
    let active = 0;
    let maxActive = 0;
    const repositories = Array.from({ length: 100 }, (_, index) => `repo-${index}`);
    const { provider } = createProvider({
      pageSize: 100,
      fetchPage: async () => {
        calls += 1;
        active += 1;
        maxActive = Math.max(maxActive, active);
        await nextTurn();
        active -= 1;
        return page([], { pageSize: 100 });
      },
    });

    await provider.searchRepos("workspace-a", repositories, "name:artifact");

    assert.strictEqual(calls, 100);
    assert.strictEqual(maxActive, 4);
    assert.strictEqual(provider.state.committed.descriptor.repositories.length, 100);
    assert(Object.isFrozen(provider.state.committed.descriptor.repositories));
    assert.strictEqual(provider.state.committed.diagnostics.unsearchedRepositoryCount, 0);
    assert.strictEqual(provider.state.committed.diagnostics.partial, false);
    assert.strictEqual(provider.state.committed.diagnostics.requestCount, 100);
    assert.strictEqual(provider.state.committed.pageable, false);
  });

  test("1,000 repositories remain structurally bounded and complete", async function () {
    this.timeout(10000);
    let calls = 0;
    let active = 0;
    let maxActive = 0;
    const repositories = Array.from({ length: 1000 }, (_, index) => `repo-${index}`);
    const { provider } = createProvider({
      pageSize: 100,
      fetchPage: async () => {
        calls += 1;
        active += 1;
        maxActive = Math.max(maxActive, active);
        await nextTurn();
        active -= 1;
        return page([], { pageSize: 100 });
      },
    });

    await provider.searchRepos("workspace-a", repositories, "name:no-match");

    assert.strictEqual(calls, 1000);
    assert.strictEqual(maxActive, 4);
    assert.strictEqual(provider.state.committed.diagnostics.requestCount, 1000);
    assert.strictEqual(provider.state.committed.diagnostics.partial, false);
    assert.strictEqual(provider.state.committed.diagnostics.unsearchedRepositoryCount, 0);
  });

  test("FIFO reservations search every first page before any second page", async () => {
    const calls = [];
    const repositories = Array.from({ length: 100 }, (_, index) => `repo-${index}`);
    const { provider } = createProvider({
      pageSize: 1,
      fetchPage: async (endpoint, requestedPage) => {
        const repository = repositoryFromEndpoint(endpoint);
        calls.push({ repository, page: requestedPage });
        await nextTurn();
        return page([pkg(`${repository}-${requestedPage}`, { repository })], {
          requestedPage,
          pageSize: 1,
          pageTotal: 2,
          count: 2,
        });
      },
    });

    await provider.searchRepos("workspace-a", repositories, "name:artifact");

    assert.strictEqual(calls.length, 200);
    assert(calls.slice(0, 100).every(call => call.page === 1));
    assert(calls.slice(100).every(call => call.page === 2));
    assert.strictEqual(new Set(calls.slice(0, 100).map(call => call.repository)).size, 100);
    assert.strictEqual(provider.state.committed.diagnostics.partial, false);
  });

  test("the global logical request ceiling stops at 2,000 without request amplification", async function () {
    this.timeout(10000);
    let calls = 0;
    const repositories = Array.from({ length: 101 }, (_, index) => `repo-${index}`);
    const { provider } = createProvider({
      pageSize: 1,
      fetchPage: async (endpoint, requestedPage) => {
        calls += 1;
        const repository = repositoryFromEndpoint(endpoint);
        return page([pkg(`${repository}-${requestedPage}`, { repository })], {
          requestedPage,
          pageSize: 1,
          pageTotal: 20,
          count: 20,
        });
      },
    });

    await provider.searchRepos("workspace-a", repositories, "name:artifact");

    assert.strictEqual(calls, 2000);
    assert.strictEqual(provider.state.committed.diagnostics.requestCount, 2000);
    assert.strictEqual(provider.state.committed.diagnostics.requestLimitReached, true);
    assert.strictEqual(provider.state.committed.diagnostics.partial, true);
    assert(provider.state.committed.diagnostics.truncatedRepositoryCount > 0);
  });

  test("the per-repository page ceiling stops before page 21", async () => {
    const calls = [];
    const { provider } = createProvider({
      pageSize: 1,
      fetchPage: async (endpoint, requestedPage) => {
        calls.push(requestedPage);
        return page([pkg(`artifact-${requestedPage}`, {
          repository: repositoryFromEndpoint(endpoint),
        })], {
          requestedPage,
          pageSize: 1,
          pageTotal: 21,
          count: 21,
        });
      },
    });

    await provider.searchRepos("workspace-a", ["repo-a"], "name:artifact");

    assert.deepStrictEqual(calls, Array.from({ length: 20 }, (_, index) => index + 1));
    assert.strictEqual(provider.state.committed.diagnostics.pageLimitReached, true);
    assert.strictEqual(provider.state.committed.diagnostics.truncatedRepositoryCount, 1);
    assert.strictEqual(provider.state.committed.diagnostics.partial, true);
  });

  test("discovers later-page results and completes anchored repository pagination", async () => {
    const { provider } = createProvider({
      pageSize: 2,
      fetchPage: async (_endpoint, requestedPage) => requestedPage === 1
        ? page([pkg("artifact-1"), pkg("artifact-2")], {
          pageSize: 2,
          pageTotal: 2,
          count: 3,
        })
        : page([pkg("artifact-3")], {
          requestedPage: 2,
          pageSize: 2,
          pageTotal: 2,
          count: 3,
        }),
    });

    await provider.searchRepos("workspace-a", ["repo-a"], "name:artifact");

    const committed = provider.state.committed;
    assert.deepStrictEqual(committed.results.map(node => node.name), [
      "artifact-1", "artifact-2", "artifact-3",
    ]);
    assert.strictEqual(committed.totalCount, 3);
    assert.strictEqual(committed.pageable, false);
    assert.strictEqual(committed.diagnostics.truncatedRepositoryCount, 0);
    assert.strictEqual(committed.diagnostics.partial, false);
    assert.strictEqual(committed.diagnostics.requestCount, 2);
    assert.strictEqual(committed.diagnostics.pageCount, 2);

    const items = (await provider.getChildren()).map(node => node.getTreeItem());
    assert.match(items[0].description, /3 packages/);
    assert.strictEqual(items.some(item => item.contextValue === "loadMore"), false);
  });

  test("multi-repository cancellation stops scheduling and preserves prior state", async () => {
    const token = { isCancellationRequested: false };
    let calls = 0;
    let active = 0;
    const requests = [];
    const { provider, messages } = createProvider({
      cancellationToken: token,
      fetchPage: async () => {
        calls += 1;
        active += 1;
        const request = deferred();
        requests.push(request);
        const result = await request.promise;
        active -= 1;
        return result;
      },
    });

    const search = provider.searchRepos(
      "workspace-a",
      Array.from({ length: 20 }, (_, index) => `repo-${index}`),
      "name:artifact"
    );
    await nextTurn();
    assert.strictEqual(calls, 4);
    assert.strictEqual(active, 4);
    token.isCancellationRequested = true;
    for (const request of requests) request.resolve(failedPage("cancelled"));
    await search;

    assert.strictEqual(calls, 4);
    assert.strictEqual(active, 0);
    assert.strictEqual(provider.state.committed, null);
    assert.strictEqual(provider.state.failure, null);
    assert.deepStrictEqual(messages.error, []);
  });

  test("partial repository success commits exact scope with only 20 failure details", async () => {
    const repositories = Array.from({ length: 26 }, (_, index) => `repo-${index}`);
    const { provider, messages } = createProvider({
      fetchPage: async endpoint => {
        const repository = repositoryFromEndpoint(endpoint);
        if (repository !== "repo-25") {
          return failedPage("forbidden");
        }
        return page([pkg("success", { repository })]);
      },
    });

    await provider.searchRepos("workspace-a", repositories, "name:artifact");

    assert.strictEqual(provider.state.committed.descriptor.kind, "repositories");
    assert.deepStrictEqual(provider.state.committed.descriptor.repositories, repositories);
    assert.strictEqual(provider.searchResults.length, 1);
    assert.strictEqual(provider.state.committed.diagnostics.failedRepositoryCount, 25);
    assert.strictEqual(provider.state.committed.diagnostics.failureDetails.length, 20);
    assert.strictEqual(messages.warning.length, 1);
    assert.match(messages.warning[0], /and 5 more/);
  });

  test("99 successful repositories survive one repository failure", async () => {
    const repositories = Array.from({ length: 100 }, (_, index) => `repo-${index}`);
    const { provider, messages } = createProvider({
      fetchPage: async endpoint => {
        const repository = repositoryFromEndpoint(endpoint);
        if (repository === "repo-99") return failedPage("forbidden");
        return page([pkg(`artifact-${repository}`, { repository })]);
      },
    });

    await provider.searchRepos("workspace-a", repositories, "name:artifact");

    assert.strictEqual(provider.searchResults.length, 99);
    assert.strictEqual(provider.state.committed.diagnostics.failedRepositoryCount, 1);
    assert.strictEqual(provider.state.committed.diagnostics.partial, true);
    assert.strictEqual(messages.warning.length, 1);
    assert.strictEqual(messages.information.length, 0);
  });

  test("HTTP 429 opens the circuit, settles active workers, and schedules no queued work", async () => {
    let calls = 0;
    let active = 0;
    const repositories = Array.from({ length: 100 }, (_, index) => `repo-${index}`);
    const { provider } = createProvider({
      fetchPage: async endpoint => {
        calls += 1;
        active += 1;
        const repository = repositoryFromEndpoint(endpoint);
        await nextTurn();
        active -= 1;
        if (repository === "repo-0") return failedPage("rate_limited");
        return page([pkg(`artifact-${repository}`, { repository })]);
      },
    });

    await provider.searchRepos("workspace-a", repositories, "name:artifact");

    assert.strictEqual(active, 0);
    assert.strictEqual(calls, 4);
    assert.strictEqual(provider.state.committed.diagnostics.rateLimited, true);
    assert.strictEqual(provider.state.committed.diagnostics.failedRepositoryCount, 1);
    assert(provider.state.committed.diagnostics.unsearchedRepositoryCount >= 96);
    assert(provider.searchResults.length > 0);
    assert.strictEqual(provider.state.committed.diagnostics.partial, true);
  });

  test("a thrown repository request releases its worker and does not starve later work", async () => {
    let calls = 0;
    let active = 0;
    let maxActive = 0;
    const repositories = Array.from({ length: 100 }, (_, index) => `repo-${index}`);
    const { provider } = createProvider({
      fetchPage: async endpoint => {
        calls += 1;
        active += 1;
        maxActive = Math.max(maxActive, active);
        const repository = repositoryFromEndpoint(endpoint);
        await nextTurn();
        active -= 1;
        if (repository === "repo-0") throw new Error("secret transport detail");
        return page([pkg(`artifact-${repository}`, { repository })]);
      },
    });

    await provider.searchRepos("workspace-a", repositories, "name:artifact");

    assert.strictEqual(calls, 100);
    assert.strictEqual(active, 0);
    assert.strictEqual(maxActive, 4);
    assert.strictEqual(provider.searchResults.length, 99);
    assert.strictEqual(provider.state.committed.diagnostics.failedRepositoryCount, 1);
  });

  test("an unexpected page-processing exception settles every worker and preserves successes", async () => {
    let calls = 0;
    let active = 0;
    const repositories = Array.from({ length: 100 }, (_, index) => `repo-${index}`);
    const { provider } = createProvider({
      fetchPage: async endpoint => {
        calls += 1;
        active += 1;
        const repository = repositoryFromEndpoint(endpoint);
        await nextTurn();
        active -= 1;
        if (repository === "repo-0") {
          return {
            data: [],
            get pagination() { throw new Error("untrusted accessor"); },
            error: null,
          };
        }
        return page([pkg(`artifact-${repository}`, { repository })]);
      },
    });

    await provider.searchRepos("workspace-a", repositories, "name:artifact");

    assert.strictEqual(calls, 4);
    assert.strictEqual(active, 0);
    assert.strictEqual(provider.searchResults.length, 3);
    assert.strictEqual(provider.state.committed.diagnostics.failedRepositoryCount, 1);
    assert.strictEqual(provider.state.committed.diagnostics.partial, true);
  });

  test("an incomplete empty multi-repository result is never announced as no packages", async () => {
    const { provider, messages } = createProvider({
      fetchPage: async endpoint => repositoryFromEndpoint(endpoint) === "repo-a"
        ? page([])
        : failedPage("forbidden"),
    });

    await provider.searchRepos("workspace-a", ["repo-a", "repo-b"], "name:missing");

    assert.strictEqual(provider.searchResults.length, 0);
    assert.strictEqual(provider.state.committed.diagnostics.partial, true);
    assert.strictEqual(messages.information.length, 0);
    const summary = (await provider.getChildren())[0].getTreeItem();
    assert.match(summary.description, /incomplete/);
  });

  test("all repository failures preserve the prior committed session", async () => {
    let fail = false;
    const { provider } = createProvider({
      fetchPage: async () => fail ? failedPage("forbidden") : page([pkg("prior")]),
    });
    await provider.search("workspace-a", "prior");
    const prior = provider.state.committed;
    fail = true;

    await provider.searchRepos("workspace-a", ["repo-a", "repo-b"], "replacement");

    assert.strictEqual(provider.state.committed, prior);
    assert.strictEqual(provider.state.failure.descriptor.kind, "repositories");
  });

  test("fails a single-scope page closed when it repeats a canonical package identity", async () => {
    const duplicate = pkg("artifact");
    const { provider } = createProvider({
      fetchPage: async () => page([duplicate, { ...duplicate }]),
    });

    await provider.search("workspace-a", "name:artifact");

    assert.strictEqual(provider.searchResults.length, 0);
    assert.strictEqual(provider.state.committed, null);
    assert.strictEqual(provider.state.failure.kind, "invalid_response");
  });

  test("a repeated identity is terminal and incomplete for that repository", async () => {
    const repeated = pkg("artifact");
    let calls = 0;
    const { provider } = createProvider({
      pageSize: 2,
      fetchPage: async (_endpoint, requestedPage) => {
        calls += 1;
        if (requestedPage === 1) {
          return page([repeated, pkg("second")], {
            pageSize: 2,
            pageTotal: 2,
            count: 4,
          });
        }
        return page([{ ...repeated }, pkg("fourth")], {
          requestedPage: 2,
          pageSize: 2,
          pageTotal: 2,
          count: 4,
        });
      },
    });

    await provider.searchRepos("workspace-a", ["repo-a"], "name:artifact");

    assert.strictEqual(calls, 2);
    assert.deepStrictEqual(provider.searchResults.map(node => node.name), ["artifact", "second"]);
    assert.strictEqual(provider.state.committed.diagnostics.failedRepositoryCount, 1);
    assert.strictEqual(provider.state.committed.diagnostics.partial, true);
  });

  test("a conflicting canonical identity fails closed without publishing both records", async () => {
    const sharedIdentity = "immutable-id";
    const { provider } = createProvider({
      fetchPage: async () => page([
        pkg("artifact-a", { slug_perm: sharedIdentity }),
        pkg("artifact-b", { slug_perm: sharedIdentity }),
      ], { pageSize: 2, count: 2 }),
    });

    await provider.searchRepos("workspace-a", ["repo-a"], "name:artifact");

    assert.deepStrictEqual(provider.searchResults.map(node => node.name), []);
    assert.strictEqual(provider.state.committed, null);
    assert.strictEqual(provider.state.failure.kind, "invalid_response");
    assert.match(provider.state.failure.message, /conflicting records/);
  });

  test("cross-page pagination metadata changes preserve prior pages as incomplete", async () => {
    const { provider } = createProvider({
      pageSize: 1,
      fetchPage: async (_endpoint, requestedPage) => requestedPage === 1
        ? page([pkg("first")], { pageSize: 1, pageTotal: 2, count: 2 })
        : page([pkg("second")], {
          requestedPage: 2,
          pageSize: 1,
          pageTotal: 3,
          count: 3,
        }),
    });

    await provider.searchRepos("workspace-a", ["repo-a"], "name:artifact");

    assert.deepStrictEqual(provider.searchResults.map(node => node.name), ["first"]);
    assert.strictEqual(provider.state.committed.diagnostics.failedRepositoryCount, 1);
    assert.match(provider.state.committed.diagnostics.failureDetails[0].message, /changed pagination metadata/);
  });

  test("a short authoritative non-final page terminates without requesting another page", async () => {
    let calls = 0;
    const { provider } = createProvider({
      pageSize: 2,
      fetchPage: async () => {
        calls += 1;
        return page([pkg("only-one")], { pageSize: 2, pageTotal: 2, count: 3 });
      },
    });

    await provider.searchRepos("workspace-a", ["repo-a"], "name:artifact");

    assert.strictEqual(calls, 1);
    assert.strictEqual(provider.state.committed, null);
    assert.strictEqual(provider.state.failure.kind, "invalid_response");
  });

  test("page-total-only metadata permits a full non-final page and bounded final page", async () => {
    const calls = [];
    const { provider } = createProvider({
      pageSize: 2,
      fetchPage: async (_endpoint, requestedPage) => {
        calls.push(requestedPage);
        return requestedPage === 1
          ? page([pkg("first"), pkg("second")], {
            pageSize: 2,
            pageTotal: 2,
            count: null,
            countAuthoritative: false,
          })
          : page([pkg("third")], {
            requestedPage: 2,
            pageSize: 2,
            pageTotal: 2,
            count: null,
            countAuthoritative: false,
          });
      },
    });

    await provider.searchRepos("workspace-a", ["repo-a"], "name:artifact");

    assert.deepStrictEqual(calls, [1, 2]);
    assert.deepStrictEqual(provider.searchResults.map(node => node.name), ["first", "second", "third"]);
    assert.strictEqual(provider.state.committed.diagnostics.partial, false);
  });

  test("multi-repository result retention is capped with only bounded in-flight overflow", async () => {
    let calls = 0;
    let active = 0;
    let maxActive = 0;
    const repositories = Array.from({ length: 60 }, (_, index) => `repo-${index}`);
    const { provider } = createProvider({
      pageSize: 100,
      fetchPage: async endpoint => {
        calls += 1;
        active += 1;
        maxActive = Math.max(maxActive, active);
        const repository = repositoryFromEndpoint(endpoint);
        await nextTurn();
        active -= 1;
        return page(Array.from({ length: 100 }, (_, index) => (
          pkg(`${repository}-${index}`, { repository })
        )), { pageSize: 100, count: 100 });
      },
    });

    await provider.searchRepos("workspace-a", repositories, "name:artifact");

    assert.strictEqual(provider.searchResults.length, 5000);
    assert.strictEqual(maxActive, 4);
    assert(calls >= 50 && calls <= 53);
    assert(calls * 100 <= 5300);
    assert.strictEqual(provider.state.committed.diagnostics.partial, true);
    assert.strictEqual(provider.state.committed.diagnostics.capReached, true);
    assert(provider.state.committed.diagnostics.droppedResultCount <= 300);
  });

  test("exactly 5,000 complete results do not imply omitted work", async () => {
    const repositories = Array.from({ length: 50 }, (_, index) => `repo-${index}`);
    const { provider } = createProvider({
      pageSize: 100,
      fetchPage: async endpoint => {
        const repository = repositoryFromEndpoint(endpoint);
        return page(Array.from({ length: 100 }, (_, index) => (
          pkg(`${repository}-${index}`, { repository })
        )), { pageSize: 100, count: 100 });
      },
    });

    await provider.searchRepos("workspace-a", repositories, "name:artifact");

    assert.strictEqual(provider.searchResults.length, 5000);
    assert.strictEqual(provider.state.committed.diagnostics.partial, false);
    assert.strictEqual(provider.state.committed.diagnostics.capReached, false);
    const labels = (await provider.getChildren()).map(node => node.getTreeItem().label);
    assert.strictEqual(labels.includes("Showing the first 5,000 results"), false);
  });

  test("a stale multi-repository run settles without publishing over the current search", async () => {
    const slow = deferred();
    let activeSlow = 0;
    const { provider, messages } = createProvider({
      fetchPage: async (endpoint, _requestedPage, _pageSize, query) => {
        const repository = repositoryFromEndpoint(endpoint);
        if (query === "slow") {
          activeSlow += 1;
          const result = await slow.promise;
          activeSlow -= 1;
          return result;
        }
        return page([pkg("current", { repository })]);
      },
    });

    const staleSearch = provider.searchRepos(
      "workspace-a",
      ["repo-a", "repo-b"],
      "slow"
    );
    await nextTurn();
    assert.strictEqual(activeSlow, 2);
    await provider.searchRepos("workspace-a", ["repo-current"], "current");
    slow.resolve(page([pkg("stale")]));
    await staleSearch;

    assert.strictEqual(activeSlow, 0);
    assert.strictEqual(provider.currentQuery, "current");
    assert.deepStrictEqual(provider.searchResults.map(node => node.name), ["current"]);
    assert.deepStrictEqual(messages.error, []);
  });

  test("duplicate next-page commands return the same promise and fetch once", async () => {
    const secondPage = deferred();
    let calls = 0;
    const { provider } = createProvider({
      pageSize: 2,
      fetchPage: async (_endpoint, requestedPage) => {
        calls += 1;
        if (requestedPage === 1) {
          return page([pkg("one"), pkg("two")], { pageTotal: 2, count: 3, pageSize: 2 });
        }
        return secondPage.promise;
      },
    });
    await provider.search("workspace-a", "name:artifact");

    const first = provider.loadNextPage();
    const duplicate = provider.loadNextPage();
    assert.strictEqual(first, duplicate);
    secondPage.resolve(page([pkg("three")], { requestedPage: 2, pageTotal: 2, count: 3, pageSize: 2 }));
    await first;

    assert.strictEqual(calls, 2);
    assert.strictEqual(provider.currentPage, 2);
    assert.strictEqual(provider.searchResults.length, 3);
  });

  test("page failure keeps the retry target available", async () => {
    let pageTwoCalls = 0;
    const { provider } = createProvider({
      pageSize: 2,
      fetchPage: async (_endpoint, requestedPage) => {
        if (requestedPage === 1) {
          return page([pkg("one"), pkg("two")], { pageTotal: 2, count: 3, pageSize: 2 });
        }
        pageTwoCalls += 1;
        if (pageTwoCalls === 1) {
          return failedPage("rate_limited", 2, 2);
        }
        return page([pkg("three")], { requestedPage: 2, pageTotal: 2, count: 3, pageSize: 2 });
      },
    });
    await provider.search("workspace-a", "name:artifact");

    await provider.loadNextPage();
    assert.strictEqual(provider.currentPage, 1);
    assert.strictEqual(provider.state.committed.pageable, true);
    await provider.loadNextPage();

    assert.strictEqual(pageTwoCalls, 2);
    assert.strictEqual(provider.currentPage, 2);
    assert.strictEqual(provider.searchResults.length, 3);
  });

  test("a new root search prevents an older page from appending", async () => {
    const oldPage = deferred();
    const { provider } = createProvider({
      pageSize: 2,
      fetchPage: async (_endpoint, requestedPage, _size, query) => {
        if (query === "old" && requestedPage === 1) {
          return page([pkg("old-one"), pkg("old-two")], { pageTotal: 2, count: 3, pageSize: 2 });
        }
        if (query === "old") {
          return oldPage.promise;
        }
        return page([pkg("new")], { pageSize: 2 });
      },
    });
    await provider.search("workspace-a", "old");
    const loadingPage = provider.loadNextPage();

    await provider.search("workspace-a", "new");
    oldPage.resolve(page([pkg("stale")], { requestedPage: 2, pageTotal: 2, count: 3, pageSize: 2 }));
    await loadingPage;

    assert.strictEqual(provider.currentQuery, "new");
    assert.deepStrictEqual(provider.searchResults.map(node => node.name), ["new"]);
  });

  test("stops single-scope pagination at the cumulative page limit", async function () {
    this.timeout(5000);
    let calls = 0;
    const { provider } = createProvider({
      pageSize: 100,
      fetchPage: async (_endpoint, requestedPage) => {
        calls += 1;
        const data = Array.from({ length: 100 }, (_, index) => (
          pkg(`artifact-${requestedPage}-${index}`)
        ));
        return page(data, {
          requestedPage,
          pageTotal: 51,
          count: 5100,
          pageSize: 100,
        });
      },
    });
    await provider.search("workspace-a", "name:artifact");

    for (let pageNumber = 2; pageNumber <= 20; pageNumber += 1) {
      await provider.loadNextPage();
    }

    assert.strictEqual(calls, 20);
    assert.strictEqual(provider.searchResults.length, 2000);
    assert.strictEqual(provider.currentPage, 20);
    assert.strictEqual(provider.state.committed.pageable, false);
    assert.strictEqual(provider.state.committed.diagnostics.capReached, true);
    assert.strictEqual(provider.state.committed.diagnostics.pageLimitReached, true);
    const labels = (await provider.getChildren()).map(node => node.getTreeItem().label);
    assert(labels.includes("Search loading limit reached"));
    assert(!labels.some(label => label.startsWith("Load more results")));
  });

  test("invalid continuation metadata is terminal and cannot amplify requests", async () => {
    let calls = 0;
    const { provider } = createProvider({
      pageSize: 2,
      fetchPage: async (_endpoint, requestedPage) => {
        calls += 1;
        if (requestedPage === 1) {
          return page([pkg("one"), pkg("two")], { pageSize: 2, pageTotal: 2, count: 3 });
        }
        return page([pkg("three")], {
          requestedPage: 2,
          pageSize: 2,
          pageTotal: 3,
          count: 5,
        });
      },
    });
    await provider.search("workspace-a", "name:artifact");

    await provider.loadNextPage();
    await provider.loadNextPage();

    assert.strictEqual(calls, 2);
    assert.strictEqual(provider.state.committed.pageable, false);
    assert.strictEqual(provider.state.committed.diagnostics.partial, true);
    assert.strictEqual(provider.state.failure.kind, "invalid_response");
  });

  test("transient continuation retries consume a cumulative request budget", async () => {
    let calls = 0;
    const { provider } = createProvider({
      pageSize: 2,
      fetchPage: async (_endpoint, requestedPage) => {
        calls += 1;
        return requestedPage === 1
          ? page([pkg("one"), pkg("two")], { pageSize: 2, pageTotal: 2, count: 3 })
          : failedPage("rate_limited", 2, 2);
      },
    });
    await provider.search("workspace-a", "name:artifact");

    for (let attempt = 0; attempt < 30; attempt += 1) {
      await provider.loadNextPage();
    }

    assert.strictEqual(calls, 24);
    assert.strictEqual(provider.state.committed.diagnostics.requestCount, 24);
    assert.strictEqual(provider.state.committed.diagnostics.requestLimitReached, true);
    assert.strictEqual(provider.state.committed.pageable, false);
  });

  test("clear invalidates a pending root and publishes no later result", async () => {
    const pending = deferred();
    const { provider } = createProvider({ fetchPage: async () => pending.promise });
    const search = provider.search("workspace-a", "slow");

    provider.clear();
    pending.resolve(page([pkg("stale")]));
    await search;

    assert.strictEqual(provider.state.committed, null);
    assert.strictEqual(provider.state.failure, null);
  });

  test("idle tree derives connection state from the shared manager", async () => {
    const connectionManager = createConnectionManager({ accountEpoch: 0, sessionConnected: false });
    const { provider } = createProvider({ connectionManager });

    let nodes = await provider.getChildren();
    assert.strictEqual(nodes[0].getTreeItem().label, "Connect to Cloudsmith");

    connectionManager.update({ accountEpoch: 0, sessionConnected: true });
    nodes = await provider.getChildren();
    assert.strictEqual(nodes[0].getTreeItem().label, "Search packages across a Cloudsmith workspace");
  });

  function createProvider(options = {}) {
    const messages = { error: [], information: [], warning: [] };
    const connectionManager = options.connectionManager || createConnectionManager();
    const fetchPage = options.fetchPage || (async () => page([]));
    const provider = new SearchProvider(
      {},
      {
        connectionManager,
        createCloudsmithAPI: () => ({}),
        createPaginatedFetch: () => ({ fetchPage }),
        withProgress: (_progressOptions, task) => task(
          { report() {} },
          options.cancellationToken || {
            isCancellationRequested: false,
            onCancellationRequested() { return { dispose() {} }; },
          }
        ),
        notifications: {
          error(message) { messages.error.push(message); },
          information(message) { messages.information.push(message); },
          warning(message) { messages.warning.push(message); },
        },
        getPageSize: () => options.pageSize || 50,
      }
    );
    providers.push(provider);
    return { provider, messages, connectionManager };
  }
});

function createConnectionManager(initial = {}) {
  let state = Object.freeze({
    activationId: "activation-a",
    accountEpoch: 0,
    sessionConnected: true,
    status: "connected",
    ...initial,
  });
  const listeners = new Set();
  return {
    getState() {
      return state;
    },
    onDidChange(listener) {
      listeners.add(listener);
      return { dispose() { listeners.delete(listener); } };
    },
    update(next) {
      state = Object.freeze({ ...state, ...next });
      for (const listener of listeners) {
        listener(state);
      }
    },
  };
}

function pkg(name, overrides = {}) {
  return {
    name,
    format: "raw",
    repository: "repo-a",
    namespace: "workspace-a",
    status_str: "Completed",
    slug: `${name}-slug`,
    slug_perm: `${name}-perm`,
    downloads: 0,
    version: "1.0.0",
    uploaded_at: "2026-03-25T00:00:00Z",
    ...overrides,
  };
}

function page(data, options = {}) {
  const requestedPage = options.requestedPage || 1;
  const pageTotal = options.pageTotal || requestedPage;
  const hasCount = Object.prototype.hasOwnProperty.call(options, "count");
  const hasCountAuthority = Object.prototype.hasOwnProperty.call(options, "countAuthoritative");
  return {
    data,
    pagination: {
      page: requestedPage,
      pageTotal,
      count: hasCount ? options.count : data.length,
      ...(hasCountAuthority ? { countAuthoritative: options.countAuthoritative } : {}),
      pageSize: options.pageSize || 50,
    },
    error: null,
  };
}

function failedPage(kind, requestedPage = 1, pageSize = 50) {
  return {
    data: [],
    pagination: { page: requestedPage, pageTotal: requestedPage, count: 0, pageSize },
    error: {
      kind,
      status: kind === "rate_limited" ? 429 : null,
      retryable: kind === "rate_limited",
      message: `Failure: ${kind}`,
      requestId: null,
      retryAfterMs: null,
      outcomeUnknown: false,
      diagnostic: {},
    },
  };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function repositoryFromEndpoint(endpoint) {
  return endpoint.split("/").filter(Boolean).at(-1);
}

function nextTurn() {
  return new Promise(resolve => setImmediate(resolve));
}

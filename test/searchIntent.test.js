const assert = require("assert");
const {
  beginAccountScopedStateReset,
  completeAccountScopedStateReset,
  createAuthenticationResultHandler,
} = require("../util/accountLifecycle");
const {
  executeSearchIntent,
  searchDescriptorFromRecent,
} = require("../util/searchIntent");

function resetAccountScopedState(context, options) {
  const reset = beginAccountScopedStateReset(options);
  return completeAccountScopedStateReset(context, options, reset);
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, reject, resolve };
}

suite("search intent command boundary", () => {
  test("account reset invalidates UI state before independently settled projections", async () => {
    const order = [];
    const cleared = new Set();
    const clear = name => () => {
      order.push(name);
      cleared.add(name);
    };

    const outcome = await resetAccountScopedState({ globalState: {} }, {
      workspaceCache: { clear: clear("workspace") },
      searchProvider: { clear: clear("search") },
      filterState: { clear: clear("filter") },
      recentPackages: { clear: clear("recent") },
      clearVulnerabilityCache: clear("vulnerability"),
      vulnerabilityStateService: { clear: clear("vulnerability-state") },
      vulnerabilityProvider: { resetForAccountChange: clear("vulnerability-panel") },
      quarantineExplainProvider: { resetForAccountChange: clear("quarantine-panel") },
      upstreamPreviewProvider: { resetForAccountChange: clear("upstream-preview-panel") },
      upstreamDetailProvider: { resetForAccountChange: clear("upstream-detail-panel") },
      dependencyHealthProvider: {
        async resetForAccountChange() {
          order.push("dependency");
          throw new Error("diagnostics failed");
        },
      },
      async projectHasMultipleWorkspaces(value) {
        order.push(`projection:${value}`);
        throw new Error("setContext failed");
      },
    });

    assert.deepStrictEqual(order.slice(0, 10), [
      "workspace",
      "search",
      "filter",
      "recent",
      "vulnerability",
      "vulnerability-state",
      "vulnerability-panel",
      "quarantine-panel",
      "upstream-preview-panel",
      "upstream-detail-panel",
    ]);
    assert.deepStrictEqual([...cleared].sort(), [
      "filter",
      "quarantine-panel",
      "recent",
      "search",
      "upstream-detail-panel",
      "upstream-preview-panel",
      "vulnerability",
      "vulnerability-panel",
      "vulnerability-state",
      "workspace",
    ]);
    assert.deepStrictEqual(order.slice(10), ["dependency", "projection:false"]);
    assert.deepStrictEqual(outcome.asyncResults.map(result => result.status), [
      "rejected",
      "rejected",
    ]);
  });

  test("account reset finishes every asynchronous invalidator before refreshing Cloudsmith", async () => {
    const dependencyReset = deferred();
    const order = [];
    const accountState = Object.freeze({ activationId: "activation-b", accountEpoch: 2 });
    const pending = resetAccountScopedState({ globalState: {} }, {
      workspaceCache: { clear() { order.push("workspace-clear"); } },
      filterState: { clear() {} },
      recentPackages: { clear() {} },
      clearVulnerabilityCache() {},
      dependencyHealthProvider: {
        async resetForAccountChange() {
          order.push("dependency-start");
          await dependencyReset.promise;
          order.push("dependency-complete");
        },
      },
      async projectHasMultipleWorkspaces() {
        order.push("workspace-context");
      },
      cloudsmithProvider: {
        completeAccountReset(state) {
          assert.strictEqual(state, accountState);
          order.push("cloudsmith-refresh");
        },
      },
      accountState,
    });

    await Promise.resolve();
    assert.strictEqual(order.includes("cloudsmith-refresh"), false);
    dependencyReset.resolve();
    await pending;
    assert.ok(order.indexOf("workspace-clear") < order.indexOf("cloudsmith-refresh"));
    assert.ok(order.indexOf("dependency-complete") < order.indexOf("cloudsmith-refresh"));
    assert.ok(order.indexOf("workspace-context") < order.indexOf("cloudsmith-refresh"));
  });

  test("authentication default offer cannot mutate settings after its account turns stale", async () => {
    let current = true;
    let updates = 0;
    let contextUpdates = 0;
    let refreshes = 0;
    const account = Object.freeze({ activationId: "activation-a", accountEpoch: 1 });
    const connectionManager = {
      getState: () => ({
        sessionConnected: true,
        credentialPresent: true,
        activationId: account.activationId,
        accountEpoch: account.accountEpoch,
      }),
    };
    const treeView = { title: "Workspaces", description: "" };
    const handler = createAuthenticationResultHandler({
      vscode: {
        ConfigurationTarget: { Global: 1 },
        workspace: {
          getConfiguration: () => ({ async update() { updates += 1; } }),
        },
        window: {
          async showInformationMessage() {
            current = false;
            return "Set as default";
          },
          showErrorMessage() { throw new Error("stale auth error must stay silent"); },
          showWarningMessage() { throw new Error("stale auth error must stay silent"); },
        },
      },
      connectionManager,
      treeView,
      cloudsmithProvider: { refresh() { refreshes += 1; } },
      async updateDefaultWorkspaceContext() { contextUpdates += 1; },
      getDefaultWorkspace: () => "",
      getWorkspaces: async () => ({
        complete: true,
        items: [{ slug: "workspace-a", name: "Workspace A" }],
      }),
      captureAccount: () => account,
      isAccountCurrent: () => current,
    });

    await handler({ ok: true }, { showSuccess: false });
    await handler({
      ok: false,
      error: { kind: "stale", message: "obsolete authentication failure" },
    });
    assert.strictEqual(updates, 0);
    assert.strictEqual(contextUpdates, 0);
    assert.strictEqual(refreshes, 0);
    assert.deepStrictEqual(treeView, { title: "Workspaces", description: "" });
  });

  test("authentication default offer preserves a newer verified default", async () => {
    let defaultWorkspace = "";
    let updates = 0;
    const account = Object.freeze({ activationId: "activation-a", accountEpoch: 1 });
    const connectionManager = {
      getState: () => ({ sessionConnected: true, credentialPresent: true }),
    };
    const handler = createAuthenticationResultHandler({
      vscode: {
        ConfigurationTarget: { Global: 1 },
        workspace: {
          getConfiguration: () => ({ async update() { updates += 1; } }),
        },
        window: {
          async showInformationMessage() {
            defaultWorkspace = "newer-verified-default";
            return "Set as default";
          },
        },
      },
      connectionManager,
      treeView: {},
      cloudsmithProvider: { refresh() {} },
      async updateDefaultWorkspaceContext() {},
      getDefaultWorkspace: () => defaultWorkspace,
      getWorkspaces: async () => ({
        complete: true,
        items: [{ slug: "workspace-a", name: "Workspace A" }],
      }),
      captureAccount: () => account,
      isAccountCurrent: () => true,
    });

    await handler({ ok: true }, { showSuccess: false });
    assert.strictEqual(updates, 0);
    assert.strictEqual(defaultWorkspace, "newer-verified-default");
  });

  test("owns and launches search before detached history persistence", async () => {
    const execution = deferred();
    const history = deferred();
    const calls = [];
    const provider = {
      beginSearch(descriptor) {
        calls.push("begin");
        return { descriptor };
      },
      executeSearch() {
        calls.push("execute");
        return execution.promise;
      },
    };
    const recentSearches = {
      add() {
        calls.push("history");
        return history.promise;
      },
    };

    const pending = executeSearchIntent(provider, {
      kind: "workspace",
      workspace: "workspace-a",
      query: "name:artifact",
      page: 1,
    }, { recentSearches, record: true });

    assert.deepStrictEqual(calls, ["begin", "execute"]);
    await Promise.resolve();
    assert.deepStrictEqual(calls, ["begin", "execute", "history"]);
    execution.resolve("searched");
    assert.strictEqual(await pending, "searched");
    history.resolve();
  });

  test("records and replays an exact single-repository descriptor", async () => {
    let recorded;
    const provider = {
      beginSearch(descriptor) { return { descriptor }; },
      async executeSearch() {},
    };
    await executeSearchIntent(provider, {
      kind: "repository",
      workspace: "workspace-a",
      repository: "repo-a",
      query: "name:artifact",
      page: 1,
    }, {
      record: true,
      recentSearches: { async add(value) { recorded = value; } },
    });
    await Promise.resolve();

    assert.deepStrictEqual(recorded, {
      workspace: "workspace-a",
      query: "name:artifact",
      scope: { kind: "repository", repository: "repo-a" },
    });
    assert.deepStrictEqual(searchDescriptorFromRecent(recorded), {
      kind: "repository",
      workspace: "workspace-a",
      repository: "repo-a",
      query: "name:artifact",
      page: 1,
    });
    assert.strictEqual(searchDescriptorFromRecent({
      ...recorded,
      scope: { kind: "repository", repository: "repo-a", extra: true },
    }), null);
  });

  test("handles detached history rejection without rejecting search", async () => {
    const result = await executeSearchIntent({
      beginSearch(descriptor) { return { descriptor }; },
      async executeSearch() { return "searched"; },
    }, {
      kind: "workspace",
      workspace: "workspace-a",
      query: "artifact",
    }, {
      record: true,
      recentSearches: { async add() { throw new Error("quota"); } },
    });
    await new Promise(resolve => setImmediate(resolve));

    assert.strictEqual(result, "searched");
  });

  test("persists the owned normalized descriptor instead of mutable caller input", async () => {
    const raw = {
      kind: "repository",
      workspace: " raw-workspace ",
      repository: " raw-repo ",
      query: "raw-query",
    };
    const owned = Object.freeze({
      kind: "repository",
      workspace: "workspace-a",
      repository: "repo-a",
      query: "normalized-query",
      page: 1,
    });
    let recorded;
    const pending = executeSearchIntent({
      beginSearch() { return Object.freeze({ descriptor: owned }); },
      async executeSearch() {},
    }, raw, {
      record: true,
      recentSearches: { async add(value) { recorded = value; } },
    });
    raw.workspace = "mutated-workspace";
    raw.repository = "mutated-repo";
    raw.query = "mutated-query";
    await pending;
    await Promise.resolve();

    assert.deepStrictEqual(recorded, {
      workspace: "workspace-a",
      query: "normalized-query",
      scope: { kind: "repository", repository: "repo-a" },
    });
  });
});

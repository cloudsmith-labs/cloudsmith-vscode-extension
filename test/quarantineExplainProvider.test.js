const assert = require("assert");
const DependencyHealthNode = require("../models/dependencyHealthNode");
const PackageNode = require("../models/packageNode");
const SearchResultNode = require("../models/searchResultNode");
const { fromPackageSelection } = require("../domain/packageAdapters");
const { QuarantineExplainProvider } = require("../views/quarantineExplainProvider");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");
const { createWebviewPanelHarness } = require("./helpers/webviewPanelHarness");
const { assertWebviewDocument } = require("./helpers/webviewSemanticContract");

suite("QuarantineExplainProvider", () => {
  function trace(overrides = {}) {
    return {
      current: {
        confirmed: true,
        format: "npm",
        name: "artifact",
        packageSlugPerm: "package-a",
        repository: "repo-a",
        status: "Quarantined",
        statusReason: "Quarantined by Dependency policy. Dependency rule matched. (Policy: policy-a)",
        uploadedAt: "2026-08-13T10:00:00.000Z",
        version: "1.0.0",
        workspace: "workspace-a",
      },
      decision: null,
      error: null,
      packageUrl: "https://app.cloudsmith.com/workspace-a/repo-a/packages/detail/npm/artifact/1.0.0/a=package-a/",
      parsedReason: {
        description: "Dependency rule matched.",
        policyName: "Dependency policy",
        policySlug: "policy-a",
      },
      policyDescription: null,
      refreshed: true,
      ...overrides,
    };
  }

  function render(overrides = {}) {
    const provider = new QuarantineExplainProvider({});
    return provider._getHtmlContent("nonce", trace(overrides));
  }

  test("renders a focused status-reason explanation without backend-gap copy", () => {
    const html = render();
    assertWebviewDocument(html, { interactive: true, scripted: true });
    assert.match(html, /<h1[^>]*>artifact 1\.0\.0<\/h1>/);
    assert.match(html, />Quarantined</);
    assert.match(html, /<dt>Policy<\/dt><dd>Dependency policy<\/dd>/);
    assert.match(html, /Dependency rule matched/);
    assert.match(html, /<dt>Action<\/dt><dd>Quarantined<\/dd>/);
    assert.doesNotMatch(html, /incomplete|additional entries|not a specific vulnerability/i);
    assert.doesNotMatch(html, /Decision log entries|<table|Unknown|Matched/);
  });

  test("renders a decision-only explanation from reconciled evidence", () => {
    const current = { ...trace().current, statusReason: null };
    const html = render({
      current,
      parsedReason: null,
      decision: {
        policyName: "Quarantine policy",
        policySlugPerm: "policy-a",
        reason: "Unsafe dependency matched.",
        endedAt: "2026-08-13T12:00:00.000Z",
      },
    });
    assert.match(html, /Quarantine policy/);
    assert.match(html, /Unsafe dependency matched/);
    assert.match(html, /Decision recorded/);
  });

  test("current status reason takes precedence over conflicting decision text", () => {
    const html = render({
      decision: {
        policyName: "Other policy",
        reason: "Contradictory reason.",
        endedAt: "2026-08-13T12:00:00.000Z",
      },
    });
    assert.match(html, /Dependency policy/);
    assert.match(html, /Dependency rule matched/);
    assert.doesNotMatch(html, /Other policy|Contradictory reason/);
  });

  test("policy description is optional, escaped, and does not expose the slug", () => {
    const html = render({ policyDescription: "Use <safe> dependencies & signed sources." });
    assert.match(html, /About this policy/);
    assert.match(html, /Use &lt;safe&gt; dependencies &amp; signed sources/);
    assert.doesNotMatch(html, />policy-a</);
  });

  test("shows accessible loading, stale, and actionable failure states", () => {
    const loading = render({
      current: { ...trace().current, status: null },
      parsedReason: null,
      refreshed: false,
    });
    assert.match(loading, /role="status" aria-live="polite"/);
    assert.doesNotMatch(loading, /⛔|Find safe version/);

    const noReason = render({
      current: { ...trace().current, statusReason: null },
      parsedReason: null,
      refreshed: false,
    });
    assert.match(noReason, /Loading quarantine details/);
    assert.doesNotMatch(noReason, /⛔|<dt>Action/);

    const stale = render({ current: { ...trace().current, status: "Available" }, error: "stale" });
    assert.match(stale, /no longer quarantined/);
    assert.doesNotMatch(stale, /Find safe version|Copy report/);

    const failed = render({ current: null, error: "load" });
    assert.match(failed, /Could not load quarantine details/);
    assert.match(failed, /data-command="retry"/);
  });

  test("renders primary explanation before optional policy description settles", async () => {
    const panelHarness = createWebviewPanelHarness();
    let resolvePolicy;
    const policyGate = new Promise(resolve => { resolvePolicy = resolve; });
    const calls = [];
    const provider = providerWith(panelHarness, {
      async get(endpoint) {
        calls.push(endpoint);
        return apiSuccess(freshPackage());
      },
      async getV2(endpoint) {
        calls.push(endpoint);
        if (endpoint.includes("/policies/policy-a/")) return policyGate;
        return emptyDecisionPage();
      },
    });

    const pending = provider.show(exactPackage());
    await tick();
    await tick();
    assert.match(panelHarness.panel.webview.html, /Dependency rule matched/);
    assert.match(panelHarness.panel.webview.html, /Find safe version/);
    assert.doesNotMatch(panelHarness.panel.webview.html, /About this policy/);
    resolvePolicy(apiSuccess({ slug_perm: "policy-a", description: "Blocks unsafe dependencies." }));
    await pending;
    assert.match(panelHarness.panel.webview.html, /About this policy/);
    assert.strictEqual(calls.filter(value => value.includes("decision-logs-v1")).length, 1);
    assert.strictEqual(calls.filter(value => value.includes("/policies/policy-a/")).length, 1);
  });

  test("optional policy failure preserves the useful primary explanation", async () => {
    const panelHarness = createWebviewPanelHarness();
    const provider = providerWith(panelHarness, {
      async get() { return apiSuccess(freshPackage()); },
      async getV2(endpoint) {
        return endpoint.includes("/policies/policy-a/")
          ? apiFailure("permission", { status: 403 })
          : emptyDecisionPage();
      },
    });
    await provider.show(exactPackage());
    const html = panelHarness.panel.webview.html;
    assert.match(html, /Dependency rule matched/);
    assert.doesNotMatch(html, /permission|403|incomplete|Could not load/);
  });

  test("production path renders a decision-only trace after exact detail reconciliation", async () => {
    const panelHarness = createWebviewPanelHarness();
    const provider = providerWith(panelHarness, {
      async get() {
        return apiSuccess(freshPackage({ status_reason: null }));
      },
      async getV2(endpoint) {
        if (/decision-logs-v1\/\d{26}\//.test(endpoint)) {
          return apiSuccess(decisionDetail());
        }
        if (endpoint.includes("decision-logs-v1")) {
          return decisionPage([decisionSummary()]);
        }
        return apiSuccess({ slug_perm: "policy-a", description: "Blocks unsafe dependencies." });
      },
    });
    await provider.show(exactPackage({ status_reason: null }));
    const html = panelHarness.panel.webview.html;
    assert.match(html, /Quarantine policy/);
    assert.match(html, /Dependency rule matched/);
    assert.match(html, /Decision recorded/);
    assert.doesNotMatch(html, /\[object Object\]|incomplete|decision log/i);
  });

  test("a tautological quarantine status reason does not suppress decision evidence", async () => {
    const panelHarness = createWebviewPanelHarness();
    let decisionCalls = 0;
    const provider = providerWith(panelHarness, {
      async get() { return apiSuccess(freshPackage({ status_reason: "Quarantined" })); },
      async getV2(endpoint) {
        if (/decision-logs-v1\/\d{26}\//.test(endpoint)) return apiSuccess(decisionDetail());
        if (endpoint.includes("decision-logs-v1")) {
          decisionCalls += 1;
          return decisionPage([decisionSummary()]);
        }
        return apiFailure("not_found", { status: 404 });
      },
    });
    await provider.show(exactPackage({ status_reason: "Quarantined" }));
    assert.strictEqual(decisionCalls, 1);
    assert.match(panelHarness.panel.webview.html, /Dependency rule matched/);
  });

  test("fresh status reason replaces provisional caller text", async () => {
    const panelHarness = createWebviewPanelHarness();
    const provider = providerWith(panelHarness, {
      async get() {
        return apiSuccess(freshPackage({
          status_reason: "Quarantined by Current policy. Current rule matched. (Policy: current-policy)",
        }));
      },
      async getV2(endpoint) {
        return endpoint.includes("/policies/current-policy/")
          ? apiFailure("not_found", { status: 404 })
          : emptyDecisionPage();
      },
    });
    await provider.show(exactPackage({
      status_reason: "Quarantined by Stale policy. Stale rule matched. (Policy: stale-policy)",
    }));
    const html = panelHarness.panel.webview.html;
    assert.match(html, /Current policy/);
    assert.match(html, /Current rule matched/);
    assert.doesNotMatch(html, /Stale policy|Stale rule matched/);
  });

  test("wrong policy detail identity is omitted", async () => {
    const panelHarness = createWebviewPanelHarness();
    const provider = providerWith(panelHarness, {
      async get() { return apiSuccess(freshPackage()); },
      async getV2(endpoint) {
        return endpoint.includes("/policies/policy-a/")
          ? apiSuccess({ slug_perm: "policy-b", description: "Wrong workspace policy." })
          : emptyDecisionPage();
      },
    });
    await provider.show(exactPackage());
    assert.doesNotMatch(panelHarness.panel.webview.html, /Wrong workspace policy/);
  });

  test("conflicting or malformed locator aliases fail before panel and API dispatch", async () => {
    const panelHarness = createWebviewPanelHarness();
    let calls = 0;
    const warnings = [];
    const provider = providerWith(panelHarness, {
      async get() { calls += 1; throw new Error("must not dispatch"); },
      async getV2() { calls += 1; throw new Error("must not dispatch"); },
    }, { warning: async value => { warnings.push(value); } });
    await provider.show(packageItem({ cloudsmithWorkspace: "workspace-b" }));
    await provider.show(packageItem({ slug_perm: { value: {} } }));
    assert.strictEqual(calls, 0);
    assert.strictEqual(panelHarness.panelCalls.length, 0);
    assert.strictEqual(warnings.length, 2);
  });

  test("provider entry rejects raw presentation identity before panel and API work", async () => {
    const panelHarness = createWebviewPanelHarness();
    let calls = 0;
    const warnings = [];
    const provider = providerWith(panelHarness, {
      async get() { calls += 1; throw new Error("must not dispatch"); },
      async getV2() { calls += 1; throw new Error("must not dispatch"); },
    }, { warning: async value => { warnings.push(value); } });

    await provider.show(packageItem());

    assert.strictEqual(calls, 0);
    assert.strictEqual(panelHarness.panelCalls.length, 0);
    assert.strictEqual(warnings.length, 1);
  });

  test("explicit boundaries adapt package, search, dependency, and legacy callers", async () => {
    const payload = nodePackagePayload();
    const nodeCases = [
      new PackageNode(payload, {}),
      new SearchResultNode(payload, {}),
      new DependencyHealthNode({
        name: payload.name,
        version: payload.version,
        format: payload.format,
        devDependency: false,
      }, payload, {}),
      packageItem({
        slug_perm_raw: null,
        slug_perm: { value: { value: "package-a" } },
        status_str_raw: null,
        status_str: { value: { value: "Quarantined" } },
        uploaded_at: { value: { value: payload.uploaded_at } },
        version: { value: { value: payload.version } },
      }),
    ];

    for (const item of nodeCases.map(fromPackageSelection)) {
      const panelHarness = createWebviewPanelHarness();
      const packageEndpoints = [];
      let resolveCurrent;
      const currentPackage = new Promise(resolve => { resolveCurrent = resolve; });
      const provider = providerWith(panelHarness, {
        async get(endpoint) {
          packageEndpoints.push(endpoint);
          return currentPackage;
        },
        async getV2(endpoint) {
          return endpoint.includes("/policies/policy-a/")
            ? apiFailure("not_found", { status: 404 })
            : emptyDecisionPage();
        },
      });

      const pending = provider.show(item);

      assert.strictEqual(panelHarness.panelCalls.length, 1);
      assert.match(packageEndpoints[0], /^packages\/workspace-a\/repo-a\/package-a\//);
      assert.match(panelHarness.panel.webview.html, /<h1[^>]*>artifact 1\.0\.0<\/h1>/);
      assert.match(panelHarness.panel.webview.html, /Dependency rule matched/);
      assert.match(panelHarness.panel.webview.html, /Refreshing current package status/);

      resolveCurrent(apiSuccess(freshPackage()));
      await pending;
      assert.match(panelHarness.panel.webview.html, /<h1[^>]*>artifact 1\.0\.0<\/h1>/);
      assert.match(panelHarness.panel.webview.html, /Dependency rule matched/);
      assert.doesNotMatch(panelHarness.panel.webview.html, /Refreshing current package status/);
    }
  });

  test("fresh identity drift fails closed and never enables commands", async () => {
    const panelHarness = createWebviewPanelHarness();
    const effects = [];
    const provider = providerWith(panelHarness, {
      async get() { return apiSuccess(freshPackage({ repository: "repo-b" })); },
      async getV2() { throw new Error("must not dispatch"); },
    }, {}, {
      packageActions: {
        findSafeVersion: async (...args) => { effects.push(args); },
      },
    });
    await provider.show(exactPackage());
    assert.match(panelHarness.panel.webview.html, /Could not load quarantine details/);
    await panelHarness.send({ command: "findSafeVersion" });
    assert.deepStrictEqual(effects, []);
  });

  test("keeps retry focus intent through loading and settles it in the same panel", async () => {
    const panelHarness = createWebviewPanelHarness();
    let calls = 0;
    let resolveRetry;
    const retryResult = new Promise(resolve => { resolveRetry = resolve; });
    const provider = providerWith(panelHarness, {
      async get() {
        calls += 1;
        return calls === 1
          ? apiFailure("server_error", { status: 500 })
          : retryResult;
      },
      async getV2() { return emptyDecisionPage(); },
    });
    await provider.show(exactPackage());
    assert.match(panelHarness.panel.webview.html, /data-command="retry"/);

    const pending = panelHarness.send({ command: "retry" });
    await tick();
    assert.strictEqual(panelHarness.panelCalls.length, 1);
    assert.match(panelHarness.panel.webview.html, /const retryFocus = "pending"/);
    assert.match(panelHarness.panel.webview.html, /data-retry-progress/);

    resolveRetry(apiSuccess(freshPackage()));
    await pending;
    assert.match(panelHarness.panel.webview.html, /const retryFocus = "settled"/);
    assert.match(panelHarness.panel.webview.html, /data-result-summary/);
  });

  test("fresh package 404 renders a stable unavailable state without enrichment", async () => {
    const panelHarness = createWebviewPanelHarness();
    let v2Calls = 0;
    const provider = providerWith(panelHarness, {
      async get() { return apiFailure("not_found", { status: 404 }); },
      async getV2() { v2Calls += 1; throw new Error("must not dispatch"); },
    });
    await provider.show(exactPackage());
    assert.match(panelHarness.panel.webview.html, /no longer available/);
    assert.doesNotMatch(panelHarness.panel.webview.html, /Quarantined|Find safe version/);
    assert.strictEqual(v2Calls, 0);
  });

  test("routes only exact messages after refresh and produces a causal report", async () => {
    const panelHarness = createWebviewPanelHarness();
    const effects = { actions: [], clipboard: [], external: [], information: [], warning: [] };
    const provider = providerWith(panelHarness, {
      async get() { return apiSuccess(freshPackage()); },
      async getV2(endpoint) {
        return endpoint.includes("/policies/policy-a/")
          ? apiSuccess({ slug_perm: "policy-a", description: "Blocks unsafe dependencies." })
          : emptyDecisionPage();
      },
    }, {
      information: async value => { effects.information.push(value); },
      warning: async value => { effects.warning.push(value); },
    }, {
      packageActions: {
        findSafeVersion: async (...args) => { effects.actions.push(["findSafeVersion", ...args]); },
        showVulnerabilities: async (...args) => {
          effects.actions.push(["showVulnerabilities", ...args]);
        },
      },
      openExternal: async value => { effects.external.push(value); },
      writeClipboard: async value => { effects.clipboard.push(value); },
    });
    await provider.show(exactPackage());

    for (const command of ["findSafeVersion", "showVulnerabilities", "openInCloudsmith", "copyReport"]) {
      await panelHarness.send({ command });
    }
    assert.deepStrictEqual(effects.actions.map(value => value[0]), [
      "findSafeVersion",
      "showVulnerabilities",
    ]);
    assert(effects.actions.every(value => value[1] === provider._operation.package));
    assert(effects.actions.every(value => typeof value[2] === "function" && value[2]() === true));
    assert.strictEqual(effects.external.length, 1);
    assert.match(effects.external[0], /^https:\/\/app\.cloudsmith\.com\//);
    assert.strictEqual(effects.clipboard.length, 1);
    assert.match(effects.clipboard[0], /^Quarantine report\n/);
    assert.match(effects.clipboard[0], /Status: Quarantined/);
    assert.doesNotMatch(effects.clipboard[0], /incomplete|decision log|policy-a/i);
    assert.deepStrictEqual(effects.information, ["Quarantine report copied."]);

    for (const message of [
      null,
      [],
      Object.create({ command: "copyReport" }),
      { command: "unknown" },
      { command: "copyReport", extra: true },
      { command: "openInCloudsmith", url: "https://evil.example" },
    ]) await panelHarness.send(message);
    assert.strictEqual(effects.clipboard.length, 1);
    assert.strictEqual(effects.external.length, 1);
  });

  test("report normalizes controls and formula-leading dynamic lines", () => {
    const provider = new QuarantineExplainProvider({});
    const value = trace({
      current: {
        ...trace().current,
        name: "=SUM(A1)\nStatus: Available",
        statusReason: "Reason\r\nAction: Available",
      },
      parsedReason: null,
    });
    const report = provider._buildPlainTextReport(value);
    assert.doesNotMatch(report, /\r/);
    assert.doesNotMatch(report, /\nStatus: Available/);
    assert.doesNotMatch(report, /\nAction: Available/);
  });

  test("account reset aborts stale loading before it can render", async () => {
    let state = { activationId: "account-a", accountEpoch: 1, sessionConnected: true };
    const panelHarness = createWebviewPanelHarness();
    let resolveFetch;
    let signal;
    const gate = new Promise(resolve => { resolveFetch = resolve; });
    const provider = providerWith(panelHarness, {
      async get(_endpoint, options) {
        signal = options.signal;
        await gate;
        return apiSuccess(freshPackage());
      },
      async getV2() { throw new Error("must not dispatch"); },
    }, {}, { connectionManager: { getState() { return { ...state }; } } });
    const pending = provider.show(exactPackage());
    await tick();
    state = { ...state, activationId: "account-b", accountEpoch: 2 };
    provider.resetForAccountChange();
    assert.strictEqual(signal.aborted, true);
    resolveFetch();
    await pending;
    assert.strictEqual(panelHarness.htmlWrites.length, 1);
    assert.strictEqual(panelHarness.stats.panelDisposals, 1);
    assert.strictEqual(panelHarness.activeMessageListenerCount(), 0);
  });

  test("a superseding package selection blocks the older completion", async () => {
    const harnesses = [createWebviewPanelHarness(), createWebviewPanelHarness()];
    let panelIndex = 0;
    let resolveFirst;
    const firstGate = new Promise(resolve => { resolveFirst = resolve; });
    const provider = new QuarantineExplainProvider({}, {
      cloudsmithAPI: {
        async get(endpoint) {
          if (endpoint.includes("package-a")) {
            await firstGate;
            return apiSuccess(freshPackage());
          }
          return apiSuccess(freshPackage({
            slug_perm: "package-b",
            name: "artifact-b",
            status_reason: "Quarantined by Policy B. Rule B matched. (Policy: policy-b)",
          }));
        },
        async getV2(endpoint) {
          if (endpoint.includes("/policies/policy-b/")) {
            return apiFailure("not_found", { status: 404 });
          }
          return emptyDecisionPage();
        },
      },
      connectionManager: connectedManager(),
      createNonce: () => "fixed-nonce",
      createWebviewPanel: (...args) => harnesses[panelIndex++].createWebviewPanel(...args),
      notifications: { information: async () => {}, warning: async () => {} },
    });
    const first = provider.show(exactPackage());
    await tick();
    const second = provider.show(exactPackage({
      name: "artifact-b",
      slug_perm: "package-b",
      slug_perm_raw: "package-b",
      status_reason: "Quarantined by Policy B. Rule B matched. (Policy: policy-b)",
    }));
    await second;
    resolveFirst();
    await first;
    assert.match(harnesses[1].panel.webview.html, /artifact-b/);
    assert.match(harnesses[1].panel.webview.html, /Policy B/);
    assert.doesNotMatch(harnesses[1].panel.webview.html, /Dependency policy/);
  });

  test("a newer retry remains authoritative when an older retry settles last", async () => {
    const panelHarness = createWebviewPanelHarness();
    let packageRequest = 0;
    let resolveOlder;
    let resolveNewer;
    const olderGate = new Promise(resolve => { resolveOlder = resolve; });
    const newerGate = new Promise(resolve => { resolveNewer = resolve; });
    const provider = providerWith(panelHarness, {
      async get() {
        packageRequest += 1;
        if (packageRequest === 2) {
          await olderGate;
          return apiSuccess(freshPackage({
            status_reason: "Quarantined by Older policy. Older rule matched.",
          }));
        }
        if (packageRequest === 3) {
          await newerGate;
          return apiSuccess(freshPackage({
            status_reason: "Quarantined by Newer policy. Newer rule matched.",
          }));
        }
        return apiSuccess(freshPackage({
          status_reason: "Quarantined by Initial policy. Initial rule matched.",
        }));
      },
      async getV2() { throw new Error("must not dispatch"); },
    });
    await provider.show(exactPackage());

    const older = panelHarness.send({ command: "retry" });
    await tick();
    assert.strictEqual(packageRequest, 2);
    const newer = panelHarness.send({ command: "retry" });
    await tick();
    assert.strictEqual(packageRequest, 3);

    resolveNewer();
    await newer;
    assert.match(panelHarness.panel.webview.html, /Newer rule matched/);
    resolveOlder();
    await older;

    assert.match(panelHarness.panel.webview.html, /Newer rule matched/);
    assert.doesNotMatch(panelHarness.panel.webview.html, /Older rule matched/);
    assert.match(provider._operation.package.statusReason, /Newer rule matched/);
  });

  test("commands remain inert until current identity and status are confirmed", async () => {
    const panelHarness = createWebviewPanelHarness();
    const actions = [];
    let resolveFetch;
    const gate = new Promise(resolve => { resolveFetch = resolve; });
    const provider = providerWith(panelHarness, {
      async get() { await gate; return apiSuccess(freshPackage()); },
      async getV2(endpoint) {
        return endpoint.includes("/policies/policy-a/")
          ? apiFailure("not_found", { status: 404 })
          : emptyDecisionPage();
      },
    }, {}, {
      packageActions: {
        findSafeVersion: async (...args) => { actions.push(args); },
      },
    });
    const pending = provider.show(exactPackage());
    await tick();
    await panelHarness.send({ command: "findSafeVersion" });
    assert.deepStrictEqual(actions, []);
    resolveFetch();
    await pending;
    await panelHarness.send({ command: "findSafeVersion" });
    assert.strictEqual(actions.length, 1);
  });

  function providerWith(panelHarness, cloudsmithAPI, notifications = {}, overrides = {}) {
    return new QuarantineExplainProvider({}, {
      cloudsmithAPI,
      connectionManager: connectedManager(),
      createNonce: () => "fixed-nonce",
      createWebviewPanel: panelHarness.createWebviewPanel,
      notifications: {
        information: notifications.information || (async () => {}),
        warning: notifications.warning || (async () => {}),
      },
      ...overrides,
    });
  }

  function freshPackage(overrides = {}) {
    return {
      namespace: "workspace-a",
      repository: "repo-a",
      slug_perm: "package-a",
      name: "artifact",
      version: "1.0.0",
      format: "npm",
      status_str: "Quarantined",
      status_reason: "Quarantined by Dependency policy. Dependency rule matched. (Policy: policy-a)",
      uploaded_at: "2026-08-13T10:00:00.000Z",
      ...overrides,
    };
  }

  function emptyDecisionPage() {
    return apiSuccess({ results: [] }, {
      headers: {
        "x-pagination-page": "1",
        "x-pagination-pagetotal": "1",
        "x-pagination-pagesize": "100",
        "x-pagination-count": "0",
      },
    });
  }

  function decisionPage(results) {
    return apiSuccess({ results }, {
      headers: {
        "x-pagination-page": "1",
        "x-pagination-pagetotal": "1",
        "x-pagination-pagesize": "100",
        "x-pagination-count": String(results.length),
      },
    });
  }

  function decisionSummary() {
    return {
      id: "00000000000000000000000001",
      actions: { action_type: "SetPackageState", package_state: "QUARANTINED" },
      correlation_id: "00000000-0000-4000-8000-000000000001",
      ended_at: "2026-08-13T12:00:01.000Z",
      match: true,
      package_format: "NPM",
      package_name: "artifact",
      package_slug: "artifact",
      package_slug_perm: "package-a",
      package_version: "1.0.0",
      policy_is_terminal: true,
      policy_name: "Quarantine policy",
      policy_precedence: 1,
      policy_slug_perm: "policy-a",
      policy_version: 1,
      repository_name: "Repository A",
      repository_slug: "repo-a",
      repository_slug_perm: "repo-perm-a",
      started_at: "2026-08-13T12:00:00.000Z",
    };
  }

  function decisionDetail() {
    return {
      id: "00000000000000000000000001",
      correlation_id: "00000000-0000-4000-8000-000000000001",
      policy: { slug_perm: "policy-a" },
      started_at: "2026-08-13T12:00:00.000Z",
      ended_at: "2026-08-13T12:00:01.000Z",
      policy_input: {
        v0: {
          workspace: { slug: "workspace-a", slug_perm: "workspace-perm-a" },
          repository: { slug: "repo-a", slug_perm: "repo-perm-a" },
          package: { slug: "artifact", slug_perm: "package-a" },
        },
      },
      policy_output: { reason: "Dependency rule matched." },
      parsed_actions: [{ action_type: "SetPackageState", package_state: "QUARANTINED" }],
    };
  }
});

function connectedManager() {
  return {
    getState() {
      return { activationId: "account-a", accountEpoch: 1, sessionConnected: true };
    },
  };
}

function packageItem(overrides = {}) {
  return {
    namespace: "workspace-a",
    cloudsmithWorkspace: "workspace-a",
    repository: "repo-a",
    cloudsmithRepo: "repo-a",
    name: "artifact",
    format: "npm",
    slug_perm: "package-a",
    slug_perm_raw: "package-a",
    version: "1.0.0",
    status_str_raw: "Quarantined",
    status_reason: "Quarantined by Dependency policy. Dependency rule matched. (Policy: policy-a)",
    uploaded_at: "2026-08-13T10:00:00.000Z",
    ...overrides,
  };
}

function exactPackage(overrides = {}) {
  return fromPackageSelection(packageItem(overrides));
}

function nodePackagePayload() {
  return {
    downloads: 0,
    format: "npm",
    name: "artifact",
    namespace: "workspace-a",
    repository: "repo-a",
    slug: "artifact-1.0.0",
    slug_perm: "package-a",
    status_reason: "Quarantined by Dependency policy. Dependency rule matched. (Policy: policy-a)",
    status_str: "Quarantined",
    tags: {},
    uploaded_at: "2026-08-13T10:00:00.000Z",
    version: "1.0.0",
  };
}

function tick() {
  return new Promise(resolve => setImmediate(resolve));
}

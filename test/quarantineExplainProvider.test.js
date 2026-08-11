const assert = require("assert");
const { QuarantineExplainProvider } = require("../views/quarantineExplainProvider");
const { createWebviewPanelHarness } = require("./helpers/webviewPanelHarness");

suite("QuarantineExplainProvider policy completeness", () => {
  function render(trace) {
    const provider = new QuarantineExplainProvider({});
    return provider._getHtmlContent(
      "nonce",
      "artifact",
      "1.0.0",
      "npm",
      "workspace-a",
      "repo-a",
      "package-a",
      "Quarantined by Policy. Rule matched. (Policy: policy-a)",
      null,
      trace
    );
  }

  test("does not claim a non-vulnerability quarantine when policy history is incomplete", () => {
    const html = render({
      parsedReason: null,
      decisionLogs: [],
      decisionLogsComplete: false,
      decisionLogsPartial: true,
      policyDetail: null,
    });

    assert.match(html, /Policy decision log history is incomplete/);
    assert.doesNotMatch(html, /not a specific vulnerability/);
  });

  test("allows a non-vulnerability conclusion only after complete policy history", () => {
    const html = render({
      parsedReason: null,
      decisionLogs: [],
      decisionLogsComplete: true,
      decisionLogsPartial: false,
      policyDetail: null,
    });

    assert.match(html, /not a specific vulnerability/);
    assert.doesNotMatch(html, /Policy decision log history is incomplete/);
  });

  test("renders a missing policy match flag as unknown rather than no", () => {
    const html = render({
      parsedReason: null,
      decisionLogs: [{ policy_name: "Policy", matched: null }],
      decisionLogsComplete: true,
      decisionLogsPartial: false,
      policyDetail: null,
    });

    assert.match(html, /<td>Unknown<\/td>/);
    assert.doesNotMatch(html, /<td>No<\/td>/);
  });

  test("account reset aborts stale policy loading before it can render", async () => {
    let state = {
      activationId: "account-a",
      accountEpoch: 1,
      sessionConnected: true,
    };
    const panelHarness = createWebviewPanelHarness();
    let resolveFetch;
    const gate = new Promise(resolve => { resolveFetch = resolve; });
    let signal;
    const provider = new QuarantineExplainProvider({}, {
      connectionManager: { getState() { return { ...state }; } },
      createWebviewPanel: panelHarness.createWebviewPanel,
      createNonce: () => "fixed-nonce",
    });
    provider._fetchPolicyDecisionTrace = async (_api, _workspace, _slug, _reason, requestSignal) => {
      signal = requestSignal;
      await gate;
      return {
        parsedReason: null,
        decisionLogs: [],
        decisionLogsComplete: true,
        policyDetail: null,
      };
    };

    const pending = provider.show(packageItem());
    await new Promise(resolve => setImmediate(resolve));
    state = { ...state, activationId: "account-b", accountEpoch: 2 };
    provider.resetForAccountChange();
    assert.strictEqual(signal.aborted, true);
    resolveFetch();
    await pending;
    assert.strictEqual(panelHarness.htmlWrites.length, 1);
    assert.strictEqual(panelHarness.stats.panelDisposals, 1);
    assert.strictEqual(panelHarness.stats.disposeDisposals, 1);
    assert.strictEqual(panelHarness.activeDisposeListenerCount(), 0);
  });

  test("routes only exact own-data messages and cleans up stale listeners", async () => {
    const panelHarness = createWebviewPanelHarness();
    const effects = { commands: [], clipboard: [], external: [], information: [], warning: [] };
    let requestSignal;
    const provider = new QuarantineExplainProvider({}, {
      connectionManager: connectedManager(),
      createWebviewPanel: panelHarness.createWebviewPanel,
      createNonce: () => "fixed-nonce",
      executeCommand: async (...args) => { effects.commands.push(args); },
      writeClipboard: async value => { effects.clipboard.push(value); },
      openExternal: async value => { effects.external.push(value); },
      notifications: {
        information: async value => { effects.information.push(value); },
        warning: async value => { effects.warning.push(value); },
      },
    });
    provider._fetchPolicyDecisionTrace = async (_api, _workspace, _slug, _reason, signal) => {
      requestSignal = signal;
      return {
        parsedReason: null,
        decisionLogs: [{ policy_name: "Policy", reason: "CVE-2026-5001" }],
        decisionLogsComplete: true,
        decisionLogsPartial: false,
        policyDetail: null,
      };
    };

    await provider.show(packageItem());

    assert.deepStrictEqual(panelHarness.panelCalls[0][3], {
      enableScripts: true,
      localResourceRoots: [],
    });
    assert.match(panelHarness.panel.webview.html, /nonce="fixed-nonce"/);
    await panelHarness.send({ command: "findSafeVersion" });
    await panelHarness.send({ command: "showVulnerabilities" });
    await panelHarness.send({ command: "openInCloudsmith" });
    await panelHarness.send({ command: "copyReport" });
    assert.deepStrictEqual(effects.commands.map(call => call[0]), [
      "cloudsmith-vsc.findSafeVersion",
      "cloudsmith-vsc.showVulnerabilities",
    ]);
    assert.strictEqual(effects.clipboard.length, 1);
    assert.deepStrictEqual(effects.information, ["Quarantine report copied."]);
    assert.strictEqual(effects.external.length, 1);
    assert.match(effects.external[0], /^https:\/\/app\.cloudsmith\.com\//);

    let accessorReads = 0;
    const accessorMessage = {};
    Object.defineProperty(accessorMessage, "command", {
      enumerable: true,
      get() { accessorReads += 1; return "copyReport"; },
    });
    for (const message of [
      null,
      [],
      accessorMessage,
      Object.create({ command: "copyReport" }),
      { command: "unknown" },
      { command: "copyReport", extra: "unexpected" },
      { command: "openInCloudsmith", url: "https://evil.example/" },
      { command: "x".repeat(65) },
    ]) {
      await panelHarness.send(message);
    }
    assert.strictEqual(accessorReads, 0);
    assert.strictEqual(effects.commands.length, 2);
    assert.strictEqual(effects.clipboard.length, 1);
    assert.strictEqual(effects.external.length, 1);
    assert.deepStrictEqual(effects.warning, []);

    provider.dispose();
    provider.dispose();
    assert.strictEqual(requestSignal.aborted, true);
    assert.strictEqual(panelHarness.stats.panelDisposals, 1);
    assert.strictEqual(panelHarness.stats.messageDisposals, 1);
    assert.strictEqual(panelHarness.stats.disposeDisposals, 1);
    assert.strictEqual(panelHarness.activeMessageListenerCount(), 0);
    assert.strictEqual(panelHarness.activeDisposeListenerCount(), 0);
    await panelHarness.sendToStaleListener({ command: "copyReport" });
    assert.strictEqual(effects.clipboard.length, 1);
  });
});

function connectedManager() {
  return {
    getState() {
      return {
        activationId: "account-a",
        accountEpoch: 1,
        sessionConnected: true,
      };
    },
  };
}

function packageItem() {
  return {
    namespace: "workspace-a",
    repository: "repo-a",
    name: "artifact",
    format: "npm",
    slug_perm_raw: "package-a",
    version: "1.0.0",
  };
}

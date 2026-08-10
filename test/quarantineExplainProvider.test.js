const assert = require("assert");
const vscode = require("vscode");
const { QuarantineExplainProvider } = require("../views/quarantineExplainProvider");

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
    const originalCreateWebviewPanel = vscode.window.createWebviewPanel;
    let state = {
      activationId: "account-a",
      accountEpoch: 1,
      sessionConnected: true,
    };
    const htmlWrites = [];
    let disposeHandler;
    const panel = {
      webview: {
        set html(value) { htmlWrites.push(value); },
        get html() { return htmlWrites[htmlWrites.length - 1]; },
        onDidReceiveMessage() { return { dispose() {} }; },
      },
      onDidDispose(handler) { disposeHandler = handler; return { dispose() {} }; },
      dispose() { if (disposeHandler) disposeHandler(); },
    };
    let resolveFetch;
    const gate = new Promise(resolve => { resolveFetch = resolve; });
    let signal;
    vscode.window.createWebviewPanel = () => panel;
    try {
      const provider = new QuarantineExplainProvider({}, {
        connectionManager: { getState() { return { ...state }; } },
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

      const pending = provider.show({
        namespace: "workspace-a",
        repository: "repo-a",
        name: "artifact",
        format: "npm",
        slug_perm_raw: "package-a",
        version: "1.0.0",
      });
      await new Promise(resolve => setImmediate(resolve));
      state = { ...state, activationId: "account-b", accountEpoch: 2 };
      provider.resetForAccountChange();
      assert.strictEqual(signal.aborted, true);
      resolveFetch();
      await pending;
      assert.strictEqual(htmlWrites.length, 1);
    } finally {
      vscode.window.createWebviewPanel = originalCreateWebviewPanel;
    }
  });
});

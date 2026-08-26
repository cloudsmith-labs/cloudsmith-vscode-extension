// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const vscode = require("vscode");
const { registerVulnerabilityCommands } = require("../commands/vulnerabilities");
const packageAdapters = require("../domain/packageAdapters");
const packageDomain = require("../domain/package");
const { QuarantineExplainProvider } = require("../views/quarantineExplainProvider");
const { VulnerabilityProvider } = require("../views/vulnerabilityProvider");
const { apiSuccess } = require("./apiResultHelpers");
const { createWebviewPanelHarness } = require("./helpers/webviewPanelHarness");
const { captureAccount, isAccountCurrent } = require("../util/accountOperation");

suite("WebView package action flow", () => {
  test("Quarantine Show vulnerabilities reaches the real target without tree provenance", async () => {
    const flow = createFlow();
    const source = exactPackage();

    await flow.quarantineProvider.show(source);
    assert.notStrictEqual(flow.quarantineProvider._operation.package, source);
    await flow.quarantineHarness.send({ command: "showVulnerabilities" });

    assert.strictEqual(flow.vulnerabilityHarness.panelCalls.length, 1);
    assert.match(flow.vulnerabilityHarness.panel.webview.html, /axios 1\.7\.2/);
    assertExactIdentity(flow.vulnerabilityProvider._operation.package, source);
  });

  test("Quarantine Find safe version reaches a truthful shared-workflow result", async () => {
    const flow = createFlow();
    const source = exactPackage();

    await flow.quarantineProvider.show(source);
    await flow.quarantineHarness.send({ command: "findSafeVersion" });

    assert.deepStrictEqual(flow.remediationCalls.map(call => call.source), [
      {
        workspace: source.workspace,
        repository: source.repository,
        name: source.name,
        format: source.format,
        version: source.version,
      },
    ]);
    assertExactIdentity(flow.resolvedPackages[0], source);
    assert.deepStrictEqual(flow.information, [
      'No compatible safe version for "axios" is available in common-testing. The reported fix is 1.8.2.',
    ]);
  });

  test("Vulnerability WebView actions use current panel provenance in both directions", async () => {
    const flow = createFlow();
    const source = exactPackage();

    await flow.vulnerabilityProvider.show(source);
    assert.match(flow.vulnerabilityHarness.panel.webview.html, /View quarantine details/);
    await flow.vulnerabilityHarness.send({ command: "findSafeVersion" });
    await flow.vulnerabilityHarness.send({ command: "explainQuarantine" });

    assert.strictEqual(flow.remediationCalls.length, 1);
    assert.strictEqual(flow.quarantineHarness.panelCalls.length, 1);
    assert.match(flow.quarantineHarness.panel.webview.html, /axios 1\.7\.2/);
    assertExactIdentity(flow.quarantineProvider._operation.package, source);
  });

  test("registered tree commands still reject arbitrary exact package arguments", async () => {
    const flow = createFlow();
    const arbitrary = exactPackage();

    await flow.handlers.get("cloudsmith-vsc.showVulnerabilities")(arbitrary);
    await flow.handlers.get("cloudsmith-vsc.findSafeVersion")(arbitrary);
    await flow.handlers.get("cloudsmith-vsc.explainQuarantine")(arbitrary);

    assert.strictEqual(flow.vulnerabilityHarness.panelCalls.length, 0);
    assert.strictEqual(flow.quarantineHarness.panelCalls.length, 0);
    assert.strictEqual(flow.remediationCalls.length, 0);
    assert.deepStrictEqual(flow.information, []);
  });

  test("current unsupported reciprocal action is unavailable and explains direct messages", async () => {
    const flow = createFlow();
    await flow.vulnerabilityProvider.show(exactPackage({
      status: "Completed",
      statusReason: null,
    }));

    assert.doesNotMatch(flow.vulnerabilityHarness.panel.webview.html, /View quarantine details/);
    await flow.vulnerabilityHarness.send({ command: "explainQuarantine" });

    assert.strictEqual(flow.quarantineHarness.panelCalls.length, 0);
    assert.deepStrictEqual(flow.warning, [
      "Quarantine details are available only for quarantined packages.",
    ]);
  });

  test("disposed WebView messages cannot enter package workflows", async () => {
    const flow = createFlow();
    await flow.quarantineProvider.show(exactPackage());
    flow.quarantineHarness.panel.dispose();

    await flow.quarantineHarness.sendToStaleListener({ command: "showVulnerabilities" });
    await flow.quarantineHarness.sendToStaleListener({ command: "findSafeVersion" });

    assert.strictEqual(flow.vulnerabilityHarness.panelCalls.length, 0);
    assert.strictEqual(flow.remediationCalls.length, 0);
    assert.deepStrictEqual(flow.information, []);
  });

  test("disposal during WebView remediation cancels every later effect", async () => {
    const remediation = deferred();
    const flow = createFlow({ remediationGate: remediation.promise });
    await flow.quarantineProvider.show(exactPackage());

    const pending = flow.quarantineHarness.send({ command: "findSafeVersion" });
    await until(() => flow.remediationCalls.length === 1);
    flow.quarantineHarness.panel.dispose();
    remediation.resolve({ success: true, versions: [], absenceProven: true });
    await pending;

    assert.deepStrictEqual(flow.information, []);
    assert.deepStrictEqual(flow.warning, []);
    assert.deepStrictEqual(flow.error, []);
    assert.deepStrictEqual(flow.recent, []);
    assert.strictEqual(flow.vulnerabilityHarness.panelCalls.length, 0);
  });

  test("account change during WebView remediation cancels every later effect", async () => {
    const remediation = deferred();
    const flow = createFlow({ remediationGate: remediation.promise });
    await flow.vulnerabilityProvider.show(exactPackage());

    const pending = flow.vulnerabilityHarness.send({ command: "findSafeVersion" });
    await until(() => flow.remediationCalls.length === 1);
    flow.switchAccount();
    remediation.resolve({ success: true, versions: [], absenceProven: true });
    await pending;

    assert.deepStrictEqual(flow.information, []);
    assert.deepStrictEqual(flow.warning, []);
    assert.deepStrictEqual(flow.error, []);
    assert.deepStrictEqual(flow.recent, []);
    assert.strictEqual(flow.quarantineHarness.panelCalls.length, 0);
  });

  test("Quarantine retry revokes remediation started from the prior package evidence", async () => {
    const remediation = deferred();
    const flow = createFlow({ remediationGate: remediation.promise });
    await flow.quarantineProvider.show(exactPackage());

    const pending = flow.quarantineHarness.send({ command: "findSafeVersion" });
    await until(() => flow.remediationCalls.length === 1);
    await flow.quarantineHarness.send({ command: "retry" });
    remediation.resolve({ success: true, versions: [], absenceProven: true });
    await pending;

    assert.deepStrictEqual(flow.information, []);
    assert.deepStrictEqual(flow.warning, []);
    assert.deepStrictEqual(flow.error, []);
    assert.deepStrictEqual(flow.recent, []);
    assert.strictEqual(flow.vulnerabilityHarness.panelCalls.length, 0);
  });

  test("Vulnerability retry revokes remediation started from the prior result generation", async () => {
    const remediation = deferred();
    const flow = createFlow({ remediationGate: remediation.promise });
    await flow.vulnerabilityProvider.show(exactPackage());

    const pending = flow.vulnerabilityHarness.send({ command: "findSafeVersion" });
    await until(() => flow.remediationCalls.length === 1);
    await flow.vulnerabilityHarness.send({ command: "retry" });
    remediation.resolve({ success: true, versions: [], absenceProven: true });
    await pending;

    assert.deepStrictEqual(flow.information, []);
    assert.deepStrictEqual(flow.warning, []);
    assert.deepStrictEqual(flow.error, []);
    assert.deepStrictEqual(flow.recent, []);
    assert.strictEqual(flow.quarantineHarness.panelCalls.length, 0);
  });

  test("Quarantine retry suppresses a late failure from the revoked action", async () => {
    const remediation = deferred();
    const flow = createFlow({ remediationGate: remediation.promise });
    await flow.quarantineProvider.show(exactPackage());

    const pending = flow.quarantineHarness.send({ command: "findSafeVersion" });
    await until(() => flow.remediationCalls.length === 1);
    await flow.quarantineHarness.send({ command: "retry" });
    remediation.reject(new Error("revoked quarantine action"));
    await pending;

    assert.deepStrictEqual(flow.information, []);
    assert.deepStrictEqual(flow.warning, []);
    assert.deepStrictEqual(flow.error, []);
    assert.deepStrictEqual(flow.recent, []);
  });

  test("Vulnerability retry suppresses a late failure from the revoked action", async () => {
    const remediation = deferred();
    const flow = createFlow({ remediationGate: remediation.promise });
    await flow.vulnerabilityProvider.show(exactPackage());

    const pending = flow.vulnerabilityHarness.send({ command: "findSafeVersion" });
    await until(() => flow.remediationCalls.length === 1);
    await flow.vulnerabilityHarness.send({ command: "retry" });
    remediation.reject(new Error("revoked vulnerability action"));
    await pending;

    assert.deepStrictEqual(flow.information, []);
    assert.deepStrictEqual(flow.warning, []);
    assert.deepStrictEqual(flow.error, []);
    assert.deepStrictEqual(flow.recent, []);
  });
});

function createFlow(options = {}) {
  const handlers = new Map();
  const information = [];
  const warning = [];
  const error = [];
  const remediationCalls = [];
  const resolvedPackages = [];
  const recent = [];
  let accountState = {
    activationId: "account-a",
    accountEpoch: 1,
    sessionConnected: true,
  };
  const connectionManager = connectedManager(() => accountState);
  const quarantineHarness = createWebviewPanelHarness();
  const vulnerabilityHarness = createWebviewPanelHarness();
  let quarantineProvider;
  let vulnerabilityProvider;

  class RecordingRemediationHelper {
    async findSafeVersions(workspace, repository, name, format, actionOptions) {
      remediationCalls.push({
        source: {
          workspace,
          repository,
          name,
          format,
          version: actionOptions.currentVersion,
        },
        options: actionOptions,
      });
      if (options.remediationGate) return options.remediationGate;
      return options.remediationResult || {
        success: true,
        versions: [],
        absenceProven: true,
      };
    }
  }

  const vulnerabilityStateService = options.vulnerabilityStateService || {
    prime() {},
    peek() { return null; },
    async resolve(pkg) { resolvedPackages.push(pkg); return vulnerableState(); },
    async refresh() { return vulnerableState(); },
  };
  const vscodeFacade = {
    CancellationTokenSource: vscode.CancellationTokenSource,
    QuickPickItemKind: vscode.QuickPickItemKind,
    Uri: vscode.Uri,
    commands: { async executeCommand() {} },
    env: {
      clipboard: { async writeText() {} },
      async openExternal() {},
    },
    window: {
      async showErrorMessage(message) { error.push(message); },
      async showInformationMessage(message) { information.push(message); },
      async showWarningMessage(message) { warning.push(message); },
      async showQuickPick() { return undefined; },
    },
  };
  const registration = registerVulnerabilityCommands({
    registerCommand(id, handler) {
      handlers.set(id, handler);
      return { dispose() { handlers.delete(id); } };
    },
    vscode: vscodeFacade,
    context: {},
    workspaceAccess: {
      connectionManager,
      captureAccount,
      isAccountCurrent,
    },
    packageAdapters,
    packageDomain,
    recentPackages: {
      add(value) { recent.push(value); },
      getAll() { return recent.slice(); },
    },
    CloudsmithAPI: class {},
    RemediationHelper: RecordingRemediationHelper,
    InstallCommandBuilder: class {},
    InstallCommandValidationError: class extends Error {},
    buildPackageUrl: () => "https://app.cloudsmith.com/package",
    vulnerabilityProvider: { show: (...args) => vulnerabilityProvider.show(...args) },
    quarantineExplainProvider: { show: (...args) => quarantineProvider.show(...args) },
    cloudsmithProvider: { refreshNode() {} },
    searchProvider: { refreshNode() {} },
    dependencyHealthProvider: { refreshNode() {}, getLastSuccessfulScope: () => null },
    vulnerabilityStateService,
    normalizeCvssScore: value => Number(value),
    formatApiError: () => "Retry.",
    isCurrentSelection: () => false,
    isCurrentPackageSelection: () => false,
    isCurrentDependencySelection: () => false,
  });
  const executeCommand = async (id, ...args) => handlers.get(id)?.(...args);
  const packageActions = registration.webviewActions;
  const notifications = {
    information: async message => { information.push(message); },
    warning: async message => { warning.push(message); },
  };
  quarantineProvider = new QuarantineExplainProvider({}, {
    cloudsmithAPI: quarantineApi(),
    connectionManager,
    createNonce: () => "fixed-nonce",
    createWebviewPanel: quarantineHarness.createWebviewPanel,
    executeCommand,
    packageActions,
    notifications,
  });
  vulnerabilityProvider = new VulnerabilityProvider({}, {
    connectionManager,
    vulnerabilityStateService,
    createNonce: () => "fixed-nonce",
    createWebviewPanel: vulnerabilityHarness.createWebviewPanel,
    executeCommand,
    packageActions,
    notifications,
  });

  return {
    error,
    handlers,
    information,
    quarantineHarness,
    quarantineProvider,
    recent,
    registration,
    remediationCalls,
    resolvedPackages,
    switchAccount() {
      accountState = {
        activationId: "account-b",
        accountEpoch: 2,
        sessionConnected: true,
      };
    },
    vulnerabilityHarness,
    vulnerabilityProvider,
    warning,
  };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

async function until(predicate) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (predicate()) return;
    await new Promise(resolve => setImmediate(resolve));
  }
  assert.fail("Timed out waiting for the WebView action boundary.");
}

function connectedManager(readState = () => ({
  activationId: "account-a",
  accountEpoch: 1,
  sessionConnected: true,
})) {
  return {
    getState() { return { ...readState() }; },
    onDidChange() { return { dispose() {} }; },
  };
}

function exactPackage(overrides = {}) {
  return packageDomain.createExactPackage({
    workspace: "dl-technology-consulting",
    repository: "common-testing",
    packageIdentifier: "axios-1-7-2",
    name: "axios",
    coordinateName: "axios",
    version: "1.7.2",
    format: "npm",
    qualifiers: { architecture: "universal", environment: "production" },
    status: "Quarantined",
    statusReason: "Quarantined by vulnerability policy.",
    copyable: false,
    policy: { violated: true, denyViolated: true, vulnerabilityViolated: true },
    vulnerability: {
      evidence: "detected",
      detected: true,
      count: 1,
      maxSeverity: "High",
    },
    ...overrides,
  });
}

function quarantineApi() {
  return {
    async get() {
      return apiSuccess({
        namespace: "dl-technology-consulting",
        repository: "common-testing",
        slug_perm: "axios-1-7-2",
        name: "axios",
        version: "1.7.2",
        format: "npm",
        status_str: "Quarantined",
        status_reason: "Quarantined by vulnerability policy.",
        uploaded_at: "2026-08-25T12:00:00.000Z",
      });
    },
    async getV2() {
      return apiSuccess({ results: [] }, {
        headers: {
          "x-pagination-page": "1",
          "x-pagination-pagetotal": "1",
          "x-pagination-pagesize": "100",
          "x-pagination-count": "0",
        },
      });
    },
  };
}

function vulnerableState() {
  return Object.freeze({
    status: "complete-vulnerable",
    complete: true,
    stale: false,
    count: 1,
    maxSeverity: "High",
    records: Object.freeze([Object.freeze({
      vulnerability_id: "CVE-2026-1720",
      severity: "High",
      fixed_version: Object.freeze({ version: "1.8.2" }),
      references: Object.freeze(["https://nvd.nist.gov/vuln/detail/CVE-2026-1720"]),
    })]),
  });
}

function assertExactIdentity(actual, expected) {
  assert.strictEqual(actual.workspace, expected.workspace);
  assert.strictEqual(actual.repository, expected.repository);
  assert.strictEqual(actual.format, expected.format);
  assert.strictEqual(actual.name, expected.name);
  assert.strictEqual(actual.version, expected.version);
  assert.strictEqual(actual.packageIdentifier, expected.packageIdentifier);
  assert.deepStrictEqual(actual.qualifiers, expected.qualifiers);
  assert.strictEqual(actual.status, expected.status);
  assert.strictEqual(actual.statusReason, expected.statusReason);
}

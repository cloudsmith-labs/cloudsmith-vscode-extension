// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const vscode = require("vscode");
const manifest = require("../package.json");
const { registerAuthenticationCommands } = require("../commands/authentication");
const { registerSettingsHelpCommands } = require("../commands/settingsHelp");
const { registerPackageCommands } = require("../commands/packages");
const { registerSearchCommands } = require("../commands/search");
const { registerDependencyHealthCommands } = require("../commands/dependencyHealth");
const { registerVulnerabilityCommands } = require("../commands/vulnerabilities");
const { registerPromotionCommands } = require("../commands/promotion");
const { registerUpstreamCommands } = require("../commands/upstream");
const { registerCommands } = require("../commands/registrar");
const packageDomain = require("../domain/package");
const packageAdapters = require("../domain/packageAdapters");
const {
  serializePackageCollectionInspection,
  serializePackageInspection,
} = require("../util/packageInspection");
const { normalizeCvssScore } = require("../util/vulnerabilitySeverity");
const { openExternalWithFeedback } = require("../util/externalNavigation");
const { HELP_LINKS } = require("../util/helpLinks");
const {
  InstallCommandBuilder,
  InstallCommandValidationError,
} = require("../util/installCommandBuilder");
const { helpProvider } = require("../views/helpProvider");

const INTERNAL_COMMANDS = [
  "cloudsmith-vsc.scanDependenciesPending",
  "cloudsmith-vsc.scanDependenciesComplete",
  "cloudsmith-vsc.rescanDependencies",
  "cloudsmith-vsc.cycleDepViewDirect",
  "cloudsmith-vsc.cycleDepViewFlat",
  "cloudsmith-vsc.cycleDepViewTree",
  "cloudsmith-vsc.depSortFilterActive",
];

function deferred() {
  let resolve;
  const promise = new Promise(resolvePromise => { resolve = resolvePromise; });
  return { promise, resolve };
}

function recordingRegistration(effects = {}) {
  const handlers = new Map();
  const disposed = [];
  return {
    disposed,
    handlers,
    registerCommand(id, handler) {
      if (effects.onRegister) effects.onRegister(id);
      handlers.set(id, handler);
      return {
        dispose() {
          disposed.push(id);
          if (handlers.get(id) === handler) handlers.delete(id);
          if (effects.throwOnDispose === id) throw new Error("dispose failed");
        },
      };
    },
  };
}

function baseDependencies(recorder) {
  return {
    registerCommand: recorder.registerCommand.bind(recorder),
    vscode: {},
    LicenseClassifier: { buildRestrictiveQuery: () => "license:restrictive" },
    FORMAT_OPTIONS: [],
    upstreamPreview: { async previewResolution() { return null; } },
    upstreamExport: {
      async getPrivilegedRepositoryUpstreamsForExport() { return null; },
    },
    isCurrentSelection: () => true,
    isCurrentPackageSelection: () => true,
    isCurrentPackageGroupSelection: () => true,
    isCurrentRepositorySelection: () => true,
    isCurrentWorkspaceSelection: () => true,
    isCurrentDependencySelection: () => true,
    isCurrentEntitlementSelection: () => true,
    workspaceAccess: currentAccountAccess(),
    serializePackageCollectionInspection,
    serializePackageInspection,
    normalizeCvssScore,
    openExternalWithFeedback,
    helpLinks: HELP_LINKS,
  };
}

function completeVulnerableStateService() {
  const state = Object.freeze({
    status: "complete-vulnerable",
    complete: true,
    stale: false,
    count: 1,
    records: Object.freeze([Object.freeze({ vulnerability_id: "CVE-2026-0001" })]),
  });
  return {
    prime() { return state; },
    async resolve() { return state; },
  };
}

function currentAccountAccess(overrides = {}) {
  return accountAccessHarness(overrides).access;
}

function accountAccessHarness(overrides = {}) {
  const connectionManager = overrides.connectionManager || {
    getAuthenticationCapabilities() {
      return { pullThroughAvailable: true };
    },
  };
  const account = Object.freeze({ activationId: "activation-a", accountEpoch: 1 });
  let current = true;
  const access = {
    connectionManager,
    captureAccount: () => (current ? account : null),
    isAccountCurrent: () => current,
    ...overrides,
  };
  return {
    access,
    stale() { current = false; },
  };
}

function workspaceCollectionHarness(overrides = {}) {
  const harness = accountAccessHarness();
  Object.assign(harness.access, {
    context: {},
    workspaceContextProjector: {
      begin: () => ({}),
      project: async () => {},
    },
    createCloudsmithAPI: () => ({}),
    fetchWorkspaces: async () => ({
      items: [{ slug: "workspace-a", name: "Workspace A" }],
      complete: true,
    }),
    normalizedWorkspaceName: workspace => workspace.name,
    replaceCollectionItems: (result, items) => ({ ...result, items }),
    setHasMultipleWorkspacesContext: async () => {},
    fetchWorkspaceRepositories: async () => ({
      items: [{ slug: "repo-a", name: "Repo A" }],
      complete: true,
      stale: false,
    }),
    formatApiError: error => error.message,
    vscode: {
      window: { showErrorMessage() {}, showWarningMessage() {} },
      QuickPickItemKind: { Separator: 1 },
    },
    ...overrides,
  });
  return harness;
}

suite("Command registrars", () => {
  test("register and directly dispose every owned production and compatibility callback", () => {
    const expected = new Set([
      ...manifest.contributes.commands.map(entry => entry.command),
      ...INTERNAL_COMMANDS,
    ]);
    const observed = new Map();
    const ownedRegistrars = [];
    const registrars = [
      ["authentication", registerAuthenticationCommands],
      ["settingsHelp", registerSettingsHelpCommands],
      ["packages", registerPackageCommands],
      ["search", registerSearchCommands],
      ["dependencyHealth", registerDependencyHealthCommands],
      ["vulnerabilities", registerVulnerabilityCommands],
      ["promotion", registerPromotionCommands],
      ["upstream", registerUpstreamCommands],
    ];

    for (const [owner, registrar] of registrars) {
      const recorder = recordingRegistration();
      const disposable = registrar(baseDependencies(recorder));
      ownedRegistrars.push({ disposable, owner, recorder });
      for (const [id, handler] of recorder.handlers) {
        assert.strictEqual(typeof handler, "function");
        assert.strictEqual(observed.has(id), false, `Duplicate command registration: ${id}`);
        observed.set(id, owner);
      }
    }

    assert.deepStrictEqual([...observed.keys()].sort(), [...expected].sort());
    assert.strictEqual(observed.size, 64);
    for (const { disposable } of [...ownedRegistrars].reverse()) disposable.dispose();
    for (const { owner, recorder } of ownedRegistrars) {
      assert.strictEqual(recorder.handlers.size, 0, `${owner} callbacks remained reachable`);
    }
  });

  test("registration rolls back partially acquired commands", () => {
    const order = [];
    assert.throws(() => registerCommands((id) => {
      if (id === "third") throw new Error("registration failed");
      return { dispose() { order.push(id); } };
    }, [
      ["first", () => {}],
      ["second", () => {}],
      ["third", () => {}],
    ]), /registration failed/);
    assert.deepStrictEqual(order, ["second", "first"]);
  });

  test("aggregate disposal is reverse-order, best-effort, and idempotent", () => {
    const order = [];
    const failures = [];
    const disposable = registerCommands((id) => ({
      dispose() {
        order.push(id);
        if (id === "second") throw new Error("dispose failed");
      },
    }), [
      ["first", () => {}],
      ["second", () => {}],
      ["third", () => {}],
    ], { reportDisposalFailure: error => failures.push(error.message) });
    disposable.dispose();
    disposable.dispose();
    assert.deepStrictEqual(order, ["third", "second", "first"]);
    assert.deepStrictEqual(failures, ["dispose failed"]);
  });

  test("settings and package registrar disposal makes every callback unreachable", () => {
    const settingsRecorder = recordingRegistration();
    const settings = registerSettingsHelpCommands(baseDependencies(settingsRecorder));
    assert.strictEqual(settingsRecorder.handlers.size, 3);
    settings.dispose();
    settings.dispose();
    assert.strictEqual(settingsRecorder.handlers.size, 0);
    assert.deepStrictEqual(settingsRecorder.disposed, [
      "cloudsmith-vscode-extension.cloudsmithDocs",
      "cloudsmith-vsc.openSettings",
      "cloudsmith-vsc.setDefaultWorkspace",
    ]);

    const packageRecorder = recordingRegistration();
    const packages = registerPackageCommands(baseDependencies(packageRecorder));
    assert.strictEqual(packageRecorder.handlers.size, 14);
    packages.dispose();
    packages.dispose();
    assert.strictEqual(packageRecorder.handlers.size, 0);
    assert.strictEqual(packageRecorder.disposed.length, 14);
    assert.strictEqual(packageRecorder.disposed[0], "cloudsmith-vsc.copyEntitlementToken");
    assert.strictEqual(packageRecorder.disposed[13], "cloudsmith-vsc.refreshView");
  });

  test("compatibility aliases preserve primary behavior while dependency aliases stay scoped", () => {
    const dependencyRecorder = recordingRegistration();
    registerDependencyHealthCommands(baseDependencies(dependencyRecorder));
    const dependencyHandlers = dependencyRecorder.handlers;
    for (const id of [
      "cloudsmith-vsc.scanDependenciesPending",
      "cloudsmith-vsc.scanDependenciesComplete",
      "cloudsmith-vsc.rescanDependencies",
    ]) {
      assert.strictEqual(
        dependencyHandlers.get(id),
        dependencyHandlers.get("cloudsmith-vsc.scanDependencies")
      );
    }
    for (const id of [
      "cloudsmith-vsc.cycleDepViewDirect",
      "cloudsmith-vsc.cycleDepViewFlat",
      "cloudsmith-vsc.cycleDepViewTree",
    ]) {
      assert.strictEqual(
        dependencyHandlers.get(id),
        dependencyHandlers.get("cloudsmith-vsc.cycleDepView")
      );
    }
    assert.strictEqual(
      dependencyHandlers.get("cloudsmith-vsc.depSortFilterActive"),
      dependencyHandlers.get("cloudsmith-vsc.depSortFilter")
    );

    const vulnerabilityRecorder = recordingRegistration();
    registerVulnerabilityCommands(baseDependencies(vulnerabilityRecorder));
    assert.notStrictEqual(
      vulnerabilityRecorder.handlers.get("cloudsmith-vsc.showDepVulnerabilities"),
      vulnerabilityRecorder.handlers.get("cloudsmith-vsc.showVulnerabilities")
    );
    assert.notStrictEqual(
      vulnerabilityRecorder.handlers.get("cloudsmith-vsc.findDepSafeVersion"),
      vulnerabilityRecorder.handlers.get("cloudsmith-vsc.findSafeVersion")
    );
    assert.strictEqual(
      typeof vulnerabilityRecorder.handlers.get("cloudsmith-vsc.showDepVulnerabilities"),
      "function"
    );
    assert.strictEqual(
      typeof vulnerabilityRecorder.handlers.get("cloudsmith-vsc.findDepSafeVersion"),
      "function"
    );

    const packageRecorder = recordingRegistration();
    registerPackageCommands(baseDependencies(packageRecorder));
    assert.strictEqual(
      packageRecorder.handlers.get("cloudsmith-vsc.changeFilter"),
      packageRecorder.handlers.get("cloudsmith-vsc.filterPackages")
    );
  });

  test("authentication registration does not initialize account authority", () => {
    const recorder = recordingRegistration();
    let initializeCalls = 0;
    registerAuthenticationCommands({
      ...baseDependencies(recorder),
      connectionManager: { initialize() { initializeCalls += 1; } },
    });
    assert.strictEqual(initializeCalls, 0);
  });

  test("authentication callbacks forward service results and stop stale operations", async () => {
    const recorder = recordingRegistration();
    const handled = [];
    let prompts = 0;
    let loginCalls = 0;
    const serviceResult = { ok: false, error: { message: "service unavailable" } };
    const successResult = { ok: true };
    registerAuthenticationCommands({
      ...baseDependencies(recorder),
      vscode: {
        window: {
          async showInputBox() { prompts += 1; return "workspace"; },
        },
      },
      connectionManager: {
        isOperationCurrent: operation => operation !== "stale",
        async initialize() { return successResult; },
      },
      credentialManager: {
        async clearCredentials() { return serviceResult; },
      },
      ssoManager: {
        async loginViaTerminal() { loginCalls += 1; },
      },
      async handleAuthenticationResult(result, options) {
        handled.push({ result, options });
      },
    });

    await recorder.handlers.get("cloudsmith-vsc.clearCredentials")();
    await recorder.handlers.get("cloudsmith-vsc.connectCloudsmith")();
    await recorder.handlers.get("cloudsmith-vsc.ssoLogin")("stale");
    assert.deepStrictEqual(handled, [
      {
        result: serviceResult,
        options: { offerDefault: false },
      },
      { result: successResult, options: undefined },
    ]);
    assert.strictEqual(prompts, 0);
    assert.strictEqual(loginCalls, 0);
  });

  test("QH-052 registered CLI-import callback owns the operation and propagates its result", async () => {
    const recorder = recordingRegistration();
    const operation = Object.freeze({ id: "cli-import" });
    const importResult = Object.freeze({ ok: true, source: "cloudsmith-cli" });
    const importedOperations = [];
    const handledResults = [];
    let beginCalls = 0;
    registerAuthenticationCommands({
      ...baseDependencies(recorder),
      connectionManager: {
        beginCredentialOperation() {
          beginCalls += 1;
          return operation;
        },
        isOperationCurrent: value => value === operation,
      },
      credentialManager: {},
      ssoManager: {
        async importFromCLI(value) {
          importedOperations.push(value);
          return importResult;
        },
      },
      async handleAuthenticationResult(result) {
        handledResults.push(result);
      },
    });

    const callback = recorder.handlers.get("cloudsmith-vsc.importCLICredentials");
    assert.strictEqual(typeof callback, "function");
    await callback();

    assert.strictEqual(beginCalls, 1);
    assert.deepStrictEqual(importedOperations, [operation]);
    assert.deepStrictEqual(handledResults, [importResult]);
  });

  test("SSO prompt rechecks operation ownership before starting login services", async () => {
    const recorder = recordingRegistration();
    const operation = Object.freeze({ id: 1 });
    let current = true;
    let terminalLogins = 0;
    let browserLogins = 0;
    registerAuthenticationCommands({
      ...baseDependencies(recorder),
      vscode: {
        workspace: { getConfiguration: () => ({ get: () => false }) },
        window: {
          async showInputBox() {
            current = false;
            return "workspace-a";
          },
        },
      },
      connectionManager: {
        isOperationCurrent: () => current,
        async cancelCredentialOperation() {},
      },
      ssoManager: {
        async loginViaTerminal() { terminalLogins += 1; },
        async loginViaBrowser() { browserLogins += 1; },
      },
      handleAuthenticationResult() {},
    });

    await recorder.handlers.get("cloudsmith-vsc.ssoLogin")(operation);
    assert.strictEqual(terminalLogins, 0);
    assert.strictEqual(browserLogins, 0);
  });

  test("SSO ignores absent and legacy experimental setting values", async () => {
    for (const legacyValue of [undefined, false, true]) {
      const recorder = recordingRegistration();
      const operation = Object.freeze({ id: `sso-${String(legacyValue)}` });
      const serviceResult = Object.freeze({ ok: true });
      const browserLogins = [];
      const handled = [];
      let configurationReads = 0;
      let warnings = 0;
      registerAuthenticationCommands({
        ...baseDependencies(recorder),
        vscode: {
          workspace: {
            getConfiguration() {
              configurationReads += 1;
              return { get: () => legacyValue };
            },
          },
          window: {
            async showInputBox() { return " workspace-a "; },
            async showWarningMessage() { warnings += 1; },
          },
        },
        connectionManager: {
          isOperationCurrent: value => value === operation,
          async cancelCredentialOperation() {},
        },
        ssoManager: {
          isValidWorkspaceSlug: value => value === "workspace-a",
          async loginViaBrowser(workspace, value) {
            browserLogins.push({ workspace, operation: value });
            return serviceResult;
          },
        },
        async handleAuthenticationResult(result) { handled.push(result); },
      });

      await recorder.handlers.get("cloudsmith-vsc.ssoLogin")(operation);
      assert.deepStrictEqual(browserLogins, [{ workspace: "workspace-a", operation }]);
      assert.deepStrictEqual(handled, [serviceResult]);
      assert.strictEqual(configurationReads, 0);
      assert.strictEqual(warnings, 0);
    }
  });

  test("authentication picker presents supported SSO and routes it to the browser flow", async () => {
    const recorder = recordingRegistration();
    const operation = Object.freeze({ id: "picker-sso" });
    const serviceResult = Object.freeze({ ok: true });
    let pickerItems = null;
    const browserLogins = [];
    const handled = [];
    registerAuthenticationCommands({
      ...baseDependencies(recorder),
      vscode: {
        window: {
          async showQuickPick(items) {
            pickerItems = items;
            return items.find(item => item.method === "sso-browser");
          },
          async showInputBox() { return "workspace-a"; },
        },
      },
      connectionManager: {
        beginCredentialOperation: () => operation,
        isOperationCurrent: value => value === operation,
        async cancelCredentialOperation() {},
      },
      credentialManager: {},
      ssoManager: {
        isValidWorkspaceSlug: value => value === "workspace-a",
        async loginViaBrowser(workspace, value) {
          browserLogins.push({ workspace, operation: value });
          return serviceResult;
        },
      },
      async handleAuthenticationResult(result) { handled.push(result); },
    });

    await recorder.handlers.get("cloudsmith-vsc.configureCredentials")();
    const ssoItem = pickerItems.find(item => item.method === "sso-browser");
    assert.deepStrictEqual(ssoItem, {
      id: "sso-browser",
      label: "$(globe) Sign in with SSO",
      description: "Sign in through your organization's identity provider",
      method: "sso-browser",
    });
    assert.deepStrictEqual(browserLogins, [{ workspace: "workspace-a", operation }]);
    assert.deepStrictEqual(handled, [serviceResult]);
  });

  test("authentication picker keeps API-key methods first and preserves input context", async () => {
    const expected = [
      ["personal-api-key", "$(key) Enter API key", "Enter a Cloudsmith personal API key"],
      ["service-account-api-key", "$(server) Enter service account API key", "Enter a Cloudsmith service account API key"],
    ];

    for (const [selectedId, expectedLabel, expectedPrompt] of expected) {
      const recorder = recordingRegistration();
      const operation = Object.freeze({ id: selectedId });
      let pickerItems;
      let inputOptions;
      registerAuthenticationCommands({
        ...baseDependencies(recorder),
        vscode: {
          window: {
            async showQuickPick(items) {
              pickerItems = items;
              return items.find(item => item.id === selectedId);
            },
            async showInputBox(options) {
              inputOptions = options;
              return undefined;
            },
          },
        },
        connectionManager: {
          beginCredentialOperation: () => operation,
          isOperationCurrent: value => value === operation,
        },
        credentialManager: {
          async storeApiKey(_operation, options) {
            await options.showInputBox({
              prompt: "Enter a Cloudsmith API key",
              password: true,
              ignoreFocusOut: true,
            });
            return { ok: false, status: "cancelled" };
          },
        },
        ssoManager: {},
        async handleAuthenticationResult() {},
      });

      await recorder.handlers.get("cloudsmith-vsc.configureCredentials")();

      assert.deepStrictEqual(
        pickerItems.map(item => [item.id, item.label]),
        [
          ["personal-api-key", "$(key) Enter API key"],
          ["service-account-api-key", "$(server) Enter service account API key"],
          ["cloudsmith-cli", "$(folder-opened) Import API key from Cloudsmith CLI"],
          ["sso-browser", "$(globe) Sign in with SSO"],
        ]
      );
      assert.strictEqual(
        pickerItems.find(item => item.id === selectedId).label,
        expectedLabel
      );
      assert.strictEqual(inputOptions.prompt, expectedPrompt);
      assert.strictEqual(inputOptions.password, true);
    }
  });

  test("authentication method cancellation closes its credential operation", async () => {
    const recorder = recordingRegistration();
    const operation = Object.freeze({ id: 1 });
    const cancelled = [];
    let stored = 0;
    registerAuthenticationCommands({
      ...baseDependencies(recorder),
      vscode: { window: { showQuickPick: async () => null } },
      connectionManager: {
        beginCredentialOperation: () => operation,
        isOperationCurrent: () => true,
        async cancelCredentialOperation(value) { cancelled.push(value); },
      },
      credentialManager: { async storeApiKey() { stored += 1; } },
      handleAuthenticationResult() {},
    });

    await recorder.handlers.get("cloudsmith-vsc.configureCredentials")();
    assert.deepStrictEqual(cancelled, [operation]);
    assert.strictEqual(stored, 0);
  });

  test("API-key input is cancelled when its credential operation is superseded", async () => {
    const recorder = recordingRegistration();
    const operation = Object.freeze({ id: 1 });
    const input = deferred();
    const sources = [];
    let current = true;
    let changeListener = null;
    let promptToken = null;
    let scopedValue = "unset";
    class CancellationTokenSource {
      constructor() {
        this.token = { isCancellationRequested: false };
        sources.push(this);
      }
      cancel() { this.token.isCancellationRequested = true; }
      dispose() {}
    }
    registerAuthenticationCommands({
      ...baseDependencies(recorder),
      vscode: {
        CancellationTokenSource,
        window: {
          async showQuickPick() { return { method: "apikey" }; },
          async showInputBox(_options, token) {
            promptToken = token;
            return input.promise;
          },
        },
      },
      connectionManager: {
        beginCredentialOperation: () => operation,
        isOperationCurrent: () => current,
        onDidChange(listener) {
          changeListener = listener;
          return { dispose() {} };
        },
      },
      credentialManager: {
        async storeApiKey(_operation, options) {
          scopedValue = await options.showInputBox({ password: true });
          return { ok: false, status: "stale" };
        },
      },
      handleAuthenticationResult() {},
    });

    const pending = recorder.handlers.get("cloudsmith-vsc.configureCredentials")();
    await new Promise(resolve => setImmediate(resolve));
    assert.strictEqual(typeof changeListener, "function");
    assert.strictEqual(promptToken.isCancellationRequested, false);
    current = false;
    changeListener();
    assert.strictEqual(promptToken.isCancellationRequested, true);
    input.resolve("secret-that-must-not-be-used");
    await pending;
    assert.strictEqual(scopedValue, null);
    assert.strictEqual(sources.length, 2);
  });

  test("settings/help callbacks invoke only their injected platform services", async () => {
    const recorder = recordingRegistration();
    const commands = [];
    const opened = [];
    registerSettingsHelpCommands({
      ...baseDependencies(recorder),
      vscode: {
        commands: {
          async executeCommand(...args) { commands.push(args); },
        },
        env: {
          async openExternal(value) { opened.push(value); return true; },
        },
        Uri: { parse: value => value },
        window: { async showWarningMessage() {} },
      },
    });

    await recorder.handlers.get("cloudsmith-vsc.openSettings")();
    const openDocumentation = recorder.handlers.get("cloudsmith-vscode-extension.cloudsmithDocs");
    for (const link of HELP_LINKS) await openDocumentation(link.id);
    assert.deepStrictEqual(commands, [[
      "workbench.action.openSettings",
      "@ext:Cloudsmith.cloudsmith-vsc",
    ]]);
    assert.deepStrictEqual(opened, HELP_LINKS.map(link => link.url));
  });

  test("Help navigation reports refused and rejected external opens", async () => {
    const recorder = recordingRegistration();
    const warnings = [];
    const outcomes = [false, new Error("platform rejected"), true];
    registerSettingsHelpCommands({
      ...baseDependencies(recorder),
      vscode: {
        env: {
          async openExternal() {
            const outcome = outcomes.shift();
            if (outcome instanceof Error) throw outcome;
            return outcome;
          },
        },
        Uri: { parse: value => value },
        window: {
          async showWarningMessage(message) { warnings.push(message); },
        },
      },
    });

    const openDocumentation = recorder.handlers.get("cloudsmith-vscode-extension.cloudsmithDocs");
    assert.strictEqual(await openDocumentation(), false);
    assert.strictEqual(await openDocumentation(), false);
    assert.strictEqual(await openDocumentation(), true);
    assert.deepStrictEqual(warnings, [
      "Could not open the extension documentation.",
      "Could not open the extension documentation.",
    ]);
  });

  test("Help tree items route authoritative link IDs through the truthful navigation command", () => {
    const provider = new helpProvider({});
    const children = provider.getChildren();
    assert.deepStrictEqual(children.map(child => ({
      id: child.command.arguments[0],
      command: child.command.command,
      url: child.tooltip,
    })), HELP_LINKS.map(link => ({
      id: link.id,
      command: "cloudsmith-vscode-extension.cloudsmithDocs",
      url: link.url,
    })));
  });

  test("settings workspace selection updates configuration and presentation", async () => {
    const recorder = recordingRegistration();
    const harness = workspaceCollectionHarness();
    const updates = [];
    const quickPicks = [];
    let contextUpdates = 0;
    let refreshes = 0;
    const treeView = { title: "Workspaces", description: "" };
    registerSettingsHelpCommands({
      ...baseDependencies(recorder),
      vscode: {
        ConfigurationTarget: { Global: 1 },
        QuickPickItemKind: { Separator: 1 },
        workspace: {
          getConfiguration: () => ({
            async update(...args) { updates.push(args); },
          }),
        },
        window: {
          async showQuickPick(items) {
            quickPicks.push(items);
            return items.find(item => item.description === "workspace-a");
          },
          showErrorMessage() {},
        },
      },
      workspaceAccess: harness.access,
      treeView,
      cloudsmithProvider: { refresh() { refreshes += 1; } },
      async updateDefaultWorkspaceContext() { contextUpdates += 1; },
    });

    await recorder.handlers.get("cloudsmith-vsc.setDefaultWorkspace")();
    assert.deepStrictEqual(updates, [["defaultWorkspace", "workspace-a", 1]]);
    assert.strictEqual(contextUpdates, 1);
    assert.deepStrictEqual(treeView, {
      title: "Repositories",
      description: "workspace-a",
    });
    assert.strictEqual(refreshes, 1);
    assert.strictEqual(quickPicks.length, 1);
    assert.strictEqual(quickPicks[0][0].clear, true);
  });

  test("settings empty workspace state offers only the clear-default recovery action", async () => {
    const recorder = recordingRegistration();
    const harness = workspaceCollectionHarness({
      fetchWorkspaces: async () => ({ items: [], complete: true }),
    });
    const errors = [];
    const quickPicks = [];
    let updates = 0;
    registerSettingsHelpCommands({
      ...baseDependencies(recorder),
      vscode: {
        ConfigurationTarget: { Global: 1 },
        QuickPickItemKind: { Separator: 1 },
        workspace: {
          getConfiguration: () => ({ async update() { updates += 1; } }),
        },
        window: {
          async showQuickPick(items) { quickPicks.push(items); },
          showErrorMessage(message) { errors.push(message); },
        },
      },
      workspaceAccess: harness.access,
      treeView: {},
      cloudsmithProvider: { refresh() {} },
      updateDefaultWorkspaceContext() {},
    });

    await recorder.handlers.get("cloudsmith-vsc.setDefaultWorkspace")();
    assert.deepStrictEqual(errors, []);
    assert.strictEqual(quickPicks.length, 1);
    assert.deepStrictEqual(quickPicks[0].map(item => ({
      clear: item.clear === true,
      label: item.label,
    })), [{
      clear: true,
      label: "$(close) Clear default workspace",
    }]);
    assert.strictEqual(updates, 0);
  });

  test("settings selection becomes inert when its captured account turns stale", async () => {
    const recorder = recordingRegistration();
    const harness = workspaceCollectionHarness();
    let updates = 0;
    let refreshes = 0;
    let contextUpdates = 0;
    registerSettingsHelpCommands({
      ...baseDependencies(recorder),
      vscode: {
        ConfigurationTarget: { Global: 1 },
        QuickPickItemKind: { Separator: 1 },
        workspace: {
          getConfiguration: () => ({ async update() { updates += 1; } }),
        },
        window: {
          async showQuickPick() {
            harness.stale();
            return { label: "Workspace A", description: "workspace-a", clear: false };
          },
          showErrorMessage() {},
        },
      },
      workspaceAccess: harness.access,
      treeView: {},
      cloudsmithProvider: { refresh() { refreshes += 1; } },
      async updateDefaultWorkspaceContext() { contextUpdates += 1; },
    });

    await recorder.handlers.get("cloudsmith-vsc.setDefaultWorkspace")();
    assert.strictEqual(updates, 0);
    assert.strictEqual(contextUpdates, 0);
    assert.strictEqual(refreshes, 0);
  });

  test("settings cancellation and update failure leave presentation unchanged", async () => {
    const cancelledRecorder = recordingRegistration();
    const cancelledHarness = workspaceCollectionHarness();
    let cancelledUpdates = 0;
    registerSettingsHelpCommands({
      ...baseDependencies(cancelledRecorder),
      vscode: {
        ConfigurationTarget: { Global: 1 },
        QuickPickItemKind: { Separator: 1 },
        workspace: {
          getConfiguration: () => ({ async update() { cancelledUpdates += 1; } }),
        },
        window: { showQuickPick: async () => null, showErrorMessage() {} },
      },
      workspaceAccess: cancelledHarness.access,
      treeView: {},
      cloudsmithProvider: { refresh() {} },
      updateDefaultWorkspaceContext() {},
    });
    await cancelledRecorder.handlers.get("cloudsmith-vsc.setDefaultWorkspace")();
    assert.strictEqual(cancelledUpdates, 0);

    const failedRecorder = recordingRegistration();
    const failedHarness = workspaceCollectionHarness();
    const treeView = { title: "Workspaces", description: "" };
    let refreshes = 0;
    registerSettingsHelpCommands({
      ...baseDependencies(failedRecorder),
      vscode: {
        ConfigurationTarget: { Global: 1 },
        QuickPickItemKind: { Separator: 1 },
        workspace: {
          getConfiguration: () => ({
            async update() { throw new Error("settings unavailable"); },
          }),
        },
        window: {
          showQuickPick: async items => items.find(item => item.workspace),
          showErrorMessage() {},
        },
      },
      workspaceAccess: failedHarness.access,
      treeView,
      cloudsmithProvider: { refresh() { refreshes += 1; } },
      updateDefaultWorkspaceContext() {},
    });
    await assert.rejects(
      failedRecorder.handlers.get("cloudsmith-vsc.setDefaultWorkspace")(),
      /settings unavailable/
    );
    assert.deepStrictEqual(treeView, { title: "Workspaces", description: "" });
    assert.strictEqual(refreshes, 0);
  });

  test("programmatic detail copy requires a current provider-owned selection", async () => {
    const recorder = recordingRegistration();
    const warnings = [];
    const copied = [];
    const current = Object.freeze({ value: "1.2.3" });
    const forged = Object.freeze({ value: "forged-secret" });
    registerPackageCommands({
      ...baseDependencies(recorder),
      isCurrentSelection: item => item === current,
      vscode: {
        env: {
          clipboard: { async writeText(value) { copied.push(value); } },
        },
        window: {
          showInformationMessage() {},
          showWarningMessage(message) { warnings.push(message); },
        },
      },
      packageAdapters: {
        fromPackageDetailNode(item) {
          return Object.freeze({ id: "Version", value: item.value });
        },
      },
    });

    const handler = recorder.handlers.get("cloudsmith-vsc.copySelected");
    await handler(null);
    await handler(forged);
    await handler(current);
    assert.deepStrictEqual(copied, ["1.2.3"]);
    assert.deepStrictEqual(warnings, []);
  });

  test("custom search and repository-filter InputBoxes reject whitespace-only queries", async () => {
    const searchRecorder = recordingRegistration();
    let searchValidator = null;
    registerSearchCommands({
      ...baseDependencies(searchRecorder),
      context: {},
      workspaceAccess: workspaceCollectionHarness().access,
      vscode: {
        QuickPickItemKind: { Separator: 1 },
        workspace: { getConfiguration: () => ({ get: () => "" }) },
        window: {
          async showInputBox(options) {
            searchValidator = options.validateInput;
            return null;
          },
          showWarningMessage() {},
        },
      },
      RecentSearches: class {},
      SearchQueryBuilder: class {},
      FORMAT_OPTIONS: [],
      searchProvider: {},
    });
    await searchRecorder.handlers.get("cloudsmith-vsc.searchInWorkspace")({
      slug: "workspace-a",
      name: "Workspace A",
    });
    assert.strictEqual(typeof searchValidator, "function");
    assert.strictEqual(searchValidator(""), "Enter a search query.");
    assert.strictEqual(searchValidator("   "), "Enter a search query.");
    assert.strictEqual(searchValidator(" name:flask "), null);
    assert.strictEqual(
      searchValidator("name:flask\u0000"),
      "Search queries cannot contain control characters."
    );
    assert.strictEqual(
      searchValidator("name:flask\nOR name:other"),
      "Search queries cannot contain control characters."
    );
    assert.strictEqual(
      searchValidator("name:flask\u202e"),
      "Search queries cannot contain control characters."
    );
    assert.strictEqual(searchValidator("a".repeat(2048)), null);
    assert.strictEqual(
      searchValidator("a".repeat(2049)),
      "Search queries must be 2048 characters or fewer."
    );

    const filterRecorder = recordingRegistration();
    let filterValidator = null;
    registerPackageCommands({
      ...baseDependencies(filterRecorder),
      packageAdapters: {
        fromRepositoryNode: () => ({
          workspace: "workspace-a",
          repository: "repo-a",
          name: "Repo A",
        }),
      },
      vscode: {
        window: {
          async showQuickPick(items) {
            return items.find(item => item.preset?.applyBuilder === null);
          },
          async showInputBox(options) {
            filterValidator = options.validateInput;
            return null;
          },
        },
      },
      cloudsmithProvider: { refresh() { throw new Error("must not refresh"); } },
    });
    await filterRecorder.handlers.get("cloudsmith-vsc.filterPackages")({});
    assert.strictEqual(typeof filterValidator, "function");
    assert.strictEqual(filterValidator(""), "Enter a filter query.");
    assert.strictEqual(filterValidator("   "), "Enter a filter query.");
    assert.strictEqual(filterValidator(" format:python "), null);
    assert.strictEqual(
      filterValidator("format:python\u0000"),
      "Filter queries cannot contain control characters."
    );
    assert.strictEqual(
      filterValidator("format:python\nOR format:npm"),
      "Filter queries cannot contain control characters."
    );
    assert.strictEqual(
      filterValidator("format:python\u202e"),
      "Filter queries cannot contain control characters."
    );
    assert.strictEqual(filterValidator("a".repeat(2048)), null);
    assert.strictEqual(
      filterValidator("a".repeat(2049)),
      "Enter a query with 2048 characters or fewer."
    );
  });

  test("package entitlement cancellation neither copies nor echoes the sensitive token", async () => {
    const recorder = recordingRegistration();
    let writes = 0;
    const prompts = [];
    registerPackageCommands({
      ...baseDependencies(recorder),
      vscode: {
        env: { clipboard: { async writeText() { writes += 1; } } },
        window: {
          async showWarningMessage(...args) {
            prompts.push(args);
            return "Cancel";
          },
        },
      },
    });

    await recorder.handlers.get("cloudsmith-vsc.copyEntitlementToken")({
      token: "secret-token",
      tokenName: "read-only",
    });
    assert.strictEqual(writes, 0);
    assert.strictEqual(prompts.length, 1);
    assert.deepStrictEqual(prompts[0].slice(1), [{ modal: true }, "Copy"]);
    assert.strictEqual(JSON.stringify(prompts).includes("secret-token"), false);
  });

  test("install commands reject non-exact and ambiguous package selections", async () => {
    const recorder = recordingRegistration();
    const builds = [];
    const copied = [];
    const recent = [];
    const warnings = [];
    class InstallCommandBuilder {
      static build(format, name, version, workspace, repository) {
        builds.push({ format, name, version, workspace, repository });
        return { command: `install ${name}@${version}` };
      }

      static toClipboardCommand(command) { return command; }
    }
    registerPackageCommands({
      ...baseDependencies(recorder),
      vscode: {
        workspace: { getConfiguration: () => ({ get: () => false }) },
        env: { clipboard: { async writeText(value) { copied.push(value); } } },
        window: {
          showInformationMessage() {},
          showWarningMessage(message) { warnings.push(message); },
        },
      },
      packageAdapters,
      packageDomain,
      recentPackages: { add: value => recent.push(value), getAll: () => [] },
      InstallCommandBuilder,
      InstallCommandValidationError: class extends Error {},
    });

    await recorder.handlers.get("cloudsmith-vsc.copyInstallCommand")({
      namespace: "workspace-a",
      repository: "repo-a",
      name: "widget",
      format: "npm",
      copyable: true,
    });
    await recorder.handlers.get("cloudsmith-vsc.copyInstallCommand")({
      cloudsmithWorkspace: "workspace-b",
      cloudsmithRepo: "repo-b",
      name: "other-widget",
      format: "python",
      copyable: true,
    });
    await recorder.handlers.get("cloudsmith-vsc.copyInstallCommand")({
      namespace: "workspace-a",
      repository: "repo-a",
      name: "widget",
      version: "",
      format: "npm",
      slug_perm: "package-one",
    });
    await recorder.handlers.get("cloudsmith-vsc.copyInstallCommand")({
      namespace: "workspace-a",
      repository: "repo-a",
      name: "widget",
      version: "1.0.0",
      format: "npm",
      slug_perm: "package-one",
      slug_perm_raw: "package-two",
    });
    await recorder.handlers.get("cloudsmith-vsc.copyInstallCommand")({
      namespace: "workspace-a",
      repository: "repo-a",
      name: "widget",
      format: "npm",
      slug_perm: "",
    });
    assert.deepStrictEqual(builds, []);
    assert.deepStrictEqual(copied, []);
    assert.deepStrictEqual(recent, []);
    assert.deepStrictEqual(warnings, [
      "Could not determine package details for install command.",
      "Could not determine package details for install command.",
      "Could not determine package details for install command.",
      "Could not determine package details for install command.",
      "Could not determine package details for install command.",
    ]);
  });

  test("registered install command publishes usable guidance through real host dispatch", async () => {
    const commandIds = new Map();
    const clipboardWrites = [];
    const informationMessages = [];
    const registration = registerPackageCommands({
      ...baseDependencies({
        registerCommand(id, handler) {
          const testId = `cloudsmith-vsc.test.install-host.${id}`;
          commandIds.set(id, testId);
          return vscode.commands.registerCommand(testId, handler);
        },
      }),
      vscode: {
        env: {
          clipboard: {
            async writeText(value) { clipboardWrites.push(value); },
          },
        },
        workspace: { getConfiguration: () => ({ get: () => false }) },
        window: {
          showErrorMessage() {},
          showWarningMessage() {},
          showInformationMessage(message) { informationMessages.push(message); },
          async showQuickPick(items) { return items[0]; },
        },
      },
      packageAdapters,
      packageDomain,
      recentPackages: { add() {}, getAll: () => [] },
      InstallCommandBuilder,
      InstallCommandValidationError,
    });
    const pkg = packageDomain.createExactPackage({
      workspace: "workspace-a",
      repository: "repo-a",
      packageIdentifier: "python-package-one",
      name: "sample-package",
      version: "1.2.3",
      format: "python",
      status: "Completed",
      copyable: true,
    });

    try {
      await vscode.commands.executeCommand(
        commandIds.get("cloudsmith-vsc.copyInstallCommand"),
        pkg
      );

      assert.strictEqual(clipboardWrites.length, 1);
      assert.match(clipboardWrites[0], /(?:^|\n)pip install 'sample-package==1\.2\.3' --index-url https:\/\/dl\.cloudsmith\.io\/basic\/workspace-a\/repo-a\/python\/simple\//u);
      assert.deepStrictEqual(informationMessages, ["Install command copied."]);
    } finally {
      registration.dispose();
    }
  });

  test("package and package-group navigation report refused and rejected opens and record only confirmed history", async () => {
    const recorder = recordingRegistration();
    const recent = [];
    const warnings = [];
    const opened = [];
    const outcomes = [false, new Error("platform rejected"), true, false, new Error("platform rejected")];
    const pkg = Object.freeze({
      workspace: "workspace-a",
      repository: "repo-a",
      packageIdentifier: "package-one",
      name: "widget",
      version: "1.0.0",
      format: "npm",
    });
    const group = Object.freeze({
      workspace: "workspace-a",
      repository: "repo-a",
      name: "widget",
    });
    registerPackageCommands({
      ...baseDependencies(recorder),
      vscode: {
        Uri: { parse: value => value },
        env: {
          async openExternal(value) {
            opened.push(value);
            const outcome = outcomes.shift();
            if (outcome instanceof Error) throw outcome;
            return outcome;
          },
        },
        window: { async showWarningMessage(message) { warnings.push(message); } },
      },
      packageAdapters: {
        fromPackageSelection: value => value,
        fromPackageGroupNode: value => value,
      },
      packageDomain: { assertExactPackage: value => value },
      recentPackages: { add: value => recent.push(value), getAll: () => [] },
      buildPackageUrl: () => "https://app.cloudsmith.com/workspace-a/repo-a/widget/1.0.0/",
      buildPackageGroupUrl: () => "https://app.cloudsmith.com/workspace-a/repo-a/widget/",
    });

    const openPackage = recorder.handlers.get("cloudsmith-vsc.openPackage");
    await openPackage(pkg);
    await openPackage(pkg);
    await openPackage(pkg);
    const openPackageGroup = recorder.handlers.get("cloudsmith-vsc.openPackageGroup");
    await openPackageGroup(group);
    await openPackageGroup(group);

    assert.strictEqual(opened.length, 5);
    assert.deepStrictEqual(recent, [pkg]);
    assert.deepStrictEqual(warnings, [
      "Could not open this package in Cloudsmith.",
      "Could not open this package in Cloudsmith.",
      "Could not open this package group in Cloudsmith.",
      "Could not open this package group in Cloudsmith.",
    ]);
  });

  test("package inspection contains a failed API result at the registrar boundary", async () => {
    const recorder = recordingRegistration();
    const errors = [];
    let apiCalls = 0;
    const pkg = Object.freeze({
      workspace: "workspace-a",
      repository: "repo-a",
      name: "widget",
      version: "1.2.3",
      format: "python",
      packageIdentifier: "pkg-1",
    });
    class FailingAPI {
      async get() {
        apiCalls += 1;
        return { ok: false, error: { message: "package service unavailable" } };
      }
    }
    registerPackageCommands({
      ...baseDependencies(recorder),
      context: {},
      vscode: { window: { showErrorMessage: message => errors.push(message) } },
      packageAdapters: { fromPackageSelection: value => value },
      packageDomain: { assertExactPackage: value => value },
      recentPackages: { add() {}, getAll: () => [] },
      CloudsmithAPI: FailingAPI,
      apiEndpoint: () => "/packages/workspace-a/repo-a/pkg-1/",
      formatApiError: error => error.message,
    });

    await recorder.handlers.get("cloudsmith-vsc.inspectPackage")(pkg);
    assert.strictEqual(apiCalls, 1);
    assert.deepStrictEqual(errors, ["Could not inspect package. package service unavailable"]);
  });

  test("package-group inspection scopes canonical identity and rejects mixed formats", async () => {
    const recorder = recordingRegistration();
    const adapterOptions = [];
    const errors = [];
    let fetchOptions;
    class SearchQueryBuilder {
      constructor() { this.terms = []; }
      name(value) { this.terms.push(`name:${value}`); return this; }
      format(value) { this.terms.push(`format:${value}`); return this; }
      build() { return this.terms.join(" AND "); }
    }
    class PaginatedFetch {
      async fetchCollection(_endpoint, options) {
        fetchOptions = options;
        return {
          complete: false,
          items: [],
          failures: [{ error: { message: "mixed format response" } }],
        };
      }
    }
    const pythonRecord = {
      workspace: "workspace-a",
      repository: "repo-a",
      name: "widget",
      format: "python",
      packageIdentifier: "python-1",
    };
    const npmRecord = { ...pythonRecord, format: "npm", packageIdentifier: "npm-1" };
    registerPackageCommands({
      ...baseDependencies(recorder),
      context: {},
      vscode: { window: { showErrorMessage: message => errors.push(message) } },
      packageAdapters: {
        fromPackageGroupNode: () => Object.freeze({
          workspace: "workspace-a",
          repository: "repo-a",
          name: "widget",
          format: "python",
        }),
        fromApiPackageRecord(record, options) {
          adapterOptions.push(options);
          if (record.invalid) throw new TypeError("invalid package");
          return record;
        },
      },
      CloudsmithAPI: class {},
      SearchQueryBuilder,
      PaginatedFetch,
      apiEndpoint: () => "/packages/workspace-a/repo-a/",
      packageCollectionIdentity: pkg => `${pkg.format}:${pkg.packageIdentifier}`,
      formatApiError: error => error.message,
    });

    await recorder.handlers.get("cloudsmith-vsc.inspectPackageGroup")({});
    assert.strictEqual(fetchOptions.query, "name:widget AND format:python");
    assert.strictEqual(
      fetchOptions.descriptor,
      "inspect-package-group:workspace-a:repo-a:widget:python"
    );
    assert.strictEqual(fetchOptions.validate([pythonRecord]), true);
    assert.strictEqual(fetchOptions.validate([pythonRecord, npmRecord]), false);
    assert.strictEqual(fetchOptions.canonicalIdentity(pythonRecord), "python:python-1");
    assert.strictEqual(fetchOptions.canonicalIdentity({ invalid: true }), null);
    assert.ok(adapterOptions.length >= 4);
    for (const options of adapterOptions) {
      assert.deepStrictEqual(options, {
        expectedWorkspace: "workspace-a",
        expectedRepository: "repo-a",
      });
    }
    assert.deepStrictEqual(errors, ["Could not inspect package group. mixed format response"]);
  });

  test("strict workspace-search command is silent without a current workspace selection", async () => {
    const recorder = recordingRegistration();
    const warnings = [];
    const information = [];
    let clearCalls = 0;
    let searchCalls = 0;
    let workspaceReads = 0;
    registerSearchCommands({
      ...baseDependencies(recorder),
      vscode: {
        workspace: {
          getConfiguration: () => ({ get: () => "" }),
        },
        window: {
          showWarningMessage(message) { warnings.push(message); },
          showInformationMessage(message) { information.push(message); },
        },
      },
      searchProvider: {
        clear() { clearCalls += 1; },
        search() { searchCalls += 1; },
      },
      workspaceAccess: workspaceCollectionHarness({
        async fetchWorkspaces() {
          workspaceReads += 1;
          return { items: [], complete: true };
        },
      }).access,
    });

    await recorder.handlers.get("cloudsmith-vsc.clearSearch")();
    await recorder.handlers.get("cloudsmith-vsc.searchInWorkspace")();
    await recorder.handlers.get("cloudsmith-vsc.filterVulnerableWorkspace")();
    assert.strictEqual(clearCalls, 1);
    assert.strictEqual(searchCalls, 0);
    assert.strictEqual(workspaceReads, 0);
    assert.deepStrictEqual(warnings, []);
    assert.deepStrictEqual(information, []);
  });

  test("workspace vulnerability shortcut rejects a stale item before recovery or search", async () => {
    const recorder = recordingRegistration();
    let workspaceReads = 0;
    let searches = 0;
    let focusCalls = 0;
    registerSearchCommands({
      ...baseDependencies(recorder),
      isCurrentWorkspaceSelection: () => false,
      vscode: {
        commands: { executeCommand() { focusCalls += 1; } },
        window: {},
      },
      workspaceAccess: workspaceCollectionHarness({
        async fetchWorkspaces() {
          workspaceReads += 1;
          return { items: [], complete: true };
        },
      }).access,
      searchProvider: { search() { searches += 1; } },
    });

    await recorder.handlers.get("cloudsmith-vsc.filterVulnerableWorkspace")({
      slug: "workspace-a",
      name: "Workspace A",
    });
    assert.strictEqual(workspaceReads, 0);
    assert.strictEqual(searches, 0);
    assert.strictEqual(focusCalls, 0);
  });

  test("search intent delegates one provider-contained service failure", async () => {
    const recorder = recordingRegistration();
    const operations = [];
    const serviceFailure = Object.freeze({ ok: false, error: "search unavailable" });
    class SearchQueryBuilder {
      advanced(value) { this.value = value; return this; }
      build() { return this.value; }
    }
    class RecentSearches {
      async add() {}
    }
    registerSearchCommands({
      ...baseDependencies(recorder),
      context: {},
      vscode: {
        window: { showInputBox: async () => "name:widget" },
      },
      SearchQueryBuilder,
      RecentSearches,
      searchProvider: {
        beginSearch(descriptor) { return { descriptor }; },
        async executeSearch(operation) {
          operations.push(operation);
          return serviceFailure;
        },
      },
      workspaceAccess: workspaceCollectionHarness().access,
    });

    await recorder.handlers.get("cloudsmith-vsc.searchInWorkspace")({ slug: "workspace-a" });
    assert.deepStrictEqual(operations.map(operation => operation.descriptor), [{
      kind: "workspace",
      workspace: "workspace-a",
      query: "name:widget",
      page: 1,
    }]);
  });

  test("search prompt cannot execute against a stale captured account", async () => {
    const recorder = recordingRegistration();
    const harness = workspaceCollectionHarness();
    let beginCalls = 0;
    registerSearchCommands({
      ...baseDependencies(recorder),
      context: {},
      vscode: {
        window: {
          async showInputBox() {
            harness.stale();
            return "name:widget";
          },
        },
      },
      workspaceAccess: harness.access,
      SearchQueryBuilder: class {
        advanced() { return this; }
        raw() { return this; }
        build() { return "name:widget"; }
      },
      RecentSearches: class {},
      searchProvider: {
        beginSearch() { beginCalls += 1; },
      },
    });

    await recorder.handlers.get("cloudsmith-vsc.searchInWorkspace")({ slug: "workspace-a" });
    assert.strictEqual(beginCalls, 0);
  });

  test("search prompt cancellation never starts a provider operation", async () => {
    const recorder = recordingRegistration();
    let beginCalls = 0;
    registerSearchCommands({
      ...baseDependencies(recorder),
      context: {},
      vscode: { window: { showInputBox: async () => null } },
      workspaceAccess: workspaceCollectionHarness().access,
      RecentSearches: class {},
      searchProvider: { beginSearch() { beginCalls += 1; } },
    });

    await recorder.handlers.get("cloudsmith-vsc.searchInWorkspace")({ slug: "workspace-a" });
    assert.strictEqual(beginCalls, 0);
  });

  test("search packages replays a recent descriptor through the provider", async () => {
    const recorder = recordingRegistration();
    const descriptors = [];
    const recentEntry = Object.freeze({
      workspace: "workspace-a",
      query: "format:npm",
      scope: Object.freeze({ kind: "repository", repository: "repo-a" }),
    });
    class RecentSearches {
      async getAll() { return [recentEntry]; }
    }
    registerSearchCommands({
      ...baseDependencies(recorder),
      context: {},
      vscode: {
        QuickPickItemKind: { Separator: 1 },
        workspace: {
          getConfiguration: () => ({ get: () => "workspace-a" }),
        },
        window: {
          async showQuickPick(items) { return items.find(item => item.recent); },
        },
      },
      workspaceAccess: workspaceCollectionHarness().access,
      RecentSearches,
      searchProvider: {
        beginSearch(descriptor) { return { descriptor }; },
        async executeSearch(operation) { descriptors.push(operation.descriptor); },
      },
    });

    await recorder.handlers.get("cloudsmith-vsc.searchPackages")();
    assert.deepStrictEqual(descriptors, [{
      kind: "repository",
      workspace: "workspace-a",
      repository: "repo-a",
      query: "format:npm",
      page: 1,
    }]);
  });

  test("QH-051 registered license-search callback searches, records history, and focuses results", async () => {
    const recorder = recordingRegistration();
    const selectedLicense = Object.freeze({
      label: "Apache-2.0",
      query: "license:Apache-2.0",
    });
    const descriptors = [];
    const executions = [];
    const history = [];
    const focusCalls = [];
    const recentConstructions = [];
    const context = Object.freeze({ kind: "extension-context" });
    const authoritativeResult = Object.freeze({ status: "complete", count: 2 });
    const execution = deferred();
    class RecentSearches {
      constructor(value, workspace) {
        recentConstructions.push({ context: value, workspace });
      }

      async add(entry) {
        history.push(entry);
      }
    }
    registerSearchCommands({
      ...baseDependencies(recorder),
      context,
      vscode: {
        QuickPickItemKind: { Separator: 1 },
        commands: {
          async executeCommand(...args) {
            focusCalls.push(args);
          },
        },
        workspace: { getConfiguration: () => ({ get: () => "" }) },
        window: {
          async showQuickPick(items, options) {
            assert.strictEqual(options.placeHolder, "Select a license to search for");
            assert.ok(items.includes(selectedLicense));
            return selectedLicense;
          },
        },
      },
      workspaceAccess: workspaceCollectionHarness().access,
      LicenseClassifier: {
        getSearchQuickPickItems: () => [selectedLicense],
        buildRestrictiveQuery: () => "license:restrictive",
        buildLicenseQuery() { throw new Error("selected canonical query must be used"); },
      },
      RecentSearches,
      searchProvider: {
        beginSearch(descriptor) {
          descriptors.push(descriptor);
          return Object.freeze({ descriptor });
        },
        executeSearch(operation) {
          executions.push(operation);
          return execution.promise;
        },
      },
    });

    const callback = recorder.handlers.get("cloudsmith-vsc.searchByLicense");
    assert.strictEqual(typeof callback, "function");
    const pendingSearch = callback();
    await new Promise(resolve => setImmediate(resolve));

    const expectedDescriptor = {
      kind: "workspace",
      workspace: "workspace-a",
      query: "license:Apache-2.0",
      page: 1,
    };
    assert.deepStrictEqual(descriptors, [expectedDescriptor]);
    assert.strictEqual(executions.length, 1);
    assert.deepStrictEqual(executions[0].descriptor, expectedDescriptor);
    assert.deepStrictEqual(recentConstructions, [{ context, workspace: "workspace-a" }]);
    assert.deepStrictEqual(history, [{
      workspace: "workspace-a",
      query: "license:Apache-2.0",
      scope: { kind: "workspace" },
    }]);
    assert.deepStrictEqual(focusCalls, []);

    execution.resolve(authoritativeResult);
    assert.strictEqual(await pendingSearch, undefined);
    assert.deepStrictEqual(focusCalls, [["cloudsmithSearchView.focus"]]);
  });

  test("guided search cancellation stops before repository or provider work", async () => {
    const recorder = recordingRegistration();
    let repositoryReads = 0;
    let beginCalls = 0;
    class RecentSearches {
      async getAll() { return []; }
    }
    registerSearchCommands({
      ...baseDependencies(recorder),
      context: {},
      vscode: {
        workspace: {
          getConfiguration: () => ({ get: () => "workspace-a" }),
        },
        window: { showQuickPick: async () => null },
      },
      workspaceAccess: workspaceCollectionHarness({
        async fetchWorkspaceRepositories() {
          repositoryReads += 1;
          return { items: [], complete: true };
        },
      }).access,
      RecentSearches,
      searchProvider: { beginSearch() { beginCalls += 1; } },
    });

    await recorder.handlers.get("cloudsmith-vsc.guidedSearch")();
    assert.strictEqual(repositoryReads, 0);
    assert.strictEqual(beginCalls, 0);
  });

  test("guided search shows only safe verified repository identities", async () => {
    const recorder = recordingRegistration();
    let repositoryItems = null;
    class RecentSearches {
      async getAll() { return []; }
    }
    registerSearchCommands({
      ...baseDependencies(recorder),
      context: {},
      vscode: {
        QuickPickItemKind: { Separator: 1 },
        workspace: {
          getConfiguration: () => ({ get: () => "workspace-a" }),
        },
        window: {
          async showQuickPick(items, options) {
            if (options.placeHolder === "Step 2: Select a search scope") {
              return items.find(item => item.scope === "repositories");
            }
            if (options.placeHolder === "Select repositories to search") {
              repositoryItems = items;
              return null;
            }
            throw new Error(`Unexpected picker: ${options.placeHolder}`);
          },
          showInformationMessage() {},
        },
      },
      workspaceAccess: workspaceCollectionHarness({
        async fetchWorkspaceRepositories() {
          return {
            items: [
              { slug: "repo-hostile\u202e", name: "Hostile" },
              { slug: "repo-safe", name: "Visible\u2066\nRepo" },
            ],
            complete: true,
            stale: false,
          };
        },
      }).access,
      RecentSearches,
      searchProvider: { beginSearch() { throw new Error("must not search"); } },
    });

    await recorder.handlers.get("cloudsmith-vsc.guidedSearch")();
    assert.ok(repositoryItems);
    assert.strictEqual(repositoryItems[0].kind, 1);
    assert.ok(repositoryItems.some(item => item.label === "Visible Repo"));
    assert.strictEqual(JSON.stringify(repositoryItems).includes("repo-hostile"), false);
    assert.strictEqual(JSON.stringify(repositoryItems).includes("\u202e"), false);
    assert.strictEqual(JSON.stringify(repositoryItems).includes("\u2066"), false);
  });

  test("guided search rejects an oversized combined custom and format query gracefully", async () => {
    const recorder = recordingRegistration();
    const warnings = [];
    let beginCalls = 0;
    class RecentSearches {
      async getAll() { return []; }
    }
    class SearchQueryBuilder {
      advanced(value) { this.value = value; return this; }
      format(value) { this.value = `format:${value}`; return this; }
      build() { return this.value || ""; }
    }
    registerSearchCommands({
      ...baseDependencies(recorder),
      context: {},
      FORMAT_OPTIONS: ["npm"],
      SearchQueryBuilder,
      RecentSearches,
      vscode: {
        workspace: { getConfiguration: () => ({ get: () => "workspace-a" }) },
        window: {
          async showInputBox() { return "x".repeat(2048); },
          async showQuickPick(items, options) {
            if (options.placeHolder === "Step 2: Select a search scope") {
              return items.find(item => item.scope === "all");
            }
            if (options.placeHolder === "Step 3: Select a filter") {
              return items.find(item => item.preset && item.preset.applyBuilder === null);
            }
            if (options.placeHolder === "Step 4: Filter by format (optional)") {
              return [items.find(item => item.label === "npm")];
            }
            throw new Error(`Unexpected picker: ${options.placeHolder}`);
          },
          async showWarningMessage(message) { warnings.push(message); },
        },
      },
      workspaceAccess: workspaceCollectionHarness().access,
      searchProvider: { beginSearch() { beginCalls += 1; } },
    });

    await recorder.handlers.get("cloudsmith-vsc.guidedSearch")();

    assert.strictEqual(beginCalls, 0);
    assert.deepStrictEqual(warnings, [
      "The combined search query exceeds the safe query limit. Shorten the custom query or select fewer formats.",
    ]);
  });

  test("workspace search shortcuts recheck provider ownership after recovery prompts", async () => {
    const recorder = recordingRegistration();
    let current = true;
    let searchCalls = 0;
    class RecentSearches {}
    registerSearchCommands({
      ...baseDependencies(recorder),
      context: {},
      isCurrentWorkspaceSelection: () => current,
      vscode: {
        QuickPickItemKind: { Separator: 1 },
        workspace: { getConfiguration: () => ({ get: () => "" }) },
        window: {
          async showInputBox() {
            current = false;
            return "name:widget";
          },
        },
      },
      workspaceAccess: workspaceCollectionHarness().access,
      RecentSearches,
      SearchQueryBuilder: class {
        advanced() { return this; }
        raw() { return this; }
        build() { return "name:widget"; }
      },
      searchProvider: {
        beginSearch() { searchCalls += 1; return {}; },
        async executeSearch() {},
        async search() { searchCalls += 1; },
      },
    });

    const workspaceNode = { slug: "workspace-a", name: "Workspace A" };
    await recorder.handlers.get("cloudsmith-vsc.searchInWorkspace")(workspaceNode);
    assert.strictEqual(searchCalls, 0);

    current = true;
    const access = workspaceCollectionHarness({
      async fetchWorkspaces() {
        current = false;
        return {
          items: [{ slug: "workspace-a", name: "Workspace A" }],
          complete: true,
        };
      },
    });
    const filterRecorder = recordingRegistration();
    registerSearchCommands({
      ...baseDependencies(filterRecorder),
      context: {},
      isCurrentWorkspaceSelection: () => current,
      vscode: { workspace: { getConfiguration: () => ({ get: () => "" }) } },
      workspaceAccess: access.access,
      searchProvider: { async search() { searchCalls += 1; } },
    });
    await filterRecorder.handlers.get("cloudsmith-vsc.filterVulnerableWorkspace")(
      workspaceNode
    );
    assert.strictEqual(searchCalls, 0);
  });

  test("repository search shortcut rechecks ownership after authoritative recovery", async () => {
    const recorder = recordingRegistration();
    let current = true;
    let searchCalls = 0;
    const access = workspaceCollectionHarness({
      async fetchWorkspaceRepositories() {
        current = false;
        return {
          items: [{ slug: "repo-a", name: "Repo A" }],
          complete: true,
          stale: false,
        };
      },
    });
    registerSearchCommands({
      ...baseDependencies(recorder),
      context: {},
      isCurrentRepositorySelection: () => current,
      packageAdapters: {
        fromRepositoryNode: () => ({
          workspace: "workspace-a",
          repository: "repo-a",
          name: "Repo A",
        }),
      },
      vscode: { workspace: { getConfiguration: () => ({ get: () => "" }) } },
      workspaceAccess: access.access,
      searchProvider: { async search() { searchCalls += 1; } },
    });

    await recorder.handlers.get("cloudsmith-vsc.filterVulnerable")({});
    assert.strictEqual(searchCalls, 0);
  });

  test("specific-repository scope cancellation never falls through to an all-repository scan", async () => {
    const recorder = recordingRegistration();
    const picks = [
      { label: "Workspace A", description: "workspace-a" },
      { label: "Select a specific repository", all: false },
      null,
    ];
    let projectFolderCalls = 0;
    let scanCalls = 0;
    const connectionManager = {};
    const workspaceContextProjector = {
      begin: () => ({}),
      project: async () => {},
    };
    registerDependencyHealthCommands({
      ...baseDependencies(recorder),
      vscode: {
        workspace: { getConfiguration: () => ({ get: () => null }) },
        window: {
          showQuickPick: async () => picks.shift(),
          showErrorMessage() {},
          showWarningMessage() {},
          showInformationMessage() {},
        },
        QuickPickItemKind: { Separator: 1 },
      },
      workspaceAccess: {
        context: {},
        connectionManager,
        workspaceContextProjector,
        captureAccount: () => ({}),
        isAccountCurrent: () => true,
        createCloudsmithAPI: () => ({}),
        fetchWorkspaces: async () => ({ items: [{ slug: "workspace-a", name: "Workspace A" }], complete: true }),
        normalizedWorkspaceName: workspace => workspace.name,
        replaceCollectionItems: (result, items) => ({ ...result, items }),
        setHasMultipleWorkspacesContext: async () => {},
        fetchWorkspaceRepositories: async () => ({
          items: [{ slug: "repo-a", name: "Repo A" }],
          complete: true,
        }),
        formatApiError: error => error.message,
        vscode: {
          window: {
            showErrorMessage() {},
            showWarningMessage() {},
          },
          QuickPickItemKind: { Separator: 1 },
        },
      },
      dependencyHealthProvider: {
        async selectProjectFolder() { projectFolderCalls += 1; return "/project"; },
        async scan() { scanCalls += 1; },
      },
      FILTER_MODES: {},
      SORT_MODES: {},
    });
    await recorder.handlers.get("cloudsmith-vsc.changeDependencyScanScope")();
    assert.strictEqual(projectFolderCalls, 0);
    assert.strictEqual(scanCalls, 0);
  });

  test("dependency scope selection cannot continue after its account becomes stale", async () => {
    const recorder = recordingRegistration();
    const harness = workspaceCollectionHarness();
    let folderCalls = 0;
    let scanCalls = 0;
    registerDependencyHealthCommands({
      ...baseDependencies(recorder),
      vscode: {
        QuickPickItemKind: { Separator: 1 },
        workspace: { getConfiguration: () => ({ get: () => null }) },
        window: {
          async showQuickPick() {
            harness.stale();
            return { label: "Workspace A", description: "workspace-a" };
          },
          showErrorMessage() {},
        },
      },
      workspaceAccess: harness.access,
      dependencyHealthProvider: {
        async selectProjectFolder() { folderCalls += 1; return "/project"; },
        async scan() { scanCalls += 1; },
      },
    });

    await recorder.handlers.get("cloudsmith-vsc.changeDependencyScanScope")();
    assert.strictEqual(folderCalls, 0);
    assert.strictEqual(scanCalls, 0);
  });

  test("default-workspace all-repository scan clears an orphan repository setting", async () => {
    const recorder = recordingRegistration();
    const scans = [];
    registerDependencyHealthCommands({
      ...baseDependencies(recorder),
      vscode: {
        workspace: {
          workspaceFolders: [{ name: "Project", uri: { fsPath: "/project" } }],
          getConfiguration: () => ({
            get(key) {
              if (key === "defaultWorkspace") return "workspace-a";
              if (key === "dependencyScanRepo") return "orphan-repo";
              return null;
            },
          }),
        },
      },
      workspaceAccess: workspaceCollectionHarness().access,
      dependencyHealthProvider: {
        hasSuccessfulScan: () => false,
        async scan(workspace, repository, projectFolder) {
          scans.push({ workspace, repository, projectFolder });
        },
      },
    });

    await recorder.handlers.get("cloudsmith-vsc.scanDependencies")();
    assert.deepStrictEqual(scans, [{
      workspace: "workspace-a",
      repository: null,
      projectFolder: "/project",
    }]);
  });

  test("primary scan rechecks account ownership after resolving its target", async () => {
    const recorder = recordingRegistration();
    const harness = workspaceCollectionHarness();
    let scanCalls = 0;
    registerDependencyHealthCommands({
      ...baseDependencies(recorder),
      vscode: {
        workspace: {
          workspaceFolders: [{ name: "Project", uri: { fsPath: "/project" } }],
          getConfiguration: () => ({
            get: key => (key === "dependencyScanWorkspace" ? "workspace-a" : null),
          }),
        },
      },
      workspaceAccess: harness.access,
      dependencyHealthProvider: {
        hasSuccessfulScan: () => false,
        async scan() { scanCalls += 1; },
      },
    });

    queueMicrotask(() => harness.stale());
    await recorder.handlers.get("cloudsmith-vsc.scanDependencies")();
    assert.strictEqual(scanCalls, 0);
  });

  test("SSO pull command callbacks stop before provider or selection adaptation", async () => {
    const recorder = recordingRegistration();
    const errors = [];
    let bulkCalls = 0;
    let singleCalls = 0;
    let adapterCalls = 0;
    registerDependencyHealthCommands({
      ...baseDependencies(recorder),
      vscode: {
        window: {
          showErrorMessage(message) { errors.push(message); },
        },
      },
      workspaceAccess: currentAccountAccess({
        connectionManager: {
          getAuthenticationCapabilities() {
            return { pullThroughAvailable: false };
          },
        },
      }),
      packageAdapters: {
        fromDependencyHealthNode() {
          adapterCalls += 1;
          throw new Error("selection adaptation must not run");
        },
      },
      dependencyHealthProvider: {
        hasSuccessfulScan: () => true,
        isScanRunning: () => false,
        isDependencyOperationRunning: () => false,
        async pullDependencies() { bulkCalls += 1; },
        async pullSingleDependency() { singleCalls += 1; },
      },
    });

    await recorder.handlers.get("cloudsmith-vsc.pullDependencies")();
    await recorder.handlers.get("cloudsmith-vsc.pullSingleDependency")({});

    assert.deepStrictEqual({ adapterCalls, bulkCalls, singleCalls }, {
      adapterCalls: 0,
      bulkCalls: 0,
      singleCalls: 0,
    });
    assert.deepStrictEqual(errors, [
      "Pull-through requires a Cloudsmith API key. Sign in with an API key to continue.",
      "Pull-through requires a Cloudsmith API key. Sign in with an API key to continue.",
    ]);
  });

  test("dependency callbacks contain scan failures and pass only canonical pull coordinates", async () => {
    const recorder = recordingRegistration();
    const scanFailure = Object.freeze({ ok: false, error: "scan unavailable" });
    const coordinate = Object.freeze({
      identityState: "coordinate",
      workspace: "workspace-a",
      repository: "repo-a",
      name: "left-pad",
      qualifiers: Object.freeze({ targetFramework: "net8.0" }),
    });
    const exact = Object.freeze({
      identityState: "exact",
      workspace: "workspace-a",
      repository: "repo-a",
      name: "left-pad",
    });
    const adapterOptions = [];
    const pulled = [];
    const warnings = [];
    let successful = false;
    registerDependencyHealthCommands({
      ...baseDependencies(recorder),
      vscode: {
        workspace: {
          workspaceFolders: [{ name: "Project", uri: { fsPath: "/project" } }],
          getConfiguration: () => ({
            get(key) {
              if (key === "dependencyScanWorkspace") return "workspace-a";
              if (key === "dependencyScanRepo") return "repo-a";
              return null;
            },
          }),
        },
        window: {
          showWarningMessage(message, options) {
            if (options?.modal) return "Pull dependency";
            warnings.push(message);
            return undefined;
          },
        },
      },
      packageAdapters: {
        fromDependencyHealthNode(item, options) {
          adapterOptions.push(options);
          if (item === "coordinate") return coordinate;
          if (item === "exact") return exact;
          throw new TypeError("invalid dependency");
        },
      },
      dependencyHealthProvider: {
        hasSuccessfulScan: () => successful,
        isScanRunning: () => false,
        isDependencyOperationRunning: () => false,
        async scan() { return scanFailure; },
        getLastSuccessfulScope: () => ({
          workspace: "workspace-a",
          repository: "repo-a",
        }),
        async pullSingleDependency(value) { pulled.push(value); },
      },
      workspaceAccess: workspaceCollectionHarness().access,
    });

    const scanResult = await recorder.handlers.get("cloudsmith-vsc.scanDependencies")();
    successful = true;
    const pull = recorder.handlers.get("cloudsmith-vsc.pullSingleDependency");
    await pull("coordinate");
    await pull("exact");
    await pull(null);
    assert.strictEqual(scanResult, scanFailure);
    assert.deepStrictEqual(pulled, [coordinate]);
    assert.deepStrictEqual(adapterOptions, [
      { workspace: "workspace-a", repository: "repo-a" },
      { workspace: "workspace-a", repository: "repo-a" },
      { workspace: "workspace-a", repository: "repo-a" },
    ]);
    assert.deepStrictEqual(warnings, [
      "Could not determine dependency details.",
      "Could not determine dependency details.",
    ]);
  });

  test("dependency registrar disposal hides and resolves an open sort/filter picker", async () => {
    const recorder = recordingRegistration();
    const acceptListeners = new Set();
    const hideListeners = new Set();
    let showCalls = 0;
    let hideCalls = 0;
    let pickerDisposeCalls = 0;
    let subscriptionDisposeCalls = 0;
    const subscribe = listeners => (listener) => {
      listeners.add(listener);
      return {
        dispose() {
          subscriptionDisposeCalls += 1;
          listeners.delete(listener);
        },
      };
    };
    const quickPick = {
      selectedItems: [],
      onDidAccept: subscribe(acceptListeners),
      onDidHide: subscribe(hideListeners),
      show() { showCalls += 1; },
      hide() {
        hideCalls += 1;
        for (const listener of [...hideListeners]) listener();
      },
      dispose() { pickerDisposeCalls += 1; },
    };
    const connectionListeners = new Set();
    const connectionManager = {
      onDidChange: subscribe(connectionListeners),
    };
    const disposable = registerDependencyHealthCommands({
      ...baseDependencies(recorder),
      vscode: {
        QuickPickItemKind: { Separator: 1 },
        window: { createQuickPick: () => quickPick },
      },
      workspaceAccess: currentAccountAccess({ connectionManager }),
      dependencyHealthProvider: {
        hasSuccessfulScan: () => true,
        isScanRunning: () => false,
        isDependencyOperationRunning: () => false,
        getSortMode: () => "alphabetical",
        getFilterMode: () => null,
      },
      SORT_MODES: {
        ALPHABETICAL: "alphabetical",
        SEVERITY: "severity",
        COVERAGE: "coverage",
      },
      FILTER_MODES: {
        VULNERABLE: "vulnerable",
        UNCOVERED: "uncovered",
        RESTRICTIVE_LICENSE: "restrictive",
        POLICY_VIOLATION: "policy",
      },
    });

    const pending = recorder.handlers.get("cloudsmith-vsc.depSortFilter")();
    await Promise.resolve();
    assert.strictEqual(showCalls, 1);
    assert.strictEqual(quickPick.items.filter(item => item.description?.startsWith("Current sort")).length, 1);
    assert.strictEqual(quickPick.items.filter(item => item.description?.startsWith("Current filter")).length, 1);
    assert.match(quickPick.items.find(item => item.description?.startsWith("Current sort")).description, /Alphabetical|Default ordering/);
    assert.strictEqual(
      quickPick.items.find(item => item.description?.startsWith("Current filter")).description,
      "Current filter · No filter applied"
    );
    disposable.dispose();
    await pending;
    assert.strictEqual(hideCalls, 1);
    assert.strictEqual(pickerDisposeCalls, 1);
    assert.strictEqual(subscriptionDisposeCalls, 3);
    assert.strictEqual(recorder.handlers.has("cloudsmith-vsc.depSortFilter"), false);
  });

  test("programmatic CVE command requires ownership and bounded CVE or GHSA identifiers", async () => {
    const recorder = recordingRegistration();
    const opened = [];
    const warnings = [];
    registerVulnerabilityCommands({
      ...baseDependencies(recorder),
      isCurrentSelection: item => item?.current === true,
      vscode: {
        Uri: { parse: value => value },
        env: { openExternal: async value => { opened.push(value); return true; } },
        window: { showWarningMessage: message => warnings.push(message) },
      },
    });
    const handler = recorder.handlers.get("cloudsmith-vsc.openCVE");
    await handler({ current: true, cveId: "CVE-2026-12345" });
    await handler({ current: true, cveId: "GHSA-abcd-1234-wxyz" });
    await handler({ cveId: "CVE-2026-99999" });
    for (const cveId of [
      "CVE-2026-12345/../../secret",
      "CVE-2026-12345?query=1",
      "CVE-2026-12\u0000",
      `CVE-2026-${"1".repeat(120)}`,
      "GHSA----",
      "GHSA-abcd-1234",
      "not-a-cve",
    ]) {
      await handler({ current: true, cveId });
    }
    assert.deepStrictEqual(opened, [
      "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
      "https://github.com/advisories/GHSA-abcd-1234-wxyz",
    ]);
    assert.strictEqual(warnings.length, 7);
  });

  test("CVE navigation reports refused and rejected external opens", async () => {
    const recorder = recordingRegistration();
    const warnings = [];
    const outcomes = [false, new Error("platform rejected")];
    registerVulnerabilityCommands({
      ...baseDependencies(recorder),
      vscode: {
        Uri: { parse: value => value },
        env: {
          async openExternal() {
            const outcome = outcomes.shift();
            if (outcome instanceof Error) throw outcome;
            return outcome;
          },
        },
        window: { async showWarningMessage(message) { warnings.push(message); } },
      },
    });
    const handler = recorder.handlers.get("cloudsmith-vsc.openCVE");
    await handler({ cveId: "CVE-2026-12345" });
    await handler({ cveId: "CVE-2026-12345" });
    assert.deepStrictEqual(warnings, [
      "Could not open the vulnerability reference.",
      "Could not open the vulnerability reference.",
    ]);
  });

  test("vulnerability and quarantine selection cancellation never reaches providers", async () => {
    const recorder = recordingRegistration();
    const information = [];
    const shown = [];
    let recent = [];
    const quarantined = Object.freeze({
      identityState: "exact",
      status: "Quarantined",
      name: "widget",
    });
    registerVulnerabilityCommands({
      ...baseDependencies(recorder),
      vscode: {
        window: {
          showInformationMessage: message => information.push(message),
          showQuickPick: async () => null,
        },
      },
      recentPackages: { getAll: () => recent, add() {} },
      packageAdapters: { fromPackageSelection: value => value },
      packageDomain: { assertExactPackage: value => value },
      vulnerabilityProvider: { show: value => shown.push(["vulnerability", value]) },
      quarantineExplainProvider: { show: value => shown.push(["quarantine", value]) },
    });

    await recorder.handlers.get("cloudsmith-vsc.showVulnerabilities")();
    recent = [quarantined];
    await recorder.handlers.get("cloudsmith-vsc.explainQuarantine")();
    assert.deepStrictEqual(shown, []);
    assert.deepStrictEqual(information, [
      "No recent packages are available. Open or inspect a package, then try again.",
    ]);
  });

  test("vulnerability provider receives only the adapted canonical package", async () => {
    const recorder = recordingRegistration();
    const canonical = Object.freeze({ identityState: "exact", name: "widget" });
    const shown = [];
    const recent = [];
    registerVulnerabilityCommands({
      ...baseDependencies(recorder),
      vscode: { window: { showWarningMessage() {} } },
      packageAdapters: { fromPackageSelection: () => canonical },
      packageDomain: { assertExactPackage: value => value },
      recentPackages: { getAll: () => [], add: value => recent.push(value) },
      vulnerabilityProvider: { async show(value) { shown.push(value); } },
    });

    await recorder.handlers.get("cloudsmith-vsc.showVulnerabilities")({ legacy: true });
    assert.deepStrictEqual(shown, [canonical]);
    assert.deepStrictEqual(recent, [canonical]);
  });

  test("dependency vulnerability commands accept exact matches and reject unmatched nodes", async () => {
    const recorder = recordingRegistration();
    const exactPackage = packageDomain.createExactPackage({
      workspace: "workspace-a",
      repository: "repo-a",
      packageIdentifier: "package-one",
      name: "canonical-widget",
      version: "2.0.0",
      format: "npm",
      status: "Completed",
    });
    const matchedNode = {
      getTreeItem: () => ({ contextValue: "dependencyHealthVulnerable" }),
      getActionCapabilities: () => ({
        actions: {
          findSafeVersion: true,
          showVulnerabilities: true,
        },
      }),
      package: exactPackage,
      cloudsmithMatch: exactPackage,
      declarationName: "declared-widget",
      name: "declared-widget",
      declaredVersion: "^1.0.0",
      resolvedVersion: "1.5.0",
      version: { id: "Version", value: exactPackage.version },
      versionState: "resolved",
      cloudsmithStatus: "FOUND",
      format: "npm",
      namespace: exactPackage.workspace,
      repository: exactPackage.repository,
      slug_perm_raw: exactPackage.packageIdentifier,
    };
    const unmatchedNode = {
      getTreeItem: () => ({ contextValue: "dependencyHealthVulnerable" }),
      getActionCapabilities: () => ({ actions: {} }),
      declarationName: "declared-other",
      name: "normalized-other",
      declaredVersion: "^3.0.0",
      resolvedVersion: "3.2.1",
      versionState: "resolved",
      cloudsmithStatus: "NOT_FOUND",
      format: "python",
    };
    const showOnlyNode = {
      ...matchedNode,
      getActionCapabilities: () => ({
        actions: {
          findSafeVersion: false,
          showVulnerabilities: true,
        },
      }),
    };
    const findOnlyNode = {
      ...matchedNode,
      getActionCapabilities: () => ({
        actions: {
          findSafeVersion: true,
          showVulnerabilities: false,
        },
      }),
    };
    const shown = [];
    const safeCalls = [];
    const recent = [];
    const errors = [];
    class RemediationHelper {
      async findSafeVersions(...args) {
        safeCalls.push(args);
        return { success: false, error: { message: "remediation unavailable" } };
      }
    }
    registerVulnerabilityCommands({
      ...baseDependencies(recorder),
      context: {},
      vscode: {
        window: {
          showErrorMessage: message => errors.push(message),
          showWarningMessage() {},
        },
      },
      packageAdapters,
      packageDomain,
      recentPackages: { getAll: () => [], add: value => recent.push(value) },
      CloudsmithAPI: class {},
      RemediationHelper,
      formatApiError: error => error.message,
      vulnerabilityProvider: { async show(value) { shown.push(value); } },
      vulnerabilityStateService: completeVulnerableStateService(),
      dependencyHealthProvider: {
        getLastSuccessfulScope: () => ({
          workspace: "workspace-a",
          repository: "repo-a",
        }),
      },
    });

    await recorder.handlers.get("cloudsmith-vsc.showDepVulnerabilities")(matchedNode);
    await recorder.handlers.get("cloudsmith-vsc.findDepSafeVersion")(matchedNode);
    await recorder.handlers.get("cloudsmith-vsc.showDepVulnerabilities")(showOnlyNode);
    await recorder.handlers.get("cloudsmith-vsc.findDepSafeVersion")(showOnlyNode);
    await recorder.handlers.get("cloudsmith-vsc.showDepVulnerabilities")(findOnlyNode);
    await recorder.handlers.get("cloudsmith-vsc.findDepSafeVersion")(unmatchedNode);
    assert.deepStrictEqual(shown, [exactPackage, exactPackage]);
    assert.deepStrictEqual(safeCalls, [
      ["workspace-a", "repo-a", "canonical-widget", "npm", {
        currentVersion: "2.0.0",
        fixedVersions: [],
      }],
    ]);
    assert.deepStrictEqual(recent, [exactPackage, exactPackage]);
    assert.deepStrictEqual(errors, [
      "Could not find safe versions. remediation unavailable",
    ]);
  });

  test("safe-version service failure is reported without opening vulnerability UI", async () => {
    const recorder = recordingRegistration();
    const errors = [];
    const warnings = [];
    const shown = [];
    const pkg = packageDomain.createExactPackage({
      workspace: "workspace-a",
      repository: "repo-a",
      packageIdentifier: "package-one",
      name: "widget",
      version: "1.0.0",
      format: "python",
      status: "Completed",
    });
    const otherPkg = packageDomain.createExactPackage({
      workspace: "workspace-b",
      repository: "repo-b",
      packageIdentifier: "package-two",
      name: "other-widget",
      version: "2.0.0",
      format: "npm",
      status: "Completed",
    });
    const malformedBase = Object.freeze({
      namespace: "workspace-a",
      repository: "repo-a",
      name: "widget",
      format: "python",
    });
    const calls = [];
    class RemediationHelper {
      async findSafeVersions(...args) {
        calls.push(args);
        return { success: false, error: { message: "remediation unavailable" } };
      }
    }
    registerVulnerabilityCommands({
      ...baseDependencies(recorder),
      context: {},
      vscode: {
        window: {
          showErrorMessage: message => errors.push(message),
          showWarningMessage: message => warnings.push(message),
        },
      },
      packageAdapters,
      packageDomain,
      recentPackages: { getAll: () => [], add() {} },
      CloudsmithAPI: class {},
      RemediationHelper,
      formatApiError: error => error.message,
      vulnerabilityProvider: { show: value => shown.push(value) },
      vulnerabilityStateService: completeVulnerableStateService(),
    });

    const handler = recorder.handlers.get("cloudsmith-vsc.findSafeVersion");
    await handler(pkg);
    await handler(otherPkg);
    await handler({
      ...malformedBase,
      version: "1.0.0",
      slug_perm: "package-one",
      slug_perm_raw: "package-two",
    });
    await handler({
      ...malformedBase,
      version: "",
      slug_perm: "package-one",
    });
    await handler({
      ...malformedBase,
      slug_perm: "",
    });
    await handler({
      ...malformedBase,
      version: "",
    });
    await handler({
      ...malformedBase,
      version: "1.0.0",
      declaredVersion: "2.0.0",
    });
    assert.deepStrictEqual(calls, [
      ["workspace-a", "repo-a", "widget", "python", {
        currentVersion: "1.0.0",
        fixedVersions: [],
      }],
      ["workspace-b", "repo-b", "other-widget", "npm", {
        currentVersion: "2.0.0",
        fixedVersions: [],
      }],
    ]);
    assert.deepStrictEqual(errors, [
      "Could not find safe versions. remediation unavailable",
      "Could not find safe versions. remediation unavailable",
    ]);
    assert.deepStrictEqual(warnings, [
      "Could not determine package details.",
      "Could not determine package details.",
      "Could not determine package details.",
      "Could not determine package details.",
      "Could not determine package details.",
    ]);
    assert.deepStrictEqual(shown, []);
  });

  test("promotion callbacks reject invalid selections and pass canonical packages locally", async () => {
    const recorder = recordingRegistration();
    const warnings = [];
    const recent = [];
    const promoted = [];
    let installGuidanceBuilds = 0;
    const exactPackage = Object.freeze({
      identityState: "exact",
      workspace: "workspace-a",
      repository: "repo-a",
      name: "widget",
      version: "1.2.3",
      format: "python",
      packageIdentifier: "pkg-1",
      copyable: true,
      status: "Completed",
    });
    const quarantinedPackage = Object.freeze({
      ...exactPackage,
      packageIdentifier: "pkg-quarantined",
      status: "Quarantined",
    });
    const nonCopyablePackage = Object.freeze({
      ...exactPackage,
      packageIdentifier: "pkg-non-copyable",
      copyable: false,
    });
    const validPackages = new Set([exactPackage, quarantinedPackage, nonCopyablePackage]);
    registerPromotionCommands({
      ...baseDependencies(recorder),
      vscode: {
        window: { showWarningMessage(message) { warnings.push(message); } },
      },
      packageAdapters: {
        fromPackageSelection(value) {
          if (!validPackages.has(value)) throw new TypeError("invalid package");
          return value;
        },
      },
      packageDomain: {
        assertExactPackage(value) {
          if (!validPackages.has(value)) throw new TypeError("invalid package");
          return value;
        },
        packageCoordinateFromExact(value) {
          return {
            workspace: value.workspace,
            repository: value.repository,
            name: value.name,
            version: value.version,
            format: value.format,
            qualifiers: {},
          };
        },
      },
      InstallCommandBuilder: {
        build() {
          installGuidanceBuilds += 1;
          return { command: "must not be built while deciding promotion" };
        },
        toClipboardCommand(value) { return value; },
      },
      recentPackages: {
        getAll: () => [],
        add: value => recent.push(value),
      },
      promotionProvider: {
        async runPromotionWorkflow(value, options) { promoted.push({ value, options }); },
      },
      cloudsmithProvider: { refresh() {} },
    });

    const handler = recorder.handlers.get("cloudsmith-vsc.promotePackage");
    await handler({ legacy: true });
    await handler(quarantinedPackage);
    await handler(nonCopyablePackage);
    await handler(exactPackage);
    assert.deepStrictEqual(warnings, [
      "Could not determine package details.",
      "This package is not eligible for promotion.",
      "This package is not eligible for promotion.",
    ]);
    assert.deepStrictEqual(recent, []);
    assert.strictEqual(promoted.length, 1);
    assert.strictEqual(
      installGuidanceBuilds,
      0,
      "promotion eligibility must not execute the independent Install guidance pipeline"
    );
    assert.strictEqual(promoted[0].value, exactPackage);
    assert.strictEqual(typeof promoted[0].options.refresh, "function");
  });

  test("promotion recent-package cancellation never starts its workflow", async () => {
    const recorder = recordingRegistration();
    const canonical = Object.freeze({
      identityState: "exact",
      name: "widget",
      version: "1.2.3",
      repository: "repo-a",
      copyable: true,
      status: "Completed",
    });
    let workflows = 0;
    registerPromotionCommands({
      ...baseDependencies(recorder),
      vscode: { window: { showQuickPick: async () => null } },
      packageAdapters: { fromPackageSelection: value => value },
      packageDomain: { assertExactPackage: value => value },
      recentPackages: { getAll: () => [canonical] },
      promotionProvider: {
        async runPromotionWorkflow() { workflows += 1; },
      },
    });

    await recorder.handlers.get("cloudsmith-vsc.promotePackage")();
    assert.strictEqual(workflows, 0);
  });

  test("promotion status contains a provider service error", async () => {
    const recorder = recordingRegistration();
    const errors = [];
    const pkg = Object.freeze({
      identityState: "exact",
      workspace: "workspace-a",
      repository: "repo-a",
      name: "widget",
      version: "1.2.3",
      format: "python",
    });
    registerPromotionCommands({
      ...baseDependencies(recorder),
      vscode: { window: { showErrorMessage: message => errors.push(message) } },
      packageAdapters: { fromPackageSelection: value => value },
      packageDomain: {
        assertExactPackage: value => value,
      },
      recentPackages: { getAll: () => [], add() {} },
      normalizePackageQueryIdentity: (workspace, name, version, format) => ({
        workspace, name, version, format,
      }),
      formatApiError: error => error.message,
      promotionProvider: {
        getPipeline: () => ["repo-a"],
        async getPromotionStatus() {
          return { error: { message: "promotion unavailable" }, items: [] };
        },
      },
    });

    await recorder.handlers.get("cloudsmith-vsc.showPromotionStatus")(pkg);
    assert.deepStrictEqual(errors, [
      "Could not load promotion status. promotion unavailable",
    ]);
  });

  test("incomplete promotion status uses warning severity", async () => {
    const pkg = Object.freeze({
      identityState: "exact",
      workspace: "workspace-a",
      repository: "repo-a",
      name: "widget",
      version: "1.2.3",
      format: "python",
      status: "Completed",
      policy: Object.freeze({ violated: false }),
    });
    for (const pipeline of [true, false]) {
      const recorder = recordingRegistration();
      const information = [];
      const warnings = [];
      registerPromotionCommands({
        ...baseDependencies(recorder),
        vscode: {
          window: {
            showErrorMessage() {},
            showInformationMessage: message => information.push(message),
            showWarningMessage: message => warnings.push(message),
          },
        },
        packageAdapters: {
          fromPackageSelection: value => value,
          fromApiPackageRecord: value => value,
        },
        packageDomain: { assertExactPackage: value => value },
        recentPackages: { getAll: () => [], add() {} },
        normalizePackageQueryIdentity: (workspaceSlug, name, version, format) => ({
          workspace: workspaceSlug,
          name,
          version,
          format,
        }),
        promotionProvider: {
          getPipeline: () => (pipeline ? ["repo-a"] : []),
          async getPromotionStatus() {
            return {
              error: null,
              complete: false,
              items: [{
                repo: "repo-a",
                status: "Completed",
                found: true,
                quarantined: false,
                policyViolated: false,
              }],
            };
          },
          async getPackageLocations() {
            return {
              items: [pkg],
              complete: false,
              failureCount: 1,
              pageCount: 1,
            };
          },
        },
      });

      await recorder.handlers.get("cloudsmith-vsc.showPromotionStatus")(pkg);
      assert.strictEqual(information.length, 0);
      assert.strictEqual(warnings.length, 1);
      assert.ok(warnings[0].includes("incomplete") || warnings[0].includes("unavailable"));
    }
  });

  test("upstream dependency target selection cannot cross an account change", async () => {
    const recorder = recordingRegistration();
    const harness = workspaceCollectionHarness({
      fetchWorkspaceRepositories: async () => ({
        items: [
          { slug: "repo-a", name: "Repo A" },
          { slug: "repo-b", name: "Repo B" },
        ],
        complete: true,
        stale: false,
      }),
    });
    let factoryCalls = 0;
    registerUpstreamCommands({
      ...baseDependencies(recorder),
      context: {},
      vscode: {
        workspace: {
          getConfiguration: () => ({ get: () => "workspace-a" }),
        },
        window: {
          async showQuickPick(items) {
            harness.stale();
            return items[0];
          },
          showInformationMessage() {},
          showWarningMessage() {},
        },
      },
      workspaceAccess: harness.access,
      FORMAT_OPTIONS: ["python"],
      packageAdapters: {
        fromDependencyHealthNode: item => ({ name: item.name, format: item.format }),
      },
      dependencyHealthProvider: {
        getLastSuccessfulScope: () => ({ workspace: "workspace-a", repository: null }),
      },
      packageDomain: {
        createPackageResolutionInput() { factoryCalls += 1; },
      },
    });

    await recorder.handlers.get("cloudsmith-vsc.previewUpstreamResolution")({
      name: "widget",
      format: "python",
      getTreeItem: () => ({ contextValue: "dependencyHealthMissing" }),
    });
    assert.strictEqual(factoryCalls, 0);
  });

  test("upstream preview prompt cancellation never resolves repository or service state", async () => {
    const recorder = recordingRegistration();
    let workspaceReads = 0;
    let repositoryReads = 0;
    let previews = 0;
    let shown = 0;
    const upstreamPreview = {
      async previewResolution() { previews += 1; }
    };
    registerUpstreamCommands({
      ...baseDependencies(recorder),
      context: {},
      vscode: {
        workspace: {
          getConfiguration() {
            workspaceReads += 1;
            return { get: () => "workspace-a" };
          },
        },
        window: { showInputBox: async () => null },
      },
      workspaceAccess: currentAccountAccess({
        async fetchWorkspaceRepositories() {
          repositoryReads += 1;
          return { items: [], complete: true };
        },
      }),
      upstreamPreview,
      upstreamPreviewProvider: { show() { shown += 1; } },
    });

    await recorder.handlers.get("cloudsmith-vsc.previewUpstreamResolution")();
    assert.strictEqual(workspaceReads, 0);
    assert.strictEqual(repositoryReads, 0);
    assert.strictEqual(previews, 0);
    assert.strictEqual(shown, 0);
  });

  test("upstream registrar disposal aborts an in-flight Terraform export", async () => {
    const recorder = recordingRegistration();
    const signals = [];
    let cancellationSubscriptionDisposals = 0;
    let documents = 0;
    let exportOptions = null;
    const resolveOnAbort = (signal, value) => new Promise(resolve => {
      signals.push(signal);
      if (signal.aborted) {
        resolve(value);
        return;
      }
      signal.addEventListener("abort", () => resolve(value), { once: true });
    });
    class CloudsmithAPI {
      async get(_endpoint, options) {
        return resolveOnAbort(options.signal, {
          ok: false,
          error: { kind: "cancelled", message: "cancelled" },
        });
      }
    }
    const disposable = registerUpstreamCommands({
      ...baseDependencies(recorder),
      context: {},
      vscode: {
        ProgressLocation: { Notification: 1 },
        window: {
          async withProgress(_options, task) {
            return task(null, {
              onCancellationRequested: () => ({
                dispose() { cancellationSubscriptionDisposals += 1; },
              }),
            });
          },
          showErrorMessage() {},
          showWarningMessage() {},
        },
        workspace: {
          async openTextDocument() { documents += 1; },
        },
      },
      workspaceAccess: workspaceCollectionHarness().access,
      packageAdapters: {
        fromRepositoryNode: () => Object.freeze({
          workspace: "workspace-a",
          repository: "repo-a",
          name: "Repo A",
        }),
      },
      CloudsmithAPI,
      apiEndpoint: parts => `/${parts.join("/")}`,
      upstreamExport: {
        getPrivilegedRepositoryUpstreamsForExport: async (
          _workspace,
          _repository,
          options
        ) => {
          exportOptions = options;
          return resolveOnAbort(options.signal, null);
        },
      },
      formatApiError: error => error.message,
    });

    const pending = recorder.handlers.get("cloudsmith-vsc.exportTerraform")({});
    await new Promise(resolve => setImmediate(resolve));
    assert.strictEqual(signals.length, 3);
    disposable.dispose();
    await pending;
    assert.ok(signals.every(signal => signal.aborted));
    assert.deepStrictEqual(exportOptions.account, {
      activationId: "activation-a",
      accountEpoch: 1,
    });
    assert.strictEqual(cancellationSubscriptionDisposals, 1);
    assert.strictEqual(documents, 0);
  });

  test("Terraform export cannot publish after its captured account changes", async () => {
    const recorder = recordingRegistration();
    const harness = workspaceCollectionHarness();
    const upstream = deferred();
    let documents = 0;
    let capturedOptions = null;
    registerUpstreamCommands({
      ...baseDependencies(recorder),
      context: {},
      vscode: {
        ProgressLocation: { Notification: 1 },
        languages: { getLanguages: async () => ["terraform"] },
        workspace: {
          async openTextDocument() { documents += 1; return {}; },
        },
        window: {
          async withProgress(_options, task) {
            return task(null, { onCancellationRequested: () => ({ dispose() {} }) });
          },
          async showTextDocument() { documents += 1; },
          showErrorMessage() {},
          showWarningMessage() {},
        },
      },
      workspaceAccess: harness.access,
      packageAdapters: {
        fromRepositoryNode: () => ({
          workspace: "workspace-a",
          repository: "repo-a",
          name: "Repo A",
        }),
      },
      CloudsmithAPI: class {
        async get() { return { ok: true, data: {} }; }
      },
      apiEndpoint: parts => `/${parts.join("/")}`,
      upstreamExport: {
        getPrivilegedRepositoryUpstreamsForExport(_workspace, _repository, options) {
          capturedOptions = options;
          return upstream.promise;
        },
      },
      generateTerraformConfig: () => "resource {}",
    });

    const pending = recorder.handlers.get("cloudsmith-vsc.exportTerraform")({});
    await new Promise(resolve => setImmediate(resolve));
    assert.deepStrictEqual(capturedOptions.account, {
      activationId: "activation-a",
      accountEpoch: 1,
    });
    assert.ok(capturedOptions.signal instanceof AbortSignal);
    harness.stale();
    upstream.resolve({ data: [], complete: true });
    await pending;
    assert.strictEqual(documents, 0);
  });

  test("Terraform export fails closed on retention failure and treats cancellation silently", async () => {
    for (const scenario of [
      {
        error: { kind: "service", message: "retention unavailable" },
        expectedErrors: [
          "Could not export repository retention settings. retention unavailable",
        ],
      },
      {
        error: { kind: "cancelled", message: "cancelled" },
        expectedErrors: [],
      },
    ]) {
      const recorder = recordingRegistration();
      const errors = [];
      let generated = 0;
      let documents = 0;
      registerUpstreamCommands({
        ...baseDependencies(recorder),
        context: {},
        vscode: {
          ProgressLocation: { Notification: 1 },
          window: {
            async withProgress(_options, task) {
              return task(null, { onCancellationRequested: () => ({ dispose() {} }) });
            },
            showErrorMessage(message) { errors.push(message); },
            showWarningMessage() {},
            async showTextDocument() { documents += 1; },
          },
          workspace: {
            async openTextDocument() { documents += 1; return {}; },
          },
        },
        workspaceAccess: workspaceCollectionHarness().access,
        packageAdapters: {
          fromRepositoryNode: () => ({
            workspace: "workspace-a",
            repository: "repo-a",
            name: "Repo A",
          }),
        },
        CloudsmithAPI: class {
          async get(endpoint) {
            return endpoint.endsWith("/retention")
              ? { ok: false, error: scenario.error }
              : { ok: true, data: {} };
          }
        },
        apiEndpoint: parts => `/${parts.join("/")}`,
        upstreamExport: {
          async getPrivilegedRepositoryUpstreamsForExport() {
            return {
              data: [],
              complete: true,
              error: null,
              failedFormats: [],
              uninspectedFormats: [],
            };
          },
        },
        generateTerraformConfig() {
          generated += 1;
          return "resource {}";
        },
        formatApiError: error => error.message,
      });

      await recorder.handlers.get("cloudsmith-vsc.exportTerraform")({});
      assert.deepStrictEqual(errors, scenario.expectedErrors);
      assert.strictEqual(generated, 0);
      assert.strictEqual(documents, 0);
    }
  });

  test("upstream preview validates input and contains a null service result", async () => {
    const recorder = recordingRegistration();
    const warnings = [];
    const factoryInputs = [];
    const previewCalls = [];
    const shown = [];
    const names = ["widget", "../escape", "service-error"];
    const upstreamPreview = {
      async previewResolution(...args) {
        previewCalls.push(args);
        return args[2] === "service-error" ? null : { resolved: true };
      }
    };
    registerUpstreamCommands({
      ...baseDependencies(recorder),
      context: {},
      vscode: {
        ProgressLocation: { Notification: 1 },
        workspace: {
          getConfiguration: () => ({ get: key => (
            key === "defaultWorkspace" ? "workspace-a" : ""
          ) }),
        },
        window: {
          async showInputBox() { return names.shift(); },
          async showQuickPick(items) { return items[0]; },
          showWarningMessage(message) { warnings.push(message); },
          async withProgress(_options, task) { return task(); },
        },
      },
      workspaceAccess: workspaceCollectionHarness({
        fetchWorkspaceRepositories: async () => ({
          items: [{ name: "Repo A", slug: "repo-a" }],
          complete: true,
          stale: false,
        }),
      }).access,
      FORMAT_OPTIONS: ["python"],
      packageDomain: {
        createPackageResolutionInput(input) {
          factoryInputs.push(input);
          if (input.name.startsWith("../")) throw new TypeError("invalid package name");
          return Object.freeze({ ...input });
        },
      },
      upstreamPreview,
      upstreamPreviewProvider: { show: value => shown.push(value) },
    });

    const handler = recorder.handlers.get("cloudsmith-vsc.previewUpstreamResolution");
    await handler();
    await handler();
    await handler();
    assert.deepStrictEqual(factoryInputs, [
      {
        workspace: "workspace-a",
        repository: "repo-a",
        name: "widget",
        format: "python",
      },
      {
        workspace: "workspace-a",
        repository: "repo-a",
        name: "../escape",
        format: "python",
      },
      {
        workspace: "workspace-a",
        repository: "repo-a",
        name: "service-error",
        format: "python",
      },
    ]);
    assert.deepStrictEqual(previewCalls.map(args => args.slice(0, 4)), [
      ["workspace-a", "repo-a", "widget", "python"],
      ["workspace-a", "repo-a", "service-error", "python"],
    ]);
    assert.ok(previewCalls.every(args => (
      args[4].account.activationId === "activation-a"
      && args[4].account.accountEpoch === 1
      && args[4].signal instanceof AbortSignal
    )));
    assert.deepStrictEqual(shown, [{ resolved: true }]);
    assert.deepStrictEqual(warnings, ["Could not determine package details."]);
  });

  test("upstream preview validates and normalizes the actual manual package InputBox", async () => {
    const recorder = recordingRegistration();
    let validateInput = null;
    const factoryInputs = [];
    const previewCalls = [];
    const warnings = [];
    const errors = [];
    registerUpstreamCommands({
      ...baseDependencies(recorder),
      context: {},
      vscode: {
        ProgressLocation: { Notification: 1 },
        workspace: {
          getConfiguration: () => ({ get: key => (
            key === "defaultWorkspace" ? "workspace-a" : ""
          ) }),
        },
        window: {
          async showInputBox(options) {
            validateInput = options.validateInput;
            return "  flask  ";
          },
          async showQuickPick(items) { return items[0]; },
          showWarningMessage(message) { warnings.push(message); },
          showErrorMessage(message) { errors.push(message); },
          async withProgress(_options, task) { return task(); },
        },
      },
      workspaceAccess: workspaceCollectionHarness().access,
      FORMAT_OPTIONS: ["python"],
      packageDomain: {
        createPackageResolutionInput(input) {
          factoryInputs.push(input);
          return Object.freeze({ ...input });
        },
      },
      upstreamPreview: {
        async previewResolution(...args) {
          previewCalls.push(args);
          return { resolved: true };
        },
      },
      upstreamPreviewProvider: { show() {} },
    });

    await recorder.handlers.get("cloudsmith-vsc.previewUpstreamResolution")();

    assert.strictEqual(typeof validateInput, "function");
    assert.strictEqual(validateInput(""), "Enter a package name.");
    assert.strictEqual(validateInput("   "), "Enter a package name.");
    assert.strictEqual(
      validateInput("flask\nmalicious"),
      "Package names cannot contain control characters."
    );
    assert.strictEqual(validateInput("a".repeat(2048)), null);
    assert.strictEqual(
      validateInput("a".repeat(2049)),
      "Package names must be 2048 characters or fewer."
    );
    assert.strictEqual(validateInput("  flask  "), null);
    assert.deepStrictEqual(factoryInputs, [{
      workspace: "workspace-a",
      repository: "repo-a",
      name: "flask",
      format: "python",
    }]);
    assert.deepStrictEqual(
      previewCalls.map(args => args.slice(0, 4)),
      [["workspace-a", "repo-a", "flask", "python"]]
    );
    assert.deepStrictEqual(warnings, []);
    assert.deepStrictEqual(errors, []);
  });

  test("upstream preview manual InputBox cancellation is silent", async () => {
    const recorder = recordingRegistration();
    let picks = 0;
    let factoryCalls = 0;
    let previewCalls = 0;
    const warnings = [];
    const errors = [];
    registerUpstreamCommands({
      ...baseDependencies(recorder),
      vscode: {
        window: {
          async showInputBox() { return null; },
          async showQuickPick() { picks += 1; return null; },
          showWarningMessage(message) { warnings.push(message); },
          showErrorMessage(message) { errors.push(message); },
        },
      },
      FORMAT_OPTIONS: ["python"],
      packageDomain: {
        createPackageResolutionInput() { factoryCalls += 1; return {}; },
      },
      upstreamPreview: {
        async previewResolution() { previewCalls += 1; return null; },
      },
      upstreamPreviewProvider: { show() {} },
    });

    await recorder.handlers.get("cloudsmith-vsc.previewUpstreamResolution")();
    assert.strictEqual(picks, 0);
    assert.strictEqual(factoryCalls, 0);
    assert.strictEqual(previewCalls, 0);
    assert.deepStrictEqual(warnings, []);
    assert.deepStrictEqual(errors, []);
  });

  test("upstream preview cancels a pending manual InputBox when the account changes", async () => {
    const recorder = recordingRegistration();
    const input = deferred();
    let changeListener = null;
    let promptToken = null;
    let picks = 0;
    let factoryCalls = 0;
    let previewCalls = 0;
    const warnings = [];
    const errors = [];
    class CancellationTokenSource {
      constructor() {
        this.token = { isCancellationRequested: false };
      }
      cancel() { this.token.isCancellationRequested = true; }
      dispose() {}
    }
    const connectionManager = {
      onDidChange(listener) {
        changeListener = listener;
        return { dispose() {} };
      },
    };
    const accountHarness = accountAccessHarness({ connectionManager });
    registerUpstreamCommands({
      ...baseDependencies(recorder),
      workspaceAccess: accountHarness.access,
      vscode: {
        CancellationTokenSource,
        window: {
          async showInputBox(_options, token) {
            promptToken = token;
            return input.promise;
          },
          async showQuickPick() { picks += 1; return null; },
          showWarningMessage(message) { warnings.push(message); },
          showErrorMessage(message) { errors.push(message); },
        },
      },
      FORMAT_OPTIONS: ["python"],
      packageDomain: {
        createPackageResolutionInput() { factoryCalls += 1; return {}; },
      },
      upstreamPreview: {
        async previewResolution() { previewCalls += 1; return null; },
      },
      upstreamPreviewProvider: { show() {} },
    });

    const pending = recorder.handlers.get("cloudsmith-vsc.previewUpstreamResolution")();
    await new Promise(resolve => setImmediate(resolve));
    assert.strictEqual(typeof changeListener, "function");
    assert.strictEqual(promptToken.isCancellationRequested, false);
    accountHarness.stale();
    changeListener();
    assert.strictEqual(promptToken.isCancellationRequested, true);
    input.resolve("flask");
    await pending;

    assert.strictEqual(picks, 0);
    assert.strictEqual(factoryCalls, 0);
    assert.strictEqual(previewCalls, 0);
    assert.deepStrictEqual(warnings, []);
    assert.deepStrictEqual(errors, []);
  });

  test("upstream preview is latest-wins within the same account", async () => {
    const recorder = recordingRegistration();
    const first = deferred();
    const second = deferred();
    const calls = [];
    const shown = [];
    registerUpstreamCommands({
      ...baseDependencies(recorder),
      vscode: {
        ProgressLocation: { Notification: 1 },
        workspace: {
          getConfiguration: () => ({ get: () => "workspace-a" }),
        },
        window: {
          async showQuickPick(items) { return items[0]; },
          async withProgress(_options, task) {
            return task(null, { onCancellationRequested: () => ({ dispose() {} }) });
          },
          showWarningMessage() {},
        },
      },
      workspaceAccess: currentAccountAccess(),
      FORMAT_OPTIONS: ["python"],
      packageAdapters: {
        fromDependencyHealthNode: item => ({ name: item.name, format: item.format }),
      },
      dependencyHealthProvider: {
        getLastSuccessfulScope: () => ({
          workspace: "workspace-a",
          repository: "repo-a",
        }),
      },
      packageDomain: {
        createPackageResolutionInput: input => Object.freeze({ ...input }),
      },
      upstreamPreview: {
        previewResolution(...args) {
          calls.push(args);
          return calls.length === 1 ? first.promise : second.promise;
        },
      },
      upstreamPreviewProvider: { show: value => shown.push(value) },
    });
    const handler = recorder.handlers.get("cloudsmith-vsc.previewUpstreamResolution");
    const firstRun = handler({
      name: "first",
      format: "python",
      getTreeItem: () => ({ contextValue: "dependencyHealthMissing" }),
    });
    await new Promise(resolve => setImmediate(resolve));
    const secondRun = handler({
      name: "second",
      format: "python",
      getTreeItem: () => ({ contextValue: "dependencyHealthMissing" }),
    });
    await new Promise(resolve => setImmediate(resolve));

    assert.strictEqual(calls.length, 2);
    assert.strictEqual(calls[0][4].signal.aborted, true);
    assert.strictEqual(calls[1][4].signal.aborted, false);
    second.resolve({ name: "second" });
    await secondRun;
    first.resolve({ name: "first" });
    await firstRun;
    assert.deepStrictEqual(shown, [{ name: "second" }]);
  });

  test("license command rejects credentials, controls, unsafe protocols, and overlong URLs", async () => {
    const recorder = recordingRegistration();
    const opened = [];
    const warnings = [];
    registerPackageCommands({
      ...baseDependencies(recorder),
      vscode: {
        Uri: { parse: value => value },
        env: { openExternal: async value => { opened.push(value); return true; } },
        window: { showWarningMessage: message => warnings.push(message) },
      },
    });
    const handler = recorder.handlers.get("cloudsmith-vsc.openLicenseUrl");
    await handler({ licenseInfo: { licenseUrl: "https://spdx.org/licenses/Apache-2.0.html" } });
    for (const licenseUrl of [
      "https://user:secret@spdx.org/licenses/MIT.html",
      "http://spdx.org/licenses/MIT.html",
      "javascript:alert(1)",
      "https://spdx.org/license\u0000/MIT",
      `https://spdx.org/${"a".repeat(2040)}`,
    ]) {
      await handler({ licenseInfo: { licenseUrl } });
    }
    assert.deepStrictEqual(opened, ["https://spdx.org/licenses/Apache-2.0.html"]);
    assert.strictEqual(warnings.length, 5);
  });

  test("license navigation confirms non-allowlisted HTTPS hosts and reports refused opens", async () => {
    const recorder = recordingRegistration();
    const opened = [];
    const prompts = [];
    const warnings = [];
    const choices = [undefined, "Open", "Open", "Open"];
    const outcomes = [false, new Error("platform rejected"), true];
    registerPackageCommands({
      ...baseDependencies(recorder),
      vscode: {
        Uri: { parse: value => value },
        env: {
          async openExternal(value) {
            opened.push(value);
            const outcome = outcomes.shift();
            if (outcome instanceof Error) throw outcome;
            return outcome;
          },
        },
        window: {
          async showWarningMessage(message, ...options) {
            if (options.length > 0) {
              prompts.push([message, ...options]);
              return choices.shift();
            }
            warnings.push(message);
            return undefined;
          },
        },
      },
    });
    const handler = recorder.handlers.get("cloudsmith-vsc.openLicenseUrl");
    const item = { licenseInfo: { licenseUrl: "https://licenses.example/private/path?token=secret" } };
    await handler(item);
    await handler(item);
    await handler(item);
    await handler(item);

    assert.strictEqual(prompts.length, 4);
    assert.deepStrictEqual(prompts[0], [
      "Open a license page on licenses.example? Continue only if you trust this site.",
      { modal: true },
      "Open",
    ]);
    assert.strictEqual(JSON.stringify(prompts).includes("token=secret"), false);
    assert.strictEqual(opened.length, 3);
    assert.deepStrictEqual(warnings, [
      "Could not open the license URL.",
      "Could not open the license URL.",
    ]);
  });
});

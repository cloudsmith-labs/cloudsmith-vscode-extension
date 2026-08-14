// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
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

const INTERNAL_COMMANDS = [
  "cloudsmith-vsc.scanDependenciesPending",
  "cloudsmith-vsc.scanDependenciesComplete",
  "cloudsmith-vsc.rescanDependencies",
];

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
  };
}

function currentAccountAccess(overrides = {}) {
  return accountAccessHarness(overrides).access;
}

function accountAccessHarness(overrides = {}) {
  const connectionManager = overrides.connectionManager || {};
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

  test("compatibility aliases share their local primary handlers", () => {
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
    assert.strictEqual(
      vulnerabilityRecorder.handlers.get("cloudsmith-vsc.showDepVulnerabilities"),
      vulnerabilityRecorder.handlers.get("cloudsmith-vsc.showVulnerabilities")
    );
    assert.strictEqual(
      vulnerabilityRecorder.handlers.get("cloudsmith-vsc.findDepSafeVersion"),
      vulnerabilityRecorder.handlers.get("cloudsmith-vsc.findSafeVersion")
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
      connectionManager: { isOperationCurrent: () => current },
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
        async cancelCredentialOperation(value) { cancelled.push(value); },
      },
      credentialManager: { async storeApiKey() { stored += 1; } },
      handleAuthenticationResult() {},
    });

    await recorder.handlers.get("cloudsmith-vsc.configureCredentials")();
    assert.deepStrictEqual(cancelled, [operation]);
    assert.strictEqual(stored, 0);
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
          async openExternal(value) { opened.push(value); },
        },
        Uri: { parse: value => value },
      },
    });

    await recorder.handlers.get("cloudsmith-vsc.openSettings")();
    await recorder.handlers.get("cloudsmith-vscode-extension.cloudsmithDocs")();
    assert.deepStrictEqual(commands, [[
      "workbench.action.openSettings",
      "@ext:Cloudsmith.cloudsmith-vsc",
    ]]);
    assert.deepStrictEqual(opened, ["https://docs.cloudsmith.com/"]);
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

  test("settings empty workspace state reports an error without opening selection", async () => {
    const recorder = recordingRegistration();
    const harness = workspaceCollectionHarness({
      fetchWorkspaces: async () => ({ items: [], complete: true }),
    });
    const errors = [];
    let quickPicks = 0;
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
          async showQuickPick() { quickPicks += 1; },
          showErrorMessage(message) { errors.push(message); },
        },
      },
      workspaceAccess: harness.access,
      treeView: {},
      cloudsmithProvider: { refresh() {} },
      updateDefaultWorkspaceContext() {},
    });

    await recorder.handlers.get("cloudsmith-vsc.setDefaultWorkspace")();
    assert.deepStrictEqual(errors, ["No workspaces found. Connect to Cloudsmith first."]);
    assert.strictEqual(quickPicks, 0);
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
          showQuickPick: async () => ({
            label: "Workspace A",
            description: "workspace-a",
            clear: false,
          }),
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

  test("package callbacks reject invalid selections and copy adapted detail values", async () => {
    const recorder = recordingRegistration();
    const warnings = [];
    const copied = [];
    registerPackageCommands({
      ...baseDependencies(recorder),
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
          if (item !== "valid") throw new TypeError("invalid detail");
          return Object.freeze({ id: "Version", value: "1.2.3" });
        },
      },
    });

    const handler = recorder.handlers.get("cloudsmith-vsc.copySelected");
    await handler(null);
    await handler("valid");
    assert.deepStrictEqual(copied, ["1.2.3"]);
    assert.deepStrictEqual(warnings, ["Run this command from a package context menu."]);
  });

  test("package entitlement cancellation never copies the sensitive token", async () => {
    const recorder = recordingRegistration();
    let writes = 0;
    registerPackageCommands({
      ...baseDependencies(recorder),
      vscode: {
        env: { clipboard: { async writeText() { writes += 1; } } },
        window: { showWarningMessage: async () => "Cancel" },
      },
    });

    await recorder.handlers.get("cloudsmith-vsc.copyEntitlementToken")({
      token: "secret-token",
      tokenName: "read-only",
    });
    assert.strictEqual(writes, 0);
  });

  test("install commands canonicalize versionless repository input and default latest", async () => {
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
    });
    await recorder.handlers.get("cloudsmith-vsc.copyInstallCommand")({
      cloudsmithWorkspace: "workspace-b",
      cloudsmithRepo: "repo-b",
      name: "other-widget",
      format: "python",
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
    assert.deepStrictEqual(builds, [
      {
        format: "npm",
        name: "widget",
        version: "latest",
        workspace: "workspace-a",
        repository: "repo-a",
      },
      {
        format: "python",
        name: "other-widget",
        version: "latest",
        workspace: "workspace-b",
        repository: "repo-b",
      },
    ]);
    assert.deepStrictEqual(copied, [
      "install widget@latest",
      "install other-widget@latest",
    ]);
    assert.deepStrictEqual(recent, []);
    assert.deepStrictEqual(warnings, [
      "Could not determine package details for install command.",
      "Could not determine package details for install command.",
      "Could not determine package details for install command.",
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
    assert.deepStrictEqual(errors, ["package service unavailable"]);
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
    assert.deepStrictEqual(errors, [" mixed format response"]);
  });

  test("search callbacks invoke the provider and fail closed without workspace context", async () => {
    const recorder = recordingRegistration();
    const warnings = [];
    let clearCalls = 0;
    registerSearchCommands({
      ...baseDependencies(recorder),
      vscode: {
        workspace: {
          getConfiguration: () => ({ get: () => "" }),
        },
        window: {
          showWarningMessage(message) { warnings.push(message); },
        },
      },
      searchProvider: {
        clear() { clearCalls += 1; },
      },
      workspaceAccess: currentAccountAccess(),
    });

    await recorder.handlers.get("cloudsmith-vsc.clearSearch")();
    await recorder.handlers.get("cloudsmith-vsc.searchInWorkspace")();
    assert.strictEqual(clearCalls, 1);
    assert.deepStrictEqual(warnings, [
      "Could not determine the workspace. Set a default workspace in settings.",
    ]);
  });

  test("search intent delegates one provider-contained service failure", async () => {
    const recorder = recordingRegistration();
    const operations = [];
    const serviceFailure = Object.freeze({ ok: false, error: "search unavailable" });
    class SearchQueryBuilder {
      raw(value) { this.value = value; return this; }
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
      workspaceAccess: currentAccountAccess(),
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
    const harness = accountAccessHarness();
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
      workspaceAccess: currentAccountAccess(),
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
      workspaceAccess: currentAccountAccess(),
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
      workspaceAccess: currentAccountAccess({
        async fetchWorkspaceRepositories() {
          repositoryReads += 1;
          return { items: [], complete: true };
        },
      }),
      RecentSearches,
      searchProvider: { beginSearch() { beginCalls += 1; } },
    });

    await recorder.handlers.get("cloudsmith-vsc.guidedSearch")();
    assert.strictEqual(repositoryReads, 0);
    assert.strictEqual(beginCalls, 0);
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
          getConfiguration: () => ({
            get(key) {
              if (key === "defaultWorkspace") return "workspace-a";
              if (key === "dependencyScanRepo") return "orphan-repo";
              return null;
            },
          }),
        },
      },
      workspaceAccess: currentAccountAccess(),
      dependencyHealthProvider: {
        hasSuccessfulScan: () => false,
        async scan(workspace, repository) { scans.push({ workspace, repository }); },
      },
    });

    await recorder.handlers.get("cloudsmith-vsc.scanDependencies")();
    assert.deepStrictEqual(scans, [{ workspace: "workspace-a", repository: null }]);
  });

  test("primary scan rechecks account ownership after resolving its target", async () => {
    const recorder = recordingRegistration();
    const harness = accountAccessHarness();
    let scanCalls = 0;
    registerDependencyHealthCommands({
      ...baseDependencies(recorder),
      vscode: {
        workspace: {
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

  test("dependency callbacks contain scan failures and pass only canonical pull coordinates", async () => {
    const recorder = recordingRegistration();
    const scanFailure = Object.freeze({ ok: false, error: "scan unavailable" });
    const coordinate = Object.freeze({ identityState: "coordinate", name: "left-pad" });
    const exact = Object.freeze({ identityState: "exact", name: "left-pad" });
    const adapterOptions = [];
    const pulled = [];
    const warnings = [];
    registerDependencyHealthCommands({
      ...baseDependencies(recorder),
      vscode: {
        workspace: {
          getConfiguration: () => ({
            get(key) {
              if (key === "dependencyScanWorkspace") return "workspace-a";
              if (key === "dependencyScanRepo") return "repo-a";
              return null;
            },
          }),
        },
        window: { showWarningMessage: message => warnings.push(message) },
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
        hasSuccessfulScan: () => false,
        async scan() { return scanFailure; },
        getLastSuccessfulScope: () => ({
          workspace: "workspace-a",
          repository: "repo-a",
        }),
        async pullSingleDependency(value) { pulled.push(value); },
      },
      workspaceAccess: currentAccountAccess(),
    });

    const scanResult = await recorder.handlers.get("cloudsmith-vsc.scanDependencies")();
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
    disposable.dispose();
    await pending;
    assert.strictEqual(hideCalls, 1);
    assert.strictEqual(pickerDisposeCalls, 1);
    assert.strictEqual(subscriptionDisposeCalls, 3);
    assert.strictEqual(recorder.handlers.has("cloudsmith-vsc.depSortFilter"), false);
  });

  test("CVE command opens only bounded CVE and GHSA identifiers", async () => {
    const recorder = recordingRegistration();
    const opened = [];
    const warnings = [];
    registerVulnerabilityCommands({
      ...baseDependencies(recorder),
      vscode: {
        Uri: { parse: value => value },
        env: { openExternal: async value => opened.push(value) },
        window: { showWarningMessage: message => warnings.push(message) },
      },
    });
    const handler = recorder.handlers.get("cloudsmith-vsc.openCVE");
    await handler({ cveId: "CVE-2026-12345" });
    await handler({ cveId: "GHSA-abcd-1234-wxyz" });
    for (const cveId of [
      "CVE-2026-12345/../../secret",
      "CVE-2026-12345?query=1",
      "CVE-2026-12\u0000",
      `CVE-2026-${"1".repeat(120)}`,
      "GHSA----",
      "GHSA-abcd-1234",
      "not-a-cve",
    ]) {
      await handler({ cveId });
    }
    assert.deepStrictEqual(opened, [
      "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
      "https://github.com/advisories/GHSA-abcd-1234-wxyz",
    ]);
    assert.strictEqual(warnings.length, 7);
  });

  test("vulnerability and quarantine selection cancellation never reaches providers", async () => {
    const recorder = recordingRegistration();
    const information = [];
    const shown = [];
    let recent = [];
    const quarantined = Object.freeze({ status: "Quarantined", name: "widget" });
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
      "No recent packages. Run this command from a package context menu.",
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

  test("dependency vulnerability commands preserve matched and unmatched source semantics", async () => {
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
      declarationName: "declared-other",
      name: "normalized-other",
      declaredVersion: "^3.0.0",
      resolvedVersion: "3.2.1",
      versionState: "resolved",
      cloudsmithStatus: "NOT_FOUND",
      format: "python",
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
      dependencyHealthProvider: {
        getLastSuccessfulScope: () => ({
          workspace: "workspace-a",
          repository: "repo-a",
        }),
      },
    });

    await recorder.handlers.get("cloudsmith-vsc.showDepVulnerabilities")(matchedNode);
    await recorder.handlers.get("cloudsmith-vsc.findDepSafeVersion")(matchedNode);
    await recorder.handlers.get("cloudsmith-vsc.findDepSafeVersion")(unmatchedNode);
    assert.deepStrictEqual(shown, [exactPackage]);
    assert.deepStrictEqual(safeCalls, [
      ["workspace-a", "repo-a", "canonical-widget", "npm"],
      ["workspace-a", "repo-a", "normalized-other", "python"],
    ]);
    assert.deepStrictEqual(recent, [exactPackage, exactPackage]);
    assert.deepStrictEqual(errors, [
      "Could not find safe versions. remediation unavailable",
      "Could not find safe versions. remediation unavailable",
    ]);
  });

  test("safe-version service failure is reported without opening vulnerability UI", async () => {
    const recorder = recordingRegistration();
    const errors = [];
    const warnings = [];
    const shown = [];
    const pkg = Object.freeze({
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
    });

    const handler = recorder.handlers.get("cloudsmith-vsc.findSafeVersion");
    await handler(pkg);
    await handler({
      cloudsmithWorkspace: "workspace-b",
      cloudsmithRepo: "repo-b",
      name: "other-widget",
      format: "npm",
    });
    await handler({
      ...pkg,
      version: "1.0.0",
      slug_perm: "package-one",
      slug_perm_raw: "package-two",
    });
    await handler({
      ...pkg,
      version: "",
      slug_perm: "package-one",
    });
    await handler({
      ...pkg,
      slug_perm: "",
    });
    await handler({
      ...pkg,
      version: "",
    });
    await handler({
      ...pkg,
      version: "1.0.0",
      declaredVersion: "2.0.0",
    });
    assert.deepStrictEqual(calls, [
      ["workspace-a", "repo-a", "widget", "python"],
      ["workspace-b", "repo-b", "other-widget", "npm"],
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
    const exactPackage = Object.freeze({
      workspace: "workspace-a",
      repository: "repo-a",
      name: "widget",
      version: "1.2.3",
      format: "python",
      packageIdentifier: "pkg-1",
    });
    registerPromotionCommands({
      ...baseDependencies(recorder),
      vscode: {
        window: { showWarningMessage(message) { warnings.push(message); } },
      },
      packageAdapters: {
        fromPackageSelection(value) {
          if (value !== exactPackage) throw new TypeError("invalid package");
          return value;
        },
      },
      packageDomain: {
        assertExactPackage(value) {
          if (value !== exactPackage) throw new TypeError("invalid package");
          return value;
        },
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
    await handler(exactPackage);
    assert.deepStrictEqual(warnings, ["Could not determine package details."]);
    assert.deepStrictEqual(recent, []);
    assert.strictEqual(promoted.length, 1);
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

  test("upstream repository selection cannot cross an account change", async () => {
    const recorder = recordingRegistration();
    const harness = workspaceCollectionHarness();
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
        },
      },
      workspaceAccess: harness.access,
      packageAdapters: { fromRepositoryNode: value => value },
      packageDomain: {
        createPackageResolutionInput() { factoryCalls += 1; },
      },
    });

    await recorder.handlers.get("cloudsmith-vsc.previewUpstreamResolution")({
      name: "widget",
      format: "python",
    });
    assert.strictEqual(factoryCalls, 0);
  });

  test("upstream preview prompt cancellation never resolves repository or service state", async () => {
    const recorder = recordingRegistration();
    let workspaceReads = 0;
    let repositoryReads = 0;
    let checkerCreations = 0;
    let previews = 0;
    let shown = 0;
    class UpstreamChecker {
      constructor() { checkerCreations += 1; }
      async previewResolution() { previews += 1; }
    }
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
      UpstreamChecker,
      upstreamPreviewProvider: { show() { shown += 1; } },
    });

    await recorder.handlers.get("cloudsmith-vsc.previewUpstreamResolution")();
    assert.strictEqual(workspaceReads, 0);
    assert.strictEqual(repositoryReads, 0);
    assert.strictEqual(checkerCreations, 0);
    assert.strictEqual(previews, 0);
    assert.strictEqual(shown, 0);
  });

  test("upstream registrar disposal aborts an in-flight Terraform export", async () => {
    const recorder = recordingRegistration();
    const signals = [];
    let cancellationSubscriptionDisposals = 0;
    let documents = 0;
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
      workspaceAccess: currentAccountAccess(),
      packageAdapters: {
        fromRepositoryNode: () => Object.freeze({
          workspace: "workspace-a",
          repository: "repo-a",
          name: "Repo A",
        }),
      },
      CloudsmithAPI,
      apiEndpoint: parts => `/${parts.join("/")}`,
      fetchRepositoryUpstreams: async (_context, _workspace, _repository, options) => (
        resolveOnAbort(options.signal, null)
      ),
      formatApiError: error => error.message,
    });

    const pending = recorder.handlers.get("cloudsmith-vsc.exportTerraform")({});
    await Promise.resolve();
    assert.strictEqual(signals.length, 3);
    disposable.dispose();
    await pending;
    assert.ok(signals.every(signal => signal.aborted));
    assert.strictEqual(cancellationSubscriptionDisposals, 1);
    assert.strictEqual(documents, 0);
  });

  test("upstream preview validates input and contains a null service result", async () => {
    const recorder = recordingRegistration();
    const warnings = [];
    const factoryInputs = [];
    const previewCalls = [];
    const shown = [];
    class UpstreamChecker {
      async previewResolution(...args) {
        previewCalls.push(args);
        return args[2] === "service-error" ? null : { resolved: true };
      }
    }
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
          async showQuickPick(items) { return items[0]; },
          showWarningMessage(message) { warnings.push(message); },
          async withProgress(_options, task) { return task(); },
        },
      },
      workspaceAccess: currentAccountAccess({
        context: {},
        fetchWorkspaceRepositories: async () => ({
          items: [{ name: "Repo A", slug: "repo-a" }],
          complete: true,
        }),
        formatApiError: error => error.message,
        vscode: { window: { showErrorMessage() {}, showWarningMessage() {} } },
      }),
      packageAdapters: {
        fromRepositoryNode: value => value,
      },
      packageDomain: {
        createPackageResolutionInput(input) {
          factoryInputs.push(input);
          if (input.name.startsWith("../")) throw new TypeError("invalid package name");
          return Object.freeze({ ...input });
        },
      },
      UpstreamChecker,
      upstreamPreviewProvider: { show: value => shown.push(value) },
    });

    const handler = recorder.handlers.get("cloudsmith-vsc.previewUpstreamResolution");
    await handler({ name: "widget", format: "python" });
    await handler({ name: "../escape", format: "python" });
    await handler({ name: "service-error", format: "python" });
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
    assert.deepStrictEqual(previewCalls, [
      ["workspace-a", "repo-a", "widget", "python"],
      ["workspace-a", "repo-a", "service-error", "python"],
    ]);
    assert.deepStrictEqual(shown, [{ resolved: true }]);
    assert.deepStrictEqual(warnings, ["Could not determine package details."]);
  });

  test("license command rejects credentials, controls, unsafe protocols, and overlong URLs", async () => {
    const recorder = recordingRegistration();
    const opened = [];
    const warnings = [];
    registerPackageCommands({
      ...baseDependencies(recorder),
      vscode: {
        Uri: { parse: value => value },
        env: { openExternal: async value => opened.push(value) },
        window: { showWarningMessage: message => warnings.push(message) },
      },
    });
    const handler = recorder.handlers.get("cloudsmith-vsc.openLicenseUrl");
    await handler({ licenseInfo: { licenseUrl: "https://spdx.org/licenses/Apache-2.0.html" } });
    for (const licenseUrl of [
      "https://user:secret@spdx.org/licenses/MIT.html",
      "javascript:alert(1)",
      "https://spdx.org/license\u0000/MIT",
      `https://spdx.org/${"a".repeat(2040)}`,
    ]) {
      await handler({ licenseInfo: { licenseUrl } });
    }
    assert.deepStrictEqual(opened, ["https://spdx.org/licenses/Apache-2.0.html"]);
    assert.strictEqual(warnings.length, 4);
  });
});

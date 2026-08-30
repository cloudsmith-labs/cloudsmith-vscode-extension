// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vscode = require("vscode");
const filterState = require("../util/filterState");
const recentPackages = require("../util/recentPackages");
const { createExactPackage } = require("../domain/package");
const { UpstreamRuntime } = require("../util/upstreamRuntime");

const PRODUCT_ROOT = path.resolve(__dirname, "..");
const PRODUCT_MANIFEST = JSON.parse(fs.readFileSync(
  path.join(PRODUCT_ROOT, "package.json"),
  "utf8"
));
const TEST_HARNESS_ID = "cloudsmith-test.cloudsmith-vsc-test-harness";
const TEST_HARNESS_ROOT = path.join(PRODUCT_ROOT, "test", "harness-extension");
const SENSITIVE_EXTENSION_IDS = new Set([
  "github.copilot",
  "github.copilot-chat",
  "typescriptteam.jsts-chat-features",
  "vscode.git",
  "vscode.github",
  "vscode.github-authentication",
  "vscode.mermaid-markdown-features",
  "vscode.microsoft-authentication",
]);

function declaresCredentialOrAiCapability(extension) {
  if (SENSITIVE_EXTENSION_IDS.has(String(extension?.id || "").toLowerCase())) return true;
  const contributions = extension?.packageJSON?.contributes;
  if (!contributions || typeof contributions !== "object" || Array.isArray(contributions)) {
    return false;
  }
  return Object.keys(contributions).some(key => (
    key === "authentication" || /^(?:chat|languageModel)/u.test(key)
  ));
}

function assertCredentialAndAiInactivity(options = {}) {
  const extensions = options.extensions || vscode.extensions.all;
  const getChatConfiguration = options.getChatConfiguration
    || (() => vscode.workspace.getConfiguration("chat"));
  const activeCredentialExtensions = extensions
    .filter(declaresCredentialOrAiCapability)
    .filter(extension => extension.isActive)
    .map(extension => extension.id)
    .sort();
  assert.deepStrictEqual(
    activeCredentialExtensions,
    [],
    "Credential-capable built-in and AI extensions must remain inactive"
  );
  const chatConfiguration = getChatConfiguration();
  assert.strictEqual(chatConfiguration.get("disableAIFeatures"), true);
  assert.strictEqual(chatConfiguration.get("enabled"), false);
}

function isWithin(candidatePath, rootPath) {
  const canonicalCandidate = (() => {
    try {
      return fs.realpathSync(candidatePath);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      const parent = fs.realpathSync(path.dirname(candidatePath));
      return path.join(parent, path.basename(candidatePath));
    }
  })();
  const relative = path.relative(
    fs.realpathSync(rootPath),
    canonicalCandidate
  );
  return relative === ""
    || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function isAllowedNonHarnessExtensionPath(candidatePath, expectedExtensionsDir, appRoot) {
  return isWithin(candidatePath, expectedExtensionsDir)
    || isWithin(candidatePath, appRoot);
}

function sameHostPath(left, right, platform = process.platform) {
  const pathApi = platform === "win32" ? path.win32 : path.posix;
  const normalize = value => {
    const normalized = pathApi.normalize(value);
    return platform === "win32" ? normalized.toLowerCase() : normalized;
  };
  return normalize(left) === normalize(right);
}

function deferred() {
  let resolve;
  const promise = new Promise(res => { resolve = res; });
  return { promise, resolve };
}

function createMemento() {
  const values = new Map();
  return {
    get(key, fallback) { return values.has(key) ? values.get(key) : fallback; },
    keys() { return [...values.keys()]; },
    async update(key, value) {
      if (value === undefined) values.delete(key);
      else values.set(key, value);
    },
  };
}

function createActivationContext(extensionPath, onCredentialRead) {
  const secretListeners = new Set();
  const secrets = new Map();
  return {
    subscriptions: [],
    extensionPath,
    extensionUri: vscode.Uri.file(extensionPath),
    globalState: createMemento(),
    workspaceState: createMemento(),
    secrets: {
      async get(key) {
        if (key === "cloudsmith-vsc.authToken") onCredentialRead();
        return secrets.get(key);
      },
      async store(key, value) {
        secrets.set(key, value);
        for (const listener of secretListeners) listener({ key });
      },
      async delete(key) {
        secrets.delete(key);
        for (const listener of secretListeners) listener({ key });
      },
      onDidChange(listener) {
        secretListeners.add(listener);
        return { dispose() { secretListeners.delete(listener); } };
      },
    },
    asAbsolutePath(relativePath) { return path.join(extensionPath, relativePath); },
  };
}

function installOwnedHostResourceFakes() {
  const originals = {
    createDiagnosticCollection: vscode.languages.createDiagnosticCollection,
    createOutputChannel: vscode.window.createOutputChannel,
    createTreeView: vscode.window.createTreeView,
    onDidChangeConfiguration: vscode.workspace.onDidChangeConfiguration,
    registerTreeDataProvider: vscode.window.registerTreeDataProvider,
  };
  const disposable = () => ({ dispose() {} });
  vscode.window.createOutputChannel = () => ({
    append() {},
    appendLine() {},
    clear() {},
    dispose() {},
    show() {},
  });
  vscode.window.createTreeView = () => ({
    description: "",
    dispose() {},
    message: undefined,
    onDidCollapseElement: disposable,
    onDidExpandElement: disposable,
    reveal: async () => undefined,
    title: "",
  });
  vscode.window.registerTreeDataProvider = disposable;
  vscode.workspace.onDidChangeConfiguration = disposable;
  vscode.languages.createDiagnosticCollection = () => ({
    clear() {},
    delete() {},
    dispose() {},
    forEach() {},
    get() { return undefined; },
    has() { return false; },
    set() {},
  });
  return () => {
    vscode.languages.createDiagnosticCollection = originals.createDiagnosticCollection;
    vscode.window.createOutputChannel = originals.createOutputChannel;
    vscode.window.createTreeView = originals.createTreeView;
    vscode.workspace.onDidChangeConfiguration = originals.onDidChangeConfiguration;
    vscode.window.registerTreeDataProvider = originals.registerTreeDataProvider;
  };
}

suite("Extension activation smoke", () => {
  test("host path comparison follows platform identity semantics", () => {
    assert.strictEqual(
      sameHostPath(
        "D:\\a\\cloudsmith-vscode-extension\\test\\harness-extension",
        "d:\\a\\cloudsmith-vscode-extension\\test\\harness-extension",
        "win32"
      ),
      true
    );
    assert.strictEqual(sameHostPath("/workspace/Harness", "/workspace/harness", "linux"), false);
    assert.strictEqual(
      sameHostPath("D:\\a\\harness", "d:\\a\\different", "win32"),
      false
    );
  });

  test("manually composes production activation in a real host with an in-memory credential boundary", async () => {
    const expectedVersion = process.env.EXPECTED_VSCODE_VERSION;
    assert.match(expectedVersion || "", /^\d+\.\d+\.\d+$/);
    assert.strictEqual(vscode.version, expectedVersion);

    assertCredentialAndAiInactivity();

    const harnessExtension = vscode.extensions.getExtension(TEST_HARNESS_ID);
    assert.ok(harnessExtension, "The credential-free test harness extension was not loaded");
    assert.strictEqual(harnessExtension.isActive, false, "The inert harness must not autoactivate");
    assert.strictEqual(
      sameHostPath(
        fs.realpathSync(harnessExtension.extensionPath),
        fs.realpathSync(TEST_HARNESS_ROOT)
      ),
      true
    );
    assert.strictEqual(
      sameHostPath(
        fs.realpathSync(harnessExtension.extensionPath),
        fs.realpathSync(PRODUCT_ROOT)
      ),
      false
    );
    assert.strictEqual(
      vscode.extensions.getExtension("Cloudsmith.cloudsmith-vsc"),
      undefined,
      "The production manifest must not be installed or host-activated by the test runner"
    );
    const expectedExtensionsDirValue = process.env.EXPECTED_EXTENSIONS_DIR || "";
    assert.strictEqual(path.isAbsolute(expectedExtensionsDirValue), true);
    const expectedExtensionsDir = fs.realpathSync(expectedExtensionsDirValue);
    const vscodeTestRoot = fs.realpathSync(path.join(PRODUCT_ROOT, ".vscode-test"));
    const appRoot = fs.realpathSync(vscode.env.appRoot);
    assert.strictEqual(
      isWithin(appRoot, vscodeTestRoot),
      true,
      "The tested editor application must come from the controlled repository-local download"
    );
    assert.strictEqual(
      isAllowedNonHarnessExtensionPath(
        path.join(vscodeTestRoot, "extensions"),
        expectedExtensionsDir,
        appRoot
      ),
      false,
      "A persistent repository-local extensions directory must not be trusted as editor-bundled provenance"
    );
    const repositoryExtensions = vscode.extensions.all
      .filter(extension => (
        isWithin(extension.extensionPath, PRODUCT_ROOT)
        && !isWithin(extension.extensionPath, appRoot)
      ))
      .map(extension => extension.id)
      .sort();
    assert.deepStrictEqual(
      repositoryExtensions,
      [TEST_HARNESS_ID],
      "Only the inert harness may be loaded from this repository"
    );
    assert.deepStrictEqual(
      vscode.extensions.all
        .filter(extension => (
          !extension.isBuiltin
          && extension.id !== TEST_HARNESS_ID
          && !isAllowedNonHarnessExtensionPath(
            extension.extensionPath,
            expectedExtensionsDir,
            appRoot
          )
        ))
        .map(extension => extension.id)
        .sort(),
      [],
      "Non-builtin seeded defaults must remain inside the unique temporary extensions directory"
    );
    const extensionModule = require("../extension");
    let inMemoryCredentialReads = 0;
    const context = createActivationContext(PRODUCT_ROOT, () => {
      inMemoryCredentialReads += 1;
    });

    const activationStartedAt = performance.now();
    await Promise.race([
      extensionModule.activate(context),
      new Promise((_resolve, reject) => setTimeout(
        () => reject(new Error("production activation composition exceeded three seconds")),
        3000
      )),
    ]);
    assert.ok(performance.now() - activationStartedAt < 3000);
    await new Promise(resolve => setImmediate(resolve));
    assertCredentialAndAiInactivity();
    assert.ok(
      inMemoryCredentialReads > 0,
      "production activation must use the explicit in-memory credential boundary"
    );

    const contributedCommands = (PRODUCT_MANIFEST.contributes?.commands || [])
      .map((entry) => entry.command);
    assert.ok(contributedCommands.length > 0, "The extension manifest contributes no commands");

    const registeredCommands = new Set(await vscode.commands.getCommands(true));
    const missingCommands = contributedCommands.filter((command) => !registeredCommands.has(command));
    assert.deepStrictEqual(missingCommands, [], "Every contributed command must be registered after activation");
    for (const compatibilityCommand of [
      "cloudsmith-vsc.scanDependenciesPending",
      "cloudsmith-vsc.scanDependenciesComplete",
      "cloudsmith-vsc.rescanDependencies",
    ]) {
      assert.ok(
        registeredCommands.has(compatibilityCommand),
        `Expected compatibility command ${compatibilityCommand} to be registered`
      );
    }
    const originalExecuteCommand = vscode.commands.executeCommand;
    const settingsTargets = [];
    vscode.commands.executeCommand = async (command, ...args) => {
      if (command === "workbench.action.openSettings") {
        settingsTargets.push({ command, args });
        return undefined;
      }
      return originalExecuteCommand.call(vscode.commands, command, ...args);
    };
    try {
      await originalExecuteCommand.call(vscode.commands, "cloudsmith-vsc.openSettings");
    } finally {
      vscode.commands.executeCommand = originalExecuteCommand;
    }
    assert.deepStrictEqual(settingsTargets, [{
      command: "workbench.action.openSettings",
      args: ["@ext:Cloudsmith.cloudsmith-vsc"],
    }]);
    assertCredentialAndAiInactivity();

    const viewIds = (PRODUCT_MANIFEST.contributes?.views?.cloudsmithSideBar || [])
      .map((entry) => entry.id);
    assert.deepStrictEqual(
      viewIds,
      ["cloudsmithView", "cloudsmithSearchView", "cloudsmithDependencyHealthView", "helpView"]
    );
    assert.strictEqual(
      vscode.extensions.getExtension("Cloudsmith.cloudsmith-vsc"),
      undefined,
      "Manual composition must not register the production manifest with the host"
    );
    assertCredentialAndAiInactivity();
  });

  test("deactivation disposes registered commands and is idempotent", async () => {
    assert.ok((await vscode.commands.getCommands(true)).includes("cloudsmith-vsc.refreshView"));

    const { deactivate } = require("../extension");
    await deactivate();
    await deactivate();
    assertCredentialAndAiInactivity();

    assert.ok(
      !(await vscode.commands.getCommands(true)).includes("cloudsmith-vsc.refreshView"),
      "Deactivation must dispose command registrations owned by activation"
    );
  });

  test("registers commands and returns before held background readiness", async () => {
    const extensionModule = require("../extension");
    await extensionModule.deactivate();
    const upstreamReadiness = deferred();
    const secretRead = deferred();
    const contextProjection = deferred();
    let upstreamStarted = false;
    let secretReadStarted = false;
    let contextProjectionStarted = false;
    let commandsAtFirstContextProjection = null;
    const settingsTargets = [];
    const activationRegistrations = new Set();
    const context = createActivationContext(PRODUCT_ROOT, () => {});
    const originalSecretGet = context.secrets.get.bind(context.secrets);
    context.secrets.get = async key => {
      if (key !== "cloudsmith-vsc.authToken") return originalSecretGet(key);
      secretReadStarted = true;
      return secretRead.promise;
    };
    const originalInitialize = UpstreamRuntime.prototype.initialize;
    UpstreamRuntime.prototype.initialize = function () {
      upstreamStarted = true;
      return upstreamReadiness.promise;
    };
    const originalExecuteCommand = vscode.commands.executeCommand;
    const originalRegisterCommand = vscode.commands.registerCommand;
    vscode.commands.registerCommand = function (id, handler) {
      activationRegistrations.add(id);
      return originalRegisterCommand.call(vscode.commands, id, handler);
    };
    vscode.commands.executeCommand = function (id, ...args) {
      if (id === "setContext") {
        contextProjectionStarted = true;
        commandsAtFirstContextProjection ||= new Set(activationRegistrations);
        return contextProjection.promise;
      }
      if (id === "workbench.action.openSettings") {
        settingsTargets.push({ command: id, args });
        return Promise.resolve(undefined);
      }
      return originalExecuteCommand.call(vscode.commands, id, ...args);
    };

    try {
      const startedAt = performance.now();
      await Promise.race([
        extensionModule.activate(context),
        new Promise((_resolve, reject) => setTimeout(
          () => reject(new Error("activation waited for background readiness")),
          750
        )),
      ]);
      assert.ok(performance.now() - startedAt < 750);
      await new Promise(resolve => setImmediate(resolve));
      assertCredentialAndAiInactivity();
      assert.strictEqual(upstreamStarted, true);
      assert.strictEqual(secretReadStarted, true);
      assert.strictEqual(contextProjectionStarted, true);

      const commands = new Set(await vscode.commands.getCommands(true));
      for (const command of [
        "cloudsmith-vsc.openSettings",
        "cloudsmith-vsc.configureCredentials",
        "cloudsmith-vsc.searchPackages",
        "cloudsmith-vsc.scanDependencies",
      ]) {
        assert.ok(commands.has(command), `${command} must be registered before readiness`);
        assert.ok(
          commandsAtFirstContextProjection?.has(command),
          `${command} must be registered before startup context projection`
        );
      }
      await vscode.commands.executeCommand("cloudsmith-vsc.openSettings");
      assert.deepStrictEqual(settingsTargets, [{
        command: "workbench.action.openSettings",
        args: ["@ext:Cloudsmith.cloudsmith-vsc"],
      }]);
      const guardedResults = await Promise.race([
        Promise.all([
          vscode.commands.executeCommand("cloudsmith-vsc.searchPackages"),
          vscode.commands.executeCommand("cloudsmith-vsc.scanDependencies"),
        ]),
        new Promise((_resolve, reject) => setTimeout(
          () => reject(new Error("connection-sensitive commands ignored unknown authority too slowly")),
          250
        )),
      ]);
      assert.deepStrictEqual(guardedResults, [undefined, undefined]);
      assertCredentialAndAiInactivity();

      const deactivationStartedAt = performance.now();
      await extensionModule.deactivate();
      assert.ok(performance.now() - deactivationStartedAt < 250);
      assertCredentialAndAiInactivity();
    } finally {
      upstreamReadiness.resolve(false);
      secretRead.resolve(undefined);
      contextProjection.resolve(undefined);
      UpstreamRuntime.prototype.initialize = originalInitialize;
      vscode.commands.registerCommand = originalRegisterCommand;
      vscode.commands.executeCommand = originalExecuteCommand;
      await extensionModule.deactivate();
      assertCredentialAndAiInactivity();
    }
  });

  test("same-context reactivation owns exactly 64 callbacks and rolls back late failure", async () => {
    const extensionModule = require("../extension");
    const expected = new Set([
      ...PRODUCT_MANIFEST.contributes.commands.map(entry => entry.command),
      "cloudsmith-vsc.scanDependenciesPending",
      "cloudsmith-vsc.scanDependenciesComplete",
      "cloudsmith-vsc.rescanDependencies",
      "cloudsmith-vsc.cycleDepViewDirect",
      "cloudsmith-vsc.cycleDepViewFlat",
      "cloudsmith-vsc.cycleDepViewTree",
      "cloudsmith-vsc.depSortFilterActive",
    ]);
    assert.strictEqual(expected.size, 64);

    const originalRegisterCommand = vscode.commands.registerCommand;
    const restoreHostResources = installOwnedHostResourceFakes();
    const active = new Map();
    const registrations = [];
    let generation = 0;
    let failId = null;
    const credentialReadSnapshots = [];
    const context = createActivationContext(PRODUCT_ROOT, () => {
      credentialReadSnapshots.push({
        filters: filterState.activeFilters.size,
        recent: recentPackages.getAll().length,
      });
    });
    vscode.commands.registerCommand = (id, handler) => {
      if (failId === id) throw new Error("late registrar failure");
      assert.ok(expected.has(id), `Unexpected product command ${id}`);
      assert.strictEqual(active.has(id), false, `Duplicate active command ${id}`);
      const registration = { disposed: false, generation, handler, id };
      registrations.push(registration);
      active.set(id, registration);
      return {
        dispose() {
          if (registration.disposed) return;
          registration.disposed = true;
          if (active.get(id) === registration) active.delete(id);
        },
      };
    };

    try {
      filterState.activeFilters.set("stale/repo", { query: "name:stale" });
      recentPackages.add(createExactPackage({
        workspace: "stale",
        repository: "repo",
        packageIdentifier: "package-1",
        name: "widget",
        version: "1.0.0",
        format: "python",
      }));

      generation = 1;
      await extensionModule.activate(context);
      assertCredentialAndAiInactivity();
      const first = registrations.filter(entry => entry.generation === 1);
      assert.strictEqual(first.length, 64);
      assert.strictEqual(active.size, 64);
      await new Promise(resolve => setImmediate(resolve));
      assert.deepStrictEqual(credentialReadSnapshots[0], { filters: 0, recent: 0 });

      generation = 2;
      await extensionModule.activate(context);
      assertCredentialAndAiInactivity();
      const second = registrations.filter(entry => entry.generation === 2);
      assert.strictEqual(second.length, 64);
      assert.strictEqual(active.size, 64);
      assert.ok(first.every(entry => entry.disposed));
      for (const entry of second) {
        assert.strictEqual(active.get(entry.id), entry);
      }

      await extensionModule.deactivate();
      assertCredentialAndAiInactivity();
      assert.strictEqual(active.size, 0);
      assert.ok(second.every(entry => entry.disposed));

      generation = 3;
      failId = "cloudsmith-vsc.previewUpstreamResolution";
      await assert.rejects(extensionModule.activate(context), /late registrar failure/);
      assertCredentialAndAiInactivity();
      const failed = registrations.filter(entry => entry.generation === 3);
      assert.strictEqual(failed.length, 63);
      assert.ok(failed.every(entry => entry.disposed));
      assert.strictEqual(active.size, 0);
    } finally {
      failId = null;
      try {
        await extensionModule.deactivate();
      } finally {
        vscode.commands.registerCommand = originalRegisterCommand;
        restoreHostResources();
        filterState.clear();
        recentPackages.clear();
      }
      assertCredentialAndAiInactivity();
    }
  });

  test("credential and AI inactivity assertions fail closed on hostile host state", () => {
    const safeConfiguration = {
      get(key) { return key === "disableAIFeatures"; },
    };
    assert.throws(
      () => assertCredentialAndAiInactivity({
        extensions: [{ id: "vscode.github-authentication", isActive: true }],
        getChatConfiguration: () => safeConfiguration,
      }),
      /must remain inactive/u
    );
    assert.throws(
      () => assertCredentialAndAiInactivity({
        extensions: [{
          id: "vendor.renamed-ai-provider",
          isActive: true,
          packageJSON: { contributes: { languageModelTools: [{ name: "fixture" }] } },
        }],
        getChatConfiguration: () => safeConfiguration,
      }),
      /must remain inactive/u
    );
    assert.throws(
      () => assertCredentialAndAiInactivity({
        extensions: [],
        getChatConfiguration: () => ({ get: () => true }),
      }),
      /false/u
    );
  });
});

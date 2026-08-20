// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const path = require("path");
const vscode = require("vscode");
const filterState = require("../util/filterState");
const recentPackages = require("../util/recentPackages");
const { createExactPackage } = require("../domain/package");
const { UpstreamRuntime } = require("../util/upstreamRuntime");

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

suite("Extension activation smoke", () => {
  test("activates on the intended VS Code runtime and registers contributed commands", async () => {
    const expectedVersion = process.env.EXPECTED_VSCODE_VERSION;
    assert.match(expectedVersion || "", /^\d+\.\d+\.\d+$/);
    assert.strictEqual(vscode.version, expectedVersion);

    const extension = vscode.extensions.getExtension("Cloudsmith.cloudsmith-vsc");
    assert.ok(extension, "Cloudsmith.cloudsmith-vsc was not loaded as the development extension");

    const activationStartedAt = performance.now();
    await Promise.race([
      extension.activate(),
      new Promise((_resolve, reject) => setTimeout(
        () => reject(new Error("real Extension Host activation exceeded three seconds")),
        3000
      )),
    ]);
    assert.ok(performance.now() - activationStartedAt < 3000);
    assert.strictEqual(extension.isActive, true);

    const contributedCommands = (extension.packageJSON.contributes?.commands || [])
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
    await vscode.commands.executeCommand("cloudsmith-vsc.openSettings");

    const viewIds = (extension.packageJSON.contributes?.views?.cloudsmithSideBar || [])
      .map((entry) => entry.id);
    assert.deepStrictEqual(
      viewIds,
      ["cloudsmithView", "cloudsmithSearchView", "cloudsmithDependencyHealthView", "helpView"]
    );
    for (const viewId of viewIds) {
      assert.ok(
        registeredCommands.has(`${viewId}.focus`),
        `Expected VS Code to initialize the ${viewId} view contribution`
      );
    }
  });

  test("deactivation disposes registered commands and is idempotent", async () => {
    const extension = vscode.extensions.getExtension("Cloudsmith.cloudsmith-vsc");
    assert.ok(extension?.isActive, "The extension must be active before deactivation is exercised");
    assert.ok((await vscode.commands.getCommands(true)).includes("cloudsmith-vsc.refreshView"));

    const { deactivate } = require("../extension");
    await deactivate();
    await deactivate();

    assert.ok(
      !(await vscode.commands.getCommands(true)).includes("cloudsmith-vsc.refreshView"),
      "Deactivation must dispose command registrations owned by activation"
    );
  });

  test("registers commands and returns before held background readiness", async () => {
    const extension = vscode.extensions.getExtension("Cloudsmith.cloudsmith-vsc");
    const extensionModule = require("../extension");
    await extensionModule.deactivate();
    const upstreamReadiness = deferred();
    const secretRead = deferred();
    const contextProjection = deferred();
    let upstreamStarted = false;
    let secretReadStarted = false;
    let contextProjectionStarted = false;
    let commandsAtFirstContextProjection = null;
    const activationRegistrations = new Set();
    const context = createActivationContext(extension.extensionPath, () => {});
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

      const deactivationStartedAt = performance.now();
      await extensionModule.deactivate();
      assert.ok(performance.now() - deactivationStartedAt < 250);
    } finally {
      upstreamReadiness.resolve(false);
      secretRead.resolve(undefined);
      contextProjection.resolve(undefined);
      UpstreamRuntime.prototype.initialize = originalInitialize;
      vscode.commands.registerCommand = originalRegisterCommand;
      vscode.commands.executeCommand = originalExecuteCommand;
      await extensionModule.deactivate();
    }
  });

  test("same-context reactivation owns exactly 64 callbacks and rolls back late failure", async () => {
    const extension = vscode.extensions.getExtension("Cloudsmith.cloudsmith-vsc");
    const extensionModule = require("../extension");
    const expected = new Set([
      ...extension.packageJSON.contributes.commands.map(entry => entry.command),
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
    const active = new Map();
    const registrations = [];
    let generation = 0;
    let failId = null;
    const credentialReadSnapshots = [];
    const context = createActivationContext(extension.extensionPath, () => {
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
      const first = registrations.filter(entry => entry.generation === 1);
      assert.strictEqual(first.length, 64);
      assert.strictEqual(active.size, 64);
      await new Promise(resolve => setImmediate(resolve));
      assert.deepStrictEqual(credentialReadSnapshots[0], { filters: 0, recent: 0 });

      generation = 2;
      await extensionModule.activate(context);
      const second = registrations.filter(entry => entry.generation === 2);
      assert.strictEqual(second.length, 64);
      assert.strictEqual(active.size, 64);
      assert.ok(first.every(entry => entry.disposed));
      for (const entry of second) {
        assert.strictEqual(active.get(entry.id), entry);
      }

      await extensionModule.deactivate();
      assert.strictEqual(active.size, 0);
      assert.ok(second.every(entry => entry.disposed));

      generation = 3;
      failId = "cloudsmith-vsc.previewUpstreamResolution";
      await assert.rejects(extensionModule.activate(context), /late registrar failure/);
      const failed = registrations.filter(entry => entry.generation === 3);
      assert.strictEqual(failed.length, 63);
      assert.ok(failed.every(entry => entry.disposed));
      assert.strictEqual(active.size, 0);
    } finally {
      failId = null;
      await extensionModule.deactivate();
      vscode.commands.registerCommand = originalRegisterCommand;
      filterState.clear();
      recentPackages.clear();
    }
  });
});

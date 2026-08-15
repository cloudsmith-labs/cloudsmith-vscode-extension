// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const path = require("path");
const vscode = require("vscode");
const filterState = require("../util/filterState");
const recentPackages = require("../util/recentPackages");
const { createExactPackage } = require("../domain/package");
const { UpstreamRuntime } = require("../util/upstreamRuntime");

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

    await extension.activate();
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

  test("owns one runtime and settles its initial cache purge before credential access", async () => {
    const extension = vscode.extensions.getExtension("Cloudsmith.cloudsmith-vsc");
    const extensionModule = require("../extension");
    await extensionModule.deactivate();

    const cacheKey = "cloudsmith-upstreams:v5:activation-order";
    const events = [];
    const initialized = [];
    const disposed = [];
    let cacheAtCredentialRead = "unread";
    let resolveCredentialRead;
    const credentialRead = new Promise(resolve => { resolveCredentialRead = resolve; });
    let context;
    context = createActivationContext(extension.extensionPath, () => {
      cacheAtCredentialRead = context.globalState.get(cacheKey);
      events.push("credential-read");
      resolveCredentialRead();
    });
    await context.globalState.update(cacheKey, { accountEpoch: 1 });

    const originalInitialize = UpstreamRuntime.prototype.initialize;
    const originalDispose = UpstreamRuntime.prototype.dispose;
    UpstreamRuntime.prototype.initialize = async function (...args) {
      initialized.push(this);
      events.push("runtime-initialize-start");
      const result = await originalInitialize.apply(this, args);
      events.push("runtime-initialize-settled");
      return result;
    };
    UpstreamRuntime.prototype.dispose = function (...args) {
      disposed.push(this);
      events.push("runtime-dispose");
      return originalDispose.apply(this, args);
    };

    try {
      await extensionModule.activate(context);
      await credentialRead;

      assert.strictEqual(initialized.length, 1);
      assert.strictEqual(cacheAtCredentialRead, undefined);
      assert.ok(
        events.indexOf("runtime-initialize-settled") < events.indexOf("credential-read"),
        "Runtime initialization must settle before ConnectionManager reads SecretStorage"
      );

      await extensionModule.deactivate();
      await extensionModule.deactivate();
      assert.deepStrictEqual(disposed, initialized);
    } finally {
      await extensionModule.deactivate();
      UpstreamRuntime.prototype.initialize = originalInitialize;
      UpstreamRuntime.prototype.dispose = originalDispose;
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

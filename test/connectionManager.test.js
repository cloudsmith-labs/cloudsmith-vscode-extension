const assert = require("assert");
const vscode = require("vscode");
const { ConnectionManager } = require("../util/connectionManager");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");

suite("ConnectionManager Test Suite", () => {
  let originalShowWarningMessage;
  let originalExecuteCommand;
  let warningCalls;
  let commandCalls;
  let originalApiGet;

  const context = {
    secrets: {
      async get() {
        return null;
      },
      async store() {},
    },
  };

  setup(() => {
    warningCalls = [];
    commandCalls = [];

    originalShowWarningMessage = vscode.window.showWarningMessage;
    originalExecuteCommand = vscode.commands.executeCommand;
    originalApiGet = CloudsmithAPI.prototype.get;

    vscode.window.showWarningMessage = async (...args) => {
      warningCalls.push(args);
      return undefined;
    };
    vscode.commands.executeCommand = async (...args) => {
      commandCalls.push(args);
    };
  });

  teardown(() => {
    vscode.window.showWarningMessage = originalShowWarningMessage;
    vscode.commands.executeCommand = originalExecuteCommand;
    CloudsmithAPI.prototype.get = originalApiGet;
  });

  test("connect() warns for missing credentials in interactive flows", async () => {
    const manager = new ConnectionManager(context);

    const status = await manager.connect();

    assert.strictEqual(status, "false");
    assert.strictEqual(warningCalls.length, 1);
    assert.strictEqual(warningCalls[0][0], "No credentials configured!");
    assert.deepStrictEqual(commandCalls, [
      ["setContext", "cloudsmith.connected", false],
    ]);
  });

  test("connect() can skip the missing credentials warning for non-interactive flows", async () => {
    const manager = new ConnectionManager(context);

    const status = await manager.connect({ promptOnMissingCredentials: false });

    assert.strictEqual(status, "false");
    assert.strictEqual(warningCalls.length, 0);
    assert.deepStrictEqual(commandCalls, [
      ["setContext", "cloudsmith.connected", false],
    ]);
  });

  test("checkConnectivity handles authenticated, negative, and typed failure responses", async () => {
    const stored = [];
    const connectivityContext = {
      secrets: {
        async get() { return null; },
        async store(key, value) { stored.push([key, value]); },
      },
    };
    const manager = new ConnectionManager(connectivityContext);

    CloudsmithAPI.prototype.get = async (_endpoint, options) => {
      assert.strictEqual(options.apiKey, "candidate-key");
      return apiSuccess({ authenticated: true });
    };
    assert.strictEqual(await manager.checkConnectivity("candidate-key"), "true");

    CloudsmithAPI.prototype.get = async () => apiSuccess({ authenticated: false });
    assert.strictEqual(await manager.checkConnectivity("candidate-key"), "false");

    CloudsmithAPI.prototype.get = async () => apiFailure("unauthorized", {
      status: 401,
      message: "Authentication failed. Check the API key.",
    });
    assert.strictEqual(await manager.checkConnectivity("candidate-key"), "error");
    assert.strictEqual(manager._lastError.kind, "unauthorized");

    CloudsmithAPI.prototype.get = async () => apiFailure("invalid_response", {
      status: 200,
      message: "Cloudsmith returned an unexpected response.",
    });
    assert.strictEqual(await manager.checkConnectivity("candidate-key"), "error");
    assert.strictEqual(manager._lastError.kind, "invalid_response");
    assert.deepStrictEqual(stored.map(([, value]) => value), ["true", "false", "error", "error"]);
  });
});

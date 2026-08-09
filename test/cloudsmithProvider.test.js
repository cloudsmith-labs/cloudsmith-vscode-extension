const assert = require("assert");
const vscode = require("vscode");
const { CloudsmithProvider } = require("../views/cloudsmithProvider");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { ConnectionManager } = require("../util/connectionManager");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");

suite("CloudsmithProvider Test Suite", () => {
  let originalExecuteCommand;
  let originalGetConfiguration;
  let originalShowWarningMessage;
  let commandCalls;
  let warningCalls;
  let defaultWorkspace;
  let treeView;
  let provider;
  let originalApiGet;
  let originalConnect;

  const context = {
    secrets: {
      onDidChange() {},
      async get(key) {
        if (key === "cloudsmith-vsc.isConnected") {
          return "false";
        }
        return null;
      },
      async store() {},
    },
    globalState: {
      get() {
        return undefined;
      },
      async update() {},
    },
  };

  setup(() => {
    commandCalls = [];
    warningCalls = [];
    defaultWorkspace = "";
    treeView = { message: "ready" };
    provider = new CloudsmithProvider(context);
    provider.setTreeView(treeView);

    originalExecuteCommand = vscode.commands.executeCommand;
    originalGetConfiguration = vscode.workspace.getConfiguration;
    originalShowWarningMessage = vscode.window.showWarningMessage;
    originalApiGet = CloudsmithAPI.prototype.get;
    originalConnect = ConnectionManager.prototype.connect;

    vscode.commands.executeCommand = async (...args) => {
      commandCalls.push(args);
    };
    vscode.workspace.getConfiguration = () => ({
      get(key) {
        if (key === "defaultWorkspace") {
          return defaultWorkspace;
        }
        return "";
      },
    });
    vscode.window.showWarningMessage = async (...args) => {
      warningCalls.push(args);
      return undefined;
    };
  });

  teardown(() => {
    vscode.commands.executeCommand = originalExecuteCommand;
    vscode.workspace.getConfiguration = originalGetConfiguration;
    vscode.window.showWarningMessage = originalShowWarningMessage;
    CloudsmithAPI.prototype.get = originalApiGet;
    ConnectionManager.prototype.connect = originalConnect;
  });

  test("silent refresh shows the signed-out root state without warning after credentials are cleared", async () => {
    provider.refresh({ suppressMissingCredentialsWarning: true });

    const nodes = await provider.getChildren();

    assert.strictEqual(warningCalls.length, 0);
    assert.strictEqual(treeView.message, undefined);
    assert.strictEqual(nodes.length, 1);
    assert.strictEqual(nodes[0].getTreeItem().label, "Connect to Cloudsmith");
    assert.ok(
      commandCalls.some((call) => (
        call[0] === "setContext" &&
        call[1] === "cloudsmith.hasMultipleWorkspaces" &&
        call[2] === false
      ))
    );
  });

  test("silent refresh also shows the signed-out state when a default workspace is configured", async () => {
    defaultWorkspace = "workspace-a";
    provider.refresh({ suppressMissingCredentialsWarning: true });

    const nodes = await provider.getChildren();

    assert.strictEqual(warningCalls.length, 0);
    assert.strictEqual(nodes.length, 1);
    assert.strictEqual(nodes[0].getTreeItem().label, "Connect to Cloudsmith");
  });

  test("a malformed workspace payload is an explicit load failure, not an empty workspace list", async () => {
    ConnectionManager.prototype.connect = async () => "true";
    CloudsmithAPI.prototype.get = async (_endpoint, options) => {
      const malformed = [{ name: "Missing stable slug" }];
      assert.strictEqual(options.validate(malformed), false);
      return apiFailure("invalid_response", {
        status: 200,
        message: "Cloudsmith returned an unexpected response.",
      });
    };

    const nodes = await provider.getWorkspaces();

    assert.strictEqual(nodes.length, 1);
    assert.strictEqual(nodes[0].getTreeItem().label, "Could not load workspaces");
    assert.ok(commandCalls.some(call => (
      call[0] === "setContext"
      && call[1] === "cloudsmith.hasMultipleWorkspaces"
      && call[2] === false
    )));
  });

  test("a validated workspace array produces workspace nodes", async () => {
    ConnectionManager.prototype.connect = async () => "true";
    CloudsmithAPI.prototype.get = async (_endpoint, options) => {
      const payload = [{ slug: "workspace-a", name: "Workspace A" }];
      assert.strictEqual(options.validate(payload), true);
      return apiSuccess(payload);
    };

    const nodes = await provider.getWorkspaces();

    assert.strictEqual(nodes.length, 1);
    assert.strictEqual(nodes[0].workspace, "workspace-a");
  });
});

const assert = require("assert");
const { EventEmitter } = require("events");
const vscode = require("vscode");
const { SSOAuthManager } = require("../util/ssoAuthManager");

function deferred() {
  let resolve;
  const promise = new Promise(res => { resolve = res; });
  return { promise, resolve };
}

function createConnectionHarness() {
  const calls = [];
  let current = null;
  let nextId = 0;
  const manager = {
    beginCredentialOperation() {
      const controller = new AbortController();
      current = Object.freeze({ id: ++nextId, controller, signal: controller.signal });
      calls.push(["begin", current.id]);
      return current;
    },
    isOperationCurrent(token) {
      return token === current && !token.signal.aborted;
    },
    cancelCredentialOperation(token) {
      calls.push(["cancel", token.id]);
      if (current === token) token.controller.abort();
      return Object.freeze({ ok: false, status: "cancelled" });
    },
    async replaceCredential(candidate, token) {
      calls.push(["replace", candidate, token.id]);
      return Object.freeze({ ok: true, status: "connected", committed: true });
    },
  };
  return { calls, manager };
}

suite("SSOAuthManager Test Suite", () => {
  let originalShowErrorMessage;
  let originalShowInformationMessage;
  let originalShowWarningMessage;
  let originalCreateTerminal;
  let originalOnDidCloseTerminal;

  setup(() => {
    originalShowErrorMessage = vscode.window.showErrorMessage;
    originalShowInformationMessage = vscode.window.showInformationMessage;
    originalShowWarningMessage = vscode.window.showWarningMessage;
    originalCreateTerminal = vscode.window.createTerminal;
    originalOnDidCloseTerminal = vscode.window.onDidCloseTerminal;
    vscode.window.showErrorMessage = async () => undefined;
    vscode.window.showInformationMessage = async () => undefined;
    vscode.window.showWarningMessage = async () => undefined;
  });

  teardown(() => {
    vscode.window.showErrorMessage = originalShowErrorMessage;
    vscode.window.showInformationMessage = originalShowInformationMessage;
    vscode.window.showWarningMessage = originalShowWarningMessage;
    vscode.window.createTerminal = originalCreateTerminal;
    vscode.window.onDidCloseTerminal = originalOnDidCloseTerminal;
  });

  test("CLI import owns an operation before reading and validates before commit", async () => {
    const read = deferred();
    const { calls, manager: connectionManager } = createConnectionHarness();
    const sso = new SSOAuthManager({}, {
      connectionManager,
      findCLIConfigPath: () => "/tmp/cloudsmith-config.ini",
      readFile: () => {
        calls.push(["read"]);
        return read.promise;
      },
    });

    const pending = sso.importFromCLI();
    assert.deepStrictEqual(calls.slice(0, 2), [["begin", 1], ["read"]]);
    assert.strictEqual(calls.some(call => call[0] === "replace"), false);
    read.resolve("[default]\napi_key = imported-key\n");
    const result = await pending;

    assert.strictEqual(result.ok, true);
    assert.deepStrictEqual(calls.at(-1), ["replace", "imported-key", 1]);
  });

  test("CLI import rejects oversized config before parsing or replacing credentials", async () => {
    const { calls, manager: connectionManager } = createConnectionHarness();
    const messages = [];
    vscode.window.showErrorMessage = async message => { messages.push(message); };
    const sso = new SSOAuthManager({}, {
      connectionManager,
      findCLIConfigPath: () => "/tmp/cloudsmith-config.ini",
      readFile: async () => `api_key=${"x".repeat(70 * 1024)}`,
    });

    const result = await sso.importFromCLI();

    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.error.kind, "config_too_large");
    assert.strictEqual(calls.some(call => call[0] === "replace"), false);
    assert.deepStrictEqual(messages, ["Cloudsmith CLI config is too large to import."]);
  });

  test("CLI read failures never expose infrastructure messages containing credentials", async () => {
    const leaked = "candidate-secret-in-filesystem-error";
    const { manager: connectionManager } = createConnectionHarness();
    const messages = [];
    vscode.window.showErrorMessage = async message => { messages.push(message); };
    const sso = new SSOAuthManager({}, {
      connectionManager,
      findCLIConfigPath: () => "/tmp/cloudsmith-config.ini",
      readFile: async () => { throw new Error(`failed while reading ${leaked}`); },
    });

    const result = await sso.importFromCLI();
    const publicSurface = JSON.stringify({ result, messages });

    assert.strictEqual(result.error.kind, "config_read_failed");
    assert.strictEqual(publicSurface.includes(leaked), false);
  });

  test("a supplied CLI operation is reused", async () => {
    const { calls, manager: connectionManager } = createConnectionHarness();
    const operation = connectionManager.beginCredentialOperation();
    calls.length = 0;
    const sso = new SSOAuthManager({}, {
      connectionManager,
      findCLIConfigPath: () => "/tmp/cloudsmith-config.ini",
      readFile: async () => "api_key=imported-key",
    });

    await sso.importFromCLI(operation);

    assert.strictEqual(calls.some(call => call[0] === "begin"), false);
    assert.deepStrictEqual(calls[0], ["replace", "imported-key", operation.id]);
  });

  test("terminal timeout and close listener are cleaned before cancellation returns", async () => {
    const { manager: connectionManager } = createConnectionHarness();
    const cleared = [];
    let disposed = 0;
    const terminal = { show() {}, sendText() {} };
    vscode.window.createTerminal = () => terminal;
    vscode.window.onDidCloseTerminal = () => ({ dispose: () => { disposed += 1; } });
    vscode.window.showInformationMessage = async () => "Not now";
    const sso = new SSOAuthManager({}, {
      connectionManager,
      setTimeout: (callback) => {
        queueMicrotask(callback);
        return 41;
      },
      clearTimeout: id => cleared.push(id),
    });

    const result = await sso.loginViaTerminal("workspace-a");

    assert.strictEqual(result.status, "cancelled");
    assert.deepStrictEqual(cleared, [41]);
    assert.strictEqual(disposed, 1);
  });

  test("workspace slugs at the maximum length are accepted", () => {
    const { manager: connectionManager } = createConnectionHarness();
    const sso = new SSOAuthManager({}, { connectionManager });

    assert.strictEqual(sso._isValidWorkspaceSlug("w".repeat(128)), true);
  });

  test("over-limit workspace slugs are rejected before terminal or browser resources start", async () => {
    const { calls, manager: connectionManager } = createConnectionHarness();
    let terminalsCreated = 0;
    let serversCreated = 0;
    let browserOpens = 0;
    vscode.window.createTerminal = () => {
      terminalsCreated += 1;
      throw new Error("must not create a terminal");
    };
    const sso = new SSOAuthManager({}, {
      connectionManager,
      createServer: () => {
        serversCreated += 1;
        throw new Error("must not create a callback server");
      },
      openExternal: async () => { browserOpens += 1; },
    });
    const overLimitSlug = "w".repeat(129);

    const terminalResult = await sso.loginViaTerminal(overLimitSlug);
    const browserResult = await sso.loginViaBrowser(overLimitSlug);

    assert.strictEqual(terminalResult.error.kind, "invalid_workspace");
    assert.strictEqual(browserResult.error.kind, "invalid_workspace");
    assert.strictEqual(terminalsCreated, 0);
    assert.strictEqual(serversCreated, 0);
    assert.strictEqual(browserOpens, 0);
    assert.strictEqual(calls.filter(call => call[0] === "cancel").length, 2);
  });

  test("browser success routes the callback candidate through the shared manager and closes the server", async () => {
    const { calls, manager: connectionManager } = createConnectionHarness();
    let requestHandler = null;
    let server = null;
    const cleared = [];
    const createServer = handler => {
      requestHandler = handler;
      server = Object.assign(new EventEmitter(), {
        closed: false,
        listen(_port, _host, callback) { callback(); },
        close() { this.closed = true; },
      });
      return server;
    };
    const sso = new SSOAuthManager({}, {
      connectionManager,
      createServer,
      randomBytes: () => Buffer.from("00112233445566778899aabbccddeeff", "hex"),
      setTimeout: () => 73,
      clearTimeout: id => cleared.push(id),
      openExternal: async () => {
        const response = { writeHead() {}, end() {} };
        requestHandler({ method: "GET", url: `${server._expectedPath}?token=browser-key` }, response);
      },
    });

    const result = await sso.loginViaBrowser("workspace-a");

    assert.strictEqual(result.ok, true);
    assert.ok(calls.some(call => call[0] === "replace" && call[1] === "browser-key"));
    assert.strictEqual(server.closed, true);
    assert.deepStrictEqual(cleared, [73]);
  });

  test("browser-open failure still closes the callback server", async () => {
    const { manager: connectionManager } = createConnectionHarness();
    let server = null;
    const createServer = () => {
      server = Object.assign(new EventEmitter(), {
        closed: false,
        listen(_port, _host, callback) { callback(); },
        close() { this.closed = true; },
      });
      return server;
    };
    const sso = new SSOAuthManager({}, {
      connectionManager,
      createServer,
      openExternal: async () => { throw new Error("browser unavailable"); },
      setTimeout: () => 19,
      clearTimeout: () => {},
    });

    const result = await sso.loginViaBrowser("workspace-a");

    assert.strictEqual(result.ok, false);
    assert.strictEqual(server.closed, true);
  });

  test("duplicate callback parameters are rejected as ambiguous", () => {
    const { manager: connectionManager } = createConnectionHarness();
    const sso = new SSOAuthManager({}, { connectionManager });
    let resolved = "not-called";
    const server = {
      _expectedPath: "/callback/id",
      _resolveToken(value) { resolved = value; },
    };
    const response = { writeHead() {}, end() {} };

    sso._handleCallbackRequest(
      { method: "GET", url: "/callback/id?token=first&token=second" },
      response,
      server
    );

    assert.strictEqual(resolved, null);
  });

  test("callback HTML reports receipt without claiming authentication succeeded", () => {
    const { manager: connectionManager } = createConnectionHarness();
    const sso = new SSOAuthManager({}, { connectionManager });

    const html = sso._buildCallbackHtml(true, "/authenticated");

    assert.ok(html.includes("Credentials received"));
    assert.ok(html.includes("validated and saved"));
    assert.strictEqual(html.includes("Authentication complete"), false);
  });
});

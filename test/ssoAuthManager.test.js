const assert = require("assert");
const { EventEmitter } = require("events");
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
  const createController = () => {
    let aborted = false;
    const listeners = new Set();
    const signal = {
      get aborted() { return aborted; },
      addEventListener(event, listener) {
        if (event === "abort") listeners.add(listener);
      },
      removeEventListener(event, listener) {
        if (event === "abort") listeners.delete(listener);
      },
    };
    return {
      signal,
      abort() {
        if (aborted) return;
        aborted = true;
        for (const listener of [...listeners]) listener();
      },
      get listenerCount() { return listeners.size; },
    };
  };
  const manager = {
    beginCredentialOperation() {
      const controller = createController();
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
  return {
    calls,
    manager,
    cancelCurrent() {
      if (current) current.controller.abort();
    },
    get abortListenerCount() {
      return current ? current.controller.listenerCount : 0;
    },
  };
}

function createManualTimers() {
  let nextId = 0;
  const pending = new Map();
  const cleared = [];
  return {
    setTimeout(callback, delay) {
      const handle = ++nextId;
      pending.set(handle, { callback, delay });
      return handle;
    },
    clearTimeout(handle) {
      if (pending.delete(handle)) cleared.push(handle);
    },
    fire(handle) {
      const timer = pending.get(handle);
      assert.ok(timer, `expected timer ${handle} to be pending`);
      pending.delete(handle);
      timer.callback();
    },
    firstHandle() {
      return pending.keys().next().value;
    },
    get pendingCount() { return pending.size; },
    get clearedHandles() { return cleared.slice(); },
  };
}

function createTerminalEvents() {
  const listeners = new Set();
  let disposals = 0;
  return {
    onDidCloseTerminal(listener) {
      listeners.add(listener);
      return {
        dispose() {
          if (listeners.delete(listener)) disposals += 1;
        },
      };
    },
    close(terminal) {
      for (const listener of [...listeners]) listener(terminal);
    },
    get listenerCount() { return listeners.size; },
    get disposalCount() { return disposals; },
  };
}

function createManager(connectionManager, options = {}) {
  return new SSOAuthManager({}, {
    connectionManager,
    showErrorMessage: async () => undefined,
    showInformationMessage: async () => undefined,
    showWarningMessage: async () => undefined,
    createTerminal: () => ({ show() {}, sendText() {} }),
    onDidCloseTerminal: () => ({ dispose() {} }),
    ...options,
  });
}

suite("SSOAuthManager Test Suite", () => {

  test("CLI import owns an operation before reading and validates before commit", async () => {
    const read = deferred();
    const { calls, manager: connectionManager } = createConnectionHarness();
    const sso = createManager(connectionManager, {
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
    const sso = createManager(connectionManager, {
      showErrorMessage: async message => { messages.push(message); },
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
    const sso = createManager(connectionManager, {
      showErrorMessage: async message => { messages.push(message); },
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
    const sso = createManager(connectionManager, {
      findCLIConfigPath: () => "/tmp/cloudsmith-config.ini",
      readFile: async () => "api_key=imported-key",
    });

    await sso.importFromCLI(operation);

    assert.strictEqual(calls.some(call => call[0] === "begin"), false);
    assert.deepStrictEqual(calls[0], ["replace", "imported-key", operation.id]);
  });

  test("terminal timeout and close listener are cleaned before cancellation returns", async () => {
    const connection = createConnectionHarness();
    const timers = createManualTimers();
    const terminalEvents = createTerminalEvents();
    const terminal = { show() {}, sendText() {} };
    const sso = createManager(connection.manager, {
      createTerminal: () => terminal,
      onDidCloseTerminal: listener => terminalEvents.onDidCloseTerminal(listener),
      showInformationMessage: async () => "Not now",
      setTimeout: timers.setTimeout,
      clearTimeout: timers.clearTimeout,
    });

    const pending = sso.loginViaTerminal("workspace-a");
    const handle = timers.firstHandle();
    assert.strictEqual(terminalEvents.listenerCount, 1);
    assert.strictEqual(connection.abortListenerCount, 1);
    timers.fire(handle);
    const result = await pending;

    assert.strictEqual(result.status, "cancelled");
    assert.strictEqual(timers.pendingCount, 0);
    assert.strictEqual(terminalEvents.listenerCount, 0);
    assert.strictEqual(terminalEvents.disposalCount, 1);
    assert.strictEqual(connection.abortListenerCount, 0);
  });

  test("terminal close wins without waiting for the timeout and releases every listener", async () => {
    const connection = createConnectionHarness();
    const timers = createManualTimers();
    const terminalEvents = createTerminalEvents();
    const terminal = { show() {}, sendText() {} };
    const sso = createManager(connection.manager, {
      createTerminal: () => terminal,
      onDidCloseTerminal: listener => terminalEvents.onDidCloseTerminal(listener),
      showInformationMessage: async () => "Not now",
      setTimeout: timers.setTimeout,
      clearTimeout: timers.clearTimeout,
    });

    const pending = sso.loginViaTerminal("workspace-a");
    const timeoutHandle = timers.firstHandle();
    terminalEvents.close(terminal);
    const result = await pending;

    assert.strictEqual(result.status, "cancelled");
    assert.deepStrictEqual(timers.clearedHandles, [timeoutHandle]);
    assert.strictEqual(timers.pendingCount, 0);
    assert.strictEqual(terminalEvents.listenerCount, 0);
    assert.strictEqual(connection.abortListenerCount, 0);
  });

  test("credential operation cancellation ends the terminal wait and cleans resources", async () => {
    const connection = createConnectionHarness();
    const timers = createManualTimers();
    const terminalEvents = createTerminalEvents();
    const sso = createManager(connection.manager, {
      onDidCloseTerminal: listener => terminalEvents.onDidCloseTerminal(listener),
      setTimeout: timers.setTimeout,
      clearTimeout: timers.clearTimeout,
    });

    const pending = sso.loginViaTerminal("workspace-a");
    const timeoutHandle = timers.firstHandle();
    connection.cancelCurrent();
    const result = await pending;

    assert.strictEqual(result.error.kind, "stale");
    assert.deepStrictEqual(timers.clearedHandles, [timeoutHandle]);
    assert.strictEqual(timers.pendingCount, 0);
    assert.strictEqual(terminalEvents.listenerCount, 0);
    assert.strictEqual(connection.abortListenerCount, 0);
  });

  test("workspace slugs at the maximum length are accepted", () => {
    const { manager: connectionManager } = createConnectionHarness();
    const sso = createManager(connectionManager);

    assert.strictEqual(sso.isValidWorkspaceSlug("w".repeat(128)), true);
  });

  test("over-limit workspace slugs are rejected before terminal or browser resources start", async () => {
    const { calls, manager: connectionManager } = createConnectionHarness();
    let terminalsCreated = 0;
    let serversCreated = 0;
    let browserOpens = 0;
    const sso = createManager(connectionManager, {
      createTerminal: () => {
        terminalsCreated += 1;
        throw new Error("must not create a terminal");
      },
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
    const connection = createConnectionHarness();
    const timers = createManualTimers();
    let requestHandler = null;
    let server = null;
    const createServer = handler => {
      requestHandler = handler;
      server = Object.assign(new EventEmitter(), {
        closed: false,
        listen(_port, _host, callback) { callback(); },
        close() { this.closed = true; },
      });
      return server;
    };
    const sso = createManager(connection.manager, {
      createServer,
      randomBytes: () => Buffer.from("00112233445566778899aabbccddeeff", "hex"),
      setTimeout: timers.setTimeout,
      clearTimeout: timers.clearTimeout,
      openExternal: async () => {
        const response = { writeHead() {}, end() {} };
        requestHandler({ method: "GET", url: `${server._expectedPath}?token=browser-key` }, response);
      },
    });

    const result = await sso.loginViaBrowser("workspace-a");

    assert.strictEqual(result.ok, true);
    assert.ok(connection.calls.some(call => call[0] === "replace" && call[1] === "browser-key"));
    assert.strictEqual(server.closed, true);
    assert.strictEqual(server._resolveToken, null);
    assert.strictEqual(timers.pendingCount, 0);
    assert.strictEqual(connection.abortListenerCount, 0);
  });

  test("browser-open failure still closes the callback server", async () => {
    let server = null;
    const createServer = () => {
      server = Object.assign(new EventEmitter(), {
        closed: false,
        listen(_port, _host, callback) { callback(); },
        close() { this.closed = true; },
      });
      return server;
    };
    const connection = createConnectionHarness();
    const timers = createManualTimers();
    const sso = createManager(connection.manager, {
      createServer,
      openExternal: async () => { throw new Error("browser unavailable"); },
      setTimeout: timers.setTimeout,
      clearTimeout: timers.clearTimeout,
    });

    const result = await sso.loginViaBrowser("workspace-a");

    assert.strictEqual(result.ok, false);
    assert.strictEqual(server.closed, true);
    assert.strictEqual(server._resolveToken, null);
    assert.strictEqual(timers.pendingCount, 0);
    assert.strictEqual(connection.abortListenerCount, 0);
  });

  test("duplicate callback parameters are rejected as ambiguous", () => {
    const { manager: connectionManager } = createConnectionHarness();
    const sso = createManager(connectionManager);
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
    const sso = createManager(connectionManager);

    const html = sso._buildCallbackHtml(true, "/authenticated");

    assert.ok(html.includes("Credentials received"));
    assert.ok(html.includes("validated and saved"));
    assert.strictEqual(html.includes("Authentication complete"), false);
  });
});

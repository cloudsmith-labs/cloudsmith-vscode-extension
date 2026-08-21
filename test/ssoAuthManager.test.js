const assert = require("assert");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");
const { createSSODiagnosticObserver } = require("../util/ssoDiagnostics");
const {
  SSOAuthManager,
  cliCredentialCandidates,
  parseDefaultAPIKey,
  readTrustedCredentialFile,
} = require("../util/ssoAuthManager");

function createManager() {
  let counter = 0;
  let current = null;
  const calls = [];
  return {
    calls,
    beginCredentialOperation() {
      const controller = new AbortController();
      current = { id: ++counter, controller, signal: controller.signal };
      calls.push(["begin", counter]);
      return current;
    },
    isOperationCurrent(operation) {
      return operation === current && !operation.signal.aborted;
    },
    async cancelCredentialOperation(operation) {
      if (operation === current) {
        operation.controller.abort();
        current = null;
      }
      calls.push(["cancel", operation.id]);
      return { ok: false, status: "cancelled" };
    },
    async replaceCredential(candidate, operation, options = {}) {
      calls.push(["replace", candidate, operation.id, options]);
      if (options.beforeCommit && !await options.beforeCommit("user-slug")) {
        return { ok: false, status: "cancelled" };
      }
      current = null;
      return { ok: true, status: "connected", committed: true };
    },
  };
}

function requestCallback(target, host = "127.0.0.1") {
  return new Promise((resolve, reject) => {
    const authority = host.includes(":") ? `[${host}]` : host;
    const request = http.get(`http://${authority}:12400${target}`, response => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", chunk => { body += chunk; });
      response.on("end", () => resolve({ body, headers: response.headers, status: response.statusCode }));
    });
    request.on("error", reject);
  });
}

suite("SSOAuthManager", () => {
  test("classifies discovery failures without the generic browser fallback", async () => {
    const messages = [];
    const manager = createManager();
    const sso = new SSOAuthManager({}, {
      callbackHosts: ["127.0.0.1"],
      connectionManager: manager,
      protocolClient: { async discover() { return { ok: false, kind: "network_error" }; } },
      showErrorMessage(message) { messages.push(message); },
    });

    const result = await sso.loginViaBrowser("workspace");

    assert.strictEqual(result.error.kind, "discovery_network_error");
    assert.deepStrictEqual(messages, [
      "Could not start SSO for that workspace. Check the network connection and try again.",
    ]);
  });

  test("classifies an unavailable workspace discovery response before browser launch", async () => {
    const messages = [];
    let browserOpens = 0;
    const manager = createManager();
    const sso = new SSOAuthManager({}, {
      callbackHosts: ["127.0.0.1"],
      connectionManager: manager,
      openExternal: async () => { browserOpens += 1; return true; },
      protocolClient: { async discover() { return { ok: false, kind: "http_error", status: 404 }; } },
      showErrorMessage(message) { messages.push(message); },
    });

    const result = await sso.loginViaBrowser("workspace");

    assert.strictEqual(result.error.kind, "discovery_http_error");
    assert.strictEqual(browserOpens, 0);
    assert.deepStrictEqual(messages, ["Could not start SSO for that workspace. Try again."]);
  });

  test("records invalid callback token shape without emitting the token value", () => {
    const lines = [];
    const marker = "synthetic:secret:marker";
    const sso = new SSOAuthManager({}, {
      connectionManager: createManager(),
      diagnosticObserver: createSSODiagnosticObserver({ appendLine(line) { lines.push(line); } }),
    });
    let status = null;
    sso._handleCallbackRequest(
      {
        method: "GET",
        url: `/?access_token=${encodeURIComponent(marker)}&refresh_token=refresh-token`,
        headers: {},
        socket: { localAddress: "127.0.0.1" },
      },
      { writeHead(value) { status = value; }, end() {} },
      () => true
    );

    assert.strictEqual(status, 400);
    const output = lines.join("\n");
    assert.strictEqual(output.includes(marker), false);
    assert.match(output, /"errorKind":"callback_invalid_token"/);
    assert.match(output, /"parameterNames":\["access_token","refresh_token"\]/);
    assert.match(output, /"tokenLength":23/);
  });

  test("rejects an unknown callback field without recording its attacker-controlled name", () => {
    const lines = [];
    const sso = new SSOAuthManager({}, {
      connectionManager: createManager(),
      diagnosticObserver: createSSODiagnosticObserver({ appendLine(line) { lines.push(line); } }),
    });
    let status = null;
    sso._handleCallbackRequest(
      {
        method: "GET",
        url: "/?csa_secret_key=value",
        headers: {},
        socket: { localAddress: "127.0.0.1" },
      },
      { writeHead(value) { status = value; }, end() {} },
      () => true
    );

    assert.strictEqual(status, 400);
    const output = lines.join("\n");
    assert.strictEqual(output.includes("csa_secret_key"), false);
    assert.match(output, /"errorKind":"callback_invalid_fields"/);
    assert.match(output, /"queryPairCount":1/);
  });

  test("uses platform user-level credentials.ini candidates and never cwd/config.ini", () => {
    assert.deepStrictEqual(cliCredentialCandidates("darwin", {}, "/Users/test").map(item => item.file), [
      "/Users/test/Library/Application Support/cloudsmith/credentials.ini",
      "/Users/test/.cloudsmith/credentials.ini",
    ]);
    assert.deepStrictEqual(cliCredentialCandidates("linux", { XDG_CONFIG_HOME: "relative" }, "/home/test").map(item => item.file), [
      "/home/test/.config/cloudsmith/credentials.ini",
      "/home/test/.cloudsmith/credentials.ini",
    ]);
    assert.deepStrictEqual(
      cliCredentialCandidates("win32", { APPDATA: "C:\\Users\\test\\AppData\\Roaming" }, "C:\\Users\\test")
        .map(item => item.file),
      [
        "C:\\Users\\test\\AppData\\Roaming\\cloudsmith\\credentials.ini",
        "C:\\Users\\test\\.cloudsmith\\credentials.ini",
      ]
    );
  });

  test("parses exactly one default API key and rejects ambiguity", () => {
    assert.deepStrictEqual(parseDefaultAPIKey("[profile]\napi_key = ignored\n[default]\napi_key = valid-key\n"), {
      ok: true,
      apiKey: "valid-key",
    });
    assert.strictEqual(parseDefaultAPIKey("[default]\napi_key=a\napi_key=b\n").ok, false);
    assert.strictEqual(parseDefaultAPIKey("[default]\napi_key=a\n[default]\napi_key=a\n").ok, false);
    assert.strictEqual(parseDefaultAPIKey("api_key=a\n").ok, false);
  });

  test("imports an explicit trusted API-key file through normal validation", async () => {
    const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), "cloudsmith-cli-import-"));
    try {
      await fs.promises.mkdir(path.join(root, "cloudsmith"));
      await fs.promises.writeFile(
        path.join(root, "cloudsmith", "credentials.ini"),
        "[default]\napi_key = imported-key\n",
        { encoding: "utf8", mode: 0o600 }
      );
      const manager = createManager();
      const sso = new SSOAuthManager({}, {
        connectionManager: manager,
        platform: "linux",
        env: { XDG_CONFIG_HOME: root },
        home: path.join(root, "home"),
        showErrorMessage() {},
      });
      const result = await sso.importFromCLI();
      assert.strictEqual(result.ok, true);
      assert.strictEqual(manager.calls.at(-1)[0], "replace");
      assert.strictEqual(manager.calls.at(-1)[1], "imported-key");
    } finally {
      await fs.promises.rm(root, { recursive: true, force: true });
    }
  });

  test("continues after a missing trusted candidate and imports the next credentials.ini", async () => {
    const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), "cloudsmith-cli-fallback-"));
    const configRoot = path.join(root, "config");
    const home = path.join(root, "home");
    try {
      await fs.promises.mkdir(path.join(configRoot, "cloudsmith"), { recursive: true });
      await fs.promises.mkdir(path.join(home, ".cloudsmith"), { recursive: true });
      await fs.promises.writeFile(
        path.join(home, ".cloudsmith", "credentials.ini"),
        "[default]\napi_key = fallback-key\n",
        { encoding: "utf8", mode: 0o600 }
      );
      const manager = createManager();
      const sso = new SSOAuthManager({}, {
        connectionManager: manager,
        platform: "linux",
        env: { XDG_CONFIG_HOME: configRoot },
        home,
        showErrorMessage() {},
      });

      const result = await sso.importFromCLI();

      assert.strictEqual(result.ok, true);
      assert.strictEqual(manager.calls.at(-1)[1], "fallback-key");
    } finally {
      await fs.promises.rm(root, { recursive: true, force: true });
    }
  });

  test("rejects symlinked CLI roots and final credential files", async () => {
    const parent = await fs.promises.mkdtemp(path.join(os.tmpdir(), "cloudsmith-cli-symlink-"));
    try {
      const outside = path.join(parent, "outside");
      await fs.promises.mkdir(outside);
      await fs.promises.writeFile(path.join(outside, "credentials.ini"), "[default]\napi_key=outside\n");
      const linkedRoot = path.join(parent, ".cloudsmith");
      await fs.promises.symlink(outside, linkedRoot);
      await assert.rejects(
        readTrustedCredentialFile(linkedRoot, path.join(linkedRoot, "credentials.ini"), fs.promises),
        error => error.code === "UNSAFE_CREDENTIAL_FILE"
      );

      const root = path.join(parent, "config");
      await fs.promises.mkdir(path.join(root, "cloudsmith"), { recursive: true });
      const linkedFile = path.join(root, "cloudsmith", "credentials.ini");
      await fs.promises.symlink(path.join(outside, "credentials.ini"), linkedFile);
      await assert.rejects(
        readTrustedCredentialFile(root, linkedFile, fs.promises),
        error => error.code === "UNSAFE_CREDENTIAL_FILE"
      );
    } finally {
      await fs.promises.rm(parent, { recursive: true, force: true });
    }
  });

  test("rejects oversized or same-size-mutating CLI credential files", async () => {
    const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), "cloudsmith-cli-mutation-"));
    const directory = path.join(root, "cloudsmith");
    const file = path.join(directory, "credentials.ini");
    try {
      await fs.promises.mkdir(directory);
      await fs.promises.writeFile(file, Buffer.alloc(64 * 1024 + 1, 65));
      await assert.rejects(
        readTrustedCredentialFile(root, file, fs.promises),
        error => error.code === "UNSAFE_CREDENTIAL_FILE"
      );

      const first = "[default]\napi_key=first-key\n";
      const second = "[default]\napi_key=other-key\n";
      assert.strictEqual(Buffer.byteLength(first), Buffer.byteLength(second));
      await fs.promises.writeFile(file, first);
      const mutatingFileSystem = Object.create(fs.promises);
      mutatingFileSystem.open = async (...args) => {
        const handle = await fs.promises.open(...args);
        let statCalls = 0;
        return {
          read: handle.read.bind(handle),
          close: handle.close.bind(handle),
          async stat() {
            statCalls += 1;
            if (statCalls === 2) await fs.promises.writeFile(file, second);
            return handle.stat();
          },
        };
      };
      await assert.rejects(
        readTrustedCredentialFile(root, file, mutatingFileSystem),
        error => error.code === "UNSAFE_CREDENTIAL_FILE"
      );
    } finally {
      await fs.promises.rm(root, { recursive: true, force: true });
    }
  });

  test("binds first, opens the exact encoded IdP string, accepts exact tokens, and confirms identity", async () => {
    const manager = createManager();
    const order = [];
    let opened = null;
    let callbackResponse;
    const redirectUrl = "https://idp.customer.example/saml?SAMLRequest=synthetic%2Bvalue%2Fwith%3Dpadding";
    const sso = new SSOAuthManager({}, {
      connectionManager: manager,
      createServer(handler) {
        const server = http.createServer(handler);
        server.on("listening", () => order.push("listen"));
        return server;
      },
      callbackHosts: ["127.0.0.1"],
      protocolClient: {
        async discover(workspace) {
          order.push("discover");
          assert.strictEqual(workspace, "workspace-a");
          return { ok: true, redirectUrl };
        },
      },
      async openExternal(target) {
        opened = target;
        order.push("open");
        callbackResponse = await requestCallback("/?access_token=access-token&refresh_token=refresh-token");
        return true;
      },
      async showInformationMessage(_message, options) {
        return options && options.modal ? "Continue" : undefined;
      },
      showErrorMessage() {},
      randomBytes: size => Buffer.alloc(size, 7),
    });
    const result = await sso.loginViaBrowser("workspace-a");
    assert.strictEqual(result.ok, true);
    assert.deepStrictEqual(order, ["listen", "discover", "open"]);
    assert.strictEqual(typeof opened, "string");
    assert.strictEqual(opened, redirectUrl);
    const replacement = manager.calls.find(call => call[0] === "replace");
    assert.strictEqual(replacement[1].kind, "sso");
    assert.strictEqual(replacement[1].accessToken, "access-token");
    assert.strictEqual(replacement[1].refreshToken, "refresh-token");
    assert.strictEqual(replacement[3].workspaceSlug, "workspace-a");
    assert.strictEqual(callbackResponse.status, 200);
    assert.match(callbackResponse.headers["content-security-policy"], /nonce-/);
    assert.ok(!callbackResponse.body.includes("access-token"));
    assert.ok(!callbackResponse.body.includes("refresh-token"));
    assert.match(callbackResponse.body, /while your session is verified/i);
  });

  test("keeps two-factor data ephemeral and commits only the exchanged pair", async () => {
    const manager = createManager();
    const exchanges = [];
    const sso = new SSOAuthManager({}, {
      connectionManager: manager,
      protocolClient: {
        async discover() { return { ok: true, redirectUrl: "https://idp.example/saml" }; },
        async exchangeTwoFactor(token, code) {
          exchanges.push([token, code]);
          return { ok: true, accessToken: "access-final", refreshToken: "refresh-final" };
        },
      },
      async openExternal() {
        await requestCallback("/?two_factor_token=temporary-two-factor");
        return true;
      },
      async showInputBox() { return "123456"; },
      async showInformationMessage(_message, options) { return options && options.modal ? "Continue" : undefined; },
      showErrorMessage() {},
    });
    const result = await sso.loginViaBrowser("workspace");
    assert.strictEqual(result.ok, true);
    assert.deepStrictEqual(exchanges, [["temporary-two-factor", "123456"]]);
    const candidate = manager.calls.find(call => call[0] === "replace")[1];
    assert.strictEqual(candidate.accessToken, "access-final");
    assert.strictEqual(candidate.refreshToken, "refresh-final");
    assert.ok(!JSON.stringify(candidate).includes("123456"));
    assert.ok(!JSON.stringify(candidate).includes("temporary-two-factor"));
  });

  test("two-factor cancellation, invalid input, exchange rejection, and malformed success never commit", async () => {
    for (const exchangeResult of [
      null,
      { ok: false, kind: "unauthorized" },
      { ok: true, accessToken: "access-without-refresh" },
    ]) {
      const manager = createManager();
      let exchanges = 0;
      const sso = new SSOAuthManager({}, {
        connectionManager: manager,
        protocolClient: {
          async discover() { return { ok: true, redirectUrl: "https://idp.example/saml" }; },
          async exchangeTwoFactor() { exchanges += 1; return exchangeResult; },
        },
        async openExternal() {
          await requestCallback("/?two_factor_token=temporary-two-factor");
          return true;
        },
        async showInputBox(options) {
          assert.ok(options.validateInput("123"));
          assert.strictEqual(options.validateInput("123456"), null);
          return exchangeResult === null ? undefined : "123456";
        },
        showErrorMessage() {},
      });
      const result = await sso.loginViaBrowser("workspace");
      assert.strictEqual(result.ok, false);
      assert.strictEqual(exchanges, exchangeResult === null ? 0 : 1);
      assert.strictEqual(manager.calls.some(call => call[0] === "replace"), false);
    }
  });

  test("rejects duplicate, mixed, alias, and wrong-path callbacks without settling", () => {
    const sso = new SSOAuthManager({}, { connectionManager: createManager() });
    const cases = [
      { url: "/?access_token=a&access_token=b&refresh_token=r" },
      { url: "/?access_token=a&refresh_token=r&error=no" },
      { url: "/?token=a" },
      { url: "/callback?access_token=a&refresh_token=r" },
      { url: "/?access_token=a" },
      { url: "/?refresh_token=r" },
      { url: "/?two_factor_token=t&error=no" },
      { url: "/?access_token=&refresh_token=r" },
      { url: `/?access_token=${"a".repeat(8193)}&refresh_token=r` },
      { url: `/?${Array.from({ length: 9 }, (_, index) => `error=${index}`).join("&")}` },
      { url: `/${"x".repeat(20 * 1024)}?error=no` },
      { url: "/?error=no", method: "POST" },
      { url: "/?error=no", headers: { "content-length": "1" } },
      { url: "/?error=no", headers: { "transfer-encoding": "chunked" } },
    ];
    for (const item of cases) {
      let settled = false;
      let status = null;
      sso._handleCallbackRequest(
        { method: item.method || "GET", url: item.url, headers: item.headers || {} },
        { writeHead(value) { status = value; }, end() {} },
        () => { settled = true; return true; }
      );
      assert.strictEqual(settled, false, item.url);
      assert.ok(status >= 400, item.url);
    }
  });

  test("the first valid callback wins exactly once and later callbacks are inert", () => {
    const sso = new SSOAuthManager({}, { connectionManager: createManager() });
    const outcomes = [];
    const statuses = [];
    const finish = outcome => {
      if (outcomes.length > 0) return false;
      outcomes.push(outcome);
      return true;
    };
    for (const target of [
      "/?access_token=first-access&refresh_token=first-refresh",
      "/?access_token=second-access&refresh_token=second-refresh",
    ]) {
      sso._handleCallbackRequest(
        { method: "GET", url: target, headers: {} },
        { writeHead(value) { statuses.push(value); }, end() {} },
        finish
      );
    }
    assert.deepStrictEqual(outcomes, [{
      kind: "tokens",
      accessToken: "first-access",
      refreshToken: "first-refresh",
    }]);
    assert.deepStrictEqual(statuses, [200, 409]);
  });

  test("a callback port conflict stops before discovery or browser navigation", async () => {
    const blocker = http.createServer((_request, response) => response.end());
    await new Promise(resolve => blocker.listen(12400, "127.0.0.1", resolve));
    try {
      let discovery = 0;
      let opened = 0;
      const sso = new SSOAuthManager({}, {
        connectionManager: createManager(),
        protocolClient: { async discover() { discovery += 1; return { ok: true }; } },
        async openExternal() { opened += 1; return true; },
        showErrorMessage() {},
      });
      const result = await sso.loginViaBrowser("workspace");
      assert.strictEqual(result.error.kind, "port_in_use");
      assert.strictEqual(discovery, 0);
      assert.strictEqual(opened, 0);
    } finally {
      await new Promise(resolve => blocker.close(resolve));
    }
  });

  test("browser-open failure offers one bounded retry without exposing the IdP URL", async () => {
    const manager = createManager();
    const messages = [];
    let opens = 0;
    const sso = new SSOAuthManager({}, {
      connectionManager: manager,
      protocolClient: {
        async discover() { return { ok: true, redirectUrl: "https://idp.example/saml?state=sensitive" }; },
      },
      async openExternal() {
        opens += 1;
        if (opens === 1) return false;
        await requestCallback("/?access_token=retry-access&refresh_token=retry-refresh");
        return true;
      },
      async showErrorMessage(message) {
        messages.push(message);
        return "Retry";
      },
      async showInformationMessage(_message, options) {
        return options && options.modal ? "Continue" : undefined;
      },
    });
    const result = await sso.loginViaBrowser("workspace");
    assert.strictEqual(result.ok, true);
    assert.strictEqual(opens, 2);
    assert.strictEqual(messages.length, 1);
    assert.strictEqual(messages[0].includes("sensitive"), false);
    assert.strictEqual(messages[0].includes("https://"), false);
  });

  test("a runtime callback-server error settles safely and leaves no listener or timer", async () => {
    const manager = createManager();
    let server = null;
    let timerActive = false;
    const sso = new SSOAuthManager({}, {
      connectionManager: manager,
      createServer(handler) {
        server = http.createServer(handler);
        return server;
      },
      callbackHosts: ["127.0.0.1"],
      protocolClient: {
        async discover() { return { ok: true, redirectUrl: "https://idp.example/saml" }; },
      },
      async openExternal() {
        server.emit("error", new Error("runtime listener failure"));
        return true;
      },
      setTimeout() { timerActive = true; return 1; },
      clearTimeout() { timerActive = false; },
      showInformationMessage() {},
      showErrorMessage() {},
    });
    const result = await sso.loginViaBrowser("workspace");
    assert.strictEqual(result.error.kind, "listener_failed");
    assert.strictEqual(timerActive, false);
    assert.strictEqual(server.listenerCount("error"), 0);
    assert.strictEqual(server.listening, false);
    assert.strictEqual(manager.calls.some(call => call[0] === "replace"), false);
  });

  test("a listener failure during discovery prevents identity-provider navigation", async () => {
    let server = null;
    let opened = 0;
    const sso = new SSOAuthManager({}, {
      connectionManager: createManager(),
      createServer(handler) {
        server = http.createServer(handler);
        return server;
      },
      callbackHosts: ["127.0.0.1"],
      protocolClient: {
        async discover() {
          server.emit("error", new Error("runtime listener failure"));
          return { ok: true, redirectUrl: "https://idp.example/saml" };
        },
      },
      async openExternal() { opened += 1; return true; },
      showErrorMessage() {},
    });
    const result = await sso.loginViaBrowser("workspace");
    assert.strictEqual(result.error.kind, "listener_failed");
    assert.strictEqual(opened, 0);
    assert.strictEqual(server.listenerCount("error"), 0);
    assert.strictEqual(server.listening, false);
  });

  test("callback cancellation performs awaited idempotent listener and timer cleanup", async () => {
    let timerActive = false;
    const controller = new AbortController();
    const sso = new SSOAuthManager({}, {
      connectionManager: createManager(),
      setTimeout() { timerActive = true; return 1; },
      clearTimeout() { timerActive = false; },
    });
    const callback = await sso._startCallbackServer(controller.signal);
    controller.abort();
    assert.deepStrictEqual(await callback.outcome, { kind: "cancelled" });
    await callback.close();
    await callback.close();
    assert.strictEqual(timerActive, false);
    assert.strictEqual(callback.server.listenerCount("error"), 0);
    assert.strictEqual(callback.server.listenerCount("connection"), 0);
    assert.strictEqual(callback.server.listening, false);
    assert.ok(callback.servers.every(server => server.listening === false));
  });

  test("advertised localhost callback listens on every supported IP loopback", async () => {
    const controller = new AbortController();
    const sso = new SSOAuthManager({}, { connectionManager: createManager() });
    const callback = await sso._startCallbackServer(controller.signal);
    try {
      const addresses = callback.servers.map(server => server.address()?.address);
      assert.ok(addresses.includes("127.0.0.1"));

      if (addresses.includes("::1")) {
        const ipv6Response = await requestCallback("/?token=unsupported-alias", "::1");
        assert.strictEqual(ipv6Response.status, 400);
      }
      const ipv4Response = await requestCallback(
        "/?access_token=loopback-access&refresh_token=loopback-refresh",
        "127.0.0.1"
      );
      assert.strictEqual(ipv4Response.status, 200);
      assert.deepStrictEqual(await callback.outcome, {
        kind: "tokens",
        accessToken: "loopback-access",
        refreshToken: "loopback-refresh",
      });
    } finally {
      await callback.close();
    }
  });

  test("the advertised localhost callback reaches an actual loopback listener on this host", async () => {
    const controller = new AbortController();
    const sso = new SSOAuthManager({}, { connectionManager: createManager() });
    const callback = await sso._startCallbackServer(controller.signal);
    try {
      const response = await requestCallback("/?token=unsupported-alias", "localhost");
      assert.strictEqual(response.status, 400);
      assert.strictEqual(callback.getSettledOutcome(), null);
    } finally {
      await callback.close();
    }
  });

  test("continues on deterministic unsupported IPv6 and keeps IPv4 usable", async () => {
    const controller = new AbortController();
    const created = [];
    const sso = new SSOAuthManager({}, {
      connectionManager: createManager(),
      createServer(handler) {
        const server = http.createServer(handler);
        created.push(server);
        if (created.length === 2) {
          server.listen = () => {
            queueMicrotask(() => {
              const error = new Error("IPv6 is unavailable");
              error.code = "EAFNOSUPPORT";
              server.emit("error", error);
            });
            return server;
          };
        }
        return server;
      },
    });
    const callback = await sso._startCallbackServer(controller.signal);
    try {
      assert.strictEqual(callback.servers.length, 1);
      assert.strictEqual(callback.server.address()?.address, "127.0.0.1");
      const response = await requestCallback(
        "/?access_token=ipv4-access&refresh_token=ipv4-refresh",
        "127.0.0.1"
      );
      assert.strictEqual(response.status, 200);
      assert.deepStrictEqual(await callback.outcome, {
        kind: "tokens",
        accessToken: "ipv4-access",
        refreshToken: "ipv4-refresh",
      });
    } finally {
      await callback.close();
    }
    assert.strictEqual(created[0].listening, false);
    assert.strictEqual(created[1].listenerCount("error"), 0);
    assert.strictEqual(created[1].listenerCount("connection"), 0);
  });

  test("an occupied supported IPv6 callback closes the already-bound IPv4 listener", async () => {
    const controller = new AbortController();
    const created = [];
    const sso = new SSOAuthManager({}, {
      connectionManager: createManager(),
      createServer(handler) {
        const server = http.createServer(handler);
        created.push(server);
        if (created.length === 2) {
          server.listen = () => {
            queueMicrotask(() => {
              const error = new Error("IPv6 callback is occupied");
              error.code = "EADDRINUSE";
              server.emit("error", error);
            });
            return server;
          };
        }
        return server;
      },
    });

    await assert.rejects(
      sso._startCallbackServer(controller.signal),
      error => error.kind === "port_in_use"
    );

    assert.strictEqual(created.length, 2);
    assert.ok(created.every(server => server.listening === false));
    assert.ok(created.every(server => server.listenerCount("error") === 0));
    assert.ok(created.every(server => server.listenerCount("connection") === 0));
  });

  test("terminal SSO is truthful about non-importable keyring state", async () => {
    const manager = createManager();
    const operation = manager.beginCredentialOperation();
    const sso = new SSOAuthManager({}, { connectionManager: manager });
    const result = await sso.loginViaTerminal("workspace", operation);
    assert.strictEqual(result.error.kind, "unsupported_terminal_flow");
    assert.match(result.error.message, /CLI keyring/);
  });
});

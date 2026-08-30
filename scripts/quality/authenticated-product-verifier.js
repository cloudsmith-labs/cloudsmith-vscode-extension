// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const fs = require("fs");
const http = require("http");
const net = require("net");
const path = require("path");
const { spawn } = require("child_process");
const { ROOT } = require("./common");
const { currentExtensionHostVersion } = require("./prepare-qualification");
const {
  ProcessTreeCleanupError,
  terminateProcessTree,
} = require("./process-tree");

const COMMAND_LABEL = "Cloudsmith: Set default workspace";
const DEFAULT_START_TIMEOUT_MS = 45_000;
const DEFAULT_WORKSPACE_TIMEOUT_MS = 90_000;
const MAX_CDP_RESPONSE_BYTES = 256 * 1024;
const CURRENT_VSCODE_VERSION = currentExtensionHostVersion(ROOT);
const SAFE_RESULT_KEYS = Object.freeze([
  "candidateReceiptFingerprint",
  "developmentPath",
  "source",
  "status",
  "surface",
  "workspace",
]);

function delay(milliseconds) {
  return new Promise(resolve => {
    setTimeout(resolve, milliseconds);
  });
}

function absoluteNormalizedPath(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value)
    || path.resolve(value) !== value || path.normalize(value) !== value
    || value.includes("\u0000")) {
    throw new Error(`${label} must be an absolute normalized path.`);
  }
  return value;
}

function assertPrivateRuntimeLogRoot(value, profileRoot) {
  const root = absoluteNormalizedPath(value, "Authenticated runtime log root");
  const stat = fs.lstatSync(root);
  if (stat.isSymbolicLink() || !stat.isDirectory() || fs.realpathSync(root) !== root
    || root === profileRoot || root.startsWith(`${profileRoot}${path.sep}`)
    || profileRoot.startsWith(`${root}${path.sep}`)
    || root === ROOT || root.startsWith(`${ROOT}${path.sep}`)
    || ROOT.startsWith(`${root}${path.sep}`)
    || (process.platform !== "win32" && (stat.mode & 0o077) !== 0)
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error(
      "Authenticated runtime logs must use an owned private directory outside the profile and repository."
    );
  }
  return root;
}

function assertPrivateProfileDirectory(value, label, profileRoot) {
  const directory = absoluteNormalizedPath(value, label);
  const stat = fs.lstatSync(directory);
  if (stat.isSymbolicLink() || !stat.isDirectory()
    || fs.realpathSync(directory) !== directory
    || (directory !== profileRoot && !directory.startsWith(`${profileRoot}${path.sep}`))
    || (process.platform !== "win32" && (stat.mode & 0o077) !== 0)
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error(`${label} must be an owned private real directory.`);
  }
  return stat;
}

function assertVerifierContext(context) {
  const expectedLaunchArguments = context?.profile ? [
    "--user-data-dir", context.profile.userDataDir,
    "--extensions-dir", context.profile.extensionsDir,
    "--disable-updates",
    "--skip-welcome",
    "--skip-release-notes",
    "--new-window",
    ROOT,
  ] : [];
  if (!context || typeof context !== "object" || Array.isArray(context)
    || context.root !== ROOT
    || context.expectedWorkspace !== "dl-technology-consulting"
    || !/^[a-f0-9]{64}$/u.test(context.candidateReceiptFingerprint || "")
    || !/^[A-Za-z0-9][A-Za-z0-9.-]*$/u.test(context.extensionId || "")
    || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(context.extensionVersion || "")
    || !/^[a-f0-9]{64}$/u.test(context.vsixSha256 || "")
    || !context.source || Object.keys(context.source).sort().join(",") !== "fingerprint,sha"
    || !/^[0-9a-f]{40,64}$/u.test(context.source.sha || "")
    || !/^[a-f0-9]{64}$/u.test(context.source.fingerprint || "")
    || !context.profile || context.profile.mode !== "ci"
    || context.profile.persistent !== false
    || context.profile.root !== context.profile.testResourcesDir
    || context.profile.homeDir !== path.join(context.profile.root, "home")
    || context.profile.userDataDir !== path.join(context.profile.root, "settings")
    || context.profile.extensionsDir !== path.join(context.profile.root, "extensions")
    || context.profile.vscodeVersion !== CURRENT_VSCODE_VERSION
    || !Array.isArray(context.launchArguments)
    || context.launchArguments.length !== expectedLaunchArguments.length
    || context.launchArguments.some((argument, index) => (
      typeof argument !== "string"
      || argument !== expectedLaunchArguments[index]
      || argument.includes("--extensionDevelopmentPath")
    ))
    || !context.environment || typeof context.environment !== "object"
    || Array.isArray(context.environment)
    || context.environment.HOME !== context.profile.homeDir
    || context.environment.USERPROFILE !== context.profile.homeDir
    || Object.keys(context.environment).some(name => /(?:API_?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)/iu.test(name))) {
    throw new Error("Authenticated product verifier context is invalid.");
  }
  const profileRoot = absoluteNormalizedPath(
    context.profile.root,
    "Authenticated profile root",
  );
  const rootStat = assertPrivateProfileDirectory(
    profileRoot,
    "Authenticated profile root",
    profileRoot,
  );
  for (const [label, directory] of [
    ["Authenticated profile home", context.profile.homeDir],
    ["Authenticated profile user data", context.profile.userDataDir],
    ["Authenticated profile extensions", context.profile.extensionsDir],
  ]) {
    const stat = assertPrivateProfileDirectory(directory, label, profileRoot);
    if (stat.dev !== rootStat.dev) {
      throw new Error("Authenticated profile directories must remain on one owned filesystem.");
    }
  }
  const executable = absoluteNormalizedPath(
    context.profile.executable,
    "Authenticated VS Code executable",
  );
  const executableStat = fs.lstatSync(executable);
  if (executableStat.isSymbolicLink() || !executableStat.isFile()
    || fs.realpathSync(executable) !== executable
    || !executable.startsWith(`${profileRoot}${path.sep}`)
    || (process.platform !== "win32" && (executableStat.mode & 0o111) === 0)) {
    throw new Error("Authenticated VS Code executable must be the exact profile-owned current build.");
  }
  assertPrivateRuntimeLogRoot(context.runtimeLogRoot, profileRoot);
  return context;
}

function reserveLoopbackPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 0, exclusive: true }, () => {
      const address = server.address();
      const port = address && typeof address === "object" ? address.port : null;
      server.close((error) => {
        if (error) reject(error);
        else if (!Number.isInteger(port) || port < 1024 || port > 65535) {
          reject(new Error("Could not reserve a bounded loopback debugging port."));
        } else resolve(port);
      });
    });
  });
}

function readCdpTargets(port, timeout = 1_000) {
  return new Promise((resolve, reject) => {
    const request = http.get({
      host: "127.0.0.1",
      port,
      path: "/json/list",
      timeout,
      headers: { Accept: "application/json" },
    }, response => {
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error("VS Code debugging target discovery failed."));
        return;
      }
      const chunks = [];
      let bytes = 0;
      response.on("data", chunk => {
        bytes += chunk.length;
        if (bytes > MAX_CDP_RESPONSE_BYTES) {
          request.destroy(new Error("VS Code debugging target inventory exceeded its bound."));
          return;
        }
        chunks.push(chunk);
      });
      response.once("error", reject);
      response.once("end", () => {
        let targets;
        try {
          targets = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        } catch {
          reject(new Error("VS Code debugging target inventory was invalid."));
          return;
        }
        resolve(targets);
      });
    });
    request.once("timeout", () => request.destroy(new Error("VS Code target discovery timed out.")));
    request.once("error", reject);
  });
}

function targetWebSocket(targets, port) {
  if (!Array.isArray(targets)) return null;
  const candidates = targets.filter(target => (
    target && target.type === "page"
    && typeof target.url === "string"
    && /(?:workbench|vscode-file:\/\/vscode-app)/u.test(target.url)
    && typeof target.webSocketDebuggerUrl === "string"
  ));
  if (candidates.length !== 1) return null;
  let parsed;
  try {
    parsed = new URL(candidates[0].webSocketDebuggerUrl);
  } catch {
    return null;
  }
  if (parsed.protocol !== "ws:" || parsed.hostname !== "127.0.0.1"
    || Number(parsed.port) !== port || parsed.username || parsed.password) {
    return null;
  }
  return parsed.toString();
}

async function discoverWorkbenchTarget(port, child, options = {}) {
  const deadline = Date.now() + (options.timeout || DEFAULT_START_TIMEOUT_MS);
  const targets = options.readTargets || readCdpTargets;
  while (Date.now() < deadline) {
    if (options.spawnFailed?.()) {
      throw new Error("Authenticated VS Code could not start.");
    }
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error("Authenticated VS Code exited before its workbench was available.");
    }
    try {
      const websocket = targetWebSocket(await targets(port), port);
      if (websocket) return websocket;
    } catch {
      // A private loopback endpoint may not be ready yet.
    }
    await delay(200);
  }
  throw new Error("Authenticated VS Code workbench did not become available.");
}

class CdpSession {
  constructor(websocket, options = {}) {
    this.websocket = websocket;
    this.timeout = options.timeout || 10_000;
    this.sequence = 0;
    this.pending = new Map();
  }

  static connect(url, options = {}) {
    const WebSocketConstructor = options.WebSocket || globalThis.WebSocket;
    if (typeof WebSocketConstructor !== "function") {
      throw new Error("Node.js WebSocket support is required for authenticated qualification.");
    }
    return new Promise((resolve, reject) => {
      const socket = new WebSocketConstructor(url);
      let settled = false;
      const timeout = setTimeout(() => {
        if (settled) return;
        settled = true;
        socket.removeEventListener("error", fail);
        try {
          socket.close();
        } catch {
          // The bounded connection attempt is already failed closed.
        }
        reject(new Error("Private VS Code workbench connection timed out."));
      }, options.connectTimeout || 10_000);
      const fail = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        reject(new Error("Could not connect to the private VS Code workbench."));
      };
      socket.addEventListener("error", fail, { once: true });
      socket.addEventListener("open", () => {
        if (settled) {
          try {
            socket.close();
          } catch {
            // The timed-out connection remains failed closed.
          }
          return;
        }
        settled = true;
        clearTimeout(timeout);
        socket.removeEventListener("error", fail);
        const session = new CdpSession(socket, options);
        socket.addEventListener("message", event => session._onMessage(event.data));
        socket.addEventListener("close", () => session._onClose());
        socket.addEventListener("error", () => session._onClose());
        resolve(session);
      }, { once: true });
    });
  }

  _onMessage(data) {
    let message;
    try {
      message = JSON.parse(String(data));
    } catch {
      return;
    }
    if (!Number.isInteger(message.id)) return;
    const pending = this.pending.get(message.id);
    if (!pending) return;
    this.pending.delete(message.id);
    clearTimeout(pending.timer);
    if (message.error) pending.reject(new Error("Private workbench command failed."));
    else pending.resolve(message.result || {});
  }

  _onClose() {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error("Private VS Code workbench connection closed."));
    }
    this.pending.clear();
  }

  send(method, params = {}) {
    if (this.websocket.readyState !== 1) {
      return Promise.reject(new Error("Private VS Code workbench is unavailable."));
    }
    const id = ++this.sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error("Private workbench command timed out."));
      }, this.timeout);
      this.pending.set(id, { resolve, reject, timer });
      try {
        this.websocket.send(JSON.stringify({ id, method, params }));
      } catch {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(new Error("Private workbench command could not be sent."));
      }
    });
  }

  close() {
    try {
      this.websocket.close();
    } catch {
      // The owned process cleanup remains authoritative.
    }
  }
}

async function booleanEvaluation(session, expression) {
  const result = await session.send("Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise: true,
  });
  if (result.exceptionDetails || result.result?.type !== "boolean") {
    throw new Error("Authenticated UI proof did not return a boolean.");
  }
  return result.result.value === true;
}

async function waitForBoolean(session, expression, timeout) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (await booleanEvaluation(session, expression)) return true;
    await delay(250);
  }
  throw new Error("Authenticated production UI did not publish the expected state.");
}

function visibleQuickInputExpression(assertion) {
  return `(() => {
    const widgets = [...document.querySelectorAll('.quick-input-widget')];
    const widget = widgets.find(element => {
      const style = getComputedStyle(element);
      return style.display !== 'none' && style.visibility !== 'hidden'
        && element.getAttribute('aria-hidden') !== 'true'
        && element.getClientRects().length > 0;
    });
    if (!widget) return false;
    ${assertion}
  })()`;
}

async function pressKey(session, key, code, virtualKeyCode) {
  const common = { key, code, windowsVirtualKeyCode: virtualKeyCode };
  await session.send("Input.dispatchKeyEvent", { type: "keyDown", ...common });
  await session.send("Input.dispatchKeyEvent", { type: "keyUp", ...common });
}

function exactWorkspacePickerState(state, workspace) {
  return Boolean(
    state && typeof state === "object" && !Array.isArray(state)
      && state.placeholder === "Select a default workspace"
      && typeof workspace === "string" && workspace.length > 0
      && Array.isArray(state.rows)
      && state.rows.some(row => (
        row && typeof row === "object" && !Array.isArray(row)
          && typeof row.label === "string" && row.label.length > 0
          && row.description === workspace
          && row.disabled === false
      ))
  );
}

async function proveConnectedWorkspace(session, workspace, options = {}) {
  await session.send("Runtime.enable");
  await waitForBoolean(
    session,
    "Boolean(document.querySelector('.monaco-workbench'))",
    options.startTimeout || DEFAULT_START_TIMEOUT_MS,
  );
  await pressKey(session, "F1", "F1", 112);
  await waitForBoolean(session, visibleQuickInputExpression(
    "return Boolean(widget.querySelector('input'));",
  ), 10_000);
  await session.send("Input.insertText", { text: COMMAND_LABEL });
  const encodedCommand = JSON.stringify(COMMAND_LABEL);
  await waitForBoolean(session, visibleQuickInputExpression(`
    return [...widget.querySelectorAll('.quick-input-list .monaco-list-row')].some(row => {
      const label = row.querySelector('.monaco-highlighted-label, .label-name');
      const text = String(label?.textContent || row.textContent || '').trim();
      const focused = row.classList.contains('focused')
        || row.getAttribute('aria-selected') === 'true';
      return text === ${encodedCommand} && focused
        && row.getAttribute('aria-disabled') !== 'true';
    });
  `), 15_000);
  await pressKey(session, "Enter", "Enter", 13);
  const encodedWorkspace = JSON.stringify(workspace);
  const pickerPredicate = `(${exactWorkspacePickerState.toString()})`;
  await waitForBoolean(session, visibleQuickInputExpression(`
    const input = widget.querySelector('input');
    const state = {
      placeholder: String(input?.placeholder || '').trim(),
      rows: [...widget.querySelectorAll('.quick-input-list .monaco-list-row')].map(row => {
        const label = row.querySelector('.monaco-highlighted-label, .label-name');
        const description = row.querySelector('.quick-input-description');
        return {
          label: String(label?.textContent || '').trim(),
          description: String(description?.textContent || '').trim(),
          disabled: row.getAttribute('aria-disabled') === 'true',
        };
      }),
    };
    return ${pickerPredicate}(state, ${encodedWorkspace});
  `), options.workspaceTimeout || DEFAULT_WORKSPACE_TIMEOUT_MS);
  await pressKey(session, "Escape", "Escape", 27);
  return true;
}

async function terminateOwnedProduct(child, session, options = {}) {
  const terminate = options.terminateProcessTree || terminateProcessTree;
  try {
    try {
      return await terminate(child, {
        ...options,
        graceful: async () => {
          if (session) await session.send("Browser.close");
        },
      });
    } catch {
      throw new ProcessTreeCleanupError();
    }
  } finally {
    session?.close();
  }
}

async function verifyConnectedWorkspace(context, options = {}) {
  assertVerifierContext(context);
  const allocatePort = options.reserveLoopbackPort || reserveLoopbackPort;
  const launch = options.spawn || spawn;
  const connect = options.connect || (url => CdpSession.connect(url, options));
  const port = await allocatePort();
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new Error("Authenticated product verifier received an invalid loopback port.");
  }
  const workspaceArgument = context.launchArguments[context.launchArguments.length - 1];
  const arguments_ = [
    ...context.launchArguments.slice(0, -1),
    "--disable-crash-reporter",
    "--disable-telemetry",
    "--no-cached-data",
    "--disable-workspace-trust",
    "--remote-debugging-address=127.0.0.1",
    `--remote-debugging-port=${port}`,
    "--logsPath",
    context.runtimeLogRoot,
    workspaceArgument,
  ];
  if (arguments_.some(argument => argument.includes("--extensionDevelopmentPath"))) {
    throw new Error("Authenticated product verifier refuses development paths.");
  }
  const child = launch(context.profile.executable, arguments_, {
    cwd: ROOT,
    env: context.environment,
    stdio: "ignore",
    windowsHide: true,
    detached: process.platform !== "win32",
  });
  if (!child || typeof child.once !== "function" || typeof child.kill !== "function") {
    throw new Error("Authenticated VS Code launch did not return an owned process.");
  }
  let spawnFailed = false;
  child.once("error", () => {
    spawnFailed = true;
  });
  let session = null;
  let terminated = false;
  let proofFailed = false;
  try {
    const websocket = await discoverWorkbenchTarget(port, child, {
      timeout: options.startTimeout,
      readTargets: options.readTargets,
      spawnFailed: () => spawnFailed,
    });
    session = await connect(websocket);
    const prove = options.proveConnectedWorkspace || proveConnectedWorkspace;
    await prove(session, context.expectedWorkspace, options);
  } catch {
    proofFailed = true;
  } finally {
    terminated = await terminateOwnedProduct(child, session, options);
  }
  if (!terminated) throw new ProcessTreeCleanupError();
  if (proofFailed) throw new Error("Authenticated production UI proof failed.");
  const result = {
    status: "passed",
    surface: "production-connected-workspace",
    workspace: context.expectedWorkspace,
    developmentPath: false,
    source: { ...context.source },
    candidateReceiptFingerprint: context.candidateReceiptFingerprint,
  };
  if (Object.keys(result).sort().join(",") !== [...SAFE_RESULT_KEYS].sort().join(",")) {
    throw new Error("Authenticated product verifier produced an unsafe result shape.");
  }
  return Object.freeze(result);
}

module.exports = {
  COMMAND_LABEL,
  CdpSession,
  assertPrivateRuntimeLogRoot,
  assertVerifierContext,
  booleanEvaluation,
  discoverWorkbenchTarget,
  exactWorkspacePickerState,
  pressKey,
  proveConnectedWorkspace,
  readCdpTargets,
  reserveLoopbackPort,
  targetWebSocket,
  terminateOwnedProduct,
  verifyConnectedWorkspace,
  visibleQuickInputExpression,
  waitForBoolean,
};

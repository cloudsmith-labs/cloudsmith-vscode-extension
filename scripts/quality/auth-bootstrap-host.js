// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const { ROOT } = require("./common");
const { REQUEST_ENV } = require("../../test/auth-bootstrap/runner");

const HOST_REQUEST_ENV = "CLOUDSMITH_AUTH_BOOTSTRAP_HOST_REQUEST";
const SECRET_ENV = "CLOUDSMITH_QUALIFICATION_API_KEY";

function assertExactPath(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value)
    || path.resolve(value) !== value || path.normalize(value) !== value
    || value.includes("\u0000")) {
    throw new Error(`${label} must be an absolute normalized path.`);
  }
  return value;
}

function assertRealDirectoryInside(value, root, label) {
  assertExactPath(value, label);
  const stat = fs.lstatSync(value);
  if (stat.isSymbolicLink() || !stat.isDirectory() || fs.realpathSync(value) !== value
    || (value !== root && !value.startsWith(`${root}${path.sep}`))) {
    throw new Error(`${label} must be a real directory inside the owned profile.`);
  }
  return stat;
}

function assertRealExecutableInside(value, root) {
  assertExactPath(value, "Authenticated CI VS Code executable");
  const stat = fs.lstatSync(value);
  if (stat.isSymbolicLink() || !stat.isFile() || fs.realpathSync(value) !== value
    || !value.startsWith(`${root}${path.sep}`)
    || (process.platform !== "win32" && (stat.mode & 0o111) === 0)) {
    throw new Error("Authenticated CI VS Code executable is not profile-owned.");
  }
  return value;
}

function parseHostRequest(environment = process.env) {
  if (Object.prototype.hasOwnProperty.call(environment, SECRET_ENV)) {
    delete environment[SECRET_ENV];
    throw new Error("Authenticated CI host refuses a credential environment variable.");
  }
  const encoded = environment[HOST_REQUEST_ENV];
  delete environment[HOST_REQUEST_ENV];
  if (typeof encoded !== "string" || encoded.length === 0 || encoded.length > 32 * 1024) {
    throw new Error("Authenticated CI host request is missing or invalid.");
  }
  let request;
  try {
    request = JSON.parse(encoded);
  } catch {
    throw new Error("Authenticated CI host request is not valid JSON.");
  }
  if (!request || typeof request !== "object" || Array.isArray(request)
    || Object.keys(request).sort().join(",") !== [
      "commandRequest", "extensionsDir", "profileRoot", "repositoryRoot",
      "schemaVersion", "userDataDir", "vscodeExecutable",
    ].sort().join(",")
    || request.schemaVersion !== 1
    || request.repositoryRoot !== ROOT
    || fs.realpathSync(request.repositoryRoot) !== ROOT
    || !request.commandRequest || typeof request.commandRequest !== "object"
    || Array.isArray(request.commandRequest)) {
    throw new Error("Authenticated CI host request has an invalid shape.");
  }
  const profileRoot = assertExactPath(request.profileRoot, "Authenticated CI profile root");
  const rootStat = assertRealDirectoryInside(profileRoot, profileRoot, "Authenticated CI profile root");
  if (process.platform !== "win32" && (rootStat.mode & 0o077) !== 0) {
    throw new Error("Authenticated CI profile root is not private.");
  }
  if (request.userDataDir !== path.join(profileRoot, "settings")
    || request.extensionsDir !== path.join(profileRoot, "extensions")) {
    throw new Error("Authenticated CI host profile layout is not canonical.");
  }
  assertRealDirectoryInside(request.userDataDir, profileRoot, "Authenticated CI user data");
  assertRealDirectoryInside(request.extensionsDir, profileRoot, "Authenticated CI extensions");
  assertRealExecutableInside(request.vscodeExecutable, profileRoot);
  return Object.freeze(request);
}

function bootstrapLaunchArguments(request, bootstrapRoot, runnerPath) {
  const arguments_ = [
    ROOT,
    `--user-data-dir=${request.userDataDir}`,
    `--extensions-dir=${request.extensionsDir}`,
    "--disable-updates",
    "--skip-welcome",
    "--skip-release-notes",
    "--no-cached-data",
    "--disable-workspace-trust",
    "--disable-crash-reporter",
    "--disable-telemetry",
    `--extensionTestsPath=${runnerPath}`,
    `--extensionDevelopmentPath=${bootstrapRoot}`,
  ];
  if (arguments_.some(argument => (
    argument === "--no-sandbox"
      || argument.startsWith("--no-sandbox=")
      || argument === "--disable-gpu-sandbox"
      || argument.startsWith("--disable-gpu-sandbox=")
  ))) {
    throw new Error("Authenticated CI bootstrap refuses sandbox-disabling arguments.");
  }
  return Object.freeze(arguments_);
}

function waitForBootstrapExit(child) {
  if (!child || typeof child.once !== "function") {
    throw new Error("Authenticated CI bootstrap launch did not return an owned process.");
  }
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve({ code: child.exitCode, signal: child.signalCode });
  }
  return new Promise(resolve => {
    let settled = false;
    const finish = value => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    child.once("error", () => finish({ startFailed: true }));
    child.once("exit", (code, signal) => finish({ code, signal }));
  });
}

async function runBootstrapHost(options = {}) {
  const environment = options.environment || process.env;
  const request = options.request || parseHostRequest(environment);
  if (Object.prototype.hasOwnProperty.call(environment, SECRET_ENV)) {
    delete environment[SECRET_ENV];
    throw new Error("Authenticated CI host refuses a credential environment variable.");
  }
  delete environment[HOST_REQUEST_ENV];
  const bootstrapRoot = path.join(ROOT, "test", "auth-bootstrap");
  const runnerPath = path.join(bootstrapRoot, "runner.js");
  assertRealDirectoryInside(bootstrapRoot, ROOT, "Authenticated CI bootstrap extension");
  const runnerStat = fs.lstatSync(runnerPath);
  if (runnerStat.isSymbolicLink() || !runnerStat.isFile()
    || fs.realpathSync(runnerPath) !== runnerPath) {
    throw new Error("Authenticated CI bootstrap runner is invalid.");
  }
  const arguments_ = bootstrapLaunchArguments(request, bootstrapRoot, runnerPath);
  const childEnvironment = {
    ...environment,
    [REQUEST_ENV]: JSON.stringify(request.commandRequest),
  };
  delete childEnvironment[SECRET_ENV];
  delete childEnvironment[HOST_REQUEST_ENV];
  const launch = options.spawn || spawn;
  let child;
  try {
    child = launch(request.vscodeExecutable, arguments_, {
      cwd: ROOT,
      env: childEnvironment,
      stdio: "ignore",
      windowsHide: true,
      detached: false,
    });
  } catch {
    throw new Error("Authenticated CI bootstrap host failed.");
  }
  const result = await waitForBootstrapExit(child);
  if (result.startFailed || result.signal || result.code !== 0) {
    throw new Error("Authenticated CI bootstrap host failed.");
  }
  return true;
}

if (require.main === module) {
  runBootstrapHost()
    .catch(() => {
      process.exitCode = 1;
    });
}

module.exports = {
  HOST_REQUEST_ENV,
  SECRET_ENV,
  bootstrapLaunchArguments,
  parseHostRequest,
  runBootstrapHost,
  waitForBootstrapExit,
};

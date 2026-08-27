// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { setTimeout: delay } = require("timers/promises");

const DEFAULT_GRACEFUL_TIMEOUT_MS = 5_000;
const DEFAULT_TERM_TIMEOUT_MS = 5_000;
const DEFAULT_KILL_TIMEOUT_MS = 5_000;

class ProcessTreeCleanupError extends Error {
  constructor() {
    super("Owned qualification process-tree cleanup did not complete.");
    this.name = "ProcessTreeCleanupError";
  }
}

function validOwnedPid(child) {
  return Boolean(child && Number.isSafeInteger(child.pid) && child.pid > 1);
}

function defaultTreeAlive(child, options = {}) {
  if (!validOwnedPid(child)) return false;
  const platform = options.platform || process.platform;
  if (platform === "win32") {
    // Authenticated CI is Linux. Windows must use an injected Job Object-backed
    // containment probe; a leader PID cannot prove descendant exit.
    throw new ProcessTreeCleanupError();
  }
  try {
    (options.kill || process.kill)(-child.pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    if (error?.code === "EPERM") return true;
    throw new ProcessTreeCleanupError();
  }
}

async function waitForTreeExit(child, timeout, options = {}) {
  const isTreeAlive = options.isTreeAlive || defaultTreeAlive;
  const pause = options.delay || delay;
  const pollInterval = options.pollInterval || 50;
  const deadline = Date.now() + timeout;
  while (true) {
    let alive;
    try {
      alive = isTreeAlive(child, options);
    } catch {
      return false;
    }
    if (!alive) return true;
    if (Date.now() >= deadline) return false;
    await pause(Math.min(pollInterval, Math.max(1, deadline - Date.now())));
  }
}

function defaultSignalTree(child, signal, options = {}) {
  if (!validOwnedPid(child)) return true;
  const platform = options.platform || process.platform;
  if (platform === "win32") throw new ProcessTreeCleanupError();
  try {
    (options.kill || process.kill)(-child.pid, signal);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return true;
    return false;
  }
}

async function terminateProcessTree(child, options = {}) {
  const wait = options.waitForTreeExit || waitForTreeExit;
  const signal = options.signalTree || defaultSignalTree;
  if (typeof options.graceful === "function") {
    try {
      await options.graceful();
    } catch {
      // Group termination remains the authoritative cleanup boundary.
    }
  }
  if (await wait(child, options.gracefulTimeout || DEFAULT_GRACEFUL_TIMEOUT_MS, options)) {
    return true;
  }
  try {
    if (signal(child, "SIGTERM", options) !== true) return false;
  } catch {
    return false;
  }
  if (await wait(child, options.termTimeout || DEFAULT_TERM_TIMEOUT_MS, options)) return true;
  try {
    if (signal(child, "SIGKILL", options) !== true) return false;
  } catch {
    return false;
  }
  return wait(child, options.killTimeout || DEFAULT_KILL_TIMEOUT_MS, options);
}

module.exports = {
  ProcessTreeCleanupError,
  defaultSignalTree,
  defaultTreeAlive,
  terminateProcessTree,
  validOwnedPid,
  waitForTreeExit,
};

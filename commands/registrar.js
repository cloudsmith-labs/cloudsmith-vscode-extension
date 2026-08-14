// Copyright 2026 Cloudsmith Ltd. All rights reserved.

function reportDisposalFailure(reportFailure, error) {
  try {
    reportFailure(error);
  } catch {
    // Cleanup remains best-effort even when the observer fails.
  }
}

function disposeRegistrations(registrations, reportFailure) {
  for (let index = registrations.length - 1; index >= 0; index -= 1) {
    try {
      registrations[index].dispose();
    } catch (error) {
      reportDisposalFailure(reportFailure, error);
    }
  }
}

function aggregateDisposables(resources, options = {}) {
  if (!Array.isArray(resources) || resources.some(resource => (
    !resource || typeof resource.dispose !== "function"
  ))) {
    throw new TypeError("Disposable resources are required.");
  }
  const reportFailure = typeof options.reportDisposalFailure === "function"
    ? options.reportDisposalFailure
    : () => {};
  const owned = resources.slice();
  let disposed = false;
  return Object.freeze({
    dispose() {
      if (disposed) return;
      disposed = true;
      disposeRegistrations(owned.splice(0), reportFailure);
    },
  });
}

function createCommandRegistration(commands) {
  if (!commands || typeof commands.registerCommand !== "function") {
    throw new TypeError("A VS Code command registry is required.");
  }
  return commands.registerCommand.bind(commands);
}

/**
 * Register a fixed command inventory transactionally.
 *
 * @param {(id: string, handler: Function) => {dispose: Function}} registerCommand
 * @param {ReadonlyArray<readonly [string, Function]>} entries
 * @param {{reportDisposalFailure?: Function}} options
 * @returns {{dispose: Function}}
 */
function registerCommands(registerCommand, entries, options = {}) {
  if (typeof registerCommand !== "function") {
    throw new TypeError("A command registration function is required.");
  }
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new TypeError("At least one command registration is required.");
  }

  const reportFailure = typeof options.reportDisposalFailure === "function"
    ? options.reportDisposalFailure
    : () => {};
  const registrations = [];
  const ids = new Set();

  try {
    for (const entry of entries) {
      if (
        !Array.isArray(entry)
        || entry.length !== 2
        || typeof entry[0] !== "string"
        || !entry[0]
        || typeof entry[1] !== "function"
        || ids.has(entry[0])
      ) {
        throw new TypeError("Command registrations must have unique IDs and callable handlers.");
      }
      ids.add(entry[0]);
      const registration = registerCommand(entry[0], entry[1]);
      if (!registration || typeof registration.dispose !== "function") {
        throw new TypeError(`Command ${entry[0]} did not return a disposable registration.`);
      }
      registrations.push(registration);
    }
  } catch (error) {
    disposeRegistrations(registrations, reportFailure);
    throw error;
  }

  return aggregateDisposables(registrations, { reportDisposalFailure: reportFailure });
}

module.exports = { aggregateDisposables, createCommandRegistration, registerCommands };

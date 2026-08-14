// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const vscode = require("vscode");

const projectors = new WeakMap();

class WorkspaceContextProjector {
  constructor(options = {}) {
    this._executeCommand = options.executeCommand
      || ((...args) => vscode.commands.executeCommand(...args));
    this._version = 0;
    this._queue = Promise.resolve();
    this._disposed = false;
  }

  begin(options = {}) {
    if (this._disposed) return null;
    return Object.freeze({
      projector: this,
      version: ++this._version,
      isCurrent: typeof options.isCurrent === "function" ? options.isCurrent : null,
    });
  }

  project(hasMultipleWorkspaces, options = {}) {
    if (this._disposed) return Promise.resolve(false);

    const operation = options.operation || this.begin(options);
    if (!operation || operation.projector !== this) return Promise.resolve(false);
    const version = operation.version;
    const value = Boolean(hasMultipleWorkspaces);
    const isCurrent = operation.isCurrent;
    const apply = async () => {
      if (this._disposed || version !== this._version) {
        return false;
      }
      if (isCurrent && !isCurrent()) {
        if (value) {
          await this._executeCommand(
            "setContext",
            "cloudsmith.hasMultipleWorkspaces",
            false
          );
        }
        return false;
      }

      await this._executeCommand(
        "setContext",
        "cloudsmith.hasMultipleWorkspaces",
        value
      );

      if (this._disposed || version !== this._version) return false;
      if (isCurrent && !isCurrent()) {
        // The account may change while VS Code is applying the context key.
        // Correct it within this serialized operation before reporting completion.
        await this._executeCommand(
          "setContext",
          "cloudsmith.hasMultipleWorkspaces",
          false
        );
        return false;
      }
      return true;
    };

    const pending = this._queue.then(apply, apply);
    this._queue = pending.then(() => undefined, () => undefined);
    return pending;
  }

  whenIdle() {
    return this._queue;
  }

  isDisposed() {
    return this._disposed;
  }

  dispose() {
    this._disposed = true;
    this._version += 1;
    return this._queue;
  }
}

function getWorkspaceContextProjector(context, options = {}) {
  if (!context || (typeof context !== "object" && typeof context !== "function")) {
    throw new TypeError("An extension context is required for workspace projection.");
  }
  let projector = projectors.get(context);
  if (!projector || projector.isDisposed()) {
    projector = new WorkspaceContextProjector(options);
    projectors.set(context, projector);
  }
  return projector;
}

module.exports = {
  getWorkspaceContextProjector,
  WorkspaceContextProjector,
};

// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { ContextKeyProjector } = require("./contextKeyProjector");

const projectors = new WeakMap();

class WorkspaceContextProjector {
  constructor(options = {}) {
    this._projector = new ContextKeyProjector({
      defaults: { "cloudsmith.hasMultipleWorkspaces": false },
      executeCommand: options.executeCommand,
      authorityScope: options.authorityScope,
    });
  }

  begin(options = {}) {
    return this._projector.begin(options);
  }

  project(hasMultipleWorkspaces, options = {}) {
    return this._projector.project({
      "cloudsmith.hasMultipleWorkspaces": Boolean(hasMultipleWorkspaces),
    }, options).then(result => {
      if (result.error) throw result.error;
      return result.applied;
    });
  }

  whenIdle() {
    return this._projector.whenIdle();
  }

  isDisposed() {
    return this._projector.isDisposed();
  }

  dispose() {
    return this._projector.dispose();
  }
}

function getWorkspaceContextProjector(context, options = {}) {
  if (!context || (typeof context !== "object" && typeof context !== "function")) {
    throw new TypeError("An extension context is required for workspace projection.");
  }
  let projector = projectors.get(context);
  if (!projector || projector.isDisposed()) {
    projector = new WorkspaceContextProjector({ ...options, authorityScope: context });
    projectors.set(context, projector);
  }
  return projector;
}

module.exports = {
  getWorkspaceContextProjector,
  WorkspaceContextProjector,
};

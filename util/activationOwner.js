// Copyright 2026 Cloudsmith Ltd. All rights reserved.

class ActivationOwner {
  constructor(reportFailure = () => {
    console.warn("[Cloudsmith] An activation resource could not be disposed cleanly.");
  }) {
    this._resources = [];
    this._pending = [];
    this._disposed = false;
    this._reportFailure = reportFailure;
  }

  add(...resources) {
    for (const resource of resources) {
      if (!resource || typeof resource.dispose !== "function") {
        throw new TypeError("Activation resources must be disposable.");
      }
      if (this._disposed) {
        this._disposeResource(resource);
      } else {
        this._resources.push(resource);
      }
    }
  }

  dispose() {
    if (this._disposed) return;
    this._disposed = true;
    for (const resource of this._resources.splice(0).reverse()) {
      this._disposeResource(resource);
    }
  }

  async settle() {
    const pending = this._pending.splice(0);
    if (pending.length > 0) {
      const results = await Promise.allSettled(pending);
      if (results.some(result => result.status === "rejected")) this._reportFailure();
    }
  }

  _disposeResource(resource) {
    try {
      const result = resource.dispose();
      if (result && typeof result.then === "function") {
        this._pending.push(Promise.resolve(result));
      }
    } catch {
      this._reportFailure();
    }
  }
}

module.exports = { ActivationOwner };

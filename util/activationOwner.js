// Copyright 2026 Cloudsmith Ltd. All rights reserved.

class ActivationOwner {
  constructor(reportFailure = () => {
    console.warn("[Cloudsmith] An activation resource could not be disposed cleanly.");
  }) {
    this._resources = [];
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
    // Ownership revocation must not inherit arbitrary latency from an async
    // disposable. Every promise is observed when registered, while settle()
    // yields once so immediately rejected cleanup is reported without making
    // activation or reload wait for storage, network, or VS Code command work.
    await Promise.resolve();
  }

  observe(promise, reportFailure = this._reportFailure) {
    return Promise.resolve(promise).then(
      () => undefined,
      () => {
        try { reportFailure(); } catch { /* observation remains fail-open */ }
      }
    );
  }

  _disposeResource(resource) {
    try {
      const result = resource.dispose();
      if (result && typeof result.then === "function") {
        this.observe(result);
      }
    } catch {
      this._reportFailure();
    }
  }
}

module.exports = { ActivationOwner };

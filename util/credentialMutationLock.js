const http = require("http");

const LOCK_HOST = "127.0.0.1";
// Dedicated dynamic/private port, separate from Cloudsmith's SAML callback.
// The kernel owns the lease and releases it if an extension host exits.
const LOCK_PORT = 53129;
const DEFAULT_WAIT_MS = 75000;
const DEFAULT_POLL_MS = 50;

class CredentialMutationLock {
  constructor(context, options = {}) {
    this._enabled = options.enabled === undefined
      ? Boolean(options.directory || (context && context.globalStorageUri && context.globalStorageUri.fsPath))
      : Boolean(options.enabled);
    this._port = Number.isInteger(options.port) ? options.port : LOCK_PORT;
    this._now = options.now || Date.now;
    this._wait = options.wait || (milliseconds => new Promise(resolve => {
      setTimeout(resolve, milliseconds);
    }));
    this._waitMs = options.waitMs || DEFAULT_WAIT_MS;
    this._createServer = options.createServer || (() => http.createServer((_request, response) => {
      response.statusCode = 503;
      response.end();
    }));
    this._inProcess = Promise.resolve();
  }

  async run(task, options = {}) {
    const previous = this._inProcess;
    let releaseQueue;
    this._inProcess = new Promise(resolve => { releaseQueue = resolve; });
    await previous;
    try {
      if (!this._enabled) return task();
      const lease = await this.acquire(options.signal);
      try {
        if (options.signal && options.signal.aborted) throw lockError("cancelled");
        return await task();
      } finally {
        await lease.release();
      }
    } finally {
      releaseQueue();
    }
  }

  async acquire(signal) {
    if (!this._enabled) return Object.freeze({ release: async () => {} });
    const deadline = this._now() + this._waitMs;
    while (true) {
      if (signal && signal.aborted) throw lockError("cancelled");
      const server = await this._tryBind(signal);
      if (server) {
        let released = false;
        return Object.freeze({
          release: async () => {
            if (released) return;
            released = true;
            await closeServer(server);
          },
        });
      }
      if (this._now() >= deadline) throw lockError("timeout");
      await this._wait(Math.min(DEFAULT_POLL_MS, Math.max(1, deadline - this._now())));
    }
  }

  _tryBind(signal) {
    return new Promise((resolve, reject) => {
      const server = this._createServer();
      let settled = false;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        server.removeListener("error", onError);
        server.removeListener("listening", onListening);
        if (signal) signal.removeEventListener("abort", onAbort);
        if (error) reject(error);
        else resolve(value);
      };
      const onError = error => {
        closeServer(server).catch(() => {});
        if (error && error.code === "EADDRINUSE") finish(null, null);
        else finish(lockError("unavailable"));
      };
      const onListening = () => {
        server.unref?.();
        finish(null, server);
      };
      const onAbort = () => {
        closeServer(server).catch(() => {});
        finish(lockError("cancelled"));
      };
      server.once("error", onError);
      server.once("listening", onListening);
      if (signal) signal.addEventListener("abort", onAbort, { once: true });
      if (signal && signal.aborted) {
        onAbort();
        return;
      }
      try {
        server.listen({ host: LOCK_HOST, port: this._port, exclusive: true });
      } catch (error) {
        finish(lockError(error && error.code === "EADDRINUSE" ? "timeout" : "unavailable"));
      }
    });
  }
}

function closeServer(server) {
  return new Promise(resolve => {
    try {
      if (!server.listening) {
        resolve();
        return;
      }
      server.close(() => resolve());
      server.closeAllConnections?.();
    } catch {
      resolve();
    }
  });
}

function lockError(kind) {
  const error = new Error("Credential storage is busy. Try again.");
  error.kind = kind === "cancelled" ? "cancelled" : "credential_lock_failed";
  return error;
}

module.exports = { CredentialMutationLock, LOCK_HOST, LOCK_PORT };

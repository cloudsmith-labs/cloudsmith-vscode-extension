const RESULT_KEYS = Object.freeze({
  failure: Object.freeze(["attempts", "error", "headers", "ok", "requestId", "serverRequestId", "status"]),
  success: Object.freeze(["attempts", "data", "headers", "ok", "redirectCount", "requestId", "serverRequestId", "status"]),
});

const MAX_FREEZE_DEPTH = 32;
const MAX_FREEZE_NODES = 10000;

function deepFreeze(value) {
  const seen = new Set();
  let nodes = 0;
  const visit = (current, depth) => {
    if (!current || typeof current !== "object" || seen.has(current)) return;
    if (depth > MAX_FREEZE_DEPTH || ++nodes > MAX_FREEZE_NODES) {
      throw new TypeError("Scripted API result exceeds structural bounds");
    }
    seen.add(current);
    const descriptors = Object.getOwnPropertyDescriptors(current);
    for (const descriptor of Object.values(descriptors)) {
      if (!Object.prototype.hasOwnProperty.call(descriptor, "value")) {
        throw new TypeError("Scripted API results must contain data properties only");
      }
      visit(descriptor.value, depth + 1);
    }
    Object.freeze(current);
  };
  visit(value, 0);
  return value;
}

function assertTypedResult(result) {
  if (!result || typeof result !== "object" || typeof result.ok !== "boolean") {
    throw new TypeError("Scripted API results must use the typed Cloudsmith result contract");
  }
  const expectedKeys = result.ok ? RESULT_KEYS.success : RESULT_KEYS.failure;
  const actualKeys = Object.keys(result).sort();
  if (actualKeys.length !== expectedKeys.length
    || actualKeys.some((key, index) => key !== expectedKeys[index])) {
    throw new TypeError("Scripted API result keys do not match the production contract");
  }
  if (!result.headers || typeof result.headers !== "object") {
    throw new TypeError("Scripted API results require a headers object");
  }
  if (!result.ok && (!result.error || typeof result.error.kind !== "string")) {
    throw new TypeError("Scripted API failures require a typed error");
  }
  return deepFreeze(result);
}

class ScriptedCloudsmithAPI {
  constructor(steps) {
    if (!Array.isArray(steps)) throw new TypeError("Scripted API steps must be an array");
    this._steps = steps.map(step => {
      if (!step || typeof step !== "object" || typeof step.method !== "string") {
        throw new TypeError("Each scripted API step requires a method");
      }
      if (!Object.prototype.hasOwnProperty.call(step, "result")
        && !Object.prototype.hasOwnProperty.call(step, "error")) {
        throw new TypeError("Each scripted API step requires a result or error");
      }
      const scriptedResult = step.result;
      return Object.freeze({
        apiVersion: step.apiVersion || "v1",
        endpoint: step.endpoint,
        error: step.error,
        method: step.method.toUpperCase(),
        result: Object.prototype.hasOwnProperty.call(step, "result")
          && typeof scriptedResult !== "function"
          && !(scriptedResult && typeof scriptedResult.then === "function")
          ? assertTypedResult(scriptedResult)
          : scriptedResult,
      });
    });
    this._calls = [];
  }

  get calls() {
    return Object.freeze(this._calls.slice());
  }

  remaining() {
    return this._steps.length;
  }

  assertExhausted() {
    if (this._steps.length !== 0) {
      throw new Error("Scripted Cloudsmith API has unconsumed steps");
    }
  }

  get(endpoint, options = {}) {
    return this._consume("GET", "v1", endpoint, undefined, options);
  }

  getV2(endpoint, options = {}) {
    return this._consume("GET", "v2", endpoint, undefined, options);
  }

  post(endpoint, json, options = {}) {
    return this._consume("POST", options.apiVersion || "v1", endpoint, json, options);
  }

  request(endpoint, options = {}) {
    return this._consume(
      String(options.method || "GET").toUpperCase(),
      options.apiVersion || "v1",
      endpoint,
      options.json,
      options,
    );
  }

  async _consume(method, apiVersion, endpoint, json, options) {
    const step = this._steps.shift();
    if (!step) throw new Error("Scripted Cloudsmith API received an unexpected request");
    if (step.method !== method || step.apiVersion !== apiVersion) {
      throw new Error("Scripted Cloudsmith API request did not match the next step");
    }
    if (step.endpoint !== undefined) {
      const matches = typeof step.endpoint === "function"
        ? step.endpoint(endpoint)
        : step.endpoint === endpoint;
      if (!matches) throw new Error("Scripted Cloudsmith API endpoint did not match the next step");
    }
    // Retain only request shape. Credential-bearing option and body values must
    // never survive in helper diagnostics or assertion snapshots.
    const call = Object.freeze({
      apiVersion,
      endpoint: summarizeEndpoint(endpoint),
      jsonKeys: objectKeys(json),
      method,
      optionKeys: objectKeys(options).filter(key => key !== "apiKey"),
    });
    this._calls.push(call);
    if (step.error !== undefined) throw step.error;
    const result = typeof step.result === "function" ? step.result(call) : step.result;
    return assertTypedResult(await result);
  }
}

function objectKeys(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return Object.freeze([]);
  return Object.freeze(Object.keys(value).sort());
}

function summarizeEndpoint(endpoint) {
  try {
    const parsed = new URL(String(endpoint), "https://scripted.invalid/");
    const segments = parsed.pathname.split("/").filter(Boolean);
    return Object.freeze({
      pathSegmentCount: segments.length,
      queryKeys: Object.freeze([...new Set(parsed.searchParams.keys())].sort()),
    });
  } catch {
    return Object.freeze({ pathSegmentCount: 0, queryKeys: Object.freeze([]) });
  }
}

module.exports = { ScriptedCloudsmithAPI, assertTypedResult, deepFreeze };

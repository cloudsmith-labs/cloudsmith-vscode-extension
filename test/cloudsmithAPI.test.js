const assert = require("assert");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");

const API_KEY = "csa_test_transport_secret_value";

function jsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function textResponse(body, status = 200, headers = {}) {
  return new Response(body, { status, headers });
}

function createApi(fetchImpl, options = {}) {
  return new CloudsmithAPI({}, {
    fetchImpl,
    credentialManager: options.credentialManager || {
      async getApiKey() {
        return API_KEY;
      },
    },
    randomUUID: () => "logical-request-id",
    ...(options.setTimeout ? { setTimeout: options.setTimeout } : {}),
    ...(options.clearTimeout ? { clearTimeout: options.clearTimeout } : {}),
    ...(options.now ? { now: options.now } : {}),
  });
}

function nextTurn() {
  return new Promise(resolve => setImmediate(resolve));
}

suite("CloudsmithAPI typed transport", () => {
  test("returns typed JSON success metadata and a frozen allowlisted header snapshot", async () => {
    const api = createApi(async (_url, request) => {
      assert.strictEqual(request.headers["X-Api-Key"], API_KEY);
      assert.strictEqual(request.redirect, "manual");
      return jsonResponse([{ slug: "workspace" }], 200, {
        "x-request-id": "server-request-id",
        "x-pagination-page": "1",
        "set-cookie": "sensitive=true",
      });
    });

    const result = await api.get("namespaces/", {
      responseType: "array",
      validate: value => value.every(item => typeof item.slug === "string"),
    });

    assert.strictEqual(result.ok, true);
    assert.deepStrictEqual(result.data, [{ slug: "workspace" }]);
    assert.strictEqual(result.status, 200);
    assert.strictEqual(result.requestId, "logical-request-id");
    assert.strictEqual(result.serverRequestId, "server-request-id");
    assert.strictEqual(result.headers["x-pagination-page"], "1");
    assert.strictEqual(result.headers["set-cookie"], undefined);
    assert.strictEqual(Object.isFrozen(result), true);
    assert.strictEqual(Object.isFrozen(result.headers), true);
    assert.strictEqual(Reflect.set(result.headers, "x-pagination-page", "2"), false);
  });

  test("supports 201 JSON, explicit 204 empty, and explicitly expected primitive JSON", async () => {
    const responses = [
      jsonResponse({ copied: true }, 201),
      new Response(null, { status: 204 }),
      jsonResponse("primitive-value"),
    ];
    const api = createApi(async () => responses.shift());

    const created = await api.post("packages/workspace/repo/pkg/copy/", {}, {
      responseType: "object",
    });
    const empty = await api.request("packages/workspace/repo/pkg/tag/", {
      method: "POST",
      apiVersion: "v1",
      json: {},
      responseType: "empty",
    });
    const primitive = await api.get("user/self", { responseType: "json" });

    assert.strictEqual(created.ok, true);
    assert.strictEqual(created.status, 201);
    assert.strictEqual(empty.ok, true);
    assert.strictEqual(empty.data, null);
    assert.strictEqual(primitive.ok, true);
    assert.strictEqual(primitive.data, "primitive-value");
  });

  test("maps invalid JSON, content type, response shape, and validator failures", async () => {
    const responses = [
      textResponse("{bad", 200, { "content-type": "application/json" }),
      textResponse("{}", 200, { "content-type": "text/html" }),
      jsonResponse({ results: [] }),
      jsonResponse([{ slug: "workspace" }]),
    ];
    const api = createApi(async () => responses.shift());

    const invalidJson = await api.get("namespaces/", { responseType: "array" });
    const wrongType = await api.get("namespaces/", { responseType: "object" });
    const wrongShape = await api.get("namespaces/", { responseType: "array" });
    const throwingValidator = await api.get("namespaces/", {
      responseType: "array",
      validate() {
        throw new Error("validator failed");
      },
    });

    for (const result of [invalidJson, wrongType, wrongShape, throwingValidator]) {
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.error.kind, "invalid_response");
    }
  });

  test("maps representative HTTP failures without retaining response bodies", async () => {
    const cases = [
      [400, "http_error"],
      [401, "unauthorized"],
      [403, "forbidden"],
      [404, "not_found"],
      [429, "rate_limited"],
      [500, "server_error"],
      [502, "server_error"],
      [503, "server_error"],
    ];

    for (const [status, kind] of cases) {
      const api = createApi(async () => textResponse(
        `private response ${API_KEY} Authorization: bearer-secret`,
        status,
        { "content-type": "text/plain" }
      ));
      const result = await api.get("packages/workspace/");
      const serialized = JSON.stringify(result);

      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.status, status);
      assert.strictEqual(result.error.kind, kind);
      assert.doesNotMatch(serialized, /private response|bearer-secret/);
      assert.doesNotMatch(serialized, new RegExp(API_KEY));
    }
  });

  test("classifies a network failure without serializing exception secrets", async () => {
    const api = createApi(async () => {
      const error = new Error(`fetch failed for https://api.cloudsmith.io/?token=${API_KEY}`);
      error.code = "ENOTFOUND";
      throw error;
    });

    const result = await api.get("packages/workspace/");

    assert.strictEqual(result.error.kind, "network_error");
    assert.strictEqual(result.error.diagnostic.causeCode, "ENOTFOUND");
    assert.doesNotMatch(JSON.stringify(result), new RegExp(API_KEY));
    assert.doesNotMatch(JSON.stringify(result), /token=/);
  });

  test("aborts the actual fetch on timeout and clears the deadline timer", async () => {
    let fetchWasAborted = false;
    let clearedTimers = 0;
    const api = createApi((_url, request) => new Promise((_resolve, reject) => {
      request.signal.addEventListener("abort", () => {
        fetchWasAborted = true;
        reject(new DOMException("aborted", "AbortError"));
      }, { once: true });
    }), {
      clearTimeout(handle) {
        clearedTimers += 1;
        clearTimeout(handle);
      },
    });

    const result = await api.get("packages/workspace/", { timeoutMs: 10 });

    assert.strictEqual(result.error.kind, "timeout");
    assert.strictEqual(fetchWasAborted, true);
    assert.strictEqual(clearedTimers, 1);
  });

  test("timeout settles hanging credential lookup and ignored late fetch success", async () => {
    let credentialTimeout;
    let fetchCalls = 0;
    const credentialApi = createApi(async () => {
      fetchCalls += 1;
      return jsonResponse({ authenticated: true });
    }, {
      credentialManager: { getApiKey() { return new Promise(() => {}); } },
      setTimeout(callback) { credentialTimeout = callback; return {}; },
      clearTimeout() {},
    });
    const credentialPending = credentialApi.get("user/self", { responseType: "object" });
    await nextTurn();
    credentialTimeout();
    const credentialResult = await credentialPending;
    assert.strictEqual(credentialResult.error.kind, "timeout");
    assert.strictEqual(fetchCalls, 0);

    let fetchTimeout;
    let lateResolve;
    let lateCancelCalled = false;
    const lateApi = createApi(async () => new Promise(resolve => { lateResolve = resolve; }), {
      setTimeout(callback) { fetchTimeout = callback; return {}; },
      clearTimeout() {},
    });
    const latePending = lateApi.get("user/self", { responseType: "object" });
    await nextTurn();
    fetchTimeout();
    const lateResult = await latePending;
    assert.strictEqual(lateResult.error.kind, "timeout");
    lateResolve({
      status: 200,
      ok: true,
      headers: new Headers({ "content-type": "application/json" }),
      body: { cancel() { lateCancelCalled = true; return new Promise(() => {}); } },
    });
    await nextTurn();
    assert.strictEqual(lateCancelCalled, true);
  });

  test("elapsed absolute deadline wins even when the timeout callback is delayed", async () => {
    let now = 1_000;
    const api = createApi(async () => {
      now = 1_011;
      return jsonResponse({ authenticated: true });
    }, {
      now: () => now,
      setTimeout() { return {}; },
      clearTimeout() {},
    });

    const result = await api.get("user/self", { responseType: "object", timeoutMs: 10 });

    assert.strictEqual(result.error.kind, "timeout");
  });

  test("pre-cancellation makes no fetch and disposes the cancellation listener", async () => {
    let fetchCalls = 0;
    let listeners = 0;
    let disposals = 0;
    const token = {
      isCancellationRequested: true,
      onCancellationRequested() {
        listeners += 1;
        return { dispose() { disposals += 1; } };
      },
    };
    const api = createApi(async () => {
      fetchCalls += 1;
      return jsonResponse({});
    });

    const result = await api.get("user/self", { cancellationToken: token });

    assert.strictEqual(result.error.kind, "cancelled");
    assert.strictEqual(fetchCalls, 0);
    assert.strictEqual(listeners, 1);
    assert.strictEqual(disposals, 1);
  });

  test("removes an external abort listener on successful completion", async () => {
    let added = 0;
    let removed = 0;
    const signal = {
      aborted: false,
      addEventListener(event, listener) {
        assert.strictEqual(event, "abort");
        assert.strictEqual(typeof listener, "function");
        added += 1;
      },
      removeEventListener(event, listener) {
        assert.strictEqual(event, "abort");
        assert.strictEqual(typeof listener, "function");
        removed += 1;
      },
    };
    const api = createApi(async () => jsonResponse({ authenticated: true }));

    const result = await api.get("user/self", { signal, responseType: "object" });

    assert.strictEqual(result.ok, true);
    assert.strictEqual(added, 1);
    assert.strictEqual(removed, 1);
  });

  test("redacts secrets from allowlisted server correlation headers", async () => {
    const api = createApi(async () => jsonResponse({}, 200, {
      "x-request-id": `server-${API_KEY}`,
    }));

    const result = await api.get("user/self", { responseType: "object" });

    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.serverRequestId, "server-[REDACTED]");
    assert.doesNotMatch(JSON.stringify(result), new RegExp(API_KEY));
  });

  test("the first abort cause wins a timeout and user-cancel race", async () => {
    let deadlineCallback;
    const external = new AbortController();
    const api = createApi((_url, request) => new Promise((_resolve, reject) => {
      request.signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
    }), {
      setTimeout(callback, delay) {
        if (delay === 1000) deadlineCallback = callback;
        return { delay };
      },
      clearTimeout() {},
    });

    const pending = api.get("user/self", { timeoutMs: 1000, signal: external.signal });
    await nextTurn();
    deadlineCallback();
    external.abort();
    const result = await pending;

    assert.strictEqual(result.error.kind, "timeout");
  });

  test("retries an opted-in safe read and caps attempts at three", async () => {
    let successCalls = 0;
    const successApi = createApi(async () => {
      successCalls += 1;
      return successCalls === 1
        ? textResponse("busy", 503, { "retry-after": "0" })
        : jsonResponse({ authenticated: true });
    });
    const eventual = await successApi.get("user/self", {
      responseType: "object",
      retry: "safe-read",
    });

    let cappedCalls = 0;
    const cappedApi = createApi(async () => {
      cappedCalls += 1;
      return textResponse("busy", 503, { "retry-after": "0" });
    });
    const capped = await cappedApi.get("user/self", { retry: "safe-read" });

    assert.strictEqual(eventual.ok, true);
    assert.strictEqual(eventual.attempts, 2);
    assert.strictEqual(successCalls, 2);
    assert.strictEqual(capped.ok, false);
    assert.strictEqual(capped.attempts, 3);
    assert.strictEqual(cappedCalls, 3);
  });

  test("honors Retry-After seconds and HTTP-date but rejects excessive delays", async () => {
    const now = Date.parse("2026-08-09T12:00:00.000Z");
    for (const [retryAfter, expectedDelay] of [
      ["1", 1000],
      [new Date(now + 2000).toUTCString(), 2000],
    ]) {
      const delays = [];
      let calls = 0;
      const api = createApi(async () => {
        calls += 1;
        return calls === 1
          ? textResponse("limited", 429, { "retry-after": retryAfter })
          : jsonResponse({ authenticated: true });
      }, {
        now: () => now,
        setTimeout(callback, delay) {
          if (delay !== 30000) {
            delays.push(delay);
            queueMicrotask(callback);
          }
          return { delay };
        },
        clearTimeout() {},
      });

      const result = await api.get("user/self", { retry: "safe-read" });
      assert.strictEqual(result.ok, true);
      assert.deepStrictEqual(delays, [expectedDelay]);
    }

    let calls = 0;
    const excessiveApi = createApi(async () => {
      calls += 1;
      return textResponse("limited", 429, { "retry-after": "60" });
    });
    const excessive = await excessiveApi.get("user/self", { retry: "safe-read" });
    assert.strictEqual(excessive.error.kind, "rate_limited");
    assert.strictEqual(excessive.error.retryAfterMs, 60000);
    assert.strictEqual(calls, 1);
  });

  test("cancellation during retry backoff clears the delay and stops requests", async () => {
    const controller = new AbortController();
    let calls = 0;
    let retryTimerCleared = false;
    let retryTimerHandle;
    const api = createApi(async () => {
      calls += 1;
      return textResponse("limited", 429, { "retry-after": "1" });
    }, {
      setTimeout(callback, delay) {
        const handle = { callback, delay };
        if (delay === 1000) retryTimerHandle = handle;
        return handle;
      },
      clearTimeout(handle) {
        if (handle === retryTimerHandle) retryTimerCleared = true;
      },
    });

    const pending = api.get("user/self", { retry: "safe-read", signal: controller.signal });
    while (!retryTimerHandle) await nextTurn();
    controller.abort();
    const result = await pending;

    assert.strictEqual(result.error.kind, "cancelled");
    assert.strictEqual(calls, 1);
    assert.strictEqual(retryTimerCleared, true);
  });

  test("follows one same-origin GET redirect and retains credentials only on the validated hop", async () => {
    const calls = [];
    const api = createApi(async (url, request) => {
      calls.push({ url: String(url), key: request.headers["X-Api-Key"] });
      if (calls.length === 1) {
        return textResponse("", 302, { location: "/v1/namespaces/?sort=slug" });
      }
      return jsonResponse([]);
    });

    const result = await api.get("packages/workspace/", { responseType: "array" });

    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.redirectCount, 1);
    assert.strictEqual(calls.length, 2);
    assert.ok(calls[1].url.startsWith("https://api.cloudsmith.io/v1/namespaces/"));
    assert.deepStrictEqual(calls.map(call => call.key), [API_KEY, API_KEY]);
  });

  test("rejects hostile, confused, downgraded, credentialed, and root-escaping redirects", async () => {
    const locations = [
      "https://evil.test/v1/packages/",
      "https://evil.api.cloudsmith.io/v1/packages/",
      "https://api.cloudsmith.io.evil.test/v1/packages/",
      "http://api.cloudsmith.io/v1/packages/",
      "https://user@api.cloudsmith.io/v1/packages/",
      "https://api.cloudsmith.io:444/v1/packages/",
      "https://api.cloudsmith.io/v2/packages/",
      "../../../outside/",
      "https://api.cloudsmith.io./v1/packages/",
    ];

    for (const location of locations) {
      let calls = 0;
      const api = createApi(async () => {
        calls += 1;
        return textResponse("", 302, { location });
      });
      const result = await api.get("packages/workspace/");
      assert.strictEqual(result.error.kind, "redirect_rejected", location);
      assert.strictEqual(calls, 1, location);
    }
  });

  test("rejects redirect loops, extra redirects, and every write redirect without replay", async () => {
    let loopCalls = 0;
    const loopApi = createApi(async () => {
      loopCalls += 1;
      return textResponse("", 302, { location: "/v1/packages/workspace/" });
    });
    const loop = await loopApi.get("packages/workspace/");
    assert.strictEqual(loop.error.kind, "redirect_rejected");
    assert.strictEqual(loopCalls, 1);

    let chainCalls = 0;
    const chainApi = createApi(async () => {
      chainCalls += 1;
      return textResponse("", 302, { location: `packages/workspace/page-${chainCalls}/` });
    });
    const chain = await chainApi.get("packages/workspace/");
    assert.strictEqual(chain.error.kind, "redirect_rejected");
    assert.strictEqual(chainCalls, 2);

    for (const status of [301, 302, 303, 307, 308]) {
      let calls = 0;
      const writeApi = createApi(async () => {
        calls += 1;
        return textResponse("", status, { location: "packages/workspace/repo/pkg/copied/" });
      });
      const result = await writeApi.post("packages/workspace/repo/pkg/copy/", {}, {
        responseType: "object",
      });
      assert.strictEqual(result.error.kind, "redirect_rejected");
      assert.strictEqual(calls, 1);
    }
  });

  test("never retries writes and marks post-dispatch uncertainty", async () => {
    let serverCalls = 0;
    const serverApi = createApi(async () => {
      serverCalls += 1;
      return textResponse("failed", 503);
    });
    const serverResult = await serverApi.post("packages/workspace/repo/pkg/copy/", {}, {
      responseType: "object",
    });

    let malformedCalls = 0;
    const malformedApi = createApi(async () => {
      malformedCalls += 1;
      return textResponse("not-json", 200, { "content-type": "application/json" });
    });
    const malformed = await malformedApi.post("packages/workspace/repo/pkg/tag/", {}, {
      responseType: "object",
    });

    assert.strictEqual(serverCalls, 1);
    assert.strictEqual(serverResult.error.outcomeUnknown, true);
    assert.match(serverResult.error.message, /may have completed/);
    assert.strictEqual(malformedCalls, 1);
    assert.strictEqual(malformed.error.kind, "invalid_response");
    assert.strictEqual(malformed.error.outcomeUnknown, true);
  });

  test("rejects credential-bearing endpoints, empty candidate keys, and oversized success bodies before unsafe use", async () => {
    let calls = 0;
    const api = createApi(async () => {
      calls += 1;
      return jsonResponse({});
    });
    const secretEndpoint = await api.get(`packages/workspace/?token=${API_KEY}`);
    const secretValue = await api.get(`packages/workspace/?query=${API_KEY}`);
    const oldSecretName = await api.get("packages/workspace/?x-api-key=old-secret-value");
    const encodedSecretName = await api.get("packages/workspace/?client%255fsecret=old-secret-value");
    const emptyCandidate = await api.get("user/self", { apiKey: "" });

    assert.strictEqual(secretEndpoint.error.kind, "invalid_request");
    assert.strictEqual(secretValue.error.kind, "invalid_request");
    assert.strictEqual(oldSecretName.error.kind, "invalid_request");
    assert.strictEqual(encodedSecretName.error.kind, "invalid_request");
    assert.strictEqual(emptyCandidate.error.kind, "unauthorized");
    assert.strictEqual(calls, 0);
    assert.doesNotMatch(JSON.stringify(secretEndpoint), new RegExp(API_KEY));
    assert.doesNotMatch(JSON.stringify(secretValue), new RegExp(API_KEY));

    const oversizedApi = createApi(async () => textResponse("{}", 200, {
      "content-type": "application/json",
      "content-length": String(6 * 1024 * 1024),
    }));
    const oversized = await oversizedApi.get("user/self", { responseType: "object" });
    assert.strictEqual(oversized.error.kind, "invalid_response");
  });

  test("rejects stored and candidate keys found at intermediate URL decode layers", async () => {
    let storedCalls = 0;
    const storedApi = createApi(async () => {
      storedCalls += 1;
      return jsonResponse({});
    }, {
      credentialManager: {
        async getApiKey() {
          return "stored%41";
        },
      },
    });
    const storedResult = await storedApi.get("packages/stored%2541/");

    let candidateCalls = 0;
    const candidateApi = createApi(async () => {
      candidateCalls += 1;
      return jsonResponse({});
    });
    const candidateResult = await candidateApi.get("packages/candidate%2541/", {
      apiKey: "candidate%41",
    });

    assert.strictEqual(storedResult.error.kind, "invalid_request");
    assert.strictEqual(candidateResult.error.kind, "invalid_request");
    assert.strictEqual(storedCalls, 0);
    assert.strictEqual(candidateCalls, 0);
    assert.doesNotMatch(JSON.stringify(storedResult), /stored%41/i);
    assert.doesNotMatch(JSON.stringify(candidateResult), /candidate%41/i);
  });

  test("never falls back to unbounded text reads and bounds unknown-length streamed bodies", async () => {
    let textRead = false;
    let bodyCanceled = false;
    const nonStreamingApi = createApi(async () => ({
      status: 200,
      statusText: "OK",
      ok: true,
      headers: new Headers({ "content-type": "application/json" }),
      body: { async cancel() { bodyCanceled = true; } },
      async text() { textRead = true; return JSON.stringify({ authenticated: true }); },
    }));
    const nonStreaming = await nonStreamingApi.get("user/self", { responseType: "object" });
    assert.strictEqual(nonStreaming.error.kind, "invalid_response");
    assert.strictEqual(textRead, false);
    assert.strictEqual(bodyCanceled, true);

    let streamCanceled = false;
    let streamReads = 0;
    const oversizedStreamApi = createApi(async () => ({
      status: 200,
      statusText: "OK",
      ok: true,
      headers: new Headers({ "content-type": "application/json" }),
      body: {
        getReader() {
          return {
            async read() {
              streamReads += 1;
              return { done: false, value: new Uint8Array((5 * 1024 * 1024) + 1) };
            },
            async cancel() { streamCanceled = true; },
            releaseLock() {},
          };
        },
      },
    }));
    const oversizedStream = await oversizedStreamApi.get("user/self", { responseType: "object" });
    assert.strictEqual(oversizedStream.error.kind, "invalid_response");
    assert.strictEqual(streamReads, 1);
    assert.strictEqual(streamCanceled, true);
  });
});

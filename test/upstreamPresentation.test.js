// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const {
  formatUpstreamError,
  formatUpstreamFailureCategory,
  formatUpstreamOrigin,
  formatUpstreamText,
  getTerraformUpstreamUrl,
  normalizeUpstreamFailure,
} = require("../util/upstreamPresentation");

suite("Upstream presentation safety", () => {
  test("normalizes supported error shapes without object, stack, body, or secret exposure", () => {
    assert.strictEqual(formatUpstreamError("Request failed"), "Request failed");
    assert.strictEqual(formatUpstreamError(new Error("Request failed")), "Request failed");
    assert.strictEqual(
      formatUpstreamError({ message: "Upstream request failed", status: 500 }),
      "Upstream request failed"
    );
    assert.strictEqual(
      formatUpstreamError({ message: "unexpected response", body: "private body" }),
      "Upstream availability could not be determined."
    );
    assert.strictEqual(
      formatUpstreamError(new Error("https://user:pass@example.com/path?token=secret")),
      "Upstream availability could not be determined."
    );
    assert.strictEqual(
      formatUpstreamError({ message: "<script>alert(1)</script>" }),
      "Upstream availability could not be determined."
    );
    assert.strictEqual(formatUpstreamError(null), "Upstream availability could not be determined.");
    assert.strictEqual(
      formatUpstreamError("Request failed".repeat(100_000)),
      "Upstream availability could not be determined."
    );
    for (const kind of ["toString", "constructor", "__proto__"]) {
      assert.strictEqual(
        formatUpstreamError({ kind }),
        "Upstream availability could not be determined.",
        kind
      );
    }
    assert.strictEqual(
      formatUpstreamError({ unexpected: true }, "toString"),
      "Upstream availability could not be determined."
    );

    const hostile = new Proxy({}, {
      get() { throw new Error("secret stack"); },
      getOwnPropertyDescriptor() { throw new Error("secret body"); },
    });
    assert.strictEqual(
      formatUpstreamError(hostile),
      "Upstream availability could not be determined."
    );
  });

  test("normalizes upstream failure categories with fixed safe copy", () => {
    const cases = [
      [{ kind: "unauthorized" }, "authentication"],
      [{ kind: "auth" }, "authentication"],
      [{ status: 401 }, "authentication"],
      [{ kind: "forbidden" }, "permission"],
      [{ status: 403 }, "permission"],
      [{ kind: "not_found" }, "not_found"],
      [{ status: 404 }, "not_found"],
      [{ kind: "timeout" }, "timeout"],
      [{ status: 408 }, "timeout"],
      [{ kind: "rate_limited" }, "rate_limit"],
      [{ kind: "rate_limit_circuit" }, "rate_limit"],
      [{ status: 429 }, "rate_limit"],
      [{ kind: "server_error" }, "server"],
      [{ status: 503 }, "server"],
      [{ kind: "network_error" }, "network"],
      [{ kind: "transport_failure" }, "network"],
      [{ kind: "invalid_response" }, "invalid_response"],
      [{ kind: "cancelled" }, "cancelled"],
      [{ name: "AbortError" }, "cancelled"],
      [{ code: "ABORT_ERR" }, "cancelled"],
      [{ kind: "invalid_request" }, "request_rejected"],
      [{ kind: "redirect_rejected" }, "request_rejected"],
      [{ status: 422 }, "request_rejected"],
      [{ kind: "request_limit" }, "request_limit"],
      [{ kind: "resource_limit" }, "request_limit"],
      [{ kind: "uninspected" }, "uninspected"],
      [new Error("unknown https://user:pass@example.com/?token=secret"), "unknown"],
    ];

    for (const [error, category] of cases) {
      const normalized = normalizeUpstreamFailure(error);
      assert.strictEqual(normalized.category, category);
      assert.strictEqual(normalized.message, formatUpstreamFailureCategory(category));
      assert.ok(!normalized.message.includes("[object Object]"));
      assert.ok(!normalized.message.includes("secret"));
    }

    assert.strictEqual(
      formatUpstreamFailureCategory("constructor"),
      "Upstream availability could not be determined."
    );
  });

  test("retains only validated failure metadata and ignores hostile properties", () => {
    const normalized = normalizeUpstreamFailure({
      ok: false,
      status: 429,
      requestId: "local-request-1234",
      serverRequestId: "0123456789abcdef-IAD",
      headers: { authorization: "Bearer secret" },
      diagnostic: { url: "https://user:pass@example.com/?token=secret" },
      error: {
        kind: "rate_limited",
        status: 429,
        retryable: true,
        retryAfterMs: 2500,
        requestId: "local-request-1234",
        message: "token=secret",
        cause: new Error("api-key=secret"),
        stack: "private stack",
      },
    });
    assert.deepStrictEqual(normalized, {
      category: "rate_limit",
      message: "Cloudsmith rate limited the upstream request. Try again later.",
      httpStatus: 429,
      retryable: true,
      retryAfterMs: 2500,
      requestId: "local-request-1234",
      serverRequestId: "0123456789abcdef-IAD",
    });
    assert.ok(Object.isFrozen(normalized));

    const malformed = normalizeUpstreamFailure({
      status: "429",
      requestId: "https://example.com/?token=secret",
      serverRequestId: "bad id with spaces",
      error: {
        retryable: "true",
        retryAfterMs: 24 * 60 * 60 * 1000 + 1,
      },
    });
    assert.deepStrictEqual(malformed, {
      category: "unknown",
      message: "Upstream availability could not be determined.",
      httpStatus: null,
      retryable: false,
      retryAfterMs: null,
      requestId: null,
      serverRequestId: null,
    });

    const hostile = new Proxy({}, {
      get(_target, property) {
        if (property === "kind") return "timeout";
        throw new Error(`secret from ${String(property)}`);
      },
    });
    const hostileNormalized = normalizeUpstreamFailure(hostile);
    assert.strictEqual(hostileNormalized.category, "timeout");
    assert.strictEqual(hostileNormalized.message, "The upstream request timed out.");
    assert.strictEqual(hostileNormalized.requestId, null);
    assert.strictEqual(hostileNormalized.serverRequestId, null);
  });

  test("projects only safe HTTP origins and fails closed", () => {
    const cases = [
      ["https://example.com/path", "https://example.com"],
      ["https://user:pass@example.com/path", "https://example.com"],
      ["https://example.com/path?token=secret", "https://example.com"],
      ["https://example.com/path#fragment", "https://example.com"],
      ["https://example.com/object?X-Amz-Signature=signed", "https://example.com"],
      ["https://example.com:8443/path", "https://example.com:8443"],
      ["http://example.com/path", "http://example.com"],
      ["not a URL", "Origin unavailable"],
      ["/relative/path", "Origin unavailable"],
      ["file:///tmp/secret", "Origin unavailable"],
      ["data:text/plain,secret", "Origin unavailable"],
      ["javascript:alert(1)", "Origin unavailable"],
      ["https:example.com/path", "Origin unavailable"],
      ["https:///example.com/path", "Origin unavailable"],
      ["https:////example.com/path", "Origin unavailable"],
      ["https://example.com/path\\other", "Origin unavailable"],
      [" https://example.com/path", "Origin unavailable"],
      ["https://example.com/path\u202esecret", "Origin unavailable"],
    ];

    for (const [input, expected] of cases) {
      assert.strictEqual(formatUpstreamOrigin(input), expected, input);
    }
  });

  test("bounds and neutralizes controls in presentation text before transformation", () => {
    const huge = `${"a".repeat(1_000_000)}\u202eprivate\nvalue`;
    const formatted = formatUpstreamText(huge);
    assert.strictEqual(formatted.length, 500);
    assert.ok(!formatted.includes("\u202e"));
    assert.ok(!formatted.includes("\n"));
    assert.strictEqual(formatUpstreamText({ value: "secret" }, "Unknown"), "Unknown");
    assert.strictEqual(getTerraformUpstreamUrl(`https://example.com/${"a".repeat(9000)}`), null);
  });

  test("validates Terraform URLs without semantic secret stripping", () => {
    assert.strictEqual(getTerraformUpstreamUrl("https://example.com/"), "https://example.com");
    assert.strictEqual(
      getTerraformUpstreamUrl("https://example.com:8443/simple/%3Fencoded"),
      "https://example.com:8443/simple/%3Fencoded"
    );
    assert.strictEqual(
      getTerraformUpstreamUrl("https://example.com/simple/%40encoded"),
      "https://example.com/simple/%40encoded"
    );
    for (const input of [
      "https://user:pass@example.com/path",
      "https://@example.com/path",
      "https://:@example.com/path",
      "https://example.com/path?",
      "https://example.com/path#",
      "https://example.com/path?token=secret",
      "https://example.com/path\\other",
      "https:example.com/path",
      "https:///example.com/path",
      "https:////example.com/path",
      "https://example.com/%2e%2e/secret",
      " https://example.com/path",
      "file:///tmp/secret",
      "not a URL",
    ]) {
      assert.strictEqual(getTerraformUpstreamUrl(input), null, input);
    }
  });
});

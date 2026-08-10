// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const {
  formatUpstreamError,
  formatUpstreamOrigin,
  formatUpstreamText,
  getTerraformUpstreamUrl,
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

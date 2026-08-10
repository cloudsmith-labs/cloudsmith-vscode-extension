const assert = require("assert");
const {
  MAX_POLICY_STATUS_REASON_LENGTH,
  fetchPackageDecisionLogs,
  normalizePolicyStatusReason,
  parsePolicyStatusReason,
} = require("../util/policyDecisionLogs");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");

suite("Policy decision log collection", () => {
  function page(data, pageNumber, pageTotal, count = 101) {
    return apiSuccess({ results: data }, {
      headers: {
        "x-pagination-page": String(pageNumber),
        "x-pagination-pagetotal": String(pageTotal),
        "x-pagination-pagesize": "100",
        "x-pagination-count": String(count),
      },
    });
  }

  function log(index, packageIdentifier = "other-package") {
    return {
      slug_perm: `decision-${index}`,
      package: { identifier: packageIdentifier },
      policy_name: "Policy",
    };
  }

  test("finds a package decision on a later page without returning unrelated entries", async () => {
    const calls = [];
    const firstPage = Array.from({ length: 100 }, (_, index) => log(index));
    const api = {
      async getV2(endpoint, options) {
        calls.push(endpoint);
        const pageNumber = Number(new URL(endpoint, "https://example.invalid").searchParams.get("page"));
        const response = pageNumber === 1
          ? page(firstPage, 1, 2)
          : page([log(100, "target-package")], 2, 2);
        assert.strictEqual(options.validate(response.data), true);
        return response;
      },
    };

    const result = await fetchPackageDecisionLogs(api, "workspace-a", "target-package");

    assert.strictEqual(result.complete, true);
    assert.strictEqual(result.pageCount, 2);
    assert.deepStrictEqual(result.items.map(item => item.slug_perm), ["decision-100"]);
    assert.strictEqual(result.items[0].matched, null);
    assert.strictEqual(calls.length, 2);
  });

  test("preserves matching decisions from successful pages and marks later failure partial", async () => {
    const firstPage = [log(0, "target-package"), ...Array.from(
      { length: 99 },
      (_, index) => log(index + 1)
    )];
    const api = {
      async getV2(endpoint) {
        const pageNumber = Number(new URL(endpoint, "https://example.invalid").searchParams.get("page"));
        return pageNumber === 1
          ? page(firstPage, 1, 2)
          : apiFailure("rate_limited", { status: 429, retryable: true });
      },
    };

    const result = await fetchPackageDecisionLogs(api, "workspace-a", "target-package");

    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.partial, true);
    assert.strictEqual(result.failureCount, 1);
    assert.deepStrictEqual(result.items.map(item => item.slug_perm), ["decision-0"]);
  });

  test("bounds status reasons before parsing policy text", () => {
    const hostile = `Quarantined by Policy. ${"x".repeat(10000)} (Policy: policy-a)`;
    const normalized = normalizePolicyStatusReason(hostile);
    const parsed = parsePolicyStatusReason(hostile);

    assert.strictEqual(normalized.length, MAX_POLICY_STATUS_REASON_LENGTH);
    assert.ok(parsed);
    assert.ok(JSON.stringify(parsed).length <= MAX_POLICY_STATUS_REASON_LENGTH + 100);
  });

  test("rejects a decision log slug beyond the shared identity bound", async () => {
    const result = await fetchPackageDecisionLogs({
      async getV2(_endpoint, options) {
        const data = {
          results: [{
            slug_perm: "x".repeat(513),
            package: { identifier: "target-package" },
          }],
        };
        assert.strictEqual(options.validate(data), false);
        return apiFailure("invalid_response", { status: 200 });
      },
    }, "workspace-a", "target-package");

    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.failures[0].error.kind, "invalid_response");
  });

  test("rejects an overlong requested package reference before dispatch", async () => {
    let calls = 0;
    const result = await fetchPackageDecisionLogs({
      async getV2() { calls += 1; throw new Error("must not dispatch"); },
    }, "workspace-a", "x".repeat(513));

    assert.strictEqual(calls, 0);
    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.termination, "invalid_request");
  });

  test("rejects conflicting package reference aliases instead of attributing the decision", async () => {
    const conflicting = {
      slug_perm: "decision-conflicting",
      package_slug_perm: "target-package",
      package: { identifier: "different-package" },
    };
    const result = await fetchPackageDecisionLogs({
      async getV2(_endpoint, options) {
        const data = { results: [conflicting] };
        assert.strictEqual(options.validate(data), false);
        return apiFailure("invalid_response", { status: 200 });
      },
    }, "workspace-a", "target-package");

    assert.strictEqual(result.complete, false);
    assert.deepStrictEqual(result.items, []);
    assert.strictEqual(result.failures[0].error.kind, "invalid_response");
  });

  test("rejects a malformed matched decision instead of normalizing it to false", async () => {
    const result = await fetchPackageDecisionLogs({
      async getV2(_endpoint, options) {
        const data = { results: [{
          slug_perm: "decision-malformed-match",
          package_slug_perm: "target-package",
          matched: "false",
        }] };
        assert.strictEqual(options.validate(data), false);
        return apiFailure("invalid_response", { status: 200 });
      },
    }, "workspace-a", "target-package");

    assert.strictEqual(result.complete, false);
    assert.deepStrictEqual(result.items, []);
    assert.strictEqual(result.failures[0].error.kind, "invalid_response");
  });
});

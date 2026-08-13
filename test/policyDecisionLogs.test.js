const assert = require("assert");
const {
  MAX_POLICY_STATUS_REASON_LENGTH,
  createQuarantineLocator,
  fetchDecisionLogDetail,
  fetchPackageDecisionLogs,
  hasQuarantineAction,
  normalizePolicyStatusReason,
  parsePolicyStatusReason,
  selectCausalDecision,
} = require("../util/policyDecisionLogs");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");

suite("Policy decision log collection", () => {
  function page(data, pageNumber = 1, pageTotal = 1, count = data.length) {
    return apiSuccess({ results: data }, {
      headers: {
        "x-pagination-page": String(pageNumber),
        "x-pagination-pagetotal": String(pageTotal),
        "x-pagination-pagesize": "100",
        "x-pagination-count": String(count),
      },
    });
  }

  function summary(index, overrides = {}) {
    return {
      id: String(index).padStart(26, "0"),
      actions: { action_type: "SetPackageState", package_state: "QUARANTINED" },
      correlation_id: `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`,
      ended_at: `2026-08-13T12:${String(index % 60).padStart(2, "0")}:01.000Z`,
      match: true,
      package_format: "NPM",
      package_name: "artifact",
      package_slug: "artifact",
      package_slug_perm: "package-a",
      package_version: "1.0.0",
      policy_is_terminal: true,
      policy_name: "Quarantine policy",
      policy_precedence: 1,
      policy_slug_perm: "policy-a",
      policy_version: 1,
      repository_name: "Repository A",
      repository_slug: "repo-a",
      repository_slug_perm: "repo-perm-a",
      started_at: `2026-08-13T12:${String(index % 60).padStart(2, "0")}:00.000Z`,
      ...overrides,
    };
  }

  const locator = Object.freeze({
    workspace: "workspace-a",
    repository: "repo-a",
    packageSlugPerm: "package-a",
  });
  const createdAfter = "2026-08-13T10:00:00.000Z";

  test("uses the current filtered endpoint and exact bounded query", async () => {
    const calls = [];
    const api = {
      async getV2(endpoint, options) {
        calls.push({ endpoint, options });
        return page([summary(1)]);
      },
    };
    const result = await fetchPackageDecisionLogs(api, locator, createdAfter, {
      policySlug: "policy-a",
      repositorySlugPerm: "repo-perm-a",
    });

    assert.strictEqual(result.complete, true);
    assert.strictEqual(result.items.length, 1);
    const url = new URL(calls[0].endpoint, "https://api.invalid/");
    assert.strictEqual(url.pathname, "/workspaces/workspace-a/policies/decision-logs-v1/");
    assert.deepStrictEqual([...url.searchParams.keys()].sort(), [
      "created_after", "match", "package_slug_perm", "page", "page_size",
      "policy_slug_perm", "repository_slug_perm", "sort",
    ].sort());
    assert.strictEqual(url.searchParams.get("created_after"), createdAfter);
    assert.strictEqual(url.searchParams.get("package_slug_perm"), "package-a");
    assert.strictEqual(url.searchParams.get("repository_slug_perm"), "repo-perm-a");
    assert.strictEqual(url.searchParams.get("match"), "true");
    assert.strictEqual(url.searchParams.get("sort"), "-id");
    assert.strictEqual(calls[0].options.retry, "never");
  });

  test("finds a causal record on a later numeric page", async () => {
    const first = Array.from({ length: 100 }, (_, index) => summary(index + 1, {
      actions: {},
    }));
    const calls = [];
    const api = {
      async getV2(endpoint) {
        const pageNumber = Number(new URL(endpoint, "https://api.invalid/").searchParams.get("page"));
        calls.push(pageNumber);
        return pageNumber === 1
          ? page(first, 1, 2, 101)
          : page([summary(101)], 2, 2, 101);
      },
    };
    const result = await fetchPackageDecisionLogs(api, locator, createdAfter);
    const selected = selectCausalDecision(result.items);

    assert.strictEqual(result.complete, true);
    assert.deepStrictEqual(calls, [1, 2]);
    assert.strictEqual(selected.id, summary(101).id);
  });

  test("selects the newest exact quarantine decision deterministically", () => {
    const records = [summary(2), summary(3, { policy_slug_perm: "policy-b" }), summary(1)]
      .map(value => ({
        id: value.id,
        match: value.match,
        action: "Quarantined",
        policySlugPerm: value.policy_slug_perm,
      }));
    assert.strictEqual(selectCausalDecision(records).id, summary(3).id);
    assert.strictEqual(selectCausalDecision(records, "policy-a").id, summary(2).id);
  });

  test("does not turn an incomplete empty collection into an authoritative match", async () => {
    const api = {
      async getV2() { return apiFailure("rate_limited", { status: 429, retryable: true }); },
    };
    const result = await fetchPackageDecisionLogs(api, locator, createdAfter);
    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.incomplete, true);
    assert.strictEqual(selectCausalDecision(result.items), null);
  });

  test("retains representative typed HTTP failures without retrying", async () => {
    for (const [kind, status] of [
      ["authentication", 401],
      ["permission", 403],
      ["not_found", 404],
      ["rate_limited", 429],
      ["server_error", 500],
      ["server_error", 503],
    ]) {
      let calls = 0;
      const result = await fetchPackageDecisionLogs({
        async getV2(_endpoint, options) {
          calls += 1;
          assert.strictEqual(options.retry, "never");
          return apiFailure(kind, { status, retryable: status === 429 || status >= 500 });
        },
      }, locator, createdAfter);
      assert.strictEqual(calls, 1);
      assert.strictEqual(result.complete, false);
      assert.strictEqual(result.failures[0].error.kind, kind);
      assert.strictEqual(result.failures[0].error.status, status);
    }
  });

  test("preserves an earlier page and marks a later failure partial", async () => {
    const first = [summary(1), ...Array.from({ length: 99 }, (_, index) => summary(index + 2, {
      actions: {},
    }))];
    const api = {
      async getV2(endpoint) {
        const pageNumber = Number(new URL(endpoint, "https://api.invalid/").searchParams.get("page"));
        return pageNumber === 1
          ? page(first, 1, 2, 101)
          : apiFailure("server", { status: 503, retryable: true });
      },
    };
    const result = await fetchPackageDecisionLogs(api, locator, createdAfter);
    assert.strictEqual(result.partial, true);
    assert.strictEqual(result.failureCount, 1);
    assert.strictEqual(selectCausalDecision(result.items).id, summary(1).id);
  });

  test("duplicate IDs across pages terminate incomplete", async () => {
    const first = Array.from({ length: 100 }, (_, index) => summary(index + 1));
    const api = {
      async getV2(endpoint) {
        const pageNumber = Number(new URL(endpoint, "https://api.invalid/").searchParams.get("page"));
        return pageNumber === 1
          ? page(first, 1, 2, 101)
          : page([summary(1)], 2, 2, 101);
      },
    };
    const result = await fetchPackageDecisionLogs(api, locator, createdAfter);
    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.incomplete, true);
    assert.strictEqual(result.items.length, 100);
  });

  test("malformed pagination metadata fails closed", async () => {
    const api = {
      async getV2() {
        return apiSuccess({ results: [summary(1)] }, {
          headers: {
            "x-pagination-page": "2",
            "x-pagination-pagetotal": "1",
            "x-pagination-pagesize": "100",
            "x-pagination-count": "1",
          },
        });
      },
    };
    const result = await fetchPackageDecisionLogs(api, locator, createdAfter);
    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.items.length, 0);
  });

  test("cancellation prevents dispatch", async () => {
    const controller = new AbortController();
    controller.abort();
    let calls = 0;
    const result = await fetchPackageDecisionLogs({
      async getV2() { calls += 1; throw new Error("must not dispatch"); },
    }, locator, createdAfter, { signal: controller.signal });
    assert.strictEqual(calls, 0);
    assert.strictEqual(result.complete, false);
  });

  test("rejects invalid time boundaries and path identities before dispatch", async () => {
    let calls = 0;
    const api = { async getV2() { calls += 1; throw new Error("must not dispatch"); } };
    for (const boundary of [null, "yesterday", " 2026-08-13T10:00:00Z", "x".repeat(129)]) {
      const result = await fetchPackageDecisionLogs(api, locator, boundary);
      assert.strictEqual(result.termination, "invalid_request");
    }
    const invalidLocator = { ...locator, repository: "repo%2Fa" };
    const result = await fetchPackageDecisionLogs(api, invalidLocator, createdAfter);
    assert.strictEqual(result.termination, "invalid_request");
    assert.strictEqual(calls, 0);
  });

  test("rejects malformed current summary fields", async () => {
    for (const malformed of [
      { id: "not-a-ulid" },
      { correlation_id: "not-a-uuid" },
      { match: "true" },
      { repository_slug: {} },
      { policy_slug_perm: [] },
      { started_at: "not-a-date" },
      { actions: [] },
    ]) {
      const api = {
        async getV2(_endpoint, options) {
          const data = { results: [{ ...summary(1), ...malformed }] };
          assert.strictEqual(options.validate(data), false);
          return apiFailure("invalid_response", { status: 200 });
        },
      };
      const result = await fetchPackageDecisionLogs(api, locator, createdAfter);
      assert.strictEqual(result.complete, false);
      assert.deepStrictEqual(result.items, []);
    }
  });

  test("rejects every character excluded from the canonical ULID alphabet", async () => {
    for (const excluded of ["I", "L", "O", "U"]) {
      const api = {
        async getV2(_endpoint, options) {
          const data = { results: [summary(1, { id: `${"0".repeat(25)}${excluded}` })] };
          assert.strictEqual(options.validate(data), false);
          return apiFailure("invalid_response", { status: 200 });
        },
      };
      const result = await fetchPackageDecisionLogs(api, locator, createdAfter);
      assert.strictEqual(result.complete, false);
      assert.deepStrictEqual(result.items, []);
    }
  });

  test("fetches and reconciles only the selected decision detail", async () => {
    const selected = {
      ...selectCausalDecision([{
        id: summary(1).id,
        correlationId: summary(1).correlation_id,
        match: true,
        action: "Quarantined",
        policySlugPerm: "policy-a",
        policyName: "Quarantine policy",
        startedAt: summary(1).started_at,
        endedAt: summary(1).ended_at,
      }]),
    };
    const calls = [];
    const api = {
      async getV2(endpoint, options) {
        calls.push(endpoint);
        const data = detail(selected);
        assert.strictEqual(options.validate(data), true);
        return apiSuccess(data);
      },
    };
    const result = await fetchDecisionLogDetail(api, locator, selected);
    assert.strictEqual(result.action, "Quarantined");
    assert.strictEqual(result.reason, "Dependency rule matched.");
    assert.match(calls[0], new RegExp(`/decision-logs-v1/${selected.id}/`));
  });

  test("rejects mismatched detail identities and unproven invoked actions", async () => {
    const selected = {
      id: summary(1).id,
      correlationId: summary(1).correlation_id,
      policySlugPerm: "policy-a",
      policyName: "Quarantine policy",
      startedAt: summary(1).started_at,
      endedAt: summary(1).ended_at,
    };
    for (const mutate of [
      value => { value.policy.slug_perm = "policy-b"; },
      value => { value.policy_input.v0.workspace.slug = "workspace-b"; },
      value => { value.policy_input.v0.repository.slug = "repo-b"; },
      value => { value.policy_input.v0.package.slug_perm = "package-b"; },
      value => { value.ended_at = "2026-08-13T12:00:02.000Z"; },
      value => { value.parsed_actions = []; },
    ]) {
      const data = detail(selected);
      mutate(data);
      const result = await fetchDecisionLogDetail({
        async getV2(_endpoint, options) {
          if (!options.validate(data)) return apiFailure("invalid_response", { status: 200 });
          return apiSuccess(data);
        },
      }, locator, selected);
      assert.strictEqual(result, null);
    }
  });

  test("canonical locator requires exact agreement between like aliases", () => {
    assert.deepStrictEqual(createQuarantineLocator({
      namespace: "workspace-a",
      cloudsmithWorkspace: "workspace-a",
      repository: "repo-a",
      cloudsmithRepo: "repo-a",
      slug_perm: { value: "package-a" },
      slug_perm_raw: "package-a",
    }), locator);
    assert.strictEqual(createQuarantineLocator({
      namespace: "workspace-a",
      cloudsmithWorkspace: "workspace-b",
      repository: "repo-a",
      slug_perm_raw: "package-a",
    }), null);
    assert.strictEqual(createQuarantineLocator({
      namespace: "workspace-a",
      repository: "repo-a",
      slug_perm: { value: {} },
      slug_perm_raw: "package-a",
    }), null);

    let reads = 0;
    const accessor = {};
    Object.defineProperty(accessor, "value", {
      enumerable: true,
      get() { reads += 1; return "package-a"; },
    });
    assert.strictEqual(createQuarantineLocator({
      namespace: "workspace-a",
      repository: "repo-a",
      slug_perm: accessor,
    }), null);
    assert.strictEqual(reads, 0);

    class PackageLikeNode {
      constructor() {
        this.namespace = "workspace-a";
        this.repository = "repo-a";
        this.slug_perm = { value: "package-a" };
        this.slug_perm_raw = "package-a";
      }
    }
    assert.deepStrictEqual(createQuarantineLocator(new PackageLikeNode()), locator);
  });

  test("bounds status reasons and extracts a canonical policy slug", () => {
    const hostile = `Quarantined by Policy. ${"x".repeat(10000)} (Policy: policy-a)`;
    assert.strictEqual(normalizePolicyStatusReason(hostile).length, MAX_POLICY_STATUS_REASON_LENGTH);
    const parsed = parsePolicyStatusReason(
      "Quarantined by Dependency policy. Dependency rule matched. (Policy: policy-a)"
    );
    assert.strictEqual(parsed.policyName, "Dependency policy");
    assert.strictEqual(parsed.policySlug, "policy-a");
    assert.strictEqual(normalizePolicyStatusReason("Rule\u202e spoofed\nAction"), "Rule  spoofed Action");
  });

  test("accepts only direct action evidence and rejects nested examples", () => {
    assert.strictEqual(hasQuarantineAction({
      action_type: "SetPackageState",
      package_state: "QUARANTINED",
    }), true);
    assert.strictEqual(hasQuarantineAction([{
      action_type: "SetPackageState",
      package_state: "QUARANTINED",
    }]), true);
    assert.strictEqual(hasQuarantineAction({
      example: {
        action_type: "SetPackageState",
        package_state: "QUARANTINED",
      },
    }), false);
  });

  function detail(selected) {
    return {
      id: selected.id,
      correlation_id: selected.correlationId,
      policy: { slug_perm: selected.policySlugPerm },
      started_at: selected.startedAt,
      ended_at: selected.endedAt,
      policy_input: {
        v0: {
          workspace: { slug: "workspace-a", slug_perm: "workspace-perm-a" },
          repository: { slug: "repo-a", slug_perm: "repo-perm-a" },
          package: { slug: "artifact", slug_perm: "package-a" },
        },
      },
      policy_output: { reason: "Dependency rule matched." },
      parsed_actions: [{ action_type: "SetPackageState", package_state: "QUARANTINED" }],
    };
  }
});

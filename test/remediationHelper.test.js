const assert = require("assert");
const { RemediationHelper } = require("../util/remediationHelper");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");

suite("RemediationHelper response validation", () => {
  test("known-fix npm lookup uses an exact safe compatible query and returns the in-scope candidate", async () => {
    const exactCandidate = {
      name: "js-yaml",
      version: "4.2.0",
      format: "npm",
      repository: "repo",
      namespace: "workspace",
      slug_perm: "js-yaml-4-2-0",
      status_str: "Completed",
      deny_policy_violated: false,
    };
    const fuzzySibling = {
      ...exactCandidate,
      name: "js-yaml-helper",
      slug_perm: "js-yaml-helper-4-2-0",
    };
    let observedQuery = "";
    const helper = new RemediationHelper({
      async get(endpoint) {
        observedQuery = decodeURIComponent(endpoint.replace(/\+/g, " "));
        const exact = observedQuery.includes("name:^js-yaml$");
        return apiSuccess(exact ? [exactCandidate] : [exactCandidate, fuzzySibling], {
          headers: paginationHeaders(1, 1, exact ? 1 : 2, 10),
        });
      },
    });

    const result = await helper.findSafeVersions(
      "workspace",
      "repo",
      "js-yaml",
      "npm",
      { currentVersion: "3.14.2", fixedVersions: ["4.2.0"] }
    );

    assert.match(observedQuery, /name:\^js-yaml\$/);
    assert.match(observedQuery, /format:npm/);
    assert.match(observedQuery, /version:>3\.14\.2/);
    assert.match(observedQuery, /version:>=4\.2\.0/);
    assert.match(observedQuery, /vulnerabilities:0/);
    assert.strictEqual(result.success, true);
    assert.deepStrictEqual(result.versions, [exactCandidate]);
  });

  test("scoped and punctuation-bearing identities survive helper query composition", async () => {
    for (const packageName of [
      "@scope/pkg",
      "owner/pkg-name+build",
      "@scope/pkg-name+meta",
    ]) {
      const candidate = {
        name: packageName,
        version: "2.0.0",
        format: "npm",
        repository: "repo",
        namespace: "workspace",
        slug_perm: `candidate-${packageName.length}`,
        status_str: "Completed",
        deny_policy_violated: false,
      };
      let observedQuery;
      const helper = new RemediationHelper({
        async get(endpoint) {
          observedQuery = decodeURIComponent(endpoint.replace(/\+/g, " "));
          return apiSuccess([candidate], {
            headers: paginationHeaders(1, 1, 1, 10),
          });
        },
      });

      const result = await helper.findSafeVersions(
        "workspace",
        "repo",
        packageName,
        "npm"
      );

      assert.ok(
        observedQuery.includes(`query=name:^${packageName}$ AND format:npm`),
        observedQuery
      );
      assert.strictEqual(result.success, true);
      assert.deepStrictEqual(result.versions, [candidate]);
    }
  });

  test("invalid compatibility constraints fail before any package request", async () => {
    let requests = 0;
    const helper = new RemediationHelper({ async get() { requests += 1; } });
    for (const options of [
      { currentVersion: "" },
      { currentVersion: Number.POSITIVE_INFINITY },
      { fixedVersions: "4.2.0" },
      { fixedVersions: ["4.2.0\nstatus:quarantined"] },
    ]) {
      const result = await helper.findSafeVersions(
        "workspace",
        "repo",
        "js-yaml",
        "npm",
        options
      );
      assert.strictEqual(result.success, false);
      assert.deepStrictEqual(result.versions, []);
    }
    assert.strictEqual(requests, 0);
  });

  test("hostile option objects fail closed without invoking accessors or rejecting", async () => {
    let requests = 0;
    let accessorCalls = 0;
    const helper = new RemediationHelper({ async get() { requests += 1; } });
    const accessorOptions = {};
    Object.defineProperty(accessorOptions, "currentVersion", {
      enumerable: true,
      get() {
        accessorCalls += 1;
        throw new Error("compatibility accessor must not run");
      },
    });
    const fixedVersions = [];
    Object.defineProperty(fixedVersions, "0", {
      configurable: true,
      enumerable: true,
      get() {
        accessorCalls += 1;
        throw new Error("fixed-version accessor must not run");
      },
    });
    Object.defineProperty(fixedVersions, "length", { value: 1 });
    const proxyOptions = new Proxy({ currentVersion: "1.0.0" }, {
      getOwnPropertyDescriptor() {
        throw new Error("options descriptor trap must be contained");
      },
    });
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();

    for (const options of [
      accessorOptions,
      { fixedVersions },
      proxyOptions,
      revoked.proxy,
    ]) {
      const result = await helper.findSafeVersions(
        "workspace",
        "repo",
        "js-yaml",
        "npm",
        options
      );
      assert.strictEqual(result.success, false);
      assert.deepStrictEqual(result.versions, []);
    }
    assert.strictEqual(accessorCalls, 0);
    assert.strictEqual(requests, 0);
  });

  test("blank package records cannot be offered as safe versions", async () => {
    const helper = new RemediationHelper({
      async get(_endpoint, options) {
        assert.strictEqual(options.validate([{}]), false);
        assert.strictEqual(options.validate([{
          name: "artifact",
          version: "1.0.0",
          format: "npm",
          repository: "repo",
          namespace: "workspace",
          slug_perm: "artifact-id",
          status_str: "Completed",
        }]), false);
        assert.strictEqual(options.validate([{
          name: "artifact",
          version: "1.0.0",
          format: "npm",
          repository: "repo",
          namespace: "workspace",
          slug_perm: "artifact-id",
          status_str: "Completed",
          deny_policy_violated: false,
        }]), true);
        return apiFailure("invalid_response", { status: 200 });
      },
    });

    const result = await helper.findSafeVersions("workspace", "repo", "artifact", "npm");

    assert.strictEqual(result.success, false);
    assert.strictEqual(result.error.kind, "invalid_response");
    assert.deepStrictEqual(result.versions, []);
  });

  test("returns a truthful newest-ten preview with authoritative total metadata", async () => {
    const versions = Array.from({ length: 10 }, (_, index) => ({
      name: "artifact",
      version: `1.0.${index}`,
      format: "npm",
      repository: "repo",
      namespace: "workspace",
      slug_perm: `artifact-${index}`,
      status_str: "Completed",
      deny_policy_violated: false,
    }));
    const helper = new RemediationHelper({
      async get(endpoint) {
        assert.strictEqual(
          endpoint,
          "packages/workspace/repo/?sort=-version&page=1&page_size=10&query=name%3A%5Eartifact%24+AND+format%3Anpm+AND+vulnerabilities%3A0+AND+NOT+status%3Aquarantined+AND+deny_policy_violated%3Afalse"
        );
        return apiSuccess(versions, {
          headers: paginationHeaders(1, 3, 25, 10),
        });
      },
    });

    const result = await helper.findSafeVersions("workspace", "repo", "artifact", "npm");

    assert.strictEqual(result.success, true);
    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.totalCount, 25);
    assert.strictEqual(result.absenceProven, false);
    assert.strictEqual(result.versions.length, 10);
  });

  test("proves no safe versions only from an authoritative zero count", async () => {
    const helper = new RemediationHelper({
      async get() {
        return apiSuccess([], { headers: paginationHeaders(1, 1, 0, 10) });
      },
    });

    const result = await helper.findSafeVersionsAcrossRepos("workspace", "artifact", "npm");

    assert.strictEqual(result.success, true);
    assert.strictEqual(result.complete, true);
    assert.strictEqual(result.totalCount, 0);
    assert.strictEqual(result.absenceProven, true);
  });

  test("rejects safe-version results outside every exact requested scope field", async () => {
    const candidate = {
      name: "artifact",
      version: "1.0.0",
      format: "npm",
      repository: "repo",
      namespace: "workspace",
      slug_perm: "artifact-id",
      status_str: "Completed",
      deny_policy_violated: false,
    };
    for (const mismatch of [
      { namespace: "other-workspace" },
      { repository: "other-repo" },
      { name: "other-artifact" },
      { format: "python" },
    ]) {
      const helper = new RemediationHelper({
        async get() {
          return apiSuccess([{ ...candidate, ...mismatch }], {
            headers: paginationHeaders(1, 1, 1, 10),
          });
        },
      });

      const result = await helper.findSafeVersions("workspace", "repo", "artifact", "npm");

      assert.strictEqual(result.success, false);
      assert.strictEqual(result.error.kind, "invalid_response");
      assert.strictEqual(result.absenceProven, false);
    }
  });

  test("rejects duplicate safe-version identities instead of publishing repeated choices", async () => {
    const duplicate = {
      name: "artifact",
      version: "1.0.0",
      format: "npm",
      repository: "repo",
      namespace: "workspace",
      slug_perm: "artifact-id",
      status_str: "Completed",
      deny_policy_violated: false,
    };
    const helper = new RemediationHelper({
      async get() {
        return apiSuccess([duplicate, { ...duplicate }], {
          headers: paginationHeaders(1, 1, 2, 10),
        });
      },
    });

    const result = await helper.findSafeVersions("workspace", "repo", "artifact", "npm");

    assert.strictEqual(result.success, false);
    assert.strictEqual(result.error.kind, "invalid_response");
    assert.deepStrictEqual(result.versions, []);
  });
});

function paginationHeaders(page, pageTotal, count, pageSize) {
  return {
    "x-pagination-page": String(page),
    "x-pagination-pagetotal": String(pageTotal),
    "x-pagination-count": String(count),
    "x-pagination-pagesize": String(pageSize),
  };
}

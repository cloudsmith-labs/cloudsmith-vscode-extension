const assert = require("assert");
const { RemediationHelper } = require("../util/remediationHelper");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");

suite("RemediationHelper response validation", () => {
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
    }));
    const helper = new RemediationHelper({
      async get(endpoint) {
        assert.strictEqual(
          endpoint,
          "packages/workspace/repo/?sort=-version&page=1&page_size=10&query=name%3Aartifact+AND+format%3Anpm+AND+NOT+status%3Aquarantined+AND+deny_policy_violated%3Afalse"
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

  test("rejects safe-version results outside the exact requested scope", async () => {
    const helper = new RemediationHelper({
      async get() {
        return apiSuccess([{
          name: "artifact",
          version: "1.0.0",
          format: "npm",
          repository: "other-repo",
          namespace: "workspace",
          slug_perm: "artifact-id",
        }], { headers: paginationHeaders(1, 1, 1, 10) });
      },
    });

    const result = await helper.findSafeVersions("workspace", "repo", "artifact", "npm");

    assert.strictEqual(result.success, false);
    assert.strictEqual(result.error.kind, "invalid_response");
    assert.strictEqual(result.absenceProven, false);
  });

  test("rejects duplicate safe-version identities instead of publishing repeated choices", async () => {
    const duplicate = {
      name: "artifact",
      version: "1.0.0",
      format: "npm",
      repository: "repo",
      namespace: "workspace",
      slug_perm: "artifact-id",
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

const assert = require("assert");
const { RemediationHelper } = require("../util/remediationHelper");
const { apiFailure } = require("./apiResultHelpers");

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
});

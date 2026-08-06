const assert = require("assert");
const {
  enrichPolicies,
} = require("../util/dependencyPolicyEnricher");

suite("dependencyPolicyEnricher", () => {
  test("maps package index policy fields onto dependency objects", async () => {
    const dependencies = [
      {
        name: "spotipy",
        version: "2.25.0",
        format: "python",
        ecosystem: "python",
        cloudsmithStatus: "FOUND",
        cloudsmithPackage: {
          namespace: "workspace-a",
          repository: "production-pypi",
          slug_perm: "pkg-1",
          status_str: "Quarantined",
          deny_policy_violated: true,
          policy_violated: true,
          status_reason: "Blocked by policy",
        },
      },
      {
        name: "clean-lib",
        version: "1.0.0",
        format: "npm",
        ecosystem: "npm",
        cloudsmithStatus: "FOUND",
        cloudsmithPackage: {
          namespace: "workspace-a",
          repository: "production-npm",
          slug_perm: "pkg-2",
          status_str: "Completed",
          policy_violated: false,
        },
      },
    ];

    const enriched = await enrichPolicies(dependencies);

    assert.strictEqual(enriched[0].policy.violated, true);
    assert.strictEqual(enriched[0].policy.denied, true);
    assert.strictEqual(enriched[0].policy.quarantined, true);
    assert.strictEqual(enriched[0].policy.status, "Quarantined");
    assert.strictEqual(enriched[0].policy.statusReason, "Blocked by policy");
    assert.strictEqual(enriched[1].policy.violated, false);
    assert.strictEqual(enriched[1].policy.denied, false);
  });
});

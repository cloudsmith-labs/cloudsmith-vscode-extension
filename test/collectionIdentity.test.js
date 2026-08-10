const assert = require("assert");
const {
  canonicalCollectionIdentity,
  packageCollectionIdentity,
  repositoryCollectionIdentity,
  unwrapIdentityValue,
} = require("../util/collectionIdentity");

suite("Collection identity", () => {
  test("uses exact scoped package identity without case folding", () => {
    const upper = packageCollectionIdentity({
      namespace: "Workspace",
      repository: "Repository",
      slug_perm: "Package",
    });
    const lower = packageCollectionIdentity({
      namespace: "workspace",
      repository: "repository",
      slug_perm: "package",
    });

    assert.notStrictEqual(upper, lower);
    assert.strictEqual(upper, JSON.stringify(["Workspace", "Repository", "Package"]));
  });

  test("unwraps bounded tree-node values through one shared path", () => {
    assert.strictEqual(unwrapIdentityValue({ value: { value: "package-id" } }), "package-id");
    assert.strictEqual(packageCollectionIdentity({
      namespace: "workspace",
      repository: "repository",
      slug_perm: { value: { value: "package-id" } },
    }), JSON.stringify(["workspace", "repository", "package-id"]));
  });

  test("rejects missing, padded, oversized, and over-nested identities", () => {
    assert.throws(() => canonicalCollectionIdentity([""]));
    assert.throws(() => canonicalCollectionIdentity([" padded"]));
    assert.throws(() => canonicalCollectionIdentity(["x".repeat(513)]));
    assert.throws(() => packageCollectionIdentity({
      namespace: "workspace",
      repository: "repository",
      slug_perm: { value: { value: { value: { value: { value: "too-deep" } } } } },
    }));
  });

  test("repository identities include their workspace scope", () => {
    assert.notStrictEqual(
      repositoryCollectionIdentity("workspace-a", { slug: "repo" }),
      repositoryCollectionIdentity("workspace-b", { slug: "repo" })
    );
  });
});

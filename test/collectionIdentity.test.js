// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const {
  canonicalCollectionIdentity,
  packageCollectionIdentity,
  repositoryCollectionIdentity,
  unwrapIdentityValue,
} = require("../util/collectionIdentity");
const { createExactPackage } = require("../domain/package");

suite("Collection identity", () => {
  test("uses exact scoped package identity without case folding", () => {
    const upper = packageCollectionIdentity(createExactPackage({
      workspace: "Workspace",
      repository: "Repository",
      packageIdentifier: "Package",
      name: "artifact",
      version: "1.0.0",
      format: "npm",
    }));
    const lower = packageCollectionIdentity(createExactPackage({
      workspace: "workspace",
      repository: "repository",
      packageIdentifier: "package",
      name: "artifact",
      version: "1.0.0",
      format: "npm",
    }));

    assert.notStrictEqual(upper, lower);
    assert.strictEqual(upper, JSON.stringify(["Workspace", "Repository", "Package"]));
  });

  test("delegates branded exact packages to the canonical domain identity", () => {
    const pkg = createExactPackage({
      workspace: "workspace",
      repository: "repository",
      packageIdentifier: "package-id",
      name: "artifact",
      version: "1.0.0",
      format: "npm",
    });
    assert.strictEqual(
      packageCollectionIdentity(pkg),
      JSON.stringify(["workspace", "repository", "package-id"])
    );
  });

  test("keeps compatibility unwrapping out of exact package identity", () => {
    assert.strictEqual(unwrapIdentityValue({ value: { value: "package-id" } }), "package-id");
    assert.throws(() => packageCollectionIdentity({
      namespace: "workspace",
      repository: "repository",
      slug_perm: { value: { value: "package-id" } },
    }));
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

  test("does not collide when any exact package identity component changes", () => {
    const base = {
      workspace: "workspace-a",
      repository: "repository-a",
      packageIdentifier: "package-a",
      name: "artifact",
      version: "1.0.0",
      format: "npm",
    };
    const identities = [
      base,
      { ...base, workspace: "workspace-b" },
      { ...base, repository: "repository-b" },
      { ...base, packageIdentifier: "package-b" },
    ].map(value => packageCollectionIdentity(createExactPackage(value)));

    assert.strictEqual(new Set(identities).size, identities.length);
  });
});

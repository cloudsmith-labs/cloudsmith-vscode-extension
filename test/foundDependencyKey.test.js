const assert = require("assert");
const { getFoundDependencyKey } = require("../util/foundDependencyKey");

suite("foundDependencyKey", () => {
  test("uses the exact shared scoped package identity", () => {
    const key = getFoundDependencyKey({
      cloudsmithPackage: {
        namespace: "Workspace-A",
        repository: "Production-NPM",
        slug_perm: "Pkg-1",
      },
    });

    assert.strictEqual(key, JSON.stringify(["Workspace-A", "Production-NPM", "Pkg-1"]));
  });

  test("requires slug_perm and rejects legacy identity fallbacks", () => {
    assert.strictEqual(getFoundDependencyKey({
      cloudsmithPackage: {
        namespace: "workspace-a",
        repository: "repo-a",
        slug_perm: "slug-perm",
        slugPerm: "slug-perm-camel",
        slug: "slug-value",
        identifier: "identifier-value",
      },
    }), JSON.stringify(["workspace-a", "repo-a", "slug-perm"]));

    assert.strictEqual(getFoundDependencyKey({
      cloudsmithPackage: {
        namespace: "workspace-a",
        repository: "repo-a",
        slugPerm: "slug-perm-camel",
        slug: "slug-value",
        identifier: "identifier-value",
      },
    }), null);

    assert.strictEqual(getFoundDependencyKey({
      cloudsmithPackage: {
        namespace: "workspace-a",
        repository: "repo-a",
        slug: "slug-value",
        identifier: "identifier-value",
      },
    }), null);

    assert.strictEqual(getFoundDependencyKey({
      cloudsmithPackage: {
        namespace: "workspace-a",
        repository: "repo-a",
        identifier: "identifier-value",
      },
    }), null);
  });

  test("returns null for null or undefined dependency inputs", () => {
    assert.strictEqual(getFoundDependencyKey(null), null);
    assert.strictEqual(getFoundDependencyKey(undefined), null);
  });

  test("returns null when cloudsmithPackage is missing", () => {
    assert.strictEqual(getFoundDependencyKey({}), null);
    assert.strictEqual(getFoundDependencyKey({ cloudsmithPackage: null }), null);
  });

  test("returns null when namespace, repository, or slug fields are blank", () => {
    assert.strictEqual(getFoundDependencyKey({
      cloudsmithPackage: {
        namespace: "   ",
        repository: "repo-a",
        slug_perm: "slug-a",
      },
    }), null);

    assert.strictEqual(getFoundDependencyKey({
      cloudsmithPackage: {
        namespace: "workspace-a",
        repository: "   ",
        slug_perm: "slug-a",
      },
    }), null);

    assert.strictEqual(getFoundDependencyKey({
      cloudsmithPackage: {
        namespace: "workspace-a",
        repository: "repo-a",
        slug_perm: "   ",
      },
    }), null);
  });

  test("does not merge case-distinct permanent package identities", () => {
    const upper = getFoundDependencyKey({
      cloudsmithPackage: {
        namespace: "Workspace-A",
        repository: "Repo-A",
        slug_perm: "Package-A",
      },
    });
    const lower = getFoundDependencyKey({
      cloudsmithPackage: {
        namespace: "workspace-a",
        repository: "repo-a",
        slug_perm: "package-a",
      },
    });

    assert.notStrictEqual(upper, lower);
  });
});

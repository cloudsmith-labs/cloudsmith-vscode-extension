const assert = require("assert");
const { getFoundDependencyKey } = require("../util/foundDependencyKey");

suite("foundDependencyKey", () => {
  test("builds a lowercase trimmed key for valid found dependencies", () => {
    const key = getFoundDependencyKey({
      cloudsmithPackage: {
        namespace: " Workspace-A ",
        repository: " Production-NPM ",
        slug_perm: "Pkg-1",
      },
    });

    assert.strictEqual(key, "workspace-a:production-npm:pkg-1");
  });

  test("uses slug fallbacks in priority order", () => {
    assert.strictEqual(getFoundDependencyKey({
      cloudsmithPackage: {
        namespace: "workspace-a",
        repository: "repo-a",
        slug_perm: "slug-perm",
        slugPerm: "slug-perm-camel",
        slug: "slug-value",
        identifier: "identifier-value",
      },
    }), "workspace-a:repo-a:slug-perm");

    assert.strictEqual(getFoundDependencyKey({
      cloudsmithPackage: {
        namespace: "workspace-a",
        repository: "repo-a",
        slugPerm: "slug-perm-camel",
        slug: "slug-value",
        identifier: "identifier-value",
      },
    }), "workspace-a:repo-a:slug-perm-camel");

    assert.strictEqual(getFoundDependencyKey({
      cloudsmithPackage: {
        namespace: "workspace-a",
        repository: "repo-a",
        slug: "slug-value",
        identifier: "identifier-value",
      },
    }), "workspace-a:repo-a:slug-value");

    assert.strictEqual(getFoundDependencyKey({
      cloudsmithPackage: {
        namespace: "workspace-a",
        repository: "repo-a",
        identifier: "identifier-value",
      },
    }), "workspace-a:repo-a:identifier-value");
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

  test("keeps the key format workspace repo slug with lowercase trimmed values", () => {
    const key = getFoundDependencyKey({
      cloudsmithPackage: {
        namespace: " Workspace-A ",
        repository: " Repo-A ",
        slugPerm: " slug-value ",
      },
    });

    assert.strictEqual(key, "workspace-a:repo-a:slug-value");
  });
});

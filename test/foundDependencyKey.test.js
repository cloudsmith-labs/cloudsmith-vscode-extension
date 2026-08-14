// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const { getFoundDependencyKey } = require("../util/foundDependencyKey");
const { fromApiPackageRecord } = require("../domain/packageAdapters");

suite("foundDependencyKey", () => {
  function packageRecord(overrides = {}) {
    return fromApiPackageRecord({
      namespace: "workspace-a",
      repository: "repo-a",
      slug_perm: "package-a",
      name: "artifact",
      version: "1.0.0",
      format: "npm",
      ...overrides,
    });
  }

  test("uses the exact shared scoped package identity", () => {
    const key = getFoundDependencyKey({
      cloudsmithPackage: packageRecord({
        namespace: "Workspace-A",
        repository: "Production-NPM",
        slug_perm: "Pkg-1",
      }),
    });

    assert.strictEqual(key, JSON.stringify(["Workspace-A", "Production-NPM", "Pkg-1"]));
  });

  test("requires a branded exact package and rejects raw compatibility aliases", () => {
    const canonical = packageRecord({ slug_perm: "slug-perm" });
    assert.strictEqual(getFoundDependencyKey({
      cloudsmithPackage: canonical,
    }), JSON.stringify(["workspace-a", "repo-a", "slug-perm"]));

    assert.strictEqual(getFoundDependencyKey({
      cloudsmithPackage: {
        namespace: "workspace-a",
        repository: "repo-a",
        slug_perm: "slug-perm",
      },
    }), null);
    assert.strictEqual(getFoundDependencyKey({ cloudsmithPackage: { ...canonical } }), null);
  });

  test("returns null for null or undefined dependency inputs", () => {
    assert.strictEqual(getFoundDependencyKey(null), null);
    assert.strictEqual(getFoundDependencyKey(undefined), null);
  });

  test("returns null when cloudsmithPackage is missing", () => {
    assert.strictEqual(getFoundDependencyKey({}), null);
    assert.strictEqual(getFoundDependencyKey({ cloudsmithPackage: null }), null);
  });

  test("does not merge case-distinct permanent package identities", () => {
    const upper = getFoundDependencyKey({
      cloudsmithPackage: packageRecord({
        namespace: "Workspace-A",
        repository: "Repo-A",
        slug_perm: "Package-A",
      }),
    });
    const lower = getFoundDependencyKey({
      cloudsmithPackage: packageRecord({
        namespace: "workspace-a",
        repository: "repo-a",
        slug_perm: "package-a",
      }),
    });

    assert.notStrictEqual(upper, lower);
  });
});

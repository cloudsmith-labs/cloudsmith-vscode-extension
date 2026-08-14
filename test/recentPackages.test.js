// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const { createExactPackage, exactPackageIdentity, isExactPackage } = require("../domain/package");

suite("RecentPackages Test Suite", () => {
  let recentPackages;

  function exactPackage(overrides = {}) {
    return createExactPackage({
      workspace: "workspace",
      repository: "source",
      packageIdentifier: "package-id",
      name: "artifact",
      version: "1.0.0",
      format: "npm",
      tags: { info: [], version: [] },
      ...overrides,
    });
  }

  function legacyPackage(overrides = {}) {
    return {
      namespace: "workspace",
      cloudsmithWorkspace: "workspace",
      repository: "source",
      cloudsmithRepo: "source",
      slug_perm: "package-id",
      slug_perm_raw: "package-id",
      name: "artifact",
      version: "1.0.0",
      format: "npm",
      ...overrides,
    };
  }

  setup(() => {
    delete require.cache[require.resolve("../util/recentPackages")];
    recentPackages = require("../util/recentPackages");
  });

  test("stores canonical packages without projecting compatibility aliases", () => {
    const pkg = exactPackage({
      format: "docker",
      checksumSha256: "abc123",
      versionDigest: "digest123",
      cdnUrl: "https://cdn.example.com/nginx.tar",
      filename: "nginx.tar",
      tags: { info: ["upstream"], version: ["stable"] },
    });
    recentPackages.add(pkg);

    const [stored] = recentPackages.getAll();
    assert.strictEqual(stored, pkg);
    assert.ok(isExactPackage(stored));
    assert.strictEqual(stored.workspace, "workspace");
    assert.strictEqual(stored.packageIdentifier, "package-id");
    assert.strictEqual(stored.checksumSha256, "abc123");
    assert.deepStrictEqual(stored.tags.version, ["stable"]);
    assert.strictEqual(Object.hasOwn(stored, "namespace"), false);
    assert.strictEqual(Object.hasOwn(stored, "slug_perm_raw"), false);
  });

  test("adapts legacy values only at add and keeps the stored result deeply immutable", () => {
    const incoming = legacyPackage({
      version: { value: { value: "1.0.0" } },
      tags_raw: { info: ["upstream"], version: ["latest"] },
    });
    recentPackages.add(incoming);
    incoming.tags_raw.info[0] = "changed";

    const snapshot = recentPackages.getAll();
    const [stored] = snapshot;
    assert.ok(Object.isFrozen(snapshot));
    assert.ok(Object.isFrozen(stored));
    assert.ok(Object.isFrozen(stored.tags.info));
    assert.deepStrictEqual(stored.tags.info, ["upstream"]);
    assert.throws(() => stored.tags.info.push("mutated"), TypeError);
  });

  test("accepts a presentation node with canonical package evidence", () => {
    const pkg = exactPackage();
    recentPackages.add({
      package: pkg,
      namespace: "workspace",
      repository: "source",
      slug_perm_raw: "package-id",
    });
    assert.strictEqual(recentPackages.getAll()[0], pkg);
  });

  test("keeps exact identities distinct across every scope component", () => {
    for (const pkg of [
      exactPackage(),
      exactPackage({ workspace: "other-workspace" }),
      exactPackage({ repository: "other-source" }),
      exactPackage({ packageIdentifier: "other-package" }),
    ]) recentPackages.add(pkg);

    assert.strictEqual(recentPackages.getAll().length, 4);
    assert.strictEqual(new Set(recentPackages.getAll().map(exactPackageIdentity)).size, 4);
  });

  test("same exact identity refreshes optional metadata and moves the package first", () => {
    recentPackages.add(exactPackage({
      repository: "other",
      packageIdentifier: "other-id",
      name: "other",
    }));
    recentPackages.add(exactPackage({ status: "old" }));
    recentPackages.add(exactPackage({ status: "new" }));

    const all = recentPackages.getAll();
    assert.strictEqual(all.length, 2);
    assert.strictEqual(all[0].name, "artifact");
    assert.strictEqual(all[0].status, "new");
  });

  test("same exact identity with a conflicting core signature preserves the trusted entry", () => {
    const trusted = exactPackage({ status: "trusted" });
    recentPackages.add(trusted);
    recentPackages.add(exactPackage({ name: "other-name" }));
    recentPackages.add(exactPackage({ version: "2.0.0" }));
    recentPackages.add(exactPackage({ format: "python" }));

    assert.deepStrictEqual(recentPackages.getAll(), [trusted]);
  });

  test("invalid aliases and wrapper shapes cannot remove a trusted entry", () => {
    const trusted = exactPackage();
    recentPackages.add(trusted);
    recentPackages.add(legacyPackage({ cloudsmithRepo: "conflict" }));
    recentPackages.add(legacyPackage({ slug_perm: { value: { value: { value: "package-id" } } } }));
    recentPackages.add(legacyPackage({ version: Number.NaN }));

    assert.deepStrictEqual(recentPackages.getAll(), [trusted]);
  });

  test("empty legacy versions use declaredVersion only as an absent-value fallback", () => {
    recentPackages.add(legacyPackage({
      version: { value: "" },
      declaredVersion: { value: "1.0.0" },
    }));
    assert.strictEqual(recentPackages.getAll()[0].version, "1.0.0");

    recentPackages.clear();
    recentPackages.add(legacyPackage({
      version: "2.0.0",
      declaredVersion: "stale-declaration",
    }));
    assert.strictEqual(recentPackages.getAll()[0].version, "2.0.0");
  });

  test("bounds the list at ten and clear removes the full snapshot", () => {
    for (let index = 0; index < 12; index += 1) {
      recentPackages.add(exactPackage({ packageIdentifier: `package-${index}` }));
    }
    assert.strictEqual(recentPackages.getAll().length, 10);
    assert.strictEqual(recentPackages.getAll()[0].packageIdentifier, "package-11");

    recentPackages.clear();
    assert.deepStrictEqual(recentPackages.getAll(), []);
    assert.ok(Object.isFrozen(recentPackages.getAll()));
  });
});

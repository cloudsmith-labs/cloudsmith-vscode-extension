const assert = require("assert");

suite("RecentPackages Test Suite", () => {
  let recentPackages;

  function identityPackage(overrides = {}) {
    return {
      name: "artifact",
      format: "npm",
      version: "1.0.0",
      namespace: "workspace",
      cloudsmithWorkspace: "workspace",
      repository: "source",
      cloudsmithRepo: "source",
      slug_perm: "package-id",
      slug_perm_raw: "package-id",
      ...overrides,
    };
  }

  setup(() => {
    delete require.cache[require.resolve("../util/recentPackages")];
    recentPackages = require("../util/recentPackages");
  });

  test("add() preserves install-command metadata fields", () => {
    recentPackages.add({
      name: "nginx",
      format: "docker",
      version: { id: "Version", value: "1.25" },
      namespace: "workspace-a",
      repository: "containers",
      checksum_sha256: "abc123",
      version_digest: "digest123",
      cdn_url: "https://cdn.example.com/nginx.tar",
      filename: "nginx.tar",
      tags_raw: {
        version: ["stable"],
        info: ["upstream"],
      },
    });

    const all = recentPackages.getAll();
    assert.strictEqual(all.length, 1);
    assert.strictEqual(all[0].version, "1.25");
    assert.strictEqual(all[0].checksum_sha256, "abc123");
    assert.strictEqual(all[0].version_digest, "digest123");
    assert.strictEqual(all[0].docker_tag, "stable");
    assert.deepStrictEqual(all[0].tags, {
      version: ["stable"],
      info: ["upstream"],
    });
    assert.deepStrictEqual(all[0].tags_raw, {
      version: ["stable"],
      info: ["upstream"],
    });
    assert.strictEqual(all[0].cdn_url, "https://cdn.example.com/nginx.tar");
    assert.strictEqual(all[0].filename, "nginx.tar");
  });

  test("add() keeps identical package coordinates from different workspaces", () => {
    recentPackages.add({
      name: "shared-lib",
      format: "raw",
      version: "1.0.0",
      namespace: "workspace-a",
      repository: "downloads",
    });
    recentPackages.add({
      name: "shared-lib",
      format: "raw",
      version: "1.0.0",
      namespace: "workspace-b",
      repository: "downloads",
    });

    const all = recentPackages.getAll();
    assert.strictEqual(all.length, 2);
    assert.strictEqual(all[0].namespace, "workspace-b");
    assert.strictEqual(all[1].namespace, "workspace-a");
  });

  test("add() derives compatible identity aliases from one canonical value", () => {
    recentPackages.add({
      name: "artifact",
      format: "npm",
      version: "1.0.0",
      namespace: "workspace",
      cloudsmithWorkspace: "workspace",
      repository: "source",
      cloudsmithRepo: "source",
      slug_perm: { value: "package-id" },
      slug_perm_raw: "package-id",
      is_copyable: true,
    });

    const [stored] = recentPackages.getAll();
    assert.strictEqual(stored.namespace, "workspace");
    assert.strictEqual(stored.cloudsmithWorkspace, "workspace");
    assert.strictEqual(stored.repository, "source");
    assert.strictEqual(stored.cloudsmithRepo, "source");
    assert.strictEqual(stored.slug_perm, "package-id");
    assert.strictEqual(stored.slug_perm_raw, "package-id");
    assert.strictEqual(stored.is_copyable, true);
  });

  test("add() cannot persist contradictory or malformed package aliases as trusted identity", () => {
    recentPackages.add({
      name: "artifact",
      format: "npm",
      version: "1.0.0",
      namespace: "workspace",
      cloudsmithWorkspace: "other-workspace",
      repository: "source",
      slug_perm: { value: {} },
      slug_perm_raw: "package-id",
      is_copyable: "false",
    });

    const [stored] = recentPackages.getAll();
    assert.strictEqual(stored.namespace, null);
    assert.strictEqual(stored.cloudsmithWorkspace, null);
    assert.strictEqual(stored.slug_perm, null);
    assert.strictEqual(stored.slug_perm_raw, null);
    assert.strictEqual(stored.is_copyable, null);
  });

  test("repository and workspace alias inversions share one recent-package identity", () => {
    const cases = [
      {
        mutateExisting(stored) { delete stored.repository; },
        mutateIncoming(incoming) { delete incoming.cloudsmithRepo; },
      },
      {
        mutateExisting(stored) { delete stored.cloudsmithRepo; },
        mutateIncoming(incoming) { delete incoming.repository; },
      },
      {
        mutateExisting(stored) { delete stored.namespace; },
        mutateIncoming(incoming) { delete incoming.cloudsmithWorkspace; },
      },
      {
        mutateExisting(stored) { delete stored.cloudsmithWorkspace; },
        mutateIncoming(incoming) { delete incoming.namespace; },
      },
    ];

    for (const testCase of cases) {
      recentPackages.clear();
      recentPackages.add(identityPackage());
      testCase.mutateExisting(recentPackages.getAll()[0]);
      const incoming = identityPackage();
      testCase.mutateIncoming(incoming);

      recentPackages.add(incoming);

      const [stored] = recentPackages.getAll();
      assert.strictEqual(recentPackages.getAll().length, 1);
      assert.strictEqual(stored.namespace, "workspace");
      assert.strictEqual(stored.cloudsmithWorkspace, "workspace");
      assert.strictEqual(stored.repository, "source");
      assert.strictEqual(stored.cloudsmithRepo, "source");
    }
  });

  test("wrapped legacy versions and absent optional aliases canonicalize before comparison", () => {
    recentPackages.add(identityPackage());
    const existing = recentPackages.getAll()[0];
    existing.version = { value: { value: "1.0.0" } };
    existing.cloudsmithWorkspace = null;
    existing.cloudsmithRepo = undefined;

    recentPackages.add(identityPackage({
      namespace: null,
      repository: null,
    }));

    const [stored] = recentPackages.getAll();
    assert.strictEqual(recentPackages.getAll().length, 1);
    assert.strictEqual(stored.version, "1.0.0");
    assert.strictEqual(stored.namespace, "workspace");
    assert.strictEqual(stored.repository, "source");
  });

  test("empty current versions fall back to the canonical declared version", () => {
    for (const emptyVersion of ["", { value: "" }, { value: { value: "" } }]) {
      recentPackages.clear();
      recentPackages.add(identityPackage({
        version: emptyVersion,
        declaredVersion: { value: "1.0.0" },
      }));
      recentPackages.add(identityPackage());

      const [stored] = recentPackages.getAll();
      assert.strictEqual(recentPackages.getAll().length, 1);
      assert.strictEqual(stored.version, "1.0.0");
    }
  });

  test("empty compatibility aliases fail closed without removing a valid identity", () => {
    const cases = [
      { cloudsmithRepo: "" },
      { cloudsmithWorkspace: "" },
    ];

    for (const overrides of cases) {
      recentPackages.clear();
      recentPackages.add(identityPackage());
      recentPackages.add(identityPackage(overrides));

      const all = recentPackages.getAll();
      assert.strictEqual(all.length, 2);
      assert.strictEqual(all.filter(pkg => (
        pkg.namespace === "workspace" && pkg.repository === "source"
      )).length, 1);
      assert.strictEqual(all.filter(pkg => (
        pkg.namespace === null || pkg.repository === null
      )).length, 1);
    }
  });

  test("structured recent identities cannot collide through delimiters", () => {
    recentPackages.add(identityPackage({ name: "artifact:1", version: "2" }));
    recentPackages.add(identityPackage({ name: "artifact", version: "1:2" }));

    assert.strictEqual(recentPackages.getAll().length, 2);
  });

  test("distinct workspace, repository, package, and version coordinates remain distinct", () => {
    for (const record of [
      identityPackage(),
      identityPackage({ cloudsmithWorkspace: "other-workspace", namespace: "other-workspace" }),
      identityPackage({ cloudsmithRepo: "other-source", repository: "other-source" }),
      identityPackage({ name: "other-artifact" }),
      identityPackage({ version: "2.0.0" }),
    ]) {
      recentPackages.add(record);
    }

    assert.strictEqual(recentPackages.getAll().length, 5);
  });

  test("malformed identities cannot remove valid entries or collapse into false equality", () => {
    recentPackages.add(identityPackage());
    recentPackages.add(identityPackage({ version: { value: { value: {} } } }));
    recentPackages.add(identityPackage({ version: Number.NaN }));
    assert.strictEqual(recentPackages.getAll().length, 1);

    recentPackages.add(identityPackage({ cloudsmithRepo: "conflicting-source" }));
    recentPackages.add(identityPackage({
      repository: "another-source",
      cloudsmithRepo: "another-conflict",
    }));

    const all = recentPackages.getAll();
    assert.strictEqual(all.length, 3);
    assert.strictEqual(all.filter(pkg => pkg.repository === "source").length, 1);
    assert.strictEqual(all.filter(pkg => pkg.repository === null).length, 2);
  });

  test("re-adding a valid identity collapses every historical duplicate and moves it first", () => {
    recentPackages.add(identityPackage({
      name: "first",
      repository: "first",
      cloudsmithRepo: "first",
    }));
    recentPackages.add(identityPackage({ repository: "source-a", cloudsmithRepo: "source-a" }));
    recentPackages.add(identityPackage({ repository: "source-b", cloudsmithRepo: "source-b" }));

    for (const entry of recentPackages.getAll().filter(pkg => pkg.name === "artifact")) {
      entry.repository = "source";
      entry.cloudsmithRepo = "source";
    }
    recentPackages.add(identityPackage());

    const all = recentPackages.getAll();
    assert.deepStrictEqual(all.map(pkg => pkg.name), ["artifact", "first"]);
    assert.strictEqual(all[0].repository, "source");
  });
});

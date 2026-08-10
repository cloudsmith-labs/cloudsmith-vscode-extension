const assert = require("assert");

suite("RecentPackages Test Suite", () => {
  let recentPackages;

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
});

const assert = require("assert");
const vscode = require("vscode");
const {
  enrichLicenses,
} = require("../util/dependencyLicenseEnricher");

suite("dependencyLicenseEnricher", () => {
  let originalGetConfiguration;

  setup(() => {
    originalGetConfiguration = vscode.workspace.getConfiguration;
    vscode.workspace.getConfiguration = () => ({
      get() {
        return undefined;
      },
    });
  });

  teardown(() => {
    vscode.workspace.getConfiguration = originalGetConfiguration;
  });

  test("classifies found dependencies using package index license metadata", async () => {
    const dependencies = [
      {
        name: "express",
        version: "4.18.2",
        format: "npm",
        ecosystem: "npm",
        cloudsmithStatus: "FOUND",
        cloudsmithPackage: {
          namespace: "workspace-a",
          repository: "production-npm",
          slug_perm: "pkg-1",
          license: "MIT",
        },
      },
      {
        name: "copyleft-lib",
        version: "1.0.0",
        format: "npm",
        ecosystem: "npm",
        cloudsmithStatus: "FOUND",
        cloudsmithPackage: {
          namespace: "workspace-a",
          repository: "production-npm",
          slug_perm: "pkg-2",
          spdx_license: "LGPL-2.1",
        },
      },
      {
        name: "missing-lib",
        version: "1.0.0",
        format: "npm",
        ecosystem: "npm",
        cloudsmithStatus: "NOT_FOUND",
      },
    ];

    const enriched = await enrichLicenses(dependencies);

    assert.strictEqual(enriched[0].license.classification, "permissive");
    assert.strictEqual(enriched[0].license.spdx, "MIT");
    assert.strictEqual(enriched[1].license.classification, "weak_copyleft");
    assert.strictEqual(enriched[1].license.spdx, "LGPL-2.1");
    assert.strictEqual(enriched[2].license, undefined);
  });
});

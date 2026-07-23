const assert = require("assert");
const path = require("path");
const vscode = require("vscode");
const PackageNode = require("../models/packageNode");
const SearchResultNode = require("../models/searchResultNode");
const DependencyHealthNode = require("../models/dependencyHealthNode");

suite("Package Metadata Flow Test Suite", () => {
  let originalGetConfiguration;

  const pkg = {
    name: "artifact",
    format: "raw",
    repository: "repo-a",
    namespace: "workspace-a",
    status_str: "Completed",
    slug: "artifact-1",
    slug_perm: "artifact-1-perm",
    downloads: 5,
    version: "1.0.0",
    uploaded_at: "2026-03-25T00:00:00Z",
    checksum_sha256: "abc123",
    version_digest: "digest123",
    cdn_url: "https://cdn.example.com/artifact.bin",
    filename: "artifact.bin",
    license: "MIT OR GPL-3.0",
    license_url: "https://example.com/license",
    tags: {
      version: ["latest"],
      info: ["upstream"],
    },
  };

  setup(() => {
    originalGetConfiguration = vscode.workspace.getConfiguration;
    vscode.workspace.getConfiguration = () => ({
      get(key) {
        if (key === "showLicenseIndicators") {
          return true;
        }
        return undefined;
      },
    });
  });

  teardown(() => {
    vscode.workspace.getConfiguration = originalGetConfiguration;
  });

  test("PackageNode preserves install-command metadata", () => {
    const node = new PackageNode(pkg, {});
    assert.strictEqual(node.checksum_sha256, "abc123");
    assert.strictEqual(node.version_digest, "digest123");
    assert.strictEqual(node.cdn_url, "https://cdn.example.com/artifact.bin");
    assert.strictEqual(node.filename, "artifact.bin");
    assert.deepStrictEqual(node.tags_raw, {
      version: ["latest"],
      info: ["upstream"],
    });
  });

  test("SearchResultNode preserves install-command metadata", () => {
    const node = new SearchResultNode(pkg, {});
    assert.strictEqual(node.checksum_sha256, "abc123");
    assert.strictEqual(node.version_digest, "digest123");
    assert.strictEqual(node.cdn_url, "https://cdn.example.com/artifact.bin");
    assert.strictEqual(node.filename, "artifact.bin");
    assert.deepStrictEqual(node.tags_raw, {
      version: ["latest"],
      info: ["upstream"],
    });
  });

  test("DependencyHealthNode preserves install-command metadata", () => {
    const node = new DependencyHealthNode({
      name: "artifact",
      version: "1.0.0",
      format: "raw",
      devDependency: false,
    }, pkg, {});
    assert.strictEqual(node.checksum_sha256, "abc123");
    assert.strictEqual(node.version_digest, "digest123");
    assert.strictEqual(node.cdn_url, "https://cdn.example.com/artifact.bin");
    assert.strictEqual(node.filename, "artifact.bin");
    assert.deepStrictEqual(node.tags_raw, {
      version: ["latest"],
      info: ["upstream"],
    });
  });

  test("package, search, and dependency views preserve the same raw Cloudsmith license display", () => {
    const packageNode = new PackageNode(pkg, {});
    const searchNode = new SearchResultNode(pkg, {});
    const dependencyNode = new DependencyHealthNode({
      name: "artifact",
      version: "1.0.0",
      format: "raw",
      devDependency: false,
    }, pkg, {});

    const packageLicenseItem = packageNode.getChildren()[2].getTreeItem();
    const searchLicenseItem = searchNode.getChildren()[2].getTreeItem();
    const dependencyLicenseItem = dependencyNode.getChildren()[2].getTreeItem();

    assert.strictEqual(packageLicenseItem.label, "License: MIT OR GPL-3.0");
    assert.strictEqual(searchLicenseItem.label, "License: MIT OR GPL-3.0");
    assert.strictEqual(dependencyLicenseItem.label, "License: MIT OR GPL-3.0");

    assert.strictEqual(packageLicenseItem.description, searchLicenseItem.description);
    assert.strictEqual(packageLicenseItem.description, dependencyLicenseItem.description);
  });

  test("spdx-only payloads stay classifiable and resolvable across all license consumers", () => {
    const spdxOnlyPkg = {
      ...pkg,
      license: null,
      raw_license: null,
      spdx_license: "Apache-2.0",
      license_url: null,
    };

    const packageNode = new PackageNode(spdxOnlyPkg, {});
    const searchNode = new SearchResultNode(spdxOnlyPkg, {});
    const dependencyNode = new DependencyHealthNode({
      name: "artifact",
      version: "1.0.0",
      format: "raw",
      devDependency: false,
    }, spdxOnlyPkg, {});

    const packageLicenseItem = packageNode.getChildren()[2].getTreeItem();
    const searchLicenseItem = searchNode.getChildren()[2].getTreeItem();
    const dependencyLicenseItem = dependencyNode.getChildren()[2].getTreeItem();

    assert.strictEqual(packageNode.licenseInfo.canonicalSourceField, "spdx_license");
    assert.strictEqual(searchNode.licenseInfo.canonicalSourceField, "spdx_license");
    assert.strictEqual(dependencyNode.licenseInfo.canonicalSourceField, "spdx_license");

    assert.strictEqual(packageLicenseItem.label, "License: Apache-2.0");
    assert.strictEqual(searchLicenseItem.label, "License: Apache-2.0");
    assert.strictEqual(dependencyLicenseItem.label, "License: Apache-2.0");
    assert.strictEqual(packageLicenseItem.description, "\u2713 Permissive");
    assert.strictEqual(searchLicenseItem.description, "\u2713 Permissive");
    assert.strictEqual(dependencyLicenseItem.description, "\u2713 Permissive");

    assert.ok(packageLicenseItem.command);
    assert.ok(searchLicenseItem.command);
    assert.ok(dependencyLicenseItem.command);
    assert.strictEqual(packageLicenseItem.command.arguments[0].licenseUrl, "https://spdx.org/licenses/Apache-2.0.html");
    assert.strictEqual(searchLicenseItem.command.arguments[0].licenseUrl, "https://spdx.org/licenses/Apache-2.0.html");
    assert.strictEqual(dependencyLicenseItem.command.arguments[0].licenseUrl, "https://spdx.org/licenses/Apache-2.0.html");
    assert.ok(dependencyNode._buildTooltip().includes("License: Apache-2.0 (Permissive)"));
  });

  test("packages with populated spdx, license, and raw license fields preserve display while sharing canonical interpretation", () => {
    const populatedPkg = {
      ...pkg,
      spdx_license: "Apache-2.0",
      license: "Apache 2.0",
      raw_license: "Apache-2.0",
      license_url: null,
    };

    const packageNode = new PackageNode(populatedPkg, {});
    const searchNode = new SearchResultNode(populatedPkg, {});
    const dependencyNode = new DependencyHealthNode({
      name: "artifact",
      version: "1.0.0",
      format: "raw",
      devDependency: false,
    }, populatedPkg, {});

    const packageLicenseItem = packageNode.getChildren()[2].getTreeItem();
    const searchLicenseItem = searchNode.getChildren()[2].getTreeItem();
    const dependencyLicenseItem = dependencyNode.getChildren()[2].getTreeItem();

    assert.strictEqual(packageNode.licenseInfo.label, "Apache 2.0");
    assert.strictEqual(searchNode.licenseInfo.label, "Apache 2.0");
    assert.strictEqual(dependencyNode.licenseInfo.label, "Apache 2.0");
    assert.strictEqual(packageNode.licenseInfo.canonicalValue, "Apache-2.0");
    assert.strictEqual(searchNode.licenseInfo.canonicalValue, "Apache-2.0");
    assert.strictEqual(dependencyNode.licenseInfo.canonicalValue, "Apache-2.0");
    assert.strictEqual(packageNode.licenseInfo.canonicalSourceField, "spdx_license");
    assert.strictEqual(searchNode.licenseInfo.canonicalSourceField, "spdx_license");
    assert.strictEqual(dependencyNode.licenseInfo.canonicalSourceField, "spdx_license");

    assert.strictEqual(packageLicenseItem.label, "License: Apache 2.0");
    assert.strictEqual(searchLicenseItem.label, "License: Apache 2.0");
    assert.strictEqual(dependencyLicenseItem.label, "License: Apache 2.0");
    assert.ok(packageLicenseItem.command);
    assert.strictEqual(packageLicenseItem.command.arguments[0].licenseUrl, "https://spdx.org/licenses/Apache-2.0.html");
  });

  test("unknown Cloudsmith-derived license values remain visible and only expose View License when resolvable", () => {
    const unknownPkg = {
      ...pkg,
      license: null,
      raw_license: "Custom Enterprise License",
      spdx_license: null,
      license_url: null,
    };

    const packageNode = new PackageNode(unknownPkg, {});
    const licenseItem = packageNode.getChildren()[2].getTreeItem();

    assert.strictEqual(packageNode.licenseInfo.label, "Custom Enterprise License");
    assert.strictEqual(packageNode.licenseInfo.tier, "unknown");
    assert.strictEqual(packageNode.licenseInfo.licenseUrl, null);
    assert.strictEqual(licenseItem.label, "License: Custom Enterprise License");
    assert.strictEqual(licenseItem.description, "? Unknown license");
    assert.strictEqual(licenseItem.command, undefined);
  });

  test("dependency health descriptions use Cloudsmith terminology", () => {
    const cleanPkg = {
      ...pkg,
      license: "MIT",
      raw_license: "MIT",
      spdx_license: "MIT",
    };

    const cleanNode = new DependencyHealthNode({
      name: "artifact",
      version: "4.18.2",
      format: "raw",
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: cleanPkg,
    }, cleanPkg, {});

    const vulnerableNode = new DependencyHealthNode({
      name: "artifact",
      version: "4.18.2",
      format: "raw",
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: cleanPkg,
      vulnerabilities: {
        count: 2,
        maxSeverity: "High",
        severityCounts: { High: 2 },
        detailsLoaded: true,
      },
    }, cleanPkg, {});

    const quarantinedNode = new DependencyHealthNode({
      name: "artifact",
      version: "4.18.2",
      format: "raw",
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: {
        ...pkg,
        status_str: "Quarantined",
      },
    }, {
      ...pkg,
      status_str: "Quarantined",
    }, {});

    assert.strictEqual(cleanNode.getTreeItem().description, "4.18.2 — No issues found");
    assert.strictEqual(vulnerableNode.getTreeItem().description, "4.18.2 — Vulnerabilities found (2 High)");
    assert.strictEqual(quarantinedNode.getTreeItem().description, "4.18.2 — Quarantined");
  });

  test("dependency health tooltips show no-license text only in the tooltip", () => {
    const node = new DependencyHealthNode({
      name: "artifact",
      version: "1.0.0",
      format: "raw",
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: {
        ...pkg,
        license: null,
        raw_license: null,
        spdx_license: null,
        license_url: null,
      },
    }, {
      ...pkg,
      license: null,
      raw_license: null,
      spdx_license: null,
      license_url: null,
    }, {});

    assert.strictEqual(node.getTreeItem().description, "1.0.0 — No issues found");
    assert.match(node.getTreeItem().tooltip, /License: No license detected/);
  });

  test("dependency health missing nodes use format icons and upstream-aware context values", () => {
    const context = { extensionPath: path.resolve(__dirname, "..") };

    const missingNode = new DependencyHealthNode({
      name: "express",
      version: "4.18.2",
      format: "npm",
      cloudsmithStatus: "NOT_FOUND",
    }, null, context);
    const reachableNode = new DependencyHealthNode({
      name: "express",
      version: "4.18.2",
      format: "npm",
      cloudsmithStatus: "NOT_FOUND",
      upstreamStatus: "reachable",
    }, null, context);
    const unreachableNode = new DependencyHealthNode({
      name: "requests",
      version: "2.31.0",
      format: "python",
      cloudsmithStatus: "NOT_FOUND",
      upstreamStatus: "no_proxy",
    }, null, context);

    const missingItem = missingNode.getTreeItem();
    const reachableItem = reachableNode.getTreeItem();
    const unreachableItem = unreachableNode.getTreeItem();

    assert.strictEqual(missingItem.contextValue, "dependencyHealthMissing");
    assert.strictEqual(reachableItem.contextValue, "dependencyHealthUpstreamReachable");
    assert.strictEqual(unreachableItem.contextValue, "dependencyHealthUpstreamUnreachable");
    assert.ok(missingItem.iconPath);
    assert.ok(reachableItem.iconPath);
    assert.ok(unreachableItem.iconPath);
    assert.ok(missingItem.iconPath.dark.fsPath.endsWith(path.join("media", "vscode_icons", "file_type_npm.svg")));
    assert.ok(reachableItem.iconPath.dark.fsPath.endsWith(path.join("media", "vscode_icons", "file_type_npm.svg")));
    assert.ok(unreachableItem.iconPath.dark.fsPath.endsWith(path.join("media", "vscode_icons", "file_type_python.svg")));
  });
});

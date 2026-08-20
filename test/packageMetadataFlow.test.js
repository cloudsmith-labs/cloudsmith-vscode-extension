// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const path = require("path");
const vscode = require("vscode");
const { registerPackageCommands } = require("../commands/packages");
const PackageNode = require("../models/packageNode");
const PackageDetailsNode = require("../models/packageDetailsNode");
const SearchResultNode = require("../models/searchResultNode");
const DependencyHealthNode = require("../models/dependencyHealthNode");
const DependencySummaryNode = require("../models/dependencySummaryNode");
const packageAdapters = require("../domain/packageAdapters");
const {
  PackageAdapterError,
  fromApiPackageRecord,
} = packageAdapters;
const { createPackageCoordinate } = require("../domain/package");
const { captureAccount, isAccountCurrent } = require("../util/accountOperation");
const { isSelectionCurrent, markSelection } = require("../util/selectionProvenance");

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

  test("package and search rows expose version, format, repository, and material state as text", () => {
    const statefulPackage = {
      ...pkg,
      status_str: "Syncing",
      policy_violated: true,
    };
    const packageItem = new PackageNode(statefulPackage, {}).getTreeItem();
    const searchItem = new SearchResultNode(statefulPackage, {}).getTreeItem();
    for (const item of [packageItem, searchItem]) {
      assert.match(item.description, /1\.0\.0/);
      assert.match(item.description, /raw/);
      assert.match(item.description, /Syncing/);
      assert.match(item.description, /Policy violation/);
    }
    assert.match(searchItem.description, /repo/);
  });

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

  test("real package-detail command arguments copy only while inherited selection is current", async () => {
    let accountState = Object.freeze({
      activationId: "activation-a",
      accountEpoch: 1,
      sessionConnected: true,
      status: "connected",
    });
    const connectionManager = {
      getState: () => accountState,
    };
    const owner = new PackageNode(pkg, {}, { connectionManager });
    const detailNode = new PackageDetailsNode(
      { id: "Version", value: "1.2.3" },
      {},
      owner
    );
    const treeItem = detailNode.getTreeItem();
    const commandArgument = treeItem.command.arguments[0];

    assert.strictEqual(commandArgument, detailNode);
    assert.deepStrictEqual(
      packageAdapters.fromPackageDetailNode(commandArgument),
      { id: "Version", value: "1.2.3" }
    );
    assert.strictEqual(isSelectionCurrent(commandArgument), true);

    const handlers = new Map();
    const copied = [];
    const information = [];
    const warnings = [];
    let invalidateOnWrite = false;
    registerPackageCommands({
      registerCommand(id, handler) {
        handlers.set(id, handler);
        return { dispose() {} };
      },
      vscode: {
        env: {
          clipboard: {
            async writeText(value) {
              copied.push(value);
              if (invalidateOnWrite) {
                accountState = Object.freeze({ ...accountState, accountEpoch: 3 });
              }
            },
          },
        },
        window: {
          showInformationMessage(message) { information.push(message); },
          showWarningMessage(message) { warnings.push(message); },
        },
      },
      workspaceAccess: {
        connectionManager,
        captureAccount,
        isAccountCurrent,
      },
      packageAdapters,
      LicenseClassifier: { buildRestrictiveQuery: () => "license:restrictive" },
      isCurrentSelection: isSelectionCurrent,
    });

    const copySelected = handlers.get("cloudsmith-vsc.copySelected");
    await copySelected(commandArgument);
    assert.deepStrictEqual(copied, ["1.2.3"]);
    assert.deepStrictEqual(information, ["Value copied."]);
    assert.deepStrictEqual(warnings, []);

    accountState = Object.freeze({ ...accountState, accountEpoch: 2 });
    await copySelected(commandArgument);
    await copySelected({ _detailId: "Version", _detailValue: "forged" });
    assert.deepStrictEqual(copied, ["1.2.3"]);
    assert.deepStrictEqual(information, ["Value copied."]);

    let getterCalls = 0;
    const hostile = markSelection({}, connectionManager);
    Object.defineProperty(hostile, "label", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return { id: "Version", value: "forged" };
      },
    });
    await copySelected(hostile);
    assert.strictEqual(getterCalls, 0);
    assert.deepStrictEqual(copied, ["1.2.3"]);
    assert.deepStrictEqual(warnings, ["No package detail selected."]);

    const rawOwner = markSelection({}, connectionManager);
    const rawNode = new PackageDetailsNode("Completed", {}, rawOwner);
    assert.strictEqual(rawNode.getTreeItem().command.arguments[0], rawNode);
    assert.deepStrictEqual(packageAdapters.fromPackageDetailNode(rawNode), {
      id: "Detail",
      value: "Completed",
    });
    invalidateOnWrite = true;
    await copySelected(rawNode);
    assert.deepStrictEqual(copied, ["1.2.3", "Completed"]);
    assert.deepStrictEqual(information, ["Value copied."]);
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

  test("package and search models share format-independent vulnerability status handling", () => {
    const cleanPayloads = [
      {
        ...pkg,
        name: "clean-npm",
        format: "npm",
        security_scan_status: "Scan Detected No Vulnerabilities",
      },
      {
        ...pkg,
        name: "clean-python",
        format: "python",
        num_vulnerabilities: "0",
        security_scan_status: "Scan Detected No Vulnerabilities",
      },
    ];

    for (const cleanPayload of cleanPayloads) {
      for (const NodeType of [PackageNode, SearchResultNode]) {
        const node = new NodeType(cleanPayload, {});
        assert.strictEqual(node.num_vulnerabilities, 0);
        const summary = node.getChildren().find(
          child => child.getTreeItem().contextValue === "vulnerabilitySummary"
        );
        assert.ok(summary, `${NodeType.name} omitted the authoritative clean vulnerability state`);
        assert.strictEqual(summary.getTreeItem().label, "Vulnerabilities: 0 (None)");
      }
    }

    const cachedVulnerable = Object.freeze({
      status: "complete-vulnerable",
      records: Object.freeze([{ vulnerability_id: "CVE-1", severity: "High" }]),
      count: 1,
      maxSeverity: "High",
      complete: true,
      detailed: true,
      revision: 1,
    });
    const vulnerabilityStateService = {
      prime() { return cachedVulnerable; },
      peek() { return cachedVulnerable; },
    };
    for (const NodeType of [PackageNode, SearchResultNode]) {
      const node = new NodeType(cleanPayloads[0], {}, { vulnerabilityStateService });
      const summary = node.getChildren().find(
        child => child.getTreeItem().contextValue === "vulnerabilitySummary"
      );
      assert.strictEqual(summary.getTreeItem().label, "Vulnerabilities: 1 (High)");
    }

    const vulnerablePayload = {
      ...pkg,
      name: "vulnerable-package",
      format: "npm",
      num_vulnerabilities: "2",
      security_scan_status: "Scan Detected Vulnerabilities",
      max_severity: "High",
    };

    for (const NodeType of [PackageNode, SearchResultNode]) {
      const node = new NodeType(vulnerablePayload, {});
      const summary = node.getChildren().find(
        child => child.getTreeItem().contextValue === "vulnerabilitySummary"
      );
      assert.ok(summary, `${NodeType.name} omitted a real vulnerability summary`);
      assert.strictEqual(summary.getTreeItem().label, "Vulnerabilities: detected");
      assert.strictEqual(summary.getTreeItem().tooltip, "Expand to load vulnerability details.");
      assert.strictEqual(
        summary.getTreeItem().collapsibleState,
        vscode.TreeItemCollapsibleState.Collapsed
      );
    }

    const statusOnlyPayload = {
      ...pkg,
      name: "status-only-vulnerable-package",
      format: "python",
      security_scan_status: "Scan Detected Vulnerabilities",
    };
    delete statusOnlyPayload.num_vulnerabilities;

    for (const NodeType of [PackageNode, SearchResultNode]) {
      const node = new NodeType(statusOnlyPayload, {});
      const summary = node.getChildren().find(
        child => child.getTreeItem().contextValue === "vulnerabilitySummary"
      );
      assert.ok(summary, `${NodeType.name} omitted a status-only vulnerability summary`);
      assert.strictEqual(summary.getTreeItem().label, "Vulnerabilities: detected");
    }
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

  test("DependencyHealthNode preserves valid canonical and raw exact matches", () => {
    const canonical = fromApiPackageRecord(pkg);
    const dependency = {
      name: "artifact",
      version: "1.0.0",
      format: "raw",
      cloudsmithStatus: "FOUND",
    };
    const canonicalNode = new DependencyHealthNode({
      ...dependency,
      cloudsmithPackage: canonical,
    }, null, {});
    const rawNode = new DependencyHealthNode({
      ...dependency,
      cloudsmithPackage: pkg,
    }, null, {});

    assert.strictEqual(canonicalNode.package, canonical);
    assert.strictEqual(canonicalNode.cloudsmithMatch, canonical);
    assert.strictEqual(canonicalNode.cloudsmithStatus, "FOUND");
    assert.strictEqual(canonicalNode.state, rawNode.state);
    assert.strictEqual(canonicalNode.getTreeItem().contextValue, "dependencyHealthFound");
    assert.match(canonicalNode.getTreeItem().description, /Vulnerability status unknown/);
    assert.doesNotMatch(canonicalNode.getTreeItem().description, /No issues found/);
    assert.deepStrictEqual(
      rawNode.getChildren().map(child => child.getTreeItem().label),
      canonicalNode.getChildren().map(child => child.getTreeItem().label)
    );
    assert.strictEqual(rawNode.package.workspace, canonical.workspace);
    assert.strictEqual(rawNode.package.repository, canonical.repository);
    assert.strictEqual(rawNode.package.packageIdentifier, canonical.packageIdentifier);
  });

  test("DependencyHealthNode renders only meaningful status details", () => {
    const baseDependency = {
      name: "artifact",
      version: "1.0.0",
      format: "raw",
      cloudsmithStatus: "FOUND",
    };
    const packageWithStatus = fromApiPackageRecord(pkg);
    const packageWithoutStatus = fromApiPackageRecord({
      ...pkg,
      status_str: undefined,
    });
    const statusNode = new DependencyHealthNode({
      ...baseDependency,
      cloudsmithPackage: packageWithStatus,
    }, null, {});
    const policyNode = new DependencyHealthNode({
      ...baseDependency,
      cloudsmithPackage: packageWithStatus,
      policy: { status: "Policy quarantined" },
    }, null, {});
    const noStatusNode = new DependencyHealthNode({
      ...baseDependency,
      cloudsmithPackage: packageWithoutStatus,
    }, null, {});
    const invalidDisplayNodes = [{ unsafe: true }, 2].map(status => new DependencyHealthNode({
      ...baseDependency,
      cloudsmithPackage: packageWithoutStatus,
      policy: { status },
    }, null, {}));

    const details = node => node.getChildren().map(child => child.getTreeItem());
    assert.strictEqual(
      details(statusNode).find(item => item.tooltip.startsWith("Status:")).label,
      "Status"
    );
    assert.strictEqual(details(statusNode).find(item => item.tooltip.startsWith("Status:")).description, "Completed");
    assert.strictEqual(
      details(policyNode).find(item => item.tooltip.startsWith("Status:")).label,
      "Status"
    );
    assert.strictEqual(details(policyNode).find(item => item.tooltip.startsWith("Status:")).description, "Policy quarantined");
    for (const node of [noStatusNode, ...invalidDisplayNodes]) {
      const items = details(node);
      assert.strictEqual(items.some(item => item.tooltip.startsWith("Status:")), false);
      assert.ok(items.some(item => item.tooltip.startsWith("Version:") && item.label === "Version" && item.description === "1.0.0"));
      assert.strictEqual(items.some(item => [item.label, item.description].some(value => (
        ["Not available", "Unknown", "undefined", "[object Object]"].includes(value)
      ))), false);
    }
    assert.throws(() => fromApiPackageRecord({ ...pkg, status_str: "" }), /status/);
  });

  test("DependencyHealthNode reports unclassified match failures without exposing input", () => {
    const originalWarn = Object.getOwnPropertyDescriptor(console, "warn");
    const warnings = [];
    Object.defineProperty(console, "warn", {
      configurable: true,
      value: (...args) => warnings.push(args),
      writable: true,
    });
    try {
      const expectedBoundaryFailure = new DependencyHealthNode({
        name: "artifact",
        version: "1.0.0",
        format: "raw",
        cloudsmithStatus: "FOUND",
        cloudsmithPackage: { ...pkg, slug_perm: undefined },
      }, null, {});
      assert.strictEqual(expectedBoundaryFailure.package, null);
      assert.strictEqual(expectedBoundaryFailure.cloudsmithStatus, "LOOKUP_FAILED");
      assert.deepStrictEqual(warnings, []);

      const forgedAdapterError = Object.create(PackageAdapterError.prototype);
      Object.defineProperty(forgedAdapterError, "unexpected", { value: false });
      for (const thrownValue of [
        new Error("secret-bearing unexpected validation detail"),
        undefined,
        forgedAdapterError,
      ]) {
        const unstableTarget = { ...pkg };
        const targetPropertyCount = Reflect.ownKeys(unstableTarget).length;
        let descriptorReads = 0;
        const node = new DependencyHealthNode({
          name: "artifact",
          version: "1.0.0",
          format: "raw",
          cloudsmithStatus: "FOUND",
          cloudsmithPackage: new Proxy(unstableTarget, {
            getOwnPropertyDescriptor(target, field) {
              descriptorReads += 1;
              if (descriptorReads > targetPropertyCount) throw thrownValue;
              return Reflect.getOwnPropertyDescriptor(target, field);
            },
          }),
        }, null, {});

        assert.strictEqual(node.package, null);
        assert.strictEqual(node.cloudsmithStatus, "LOOKUP_FAILED");
        assert.deepStrictEqual(node.getChildren(), []);
      }
      assert.deepStrictEqual(warnings, [
        ["[Cloudsmith] Unexpected dependency package match validation failure."],
        ["[Cloudsmith] Unexpected dependency package match validation failure."],
        ["[Cloudsmith] Unexpected dependency package match validation failure."],
      ]);
      assert.doesNotMatch(JSON.stringify(warnings), /secret-bearing|validation detail/);
    } finally {
      Object.defineProperty(console, "warn", originalWarn);
    }
  });

  test("DependencyHealthNode contains malformed optional matches without restoring raw identity", () => {
    let accessorCalls = 0;
    const ownAccessor = { ...pkg };
    Object.defineProperty(ownAccessor, "slug_perm", {
      enumerable: true,
      get() {
        accessorCalls += 1;
        return "unsafe-accessor";
      },
    });
    const inheritedAccessor = Object.create({
      get slug_perm() {
        accessorCalls += 1;
        return "unsafe-inherited";
      },
    });
    for (const [key, value] of Object.entries(pkg)) {
      if (key !== "slug_perm") {
        Object.defineProperty(inheritedAccessor, key, {
          configurable: true,
          enumerable: true,
          value,
          writable: true,
        });
      }
    }
    const nonPlain = Object.assign(Object.create({ customPrototype: true }), pkg);
    const malformedMatches = [
      { ...pkg, slug_perm: undefined },
      { ...pkg, name: undefined },
      { ...pkg, version: undefined },
      { ...pkg, format: undefined },
      nonPlain,
      ownAccessor,
      inheritedAccessor,
      new Proxy({}, {
        getPrototypeOf() {
          throw new Error("getPrototypeOf trap must be contained");
        },
      }),
      new Proxy({}, {
        ownKeys() {
          throw new Error("ownKeys trap must be contained");
        },
      }),
      { ...pkg, slug_perm_raw: "conflicting-package-id" },
    ];

    for (const malformedMatch of malformedMatches) {
      let registeredSummaries = 0;
      const node = new DependencyHealthNode({
        name: "artifact",
        version: "1.0.0",
        format: "raw",
        cloudsmithStatus: "FOUND",
        cloudsmithPackage: malformedMatch,
      }, null, {}, {
        registerVulnerabilitySummary() {
          registeredSummaries += 1;
        },
      });
      const item = node.getTreeItem();

      assert.strictEqual(node.package, null);
      assert.strictEqual(node.cloudsmithMatch, null);
      assert.strictEqual(node.cloudsmithStatus, "LOOKUP_FAILED");
      assert.strictEqual(node.state, "lookup_failed");
      assert.strictEqual(node.namespace, undefined);
      assert.strictEqual(node.repository, undefined);
      assert.strictEqual(node.slug_perm, undefined);
      assert.strictEqual(node.status_str, undefined);
      assert.strictEqual(node.num_vulnerabilities, undefined);
      assert.strictEqual(item.contextValue, "dependencyHealthUnknown");
      assert.strictEqual(item.collapsibleState, vscode.TreeItemCollapsibleState.None);
      assert.match(item.description, /Cloudsmith lookup failed/);
      assert.doesNotMatch(item.description, /Not found|No issues found|Quarantined/);
      assert.doesNotMatch(item.tooltip, /Found in Cloudsmith|Vulnerabilities: none known|Quarantined/);
      assert.deepStrictEqual(node.getChildren(), []);
      assert.strictEqual(registeredSummaries, 0);
    }
    assert.strictEqual(accessorCalls, 0);
  });

  test("DependencyHealthNode does not turn rejected zero-vulnerability evidence into clean state", () => {
    const node = new DependencyHealthNode({
      name: "artifact",
      version: "1.0.0",
      format: "raw",
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: {
        ...pkg,
        slug_perm: undefined,
        num_vulnerabilities: 0,
        security_scan_status: "Scan Detected No Vulnerabilities",
        status_str: "Quarantined",
      },
    }, null, {});

    assert.strictEqual(node.package, null);
    assert.strictEqual(node.cloudsmithStatus, "LOOKUP_FAILED");
    assert.strictEqual(node._getVulnerabilityData(), null);
    assert.strictEqual(node._getPolicyData(), null);
    assert.doesNotMatch(node.getTreeItem().description, /No issues found|Quarantined/);
    assert.deepStrictEqual(node.getChildren(), []);
  });

  test("DependencyHealthNode contains malformed matches from every compatibility input", () => {
    const malformedMatch = {
      ...pkg,
      name: undefined,
      slug_perm: "untrusted-package-id",
      repository: "untrusted-repository",
      slug_perm_raw: "untrusted-package-id",
    };
    const nodes = [
      new DependencyHealthNode({
        name: "artifact",
        version: "1.0.0",
        format: "raw",
        cloudsmithStatus: "FOUND",
        cloudsmithPackage: malformedMatch,
      }, null, {}),
      new DependencyHealthNode({
        name: "artifact",
        version: "1.0.0",
        format: "raw",
        cloudsmithStatus: "FOUND",
        cloudsmithMatch: malformedMatch,
      }, null, {}),
      new DependencyHealthNode({
        name: "artifact",
        version: "1.0.0",
        format: "raw",
        cloudsmithStatus: "FOUND",
      }, malformedMatch, {}),
    ];

    for (const node of nodes) {
      assert.strictEqual(node.package, null);
      assert.strictEqual(node.cloudsmithMatch, null);
      assert.strictEqual(node.cloudsmithStatus, "LOOKUP_FAILED");
      assert.strictEqual(node.repository, undefined);
      assert.strictEqual(node.slug_perm_raw, undefined);
      assert.deepStrictEqual(node.getChildren(), []);
    }
  });

  test("DependencyHealthNode requires consensus across simultaneous package evidence", () => {
    const canonical = fromApiPackageRecord(pkg);
    const conflicts = [
      {
        cloudsmithPackage: pkg,
        cloudsmithMatch: { ...pkg, version: "9.9.9" },
      },
      {
        cloudsmithPackage: "",
        cloudsmithMatch: pkg,
      },
      {
        cloudsmithPackage: pkg,
        repository: "conflicting-repository",
      },
      {
        package: createPackageCoordinate({
          workspace: canonical.workspace,
          repository: canonical.repository,
          name: canonical.name,
          version: canonical.version,
          format: canonical.format,
        }),
      },
    ];

    for (const evidence of conflicts) {
      const node = new DependencyHealthNode({
        name: "artifact",
        version: "1.0.0",
        format: "raw",
        cloudsmithStatus: "FOUND",
        ...evidence,
      }, null, {});
      assert.strictEqual(node.package, null);
      assert.strictEqual(node.cloudsmithMatch, null);
      assert.strictEqual(node.cloudsmithStatus, "LOOKUP_FAILED");
      assert.deepStrictEqual(node.getChildren(), []);
    }

    const explicitConflict = new DependencyHealthNode({
      name: "artifact",
      version: "1.0.0",
      format: "raw",
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: pkg,
    }, { ...pkg, slug_perm: "conflicting-explicit-id" }, {});
    assert.strictEqual(explicitConflict.package, null);
    assert.strictEqual(explicitConflict.cloudsmithStatus, "LOOKUP_FAILED");
  });

  test("DependencyHealthNode preserves independent dependency license evidence after match rejection", () => {
    const node = new DependencyHealthNode({
      name: "artifact",
      version: "1.0.0",
      format: "raw",
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: {
        ...pkg,
        slug_perm: undefined,
        license: "Rejected raw license",
      },
      license: {
        display: "Apache-2.0",
        spdx: "Apache-2.0",
        raw: "Apache-2.0",
        url: "https://spdx.org/licenses/Apache-2.0.html",
      },
    }, null, {});

    assert.strictEqual(node.package, null);
    assert.strictEqual(node.cloudsmithStatus, "LOOKUP_FAILED");
    assert.strictEqual(node.licenseInfo.displayValue, "Apache-2.0");
    assert.notStrictEqual(node.licenseInfo.displayValue, "Rejected raw license");
  });

  test("DependencyHealthNode preserves no-match and explicit uncertainty states", () => {
    for (const [cloudsmithStatus, expectedState] of [
      ["LOOKUP_FAILED", "lookup_failed"],
      ["NOT_FOUND", "not_found"],
      [null, "unknown"],
    ]) {
      const node = new DependencyHealthNode({
        name: "artifact",
        version: "1.0.0",
        format: "raw",
        cloudsmithStatus,
      }, null, {});
      assert.strictEqual(node.cloudsmithStatus, cloudsmithStatus);
      assert.strictEqual(node.state, expectedState);
      assert.strictEqual(node.package, null);
      assert.ok(node.getTreeItem());
    }
  });

  test("DependencyHealthNode does not retain exact enrichment for non-FOUND states", () => {
    for (const cloudsmithStatus of ["LOOKUP_FAILED", "NOT_FOUND", "CHECKING"]) {
      const node = new DependencyHealthNode({
        name: "artifact",
        version: "1.0.0",
        format: "raw",
        cloudsmithStatus,
        cloudsmithPackage: pkg,
      }, null, {});

      assert.strictEqual(node.cloudsmithStatus, cloudsmithStatus);
      assert.strictEqual(node.package, null);
      assert.strictEqual(node.cloudsmithMatch, null);
      assert.strictEqual(node.namespace, undefined);
      assert.strictEqual(node.repository, undefined);
      assert.strictEqual(node.slug_perm, undefined);
      assert.deepStrictEqual(node.getChildren(), []);
      assert.notStrictEqual(node.getTreeItem().contextValue, "dependencyHealthFound");
      assert.notStrictEqual(node.getTreeItem().contextValue, "dependencyHealthVulnerable");
      assert.notStrictEqual(node.getTreeItem().contextValue, "dependencyHealthQuarantined");
    }
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

    assert.strictEqual(cleanNode.getTreeItem().description, "4.18.2 — Vulnerability status unknown");
    assert.strictEqual(vulnerableNode.getTreeItem().description, "4.18.2 — Vulnerabilities found (2 High)");
    assert.strictEqual(quarantinedNode.getTreeItem().description, "4.18.2 — Quarantined");
  });

  test("dependency vulnerability indicators never turn conflicting positive evidence into clean state", () => {
    const cloudsmithPackage = {
      ...pkg,
      vulnerability_scan_results_count: 0,
      has_vulnerabilities: true,
      max_severity: undefined,
    };
    const node = new DependencyHealthNode({
      name: "artifact",
      version: "4.18.2",
      format: "raw",
      cloudsmithStatus: "FOUND",
      cloudsmithPackage,
    }, cloudsmithPackage, {});

    assert.match(node.getTreeItem().description, /Vulnerabilities detected/);
    assert.doesNotMatch(node.getTreeItem().description, /undefined/);
    assert.strictEqual(node.num_vulnerabilities, -1);
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

    assert.strictEqual(node.getTreeItem().description, "1.0.0 — Vulnerability status unknown");
    assert.match(node.getTreeItem().tooltip, /License: No license detected/);
  });

  test("dependency health tooltips do not expose source credentials or absolute paths", () => {
    const remoteNode = new DependencyHealthNode({
      name: "remote-artifact",
      version: "1.0.0",
      format: "cargo",
      cloudsmithStatus: "NOT_APPLICABLE",
      packageSource: {
        kind: "git",
        location: "https://user:secret@example.com/team/repo.git?token=hidden#main",
        branch: "https://branch-user:branch-secret@example.com/release?token=hidden",
        revision: "/Users/private-user/workspace/private-revision.txt",
      },
      qualifiers: {
        repository: "https://repo-user:repo-secret@example.com/index?api_key=hidden",
      },
    }, {});
    const localNode = new DependencyHealthNode({
      name: "local-artifact",
      version: "1.0.0",
      format: "maven",
      cloudsmithStatus: "NOT_APPLICABLE",
      packageSource: {
        kind: "path",
        location: "/Users/private-user/workspace/libs/local-artifact.jar",
      },
    }, {});

    const remoteTooltip = remoteNode.getTreeItem().tooltip;
    const localTooltip = localNode.getTreeItem().tooltip;
    assert.match(remoteTooltip, /Source location: https:\/\/example\.com\/team\/repo\.git/);
    assert.match(remoteTooltip, /Source branch: https:\/\/example\.com\/release/);
    assert.match(remoteTooltip, /Source revision: private-revision\.txt/);
    assert.match(remoteTooltip, /Repository: https:\/\/example\.com\/index/);
    assert.doesNotMatch(
      remoteTooltip,
      /user:secret|branch-user|branch-secret|repo-user|repo-secret|private-user|\/Users\/|token=|api_key=|#main/
    );
    assert.match(localTooltip, /Source location: local-artifact\.jar/);
    assert.doesNotMatch(localTooltip, /private-user|\/Users\//);
  });

  test("dependency qualifier presentation omits absent and non-display values", () => {
    const node = new DependencyHealthNode({
      name: "qualified-artifact",
      version: "1.0.0",
      format: "docker",
      cloudsmithStatus: "NOT_APPLICABLE",
      packageSource: { kind: "registry" },
      qualifiers: {
        platform: "linux-x64",
        configurations: ["runtime", "test"],
        repository: "https://user:secret@example.com/index?token=hidden#private",
        tag: 0,
        classifier: undefined,
        alias: "",
        scope: { unsafe: "raw-object" },
      },
    }, {});
    const unsafeNode = new DependencyHealthNode({
      name: "legacy-artifact",
      version: "1.0.0",
      format: "maven",
      cloudsmithStatus: "NOT_APPLICABLE",
      qualifiers: {
        repository: { unsafe: "https://user:secret@example.com/?token=hidden" },
        configurations: [{ unsafe: "raw-object" }],
      },
    }, {});
    const emptyNode = new DependencyHealthNode({
      name: "plain-artifact",
      version: "1.0.0",
      format: "npm",
      cloudsmithStatus: "NOT_APPLICABLE",
      qualifiers: {},
    }, {});
    const unsafeLookupNode = new DependencyHealthNode({
      name: "local-artifact",
      version: "1.0.0",
      format: "npm",
      cloudsmithStatus: "NOT_APPLICABLE",
      cloudsmithLookupDetail: { unsafe: "raw-lookup-detail" },
      qualifiers: {},
    }, {});
    const unsafeUpstreamNode = new DependencyHealthNode({
      name: "missing-artifact",
      version: "1.0.0",
      format: "npm",
      cloudsmithStatus: "NOT_FOUND",
      upstreamDetail: { unsafe: "raw-upstream-detail" },
      qualifiers: {},
    }, {});

    const item = node.getTreeItem();
    const tooltip = item.tooltip;
    assert.match(item.description, /\[linux-x64\]/);
    assert.match(tooltip, /Platform: linux-x64/);
    assert.match(tooltip, /Configurations: runtime, test/);
    assert.match(tooltip, /Repository: https:\/\/example\.com\/index/);
    assert.match(tooltip, /Tag: 0/);
    assert.doesNotMatch(tooltip, /Classifier:|Alias:|Scope:/);
    assert.doesNotMatch(
      tooltip,
      /null|undefined|\[object Object\]|user:secret|token=|#private|raw-object/
    );
    assert.doesNotMatch(
      unsafeNode.getTreeItem().tooltip,
      /Repository:|Configurations:|null|undefined|\[object Object\]|user:secret|token=|raw-object/
    );
    assert.doesNotMatch(
      emptyNode.getTreeItem().tooltip,
      /Platform:|Configurations:|Repository:|Tag:|Classifier:|Alias:|Scope:/
    );
    assert.doesNotMatch(
      `${unsafeLookupNode.getTreeItem().tooltip}\n${unsafeUpstreamNode.getTreeItem().tooltip}`,
      /\[object Object\]|raw-lookup-detail|raw-upstream-detail/
    );
  });

  test("dependency tooltip renders qualifier-bearing ecosystem values", () => {
    const fixtures = [
      ["maven", { classifier: "tests", type: "test-jar" }, ["Classifier: tests", "Type: test-jar"]],
      ["gradle", { configurations: ["runtimeClasspath", "testRuntimeClasspath"] }, ["Configurations: runtimeClasspath, testRuntimeClasspath"]],
      ["ruby", { platform: "arm64-darwin" }, ["Platform: arm64-darwin"]],
      ["docker", { stage: "builder", service: "api", pullPolicy: "always", tag: "1.2.3", digest: "sha256:abc" }, ["Stage: builder", "Service: api", "Pull policy: always", "Tag: 1.2.3", "Digest: sha256:abc"]],
      ["nuget", { targetFramework: "net8.0" }, ["Target framework: net8.0"]],
      ["helm", { repository: "https://charts.example.com/private?token=hidden", alias: "cache" }, ["Repository: https://charts.example.com/private", "Alias: cache"]],
      ["swift", { scope: "acme" }, ["Scope: acme"]],
      ["hex", { environment: "dev" }, ["Environment: dev"]],
    ];

    for (const [format, qualifiers, expectedLines] of fixtures) {
      const tooltip = new DependencyHealthNode({
        name: `${format}-artifact`,
        version: "1.0.0",
        format,
        cloudsmithStatus: "NOT_APPLICABLE",
        packageSource: { kind: "registry" },
        qualifiers,
      }, {}).getTreeItem().tooltip;

      for (const line of expectedLines) assert.match(tooltip, new RegExp(line));
      assert.doesNotMatch(tooltip, /null|undefined|\[object Object\]|token=hidden/);
    }
  });

  test("dependency source labels never expose legacy absolute paths", () => {
    const tooltip = new DependencyHealthNode({
      name: "legacy-source",
      version: "1.0.0",
      format: "maven",
      cloudsmithStatus: "NOT_APPLICABLE",
      sourceManifest: {
        label: "/Users/private-user/workspace/pom.xml",
      },
      qualifiers: {},
    }, {}).getTreeItem().tooltip;

    assert.match(tooltip, /Source: pom\.xml/);
    assert.doesNotMatch(tooltip, /private-user|\/Users\//);
  });

  test("dependency summary omits a zero not-applicable detail", () => {
    const zeroTooltip = new DependencySummaryNode({
      total: 5,
      artifacts: 5,
      applicableArtifacts: 5,
      found: 3,
      coveragePercent: 60,
      notApplicable: 0,
    }).getTreeItem().tooltip;
    const positiveTooltip = new DependencySummaryNode({
      total: 5,
      artifacts: 5,
      applicableArtifacts: 4,
      found: 3,
      coveragePercent: 75,
      notApplicable: 1,
    }).getTreeItem().tooltip;

    assert.doesNotMatch(zeroTooltip, /0 not applicable/);
    assert.match(positiveTooltip, /1 not applicable/);
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

  test("dependency health uncertainty never renders as not found", () => {
    const cases = [
      ["UNRESOLVED", "^4.18.0", "Version unresolved"],
      ["LOOKUP_FAILED", "4.18.2", "Cloudsmith lookup failed"],
      ["LOOKUP_INCOMPLETE", "4.18.2", "Cloudsmith lookup incomplete"],
      ["RATE_LIMITED", "4.18.2", "Cloudsmith lookup rate limited"],
    ];

    for (const [cloudsmithStatus, displayVersion, expectedDetail] of cases) {
      const node = new DependencyHealthNode({
        name: "express",
        version: displayVersion,
        legacyVersion: cloudsmithStatus === "UNRESOLVED" ? "4.18.0" : displayVersion,
        declaredConstraint: cloudsmithStatus === "UNRESOLVED" ? displayVersion : null,
        resolvedVersion: cloudsmithStatus === "UNRESOLVED" ? null : displayVersion,
        versionState: cloudsmithStatus === "UNRESOLVED" ? "range" : "resolved",
        format: "npm",
        cloudsmithStatus,
        cloudsmithLookupDetail: "Evidence was incomplete.",
      }, null, {});
      const item = node.getTreeItem();

      assert.strictEqual(item.contextValue, "dependencyHealthUnknown");
      assert.match(item.description, new RegExp(expectedDetail));
      assert.doesNotMatch(item.description, /Not found/);
      assert.doesNotMatch(item.tooltip, /Not found/);
      assert.match(item.tooltip, /Evidence was incomplete/);
      if (cloudsmithStatus === "UNRESOLVED") {
        assert.match(item.description, /^\^4\.18\.0/);
        assert.doesNotMatch(item.description, /^4\.18\.0/);
      }
    }
  });

  test("package, search, and dependency models preserve only literal copyability booleans", () => {
    for (const [value, expected] of [[true, true], [false, false], [undefined, null]]) {
      const packageNode = new PackageNode({ ...pkg, is_copyable: value }, {});
      const searchNode = new SearchResultNode({ ...pkg, is_copyable: value }, {});
      const dependencyNode = new DependencyHealthNode({
        name: pkg.name,
        version: pkg.version,
        format: pkg.format,
        cloudsmithPackage: { ...pkg, is_copyable: value },
      }, null, {});
      assert.strictEqual(packageNode.is_copyable, expected);
      assert.strictEqual(searchNode.is_copyable, expected);
      assert.strictEqual(dependencyNode.is_copyable, expected);
    }

    for (const createNode of [
      () => new PackageNode({ ...pkg, is_copyable: "false" }, {}),
      () => new SearchResultNode({ ...pkg, is_copyable: "false" }, {}),
    ]) {
      assert.throws(createNode, TypeError);
    }

    const containedDependency = new DependencyHealthNode({
      name: pkg.name,
      version: pkg.version,
      format: pkg.format,
      cloudsmithStatus: "FOUND",
      cloudsmithPackage: { ...pkg, is_copyable: "false" },
    }, null, {});
    assert.strictEqual(containedDependency.package, null);
    assert.strictEqual(containedDependency.cloudsmithStatus, "LOOKUP_FAILED");
  });
});

// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const manifest = require("../package.json");
const { registerPackageCommands } = require("../commands/packages");
const { registerVulnerabilityCommands } = require("../commands/vulnerabilities");
const packageAdapters = require("../domain/packageAdapters");
const packageDomain = require("../domain/package");
const {
  serializePackageCollectionInspection,
  serializePackageInspection,
} = require("../util/packageInspection");
const { normalizeCvssScore } = require("../util/vulnerabilitySeverity");

function recorder() {
  const handlers = new Map();
  return {
    handlers,
    registerCommand(id, handler) {
      handlers.set(id, handler);
      return { dispose() { handlers.delete(id); } };
    },
  };
}

function accountAccess() {
  const account = Object.freeze({ activationId: "activation-a", accountEpoch: 1 });
  return {
    connectionManager: {},
    captureAccount: () => account,
    isAccountCurrent: () => true,
  };
}

function exactPackage(overrides = {}) {
  return packageDomain.createExactPackage({
    workspace: "workspace-a",
    repository: "repo-a",
    packageIdentifier: "package-one",
    name: "widget",
    version: "1.0.0",
    format: "npm",
    status: "Completed",
    copyable: true,
    ...overrides,
  });
}

class SearchQueryBuilder {
  raw() { return this; }
  status() { return this; }
  build() { return "query"; }
}

class InstallCommandBuilder {
  static build() {
    return {
      command: "npm install widget@1.0.0",
      alternatives: [{ label: "Alternative", command: "npm i widget@1.0.0" }],
    };
  }

  static toClipboardCommand(value) { return value; }
}

function packageDeps(registration, overrides = {}) {
  return {
    registerCommand: registration.registerCommand.bind(registration),
    vscode: {
      workspace: { getConfiguration: () => ({ get: () => false }) },
      window: {
        showInformationMessage() {},
        showWarningMessage() {},
        showErrorMessage() {},
      },
    },
    context: {},
    workspaceAccess: accountAccess(),
    packageAdapters,
    packageDomain,
    recentPackages: { getAll: () => [], add() {} },
    cloudsmithProvider: { refresh() {}, refreshNode() {} },
    searchProvider: { refresh() {}, refreshNode() {} },
    dependencyHealthProvider: { refresh() {}, refreshNode() {} },
    inspectOutputChannel: { clear() {}, show() {}, append() {} },
    CloudsmithAPI: class {},
    apiEndpoint: () => "packages/workspace-a/repo-a/package-one/",
    PaginatedFetch: class {},
    packageCollectionIdentity: () => "identity",
    SearchQueryBuilder,
    LicenseClassifier: {
      buildRestrictiveQuery: () => "license:restrictive",
      inspect: () => null,
    },
    InstallCommandBuilder,
    InstallCommandValidationError: class extends Error {},
    buildPackageUrl: () => "https://cloudsmith.example/package",
    buildPackageGroupUrl: () => "https://cloudsmith.example/group",
    filterState: { activeFilters: new Map() },
    serializePackageCollectionInspection,
    serializePackageInspection,
    formatApiError: error => error.message,
    isCurrentSelection: () => true,
    isCurrentPackageSelection: () => true,
    isCurrentPackageGroupSelection: () => true,
    isCurrentRepositorySelection: () => true,
    isCurrentEntitlementSelection: () => true,
    ...overrides,
  };
}

function vulnerabilityDeps(registration, overrides = {}) {
  return {
    registerCommand: registration.registerCommand.bind(registration),
    vscode: {
      QuickPickItemKind: { Separator: 1 },
      window: {
        showInformationMessage() {},
        showWarningMessage() {},
        showErrorMessage() {},
      },
    },
    context: {},
    workspaceAccess: accountAccess(),
    packageAdapters,
    packageDomain,
    recentPackages: { getAll: () => [], add() {} },
    CloudsmithAPI: class {},
    RemediationHelper: class {},
    InstallCommandBuilder,
    InstallCommandValidationError: class extends Error {},
    buildPackageUrl: () => "https://cloudsmith.example/package",
    vulnerabilityProvider: { async show() {} },
    quarantineExplainProvider: { async show() {} },
    cloudsmithProvider: { refreshNode() {} },
    searchProvider: { refreshNode() {} },
    dependencyHealthProvider: { refreshNode() {}, getLastSuccessfulScope: () => null },
    normalizeCvssScore,
    formatApiError: error => error.message,
    isCurrentSelection: () => true,
    isCurrentPackageSelection: () => true,
    isCurrentDependencySelection: () => true,
    ...overrides,
  };
}

suite("Command selection freshness", () => {
  test("install menus and callbacks require exact copyable non-quarantined packages", async () => {
    const installCommands = new Set([
      "cloudsmith-vsc.copyInstallCommand",
      "cloudsmith-vsc.showInstallCommand",
    ]);
    const menuEntries = manifest.contributes.menus["view/item/context"]
      .filter(entry => installCommands.has(entry.command));
    assert.strictEqual(menuEntries.length, 6);
    assert(menuEntries.every(entry => !entry.when.includes("packageNotCopyable")));
    assert(menuEntries.every(entry => !entry.when.includes("packageQuarantined")));

    const registration = recorder();
    const warnings = [];
    let builds = 0;
    class RecordingBuilder extends InstallCommandBuilder {
      static build(...args) {
        builds += 1;
        return super.build(...args);
      }
    }
    registerPackageCommands(packageDeps(registration, {
      InstallCommandBuilder: RecordingBuilder,
      vscode: {
        workspace: { getConfiguration: () => ({ get: () => false }) },
        window: {
          showInformationMessage() {},
          showWarningMessage: message => warnings.push(message),
        },
      },
    }));
    const install = registration.handlers.get("cloudsmith-vsc.copyInstallCommand");
    await install(exactPackage({ copyable: false }));
    await install(exactPackage({ status: "Quarantined", copyable: true }));
    await install({
      namespace: "workspace-a",
      repository: "repo-a",
      name: "widget",
      format: "npm",
    });
    assert.strictEqual(builds, 0);
    assert.strictEqual(warnings.length, 3);
  });

  test("install variant and repository-filter prompts stop on same-account detachment", async () => {
    const registration = recorder();
    let packageOwned = true;
    let repositoryOwned = true;
    let clipboardWrites = 0;
    let refreshes = 0;
    const activeFilters = new Map();
    registerPackageCommands(packageDeps(registration, {
      isCurrentPackageSelection: () => packageOwned,
      isCurrentRepositorySelection: () => repositoryOwned,
      filterState: { activeFilters },
      cloudsmithProvider: { refresh() { refreshes += 1; } },
      vscode: {
        workspace: { getConfiguration: () => ({ get: () => false }) },
        env: { clipboard: { async writeText() { clipboardWrites += 1; } } },
        window: {
          showInformationMessage() {},
          showWarningMessage() {},
          async showQuickPick(items, options) {
            if (options.placeHolder === "Select an install command") {
              packageOwned = false;
            } else {
              repositoryOwned = false;
            }
            return items[0];
          },
        },
      },
    }));

    await registration.handlers.get("cloudsmith-vsc.copyInstallCommand")(exactPackage());
    assert.strictEqual(clipboardWrites, 0);

    await registration.handlers.get("cloudsmith-vsc.filterPackages")({
      workspace: "workspace-a",
      slug: "repo-a",
      name: "Repo A",
    });
    assert.strictEqual(activeFilters.size, 0);
    assert.strictEqual(refreshes, 0);
  });

  test("inspection failures retain operation context and stale service completions stay silent", async () => {
    const pkg = exactPackage();
    const errors = [];
    let owned = true;
    let staleOnRead = false;
    class FailingAPI {
      async get() {
        if (staleOnRead) owned = false;
        return { ok: false, error: { message: "service unavailable" } };
      }
    }
    const registration = recorder();
    registerPackageCommands(packageDeps(registration, {
      isCurrentPackageSelection: () => owned,
      CloudsmithAPI: FailingAPI,
      vscode: {
        workspace: { getConfiguration: () => ({ get: () => false }) },
        window: {
          showErrorMessage: message => errors.push(message),
          showWarningMessage() {},
        },
      },
    }));
    const inspect = registration.handlers.get("cloudsmith-vsc.inspectPackage");
    await inspect(pkg);
    assert.deepStrictEqual(errors, ["Could not inspect package. service unavailable"]);

    errors.length = 0;
    staleOnRead = true;
    await inspect(pkg);
    assert.deepStrictEqual(errors, []);

    const groupRegistration = recorder();
    registerPackageCommands(packageDeps(groupRegistration, {
      packageAdapters: {
        ...packageAdapters,
        fromPackageGroupNode: () => ({
          workspace: "workspace-a",
          repository: "repo-a",
          name: "widget",
          format: "npm",
        }),
      },
      SearchQueryBuilder: class {
        name() { return this; }
        format() { return this; }
        build() { return "name:widget"; }
      },
      PaginatedFetch: class {
        async fetchCollection() {
          return {
            complete: false,
            items: [],
            failures: [{ error: { message: "group service unavailable" } }],
            failureCount: 1,
          };
        }
      },
      vscode: { window: { showErrorMessage: message => errors.push(message) } },
    }));
    await groupRegistration.handlers.get("cloudsmith-vsc.inspectPackageGroup")({});
    assert.match(errors[0], /^Could not inspect package group\./);
  });

  test("inspection document and output-channel failures are contained with contextual errors", async () => {
    const errors = [];
    const apiRecord = {
      namespace: "workspace-a",
      repository: "repo-a",
      slug_perm: "package-one",
      name: "widget",
      version: "1.0.0",
      format: "npm",
      status_str: "Completed",
      is_copyable: true,
    };
    const registration = recorder();
    registerPackageCommands(packageDeps(registration, {
      CloudsmithAPI: class {
        async get() { return { ok: true, data: apiRecord }; }
      },
      vscode: {
        workspace: {
          getConfiguration: () => ({ get: () => true }),
          async openTextDocument() { throw new Error("document service unavailable"); },
        },
        window: {
          showErrorMessage: message => errors.push(message),
          showWarningMessage() {},
        },
      },
    }));
    await registration.handlers.get("cloudsmith-vsc.inspectPackage")(exactPackage());
    assert.deepStrictEqual(errors, [
      "Could not inspect package. The inspection output could not be opened.",
    ]);

    const groupRegistration = recorder();
    registerPackageCommands(packageDeps(groupRegistration, {
      packageAdapters: {
        ...packageAdapters,
        fromPackageGroupNode: () => ({
          workspace: "workspace-a",
          repository: "repo-a",
          name: "widget",
          format: "npm",
        }),
      },
      SearchQueryBuilder: class {
        name() { return this; }
        format() { return this; }
        build() { return "name:widget"; }
      },
      PaginatedFetch: class {
        async fetchCollection() {
          return {
            complete: true,
            items: [apiRecord],
            failureCount: 0,
          };
        }
      },
      inspectOutputChannel: {
        clear() { throw new Error("output channel unavailable"); },
        show() {},
        append() {},
      },
      vscode: {
        workspace: { getConfiguration: () => ({ get: () => false }) },
        window: { showErrorMessage: message => errors.push(message) },
      },
    }));
    await groupRegistration.handlers.get("cloudsmith-vsc.inspectPackageGroup")({});
    assert.deepStrictEqual(errors, [
      "Could not inspect package. The inspection output could not be opened.",
      "Could not inspect package group. The inspection output could not be opened.",
    ]);
  });

  test("quarantine explanation applies its predicate after canonical assertion", async () => {
    const registration = recorder();
    const warnings = [];
    let providerCalls = 0;
    let assertions = 0;
    registerVulnerabilityCommands(vulnerabilityDeps(registration, {
      packageDomain: {
        assertExactPackage(value) {
          assertions += 1;
          return packageDomain.assertExactPackage(value);
        },
      },
      quarantineExplainProvider: { async show() { providerCalls += 1; } },
      vscode: { window: { showWarningMessage: message => warnings.push(message) } },
    }));
    await registration.handlers.get("cloudsmith-vsc.explainQuarantine")(exactPackage());
    assert.strictEqual(assertions, 1);
    assert.strictEqual(providerCalls, 0);
    assert.deepStrictEqual(warnings, [
      "Quarantine details are available only for quarantined packages.",
    ]);
  });

  test("recovered quarantine selection is canonically asserted before eligibility and provider use", async () => {
    const registration = recorder();
    const quarantined = exactPackage({ status: "Quarantined" });
    let assertions = 0;
    let shown = null;
    registerVulnerabilityCommands(vulnerabilityDeps(registration, {
      packageDomain: {
        assertExactPackage(value) {
          assertions += 1;
          return packageDomain.assertExactPackage(value);
        },
      },
      recentPackages: { getAll: () => [quarantined], add() {} },
      quarantineExplainProvider: { async show(value) { shown = value; } },
      vscode: { window: { showQuickPick: async items => items[0] } },
    }));
    await registration.handlers.get("cloudsmith-vsc.explainQuarantine")();
    assert(assertions >= 2);
    assert.strictEqual(shown, quarantined);

    const rejectedRegistration = recorder();
    const information = [];
    let rejectedProviderCalls = 0;
    registerVulnerabilityCommands(vulnerabilityDeps(rejectedRegistration, {
      recentPackages: { getAll: () => [exactPackage()], add() {} },
      quarantineExplainProvider: { async show() { rejectedProviderCalls += 1; } },
      vscode: {
        window: { showInformationMessage: message => information.push(message) },
      },
    }));
    await rejectedRegistration.handlers.get("cloudsmith-vsc.explainQuarantine")();
    assert.strictEqual(rejectedProviderCalls, 0);
    assert.deepStrictEqual(information, [
      "No recent quarantined packages. Open a quarantined package, then try again.",
    ]);
  });

  test("vulnerability filters revalidate ownership after every picker, setter, and refresh", async () => {
    for (const staleAt of [1, 2, 3]) {
      const registration = recorder();
      let owned = true;
      let prompt = 0;
      let mutations = 0;
      let refreshes = 0;
      const summary = {
        setSeverityFilter() { mutations += 1; },
        setCvssThreshold() { mutations += 1; },
      };
      registerVulnerabilityCommands(vulnerabilityDeps(registration, {
        isCurrentSelection: item => owned && item === summary,
        cloudsmithProvider: { refreshNode() { refreshes += 1; } },
        searchProvider: { refreshNode() { refreshes += 1; } },
        dependencyHealthProvider: { refreshNode() { refreshes += 1; } },
        vscode: {
          window: {
            async showQuickPick(items) {
              prompt += 1;
              if (prompt === staleAt) owned = false;
              if (prompt === 1) return items.find(item => item.value === "cvss");
              return items.find(item => item.value === "custom");
            },
            async showInputBox() {
              prompt += 1;
              if (prompt === staleAt) owned = false;
              return "7.5";
            },
          },
        },
      }));
      await registration.handlers.get("cloudsmith-vsc.filterVulnerabilities")(summary);
      assert.strictEqual(mutations, 0);
      assert.strictEqual(refreshes, 0);
    }

    const registration = recorder();
    let owned = true;
    let searchRefreshes = 0;
    const summary = {
      setSeverityFilter() { owned = false; },
      setCvssThreshold() { throw new Error("must not run"); },
    };
    registerVulnerabilityCommands(vulnerabilityDeps(registration, {
      isCurrentSelection: item => owned && item === summary,
      cloudsmithProvider: { refreshNode() { owned = false; } },
      searchProvider: { refreshNode() { searchRefreshes += 1; } },
      vscode: {
        window: {
          showQuickPick: async items => items.find(item => item.value === "clear"),
        },
      },
    }));
    await registration.handlers.get("cloudsmith-vsc.filterVulnerabilities")(summary);
    assert.strictEqual(searchRefreshes, 0);
  });

  test("safe-version actions omit ineligible installs and discard detached service results", async () => {
    for (const overrides of [
      { is_copyable: false, status_str: "Completed" },
      { is_copyable: true, status_str: "Quarantined" },
    ]) {
      const registration = recorder();
      let actionItems = null;
      let picker = 0;
      class RemediationHelper {
        async findSafeVersions() {
          return {
            success: true,
            complete: true,
            totalCount: 1,
            versions: [{
              namespace: "workspace-a",
              repository: "repo-a",
              slug_perm: "safe-package",
              name: "widget",
              version: "2.0.0",
              format: "npm",
              ...overrides,
            }],
          };
        }
      }
      registerVulnerabilityCommands(vulnerabilityDeps(registration, {
        RemediationHelper,
        vscode: {
          QuickPickItemKind: { Separator: 1 },
          window: {
            async showQuickPick(items) {
              picker += 1;
              if (picker === 1) return items.find(item => item.package);
              actionItems = items;
              return undefined;
            },
            showErrorMessage() {},
            showWarningMessage() {},
          },
        },
      }));
      await registration.handlers.get("cloudsmith-vsc.findSafeVersion")(exactPackage());
      assert(actionItems);
      assert.strictEqual(actionItems.some(item => item.id === "install"), false);
    }

    const registration = recorder();
    let owned = true;
    let pickerCalls = 0;
    class DetachingRemediationHelper {
      async findSafeVersions() {
        owned = false;
        return { success: true, complete: true, totalCount: 0, versions: [] };
      }
    }
    registerVulnerabilityCommands(vulnerabilityDeps(registration, {
      isCurrentPackageSelection: () => owned,
      RemediationHelper: DetachingRemediationHelper,
      vscode: { window: { showQuickPick() { pickerCalls += 1; } } },
    }));
    await registration.handlers.get("cloudsmith-vsc.findSafeVersion")(exactPackage());
    assert.strictEqual(pickerCalls, 0);
  });

  test("safe-version URL construction failure is a warning", async () => {
    const registration = recorder();
    const warnings = [];
    let picker = 0;
    class RemediationHelper {
      async findSafeVersions() {
        return {
          success: true,
          complete: true,
          totalCount: 1,
          versions: [{
            namespace: "workspace-a",
            repository: "repo-a",
            slug_perm: "safe-package",
            name: "widget",
            version: "2.0.0",
            format: "npm",
            is_copyable: true,
            status_str: "Completed",
          }],
        };
      }
    }
    registerVulnerabilityCommands(vulnerabilityDeps(registration, {
      RemediationHelper,
      buildPackageUrl: () => null,
      vscode: {
        QuickPickItemKind: { Separator: 1 },
        window: {
          async showQuickPick(items) {
            picker += 1;
            return picker === 1
              ? items.find(item => item.package)
              : items.find(item => item.id === "open");
          },
          showWarningMessage: message => warnings.push(message),
          showErrorMessage() {},
        },
      },
    }));
    await registration.handlers.get("cloudsmith-vsc.findSafeVersion")(exactPackage());
    assert.deepStrictEqual(warnings, ["Could not open this package in Cloudsmith."]);
  });
});

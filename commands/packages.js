// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { registerCommands } = require("./registrar");
const {
  adaptInstallSelection,
  adaptPackageSelection,
  buildInstallCommand,
  buildPresetQuery,
  createFilterPresets,
  firstCollectionFailureMessage,
  isQuarantinedPackage,
  pickInstallCommandVariant,
  pickRecentPackage,
  commentCommandNote,
} = require("./support");

function registerPackageCommands(deps) {
  const {
    registerCommand,
    vscode,
    context,
    packageAdapters,
    packageDomain,
    recentPackages,
    cloudsmithProvider,
    searchProvider,
    dependencyHealthProvider,
    inspectOutputChannel,
    CloudsmithAPI,
    apiEndpoint,
    PaginatedFetch,
    packageCollectionIdentity,
    SearchQueryBuilder,
    LicenseClassifier,
    InstallCommandBuilder,
    buildPackageUrl,
    buildPackageGroupUrl,
    filterState,
  } = deps;
  const filterPresets = createFilterPresets(LicenseClassifier);
  const recentSupport = { recentPackages, packageAdapters, vscode };

  async function selectedPackage(item, options = {}) {
    const pkg = item
      ? adaptPackageSelection(packageAdapters, item)
      : await pickRecentPackage(recentSupport, options);
    if (!pkg && !item) return null;
    try {
      return packageDomain.assertExactPackage(pkg);
    } catch {
      vscode.window.showWarningMessage(options.invalidMessage || "Run this command from a package context menu.");
      return null;
    }
  }

  async function showInspectOutput(jsonContent) {
    const inspectOutput = await vscode.workspace
      .getConfiguration("cloudsmith-vsc")
      .get("inspectOutput");
    if (inspectOutput) {
      const document = await vscode.workspace.openTextDocument({
        language: "json",
        content: jsonContent,
      });
      await vscode.window.showTextDocument(document, { preview: true });
    } else {
      inspectOutputChannel.clear();
      inspectOutputChannel.show(true);
      inspectOutputChannel.append(jsonContent);
    }
  }

  async function copySelected(item) {
    let detail;
    try {
      detail = packageAdapters.fromPackageDetailNode(item);
    } catch {
      vscode.window.showWarningMessage("Run this command from a package context menu.");
      return;
    }
    await vscode.env.clipboard.writeText(String(detail.value));
    vscode.window.showInformationMessage("Value copied.");
  }

  async function inspectPackage(item) {
    const pkg = await selectedPackage(item);
    if (!pkg) return;
    recentPackages.add(pkg);
    let endpoint;
    try {
      endpoint = apiEndpoint([
        "packages",
        pkg.workspace,
        pkg.repository,
        pkg.packageIdentifier,
      ]);
    } catch {
      vscode.window.showErrorMessage("Could not inspect the package because its identifier was invalid.");
      return;
    }
    const result = await new CloudsmithAPI(context).get(endpoint, {
      responseType: "object",
      validate: value => Boolean(value) && typeof value === "object" && !Array.isArray(value),
      retry: "safe-read",
    });
    if (!result.ok) {
      vscode.window.showErrorMessage(deps.formatApiError(result.error));
      return;
    }
    await showInspectOutput(JSON.stringify(result.data, null, 2));
    vscode.window.showInformationMessage(
      `Inspecting package ${pkg.name} in repository ${pkg.repository}.`
    );
  }

  async function inspectPackageGroup(item) {
    let group;
    try {
      group = packageAdapters.fromPackageGroupNode(item);
    } catch {
      vscode.window.showWarningMessage("Run this command from a package context menu.");
      return;
    }
    const cloudsmithAPI = new CloudsmithAPI(context);
    let endpoint;
    let query;
    const expectedScope = {
      expectedWorkspace: group.workspace,
      expectedRepository: group.repository,
    };
    const adaptGroupPackage = record => packageAdapters.fromApiPackageRecord(
      record,
      expectedScope
    );
    const canonicalGroupIdentity = (record) => {
      try {
        return packageCollectionIdentity(adaptGroupPackage(record));
      } catch {
        return null;
      }
    };
    try {
      const queryBuilder = new SearchQueryBuilder().name(group.name);
      if (group.format) queryBuilder.format(group.format);
      query = queryBuilder.build();
      endpoint = apiEndpoint(
        ["packages", group.workspace, group.repository],
        { query: { sort: "-version" } }
      );
    } catch {
      vscode.window.showErrorMessage(
        "Could not inspect the package group because its identity was invalid."
      );
      return;
    }
    const result = await new PaginatedFetch(cloudsmithAPI).fetchCollection(endpoint, {
      pageSize: 100,
      maxPages: 20,
      maxRequests: 20,
      maxItems: 2000,
      query,
      descriptor: `inspect-package-group:${group.workspace}:${group.repository}:${group.name}:${group.format || "all-formats"}`,
      canonicalIdentity: canonicalGroupIdentity,
      validate: value => Array.isArray(value) && value.every(record => {
        try {
          const pkg = adaptGroupPackage(record);
          return pkg.workspace === group.workspace
            && pkg.repository === group.repository
            && pkg.name === group.name
            && (!group.format || pkg.format === group.format);
        } catch {
          return false;
        }
      }),
      retry: "safe-read",
    });
    if (!result.complete && result.items.length === 0) {
      vscode.window.showErrorMessage(
        firstCollectionFailureMessage(result, deps.formatApiError)
          || "Could not inspect the package group completely."
      );
      return;
    }
    await showInspectOutput(JSON.stringify({
      items: result.items,
      complete: result.complete,
      loadedCount: result.items.length,
      totalCount: result.pagination?.countAuthoritative ? result.pagination.count : null,
      termination: result.termination,
      failureCount: result.failureCount,
    }, null, 2));
    if (result.complete) {
      vscode.window.showInformationMessage(`Inspecting package group ${group.name}.`);
    } else {
      vscode.window.showWarningMessage(
        `Inspecting an incomplete package-group result (${result.items.length} packages loaded).`
      );
    }
  }

  async function openPackage(item) {
    const pkg = await selectedPackage(item);
    if (!pkg) return;
    recentPackages.add(pkg);
    const url = buildPackageUrl(
      pkg.workspace,
      pkg.repository,
      pkg.format,
      pkg.name,
      pkg.version,
      pkg.packageIdentifier
    );
    if (!url) {
      vscode.window.showWarningMessage("Run this command from a package context menu.");
      return;
    }
    await vscode.env.openExternal(vscode.Uri.parse(url));
  }

  async function openPackageGroup(item) {
    let group;
    try {
      group = packageAdapters.fromPackageGroupNode(item);
    } catch {
      vscode.window.showWarningMessage("Run this command from a package context menu.");
      return;
    }
    const url = buildPackageGroupUrl(group.workspace, group.repository, group.name);
    if (!url) {
      vscode.window.showWarningMessage("Please use this command from the package context menu.");
      return;
    }
    await vscode.env.openExternal(vscode.Uri.parse(url));
  }

  async function loadMoreRepositoryPackages(item) {
    if (item && typeof item.loadMorePackages === "function") {
      await item.loadMorePackages();
    }
  }

  async function filterPackages(item) {
    let repository;
    try {
      repository = packageAdapters.fromRepositoryNode(item);
    } catch {
      vscode.window.showWarningMessage("No repository selected.");
      return;
    }
    const selected = await vscode.window.showQuickPick(
      filterPresets.map(preset => ({ label: preset.label, preset })),
      { placeHolder: `Filter packages in ${repository.name}` }
    );
    if (!selected) return;
    let query;
    if (selected.preset.applyBuilder === null) {
      query = await vscode.window.showInputBox({
        placeHolder: "Enter filter query",
        prompt: `Filter packages in ${repository.name}`,
      });
      if (!query) return;
      query = buildPresetQuery(SearchQueryBuilder, selected.preset, query);
    } else {
      query = buildPresetQuery(SearchQueryBuilder, selected.preset);
    }
    const filterKey = `${repository.workspace}/${repository.repository}`;
    const filterLabel = selected.preset.applyBuilder === null
      ? "Custom query"
      : selected.preset.label;
    if (query) {
      filterState.activeFilters.set(filterKey, { query, label: filterLabel });
    } else {
      filterState.activeFilters.delete(filterKey);
    }
    cloudsmithProvider.refresh();
  }

  async function clearFilter(item) {
    let repository;
    try {
      repository = packageAdapters.fromRepositoryNode(item);
    } catch {
      return;
    }
    filterState.activeFilters.delete(`${repository.workspace}/${repository.repository}`);
    cloudsmithProvider.refresh();
  }

  async function installCommand(item, showDocument) {
    let selection = item;
    if (!selection) selection = await pickRecentPackage(recentSupport);
    if (!selection) return;
    let installSelection;
    try {
      installSelection = adaptInstallSelection(
        packageAdapters,
        packageDomain,
        selection
      );
    } catch {
      vscode.window.showWarningMessage(
        "Could not determine package details for install command."
      );
      return;
    }
    const pkg = installSelection.package;
    if (isQuarantinedPackage(pkg)) {
      vscode.window.showWarningMessage("Install commands are not available for quarantined packages.");
      return;
    }
    if (installSelection.exactPackage) recentPackages.add(installSelection.exactPackage);
    const result = buildInstallCommand(deps, pkg);
    if (!result) return;
    if (showDocument) {
      let content = result.command;
      if (result.alternatives && result.alternatives.length > 0) {
        for (const alternative of result.alternatives) {
          content += `\n\n# Alternative: ${alternative.label}\n${alternative.command}`;
        }
      }
      if (result.note) content += `\n\n# Note\n${commentCommandNote(result.note)}`;
      const document = await vscode.workspace.openTextDocument({
        language: pkg.format === "maven" ? "xml" : "shellscript",
        content,
      });
      await vscode.window.showTextDocument(document, { preview: true });
      return;
    }
    const chosenCommand = await pickInstallCommandVariant(deps, result);
    if (!chosenCommand) return;
    await vscode.env.clipboard.writeText(
      InstallCommandBuilder.toClipboardCommand(chosenCommand)
    );
    const message = result.note
      ? `Install command copied for ${pkg.name}. Note: ${result.note}`
      : `Install command copied for ${pkg.name}.`;
    vscode.window.showInformationMessage(message);
  }

  async function openLicenseUrl(item) {
    const licenseInfo = item && item.licenseInfo
      ? item.licenseInfo
      : LicenseClassifier.inspect(item);
    const licenseUrl = licenseInfo
      ? (licenseInfo.licenseUrl || (item && item.licenseUrl) || null)
      : null;
    if (
      !item
      || typeof licenseUrl !== "string"
      || licenseUrl.length === 0
      || licenseUrl.length > 2048
      || /[\u0000-\u001f\u007f]/.test(licenseUrl)
    ) {
      vscode.window.showWarningMessage("No license URL available.");
      return;
    }
    let parsedUrl;
    try {
      parsedUrl = new URL(licenseUrl);
    } catch {
      vscode.window.showWarningMessage("Invalid license URL.");
      return;
    }
    if (
      (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:")
      || parsedUrl.username
      || parsedUrl.password
    ) {
      vscode.window.showWarningMessage("Could not open the license URL. Unsupported protocol.");
      return;
    }
    await vscode.env.openExternal(vscode.Uri.parse(parsedUrl.toString()));
  }

  async function copyEntitlementToken(item) {
    if (!item || !item.token) {
      vscode.window.showWarningMessage("No token available to copy.");
      return;
    }
    const choice = await vscode.window.showWarningMessage(
      "Copy the entitlement token to the clipboard? Entitlement tokens are sensitive.",
      "Copy",
      "Cancel"
    );
    if (choice !== "Copy") return;
    await vscode.env.clipboard.writeText(item.token);
    vscode.window.showInformationMessage(`Entitlement token "${item.tokenName}" copied.`);
  }

  return registerCommands(registerCommand, [
    ["cloudsmith-vsc.refreshView", () => {
      cloudsmithProvider.refresh();
      searchProvider.refresh();
      dependencyHealthProvider.refresh();
    }],
    ["cloudsmith-vsc.copySelected", copySelected],
    ["cloudsmith-vsc.inspectPackage", inspectPackage],
    ["cloudsmith-vsc.inspectPackageGroup", inspectPackageGroup],
    ["cloudsmith-vsc.openPackage", openPackage],
    ["cloudsmith-vsc.openPackageGroup", openPackageGroup],
    ["cloudsmith-vsc.loadMoreRepositoryPackages", loadMoreRepositoryPackages],
    ["cloudsmith-vsc.filterPackages", filterPackages],
    ["cloudsmith-vsc.clearFilter", clearFilter],
    ["cloudsmith-vsc.changeFilter", filterPackages],
    ["cloudsmith-vsc.copyInstallCommand", item => installCommand(item, false)],
    ["cloudsmith-vsc.showInstallCommand", item => installCommand(item, true)],
    ["cloudsmith-vsc.openLicenseUrl", openLicenseUrl],
    ["cloudsmith-vsc.copyEntitlementToken", copyEntitlementToken],
  ], deps);
}

module.exports = { registerPackageCommands };

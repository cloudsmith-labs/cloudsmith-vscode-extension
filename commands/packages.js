// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { registerCommands } = require("./registrar");
const {
  adaptPackageSelection,
  buildInstallCommand,
  buildPresetQuery,
  captureCommandAccount,
  createFilterPresets,
  firstCollectionFailureMessage,
  installGuidanceCopiedMessage,
  isInstallablePackage,
  pickInstallCommandVariant,
  pickRecentPackage,
  renderInstallCommandGuidance,
  isCommandAccountCurrent,
  showAccountInputBox,
  showAccountQuickPick,
} = require("./support");

const MAX_FILTER_INPUT_LENGTH = 2048;
const QUERY_CONTROL_OR_BIDI_PATTERN = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/;
const TRUSTED_LICENSE_HOSTS = new Set(["spdx.org", "www.spdx.org"]);
const VERSIONLESS_URL_PLACEHOLDER = "cloudsmith-vsc-versionless-package";

function filterInputValidationMessage(value) {
  if (typeof value !== "string") return "Enter a filter query.";
  if (QUERY_CONTROL_OR_BIDI_PATTERN.test(value)) {
    return "Filter queries cannot contain control characters.";
  }
  if (value.length > MAX_FILTER_INPUT_LENGTH) {
    return `Enter a query with ${MAX_FILTER_INPUT_LENGTH} characters or fewer.`;
  }
  if (value.trim().length === 0) return "Enter a filter query.";
  return null;
}

function validFilterInput(value) {
  return filterInputValidationMessage(value) === null;
}

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
    buildPackageUrl,
    buildPackageGroupUrl,
    filterState,
    serializePackageCollectionInspection,
    serializePackageInspection,
    openExternalWithFeedback,
  } = deps;
  const filterPresets = createFilterPresets(LicenseClassifier);
  const recentSupport = { ...deps, recentPackages, packageAdapters, vscode };

  function ownsSelection(kind, item) {
    let validator = null;
    if (kind === "isCurrentSelection") validator = deps.isCurrentSelection;
    if (kind === "isCurrentPackageSelection") validator = deps.isCurrentPackageSelection;
    if (kind === "isCurrentPackageGroupSelection") validator = deps.isCurrentPackageGroupSelection;
    if (kind === "isCurrentRepositorySelection") validator = deps.isCurrentRepositorySelection;
    if (kind === "isCurrentEntitlementSelection") validator = deps.isCurrentEntitlementSelection;
    return typeof validator === "function" && validator(item) === true;
  }

  function currentSelection(accountScope, kind, item) {
    return isCommandAccountCurrent(accountScope) && ownsSelection(kind, item);
  }

  async function selectedPackage(item, accountScope, options = {}) {
    let pkg;
    let selection = item;
    if (item) {
      try {
        pkg = adaptPackageSelection(packageAdapters, item);
      } catch {
        vscode.window.showWarningMessage(options.invalidMessage || "Could not determine package details.");
        return null;
      }
      if (!ownsSelection("isCurrentPackageSelection", item)) return null;
    } else {
      selection = await pickRecentPackage(recentSupport, {
        ...options,
        accountScope,
        predicate: typeof options.predicate === "function"
          ? (candidate) => {
            try {
              return options.predicate(packageDomain.assertExactPackage(candidate));
            } catch {
              return false;
            }
          }
          : undefined,
        currentSelection: selection => ownsSelection("isCurrentPackageSelection", selection),
      });
      pkg = selection;
    }
    if (!pkg && !item) return null;
    if (!isCommandAccountCurrent(accountScope)) return null;
    try {
      const exactPackage = packageDomain.assertExactPackage(pkg);
      if (typeof options.predicate === "function" && !options.predicate(exactPackage)) {
        vscode.window.showWarningMessage(
          options.invalidStateMessage || "This package is not available for this command."
        );
        return null;
      }
      const isCurrent = () => currentSelection(
        accountScope,
        "isCurrentPackageSelection",
        selection
      );
      if (!isCurrent()) return null;
      return Object.freeze({ package: exactPackage, isCurrent });
    } catch {
      vscode.window.showWarningMessage(options.invalidMessage || "Could not determine package details.");
      return null;
    }
  }

  async function showInspectOutput(jsonContent, isCurrent, errorMessage) {
    try {
      const inspectOutput = vscode.workspace
        .getConfiguration("cloudsmith-vsc")
        .get("inspectOutput");
      if (!isCurrent()) return false;
      if (inspectOutput) {
        if (!isCurrent()) return false;
        const document = await vscode.workspace.openTextDocument({
          language: "json",
          content: jsonContent,
        });
        if (!isCurrent()) return false;
        await vscode.window.showTextDocument(document, { preview: true });
      } else {
        if (!isCurrent()) return false;
        inspectOutputChannel.clear();
        if (!isCurrent()) return false;
        inspectOutputChannel.show(true);
        if (!isCurrent()) return false;
        inspectOutputChannel.append(jsonContent);
      }
      return isCurrent();
    } catch {
      if (!isCurrent()) return false;
      try {
        await vscode.window.showErrorMessage(errorMessage);
      } catch {
        // Notification failures must not escape the command boundary.
      }
      return false;
    }
  }

  async function copySelected(item) {
    const accountScope = captureCommandAccount(deps.workspaceAccess);
    if (!accountScope || !ownsSelection("isCurrentSelection", item)) return;
    const isCurrent = () => currentSelection(accountScope, "isCurrentSelection", item);
    let detail;
    try {
      detail = packageAdapters.fromPackageDetailNode(item);
    } catch {
      vscode.window.showWarningMessage("No package detail selected.");
      return;
    }
    if (!isCurrent()) return;
    await vscode.env.clipboard.writeText(String(detail.value));
    if (!isCurrent()) return;
    vscode.window.showInformationMessage("Value copied.");
  }

  async function inspectPackage(item) {
    const accountScope = captureCommandAccount(deps.workspaceAccess);
    if (!accountScope) return;
    const selected = await selectedPackage(item, accountScope);
    if (!selected) return;
    const { package: pkg, isCurrent } = selected;
    if (!isCurrent()) return;
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
    if (!isCurrent()) return;
    const result = await new CloudsmithAPI(context).get(endpoint, {
      responseType: "object",
      validate: value => Boolean(value) && typeof value === "object" && !Array.isArray(value),
      retry: "safe-read",
    });
    if (!isCurrent()) return;
    if (!result.ok) {
      vscode.window.showErrorMessage(
        `Could not inspect package. ${deps.formatApiError(result.error)}`
      );
      return;
    }
    let jsonContent;
    try {
      const inspectedPackage = packageAdapters.fromApiPackageRecord(result.data, {
        expectedWorkspace: pkg.workspace,
        expectedRepository: pkg.repository,
      });
      if (
        inspectedPackage.packageIdentifier !== pkg.packageIdentifier
        || inspectedPackage.name !== pkg.name
        || inspectedPackage.version !== pkg.version
        || inspectedPackage.format !== pkg.format
      ) {
        throw new TypeError("The inspection response did not match the selected package.");
      }
      jsonContent = serializePackageInspection(inspectedPackage);
    } catch {
      vscode.window.showErrorMessage("Could not safely inspect the package response.");
      return;
    }
    const outputShown = await showInspectOutput(
      jsonContent,
      isCurrent,
      "Could not inspect package. The inspection output could not be opened."
    );
    if (!outputShown || !isCurrent()) return;
    recentPackages.add(pkg);
  }

  async function inspectPackageGroup(item) {
    const accountScope = captureCommandAccount(deps.workspaceAccess);
    if (!accountScope || !ownsSelection("isCurrentPackageGroupSelection", item)) return;
    let group;
    try {
      group = packageAdapters.fromPackageGroupNode(item);
    } catch {
      vscode.window.showWarningMessage("No package group selected.");
      return;
    }
    const isCurrent = () => currentSelection(
      accountScope,
      "isCurrentPackageGroupSelection",
      item
    );
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
    if (!isCurrent()) return;
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
    if (!isCurrent()) return;
    if (!result.complete && result.items.length === 0) {
      const detail = firstCollectionFailureMessage(result, deps.formatApiError)
        || "The package group could not be loaded completely.";
      vscode.window.showErrorMessage(
        `Could not inspect package group. ${String(detail).trim()}`
      );
      return;
    }
    let jsonContent;
    try {
      jsonContent = serializePackageCollectionInspection(
        result.items.map(adaptGroupPackage),
        {
          complete: result.complete,
          totalCount: result.pagination?.countAuthoritative ? result.pagination.count : null,
          termination: result.termination,
          failureCount: result.failureCount,
        }
      );
    } catch {
      vscode.window.showErrorMessage("Could not safely inspect the package-group response.");
      return;
    }
    const outputShown = await showInspectOutput(
      jsonContent,
      isCurrent,
      "Could not inspect package group. The inspection output could not be opened."
    );
    if (!outputShown || !isCurrent()) return;
    if (!result.complete) {
      vscode.window.showWarningMessage(
        `Package-group results are incomplete (${result.items.length} packages loaded).`
      );
    }
  }

  async function openPackage(item) {
    const accountScope = captureCommandAccount(deps.workspaceAccess);
    if (!accountScope) return;
    const selected = await selectedPackage(item, accountScope);
    if (!selected) return;
    const { package: pkg, isCurrent } = selected;
    if (!isCurrent()) return;
    const url = buildPackageNavigationUrl(buildPackageUrl, pkg);
    if (!url) {
      vscode.window.showWarningMessage("Could not open this package in Cloudsmith.");
      return;
    }
    if (!isCurrent()) return;
    const opened = await openExternalWithFeedback({
      target: vscode.Uri.parse(url),
      openExternal: target => vscode.env.openExternal(target),
      showWarningMessage: message => vscode.window.showWarningMessage(message),
      failureMessage: "Could not open this package in Cloudsmith.",
      isCurrent,
    });
    if (!opened || !isCurrent()) return;
    recentPackages.add(pkg);
  }

  async function openPackageGroup(item) {
    const accountScope = captureCommandAccount(deps.workspaceAccess);
    if (!accountScope || !ownsSelection("isCurrentPackageGroupSelection", item)) return;
    let group;
    try {
      group = packageAdapters.fromPackageGroupNode(item);
    } catch {
      vscode.window.showWarningMessage("No package group selected.");
      return;
    }
    const isCurrent = () => currentSelection(
      accountScope,
      "isCurrentPackageGroupSelection",
      item
    );
    const url = buildPackageGroupUrl(group.workspace, group.repository, group.name);
    if (!url) {
      vscode.window.showWarningMessage("Could not open this package group in Cloudsmith.");
      return;
    }
    if (!isCurrent()) return;
    await openExternalWithFeedback({
      target: vscode.Uri.parse(url),
      openExternal: target => vscode.env.openExternal(target),
      showWarningMessage: message => vscode.window.showWarningMessage(message),
      failureMessage: "Could not open this package group in Cloudsmith.",
      isCurrent,
    });
  }

  async function loadMoreRepositoryPackages(item) {
    const accountScope = captureCommandAccount(deps.workspaceAccess);
    if (
      !accountScope
      || !item
      || typeof item.loadMorePackages !== "function"
      || !ownsSelection("isCurrentRepositorySelection", item)
    ) return;
    if (!currentSelection(accountScope, "isCurrentRepositorySelection", item)) return;
    await item.loadMorePackages();
  }

  async function filterPackages(item) {
    const accountScope = captureCommandAccount(deps.workspaceAccess);
    if (!accountScope || !ownsSelection("isCurrentRepositorySelection", item)) return;
    let repository;
    try {
      repository = packageAdapters.fromRepositoryNode(item);
    } catch {
      vscode.window.showWarningMessage("No repository selected.");
      return;
    }
    const isCurrent = () => currentSelection(
      accountScope,
      "isCurrentRepositorySelection",
      item
    );
    const selected = await showAccountQuickPick(
      deps,
      accountScope,
      filterPresets.map(preset => ({ label: preset.label, preset })),
      { placeHolder: `Filter packages in ${repository.name}` }
    );
    if (!selected || !isCurrent()) return;
    let query;
    if (selected.preset.applyBuilder === null) {
      query = await showAccountInputBox(deps, accountScope, {
        placeHolder: "Enter filter query",
        prompt: `Filter packages in ${repository.name}`,
        validateInput: filterInputValidationMessage,
      });
      if (!validFilterInput(query) || !isCurrent()) return;
      query = buildPresetQuery(SearchQueryBuilder, selected.preset, query);
    } else {
      query = buildPresetQuery(SearchQueryBuilder, selected.preset);
    }
    const filterKey = `${repository.workspace}/${repository.repository}`;
    const filterLabel = selected.preset.applyBuilder === null
      ? "Custom query"
      : selected.preset.label;
    if (!isCurrent()) return;
    if (query) {
      filterState.activeFilters.set(filterKey, { query, label: filterLabel });
    } else {
      filterState.activeFilters.delete(filterKey);
    }
    if (!isCurrent()) return;
    cloudsmithProvider.refresh();
  }

  async function clearFilter(item) {
    const accountScope = captureCommandAccount(deps.workspaceAccess);
    if (!accountScope) return;
    let repository;
    try {
      repository = packageAdapters.fromRepositoryNode(item);
    } catch {
      return;
    }
    if (!ownsSelection("isCurrentRepositorySelection", item)) return;
    const isCurrent = () => currentSelection(
      accountScope,
      "isCurrentRepositorySelection",
      item
    );
    if (!isCurrent()) return;
    filterState.activeFilters.delete(`${repository.workspace}/${repository.repository}`);
    if (!isCurrent()) return;
    cloudsmithProvider.refresh();
  }

  async function installCommand(item, showDocument) {
    const accountScope = captureCommandAccount(deps.workspaceAccess);
    if (!accountScope) return;
    const selected = await selectedPackage(item, accountScope, {
      predicate: pkg => isInstallablePackage(pkg, deps),
      invalidMessage: "Could not determine package details for install command.",
      invalidStateMessage: "Install guidance is not available for this package.",
      emptyMessage: "No recent installable packages. Open or search for a package, then try again.",
    });
    if (!selected) return;
    const { package: pkg, isCurrent } = selected;
    if (!isCurrent()) return;
    const result = buildInstallCommand(deps, pkg);
    if (!result) return;
    const chosenCommand = await pickInstallCommandVariant(deps, result, { accountScope });
    if (!chosenCommand || !isCurrent()) return;
    const content = renderInstallCommandGuidance(deps, result, chosenCommand);
    if (showDocument) {
      const document = await vscode.workspace.openTextDocument({
        language: result.language || "shellscript",
        content,
      });
      if (!isCurrent()) return;
      await vscode.window.showTextDocument(document, { preview: true });
      if (!isCurrent()) return;
      recentPackages.add(pkg);
      return;
    }
    await vscode.env.clipboard.writeText(content);
    if (!isCurrent()) return;
    vscode.window.showInformationMessage(installGuidanceCopiedMessage(result));
    if (!isCurrent()) return;
    recentPackages.add(pkg);
  }

  async function openLicenseUrl(item) {
    const accountScope = captureCommandAccount(deps.workspaceAccess);
    if (!accountScope || !ownsSelection("isCurrentSelection", item)) return;
    const isCurrent = () => currentSelection(accountScope, "isCurrentSelection", item);
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
      parsedUrl.protocol !== "https:"
      || parsedUrl.username
      || parsedUrl.password
    ) {
      vscode.window.showWarningMessage("Could not open the license URL. Only HTTPS links are supported.");
      return;
    }
    if (!isCurrent()) return;
    const trustedHost = TRUSTED_LICENSE_HOSTS.has(parsedUrl.hostname.toLowerCase())
      && (parsedUrl.port === "" || parsedUrl.port === "443");
    if (!trustedHost) {
      const choice = await vscode.window.showWarningMessage(
        `Open a license page on ${parsedUrl.hostname}? Continue only if you trust this site.`,
        { modal: true },
        "Open"
      );
      if (choice !== "Open" || !isCurrent()) return;
    }
    await openExternalWithFeedback({
      target: vscode.Uri.parse(parsedUrl.toString()),
      openExternal: target => vscode.env.openExternal(target),
      showWarningMessage: message => vscode.window.showWarningMessage(message),
      failureMessage: "Could not open the license URL.",
      isCurrent,
    });
  }

  async function copyEntitlementToken(item) {
    const accountScope = captureCommandAccount(deps.workspaceAccess);
    if (
      !accountScope
      || !ownsSelection("isCurrentEntitlementSelection", item)
    ) return;
    const isCurrent = () => currentSelection(
      accountScope,
      "isCurrentEntitlementSelection",
      item
    );
    if (!item || !item.token) {
      vscode.window.showWarningMessage("No token available to copy.");
      return;
    }
    if (!isCurrent()) return;
    const choice = await vscode.window.showWarningMessage(
      "Copy the entitlement token to the clipboard? Entitlement tokens are sensitive.",
      { modal: true },
      "Copy"
    );
    if (choice !== "Copy" || !isCurrent()) return;
    await vscode.env.clipboard.writeText(item.token);
    if (!isCurrent()) return;
    vscode.window.showInformationMessage("Entitlement token copied.");
  }

  return registerCommands(registerCommand, [
    ["cloudsmith-vsc.refreshView", () => {
      if (!captureCommandAccount(deps.workspaceAccess)) return;
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

function buildPackageNavigationUrl(buildPackageUrl, pkg) {
  const versionless = pkg.version === ""
    && ["generic", "raw"].includes(String(pkg.format || "").trim().toLowerCase());
  const url = buildPackageUrl(
    pkg.workspace,
    pkg.repository,
    pkg.format,
    pkg.name,
    versionless ? VERSIONLESS_URL_PLACEHOLDER : pkg.version,
    pkg.packageIdentifier
  );
  if (!versionless || !url) return url;
  const encodedIdentifier = encodeURIComponent(pkg.packageIdentifier);
  const suffix = `/${VERSIONLESS_URL_PLACEHOLDER}/${encodedIdentifier}`;
  if (!url.endsWith(suffix)) return null;
  return `${url.slice(0, -suffix.length)}//${encodedIdentifier}`;
}

module.exports = { registerPackageCommands };

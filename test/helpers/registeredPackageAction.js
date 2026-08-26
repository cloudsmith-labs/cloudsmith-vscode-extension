// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const vscode = require("vscode");
const { registerPackageCommands } = require("../../commands/packages");
const packageAdapters = require("../../domain/packageAdapters");
const packageDomain = require("../../domain/package");
const { createSelectionOwnership } = require("../../extension");
const { captureAccount, isAccountCurrent } = require("../../util/accountOperation");
const { openExternalWithFeedback } = require("../../util/externalNavigation");

let commandGeneration = 0;

function noTreeOwner() {
  return {
    ownsDependencySelection() { return false; },
    ownsEntitlementSelection() { return false; },
    ownsPackageSelection() { return false; },
    ownsRepositoryContextSelection() { return false; },
    ownsSelection() { return false; },
    ownsWorkspaceSelection() { return false; },
    refresh() {},
  };
}

function registerOwnedOpenPackageCommand(options) {
  const {
    connectionManager,
    opened,
    targetUrl,
    cloudsmithProvider = noTreeOwner(),
    dependencyHealthProvider = noTreeOwner(),
    searchProvider = noTreeOwner(),
  } = options;
  const commandIds = new Map();
  const prefix = `cloudsmith-vsc.test.package-action-${++commandGeneration}`;
  const recentPackageStore = {
    add() {},
    getAll() { return []; },
  };
  const registrations = registerPackageCommands({
    registerCommand(id, handler) {
      const testId = `${prefix}.${id}`;
      commandIds.set(id, testId);
      return vscode.commands.registerCommand(testId, handler);
    },
    vscode: {
      Uri: vscode.Uri,
      env: {
        clipboard: { async writeText() {} },
        async openExternal(uri) { opened.push(uri.toString()); return true; },
      },
      workspace: { getConfiguration: () => ({ get: () => false }) },
      window: {
        showErrorMessage() {},
        showInformationMessage() {},
        showWarningMessage() {},
      },
    },
    context: {},
    workspaceAccess: {
      connectionManager,
      captureAccount,
      isAccountCurrent,
    },
    packageAdapters,
    packageDomain,
    recentPackages: recentPackageStore,
    cloudsmithProvider,
    searchProvider,
    dependencyHealthProvider,
    inspectOutputChannel: { append() {}, clear() {}, show() {} },
    CloudsmithAPI: class {},
    apiEndpoint: () => "unused",
    PaginatedFetch: class {},
    packageCollectionIdentity: () => "unused",
    SearchQueryBuilder: class {},
    LicenseClassifier: { buildRestrictiveQuery: () => "license:restrictive" },
    InstallCommandBuilder: class {},
    InstallCommandValidationError: class extends Error {},
    buildPackageUrl: () => targetUrl,
    buildPackageGroupUrl: () => "https://cloudsmith.example/package-group",
    filterState: { activeFilters: new Map() },
    serializePackageCollectionInspection: () => "[]",
    serializePackageInspection: () => "{}",
    formatApiError: () => "unavailable",
    openExternalWithFeedback,
    ...createSelectionOwnership({
      cloudsmithProvider,
      dependencyHealthProvider,
      recentPackages: recentPackageStore,
      searchProvider,
    }),
  });
  return {
    id: commandIds.get("cloudsmith-vsc.openPackage"),
    dispose() { registrations.dispose(); },
  };
}

module.exports = { registerOwnedOpenPackageCommand };

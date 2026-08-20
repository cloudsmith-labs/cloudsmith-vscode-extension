// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const manifest = require("../package.json");
const architecture = require("../scripts/architecture/architecture.json");

// This hard-coded inventory independently reviews both customer contributions and
// architecture metadata so a classification change cannot preserve a false green.
const COMMANDS = Object.freeze([
  ["cloudsmith-vsc.openSettings", "Open Cloudsmith settings", "global", true, null],
  ["cloudsmith-vsc.configureCredentials", "Set up Cloudsmith authentication", "global", true, "!cloudsmith.connected && cloudsmith.connectionSetupAvailable"],
  ["cloudsmith-vsc.connectCloudsmith", "Connect to Cloudsmith", "global", true, "!cloudsmith.connected && cloudsmith.connectionSetupAvailable && cloudsmith.credentialsPresent"],
  ["cloudsmith-vsc.clearCredentials", "Clear stored credentials", "global", true, "cloudsmith.credentialsPresent"],
  ["cloudsmith-vsc.copySelected", "Copy value", "context-only", false, "cloudsmith.connected"],
  ["cloudsmith-vsc.inspectPackage", "Inspect package", "recoverable", true, "cloudsmith.connected"],
  ["cloudsmith-vsc.inspectPackageGroup", "Inspect package group", "context-only", false, "cloudsmith.connected"],
  ["cloudsmith-vsc.openPackage", "View package in Cloudsmith", "recoverable", true, "cloudsmith.connected"],
  ["cloudsmith-vsc.openPackageGroup", "View package group in Cloudsmith", "context-only", false, "cloudsmith.connected"],
  ["cloudsmith-vsc.refreshView", "Refresh", "global", true, "cloudsmith.connected"],
  ["cloudsmith-vscode-extension.cloudsmithDocs", "View Cloudsmith documentation", "global", true, null],
  ["cloudsmith-vsc.searchPackages", "Search packages", "global", true, "cloudsmith.connected"],
  ["cloudsmith-vsc.clearSearch", "Clear search results", "global", true, "cloudsmith.connected && cloudsmith.searchActive"],
  ["cloudsmith-vsc.searchNextPage", "Load more results", "global", true, "cloudsmith.connected && cloudsmith.searchCanLoadMore"],
  ["cloudsmith-vsc.loadMoreRepositoryPackages", "Load more repository packages", "context-only", false, "cloudsmith.connected"],
  ["cloudsmith-vsc.searchInWorkspace", "Search packages in this workspace", "context-only", false, "cloudsmith.connected"],
  ["cloudsmith-vsc.guidedSearch", "Advanced search", "global", true, "cloudsmith.connected"],
  ["cloudsmith-vsc.filterPackages", "Filter packages in this repository", "context-only", false, "cloudsmith.connected"],
  ["cloudsmith-vsc.clearFilter", "Clear package filter", "context-only", false, "cloudsmith.connected"],
  ["cloudsmith-vsc.changeFilter", "Change package filter", "context-only", false, "cloudsmith.connected"],
  ["cloudsmith-vsc.findSafeVersion", "Find safe version", "recoverable", true, "cloudsmith.connected"],
  ["cloudsmith-vsc.openCVE", "Open CVE in browser", "context-only", false, "cloudsmith.connected"],
  ["cloudsmith-vsc.showVulnerabilities", "Show vulnerabilities", "recoverable", true, "cloudsmith.connected"],
  ["cloudsmith-vsc.showDepVulnerabilities", "Show vulnerabilities", "context-only", false, "cloudsmith.connected && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning"],
  ["cloudsmith-vsc.findDepSafeVersion", "Find safe version", "context-only", false, "cloudsmith.connected && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning"],
  ["cloudsmith-vsc.filterVulnerabilities", "Filter vulnerabilities", "context-only", false, "cloudsmith.connected"],
  ["cloudsmith-vsc.explainQuarantine", "Explain quarantine", "recoverable", true, "cloudsmith.connected"],
  ["cloudsmith-vsc.scanDependencies", "Scan dependencies", "global", true, "cloudsmith.connected && !cloudsmith.depOperationRunning"],
  ["cloudsmith-vsc.changeDependencyScanScope", "Change dependency scan scope", "global", true, "cloudsmith.connected && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning"],
  ["cloudsmith-vsc.pullDependencies", "Pull dependencies", "global", true, "cloudsmith.connected && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning"],
  ["cloudsmith-vsc.pullSingleDependency", "Pull dependency", "context-only", false, "cloudsmith.connected && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning"],
  ["cloudsmith-vsc.cycleDepView", "Cycle dependency view", "global", true, "cloudsmith.connected && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning"],
  ["cloudsmith-vsc.depViewDirect", "Show direct dependencies", "global", true, "cloudsmith.connected && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning"],
  ["cloudsmith-vsc.depViewFlat", "Show all dependencies (flat)", "global", true, "cloudsmith.connected && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning"],
  ["cloudsmith-vsc.depViewTree", "Show dependency tree", "global", true, "cloudsmith.connected && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning"],
  ["cloudsmith-vsc.depFilterVulnerable", "Show only vulnerable", "global", true, "cloudsmith.connected && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning"],
  ["cloudsmith-vsc.depFilterUncovered", "Show only not in Cloudsmith", "global", true, "cloudsmith.connected && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning"],
  ["cloudsmith-vsc.depFilterRestrictiveLicense", "Show only restrictive licenses", "global", true, "cloudsmith.connected && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning"],
  ["cloudsmith-vsc.depFilterPolicyViolation", "Show only policy violations", "global", true, "cloudsmith.connected && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning"],
  ["cloudsmith-vsc.depFilterClear", "Clear dependency filters", "global", true, "cloudsmith.connected && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning"],
  ["cloudsmith-vsc.depSortFilter", "Sort & filter dependencies", "global", true, "cloudsmith.connected && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning"],
  ["cloudsmith-vsc.viewComplianceReport", "View compliance report", "global", true, "cloudsmith.connected && cloudsmith.depReportAvailable"],
  ["cloudsmith-vsc.copyInstallCommand", "Copy install command", "recoverable", true, "cloudsmith.connected"],
  ["cloudsmith-vsc.showInstallCommand", "Show install command", "recoverable", true, "cloudsmith.connected"],
  ["cloudsmith-vsc.searchByLicense", "Search packages by license", "global", true, "cloudsmith.connected"],
  ["cloudsmith-vsc.openLicenseUrl", "View license", "context-only", false, "cloudsmith.connected"],
  ["cloudsmith-vsc.ssoLogin", "Sign in with SSO (Experimental)", "global", true, "!cloudsmith.connected && cloudsmith.connectionSetupAvailable"],
  ["cloudsmith-vsc.importCLICredentials", "Import API key from Cloudsmith CLI", "global", true, "!cloudsmith.connected && cloudsmith.connectionSetupAvailable"],
  ["cloudsmith-vsc.setDefaultWorkspace", "Set default workspace", "global", true, "cloudsmith.connected"],
  ["cloudsmith-vsc.previewUpstreamResolution", "Preview upstream resolution", "global", true, "cloudsmith.connected"],
  ["cloudsmith-vsc.inspectUpstreams", "View upstreams", "recoverable", true, "cloudsmith.connected"],
  ["cloudsmith-vsc.exportTerraform", "Export as Terraform", "recoverable", true, "cloudsmith.connected"],
  ["cloudsmith-vsc.showPromotionStatus", "Show promotion status", "recoverable", true, "cloudsmith.connected"],
  ["cloudsmith-vsc.promotePackage", "Promote package", "recoverable", true, "cloudsmith.connected"],
  ["cloudsmith-vsc.copyEntitlementToken", "Copy entitlement token", "context-only", false, "cloudsmith.connected"],
  ["cloudsmith-vsc.filterVulnerable", "Show vulnerable packages", "context-only", false, "cloudsmith.connected"],
  ["cloudsmith-vsc.filterVulnerableWorkspace", "Show vulnerable packages (all repositories)", "context-only", false, "cloudsmith.connected"],
]);

const PALETTE_EXCLUSIONS = Object.freeze([
  ["cloudsmith-vsc.copySelected", "false"],
  ["cloudsmith-vsc.inspectPackageGroup", "false"],
  ["cloudsmith-vsc.openPackageGroup", "false"],
  ["cloudsmith-vsc.loadMoreRepositoryPackages", "false"],
  ["cloudsmith-vsc.searchInWorkspace", "false"],
  ["cloudsmith-vsc.filterPackages", "false"],
  ["cloudsmith-vsc.clearFilter", "false"],
  ["cloudsmith-vsc.changeFilter", "false"],
  ["cloudsmith-vsc.filterVulnerable", "false"],
  ["cloudsmith-vsc.filterVulnerableWorkspace", "false"],
  ["cloudsmith-vsc.openCVE", "false"],
  ["cloudsmith-vsc.showDepVulnerabilities", "false"],
  ["cloudsmith-vsc.findDepSafeVersion", "false"],
  ["cloudsmith-vsc.filterVulnerabilities", "false"],
  ["cloudsmith-vsc.pullSingleDependency", "false"],
  ["cloudsmith-vsc.openLicenseUrl", "false"],
  ["cloudsmith-vsc.copyEntitlementToken", "false"],
]);

const ITEM_PLACEMENTS = Object.freeze([
  ["cloudsmith-vsc.inspectPackage", "view == cloudsmithView && viewItem =~ /^(package|packageNotCopyable|packageQuarantined)$/", "navigation"],
  ["cloudsmith-vsc.inspectPackageGroup", "view == cloudsmithView && viewItem == packageGroup", "navigation"],
  ["cloudsmith-vsc.copySelected", "view == cloudsmithView && viewItem == packageDetail", "9_cutcopypaste"],
  ["cloudsmith-vsc.openPackage", "view == cloudsmithView && viewItem =~ /^(package|packageNotCopyable|packageQuarantined)$/", "navigation"],
  ["cloudsmith-vsc.openPackageGroup", "view == cloudsmithView && viewItem == packageGroup", "navigation"],
  ["cloudsmith-vsc.searchInWorkspace", "view == cloudsmithView && viewItem == workspace", "navigation"],
  ["cloudsmith-vsc.filterVulnerableWorkspace", "view == cloudsmithView && viewItem == workspace", "filter@3"],
  ["cloudsmith-vsc.inspectPackage", "view == cloudsmithSearchView && viewItem =~ /^(package|packageNotCopyable|packageQuarantined)$/", "navigation"],
  ["cloudsmith-vsc.openPackage", "view == cloudsmithSearchView && viewItem =~ /^(package|packageNotCopyable|packageQuarantined)$/", "navigation"],
  ["cloudsmith-vsc.inspectPackage", "view == cloudsmithDependencyHealthView && viewItem =~ /^(dependencyHealthFound|dependencyHealthVulnerable|dependencyHealthQuarantined)$/", "navigation"],
  ["cloudsmith-vsc.openPackage", "view == cloudsmithDependencyHealthView && viewItem =~ /^(dependencyHealthFound|dependencyHealthVulnerable|dependencyHealthQuarantined)$/", "navigation"],
  ["cloudsmith-vsc.filterPackages", "view == cloudsmithView && viewItem == repository", "navigation"],
  ["cloudsmith-vsc.filterPackages", "view == cloudsmithView && viewItem == repositoryFiltered", "navigation"],
  ["cloudsmith-vsc.changeFilter", "view == cloudsmithView && viewItem == repositoryFiltered", "navigation"],
  ["cloudsmith-vsc.clearFilter", "view == cloudsmithView && viewItem == repositoryFiltered", "navigation"],
  ["cloudsmith-vsc.filterVulnerable", "view == cloudsmithView && viewItem == repository", "filter@3"],
  ["cloudsmith-vsc.inspectUpstreams", "view == cloudsmithView && viewItem =~ /^(repository|repositoryFiltered|upstreamIndicator)$/", "navigation@2"],
  ["cloudsmith-vsc.exportTerraform", "view == cloudsmithView && viewItem == repository", "cloudsmith.export"],
  ["cloudsmith-vsc.exportTerraform", "view == cloudsmithView && viewItem == repositoryFiltered", "cloudsmith.export"],
  ["cloudsmith-vsc.filterVulnerable", "view == cloudsmithView && viewItem == repositoryFiltered", "filter@3"],
  ["cloudsmith-vsc.copySelected", "view == cloudsmithSearchView && viewItem == packageDetail", "9_cutcopypaste"],
  ["cloudsmith-vsc.findSafeVersion", "view == cloudsmithView && viewItem =~ /^(package|packageNotCopyable|packageQuarantined)$/", "navigation"],
  ["cloudsmith-vsc.findSafeVersion", "view == cloudsmithSearchView && viewItem =~ /^(package|packageNotCopyable|packageQuarantined)$/", "navigation"],
  ["cloudsmith-vsc.openCVE", "view == cloudsmithView && viewItem == vulnerability", "navigation"],
  ["cloudsmith-vsc.openCVE", "view == cloudsmithSearchView && viewItem == vulnerability", "navigation"],
  ["cloudsmith-vsc.openCVE", "view == cloudsmithDependencyHealthView && viewItem == vulnerability", "navigation"],
  ["cloudsmith-vsc.showVulnerabilities", "view == cloudsmithView && viewItem =~ /^(package|packageNotCopyable|packageQuarantined)$/", "navigation"],
  ["cloudsmith-vsc.showVulnerabilities", "view == cloudsmithSearchView && viewItem =~ /^(package|packageNotCopyable|packageQuarantined)$/", "navigation"],
  ["cloudsmith-vsc.showDepVulnerabilities", "view == cloudsmithDependencyHealthView && viewItem == dependencyHealthVulnerable", "navigation"],
  ["cloudsmith-vsc.findDepSafeVersion", "view == cloudsmithDependencyHealthView && viewItem == dependencyHealthVulnerable", "navigation"],
  ["cloudsmith-vsc.filterVulnerabilities", "view == cloudsmithView && viewItem == vulnerabilitySummary", "inline"],
  ["cloudsmith-vsc.filterVulnerabilities", "view == cloudsmithView && viewItem == vulnerabilitySummary", "navigation"],
  ["cloudsmith-vsc.filterVulnerabilities", "view == cloudsmithSearchView && viewItem == vulnerabilitySummary", "inline"],
  ["cloudsmith-vsc.filterVulnerabilities", "view == cloudsmithSearchView && viewItem == vulnerabilitySummary", "navigation"],
  ["cloudsmith-vsc.filterVulnerabilities", "view == cloudsmithDependencyHealthView && viewItem == vulnerabilitySummary", "inline"],
  ["cloudsmith-vsc.filterVulnerabilities", "view == cloudsmithDependencyHealthView && viewItem == vulnerabilitySummary", "navigation"],
  ["cloudsmith-vsc.explainQuarantine", "view == cloudsmithView && viewItem == packageQuarantined", "navigation"],
  ["cloudsmith-vsc.explainQuarantine", "view == cloudsmithSearchView && viewItem == packageQuarantined", "navigation"],
  ["cloudsmith-vsc.explainQuarantine", "view == cloudsmithDependencyHealthView && viewItem == dependencyHealthQuarantined", "navigation"],
  ["cloudsmith-vsc.copyInstallCommand", "view == cloudsmithView && viewItem == package", "navigation"],
  ["cloudsmith-vsc.copyInstallCommand", "view == cloudsmithSearchView && viewItem == package", "navigation"],
  ["cloudsmith-vsc.copyInstallCommand", "view == cloudsmithDependencyHealthView && viewItem =~ /^(dependencyHealthFound|dependencyHealthVulnerable)$/", "navigation"],
  ["cloudsmith-vsc.showInstallCommand", "view == cloudsmithView && viewItem == package", "navigation"],
  ["cloudsmith-vsc.showInstallCommand", "view == cloudsmithSearchView && viewItem == package", "navigation"],
  ["cloudsmith-vsc.showInstallCommand", "view == cloudsmithDependencyHealthView && viewItem =~ /^(dependencyHealthFound|dependencyHealthVulnerable)$/", "navigation"],
  ["cloudsmith-vsc.openLicenseUrl", "view == cloudsmithView && viewItem == licenseDetailWithUrl", "navigation"],
  ["cloudsmith-vsc.openLicenseUrl", "view == cloudsmithSearchView && viewItem == licenseDetailWithUrl", "navigation"],
  ["cloudsmith-vsc.previewUpstreamResolution", "view == cloudsmithDependencyHealthView && viewItem =~ /^(dependencyHealthMissing|dependencyHealthUpstreamReachable|dependencyHealthUpstreamUnreachable)$/", "navigation"],
  ["cloudsmith-vsc.pullSingleDependency", "view == cloudsmithDependencyHealthView && viewItem =~ /^(dependencyHealthMissing|dependencyHealthUpstreamReachable)$/", "inline"],
  ["cloudsmith-vsc.pullSingleDependency", "view == cloudsmithDependencyHealthView && viewItem =~ /^(dependencyHealthMissing|dependencyHealthUpstreamReachable)$/", "1_pull"],
  ["cloudsmith-vsc.showPromotionStatus", "view == cloudsmithView && viewItem =~ /^(package|packageNotCopyable|packageQuarantined)$/", "2_promotion"],
  ["cloudsmith-vsc.showPromotionStatus", "view == cloudsmithSearchView && viewItem =~ /^(package|packageNotCopyable|packageQuarantined)$/", "2_promotion"],
  ["cloudsmith-vsc.promotePackage", "view == cloudsmithView && viewItem == package", "2_promotion"],
  ["cloudsmith-vsc.promotePackage", "view == cloudsmithSearchView && viewItem == package", "2_promotion"],
  ["cloudsmith-vsc.copyEntitlementToken", "view == cloudsmithView && viewItem == entitlementWithToken", "9_cutcopypaste"],
]);

const TITLE_PLACEMENTS = Object.freeze([
  ["cloudsmith-vsc.refreshView", "view == cloudsmithView && cloudsmith.connected", "navigation"],
  ["cloudsmith-vsc.setDefaultWorkspace", "view == cloudsmithView && cloudsmith.connected && cloudsmith.hasMultipleWorkspaces && !cloudsmith.hasDefaultWorkspace", "navigation"],
  ["cloudsmith-vsc.connectCloudsmith", "view == cloudsmithView && !cloudsmith.connected && cloudsmith.connectionSetupAvailable && cloudsmith.credentialsPresent", "navigation"],
  ["cloudsmith-vsc.configureCredentials", "view == cloudsmithView && !cloudsmith.connected && cloudsmith.connectionSetupAvailable", "navigation"],
  ["cloudsmith-vsc.openSettings", "view == cloudsmithView", "navigation"],
  ["cloudsmith-vsc.clearCredentials", "view == cloudsmithView && cloudsmith.credentialsPresent", "navigation"],
  ["cloudsmith-vsc.searchPackages", "view == cloudsmithSearchView && cloudsmith.connected", "navigation"],
  ["cloudsmith-vsc.clearSearch", "view == cloudsmithSearchView && cloudsmith.connected && cloudsmith.searchActive", "navigation"],
  ["cloudsmith-vsc.scanDependencies", "view == cloudsmithDependencyHealthView && cloudsmith.connected && !cloudsmith.depOperationRunning", "navigation@1"],
  ["cloudsmith-vsc.changeDependencyScanScope", "view == cloudsmithDependencyHealthView && cloudsmith.connected && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning", "navigation@1.5"],
  ["cloudsmith-vsc.pullDependencies", "view == cloudsmithDependencyHealthView && cloudsmith.connected && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning", "navigation@2"],
  ["cloudsmith-vsc.cycleDepView", "view == cloudsmithDependencyHealthView && cloudsmith.connected && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning", "navigation@3"],
  ["cloudsmith-vsc.depSortFilter", "view == cloudsmithDependencyHealthView && cloudsmith.connected && cloudsmith.depScanSucceeded && !cloudsmith.depOperationRunning", "navigation@4"],
  ["cloudsmith-vsc.viewComplianceReport", "view == cloudsmithDependencyHealthView && cloudsmith.connected && cloudsmith.depReportAvailable", "navigation@5"],
]);

const INTERNAL_COMMANDS = Object.freeze([
  "cloudsmith-vsc.scanDependenciesPending",
  "cloudsmith-vsc.scanDependenciesComplete",
  "cloudsmith-vsc.rescanDependencies",
  "cloudsmith-vsc.cycleDepViewDirect",
  "cloudsmith-vsc.cycleDepViewFlat",
  "cloudsmith-vsc.cycleDepViewTree",
  "cloudsmith-vsc.depSortFilterActive",
]);

const EXPECTED_CLASSIFICATIONS = Object.freeze({
  global: Object.freeze(COMMANDS.filter(entry => entry[2] === "global").map(entry => entry[0])),
  recoverable: Object.freeze(COMMANDS.filter(entry => entry[2] === "recoverable").map(entry => entry[0])),
  contextOnly: Object.freeze(COMMANDS.filter(entry => entry[2] === "context-only").map(entry => entry[0])),
});

function menuTuples(entries) {
  return entries.map(entry => [entry.command, entry.when, entry.group]);
}

function assertArchitectureClassifications(metadata) {
  assert.deepStrictEqual(
    [...metadata.commandUx.classifications.global].sort(),
    [...EXPECTED_CLASSIFICATIONS.global].sort(),
  );
  assert.deepStrictEqual(
    [...metadata.commandUx.classifications.recoverable].sort(),
    [...EXPECTED_CLASSIFICATIONS.recoverable].sort(),
  );
  assert.deepStrictEqual(
    [...metadata.commandUx.classifications.contextOnly].sort(),
    [...EXPECTED_CLASSIFICATIONS.contextOnly].sort(),
  );
}

suite("M13 command UX oracle", () => {
  test("hard-coded command classification, palette, titles, categories, and enablement match", () => {
    assert.strictEqual(COMMANDS.filter(entry => entry[2] === "global").length, 29);
    assert.strictEqual(COMMANDS.filter(entry => entry[2] === "recoverable").length, 11);
    assert.strictEqual(COMMANDS.filter(entry => entry[2] === "context-only").length, 17);
    assertArchitectureClassifications(architecture);

    assert.deepStrictEqual(
      manifest.contributes.commands.map(entry => [
        entry.command,
        entry.title,
        entry.category,
        entry.enablement || null,
      ]),
      COMMANDS.map(entry => [entry[0], entry[1], "Cloudsmith", entry[4]]),
    );
    const paletteEntries = manifest.contributes.menus.commandPalette;
    assert.deepStrictEqual(
      paletteEntries.map(entry => [entry.command, entry.when]),
      PALETTE_EXCLUSIONS,
    );
    assert.strictEqual(COMMANDS.every(entry => (
      entry[3] === (entry[2] !== "context-only")
    )), true);
  });

  test("classification oracle rejects a count-preserving metadata mutation", () => {
    const mutated = JSON.parse(JSON.stringify(architecture));
    const globalCommand = mutated.commandUx.classifications.global[0];
    const recoverableCommand = mutated.commandUx.classifications.recoverable[0];
    mutated.commandUx.classifications.global[0] = recoverableCommand;
    mutated.commandUx.classifications.recoverable[0] = globalCommand;

    assert.throws(() => assertArchitectureClassifications(mutated), assert.AssertionError);
  });

  test("hard-coded item and title placements match exactly", () => {
    assert.deepStrictEqual(
      menuTuples(manifest.contributes.menus["view/item/context"]),
      ITEM_PLACEMENTS,
    );
    assert.deepStrictEqual(
      menuTuples(manifest.contributes.menus["view/title"]),
      TITLE_PLACEMENTS,
    );
  });

  test("all internal aliases stay out of every customer contribution surface", () => {
    const customerIds = new Set(manifest.contributes.commands.map(entry => entry.command));
    const menuIds = new Set(Object.values(manifest.contributes.menus).flat().map(entry => entry.command));
    const keybindingIds = new Set((manifest.contributes.keybindings || []).map(entry => entry.command));
    assert.deepStrictEqual(architecture.internalCommandIds, INTERNAL_COMMANDS);
    for (const alias of INTERNAL_COMMANDS) {
      assert.strictEqual(customerIds.has(alias), false);
      assert.strictEqual(menuIds.has(alias), false);
      assert.strictEqual(keybindingIds.has(alias), false);
    }
  });
});

// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { registerCommands } = require("./registrar");
const {
  adaptPackageSelection,
  adaptRepositoryResolutionSelection,
  buildInstallCommand,
  isQuarantinedPackage,
  pickInstallCommandVariant,
  pickRecentPackage,
} = require("./support");

function registerVulnerabilityCommands(deps) {
  const {
    registerCommand,
    vscode,
    context,
    packageAdapters,
    packageDomain,
    recentPackages,
    CloudsmithAPI,
    RemediationHelper,
    InstallCommandBuilder,
    buildPackageUrl,
    vulnerabilityProvider,
    quarantineExplainProvider,
    cloudsmithProvider,
    searchProvider,
    dependencyHealthProvider,
  } = deps;
  const recentSupport = { recentPackages, packageAdapters, vscode };

  async function selectedPackage(item, options = {}) {
    const pkg = item
      ? adaptPackageSelection(packageAdapters, item)
      : await pickRecentPackage(recentSupport, options);
    if (!pkg && !item) return null;
    try {
      return packageDomain.assertExactPackage(pkg);
    } catch {
      vscode.window.showWarningMessage(options.invalidMessage || "Could not determine package details.");
      return null;
    }
  }

  async function findSafeVersion(item) {
    let selection = item;
    if (!selection) selection = await pickRecentPackage(recentSupport);
    if (!selection) return;
    let safeVersionSelection;
    try {
      const scope = dependencyHealthProvider?.getLastSuccessfulScope?.() || null;
      safeVersionSelection = adaptRepositoryResolutionSelection(
        packageAdapters,
        packageDomain,
        selection,
        scope ? { workspace: scope.workspace, repository: scope.repository } : {}
      );
    } catch {
      vscode.window.showWarningMessage("Could not determine package details.");
      return;
    }
    if (safeVersionSelection.exactPackage) {
      recentPackages.add(safeVersionSelection.exactPackage);
    }
    const source = safeVersionSelection.resolution;
    const helper = new RemediationHelper(new CloudsmithAPI(context));
    let result = await helper.findSafeVersions(
      source.workspace,
      source.repository,
      source.name,
      source.format
    );
    let crossRepo = false;
    if (!result.success) {
      vscode.window.showErrorMessage(
        `Could not find safe versions. ${deps.formatApiError(result.error)}`
      );
      return;
    }
    if (result.versions.length === 0) {
      result = await helper.findSafeVersionsAcrossRepos(
        source.workspace,
        source.name,
        source.format
      );
      crossRepo = true;
      if (!result.success) {
        vscode.window.showErrorMessage(
          `Could not find safe versions. ${deps.formatApiError(result.error)}`
        );
        return;
      }
    }
    if (result.versions.length === 0) {
      if (result.absenceProven) {
        vscode.window.showInformationMessage(
          `No safe versions found for "${source.name}" in ${crossRepo ? "the workspace" : source.repository}.`
        );
      } else {
        vscode.window.showWarningMessage(
          `Safe-version results were incomplete; no absence claim can be made for "${source.name}".`
        );
      }
      return;
    }

    const versions = [];
    try {
      for (const record of result.versions) {
        versions.push(packageDomain.assertExactPackage(
          packageAdapters.fromApiPackageRecord(record)
        ));
      }
    } catch {
      vscode.window.showErrorMessage("Could not safely interpret the available package versions.");
      return;
    }
    const quickPickItems = versions.map(pkg => {
      const policyIcon = pkg.policy.violated ? "$(warning)" : "$(check)";
      const repositoryLabel = crossRepo ? ` [${pkg.repository}]` : "";
      let detail = "No policy violations";
      if (pkg.policy.violated) detail = "Policy violations found";
      if (pkg.vulnerability.count > 0) {
        detail = `${pkg.vulnerability.count} vulnerabilit${pkg.vulnerability.count === 1 ? "y" : "ies"} (${pkg.vulnerability.maxSeverity || "Unknown"})`;
      }
      return {
        label: `${policyIcon} ${source.name} ${pkg.version}`,
        description: `${pkg.repository || source.repository} — ${pkg.status}${repositoryLabel}`,
        detail,
        package: pkg,
      };
    });
    if (!result.complete) {
      const countDetail = result.totalCount === null
        ? `${versions.length} loaded`
        : `showing newest ${versions.length} of ${result.totalCount}`;
      quickPickItems.unshift({
        label: `Safe-version preview incomplete (${countDetail})`,
        kind: vscode.QuickPickItemKind.Separator,
      });
    }
    const title = crossRepo
      ? `Newest safe versions of "${source.name}" (${source.format}) in the workspace`
      : `Newest safe versions of "${source.name}" (${source.format}) in ${source.repository}`;
    const selected = await vscode.window.showQuickPick(quickPickItems, { placeHolder: title });
    if (!selected || !selected.package) return;
    const pkg = selected.package;
    const action = await vscode.window.showQuickPick([
      { label: "$(clippy) Copy install command", id: "install" },
      { label: "$(shield) Show vulnerabilities", id: "vulns" },
      { label: "$(globe) View in Cloudsmith", id: "open" },
      { label: "$(json) Inspect package", id: "inspect" },
      { label: "$(copy) Copy version", id: "copy" },
    ], { placeHolder: `Select an action for ${source.name} ${pkg.version}` });
    if (!action) return;

    if (action.id === "install") {
      const installResult = buildInstallCommand(deps, pkg);
      if (!installResult) return;
      const chosenCommand = await pickInstallCommandVariant(deps, installResult);
      if (!chosenCommand) return;
      await vscode.env.clipboard.writeText(
        InstallCommandBuilder.toClipboardCommand(chosenCommand)
      );
      let message = crossRepo
        ? `Install command copied for ${source.name} ${pkg.version} from ${pkg.repository}.`
        : `Install command copied for ${source.name} ${pkg.version}.`;
      if (installResult.note) message += ` Note: ${installResult.note}`;
      vscode.window.showInformationMessage(message);
    } else if (action.id === "vulns") {
      await showVulnerabilities(pkg);
    } else if (action.id === "open") {
      const url = buildPackageUrl(
        pkg.workspace,
        pkg.repository,
        pkg.format,
        pkg.name,
        pkg.version,
        pkg.packageIdentifier
      );
      if (url) {
        await vscode.env.openExternal(vscode.Uri.parse(url));
      } else {
        vscode.window.showInformationMessage("Could not open this package in Cloudsmith.");
      }
    } else if (action.id === "inspect") {
      await vscode.commands.executeCommand("cloudsmith-vsc.inspectPackage", pkg);
    } else if (action.id === "copy") {
      await vscode.env.clipboard.writeText(pkg.version);
      vscode.window.showInformationMessage(`Version copied: ${pkg.version}.`);
    }
  }

  async function openCVE(item) {
    const cveId = item && item.cveId;
    if (
      typeof cveId !== "string"
      || cveId.length === 0
      || cveId.length > 128
      || cveId.trim() !== cveId
      || /[\u0000-\u001f\u007f/\\?#]/.test(cveId)
      || !/^(?:CVE-[0-9]{4}-[0-9]{4,19}|GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4})$/.test(cveId)
    ) {
      vscode.window.showWarningMessage("No vulnerability selected.");
      return;
    }
    const encodedIdentifier = encodeURIComponent(cveId);
    const url = cveId.startsWith("GHSA-")
      ? `https://github.com/advisories/${encodedIdentifier}`
      : `https://nvd.nist.gov/vuln/detail/${encodedIdentifier}`;
    await vscode.env.openExternal(vscode.Uri.parse(url));
  }

  async function showVulnerabilities(item) {
    const pkg = await selectedPackage(item);
    if (!pkg) return;
    recentPackages.add(pkg);
    await vulnerabilityProvider.show(pkg);
  }

  async function filterVulnerabilities(summaryNode) {
    if (
      !summaryNode
      || typeof summaryNode.setSeverityFilter !== "function"
      || typeof summaryNode.setCvssThreshold !== "function"
    ) {
      vscode.window.showWarningMessage("No vulnerability summary selected.");
      return;
    }
    const filterType = await vscode.window.showQuickPick([
      { label: "$(filter) Filter by severity", value: "severity" },
      { label: "$(dashboard) Filter by CVSS threshold", value: "cvss" },
      { label: "$(clear-all) Clear filters", value: "clear" },
    ], { placeHolder: "Filter vulnerabilities" });
    if (!filterType) return;

    if (filterType.value === "severity") {
      const severities = await vscode.window.showQuickPick([
        { label: "Critical", picked: true },
        { label: "High", picked: true },
        { label: "Medium", picked: false },
        { label: "Low", picked: false },
      ], { canPickMany: true, placeHolder: "Select severity levels to show" });
      if (!severities || severities.length === 0) return;
      summaryNode.setSeverityFilter(severities.map(severity => severity.label.toLowerCase()));
    } else if (filterType.value === "cvss") {
      const thresholdPick = await vscode.window.showQuickPick([
        { label: "CVSS >= 9.0 (Critical)", value: 9.0 },
        { label: "CVSS >= 7.0 (High+)", value: 7.0 },
        { label: "CVSS >= 4.0 (Medium+)", value: 4.0 },
        { label: "Custom threshold", value: "custom" },
      ], { placeHolder: "Select minimum CVSS score" });
      if (!thresholdPick) return;
      let cvssValue = thresholdPick.value;
      if (cvssValue === "custom") {
        const input = await vscode.window.showInputBox({
          prompt: "Enter a minimum CVSS score (0.0 - 10.0)",
          placeHolder: "7.0",
          validateInput: value => {
            const parsed = Number.parseFloat(value);
            return Number.isNaN(parsed) || parsed < 0 || parsed > 10
              ? "Enter a number between 0.0 and 10.0."
              : null;
          },
        });
        if (!input) return;
        cvssValue = Number.parseFloat(input);
      }
      summaryNode.setCvssThreshold(cvssValue);
    } else {
      summaryNode.setSeverityFilter(null);
      summaryNode.setCvssThreshold(null);
    }
    cloudsmithProvider._onDidChangeTreeData.fire(summaryNode);
    searchProvider._onDidChangeTreeData.fire(summaryNode);
    dependencyHealthProvider._onDidChangeTreeData.fire(summaryNode);
  }

  async function explainQuarantine(item) {
    const pkg = await selectedPackage(item, {
      predicate: isQuarantinedPackage,
      emptyMessage: "No recent quarantined packages. Run this command from a quarantined package context menu.",
      placeHolder: "Select a quarantined package",
    });
    if (!pkg) return;
    recentPackages.add(pkg);
    await quarantineExplainProvider.show(pkg);
  }

  return registerCommands(registerCommand, [
    ["cloudsmith-vsc.findSafeVersion", findSafeVersion],
    ["cloudsmith-vsc.openCVE", openCVE],
    ["cloudsmith-vsc.showVulnerabilities", showVulnerabilities],
    ["cloudsmith-vsc.showDepVulnerabilities", showVulnerabilities],
    ["cloudsmith-vsc.findDepSafeVersion", findSafeVersion],
    ["cloudsmith-vsc.filterVulnerabilities", filterVulnerabilities],
    ["cloudsmith-vsc.explainQuarantine", explainQuarantine],
  ], deps);
}

module.exports = { registerVulnerabilityCommands };

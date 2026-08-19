// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { registerCommands } = require("./registrar");
const {
  adaptPackageSelection,
  adaptRepositoryResolutionSelection,
  buildInstallCommand,
  captureCommandAccount,
  isCommandAccountCurrent,
  isQuarantinedPackage,
  pickInstallCommandVariant,
  pickRecentPackage,
  showAccountInputBox,
  showAccountQuickPick,
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
    normalizeCvssScore,
  } = deps;
  const recentSupport = { ...deps, recentPackages, packageAdapters, vscode };

  function ownsSelection(kind, item) {
    let validator = null;
    if (kind === "isCurrentSelection") validator = deps.isCurrentSelection;
    if (kind === "isCurrentPackageSelection") validator = deps.isCurrentPackageSelection;
    if (kind === "isCurrentDependencySelection") validator = deps.isCurrentDependencySelection;
    return typeof validator === "function" && validator(item) === true;
  }

  function currentSelection(accountScope, kind, item) {
    return isCommandAccountCurrent(accountScope) && ownsSelection(kind, item);
  }

  function isVulnerableDependencySelection(item) {
    if (!ownsSelection("isCurrentDependencySelection", item)) return false;
    try {
      return item?.getTreeItem?.().contextValue === "dependencyHealthVulnerable";
    } catch {
      return false;
    }
  }

  async function selectedPackage(item, accountScope, options = {}) {
    let pkg;
    let selection = item;
    const selectionValidator = options.selectionValidator || "isCurrentPackageSelection";
    if (item) {
      try {
        pkg = adaptPackageSelection(packageAdapters, item);
      } catch {
        vscode.window.showWarningMessage(options.invalidMessage || "Could not determine package details.");
        return null;
      }
      if (!ownsSelection(selectionValidator, item)) return null;
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
        currentSelection: candidate => ownsSelection("isCurrentPackageSelection", candidate),
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
      const isCurrent = () => Boolean(
        currentSelection(accountScope, selectionValidator, selection)
        && (
          typeof options.currentSelection !== "function"
          || options.currentSelection(selection)
        )
      );
      if (!isCurrent()) return null;
      return Object.freeze({ package: exactPackage, isCurrent });
    } catch {
      vscode.window.showWarningMessage(options.invalidMessage || "Could not determine package details.");
      return null;
    }
  }

  async function findSafeVersion(item, options = {}) {
    const accountScope = captureCommandAccount(deps.workspaceAccess);
    if (!accountScope) return;
    let selection = item;
    if (options.dependencyOnly) {
      if (!selection || !isVulnerableDependencySelection(selection)) return;
    } else if (!selection) {
      selection = await pickRecentPackage(recentSupport, {
        accountScope,
        currentSelection: candidate => ownsSelection("isCurrentPackageSelection", candidate),
      });
    } else if (!ownsSelection("isCurrentPackageSelection", selection)) {
      return;
    }
    if (!selection) return;
    let safeVersionSelection;
    try {
      safeVersionSelection = adaptRepositoryResolutionSelection(
        packageAdapters,
        packageDomain,
        selection
      );
    } catch {
      vscode.window.showWarningMessage("Could not determine package details.");
      return;
    }
    if (options.dependencyOnly && !safeVersionSelection.exactPackage) return;
    const dependencyScope = options.dependencyOnly
      ? dependencyHealthProvider.getLastSuccessfulScope?.()
      : null;
    if (
      options.dependencyOnly
      && (
        !dependencyScope
        || dependencyScope.workspace !== safeVersionSelection.resolution.workspace
        || (
          dependencyScope.repository
          && dependencyScope.repository !== safeVersionSelection.resolution.repository
        )
      )
    ) return;
    const isFindCurrent = () => {
      if (!isCommandAccountCurrent(accountScope)) return false;
      if (!options.dependencyOnly) {
        return ownsSelection("isCurrentPackageSelection", selection);
      }
      if (!isVulnerableDependencySelection(selection)) return false;
      const currentScope = dependencyHealthProvider.getLastSuccessfulScope?.();
      return Boolean(
        currentScope
        && currentScope.workspace === dependencyScope.workspace
        && (currentScope.repository || null) === (dependencyScope.repository || null)
      );
    };
    const source = safeVersionSelection.resolution;
    const helper = new RemediationHelper(new CloudsmithAPI(context));
    if (!isFindCurrent()) return;
    let result = await helper.findSafeVersions(
      source.workspace,
      source.repository,
      source.name,
      source.format
    );
    if (!isFindCurrent()) return;
    let crossRepo = false;
    if (!result.success) {
      if (!isFindCurrent()) return;
      vscode.window.showErrorMessage(
        `Could not find safe versions. ${deps.formatApiError(result.error)}`
      );
      return;
    }
    if (result.versions.length === 0) {
      if (!isFindCurrent()) return;
      result = await helper.findSafeVersionsAcrossRepos(
        source.workspace,
        source.name,
        source.format
      );
      if (!isFindCurrent()) return;
      crossRepo = true;
      if (!result.success) {
        if (!isFindCurrent()) return;
        vscode.window.showErrorMessage(
          `Could not find safe versions. ${deps.formatApiError(result.error)}`
        );
        return;
      }
    }
    if (result.versions.length === 0) {
      if (!isFindCurrent()) return;
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
      if (!isFindCurrent()) return;
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
    const selected = await showAccountQuickPick(
      deps,
      accountScope,
      quickPickItems,
      { placeHolder: title }
    );
    if (
      !selected
      || !quickPickItems.includes(selected)
      || !selected.package
      || !isFindCurrent()
    ) return;
    const pkg = selected.package;
    const installEligible = pkg.copyable === true && !isQuarantinedPackage(pkg);
    const actionItems = [
      ...(installEligible
        ? [{ label: "$(clippy) Copy install command", id: "install" }]
        : []),
      { label: "$(shield) Show vulnerabilities", id: "vulns" },
      { label: "$(globe) View in Cloudsmith", id: "open" },
      { label: "$(json) Inspect package", id: "inspect" },
      { label: "$(copy) Copy version", id: "copy" },
    ];
    const action = await showAccountQuickPick(
      deps,
      accountScope,
      actionItems,
      { placeHolder: `Select an action for ${source.name} ${pkg.version}` }
    );
    if (!action || !actionItems.includes(action) || !isFindCurrent()) return;

    if (action.id === "install") {
      if (!installEligible || !isFindCurrent()) return;
      const installResult = buildInstallCommand(deps, pkg);
      if (!installResult) return;
      const chosenCommand = await pickInstallCommandVariant(deps, installResult, { accountScope });
      if (!chosenCommand) return;
      if (!isFindCurrent()) return;
      await vscode.env.clipboard.writeText(
        InstallCommandBuilder.toClipboardCommand(chosenCommand)
      );
      if (!isFindCurrent()) return;
      vscode.window.showInformationMessage("Install command copied.");
    } else if (action.id === "vulns") {
      if (!isFindCurrent()) return;
      await vulnerabilityProvider.show(pkg);
      if (!isFindCurrent()) return;
      recentPackages.add(pkg);
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
        if (!isFindCurrent()) return;
        await vscode.env.openExternal(vscode.Uri.parse(url));
      } else {
        if (!isFindCurrent()) return;
        vscode.window.showWarningMessage("Could not open this package in Cloudsmith.");
      }
    } else if (action.id === "inspect") {
      if (!isFindCurrent()) return;
      recentPackages.add(pkg);
      if (!isFindCurrent()) return;
      await vscode.commands.executeCommand("cloudsmith-vsc.inspectPackage", pkg);
    } else if (action.id === "copy") {
      if (!isFindCurrent()) return;
      await vscode.env.clipboard.writeText(pkg.version);
      if (!isFindCurrent()) return;
      vscode.window.showInformationMessage("Version copied.");
    }
  }

  async function openCVE(item) {
    const accountScope = captureCommandAccount(deps.workspaceAccess);
    if (!accountScope || !ownsSelection("isCurrentSelection", item)) return;
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
    if (!isCommandAccountCurrent(accountScope)) return;
    await vscode.env.openExternal(vscode.Uri.parse(url));
  }

  async function showVulnerabilities(item, options = {}) {
    const accountScope = captureCommandAccount(deps.workspaceAccess);
    if (!accountScope) return;
    if (options.dependencyOnly && !isVulnerableDependencySelection(item)) return;
    const selected = await selectedPackage(item, accountScope, {
      ...options,
      selectionValidator: options.dependencyOnly
        ? "isCurrentDependencySelection"
        : "isCurrentPackageSelection",
      currentSelection: options.dependencyOnly ? isVulnerableDependencySelection : undefined,
    });
    if (!selected) return;
    const { package: pkg, isCurrent } = selected;
    if (!isCurrent()) return;
    await vulnerabilityProvider.show(pkg);
    if (!isCurrent()) return;
    recentPackages.add(pkg);
  }

  async function filterVulnerabilities(summaryNode) {
    const accountScope = captureCommandAccount(deps.workspaceAccess);
    if (!accountScope || !ownsSelection("isCurrentSelection", summaryNode)) return;
    const isCurrent = () => currentSelection(accountScope, "isCurrentSelection", summaryNode);
    if (
      !summaryNode
      || typeof summaryNode.setSeverityFilter !== "function"
      || typeof summaryNode.setCvssThreshold !== "function"
    ) {
      vscode.window.showWarningMessage("No vulnerability summary selected.");
      return;
    }
    const filterType = await showAccountQuickPick(deps, accountScope, [
      { label: "$(filter) Filter by severity", value: "severity" },
      { label: "$(dashboard) Filter by CVSS threshold", value: "cvss" },
      { label: "$(clear-all) Clear filters", value: "clear" },
    ], { placeHolder: "Filter vulnerabilities" });
    if (!filterType || !isCurrent()) return;

    if (filterType.value === "severity") {
      const severities = await showAccountQuickPick(deps, accountScope, [
        { label: "Critical", picked: true },
        { label: "High", picked: true },
        { label: "Medium", picked: false },
        { label: "Low", picked: false },
      ], { canPickMany: true, placeHolder: "Select severity levels to show" });
      if (!severities || severities.length === 0 || !isCurrent()) return;
      summaryNode.setSeverityFilter(severities.map(severity => severity.label.toLowerCase()));
    } else if (filterType.value === "cvss") {
      const thresholdPick = await showAccountQuickPick(deps, accountScope, [
        { label: "CVSS >= 9.0 (Critical)", value: 9.0 },
        { label: "CVSS >= 7.0 (High+)", value: 7.0 },
        { label: "CVSS >= 4.0 (Medium+)", value: 4.0 },
        { label: "Custom threshold", value: "custom" },
      ], { placeHolder: "Select minimum CVSS score" });
      if (!thresholdPick || !isCurrent()) return;
      let cvssValue = thresholdPick.value;
      if (cvssValue === "custom") {
        const input = await showAccountInputBox(deps, accountScope, {
          prompt: "Enter a minimum CVSS score (0.0 - 10.0)",
          placeHolder: "7.0",
          validateInput: value => {
            const parsed = normalizeCvssScore(value);
            return parsed === null
              ? "Enter a number between 0.0 and 10.0."
              : null;
          },
        });
        if (!input || !isCurrent()) return;
        cvssValue = normalizeCvssScore(input);
        if (cvssValue === null) return;
      }
      if (!isCurrent()) return;
      summaryNode.setCvssThreshold(cvssValue);
    } else {
      if (!isCurrent()) return;
      summaryNode.setSeverityFilter(null);
      if (!isCurrent()) return;
      summaryNode.setCvssThreshold(null);
    }
    if (!isCurrent()) return;
    cloudsmithProvider.refreshNode(summaryNode);
    if (!isCurrent()) return;
    searchProvider.refreshNode(summaryNode);
    if (!isCurrent()) return;
    dependencyHealthProvider.refreshNode(summaryNode);
  }

  async function explainQuarantine(item) {
    const accountScope = captureCommandAccount(deps.workspaceAccess);
    if (!accountScope) return;
    const selected = await selectedPackage(item, accountScope, {
      predicate: isQuarantinedPackage,
      invalidStateMessage: "Quarantine details are available only for quarantined packages.",
      emptyMessage: "No recent quarantined packages. Open a quarantined package, then try again.",
      placeHolder: "Select a quarantined package",
    });
    if (!selected) return;
    const { package: pkg, isCurrent } = selected;
    if (!isCurrent()) return;
    await quarantineExplainProvider.show(pkg);
    if (!isCurrent()) return;
    recentPackages.add(pkg);
  }

  return registerCommands(registerCommand, [
    ["cloudsmith-vsc.findSafeVersion", findSafeVersion],
    ["cloudsmith-vsc.openCVE", openCVE],
    ["cloudsmith-vsc.showVulnerabilities", showVulnerabilities],
    ["cloudsmith-vsc.showDepVulnerabilities", item => showVulnerabilities(item, { dependencyOnly: true })],
    ["cloudsmith-vsc.findDepSafeVersion", item => findSafeVersion(item, { dependencyOnly: true })],
    ["cloudsmith-vsc.filterVulnerabilities", filterVulnerabilities],
    ["cloudsmith-vsc.explainQuarantine", explainQuarantine],
  ], deps);
}

module.exports = { registerVulnerabilityCommands };

// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { registerCommands } = require("./registrar");
const { PACKAGE_ACTIONS } = require("../domain/packageActionCapabilities");
const {
  adaptPackageSelection,
  adaptRepositoryResolutionSelection,
  buildInstallCommand,
  captureCommandAccount,
  isDependencyActionAvailable,
  isCommandAccountCurrent,
  isInstallablePackage,
  installGuidanceCopiedMessage,
  isQuarantinedPackage,
  pickInstallCommandVariant,
  pickRecentPackage,
  renderInstallCommandGuidance,
  safeDisplayName,
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
    buildPackageUrl,
    vulnerabilityProvider,
    quarantineExplainProvider,
    cloudsmithProvider,
    searchProvider,
    dependencyHealthProvider,
    vulnerabilityStateService,
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

  function isVulnerableDependencySelection(item, action) {
    if (!ownsSelection("isCurrentDependencySelection", item)) return false;
    return isDependencyActionAvailable(item, action);
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
      if (
        !selection
        || !isVulnerableDependencySelection(selection, PACKAGE_ACTIONS.FIND_SAFE_VERSION)
      ) return;
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
    if (!safeVersionSelection.exactPackage) {
      vscode.window.showWarningMessage("Could not determine package details.");
      return;
    }
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
      if (!isVulnerableDependencySelection(selection, PACKAGE_ACTIONS.FIND_SAFE_VERSION)) {
        return false;
      }
      const currentScope = dependencyHealthProvider.getLastSuccessfulScope?.();
      return Boolean(
        currentScope
        && currentScope.workspace === dependencyScope.workspace
        && (currentScope.repository || null) === (dependencyScope.repository || null)
      );
    };
    const source = safeVersionSelection.exactPackage;
    if (
      !vulnerabilityStateService
      || typeof vulnerabilityStateService.prime !== "function"
      || typeof vulnerabilityStateService.resolve !== "function"
    ) {
      vscode.window.showWarningMessage("Could not verify safe versions. Retry.");
      return;
    }
    let sourceVulnerabilityState;
    try {
      vulnerabilityStateService.prime(source);
      sourceVulnerabilityState = await vulnerabilityStateService.resolve(source);
    } catch {
      sourceVulnerabilityState = null;
    }
    if (!isFindCurrent()) return;
    if (!isCompleteVulnerabilityState(sourceVulnerabilityState)) {
      vscode.window.showWarningMessage("Could not verify safe versions. Retry.");
      return;
    }
    if (isCompleteCleanVulnerabilityState(sourceVulnerabilityState)) {
      vscode.window.showInformationMessage(
        `No known vulnerabilities were found for "${source.name}" ${source.version}.`
      );
      return;
    }
    const fixedVersions = sourceVulnerabilityState.status === "complete-vulnerable"
      ? vulnerabilityFixVersions(sourceVulnerabilityState)
      : [];
    const helper = new RemediationHelper(new CloudsmithAPI(context));
    if (!isFindCurrent()) return;
    const result = await helper.findSafeVersions(
      source.workspace,
      source.repository,
      source.name,
      source.format,
      {
        currentVersion: source.version,
        fixedVersions,
      }
    );
    if (!isFindCurrent()) return;
    if (!result.success) {
      if (!isFindCurrent()) return;
      vscode.window.showErrorMessage(
        `Could not find safe versions. ${deps.formatApiError(result.error)}`
      );
      return;
    }
    if (result.versions.length === 0) {
      if (!isFindCurrent()) return;
      if (result.absenceProven) {
        vscode.window.showInformationMessage(
          `No compatible safe version for "${source.name}" is available in ${source.repository}.${reportedFixCopy(fixedVersions)}`
        );
      } else {
        vscode.window.showWarningMessage(
          "Could not verify whether compatible safe versions are available. Retry."
        );
      }
      return;
    }

    const versions = [];
    try {
      for (const record of result.versions) {
        const candidate = packageAdapters.fromSafeVersionApiRecord(record, {
          expectedWorkspace: source.workspace,
          expectedRepository: source.repository,
        });
        if (!candidate) continue;
        const pkg = packageDomain.assertExactPackage(candidate);
        if (
          pkg.workspace !== source.workspace
          || pkg.repository !== source.repository
          || pkg.name !== source.name
          || pkg.format !== source.format
          || !sameRemediationIdentity(source, pkg)
          || pkg.version === source.version
          || definitelyViolatesCompatibility(
            pkg.version,
            source.version,
            fixedVersions,
            source.format
          )
        ) {
          throw new TypeError("Safe-version result escaped its selected package scope.");
        }
        if (isRejectedSafeVersionCandidate(pkg)) continue;
        versions.push(pkg);
      }
    } catch {
      if (!isFindCurrent()) return;
      vscode.window.showErrorMessage("Could not safely interpret the available package versions.");
      return;
    }
    const verification = await Promise.all(versions.map(async pkg => {
      try {
        vulnerabilityStateService.prime(pkg);
        const state = await vulnerabilityStateService.resolve(pkg);
        return isCompleteCleanVulnerabilityState(state) ? pkg : null;
      } catch {
        return null;
      }
    }));
    if (!isFindCurrent()) return;
    const verifiedVersions = verification.filter(Boolean);
    if (verifiedVersions.length === 0) {
      vscode.window.showWarningMessage("Could not verify safe versions. Retry.");
      return;
    }
    const quickPickItems = verifiedVersions.map(pkg => {
      const policyIcon = pkg.policy.violated ? "$(warning)" : "$(check)";
      const verificationDetail = pkg.policy.violated
        ? "Policy violations found"
        : "No known vulnerabilities";
      const packageIdentity = safeDisplayName(
        pkg.packageIdentifier,
        "unknown-package",
        512
      );
      return {
        label: `${policyIcon} ${source.name} ${pkg.version}`,
        description: [pkg.repository || source.repository, pkg.status]
          .filter(Boolean)
          .join(" — "),
        detail: `${verificationDetail} — ${safeDisplayName(
          pkg.format,
          "unknown-format",
          64
        )} — ${packageIdentity}`,
        package: pkg,
      };
    });
    const title = `Verified safe versions of "${source.name}" (${source.format}) in ${source.repository}`;
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
    const installEligible = isInstallablePackage(pkg);
    const actionItems = [
      ...(installEligible
        ? [{
          label: pkg.format === "maven"
            ? "$(file-code) Copy Maven setup guidance"
            : "$(clippy) Copy install command",
          id: "install",
        }]
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
        renderInstallCommandGuidance(deps, installResult, chosenCommand)
      );
      if (!isFindCurrent()) return;
      vscode.window.showInformationMessage(installGuidanceCopiedMessage(installResult));
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
    const canShowDependencyVulnerabilities = candidate => (
      isVulnerableDependencySelection(candidate, PACKAGE_ACTIONS.SHOW_VULNERABILITIES)
    );
    if (options.dependencyOnly && !canShowDependencyVulnerabilities(item)) return;
    const selected = await selectedPackage(item, accountScope, {
      ...options,
      selectionValidator: options.dependencyOnly
        ? "isCurrentDependencySelection"
        : "isCurrentPackageSelection",
      currentSelection: options.dependencyOnly ? canShowDependencyVulnerabilities : undefined,
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

function isCompleteVulnerabilityState(state) {
  return isCompleteCleanVulnerabilityState(state)
    || isCompleteVulnerableState(state);
}

function isCompleteCleanVulnerabilityState(state) {
  return Boolean(
    state
    && state.status === "complete-clean"
    && state.complete === true
    && state.stale === false
    && state.refreshing !== true
    && !state.refreshFailure
    && state.count === 0
    && Array.isArray(state.records)
    && state.records.length === 0
  );
}

function isCompleteVulnerableState(state) {
  return Boolean(
    state
    && state.status === "complete-vulnerable"
    && state.complete === true
    && state.stale === false
    && state.refreshing !== true
    && !state.refreshFailure
    && Number.isSafeInteger(state.count)
    && state.count > 0
    && Array.isArray(state.records)
    && state.records.length === state.count
  );
}

function vulnerabilityFixVersions(state) {
  if (!isCompleteVulnerableState(state)) return [];
  const seen = new Set();
  const versions = [];
  for (const record of state.records) {
    const raw = record && (record.fixed_version || record.fixVersion);
    const candidate = raw && typeof raw === "object" && !Array.isArray(raw)
      ? raw.version || raw.raw_version
      : raw;
    if (typeof candidate !== "string" && typeof candidate !== "number") continue;
    const version = String(candidate);
    if (
      version.length === 0
      || version.length > 2048
      || version.trim() !== version
      || /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u.test(version)
      || seen.has(version)
    ) continue;
    seen.add(version);
    versions.push(version);
  }
  return versions;
}

function isRejectedSafeVersionCandidate(pkg) {
  return String(pkg.status || "").trim().toLowerCase() === "quarantined"
    || pkg.policy.denyViolated === true;
}

function sameRemediationIdentity(source, candidate) {
  if (candidate.coordinateName !== source.coordinateName) return false;
  const format = String(source.format || "").trim().toLowerCase();
  if (format === "maven") {
    const sourceCoordinate = source.coordinateName.split(":");
    const candidateCoordinate = candidate.coordinateName.split(":");
    return sourceCoordinate.length === 2
      && candidateCoordinate.length === 2
      && sourceCoordinate.every(Boolean)
      && candidateCoordinate.every(Boolean)
      && (source.qualifiers.type || "jar") === (candidate.qualifiers.type || "jar")
      && (source.qualifiers.classifier || null) === (candidate.qualifiers.classifier || null);
  }
  if (format === "conda") {
    return typeof source.qualifiers.subdir === "string"
      && typeof candidate.qualifiers.subdir === "string"
      && source.qualifiers.subdir.length > 0
      && source.qualifiers.subdir === candidate.qualifiers.subdir;
  }
  if (format === "rpm") {
    return typeof source.qualifiers.architecture === "string"
      && typeof candidate.qualifiers.architecture === "string"
      && source.qualifiers.architecture.length > 0
      && source.qualifiers.architecture === candidate.qualifiers.architecture;
  }
  if (format === "ruby") {
    return (source.qualifiers.platform || "ruby") === (candidate.qualifiers.platform || "ruby");
  }
  return true;
}

function definitelyViolatesCompatibility(
  candidateVersion,
  currentVersion,
  fixedVersions,
  format
) {
  const compareVersions = String(format).trim().toLowerCase() === "npm"
    ? compareNpmSemver
    : compareSimpleNumericVersions;
  const currentComparison = compareVersions(candidateVersion, currentVersion);
  if (String(format).trim().toLowerCase() === "npm" && currentComparison === null) return true;
  if (currentComparison !== null && currentComparison <= 0) return true;
  return fixedVersions.some(fixedVersion => {
    const fixComparison = compareVersions(candidateVersion, fixedVersion);
    if (String(format).trim().toLowerCase() === "npm" && fixComparison === null) return true;
    return fixComparison !== null && fixComparison < 0;
  });
}

function compareNpmSemver(left, right) {
  const leftVersion = parseNpmSemver(left);
  const rightVersion = parseNpmSemver(right);
  if (!leftVersion || !rightVersion) return null;
  for (let index = 0; index < 3; index += 1) {
    const comparison = compareNumericVersionPart(
      leftVersion.core.at(index),
      rightVersion.core.at(index)
    );
    if (comparison !== 0) return comparison;
  }
  if (leftVersion.prerelease.length === 0 || rightVersion.prerelease.length === 0) {
    if (leftVersion.prerelease.length === rightVersion.prerelease.length) return 0;
    return leftVersion.prerelease.length === 0 ? 1 : -1;
  }
  const count = Math.max(leftVersion.prerelease.length, rightVersion.prerelease.length);
  for (let index = 0; index < count; index += 1) {
    const leftPart = leftVersion.prerelease.at(index);
    const rightPart = rightVersion.prerelease.at(index);
    if (leftPart === undefined || rightPart === undefined) {
      return leftPart === undefined ? -1 : 1;
    }
    const leftNumeric = /^\d+$/u.test(leftPart);
    const rightNumeric = /^\d+$/u.test(rightPart);
    if (leftNumeric && rightNumeric) {
      const comparison = compareNumericVersionPart(leftPart, rightPart);
      if (comparison !== 0) return comparison;
    } else if (leftNumeric !== rightNumeric) {
      return leftNumeric ? -1 : 1;
    } else if (leftPart !== rightPart) {
      return leftPart < rightPart ? -1 : 1;
    }
  }
  return 0;
}

function parseNpmSemver(value) {
  const normalized = typeof value === "string" || typeof value === "number"
    ? String(value)
    : "";
  const match = normalized.match(
    /^[vV]?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u
  );
  if (!match) return null;
  const prerelease = match[4] ? match[4].split(".") : [];
  if (prerelease.some(part => /^\d+$/u.test(part) && part.length > 1 && part.startsWith("0"))) {
    return null;
  }
  return { core: match.slice(1, 4), prerelease };
}

function compareNumericVersionPart(left, right) {
  const normalizedLeft = normalizedNumericPart(left);
  const normalizedRight = normalizedNumericPart(right);
  if (normalizedLeft.length !== normalizedRight.length) {
    return normalizedLeft.length < normalizedRight.length ? -1 : 1;
  }
  if (normalizedLeft === normalizedRight) return 0;
  return normalizedLeft < normalizedRight ? -1 : 1;
}

function compareSimpleNumericVersions(left, right) {
  const leftValue = typeof left === "string" || typeof left === "number" ? String(left) : "";
  const rightValue = typeof right === "string" || typeof right === "number" ? String(right) : "";
  const simpleNumericVersion = /^[vV]?\d+(?:\.\d+)*$/u;
  if (!simpleNumericVersion.test(leftValue) || !simpleNumericVersion.test(rightValue)) {
    return null;
  }
  const leftParts = leftValue.replace(/^[vV]/u, "").split(".");
  const rightParts = rightValue.replace(/^[vV]/u, "").split(".");
  const count = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < count; index += 1) {
    const leftPart = normalizedNumericPart(leftParts.at(index) || "0");
    const rightPart = normalizedNumericPart(rightParts.at(index) || "0");
    if (leftPart.length !== rightPart.length) {
      return leftPart.length < rightPart.length ? -1 : 1;
    }
    if (leftPart !== rightPart) return leftPart < rightPart ? -1 : 1;
  }
  return 0;
}

function normalizedNumericPart(value) {
  return value.replace(/^0+(?=\d)/u, "");
}

function reportedFixCopy(fixedVersions) {
  if (fixedVersions.length === 0) return "";
  if (fixedVersions.length === 1) return ` The reported fix is ${fixedVersions[0]}.`;
  const last = fixedVersions.at(-1);
  const prefix = fixedVersions.slice(0, -1).join(", ");
  return ` The reported fixes are ${prefix} and ${last}.`;
}

module.exports = { registerVulnerabilityCommands };

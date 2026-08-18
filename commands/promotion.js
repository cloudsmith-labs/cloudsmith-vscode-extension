// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { registerCommands } = require("./registrar");
const {
  adaptPackageSelection,
  captureCommandAccount,
  firstCollectionFailureMessage,
  pickRecentPackage,
  isCommandAccountCurrent,
  isQuarantinedPackage,
} = require("./support");

function registerPromotionCommands(deps) {
  const {
    registerCommand,
    vscode,
    packageAdapters,
    packageDomain,
    recentPackages,
    promotionProvider,
    normalizePackageQueryIdentity,
    cloudsmithProvider,
  } = deps;
  const recentSupport = { ...deps, recentPackages, packageAdapters, vscode };

  async function selectedPackage(item, accountScope, options = {}) {
    let pkg;
    if (item) {
      try {
        pkg = adaptPackageSelection(packageAdapters, item);
      } catch {
        vscode.window.showWarningMessage("Could not determine package details.");
        return null;
      }
      if (
        typeof deps.isCurrentPackageSelection !== "function"
        || !deps.isCurrentPackageSelection(item)
      ) return null;
    } else {
      pkg = await pickRecentPackage(recentSupport, {
        ...options,
        accountScope,
        currentSelection: candidate => deps.isCurrentPackageSelection?.(candidate) === true,
      });
    }
    if (!pkg && !item) return null;
    if (!isCommandAccountCurrent(accountScope)) return null;
    try {
      const exact = packageDomain.assertExactPackage(pkg);
      if (options.predicate && !options.predicate(exact)) {
        vscode.window.showWarningMessage(options.invalidStateMessage || "This package is not eligible for promotion.");
        return null;
      }
      return exact;
    } catch {
      vscode.window.showWarningMessage("Could not determine package details.");
      return null;
    }
  }

  async function showPromotionStatus(item) {
    const accountScope = captureCommandAccount(deps.workspaceAccess);
    if (!accountScope) return;
    const pkg = await selectedPackage(item, accountScope);
    if (!pkg) return;
    if (!isCommandAccountCurrent(accountScope)) return;
    recentPackages.add(pkg);
    let identity;
    try {
      identity = normalizePackageQueryIdentity(
        pkg.workspace,
        pkg.name,
        pkg.version,
        pkg.format
      );
    } catch {
      vscode.window.showWarningMessage("Could not determine package details.");
      return;
    }

    const pipeline = promotionProvider.getPipeline();
    if (pipeline.length > 0) {
      if (!isCommandAccountCurrent(accountScope)) return;
      const statusResult = await promotionProvider.getPromotionStatus(
        identity.workspace,
        identity.name,
        identity.version,
        identity.format
      );
      if (!isCommandAccountCurrent(accountScope)) return;
      if (statusResult.error) {
        vscode.window.showErrorMessage(
          `Could not load promotion status. ${deps.formatApiError(statusResult.error)}`
        );
        return;
      }
      if (statusResult.items.length === 0) {
        vscode.window.showInformationMessage("No pipeline repositories found.");
        return;
      }
      const lines = statusResult.items.map(status => {
        const icon = status.found === null
          ? "?"
          : !status.found
            ? "—"
            : (status.quarantined ? "❌" : (status.policyViolated ? "⚠️" : "✅"));
        return `${icon} ${status.repo}: ${status.status}`;
      });
      const completeness = statusResult.complete
        ? ""
        : " (package-location search incomplete)";
      const message = `Pipeline for ${identity.name} ${identity.version}: ${lines.join(" → ")}${completeness}`;
      if (statusResult.complete) {
        vscode.window.showInformationMessage(message);
      } else {
        vscode.window.showWarningMessage(message);
      }
      return;
    }

    if (!isCommandAccountCurrent(accountScope)) return;
    const results = await promotionProvider.getPackageLocations(
      identity.workspace,
      identity.name,
      identity.version,
      identity.format
    );
    if (!isCommandAccountCurrent(accountScope)) return;
    if (results.items.length === 0 && results.failureCount > 0 && results.pageCount === 0) {
      vscode.window.showErrorMessage(
        `Could not load package locations.${firstCollectionFailureMessage(results, deps.formatApiError)}`
      );
      return;
    }
    if (results.items.length === 0) {
      if (results.complete) {
        vscode.window.showInformationMessage(
          `${identity.name} ${identity.version} was not found in any other repository.`
        );
      } else {
        vscode.window.showWarningMessage(
          `Package locations are incomplete; ${identity.name} ${identity.version} may exist in another repository.`
        );
      }
      return;
    }
    let packages;
    try {
      packages = results.items.map(record => packageDomain.assertExactPackage(
        packageAdapters.fromApiPackageRecord(record)
      ));
    } catch {
      vscode.window.showErrorMessage("Could not safely interpret package locations.");
      return;
    }
    const lines = packages.map(location => {
      const icon = location.status === "Quarantined"
        ? "❌"
        : (location.policy.violated ? "⚠️" : "✅");
      return `${icon} ${location.repository}: ${location.status || "Unknown"}`;
    });
    const completeness = results.complete ? "" : " (additional locations may be unavailable)";
    const message = `${identity.name} ${identity.version} found in: ${lines.join(", ")}${completeness}`;
    if (results.complete) {
      vscode.window.showInformationMessage(message);
    } else {
      vscode.window.showWarningMessage(message);
    }
  }

  async function promotePackage(item) {
    const accountScope = captureCommandAccount(deps.workspaceAccess);
    if (!accountScope) return;
    const pkg = await selectedPackage(item, accountScope, {
      predicate: pkg => pkg.copyable === true && !isQuarantinedPackage(pkg),
      emptyMessage: "No recent promotable packages. Open or search for an eligible package, then try again.",
      invalidStateMessage: "This package is not eligible for promotion.",
    });
    if (!pkg) return;
    if (!isCommandAccountCurrent(accountScope)) return;
    await promotionProvider.runPromotionWorkflow(pkg, {
      refresh: () => cloudsmithProvider.refresh(),
    });
  }

  return registerCommands(registerCommand, [
    ["cloudsmith-vsc.showPromotionStatus", showPromotionStatus],
    ["cloudsmith-vsc.promotePackage", promotePackage],
  ], deps);
}

module.exports = { registerPromotionCommands };

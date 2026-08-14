// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { registerCommands } = require("./registrar");
const {
  adaptPackageSelection,
  firstCollectionFailureMessage,
  pickRecentPackage,
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
  const recentSupport = { recentPackages, packageAdapters, vscode };

  async function selectedPackage(item) {
    const pkg = item
      ? adaptPackageSelection(packageAdapters, item)
      : await pickRecentPackage(recentSupport);
    if (!pkg && !item) return null;
    try {
      return packageDomain.assertExactPackage(pkg);
    } catch {
      vscode.window.showWarningMessage("Could not determine package details.");
      return null;
    }
  }

  async function showPromotionStatus(item) {
    const pkg = await selectedPackage(item);
    if (!pkg) return;
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
      const statusResult = await promotionProvider.getPromotionStatus(
        identity.workspace,
        identity.name,
        identity.version,
        identity.format
      );
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
      vscode.window.showInformationMessage(
        `Pipeline for ${identity.name} ${identity.version}: ${lines.join(" → ")}${completeness}`
      );
      return;
    }

    const results = await promotionProvider.getPackageLocations(
      identity.workspace,
      identity.name,
      identity.version,
      identity.format
    );
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
    vscode.window.showInformationMessage(
      `${identity.name} ${identity.version} found in: ${lines.join(", ")}${completeness}`
    );
  }

  async function promotePackage(item) {
    const pkg = await selectedPackage(item);
    if (!pkg) return;
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

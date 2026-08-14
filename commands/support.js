// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const {
  firstCollectionFailureMessage,
  getWorkspaces,
  getWorkspaceRepositories,
} = require("../util/workspaceAccess");

function getDefaultWorkspace(vscode) {
  return vscode.workspace.getConfiguration("cloudsmith-vsc").get("defaultWorkspace") || "";
}

function captureCommandAccount(workspaceAccess) {
  if (
    !workspaceAccess
    || typeof workspaceAccess.captureAccount !== "function"
    || typeof workspaceAccess.isAccountCurrent !== "function"
  ) {
    return null;
  }
  const account = workspaceAccess.captureAccount(workspaceAccess.connectionManager);
  if (!account) return null;
  return Object.freeze({
    account,
    isCurrent: () => workspaceAccess.isAccountCurrent(
      workspaceAccess.connectionManager,
      account
    ),
  });
}

function collectionQuickPickItems(vscode, result, mapper, incompleteLabel) {
  const items = result.items.map(mapper);
  if (!result.complete) {
    items.unshift({
      label: incompleteLabel,
      kind: vscode.QuickPickItemKind.Separator,
    });
  }
  return items;
}

function adaptPackageSelection(packageAdapters, value) {
  try {
    return packageAdapters.fromPackageSelection(value);
  } catch {
    return null;
  }
}

function adaptRepositoryResolutionSelection(
  packageAdapters,
  packageDomain,
  value,
  options = {}
) {
  const adapted = packageAdapters.fromExactPackageSelectionIfPresent(value);
  const exactPackage = adapted ? packageDomain.assertExactPackage(adapted) : null;
  return Object.freeze({
    exactPackage,
    resolution: packageAdapters.fromPackageResolutionSelection(
      exactPackage || value,
      options
    ),
  });
}

function adaptInstallSelection(packageAdapters, packageDomain, value) {
  const adapted = packageAdapters.fromExactPackageSelectionIfPresent(value);
  if (adapted) {
    const exactPackage = packageDomain.assertExactPackage(adapted);
    return Object.freeze({ exactPackage, package: exactPackage });
  }
  const coordinate = packageAdapters.fromRepositoryPackageSelection(value, {
    defaultVersion: "latest",
  });
  return Object.freeze({ exactPackage: null, package: coordinate });
}

async function pickRecentPackage(deps, options = {}) {
  const predicate = typeof options.predicate === "function" ? options.predicate : () => true;
  const recent = deps.recentPackages.getAll().filter(predicate);
  if (recent.length === 0) {
    deps.vscode.window.showInformationMessage(
      options.emptyMessage || "No recent packages. Run this command from a package context menu."
    );
    return null;
  }
  const selected = await deps.vscode.window.showQuickPick(
    recent.map(pkg => ({
      label: pkg.name,
      description: `${pkg.version || ""} — ${pkg.repository || ""}`,
      package: pkg,
    })),
    { placeHolder: options.placeHolder || "Select a package" }
  );
  return selected ? selected.package : null;
}

function isQuarantinedPackage(pkg) {
  return Boolean(pkg) && pkg.status === "Quarantined";
}

function installOptions(vscode, pkg) {
  const options = {};
  if (pkg.tags && (pkg.tags.info.length > 0 || pkg.tags.version.length > 0)) {
    options.tags = pkg.tags;
  }
  if (
    vscode.workspace.getConfiguration("cloudsmith-vsc").get("showDockerDigestCommand", false)
  ) {
    if (pkg.checksumSha256) options.checksumSha256 = pkg.checksumSha256;
    if (pkg.versionDigest) options.versionDigest = pkg.versionDigest;
  }
  if (pkg.cdnUrl) options.cdnUrl = pkg.cdnUrl;
  if (pkg.filename) options.filename = pkg.filename;
  return options;
}

function buildInstallCommand(deps, pkg) {
  try {
    return deps.InstallCommandBuilder.build(
      pkg.format,
      pkg.name,
      pkg.version || "latest",
      pkg.workspace,
      pkg.repository,
      installOptions(deps.vscode, pkg)
    );
  } catch (error) {
    if (error instanceof deps.InstallCommandValidationError) {
      deps.vscode.window.showErrorMessage(
        `Could not safely generate install command: ${error.message}`
      );
      return null;
    }
    throw error;
  }
}

async function pickInstallCommandVariant(deps, result) {
  if (!result.alternatives || result.alternatives.length === 0) {
    return result.command;
  }
  const picks = [
    {
      label: "$(arrow-right) Primary",
      description: deps.InstallCommandBuilder.toClipboardCommand(result.command),
      command: result.command,
    },
    ...result.alternatives.map(alternative => ({
      label: `$(arrow-right) ${alternative.label}`,
      description: deps.InstallCommandBuilder.toClipboardCommand(alternative.command),
      command: alternative.command,
    })),
  ];
  const selected = await deps.vscode.window.showQuickPick(picks, {
    placeHolder: "Select an install command",
  });
  return selected ? selected.command : null;
}

function commentCommandNote(note) {
  return String(note)
    .split(/\r?\n/)
    .map(line => `# ${line}`)
    .join("\n");
}

function buildRawSearchQuery(SearchQueryBuilder, query) {
  return new SearchQueryBuilder().raw(query).build();
}

function buildPresetQuery(SearchQueryBuilder, preset, customQuery) {
  if (!preset) return "";
  if (preset.applyBuilder === null) {
    return buildRawSearchQuery(SearchQueryBuilder, customQuery || "");
  }
  const builder = new SearchQueryBuilder();
  const maybeString = preset.applyBuilder(builder);
  return typeof maybeString === "string" ? maybeString : builder.build();
}

function createFilterPresets(LicenseClassifier) {
  return Object.freeze([
    { label: "All packages", applyBuilder: () => "" },
    {
      label: "Available packages",
      applyBuilder: builder => builder
        .raw("NOT status:quarantined")
        .raw("deny_policy_violated:false"),
    },
    { label: "Quarantined packages", applyBuilder: builder => builder.status("quarantined") },
    {
      label: "Packages with policy violations",
      applyBuilder: builder => builder.raw("policy_violated:true"),
    },
    {
      label: "$(shield) Vulnerable packages",
      description: "Packages with known vulnerabilities",
      applyBuilder: builder => builder.raw("vulnerabilities:>0"),
    },
    {
      label: "Packages with vulnerability violations",
      applyBuilder: builder => builder.raw("vulnerability_policy_violated:true"),
    },
    {
      label: "Packages with license violations",
      applyBuilder: builder => builder.raw("license_policy_violated:true"),
    },
    {
      label: "Packages with restrictive licenses",
      applyBuilder: builder => builder.raw(LicenseClassifier.buildRestrictiveQuery()),
    },
    { label: "Custom query", applyBuilder: null },
  ]);
}

module.exports = {
  adaptInstallSelection,
  adaptPackageSelection,
  adaptRepositoryResolutionSelection,
  buildInstallCommand,
  buildPresetQuery,
  buildRawSearchQuery,
  captureCommandAccount,
  collectionQuickPickItems,
  commentCommandNote,
  createFilterPresets,
  firstCollectionFailureMessage,
  getDefaultWorkspace,
  getWorkspaces,
  getWorkspaceRepositories,
  isQuarantinedPackage,
  pickInstallCommandVariant,
  pickRecentPackage,
};

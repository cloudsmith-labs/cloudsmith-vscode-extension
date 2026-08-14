// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { LicenseClassifier } = require("./licenseClassifier");
const { getFoundDependencyKey } = require("./foundDependencyKey");

function toLicenseClassification(tier) {
  switch (tier) {
    case "permissive":
      return "permissive";
    case "cautious":
      return "weak_copyleft";
    case "restrictive":
      return "restrictive";
    default:
      return "unknown";
  }
}

function buildLicensePatch(dependencies) {
  const patchMap = new Map();

  for (const dependency of Array.isArray(dependencies) ? dependencies : []) {
    if (dependency.cloudsmithStatus !== "FOUND" || !dependency.cloudsmithPackage) {
      continue;
    }

    const key = getFoundDependencyKey(dependency);
    if (!key || patchMap.has(key)) {
      continue;
    }

    const pkg = dependency.cloudsmithPackage;
    const canonicalLicense = pkg.license.spdx || pkg.license.declared || pkg.license.raw;
    const inspection = LicenseClassifier.inspect(canonicalLicense);
    const spdx = pkg.license.spdx
      || inspection.spdxLicense
      || inspection.canonicalValue
      || inspection.displayValue
      || null;

    patchMap.set(key, {
      spdx,
      display: pkg.license.declared || inspection.displayValue || spdx || null,
      url: pkg.license.url || inspection.licenseUrl || null,
      classification: toLicenseClassification(inspection.tier),
      classifierTier: inspection.tier,
      raw: pkg.license.raw || inspection.rawLicense || inspection.raw || null,
      overrideApplied: Boolean(inspection.overrideApplied),
    });
  }

  return patchMap;
}

function throwIfCancelled(cancellationToken) {
  if (cancellationToken && cancellationToken.isCancellationRequested) {
    const error = new Error("Dependency license enrichment was cancelled.");
    error.code = "ERR_DEPENDENCY_ENRICHMENT_CANCELLED";
    throw error;
  }
}

function applyLicensePatch(dependencies, patchMap) {
  return (Array.isArray(dependencies) ? dependencies : []).map((dependency) => {
    const key = getFoundDependencyKey(dependency);
    if (!key || !patchMap.has(key)) {
      return dependency;
    }

    return {
      ...dependency,
      license: patchMap.get(key),
    };
  });
}

async function enrichLicenses(dependencies, options = {}) {
  const onProgress = typeof options.onProgress === "function" ? options.onProgress : null;
  throwIfCancelled(options.cancellationToken);
  const patchMap = buildLicensePatch(dependencies);
  throwIfCancelled(options.cancellationToken);

  if (onProgress && patchMap.size > 0) {
    onProgress(new Map(patchMap), { stage: "licenses" });
  }

  throwIfCancelled(options.cancellationToken);
  return applyLicensePatch(dependencies, patchMap);
}

module.exports = {
  enrichLicenses,
};

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

    const inspection = LicenseClassifier.inspect(dependency.cloudsmithPackage);
    const spdx = inspection.spdxLicense || inspection.canonicalValue || inspection.displayValue || null;

    patchMap.set(key, {
      spdx,
      display: inspection.displayValue || spdx || null,
      url: inspection.licenseUrl || null,
      classification: toLicenseClassification(inspection.tier),
      classifierTier: inspection.tier,
      raw: inspection.rawLicense || inspection.raw || null,
      overrideApplied: Boolean(inspection.overrideApplied),
    });
  }

  return patchMap;
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
  const patchMap = buildLicensePatch(dependencies);

  if (onProgress && patchMap.size > 0) {
    onProgress(new Map(patchMap), { stage: "licenses" });
  }

  return applyLicensePatch(dependencies, patchMap);
}

module.exports = {
  enrichLicenses,
};

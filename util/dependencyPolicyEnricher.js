// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { getFoundDependencyKey } = require("./foundDependencyKey");

function buildPolicyPatch(dependencies) {
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
    const status = String(pkg.status_str || "").trim() || null;
    const quarantined = status === "Quarantined";
    const denied = quarantined || Boolean(pkg.deny_policy_violated);
    const violated = denied
      || Boolean(pkg.policy_violated)
      || Boolean(pkg.license_policy_violated)
      || Boolean(pkg.vulnerability_policy_violated);

    patchMap.set(key, {
      violated,
      denied,
      quarantined,
      status,
      statusReason: String(pkg.status_reason || "").trim() || null,
      vulnerabilityViolated: Boolean(pkg.vulnerability_policy_violated),
      licenseViolated: Boolean(pkg.license_policy_violated),
    });
  }

  return patchMap;
}

function applyPolicyPatch(dependencies, patchMap) {
  return (Array.isArray(dependencies) ? dependencies : []).map((dependency) => {
    const key = getFoundDependencyKey(dependency);
    if (!key || !patchMap.has(key)) {
      return dependency;
    }

    return {
      ...dependency,
      policy: patchMap.get(key),
    };
  });
}

async function enrichPolicies(dependencies, options = {}) {
  const onProgress = typeof options.onProgress === "function" ? options.onProgress : null;
  const patchMap = buildPolicyPatch(dependencies);

  if (onProgress && patchMap.size > 0) {
    onProgress(new Map(patchMap), { stage: "policy" });
  }

  return applyPolicyPatch(dependencies, patchMap);
}

module.exports = {
  enrichPolicies,
};

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
    const status = pkg.status;
    const quarantined = status === "Quarantined";
    const denied = quarantined || pkg.policy.denyViolated;
    const violated = denied
      || pkg.policy.violated
      || pkg.policy.licenseViolated
      || pkg.policy.vulnerabilityViolated;

    patchMap.set(key, {
      violated,
      denied,
      quarantined,
      status,
      statusReason: pkg.statusReason,
      vulnerabilityViolated: pkg.policy.vulnerabilityViolated,
      licenseViolated: pkg.policy.licenseViolated,
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

function throwIfCancelled(cancellationToken) {
  if (cancellationToken && cancellationToken.isCancellationRequested) {
    const error = new Error("Dependency policy enrichment was cancelled.");
    error.code = "ERR_DEPENDENCY_ENRICHMENT_CANCELLED";
    throw error;
  }
}

async function enrichPolicies(dependencies, options = {}) {
  const onProgress = typeof options.onProgress === "function" ? options.onProgress : null;
  throwIfCancelled(options.cancellationToken);
  const patchMap = buildPolicyPatch(dependencies);
  throwIfCancelled(options.cancellationToken);

  if (onProgress && patchMap.size > 0) {
    onProgress(new Map(patchMap), { stage: "policy" });
  }

  throwIfCancelled(options.cancellationToken);
  return applyPolicyPatch(dependencies, patchMap);
}

module.exports = {
  enrichPolicies,
};

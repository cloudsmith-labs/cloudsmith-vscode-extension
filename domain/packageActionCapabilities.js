// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const PACKAGE_ACTIONS = Object.freeze({
  INSPECT: "inspect",
  OPEN: "open",
  FIND_SAFE_VERSION: "findSafeVersion",
  SHOW_VULNERABILITIES: "showVulnerabilities",
  EXPLAIN_QUARANTINE: "explainQuarantine",
  INSTALL: "install",
  PROMOTE: "promote",
  SHOW_PROMOTION_STATUS: "showPromotionStatus",
});

const PACKAGE_ACTION_ORDER = Object.freeze([
  PACKAGE_ACTIONS.INSPECT,
  PACKAGE_ACTIONS.OPEN,
  PACKAGE_ACTIONS.FIND_SAFE_VERSION,
  PACKAGE_ACTIONS.SHOW_VULNERABILITIES,
  PACKAGE_ACTIONS.EXPLAIN_QUARANTINE,
  PACKAGE_ACTIONS.INSTALL,
  PACKAGE_ACTIONS.PROMOTE,
  PACKAGE_ACTIONS.SHOW_PROMOTION_STATUS,
]);

const PACKAGE_ACTION_SURFACES = Object.freeze({
  PACKAGE: "package",
  DEPENDENCY_HEALTH: "dependency-health",
});

const PACKAGE_ACTION_CONTEXT_FAMILIES = Object.freeze({
  PACKAGE: "packageActions",
  DEPENDENCY_HEALTH: "dependencyHealthActions",
});

function strictEvidence(value) {
  return value === true;
}

function ownDataValue(value, key) {
  if ((typeof value !== "object" || value === null) && typeof value !== "function") {
    return undefined;
  }
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && Object.prototype.hasOwnProperty.call(descriptor, "value")
      ? descriptor.value
      : undefined;
  } catch {
    return undefined;
  }
}

function noActions() {
  return Object.freeze(Object.fromEntries(
    PACKAGE_ACTION_ORDER.map(action => [action, false])
  ));
}

function derivePackageActionCapabilities(input = {}) {
  const surface = ownDataValue(input, "surface");
  const evidence = Object.freeze({
    copyable: strictEvidence(ownDataValue(input, "copyable")),
    exact: strictEvidence(ownDataValue(input, "exact")),
    found: strictEvidence(ownDataValue(input, "found")),
    installGuidance: strictEvidence(ownDataValue(input, "installGuidance")),
    policyViolation: strictEvidence(ownDataValue(input, "policyViolation")),
    quarantined: strictEvidence(ownDataValue(input, "quarantined")),
    restrictiveLicense: strictEvidence(ownDataValue(input, "restrictiveLicense")),
    vulnerable: strictEvidence(ownDataValue(input, "vulnerable")),
  });
  const validSurface = Object.values(PACKAGE_ACTION_SURFACES).includes(surface);
  if (!validSurface || !evidence.found || !evidence.exact) {
    return Object.freeze({ actions: noActions(), evidence, surface: null });
  }

  const packageSurface = surface === PACKAGE_ACTION_SURFACES.PACKAGE;
  const vulnerabilityActions = packageSurface || evidence.vulnerable;
  const safeToDistribute = evidence.copyable && !evidence.quarantined;
  const installable = safeToDistribute && evidence.installGuidance;
  const actions = Object.freeze({
    [PACKAGE_ACTIONS.INSPECT]: true,
    [PACKAGE_ACTIONS.OPEN]: true,
    [PACKAGE_ACTIONS.FIND_SAFE_VERSION]: vulnerabilityActions,
    [PACKAGE_ACTIONS.SHOW_VULNERABILITIES]: vulnerabilityActions,
    [PACKAGE_ACTIONS.EXPLAIN_QUARANTINE]: evidence.quarantined,
    [PACKAGE_ACTIONS.INSTALL]: installable,
    [PACKAGE_ACTIONS.PROMOTE]: packageSurface && safeToDistribute,
    [PACKAGE_ACTIONS.SHOW_PROMOTION_STATUS]: packageSurface,
  });
  return Object.freeze({ actions, evidence, surface });
}

function hasPackageAction(capabilities, action) {
  const actions = ownDataValue(capabilities, "actions");
  if (!actions) return false;
  switch (action) {
    case PACKAGE_ACTIONS.INSPECT: return ownDataValue(actions, "inspect") === true;
    case PACKAGE_ACTIONS.OPEN: return ownDataValue(actions, "open") === true;
    case PACKAGE_ACTIONS.FIND_SAFE_VERSION: return ownDataValue(actions, "findSafeVersion") === true;
    case PACKAGE_ACTIONS.SHOW_VULNERABILITIES: return ownDataValue(actions, "showVulnerabilities") === true;
    case PACKAGE_ACTIONS.EXPLAIN_QUARANTINE: return ownDataValue(actions, "explainQuarantine") === true;
    case PACKAGE_ACTIONS.INSTALL: return ownDataValue(actions, "install") === true;
    case PACKAGE_ACTIONS.PROMOTE: return ownDataValue(actions, "promote") === true;
    case PACKAGE_ACTIONS.SHOW_PROMOTION_STATUS: return ownDataValue(actions, "showPromotionStatus") === true;
    default: return false;
  }
}

function encodePackageActionContext(family, capabilities) {
  if (!Object.values(PACKAGE_ACTION_CONTEXT_FAMILIES).includes(family)) return null;
  const actions = PACKAGE_ACTION_ORDER.filter(action => (
    hasPackageAction(capabilities, action)
  ));
  const contextValue = [family, ...actions].join(".");
  return contextValue.length <= 256 ? contextValue : null;
}

module.exports = {
  PACKAGE_ACTION_CONTEXT_FAMILIES,
  PACKAGE_ACTION_SURFACES,
  PACKAGE_ACTIONS,
  derivePackageActionCapabilities,
  encodePackageActionContext,
  hasPackageAction,
};

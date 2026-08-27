const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const isolatedQualificationRoots = new Map();
const QUALIFICATION_ROOT_TRANSFER_MARKER = ".cloudsmith-quality-root-owner";

const STANDALONE_NODE_TESTS = Object.freeze([
  "test/accountOperation.test.js",
  "test/apiEndpoint.test.js",
  "test/architectureGate.test.js",
  "test/authBootstrap.test.js",
  "test/authCapabilities.test.js",
  "test/candidateBinding.test.js",
  "test/commandFreshness.test.js",
  "test/commandRecovery.test.js",
  "test/commandUxOracle.test.js",
  "test/collectionIdentity.test.js",
  "test/connectionPresentation.test.js",
  "test/credentialEnvelope.test.js",
  "test/credentialMutationLock.test.js",
  "test/dependencyAdapterRegistry.test.js",
  "test/dependencyManifestDiscovery.test.js",
  "test/dependencyPolicyEnricher.test.js",
  "test/dependencyRecord.test.js",
  "test/externalNavigation.test.js",
  "test/foundDependencyKey.test.js",
  "test/formatIconInventory.test.js",
  "test/installCommandBuilder.test.js",
  "test/installGuidanceSupport.test.js",
  "test/manifestParser.test.js",
  "test/packageDomain.test.js",
  "test/packageActionCapabilities.test.js",
  "test/packageQuery.test.js",
  "test/packageVulnerabilities.test.js",
  "test/vulnerabilityStateService.test.js",
  "test/vulnerabilityReportProjection.test.js",
  "test/paginatedFetch.test.js",
  "test/policyDecisionLogs.test.js",
  "test/polishGate.test.js",
  "test/processTree.test.js",
  "test/promotionContracts.test.js",
  "test/qualityHarness.test.js",
  "test/qualificationProfile.test.js",
  "test/releaseChecklistTrust.test.js",
  "test/recentPackages.test.js",
  "test/registryEndpoints.test.js",
  "test/releaseGate.test.js",
  "test/remediationHelper.test.js",
  "test/reportReadinessModel.test.js",
  "test/runtimeProcessGuard.test.js",
  "test/searchQueryBuilder.test.js",
  "test/secretScan.test.js",
  "test/ssoDiagnostics.test.js",
  "test/ssoProtocolClient.test.js",
  "test/testHelpers.test.js",
  "test/testInventories.test.js",
  "test/uiSmokeRunner.test.js",
  "test/upstreamFormats.test.js",
  "test/upstreamOperationScheduler.test.js",
  "test/upstreamPresentation.test.js",
  "test/webAppUrls.test.js",
  "test/webviewMessage.test.js",
  "test/webviewSemanticContract.test.js",
  "test/workspaceCache.test.js",
  "test/lockfileParsers/cargoParser.test.js",
  "test/lockfileParsers/composerParser.test.js",
  "test/lockfileParsers/dockerParser.test.js",
  "test/lockfileParsers/dartParser.test.js",
  "test/lockfileParsers/goParser.test.js",
  "test/lockfileParsers/gradleParser.test.js",
  "test/lockfileParsers/hexParser.test.js",
  "test/lockfileParsers/helmParser.test.js",
  "test/lockfileParsers/mavenParser.test.js",
  "test/lockfileParsers/npmParser.test.js",
  "test/lockfileParsers/nugetParser.test.js",
  "test/lockfileParsers/pythonParser.test.js",
  "test/lockfileParsers/rubyParser.test.js",
  "test/lockfileParsers/shared.test.js",
  "test/lockfileParsers/swiftParser.test.js",
  "test/integration/installCommand.test.js",
  "test/integration/manifestParser.test.js",
]);

const VSCODE_CORE_TESTS = Object.freeze([
  "test/authSessionManager.test.js",
  "test/cloudsmithAPI.test.js",
  "test/cloudsmithProvider.test.js",
  "test/commandRegistrars.test.js",
  "test/complianceReportProvider.test.js",
  "test/connectionManager.test.js",
  "test/contextKeyProjector.test.js",
  "test/credentialManager.test.js",
  "test/dependencyCommandState.test.js",
  "test/dependencyHealthProvider.test.js",
  "test/dependencyLicenseEnricher.test.js",
  "test/dependencyVulnEnricher.test.js",
  "test/diagnosticsPublisher.test.js",
  "test/extension.test.js",
  "test/formatIcons.test.js",
  "test/licenseClassifier.test.js",
  "test/lockfileResolver.test.js",
  "test/packageMetadataFlow.test.js",
  "test/promotionProvider.test.js",
  "test/quarantineExplainProvider.test.js",
  "test/recentSearches.test.js",
  "test/repositoryNode.test.js",
  "test/searchIntent.test.js",
  "test/searchProvider.test.js",
  "test/ssoAuthManager.test.js",
  "test/terraformExporter.test.js",
  "test/treeVisualization.test.js",
  "test/upstreamChecker.test.js",
  "test/upstreamRuntime.test.js",
  "test/upstreamGapAnalyzer.test.js",
  "test/upstreamDetailProvider.test.js",
  "test/upstreamPreviewProvider.test.js",
  "test/upstreamPullService.test.js",
  "test/vulnerabilityProvider.test.js",
  "test/vulnerabilitySummaryNode.test.js",
  "test/webviewPackageActionFlow.test.js",
  "test/workspaceNode.test.js",
  "test/workspaceFetcher.test.js",
  "test/workspaceRepositoryFetcher.test.js",
  "test/integration/licenseClassifier.test.js",
]);

const VSCODE_SMOKE_TESTS = Object.freeze([
  "test/activation.test.js",
]);

const CREDENTIAL_BOUNDARY_EXCLUDED_TESTS = Object.freeze([
  "test/integration/policyDecisionLogs.test.js",
  "test/integration/search.test.js",
  "test/integration/upstreams.test.js",
  "test/integration/vulnerabilities.test.js",
  "test/integration/ssoAuthentication.test.js",
]);

const CREDENTIAL_BOUNDARY_SKIP_REASON = "General credential-bearing live suites are excluded from deterministic qualification; authenticated acceptance uses only the dedicated pre-authenticated local profile or the reviewed step-scoped ephemeral CI handoff/bootstrap lane, with value-blind evidence.";
const CREDENTIAL_LIKE_ENVIRONMENT = /(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSCODE|MFA|CREDENTIAL|KEYCHAIN|ONEPASSWORD|1PASSWORD|PRIVATE_?KEY|ACCESS_?KEY|REFRESH_?TOKEN)/iu;
const QUALIFICATION_ENVIRONMENT_ALLOWLIST = Object.freeze([
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "WINDIR",
  "COMSPEC",
  "PROCESSOR_ARCHITECTURE",
  "NUMBER_OF_PROCESSORS",
  "LANG",
  "LC_ALL",
  "LC_COLLATE",
  "LC_CTYPE",
  "LC_MESSAGES",
  "LC_MONETARY",
  "LC_NUMERIC",
  "LC_TIME",
  "TERM",
  "COLORTERM",
  "FORCE_COLOR",
  "NO_COLOR",
  "CI",
  "GITHUB_ACTIONS",
  "RUNNER_OS",
  "RUNNER_ARCH",
  "DISPLAY",
  "WAYLAND_DISPLAY",
  "XAUTHORITY",
  "DBUS_SESSION_BUS_ADDRESS",
  "TMPDIR",
  "TMP",
  "TEMP",
  "USER",
  "LOGNAME",
  "USERNAME",
  "SHELL",
  "VSCODE_TEST_VERSION",
  "VSCODE_TEST_LABEL",
  "CLOUDSMITH_QUALITY_TEST_EVIDENCE",
  "CLOUDSMITH_QUALITY_SOURCE_SHA",
  "CLOUDSMITH_QUALITY_SOURCE_FINGERPRINT",
  "CLOUDSMITH_QUALITY_TEST_SUITE",
]);

function assertCredentialFreeRequiredEnvironment(names) {
  if (!Array.isArray(names)) {
    throw new TypeError("Qualification required environment must be an array.");
  }
  for (const name of names) {
    if (typeof name !== "string"
      || !/^[A-Z][A-Z0-9_]{0,127}$/u.test(name)
      || CREDENTIAL_LIKE_ENVIRONMENT.test(name)) {
      throw new Error(`Qualification cannot require credential-like environment input: ${String(name)}`);
    }
  }
  return names;
}

function sanitizeQualificationEnvironment(environment, isolatedHome, options = {}) {
  if (!environment || typeof environment !== "object" || Array.isArray(environment)) {
    throw new TypeError("Qualification environment must be an object.");
  }
  if (typeof isolatedHome !== "string" || !isolatedHome || !path.isAbsolute(isolatedHome)) {
    throw new Error("Qualification isolated home must be an absolute path.");
  }
  const platform = options.platform || process.platform;
  const sourceEntries = Object.entries(environment);
  const readAllowedValue = expectedName => {
    if (platform !== "win32") {
      return Object.prototype.hasOwnProperty.call(environment, expectedName)
        ? environment[expectedName]
        : undefined;
    }
    const matching = sourceEntries.filter(([name]) => name.toUpperCase() === expectedName);
    if (matching.length > 1) {
      throw new Error(`Qualification environment has a case-colliding key: ${expectedName}`);
    }
    return matching[0]?.[1];
  };
  const sanitized = {};
  for (const name of QUALIFICATION_ENVIRONMENT_ALLOWLIST) {
    const value = readAllowedValue(name);
    if (typeof value === "string" && value.length <= 32768 && !value.includes("\u0000")) {
      sanitized[name] = value;
    }
  }
  Object.assign(sanitized, {
    HOME: isolatedHome,
    USERPROFILE: isolatedHome,
    XDG_CONFIG_HOME: path.join(isolatedHome, ".config"),
    XDG_CACHE_HOME: path.join(isolatedHome, ".cache"),
    XDG_DATA_HOME: path.join(isolatedHome, ".local", "share"),
    XDG_STATE_HOME: path.join(isolatedHome, ".local", "state"),
    APPDATA: path.join(isolatedHome, "AppData", "Roaming"),
    LOCALAPPDATA: path.join(isolatedHome, "AppData", "Local"),
  });
  return Object.freeze(sanitized);
}

function createIsolatedQualificationRoot(label, temporaryParent = os.tmpdir()) {
  if (!new Set(["core", "smoke"]).has(label)) {
    throw new Error("Qualification host label must be core or smoke.");
  }
  if (typeof temporaryParent !== "string" || !path.isAbsolute(temporaryParent)) {
    throw new Error("Qualification temporary parent must be an absolute path.");
  }
  const parent = fs.realpathSync(temporaryParent);
  const parentStat = fs.lstatSync(parent);
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) {
    throw new Error("Qualification temporary parent must resolve to a real directory.");
  }

  const runRoot = fs.mkdtempSync(path.join(
    parent,
    `csv-${label === "core" ? "c" : "s"}-`
  ));
  try {
    fs.chmodSync(runRoot, 0o700);
    const stat = fs.lstatSync(runRoot);
    if (!stat.isDirectory() || stat.isSymbolicLink()
      || (process.platform !== "win32" && (stat.mode & 0o077) !== 0)) {
      throw new Error("Qualification host root must be a private real directory.");
    }
    isolatedQualificationRoots.set(runRoot, Object.freeze({
      device: stat.dev,
      inode: stat.ino,
      parent,
    }));
    return runRoot;
  } catch (error) {
    fs.rmSync(runRoot, { force: true, recursive: true });
    throw error;
  }
}

function exportIsolatedQualificationRoot(runRoot) {
  const resolved = typeof runRoot === "string" ? path.resolve(runRoot) : "";
  const identity = isolatedQualificationRoots.get(resolved);
  if (!identity || path.dirname(resolved) !== identity.parent) {
    throw new Error("Qualification transfer refuses a directory it did not create.");
  }
  const stat = fs.lstatSync(resolved);
  if (!stat.isDirectory() || stat.isSymbolicLink()
    || stat.dev !== identity.device || stat.ino !== identity.inode) {
    throw new Error("Qualification transfer refuses a replaced host root.");
  }
  const proof = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(
    path.join(resolved, QUALIFICATION_ROOT_TRANSFER_MARKER),
    `${proof}\n`,
    { encoding: "utf8", flag: "wx", mode: 0o600 }
  );
  return proof;
}

function adoptIsolatedQualificationRoot(runRoot, proof, label, temporaryParent = os.tmpdir()) {
  if (!new Set(["core", "smoke"]).has(label)) {
    throw new Error("Qualification transfer label must be core or smoke.");
  }
  if (typeof runRoot !== "string" || !path.isAbsolute(runRoot)
    || !/^[a-f0-9]{64}$/u.test(proof || "")) {
    throw new Error("Qualification transfer requires an absolute root and exact ownership proof.");
  }
  const parent = fs.realpathSync(temporaryParent);
  const resolved = path.resolve(runRoot);
  const expectedName = new RegExp(
    `^csv-${label === "core" ? "c" : "s"}-[A-Za-z0-9]{6}$`,
    "u"
  );
  if (path.dirname(resolved) !== parent
    || !expectedName.test(path.basename(resolved))
    || isolatedQualificationRoots.has(resolved)) {
    throw new Error("Qualification transfer root is outside its exact temporary namespace.");
  }
  const stat = fs.lstatSync(resolved);
  if (!stat.isDirectory() || stat.isSymbolicLink()
    || (process.platform !== "win32" && (stat.mode & 0o077) !== 0)) {
    throw new Error("Qualification transfer root must be a private real directory.");
  }
  const marker = path.join(resolved, QUALIFICATION_ROOT_TRANSFER_MARKER);
  const markerStat = fs.lstatSync(marker);
  if (!markerStat.isFile() || markerStat.isSymbolicLink()
    || markerStat.size !== 65
    || (process.platform !== "win32" && (markerStat.mode & 0o077) !== 0)
    || fs.readFileSync(marker, "utf8") !== `${proof}\n`) {
    throw new Error("Qualification transfer ownership proof does not match.");
  }
  fs.unlinkSync(marker);
  isolatedQualificationRoots.set(resolved, Object.freeze({
    device: stat.dev,
    inode: stat.ino,
    parent,
  }));
  return resolved;
}

function removeIsolatedQualificationRoot(runRoot) {
  const resolved = typeof runRoot === "string" ? path.resolve(runRoot) : "";
  const identity = isolatedQualificationRoots.get(resolved);
  if (!identity || path.dirname(resolved) !== identity.parent) {
    throw new Error("Qualification cleanup refuses a directory it did not create.");
  }
  if (!fs.existsSync(resolved)) {
    isolatedQualificationRoots.delete(resolved);
    return;
  }
  const stat = fs.lstatSync(resolved);
  if (!stat.isDirectory() || stat.isSymbolicLink()
    || stat.dev !== identity.device || stat.ino !== identity.inode) {
    throw new Error("Qualification cleanup refuses a replaced host root.");
  }
  fs.rmSync(resolved, { force: true, maxRetries: 3, recursive: true });
  isolatedQualificationRoots.delete(resolved);
}

const QUALIFICATION_REQUIRED_ENV = Object.freeze(
  assertCredentialFreeRequiredEnvironment([])
);

module.exports = {
  CREDENTIAL_BOUNDARY_EXCLUDED_TESTS,
  CREDENTIAL_BOUNDARY_SKIP_REASON,
  QUALIFICATION_REQUIRED_ENV,
  STANDALONE_NODE_TESTS,
  VSCODE_CORE_TESTS,
  VSCODE_SMOKE_TESTS,
  assertCredentialFreeRequiredEnvironment,
  adoptIsolatedQualificationRoot,
  createIsolatedQualificationRoot,
  exportIsolatedQualificationRoot,
  removeIsolatedQualificationRoot,
  sanitizeQualificationEnvironment,
};

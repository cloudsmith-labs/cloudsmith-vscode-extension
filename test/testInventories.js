const STANDALONE_NODE_TESTS = Object.freeze([
  "test/accountOperation.test.js",
  "test/apiEndpoint.test.js",
  "test/architectureGate.test.js",
  "test/authCapabilities.test.js",
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
  "test/promotionContracts.test.js",
  "test/qualityHarness.test.js",
  "test/releaseChecklistTrust.test.js",
  "test/recentPackages.test.js",
  "test/registryEndpoints.test.js",
  "test/releaseGate.test.js",
  "test/remediationHelper.test.js",
  "test/runtimeProcessGuard.test.js",
  "test/searchQueryBuilder.test.js",
  "test/ssoDiagnostics.test.js",
  "test/ssoProtocolClient.test.js",
  "test/testHelpers.test.js",
  "test/testInventories.test.js",
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

const CREDENTIAL_BOUNDARY_SKIP_REASON = "Credential-bearing automated live suites are excluded from qualification; live acceptance may use only an existing authenticated session and sanitized evidence.";
const CREDENTIAL_LIKE_ENVIRONMENT = /(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSCODE|MFA|CREDENTIAL|KEYCHAIN|ONEPASSWORD|1PASSWORD|PRIVATE_?KEY|ACCESS_?KEY|REFRESH_?TOKEN)/iu;

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
};

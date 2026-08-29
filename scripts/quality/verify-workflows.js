// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const fs = require("fs");
const path = require("path");
const { isDeepStrictEqual } = require("util");
const yaml = require("js-yaml");
const {
  AUTOMATED_LAYERS,
  ROOT,
  gitVisibleFiles,
  isPlainObject,
  matchesPattern,
  readJson,
  requireNonEmptyString,
  resolveGitVisibleRegularFile,
  testSourceContains,
  stripJavaScriptComments,
  uniqueSorted,
} = require("./common");
const { validateMutationBaseline } = require("./mutation-baseline");

const REQUIRED_FAILURE_CLASSES = [
  "contract-mismatch",
  "provenance",
  "canonical-identity",
  "async-authority",
  "stale-publication",
  "terminal-state",
  "pagination",
  "boundedness",
  "error-normalization",
  "validation/security",
  "auth-capability",
  "cross-surface-parity",
  "capability-composition",
  "format-native-semantics",
  "false-green-test",
  "accessibility",
  "documentation-drift",
];

const EXPECTED_QUALITY_SCRIPT_ENTRYPOINTS = Object.freeze({
  "audit:dev": "node scripts/release/verify-dependency-audit.js development",
  "audit:runtime": "node scripts/release/verify-dependency-audit.js runtime",
  build: "node scripts/verify-build.js",
  check: "npm run lint && npm run syntax && npm run build"
    + " && npm run verify:architecture && npm run verify:polish && npm run verify:version",
  lint: "eslint . --max-warnings 0",
  package: "node scripts/release/package-vsix.js",
  "package:list":
    "node scripts/release/verify-vsix.js --require-sidecars --current-source --list",
  "package:verify": "node scripts/release/verify-vsix.js --require-sidecars --current-source",
  pretest: "npm run lint",
  "quality:fast": "node scripts/quality/gate.js fast",
  "quality:full": "node scripts/quality/gate.js full",
  "quality:remote-ci:collect": "node scripts/quality/collect-remote-ci.js",
  "quality:qualification:launch": "node scripts/quality/prepare-qualification.js --launch",
  "quality:qualification:prepare": "node scripts/quality/prepare-qualification.js",
  "quality:qualification:prepare-authenticated-ci":
    "node scripts/quality/authenticated-candidate-session.js prepare",
  "quality:qualification:reset": "node scripts/quality/reset-qualification-profile.js",
  "quality:release": "node scripts/quality/gate.js release",
  "quality:secrets:artifacts": "node scripts/quality/secret-scan.js artifacts",
  "quality:secrets:evidence": "node scripts/quality/secret-scan.js evidence",
  "quality:secrets:history": "node scripts/quality/secret-scan.js history",
  "quality:secrets:signed-out-evidence":
    "node scripts/quality/secret-scan.js evidence --signed-out-bundle",
  "quality:verify-authenticated-evidence":
    "node scripts/quality/verify-authenticated-evidence.js",
  "quality:verify-evidence": "node scripts/quality/verify-handoff.js",
  "quality:verify-mutation-evidence": "node scripts/quality/verify-mutation-handoff.js",
  test: "node scripts/run-tests.js",
  "test:mutation:changed": "node scripts/quality/run-mutation.js changed",
  "test:mutation:core": "node scripts/quality/run-mutation.js core",
  "test:node": "node scripts/run-node-tests.js",
  "test:ui:smoke": "node scripts/quality/run-ui-smoke.js",
  "test:zero-guard": "node scripts/run-tests.js --zero-probe",
  syntax: "node scripts/check-syntax.js",
  "verify:architecture": "node scripts/architecture/verify.js",
  "verify:polish": "node scripts/polish/verify.js",
  "verify:quality": "node scripts/quality/verify.js",
  "verify:version": "node scripts/release/verify-version.js",
  "vscode:prepublish": "npm run check",
});

function verifyQualityContracts(options = {}) {
  const root = options.root || ROOT;
  const workflowsDocument = options.workflows || readJson("quality/critical-workflows.json", root);
  const actionDocument = options.actions || readJson("quality/action-contracts.json", root);
  const taxonomy = options.taxonomy || readJson("quality/defect-taxonomy.json", root);
  const findingSchema = options.findingSchema || readJson("quality/finding.schema.json", root);
  const sourceOverrides = options.sourceOverrides || {};
  const repositoryFiles = options.repositoryFiles || gitVisibleFiles(root);
  const manifest = options.manifest || readJson("package.json", root);
  const lockfile = options.lockfile || readJson("package-lock.json", root);
  const mutationBaseline = options.mutationBaseline
    || readJson("quality/mutation-baseline.json", root);
  const inventories = options.inventories
    || require(path.join(root, "test", "testInventories.js"));
  const errors = [];

  errors.push(...validateMutationBaseline(mutationBaseline, {
    root,
    commitIsAncestor: options.mutationBaselineCommitIsAncestor,
    lockfile,
    manifest,
    repositoryFiles,
  }).errors);
  verifyTaxonomy(taxonomy, findingSchema, errors);
  verifyExtensionHostHarness(root, repositoryFiles, sourceOverrides, errors);
  verifyEvidenceHandoffContract(
    root,
    repositoryFiles,
    sourceOverrides,
    errors,
    manifest
  );
  const workflowIds = verifyWorkflows(
    workflowsDocument,
    actionDocument,
    root,
    repositoryFiles,
    sourceOverrides,
    errors,
    taxonomy,
    manifest,
    inventories
  );
  verifyActions(
    actionDocument,
    workflowIds,
    root,
    repositoryFiles,
    sourceOverrides,
    errors,
    manifest
  );
  verifyScriptedWebviews(actionDocument, root, repositoryFiles, sourceOverrides, errors);

  return { errors: uniqueSorted(errors), workflowCount: workflowIds.size };
}

function verifyEvidenceHandoffContract(
  root,
  repositoryFiles,
  sourceOverrides,
  errors,
  manifest
) {
  const verifierPath = "scripts/quality/verify-handoff.js";
  const mutationVerifierPath = "scripts/quality/verify-mutation-handoff.js";
  const uiVerifierPath = "scripts/quality/verify-ui-evidence.js";
  const authenticatedVerifierPath = "scripts/quality/verify-authenticated-evidence.js";
  const authenticatedSessionPath = "scripts/quality/authenticated-candidate-session.js";
  const processTreePath = "scripts/quality/process-tree.js";
  const gitleaksActionPath = ".github/actions/setup-gitleaks/action.yml";
  const deepWorkflowPath = ".github/workflows/deep-quality.yml";
  const workflowPath = ".github/workflows/main.yml";
  const remoteCiSchemaPath = "quality/remote-ci.schema.json";
  const remoteCiCollectorPath = "scripts/quality/collect-remote-ci.js";
  verifyQualityManifestEntrypoints(manifest, errors);
  let deepWorkflowTarget;
  let gitleaksActionTarget;
  let workflowTarget;
  let remoteCiSchemaTarget;
  try {
    resolveGitVisibleRegularFile(verifierPath, repositoryFiles, root);
    resolveGitVisibleRegularFile(mutationVerifierPath, repositoryFiles, root);
    resolveGitVisibleRegularFile(uiVerifierPath, repositoryFiles, root);
    resolveGitVisibleRegularFile(authenticatedVerifierPath, repositoryFiles, root);
    resolveGitVisibleRegularFile(authenticatedSessionPath, repositoryFiles, root);
    resolveGitVisibleRegularFile(processTreePath, repositoryFiles, root);
    gitleaksActionTarget = resolveGitVisibleRegularFile(
      gitleaksActionPath,
      repositoryFiles,
      root
    );
    deepWorkflowTarget = resolveGitVisibleRegularFile(deepWorkflowPath, repositoryFiles, root);
    workflowTarget = resolveGitVisibleRegularFile(workflowPath, repositoryFiles, root);
    remoteCiSchemaTarget = resolveGitVisibleRegularFile(
      remoteCiSchemaPath,
      repositoryFiles,
      root,
    );
    resolveGitVisibleRegularFile(remoteCiCollectorPath, repositoryFiles, root);
  } catch {
    errors.push(
      "Quality evidence handoff, pinned scanner setup, and CI workflow sources must be Git-visible regular files."
    );
    return;
  }
  const gitleaksAction = verifiedSource(
    gitleaksActionPath,
    gitleaksActionTarget,
    sourceOverrides
  );
  const deepWorkflow = verifiedSource(deepWorkflowPath, deepWorkflowTarget, sourceOverrides);
  const workflow = verifiedSource(workflowPath, workflowTarget, sourceOverrides);
  const remoteCiSchema = parseCiWorkflow(verifiedSource(
    remoteCiSchemaPath,
    remoteCiSchemaTarget,
    sourceOverrides,
  ));
  const gitleaksActionDocument = parseCiWorkflow(gitleaksAction);
  const workflowDocument = parseCiWorkflow(workflow);
  const deepWorkflowDocument = parseCiWorkflow(deepWorkflow);
  if (!validRemoteCiSchema(remoteCiSchema)) {
    errors.push("Final-head remote CI schema must match the reviewed GitHub API evidence contract.");
  }
  if (!isDeepStrictEqual(gitleaksActionDocument, expectedPinnedGitleaksAction())) {
    errors.push("CI secret scanning must use the exact reviewed Gitleaks release and archive digest.");
  }
  if (!validMainWorkflowEnvelope(workflowDocument)
    || !isDeepStrictEqual(workflowDocument?.jobs?.quality, expectedQualityJob())) {
    errors.push(
      "CI must verify the exact fast-gate evidence immediately before a verifier-gated upload."
    );
  }
  if (!validMainWorkflowEnvelope(workflowDocument)
    || !isDeepStrictEqual(workflowDocument?.jobs?.mutation, expectedChangedMutationJob())
    || !validArtifactUploadInventory(workflowDocument, {
      quality: 1,
      mutation: 1,
      "extension-tests": 0,
      package: 1,
      "core-mutation": 2,
      "signed-out-black-box-ui": 1,
      "build-candidate": 0,
    })) {
    errors.push(
      "CI must verify the exact changed-mutation evidence immediately before a verifier-gated upload."
    );
  }
  if (!validMainWorkflowEnvelope(workflowDocument)
    || !isDeepStrictEqual(
      workflowDocument?.jobs?.["extension-tests"],
      expectedExtensionTestsJob()
    )) {
    errors.push("CI must execute the exact extension-test matrix and zero-test guard.");
  }
  if (!validMainWorkflowEnvelope(workflowDocument)
    || !isDeepStrictEqual(workflowDocument?.jobs?.package, expectedPackageJob())) {
    errors.push("CI must build, verify, scan, and upload the exact reproducible VSIX inputs.");
  }
  if (!validMainWorkflowEnvelope(workflowDocument)
    || !isDeepStrictEqual(workflowDocument?.jobs?.["core-mutation"], expectedCoreMutationJob())) {
    errors.push("CI must execute exact core mutation on the pushed PR head.");
  }
  if (!validMainWorkflowEnvelope(workflowDocument)
    || !isDeepStrictEqual(
      workflowDocument?.jobs?.["signed-out-black-box-ui"],
      expectedSignedOutUiJob(),
    )) {
    errors.push("CI must execute exact signed-out packaged UI on the pushed PR head.");
  }
  if (!validMainWorkflowEnvelope(workflowDocument)
    || !isDeepStrictEqual(
      workflowDocument?.jobs?.["build-candidate"],
      expectedBuildCandidateJob()
    )) {
    errors.push("CI build-candidate must require every deterministic input to succeed.");
  }
  if (!validDeepWorkflowEnvelope(deepWorkflowDocument)
    || !isDeepStrictEqual(
      deepWorkflowDocument?.jobs?.["core-mutation"],
      expectedCoreMutationJob()
    )
    || !validArtifactUploadInventory(deepWorkflowDocument, {
      "core-mutation": 2,
    })) {
    errors.push(
      "Deep CI must verify exact core-mutation evidence before a verifier-gated upload."
    );
  }
  if (!validDeepWorkflowEnvelope(deepWorkflowDocument)
    || !isDeepStrictEqual(
      deepWorkflowDocument?.jobs?.["signed-out-black-box-ui"],
      expectedSignedOutUiJob()
    )
    || !validArtifactUploadInventory(deepWorkflowDocument, {
      "signed-out-black-box-ui": 1,
    })) {
    errors.push(
      "Deep CI must bind and secret-scan signed-out packaged UI evidence before upload."
    );
  }
  if (!validDeepWorkflowEnvelope(deepWorkflowDocument)
    || !isDeepStrictEqual(
      deepWorkflowDocument?.jobs?.["authenticated-production-ui"],
      expectedAuthenticatedUiJob()
    )
    || !validArtifactUploadInventory(deepWorkflowDocument, {
      "authenticated-production-ui": 1,
    })) {
    errors.push(
      "Deep CI must verify production authenticated UI through the value-blind bootstrap boundary."
    );
  }
}

function validRemoteCiSchema(document) {
  return isPlainObject(document)
    && document.$id === "https://cloudsmith.com/schemas/vscode-extension-remote-ci-receipt-v2.json"
    && document.properties?.schemaVersion?.const === 2
    && document.properties?.repository?.const
      === "cloudsmith-labs/cloudsmith-vscode-extension"
    && document.properties?.evidence?.properties?.path?.const
      === "internal_docs/quality/remote-ci-api.json"
    && document.properties?.runs?.minItems === 1
    && document.properties?.runs?.maxItems === 1
    && document.properties?.runs?.items?.properties?.workflowFile?.const
      === ".github/workflows/main.yml"
    && document.properties?.runs?.items?.properties?.event?.const === "pull_request"
    && document.properties?.runs?.items?.properties?.pullRequestNumber?.type === "integer"
    && isDeepStrictEqual(document.required, [
      "schemaVersion", "repository", "branch", "sourceSha", "sourceFingerprint", "capturedAt",
      "pullRequest", "runs", "evidence",
    ])
    && isDeepStrictEqual(document.properties?.pullRequest?.required, [
      "number", "draft", "state", "baseRef", "headRef", "headSha", "url",
    ])
    && isDeepStrictEqual(document.properties?.runs?.items?.required, [
      "workflowFile", "workflowName", "event", "runId", "runAttempt",
      "pullRequestNumber", "headSha", "status", "conclusion", "createdAt",
      "completedAt", "url", "jobs",
    ])
    && isDeepStrictEqual(document.properties?.runs?.items?.properties?.jobs?.items?.required, [
      "id", "name", "databaseId", "status", "conclusion", "startedAt", "completedAt",
    ]);
}

function verifyQualityManifestEntrypoints(manifest, errors) {
  for (const [name, expected] of Object.entries(EXPECTED_QUALITY_SCRIPT_ENTRYPOINTS)) {
    if (manifest?.scripts?.[name] !== expected) {
      errors.push(`Package script ${name} must expose its exact reviewed quality entrypoint.`);
    }
  }
}

const CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1";
const SETUP_NODE_ACTION = "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020";
const UPLOAD_ACTION = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a";
const QUALITY_BASE = "${{ github.event_name == 'push' && github.event.before || 'origin/main' }}";
const CANDIDATE_SHA = "${{ env.CANDIDATE_SHA }}";

function parseCiWorkflow(source) {
  try {
    const document = yaml.load(source, { schema: yaml.CORE_SCHEMA });
    return isPlainObject(document) ? document : null;
  } catch {
    return null;
  }
}

function validMainWorkflowEnvelope(document) {
  return isPlainObject(document)
    && isDeepStrictEqual(Object.keys(document).sort(), ["env", "jobs", "name", "on", "permissions"])
    && isDeepStrictEqual(document.on, {
      push: { branches: ["main"] },
      pull_request: { branches: ["main"] },
    })
    && isDeepStrictEqual(document.permissions, { contents: "read" })
    && isDeepStrictEqual(document.env, {
      NODE_VERSION: "22.23.2",
      CANDIDATE_SHA: "${{ github.event.pull_request.head.sha || github.sha }}",
    })
    && isDeepStrictEqual(Object.keys(document.jobs || {}).sort(), [
      "build-candidate",
      "core-mutation",
      "extension-tests",
      "mutation",
      "package",
      "quality",
      "signed-out-black-box-ui",
    ]);
}

function validDeepWorkflowEnvelope(document) {
  return isPlainObject(document)
    && isDeepStrictEqual(Object.keys(document).sort(), ["env", "jobs", "name", "on", "permissions"])
    && isDeepStrictEqual(document.on, { workflow_dispatch: null })
    && isDeepStrictEqual(document.permissions, { contents: "read" })
    && isDeepStrictEqual(document.env, {
      NODE_VERSION: "22.23.2",
      CANDIDATE_SHA: "${{ github.sha }}",
    })
    && isDeepStrictEqual(Object.keys(document.jobs || {}).sort(), [
      "authenticated-production-ui",
      "core-mutation",
      "signed-out-black-box-ui",
    ]);
}

function expectedQualityJob() {
  return {
    name: "Quality",
    "runs-on": "ubuntu-24.04",
    "timeout-minutes": 15,
    steps: [
      checkoutStep("Checkout exact source", true),
      setupNodeStep(),
      installStep(),
      {
        name: "Set up the pinned secret scanner",
        uses: "./.github/actions/setup-gitleaks",
      },
      {
        name: "Log toolchain",
        run: "node -e \"console.log({node:process.version,npm:process.env.npm_config_user_agent,platform:process.platform,arch:process.arch})\"",
      },
      { name: "Verify architecture boundaries", run: "npm run verify:architecture" },
      { name: "Audit runtime dependency graph", run: "npm run audit:runtime" },
      { name: "Audit development dependency graph", run: "npm run audit:dev" },
      {
        name: "Run the deterministic fast quality gate",
        env: { QUALITY_BASE },
        run: "npm run quality:fast",
      },
      {
        name: "Scan upload-eligible quality evidence",
        id: "quality_evidence_secret_scan",
        if: "${{ always() }}",
        run: "npm run quality:secrets:evidence",
      },
      {
        name: "Verify exact quality evidence handoff",
        id: "quality_evidence_handoff",
        if: "${{ always() }}",
        run: "npm run quality:verify-evidence -- --gate-profile fast",
      },
      {
        name: "Upload quality impact and report evidence",
        if: "${{ always() && steps.quality_evidence_handoff.outcome == 'success' && steps.quality_evidence_secret_scan.outcome == 'success' }}",
        uses: UPLOAD_ACTION,
        with: {
          name: "quality-evidence-${{ env.CANDIDATE_SHA }}-${{ github.run_attempt }}",
          path: ".quality/impact.json\n.quality/gates/fast.json\n.quality/gates/fast/*.json\n.quality/report.json\n.quality/report.md\n.quality/secrets/current.json\n.quality/secrets/evidence.json\n",
          "if-no-files-found": "error",
          "include-hidden-files": true,
          "retention-days": 30,
        },
      },
    ],
  };
}

function expectedChangedMutationJob() {
  return {
    name: "Changed high-risk mutation gate",
    "runs-on": "ubuntu-24.04",
    "timeout-minutes": 30,
    steps: [
      checkoutStep("Checkout exact source with comparison history", true),
      setupNodeStep(),
      installStep(),
      {
        name: "Run changed high-risk mutation gate",
        id: "mutation_run",
        env: { QUALITY_BASE },
        run: "set +e\nnpm run test:mutation:changed -- --base \"$QUALITY_BASE\"\nstatus=$?\necho \"exit_code=$status\" >> \"$GITHUB_OUTPUT\"\nexit \"$status\"\n",
      },
      {
        name: "Verify exact mutation evidence handoff",
        id: "mutation_evidence_handoff",
        if: "${{ always() }}",
        env: {
          QUALITY_BASE,
          EXPECTED_MUTATION_EXIT_CODE: "${{ steps.mutation_run.outputs.exit_code }}",
          EXPECTED_MUTATION_OUTCOME: "${{ steps.mutation_run.outcome }}",
          EXPECTED_SOURCE_SHA: CANDIDATE_SHA,
        },
        run: "npm run quality:verify-mutation-evidence -- --base \"$QUALITY_BASE\" --expected-exit-code \"$EXPECTED_MUTATION_EXIT_CODE\" --expected-run-outcome \"$EXPECTED_MUTATION_OUTCOME\" --expected-source-sha \"$EXPECTED_SOURCE_SHA\"",
      },
      {
        name: "Upload mutation evidence",
        if: "${{ always() && steps.mutation_evidence_handoff.outcome == 'success' }}",
        uses: UPLOAD_ACTION,
        with: {
          name: "mutation-evidence-${{ env.CANDIDATE_SHA }}-${{ github.run_attempt }}",
          path: ".quality/mutation/summary-changed.json\n.quality/mutation/mutation.json\n",
          "if-no-files-found": "error",
          "include-hidden-files": true,
          "retention-days": 30,
        },
      },
    ],
  };
}

function expectedExtensionTestsJob() {
  return {
    name: "Extension tests (${{ matrix.os }}, VS Code ${{ matrix.vscode }}, ${{ matrix.label }})",
    "runs-on": "${{ matrix.os }}",
    "timeout-minutes": 20,
    strategy: {
      "fail-fast": false,
      matrix: {
        include: [
          { os: "ubuntu-24.04", vscode: "1.99.0", label: "core", "node-tests": "true" },
          { os: "ubuntu-24.04", vscode: "1.99.0", label: "smoke", "node-tests": "false" },
          { os: "ubuntu-24.04", vscode: "1.134.0", label: "core", "node-tests": "true" },
          { os: "windows-2025", vscode: "1.134.0", label: "smoke", "node-tests": "true" },
          { os: "macos-15", vscode: "1.134.0", label: "smoke", "node-tests": "true" },
        ],
      },
    },
    env: {
      VSCODE_TEST_VERSION: "${{ matrix.vscode }}",
      VSCODE_TEST_LABEL: "${{ matrix.label }}",
      CLOUDSMITH_RUN_NODE_TESTS: "${{ matrix.node-tests }}",
    },
    steps: [
      checkoutStep("Checkout exact source", true),
      setupNodeStep(),
      installStep(),
      {
        name: "Log test runtime",
        run: "node -e \"console.log({node:process.version,platform:process.platform,arch:process.arch,vscode:process.env.VSCODE_TEST_VERSION,label:process.env.VSCODE_TEST_LABEL})\"",
      },
      {
        name: "Preflight canonical npm launcher and packaging on Windows",
        if: "runner.os == 'Windows'",
        run: "npm run package",
      },
      {
        name: "Run deterministic extension suite",
        run: "npm test -- --extension-matrix",
      },
      {
        name: "Prove the real test entrypoint rejects zero tests",
        run: "npm run test:zero-guard -- --extension-matrix",
      },
    ],
  };
}

function expectedPackageJob() {
  return {
    name: "Reproducible VSIX",
    needs: ["quality", "mutation", "extension-tests"],
    "runs-on": "ubuntu-24.04",
    "timeout-minutes": 20,
    steps: [
      checkoutStep("Checkout exact source in a fresh job", false),
      setupNodeStep(),
      installStep(),
      {
        name: "Set up the pinned secret scanner",
        uses: "./.github/actions/setup-gitleaks",
      },
      {
        name: "Build and verify byte-reproducible VSIX twice",
        id: "package",
        env: {
          M9_REQUIRE_CLEAN: 1,
          M9_SOURCE_SHA: CANDIDATE_SHA,
        },
        run: "npm run package -- --github-output \"$GITHUB_OUTPUT\"",
      },
      {
        name: "Re-verify artifact and sidecars before handoff",
        env: {
          EXPECTED_SOURCE_SHA: CANDIDATE_SHA,
          VSIX_PATH: "${{ steps.package.outputs.vsix_path }}",
        },
        run: "npm run package:verify -- --expected-source-sha \"$EXPECTED_SOURCE_SHA\" --require-publishable \"$VSIX_PATH\"",
      },
      {
        name: "Scan archive bytes and expanded VSIX contents",
        run: "npm run quality:secrets:artifacts",
      },
      {
        name: "Upload exact verified release inputs",
        uses: UPLOAD_ACTION,
        with: {
          name: "vsix-${{ env.CANDIDATE_SHA }}",
          path: "${{ steps.package.outputs.vsix_path }}\n${{ steps.package.outputs.checksum_path }}\n${{ steps.package.outputs.provenance_path }}\n.quality/secrets/artifacts.json\n",
          "if-no-files-found": "error",
          "retention-days": 90,
          "compression-level": 0,
        },
      },
    ],
  };
}

function expectedBuildCandidateJob() {
  return {
    name: "Deterministic build candidate",
    needs: [
      "quality", "mutation", "extension-tests", "package", "core-mutation",
      "signed-out-black-box-ui",
    ],
    if: "${{ always() }}",
    "runs-on": "ubuntu-24.04",
    "timeout-minutes": 5,
    steps: [{
      name: "Require every deterministic candidate input to succeed",
      env: {
        QUALITY_RESULT: "${{ needs.quality.result }}",
        MUTATION_RESULT: "${{ needs.mutation.result }}",
        TEST_RESULT: "${{ needs.extension-tests.result }}",
        PACKAGE_RESULT: "${{ needs.package.result }}",
        CORE_MUTATION_RESULT: "${{ needs.core-mutation.result }}",
        SIGNED_OUT_UI_RESULT: "${{ needs.signed-out-black-box-ui.result }}",
      },
      run: "if [[ \"$QUALITY_RESULT\" != \"success\" || \"$MUTATION_RESULT\" != \"success\" || \"$TEST_RESULT\" != \"success\" || \"$PACKAGE_RESULT\" != \"success\" || \"$CORE_MUTATION_RESULT\" != \"success\" || \"$SIGNED_OUT_UI_RESULT\" != \"success\" ]]; then\n  echo \"A deterministic build-candidate input failed, was canceled, or was skipped.\"\n  exit 1\nfi\necho \"Every deterministic build-candidate input succeeded; production release readiness remains blocked pending separately sourced UI and live qualification.\"\n",
    }],
  };
}

function expectedCoreMutationJob() {
  return {
    name: "Core mutation",
    "runs-on": "ubuntu-24.04",
    "timeout-minutes": 60,
    steps: [
      checkoutStep("Checkout exact source", true),
      setupNodeStep(),
      installStep(),
      { name: "Verify release-quality contracts", run: "npm run verify:quality" },
      {
        name: "Run core mutation",
        id: "mutation_run",
        run: "set +e\nnpm run test:mutation:core\nstatus=$?\necho \"exit_code=$status\" >> \"$GITHUB_OUTPUT\"\nexit \"$status\"\n",
      },
      {
        name: "Verify exact core mutation evidence handoff",
        id: "mutation_evidence_handoff",
        if: "${{ always() }}",
        env: {
          EXPECTED_MUTATION_EXIT_CODE: "${{ steps.mutation_run.outputs.exit_code }}",
          EXPECTED_MUTATION_OUTCOME: "${{ steps.mutation_run.outcome }}",
          EXPECTED_SOURCE_SHA: CANDIDATE_SHA,
        },
        run: "npm run quality:verify-mutation-evidence -- --mode core --expected-exit-code \"$EXPECTED_MUTATION_EXIT_CODE\" --expected-run-outcome \"$EXPECTED_MUTATION_OUTCOME\" --expected-source-sha \"$EXPECTED_SOURCE_SHA\"",
      },
      {
        name: "Upload core mutation evidence",
        if: "${{ always() && steps.mutation_evidence_handoff.outcome == 'success' }}",
        uses: UPLOAD_ACTION,
        with: {
          name: "core-mutation-evidence-${{ env.CANDIDATE_SHA }}-${{ github.run_attempt }}",
          path: ".quality/mutation/summary-core.json\n.quality/mutation/mutation.json\n",
          "if-no-files-found": "error",
          "include-hidden-files": true,
          "retention-days": 30,
        },
      },
      {
        name: "Set up the pinned secret scanner after mutation evidence",
        if: "${{ always() }}",
        uses: "./.github/actions/setup-gitleaks",
      },
      {
        name: "Scan complete Git history without suppressing mutation work",
        id: "history_secret_scan",
        if: "${{ always() }}",
        run: "npm run quality:secrets:history",
      },
      {
        name: "Upload only the value-blind history receipt",
        if: "${{ always() }}",
        uses: UPLOAD_ACTION,
        with: {
          name: "history-secret-receipt-${{ env.CANDIDATE_SHA }}-${{ github.run_attempt }}",
          path: ".quality/secrets/history.json",
          "if-no-files-found": "error",
          "include-hidden-files": true,
          "retention-days": 30,
        },
      },
    ],
  };
}

function expectedSignedOutUiJob() {
  return {
    name: "Signed-out packaged black-box UI",
    "runs-on": "ubuntu-24.04",
    "timeout-minutes": 30,
    steps: [
      checkoutStep("Checkout exact source", true),
      setupNodeStep(),
      installStep(),
      {
        name: "Set up the pinned secret scanner",
        uses: "./.github/actions/setup-gitleaks",
      },
      {
        name: "Run signed-out packaged black-box UI",
        id: "ui_smoke",
        run: "npm run test:ui:smoke",
      },
      {
        name: "Verify exact candidate and UI result binding",
        id: "ui_evidence_handoff",
        if: "${{ always() }}",
        run: "node scripts/quality/verify-ui-evidence.js",
      },
      {
        name: "Scan upload-eligible signed-out UI evidence",
        id: "ui_evidence_secret_scan",
        if: "${{ always() }}",
        run: "npm run quality:secrets:signed-out-evidence",
      },
      {
        name: "Verify detached staged signed-out UI evidence",
        id: "ui_evidence_bundle",
        if: "${{ always() }}",
        env: { EXPECTED_SOURCE_SHA: CANDIDATE_SHA },
        run: "node scripts/quality/verify-ui-evidence.js --bundle .quality/upload/signed-out-ui",
      },
      {
        name: "Upload safe signed-out UI receipts",
        if: "${{ always() && steps.ui_evidence_handoff.outcome == 'success' && steps.ui_evidence_secret_scan.outcome == 'success' && steps.ui_evidence_bundle.outcome == 'success' }}",
        uses: UPLOAD_ACTION,
        with: {
          name: "signed-out-ui-evidence-${{ env.CANDIDATE_SHA }}-${{ github.run_attempt }}",
          path: [
            ".quality/upload/signed-out-ui/evidence.json",
            ".quality/upload/signed-out-ui/result.json",
            ".quality/upload/signed-out-ui/ui-candidate.json",
            ".quality/upload/signed-out-ui/ui-candidate.vsix",
          ].join("\n"),
          "if-no-files-found": "error",
          "include-hidden-files": true,
          "retention-days": 30,
        },
      },
    ],
  };
}

function expectedAuthenticatedUiJob() {
  return {
    name: "Authenticated packaged production UI",
    "runs-on": "ubuntu-24.04",
    environment: "cloudsmith-release-qualification",
    "timeout-minutes": 45,
    steps: [
      checkoutStep("Checkout exact source", true),
      setupNodeStep(),
      installStep(),
      {
        name: "Set up the pinned secret scanner",
        uses: "./.github/actions/setup-gitleaks",
      },
      {
        name: "Prepare and validate exact authenticated candidate without credentials",
        run: "npm run quality:qualification:prepare-authenticated-ci",
      },
      {
        name: "Run authenticated packaged production UI",
        id: "authenticated_qualification",
        "timeout-minutes": 15,
        env: {
          CLOUDSMITH_QUALIFICATION_API_KEY:
            "${{ secrets.CLOUDSMITH_QUALIFICATION_API_KEY }}",
        },
        run: "xvfb-run -a node scripts/quality/run-authenticated-ci.js",
      },
      {
        name: "Always clean the authenticated profile session",
        id: "authenticated_profile_cleanup",
        if: "${{ always() }}",
        run: "node scripts/quality/authenticated-candidate-session.js cleanup",
      },
      {
        name: "Verify exact authenticated evidence binding",
        id: "authenticated_evidence_handoff",
        if: "${{ always() }}",
        env: { EXPECTED_SOURCE_SHA: CANDIDATE_SHA },
        run: "npm run quality:verify-authenticated-evidence",
      },
      {
        name: "Scan upload-eligible authenticated evidence",
        id: "authenticated_evidence_secret_scan",
        if: "${{ always() }}",
        run: "npm run quality:secrets:evidence",
      },
      {
        name: "Upload safe authenticated UI receipts",
        if: "${{ always() && steps.authenticated_evidence_handoff.outcome == 'success' && steps.authenticated_evidence_secret_scan.outcome == 'success' }}",
        uses: UPLOAD_ACTION,
        with: {
          name: "authenticated-ui-evidence-${{ env.CANDIDATE_SHA }}-${{ github.run_attempt }}",
          path: ".quality/qualification/authenticated-candidate.json\n.quality/qualification/authenticated-candidate.vsix\n.quality/qualification/authenticated-ci.json\n.quality/secrets/authenticated-ci.json\n.quality/secrets/evidence.json\n",
          "if-no-files-found": "error",
          "include-hidden-files": true,
          "retention-days": 30,
        },
      },
    ],
  };
}

function expectedPinnedGitleaksAction() {
  return {
    name: "Set up pinned Gitleaks",
    description: "Install the reviewed Gitleaks release with an exact archive digest.",
    runs: {
      using: "composite",
      steps: [{
        name: "Install Gitleaks 8.30.1",
        shell: "bash",
        run: [
          "set -euo pipefail",
          "readonly version=\"8.30.1\"",
          "readonly archive=\"gitleaks_${version}_linux_x64.tar.gz\"",
          "readonly expected_sha256=\"551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb\"",
          "readonly download_path=\"${RUNNER_TEMP}/${archive}\"",
          "readonly install_dir=\"${RUNNER_TEMP}/cloudsmith-gitleaks-${version}\"",
          "",
          "curl --fail --location --silent --show-error \\",
          "  \"https://github.com/gitleaks/gitleaks/releases/download/v${version}/${archive}\" \\",
          "  --output \"$download_path\"",
          "echo \"${expected_sha256}  ${download_path}\" | sha256sum --check --strict",
          "mkdir --mode=0700 \"$install_dir\"",
          "tar --extract --gzip --file \"$download_path\" --directory \"$install_dir\" gitleaks",
          "chmod 0700 \"$install_dir/gitleaks\"",
          "rm --force \"$download_path\"",
          "echo \"$install_dir\" >> \"$GITHUB_PATH\"",
          "[[ \"$($install_dir/gitleaks version)\" == \"$version\" ]]",
          "",
        ].join("\n"),
      }],
    },
  };
}

function checkoutStep(name, history) {
  const withOptions = { "persist-credentials": false, ref: CANDIDATE_SHA };
  if (history) withOptions["fetch-depth"] = 0;
  return { name, uses: CHECKOUT_ACTION, with: withOptions };
}

function setupNodeStep() {
  return {
    name: "Set up exact Node.js",
    uses: SETUP_NODE_ACTION,
    with: {
      "node-version": "${{ env.NODE_VERSION }}",
      "package-manager-cache": false,
    },
  };
}

function installStep() {
  return {
    name: "Install locked dependencies without lifecycle scripts",
    run: "npm ci --ignore-scripts --no-audit --no-fund",
  };
}

function validArtifactUploadInventory(document, expectedByJob) {
  if (!isPlainObject(document?.jobs)) return false;
  return Object.entries(expectedByJob).every(([jobId, expected]) => {
    const steps = document.jobs[jobId]?.steps;
    return Array.isArray(steps) && steps.filter(step => (
      typeof step?.uses === "string" && step.uses.startsWith("actions/upload-artifact@")
    )).length === expected;
  });
}

function verifyTaxonomy(taxonomy, findingSchema, errors) {
  if (!isPlainObject(taxonomy)) {
    errors.push("Defect taxonomy must be an object.");
    return;
  }
  for (const severity of ["P0", "P1", "P2", "P3"]) {
    if (!isPlainObject(taxonomy.severities?.[severity])) {
      errors.push(`Defect taxonomy is missing severity ${severity}.`);
    }
  }
  for (const failureClass of REQUIRED_FAILURE_CLASSES) {
    if (!taxonomy.failureClasses?.includes(failureClass)) {
      errors.push(`Defect taxonomy is missing failure class ${failureClass}.`);
    }
  }
  if (!isPlainObject(findingSchema) || findingSchema.type !== "object") {
    errors.push("Finding schema must describe one object.");
    return;
  }
  const taxonomyFields = uniqueSorted(taxonomy.requiredFields || []);
  const schemaFields = uniqueSorted(findingSchema.required || []);
  if (JSON.stringify(taxonomyFields) !== JSON.stringify(schemaFields)) {
    errors.push("Finding schema required fields do not match the defect taxonomy.");
  }
  if (findingSchema.additionalProperties !== false) {
    errors.push("Finding schema must reject unknown fields.");
  }
  const enumParity = [
    ["domain", Object.keys(taxonomy.domains || {}), findingSchema.properties?.domain?.enum],
    ["status", taxonomy.statuses, findingSchema.properties?.status?.enum],
    ["deterministicStatus", taxonomy.deterministicStatuses,
      findingSchema.properties?.deterministicStatus?.enum],
    ["liveStatus", taxonomy.liveStatuses, findingSchema.properties?.liveStatus?.enum],
    ["severity", Object.keys(taxonomy.severities || {}),
      findingSchema.properties?.severity?.enum],
    ["failureClasses", taxonomy.failureClasses,
      findingSchema.properties?.failureClasses?.items?.enum],
    ["reproductionConfidence", taxonomy.reproductionConfidences,
      findingSchema.properties?.reproductionConfidence?.enum],
    ["rootCauseStatus", taxonomy.rootCauseStatuses,
      findingSchema.properties?.rootCauseStatus?.enum],
    ["testLayerThatShouldHaveCaughtIt", taxonomy.testLayers,
      findingSchema.properties?.testLayerThatShouldHaveCaughtIt?.enum],
    ["mutationProof.status", taxonomy.mutationProofStatuses,
      findingSchema.properties?.mutationProof?.properties?.status?.enum],
  ];
  for (const [label, taxonomyValues, schemaValues] of enumParity) {
    if (JSON.stringify(uniqueSorted(taxonomyValues || []))
      !== JSON.stringify(uniqueSorted(schemaValues || []))) {
      errors.push(`Finding schema ${label} values do not match the defect taxonomy.`);
    }
  }
  if (findingSchema.properties?.id?.pattern !== taxonomy.idPattern) {
    errors.push("Finding schema ID pattern does not match the defect taxonomy.");
  }
  if (findingSchema.properties?.releaseBlocking?.type !== "boolean") {
    errors.push("Finding schema releaseBlocking must be a boolean policy assertion.");
  }
  const evidenceLayers = new Set(taxonomy.evidenceLayers || []);
  const policy = taxonomy.requiredEvidencePolicy;
  if (!isPlainObject(policy)
    || policy.derivationField !== "testLayerThatShouldHaveCaughtIt") {
    errors.push("Defect taxonomy must derive required evidence from the escaped layer.");
    return;
  }
  for (const testLayer of taxonomy.testLayers || []) {
    const derived = policy.defaultByEscapedLayer?.[testLayer];
    if (!Array.isArray(derived) || derived.length !== 1 || derived[0] !== testLayer) {
      errors.push(`Defect taxonomy must default ${testLayer} to its exact finding evidence layer.`);
    }
  }
  for (const layer of [
    ...(policy.liveStatusLayers || []),
    ...(policy.externalSecurityOverride?.requiredLayers || []),
  ]) {
    if (!evidenceLayers.has(layer)) {
      errors.push(`Defect taxonomy required evidence references unknown layer ${String(layer)}.`);
    }
  }
  const override = policy.externalSecurityOverride;
  if (!isPlainObject(override)
    || override.domain !== "security-environment"
    || override.severity !== "P0"
    || override.deterministicStatus !== "not-applicable"
    || JSON.stringify(uniqueSorted(override.requiredLayers || []))
      !== JSON.stringify(["durable-security-scan", "external-confirmation"])) {
    errors.push("Defect taxonomy external security evidence override is invalid.");
  }
  if (!isPlainObject(policy.findingOverrides)
    || JSON.stringify(policy.findingOverrides) !== JSON.stringify({
      "QH-011": ["contract"],
      "QH-012": ["contract"],
      "QH-026": ["contract"],
    })) {
    errors.push("Defect taxonomy reviewed finding evidence overrides are invalid.");
  }
}

function verifyWorkflows(
  document,
  actionDocument,
  root,
  repositoryFiles,
  sourceOverrides,
  errors,
  taxonomy,
  manifest,
  inventories
) {
  const workflows = Array.isArray(document?.workflows) ? document.workflows : [];
  if (workflows.length === 0) errors.push("Workflow manifest must contain workflows.");
  const ids = new Set();
  const actionIds = new Set((actionDocument?.actions || []).map(action => action.id));
  const criticalityValues = new Set(document?.criticalityValues || []);
  const layerValues = new Set(document?.layerValues || []);
  const interactionModeValues = new Set(document?.interactionModeValues || []);
  const executionModeValues = new Set(document?.extensionHostExecutionModeValues || []);

  for (const workflow of workflows) {
    const label = requireNonEmptyString(workflow?.id) ? workflow.id : "<missing-workflow-id>";
    if (!/^WF-[A-Z0-9-]+$/.test(label)) errors.push(`Workflow ${label} has an invalid ID.`);
    if (ids.has(label)) errors.push(`Duplicate workflow ID: ${label}.`);
    ids.add(label);
    if (!criticalityValues.has(workflow?.criticality)) {
      errors.push(`Workflow ${label} has invalid criticality ${String(workflow?.criticality)}.`);
    }
    if (!requireNonEmptyString(workflow?.surface)) errors.push(`Workflow ${label} is missing its surface.`);
    if (!requireNonEmptyString(workflow?.authoritativeOutcome)) {
      errors.push(`Workflow ${label} is missing an authoritative outcome.`);
    }
    if (!Array.isArray(workflow?.riskClasses) || workflow.riskClasses.length === 0) {
      errors.push(`Workflow ${label} must declare risk classes.`);
    }
    for (const riskClass of workflow?.riskClasses || []) {
      if (!(taxonomy?.failureClasses || []).includes(riskClass)) {
        errors.push(`Workflow ${label} has invalid risk class ${String(riskClass)}.`);
      }
    }
    if (!Array.isArray(workflow?.requiredLayers) || workflow.requiredLayers.length === 0) {
      errors.push(`Workflow ${label} must declare required layers.`);
    }
    for (const layer of workflow?.requiredLayers || []) {
      if (!layerValues.has(layer)) errors.push(`Workflow ${label} has invalid layer ${String(layer)}.`);
    }
    const evidence = Array.isArray(workflow?.evidence) ? workflow.evidence : [];
    const filesFromEvidence = uniqueSorted(evidence.map(item => item?.testFile).filter(Boolean));
    const declaredFiles = uniqueSorted(workflow?.testFiles || []);
    if (JSON.stringify(filesFromEvidence) !== JSON.stringify(declaredFiles)) {
      errors.push(`Workflow ${label} testFiles must exactly match its named evidence files.`);
    }
    if (workflow?.criticality === "release-critical"
      && !evidence.some(item => AUTOMATED_LAYERS.has(item?.layer))) {
      errors.push(`Release-critical workflow ${label} has no automated evidence.`);
    }
    for (const requiredLayer of workflow?.requiredLayers || []) {
      if (AUTOMATED_LAYERS.has(requiredLayer)
        && !evidence.some(item => item?.layer === requiredLayer)) {
        errors.push(`Workflow ${label} requires ${requiredLayer} evidence but declares none.`);
      }
      if (requiredLayer === "live-protocol" && workflow?.liveFixture?.required !== true) {
        errors.push(`Workflow ${label} requires live-protocol evidence but has no required live fixture.`);
      }
    }
    if (!isPlainObject(workflow?.liveFixture)
      || workflow.liveFixture.required !== true
      || !requireNonEmptyString(workflow.liveFixture.kind)
      || !requireNonEmptyString(workflow.liveFixture.description)
      || workflow.liveFixture.destructive !== false) {
      errors.push(
        `Workflow ${label} must declare a required, non-destructive authenticated live fixture.`
      );
    }
    for (const item of evidence) {
      verifyInteractionClassification(
        label,
        item,
        interactionModeValues,
        executionModeValues,
        errors
      );
      verifyEvidence(
        label,
        item,
        root,
        repositoryFiles,
        sourceOverrides,
        errors,
        inventories
      );
    }
    const proofValues = new Set(document?.proofValues || []);
    for (const item of evidence) {
      for (const proof of item?.proves || []) {
        if (!proofValues.has(proof)) {
          errors.push(`Workflow ${label} has invalid proof kind ${String(proof)}.`);
        }
      }
    }
    const proofKinds = new Set(evidence.flatMap(item => item?.proves || []));
    if (workflow?.criticality === "release-critical" && !proofKinds.has("authoritative-outcome")) {
      errors.push(`Release-critical workflow ${label} has no named authoritative-outcome proof.`);
    }
    if (!Array.isArray(workflow?.productionAreas) || workflow.productionAreas.length === 0) {
      errors.push(`Workflow ${label} must map production areas.`);
    }
    for (const pattern of workflow?.productionAreas || []) {
      if (!requireNonEmptyString(pattern)
        || !repositoryFiles.some(file => matchesPattern(file, pattern))) {
        errors.push(`Workflow ${label} production area does not match a tracked file: ${String(pattern)}.`);
      }
    }
    for (const actionId of workflow?.actionContractIds || []) {
      if (!actionIds.has(actionId)) errors.push(`Workflow ${label} references missing action ${actionId}.`);
    }
    if (!Array.isArray(workflow?.targetCommands) || workflow.targetCommands.length === 0) {
      errors.push(`Workflow ${label} must declare targeted commands.`);
    }
    for (const command of workflow?.targetCommands || []) {
      const match = /^npm run ([A-Za-z0-9:_-]+)$/u.exec(command || "");
      if (!match || !Object.prototype.hasOwnProperty.call(manifest?.scripts || {}, match[1])) {
        errors.push(`Workflow ${label} targets unknown command ${String(command)}.`);
      }
    }
    if (typeof workflow?.destructive !== "boolean") {
      errors.push(`Workflow ${label} must declare whether it is destructive.`);
    }
  }
  return ids;
}

function verifyInteractionClassification(
  workflowId,
  evidence,
  allowedModes,
  allowedExecutionModes,
  errors
) {
  const mode = evidence?.interactionMode;
  if (mode !== undefined && !allowedModes.has(mode)) {
    errors.push(`Workflow ${workflowId} evidence has invalid interaction mode ${String(mode)}.`);
    return;
  }
  if (mode === "synthetic-host-message" && evidence?.layer !== "extension-host") {
    errors.push(`Workflow ${workflowId} synthetic host-message evidence must be classified as extension-host wiring.`);
  }
  if (mode === "rendered-dom-activation" && evidence?.layer !== "black-box-ui") {
    errors.push(`Workflow ${workflowId} rendered DOM activation evidence must be classified as black-box-ui.`);
  }
  if (mode === "rendered-keyboard-navigation" && evidence?.layer !== "black-box-ui") {
    errors.push(`Workflow ${workflowId} rendered keyboard navigation evidence must be classified as black-box-ui.`);
  }
  if (evidence?.layer === "black-box-ui"
    && !new Set(["rendered-dom-activation", "rendered-keyboard-navigation"]).has(mode)) {
    errors.push(`Workflow ${workflowId} black-box-ui evidence must prove a rendered interaction.`);
  }
  if (evidence?.testFile === "test/webviewPackageActionFlow.test.js"
    && (mode !== "synthetic-host-message" || evidence?.layer !== "extension-host")) {
    errors.push(`Workflow ${workflowId} synthetic WebView composition must remain extension-host wiring evidence.`);
  }
  if (mode === "synthetic-host-message" && evidence?.proves?.includes("visible-publication")) {
    errors.push(`Workflow ${workflowId} synthetic host-message evidence cannot claim visible publication.`);
  }
  const executionMode = evidence?.executionMode;
  if (executionMode !== undefined && !allowedExecutionModes.has(executionMode)) {
    errors.push(`Workflow ${workflowId} evidence has invalid Extension Host execution mode ${String(executionMode)}.`);
  }
  if (executionMode === "manual-production-composition" && evidence?.layer !== "extension-host") {
    errors.push(`Workflow ${workflowId} manual production composition must remain extension-host evidence.`);
  }
  if (evidence?.testFile === "test/activation.test.js"
    && (executionMode !== "manual-production-composition" || evidence?.layer !== "extension-host")) {
    errors.push(`Workflow ${workflowId} activation evidence must describe manual production composition in the credential-free test host.`);
  }
}

function verifyExtensionHostHarness(root, repositoryFiles, sourceOverrides, errors) {
  const paths = {
    config: ".vscode-test.mjs",
    entrypoint: "test/harness-extension/extension.js",
    manifest: "test/harness-extension/package.json",
  };
  const resolved = {};
  for (const [kind, relativePath] of Object.entries(paths)) {
    try {
      resolved[kind] = resolveGitVisibleRegularFile(relativePath, repositoryFiles, root);
    } catch {
      errors.push(`Extension Host ${kind} is not a normalized Git-visible regular file: ${relativePath}.`);
      return;
    }
  }
  const repositoryReal = fs.realpathSync(root);
  const harnessReal = fs.realpathSync(path.dirname(resolved.manifest));
  if (harnessReal === repositoryReal) {
    errors.push("Extension Host tests must install a credential-free harness path, not the production root.");
  }
  const configSource = verifiedSource(
    paths.config,
    resolved.config,
    sourceOverrides
  );
  const developmentPathAssignments = configSource.match(/extensionDevelopmentPath\s*:/gu) || [];
  if (developmentPathAssignments.length !== 1
    || !configSource.includes("extensionDevelopmentPath: TEST_HARNESS_EXTENSION_PATH")
    || !configSource.includes("path.join(repositoryRoot, \"test\", \"harness-extension\")")) {
    errors.push("VS Code test configuration must install only the tracked credential-free harness extension.");
  }
  if (!configSource.includes("skipExtensionDependencies: true")
    || /installExtensions\s*:/u.test(configSource)) {
    errors.push("VS Code test configuration must not install product or dependency extensions.");
  }
  if (!configSource.includes("--extensions-dir=")) {
    errors.push("VS Code test configuration must isolate the installed-extension directory per run.");
  }
  if (!configSource.includes("createIsolatedQualificationRoot(label, os.tmpdir())")
    || !configSource.includes("process.once(\"exit\", () => removeIsolatedQualificationRoot(runRoot))")
    || configSource.includes("cloudsmith-vsc-${label}-${process.pid}")) {
    errors.push("VS Code test configuration must atomically create and exactly clean private per-run host roots.");
  }
  let manifest;
  try {
    manifest = JSON.parse(verifiedSource(
      paths.manifest,
      resolved.manifest,
      sourceOverrides
    ));
  } catch {
    errors.push("Credential-free test harness manifest must be valid JSON.");
    return;
  }
  if (manifest.name !== "cloudsmith-vsc-test-harness"
    || manifest.publisher !== "cloudsmith-test"
    || manifest.main !== "./extension.js"
    || !Array.isArray(manifest.activationEvents)
    || manifest.activationEvents.length !== 0
    || manifest.contributes !== undefined
    || manifest.extensionDependencies !== undefined
    || manifest.extensionPack !== undefined) {
    errors.push("Credential-free test harness manifest must remain inert and contribution-free.");
  }
  const entrypoint = verifiedSource(
    paths.entrypoint,
    resolved.entrypoint,
    sourceOverrides
  );
  if (/\b(?:SecretStorage|secrets|process\.env|require|cloudsmith-vsc\.authToken)\b/u.test(entrypoint)) {
    errors.push("Credential-free test harness entrypoint may not read credentials or load production code.");
  }
}

function verifiedSource(relativePath, resolvedPath, sourceOverrides) {
  return Object.prototype.hasOwnProperty.call(sourceOverrides, relativePath)
    ? sourceOverrides[relativePath]
    : fs.readFileSync(resolvedPath, "utf8");
}

function verifyEvidence(
  workflowId,
  evidence,
  root,
  repositoryFiles,
  sourceOverrides,
  errors,
  inventories
) {
  if (!isPlainObject(evidence)) {
    errors.push(`Workflow ${workflowId} contains malformed evidence.`);
    return;
  }
  const file = evidence.testFile;
  if (!manifestFileTarget(file, root, repositoryFiles)) {
    errors.push(`Workflow ${workflowId} test file is not a normalized Git-visible regular file: ${String(file)}.`);
    return;
  }
  if (!Array.isArray(evidence.testNames) || evidence.testNames.length === 0) {
    errors.push(`Workflow ${workflowId} evidence ${file} must name test assertions.`);
  }
  for (const testName of evidence.testNames || []) {
    if (!requireNonEmptyString(testName)
      || !testSourceContains(root, file, testName, sourceOverrides)) {
      errors.push(`Workflow ${workflowId} names missing test assertion in ${file}: ${String(testName)}.`);
    }
  }
  if (!Array.isArray(evidence.proves) || evidence.proves.length === 0) {
    errors.push(`Workflow ${workflowId} evidence ${file} must declare what it proves.`);
  }
  verifyEvidenceInventoryLayer(workflowId, evidence, inventories, errors);
}

function verifyEvidenceInventoryLayer(workflowId, evidence, inventories, errors) {
  const file = evidence.testFile;
  const memberships = [];
  for (const [name, files] of [
    ["standalone", inventories?.STANDALONE_NODE_TESTS],
    ["extension-host-core", inventories?.VSCODE_CORE_TESTS],
    ["extension-host-smoke", inventories?.VSCODE_SMOKE_TESTS],
    ["credential-boundary-excluded", inventories?.CREDENTIAL_BOUNDARY_EXCLUDED_TESTS],
  ]) {
    if ((files || []).includes(file)) memberships.push(name);
  }
  const layer = evidence.layer;
  let allowed;
  if (layer === "unit") allowed = new Set(["standalone"]);
  else if (layer === "contract") {
    allowed = new Set(["standalone", "extension-host-core", "extension-host-smoke"]);
  } else if (layer === "extension-host") {
    allowed = new Set(["extension-host-core", "extension-host-smoke"]);
  } else if (layer === "live-protocol") {
    allowed = new Set(["credential-boundary-excluded"]);
  } else if (layer === "black-box-ui") {
    if (!String(file).startsWith("ui-test/")) {
      errors.push(
        `Workflow ${workflowId} evidence ${file} declares black-box-ui but is not a ui-test file.`
      );
    }
    return;
  } else {
    return;
  }
  if (memberships.length !== 1 || !allowed.has(memberships[0])) {
    errors.push(
      `Workflow ${workflowId} evidence ${file} declares ${String(layer)} but belongs to ${memberships.join(", ") || "no executable test inventory"}.`
    );
  }
}

function verifyActions(
  document,
  workflowIds,
  root,
  repositoryFiles,
  sourceOverrides,
  errors,
  manifest
) {
  const provenanceClasses = new Set(document?.provenanceClasses || []);
  const argumentTypes = new Set(document?.canonicalArgumentTypes || []);
  const ids = new Set();
  const contributedCommands = new Set(
    (manifest?.contributes?.commands || []).map(command => command?.command).filter(Boolean)
  );
  const webviewProducerByContract = new Map();
  for (const webview of document?.scriptedWebviews || []) {
    for (const command of webview?.commands || []) {
      if (!webviewProducerByContract.has(command?.actionContract)) {
        webviewProducerByContract.set(command?.actionContract, []);
      }
      webviewProducerByContract.get(command?.actionContract).push(command?.message);
    }
  }
  for (const action of document?.actions || []) {
    const label = requireNonEmptyString(action?.id) ? action.id : "<missing-action-id>";
    if (!/^ACT-[A-Z0-9-]+$/.test(label)) errors.push(`Action ${label} has an invalid ID.`);
    if (ids.has(label)) errors.push(`Duplicate action ID: ${label}.`);
    ids.add(label);
    if (!workflowIds.has(action?.workflow)) errors.push(`Action ${label} references missing workflow ${String(action?.workflow)}.`);
    const provenance = action?.producer?.provenance;
    if (!provenanceClasses.has(provenance)) errors.push(`Action ${label} has invalid producer provenance ${String(provenance)}.`);
    const accepted = action?.consumer?.acceptedProvenance;
    if (!Array.isArray(accepted) || !accepted.includes(provenance)) {
      errors.push(`Action ${label} producer provenance ${String(provenance)} is rejected by its consumer.`);
    }
    for (const acceptedProvenance of accepted || []) {
      if (!provenanceClasses.has(acceptedProvenance)) {
        errors.push(`Action ${label} consumer accepts unknown provenance ${String(acceptedProvenance)}.`);
      }
    }
    if (!argumentTypes.has(action?.canonicalArgumentType)) {
      errors.push(`Action ${label} has invalid canonical argument type ${String(action?.canonicalArgumentType)}.`);
    }
    for (const [field, value] of [
      ["producer surface", action?.producer?.surface],
      ["producer action ID", action?.producer?.actionId],
      ["consumer target", action?.consumer?.target],
      ["freshness owner", action?.freshnessOwner],
      ["authoritative outcome", action?.authoritativeOutcome],
    ]) {
      if (!requireNonEmptyString(value)) errors.push(`Action ${label} is missing ${field}.`);
    }
    if (String(action?.producer?.actionId || "").startsWith("cloudsmith-")) {
      if (!contributedCommands.has(action.producer.actionId)) {
        errors.push(`Action ${label} producer command ${action.producer.actionId} is not contributed.`);
      }
    } else {
      const linkedMessages = webviewProducerByContract.get(label) || [];
      if (linkedMessages.length !== 1 || linkedMessages[0] !== action?.producer?.actionId) {
        errors.push(`Action ${label} producer action ${String(action?.producer?.actionId)} has no unique scripted WebView wiring.`);
      }
    }
    const testFile = action?.requiredTest?.file;
    const testName = action?.requiredTest?.name;
    if (!manifestFileTarget(testFile, root, repositoryFiles)) {
      errors.push(`Action ${label} test file is not a normalized Git-visible regular file: ${String(testFile)}.`);
    } else if (!requireNonEmptyString(testName)
      || !testSourceContains(root, testFile, testName, sourceOverrides)) {
      errors.push(`Action ${label} names missing test assertion in ${testFile}: ${String(testName)}.`);
    }
  }
}

function verifyScriptedWebviews(document, root, repositoryFiles, sourceOverrides, errors) {
  const inventories = Array.isArray(document?.scriptedWebviews) ? document.scriptedWebviews : [];
  const actionIds = new Set((document?.actions || []).map(action => action.id));
  const inventoriedProviders = new Set(inventories.map(item => item.provider));
  const scriptedProviders = repositoryFiles.filter(file => {
    if (!/^views\/[^/]+Provider\.js$/.test(file)) return false;
    const source = sourceFor(root, file, repositoryFiles, sourceOverrides);
    return source.includes("onDidReceiveMessage");
  });
  for (const provider of scriptedProviders) {
    if (!inventoriedProviders.has(provider)) {
      errors.push(`Scripted WebView provider has no message inventory: ${provider}.`);
    }
  }
  for (const webview of inventories) {
    const provider = webview?.provider;
    if (!manifestFileTarget(provider, root, repositoryFiles)) {
      errors.push(`WebView inventory ${String(webview?.id)} provider is not a normalized Git-visible regular file: ${String(provider)}.`);
      continue;
    }
    const source = stripJavaScriptComments(sourceFor(
      root,
      provider,
      repositoryFiles,
      sourceOverrides
    ));
    const messages = new Set();
    for (const command of webview?.commands || []) {
      if (messages.has(command?.message)) {
        errors.push(`WebView ${webview.id} declares duplicate message ${String(command?.message)}.`);
      }
      messages.add(command?.message);
      for (const [boundary, pattern] of [
        ["render", command?.renderPattern],
        ["parser", command?.parserPattern],
        ["handler", command?.handlerPattern],
        ["target", command?.targetPattern],
      ]) {
        if (!requireNonEmptyString(pattern) || !source.includes(pattern)) {
          errors.push(`WebView ${webview.id} message ${String(command?.message)} has no ${boundary} boundary matching ${String(pattern)}.`);
        }
      }
      if (!actionIds.has(command?.actionContract)) {
        errors.push(`WebView ${webview.id} message ${String(command?.message)} references missing action ${String(command?.actionContract)}.`);
      }
    }
    if (webview?.rendererKind === "data-command") {
      const rendered = new Set();
      const expression = /data-command=["']([A-Za-z][A-Za-z0-9]*)["']/g;
      let match;
      while ((match = expression.exec(source)) !== null) rendered.add(match[1]);
      for (const message of rendered) {
        if (!messages.has(message)) {
          errors.push(`WebView ${webview.id} renders unhandled data-command ${message}.`);
        }
      }
      for (const message of messages) {
        const command = (webview?.commands || []).find(item => item?.message === message);
        if (command?.renderChannel && command.renderChannel !== "data-command") continue;
        if (!rendered.has(message)) {
          errors.push(`WebView ${webview.id} declares message ${message} but never renders it.`);
        }
      }
    }
  }
}

function sourceFor(root, file, repositoryFiles, sourceOverrides) {
  return Object.prototype.hasOwnProperty.call(sourceOverrides, file)
    ? sourceOverrides[file]
    : fs.readFileSync(resolveGitVisibleRegularFile(file, repositoryFiles, root), "utf8");
}

function manifestFileTarget(file, root, repositoryFiles) {
  if (!requireNonEmptyString(file)) return null;
  try {
    return resolveGitVisibleRegularFile(file, repositoryFiles, root);
  } catch {
    return null;
  }
}

function main() {
  const result = verifyQualityContracts();
  if (result.errors.length > 0) {
    for (const error of result.errors) console.error(`quality: ${error}`);
    process.exitCode = 1;
    return;
  }
  console.log(`Verified ${result.workflowCount} critical workflow contracts and every declared action/WebView boundary.`);
}

if (require.main === module) main();

module.exports = { verifyQualityContracts };

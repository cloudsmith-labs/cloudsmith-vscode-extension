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
  const deepWorkflowPath = ".github/workflows/deep-quality.yml";
  const workflowPath = ".github/workflows/main.yml";
  if (manifest?.scripts?.["quality:verify-evidence"]
    !== "node scripts/quality/verify-handoff.js") {
    errors.push("Package scripts must expose the exact quality evidence handoff verifier.");
  }
  if (manifest?.scripts?.["quality:verify-mutation-evidence"]
    !== "node scripts/quality/verify-mutation-handoff.js") {
    errors.push("Package scripts must expose the exact mutation evidence handoff verifier.");
  }
  let deepWorkflowTarget;
  let workflowTarget;
  try {
    resolveGitVisibleRegularFile(verifierPath, repositoryFiles, root);
    resolveGitVisibleRegularFile(mutationVerifierPath, repositoryFiles, root);
    deepWorkflowTarget = resolveGitVisibleRegularFile(deepWorkflowPath, repositoryFiles, root);
    workflowTarget = resolveGitVisibleRegularFile(workflowPath, repositoryFiles, root);
  } catch {
    errors.push("Quality evidence handoff source and CI workflow must be Git-visible regular files.");
    return;
  }
  const deepWorkflow = verifiedSource(deepWorkflowPath, deepWorkflowTarget, sourceOverrides);
  const workflow = verifiedSource(workflowPath, workflowTarget, sourceOverrides);
  const workflowDocument = parseCiWorkflow(workflow);
  const deepWorkflowDocument = parseCiWorkflow(deepWorkflow);
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
      "build-candidate": 0,
    })) {
    errors.push(
      "CI must verify the exact changed-mutation evidence immediately before a verifier-gated upload."
    );
  }
  if (!validDeepWorkflowEnvelope(deepWorkflowDocument)
    || !isDeepStrictEqual(
      deepWorkflowDocument?.jobs?.["core-mutation"],
      expectedCoreMutationJob()
    )
    || !validArtifactUploadInventory(deepWorkflowDocument, {
      "core-mutation": 1,
      "black-box-ui-boundary": 1,
    })) {
    errors.push(
      "Deep CI must verify exact core-mutation evidence before a verifier-gated upload."
    );
  }
}

const CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1";
const SETUP_NODE_ACTION = "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020";
const UPLOAD_ACTION = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a";
const QUALITY_BASE = "${{ github.event_name == 'push' && github.event.before || 'origin/main' }}";

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
    && isDeepStrictEqual(document.env, { NODE_VERSION: "22.23.2" })
    && isDeepStrictEqual(Object.keys(document.jobs || {}).sort(), [
      "build-candidate",
      "extension-tests",
      "mutation",
      "package",
      "quality",
    ]);
}

function validDeepWorkflowEnvelope(document) {
  return isPlainObject(document)
    && isDeepStrictEqual(Object.keys(document).sort(), ["env", "jobs", "name", "on", "permissions"])
    && isDeepStrictEqual(document.on, { workflow_dispatch: null })
    && isDeepStrictEqual(document.permissions, { contents: "read" })
    && isDeepStrictEqual(document.env, { NODE_VERSION: "22.23.2" })
    && isDeepStrictEqual(Object.keys(document.jobs || {}).sort(), [
      "black-box-ui-boundary",
      "core-mutation",
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
        name: "Verify exact quality evidence handoff",
        id: "quality_evidence_handoff",
        if: "${{ always() }}",
        run: "npm run quality:verify-evidence -- --gate-profile fast",
      },
      {
        name: "Upload quality impact and report evidence",
        if: "${{ always() && steps.quality_evidence_handoff.outcome == 'success' }}",
        uses: UPLOAD_ACTION,
        with: {
          name: "quality-evidence-${{ github.sha }}-${{ github.run_attempt }}",
          path: ".quality/impact.json\n.quality/gates/fast.json\n.quality/gates/fast/*.json\n.quality/report.json\n.quality/report.md\n",
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
          EXPECTED_SOURCE_SHA: "${{ github.sha }}",
        },
        run: "npm run quality:verify-mutation-evidence -- --base \"$QUALITY_BASE\" --expected-exit-code \"$EXPECTED_MUTATION_EXIT_CODE\" --expected-run-outcome \"$EXPECTED_MUTATION_OUTCOME\" --expected-source-sha \"$EXPECTED_SOURCE_SHA\"",
      },
      {
        name: "Upload mutation evidence",
        if: "${{ always() && steps.mutation_evidence_handoff.outcome == 'success' }}",
        uses: UPLOAD_ACTION,
        with: {
          name: "mutation-evidence-${{ github.sha }}-${{ github.run_attempt }}",
          path: ".quality/mutation/summary-changed.json\n.quality/mutation/mutation.json\n",
          "if-no-files-found": "error",
          "include-hidden-files": true,
          "retention-days": 30,
        },
      },
    ],
  };
}

function expectedCoreMutationJob() {
  return {
    name: "Core mutation",
    "runs-on": "ubuntu-24.04",
    "timeout-minutes": 45,
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
          EXPECTED_SOURCE_SHA: "${{ github.sha }}",
        },
        run: "npm run quality:verify-mutation-evidence -- --mode core --expected-exit-code \"$EXPECTED_MUTATION_EXIT_CODE\" --expected-run-outcome \"$EXPECTED_MUTATION_OUTCOME\" --expected-source-sha \"$EXPECTED_SOURCE_SHA\"",
      },
      {
        name: "Upload core mutation evidence",
        if: "${{ always() && steps.mutation_evidence_handoff.outcome == 'success' }}",
        uses: UPLOAD_ACTION,
        with: {
          name: "core-mutation-evidence-${{ github.sha }}-${{ github.run_attempt }}",
          path: ".quality/mutation/summary-core.json\n.quality/mutation/mutation.json\n",
          "if-no-files-found": "error",
          "include-hidden-files": true,
          "retention-days": 30,
        },
      },
    ],
  };
}

function checkoutStep(name, history) {
  const withOptions = { "persist-credentials": false };
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
  if (evidence?.layer === "black-box-ui" && mode !== "rendered-dom-activation") {
    errors.push(`Workflow ${workflowId} black-box-ui evidence must prove rendered DOM activation.`);
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

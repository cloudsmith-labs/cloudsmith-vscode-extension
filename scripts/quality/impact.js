// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const {
  ROOT,
  matchesPattern,
  readJson,
  uniqueSorted,
  writeJson,
} = require("./common");
const { sourceIdentity } = require("./evidence");
const { MUTATION_GLOBAL_OWNERS } = require("./run-mutation");

const DEFAULT_BASE = "origin/main";
const DEFAULT_OUTPUT = ".quality/impact.json";
const QUALITY_VERIFY_COMMAND = "node scripts/quality/verify.js";
const CANONICAL_TOOLCHAIN_PIN_FILES = new Set([
  ".node-version",
  ".npm-integrity",
  ".npm-version",
]);
const CANONICAL_TOOLCHAIN_FILES = new Set([
  ...CANONICAL_TOOLCHAIN_PIN_FILES,
  "scripts/quality/candidate-binding.js",
  "scripts/quality/canonical-node-runtime.js",
  "scripts/quality/gate.js",
  "scripts/quality/non-auth-environment.js",
  "scripts/quality/prepare-qualification.js",
  "scripts/quality/run-mutation.js",
  "scripts/quality/run-ui-smoke.js",
  "scripts/quality/verify-ui-evidence.js",
  "scripts/release/package-vsix.js",
  "scripts/release/verify-vsix.js",
]);
const TEST_COMMANDS_BY_LAYER = Object.freeze({
  unit: "npm run test:node",
  contract: "npm run test:node",
  "extension-host": "npm run test:vscode",
  "black-box-ui": "npm run test:ui:smoke",
  "live-protocol": "npm run test:live",
});

class ImpactAnalysisError extends Error {
  constructor(message, report = null) {
    super(message);
    this.name = "ImpactAnalysisError";
    this.report = report;
  }
}

function normalizeChangedPath(value) {
  const normalized = String(value || "")
    .replace(/\\/g, "/")
    .replace(/^\.\//, "")
    .replace(/\/{2,}/g, "/");
  if (
    !normalized
    || /[\u0000-\u001f\u007f]/.test(normalized)
    || path.posix.isAbsolute(normalized)
    || /^[A-Za-z]:\//.test(normalized)
    || normalized === ".."
    || normalized.startsWith("../")
    || normalized.includes("/../")
  ) {
    throw new ImpactAnalysisError(`Invalid changed path: ${String(value)}`);
  }
  return normalized;
}

function normalizeOutputPath(value) {
  const normalized = normalizeChangedPath(value);
  if (!normalized.startsWith(".quality/")) {
    throw new ImpactAnalysisError("Impact output must stay under .quality/.");
  }
  return normalized;
}

function parseNameStatus(output, source = "git") {
  if (!output) return [];
  const fields = String(output).split("\0");
  if (fields[fields.length - 1] === "") fields.pop();
  const records = [];
  for (let index = 0; index < fields.length;) {
    const status = fields[index++];
    if (!status) throw new ImpactAnalysisError(`Malformed ${source} name-status output.`);
    if (/^[RC](?:\d{1,3})?$/.test(status)) {
      if (index + 1 >= fields.length) {
        throw new ImpactAnalysisError(`Truncated ${source} rename/copy record.`);
      }
      const oldPath = normalizeChangedPath(fields[index++]);
      const newPath = normalizeChangedPath(fields[index++]);
      records.push({ source, status, oldPath, newPath });
      continue;
    }
    if (index >= fields.length) {
      throw new ImpactAnalysisError(`Truncated ${source} change record.`);
    }
    records.push({ source, status, path: normalizeChangedPath(fields[index++]) });
  }
  return records;
}

function parseUntracked(output, source = "untracked") {
  if (!output) return [];
  return String(output)
    .split("\0")
    .filter(Boolean)
    .map(file => ({ source, status: "?", path: normalizeChangedPath(file) }));
}

function recordKey(record) {
  return [
    record.source,
    record.status,
    record.oldPath || "",
    record.newPath || "",
    record.path || "",
  ].join("\0");
}

function mergeChangeRecords(...recordGroups) {
  const records = [];
  const seen = new Set();
  for (const record of recordGroups.flat()) {
    const normalized = record.oldPath || record.newPath
      ? {
        source: String(record.source || "unknown"),
        status: String(record.status || "M"),
        oldPath: normalizeChangedPath(record.oldPath),
        newPath: normalizeChangedPath(record.newPath),
      }
      : {
        source: String(record.source || "unknown"),
        status: String(record.status || "M"),
        path: normalizeChangedPath(record.path),
      };
    const key = recordKey(normalized);
    if (seen.has(key)) continue;
    seen.add(key);
    records.push(normalized);
  }
  return records.sort((left, right) => recordKey(left).localeCompare(recordKey(right)));
}

function changedFilesFromRecords(records) {
  return uniqueSorted(records.flatMap(record => (
    record.oldPath || record.newPath
      ? [record.oldPath, record.newPath]
      : [record.path]
  )).filter(Boolean));
}

function runGit(root, args, options = {}) {
  const result = (options.spawnSync || spawnSync)("git", args, {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.signal || result.status !== 0) {
    const detail = String(result.stderr || result.stdout || "").trim();
    throw new ImpactAnalysisError(
      `git ${args.join(" ")} failed${detail ? `: ${detail}` : "."}`
    );
  }
  return String(result.stdout || "");
}

function collectGitChanges(options = {}) {
  const root = options.root || ROOT;
  const base = options.base || DEFAULT_BASE;
  const git = args => runGit(root, args, options);
  const sourceSha = git(["rev-parse", "--verify", "HEAD"]).trim();
  const baseSha = git(["merge-base", base, "HEAD"]).trim();
  const committed = parseNameStatus(
    git(["diff", "--name-status", "-z", "--find-renames", `${base}...HEAD`]),
    "committed"
  );
  const staged = parseNameStatus(
    git(["diff", "--cached", "--name-status", "-z", "--find-renames"]),
    "staged"
  );
  const unstaged = parseNameStatus(
    git(["diff", "--name-status", "-z", "--find-renames"]),
    "unstaged"
  );
  const untracked = parseUntracked(
    git(["ls-files", "--others", "--exclude-standard", "-z"])
  );
  const records = mergeChangeRecords(committed, staged, unstaged, untracked);
  return {
    mode: "git",
    base,
    baseSha,
    sourceSha,
    records,
    files: changedFilesFromRecords(records),
  };
}

function explicitChanges(files, options = {}) {
  const normalized = uniqueSorted(files.map(normalizeChangedPath));
  return {
    mode: "explicit",
    base: options.base || null,
    baseSha: options.baseSha || null,
    sourceSha: options.sourceSha || resolveHeadSha(options.root || ROOT, options),
    records: normalized.map(file => ({ source: "explicit", status: "M", path: file })),
    files: normalized,
  };
}

function resolveHeadSha(root, options = {}) {
  if (options.sourceSha) return options.sourceSha;
  return runGit(root, ["rev-parse", "--verify", "HEAD"], options).trim();
}

function isTestFile(file) {
  return file.startsWith("test/") || file.startsWith("ui-test/");
}

function isManifestFile(file) {
  return CANONICAL_TOOLCHAIN_PIN_FILES.has(file)
    || file === "package.json"
    || file === "package-lock.json"
    || file === ".vscode-test.mjs"
    || file === "stryker.config.mjs"
    || file === "extester.config.json"
    || file.startsWith(".github/workflows/")
    || file.startsWith("quality/");
}

function isRuntimeFile(file, productionRoots) {
  return productionRoots.some(root => file === root || file.startsWith(`${root}/`));
}

function matchingEvidence(workflow, file) {
  return (workflow.evidence || []).filter(item => matchesPattern(file, item.testFile));
}

function buildTestCommandMap(root = ROOT) {
  const inventoryPath = path.join(root, "test", "testInventories.js");
  if (!fs.existsSync(inventoryPath)) return new Map();
  const resolved = require.resolve(inventoryPath);
  delete require.cache[resolved];
  const inventories = require(resolved);
  const result = new Map();
  const add = (files, command) => {
    for (const file of files || []) {
      const normalized = normalizeChangedPath(file);
      if (!result.has(normalized)) result.set(normalized, new Set());
      result.get(normalized).add(command);
    }
  };
  add(inventories.STANDALONE_NODE_TESTS, "npm run test:node");
  add(inventories.VSCODE_CORE_TESTS, "npm run test:vscode");
  add(inventories.VSCODE_SMOKE_TESTS, "npm run test:vscode");
  add(inventories.LIVE_TESTS, "npm run test:live");
  add(inventories.SSO_LIVE_TESTS, "npm run test:sso-live");
  return result;
}

function resolveRelativeTestDependency(root, importer, request) {
  if (typeof request !== "string" || !request.startsWith(".")) return null;
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(importer), request));
  if (base === ".." || base.startsWith("../") || !base.startsWith("test/")) return null;
  for (const candidate of [base, `${base}.js`, `${base}/index.js`]) {
    const target = path.join(root, ...candidate.split("/"));
    if (fs.existsSync(target) && fs.lstatSync(target).isFile()) return candidate;
  }
  return null;
}

function directRelativeTestDependencies(root, file) {
  const target = path.join(root, ...file.split("/"));
  if (!fs.existsSync(target) || !fs.lstatSync(target).isFile()) return [];
  const source = fs.readFileSync(target, "utf8");
  const requests = [];
  const expression = /\brequire\s*\(\s*["']([^"']+)["']\s*\)|\bfrom\s+["']([^"']+)["']/gu;
  for (const match of source.matchAll(expression)) {
    const dependency = resolveRelativeTestDependency(root, file, match[1] || match[2]);
    if (dependency) requests.push(dependency);
  }
  return uniqueSorted(requests);
}

function buildTestOwnershipMap(root = ROOT, testCommandMap = buildTestCommandMap(root)) {
  const ownersByDependency = new Map();
  for (const owner of testCommandMap.keys()) {
    const pending = [owner];
    const visited = new Set();
    while (pending.length > 0) {
      const current = pending.pop();
      for (const dependency of directRelativeTestDependencies(root, current)) {
        if (!ownersByDependency.has(dependency)) ownersByDependency.set(dependency, new Set());
        ownersByDependency.get(dependency).add(owner);
        if (!visited.has(dependency)) {
          visited.add(dependency);
          pending.push(dependency);
        }
      }
    }
  }
  return ownersByDependency;
}

function addWorkflowReason(workflowReasons, workflowId, kind, value) {
  if (!workflowReasons.has(workflowId)) {
    workflowReasons.set(workflowId, {
      productionFiles: new Set(),
      testFiles: new Set(),
      actionIds: new Set(),
      productionActionIds: new Set(),
      manifestFiles: new Set(),
    });
  }
  workflowReasons.get(workflowId)[kind].add(value);
}

function selectImpact(files, workflowsDocument, actionDocument, testOwnershipMap = new Map()) {
  const workflows = Array.isArray(workflowsDocument?.workflows)
    ? workflowsDocument.workflows
    : [];
  const actions = Array.isArray(actionDocument?.actions) ? actionDocument.actions : [];
  const workflowsById = new Map(workflows.map(workflow => [workflow.id, workflow]));
  const actionsById = new Map(actions.map(action => [action.id, action]));
  const workflowReasons = new Map();
  const selectedActionIds = new Set();
  const productionActionIds = new Set();
  const directRuntimeMappings = new Map();

  for (const file of files) {
    const evidenceFiles = uniqueSorted([file, ...(testOwnershipMap.get(file) || [])]);
    for (const workflow of workflows) {
      const productionMatches = (workflow.productionAreas || [])
        .filter(pattern => matchesPattern(file, pattern));
      if (productionMatches.length > 0) {
        addWorkflowReason(workflowReasons, workflow.id, "productionFiles", file);
        if (!directRuntimeMappings.has(file)) directRuntimeMappings.set(file, new Set());
        directRuntimeMappings.get(file).add(workflow.id);
      }
      for (const evidenceFile of evidenceFiles) {
        if (isTestFile(file) && matchingEvidence(workflow, evidenceFile).length > 0) {
          addWorkflowReason(workflowReasons, workflow.id, "testFiles", evidenceFile);
        }
      }
    }
    for (const action of actions) {
      if (isTestFile(file) && evidenceFiles.some(evidenceFile => (
        matchesPattern(evidenceFile, action.requiredTest?.file || "")
      ))) {
        selectedActionIds.add(action.id);
        for (const evidenceFile of evidenceFiles.filter(candidate => (
          matchesPattern(candidate, action.requiredTest?.file || "")
        ))) addWorkflowReason(workflowReasons, action.workflow, "testFiles", evidenceFile);
        addWorkflowReason(workflowReasons, action.workflow, "actionIds", action.id);
      }
      if (file === "package.json") {
        selectedActionIds.add(action.id);
        productionActionIds.add(action.id);
      }
    }
    for (const webview of actionDocument?.scriptedWebviews || []) {
      if (!matchesPattern(file, webview.provider || "")) continue;
      for (const command of webview.commands || []) {
        if (actionsById.has(command.actionContract)) {
          selectedActionIds.add(command.actionContract);
          productionActionIds.add(command.actionContract);
        }
      }
    }
  }

  if (files.includes("quality/critical-workflows.json")) {
    for (const workflow of workflows) {
      addWorkflowReason(
        workflowReasons,
        workflow.id,
        "manifestFiles",
        "quality/critical-workflows.json"
      );
    }
  }
  if (files.includes("quality/action-contracts.json")) {
    for (const action of actions) {
      selectedActionIds.add(action.id);
      addWorkflowReason(
        workflowReasons,
        action.workflow,
        "manifestFiles",
        "quality/action-contracts.json"
      );
    }
  }

  let changed = true;
  while (changed) {
    changed = false;
    for (const [workflowId, reason] of [...workflowReasons]) {
      if (reason.productionFiles.size === 0 && reason.productionActionIds.size === 0) continue;
      const workflow = workflowsById.get(workflowId);
      const relatedActions = [
        ...(workflow?.actionContractIds || []),
        ...actions.filter(action => action.workflow === workflowId).map(action => action.id),
      ];
      for (const actionId of relatedActions) {
        if (!actionsById.has(actionId)) continue;
        if (!selectedActionIds.has(actionId)) {
          selectedActionIds.add(actionId);
          changed = true;
        }
        productionActionIds.add(actionId);
      }
    }
    for (const actionId of [...selectedActionIds]) {
      const action = actionsById.get(actionId);
      if (!action || workflowReasons.has(action.workflow)) continue;
      addWorkflowReason(
        workflowReasons,
        action.workflow,
        productionActionIds.has(actionId) ? "productionActionIds" : "actionIds",
        actionId
      );
      changed = true;
    }
  }

  for (const actionId of selectedActionIds) {
    const action = actionsById.get(actionId);
    if (action && workflowReasons.has(action.workflow)) {
      workflowReasons.get(action.workflow).actionIds.add(actionId);
      if (productionActionIds.has(actionId)) {
        workflowReasons.get(action.workflow).productionActionIds.add(actionId);
      }
    }
  }

  return {
    workflowsById,
    actionsById,
    workflowReasons,
    selectedActionIds,
    directRuntimeMappings,
  };
}

function applyRenameOwnership(selection, records) {
  for (const record of records || []) {
    if (!/^[RC](?:\d{1,3})?$/.test(record.status || "")) continue;
    if (!record.oldPath || !record.newPath) continue;
    if (selection.directRuntimeMappings.has(record.oldPath)) continue;
    const owners = selection.directRuntimeMappings.get(record.newPath);
    if (!owners || owners.size === 0) continue;
    selection.directRuntimeMappings.set(record.oldPath, new Set(owners));
    for (const workflowId of owners) {
      addWorkflowReason(selection.workflowReasons, workflowId, "productionFiles", record.oldPath);
    }
  }
}

function inferTestLayer(file) {
  if (file.startsWith("ui-test/")) return "black-box-ui";
  if (file.startsWith("test/integration/")) return "contract";
  return "unit";
}

function requiredEvidence(files, selection, testCommandMap, testOwnershipMap = new Map()) {
  const layers = new Set();
  const commands = new Set();
  const evidencedTestFiles = new Set();
  for (const [workflowId, reason] of selection.workflowReasons) {
    const workflow = selection.workflowsById.get(workflowId);
    if (!workflow) continue;
    if (reason.productionFiles.size > 0 || reason.productionActionIds.size > 0) {
      for (const layer of workflow.requiredLayers || []) layers.add(layer);
      for (const command of workflow.targetCommands || []) commands.add(command);
      continue;
    }
    if (reason.manifestFiles.size > 0) {
      layers.add("contract");
      commands.add(QUALITY_VERIFY_COMMAND);
      continue;
    }
    for (const file of reason.testFiles) {
      const evidence = matchingEvidence(workflow, file);
      if (evidence.length > 0) evidencedTestFiles.add(file);
      for (const item of evidence) layers.add(item.layer);
      const mappedCommands = testCommandMap.get(file);
      if (mappedCommands) {
        for (const command of mappedCommands) commands.add(command);
      } else {
        for (const item of evidence) {
          const command = TEST_COMMANDS_BY_LAYER[item.layer];
          if (command && item.layer !== "live-protocol") commands.add(command);
        }
      }
    }
  }
  for (const file of files.filter(isTestFile)) {
    const commandFiles = uniqueSorted([file, ...(testOwnershipMap.get(file) || [])]);
    const mappedCommands = new Set(commandFiles.flatMap(commandFile => (
      [...(testCommandMap.get(commandFile) || [])]
    )));
    if (mappedCommands.size > 0) {
      for (const command of mappedCommands) commands.add(command);
      if (mappedCommands.has("npm run test:vscode")) layers.add("extension-host");
      if (mappedCommands.has("npm run test:ui:smoke")) layers.add("black-box-ui");
      if (mappedCommands.has("npm run test:live")
        || mappedCommands.has("npm run test:sso-live")) layers.add("live-protocol");
      if (mappedCommands.has("npm run test:node")) layers.add("unit");
    } else if (!commandFiles.some(candidate => evidencedTestFiles.has(candidate))) {
      const layer = inferTestLayer(file);
      layers.add(layer);
      const command = TEST_COMMANDS_BY_LAYER[layer];
      if (command) commands.add(command);
    }
  }
  if (files.some(file => file.startsWith("scripts/quality/") || file === "test/qualityHarness.test.js")) {
    layers.add("unit");
    commands.add("npm run test:node");
  }
  if (files.some(file => CANONICAL_TOOLCHAIN_FILES.has(file))) {
    layers.add("black-box-ui");
    layers.add("contract");
    layers.add("unit");
    commands.add(QUALITY_VERIFY_COMMAND);
    commands.add("npm run package");
    commands.add("npm run test:mutation:core");
    commands.add("npm run test:node");
    commands.add("npm run test:ui:smoke");
  }
  if (files.some(file => MUTATION_GLOBAL_OWNERS.includes(file))) {
    layers.add("unit");
    commands.add("npm run test:node");
    commands.add("npm run test:mutation:core");
  }
  if (files.some(file => (
    file === "extester.config.json"
    || file.startsWith("ui-test/")
    || file === "scripts/quality/run-ui-smoke.js"
  ))) {
    layers.add("black-box-ui");
    commands.add("npm run test:ui:smoke");
  }
  if (files.some(file => file.startsWith(".github/workflows/"))) {
    layers.add("contract");
    commands.add(QUALITY_VERIFY_COMMAND);
    commands.add("npm run test:node");
  }
  return { layers: uniqueSorted(layers), commands: uniqueSorted(commands) };
}

function highRiskCategories(files, selectedWorkflows, selectedActions) {
  const categories = new Set();
  const workflowIds = new Set(selectedWorkflows.map(workflow => workflow.id));
  const riskClasses = new Set(selectedWorkflows.flatMap(workflow => workflow.riskClasses || []));
  const actionSurfaces = selectedActions.map(action => action.producer?.surface || "").join(" ");
  const canonicalArguments = new Set(selectedActions.map(action => action.canonicalArgumentType));
  const hasFile = expression => files.some(file => expression.test(file));

  if (hasFile(/^(commands\/|extension\.js$|package\.json$)/) || selectedActions.length > 0) {
    categories.add("commands");
  }
  if (
    hasFile(/^views\/(?:vulnerability|quarantineExplain|complianceReport|upstreamDetail|upstreamPreview)Provider\.js$/)
    || /WebView/.test(actionSurfaces)
  ) categories.add("webviews");
  if (
    hasFile(/^views\/(?:cloudsmith|search|dependencyHealth|help)Provider\.js$/)
    || hasFile(/^models\/.+Node\.js$/)
  ) categories.add("tree-data-provider");
  if (
    files.includes("package.json")
    || hasFile(/^models\/.+Node\.js$/)
    || hasFile(/^views\/(?:cloudsmith|search|dependencyHealth|help)Provider\.js$/)
  ) {
    categories.add("context-value-menu-when");
  }
  if (riskClasses.has("auth-capability") || hasFile(/(?:auth|credential|connection)/i)) {
    categories.add("auth");
  }
  if (workflowIds.has("WF-SEARCH-FIRST-PAGE") || hasFile(/search(?:Intent|QueryBuilder|Provider|\.js)/)) {
    categories.add("query-construction");
  }
  if (workflowIds.has("WF-INSTALL-GUIDANCE") || hasFile(/installCommand/i)) {
    categories.add("install-commands");
  }
  if (riskClasses.has("pagination") || hasFile(/(?:paginatedFetch|loadMore)/i)) {
    categories.add("pagination");
  }
  if (
    hasFile(/(?:Scheduler|paginatedFetch|activationOwner|accountLifecycle)/)
    || workflowIds.has("WF-DEPENDENCY-COVERAGE-SETTLEMENT")
    || (riskClasses.has("async-authority")
      && (riskClasses.has("boundedness") || riskClasses.has("stale-publication")))
  ) categories.add("async-schedulers");
  if (
    riskClasses.has("canonical-identity")
    || hasFile(/(?:packageAdapters|packageActionCapabilities|dependencyAdapterRegistry|dependencyRecord)/)
  ) categories.add("canonical-adapters");
  if (
    canonicalArguments.has("validated-external-url")
    || hasFile(/(?:webAppUrls|registryEndpoints|apiEndpoint|helpLinks|ssoProtocol)/i)
  ) categories.add("url-redirect-handling");

  return uniqueSorted(categories);
}

function fileState(root, file) {
  const target = path.join(root, file);
  if (!fs.existsSync(target)) return "missing";
  const stat = fs.lstatSync(target);
  if (stat.isSymbolicLink()) {
    return `symlink:${crypto.createHash("sha256").update(fs.readlinkSync(target)).digest("hex")}`;
  }
  if (!stat.isFile()) return stat.isDirectory() ? "directory" : "other";
  return `sha256:${crypto.createHash("sha256").update(fs.readFileSync(target)).digest("hex")}`;
}

function stableFingerprint(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

const IMPACT_CORE_FIELDS = Object.freeze([
  "schemaVersion",
  "source",
  "analysisScope",
  "changes",
  "changedFiles",
  "fileStates",
  "runtimeFiles",
  "testFiles",
  "manifestFiles",
  "workflows",
  "workflowMappings",
  "actions",
  "requiredLayers",
  "commands",
  "workflowRiskClasses",
  "riskCategories",
  "unmappedRuntimeFiles",
]);

function impactFingerprint(value) {
  return stableFingerprint(Object.fromEntries(
    IMPACT_CORE_FIELDS.map(field => [field, value?.[field]])
  ));
}

function analyzeImpact(options = {}) {
  const root = options.root || ROOT;
  const workflowsDocument = options.workflows
    || readJson("quality/critical-workflows.json", root);
  const actionDocument = options.actions || readJson("quality/action-contracts.json", root);
  const changeSet = options.changeSet || explicitChanges(options.files || [], {
    ...options,
    root,
  });
  const identity = options.sourceIdentity || (changeSet.mode === "git"
    ? sourceIdentity(root)
    : { sha: changeSet.sourceSha, fingerprint: null });
  if (identity.sha !== changeSet.sourceSha) {
    throw new ImpactAnalysisError("Impact source changed while analysis was starting.");
  }
  const records = mergeChangeRecords(changeSet.records || []);
  const files = uniqueSorted([
    ...(changeSet.files || []).map(normalizeChangedPath),
    ...changedFilesFromRecords(records),
  ]);
  const testCommandMap = options.testCommandMap || buildTestCommandMap(root);
  const testOwnershipMap = options.testOwnershipMap || buildTestOwnershipMap(root, testCommandMap);
  const selection = selectImpact(files, workflowsDocument, actionDocument, testOwnershipMap);
  applyRenameOwnership(selection, records);
  const productionRoots = workflowsDocument.productionFileRoots || [];
  const runtimeFiles = files.filter(file => isRuntimeFile(file, productionRoots));
  const unmappedRuntimeFiles = runtimeFiles.filter(file => (
    !selection.directRuntimeMappings.has(file)
  ));
  const evidence = requiredEvidence(files, selection, testCommandMap, testOwnershipMap);
  const selectedWorkflows = [...selection.workflowReasons.keys()]
    .map(id => selection.workflowsById.get(id))
    .filter(Boolean)
    .sort((left, right) => left.id.localeCompare(right.id));
  const selectedActions = [...selection.selectedActionIds]
    .map(id => selection.actionsById.get(id))
    .filter(Boolean)
    .sort((left, right) => left.id.localeCompare(right.id));
  const workflowMappings = selectedWorkflows.map(workflow => {
    const reason = selection.workflowReasons.get(workflow.id);
    return {
      id: workflow.id,
      criticality: workflow.criticality,
      productionFiles: uniqueSorted(reason.productionFiles),
      testFiles: uniqueSorted(reason.testFiles),
      actionIds: uniqueSorted(reason.actionIds),
      productionActionIds: uniqueSorted(reason.productionActionIds),
      manifestFiles: uniqueSorted(reason.manifestFiles),
    };
  });
  const fileStates = files.map(file => ({
    file,
    state: options.fileStates?.[file] || fileState(root, file),
  }));
  const reportCore = {
    schemaVersion: 1,
    source: {
      mode: changeSet.mode,
      sha: changeSet.sourceSha,
      fingerprint: identity.fingerprint,
      base: changeSet.base,
      baseSha: changeSet.baseSha,
    },
    analysisScope: changeSet.mode === "git" ? "complete-working-tree" : "explicit-files",
    changes: records,
    changedFiles: files,
    fileStates,
    runtimeFiles,
    testFiles: files.filter(isTestFile),
    manifestFiles: files.filter(isManifestFile),
    workflows: selectedWorkflows.map(workflow => workflow.id),
    workflowMappings,
    actions: selectedActions.map(action => action.id),
    requiredLayers: evidence.layers,
    commands: evidence.commands,
    workflowRiskClasses: uniqueSorted(selectedWorkflows.flatMap(
      workflow => workflow.riskClasses || []
    )),
    riskCategories: highRiskCategories(files, selectedWorkflows, selectedActions),
    unmappedRuntimeFiles,
  };
  const fingerprint = impactFingerprint(reportCore);
  return {
    ...reportCore,
    key: {
      sha: changeSet.sourceSha,
      fingerprint,
    },
    analysisKey: `${changeSet.sourceSha}:${fingerprint}`,
    ok: unmappedRuntimeFiles.length === 0,
  };
}

function parseArguments(argv) {
  const environmentBase = String(process.env.QUALITY_BASE || "").trim();
  const result = {
    base: environmentBase || DEFAULT_BASE,
    files: null,
    output: DEFAULT_OUTPUT,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--base") {
      if (index + 1 >= argv.length) throw new ImpactAnalysisError("--base requires a value.");
      result.base = argv[++index];
    } else if (argument.startsWith("--base=")) {
      result.base = argument.slice("--base=".length);
    } else if (argument === "--output") {
      if (index + 1 >= argv.length) throw new ImpactAnalysisError("--output requires a value.");
      result.output = normalizeOutputPath(argv[++index]);
    } else if (argument.startsWith("--output=")) {
      result.output = normalizeOutputPath(argument.slice("--output=".length));
    } else if (argument === "--files") {
      const files = [];
      while (index + 1 < argv.length && !argv[index + 1].startsWith("--")) {
        files.push(...argv[++index].split(","));
      }
      if (files.length === 0) throw new ImpactAnalysisError("--files requires at least one path.");
      result.files = files.filter(Boolean);
    } else if (argument.startsWith("--files=")) {
      result.files = argument.slice("--files=".length).split(",").filter(Boolean);
      if (result.files.length === 0) {
        throw new ImpactAnalysisError("--files requires at least one path.");
      }
    } else {
      throw new ImpactAnalysisError(`Unknown impact option: ${argument}`);
    }
  }
  return result;
}

function printReport(report) {
  console.log(`Impact analysis ${report.analysisKey}`);
  console.log(`Changed files: ${report.changedFiles.join(", ") || "none"}`);
  console.log(`Workflows: ${report.workflows.join(", ") || "none"}`);
  console.log(`Actions: ${report.actions.join(", ") || "none"}`);
  console.log(`Required layers: ${report.requiredLayers.join(", ") || "none"}`);
  console.log(`Commands: ${report.commands.join(", ") || "none"}`);
  console.log(`Risk categories: ${report.riskCategories.join(", ") || "none"}`);
  if (report.unmappedRuntimeFiles.length > 0) {
    console.error(`Unmapped runtime files: ${report.unmappedRuntimeFiles.join(", ")}`);
  }
}

function requireMappedRuntime(report) {
  if (report.ok) return report;
  throw new ImpactAnalysisError(
    `Changed runtime files have no workflow mapping: ${report.unmappedRuntimeFiles.join(", ")}`,
    report
  );
}

function runImpact(options = {}) {
  const root = options.root || ROOT;
  const changeSet = options.changeSet || (
    options.files
      ? explicitChanges(options.files, { ...options, root })
      : collectGitChanges({ ...options, root })
  );
  const report = analyzeImpact({ ...options, root, changeSet });
  writeJson(normalizeOutputPath(options.output || DEFAULT_OUTPUT), report, root);
  return requireMappedRuntime(report);
}

function main() {
  try {
    const arguments_ = parseArguments(process.argv.slice(2));
    const report = runImpact(arguments_);
    printReport(report);
  } catch (error) {
    if (error.report) printReport(error.report);
    console.error(`quality:impact: ${error.message}`);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  DEFAULT_BASE,
  DEFAULT_OUTPUT,
  ImpactAnalysisError,
  analyzeImpact,
  applyRenameOwnership,
  buildTestCommandMap,
  buildTestOwnershipMap,
  changedFilesFromRecords,
  collectGitChanges,
  explicitChanges,
  highRiskCategories,
  impactFingerprint,
  mergeChangeRecords,
  normalizeChangedPath,
  normalizeOutputPath,
  parseArguments,
  parseNameStatus,
  parseUntracked,
  requireMappedRuntime,
  runImpact,
  stableFingerprint,
};

// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const { TextDecoder } = require("util");
const {
  ROOT,
  assertRepositoryRelativePath,
  gitVisibleFiles,
  isPlainObject,
  prepareOutputDirectory,
  readJson,
  removeOutputFile,
  resolveExistingRepositoryFile,
  summarizeMutationReport,
  uniqueSorted,
  writeJson,
} = require("./common");
const { assertCanonicalNodeRuntime } = require("./canonical-node-runtime");
const { fingerprint, sourceIdentity } = require("./evidence");
const { validateMutationToolchain } = require("./mutation-toolchain");

const REPORT = ".quality/mutation/mutation.json";
const STRYKER_REPORT_CONFIG_KEYS = Object.freeze([
  "allowConsoleColors",
  "allowEmpty",
  "appendPlugins",
  "checkerNodeArgs",
  "checkers",
  "cleanTempDir",
  "clearTextReporter",
  "commandRunner",
  "concurrency",
  "configFile",
  "coverageAnalysis",
  "dashboard",
  "disableBail",
  "disableTypeChecks",
  "dryRunOnly",
  "dryRunTimeoutMinutes",
  "eventReporter",
  "fileLogLevel",
  "force",
  "htmlReporter",
  "ignorePatterns",
  "ignoreStatic",
  "ignorers",
  "inPlace",
  "incremental",
  "incrementalFile",
  "jsonReporter",
  "logLevel",
  "maxConcurrentTestRunners",
  "maxTestRunnerReuse",
  "mochaOptions",
  "mutate",
  "mutator",
  "plugins",
  "reporters",
  "symlinkNodeModules",
  "tempDirName",
  "testFiles",
  "testRunner",
  "testRunnerNodeArgs",
  "thresholds",
  "timeoutFactor",
  "timeoutMS",
  "tsconfigFile",
  "warnings",
]);
const MUTATION_GLOBAL_OWNERS = Object.freeze([
  ".npm-integrity",
  ".npm-version",
  ".node-version",
  ".github/workflows/deep-quality.yml",
  ".github/workflows/main.yml",
  "package-lock.json",
  "package.json",
  "quality/mutation-baseline.json",
  "scripts/quality/canonical-node-runtime.js",
  "scripts/quality/common.js",
  "scripts/quality/evidence.js",
  "scripts/quality/mutation-baseline.js",
  "scripts/quality/mutation-toolchain.js",
  "scripts/quality/run-mutation.js",
  "scripts/quality/verify-mutation-handoff.js",
  "scripts/quality/verify-workflows.js",
  "stryker.config.mjs",
]);

function runMutation(options = {}) {
  const root = options.root || ROOT;
  const validateRuntime = options.assertCanonicalNodeRuntime
    || assertCanonicalNodeRuntime;
  validateRuntime(root, process.version);
  const entrypointArguments = options.argumentsList || process.argv.slice(2);
  const mode = entrypointArguments[0] || "changed";
  if (!new Set(["core", "changed"]).has(mode)) {
    throw new Error(`Unknown mutation mode: ${mode}`);
  }
  const baseline = readJson("quality/mutation-baseline.json", root);
  assertCanonicalMutationRuntime(baseline, root, process);
  assertValidMutationBaseline(baseline, root);
  assertMutationTestOwners(baseline, root);
  const argumentsList = entrypointArguments.slice(1);
  assertMutationGateArguments(mode, argumentsList);
  const source = sourceIdentity(root);
  const selection = mode === "changed"
    ? resolveMutationSelection(argumentsList, root)
    : fullMutationSelection(root);
  assertMutationRunStable(source, selection, mode, argumentsList, root);
  const targets = mode === "core"
    ? baseline.scope
    : selectMutationTargets(baseline.scope, selection.changedFiles, baseline.files);
  prepareOutputDirectory(".quality/mutation", root);
  removeOutputFile(`.quality/mutation/summary-${mode}.json`, root);
  removeOutputFile(REPORT, root);
  if (targets.length === 0) {
    assertMutationRunStable(source, selection, mode, argumentsList, root);
    const summary = receipt(mode, targets, {
      status: "not-applicable",
      reason: "no-configured-mutation-target-changed",
      mutants: 0,
      killed: 0,
      survived: 0,
      timeout: 0,
      noCoverage: 0,
      runtimeError: 0,
      compileError: 0,
      ignored: 0,
      score: null,
      files: {},
      survivors: [],
      strykerExitCode: null,
    }, { source, selection, rawReportFingerprint: null });
    writeStableMutationSummary(mode, summary, source, selection, argumentsList, root);
    console.log("Mutation gate is not applicable: no configured mutation target changed.");
    return;
  }

  const cli = path.join(root, "node_modules", "@stryker-mutator", "core", "bin", "stryker.js");
  const args = [cli, "run", "stryker.config.mjs", "--mutate", targets.join(",")];
  if (mode === "changed") args.push("--incremental", "--force");
  const spawn = options.spawnSync || spawnSync;
  const result = spawn(process.execPath, args, { cwd: root, encoding: "utf8", stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.signal) throw new Error(`Stryker terminated by signal ${result.signal}.`);
  if (!Number.isInteger(result.status) || result.status < 0 || result.status > 255) {
    throw new Error("Stryker produced no canonical process exit status.");
  }
  assertMutationRunStable(source, selection, mode, argumentsList, root);
  let reportArtifact;
  try {
    reportArtifact = readMutationReportArtifact(root);
  } catch {
    throw new Error(`Stryker did not write a safe ${REPORT} (exit ${String(result.status)}).`);
  }
  const report = reportArtifact.value;
  validateMutationTestOwnership(report, targets, baseline, root, mode);
  const derived = deriveMutationEvidence(report, targets);
  const candidate = receipt(mode, targets, {
    status: "passed",
    ...derived,
    strykerExitCode: result.status,
  }, {
    source,
    selection,
    rawReportFingerprint: reportArtifact.fingerprint,
  });
  try {
    if (result.status !== 0) {
      const failure = new Error(`Stryker exited ${String(result.status)}.`);
      failure.mutationExitCode = result.status;
      throw failure;
    }
    validateMutationSummary(candidate, baseline, mode);
    writeStableMutationSummary(mode, candidate, source, selection, argumentsList, root);
  } catch (error) {
    const failedValues = {
      ...candidate,
      status: "failed",
      reason: error.message,
    };
    delete failedValues.key;
    const failed = bindMutationSummaryKey(failedValues);
    writeStableMutationSummary(mode, failed, source, selection, argumentsList, root);
    throw error;
  }
}

function assertMutationGateArguments(mode, argumentsList = []) {
  if (mode === "core" && argumentsList.length > 0) {
    throw new Error("Core mutation mode does not accept changed-file selection options.");
  }
  if (mode === "changed") {
    const options = parseMutationSelectionArguments(argumentsList);
    if (options.files !== null) {
      throw new Error(
        "Changed mutation gate does not accept caller-authored --files selection; use --base."
      );
    }
  }
}

function changedMutationTargets(scope, argumentsList = [], fileBaselines = {}, root = ROOT) {
  const selection = resolveMutationSelection(argumentsList, root);
  return selectMutationTargets(scope, selection.changedFiles, fileBaselines);
}

function selectMutationTargets(scope, changedFiles, fileBaselines = {}) {
  const changedSet = new Set(changedFiles.map(file => assertRepositoryRelativePath(file)));
  const directOwners = new Set(scope.flatMap(file => [
    mutationTargetFile(file),
    ...(fileBaselines[file]?.testFiles || []),
  ]));
  if ([...changedSet].some(file => (
    MUTATION_GLOBAL_OWNERS.includes(file)
    || (isMutationSemanticOwner(file) && !directOwners.has(file))
  ))) return uniqueSorted(scope);
  return uniqueSorted(scope.filter(file => (
    changedSet.has(mutationTargetFile(file))
    || (fileBaselines[file]?.testFiles || []).some(testFile => changedSet.has(testFile))
  )));
}

function isMutationSemanticOwner(file) {
  return MUTATION_GLOBAL_OWNERS.includes(file)
    || /^(?:commands|domain|models|util|views)\/.+\.js$/u.test(file)
    || /^test\/.+\.js$/u.test(file)
    || /^scripts\/quality\/.+\.js$/u.test(file)
    || file === "extension.js";
}

function fullMutationSelection(root = ROOT) {
  const changedFiles = [];
  return {
    mode: "full-scope",
    base: null,
    baseSha: null,
    mergeBaseSha: null,
    changedFiles,
    fingerprint: workingTreeFingerprint(root, changedFiles),
  };
}

function resolveMutationSelection(argumentsList = [], root = ROOT) {
  const options = parseMutationSelectionArguments(argumentsList);
  if (options.files) {
    const changedFiles = uniqueSorted(options.files.split(",").map(file => {
      if (!file) throw new Error("--files requires nonempty comma-separated paths.");
      return assertRepositoryRelativePath(file);
    }));
    return {
      mode: "explicit-files",
      base: null,
      baseSha: null,
      mergeBaseSha: null,
      changedFiles,
      fingerprint: workingTreeFingerprint(root, changedFiles),
    };
  }
  const base = options.base || "origin/main";
  const baseSha = resolveGitCommit(base, root);
  const mergeBaseSha = runGitText(["merge-base", "HEAD", baseSha], root);
  if (!/^[a-f0-9]{40}$/u.test(mergeBaseSha)) {
    throw new Error(`git merge-base produced an invalid commit for ${base}.`);
  }
  const changedFiles = collectGitChangedFiles(mergeBaseSha, root);
  return {
    mode: "git",
    base,
    baseSha,
    mergeBaseSha,
    changedFiles,
    fingerprint: workingTreeFingerprint(root, changedFiles),
  };
}

function parseMutationSelectionArguments(argumentsList) {
  const options = { base: null, files: null };
  for (let index = 0; index < argumentsList.length; index += 1) {
    const argument = argumentsList[index];
    let name;
    let value;
    if (["--base", "--files"].includes(argument)) {
      name = argument.slice(2);
      value = argumentsList[++index];
    } else if (/^--(?:base|files)=/u.test(argument)) {
      const separator = argument.indexOf("=");
      name = argument.slice(2, separator);
      value = argument.slice(separator + 1);
    } else {
      throw new Error(`Unknown mutation selection option: ${String(argument)}`);
    }
    if (typeof value !== "string" || value.length === 0 || value !== value.trim()) {
      throw new Error(`--${name} requires at least one nonempty canonical value.`);
    }
    if (options[name] !== null) throw new Error(`--${name} may be specified only once.`);
    options[name] = value;
  }
  if (options.base && options.files) throw new Error("--base and --files are mutually exclusive.");
  return options;
}

function assertMutationTestOwners(baseline, root = ROOT, repositoryFiles = gitVisibleFiles(root)) {
  const visible = new Set(repositoryFiles);
  const scope = baseline?.scope;
  const files = baseline?.files;
  if (!Array.isArray(scope) || scope.length === 0) {
    throw new Error("Mutation baseline must declare a nonempty scope.");
  }
  if (!isPlainObject(files)
    || JSON.stringify(uniqueSorted(Object.keys(files))) !== JSON.stringify(uniqueSorted(scope))) {
    throw new Error("Mutation baseline scope and files must have exact target parity.");
  }
  if (new Set(scope).size !== scope.length) {
    throw new Error("Mutation baseline scope must not contain duplicate targets.");
  }
  const toolchainErrors = validateMutationToolchain(
    baseline,
    readJson("package.json", root),
    readJson("package-lock.json", root)
  );
  if (toolchainErrors.length > 0) throw new Error(toolchainErrors[0]);
  for (const target of scope) {
    let sourceFile;
    try {
      sourceFile = validatedMutationSourceFile(target);
    } catch {
      throw new Error(
        `Mutation target ${String(target)} must exist as a Git-visible regular source file.`
      );
    }
    let targetStat = null;
    try {
      targetStat = fs.lstatSync(resolveExistingRepositoryFile(sourceFile, root));
    } catch {
      // The stable failure below covers missing or unreadable target paths.
    }
    if (!visible.has(sourceFile) || !targetStat?.isFile() || targetStat.isSymbolicLink()) {
      throw new Error(
        `Mutation target ${String(target)} must exist as a Git-visible regular source file.`
      );
    }
    const owners = baseline?.files?.[target]?.testFiles;
    if (!Array.isArray(owners) || owners.length === 0
      || uniqueSorted(owners).length !== owners.length) {
      throw new Error(`Mutation target ${String(target)} must have unique test owners.`);
    }
    for (const owner of owners) {
      let normalizedOwner;
      try {
        normalizedOwner = validatedMutationOwner(owner);
      } catch {
        throw new Error(
          `Mutation target ${String(target)} test owner ${String(owner)} `
          + "must exist as a Git-visible regular test file."
        );
      }
      let stat = null;
      try {
        stat = fs.lstatSync(resolveExistingRepositoryFile(normalizedOwner, root));
      } catch {
        // The stable failure below covers missing or unreadable owner paths.
      }
      if (!visible.has(normalizedOwner) || !stat?.isFile() || stat.isSymbolicLink()) {
        throw new Error(
          `Mutation target ${String(target)} test owner ${String(owner)} `
          + "must exist as a Git-visible regular test file."
        );
      }
    }
  }
}

function assertValidMutationBaseline(baseline, root = ROOT) {
  const { validateMutationBaseline } = require("./mutation-baseline");
  const { errors } = validateMutationBaseline(baseline, { root });
  if (errors.length > 0) {
    throw new Error(`Invalid mutation baseline: ${errors.join(" ")}`);
  }
}

function assertCanonicalMutationRuntime(baseline, root = ROOT, runtime = process) {
  const versionPath = resolveExistingRepositoryFile(".node-version", root);
  const stat = fs.lstatSync(versionPath);
  if (stat.size <= 0 || stat.size > 32) {
    throw new Error("Canonical mutation Node version file is invalid.");
  }
  const declared = new TextDecoder("utf-8", { fatal: true })
    .decode(fs.readFileSync(versionPath));
  const expected = baseline?.tool?.nodeVersion;
  if (!/^\d+\.\d+\.\d+$/u.test(expected || "")
    || declared !== `${expected}\n`
    || runtime.version !== `v${expected}`) {
    throw new Error(
      `Mutation evidence requires exact Node v${String(expected)} from .node-version; `
      + `current runtime is ${String(runtime.version)}.`
    );
  }
}

function validateMutationTestOwnership(
  report,
  targets,
  baseline,
  root = ROOT,
  mode = "core"
) {
  validateMutationReportProvenance(report, targets, baseline, root, mode);
  if (!isPlainObject(report?.testFiles)) {
    throw new Error("Stryker report has no canonical test-file inventory.");
  }
  const configuredOwners = uniqueSorted((baseline?.scope || []).flatMap(
    target => baseline?.files?.[target]?.testFiles || []
  ));
  const reportedOwners = uniqueSorted(Object.keys(report.testFiles));
  if (JSON.stringify(reportedOwners) !== JSON.stringify(configuredOwners)) {
    throw new Error("Stryker report test-file inventory does not match canonical mutation owners.");
  }

  const ownerByTestId = new Map();
  for (const [owner, testFile] of Object.entries(report.testFiles)) {
    const normalizedOwner = validatedMutationOwner(owner);
    if (!Array.isArray(testFile?.tests)) {
      throw new Error(`Stryker report test owner ${owner} has no test inventory.`);
    }
    if (testFile.source !== fs.readFileSync(
      resolveExistingRepositoryFile(normalizedOwner, root),
      "utf8"
    )) {
      throw new Error(`Stryker report test owner ${owner} does not bind current source bytes.`);
    }
    for (const test of testFile.tests) {
      const id = test?.id;
      if (typeof id !== "string" || id.length === 0 || ownerByTestId.has(id)) {
        throw new Error("Stryker report has an invalid or duplicate test ID.");
      }
      ownerByTestId.set(id, owner);
    }
  }

  const mutantIds = new Set();
  const mutantFingerprints = new Set();
  for (const target of targets) {
    const sourceFile = validatedMutationSourceFile(target);
    const mutants = report?.files?.[sourceFile]?.mutants;
    if (!Array.isArray(mutants) || mutants.length === 0) {
      throw new Error(`Mutation target ${target} has no raw Stryker mutant evidence.`);
    }
    if (report.files[sourceFile]?.source
      !== fs.readFileSync(resolveExistingRepositoryFile(sourceFile, root), "utf8")) {
      throw new Error(`Mutation target ${target} does not bind current source bytes.`);
    }
    const range = mutationTargetRange(target);
    const observedOwners = new Set();
    for (const mutant of mutants) {
      validateRawMutantStatus(mutant);
      if (typeof mutant?.id !== "string" || mutant.id.length === 0
        || mutantIds.has(mutant.id)) {
        throw new Error("Stryker report has an invalid or duplicate raw mutant ID.");
      }
      mutantIds.add(mutant.id);
      const semanticFingerprint = survivorFingerprint(sourceFile, mutant);
      if (mutantFingerprints.has(semanticFingerprint)) {
        throw new Error("Stryker report has duplicate raw mutant semantics.");
      }
      mutantFingerprints.add(semanticFingerprint);
      if (!validMutationLocation(mutant?.location, report.files[sourceFile].source)
        || (range && (mutant.location.start.line < range.startLine
        || mutant.location.end.line > range.endLine
        ))) {
        throw new Error(`Mutation target ${target} has mutant evidence outside its declared range.`);
      }
      for (const id of [...(mutant.coveredBy || []), ...(mutant.killedBy || [])]) {
        const owner = ownerByTestId.get(String(id));
        if (!owner) {
          throw new Error(`Mutation target ${target} references an unknown Stryker test ID.`);
        }
        observedOwners.add(owner);
      }
    }
    const declaredOwners = uniqueSorted(baseline?.files?.[target]?.testFiles || []);
    if (JSON.stringify(uniqueSorted([...observedOwners])) !== JSON.stringify(declaredOwners)) {
      throw new Error(`Mutation target ${target} observed test ownership does not match its baseline.`);
    }
  }
}

function validateRawMutantStatus(mutant) {
  const commonKeys = [
    "coveredBy", "id", "location", "mutatorName", "replacement", "static", "status",
  ];
  let statusKeys = {
    Killed: ["killedBy", "statusReason", "testsCompleted"],
    Survived: ["testsCompleted"],
    Ignored: ["statusReason"],
    NoCoverage: [],
    CompileError: ["statusReason"],
    RuntimeError: ["statusReason"],
    Timeout: [],
  }[mutant?.status];
  if (mutant?.status === "Timeout"
    && Object.prototype.hasOwnProperty.call(mutant, "statusReason")) {
    statusKeys = ["statusReason"];
  }
  const exactKeys = statusKeys && uniqueSorted([...commonKeys, ...statusKeys]);
  const coveredBy = mutant?.coveredBy;
  if (!exactKeys
    || JSON.stringify(uniqueSorted(Object.keys(mutant || {}))) !== JSON.stringify(exactKeys)
    || typeof mutant.mutatorName !== "string" || mutant.mutatorName.length === 0
    || typeof mutant.replacement !== "string"
    || typeof mutant.static !== "boolean"
    || !Array.isArray(coveredBy)
    || coveredBy.some(id => typeof id !== "string" || id.length === 0)
    || new Set(coveredBy).size !== coveredBy.length) {
    throw new Error("Stryker report has invalid status-specific raw mutant evidence.");
  }
  if (mutant.status === "Killed") {
    if (!Array.isArray(mutant.killedBy) || mutant.killedBy.length === 0
      || new Set(mutant.killedBy).size !== mutant.killedBy.length
      || mutant.killedBy.some(id => typeof id !== "string" || !coveredBy.includes(id))
      || typeof mutant.statusReason !== "string" || mutant.statusReason.length === 0
      || !Number.isInteger(mutant.testsCompleted) || mutant.testsCompleted <= 0
      || mutant.testsCompleted > coveredBy.length) {
      throw new Error("Stryker killed mutant has incomplete test-failure evidence.");
    }
  } else if (mutant.status === "Survived") {
    if (coveredBy.length === 0
      || !Number.isInteger(mutant.testsCompleted)
      || mutant.testsCompleted !== coveredBy.length) {
      throw new Error("Stryker survived mutant has incomplete completed-test evidence.");
    }
  } else if (mutant.status === "Ignored") {
    if (mutant.static !== true || coveredBy.length !== 0
      || mutant.statusReason !== "Static mutant (and \"ignoreStatic\" was enabled)") {
      throw new Error("Stryker ignored mutant does not match the configured static policy.");
    }
  } else if (mutant.status === "NoCoverage") {
    if (mutant.static !== false || coveredBy.length !== 0) {
      throw new Error("Stryker uncovered mutant has contradictory coverage evidence.");
    }
  } else if (mutant.status !== "Timeout"
    && (typeof mutant.statusReason !== "string" || mutant.statusReason.length === 0)) {
    throw new Error(`Stryker ${mutant.status} mutant has no failure reason.`);
  } else if (mutant.status === "Timeout"
    && Object.prototype.hasOwnProperty.call(mutant, "statusReason")
    && (typeof mutant.statusReason !== "string" || mutant.statusReason.length === 0)) {
    throw new Error("Stryker timeout mutant has a malformed optional failure reason.");
  }
}

function validateMutationReportProvenance(report, targets, baseline, root, mode) {
  const configuredOwners = uniqueSorted((baseline?.scope || []).flatMap(
    target => baseline?.files?.[target]?.testFiles || []
  ));
  const expectedSources = uniqueSorted(targets.map(mutationTargetFile));
  const config = report?.config;
  const expectedThresholds = {
    high: baseline?.thresholds?.high,
    low: baseline?.thresholds?.low,
    break: 0,
  };
  const exactMochaKeys = ["no-config", "no-opts", "no-package", "spec", "ui"];
  const changedMode = mode === "changed";
  if (!new Set(["core", "changed"]).has(mode)
    || report?.schemaVersion !== "1.0"
    || typeof report.projectRoot !== "string"
    || path.resolve(report.projectRoot) !== path.resolve(root)
    || report.framework?.name !== "StrykerJS"
    || report.framework?.version !== baseline?.tool?.version
    || report.framework?.dependencies?.[baseline?.tool?.runner]
      !== baseline?.tool?.runnerVersion
    || report.framework?.dependencies?.[baseline?.tool?.engine]
      !== baseline?.tool?.engineVersion
    || !isPlainObject(config)
    || JSON.stringify(uniqueSorted(Object.keys(config)))
      !== JSON.stringify(uniqueSorted(STRYKER_REPORT_CONFIG_KEYS))
    || config.testRunner !== "mocha"
    || config.coverageAnalysis !== "perTest"
    || config.ignoreStatic !== true
    || config.allowEmpty !== false
    || !Array.isArray(config.mutate)
    || !Array.isArray(config.testFiles)
    || !Array.isArray(config.mochaOptions?.spec)
    || JSON.stringify(uniqueSorted(Object.keys(config.mochaOptions || {})))
      !== JSON.stringify(exactMochaKeys)
    || new Set(config.mutate).size !== config.mutate.length
    || new Set(config.testFiles).size !== config.testFiles.length
    || JSON.stringify(uniqueSorted(config.mutate)) !== JSON.stringify(uniqueSorted(targets))
    || JSON.stringify(uniqueSorted(config.testFiles)) !== JSON.stringify(configuredOwners)
    || config.mochaOptions?.ui !== "tdd"
    || config.mochaOptions?.["no-config"] !== true
    || config.mochaOptions?.["no-package"] !== true
    || config.mochaOptions?.["no-opts"] !== true
    || new Set(config.mochaOptions.spec).size !== config.mochaOptions.spec.length
    || JSON.stringify(uniqueSorted(config.mochaOptions.spec))
      !== JSON.stringify(configuredOwners)
    || config.configFile !== "stryker.config.mjs"
    || config.incremental !== changedMode
    || config.force !== changedMode
    || config.incrementalFile !== ".quality/mutation/stryker-incremental.json"
    || config.tempDirName !== ".stryker-tmp"
    || config.cleanTempDir !== "always"
    || config.concurrency !== 4
    || config.timeoutMS !== 10_000
    || config.timeoutFactor !== 1.5
    || config.disableBail !== false
    || config.disableTypeChecks !== true
    || config.dryRunOnly !== false
    || config.inPlace !== false
    || config.maxTestRunnerReuse !== 0
    || config.symlinkNodeModules !== true
    || JSON.stringify(config.plugins) !== JSON.stringify(["@stryker-mutator/*"])
    || JSON.stringify(config.appendPlugins) !== "[]"
    || JSON.stringify(config.checkers) !== "[]"
    || JSON.stringify(config.checkerNodeArgs) !== "[]"
    || JSON.stringify(config.testRunnerNodeArgs) !== "[]"
    || JSON.stringify(config.ignorers) !== "[]"
    || JSON.stringify(config.mutator) !== JSON.stringify({
      plugins: null,
      excludedMutations: [],
    })
    || JSON.stringify(config.ignorePatterns) !== JSON.stringify([
      ".vscode-test",
      ".quality",
      "internal_docs",
      "out",
      "coverage",
      "*.vsix",
    ])
    || JSON.stringify(config.reporters)
      !== JSON.stringify(["clear-text", "progress", "json", "html"])
    || config.jsonReporter?.fileName !== REPORT
    || config.htmlReporter?.fileName !== ".quality/mutation/mutation.html"
    || JSON.stringify(config.thresholds) !== JSON.stringify(expectedThresholds)
    || JSON.stringify(report.thresholds) !== JSON.stringify(expectedThresholds)
    || JSON.stringify(uniqueSorted(Object.keys(report.files || {})))
      !== JSON.stringify(expectedSources)) {
    throw new Error("Stryker report provenance does not match the canonical mutation run.");
  }
}

function validMutationLocation(location, source) {
  const start = location?.start;
  const end = location?.end;
  if (!(Number.isInteger(start?.line) && start.line > 0
    && Number.isInteger(end?.line) && end.line > 0
    && Number.isInteger(start?.column) && start.column >= 0
    && Number.isInteger(end?.column) && end.column >= 0
    && (end.line > start.line || (end.line === start.line && end.column >= start.column)))) {
    return false;
  }
  const lines = String(source).split("\n").map(line => line.endsWith("\r")
    ? line.slice(0, -1)
    : line);
  return start.line <= lines.length
    && end.line <= lines.length
    && start.column <= lines[start.line - 1].length
    && end.column <= lines[end.line - 1].length + 1;
}

function mutationTargetRange(target) {
  const match = String(target).match(/:(\d+)-(\d+)$/u);
  return match ? { startLine: Number(match[1]), endLine: Number(match[2]) } : null;
}

function mutationTargetFile(target) {
  return String(target).replace(/:\d+-\d+$/u, "");
}

function validatedMutationSourceFile(target) {
  if (typeof target !== "string" || target.length === 0 || target !== target.trim()) {
    throw new Error("Mutation target must be a canonical string.");
  }
  const match = target.match(/^((?:domain|util)\/[A-Za-z0-9_./-]+\.js)(?::(\d+)-(\d+))?$/u);
  if (!match) throw new Error(`Mutation target has invalid syntax: ${target}`);
  const sourceFile = assertRepositoryRelativePath(match[1]);
  if (match[2]) {
    const startLine = Number(match[2]);
    const endLine = Number(match[3]);
    if (!Number.isSafeInteger(startLine) || startLine <= 0
      || !Number.isSafeInteger(endLine) || endLine < startLine) {
      throw new Error(`Mutation target has an invalid line range: ${target}`);
    }
  }
  return sourceFile;
}

function validatedMutationOwner(owner) {
  const normalized = assertRepositoryRelativePath(owner);
  if (!/^test\/[A-Za-z0-9_./-]+\.test\.js$/u.test(normalized)) {
    throw new Error(`Mutation test owner has invalid syntax: ${String(owner)}`);
  }
  return normalized;
}

function runGitBuffer(argumentsList, root = ROOT) {
  const result = spawnSync("git", argumentsList, {
    cwd: root,
    encoding: null,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.signal || result.status !== 0) {
    const detail = Buffer.from(result.stderr || []).toString("utf8").trim();
    throw new Error(
      `git ${argumentsList.join(" ")} failed${detail ? `: ${detail}` : "."}`
    );
  }
  return Buffer.from(result.stdout || []);
}

function runGitText(argumentsList, root = ROOT) {
  const output = new TextDecoder("utf-8", { fatal: true }).decode(
    runGitBuffer(argumentsList, root)
  ).trim();
  if (!output) throw new Error(`git ${argumentsList.join(" ")} produced no output.`);
  return output;
}

function resolveGitCommit(reference, root = ROOT) {
  if (typeof reference !== "string" || reference.length === 0
    || reference !== reference.trim() || reference.startsWith("-")
    || /[\u0000-\u001f\u007f-\u009f]/u.test(reference)) {
    throw new Error("Mutation comparison base must be one canonical Git reference.");
  }
  const sha = runGitText(
    ["rev-parse", "--verify", "--end-of-options", `${reference}^{commit}`],
    root
  );
  if (!/^[a-f0-9]{40}$/u.test(sha)) {
    throw new Error(`Git reference ${reference} did not resolve to a full commit SHA.`);
  }
  return sha;
}

function parseGitPathInventory(bytes) {
  const output = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (output.length > 0 && !output.endsWith("\0")) {
    throw new Error("Git changed-file inventory is not NUL terminated.");
  }
  return output.split("\0").filter(Boolean).map(assertRepositoryRelativePath);
}

function collectGitChangedFiles(mergeBaseSha, root = ROOT) {
  const unresolved = parseGitPathInventory(runGitBuffer(
    ["diff", "-z", "--name-only", "--diff-filter=U", "--"],
    root
  ));
  if (unresolved.length > 0) {
    throw new Error("Mutation target selection rejects unresolved Git paths.");
  }
  const commands = [
    ["diff", "-z", "--name-only", "--no-renames", "--diff-filter=ACMRDTXB", `${mergeBaseSha}..HEAD`, "--"],
    ["diff", "-z", "--name-only", "--no-renames", "--diff-filter=ACMRDTXB", "HEAD", "--"],
    ["diff", "-z", "--name-only", "--no-renames", "--diff-filter=ACMRDTXB", "--cached", "--"],
    ["ls-files", "-z", "--others", "--exclude-standard", "--"],
  ];
  const files = [];
  for (const args of commands) {
    files.push(...parseGitPathInventory(runGitBuffer(args, root)));
  }
  return uniqueSorted(files);
}

function gitChangedFiles(base = "origin/main", root = ROOT) {
  const baseSha = resolveGitCommit(base, root);
  const mergeBaseSha = runGitText(["merge-base", "HEAD", baseSha], root);
  if (!/^[a-f0-9]{40}$/u.test(mergeBaseSha)) {
    throw new Error(`git merge-base produced an invalid commit for ${base}.`);
  }
  return collectGitChangedFiles(mergeBaseSha, root);
}

function filterMutationReport(report, targets) {
  const files = {};
  for (const target of targets) {
    const sourceFile = mutationTargetFile(target);
    if (Object.prototype.hasOwnProperty.call(files, sourceFile)) {
      throw new Error(`Mutation scope declares multiple ranges for ${sourceFile}; evidence would be ambiguous.`);
    }
    if (report?.files?.[sourceFile]) files[sourceFile] = report.files[sourceFile];
  }
  return { ...report, files };
}

function deriveMutationEvidence(report, targets) {
  const scopedReport = filterMutationReport(report, targets);
  return {
    ...summarizeMutationReport(scopedReport),
    files: perFileCounts(scopedReport, targets),
    survivors: survivingMutants(scopedReport, targets),
  };
}

function perFileCounts(report, targets = Object.keys(report?.files || {})) {
  const output = {};
  for (const target of targets) {
    const file = mutationTargetFile(target);
    if (!report?.files?.[file]) continue;
    output[target] = summarizeMutationReport({ files: { [file]: report.files[file] } });
  }
  return output;
}

function survivorFingerprint(file, mutant) {
  return crypto.createHash("sha256").update(JSON.stringify({
    file,
    mutator: mutant?.mutatorName || null,
    replacement: mutant?.replacement || null,
    location: mutant?.location ? {
      end: {
        column: mutant.location.end?.column ?? null,
        line: mutant.location.end?.line ?? null,
      },
      start: {
        column: mutant.location.start?.column ?? null,
        line: mutant.location.start?.line ?? null,
      },
    } : null,
  })).digest("hex");
}

function survivingMutants(report, targets = Object.keys(report?.files || {})) {
  const targetByFile = new Map(targets.map(target => [mutationTargetFile(target), target]));
  const survivors = [];
  for (const [file, value] of Object.entries(report?.files || {})) {
    for (const mutant of value?.mutants || []) {
      if (mutant.status !== "Survived") continue;
      survivors.push({
        fingerprint: survivorFingerprint(file, mutant),
        target: targetByFile.get(file) || file,
        file,
        line: mutant.location?.start?.line || null,
        mutator: mutant.mutatorName || null,
      });
    }
  }
  return survivors.sort((left, right) => left.fingerprint.localeCompare(right.fingerprint));
}

function validateMutationSummary(summary, baseline, mode) {
  if (!new Set(["core", "changed"]).has(mode) || summary?.mode !== mode) {
    throw new Error("Mutation summary has an invalid mutation mode.");
  }
  if (summary.status !== "passed") throw new Error("Mutation summary does not claim a passing run.");
  validateMutationCounts(summary, "Mutation gate");
  if (summary.mutants <= 0) {
    throw new Error("Mutation gate executed without producing a mutant.");
  }
  for (const failure of ["timeout", "runtimeError", "compileError", "noCoverage"]) {
    if (summary[failure] > 0) throw new Error(`Mutation gate has ${summary[failure]} ${failure} mutants.`);
  }
  if (!Number.isFinite(summary.score)) throw new Error("Mutation gate produced no scored mutants.");
  if (!Array.isArray(summary.targets) || summary.targets.length === 0) {
    throw new Error("Mutation gate has no selected targets.");
  }
  const fileTargets = uniqueSorted(Object.keys(summary.files || {}));
  if (JSON.stringify(fileTargets) !== JSON.stringify(uniqueSorted(summary.targets))) {
    throw new Error("Mutation summary files do not exactly match its selected targets.");
  }
  for (const target of summary.targets) {
    const expected = baseline.files?.[target];
    const actual = summary.files?.[target];
    if (!expected || !Number.isFinite(expected.score)) {
      throw new Error(`Mutation target ${target} has no measured per-target baseline.`);
    }
    if (!Number.isInteger(expected.mutants) || expected.mutants <= 0) {
      throw new Error(`Mutation target ${target} has no measured mutant population baseline.`);
    }
    if (!actual) {
      throw new Error(`Mutation target ${target} produced no scoped evidence.`);
    }
    validateMutationCounts(actual, `Mutation target ${target}`);
    if (actual.mutants <= 0) {
      throw new Error(`Mutation target ${target} produced no scoped mutants.`);
    }
    if (!Number.isFinite(actual.score)) {
      throw new Error(`Mutation target ${target} produced no scoped score.`);
    }
    if (actual.mutants !== expected.mutants) {
      throw new Error(
        `Mutation target ${target} produced ${actual.mutants} mutants; `
        + `measured baseline requires exactly ${expected.mutants}. `
        + "Update quality/mutation-baseline.json only after an explicit full mutation remeasurement."
      );
    }
    const expectedIgnored = Number.isInteger(expected.ignored) ? expected.ignored : 0;
    if (actual.ignored !== expectedIgnored
      || actual.mutants - actual.ignored !== expected.mutants - expectedIgnored) {
      throw new Error(
        `Mutation target ${target} ignored population drifted from ${expectedIgnored} `
        + `to ${actual.ignored}; measured scored population must remain exact.`
      );
    }
    for (const field of [
      "killed", "survived", "timeout", "noCoverage", "runtimeError", "compileError",
    ]) {
      if (Number.isInteger(expected[field]) && actual[field] !== expected[field]) {
        throw new Error(
          `Mutation target ${target} ${field} population drifted from `
          + `${expected[field]} to ${actual[field]}; remeasure the explicit mutation baseline.`
        );
      }
    }
    for (const failure of ["timeout", "runtimeError", "compileError", "noCoverage"]) {
      if (actual[failure] > 0) {
        throw new Error(`Mutation target ${target} has ${actual[failure]} ${failure} mutants.`);
      }
    }
  }
  for (const field of [
    "mutants", "killed", "survived", "timeout", "noCoverage",
    "runtimeError", "compileError", "ignored",
  ]) {
    const total = Object.values(summary.files).reduce((sum, file) => sum + file[field], 0);
    if (summary[field] !== total) {
      throw new Error(`Mutation aggregate ${field} does not equal its scoped file totals.`);
    }
  }
  const configuredFloor = baseline.thresholds?.break;
  const floor = configuredFloor === null || configuredFloor === undefined
    ? null
    : Number(configuredFloor);
  if (mode === "core" && floor !== null && Number.isFinite(floor) && summary.score < floor) {
    throw new Error(`Mutation score ${summary.score} is below the baseline floor ${floor}.`);
  }
  if (mode === "changed") {
    for (const target of summary.targets) {
      const expected = baseline.files?.[target]?.score;
      const actual = summary.files?.[target]?.score;
      if (!Number.isFinite(actual) || actual < expected) {
        throw new Error(`Changed mutation score for ${target} regressed below ${expected}.`);
      }
    }
  }
  validateSurvivorClassifications(summary, baseline);
}

function validateMutationCounts(value, label) {
  const fields = [
    "mutants", "killed", "survived", "timeout", "noCoverage",
    "runtimeError", "compileError", "ignored",
  ];
  if (fields.some(field => !Number.isInteger(value?.[field]) || value[field] < 0)) {
    throw new Error(`${label} has invalid mutation counts.`);
  }
  const classified = fields.slice(1).reduce((sum, field) => sum + value[field], 0);
  if (classified !== value.mutants) {
    throw new Error(`${label} mutation counts do not reconcile.`);
  }
  const scored = value.killed + value.survived + value.timeout + value.noCoverage;
  const expectedScore = scored === 0
    ? null
    : Number(((value.killed / scored) * 100).toFixed(2));
  if (value.score !== expectedScore) {
    throw new Error(`${label} mutation score does not match its counts.`);
  }
}

function validateSurvivorClassifications(summary, baseline) {
  const exactKeys = ["file", "fingerprint", "line", "mutator", "target"];
  if (!Array.isArray(summary.survivors)
    || summary.survivors.length !== summary.survived
    || summary.survivors.some(item => (
      !isPlainObject(item)
      || JSON.stringify(Object.keys(item).sort()) !== JSON.stringify(exactKeys)
      || !/^[a-f0-9]{64}$/u.test(item.fingerprint || "")
      || !summary.targets.includes(item.target)
      || item.file !== mutationTargetFile(item.target)
      || !Number.isInteger(item.line) || item.line <= 0
      || typeof item.mutator !== "string" || item.mutator.length === 0
    ))) {
    throw new Error("Mutation summary has incomplete survivor fingerprints.");
  }
  if (new Set(summary.survivors.map(item => item.fingerprint)).size
    !== summary.survivors.length) {
    throw new Error("Mutation summary has duplicate survivor fingerprints.");
  }
  if (!Array.isArray(baseline.survivorClassifications)) return;
  const equivalentClasses = new Set(
    (baseline.equivalentSurvivorClasses || []).map(item => item.class)
  );
  const classifications = new Map(
    baseline.survivorClassifications.map(item => [item.fingerprint, item])
  );
  const meaningful = new Set(
    (baseline.meaningfulSurvivors || []).map(item => (
      typeof item === "string" ? item : item?.fingerprint
    )).filter(Boolean)
  );
  for (const survivor of summary.survivors) {
    if (meaningful.has(survivor.fingerprint)) {
      throw new Error(`Meaningful survivor remains: ${survivor.fingerprint}.`);
    }
    const classification = classifications.get(survivor.fingerprint);
    if (!classification || !equivalentClasses.has(classification.class)) {
      throw new Error(`Unclassified mutation survivor: ${survivor.fingerprint}.`);
    }
  }
}

function bindMutationSummaryKey(summary) {
  const output = { ...summary };
  delete output.key;
  output.key = {
    sha: output.source.sha,
    fingerprint: fingerprint(output),
  };
  return output;
}

function mutationRuntimeIdentity() {
  return {
    node: process.version,
    platform: process.platform,
    architecture: process.arch,
  };
}

function receipt(mode, targets, values, context) {
  const source = context?.source;
  const selection = context?.selection;
  if (!source || !/^[a-f0-9]{40}$/u.test(source.sha || "")
    || !/^[a-f0-9]{64}$/u.test(source.fingerprint || "")
    || !selection || !/^[a-f0-9]{64}$/u.test(selection.fingerprint || "")
    || !(context.rawReportFingerprint === null
      || /^[a-f0-9]{64}$/u.test(context.rawReportFingerprint || ""))) {
    throw new Error("Mutation receipt requires exact source, selection, and raw-report provenance.");
  }
  return bindMutationSummaryKey({
    schemaVersion: 1,
    mode,
    source,
    sourceSha: source.sha,
    runtime: context.runtime || mutationRuntimeIdentity(),
    selection,
    workingTreeFingerprint: selection.fingerprint,
    rawReportFingerprint: context.rawReportFingerprint,
    targets: uniqueSorted(targets),
    ...values,
  });
}

function readMutationReportArtifact(root = ROOT) {
  const target = resolveExistingRepositoryFile(REPORT, root, {
    subtree: ".quality/mutation",
  });
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
  let descriptor = null;
  try {
    descriptor = fs.openSync(target, flags);
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.size <= 0 || stat.size > 64 * 1024 * 1024) {
      throw new Error("Mutation report must be a bounded nonempty regular file.");
    }
    const bytes = fs.readFileSync(descriptor);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const value = JSON.parse(text);
    if (!isPlainObject(value)) throw new Error("Mutation report JSON must be an object.");
    return {
      bytes,
      value,
      fingerprint: crypto.createHash("sha256").update(bytes).digest("hex"),
    };
  } finally {
    if (descriptor !== null) fs.closeSync(descriptor);
  }
}

function sameCanonicalValue(left, right) {
  return fingerprint(left) === fingerprint(right);
}

function assertMutationRunStable(
  expectedSource,
  expectedSelection,
  mode,
  argumentsList = [],
  root = ROOT
) {
  const before = sourceIdentity(root);
  const currentSelection = mode === "changed"
    ? resolveMutationSelection(argumentsList, root)
    : fullMutationSelection(root);
  const after = sourceIdentity(root);
  if (!sameCanonicalValue(expectedSource, before)
    || !sameCanonicalValue(before, after)
    || !sameCanonicalValue(expectedSelection, currentSelection)) {
    throw new Error("Mutation source or target selection changed during evidence generation.");
  }
}

function writeStableMutationSummary(
  mode,
  summary,
  source,
  selection,
  argumentsList = [],
  root = ROOT
) {
  const relativePath = `.quality/mutation/summary-${mode}.json`;
  try {
    const withoutKey = { ...summary };
    delete withoutKey.key;
    if (!sameCanonicalValue(summary.key, {
      sha: summary.source?.sha,
      fingerprint: fingerprint(withoutKey),
    })) {
      throw new Error("Mutation summary key does not bind its exact content.");
    }
    assertMutationRunStable(source, selection, mode, argumentsList, root);
    writeJson(relativePath, summary, root);
    assertMutationRunStable(source, selection, mode, argumentsList, root);
  } catch (error) {
    try {
      removeOutputFile(relativePath, root);
    } catch {
      // Preserve the original evidence-integrity failure.
    }
    throw error;
  }
}

function workingTreeFingerprint(root = ROOT, files = []) {
  const hash = crypto.createHash("sha256");
  for (const candidate of uniqueSorted(files)) {
    const file = assertRepositoryRelativePath(candidate);
    const target = path.join(root, ...file.split("/"));
    hash.update(`${file}\0`);
    if (!fs.existsSync(target)) {
      hash.update("missing\0");
      continue;
    }
    const safeTarget = resolveExistingRepositoryFile(file, root);
    const stat = fs.lstatSync(safeTarget);
    hash.update(`file:${stat.mode & 0o111 ? "executable" : "regular"}\0`);
    hash.update(fs.readFileSync(safeTarget));
    hash.update("\0");
  }
  return hash.digest("hex");
}

module.exports = {
  MUTATION_GLOBAL_OWNERS,
  assertCanonicalMutationRuntime,
  assertMutationGateArguments,
  assertValidMutationBaseline,
  assertMutationTestOwners,
  bindMutationSummaryKey,
  changedMutationTargets,
  deriveMutationEvidence,
  filterMutationReport,
  fullMutationSelection,
  gitChangedFiles,
  mutationTargetFile,
  parseMutationSelectionArguments,
  perFileCounts,
  readMutationReportArtifact,
  receipt,
  runMutation,
  resolveMutationSelection,
  selectMutationTargets,
  survivorFingerprint,
  survivingMutants,
  validateMutationSummary,
  validateMutationTestOwnership,
  validateMutationCounts,
  validateSurvivorClassifications,
  workingTreeFingerprint,
};

if (require.main === module) {
  try {
    runMutation();
  } catch (error) {
    console.error(`mutation: ${error.message}`);
    process.exitCode = Number.isInteger(error.mutationExitCode)
      ? error.mutationExitCode
      : 1;
  }
}

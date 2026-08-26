// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const {
  ROOT,
  gitVisibleFiles,
  prepareOutputDirectory,
  readJson,
  removeOutputFile,
  summarizeMutationReport,
  uniqueSorted,
  writeJson,
} = require("./common");
const { sourceIdentity } = require("./evidence");

const REPORT = ".quality/mutation/mutation.json";

function main() {
  const mode = process.argv[2] || "changed";
  if (!new Set(["core", "changed"]).has(mode)) {
    throw new Error(`Unknown mutation mode: ${mode}`);
  }
  const baseline = readJson("quality/mutation-baseline.json");
  assertMutationTestOwners(baseline);
  const targets = mode === "core"
    ? baseline.scope
    : changedMutationTargets(baseline.scope, process.argv.slice(3), baseline.files);
  if (targets.length === 0) {
    const summary = receipt(mode, targets, { status: "not-applicable", mutants: 0 });
    writeJson(`.quality/mutation/summary-${mode}.json`, summary);
    console.log("Mutation gate is not applicable: no configured mutation target changed.");
    return;
  }

  prepareOutputDirectory(".quality/mutation");
  removeOutputFile(REPORT);
  const cli = path.join(ROOT, "node_modules", "@stryker-mutator", "core", "bin", "stryker.js");
  const args = [cli, "run", "stryker.config.mjs", "--mutate", targets.join(",")];
  if (mode === "changed") args.push("--incremental", "--force");
  const result = spawnSync(process.execPath, args, { cwd: ROOT, encoding: "utf8", stdio: "inherit" });
  let report;
  try {
    report = readJson(REPORT);
  } catch {
    throw new Error(`Stryker did not write a safe ${REPORT} (exit ${String(result.status)}).`);
  }
  const scopedReport = filterMutationReport(report, targets);
  const counts = summarizeMutationReport(scopedReport);
  const candidate = receipt(mode, targets, {
    status: "passed",
    ...counts,
    files: perFileCounts(scopedReport, targets),
    survivors: survivingMutants(scopedReport, targets),
  });
  try {
    if (result.status !== 0) {
      throw new Error(`Stryker exited ${String(result.status)}.`);
    }
    validateMutationSummary(candidate, baseline, mode);
    writeJson(`.quality/mutation/summary-${mode}.json`, candidate);
  } catch (error) {
    writeJson(`.quality/mutation/summary-${mode}.json`, {
      ...candidate,
      status: "failed",
      reason: error.message,
    });
    throw error;
  }
}

function changedMutationTargets(scope, argumentsList = [], fileBaselines = {}) {
  const explicitIndex = argumentsList.indexOf("--files");
  if (explicitIndex >= 0 && !String(argumentsList[explicitIndex + 1] || "").trim()) {
    throw new Error("--files requires at least one changed source, test, or harness path.");
  }
  const changed = explicitIndex >= 0
    ? String(argumentsList[explicitIndex + 1] || "").split(",").filter(Boolean)
    : gitChangedFiles(optionValue(argumentsList, "--base") || "origin/main");
  const changedSet = new Set(changed);
  const globalOwners = new Set([
    "quality/mutation-baseline.json",
    "scripts/quality/run-mutation.js",
    "stryker.config.mjs",
  ]);
  if ([...globalOwners].some(file => changedSet.has(file))) return uniqueSorted(scope);
  return uniqueSorted(scope.filter(file => (
    changedSet.has(mutationTargetFile(file))
    || (fileBaselines[file]?.testFiles || []).some(testFile => changedSet.has(testFile))
  )));
}

function assertMutationTestOwners(baseline, root = ROOT, repositoryFiles = gitVisibleFiles(root)) {
  const visible = new Set(repositoryFiles);
  for (const target of baseline?.scope || []) {
    const owners = baseline?.files?.[target]?.testFiles;
    if (!Array.isArray(owners) || owners.length === 0) {
      throw new Error(`Mutation target ${String(target)} has no test owners.`);
    }
    for (const owner of owners) {
      const targetPath = path.join(root, String(owner));
      let stat = null;
      try {
        stat = fs.lstatSync(targetPath);
      } catch {
        // The stable failure below covers missing or unreadable owner paths.
      }
      if (!/^test\/[A-Za-z0-9_./-]+\.test\.js$/u.test(owner)
        || !visible.has(owner) || !stat?.isFile() || stat.isSymbolicLink()) {
        throw new Error(
          `Mutation target ${String(target)} test owner ${String(owner)} `
          + "must exist as a Git-visible regular test file."
        );
      }
    }
  }
}

function mutationTargetFile(target) {
  return String(target).replace(/:\d+(?::\d+)?-\d+(?::\d+)?$/u, "");
}

function optionValue(argumentsList, option) {
  const exact = argumentsList.indexOf(option);
  if (exact >= 0) return argumentsList[exact + 1] || null;
  const prefix = `${option}=`;
  const inline = argumentsList.find(argument => argument.startsWith(prefix));
  return inline ? inline.slice(prefix.length) : null;
}

function gitChangedFiles(base = "origin/main", root = ROOT) {
  const commands = [
    ["diff", "--name-only", "--no-renames", "--diff-filter=ACMRD", `${base}...HEAD`],
    ["diff", "--name-only", "--no-renames", "--diff-filter=ACMRD", "HEAD"],
    ["diff", "--name-only", "--no-renames", "--diff-filter=ACMRD", "--cached"],
    ["ls-files", "--others", "--exclude-standard"],
  ];
  const files = [];
  for (const args of commands) {
    const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
    if (result.status !== 0) throw new Error(`git ${args.join(" ")} failed while selecting mutation targets.`);
    files.push(...result.stdout.split(/\r?\n/u).filter(Boolean));
  }
  return uniqueSorted(files);
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
    location: mutant?.location || null,
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
  if (!Array.isArray(summary.survivors)
    || summary.survivors.length !== summary.survived
    || summary.survivors.some(item => !/^[a-f0-9]{64}$/u.test(item?.fingerprint || ""))) {
    throw new Error("Mutation summary has incomplete survivor fingerprints.");
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

function receipt(mode, targets, values) {
  const source = sourceIdentity(ROOT);
  const fingerprint = workingTreeFingerprint();
  return {
    schemaVersion: 1,
    mode,
    source,
    sourceSha: source.sha,
    workingTreeFingerprint: fingerprint,
    targets: uniqueSorted(targets),
    ...values,
  };
}

function workingTreeFingerprint(root = ROOT, files = gitChangedFiles("origin/main")) {
  const hash = crypto.createHash("sha256");
  for (const file of uniqueSorted(files)) {
    const target = path.join(root, file);
    hash.update(`${file}\0`);
    if (!fs.existsSync(target)) {
      hash.update("missing\0");
      continue;
    }
    const stat = fs.lstatSync(target);
    if (stat.isSymbolicLink()) {
      hash.update(`symlink\0${fs.readlinkSync(target)}\0`);
    } else if (stat.isFile()) {
      hash.update("file\0");
      hash.update(fs.readFileSync(target));
      hash.update("\0");
    } else {
      hash.update(`other:${stat.mode}\0`);
    }
  }
  return hash.digest("hex");
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(`mutation: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = {
  assertMutationTestOwners,
  changedMutationTargets,
  filterMutationReport,
  gitChangedFiles,
  mutationTargetFile,
  perFileCounts,
  survivorFingerprint,
  survivingMutants,
  validateMutationSummary,
  validateMutationCounts,
  validateSurvivorClassifications,
  workingTreeFingerprint,
};

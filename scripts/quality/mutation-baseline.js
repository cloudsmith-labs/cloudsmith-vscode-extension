// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const {
  ROOT,
  assertRepositoryRelativePath,
  isPlainObject,
  requireNonEmptyString,
  uniqueSorted,
} = require("./common");
const {
  mutationTargetFile,
  validateMutationCounts,
} = require("./run-mutation");

const COUNT_FIELDS = [
  "mutants", "killed", "survived", "timeout", "noCoverage",
  "runtimeError", "compileError", "ignored",
];
const OPTIONAL_ZERO_COUNT_FIELDS = new Set([
  "timeout", "noCoverage", "runtimeError", "compileError",
]);

function validateMutationBaseline(baseline, options = {}) {
  const root = options.root || ROOT;
  const commitIsAncestor = options.commitIsAncestor || isAncestorCommit;
  const errors = [];
  if (!isPlainObject(baseline)) {
    return { errors: ["Mutation baseline must be an object."] };
  }

  if (baseline.schemaVersion !== 1) {
    errors.push("Mutation baseline schemaVersion must be 1.");
  }
  if (!/^[a-f0-9]{40}$/u.test(baseline.measuredAtSha || "")) {
    errors.push("Mutation baseline measuredAtSha must be a full 40-hex commit.");
  } else if (!commitIsAncestor(baseline.measuredAtSha, root)) {
    errors.push("Mutation baseline measuredAtSha must name a commit reachable from current HEAD.");
  }

  const scope = Array.isArray(baseline.scope) ? baseline.scope : [];
  if (scope.length === 0) {
    errors.push("Mutation baseline scope must contain at least one target.");
  }
  const validTargets = [];
  const sourceFiles = new Set();
  for (const target of scope) {
    if (!validMutationTarget(target)) {
      errors.push(`Mutation baseline scope has an invalid target: ${String(target)}.`);
      continue;
    }
    validTargets.push(target);
    const sourceFile = mutationTargetFile(target);
    let sourceStat = null;
    try {
      sourceStat = fs.lstatSync(path.join(root, sourceFile));
    } catch {
      // The stable error below covers missing and unreadable target paths.
    }
    if (!sourceStat?.isFile() || sourceStat.isSymbolicLink()) {
      errors.push(`Mutation baseline target ${target} must exist as a regular repository file.`);
    }
    if (sourceFiles.has(sourceFile)) {
      errors.push(`Mutation baseline scope declares multiple targets for ${sourceFile}.`);
    }
    sourceFiles.add(sourceFile);
  }
  if (validTargets.length !== uniqueSorted(validTargets).length) {
    errors.push("Mutation baseline scope contains duplicate targets.");
  }

  const files = isPlainObject(baseline.files) ? baseline.files : {};
  if (!isPlainObject(baseline.files)) {
    errors.push("Mutation baseline files must be an object.");
  }
  const scopeKeys = uniqueSorted(validTargets);
  const fileKeys = uniqueSorted(Object.keys(files));
  if (JSON.stringify(scopeKeys) !== JSON.stringify(fileKeys)) {
    errors.push("Mutation baseline scope and files must have exact target parity.");
  }

  const normalizedFiles = new Map();
  for (const target of fileKeys) {
    const record = files[target];
    if (!isPlainObject(record)) {
      errors.push(`Mutation baseline target ${target} must be an object.`);
      continue;
    }
    const counts = normalizedMutationCounts(record);
    try {
      validateMutationCounts(counts, `Mutation baseline target ${target}`);
      normalizedFiles.set(target, counts);
    } catch (error) {
      errors.push(error.message);
    }
    const testFiles = Array.isArray(record.testFiles) ? record.testFiles : [];
    if (testFiles.length === 0
      || testFiles.some(file => !validRepositoryPath(file))
      || uniqueSorted(testFiles).length !== testFiles.length) {
      errors.push(`Mutation baseline target ${target} must have unique normalized testFiles.`);
    }
  }

  const metrics = normalizedMutationCounts(baseline.metrics);
  let metricsAreValid = false;
  try {
    validateMutationCounts(metrics, "Mutation baseline aggregate");
    metricsAreValid = true;
  } catch (error) {
    errors.push(error.message);
  }
  if (metricsAreValid && normalizedFiles.size === fileKeys.length) {
    for (const field of COUNT_FIELDS) {
      const total = [...normalizedFiles.values()]
        .reduce((sum, counts) => sum + counts[field], 0);
      if (metrics[field] !== total) {
        errors.push(`Mutation baseline aggregate ${field} does not equal its file totals.`);
      }
    }
  }
  if (metricsAreValid && baseline.thresholds?.break !== metrics.score) {
    errors.push("Mutation baseline break threshold must equal its measured aggregate score.");
  }

  const meaningfulSurvivors = baseline.meaningfulSurvivors;
  if (!Array.isArray(meaningfulSurvivors)) {
    errors.push("Mutation baseline meaningfulSurvivors must be an array.");
  } else if (meaningfulSurvivors.length > 0) {
    errors.push("Mutation baseline cannot be accepted with meaningful survivors.");
  }

  const classDefinitions = validateEquivalentClasses(
    baseline.equivalentSurvivorClasses,
    metrics,
    metricsAreValid,
    errors
  );
  validateClassifications(
    baseline.survivorClassifications,
    classDefinitions,
    metrics,
    metricsAreValid,
    errors
  );

  return { errors: uniqueSorted(errors) };
}

function normalizedMutationCounts(value) {
  const output = { score: value?.score };
  for (const field of COUNT_FIELDS) {
    output[field] = value?.[field] === undefined && OPTIONAL_ZERO_COUNT_FIELDS.has(field)
      ? 0
      : value?.[field];
  }
  return output;
}

function validateEquivalentClasses(value, metrics, metricsAreValid, errors) {
  if (!Array.isArray(value)) {
    errors.push("Mutation baseline equivalentSurvivorClasses must be an array.");
    return null;
  }
  const definitions = new Map();
  let declaredCount = 0;
  for (const entry of value) {
    if (!isPlainObject(entry)
      || !requireNonEmptyString(entry.class)
      || !Number.isInteger(entry.count)
      || entry.count <= 0
      || !requireNonEmptyString(entry.reason)) {
      errors.push("Mutation baseline has an invalid equivalent survivor class.");
      continue;
    }
    if (definitions.has(entry.class)) {
      errors.push(`Mutation baseline has duplicate equivalent class ${entry.class}.`);
      continue;
    }
    definitions.set(entry.class, entry.count);
    declaredCount += entry.count;
  }
  if (metricsAreValid && declaredCount !== metrics.survived) {
    errors.push("Mutation baseline equivalent class counts do not equal its surviving mutant count.");
  }
  return definitions;
}

function validateClassifications(value, classDefinitions, metrics, metricsAreValid, errors) {
  if (!Array.isArray(value)) {
    errors.push("Mutation baseline survivorClassifications must be an array.");
    return;
  }
  if (metricsAreValid && value.length !== metrics.survived) {
    errors.push("Mutation baseline must classify every surviving fingerprint exactly once.");
  }
  const fingerprints = new Set();
  const actualClassCounts = new Map();
  for (const classification of value) {
    if (!isPlainObject(classification)
      || !/^[a-f0-9]{64}$/u.test(classification.fingerprint || "")
      || !requireNonEmptyString(classification.class)) {
      errors.push("Mutation baseline has an invalid survivor classification.");
      continue;
    }
    if (fingerprints.has(classification.fingerprint)) {
      errors.push(`Mutation baseline has duplicate survivor fingerprint ${classification.fingerprint}.`);
    }
    fingerprints.add(classification.fingerprint);
    if (!classDefinitions?.has(classification.class)) {
      errors.push(`Mutation baseline survivor ${classification.fingerprint} uses unknown equivalent class ${classification.class}.`);
      continue;
    }
    actualClassCounts.set(
      classification.class,
      (actualClassCounts.get(classification.class) || 0) + 1
    );
  }
  if (!classDefinitions) return;
  for (const [className, declaredCount] of classDefinitions) {
    if ((actualClassCounts.get(className) || 0) !== declaredCount) {
      errors.push(`Mutation baseline equivalent class ${className} count does not match its classifications.`);
    }
  }
}

function validMutationTarget(value) {
  if (!requireNonEmptyString(value) || value !== value.trim()) return false;
  const sourceFile = mutationTargetFile(value);
  if (!validRepositoryPath(sourceFile)) return false;
  return value === sourceFile
    || new RegExp(`^${escapeRegExp(sourceFile)}:\\d+(?::\\d+)?-\\d+(?::\\d+)?$`, "u").test(value);
}

function validRepositoryPath(value) {
  try {
    assertRepositoryRelativePath(value);
    return true;
  } catch {
    return false;
  }
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function isAncestorCommit(sha, root = ROOT) {
  const result = spawnSync(
    "git",
    ["merge-base", "--is-ancestor", sha, "HEAD"],
    { cwd: root, encoding: "utf8", stdio: "ignore" }
  );
  return result.status === 0;
}

module.exports = {
  isAncestorCommit,
  validateMutationBaseline,
};

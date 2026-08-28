// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { spawnSync } = require("child_process");
const { TextDecoder } = require("util");
const {
  ROOT,
  isPlainObject,
  readJson,
  requireNonEmptyString,
  resolveExistingRepositoryFile,
  uniqueSorted,
} = require("./common");
const { withStableSingleLinkFile } = require("./candidate-binding");

const FINDINGS_MAX_BYTES = 16 * 1024 * 1024;
const CLOSED_FINDING_STATUSES = new Set(["closed", "closed-non-issue"]);

function readBoundedFindingsBytes(target, options = {}) {
  return withStableSingleLinkFile(target, {
    errorMessage: "The ignored findings ledger is not a bounded single-link regular file.",
    fileSystem: options.fileSystem,
    maximumBytes: FINDINGS_MAX_BYTES,
    minimumBytes: 0,
  }, bytes => Buffer.from(bytes));
}

function decodeFindingsBytes(bytes) {
  return decodeUtf8Bytes(bytes, "The ignored findings ledger");
}

function decodeUtf8Bytes(bytes, label = "Evidence") {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new Error(`${label} is not valid UTF-8: ${error.message}`);
  }
}

function parseFindingsJsonl(source) {
  const findings = [];
  const lines = String(source).split(/\r?\n/u);
  for (let index = 0; index < lines.length; index += 1) {
    if (!lines[index].trim()) continue;
    try {
      findings.push(JSON.parse(lines[index]));
    } catch (error) {
      throw new Error(`Invalid finding JSON on line ${index + 1}: ${error.message}`);
    }
  }
  return findings;
}

function isClosedFinding(finding) {
  return CLOSED_FINDING_STATUSES.has(finding?.status);
}

function findingRequiresLiveVerification(finding) {
  if (!isPlainObject(finding)) return false;
  if (finding.liveStatus !== "not-required") return true;
  if (finding.domain === "security-environment" && finding.severity === "P0") return true;
  return finding.domain === "product"
    && ["live-protocol", "black-box-ui"].includes(finding.testLayerThatShouldHaveCaughtIt);
}

function deriveReleaseBlocking(finding, workflow = null) {
  if (!isPlainObject(finding)) return true;
  if (isClosedFinding(finding)) return false;
  if (finding.severity === "P3") return false;
  if (finding.severity === "P0") return true;
  if (finding.severity === "P1") return true;

  const deterministicUnresolved = finding.deterministicStatus !== "fixed";
  const liveUnresolved = findingRequiresLiveVerification(finding)
    && finding.liveStatus !== "verified";
  if (finding.domain === "product") {
    const releaseCritical = workflow == null || workflow.criticality === "release-critical";
    return finding.severity === "P2"
      && releaseCritical
      && (deterministicUnresolved || liveUnresolved);
  }
  return false;
}

function validateFindings(findings, schema, taxonomy, root = ROOT) {
  const errors = [];
  const ids = new Set();
  let workflows = null;
  try {
    workflows = readJson("quality/critical-workflows.json", root);
  } catch (error) {
    errors.push(`Findings workflow manifest is unavailable: ${error.message}`);
  }
  findings.forEach((finding, index) => {
    errors.push(...validateFindingRecord(
      finding,
      schema,
      taxonomy,
      index + 1,
      root,
      workflows
    ));
    if (!requireNonEmptyString(finding?.id)) return;
    if (ids.has(finding.id)) errors.push(`Duplicate finding ID: ${finding.id}.`);
    ids.add(finding.id);
  });
  return uniqueSorted(errors);
}

function validateFindingRecord(
  finding,
  schema,
  taxonomy,
  line = 1,
  root = ROOT,
  workflowsDocument = null
) {
  const errors = [];
  const label = requireNonEmptyString(finding?.id) ? finding.id : `line ${line}`;
  if (!isPlainObject(finding)) return [`Finding ${label} must be an object.`];
  validateSchemaValue(finding, schema, `Finding ${label}`, errors);
  const allowed = new Set(Object.keys(schema?.properties || {}));
  for (const key of Object.keys(finding)) {
    if (!allowed.has(key)) errors.push(`Finding ${label} has unknown field ${key}.`);
  }
  for (const key of schema?.required || []) {
    if (!Object.prototype.hasOwnProperty.call(finding, key)) {
      errors.push(`Finding ${label} is missing required field ${key}.`);
    }
  }
  if (!(new RegExp(taxonomy?.idPattern || "a^")).test(finding.id || "")) {
    errors.push(`Finding ${label} has an invalid ID.`);
  }
  if (!Object.prototype.hasOwnProperty.call(taxonomy?.severities || {}, finding.severity)) {
    errors.push(`Finding ${label} has invalid severity ${String(finding.severity)}.`);
  }
  if (!Object.prototype.hasOwnProperty.call(taxonomy?.domains || {}, finding.domain)) {
    errors.push(`Finding ${label} has invalid domain ${String(finding.domain)}.`);
  }
  if (!(taxonomy?.statuses || []).includes(finding.status)) {
    errors.push(`Finding ${label} has invalid status ${String(finding.status)}.`);
  }
  if (!(taxonomy?.deterministicStatuses || []).includes(finding.deterministicStatus)) {
    errors.push(
      `Finding ${label} has invalid deterministic status ${String(finding.deterministicStatus)}.`
    );
  }
  if (!(taxonomy?.liveStatuses || []).includes(finding.liveStatus)) {
    errors.push(`Finding ${label} has invalid live status ${String(finding.liveStatus)}.`);
  }
  let workflow = null;
  try {
    const workflows = workflowsDocument || readJson("quality/critical-workflows.json", root);
    workflow = (workflows?.workflows || []).find(candidate => (
      candidate?.id === finding.workflowContract
    ));
  } catch (error) {
    errors.push(`Finding ${label} workflow manifest is unavailable: ${error.message}`);
  }
  if (!workflow) {
    errors.push(
      `Finding ${label} references unknown workflow contract ${String(finding.workflowContract)}.`
    );
  }
  if (!Array.isArray(finding.failureClasses)
    || finding.failureClasses.length === 0
    || new Set(finding.failureClasses).size !== finding.failureClasses.length) {
    errors.push(`Finding ${label} must declare unique failure classes.`);
  } else {
    for (const failureClass of finding.failureClasses) {
      if (!(taxonomy?.failureClasses || []).includes(failureClass)) {
        errors.push(`Finding ${label} has invalid failure class ${String(failureClass)}.`);
      }
    }
  }
  validateNestedEvidenceStatus(
    finding.mutationProof,
    schema?.properties?.mutationProof?.properties?.status?.enum,
    "mutation proof",
    label,
    errors
  );
  if (!isPlainObject(finding.liveVerification)
    || !requireNonEmptyString(finding.liveVerification.summary)) {
    errors.push(`Finding ${label} has invalid live verification summary.`);
  }
  if (typeof finding.releaseBlocking !== "boolean") {
    errors.push(`Finding ${label} must declare boolean releaseBlocking.`);
  }
  const derivedReleaseBlocking = deriveReleaseBlocking(finding, workflow);
  if (typeof finding.releaseBlocking === "boolean"
    && finding.releaseBlocking !== derivedReleaseBlocking) {
    errors.push(
      `Finding ${label} releaseBlocking must match policy-derived value `
      + `${String(derivedReleaseBlocking)}.`
    );
  }
  const deterministicFix = finding.deterministicStatus === "fixed";
  const closedNonIssue = finding.status === "closed-non-issue";
  const closedResolved = finding.status === "closed";
  const releaseCriticalProduct = finding.domain === "product"
    && (finding.severity === "P0"
      || finding.severity === "P1"
      || (finding.severity === "P2" && workflow?.criticality === "release-critical"));
  if (deterministicFix) {
    if (!requireNonEmptyString(finding.regressionTest)) {
      errors.push(`Finding ${label} deterministic fix requires a regression test.`);
    }
    if (finding.rootCauseStatus !== "proven") {
      errors.push(`Finding ${label} deterministic fix requires proven root cause.`);
    }
    if (!/^[a-f0-9]{7,40}$/u.test(finding.fixedSha || "")) {
      errors.push(`Finding ${label} deterministic fix requires a fixed SHA.`);
    } else if (!isAncestorCommit(root, finding.fixedSha)) {
      errors.push(`Finding ${label} fixed SHA is not an ancestor of the current candidate.`);
    }
    if (!["mutation-killed", "not-applicable"].includes(finding.mutationProof?.status)) {
      errors.push(`Finding ${label} deterministic fix requires completed mutation proof.`);
    }
  }
  if (finding.deterministicStatus === "failing" && isClosedFinding(finding)) {
    errors.push(`Finding ${label} cannot close while deterministic evidence is failing.`);
  }
  if (finding.deterministicStatus === "not-applicable"
    && finding.mutationProof?.status !== "not-applicable") {
    errors.push(`Finding ${label} deterministic non-applicability requires matching mutation proof.`);
  }
  if (isClosedFinding(finding)
    && !["fixed", "not-applicable"].includes(finding.deterministicStatus)) {
    errors.push(`Finding ${label} closed lifecycle requires completed deterministic disposition.`);
  }
  if (isClosedFinding(finding)
    && !["verified", "not-required"].includes(finding.liveStatus)) {
    errors.push(`Finding ${label} closed lifecycle requires completed live disposition.`);
  }
  if (closedResolved && releaseCriticalProduct && !deterministicFix) {
    errors.push(
      `Finding ${label} cannot close a release-critical product defect without a deterministic fix.`
    );
  }
  if (closedResolved && finding.deterministicStatus === "not-applicable") {
    if (finding.rootCauseStatus !== "proven" || !requireNonEmptyString(finding.rootCause)) {
      errors.push(`Finding ${label} deterministic non-applicability requires a proven disposition.`);
    }
    if (!Array.isArray(finding.evidence) || !finding.evidence.some(evidence => (
      ["test", "source", "log", "screenshot"].includes(evidence?.kind)
    ))) {
      errors.push(
        `Finding ${label} deterministic non-applicability requires repository-verifiable evidence.`
      );
    }
  }
  if (findingRequiresLiveVerification(finding)
    && finding.liveStatus === "not-required") {
    errors.push(`Finding ${label} cannot mark required live verification as not-required.`);
  }
  if (finding.rootCauseStatus === "proven" && !requireNonEmptyString(finding.rootCause)) {
    errors.push(`Finding ${label} proven root cause requires a nonempty rootCause.`);
  }
  if (closedNonIssue) {
    if (finding.rootCauseStatus !== "proven" || !requireNonEmptyString(finding.rootCause)) {
      errors.push(`Finding ${label} closed-non-issue requires a proven disposition.`);
    }
    if (!requireNonEmptyString(finding.regressionTest)) {
      errors.push(`Finding ${label} closed-non-issue requires a protecting regression test.`);
    }
    if (!Array.isArray(finding.evidence) || !finding.evidence.some(evidence => (
      ["test", "source", "log", "screenshot"].includes(evidence?.kind)
    ))) {
      errors.push(`Finding ${label} closed-non-issue requires repository-verifiable evidence.`);
    }
    if (!["mutation-killed", "not-applicable"].includes(finding.mutationProof?.status)) {
      errors.push(`Finding ${label} closed-non-issue requires completed mutation disposition.`);
    }
    if (!["verified", "not-required"].includes(finding.liveStatus)) {
      errors.push(`Finding ${label} closed-non-issue requires completed live disposition.`);
    }
    if (finding.releaseBlocking !== false) {
      errors.push(`Finding ${label} closed-non-issue must clear releaseBlocking.`);
    }
  }
  for (const evidence of finding.evidence || []) {
    if (!["test", "source", "log", "screenshot"].includes(evidence?.kind)) continue;
    const reference = String(evidence.location || "").replace(/:(?:\d+)(?::\d+)?$/u, "");
    if (!safeExistingEvidencePath(root, reference)) {
      errors.push(`Finding ${label} evidence path is missing or unsafe: ${String(evidence.location)}.`);
    }
  }
  return errors;
}

function validateSchemaValue(value, schema, label, errors) {
  if (!isPlainObject(schema)) {
    errors.push(`${label} has no valid schema.`);
    return;
  }
  const types = Array.isArray(schema.type) ? schema.type : schema.type ? [schema.type] : [];
  if (types.length > 0 && !types.some(type => schemaTypeMatches(value, type))) {
    errors.push(`${label} has invalid type.`);
    return;
  }
  if (Array.isArray(schema.enum)
    && !schema.enum.some(candidate => JSON.stringify(candidate) === JSON.stringify(value))) {
    errors.push(`${label} must match its declared enum.`);
  }
  if (typeof value === "string") {
    if (Number.isInteger(schema.minLength) && value.length < schema.minLength) {
      errors.push(`${label} is shorter than ${schema.minLength}.`);
    }
    if (Number.isInteger(schema.maxLength) && value.length > schema.maxLength) {
      errors.push(`${label} is longer than ${schema.maxLength}.`);
    }
    if (schema.pattern && !(new RegExp(schema.pattern, "u")).test(value)) {
      errors.push(`${label} does not match its declared pattern.`);
    }
  }
  if (Array.isArray(value)) {
    if (Number.isInteger(schema.minItems) && value.length < schema.minItems) {
      errors.push(`${label} has fewer than ${schema.minItems} items.`);
    }
    if (schema.uniqueItems === true
      && new Set(value.map(item => JSON.stringify(item))).size !== value.length) {
      errors.push(`${label} must contain unique items.`);
    }
    if (schema.items) {
      value.forEach((item, index) => validateSchemaValue(
        item,
        schema.items,
        `${label}[${index}]`,
        errors
      ));
    }
  }
  if (isPlainObject(value)) {
    const properties = schema.properties || {};
    for (const key of schema.required || []) {
      if (!Object.prototype.hasOwnProperty.call(value, key)) {
        errors.push(`${label} is missing required field ${key}.`);
      }
    }
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!Object.prototype.hasOwnProperty.call(properties, key)) {
          errors.push(`${label} has unknown field ${key}.`);
        }
      }
    }
    for (const [key, child] of Object.entries(properties)) {
      if (Object.prototype.hasOwnProperty.call(value, key)) {
        validateSchemaValue(value[key], child, `${label}.${key}`, errors);
      }
    }
  }
}

function schemaTypeMatches(value, type) {
  if (type === "null") return value === null;
  if (type === "object") return isPlainObject(value);
  if (type === "array") return Array.isArray(value);
  if (type === "string") return typeof value === "string";
  if (type === "boolean") return typeof value === "boolean";
  if (type === "integer") return Number.isInteger(value);
  if (type === "number") return Number.isFinite(value);
  return false;
}

function isAncestorCommit(root, sha) {
  const exists = spawnSync("git", ["cat-file", "-e", `${sha}^{commit}`], { cwd: root });
  if (exists.error || exists.signal || exists.status !== 0) return false;
  const ancestor = spawnSync("git", ["merge-base", "--is-ancestor", sha, "HEAD"], { cwd: root });
  return !ancestor.error && !ancestor.signal && ancestor.status === 0;
}

function safeExistingEvidencePath(root, reference) {
  if (!requireNonEmptyString(reference)) return false;
  try {
    resolveExistingRepositoryFile(reference, root);
    return true;
  } catch {
    return false;
  }
}

function validateNestedEvidenceStatus(value, allowedStatuses, field, label, errors) {
  if (!isPlainObject(value)
    || !(allowedStatuses || []).includes(value.status)
    || typeof value.summary !== "string") {
    errors.push(`Finding ${label} has invalid ${field}.`);
  }
}

module.exports = {
  decodeFindingsBytes,
  decodeUtf8Bytes,
  deriveReleaseBlocking,
  findingRequiresLiveVerification,
  isClosedFinding,
  parseFindingsJsonl,
  readBoundedFindingsBytes,
  validateFindingRecord,
  validateFindings,
};

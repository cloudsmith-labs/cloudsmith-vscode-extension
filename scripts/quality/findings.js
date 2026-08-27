// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const fs = require("fs");
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

const FINDINGS_MAX_BYTES = 16 * 1024 * 1024;

function readBoundedFindingsBytes(target) {
  const stat = fs.lstatSync(target);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > FINDINGS_MAX_BYTES) {
    throw new Error("The ignored findings ledger is not a bounded regular file.");
  }
  return fs.readFileSync(target);
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
  if (!(taxonomy?.statuses || []).includes(finding.status)) {
    errors.push(`Finding ${label} has invalid status ${String(finding.status)}.`);
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
  validateNestedEvidenceStatus(
    finding.liveVerification,
    schema?.properties?.liveVerification?.properties?.status?.enum,
    "live verification",
    label,
    errors
  );
  if (typeof finding.releaseBlocking !== "boolean") {
    errors.push(`Finding ${label} must declare boolean releaseBlocking.`);
  }
  const terminalFix = finding.status === "fixed";
  const pendingFix = finding.status === "fixed-pending-verification";
  const closedNonIssue = finding.status === "closed-non-issue";
  if (["P0", "P1"].includes(finding.severity)
    && !terminalFix
    && finding.status !== "closed-non-issue"
    && finding.releaseBlocking !== true) {
    errors.push(`Finding ${label} ${finding.severity} must remain release blocking until fixed.`);
  }
  if (finding.severity === "P2"
    && workflow?.criticality === "release-critical"
    && !terminalFix
    && finding.status !== "closed-non-issue"
    && finding.releaseBlocking !== true) {
    errors.push(
      `Finding ${label} unresolved P2 on a release-critical workflow must remain release blocking.`
    );
  }
  if (finding.severity === "P3" && finding.releaseBlocking !== false) {
    errors.push(`Finding ${label} P3 must not be release blocking.`);
  }
  if (terminalFix || pendingFix) {
    if (!requireNonEmptyString(finding.regressionTest)) {
      errors.push(`Finding ${label} fixed lifecycle requires a regression test.`);
    }
    if (finding.rootCauseStatus !== "proven") {
      errors.push(`Finding ${label} fixed lifecycle requires proven root cause.`);
    }
    if (!/^[a-f0-9]{7,40}$/u.test(finding.fixedSha || "")) {
      errors.push(`Finding ${label} fixed lifecycle requires a fixed SHA.`);
    } else if (!isAncestorCommit(root, finding.fixedSha)) {
      errors.push(`Finding ${label} fixed SHA is not an ancestor of the current candidate.`);
    }
    if (!["mutation-killed", "not-applicable"].includes(finding.mutationProof?.status)) {
      errors.push(`Finding ${label} fixed lifecycle requires completed mutation proof.`);
    }
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
    if (!["live-pass", "not-applicable"].includes(finding.liveVerification?.status)) {
      errors.push(`Finding ${label} closed-non-issue requires completed live disposition.`);
    }
    if (finding.releaseBlocking !== false) {
      errors.push(`Finding ${label} closed-non-issue must clear releaseBlocking.`);
    }
  }
  if (terminalFix) {
    if (!["live-pass", "not-applicable"].includes(finding.liveVerification?.status)) {
      errors.push(`Finding ${label} cannot be fixed without completed live verification.`);
    }
    if (finding.releaseBlocking !== false) {
      errors.push(`Finding ${label} fixed lifecycle must clear releaseBlocking.`);
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
  parseFindingsJsonl,
  readBoundedFindingsBytes,
  validateFindingRecord,
  validateFindings,
};

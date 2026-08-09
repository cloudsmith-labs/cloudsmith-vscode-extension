// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const crypto = require("crypto");
const path = require("path");
const { pathToFileURL } = require("url");
const vscode = require("vscode");
const {
  createDependencyRecord,
  createDependencySource,
  getDependencyOccurrenceKey,
} = require("./dependencyRecord");
const {
  buildDependencyDeclarationIndex,
  findDependencyDeclarationOffsets,
  offsetRangesToSourceRanges,
  validateDependencyDeclarationSourceContract,
  validateSourceRanges,
} = require("./dependencyDeclarationIndex");
const { readUtf8 } = require("./lockfileParsers/shared");
const { buildRepositoryUrl } = require("./webAppUrls");

const MAX_DIAGNOSTIC_OCCURRENCES = 10000;
const MAX_IDENTITY_FIELD_LENGTH = 8192;
const MAX_PACKAGE_NAME_LENGTH = 1024;
const MAX_PARENT_CHAIN_LENGTH = 128;
const MAX_PATH_LENGTH = 8192;
const MAX_SOURCE_TYPE_LENGTH = 256;
const PROBLEM_STATES = new Set(["quarantined", "violated", "not_found"]);
const STATE_PRIORITY = Object.freeze({
  quarantined: 3,
  violated: 2,
  not_found: 1,
});
const DIAGNOSTIC_CANDIDATES = new WeakSet();

class DiagnosticPreparationCancelledError extends Error {
  constructor() {
    super("Dependency diagnostic preparation was cancelled.");
    this.code = "ERR_DEPENDENCY_DIAGNOSTIC_PREPARATION_CANCELLED";
  }
}

/**
 * Create a bounded immutable diagnostic input without retaining mutable health
 * overlays or the dependency's transitive graph.
 */
function createDiagnosticCandidate(dependency, values = {}) {
  const dependencyProperties = getPlainDataProperties(dependency, "dependency occurrence");
  const ecosystem = boundedString(
    ownDataValue(dependencyProperties, "ecosystem", true),
    "dependency ecosystem",
    MAX_PACKAGE_NAME_LENGTH
  ).toLowerCase();
  const format = boundedString(
    ownDataValue(dependencyProperties, "format", true),
    "dependency format",
    MAX_PACKAGE_NAME_LENGTH
  );
  const name = boundedString(
    ownDataValue(dependencyProperties, "name", true),
    "dependency name",
    MAX_PACKAGE_NAME_LENGTH
  );
  const declarationName = boundedOptionalString(
    ownDataValue(dependencyProperties, "declarationName", false),
    "dependency declaration name",
    MAX_PACKAGE_NAME_LENGTH
  ) || name;
  const declaredConstraint = boundedOptionalString(
    ownDataValue(dependencyProperties, "declaredConstraint", false),
    "dependency declared constraint",
    MAX_IDENTITY_FIELD_LENGTH
  );
  const resolvedVersion = boundedOptionalString(
    ownDataValue(dependencyProperties, "resolvedVersion", false),
    "dependency resolved version",
    MAX_IDENTITY_FIELD_LENGTH
  );
  const versionState = boundedString(
    ownDataValue(dependencyProperties, "versionState", true),
    "dependency version state",
    MAX_PACKAGE_NAME_LENGTH
  );
  const legacyVersion = boundedOptionalString(
    ownDataValue(dependencyProperties, "legacyVersion", false),
    "dependency compatibility version",
    MAX_IDENTITY_FIELD_LENGTH
  ) || "";
  const environmentMarker = boundedOptionalString(
    ownDataValue(dependencyProperties, "environmentMarker", false),
    "dependency environment marker",
    MAX_IDENTITY_FIELD_LENGTH
  );
  const parent = boundedOptionalString(
    ownDataValue(dependencyProperties, "parent", false),
    "dependency parent",
    MAX_PACKAGE_NAME_LENGTH
  );
  const parentChain = snapshotStringArray(
    ownDataValue(dependencyProperties, "parentChain", false),
    "dependency parent chain"
  );
  const sourceManifest = snapshotSource(
    ownDataValue(dependencyProperties, "sourceManifest", false),
    "dependency manifest source"
  );
  const resolutionSource = snapshotSource(
    ownDataValue(dependencyProperties, "resolutionSource", false),
    "dependency resolution source"
  );

  const occurrence = createDependencyRecord({
    ecosystem,
    format,
    name,
    declarationName,
    declaredConstraint,
    resolvedVersion,
    versionState,
    resolutionSource,
    sourceManifest,
    environmentMarker,
    isDirect: ownDataValue(dependencyProperties, "isDirect", true) === true,
    isDevelopmentDependency: ownDataValue(
      dependencyProperties,
      "isDevelopmentDependency",
      false
    ) === true,
    parent,
    parentChain,
    transitives: [],
    legacyVersion,
  });

  const valuesProperties = getPlainDataProperties(values, "diagnostic candidate values");
  const state = boundedString(
    ownDataValue(valuesProperties, "state", true),
    "diagnostic state",
    32
  );
  if (!PROBLEM_STATES.has(state)) {
    throw new TypeError("Diagnostic candidates must use a supported problematic state.");
  }
  const displayVersion = boundedOptionalString(
    ownDataValue(valuesProperties, "displayVersion", false),
    "diagnostic display version",
    MAX_IDENTITY_FIELD_LENGTH
  );
  const cloudsmith = snapshotCloudsmithMetadata(
    ownDataValue(valuesProperties, "cloudsmithMatch", false)
  );
  const candidate = Object.freeze({ occurrence, state, displayVersion, cloudsmith });
  DIAGNOSTIC_CANDIDATES.add(candidate);
  return candidate;
}

class DiagnosticsPublisher {
  constructor(options = {}) {
    this.collection = vscode.languages.createDiagnosticCollection("cloudsmith");
    this._readSource = typeof options.readSource === "function"
      ? options.readSource
      : readUtf8;
    this._buildIndex = typeof options.buildIndex === "function"
      ? options.buildIndex
      : buildDependencyDeclarationIndex;
    this._maxDiagnostics = Number.isInteger(options.maxDiagnostics) && options.maxDiagnostics > 0
      ? Math.min(options.maxDiagnostics, MAX_DIAGNOSTIC_OCCURRENCES)
      : MAX_DIAGNOSTIC_OCCURRENCES;
  }

  /** Build a complete scan-local snapshot without changing the collection. */
  async prepare(options) {
    const properties = getPlainDataProperties(options, "diagnostic preparation options");
    const workspaceFolder = validateWorkspaceFolder(
      ownDataValue(properties, "workspaceFolder", true)
    );
    const candidates = snapshotCandidateArray(
      ownDataValue(properties, "candidates", true),
      MAX_DIAGNOSTIC_OCCURRENCES
    );
    const cancellationToken = ownDataValue(properties, "cancellationToken", false);
    const isCancelled = () => Boolean(
      cancellationToken && cancellationToken.isCancellationRequested
    );
    throwIfCancelled(isCancelled);

    const warnings = [];
    const candidateByIdentity = new Map();
    let missingProvenance = 0;
    for (const candidate of candidates) {
      if (!candidate.occurrence.isDirect) {
        continue;
      }
      if (!candidate.occurrence.sourceManifest) {
        missingProvenance += 1;
        continue;
      }
      const identity = digestIdentity(getDependencyOccurrenceKey(candidate.occurrence));
      const existing = candidateByIdentity.get(identity);
      if (!existing || STATE_PRIORITY[candidate.state] > STATE_PRIORITY[existing.state]) {
        candidateByIdentity.set(identity, candidate);
      }
    }
    if (missingProvenance > 0) {
      warnings.push(
        `${missingProvenance} direct dependency diagnostic occurrence${missingProvenance === 1 ? " was" : "s were"} skipped because manifest provenance was unavailable.`
      );
    }

    const sourceGroups = new Map();
    for (const candidate of candidateByIdentity.values()) {
      const source = candidate.occurrence.sourceManifest;
      const indexingContract = Object.freeze({
        ecosystem: candidate.occurrence.ecosystem,
        format: candidate.occurrence.format,
      });
      const key = source.filePath;
      const existing = sourceGroups.get(key);
      if (existing) {
        if (
          existing.source.type !== source.type
          || existing.source.uri !== source.uri
          || existing.indexingContract.ecosystem !== indexingContract.ecosystem
          || existing.indexingContract.format !== indexingContract.format
        ) {
          throw new TypeError("Dependency occurrences disagree about their manifest source contract.");
        }
        existing.candidates.push(candidate);
      } else {
        sourceGroups.set(key, { source, indexingContract, candidates: [candidate] });
      }
    }

    const entries = [];
    const finalIdentities = new Set();
    let diagnosticsCreated = 0;
    let exactRanges = 0;
    let fileRanges = 0;
    let indexedSources = 0;
    let sourceReads = 0;
    let diagnosticOutputTruncated = false;
    let truncatedSourceIndexes = 0;
    const sortedGroups = [...sourceGroups.values()].sort((left, right) => (
      left.source.uri.localeCompare(right.source.uri)
    ));

    for (const group of sortedGroups) {
      if (diagnosticsCreated >= this._maxDiagnostics) {
        diagnosticOutputTruncated = true;
        break;
      }
      throwIfCancelled(isCancelled);
      const content = await this._readSource(group.source.filePath, workspaceFolder);
      sourceReads += 1;
      throwIfCancelled(isCancelled);
      if (typeof content !== "string") {
        throw new TypeError("Dependency source readers must return UTF-8 text.");
      }
      validateDependencyDeclarationSourceContract(
        group.source.type,
        group.indexingContract.ecosystem
      );

      const rangedCandidates = group.candidates.filter((candidate) => (
        candidate.occurrence.sourceManifest.range
      ));
      if (rangedCandidates.length > 0) {
        validateSourceRanges(
          content,
          rangedCandidates.map((candidate) => candidate.occurrence.sourceManifest.range),
          isCancelled
        );
      }
      const candidatesNeedingIndex = group.candidates.filter((candidate) => (
        !candidate.occurrence.sourceManifest.range
      ));
      let index = null;
      if (candidatesNeedingIndex.length > 0) {
        const wantedNames = candidatesNeedingIndex.map((candidate) => (
          candidate.occurrence.declarationName
        ));
        index = this._buildIndex({
          content,
          sourceType: group.source.type,
          ecosystem: group.indexingContract.ecosystem,
          wantedNames,
          shouldCancel: isCancelled,
        });
        indexedSources += 1;
        if (index.truncated) {
          truncatedSourceIndexes += 1;
        }
      }

      const plans = [];
      for (const candidate of group.candidates) {
        if (diagnosticsCreated + plans.length >= this._maxDiagnostics) {
          diagnosticOutputTruncated = true;
          break;
        }
        const providedRange = candidate.occurrence.sourceManifest.range;
        if (providedRange) {
          plans.push({ candidate, range: providedRange, precision: "exact" });
          continue;
        }

        if (!index) {
          throw new TypeError("A dependency declaration index is required for missing source ranges.");
        }
        const offsets = findDependencyDeclarationOffsets(index, candidate.occurrence);
        if (offsets.length === 0) {
          plans.push({ candidate, range: fileLevelRange(), precision: "file" });
          continue;
        }
        for (const offsetRange of offsets) {
          if (diagnosticsCreated + plans.length >= this._maxDiagnostics) {
            diagnosticOutputTruncated = true;
            break;
          }
          plans.push({ candidate, offsetRange, precision: "exact" });
        }
      }

      const offsetPlans = plans.filter((plan) => plan.offsetRange);
      const convertedRanges = offsetRangesToSourceRanges(
        content,
        offsetPlans.map((plan) => plan.offsetRange),
        isCancelled
      );
      let convertedIndex = 0;
      const diagnostics = [];
      for (const plan of plans) {
        const range = plan.range || convertedRanges[convertedIndex++];
        const identity = finalDiagnosticIdentity(plan.candidate, group.source.uri, range);
        if (finalIdentities.has(identity)) {
          continue;
        }
        finalIdentities.add(identity);
        diagnostics.push(this._createDiagnostic(plan.candidate, range));
        diagnosticsCreated += 1;
        if (plan.precision === "exact") {
          exactRanges += 1;
        } else {
          fileRanges += 1;
        }
      }
      entries.push([vscode.Uri.file(group.source.filePath), diagnostics]);
      throwIfCancelled(isCancelled);
    }

    if (truncatedSourceIndexes > 0) {
      warnings.push(
        `${truncatedSourceIndexes} dependency source declaration index${truncatedSourceIndexes === 1 ? " was" : "es were"} capped; unresolved declaration locations use file-level ranges.`
      );
    }
    if (diagnosticOutputTruncated) {
      warnings.push(
        `Dependency diagnostics were capped at ${this._maxDiagnostics} occurrences; dependency health results remain complete.`
      );
    }

    return Object.freeze({
      entries: Object.freeze(entries.map(([uri, diagnostics]) => (
        Object.freeze([uri, Object.freeze(diagnostics.slice())])
      ))),
      warnings: Object.freeze(warnings.slice().sort()),
      stats: Object.freeze({
        candidates: candidates.length,
        uniqueOccurrences: candidateByIdentity.size,
        sourceReads,
        indexedSources,
        diagnostics: diagnosticsCreated,
        exactRanges,
        fileRanges,
        truncated: diagnosticOutputTruncated || truncatedSourceIndexes > 0,
        diagnosticOutputTruncated,
        truncatedSourceIndexes,
      }),
    });
  }

  replace(entries) {
    if (!Array.isArray(entries)) {
      throw new TypeError("Diagnostic replacement entries must be an array.");
    }
    this.collection.set(entries);
  }

  async publish(options) {
    const prepared = await this.prepare(options);
    this.replace(prepared.entries);
    return prepared;
  }

  _createDiagnostic(candidate, sourceRange) {
    const range = new vscode.Range(
      sourceRange.start.line,
      sourceRange.start.character,
      sourceRange.end.line,
      sourceRange.end.character
    );
    const diagnostic = new vscode.Diagnostic(
      range,
      this._getMessage(candidate),
      this._getSeverity(candidate.state)
    );
    diagnostic.source = "Cloudsmith";

    if (candidate.cloudsmith && candidate.cloudsmith.numVulnerabilities > 0) {
      const repositoryUrl = buildRepositoryUrl(
        candidate.cloudsmith.namespace,
        candidate.cloudsmith.repository
      );
      const vulnerabilityCode = `${candidate.cloudsmith.numVulnerabilities} vulnerabilities`;
      diagnostic.code = repositoryUrl
        ? { value: vulnerabilityCode, target: vscode.Uri.parse(repositoryUrl) }
        : vulnerabilityCode;
    }
    return diagnostic;
  }

  _getSeverity(state) {
    switch (state) {
      case "quarantined":
        return vscode.DiagnosticSeverity.Error;
      case "violated":
        return vscode.DiagnosticSeverity.Warning;
      default:
        return vscode.DiagnosticSeverity.Information;
    }
  }

  _getMessage(candidate) {
    const version = candidate.displayVersion ? ` ${candidate.displayVersion}` : "";
    switch (candidate.state) {
      case "quarantined":
        return `${candidate.occurrence.name}${version} is quarantined in Cloudsmith. Use "Find safe version" to find an alternative.`;
      case "violated":
        return `${candidate.occurrence.name}${version} has policy violations in Cloudsmith.`;
      default:
        return `${candidate.occurrence.name}${version} was not found in the configured Cloudsmith workspace.`;
    }
  }

  clear() {
    this.collection.clear();
  }

  dispose() {
    this.collection.dispose();
  }
}

function snapshotSource(source, label) {
  if (source == null) {
    return null;
  }
  const properties = getPlainDataProperties(source, label);
  const kind = boundedString(ownDataValue(properties, "kind", true), `${label} kind`, 32);
  const filePath = boundedString(
    ownDataValue(properties, "filePath", true),
    `${label} path`,
    MAX_PATH_LENGTH
  );
  if (filePath.includes("\u0000") || !path.isAbsolute(filePath) || path.normalize(filePath) !== filePath) {
    throw new TypeError("Dependency source paths must be normalized absolute paths.");
  }
  const type = boundedString(
    ownDataValue(properties, "type", true),
    `${label} type`,
    MAX_SOURCE_TYPE_LENGTH
  );
  if (type.includes("\u0000")) {
    throw new TypeError("Dependency source types must not contain NUL bytes.");
  }
  const uri = boundedString(
    ownDataValue(properties, "uri", true),
    `${label} URI`,
    MAX_PATH_LENGTH * 3
  );
  const canonicalUri = pathToFileURL(filePath).toString();
  if (uri !== canonicalUri) {
    throw new TypeError("Dependency source URI and path must identify the same file.");
  }
  const range = snapshotRange(ownDataValue(properties, "range", false), `${label} range`);
  return createDependencySource({ kind, filePath, type, range });
}

function snapshotRange(range, label) {
  if (range == null) {
    return null;
  }
  const properties = getPlainDataProperties(range, label);
  return Object.freeze({
    start: snapshotPosition(ownDataValue(properties, "start", true), `${label} start`),
    end: snapshotPosition(ownDataValue(properties, "end", true), `${label} end`),
  });
}

function snapshotPosition(position, label) {
  const properties = getPlainDataProperties(position, label);
  const line = ownDataValue(properties, "line", true);
  const character = ownDataValue(properties, "character", true);
  if (!Number.isInteger(line) || line < 0 || !Number.isInteger(character) || character < 0) {
    throw new TypeError("Dependency source positions must use non-negative integers.");
  }
  return Object.freeze({ line, character });
}

function snapshotStringArray(values, label) {
  if (values == null) {
    return Object.freeze([]);
  }
  if (!Array.isArray(values)) {
    throw new TypeError(`${label} must be an array.`);
  }
  let descriptors;
  try {
    descriptors = Object.getOwnPropertyDescriptors(values);
  } catch {
    throw new TypeError(`${label} must expose stable data properties.`);
  }
  const length = descriptors.length && descriptors.length.value;
  if (!Number.isInteger(length) || length < 0 || length > MAX_PARENT_CHAIN_LENGTH) {
    throw new TypeError(`${label} exceeds the supported length.`);
  }
  const copy = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[index];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw new TypeError(`${label} must contain only stable data properties.`);
    }
    copy.push(boundedString(
      descriptor.value,
      `${label} entry`,
      MAX_PACKAGE_NAME_LENGTH
    ));
  }
  return Object.freeze(copy);
}

function snapshotCloudsmithMetadata(value) {
  if (value == null) {
    return null;
  }
  const properties = getPlainDataProperties(value, "Cloudsmith diagnostic metadata");
  const namespace = boundedOptionalString(
    ownDataValue(properties, "namespace", false),
    "Cloudsmith namespace",
    MAX_PACKAGE_NAME_LENGTH
  );
  const repository = boundedOptionalString(
    ownDataValue(properties, "repository", false),
    "Cloudsmith repository",
    MAX_PACKAGE_NAME_LENGTH
  );
  const rawCount = ownDataValue(properties, "num_vulnerabilities", false);
  const numVulnerabilities = Number.isInteger(rawCount) && rawCount > 0 ? rawCount : 0;
  return Object.freeze({ namespace, repository, numVulnerabilities });
}

function snapshotCandidateArray(candidates, maximum) {
  if (!Array.isArray(candidates)) {
    throw new TypeError("Diagnostic candidates must be an array.");
  }
  let descriptors;
  try {
    descriptors = Object.getOwnPropertyDescriptors(candidates);
  } catch {
    throw new TypeError("Diagnostic candidates must expose stable data properties.");
  }
  const length = descriptors.length && descriptors.length.value;
  if (!Number.isInteger(length) || length < 0 || length > maximum) {
    throw new TypeError(`Diagnostic candidates must contain at most ${maximum} occurrences.`);
  }
  const snapshot = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[index];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw new TypeError("Diagnostic candidate arrays must not contain accessors or holes.");
    }
    if (!DIAGNOSTIC_CANDIDATES.has(descriptor.value)) {
      throw new TypeError("Diagnostic candidates must be created from immutable occurrence snapshots.");
    }
    snapshot.push(descriptor.value);
  }
  return snapshot;
}

function getPlainDataProperties(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be a plain object.`);
  }
  let prototype;
  let properties;
  try {
    prototype = Object.getPrototypeOf(value);
    properties = Object.getOwnPropertyDescriptors(value);
  } catch {
    throw new TypeError(`${label} must expose a stable plain-object contract.`);
  }
  if (prototype !== Object.prototype) {
    throw new TypeError(`${label} must use the standard object prototype.`);
  }
  for (const descriptor of Object.values(properties)) {
    if (!Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw new TypeError(`${label} must not contain accessors.`);
    }
  }
  return properties;
}

function ownDataValue(properties, name, required) {
  const descriptor = properties[name];
  if (!descriptor) {
    if (required) {
      throw new TypeError(`Required diagnostic field is missing: ${name}.`);
    }
    return null;
  }
  return descriptor.value;
}

function validateWorkspaceFolder(value) {
  const workspaceFolder = boundedString(value, "diagnostic workspace folder", MAX_PATH_LENGTH);
  if (
    workspaceFolder.includes("\u0000")
    || !path.isAbsolute(workspaceFolder)
    || path.normalize(workspaceFolder) !== workspaceFolder
  ) {
    throw new TypeError("Diagnostic workspace folders must be normalized absolute paths.");
  }
  return workspaceFolder;
}

function boundedString(value, label, maximum) {
  if (typeof value !== "string") {
    throw new TypeError(`${label} must be a string.`);
  }
  const normalized = value.trim();
  if (!normalized || normalized.length > maximum || normalized.includes("\u0000")) {
    throw new TypeError(`${label} is empty or exceeds its supported bound.`);
  }
  return normalized;
}

function boundedOptionalString(value, label, maximum) {
  if (value == null || value === "") {
    return null;
  }
  return boundedString(value, label, maximum);
}

function digestIdentity(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function finalDiagnosticIdentity(candidate, uri, range) {
  return digestIdentity(JSON.stringify([
    getDependencyOccurrenceKey(candidate.occurrence),
    candidate.state,
    uri,
    range,
  ]));
}

function fileLevelRange() {
  return Object.freeze({
    start: Object.freeze({ line: 0, character: 0 }),
    end: Object.freeze({ line: 0, character: 0 }),
  });
}

function throwIfCancelled(isCancelled) {
  if (isCancelled()) {
    throw new DiagnosticPreparationCancelledError();
  }
}

module.exports = {
  MAX_DIAGNOSTIC_OCCURRENCES,
  DiagnosticPreparationCancelledError,
  DiagnosticsPublisher,
  createDiagnosticCandidate,
};

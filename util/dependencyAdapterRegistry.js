// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const { ManifestParser } = require("./manifestParser");
const { LockfileResolver } = require("./lockfileResolver");
const { discoverDependencyManifests } = require("./dependencyManifestDiscovery");
const {
  DEPENDENCY_PACKAGE_SOURCE_KINDS,
  DEPENDENCY_VERSION_STATES,
  RESOLUTION_SOURCE_KINDS,
  createDependencyPackageSource,
  createDependencyQualifiers,
  createDependencyRecord,
  createDependencySource,
} = require("./dependencyRecord");
const {
  DEPENDENCY_FILE_ERROR_CODES,
  getWorkspacePath,
  readUtf8,
  resolveWorkspaceFilePath,
} = require("./lockfileParsers/shared");
const {
  canonicalFormat,
  normalizePackageName,
} = require("./packageNameNormalizer");

const ADAPTER_RESULT_STATUSES = Object.freeze({
  SUCCESS: "success",
  PARTIAL: "partial",
  ERROR: "error",
  UNSUPPORTED: "unsupported",
});
const ADAPTER_RESULT_STATUS_VALUES = new Set(Object.values(ADAPTER_RESULT_STATUSES));
const ADAPTER_ERROR_CODES = Object.freeze({
  CANCELLED: "scan-cancelled",
  DEPENDENCY_FILE_CHANGED: "dependency-file-changed",
  DEPENDENCY_FILE_MISSING: "dependency-file-missing",
  DEPENDENCY_FILE_NOT_REGULAR: "dependency-file-not-regular",
  DEPENDENCY_FILE_OUTSIDE_WORKSPACE: "dependency-file-outside-workspace",
  DEPENDENCY_FILE_TOO_LARGE: "dependency-file-too-large",
  DEPENDENCY_FILE_UNREADABLE: "dependency-file-unreadable",
  PARSE_ERROR: "parse-error",
  UNSUPPORTED_ADAPTER: "unsupported-adapter",
  UNSUPPORTED_MANIFEST: "unsupported-manifest",
});
const SAFE_ADAPTER_ERROR_MESSAGES = Object.freeze({
  [ADAPTER_ERROR_CODES.CANCELLED]: "Dependency scanning was canceled.",
  [ADAPTER_ERROR_CODES.DEPENDENCY_FILE_CHANGED]:
    "A dependency file changed during the scan. Rescan the workspace.",
  [ADAPTER_ERROR_CODES.DEPENDENCY_FILE_MISSING]:
    "A dependency file could not be found. Rescan the workspace.",
  [ADAPTER_ERROR_CODES.DEPENDENCY_FILE_NOT_REGULAR]:
    "A dependency path could not be read as a file. Check the dependency files and rescan.",
  [ADAPTER_ERROR_CODES.DEPENDENCY_FILE_OUTSIDE_WORKSPACE]:
    "A dependency file is outside the selected workspace. Check the dependency paths and rescan.",
  [ADAPTER_ERROR_CODES.DEPENDENCY_FILE_TOO_LARGE]:
    "A dependency file could not be scanned because of its size. Check the dependency file and rescan.",
  [ADAPTER_ERROR_CODES.DEPENDENCY_FILE_UNREADABLE]:
    "A dependency file could not be read. Check file access and rescan.",
  [ADAPTER_ERROR_CODES.PARSE_ERROR]:
    "Dependency data could not be parsed. Check the dependency files and rescan.",
  [ADAPTER_ERROR_CODES.UNSUPPORTED_ADAPTER]:
    "Dependency data could not be read from this source.",
  [ADAPTER_ERROR_CODES.UNSUPPORTED_MANIFEST]:
    "Dependency data could not be read from this file.",
});
const DEPENDENCY_FILE_ADAPTER_ERROR_CODES = Object.freeze({
  [DEPENDENCY_FILE_ERROR_CODES.CHANGED]: ADAPTER_ERROR_CODES.DEPENDENCY_FILE_CHANGED,
  [DEPENDENCY_FILE_ERROR_CODES.MISSING]: ADAPTER_ERROR_CODES.DEPENDENCY_FILE_MISSING,
  [DEPENDENCY_FILE_ERROR_CODES.NOT_REGULAR]: ADAPTER_ERROR_CODES.DEPENDENCY_FILE_NOT_REGULAR,
  [DEPENDENCY_FILE_ERROR_CODES.OUTSIDE_WORKSPACE]:
    ADAPTER_ERROR_CODES.DEPENDENCY_FILE_OUTSIDE_WORKSPACE,
  [DEPENDENCY_FILE_ERROR_CODES.SYMLINK_ESCAPE]:
    ADAPTER_ERROR_CODES.DEPENDENCY_FILE_OUTSIDE_WORKSPACE,
  [DEPENDENCY_FILE_ERROR_CODES.TOO_LARGE]: ADAPTER_ERROR_CODES.DEPENDENCY_FILE_TOO_LARGE,
  [DEPENDENCY_FILE_ERROR_CODES.UNREADABLE]: ADAPTER_ERROR_CODES.DEPENDENCY_FILE_UNREADABLE,
});
const MAX_STRUCTURAL_GRAPH_ENTRIES = 50000;
const MAX_STRUCTURAL_GRAPH_EDGES = 500000;
const SAFE_DOCKER_ADAPTER_WARNINGS = new Map([
  [
    "a dockerfile target platform could not be resolved, so dependency results are partial.",
    "A Dockerfile target platform could not be resolved; affected dependencies remain incomplete.",
  ],
  [
    "a compose image reference could not be resolved, so dependency results are partial.",
    "A Compose image reference could not be resolved; affected dependencies were omitted.",
  ],
  [
    "a compose image platform could not be resolved, so dependency results are partial.",
    "A Compose image platform could not be resolved; affected dependencies remain incomplete.",
  ],
  [
    "a compose image platform was invalid and could not be checked.",
    "A Compose image platform was invalid; affected dependencies remain incomplete.",
  ],
  [
    "a compose pull policy could not be resolved, so dependency results are partial.",
    "A Compose pull policy could not be resolved; affected services were omitted.",
  ],
  [
    "a compose service requests a local build but has no usable build definition.",
    "A Compose service requested a local build without a usable build definition.",
  ],
  [
    "a compose image reference was invalid and could not be checked.",
    "A Compose image reference was invalid; affected dependencies were omitted.",
  ],
]);
for (const safeWarning of SAFE_DOCKER_ADAPTER_WARNINGS.values()) {
  SAFE_DOCKER_ADAPTER_WARNINGS.set(safeWarning.toLowerCase(), safeWarning);
}

const RESOLUTION_AVAILABILITY = Object.freeze({
  AVAILABLE: "available",
  MISSING: "missing",
  NOT_APPLICABLE: "not-applicable",
});

const RESOLVER_MANIFEST_TYPES = Object.freeze({
  npmParser: ["package.json"],
  pythonParser: ["requirements.txt", "pyproject.toml", "Pipfile"],
  mavenParser: ["pom.xml"],
  gradleParser: ["build.gradle", "build.gradle.kts"],
  goParser: ["go.mod"],
  cargoParser: ["Cargo.toml"],
  rubyParser: ["Gemfile"],
  dockerParser: ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"],
  nugetParser: [],
  dartParser: ["pubspec.yaml"],
  composerParser: ["composer.json"],
  helmParser: ["Chart.yaml"],
  swiftParser: ["Package.swift"],
  hexParser: ["mix.exs"],
});

const LEGACY_MANIFEST_PARSERS = Object.freeze({
  "package.json": (content) => ManifestParser.parseNpm(content, "npm"),
  "requirements.txt": (content) => ManifestParser.parsePythonRequirements(content, "python"),
  "pyproject.toml": (content) => ManifestParser.parsePyproject(content, "python"),
  "pipfile": (content, _resolver, options) => (
    require("./lockfileParsers/pythonParser").parsePipfileManifest(content, options)
  ),
  "pom.xml": (content) => ManifestParser.parseMaven(content, "maven"),
  "go.mod": (content) => ManifestParser.parseGoMod(content, "go"),
  "cargo.toml": (content) => ManifestParser.parseCargo(content, "cargo"),
});

const LOCKFILE_TYPES = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "uv.lock",
  "poetry.lock",
  "pipfile.lock",
  "gradle.lockfile",
  "cargo.lock",
  "gemfile.lock",
  "packages.lock.json",
  "pubspec.lock",
  "composer.lock",
  "chart.lock",
  "package.resolved",
  "mix.lock",
]);

const PACKAGE_MANAGER_OUTPUT_TYPES = new Set([
  "dependency-tree.txt",
]);

const RESOLVER_DIRECT_MANIFEST_TYPES = new Set([
  "build.gradle",
  "build.gradle.kts",
  "chart.yaml",
  "composer.json",
  "compose.yaml",
  "compose.yml",
  "docker-compose.yaml",
  "docker-compose.yml",
  "dockerfile",
  "gemfile",
  "requirements.txt",
  "pom.xml",
  "package.swift",
  "pubspec.yaml",
  "mix.exs",
  "go.mod",
  "cargo.toml",
]);

class DependencyAdapterRegistry {
  constructor(adapters = []) {
    this._adapters = new Map();
    this._manifestAdapters = new Map();
    this._discoveryWarnings = [];

    for (const adapter of adapters) {
      this.register(adapter);
    }
  }

  register(adapter) {
    if (
      !adapter
      || typeof adapter.id !== "string"
      || !adapter.id
      || typeof adapter.detect !== "function"
      || typeof adapter.parse !== "function"
    ) {
      throw new TypeError("Dependency adapters require an id, detect(), and parse().");
    }

    if (this._adapters.has(adapter.id)) {
      throw new Error(`Dependency adapter already registered: ${adapter.id}`);
    }

    this._adapters.set(adapter.id, adapter);
    for (const manifestType of adapter.manifestTypes || []) {
      const key = normalizeManifestType(manifestType);
      if (key && !this._manifestAdapters.has(key)) {
        this._manifestAdapters.set(key, adapter);
      }
    }
  }

  getAdapter(id) {
    return this._adapters.get(id) || null;
  }

  getAdapterForManifest(manifestType) {
    const normalizedType = normalizeManifestType(manifestType);
    if (this._manifestAdapters.has(normalizedType)) {
      return this._manifestAdapters.get(normalizedType);
    }
    if (normalizedType.startsWith("dockerfile.")) {
      return this._adapters.get("dockerParser") || null;
    }
    if (normalizedType.endsWith(".csproj")) {
      return this._adapters.get("nugetParser") || null;
    }
    return null;
  }

  async detect(workspaceFolder, options = {}) {
    const workspaceRoot = getWorkspacePath(workspaceFolder);
    throwIfCancelled(options.cancellationToken);
    const discovery = await discoverDependencyManifests(workspaceRoot, options);
    this._discoveryWarnings = discovery.warnings.slice();
    const nestedAdapterRoots = new Map();
    for (const manifest of discovery.manifests) {
      const projectRoot = path.dirname(manifest.filePath);
      if (path.resolve(projectRoot) === path.resolve(workspaceRoot)) {
        continue;
      }
      const adapter = this.getAdapterForManifest(path.basename(manifest.filePath));
      if (!adapter) {
        continue;
      }
      if (!nestedAdapterRoots.has(projectRoot)) {
        nestedAdapterRoots.set(projectRoot, new Set());
      }
      nestedAdapterRoots.get(projectRoot).add(adapter.id);
    }

    const detections = [];
    const detectionTargets = [
      [workspaceRoot, new Set(this._adapters.keys())],
      ...nestedAdapterRoots.entries(),
    ];
    const seen = new Set();
    for (const [projectRoot, adapterIds] of detectionTargets) {
      for (const adapterId of adapterIds) {
        throwIfCancelled(options.cancellationToken);
        const adapter = this._adapters.get(adapterId);
        const adapterDetections = validateDetectionResult(
          adapter,
          await adapter.detect(projectRoot, options)
        );
        for (const detection of adapterDetections) {
          const detectionKey = JSON.stringify([
            adapter.id,
            detection.lockfilePath || null,
            detection.manifestPath || null,
            detection.sourceFile || null,
          ]);
          if (seen.has(detectionKey)) {
            continue;
          }
          seen.add(detectionKey);
          detections.push({
            ...detection,
            adapterId: adapter.id,
            resolverName: adapter.id,
            ecosystem: detection.ecosystem || adapter.ecosystem,
            workspaceFolder: workspaceRoot,
            ...(path.resolve(projectRoot) === path.resolve(workspaceRoot)
              ? {}
              : { projectFolder: projectRoot }),
          });
        }
      }
    }
    return detections;
  }

  getDiscoveryWarnings() {
    return this._discoveryWarnings.slice();
  }

  async detectManifests(workspaceFolder, options = {}) {
    throwIfCancelled(options.cancellationToken);
    const discovery = await discoverDependencyManifests(workspaceFolder, options);
    this._discoveryWarnings = discovery.warnings.slice();
    const manifests = discovery.manifests;
    return manifests.map((manifest) => {
      const adapter = this.getAdapterForManifest(path.basename(manifest.filePath));
      return {
        ...manifest,
        adapterId: adapter ? adapter.id : null,
        manifestType: path.basename(manifest.filePath),
      };
    });
  }

  async parse(detection, options = {}) {
    try {
      throwIfCancelled(options.cancellationToken);
    } catch (error) {
      return createAdapterResult({
        status: ADAPTER_RESULT_STATUSES.ERROR,
        adapterId: null,
        ecosystem: null,
        sourceFile: null,
        resolutionAvailability: RESOLUTION_AVAILABILITY.UNKNOWN,
        error,
      });
    }
    const adapterId = detection && (detection.adapterId || detection.resolverName);
    const adapter = this.getAdapter(adapterId);
    if (!adapter) {
      return createAdapterResult({
        status: ADAPTER_RESULT_STATUSES.UNSUPPORTED,
        adapterId: adapterId || null,
        ecosystem: detection && detection.ecosystem || null,
        sourceFile: detection && detection.sourceFile || null,
        resolutionAvailability: RESOLUTION_AVAILABILITY.NOT_APPLICABLE,
        error: {
          code: "unsupported-adapter",
          message: `No dependency adapter is registered for ${adapterId || "this source"}.`,
        },
      });
    }

    return validateAdapterResult(adapter, "parse", await adapter.parse(detection, options));
  }

  async parseManifest(manifest, options = {}) {
    const manifestType = path.basename(String(manifest && manifest.filePath || manifest && manifest.manifestType || ""));
    const adapter = this.getAdapterForManifest(manifestType);
    if (!adapter || typeof adapter.parseManifest !== "function") {
      return createAdapterResult({
        status: ADAPTER_RESULT_STATUSES.UNSUPPORTED,
        adapterId: adapter ? adapter.id : null,
        ecosystem: manifest && manifest.format || null,
        sourceFile: manifestType || null,
        resolutionAvailability: RESOLUTION_AVAILABILITY.NOT_APPLICABLE,
        error: {
          code: "unsupported-manifest",
          message: `No dependency adapter supports ${manifestType || "this manifest"}.`,
        },
      });
    }

    throwIfCancelled(options.cancellationToken);
    return validateAdapterResult(
      adapter,
      "parseManifest",
      await adapter.parseManifest(manifest, options)
    );
  }
}

function createDefaultDependencyAdapterRegistry() {
  return new DependencyAdapterRegistry(
    LockfileResolver.getResolvers().map((resolver) => createResolverAdapter(resolver))
  );
}

function createResolverAdapter(resolver) {
  const manifestTypes = RESOLVER_MANIFEST_TYPES[resolver.name] || [];
  return Object.freeze({
    id: resolver.name,
    ecosystem: resolver.ecosystem,
    manifestTypes: Object.freeze(manifestTypes.slice()),
    normalizeName(name) {
      return normalizePackageName(name, resolver.ecosystem);
    },
    async detect(workspaceFolder, options = {}) {
      const rootPath = getWorkspacePath(workspaceFolder);
      throwIfCancelled(options.cancellationToken);
      if (!rootPath || (typeof resolver.canResolve === "function" && !(await resolver.canResolve(rootPath, options)))) {
        return [];
      }
      throwIfCancelled(options.cancellationToken);
      const detections = typeof resolver.detect === "function"
        ? await resolver.detect(rootPath, options)
        : [];
      throwIfCancelled(options.cancellationToken);
      return detections;
    },
    async parse(detection, options) {
      try {
        throwIfCancelled(options && options.cancellationToken);
        const safeDetection = await resolveDetectionPaths(
          detection,
          options && options.workspaceFolder
        );
        const legacyTree = await LockfileResolver.resolve(
          resolver.name,
          safeDetection.lockfilePath,
          safeDetection.manifestPath,
          {
            ...options,
            workspaceFolder: safeDetection.workspaceFolder,
          }
        );
        throwIfCancelled(options && options.cancellationToken);
        const sources = createSourceSet(safeDetection, resolver);
        const declaredConstraints = await readDeclaredConstraintIndex(
          sources.manifest,
          resolver.ecosystem,
          safeDetection.workspaceFolder,
          options
        );
        const dependencyGraph = adaptPackageLockGraph(legacyTree && legacyTree.dependencyGraph);
        const dependencies = (legacyTree && legacyTree.dependencies || []).map((dependency) => (
          adaptLegacyDependency(
            dependency,
            legacyTree,
            sources,
            declaredConstraints,
            safeDetection.workspaceFolder,
            Boolean(dependencyGraph)
          )
        ));
        const warnings = Array.isArray(legacyTree && legacyTree.warnings)
          ? legacyTree.warnings.slice()
          : [];

        return createAdapterResult({
          status: warnings.length > 0
            ? ADAPTER_RESULT_STATUSES.PARTIAL
            : ADAPTER_RESULT_STATUSES.SUCCESS,
          adapterId: resolver.name,
          ecosystem: resolver.ecosystem,
          sourceFile: getAdapterSourceLabel(sources, legacyTree && legacyTree.sourceFile || safeDetection.sourceFile),
          source: sources,
          dependencies,
          dependencyGraph,
          warnings,
          resolutionAvailability: sources.resolution
            ? RESOLUTION_AVAILABILITY.AVAILABLE
            : missingResolutionAvailability(resolver.name),
        });
      } catch (error) {
        return createAdapterResult({
          status: ADAPTER_RESULT_STATUSES.ERROR,
          adapterId: resolver.name,
          ecosystem: resolver.ecosystem,
          sourceFile: detection && detection.sourceFile || null,
          resolutionAvailability: RESOLUTION_AVAILABILITY.NOT_APPLICABLE,
          error: createSafeAdapterError(error),
        });
      }
    },
    parseManifest: manifestTypes.length > 0 || resolver.name === "nugetParser"
      ? (manifest, options) => parseLegacyManifest(resolver, manifest, options)
      : undefined,
  });
}

async function parseLegacyManifest(resolver, manifest, options = {}) {
  const manifestType = normalizeManifestType(path.basename(String(manifest && manifest.filePath || "")));
  const parser = LEGACY_MANIFEST_PARSERS[manifestType];
  const useResolverDirectly = RESOLVER_DIRECT_MANIFEST_TYPES.has(manifestType)
    || (resolver.name === "dockerParser" && manifestType.startsWith("dockerfile."))
    || (resolver.name === "nugetParser" && manifestType.endsWith(".csproj"));
  if (!parser && !useResolverDirectly) {
    return createAdapterResult({
      status: ADAPTER_RESULT_STATUSES.UNSUPPORTED,
      adapterId: resolver.name,
      ecosystem: resolver.ecosystem,
      sourceFile: manifestType || null,
      resolutionAvailability: RESOLUTION_AVAILABILITY.NOT_APPLICABLE,
      error: {
        code: "unsupported-manifest",
        message: `No direct manifest parser supports ${manifestType || "this manifest"}.`,
      },
    });
  }

  try {
    throwIfCancelled(options.cancellationToken);
    const workspaceFolder = getWorkspacePath(manifest.workspaceFolder);
    if (!workspaceFolder) {
      throw createDependencyFileBoundaryError();
    }
    const safeWorkspaceFolder = await resolveWorkspaceFilePath(workspaceFolder, workspaceFolder);
    const safeFilePath = await resolveWorkspaceFilePath(manifest.filePath, workspaceFolder);
    if (!safeFilePath) {
      throw createDependencyFileBoundaryError();
    }
    const content = await readUtf8(safeFilePath, workspaceFolder, options);
    if (manifestType === "package.json") {
      JSON.parse(content);
    }

    const sourceManifest = createDependencySource({
      kind: RESOLUTION_SOURCE_KINDS.MANIFEST,
      filePath: safeFilePath,
      type: path.basename(safeFilePath),
      workspaceFolder,
    });
    if (useResolverDirectly) {
      const resolverResult = await parseResolverManifest(
        resolver,
        safeFilePath,
        safeWorkspaceFolder || workspaceFolder,
        sourceManifest,
        options
      );
      return resolverResult;
    }
    const dependencies = parser(content, resolver, options).map((dependency) => adaptLegacyManifestDependency(
      dependency,
      resolver.ecosystem,
      sourceManifest
    ));

    return createAdapterResult({
      status: ADAPTER_RESULT_STATUSES.SUCCESS,
      adapterId: resolver.name,
      ecosystem: resolver.ecosystem,
      sourceFile: sourceManifest.label,
      source: Object.freeze({ manifest: sourceManifest, resolution: null }),
      dependencies,
      resolutionAvailability: missingResolutionAvailability(resolver.name),
    });
  } catch (error) {
    return createAdapterResult({
      status: ADAPTER_RESULT_STATUSES.ERROR,
      adapterId: resolver.name,
      ecosystem: resolver.ecosystem,
      sourceFile: manifestType || null,
      resolutionAvailability: RESOLUTION_AVAILABILITY.NOT_APPLICABLE,
      error: createSafeAdapterError(error),
    });
  }
}

async function parseResolverManifest(resolver, safeFilePath, workspaceFolder, sourceManifest, options = {}) {
  const manifestType = normalizeManifestType(path.basename(safeFilePath));
  const isLockfileShapedManifest = manifestType === "requirements.txt"
    || manifestType === "dockerfile"
    || manifestType.startsWith("dockerfile.")
    || ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"].includes(manifestType);
  const legacyTree = await LockfileResolver.resolve(
    resolver.name,
    isLockfileShapedManifest ? safeFilePath : null,
    isLockfileShapedManifest ? null : safeFilePath,
    { ...options, workspaceFolder }
  );
  const sources = Object.freeze({
    manifest: sourceManifest,
    resolution: null,
    adapterId: resolver.name,
  });
  const declaredConstraints = await readDeclaredConstraintIndex(
    sourceManifest,
    resolver.ecosystem,
    workspaceFolder,
    options
  );
  const dependencies = (legacyTree && legacyTree.dependencies || []).map((dependency) => (
    adaptLegacyDependency(
      dependency,
      legacyTree,
      sources,
      declaredConstraints,
      workspaceFolder
    )
  ));
  const warnings = Array.isArray(legacyTree && legacyTree.warnings)
    ? legacyTree.warnings.slice()
    : [];

  return createAdapterResult({
    status: warnings.length > 0
      ? ADAPTER_RESULT_STATUSES.PARTIAL
      : ADAPTER_RESULT_STATUSES.SUCCESS,
    adapterId: resolver.name,
    ecosystem: resolver.ecosystem,
    sourceFile: sourceManifest.label || legacyTree && legacyTree.sourceFile || path.basename(safeFilePath),
    source: sources,
    dependencies,
    warnings,
    resolutionAvailability: missingResolutionAvailability(resolver.name),
  });
}

async function resolveDetectionPaths(detection, callerWorkspaceFolder) {
  const workspaceFolder = getWorkspacePath(
    callerWorkspaceFolder || detection && detection.workspaceFolder
  );
  if (!workspaceFolder) {
    throw createDependencyFileBoundaryError();
  }
  const safeWorkspaceFolder = await resolveWorkspaceFilePath(workspaceFolder, workspaceFolder);

  const lockfilePath = detection && detection.lockfilePath
    ? await resolveWorkspaceFilePath(detection.lockfilePath, workspaceFolder)
    : null;
  const manifestPath = detection && detection.manifestPath
    ? await resolveWorkspaceFilePath(detection.manifestPath, workspaceFolder)
    : null;
  if (detection && detection.lockfilePath && !lockfilePath) {
    throw createDependencyFileBoundaryError();
  }
  if (detection && detection.manifestPath && !manifestPath) {
    throw createDependencyFileBoundaryError();
  }

  return {
    ...detection,
    workspaceFolder: safeWorkspaceFolder || workspaceFolder,
    lockfilePath,
    manifestPath,
    sourceFile: detection && detection.sourceFile
      || path.basename(lockfilePath || manifestPath || ""),
  };
}

function createSourceSet(detection, resolver) {
  const lockfileKind = getSourceKind(detection.lockfilePath);
  const manifestPath = lockfileKind === RESOLUTION_SOURCE_KINDS.MANIFEST
    ? detection.lockfilePath
    : detection.manifestPath;
  const resolutionPath = lockfileKind && lockfileKind !== RESOLUTION_SOURCE_KINDS.MANIFEST
    ? detection.lockfilePath
    : null;

  return Object.freeze({
    manifest: manifestPath
      ? createDependencySource({
        kind: RESOLUTION_SOURCE_KINDS.MANIFEST,
        filePath: manifestPath,
        type: path.basename(manifestPath),
        workspaceFolder: detection.workspaceFolder,
      })
      : null,
    resolution: resolutionPath
      ? createDependencySource({
        kind: lockfileKind,
        filePath: resolutionPath,
        type: path.basename(resolutionPath),
        workspaceFolder: detection.workspaceFolder,
      })
      : null,
    adapterId: resolver.name,
  });
}

function getSourceKind(filePath) {
  if (!filePath) {
    return null;
  }
  const type = normalizeManifestType(path.basename(filePath));
  if (LOCKFILE_TYPES.has(type)) {
    return RESOLUTION_SOURCE_KINDS.LOCKFILE;
  }
  if (PACKAGE_MANAGER_OUTPUT_TYPES.has(type)) {
    return RESOLUTION_SOURCE_KINDS.PACKAGE_MANAGER;
  }
  return RESOLUTION_SOURCE_KINDS.MANIFEST;
}

async function readDeclaredConstraintIndex(sourceManifest, ecosystem, workspaceFolder, options = {}) {
  const index = new Map();
  if (!sourceManifest) {
    return index;
  }
  const parser = LEGACY_MANIFEST_PARSERS[normalizeManifestType(sourceManifest.type)];
  if (!parser) {
    return index;
  }

  throwIfCancelled(options.cancellationToken);
  const content = await readUtf8(sourceManifest.filePath, workspaceFolder, options);
  if (normalizeManifestType(sourceManifest.type) === "package.json") {
    JSON.parse(content);
  }
  for (const dependency of parser(content, null, options)) {
    const name = normalizePackageName(dependency.name, ecosystem);
    if (!name || index.has(name)) {
      continue;
    }
    index.set(name, Object.freeze({
      declaredConstraint: dependency.declaredConstraint != null
        ? String(dependency.declaredConstraint).trim()
        : String(dependency.version || "").trim(),
      environmentMarker: optionalConstraint(dependency.environmentMarker),
    }));
  }
  return index;
}

function adaptLegacyDependency(
  dependency,
  tree,
  sources,
  declaredConstraints,
  workspaceFolder,
  omitTransitives = false
) {
  const ecosystem = dependency.ecosystem || tree.ecosystem;
  const format = dependency.format || canonicalFormat(ecosystem);
  const name = String(dependency.name || "").trim();
  const declarationName = String(dependency.declaredName || dependency.declarationName || name).trim();
  const indexedDeclaration = dependency.isDirect
    ? declaredConstraints.get(normalizePackageName(declarationName, format)) || null
    : null;
  const indexedConstraint = indexedDeclaration && indexedDeclaration.declaredConstraint || null;
  const declaredConstraint = optionalConstraint(dependency.declaredConstraint) || indexedConstraint;
  const environmentMarker = optionalConstraint(dependency.environmentMarker)
    || (indexedDeclaration && indexedDeclaration.environmentMarker)
    || null;
  const explicitResolvedVersion = optionalConstraint(dependency.resolvedVersion);
  const candidateResolvedVersion = explicitResolvedVersion || optionalConstraint(dependency.version);
  const hasExplicitResolutionFlag = Object.prototype.hasOwnProperty.call(
    dependency,
    "hasResolutionEvidence"
  );
  const parserQualifiers = adaptDependencyQualifiers(dependency);
  const usesAuthoritativeManifestResolution = format === "docker"
    && dependency.hasResolutionEvidence === true
    && Boolean(parserQualifiers.tag || parserQualifiers.digest)
    && Boolean(sources.manifest);
  const effectiveResolutionSource = sources.resolution
    || (usesAuthoritativeManifestResolution ? sources.manifest : null);
  const hasResolutionEvidence = Boolean(
    effectiveResolutionSource
    && candidateResolvedVersion
    && !environmentMarker
    && (!hasExplicitResolutionFlag || dependency.hasResolutionEvidence === true)
  );
  const resolvedVersion = hasResolutionEvidence ? candidateResolvedVersion : null;
  let versionState = normalizeVersionState(
    dependency.versionState || dependency.manifestVersionState
  ) || classifyDeclaredConstraint(declaredConstraint, ecosystem);
  if (environmentMarker) {
    versionState = DEPENDENCY_VERSION_STATES.INCOMPLETE;
  } else if (resolvedVersion) {
    versionState = DEPENDENCY_VERSION_STATES.RESOLVED;
  }
  const transitives = !omitTransitives && Array.isArray(dependency.transitives)
    ? dependency.transitives.map((child) => adaptLegacyDependency(
      child,
      tree,
      sources,
      declaredConstraints,
      workspaceFolder,
      false
    ))
    : [];
  const sourceManifest = dependency.isDirect
    ? createDependencyManifestSource(dependency, sources.manifest, workspaceFolder)
    : null;
  const qualifiers = parserQualifiers;
  const packageSource = adaptDependencyPackageSource(dependency, declaredConstraint);

  return createDependencyRecord({
    ecosystem,
    format,
    name,
    declarationName,
    declaredConstraint,
    resolvedVersion,
    versionState,
    resolutionSource: resolvedVersion ? effectiveResolutionSource : null,
    sourceManifest,
    packageSource,
    qualifiers,
    environmentMarker,
    isDirect: dependency.isDirect,
    isDevelopmentDependency: dependency.isDevelopmentDependency || dependency.devDependency,
    parent: dependency.parent,
    parentChain: dependency.parentChain,
    transitives,
    legacyVersion: dependency.version,
  });
}

function adaptPackageLockGraph(graph) {
  if (graph == null) {
    return null;
  }
  if (!graph || typeof graph !== "object" || Array.isArray(graph) || graph.kind !== "package-lock") {
    throw new TypeError("Package-lock structural graph must use the package-lock contract.");
  }
  if (!Array.isArray(graph.entries) || graph.entries.length > MAX_STRUCTURAL_GRAPH_ENTRIES) {
    throw new TypeError("Package-lock structural graph entries exceed the supported bound.");
  }
  if (!Array.isArray(graph.roots) || graph.roots.length > MAX_STRUCTURAL_GRAPH_ENTRIES) {
    throw new TypeError("Package-lock structural graph roots exceed the supported bound.");
  }

  const keys = new Set();
  let edgeCount = 0;
  const entries = graph.entries.map((entry) => {
    const key = requiredGraphString(entry && entry.key, "entry key");
    if (keys.has(key)) {
      throw new TypeError("Package-lock structural graph entry keys must be unique.");
    }
    keys.add(key);
    if (!Array.isArray(entry.edges)) {
      throw new TypeError("Package-lock structural graph entry edges must be an array.");
    }
    edgeCount += entry.edges.length;
    if (edgeCount > MAX_STRUCTURAL_GRAPH_EDGES) {
      throw new TypeError("Package-lock structural graph edges exceed the supported bound.");
    }
    return Object.freeze({
      key,
      name: requiredGraphString(entry.name, "package name"),
      installedName: requiredGraphString(entry.installedName, "installed name"),
      version: requiredGraphString(entry.version, "package version"),
      isDevelopmentDependency: entry.isDevelopmentDependency === true,
      edges: Object.freeze(entry.edges.map((edge) => Object.freeze({
        declaredName: requiredGraphString(edge && edge.declaredName, "dependency name"),
        childKey: edge && edge.childKey == null
          ? null
          : requiredGraphString(edge.childKey, "child key"),
      }))),
    });
  });

  const roots = graph.roots.map((root) => Object.freeze({
    declaredName: requiredGraphString(root && root.declaredName, "root dependency name"),
    entryKey: root && root.entryKey == null
      ? null
      : requiredGraphString(root.entryKey, "root entry key"),
    isDevelopmentDependency: root && root.isDevelopmentDependency === true,
  }));
  for (const root of roots) {
    if (root.entryKey && !keys.has(root.entryKey) && graph.incomplete !== true) {
      throw new TypeError("Complete package-lock structural graph roots must reference known entries.");
    }
  }
  for (const entry of entries) {
    for (const edge of entry.edges) {
      if (edge.childKey && !keys.has(edge.childKey) && graph.incomplete !== true) {
        throw new TypeError("Complete package-lock structural graph edges must reference known entries.");
      }
    }
  }

  return Object.freeze({
    kind: "package-lock",
    entries: Object.freeze(entries),
    roots: Object.freeze(roots),
    incomplete: graph.incomplete === true,
    maxDepth: requiredGraphLimit(graph.maxDepth, 128, "depth"),
    maxNodes: requiredGraphLimit(graph.maxNodes, MAX_STRUCTURAL_GRAPH_ENTRIES, "node"),
    maxEdges: requiredGraphLimit(graph.maxEdges, MAX_STRUCTURAL_GRAPH_EDGES, "edge"),
  });
}

function requiredGraphLimit(value, maximum, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new TypeError(`Package-lock structural graph ${label} limit is invalid.`);
  }
  return value;
}

function requiredGraphString(value, label) {
  const normalized = String(value || "").trim();
  if (!normalized || normalized.length > 8192) {
    throw new TypeError(`Package-lock structural graph ${label} is invalid.`);
  }
  return normalized;
}

function adaptLegacyManifestDependency(dependency, ecosystem, sourceManifest) {
  const declaredConstraint = dependency.declaredConstraint != null
    ? String(dependency.declaredConstraint).trim()
    : String(dependency.version || "").trim() || null;
  const versionState = dependency.environmentMarker
    ? DEPENDENCY_VERSION_STATES.INCOMPLETE
    : normalizeVersionState(dependency.versionState || dependency.manifestVersionState)
      || classifyDeclaredConstraint(declaredConstraint, ecosystem);
  return createDependencyRecord({
    ecosystem,
    format: dependency.format || canonicalFormat(ecosystem),
    name: dependency.name,
    declarationName: dependency.declaredName || dependency.declarationName || dependency.name,
    declaredConstraint,
    resolvedVersion: null,
    versionState,
    resolutionSource: null,
    sourceManifest,
    packageSource: adaptDependencyPackageSource(dependency, declaredConstraint),
    qualifiers: adaptDependencyQualifiers(dependency),
    environmentMarker: dependency.environmentMarker,
    isDirect: true,
    isDevelopmentDependency: dependency.isDevelopmentDependency || dependency.devDependency,
    parent: null,
    parentChain: [],
    transitives: [],
    legacyVersion: dependency.version,
  });
}

function classifyDeclaredConstraint(constraint, ecosystem) {
  const value = String(constraint || "").trim();
  if (!value) {
    return DEPENDENCY_VERSION_STATES.UNRESOLVED;
  }
  if (
    value.includes("${")
    || /^(?:workspace|file|git|path|link|https?):/i.test(value)
    || /^npm:[^@]+(?:@|$)/i.test(value)
  ) {
    return DEPENDENCY_VERSION_STATES.INCOMPLETE;
  }

  const normalizedEcosystem = canonicalFormat(ecosystem);
  if (normalizedEcosystem === "npm") {
    const exactCandidate = /^=\s*/.test(value) && !/^==/.test(value)
      ? value.replace(/^=\s*/, "")
      : value;
    if (isExactNpmVersion(exactCandidate)) {
      return DEPENDENCY_VERSION_STATES.EXACT_DECLARATION;
    }
    if (
      /^(?:v?\d+|v?\d+\.\d+)$/.test(value)
      || /(?:^|\.)[xX*](?:\.|$)/.test(value)
      || value === "*"
      || /[~^<>=!|,]/.test(value)
      || /\s+-\s+/.test(value)
    ) {
      return DEPENDENCY_VERSION_STATES.RANGE;
    }
    return DEPENDENCY_VERSION_STATES.INCOMPLETE;
  }
  if (normalizedEcosystem === "python") {
    if (/^={2,3}\s*[^*\s,;]+$/.test(value)) {
      return DEPENDENCY_VERSION_STATES.EXACT_DECLARATION;
    }
    if (/^v?\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$/.test(value)) {
      return DEPENDENCY_VERSION_STATES.EXACT_DECLARATION;
    }
    return DEPENDENCY_VERSION_STATES.RANGE;
  }
  if (normalizedEcosystem === "cargo") {
    return /^=\s*v?\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$/.test(value)
      ? DEPENDENCY_VERSION_STATES.EXACT_DECLARATION
      : DEPENDENCY_VERSION_STATES.RANGE;
  }
  if (normalizedEcosystem === "nuget") {
    return /^\[\s*[^,\]]+\s*]$/.test(value)
      ? DEPENDENCY_VERSION_STATES.EXACT_DECLARATION
      : DEPENDENCY_VERSION_STATES.RANGE;
  }
  if (/^v?\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$/.test(value)) {
    return DEPENDENCY_VERSION_STATES.EXACT_DECLARATION;
  }
  if (/[~^<>=!*,|]/.test(value) || /\s+-\s+/.test(value)) {
    return DEPENDENCY_VERSION_STATES.RANGE;
  }
  return DEPENDENCY_VERSION_STATES.INCOMPLETE;
}

function isExactNpmVersion(value) {
  return /^v?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.test(
    String(value || "")
  );
}

function normalizeVersionState(versionState) {
  const value = String(versionState || "").trim();
  return Object.values(DEPENDENCY_VERSION_STATES).includes(value) ? value : null;
}

function optionalConstraint(value) {
  const normalized = String(value == null ? "" : value).trim();
  return normalized || null;
}

function createDependencyManifestSource(dependency, fallbackSource, workspaceFolder) {
  const candidate = optionalConstraint(dependency.sourceManifestPath);
  if (!candidate) {
    return fallbackSource;
  }
  const workspaceRoot = path.resolve(getWorkspacePath(workspaceFolder));
  const candidatePath = path.resolve(candidate);
  const relativePath = path.relative(workspaceRoot, candidatePath);
  if (relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
    return fallbackSource;
  }
  return createDependencySource({
    kind: RESOLUTION_SOURCE_KINDS.MANIFEST,
    filePath: candidatePath,
    type: path.basename(candidatePath),
    workspaceFolder,
  });
}

function adaptDependencyQualifiers(dependency) {
  const canonical = dependency && dependency.qualifiers != null
    ? createDependencyQualifiers(dependency.qualifiers)
    : Object.freeze({});
  const compatibilityValues = {
    targetFramework: dependency && dependency.targetFramework,
    platform: dependency && dependency.platform,
    scope: dependency && dependency.scope,
    type: dependency && (dependency.mavenType || dependency.type),
    classifier: dependency && (dependency.mavenClassifier || dependency.classifier),
    configurations: dependency && dependency.configurations,
    repository: dependency && dependency.repository,
    alias: dependency && dependency.alias,
    service: dependency && dependency.service,
    pullPolicy: dependency && dependency.pullPolicy,
    tag: dependency && dependency.tag,
    digest: dependency && dependency.digest,
    stage: dependency && dependency.stage,
    environment: dependency && dependency.environment,
    section: dependency && dependency.section,
  };
  const compatibility = Object.fromEntries(Object.entries(compatibilityValues).filter(
    ([key, value]) => value != null && !Object.prototype.hasOwnProperty.call(canonical, key)
  ));
  return createDependencyQualifiers({ ...compatibility, ...canonical });
}

function adaptDependencyPackageSource(dependency, declaredConstraint) {
  if (dependency && dependency.packageSource != null) {
    return createDependencyPackageSource(dependency.packageSource);
  }
  const compatibilityKind = optionalConstraint(dependency && dependency.sourceKind);
  if (compatibilityKind) {
    return createDependencyPackageSource({
      kind: compatibilityKind,
      ...(dependency.sourceLocation != null ? { location: dependency.sourceLocation } : {}),
      ...(dependency.sourceBranch != null ? { branch: dependency.sourceBranch } : {}),
      ...(dependency.sourceRevision != null ? { revision: dependency.sourceRevision } : {}),
    });
  }

  const branch = optionalConstraint(dependency && dependency.sourceBranch);
  const revision = optionalConstraint(dependency && dependency.sourceRevision);
  const sourceLocation = optionalConstraint(
    dependency && (dependency.sourceLocation || dependency.repositoryUrl)
  );
  if (branch || revision) {
    return createDependencyPackageSource({
      kind: DEPENDENCY_PACKAGE_SOURCE_KINDS.SCM,
      ...(sourceLocation ? { location: sourceLocation } : {}),
      ...(branch ? { branch } : {}),
      ...(revision ? { revision } : {}),
    });
  }

  const evidence = [
    declaredConstraint,
    dependency && dependency.resolved,
    dependency && dependency.source,
    dependency && dependency.replacementTarget,
  ].map((value) => String(value || "").trim()).filter(Boolean).join(" ");
  const inferredKind = inferPackageSourceKind(evidence);
  return createDependencyPackageSource({
    kind: inferredKind,
    ...(sourceLocation ? { location: sourceLocation } : {}),
  });
}

function inferPackageSourceKind(evidence) {
  const value = String(evidence || "").trim();
  if (!value) return DEPENDENCY_PACKAGE_SOURCE_KINDS.REGISTRY;
  if (/(?:^|\s)(?:workspace|link):/i.test(value)) return DEPENDENCY_PACKAGE_SOURCE_KINDS.LOCAL;
  if (/(?:^|\s)(?:file|path):/i.test(value) || /(?:^|\s)(?:\.\.?[/\\]|[/\\])/i.test(value)) {
    return DEPENDENCY_PACKAGE_SOURCE_KINDS.PATH;
  }
  if (/(?:^|\s)(?:git\+|git:|github:|gitlab:|bitbucket:)/i.test(value) || /(?:^|\s)git@/i.test(value)) {
    return DEPENDENCY_PACKAGE_SOURCE_KINDS.GIT;
  }
  if (/(?:^|\s)(?:sdk|system):/i.test(value)) {
    return /(?:^|\s)sdk:/i.test(value)
      ? DEPENDENCY_PACKAGE_SOURCE_KINDS.SDK
      : DEPENDENCY_PACKAGE_SOURCE_KINDS.SYSTEM;
  }
  if (/(?:^|\s)https?:/i.test(value)) return DEPENDENCY_PACKAGE_SOURCE_KINDS.SCM;
  return DEPENDENCY_PACKAGE_SOURCE_KINDS.REGISTRY;
}

function getAdapterSourceLabel(sources, fallback) {
  return sources && (sources.resolution && sources.resolution.label
    || sources.manifest && sources.manifest.label)
    || String(fallback || "");
}

function throwIfCancelled(cancellationToken) {
  if (cancellationToken && cancellationToken.isCancellationRequested) {
    const error = new Error("Dependency adapter operation was cancelled.");
    error.code = "ERR_DEPENDENCY_ADAPTER_CANCELLED";
    throw error;
  }
}

function createDependencyFileBoundaryError() {
  const error = new Error("Dependency file path rejected by the workspace boundary.");
  error.code = DEPENDENCY_FILE_ERROR_CODES.OUTSIDE_WORKSPACE;
  return error;
}

/**
 * Map parser and filesystem failures onto closed, customer-safe adapter
 * categories. Parser messages can contain complete source lines, absolute
 * paths, URLs, credentials, or internal safety bounds, so none of their text
 * crosses the adapter boundary.
 */
function createSafeAdapterError(error) {
  const internalCode = error && typeof error.code === "string"
    ? error.code
    : "";
  let publicCode;
  if (Object.prototype.hasOwnProperty.call(SAFE_ADAPTER_ERROR_MESSAGES, internalCode)) {
    publicCode = internalCode;
  } else if (Object.prototype.hasOwnProperty.call(
    DEPENDENCY_FILE_ADAPTER_ERROR_CODES,
    internalCode
  )) {
    publicCode = DEPENDENCY_FILE_ADAPTER_ERROR_CODES[internalCode];
  } else if (internalCode === "ENOENT" || internalCode === "ENOTDIR") {
    publicCode = ADAPTER_ERROR_CODES.DEPENDENCY_FILE_MISSING;
  } else if (/cancel(?:led|ed|lation)/i.test(internalCode)) {
    publicCode = ADAPTER_ERROR_CODES.CANCELLED;
  } else {
    publicCode = ADAPTER_ERROR_CODES.PARSE_ERROR;
  }
  return Object.freeze({
    code: publicCode,
    message: SAFE_ADAPTER_ERROR_MESSAGES[publicCode],
  });
}

function createAdapterResult(values) {
  const adapterId = values.adapterId || "<unknown>";
  if (!ADAPTER_RESULT_STATUS_VALUES.has(values.status)) {
    throw new TypeError(`Dependency adapter "${adapterId}" result must use a supported status.`);
  }
  if (values.dependencies != null && !Array.isArray(values.dependencies)) {
    throw new TypeError(`Dependency adapter "${adapterId}" result dependencies must be an array.`);
  }
  if (values.warnings != null && !Array.isArray(values.warnings)) {
    throw new TypeError(`Dependency adapter "${adapterId}" result warnings must be an array.`);
  }

  const error = values.error
    ? createSafeAdapterError(values.error)
    : null;
  const warnings = Array.isArray(values.warnings)
    ? [...new Set(values.warnings.map(createSafeAdapterWarning))]
    : [];
  return Object.freeze({
    status: values.status,
    adapterId: values.adapterId || null,
    ecosystem: values.ecosystem || null,
    sourceFile: values.sourceFile
      ? boundedAdapterText(values.sourceFile, "source file", 8192)
      : null,
    source: values.source || null,
    dependencies: Object.freeze(Array.isArray(values.dependencies) ? values.dependencies.slice() : []),
    dependencyGraph: values.dependencyGraph || null,
    warnings: Object.freeze(warnings),
    error,
    resolutionAvailability: values.resolutionAvailability || RESOLUTION_AVAILABILITY.NOT_APPLICABLE,
  });
}

function createSafeAdapterWarning(warning) {
  const normalized = boundedAdapterText(String(warning || ""), "warning").toLowerCase();
  if (SAFE_DOCKER_ADAPTER_WARNINGS.has(normalized)) {
    return SAFE_DOCKER_ADAPTER_WARNINGS.get(normalized);
  }
  if (normalized.includes("display is capped") || normalized.includes("display reached")) {
    return "Dependency display reached its configured safety limit.";
  }
  if (normalized.includes("environment marker") || normalized.includes("conditional requirement")) {
    return "Some conditional dependencies do not have a concrete version.";
  }
  if (normalized.includes("direct dependency relationship")) {
    return "Direct dependency relationships could not be determined for some packages.";
  }
  if (normalized.includes("no locally resolvable version")) {
    return "Some Maven dependencies do not have a locally resolvable version.";
  }
  if (normalized.includes("maven dependency tree output")) {
    return "Some Maven dependency relationships could not be resolved.";
  }
  if (normalized.includes("compose")) {
    return "Some Compose dependencies could not be fully resolved.";
  }
  if (
    normalized.includes("relationship")
    || normalized.includes("transitive")
    || normalized.includes("graph")
  ) {
    return "Some dependency relationships could not be fully analyzed.";
  }
  if (normalized.includes("skipped") || normalized.includes("omitted")) {
    return "Some dependency declarations could not be fully analyzed.";
  }
  return "Some dependency data could not be fully analyzed.";
}

function boundedAdapterText(value, label, maximum = 2048) {
  if (typeof value !== "string") {
    throw new TypeError(`Dependency adapter ${label} values must be strings.`);
  }
  const normalized = value.replace(/[\r\n\t\u0000-\u001f\u007f]+/g, " ").trim();
  if (!normalized) {
    throw new TypeError(`Dependency adapter ${label} values must not be empty.`);
  }
  return normalized.length <= maximum ? normalized : `${normalized.slice(0, maximum - 1)}…`;
}

function validateDetectionResult(adapter, detections) {
  if (!Array.isArray(detections)) {
    throw new TypeError(`Dependency adapter "${adapter.id}" detect() must return an array.`);
  }
  return detections;
}

function validateAdapterResult(adapter, methodName, result) {
  const methodLabel = `Dependency adapter "${adapter.id}" ${methodName}()`;
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new TypeError(`${methodLabel} must return an adapter result object.`);
  }
  if (!ADAPTER_RESULT_STATUS_VALUES.has(result.status)) {
    throw new TypeError(`${methodLabel} result must use a supported status.`);
  }
  if (!Array.isArray(result.dependencies)) {
    throw new TypeError(`${methodLabel} result dependencies must be an array.`);
  }
  if (!Array.isArray(result.warnings)) {
    throw new TypeError(`${methodLabel} result warnings must be an array.`);
  }
  return result;
}

function missingResolutionAvailability(adapterId) {
  return ["goParser", "dockerParser"].includes(adapterId)
    ? RESOLUTION_AVAILABILITY.NOT_APPLICABLE
    : RESOLUTION_AVAILABILITY.MISSING;
}

function normalizeManifestType(manifestType) {
  return String(manifestType || "").trim().toLowerCase();
}

module.exports = {
  ADAPTER_ERROR_CODES,
  ADAPTER_RESULT_STATUSES,
  DependencyAdapterRegistry,
  RESOLUTION_AVAILABILITY,
  createDefaultDependencyAdapterRegistry,
  createSafeAdapterError,
  createSafeAdapterWarning,
};

// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const { ManifestParser } = require("./manifestParser");
const { LockfileResolver } = require("./lockfileResolver");
const { discoverDependencyManifests } = require("./dependencyManifestDiscovery");
const {
  DEPENDENCY_VERSION_STATES,
  RESOLUTION_SOURCE_KINDS,
  createDependencyRecord,
  createDependencySource,
} = require("./dependencyRecord");
const {
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

const RESOLUTION_AVAILABILITY = Object.freeze({
  AVAILABLE: "available",
  MISSING: "missing",
  NOT_APPLICABLE: "not-applicable",
});

const RESOLVER_MANIFEST_TYPES = Object.freeze({
  npmParser: ["package.json"],
  pythonParser: ["requirements.txt", "pyproject.toml"],
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

  async detect(workspaceFolder) {
    const workspaceRoot = getWorkspacePath(workspaceFolder);
    const discovery = await discoverDependencyManifests(workspaceRoot);
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
        const adapter = this._adapters.get(adapterId);
        const adapterDetections = validateDetectionResult(
          adapter,
          await adapter.detect(projectRoot)
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

  async detectManifests(workspaceFolder) {
    const discovery = await discoverDependencyManifests(workspaceFolder);
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

  async parseManifest(manifest) {
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

    return validateAdapterResult(adapter, "parseManifest", await adapter.parseManifest(manifest));
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
    async detect(workspaceFolder) {
      const rootPath = getWorkspacePath(workspaceFolder);
      if (!rootPath || (typeof resolver.canResolve === "function" && !(await resolver.canResolve(rootPath)))) {
        return [];
      }
      const detections = typeof resolver.detect === "function"
        ? await resolver.detect(rootPath)
        : [];
      return detections;
    },
    async parse(detection, options) {
      try {
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
        const sources = createSourceSet(safeDetection, resolver);
        const declaredConstraints = await readDeclaredConstraintIndex(
          sources.manifest,
          resolver.ecosystem,
          safeDetection.workspaceFolder
        );
        const dependencies = (legacyTree && legacyTree.dependencies || []).map((dependency) => (
          adaptLegacyDependency(
            dependency,
            legacyTree,
            sources,
            declaredConstraints,
            safeDetection.workspaceFolder
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
          sourceFile: legacyTree && legacyTree.sourceFile || safeDetection.sourceFile,
          source: sources,
          dependencies,
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
          error: {
            code: "parse-error",
            message: error && error.message ? error.message : "Dependency parsing failed.",
          },
        });
      }
    },
    parseManifest: manifestTypes.length > 0 || resolver.name === "nugetParser"
      ? (manifest) => parseLegacyManifest(resolver, manifest)
      : undefined,
  });
}

async function parseLegacyManifest(resolver, manifest) {
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
    const workspaceFolder = getWorkspacePath(manifest.workspaceFolder);
    if (!workspaceFolder) {
      throw new Error("Dependency manifests require a workspace folder.");
    }
    const safeWorkspaceFolder = await resolveWorkspaceFilePath(workspaceFolder, workspaceFolder);
    const safeFilePath = await resolveWorkspaceFilePath(manifest.filePath, workspaceFolder);
    if (!safeFilePath) {
      throw new Error("Manifest paths must stay within the workspace folder.");
    }
    const content = await readUtf8(safeFilePath, workspaceFolder);
    if (manifestType === "package.json") {
      JSON.parse(content);
    }

    const sourceManifest = createDependencySource({
      kind: RESOLUTION_SOURCE_KINDS.MANIFEST,
      filePath: safeFilePath,
      type: path.basename(safeFilePath),
    });
    if (useResolverDirectly) {
      return parseResolverManifest(
        resolver,
        safeFilePath,
        safeWorkspaceFolder || workspaceFolder,
        sourceManifest
      );
    }
    const dependencies = parser(content).map((dependency) => adaptLegacyManifestDependency(
      dependency,
      resolver.ecosystem,
      sourceManifest
    ));

    return createAdapterResult({
      status: ADAPTER_RESULT_STATUSES.SUCCESS,
      adapterId: resolver.name,
      ecosystem: resolver.ecosystem,
      sourceFile: path.basename(safeFilePath),
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
      error: {
        code: "parse-error",
        message: error && error.message ? error.message : "Manifest parsing failed.",
      },
    });
  }
}

async function parseResolverManifest(resolver, safeFilePath, workspaceFolder, sourceManifest) {
  const manifestType = normalizeManifestType(path.basename(safeFilePath));
  const isLockfileShapedManifest = manifestType === "requirements.txt"
    || manifestType === "dockerfile"
    || manifestType.startsWith("dockerfile.")
    || ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"].includes(manifestType);
  const legacyTree = await LockfileResolver.resolve(
    resolver.name,
    isLockfileShapedManifest ? safeFilePath : null,
    isLockfileShapedManifest ? null : safeFilePath,
    { workspaceFolder }
  );
  const sources = Object.freeze({
    manifest: sourceManifest,
    resolution: null,
    adapterId: resolver.name,
  });
  const declaredConstraints = await readDeclaredConstraintIndex(
    sourceManifest,
    resolver.ecosystem,
    workspaceFolder
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
    sourceFile: legacyTree && legacyTree.sourceFile || path.basename(safeFilePath),
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
    throw new Error("Dependency detections require a workspace folder.");
  }
  const safeWorkspaceFolder = await resolveWorkspaceFilePath(workspaceFolder, workspaceFolder);

  const lockfilePath = detection && detection.lockfilePath
    ? await resolveWorkspaceFilePath(detection.lockfilePath, workspaceFolder)
    : null;
  const manifestPath = detection && detection.manifestPath
    ? await resolveWorkspaceFilePath(detection.manifestPath, workspaceFolder)
    : null;
  if (detection && detection.lockfilePath && !lockfilePath) {
    throw new Error("Lockfile paths must stay within the workspace folder.");
  }
  if (detection && detection.manifestPath && !manifestPath) {
    throw new Error("Manifest paths must stay within the workspace folder.");
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
      })
      : null,
    resolution: resolutionPath
      ? createDependencySource({
        kind: lockfileKind,
        filePath: resolutionPath,
        type: path.basename(resolutionPath),
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

async function readDeclaredConstraintIndex(sourceManifest, ecosystem, workspaceFolder) {
  const index = new Map();
  if (!sourceManifest) {
    return index;
  }
  const parser = LEGACY_MANIFEST_PARSERS[normalizeManifestType(sourceManifest.type)];
  if (!parser) {
    return index;
  }

  const content = await readUtf8(sourceManifest.filePath, workspaceFolder);
  if (normalizeManifestType(sourceManifest.type) === "package.json") {
    JSON.parse(content);
  }
  for (const dependency of parser(content)) {
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

function adaptLegacyDependency(dependency, tree, sources, declaredConstraints, workspaceFolder) {
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
  const hasResolutionEvidence = Boolean(
    sources.resolution
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
  const transitives = Array.isArray(dependency.transitives)
    ? dependency.transitives.map((child) => adaptLegacyDependency(
      child,
      tree,
      sources,
      declaredConstraints,
      workspaceFolder
    ))
    : [];
  const sourceManifest = dependency.isDirect
    ? createDependencyManifestSource(dependency, sources.manifest, workspaceFolder)
    : null;

  return createDependencyRecord({
    ecosystem,
    format,
    name,
    declarationName,
    declaredConstraint,
    resolvedVersion,
    versionState,
    resolutionSource: resolvedVersion ? sources.resolution : null,
    sourceManifest,
    environmentMarker,
    isDirect: dependency.isDirect,
    isDevelopmentDependency: dependency.isDevelopmentDependency || dependency.devDependency,
    parent: dependency.parent,
    parentChain: dependency.parentChain,
    transitives,
    legacyVersion: dependency.version,
  });
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
    ? Object.freeze({
      code: String(values.error.code || "unknown-error"),
      message: String(values.error.message || "Dependency adapter failed."),
    })
    : null;
  return Object.freeze({
    status: values.status,
    adapterId: values.adapterId || null,
    ecosystem: values.ecosystem || null,
    sourceFile: values.sourceFile || null,
    source: values.source || null,
    dependencies: Object.freeze(Array.isArray(values.dependencies) ? values.dependencies.slice() : []),
    warnings: Object.freeze(Array.isArray(values.warnings) ? values.warnings.slice() : []),
    error,
    resolutionAvailability: values.resolutionAvailability || RESOLUTION_AVAILABILITY.NOT_APPLICABLE,
  });
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
  ADAPTER_RESULT_STATUSES,
  DependencyAdapterRegistry,
  RESOLUTION_AVAILABILITY,
  createDefaultDependencyAdapterRegistry,
};

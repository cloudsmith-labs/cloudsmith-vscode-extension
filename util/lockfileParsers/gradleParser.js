// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  createDependency,
  getSourceFileName,
  getWorkspacePath,
  pathExists,
  readUtf8,
  throwIfTraversalCancelled,
} = require("./shared");
const { parseBuildGradleManifest } = require("./manifestHelpers");

const BUILD_FILES = ["build.gradle", "build.gradle.kts"];
const MAX_GRADLE_CONFIGURATIONS = 64;
const MAX_GRADLE_CONFIGURATION_LENGTH = 256;

const gradleParser = {
  name: "gradleParser",
  ecosystem: "gradle",

  async canResolve(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    for (const buildFile of BUILD_FILES) {
      if (await pathExists(path.join(rootPath, buildFile), workspaceFolder)) {
        return true;
      }
    }
    return false;
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    for (const buildFile of BUILD_FILES) {
      const manifestPath = path.join(rootPath, buildFile);
      if (!(await pathExists(manifestPath, workspaceFolder))) {
        continue;
      }
      const lockfilePath = await pathExists(path.join(rootPath, "gradle.lockfile"), workspaceFolder)
        ? path.join(rootPath, "gradle.lockfile")
        : null;
      return [{
        resolverName: this.name,
        ecosystem: this.ecosystem,
        lockfilePath,
        manifestPath,
        sourceFile: buildFile,
      }];
    }
    return [];
  },

  async resolve({ lockfilePath, manifestPath, workspaceFolder, options = {} }) {
    const cancellationToken = options.cancellationToken;
    throwIfTraversalCancelled(cancellationToken);
    const manifestContent = await readUtf8(manifestPath, workspaceFolder, options);
    const directDependencies = parseGradleManifest(manifestContent);
    const sourceFile = getSourceFileName(manifestPath);

    if (!lockfilePath) {
      return buildGradleTree(sourceFile, directDependencies.map((dependency) => {
        throwIfTraversalCancelled(cancellationToken);
        return createGradleDependency({
          name: dependency.name,
          version: dependency.version,
          ecosystem: "gradle",
          isDirect: true,
          parent: null,
          parentChain: [],
          transitives: [],
          sourceFile,
          isDevelopmentDependency: dependency.isDevelopmentDependency,
        }, dependency, false);
      }));
    }

    const lockRecords = parseGradleLockfile(
      await readUtf8(lockfilePath, workspaceFolder, options),
      cancellationToken
    );
    const dependencies = [];
    const representedLockRecords = new Set();

    for (const directDependency of directDependencies) {
      throwIfTraversalCancelled(cancellationToken);
      const lockRecord = selectGradleLockRecord(lockRecords, directDependency);
      const hasResolutionEvidence = Boolean(lockRecord);
      const resolvedVersion = lockRecord ? lockRecord.version : "";
      if (lockRecord) {
        representedLockRecords.add(gradleLockRecordKey(lockRecord));
      }
      dependencies.push(createGradleDependency({
        name: directDependency.name,
        version: resolvedVersion,
        ecosystem: "gradle",
        isDirect: true,
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: directDependency.isDevelopmentDependency,
      }, directDependency, hasResolutionEvidence, lockRecord && lockRecord.configurations));
    }

    for (const record of lockRecords) {
      throwIfTraversalCancelled(cancellationToken);
      if (representedLockRecords.has(gradleLockRecordKey(record))) {
        continue;
      }
      dependencies.push(createGradleDependency({
        name: record.name,
        version: record.version,
        ecosystem: "gradle",
        isDirect: directDependencies.some((dependency) => dependency.name === record.name),
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: isTestOnlyGradleConfigurations(record.configurations),
      }, null, true, record.configurations));
    }

    return buildGradleTree(sourceFile, dependencies);
  },
};

function parseGradleLockfile(content, cancellationToken) {
  const records = new Map();

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    throwIfTraversalCancelled(cancellationToken);
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }
    const separatorIndex = line.indexOf("=");
    const entry = (separatorIndex === -1 ? line : line.slice(0, separatorIndex)).trim();
    const parts = entry.split(":");
    if (parts.length < 3) {
      continue;
    }
    const name = `${parts[0]}:${parts[1]}`;
    const version = parts.slice(2).join(":").trim();
    if (!version) {
      continue;
    }
    const key = JSON.stringify([name, version]);
    if (!records.has(key)) {
      records.set(key, { name, version, configurations: [] });
    }
    if (separatorIndex !== -1) {
      const configurations = line.slice(separatorIndex + 1).split(",");
      for (const configuration of configurations) {
        const normalized = configuration.trim();
        const record = records.get(key);
        if (
          normalized
          && normalized.length <= MAX_GRADLE_CONFIGURATION_LENGTH
          && record.configurations.length < MAX_GRADLE_CONFIGURATIONS
          && !record.configurations.includes(normalized)
        ) {
          record.configurations.push(normalized);
        }
      }
    }
  }

  return [...records.values()];
}

function parseGradleManifest(content) {
  const dependencies = parseBuildGradleManifest(content);
  const declarations = new Map();

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const line = rawLine.replace(/\/\/.*$/, "").trim();
    const match = line.match(/^([A-Za-z][A-Za-z0-9_-]*)\s*\(?\s*["']([^"']+)["']/);
    if (!match) {
      continue;
    }
    const coordinates = match[2].split(":");
    if (coordinates.length < 3 || !coordinates[0] || !coordinates[1]) {
      continue;
    }
    const name = `${coordinates[0]}:${coordinates[1]}`;
    const isDevelopmentDependency = match[1].toLowerCase().includes("test");
    const key = gradleManifestDependencyKey(name, isDevelopmentDependency);
    if (!declarations.has(key)) {
      declarations.set(key, []);
    }
    const declaredConstraint = coordinates.slice(2).join(":").trim() || null;
    declarations.get(key).push({
      declaredConstraint,
      versionState: classifyGradleDeclaredConstraint(declaredConstraint),
      configuration: match[1],
    });
  }

  return dependencies.map((dependency) => {
    const key = gradleManifestDependencyKey(dependency.name, dependency.isDevelopmentDependency);
    const candidates = declarations.get(key) || [];
    const matchIndex = candidates.findIndex((candidate) => (
      candidate.declaredConstraint === dependency.version
    ));
    const declaration = candidates[matchIndex === -1 ? 0 : matchIndex];
    const matchingDeclarations = declaration
      ? candidates.filter((candidate) => candidate.declaredConstraint === declaration.declaredConstraint)
      : [];
    if (declaration) {
      declarations.set(key, candidates.filter((candidate) => !matchingDeclarations.includes(candidate)));
    }
    return {
      ...dependency,
      declaredConstraint: declaration && declaration.declaredConstraint || null,
      versionState: declaration && declaration.versionState || "unresolved",
      gradleConfigurations: uniqueGradleConfigurations(
        matchingDeclarations.map((candidate) => candidate.configuration)
      ),
    };
  });
}

function classifyGradleDeclaredConstraint(declaredConstraint) {
  const value = String(declaredConstraint || "").trim();
  if (!value) {
    return "unresolved";
  }
  if (value.includes("$") || value.includes("{")) {
    return "incomplete";
  }
  if (
    value.includes("+")
    || /[\[\](),]/.test(value)
    || /^(?:latest|release|integration)(?:[.-]|$)/i.test(value)
  ) {
    return "range";
  }
  return "exact-declaration";
}

function createGradleDependency(values, declaration, hasResolutionEvidence, resolvedConfigurations = null) {
  const configurations = uniqueGradleConfigurations(
    resolvedConfigurations || declaration && declaration.gradleConfigurations || []
  );
  return {
    ...createDependency(values),
    declaredConstraint: declaration && declaration.declaredConstraint || null,
    versionState: hasResolutionEvidence
      ? "resolved"
      : declaration && declaration.versionState || "unresolved",
    hasResolutionEvidence: Boolean(hasResolutionEvidence),
    gradleConfigurations: configurations,
    qualifiers: { configurations },
    packageSource: { kind: "registry" },
  };
}

function selectGradleLockRecord(records, dependency) {
  const candidates = records.filter((record) => record.name === dependency.name);
  if (candidates.length === 1) {
    return candidates[0];
  }
  const declaredConstraint = String(dependency.declaredConstraint || "").trim();
  return candidates.find((record) => record.version === declaredConstraint) || null;
}

function gradleLockRecordKey(record) {
  return JSON.stringify([record.name, record.version]);
}

function uniqueGradleConfigurations(configurations) {
  return [...new Set((Array.isArray(configurations) ? configurations : [])
    .map((configuration) => String(configuration || "").trim())
    .filter((configuration) => (
      configuration
      && configuration.length <= MAX_GRADLE_CONFIGURATION_LENGTH
    )))].slice(0, MAX_GRADLE_CONFIGURATIONS);
}

function isTestOnlyGradleConfigurations(configurations) {
  const normalized = uniqueGradleConfigurations(configurations);
  return normalized.length > 0 && normalized.every((configuration) => /test/i.test(configuration));
}

function buildGradleTree(sourceFile, dependencies) {
  const seen = new Set();
  const unique = [];
  for (const dependency of dependencies) {
    const key = JSON.stringify([
      dependency.name,
      dependency.version,
      dependency.gradleConfigurations,
      dependency.isDirect,
      dependency.isDevelopmentDependency,
      dependency.declaredConstraint || "",
    ]);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(dependency);
  }
  return { ecosystem: "gradle", sourceFile, dependencies: unique, warnings: [] };
}

function gradleManifestDependencyKey(name, isDevelopmentDependency) {
  return `${String(name || "").trim()}:${isDevelopmentDependency ? "development" : "runtime"}`;
}

module.exports = gradleParser;

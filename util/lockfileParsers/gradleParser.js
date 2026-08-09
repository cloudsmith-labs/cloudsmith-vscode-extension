// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  buildTree,
  createDependency,
  deduplicateDeps,
  getSourceFileName,
  getWorkspacePath,
  pathExists,
  readUtf8,
} = require("./shared");
const { parseBuildGradleManifest } = require("./manifestHelpers");

const BUILD_FILES = ["build.gradle", "build.gradle.kts"];

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

  async resolve({ lockfilePath, manifestPath, workspaceFolder }) {
    const manifestContent = await readUtf8(manifestPath, workspaceFolder);
    const directDependencies = parseGradleManifest(manifestContent);
    const sourceFile = getSourceFileName(manifestPath);

    if (!lockfilePath) {
      return buildTree("gradle", sourceFile, directDependencies.map((dependency) => (
        createGradleDependency({
          name: dependency.name,
          version: dependency.version,
          ecosystem: "gradle",
          isDirect: true,
          parent: null,
          parentChain: [],
          transitives: [],
          sourceFile,
          isDevelopmentDependency: dependency.isDevelopmentDependency,
        }, dependency, false)
      )));
    }

    const lockVersions = parseGradleLockfile(await readUtf8(lockfilePath, workspaceFolder));
    const dependencies = [];

    for (const directDependency of directDependencies) {
      const hasResolutionEvidence = lockVersions.has(directDependency.name);
      const resolvedVersion = hasResolutionEvidence ? lockVersions.get(directDependency.name) : "";
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
      }, directDependency, hasResolutionEvidence));
    }

    for (const [name, version] of lockVersions.entries()) {
      dependencies.push(createGradleDependency({
        name,
        version,
        ecosystem: "gradle",
        isDirect: directDependencies.some((dependency) => dependency.name === name),
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        isDevelopmentDependency: false,
      }, null, true));
    }

    return buildTree("gradle", sourceFile, deduplicateDeps(dependencies));
  },
};

function parseGradleLockfile(content) {
  const versions = new Map();

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }
    const entry = line.split("=", 1)[0].trim();
    const parts = entry.split(":");
    if (parts.length < 3) {
      continue;
    }
    versions.set(`${parts[0]}:${parts[1]}`, parts[2]);
  }

  return versions;
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
    });
  }

  return dependencies.map((dependency) => {
    const key = gradleManifestDependencyKey(dependency.name, dependency.isDevelopmentDependency);
    const declaration = declarations.get(key) && declarations.get(key).shift();
    return {
      ...dependency,
      declaredConstraint: declaration && declaration.declaredConstraint || null,
      versionState: declaration && declaration.versionState || "unresolved",
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

function createGradleDependency(values, declaration, hasResolutionEvidence) {
  return {
    ...createDependency(values),
    declaredConstraint: declaration && declaration.declaredConstraint || null,
    versionState: hasResolutionEvidence
      ? "resolved"
      : declaration && declaration.versionState || "unresolved",
    hasResolutionEvidence: Boolean(hasResolutionEvidence),
  };
}

function gradleManifestDependencyKey(name, isDevelopmentDependency) {
  return `${String(name || "").trim()}:${isDevelopmentDependency ? "development" : "runtime"}`;
}

module.exports = gradleParser;

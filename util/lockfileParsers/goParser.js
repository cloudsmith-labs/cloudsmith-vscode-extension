// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  buildTree,
  createDependency,
  getSourceFileName,
  getWorkspacePath,
  pathExists,
  readUtf8,
  throwIfTraversalCancelled,
} = require("./shared");

const goParser = {
  name: "goParser",
  ecosystem: "go",

  async canResolve(workspaceFolder) {
    return pathExists(path.join(getWorkspacePath(workspaceFolder), "go.mod"), workspaceFolder);
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    const manifestPath = path.join(rootPath, "go.mod");
    if (!(await pathExists(manifestPath, workspaceFolder))) {
      return [];
    }
    return [{
      resolverName: this.name,
      ecosystem: this.ecosystem,
      lockfilePath: manifestPath,
      manifestPath,
      sourceFile: "go.mod",
    }];
  },

  async resolve({ manifestPath, workspaceFolder, options = {} }) {
    const cancellationToken = options.cancellationToken;
    throwIfTraversalCancelled(cancellationToken);
    const sourceFile = getSourceFileName(manifestPath);
    const content = String(await readUtf8(manifestPath, workspaceFolder, options));
    const replacements = parseGoReplacements(content);
    const dependencies = [];
    let inRequireBlock = false;

    for (const rawLine of content.split(/\r?\n/)) {
      throwIfTraversalCancelled(cancellationToken);
      const line = rawLine.trim();
      if (!line || line.startsWith("//")) {
        continue;
      }
      if (line === "require (") {
        inRequireBlock = true;
        continue;
      }
      if (line === ")" && inRequireBlock) {
        inRequireBlock = false;
        continue;
      }

      const lineToParse = line.startsWith("require ") ? line.slice("require ".length).trim() : line;
      if (!inRequireBlock && !line.startsWith("require ")) {
        continue;
      }

      const cleaned = lineToParse.split("//")[0].trim();
      const parts = cleaned.split(/\s+/);
      if (parts.length < 2) {
        continue;
      }

      const requiredModule = parts[0];
      const requiredVersion = parts[1];
      const replacement = selectGoReplacement(replacements, requiredModule, requiredVersion);
      dependencies.push(createGoDependency({
        requiredModule,
        requiredVersion,
        replacement,
        ecosystem: "go",
        isDirect: !rawLine.includes("// indirect"),
        parent: null,
        parentChain: [],
        transitives: [],
        sourceFile,
        // Go's // indirect marker describes graph reachability, not a
        // development-only dependency class.
        isDevelopmentDependency: false,
      }));
    }

    return buildTree("go", sourceFile, dependencies);
  },
};

function parseGoReplacements(content) {
  const replacements = new Map();
  let inReplaceBlock = false;

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const line = rawLine.split("//")[0].trim();
    if (!line) {
      continue;
    }
    if (line === "replace (") {
      inReplaceBlock = true;
      continue;
    }
    if (line === ")" && inReplaceBlock) {
      inReplaceBlock = false;
      continue;
    }

    const declaration = inReplaceBlock
      ? line
      : line.startsWith("replace ")
        ? line.slice("replace ".length).trim()
        : "";
    if (!declaration) {
      continue;
    }

    const replacement = parseGoReplacementDeclaration(declaration);
    if (!replacement) {
      continue;
    }
    const key = goReplacementKey(
      replacement.module,
      replacement.invalid || (replacement.version && !isConcreteGoVersion(replacement.version))
        ? ""
        : replacement.version
    );
    if (!replacements.has(key)) {
      replacements.set(key, []);
    }
    replacements.get(key).push(replacement);
  }

  return replacements;
}

function parseGoReplacementDeclaration(declaration) {
  const value = String(declaration || "").trim();
  const sides = value.split(/\s*=>\s*/);
  const source = sides[0].trim().split(/\s+/).filter(Boolean);
  if (source.length < 1) {
    return null;
  }
  const target = sides.length === 2
    ? sides[1].trim().split(/\s+/).filter(Boolean)
    : [];
  const invalid = sides.length !== 2
    || source.length > 2
    || target.length < 1
    || target.length > 2;

  return {
    module: source[0],
    version: source[1] || "",
    target: target[0] || "",
    targetVersion: target[1] || "",
    declaration: value,
    invalid,
  };
}

function selectGoReplacement(replacements, moduleName, version) {
  for (const key of [
    goReplacementKey(moduleName, version),
    goReplacementKey(moduleName, ""),
  ]) {
    const candidates = replacements.get(key) || [];
    if (candidates.length === 1) {
      return candidates[0];
    }
    if (candidates.length > 1) {
      return {
        ambiguous: true,
        declaration: candidates.map((candidate) => candidate.declaration).join(" | "),
      };
    }
  }
  return null;
}

function createGoDependency(values) {
  const replacement = values.replacement;
  const supportedReplacement = getSupportedGoModuleReplacement(replacement);
  const hasUnresolvedReplacement = Boolean(replacement) && !supportedReplacement;
  const hasConcreteRequirement = isConcreteGoVersion(values.requiredVersion);
  const name = supportedReplacement ? supportedReplacement.name : values.requiredModule;
  const version = supportedReplacement
    ? supportedReplacement.version
    : hasUnresolvedReplacement || !hasConcreteRequirement
      ? ""
      : normalizeGoVersion(values.requiredVersion);
  const declaredConstraint = supportedReplacement
    ? replacement.targetVersion
    : hasUnresolvedReplacement
      ? getUnresolvedGoReplacementConstraint(replacement)
      : values.requiredVersion;
  const packageSource = goPackageSource(replacement, supportedReplacement);

  return {
    ...createDependency({
      name,
      version,
      ecosystem: values.ecosystem,
      isDirect: values.isDirect,
      parent: values.parent,
      parentChain: values.parentChain,
      transitives: values.transitives,
      sourceFile: values.sourceFile,
      isDevelopmentDependency: values.isDevelopmentDependency,
    }),
    declarationName: values.requiredModule,
    declaredConstraint,
    versionState: version ? "exact-declaration" : "incomplete",
    hasResolutionEvidence: false,
    requiredVersion: values.requiredVersion,
    replacementFor: replacement ? values.requiredModule : null,
    replacementTarget: replacement ? replacement.target || null : null,
    packageSource,
  };
}

function getSupportedGoModuleReplacement(replacement) {
  if (
    !replacement
    || replacement.ambiguous
    || replacement.invalid
    || isLocalGoReplacementTarget(replacement.target)
    || !isSupportedGoModulePath(replacement.target)
    || !isConcreteGoVersion(replacement.targetVersion)
  ) {
    return null;
  }

  return {
    name: replacement.target,
    version: normalizeGoVersion(replacement.targetVersion),
  };
}

function getUnresolvedGoReplacementConstraint(replacement) {
  if (!replacement || replacement.ambiguous) {
    return `replace:${String(replacement && replacement.declaration || "ambiguous").trim()}`;
  }
  if (isLocalGoReplacementTarget(replacement.target)) {
    return `path:${replacement.target}`;
  }
  return `replace:${replacement.target}${replacement.targetVersion ? `@${replacement.targetVersion}` : ""}`;
}

function isLocalGoReplacementTarget(target) {
  const value = String(target || "").trim();
  return value === "."
    || value === ".."
    || value.startsWith("./")
    || value.startsWith("../")
    || path.isAbsolute(value)
    || /^[A-Za-z]:[\\/]/.test(value);
}

function isSupportedGoModulePath(moduleName) {
  const value = String(moduleName || "").trim();
  return Boolean(value)
    && !value.startsWith(".")
    && !value.includes("://")
    && !value.includes("\\")
    && !value.includes("@");
}

function isConcreteGoVersion(version) {
  return /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(
    String(version || "").trim()
  );
}

function normalizeGoVersion(version) {
  const value = String(version || "").trim().replace(/^v+/, "");
  return value ? `v${value}` : "";
}

function goPackageSource(replacement, supportedReplacement) {
  if (!replacement || supportedReplacement) {
    return { kind: "registry" };
  }
  if (isLocalGoReplacementTarget(replacement.target)) {
    return { kind: "path", location: replacement.target };
  }
  return { kind: "unknown" };
}

function goReplacementKey(moduleName, version) {
  return `${String(moduleName || "").trim()}@${String(version || "").trim()}`;
}

module.exports = goParser;

// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  createDependency,
  getSourceFileName,
  getWorkspacePath,
  readJson,
  pathExists,
  readUtf8,
  throwIfTraversalCancelled,
} = require("./shared");
const { normalizeSwiftIdentity, parsePackageSwiftManifest } = require("./manifestHelpers");

const swiftParser = {
  name: "swiftParser",
  ecosystem: "swift",

  async canResolve(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    return (await pathExists(path.join(rootPath, "Package.resolved"), workspaceFolder))
      || (await pathExists(path.join(rootPath, "Package.swift"), workspaceFolder));
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    const lockfilePath = await pathExists(path.join(rootPath, "Package.resolved"), workspaceFolder)
      ? path.join(rootPath, "Package.resolved")
      : null;
    const manifestPath = await pathExists(path.join(rootPath, "Package.swift"), workspaceFolder)
      ? path.join(rootPath, "Package.swift")
      : null;
    if (!lockfilePath && !manifestPath) {
      return [];
    }
    return [{
      resolverName: this.name,
      ecosystem: this.ecosystem,
      lockfilePath,
      manifestPath,
      sourceFile: getSourceFileName(lockfilePath || manifestPath),
    }];
  },

  async resolve({ lockfilePath, manifestPath, workspaceFolder, options = {} }) {
    const cancellationToken = options.cancellationToken;
    throwIfTraversalCancelled(cancellationToken);
    const sourceFile = getSourceFileName(lockfilePath || manifestPath);
    const manifestDependencies = manifestPath && await pathExists(manifestPath, workspaceFolder)
      ? parsePackageSwiftManifest(await readUtf8(manifestPath, workspaceFolder, options))
      : [];
    if (!lockfilePath) {
      return buildSwiftTree(sourceFile, manifestDependencies.map((dependency) => {
        throwIfTraversalCancelled(cancellationToken);
        return createSwiftDependency({
          name: dependency.name,
          version: dependency.version,
          isDirect: true,
          sourceFile,
          packageSource: dependency.packageSource,
          qualifiers: dependency.qualifiers,
        });
      }));
    }

    const root = await readJson(lockfilePath, workspaceFolder, options);
    const pins = Array.isArray(root.pins)
      ? root.pins
      : (root.object && Array.isArray(root.object.pins) ? root.object.pins : []);
    if (pins.length === 0) {
      throw new Error("Malformed Package.resolved: missing pins array");
    }

    return buildSwiftTree(sourceFile, pins.map((pin) => {
      throwIfTraversalCancelled(cancellationToken);
      const state = pin.state || {};
      const packageSource = swiftPinPackageSource(pin, state);
      const identity = swiftPinIdentity(pin, packageSource);
      const scope = packageSource.kind === "registry" ? swiftRegistryScope(identity) : "";
      return createSwiftDependency({
        name: identity,
        // A branch or commit revision is concrete source-control evidence,
        // but it is not a package version that can be matched as such.
        version: state.version || "",
        isDirect: manifestDependencies.some((dependency) => (
          swiftManifestMatchesPin(dependency, identity, packageSource)
        )),
        sourceFile,
        packageSource,
        qualifiers: scope ? { scope } : {},
        sourceRevision: state.revision || null,
        sourceBranch: state.branch || null,
      });
    }));
  },
};

function createSwiftDependency(values) {
  const packageSource = values.packageSource || { kind: "unknown" };
  const qualifiers = values.qualifiers && typeof values.qualifiers === "object"
    ? { ...values.qualifiers }
    : {};
  return {
    ...createDependency({
      name: values.name,
      version: values.version,
      ecosystem: "swift",
      isDirect: values.isDirect,
      parent: null,
      parentChain: [],
      transitives: [],
      sourceFile: values.sourceFile,
      isDevelopmentDependency: false,
    }),
    packageSource,
    qualifiers,
    swiftScope: qualifiers.scope || null,
    swiftLocation: packageSource.location || null,
    sourceRevision: values.sourceRevision || packageSource.revision || null,
    sourceBranch: values.sourceBranch || packageSource.branch || null,
  };
}

function swiftPinPackageSource(pin, state) {
  const kind = String(pin && pin.kind || "").trim().toLowerCase();
  const location = sanitizeSwiftLocation(
    pin && (pin.location || pin.repositoryURL || pin.repositoryUrl) || ""
  );
  const branch = boundedSwiftSourceValue(state && state.branch);
  const revision = boundedSwiftSourceValue(state && state.revision);
  if (kind === "registry") {
    return { kind: "registry", ...(location ? { location } : {}) };
  }
  if (kind.includes("local") || looksLikeSwiftLocalPath(location)) {
    return { kind: "path", ...(location ? { location } : {}) };
  }
  if (kind.includes("sourcecontrol") || location) {
    return {
      kind: "scm",
      ...(location ? { location } : {}),
      ...(branch ? { branch } : {}),
      ...(revision ? { revision } : {}),
    };
  }
  return { kind: "unknown" };
}

function swiftPinIdentity(pin, packageSource) {
  const rawIdentity = String(
    pin && (pin.identity || pin.package) || packageSource.location || ""
  ).trim();
  return packageSource.kind === "registry"
    ? rawIdentity.toLowerCase()
    : normalizeSwiftIdentity(packageSource.location || rawIdentity);
}

function swiftRegistryScope(identity) {
  const separator = String(identity || "").indexOf(".");
  return separator > 0 ? identity.slice(0, separator) : "";
}

function swiftManifestMatchesPin(dependency, identity, packageSource) {
  if (!dependency || !dependency.packageSource) {
    return false;
  }
  if (dependency.packageSource.kind !== packageSource.kind) {
    return false;
  }
  if (packageSource.kind === "registry") {
    return String(dependency.name || "").toLowerCase() === identity;
  }
  const manifestLocation = normalizeSwiftLocationForComparison(dependency.packageSource.location);
  const pinLocation = normalizeSwiftLocationForComparison(packageSource.location);
  return Boolean(manifestLocation && pinLocation && manifestLocation === pinLocation);
}

function sanitizeSwiftLocation(value) {
  const location = String(value || "").trim();
  if (!location || location.length > 4096 || /[\0\r\n]/.test(location)) {
    return "";
  }
  if (!/^https?:\/\//i.test(location)) {
    return location;
  }
  try {
    const parsed = new URL(location);
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    return parsed.toString().replace(/\/$/, "");
  } catch {
    return "";
  }
}

function normalizeSwiftLocationForComparison(value) {
  return sanitizeSwiftLocation(value).replace(/\/$/, "");
}

function boundedSwiftSourceValue(value) {
  const normalized = String(value || "").trim();
  return normalized && normalized.length <= 512 && !/[\0\r\n]/.test(normalized)
    ? normalized
    : "";
}

function looksLikeSwiftLocalPath(location) {
  return location === "."
    || location === ".."
    || location.startsWith("./")
    || location.startsWith("../")
    || path.isAbsolute(location);
}

function buildSwiftTree(sourceFile, dependencies) {
  const unique = [];
  const seen = new Set();
  for (const dependency of dependencies) {
    if (!dependency.name) {
      continue;
    }
    const key = JSON.stringify([
      dependency.name,
      dependency.version,
      dependency.packageSource.kind,
      dependency.packageSource.location || "",
      dependency.sourceBranch || "",
      dependency.sourceRevision || "",
    ]);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(dependency);
  }
  return { ecosystem: "swift", sourceFile, dependencies: unique, warnings: [] };
}

module.exports = swiftParser;

// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const { DEPENDENCY_VERSION_STATES } = require("../dependencyRecord");
const { isDockerDigest } = require("../registryEndpoints");
const {
  buildTree,
  countIndent,
  createDependency,
  getSourceFileName,
  getWorkspacePath,
  pathExists,
  readBoundedDirectoryEntries,
  readUtf8,
  resolveWorkspaceFilePath,
  stripYamlComment,
  throwIfTraversalCancelled,
} = require("./shared");

const dockerParser = {
  name: "dockerParser",
  ecosystem: "docker",

  async canResolve(workspaceFolder, options = {}) {
    const matches = await this.detect(workspaceFolder, options);
    return matches.length > 0;
  },

  async detect(workspaceFolder, options = {}) {
    throwIfTraversalCancelled(options.cancellationToken);
    const rootPath = getWorkspacePath(workspaceFolder);
    const safeRootPath = await resolveWorkspaceFilePath(rootPath, workspaceFolder);
    if (!safeRootPath) {
      return [];
    }
    const entries = [];
    const directory = await readBoundedDirectoryEntries(safeRootPath, undefined, {
      ...options,
      workspaceFolder,
    });
    const allFiles = directory.entries
      .filter((entry) => entry.isFile())
      .map((entry) => entry.name);

    for (const fileName of allFiles.sort()) {
      throwIfTraversalCancelled(options.cancellationToken);
      const isDockerfile = fileName === "Dockerfile" || fileName.startsWith("Dockerfile.");
      const isComposeFile = [
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
      ].includes(fileName);
      if (!isDockerfile && !isComposeFile) {
        continue;
      }
      entries.push({
        resolverName: this.name,
        ecosystem: this.ecosystem,
        lockfilePath: path.join(safeRootPath, fileName),
        manifestPath: null,
        sourceFile: fileName,
      });
    }

    return entries;
  },

  async resolve({ lockfilePath, workspaceFolder, options = {} }) {
    const cancellationToken = options.cancellationToken;
    throwIfTraversalCancelled(cancellationToken);
    const sourceFile = getSourceFileName(lockfilePath);
    const content = await readUtf8(lockfilePath, workspaceFolder, options);
    if (isComposeFileName(sourceFile)) {
      const projectEnvironment = await readComposeProjectEnvironment(
        lockfilePath,
        workspaceFolder,
        options
      );
      const parsed = parseCompose(content, sourceFile, projectEnvironment, cancellationToken);
      return buildTree("docker", sourceFile, parsed.dependencies, parsed.warnings);
    }
    const parsed = parseDockerfile(content, sourceFile, cancellationToken);
    return buildTree("docker", sourceFile, parsed.dependencies, parsed.warnings);
  },
};

function parseDockerfile(content, sourceFile, cancellationToken) {
  const dependencies = [];
  const warnings = [];
  const addWarningOnce = createWarningCollector(warnings);
  const stageAliases = new Set();
  const argDefaults = new Map();
  let stageIndex = 0;

  for (const instruction of toLogicalDockerLines(content)) {
    throwIfTraversalCancelled(cancellationToken);
    const cleaned = stripDockerComment(instruction).trim();
    if (!cleaned) {
      continue;
    }

    if (/^ARG\s+/i.test(cleaned)) {
      const definition = cleaned.replace(/^ARG\s+/i, "");
      const [name, value] = definition.split("=", 2);
      if (name && value) {
        argDefaults.set(name.trim(), resolveDockerArgs(value.trim(), argDefaults));
      }
      continue;
    }

    if (!/^FROM\s+/i.test(cleaned)) {
      continue;
    }

    const parsed = parseFromInstruction(cleaned, argDefaults, stageAliases);
    if (!parsed) {
      continue;
    }
    if (parsed.alias) {
      stageAliases.add(parsed.alias.toLowerCase());
    }
    if (!parsed.isDependency) {
      stageIndex += 1;
      continue;
    }

    if (parsed.platformUnresolved) {
      addWarningOnce(
        "A Dockerfile target platform could not be resolved, so dependency results are partial."
      );
    }

    dependencies.push(withDockerResolutionEvidence(createDependency({
      name: parsed.name,
      version: parsed.version,
      ecosystem: "docker",
      isDirect: true,
      parent: null,
      parentChain: [],
      transitives: [],
      sourceFile,
      isDevelopmentDependency: false,
      tag: parsed.tag,
      digest: parsed.digest,
      stage: parsed.alias || `stage-${stageIndex + 1}`,
      platform: parsed.platform || null,
      packageSource: { kind: "registry" },
    }), parsed));
    stageIndex += 1;
  }

  return { dependencies, warnings };
}

function parseCompose(content, sourceFile, projectEnvironment = new Map(), cancellationToken) {
  const dependencies = [];
  const warnings = [];
  const addWarningOnce = createWarningCollector(warnings);
  let servicesIndent = null;
  let serviceIndent = null;
  let currentService = null;

  const flushCurrentService = () => {
    if (!currentService) {
      return;
    }
    const pullPolicy = interpolateComposeValue(currentService.pullPolicy, projectEnvironment);
    if (pullPolicy.unresolved) {
      addWarningOnce("A Compose pull policy could not be resolved, so dependency results are partial.");
      currentService = null;
      return;
    }
    const normalizedPullPolicy = pullPolicy.value.toLowerCase();
    if (normalizedPullPolicy === "build" && !currentService.hasBuild) {
      addWarningOnce("A Compose service requests a local build but has no usable build definition.");
    }
    const shouldIncludeImage = currentService.image && normalizedPullPolicy !== "build";
    if (shouldIncludeImage) {
      const interpolated = interpolateComposeValue(currentService.image, projectEnvironment);
      const interpolatedPlatform = interpolateComposeValue(
        currentService.platform,
        projectEnvironment
      );
      if (interpolated.unresolved) {
        addWarningOnce("A Compose image reference could not be resolved, so dependency results are partial.");
        currentService = null;
        return;
      }
      const parsed = parseDockerImageReference(interpolated.value);
      if (!parsed) {
        if (interpolated.value) {
          addWarningOnce("A Compose image reference was invalid and could not be checked.");
        }
        currentService = null;
        return;
      }
      let platform = "";
      let platformUnresolved = false;
      if (interpolatedPlatform.unresolved) {
        platformUnresolved = true;
        addWarningOnce("A Compose image platform could not be resolved, so dependency results are partial.");
      } else {
        platform = normalizeDockerPlatform(interpolatedPlatform.value);
      }
      if (!platformUnresolved && interpolatedPlatform.value && !platform) {
        platformUnresolved = true;
        addWarningOnce("A Compose image platform was invalid and could not be checked.");
      }
      if (parsed.name.toLowerCase() !== "scratch") {
        dependencies.push(withDockerResolutionEvidence(createDependency({
          name: parsed.name,
          version: parsed.version,
          ecosystem: "docker",
          isDirect: true,
          parent: null,
          parentChain: [],
          transitives: [],
          sourceFile,
          isDevelopmentDependency: false,
          service: currentService.name,
          pullPolicy: normalizedPullPolicy || "default",
          tag: parsed.tag,
          digest: parsed.digest,
          platform: platform || null,
          packageSource: { kind: "registry" },
        }), { ...parsed, platformUnresolved }));
      }
    }
    currentService = null;
  };

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    throwIfTraversalCancelled(cancellationToken);
    const cleaned = stripYamlComment(rawLine).trim();
    if (!cleaned) {
      continue;
    }

    const indent = countIndent(rawLine);
    if (cleaned === "services:") {
      flushCurrentService();
      servicesIndent = indent;
      serviceIndent = null;
      continue;
    }
    if (servicesIndent != null && indent <= servicesIndent && cleaned.endsWith(":")) {
      flushCurrentService();
      servicesIndent = null;
      serviceIndent = null;
    }
    if (servicesIndent == null || indent <= servicesIndent) {
      continue;
    }

    if (cleaned.endsWith(":") && (serviceIndent == null || indent === serviceIndent)) {
      flushCurrentService();
      serviceIndent = indent;
      currentService = {
        name: unquote(cleaned.slice(0, -1)),
        indent,
        hasBuild: false,
        image: "",
        platform: "",
        pullPolicy: "",
      };
      continue;
    }

    if (!currentService || indent <= currentService.indent || cleaned.startsWith("- ")) {
      continue;
    }

    if (cleaned.startsWith("build:")) {
      currentService.hasBuild = true;
      continue;
    }
    if (cleaned.startsWith("image:")) {
      currentService.image = unquote(cleaned.slice("image:".length).trim());
      continue;
    }
    if (cleaned.startsWith("platform:")) {
      currentService.platform = unquote(cleaned.slice("platform:".length).trim());
      continue;
    }
    if (cleaned.startsWith("pull_policy:")) {
      currentService.pullPolicy = unquote(cleaned.slice("pull_policy:".length).trim());
    }
  }

  flushCurrentService();
  return {
    dependencies,
    warnings,
  };
}

function createWarningCollector(warnings) {
  const emitted = new Set();
  return (warning) => {
    if (emitted.has(warning)) return;
    emitted.add(warning);
    warnings.push(warning);
  };
}

function toLogicalDockerLines(content) {
  const lines = [];
  let current = "";
  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const trimmed = rawLine.trimEnd();
    if (!trimmed) {
      if (current) {
        lines.push(current);
        current = "";
      }
      continue;
    }

    const continues = trimmed.endsWith("\\");
    const segment = continues ? trimmed.slice(0, -1).trimEnd() : trimmed;
    current += current ? ` ${segment}` : segment;
    if (!continues) {
      lines.push(current);
      current = "";
    }
  }
  if (current) {
    lines.push(current);
  }
  return lines;
}

function stripDockerComment(line) {
  let inSingleQuote = false;
  let inDoubleQuote = false;

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    const previous = index > 0 ? line[index - 1] : "";
    if (char === "'" && !inDoubleQuote && previous !== "\\") {
      inSingleQuote = !inSingleQuote;
      continue;
    }
    if (char === "\"" && !inSingleQuote && previous !== "\\") {
      inDoubleQuote = !inDoubleQuote;
      continue;
    }
    if (char === "#" && !inSingleQuote && !inDoubleQuote) {
      return line.slice(0, index);
    }
  }
  return line;
}

function resolveDockerArgs(value, args) {
  return String(value || "")
    .replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-+?])([^}]*))?}/g, (_match, name, operator, fallback) => {
      if (args.has(name)) {
        return args.get(name);
      }
      return operator === "-" || operator === ":-" ? fallback : _match;
    })
    .replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, (match, name) => (args.has(name) ? args.get(name) : match));
}

async function readComposeProjectEnvironment(lockfilePath, workspaceFolder, options = {}) {
  const environment = new Map();
  const envPath = path.join(path.dirname(lockfilePath), ".env");
  if (await pathExists(envPath, workspaceFolder)) {
    const content = await readUtf8(envPath, workspaceFolder, options);
    for (const rawLine of String(content || "").split(/\r?\n/)) {
      throwIfTraversalCancelled(options.cancellationToken);
      const line = stripDockerComment(rawLine).trim();
      if (!line || line.startsWith("#")) {
        continue;
      }
      const separator = line.indexOf("=");
      if (separator <= 0) {
        continue;
      }
      const name = line.slice(0, separator).trim();
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
        continue;
      }
      const value = unquote(line.slice(separator + 1).trim());
      if (value.length <= 4096 && !/[\u0000-\u001f\u007f]/.test(value)) {
        environment.set(name, value);
      }
    }
  }
  // Compose gives the invoking process environment precedence over project
  // .env values. Copy only bounded, plain values; do not mutate process.env.
  for (const [name, value] of Object.entries(process.env || {})) {
    throwIfTraversalCancelled(options.cancellationToken);
    if (
      /^[A-Za-z_][A-Za-z0-9_]*$/.test(name)
      && typeof value === "string"
      && value.length <= 4096
      && !/[\u0000-\u001f\u007f]/.test(value)
    ) {
      environment.set(name, value);
    }
  }
  return environment;
}

function interpolateComposeValue(input, environment) {
  const escapedDollar = "\u0000CLOUDSMITH_DOLLAR\u0000";
  let unresolved = false;
  const value = String(input || "")
    .replace(/\$\$/g, escapedDollar)
    .replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-+?])([^}]*))?}/g, (_match, name, operator, fallback = "") => {
      const isSet = environment.has(name);
      const resolved = isSet ? String(environment.get(name) || "") : "";
      const hasValue = resolved !== "";
      if (!operator) {
        if (!isSet) unresolved = true;
        return isSet ? resolved : "";
      }
      if (operator === "-") return isSet ? resolved : fallback;
      if (operator === ":-") return hasValue ? resolved : fallback;
      if (operator === "+") return isSet ? fallback : "";
      if (operator === ":+") return hasValue ? fallback : "";
      if (operator === "?" || operator === ":?") {
        if (operator === "?" ? !isSet : !hasValue) unresolved = true;
        return operator === "?" ? (isSet ? resolved : "") : (hasValue ? resolved : "");
      }
      unresolved = true;
      return "";
    })
    .replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, (_match, name) => {
      if (!environment.has(name)) {
        unresolved = true;
        return "";
      }
      return String(environment.get(name) || "");
    })
    .replaceAll(escapedDollar, "$");
  return { value, unresolved };
}

function parseFromInstruction(line, argDefaults, stageAliases) {
  const parts = line.split(/\s+/).filter(Boolean);
  let index = 1;
  let platform = "";
  let platformUnresolved = false;
  while (parts[index] && parts[index].startsWith("--")) {
    if (parts[index].toLowerCase().startsWith("--platform=")) {
      const resolvedPlatform = resolveDockerArgs(
        unquote(parts[index].slice("--platform=".length)),
        argDefaults
      );
      platform = normalizeDockerPlatform(resolvedPlatform);
      platformUnresolved = !platform || resolvedPlatform.includes("$");
    }
    index += 1;
  }
  const imageToken = parts[index];
  if (!imageToken) {
    return null;
  }
  const alias = parts[index + 1] && /^AS$/i.test(parts[index + 1]) ? parts[index + 2] : "";
  const resolvedImage = resolveDockerArgs(unquote(imageToken), argDefaults).trim();
  if (!resolvedImage) {
    return null;
  }
  const stageReference = stageAliases.has(resolvedImage.toLowerCase());
  const parsed = parseDockerImageReference(resolvedImage);
  if (!parsed) {
    return null;
  }
  return {
    ...parsed,
    alias: alias ? unquote(alias) : "",
    platform,
    platformUnresolved,
    isDependency: !stageReference && parsed.name.toLowerCase() !== "scratch",
  };
}

function normalizeDockerPlatform(value) {
  const platform = String(value || "").trim().toLowerCase();
  if (!platform) return "";
  const parts = platform.split("/");
  return (
    (parts.length === 2 || parts.length === 3)
    && parts.every(part => part && /^[a-z0-9_.-]+$/.test(part))
  ) ? parts.join("/") : "";
}

function parseDockerImageReference(reference) {
  const raw = unquote(reference);
  if (!raw || raw.includes("$")) {
    return null;
  }
  const digestSeparator = raw.indexOf("@");
  const withoutDigest = digestSeparator >= 0 ? raw.slice(0, digestSeparator) : raw;
  const digest = digestSeparator >= 0 ? raw.slice(digestSeparator + 1) : "";
  if (digestSeparator >= 0 && !isDockerDigest(digest)) {
    return null;
  }
  const lastSlash = withoutDigest.lastIndexOf("/");
  const lastColon = withoutDigest.lastIndexOf(":");
  const hasTag = lastColon > lastSlash;
  const name = hasTag ? withoutDigest.slice(0, lastColon) : withoutDigest;
  const tag = hasTag ? withoutDigest.slice(lastColon + 1) : "";
  const version = tag || digest;
  if (!name || (hasTag && !tag)) {
    return null;
  }
  return {
    name,
    version,
    tag,
    digest,
    hasResolutionEvidence: Boolean(tag || digest),
  };
}

function withDockerResolutionEvidence(dependency, parsed) {
  const hasResolutionEvidence = Boolean(
    parsed && parsed.hasResolutionEvidence && !parsed.platformUnresolved
  );
  return {
    ...dependency,
    hasResolutionEvidence,
    resolvedVersion: hasResolutionEvidence ? parsed.version : null,
    declaredConstraint: parsed && (parsed.tag || parsed.digest) || null,
    ...(parsed?.platformUnresolved
      ? { versionState: DEPENDENCY_VERSION_STATES.INCOMPLETE }
      : {}),
  };
}

function unquote(value) {
  return String(value || "").trim().replace(/^["']|["']$/g, "");
}

function isComposeFileName(fileName) {
  return ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"].includes(fileName);
}

module.exports = dockerParser;

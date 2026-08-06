// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  buildTree,
  countIndent,
  createDependency,
  getSourceFileName,
  getWorkspacePath,
  readUtf8,
  resolveWorkspaceFilePath,
  stripYamlComment,
} = require("./shared");

const dockerParser = {
  name: "dockerParser",
  ecosystem: "docker",

  async canResolve(workspaceFolder) {
    const matches = await this.detect(workspaceFolder);
    return matches.length > 0;
  },

  async detect(workspaceFolder) {
    const rootPath = getWorkspacePath(workspaceFolder);
    const safeRootPath = await resolveWorkspaceFilePath(rootPath, workspaceFolder);
    if (!safeRootPath) {
      return [];
    }
    const entries = [];
    const allFiles = await require("fs").promises.readdir(safeRootPath);

    for (const fileName of allFiles.sort()) {
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

  async resolve({ lockfilePath, workspaceFolder }) {
    const sourceFile = getSourceFileName(lockfilePath);
    const content = await readUtf8(lockfilePath, workspaceFolder);
    const dependencies = isComposeFileName(sourceFile)
      ? parseCompose(content, sourceFile)
      : parseDockerfile(content, sourceFile);
    return buildTree("docker", sourceFile, dependencies);
  },
};

function parseDockerfile(content, sourceFile) {
  const dependencies = [];
  const stageAliases = new Set();
  const argDefaults = new Map();

  for (const instruction of toLogicalDockerLines(content)) {
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
      continue;
    }

    dependencies.push(createDependency({
      name: parsed.name,
      version: parsed.version,
      ecosystem: "docker",
      isDirect: true,
      parent: null,
      parentChain: [],
      transitives: [],
      sourceFile,
      isDevelopmentDependency: false,
    }));
  }

  return dependencies;
}

function parseCompose(content, sourceFile) {
  const dependencies = [];
  let servicesIndent = null;
  let currentService = null;

  const flushCurrentService = () => {
    if (!currentService) {
      return;
    }
    if (!currentService.hasBuild && currentService.image) {
      const parsed = parseDockerImageReference(currentService.image);
      if (parsed && parsed.name.toLowerCase() !== "scratch") {
        dependencies.push(createDependency({
          name: parsed.name,
          version: parsed.version,
          ecosystem: "docker",
          isDirect: true,
          parent: null,
          parentChain: [],
          transitives: [],
          sourceFile,
          isDevelopmentDependency: false,
        }));
      }
    }
    currentService = null;
  };

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const cleaned = stripYamlComment(rawLine).trim();
    if (!cleaned) {
      continue;
    }

    const indent = countIndent(rawLine);
    if (cleaned === "services:") {
      flushCurrentService();
      servicesIndent = indent;
      continue;
    }
    if (servicesIndent != null && indent <= servicesIndent && cleaned.endsWith(":")) {
      flushCurrentService();
      servicesIndent = null;
    }
    if (servicesIndent == null || indent <= servicesIndent) {
      continue;
    }

    if (indent === servicesIndent + 2 && cleaned.endsWith(":")) {
      flushCurrentService();
      currentService = { indent, hasBuild: false, image: "" };
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
    }
  }

  flushCurrentService();
  return dependencies;
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

function parseFromInstruction(line, argDefaults, stageAliases) {
  const parts = line.split(/\s+/).filter(Boolean);
  let index = 1;
  while (parts[index] && parts[index].startsWith("--")) {
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
    isDependency: !stageReference && parsed.name.toLowerCase() !== "scratch",
  };
}

function parseDockerImageReference(reference) {
  const raw = unquote(reference);
  if (!raw || raw.includes("$")) {
    return null;
  }
  const withoutDigest = raw.split("@")[0];
  const digest = raw.includes("@") ? raw.split("@")[1] : "";
  const lastSlash = withoutDigest.lastIndexOf("/");
  const lastColon = withoutDigest.lastIndexOf(":");
  const hasTag = lastColon > lastSlash;
  const name = hasTag ? withoutDigest.slice(0, lastColon) : withoutDigest;
  const version = hasTag ? withoutDigest.slice(lastColon + 1) : digest || "latest";
  if (!name) {
    return null;
  }
  return { name, version };
}

function unquote(value) {
  return String(value || "").trim().replace(/^["']|["']$/g, "");
}

function isComposeFileName(fileName) {
  return ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"].includes(fileName);
}

module.exports = dockerParser;

// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  escapeRegExp,
  normalizeVersion,
  parseInlineTomlValue,
  parseKeyValueLine,
  parseQuotedArray,
  stripTomlComment,
  stripYamlComment,
} = require("./shared");

function parsePackageJsonManifest(content) {
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch {
    return {
      dependencies: [],
      directNames: new Set(),
      devNames: new Set(),
    };
  }

  const dependencies = [];
  const directNames = new Set();
  const devNames = new Set();

  const addSection = (sectionName, isDevelopmentDependency) => {
    const section = parsed[sectionName];
    if (!section || typeof section !== "object") {
      return;
    }

    for (const [name, version] of Object.entries(section)) {
      dependencies.push({
        name,
        version: normalizeVersion(version),
        declaredConstraint: String(version || "").trim() || null,
        isDevelopmentDependency,
      });
      if (isDevelopmentDependency) {
        devNames.add(name);
      } else {
        directNames.add(name);
      }
    }
  };

  addSection("dependencies", false);
  addSection("devDependencies", true);
  addSection("optionalDependencies", false);
  addSection("peerDependencies", false);

  return {
    dependencies,
    directNames,
    devNames,
  };
}

function parsePyprojectManifest(content) {
  const lines = String(content || "").split(/\r?\n/);
  const dependencies = [];
  const directNames = new Set();
  const devNames = new Set();
  let projectName = "";
  let section = "";
  let collectingProjectDependencies = false;
  let projectDependenciesBuffer = "";

  const flushProjectDependencies = () => {
    if (!projectDependenciesBuffer) {
      return;
    }
    for (const item of parseQuotedArray(projectDependenciesBuffer)) {
      const parsed = parseRequirementSpec(item);
      if (!parsed) {
        continue;
      }
      dependencies.push({
        ...parsed,
        isDevelopmentDependency: false,
      });
      directNames.add(parsed.name);
    }
    projectDependenciesBuffer = "";
    collectingProjectDependencies = false;
  };

  for (const rawLine of lines) {
    const withoutComment = stripTomlComment(rawLine);
    const line = withoutComment.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    if (collectingProjectDependencies) {
      projectDependenciesBuffer += projectDependenciesBuffer ? ` ${line}` : line;
      if (hasCompleteTomlArray(projectDependenciesBuffer)) {
        flushProjectDependencies();
      }
      continue;
    }

    if (line.startsWith("[") && line.endsWith("]")) {
      section = line;
      continue;
    }

    if (section === "[project]" && line.startsWith("name =")) {
      projectName = unquote(parseKeyValueLine(line).value);
      continue;
    }

    if (section === "[tool.poetry]" && line.startsWith("name =")) {
      projectName = unquote(parseKeyValueLine(line).value);
      continue;
    }

    if (section === "[project]" && line.startsWith("dependencies")) {
      projectDependenciesBuffer = parseKeyValueLine(line).value;
      if (hasCompleteTomlArray(projectDependenciesBuffer)) {
        flushProjectDependencies();
      } else {
        collectingProjectDependencies = true;
      }
      continue;
    }

    if (
      section === "[tool.poetry.dependencies]"
      || section === "[tool.poetry.dev-dependencies]"
      || /^\[tool\.poetry\.group\.[^.]+\.dependencies]$/.test(section)
    ) {
      const parts = parseKeyValueLine(line);
      if (!parts) {
        continue;
      }

      // TOML permits quoted dotted keys (for example, "ruamel.yaml"). The
      // quotes are syntax, not part of the package identity.
      const name = unquote(parts.key);
      if (!name || name.toLowerCase() === "python") {
        continue;
      }

      const rawValue = parts.value;
      const declaredConstraint = rawValue.startsWith("{")
        ? parseInlineTomlValue(rawValue, "version")
        : unquote(rawValue);
      const environmentMarker = rawValue.startsWith("{")
        ? parseInlineTomlValue(rawValue, "markers") || null
        : null;
      const version = normalizeVersion(declaredConstraint);
      const isDevelopmentDependency = section !== "[tool.poetry.dependencies]";

      dependencies.push({
        name,
        version: version === "*" || environmentMarker ? "" : version,
        declaredConstraint: declaredConstraint === "*" ? null : declaredConstraint || null,
        environmentMarker,
        isDevelopmentDependency,
      });

      if (isDevelopmentDependency) {
        devNames.add(name);
      } else {
        directNames.add(name);
      }
    }
  }

  if (collectingProjectDependencies) {
    throw new Error("Malformed pyproject.toml: unterminated project dependencies array");
  }

  return {
    projectName,
    dependencies,
    directNames,
    devNames,
  };
}

function parseRequirementSpec(spec) {
  const trimmedSpec = String(spec || "").trim();
  const enclosingQuote = trimmedSpec[0];
  const rawSpec = (enclosingQuote === "\"" || enclosingQuote === "'")
    && trimmedSpec.endsWith(enclosingQuote)
    ? trimmedSpec.slice(1, -1)
    : trimmedSpec;
  if (!rawSpec) {
    return null;
  }

  const markerSeparator = rawSpec.indexOf(";");
  const withoutMarker = (markerSeparator >= 0
    ? rawSpec.slice(0, markerSeparator)
    : rawSpec).trim();
  const environmentMarker = markerSeparator >= 0
    ? rawSpec.slice(markerSeparator + 1).trim() || null
    : null;
  const match = withoutMarker.match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]+])?\s*(.*)$/);
  if (!match) {
    return null;
  }

  const declaredConstraint = String(match[2] || "").trim() || null;
  if (!isValidPep508Constraint(declaredConstraint)) {
    return null;
  }

  return {
    name: match[1],
    version: environmentMarker ? "" : normalizeVersion(declaredConstraint || ""),
    declaredConstraint,
    environmentMarker,
  };
}

function isValidPep508Constraint(constraint) {
  if (!constraint) {
    return true;
  }
  const value = String(constraint).trim().replace(/^\(|\)$/g, "").trim();
  if (value.startsWith("@")) {
    return Boolean(value.slice(1).trim());
  }
  return /^(?:===|==|~=|!=|<=|>=|<|>)/.test(value);
}

function hasCompleteTomlArray(value) {
  let quote = "";
  let escaped = false;
  let depth = 0;
  let opened = false;

  for (const character of String(value || "")) {
    if (quote) {
      if (quote === '"' && character === "\\" && !escaped) {
        escaped = true;
        continue;
      }
      if (character === quote && !escaped) {
        quote = "";
      }
      escaped = false;
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }
    if (character === "[") {
      opened = true;
      depth += 1;
      continue;
    }
    if (character === "]" && opened) {
      depth -= 1;
      if (depth === 0) {
        return true;
      }
    }
  }

  return false;
}

function parseCargoTomlManifest(content) {
  const dependencies = [];
  let section = "";

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const line = stripTomlComment(rawLine).trim();
    if (!line) {
      continue;
    }

    if (line.startsWith("[") && line.endsWith("]")) {
      section = line;
      continue;
    }

    if (![
      "[dependencies]",
      "[dev-dependencies]",
      "[build-dependencies]",
      "[workspace.dependencies]",
    ].includes(section)) {
      continue;
    }

    const parts = parseKeyValueLine(line);
    if (!parts) {
      continue;
    }

    const declaredName = parts.key;
    const rawValue = parts.value;
    const actualName = parseInlineTomlValue(rawValue, "package") || declaredName;
    const version = rawValue.startsWith("{")
      ? normalizeVersion(parseInlineTomlValue(rawValue, "version"))
      : normalizeVersion(unquote(rawValue));
    const localPath = parseInlineTomlValue(rawValue, "path");
    const gitUrl = parseInlineTomlValue(rawValue, "git");

    dependencies.push({
      name: actualName,
      version,
      isDevelopmentDependency: section !== "[dependencies]" && section !== "[workspace.dependencies]",
      packageSource: localPath
        ? { kind: "path", location: localPath }
        : gitUrl
          ? { kind: "git", location: sanitizeSourceLocation(gitUrl) }
          : { kind: "registry" },
    });
  }

  return dependencies;
}

function parseGemfileManifest(content) {
  const dependenciesByName = new Map();
  const pattern = /^\s*gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?/;
  const blockStack = [];

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const line = stripRubyComment(rawLine).trim();
    if (!line) {
      continue;
    }

    const groupMatch = line.match(/^group\s*(?:\((.*?)\)|(.*?))\s+do\b/);
    if (groupMatch) {
      const groups = (groupMatch[1] || groupMatch[2] || "").match(/:[A-Za-z0-9_]+/g) || [];
      blockStack.push(groups.some((group) => [":development", ":test"].includes(group.toLowerCase())));
      continue;
    }

    if (/^end\b/.test(line)) {
      blockStack.pop();
      continue;
    }

    if (/\bdo\b(?:\s*\|[^|]*\|)?\s*$/.test(line)) {
      blockStack.push(false);
    }

    const match = line.match(pattern);
    if (!match) {
      continue;
    }

    const inlineGroups = line.match(/\b(?:group|groups)\s*:\s*(?:\[[^\]]*]|:[A-Za-z0-9_]+)/g) || [];
    const isDevelopmentDependency = blockStack.includes(true)
      || inlineGroups.some((value) => /:(?:development|test)\b/i.test(value));
    const dependency = {
      name: match[1],
      version: normalizeVersion(match[2] || ""),
      isDevelopmentDependency,
      packageSource: { kind: "registry" },
    };
    const key = dependency.name.toLowerCase();
    const existing = dependenciesByName.get(key);
    if (!existing || (existing.isDevelopmentDependency && !isDevelopmentDependency)) {
      dependenciesByName.set(key, dependency);
    }
  }

  return [...dependenciesByName.values()];
}

function parseBuildGradleManifest(content) {
  const dependencies = [];
  const lines = String(content || "").split(/\r?\n/);
  let inDependenciesBlock = false;
  let braceDepth = 0;
  let dependencyBlockDepth = 0;

  for (const rawLine of lines) {
    const line = stripJavaLikeComment(rawLine).trim();
    if (!line) {
      braceDepth += countBraces(rawLine);
      continue;
    }

    if (!inDependenciesBlock && /^dependencies\s*\{/.test(line)) {
      inDependenciesBlock = true;
      dependencyBlockDepth = braceDepth + 1;
    } else if (!inDependenciesBlock && line === "dependencies") {
      inDependenciesBlock = true;
      dependencyBlockDepth = braceDepth + 1;
    } else if (inDependenciesBlock) {
      const parsed = parseGradleDependencyLine(line);
      if (parsed) {
        dependencies.push(parsed);
      }
    }

    braceDepth += countBraces(rawLine);
    if (inDependenciesBlock && braceDepth < dependencyBlockDepth) {
      inDependenciesBlock = false;
      dependencyBlockDepth = 0;
    }
  }

  return dedupeManifestDeps(dependencies, { caseSensitiveName: true });
}

function parseGradleDependencyLine(line) {
  const match = line.match(/^\s*([A-Za-z][A-Za-z0-9_-]*)\s*\(?\s*["']([^"']+)["']/);
  if (!match) {
    return null;
  }

  const configuration = match[1].toLowerCase();
  const coordinates = match[2].split(":").filter(Boolean);
  if (coordinates.length < 2) {
    return null;
  }

  return {
    name: `${coordinates[0]}:${coordinates[1]}`,
    version: coordinates[2] ? normalizeVersion(coordinates[2]) : "",
    isDevelopmentDependency: configuration.includes("test"),
    qualifiers: { configurations: [configuration] },
    packageSource: { kind: "registry" },
  };
}

function parseCsprojManifest(content) {
  const dependencies = [];
  const inlinePattern = /<PackageReference\b([^>]*)\/>/gi;
  const blockPattern = /<PackageReference\b([^>]*)>([\s\S]*?)<\/PackageReference>/gi;

  const parseAttributes = (attributesText, blockText) => {
    const includeMatch = attributesText.match(/\b(?:Include|Update)="([^"]+)"/i);
    if (!includeMatch) {
      return;
    }

    let version = "";
    const attributeVersionMatch = attributesText.match(/\bVersion="([^"]+)"/i);
    if (attributeVersionMatch) {
      version = attributeVersionMatch[1];
    } else if (blockText) {
      const nestedVersionMatch = blockText.match(/<Version>\s*([^<]+)\s*<\/Version>/i);
      if (nestedVersionMatch) {
        version = nestedVersionMatch[1];
      }
    }

    dependencies.push({
      name: includeMatch[1].trim(),
      version: normalizeVersion(version),
      isDevelopmentDependency: false,
      packageSource: { kind: "registry" },
    });
  };

  for (const match of content.matchAll(inlinePattern)) {
    parseAttributes(match[1], "");
  }

  for (const match of content.matchAll(blockPattern)) {
    parseAttributes(match[1], match[2]);
  }

  return dedupeManifestDeps(dependencies);
}

function parsePubspecManifest(content) {
  const dependencies = [];
  let section = "";
  let current = null;

  const flushCurrent = () => {
    if (!current || !current.name) {
      current = null;
      return;
    }
    const source = current.source || "registry";
    dependencies.push({
      name: current.name,
      version: normalizeVersion(current.version),
      isDevelopmentDependency: current.isDevelopmentDependency,
      packageSource: source === "hosted" || source === "registry"
        ? { kind: "registry" }
        : source === "path"
          ? { kind: "path", ...(current.location ? { location: current.location } : {}) }
          : source === "git"
            ? { kind: "git", ...(current.location ? { location: sanitizeSourceLocation(current.location) } : {}) }
            : source === "sdk"
              ? { kind: "sdk" }
              : { kind: "unknown" },
    });
    current = null;
  };

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const lineWithoutComment = stripYamlComment(rawLine);
    const line = lineWithoutComment.trim();
    if (!line) {
      continue;
    }

    const indent = rawLine.search(/\S/);
    if (indent === 0 && line.endsWith(":")) {
      flushCurrent();
      section = line.slice(0, -1);
      continue;
    }

    if (!["dependencies", "dev_dependencies"].includes(section)) {
      continue;
    }

    if (indent === 2 && line.startsWith("-")) {
      continue;
    }

    if (indent === 2 && line.includes(":")) {
      flushCurrent();
      const name = line.split(":", 1)[0].trim();
      const rawValue = line.split(":").slice(1).join(":").trim();
      if (!name) {
        continue;
      }
      current = {
        name,
        version: rawValue.startsWith("{")
          ? parseYamlInlineValue(rawValue, "version")
          : unquote(rawValue),
        isDevelopmentDependency: section === "dev_dependencies",
        source: rawValue.includes("path:") ? "path"
          : rawValue.includes("git:") ? "git"
            : rawValue.includes("sdk:") ? "sdk" : "registry",
        location: parseYamlInlineValue(rawValue, "path") || parseYamlInlineValue(rawValue, "url"),
      };
      continue;
    }

    if (!current || indent < 4 || !line.includes(":")) {
      continue;
    }
    const key = line.split(":", 1)[0].trim().toLowerCase();
    const value = unquote(line.split(":").slice(1).join(":").trim());
    if (["path", "git", "sdk", "hosted"].includes(key)) {
      current.source = key;
      if (key === "path") current.location = value;
    } else if (key === "url") {
      current.location = value;
    } else if (key === "version") {
      current.version = value;
    }
  }

  flushCurrent();
  return dedupeManifestDeps(dependencies);
}

function parseComposerManifest(content) {
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }

  const dependencies = [];
  const sourceKinds = composerManifestSourceKinds(parsed.repositories);
  for (const [name, version] of Object.entries(parsed.require || {})) {
    if (!isComposerPackageName(name)) {
      continue;
    }
    dependencies.push({
      name,
      version: normalizeVersion(version),
      isDevelopmentDependency: false,
      packageSource: sourceKinds.get(name.toLowerCase()) || { kind: "registry" },
    });
  }
  for (const [name, version] of Object.entries(parsed["require-dev"] || {})) {
    if (!isComposerPackageName(name)) {
      continue;
    }
    dependencies.push({
      name,
      version: normalizeVersion(version),
      isDevelopmentDependency: true,
      packageSource: sourceKinds.get(name.toLowerCase()) || { kind: "registry" },
    });
  }
  return dedupeManifestDeps(dependencies);
}

function parseChartManifest(content) {
  return parseSimpleYamlDependencyList(content, "dependencies");
}

function parsePackageSwiftManifest(content) {
  const dependencies = [];
  const pattern = /\.package\s*\(([\s\S]*?)\)/g;

  for (const match of content.matchAll(pattern)) {
    const declaration = match[1];
    const identityMatch = declaration.match(/\b(?:name|id|identity)\s*:\s*"([^"]+)"/);
    const urlMatch = declaration.match(/\burl\s*:\s*"([^"]+)"/);
    const pathMatch = declaration.match(/\bpath\s*:\s*"([^"]+)"/);
    const registryIdentityMatch = declaration.match(/\b(?:id|identity)\s*:\s*"([^"]+)"/);
    const semanticVersionMatch = declaration.match(/\b(?:from|exact)\s*:\s*"([^"]+)"/);
    const branchMatch = declaration.match(/\bbranch\s*:\s*"([^"]+)"/);
    const revisionMatch = declaration.match(/\brevision\s*:\s*"([^"]+)"/);
    const rawIdentity = registryIdentityMatch
      ? registryIdentityMatch[1]
      : identityMatch ? identityMatch[1]
        : urlMatch ? urlMatch[1]
          : pathMatch ? pathMatch[1] : "";
    const name = normalizeSwiftIdentity(rawIdentity);
    if (!name) {
      continue;
    }
    const isRegistry = Boolean(registryIdentityMatch && !urlMatch && !pathMatch);
    const packageSource = isRegistry
      ? { kind: "registry" }
      : pathMatch
        ? { kind: "path", location: pathMatch[1] }
        : {
          kind: "scm",
          ...(urlMatch ? { location: sanitizeSourceLocation(urlMatch[1]) } : {}),
          ...(branchMatch ? { branch: branchMatch[1] } : {}),
          ...(revisionMatch ? { revision: revisionMatch[1] } : {}),
        };
    const scope = isRegistry && name.includes(".") ? name.split(".", 1)[0] : "";
    dependencies.push({
      name,
      version: normalizeVersion(semanticVersionMatch ? semanticVersionMatch[1] : ""),
      isDevelopmentDependency: false,
      packageSource,
      ...(scope ? { qualifiers: { scope } } : {}),
    });
  }

  const seen = new Set();
  return dependencies.filter((dependency) => {
    const source = dependency.packageSource || {};
    const key = JSON.stringify([
      dependency.name,
      dependency.version,
      source.kind || "unknown",
      source.location || "",
      source.branch || "",
      source.revision || "",
    ]);
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function normalizeSwiftIdentity(name) {
  const value = String(name || "").trim();
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+$/.test(value) && !value.includes("/") && !value.includes("://")) {
    return value.toLocaleLowerCase("en-US");
  }
  return value.split("/").filter(Boolean).pop()?.replace(/\.git$/i, "").toLocaleLowerCase("en-US") || "";
}

function parseMixExsManifest(content) {
  const dependencies = [];
  const depsBlockMatch = content.match(/defp\s+deps\s+do\s*\[([\s\S]*?)\]\s*end/m);
  if (!depsBlockMatch) {
    return [];
  }

  for (const tuple of extractBalancedDelimitedValues(depsBlockMatch[1], "{", "}")) {
    const match = tuple.match(/^\{\s*:([A-Za-z0-9_]+)\s*,([\s\S]*)}$/);
    if (!match) continue;
    const options = match[2] || "";
    const constraintMatch = options.match(/^\s*"([^"]*)"/);
    const pathMatch = options.match(/\bpath\s*:\s*"([^"]+)"/);
    const gitMatch = options.match(/\bgit\s*:\s*"([^"]+)"/);
    const environments = (options.match(/:(?:dev|test|prod)\b/g) || [])
      .map((value) => value.slice(1));
    const isDevelopmentDependency = environments.length > 0
      && environments.every((environment) => environment === "dev" || environment === "test");
    dependencies.push({
      name: match[1],
      version: normalizeVersion(constraintMatch ? constraintMatch[1] : ""),
      isDevelopmentDependency,
      packageSource: pathMatch
        ? { kind: "path", location: pathMatch[1] }
        : gitMatch
          ? { kind: "git", location: sanitizeSourceLocation(gitMatch[1]) }
          : { kind: "registry" },
      ...(environments.length > 0 ? { qualifiers: { environment: environments.join(",") } } : {}),
    });
  }
  return dedupeManifestDeps(dependencies);
}

function extractBalancedDelimitedValues(content, openCharacter, closeCharacter) {
  const values = [];
  let depth = 0;
  let start = -1;
  let quote = "";
  let escaped = false;
  for (let index = 0; index < String(content || "").length; index += 1) {
    const character = content[index];
    if (quote) {
      if (character === "\\" && !escaped) {
        escaped = true;
        continue;
      }
      if (character === quote && !escaped) quote = "";
      escaped = false;
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }
    if (character === openCharacter) {
      if (depth === 0) start = index;
      depth += 1;
      continue;
    }
    if (character === closeCharacter && depth > 0) {
      depth -= 1;
      if (depth === 0 && start >= 0) {
        values.push(content.slice(start, index + 1));
        start = -1;
      }
    }
  }
  return values;
}

function parsePomManifest(content) {
  const dependencies = [];
  const dependencyBlocks = content.match(/<dependency>[\s\S]*?<\/dependency>/gi) || [];

  for (const block of dependencyBlocks) {
    const groupId = matchXmlValue(block, "groupId");
    const artifactId = matchXmlValue(block, "artifactId");
    const scope = matchXmlValue(block, "scope");
    const type = matchXmlValue(block, "type") || "jar";
    const classifier = matchXmlValue(block, "classifier");
    const systemPath = matchXmlValue(block, "systemPath");
    if (!groupId || !artifactId) {
      continue;
    }

    let version = matchXmlValue(block, "version");
    if (version && /\$\{[^}]+}/.test(version)) {
      version = "";
    }

    dependencies.push({
      name: `${groupId}:${artifactId}`,
      version: normalizeVersion(version),
      isDevelopmentDependency: scope === "test",
      qualifiers: {
        type,
        ...(classifier ? { classifier } : {}),
      },
      packageSource: scope === "system"
        ? { kind: "system", ...(systemPath ? { location: systemPath } : {}) }
        : { kind: "registry" },
    });
  }

  return dedupeManifestDeps(dependencies);
}

function parseSimpleYamlDependencyList(content, sectionName) {
  const dependencies = [];
  let inSection = false;
  let sectionIndent = -1;
  let currentDependency = null;
  let itemIndent = -1;

  const flushCurrent = () => {
    if (!currentDependency || !currentDependency.name) {
      currentDependency = null;
      return;
    }
    const repository = currentDependency.repository
      ? unquote(currentDependency.repository)
      : "";
    const packageSource = repository && /^(?:file:|\.?\.?\/)/i.test(repository)
      ? { kind: "path", location: repository }
      : repository && /^(?:git\+|git:|ssh:)|\.git(?:#|$)/i.test(repository)
        ? { kind: "git", location: repository }
        : { kind: "registry" };
    dependencies.push({
      name: unquote(currentDependency.name),
      version: normalizeVersion(currentDependency.version),
      isDevelopmentDependency: false,
      repository: repository || undefined,
      alias: currentDependency.alias ? unquote(currentDependency.alias) : undefined,
      packageSource,
    });
    currentDependency = null;
    itemIndent = -1;
  };

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const lineWithoutComment = stripYamlComment(rawLine);
    const line = lineWithoutComment.trim();
    if (!line) {
      continue;
    }

    const indent = rawLine.search(/\S/);
    if (line === `${sectionName}:`) {
      flushCurrent();
      inSection = true;
      sectionIndent = indent;
      continue;
    }

    if (inSection && line.startsWith("- ") && indent >= sectionIndent) {
      flushCurrent();
      currentDependency = { name: "", version: "", repository: "", alias: "" };
      itemIndent = indent;
      const remainder = line.slice(2).trim();
      if (remainder.startsWith("name:")) {
        currentDependency.name = remainder.slice("name:".length).trim();
      }
      continue;
    }

    if (inSection && indent <= sectionIndent) {
      inSection = false;
      flushCurrent();
    }
    if (!inSection) {
      continue;
    }

    if (!currentDependency || indent <= itemIndent) {
      continue;
    }

    if (line.startsWith("name:")) {
      currentDependency.name = line.slice("name:".length).trim();
    }
    if (line.startsWith("version:")) {
      currentDependency.version = line.slice("version:".length).trim();
    }
    if (line.startsWith("repository:")) {
      currentDependency.repository = line.slice("repository:".length).trim();
    }
    if (line.startsWith("alias:")) {
      currentDependency.alias = line.slice("alias:".length).trim();
    }
  }

  flushCurrent();
  return dedupeManifestDeps(dependencies);
}

function dedupeManifestDeps(dependencies, options = {}) {
  const seen = new Set();
  const results = [];
  for (const dependency of dependencies) {
    const rawName = String(dependency.name || "");
    const name = options.caseSensitiveName ? rawName : rawName.toLowerCase();
    const key = `${name}:${String(dependency.version || "")}:${dependency.isDevelopmentDependency}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    results.push(dependency);
  }
  return results;
}

function parseYamlInlineValue(block, key) {
  const match = String(block || "").match(new RegExp(`${escapeRegExp(key)}\\s*:\\s*([^,}]+)`));
  return match ? unquote(match[1].trim()) : "";
}

function unquote(value) {
  return String(value || "").trim().replace(/^["']|["']$/g, "");
}

function stripRubyComment(line) {
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

function stripJavaLikeComment(line) {
  return String(line || "").replace(/\/\/.*$/, "").trimEnd();
}

function composerManifestSourceKinds(repositories) {
  const sources = new Map();
  const entries = Array.isArray(repositories)
    ? repositories
    : repositories && typeof repositories === "object"
      ? Object.values(repositories)
      : [];
  for (const repository of entries) {
    if (!repository || typeof repository !== "object" || Array.isArray(repository)) {
      continue;
    }
    const descriptor = repository.package && typeof repository.package === "object"
      ? repository.package
      : repository;
    const name = String(descriptor.name || repository.name || "").trim().toLowerCase();
    if (!name || !isComposerPackageName(name)) {
      continue;
    }
    const type = String(repository.type || descriptor.type || "").toLowerCase();
    const location = repository.url
      || descriptor.dist && descriptor.dist.url
      || descriptor.source && descriptor.source.url
      || "";
    const kind = type === "path" ? "path"
      : ["git", "github", "gitlab", "bitbucket", "vcs"].includes(type) ? "git"
        : "registry";
    sources.set(name, {
      kind,
      ...(location ? { location: sanitizeSourceLocation(location) } : {}),
    });
  }
  return sources;
}

function sanitizeSourceLocation(value) {
  const raw = String(value || "").trim().replace(/[\u0000-\u001f\u007f]/g, "");
  if (!raw) {
    return "";
  }
  if (path.isAbsolute(raw)) {
    return path.basename(raw).slice(0, 4096);
  }
  try {
    const parsed = new URL(raw);
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    return parsed.toString().slice(0, 4096);
  } catch {
    return raw
      .replace(/^[^/@\s]+@(?=[^/:\s]+[:/])/, "")
      .replace(/[?#].*$/, "")
      .slice(0, 4096);
  }
}

function countBraces(line) {
  const openBraces = (line.match(/\{/g) || []).length;
  const closeBraces = (line.match(/\}/g) || []).length;
  return openBraces - closeBraces;
}

function isComposerPackageName(name) {
  return typeof name === "string"
    && name.includes("/")
    && !name.startsWith("ext-")
    && !name.startsWith("lib-")
    && name !== "php";
}

function matchXmlValue(block, tagName) {
  const match = String(block || "").match(new RegExp(`<${tagName}>\\s*([^<]+)\\s*</${tagName}>`, "i"));
  return match ? match[1].trim() : "";
}

module.exports = {
  normalizeSwiftIdentity,
  hasCompleteTomlArray,
  parseBuildGradleManifest,
  parseCargoTomlManifest,
  parseChartManifest,
  parseComposerManifest,
  parseCsprojManifest,
  parseGemfileManifest,
  parseMixExsManifest,
  parsePackageJsonManifest,
  parsePackageSwiftManifest,
  parsePomManifest,
  parsePubspecManifest,
  parsePyprojectManifest,
  parseRequirementSpec,
};

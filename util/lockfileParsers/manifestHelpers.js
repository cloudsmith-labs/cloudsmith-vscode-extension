// Copyright 2026 Cloudsmith Ltd. All rights reserved.
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
      if (projectDependenciesBuffer.includes("]")) {
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
      if (projectDependenciesBuffer.includes("]")) {
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

      const name = parts.key;
      if (!name || name.toLowerCase() === "python") {
        continue;
      }

      const rawValue = parts.value;
      const version = rawValue.startsWith("{")
        ? normalizeVersion(parseInlineTomlValue(rawValue, "version"))
        : normalizeVersion(unquote(rawValue));
      const isDevelopmentDependency = section !== "[tool.poetry.dependencies]";

      dependencies.push({
        name,
        version: version === "*" ? "" : version,
        isDevelopmentDependency,
      });

      if (isDevelopmentDependency) {
        devNames.add(name);
      } else {
        directNames.add(name);
      }
    }
  }

  return {
    projectName,
    dependencies,
    directNames,
    devNames,
  };
}

function parseRequirementSpec(spec) {
  const rawSpec = String(spec || "").trim().replace(/^["']|["']$/g, "");
  if (!rawSpec) {
    return null;
  }

  const withoutMarker = rawSpec.split(";")[0].trim();
  const match = withoutMarker.match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]+])?\s*(.*)$/);
  if (!match) {
    return null;
  }

  return {
    name: match[1],
    version: normalizeVersion(match[2] || ""),
  };
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

    dependencies.push({
      name: actualName,
      version,
      isDevelopmentDependency: section !== "[dependencies]" && section !== "[workspace.dependencies]",
    });
  }

  return dependencies;
}

function parseGemfileManifest(content) {
  const dependencies = [];
  const pattern = /^\s*gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?/;

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const line = stripRubyComment(rawLine).trim();
    const match = line.match(pattern);
    if (!match) {
      continue;
    }
    dependencies.push({
      name: match[1],
      version: normalizeVersion(match[2] || ""),
      isDevelopmentDependency: false,
    });
  }

  return dependencies;
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

  return dedupeManifestDeps(dependencies);
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

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const lineWithoutComment = stripYamlComment(rawLine);
    const line = lineWithoutComment.trim();
    if (!line) {
      continue;
    }

    const indent = rawLine.search(/\S/);
    if (indent === 0 && line.endsWith(":")) {
      section = line.slice(0, -1);
      continue;
    }

    if (!["dependencies", "dev_dependencies"].includes(section) || indent !== 2) {
      continue;
    }

    if (line.startsWith("-")) {
      continue;
    }

    const name = line.split(":", 1)[0].trim();
    const rawValue = line.includes(":") ? line.split(":").slice(1).join(":").trim() : "";
    const version = rawValue.startsWith("{")
      ? normalizeVersion(parseYamlInlineValue(rawValue, "version"))
      : normalizeVersion(unquote(rawValue));

    if (!name) {
      continue;
    }

    dependencies.push({
      name,
      version,
      isDevelopmentDependency: section === "dev_dependencies",
    });
  }

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
  for (const [name, version] of Object.entries(parsed.require || {})) {
    if (!isComposerPackageName(name)) {
      continue;
    }
    dependencies.push({ name, version: normalizeVersion(version), isDevelopmentDependency: false });
  }
  for (const [name, version] of Object.entries(parsed["require-dev"] || {})) {
    if (!isComposerPackageName(name)) {
      continue;
    }
    dependencies.push({ name, version: normalizeVersion(version), isDevelopmentDependency: true });
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
    const versionMatch = declaration.match(/\b(?:from|exact|branch|revision)\s*:\s*"([^"]+)"/);
    const name = normalizeSwiftIdentity(identityMatch ? identityMatch[1] : urlMatch ? urlMatch[1] : "");
    if (!name) {
      continue;
    }
    dependencies.push({
      name,
      version: normalizeVersion(versionMatch ? versionMatch[1] : ""),
      isDevelopmentDependency: false,
    });
  }

  return dedupeManifestDeps(dependencies);
}

function normalizeSwiftIdentity(name) {
  return String(name || "")
    .trim()
    .split("/")
    .filter(Boolean)
    .pop()
    ?.replace(/\.git$/i, "")
    .toLowerCase() || "";
}

function parseMixExsManifest(content) {
  const dependencies = [];
  const depsBlockMatch = content.match(/defp\s+deps\s+do\s*\[([\s\S]*?)\]\s*end/m);
  if (!depsBlockMatch) {
    return [];
  }

  const pattern = /\{\s*:([A-Za-z0-9_]+)\s*,\s*"([^"]*)"/g;
  for (const match of depsBlockMatch[1].matchAll(pattern)) {
    dependencies.push({
      name: match[1],
      version: normalizeVersion(match[2]),
      isDevelopmentDependency: false,
    });
  }
  return dedupeManifestDeps(dependencies);
}

function parsePomManifest(content) {
  const dependencies = [];
  const dependencyBlocks = content.match(/<dependency>[\s\S]*?<\/dependency>/gi) || [];

  for (const block of dependencyBlocks) {
    const groupId = matchXmlValue(block, "groupId");
    const artifactId = matchXmlValue(block, "artifactId");
    const scope = matchXmlValue(block, "scope");
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
    });
  }

  return dedupeManifestDeps(dependencies);
}

function parseSimpleYamlDependencyList(content, sectionName) {
  const dependencies = [];
  let inSection = false;
  let currentDependency = null;

  const flushCurrent = () => {
    if (!currentDependency || !currentDependency.name) {
      currentDependency = null;
      return;
    }
    dependencies.push({
      name: currentDependency.name,
      version: normalizeVersion(currentDependency.version),
      isDevelopmentDependency: false,
    });
    currentDependency = null;
  };

  for (const rawLine of String(content || "").split(/\r?\n/)) {
    const lineWithoutComment = stripYamlComment(rawLine);
    const line = lineWithoutComment.trim();
    if (!line) {
      continue;
    }

    const indent = rawLine.search(/\S/);
    if (indent === 0 && line === `${sectionName}:`) {
      inSection = true;
      continue;
    }
    if (indent === 0 && line.endsWith(":") && line !== `${sectionName}:`) {
      inSection = false;
      flushCurrent();
      continue;
    }
    if (!inSection) {
      continue;
    }

    if (indent === 2 && line.startsWith("- ")) {
      flushCurrent();
      currentDependency = { name: "", version: "" };
      const remainder = line.slice(2).trim();
      if (remainder.startsWith("name:")) {
        currentDependency.name = remainder.slice("name:".length).trim();
      }
      continue;
    }

    if (!currentDependency) {
      continue;
    }

    if (indent >= 4 && line.startsWith("name:")) {
      currentDependency.name = line.slice("name:".length).trim();
    }
    if (indent >= 4 && line.startsWith("version:")) {
      currentDependency.version = line.slice("version:".length).trim();
    }
  }

  flushCurrent();
  return dedupeManifestDeps(dependencies);
}

function dedupeManifestDeps(dependencies) {
  const seen = new Set();
  const results = [];
  for (const dependency of dependencies) {
    const key = `${dependency.name.toLowerCase()}:${dependency.version.toLowerCase()}:${dependency.isDevelopmentDependency}`;
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

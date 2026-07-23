// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const fs = require("fs");
const path = require("path");

const LARGE_FILE_THRESHOLD_BYTES = 50 * 1024 * 1024;
const WORKSPACE_PATH_ERROR = "Refusing to read files outside the workspace folder.";

function getWorkspacePath(workspaceFolder) {
  if (!workspaceFolder) {
    return "";
  }

  if (typeof workspaceFolder === "string") {
    return workspaceFolder;
  }

  if (workspaceFolder.uri && workspaceFolder.uri.fsPath) {
    return workspaceFolder.uri.fsPath;
  }

  return String(workspaceFolder);
}

async function pathExists(targetPath, workspaceFolder) {
  const safePath = await resolveWorkspaceFilePath(targetPath, workspaceFolder);
  if (!safePath) {
    return false;
  }

  try {
    await fs.promises.access(safePath, fs.constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

function getCandidateWorkspaceRoot(targetPath, workspaceFolder) {
  const workspacePath = getWorkspacePath(workspaceFolder);
  if (workspacePath) {
    return workspacePath;
  }

  const rawTargetPath = String(targetPath || "").trim();
  if (!rawTargetPath) {
    return "";
  }

  return path.dirname(path.resolve(rawTargetPath));
}

async function resolveWorkspaceRoot(targetPath, workspaceFolder) {
  const candidateRoot = getCandidateWorkspaceRoot(targetPath, workspaceFolder);
  if (!candidateRoot) {
    return "";
  }

  try {
    return await fs.promises.realpath(candidateRoot);
  } catch {
    return path.resolve(candidateRoot);
  }
}

function isWithinWorkspace(workspaceRoot, targetPath) {
  if (!workspaceRoot || !targetPath) {
    return false;
  }

  const relativePath = path.relative(workspaceRoot, targetPath);
  return relativePath === ""
    || (!relativePath.startsWith("..") && !path.isAbsolute(relativePath));
}

async function resolveWorkspaceFilePath(targetPath, workspaceFolder) {
  const rawTargetPath = String(targetPath || "").trim();
  if (!rawTargetPath) {
    return null;
  }

  const resolvedTargetPath = path.resolve(rawTargetPath);
  const workspaceRoot = await resolveWorkspaceRoot(resolvedTargetPath, workspaceFolder);
  if (!workspaceRoot) {
    return null;
  }

  let realTargetPath;
  try {
    realTargetPath = await fs.promises.realpath(resolvedTargetPath);
  } catch {
    return null;
  }

  return isWithinWorkspace(workspaceRoot, realTargetPath)
    ? realTargetPath
    : null;
}

async function readUtf8(targetPath, workspaceFolder) {
  const safePath = await resolveWorkspaceFilePath(targetPath, workspaceFolder);
  if (!safePath) {
    throw new Error(WORKSPACE_PATH_ERROR);
  }

  return fs.promises.readFile(safePath, "utf8");
}

async function readJson(targetPath, workspaceFolder) {
  return JSON.parse(await readUtf8(targetPath, workspaceFolder));
}

async function statSafe(targetPath, workspaceFolder) {
  const safePath = await resolveWorkspaceFilePath(targetPath, workspaceFolder);
  if (!safePath) {
    return null;
  }

  try {
    return await fs.promises.stat(safePath);
  } catch {
    return null;
  }
}

function getSourceFileName(targetPath) {
  return path.basename(targetPath || "");
}

function normalizeVersion(version) {
  if (version == null) {
    return "";
  }

  return String(version)
    .trim()
    .replace(/^["']|["']$/g, "")
    .replace(/^[~^<>=! ]+/, "")
    .trim();
}

function createDependency({
  name,
  version,
  ecosystem,
  isDirect,
  parent,
  parentChain,
  transitives,
  sourceFile,
  isDevelopmentDependency,
}) {
  return {
    name: String(name || "").trim(),
    version: String(version || "").trim(),
    ecosystem: String(ecosystem || "").trim(),
    isDirect: Boolean(isDirect),
    parent: parent || null,
    parentChain: Array.isArray(parentChain) ? parentChain.slice() : [],
    transitives: Array.isArray(transitives) ? transitives.slice() : [],
    cloudsmithStatus: null,
    cloudsmithPackage: null,
    sourceFile: sourceFile || null,
    isDevelopmentDependency: Boolean(isDevelopmentDependency),
  };
}

function flattenDependencies(dependencies) {
  const flattened = [];

  for (const dependency of Array.isArray(dependencies) ? dependencies : []) {
    flattened.push(dependency);
    if (Array.isArray(dependency.transitives) && dependency.transitives.length > 0) {
      flattened.push(...flattenDependencies(dependency.transitives));
    }
  }

  return flattened;
}

function dependencyKey(dependency) {
  return [
    String(dependency.ecosystem || "").trim().toLowerCase(),
    String(dependency.name || "").trim().toLowerCase(),
    String(dependency.version || "").trim().toLowerCase(),
  ].join(":");
}

function deduplicateDeps(dependencies) {
  const unique = [];
  const seen = new Map();

  for (const dependency of Array.isArray(dependencies) ? dependencies : []) {
    const key = dependencyKey(dependency);
    const existing = seen.get(key);
    if (!existing) {
      seen.set(key, dependency);
      unique.push(dependency);
      continue;
    }

    if (!existing.isDirect && dependency.isDirect) {
      const index = unique.indexOf(existing);
      if (index !== -1) {
        unique[index] = dependency;
      }
      seen.set(key, dependency);
      continue;
    }

    if (
      Array.isArray(existing.parentChain) &&
      existing.parentChain.length === 0 &&
      Array.isArray(dependency.parentChain) &&
      dependency.parentChain.length > 0
    ) {
      const merged = {
        ...existing,
        parent: dependency.parent,
        parentChain: dependency.parentChain.slice(),
      };
      const index = unique.indexOf(existing);
      if (index !== -1) {
        unique[index] = merged;
      }
      seen.set(key, merged);
    }
  }

  return unique;
}

function buildTree(ecosystem, sourceFile, dependencies, warnings) {
  return {
    ecosystem,
    sourceFile,
    dependencies: deduplicateDeps(dependencies),
    warnings: Array.isArray(warnings) ? warnings.slice() : [],
  };
}

function stripTomlComment(line) {
  if (typeof line !== "string" || !line.includes("#")) {
    return line || "";
  }

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

function stripYamlComment(line) {
  if (typeof line !== "string" || !line.includes("#")) {
    return line || "";
  }

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

function countIndent(line) {
  if (typeof line !== "string") {
    return 0;
  }

  const firstNonWhitespace = line.search(/\S/);
  return firstNonWhitespace === -1 ? line.length : firstNonWhitespace;
}

function parseQuotedArray(rawValue) {
  const value = String(rawValue || "").trim();
  if (!value.startsWith("[") || !value.endsWith("]")) {
    return [];
  }

  const results = [];
  let current = "";
  let inSingleQuote = false;
  let inDoubleQuote = false;

  for (let index = 1; index < value.length - 1; index += 1) {
    const char = value[index];
    const previous = index > 0 ? value[index - 1] : "";

    if (char === "'" && !inDoubleQuote && previous !== "\\") {
      inSingleQuote = !inSingleQuote;
      current += char;
      continue;
    }
    if (char === "\"" && !inSingleQuote && previous !== "\\") {
      inDoubleQuote = !inDoubleQuote;
      current += char;
      continue;
    }

    if (char === "," && !inSingleQuote && !inDoubleQuote) {
      const cleaned = current.trim().replace(/^["']|["']$/g, "");
      if (cleaned) {
        results.push(cleaned);
      }
      current = "";
      continue;
    }

    current += char;
  }

  const cleaned = current.trim().replace(/^["']|["']$/g, "");
  if (cleaned) {
    results.push(cleaned);
  }

  return results;
}

function parseInlineTomlValue(block, key) {
  if (typeof block !== "string" || !block.includes("{")) {
    return "";
  }

  const expression = new RegExp(`${escapeRegExp(key)}\\s*=\\s*(\"([^\"]*)\"|'([^']*)'|([^,}]+))`);
  const match = block.match(expression);
  if (!match) {
    return "";
  }

  return (match[2] || match[3] || match[4] || "").trim();
}

function escapeRegExp(value) {
  return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function firstDefined(...values) {
  for (const value of values) {
    if (value != null && value !== "") {
      return value;
    }
  }
  return "";
}

function parseKeyValueLine(line) {
  if (typeof line !== "string" || !line.includes("=")) {
    return null;
  }

  const separatorIndex = line.indexOf("=");
  return {
    key: line.slice(0, separatorIndex).trim(),
    value: line.slice(separatorIndex + 1).trim(),
  };
}

module.exports = {
  LARGE_FILE_THRESHOLD_BYTES,
  buildTree,
  countIndent,
  createDependency,
  deduplicateDeps,
  dependencyKey,
  escapeRegExp,
  firstDefined,
  flattenDependencies,
  getSourceFileName,
  getWorkspacePath,
  normalizeVersion,
  parseInlineTomlValue,
  readJson,
  parseKeyValueLine,
  parseQuotedArray,
  pathExists,
  readUtf8,
  resolveWorkspaceFilePath,
  statSafe,
  stripTomlComment,
  stripYamlComment,
};

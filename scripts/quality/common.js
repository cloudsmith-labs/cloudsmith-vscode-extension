// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "../..");
const AUTOMATED_LAYERS = new Set(["unit", "contract", "extension-host", "black-box-ui"]);
const EXCLUDED_WALK_NAMES = new Set([".git", ".quality", ".stryker-tmp", ".vscode-test", "internal_docs", "node_modules"]);
let outputSequence = 0;

function readJson(relativePath, root = ROOT) {
  return JSON.parse(fs.readFileSync(resolveExistingRepositoryFile(relativePath, root), "utf8"));
}

function writeJson(relativePath, value, root = ROOT, options = {}) {
  return writeText(relativePath, `${JSON.stringify(value, null, 2)}\n`, root, options);
}

function writeText(relativePath, value, root = ROOT, options = {}) {
  return writeFile(relativePath, String(value), root, options);
}

function writeFile(relativePath, value, root = ROOT, options = {}) {
  const subtree = options.subtree || ".quality";
  const normalized = assertRepositoryRelativePath(relativePath, { subtree });
  const rootPath = assertRealRepositoryRoot(root);
  const parentRelative = path.posix.dirname(normalized);
  ensureRealRepositoryDirectory(rootPath, parentRelative, true);
  const target = path.join(rootPath, ...normalized.split("/"));
  assertWritableFinalPath(target);
  outputSequence += 1;
  const temporary = `${target}.tmp-${process.pid}-${outputSequence}`;
  let descriptor = null;
  try {
    const flags = fs.constants.O_WRONLY
      | fs.constants.O_CREAT
      | fs.constants.O_EXCL
      | (fs.constants.O_NOFOLLOW || 0);
    descriptor = fs.openSync(temporary, flags, 0o600);
    fs.writeFileSync(descriptor, value);
    fs.closeSync(descriptor);
    descriptor = null;
    ensureRealRepositoryDirectory(rootPath, parentRelative, false);
    assertWritableFinalPath(target);
    fs.renameSync(temporary, target);
    return target;
  } catch (error) {
    if (descriptor !== null) fs.closeSync(descriptor);
    fs.rmSync(temporary, { force: true });
    throw error;
  }
}

function prepareOutputDirectory(relativePath, root = ROOT, options = {}) {
  const subtree = options.subtree || ".quality";
  const normalized = assertRepositoryRelativePath(relativePath, { subtree });
  const rootPath = assertRealRepositoryRoot(root);
  return ensureRealRepositoryDirectory(rootPath, normalized, true);
}

function removeOutputFile(relativePath, root = ROOT, options = {}) {
  const subtree = options.subtree || ".quality";
  const normalized = assertRepositoryRelativePath(relativePath, { subtree });
  const rootPath = assertRealRepositoryRoot(root);
  const parentRelative = path.posix.dirname(normalized);
  const parent = path.join(rootPath, ...parentRelative.split("/"));
  if (!fs.existsSync(parent)) return false;
  ensureRealRepositoryDirectory(rootPath, parentRelative, false);
  const target = path.join(rootPath, ...normalized.split("/"));
  if (!fs.existsSync(target)) return false;
  const stat = fs.lstatSync(target);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error(`Quality output must be a real regular file: ${normalized}`);
  }
  fs.rmSync(target);
  return true;
}

function resolveExistingRepositoryFile(relativePath, root = ROOT, options = {}) {
  const normalized = assertRepositoryRelativePath(relativePath, options);
  const target = resolveOptionalRepositoryFile(normalized, root, options);
  if (!target) throw new Error(`Repository file is missing: ${normalized}`);
  return target;
}

function resolveOptionalRepositoryFile(relativePath, root = ROOT, options = {}) {
  const normalized = assertRepositoryRelativePath(relativePath, options);
  const rootPath = assertRealRepositoryRoot(root);
  try {
    ensureRealRepositoryDirectory(rootPath, path.posix.dirname(normalized), false);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
  const target = path.join(rootPath, ...normalized.split("/"));
  let stat;
  try {
    stat = fs.lstatSync(target);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error(`Repository file must be a real regular file: ${normalized}`);
  }
  const realTarget = fs.realpathSync(target);
  const prefix = `${rootPath}${path.sep}`;
  if (!realTarget.startsWith(prefix)) {
    throw new Error(`Repository file escaped its real root: ${normalized}`);
  }
  return target;
}

function discoverRepositoryOutputFiles(relativeDirectory, root = ROOT, options = {}) {
  const subtree = options.subtree || ".quality";
  const normalized = assertRepositoryRelativePath(relativeDirectory, { subtree });
  const rootPath = assertRealRepositoryRoot(root);
  let directory;
  try {
    directory = ensureRealRepositoryDirectory(rootPath, normalized, false);
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
  const files = [];
  const pending = [directory];
  let visited = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      visited += 1;
      if (visited > 5000) {
        throw new Error("Quality output discovery exceeded its structural bound.");
      }
      const target = path.join(current, entry.name);
      const stat = fs.lstatSync(target);
      if (stat.isSymbolicLink()) {
        throw new Error(`Quality output discovery rejects symbolic links: ${entry.name}`);
      }
      if (stat.isDirectory()) pending.push(target);
      else if (stat.isFile()) files.push(normalizePath(path.relative(rootPath, target)));
    }
  }
  return uniqueSorted(files);
}

function resolveGitVisibleRegularFile(relativePath, repositoryFiles, root = ROOT) {
  const normalized = assertRepositoryRelativePath(relativePath);
  const visible = repositoryFiles instanceof Set
    ? repositoryFiles
    : new Set(repositoryFiles || []);
  if (!visible.has(normalized)) {
    throw new Error(`Path is not a normalized Git-visible regular file: ${normalized}`);
  }
  try {
    return resolveExistingRepositoryFile(normalized, root);
  } catch {
    throw new Error(`Path is not a normalized Git-visible regular file: ${normalized}`);
  }
}

function assertRepositoryRelativePath(value, options = {}) {
  if (typeof value !== "string"
    || value.length === 0
    || value !== value.trim()
    || path.posix.isAbsolute(value)
    || path.win32.isAbsolute(value)
    || /^[A-Za-z]:/u.test(value)
    || /[\u0000-\u001f\u007f-\u009f\\]/u.test(value)
    || path.posix.normalize(value) !== value
    || value === "."
    || value.startsWith("../")
    || value.includes("/../")
    || value.includes("/./")
    || value.endsWith("/")) {
    throw new Error(`Repository path must be normalized and traversal-free: ${String(value)}`);
  }
  const subtree = options.subtree;
  if (subtree) {
    const normalizedSubtree = assertRepositoryRelativePath(subtree);
    if (value !== normalizedSubtree && !value.startsWith(`${normalizedSubtree}/`)) {
      throw new Error(`Repository path must remain within the ${normalizedSubtree} subtree: ${value}`);
    }
  }
  return value;
}

function assertRealRepositoryRoot(root) {
  const rootPath = path.resolve(root);
  const stat = fs.lstatSync(rootPath);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error("Quality operations require a real repository directory.");
  }
  return fs.realpathSync(rootPath);
}

function ensureRealRepositoryDirectory(rootPath, relativeDirectory, create) {
  if (relativeDirectory === "." || relativeDirectory === "") return rootPath;
  const normalized = assertRepositoryRelativePath(relativeDirectory);
  let current = rootPath;
  for (const segment of normalized.split("/")) {
    current = path.join(current, segment);
    let stat;
    try {
      stat = fs.lstatSync(current);
    } catch (error) {
      if (error.code !== "ENOENT" || !create) throw error;
      try {
        fs.mkdirSync(current, { mode: 0o700 });
      } catch (mkdirError) {
        if (mkdirError.code !== "EEXIST") throw mkdirError;
      }
      stat = fs.lstatSync(current);
    }
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new Error(`Quality path ancestry must use real repository directories: ${relativeDirectory}`);
    }
    const realCurrent = fs.realpathSync(current);
    if (realCurrent !== rootPath && !realCurrent.startsWith(`${rootPath}${path.sep}`)) {
      throw new Error(`Quality path ancestry escaped the real repository: ${relativeDirectory}`);
    }
  }
  return current;
}

function assertWritableFinalPath(target) {
  if (!fs.existsSync(target)) return;
  const stat = fs.lstatSync(target);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error("Quality output must be a real regular file.");
  }
}

function normalizePath(value) {
  return String(value).split(path.sep).join("/").replace(/^\.\//, "");
}

function patternToRegExp(pattern) {
  const normalized = normalizePath(pattern);
  let expression = "";
  for (let index = 0; index < normalized.length; index += 1) {
    const character = normalized[index];
    if (character === "*" && normalized[index + 1] === "*") {
      expression += ".*";
      index += 1;
    } else if (character === "*") {
      expression += "[^/]*";
    } else if (character === "?") {
      expression += "[^/]";
    } else {
      expression += character.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
    }
  }
  return new RegExp(`^${expression}$`);
}

function matchesPattern(file, pattern) {
  return patternToRegExp(pattern).test(normalizePath(file));
}

function walkFiles(root = ROOT, directory = root, state = { count: 0 }) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory() && EXCLUDED_WALK_NAMES.has(entry.name)) continue;
    state.count += 1;
    if (state.count > 20000) throw new Error("Quality file discovery exceeded its structural bound.");
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...walkFiles(root, absolute, state));
    else if (entry.isFile()) files.push(normalizePath(path.relative(root, absolute)));
  }
  return files.sort();
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function requireNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function testSourceContains(root, file, testName, sourceOverrides = {}) {
  const source = Object.prototype.hasOwnProperty.call(sourceOverrides, file)
    ? sourceOverrides[file]
    : fs.readFileSync(resolveExistingRepositoryFile(file, root), "utf8");
  const withoutComments = stripJavaScriptComments(source);
  const literals = [
    JSON.stringify(testName),
    `'${String(testName).replace(/\\/gu, "\\\\").replace(/'/gu, "\\'")}'`,
    `\`${String(testName).replace(/\\/gu, "\\\\").replace(/`/gu, "\\`")}\``,
  ];
  return literals.some(literal => (
    new RegExp(`(?:^|[^A-Za-z0-9_$])(?:test|it)\\s*\\(\\s*${escapeRegExp(literal)}`, "u")
      .test(withoutComments)
  ));
}

function stripJavaScriptComments(source) {
  return String(source)
    .replace(/\/\*[\s\S]*?\*\//gu, "")
    .replace(/(^|[^:\\])\/\/[^\r\n]*/gmu, "$1");
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function gitVisibleFiles(root = ROOT) {
  const result = spawnSync(
    "git",
    ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    { cwd: root, encoding: "utf8", maxBuffer: 20 * 1024 * 1024 }
  );
  if (result.error) throw result.error;
  if (result.signal || result.status !== 0) {
    throw new Error("Git file discovery failed for quality verification.");
  }
  return uniqueSorted(result.stdout.split("\0").filter(Boolean).map(normalizePath).filter(file => {
    const target = path.join(root, file);
    return fs.existsSync(target) && fs.lstatSync(target).isFile();
  }));
}

function summarizeMutationReport(report) {
  const mutants = [];
  for (const file of Object.values(report?.files || {})) {
    if (Array.isArray(file?.mutants)) mutants.push(...file.mutants);
  }
  const counts = {
    mutants: mutants.length,
    killed: 0,
    survived: 0,
    timeout: 0,
    noCoverage: 0,
    runtimeError: 0,
    compileError: 0,
    ignored: 0,
  };
  for (const mutant of mutants) {
    const key = {
      Killed: "killed",
      Survived: "survived",
      Timeout: "timeout",
      NoCoverage: "noCoverage",
      RuntimeError: "runtimeError",
      CompileError: "compileError",
      Ignored: "ignored",
    }[mutant.status];
    if (key) counts[key] += 1;
  }
  const scored = counts.killed + counts.survived + counts.timeout + counts.noCoverage;
  counts.score = scored === 0 ? null : Number(((counts.killed / scored) * 100).toFixed(2));
  return counts;
}

module.exports = {
  AUTOMATED_LAYERS,
  ROOT,
  assertRepositoryRelativePath,
  discoverRepositoryOutputFiles,
  prepareOutputDirectory,
  removeOutputFile,
  resolveExistingRepositoryFile,
  resolveOptionalRepositoryFile,
  resolveGitVisibleRegularFile,
  isPlainObject,
  gitVisibleFiles,
  matchesPattern,
  normalizePath,
  patternToRegExp,
  readJson,
  requireNonEmptyString,
  summarizeMutationReport,
  testSourceContains,
  stripJavaScriptComments,
  uniqueSorted,
  walkFiles,
  writeJson,
  writeFile,
  writeText,
};

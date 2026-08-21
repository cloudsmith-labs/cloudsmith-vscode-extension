// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const fs = require("fs");
const path = require("path");
const {
  DEPENDENCY_PACKAGE_SOURCE_KINDS,
  createDependencyPackageSource,
  createDependencyQualifiers,
} = require("../dependencyRecord");

const MAX_DEPENDENCY_FILE_BYTES = 50 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES = 50000;
const WORKSPACE_PATH_ERROR = "Refusing to read files outside the workspace folder.";
const DEPENDENCY_FILE_ERROR_CODES = Object.freeze({
  CHANGED: "ERR_DEPENDENCY_FILE_CHANGED",
  MISSING: "ERR_DEPENDENCY_FILE_MISSING",
  NOT_REGULAR: "ERR_DEPENDENCY_FILE_NOT_REGULAR",
  OUTSIDE_WORKSPACE: "ERR_DEPENDENCY_FILE_OUTSIDE_WORKSPACE",
  SYMLINK_ESCAPE: "ERR_DEPENDENCY_FILE_SYMLINK_ESCAPE",
  TOO_LARGE: "ERR_DEPENDENCY_FILE_TOO_LARGE",
  UNREADABLE: "ERR_DEPENDENCY_FILE_UNREADABLE",
});
const CASE_SENSITIVE_PACKAGE_NAME_ECOSYSTEMS = new Set(["go", "gradle", "maven"]);

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
    || (
      relativePath !== ".."
      && !relativePath.startsWith(`..${path.sep}`)
      && !path.isAbsolute(relativePath)
    );
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

async function resolveWorkspaceReadPath(targetPath, workspaceFolder) {
  const rawTargetPath = String(targetPath || "").trim();
  if (!rawTargetPath) {
    throw createDependencyFileError(
      DEPENDENCY_FILE_ERROR_CODES.OUTSIDE_WORKSPACE,
      WORKSPACE_PATH_ERROR
    );
  }

  const resolvedTargetPath = path.resolve(rawTargetPath);
  const candidateWorkspaceRoot = getCandidateWorkspaceRoot(resolvedTargetPath, workspaceFolder);
  if (!candidateWorkspaceRoot) {
    throw createDependencyFileError(
      DEPENDENCY_FILE_ERROR_CODES.OUTSIDE_WORKSPACE,
      WORKSPACE_PATH_ERROR
    );
  }

  const workspaceRoot = await resolveWorkspaceRoot(resolvedTargetPath, workspaceFolder);
  const isLexicallyContained = isWithinWorkspace(
    path.resolve(candidateWorkspaceRoot),
    resolvedTargetPath
  );
  const isCanonicalPathContained = isWithinWorkspace(workspaceRoot, resolvedTargetPath);
  let initialTargetStats;
  try {
    // Capture the identity before resolving the canonical pathname. Otherwise
    // a replacement performed immediately after realpath can become the
    // trusted baseline for the later open.
    initialTargetStats = await fs.promises.stat(resolvedTargetPath, { bigint: true });
  } catch (error) {
    if (!isLexicallyContained && !isCanonicalPathContained) {
      throw createDependencyFileError(
        DEPENDENCY_FILE_ERROR_CODES.OUTSIDE_WORKSPACE,
        WORKSPACE_PATH_ERROR,
        error
      );
    }
    throw createReadFileSystemError(error);
  }
  let realTargetPath;
  try {
    realTargetPath = await fs.promises.realpath(resolvedTargetPath);
  } catch (error) {
    if (!isLexicallyContained && !isCanonicalPathContained) {
      throw createDependencyFileError(
        DEPENDENCY_FILE_ERROR_CODES.OUTSIDE_WORKSPACE,
        WORKSPACE_PATH_ERROR,
        error
      );
    }
    throw createReadFileSystemError(error);
  }

  if (!isWithinWorkspace(workspaceRoot, realTargetPath)) {
    if (!isLexicallyContained && !isCanonicalPathContained) {
      throw createDependencyFileError(
        DEPENDENCY_FILE_ERROR_CODES.OUTSIDE_WORKSPACE,
        WORKSPACE_PATH_ERROR
      );
    }
    throw createDependencyFileError(
      DEPENDENCY_FILE_ERROR_CODES.SYMLINK_ESCAPE,
      "Dependency file symlink targets must stay within the workspace folder."
    );
  }

  let expectedStats;
  try {
    expectedStats = await fs.promises.lstat(realTargetPath, { bigint: true });
  } catch (error) {
    throw createReadFileSystemError(error);
  }
  if (expectedStats.isSymbolicLink()) {
    throw createDependencyFileChangedError();
  }
  if (!isSameFileIdentity(initialTargetStats, expectedStats)) {
    throw createDependencyFileChangedError();
  }

  return { safePath: realTargetPath, workspaceRoot, expectedStats };
}

async function readUtf8(targetPath, workspaceFolder, options = {}) {
  throwIfTraversalCancelled(options && options.cancellationToken);
  const {
    safePath,
    workspaceRoot,
    expectedStats,
  } = await resolveWorkspaceReadPath(targetPath, workspaceFolder);
  throwIfTraversalCancelled(options && options.cancellationToken);
  const noFollowFlag = Number.isInteger(fs.constants.O_NOFOLLOW)
    ? fs.constants.O_NOFOLLOW
    : 0;
  let fileHandle;
  try {
    fileHandle = await fs.promises.open(safePath, fs.constants.O_RDONLY | noFollowFlag);
  } catch (error) {
    if (error && error.code === "ELOOP") {
      throw createDependencyFileError(
        DEPENDENCY_FILE_ERROR_CODES.CHANGED,
        "Dependency file changed while it was being opened.",
        error
      );
    }
    throw createReadFileSystemError(error);
  }

  let result;
  let readError = null;
  try {
    const stats = await validateOpenedWorkspaceFile(
      fileHandle,
      safePath,
      workspaceRoot,
      expectedStats
    );
    if (!stats.isFile()) {
      throw createDependencyFileError(
        DEPENDENCY_FILE_ERROR_CODES.NOT_REGULAR,
        "Dependency paths must refer to regular files."
      );
    }
    if (stats.size > MAX_DEPENDENCY_FILE_BYTES) {
      throw createDependencyFileError(
        DEPENDENCY_FILE_ERROR_CODES.TOO_LARGE,
        "Dependency file exceeds the supported parsing size."
      );
    }

    result = await readFileHandleUtf8(
      fileHandle,
      options && options.cancellationToken
    );
    throwIfTraversalCancelled(options && options.cancellationToken);
  } catch (error) {
    readError = isDependencyFileError(error) || isTraversalCancellationError(error)
      ? error
      : createReadFileSystemError(error);
  }

  try {
    await fileHandle.close();
  } catch (error) {
    readError ||= createReadFileSystemError(error);
  }

  if (readError) {
    throw readError;
  }
  return result;
}

async function validateOpenedWorkspaceFile(
  fileHandle,
  safePath,
  workspaceRoot,
  expectedStats
) {
  const openedStats = await fileHandle.stat({ bigint: true });
  if (!isSameFileIdentity(expectedStats, openedStats)) {
    throw createDependencyFileChangedError();
  }
  let currentRealPath;
  let currentPathStats;
  try {
    currentRealPath = await fs.promises.realpath(safePath);
    if (!isWithinWorkspace(workspaceRoot, currentRealPath)) {
      throw createDependencyFileChangedError();
    }
    currentPathStats = await fs.promises.lstat(currentRealPath, { bigint: true });
  } catch (error) {
    if (isDependencyFileError(error)) {
      throw error;
    }
    throw createDependencyFileChangedError(error);
  }

  if (currentPathStats.isSymbolicLink() || !isSameFileIdentity(openedStats, currentPathStats)) {
    throw createDependencyFileChangedError();
  }

  return openedStats;
}

function isSameFileIdentity(left, right) {
  return left && right
    && left.dev === right.dev
    && left.ino === right.ino;
}

function createDependencyFileChangedError(cause) {
  return createDependencyFileError(
    DEPENDENCY_FILE_ERROR_CODES.CHANGED,
    "Dependency file changed while it was being opened.",
    cause
  );
}

async function readFileHandleUtf8(fileHandle, cancellationToken = null) {
  const chunks = [];
  let totalBytes = 0;

  while (totalBytes <= MAX_DEPENDENCY_FILE_BYTES) {
    throwIfTraversalCancelled(cancellationToken);
    const bytesRemaining = (MAX_DEPENDENCY_FILE_BYTES + 1) - totalBytes;
    const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, bytesRemaining));
    const { bytesRead } = await fileHandle.read(buffer, 0, buffer.length, null);
    throwIfTraversalCancelled(cancellationToken);
    if (bytesRead === 0) {
      return Buffer.concat(chunks, totalBytes).toString("utf8");
    }

    totalBytes += bytesRead;
    if (totalBytes > MAX_DEPENDENCY_FILE_BYTES) {
      throw createDependencyFileError(
        DEPENDENCY_FILE_ERROR_CODES.TOO_LARGE,
        "Dependency file exceeds the supported parsing size."
      );
    }
    chunks.push(buffer.subarray(0, bytesRead));
  }

  throw createDependencyFileError(
    DEPENDENCY_FILE_ERROR_CODES.TOO_LARGE,
    "Dependency file exceeds the supported parsing size."
  );
}

function createReadFileSystemError(error) {
  if (error && (error.code === "ENOENT" || error.code === "ENOTDIR")) {
    return createDependencyFileError(
      DEPENDENCY_FILE_ERROR_CODES.MISSING,
      "Dependency file does not exist.",
      error
    );
  }

  return createDependencyFileError(
    DEPENDENCY_FILE_ERROR_CODES.UNREADABLE,
    "Dependency file could not be read.",
    error
  );
}

function createDependencyFileError(code, message, cause) {
  const error = new Error(message);
  error.code = code;
  if (cause) {
    error.cause = cause;
  }
  return error;
}

function isDependencyFileError(error) {
  return Boolean(error && Object.values(DEPENDENCY_FILE_ERROR_CODES).includes(error.code));
}

function isTraversalCancellationError(error) {
  return Boolean(error && error.code === "ERR_DEPENDENCY_TRAVERSAL_CANCELLED");
}

async function readJson(targetPath, workspaceFolder, options = {}) {
  return JSON.parse(await readUtf8(targetPath, workspaceFolder, options));
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

async function readBoundedDirectoryEntries(
  directoryPath,
  maxEntries = MAX_DIRECTORY_ENTRIES,
  options = {}
) {
  throwIfTraversalCancelled(options && options.cancellationToken);
  const requestedLimit = Number.isInteger(maxEntries) && maxEntries > 0
    ? maxEntries
    : MAX_DIRECTORY_ENTRIES;
  const limit = Math.min(requestedLimit, MAX_DIRECTORY_ENTRIES);
  const workspaceFolder = options && options.workspaceFolder || directoryPath;
  const workspaceRoot = await resolveWorkspaceRoot(directoryPath, workspaceFolder);
  const requestedPath = path.resolve(String(directoryPath || ""));
  let expectedStats;
  let safePath;
  try {
    expectedStats = await fs.promises.stat(requestedPath, { bigint: true });
    safePath = await fs.promises.realpath(requestedPath);
  } catch (error) {
    throw createReadFileSystemError(error);
  }
  if (!expectedStats.isDirectory() || !isWithinWorkspace(workspaceRoot, safePath)) {
    throw createDependencyFileChangedError();
  }
  const noFollowFlag = Number.isInteger(fs.constants.O_NOFOLLOW)
    ? fs.constants.O_NOFOLLOW
    : 0;
  const directoryOnlyFlag = Number.isInteger(fs.constants.O_DIRECTORY)
    ? fs.constants.O_DIRECTORY
    : 0;
  let directoryHandle;
  let directory;
  try {
    directoryHandle = await fs.promises.open(
      safePath,
      fs.constants.O_RDONLY | noFollowFlag | directoryOnlyFlag
    );
    const openedStats = await directoryHandle.stat({ bigint: true });
    const currentRealPath = await fs.promises.realpath(safePath);
    const currentStats = await fs.promises.stat(currentRealPath, { bigint: true });
    if (
      !isWithinWorkspace(workspaceRoot, currentRealPath)
      || !openedStats.isDirectory()
      || !isSameFileIdentity(expectedStats, openedStats)
      || !isSameFileIdentity(openedStats, currentStats)
    ) {
      throw createDependencyFileChangedError();
    }
    directory = await fs.promises.opendir(safePath);
    const postOpenRealPath = await fs.promises.realpath(safePath);
    const postOpenStats = await fs.promises.stat(postOpenRealPath, { bigint: true });
    if (
      !isWithinWorkspace(workspaceRoot, postOpenRealPath)
      || !isSameFileIdentity(openedStats, postOpenStats)
    ) {
      throw createDependencyFileChangedError();
    }
  } catch (error) {
    if (directory) await directory.close().catch(() => {});
    if (directoryHandle) await directoryHandle.close().catch(() => {});
    throw isDependencyFileError(error) ? error : createReadFileSystemError(error);
  }
  const entries = [];
  let truncated = false;
  let enumerationError = null;
  try {
    for await (const entry of directory) {
      throwIfTraversalCancelled(options && options.cancellationToken);
      if (entries.length >= limit) {
        truncated = true;
        break;
      }
      entries.push(await validateBoundedDirectoryEntry(
        entry,
        safePath,
        workspaceRoot,
        expectedStats
      ));
    }
    throwIfTraversalCancelled(options && options.cancellationToken);
    const finalRealPath = await fs.promises.realpath(safePath);
    const finalStats = await fs.promises.stat(finalRealPath, { bigint: true });
    if (
      !isWithinWorkspace(workspaceRoot, finalRealPath)
      || !isSameFileIdentity(expectedStats, finalStats)
    ) {
      throw createDependencyFileChangedError();
    }
  } catch (error) {
    enumerationError = error;
  }
  try {
    await directoryHandle.close();
  } catch (error) {
    enumerationError ||= createReadFileSystemError(error);
  }
  if (enumerationError) throw enumerationError;

  return { entries, truncated };
}

async function validateBoundedDirectoryEntry(
  entry,
  safeDirectoryPath,
  workspaceRoot,
  expectedDirectoryStats
) {
  const name = entry && entry.name;
  if (
    typeof name !== "string"
    || !name
    || name === "."
    || name === ".."
    || path.basename(name) !== name
    || name.includes("/")
    || name.includes("\\")
  ) {
    throw createDependencyFileChangedError();
  }

  await validateCurrentDirectoryIdentity(
    safeDirectoryPath,
    workspaceRoot,
    expectedDirectoryStats
  );
  const childPath = path.join(safeDirectoryPath, name);
  const reportsFile = typeof entry.isFile === "function" && entry.isFile();
  const reportsDirectory = typeof entry.isDirectory === "function"
    && entry.isDirectory();
  const reportsSymlink = typeof entry.isSymbolicLink === "function"
    && entry.isSymbolicLink();

  // Symlink and special entries are never opened. Validate their type against
  // the current path and return a frozen snapshot so callers can skip them.
  // If an untrusted/replaced directory handle reports the wrong type, fail
  // closed instead of following or reclassifying the entry.
  if (reportsSymlink || (!reportsFile && !reportsDirectory)) {
    let currentChildStats;
    try {
      currentChildStats = await fs.promises.lstat(childPath, { bigint: true });
    } catch (error) {
      throw createDependencyFileChangedError(error);
    }
    if (!doesDirectoryEntryTypeMatchStats(entry, currentChildStats)) {
      throw createDependencyFileChangedError();
    }
    await validateCurrentDirectoryIdentity(
      safeDirectoryPath,
      workspaceRoot,
      expectedDirectoryStats
    );
    return createDirectoryEntrySnapshot(name, currentChildStats);
  }

  const noFollowFlag = Number.isInteger(fs.constants.O_NOFOLLOW)
    ? fs.constants.O_NOFOLLOW
    : 0;
  const nonBlockFlag = Number.isInteger(fs.constants.O_NONBLOCK)
    ? fs.constants.O_NONBLOCK
    : 0;
  const directoryOnlyFlag = reportsDirectory && Number.isInteger(fs.constants.O_DIRECTORY)
    ? fs.constants.O_DIRECTORY
    : 0;
  let childHandle;
  try {
    childHandle = await fs.promises.open(
      childPath,
      fs.constants.O_RDONLY | noFollowFlag | nonBlockFlag | directoryOnlyFlag
    );
    const openedChildStats = await childHandle.stat({ bigint: true });
    const currentChildStats = await fs.promises.lstat(childPath, { bigint: true });
    if (
      reportsFile === reportsDirectory
      || reportsFile !== openedChildStats.isFile()
      || reportsDirectory !== openedChildStats.isDirectory()
      || currentChildStats.isSymbolicLink()
      || !isSameFileIdentity(openedChildStats, currentChildStats)
    ) {
      throw createDependencyFileChangedError();
    }
    await validateCurrentDirectoryIdentity(
      safeDirectoryPath,
      workspaceRoot,
      expectedDirectoryStats
    );
    return createDirectoryEntrySnapshot(name, openedChildStats);
  } catch (error) {
    throw isDependencyFileError(error)
      ? error
      : createDependencyFileChangedError(error);
  } finally {
    if (childHandle) await childHandle.close().catch(() => {});
  }
}

function doesDirectoryEntryTypeMatchStats(entry, stats) {
  return [
    "isBlockDevice",
    "isCharacterDevice",
    "isDirectory",
    "isFIFO",
    "isFile",
    "isSocket",
    "isSymbolicLink",
  ].every((method) => (
    typeof entry[method] === "function"
    && entry[method]() === stats[method]()
  ));
}

async function validateCurrentDirectoryIdentity(safePath, workspaceRoot, expectedStats) {
  let currentRealPath;
  let currentStats;
  try {
    currentRealPath = await fs.promises.realpath(safePath);
    currentStats = await fs.promises.stat(currentRealPath, { bigint: true });
  } catch (error) {
    throw createDependencyFileChangedError(error);
  }
  if (
    !isWithinWorkspace(workspaceRoot, currentRealPath)
    || !currentStats.isDirectory()
    || !isSameFileIdentity(expectedStats, currentStats)
  ) {
    throw createDependencyFileChangedError();
  }
}

function createDirectoryEntrySnapshot(name, stats) {
  return Object.freeze({
    name,
    isBlockDevice: () => stats.isBlockDevice(),
    isCharacterDevice: () => stats.isCharacterDevice(),
    isDirectory: () => stats.isDirectory(),
    isFIFO: () => stats.isFIFO(),
    isFile: () => stats.isFile(),
    isSocket: () => stats.isSocket(),
    isSymbolicLink: () => stats.isSymbolicLink(),
  });
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
  qualifiers,
  packageSource,
  repository,
  alias,
  service,
  pullPolicy,
  tag,
  digest,
  stage,
  platform,
  targetFramework,
  environment,
  section,
  scope,
  type,
  classifier,
  configurations,
  sourceKind,
  sourceLocation,
  sourceBranch,
  sourceRevision,
}) {
  const canonicalQualifiers = createDependencyQualifiers(qualifiers || {});
  const compatibilityQualifiers = {
    ...canonicalQualifiers,
    ...optionalQualifierValues({
      repository,
      alias,
      service,
      pullPolicy,
      tag,
      digest,
      stage,
      platform,
      targetFramework,
      environment,
      section,
      scope,
      type,
      classifier,
      configurations,
    }),
  };
  const normalizedQualifiers = createDependencyQualifiers(compatibilityQualifiers);
  const normalizedPackageSource = createDependencyPackageSource(packageSource || {
    kind: sourceKind || DEPENDENCY_PACKAGE_SOURCE_KINDS.REGISTRY,
    ...(sourceLocation ? { location: sourceLocation } : {}),
    ...(sourceBranch ? { branch: sourceBranch } : {}),
    ...(sourceRevision ? { revision: sourceRevision } : {}),
  });
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
    qualifiers: normalizedQualifiers,
    packageSource: normalizedPackageSource,
  };
}

function optionalQualifierValues(values) {
  return Object.fromEntries(Object.entries(values).filter(([, value]) => value != null));
}

function flattenDependencies(dependencies, options = {}) {
  const flattened = [];
  const stack = (Array.isArray(dependencies) ? dependencies : []).slice().reverse();
  const cancellationToken = options && options.cancellationToken || null;
  while (stack.length > 0) {
    if (cancellationToken && cancellationToken.isCancellationRequested) {
      throwIfTraversalCancelled(cancellationToken);
    }
    if (flattened.length >= MAX_DIRECTORY_ENTRIES) {
      throw new Error("Dependency traversal exceeded the supported occurrence limit.");
    }
    const dependency = stack.pop();
    if (!dependency || typeof dependency !== "object" || Array.isArray(dependency)) {
      continue;
    }
    flattened.push(dependency);
    if (Array.isArray(dependency.transitives) && dependency.transitives.length > 0) {
      for (let index = dependency.transitives.length - 1; index >= 0; index -= 1) {
        stack.push(dependency.transitives[index]);
      }
    }
  }
  return flattened;
}

function throwIfTraversalCancelled(cancellationToken) {
  if (cancellationToken && cancellationToken.isCancellationRequested) {
    const error = new Error("Dependency traversal was cancelled.");
    error.code = "ERR_DEPENDENCY_TRAVERSAL_CANCELLED";
    throw error;
  }
}

function dependencyKey(dependency) {
  const ecosystem = String(dependency.ecosystem || "").trim().toLowerCase();
  const packageName = String(dependency.name || "").trim();
  const qualifiers = dependency && dependency.qualifiers || {};
  const artifactQualifiers = {};
  if (ecosystem === "ruby" && qualifiers.platform) {
    artifactQualifiers.platform = qualifiers.platform;
  }
  if (ecosystem === "nuget" && qualifiers.targetFramework) {
    artifactQualifiers.targetFramework = qualifiers.targetFramework;
  }
  if (["maven", "gradle"].includes(ecosystem)) {
    if (qualifiers.type) artifactQualifiers.type = qualifiers.type;
    if (qualifiers.classifier) artifactQualifiers.classifier = qualifiers.classifier;
  }
  if (ecosystem === "docker") {
    if (qualifiers.tag) artifactQualifiers.tag = qualifiers.tag;
    if (qualifiers.digest) artifactQualifiers.digest = qualifiers.digest;
    if (qualifiers.platform) artifactQualifiers.platform = qualifiers.platform;
    if (qualifiers.service) artifactQualifiers.service = qualifiers.service;
    if (qualifiers.stage) artifactQualifiers.stage = qualifiers.stage;
    if (qualifiers.pullPolicy) artifactQualifiers.pullPolicy = qualifiers.pullPolicy;
  }
  return JSON.stringify([
    ecosystem,
    CASE_SENSITIVE_PACKAGE_NAME_ECOSYSTEMS.has(ecosystem)
      ? packageName
      : packageName.toLowerCase(),
    String(dependency.version || "").trim(),
    artifactQualifiers,
    dependency.packageSource && dependency.packageSource.kind || null,
  ]);
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
      !existing.isDirect &&
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
  DEPENDENCY_FILE_ERROR_CODES,
  LARGE_FILE_THRESHOLD_BYTES: MAX_DEPENDENCY_FILE_BYTES,
  MAX_DEPENDENCY_FILE_BYTES,
  MAX_DIRECTORY_ENTRIES,
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
  readBoundedDirectoryEntries,
  parseKeyValueLine,
  parseQuotedArray,
  pathExists,
  readUtf8,
  resolveWorkspaceFilePath,
  statSafe,
  stripTomlComment,
  stripYamlComment,
  throwIfTraversalCancelled,
};

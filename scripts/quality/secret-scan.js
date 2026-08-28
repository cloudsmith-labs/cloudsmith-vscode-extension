// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { types: utilTypes } = require("util");
const { spawnSync } = require("child_process");
const yauzl = require("yauzl");
const {
  UI_CANDIDATE_ARTIFACT,
  UI_CANDIDATE_RECEIPT,
  candidateBindingFromReceipt,
  digestStableSingleLinkFile,
  exactFileIdentity,
  readStableSingleLinkFile,
  sameExactFileIdentity,
  withStableSingleLinkFile,
} = require("./candidate-binding");
const {
  ROOT,
  assertRealRepositoryRoot,
  assertRepositoryRelativePath,
  normalizePath,
  removeOutputFile,
  resolveExistingRepositoryFile,
  writeJson,
} = require("./common");
const { fingerprint, sourceIdentity } = require("./evidence");
const { removeExactOwnedDirectoryTree } = require("./non-auth-environment");

const INTRINSIC_ARRAY_IS_ARRAY = Array.isArray;
const INTRINSIC_ARRAY_ITERATOR = Array.prototype[Symbol.iterator];
const INTRINSIC_ARRAY_PROTOTYPE = Array.prototype;
const INTRINSIC_ARRAY_SORT = Array.prototype.sort;
const INTRINSIC_BIGINT = BigInt;
const INTRINSIC_BUFFER = Buffer;
const INTRINSIC_BUFFER_ALLOC_UNSAFE = Buffer.allocUnsafe;
const INTRINSIC_BUFFER_FROM = Buffer.from;
const INTRINSIC_BUFFER_IS_BUFFER = Buffer.isBuffer;
const INTRINSIC_GET_OWN_PROPERTY_DESCRIPTOR = Object.getOwnPropertyDescriptor;
const INTRINSIC_GET_PROTOTYPE_OF = Object.getPrototypeOf;
const INTRINSIC_HAS_OWN = Object.prototype.hasOwnProperty;
const INTRINSIC_IS_FROZEN = Object.isFrozen;
const INTRINSIC_IS_PROXY = utilTypes.isProxy;
const INTRINSIC_NUMBER = Number;
const INTRINSIC_NUMBER_IS_SAFE_INTEGER = Number.isSafeInteger;
const INTRINSIC_OBJECT_FREEZE = Object.freeze;
const INTRINSIC_OBJECT_PROTOTYPE = Object.prototype;
const INTRINSIC_REGEXP_TEST = RegExp.prototype.test;
const INTRINSIC_REFLECT_APPLY = Reflect.apply;
const INTRINSIC_REFLECT_OWN_KEYS = Reflect.ownKeys;
const INTRINSIC_PATH_JOIN = path.join;
const INTRINSIC_STRING_SPLIT = String.prototype.split;
const INTRINSIC_SYMBOL_ITERATOR = Symbol.iterator;
const INTRINSIC_UINT8_ARRAY_FILL = Uint8Array.prototype.fill;
const TRACKED_READ_FLAGS = fs.constants.O_RDONLY
  | (fs.constants.O_NOFOLLOW || 0)
  | (fs.constants.O_NONBLOCK || 0);

function hasOwnDataValue(object, key) {
  const descriptor = INTRINSIC_GET_OWN_PROPERTY_DESCRIPTOR(object, key);
  return descriptor
    && INTRINSIC_REFLECT_APPLY(INTRINSIC_HAS_OWN, descriptor, ["value"])
    ? descriptor
    : null;
}

const GITLEAKS_VERSION = "8.30.1";
const REPORT_TEMPLATE = "scripts/quality/gitleaks-report.tmpl";
const CONFIG_PATH = ".gitleaks.toml";
const OUTPUT_ROOT = ".quality/secrets";
const SAFE_REPORT_KEYS = Object.freeze(["commit", "endLine", "file", "ruleId", "startLine"]);
const FORBIDDEN_REPORT_FIELDS = /"(?:Secret|Match|Fingerprint|Entropy|Author|Email|Message)"\s*:/u;
const SAFE_ENVIRONMENT_NAMES = Object.freeze([
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "WINDIR",
  "COMSPEC",
  "TMPDIR",
  "TMP",
  "TEMP",
  "USER",
  "LOGNAME",
  "USERNAME",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "NO_COLOR",
]);
const MAX_TRACKED_FILES = 30000;
const MAX_GENERATED_FILES = 10000;
const MAX_GENERATED_FILE_BYTES = 64 * 1024 * 1024;
const MAX_TRACKED_FILE_BYTES = MAX_GENERATED_FILE_BYTES;
const MAX_TRACKED_TOTAL_BYTES = 256 * 1024 * 1024;
const MAX_VSIX_ENTRIES = 10000;
const MAX_VSIX_ENTRY_BYTES = 50 * 1024 * 1024;
const MAX_VSIX_TOTAL_BYTES = 500 * 1024 * 1024;
const MAX_UI_CANDIDATE_RECEIPT_BYTES = 2 * 1024 * 1024;
const MAX_UI_CANDIDATE_VSIX_BYTES = 12 * 1024 * 1024;
const MAX_UI_RESULT_BYTES = 2 * 1024 * 1024;
const MAX_SIGNED_OUT_EVIDENCE_BYTES = 2 * 1024 * 1024;
const MAX_SAFE_REPORT_BYTES = 2 * 1024 * 1024;
const SCANNER_PROCESS_TIMEOUT_MS = 60 * 1000;
const TRACKED_FINDING_KEYS = Object.freeze([
  "commit",
  "endLine",
  "path",
  "ruleId",
  "startLine",
]);
const UI_RESULT = ".quality/ui/result.json";
const TRACKED_SOURCE_ERROR =
  "Tracked-file source changed or became unsafe during in-memory capture.";
const SIGNED_OUT_BUNDLE_DIRECTORY = ".quality/upload/signed-out-ui";
const SIGNED_OUT_BUNDLE_RECEIPT = "evidence.json";
const SIGNED_OUT_BUNDLE_INPUTS = Object.freeze([
  Object.freeze({
    name: path.basename(UI_CANDIDATE_RECEIPT),
    role: "candidate-receipt",
    relativePath: UI_CANDIDATE_RECEIPT,
  }),
  Object.freeze({
    name: path.basename(UI_CANDIDATE_ARTIFACT),
    role: "candidate-vsix",
    relativePath: UI_CANDIDATE_ARTIFACT,
  }),
  Object.freeze({
    name: path.basename(UI_RESULT),
    role: "signed-out-ui-result",
    relativePath: UI_RESULT,
  }),
]);
const SIGNED_OUT_BUNDLE_NAMES = Object.freeze([
  ...SIGNED_OUT_BUNDLE_INPUTS.map(entry => entry.name),
  SIGNED_OUT_BUNDLE_RECEIPT,
].sort());
const UI_CANDIDATE_SCAN_EXCLUSIONS = Object.freeze([
  OUTPUT_ROOT,
  SIGNED_OUT_BUNDLE_DIRECTORY,
  UI_CANDIDATE_RECEIPT,
  UI_CANDIDATE_ARTIFACT,
]);
const SIGNED_OUT_UI_SCAN_EXCLUSIONS = Object.freeze([
  ...UI_CANDIDATE_SCAN_EXCLUSIONS,
  UI_RESULT,
]);
const temporaryRootOwnership = new Map();

function parseArguments(argv) {
  const args = [...argv];
  const mode = args.shift() || "current";
  if (!new Set(["current", "history", "artifacts", "evidence", "all"]).has(mode)) {
    throw new Error("Secret scan mode must be current, history, artifacts, evidence, or all.");
  }
  let includeLocalEvidence = false;
  let signedOutBundle = false;
  for (const argument of args) {
    if (argument === "--include-local-evidence") includeLocalEvidence = true;
    else if (argument === "--signed-out-bundle") signedOutBundle = true;
    else throw new Error(`Unknown secret scan argument: ${argument}`);
  }
  if (includeLocalEvidence && !new Set(["current", "all"]).has(mode)) {
    throw new Error("Local evidence may only be added to current or all scans.");
  }
  if (signedOutBundle && mode !== "evidence") {
    throw new Error("The signed-out upload bundle may only be produced by an evidence scan.");
  }
  return { mode, includeLocalEvidence, signedOutBundle };
}

function scannerEnvironment(environment = process.env) {
  return Object.fromEntries(
    SAFE_ENVIRONMENT_NAMES
      .filter(name => typeof environment[name] === "string")
      .map(name => [name, environment[name]])
  );
}

function privateScannerEnvironment(environment, scannerHome) {
  const home = fs.realpathSync(scannerHome);
  const stat = fs.lstatSync(home);
  if (stat.isSymbolicLink() || !stat.isDirectory()
    || (process.platform !== "win32" && (stat.mode & 0o077) !== 0)) {
    throw new Error("Secret scanner HOME must be a private real directory.");
  }
  const directories = {
    XDG_CONFIG_HOME: path.join(home, "config"),
    XDG_CACHE_HOME: path.join(home, "cache"),
    XDG_DATA_HOME: path.join(home, "data"),
    XDG_STATE_HOME: path.join(home, "state"),
    TMPDIR: path.join(home, "tmp"),
  };
  for (const directory of Object.values(directories)) {
    fs.mkdirSync(directory, { mode: 0o700 });
    if (process.platform !== "win32") fs.chmodSync(directory, 0o700);
  }
  return Object.freeze({
    ...scannerEnvironment(environment),
    HOME: home,
    USERPROFILE: home,
    ...directories,
    TMP: directories.TMPDIR,
    TEMP: directories.TMPDIR,
    APPDATA: directories.XDG_CONFIG_HOME,
    LOCALAPPDATA: directories.XDG_DATA_HOME,
  });
}

function run(executable, args, options = {}) {
  const timeout = options.timeoutMilliseconds === undefined
    ? SCANNER_PROCESS_TIMEOUT_MS
    : options.timeoutMilliseconds;
  if (!Number.isSafeInteger(timeout) || timeout <= 0
    || timeout > SCANNER_PROCESS_TIMEOUT_MS) {
    throw new Error("Secret scanner process timeout is invalid.");
  }
  const result = spawnSync(executable, args, {
    cwd: options.cwd || ROOT,
    encoding: "utf8",
    env: options.env || scannerEnvironment(),
    input: options.input,
    maxBuffer: 2 * 1024 * 1024,
    stdio: "pipe",
    timeout,
    killSignal: "SIGKILL",
  });
  return result;
}

function assertScannerVersion(options = {}) {
  const execute = options.execute || run;
  const scannerHome = temporaryRoot("cloudsmith-gitleaks-home-");
  try {
    const result = execute("gitleaks", ["version"], {
      cwd: options.root || ROOT,
      env: privateScannerEnvironment(options.environment, scannerHome),
    });
    if (result.error || result.signal || result.status !== 0) {
      throw new Error(`Gitleaks ${GITLEAKS_VERSION} is required; install the pinned scanner before qualification.`);
    }
    if (String(result.stdout || "").trim() !== GITLEAKS_VERSION) {
      throw new Error(`Gitleaks version mismatch; expected ${GITLEAKS_VERSION}.`);
    }
    return GITLEAKS_VERSION;
  } finally {
    removePrivateSnapshotRoot(
      scannerHome,
      temporaryRootOwnership.get(scannerHome),
      "Gitleaks version-check cleanup refused an unsafe or changed root.",
    );
  }
}

function gitOutput(args, options = {}) {
  const execute = options.executeGit || run;
  const scannerHome = temporaryRoot("cloudsmith-secret-git-home-");
  try {
    const result = execute("git", args, {
      cwd: options.root || ROOT,
      env: privateScannerEnvironment(options.environment, scannerHome),
    });
    if (!result || typeof result !== "object" || INTRINSIC_IS_PROXY(result)
      || INTRINSIC_GET_PROTOTYPE_OF(result) !== INTRINSIC_OBJECT_PROTOTYPE) {
      throw new Error("Git metadata required by the secret gate was unavailable.");
    }
    const error = hasOwnDataValue(result, "error");
    const hasError = INTRINSIC_REFLECT_APPLY(INTRINSIC_HAS_OWN, result, ["error"]);
    const signal = hasOwnDataValue(result, "signal");
    const status = hasOwnDataValue(result, "status");
    const stdout = hasOwnDataValue(result, "stdout");
    if ((hasError && (!error || (error.value !== null && error.value !== undefined)))
      || !signal || signal.value
      || !status || status.value !== 0
      || !stdout || typeof stdout.value !== "string") {
      throw new Error("Git metadata required by the secret gate was unavailable.");
    }
    return stdout.value;
  } finally {
    removePrivateSnapshotRoot(
      scannerHome,
      temporaryRootOwnership.get(scannerHome),
      "Secret-scan Git metadata cleanup refused an unsafe or changed root.",
    );
  }
}

function currentHead(root = ROOT, options = {}) {
  const value = gitOutput(["rev-parse", "--verify", "HEAD^{commit}"], {
    ...options,
    root,
  }).trim();
  if (!/^[0-9a-f]{40}$/u.test(value)) {
    throw new Error("Secret gate could not resolve an exact source commit.");
  }
  return value;
}

function trackedFiles(root = ROOT, options = {}) {
  const output = gitOutput([
    "ls-files",
    "-z",
    "--cached",
    "--others",
    "--exclude-standard",
  ], { ...options, root });
  const fields = INTRINSIC_REFLECT_APPLY(INTRINSIC_STRING_SPLIT, output, ["\0"]);
  const files = [];
  for (let index = 0; index < fields.length; index += 1) {
    if (fields[index] !== "") files[files.length] = normalizePath(fields[index]);
  }
  if (files.length === 0 || files.length > MAX_TRACKED_FILES) {
    throw new Error("Tracked-file secret scan inventory is empty or exceeds its safety bound.");
  }
  const unique = new Set();
  for (let index = 0; index < files.length; index += 1) {
    const file = files[index];
    assertRepositoryRelativePath(file);
    if (unique.has(file)) throw new Error(`Tracked-file inventory contains a duplicate path: ${file}`);
    unique.add(file);
  }
  INTRINSIC_REFLECT_APPLY(INTRINSIC_ARRAY_SORT, files, []);
  return INTRINSIC_OBJECT_FREEZE(files);
}

function ensureSnapshotDirectory(snapshotRoot, relativeDirectory) {
  if (relativeDirectory === "." || relativeDirectory === "") return snapshotRoot;
  let current = snapshotRoot;
  for (const segment of relativeDirectory.split("/")) {
    current = path.join(current, segment);
    if (!fs.existsSync(current)) fs.mkdirSync(current, { mode: 0o700 });
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new Error("Secret scan snapshot ancestry must use real directories.");
    }
  }
  return current;
}

function canonicalInjectedTrackedFiles(value) {
  const errorMessage = "Injected tracked-file inventory must be a plain frozen dense array.";
  try {
    if (!INTRINSIC_REFLECT_APPLY(INTRINSIC_ARRAY_IS_ARRAY, Array, [value])
      || INTRINSIC_IS_PROXY(value)
      || !INTRINSIC_IS_FROZEN(value)
      || INTRINSIC_GET_PROTOTYPE_OF(value) !== INTRINSIC_ARRAY_PROTOTYPE) {
      throw new Error(errorMessage);
    }
    const iterator = hasOwnDataValue(
      INTRINSIC_ARRAY_PROTOTYPE,
      INTRINSIC_SYMBOL_ITERATOR,
    );
    const length = hasOwnDataValue(value, "length");
    if (!iterator || iterator.value !== INTRINSIC_ARRAY_ITERATOR
      || !length || !INTRINSIC_NUMBER_IS_SAFE_INTEGER(length.value)
      || length.value <= 0 || length.value > MAX_TRACKED_FILES) {
      throw new Error(errorMessage);
    }
    const keys = INTRINSIC_REFLECT_OWN_KEYS(value);
    if (keys.length !== length.value + 1) throw new Error(errorMessage);
    const canonical = [];
    for (let index = 0; index < length.value; index += 1) {
      const descriptor = hasOwnDataValue(value, `${index}`);
      if (!descriptor || typeof descriptor.value !== "string"
        || descriptor.enumerable !== true
        || descriptor.configurable !== false
        || descriptor.writable !== false) {
        throw new Error(errorMessage);
      }
      canonical[index] = descriptor.value;
    }
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      if (typeof key !== "string"
        || (key !== "length"
          && (!INTRINSIC_REFLECT_APPLY(
            INTRINSIC_REGEXP_TEST,
            /^(?:0|[1-9]\d*)$/u,
            [key],
          )
            || INTRINSIC_REFLECT_APPLY(INTRINSIC_NUMBER, null, [key])
              >= length.value))) {
        throw new Error(errorMessage);
      }
    }
    return INTRINSIC_OBJECT_FREEZE(canonical);
  } catch {
    throw new Error(errorMessage);
  }
}

function trackedSourcePath(root, relativePath) {
  const segments = INTRINSIC_REFLECT_APPLY(
    INTRINSIC_STRING_SPLIT,
    relativePath,
    ["/"],
  );
  const joinArguments = [root];
  for (let index = 0; index < segments.length; index += 1) {
    joinArguments[index + 1] = segments[index];
  }
  return INTRINSIC_REFLECT_APPLY(INTRINSIC_PATH_JOIN, path, joinArguments);
}

function intrinsicBuffer(value) {
  return INTRINSIC_REFLECT_APPLY(INTRINSIC_BUFFER_IS_BUFFER, INTRINSIC_BUFFER, [value]);
}

function wipeTrackedBuffer(value) {
  if (!intrinsicBuffer(value)) return false;
  INTRINSIC_REFLECT_APPLY(INTRINSIC_UINT8_ARRAY_FILL, value, [0]);
  return true;
}

function exactTrackedBufferCopy(value) {
  return INTRINSIC_REFLECT_APPLY(INTRINSIC_BUFFER_FROM, INTRINSIC_BUFFER, [value]);
}

function trackedReadBuffer(size) {
  return INTRINSIC_REFLECT_APPLY(
    INTRINSIC_BUFFER_ALLOC_UNSAFE,
    INTRINSIC_BUFFER,
    [size],
  );
}

function sameTrackedFilesystemPath(left, right) {
  const normalizedLeft = path.normalize(left);
  const normalizedRight = path.normalize(right);
  return process.platform === "win32"
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight;
}

function assertTrackedSourceStat(stat) {
  const one = typeof stat.nlink === "bigint" ? 1n : 1;
  const size = typeof stat.size === "bigint"
    ? stat.size
    : INTRINSIC_REFLECT_APPLY(INTRINSIC_BIGINT, null, [stat.size]);
  if (!stat.isFile() || stat.nlink !== one || size < 0n
    || size > INTRINSIC_REFLECT_APPLY(INTRINSIC_BIGINT, null, [MAX_TRACKED_FILE_BYTES])) {
    throw new Error(TRACKED_SOURCE_ERROR);
  }
  return stat;
}

function assertStableTrackedOpenFile(file, descriptor, identity, fileSystem) {
  const descriptorStat = assertTrackedSourceStat(
    fileSystem.fstatSync(descriptor, { bigint: true }),
  );
  const pathStat = assertTrackedSourceStat(fileSystem.lstatSync(file, { bigint: true }));
  if (pathStat.isSymbolicLink()
    || !sameTrackedFilesystemPath(fileSystem.realpathSync(file), file)
    || !sameExactFileIdentity(identity, exactFileIdentity(descriptorStat))
    || !sameExactFileIdentity(identity, exactFileIdentity(pathStat))) {
    throw new Error(TRACKED_SOURCE_ERROR);
  }
  return true;
}

function withStableTrackedSource(file, options, consume) {
  const fileSystem = options.fileSystem || fs;
  let bytes;
  let completed = false;
  let descriptor;
  let result;
  try {
    const pathStat = assertTrackedSourceStat(
      fileSystem.lstatSync(file, { bigint: true }),
    );
    if (pathStat.isSymbolicLink()
      || !sameTrackedFilesystemPath(fileSystem.realpathSync(file), file)) {
      throw new Error(TRACKED_SOURCE_ERROR);
    }
    const identity = exactFileIdentity(pathStat);
    if (options.expectedIdentity
      && !sameExactFileIdentity(options.expectedIdentity, identity)) {
      throw new Error(TRACKED_SOURCE_ERROR);
    }
    descriptor = fileSystem.openSync(file, TRACKED_READ_FLAGS);
    const openedStat = assertTrackedSourceStat(
      fileSystem.fstatSync(descriptor, { bigint: true }),
    );
    if (!sameExactFileIdentity(identity, exactFileIdentity(openedStat))) {
      throw new Error(TRACKED_SOURCE_ERROR);
    }
    const openedBytes = INTRINSIC_REFLECT_APPLY(
      INTRINSIC_NUMBER,
      null,
      [openedStat.size],
    );
    bytes = trackedReadBuffer(openedBytes);
    let offset = 0;
    while (offset < openedBytes) {
      const bytesRead = fileSystem.readSync(
        descriptor,
        bytes,
        offset,
        openedBytes - offset,
        offset,
      );
      if (!INTRINSIC_NUMBER_IS_SAFE_INTEGER(bytesRead) || bytesRead <= 0
        || bytesRead > openedBytes - offset) {
        throw new Error(TRACKED_SOURCE_ERROR);
      }
      offset += bytesRead;
    }
    assertStableTrackedOpenFile(file, descriptor, identity, fileSystem);
    result = consume(bytes, identity);
    if (result && typeof result.then === "function") {
      throw new Error(TRACKED_SOURCE_ERROR);
    }
    assertStableTrackedOpenFile(file, descriptor, identity, fileSystem);
    completed = true;
  } catch {
    completed = false;
  } finally {
    wipeTrackedBuffer(bytes);
    if (descriptor !== undefined) {
      try {
        fileSystem.closeSync(descriptor);
      } catch {
        completed = false;
      }
    }
  }
  if (!completed) throw new Error(TRACKED_SOURCE_ERROR);
  return result;
}

function clearTrackedSourceBuffers(inventory) {
  if (!inventory || !INTRINSIC_REFLECT_APPLY(
    INTRINSIC_ARRAY_IS_ARRAY,
    Array,
    [inventory.sources],
  )) return;
  for (let index = 0; index < inventory.sources.length; index += 1) {
    wipeTrackedBuffer(inventory.sources[index].bytes);
  }
}

function captureTrackedSources(root, options = {}) {
  const injectedDescriptor = hasOwnDataValue(options, "files");
  const hasInjectedProperty = INTRINSIC_REFLECT_APPLY(
    INTRINSIC_HAS_OWN,
    options,
    ["files"],
  );
  if (hasInjectedProperty && !injectedDescriptor) {
    throw new Error("Injected tracked-file inventory must be a plain frozen dense array.");
  }
  const injectedFiles = Boolean(injectedDescriptor);
  const files = injectedFiles
    ? canonicalInjectedTrackedFiles(injectedDescriptor.value)
    : trackedFiles(root, options);
  const fileSystem = options.fileSystem || fs;
  if (!INTRINSIC_REFLECT_APPLY(INTRINSIC_ARRAY_IS_ARRAY, Array, [files])
    || files.length === 0 || files.length > MAX_TRACKED_FILES) {
    throw new Error("Tracked-file secret scan inventory is empty or exceeds its safety bound.");
  }
  const deleted = [];
  const sources = [];
  const unique = new Set();
  let totalCapturedBytes = 0n;
  try {
    for (let index = 0; index < files.length; index += 1) {
      const file = files[index];
      assertRepositoryRelativePath(file);
      if (unique.has(file)) {
        throw new Error(`Tracked-file inventory contains a duplicate path: ${file}`);
      }
      unique.add(file);
      const source = trackedSourcePath(root, file);
      let sourceStat;
      try {
        sourceStat = fileSystem.lstatSync(source, { bigint: true });
      } catch (error) {
        if (error?.code !== "ENOENT") throw new Error(TRACKED_SOURCE_ERROR);
        deleted[deleted.length] = file;
        continue;
      }
      const sourceBytes = INTRINSIC_REFLECT_APPLY(
        INTRINSIC_BIGINT,
        null,
        [sourceStat.size],
      );
      if (sourceBytes < 0n
        || sourceBytes > INTRINSIC_REFLECT_APPLY(
          INTRINSIC_BIGINT,
          null,
          [MAX_TRACKED_FILE_BYTES],
        )
        || totalCapturedBytes + sourceBytes > INTRINSIC_REFLECT_APPLY(
          INTRINSIC_BIGINT,
          null,
          [MAX_TRACKED_TOTAL_BYTES],
        )) {
        throw new Error(TRACKED_SOURCE_ERROR);
      }
      const captured = withStableTrackedSource(source, {
        expectedIdentity: exactFileIdentity(sourceStat),
        fileSystem,
      }, (bytes, identity) => ({ bytes: exactTrackedBufferCopy(bytes), identity }));
      totalCapturedBytes += INTRINSIC_REFLECT_APPLY(
        INTRINSIC_BIGINT,
        null,
        [captured.bytes.length],
      );
      sources[sources.length] = INTRINSIC_OBJECT_FREEZE({
        bytes: captured.bytes,
        identity: captured.identity,
        path: file,
      });
    }
    if (sources.length === 0) {
      throw new Error("Tracked-file secret scan capture contains no files.");
    }
    return INTRINSIC_OBJECT_FREEZE({
      deleted: INTRINSIC_OBJECT_FREEZE(deleted),
      files,
      injectedFiles,
      sources: INTRINSIC_OBJECT_FREEZE(sources),
    });
  } catch (error) {
    clearTrackedSourceBuffers({ sources });
    throw error;
  }
}

function sameTrackedInventory(left, right) {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function assertStableTrackedInventory(root, inventory, options = {}) {
  if (inventory.injectedFiles) return true;
  let current;
  try {
    current = trackedFiles(root, options);
  } catch {
    throw new Error(TRACKED_SOURCE_ERROR);
  }
  if (!sameTrackedInventory(current, inventory.files)) {
    throw new Error(TRACKED_SOURCE_ERROR);
  }
  return true;
}

function assertStableTrackedSource(root, entry, options = {}) {
  const fileSystem = options.fileSystem || fs;
  return withStableTrackedSource(
    trackedSourcePath(root, entry.path),
    { expectedIdentity: entry.identity, fileSystem },
    () => true,
  );
}

function assertStableTrackedDeletions(root, inventory, options = {}) {
  const fileSystem = options.fileSystem || fs;
  for (let index = 0; index < inventory.deleted.length; index += 1) {
    const relativePath = inventory.deleted[index];
    try {
      fileSystem.lstatSync(trackedSourcePath(root, relativePath), {
        bigint: true,
      });
    } catch (error) {
      if (error?.code === "ENOENT") continue;
      throw new Error(TRACKED_SOURCE_ERROR);
    }
    throw new Error(TRACKED_SOURCE_ERROR);
  }
  return true;
}

function assertStableTrackedSources(root, inventory, options = {}) {
  for (let index = 0; index < inventory.sources.length; index += 1) {
    assertStableTrackedSource(root, inventory.sources[index], options);
  }
  assertStableTrackedDeletions(root, inventory, options);
  return true;
}

function walkGeneratedFiles(root, relativeDirectory, options = {}) {
  const absoluteRoot = path.join(root, ...relativeDirectory.split("/"));
  if (!fs.existsSync(absoluteRoot)) return [];
  const rootStat = fs.lstatSync(absoluteRoot);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
    throw new Error(`Generated evidence root must be a real directory: ${relativeDirectory}`);
  }
  const excludedPrefixes = options.excludedPrefixes || [];
  const excludedFiles = options.excludedFiles || [];
  if (!Array.isArray(excludedFiles)
    || excludedFiles.length !== new Set(excludedFiles).size) {
    throw new Error("Generated evidence exact-file exclusions are invalid.");
  }
  const excludedFileSet = new Set(excludedFiles.map(relative => {
    assertRepositoryRelativePath(relative);
    return relative;
  }));
  const files = [];
  const pending = [absoluteRoot];
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      const relative = normalizePath(path.relative(root, absolute));
      if (excludedPrefixes.some(prefix => relative === prefix || relative.startsWith(`${prefix}/`))) continue;
      const stat = fs.lstatSync(absolute);
      if (excludedFileSet.has(relative)) {
        if (stat.isSymbolicLink() || !stat.isFile()
          || stat.nlink !== 1 || stat.size <= 0
          || stat.size > MAX_GENERATED_FILE_BYTES
          || fs.realpathSync(absolute) !== absolute) {
          throw new Error(`Generated evidence exact-file exclusion is unsafe: ${relative}`);
        }
        continue;
      }
      if (stat.isSymbolicLink()) {
        throw new Error(`Generated evidence scan rejects symbolic links: ${relative}`);
      }
      if (stat.isDirectory()) pending.push(absolute);
      else if (stat.isFile()) {
        if (stat.nlink !== 1 || stat.size > MAX_GENERATED_FILE_BYTES) {
          throw new Error(`Generated evidence must be a bounded single-link file: ${relative}`);
        }
        files.push(relative);
      }
      else throw new Error(`Generated evidence scan rejects non-file entries: ${relative}`);
      if (files.length > MAX_GENERATED_FILES) {
        throw new Error("Generated evidence scan exceeded its structural bound.");
      }
    }
  }
  return files.sort();
}

function copyGeneratedFileIntoSnapshot(source, relativePath, snapshotRoot, options = {}) {
  assertRepositoryRelativePath(relativePath);
  const parent = ensureSnapshotDirectory(snapshotRoot, path.posix.dirname(relativePath));
  const destination = path.join(parent, path.posix.basename(relativePath));
  const copied = withStableSingleLinkFile(source, {
    errorMessage: "Generated evidence changed or became unsafe during secret scanning.",
    expectedIdentity: options.expectedIdentity,
    fileSystem: options.fileSystem,
    maximumBytes: MAX_GENERATED_FILE_BYTES,
    minimumBytes: 0,
  }, (bytes, identity) => {
    const digestBytes = options.digestBytes || sha256;
    const digest = digestBytes(bytes);
    if (!/^[a-f0-9]{64}$/u.test(digest || "")) {
      throw new Error("Generated evidence changed or became unsafe during secret scanning.");
    }
    fs.writeFileSync(destination, bytes, { flag: "wx", mode: 0o600 });
    return Object.freeze({
      path: relativePath,
      identity,
      sha256: digest,
    });
  });
  if (process.platform !== "win32") fs.chmodSync(destination, 0o400);
  const snapshotProof = digestStableSingleLinkFile(destination, {
    errorMessage: "Generated evidence snapshot changed or became unsafe during secret scanning.",
    maximumBytes: MAX_GENERATED_FILE_BYTES,
    minimumBytes: 0,
  });
  if (snapshotProof.sha256 !== copied.sha256) {
    throw new Error("Generated evidence snapshot changed or became unsafe during secret scanning.");
  }
  return Object.freeze({
    manifest: copied,
    snapshot: Object.freeze({
      identity: snapshotProof.identity,
      sha256: snapshotProof.sha256,
    }),
  });
}

function createSelectedSnapshot(root, snapshotRoot, files, options = {}) {
  const expectedByPath = new Map((options.expectedInventory || []).map(entry => [
    entry.path,
    entry.identity,
  ]));
  const entries = [];
  for (const file of files) {
    assertRepositoryRelativePath(file);
    entries.push(copyGeneratedFileIntoSnapshot(
      path.join(root, ...file.split("/")),
      file,
      snapshotRoot,
      {
        ...options,
        expectedIdentity: expectedByPath.get(file),
      },
    ));
  }
  return entries;
}

function temporaryRoot(prefix = "cloudsmith-secret-scan-") {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  fs.chmodSync(directory, 0o700);
  temporaryRootOwnership.set(directory, exactPrivateSnapshotRoot(
    directory,
    "Secret scan temporary root must remain creator-owned and private.",
  ));
  return directory;
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function exactPrivateSnapshotRoot(root, errorMessage) {
  const stat = fs.lstatSync(root, { bigint: true });
  const expectedOwner = typeof process.getuid === "function"
    ? BigInt(process.getuid())
    : stat.uid;
  if (stat.isSymbolicLink() || !stat.isDirectory() || fs.realpathSync(root) !== root
    || stat.uid !== expectedOwner
    || (process.platform !== "win32" && (stat.mode & 0o077n) !== 0n)) {
    throw new Error(errorMessage);
  }
  return Object.freeze({ device: String(stat.dev), inode: String(stat.ino) });
}

function snapshotTreeInventory(snapshotRoot, errorMessage) {
  const files = [];
  const directories = ["."];
  const pending = [{ absolute: snapshotRoot, relative: "." }];
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const name of fs.readdirSync(directory.absolute)) {
      const absolute = path.join(directory.absolute, name);
      const relative = directory.relative === "."
        ? normalizePath(name)
        : `${directory.relative}/${normalizePath(name)}`;
      const stat = fs.lstatSync(absolute);
      if (stat.isSymbolicLink()) throw new Error(errorMessage);
      if (stat.isDirectory()) {
        directories.push(relative);
        pending.push({ absolute, relative });
      } else if (stat.isFile() && stat.nlink === 1) {
        files.push(relative);
      } else {
        throw new Error(errorMessage);
      }
      if (files.length > MAX_GENERATED_FILES || directories.length > MAX_GENERATED_FILES * 4) {
        throw new Error(errorMessage);
      }
    }
  }
  return Object.freeze({
    directories: directories.sort(),
    files: files.sort(),
  });
}

function expectedSnapshotDirectories(files) {
  const directories = new Set(["."]);
  for (const file of files) {
    let current = path.posix.dirname(file);
    while (current !== ".") {
      directories.add(current);
      current = path.posix.dirname(current);
    }
  }
  return [...directories].sort();
}

function sealSnapshotTree(snapshotRoot, entries, errorMessage) {
  const files = entries.map(entry => entry.manifest.path).sort();
  const inventory = snapshotTreeInventory(snapshotRoot, errorMessage);
  if (JSON.stringify(inventory.files) !== JSON.stringify(files)
    || JSON.stringify(inventory.directories) !== JSON.stringify(
      expectedSnapshotDirectories(files),
    )) {
    throw new Error(errorMessage);
  }
  return inventory;
}

function assertStableSnapshotTree(
  snapshotRoot,
  ownership,
  entries,
  maximumBytes,
  errorMessage,
) {
  const currentOwnership = exactPrivateSnapshotRoot(snapshotRoot, errorMessage);
  if (currentOwnership.device !== ownership.device
    || currentOwnership.inode !== ownership.inode) {
    throw new Error(errorMessage);
  }
  const files = entries.map(entry => entry.manifest.path).sort();
  const inventory = snapshotTreeInventory(snapshotRoot, errorMessage);
  if (JSON.stringify(inventory.files) !== JSON.stringify(files)
    || JSON.stringify(inventory.directories)
      !== JSON.stringify(expectedSnapshotDirectories(files))) {
    throw new Error(errorMessage);
  }
  for (const entry of entries) {
    const target = path.join(snapshotRoot, ...entry.manifest.path.split("/"));
    const proof = digestStableSingleLinkFile(target, {
      errorMessage,
      expectedIdentity: entry.snapshot.identity,
      maximumBytes,
      minimumBytes: 0,
    });
    if (proof.sha256 !== entry.snapshot.sha256
      || proof.sha256 !== entry.manifest.sha256
      || !sameExactFileIdentity(proof.identity, entry.snapshot.identity)) {
      throw new Error(errorMessage);
    }
  }
  return true;
}

function captureSnapshotTreeEntries(snapshotRoot, maximumBytes, errorMessage) {
  const inventory = snapshotTreeInventory(snapshotRoot, errorMessage);
  return inventory.files.map(relativePath => {
    const proof = digestStableSingleLinkFile(
      path.join(snapshotRoot, ...relativePath.split("/")),
      {
        errorMessage,
        maximumBytes,
        minimumBytes: 0,
      },
    );
    return Object.freeze({
      manifest: Object.freeze({
        path: relativePath,
        identity: proof.identity,
        sha256: proof.sha256,
      }),
      snapshot: proof,
    });
  });
}

function readSnapshotEntryBytes(snapshotRoot, entry, maximumBytes, errorMessage) {
  const proof = readStableSingleLinkFile(
    path.join(snapshotRoot, ...entry.manifest.path.split("/")),
    {
      errorMessage,
      expectedIdentity: entry.snapshot.identity,
      maximumBytes: entry.maximumBytes || maximumBytes,
      minimumBytes: 0,
    },
  );
  if (sha256(proof.bytes) !== entry.snapshot.sha256
    || !sameExactFileIdentity(proof.identity, entry.snapshot.identity)) {
    proof.bytes.fill(0);
    throw new Error(errorMessage);
  }
  return proof.bytes;
}

function exactScannerFindings(value, errorMessage) {
  if (!Array.isArray(value)) throw new Error(errorMessage);
  return value;
}

function exactTrackedArrayLength(value, errorMessage) {
  if (!INTRINSIC_REFLECT_APPLY(INTRINSIC_ARRAY_IS_ARRAY, Array, [value])
    || INTRINSIC_IS_PROXY(value)
    || INTRINSIC_GET_PROTOTYPE_OF(value) !== INTRINSIC_ARRAY_PROTOTYPE) {
    throw new Error(errorMessage);
  }
  const iterator = hasOwnDataValue(
    INTRINSIC_ARRAY_PROTOTYPE,
    INTRINSIC_SYMBOL_ITERATOR,
  );
  const length = hasOwnDataValue(value, "length");
  if (!iterator || iterator.value !== INTRINSIC_ARRAY_ITERATOR
    || !length || !INTRINSIC_NUMBER_IS_SAFE_INTEGER(length.value)
    || length.value < 0 || length.value > MAX_TRACKED_FILES) {
    throw new Error(errorMessage);
  }
  const keys = INTRINSIC_REFLECT_OWN_KEYS(value);
  if (keys.length !== length.value + 1) throw new Error(errorMessage);
  for (let index = 0; index < length.value; index += 1) {
    const descriptor = hasOwnDataValue(value, `${index}`);
    if (!descriptor || descriptor.enumerable !== true) throw new Error(errorMessage);
  }
  for (let index = 0; index < keys.length; index += 1) {
    if (typeof keys[index] !== "string") throw new Error(errorMessage);
  }
  return length.value;
}

function normalizeTrackedFinding(value, logicalPath, errorMessage) {
  if (!value || typeof value !== "object"
    || INTRINSIC_IS_PROXY(value)
    || INTRINSIC_REFLECT_APPLY(INTRINSIC_ARRAY_IS_ARRAY, Array, [value])
    || INTRINSIC_GET_PROTOTYPE_OF(value) !== INTRINSIC_OBJECT_PROTOTYPE) {
    throw new Error(errorMessage);
  }
  const keys = INTRINSIC_REFLECT_OWN_KEYS(value);
  if (keys.length !== TRACKED_FINDING_KEYS.length) throw new Error(errorMessage);
  for (let index = 0; index < keys.length; index += 1) {
    if (typeof keys[index] !== "string") throw new Error(errorMessage);
  }
  const fields = [];
  for (let index = 0; index < TRACKED_FINDING_KEYS.length; index += 1) {
    const descriptor = hasOwnDataValue(value, TRACKED_FINDING_KEYS[index]);
    if (!descriptor || descriptor.enumerable !== true) throw new Error(errorMessage);
    fields[index] = descriptor.value;
  }
  const commit = fields[0];
  const endLine = fields[1];
  const reportedPath = fields[2];
  const ruleId = fields[3];
  const startLine = fields[4];
  if ((commit !== null && (typeof commit !== "string"
      || !INTRINSIC_REFLECT_APPLY(
        INTRINSIC_REGEXP_TEST,
        /^[0-9a-f]{40,64}$/iu,
        [commit],
      )))
    || !INTRINSIC_NUMBER_IS_SAFE_INTEGER(endLine) || endLine < 0
    || reportedPath !== logicalPath
    || typeof ruleId !== "string"
    || !INTRINSIC_REFLECT_APPLY(
      INTRINSIC_REGEXP_TEST,
      /^[a-z0-9][a-z0-9._-]{0,127}$/iu,
      [ruleId],
    )
    || !INTRINSIC_NUMBER_IS_SAFE_INTEGER(startLine) || startLine < 0) {
    throw new Error(errorMessage);
  }
  return INTRINSIC_OBJECT_FREEZE({
    ruleId,
    path: reportedPath,
    startLine,
    endLine,
    commit,
  });
}

function normalizeTrackedFindings(value, logicalPath) {
  const errorMessage = "Tracked-file scanner must return exact value-blind findings.";
  try {
    const length = exactTrackedArrayLength(value, errorMessage);
    const normalized = [];
    for (let index = 0; index < length; index += 1) {
      normalized[index] = normalizeTrackedFinding(
        hasOwnDataValue(value, `${index}`).value,
        logicalPath,
        errorMessage,
      );
    }
    return INTRINSIC_OBJECT_FREEZE(normalized);
  } catch {
    throw new Error(errorMessage);
  }
}

async function scanProvenBytes(scan, logicalPath, provenBytes, options, errorMessage) {
  let scannerBytes;
  try {
    scannerBytes = Buffer.from(provenBytes);
    const result = await scan("stdin", logicalPath, {
      ...options,
      input: scannerBytes,
      logicalPath,
    });
    return exactScannerFindings(result, errorMessage);
  } finally {
    if (Buffer.isBuffer(scannerBytes)) scannerBytes.fill(0);
  }
}

function scanSnapshotEntriesSync(
  snapshotRoot,
  entries,
  maximumBytes,
  scan,
  options,
  errorMessage,
) {
  const findings = [];
  for (const entry of entries) {
    let provenBytes;
    let scannerBytes;
    try {
      provenBytes = readSnapshotEntryBytes(
        snapshotRoot,
        entry,
        maximumBytes,
        errorMessage,
      );
      scannerBytes = Buffer.from(provenBytes);
      const result = scan("stdin", entry.manifest.path, {
        ...options,
        input: scannerBytes,
        logicalPath: entry.manifest.path,
        scanRoot: snapshotRoot,
      });
      if (result && typeof result.then === "function") throw new Error(errorMessage);
      findings.push(...exactScannerFindings(result, errorMessage));
    } finally {
      if (Buffer.isBuffer(scannerBytes)) scannerBytes.fill(0);
      if (Buffer.isBuffer(provenBytes)) provenBytes.fill(0);
    }
  }
  return findings;
}

function makeExactDirectoryWritable(root, ownership, errorMessage) {
  if (process.platform === "win32") return true;
  const flags = fs.constants.O_RDONLY
    | (fs.constants.O_DIRECTORY || 0)
    | (fs.constants.O_NOFOLLOW || 0);
  let descriptor;
  let completed = false;
  try {
    descriptor = fs.openSync(root, flags);
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isDirectory()
      || String(opened.dev) !== String(ownership.device ?? ownership.dev)
      || String(opened.ino) !== String(ownership.inode ?? ownership.ino)) {
      throw new Error(errorMessage);
    }
    fs.fchmodSync(descriptor, 0o700);
    const current = fs.lstatSync(root, { bigint: true });
    if (!current.isDirectory()
      || String(current.dev) !== String(opened.dev)
      || String(current.ino) !== String(opened.ino)) {
      throw new Error(errorMessage);
    }
    completed = true;
  } catch {
    completed = false;
  } finally {
    if (descriptor !== undefined) {
      try {
        fs.closeSync(descriptor);
      } catch {
        completed = false;
      }
    }
  }
  if (!completed) throw new Error(errorMessage);
  return true;
}

async function scanSnapshotEntries(
  snapshotRoot,
  entries,
  maximumBytes,
  scan,
  options,
  errorMessage,
) {
  const findings = [];
  for (const entry of entries) {
    let provenBytes;
    let scannerBytes;
    try {
      provenBytes = readSnapshotEntryBytes(
        snapshotRoot,
        entry,
        maximumBytes,
        errorMessage,
      );
      scannerBytes = Buffer.from(provenBytes);
      const result = await scan("stdin", entry.manifest.path, {
        ...options,
        input: scannerBytes,
        logicalPath: entry.manifest.path,
        scanRoot: snapshotRoot,
      });
      findings.push(...exactScannerFindings(result, errorMessage));
    } finally {
      if (Buffer.isBuffer(scannerBytes)) scannerBytes.fill(0);
      if (Buffer.isBuffer(provenBytes)) provenBytes.fill(0);
    }
  }
  return findings;
}

function removePrivateSnapshotRoot(root, ownership, errorMessage) {
  const expected = ownership || temporaryRootOwnership.get(root);
  let quarantineRoot;
  let quarantineOwnership;
  let movedRoot;
  try {
    const current = exactPrivateSnapshotRoot(root, errorMessage);
    if (!expected
      || current.device !== String(expected.device ?? expected.dev)
      || current.inode !== String(expected.inode ?? expected.ino)) {
      throw new Error(errorMessage);
    }
    makeExactDirectoryWritable(root, expected, errorMessage);
    quarantineRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      path.dirname(root),
      `.${path.basename(root)}.cleanup-`,
    )));
    fs.chmodSync(quarantineRoot, 0o700);
    quarantineOwnership = exactPrivateSnapshotRoot(quarantineRoot, errorMessage);
    movedRoot = path.join(quarantineRoot, "owned");
    fs.renameSync(root, movedRoot);
    const moved = exactPrivateSnapshotRoot(movedRoot, errorMessage);
    if (moved.device !== current.device || moved.inode !== current.inode) {
      throw new Error(errorMessage);
    }
    removeExactOwnedDirectoryTree(movedRoot, {
      allowAdditionalRootEntries: true,
      errorMessage,
      expectedRootEntries: [],
      expectedRootIdentity: expected,
    });
    const reoccupied = fs.existsSync(root);
    removeExactOwnedDirectoryTree(quarantineRoot, {
      errorMessage,
      expectedRootEntries: [],
      expectedRootIdentity: quarantineOwnership,
    });
    temporaryRootOwnership.delete(root);
    if (reoccupied) throw new Error(errorMessage);
    return true;
  } catch {
    throw new Error(errorMessage);
  }
}

function candidateFileIdentity(stat) {
  return Object.freeze({
    changedNanoseconds: String(stat.ctimeNs),
    device: String(stat.dev),
    group: String(stat.gid),
    inode: String(stat.ino),
    links: String(stat.nlink),
    mode: String(stat.mode),
    modifiedNanoseconds: String(stat.mtimeNs),
    owner: String(stat.uid),
    size: String(stat.size),
  });
}

function sameCandidateFileIdentity(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function exactCandidateFile(target) {
  const stat = fs.lstatSync(target, { bigint: true });
  if (stat.isSymbolicLink() || !stat.isFile() || fs.realpathSync(target) !== target
    || stat.nlink !== 1n) {
    throw new Error("Upload-eligible UI candidate files must be exact single-link files.");
  }
  return Object.freeze({
    target,
    identity: candidateFileIdentity(stat),
    descriptorIdentity: exactFileIdentity(stat),
  });
}

function candidatePathExists(target) {
  try {
    fs.lstatSync(target);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function uploadCandidatePairState(root) {
  const receiptTarget = path.join(root, ...UI_CANDIDATE_RECEIPT.split("/"));
  const artifactTarget = path.join(root, ...UI_CANDIDATE_ARTIFACT.split("/"));
  const receiptPresent = candidatePathExists(receiptTarget);
  const artifactPresent = candidatePathExists(artifactTarget);
  if (!receiptPresent && !artifactPresent) {
    return Object.freeze({ status: "not-present", root });
  }
  if (!receiptPresent || !artifactPresent) {
    throw new Error("Upload-eligible UI candidate receipt/proof pair is incomplete.");
  }
  return Object.freeze({
    status: "present",
    root,
    receipt: exactCandidateFile(resolveExistingRepositoryFile(
      UI_CANDIDATE_RECEIPT,
      root,
      { subtree: ".quality/qualification" },
    )),
    artifact: exactCandidateFile(resolveExistingRepositoryFile(
      UI_CANDIDATE_ARTIFACT,
      root,
      { subtree: ".quality/qualification" },
    )),
  });
}

function signedOutUiSourceState(root) {
  const pair = uploadCandidatePairState(root);
  if (pair.status !== "present") {
    throw new Error("Signed-out UI evidence requires the exact candidate receipt/proof pair.");
  }
  const target = resolveExistingRepositoryFile(UI_RESULT, root, { subtree: ".quality/ui" });
  return Object.freeze({
    ...pair,
    ui: exactCandidateFile(target),
  });
}

function readExactCandidateBytes(entry, maximumBytes) {
  return withStableSingleLinkFile(entry.target, {
    errorMessage: "Upload-eligible UI candidate changed during secret scanning.",
    expectedIdentity: entry.descriptorIdentity,
    maximumBytes,
    minimumBytes: 1,
  }, bytes => Buffer.from(bytes));
}

function assertCandidateEntryDigest(entry, maximumBytes, expectedDigest) {
  const bytes = readExactCandidateBytes(entry, maximumBytes);
  try {
    if (sha256(bytes) !== expectedDigest) {
      throw new Error("Upload-eligible UI candidate changed during secret scanning.");
    }
  } finally {
    bytes.fill(0);
  }
}

function assertSameCandidatePair(expected, actual) {
  if (expected.status !== "present" || actual.status !== "present"
    || !sameCandidateFileIdentity(expected.receipt.identity, actual.receipt.identity)
    || !sameCandidateFileIdentity(expected.artifact.identity, actual.artifact.identity)) {
    throw new Error("Upload-eligible UI candidate changed during secret scanning.");
  }
}

function assertSameSignedOutUiSource(expected, actual) {
  assertSameCandidatePair(expected, actual);
  if (!expected.ui || !actual.ui
    || !sameCandidateFileIdentity(expected.ui.identity, actual.ui.identity)) {
    throw new Error("Upload-eligible signed-out UI evidence changed during secret scanning.");
  }
}

function exactPrivateCandidateSnapshotRoot(root) {
  const stat = fs.lstatSync(root);
  if (stat.isSymbolicLink() || !stat.isDirectory() || fs.realpathSync(root) !== root
    || (process.platform !== "win32" && (stat.mode & 0o077) !== 0)
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error("Upload-eligible UI candidate snapshot must be creator-owned and private.");
  }
  return stat;
}

function destroyUploadCandidateSnapshot(snapshot) {
  if (snapshot.status === "not-present") return true;
  const stat = exactPrivateCandidateSnapshotRoot(snapshot.scratch);
  if (stat.dev !== snapshot.dev || stat.ino !== snapshot.ino) {
    throw new Error("Upload-eligible UI candidate snapshot cleanup refused replacement.");
  }
  if (candidatePathExists(snapshot.candidateRoot)) {
    const candidateStat = fs.lstatSync(snapshot.candidateRoot);
    if (!candidateStat.isSymbolicLink() && candidateStat.isDirectory()
      && fs.realpathSync(snapshot.candidateRoot) === snapshot.candidateRoot) {
      if (process.platform !== "win32") fs.chmodSync(snapshot.candidateRoot, 0o700);
    }
  }
  removePrivateSnapshotRoot(
    snapshot.scratch,
    { device: String(snapshot.dev), inode: String(snapshot.ino) },
    "Upload-eligible UI candidate snapshot cleanup refused replacement.",
  );
  return !fs.existsSync(snapshot.scratch);
}

function captureUploadCandidateSnapshot(root, options = {}) {
  const source = options.signedOutBundle
    ? signedOutUiSourceState(root)
    : uploadCandidatePairState(root);
  if (source.status === "not-present") return source;
  const scratch = fs.realpathSync(temporaryRoot("cloudsmith-ui-candidate-snapshot-"));
  const scratchStat = exactPrivateCandidateSnapshotRoot(scratch);
  const candidateRoot = path.join(scratch, "candidate");
  fs.mkdirSync(candidateRoot, { mode: 0o700 });
  let receiptBytes;
  let artifactBytes;
  let uiBytes;
  const ownership = {
    status: "present",
    scratch,
    candidateRoot,
    dev: scratchStat.dev,
    ino: scratchStat.ino,
  };
  try {
    receiptBytes = readExactCandidateBytes(source.receipt, MAX_UI_CANDIDATE_RECEIPT_BYTES);
    artifactBytes = readExactCandidateBytes(source.artifact, MAX_UI_CANDIDATE_VSIX_BYTES);
    if (options.signedOutBundle) {
      uiBytes = readExactCandidateBytes(source.ui, MAX_UI_RESULT_BYTES);
    }
    const receiptSha256 = sha256(receiptBytes);
    const vsixSha256 = sha256(artifactBytes);
    const uiResultSha256 = uiBytes ? sha256(uiBytes) : null;
    const receiptTarget = path.join(candidateRoot, path.basename(UI_CANDIDATE_RECEIPT));
    const artifactTarget = path.join(candidateRoot, path.basename(UI_CANDIDATE_ARTIFACT));
    const uiTarget = path.join(candidateRoot, path.basename(UI_RESULT));
    fs.writeFileSync(receiptTarget, receiptBytes, { flag: "wx", mode: 0o600 });
    fs.writeFileSync(artifactTarget, artifactBytes, { flag: "wx", mode: 0o600 });
    if (uiBytes) fs.writeFileSync(uiTarget, uiBytes, { flag: "wx", mode: 0o600 });
    if (process.platform !== "win32") {
      fs.chmodSync(receiptTarget, 0o400);
      fs.chmodSync(artifactTarget, 0o400);
      if (uiBytes) fs.chmodSync(uiTarget, 0o400);
    }
    const snapshotReceipt = exactCandidateFile(receiptTarget);
    const snapshotArtifact = exactCandidateFile(artifactTarget);
    const snapshotUi = uiBytes ? exactCandidateFile(uiTarget) : null;
    const receipt = JSON.parse(receiptBytes.toString("utf8"));
    const snapshotBinding = candidateBindingFromReceipt(receipt, {
      artifactPath: snapshotArtifact.target,
    });
    const sourceBinding = candidateBindingFromReceipt(receipt, {
      root,
      source: receipt.source,
      artifactPath: source.artifact.target,
    });
    if (JSON.stringify(snapshotBinding) !== JSON.stringify(sourceBinding)
      || snapshotBinding.vsixSha256 !== vsixSha256
      || (options.sourceSha && snapshotBinding.sourceSha !== options.sourceSha)) {
      throw new Error("Upload-eligible UI candidate receipt/proof binding is invalid.");
    }
    if (options.signedOutBundle) {
      const ui = JSON.parse(uiBytes.toString("utf8"));
      const identifySource = options.sourceIdentity || sourceIdentity;
      const currentSource = identifySource(root);
      if (currentSource.sha !== receipt.source.sha
        || currentSource.fingerprint !== receipt.source.fingerprint) {
        throw new Error("Upload-eligible signed-out UI evidence source is stale or mismatched.");
      }
      const verify = options.verifySignedOutUiEvidence
        || require("./verify-ui-evidence").verifySignedOutUiEvidence;
      verify({
        root,
        source: currentSource,
        candidateReceipt: receipt,
        candidateArtifactPath: source.artifact.target,
        ui,
      });
      assertSameSignedOutUiSource(source, signedOutUiSourceState(root));
    } else {
      assertSameCandidatePair(source, uploadCandidatePairState(root));
    }
    assertCandidateEntryDigest(source.receipt, MAX_UI_CANDIDATE_RECEIPT_BYTES, receiptSha256);
    assertCandidateEntryDigest(source.artifact, MAX_UI_CANDIDATE_VSIX_BYTES, vsixSha256);
    assertCandidateEntryDigest(
      snapshotReceipt,
      MAX_UI_CANDIDATE_RECEIPT_BYTES,
      receiptSha256,
    );
    assertCandidateEntryDigest(snapshotArtifact, MAX_UI_CANDIDATE_VSIX_BYTES, vsixSha256);
    if (options.signedOutBundle) {
      assertCandidateEntryDigest(source.ui, MAX_UI_RESULT_BYTES, uiResultSha256);
      assertCandidateEntryDigest(snapshotUi, MAX_UI_RESULT_BYTES, uiResultSha256);
    }
    return Object.freeze({
      ...ownership,
      root,
      source,
      snapshot: Object.freeze({
        receipt: snapshotReceipt,
        artifact: snapshotArtifact,
        ...(snapshotUi ? { ui: snapshotUi } : {}),
      }),
      candidate: Object.freeze({
        receiptFingerprint: snapshotBinding.receiptFingerprint,
        receiptSha256,
        vsixSha256,
      }),
      ...(options.signedOutBundle ? {
        signedOut: Object.freeze({
          source: Object.freeze({ ...receipt.source }),
          uiResultSha256,
          files: Object.freeze([
            Object.freeze({
              bytes: receiptBytes.length,
              name: path.basename(UI_CANDIDATE_RECEIPT),
              role: "candidate-receipt",
              sha256: receiptSha256,
            }),
            Object.freeze({
              bytes: artifactBytes.length,
              name: path.basename(UI_CANDIDATE_ARTIFACT),
              role: "candidate-vsix",
              sha256: vsixSha256,
            }),
            Object.freeze({
              bytes: uiBytes.length,
              name: path.basename(UI_RESULT),
              role: "signed-out-ui-result",
              sha256: uiResultSha256,
            }),
          ].sort((left, right) => left.name.localeCompare(right.name))),
        }),
      } : {}),
    });
  } catch (error) {
    try {
      destroyUploadCandidateSnapshot(ownership);
    } catch {
      throw new Error("Upload-eligible UI candidate snapshot cleanup failed.");
    }
    throw error;
  } finally {
    if (receiptBytes) receiptBytes.fill(0);
    if (artifactBytes) artifactBytes.fill(0);
    if (uiBytes) uiBytes.fill(0);
  }
}

function assertStableUploadCandidateSnapshot(snapshot) {
  try {
    const current = snapshot.signedOut
      ? signedOutUiSourceState(snapshot.root)
      : uploadCandidatePairState(snapshot.root);
    if (snapshot.status === "not-present") {
      if (current.status !== "not-present") {
        throw new Error("Upload-eligible UI candidate changed during secret scanning.");
      }
      return snapshot;
    }
    if (snapshot.signedOut) assertSameSignedOutUiSource(snapshot.source, current);
    else assertSameCandidatePair(snapshot.source, current);
    const names = fs.readdirSync(snapshot.candidateRoot).sort();
    const expectedNames = [
      path.basename(UI_CANDIDATE_RECEIPT),
      path.basename(UI_CANDIDATE_ARTIFACT),
      ...(snapshot.signedOut ? [path.basename(UI_RESULT)] : []),
    ].sort();
    if (JSON.stringify(names) !== JSON.stringify(expectedNames)) {
      throw new Error("Upload-eligible UI candidate changed during secret scanning.");
    }
    const snapshotReceipt = exactCandidateFile(snapshot.snapshot.receipt.target);
    const snapshotArtifact = exactCandidateFile(snapshot.snapshot.artifact.target);
    const snapshotUi = snapshot.signedOut
      ? exactCandidateFile(snapshot.snapshot.ui.target)
      : null;
    if (!sameCandidateFileIdentity(
      snapshot.snapshot.receipt.identity,
      snapshotReceipt.identity,
    ) || !sameCandidateFileIdentity(
      snapshot.snapshot.artifact.identity,
      snapshotArtifact.identity,
    )) {
      throw new Error("Upload-eligible UI candidate changed during secret scanning.");
    }
    if (snapshot.signedOut && !sameCandidateFileIdentity(
      snapshot.snapshot.ui.identity,
      snapshotUi.identity,
    )) {
      throw new Error("Upload-eligible signed-out UI evidence changed during secret scanning.");
    }
    assertCandidateEntryDigest(
      current.receipt,
      MAX_UI_CANDIDATE_RECEIPT_BYTES,
      snapshot.candidate.receiptSha256,
    );
    assertCandidateEntryDigest(
      current.artifact,
      MAX_UI_CANDIDATE_VSIX_BYTES,
      snapshot.candidate.vsixSha256,
    );
    assertCandidateEntryDigest(
      snapshotReceipt,
      MAX_UI_CANDIDATE_RECEIPT_BYTES,
      snapshot.candidate.receiptSha256,
    );
    assertCandidateEntryDigest(
      snapshotArtifact,
      MAX_UI_CANDIDATE_VSIX_BYTES,
      snapshot.candidate.vsixSha256,
    );
    if (snapshot.signedOut) {
      assertCandidateEntryDigest(
        current.ui,
        MAX_UI_RESULT_BYTES,
        snapshot.signedOut.uiResultSha256,
      );
      assertCandidateEntryDigest(
        snapshotUi,
        MAX_UI_RESULT_BYTES,
        snapshot.signedOut.uiResultSha256,
      );
      assertSameSignedOutUiSource(snapshot.source, signedOutUiSourceState(snapshot.root));
    } else {
      assertSameCandidatePair(snapshot.source, uploadCandidatePairState(snapshot.root));
    }
    return snapshot;
  } catch {
    throw new Error("Upload-eligible UI candidate changed during secret scanning.");
  }
}

function assertStableSignedOutSource(snapshot, options = {}) {
  if (!snapshot?.signedOut) return true;
  const identifySource = options.sourceIdentity || sourceIdentity;
  const current = identifySource(snapshot.root);
  if (current.sha !== snapshot.signedOut.source.sha
    || current.fingerprint !== snapshot.signedOut.source.fingerprint) {
    throw new Error("Upload-eligible signed-out UI evidence source changed during secret scanning.");
  }
  return true;
}

function safeInteger(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`Gitleaks safe report contains an invalid ${field}.`);
  }
  return value;
}

function normalizeReportedPath(value, scanRoot, label, logicalPath) {
  if (typeof value !== "string" || value.length === 0 || value.length > 1000
    || /[\u0000-\u001f\u007f-\u009f]/u.test(value)) {
    throw new Error("Gitleaks safe report contains an invalid file location.");
  }
  if (logicalPath !== undefined) {
    if (!new Set(["-", "stdin"]).has(value)) {
      throw new Error("Gitleaks stdin report contains an invalid file location.");
    }
    assertRepositoryRelativePath(logicalPath);
    return label ? `${label}/${logicalPath}` : logicalPath;
  }
  const normalizedValue = normalizePath(value);
  let relative = normalizedValue;
  if (path.isAbsolute(value)) relative = normalizePath(path.relative(scanRoot, value));
  relative = relative.replace(/^\.\//u, "");
  if (relative === ".." || relative.startsWith("../") || path.isAbsolute(relative)) {
    throw new Error("Gitleaks safe report escaped its scan root.");
  }
  return label ? `${label}/${relative}` : relative;
}

function parseSafeReportText(text, options = {}) {
  if (FORBIDDEN_REPORT_FIELDS.test(text)) {
    throw new Error("Gitleaks emitted a forbidden secret-bearing report field; refusing to parse it.");
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error("Gitleaks safe metadata report is invalid.");
  }
  if (!Array.isArray(value)) throw new Error("Gitleaks safe report must be an array.");
  return value.map(item => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error("Gitleaks safe report contains an invalid finding.");
    }
    const keys = Object.keys(item).sort();
    if (JSON.stringify(keys) !== JSON.stringify(SAFE_REPORT_KEYS)) {
      throw new Error("Gitleaks safe report contains unexpected fields.");
    }
    if (typeof item.ruleId !== "string" || !/^[a-z0-9][a-z0-9._-]{0,127}$/iu.test(item.ruleId)) {
      throw new Error("Gitleaks safe report contains an invalid rule identifier.");
    }
    const commit = item.commit === "" ? null : item.commit;
    if (commit !== null && !/^[0-9a-f]{40,64}$/iu.test(commit)) {
      throw new Error("Gitleaks safe report contains an invalid commit location.");
    }
    return {
      ruleId: item.ruleId,
      path: normalizeReportedPath(
        item.file,
        options.scanRoot,
        options.label,
        options.logicalPath,
      ),
      startLine: safeInteger(item.startLine, "start line"),
      endLine: safeInteger(item.endLine, "end line"),
      commit,
    };
  });
}

function parseSafeReport(reportPath, options = {}) {
  return parseSafeReportText(fs.readFileSync(reportPath, "utf8"), options);
}

function scannerReportText(stdout) {
  const bytes = Buffer.isBuffer(stdout)
    ? Buffer.from(stdout)
    : typeof stdout === "string"
      ? Buffer.from(stdout, "utf8")
      : null;
  if (!bytes || bytes.length === 0 || bytes.length > MAX_SAFE_REPORT_BYTES) {
    throw new Error("Gitleaks did not emit one bounded safe metadata report.");
  }
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) {
    throw new Error("Gitleaks did not emit one bounded safe metadata report.");
  }
  return text;
}

function scanWithGitleaks(kind, target, options = {}) {
  if (!new Set(["dir", "git", "stdin"]).has(kind)) {
    throw new Error("Gitleaks scan kind is invalid.");
  }
  if (kind === "stdin") {
    assertRepositoryRelativePath(target);
    if (!Buffer.isBuffer(options.input)) {
      throw new Error("Gitleaks stdin scan requires an exact byte snapshot.");
    }
  }
  const root = options.root || ROOT;
  const execute = options.execute || run;
  const reportRoot = temporaryRoot("cloudsmith-gitleaks-runtime-");
  const scannerHome = path.join(reportRoot, "scanner-home");
  fs.mkdirSync(scannerHome, { mode: 0o700 });
  if (process.platform !== "win32") fs.chmodSync(scannerHome, 0o700);
  const args = [
    kind,
    "--config", path.join(root, CONFIG_PATH),
    "--redact=100",
    "--no-banner",
    "--no-color",
    "--log-level", "error",
    "--report-format", "template",
    "--report-template", path.join(root, REPORT_TEMPLATE),
    "--report-path", "-",
    "--exit-code", "1",
    "--timeout", "300",
  ];
  if (kind === "git") args.push("--log-opts=--all", target);
  else if (kind === "dir") args.push("--max-archive-depth", "0", target);
  else args.push("--max-archive-depth", "0");
  try {
    const result = execute("gitleaks", args, {
      cwd: root,
      env: privateScannerEnvironment(options.environment, scannerHome),
      ...(kind === "stdin" ? { input: options.input } : {}),
    });
    if (result.error || result.signal || !new Set([0, 1]).has(result.status)) {
      throw new Error("Gitleaks failed closed before producing a trustworthy result.");
    }
    const findings = parseSafeReportText(scannerReportText(result.stdout), {
      scanRoot: options.scanRoot || target,
      label: options.label,
      ...(kind === "stdin" ? { logicalPath: target } : {}),
    });
    if ((result.status === 0) !== (findings.length === 0)) {
      throw new Error("Gitleaks exit status disagrees with its safe metadata report.");
    }
    return findings;
  } finally {
    removePrivateSnapshotRoot(
      reportRoot,
      temporaryRootOwnership.get(reportRoot),
      "Gitleaks runtime cleanup refused an unsafe or changed root.",
    );
  }
}

function scanCurrentWorktreeValueBlind(root = ROOT, options = {}) {
  assertScannerVersion({ ...options, root });
  const component = scanTracked(root, options);
  return Object.freeze({
    status: component.findings.length === 0 ? "passed" : "failed",
    findingCount: component.findings.length,
  });
}

function scanTrackedSourceSync(root, entry, scan, options) {
  let scanFailed = false;
  let scanResult;
  let scannerBytes;
  assertStableTrackedSource(root, entry, options);
  try {
    scannerBytes = exactTrackedBufferCopy(entry.bytes);
    try {
      scanResult = scan("stdin", entry.path, {
        ...options,
        input: scannerBytes,
        logicalPath: entry.path,
        root,
        scanRoot: root,
      });
    } catch {
      scanFailed = true;
    }
    assertStableTrackedSource(root, entry, options);
    if (scanFailed) {
      throw new Error("Tracked-file scanner failed closed on exact captured bytes.");
    }
    return normalizeTrackedFindings(scanResult, entry.path);
  } finally {
    wipeTrackedBuffer(scannerBytes);
  }
}

function scanTracked(root, options = {}) {
  const inventory = captureTrackedSources(root, options);
  try {
    assertStableTrackedInventory(root, inventory, options);
    assertStableTrackedSources(root, inventory, options);
    const scan = options.scanWithGitleaks || scanWithGitleaks;
    const findings = [];
    for (let index = 0; index < inventory.sources.length; index += 1) {
      const sourceFindings = scanTrackedSourceSync(
        root,
        inventory.sources[index],
        scan,
        options,
      );
      for (let findingIndex = 0; findingIndex < sourceFindings.length; findingIndex += 1) {
        findings[findings.length] = sourceFindings[findingIndex];
      }
    }
    assertStableTrackedSources(root, inventory, options);
    assertStableTrackedInventory(root, inventory, options);
    assertStableTrackedSources(root, inventory, options);
    assertStableTrackedInventory(root, inventory, options);
    assertStableTrackedSources(root, inventory, options);
    return {
      id: "tracked-current",
      status: "scanned",
      fileCount: inventory.sources.length,
      omittedDeletedFileCount: inventory.deleted.length,
      findings: INTRINSIC_OBJECT_FREEZE(findings),
    };
  } finally {
    clearTrackedSourceBuffers(inventory);
  }
}

function scanGeneratedEvidence(root, relativeDirectory, options = {}) {
  const files = walkGeneratedFiles(root, relativeDirectory, options);
  const id = options.id || relativeDirectory.replace(/[^a-z0-9]+/giu, "-");
  const expectedInventory = options.expectedInventory || null;
  if (expectedInventory) {
    const expectedPaths = expectedInventory.map(entry => entry?.path);
    if (expectedPaths.some(relativePath => typeof relativePath !== "string")
      || JSON.stringify(expectedPaths) !== JSON.stringify([...new Set(expectedPaths)].sort())
      || JSON.stringify(files) !== JSON.stringify(expectedPaths)) {
      throw new Error("Generated evidence changed or became unsafe during secret scanning.");
    }
  }
  if (files.length === 0) {
    return { id, status: "not-present", fileCount: 0, findings: [], snapshotManifest: [] };
  }
  const scratch = fs.realpathSync(temporaryRoot());
  const scratchOwnership = exactPrivateSnapshotRoot(
    scratch,
    "Generated evidence snapshot must remain creator-owned and private.",
  );
  const snapshot = path.join(scratch, "evidence");
  fs.mkdirSync(snapshot, { mode: 0o700 });
  try {
    const snapshotOwnership = exactPrivateSnapshotRoot(
      snapshot,
      "Generated evidence snapshot must remain creator-owned and private.",
    );
    const entries = createSelectedSnapshot(root, snapshot, files, {
      ...options,
      expectedInventory,
    });
    sealSnapshotTree(
      snapshot,
      entries,
      "Generated evidence snapshot changed or became unsafe during secret scanning.",
    );
    assertStableSnapshotTree(
      snapshot,
      snapshotOwnership,
      entries,
      MAX_GENERATED_FILE_BYTES,
      "Generated evidence snapshot changed or became unsafe during secret scanning.",
    );
    const scan = options.scanWithGitleaks || scanWithGitleaks;
    const findings = scanSnapshotEntriesSync(
      snapshot,
      entries,
      MAX_GENERATED_FILE_BYTES,
      scan,
      { ...options, root },
      "Generated evidence scanner must complete synchronously on exact snapshot bytes.",
    );
    assertStableSnapshotTree(
      snapshot,
      snapshotOwnership,
      entries,
      MAX_GENERATED_FILE_BYTES,
      "Generated evidence snapshot changed or became unsafe during secret scanning.",
    );
    return {
      id,
      status: "scanned",
      fileCount: files.length,
      findings,
      snapshotManifest: entries.map(entry => entry.manifest),
    };
  } finally {
    removePrivateSnapshotRoot(
      scratch,
      scratchOwnership,
      "Generated evidence snapshot cleanup refused a replaced root.",
    );
  }
}

function uploadCandidateSnapshotEntries(snapshot) {
  const specifications = [
    {
      entry: snapshot.snapshot.receipt,
      maximumBytes: MAX_UI_CANDIDATE_RECEIPT_BYTES,
      sha256: snapshot.candidate.receiptSha256,
    },
    {
      entry: snapshot.snapshot.artifact,
      maximumBytes: MAX_UI_CANDIDATE_VSIX_BYTES,
      sha256: snapshot.candidate.vsixSha256,
    },
    ...(snapshot.signedOut ? [{
      entry: snapshot.snapshot.ui,
      maximumBytes: MAX_UI_RESULT_BYTES,
      sha256: snapshot.signedOut.uiResultSha256,
    }] : []),
  ];
  return specifications.map(specification => Object.freeze({
    manifest: Object.freeze({ path: path.basename(specification.entry.target) }),
    maximumBytes: specification.maximumBytes,
    snapshot: Object.freeze({
      identity: specification.entry.descriptorIdentity,
      sha256: specification.sha256,
    }),
  })).sort((left, right) => left.manifest.path.localeCompare(right.manifest.path));
}

async function scanUploadCandidateSnapshot(root, snapshot, options = {}) {
  if (snapshot.status === "not-present") return null;
  const scan = options.scanWithGitleaks || scanWithGitleaks;
  const rawEntries = uploadCandidateSnapshotEntries(snapshot);
  const archiveName = path.basename(UI_CANDIDATE_ARTIFACT);
  const rawFindings = [];
  let archiveBytes;
  try {
    for (const entry of rawEntries) {
      let provenBytes;
      try {
        provenBytes = readSnapshotEntryBytes(
          snapshot.candidateRoot,
          entry,
          entry.maximumBytes,
          "Upload-eligible UI candidate snapshot changed during secret scanning.",
        );
        rawFindings.push(...await scanProvenBytes(
          scan,
          entry.manifest.path,
          provenBytes,
          {
            ...options,
            root,
            scanRoot: snapshot.candidateRoot,
            label: "ui-candidate::raw",
          },
          "Upload-eligible UI candidate scanner returned invalid findings.",
        ));
        if (entry.manifest.path === archiveName) {
          archiveBytes = provenBytes;
          provenBytes = undefined;
        }
      } finally {
        if (Buffer.isBuffer(provenBytes)) provenBytes.fill(0);
      }
    }
    if (!Buffer.isBuffer(archiveBytes)) {
      throw new Error("Upload-eligible UI candidate snapshot is incomplete.");
    }
    const expanded = path.join(snapshot.scratch, "expanded");
    fs.mkdirSync(expanded, { mode: 0o700 });
    const expandedOwnership = exactPrivateSnapshotRoot(
      expanded,
      "Expanded UI candidate snapshot must remain creator-owned and private.",
    );
    const extraction = await extractVsix(archiveBytes, expanded);
    archiveBytes.fill(0);
    archiveBytes = undefined;
    const expandedError = "Expanded UI candidate snapshot changed or became unsafe.";
    const expandedEntries = captureSnapshotTreeEntries(
      expanded,
      MAX_VSIX_ENTRY_BYTES,
      expandedError,
    );
    sealSnapshotTree(expanded, expandedEntries, expandedError);
    assertStableSnapshotTree(
      expanded,
      expandedOwnership,
      expandedEntries,
      MAX_VSIX_ENTRY_BYTES,
      expandedError,
    );
    const expandedFindings = await scanSnapshotEntries(
      expanded,
      expandedEntries,
      MAX_VSIX_ENTRY_BYTES,
      scan,
      {
        ...options,
        root,
        label: `${UI_CANDIDATE_ARTIFACT}::expanded`,
      },
      "Expanded UI candidate scanner returned invalid findings.",
    );
    assertStableSnapshotTree(
      expanded,
      expandedOwnership,
      expandedEntries,
      MAX_VSIX_ENTRY_BYTES,
      expandedError,
    );
    return {
      id: `vsix:${UI_CANDIDATE_ARTIFACT}`,
      status: "scanned",
      fileCount: extraction.entryCount + rawEntries.length,
      findings: [...rawFindings, ...expandedFindings],
    };
  } finally {
    if (Buffer.isBuffer(archiveBytes)) archiveBytes.fill(0);
  }
}

async function scanUploadEligibleEvidenceFromSnapshot(root, snapshot, options = {}) {
  const scanGenerated = options.scanGeneratedEvidence || scanGeneratedEvidence;
  const components = [scanGenerated(root, ".quality", {
    ...options,
    id: "generated-quality-evidence",
    excludedPrefixes: snapshot.signedOut
      ? SIGNED_OUT_UI_SCAN_EXCLUSIONS
      : UI_CANDIDATE_SCAN_EXCLUSIONS,
  })];
  assertStableUploadCandidateSnapshot(snapshot);
  const candidate = await scanUploadCandidateSnapshot(root, snapshot, options);
  if (candidate) components.push(candidate);
  assertStableUploadCandidateSnapshot(snapshot);
  return components;
}

async function scanUploadEligibleEvidence(root, options = {}) {
  const snapshot = captureUploadCandidateSnapshot(root, options);
  try {
    return await scanUploadEligibleEvidenceFromSnapshot(root, snapshot, options);
  } finally {
    destroyUploadCandidateSnapshot(snapshot);
  }
}

function discoverVsixFiles(root) {
  const out = path.join(root, "out");
  if (!fs.existsSync(out)) return [];
  const pending = [out];
  const files = [];
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const target = path.join(directory, entry.name);
      const relative = normalizePath(path.relative(root, target));
      const stat = fs.lstatSync(target);
      if (stat.isSymbolicLink()) throw new Error(`VSIX discovery rejects symbolic links: ${relative}`);
      if (stat.isDirectory()) pending.push(target);
      else if (stat.isFile() && entry.name.endsWith(".vsix")) files.push(relative);
      if (files.length > 1000) throw new Error("VSIX discovery exceeded its structural bound.");
    }
  }
  return files.sort();
}

function validateArchiveEntryPath(entryName) {
  const normalized = normalizePath(entryName);
  if (!normalized || normalized.startsWith("/") || normalized.endsWith("/")
    || normalized.includes("\\") || normalized.includes("\0")
    || normalized === ".." || normalized.startsWith("../") || normalized.includes("/../")) {
    throw new Error("VSIX secret scan rejected an unsafe archive path.");
  }
  return normalized;
}

function extractVsix(source, destination) {
  return new Promise((resolve, reject) => {
    const openArchive = callback => {
      const archiveOptions = { lazyEntries: true, autoClose: true, validateEntrySizes: true };
      if (Buffer.isBuffer(source)) yauzl.fromBuffer(source, archiveOptions, callback);
      else yauzl.open(source, archiveOptions, callback);
    };
    openArchive((openError, zip) => {
      if (openError) return reject(new Error("VSIX secret scan could not open the archive."));
      let entryCount = 0;
      let totalBytes = 0;
      let settled = false;
      const fail = (message) => {
        if (settled) return;
        settled = true;
        zip.close();
        reject(message instanceof Error ? message : new Error(message));
      };
      zip.on("error", () => fail("VSIX secret scan encountered an archive error."));
      zip.on("end", () => {
        if (settled) return;
        settled = true;
        resolve({ entryCount, totalBytes });
      });
      zip.on("entry", (entry) => {
        if (settled) return;
        entryCount += 1;
        if (entryCount > MAX_VSIX_ENTRIES) return fail("VSIX secret scan exceeded its entry bound.");
        const isDirectory = entry.fileName.endsWith("/");
        if (isDirectory) {
          zip.readEntry();
          return;
        }
        let relative;
        try {
          relative = validateArchiveEntryPath(entry.fileName);
        } catch (error) {
          fail(error);
          return;
        }
        const unixMode = (entry.externalFileAttributes >>> 16) & 0xffff;
        if ((unixMode & 0o170000) === 0o120000) return fail("VSIX secret scan rejects symbolic-link entries.");
        if (entry.uncompressedSize > MAX_VSIX_ENTRY_BYTES) return fail("VSIX secret scan exceeded its per-entry byte bound.");
        totalBytes += entry.uncompressedSize;
        if (totalBytes > MAX_VSIX_TOTAL_BYTES) return fail("VSIX secret scan exceeded its total byte bound.");
        const target = path.join(destination, ...relative.split("/"));
        ensureSnapshotDirectory(destination, path.posix.dirname(relative));
        zip.openReadStream(entry, (streamError, stream) => {
          if (streamError) return fail("VSIX secret scan could not read an archive entry.");
          const output = fs.createWriteStream(target, { flags: "wx", mode: 0o600 });
          stream.on("error", () => fail("VSIX secret scan could not read an archive entry."));
          output.on("error", () => fail("VSIX secret scan could not persist an archive entry."));
          output.on("finish", () => zip.readEntry());
          stream.pipe(output);
        });
      });
      zip.readEntry();
    });
  });
}

function captureVsixSnapshot(source, relativePath, snapshotRoot, options = {}) {
  const target = path.join(snapshotRoot, "candidate.vsix");
  const sourceProof = withStableSingleLinkFile(source, {
    errorMessage: "VSIX secret scan source changed or became unsafe.",
    expectedIdentity: options.expectedVsixIdentity,
    fileSystem: options.fileSystem,
    maximumBytes: MAX_VSIX_TOTAL_BYTES,
    minimumBytes: 1,
  }, (bytes, identity) => {
    const digest = sha256(bytes);
    fs.writeFileSync(target, bytes, { flag: "wx", mode: 0o600 });
    return Object.freeze({
      path: relativePath,
      identity,
      sha256: digest,
    });
  });
  if (options.expectedVsixSha256 && sourceProof.sha256 !== options.expectedVsixSha256) {
    throw new Error("VSIX secret scan source did not match its accepted candidate digest.");
  }
  if (process.platform !== "win32") {
    fs.chmodSync(target, 0o400);
  }
  const snapshotProof = digestStableSingleLinkFile(target, {
    errorMessage: "VSIX secret scan snapshot changed or became unsafe.",
    maximumBytes: MAX_VSIX_TOTAL_BYTES,
    minimumBytes: 1,
  });
  if (snapshotProof.sha256 !== sourceProof.sha256) {
    throw new Error("VSIX secret scan snapshot changed or became unsafe.");
  }
  return Object.freeze({
    source: sourceProof,
    target,
    snapshot: snapshotProof,
  });
}

function assertStableVsixSnapshot(snapshotRoot, ownership, snapshot) {
  const errorMessage = "VSIX secret scan snapshot changed or became unsafe.";
  const currentOwnership = exactPrivateSnapshotRoot(snapshotRoot, errorMessage);
  const inventory = snapshotTreeInventory(snapshotRoot, errorMessage);
  if (currentOwnership.device !== ownership.device
    || currentOwnership.inode !== ownership.inode
    || JSON.stringify(inventory.directories) !== JSON.stringify(["."])
    || JSON.stringify(inventory.files) !== JSON.stringify(["candidate.vsix"])) {
    throw new Error(errorMessage);
  }
  const current = digestStableSingleLinkFile(snapshot.target, {
    errorMessage,
    expectedIdentity: snapshot.snapshot.identity,
    maximumBytes: MAX_VSIX_TOTAL_BYTES,
    minimumBytes: 1,
  });
  if (current.sha256 !== snapshot.source.sha256
    || current.sha256 !== snapshot.snapshot.sha256
    || !sameExactFileIdentity(current.identity, snapshot.snapshot.identity)) {
    throw new Error(errorMessage);
  }
  return true;
}

function assertStableVsixSource(source, snapshot, options = {}) {
  const errorMessage = "VSIX secret scan source changed or became unsafe.";
  const current = digestStableSingleLinkFile(source, {
    errorMessage,
    expectedIdentity: snapshot.source.identity,
    fileSystem: options.fileSystem,
    maximumBytes: MAX_VSIX_TOTAL_BYTES,
    minimumBytes: 1,
  });
  if (current.sha256 !== snapshot.source.sha256
    || !sameExactFileIdentity(current.identity, snapshot.source.identity)) {
    throw new Error(errorMessage);
  }
  return true;
}

async function scanVsix(root, relativePath, options = {}) {
  assertRepositoryRelativePath(relativePath);
  const filePath = path.join(root, ...relativePath.split("/"));
  const scratch = fs.realpathSync(temporaryRoot("cloudsmith-vsix-secret-scan-"));
  const scratchOwnership = exactPrivateSnapshotRoot(
    scratch,
    "VSIX secret scan snapshot must remain creator-owned and private.",
  );
  const candidateRoot = path.join(scratch, "candidate");
  fs.mkdirSync(candidateRoot, { mode: 0o700 });
  const candidateRootOwnership = exactPrivateSnapshotRoot(
    candidateRoot,
    "VSIX secret scan snapshot must remain creator-owned and private.",
  );
  const expanded = path.join(scratch, "expanded");
  let archiveBytes;
  try {
    const snapshot = captureVsixSnapshot(filePath, relativePath, candidateRoot, options);
    assertStableVsixSnapshot(candidateRoot, candidateRootOwnership, snapshot);
    const scan = options.scanWithGitleaks || scanWithGitleaks;
    archiveBytes = readSnapshotEntryBytes(
      candidateRoot,
      {
        manifest: { path: path.basename(snapshot.target) },
        snapshot: snapshot.snapshot,
      },
      MAX_VSIX_TOTAL_BYTES,
      "VSIX secret scan snapshot changed or became unsafe.",
    );
    const archiveFindings = await scanProvenBytes(
      scan,
      path.basename(snapshot.target),
      archiveBytes,
      {
        ...options,
        root,
        scanRoot: candidateRoot,
        label: `${relativePath}::archive`,
      },
      "VSIX secret scanner did not return exact value-blind findings.",
    );
    assertStableVsixSnapshot(candidateRoot, candidateRootOwnership, snapshot);
    fs.mkdirSync(expanded, { mode: 0o700 });
    const expandedOwnership = exactPrivateSnapshotRoot(
      expanded,
      "Expanded VSIX snapshot must remain creator-owned and private.",
    );
    const extraction = await (options.extractVsix || extractVsix)(archiveBytes, expanded);
    archiveBytes.fill(0);
    archiveBytes = undefined;
    assertStableVsixSnapshot(candidateRoot, candidateRootOwnership, snapshot);
    const expandedError = "Expanded VSIX snapshot changed or became unsafe.";
    const expandedEntries = captureSnapshotTreeEntries(
      expanded,
      MAX_VSIX_ENTRY_BYTES,
      expandedError,
    );
    sealSnapshotTree(expanded, expandedEntries, expandedError);
    assertStableSnapshotTree(
      expanded,
      expandedOwnership,
      expandedEntries,
      MAX_VSIX_ENTRY_BYTES,
      expandedError,
    );
    const expandedFindings = await scanSnapshotEntries(
      expanded,
      expandedEntries,
      MAX_VSIX_ENTRY_BYTES,
      scan,
      {
        ...options,
        root,
        label: `${relativePath}::expanded`,
      },
      "Expanded VSIX scanner did not return exact value-blind findings.",
    );
    assertStableSnapshotTree(
      expanded,
      expandedOwnership,
      expandedEntries,
      MAX_VSIX_ENTRY_BYTES,
      expandedError,
    );
    assertStableVsixSnapshot(candidateRoot, candidateRootOwnership, snapshot);
    assertStableVsixSource(filePath, snapshot, options);
    return {
      id: `vsix:${relativePath}`,
      status: "scanned",
      fileCount: extraction.entryCount + 1,
      findings: [...archiveFindings, ...expandedFindings],
      snapshot: snapshot.source,
    };
  } finally {
    if (Buffer.isBuffer(archiveBytes)) archiveBytes.fill(0);
    removePrivateSnapshotRoot(
      scratch,
      scratchOwnership,
      "VSIX secret scan snapshot cleanup refused a replaced root.",
    );
  }
}

async function scanArtifacts(root, options = {}) {
  const files = discoverVsixFiles(root);
  if (files.length === 0) return [{ id: "vsix-artifacts", status: "not-present", fileCount: 0, findings: [] }];
  const results = [];
  for (const file of files) results.push(await scanVsix(root, file, options));
  return results;
}

function scanHistory(root, options = {}) {
  const findings = scanWithGitleaks("git", root, {
    ...options,
    root,
    scanRoot: root,
  });
  return { id: "git-history-all-refs", status: "scanned", fileCount: null, findings };
}

function safeUploadCandidateEvidence(value) {
  if (value === null) return null;
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join(",")
      !== "receiptFingerprint,receiptSha256,vsixSha256"
    || Object.values(value).some(item => !/^[a-f0-9]{64}$/u.test(item || ""))) {
    throw new Error("Upload-eligible UI candidate evidence is not value-safe.");
  }
  return Object.freeze({ ...value });
}

function resultDocument(mode, sourceSha, components, now = new Date(), options = {}) {
  const findings = components.flatMap(component => component.findings.map(finding => ({
    component: component.id,
    ...finding,
  })));
  const result = {
    schemaVersion: 1,
    scanner: {
      name: "gitleaks",
      version: GITLEAKS_VERSION,
      redactionPercent: 100,
      secretBearingFieldsPersisted: false,
    },
    mode,
    status: findings.length === 0 ? "passed" : "failed",
    sourceSha,
    capturedAt: now.toISOString(),
    findingCount: findings.length,
    components: components.map(component => ({
      id: component.id,
      status: component.status,
      fileCount: component.fileCount,
      findingCount: component.findings.length,
      ...(Number.isInteger(component.omittedDeletedFileCount)
        ? { omittedDeletedFileCount: component.omittedDeletedFileCount }
        : {}),
    })),
    findings,
  };
  if (Object.prototype.hasOwnProperty.call(options, "candidate")) {
    result.candidate = safeUploadCandidateEvidence(options.candidate);
  }
  return result;
}

function serializedReceiptBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function signedOutBundleResult(result, snapshot) {
  if (!snapshot?.signedOut || result.mode !== "evidence") {
    throw new Error("Signed-out UI bundle receipt requires an exact evidence snapshot.");
  }
  const document = {
    ...result,
    schemaVersion: 2,
    bundle: {
      schemaVersion: 1,
      kind: "signed-out-ui-evidence",
      source: { ...snapshot.signedOut.source },
      candidateReceiptFingerprint: snapshot.candidate.receiptFingerprint,
      scanResult: {
        mode: result.mode,
        status: result.status,
        findingCount: result.findingCount,
      },
      files: snapshot.signedOut.files.map(entry => ({ ...entry })),
      receipt: {
        name: SIGNED_OUT_BUNDLE_RECEIPT,
        role: "value-blind-secret-scan-receipt",
        bytes: 0,
        integrity: "canonical-self-fingerprint",
      },
    },
  };
  for (let attempts = 0; attempts < 8; attempts += 1) {
    const unsigned = { ...document };
    delete unsigned.fingerprint;
    document.fingerprint = fingerprint(unsigned);
    const byteLength = serializedReceiptBytes(document).length;
    if (document.bundle.receipt.bytes === byteLength) return document;
    document.bundle.receipt.bytes = byteLength;
  }
  throw new Error("Signed-out UI bundle receipt did not reach a canonical byte size.");
}

function ensureSignedOutBundleParent(root) {
  const qualityRoot = path.join(root, ".quality");
  const parent = path.join(qualityRoot, "upload");
  for (const directory of [qualityRoot, parent]) {
    if (!candidatePathExists(directory)) fs.mkdirSync(directory, { mode: 0o700 });
    const stat = fs.lstatSync(directory);
    if (stat.isSymbolicLink() || !stat.isDirectory()
      || fs.realpathSync(directory) !== directory
      || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
      throw new Error("Signed-out UI bundle ancestry must be creator-owned real directories.");
    }
  }
  if (process.platform !== "win32") fs.chmodSync(parent, 0o700);
  exactPrivateSnapshotRoot(
    parent,
    "Signed-out UI bundle parent must be creator-owned and private.",
  );
  return parent;
}

function removeSignedOutBundleStage(root) {
  const target = path.join(root, ...SIGNED_OUT_BUNDLE_DIRECTORY.split("/"));
  if (!candidatePathExists(target)) return false;
  const ownership = exactPrivateSnapshotRoot(
    target,
    "Signed-out UI bundle cleanup refused an unsafe or replaced directory.",
  );
  snapshotTreeInventory(
    target,
    "Signed-out UI bundle cleanup refused unsafe contents.",
  );
  removePrivateSnapshotRoot(
    target,
    ownership,
    "Signed-out UI bundle cleanup refused an unsafe or replaced directory.",
  );
  return true;
}

function signedOutSnapshotEntry(snapshot, name) {
  if (name === path.basename(UI_CANDIDATE_RECEIPT)) return snapshot.snapshot.receipt;
  if (name === path.basename(UI_CANDIDATE_ARTIFACT)) return snapshot.snapshot.artifact;
  if (name === path.basename(UI_RESULT)) return snapshot.snapshot.ui;
  throw new Error("Signed-out UI bundle contains an unknown evidence role.");
}

function validateStagedSignedOutBundle(stageRoot, ownership, result, expected = null) {
  const errorMessage = "Staged signed-out UI evidence changed or became unsafe.";
  const currentOwnership = exactPrivateSnapshotRoot(stageRoot, errorMessage);
  if (currentOwnership.device !== ownership.device
    || currentOwnership.inode !== ownership.inode) throw new Error(errorMessage);
  const inventory = snapshotTreeInventory(stageRoot, errorMessage);
  if (JSON.stringify(inventory.directories) !== JSON.stringify(["."])
    || JSON.stringify(inventory.files) !== JSON.stringify(SIGNED_OUT_BUNDLE_NAMES)) {
    throw new Error(errorMessage);
  }
  const files = {};
  for (const entry of result.bundle.files) {
    const proof = digestStableSingleLinkFile(path.join(stageRoot, entry.name), {
      errorMessage,
      ...(expected ? { expectedIdentity: expected.files[entry.name].identity } : {}),
      expectedBytes: entry.bytes,
      maximumBytes: entry.name.endsWith(".vsix")
        ? MAX_UI_CANDIDATE_VSIX_BYTES
        : MAX_SIGNED_OUT_EVIDENCE_BYTES,
      minimumBytes: 1,
    });
    if (proof.sha256 !== entry.sha256) throw new Error(errorMessage);
    files[entry.name] = proof;
  }
  const receipt = withStableSingleLinkFile(
    path.join(stageRoot, SIGNED_OUT_BUNDLE_RECEIPT),
    {
      errorMessage,
      ...(expected ? {
        expectedIdentity: expected.files[SIGNED_OUT_BUNDLE_RECEIPT].identity,
      } : {}),
      expectedBytes: result.bundle.receipt.bytes,
      maximumBytes: MAX_SIGNED_OUT_EVIDENCE_BYTES,
      minimumBytes: 1,
    },
    (bytes, identity) => Object.freeze({
      bytes: Buffer.from(bytes),
      identity,
      sha256: sha256(bytes),
    }),
  );
  try {
    if (!receipt.bytes.equals(serializedReceiptBytes(result))) throw new Error(errorMessage);
  } finally {
    receipt.bytes.fill(0);
  }
  files[SIGNED_OUT_BUNDLE_RECEIPT] = Object.freeze({
    identity: receipt.identity,
    sha256: receipt.sha256,
  });
  if (expected && SIGNED_OUT_BUNDLE_NAMES.some(name => (
    !sameExactFileIdentity(files[name].identity, expected.files[name].identity)
    || files[name].sha256 !== expected.files[name].sha256
  ))) throw new Error(errorMessage);
  return Object.freeze({ files: Object.freeze(files) });
}

function stageSignedOutBundle(root, snapshot, result, options = {}) {
  if (result.status !== "passed" || !snapshot.signedOut) {
    throw new Error("Only passed signed-out UI evidence may be staged for upload.");
  }
  assertStableUploadCandidateSnapshot(snapshot);
  assertStableSignedOutSource(snapshot, options);
  const parent = ensureSignedOutBundleParent(root);
  removeSignedOutBundleStage(root);
  const target = path.join(root, ...SIGNED_OUT_BUNDLE_DIRECTORY.split("/"));
  const temporary = fs.realpathSync(fs.mkdtempSync(path.join(parent, ".signed-out-ui-")));
  if (process.platform !== "win32") fs.chmodSync(temporary, 0o700);
  const ownership = exactPrivateSnapshotRoot(
    temporary,
    "Signed-out UI bundle staging root must be creator-owned and private.",
  );
  let renamed = false;
  try {
    for (const entry of result.bundle.files) {
      const source = signedOutSnapshotEntry(snapshot, entry.name);
      withStableSingleLinkFile(source.target, {
        errorMessage: "Signed-out UI snapshot changed while staging upload evidence.",
        expectedBytes: entry.bytes,
        maximumBytes: entry.name.endsWith(".vsix")
          ? MAX_UI_CANDIDATE_VSIX_BYTES
          : MAX_SIGNED_OUT_EVIDENCE_BYTES,
        minimumBytes: 1,
      }, bytes => {
        if (sha256(bytes) !== entry.sha256) {
          throw new Error("Signed-out UI snapshot digest changed while staging upload evidence.");
        }
        fs.writeFileSync(path.join(temporary, entry.name), bytes, {
          flag: "wx",
          mode: 0o400,
        });
      });
    }
    const receiptBytes = serializedReceiptBytes(result);
    try {
      fs.writeFileSync(path.join(temporary, SIGNED_OUT_BUNDLE_RECEIPT), receiptBytes, {
        flag: "wx",
        mode: 0o400,
      });
    } finally {
      receiptBytes.fill(0);
    }
    const staged = validateStagedSignedOutBundle(temporary, ownership, result);
    assertStableUploadCandidateSnapshot(snapshot);
    assertStableSignedOutSource(snapshot, options);
    fs.renameSync(temporary, target);
    renamed = true;
    validateStagedSignedOutBundle(target, ownership, result, staged);
    if (typeof options.afterSignedOutBundleStage === "function") {
      options.afterSignedOutBundleStage(target, result);
    }
    validateStagedSignedOutBundle(target, ownership, result, staged);
    assertStableUploadCandidateSnapshot(snapshot);
    assertStableSignedOutSource(snapshot, options);
    return target;
  } catch (error) {
    const cleanupTarget = renamed ? target : temporary;
    if (candidatePathExists(cleanupTarget)) {
      try {
        const current = exactPrivateSnapshotRoot(
          cleanupTarget,
          "Signed-out UI bundle cleanup refused a replaced staging root.",
        );
        if (current.device !== ownership.device || current.inode !== ownership.inode) {
          throw new Error("Signed-out UI bundle cleanup refused a replaced staging root.");
        }
        removePrivateSnapshotRoot(
          cleanupTarget,
          current,
          "Signed-out UI bundle cleanup refused a replaced staging root.",
        );
      } catch {
        throw new Error("Signed-out UI bundle cleanup failed after evidence drift.");
      }
    }
    throw error;
  }
}

async function finalizeScanResult(root, mode, sourceSha, components, snapshot, options) {
  const baseResult = resultDocument(
    mode,
    sourceSha,
    components,
    options.now || new Date(),
    snapshot ? { candidate: snapshot.status === "present" ? snapshot.candidate : null } : {},
  );
  const result = options.signedOutBundle
    ? signedOutBundleResult(baseResult, snapshot)
    : baseResult;
  if (snapshot) assertStableUploadCandidateSnapshot(snapshot);
  if (options.signedOutBundle) assertStableSignedOutSource(snapshot, options);
  const writer = options.writeReceipt || (options.outputPath
    ? value => writeJson(options.outputPath, value, root)
    : null);
  if (writer) {
    try {
      await writer(result);
      if (snapshot) assertStableUploadCandidateSnapshot(snapshot);
      if (options.signedOutBundle) assertStableSignedOutSource(snapshot, options);
      if (options.signedOutBundle) {
        if (result.status === "passed") stageSignedOutBundle(root, snapshot, result, options);
        else removeSignedOutBundleStage(root);
      }
    } catch (error) {
      if (options.outputPath) {
        try {
          removeOutputFile(options.outputPath, root);
        } catch {
          throw new Error("Secret scan receipt cleanup failed after candidate drift.");
        }
      }
      if (options.signedOutBundle) {
        try {
          removeSignedOutBundleStage(root);
        } catch {
          throw new Error("Signed-out UI bundle cleanup failed after evidence drift.");
        }
      }
      throw error;
    }
  } else if (options.signedOutBundle) {
    if (result.status === "passed") stageSignedOutBundle(root, snapshot, result, options);
    else removeSignedOutBundleStage(root);
  }
  return result;
}

async function scanComponents(root, mode, sourceSha, snapshot, options) {
  const components = [];
  if (mode === "current" || mode === "all") {
    components.push(scanTracked(root, options));
  }
  if (mode === "evidence" || mode === "all") {
    components.push(...await scanUploadEligibleEvidenceFromSnapshot(root, snapshot, options));
  } else if (mode === "current") {
    components.push(scanGeneratedEvidence(root, ".quality", {
      ...options,
      id: "generated-quality-evidence",
      excludedPrefixes: [OUTPUT_ROOT],
    }));
  }
  if (options.includeLocalEvidence) {
    components.push(scanGeneratedEvidence(root, "internal_docs/quality", {
      ...options,
      id: "local-internal-quality-evidence",
    }));
  }
  if (mode === "artifacts" || mode === "current" || mode === "all") {
    components.push(...await scanArtifacts(root, options));
  }
  if (mode === "history" || mode === "all") components.push(scanHistory(root, options));
  return finalizeScanResult(root, mode, sourceSha, components, snapshot, options);
}

async function executeScan(options = {}) {
  const root = assertRealRepositoryRoot(options.root || ROOT);
  const mode = options.mode || "current";
  if (options.signedOutBundle) {
    if (mode !== "evidence") {
      throw new Error("The signed-out upload bundle may only be produced by an evidence scan.");
    }
    if (options.outputPath) removeOutputFile(options.outputPath, root);
    removeSignedOutBundleStage(root);
  }
  const assertScanner = options.assertScannerVersion || assertScannerVersion;
  const identifyHead = options.currentHead || currentHead;
  assertScanner({ ...options, root });
  const sourceSha = identifyHead(root, options);
  if (mode !== "evidence" && mode !== "all") {
    return scanComponents(root, mode, sourceSha, null, options);
  }
  const snapshot = captureUploadCandidateSnapshot(root, { ...options, sourceSha });
  try {
    return await scanComponents(root, mode, sourceSha, snapshot, options);
  } finally {
    destroyUploadCandidateSnapshot(snapshot);
  }
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArguments(argv);
  const outputPath = `${OUTPUT_ROOT}/${options.mode}.json`;
  removeOutputFile(outputPath, ROOT);
  const result = await executeScan({ ...options, outputPath });
  console.log(
    `Secret exposure gate ${result.status}: ${result.findingCount} finding(s) across `
    + `${result.components.length} scanned component(s).`
  );
  if (result.status !== "passed") process.exitCode = 1;
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`Secret exposure gate failed closed: ${error.message}`);
    process.exit(1);
  });
}

module.exports = {
  CONFIG_PATH,
  FORBIDDEN_REPORT_FIELDS,
  GITLEAKS_VERSION,
  MAX_GENERATED_FILE_BYTES,
  MAX_TRACKED_FILE_BYTES,
  SCANNER_PROCESS_TIMEOUT_MS,
  REPORT_TEMPLATE,
  SAFE_REPORT_KEYS,
  SIGNED_OUT_BUNDLE_DIRECTORY,
  SIGNED_OUT_BUNDLE_NAMES,
  SIGNED_OUT_UI_SCAN_EXCLUSIONS,
  UI_CANDIDATE_SCAN_EXCLUSIONS,
  assertScannerVersion,
  assertStableUploadCandidateSnapshot,
  captureUploadCandidateSnapshot,
  copyGeneratedFileIntoSnapshot,
  discoverVsixFiles,
  destroyUploadCandidateSnapshot,
  executeScan,
  extractVsix,
  parseArguments,
  parseSafeReport,
  resultDocument,
  safeUploadCandidateEvidence,
  signedOutBundleResult,
  stageSignedOutBundle,
  scanGeneratedEvidence,
  scanUploadEligibleEvidence,
  scanCurrentWorktreeValueBlind,
  scanTracked,
  scanVsix,
  scanWithGitleaks,
  scannerEnvironment,
  privateScannerEnvironment,
  removePrivateSnapshotRoot,
  runScannerProcess: run,
  trackedFiles,
  validateArchiveEntryPath,
  walkGeneratedFiles,
};

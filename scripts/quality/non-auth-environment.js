// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const CREDENTIAL_LIKE_ENVIRONMENT_NAME = /(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSCODE|MFA|CREDENTIAL|KEYCHAIN|ONEPASSWORD|1PASSWORD|PRIVATE_?KEY|ACCESS_?KEY|REFRESH_?TOKEN)/iu;
const NON_AUTH_BOUNDARY_PREFIX = "cloudsmith-non-auth-";
const NON_AUTH_BOUNDARY_MARKER = ".cloudsmith-non-auth-owner.json";
const NON_AUTH_BOUNDARY_OWNER = "cloudsmith-vscode-non-auth-quality";
const EXACT_CLEANUP_MAX_ENTRIES = 100_000;
const EXACT_CLEANUP_MAX_DEPTH = 128;
const EXACT_CLEANUP_MAX_NAME_BYTES = 1024;
const NON_AUTH_BOUNDARY_DIRECTORY_PATHS = Object.freeze([
  "home",
  "xdgConfig",
  "xdgCache",
  "xdgData",
  "xdgState",
  "appData",
  "localAppData",
  "temporary",
  "npmCache",
]);
const NON_AUTH_BOUNDARY_EMPTY_FILE_PATHS = Object.freeze([
  "npmUserConfig",
  "npmGlobalConfig",
  "gitGlobalConfig",
]);
const NON_AUTH_AMBIENT_CAPABILITY_NAMES = Object.freeze([
  "DBUS_SESSION_BUS_ADDRESS",
  "DISPLAY",
  "GPG_AGENT_INFO",
  "KRB5CCNAME",
  "SECURITYSESSIONID",
  "SSH_AGENT_PID",
  "SSH_AUTH_SOCK",
  "WAYLAND_DISPLAY",
  "XAUTHORITY",
  "XDG_RUNTIME_DIR",
]);
const activeBoundaries = new Map();

function sameFilesystemPath(left, right) {
  const normalizedLeft = path.normalize(left);
  const normalizedRight = path.normalize(right);
  return process.platform === "win32"
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight;
}

// Non-authenticated quality work starts from this exact set instead of the
// caller's complete environment. In particular, user/profile locations,
// package-manager configuration, credential-agent sockets, and arbitrary CI
// variables are intentionally absent.
const NON_AUTH_QUALITY_ENVIRONMENT_ALLOWLIST = Object.freeze([
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "WINDIR",
  "COMSPEC",
  "PROCESSOR_ARCHITECTURE",
  "NUMBER_OF_PROCESSORS",
  "LANG",
  "LC_ALL",
  "LC_COLLATE",
  "LC_CTYPE",
  "LC_MESSAGES",
  "LC_MONETARY",
  "LC_NUMERIC",
  "LC_TIME",
  "TZ",
  "TERM",
  "COLORTERM",
  "FORCE_COLOR",
  "NO_COLOR",
  "CI",
  "GITHUB_ACTIONS",
  "GITHUB_REF_NAME",
  "GITHUB_SHA",
  "RUNNER_OS",
  "RUNNER_ARCH",
  "TMPDIR",
  "TMP",
  "TEMP",
  "USER",
  "LOGNAME",
  "USERNAME",
  "SHELL",
  "QUALITY_BASE",
  "M9_REQUIRE_CLEAN",
  "M9_SOURCE_SHA",
  "VSCODE_TEST_VERSION",
  "VSCODE_TEST_LABEL",
]);

const NON_AUTH_QUALITY_OVERRIDE_NAMES = Object.freeze([
  "CLOUDSMITH_QUALITY_SOURCE_SHA",
  "CLOUDSMITH_QUALITY_SOURCE_FINGERPRINT",
  "CLOUDSMITH_QUALITY_TEST_EVIDENCE",
  "CLOUDSMITH_QUALITY_TEST_SUITE",
  "SOURCE_DATE_EPOCH",
  "TZ",
]);

function assertSafeNames(names, label) {
  if (names.length !== new Set(names).size) {
    throw new Error(`${label} contains a duplicate name.`);
  }
  for (const name of names) {
    if (!/^[A-Z][A-Z0-9_]{0,127}$/u.test(name)
      || CREDENTIAL_LIKE_ENVIRONMENT_NAME.test(name)) {
      throw new Error(`${label} contains an unsafe name.`);
    }
  }
}

assertSafeNames(NON_AUTH_QUALITY_ENVIRONMENT_ALLOWLIST, "Non-auth environment allowlist");
assertSafeNames(NON_AUTH_QUALITY_OVERRIDE_NAMES, "Non-auth environment override list");
if ([...NON_AUTH_QUALITY_ENVIRONMENT_ALLOWLIST, ...NON_AUTH_QUALITY_OVERRIDE_NAMES]
  .some(name => NON_AUTH_AMBIENT_CAPABILITY_NAMES.includes(name))) {
  throw new Error("Non-auth environment cannot forward ambient display or session capabilities.");
}

function isBoundedEnvironmentValue(value) {
  return typeof value === "string"
    && value.length <= 32768
    && !value.includes("\u0000");
}

function buildNonAuthQualityEnvironment(environment = process.env, overrides = {}, options = {}) {
  if (!environment || typeof environment !== "object" || Array.isArray(environment)) {
    throw new TypeError("Non-auth quality environment must be an object.");
  }
  if (!overrides || typeof overrides !== "object" || Array.isArray(overrides)) {
    throw new TypeError("Non-auth quality environment overrides must be an object.");
  }
  const platform = options.platform || process.platform;
  const sourceNames = Object.keys(environment);
  const readAllowlistedValue = expectedName => {
    if (platform !== "win32") {
      return Object.prototype.hasOwnProperty.call(environment, expectedName)
        ? environment[expectedName]
        : undefined;
    }
    const matches = sourceNames.filter(name => name.toUpperCase() === expectedName);
    if (matches.length > 1) {
      throw new Error(`Non-auth quality environment has a case-colliding key: ${expectedName}`);
    }
    return matches.length === 1 ? environment[matches[0]] : undefined;
  };

  const sanitized = {};
  for (const name of NON_AUTH_QUALITY_ENVIRONMENT_ALLOWLIST) {
    const value = readAllowlistedValue(name);
    if (isBoundedEnvironmentValue(value)) sanitized[name] = value;
  }

  const allowedOverrides = new Set(NON_AUTH_QUALITY_OVERRIDE_NAMES);
  for (const name of Object.keys(overrides)) {
    if (!allowedOverrides.has(name) || !isBoundedEnvironmentValue(overrides[name])) {
      throw new Error(`Non-auth quality environment override is unsafe: ${String(name)}`);
    }
    sanitized[name] = overrides[name];
  }
  return Object.freeze(sanitized);
}

function privateDirectory(directory, label, expected = null) {
  const stat = fs.lstatSync(directory);
  if (stat.isSymbolicLink() || !stat.isDirectory()
    || !sameFilesystemPath(fs.realpathSync(directory), directory)
    || (process.platform !== "win32" && (stat.mode & 0o077) !== 0)
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())
    || (expected && (stat.dev !== expected.dev || stat.ino !== expected.ino))) {
    throw new Error(`${label} is not the exact creator-owned private directory.`);
  }
  return stat;
}

function privateFile(file, label, expected = null) {
  const stat = fs.lstatSync(file);
  if (stat.isSymbolicLink() || !stat.isFile()
    || !sameFilesystemPath(fs.realpathSync(file), file)
    || (process.platform !== "win32" && (stat.mode & 0o077) !== 0)
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())
    || (expected && (stat.dev !== expected.dev || stat.ino !== expected.ino))) {
    throw new Error(`${label} is not the exact creator-owned private file.`);
  }
  return stat;
}

function canonicalTemporaryParent(value) {
  if (typeof value !== "string" || !path.isAbsolute(value)
    || path.resolve(value) !== value || path.normalize(value) !== value
    || value.includes("\u0000")) {
    throw new Error("Non-auth quality temporary parent must be an absolute normalized path.");
  }
  const parent = fs.realpathSync(value);
  const stat = fs.lstatSync(parent);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error("Non-auth quality temporary parent must resolve to a real directory.");
  }
  return parent;
}

function createPrivateDirectory(root, name, cleanupEntries = null) {
  const directory = path.join(root, name);
  fs.mkdirSync(directory, { mode: 0o700 });
  if (process.platform !== "win32") fs.chmodSync(directory, 0o700);
  const stat = privateDirectory(directory, `Non-auth quality ${name}`);
  cleanupEntries?.push(Object.freeze({
    name,
    kind: "directory",
    identity: exactIdentity(stat),
  }));
  return directory;
}

function createPrivateEmptyFile(root, name, cleanupEntries = null) {
  const file = path.join(root, name);
  fs.writeFileSync(file, "", { encoding: "utf8", flag: "wx", mode: 0o600 });
  if (process.platform !== "win32") fs.chmodSync(file, 0o600);
  const stat = privateFile(file, `Non-auth quality ${name}`);
  cleanupEntries?.push(Object.freeze({
    name,
    kind: "file",
    identity: exactIdentity(stat),
  }));
  return file;
}

function exactIdentity(stat) {
  return Object.freeze({ dev: stat.dev, ino: stat.ino });
}

function exactCleanupError(message) {
  throw new Error(message);
}

function cleanupEntryKind(stat, errorMessage) {
  if (stat.isDirectory()) return "directory";
  if (stat.isSymbolicLink() && stat.nlink >= 1n) return "link";
  if (stat.isFile() && stat.nlink >= 1n) return "file";
  if (process.platform !== "win32" && stat.isSocket() && stat.nlink === 1n) return "socket";
  return exactCleanupError(errorMessage);
}

function cleanupEntryIdentity(stat, kind) {
  const identity = {
    device: String(stat.dev),
    group: String(stat.gid),
    inode: String(stat.ino),
    mode: String(stat.mode),
    owner: String(stat.uid),
  };
  if (kind !== "directory") {
    Object.assign(identity, {
      modifiedNanoseconds: String(stat.mtimeNs),
      size: String(stat.size),
    });
    if (stat.nlink === 1n) {
      Object.assign(identity, {
        changedNanoseconds: String(stat.ctimeNs),
        links: String(stat.nlink),
      });
    }
  }
  return Object.freeze(identity);
}

function sameCleanupIdentity(stat, kind, identity) {
  if (cleanupEntryKind(stat, "Exact cleanup entry changed.") !== kind) return false;
  const current = cleanupEntryIdentity(stat, kind);
  return Object.entries(identity).every(([key, value]) => current[key] === value);
}

function expectedIdentityValue(identity, primary, alternate = primary) {
  const value = identity?.[primary] ?? identity?.[alternate];
  return value === undefined ? null : String(value);
}

function matchesExpectedCleanupEntry(stat, kind, expected) {
  if (!expected || expected.kind !== kind || !expected.identity) return false;
  if (String(stat.dev) !== expectedIdentityValue(expected.identity, "dev", "device")
    || String(stat.ino) !== expectedIdentityValue(expected.identity, "ino", "inode")) {
    return false;
  }
  if (kind === "directory") return true;
  for (const key of ["mode", "nlink", "size"]) {
    if (expected.identity[key] !== undefined
      && String(stat[key]) !== String(expected.identity[key])) {
      return false;
    }
  }
  return true;
}

function cleanupName(rawName, errorMessage) {
  if (!Buffer.isBuffer(rawName)
    || rawName.length === 0
    || rawName.length > EXACT_CLEANUP_MAX_NAME_BYTES) {
    return exactCleanupError(errorMessage);
  }
  const name = rawName.toString("utf8");
  if (!Buffer.from(name, "utf8").equals(rawName)
    || name === "." || name === ".."
    || name.includes("/")
    || (process.platform === "win32" && name.includes("\\"))) {
    return exactCleanupError(errorMessage);
  }
  return name;
}

function boundedDirectoryNames(directory, maximumNames, errorMessage) {
  const names = [];
  const handle = fs.opendirSync(directory, { encoding: "buffer" });
  try {
    for (let entry = handle.readSync(); entry !== null; entry = handle.readSync()) {
      names.push(cleanupName(entry.name, errorMessage));
      if (names.length > maximumNames) exactCleanupError(errorMessage);
    }
  } finally {
    handle.closeSync();
  }
  names.sort();
  if (names.length !== new Set(names).size) exactCleanupError(errorMessage);
  return names;
}

function sameCleanupNames(left, right) {
  return left.length === right.length && left.every((name, index) => name === right[index]);
}

function expectedRootCleanupEntries(entries, errorMessage) {
  if (!Array.isArray(entries) || entries.length > EXACT_CLEANUP_MAX_ENTRIES) {
    return exactCleanupError(errorMessage);
  }
  const expected = new Map();
  for (const entry of entries) {
    if (!entry || typeof entry.name !== "string"
      || !new Set(["directory", "file", "link"]).has(entry.kind)
      || entry.name !== cleanupName(Buffer.from(entry.name, "utf8"), errorMessage)
      || expected.has(entry.name)) {
      return exactCleanupError(errorMessage);
    }
    expected.set(entry.name, entry);
  }
  return expected;
}

function snapshotCleanupEntry(
  target,
  depth,
  state,
  expected,
  expectedChildren,
  allowAdditionalExpectedChildren,
  errorMessage,
) {
  if (depth > EXACT_CLEANUP_MAX_DEPTH || state.entries >= EXACT_CLEANUP_MAX_ENTRIES) {
    return exactCleanupError(errorMessage);
  }
  state.entries += 1;
  const stat = fs.lstatSync(target, { bigint: true });
  const kind = cleanupEntryKind(stat, errorMessage);
  if (kind === "socket" && state.allowSingleLinkUnixSockets !== true) {
    return exactCleanupError(errorMessage);
  }
  if (expected && !matchesExpectedCleanupEntry(stat, kind, expected)) {
    return exactCleanupError(errorMessage);
  }
  const identity = cleanupEntryIdentity(stat, kind);
  if (kind !== "directory") return Object.freeze({ identity, kind, target });

  const names = boundedDirectoryNames(
    target,
    EXACT_CLEANUP_MAX_ENTRIES - state.entries,
    errorMessage,
  );
  if (expectedChildren) {
    const requiredNames = [...expectedChildren.keys()].sort();
    if (allowAdditionalExpectedChildren
      ? requiredNames.some(name => !names.includes(name))
      : !sameCleanupNames(names, requiredNames)) {
      return exactCleanupError(errorMessage);
    }
  }
  const children = names.map(name => snapshotCleanupEntry(
    path.join(target, name),
    depth + 1,
    state,
    expectedChildren?.get(name),
    null,
    false,
    errorMessage,
  ));
  const current = fs.lstatSync(target, { bigint: true });
  if (!sameCleanupIdentity(current, kind, identity)
    || !sameCleanupNames(
      boundedDirectoryNames(target, names.length + 1, errorMessage),
      names,
    )) {
    return exactCleanupError(errorMessage);
  }
  return Object.freeze({ children: Object.freeze(children), identity, kind, target });
}

function assertCleanupEntry(node, errorMessage) {
  const stat = fs.lstatSync(node.target, { bigint: true });
  if (!sameCleanupIdentity(stat, node.kind, node.identity)) {
    return exactCleanupError(errorMessage);
  }
}

function assertCleanupDirectory(node, names, errorMessage) {
  assertCleanupEntry(node, errorMessage);
  if (!sameCleanupNames(
    boundedDirectoryNames(node.target, names.length + 1, errorMessage),
    names,
  )) {
    return exactCleanupError(errorMessage);
  }
}

function assertCleanupEntryAbsent(target, errorMessage) {
  try {
    fs.lstatSync(target);
  } catch (error) {
    if (error.code === "ENOENT") return;
    return exactCleanupError(errorMessage);
  }
  exactCleanupError(errorMessage);
}

function removeCleanupDirectoryChildren(node, errorMessage) {
  const names = node.children.map(child => path.basename(child.target)).sort();
  assertCleanupDirectory(node, names, errorMessage);
  for (const child of node.children) {
    assertCleanupEntry(node, errorMessage);
    removeCleanupSnapshot(child, errorMessage);
    assertCleanupEntry(node, errorMessage);
  }
  assertCleanupDirectory(node, [], errorMessage);
}

function removeCleanupSnapshot(node, errorMessage) {
  if (node.kind !== "directory") {
    assertCleanupEntry(node, errorMessage);
    fs.unlinkSync(node.target);
    assertCleanupEntryAbsent(node.target, errorMessage);
    return;
  }

  removeCleanupDirectoryChildren(node, errorMessage);
  // This must stay nonrecursive: a replacement after the final identity check
  // can make rmdir fail, but can never redirect cleanup into a nonempty tree.
  fs.rmdirSync(node.target);
  assertCleanupEntryAbsent(node.target, errorMessage);
}

function snapshotExactOwnedTree(root, options, errorMessage) {
  if (typeof root !== "string" || !path.isAbsolute(root)
    || path.normalize(root) !== root || path.resolve(root) !== root
    || root.includes("\u0000")) {
    return exactCleanupError(errorMessage);
  }
  const expectedEntries = expectedRootCleanupEntries(
    options.expectedRootEntries,
    errorMessage,
  );
  const expectedRoot = options.expectedRootIdentity
    ? { kind: "directory", identity: options.expectedRootIdentity }
    : null;
  const snapshot = snapshotCleanupEntry(
    root,
    0,
    {
      allowSingleLinkUnixSockets: options.allowSingleLinkUnixSockets === true,
      entries: 0,
    },
    expectedRoot,
    expectedEntries,
    options.allowAdditionalRootEntries === true,
    errorMessage,
  );
  if (!sameFilesystemPath(fs.realpathSync(root), root)) exactCleanupError(errorMessage);
  return snapshot;
}

function emptyExactOwnedDirectory(root, options = {}) {
  const errorMessage = options.errorMessage || "Exact cleanup refused an unsafe or changed tree.";
  try {
    const snapshot = snapshotExactOwnedTree(root, options, errorMessage);
    if (snapshot.kind !== "directory") exactCleanupError(errorMessage);
    removeCleanupDirectoryChildren(snapshot, errorMessage);
    return true;
  } catch {
    throw new Error(errorMessage);
  }
}

function removeExactOwnedDirectoryTree(root, options = {}) {
  const errorMessage = options.errorMessage || "Exact cleanup refused an unsafe or changed tree.";
  try {
    const snapshot = snapshotExactOwnedTree(root, options, errorMessage);
    removeCleanupSnapshot(snapshot, errorMessage);
    return true;
  } catch {
    throw new Error(errorMessage);
  }
}

function validateOwnershipMarker(identity) {
  privateFile(identity.marker, "Non-auth quality ownership marker", identity.markerIdentity);
  let marker;
  try {
    marker = JSON.parse(fs.readFileSync(identity.marker, "utf8"));
  } catch {
    throw new Error("Non-auth quality ownership marker is invalid.");
  }
  if (marker?.schemaVersion !== 1
    || marker.owner !== NON_AUTH_BOUNDARY_OWNER
    || marker.proof !== identity.proof
    || Object.keys(marker).sort().join(",") !== "owner,proof,schemaVersion") {
    throw new Error("Non-auth quality ownership marker is invalid.");
  }
}

function activeBoundaryIdentity(boundary) {
  if (!boundary || typeof boundary !== "object" || Array.isArray(boundary)
    || typeof boundary.root !== "string") {
    throw new TypeError("Non-auth quality boundary authentication requires its creator-owned boundary.");
  }
  const identity = activeBoundaries.get(boundary.root);
  if (!identity
    || identity.boundary !== boundary
    || boundary.paths !== identity.paths
    || boundary.environment !== identity.environment
    || path.dirname(boundary.root) !== identity.parent
    || !path.basename(boundary.root).startsWith(NON_AUTH_BOUNDARY_PREFIX)) {
    throw new Error("Non-auth quality boundary authentication refuses an unknown boundary.");
  }
  privateDirectory(boundary.root, "Non-auth quality boundary", identity.rootIdentity);
  validateOwnershipMarker(identity);
  for (const name of NON_AUTH_BOUNDARY_DIRECTORY_PATHS) {
    privateDirectory(
      boundary.paths[name],
      `Non-auth quality ${name}`,
      identity.pathIdentities[name],
    );
  }
  for (const name of NON_AUTH_BOUNDARY_EMPTY_FILE_PATHS) {
    const stat = privateFile(
      boundary.paths[name],
      `Non-auth quality ${name}`,
      identity.pathIdentities[name],
    );
    if (stat.size !== 0) {
      throw new Error(`Non-auth quality ${name} must remain exactly empty.`);
    }
  }
  return identity;
}

function assertActiveNonAuthQualityBoundary(boundary, environment = boundary?.environment) {
  activeBoundaryIdentity(boundary);
  if (environment !== boundary.environment) {
    throw new Error("Non-auth quality boundary environment is not the exact active environment.");
  }
  return boundary;
}

function removeCreatedBoundary(root, identity, expectedRootEntries = undefined, options = {}) {
  if (!root || !identity) return Object.freeze({ reoccupied: false });
  privateDirectory(root, "Non-auth quality boundary", identity);
  const quarantine = path.join(
    path.dirname(root),
    `.${path.basename(root)}.cleanup-${crypto.randomBytes(16).toString("hex")}`,
  );
  if (fs.existsSync(quarantine)) {
    throw new Error("Non-auth quality boundary cleanup quarantine already exists.");
  }
  fs.renameSync(root, quarantine);
  privateDirectory(quarantine, "Quarantined non-auth quality boundary", identity);
  removeExactOwnedDirectoryTree(quarantine, {
    allowSingleLinkUnixSockets: options.allowSingleLinkUnixSockets === true,
    errorMessage: "Non-auth quality boundary cleanup refused an unsafe or changed tree.",
    expectedRootEntries,
    expectedRootIdentity: identity,
  });
  return Object.freeze({ reoccupied: fs.existsSync(root) });
}

function nonAuthBoundaryCleanupEntries(identity) {
  return Object.freeze([
    ...NON_AUTH_BOUNDARY_DIRECTORY_PATHS.map(name => Object.freeze({
      name: path.basename(identity.paths[name]),
      kind: "directory",
      identity: identity.pathIdentities[name],
    })),
    ...NON_AUTH_BOUNDARY_EMPTY_FILE_PATHS.map(name => Object.freeze({
      name: path.basename(identity.paths[name]),
      kind: "file",
      identity: identity.pathIdentities[name],
    })),
    Object.freeze({
      name: path.basename(identity.marker),
      kind: "file",
      identity: identity.markerIdentity,
    }),
  ]);
}

function createNonAuthQualityEnvironment(options = {}) {
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    throw new TypeError("Non-auth quality boundary options must be an object.");
  }
  const environment = Object.prototype.hasOwnProperty.call(options, "environment")
    ? options.environment
    : process.env;
  const overrides = Object.prototype.hasOwnProperty.call(options, "overrides")
    ? options.overrides
    : {};
  const baseEnvironment = buildNonAuthQualityEnvironment(environment, overrides, {
    platform: options.platform,
  });
  const temporaryParent = options.temporaryParent === undefined
    ? (process.platform === "darwin" ? "/tmp" : os.tmpdir())
    : options.temporaryParent;
  const parent = canonicalTemporaryParent(temporaryParent);
  let root = null;
  let rootIdentity = null;
  const createdRootEntries = [];
  try {
    root = fs.mkdtempSync(path.join(parent, NON_AUTH_BOUNDARY_PREFIX));
    rootIdentity = fs.lstatSync(root);
    const canonicalRoot = fs.realpathSync(root);
    if (!sameFilesystemPath(root, canonicalRoot)) {
      throw new Error("Non-auth quality boundary root is not canonical.");
    }
    root = canonicalRoot;
    if (path.dirname(root) !== parent
      || !path.basename(root).startsWith(NON_AUTH_BOUNDARY_PREFIX)) {
      throw new Error("Non-auth quality boundary escaped its canonical temporary parent.");
    }
    if (process.platform !== "win32") fs.chmodSync(root, 0o700);
    privateDirectory(root, "Non-auth quality boundary", rootIdentity);
    rootIdentity = fs.lstatSync(root);

    const paths = Object.freeze({
      home: createPrivateDirectory(root, "home", createdRootEntries),
      xdgConfig: createPrivateDirectory(root, "xdg-config", createdRootEntries),
      xdgCache: createPrivateDirectory(root, "xdg-cache", createdRootEntries),
      xdgData: createPrivateDirectory(root, "xdg-data", createdRootEntries),
      xdgState: createPrivateDirectory(root, "xdg-state", createdRootEntries),
      appData: createPrivateDirectory(root, "app-data", createdRootEntries),
      localAppData: createPrivateDirectory(root, "local-app-data", createdRootEntries),
      temporary: createPrivateDirectory(root, "tmp", createdRootEntries),
      npmCache: createPrivateDirectory(root, "npm-cache", createdRootEntries),
      npmUserConfig: createPrivateEmptyFile(root, "npm-userconfig", createdRootEntries),
      npmGlobalConfig: createPrivateEmptyFile(root, "npm-globalconfig", createdRootEntries),
      gitGlobalConfig: createPrivateEmptyFile(root, "git-global-config", createdRootEntries),
    });
    const proof = crypto.randomBytes(32).toString("hex");
    const marker = path.join(root, NON_AUTH_BOUNDARY_MARKER);
    fs.writeFileSync(marker, `${JSON.stringify({
      schemaVersion: 1,
      owner: NON_AUTH_BOUNDARY_OWNER,
      proof,
    })}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    if (process.platform !== "win32") fs.chmodSync(marker, 0o600);
    const markerIdentity = privateFile(marker, "Non-auth quality ownership marker");
    createdRootEntries.push(Object.freeze({
      name: NON_AUTH_BOUNDARY_MARKER,
      kind: "file",
      identity: exactIdentity(markerIdentity),
    }));
    const pathIdentities = Object.freeze(Object.fromEntries(
      Object.entries(paths).map(([name, target]) => [name, exactIdentity(fs.lstatSync(target))])
    ));

    const childEnvironment = Object.freeze({
      ...baseEnvironment,
      HOME: paths.home,
      USERPROFILE: paths.home,
      XDG_CONFIG_HOME: paths.xdgConfig,
      XDG_CACHE_HOME: paths.xdgCache,
      XDG_DATA_HOME: paths.xdgData,
      XDG_STATE_HOME: paths.xdgState,
      APPDATA: paths.appData,
      LOCALAPPDATA: paths.localAppData,
      TMPDIR: paths.temporary,
      TMP: paths.temporary,
      TEMP: paths.temporary,
      NPM_CONFIG_USERCONFIG: paths.npmUserConfig,
      NPM_CONFIG_GLOBALCONFIG: paths.npmGlobalConfig,
      NPM_CONFIG_CACHE: paths.npmCache,
      NPM_CONFIG_UPDATE_NOTIFIER: "false",
      NPM_CONFIG_FUND: "false",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: paths.gitGlobalConfig,
      GIT_CONFIG_COUNT: "0",
      GIT_ATTR_NOSYSTEM: "1",
      GIT_TERMINAL_PROMPT: "0",
      GCM_INTERACTIVE: "never",
    });
    const boundary = Object.freeze({ root, paths, environment: childEnvironment });
    activeBoundaries.set(root, Object.freeze({
      boundary,
      environment: childEnvironment,
      parent,
      paths,
      pathIdentities,
      proof,
      rootIdentity,
      marker,
      markerIdentity,
    }));
    return boundary;
  } catch (error) {
    removeCreatedBoundary(root, rootIdentity, createdRootEntries);
    throw error;
  }
}

function cleanupNonAuthQualityEnvironment(boundary) {
  const identity = activeBoundaryIdentity(boundary);
  const removal = removeCreatedBoundary(
    boundary.root,
    identity.rootIdentity,
    nonAuthBoundaryCleanupEntries(identity),
    { allowSingleLinkUnixSockets: true },
  );
  activeBoundaries.delete(boundary.root);
  if (removal.reoccupied) {
    throw new Error("Non-auth quality boundary path was reoccupied during cleanup.");
  }
  return true;
}

function withNonAuthQualityEnvironment(options, callback) {
  if (typeof callback !== "function") {
    throw new TypeError("Non-auth quality boundary callback must be a function.");
  }
  const boundary = createNonAuthQualityEnvironment(options);
  try {
    const result = callback(boundary.environment, boundary);
    if (result && typeof result.then === "function") {
      throw new Error("Non-auth quality boundary callback must remain synchronous.");
    }
    return result;
  } finally {
    cleanupNonAuthQualityEnvironment(boundary);
  }
}

module.exports = {
  CREDENTIAL_LIKE_ENVIRONMENT_NAME,
  NON_AUTH_AMBIENT_CAPABILITY_NAMES,
  NON_AUTH_BOUNDARY_PREFIX,
  NON_AUTH_QUALITY_ENVIRONMENT_ALLOWLIST,
  NON_AUTH_QUALITY_OVERRIDE_NAMES,
  assertActiveNonAuthQualityBoundary,
  buildNonAuthQualityEnvironment,
  cleanupNonAuthQualityEnvironment,
  createNonAuthQualityEnvironment,
  emptyExactOwnedDirectory,
  removeExactOwnedDirectoryTree,
  withNonAuthQualityEnvironment,
};

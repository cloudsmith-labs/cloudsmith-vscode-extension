// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const {
  emptyExactOwnedDirectory,
  removeExactOwnedDirectoryTree,
} = require("./non-auth-environment");

const LOCAL_PROFILE_BASENAME = ".cloudsmith-vscode-qualification";
const CI_PROFILE_PREFIX = "csvq-";
const PROFILE_MARKER = ".cloudsmith-qualification-owner.json";
const PROFILE_OWNER = "cloudsmith-vscode-qualification";
const LOCAL_PROFILE_SUBDIRECTORIES = Object.freeze(["home", "user-data", "extensions"]);
const CI_PROFILE_SUBDIRECTORIES = Object.freeze(["home", "settings", "extensions"]);
const activeCiProfiles = new Map();

function assertAbsoluteNormalizedPath(value, label) {
  if (typeof value !== "string"
    || value.length === 0
    || value.includes("\u0000")
    || !path.isAbsolute(value)
    || path.normalize(value) !== value
    || path.resolve(value) !== value) {
    throw new Error(`${label} must be an absolute, normalized, traversal-free path.`);
  }
  return value;
}

function assertPrivateRealDirectory(directory, label) {
  const normalized = assertAbsoluteNormalizedPath(directory, label);
  const stat = fs.lstatSync(normalized);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(`${label} must be a real directory, not a symbolic link.`);
  }
  if (process.platform !== "win32" && (stat.mode & 0o077) !== 0) {
    throw new Error(`${label} must not grant group or other permissions.`);
  }
  if (fs.realpathSync(normalized) !== normalized) {
    throw new Error(`${label} must use its exact real path.`);
  }
  return stat;
}

function canonicalLocalProfileRoot(homeDirectory = os.homedir()) {
  const home = assertAbsoluteNormalizedPath(homeDirectory, "Qualification home");
  const stat = fs.lstatSync(home);
  if (stat.isSymbolicLink() || !stat.isDirectory() || fs.realpathSync(home) !== home) {
    throw new Error("Qualification home must be an exact real directory.");
  }
  return path.join(home, LOCAL_PROFILE_BASENAME);
}

function createPrivateDirectory(directory) {
  fs.mkdirSync(directory, { mode: 0o700 });
  if (process.platform !== "win32") fs.chmodSync(directory, 0o700);
  assertPrivateRealDirectory(directory, "Qualification profile directory");
}

function createOwnedSubdirectory(root, name, cleanupEntries = null) {
  const target = path.join(root, name);
  if (!fs.existsSync(target)) {
    createPrivateDirectory(target);
    const stat = fs.lstatSync(target);
    cleanupEntries?.push(Object.freeze({
      name,
      kind: "directory",
      identity: Object.freeze({ dev: stat.dev, ino: stat.ino }),
    }));
    return target;
  }
  const stat = assertPrivateRealDirectory(target, `Qualification ${name} directory`);
  if (path.dirname(target) !== root) {
    throw new Error(`Qualification ${name} directory escaped its owned profile.`);
  }
  cleanupEntries?.push(Object.freeze({
    name,
    kind: "directory",
    identity: Object.freeze({ dev: stat.dev, ino: stat.ino }),
  }));
  return target;
}

function markerPath(root) {
  return path.join(root, PROFILE_MARKER);
}

function lstatIfPresent(target) {
  try {
    return fs.lstatSync(target);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

function writeMarker(root, mode, proof) {
  const marker = {
    schemaVersion: 1,
    owner: PROFILE_OWNER,
    mode,
    proof,
  };
  fs.writeFileSync(
    markerPath(root),
    `${JSON.stringify(marker)}\n`,
    { encoding: "utf8", flag: "wx", mode: 0o600 },
  );
  return marker;
}

function readMarker(root) {
  const target = markerPath(root);
  const stat = fs.lstatSync(target);
  if (stat.isSymbolicLink() || !stat.isFile()
    || (process.platform !== "win32" && (stat.mode & 0o077) !== 0)
    || stat.size > 1024) {
    throw new Error("Qualification profile ownership marker is not a private regular file.");
  }
  let marker;
  try {
    marker = JSON.parse(fs.readFileSync(target, "utf8"));
  } catch {
    throw new Error("Qualification profile ownership marker is invalid.");
  }
  if (marker?.schemaVersion !== 1
    || marker.owner !== PROFILE_OWNER
    || !new Set(["local", "ci"]).has(marker.mode)
    || !/^[a-f0-9]{64}$/u.test(marker.proof || "")
    || Object.keys(marker).sort().join(",") !== "mode,owner,proof,schemaVersion") {
    throw new Error("Qualification profile ownership marker is invalid.");
  }
  return marker;
}

function assertLegacyDirectoryIdentity(target, label, expected = null) {
  const normalized = assertAbsoluteNormalizedPath(target, label);
  const stat = fs.lstatSync(normalized);
  if (stat.isSymbolicLink() || !stat.isDirectory()
    || fs.realpathSync(normalized) !== normalized
    || (expected && (stat.dev !== expected.dev || stat.ino !== expected.ino))) {
    throw new Error(`${label} must remain a real directory, not a symbolic link.`);
  }
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
    throw new Error(`${label} must be owned by the qualification process user.`);
  }
  return stat;
}

function adoptLegacyLocalQualificationProfile(root, options = {}) {
  const expectedRoot = assertAbsoluteNormalizedPath(root, "Legacy local profile root");
  if (expectedRoot !== canonicalLocalProfileRoot(options.homeDirectory || os.homedir())) {
    throw new Error("Legacy qualification adoption refuses a noncanonical profile root.");
  }
  const markerTarget = markerPath(expectedRoot);
  if (lstatIfPresent(markerTarget)) {
    throw new Error("Legacy qualification adoption requires an absent ownership marker.");
  }
  const rootStat = assertLegacyDirectoryIdentity(
    expectedRoot, "Legacy local qualification profile root"
  );
  const userDataDir = path.join(expectedRoot, "user-data");
  const extensionsDir = path.join(expectedRoot, "extensions");
  const homeDir = path.join(expectedRoot, "home");
  const userDataStat = assertLegacyDirectoryIdentity(
    userDataDir, "Legacy local qualification user-data"
  );
  const extensionsStat = assertLegacyDirectoryIdentity(
    extensionsDir, "Legacy local qualification extensions"
  );
  if (userDataStat.dev !== rootStat.dev || extensionsStat.dev !== rootStat.dev) {
    throw new Error("Legacy qualification directories must share the canonical root filesystem.");
  }
  if (lstatIfPresent(homeDir)) {
    throw new Error("Legacy qualification adoption refuses an unexpected home path.");
  }

  const identities = [
    [expectedRoot, "Legacy local qualification profile root", rootStat],
    [userDataDir, "Legacy local qualification user-data", userDataStat],
    [extensionsDir, "Legacy local qualification extensions", extensionsStat],
  ];
  for (const [target, label, identity] of identities) {
    assertLegacyDirectoryIdentity(target, label, identity);
    if (process.platform !== "win32") fs.chmodSync(target, 0o700);
    assertPrivateRealDirectory(target, label);
    assertLegacyDirectoryIdentity(target, label, identity);
  }

  createPrivateDirectory(homeDir);
  const homeStat = fs.lstatSync(homeDir);
  if (homeStat.dev !== rootStat.dev) {
    fs.rmdirSync(homeDir);
    throw new Error("Legacy qualification home must remain on the canonical root filesystem.");
  }
  let createdMarkerStat = null;
  try {
    for (const [target, label, identity] of identities) {
      assertLegacyDirectoryIdentity(target, label, identity);
    }
    if (lstatIfPresent(markerTarget)) {
      throw new Error("Legacy qualification ownership marker appeared during adoption.");
    }
    const marker = writeMarker(
      expectedRoot, "local", crypto.randomBytes(32).toString("hex")
    );
    createdMarkerStat = fs.lstatSync(markerTarget);
    for (const [target, label, identity] of identities) {
      assertLegacyDirectoryIdentity(target, label, identity);
    }
    assertLegacyDirectoryIdentity(homeDir, "Legacy local qualification home", homeStat);
    return marker;
  } catch (error) {
    if (createdMarkerStat) {
      const currentMarker = lstatIfPresent(markerTarget);
      if (currentMarker && !currentMarker.isSymbolicLink() && currentMarker.isFile()
        && currentMarker.dev === createdMarkerStat.dev
        && currentMarker.ino === createdMarkerStat.ino) {
        fs.unlinkSync(markerTarget);
      }
    }
    if (!lstatIfPresent(markerTarget)) {
      const currentHome = lstatIfPresent(homeDir);
      if (currentHome && !currentHome.isSymbolicLink() && currentHome.isDirectory()
        && currentHome.dev === homeStat.dev && currentHome.ino === homeStat.ino) {
        try {
          fs.rmdirSync(homeDir);
        } catch {
          // A no-longer-empty/replaced path is never removed by adoption rollback.
        }
      }
    }
    throw error;
  }
}

function profileDescriptor(root, mode, proof) {
  const userDataName = mode === "local" ? "user-data" : "settings";
  return Object.freeze({
    mode,
    persistent: mode === "local",
    root,
    testResourcesDir: root,
    homeDir: path.join(root, "home"),
    userDataDir: path.join(root, userDataName),
    extensionsDir: path.join(root, "extensions"),
    cleanupProof: proof,
  });
}

function validateProfileLayout(root, mode, proof) {
  const stat = assertPrivateRealDirectory(root, "Qualification profile root");
  const marker = readMarker(root);
  if (marker.mode !== mode || marker.proof !== proof) {
    throw new Error("Qualification profile ownership does not match this run.");
  }
  const subdirectories = mode === "local"
    ? LOCAL_PROFILE_SUBDIRECTORIES
    : CI_PROFILE_SUBDIRECTORIES;
  for (const name of subdirectories) {
    const directory = path.join(root, name);
    const child = assertPrivateRealDirectory(directory, `Qualification ${name} directory`);
    if (child.dev !== stat.dev) {
      throw new Error("Qualification profile directories must remain on the owned filesystem.");
    }
  }
  return stat;
}

function ciProfileCleanupEntries(root) {
  return Object.freeze([
    Object.freeze({
      name: PROFILE_MARKER,
      kind: "file",
      identity: fs.lstatSync(markerPath(root)),
    }),
    ...CI_PROFILE_SUBDIRECTORIES.map(name => Object.freeze({
      name,
      kind: "directory",
      identity: fs.lstatSync(path.join(root, name)),
    })),
  ]);
}

function matchesCiProfileEntry(stat, entry) {
  if (!entry?.identity || stat.isSymbolicLink()
    || (entry.kind === "directory" ? !stat.isDirectory() : !stat.isFile())
    || String(stat.dev) !== String(entry.identity.dev)
    || String(stat.ino) !== String(entry.identity.ino)) {
    return false;
  }
  if (entry.kind === "directory") return true;
  return ["mode", "nlink", "size"].every(key => (
    entry.identity[key] === undefined
      || String(stat[key]) === String(entry.identity[key])
  ));
}

function assertCiProfileResetSiblings(root, identity) {
  for (const entry of identity.entries) {
    if (entry.name === "settings") continue;
    let stat;
    try {
      stat = fs.lstatSync(path.join(root, entry.name));
    } catch {
      throw new Error("Qualification reset refuses a changed profile entry.");
    }
    if (!matchesCiProfileEntry(stat, entry)) {
      throw new Error("Qualification reset refuses a changed profile entry.");
    }
  }
  let marker;
  try {
    marker = readMarker(root);
  } catch {
    throw new Error("Qualification reset refuses a changed profile entry.");
  }
  if (marker.mode !== "ci" || marker.proof !== identity.proof) {
    throw new Error("Qualification reset refuses a changed profile entry.");
  }
}

function localProfileCleanupEntries(root) {
  return Object.freeze([
    Object.freeze({
      name: PROFILE_MARKER,
      kind: "file",
      identity: fs.lstatSync(markerPath(root)),
    }),
    ...LOCAL_PROFILE_SUBDIRECTORIES.map(name => Object.freeze({
      name,
      kind: "directory",
      identity: fs.lstatSync(path.join(root, name)),
    })),
  ]);
}

function prepareLocalQualificationProfile(options = {}) {
  const homeDirectory = options.homeDirectory || os.homedir();
  const expectedRoot = canonicalLocalProfileRoot(homeDirectory);
  if (options.profileRoot !== undefined) {
    const supplied = assertAbsoluteNormalizedPath(options.profileRoot, "Local profile root");
    if (supplied !== expectedRoot) {
      throw new Error(`Local qualification profile must be exactly ${expectedRoot}.`);
    }
  }

  let marker;
  if (!fs.existsSync(expectedRoot)) {
    createPrivateDirectory(expectedRoot);
    const createdRootIdentity = fs.lstatSync(expectedRoot);
    const createdRootEntries = [];
    try {
      marker = writeMarker(expectedRoot, "local", crypto.randomBytes(32).toString("hex"));
      const markerIdentity = fs.lstatSync(markerPath(expectedRoot));
      createdRootEntries.push(Object.freeze({
        name: PROFILE_MARKER,
        kind: "file",
        identity: Object.freeze({ dev: markerIdentity.dev, ino: markerIdentity.ino }),
      }));
      for (const name of LOCAL_PROFILE_SUBDIRECTORIES) {
        createOwnedSubdirectory(expectedRoot, name, createdRootEntries);
      }
    } catch (error) {
      removeExactOwnedDirectoryTree(expectedRoot, {
        errorMessage: "Local qualification profile rollback refused an unsafe or changed tree.",
        expectedRootEntries: createdRootEntries,
        expectedRootIdentity: createdRootIdentity,
      });
      throw error;
    }
  } else {
    const existingMarker = lstatIfPresent(markerPath(expectedRoot));
    if (!existingMarker) {
      marker = adoptLegacyLocalQualificationProfile(expectedRoot, { homeDirectory });
    } else {
      assertPrivateRealDirectory(expectedRoot, "Local qualification profile root");
      marker = readMarker(expectedRoot);
      if (marker.mode !== "local") {
        throw new Error("Canonical local qualification root is not a local profile.");
      }
      for (const name of LOCAL_PROFILE_SUBDIRECTORIES) {
        createOwnedSubdirectory(expectedRoot, name);
      }
    }
  }
  validateProfileLayout(expectedRoot, "local", marker.proof);
  return profileDescriptor(expectedRoot, "local", marker.proof);
}

function resetLocalQualificationProfile(options = {}) {
  const homeDirectory = options.homeDirectory || os.homedir();
  const expectedRoot = canonicalLocalProfileRoot(homeDirectory);
  if (options.profileRoot !== undefined) {
    const supplied = assertAbsoluteNormalizedPath(options.profileRoot, "Local profile root");
    if (supplied !== expectedRoot) {
      throw new Error("Local qualification reset refuses a noncanonical profile root.");
    }
  }
  let entry;
  try {
    entry = fs.lstatSync(expectedRoot);
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
  if (entry.isSymbolicLink() || !entry.isDirectory()) {
    throw new Error("Local qualification reset refuses a symbolic link or non-directory root.");
  }
  const rootStat = assertPrivateRealDirectory(expectedRoot, "Local qualification profile root");
  const marker = readMarker(expectedRoot);
  if (marker.mode !== "local") {
    throw new Error("Local qualification reset refuses an unknown profile owner.");
  }
  validateProfileLayout(expectedRoot, "local", marker.proof);
  const current = fs.lstatSync(expectedRoot);
  if (current.isSymbolicLink() || !current.isDirectory()
    || current.dev !== rootStat.dev || current.ino !== rootStat.ino) {
    throw new Error("Local qualification reset refuses a replaced profile root.");
  }
  removeExactOwnedDirectoryTree(expectedRoot, {
    allowAdditionalRootEntries: true,
    errorMessage: "Local qualification reset refuses an unsafe or changed profile tree.",
    expectedRootEntries: localProfileCleanupEntries(expectedRoot),
    expectedRootIdentity: rootStat,
  });
  return true;
}

function createCiQualificationProfile(options = {}) {
  const platformTemporaryParent = process.platform === "darwin"
    ? fs.realpathSync("/tmp")
    : os.tmpdir();
  const parentInput = options.temporaryParent || platformTemporaryParent;
  assertAbsoluteNormalizedPath(parentInput, "CI temporary parent");
  const parent = fs.realpathSync(parentInput);
  const parentStat = fs.lstatSync(parent);
  if (parentStat.isSymbolicLink() || !parentStat.isDirectory()) {
    throw new Error("CI temporary parent must resolve to a real directory.");
  }
  const root = fs.mkdtempSync(path.join(parent, CI_PROFILE_PREFIX));
  const createdRootIdentity = fs.lstatSync(root);
  const createdRootEntries = [];
  try {
    if (process.platform !== "win32") fs.chmodSync(root, 0o700);
    const proof = crypto.randomBytes(32).toString("hex");
    writeMarker(root, "ci", proof);
    const markerIdentity = fs.lstatSync(markerPath(root));
    createdRootEntries.push(Object.freeze({
      name: PROFILE_MARKER,
      kind: "file",
      identity: Object.freeze({ dev: markerIdentity.dev, ino: markerIdentity.ino }),
    }));
    for (const name of CI_PROFILE_SUBDIRECTORIES) {
      createOwnedSubdirectory(root, name, createdRootEntries);
    }
    const stat = validateProfileLayout(root, "ci", proof);
    activeCiProfiles.set(root, Object.freeze({
      device: stat.dev,
      entries: ciProfileCleanupEntries(root),
      inode: stat.ino,
      parent,
      proof,
      rootIdentity: stat,
    }));
    return profileDescriptor(root, "ci", proof);
  } catch (error) {
    removeExactOwnedDirectoryTree(root, {
      errorMessage: "CI qualification profile rollback refused an unsafe or changed tree.",
      expectedRootEntries: createdRootEntries,
      expectedRootIdentity: createdRootIdentity,
    });
    throw error;
  }
}

function cleanupCiQualificationProfile(profile) {
  if (!profile || profile.mode !== "ci") {
    throw new Error("Qualification cleanup refuses persistent or unknown profiles.");
  }
  const root = assertAbsoluteNormalizedPath(profile.root, "CI qualification profile root");
  const identity = activeCiProfiles.get(root);
  if (!identity
    || path.dirname(root) !== identity.parent
    || profile.cleanupProof !== identity.proof) {
    throw new Error("Qualification cleanup refuses a profile it did not create.");
  }
  if (!fs.existsSync(root)) {
    activeCiProfiles.delete(root);
    return false;
  }
  const stat = fs.lstatSync(root);
  if (stat.isSymbolicLink() || !stat.isDirectory()
    || stat.dev !== identity.device || stat.ino !== identity.inode) {
    throw new Error("Qualification cleanup refuses a replaced profile root.");
  }
  removeExactOwnedDirectoryTree(root, {
    allowAdditionalRootEntries: true,
    errorMessage: "Qualification cleanup refuses an unsafe or changed profile tree.",
    expectedRootEntries: identity.entries,
    expectedRootIdentity: identity.rootIdentity,
  });
  activeCiProfiles.delete(root);
  return true;
}

function resetCiQualificationUserData(profile) {
  if (!profile || profile.mode !== "ci") {
    throw new Error("Qualification reset refuses persistent or unknown profiles.");
  }
  const root = assertAbsoluteNormalizedPath(profile.root, "CI qualification profile root");
  const identity = activeCiProfiles.get(root);
  if (!identity
    || path.dirname(root) !== identity.parent
    || profile.cleanupProof !== identity.proof
    || profile.userDataDir !== path.join(root, "settings")) {
    throw new Error("Qualification reset refuses a profile it did not create.");
  }
  const rootStat = fs.lstatSync(root);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()
    || rootStat.dev !== identity.device || rootStat.ino !== identity.inode) {
    throw new Error("Qualification reset refuses a replaced profile root.");
  }
  const userDataDir = profile.userDataDir;
  const userDataIdentity = identity.entries.find(entry => entry.name === "settings");
  if (!userDataIdentity || userDataIdentity.kind !== "directory") {
    throw new Error("Qualification reset refuses an unknown user-data directory.");
  }
  assertCiProfileResetSiblings(root, identity);
  emptyExactOwnedDirectory(userDataDir, {
    allowAdditionalRootEntries: true,
    errorMessage: "Qualification reset refuses an unsafe or changed user-data tree.",
    expectedRootEntries: [],
    expectedRootIdentity: userDataIdentity.identity,
  });
  const currentRoot = fs.lstatSync(root);
  if (currentRoot.isSymbolicLink() || !currentRoot.isDirectory()
    || currentRoot.dev !== identity.device || currentRoot.ino !== identity.inode) {
    throw new Error("Qualification profile root changed during user-data reset.");
  }
  const resetStat = assertPrivateRealDirectory(
    userDataDir,
    "Reset qualification user-data",
  );
  if (!matchesCiProfileEntry(resetStat, userDataIdentity)) {
    throw new Error("Qualification reset refuses a changed user-data directory.");
  }
  assertCiProfileResetSiblings(root, identity);
  return userDataDir;
}

function parseNulList(value) {
  return String(value || "").split("\u0000").filter(Boolean);
}

function gitListedAppleMetadata(repositoryRoot, spawn = spawnSync, environment = undefined) {
  const pathspecs = ["--", ".DS_Store", ":(glob)**/.DS_Store", ":(glob)**/._*"];
  const commands = [
    ["ls-files", "--others", "--exclude-standard", "-z", ...pathspecs],
    ["ls-files", "--others", "--ignored", "--exclude-standard", "-z", ...pathspecs],
  ];
  const files = new Set();
  for (const arguments_ of commands) {
    const result = spawn("git", arguments_, {
      cwd: repositoryRoot,
      encoding: "utf8",
      env: environment,
      maxBuffer: 4 * 1024 * 1024,
    });
    if (result.error) throw result.error;
    if (result.signal || result.status !== 0) {
      throw new Error("Git could not enumerate safe Apple metadata candidates.");
    }
    for (const file of parseNulList(result.stdout)) files.add(file);
  }
  return [...files].sort();
}

function removeSafeAppleMetadata(repositoryRoot, options = {}) {
  const root = assertAbsoluteNormalizedPath(repositoryRoot, "Repository root");
  const stat = fs.lstatSync(root);
  if (stat.isSymbolicLink() || !stat.isDirectory() || fs.realpathSync(root) !== root) {
    throw new Error("Apple metadata cleanup requires an exact real repository root.");
  }
  const listed = gitListedAppleMetadata(
    root,
    options.spawnSync || spawnSync,
    options.environment,
  );
  const removed = [];
  for (const relative of listed) {
    if (typeof relative !== "string"
      || relative.includes("\u0000")
      || path.posix.isAbsolute(relative)
      || path.win32.isAbsolute(relative)
      || path.posix.normalize(relative) !== relative
      || relative.includes("\\")
      || relative === ".."
      || relative.startsWith("../")) {
      throw new Error("Git returned an unsafe Apple metadata path.");
    }
    const base = path.posix.basename(relative);
    if (base !== ".DS_Store" && !base.startsWith("._")) {
      throw new Error("Cleanup refuses files outside the Apple metadata allowlist.");
    }
    const target = path.join(root, ...relative.split("/"));
    let targetStat;
    try {
      targetStat = fs.lstatSync(target);
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    const parent = fs.realpathSync(path.dirname(target));
    if (parent !== root && !parent.startsWith(`${root}${path.sep}`)) {
      throw new Error("Apple metadata cleanup path escaped the repository.");
    }
    if (targetStat.isSymbolicLink() || !targetStat.isFile()) {
      throw new Error("Apple metadata cleanup removes only real regular files.");
    }
    fs.unlinkSync(target);
    removed.push(relative);
  }
  return Object.freeze(removed);
}

module.exports = {
  CI_PROFILE_PREFIX,
  LOCAL_PROFILE_BASENAME,
  PROFILE_MARKER,
  adoptLegacyLocalQualificationProfile,
  canonicalLocalProfileRoot,
  cleanupCiQualificationProfile,
  createCiQualificationProfile,
  gitListedAppleMetadata,
  prepareLocalQualificationProfile,
  removeSafeAppleMetadata,
  resetLocalQualificationProfile,
  resetCiQualificationUserData,
};

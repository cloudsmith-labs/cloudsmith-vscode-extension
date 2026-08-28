// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const { TextDecoder } = require("util");
const {
  ROOT,
  assertRepositoryRelativePath,
  removeOutputFile,
  resolveExistingRepositoryFile,
  resolveOptionalRepositoryFile,
  writeFile,
  writeJson,
} = require("./common");
const { fingerprint, sourceIdentity } = require("./evidence");
const {
  assertActiveNonAuthQualityBoundary,
  removeExactOwnedDirectoryTree,
} = require("./non-auth-environment");
const {
  AUTHENTICATED_CANDIDATE_ARTIFACT,
  AUTHENTICATED_CANDIDATE_RECEIPT,
  LIVE_CANDIDATE_ARTIFACT,
  LIVE_CANDIDATE_RECEIPT,
  UI_CANDIDATE_ARTIFACT,
  UI_CANDIDATE_RECEIPT,
  sameExactFileIdentity,
  withStableSingleLinkFile,
} = require("./candidate-binding");
const {
  cleanupCiQualificationProfile,
  createCiQualificationProfile,
  prepareLocalQualificationProfile,
  removeSafeAppleMetadata,
} = require("./qualification-profile");
const { assertVersionState } = require("../release/verify-version");
const {
  readProvenanceSidecar,
  validateSidecars,
  verifyVsix,
  withStableArtifact,
  withStableSidecarSet,
} = require("../release/verify-vsix");

const CANDIDATE_RECEIPT = ".quality/qualification/candidate.json";
const MAX_PACKAGE_OUTPUT_BYTES = 16 * 1024;
const ALLOWED_ENVIRONMENT = Object.freeze([
  "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC",
  "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS",
  "LANG", "LC_ALL", "LC_COLLATE", "LC_CTYPE", "LC_MESSAGES",
  "TERM", "COLORTERM", "FORCE_COLOR", "NO_COLOR",
  "CI", "GITHUB_ACTIONS", "RUNNER_OS", "RUNNER_ARCH",
  "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS",
  "TMPDIR", "TMP", "TEMP", "M9_REQUIRE_CLEAN", "M9_SOURCE_SHA",
]);

function currentExtensionHostVersion(root) {
  const source = fs.readFileSync(
    resolveExistingRepositoryFile(".vscode-test.mjs", root), "utf8"
  );
  const matches = [...source.matchAll(
    /^const version = process\.env\.VSCODE_TEST_VERSION \|\| "(\d+\.\d+\.\d+)";\r?$/gmu
  )];
  if (matches.length !== 1) {
    throw new Error("Current local VS Code qualification version must have one canonical exact pin.");
  }
  return matches[0][1];
}

function exactVersionState(root, mode = "ci", qualificationLane = null) {
  const manifest = JSON.parse(fs.readFileSync(
    resolveExistingRepositoryFile("package.json", root), "utf8"
  ));
  const lockfile = JSON.parse(fs.readFileSync(
    resolveExistingRepositoryFile("package-lock.json", root), "utf8"
  ));
  const changelog = fs.readFileSync(
    resolveExistingRepositoryFile("CHANGELOG.md", root), "utf8"
  );
  const extension = assertVersionState({ manifest, lockfile, changelog });
  if (!new Set(["local", "ci"]).has(mode)) {
    throw new Error("Qualification version mode must be local or ci.");
  }
  const lane = qualificationLane || (mode === "local" ? "current" : "black-box");
  if (!new Set(["current", "black-box"]).has(lane)
    || (mode === "local" && lane !== "current")) {
    throw new Error("Qualification version lane is incompatible with the profile mode.");
  }
  let vscodeVersion;
  if (lane === "current") {
    vscodeVersion = currentExtensionHostVersion(root);
  } else {
    const extester = JSON.parse(fs.readFileSync(
      resolveExistingRepositoryFile("extester.config.json", root), "utf8"
    ));
    const setupVersion = extester?.setup?.vscodeVersion;
    const runVersion = extester?.run?.vscodeVersion;
    if (!/^\d+\.\d+\.\d+$/u.test(setupVersion || "")
      || runVersion !== setupVersion
      || extester?.setup?.type !== "stable"
      || extester?.run?.type !== "stable") {
      throw new Error("ExTester setup and run must use the same exact stable VS Code version.");
    }
    vscodeVersion = setupVersion;
  }
  return Object.freeze({
    ...extension,
    id: `${extension.publisher}.${extension.name}`,
    vscodeVersion,
  });
}

function assertSourceIdentity(value, label = "Qualification source") {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || !/^[0-9a-f]{40,64}$/u.test(value.sha || "")
    || !/^[0-9a-f]{64}$/u.test(value.fingerprint || "")
    || Object.keys(value).sort().join(",") !== "fingerprint,sha") {
    throw new Error(`${label} identity is invalid.`);
  }
  return value;
}

function assertStableSource(before, after) {
  assertSourceIdentity(before, "Initial qualification source");
  assertSourceIdentity(after, "Final qualification source");
  if (after.sha !== before.sha || after.fingerprint !== before.fingerprint) {
    throw new Error("Repository source changed while preparing the qualification candidate.");
  }
  return before;
}

function qualificationEnvironment(environment, profile, nonAuthBoundary = null) {
  if (!environment || typeof environment !== "object" || Array.isArray(environment)) {
    throw new Error("Qualification environment must be an object.");
  }
  const sanitized = {};
  if (nonAuthBoundary) {
    assertActiveNonAuthQualityBoundary(nonAuthBoundary, environment);
    Object.assign(sanitized, environment);
  } else {
    for (const name of ALLOWED_ENVIRONMENT) {
      const value = environment[name];
      if (typeof value === "string" && value.length <= 32768 && !value.includes("\u0000")) {
        sanitized[name] = value;
      }
    }
  }
  return Object.freeze({
    ...sanitized,
    HOME: profile.homeDir,
    USERPROFILE: profile.homeDir,
    XDG_CONFIG_HOME: path.join(profile.homeDir, ".config"),
    XDG_CACHE_HOME: path.join(profile.homeDir, ".cache"),
    XDG_DATA_HOME: path.join(profile.homeDir, ".local", "share"),
    XDG_STATE_HOME: path.join(profile.homeDir, ".local", "state"),
    APPDATA: path.join(profile.homeDir, "AppData", "Roaming"),
    LOCALAPPDATA: path.join(profile.homeDir, "AppData", "Local"),
  });
}

function runChecked(spawn, command, arguments_, options, label) {
  if (arguments_.some(argument => String(argument).includes("--extensionDevelopmentPath"))) {
    throw new Error("Qualification refuses extension development paths.");
  }
  const result = spawn(command, arguments_, {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    windowsHide: true,
    ...options,
  });
  if (result.error) throw new Error(`${label} could not start: ${result.error.message}`);
  if (result.signal || result.status !== 0) {
    throw new Error(`${label} failed without producing candidate evidence.`);
  }
  return String(result.stdout || "");
}

function removeFreshPackageOutputs(root, name, version) {
  const filename = `${name}-${version}.vsix`;
  const removed = [];
  for (const kind of ["release", "development"]) {
    for (const suffix of ["", ".sha256", ".provenance.json"]) {
      const relative = `out/${kind}/${filename}${suffix}`;
      const target = resolveOptionalRepositoryFile(relative, root);
      if (!target) continue;
      fs.unlinkSync(target);
      removed.push(relative);
    }
  }
  return Object.freeze(removed);
}

function parsePackageOutput(output, root, name, version, options = {}) {
  const errorMessage = "Canonical package output is not an exact bounded single-link file.";
  let parseError;
  let parsed;
  withStableSingleLinkFile(output, {
    errorMessage,
    fileSystem: options.fileSystem,
    maximumBytes: MAX_PACKAGE_OUTPUT_BYTES,
    minimumBytes: 1,
  }, (bytes, identity) => {
    try {
      const expectedIdentity = options.expectedIdentity;
      if (expectedIdentity && (String(expectedIdentity.dev) !== identity.device
        || String(expectedIdentity.ino) !== identity.inode)) {
        throw new Error(errorMessage);
      }
      const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      if (!text.endsWith("\n")) throw new Error("Canonical package output is incomplete.");
      const entries = new Map();
      for (const line of text.slice(0, -1).split("\n")) {
        const match = /^(vsix_path|checksum_path|provenance_path)=([^\r\n]+)$/u.exec(line);
        if (!match || entries.has(match[1])) {
          throw new Error("Canonical package output has unexpected or duplicate fields.");
        }
        entries.set(match[1], match[2]);
      }
      if (entries.size !== 3) {
        throw new Error("Canonical package output is missing required fields.");
      }
      const filename = `${name}-${version}.vsix`;
      const vsixPath = assertRepositoryRelativePath(entries.get("vsix_path"), {
        subtree: "out",
      });
      if (!new Set([
        `out/release/${filename}`,
        `out/development/${filename}`,
      ]).has(vsixPath)
        || entries.get("checksum_path") !== `${vsixPath}.sha256`
        || entries.get("provenance_path") !== `${vsixPath}.provenance.json`) {
        throw new Error(
          "Canonical package output does not identify the exact expected VSIX and sidecars.",
        );
      }
      parsed = Object.freeze({
        vsixPath,
        absoluteVsixPath: resolveExistingRepositoryFile(vsixPath, root),
        absoluteChecksumPath: resolveExistingRepositoryFile(`${vsixPath}.sha256`, root),
        absoluteProvenancePath: resolveExistingRepositoryFile(
          `${vsixPath}.provenance.json`,
          root,
        ),
      });
    } catch (error) {
      parseError = error;
    }
    return true;
  });
  if (parseError) throw parseError;
  return parsed;
}

function assertRealExecutable(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value)
    || path.resolve(value) !== value || path.normalize(value) !== value
    || value.includes("\u0000")) {
    throw new Error(`${label} must be an absolute normalized path.`);
  }
  const stat = fs.lstatSync(value);
  if (stat.isSymbolicLink() || !stat.isFile() || fs.realpathSync(value) !== value
    || (process.platform !== "win32" && (stat.mode & 0o111) === 0)) {
    throw new Error(`${label} must be an exact real file.`);
  }
  return value;
}

function assertRealDirectory(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value)
    || path.resolve(value) !== value || path.normalize(value) !== value
    || value.includes("\u0000")) {
    throw new Error(`${label} must be an absolute normalized path.`);
  }
  const stat = fs.lstatSync(value);
  if (stat.isSymbolicLink() || !stat.isDirectory() || fs.realpathSync(value) !== value) {
    throw new Error(`${label} must be an exact real directory.`);
  }
  return value;
}

function assertPathWithinBoundaryTemporary(value, nonAuthBoundary, label) {
  assertActiveNonAuthQualityBoundary(nonAuthBoundary);
  if (typeof value !== "string" || !path.isAbsolute(value)
    || path.resolve(value) !== value || path.normalize(value) !== value
    || value.includes("\u0000")) {
    throw new Error(`${label} must be an absolute normalized boundary path.`);
  }
  const stat = fs.lstatSync(value);
  const canonical = fs.realpathSync(value);
  const temporaryRoot = nonAuthBoundary.paths.temporary;
  if (stat.isSymbolicLink()
    || canonical !== value
    || !canonical.startsWith(`${temporaryRoot}${path.sep}`)) {
    throw new Error(`${label} escaped the active private non-auth temporary root.`);
  }
  return value;
}

function codePathsFromBundledCli(value) {
  if (typeof value !== "string" || !path.isAbsolute(value)
    || path.resolve(value) !== value || path.normalize(value) !== value
    || value.includes("\u0000")) {
    throw new Error("Discovered VS Code CLI path is invalid.");
  }
  const cli = assertRealExecutable(fs.realpathSync(value), "VS Code CLI");
  const appRoot = assertRealDirectory(
    path.dirname(path.dirname(cli)),
    "Visual Studio Code application root",
  );
  const contents = path.dirname(path.dirname(appRoot));
  const bundle = assertRealDirectory(path.dirname(contents), "Visual Studio Code application bundle");
  if (path.basename(bundle) !== "Visual Studio Code.app"
    || cli !== path.join(appRoot, "bin", "code")) {
    throw new Error("Discovered VS Code CLI is not app-bundled.");
  }
  const executable = assertRealExecutable(
    path.join(contents, "MacOS", "Code"),
    "VS Code executable",
  );
  return Object.freeze({ executable, cli, appRoot });
}

function commandVCode(options) {
  let result;
  try {
    result = options.spawnSync("/bin/sh", ["-c", "command -v code"], {
      cwd: options.root,
      env: options.environment,
      encoding: "utf8",
      maxBuffer: 16 * 1024,
      shell: false,
      windowsHide: true,
    });
  } catch {
    return null;
  }
  if (!result || result.error || result.signal || result.status !== 0) return null;
  const lines = String(result.stdout || "").trim().split(/\r?\n/u).filter(Boolean);
  if (lines.length !== 1 || lines[0].length > 4096) return null;
  try {
    return codePathsFromBundledCli(lines[0]);
  } catch {
    return null;
  }
}

function discoverLocalCodePaths(options = {}) {
  const platform = options.platform || process.platform;
  if (platform !== "darwin") {
    throw new Error(
      "Automatic local VS Code discovery is supported only on macOS; "
      + "pass an exact executable on this platform."
    );
  }
  const spawn = options.spawnSync || spawnSync;
  const commandCandidate = commandVCode({
    spawnSync: spawn,
    root: options.root,
    environment: options.environment,
  });
  if (commandCandidate) return commandCandidate;
  try {
    const applicationsDirectory = assertRealDirectory(
      options.applicationsDirectory || "/Applications",
      "macOS Applications directory",
    );
    return codePathsFromBundledCli(path.join(
      applicationsDirectory,
      "Visual Studio Code.app",
      "Contents",
      "Resources",
      "app",
      "bin",
      "code",
    ));
  } catch {
    throw new Error(
      "VS Code was not found via `command -v code` or the standard macOS app bundle; "
      + "install the exact pinned version or pass --vscode-executable."
    );
  }
}

function captureRepositoryState(root, spawn, environment) {
  const branchOutput = runChecked(
    spawn,
    "git",
    ["branch", "--show-current"],
    { cwd: root, env: environment },
    "Git branch capture",
  );
  const branch = branchOutput.trim() || null;
  if (branch !== null
    && (branch.length > 255 || /[\u0000-\u001f\u007f]/u.test(branch))) {
    throw new Error("Git branch capture produced an invalid branch name.");
  }
  const statusOutput = runChecked(
    spawn,
    "git",
    ["status", "--short", "--untracked-files=all", "--ignore-submodules=none"],
    { cwd: root, env: environment },
    "Git status capture",
  );
  const dirty = statusOutput.length > 0;
  return Object.freeze({ branch, dirty, status: dirty ? "dirty" : "clean" });
}

function assertStableRepositoryState(before, after) {
  if (JSON.stringify(before) !== JSON.stringify(after)) {
    throw new Error("Repository branch or Git status changed during candidate preparation.");
  }
  return before;
}

function capturedAt(now) {
  const value = now();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new Error("Qualification capture time is invalid.");
  }
  return value.toISOString();
}

function bundledCliCandidates(vscodeExecutable, appRoot, platform = process.platform) {
  const candidates = [];
  const cliName = platform === "win32" ? "code.cmd" : "code";
  if (appRoot) candidates.push(path.join(appRoot, "bin", cliName));
  if (vscodeExecutable) {
    const executableDirectory = path.dirname(vscodeExecutable);
    candidates.push(path.join(executableDirectory, "bin", cliName));
    if (platform === "darwin") {
      candidates.push(path.join(
        path.dirname(executableDirectory), "Resources", "app", "bin", "code"
      ));
    }
  }
  return [...new Set(candidates)];
}

function resolveCodeInstallation(options) {
  const executable = assertRealExecutable(options.vscodeExecutable, "VS Code executable");
  const candidates = bundledCliCandidates(executable, options.appRoot, options.platform);
  let cli = options.vscodeCli;
  if (cli !== undefined) {
    cli = assertRealExecutable(cli, "VS Code CLI");
    if (!candidates.includes(cli)) {
      throw new Error("VS Code CLI must belong to the exact candidate application bundle.");
    }
  } else {
    for (const candidate of candidates) {
      try {
        cli = assertRealExecutable(candidate, "Bundled VS Code CLI");
        break;
      } catch (error) {
        if (error.code && error.code !== "ENOENT") throw error;
      }
    }
  }
  if (!cli) {
    throw new Error("Could not resolve the app-bundled VS Code CLI.");
  }
  const output = runChecked(
    options.spawnSync,
    cli,
    ["--version"],
    { cwd: options.root, env: options.environment },
    "VS Code version verification",
  );
  const actualVersion = output.split(/\r?\n/u).find(Boolean);
  if (actualVersion !== options.vscodeVersion) {
    throw new Error(`VS Code CLI must report exact version ${options.vscodeVersion}.`);
  }
  return Object.freeze({ executable, cli, version: actualVersion });
}

function installAndVerifyCandidate(options) {
  const common = [
    "--user-data-dir", options.profile.userDataDir,
    "--extensions-dir", options.profile.extensionsDir,
  ];
  runChecked(
    options.spawnSync,
    options.code.cli,
    [...common, "--force", "--install-extension", options.vsixPath],
    { cwd: options.root, env: options.environment },
    "VSIX candidate installation",
  );
  const output = runChecked(
    options.spawnSync,
    options.code.cli,
    [...common, "--list-extensions", "--show-versions"],
    { cwd: options.root, env: options.environment },
    "Installed extension verification",
  );
  const installed = output.split(/\r?\n/u).filter(Boolean);
  if (installed.length !== 1) {
    throw new Error("Isolated qualification profile must list exactly one installed extension.");
  }
  const split = /^(?<id>[A-Za-z0-9][A-Za-z0-9.-]*)@(?<version>\d+\.\d+\.\d+)$/u.exec(installed[0]);
  if (!split
    || split.groups.id.toLowerCase() !== options.extension.id.toLowerCase()
    || split.groups.version !== options.extension.version) {
    throw new Error("Installed extension ID/version does not match the verified VSIX candidate.");
  }
  return Object.freeze({
    status: "passed",
    id: options.extension.id,
    version: options.extension.version,
  });
}

function createVerifiedInstallArtifact(verification, options = {}) {
  if (!Buffer.isBuffer(verification?.buffer)
    || verification.buffer.length !== verification.archiveBytes
    || crypto.createHash("sha256").update(verification.buffer).digest("hex") !== verification.sha256) {
    throw new Error("VSIX verifier did not return the exact verified artifact bytes.");
  }
  const temporaryParent = options.temporaryParent === undefined
    ? os.tmpdir()
    : options.temporaryParent;
  const canonicalParent = assertRealDirectory(
    fs.realpathSync(temporaryParent),
    "Private install artifact temporary parent",
  );
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(
    canonicalParent,
    "cloudsmith-install-vsix-",
  )));
  if (process.platform !== "win32") fs.chmodSync(directory, 0o700);
  const directoryStat = fs.lstatSync(directory);
  const file = path.join(directory, "candidate.vsix");
  let fileStat;
  try {
    fs.writeFileSync(file, verification.buffer, { flag: "wx", mode: 0o400 });
    fileStat = fs.lstatSync(file);
    if (fileStat.isSymbolicLink() || !fileStat.isFile()
      || fileStat.size !== verification.archiveBytes) {
      throw new Error("Private install artifact is not the exact verified VSIX.");
    }
  } catch (error) {
    removeExactOwnedDirectoryTree(directory, {
      errorMessage: "Private install artifact rollback refused an unsafe or changed tree.",
      expectedRootEntries: fileStat ? [{
        name: path.basename(file),
        kind: "file",
        identity: fileStat,
      }] : [],
      expectedRootIdentity: directoryStat,
    });
    throw error;
  }
  return Object.freeze({
    file,
    cleanup() {
      removeExactOwnedDirectoryTree(directory, {
        errorMessage: "Private install artifact cleanup refuses an unsafe or changed tree.",
        expectedRootEntries: [{
          name: path.basename(file),
          kind: "file",
          identity: fileStat,
        }],
        expectedRootIdentity: directoryStat,
      });
    },
  });
}

function assertArtifactVerificationProof(verification, bytes, artifactIdentity) {
  if (!Buffer.isBuffer(verification?.buffer)
    || verification.buffer.length !== verification.archiveBytes
    || !verification.buffer.equals(bytes)
    || crypto.createHash("sha256").update(verification.buffer).digest("hex")
      !== verification.sha256
    || !sameExactFileIdentity(verification.artifactIdentity, artifactIdentity)) {
    throw new Error("VSIX verifier did not return the exact descriptor-proven artifact identity.");
  }
  return verification;
}

async function verifyQualificationArtifact(filePath, options = {}, verifier = verifyVsix) {
  if (verifier === verifyVsix) {
    const verification = await verifier(filePath, options);
    if (!sameExactFileIdentity(
      verification?.artifactIdentity,
      verification?.artifactIdentity,
    )) {
      throw new Error("VSIX verifier did not return an exact artifact identity.");
    }
    return verification;
  }
  return withStableArtifact(filePath, {}, async (bytes, artifactIdentity) => (
    assertArtifactVerificationProof(
      await verifier(filePath, options),
      bytes,
      artifactIdentity,
    )
  ));
}

function assertSidecarVerificationProof(sidecars, proof) {
  if (!sameExactFileIdentity(sidecars?.artifactIdentity, proof.artifactIdentity)
    || !sameExactFileIdentity(sidecars?.checksumIdentity, proof.checksumIdentity)
    || !sameExactFileIdentity(sidecars?.provenanceIdentity, proof.provenanceIdentity)) {
    throw new Error("Sidecar verifier did not return exact descriptor-proven identities.");
  }
  return sidecars;
}

function verifyQualificationSidecars(
  filePath,
  verification,
  options = {},
  verifier = validateSidecars,
) {
  if (verifier === validateSidecars) {
    const sidecars = verifier(filePath, verification, options);
    if (!sameExactFileIdentity(sidecars?.artifactIdentity, verification.artifactIdentity)
      || !sameExactFileIdentity(sidecars?.checksumIdentity, sidecars?.checksumIdentity)
      || !sameExactFileIdentity(sidecars?.provenanceIdentity, sidecars?.provenanceIdentity)) {
      throw new Error("Sidecar verifier did not return exact descriptor-proven identities.");
    }
    return sidecars;
  }
  return withStableSidecarSet(filePath, verification, options, proof => (
    assertSidecarVerificationProof(
      verifier(filePath, verification, options),
      proof,
    )
  ));
}

function assertEquivalentVerification(initial, final) {
  for (const field of ["sha256", "archiveBytes", "entryCount", "totalUncompressedBytes"]) {
    if (initial[field] !== final[field]) {
      throw new Error("Canonical VSIX changed after it was verified for installation.");
    }
  }
  if (JSON.stringify(initial.manifest) !== JSON.stringify(final.manifest)) {
    throw new Error("Canonical VSIX identity changed after installation verification.");
  }
  if (!sameExactFileIdentity(initial.artifactIdentity, initial.artifactIdentity)
    || !sameExactFileIdentity(final.artifactIdentity, final.artifactIdentity)
    || !sameExactFileIdentity(initial.artifactIdentity, final.artifactIdentity)) {
    throw new Error("Canonical VSIX pathname identity changed after installation verification.");
  }
  return final;
}

function writeCandidateProof(root, receipt, verifiedBuffer, paths) {
  if (!Buffer.isBuffer(verifiedBuffer)
    || verifiedBuffer.length !== receipt?.artifact?.archiveBytes
    || crypto.createHash("sha256").update(verifiedBuffer).digest("hex")
      !== receipt?.artifact?.sha256) {
    throw new Error("Qualification candidate proof bytes do not match the exact receipt.");
  }
  writeFile(
    paths.artifactPath,
    verifiedBuffer,
    root,
    { subtree: ".quality/qualification" }
  );
  writeJson(
    paths.receiptPath,
    receipt,
    root,
    { subtree: ".quality/qualification" }
  );
  return Object.freeze({ ...paths });
}

function writeLiveCandidateProof(root, receipt, verifiedBuffer) {
  return writeCandidateProof(root, receipt, verifiedBuffer, {
    artifactPath: LIVE_CANDIDATE_ARTIFACT,
    receiptPath: LIVE_CANDIDATE_RECEIPT,
  });
}

function writeAuthenticatedCandidateProof(root, receipt, verifiedBuffer) {
  return writeCandidateProof(root, receipt, verifiedBuffer, {
    artifactPath: AUTHENTICATED_CANDIDATE_ARTIFACT,
    receiptPath: AUTHENTICATED_CANDIDATE_RECEIPT,
  });
}

function writeUiCandidateProof(root, receipt, verifiedBuffer) {
  return writeCandidateProof(root, receipt, verifiedBuffer, {
    artifactPath: UI_CANDIDATE_ARTIFACT,
    receiptPath: UI_CANDIDATE_RECEIPT,
  });
}

function profileFromCandidate(candidateOrProfile) {
  const profile = candidateOrProfile?.profile || candidateOrProfile;
  if (!profile || typeof profile !== "object") {
    throw new Error("Qualification launch requires a prepared profile.");
  }
  const root = profile.root;
  const userDataName = profile.mode === "local" ? "user-data" : "settings";
  if (profile.testResourcesDir !== root
    || profile.userDataDir !== path.join(root, userDataName)
    || profile.extensionsDir !== path.join(root, "extensions")) {
    throw new Error("Qualification launch profile layout is not canonical.");
  }
  return profile;
}

function qualificationLaunchArguments(candidateOrProfile, options = {}) {
  const profile = profileFromCandidate(candidateOrProfile);
  const arguments_ = [
    "--user-data-dir", profile.userDataDir,
    "--extensions-dir", profile.extensionsDir,
    "--disable-updates",
    "--skip-welcome",
    "--skip-release-notes",
    "--new-window",
  ];
  if (options.workspacePath !== undefined) {
    const workspace = options.workspacePath;
    if (typeof workspace !== "string" || !path.isAbsolute(workspace)
      || path.resolve(workspace) !== workspace || path.normalize(workspace) !== workspace) {
      throw new Error("Qualification workspace must be an absolute normalized path.");
    }
    const stat = fs.lstatSync(workspace);
    if (stat.isSymbolicLink() || !stat.isDirectory() || fs.realpathSync(workspace) !== workspace) {
      throw new Error("Qualification workspace must be an exact real directory.");
    }
    arguments_.push(workspace);
  }
  if (arguments_.some(argument => argument.includes("--extensionDevelopmentPath"))) {
    throw new Error("Qualification launch refuses extension development paths.");
  }
  return Object.freeze(arguments_);
}

async function prepareCodePaths(options) {
  if (options.vscodeExecutable) {
    return Object.freeze({
      executable: options.vscodeExecutable,
      cli: options.vscodeCli,
      appRoot: options.appRoot,
    });
  }
  if (typeof options.prepareCode !== "function") {
    if (options.profile.mode !== "local") {
      throw new Error(
        "Candidate preparation requires an exact VS Code executable or prepareCode callback."
      );
    }
    const discovered = discoverLocalCodePaths({
      platform: options.platform,
      applicationsDirectory: options.applicationsDirectory,
      spawnSync: options.spawnSync,
      root: options.root,
      environment: options.environment,
    });
    return Object.freeze({
      ...discovered,
      cli: options.vscodeCli || discovered.cli,
    });
  }
  const callbackProfile = Object.freeze({
    mode: options.profile.mode,
    persistent: options.profile.persistent,
    root: options.profile.root,
    testResourcesDir: options.profile.testResourcesDir,
    homeDir: options.profile.homeDir,
    userDataDir: options.profile.userDataDir,
    extensionsDir: options.profile.extensionsDir,
  });
  const prepared = await options.prepareCode(Object.freeze({
    root: options.root,
    profile: callbackProfile,
    vscodeVersion: options.vscodeVersion,
    environment: options.environment,
  }));
  if (!prepared || typeof prepared !== "object" || Array.isArray(prepared)
    || Object.keys(prepared).some(key => !new Set(["executable", "cli", "appRoot"]).has(key))
    || typeof prepared.executable !== "string") {
    throw new Error("prepareCode must return exact candidate application paths.");
  }
  return Object.freeze({
    executable: prepared.executable,
    cli: prepared.cli,
    appRoot: prepared.appRoot,
  });
}

async function prepareQualificationCandidate(options = {}) {
  const root = options.root || ROOT;
  const adapters = options.adapters || {};
  const spawn = adapters.spawnSync || spawnSync;
  const identifySource = adapters.sourceIdentity || sourceIdentity;
  const verifyArtifact = adapters.verifyVsix || verifyVsix;
  const verifySidecars = adapters.validateSidecars || validateSidecars;
  const now = adapters.now || (() => new Date());
  removeOutputFile(CANDIDATE_RECEIPT, root, { subtree: ".quality/qualification" });
  const mode = options.mode || "local";
  if (!new Set(["local", "ci"]).has(mode)) {
    throw new Error("Qualification profile mode must be local or ci.");
  }
  const suppliedEnvironment = Object.prototype.hasOwnProperty.call(options, "environment")
    ? options.environment
    : process.env;
  const nonAuthBoundary = options.nonAuthBoundary === undefined
    ? null
    : assertActiveNonAuthQualityBoundary(options.nonAuthBoundary, suppliedEnvironment);
  if (nonAuthBoundary && mode !== "ci") {
    throw new Error("A private non-auth boundary is supported only for CI qualification profiles.");
  }
  if (nonAuthBoundary && options.temporaryParent !== undefined
    && options.temporaryParent !== nonAuthBoundary.paths.temporary) {
    throw new Error("Nested non-auth qualification cannot override its boundary temporary parent.");
  }
  const nestedTemporaryParent = nonAuthBoundary?.paths.temporary || options.temporaryParent;
  const qualificationLane = options.qualificationLane
    || (mode === "local" ? "current" : "black-box");
  const proofPaths = qualificationLane === "current"
    ? mode === "local"
      ? [LIVE_CANDIDATE_RECEIPT, LIVE_CANDIDATE_ARTIFACT]
      : [AUTHENTICATED_CANDIDATE_RECEIPT, AUTHENTICATED_CANDIDATE_ARTIFACT]
    : [UI_CANDIDATE_RECEIPT, UI_CANDIDATE_ARTIFACT];
  for (const proofPath of proofPaths) {
    removeOutputFile(proofPath, root, { subtree: ".quality/qualification" });
  }
  let profile;
  let succeeded = false;
  try {
    profile = mode === "local"
      ? prepareLocalQualificationProfile({
        homeDirectory: options.homeDirectory,
        profileRoot: options.profileRoot,
      })
      : createCiQualificationProfile({ temporaryParent: nestedTemporaryParent });
    if (nonAuthBoundary) {
      assertPathWithinBoundaryTemporary(profile.root, nonAuthBoundary, "CI qualification profile");
    }
    const environment = qualificationEnvironment(
      suppliedEnvironment,
      profile,
      nonAuthBoundary,
    );
    removeSafeAppleMetadata(root, { spawnSync: spawn, environment });
    runChecked(
      spawn,
      process.platform === "win32" ? "npm.cmd" : "npm",
      ["run", "verify:polish"],
      { cwd: root, env: environment },
      "Post-cleanup polish verification",
    );
    const repositoryBefore = captureRepositoryState(root, spawn, environment);
    const sourceBefore = assertSourceIdentity(identifySource(root, spawn, environment, {
      temporaryParent: nonAuthBoundary?.paths.temporary,
    }));
    const extension = exactVersionState(root, mode, qualificationLane);
    removeFreshPackageOutputs(root, extension.name, extension.version);

    const candidateTemporaryParent = fs.realpathSync(nestedTemporaryParent || os.tmpdir());
    const temporary = fs.realpathSync(fs.mkdtempSync(path.join(
      candidateTemporaryParent,
      "cloudsmith-candidate-",
    )));
    const temporaryIdentity = fs.lstatSync(temporary);
    if (nonAuthBoundary) {
      assertPathWithinBoundaryTemporary(temporary, nonAuthBoundary, "Candidate package scratch");
    }
    let packageOutput;
    let packageOutputFileIdentity;
    const packageOutputFile = path.join(temporary, "package-output");
    try {
      fs.writeFileSync(packageOutputFile, "", { flag: "wx", mode: 0o600 });
      const packageOutputStat = fs.lstatSync(packageOutputFile);
      packageOutputFileIdentity = Object.freeze({
        dev: packageOutputStat.dev,
        ino: packageOutputStat.ino,
      });
      runChecked(
        spawn,
        process.platform === "win32" ? "npm.cmd" : "npm",
        ["run", "package", "--", "--github-output", packageOutputFile],
        { cwd: root, env: environment },
        "Canonical npm package",
      );
      packageOutput = parsePackageOutput(
        packageOutputFile,
        root,
        extension.name,
        extension.version,
        { expectedIdentity: packageOutputFileIdentity },
      );
    } finally {
      removeExactOwnedDirectoryTree(temporary, {
        errorMessage: "Candidate package scratch cleanup refused an unsafe or changed tree.",
        expectedRootEntries: packageOutputFileIdentity ? [{
          name: path.basename(packageOutputFile),
          kind: "file",
          identity: packageOutputFileIdentity,
        }] : [],
        expectedRootIdentity: temporaryIdentity,
      });
    }

    const provenanceProof = readProvenanceSidecar(packageOutput.absoluteVsixPath);
    const provenance = provenanceProof.provenance;
    const initialVerification = await verifyQualificationArtifact(packageOutput.absoluteVsixPath, {
      sourceSha: provenance.sourceClean ? sourceBefore.sha : null,
    }, verifyArtifact);
    const initialSidecars = verifyQualificationSidecars(
      packageOutput.absoluteVsixPath,
      initialVerification,
      {
      expectedSourceSha: sourceBefore.sha,
      expectedProvenanceIdentity: provenanceProof.identity,
      requirePublishable: false,
      },
      verifySidecars,
    );
    if (initialVerification.manifest.name !== extension.name
      || initialVerification.manifest.publisher !== extension.publisher
      || initialVerification.manifest.version !== extension.version) {
      throw new Error("Verified VSIX identity does not match the exact current package version.");
    }
    const codePaths = await prepareCodePaths({
      root,
      profile,
      environment,
      vscodeVersion: extension.vscodeVersion,
      vscodeExecutable: options.vscodeExecutable,
      vscodeCli: options.vscodeCli,
      appRoot: options.appRoot,
      prepareCode: options.prepareCode,
      platform: options.platform,
      applicationsDirectory: options.applicationsDirectory,
      spawnSync: spawn,
    });
    const code = resolveCodeInstallation({
      vscodeExecutable: codePaths.executable,
      vscodeCli: codePaths.cli,
      appRoot: codePaths.appRoot,
      platform: options.platform,
      spawnSync: spawn,
      root,
      environment,
      vscodeVersion: extension.vscodeVersion,
    });
    const privateArtifact = createVerifiedInstallArtifact(initialVerification, {
      temporaryParent: nestedTemporaryParent,
    });
    if (nonAuthBoundary) {
      assertPathWithinBoundaryTemporary(
        privateArtifact.file,
        nonAuthBoundary,
        "Verified install artifact",
      );
    }
    let installation;
    try {
      installation = installAndVerifyCandidate({
        root,
        spawnSync: spawn,
        environment,
        profile,
        code,
        extension,
        vsixPath: privateArtifact.file,
      });
    } finally {
      privateArtifact.cleanup();
    }
    let launchStatus = "not-requested";
    if (options.launch) {
      runChecked(
        spawn,
        code.cli,
        qualificationLaunchArguments(profile, { workspacePath: options.workspacePath }),
        { cwd: root, env: environment },
        "Qualification candidate launch",
      );
      launchStatus = "command-accepted";
    }
    const finalVerification = await verifyQualificationArtifact(packageOutput.absoluteVsixPath, {
      sourceSha: provenance.sourceClean ? sourceBefore.sha : null,
    }, verifyArtifact);
    const verification = assertEquivalentVerification(initialVerification, finalVerification);
    verifyQualificationSidecars(
      packageOutput.absoluteVsixPath,
      verification,
      {
        expectedChecksumIdentity: initialSidecars.checksumIdentity,
        expectedProvenanceIdentity: initialSidecars.provenanceIdentity,
        expectedSourceSha: sourceBefore.sha,
        requirePublishable: false,
      },
      verifySidecars,
    );
    assertStableSource(sourceBefore, identifySource(root, spawn, environment, {
      temporaryParent: nonAuthBoundary?.paths.temporary,
    }));
    assertStableRepositoryState(
      repositoryBefore,
      captureRepositoryState(root, spawn, environment),
    );
    if (nonAuthBoundary) {
      assertActiveNonAuthQualityBoundary(nonAuthBoundary, suppliedEnvironment);
    }

    const receiptBase = {
      schemaVersion: 2,
      status: "passed",
      capturedAt: capturedAt(now),
      source: sourceBefore,
      repository: repositoryBefore,
      extension: {
        id: extension.id,
        publisher: extension.publisher,
        name: extension.name,
        version: extension.version,
      },
      vscode: {
        version: code.version,
        executable: code.executable,
        cli: code.cli,
      },
      profile: {
        mode: profile.mode,
        persistent: profile.persistent,
        root: profile.root,
        testResourcesDir: profile.testResourcesDir,
        userDataDir: profile.userDataDir,
        extensionsDir: profile.extensionsDir,
      },
      artifact: {
        vsixPath: packageOutput.vsixPath,
        absoluteVsixPath: packageOutput.absoluteVsixPath,
        sha256: verification.sha256,
        archiveBytes: verification.archiveBytes,
        entryCount: verification.entryCount,
        sourceSha: sourceBefore.sha,
        sourceFingerprint: sourceBefore.fingerprint,
      },
      installation,
      launch: {
        status: launchStatus,
        developmentPath: false,
      },
    };
    const receipt = Object.freeze({
      ...receiptBase,
      fingerprint: fingerprint(receiptBase),
    });
    writeJson(CANDIDATE_RECEIPT, receipt, root, { subtree: ".quality/qualification" });
    if (qualificationLane === "current") {
      if (mode === "local") writeLiveCandidateProof(root, receipt, verification.buffer);
      else writeAuthenticatedCandidateProof(root, receipt, verification.buffer);
    } else writeUiCandidateProof(root, receipt, verification.buffer);
    succeeded = true;
    const cleanup = profile.mode === "ci"
      ? () => cleanupCiQualificationProfile(profile)
      : () => false;
    const runtimeProfile = Object.freeze({
      ...profile,
      executable: code.executable,
      cli: code.cli,
      vscodeVersion: code.version,
    });
    return Object.freeze({ receipt, profile: runtimeProfile, cleanup });
  } finally {
    if (!succeeded && profile?.mode === "ci") {
      cleanupCiQualificationProfile(profile);
    }
  }
}

function parseCli(arguments_) {
  const options = { mode: "local", launch: false };
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--launch") options.launch = true;
    else if (["--mode", "--vscode-executable", "--vscode-cli", "--workspace"].includes(argument)) {
      const value = arguments_[index + 1];
      if (!value) throw new Error(`${argument} requires a value.`);
      index += 1;
      if (argument === "--mode") options.mode = value;
      if (argument === "--vscode-executable") options.vscodeExecutable = path.resolve(value);
      if (argument === "--vscode-cli") options.vscodeCli = path.resolve(value);
      if (argument === "--workspace") options.workspacePath = path.resolve(value);
    } else {
      throw new Error(`Unknown qualification candidate argument: ${argument}`);
    }
  }
  if (options.mode === "ci") {
    throw new Error("CI candidate preparation must be invoked in-process so cleanup stays guaranteed.");
  }
  return options;
}

if (require.main === module) {
  prepareQualificationCandidate(parseCli(process.argv.slice(2)))
    .then(({ receipt }) => {
      process.stdout.write(
        `Prepared ${receipt.extension.id}@${receipt.extension.version} from ${receipt.artifact.vsixPath}.\n`
      );
    })
    .catch(error => {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 1;
    });
}

module.exports = {
  CANDIDATE_RECEIPT,
  assertSourceIdentity,
  assertStableSource,
  assertEquivalentVerification,
  assertStableRepositoryState,
  bundledCliCandidates,
  captureRepositoryState,
  codePathsFromBundledCli,
  createVerifiedInstallArtifact,
  currentExtensionHostVersion,
  discoverLocalCodePaths,
  exactVersionState,
  installAndVerifyCandidate,
  parseCli,
  parsePackageOutput,
  prepareCodePaths,
  prepareQualificationCandidate,
  qualificationEnvironment,
  qualificationLaunchArguments,
  removeFreshPackageOutputs,
  resolveCodeInstallation,
  verifyQualificationArtifact,
  verifyQualificationSidecars,
  writeLiveCandidateProof,
  writeUiCandidateProof,
  writeAuthenticatedCandidateProof,
};

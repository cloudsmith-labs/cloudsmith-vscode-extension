// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  ROOT,
  readJson,
  removeOutputFile,
  writeJson,
} = require("./common");
const { fingerprint } = require("./evidence");
const { removeExactOwnedDirectoryTree } = require("./non-auth-environment");
const {
  AUTHENTICATED_CANDIDATE_ARTIFACT,
  AUTHENTICATED_CANDIDATE_RECEIPT,
  candidateBindingFromReceipt,
} = require("./candidate-binding");
const {
  currentExtensionHostVersion,
  prepareQualificationCandidate,
} = require("./prepare-qualification");
const { CI_PROFILE_PREFIX } = require("./qualification-profile");

const AUTHENTICATED_SESSION = ".quality/qualification/authenticated-session.json";
const CURRENT_VSCODE_VERSION = currentExtensionHostVersion(ROOT);
const SECRET_ENV = "CLOUDSMITH_QUALIFICATION_API_KEY";

async function prepareCurrentCode(context, adapters = {}) {
  if (context.vscodeVersion !== CURRENT_VSCODE_VERSION
    || context.profile.mode !== "ci" || context.profile.persistent !== false) {
    throw new Error("Authenticated candidate session requires exact current VS Code.");
  }
  const electron = adapters.electron || require("@vscode/test-electron");
  const cachePath = path.join(context.profile.root, "app");
  fs.mkdirSync(cachePath, { mode: 0o700 });
  if (process.platform !== "win32") fs.chmodSync(cachePath, 0o700);
  const executable = await electron.downloadAndUnzipVSCode({
    version: CURRENT_VSCODE_VERSION,
    cachePath,
    reporter: new electron.SilentReporter(),
  });
  return Object.freeze({
    executable,
    cli: electron.resolveCliPathFromVSCodeExecutablePath(executable),
  });
}

function exactKeys(value, keys) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).sort().join(",") === [...keys].sort().join(","));
}

function exactPath(value) {
  return typeof value === "string" && path.isAbsolute(value)
    && path.resolve(value) === value && path.normalize(value) === value
    && !value.includes("\u0000");
}

function canonicalApprovedTemporaryBase(environment = process.env) {
  if (!environment || typeof environment !== "object" || Array.isArray(environment)) {
    throw new Error("Authenticated candidate temporary environment is invalid.");
  }
  const configured = environment.RUNNER_TEMP;
  const input = configured === undefined ? os.tmpdir() : configured;
  if (typeof input !== "string" || input.length === 0 || !path.isAbsolute(input)
    || path.resolve(input) !== input || path.normalize(input) !== input
    || input.includes("\u0000")) {
    throw new Error("Authenticated candidate temporary base is invalid.");
  }
  const base = fs.realpathSync(input);
  const stat = fs.lstatSync(base);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error("Authenticated candidate temporary base must be a canonical real directory.");
  }
  return base;
}

function profileMetadata(session) {
  const profile = session.profile;
  if (!exactKeys(profile, [
    "cli", "executable", "extensionsDir", "homeDir", "mode", "persistent",
    "root", "testResourcesDir", "userDataDir", "vscodeVersion",
  ])
    || profile.mode !== "ci" || profile.persistent !== false
    || !exactPath(profile.root)
    || profile.testResourcesDir !== profile.root
    || profile.homeDir !== path.join(profile.root, "home")
    || profile.userDataDir !== path.join(profile.root, "settings")
    || profile.extensionsDir !== path.join(profile.root, "extensions")
    || profile.vscodeVersion !== CURRENT_VSCODE_VERSION
    || !exactPath(profile.executable) || !exactPath(profile.cli)
    || !profile.executable.startsWith(`${profile.root}${path.sep}`)
    || !profile.cli.startsWith(`${profile.root}${path.sep}`)) {
    throw new Error("Authenticated candidate session profile metadata is invalid.");
  }
  return profile;
}

function assertPreparedSession(session, options = {}) {
  const unsigned = { ...session };
  delete unsigned.fingerprint;
  if (!exactKeys(session, [
    "candidateReceiptFingerprint", "fingerprint", "ownership", "profile",
    "processTreeExit", "schemaVersion", "source", "status",
  ])
    || session.schemaVersion !== 2 || session.status !== "prepared"
    || !new Set(["pending", "proven", "unproven"]).has(session.processTreeExit)
    || !exactKeys(session.source, ["fingerprint", "sha"])
    || !/^[a-f0-9]{40,64}$/u.test(session.source.sha || "")
    || !/^[a-f0-9]{64}$/u.test(session.source.fingerprint || "")
    || !/^[a-f0-9]{64}$/u.test(session.candidateReceiptFingerprint || "")
    || !exactKeys(session.ownership, ["device", "inode", "parent", "uid"])
    || !/^\d+$/u.test(session.ownership.device || "")
    || !/^\d+$/u.test(session.ownership.inode || "")
    || !(session.ownership.uid === null || /^\d+$/u.test(session.ownership.uid))
    || !exactPath(session.ownership.parent)
    || fingerprint(unsigned) !== session.fingerprint) {
    throw new Error("Authenticated candidate session receipt is invalid.");
  }
  const profile = profileMetadata(session);
  const approvedTemporaryBase = canonicalApprovedTemporaryBase(
    options.environment || process.env,
  );
  if (session.ownership.parent !== approvedTemporaryBase
    || path.dirname(profile.root) !== approvedTemporaryBase
    || !path.basename(profile.root).startsWith(CI_PROFILE_PREFIX)) {
    throw new Error("Authenticated candidate session root is outside its approved temporary base.");
  }
  if (options.allowMissing === true && !fs.existsSync(profile.root)) return session;
  const rootStat = fs.lstatSync(profile.root);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()
    || fs.realpathSync(profile.root) !== profile.root
    || String(rootStat.dev) !== session.ownership.device
    || String(rootStat.ino) !== session.ownership.inode
    || (process.platform !== "win32" && (rootStat.mode & 0o077) !== 0)
    || (typeof process.getuid === "function" && rootStat.uid !== process.getuid())
    || (session.ownership.uid !== null && String(rootStat.uid) !== session.ownership.uid)) {
    throw new Error("Authenticated candidate session root identity changed.");
  }
  for (const directory of [
    profile.homeDir, profile.userDataDir, profile.extensionsDir,
  ]) {
    const stat = fs.lstatSync(directory);
    if (stat.isSymbolicLink() || !stat.isDirectory()
      || fs.realpathSync(directory) !== directory
      || !directory.startsWith(`${profile.root}${path.sep}`)
      || stat.dev !== rootStat.dev
      || (process.platform !== "win32" && (stat.mode & 0o077) !== 0)) {
      throw new Error("Authenticated candidate session directory identity changed.");
    }
  }
  for (const executable of [profile.executable, profile.cli]) {
    const stat = fs.lstatSync(executable);
    if (stat.isSymbolicLink() || !stat.isFile() || fs.realpathSync(executable) !== executable
      || (process.platform !== "win32" && (stat.mode & 0o111) === 0)) {
      throw new Error("Authenticated candidate session executable identity changed.");
    }
  }
  return session;
}

function sessionFromCandidate(candidate, options = {}) {
  const profile = candidate.profile;
  const rootStat = fs.lstatSync(profile.root);
  const approvedTemporaryBase = canonicalApprovedTemporaryBase(
    options.environment || process.env,
  );
  if (path.dirname(profile.root) !== approvedTemporaryBase) {
    throw new Error("Authenticated candidate profile is outside its approved temporary base.");
  }
  const base = {
    schemaVersion: 2,
    status: "prepared",
    processTreeExit: "pending",
    source: { ...candidate.receipt.source },
    candidateReceiptFingerprint: candidate.receipt.fingerprint,
    profile: {
      mode: "ci",
      persistent: false,
      root: profile.root,
      testResourcesDir: profile.testResourcesDir,
      homeDir: profile.homeDir,
      userDataDir: profile.userDataDir,
      extensionsDir: profile.extensionsDir,
      executable: profile.executable,
      cli: profile.cli,
      vscodeVersion: profile.vscodeVersion,
    },
    ownership: {
      parent: approvedTemporaryBase,
      device: String(rootStat.dev),
      inode: String(rootStat.ino),
      uid: typeof rootStat.uid === "number" ? String(rootStat.uid) : null,
    },
  };
  return assertPreparedSession(
    { ...base, fingerprint: fingerprint(base) },
    { environment: options.environment },
  );
}

function markPreparedAuthenticatedCandidateProcessExit(
  processTreeExit,
  root = ROOT,
  options = {},
) {
  if (!new Set(["proven", "unproven"]).has(processTreeExit)) {
    throw new Error("Authenticated candidate process-tree exit state is invalid.");
  }
  const session = assertPreparedSession(readJson(AUTHENTICATED_SESSION, root), {
    environment: options.environment,
  });
  const unsigned = { ...session, processTreeExit };
  delete unsigned.fingerprint;
  const updated = assertPreparedSession({
    ...unsigned,
    fingerprint: fingerprint(unsigned),
  }, { environment: options.environment });
  writeJson(AUTHENTICATED_SESSION, updated, root, {
    subtree: ".quality/qualification",
  });
  return updated;
}

function cleanupPreparedAuthenticatedCandidate(root = ROOT, options = {}) {
  let session;
  try {
    session = readJson(AUTHENTICATED_SESSION, root);
  } catch (error) {
    if (error.code === "ENOENT" || /missing/u.test(error.message)) return true;
    throw error;
  }
  assertPreparedSession(session, {
    allowMissing: true,
    environment: options.environment,
  });
  if (session.processTreeExit !== "proven") {
    throw new Error(
      "Authenticated candidate cleanup requires independently proven process-tree exit."
    );
  }
  if (fs.existsSync(session.profile.root)) {
    assertPreparedSession(session, { environment: options.environment });
    const expectedRootEntries = [
      session.profile.homeDir,
      session.profile.userDataDir,
      session.profile.extensionsDir,
    ].map(directory => Object.freeze({
      name: path.basename(directory),
      kind: "directory",
      identity: fs.lstatSync(directory),
    }));
    removeExactOwnedDirectoryTree(session.profile.root, {
      allowAdditionalRootEntries: true,
      errorMessage: "Authenticated candidate profile cleanup refused an unsafe or changed tree.",
      expectedRootEntries,
      expectedRootIdentity: session.ownership,
    });
  }
  if (fs.existsSync(session.profile.root)) {
    throw new Error("Authenticated candidate profile cleanup did not complete.");
  }
  removeOutputFile(AUTHENTICATED_SESSION, root, {
    subtree: ".quality/qualification",
  });
  return true;
}

function loadPreparedAuthenticatedCandidate(root = ROOT, options = {}) {
  const session = assertPreparedSession(readJson(AUTHENTICATED_SESSION, root), {
    environment: options.environment,
  });
  const receipt = readJson(AUTHENTICATED_CANDIDATE_RECEIPT, root);
  if (receipt.fingerprint !== session.candidateReceiptFingerprint
    || receipt.source?.sha !== session.source.sha
    || receipt.source?.fingerprint !== session.source.fingerprint
    || receipt.profile?.root !== session.profile.root
    || receipt.vscode?.executable !== session.profile.executable
    || receipt.vscode?.cli !== session.profile.cli) {
    throw new Error("Authenticated candidate session does not bind its exact receipt.");
  }
  const binding = candidateBindingFromReceipt(receipt, {
    root,
    source: session.source,
    artifactPath: path.join(root, AUTHENTICATED_CANDIDATE_ARTIFACT),
  });
  if (binding.profileMode !== "ci"
    || binding.receiptFingerprint !== session.candidateReceiptFingerprint) {
    throw new Error("Authenticated candidate session binding is invalid.");
  }
  return Object.freeze({
    receipt,
    profile: Object.freeze({ ...session.profile }),
    markProcessTreeExit: processTreeExit => (
      markPreparedAuthenticatedCandidateProcessExit(processTreeExit, root, {
        environment: options.environment,
      })
    ),
    cleanup: () => cleanupPreparedAuthenticatedCandidate(root, {
      environment: options.environment,
    }),
  });
}

async function prepareAuthenticatedCandidateSession(options = {}) {
  const root = options.root || ROOT;
  const environment = options.environment || process.env;
  if (root !== ROOT) throw new Error("Authenticated candidate preparation requires the exact root.");
  if (Object.prototype.hasOwnProperty.call(environment, SECRET_ENV)) {
    delete environment[SECRET_ENV];
    throw new Error("Credential-bearing environments cannot prepare an authenticated candidate.");
  }
  try {
    cleanupPreparedAuthenticatedCandidate(root, { environment });
  } catch {
    throw new Error("A prior authenticated candidate session could not be safely cleaned.");
  }
  let candidate;
  let retained = false;
  try {
    const temporaryParent = canonicalApprovedTemporaryBase(environment);
    candidate = await (options.prepareQualificationCandidate || prepareQualificationCandidate)({
      root,
      mode: "ci",
      qualificationLane: "current",
      launch: false,
      environment,
      temporaryParent,
      prepareCode: options.prepareCode || (context => prepareCurrentCode(context, {
        electron: options.electron,
      })),
      adapters: options.adapters,
    });
    candidateBindingFromReceipt(candidate.receipt, {
      root,
      source: candidate.receipt.source,
      artifactPath: path.join(root, AUTHENTICATED_CANDIDATE_ARTIFACT),
    });
    const session = sessionFromCandidate(candidate, { environment });
    writeJson(AUTHENTICATED_SESSION, session, root, {
      subtree: ".quality/qualification",
    });
    retained = true;
    return session;
  } finally {
    if (candidate && !retained) await candidate.cleanup();
  }
}

async function runAuthenticatedCandidateSessionCommand(arguments_, options = {}) {
  if (arguments_.length !== 1 || !new Set(["prepare", "cleanup"]).has(arguments_[0])) {
    throw new Error("Authenticated candidate session requires prepare or cleanup.");
  }
  if (arguments_[0] === "prepare") {
    await prepareAuthenticatedCandidateSession(options);
  } else {
    cleanupPreparedAuthenticatedCandidate(options.root || ROOT, {
      environment: options.environment,
    });
  }
}

if (require.main === module) {
  runAuthenticatedCandidateSessionCommand(process.argv.slice(2)).catch(() => {
    process.exitCode = 1;
  });
}

module.exports = {
  AUTHENTICATED_SESSION,
  assertPreparedSession,
  canonicalApprovedTemporaryBase,
  cleanupPreparedAuthenticatedCandidate,
  loadPreparedAuthenticatedCandidate,
  markPreparedAuthenticatedCandidateProcessExit,
  prepareCurrentCode,
  prepareAuthenticatedCandidateSession,
  runAuthenticatedCandidateSessionCommand,
  sessionFromCandidate,
};

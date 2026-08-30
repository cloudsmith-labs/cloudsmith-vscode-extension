// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const { ROOT, readJson, removeOutputFile, writeJson } = require("./common");
const { fingerprint, sourceIdentity } = require("./evidence");
const {
  LIVE_CANDIDATE_ARTIFACT,
  LIVE_CANDIDATE_RECEIPT,
} = require("./candidate-binding");
const { prepareLocalQualificationProfile } = require("./qualification-profile");
const {
  CANDIDATE_RECEIPT,
  assertEquivalentVerification,
  assertSourceIdentity,
  assertStableRepositoryState,
  assertStableSource,
  captureRepositoryState,
  createVerifiedInstallArtifact,
  exactVersionState,
  installAndVerifyCandidate,
  prepareCodePaths,
  qualificationEnvironment,
  qualificationToolchainPreflight,
  resolveCodeInstallation,
  verifyQualificationArtifact,
  writeLiveCandidateProof,
} = require("./prepare-qualification");
const { verifyStagedBundleMatchesArchive } = require("./remote-signed-out-artifact");
const { verifyDetachedSignedOutUiBundle } = require("./verify-ui-evidence");
const { validatedRemoteCiAuthority } = require("./release-checklist");

const REMOTE_CI = "internal_docs/quality/remote-ci.json";
const REMOTE_ARCHIVE = ".quality/remote-ci/signed-out-ui.zip";
const REMOTE_BUNDLE = ".quality/remote-ci/signed-out-ui";
const REMOTE_VSIX = `${REMOTE_BUNDLE}/ui-candidate.vsix`;

function assertRemoteCiIdentity(remote, source) {
  const main = remote?.runs?.find(run => run.workflowFile === ".github/workflows/main.yml");
  const artifact = remote?.signedOutUiArtifact;
  if (remote?.sourceSha !== source.sha
    || remote?.sourceFingerprint !== source.fingerprint
    || remote?.pullRequest?.headSha !== source.sha
    || remote?.pullRequest?.state !== "open"
    || remote?.pullRequest?.draft !== true
    || main?.headSha !== source.sha
    || main?.status !== "completed"
    || main?.conclusion !== "success"
    || artifact?.headSha !== source.sha
    || artifact?.runId !== main.runId
    || artifact?.runAttempt !== main.runAttempt
    || artifact?.expired !== false
    || !Number.isSafeInteger(artifact?.artifactId)
    || !/^sha256:[a-f0-9]{64}$/u.test(artifact?.digest || "")) {
    throw new Error("Remote signed-out CI receipt is stale, incomplete, or candidate-mismatched.");
  }
  return Object.freeze({ artifact, main });
}

function assertRemoteCandidateIdentity(remoteCandidate, verification, source, extension) {
  if (remoteCandidate.sourceSha !== source.sha
    || remoteCandidate.sourceFingerprint !== source.fingerprint
    || remoteCandidate.extensionId !== extension.id
    || remoteCandidate.extensionVersion !== extension.version
    || remoteCandidate.vsixSha256 !== verification.sha256
    || verification.manifest.publisher !== extension.publisher
    || verification.manifest.name !== extension.name
    || verification.manifest.version !== extension.version) {
    throw new Error("Remote signed-out VSIX identity does not match the exact current candidate.");
  }
  return true;
}

function parseCli(arguments_) {
  const options = {};
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (!["--vscode-executable", "--vscode-cli"].includes(argument)) {
      throw new Error(`Unknown remote qualification argument: ${argument}`);
    }
    const value = arguments_[index + 1];
    if (!value) throw new Error(`${argument} requires a value.`);
    index += 1;
    if (argument === "--vscode-executable") options.vscodeExecutable = path.resolve(value);
    if (argument === "--vscode-cli") options.vscodeCli = path.resolve(value);
  }
  return options;
}

async function prepareRemoteAttestedQualificationCandidate(options = {}) {
  const root = options.root || ROOT;
  const adapters = options.adapters || {};
  const suppliedEnvironment = Object.prototype.hasOwnProperty.call(options, "environment")
    ? options.environment
    : process.env;
  const spawn = adapters.spawnSync || spawnSync;
  const identifySource = adapters.sourceIdentity || sourceIdentity;
  const now = adapters.now || (() => new Date());
  const verifyArchive = adapters.verifyStagedBundleMatchesArchive
    || verifyStagedBundleMatchesArchive;
  const verifyBundle = adapters.verifyDetachedSignedOutUiBundle
    || verifyDetachedSignedOutUiBundle;
  const verifyArtifact = adapters.verifyQualificationArtifact
    || verifyQualificationArtifact;
  const preflightToolchain = adapters.qualificationToolchainPreflight
    || qualificationToolchainPreflight;
  const prepareProfile = adapters.prepareLocalQualificationProfile
    || prepareLocalQualificationProfile;
  const buildEnvironment = adapters.qualificationEnvironment || qualificationEnvironment;
  const captureRepository = adapters.captureRepositoryState || captureRepositoryState;
  const versionState = adapters.exactVersionState || exactVersionState;
  const prepareCode = adapters.prepareCodePaths || prepareCodePaths;
  const resolveCode = adapters.resolveCodeInstallation || resolveCodeInstallation;
  const createInstallArtifact = adapters.createVerifiedInstallArtifact
    || createVerifiedInstallArtifact;
  const installCandidate = adapters.installAndVerifyCandidate || installAndVerifyCandidate;
  const persistJson = adapters.writeJson || writeJson;
  const persistLiveProof = adapters.writeLiveCandidateProof || writeLiveCandidateProof;
  const clearOutput = adapters.removeOutputFile || removeOutputFile;
  const validateRemoteAuthority = adapters.validatedRemoteCiAuthority
    || validatedRemoteCiAuthority;
  const toolchain = preflightToolchain({
    root,
    adapters,
    environment: suppliedEnvironment,
  });
  const profile = prepareProfile({
    homeDirectory: options.homeDirectory,
    profileRoot: options.profileRoot,
  });
  const environment = buildEnvironment(
    suppliedEnvironment,
    profile,
    null,
    process.platform,
  );
  const repositoryBefore = captureRepository(root, spawn, environment);
  if (repositoryBefore.dirty) {
    throw new Error("Remote qualification import requires a clean tracked worktree.");
  }
  const sourceBefore = assertSourceIdentity(identifySource(root, spawn, environment));
  const extension = versionState(root, "local", "current");
  const remote = readJson(REMOTE_CI, root);
  const { artifact } = assertRemoteCiIdentity(remote, sourceBefore);
  const authority = validateRemoteAuthority(root, sourceBefore, adapters);
  if (authority?.laneStatuses?.["remote-ci"] !== "passed"
    || authority?.laneStatuses?.codeql !== "passed"
    || !authority.signedOutCandidate) {
    throw new Error("Remote CI receipt is not independently bound to its API capture and artifact.");
  }
  const archivePath = path.join(root, REMOTE_ARCHIVE);
  const bundleRoot = path.join(root, REMOTE_BUNDLE);
  const vsixPath = path.join(root, REMOTE_VSIX);
  const memberDigests = verifyArchive({
    archivePath,
    bundleRoot,
    expectedDigest: artifact.digest,
  });
  const detached = verifyBundle({
    bundleRoot,
    contractRoot: root,
    expectedMemberDigests: memberDigests,
    expectedSourceSha: sourceBefore.sha,
  });
  const initialVerification = await verifyArtifact(vsixPath, { sourceSha: sourceBefore.sha });
  assertRemoteCandidateIdentity(detached.candidate, initialVerification, sourceBefore, extension);
  assertRemoteCandidateIdentity(
    authority.signedOutCandidate,
    initialVerification,
    sourceBefore,
    extension,
  );
  const codePaths = await prepareCode({
    root,
    profile,
    environment,
    vscodeVersion: extension.vscodeVersion,
    vscodeExecutable: options.vscodeExecutable,
    vscodeCli: options.vscodeCli,
    appRoot: options.appRoot,
    platform: options.platform,
    applicationsDirectory: options.applicationsDirectory,
    spawnSync: spawn,
  });
  const code = resolveCode({
    vscodeExecutable: codePaths.executable,
    vscodeCli: codePaths.cli,
    appRoot: codePaths.appRoot,
    platform: options.platform,
    spawnSync: spawn,
    root,
    environment,
    vscodeVersion: extension.vscodeVersion,
  });
  clearOutput(CANDIDATE_RECEIPT, root, { subtree: ".quality/qualification" });
  clearOutput(LIVE_CANDIDATE_RECEIPT, root, { subtree: ".quality/qualification" });
  clearOutput(LIVE_CANDIDATE_ARTIFACT, root, { subtree: ".quality/qualification" });
  const privateArtifact = createInstallArtifact(initialVerification, {
    temporaryParent: options.temporaryParent || os.tmpdir(),
  });
  let installation;
  try {
    installation = installCandidate({
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
  const finalVerification = await verifyArtifact(vsixPath, { sourceSha: sourceBefore.sha });
  const verification = assertEquivalentVerification(initialVerification, finalVerification);
  assertStableSource(sourceBefore, identifySource(root, spawn, environment));
  assertStableRepositoryState(repositoryBefore, captureRepository(root, spawn, environment));
  const captured = now();
  if (!(captured instanceof Date) || !Number.isFinite(captured.getTime())) {
    throw new Error("Remote qualification capture time is invalid.");
  }
  const receiptBase = {
    schemaVersion: 3,
    status: "passed",
    capturedAt: captured.toISOString(),
    source: sourceBefore,
    repository: repositoryBefore,
    toolchain: {
      nodeVersion: process.version,
      npmVersion: toolchain.npm.version,
      npmInstallationSha256: toolchain.npm.installation.sha256,
      platform: process.platform,
    },
    extension: {
      id: extension.id,
      publisher: extension.publisher,
      name: extension.name,
      version: extension.version,
    },
    vscode: { version: code.version, executable: code.executable, cli: code.cli },
    profile: {
      mode: profile.mode,
      persistent: profile.persistent,
      root: profile.root,
      testResourcesDir: profile.testResourcesDir,
      userDataDir: profile.userDataDir,
      extensionsDir: profile.extensionsDir,
    },
    artifact: {
      vsixPath: REMOTE_VSIX,
      absoluteVsixPath: vsixPath,
      sha256: verification.sha256,
      archiveBytes: verification.archiveBytes,
      entryCount: verification.entryCount,
      sourceSha: sourceBefore.sha,
      sourceFingerprint: sourceBefore.fingerprint,
    },
    installation,
    launch: { status: "not-requested", developmentPath: false },
  };
  const receipt = Object.freeze({ ...receiptBase, fingerprint: fingerprint(receiptBase) });
  persistJson(CANDIDATE_RECEIPT, receipt, root, { subtree: ".quality/qualification" });
  persistLiveProof(root, receipt, verification.buffer);
  return Object.freeze({
    receipt,
    profile: Object.freeze({
      ...profile,
      executable: code.executable,
      cli: code.cli,
      vscodeVersion: code.version,
    }),
    remoteCandidate: detached.candidate,
  });
}

if (require.main === module) {
  prepareRemoteAttestedQualificationCandidate(parseCli(process.argv.slice(2)))
    .then(({ receipt }) => {
      process.stdout.write(
        `Prepared ${receipt.extension.id}@${receipt.extension.version} from remote attested VSIX ${receipt.artifact.sha256}.\n`
      );
    })
    .catch(error => {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 1;
    });
}

module.exports = {
  REMOTE_ARCHIVE,
  REMOTE_BUNDLE,
  REMOTE_CI,
  REMOTE_VSIX,
  assertRemoteCandidateIdentity,
  assertRemoteCiIdentity,
  parseCli,
  prepareRemoteAttestedQualificationCandidate,
};

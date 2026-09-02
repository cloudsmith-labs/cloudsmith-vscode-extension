// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const fs = require("fs");
const crypto = require("crypto");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const {
  preserveNonAuthCleanupSubtree,
  withNonAuthQualityEnvironment,
} = require("../quality/non-auth-environment");
const {
  exactFileIdentity,
  sameExactFileIdentity,
} = require("../quality/candidate-binding");
const {
  assertCanonicalNpmRuntime,
  assertCanonicalNodeRuntime,
  assertExactNodeExecutable,
  assertNoNpmToolchainShadowing,
  canonicalToolchainEnvironment,
  withCanonicalNpmLauncher,
} = require("../quality/canonical-node-runtime");
const { assertVersionState } = require("./verify-version");
const {
  validateSidecars,
  verifyFreshVsix,
} = require("./verify-vsix");

const root = path.resolve(__dirname, "../..");
const VSCE_ENTRY_EVAL = "require(process.argv[1])(process.argv);";
const packageCleanupFailures = new WeakSet();
const WINDOWS_PACKAGE_CLEANUP_RETRIES = 32;
const PACKAGE_BUILD_STAGES = new Set([
  "first-build-command",
  "first-output-receipt",
  "first-source-integrity",
  "first-artifact-verification",
  "second-build-command",
  "second-output-receipt",
  "second-source-integrity",
  "second-artifact-verification",
  "reproducibility",
  "artifact-publication",
  "published-artifact-verification",
  "github-output",
  "completion",
]);

function exactAbsolutePath(value, errorMessage) {
  if (typeof value !== "string" || !path.isAbsolute(value)
    || path.resolve(value) !== value || path.normalize(value) !== value
    || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(errorMessage);
  }
  return value;
}

function canonicalVscePackageInvocation(outputPath, options = {}) {
  const nodeExecutable = assertExactNodeExecutable(
    options.nodeExecutable || process.execPath,
  );
  const vsceEntry = exactAbsolutePath(
    options.vsceEntry || require.resolve("@vscode/vsce/out/main"),
    "Canonical VSCE entry is invalid",
  );
  const output = exactAbsolutePath(outputPath, "Canonical VSCE output path is invalid");
  return Object.freeze({
    command: nodeExecutable,
    arguments_: Object.freeze([
      "--eval",
      VSCE_ENTRY_EVAL,
      vsceEntry,
      "package",
      "--no-dependencies",
      "--out",
      output,
    ]),
  });
}

function run(command, arguments_, options = {}) {
  const spawn = options.spawnSync || spawnSync;
  const suppliedEnvironment = options.environment || process.env;
  const nodeExecutable = options.nodeExecutable
    ? assertExactNodeExecutable(options.nodeExecutable, { platform: options.platform })
    : null;
  const environment = nodeExecutable
    ? canonicalToolchainEnvironment(suppliedEnvironment, {
      nodeExecutable,
      platform: options.platform,
    })
    : suppliedEnvironment;
  const repositoryRoot = options.npm?.repositoryRoot
    || options.repositoryRoot || options.cwd || root;
  if (options.npm) {
    if (!nodeExecutable) throw new Error("Canonical npm packaging requires an exact Node.js runtime");
    if (options.repositoryRoot && options.repositoryRoot !== repositoryRoot) {
      throw new Error("Canonical npm packaging repository binding is unsafe or invalid");
    }
    assertNoNpmToolchainShadowing(repositoryRoot, { platform: options.platform });
  }
  return withNonAuthQualityEnvironment({
    environment,
    overrides: options.environmentOverrides || {},
    platform: options.platform,
    temporaryParent: options.temporaryParent,
  }, (boundaryEnvironment, boundary) => {
    const spawnChild = launcher => spawn(command, arguments_, {
      cwd: options.cwd || root,
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
      windowsHide: true,
      env: nodeExecutable ? canonicalToolchainEnvironment(boundaryEnvironment, {
        launcherDirectory: launcher?.directory,
        nodeExecutable,
        platform: options.platform,
        scriptShell: launcher?.scriptShell,
      }) : boundaryEnvironment,
    });
    const result = options.npm ? withCanonicalNpmLauncher({
      nodeExecutable,
      npm: options.npm,
      platform: options.platform,
      temporaryParent: boundary.paths.temporary,
    }, launcher => spawnChild(launcher)) : spawnChild(null);
    if (result.error || result.signal || result.status !== 0) {
      process.stderr.write(result.stdout || "");
      process.stderr.write(result.stderr || "");
      throw new Error(`${path.basename(command)} failed while building the release artifact`);
    }
    return result.stdout.trim();
  });
}

function gitStatus() {
  return run("git", ["status", "--porcelain=v1", "--untracked-files=all"]);
}

function assertCleanSource(required, expectedSha) {
  const sourceSha = run("git", ["rev-parse", "HEAD^{commit}"]);
  if (expectedSha && sourceSha !== expectedSha) {
    throw new Error("The checked-out HEAD does not match M9_SOURCE_SHA");
  }
  const clean = gitStatus() === "";
  if (required && !clean) {
    throw new Error("Release packaging requires a clean checkout");
  }
  return { clean, sourceSha };
}

function writeAtomically(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const temporary = `${filePath}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, content, { flag: "wx" });
  fs.renameSync(temporary, filePath);
}

function resolveOutputPath(directory, filename) {
  const resolvedDirectory = path.resolve(directory);
  const resolved = path.resolve(resolvedDirectory, filename);
  if (path.dirname(resolved) !== resolvedDirectory) {
    throw new Error("Artifact filename escaped its intended output directory");
  }
  return resolved;
}

function samePackagePath(left, right, platform = process.platform) {
  const pathApi = platform === "win32" ? path.win32 : path.posix;
  const normalize = value => {
    const normalized = pathApi.normalize(value);
    return platform === "win32" ? normalized.toLowerCase() : normalized;
  };
  return normalize(left) === normalize(right);
}

function packageBuildDirectoryIdentity(directory, fileSystem = fs) {
  const stat = fileSystem.lstatSync(directory, { bigint: true });
  if (stat.isSymbolicLink() || !stat.isDirectory()
    || !samePackagePath(fileSystem.realpathSync(directory), directory)) {
    throw new Error("Release package temporary directory must remain an exact real directory.");
  }
  return Object.freeze({
    dev: stat.dev,
    gid: stat.gid,
    ino: stat.ino,
    mode: stat.mode,
    uid: stat.uid,
  });
}

function packageCleanupErrorCode(cause) {
  let descriptor = null;
  try {
    descriptor = cause && (typeof cause === "object" || typeof cause === "function")
      ? Object.getOwnPropertyDescriptor(cause, "code")
      : null;
  } catch {
    return null;
  }
  return descriptor && Object.prototype.hasOwnProperty.call(descriptor, "value")
    && typeof descriptor.value === "string" && /^[A-Z][A-Z0-9_]{1,23}$/u.test(descriptor.value)
    ? descriptor.value
    : null;
}

function packageCleanupError(stage = "validation", cause = null) {
  const code = packageCleanupErrorCode(cause);
  const detail = code ? `${stage}:${code}` : stage;
  const error = new Error(
    `Release package temporary cleanup refused an unsafe or changed tree [${detail}].`,
  );
  packageCleanupFailures.add(error);
  throw error;
}

function isPackageCleanupFailure(error) {
  return Boolean(error && (typeof error === "object" || typeof error === "function")
    && packageCleanupFailures.has(error));
}

function assertPackageCleanupPathAbsent(target, fileSystem, stage) {
  try {
    fileSystem.lstatSync(target);
  } catch (error) {
    if (packageCleanupErrorCode(error) === "ENOENT") return;
    packageCleanupError(stage, error);
  }
  packageCleanupError(stage);
}

function exactPackageBuildRoot(
  directory,
  identity,
  expectedNames,
  fileSystem,
  stage = "root-validation",
) {
  const stat = fileSystem.lstatSync(directory, { bigint: true });
  if (stat.isSymbolicLink() || !stat.isDirectory()
    || String(stat.dev) !== String(identity?.dev)
    || String(stat.gid) !== String(identity?.gid)
    || String(stat.ino) !== String(identity?.ino)
    || String(stat.mode) !== String(identity?.mode)
    || String(stat.uid) !== String(identity?.uid)) {
    packageCleanupError(stage);
  }
  if (!samePackagePath(fileSystem.realpathSync(directory), directory)) {
    packageCleanupError(`${stage}-path`);
  }
  const names = fileSystem.readdirSync(directory).sort();
  if (JSON.stringify(names) !== JSON.stringify([...expectedNames].sort())) {
    packageCleanupError(`${stage}-inventory`);
  }
}

function exactPackageBuildFile(
  directory,
  expected,
  fileSystem,
  stage = "file-validation",
) {
  if (!expected || expected.kind !== "file" || typeof expected.name !== "string"
    || path.basename(expected.name) !== expected.name
    || /[\/\\\u0000-\u001f\u007f]/u.test(expected.name)) {
    packageCleanupError(stage);
  }
  const target = path.join(directory, expected.name);
  const stat = fileSystem.lstatSync(target, { bigint: true });
  if (stat.isSymbolicLink() || !stat.isFile()
    || !sameExactFileIdentity(expected.identity, exactFileIdentity(stat))) {
    packageCleanupError(stage);
  }
  return target;
}

function transientPackageCleanupError(error, operation) {
  const code = packageCleanupErrorCode(error);
  return code === "EPERM" || code === "EBUSY"
    || (operation === "rmdir" && code === "ENOTEMPTY");
}

function boundedRetryDelay(attempt) {
  const milliseconds = Math.min(25 * (2 ** attempt), 800);
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function removePackageBuildDirectory(
  directory,
  identity,
  expectedRootEntries = [],
  options = {},
) {
  const fileSystem = options.fileSystem || fs;
  const platform = options.platform || process.platform;
  const retryDelay = options.retryDelay || boundedRetryDelay;
  const maximumRetries = platform === "win32" ? WINDOWS_PACKAGE_CLEANUP_RETRIES : 0;
  const expectedByName = new Map();
  let cleanupContainer = null;
  let cleanupDirectory = directory;
  try {
    if (!Array.isArray(expectedRootEntries) || expectedRootEntries.length > 2) {
      packageCleanupError("entry-inventory");
    }
    for (const expected of expectedRootEntries) {
      if (!expected || expected.kind !== "file" || typeof expected.name !== "string"
        || path.basename(expected.name) !== expected.name
        || /[\/\\\u0000-\u001f\u007f]/u.test(expected.name)
        || expectedByName.has(expected.name)) {
        packageCleanupError("entry-inventory");
      }
      expectedByName.set(expected.name, expected);
    }
    exactPackageBuildRoot(
      directory,
      identity,
      expectedByName.keys(),
      fileSystem,
      "initial-root-validation",
    );
    for (const expected of expectedRootEntries) {
      exactPackageBuildFile(directory, expected, fileSystem, "initial-file-validation");
    }

    const cleanupToken = crypto.randomBytes(16).toString("hex");
    cleanupContainer = path.join(
      path.dirname(directory),
      `.${path.basename(directory)}.cleanup-${cleanupToken}`,
    );
    if (fileSystem.existsSync(cleanupContainer)) {
      packageCleanupError("quarantine-collision");
    }
    fileSystem.mkdirSync(cleanupContainer, { mode: 0o700 });
    if (platform !== "win32") fileSystem.chmodSync(cleanupContainer, 0o700);
    const cleanupContainerIdentity = packageBuildDirectoryIdentity(
      cleanupContainer,
      fileSystem,
    );
    exactPackageBuildRoot(
      cleanupContainer,
      cleanupContainerIdentity,
      [],
      fileSystem,
      "quarantine-container-validation",
    );
    cleanupDirectory = path.join(cleanupContainer, "tree");
    let quarantineAttempt = 0;
    while (true) {
      exactPackageBuildRoot(
        directory,
        identity,
        expectedByName.keys(),
        fileSystem,
        "quarantine-rename-root-validation",
      );
      for (const expected of expectedRootEntries) {
        exactPackageBuildFile(
          directory,
          expected,
          fileSystem,
          "quarantine-rename-file-validation",
        );
      }
      exactPackageBuildRoot(
        cleanupContainer,
        cleanupContainerIdentity,
        [],
        fileSystem,
        "quarantine-rename-container-validation",
      );
      assertPackageCleanupPathAbsent(
        cleanupDirectory,
        fileSystem,
        "quarantine-rename-target-occupied",
      );
      try {
        fileSystem.renameSync(directory, cleanupDirectory);
      } catch (error) {
        if (quarantineAttempt >= maximumRetries
          || !transientPackageCleanupError(error, "rename")) {
          packageCleanupError("quarantine-rename-retry-exhausted", error);
        }
        retryDelay(quarantineAttempt);
        quarantineAttempt += 1;
        continue;
      }
      break;
    }
    assertPackageCleanupPathAbsent(
      directory,
      fileSystem,
      "original-path-reoccupied-after-quarantine",
    );
    exactPackageBuildRoot(
      cleanupContainer,
      cleanupContainerIdentity,
      [path.basename(cleanupDirectory)],
      fileSystem,
      "quarantine-container-validation",
    );
    exactPackageBuildRoot(
      cleanupDirectory,
      identity,
      expectedByName.keys(),
      fileSystem,
      "quarantined-root-validation",
    );
    for (const expected of expectedRootEntries) {
      exactPackageBuildFile(
        cleanupDirectory,
        expected,
        fileSystem,
        "quarantined-file-validation",
      );
    }

    for (const expected of expectedRootEntries) {
      let attempt = 0;
      while (true) {
        assertPackageCleanupPathAbsent(
          directory,
          fileSystem,
          "original-path-reoccupied-before-unlink",
        );
        exactPackageBuildRoot(
          cleanupDirectory,
          identity,
          expectedByName.keys(),
          fileSystem,
          "unlink-root-validation",
        );
        const target = exactPackageBuildFile(
          cleanupDirectory,
          expected,
          fileSystem,
          "unlink-file-validation",
        );
        try {
          fileSystem.unlinkSync(target);
        } catch (error) {
          if (attempt >= maximumRetries || !transientPackageCleanupError(error, "unlink")) {
            packageCleanupError("unlink-retry-exhausted", error);
          }
          exactPackageBuildRoot(
            cleanupDirectory,
            identity,
            expectedByName.keys(),
            fileSystem,
            "unlink-retry-root-validation",
          );
          exactPackageBuildFile(
            cleanupDirectory,
            expected,
            fileSystem,
            "unlink-retry-file-validation",
          );
          retryDelay(attempt);
          assertPackageCleanupPathAbsent(
            directory,
            fileSystem,
            "original-path-reoccupied-during-unlink-retry",
          );
          attempt += 1;
          continue;
        }
        try {
          fileSystem.lstatSync(target);
          packageCleanupError("unlink-postcondition");
        } catch (error) {
          if (isPackageCleanupFailure(error)) throw error;
          if (packageCleanupErrorCode(error) !== "ENOENT") {
            packageCleanupError("unlink-postcondition", error);
          }
        }
        expectedByName.delete(expected.name);
        assertPackageCleanupPathAbsent(
          directory,
          fileSystem,
          "original-path-reoccupied-after-unlink",
        );
        break;
      }
    }

    let attempt = 0;
    while (true) {
      assertPackageCleanupPathAbsent(
        directory,
        fileSystem,
        "original-path-reoccupied-before-rmdir",
      );
      exactPackageBuildRoot(
        cleanupDirectory,
        identity,
        [],
        fileSystem,
        "rmdir-root-validation",
      );
      try {
        fileSystem.rmdirSync(cleanupDirectory);
      } catch (error) {
        if (attempt >= maximumRetries || !transientPackageCleanupError(error, "rmdir")) {
          packageCleanupError("rmdir-retry-exhausted", error);
        }
        exactPackageBuildRoot(
          cleanupDirectory,
          identity,
          [],
          fileSystem,
          "rmdir-retry-root-validation",
        );
        retryDelay(attempt);
        assertPackageCleanupPathAbsent(
          directory,
          fileSystem,
          "original-path-reoccupied-during-rmdir-retry",
        );
        attempt += 1;
        continue;
      }
      assertPackageCleanupPathAbsent(
        directory,
        fileSystem,
        "original-path-reoccupied-after-rmdir",
      );
      break;
    }
    if (fileSystem.existsSync(cleanupDirectory)) packageCleanupError("rmdir-postcondition");
    exactPackageBuildRoot(
      cleanupContainer,
      cleanupContainerIdentity,
      [],
      fileSystem,
      "quarantine-container-final-validation",
    );
    assertPackageCleanupPathAbsent(
      directory,
      fileSystem,
      "original-path-reoccupied-before-quarantine-rmdir",
    );
    attempt = 0;
    while (true) {
      exactPackageBuildRoot(
        cleanupContainer,
        cleanupContainerIdentity,
        [],
        fileSystem,
        "quarantine-rmdir-validation",
      );
      assertPackageCleanupPathAbsent(
        cleanupDirectory,
        fileSystem,
        "quarantine-tree-reoccupied-before-container-rmdir",
      );
      assertPackageCleanupPathAbsent(
        directory,
        fileSystem,
        "original-path-reoccupied-before-quarantine-rmdir",
      );
      try {
        fileSystem.rmdirSync(cleanupContainer);
      } catch (error) {
        if (attempt >= maximumRetries || !transientPackageCleanupError(error, "rmdir")) {
          packageCleanupError("quarantine-rmdir-retry-exhausted", error);
        }
        exactPackageBuildRoot(
          cleanupContainer,
          cleanupContainerIdentity,
          [],
          fileSystem,
          "quarantine-rmdir-retry-validation",
        );
        retryDelay(attempt);
        assertPackageCleanupPathAbsent(
          directory,
          fileSystem,
          "original-path-reoccupied-during-quarantine-rmdir-retry",
        );
        attempt += 1;
        continue;
      }
      break;
    }
    assertPackageCleanupPathAbsent(
      cleanupContainer,
      fileSystem,
      "quarantine-container-rmdir-postcondition",
    );
    assertPackageCleanupPathAbsent(
      directory,
      fileSystem,
      "original-path-reoccupied-after-quarantine-rmdir",
    );
    return true;
  } catch (error) {
    if (typeof cleanupContainer === "string" && path.isAbsolute(cleanupContainer)) {
      preserveNonAuthCleanupSubtree(cleanupContainer);
    }
    if (typeof directory === "string" && path.isAbsolute(directory)) {
      preserveNonAuthCleanupSubtree(directory);
    }
    if (isPackageCleanupFailure(error)) throw error;
    packageCleanupError("unexpected-cleanup-failure", error);
  }
}

function authenticatePackageNpmRuntime(
  repositoryRoot,
  nodeExecutable,
  authenticate = assertCanonicalNpmRuntime,
) {
  // npm rewrites npm_execpath when an npm lifecycle runs through our private
  // snapshot. That ambient bookkeeping field is not an authority claim: bind
  // the complete canonical installation beside the already exact Node binary.
  return authenticate(repositoryRoot, undefined, { nodeExecutable });
}

function capturePackageBuildOutput(directory, outputPath, options = {}) {
  const fileSystem = options.fileSystem || fs;
  const platform = options.platform || process.platform;
  const pathApi = platform === "win32" ? path.win32 : path.posix;
  const errorMessage = "Release package output cleanup receipt is unsafe or invalid.";
  if (typeof directory !== "string" || typeof outputPath !== "string"
    || !pathApi.isAbsolute(directory) || !pathApi.isAbsolute(outputPath)
    || pathApi.normalize(directory) !== directory || pathApi.resolve(directory) !== directory
    || pathApi.normalize(outputPath) !== outputPath || pathApi.resolve(outputPath) !== outputPath
    || !samePackagePath(pathApi.dirname(outputPath), directory, platform)) {
    throw new Error(errorMessage);
  }
  let before;
  try {
    before = fileSystem.lstatSync(outputPath, { bigint: true });
  } catch (error) {
    if (packageCleanupErrorCode(error) === "ENOENT") return null;
    throw new Error(errorMessage);
  }
  try {
    if (before.isSymbolicLink() || !before.isFile() || before.nlink !== 1n
      || !samePackagePath(fileSystem.realpathSync(outputPath), outputPath, platform)) {
      throw new Error(errorMessage);
    }
    const identity = exactFileIdentity(before);
    const after = fileSystem.lstatSync(outputPath, { bigint: true });
    if (!sameExactFileIdentity(identity, exactFileIdentity(after))) {
      throw new Error(errorMessage);
    }
    return Object.freeze({
      identity,
      kind: "file",
      name: pathApi.basename(outputPath),
    });
  } catch {
    throw new Error(errorMessage);
  }
}

function capturePackageBuildOutputAfterCommand(
  directory,
  outputPath,
  cleanupEntries,
  commandError = null,
  options = {},
) {
  let receipt = null;
  let receiptError = null;
  try {
    receipt = capturePackageBuildOutput(directory, outputPath, options);
  } catch (error) {
    receiptError = error;
  }
  if (receipt) cleanupEntries.push(receipt);
  if (commandError) throw commandError;
  if (receiptError) throw receiptError;
  if (!receipt) throw new Error("VSCE packaging did not create its exact output file");
  return receipt;
}

function packageBuildError(stage) {
  const safeStage = PACKAGE_BUILD_STAGES.has(stage) ? stage : "unexpected";
  return new Error(`Release package build failed [${safeStage}].`);
}

function settlePackageBuildDirectory(
  directory,
  identity,
  expectedEntries,
  primaryError = null,
  stage = "unexpected",
  options = {},
) {
  const remove = options.removePackageBuildDirectory || removePackageBuildDirectory;
  try {
    remove(directory, identity, expectedEntries, options.cleanupOptions || {});
  } catch (cleanupError) {
    if (!primaryError) throw cleanupError;
    const safeStage = PACKAGE_BUILD_STAGES.has(stage) ? stage : "unexpected";
    throw new Error(
      `Release package build failed and its temporary tree was preserved `
      + `[${safeStage}:cleanup-refused].`,
    );
  }
  if (primaryError) throw packageBuildError(stage);
  return true;
}

async function main() {
  assertCanonicalNodeRuntime(root, process.version);
  const nodeExecutable = assertExactNodeExecutable(process.execPath);
  canonicalToolchainEnvironment(process.env, { nodeExecutable });
  const npm = authenticatePackageNpmRuntime(root, nodeExecutable);
  assertNoNpmToolchainShadowing(root);
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const lockfile = JSON.parse(fs.readFileSync(path.join(root, "package-lock.json"), "utf8"));
  const changelog = fs.readFileSync(path.join(root, "CHANGELOG.md"), "utf8");
  const { name, version } = assertVersionState({ manifest, lockfile, changelog });
  if (!manifest.dependencies || Object.keys(manifest.dependencies).length) {
    throw new Error("VSIX packaging requires package.json dependencies to be explicitly empty");
  }

  const requireClean = process.env.M9_REQUIRE_CLEAN === "1";
  const { clean, sourceSha } = assertCleanSource(requireClean, process.env.M9_SOURCE_SHA);
  const releaseBuild = requireClean && clean;
  const sourceCommitEpoch = Number(run("git", ["show", "-s", "--format=%ct", sourceSha]));
  if (!Number.isSafeInteger(sourceCommitEpoch) || sourceCommitEpoch <= 0) {
    throw new Error("Could not derive a valid source commit epoch");
  }

  const tempDirectory = fs.realpathSync(fs.mkdtempSync(
    path.join(os.tmpdir(), "cloudsmith-vsix-"),
  ));
  if (process.platform !== "win32") fs.chmodSync(tempDirectory, 0o700);
  const tempDirectoryIdentity = packageBuildDirectoryIdentity(tempDirectory);
  const filename = `${name}-${version}.vsix`;
  const firstPath = resolveOutputPath(tempDirectory, `first-${filename}`);
  const secondPath = resolveOutputPath(tempDirectory, `second-${filename}`);
  const environmentOverrides = {
    SOURCE_DATE_EPOCH: String(sourceCommitEpoch),
    TZ: "UTC",
  };
  const buildResults = [];
  const cleanupBuildEntries = [];
  let buildStage = "first-build-command";
  let primaryError = null;

  try {
    const sourceReference = clean ? sourceSha : null;
    for (const [index, outputPath] of [firstPath, secondPath].entries()) {
      const ordinal = index === 0 ? "first" : "second";
      buildStage = `${ordinal}-build-command`;
      const invocation = canonicalVscePackageInvocation(outputPath);
      let commandError = null;
      try {
        run(invocation.command, invocation.arguments_, {
          environmentOverrides,
          nodeExecutable,
          npm,
          repositoryRoot: root,
        });
      } catch (error) {
        commandError = error;
      }
      buildStage = `${ordinal}-output-receipt`;
      let outputReceipt;
      try {
        outputReceipt = capturePackageBuildOutputAfterCommand(
          tempDirectory,
          outputPath,
          cleanupBuildEntries,
          commandError,
        );
      } catch (error) {
        if (error === commandError) buildStage = `${ordinal}-build-command`;
        throw error;
      }
      buildStage = `${ordinal}-source-integrity`;
      if (requireClean && gitStatus() !== "") {
        throw new Error("VSCE prepublish changed the clean source checkout");
      }
      buildStage = `${ordinal}-artifact-verification`;
      const verification = await verifyFreshVsix(outputPath, {
        expectedIdentity: outputReceipt.identity,
        sourceSha: sourceReference,
      });
      buildResults.push(verification);
    }

    buildStage = "reproducibility";
    const [first, second] = buildResults;
    if (first.sha256 !== second.sha256 || !first.buffer.equals(second.buffer)) {
      throw new Error("Two canonical VSIX builds from the same source were not byte-identical");
    }

    const outputKind = releaseBuild ? "release" : "development";
    const outputDirectory = path.join(root, "out", outputKind);
    const outputPath = resolveOutputPath(outputDirectory, filename);
    const checksumPath = `${outputPath}.sha256`;
    const provenancePath = `${outputPath}.provenance.json`;
    const provenance = {
      schemaVersion: 3,
      sourceSha,
      sourceCommitEpoch,
      sourceClean: clean,
      publishable: releaseBuild,
      publisher: manifest.publisher,
      name,
      version,
      filename,
      sha256: first.sha256,
      archiveBytes: first.archiveBytes,
      entryCount: first.entryCount,
      totalUncompressedBytes: first.totalUncompressedBytes,
      nodeVersion: process.version,
      npmVersion: npm.version,
      npmInstallationSha256: npm.installation.sha256,
      platform: process.platform,
    };

    buildStage = "artifact-publication";
    writeAtomically(outputPath, first.buffer);
    writeAtomically(checksumPath, `${first.sha256}  ${filename}\n`);
    writeAtomically(provenancePath, `${JSON.stringify(provenance, null, 2)}\n`);

    buildStage = "published-artifact-verification";
    const publishedReceipt = capturePackageBuildOutput(outputDirectory, outputPath);
    const written = await verifyFreshVsix(outputPath, {
      expectedIdentity: publishedReceipt.identity,
      sourceSha: sourceReference,
    });
    validateSidecars(outputPath, written, {
      expectedSourceSha: sourceSha,
      requirePublishable: releaseBuild,
    });

    buildStage = "github-output";
    const githubOutputIndex = process.argv.indexOf("--github-output");
    if (githubOutputIndex !== -1) {
      const githubOutput = process.argv[githubOutputIndex + 1];
      if (!githubOutput) {
        throw new Error("--github-output requires a file path");
      }
      const relative = (value) => path.relative(root, value).split(path.sep).join("/");
      const outputValues = [outputPath, checksumPath, provenancePath].map(relative);
      if (outputValues.some((value) => value.startsWith("../") || /[\r\n]/.test(value))) {
        throw new Error("Artifact path is unsafe for GitHub output emission");
      }
      fs.appendFileSync(
        githubOutput,
        `vsix_path=${outputValues[0]}\nchecksum_path=${outputValues[1]}\nprovenance_path=${outputValues[2]}\n`,
      );
    }

    buildStage = "completion";
    console.log(
      `Built reproducible ${outputKind} artifact ${path.relative(root, outputPath)} `
      + `(${first.entryCount} entries, sha256 ${first.sha256}).`,
    );
    if (!clean) {
      console.log("The worktree is dirty; this development artifact is explicitly non-publishable.");
    } else if (!releaseBuild) {
      console.log("Release mode was not requested; this development artifact is explicitly non-publishable.");
    }
  } catch {
    primaryError = true;
  }
  settlePackageBuildDirectory(
    tempDirectory,
    tempDirectoryIdentity,
    Object.freeze([...cleanupBuildEntries]),
    primaryError,
    buildStage,
  );
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}

module.exports = {
  authenticatePackageNpmRuntime,
  capturePackageBuildOutput,
  capturePackageBuildOutputAfterCommand,
  canonicalVscePackageInvocation,
  packageBuildDirectoryIdentity,
  removePackageBuildDirectory,
  runPackageCommand: run,
  settlePackageBuildDirectory,
  resolveOutputPath,
  samePackagePath,
};

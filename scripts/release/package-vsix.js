// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const {
  removeExactOwnedDirectoryTree,
  withNonAuthQualityEnvironment,
} = require("../quality/non-auth-environment");
const {
  assertCanonicalNpmRuntime,
  assertCanonicalNodeRuntime,
  assertExactNodeExecutable,
  assertNoNpmToolchainShadowing,
  canonicalToolchainEnvironment,
  withCanonicalNpmLauncher,
} = require("../quality/canonical-node-runtime");
const { assertVersionState } = require("./verify-version");
const { validateSidecars, verifyVsix } = require("./verify-vsix");

const root = path.resolve(__dirname, "../..");
const VSCE_ENTRY_EVAL = "require(process.argv[1])(process.argv);";

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

function packageBuildDirectoryIdentity(directory) {
  const stat = fs.lstatSync(directory, { bigint: true });
  if (stat.isSymbolicLink() || !stat.isDirectory()
    || fs.realpathSync(directory) !== directory) {
    throw new Error("Release package temporary directory must remain an exact real directory.");
  }
  return Object.freeze({ dev: stat.dev, ino: stat.ino });
}

function removePackageBuildDirectory(directory, identity, expectedRootEntries = []) {
  removeExactOwnedDirectoryTree(directory, {
    errorMessage: "Release package temporary cleanup refused an unsafe or changed tree.",
    expectedRootEntries,
    expectedRootIdentity: identity,
  });
  return !fs.existsSync(directory);
}

async function main() {
  assertCanonicalNodeRuntime(root, process.version);
  const nodeExecutable = assertExactNodeExecutable(process.execPath);
  canonicalToolchainEnvironment(process.env, { nodeExecutable });
  const npm = assertCanonicalNpmRuntime(root, process.env.npm_execpath, { nodeExecutable });
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
  const expectedBuildEntries = [];

  try {
    const sourceReference = clean ? sourceSha : null;
    for (const outputPath of [firstPath, secondPath]) {
      const invocation = canonicalVscePackageInvocation(outputPath);
      run(invocation.command, invocation.arguments_, {
        environmentOverrides,
        nodeExecutable,
        npm,
        repositoryRoot: root,
      });
      if (requireClean && gitStatus() !== "") {
        throw new Error("VSCE prepublish changed the clean source checkout");
      }
      const verification = await verifyVsix(outputPath, { sourceSha: sourceReference });
      buildResults.push(verification);
      expectedBuildEntries.push(Object.freeze({
        identity: verification.artifactIdentity,
        kind: "file",
        name: path.basename(outputPath),
      }));
    }

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

    writeAtomically(outputPath, first.buffer);
    writeAtomically(checksumPath, `${first.sha256}  ${filename}\n`);
    writeAtomically(provenancePath, `${JSON.stringify(provenance, null, 2)}\n`);

    const written = await verifyVsix(outputPath, { sourceSha: sourceReference });
    validateSidecars(outputPath, written, {
      expectedSourceSha: sourceSha,
      requirePublishable: releaseBuild,
    });

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

    console.log(
      `Built reproducible ${outputKind} artifact ${path.relative(root, outputPath)} `
      + `(${first.entryCount} entries, sha256 ${first.sha256}).`,
    );
    if (!clean) {
      console.log("The worktree is dirty; this development artifact is explicitly non-publishable.");
    } else if (!releaseBuild) {
      console.log("Release mode was not requested; this development artifact is explicitly non-publishable.");
    }
  } finally {
    removePackageBuildDirectory(
      tempDirectory,
      tempDirectoryIdentity,
      Object.freeze([...expectedBuildEntries]),
    );
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}

module.exports = {
  canonicalVscePackageInvocation,
  packageBuildDirectoryIdentity,
  removePackageBuildDirectory,
  runPackageCommand: run,
  resolveOutputPath,
};

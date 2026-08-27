// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const { buildNonAuthQualityEnvironment } = require("../quality/non-auth-environment");
const { assertVersionState } = require("./verify-version");
const { validateSidecars, verifyVsix } = require("./verify-vsix");

const root = path.resolve(__dirname, "../..");

function run(command, arguments_, options = {}) {
  const spawn = options.spawnSync || spawnSync;
  const environment = buildNonAuthQualityEnvironment(
    options.environment || process.env,
    options.environmentOverrides || {},
    { platform: options.platform }
  );
  const result = spawn(command, arguments_, {
    cwd: options.cwd || root,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    windowsHide: true,
    env: environment,
  });
  if (result.error || result.signal || result.status !== 0) {
    process.stderr.write(result.stdout || "");
    process.stderr.write(result.stderr || "");
    throw new Error(`${path.basename(command)} failed while building the release artifact`);
  }
  return result.stdout.trim();
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

async function main() {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const lockfile = JSON.parse(fs.readFileSync(path.join(root, "package-lock.json"), "utf8"));
  const changelog = fs.readFileSync(path.join(root, "CHANGELOG.md"), "utf8");
  const { name, version } = assertVersionState({ manifest, lockfile, changelog });
  if (!manifest.dependencies || Object.keys(manifest.dependencies).length) {
    throw new Error("VSIX packaging requires package.json dependencies to be explicitly empty");
  }

  const requireClean = process.env.M9_REQUIRE_CLEAN === "1";
  const canonicalNodeVersion = `v${fs.readFileSync(path.join(root, ".node-version"), "utf8").trim()}`;
  if (requireClean && process.version !== canonicalNodeVersion) {
    throw new Error(`Release packaging requires Node.js ${canonicalNodeVersion}`);
  }
  const { clean, sourceSha } = assertCleanSource(requireClean, process.env.M9_SOURCE_SHA);
  const releaseBuild = requireClean && clean;
  const sourceCommitEpoch = Number(run("git", ["show", "-s", "--format=%ct", sourceSha]));
  if (!Number.isSafeInteger(sourceCommitEpoch) || sourceCommitEpoch <= 0) {
    throw new Error("Could not derive a valid source commit epoch");
  }

  const tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-vsix-"));
  const filename = `${name}-${version}.vsix`;
  const firstPath = resolveOutputPath(tempDirectory, `first-${filename}`);
  const secondPath = resolveOutputPath(tempDirectory, `second-${filename}`);
  const vsce = path.join(root, "node_modules", ".bin", process.platform === "win32" ? "vsce.cmd" : "vsce");
  const environmentOverrides = {
    SOURCE_DATE_EPOCH: String(sourceCommitEpoch),
    TZ: "UTC",
  };

  try {
    for (const outputPath of [firstPath, secondPath]) {
      run(vsce, ["package", "--no-dependencies", "--out", outputPath], {
        environmentOverrides,
      });
      if (requireClean && gitStatus() !== "") {
        throw new Error("VSCE prepublish changed the clean source checkout");
      }
    }

    const sourceReference = clean ? sourceSha : null;
    const first = await verifyVsix(firstPath, { sourceSha: sourceReference });
    const second = await verifyVsix(secondPath, { sourceSha: sourceReference });
    if (first.sha256 !== second.sha256 || !first.buffer.equals(second.buffer)) {
      throw new Error("Two canonical VSIX builds from the same source were not byte-identical");
    }

    const outputKind = releaseBuild ? "release" : "development";
    const outputDirectory = path.join(root, "out", outputKind);
    const outputPath = resolveOutputPath(outputDirectory, filename);
    const checksumPath = `${outputPath}.sha256`;
    const provenancePath = `${outputPath}.provenance.json`;
    const provenance = {
      schemaVersion: 1,
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
      npmVersion: run(process.platform === "win32" ? "npm.cmd" : "npm", ["--version"]),
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
    fs.rmSync(tempDirectory, { recursive: true, force: true });
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}

module.exports = {
  runPackageCommand: run,
  resolveOutputPath,
};

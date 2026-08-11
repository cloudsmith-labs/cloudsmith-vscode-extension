// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const root = path.resolve(__dirname, "../..");

function assertVersionState({ manifest, lockfile, changelog }) {
  const { name, publisher, version } = manifest;
  if (!/^[a-z0-9][a-z0-9-]{0,99}$/.test(name || "")) {
    throw new Error("package.json name must be a safe lowercase extension identifier");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,99}$/.test(publisher || "")) {
    throw new Error("package.json publisher must be a safe extension publisher identifier");
  }
  if (!/^\d+\.\d+\.\d+$/.test(version || "")) {
    throw new Error("package.json must contain an exact semantic version");
  }
  if (lockfile.name !== name || lockfile.version !== version) {
    throw new Error("package-lock.json name/version must match package.json");
  }
  if (lockfile.packages?.[""]?.name !== name || lockfile.packages?.[""]?.version !== version) {
    throw new Error("package-lock.json root package name/version must match package.json");
  }

  const escapedVersion = version.replaceAll(".", "\\.");
  const versionHeading = new RegExp(`^##\\s+${escapedVersion}(?:\\s|$)`, "gm");
  const matches = changelog.match(versionHeading) || [];
  if (matches.length !== 1) {
    throw new Error(`CHANGELOG.md must contain exactly one level-two heading for ${version}`);
  }
  const versionHeadings = [...changelog.matchAll(/^##\s+(?!Unreleased\b)(\d+\.\d+\.\d+)(?:\s|$)/gim)];
  if (!versionHeadings.length || versionHeadings[0][1] !== version) {
    throw new Error(`The newest versioned CHANGELOG.md heading must be ${version}`);
  }
  return { name, publisher, version };
}

function runGit(arguments_) {
  const result = spawnSync("git", arguments_, { cwd: root, encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error((result.stderr || result.stdout || "git command failed").trim());
  }
  return result.stdout.trim();
}

function verifyReleaseTag(version, tag = process.env.GITHUB_REF_NAME) {
  const expectedTag = `v${version}`;
  if (tag !== expectedTag) {
    throw new Error(`Release tag must be ${expectedTag}`);
  }
  const head = runGit(["rev-parse", "HEAD^{commit}"]);
  const taggedCommit = runGit(["rev-parse", `${tag}^{commit}`]);
  if (head !== taggedCommit) {
    throw new Error(`Release tag ${tag} does not point to the checked-out source commit`);
  }
}

function main() {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const lockfile = JSON.parse(fs.readFileSync(path.join(root, "package-lock.json"), "utf8"));
  const changelog = fs.readFileSync(path.join(root, "CHANGELOG.md"), "utf8");
  const { name, version } = assertVersionState({ manifest, lockfile, changelog });
  if (process.argv.includes("--release")) {
    verifyReleaseTag(version);
  }
  console.log(`Verified ${name} version ${version}${process.argv.includes("--release") ? " and release tag" : ""}.`);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

module.exports = {
  assertVersionState,
  verifyReleaseTag,
};

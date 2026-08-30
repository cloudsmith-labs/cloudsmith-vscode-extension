// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const { ROOT, normalizePath, uniqueSorted } = require("./common");
const { withNonAuthQualityEnvironment } = require("./non-auth-environment");

const EVIDENCE_STATUSES = Object.freeze([
  "passed",
  "failed",
  "blocked",
  "not-run",
  "not-applicable",
]);
const EXACT_SOURCE_READ_FLAGS = fs.constants.O_RDONLY
  | (fs.constants.O_NOFOLLOW || 0)
  | (fs.constants.O_NONBLOCK || 0);
const MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024;

function canonicalize(value) {
  if (Array.isArray(value)) {
    const normalized = value.map(canonicalize);
    Object.defineProperty(normalized, "toJSON", {
      configurable: false,
      enumerable: false,
      value: undefined,
      writable: false,
    });
    return normalized;
  }
  if (!value || typeof value !== "object") return value;
  const normalized = Object.create(null);
  for (const key of Object.keys(value).sort()) {
    normalized[key] = canonicalize(value[key]);
  }
  return normalized;
}

function fingerprint(value) {
  return crypto.createHash("sha256")
    .update(JSON.stringify(canonicalize(value)))
    .digest("hex");
}

function sourceIdentity(
  root = ROOT,
  spawn = spawnSync,
  environment = process.env,
  options = {}
) {
  return withNonAuthQualityEnvironment({
    environment,
    platform: options.platform,
    temporaryParent: options.temporaryParent,
  }, childEnvironment => {
    const head = runGit(root, spawn, ["rev-parse", "HEAD"], "utf8", childEnvironment);
    const diff = runGit(root, spawn, ["diff", "--binary", "HEAD", "--"], null, childEnvironment);
    const untracked = runGit(
      root,
      spawn,
      ["ls-files", "--others", "--exclude-standard", "-z"],
      null,
      childEnvironment
    );
    const sourceSha = head.toString("utf8").trim();
    const hash = crypto.createHash("sha256");
    hash.update(`sha\0${sourceSha}\0tracked\0`);
    hash.update(diff);
    hash.update("\0untracked\0");
    const files = uniqueSorted(
      untracked.toString("utf8").split("\0").filter(Boolean).map(normalizePath)
    );
    for (const file of files) hashFileState(hash, root, file);
    return { sha: sourceSha, fingerprint: hash.digest("hex") };
  });
}

function runGit(root, spawn, args, encoding, environment) {
  const result = spawn("git", args, {
    cwd: root,
    encoding,
    env: environment,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.signal || result.status !== 0) {
    const detail = Buffer.isBuffer(result.stderr)
      ? result.stderr.toString("utf8").trim()
      : String(result.stderr || "").trim();
    throw new Error(`git ${args.join(" ")} failed${detail ? `: ${detail}` : "."}`);
  }
  return Buffer.isBuffer(result.stdout)
    ? result.stdout
    : Buffer.from(result.stdout || "", encoding || "utf8");
}

function hashFileState(hash, root, file) {
  const target = path.join(root, file);
  hash.update(`${file}\0`);
  let descriptor;
  try {
    descriptor = fs.openSync(target, EXACT_SOURCE_READ_FLAGS);
  } catch (openError) {
    let stat;
    try {
      stat = fs.lstatSync(target, { bigint: true });
    } catch (statError) {
      if (openError.code === "ENOENT" && statError.code === "ENOENT") {
        hash.update("missing\0");
        return;
      }
      throw openError;
    }
    if (!stat.isSymbolicLink()) throw openError;
    const link = fs.readlinkSync(target);
    const finalStat = fs.lstatSync(target, { bigint: true });
    if (!finalStat.isSymbolicLink() || !sameFileIdentity(stat, finalStat)) {
      throw new Error("Source file changed while its symlink state was captured.");
    }
    hash.update(`symlink\0${link}\0`);
    return;
  }

  let bytes;
  let completed = false;
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    const current = fs.lstatSync(target, { bigint: true });
    if (current.isSymbolicLink()) {
      const link = fs.readlinkSync(target);
      const finalStat = fs.lstatSync(target, { bigint: true });
      if (!finalStat.isSymbolicLink() || !sameFileIdentity(current, finalStat)) {
        throw new Error("Source file changed while its symlink state was captured.");
      }
      hash.update(`symlink\0${link}\0`);
    } else {
      if (!sameFileIdentity(opened, current)) {
        throw new Error("Source file changed before its fingerprint was captured.");
      }
      if (!opened.isFile()) {
        hash.update(`other:${String(opened.mode)}\0`);
      } else {
        if (opened.size > BigInt(MAX_SOURCE_FILE_BYTES)) {
          throw new Error("Source file exceeds the fingerprint size bound.");
        }
        bytes = fs.readFileSync(descriptor);
        const finalOpened = fs.fstatSync(descriptor, { bigint: true });
        const finalPath = fs.lstatSync(target, { bigint: true });
        if (bytes.length !== Number(opened.size)
          || finalPath.isSymbolicLink()
          || !sameFileIdentity(opened, finalOpened)
          || !sameFileIdentity(opened, finalPath)) {
          throw new Error("Source file changed while its fingerprint was captured.");
        }
        hash.update(`file:${(opened.mode & 0o111n) !== 0n ? "executable" : "regular"}\0`);
        hash.update(bytes);
        hash.update("\0");
      }
    }
    completed = true;
  } finally {
    if (Buffer.isBuffer(bytes)) bytes.fill(0);
    try {
      fs.closeSync(descriptor);
    } catch {
      completed = false;
    }
  }
  if (!completed) throw new Error("Source file descriptor could not be closed safely.");
}

function sameFileIdentity(left, right) {
  return ["dev", "ino", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every(key => left[key] === right[key]);
}

function aggregateStatuses(statuses) {
  const values = statuses.filter(status => EVIDENCE_STATUSES.includes(status));
  if (values.includes("failed")) return "failed";
  if (values.includes("blocked")) return "blocked";
  if (values.includes("not-run")) return "not-run";
  if (values.includes("passed")) return "passed";
  return "not-applicable";
}

function readJsonIfPresent(target) {
  if (!target || !fs.existsSync(target)) return null;
  return JSON.parse(fs.readFileSync(target, "utf8"));
}

function relativeEvidencePath(root, target) {
  const relative = normalizePath(path.relative(root, target));
  if (relative.startsWith("../") || path.isAbsolute(relative)) {
    throw new Error(`Evidence output must remain inside the repository: ${target}`);
  }
  return relative;
}

module.exports = {
  EVIDENCE_STATUSES,
  aggregateStatuses,
  canonicalize,
  fingerprint,
  readJsonIfPresent,
  relativeEvidencePath,
  sourceIdentity,
};

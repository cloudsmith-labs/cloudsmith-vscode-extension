// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const root = path.resolve(__dirname, "../..");
const severityRank = Object.freeze({ info: 0, low: 1, moderate: 2, high: 3, critical: 4 });
const allowedInstallScripts = new Set([
  "node_modules/@vscode/vsce-sign",
  "node_modules/keytar",
]);

function advisoryId(advisory) {
  const match = /^https:\/\/github\.com\/advisories\/(GHSA-[a-z0-9-]+)$/i.exec(advisory.url || "");
  if (!match) {
    throw new Error(`Audit advisory ${advisory.source ?? "unknown"} has no exact GHSA URL`);
  }
  return match[1].toUpperCase();
}

function collectLeaves(vulnerabilities, packageName, stack = []) {
  if (stack.includes(packageName)) {
    throw new Error(`Audit dependency cycle: ${[...stack, packageName].join(" -> ")}`);
  }
  const vulnerability = vulnerabilities[packageName];
  if (!vulnerability) {
    throw new Error(`Audit aggregate references missing vulnerability ${packageName}`);
  }
  if (!Array.isArray(vulnerability.via) || vulnerability.via.length === 0) {
    throw new Error(`Audit vulnerability ${packageName} has no reachable leaf advisory`);
  }
  const leaves = [];
  for (const via of vulnerability.via || []) {
    if (typeof via === "string") {
      leaves.push(...collectLeaves(vulnerabilities, via, [...stack, packageName]));
    } else if (via && typeof via === "object") {
      if (!Object.hasOwn(severityRank, via.severity)) {
        throw new Error(`Audit leaf advisory for ${packageName} has an unknown severity`);
      }
      leaves.push({ advisory: via, path: [...stack, packageName] });
    } else {
      throw new Error(`Audit vulnerability ${packageName} contains an invalid via entry`);
    }
  }
  return leaves;
}

function validateLockfile(lockfile) {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  if (!manifest.dependencies || Object.keys(manifest.dependencies).length !== 0) {
    throw new Error("package.json dependencies must remain explicitly empty");
  }

  const installScripts = new Set();
  for (const [packagePath, entry] of Object.entries(lockfile.packages || {})) {
    if (!packagePath) {
      continue;
    }
    if (entry.link || entry.dev !== true) {
      throw new Error(`Lockfile package must be a non-link development dependency: ${packagePath}`);
    }
    if (!entry.resolved?.startsWith("https://registry.npmjs.org/") || !entry.integrity) {
      throw new Error(`Lockfile package lacks reviewed registry and integrity metadata: ${packagePath}`);
    }
    if (entry.hasInstallScript) {
      installScripts.add(packagePath);
    }
  }
  const unexpected = [...installScripts].filter((entry) => !allowedInstallScripts.has(entry));
  const missing = [...allowedInstallScripts].filter((entry) => !installScripts.has(entry));
  if (unexpected.length || missing.length) {
    throw new Error(`Install-script dependency set changed (unexpected=${unexpected.length}, missing=${missing.length})`);
  }
}

function validateException(exception, advisory, fixAvailable, now) {
  const id = advisoryId(advisory);
  if (exception.package !== advisory.name || exception.severity !== advisory.severity) {
    throw new Error(`Audit exception metadata drifted for ${id}`);
  }
  if (!exception.owner || !exception.rationale || !/^\d{4}-\d{2}-\d{2}$/.test(exception.reviewedOn || "")) {
    throw new Error(`Audit exception ${id} lacks owner, rationale, or review date`);
  }
  const reviewed = Date.parse(`${exception.reviewedOn}T00:00:00Z`);
  const expires = Date.parse(`${exception.expiresOn}T23:59:59Z`);
  if (!Number.isFinite(reviewed) || !Number.isFinite(expires) || expires <= now.getTime()) {
    throw new Error(`Audit exception ${id} is invalid or expired`);
  }
  if (expires - reviewed > 90 * 24 * 60 * 60 * 1000) {
    throw new Error(`Audit exception ${id} exceeds the 90-day review limit`);
  }
  if (fixAvailable) {
    if (fixAvailable === true || !exception.rejectedFix) {
      throw new Error(`Audit exception ${id} has a supported or unreviewed fix path`);
    }
    for (const field of ["name", "version", "isSemVerMajor"]) {
      if (exception.rejectedFix[field] !== fixAvailable[field]) {
        throw new Error(`Audit exception ${id} rejected-fix metadata drifted`);
      }
    }
    if (!fixAvailable.isSemVerMajor || !exception.rejectedFix.reason) {
      throw new Error(`Audit exception ${id} may not reject a non-breaking or unexplained fix`);
    }
  }
}

function applyAuditPolicy({ report, lockfile, exceptions, mode, now = new Date() }) {
  if (!report || report.auditReportVersion !== 2 || report.error || !report.vulnerabilities) {
    throw new Error("npm audit returned an error or unsupported report schema");
  }
  const vulnerabilities = report.vulnerabilities;
  for (const [packageName, vulnerability] of Object.entries(vulnerabilities)) {
    if (!Object.hasOwn(severityRank, vulnerability.severity)) {
      throw new Error(`Audit vulnerability ${packageName} has an unknown severity`);
    }
    if (!Array.isArray(vulnerability.nodes) || vulnerability.nodes.length === 0) {
      throw new Error(`Audit vulnerability ${packageName} has no affected lockfile nodes`);
    }
  }
  if (mode === "runtime") {
    const blocking = Object.values(vulnerabilities).filter(
      (entry) => severityRank[entry.severity] >= severityRank.moderate,
    );
    if (blocking.length) {
      throw new Error(`Runtime audit found ${blocking.length} moderate-or-higher vulnerable package nodes`);
    }
    return { packageNodes: Object.keys(vulnerabilities).length, leafAdvisories: 0, exceptionsUsed: 0 };
  }

  validateLockfile(lockfile);
  const exceptionMap = new Map();
  for (const exception of exceptions) {
    const id = (exception.advisoryId || "").toUpperCase();
    if (!/^GHSA-[A-Z0-9-]+$/.test(id) || exceptionMap.has(id)) {
      throw new Error(`Invalid or duplicate audit exception ${exception.advisoryId}`);
    }
    exceptionMap.set(id, exception);
  }

  const used = new Set();
  const leafMap = new Map();
  for (const packageName of Object.keys(vulnerabilities)) {
    const vulnerability = vulnerabilities[packageName];
    for (const node of vulnerability.nodes || []) {
      if (lockfile.packages?.[node]?.dev !== true) {
        throw new Error(`Audit finding is not confined to a lockfile development node: ${packageName}`);
      }
    }
    for (const leaf of collectLeaves(vulnerabilities, packageName)) {
      const id = advisoryId(leaf.advisory);
      const existing = leafMap.get(id) || { advisory: leaf.advisory, fixPaths: [] };
      for (const pathName of leaf.path) {
        const fix = vulnerabilities[pathName]?.fixAvailable;
        if (fix) {
          existing.fixPaths.push(fix);
        }
      }
      leafMap.set(id, existing);
    }
  }

  for (const [id, leaf] of leafMap) {
    if (leaf.advisory.severity === "critical") {
      throw new Error(`Critical development advisory is never exceptable: ${id}`);
    }
    const exception = exceptionMap.get(id);
    if (!exception) {
      throw new Error(`Unexcepted development advisory: ${id}`);
    }
    for (const fixAvailable of leaf.fixPaths.length ? leaf.fixPaths : [false]) {
      validateException(exception, leaf.advisory, fixAvailable, now);
    }
    used.add(id);
  }

  const unused = [...exceptionMap.keys()].filter((id) => !used.has(id));
  if (unused.length) {
    throw new Error(`Unused audit exceptions: ${unused.join(", ")}`);
  }
  return {
    packageNodes: Object.keys(vulnerabilities).length,
    leafAdvisories: leafMap.size,
    exceptionsUsed: used.size,
  };
}

function runAudit(mode) {
  const command = process.platform === "win32" ? "npm.cmd" : "npm";
  const arguments_ = ["audit", "--json"];
  if (mode === "runtime") {
    arguments_.splice(1, 0, "--omit=dev");
  }
  const result = spawnSync(command, arguments_, {
    cwd: root,
    encoding: "utf8",
    timeout: 120000,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.signal || ![0, 1].includes(result.status)) {
    throw new Error("npm audit failed, timed out, or exited abnormally");
  }
  let report;
  try {
    report = JSON.parse(result.stdout);
  } catch {
    throw new Error("npm audit did not return valid JSON");
  }
  const lockfile = JSON.parse(fs.readFileSync(path.join(root, "package-lock.json"), "utf8"));
  const policy = JSON.parse(fs.readFileSync(path.join(__dirname, "audit-exceptions.json"), "utf8"));
  if (policy.schemaVersion !== 1 || !Array.isArray(policy.exceptions)) {
    throw new Error("Audit exception policy has an unsupported schema");
  }
  return applyAuditPolicy({ report, lockfile, exceptions: policy.exceptions, mode });
}

function main() {
  const mode = process.argv[2];
  if (!['runtime', 'development'].includes(mode)) {
    throw new Error("Usage: verify-dependency-audit.js <runtime|development>");
  }
  const summary = runAudit(mode);
  console.log(
    `${mode} audit passed: ${summary.packageNodes} package nodes, `
    + `${summary.leafAdvisories} leaf advisories, ${summary.exceptionsUsed} reviewed exceptions.`,
  );
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
  advisoryId,
  applyAuditPolicy,
  collectLeaves,
  validateLockfile,
};

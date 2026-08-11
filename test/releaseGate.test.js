// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const os = require("os");
const path = require("path");
const { applyAuditPolicy } = require("../scripts/release/verify-dependency-audit");
const { resolveOutputPath } = require("../scripts/release/package-vsix");
const { assertVersionState } = require("../scripts/release/verify-version");
const {
  isApprovedSourcePath,
  parseCliArguments,
  scanSensitiveBytes,
  validateArchivePath,
} = require("../scripts/release/verify-vsix");

function auditLockfile(packageName = "affected") {
  const packages = {
    "": { name: "cloudsmith-vsc", version: "2.2.0" },
  };
  for (const packagePath of [
    "node_modules/@vscode/vsce-sign",
    "node_modules/keytar",
  ]) {
    packages[packagePath] = {
      version: "1.0.0",
      resolved: "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
      integrity: "sha512-example",
      dev: true,
      hasInstallScript: true,
    };
  }
  packages[`node_modules/${packageName}`] = {
    version: "1.0.0",
    resolved: "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
    integrity: "sha512-example",
    dev: true,
  };
  return { packages };
}

function advisoryReport() {
  return {
    auditReportVersion: 2,
    vulnerabilities: {
      affected: {
        name: "affected",
        severity: "high",
        nodes: ["node_modules/affected"],
        fixAvailable: false,
        via: [{
          source: 1,
          name: "affected",
          dependency: "affected",
          severity: "high",
          url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        }],
      },
    },
  };
}

function exception(overrides = {}) {
  return {
    advisoryId: "GHSA-AAAA-BBBB-CCCC",
    package: "affected",
    severity: "high",
    owner: "release-engineering",
    reviewedOn: "2026-08-01",
    expiresOn: "2026-08-31",
    rationale: "Development-only fixture.",
    ...overrides,
  };
}

suite("M9 release gate helpers", () => {
  test("archive paths reject traversal, local files, normalization drift, and case collisions", () => {
    const seen = new Set();
    assert.strictEqual(validateArchivePath("extension/extension.js", seen), "extension/extension.js");
    assert.throws(() => validateArchivePath("extension/../secret", new Set()), /traversing/);
    assert.throws(() => validateArchivePath("extension\\secret", new Set()), /backslash/);
    assert.throws(() => validateArchivePath("extension/internal_docs/audit.md", new Set()), /forbidden/);
    assert.throws(() => validateArchivePath("extension/.mcp.json", new Set()), /forbidden/);
    assert.throws(() => validateArchivePath("extension/e\u0301.js", new Set()), /normalization/);
    assert.throws(() => validateArchivePath("EXTENSION/EXTENSION.JS", seen), /duplicate/);
  });

  test("package allowlist accepts runtime/media and rejects tests and local configuration", () => {
    assert.strictEqual(isApprovedSourcePath("extension.js"), true);
    assert.strictEqual(isApprovedSourcePath("util/lockfileParsers/npm.js"), true);
    assert.strictEqual(isApprovedSourcePath("media/vscode_icons/file_type_npm.svg"), true);
    assert.strictEqual(isApprovedSourcePath("test/activation.test.js"), false);
    assert.strictEqual(isApprovedSourcePath("internal_docs/audit.md"), false);
    assert.strictEqual(isApprovedSourcePath(".mcp.json"), false);
  });

  test("sensitive-content failures identify only the rule and archive ordinal", () => {
    const token = `csa_${"A".repeat(24)}`;
    assert.throws(
      () => scanSensitiveBytes(Buffer.from(token), 7),
      (error) => error.message.includes("cloudsmith-token")
        && error.message.includes("entry 7")
        && !error.message.includes(token),
    );
  });

  test("version policy rejects manifest, lockfile, and changelog drift", () => {
    const state = {
      manifest: { name: "cloudsmith-vsc", publisher: "Cloudsmith", version: "2.2.0" },
      lockfile: {
        name: "cloudsmith-vsc",
        version: "2.2.0",
        packages: { "": { name: "cloudsmith-vsc", version: "2.2.0" } },
      },
      changelog: "## Unreleased\n\n## 2.2.0 - August 2026\n",
    };
    assert.deepStrictEqual(assertVersionState(state), {
      name: "cloudsmith-vsc",
      publisher: "Cloudsmith",
      version: "2.2.0",
    });
    assert.throws(
      () => assertVersionState({ ...state, changelog: "## 2.1.0\n" }),
      /2.2.0/,
    );
    assert.throws(
      () => assertVersionState({ ...state, manifest: { ...state.manifest, name: "../unsafe\nname" } }),
      /safe lowercase/,
    );
  });

  test("artifact output paths cannot escape their intended directory", () => {
    const outputRoot = path.join(os.tmpdir(), "m9-output");
    assert.strictEqual(resolveOutputPath(outputRoot, "extension.vsix"), path.join(outputRoot, "extension.vsix"));
    assert.throws(
      () => resolveOutputPath(outputRoot, "../escaped.vsix"),
      /escaped/,
    );
  });

  test("artifact verifier does not confuse option values with the VSIX path", () => {
    const sourceSha = "a".repeat(40);
    assert.deepStrictEqual(
      parseCliArguments([
        "--require-sidecars",
        "--expected-source-sha",
        sourceSha,
        "--require-publishable",
        "out/release/extension.vsix",
      ]),
      {
        expectedSourceSha: sourceSha,
        explicitPath: "out/release/extension.vsix",
        list: false,
        requirePublishable: true,
        requireSidecars: true,
      },
    );
  });

  test("development audit requires exact live exceptions and rejects expiry or unused policy", () => {
    const input = {
      report: advisoryReport(),
      lockfile: auditLockfile(),
      exceptions: [exception()],
      mode: "development",
      now: new Date("2026-08-11T00:00:00Z"),
    };
    assert.deepStrictEqual(applyAuditPolicy(input), {
      packageNodes: 1,
      leafAdvisories: 1,
      exceptionsUsed: 1,
    });
    assert.throws(
      () => applyAuditPolicy({ ...input, exceptions: [exception({ expiresOn: "2026-08-10" })] }),
      /expired/,
    );
    assert.throws(
      () => applyAuditPolicy({ ...input, exceptions: [...input.exceptions, exception({ advisoryId: "GHSA-DDDD-EEEE-FFFF" })] }),
      /Unused/,
    );
  });

  test("audit policy fails invalid reports and runtime moderate findings", () => {
    assert.throws(
      () => applyAuditPolicy({ report: { auditReportVersion: 2, error: {} }, mode: "runtime" }),
      /error or unsupported/,
    );
    const report = advisoryReport();
    assert.throws(
      () => applyAuditPolicy({ report, mode: "runtime" }),
      /moderate-or-higher/,
    );
    for (const mutation of [
      (entry) => { entry.via = []; },
      (entry) => { entry.nodes = []; },
      (entry) => { entry.severity = "unknown"; },
      (entry) => { entry.fixAvailable = { name: "affected" }; },
    ]) {
      const malformed = advisoryReport();
      mutation(malformed.vulnerabilities.affected);
      assert.throws(
        () => applyAuditPolicy({
          report: malformed,
          lockfile: auditLockfile(),
          exceptions: [exception()],
          mode: "development",
          now: new Date("2026-08-11T00:00:00Z"),
        }),
      );
    }

    const malformedLeaf = advisoryReport();
    malformedLeaf.vulnerabilities.affected.severity = "low";
    malformedLeaf.vulnerabilities.affected.via[0].severity = "catastrophic";
    assert.throws(
      () => applyAuditPolicy({
        report: malformedLeaf,
        lockfile: auditLockfile(),
        exceptions: [exception({ severity: "catastrophic" })],
        mode: "development",
        now: new Date("2026-08-11T00:00:00Z"),
      }),
      /leaf advisory.*unknown severity/,
    );
  });
});

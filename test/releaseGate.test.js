// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const { applyAuditPolicy } = require("../scripts/release/verify-dependency-audit");
const {
  packageBuildDirectoryIdentity,
  removePackageBuildDirectory,
  resolveOutputPath,
  runPackageCommand,
} = require("../scripts/release/package-vsix");
const {
  scanAcceptedEvidence,
} = require("../scripts/quality/release-exposure-scan");
const { assertVersionState } = require("../scripts/release/verify-version");
const {
  NON_AUTH_AMBIENT_CAPABILITY_NAMES,
} = require("../scripts/quality/non-auth-environment");
const { exactFileIdentity } = require("../scripts/quality/candidate-binding");
const {
  assertRelativeModuleClosure,
  isApprovedSourcePath,
  parseCliArguments,
  readProvenanceSidecar,
  resolveExpectedSourceSha,
  runPackageGitCommand,
  scanSensitiveBytes,
  selectArtifactPath,
  validateSidecars,
  validateArchivePath,
  verificationSourceSha,
  withStableArtifact,
} = require("../scripts/release/verify-vsix");

function sidecarFixture() {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(
    os.tmpdir(),
    "release-sidecar-transaction-",
  )));
  const filePath = path.join(directory, "synthetic.vsix");
  const buffer = Buffer.from("synthetic bounded VSIX bytes\n", "utf8");
  fs.writeFileSync(filePath, buffer);
  const sourceSha = runPackageGitCommand([
    "rev-parse", "--verify", "HEAD^{commit}",
  ]).trim();
  const sourceCommitEpoch = Number(runPackageGitCommand([
    "show", "-s", "--format=%ct", sourceSha,
  ]).trim());
  const sha256 = crypto.createHash("sha256").update(buffer).digest("hex");
  const verification = Object.freeze({
    archiveBytes: buffer.length,
    artifactIdentity: exactFileIdentity(fs.lstatSync(filePath, { bigint: true })),
    buffer,
    entryCount: 7,
    manifest: Object.freeze({
      name: "cloudsmith-vsc",
      publisher: "Cloudsmith",
      version: "2.3.0",
    }),
    sha256,
    totalUncompressedBytes: 4096,
  });
  const provenance = Object.freeze({
    archiveBytes: verification.archiveBytes,
    entryCount: verification.entryCount,
    filename: path.basename(filePath),
    name: verification.manifest.name,
    nodeVersion: process.version,
    npmVersion: "10.9.2",
    publishable: false,
    publisher: verification.manifest.publisher,
    schemaVersion: 1,
    sha256,
    sourceClean: true,
    sourceCommitEpoch,
    sourceSha,
    totalUncompressedBytes: verification.totalUncompressedBytes,
    version: verification.manifest.version,
  });
  const checksumPath = `${filePath}.sha256`;
  const provenancePath = `${filePath}.provenance.json`;
  fs.writeFileSync(checksumPath, `${sha256}  ${path.basename(filePath)}\n`);
  fs.writeFileSync(provenancePath, `${JSON.stringify(provenance)}\n`);
  return {
    checksumPath,
    directory,
    filePath,
    provenance,
    provenancePath,
    sourceSha,
    verification,
  };
}

function auditLockfile(packageName = "affected") {
  const packages = {
    "": { name: "cloudsmith-vsc", version: "2.3.0" },
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
  test("Quality explicitly verifies architecture before the build candidate can pass", () => {
    const workflow = fs.readFileSync(path.join(__dirname, "../.github/workflows/main.yml"), "utf8");
    assert.match(workflow, /- name: Verify architecture boundaries\s+run: npm run verify:architecture/);
    assert.match(
      workflow,
      /build-candidate:[\s\S]*needs: \[quality, mutation, extension-tests, package\]/
    );
  });

  test("CI certifies only a deterministic build candidate while release evidence is blocked", () => {
    const workflow = fs.readFileSync(path.join(__dirname, "../.github/workflows/main.yml"), "utf8");
    assert.match(workflow, /^name: Deterministic build candidate$/m);
    assert.match(workflow, /name: Deterministic build candidate[\s\S]*Require every deterministic candidate input to succeed/);
    assert.match(
      workflow,
      /Every deterministic build-candidate input succeeded; production release readiness remains blocked pending separately sourced UI and live qualification\./
    );
    assert.doesNotMatch(workflow, /^name: Production release gate$/m);
    assert.doesNotMatch(workflow, /Every required release input succeeded\./);
  });

  test("manual deep quality executes and binds the signed-out packaged UI lane", () => {
    const workflow = fs.readFileSync(
      path.join(__dirname, "../.github/workflows/deep-quality.yml"),
      "utf8"
    );
    const coreMutationJob = workflow.slice(
      workflow.indexOf("  core-mutation:"),
      workflow.indexOf("  signed-out-black-box-ui:")
    );
    const signedOutUiJob = workflow.slice(
      workflow.indexOf("  signed-out-black-box-ui:"),
      workflow.indexOf("  authenticated-production-ui:")
    );
    assert.match(coreMutationJob, /fetch-depth:\s+0/);
    assert.match(signedOutUiJob, /- name: Checkout exact source[\s\S]*persist-credentials:\s+false/);
    assert.match(signedOutUiJob, /- name: Set up exact Node\.js[\s\S]*node-version:\s+\$\{\{ env\.NODE_VERSION \}\}/);
    assert.match(signedOutUiJob, /run: npm run test:ui:smoke/);
    assert.doesNotMatch(signedOutUiJob, /xvfb-run/);
    assert.match(signedOutUiJob, /id: ui_evidence_handoff[\s\S]*if: \$\{\{ always\(\) \}\}[\s\S]*node scripts\/quality\/verify-ui-evidence\.js/);
    assert.match(signedOutUiJob, /steps\.ui_evidence_handoff\.outcome == 'success'[\s\S]*steps\.ui_evidence_secret_scan\.outcome == 'success'/);
    assert.doesNotMatch(signedOutUiJob, /secrets\.|CLOUDSMITH_QUALIFICATION_API_KEY/);
  });

  test("CI retains the minimum VS Code contract and current stable 1.134.0 matrix", () => {
    const workflow = fs.readFileSync(path.join(__dirname, "../.github/workflows/main.yml"), "utf8");
    assert.match(workflow, /- os: [^\n]+\n\s+vscode: 1\.99\.0\n\s+label: core/);
    assert.match(workflow, /- os: [^\n]+\n\s+vscode: 1\.99\.0\n\s+label: smoke/);
    for (const os of ["ubuntu-24.04", "windows-2025", "macos-15"]) {
      assert.match(workflow, new RegExp(`os: ${os}[\\s\\S]*?vscode: 1\\.134\\.0`));
    }
    assert.doesNotMatch(workflow, /vscode: 1\.132\.0/);
  });

  test("local checks and package inputs include every M11 runtime root", () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "../package.json"), "utf8"));
    assert.ok(manifest.files.includes("commands/**/*.js"));
    assert.ok(manifest.files.includes("domain/**/*.js"));
    assert.match(manifest.scripts.check, /npm run verify:architecture/);
    assert.match(manifest.scripts["package:verify"], /--require-sidecars --current-source$/);
    assert.match(manifest.scripts["package:list"], /--require-sidecars --current-source --list$/);
    assert.strictEqual(manifest.scripts["vscode:prepublish"], "npm run check");

    const syntax = fs.readFileSync(path.join(__dirname, "../scripts/check-syntax.js"), "utf8");
    const build = fs.readFileSync(path.join(__dirname, "../scripts/verify-build.js"), "utf8");
    for (const runtimeRoot of ["commands", "domain"]) {
      assert.ok(syntax.includes(`\"${runtimeRoot}\"`));
      assert.ok(build.includes(`\"${runtimeRoot}\"`));
    }
  });

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
    assert.strictEqual(isApprovedSourcePath("commands/packages.js"), true);
    assert.strictEqual(isApprovedSourcePath("domain/package.js"), true);
    assert.strictEqual(isApprovedSourcePath("util/lockfileParsers/npm.js"), true);
    assert.strictEqual(isApprovedSourcePath("media/vscode_icons/file_type_npm.svg"), true);
    assert.strictEqual(isApprovedSourcePath("test/activation.test.js"), false);
    assert.strictEqual(isApprovedSourcePath("internal_docs/audit.md"), false);
    assert.strictEqual(isApprovedSourcePath(".mcp.json"), false);
  });

  test("relative runtime closure follows command and domain modules", () => {
    const entries = new Map([
      ["extension/commands/packages.js", Buffer.from("require('../domain/package');")],
      ["extension/domain/package.js", Buffer.from("module.exports = {};")],
    ]);
    const expected = new Map([
      ["extension/commands/packages.js", {}],
      ["extension/domain/package.js", {}],
    ]);
    assert.doesNotThrow(() => assertRelativeModuleClosure(entries, expected));
    expected.delete("extension/domain/package.js");
    assert.throws(
      () => assertRelativeModuleClosure(entries, expected),
      /omits relative runtime module/,
    );
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

  test("packaged-content scanning rejects the declared credential-family matrix", () => {
    const fixtures = [
      ["url-userinfo", `https://fixture-user:${"p".repeat(24)}@packages.example.invalid/path`],
      ["authorization-header", `Authorization: Basic ${Buffer.from("fixture-user:fixture-password").toString("base64")}`],
      ["authorization-header", `authorization: bearer ${"b".repeat(32)}`],
      ["npm-token", `npm_${"n".repeat(36)}`],
      ["gitlab-token", `glpat-${"g".repeat(24)}`],
      ["azure-devops-token", `${"A".repeat(75)}AZDO${"B".repeat(5)}`],
      ["gcp-api-key", `AIza${"G".repeat(35)}`],
      ["ssh-private-key", "PuTTY-User-Key-File-3: ssh-ed25519"],
    ];

    fixtures.forEach(([rule, value], index) => {
      assert.throws(
        () => scanSensitiveBytes(Buffer.from(value), index + 11),
        error => error.message.includes(`rule ${rule}`)
          && error.message.includes(`entry ${index + 11}`)
          && !error.message.includes(value),
        rule
      );
    });
  });

  test("version policy rejects manifest, lockfile, and changelog drift", () => {
    const state = {
      manifest: { name: "cloudsmith-vsc", publisher: "Cloudsmith", version: "2.3.0" },
      lockfile: {
        name: "cloudsmith-vsc",
        version: "2.3.0",
        packages: { "": { name: "cloudsmith-vsc", version: "2.3.0" } },
      },
      changelog: "## Unreleased\n\n## 2.3.0 - August 2026\n\n## 2.2.0 - August 2026\n",
    };
    assert.deepStrictEqual(assertVersionState(state), {
      name: "cloudsmith-vsc",
      publisher: "Cloudsmith",
      version: "2.3.0",
    });
    assert.throws(
      () => assertVersionState({ ...state, changelog: "## 2.1.0\n" }),
      /2.3.0/,
    );
    assert.throws(
      () => assertVersionState({ ...state, manifest: { ...state.manifest, name: "../unsafe\nname" } }),
      /safe lowercase/,
    );
  });

  test("changelog preserves released 2.2.0 history below 2.3.0", () => {
    const changelog = fs.readFileSync(path.join(__dirname, "../CHANGELOG.md"), "utf8");
    const currentStart = changelog.indexOf("## 2.3.0 - August 2026");
    const releasedStart = changelog.indexOf("## 2.2.0 - August 2026");
    const olderStart = changelog.indexOf("## 2.1.1 - April 2026");
    const releasedSection = changelog.slice(releasedStart, olderStart).replace(/\r\n/g, "\n");
    const releasedSectionHash = crypto.createHash("sha256").update(releasedSection).digest("hex");

    assert.ok(currentStart >= 0 && releasedStart > currentStart);
    assert.ok(olderStart > releasedStart);
    assert.strictEqual(
      releasedSectionHash,
      "bef2948304e549036a73149c6456b7a59394834ee3aaed29b39ea3b9efa574fd",
      "2.2.0 changelog history must match the released source"
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

  test("accepted evidence scanning consumes only descriptor-proven stdin bytes across a swap", () => {
    const evidenceRoot = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "release-evidence-stdin-swap-",
    )));
    const relativePath = "internal_docs/quality/review.md";
    const target = path.join(evidenceRoot, ...relativePath.split("/"));
    const displaced = `${target}.descriptor-proven`;
    const originalBytes = Buffer.from("authorized synthetic release evidence\n");
    const replacementBytes = Buffer.from("unaccepted synthetic replacement bytes\n");
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, originalBytes);
    let scannerInput;
    let scannerInputReference;
    try {
      const component = scanAcceptedEvidence(evidenceRoot, [relativePath], {
        scanWithGitleaks(kind, logicalPath, options) {
          assert.strictEqual(kind, "stdin");
          assert.strictEqual(logicalPath, relativePath);
          assert.strictEqual(options.logicalPath, relativePath);
          assert.strictEqual(options.scanRoot, evidenceRoot);
          fs.renameSync(target, displaced);
          try {
            fs.writeFileSync(target, replacementBytes);
            scannerInputReference = options.input;
            scannerInput = Buffer.from(options.input);
          } finally {
            fs.rmSync(target);
            fs.renameSync(displaced, target);
          }
          return [];
        },
      });

      assert.deepStrictEqual(scannerInput, originalBytes);
      assert.deepStrictEqual(component.snapshot[relativePath], originalBytes);
      assert.strictEqual(scannerInputReference.every(byte => byte === 0), true);
      assert.deepStrictEqual(fs.readFileSync(target), originalBytes);
      assert.deepStrictEqual(component.findings, []);
    } finally {
      fs.rmSync(evidenceRoot, { recursive: true, force: true });
    }
  });

  test("release package cleanup fails closed on final owned-root substitution", () => {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "release-package-cleanup-final-swap-",
    )));
    const ownedRoot = path.join(scratch, "owned-build");
    const victim = path.join(scratch, "preserve-victim");
    const displacedOwnedRoot = path.join(scratch, "displaced-owned-build");
    fs.mkdirSync(ownedRoot);
    fs.writeFileSync(path.join(ownedRoot, "temporary.vsix"), "synthetic build bytes\n");
    fs.mkdirSync(victim);
    fs.writeFileSync(path.join(victim, "preserve.txt"), "synthetic victim survives\n");
    const identity = packageBuildDirectoryIdentity(ownedRoot);
    const originalRmdir = fs.rmdirSync;
    let substituted = false;
    try {
      fs.rmdirSync = function substituteAtFinalRemoval(target, options) {
        if (!substituted && target === ownedRoot) {
          substituted = true;
          fs.renameSync(ownedRoot, displacedOwnedRoot);
          fs.renameSync(victim, ownedRoot);
        }
        return originalRmdir.call(fs, target, options);
      };
      assert.throws(
        () => removePackageBuildDirectory(ownedRoot, identity),
        /temporary cleanup refused an unsafe or changed tree/u,
      );
    } finally {
      fs.rmdirSync = originalRmdir;
    }
    try {
      assert.strictEqual(substituted, true);
      assert.strictEqual(
        fs.readFileSync(path.join(ownedRoot, "preserve.txt"), "utf8"),
        "synthetic victim survives\n",
      );
      assert.strictEqual(fs.existsSync(displacedOwnedRoot), true);
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });

  test("release exposure and packaging production cleanup forbid recursive deletion", () => {
    for (const relativePath of [
      "scripts/quality/release-exposure-scan.js",
      "scripts/release/package-vsix.js",
    ]) {
      const source = fs.readFileSync(path.join(__dirname, "..", relativePath), "utf8");
      assert.doesNotMatch(
        source,
        /\bfs\.rm(?:Sync)?\s*\([^;]*?\brecursive\s*:\s*true\b/gsu,
        `${relativePath} must use exact entry-bounded cleanup`,
      );
    }
  });

  test("package and VSCE subprocesses receive only the non-auth environment allowlist", () => {
    const syntheticEnvironment = {
      PATH: "/fixture/bin",
      LANG: "en_US.UTF-8",
      CLOUDSMITH_API_KEY: "synthetic-qh141-package-sentinel",
      ARBITRARY_REFRESH_TOKEN: "synthetic-qh141-refresh-sentinel",
      NODE_OPTIONS: "--require=synthetic-untrusted-hook",
      DISPLAY: ":synthetic-host-display",
      WAYLAND_DISPLAY: "synthetic-host-wayland",
      XAUTHORITY: "/synthetic/host-xauthority",
      XDG_RUNTIME_DIR: "/synthetic/host-runtime",
      DBUS_SESSION_BUS_ADDRESS: "unix:path=/synthetic/host-session-bus",
      SSH_AUTH_SOCK: "/synthetic/host-agent.sock",
      SSH_AGENT_PID: "12345",
      GPG_AGENT_INFO: "/synthetic/host-gpg-agent",
      KRB5CCNAME: "/synthetic/host-credential-cache",
      SECURITYSESSIONID: "synthetic-host-security-session",
    };
    let childEnvironment;
    const output = runPackageCommand("fixture-vsce", ["package"], {
      environment: syntheticEnvironment,
      environmentOverrides: { SOURCE_DATE_EPOCH: "1234567890", TZ: "UTC" },
      spawnSync(_command, _arguments, options) {
        childEnvironment = options.env;
        const unsafe = [
          "CLOUDSMITH_API_KEY",
          "ARBITRARY_REFRESH_TOKEN",
          "NODE_OPTIONS",
          ...NON_AUTH_AMBIENT_CAPABILITY_NAMES,
        ].some(name => Object.prototype.hasOwnProperty.call(options.env, name));
        return {
          status: 0,
          signal: null,
          error: null,
          stdout: unsafe ? "unsafe-package-output" : "safe-package-output",
          stderr: "",
        };
      },
    });

    assert.strictEqual(output, "safe-package-output");
    const packageBoundaryRoot = path.dirname(childEnvironment.HOME);
    assert.strictEqual(childEnvironment.PATH, "/fixture/bin");
    assert.strictEqual(childEnvironment.LANG, "en_US.UTF-8");
    assert.strictEqual(childEnvironment.TZ, "UTC");
    assert.strictEqual(childEnvironment.SOURCE_DATE_EPOCH, "1234567890");
    assert.strictEqual(childEnvironment.HOME, childEnvironment.USERPROFILE);
    assert.strictEqual(childEnvironment.GIT_CONFIG_NOSYSTEM, "1");
    assert.strictEqual(childEnvironment.GIT_CONFIG_COUNT, "0");
    for (const name of NON_AUTH_AMBIENT_CAPABILITY_NAMES) {
      assert.strictEqual(Object.prototype.hasOwnProperty.call(childEnvironment, name), false);
    }
    assert.strictEqual(childEnvironment.NPM_CONFIG_USERCONFIG.startsWith(
      `${packageBoundaryRoot}${path.sep}`
    ), true);
    assert.strictEqual(fs.existsSync(packageBoundaryRoot), false);
    assert.strictEqual(
      crypto.createHash("sha256").update(output).digest("hex"),
      crypto.createHash("sha256").update("safe-package-output").digest("hex")
    );
    for (const value of [
      syntheticEnvironment.CLOUDSMITH_API_KEY,
      syntheticEnvironment.ARBITRARY_REFRESH_TOKEN,
    ]) {
      assert.strictEqual(JSON.stringify(childEnvironment).includes(value), false);
      assert.strictEqual(output.includes(value), false);
    }

    let verifierEnvironment;
    const verifierOutput = runPackageGitCommand(["status"], "utf8", {
      environment: syntheticEnvironment,
      spawnSync(_command, _arguments, options) {
        verifierEnvironment = options.env;
        const unsafe = [
          "CLOUDSMITH_API_KEY",
          ...NON_AUTH_AMBIENT_CAPABILITY_NAMES,
        ].some(name => Object.prototype.hasOwnProperty.call(options.env, name));
        return {
          status: 0,
          signal: null,
          error: null,
          stdout: unsafe ? "unsafe-verifier-output" : "safe-verifier-output",
          stderr: "",
        };
      },
    });
    assert.strictEqual(verifierOutput, "safe-verifier-output");
    const verifierBoundaryRoot = path.dirname(verifierEnvironment.HOME);
    assert.strictEqual(verifierEnvironment.PATH, "/fixture/bin");
    assert.strictEqual(verifierEnvironment.LANG, "en_US.UTF-8");
    assert.strictEqual(verifierEnvironment.HOME, verifierEnvironment.USERPROFILE);
    assert.strictEqual(verifierEnvironment.GIT_CONFIG_NOSYSTEM, "1");
    assert.strictEqual(verifierEnvironment.GIT_CONFIG_COUNT, "0");
    for (const name of NON_AUTH_AMBIENT_CAPABILITY_NAMES) {
      assert.strictEqual(Object.prototype.hasOwnProperty.call(verifierEnvironment, name), false);
    }
    assert.strictEqual(fs.existsSync(verifierBoundaryRoot), false);
    assert.strictEqual(
      crypto.createHash("sha256").update(verifierOutput).digest("hex"),
      crypto.createHash("sha256").update("safe-verifier-output").digest("hex")
    );

    let failedBoundaryRoot;
    assert.throws(() => runPackageCommand("fixture-vsce", ["package"], {
      environment: syntheticEnvironment,
      spawnSync(_command, _arguments, options) {
        failedBoundaryRoot = path.dirname(options.env.HOME);
        return {
          status: 1,
          signal: null,
          error: null,
          stdout: "",
          stderr: "",
        };
      },
    }), /failed while building the release artifact/u);
    assert.strictEqual(fs.existsSync(failedBoundaryRoot), false);
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
        currentSource: false,
        expectedSourceSha: sourceSha,
        explicitPath: "out/release/extension.vsix",
        list: false,
        requirePublishable: true,
        requireSidecars: true,
      },
    );
    assert.throws(
      () => parseCliArguments(["--require-sidecars"]),
      /explicit artifact path or source binding/,
    );
    const combinedBinding = parseCliArguments([
      "--require-sidecars",
      "--current-source",
      "--expected-source-sha",
      sourceSha,
      "out/release/extension.vsix",
    ]);
    assert.strictEqual(resolveExpectedSourceSha(combinedBinding, sourceSha), sourceSha);
    assert.throws(
      () => resolveExpectedSourceSha(
        combinedBinding,
        "b".repeat(40),
      ),
      /does not match the current checkout/,
    );
    assert.throws(
      () => parseCliArguments([
        "--current-source",
        "out/development/extension.vsix",
      ]),
      /requires --require-sidecars/,
    );
  });

  test("release sidecars are validated inside exact descriptor transactions", () => {
    const fixture = sidecarFixture();
    try {
      const provenanceProof = readProvenanceSidecar(fixture.filePath);
      assert.deepStrictEqual(provenanceProof.provenance, fixture.provenance);
      const sidecars = validateSidecars(fixture.filePath, fixture.verification, {
        expectedProvenanceIdentity: provenanceProof.identity,
        expectedSourceSha: fixture.sourceSha,
      });
      assert.strictEqual(sidecars.checksumPath, fixture.checksumPath);
      assert.strictEqual(sidecars.provenancePath, fixture.provenancePath);
      assert.deepStrictEqual(sidecars.provenance, fixture.provenance);
    } finally {
      fs.rmSync(fixture.directory, { recursive: true, force: true });
    }
  });

  test("VSIX pathname stays rebound to its descriptor through async verification", async () => {
    const fixture = sidecarFixture();
    const displaced = `${fixture.filePath}.descriptor`;
    let consumed = false;
    try {
      await assert.rejects(
        withStableArtifact(fixture.filePath, {}, async bytes => {
          consumed = true;
          fs.renameSync(fixture.filePath, displaced);
          fs.writeFileSync(fixture.filePath, bytes);
          await Promise.resolve();
          return Buffer.from(bytes);
        }),
        /exact bounded single-link file/u,
      );
      assert.strictEqual(consumed, true);
    } finally {
      fs.rmSync(fixture.directory, { recursive: true, force: true });
    }
  });

  test("VSIX descriptor reads never request bytes beyond the opened size", async () => {
    const fixture = sidecarFixture();
    const requests = [];
    const fileSystem = Object.create(fs);
    fileSystem.readSync = (descriptor, buffer, offset, length, position) => {
      requests.push({ length, position });
      assert.ok(position >= 0);
      assert.ok(length > 0);
      assert.ok(position + length <= fixture.verification.archiveBytes);
      return fs.readSync(descriptor, buffer, offset, length, position);
    };
    try {
      const consumed = await withStableArtifact(
        fixture.filePath,
        { fileSystem },
        async bytes => Buffer.from(bytes),
      );
      assert.deepStrictEqual(consumed, fixture.verification.buffer);
      assert.ok(requests.length >= 1);
      assert.strictEqual(
        requests.at(-1).position + requests.at(-1).length,
        fixture.verification.archiveBytes,
      );
    } finally {
      fs.rmSync(fixture.directory, { recursive: true, force: true });
    }
  });

  test("VSIX descriptor postchecks reject growth after the exact-size read", async () => {
    const fixture = sidecarFixture();
    let grew = false;
    const fileSystem = Object.create(fs);
    fileSystem.readSync = (...arguments_) => {
      const bytesRead = fs.readSync(...arguments_);
      if (!grew) {
        fs.appendFileSync(fixture.filePath, "synthetic growth\n");
        grew = true;
      }
      return bytesRead;
    };
    try {
      await assert.rejects(
        withStableArtifact(fixture.filePath, { fileSystem }, async bytes => Buffer.from(bytes)),
        /exact bounded single-link file/u,
      );
      assert.strictEqual(grew, true);
    } finally {
      fs.rmSync(fixture.directory, { recursive: true, force: true });
    }
  });

  test("sidecar validation rejects artifact and sidecar swaps between lstat and open", () => {
    for (const selected of ["filePath", "checksumPath", "provenancePath"]) {
      const fixture = sidecarFixture();
      const target = fixture[selected];
      const displaced = `${target}.descriptor`;
      const originalBytes = fs.readFileSync(target);
      let swapped = false;
      const fileSystem = Object.create(fs);
      fileSystem.openSync = (openedPath, flags) => {
        if (!swapped && openedPath === target) {
          fs.renameSync(target, displaced);
          fs.writeFileSync(target, originalBytes);
          swapped = true;
        }
        return fs.openSync(openedPath, flags);
      };
      try {
        assert.throws(
          () => validateSidecars(fixture.filePath, fixture.verification, {
            expectedSourceSha: fixture.sourceSha,
            fileSystem,
          }),
          /exact bounded single-link file/u,
          `${selected} replacement must fail closed`,
        );
        assert.strictEqual(swapped, true);
      } finally {
        fs.rmSync(fixture.directory, { recursive: true, force: true });
      }
    }
  });

  test("sidecar validation retains prior checksum and provenance pathname identities", () => {
    const fixture = sidecarFixture();
    try {
      const first = validateSidecars(fixture.filePath, fixture.verification, {
        expectedSourceSha: fixture.sourceSha,
      });
      for (const [target, expectedOption, expectedIdentity] of [
        [fixture.checksumPath, "expectedChecksumIdentity", first.checksumIdentity],
        [fixture.provenancePath, "expectedProvenanceIdentity", first.provenanceIdentity],
      ]) {
        const displaced = `${target}.prior`;
        const bytes = fs.readFileSync(target);
        fs.renameSync(target, displaced);
        fs.writeFileSync(target, bytes);
        assert.throws(
          () => validateSidecars(fixture.filePath, fixture.verification, {
            [expectedOption]: expectedIdentity,
            expectedSourceSha: fixture.sourceSha,
          }),
          /exact bounded single-link file/u,
        );
        fs.unlinkSync(target);
        fs.renameSync(displaced, target);
      }
    } finally {
      fs.rmSync(fixture.directory, { recursive: true, force: true });
    }
  });

  test("checksum and provenance sidecars reject symbolic and multiply-linked files", () => {
    for (const selected of ["checksumPath", "provenancePath"]) {
      for (const linkKind of ["symbolic", "hard"]) {
        const fixture = sidecarFixture();
        const target = fixture[selected];
        const source = `${target}.source`;
        fs.renameSync(target, source);
        if (linkKind === "symbolic") fs.symlinkSync(source, target);
        else fs.linkSync(source, target);
        try {
          assert.throws(
            () => validateSidecars(fixture.filePath, fixture.verification, {
              expectedSourceSha: fixture.sourceSha,
            }),
            /exact bounded single-link file/u,
            `${selected} ${linkKind} link must fail closed`,
          );
        } finally {
          fs.rmSync(fixture.directory, { recursive: true, force: true });
        }
      }
    }
  });

  test("provenance FIFO substitution is opened nonblocking and rejected", function fifoTest() {
    if (process.platform === "win32") this.skip();
    const fixture = sidecarFixture();
    const displaced = `${fixture.provenancePath}.regular`;
    let substituted = false;
    const fileSystem = Object.create(fs);
    fileSystem.openSync = (openedPath, flags) => {
      if (!substituted && openedPath === fixture.provenancePath) {
        fs.renameSync(fixture.provenancePath, displaced);
        const created = spawnSync("mkfifo", [fixture.provenancePath]);
        assert.strictEqual(created.status, 0);
        substituted = true;
      }
      return fs.openSync(openedPath, flags);
    };
    try {
      assert.throws(
        () => validateSidecars(fixture.filePath, fixture.verification, {
          expectedSourceSha: fixture.sourceSha,
          fileSystem,
        }),
        /exact bounded single-link file/u,
      );
      assert.strictEqual(substituted, true);
    } finally {
      fs.rmSync(fixture.directory, { recursive: true, force: true });
    }
  });

  test("provenance descriptor detects growth during its bounded read", () => {
    const fixture = sidecarFixture();
    let descriptor;
    let grew = false;
    const fileSystem = Object.create(fs);
    fileSystem.openSync = (openedPath, flags) => {
      const opened = fs.openSync(openedPath, flags);
      if (openedPath === fixture.provenancePath) descriptor = opened;
      return opened;
    };
    fileSystem.readSync = (...arguments_) => {
      const bytesRead = fs.readSync(...arguments_);
      if (!grew && arguments_[0] === descriptor) {
        fs.appendFileSync(fixture.provenancePath, " ");
        grew = true;
      }
      return bytesRead;
    };
    try {
      assert.throws(
        () => validateSidecars(fixture.filePath, fixture.verification, {
          expectedSourceSha: fixture.sourceSha,
          fileSystem,
        }),
        /exact bounded single-link file/u,
      );
      assert.strictEqual(grew, true);
    } finally {
      fs.rmSync(fixture.directory, { recursive: true, force: true });
    }
  });

  test("provenance sidecar rejects oversized otherwise-valid JSON", () => {
    const fixture = sidecarFixture();
    fs.appendFileSync(fixture.provenancePath, " ".repeat(32 * 1024));
    try {
      assert.throws(
        () => validateSidecars(fixture.filePath, fixture.verification, {
          expectedSourceSha: fixture.sourceSha,
        }),
        /exact bounded single-link file/u,
      );
    } finally {
      fs.rmSync(fixture.directory, { recursive: true, force: true });
    }
  });

  test("default artifact selection is current-source-bound and unambiguous", () => {
    const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "vsix-selection-")));
    const currentSha = "a".repeat(40);
    const staleSha = "b".repeat(40);
    const releasePath = path.join(directory, "release.vsix");
    const developmentPath = path.join(directory, "development.vsix");
    const writeCandidate = (filePath, sourceSha) => {
      fs.writeFileSync(filePath, "fixture");
      fs.writeFileSync(`${filePath}.provenance.json`, JSON.stringify({ sourceSha }));
    };
    try {
      writeCandidate(releasePath, staleSha);
      assert.throws(
        () => selectArtifactPath({ releasePath, developmentPath, expectedSourceSha: currentSha }),
        /valid provenance for the expected source SHA/,
      );

      writeCandidate(developmentPath, currentSha);
      assert.strictEqual(
        selectArtifactPath({ releasePath, developmentPath, expectedSourceSha: currentSha }),
        developmentPath,
      );

      writeCandidate(releasePath, currentSha);
      assert.throws(
        () => selectArtifactPath({ releasePath, developmentPath, expectedSourceSha: currentSha }),
        /ambiguous/,
      );
    } finally {
      fs.rmSync(directory, { force: true, recursive: true });
    }
  });

  test("dirty current-source verification cannot reuse a stale clean same-HEAD artifact", () => {
    const currentSha = "a".repeat(40);
    const cleanArtifactProvenance = {
      sourceClean: true,
      sourceSha: currentSha,
    };

    assert.strictEqual(
      verificationSourceSha(cleanArtifactProvenance, {
        currentSource: true,
        currentSourceDirty: false,
      }),
      currentSha,
      "clean CI should verify against the exact commit tree",
    );
    assert.strictEqual(
      verificationSourceSha(cleanArtifactProvenance, {
        currentSource: true,
        currentSourceDirty: true,
      }),
      null,
      "dirty current-source verification must compare archive bytes with the worktree",
    );
    assert.throws(
      () => verificationSourceSha(cleanArtifactProvenance, {
        currentSource: false,
        currentSourceDirty: true,
      }),
      /requires --current-source/,
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
      () => applyAuditPolicy({
        ...input,
        exceptions: [exception({
          reviewedOn: "2026-08-12",
          expiresOn: "2026-09-10",
        })],
      }),
      /future review date/,
    );
    assert.throws(
      () => applyAuditPolicy({ ...input, exceptions: [...input.exceptions, exception({ advisoryId: "GHSA-DDDD-EEEE-FFFF" })] }),
      /Unused/,
    );
  });

  test("serialize-javascript exceptions describe the reviewed parallel-worker path", () => {
    const policy = JSON.parse(fs.readFileSync(
      path.join(__dirname, "../scripts/release/audit-exceptions.json"),
      "utf8",
    ));
    const serializerExceptions = policy.exceptions.filter(entry => (
      entry.package === "serialize-javascript"
    ));

    assert.ok(serializerExceptions.length > 0);
    for (const exception_ of serializerExceptions) {
      assert.match(exception_.rationale, /Mocha parallel-worker option serialization/);
      assert.doesNotMatch(exception_.rationale, /reporter serialization/);
    }
  });

  test("development audit records every distinct breaking fix path for one advisory", () => {
    const report = advisoryReport();
    report.vulnerabilities.wrapper = {
      name: "wrapper",
      severity: "high",
      nodes: ["node_modules/wrapper"],
      fixAvailable: {
        name: "wrapper",
        version: "0.9.0",
        isSemVerMajor: true,
      },
      via: ["affected"],
    };
    report.vulnerabilities.affected.fixAvailable = {
      name: "affected",
      version: "0.9.0",
      isSemVerMajor: true,
    };
    const lockfile = auditLockfile();
    lockfile.packages["node_modules/wrapper"] = {
      version: "1.0.0",
      resolved: "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
      integrity: "sha512-example",
      dev: true,
    };
    const rejectedFixes = [
      {
        name: "affected",
        version: "0.9.0",
        isSemVerMajor: true,
        reason: "The proposed downgrade is outside the supported toolchain.",
      },
      {
        name: "wrapper",
        version: "0.9.0",
        isSemVerMajor: true,
        reason: "The proposed wrapper downgrade is outside the supported toolchain.",
      },
    ];
    const input = {
      report,
      lockfile,
      exceptions: [exception({ rejectedFixes })],
      mode: "development",
      now: new Date("2026-08-11T00:00:00Z"),
    };

    assert.deepStrictEqual(applyAuditPolicy(input), {
      packageNodes: 2,
      leafAdvisories: 1,
      exceptionsUsed: 1,
    });
    assert.throws(
      () => applyAuditPolicy({
        ...input,
        exceptions: [exception({ rejectedFixes: rejectedFixes.slice(0, 1) })],
      }),
      /rejected-fix metadata drifted/,
    );
    assert.throws(
      () => applyAuditPolicy({
        ...input,
        exceptions: [exception({
          rejectedFixes: [...rejectedFixes, {
            name: "stale",
            version: "0.1.0",
            isSemVerMajor: true,
            reason: "Stale fixture.",
          }],
        })],
      }),
      /unused rejected-fix metadata/,
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

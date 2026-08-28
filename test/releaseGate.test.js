// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const { withExpectedCleanupTaint } = require("./helpers/expectedCleanupTaint");
const { applyAuditPolicy } = require("../scripts/release/verify-dependency-audit");
const {
  assertCanonicalNpmRuntime,
  assertCanonicalNodeRuntime,
  canonicalToolchainEnvironment,
  npmInstallationFingerprint,
  withCanonicalNpmLauncher,
} = require("../scripts/quality/canonical-node-runtime");
const {
  authenticatePackageNpmRuntime,
  canonicalVscePackageInvocation,
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
  cleanupNonAuthQualityEnvironment,
  createNonAuthQualityEnvironment,
  expectedExactCleanupTreeEntry,
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
  const npmIntegrityPins = JSON.parse(fs.readFileSync(path.join(__dirname, "../.npm-integrity"), "utf8"));
  const provenance = Object.freeze({
    archiveBytes: verification.archiveBytes,
    entryCount: verification.entryCount,
    filename: path.basename(filePath),
    name: verification.manifest.name,
    nodeVersion: "v22.23.2",
    npmVersion: "10.9.8",
    npmInstallationSha256: npmIntegrityPins[process.platform === "win32" ? "win32" : "posix"],
    platform: process.platform,
    publishable: false,
    publisher: verification.manifest.publisher,
    schemaVersion: 3,
    sha256,
    sourceClean: false,
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

function withNodeVersionPin(contents, callback) {
  const fixtureRoot = fs.realpathSync(fs.mkdtempSync(path.join(
    os.tmpdir(),
    "cloudsmith-node-version-pin-",
  )));
  try {
    fs.writeFileSync(path.join(fixtureRoot, ".node-version"), contents);
    return callback(fixtureRoot);
  } finally {
    fs.rmSync(fixtureRoot, { recursive: true, force: true });
  }
}

function createCanonicalNpmFixture(fixtureRoot, options = {}) {
  const version = options.version || "10.9.8";
  const platform = options.platform || "linux";
  const nodeExecutable = options.nodeExecutable
    || path.join(fixtureRoot, "runtime", "bin", "node");
  fs.mkdirSync(path.dirname(nodeExecutable), { recursive: true });
  if (!fs.existsSync(nodeExecutable)) {
    fs.writeFileSync(nodeExecutable, "synthetic exact node runtime\n", { mode: 0o700 });
  }
  const packageRoot = platform === "win32"
    ? path.join(path.dirname(nodeExecutable), "node_modules", "npm")
    : path.join(path.dirname(path.dirname(nodeExecutable)), "lib", "node_modules", "npm");
  const cliPath = path.join(packageRoot, "bin", "npm-cli.js");
  const packageJsonPath = path.join(packageRoot, "package.json");
  fs.mkdirSync(path.dirname(cliPath), { recursive: true });
  fs.mkdirSync(path.join(packageRoot, "lib"), { recursive: true });
  fs.writeFileSync(path.join(fixtureRoot, ".npm-version"), `${version}\n`);
  const newline = platform === "win32" ? "\r\n" : "\n";
  fs.writeFileSync(
    cliPath,
    `#!/usr/bin/env node${newline}require('../lib/cli.js')(process)${newline}`,
  );
  fs.writeFileSync(path.join(packageRoot, "lib", "cli.js"), "module.exports = () => {}\n");
  fs.writeFileSync(packageJsonPath, `${JSON.stringify({
    name: options.name || "npm",
    version: options.metadataVersion || version,
    main: "./index.js",
    bin: options.bin || { npm: "bin/npm-cli.js", npx: "bin/npx-cli.js" },
    engines: { node: "^18.17.0 || >=20.5.0" },
  }, null, 2)}\n`);
  const installation = npmInstallationFingerprint(packageRoot, { platform });
  fs.writeFileSync(path.join(fixtureRoot, ".npm-integrity"), `${JSON.stringify({
    posix: installation.sha256,
    win32: installation.sha256,
  })}\n`);
  return {
    cliPath,
    installation,
    nodeExecutable,
    packageJsonPath,
    packageRoot,
    platform,
    version,
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

  test("canonical package runtime accepts the exact Node version pin", () => {
    withNodeVersionPin("22.23.2\n", fixtureRoot => {
      assert.strictEqual(
        assertCanonicalNodeRuntime(fixtureRoot, "v22.23.2"),
        "v22.23.2",
      );
    });
  });

  test("canonical package runtime rejects a Node version mismatch", () => {
    withNodeVersionPin("22.23.2\n", fixtureRoot => {
      assert.throws(
        () => assertCanonicalNodeRuntime(fixtureRoot, "v22.23.1"),
        /runtime does not match the exact version pin/u,
      );
    });
  });

  test("canonical package runtime rejects malformed Node version pins", () => {
    for (const contents of [
      "",
      "22.23\n",
      "v22.23.2\n",
      "22.23.2 \n",
      "22.23.2\n23.0.0\n",
    ]) {
      withNodeVersionPin(contents, fixtureRoot => {
        assert.throws(
          () => assertCanonicalNodeRuntime(fixtureRoot, "v22.23.2"),
          /version pin is unsafe or invalid/u,
        );
      });
    }
  });

  test("canonical package runtime rejects unsafe Node version pin files", function() {
    const runtimeModule = path.join(__dirname, "../scripts/quality/canonical-node-runtime.js");
    const unsafeError = /version pin is unsafe or invalid/u;

    withNodeVersionPin("22.23.2\n", fixtureRoot => {
      const pin = path.join(fixtureRoot, ".node-version");
      const target = path.join(fixtureRoot, "pin-target");
      fs.renameSync(pin, target);
      fs.symlinkSync(target, pin);
      assert.throws(
        () => assertCanonicalNodeRuntime(fixtureRoot, "v22.23.2"),
        unsafeError,
      );
    });

    withNodeVersionPin("22.23.2\n", fixtureRoot => {
      const pin = path.join(fixtureRoot, ".node-version");
      fs.linkSync(pin, path.join(fixtureRoot, "pin-hard-link"));
      assert.throws(
        () => assertCanonicalNodeRuntime(fixtureRoot, "v22.23.2"),
        unsafeError,
      );
    });

    withNodeVersionPin("1".repeat(65), fixtureRoot => {
      assert.throws(
        () => assertCanonicalNodeRuntime(fixtureRoot, "v22.23.2"),
        unsafeError,
      );
    });

    if (process.platform === "win32") return;
    withNodeVersionPin("22.23.2\n", fixtureRoot => {
      const pin = path.join(fixtureRoot, ".node-version");
      fs.unlinkSync(pin);
      const fifo = spawnSync("mkfifo", [pin]);
      assert.strictEqual(fifo.status, 0);
      const probe = spawnSync(process.execPath, [
        "-e",
        "const {assertCanonicalNodeRuntime}=require(process.argv[1]);"
          + "try{assertCanonicalNodeRuntime(process.argv[2],'v22.23.2');process.exit(0)}"
          + "catch(error){process.stderr.write(error.message);process.exit(7)}",
        runtimeModule,
        fixtureRoot,
      ], {
        encoding: "utf8",
        env: {},
        timeout: 2_000,
      });
      assert.strictEqual(probe.error, undefined);
      assert.strictEqual(probe.status, 7);
      assert.match(probe.stderr, unsafeError);
    });
  });

  test("VSCE packaging anchors its exact Node executable ahead of conflicting PATH", () => {
    withNodeVersionPin("22.23.2\n", fixtureRoot => {
      const nodeExecutable = path.join(fixtureRoot, "canonical-node", "bin", "node");
      const conflictingBin = path.join(fixtureRoot, "conflicting-node", "bin");
      const vsceEntry = path.join(
        fixtureRoot,
        "node_modules",
        "@vscode",
        "vsce",
        "out",
        "main.js",
      );
      const outputPath = path.join(fixtureRoot, "candidate.vsix");
      fs.mkdirSync(path.dirname(nodeExecutable), { recursive: true });
      fs.writeFileSync(nodeExecutable, "synthetic exact node runtime\n", { mode: 0o700 });
      const invocation = canonicalVscePackageInvocation(outputPath, {
        nodeExecutable,
        vsceEntry,
      });
      assert.strictEqual(invocation.command, nodeExecutable);
      assert.deepStrictEqual(invocation.arguments_, [
        "--eval",
        "require(process.argv[1])(process.argv);",
        vsceEntry,
        "package",
        "--no-dependencies",
        "--out",
        outputPath,
      ]);

      let child;
      runPackageCommand(invocation.command, invocation.arguments_, {
        environment: { PATH: conflictingBin },
        nodeExecutable,
        spawnSync(command, arguments_, options) {
          child = { command, arguments_, environment: options.env };
          return { status: 0, signal: null, stdout: "packaged\n", stderr: "" };
        },
      });
      assert.strictEqual(child.command, nodeExecutable);
      assert.deepStrictEqual(child.arguments_, invocation.arguments_);
      assert.deepStrictEqual(child.environment.PATH.split(path.delimiter), [
        path.dirname(nodeExecutable),
        conflictingBin,
      ]);
    });
  });

  test("VSCE packaging exposes only its exact validated npm launcher to prepublish", () => {
    withNodeVersionPin("22.23.2\n", fixtureRoot => {
      const fixture = createCanonicalNpmFixture(fixtureRoot);
      const npm = assertCanonicalNpmRuntime(fixtureRoot, fixture.cliPath, {
        nodeExecutable: fixture.nodeExecutable,
        platform: fixture.platform,
      });
      const conflictingBin = path.join(fixtureRoot, "conflicting", "bin");
      fs.mkdirSync(conflictingBin, { recursive: true });
      let launcherDirectory;
      runPackageCommand(fixture.nodeExecutable, ["fixture-vsce-entry"], {
        cwd: fixtureRoot,
        environment: { PATH: conflictingBin },
        nodeExecutable: fixture.nodeExecutable,
        npm,
        platform: fixture.platform,
        temporaryParent: fixtureRoot,
        spawnSync(command, arguments_, options) {
          launcherDirectory = options.env.PATH.split(path.delimiter)[0];
          assert.strictEqual(command, fixture.nodeExecutable);
          assert.deepStrictEqual(arguments_, ["fixture-vsce-entry"]);
          assert.deepStrictEqual(options.env.PATH.split(path.delimiter).slice(0, 3), [
            launcherDirectory,
            path.dirname(fixture.nodeExecutable),
            conflictingBin,
          ]);
          assert.strictEqual(fs.lstatSync(path.join(launcherDirectory, "node")).isFile(), true);
          assert.strictEqual(fs.lstatSync(path.join(launcherDirectory, "npm")).isFile(), true);
          assert.strictEqual(
            fs.lstatSync(path.join(launcherDirectory, "script-shell")).isFile(),
            true,
          );
          assert.strictEqual(
            options.env.NPM_CONFIG_SCRIPT_SHELL,
            path.join(launcherDirectory, "script-shell"),
          );
          return { status: 0, signal: null, stdout: "packaged\n", stderr: "" };
        },
      });
      assert.strictEqual(fs.existsSync(launcherDirectory), false);
    });
  });

  test("canonical npm runtime binds the exact pin, owner metadata, and bin contract", () => {
    withNodeVersionPin("22.23.2\n", fixtureRoot => {
      const fixture = createCanonicalNpmFixture(fixtureRoot);
      const npm = assertCanonicalNpmRuntime(fixtureRoot, fixture.cliPath, {
        nodeExecutable: fixture.nodeExecutable,
        platform: fixture.platform,
      });
      assert.strictEqual(npm.cliPath, fixture.cliPath);
      assert.strictEqual(npm.packageJsonPath, fixture.packageJsonPath);
      assert.strictEqual(npm.packageRoot, fixture.packageRoot);
      assert.strictEqual(npm.version, fixture.version);
      assert.deepStrictEqual(npm.installation, fixture.installation);
      assert.strictEqual(Object.isFrozen(npm.identities), true);
    });
  });

  test("package lifecycle ignores npm snapshot bookkeeping and authenticates the install", () => {
    withNodeVersionPin("22.23.2\n", fixtureRoot => {
      const fixture = createCanonicalNpmFixture(fixtureRoot);
      const installed = assertCanonicalNpmRuntime(fixtureRoot, fixture.cliPath, {
        nodeExecutable: fixture.nodeExecutable,
        platform: fixture.platform,
      });
      withCanonicalNpmLauncher({
        nodeExecutable: fixture.nodeExecutable,
        npm: installed,
        platform: fixture.platform,
        temporaryParent: fixtureRoot,
      }, launcher => {
        assert.notStrictEqual(launcher.npmCliPath, fixture.cliPath);
        assert.throws(
          () => assertCanonicalNpmRuntime(fixtureRoot, launcher.npmCliPath, {
            nodeExecutable: fixture.nodeExecutable,
            platform: fixture.platform,
          }),
          /Canonical npm runtime is unsafe or invalid/u,
        );
        let claimedPath = "not-called";
        const authenticated = authenticatePackageNpmRuntime(
          fixtureRoot,
          fixture.nodeExecutable,
          (repositoryRoot, npmExecPath, options) => {
            claimedPath = npmExecPath;
            return assertCanonicalNpmRuntime(repositoryRoot, npmExecPath, {
              ...options,
              platform: fixture.platform,
            });
          },
        );
        assert.strictEqual(claimedPath, undefined);
        assert.strictEqual(authenticated.cliPath, fixture.cliPath);
        assert.strictEqual(authenticated.version, installed.version);
        assert.strictEqual(authenticated.installation.sha256, installed.installation.sha256);
      });
    });
  });

  test("canonical npm runtime rejects standalone and metadata-forged npm CLI files", () => {
    withNodeVersionPin("22.23.2\n", fixtureRoot => {
      const fixture = createCanonicalNpmFixture(fixtureRoot);
      const standalone = path.join(fixtureRoot, "npm-cli.js");
      fs.writeFileSync(standalone, "process.exit(0)\n");
      assert.throws(
        () => assertCanonicalNpmRuntime(fixtureRoot, standalone, {
          nodeExecutable: fixture.nodeExecutable,
          platform: fixture.platform,
        }),
        /Canonical npm runtime is unsafe or invalid/u,
      );
    });
    for (const options of [
      { name: "not-npm" },
      { metadataVersion: "10.9.7" },
      { bin: { npm: "bin/not-the-cli.js", npx: "bin/npx-cli.js" } },
    ]) {
      withNodeVersionPin("22.23.2\n", fixtureRoot => {
        const fixture = createCanonicalNpmFixture(fixtureRoot, options);
        assert.throws(
          () => assertCanonicalNpmRuntime(fixtureRoot, fixture.cliPath, {
            nodeExecutable: fixture.nodeExecutable,
            platform: fixture.platform,
          }),
          /Canonical npm runtime is unsafe or invalid/u,
        );
      });
    }
  });

  test("canonical npm runtime rejects CLI replacement at its descriptor boundary", () => {
    withNodeVersionPin("22.23.2\n", fixtureRoot => {
      const fixture = createCanonicalNpmFixture(fixtureRoot);
      const displaced = path.join(fixtureRoot, "original-npm-cli.js");
      let replaced = false;
      const fileSystem = Object.create(fs);
      fileSystem.openSync = (target, flags, mode) => {
        if (target === fixture.cliPath && !replaced) {
          replaced = true;
          fs.renameSync(fixture.cliPath, displaced);
          fs.writeFileSync(fixture.cliPath, "process.exit(0)\n");
        }
        return fs.openSync(target, flags, mode);
      };
      assert.throws(
        () => assertCanonicalNpmRuntime(
          fixtureRoot,
          fixture.cliPath,
          {
            fileSystem,
            nodeExecutable: fixture.nodeExecutable,
            platform: fixture.platform,
          },
        ),
        /Canonical npm runtime is unsafe or invalid/u,
      );
      assert.strictEqual(replaced, true);
    });
  });

  test("canonical npm runtime rejects changed installation content despite valid metadata", () => {
    withNodeVersionPin("22.23.2\n", fixtureRoot => {
      const fixture = createCanonicalNpmFixture(fixtureRoot);
      fs.writeFileSync(
        path.join(fixture.packageRoot, "lib", "cli.js"),
        "module.exports = process => process.exit(99)\n",
      );
      assert.throws(
        () => assertCanonicalNpmRuntime(fixtureRoot, fixture.cliPath, {
          nodeExecutable: fixture.nodeExecutable,
          platform: fixture.platform,
        }),
        /Canonical npm runtime is unsafe or invalid/u,
      );
    });
    withNodeVersionPin("22.23.2\n", fixtureRoot => {
      const fixture = createCanonicalNpmFixture(fixtureRoot);
      fs.mkdirSync(path.join(fixture.packageRoot, "unexpected-empty-directory"));
      assert.throws(
        () => assertCanonicalNpmRuntime(fixtureRoot, fixture.cliPath, {
          nodeExecutable: fixture.nodeExecutable,
          platform: fixture.platform,
        }),
        /Canonical npm runtime is unsafe or invalid/u,
      );
    });
  });

  test("canonical npm launcher revalidates the owned installation after its child", () => {
    withNodeVersionPin("22.23.2\n", fixtureRoot => {
      const fixture = createCanonicalNpmFixture(fixtureRoot);
      const npm = assertCanonicalNpmRuntime(fixtureRoot, fixture.cliPath, {
        nodeExecutable: fixture.nodeExecutable,
        platform: fixture.platform,
      });
      let launcherDirectory;
      assert.throws(() => withCanonicalNpmLauncher({
        nodeExecutable: fixture.nodeExecutable,
        npm,
        platform: fixture.platform,
        temporaryParent: fixtureRoot,
      }, launcher => {
        launcherDirectory = launcher.directory;
        fs.writeFileSync(
          path.join(fixture.packageRoot, "lib", "cli.js"),
          "module.exports = process => process.exit(99)\n",
        );
      }), /Canonical npm launcher is unsafe or invalid/u);
      assert.strictEqual(fs.existsSync(launcherDirectory), false);
    });
  });

  test("canonical npm cleanup preserves an unrelated directory moved into its snapshot", () => {
    withNodeVersionPin("22.23.2\n", fixtureRoot => {
      const fixture = createCanonicalNpmFixture(fixtureRoot);
      const npm = assertCanonicalNpmRuntime(fixtureRoot, fixture.cliPath, {
        nodeExecutable: fixture.nodeExecutable,
        platform: fixture.platform,
      });
      const victim = path.join(fixtureRoot, "unrelated-victim");
      fs.mkdirSync(victim);
      fs.writeFileSync(path.join(victim, "preserve.txt"), "unrelated bytes survive\n");
      let launcherDirectory;
      withExpectedCleanupTaint(() => {
        assert.throws(() => withCanonicalNpmLauncher({
          nodeExecutable: fixture.nodeExecutable,
          npm,
          platform: fixture.platform,
          temporaryParent: fixtureRoot,
        }, launcher => {
          launcherDirectory = launcher.directory;
          const snapshotLib = path.join(launcher.directory, "npm-runtime", "lib");
          fs.renameSync(snapshotLib, `${snapshotLib}-owned`);
          fs.renameSync(victim, snapshotLib);
        }), /Canonical npm launcher is unsafe or invalid/u);
      });
      assert.strictEqual(
        fs.readFileSync(
          path.join(launcherDirectory, "npm-runtime", "lib", "preserve.txt"),
          "utf8",
        ),
        "unrelated bytes survive\n",
      );
    });
  });

  test("outer non-auth cleanup quarantines a tainted npm snapshot without deleting it", () => {
    withNodeVersionPin("22.23.2\n", fixtureRoot => {
      const fixture = createCanonicalNpmFixture(fixtureRoot);
      const npm = assertCanonicalNpmRuntime(fixtureRoot, fixture.cliPath, {
        nodeExecutable: fixture.nodeExecutable,
        platform: fixture.platform,
      });
      const boundary = createNonAuthQualityEnvironment({ temporaryParent: fixtureRoot });
      const boundaryName = path.basename(boundary.root);
      const victim = path.join(fixtureRoot, "outer-unrelated-victim");
      fs.mkdirSync(victim);
      fs.writeFileSync(path.join(victim, "preserve.txt"), "outer unrelated bytes survive\n");
      let launcherName;
      withExpectedCleanupTaint(() => {
        assert.throws(() => withCanonicalNpmLauncher({
          nodeExecutable: fixture.nodeExecutable,
          npm,
          platform: fixture.platform,
          temporaryParent: boundary.paths.temporary,
        }, launcher => {
          launcherName = path.basename(launcher.directory);
          const snapshotLib = path.join(launcher.directory, "npm-runtime", "lib");
          fs.renameSync(snapshotLib, `${snapshotLib}-owned`);
          fs.renameSync(victim, snapshotLib);
        }), /Canonical npm launcher is unsafe or invalid/u);
      });
      withExpectedCleanupTaint(() => {
        assert.throws(
          () => cleanupNonAuthQualityEnvironment(boundary),
          /preserved an unsafe or changed tree/u,
        );
      });
      const quarantineName = fs.readdirSync(fixtureRoot).find(
        name => name.startsWith(`.${boundaryName}.cleanup-`),
      );
      assert.strictEqual(typeof quarantineName, "string");
      assert.strictEqual(
        fs.readFileSync(path.join(
          fixtureRoot,
          quarantineName,
          "tmp",
          launcherName,
          "npm-runtime",
          "lib",
          "preserve.txt",
        ), "utf8"),
        "outer unrelated bytes survive\n",
      );
    });
  });

  test("canonical npm launcher executes only its private snapshot across source substitution", () => {
    withNodeVersionPin("22.23.2\n", fixtureRoot => {
      const fixture = createCanonicalNpmFixture(fixtureRoot);
      const sourceDependency = path.join(fixture.packageRoot, "lib", "cli.js");
      const sourceBytes = fs.readFileSync(sourceDependency);
      const npm = assertCanonicalNpmRuntime(fixtureRoot, fixture.cliPath, {
        nodeExecutable: fixture.nodeExecutable,
        platform: fixture.platform,
      });
      let launcherDirectory;
      assert.throws(() => withCanonicalNpmLauncher({
        nodeExecutable: fixture.nodeExecutable,
        npm,
        platform: fixture.platform,
        temporaryParent: fixtureRoot,
      }, launcher => {
        launcherDirectory = launcher.directory;
        const snapshotDependency = path.join(launcher.directory, "npm-runtime", "lib", "cli.js");
        assert.strictEqual(launcher.npmCliPath, path.join(
          launcher.directory,
          "npm-runtime",
          "bin",
          "npm-cli.js",
        ));
        fs.writeFileSync(sourceDependency, Buffer.alloc(sourceBytes.length, 0x78));
        fs.writeFileSync(sourceDependency, sourceBytes);
        assert.deepStrictEqual(fs.readFileSync(snapshotDependency), sourceBytes);
      }), /Canonical npm launcher is unsafe or invalid/u);
      assert.strictEqual(fs.existsSync(launcherDirectory), false);
    });
  });

  test("canonical npm launcher rejects and preserves a changed private snapshot", () => {
    withNodeVersionPin("22.23.2\n", fixtureRoot => {
      const fixture = createCanonicalNpmFixture(fixtureRoot);
      const npm = assertCanonicalNpmRuntime(fixtureRoot, fixture.cliPath, {
        nodeExecutable: fixture.nodeExecutable,
        platform: fixture.platform,
      });
      let launcherDirectory;
      withExpectedCleanupTaint(() => {
        assert.throws(() => withCanonicalNpmLauncher({
          nodeExecutable: fixture.nodeExecutable,
          npm,
          platform: fixture.platform,
          temporaryParent: fixtureRoot,
        }, launcher => {
          launcherDirectory = launcher.directory;
          const snapshotDependency = path.join(launcher.directory, "npm-runtime", "lib", "cli.js");
          fs.chmodSync(snapshotDependency, 0o600);
          fs.writeFileSync(snapshotDependency, "module.exports = process => process.exit(99)\n");
        }), /Canonical npm launcher is unsafe or invalid/u);
      });
      assert.strictEqual(fs.existsSync(launcherDirectory), true);
    });
  });

  test("canonical npm launcher covers node-only POSIX and Windows runtimes and cleans up", () => {
    for (const platform of ["linux", "win32"]) {
      withNodeVersionPin("22.23.2\n", fixtureRoot => {
        const fixture = createCanonicalNpmFixture(fixtureRoot, { platform });
        const runtime = fixture.nodeExecutable;
        const npm = assertCanonicalNpmRuntime(fixtureRoot, fixture.cliPath, {
          nodeExecutable: runtime,
          platform,
        });
        let launcherDirectory;
        withCanonicalNpmLauncher({
          nodeExecutable: runtime,
          npm,
          platform,
          temporaryParent: fixtureRoot,
        }, launcher => {
          launcherDirectory = launcher.directory;
          const npmName = platform === "win32" ? "npm.cmd" : "npm";
          const nodeName = platform === "win32" ? "node.cmd" : "node";
          assert.strictEqual(fs.lstatSync(path.join(launcher.directory, npmName)).isFile(), true);
          assert.strictEqual(fs.lstatSync(path.join(launcher.directory, nodeName)).isFile(), true);
          assert.strictEqual(launcher.npmCliPath, path.join(
            launcher.directory,
            "npm-runtime",
            "bin",
            "npm-cli.js",
          ));
          assert.strictEqual(fs.existsSync(path.join(path.dirname(runtime), npmName)), false);
          const environment = canonicalToolchainEnvironment(
            { PATH: path.join(fixtureRoot, "conflicting", "bin") },
            {
              launcherDirectory: launcher.directory,
              nodeExecutable: runtime,
              platform,
            },
          );
          assert.deepStrictEqual(environment.PATH.split(path.delimiter).slice(0, 2), [
            launcher.directory,
            path.dirname(runtime),
          ]);
        });
        assert.strictEqual(fs.existsSync(launcherDirectory), false);
      });
    }
  });

  test("canonical toolchain environment rejects Windows PATH key collisions", () => {
    assert.throws(
      () => canonicalToolchainEnvironment(
        { PATH: "first", Path: "second" },
        {
          launcherDirectory: path.resolve(os.tmpdir(), "fixture-launcher"),
          nodeExecutable: process.execPath,
          platform: "win32",
        },
      ),
      /PATH has case-colliding keys/u,
    );
  });

  test("canonical toolchain environment rejects Windows PATHEXT key collisions", () => {
    assert.throws(
      () => canonicalToolchainEnvironment(
        { PATH: path.dirname(process.execPath), PATHEXT: ".EXE", Pathext: ".CMD" },
        { nodeExecutable: process.execPath, platform: "win32" },
      ),
      /PATHEXT has case-colliding keys/u,
    );
  });

  test("canonical npm launcher cleanup rejects unexpected entries", () => {
    withNodeVersionPin("22.23.2\n", fixtureRoot => {
      const fixture = createCanonicalNpmFixture(fixtureRoot);
      const runtime = fixture.nodeExecutable;
      const npm = assertCanonicalNpmRuntime(fixtureRoot, fixture.cliPath, {
        nodeExecutable: runtime,
        platform: fixture.platform,
      });
      let launcherDirectory;
      withExpectedCleanupTaint(() => {
        assert.throws(() => withCanonicalNpmLauncher({
          nodeExecutable: runtime,
          npm,
          platform: "linux",
          temporaryParent: fixtureRoot,
        }, launcher => {
          launcherDirectory = launcher.directory;
          fs.writeFileSync(path.join(launcher.directory, "unexpected"), "do not remove\n");
        }), /Canonical npm launcher cleanup refused/u);
      });
      assert.strictEqual(fs.readFileSync(
        path.join(launcherDirectory, "unexpected"),
        "utf8",
      ), "do not remove\n");
    });
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
    const expectedEntries = [expectedExactCleanupTreeEntry(path.join(
      ownedRoot,
      "temporary.vsix",
    ))];
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
      withExpectedCleanupTaint(() => {
        assert.throws(
          () => removePackageBuildDirectory(ownedRoot, identity, expectedEntries),
          /temporary cleanup refused an unsafe or changed tree/u,
        );
      });
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

  test("release package cleanup preserves an unrelated directory moved into its build root", () => {
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(
      os.tmpdir(),
      "release-package-cleanup-moved-victim-",
    )));
    const ownedRoot = path.join(scratch, "owned-build");
    const artifact = path.join(ownedRoot, "temporary.vsix");
    const victim = path.join(scratch, "preserve-victim");
    fs.mkdirSync(ownedRoot);
    fs.writeFileSync(artifact, "synthetic build bytes\n");
    fs.mkdirSync(victim);
    fs.writeFileSync(path.join(victim, "preserve.txt"), "moved victim survives\n");
    const identity = packageBuildDirectoryIdentity(ownedRoot);
    const expectedEntries = [expectedExactCleanupTreeEntry(artifact)];
    fs.renameSync(victim, path.join(ownedRoot, "moved-victim"));
    try {
      withExpectedCleanupTaint(() => {
        assert.throws(
          () => removePackageBuildDirectory(ownedRoot, identity, expectedEntries),
          /temporary cleanup refused an unsafe or changed tree/u,
        );
      });
      assert.strictEqual(
        fs.readFileSync(path.join(ownedRoot, "moved-victim", "preserve.txt"), "utf8"),
        "moved victim survives\n",
      );
      assert.strictEqual(fs.existsSync(artifact), true);
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

  test("release provenance binds the exact Node, npm, and npm installation pins", () => {
    for (const mutation of [
      { nodeVersion: "v22.23.1" },
      { npmVersion: "10.9.7" },
      { npmInstallationSha256: "0".repeat(64) },
      { platform: process.platform === "win32" ? "linux" : "win32" },
    ]) {
      const fixture = sidecarFixture();
      try {
        fs.writeFileSync(
          fixture.provenancePath,
          `${JSON.stringify({ ...fixture.provenance, ...mutation })}\n`,
        );
        assert.throws(
          () => validateSidecars(fixture.filePath, fixture.verification, {
            expectedSourceSha: fixture.sourceSha,
          }),
          /toolchain does not match the exact repository pins/u,
        );
      } finally {
        fs.rmSync(fixture.directory, { recursive: true, force: true });
      }
    }
  });

  test("clean release provenance binds platform pins from its exact source commit", () => {
    const fixture = sidecarFixture();
    const sourcePins = {
      ".node-version": "22.23.2\n",
      ".npm-version": "10.9.8\n",
      ".npm-integrity": `${JSON.stringify({
        posix: "7".repeat(64),
        win32: "8".repeat(64),
      })}\n`,
    };
    const queries = [];
    const runGitCommand = arguments_ => {
      queries.push([...arguments_]);
      if (arguments_[0] === "rev-parse") return `${fixture.sourceSha}\n`;
      if (arguments_[0] === "show" && arguments_[1] === "-s") {
        return `${fixture.provenance.sourceCommitEpoch}\n`;
      }
      const object = arguments_[arguments_.length - 1];
      const name = Object.keys(sourcePins).find(candidate => object.endsWith(`:${candidate}`));
      if (!name) throw new Error("Unexpected synthetic Git provenance query");
      if (arguments_[0] === "cat-file" && arguments_[1] === "-s") {
        return `${Buffer.byteLength(sourcePins[name])}\n`;
      }
      if (arguments_[0] === "show") return sourcePins[name];
      throw new Error("Unexpected synthetic Git provenance query");
    };
    const provenance = {
      ...fixture.provenance,
      npmInstallationSha256: "7".repeat(64),
      platform: "linux",
      sourceClean: true,
    };
    try {
      fs.writeFileSync(fixture.provenancePath, `${JSON.stringify(provenance)}\n`);
      const validated = validateSidecars(fixture.filePath, fixture.verification, {
        expectedSourceSha: fixture.sourceSha,
        runGitCommand,
      });
      assert.strictEqual(validated.provenance.platform, "linux");
      for (const name of Object.keys(sourcePins)) {
        assert.ok(queries.some(arguments_ => (
          arguments_[0] === "show"
          && arguments_[1] === `${fixture.sourceSha}:${name}`
        )), name);
      }

      fs.writeFileSync(fixture.provenancePath, `${JSON.stringify({
        ...provenance,
        npmInstallationSha256: "8".repeat(64),
      })}\n`);
      assert.throws(
        () => validateSidecars(fixture.filePath, fixture.verification, {
          expectedSourceSha: fixture.sourceSha,
          runGitCommand,
        }),
        /toolchain does not match the exact repository pins/u,
      );
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

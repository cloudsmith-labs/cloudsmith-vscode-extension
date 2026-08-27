// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { fingerprint } = require("../scripts/quality/evidence");
const {
  LOCAL_PROFILE_BASENAME,
  PROFILE_MARKER,
  adoptLegacyLocalQualificationProfile,
  cleanupCiQualificationProfile,
  createCiQualificationProfile,
  prepareLocalQualificationProfile,
  removeSafeAppleMetadata,
  resetLocalQualificationProfile,
  resetCiQualificationUserData,
} = require("../scripts/quality/qualification-profile");
const {
  assertStableSource,
  discoverLocalCodePaths,
  exactVersionState,
  installAndVerifyCandidate,
  parseCli,
  parsePackageOutput,
  prepareCodePaths,
  prepareQualificationCandidate,
  qualificationEnvironment,
  qualificationLaunchArguments,
  resolveCodeInstallation,
} = require("../scripts/quality/prepare-qualification");

const temporaryRoots = [];

function temporaryRoot(prefix = "cloudsmith-qualification-test-") {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  if (process.platform !== "win32") fs.chmodSync(root, 0o700);
  temporaryRoots.push(root);
  return root;
}

function makeExecutable(target) {
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  fs.writeFileSync(target, "fixture\n", { mode: 0o700 });
  if (process.platform !== "win32") fs.chmodSync(target, 0o700);
  return target;
}

function writeCandidateRepository(root, vscodeVersion = "1.131.0") {
  const manifest = {
    name: "cloudsmith-vsc",
    publisher: "Cloudsmith",
    version: "2.3.0",
  };
  fs.writeFileSync(path.join(root, "package.json"), JSON.stringify(manifest));
  fs.writeFileSync(path.join(root, "package-lock.json"), JSON.stringify({
    name: manifest.name,
    version: manifest.version,
    packages: { "": { name: manifest.name, version: manifest.version } },
  }));
  fs.writeFileSync(
    path.join(root, "CHANGELOG.md"),
    "## Unreleased\n\n## 2.3.0 - August 2026\n\n## 2.2.0 - August 2026\n",
  );
  fs.writeFileSync(path.join(root, "extester.config.json"), JSON.stringify({
    setup: { vscodeVersion, type: "stable" },
    run: { vscodeVersion, type: "stable" },
  }));
  fs.writeFileSync(
    path.join(root, ".vscode-test.mjs"),
    "const version = process.env.VSCODE_TEST_VERSION || \"1.134.0\";\n",
  );
}

suite("qualification candidate isolation", () => {
  teardown(() => {
    while (temporaryRoots.length > 0) {
      fs.rmSync(temporaryRoots.pop(), { recursive: true, force: true });
    }
  });

  test("local profile is canonical, private, and persistent", () => {
    const parent = temporaryRoot();
    const home = path.join(parent, "home");
    fs.mkdirSync(home, { mode: 0o700 });
    const first = prepareLocalQualificationProfile({ homeDirectory: home });
    assert.strictEqual(first.root, path.join(home, LOCAL_PROFILE_BASENAME));
    assert.strictEqual(first.userDataDir, path.join(first.root, "user-data"));
    assert.strictEqual(first.extensionsDir, path.join(first.root, "extensions"));
    assert.strictEqual(first.testResourcesDir, first.root);
    assert.strictEqual(first.persistent, true);
    if (process.platform !== "win32") {
      assert.strictEqual(fs.lstatSync(first.root).mode & 0o077, 0);
    }
    const preserved = path.join(first.userDataDir, "preserved-fixture");
    fs.writeFileSync(preserved, "preserved");
    const second = prepareLocalQualificationProfile({ homeDirectory: home });
    assert.strictEqual(second.root, first.root);
    assert.strictEqual(fs.readFileSync(preserved, "utf8"), "preserved");
    assert.throws(() => cleanupCiQualificationProfile(first), /refuses persistent/);
  });

  test("local profile refuses wrong roots, traversal, and symbolic links", () => {
    const parent = temporaryRoot();
    const home = path.join(parent, "home");
    fs.mkdirSync(home, { mode: 0o700 });
    const canonical = path.join(home, LOCAL_PROFILE_BASENAME);
    assert.throws(
      () => prepareLocalQualificationProfile({ homeDirectory: home, profileRoot: parent }),
      /must be exactly/,
    );
    assert.throws(
      () => prepareLocalQualificationProfile({
        homeDirectory: home,
        profileRoot: `${home}${path.sep}child${path.sep}..${path.sep}${LOCAL_PROFILE_BASENAME}`,
      }),
      /traversal-free/,
    );
    const target = path.join(parent, "target");
    fs.mkdirSync(target, { mode: 0o700 });
    fs.symlinkSync(target, canonical);
    assert.throws(
      () => prepareLocalQualificationProfile({ homeDirectory: home }),
      /real directory|symbolic link/,
    );
  });

  test("canonical legacy profile adoption preserves opaque bytes without listing or opening them", () => {
    const parent = temporaryRoot();
    const home = path.join(parent, "home");
    fs.mkdirSync(home, { mode: 0o700 });
    const root = path.join(home, LOCAL_PROFILE_BASENAME);
    const userData = path.join(root, "user-data");
    const extensions = path.join(root, "extensions");
    fs.mkdirSync(root, { mode: 0o755 });
    fs.mkdirSync(userData, { mode: 0o755 });
    fs.mkdirSync(extensions, { mode: 0o755 });
    if (process.platform !== "win32") {
      fs.chmodSync(root, 0o755);
      fs.chmodSync(userData, 0o755);
      fs.chmodSync(extensions, 0o755);
    }
    const userSentinel = path.join(userData, "opaque-existing-state");
    const extensionSentinel = path.join(extensions, "opaque-installed-extension");
    fs.writeFileSync(userSentinel, "preserve-user-bytes");
    fs.writeFileSync(extensionSentinel, "preserve-extension-bytes");

    const originalRead = fs.readFileSync;
    const originalList = fs.readdirSync;
    fs.readFileSync = function guardedRead(target, ...args) {
      if (target === userSentinel || target === extensionSentinel) {
        throw new Error("Adoption opened opaque profile state.");
      }
      return originalRead.call(this, target, ...args);
    };
    fs.readdirSync = function guardedList(target, ...args) {
      if (target === root || target === userData || target === extensions) {
        throw new Error("Adoption enumerated legacy profile state.");
      }
      return originalList.call(this, target, ...args);
    };
    let profile;
    try {
      profile = prepareLocalQualificationProfile({ homeDirectory: home });
    } finally {
      fs.readFileSync = originalRead;
      fs.readdirSync = originalList;
    }

    assert.strictEqual(profile.root, root);
    assert.strictEqual(fs.readFileSync(userSentinel, "utf8"), "preserve-user-bytes");
    assert.strictEqual(fs.readFileSync(extensionSentinel, "utf8"), "preserve-extension-bytes");
    assert.strictEqual(fs.lstatSync(path.join(root, PROFILE_MARKER)).isFile(), true);
    assert.strictEqual(fs.lstatSync(path.join(root, "home")).isDirectory(), true);
    if (process.platform !== "win32") {
      for (const directory of [root, userData, extensions, path.join(root, "home")]) {
        assert.strictEqual(fs.lstatSync(directory).mode & 0o077, 0);
      }
    }
  });

  test("legacy adoption refuses markers, symlinks, unexpected home, and noncanonical roots", () => {
    const parent = temporaryRoot();
    const noncanonical = path.join(parent, "profile");
    fs.mkdirSync(noncanonical, { mode: 0o700 });
    assert.throws(
      () => adoptLegacyLocalQualificationProfile(noncanonical, { homeDirectory: parent }),
      /noncanonical/u,
    );

    const home = path.join(parent, "home");
    fs.mkdirSync(home, { mode: 0o700 });
    const root = path.join(home, LOCAL_PROFILE_BASENAME);
    fs.mkdirSync(root, { mode: 0o700 });
    const target = path.join(parent, "user-data-target");
    fs.mkdirSync(target, { mode: 0o700 });
    fs.symlinkSync(target, path.join(root, "user-data"));
    fs.mkdirSync(path.join(root, "extensions"), { mode: 0o700 });
    assert.throws(
      () => prepareLocalQualificationProfile({ homeDirectory: home }),
      /real directory.*symbolic link/u,
    );
    fs.unlinkSync(path.join(root, "user-data"));
    fs.mkdirSync(path.join(root, "user-data"), { mode: 0o700 });
    fs.mkdirSync(path.join(root, "home"), { mode: 0o700 });
    assert.throws(
      () => prepareLocalQualificationProfile({ homeDirectory: home }),
      /unexpected home/u,
    );
    fs.rmdirSync(path.join(root, "home"));
    fs.writeFileSync(path.join(root, PROFILE_MARKER), "malformed\n", { mode: 0o600 });
    assert.throws(
      () => prepareLocalQualificationProfile({ homeDirectory: home }),
      /ownership marker/u,
    );
    assert.strictEqual(fs.existsSync(root), true);
  });

  test("local reset deletes only the exact owned canonical profile", () => {
    const parent = temporaryRoot();
    const home = path.join(parent, "home");
    fs.mkdirSync(home, { mode: 0o700 });
    const profile = prepareLocalQualificationProfile({ homeDirectory: home });
    const ordinaryVsCode = path.join(home, ".config", "Code", "User");
    fs.mkdirSync(ordinaryVsCode, { recursive: true });
    fs.writeFileSync(path.join(ordinaryVsCode, "settings.json"), "ordinary");
    assert.throws(
      () => resetLocalQualificationProfile({ homeDirectory: home, profileRoot: parent }),
      /noncanonical/,
    );
    assert.strictEqual(resetLocalQualificationProfile({ homeDirectory: home }), true);
    assert.strictEqual(fs.existsSync(profile.root), false);
    assert.strictEqual(
      fs.readFileSync(path.join(ordinaryVsCode, "settings.json"), "utf8"),
      "ordinary",
    );
    assert.strictEqual(resetLocalQualificationProfile({ homeDirectory: home }), false);
  });

  test("local reset refuses a symbolic-link or unknown ownership marker", () => {
    const parent = temporaryRoot();
    const home = path.join(parent, "home");
    fs.mkdirSync(home, { mode: 0o700 });
    const canonical = path.join(home, LOCAL_PROFILE_BASENAME);
    const target = path.join(parent, "target");
    fs.mkdirSync(target, { mode: 0o700 });
    fs.symlinkSync(target, canonical);
    assert.throws(
      () => resetLocalQualificationProfile({ homeDirectory: home }),
      /real directory|symbolic link/,
    );
    fs.unlinkSync(canonical);
    fs.mkdirSync(canonical, { mode: 0o700 });
    fs.writeFileSync(
      path.join(canonical, ".cloudsmith-qualification-owner.json"),
      "{\"schemaVersion\":1,\"owner\":\"unknown\",\"mode\":\"local\",\"proof\":\"0000000000000000000000000000000000000000000000000000000000000000\"}\n",
      { mode: 0o600 },
    );
    assert.throws(
      () => resetLocalQualificationProfile({ homeDirectory: home }),
      /ownership marker is invalid/,
    );
    assert.strictEqual(fs.existsSync(canonical), true);
  });

  test("CI profile is 0700, canonical, and cleanup is creator-bound", () => {
    const parent = temporaryRoot();
    const profile = createCiQualificationProfile({ temporaryParent: parent });
    assert.strictEqual(profile.mode, "ci");
    assert.strictEqual(profile.persistent, false);
    assert.strictEqual(profile.userDataDir, path.join(profile.root, "settings"));
    assert.strictEqual(profile.extensionsDir, path.join(profile.root, "extensions"));
    if (process.platform !== "win32") {
      assert.strictEqual(fs.lstatSync(profile.root).mode & 0o077, 0);
    }
    assert.throws(
      () => cleanupCiQualificationProfile({ ...profile, cleanupProof: "0".repeat(64) }),
      /did not create/,
    );
    assert.strictEqual(cleanupCiQualificationProfile(profile), true);
    assert.strictEqual(fs.existsSync(profile.root), false);
    assert.throws(() => cleanupCiQualificationProfile(profile), /did not create/);
  });

  test("default CI profile keeps the macOS VS Code IPC socket path below its limit", () => {
    const profile = createCiQualificationProfile();
    try {
      assert.match(path.basename(profile.root), /^csvq-[A-Za-z0-9]{6}$/u);
      if (process.platform === "darwin") {
        const socketPath = path.join(profile.userDataDir, "1.13-main.sock");
        assert.ok(Buffer.byteLength(socketPath, "utf8") <= 103);
        assert.strictEqual(path.dirname(profile.root), fs.realpathSync("/tmp"));
      }
    } finally {
      cleanupCiQualificationProfile(profile);
    }
  });

  test("CI probe user-data reset is exact and preserves the installed extension directory", () => {
    const parent = temporaryRoot();
    const profile = createCiQualificationProfile({ temporaryParent: parent });
    fs.mkdirSync(path.join(profile.userDataDir, "User"));
    fs.writeFileSync(path.join(profile.userDataDir, "User", "probe"), "probe");
    const installed = path.join(profile.extensionsDir, "candidate");
    fs.writeFileSync(installed, "installed");
    assert.strictEqual(resetCiQualificationUserData(profile), profile.userDataDir);
    assert.deepStrictEqual(fs.readdirSync(profile.userDataDir), []);
    assert.strictEqual(fs.readFileSync(installed, "utf8"), "installed");
    if (process.platform !== "win32") {
      assert.strictEqual(fs.lstatSync(profile.userDataDir).mode & 0o077, 0);
    }
    assert.throws(
      () => resetCiQualificationUserData({ ...profile, mode: "local" }),
      /refuses persistent/,
    );
    cleanupCiQualificationProfile(profile);
  });

  test("Apple metadata cleanup removes only Git-listed real metadata files", () => {
    const root = temporaryRoot();
    fs.mkdirSync(path.join(root, "nested"));
    fs.mkdirSync(path.join(root, "tracked"));
    fs.writeFileSync(path.join(root, ".DS_Store"), "ignored");
    fs.writeFileSync(path.join(root, "nested", "._fork"), "untracked");
    fs.writeFileSync(path.join(root, "tracked", ".DS_Store"), "tracked");
    fs.writeFileSync(path.join(root, "keep.txt"), "keep");
    let calls = 0;
    const git = (command, arguments_) => {
      assert.strictEqual(command, "git");
      assert.ok(arguments_.includes("--others"));
      calls += 1;
      return {
        status: 0,
        signal: null,
        stdout: calls === 1 ? "nested/._fork\u0000" : ".DS_Store\u0000",
        stderr: "",
      };
    };
    assert.deepStrictEqual(
      [...removeSafeAppleMetadata(root, { spawnSync: git })],
      [".DS_Store", "nested/._fork"],
    );
    assert.strictEqual(fs.existsSync(path.join(root, ".DS_Store")), false);
    assert.strictEqual(fs.existsSync(path.join(root, "nested", "._fork")), false);
    assert.strictEqual(fs.readFileSync(path.join(root, "tracked", ".DS_Store"), "utf8"), "tracked");
    assert.strictEqual(fs.readFileSync(path.join(root, "keep.txt"), "utf8"), "keep");
  });

  test("Apple metadata cleanup rejects traversal and symbolic-link targets", () => {
    const root = temporaryRoot();
    const outside = path.join(path.dirname(root), `${path.basename(root)}-outside`);
    fs.writeFileSync(outside, "outside");
    temporaryRoots.push(outside);
    const traversalGit = () => ({
      status: 0, signal: null, stdout: "../.DS_Store\u0000", stderr: "",
    });
    assert.throws(
      () => removeSafeAppleMetadata(root, { spawnSync: traversalGit }),
      /unsafe Apple metadata path/,
    );
    assert.strictEqual(fs.readFileSync(outside, "utf8"), "outside");
    fs.symlinkSync(outside, path.join(root, ".DS_Store"));
    let calls = 0;
    const symlinkGit = () => ({
      status: 0,
      signal: null,
      stdout: ++calls === 1 ? ".DS_Store\u0000" : "",
      stderr: "",
    });
    assert.throws(
      () => removeSafeAppleMetadata(root, { spawnSync: symlinkGit }),
      /real regular files/,
    );
    assert.strictEqual(fs.readFileSync(outside, "utf8"), "outside");
  });

  test("qualification environment strips credentials and launch args bind owned dirs", () => {
    const root = temporaryRoot();
    const profile = {
      mode: "ci",
      root,
      testResourcesDir: root,
      homeDir: path.join(root, "home"),
      userDataDir: path.join(root, "settings"),
      extensionsDir: path.join(root, "extensions"),
    };
    const environment = qualificationEnvironment({
      PATH: "/fixture/bin",
      CLOUDSMITH_API_KEY: "must-not-pass",
      NODE_OPTIONS: "--require=unexpected",
    }, profile);
    assert.strictEqual(environment.PATH, "/fixture/bin");
    assert.strictEqual(environment.HOME, profile.homeDir);
    assert.strictEqual(environment.CLOUDSMITH_API_KEY, undefined);
    assert.strictEqual(environment.NODE_OPTIONS, undefined);
    assert.ok(Object.isFrozen(environment));
    const arguments_ = qualificationLaunchArguments(profile);
    assert.deepStrictEqual([...arguments_], [
      "--user-data-dir", profile.userDataDir,
      "--extensions-dir", profile.extensionsDir,
      "--disable-updates", "--skip-welcome", "--skip-release-notes", "--new-window",
    ]);
    assert.strictEqual(arguments_.some(value => value.includes("extensionDevelopmentPath")), false);
  });

  test("candidate source handoff rejects commit and working-tree drift", () => {
    const initial = { sha: "a".repeat(40), fingerprint: "b".repeat(64) };
    assert.strictEqual(assertStableSource(initial, { ...initial }), initial);
    assert.throws(
      () => assertStableSource(initial, { ...initial, sha: "c".repeat(40) }),
      /source changed/,
    );
    assert.throws(
      () => assertStableSource(initial, { ...initial, fingerprint: "d".repeat(64) }),
      /source changed/,
    );
    assert.throws(
      () => assertStableSource(initial, { sha: initial.sha, fingerprint: "malformed" }),
      /identity is invalid/,
    );
  });

  test("local and CI qualification use distinct exact canonical VS Code pins", () => {
    const root = temporaryRoot();
    writeCandidateRepository(root, "1.131.0");
    assert.strictEqual(exactVersionState(root, "local").vscodeVersion, "1.134.0");
    assert.strictEqual(exactVersionState(root, "ci").vscodeVersion, "1.131.0");
    assert.strictEqual(
      exactVersionState(root, "ci", "current").vscodeVersion,
      "1.134.0",
    );
    assert.throws(
      () => exactVersionState(root, "local", "black-box"),
      /lane is incompatible/,
    );
    assert.throws(() => exactVersionState(root, "unknown"), /mode must be local or ci/);
  });

  test("package handoff accepts only the exact canonical VSIX and sidecars", () => {
    const root = temporaryRoot();
    const outputDirectory = path.join(root, "out", "development");
    fs.mkdirSync(outputDirectory, { recursive: true });
    const relative = "out/development/cloudsmith-vsc-2.3.0.vsix";
    for (const suffix of ["", ".sha256", ".provenance.json"]) {
      fs.writeFileSync(path.join(root, `${relative}${suffix}`), "fixture");
    }
    const output = path.join(root, "package-output");
    fs.writeFileSync(output,
      `vsix_path=${relative}\nchecksum_path=${relative}.sha256\nprovenance_path=${relative}.provenance.json\n`
    );
    assert.strictEqual(
      parsePackageOutput(output, root, "cloudsmith-vsc", "2.3.0").vsixPath,
      relative,
    );
    fs.appendFileSync(output, "unexpected=value\n");
    assert.throws(
      () => parsePackageOutput(output, root, "cloudsmith-vsc", "2.3.0"),
      /unexpected or duplicate/,
    );
  });

  test("app-bundled CLI fallback verifies the exact VS Code version", () => {
    const root = temporaryRoot();
    const executable = makeExecutable(path.join(
      root, "Visual Studio Code.app", "Contents", "MacOS", "Electron"
    ));
    const cli = makeExecutable(path.join(
      root, "Visual Studio Code.app", "Contents", "Resources", "app", "bin", "code"
    ));
    const installation = resolveCodeInstallation({
      vscodeExecutable: executable,
      platform: "darwin",
      spawnSync(command, arguments_) {
        assert.strictEqual(command, cli);
        assert.deepStrictEqual(arguments_, ["--version"]);
        return { status: 0, signal: null, stdout: "1.131.0\nfixture-commit\narm64\n", stderr: "" };
      },
      root,
      environment: {},
      vscodeVersion: "1.131.0",
    });
    assert.strictEqual(installation.cli, cli);
    assert.strictEqual(installation.executable, executable);
    assert.strictEqual(installation.version, "1.131.0");
  });

  test("no-argument local preparation discovers the canonical macOS app and exact pin", async () => {
    const applicationsDirectory = temporaryRoot("cloudsmith-applications-");
    const fallbackBundle = path.join(applicationsDirectory, "Visual Studio Code.app");
    makeExecutable(path.join(fallbackBundle, "Contents", "MacOS", "Code"));
    makeExecutable(path.join(
      fallbackBundle, "Contents", "Resources", "app", "bin", "code"
    ));
    const bundle = path.join(
      applicationsDirectory, "path-install", "Visual Studio Code.app"
    );
    const appRoot = path.join(bundle, "Contents", "Resources", "app");
    const executable = makeExecutable(path.join(bundle, "Contents", "MacOS", "Code"));
    const cli = makeExecutable(path.join(appRoot, "bin", "code"));
    const commandLink = path.join(applicationsDirectory, "command-bin", "code");
    fs.mkdirSync(path.dirname(commandLink), { mode: 0o700 });
    fs.symlinkSync(cli, commandLink);
    const discoveryCalls = [];
    const options = parseCli([]);
    assert.deepStrictEqual(options, { mode: "local", launch: false });
    assert.deepStrictEqual(parseCli(["--launch"]), { mode: "local", launch: true });
    assert.deepStrictEqual(
      parseCli(["--vscode-executable", executable, "--vscode-cli", cli]),
      { mode: "local", launch: false, vscodeExecutable: executable, vscodeCli: cli },
    );
    const discovered = await prepareCodePaths({
      ...options,
      platform: "darwin",
      applicationsDirectory,
      profile: { mode: "local" },
      root: applicationsDirectory,
      environment: { PATH: path.dirname(commandLink) },
      spawnSync(command, arguments_) {
        discoveryCalls.push({ command, arguments_ });
        return { status: 0, signal: null, stdout: `${commandLink}\n`, stderr: "" };
      },
    });
    assert.deepStrictEqual(discovered, { executable, cli, appRoot });
    assert.strictEqual(fs.lstatSync(discovered.cli).isSymbolicLink(), false);
    assert.deepStrictEqual(discoveryCalls, [{
      command: "/bin/sh",
      arguments_: ["-c", "command -v code"],
    }]);
    const installation = resolveCodeInstallation({
      vscodeExecutable: discovered.executable,
      vscodeCli: discovered.cli,
      appRoot: discovered.appRoot,
      platform: "darwin",
      spawnSync(command, arguments_) {
        assert.strictEqual(command, cli);
        assert.deepStrictEqual(arguments_, ["--version"]);
        return { status: 0, signal: null, stdout: "1.134.0\nfixture-commit\narm64\n" };
      },
      root: applicationsDirectory,
      environment: {},
      vscodeVersion: "1.134.0",
    });
    assert.strictEqual(installation.version, "1.134.0");
  });

  test("automatic local discovery fails closed off macOS and on a version mismatch", async () => {
    const applicationsDirectory = temporaryRoot("cloudsmith-applications-");
    const bundle = path.join(applicationsDirectory, "Visual Studio Code.app");
    const appRoot = path.join(bundle, "Contents", "Resources", "app");
    const executable = makeExecutable(path.join(bundle, "Contents", "MacOS", "Code"));
    const cli = makeExecutable(path.join(appRoot, "bin", "code"));
    await assert.rejects(
      prepareCodePaths({
        platform: "linux",
        applicationsDirectory,
        profile: { mode: "local" },
      }),
      /supported only on macOS/,
    );
    const discovered = discoverLocalCodePaths({
      platform: "darwin",
      applicationsDirectory,
      spawnSync(command, arguments_) {
        assert.strictEqual(command, "/bin/sh");
        assert.deepStrictEqual(arguments_, ["-c", "command -v code"]);
        return { status: 1, signal: null, stdout: "", stderr: "" };
      },
    });
    assert.throws(
      () => resolveCodeInstallation({
        vscodeExecutable: discovered.executable,
        vscodeCli: discovered.cli,
        appRoot: discovered.appRoot,
        platform: "darwin",
        spawnSync: () => ({
          status: 0, signal: null, stdout: "1.135.0\nfixture-commit\narm64\n",
        }),
        root: applicationsDirectory,
        environment: {},
        vscodeVersion: "1.134.0",
      }),
      /must report exact version 1\.134\.0/,
    );
    assert.strictEqual(executable, discovered.executable);
    assert.strictEqual(cli, discovered.cli);
    const emptyApplicationsDirectory = temporaryRoot("cloudsmith-empty-applications-");
    assert.throws(
      () => discoverLocalCodePaths({
        platform: "darwin",
        applicationsDirectory: emptyApplicationsDirectory,
        spawnSync: () => ({ status: 1, signal: null, stdout: "", stderr: "" }),
      }),
      /not found via `command -v code` or the standard macOS app bundle/,
    );
  });

  test("VSIX install is forced into isolated dirs and exact listing is required", () => {
    const root = temporaryRoot();
    const profile = {
      userDataDir: path.join(root, "settings"),
      extensionsDir: path.join(root, "extensions"),
    };
    const calls = [];
    const options = {
      root,
      environment: {},
      profile,
      code: { cli: path.join(root, "code") },
      extension: { id: "Cloudsmith.cloudsmith-vsc", version: "2.3.0" },
      vsixPath: path.join(root, "candidate.vsix"),
      spawnSync(command, arguments_) {
        calls.push({ command, arguments_ });
        return {
          status: 0,
          signal: null,
          stdout: arguments_.includes("--list-extensions")
            ? "cloudsmith.cloudsmith-vsc@2.3.0\n"
            : "",
          stderr: "",
        };
      },
    };
    assert.deepStrictEqual(installAndVerifyCandidate(options), {
      status: "passed", id: "Cloudsmith.cloudsmith-vsc", version: "2.3.0",
    });
    assert.ok(calls[0].arguments_.includes("--force"));
    assert.ok(calls[0].arguments_.includes("--install-extension"));
    assert.ok(calls.every(call => call.arguments_.includes(profile.userDataDir)));
    assert.ok(calls.every(call => call.arguments_.includes(profile.extensionsDir)));
    assert.ok(calls.every(call => !call.arguments_.some(value => value.includes("extensionDevelopmentPath"))));
  });

  test("candidate receipt is fresh, source-bound, VSIX-only, and omits cleanup capability", async () => {
    const root = temporaryRoot();
    writeCandidateRepository(root);
    const temporaryParent = temporaryRoot("cloudsmith-ci-parent-");
    const executable = makeExecutable(path.join(
      root, "Visual Studio Code.app", "Contents", "MacOS", "Electron"
    ));
    const cli = makeExecutable(path.join(
      root, "Visual Studio Code.app", "Contents", "Resources", "app", "bin", "code"
    ));
    const receiptPath = path.join(root, ".quality", "qualification", "candidate.json");
    fs.mkdirSync(path.dirname(receiptPath), { recursive: true });
    fs.writeFileSync(receiptPath, "{\"stale\":true}\n");
    const artifactRelative = "out/development/cloudsmith-vsc-2.3.0.vsix";
    const artifact = path.join(root, artifactRelative);
    fs.mkdirSync(path.dirname(artifact), { recursive: true });
    for (const suffix of ["", ".sha256", ".provenance.json"]) {
      fs.writeFileSync(`${artifact}${suffix}`, "stale");
    }
    const source = { sha: "a".repeat(40), fingerprint: "b".repeat(64) };
    const repository = {
      branch: "test/release-quality-harness",
      dirty: true,
      status: "dirty",
    };
    const capturedAt = "2026-08-27T00:00:00.000Z";
    const verifiedBytes = Buffer.from("verified-vsix");
    const verifiedSha = crypto.createHash("sha256").update(verifiedBytes).digest("hex");
    let polishPassed = false;
    const spawn = (command, arguments_, options) => {
      assert.strictEqual(options.env?.CLOUDSMITH_API_KEY, undefined);
      if (command === "git") {
        if (arguments_[0] === "branch") {
          return { status: 0, signal: null, stdout: `${repository.branch}\n`, stderr: "" };
        }
        if (arguments_[0] === "status") {
          return { status: 0, signal: null, stdout: " M bounded-fixture.js\n", stderr: "" };
        }
        return { status: 0, signal: null, stdout: "", stderr: "" };
      }
      if (new Set(["npm", "npm.cmd"]).has(path.basename(command))) {
        if (JSON.stringify(arguments_) === JSON.stringify(["run", "verify:polish"])) {
          polishPassed = true;
          return { status: 0, signal: null, stdout: "polish passed\n", stderr: "" };
        }
        assert.strictEqual(polishPassed, true, "polish must pass before packaging");
        assert.deepStrictEqual(arguments_.slice(0, 4), ["run", "package", "--", "--github-output"]);
        assert.strictEqual(fs.existsSync(artifact), false, "stale artifact must be invalidated");
        fs.writeFileSync(artifact, verifiedBytes);
        fs.writeFileSync(`${artifact}.sha256`, "verified-sidecar");
        fs.writeFileSync(`${artifact}.provenance.json`, JSON.stringify({
          sourceClean: false,
          sourceSha: source.sha,
        }));
        fs.appendFileSync(
          arguments_[4],
          `vsix_path=${artifactRelative}\nchecksum_path=${artifactRelative}.sha256\nprovenance_path=${artifactRelative}.provenance.json\n`,
        );
        return { status: 0, signal: null, stdout: "packaged\n", stderr: "" };
      }
      assert.strictEqual(command, cli);
      if (arguments_.includes("--version")) {
        return { status: 0, signal: null, stdout: "1.131.0\nfixture\narm64\n", stderr: "" };
      }
      if (arguments_.includes("--list-extensions")) {
        return {
          status: 0, signal: null,
          stdout: "cloudsmith.cloudsmith-vsc@2.3.0\n", stderr: "",
        };
      }
      assert.ok(arguments_.includes("--force"));
      assert.ok(arguments_.includes("--install-extension"));
      const installPath = arguments_[arguments_.indexOf("--install-extension") + 1];
      assert.notStrictEqual(installPath, artifact);
      assert.deepStrictEqual(fs.readFileSync(installPath), verifiedBytes);
      return { status: 0, signal: null, stdout: "installed\n", stderr: "" };
    };
    const result = await prepareQualificationCandidate({
      root,
      mode: "ci",
      temporaryParent,
      platform: "darwin",
      prepareCode({ profile, vscodeVersion, environment }) {
        assert.strictEqual(profile.mode, "ci");
        assert.strictEqual(profile.userDataDir, path.join(profile.root, "settings"));
        assert.strictEqual(profile.cleanupProof, undefined);
        assert.strictEqual(vscodeVersion, "1.131.0");
        assert.strictEqual(environment.CLOUDSMITH_API_KEY, undefined);
        return { executable, cli };
      },
      environment: { PATH: process.env.PATH || "", CLOUDSMITH_API_KEY: "must-not-pass" },
      adapters: {
        spawnSync: spawn,
        sourceIdentity: () => {
          assert.strictEqual(polishPassed, true, "polish must pass before source capture");
          return source;
        },
        now: () => new Date(capturedAt),
        verifyVsix: async (file, verificationOptions) => {
          assert.strictEqual(file, artifact);
          assert.strictEqual(verificationOptions.sourceSha, null);
          return {
            buffer: verifiedBytes,
            sha256: verifiedSha,
            archiveBytes: verifiedBytes.length,
            entryCount: 7,
            manifest: { name: "cloudsmith-vsc", publisher: "Cloudsmith", version: "2.3.0" },
          };
        },
        validateSidecars: (file, verification, sidecarOptions) => {
          assert.strictEqual(file, artifact);
          assert.strictEqual(verification.sha256, verifiedSha);
          assert.strictEqual(sidecarOptions.expectedSourceSha, source.sha);
          return { provenance: {} };
        },
      },
    });
    const persisted = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
    const { fingerprint: persistedFingerprint, ...withoutFingerprint } = persisted;
    assert.strictEqual(persistedFingerprint, fingerprint(withoutFingerprint));
    assert.strictEqual(persisted.schemaVersion, 2);
    assert.strictEqual(persisted.capturedAt, capturedAt);
    assert.deepStrictEqual(persisted.source, source);
    assert.deepStrictEqual(persisted.repository, repository);
    assert.strictEqual(persisted.artifact.vsixPath, artifactRelative);
    assert.strictEqual(persisted.artifact.absoluteVsixPath, artifact);
    assert.strictEqual(persisted.artifact.sourceSha, source.sha);
    assert.strictEqual(persisted.artifact.sourceFingerprint, source.fingerprint);
    assert.strictEqual(persisted.extension.id, "Cloudsmith.cloudsmith-vsc");
    assert.strictEqual(persisted.installation.version, "2.3.0");
    assert.deepStrictEqual(persisted.launch, { status: "not-requested", developmentPath: false });
    assert.strictEqual(persisted.profile.mode, "ci");
    assert.strictEqual(persisted.profile.persistent, false);
    assert.strictEqual(persisted.profile.testResourcesDir, persisted.profile.root);
    assert.strictEqual(persisted.profile.userDataDir, path.join(persisted.profile.root, "settings"));
    assert.strictEqual(persisted.profile.extensionsDir, path.join(persisted.profile.root, "extensions"));
    assert.strictEqual(JSON.stringify(persisted).includes("cleanupProof"), false);
    assert.strictEqual(JSON.stringify(persisted).includes("homeDir"), false);
    assert.strictEqual(result.receipt.fingerprint, persisted.fingerprint);
    assert.strictEqual(result.profile.executable, executable);
    assert.strictEqual(result.profile.cli, cli);
    assert.strictEqual(result.profile.vscodeVersion, "1.131.0");
    assert.strictEqual(result.cleanup(), true);
    assert.strictEqual(fs.existsSync(result.profile.root), false);
  });

  test("post-cleanup polish failure stops before source capture and packaging", async () => {
    const root = temporaryRoot();
    const temporaryParent = temporaryRoot("cloudsmith-ci-parent-");
    const receipt = path.join(root, ".quality", "qualification", "candidate.json");
    fs.mkdirSync(path.dirname(receipt), { recursive: true });
    fs.writeFileSync(receipt, "{\"stale\":true}\n");
    let sourceCaptures = 0;
    let packageCalls = 0;
    await assert.rejects(
      prepareQualificationCandidate({
        root,
        mode: "ci",
        temporaryParent,
        environment: { PATH: process.env.PATH || "" },
        adapters: {
          sourceIdentity: () => {
            sourceCaptures += 1;
            return { sha: "a".repeat(40), fingerprint: "b".repeat(64) };
          },
          spawnSync(command, arguments_) {
            if (command === "git") {
              return { status: 0, signal: null, stdout: "", stderr: "" };
            }
            if (new Set(["npm", "npm.cmd"]).has(path.basename(command))) {
              if (arguments_.includes("package")) packageCalls += 1;
              return { status: 1, signal: null, stdout: "", stderr: "" };
            }
            throw new Error("unexpected command");
          },
        },
      }),
      /Post-cleanup polish verification failed/,
    );
    assert.strictEqual(sourceCaptures, 0);
    assert.strictEqual(packageCalls, 0);
    assert.strictEqual(fs.existsSync(receipt), false);
  });

  test("stale candidate receipt is invalidated before argument failure", async () => {
    const root = temporaryRoot();
    const receipt = path.join(root, ".quality", "qualification", "candidate.json");
    fs.mkdirSync(path.dirname(receipt), { recursive: true });
    fs.writeFileSync(receipt, "{\"stale\":true}\n");
    await assert.rejects(
      prepareQualificationCandidate({ root, mode: "unsupported" }),
      /must be local or ci/,
    );
    assert.strictEqual(fs.existsSync(receipt), false);
  });
});

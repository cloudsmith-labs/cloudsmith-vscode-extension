// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const crypto = require("crypto");
const { EventEmitter } = require("events");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const { exactFileIdentity } = require("../scripts/quality/candidate-binding");
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
  createVerifiedInstallArtifact,
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
  verifyQualificationArtifact,
  verifyQualificationSidecars,
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

function packageOutputFixture() {
  const root = temporaryRoot("cloudsmith-package-output-");
  const relative = "out/development/cloudsmith-vsc-2.3.0.vsix";
  fs.mkdirSync(path.join(root, "out", "development"), { recursive: true });
  for (const suffix of ["", ".sha256", ".provenance.json"]) {
    fs.writeFileSync(path.join(root, `${relative}${suffix}`), "synthetic fixture bytes\n");
  }
  const bytes = Buffer.from(
    `vsix_path=${relative}\nchecksum_path=${relative}.sha256\n`
      + `provenance_path=${relative}.provenance.json\n`,
    "utf8",
  );
  const output = path.join(root, "package-output");
  fs.writeFileSync(output, bytes);
  return { bytes, output, relative, root };
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

  test("local reset fails closed on final persistent-root substitution", () => {
    const parent = temporaryRoot("cloudsmith-local-profile-reset-swap-");
    const home = path.join(parent, "home");
    fs.mkdirSync(home, { mode: 0o700 });
    const profile = prepareLocalQualificationProfile({ homeDirectory: home });
    fs.writeFileSync(path.join(profile.userDataDir, "owned.txt"), "synthetic owned bytes\n");
    const victim = path.join(home, "synthetic-local-victim");
    fs.mkdirSync(victim, { mode: 0o700 });
    fs.writeFileSync(path.join(victim, "preserve.txt"), "synthetic victim survives\n");
    const displaced = path.join(home, "owned-profile-displaced");
    const originalRename = fs.renameSync;
    const originalRmdir = fs.rmdirSync;
    let substituted = false;
    try {
      fs.rmdirSync = function interceptFinalLocalProfileRemoval(target, options) {
        if (!substituted && target === profile.root) {
          originalRename.call(fs, target, displaced);
          originalRename.call(fs, victim, target);
          substituted = true;
        }
        return originalRmdir.call(fs, target, options);
      };
      assert.throws(
        () => resetLocalQualificationProfile({ homeDirectory: home }),
        /unsafe or changed profile tree/u,
      );
    } finally {
      fs.rmdirSync = originalRmdir;
    }
    assert.strictEqual(substituted, true);
    assert.strictEqual(fs.existsSync(displaced), true);
    assert.strictEqual(
      fs.readFileSync(path.join(profile.root, "preserve.txt"), "utf8"),
      "synthetic victim survives\n",
    );
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

  test("CI profile cleanup fails closed on final root substitution", () => {
    const parent = temporaryRoot("cloudsmith-ci-profile-cleanup-swap-");
    const profile = createCiQualificationProfile({ temporaryParent: parent });
    fs.mkdirSync(path.join(profile.userDataDir, "nested"));
    fs.writeFileSync(
      path.join(profile.userDataDir, "nested", "owned.txt"),
      "synthetic owned profile bytes\n",
    );
    const victim = path.join(parent, "synthetic-victim");
    fs.mkdirSync(victim, { mode: 0o700 });
    fs.writeFileSync(path.join(victim, "preserve.txt"), "synthetic victim survives\n");
    const displaced = path.join(parent, "owned-profile-displaced");
    const originalRename = fs.renameSync;
    const originalRmdir = fs.rmdirSync;
    let substituted = false;
    try {
      fs.rmdirSync = function interceptFinalProfileRemoval(target, options) {
        if (!substituted && target === profile.root) {
          originalRename.call(fs, target, displaced);
          originalRename.call(fs, victim, target);
          substituted = true;
        }
        return originalRmdir.call(fs, target, options);
      };
      assert.throws(
        () => cleanupCiQualificationProfile(profile),
        /unsafe or changed profile tree/u,
      );
    } finally {
      fs.rmdirSync = originalRmdir;
    }
    assert.strictEqual(substituted, true);
    assert.strictEqual(fs.existsSync(displaced), true);
    assert.strictEqual(
      fs.readFileSync(path.join(profile.root, "preserve.txt"), "utf8"),
      "synthetic victim survives\n",
    );
  });

  test("CI profile cleanup rejects creator type and identity drift", () => {
    const parent = temporaryRoot("cloudsmith-ci-profile-cleanup-drift-");
    const profile = createCiQualificationProfile({ temporaryParent: parent });
    const displacedSettings = path.join(parent, "owned-settings-displaced");
    fs.renameSync(profile.userDataDir, displacedSettings);
    fs.writeFileSync(profile.userDataDir, "synthetic wrong-type bytes\n");
    assert.throws(
      () => cleanupCiQualificationProfile(profile),
      /unsafe or changed profile tree/u,
    );
    assert.strictEqual(
      fs.readFileSync(profile.userDataDir, "utf8"),
      "synthetic wrong-type bytes\n",
    );
    fs.unlinkSync(profile.userDataDir);

    fs.mkdirSync(profile.userDataDir, { mode: 0o700 });
    fs.writeFileSync(
      path.join(profile.userDataDir, "preserve.txt"),
      "synthetic replacement survives\n",
    );
    assert.throws(
      () => cleanupCiQualificationProfile(profile),
      /unsafe or changed profile tree/u,
    );
    assert.strictEqual(
      fs.readFileSync(path.join(profile.userDataDir, "preserve.txt"), "utf8"),
      "synthetic replacement survives\n",
    );
    fs.rmSync(profile.userDataDir, { recursive: true, force: true });
    fs.renameSync(displacedSettings, profile.userDataDir);
    assert.strictEqual(cleanupCiQualificationProfile(profile), true);
  });

  test("verified install cleanup is exact and fails closed on final root substitution", () => {
    const parent = temporaryRoot("cloudsmith-install-cleanup-swap-");
    const bytes = Buffer.from("synthetic verified VSIX bytes\n", "utf8");
    const verification = Object.freeze({
      archiveBytes: bytes.length,
      buffer: bytes,
      sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    });
    const exact = createVerifiedInstallArtifact(verification, { temporaryParent: parent });
    const exactRoot = path.dirname(exact.file);
    exact.cleanup();
    assert.strictEqual(fs.existsSync(exactRoot), false);

    const swapped = createVerifiedInstallArtifact(verification, { temporaryParent: parent });
    const swappedRoot = path.dirname(swapped.file);
    const victim = path.join(parent, "synthetic-install-victim");
    fs.mkdirSync(victim, { mode: 0o700 });
    fs.writeFileSync(path.join(victim, "preserve.txt"), "synthetic victim survives\n");
    const displaced = path.join(parent, "owned-install-displaced");
    const originalRename = fs.renameSync;
    const originalRmdir = fs.rmdirSync;
    let substituted = false;
    try {
      fs.rmdirSync = function interceptFinalInstallRemoval(target, options) {
        if (!substituted && target === swappedRoot) {
          originalRename.call(fs, target, displaced);
          originalRename.call(fs, victim, target);
          substituted = true;
        }
        return originalRmdir.call(fs, target, options);
      };
      assert.throws(
        () => swapped.cleanup(),
        /unsafe or changed tree/u,
      );
    } finally {
      fs.rmdirSync = originalRmdir;
    }
    assert.strictEqual(substituted, true);
    assert.strictEqual(fs.existsSync(displaced), true);
    assert.strictEqual(
      fs.readFileSync(path.join(swappedRoot, "preserve.txt"), "utf8"),
      "synthetic victim survives\n",
    );
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
    const settingsIdentity = fs.lstatSync(profile.userDataDir);
    assert.strictEqual(resetCiQualificationUserData(profile), profile.userDataDir);
    assert.deepStrictEqual(fs.readdirSync(profile.userDataDir), []);
    const currentSettings = fs.lstatSync(profile.userDataDir);
    assert.strictEqual(currentSettings.dev, settingsIdentity.dev);
    assert.strictEqual(currentSettings.ino, settingsIdentity.ino);
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

  test("CI user-data reset never adopts replaced creator-owned siblings", () => {
    for (const name of ["home", "extensions", PROFILE_MARKER]) {
      const parent = temporaryRoot(`cloudsmith-ci-reset-${name}-swap-`);
      const profile = createCiQualificationProfile({ temporaryParent: parent });
      const target = path.join(profile.root, name);
      const displaced = path.join(parent, `displaced-${name}`);
      const settingsIdentity = fs.lstatSync(profile.userDataDir);
      fs.renameSync(target, displaced);
      if (name === PROFILE_MARKER) {
        fs.copyFileSync(displaced, target);
        if (process.platform !== "win32") fs.chmodSync(target, 0o600);
      } else {
        fs.mkdirSync(target, { mode: 0o700 });
      }

      assert.throws(
        () => resetCiQualificationUserData(profile),
        /refuses a changed profile entry/u,
      );
      const currentSettings = fs.lstatSync(profile.userDataDir);
      assert.strictEqual(currentSettings.dev, settingsIdentity.dev);
      assert.strictEqual(currentSettings.ino, settingsIdentity.ino);
      assert.strictEqual(fs.existsSync(displaced), true);
      assert.strictEqual(fs.existsSync(target), true);
    }
  });

  test("CI probe user-data reset fails closed on final settings substitution", () => {
    const parent = temporaryRoot("cloudsmith-ci-settings-reset-swap-");
    const profile = createCiQualificationProfile({ temporaryParent: parent });
    fs.mkdirSync(path.join(profile.userDataDir, "nested"));
    const owned = path.join(profile.userDataDir, "nested", "owned.txt");
    fs.writeFileSync(
      owned,
      "synthetic owned settings bytes\n",
    );
    const victim = path.join(parent, "synthetic-settings-victim");
    fs.mkdirSync(victim, { mode: 0o700 });
    fs.writeFileSync(path.join(victim, "preserve.txt"), "synthetic victim survives\n");
    const displaced = path.join(parent, "owned-settings-displaced");
    const originalRename = fs.renameSync;
    const originalUnlink = fs.unlinkSync;
    let substituted = false;
    try {
      fs.unlinkSync = function interceptSettingsChildRemoval(target) {
        if (!substituted && target === owned) {
          originalRename.call(fs, profile.userDataDir, displaced);
          originalRename.call(fs, victim, profile.userDataDir);
          substituted = true;
        }
        return originalUnlink.call(fs, target);
      };
      assert.throws(
        () => resetCiQualificationUserData(profile),
        /unsafe or changed user-data tree/u,
      );
    } finally {
      fs.unlinkSync = originalUnlink;
    }
    assert.strictEqual(substituted, true);
    assert.strictEqual(fs.existsSync(displaced), true);
    assert.strictEqual(
      fs.readFileSync(path.join(profile.userDataDir, "preserve.txt"), "utf8"),
      "synthetic victim survives\n",
    );
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

  test("actual local preparation cold-launches with host identity only at the final boundary", async () => {
    const root = temporaryRoot();
    writeCandidateRepository(root);
    const profileOwnerHome = temporaryRoot("cloudsmith-profile-owner-");
    const hostHome = temporaryRoot("cloudsmith-os-account-home-");
    const profileRoot = path.join(profileOwnerHome, LOCAL_PROFILE_BASENAME);
    const syntheticHome = path.join(profileRoot, "home");
    const executable = makeExecutable(path.join(
      root, "Visual Studio Code.app", "Contents", "MacOS", "Code"
    ));
    const cli = makeExecutable(path.join(
      root, "Visual Studio Code.app", "Contents", "Resources", "app", "bin", "code"
    ));
    const artifactRelative = "out/development/cloudsmith-vsc-2.3.0.vsix";
    const artifact = path.join(root, artifactRelative);
    const verifiedBytes = Buffer.from("verified-local-vsix");
    const verifiedSha = crypto.createHash("sha256").update(verifiedBytes).digest("hex");
    const source = { sha: "a".repeat(40), fingerprint: "b".repeat(64) };
    let polishPassed = false;
    let artifactVerificationCount = 0;
    const prelaunchEnvironments = [];
    const spawnSyncFixture = (command, arguments_, options) => {
      prelaunchEnvironments.push(options.env);
      assert.strictEqual(options.env.HOME, syntheticHome);
      assert.strictEqual(options.env.USERPROFILE, syntheticHome);
      assert.strictEqual(options.env.CLOUDSMITH_API_KEY, undefined);
      if (command === "git") {
        if (arguments_[0] === "branch") {
          return {
            status: 0,
            signal: null,
            stdout: "test/release-quality-harness\n",
            stderr: "",
          };
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
        assert.strictEqual(polishPassed, true);
        fs.mkdirSync(path.dirname(artifact), { recursive: true });
        fs.writeFileSync(artifact, verifiedBytes);
        fs.writeFileSync(`${artifact}.sha256`, "verified-sidecar");
        fs.writeFileSync(`${artifact}.provenance.json`, JSON.stringify({
          sourceClean: false,
          sourceSha: source.sha,
        }));
        fs.appendFileSync(
          arguments_[4],
          `vsix_path=${artifactRelative}\nchecksum_path=${artifactRelative}.sha256\n`
            + `provenance_path=${artifactRelative}.provenance.json\n`,
        );
        return { status: 0, signal: null, stdout: "packaged\n", stderr: "" };
      }
      assert.strictEqual(command, cli);
      if (arguments_.includes("--version")) {
        return { status: 0, signal: null, stdout: "1.134.0\nfixture\narm64\n", stderr: "" };
      }
      if (arguments_.includes("--list-extensions")) {
        return {
          status: 0,
          signal: null,
          stdout: "cloudsmith.cloudsmith-vsc@2.3.0\n",
          stderr: "",
        };
      }
      assert.ok(arguments_.includes("--force"));
      assert.ok(arguments_.includes("--install-extension"));
      return { status: 0, signal: null, stdout: "installed\n", stderr: "" };
    };
    const launchedChild = new EventEmitter();
    launchedChild.exitCode = null;
    launchedChild.signalCode = null;
    launchedChild.unrefCalled = false;
    launchedChild.unref = () => { launchedChild.unrefCalled = true; };
    const forwardedChild = new EventEmitter();
    forwardedChild.exitCode = null;
    forwardedChild.signalCode = null;
    forwardedChild.unrefCalled = false;
    forwardedChild.unref = () => { forwardedChild.unrefCalled = true; };
    let launchCall = null;
    let launchAttempts = 0;
    const candidateOptions = {
      root,
      mode: "local",
      launch: true,
      homeDirectory: profileOwnerHome,
      vscodeExecutable: executable,
      vscodeCli: cli,
      platform: "darwin",
      environment: {
        PATH: process.env.PATH || "",
        HOME: "/ambient/home/must-not-own-keyring",
        CLOUDSMITH_API_KEY: "must-not-pass",
      },
      adapters: {
        spawnSync: spawnSyncFixture,
        spawn(command, arguments_, options) {
          assert.strictEqual(artifactVerificationCount, (launchAttempts + 1) * 2);
          launchCall = { command, arguments_, options, environment: options.env };
          launchAttempts += 1;
          if (launchAttempts === 1) {
            queueMicrotask(() => {
              forwardedChild.exitCode = 0;
              forwardedChild.emit("exit", 0, null);
            });
            return forwardedChild;
          }
          return launchedChild;
        },
        userInfo: () => ({ homedir: hostHome }),
        launchStabilizationMs: 0,
        sourceIdentity: () => source,
        now: () => new Date("2026-08-28T00:00:00.000Z"),
        verifyVsix: async file => {
          artifactVerificationCount += 1;
          return {
            buffer: verifiedBytes,
            sha256: verifiedSha,
            archiveBytes: verifiedBytes.length,
            artifactIdentity: exactFileIdentity(fs.lstatSync(file, { bigint: true })),
            entryCount: 7,
            manifest: { name: "cloudsmith-vsc", publisher: "Cloudsmith", version: "2.3.0" },
          };
        },
        validateSidecars: (file, verification) => ({
          artifactIdentity: verification.artifactIdentity,
          checksumIdentity: exactFileIdentity(fs.lstatSync(`${file}.sha256`, { bigint: true })),
          provenance: {},
          provenanceIdentity: exactFileIdentity(
            fs.lstatSync(`${file}.provenance.json`, { bigint: true }),
          ),
        }),
      },
    };

    await assert.rejects(
      prepareQualificationCandidate(candidateOptions),
      /cold launch exited before owning the dedicated profile/,
    );
    assert.strictEqual(forwardedChild.unrefCalled, false);
    assert.strictEqual(fs.existsSync(path.join(
      root, ".quality", "qualification", "candidate.json"
    )), false);

    const result = await prepareQualificationCandidate(candidateOptions);

    assert.ok(prelaunchEnvironments.length > 0);
    assert.strictEqual(launchCall.command, executable);
    assert.strictEqual(launchCall.environment.HOME, hostHome);
    assert.strictEqual(launchCall.environment.USERPROFILE, hostHome);
    assert.strictEqual(launchCall.environment.CLOUDSMITH_API_KEY, undefined);
    assert.strictEqual(launchCall.options.cwd, root);
    assert.strictEqual(launchCall.options.detached, true);
    assert.strictEqual(launchCall.options.stdio, "ignore");
    assert.strictEqual(launchCall.options.windowsHide, true);
    for (const [name, expected] of Object.entries({
      XDG_CONFIG_HOME: path.join(syntheticHome, ".config"),
      XDG_CACHE_HOME: path.join(syntheticHome, ".cache"),
      XDG_DATA_HOME: path.join(syntheticHome, ".local", "share"),
      XDG_STATE_HOME: path.join(syntheticHome, ".local", "state"),
      APPDATA: path.join(syntheticHome, "AppData", "Roaming"),
      LOCALAPPDATA: path.join(syntheticHome, "AppData", "Local"),
    })) {
      assert.strictEqual(launchCall.environment[name], expected);
    }
    assert.deepStrictEqual(launchCall.arguments_, [...qualificationLaunchArguments(result.profile)]);
    assert.strictEqual(launchCall.arguments_.some(value => value.includes("password-store")), false);
    assert.strictEqual(launchedChild.unrefCalled, true);
    assert.strictEqual(launchAttempts, 2);
    assert.deepStrictEqual(result.receipt.launch, {
      status: "command-accepted",
      developmentPath: false,
    });
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

  test("package output stays bound to one pathname inode through parsing", () => {
    const fixture = packageOutputFixture();
    const displaced = `${fixture.output}.opened`;
    let swapped = false;
    const fileSystem = Object.create(fs);
    fileSystem.readSync = (...arguments_) => {
      const bytesRead = fs.readSync(...arguments_);
      if (!swapped) {
        fs.renameSync(fixture.output, displaced);
        fs.writeFileSync(fixture.output, fixture.bytes);
        swapped = true;
      }
      return bytesRead;
    };
    assert.throws(
      () => parsePackageOutput(
        fixture.output,
        fixture.root,
        "cloudsmith-vsc",
        "2.3.0",
        { fileSystem },
      ),
      /exact bounded single-link file/u,
    );
    assert.strictEqual(swapped, true);
  });

  test("package output rejects symbolic and multiply-linked files", () => {
    for (const kind of ["symbolic", "hard"]) {
      const fixture = packageOutputFixture();
      const source = `${fixture.output}.source`;
      fs.renameSync(fixture.output, source);
      if (kind === "symbolic") fs.symlinkSync(source, fixture.output);
      else fs.linkSync(source, fixture.output);
      assert.throws(
        () => parsePackageOutput(
          fixture.output,
          fixture.root,
          "cloudsmith-vsc",
          "2.3.0",
        ),
        /exact bounded single-link file/u,
        `${kind} package output must fail closed`,
      );
    }
  });

  test("package output opens a post-check FIFO nonblocking and fails closed", function fifoTest() {
    if (process.platform === "win32") this.skip();
    const fixture = packageOutputFixture();
    const displaced = `${fixture.output}.regular`;
    let substituted = false;
    const fileSystem = Object.create(fs);
    fileSystem.openSync = (target, flags) => {
      if (!substituted && target === fixture.output) {
        fs.renameSync(fixture.output, displaced);
        const created = spawnSync("mkfifo", [fixture.output]);
        assert.strictEqual(created.status, 0);
        substituted = true;
      }
      return fs.openSync(target, flags);
    };
    assert.throws(
      () => parsePackageOutput(
        fixture.output,
        fixture.root,
        "cloudsmith-vsc",
        "2.3.0",
        { fileSystem },
      ),
      /exact bounded single-link file/u,
    );
    assert.strictEqual(substituted, true);
  });

  test("package output detects growth beyond its opened descriptor size", () => {
    const fixture = packageOutputFixture();
    let grew = false;
    const fileSystem = Object.create(fs);
    fileSystem.readSync = (...arguments_) => {
      const bytesRead = fs.readSync(...arguments_);
      if (!grew) {
        fs.appendFileSync(fixture.output, "\n");
        grew = true;
      }
      return bytesRead;
    };
    assert.throws(
      () => parsePackageOutput(
        fixture.output,
        fixture.root,
        "cloudsmith-vsc",
        "2.3.0",
        { fileSystem },
      ),
      /exact bounded single-link file/u,
    );
    assert.strictEqual(grew, true);
  });

  test("package output enforces its byte bound before opening", () => {
    const fixture = packageOutputFixture();
    let opened = false;
    const fileSystem = Object.create(fs);
    fileSystem.lstatSync = (target, options) => {
      const stat = fs.lstatSync(target, options);
      if (target === fixture.output) stat.size = BigInt(16 * 1024 + 1);
      return stat;
    };
    fileSystem.openSync = (...arguments_) => {
      opened = true;
      return fs.openSync(...arguments_);
    };
    assert.throws(
      () => parsePackageOutput(
        fixture.output,
        fixture.root,
        "cloudsmith-vsc",
        "2.3.0",
        { fileSystem },
      ),
      /exact bounded single-link file/u,
    );
    assert.strictEqual(opened, false);
  });

  test("injected artifact verifier rejects identityless and forged results", async () => {
    const fixture = packageOutputFixture();
    const artifact = path.join(fixture.root, fixture.relative);
    const buffer = fs.readFileSync(artifact);
    const sha256 = crypto.createHash("sha256").update(buffer).digest("hex");
    const base = {
      archiveBytes: buffer.length,
      buffer,
      entryCount: 1,
      manifest: { name: "cloudsmith-vsc", publisher: "Cloudsmith", version: "2.3.0" },
      sha256,
      totalUncompressedBytes: buffer.length,
    };
    await assert.rejects(
      verifyQualificationArtifact(artifact, {}, async () => ({ ...base })),
      /descriptor-proven artifact identity/u,
    );
    const forgedIdentity = exactFileIdentity(
      fs.lstatSync(`${artifact}.sha256`, { bigint: true }),
    );
    await assert.rejects(
      verifyQualificationArtifact(
        artifact,
        {},
        async () => ({ ...base, artifactIdentity: forgedIdentity }),
      ),
      /descriptor-proven artifact identity/u,
    );
  });

  test("injected sidecar verifier rejects identityless and forged results", () => {
    const fixture = packageOutputFixture();
    const artifact = path.join(fixture.root, fixture.relative);
    const buffer = fs.readFileSync(artifact);
    const verification = Object.freeze({
      archiveBytes: buffer.length,
      artifactIdentity: exactFileIdentity(fs.lstatSync(artifact, { bigint: true })),
      buffer,
      entryCount: 1,
      manifest: { name: "cloudsmith-vsc", publisher: "Cloudsmith", version: "2.3.0" },
      sha256: crypto.createHash("sha256").update(buffer).digest("hex"),
      totalUncompressedBytes: buffer.length,
    });
    assert.throws(
      () => verifyQualificationSidecars(artifact, verification, {}, () => ({})),
      /descriptor-proven identities/u,
    );
    assert.throws(
      () => verifyQualificationSidecars(artifact, verification, {}, () => ({
        artifactIdentity: verification.artifactIdentity,
        checksumIdentity: verification.artifactIdentity,
        provenanceIdentity: verification.artifactIdentity,
      })),
      /descriptor-proven identities/u,
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
    const ciLaunchedChild = new EventEmitter();
    ciLaunchedChild.exitCode = null;
    ciLaunchedChild.signalCode = null;
    ciLaunchedChild.unref = () => {};
    let ciLaunchCall = null;
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
      launch: true,
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
        spawn(command, arguments_, options) {
          ciLaunchCall = { command, arguments_, environment: options.env };
          return ciLaunchedChild;
        },
        userInfo: () => { throw new Error("CI launch must not query OS account identity"); },
        launchStabilizationMs: 0,
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
            artifactIdentity: exactFileIdentity(fs.lstatSync(file, { bigint: true })),
            entryCount: 7,
            manifest: { name: "cloudsmith-vsc", publisher: "Cloudsmith", version: "2.3.0" },
          };
        },
        validateSidecars: (file, verification, sidecarOptions) => {
          assert.strictEqual(file, artifact);
          assert.strictEqual(verification.sha256, verifiedSha);
          assert.strictEqual(sidecarOptions.expectedSourceSha, source.sha);
          return {
            artifactIdentity: verification.artifactIdentity,
            checksumIdentity: exactFileIdentity(fs.lstatSync(`${file}.sha256`, { bigint: true })),
            provenance: {},
            provenanceIdentity: exactFileIdentity(
              fs.lstatSync(`${file}.provenance.json`, { bigint: true }),
            ),
          };
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
    assert.deepStrictEqual(persisted.launch, {
      status: "command-accepted",
      developmentPath: false,
    });
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
    assert.strictEqual(ciLaunchCall.command, executable);
    assert.strictEqual(ciLaunchCall.environment.HOME, path.join(result.profile.root, "home"));
    assert.strictEqual(
      ciLaunchCall.environment.USERPROFILE,
      path.join(result.profile.root, "home"),
    );
    assert.deepStrictEqual(ciLaunchCall.arguments_, [
      "--user-data-dir", result.profile.userDataDir,
      "--extensions-dir", result.profile.extensionsDir,
      "--disable-updates", "--skip-welcome", "--skip-release-notes", "--new-window",
    ]);
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

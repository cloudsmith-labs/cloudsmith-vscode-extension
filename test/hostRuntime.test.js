// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const yazl = require("yazl");
const {
  exactFileIdentity,
} = require("../scripts/quality/candidate-binding");
const {
  cleanupCiQualificationProfile,
  createCiQualificationProfile,
} = require("../scripts/quality/qualification-profile");
const {
  scanVsix,
} = require("../scripts/quality/secret-scan");
const {
  packageBuildDirectoryIdentity,
  removePackageBuildDirectory,
} = require("../scripts/release/package-vsix");

function writeZip(file, entries) {
  return new Promise((resolve, reject) => {
    const archive = new yazl.ZipFile();
    const output = fs.createWriteStream(file, { flags: "wx", mode: 0o600 });
    output.on("error", reject);
    output.on("close", resolve);
    archive.outputStream.on("error", reject);
    archive.outputStream.pipe(output);
    for (const [name, bytes] of entries) archive.addBuffer(Buffer.from(bytes), name);
    archive.end();
  });
}

suite("native host quality contracts", () => {
  let scratch;

  setup(() => {
    scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-host-test-")));
    if (process.platform !== "win32") fs.chmodSync(scratch, 0o700);
  });

  teardown(() => {
    if (scratch && fs.existsSync(scratch)) fs.rmSync(scratch, { recursive: true });
  });

  test("binds the declared GitHub runner host to the actual Node platform", () => {
    const expectedPlatforms = Object.freeze({
      Linux: "linux",
      macOS: "darwin",
      Windows: "win32",
    });
    if (process.env.GITHUB_ACTIONS === "true") {
      assert.strictEqual(process.platform, expectedPlatforms[process.env.RUNNER_OS]);
    } else {
      assert.ok(new Set(Object.values(expectedPlatforms)).has(process.platform));
    }
  });

  test("creates and exactly cleans a native qualification profile", () => {
    const profile = createCiQualificationProfile();
    assert.strictEqual(fs.realpathSync(profile.root), profile.root);
    assert.strictEqual(fs.lstatSync(profile.root).isDirectory(), true);
    assert.strictEqual(fs.lstatSync(profile.root).isSymbolicLink(), false);
    assert.strictEqual(fs.realpathSync(profile.userDataDir), profile.userDataDir);
    assert.strictEqual(fs.realpathSync(profile.extensionsDir), profile.extensionsDir);
    if (process.platform === "darwin") {
      const socketPath = path.join(profile.userDataDir, "1.13-main.sock");
      assert.ok(Buffer.byteLength(socketPath, "utf8") <= 103);
    }
    assert.strictEqual(cleanupCiQualificationProfile(profile), true);
    assert.strictEqual(fs.existsSync(profile.root), false);
  });

  test("scans exact VSIX bytes through the host-native descriptor transport", async () => {
    const relativePath = "candidate.vsix";
    const target = path.join(scratch, relativePath);
    const expandedBytes = Buffer.from("host-native scan fixture\n");
    await writeZip(target, [["extension/safe.txt", expandedBytes]]);
    const archiveBytes = fs.readFileSync(target);
    const scans = [];

    const component = await scanVsix(scratch, relativePath, {
      scanWithGitleaks(kind, logicalPath, options) {
        scans.push([kind, logicalPath]);
        if (kind === "dir") {
          if (process.platform === "win32") {
            assert.strictEqual(logicalPath, options.descriptorSourcePath);
            assert.strictEqual(options.extraFileDescriptor, undefined);
            assert.deepStrictEqual(fs.readFileSync(logicalPath), archiveBytes);
          } else {
            assert.strictEqual(Number.isSafeInteger(options.extraFileDescriptor), true);
            assert.deepStrictEqual(
              fs.readFileSync(options.extraFileDescriptor),
              archiveBytes,
            );
          }
        } else {
          assert.strictEqual(kind, "stdin");
          assert.strictEqual(logicalPath, "extension/safe.txt");
          assert.deepStrictEqual(options.input, expandedBytes);
        }
        return [];
      },
    });

    assert.strictEqual(component.status, "scanned");
    assert.strictEqual(component.fileCount, 2);
    assert.deepStrictEqual(component.findings, []);
    assert.strictEqual(scans.length, 2);
  });

  test("removes only an exact native package build tree", () => {
    const buildRoot = fs.realpathSync(fs.mkdtempSync(path.join(scratch, "package-build-")));
    if (process.platform !== "win32") fs.chmodSync(buildRoot, 0o700);
    const identity = packageBuildDirectoryIdentity(buildRoot);
    const entries = ["first.vsix", "second.vsix"].map(name => {
      const target = path.join(buildRoot, name);
      fs.writeFileSync(target, `${name}\n`, { flag: "wx", mode: 0o600 });
      return Object.freeze({
        identity: exactFileIdentity(fs.lstatSync(target, { bigint: true })),
        kind: "file",
        name,
      });
    });

    assert.strictEqual(removePackageBuildDirectory(buildRoot, identity, entries), true);
    assert.strictEqual(fs.existsSync(buildRoot), false);
  });
});

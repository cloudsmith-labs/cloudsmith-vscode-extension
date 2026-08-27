// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  FORBIDDEN_REPORT_FIELDS,
  GITLEAKS_VERSION,
  REPORT_TEMPLATE,
  copyFileIntoSnapshot,
  parseArguments,
  parseSafeReport,
  resultDocument,
  scanWithGitleaks,
  scannerEnvironment,
  validateArchiveEntryPath,
} = require("../scripts/quality/secret-scan");

suite("secret exposure gate", () => {
  let scratch;

  setup(() => {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-secret-gate-test-"));
  });

  teardown(() => {
    fs.rmSync(scratch, { recursive: true, force: true });
  });

  test("defines explicit current, history, artifact, evidence, and all modes", () => {
    assert.deepStrictEqual(parseArguments([]), {
      mode: "current",
      includeLocalEvidence: false,
    });
    assert.deepStrictEqual(parseArguments(["all", "--include-local-evidence"]), {
      mode: "all",
      includeLocalEvidence: true,
    });
    assert.deepStrictEqual(parseArguments(["evidence"]), {
      mode: "evidence",
      includeLocalEvidence: false,
    });
    assert.throws(() => parseArguments(["history", "--include-local-evidence"]));
    assert.throws(() => parseArguments(["unknown"]));
  });

  test("passes only non-credential process environment names to the scanner", () => {
    const environment = scannerEnvironment({
      PATH: "/fixture/bin",
      LANG: "en_US.UTF-8",
      CLOUDSMITH_API_KEY: "non-secret-test-marker",
      ARBITRARY_TOKEN: "non-secret-test-marker",
    });
    assert.deepStrictEqual(environment, {
      PATH: "/fixture/bin",
      LANG: "en_US.UTF-8",
    });
  });

  test("safe report template cannot serialize secret-bearing finding fields", () => {
    const template = fs.readFileSync(path.resolve(__dirname, "..", REPORT_TEMPLATE), "utf8");
    assert.strictEqual(/\$finding\.(?:Secret|Match|Fingerprint|Entropy|Author|Email|Message)\b/u.test(template), false);
    assert.strictEqual(FORBIDDEN_REPORT_FIELDS.test(template), false);
    for (const field of ["RuleID", "File", "StartLine", "EndLine", "Commit"]) {
      assert.match(template, new RegExp(`\\$finding\\.${field}\\b`, "u"));
    }
  });

  test("rejects a scanner report before parsing if a forbidden field appears", () => {
    const reportPath = path.join(scratch, "unsafe.json");
    fs.writeFileSync(reportPath, '[{"Secret":null}]\n', { mode: 0o600 });
    assert.throws(
      () => parseSafeReport(reportPath, { scanRoot: scratch }),
      /forbidden secret-bearing report field/u,
    );
  });

  test("retains only bounded rule and location metadata from a finding", () => {
    const reportPath = path.join(scratch, "safe.json");
    fs.writeFileSync(reportPath, JSON.stringify([{
      ruleId: "fixture-rule",
      file: "quality/example.json",
      startLine: 4,
      endLine: 4,
      commit: "a".repeat(40),
    }]), { mode: 0o600 });
    assert.deepStrictEqual(parseSafeReport(reportPath, { scanRoot: scratch }), [{
      ruleId: "fixture-rule",
      path: "quality/example.json",
      startLine: 4,
      endLine: 4,
      commit: "a".repeat(40),
    }]);
  });

  test("does not propagate scanner stdout or stderr into finding evidence", () => {
    const target = path.join(scratch, "target");
    fs.mkdirSync(target);
    const execute = (_executable, args) => {
      const reportPath = args[args.indexOf("--report-path") + 1];
      fs.writeFileSync(reportPath, JSON.stringify([{
        ruleId: "fixture-rule",
        file: "fixture.txt",
        startLine: 1,
        endLine: 1,
        commit: "",
      }]), { mode: 0o600 });
      return {
        status: 1,
        signal: null,
        error: null,
        stdout: "scanner-output-must-not-propagate",
        stderr: "scanner-error-must-not-propagate",
      };
    };
    const findings = scanWithGitleaks("dir", target, {
      root: path.resolve(__dirname, ".."),
      scanRoot: target,
      execute,
    });
    assert.deepStrictEqual(findings, [{
      ruleId: "fixture-rule",
      path: "fixture.txt",
      startLine: 1,
      endLine: 1,
      commit: null,
    }]);
    assert.doesNotMatch(JSON.stringify(findings), /must-not-propagate/u);
  });

  test("runs the scanner with a separate private HOME and XDG boundary", () => {
    const target = path.join(scratch, "target-private-home");
    fs.mkdirSync(target);
    const forbiddenHome = path.join(scratch, "qualification-profile-home");
    fs.mkdirSync(forbiddenHome);
    let scannerHome;
    const findings = scanWithGitleaks("dir", target, {
      root: path.resolve(__dirname, ".."),
      scanRoot: target,
      environment: {
        PATH: process.env.PATH || "",
        HOME: forbiddenHome,
        XDG_CONFIG_HOME: path.join(forbiddenHome, ".config"),
      },
      execute(_executable, args, options) {
        scannerHome = options.env.HOME;
        assert.notStrictEqual(scannerHome, forbiddenHome);
        const homeStat = fs.lstatSync(scannerHome);
        assert.strictEqual(homeStat.isDirectory(), true);
        if (process.platform !== "win32") assert.strictEqual(homeStat.mode & 0o077, 0);
        for (const name of [
          "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
        ]) {
          assert.strictEqual(options.env[name].startsWith(`${scannerHome}${path.sep}`), true);
        }
        const reportPath = args[args.indexOf("--report-path") + 1];
        fs.writeFileSync(reportPath, "[]\n", { mode: 0o600 });
        return { status: 0, signal: null, error: null, stdout: "", stderr: "" };
      },
    });
    assert.deepStrictEqual(findings, []);
    assert.strictEqual(fs.existsSync(scannerHome), false);
  });

  test("fails closed when scanner exit status and safe report disagree", () => {
    const target = path.join(scratch, "target");
    fs.mkdirSync(target);
    const execute = (_executable, args) => {
      const reportPath = args[args.indexOf("--report-path") + 1];
      fs.writeFileSync(reportPath, "[]\n", { mode: 0o600 });
      return { status: 1, signal: null, error: null, stdout: "", stderr: "" };
    };
    assert.throws(
      () => scanWithGitleaks("dir", target, {
        root: path.resolve(__dirname, ".."),
        scanRoot: target,
        execute,
      }),
      /exit status disagrees/u,
    );
  });

  test("copies a tracked symbolic link as link metadata without following it", () => {
    const sourceRoot = path.join(scratch, "source");
    const snapshotRoot = path.join(scratch, "snapshot");
    fs.mkdirSync(sourceRoot);
    fs.mkdirSync(snapshotRoot);
    fs.writeFileSync(path.join(scratch, "outside.txt"), "outside-content\n");
    fs.symlinkSync("../outside.txt", path.join(sourceRoot, "linked.txt"));
    copyFileIntoSnapshot(path.join(sourceRoot, "linked.txt"), "linked.txt", snapshotRoot);
    const copied = path.join(snapshotRoot, "linked.txt");
    assert.strictEqual(fs.lstatSync(copied).isSymbolicLink(), false);
    assert.strictEqual(fs.readFileSync(copied, "utf8"), "../outside.txt");
  });

  test("rejects traversal and symbolic-link shaped VSIX entries", () => {
    assert.strictEqual(validateArchiveEntryPath("extension/package.json"), "extension/package.json");
    for (const candidate of ["../escape", "/absolute", "folder/../escape", "folder\\escape"]) {
      assert.throws(() => validateArchiveEntryPath(candidate));
    }
  });

  test("result receipts contain no secret-derived hash or scanner fingerprint", () => {
    const document = resultDocument("history", "b".repeat(40), [{
      id: "git-history-all-refs",
      status: "scanned",
      fileCount: null,
      findings: [{
        ruleId: "fixture-rule",
        path: "fixture.txt",
        startLine: 2,
        endLine: 2,
        commit: "a".repeat(40),
      }],
    }], new Date("2026-08-27T00:00:00.000Z"));
    assert.strictEqual(document.status, "failed");
    assert.strictEqual(document.findingCount, 1);
    assert.strictEqual(document.scanner.version, GITLEAKS_VERSION);
    assert.doesNotMatch(JSON.stringify(document), /(?:secretHash|fingerprint|match|entropy|author|email|message)/iu);
  });
});

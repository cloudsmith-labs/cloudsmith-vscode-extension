// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const fs = require("fs");
const path = require("path");
const Mocha = require("mocha");

const {
  EVENT_RUN_END,
  EVENT_TEST_FAIL,
  EVENT_TEST_PASS,
  EVENT_TEST_PENDING,
} = Mocha.Runner.constants;

class UiEvidenceReporter extends Mocha.reporters.Base {
  constructor(runner, options) {
    super(runner, options);
    clearExTesterDevelopmentPath();
    const configuration = readConfiguration();
    const records = [];
    runner.on(EVENT_TEST_PASS, test => records.push(record(test, "passed", null)));
    runner.on(EVENT_TEST_PENDING, test => records.push(record(test, "pending", null)));
    runner.on(EVENT_TEST_FAIL, (test, error) => records.push(record(
      test,
      "failed",
      classifyFailure(configuration, test, error)
    )));
    runner.once(EVENT_RUN_END, () => writeEvidence(configuration, records));
  }
}

function clearExTesterDevelopmentPath(environment = process.env) {
  if (!Object.prototype.hasOwnProperty.call(environment, "EXTENSION_DEV_PATH")) return;
  if (environment.EXTENSION_DEV_PATH !== undefined
    && environment.EXTENSION_DEV_PATH !== "undefined") {
    throw new Error("Black-box UI execution refuses extension development paths.");
  }
  delete environment.EXTENSION_DEV_PATH;
  if (Object.prototype.hasOwnProperty.call(environment, "EXTENSION_DEV_PATH")) {
    throw new Error("Black-box UI execution could not clear the tool development-path sentinel.");
  }
}

function readConfiguration(environment = process.env) {
  const phase = environment.CLOUDSMITH_UI_EVIDENCE_PHASE;
  const nonce = environment.CLOUDSMITH_UI_EVIDENCE_NONCE;
  const root = environment.CLOUDSMITH_UI_EVIDENCE_ROOT;
  const output = environment.CLOUDSMITH_UI_EVIDENCE_PATH;
  const source = {
    sha: environment.CLOUDSMITH_QUALITY_SOURCE_SHA,
    fingerprint: environment.CLOUDSMITH_QUALITY_SOURCE_FINGERPRINT,
  };
  if (!new Set(["probe", "suite"]).has(phase)
    || !/^[a-f0-9]{64}$/u.test(nonce || "")
    || !/^[a-f0-9]{40,64}$/u.test(source.sha || "")
    || !/^[a-f0-9]{64}$/u.test(source.fingerprint || "")
    || typeof root !== "string" || !path.isAbsolute(root)) {
    throw new Error("Black-box UI reporter configuration is invalid.");
  }
  const expected = path.join(root, "evidence", `${phase}-${nonce}.json`);
  if (output !== expected) {
    throw new Error("Black-box UI reporter output is not the exact owned evidence path.");
  }
  assertRealDirectory(root, "Black-box UI evidence root");
  assertRealDirectory(path.dirname(expected), "Black-box UI evidence directory");
  return Object.freeze({ phase, nonce, output, root, source: Object.freeze(source) });
}

function record(test, status, errorKind) {
  return Object.freeze({
    name: typeof test?.title === "string" ? test.title : "<unknown>",
    status,
    errorKind,
  });
}

function classifyFailure(configuration, test, error) {
  if (test?.type === "test"
    && configuration.phase === "probe"
    && error?.code === "ERR_ASSERTION"
    && error?.operator === "strictEqual"
    && error?.actual === null
    && error?.expected === `Cloudsmith false-green ${configuration.nonce}`) {
    return "fresh-wrong-selector-rejected";
  }
  return test?.type === "hook" ? "unexpected-hook-failure" : "unexpected-test-failure";
}

function writeEvidence(configuration, records) {
  assertRealDirectory(configuration.root, "Black-box UI evidence root");
  assertRealDirectory(path.dirname(configuration.output), "Black-box UI evidence directory");
  if (fs.existsSync(configuration.output)) {
    throw new Error("Black-box UI reporter refuses to replace existing evidence.");
  }
  const totals = {
    passed: records.filter(item => item.status === "passed").length,
    failed: records.filter(item => item.status === "failed").length,
    pending: records.filter(item => item.status === "pending").length,
  };
  const document = {
    schemaVersion: 1,
    phase: configuration.phase,
    nonce: configuration.nonce,
    source: configuration.source,
    totals,
    records,
  };
  const temporary = `${configuration.output}.tmp-${process.pid}`;
  let descriptor = null;
  try {
    descriptor = fs.openSync(
      temporary,
      fs.constants.O_WRONLY
        | fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | (fs.constants.O_NOFOLLOW || 0),
      0o600
    );
    fs.writeFileSync(descriptor, `${JSON.stringify(document, null, 2)}\n`);
    fs.closeSync(descriptor);
    descriptor = null;
    fs.linkSync(temporary, configuration.output);
    fs.unlinkSync(temporary);
  } catch (error) {
    if (descriptor !== null) fs.closeSync(descriptor);
    fs.rmSync(temporary, { force: true });
    throw error;
  }
}

function assertRealDirectory(directory, label) {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`${label} must be a real directory.`);
  }
}

module.exports = UiEvidenceReporter;
module.exports.classifyFailure = classifyFailure;
module.exports.clearExTesterDevelopmentPath = clearExTesterDevelopmentPath;
module.exports.readConfiguration = readConfiguration;

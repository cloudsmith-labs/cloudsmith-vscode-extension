// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const path = require("path");
const Mocha = require("mocha");
const { ROOT, normalizePath, writeJson } = require("./common");

const {
  EVENT_RUN_END,
  EVENT_TEST_FAIL,
  EVENT_TEST_PASS,
  EVENT_TEST_PENDING,
} = Mocha.Runner.constants;

class QualityEvidenceReporter extends Mocha.reporters.Spec {
  constructor(runner, options) {
    super(runner, options);
    const tests = [];
    const record = (test, status) => {
      const file = test?.file ? normalizePath(path.relative(ROOT, test.file)) : null;
      tests.push({
        file,
        title: typeof test?.title === "string" ? test.title : null,
        fullTitle: typeof test?.fullTitle === "function" ? test.fullTitle() : null,
        status,
      });
    };
    runner.on(EVENT_TEST_PASS, test => record(test, "passed"));
    runner.on(EVENT_TEST_FAIL, test => record(test, "failed"));
    runner.on(EVENT_TEST_PENDING, test => record(test, "pending"));
    runner.once(EVENT_RUN_END, () => writeEvidence(tests));
  }
}

function writeEvidence(tests) {
  const relativeOutput = process.env.CLOUDSMITH_QUALITY_TEST_EVIDENCE;
  if (!relativeOutput) return;
  const ordered = tests.map(test => Object.freeze({ ...test }));
  const counts = {
    passed: ordered.filter(test => test.status === "passed").length,
    failed: ordered.filter(test => test.status === "failed").length,
    pending: ordered.filter(test => test.status === "pending").length,
  };
  const document = {
    schemaVersion: 1,
    source: {
      sha: process.env.CLOUDSMITH_QUALITY_SOURCE_SHA || null,
      fingerprint: process.env.CLOUDSMITH_QUALITY_SOURCE_FINGERPRINT || null,
    },
    suite: process.env.CLOUDSMITH_QUALITY_TEST_SUITE || null,
    counts,
    tests: ordered,
  };
  writeJson(relativeOutput, document, ROOT, { subtree: ".quality/test-results" });
}

module.exports = QualityEvidenceReporter;

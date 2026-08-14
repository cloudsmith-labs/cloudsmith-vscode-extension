// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const path = require("path");
const {
  fixtureMetadata,
  resultFor,
  runArchitectureSelfTests,
} = require("../scripts/architecture/self-test");
const {
  validateMetadata,
  verifyArchitecture,
} = require("../scripts/architecture/verifier");

const root = path.resolve(__dirname, "..");

suite("M11 architecture gate", () => {
  test("production architecture, ownership, and executable registration parity pass", () => {
    const result = verifyArchitecture({ root });
    assert.strictEqual(result.diagnostics.length, 0);
    assert.strictEqual(result.observed.length, 64);
    assert.strictEqual(new Set(result.observed.map((entry) => entry.command)).size, 64);
  });

  test("controlled valid, boundary, parity, and scanner fixtures prove stable rules", () => {
    assert.deepStrictEqual(runArchitectureSelfTests(), {
      invalidFixtures: 61,
      validFixtures: 1,
    });
  });

  test("metadata rejects unsupported keys and broad bypass paths", () => {
    const fixtureRoot = path.join(__dirname, "fixtures/architecture/valid");
    const unsupported = { ...fixtureMetadata(fixtureRoot), unsupported: true };
    assert.ok(validateMetadata(fixtureRoot, unsupported).diagnostics.some(
      (entry) => entry.code === "ARCH_METADATA_SCHEMA" && entry.path === "architecture.json",
    ));

    const broad = fixtureMetadata(fixtureRoot);
    broad.adapterFiles = ["domain/*.js"];
    assert.ok(validateMetadata(fixtureRoot, broad).diagnostics.some(
      (entry) => entry.code === "ARCH_METADATA_PATH" && entry.path === "architecture.json",
    ));
  });

  test("command parity fixtures distinguish duplicate execution and missing registration", () => {
    const duplicate = resultFor("duplicate-registration");
    assert.ok(duplicate.diagnostics.some(
      (entry) => entry.code === "ARCH_COMMAND_DUPLICATE" && entry.path === "commands/general.js",
    ));
    const missing = resultFor("missing-manifest");
    assert.ok(missing.diagnostics.some(
      (entry) => entry.code === "ARCH_COMMAND_REGISTRATION_MISSING" && entry.path === "commands",
    ));
  });
});

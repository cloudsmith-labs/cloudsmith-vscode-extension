// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const { runSelfTests } = require("../scripts/polish/self-test");
const { verifyRepository } = require("../scripts/polish/verifier");

suite("M14 polish gate", () => {
  test("production repository satisfies the closed documentation and media contract", () => {
    const result = verifyRepository();
    assert.deepStrictEqual(result, { activeSettings: 20, deprecatedSettings: 2, media: 29 });
  });

  test("controlled mutations prove the checker fails closed", () => {
    assert.strictEqual(runSelfTests(), true);
  });
});

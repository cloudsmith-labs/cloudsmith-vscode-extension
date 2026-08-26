// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const { openExternalWithFeedback } = require("../util/externalNavigation");

suite("External navigation", () => {
  test("returns true only for an explicit successful platform open", async () => {
    const warnings = [];
    const opened = await openExternalWithFeedback({
      target: "https://docs.cloudsmith.com/",
      openExternal: async () => true,
      showWarningMessage: async message => warnings.push(message),
      failureMessage: "Could not open documentation.",
    });

    assert.strictEqual(opened, true);
    assert.deepStrictEqual(warnings, []);
  });

  for (const [label, openExternal] of [
    ["refusal", async () => false],
    ["non-boolean success", async () => ({ opened: true })],
    ["rejection", async () => { throw new Error("platform rejected"); }],
  ]) {
    test(`reports a visible failure after platform ${label}`, async () => {
      const warnings = [];
      const opened = await openExternalWithFeedback({
        target: "https://docs.cloudsmith.com/",
        openExternal,
        showWarningMessage: async message => warnings.push(message),
        failureMessage: "Could not open documentation.",
      });

      assert.strictEqual(opened, false);
      assert.deepStrictEqual(warnings, ["Could not open documentation."]);
    });
  }

  test("does not open or warn after ownership is already stale", async () => {
    let opens = 0;
    let warnings = 0;
    const opened = await openExternalWithFeedback({
      target: "https://docs.cloudsmith.com/",
      openExternal: async () => { opens += 1; return true; },
      showWarningMessage: async () => { warnings += 1; },
      failureMessage: "Could not open documentation.",
      isCurrent: () => false,
    });

    assert.strictEqual(opened, false);
    assert.strictEqual(opens, 0);
    assert.strictEqual(warnings, 0);
  });

  test("suppresses stale failure feedback when ownership changes during the open", async () => {
    let current = true;
    let warnings = 0;
    const opened = await openExternalWithFeedback({
      target: "https://docs.cloudsmith.com/",
      openExternal: async () => { current = false; return false; },
      showWarningMessage: async () => { warnings += 1; },
      failureMessage: "Could not open documentation.",
      isCurrent: () => current,
    });

    assert.strictEqual(opened, false);
    assert.strictEqual(warnings, 0);
  });

  test("rejects each incomplete navigation contract field before invoking a target", async () => {
    const valid = {
      target: "https://docs.cloudsmith.com/",
      openExternal: async () => true,
      showWarningMessage: async () => undefined,
      failureMessage: "Could not open documentation.",
      isCurrent: () => true,
    };
    for (const invalid of [
      { openExternal: null },
      { showWarningMessage: null },
      { failureMessage: null },
      { failureMessage: "" },
      { isCurrent: null },
    ]) {
      await assert.rejects(
        () => openExternalWithFeedback({ ...valid, ...invalid }),
        /requires an opener, warning sink, and failure copy/
      );
    }
  });
});

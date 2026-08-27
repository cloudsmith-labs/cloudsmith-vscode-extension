// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const { ActivityBar } = require("vscode-extension-tester");

const PROBE_TEST = "rejects a fresh intentionally incorrect Activity Bar selector";

suite("packaged black-box UI false-green probe", function () {
  this.timeout(45_000);

  test("rejects a fresh intentionally incorrect Activity Bar selector", async () => {
    const selector = process.env.CLOUDSMITH_UI_PROBE_SELECTOR;
    assert.match(
      selector || "",
      /^Cloudsmith false-green [a-f0-9]{64}$/u,
      "the runner must provide a fresh bounded false-green selector"
    );
    const control = await new ActivityBar().getViewControl(selector);
    const visibleTitle = control ? await control.getTitle() : null;
    assert.strictEqual(
      visibleTitle,
      selector,
      "the intentionally incorrect selector must not match a real Activity Bar control"
    );
  });
});

module.exports = { PROBE_TEST };

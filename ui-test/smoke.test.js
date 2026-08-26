// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const {
  ActivityBar,
  SettingsEditor,
  VSBrowser,
  Workbench,
} = require("vscode-extension-tester");
const { writeFile, writeText } = require("../scripts/quality/common");

const SECTION_TITLES = Object.freeze([
  "Workspaces",
  "Package search",
  "Dependency health",
  "Help and feedback",
]);
const HELP_ROWS = Object.freeze([
  "Read extension documentation",
  "Get started with Cloudsmith",
  "View issues",
  "Report an issue",
]);

suite("packaged black-box UI smoke", function () {
  this.timeout(45_000);
  let sideBar;

  suiteSetup(function () {
    throw new Error(
      "UI smoke is blocked: production activation reads VS Code SecretStorage; "
      + "no environment acknowledgement authorizes automated launch."
    );
  });

  teardown(async function () {
    if (this.currentTest?.state !== "failed") return;
    const slug = String(this.currentTest.title).replace(/[^a-z0-9]+/gi, "-").toLowerCase();
    const screenshot = await VSBrowser.instance.driver.takeScreenshot();
    writeFile(
      `.quality/ui/${slug}.png`,
      Buffer.from(screenshot, "base64"),
      undefined,
      { subtree: ".quality/ui" }
    );
    writeText(
      `.quality/ui/${slug}.json`,
      `${JSON.stringify({
        test: this.currentTest.title,
        expected: "authoritative visible outcome",
        actual: this.currentTest.err?.message || "unknown UI failure",
      }, null, 2)}\n`,
      undefined,
      { subtree: ".quality/ui" }
    );
  });

  test("installs, activates, and exposes the Cloudsmith Activity Bar container", async () => {
    const control = await new ActivityBar().getViewControl("Cloudsmith");
    assert.ok(control, "Cloudsmith Activity Bar control must exist in the installed VSIX");
    sideBar = await control.openView();
    assert.strictEqual(await sideBar.getTitlePart().getTitle(), "CLOUDSMITH");
  });

  test("opens every extension-owned view without a blank container", async () => {
    assert.ok(sideBar, "the activation smoke must open the production Cloudsmith container first");
    const content = sideBar.getContent();
    for (const title of SECTION_TITLES) {
      const section = await content.getSection(title);
      assert.ok(section, `${title} section must be contributed`);
      await section.expand(5_000);
      await VSBrowser.instance.driver.wait(async () => {
        const labels = await labelsFor(section);
        return labels.length > 0 && labels.every(label => label !== "Connecting to Cloudsmith...");
      }, 10_000, `${title} never published a non-blank terminal`);
    }
    const help = await content.getSection("Help and feedback");
    const labels = await labelsFor(help);
    for (const row of HELP_ROWS) assert.ok(labels.includes(row), `missing Help row: ${row}`);
  });

  test("lists release-critical commands in the real Command Palette", async () => {
    const input = await new Workbench().openCommandPrompt();
    await input.setText("Cloudsmith:");
    const labels = await Promise.all((await input.getQuickPicks()).map(item => item.getLabel()));
    assert.ok(labels.includes("Cloudsmith: Open Cloudsmith settings"));
    assert.ok(labels.includes("Cloudsmith: View Cloudsmith documentation"));
    await input.cancel();
  });

  test("opens Cloudsmith settings through the real Command Palette action", async () => {
    await new Workbench().executeCommand("Cloudsmith: Open Cloudsmith settings");
    const settings = new SettingsEditor();
    const setting = await settings.findSettingByID("cloudsmith-vsc.showMaxPackages");
    assert.ok(setting, "the exact Cloudsmith setting must be visible after command execution");
    assert.strictEqual(String(await setting.getValue()), "30");
  });
});

async function labelsFor(section) {
  const items = await section.getVisibleItems();
  return Promise.all(items.map(item => item.getLabel()));
}

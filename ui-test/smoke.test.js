// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const {
  ActivityBar,
  By,
  Key,
  SettingsEditor,
  VSBrowser,
  Workbench,
} = require("vscode-extension-tester");

const HELP_ROWS = Object.freeze([
  "Read extension documentation",
  "Get started with Cloudsmith",
  "View issues",
  "Report an issue",
]);
const SIGNED_OUT_COMMANDS = Object.freeze([
  Object.freeze({ label: "Cloudsmith: Focus on Dependency health View", enabled: true }),
  Object.freeze({ label: "Cloudsmith: Focus on Help and feedback View", enabled: true }),
  Object.freeze({ label: "Cloudsmith: Focus on Package search View", enabled: true }),
  Object.freeze({ label: "Cloudsmith: Focus on Workspaces View", enabled: true }),
  Object.freeze({ label: "Cloudsmith: Import API key from Cloudsmith CLI", enabled: true }),
  Object.freeze({ label: "Cloudsmith: Open Cloudsmith settings", enabled: true }),
  Object.freeze({ label: "Cloudsmith: Set up Cloudsmith authentication", enabled: true }),
  Object.freeze({ label: "Cloudsmith: Sign in with SSO", enabled: true }),
  Object.freeze({ label: "Cloudsmith: View Cloudsmith documentation", enabled: true }),
]);
const SIGNED_OUT_ROWS = Object.freeze({
  Workspaces: Object.freeze(["Connect to Cloudsmith"]),
  "Package search": Object.freeze(["Connect to Cloudsmith"]),
  "Dependency health": Object.freeze(["Connect to Cloudsmith"]),
  "Help and feedback": HELP_ROWS,
});

suite("packaged black-box UI smoke", function () {
  this.timeout(45_000);
  let sideBar;

  test("installs, activates, and exposes the Cloudsmith Activity Bar container", async () => {
    const control = await new ActivityBar().getViewControl("Cloudsmith");
    assert.ok(control, "Cloudsmith Activity Bar control must exist in the installed VSIX");
    sideBar = await control.openView();
    assert.strictEqual(await sideBar.getTitlePart().getTitle(), "CLOUDSMITH");
  });

  test("opens every extension-owned view without a blank container", async () => {
    assert.ok(sideBar, "the activation smoke must open the production Cloudsmith container first");
    const content = sideBar.getContent();
    for (const [title, expectedRows] of Object.entries(SIGNED_OUT_ROWS)) {
      const section = await content.getSection(title);
      assert.ok(section, `${title} section must be contributed`);
      await section.expand(5_000);
      await VSBrowser.instance.driver.wait(async () => {
        const labels = await labelsFor(section);
        return JSON.stringify(labels) === JSON.stringify(expectedRows);
      }, 10_000, `${title} never published its exact signed-out terminal`);
      assert.deepStrictEqual(await labelsFor(section), expectedRows);
    }
  });

  test("publishes the exact signed-out command set in the real Command Palette", async () => {
    const input = await new Workbench().openCommandPrompt();
    await input.setText(">Cloudsmith:");
    const choices = await VSBrowser.instance.driver.wait(async () => {
      try {
        const current = await commandChoices(input);
        return JSON.stringify(current) === JSON.stringify(SIGNED_OUT_COMMANDS) ? current : false;
      } catch (error) {
        return error?.name === "StaleElementReferenceError" ? false : Promise.reject(error);
      }
    }, 10_000, "the Command Palette never published its exact signed-out command set");
    assert.deepStrictEqual(choices, SIGNED_OUT_COMMANDS);
    await input.cancel();
  });

  test("moves keyboard focus through the rendered Help tree", async () => {
    assert.ok(sideBar, "the activation smoke must open the production Cloudsmith container first");
    const section = await sideBar.getContent().getSection("Help and feedback");
    assert.ok(section, "Help and feedback must be contributed before keyboard navigation");
    await section.expand(5_000);
    const container = await section.findElement(By.css("[role='tree']"));
    await container.sendKeys(Key.HOME);
    const firstId = await VSBrowser.instance.driver.wait(async () => (
      (await container.getAttribute("aria-activedescendant")) || false
    ), 5_000, "the Help tree never exposed its keyboard-focused row");
    const first = await VSBrowser.instance.driver.findElement(By.id(firstId));
    assert.strictEqual(await first.getAttribute("aria-label"), HELP_ROWS[0]);

    await container.sendKeys(Key.ARROW_DOWN);
    const secondId = await VSBrowser.instance.driver.wait(async () => {
      const current = await container.getAttribute("aria-activedescendant");
      return current && current !== firstId ? current : false;
    }, 5_000, "ArrowDown never moved focus to a different Help action");
    const second = await VSBrowser.instance.driver.findElement(By.id(secondId));
    assert.strictEqual(await second.getAttribute("aria-label"), HELP_ROWS[1]);
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

async function commandChoices(input) {
  const choices = await Promise.all((await input.getQuickPicks()).map(async item => ({
    label: await item.getLabel(),
    enabled: await item.isEnabled(),
  })));
  return choices.sort((left, right) => left.label.localeCompare(right.label));
}

// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const vscode = require("vscode");

suite("Extension activation smoke", () => {
  test("activates on the intended VS Code runtime and registers contributed commands", async () => {
    const expectedVersion = process.env.EXPECTED_VSCODE_VERSION;
    assert.match(expectedVersion || "", /^\d+\.\d+\.\d+$/);
    assert.strictEqual(vscode.version, expectedVersion);

    const extension = vscode.extensions.getExtension("Cloudsmith.cloudsmith-vsc");
    assert.ok(extension, "Cloudsmith.cloudsmith-vsc was not loaded as the development extension");

    await extension.activate();
    assert.strictEqual(extension.isActive, true);

    const contributedCommands = (extension.packageJSON.contributes?.commands || [])
      .map((entry) => entry.command);
    assert.ok(contributedCommands.length > 0, "The extension manifest contributes no commands");

    const registeredCommands = new Set(await vscode.commands.getCommands(true));
    const missingCommands = contributedCommands.filter((command) => !registeredCommands.has(command));
    assert.deepStrictEqual(missingCommands, [], "Every contributed command must be registered after activation");
  });
});

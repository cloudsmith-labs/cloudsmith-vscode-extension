// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  APPROVED_MEDIA,
  validateCommandDocs,
  validateHelpLinks,
  validateMedia,
  validateSettingsDocs,
  walkForJunk,
} = require("./verifier");

function expectFailure(action, pattern) {
  assert.throws(action, pattern);
}

function runSelfTests() {
  const manifest = {
    contributes: {
      configuration: { properties: {
        "cloudsmith-vsc.example": { type: "integer", default: 3, minimum: 1, maximum: 5 },
        "cloudsmith-vsc.autoScanOnOpen": {
          type: "boolean",
          default: false,
          deprecationMessage: "This setting has no effect and is retained only so existing configuration remains valid.",
        },
        "cloudsmith-vsc.showRepoMetrics": {
          type: "boolean",
          default: false,
          deprecationMessage: "This setting has no effect and is retained only so existing configuration remains valid.",
        },
      } },
      commands: [{ command: "cloudsmith-vsc.example", title: "Example command" }],
    },
  };
  const active = Array.from({ length: 19 }, (_, index) => `| \`cloudsmith-vsc.filler${index}\` | \`false\` | Boolean | Filler. |`).join("\n");
  for (let index = 0; index < 19; index += 1) {
    manifest.contributes.configuration.properties[`cloudsmith-vsc.filler${index}`] = { type: "boolean", default: false };
  }
  const readme = `### Active settings\n| Setting | Default | Constraints | Purpose |\n|---|---|---|---|\n| \`cloudsmith-vsc.example\` | \`3\` | Integer, 1-5 | Example. |\n${active}\n### Deprecated compatibility settings\n| Setting | Default | Status | Purpose |\n|---|---|---|---|\n| \`cloudsmith-vsc.autoScanOnOpen\` | \`false\` | Deprecated | No effect. |\n| \`cloudsmith-vsc.showRepoMetrics\` | \`false\` | Deprecated | No effect. |\n## Command surfaces\n| Surface | Command ID | Command | Purpose |\n|---|---|---|---|\n| Command Palette | \`cloudsmith-vsc.example\` | \`Example command\` | Example. |`;
  const architecture = { commandUx: { classifications: { global: ["cloudsmith-vsc.example"], recoverable: [], contextOnly: [] } } };

  assert.doesNotThrow(() => validateSettingsDocs(manifest, readme));
  assert.doesNotThrow(() => validateCommandDocs(manifest, architecture, readme));
  expectFailure(() => validateSettingsDocs(manifest, readme.replace("| `3` |", "| `4` |")), /README default/);
  expectFailure(() => validateSettingsDocs(manifest, readme.replace("Integer, 1-5", "Integer")), /omits minimum/);
  expectFailure(() => validateSettingsDocs(manifest, readme.replace(/\| `cloudsmith-vsc\.filler0`[^\n]+\n/, "")), /omits contributed setting/);
  expectFailure(() => validateCommandDocs(manifest, architecture, readme.replace("Example command", "Wrong title")), /README title/);
  expectFailure(() => validateCommandDocs(manifest, {
    commandUx: { classifications: { global: [], recoverable: [], contextOnly: ["cloudsmith-vsc.example"] } },
  }, readme), /misclassifies/);
  assert.doesNotThrow(() => validateHelpLinks([
    { url: "https://docs.cloudsmith.com/developer-tools/vscode" },
    { url: "https://docs.cloudsmith.com/" },
    { url: "https://github.com/cloudsmith-labs/cloudsmith-vscode-extension/issues" },
    { url: "https://github.com/cloudsmith-labs/cloudsmith-vscode-extension/issues/new/choose" },
  ], [
    "https://docs.cloudsmith.com/developer-tools/vscode",
    "https://docs.cloudsmith.com/",
    "https://github.com/cloudsmith-labs/cloudsmith-vscode-extension/issues",
    "https://github.com/cloudsmith-labs/cloudsmith-vscode-extension/issues/new/choose",
  ].join("\n")));
  expectFailure(() => validateHelpLinks([{ url: "http://example.com" }], "http://example.com"), /verified destinations/);

  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-polish-self-test-"));
  try {
    for (const relative of APPROVED_MEDIA) {
      const absolute = path.join(temporary, relative);
      fs.mkdirSync(path.dirname(absolute), { recursive: true });
      fs.writeFileSync(absolute, "bounded fixture\n");
    }
    const mediaManifest = { files: [...APPROVED_MEDIA] };
    const mediaArchitecture = { nonJavaScriptPackageFiles: [...APPROVED_MEDIA] };
    const mediaReadme = '<img src="media/readme/brand-banner.png" alt="" />';
    assert.doesNotThrow(() => validateMedia(
      temporary,
      mediaManifest,
      mediaArchitecture,
      mediaReadme
    ));

    const retainedIcon = "media/vscode_icons/file_type_npm.svg";
    fs.unlinkSync(path.join(temporary, retainedIcon));
    expectFailure(
      () => validateMedia(temporary, mediaManifest, mediaArchitecture, mediaReadme),
      /required media is missing: media\/vscode_icons\/file_type_npm\.svg/
    );
    fs.writeFileSync(path.join(temporary, retainedIcon), "bounded fixture\n");

    const rogueReadmeMedia = path.join(temporary, "media/readme/rogue.gif");
    fs.writeFileSync(rogueReadmeMedia, "bounded fixture\n");
    expectFailure(
      () => validateMedia(temporary, mediaManifest, mediaArchitecture, mediaReadme),
      /README media directory contains stale or unreferenced assets/
    );
    fs.unlinkSync(rogueReadmeMedia);

    expectFailure(
      () => validateMedia(
        temporary,
        { files: [...APPROVED_MEDIA, "media/readme/*.gif"] },
        mediaArchitecture,
        mediaReadme
      ),
      /package\.json contains a broad media glob/
    );

    const junk = path.join(temporary, ".DS_Store");
    fs.writeFileSync(junk, "bounded fixture\n");
    expectFailure(() => walkForJunk(temporary), /repository contains OS\/editor junk: \.DS_Store/);
    fs.unlinkSync(junk);
    assert.doesNotThrow(() => walkForJunk(temporary));
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
  return true;
}

module.exports = { runSelfTests };

// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { runSelfTests } = require("../scripts/polish/self-test");
const {
  validateDocumentationTruth,
  validateHelpLinks,
  verifyRepository,
} = require("../scripts/polish/verifier");

const EXTENSION_HOMEPAGE =
  "https://github.com/cloudsmith-labs/cloudsmith-vscode-extension/blob/main/README.md";
const RETIRED_EXTENSION_DOCS = "https://docs.cloudsmith.com/developer-tools/vscode";

suite("M14 polish gate", () => {
  test("production repository satisfies the closed documentation and media contract", () => {
    const result = verifyRepository();
    assert.deepStrictEqual(result, { activeSettings: 19, deprecatedSettings: 3, media: 29 });
  });

  test("controlled mutations prove the checker fails closed", () => {
    assert.strictEqual(runSelfTests(), true);
  });

  test("primary extension Help is the manifest homepage and the retired URL fails closed", () => {
    const manifest = { homepage: EXTENSION_HOMEPAGE };
    const links = [
      {
        id: "extensionDocs",
        label: "Read extension documentation",
        url: EXTENSION_HOMEPAGE,
        icon: "external",
      },
      {
        id: "gettingStarted",
        label: "Get started with Cloudsmith",
        url: "https://docs.cloudsmith.com/",
        icon: "cloudsmith",
      },
      {
        id: "viewIssues",
        label: "View issues",
        url: "https://github.com/cloudsmith-labs/cloudsmith-vscode-extension/issues",
        icon: "github",
      },
      {
        id: "reportIssue",
        label: "Report an issue",
        url: "https://github.com/cloudsmith-labs/cloudsmith-vscode-extension/issues/new/choose",
        icon: "github",
      },
    ];
    const readme = links.map(link => link.url).join("\n");

    assert.doesNotThrow(() => validateHelpLinks(links, readme, manifest));
    assert.throws(
      () => validateHelpLinks([
        { ...links[0], url: RETIRED_EXTENSION_DOCS },
        ...links.slice(1),
      ], `${readme}\n${RETIRED_EXTENSION_DOCS}`, manifest),
      /retired extension documentation URL/
    );
  });

  test("install-command documentation fails closed when native setup guidance drifts", () => {
    const root = path.resolve(__dirname, "..");
    const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
    const mutated = readme.replace(
      "**Go** sets a repository-specific `GOPROXY`",
      "**Go** provides generic setup"
    );

    assert.throws(
      () => validateDocumentationTruth(manifest, mutated),
      /README omits install-command guidance/
    );
  });

  test("authentication documentation distinguishes REST API and trusted registry transport", () => {
    const root = path.resolve(__dirname, "..");
    const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
    const mutated = readme.replace(
      "only with validated Cloudsmith registry hosts",
      "with registry hosts"
    );

    assert.throws(
      () => validateDocumentationTruth(manifest, mutated),
      /README omits the REST API and registry authentication boundary/
    );
  });
});

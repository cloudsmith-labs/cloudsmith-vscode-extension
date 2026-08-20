// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const {
  FALLBACK_FORMATS,
  FORMAT_ICON_FILES,
  FORMAT_ICON_KEYS,
  NATIVE_FORMAT_ICONS,
} = require("../util/formatIconInventory");
const { ECOSYSTEM_TO_FORMAT } = require("../util/packageNameNormalizer");
const { SUPPORTED_UPSTREAM_FORMATS } = require("../util/upstreamFormats");

suite("format icon inventory", () => {
  test("every supported format and ecosystem alias has an explicit icon decision", () => {
    assert.strictEqual(SUPPORTED_UPSTREAM_FORMATS.length, 26);
    for (const format of [...SUPPORTED_UPSTREAM_FORMATS, ...Object.values(ECOSYSTEM_TO_FORMAT)]) {
      assert.ok(
        Object.hasOwn(FORMAT_ICON_KEYS, format)
          || Object.hasOwn(NATIVE_FORMAT_ICONS, format)
          || FALLBACK_FORMATS.includes(format),
        format,
      );
    }
    assert.deepStrictEqual(FALLBACK_FORMATS, ["huggingface"]);
    assert.deepStrictEqual(NATIVE_FORMAT_ICONS, { generic: "file-binary", raw: "file-binary" });
  });

  test("dedicated cargo, rust, and rust light assets are frozen and present", () => {
    assert.strictEqual(FORMAT_ICON_KEYS.cargo, "cargo");
    assert.strictEqual(FORMAT_ICON_KEYS.rust, "rust");
    assert.ok(FORMAT_ICON_FILES.includes("media/vscode_icons/file_type_cargo.svg"));
    assert.ok(FORMAT_ICON_FILES.includes("media/vscode_icons/file_type_rust.svg"));
    assert.ok(FORMAT_ICON_FILES.includes("media/vscode_icons/file_type_light_rust.svg"));
    for (const relative of FORMAT_ICON_FILES) {
      assert.ok(fs.statSync(path.join(__dirname, "..", relative)).isFile(), relative);
    }
  });

});

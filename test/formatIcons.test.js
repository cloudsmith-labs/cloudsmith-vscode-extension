// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const path = require("path");
const {
  FALLBACK_FORMATS,
  FORMAT_ICON_KEYS,
  NATIVE_FORMAT_ICONS,
} = require("../util/formatIconInventory");
const { getFormatIconPath } = require("../util/formatIcons");
const { ECOSYSTEM_TO_FORMAT } = require("../util/packageNameNormalizer");
const { SUPPORTED_UPSTREAM_FORMATS } = require("../util/upstreamFormats");

suite("format icon runtime resolver", () => {
  test("executes every supported decision and alias with bounded fallback", () => {
    const extensionPath = path.join(__dirname, "..");
    const cases = new Set([
      ...SUPPORTED_UPSTREAM_FORMATS,
      ...Object.keys(ECOSYSTEM_TO_FORMAT),
      ...Object.values(ECOSYSTEM_TO_FORMAT),
      ...FALLBACK_FORMATS,
      "generic",
      "raw",
      "unknown-format",
    ]);

    for (const format of cases) {
      const canonical = ECOSYSTEM_TO_FORMAT[format] || format;
      const result = getFormatIconPath(format, extensionPath);
      if (NATIVE_FORMAT_ICONS[canonical]) {
        assert.strictEqual(result.id, "file-binary", format);
      } else if (FORMAT_ICON_KEYS[canonical]) {
        assert.ok(result.dark.fsPath.endsWith(`file_type_${FORMAT_ICON_KEYS[canonical]}.svg`), format);
        const expectedLight = canonical === "rust"
          ? "file_type_light_rust.svg"
          : `file_type_${FORMAT_ICON_KEYS[canonical]}.svg`;
        assert.ok(result.light.fsPath.endsWith(expectedLight), format);
      } else {
        assert.strictEqual(result.id, "package", format);
      }
    }

    assert.ok(getFormatIconPath("cargo", extensionPath).dark.fsPath.endsWith("file_type_cargo.svg"));
    assert.ok(getFormatIconPath("rust", extensionPath).dark.fsPath.endsWith("file_type_rust.svg"));
    assert.strictEqual(
      getFormatIconPath("npm", path.join(extensionPath, "missing-icons")).id,
      "package"
    );
  });
});

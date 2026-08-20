// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const fs = require("fs");
const vscode = require("vscode");
const { canonicalFormat } = require("./packageNameNormalizer");
const {
  FORMAT_ICON_KEYS,
  NATIVE_FORMAT_ICONS,
} = require("./formatIconInventory");

const warnedMissingIcons = new Set();

function getFormatIconPath(format, extensionPath, options = {}) {
  const fallbackIcon = Object.prototype.hasOwnProperty.call(options, "fallbackIcon")
    ? options.fallbackIcon
    : new vscode.ThemeIcon("package");
  const normalizedFormat = canonicalFormat(format);
  if (!normalizedFormat || !extensionPath) {
    return fallbackIcon;
  }

  const nativeIcon = NATIVE_FORMAT_ICONS[normalizedFormat];
  if (nativeIcon) {
    return new vscode.ThemeIcon(nativeIcon);
  }

  const iconKey = FORMAT_ICON_KEYS[normalizedFormat];
  if (!iconKey) {
    warnMissingIconOnce(normalizedFormat);
    return fallbackIcon;
  }
  const iconPath = resolveThemedIconPath(extensionPath, iconKey);
  if (iconPath) {
    return iconPath;
  }

  warnMissingIconOnce(normalizedFormat);
  return fallbackIcon;
}

function resolveThemedIconPath(extensionPath, iconKey) {
  if (!extensionPath || !iconKey) {
    return null;
  }

  const extensionUri = vscode.Uri.file(extensionPath);
  const dark = vscode.Uri.joinPath(extensionUri, "media", "vscode_icons", `file_type_${iconKey}.svg`);
  if (!fs.existsSync(dark.fsPath)) {
    return null;
  }

  const lightCandidate = vscode.Uri.joinPath(extensionUri, "media", "vscode_icons", `file_type_light_${iconKey}.svg`);
  return {
    light: fs.existsSync(lightCandidate.fsPath) ? lightCandidate : dark,
    dark,
  };
}

function warnMissingIconOnce(format) {
  const normalizedFormat = canonicalFormat(format);
  if (!normalizedFormat || warnedMissingIcons.has(normalizedFormat)) {
    return;
  }

  warnedMissingIcons.add(normalizedFormat);
  console.warn(`No format icon found for ecosystem '${normalizedFormat}', using generic icon`);
}

module.exports = {
  FORMAT_ICON_KEYS,
  getFormatIconPath,
};

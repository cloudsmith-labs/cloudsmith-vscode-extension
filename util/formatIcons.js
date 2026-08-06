// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const fs = require("fs");
const vscode = require("vscode");
const { canonicalFormat } = require("./packageNameNormalizer");

const FORMAT_ICON_KEYS = Object.freeze({
  cargo: "cargo",
  composer: "composer",
  conda: "conda",
  dart: "dart",
  docker: "docker",
  elixir: "elixir",
  gem: "ruby",
  go: "go",
  golang: "go",
  gradle: "maven",
  helm: "helm",
  hex: "elixir",
  maven: "maven",
  npm: "npm",
  nuget: "nuget",
  php: "php",
  pypi: "python",
  python: "python",
  ruby: "ruby",
  rust: "rust",
  swift: "swift",
});

const warnedMissingIcons = new Set();

function getFormatIconPath(format, extensionPath, options = {}) {
  const fallbackIcon = Object.prototype.hasOwnProperty.call(options, "fallbackIcon")
    ? options.fallbackIcon
    : new vscode.ThemeIcon("package");
  const normalizedFormat = canonicalFormat(format);
  if (!normalizedFormat || !extensionPath) {
    return fallbackIcon;
  }

  const iconKey = FORMAT_ICON_KEYS[normalizedFormat] || normalizedFormat;
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

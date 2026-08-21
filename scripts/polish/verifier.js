// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const fs = require("fs");
const path = require("path");
const {
  FALLBACK_FORMATS,
  FORMAT_ICON_FILES,
  FORMAT_ICON_KEYS,
  NATIVE_FORMAT_ICONS,
} = require("../../util/formatIconInventory");
const { ECOSYSTEM_TO_FORMAT } = require("../../util/packageNameNormalizer");
const { SUPPORTED_UPSTREAM_FORMATS } = require("../../util/upstreamFormats");

const DEPRECATED_SETTINGS = new Set([
  "cloudsmith-vsc.autoScanOnOpen",
  "cloudsmith-vsc.showRepoMetrics",
]);
const SETTINGS_WITH_NO_PRODUCTION_READS = new Set([
  ...DEPRECATED_SETTINGS,
  "cloudsmith-vsc.experimentalSSOBrowser",
]);
const BASE_MEDIA = Object.freeze([
  "media/icon.svg",
  "media/logo.png",
  "media/workspace_dark.svg",
  "media/workspace_light.svg",
  "media/readme/brand-banner.png",
]);
const APPROVED_MEDIA = Object.freeze([...BASE_MEDIA, ...FORMAT_ICON_FILES]);
const DECORATIVE_README_MEDIA = new Set(["media/readme/brand-banner.png"]);
const HELP_LINK_URLS = Object.freeze([
  "https://docs.cloudsmith.com/developer-tools/vscode",
  "https://docs.cloudsmith.com/",
  "https://github.com/cloudsmith-labs/cloudsmith-vscode-extension/issues",
  "https://github.com/cloudsmith-labs/cloudsmith-vscode-extension/issues/new/choose",
]);
const FORBIDDEN_DOC_PATTERNS = Object.freeze([
  /all commands are available (?:from|via)/i,
  /full raw (?:api|json)/i,
  /enter your api key directly in (?:the )?extension settings/i,
]);
const FORBIDDEN_DOC_FRAGMENTS = Object.freeze([
  "help.cloudsmith.io",
  "github.com/cloudsmith-io/cloudsmith-vscode-extension",
]);

function fail(message) {
  throw new Error(`M14 polish gate: ${message}`);
}

function parseMarkdownRows(markdown) {
  const rows = [];
  for (const line of markdown.split(/\r?\n/)) {
    if (!line.startsWith("|")) continue;
    const cells = line.slice(1, -1).split("|").map(cell => cell.trim());
    if (cells.some(cell => /^:?-{3,}:?$/.test(cell))) continue;
    rows.push(cells);
  }
  return rows;
}

function settingRows(readme) {
  const activeStart = readme.indexOf("### Active settings");
  const deprecatedStart = readme.indexOf("### Deprecated compatibility settings");
  const commandsStart = readme.indexOf("## Command surfaces");
  if (activeStart < 0 || deprecatedStart < activeStart || commandsStart < deprecatedStart) {
    fail("README setting sections are missing or out of order");
  }
  const collect = (source, classification) => parseMarkdownRows(source)
    .filter(row => /^`cloudsmith-vsc\.[^`]+`$/.test(row[0] || ""))
    .map(row => ({
      classification,
      key: row[0].slice(1, -1),
      defaultText: row[1],
      constraintText: row[2] || "",
    }));
  return [
    ...collect(readme.slice(activeStart, deprecatedStart), "active"),
    ...collect(readme.slice(deprecatedStart, commandsStart), "deprecated"),
  ];
}

function validateConstraint(setting, text, key) {
  const normalized = text.toLowerCase().replace(/[–—]/g, "-");
  if (setting.type === "boolean" && !normalized.includes("boolean")) {
    fail(`README omits the Boolean constraint for ${key}`);
  }
  if (setting.type === "integer" && !normalized.includes("integer")) {
    fail(`README omits the Integer constraint for ${key}`);
  }
  if (Number.isFinite(setting.minimum) && !normalized.includes(String(setting.minimum))) {
    fail(`README omits minimum ${setting.minimum} for ${key}`);
  }
  if (Number.isFinite(setting.maximum) && !normalized.includes(String(setting.maximum))) {
    fail(`README omits maximum ${setting.maximum} for ${key}`);
  }
  for (const value of setting.enum || []) {
    if (!text.includes(JSON.stringify(value))) {
      fail(`README omits enum value ${JSON.stringify(value)} for ${key}`);
    }
  }
}

function validateSettingsDocs(manifest, readme) {
  const properties = manifest?.contributes?.configuration?.properties || {};
  const rows = settingRows(readme);
  const seen = new Set();
  for (const row of rows) {
    if (seen.has(row.key)) fail(`README documents setting more than once: ${row.key}`);
    seen.add(row.key);
    const setting = properties[row.key];
    if (!setting) fail(`README documents an unknown setting: ${row.key}`);
    const expectedDefault = `\`${JSON.stringify(setting.default)}\``;
    if (row.defaultText !== expectedDefault) {
      fail(`README default for ${row.key} must be ${expectedDefault}`);
    }
    const expectedClass = DEPRECATED_SETTINGS.has(row.key) ? "deprecated" : "active";
    if (row.classification !== expectedClass) {
      fail(`README classifies ${row.key} as ${row.classification}, expected ${expectedClass}`);
    }
    if (expectedClass === "active") validateConstraint(setting, row.constraintText, row.key);
  }
  for (const key of Object.keys(properties)) {
    if (!seen.has(key)) fail(`README omits contributed setting: ${key}`);
  }
  for (const key of DEPRECATED_SETTINGS) {
    const setting = properties[key];
    if (!setting || setting.default !== false) fail(`${key} must remain contributed with default false`);
    const message = String(setting.deprecationMessage || "");
    if (!message.includes("has no effect") || !message.includes("existing configuration remains valid")) {
      fail(`${key} must explain its no-op compatibility status`);
    }
  }
  if (rows.filter(row => row.classification === "active").length !== 20) {
    fail("README must document exactly 20 active settings");
  }
}

function commandRows(readme) {
  return parseMarkdownRows(readme)
    .filter(row => row[0] === "Command Palette" && /^`cloudsmith-vsc\.[^`]+`$/.test(row[1] || ""))
    .map(row => ({ id: row[1].slice(1, -1), title: (row[2] || "").replace(/^`|`$/g, "") }));
}

function validateCommandDocs(manifest, architecture, readme) {
  const commands = new Map((manifest?.contributes?.commands || []).map(command => [command.command, command]));
  const classifications = architecture?.commandUx?.classifications || {};
  const palette = new Set([...(classifications.global || []), ...(classifications.recoverable || [])]);
  const contextOnly = new Set(classifications.contextOnly || []);
  const seen = new Set();
  for (const row of commandRows(readme)) {
    if (seen.has(row.id)) fail(`README documents command more than once: ${row.id}`);
    seen.add(row.id);
    const command = commands.get(row.id);
    if (!command) fail(`README documents unknown command: ${row.id}`);
    if (command.title !== row.title) fail(`README title for ${row.id} must be ${command.title}`);
    if (!palette.has(row.id) || contextOnly.has(row.id)) {
      fail(`README misclassifies ${row.id} as a Command Palette workflow`);
    }
  }
  if (!seen.size) fail("README command workflow table is empty");
}

function parseReadmeImages(readme) {
  const images = [];
  const html = /<img\s+[^>]*src="([^"]+)"[^>]*alt="([^"]*)"[^>]*>/gi;
  const markdown = /!\[([^\]]*)\]\(([^)]+)\)/g;
  for (const match of readme.matchAll(html)) images.push({ path: match[1], alt: match[2] });
  for (const match of readme.matchAll(markdown)) images.push({ path: match[2], alt: match[1] });
  return images;
}

function validateMedia(root, manifest, architecture, readme) {
  const packageMedia = (manifest.files || []).filter(file => file.startsWith("media/"));
  if (packageMedia.some(file => /[*?\[\]{}]/.test(file))) fail("package.json contains a broad media glob");
  if (JSON.stringify(packageMedia) !== JSON.stringify(APPROVED_MEDIA)) {
    fail("package.json media inventory differs from the approved closed inventory");
  }
  const architectureMedia = (architecture.nonJavaScriptPackageFiles || [])
    .filter(file => file.startsWith("media/"));
  if (JSON.stringify(architectureMedia) !== JSON.stringify(APPROVED_MEDIA)) {
    fail("architecture media inventory differs from the approved closed inventory");
  }
  for (const asset of APPROVED_MEDIA) {
    const absolute = path.join(root, asset);
    if (!fs.existsSync(absolute) || !fs.lstatSync(absolute).isFile()) fail(`required media is missing: ${asset}`);
  }
  const images = parseReadmeImages(readme);
  const referenced = new Set();
  for (const image of images) {
    const normalized = path.posix.normalize(image.path);
    if (normalized !== image.path || normalized.startsWith("../") || path.isAbsolute(image.path)) {
      fail(`README image path is unsafe: ${image.path}`);
    }
    if (referenced.has(image.path)) fail(`README references media more than once: ${image.path}`);
    referenced.add(image.path);
    if (!packageMedia.includes(image.path)) fail(`README media is not packaged: ${image.path}`);
    if (!image.alt && !DECORATIVE_README_MEDIA.has(image.path)) {
      fail(`README informational image has empty alt text: ${image.path}`);
    }
  }
  const readmeDirectory = path.join(root, "media/readme");
  const onDiskReadmeMedia = fs.readdirSync(readmeDirectory).sort().map(file => `media/readme/${file}`);
  if (JSON.stringify(onDiskReadmeMedia) !== JSON.stringify([...referenced].sort())) {
    fail("README media directory contains stale or unreferenced assets");
  }
}

function validateHelpLinks(helpLinks, readme) {
  const urls = helpLinks.map(link => link.url);
  if (JSON.stringify(urls) !== JSON.stringify(HELP_LINK_URLS)) fail("help links differ from the verified destinations");
  if (new Set(urls).size !== urls.length) fail("help links must be distinct");
  for (const url of urls) {
    if (!url.startsWith("https://") || !readme.includes(url)) fail(`README/help link is missing or unsafe: ${url}`);
  }
}

function validateFormatInventory() {
  const supported = new Set(SUPPORTED_UPSTREAM_FORMATS);
  for (const format of supported) {
    if (!(format in FORMAT_ICON_KEYS) && !(format in NATIVE_FORMAT_ICONS) && !FALLBACK_FORMATS.includes(format)) {
      fail(`supported format lacks an explicit icon decision: ${format}`);
    }
  }
  for (const format of Object.values(ECOSYSTEM_TO_FORMAT)) {
    if (!(format in FORMAT_ICON_KEYS) && !(format in NATIVE_FORMAT_ICONS) && !FALLBACK_FORMATS.includes(format)) {
      fail(`ecosystem alias lacks an explicit icon decision: ${format}`);
    }
  }
  if (FORMAT_ICON_KEYS.cargo !== "cargo" || FORMAT_ICON_KEYS.rust !== "rust") {
    fail("cargo and rust must retain their exact dedicated icons");
  }
  if (!FORMAT_ICON_FILES.includes("media/vscode_icons/file_type_light_rust.svg")) {
    fail("rust light-theme icon is missing from the inventory");
  }
}

function walkForJunk(root, relative = "") {
  const skipped = new Set([".git", "node_modules", "out", ".vscode-test"]);
  for (const entry of fs.readdirSync(path.join(root, relative), { withFileTypes: true })) {
    if (skipped.has(entry.name)) continue;
    const child = relative ? `${relative}/${entry.name}` : entry.name;
    if (/^(?:\.DS_Store|Thumbs\.db)$/.test(entry.name) || /(?:~|\.swp)$/.test(entry.name)) {
      fail(`repository contains OS/editor junk: ${child}`);
    }
    if (entry.isDirectory()) walkForJunk(root, child);
  }
}

function validateNoProductionSettingReads(root) {
  const roots = ["extension.js", "commands", "domain", "models", "util", "views"];
  for (const key of SETTINGS_WITH_NO_PRODUCTION_READS) {
    const shortName = key.slice("cloudsmith-vsc.".length);
    const hits = [];
    const scanFile = (relative) => {
      if (!relative.endsWith(".js") || relative.endsWith("formatIconInventory.js")) return;
      const absolute = path.join(root, relative);
      if (fs.readFileSync(absolute, "utf8").includes(shortName)) hits.push(relative);
    };
    const visitDirectory = (relative) => {
      const absolute = path.join(root, relative);
      for (const entry of fs.readdirSync(absolute, { withFileTypes: true })) {
        const child = `${relative}/${entry.name}`;
        if (entry.isDirectory()) visitDirectory(child);
        else if (entry.isFile()) scanFile(child);
      }
    };
    for (const relative of roots) {
      if (relative.endsWith(".js")) scanFile(relative);
      else visitDirectory(relative);
    }
    if (hits.length) fail(`${key} must have zero production reads; found ${hits.join(", ")}`);
  }
}

function verifyRepository(root = path.resolve(__dirname, "../..")) {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const architecture = JSON.parse(fs.readFileSync(path.join(root, "scripts/architecture/architecture.json"), "utf8"));
  const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
  const { HELP_LINKS } = require(path.join(root, "util/helpLinks"));
  validateSettingsDocs(manifest, readme);
  validateCommandDocs(manifest, architecture, readme);
  validateMedia(root, manifest, architecture, readme);
  validateHelpLinks(HELP_LINKS, readme);
  validateFormatInventory();
  validateNoProductionSettingReads(root);
  walkForJunk(root);
  for (const pattern of FORBIDDEN_DOC_PATTERNS) {
    if (pattern.test(readme)) fail(`README contains stale claim matching ${pattern}`);
  }
  for (const fragment of FORBIDDEN_DOC_FRAGMENTS) {
    if (readme.toLowerCase().includes(fragment)) {
      fail(`README contains stale link fragment: ${fragment}`);
    }
  }
  return { activeSettings: 20, deprecatedSettings: 2, media: APPROVED_MEDIA.length };
}

module.exports = {
  APPROVED_MEDIA,
  DEPRECATED_SETTINGS,
  parseReadmeImages,
  validateCommandDocs,
  validateFormatInventory,
  validateHelpLinks,
  validateMedia,
  validateSettingsDocs,
  verifyRepository,
  walkForJunk,
};

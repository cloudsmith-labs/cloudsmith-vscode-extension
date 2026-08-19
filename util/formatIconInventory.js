// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const FORMAT_ICON_KEYS = Object.freeze({
  alpine: "alpine",
  cargo: "cargo",
  cocoapods: "swift",
  composer: "composer",
  conan: "conan",
  conda: "conda",
  cran: "r",
  dart: "dart",
  deb: "deb",
  docker: "docker",
  elixir: "elixir",
  gem: "ruby",
  go: "go",
  golang: "go",
  gradle: "maven",
  helm: "helm",
  hex: "elixir",
  luarocks: "lua",
  maven: "maven",
  npm: "npm",
  nuget: "nuget",
  php: "composer",
  pypi: "python",
  python: "python",
  rpm: "rpm",
  ruby: "ruby",
  rust: "rust",
  swift: "swift",
  terraform: "terraform",
  vagrant: "vagrant",
});

const NATIVE_FORMAT_ICONS = Object.freeze({
  generic: "file-binary",
  raw: "file-binary",
});

const FALLBACK_FORMATS = Object.freeze([
  "huggingface",
]);

const DARK_FORMAT_ICON_FILES = Object.freeze(
  [...new Set(Object.values(FORMAT_ICON_KEYS))]
    .sort()
    .map(iconKey => `media/vscode_icons/file_type_${iconKey}.svg`)
);

const LIGHT_FORMAT_ICON_FILES = Object.freeze([
  "media/vscode_icons/file_type_light_rust.svg",
]);

const FORMAT_ICON_FILES = Object.freeze([
  ...DARK_FORMAT_ICON_FILES,
  ...LIGHT_FORMAT_ICON_FILES,
]);

module.exports = {
  DARK_FORMAT_ICON_FILES,
  FALLBACK_FORMATS,
  FORMAT_ICON_FILES,
  FORMAT_ICON_KEYS,
  LIGHT_FORMAT_ICON_FILES,
  NATIVE_FORMAT_ICONS,
};

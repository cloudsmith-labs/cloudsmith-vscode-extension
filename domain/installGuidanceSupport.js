// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const INSTALL_GUIDANCE_SUPPORT = Object.freeze({
  python: Object.freeze({
    strategy: "template",
    output: "shell-command",
    requiredEvidence: Object.freeze(["exact name and version"]),
  }),
  npm: Object.freeze({
    strategy: "template",
    output: "shell-command",
    requiredEvidence: Object.freeze(["exact native package name and version"]),
  }),
  maven: Object.freeze({
    strategy: "template",
    output: "setup-document",
    requiredEvidence: Object.freeze(["exact groupId:artifactId coordinate and version"]),
  }),
  nuget: Object.freeze({
    strategy: "template",
    output: "shell-command",
    requiredEvidence: Object.freeze(["exact package ID and version"]),
  }),
  helm: Object.freeze({
    strategy: "template",
    output: "shell-command",
    requiredEvidence: Object.freeze(["exact chart name and version"]),
  }),
  cargo: Object.freeze({
    strategy: "template",
    output: "shell-command",
    requiredEvidence: Object.freeze(["exact crate name and version"]),
  }),
  go: Object.freeze({
    strategy: "template",
    output: "shell-command",
    requiredEvidence: Object.freeze(["exact module path and semantic version"]),
  }),
  ruby: Object.freeze({
    strategy: "template",
    output: "shell-command",
    requiredEvidence: Object.freeze(["exact gem name and version", "platform when package-specific"]),
  }),
  conda: Object.freeze({
    strategy: "template",
    output: "shell-command",
    requiredEvidence: Object.freeze(["exact name and version", "build qualifier", "subdir qualifier"]),
  }),
  composer: Object.freeze({
    strategy: "template",
    output: "shell-command",
    requiredEvidence: Object.freeze(["exact vendor/package name and version"]),
  }),
  dart: Object.freeze({
    strategy: "template",
    output: "shell-command",
    requiredEvidence: Object.freeze(["exact package name and version"]),
  }),
  docker: Object.freeze({
    strategy: "docker",
    output: "shell-command",
    requiredEvidence: Object.freeze(["exact image name", "authoritative tag or sha256 digest"]),
  }),
  rpm: Object.freeze({
    strategy: "rpm",
    output: "shell-command",
    requiredEvidence: Object.freeze(["exact name and version", "release qualifier", "architecture qualifier"]),
  }),
  raw: Object.freeze({
    strategy: "download",
    output: "shell-command",
    requiredEvidence: Object.freeze(["authoritative repository-scoped CDN URL"]),
  }),
  generic: Object.freeze({
    strategy: "download",
    output: "shell-command",
    requiredEvidence: Object.freeze(["authoritative repository-scoped CDN URL"]),
  }),
});

function ownDataValue(value, key) {
  if ((typeof value !== "object" || value === null) && typeof value !== "function") {
    return undefined;
  }
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && Object.prototype.hasOwnProperty.call(descriptor, "value")
      ? descriptor.value
      : undefined;
  } catch {
    return undefined;
  }
}

function installGuidanceSupportForFormat(format) {
  if (typeof format !== "string") return null;
  return ownDataValue(INSTALL_GUIDANCE_SUPPORT, format) || null;
}

function installGuidanceOptions(pkg, coordinate) {
  const options = { qualifiers: coordinate.qualifiers };
  if (pkg.tags && (pkg.tags.info.length > 0 || pkg.tags.version.length > 0)) {
    options.tags = pkg.tags;
  }
  if (pkg.cdnUrl) options.cdnUrl = pkg.cdnUrl;
  if (pkg.filename) options.filename = pkg.filename;
  return options;
}

function usableInstallGuidance(result, support, InstallCommandBuilder) {
  if (
    !support
    || !result
    || typeof result !== "object"
    || typeof result.command !== "string"
    || result.command.trim().length === 0
    || /No install command template for format:/u.test(result.command)
  ) {
    return false;
  }
  const toClipboardCommand = InstallCommandBuilder?.toClipboardCommand;
  if (typeof toClipboardCommand !== "function") return false;
  const content = toClipboardCommand.call(InstallCommandBuilder, result.command);
  if (typeof content !== "string" || content.trim().length === 0) return false;
  if (support.output === "setup-document") {
    return result.language === "markdown"
      && /```xml\s[\s\S]*<(?:settings|dependency)>/u.test(content);
  }
  if (support.output !== "shell-command") return false;
  return content.split(/\r?\n/u).some(line => (
    line.trim().length > 0 && !/^\s*(?:#|REM\b)/iu.test(line)
  ));
}

function buildInstallGuidanceForPackage(packageDomain, InstallCommandBuilder, pkg) {
  if (
    !packageDomain
    || typeof packageDomain.packageCoordinateFromExact !== "function"
    || !InstallCommandBuilder
    || typeof InstallCommandBuilder.build !== "function"
  ) {
    return null;
  }
  const coordinate = packageDomain.packageCoordinateFromExact(pkg);
  const support = installGuidanceSupportForFormat(coordinate.format);
  if (!support) return null;
  const result = InstallCommandBuilder.build(
    coordinate.format,
    coordinate.name,
    coordinate.version,
    coordinate.workspace,
    coordinate.repository,
    installGuidanceOptions(pkg, coordinate)
  );
  return usableInstallGuidance(result, support, InstallCommandBuilder) ? result : null;
}

function hasInstallGuidanceForPackage(packageDomain, InstallCommandBuilder, pkg) {
  try {
    return buildInstallGuidanceForPackage(packageDomain, InstallCommandBuilder, pkg) !== null;
  } catch {
    return false;
  }
}

module.exports = {
  INSTALL_GUIDANCE_SUPPORT,
  buildInstallGuidanceForPackage,
  hasInstallGuidanceForPackage,
  installGuidanceSupportForFormat,
  usableInstallGuidance,
};

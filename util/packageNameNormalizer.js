// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const MAX_PACKAGE_NAME_LENGTH = 4096;

const ECOSYSTEM_TO_FORMAT = {
  npm: "npm",
  maven: "maven",
  gradle: "maven",
  pypi: "python",
  python: "python",
  go: "go",
  cargo: "cargo",
  ruby: "ruby",
  docker: "docker",
  nuget: "nuget",
  dart: "dart",
  composer: "composer",
  helm: "helm",
  swift: "swift",
  hex: "hex",
  conda: "conda",
};

function sanitizePackageNameInput(name) {
  if (typeof name !== "string") {
    return "";
  }
  const normalized = name.trim();

  if (
    !normalized
    || normalized.length > MAX_PACKAGE_NAME_LENGTH
    || /[\u0000-\u001f\u007f]/.test(normalized)
  ) {
    return "";
  }

  return normalized;
}

function canonicalFormat(ecosystemOrFormat) {
  const normalized = sanitizePackageNameInput(ecosystemOrFormat).toLowerCase();
  return ECOSYSTEM_TO_FORMAT[normalized] || normalized;
}

function normalizePackageName(name, ecosystemOrFormat) {
  const format = canonicalFormat(ecosystemOrFormat);
  const rawName = sanitizePackageNameInput(name);
  if (!rawName) {
    return "";
  }

  if (format === "python") {
    return rawName.toLowerCase().replace(/[-_.]+/g, "-");
  }

  if (format === "maven" || format === "go") {
    return rawName;
  }

  return rawName.toLowerCase();
}

function normalizeNuGetVersion(version) {
  const raw = String(version || "").trim();
  if (!raw || /[\u0000-\u001f\u007f\\/?#]/.test(raw)) return "";
  const withoutMetadata = raw.split("+", 1)[0];
  const separatorIndex = withoutMetadata.indexOf("-");
  const release = separatorIndex >= 0
    ? withoutMetadata.slice(0, separatorIndex)
    : withoutMetadata;
  const prerelease = separatorIndex >= 0
    ? withoutMetadata.slice(separatorIndex + 1)
    : "";
  const releaseParts = release.split(".");
  if (
    releaseParts.length < 1
    || releaseParts.length > 4
    || releaseParts.some(part => !/^\d+$/.test(part))
    || (separatorIndex >= 0 && !/^[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*$/.test(prerelease))
  ) return "";
  const normalizedRelease = releaseParts.map(part => part.replace(/^0+(?=\d)/, ""));
  while (normalizedRelease.length < 3) normalizedRelease.push("0");
  if (normalizedRelease.length === 4 && normalizedRelease[3] === "0") {
    normalizedRelease.pop();
  }
  return `${normalizedRelease.join(".")}${prerelease ? `-${prerelease.toLowerCase()}` : ""}`;
}

function normalizeDockerPlatformIdentity(platform) {
  const parts = String(platform || "").trim().toLowerCase().split("/");
  if (parts.length < 2 || parts.length > 3 || parts.some(part => !part)) return "";
  const architecture = {
    "x86-64": "amd64",
    x86_64: "amd64",
    aarch64: "arm64",
  }[parts[1]] || parts[1];
  const variant = architecture === "arm64" && parts[2] === "v8" ? "" : parts[2] || "";
  return `${parts[0]}/${architecture}${variant ? `/${variant}` : ""}`;
}

function getPackageLookupKeys(name, ecosystemOrFormat, identifiers) {
  const format = canonicalFormat(ecosystemOrFormat);
  const rawName = sanitizePackageNameInput(name);
  if (!rawName) {
    return [];
  }

  if (format === "maven") {
    const artifactId = rawName.includes(":") ? rawName.split(":").slice(1).join(":") : rawName;
    const keys = [normalizePackageName(rawName, format)];
    if (artifactId) {
      keys.push(normalizePackageName(artifactId, format));
    }
    if (identifiers && identifiers.group_id) {
      keys.push(normalizePackageName(`${identifiers.group_id}:${rawName}`, format));
    }
    return [...new Set(keys.filter(Boolean))];
  }

  if (format === "docker") {
    return buildDockerLookupKeys(rawName);
  }

  if (format === "swift") {
    const scope = sanitizePackageNameInput(identifiers && identifiers.scope);
    const identity = normalizeSwiftIdentity(rawName, scope);
    const unscoped = swiftUnscopedName(identity);
    return [...new Set([identity, unscoped].filter(Boolean))];
  }

  return [normalizePackageName(rawName, format)];
}

function getCloudsmithPackageLookupKeys(pkg, ecosystemOrFormat) {
  if (!pkg || typeof pkg !== "object") {
    return [];
  }

  const format = canonicalFormat(ecosystemOrFormat || pkg.format);
  if (format === "swift") {
    const identifiers = pkg.identifiers && typeof pkg.identifiers === "object"
      ? pkg.identifiers
      : {};
    const scope = sanitizePackageNameInput(pkg.scope || identifiers.scope);
    return [normalizeSwiftIdentity(pkg.name, scope)].filter(Boolean);
  }

  if (format !== "maven") {
    return getPackageLookupKeys(pkg.name, format);
  }

  const identifiers = pkg.identifiers && typeof pkg.identifiers === "object" ? pkg.identifiers : {};
  const keys = [normalizePackageName(pkg.name, format)];
  if (identifiers.group_id) {
    keys.push(normalizePackageName(`${identifiers.group_id}:${pkg.name}`, format));
  }
  return [...new Set(keys.filter(Boolean))];
}

function normalizeSwiftIdentity(name, scope) {
  const rawName = sanitizePackageNameInput(name);
  const rawScope = sanitizePackageNameInput(scope);
  if (!rawName) return "";
  const normalizedName = rawName.toLowerCase().replace(/^\/+|\/+$/g, "");
  if (!rawScope) {
    const slashIndex = normalizedName.indexOf("/");
    if (slashIndex > 0) return normalizedName;
    const dotIndex = normalizedName.indexOf(".");
    return dotIndex > 0
      ? `${normalizedName.slice(0, dotIndex)}/${normalizedName.slice(dotIndex + 1)}`
      : normalizedName;
  }
  const normalizedScope = rawScope.toLowerCase().replace(/^\/+|\/+$/g, "");
  if (!normalizedScope) return normalizedName;
  if (
    normalizedName.startsWith(`${normalizedScope}/`)
    || normalizedName.startsWith(`${normalizedScope}.`)
  ) {
    return `${normalizedScope}/${normalizedName.slice(normalizedScope.length + 1)}`;
  }
  return `${normalizedScope}/${normalizedName}`;
}

function swiftUnscopedName(identity) {
  const normalized = sanitizePackageNameInput(identity).toLowerCase();
  if (!normalized) return "";
  const slashIndex = normalized.lastIndexOf("/");
  const separatorIndex = slashIndex >= 0 ? slashIndex : normalized.indexOf(".");
  return separatorIndex >= 0 ? normalized.slice(separatorIndex + 1) : normalized;
}

function buildDockerLookupKeys(name) {
  const raw = normalizePackageName(String(name || "").replace(/^\/+/, ""), "docker").replace(/^\/+/, "");
  if (!raw) {
    return [];
  }

  const segments = raw.split("/").filter(Boolean);
  const keys = new Set([raw]);
  const firstSegment = segments[0] || "";
  const hasExplicitRegistry = segments.length > 1 && (firstSegment.includes(".") || firstSegment.includes(":") || firstSegment === "localhost");

  if (!hasExplicitRegistry) {
    if (segments.length === 1) {
      keys.add(`library/${segments[0]}`);
      keys.add(`docker.io/library/${segments[0]}`);
      keys.add(`index.docker.io/library/${segments[0]}`);
    } else {
      keys.add(`docker.io/${raw}`);
      keys.add(`index.docker.io/${raw}`);
      if (raw.startsWith("library/")) {
        keys.add(raw.slice("library/".length));
      }
    }
    return [...keys];
  }

  const pathPart = segments.slice(1).join("/");
  if (["docker.io", "index.docker.io", "registry-1.docker.io"].includes(firstSegment) && pathPart) {
    keys.add(pathPart);
    keys.add(`docker.io/${pathPart}`);
    if (pathPart.startsWith("library/")) {
      keys.add(pathPart.slice("library/".length));
    }
  }

  return [...keys];
}

module.exports = {
  ECOSYSTEM_TO_FORMAT,
  canonicalFormat,
  getCloudsmithPackageLookupKeys,
  getPackageLookupKeys,
  normalizePackageName,
  normalizeNuGetVersion,
  normalizeDockerPlatformIdentity,
  normalizeSwiftIdentity,
  sanitizePackageNameInput,
};

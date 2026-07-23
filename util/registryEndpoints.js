// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const {
  canonicalFormat,
  sanitizePackageNameInput,
} = require("./packageNameNormalizer");

const CLOUDSMITH_HOST_SUFFIX = ".cloudsmith.io";
const MAX_REGISTRY_VALUE_LENGTH = 4096;

const UNSUPPORTED_PULL_FORMATS = new Set([
  "alpine",
  "conda",
  "deb",
  "generic",
  "huggingface",
  "raw",
  "rpm",
]);

const DOCKER_MANIFEST_ACCEPT =
  "application/vnd.docker.distribution.manifest.v2+json, "
  + "application/vnd.docker.distribution.manifest.list.v2+json, "
  + "application/vnd.oci.image.manifest.v1+json, "
  + "application/vnd.oci.image.index.v1+json";

function formatForEcosystem(ecosystemOrFormat) {
  const normalized = canonicalFormat(ecosystemOrFormat);
  return normalized || null;
}

function formatForDependency(dependency) {
  return formatForEcosystem(dependency && (dependency.format || dependency.ecosystem));
}

function isPullUnsupportedFormat(format) {
  const normalized = formatForEcosystem(format);
  return Boolean(normalized && UNSUPPORTED_PULL_FORMATS.has(normalized));
}

function encodePathSegment(value) {
  const normalized = String(value == null ? "" : value)
    .replace(/\0/g, "")
    .trim();

  if (!normalized || normalized.length > MAX_REGISTRY_VALUE_LENGTH) {
    return "";
  }

  if (normalized === ".") {
    return "%2E";
  }

  if (normalized === "..") {
    return "%2E%2E";
  }

  return encodeURIComponent(normalized);
}

function encodePath(value) {
  return String(value == null ? "" : value)
    .replace(/\0/g, "")
    .trim()
    .split("/")
    .filter(Boolean)
    .map((segment) => encodePathSegment(segment))
    .join("/");
}

function normalizePythonName(name) {
  return sanitizePackageNameInput(name).toLowerCase().replace(/[-_.]+/g, "-");
}

function encodeGoModulePath(modulePath) {
  return [...String(modulePath || "")]
    .map((character) => {
      if (character === "!") {
        return "!!";
      }
      if (character >= "A" && character <= "Z") {
        return `!${character.toLowerCase()}`;
      }
      return character;
    })
    .join("");
}

function cargoIndexPath(crateName) {
  const normalized = String(crateName || "").trim().toLowerCase();
  if (!normalized) {
    return null;
  }

  if (normalized.length <= 2) {
    return encodePathSegment(normalized);
  }

  if (normalized.length === 3) {
    return `1/${encodePathSegment(normalized)}`;
  }

  return [
    encodePathSegment(normalized.slice(0, 2)),
    encodePathSegment(normalized.slice(2, 4)),
    encodePathSegment(normalized),
  ].join("/");
}

function buildNpmPackagePath(name) {
  const rawName = sanitizePackageNameInput(name);
  if (!rawName) {
    return null;
  }

  if (!rawName.startsWith("@")) {
    if (rawName.includes("/")) {
      return null;
    }

    const encodedName = encodePathSegment(rawName);
    return {
      segments: [encodedName],
      tarballBaseName: encodedName,
    };
  }

  const separatorIndex = rawName.indexOf("/");
  if (
    separatorIndex <= 1
    || separatorIndex === rawName.length - 1
    || rawName.indexOf("/", separatorIndex + 1) !== -1
  ) {
    return null;
  }

  const scope = rawName.slice(0, separatorIndex);
  const packageName = rawName.slice(separatorIndex + 1);

  return {
    segments: [encodePathSegment(scope), encodePathSegment(packageName)],
    tarballBaseName: encodePathSegment(packageName),
  };
}

function buildMavenCoordinates(dependency) {
  const name = sanitizePackageNameInput(dependency && dependency.name);
  const version = String(dependency && dependency.version || "")
    .replace(/\0/g, "")
    .trim();
  const coordinates = name.split(":", 3);

  if (coordinates.length < 2 || !version) {
    return null;
  }

  const groupId = coordinates[0].trim();
  const artifactId = coordinates[1].trim();
  if (!groupId || !artifactId) {
    return null;
  }

  const groupPath = groupId
    .split(".")
    .filter(Boolean)
    .map((segment) => encodePathSegment(segment))
    .join("/");

  if (!groupPath) {
    return null;
  }

  return {
    groupPath,
    artifactId: encodePathSegment(artifactId),
    version: encodePathSegment(version),
  };
}

function buildComposerCoordinates(name) {
  const rawName = sanitizePackageNameInput(name);
  const separatorIndex = rawName.indexOf("/");
  if (
    separatorIndex <= 0
    || separatorIndex === rawName.length - 1
    || rawName.indexOf("/", separatorIndex + 1) !== -1
  ) {
    return null;
  }

  const vendor = rawName.slice(0, separatorIndex);
  const packageName = rawName.slice(separatorIndex + 1);

  return {
    vendor: encodePathSegment(vendor),
    package: encodePathSegment(packageName),
    packageName: `${vendor}/${packageName}`,
  };
}

function buildSwiftCoordinates(name) {
  const parts = sanitizePackageNameInput(name).split("/").filter(Boolean);
  if (parts.length < 2) {
    return null;
  }

  return {
    scope: parts.slice(0, -1).map((part) => encodePathSegment(part)).join("/"),
    name: encodePathSegment(parts[parts.length - 1]),
  };
}

function buildRegistryTriggerPlan(workspace, repo, dependency) {
  const format = formatForDependency(dependency);
  if (!format || isPullUnsupportedFormat(format)) {
    return null;
  }

  const safeWorkspace = encodePathSegment(workspace);
  const safeRepo = encodePathSegment(repo);
  const version = encodePathSegment(dependency && dependency.version);

  switch (format) {
    case "maven": {
      const coordinates = buildMavenCoordinates(dependency);
      if (!coordinates) {
        return null;
      }
      return {
        format,
        strategy: "direct",
        request: {
          method: "GET",
          url: `https://dl.cloudsmith.io/basic/${safeWorkspace}/${safeRepo}/maven/${coordinates.groupPath}/${coordinates.artifactId}/${coordinates.version}/${coordinates.artifactId}-${coordinates.version}.pom`,
          headers: {},
        },
      };
    }
    case "npm": {
      const packagePath = buildNpmPackagePath(dependency && dependency.name);
      if (!packagePath || !version) {
        return null;
      }
      return {
        format,
        strategy: "direct",
        request: {
          method: "GET",
          url: `https://npm.cloudsmith.io/${safeWorkspace}/${safeRepo}/${packagePath.segments.join("/")}/-/${packagePath.tarballBaseName}-${version}.tgz`,
          headers: {},
        },
      };
    }
    case "python": {
      const normalizedName = normalizePythonName(dependency && dependency.name);
      if (!normalizedName) {
        return null;
      }
      return {
        format,
        strategy: "python-simple-index",
        request: {
          method: "GET",
          url: `https://dl.cloudsmith.io/basic/${safeWorkspace}/${safeRepo}/python/simple/${encodePathSegment(normalizedName)}/`,
          headers: {},
        },
      };
    }
    case "go": {
      const modulePath = encodeGoModulePath(String(dependency && dependency.name || "").trim());
      if (!modulePath || !version) {
        return null;
      }
      return {
        format,
        strategy: "direct",
        request: {
          method: "GET",
          url: `https://golang.cloudsmith.io/${safeWorkspace}/${safeRepo}/${modulePath}/@v/${version}.info`,
          headers: {},
        },
      };
    }
    case "cargo": {
      const indexPath = cargoIndexPath(dependency && dependency.name);
      if (!indexPath) {
        return null;
      }
      return {
        format,
        strategy: "direct",
        request: {
          method: "GET",
          url: `https://cargo.cloudsmith.io/${safeWorkspace}/${safeRepo}/${indexPath}`,
          headers: {},
        },
      };
    }
    case "ruby": {
      const name = encodePathSegment(dependency && dependency.name);
      if (!name || !version) {
        return null;
      }
      return {
        format,
        strategy: "direct",
        request: {
          method: "GET",
          url: `https://dl.cloudsmith.io/basic/${safeWorkspace}/${safeRepo}/ruby/gems/${name}-${version}.gem`,
          headers: {},
        },
      };
    }
    case "nuget": {
      const name = encodePathSegment(dependency && dependency.name);
      if (!name || !version) {
        return null;
      }
      return {
        format,
        strategy: "direct",
        request: {
          method: "GET",
          url: `https://nuget.cloudsmith.io/${safeWorkspace}/${safeRepo}/v3/package/${name}/${version}/${name}.${version}.nupkg`,
          headers: {},
        },
      };
    }
    case "docker": {
      const image = encodePath(dependency && dependency.name);
      if (!image || !version) {
        return null;
      }
      return {
        format,
        strategy: "direct",
        request: {
          method: "GET",
          url: `https://docker.cloudsmith.io/v2/${safeWorkspace}/${safeRepo}/${image}/manifests/${version}`,
          headers: {
            Accept: DOCKER_MANIFEST_ACCEPT,
          },
        },
      };
    }
    case "helm": {
      const name = encodePathSegment(dependency && dependency.name);
      if (!name || !version) {
        return null;
      }
      return {
        format,
        strategy: "direct",
        request: {
          method: "GET",
          url: `https://dl.cloudsmith.io/basic/${safeWorkspace}/${safeRepo}/helm/charts/${name}-${version}.tgz`,
          headers: {},
        },
      };
    }
    case "dart": {
      const name = encodePathSegment(dependency && dependency.name);
      if (!name) {
        return null;
      }
      return {
        format,
        strategy: "dart-api",
        request: {
          method: "GET",
          url: `https://dart.cloudsmith.io/${safeWorkspace}/${safeRepo}/api/packages/${name}`,
          headers: {},
        },
      };
    }
    case "composer": {
      const coordinates = buildComposerCoordinates(dependency && dependency.name);
      if (!coordinates) {
        return null;
      }
      return {
        format,
        strategy: "composer-p2",
        packageName: coordinates.packageName,
        request: {
          method: "GET",
          url: `https://composer.cloudsmith.io/${safeWorkspace}/${safeRepo}/p2/${coordinates.vendor}/${coordinates.package}.json`,
          headers: {},
        },
      };
    }
    case "hex": {
      const name = encodePathSegment(dependency && dependency.name);
      if (!name || !version) {
        return null;
      }
      return {
        format,
        strategy: "direct",
        request: {
          method: "GET",
          url: `https://dl.cloudsmith.io/basic/${safeWorkspace}/${safeRepo}/hex/tarballs/${name}-${version}.tar`,
          headers: {},
        },
      };
    }
    case "swift": {
      const coordinates = buildSwiftCoordinates(dependency && dependency.name);
      if (!coordinates || !coordinates.scope || !coordinates.name || !version) {
        return null;
      }
      return {
        format,
        strategy: "direct",
        request: {
          method: "GET",
          url: `https://dl.cloudsmith.io/basic/${safeWorkspace}/${safeRepo}/swift/${coordinates.scope}/${coordinates.name}/${version}.zip`,
          headers: {},
        },
      };
    }
    default:
      return null;
  }
}

function isTrustedCloudsmithHost(host) {
  const normalizedHost = String(host || "").trim().toLowerCase();
  return normalizedHost === "cloudsmith.io" || normalizedHost.endsWith(CLOUDSMITH_HOST_SUFFIX);
}

function isTrustedRegistryUrl(candidateUrl) {
  try {
    const parsed = new URL(candidateUrl);
    return parsed.protocol === "https:" && isTrustedCloudsmithHost(parsed.host);
  } catch {
    return false;
  }
}

function resolveAndValidateRegistryUrl(candidate, baseUrl) {
  if (!candidate) {
    return null;
  }

  let resolved;
  try {
    resolved = new URL(candidate, baseUrl);
  } catch {
    return null;
  }

  if (!isTrustedRegistryUrl(resolved.toString())) {
    return null;
  }

  return resolved.toString();
}

function collectHrefValues(html) {
  const hrefs = [];
  const pattern = /<a\b[^>]*\bhref\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/gi;
  let match = pattern.exec(String(html || ""));

  while (match) {
    hrefs.push(match[1] || match[2] || match[3] || "");
    match = pattern.exec(String(html || ""));
  }

  return hrefs.filter(Boolean);
}

function scorePythonArtifact(url, version) {
  const normalizedVersion = String(version || "").trim().toLowerCase();
  const fileName = decodeURIComponent(String(url || "").split("/").pop() || "").toLowerCase();

  if (!fileName) {
    return -1;
  }

  let score = 0;
  if (normalizedVersion) {
    if (!fileName.includes(normalizedVersion)) {
      return -1;
    }
    score += 10;
  }

  if (fileName.endsWith(".whl")) {
    score += 2;
  } else if (fileName.endsWith(".tar.gz") || fileName.endsWith(".zip")) {
    score += 1;
  }

  return score;
}

function findPythonDistributionUrl(html, version, baseUrl) {
  const candidates = collectHrefValues(html)
    .map((href) => resolveAndValidateRegistryUrl(href, baseUrl))
    .filter(Boolean)
    .map((url) => ({
      url,
      score: scorePythonArtifact(url, version),
    }))
    .filter((candidate) => candidate.score >= 0)
    .sort((left, right) => right.score - left.score || left.url.localeCompare(right.url));

  return candidates.length > 0 ? candidates[0].url : null;
}

function parseDartArchiveUrl(body, version, baseUrl) {
  let payload;
  try {
    payload = JSON.parse(String(body || ""));
  } catch {
    return null;
  }

  const wantedVersion = String(version || "").trim();
  const candidates = [];

  if (payload && payload.latest && payload.latest.version === wantedVersion && payload.latest.archive_url) {
    candidates.push(payload.latest.archive_url);
  }

  if (Array.isArray(payload && payload.versions)) {
    for (const entry of payload.versions) {
      if (entry && entry.version === wantedVersion && entry.archive_url) {
        candidates.push(entry.archive_url);
      }
    }
  } else if (payload && payload.versions && typeof payload.versions === "object") {
    const entry = payload.versions[wantedVersion];
    if (entry && entry.archive_url) {
      candidates.push(entry.archive_url);
    }
  }

  if (payload && payload.version === wantedVersion && payload.archive_url) {
    candidates.push(payload.archive_url);
  }

  for (const candidate of candidates) {
    const resolved = resolveAndValidateRegistryUrl(candidate, baseUrl);
    if (resolved) {
      return resolved;
    }
  }

  return null;
}

function parseComposerDistUrl(body, packageName, version, baseUrl) {
  let payload;
  try {
    payload = JSON.parse(String(body || ""));
  } catch {
    return null;
  }

  const entries = [];
  const normalizedPackageName = sanitizePackageNameInput(packageName);

  if (payload && payload.packages && typeof payload.packages === "object") {
    if (Array.isArray(payload.packages[normalizedPackageName])) {
      entries.push(...payload.packages[normalizedPackageName]);
    } else {
      for (const value of Object.values(payload.packages)) {
        if (Array.isArray(value)) {
          entries.push(...value);
        }
      }
    }
  }

  if (Array.isArray(payload)) {
    entries.push(...payload);
  }

  const matchedEntry = entries.find((entry) => entry && entry.version === version)
    || entries.find(Boolean);
  const distUrl = matchedEntry
    && matchedEntry.dist
    && typeof matchedEntry.dist === "object"
    ? matchedEntry.dist.url
    : null;

  return resolveAndValidateRegistryUrl(distUrl, baseUrl);
}

module.exports = {
  buildRegistryTriggerPlan,
  findPythonDistributionUrl,
  formatForDependency,
  isPullUnsupportedFormat,
  isTrustedRegistryUrl,
  parseComposerDistUrl,
  parseDartArchiveUrl,
  resolveAndValidateRegistryUrl,
};

// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const {
  canonicalFormat,
  sanitizePackageNameInput,
} = require("./packageNameNormalizer");

const MAX_REGISTRY_VALUE_LENGTH = 4096;
const TRUSTED_REGISTRY_HOSTS = new Set([
  "cargo.cloudsmith.io",
  "composer.cloudsmith.io",
  "dart.cloudsmith.io",
  "dl.cloudsmith.io",
  "docker.cloudsmith.io",
  "golang.cloudsmith.io",
  "npm.cloudsmith.io",
  "nuget.cloudsmith.io",
]);

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
  const raw = String(value == null ? "" : value);
  const normalized = raw.trim();

  if (
    !normalized
    || normalized !== raw
    || normalized.length > MAX_REGISTRY_VALUE_LENGTH
    || /[\u0000-\u001f\u007f\\/?#]/.test(normalized)
  ) {
    return "";
  }

  let decoded = normalized;
  for (let depth = 0; depth < 3; depth += 1) {
    let next;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      return "";
    }
    if (next === decoded) {
      break;
    }
    decoded = next;
  }
  if (decoded === "." || decoded === ".." || /[\u0000-\u001f\u007f\\/?#]/.test(decoded)) {
    return "";
  }

  return encodeURIComponent(normalized);
}

function encodePath(value) {
  const raw = String(value == null ? "" : value);
  if (!raw || raw !== raw.trim() || /[\\?#\u0000-\u001f\u007f]/.test(raw)) {
    return "";
  }
  const segments = raw.split("/");
  if (segments.some(segment => !segment)) {
    return "";
  }
  const encoded = segments.map(encodePathSegment);
  return encoded.every(Boolean) ? encoded.join("/") : "";
}

function normalizePythonName(name) {
  return sanitizePackageNameInput(name).toLowerCase().replace(/[-_.]+/g, "-");
}

function encodeGoModulePath(modulePath) {
  const raw = String(modulePath || "");
  if (!raw || raw !== raw.trim() || /[\\?#\u0000-\u001f\u007f]/.test(raw)) {
    return "";
  }
  const segments = raw.split("/");
  if (segments.some(segment => !encodePathSegment(segment))) {
    return "";
  }
  return segments.map(segment => encodePathSegment(
    [...segment]
      .map((character) => {
        if (character === "!") return "!!";
        if (character >= "A" && character <= "Z") return `!${character.toLowerCase()}`;
        return character;
      })
      .join("")
  )).join("/");
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

  const groupSegments = groupId.split(".").map(segment => encodePathSegment(segment));
  const encodedArtifactId = encodePathSegment(artifactId);
  const encodedVersion = encodePathSegment(version);
  if (!groupSegments.every(Boolean) || !encodedArtifactId || !encodedVersion) {
    return null;
  }

  return {
    groupPath: groupSegments.join("/"),
    artifactId: encodedArtifactId,
    version: encodedVersion,
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
  const rawName = sanitizePackageNameInput(name);
  const parts = rawName.split("/");
  if (parts.length < 2 || parts.some(part => !encodePathSegment(part))) {
    return null;
  }

  return {
    scope: parts.slice(0, -1).map((part) => encodePathSegment(part)).join("/"),
    name: encodePathSegment(parts[parts.length - 1]),
  };
}

function buildRegistryTriggerPlanUnchecked(workspace, repo, dependency) {
  const format = formatForDependency(dependency);
  if (!format || isPullUnsupportedFormat(format)) {
    return null;
  }

  const safeWorkspace = encodePathSegment(workspace);
  const safeRepo = encodePathSegment(repo);
  const version = encodePathSegment(dependency && dependency.version);
  if (!safeWorkspace || !safeRepo) {
    return null;
  }

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

function buildRegistryTriggerPlan(workspace, repo, dependency) {
  const safeWorkspace = encodePathSegment(workspace);
  const safeRepo = encodePathSegment(repo);
  const rawName = String(dependency && dependency.name || "");
  const rawVersion = String(dependency && dependency.version || "");
  if (
    !safeWorkspace
    || !safeRepo
    || !rawName
    || /[\u0000-\u001f\u007f\\?#]/.test(rawName)
    || /[\u0000-\u001f\u007f\\/?#]/.test(rawVersion)
    || rawName.split("/").some(segment => segment === "." || segment === ".." || segment === "")
  ) {
    return null;
  }
  const plan = buildRegistryTriggerPlanUnchecked(workspace, repo, dependency);
  if (!plan || !plan.request || typeof plan.request.url !== "string") {
    return null;
  }

  let parsed;
  try {
    parsed = new URL(plan.request.url);
  } catch {
    return null;
  }
  if (!isTrustedRegistryUrl(parsed.toString()) || parsed.search || parsed.hash) {
    return null;
  }
  const expectedPrefix = parsed.hostname === "docker.cloudsmith.io"
    ? `/v2/${safeWorkspace}/${safeRepo}/`
    : parsed.hostname === "dl.cloudsmith.io"
      ? `/basic/${safeWorkspace}/${safeRepo}/`
      : `/${safeWorkspace}/${safeRepo}/`;
  if (!parsed.pathname.startsWith(expectedPrefix)) {
    return null;
  }
  const remainingSegments = parsed.pathname.slice(expectedPrefix.length).split("/");
  if (remainingSegments[remainingSegments.length - 1] === "") {
    if (plan.strategy !== "python-simple-index") {
      return null;
    }
    remainingSegments.pop();
  }
  return remainingSegments.length > 0 && remainingSegments.every(Boolean) ? plan : null;
}

function isTrustedCloudsmithHost(host) {
  const normalizedHost = String(host || "").trim().toLowerCase();
  return TRUSTED_REGISTRY_HOSTS.has(normalizedHost);
}

function isTrustedRegistryUrl(candidateUrl) {
  try {
    const parsed = new URL(candidateUrl);
    return parsed.protocol === "https:"
      && parsed.origin === `https://${parsed.hostname}`
      && parsed.port === ""
      && parsed.username === ""
      && parsed.password === ""
      && parsed.hash === ""
      && isTrustedCloudsmithHost(parsed.hostname);
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
  const source = String(html || "");
  const lower = source.toLowerCase();
  const hrefs = [];
  const maximumTagLength = 4096;
  const maximumCandidates = 500;
  let cursor = 0;

  while (cursor < source.length && hrefs.length < maximumCandidates) {
    const anchorStart = lower.indexOf("<a", cursor);
    if (anchorStart < 0) {
      break;
    }
    const boundary = lower[anchorStart + 2];
    if (boundary && !/[\s/>]/.test(boundary)) {
      cursor = anchorStart + 2;
      continue;
    }

    let tagEnd = anchorStart + 2;
    const tagLimit = Math.min(source.length, anchorStart + maximumTagLength + 1);
    while (tagEnd < tagLimit && source[tagEnd] !== "<" && source[tagEnd] !== ">") {
      tagEnd += 1;
    }
    if (tagEnd >= source.length) {
      break;
    }
    if (source[tagEnd] === "<") {
      cursor = tagEnd;
      continue;
    }
    if (tagEnd >= tagLimit) {
      cursor = tagEnd;
      continue;
    }

    const tag = source.slice(anchorStart, tagEnd + 1);
    const match = /\bhref\s*=\s*(?:"([^"<>]{1,4096})"|'([^'<>]{1,4096})'|([^\s<>]{1,4096}))/i.exec(tag);
    const href = match && (match[1] || match[2] || match[3]);
    if (href) {
      hrefs.push(href);
    }
    cursor = tagEnd + 1;
  }

  return hrefs;
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

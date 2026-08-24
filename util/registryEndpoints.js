// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const {
  canonicalFormat,
  normalizeNuGetVersion,
  sanitizePackageNameInput,
} = require("./packageNameNormalizer");

const MAX_REGISTRY_VALUE_LENGTH = 4096;
const MAX_REGISTRY_URL_LENGTH = 16384;
const MAX_REGISTRY_DECODE_DEPTH = 8;
const REGISTRY_CONTROL_OR_BIDI = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u;
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

const NPM_PACKUMENT_ACCEPT = "application/vnd.npm.install-v1+json, application/json";
const DART_PACKAGE_ACCEPT = "application/vnd.pub.v2+json";
const MAX_DOCKER_MANIFEST_DESCRIPTORS = 256;
const DOCKER_DIGEST_PATTERN = /^([a-z0-9_+.-]+):([a-f0-9]{32,512})$/i;
const DOCKER_BLOB_REDIRECT_HOST_SUFFIXES = Object.freeze([
  ".amazonaws.com",
  ".cloudfront.net",
]);

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
    || REGISTRY_CONTROL_OR_BIDI.test(normalized)
    || /[\\/?#]/.test(normalized)
  ) {
    return "";
  }

  const decoded = repeatedlyDecode(normalized);
  if (
    decoded == null
    || decoded === "."
    || decoded === ".."
    || REGISTRY_CONTROL_OR_BIDI.test(decoded)
    || /[\\/?#]/.test(decoded)
  ) {
    return "";
  }

  return encodeURIComponent(normalized);
}

function encodePath(value) {
  const raw = String(value == null ? "" : value);
  if (!raw || raw !== raw.trim() || REGISTRY_CONTROL_OR_BIDI.test(raw) || /[\\?#]/.test(raw)) {
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

function encodeGoVersion(version) {
  const raw = String(version || "");
  if (!raw || raw !== raw.trim()) {
    return "";
  }
  return encodePathSegment([...raw]
    .map((character) => {
      if (character === "!") return "!!";
      if (character >= "A" && character <= "Z") return `!${character.toLowerCase()}`;
      return character;
    })
    .join(""));
}

function cargoIndexPath(crateName) {
  const normalized = String(crateName || "").trim().toLowerCase();
  const encodedName = encodePathSegment(normalized);
  if (!encodedName) {
    return null;
  }
  const prefix = cargoPrefix(normalized);
  return prefix ? `${prefix}/${encodedName}` : null;
}

function cargoPrefix(crateName, lowercase = false) {
  const raw = String(crateName || "").trim();
  const name = lowercase ? raw.toLowerCase() : raw;
  if (!encodePathSegment(name)) return null;
  if (name.length === 1) return "1";
  if (name.length === 2) return "2";
  if (name.length === 3) return `3/${encodePathSegment(name.slice(0, 1))}`;
  return `${encodePathSegment(name.slice(0, 2))}/${encodePathSegment(name.slice(2, 4))}`;
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
      packumentPath: encodedName,
      packageName: rawName,
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
    // npm's registry route treats the complete scoped name as one encoded
    // package identifier. The slash is identity here, not a path boundary.
    packumentPath: encodeURIComponent(`${scope}/${packageName}`),
    packageName: `${scope}/${packageName}`,
  };
}

function normalizeDockerImageName(name) {
  const raw = sanitizePackageNameInput(name).replace(/^\/+|\/+$/g, "").toLowerCase();
  if (!raw) {
    return "";
  }

  const segments = raw.split("/");
  if (segments.some(segment => !encodePathSegment(segment))) {
    return "";
  }

  if (["docker.io", "index.docker.io", "registry-1.docker.io"].includes(segments[0])) {
    segments.shift();
  }
  if (segments.length === 1) {
    segments.unshift("library");
  }

  return segments.join("/");
}

function dockerCandidateMatchesPlatform(candidate, platform) {
  const requested = parseDockerPlatform(platform);
  if (!requested) return !String(platform || "").trim();
  const identifiers = candidate?.identifiers && typeof candidate.identifiers === "object"
    ? candidate.identifiers
    : {};
  const observedPlatforms = collectCandidateArchitectureValues(candidate)
    .map(parseDockerPlatform)
    .filter(Boolean);
  const architecture = normalizeDockerArchitecture(
    candidate?.architecture || identifiers.architecture
  );
  const os = String(
    candidate?.os || candidate?.platform_os || identifiers.docker_platform_os || ""
  ).trim().toLowerCase();
  const variant = String(
    candidate?.variant || identifiers.docker_platform_variant || ""
  ).trim().toLowerCase();
  if (architecture && os) {
    observedPlatforms.push({ os, architecture, variant });
  }
  return observedPlatforms.some(observed => (
    observed.os === requested.os
    && observed.architecture === requested.architecture
    && dockerVariantMatches(requested, observed)
  ));
}

function parseDockerPlatform(value) {
  const parts = String(value || "").trim().toLowerCase().split("/");
  if (parts.length < 2 || parts.length > 3 || parts.some(part => !part)) return null;
  return {
    os: parts[0],
    architecture: normalizeDockerArchitecture(parts[1]),
    variant: parts[2] || "",
  };
}

function normalizeDockerArchitecture(value) {
  const architecture = String(value || "").trim().toLowerCase();
  if (architecture === "x86_64" || architecture === "x86-64") return "amd64";
  if (architecture === "aarch64") return "arm64";
  return architecture;
}

function dockerVariantMatches(requested, observed) {
  if (!requested.variant) return true;
  if (observed.variant) return observed.variant === requested.variant;
  return requested.architecture === "arm64" && requested.variant === "v8";
}

function dockerDigestMatches(observedValue, requestedValue) {
  const observed = String(observedValue || "").trim().toLowerCase();
  const requested = String(requestedValue || "").trim().toLowerCase();
  if (!observed || !requested) return false;
  const split = value => {
    const match = value.match(DOCKER_DIGEST_PATTERN);
    if (match && isDockerDigest(value)) return { algorithm: match[1], digest: match[2] };
    if (!/^[a-f0-9]{32,512}$/.test(value)) return null;
    return {
      algorithm: value.length === 64 ? "sha256" : value.length === 128 ? "sha512" : "",
      digest: value,
    };
  };
  const observedDigest = split(observed);
  const requestedDigest = split(requested);
  if (!observedDigest || !requestedDigest) return false;
  if (
    observedDigest.algorithm !== requestedDigest.algorithm
    && (observedDigest.algorithm || requestedDigest.algorithm)
  ) {
    return false;
  }
  return observedDigest.digest === requestedDigest.digest;
}

function rubyCandidateMatchesPlatform(candidate, platform) {
  const requested = String(platform || "ruby").trim().toLowerCase() || "ruby";
  const observed = collectCandidateArchitectureValues(candidate)
    .map(value => String(value || "").trim().toLowerCase())
    .filter(Boolean);
  return requested === "ruby"
    ? observed.length === 0 || observed.includes("ruby")
    : observed.includes(requested);
}

function collectCandidateArchitectureValues(candidate) {
  const identifiers = candidate?.identifiers && typeof candidate.identifiers === "object"
    ? candidate.identifiers
    : {};
  const values = [
    candidate?.platform,
    candidate?.architecture,
    identifiers.platform,
    identifiers.architecture,
  ];
  if (Array.isArray(candidate?.architectures)) {
    for (const architecture of candidate.architectures) {
      values.push(architecture && typeof architecture === "object"
        ? architecture.name || architecture.slug || architecture.identifier
        : architecture);
    }
  }
  return values.filter(value => typeof value === "string" && value.trim());
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
  const qualifiers = dependency?.qualifiers || {};
  const type = String(qualifiers.type || "jar").trim().toLowerCase();
  const classifierValue = qualifiers.classifier || mavenDefaultClassifier(type);
  const classifier = classifierValue
    ? encodePathSegment(classifierValue)
    : "";
  const extension = mavenArtifactExtension(type);
  if (
    !groupSegments.every(Boolean)
    || !encodedArtifactId
    || !encodedVersion
    || (classifierValue && !classifier)
    || !extension
  ) {
    return null;
  }

  return {
    groupPath: groupSegments.join("/"),
    artifactId: encodedArtifactId,
    version: encodedVersion,
    classifier,
    extension,
  };
}

function mavenDefaultClassifier(type) {
  switch (type) {
    case "test-jar": return "tests";
    case "java-source": return "sources";
    case "javadoc": return "javadoc";
    case "ejb-client": return "client";
    default: return "";
  }
}

function mavenArtifactFileName(dependency, versionOverride = null) {
  const coordinates = buildMavenCoordinates(versionOverride == null ? dependency : {
    ...dependency,
    version: versionOverride,
  });
  if (!coordinates) {
    return "";
  }
  try {
    return decodeURIComponent(
      `${coordinates.artifactId}-${coordinates.version}`
      + `${coordinates.classifier ? `-${coordinates.classifier}` : ""}`
      + `.${coordinates.extension}`
    );
  } catch {
    return "";
  }
}

function mavenArtifactExtension(type) {
  if (!type || /[\u0000-\u001f\u007f\\/?#]/.test(type)) {
    return "";
  }
  if (["bundle", "ejb", "ejb-client", "java-source", "javadoc", "maven-plugin", "test-jar"].includes(type)) {
    return "jar";
  }
  return encodePathSegment(type);
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

function buildSwiftCoordinates(name, qualifiers = {}) {
  const rawName = sanitizePackageNameInput(name);
  const rawScope = sanitizePackageNameInput(qualifiers && qualifiers.scope);
  let scope = rawScope;
  let packageName = rawName;
  if (scope && (packageName.toLowerCase().startsWith(`${scope.toLowerCase()}.`)
    || packageName.toLowerCase().startsWith(`${scope.toLowerCase()}/`))) {
    packageName = packageName.slice(scope.length + 1);
  } else if (!scope) {
    const slashIndex = packageName.indexOf("/");
    const dotIndex = packageName.indexOf(".");
    const separatorIndex = slashIndex > 0 ? slashIndex : dotIndex;
    if (separatorIndex > 0) {
      scope = packageName.slice(0, separatorIndex);
      packageName = packageName.slice(separatorIndex + 1);
    }
  }
  const encodedScope = scope ? encodePathSegment(scope.toLowerCase()) : "";
  const encodedName = encodePathSegment(packageName.toLowerCase());
  if (!encodedScope || !encodedName) {
    return null;
  }

  return {
    scope: encodedScope,
    name: encodedName,
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
          url: `https://dl.cloudsmith.io/basic/${safeWorkspace}/${safeRepo}/maven/${coordinates.groupPath}/${coordinates.artifactId}/${coordinates.version}/${coordinates.artifactId}-${coordinates.version}${coordinates.classifier ? `-${coordinates.classifier}` : ""}.${coordinates.extension}`,
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
        strategy: "npm-packument",
        packageName: packagePath.packageName,
        trustScope: createRegistryTrustScope(workspace, repo),
        request: {
          method: "GET",
          url: `https://npm.cloudsmith.io/${safeWorkspace}/${safeRepo}/${packagePath.packumentPath}/${version}`,
          headers: {
            Accept: NPM_PACKUMENT_ACCEPT,
          },
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
        packageName: normalizedName,
        trustScope: createRegistryTrustScope(workspace, repo),
        request: {
          method: "GET",
          url: `https://dl.cloudsmith.io/basic/${safeWorkspace}/${safeRepo}/python/simple/${encodePathSegment(normalizedName)}/`,
          headers: {},
        },
      };
    }
    case "go": {
      const modulePath = encodeGoModulePath(String(dependency && dependency.name || "").trim());
      const goVersion = encodeGoVersion(dependency && dependency.version);
      if (!modulePath || !goVersion) {
        return null;
      }
      return {
        format,
        strategy: "direct",
        request: {
          method: "GET",
          url: `https://golang.cloudsmith.io/${safeWorkspace}/${safeRepo}/${modulePath}/@v/${goVersion}.zip`,
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
        strategy: "cargo-sparse-index",
        crateName: String(dependency && dependency.name || "").trim().toLowerCase(),
        trustScope: createRegistryTrustScope(workspace, repo),
        request: {
          method: "GET",
          url: `https://cargo.cloudsmith.io/${safeWorkspace}/${safeRepo}/${indexPath}`,
          headers: {
            Accept: "text/plain, application/octet-stream",
          },
        },
        configRequest: {
          method: "GET",
          url: `https://cargo.cloudsmith.io/${safeWorkspace}/${safeRepo}/config.json`,
          headers: {
            Accept: "application/json",
          },
        },
      };
    }
    case "ruby": {
      const name = encodePathSegment(dependency && dependency.name);
      const platformValue = dependency?.qualifiers?.platform || dependency?.platform;
      const platform = platformValue && String(platformValue).toLowerCase() !== "ruby"
        ? encodePathSegment(platformValue)
        : "";
      if (!name || !version) {
        return null;
      }
      return {
        format,
        strategy: "direct",
        request: {
          method: "GET",
          url: `https://dl.cloudsmith.io/basic/${safeWorkspace}/${safeRepo}/ruby/gems/${name}-${version}${platform ? `-${platform}` : ""}.gem`,
          headers: {},
        },
      };
    }
    case "nuget": {
      const normalizedName = sanitizePackageNameInput(dependency && dependency.name).toLowerCase();
      const normalizedVersion = normalizeNuGetVersion(dependency && dependency.version);
      const name = encodePathSegment(normalizedName);
      const packageVersion = encodePathSegment(normalizedVersion);
      if (!name || !packageVersion) {
        return null;
      }
      return {
        format,
        strategy: "nuget-service-index",
        packageName: name,
        packageVersion,
        trustScope: createRegistryTrustScope(workspace, repo),
        request: {
          method: "GET",
          url: `https://nuget.cloudsmith.io/${safeWorkspace}/${safeRepo}/v3/index.json`,
          headers: { Accept: "application/json" },
        },
      };
    }
    case "docker": {
      const image = encodePath(normalizeDockerImageName(dependency && dependency.name));
      const qualifiers = dependency?.qualifiers || dependency?.identifiers || {};
      const requestedDigest = String(qualifiers.digest || dependency?.digest || "").trim();
      if (requestedDigest && !isDockerDigest(requestedDigest)) {
        return null;
      }
      const reference = encodePathSegment(
        requestedDigest || qualifiers.tag || dependency?.version
      );
      if (!image || !reference) {
        return null;
      }
      return {
        format,
        strategy: "docker-manifest",
        imageBaseUrl: `https://docker.cloudsmith.io/v2/${safeWorkspace}/${safeRepo}/${image}`,
        request: {
          method: "GET",
          url: `https://docker.cloudsmith.io/v2/${safeWorkspace}/${safeRepo}/${image}/manifests/${reference}`,
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
        packageName: String(dependency && dependency.name || "").trim(),
        trustScope: createRegistryTrustScope(workspace, repo),
        request: {
          method: "GET",
          url: `https://dart.cloudsmith.io/${safeWorkspace}/${safeRepo}/api/packages/${name}`,
          authScheme: "bearer",
          headers: {
            Accept: DART_PACKAGE_ACCEPT,
          },
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
        trustScope: createRegistryTrustScope(workspace, repo),
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
      const coordinates = buildSwiftCoordinates(
        dependency && dependency.name,
        dependency && (dependency.qualifiers || dependency.identifiers)
      );
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

function createRegistryTrustScope(workspace, repo) {
  const normalizedWorkspace = String(workspace || "").trim();
  const normalizedRepository = String(repo || "").trim();
  if (!encodePathSegment(normalizedWorkspace) || !encodePathSegment(normalizedRepository)) {
    return null;
  }
  return Object.freeze({
    workspace: normalizedWorkspace,
    repository: normalizedRepository,
  });
}

function repeatedlyDecode(value) {
  let decoded = String(value || "");
  if (decoded.length > MAX_REGISTRY_URL_LENGTH) return null;
  for (let depth = 0; depth < MAX_REGISTRY_DECODE_DEPTH; depth += 1) {
    let next;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      return null;
    }
    if (next === decoded) {
      return decoded;
    }
    decoded = next;
  }
  return null;
}

function hasUnsafeRegistryPath(pathname) {
  const decoded = repeatedlyDecode(pathname);
  if (decoded == null || REGISTRY_CONTROL_OR_BIDI.test(decoded) || /\\/.test(decoded)) {
    return true;
  }
  return decoded.split("/").some(segment => segment === "." || segment === "..");
}

function decodedPathSegments(parsedUrl) {
  const segments = parsedUrl.pathname.split("/").filter(Boolean);
  const decoded = segments.map(repeatedlyDecode);
  return decoded.every(value => value != null) ? decoded : null;
}

function repositoryCoordinatesForUrl(parsedUrl) {
  const segments = decodedPathSegments(parsedUrl);
  if (!segments) {
    return null;
  }

  if (parsedUrl.hostname === "dl.cloudsmith.io") {
    if (segments.length < 3 || !["basic", "public", "signed"].includes(segments[0])) {
      return null;
    }
    return { workspace: segments[1], repository: segments[2] };
  }

  if (parsedUrl.hostname === "docker.cloudsmith.io") {
    if (segments.length < 3 || segments[0] !== "v2") {
      return null;
    }
    return { workspace: segments[1], repository: segments[2] };
  }

  if (segments.length < 2) {
    return null;
  }
  return { workspace: segments[0], repository: segments[1] };
}

function inferRegistryTrustScope(baseUrl) {
  let parsed;
  try {
    parsed = new URL(baseUrl);
  } catch {
    return null;
  }
  if (!isTrustedRegistryUrl(parsed.toString()) || hasUnsafeRegistryPath(parsed.pathname)) {
    return null;
  }
  const coordinates = repositoryCoordinatesForUrl(parsed);
  return coordinates
    ? createRegistryTrustScope(coordinates.workspace, coordinates.repository)
    : null;
}

function isSupportedArtifactHash(hash) {
  if (!hash) {
    return true;
  }
  const match = /^#([a-z0-9_+-]{1,32})=([a-f0-9]{16,256})$/i.exec(hash);
  return Boolean(match);
}

/**
 * Resolve a metadata-provided registry URL and constrain it to the selected
 * Cloudsmith workspace/repository. A valid Python index hash fragment may be
 * accepted and is stripped because URL fragments must never be sent over HTTP.
 */
function resolveAndValidateScopedRegistryUrl(candidate, baseUrl, trustScope, options = {}) {
  if (
    !candidate
    || String(candidate).length > MAX_REGISTRY_URL_LENGTH
    || String(baseUrl || "").length > MAX_REGISTRY_URL_LENGTH
  ) {
    return null;
  }

  let resolved;
  try {
    resolved = new URL(candidate, baseUrl);
  } catch {
    return null;
  }

  if (
    (resolved.search && !options.allowQuery)
    || (resolved.hash && (!options.allowHashFragment || !isSupportedArtifactHash(resolved.hash)))
    || hasUnsafeRegistryPath(resolved.pathname)
  ) {
    return null;
  }

  resolved.hash = "";
  if (!isTrustedRegistryUrl(resolved.toString())) {
    return null;
  }

  const expectedScope = trustScope || inferRegistryTrustScope(baseUrl);
  const actualScope = repositoryCoordinatesForUrl(resolved);
  if (
    !expectedScope
    || !actualScope
    || actualScope.workspace !== expectedScope.workspace
    || actualScope.repository !== expectedScope.repository
  ) {
    return null;
  }

  return resolved.toString();
}

function resolveAndValidateDockerBlobRedirectUrl(candidate, baseUrl) {
  if (
    !candidate
    || String(candidate).length > MAX_REGISTRY_URL_LENGTH
    || String(baseUrl || "").length > MAX_REGISTRY_URL_LENGTH
  ) return null;
  const rawCandidate = String(candidate);
  const rawPath = rawCandidate
    .replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]+/i, "")
    .split(/[?#]/, 1)[0];
  if (hasUnsafeRegistryPath(rawPath)) return null;
  let resolved;
  try {
    resolved = new URL(candidate, baseUrl);
  } catch {
    return null;
  }

  if (isTrustedRegistryUrl(resolved.toString())) {
    return resolveAndValidateScopedRegistryUrl(
      resolved.toString(),
      baseUrl,
      null,
      { allowQuery: true }
    );
  }

  const hostname = resolved.hostname.toLowerCase();
  if (
    resolved.protocol !== "https:"
    || resolved.port
    || resolved.username
    || resolved.password
    || resolved.hash
    || hasUnsafeRegistryPath(resolved.pathname)
    || !hostname.includes(".")
    || hostname.endsWith(".")
    || isLiteralIpHostname(hostname)
    || !isSafeDnsHostname(hostname)
    || hostname === "localhost"
    || hostname.endsWith(".localhost")
    || hostname.endsWith(".local")
    || hostname.endsWith(".internal")
    || hostname.endsWith(".home.arpa")
    || !DOCKER_BLOB_REDIRECT_HOST_SUFFIXES.some(suffix => hostname.endsWith(suffix))
  ) {
    return null;
  }
  return resolved.toString();
}

function isSafeDnsHostname(hostname) {
  return hostname.length <= 253 && hostname.split(".").every(label => (
    label.length > 0
    && label.length <= 63
    && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  ));
}

function isLiteralIpHostname(hostname) {
  if (hostname.startsWith("[") && hostname.endsWith("]")) return true;
  const parts = hostname.split(".");
  return parts.length === 4
    && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function isTrustedCloudsmithHost(host) {
  const normalizedHost = String(host || "").trim().toLowerCase();
  return TRUSTED_REGISTRY_HOSTS.has(normalizedHost);
}

function isTrustedRegistryUrl(candidateUrl) {
  if (String(candidateUrl || "").length > MAX_REGISTRY_URL_LENGTH) return false;
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

function normalizePythonFileNameIdentity(value) {
  return String(value || "").trim().toLowerCase().replace(/[-_.]+/g, "-");
}

function pythonArtifactIdentity(url) {
  let fileName;
  try {
    const parsed = new URL(url);
    fileName = decodeURIComponent(parsed.pathname.split("/").pop() || "");
  } catch {
    return null;
  }
  if (!fileName) {
    return null;
  }

  const lowerFileName = fileName.toLowerCase();
  if (lowerFileName.endsWith(".whl")) {
    const fields = fileName.slice(0, -4).split("-");
    if (fields.length < 5) {
      return null;
    }
    return {
      name: normalizePythonFileNameIdentity(fields[0]),
      version: normalizePythonFileNameIdentity(fields[1]),
      score: 2,
    };
  }

  const extension = lowerFileName.endsWith(".tar.gz")
    ? ".tar.gz"
    : lowerFileName.endsWith(".zip")
      ? ".zip"
      : "";
  if (!extension) {
    return null;
  }

  return {
    stem: fileName.slice(0, -extension.length),
    score: 1,
  };
}

function scorePythonArtifact(url, packageName, version) {
  const identity = pythonArtifactIdentity(url);
  const normalizedName = normalizePythonFileNameIdentity(packageName);
  const normalizedVersion = normalizePythonFileNameIdentity(version);
  if (!identity || !normalizedVersion) {
    return -1;
  }

  if (identity.stem != null) {
    const versionSuffix = `-${String(version || "").trim()}`.toLowerCase();
    if (!identity.stem.toLowerCase().endsWith(versionSuffix)) {
      return -1;
    }
    const distribution = identity.stem.slice(0, -versionSuffix.length);
    if (normalizedName && normalizePythonFileNameIdentity(distribution) !== normalizedName) {
      return -1;
    }
    return identity.score + 10;
  }

  if (
    identity.version !== normalizedVersion
    || (normalizedName && identity.name !== normalizedName)
  ) {
    return -1;
  }
  return identity.score + 10;
}

function findPythonDistributionUrl(html, packageName, version, baseUrl, trustScope) {
  const wantedName = sanitizePackageNameInput(packageName);
  const wantedVersion = String(version || "").trim();
  if (!wantedName || !wantedVersion || !baseUrl) return null;

  const candidates = collectHrefValues(html)
    .map((href) => resolveAndValidateScopedRegistryUrl(
      href,
      baseUrl,
      trustScope,
      { allowHashFragment: true }
    ))
    .filter(Boolean)
    .map((url) => ({
      url,
      score: scorePythonArtifact(url, wantedName, wantedVersion),
    }))
    .filter((candidate) => candidate.score >= 0)
    .sort((left, right) => right.score - left.score || left.url.localeCompare(right.url));

  return candidates.length > 0 ? candidates[0].url : null;
}

function parseNpmTarballUrl(body, packageName, version, baseUrl, trustScope) {
  let payload;
  try {
    payload = JSON.parse(String(body || ""));
  } catch {
    return null;
  }

  const wantedName = sanitizePackageNameInput(packageName).toLowerCase();
  const wantedVersion = String(version || "").trim();
  if (
    !wantedName
    || !wantedVersion
    || !payload
    || typeof payload !== "object"
    || Array.isArray(payload)
    || typeof payload.name !== "string"
    || payload.name.toLowerCase() !== wantedName
  ) {
    return null;
  }

  const entry = payload.version === wantedVersion
    ? payload
    : payload.versions
      && typeof payload.versions === "object"
      && !Array.isArray(payload.versions)
      && Object.prototype.hasOwnProperty.call(payload.versions, wantedVersion)
      ? payload.versions[wantedVersion]
      : null;
  if (
    !entry
    || typeof entry !== "object"
    || Array.isArray(entry)
    || entry.version !== wantedVersion
    || !entry.dist
    || typeof entry.dist !== "object"
  ) {
    return null;
  }

  return resolveAndValidateScopedRegistryUrl(
    entry.dist.tarball,
    baseUrl,
    trustScope
  );
}

function parseCargoIndexEntry(body, crateName, version) {
  const wantedName = String(crateName || "").trim().toLowerCase();
  const wantedVersion = String(version || "").trim();
  if (!wantedName || !wantedVersion) {
    return null;
  }

  const lines = String(body || "").split(/\r?\n/, 10001);
  if (lines.length > 10000) {
    return null;
  }
  for (const line of lines) {
    if (!line.trim()) {
      continue;
    }
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      continue;
    }
    if (
      entry
      && typeof entry === "object"
      && String(entry.name || "").toLowerCase() === wantedName
      && entry.vers === wantedVersion
      && /^[a-f0-9]{64}$/i.test(String(entry.cksum || ""))
    ) {
      return Object.freeze({
        name: String(entry.name),
        version: entry.vers,
        checksum: String(entry.cksum).toLowerCase(),
        yanked: Boolean(entry.yanked),
      });
    }
  }
  return null;
}

function parseCargoDownloadUrl(body, crateName, version, checksum, baseUrl, trustScope) {
  let payload;
  try {
    payload = JSON.parse(String(body || ""));
  } catch {
    return null;
  }

  const rawName = String(crateName || "").trim();
  const encodedName = encodePathSegment(rawName);
  const encodedVersion = encodePathSegment(version);
  const normalizedChecksum = String(checksum || "").trim().toLowerCase();
  if (
    !payload
    || typeof payload.dl !== "string"
    || !encodedName
    || !encodedVersion
    || !/^[a-f0-9]{64}$/.test(normalizedChecksum)
  ) {
    return null;
  }

  const prefix = cargoPrefix(rawName);
  const lowerPrefix = cargoPrefix(rawName, true);
  if (!prefix || !lowerPrefix) return null;
  const hadTemplateMarker = /\{(?:crate|version|prefix|lowerprefix|sha256-checksum)\}/.test(payload.dl);
  let candidate = payload.dl
    .replaceAll("{crate}", encodedName)
    .replaceAll("{version}", encodedVersion)
    .replaceAll("{prefix}", prefix)
    .replaceAll("{lowerprefix}", lowerPrefix)
    .replaceAll("{sha256-checksum}", normalizedChecksum);
  if (/\{[^{}]+\}/.test(candidate)) {
    return null;
  }
  if (!hadTemplateMarker) {
    candidate = `${candidate.replace(/\/$/, "")}/${encodedName}/${encodedVersion}/download`;
  }

  return resolveAndValidateScopedRegistryUrl(candidate, baseUrl, trustScope);
}

function parseDockerManifest(body, preferredPlatform = {}) {
  let payload;
  try {
    payload = JSON.parse(String(body || ""));
  } catch {
    return null;
  }

  if (!payload || payload.schemaVersion !== 2) {
    return null;
  }

  if (Array.isArray(payload.manifests)) {
    if (
      payload.manifests.length === 0
      || payload.manifests.length > MAX_DOCKER_MANIFEST_DESCRIPTORS
    ) {
      return null;
    }
    const requested = preferredDockerPlatform(preferredPlatform);
    if (!requested) {
      return null;
    }
    const candidates = payload.manifests.filter(entry => (
      entry
      && isDockerDigest(entry.digest)
      && entry.platform
      && typeof entry.platform === "object"
    ));
    const exact = candidates.find(entry => dockerPlatformValuesMatch(requested, entry.platform));
    const selected = exact || (requested.explicit ? null : candidates.find(entry => (
      String(entry.platform.os || "").toLowerCase() === "linux"
      && String(entry.platform.architecture || "").toLowerCase() === "amd64"
    ))) || (requested.explicit ? null : candidates[0]);
    return selected ? { manifestDigest: selected.digest, blobDigests: [] } : null;
  }

  const descriptors = [payload.config, ...(Array.isArray(payload.layers) ? payload.layers : [])];
  if (
    descriptors.length === 0
    || descriptors.length > MAX_DOCKER_MANIFEST_DESCRIPTORS
    || descriptors.some(entry => !entry || !isDockerDigest(entry.digest))
  ) {
    return null;
  }

  return {
    manifestDigest: null,
    blobDigests: [...new Set(descriptors.map(entry => entry.digest))],
  };
}

function preferredDockerPlatform(value) {
  const preferred = value && typeof value === "object" ? value : {};
  const platform = String(preferred.platform || "").trim().toLowerCase();
  if (platform) {
    const parsed = parseDockerPlatform(platform);
    if (!parsed) return null;
    return {
      ...parsed,
      explicit: true,
    };
  }

  const explicit = Boolean(preferred.os || preferred.architecture || preferred.arch || preferred.variant);
  const os = String(preferred.os || "linux").trim().toLowerCase();
  const architecture = normalizeDockerArchitecture(
    preferred.architecture || preferred.arch || "amd64"
  );
  const variant = String(preferred.variant || "").trim().toLowerCase();
  if (
    !os
    || !architecture
    || !/^[a-z0-9_.-]+$/.test(os)
    || !/^[a-z0-9_.-]+$/.test(architecture)
    || (variant && !/^[a-z0-9_.-]+$/.test(variant))
  ) {
    return null;
  }
  return { os, architecture, variant, explicit };
}

function dockerPlatformValuesMatch(requested, observedValue) {
  if (!requested || !observedValue || typeof observedValue !== "object") return false;
  const observed = {
    os: String(observedValue.os || "").trim().toLowerCase(),
    architecture: normalizeDockerArchitecture(observedValue.architecture),
    variant: String(observedValue.variant || "").trim().toLowerCase(),
  };
  return Boolean(
    observed.os
    && observed.architecture
    && observed.os === requested.os
    && observed.architecture === requested.architecture
    && dockerVariantMatches(requested, observed)
  );
}

function parseNuGetPackageUrl(body, packageName, packageVersion, baseUrl, trustScope) {
  let payload;
  try {
    payload = JSON.parse(String(body || ""));
  } catch {
    return null;
  }
  const normalizedName = encodePathSegment(String(packageName || "").toLowerCase());
  const normalizedVersion = encodePathSegment(normalizeNuGetVersion(packageVersion));
  if (!normalizedName || !normalizedVersion || !Array.isArray(payload?.resources)) {
    return null;
  }

  for (const resource of payload.resources.slice(0, 256)) {
    if (!resource || typeof resource !== "object") continue;
    const types = Array.isArray(resource["@type"])
      ? resource["@type"]
      : [resource["@type"]];
    if (!types.some(type => String(type || "").startsWith("PackageBaseAddress/"))) {
      continue;
    }
    const packageBase = resolveAndValidateScopedRegistryUrl(
      resource["@id"],
      baseUrl,
      trustScope
    );
    if (!packageBase) continue;
    return `${packageBase.replace(/\/$/, "")}/${normalizedName}/${normalizedVersion}/${normalizedName}.${normalizedVersion}.nupkg`;
  }
  return null;
}

function isDockerDigest(value) {
  if (typeof value !== "string" || value.length > 1024) return false;
  const match = value.match(DOCKER_DIGEST_PATTERN);
  if (!match) return false;
  const algorithm = match[1].toLowerCase();
  const length = match[2].length;
  if (algorithm === "sha256") return length === 64;
  if (algorithm === "sha512") return length === 128;
  return length >= 32 && length <= 512;
}

function parseDartArchiveUrl(body, packageName, version, baseUrl, trustScope) {
  let payload;
  try {
    payload = JSON.parse(String(body || ""));
  } catch {
    return null;
  }

  const wantedName = sanitizePackageNameInput(packageName).toLowerCase();
  const observedName = sanitizePackageNameInput(payload && payload.name).toLowerCase();
  const wantedVersion = String(version || "").trim();
  if (!wantedName || observedName !== wantedName) {
    return null;
  }
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
    const resolved = resolveAndValidateScopedRegistryUrl(candidate, baseUrl, trustScope);
    if (resolved) {
      return resolved;
    }
  }

  return null;
}

function parseComposerDistUrl(body, packageName, version, baseUrl, trustScope) {
  let payload;
  try {
    payload = JSON.parse(String(body || ""));
  } catch {
    return null;
  }

  const entries = [];
  const normalizedPackageName = sanitizePackageNameInput(packageName).toLowerCase();

  if (payload && payload.packages && typeof payload.packages === "object") {
    const exactKey = Object.keys(payload.packages).find(key => (
      sanitizePackageNameInput(key).toLowerCase() === normalizedPackageName
    ));
    if (exactKey && Array.isArray(payload.packages[exactKey])) {
      entries.push(...payload.packages[exactKey]);
    }
  } else if (Array.isArray(payload)) {
    for (const entry of payload) {
      if (
        entry
        && sanitizePackageNameInput(entry.name).toLowerCase() === normalizedPackageName
      ) {
        entries.push(entry);
      }
    }
  }

  const matchedEntry = entries.find((entry) => (
    entry
    && entry.version === version
    && (!entry.name
      || sanitizePackageNameInput(entry.name).toLowerCase() === normalizedPackageName)
  ));
  const distUrl = matchedEntry
    && matchedEntry.dist
    && typeof matchedEntry.dist === "object"
    ? matchedEntry.dist.url
    : null;

  return resolveAndValidateScopedRegistryUrl(distUrl, baseUrl, trustScope);
}

module.exports = {
  buildRegistryTriggerPlan,
  dockerCandidateMatchesPlatform,
  dockerDigestMatches,
  findPythonDistributionUrl,
  formatForDependency,
  isPullUnsupportedFormat,
  isDockerDigest,
  isTrustedRegistryUrl,
  mavenArtifactFileName,
  normalizeNuGetVersion,
  parseDockerManifest,
  parseNuGetPackageUrl,
  parseCargoDownloadUrl,
  parseCargoIndexEntry,
  parseComposerDistUrl,
  parseDartArchiveUrl,
  parseNpmTarballUrl,
  resolveAndValidateDockerBlobRedirectUrl,
  resolveAndValidateScopedRegistryUrl,
  rubyCandidateMatchesPlatform,
};

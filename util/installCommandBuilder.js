// Install command builder - generates format-native install commands
// with Cloudsmith registry URLs pre-filled.

const { createHash } = require("crypto");
const {
  installGuidanceSupportForFormat,
} = require("../domain/installGuidanceSupport");

const VERIFICATION_BANNER = "# Verify package details before running";
const CLOUDSMITH_DOWNLOAD_HOST = "dl.cloudsmith.io";
const CLOUDSMITH_GENERIC_HOST = "generic.cloudsmith.io";
const DOCKER_REGISTRY = "docker.cloudsmith.io";
const MAX_IDENTIFIER_LENGTH = 255;
const MAX_DOCKER_NAME_LENGTH = 255;
const MAX_CARGO_REGISTRY_NAME_LENGTH = 64;
const MAX_RAW_DOWNLOAD_URL_LENGTH = 8192;
const ASCII_CONTROL_PATTERN = /[\u0000-\u001f\u007f]/;
const CLOUDSMITH_IDENTIFIER_PATTERN = /^[A-Za-z0-9._-]+$/;
const COMMAND_FORMAT_PATTERN = /^[a-z0-9][a-z0-9._+-]{0,63}$/;
const DOCKER_NAME_COMPONENT_PATTERN = /^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$/;
const DOCKER_TAG_PATTERN = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
const SHA256_DIGEST_PATTERN = /^(?:sha256:)?([a-fA-F0-9]{64})$/;
const SEMANTIC_VERSION_PATTERN = /^v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;
const SHELL_ARGUMENT_FORMATS = new Set([
  "python", "npm", "nuget", "helm", "cargo", "go",
  "ruby", "conda", "composer", "dart", "rpm",
]);

class InstallCommandValidationError extends Error {
  constructor(field, reason) {
    super(`${field} ${reason}`);
    this.name = "InstallCommandValidationError";
    this.field = field;
  }
}

class InstallCommandBuilder {
  /**
   * Render one argument using syntax shared by POSIX-compatible shells and PowerShell.
   * Embedded apostrophes are rejected because those shells escape them differently.
   */
  static shellEscape(str) {
    const value = String(str);
    if (value.includes("'")) {
      throw new InstallCommandValidationError(
        "Shell argument",
        "must not contain an apostrophe."
      );
    }
    return `'${value}'`;
  }

  /**
   * Remove the display-only verification banner from an already validated command.
   * Unknown-format fallback comments are preserved and remain non-executable.
   *
   * @param   {string} command
   * @returns {string}
   */
  static toClipboardCommand(command) {
    if (typeof command !== "string") {
      return "";
    }

    const unixBanner = `${VERIFICATION_BANNER}\n`;
    if (command.startsWith(unixBanner)) {
      return command.slice(unixBanner.length);
    }

    const windowsBanner = `${VERIFICATION_BANNER}\r\n`;
    if (command.startsWith(windowsBanner)) {
      return command.slice(windowsBanner.length);
    }

    return command;
  }

  /**
   * Extract a Docker image tag from package-like data.
   * Cloudsmith may expose human-readable tags separately from the version/digest.
   *
   * @param   {object} pkgLike
   * @returns {string|null}
   */
  static extractDockerTag(pkgLike) {
    try {
      const snapshot = InstallCommandBuilder._snapshotPlainDataObject(
        pkgLike,
        "Docker package metadata"
      );
      return InstallCommandBuilder._dockerTagFromOptions(snapshot, { strict: false });
    } catch {
      return null;
    }
  }

  static _normalizeDockerTag(value) {
    try {
      if (Array.isArray(value)) {
        const entries = InstallCommandBuilder._snapshotFlatStringArray(value, "Docker tag");
        return {
          tag: entries.length > 0 && entries.every(entry => DOCKER_TAG_PATTERN.test(entry))
            ? entries[0]
            : null,
          emptyArray: entries.length === 0,
        };
      }

      return {
        tag: typeof value === "string" && DOCKER_TAG_PATTERN.test(value) ? value : null,
        emptyArray: false,
      };
    } catch {
      throw new InstallCommandValidationError(
        "Docker tag",
        "must be a string or a bounded flat string array using Docker tag syntax."
      );
    }
  }

  static _dockerTagFromOptions(options, { strict = true } = {}) {
    for (const field of ["tags", "tags_raw"]) {
      if (!Object.prototype.hasOwnProperty.call(options, field)) continue;
      const raw = options[field];
      if (raw === undefined || raw === null) continue;
      let tags;
      try {
        tags = InstallCommandBuilder._snapshotPlainDataObject(raw, "Docker tags");
      } catch (error) {
        if (strict) throw error;
        return null;
      }
      const candidate = Object.prototype.hasOwnProperty.call(tags, "version")
        ? tags.version
        : null;
      const normalized = InstallCommandBuilder._normalizeDockerTag(candidate);
      const { tag } = normalized;
      if (tag) return tag;
      if (normalized.emptyArray) continue;
      if (candidate !== undefined && candidate !== null && candidate !== "" && strict) {
        throw new InstallCommandValidationError(
          "Docker tag",
          "must be a string or a bounded flat string array using Docker tag syntax."
        );
      }
    }
    return null;
  }

  static _normalizeDockerDigest(value) {
    if (value == null || value === "") {
      return null;
    }

    if (typeof value !== "string") {
      throw new InstallCommandValidationError("Docker digest", "must be a string.");
    }

    const match = value.match(SHA256_DIGEST_PATTERN);
    if (!match) {
      throw new InstallCommandValidationError(
        "Docker digest",
        "must be a sha256 digest containing exactly 64 hexadecimal characters."
      );
    }

    return match[1].toLowerCase();
  }

  static _resolveDockerTag(version, opts) {
    const explicitTag = InstallCommandBuilder._dockerTagFromOptions(opts || {});
    if (explicitTag) return explicitTag;

    if (version === "") {
      return "latest";
    }

    if (!DOCKER_TAG_PATTERN.test(version)) {
      throw new InstallCommandValidationError(
        "Docker tag",
        "must start with an alphanumeric character or underscore, contain only alphanumerics, underscores, periods, or dashes, and be at most 128 characters."
      );
    }

    return version;
  }

  static _normalizeDockerName(name) {
    return name.endsWith(".sig") ? name.slice(0, -4) : name;
  }

  static _validateCommandFormat(format) {
    if (typeof format !== "string" || !COMMAND_FORMAT_PATTERN.test(format)) {
      throw new InstallCommandValidationError(
        "Package format",
        "must be a lowercase identifier containing only letters, numbers, periods, underscores, plus signs, or dashes."
      );
    }
    return format;
  }

  static _validateCommandValue(value, field, allowEmpty = false) {
    if (typeof value !== "string") {
      throw new InstallCommandValidationError(field, "must be a string.");
    }
    if ((!allowEmpty && value.length === 0) || ASCII_CONTROL_PATTERN.test(value)) {
      throw new InstallCommandValidationError(field, "must be non-empty and contain no control characters or newlines.");
    }
    return value;
  }

  static _validateShellArgument(value, field) {
    if (value.includes("'")) {
      throw new InstallCommandValidationError(
        field,
        "must not contain an apostrophe because generated commands support both POSIX shells and PowerShell."
      );
    }
    return value;
  }

  static _validateCloudsmithIdentifier(value, field) {
    if (
      typeof value !== "string"
      || value.length === 0
      || value.length > MAX_IDENTIFIER_LENGTH
      || value === "."
      || value === ".."
      || !CLOUDSMITH_IDENTIFIER_PATTERN.test(value)
    ) {
      throw new InstallCommandValidationError(
        field,
        "must be a Cloudsmith slug containing only letters, numbers, periods, underscores, or dashes."
      );
    }
    return value;
  }

  static _validateNugetPackageId(value) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u.test(value)) {
      throw new InstallCommandValidationError(
        "NuGet package name",
        "must use a native NuGet package identifier."
      );
    }
    return value;
  }

  static _validateNugetVersion(value) {
    if (!/^(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){0,3}(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u.test(value)) {
      throw new InstallCommandValidationError(
        "NuGet package version",
        "must use a native NuGet version that can be pinned exactly."
      );
    }
    return value;
  }

  static _validateNpmPackageName(value) {
    if (
      value.length > 214
      || !/^(?:@[A-Za-z0-9][A-Za-z0-9._~-]*\/)?[A-Za-z0-9][A-Za-z0-9._~-]*$/u.test(value)
    ) {
      throw new InstallCommandValidationError(
        "npm package name",
        "must use a native registry package identity, not a URL, path, alias, or direct reference."
      );
    }
    return value;
  }

  static _validateNpmVersion(value) {
    if (!SEMANTIC_VERSION_PATTERN.test(value)) {
      throw new InstallCommandValidationError(
        "npm package version",
        "must use an exact native semantic version, not a tag, range, URL, path, or alias."
      );
    }
    return value;
  }

  static _validatePythonPackageName(value) {
    if (
      value.length > 255
      || !/^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,253}[A-Za-z0-9])?$/u.test(value)
    ) {
      throw new InstallCommandValidationError(
        "Python package name",
        "must use a native project name, not a URL, path, or direct reference."
      );
    }
    return value;
  }

  static _validatePythonVersion(value) {
    if (
      value.length > 255
      || !/^(?:v)?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview))[-_.]?[0-9]+)?(?:(?:-[0-9]+|[-_.]?(?:post|rev|r)[-_.]?[0-9]+))?(?:[-_.]?dev[-_.]?[0-9]+)?(?:\+[A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)*)?$/iu.test(value)
    ) {
      throw new InstallCommandValidationError(
        "Python package version",
        "must use an exact native Python version, not a URL, path, or direct reference."
      );
    }
    return value;
  }

  static _validateHelmChartName(value) {
    if (
      value.length > 255
      || !/^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,253}[A-Za-z0-9])?$/u.test(value)
    ) {
      throw new InstallCommandValidationError(
        "Helm chart name",
        "must use a native chart name, not a URL, repository reference, or local path."
      );
    }
    return value;
  }

  static _validateHelmVersion(value) {
    if (!SEMANTIC_VERSION_PATTERN.test(value)) {
      throw new InstallCommandValidationError(
        "Helm chart version",
        "must use an exact native semantic version."
      );
    }
    return value;
  }

  static _validateCargoPackageName(value) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/u.test(value)) {
      throw new InstallCommandValidationError(
        "Cargo package name",
        "must use a native registry crate name, not a URL, Git reference, or local path."
      );
    }
    return value;
  }

  static _validateCargoVersion(value) {
    if (!SEMANTIC_VERSION_PATTERN.test(value)) {
      throw new InstallCommandValidationError(
        "Cargo package version",
        "must use an exact native semantic version."
      );
    }
    return value;
  }

  static _validateRubyGemName(value) {
    if (
      value.length > 255
      || !/^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,253}[A-Za-z0-9])?$/u.test(value)
    ) {
      throw new InstallCommandValidationError(
        "Ruby gem name",
        "must use a native gem name, not a URL or local path."
      );
    }
    return value;
  }

  static _validateRubyVersion(value) {
    if (
      value.length > 255
      || !/^[0-9](?:[0-9A-Za-z.-]{0,253}[0-9A-Za-z])?$/u.test(value)
      || value.includes("..")
    ) {
      throw new InstallCommandValidationError(
        "Ruby gem version",
        "must use an exact native gem version, not a URL or local path."
      );
    }
    return value;
  }

  static _validateComposerPackageName(value) {
    if (
      value.length > 255
      || !/^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\/[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/u.test(value)
    ) {
      throw new InstallCommandValidationError(
        "Composer package name",
        "must use a native vendor/package identity, not a URL, path, or repository descriptor."
      );
    }
    return value;
  }

  static _validateComposerVersion(value) {
    if (
      value.length > 255
      || !/^[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,253}[A-Za-z0-9])?$/u.test(value)
    ) {
      throw new InstallCommandValidationError(
        "Composer package version",
        "must use a native exact version without range or repository syntax."
      );
    }
    return value;
  }

  static _validateDartPackageName(value) {
    if (value.length > 64 || !/^[a-z][a-z0-9_]*$/u.test(value)) {
      throw new InstallCommandValidationError(
        "Dart package name",
        "must use a native hosted package name without dependency-section or source syntax."
      );
    }
    return value;
  }

  static _validateDartVersion(value) {
    if (!SEMANTIC_VERSION_PATTERN.test(value)) {
      throw new InstallCommandValidationError(
        "Dart package version",
        "must use an exact native semantic version without a source descriptor."
      );
    }
    return value;
  }

  static _validateMavenToken(value, field) {
    if (
      value.length > 255
      || !/^[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,253}[A-Za-z0-9])?$/u.test(value)
    ) {
      throw new InstallCommandValidationError(
        field,
        "must use a native literal coordinate without interpolation, range, path, or markup syntax."
      );
    }
    return value;
  }

  static _validateGoModule(value) {
    if (
      !/^[A-Za-z0-9][A-Za-z0-9._~/-]{0,2047}$/u.test(value)
      || value.includes("//")
      || value.split("/").some(part => part === "." || part === ".." || part.length === 0)
    ) {
      throw new InstallCommandValidationError(
        "Go module path",
        "must use a native module path safe for POSIX, PowerShell, and Command Prompt."
      );
    }
    return value;
  }

  static _validateGoVersion(value) {
    if (!/^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u.test(value)) {
      throw new InstallCommandValidationError(
        "Go module version",
        "must use a native semantic module version."
      );
    }
    return value;
  }

  static _encodeUrlPathSegment(value) {
    return encodeURIComponent(value).replace(/[!'()*]/g, character =>
      `%${character.charCodeAt(0).toString(16).toUpperCase()}`
    );
  }

  static _validateDockerPathComponent(value, field) {
    if (!DOCKER_NAME_COMPONENT_PATTERN.test(value)) {
      throw new InstallCommandValidationError(
        field,
        "must be a lowercase Docker repository component using valid periods, underscores, or dashes."
      );
    }
    return value;
  }

  static _validateDockerImageName(value) {
    const imageName = InstallCommandBuilder._normalizeDockerName(value);
    const components = imageName.split("/");
    if (!imageName || components.some(component => !DOCKER_NAME_COMPONENT_PATTERN.test(component))) {
      throw new InstallCommandValidationError(
        "Docker image name",
        "must be a lowercase slash-delimited Docker repository path."
      );
    }
    return imageName;
  }

  static _validateRawDownloadUrl(value, workspace, repo, format) {
    if (
      typeof value !== "string"
      || value.length === 0
      || value.length > MAX_RAW_DOWNLOAD_URL_LENGTH
      || value !== value.trim()
      || ASCII_CONTROL_PATTERN.test(value)
      || /[\\\s]/.test(value)
      || value.includes("'")
    ) {
      throw new InstallCommandValidationError(
        "Raw download URL",
        "must be a well-formed HTTPS Cloudsmith download URL without whitespace, backslashes, or apostrophes."
      );
    }

    let parsed;
    try {
      parsed = new URL(value);
    } catch {
      throw new InstallCommandValidationError("Raw download URL", "must be a well-formed URL.");
    }

    const authorityStart = value.indexOf("://") + 3;
    const pathStart = value.indexOf("/", authorityStart);
    const suffixStart = [value.indexOf("?", authorityStart), value.indexOf("#", authorityStart)]
      .filter(index => index >= 0)
      .reduce((minimum, index) => Math.min(minimum, index), value.length);
    const rawPathname = pathStart >= 0 && pathStart < suffixStart
      ? value.slice(pathStart, suffixStart)
      : "";
    for (const rawSegment of rawPathname.split("/")) {
      if (!rawSegment) continue;
      let decodedSegment = rawSegment;
      const maximumDecodeDepth = Math.ceil(rawSegment.length / 2) + 1;
      for (let depth = 0; depth < maximumDecodeDepth; depth += 1) {
        let next;
        try {
          next = decodeURIComponent(decodedSegment);
        } catch {
          break;
        }
        if (next === decodedSegment) break;
        decodedSegment = next;
      }
      if (decodedSegment === "." || decodedSegment === "..") {
        throw new InstallCommandValidationError(
          "Raw download URL",
          "must use a canonical package path."
        );
      }
    }

    if (parsed.protocol !== "https:") {
      throw new InstallCommandValidationError("Raw download URL", "must use HTTPS.");
    }
    const genericEndpoint = format === "generic" && parsed.hostname === CLOUDSMITH_GENERIC_HOST;
    if (
      (!genericEndpoint && parsed.hostname !== CLOUDSMITH_DOWNLOAD_HOST)
      || parsed.port
    ) {
      throw new InstallCommandValidationError(
        "Raw download URL",
        "must use an approved Cloudsmith download host for the selected format."
      );
    }
    if (parsed.username || parsed.password) {
      throw new InstallCommandValidationError("Raw download URL", "must not contain embedded credentials.");
    }
    if (parsed.hash) {
      throw new InstallCommandValidationError("Raw download URL", "must not contain a fragment.");
    }
    if (parsed.search) {
      throw new InstallCommandValidationError(
        "Raw download URL",
        "must not contain query parameters or credential material."
      );
    }

    const selectedScopes = genericEndpoint
      ? [`/${workspace}/${repo}/`]
      : [`/basic/${workspace}/${repo}/`, `/public/${workspace}/${repo}/`];
    const selectedScope = selectedScopes.find(scope => parsed.pathname.startsWith(scope));
    const scopedPath = selectedScope ? parsed.pathname.slice(selectedScope.length) : "";
    const formatPath = genericEndpoint ? scopedPath : scopedPath.slice(`${format}/`.length);
    if (!selectedScope || (!genericEndpoint && !scopedPath.startsWith(`${format}/`))) {
      throw new InstallCommandValidationError(
        "Raw download URL",
        "must target the selected Cloudsmith workspace and repository."
      );
    }
    for (const encodedSegment of formatPath.split("/")) {
      if (!encodedSegment) {
        throw new InstallCommandValidationError(
          "Raw download URL",
          "must use a canonical package path."
        );
      }
      let decodedSegment = encodedSegment;
      const maximumDecodeDepth = Math.ceil(encodedSegment.length / 2) + 1;
      for (let depth = 0; depth < maximumDecodeDepth; depth += 1) {
        let next;
        try {
          next = decodeURIComponent(decodedSegment);
        } catch {
          throw new InstallCommandValidationError(
            "Raw download URL",
            "must use valid URL path encoding."
          );
        }
        if (next === decodedSegment) break;
        decodedSegment = next;
      }
      if (
        decodedSegment === "."
        || decodedSegment === ".."
        || decodedSegment.includes("/")
        || decodedSegment.includes("\\")
        || ASCII_CONTROL_PATTERN.test(decodedSegment)
      ) {
        throw new InstallCommandValidationError(
          "Raw download URL",
          "must use a canonical package path."
        );
      }
    }

    return parsed.toString();
  }

  static _validateFilename(value) {
    if (
      typeof value !== "string"
      || value.length === 0
      || value === "."
      || value === ".."
      || ASCII_CONTROL_PATTERN.test(value)
      || value.includes("/")
      || value.includes("\\")
    ) {
      throw new InstallCommandValidationError(
        "Raw package filename",
        "must be a non-empty filename without control characters or path separators."
      );
    }
    return value;
  }

  /**
   * Build a copy-paste-ready install command for a package.
   *
   * @param   {string} format    Package format (e.g., 'python', 'npm', 'maven').
   * @param   {string} name      Package name.
   * @param   {string} version   Package version.
   * @param   {string} workspace Cloudsmith workspace/owner slug.
   * @param   {string} repo      Cloudsmith repository slug.
   * @param   {object} [opts]    Extra package fields for format-specific handling.
   * @param   {string} [opts.cdnUrl]         Direct CDN download URL (raw/generic).
   * @param   {string} [opts.filename]       Original filename (raw/generic).
   * @returns {{ command: string, note: string|null, alternatives?: Array<{label: string, command: string}> }}
   */
  static build(format, name, version, workspace, repo, opts) {
    const options = InstallCommandBuilder._validateOptions(opts);
    const validatedFormat = InstallCommandBuilder._validateCommandFormat(format);
    const support = installGuidanceSupportForFormat(validatedFormat);
    if (!support) {
      throw new InstallCommandValidationError(
        "Package format",
        `does not have authoritative install guidance: ${validatedFormat}.`
      );
    }
    const validatedName = InstallCommandBuilder._validateCommandValue(name, "Package name");
    const validatedVersion = InstallCommandBuilder._validateCommandValue(
      version,
      "Package version",
      ["docker", "generic", "raw"].includes(validatedFormat)
    );
    const validatedWorkspace = InstallCommandBuilder._validateCloudsmithIdentifier(workspace, "Workspace slug");
    const validatedRepo = InstallCommandBuilder._validateCloudsmithIdentifier(repo, "Repository slug");
    const encodedWorkspace = InstallCommandBuilder._encodeUrlPathSegment(validatedWorkspace);
    const encodedRepo = InstallCommandBuilder._encodeUrlPathSegment(validatedRepo);
    const qualifiers = InstallCommandBuilder._packageQualifiers(options.qualifiers);
    const usesShellArguments = SHELL_ARGUMENT_FORMATS.has(validatedFormat);
    if (usesShellArguments) {
      InstallCommandBuilder._validateShellArgument(validatedName, "Package name");
      InstallCommandBuilder._validateShellArgument(validatedVersion, "Package version");
      if (validatedName.startsWith("-")) {
        throw new InstallCommandValidationError(
          "Package name",
          "must not begin with a dash because package-manager options are not package identities."
        );
      }
      if (validatedVersion.startsWith("-")) {
        throw new InstallCommandValidationError(
          "Package version",
          "must not begin with a dash because package-manager options are not versions."
        );
      }
    }
    const nativeValidators = {
      python: ["_validatePythonPackageName", "_validatePythonVersion"],
      npm: ["_validateNpmPackageName", "_validateNpmVersion"],
      helm: ["_validateHelmChartName", "_validateHelmVersion"],
      cargo: ["_validateCargoPackageName", "_validateCargoVersion"],
      ruby: ["_validateRubyGemName", "_validateRubyVersion"],
      composer: ["_validateComposerPackageName", "_validateComposerVersion"],
      dart: ["_validateDartPackageName", "_validateDartVersion"],
    };
    const nativeValidator = nativeValidators[validatedFormat];
    if (nativeValidator) {
      InstallCommandBuilder[nativeValidator[0]](validatedName);
      InstallCommandBuilder[nativeValidator[1]](validatedVersion);
    }
    const safeName = usesShellArguments ? InstallCommandBuilder.shellEscape(validatedName) : "";
    const safeVersion = usesShellArguments ? InstallCommandBuilder.shellEscape(validatedVersion) : "";
    const shellArgument = value => InstallCommandBuilder.shellEscape(value);
    const goVersion = `v${validatedVersion.replace(/^v+/i, "")}`;
    const cargoRegistry = InstallCommandBuilder._cargoRegistryName(
      validatedWorkspace,
      validatedRepo
    );
    const goProxy = `https://golang.cloudsmith.io/${encodedWorkspace}/${encodedRepo}/`;
    const composerRepository = `https://composer.cloudsmith.io/${encodedWorkspace}/${encodedRepo}/`;
    const dartRepository = `https://dart.cloudsmith.io/${encodedWorkspace}/${encodedRepo}/`;
    let npmScopeOption = "";
    if (validatedFormat === "npm" && validatedName.startsWith("@")) {
      const npmScope = validatedName.slice(0, validatedName.indexOf("/"));
      npmScopeOption = ` --${npmScope}:registry=https://npm.cloudsmith.io/${encodedWorkspace}/${encodedRepo}/`;
    }
    const commands = {
      python: () => ({
        command: `# Verify package details before running\npip install ${shellArgument(`${validatedName}==${validatedVersion}`)} --index-url https://dl.cloudsmith.io/basic/${encodedWorkspace}/${encodedRepo}/python/simple/`,
        note: 'For private repositories, replace "basic" with an entitlement token.',
      }),
      npm: () => ({
        command: `# Verify package details before running\nnpm install ${shellArgument(`${validatedName}@${validatedVersion}`)} --save-exact --registry=https://npm.cloudsmith.io/${encodedWorkspace}/${encodedRepo}/${npmScopeOption}`,
        note: "Run `npm login --registry=https://npm.cloudsmith.io/" + encodedWorkspace + "/" + encodedRepo + "/` first for private repositories.",
      }),
      maven: () => ({
        command: InstallCommandBuilder._buildMaven(
          validatedName,
          validatedVersion,
          validatedWorkspace,
          validatedRepo,
          encodedWorkspace,
          encodedRepo,
          qualifiers
        ),
        language: "markdown",
        note: "For private repositories, configure Maven server credentials in settings.xml using the generated mirror id; never commit credentials to pom.xml.",
      }),
      nuget: () => ({
        command: `# Verify package details before running\ndotnet add package ${shellArgument(InstallCommandBuilder._validateNugetPackageId(validatedName))} --version ${shellArgument(`[${InstallCommandBuilder._validateNugetVersion(validatedVersion)}]`)} --source https://nuget.cloudsmith.io/${encodedWorkspace}/${encodedRepo}/v3/index.json`,
        note: "For private repositories, configure NuGet source credentials.",
      }),
      helm: () => ({
        command: `# Verify package details before running\nhelm install --generate-name ${safeName} --repo https://dl.cloudsmith.io/basic/${encodedWorkspace}/${encodedRepo}/helm/charts/ --version ${safeVersion}`,
        note: 'For private repositories, replace "basic" with an entitlement token.',
      }),
      cargo: () => ({
        command: `# Verify package details before running\ncargo add ${shellArgument(`${validatedName}@=${validatedVersion}`)} --registry ${shellArgument(cargoRegistry)}`,
        note: `Add the selected registry to .cargo/config.toml before running the command:\n[registries.${cargoRegistry}]\nindex = "sparse+https://cargo.cloudsmith.io/${encodedWorkspace}/${encodedRepo}/"\ncredential-provider = "cargo:token"\nConfigure a Cargo token separately for private repositories; do not store credentials in shared project files.`,
      }),
      go: () => ({
        command: `# Verify package details before running\nGOPROXY=${shellArgument(goProxy)} GONOPROXY='none' go get ${shellArgument(`${InstallCommandBuilder._validateGoModule(validatedName)}@${InstallCommandBuilder._validateGoVersion(goVersion)}`)}`,
        note: "Private repositories require HTTP Basic credentials in GOPROXY. Configure GONOSUMDB only for private module path prefixes that cannot use the public checksum database.",
        alternatives: [
          {
            label: "PowerShell",
            command: `# Verify package details before running\n$cloudsmithPreviousGoproxy=$env:GOPROXY; $cloudsmithPreviousGonoproxy=$env:GONOPROXY; try { $env:GOPROXY=${shellArgument(goProxy)}; $env:GONOPROXY='none'; go get ${shellArgument(`${InstallCommandBuilder._validateGoModule(validatedName)}@${InstallCommandBuilder._validateGoVersion(goVersion)}`)} } finally { if ($null -eq $cloudsmithPreviousGoproxy) { Remove-Item Env:GOPROXY -ErrorAction SilentlyContinue } else { $env:GOPROXY=$cloudsmithPreviousGoproxy }; if ($null -eq $cloudsmithPreviousGonoproxy) { Remove-Item Env:GONOPROXY -ErrorAction SilentlyContinue } else { $env:GONOPROXY=$cloudsmithPreviousGonoproxy } }`,
          },
          {
            label: "Command Prompt",
            command: `# Verify package details before running\ncmd.exe /D /V:OFF /C "set GOPROXY=${goProxy}&& set GONOPROXY=none&& go get ${InstallCommandBuilder._validateGoModule(validatedName)}@${InstallCommandBuilder._validateGoVersion(goVersion)}"`,
            commentStyle: "cmd",
          },
        ],
      }),
      ruby: () => ({
        command: `# Verify package details before running\ngem install ${safeName} -v ${safeVersion} --remote${qualifiers.platform ? ` --platform ${shellArgument(InstallCommandBuilder._qualifierValue(qualifiers, "platform", "Ruby platform"))}` : ""} --clear-sources --source https://dl.cloudsmith.io/basic/${encodedWorkspace}/${encodedRepo}/ruby/`,
        note: 'For private repositories, replace "basic" with an entitlement token.',
      }),
      conda: () => ({
        command: InstallCommandBuilder._buildConda(
          validatedName,
          validatedVersion,
          encodedWorkspace,
          encodedRepo,
          qualifiers
        ),
        note: "Configure Cloudsmith channel authentication separately for private repositories.",
      }),
      composer: () => ({
        command: `# Verify package details before running\ncomposer config repositories.packagist.org false && composer config repositories.cloudsmith composer ${shellArgument(composerRepository)} && composer require ${shellArgument(`${validatedName}:${validatedVersion}`)}`,
        note: "Configure Composer authentication separately for private repositories; generated commands never include credentials.",
        alternatives: [{
          label: "PowerShell",
          command: `# Verify package details before running\ncomposer config repositories.packagist.org false; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; composer config repositories.cloudsmith composer ${shellArgument(composerRepository)}; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; composer require ${shellArgument(`${validatedName}:${validatedVersion}`)}`,
        }],
      }),
      dart: () => ({
        command: `# Verify package details before running\ndart pub add ${shellArgument(`${validatedName}:${validatedVersion}`)} --hosted ${shellArgument(dartRepository)}`,
        note: "Use `dart pub token add` for the same Cloudsmith repository URL before accessing a private repository.",
      }),
    };

    if (support.strategy === "docker") {
      return InstallCommandBuilder._buildDocker(
        validatedName,
        validatedVersion,
        validatedWorkspace,
        validatedRepo,
        { ...options, qualifiers }
      );
    }
    if (support.strategy === "rpm") {
      return InstallCommandBuilder._buildRpm(
        validatedName,
        validatedVersion,
        validatedWorkspace,
        validatedRepo,
        encodedWorkspace,
        encodedRepo,
        qualifiers
      );
    }
    if (support.strategy === "download") {
      return InstallCommandBuilder._buildRaw(
        validatedFormat,
        validatedName,
        validatedVersion,
        encodedWorkspace,
        encodedRepo,
        options
      );
    }

    return InstallCommandBuilder._requireTemplateRenderer(
      commands[validatedFormat],
      validatedFormat
    )();
  }

  static _requireTemplateRenderer(entryFactory, format) {
    if (typeof entryFactory !== "function") {
      throw new InstallCommandValidationError(
        "Package format",
        `does not have a usable install-guidance renderer: ${format}.`
      );
    }
    return entryFactory;
  }

  static _validateOptions(value) {
    if (value === undefined || value === null) return {};
    return InstallCommandBuilder._snapshotPlainDataObject(value, "Install command options");
  }

  static _packageQualifiers(value) {
    if (value === undefined || value === null) return Object.freeze(Object.create(null));
    return InstallCommandBuilder._snapshotPlainDataObject(value, "Package qualifiers");
  }

  static _qualifierValue(qualifiers, key, field, { required = false } = {}) {
    const candidate = Object.prototype.hasOwnProperty.call(qualifiers, key)
      ? qualifiers[key]
      : null;
    if (candidate === undefined || candidate === null || candidate === "") {
      if (required) {
        throw new InstallCommandValidationError(field, "is required for an exact package identity.");
      }
      return null;
    }
    return InstallCommandBuilder._validateCommandValue(candidate, field);
  }

  static _snapshotPlainDataObject(value, field) {
    try {
      if (
        typeof value !== "object"
        || value === null
        || Array.isArray(value)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      ) {
        throw new Error("invalid object shape");
      }
      const keys = Reflect.ownKeys(value);
      if (keys.length > 64 || keys.some(key => typeof key !== "string")) {
        throw new Error("invalid object keys");
      }
      const snapshot = Object.create(null);
      for (const key of keys) {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor || !("value" in descriptor)) {
          throw new Error("invalid object property");
        }
        snapshot[key] = descriptor.value;
      }
      return Object.freeze(snapshot);
    } catch {
      throw new InstallCommandValidationError(field, "must be a plain data object.");
    }
  }

  static _snapshotFlatStringArray(value, field) {
    try {
      if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
        throw new Error("invalid array shape");
      }
      const keys = Reflect.ownKeys(value);
      const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
      if (
        !lengthDescriptor
        || !("value" in lengthDescriptor)
        || !Number.isInteger(lengthDescriptor.value)
        || lengthDescriptor.value < 0
        || lengthDescriptor.value > 64
        || keys.some(key => key !== "length" && !/^(?:0|[1-9][0-9]*)$/.test(key))
      ) {
        throw new Error("invalid array bounds");
      }
      const snapshot = [];
      for (let index = 0; index < lengthDescriptor.value; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !("value" in descriptor) || typeof descriptor.value !== "string") {
          throw new Error("invalid array entry");
        }
        snapshot.push(descriptor.value);
      }
      return Object.freeze(snapshot);
    } catch {
      throw new InstallCommandValidationError(
        field,
        "must be a bounded flat string array."
      );
    }
  }

  static _cargoRegistryName(workspace, repo) {
    const source = `cloudsmith-${workspace}-${repo}`;
    const raw = source.toLowerCase();
    const normalized = raw
      .replace(/[^a-z0-9_-]+/g, "-")
      .replace(/-+/g, "-")
      .replace(/^-|-$/g, "");
    const digest = createHash("sha256")
      .update(JSON.stringify([workspace, repo]))
      .digest("hex")
      .slice(0, 12);
    const prefixLength = MAX_CARGO_REGISTRY_NAME_LENGTH - digest.length - 1;
    const prefix = normalized.slice(0, prefixLength).replace(/-+$/g, "") || "cloudsmith";
    return `${prefix}-${digest}`;
  }

  /**
   * Build Docker pull command — tag-first with optional digest alternative.
   */
  static _buildDocker(name, version, workspace, repo, opts) {
    InstallCommandBuilder._validateDockerPathComponent(workspace, "Docker workspace slug");
    InstallCommandBuilder._validateDockerPathComponent(repo, "Docker repository slug");
    const imageName = InstallCommandBuilder._validateDockerImageName(name);
    const explicitTag = InstallCommandBuilder._dockerTagFromOptions(opts || {});
    const repositoryName = `${DOCKER_REGISTRY}/${workspace}/${repo}/${imageName}`;
    if (repositoryName.length > MAX_DOCKER_NAME_LENGTH) {
      throw new InstallCommandValidationError(
        "Docker repository name",
        `must be at most ${MAX_DOCKER_NAME_LENGTH} characters.`
      );
    }
    const qualifiedDigest = InstallCommandBuilder._qualifierValue(
      opts.qualifiers || {},
      "digest",
      "Docker digest"
    );
    const versionDigest = SHA256_DIGEST_PATTERN.test(version) ? version : null;
    const digest = InstallCommandBuilder._normalizeDockerDigest(qualifiedDigest || versionDigest);
    if (!digest && !explicitTag && version === "") {
      throw new InstallCommandValidationError(
        "Docker tag or digest",
        "is required to preserve an authoritative image identity."
      );
    }
    const tag = explicitTag || (digest ? null : InstallCommandBuilder._resolveDockerTag(version, {}));
    const result = {
      command: digest
        ? `# Verify package details before running\ndocker pull ${repositoryName}@sha256:${digest}`
        : `# Verify package details before running\ndocker pull ${repositoryName}:${tag}`,
      note: `Run \`docker login ${DOCKER_REGISTRY}\` first for private repositories.`,
    };
    if (digest && explicitTag) {
      result.alternatives = [{
        label: "Pull by tag",
        command: `# Verify package details before running\ndocker pull ${repositoryName}:${tag}`,
      }];
    }

    return result;
  }

  /**
   * Build RPM install command — dnf primary, yum alternative.
   */
  static _buildRpm(name, version, workspace, repo, encodedWorkspace, encodedRepo, qualifiers) {
    if (!/^[A-Za-z0-9][A-Za-z0-9+._-]*$/.test(name)) {
      throw new InstallCommandValidationError(
        "RPM package name",
        "must use a native RPM package identifier."
      );
    }
    const epoch = InstallCommandBuilder._qualifierValue(qualifiers, "epoch", "RPM epoch");
    const release = InstallCommandBuilder._qualifierValue(qualifiers, "release", "RPM release");
    const architecture = InstallCommandBuilder._qualifierValue(
      qualifiers,
      "architecture",
      "RPM architecture"
    );
    const nativeVersion = InstallCommandBuilder._qualifierValue(
      qualifiers,
      "nativeVersion",
      "RPM native version"
    );
    if (!release || !architecture) {
      throw new InstallCommandValidationError(
        "RPM qualifiers",
        "must include release and architecture for an exact NEVRA."
      );
    }
    if (epoch && !/^[0-9]+$/.test(epoch)) {
      throw new InstallCommandValidationError("RPM epoch", "must be a nonnegative integer.");
    }
    if (!nativeVersion && version.endsWith(`-${release}`)) {
      throw new InstallCommandValidationError(
        "RPM native version",
        "is required when the API version already contains the release suffix."
      );
    }
    if (
      nativeVersion
      && version !== nativeVersion
      && version !== `${nativeVersion}-${release}`
    ) {
      throw new InstallCommandValidationError(
        "RPM native version",
        "must match the authoritative package version and release."
      );
    }
    const rpmVersion = nativeVersion || version;
    if (!/^[A-Za-z0-9._+~^]+$/.test(rpmVersion)) {
      throw new InstallCommandValidationError("RPM version", "contains unsupported NEVRA characters.");
    }
    if (!/^[A-Za-z0-9._+~^]+$/.test(release)) {
      throw new InstallCommandValidationError("RPM release", "contains unsupported NEVRA characters.");
    }
    if (!/^[A-Za-z0-9._+~-]+$/.test(architecture)) {
      throw new InstallCommandValidationError("RPM architecture", "contains unsupported NEVRA characters.");
    }
    const safeCoordinate = InstallCommandBuilder.shellEscape(
      `${name}-${epoch ? `${epoch}:` : ""}${rpmVersion}-${release}.${architecture}`
    );
    const repositoryId = InstallCommandBuilder.shellEscape(`${workspace}-${repo}`);
    const repositorySelector = `--disablerepo='*' --enablerepo=${repositoryId}`;
    return {
      command: `# Verify package details before running\ndnf install-nevra ${safeCoordinate} ${repositorySelector}`,
      note: `Requires the selected Cloudsmith repository to be configured first.\nSetup URL: https://dl.cloudsmith.io/basic/${encodedWorkspace}/${encodedRepo}/cfg/setup/bash.rpm.sh`,
      alternatives: [{
        label: "Install via yum",
        command: `# Verify package details before running\nyum install ${safeCoordinate} ${repositorySelector}`,
      }],
    };
  }

  /**
   * Build Raw/Generic download command — curl primary, wget alternative.
   */
  static _buildRaw(format, name, version, workspace, repo, opts) {
    let cdnUrl;
    if (opts.cdnUrl != null && opts.cdnUrl !== "") {
      cdnUrl = InstallCommandBuilder._validateRawDownloadUrl(
        opts.cdnUrl,
        workspace,
        repo,
        format
      );
    } else {
      throw new InstallCommandValidationError(
        format === "generic" ? "Generic download URL" : "Raw download URL",
        "is required to preserve the authoritative package filepath and URL shape."
      );
    }
    const safeCdnUrl = InstallCommandBuilder.shellEscape(cdnUrl);
    const parsedCdnUrl = new URL(cdnUrl);
    const note = parsedCdnUrl.hostname === CLOUDSMITH_DOWNLOAD_HOST
      && parsedCdnUrl.pathname.startsWith(`/basic/${workspace}/${repo}/`)
      ? 'For private repositories, replace "basic" in the URL with a scoped entitlement token.'
      : parsedCdnUrl.hostname === CLOUDSMITH_DOWNLOAD_HOST
        ? "This URL targets a public repository and requires no Cloudsmith credentials."
        : "For private repositories on this format-specific endpoint, configure curl or wget HTTP authentication outside the generated command.";

    return {
      command: `# Verify package details before running\ncurl -fL -O --no-clobber --proto '=https' --proto-redir '=https' ${safeCdnUrl}`,
      note,
      alternatives: [{
        label: "Download via wget",
        command: `# Verify package details before running\nwget --https-only --no-clobber ${safeCdnUrl}`,
      }],
    };
  }

  /**
   * Build a Maven pom.xml snippet with repository and dependency blocks.
   * Splits name on : to get groupId and artifactId.
   */
  static _buildMaven(name, version, workspace, repo, encodedWorkspace, encodedRepo, qualifiers) {
    let groupId;
    let artifactId;
    if (name.includes(":")) {
      const parts = name.split(":");
      if (parts.length !== 2 || parts.some(part => part.length === 0)) {
        throw new InstallCommandValidationError(
          "Maven package name",
          "must contain exactly one separator between a non-empty groupId and artifactId."
        );
      }
      groupId = InstallCommandBuilder._validateMavenToken(parts[0], "Maven groupId");
      artifactId = InstallCommandBuilder._validateMavenToken(parts[1], "Maven artifactId");
    } else {
      throw new InstallCommandValidationError(
        "Maven package name",
        "must preserve groupId and artifactId separated by exactly one colon."
      );
    }

    const nativeVersion = InstallCommandBuilder._validateMavenToken(version, "Maven version");
    const escapeXml = (value) => String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");

    const mavenQualifiers = InstallCommandBuilder._mavenQualifiers(qualifiers);
    const repositoryId = InstallCommandBuilder._scopedRepositoryId(workspace, repo);
    return [
      "# Maven package setup",
      "",
      "> **Setup guidance only:** Merge the XML into the named files. Do not run this document as a shell command.",
      "",
      "The generated setup keeps credentials out of project files. Merge each XML block into the named file. The exclusive `<mirrorOf>*</mirrorOf>` rule routes all external Maven dependencies through the selected Cloudsmith repository, so that repository must proxy every dependency the project needs.",
      "",
      "## `~/.m2/settings.xml`",
      "",
      "```xml",
      "<settings>",
      "  <mirrors>",
      "    <mirror>",
      `      <id>${escapeXml(repositoryId)}</id>`,
      `      <url>https://dl.cloudsmith.io/basic/${encodedWorkspace}/${encodedRepo}/maven/</url>`,
      "      <mirrorOf>*</mirrorOf>",
      "    </mirror>",
      "  </mirrors>",
      "</settings>",
      "```",
      "",
      "Configure private-repository credentials in the same settings file under `<servers>` using the mirror id shown above.",
      "",
      "## `pom.xml`",
      "",
      "Merge this dependency into `<dependencies>`:",
      "",
      "```xml",
      "<dependency>",
      `  <groupId>${escapeXml(groupId)}</groupId>`,
      `  <artifactId>${escapeXml(artifactId)}</artifactId>`,
      `  <version>${escapeXml(nativeVersion)}</version>`,
      ...(mavenQualifiers.type ? [`  <type>${escapeXml(mavenQualifiers.type)}</type>`] : []),
      ...(mavenQualifiers.classifier
        ? [`  <classifier>${escapeXml(mavenQualifiers.classifier)}</classifier>`]
        : []),
      ...(mavenQualifiers.scope ? [`  <scope>${escapeXml(mavenQualifiers.scope)}</scope>`] : []),
      "</dependency>",
      "```",
    ].join("\n");
  }

  static _scopedRepositoryId(workspace, repo) {
    const digest = createHash("sha256")
      .update(JSON.stringify([workspace, repo]))
      .digest("hex")
      .slice(0, 12);
    const normalized = `cloudsmith-${workspace}-${repo}`
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, "-")
      .replace(/-+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 96)
      .replace(/-+$/g, "");
    return `${normalized || "cloudsmith"}-${digest}`;
  }

  static _buildConda(name, version, workspace, repo, qualifiers) {
    const build = InstallCommandBuilder._qualifierValue(qualifiers, "build", "Conda build");
    const subdir = InstallCommandBuilder._qualifierValue(qualifiers, "subdir", "Conda subdir");
    if (!build || !subdir) {
      throw new InstallCommandValidationError(
        "Conda qualifiers",
        "must include build and subdir for an exact MatchSpec."
      );
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u.test(name)) {
      throw new InstallCommandValidationError("Conda package name", "must use a native package name.");
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._+!-]{0,255}$/u.test(version)) {
      throw new InstallCommandValidationError("Conda package version", "must use a native version.");
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$/u.test(build)) {
      throw new InstallCommandValidationError("Conda build", "must use a native build string.");
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,100}$/u.test(subdir)) {
      throw new InstallCommandValidationError("Conda subdir", "must use a native subdirectory.");
    }
    const matchSpec = `${name}==${version}=${build}[subdir=${subdir}]`;
    return `# Verify package details before running\nconda install --override-channels -c https://conda.cloudsmith.io/${workspace}/${repo}/ ${InstallCommandBuilder.shellEscape(matchSpec)}`;
  }

  static _mavenQualifiers(value) {
    if (value === undefined || value === null) {
      return { type: null, classifier: null, scope: null };
    }
    const qualifiers = InstallCommandBuilder._snapshotPlainDataObject(value, "Maven qualifiers");
    const read = field => {
      const candidate = Object.prototype.hasOwnProperty.call(qualifiers, field)
        ? qualifiers[field]
        : null;
      if (candidate === null || candidate === undefined || candidate === "") return null;
      const validated = InstallCommandBuilder._validateCommandValue(candidate, `Maven ${field}`);
      if (field === "scope") {
        if (!new Set(["compile", "provided", "runtime", "test", "system", "import"])
          .has(validated)) {
          throw new InstallCommandValidationError(
            "Maven scope",
            "must use a native dependency scope."
          );
        }
        return validated;
      }
      return InstallCommandBuilder._validateMavenToken(validated, `Maven ${field}`);
    };
    return { type: read("type"), classifier: read("classifier"), scope: read("scope") };
  }
}

module.exports = { InstallCommandBuilder, InstallCommandValidationError };

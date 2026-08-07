// Install command builder - generates format-native install commands
// with Cloudsmith registry URLs pre-filled.

const { WEB_APP_BASE_URL, buildRepositoryUrl } = require("./webAppUrls");

const VERIFICATION_BANNER = "# Verify package details before running";
const CLOUDSMITH_DOWNLOAD_HOST = "dl.cloudsmith.io";
const DOCKER_REGISTRY = "docker.cloudsmith.io";
const MAX_IDENTIFIER_LENGTH = 255;
const MAX_DOCKER_NAME_LENGTH = 255;
const ASCII_CONTROL_PATTERN = /[\u0000-\u001f\u007f]/;
const CLOUDSMITH_IDENTIFIER_PATTERN = /^[A-Za-z0-9._-]+$/;
const COMMAND_FORMAT_PATTERN = /^[a-z0-9][a-z0-9._+-]{0,63}$/;
const DOCKER_NAME_COMPONENT_PATTERN = /^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$/;
const DOCKER_TAG_PATTERN = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
const SHA256_DIGEST_PATTERN = /^(?:sha256:)?([a-fA-F0-9]{64})$/;
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
    if (!pkgLike || typeof pkgLike !== "object") {
      return null;
    }

    const candidates = [
      pkgLike.tags && pkgLike.tags.version,
      pkgLike.tags_raw && pkgLike.tags_raw.version,
      pkgLike.cloudsmithMatch && pkgLike.cloudsmithMatch.tags && pkgLike.cloudsmithMatch.tags.version,
    ];

    for (const candidate of candidates) {
      const tag = InstallCommandBuilder._normalizeDockerTag(candidate);
      if (tag) {
        return tag;
      }
    }

    return null;
  }

  static _normalizeDockerTag(value) {
    if (Array.isArray(value)) {
      for (const entry of value) {
        const normalizedEntry = InstallCommandBuilder._normalizeDockerTag(entry);
        if (normalizedEntry) {
          return normalizedEntry;
        }
      }
      return null;
    }

    if (typeof value !== "string") {
      return null;
    }

    return DOCKER_TAG_PATTERN.test(value) ? value : null;
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
    const candidates = [
      opts.tags && opts.tags.version,
      opts.tags_raw && opts.tags_raw.version,
      opts.cloudsmithMatch && opts.cloudsmithMatch.tags && opts.cloudsmithMatch.tags.version,
    ];

    for (const candidate of candidates) {
      const values = Array.isArray(candidate) ? candidate : [candidate];
      for (const value of values) {
        if (value == null || value === "") {
          continue;
        }
        if (typeof value !== "string" || !DOCKER_TAG_PATTERN.test(value)) {
          throw new InstallCommandValidationError(
            "Docker tag",
            "must start with an alphanumeric character or underscore, contain only alphanumerics, underscores, periods, or dashes, and be at most 128 characters."
          );
        }
        return value;
      }
    }

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

  static _validateRawDownloadUrl(value) {
    if (
      typeof value !== "string"
      || value.length === 0
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

    if (parsed.protocol !== "https:") {
      throw new InstallCommandValidationError("Raw download URL", "must use HTTPS.");
    }
    if (parsed.hostname !== CLOUDSMITH_DOWNLOAD_HOST || parsed.port) {
      throw new InstallCommandValidationError(
        "Raw download URL",
        `must use the approved ${CLOUDSMITH_DOWNLOAD_HOST} host.`
      );
    }
    if (parsed.username || parsed.password) {
      throw new InstallCommandValidationError("Raw download URL", "must not contain embedded credentials.");
    }
    if (parsed.hash) {
      throw new InstallCommandValidationError("Raw download URL", "must not contain a fragment.");
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
   * @param   {string} [opts.checksumSha256] Docker image digest for pinned pulls.
   * @param   {string} [opts.cdnUrl]         Direct CDN download URL (raw/generic).
   * @param   {string} [opts.filename]       Original filename (raw/generic).
   * @returns {{ command: string, note: string|null, alternatives?: Array<{label: string, command: string}> }}
   */
  static build(format, name, version, workspace, repo, opts) {
    const options = opts || {};
    const validatedFormat = InstallCommandBuilder._validateCommandFormat(format);
    const validatedName = InstallCommandBuilder._validateCommandValue(name, "Package name");
    const validatedVersion = InstallCommandBuilder._validateCommandValue(
      version,
      "Package version",
      validatedFormat === "docker"
    );
    const validatedWorkspace = InstallCommandBuilder._validateCloudsmithIdentifier(workspace, "Workspace slug");
    const validatedRepo = InstallCommandBuilder._validateCloudsmithIdentifier(repo, "Repository slug");
    const encodedWorkspace = InstallCommandBuilder._encodeUrlPathSegment(validatedWorkspace);
    const encodedRepo = InstallCommandBuilder._encodeUrlPathSegment(validatedRepo);
    const usesShellArguments = SHELL_ARGUMENT_FORMATS.has(validatedFormat);
    if (usesShellArguments) {
      InstallCommandBuilder._validateShellArgument(validatedName, "Package name");
      InstallCommandBuilder._validateShellArgument(validatedVersion, "Package version");
    }
    const safeName = usesShellArguments ? InstallCommandBuilder.shellEscape(validatedName) : "";
    const safeVersion = usesShellArguments ? InstallCommandBuilder.shellEscape(validatedVersion) : "";
    const shellArgument = value => usesShellArguments ? InstallCommandBuilder.shellEscape(value) : "";
    const commands = {
      python: {
        command: `# Verify package details before running\npip install ${shellArgument(`${validatedName}==${validatedVersion}`)} --index-url https://dl.cloudsmith.io/basic/${encodedWorkspace}/${encodedRepo}/python/simple/`,
        note: 'For private repositories, replace "basic" with an entitlement token.',
      },
      npm: {
        command: `# Verify package details before running\nnpm install ${shellArgument(`${validatedName}@${validatedVersion}`)} --registry=https://npm.cloudsmith.io/${encodedWorkspace}/${encodedRepo}/`,
        note: "Run `npm login --registry=https://npm.cloudsmith.io/" + encodedWorkspace + "/" + encodedRepo + "/` first for private repositories.",
      },
      maven: {
        command: InstallCommandBuilder._buildMaven(
          validatedName,
          validatedVersion,
          validatedRepo,
          encodedWorkspace,
          encodedRepo
        ),
        note: 'For private repositories, replace "basic" with an entitlement token in the repository URL.',
      },
      nuget: {
        command: `# Verify package details before running\ndotnet add package ${safeName} --version ${safeVersion} --source https://nuget.cloudsmith.io/${encodedWorkspace}/${encodedRepo}/v3/index.json`,
        note: "For private repositories, configure NuGet source credentials.",
      },
      helm: {
        command: `# Verify package details before running\nhelm install ${safeName} --repo https://dl.cloudsmith.io/basic/${encodedWorkspace}/${encodedRepo}/helm/charts/ --version ${safeVersion}`,
        note: 'For private repositories, replace "basic" with an entitlement token.',
      },
      cargo: {
        command: `# Verify package details before running\ncargo add ${shellArgument(`${validatedName}@${validatedVersion}`)}`,
        note: `Add registry to .cargo/config.toml:\n[registries.cloudsmith]\nindex = "sparse+https://cargo.cloudsmith.io/${encodedWorkspace}/${encodedRepo}/"`,
      },
      go: {
        command: `# Verify package details before running\nGONOSUMCHECK=${safeName} go get ${shellArgument(`${validatedName}@v${validatedVersion}`)}`,
        note: `Set GOPROXY=https://go.cloudsmith.io/basic/${encodedWorkspace}/${encodedRepo}/,direct`,
      },
      ruby: {
        command: `# Verify package details before running\ngem install ${safeName} -v ${safeVersion} --source https://dl.cloudsmith.io/basic/${encodedWorkspace}/${encodedRepo}/ruby/`,
        note: 'For private repositories, replace "basic" with an entitlement token.',
      },
      conda: {
        command: `# Verify package details before running\nconda install -c https://conda.cloudsmith.io/${encodedWorkspace}/${encodedRepo}/ ${shellArgument(`${validatedName}=${validatedVersion}`)}`,
        note: null,
      },
      composer: {
        command: `# Verify package details before running\ncomposer require ${shellArgument(`${validatedName}:${validatedVersion}`)}`,
        note: `Add repository to composer.json:\n{"type": "composer", "url": "https://composer.cloudsmith.io/${encodedWorkspace}/${encodedRepo}/"}`,
      },
      dart: {
        command: `# Verify package details before running\ndart pub add ${shellArgument(`${validatedName}:${validatedVersion}`)}`,
        note: `Add hosted URL to pubspec.yaml:\n  ${validatedName}:\n    hosted: https://dart.cloudsmith.io/basic/${encodedWorkspace}/${encodedRepo}/pub/\n    version: ${validatedVersion}`,
      },
    };

    // Formats with dedicated handlers
    if (validatedFormat === "docker") {
      return InstallCommandBuilder._buildDocker(
        validatedName,
        validatedVersion,
        validatedWorkspace,
        validatedRepo,
        options
      );
    }
    if (validatedFormat === "rpm") {
      return InstallCommandBuilder._buildRpm(
        validatedName,
        validatedVersion,
        encodedWorkspace,
        encodedRepo
      );
    }
    if (validatedFormat === "raw" || validatedFormat === "generic") {
      return InstallCommandBuilder._buildRaw(
        validatedName,
        validatedVersion,
        encodedWorkspace,
        encodedRepo,
        options
      );
    }

    const entry = commands[validatedFormat];
    if (!entry) {
      const repositoryUrl = buildRepositoryUrl(validatedWorkspace, validatedRepo) || WEB_APP_BASE_URL;
      return {
        command: `# Verify package details before running\n# No install command template for format: ${validatedFormat}`,
        note: `Visit ${repositoryUrl} for setup instructions.`,
      };
    }
    return entry;
  }

  /**
   * Build Docker pull command — tag-first with optional digest alternative.
   */
  static _buildDocker(name, version, workspace, repo, opts) {
    InstallCommandBuilder._validateDockerPathComponent(workspace, "Docker workspace slug");
    InstallCommandBuilder._validateDockerPathComponent(repo, "Docker repository slug");
    const imageName = InstallCommandBuilder._validateDockerImageName(name);
    const tag = InstallCommandBuilder._resolveDockerTag(version, opts || {});
    const repositoryName = `${DOCKER_REGISTRY}/${workspace}/${repo}/${imageName}`;
    if (repositoryName.length > MAX_DOCKER_NAME_LENGTH) {
      throw new InstallCommandValidationError(
        "Docker repository name",
        `must be at most ${MAX_DOCKER_NAME_LENGTH} characters.`
      );
    }
    const result = {
      command: `# Verify package details before running\ndocker pull ${repositoryName}:${tag}`,
      note: `Run \`docker login ${DOCKER_REGISTRY}\` first for private repositories.`,
    };

    const digest = InstallCommandBuilder._normalizeDockerDigest((opts || {}).checksumSha256 || (opts || {}).versionDigest);
    if (digest) {
      result.alternatives = [{
        label: "Pull by digest (pinned)",
        command: `# Verify package details before running\ndocker pull ${repositoryName}@sha256:${digest}`,
      }];
    }

    return result;
  }

  /**
   * Build RPM install command — dnf primary, yum alternative.
   */
  static _buildRpm(name, version, workspace, repo) {
    const safeCoordinate = InstallCommandBuilder.shellEscape(`${name}-${version}`);
    return {
      command: `# Verify package details before running\ndnf install ${safeCoordinate}`,
      note: `Requires a Cloudsmith repository configured in /etc/yum.repos.d/.\nRepository URL: https://dl.cloudsmith.io/basic/${workspace}/${repo}/rpm/`,
      alternatives: [{
        label: "Install via yum",
        command: `# Verify package details before running\nyum install ${safeCoordinate}`,
      }],
    };
  }

  /**
   * Build Raw/Generic download command — curl primary, wget alternative.
   */
  static _buildRaw(name, version, workspace, repo, opts) {
    let cdnUrl;
    if (opts.cdnUrl != null && opts.cdnUrl !== "") {
      cdnUrl = InstallCommandBuilder._validateRawDownloadUrl(opts.cdnUrl);
    } else {
      const filename = opts.filename
        ? InstallCommandBuilder._validateFilename(opts.filename)
        : `${name}-${version}`;
      cdnUrl = `https://${CLOUDSMITH_DOWNLOAD_HOST}/basic/${workspace}/${repo}`
        + `/raw/names/${InstallCommandBuilder._encodeUrlPathSegment(name)}`
        + `/versions/${InstallCommandBuilder._encodeUrlPathSegment(version)}`
        + `/${InstallCommandBuilder._encodeUrlPathSegment(filename)}`;
    }
    const safeCdnUrl = InstallCommandBuilder.shellEscape(cdnUrl);

    return {
      command: `# Verify package details before running\ncurl -L -O ${safeCdnUrl}`,
      note: 'For private repositories, replace "basic" with an entitlement token or use authentication headers.',
      alternatives: [{
        label: "Download via wget",
        command: `# Verify package details before running\nwget ${safeCdnUrl}`,
      }],
    };
  }

  /**
   * Build a Maven pom.xml snippet with repository and dependency blocks.
   * Splits name on : to get groupId and artifactId.
   */
  static _buildMaven(name, version, repo, encodedWorkspace, encodedRepo) {
    let groupId;
    let artifactId;
    if (name.includes(":")) {
      const parts = name.split(":");
      groupId = parts[0];
      artifactId = parts[1];
    } else {
      groupId = name;
      artifactId = name;
    }

    const escapeXml = (value) => String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");

    return [
      "<!-- Add to pom.xml repositories -->",
      "<repository>",
      `  <id>cloudsmith-${escapeXml(repo)}</id>`,
      `  <url>https://dl.cloudsmith.io/basic/${encodedWorkspace}/${encodedRepo}/maven/</url>`,
      "</repository>",
      "",
      "<!-- Add to dependencies -->",
      "<dependency>",
      `  <groupId>${escapeXml(groupId)}</groupId>`,
      `  <artifactId>${escapeXml(artifactId)}</artifactId>`,
      `  <version>${escapeXml(version)}</version>`,
      "</dependency>",
    ].join("\n");
  }
}

module.exports = { InstallCommandBuilder, InstallCommandValidationError };

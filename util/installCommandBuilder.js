// Install command builder - generates format-native install commands
// with Cloudsmith registry URLs pre-filled.

const { WEB_APP_BASE_URL, buildRepositoryUrl } = require("./webAppUrls");

const VERIFICATION_BANNER = "# Verify package details before running";

class InstallCommandBuilder {
  /**
   * Escape a string for safe single-quoted shell usage.
   */
  static shellEscape(str) {
    const value = String(str);
    return `'${value.replace(/'/g, `'\\''`)}'`;
  }

  /**
   * Remove the display-only verification banner before copying to the clipboard.
   * Unknown-format fallback comments are preserved.
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

    const normalized = InstallCommandBuilder._sanitizeDockerComponent(value);
    return normalized || null;
  }

  static _sanitizeDockerComponent(value) {
    return String(value).trim().replace(/^['"]+|['"]+$/g, "");
  }

  static _normalizeDockerDigest(value) {
    if (typeof value !== "string") {
      return null;
    }

    const normalized = InstallCommandBuilder._sanitizeDockerComponent(value).replace(/^sha256:/i, "");
    return normalized || null;
  }

  static _resolveDockerTag(version, opts) {
    const explicitTag = InstallCommandBuilder.extractDockerTag(opts);
    if (explicitTag) {
      return explicitTag;
    }

    const normalizedVersion = InstallCommandBuilder._normalizeDockerTag(version);
    if (normalizedVersion) {
      return normalizedVersion;
    }

    return "latest";
  }

  static _normalizeDockerName(name) {
    const normalized = InstallCommandBuilder._sanitizeDockerComponent(name);
    return normalized.endsWith(".sig") ? normalized.slice(0, -4) : normalized;
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
    const safeName = InstallCommandBuilder.shellEscape(name);
    const safeVersion = InstallCommandBuilder.shellEscape(version);
    const commands = {
      python: {
        command: `# Verify package details before running\npip install ${safeName}==${safeVersion} --index-url https://dl.cloudsmith.io/basic/${workspace}/${repo}/python/simple/`,
        note: 'For private repositories, replace "basic" with an entitlement token.',
      },
      npm: {
        command: `# Verify package details before running\nnpm install ${safeName}@${safeVersion} --registry=https://npm.cloudsmith.io/${workspace}/${repo}/`,
        note: "Run `npm login --registry=https://npm.cloudsmith.io/" + workspace + "/" + repo + "/` first for private repositories.",
      },
      maven: {
        command: InstallCommandBuilder._buildMaven(name, version, workspace, repo),
        note: 'For private repositories, replace "basic" with an entitlement token in the repository URL.',
      },
      nuget: {
        command: `# Verify package details before running\ndotnet add package ${safeName} --version ${safeVersion} --source https://nuget.cloudsmith.io/${workspace}/${repo}/v3/index.json`,
        note: "For private repositories, configure NuGet source credentials.",
      },
      helm: {
        command: `# Verify package details before running\nhelm install ${safeName} --repo https://dl.cloudsmith.io/basic/${workspace}/${repo}/helm/charts/ --version ${safeVersion}`,
        note: 'For private repositories, replace "basic" with an entitlement token.',
      },
      cargo: {
        command: `# Verify package details before running\ncargo add ${safeName}@${safeVersion}`,
        note: `Add registry to .cargo/config.toml:\n[registries.cloudsmith]\nindex = "sparse+https://cargo.cloudsmith.io/${workspace}/${repo}/"`,
      },
      go: {
        command: `# Verify package details before running\nGONOSUMCHECK=${safeName} go get ${safeName}@v${safeVersion}`,
        note: `Set GOPROXY=https://go.cloudsmith.io/basic/${workspace}/${repo}/,direct`,
      },
      ruby: {
        command: `# Verify package details before running\ngem install ${safeName} -v ${safeVersion} --source https://dl.cloudsmith.io/basic/${workspace}/${repo}/ruby/`,
        note: 'For private repositories, replace "basic" with an entitlement token.',
      },
      conda: {
        command: `# Verify package details before running\nconda install -c https://conda.cloudsmith.io/${workspace}/${repo}/ ${safeName}=${safeVersion}`,
        note: null,
      },
      composer: {
        command: `# Verify package details before running\ncomposer require ${safeName}:${safeVersion}`,
        note: `Add repository to composer.json:\n{"type": "composer", "url": "https://composer.cloudsmith.io/${workspace}/${repo}/"}`,
      },
      dart: {
        command: `# Verify package details before running\ndart pub add ${safeName}:${safeVersion}`,
        note: `Add hosted URL to pubspec.yaml:\n  ${name}:\n    hosted: https://dart.cloudsmith.io/basic/${workspace}/${repo}/pub/\n    version: ${version}`,
      },
    };

    // Formats with dedicated handlers
    if (format === "docker") {
      return InstallCommandBuilder._buildDocker(name, version, workspace, repo, options);
    }
    if (format === "rpm") {
      return InstallCommandBuilder._buildRpm(name, version, workspace, repo);
    }
    if (format === "raw" || format === "generic") {
      return InstallCommandBuilder._buildRaw(name, version, workspace, repo, options);
    }

    const entry = commands[format];
    if (!entry) {
      const repositoryUrl = buildRepositoryUrl(workspace, repo) || WEB_APP_BASE_URL;
      return {
        command: `# Verify package details before running\n# No install command template for format: ${format}`,
        note: `Visit ${repositoryUrl} for setup instructions.`,
      };
    }
    return entry;
  }

  /**
   * Build Docker pull command — tag-first with optional digest alternative.
   */
  static _buildDocker(name, version, workspace, repo, opts) {
    const registry = `docker.cloudsmith.io/${workspace}/${repo}`;
    const imageName = InstallCommandBuilder._normalizeDockerName(name);
    const tag = InstallCommandBuilder._resolveDockerTag(version, opts || {});
    const result = {
      command: `# Verify package details before running\ndocker pull ${registry}/${imageName}:${tag}`,
      note: "Run `docker login docker.cloudsmith.io` first for private repositories.",
    };

    const digest = InstallCommandBuilder._normalizeDockerDigest((opts || {}).checksumSha256 || (opts || {}).versionDigest);
    if (digest) {
      result.alternatives = [{
        label: "Pull by digest (pinned)",
        command: `# Verify package details before running\ndocker pull ${registry}/${imageName}@sha256:${digest}`,
      }];
    }

    return result;
  }

  /**
   * Build RPM install command — dnf primary, yum alternative.
   */
  static _buildRpm(name, version, workspace, repo) {
    const safeName = InstallCommandBuilder.shellEscape(name);
    const safeVersion = InstallCommandBuilder.shellEscape(version);
    return {
      command: `# Verify package details before running\ndnf install ${safeName}-${safeVersion}`,
      note: `Requires a Cloudsmith repository configured in /etc/yum.repos.d/.\nRepository URL: https://dl.cloudsmith.io/basic/${workspace}/${repo}/rpm/`,
      alternatives: [{
        label: "Install via yum",
        command: `# Verify package details before running\nyum install ${safeName}-${safeVersion}`,
      }],
    };
  }

  /**
   * Build Raw/Generic download command — curl primary, wget alternative.
   */
  static _buildRaw(name, version, workspace, repo, opts) {
    const filename = opts.filename || `${name}-${version}`;
    const cdnUrl = opts.cdnUrl ||
      `https://dl.cloudsmith.io/basic/${workspace}/${repo}/raw/names/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}/${encodeURIComponent(filename)}`;

    return {
      command: `# Verify package details before running\ncurl -L -O "${cdnUrl}"`,
      note: 'For private repositories, replace "basic" with an entitlement token or use authentication headers.',
      alternatives: [{
        label: "Download via wget",
        command: `# Verify package details before running\nwget "${cdnUrl}"`,
      }],
    };
  }

  /**
   * Build a Maven pom.xml snippet with repository and dependency blocks.
   * Splits name on : to get groupId and artifactId.
   */
  static _buildMaven(name, version, workspace, repo) {
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
      `  <url>https://dl.cloudsmith.io/basic/${escapeXml(workspace)}/${escapeXml(repo)}/maven/</url>`,
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

module.exports = { InstallCommandBuilder };

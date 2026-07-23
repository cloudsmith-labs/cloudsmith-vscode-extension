// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const { parsePyprojectManifest } = require("./lockfileParsers/manifestHelpers");
const {
  getWorkspacePath,
  pathExists,
  readUtf8,
} = require("./lockfileParsers/shared");

class ManifestParser {
  /**
   * Detect which manifest files exist in a project directory.
   * Accepts a VS Code WorkspaceFolder object or a plain filesystem path string.
   * Returns array of { filePath, format, parserMethod }.
   *
   * @param   {vscode.WorkspaceFolder|string} workspaceFolderOrPath
   * @returns {Array<{filePath: string, format: string, parserMethod: string}>}
   */
  static async detectManifests(workspaceFolderOrPath) {
    const root = getWorkspacePath(workspaceFolderOrPath);
    const manifests = [];

    const checks = [
      { file: "package.json", format: "npm", parserMethod: "parseNpm" },
      { file: "requirements.txt", format: "python", parserMethod: "parsePythonRequirements" },
      { file: "pyproject.toml", format: "python", parserMethod: "parsePyproject" },
      { file: "pom.xml", format: "maven", parserMethod: "parseMaven" },
      { file: "go.mod", format: "go", parserMethod: "parseGoMod" },
      { file: "Cargo.toml", format: "cargo", parserMethod: "parseCargo" },
    ];

    for (const check of checks) {
      const filePath = path.join(root, check.file);
      if (await pathExists(filePath, root)) {
        manifests.push({
          filePath,
          format: check.format,
          parserMethod: check.parserMethod,
          workspaceFolder: root,
        });
      }
    }

    return manifests;
  }

  /**
   * Parse a manifest file using the appropriate parser method.
   *
   * @param   {{filePath: string, format: string, parserMethod: string}} manifest
   * @returns {Array<{name: string, version: string, devDependency: boolean, format: string}>}
   */
  static async parseManifest(manifest) {
    try {
      const content = await readUtf8(
        manifest.filePath,
        manifest.workspaceFolder || path.dirname(manifest.filePath || "")
      );
      const parser = ManifestParser[manifest.parserMethod];
      if (!parser) {
        return [];
      }
      return parser(content, manifest.format);
    } catch (e) {  // eslint-disable-line no-unused-vars
      return [];
    }
  }

  /**
   * Strip common version prefixes (^, ~, >=, <=, ~=, ==, !=, >).
   * Returns the bare version string.
   */
  static _stripVersionPrefix(version) {
    if (!version || typeof version !== "string") {
      return "";
    }
    return version.replace(/^[\^~>=<!]+\s*/, "").trim();
  }

  /**
   * Parse package.json — extract dependencies and devDependencies.
   * Returns [{ name, version, devDependency, format }]
   */
  static parseNpm(content, format) {
    const deps = [];
    try {
      const pkg = JSON.parse(content);

      if (pkg.dependencies) {
        for (const [name, version] of Object.entries(pkg.dependencies)) {
          deps.push({
            name: name,
            version: ManifestParser._stripVersionPrefix(version),
            devDependency: false,
            format: format || "npm",
          });
        }
      }

      if (pkg.devDependencies) {
        for (const [name, version] of Object.entries(pkg.devDependencies)) {
          deps.push({
            name: name,
            version: ManifestParser._stripVersionPrefix(version),
            devDependency: true,
            format: format || "npm",
          });
        }
      }
    } catch (e) {  // eslint-disable-line no-unused-vars
      // Malformed JSON, return what we have
    }
    return deps;
  }

  /**
   * Parse requirements.txt — line-by-line with operator handling.
   * Handles ==, >=, ~=, <=, != operators. Skips comments, blank lines,
   * -r includes, --index-url flags, and -e editable installs.
   */
  static parsePythonRequirements(content, format) {
    const deps = [];
    const lines = content.split("\n");

    for (const rawLine of lines) {
      const line = rawLine.trim();

      // Skip empty lines, comments, flags, and includes
      if (!line || line.startsWith("#") || line.startsWith("-r") ||
          line.startsWith("--") || line.startsWith("-e") ||
          line.startsWith("-f") || line.startsWith("-i")) {
        continue;
      }

      // Match: package_name[extras]==version, >=version, ~=version, etc.
      const match = line.match(/^([a-zA-Z0-9_\-.]+)(?:\[.*?\])?\s*([><=!~]+)\s*(.+)/);
      if (match) {
        deps.push({
          name: match[1],
          version: match[3].trim().split(/[,;]/)[0].trim(),
          devDependency: false,
          format: format || "python",
        });
      } else {
        // Bare package name without version
        const bareMatch = line.match(/^([a-zA-Z0-9_\-.]+)(?:\[.*?\])?\s*$/);
        if (bareMatch) {
          deps.push({
            name: bareMatch[1],
            version: "",
            devDependency: false,
            format: format || "python",
          });
        }
      }
    }
    return deps;
  }

  /**
   * Parse pyproject.toml via the shared lockfile manifest helper so
   * Poetry and PEP 621 formats stay consistent with lockfile resolution.
   */
  static parsePyproject(content, format) {
    const parsed = parsePyprojectManifest(content);
    return parsed.dependencies.map((dependency) => ({
      name: dependency.name,
      version: dependency.version,
      devDependency: dependency.isDevelopmentDependency,
      format: format || "python",
    }));
  }

  /**
   * Parse pom.xml — regex-based extraction of <dependency> blocks.
   * Pulls groupId, artifactId, version. Combines as groupId:artifactId.
   * Skips dependencies with property references like ${project.version}.
   */
  static parseMaven(content, format) {
    const deps = [];
    const depBlockRegex = /<dependency>\s*([\s\S]*?)\s*<\/dependency>/g;
    const groupIdRegex = /<groupId>\s*([^<]+)\s*<\/groupId>/;
    const artifactIdRegex = /<artifactId>\s*([^<]+)\s*<\/artifactId>/;
    const versionRegex = /<version>\s*([^<]+)\s*<\/version>/;
    const scopeRegex = /<scope>\s*([^<]+)\s*<\/scope>/;

    let match;
    while ((match = depBlockRegex.exec(content)) !== null) {
      const block = match[1];
      const groupId = groupIdRegex.exec(block);
      const artifactId = artifactIdRegex.exec(block);
      const version = versionRegex.exec(block);
      const scope = scopeRegex.exec(block);

      if (!groupId || !artifactId) {
        continue;
      }

      const versionStr = version ? version[1].trim() : "";

      // Skip property references like ${project.version}
      if (versionStr.startsWith("${")) {
        continue;
      }

      const isTest = !!(scope && scope[1].trim() === "test");

      deps.push({
        name: `${groupId[1].trim()}:${artifactId[1].trim()}`,
        version: versionStr,
        devDependency: isTest,
        format: format || "maven",
      });
    }
    return deps;
  }

  /**
   * Parse go.mod — extract require block entries.
   * Each line in the require block: module/path vX.Y.Z
   * Strips the v prefix from versions.
   */
  static parseGoMod(content, format) {
    const deps = [];
    const lines = content.split("\n");
    let inRequire = false;

    for (const rawLine of lines) {
      const line = rawLine.trim();

      // Single-line require: require module/path v1.2.3
      if (line.startsWith("require ") && !line.includes("(")) {
        const match = line.match(/^require\s+(\S+)\s+v?(\S+)/);
        if (match) {
          deps.push({
            name: match[1],
            version: match[2],
            devDependency: false,
            format: format || "go",
          });
        }
        continue;
      }

      // Block require start
      if (line === "require (") {
        inRequire = true;
        continue;
      }

      if (line === ")" && inRequire) {
        inRequire = false;
        continue;
      }

      if (inRequire) {
        if (!line || line.startsWith("//")) {
          continue;
        }
        // module/path v1.2.3 // indirect
        const match = line.match(/^(\S+)\s+v?(\S+)/);
        if (match) {
          const isIndirect = line.includes("// indirect");
          deps.push({
            name: match[1],
            version: match[2],
            devDependency: isIndirect,
            format: format || "go",
          });
        }
      }
    }
    return deps;
  }

  /**
   * Parse Cargo.toml — find [dependencies] and [dev-dependencies] sections.
   * Handles name = "version" and name = { version = "version" } patterns.
   */
  static parseCargo(content, format) {
    const deps = [];
    const lines = content.split("\n");
    let currentSection = null;

    for (const rawLine of lines) {
      const line = rawLine.trim();

      // Detect section headers
      if (line.startsWith("[")) {
        if (line === "[dependencies]") {
          currentSection = "deps";
        } else if (line === "[dev-dependencies]") {
          currentSection = "devDeps";
        } else {
          currentSection = null;
        }
        continue;
      }

      if (!currentSection) {
        continue;
      }

      if (!line || line.startsWith("#")) {
        continue;
      }

      const isDev = currentSection === "devDeps";

      // name = "version"
      const simpleMatch = line.match(/^([a-zA-Z0-9_\-.]+)\s*=\s*"([^"]*)"/);
      if (simpleMatch) {
        deps.push({
          name: simpleMatch[1],
          version: ManifestParser._stripVersionPrefix(simpleMatch[2]),
          devDependency: isDev,
          format: format || "cargo",
        });
        continue;
      }

      // name = { version = "version", ... }
      const complexMatch = line.match(/^([a-zA-Z0-9_\-.]+)\s*=\s*\{.*version\s*=\s*"([^"]*)"/);
      if (complexMatch) {
        deps.push({
          name: complexMatch[1],
          version: ManifestParser._stripVersionPrefix(complexMatch[2]),
          devDependency: isDev,
          format: format || "cargo",
        });
      }
    }
    return deps;
  }

  /**
   * Find the location of a dependency name within a manifest file.
   * Returns { line, startChar, endChar } (0-indexed) or null if not found.
   *
   * @param   {string} filePath       Absolute path to the manifest file.
   * @param   {string} dependencyName The dependency name to locate.
   * @param   {string} format         The manifest format (npm, python, maven, go, cargo).
   * @returns {Promise<{line: number, startChar: number, endChar: number}|null>}
   */
  static async findDependencyLocation(filePath, dependencyName, format) {
    try {
      const content = await readUtf8(filePath, path.dirname(filePath));
      const lines = content.split("\n");

      switch (format) {
        case "npm":
          return ManifestParser._findInPackageJson(lines, dependencyName);
        case "python":
          return ManifestParser._findLineStartsWith(lines, dependencyName);
        case "maven":
          return ManifestParser._findInMaven(lines, dependencyName);
        case "go":
          return ManifestParser._findInGoMod(lines, dependencyName);
        default:
          return ManifestParser._findLineContaining(lines, dependencyName);
      }
    } catch (e) {  // eslint-disable-line no-unused-vars
      return null;
    }
  }

  /**
   * Find a dependency key in package.json's dependencies/devDependencies objects.
   */
  static _findInPackageJson(lines, name) {
    // Look for "name": inside dependencies or devDependencies
    const pattern = new RegExp(`"${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"\\s*:`);
    for (let i = 0; i < lines.length; i++) {
      const match = lines[i].match(pattern);
      if (match) {
        const startChar = lines[i].indexOf(`"${name}"`);
        return { line: i, startChar: startChar, endChar: startChar + name.length + 2 };
      }
    }
    return ManifestParser._findLineContaining(lines, name);
  }

  /**
   * Find a line that starts with the dependency name (requirements.txt, pyproject.toml).
   */
  static _findLineStartsWith(lines, name) {
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trim();
      if (trimmed.startsWith(name) && (trimmed.length === name.length || /[\s=<>!~\[;,]/.test(trimmed[name.length]))) {
        const startChar = lines[i].indexOf(name);
        return { line: i, startChar: startChar, endChar: startChar + name.length };
      }
    }
    return ManifestParser._findLineContaining(lines, name);
  }

  /**
   * Find a dependency in pom.xml by looking for <artifactId>name</artifactId>.
   * For groupId:artifactId format, search for the artifactId part.
   */
  static _findInMaven(lines, name) {
    const artifactId = name.includes(":") ? name.split(":")[1] : name;
    const pattern = `<artifactId>${artifactId}</artifactId>`;
    for (let i = 0; i < lines.length; i++) {
      const idx = lines[i].indexOf(pattern);
      if (idx !== -1) {
        return { line: i, startChar: idx, endChar: idx + pattern.length };
      }
    }
    return ManifestParser._findLineContaining(lines, artifactId);
  }

  /**
   * Find a module path in go.mod's require block.
   */
  static _findInGoMod(lines, name) {
    for (let i = 0; i < lines.length; i++) {
      const idx = lines[i].indexOf(name);
      if (idx !== -1) {
        return { line: i, startChar: idx, endChar: idx + name.length };
      }
    }
    return null;
  }

  /**
   * Fallback: find any line containing the dependency name.
   */
  static _findLineContaining(lines, name) {
    for (let i = 0; i < lines.length; i++) {
      const idx = lines[i].indexOf(name);
      if (idx !== -1) {
        return { line: i, startChar: idx, endChar: idx + name.length };
      }
    }
    return null;
  }
}

module.exports = { ManifestParser };

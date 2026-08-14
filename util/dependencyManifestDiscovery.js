// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const {
  getWorkspacePath,
  readBoundedDirectoryEntries,
  resolveWorkspaceFilePath,
} = require("./lockfileParsers/shared");

const MAX_DISCOVERY_DEPTH = 8;
const MAX_DISCOVERY_DIRECTORIES = 5000;
const MAX_DISCOVERY_ENTRIES = 50000;
const MAX_DISCOVERED_MANIFESTS = 250;

const EXCLUDED_DIRECTORIES = new Set([
  ".dart_tool",
  ".git",
  ".gradle",
  ".idea",
  ".mypy_cache",
  ".next",
  ".pytest_cache",
  ".tox",
  ".venv",
  ".vscode",
  "__pycache__",
  "build",
  "coverage",
  "deriveddata",
  "dist",
  "env",
  "node_modules",
  "out",
  "pods",
  "target",
  "vendor",
  "venv",
]);

const MANIFEST_DESCRIPTORS = Object.freeze({
  "package.json": { format: "npm", parserMethod: "parseNpm" },
  "requirements.txt": { format: "python", parserMethod: "parsePythonRequirements" },
  "pyproject.toml": { format: "python", parserMethod: "parsePyproject" },
  "pipfile": { format: "python", parserMethod: null },
  "pom.xml": { format: "maven", parserMethod: "parseMaven" },
  "build.gradle": { format: "gradle", parserMethod: null },
  "build.gradle.kts": { format: "gradle", parserMethod: null },
  "go.mod": { format: "go", parserMethod: "parseGoMod" },
  "cargo.toml": { format: "cargo", parserMethod: "parseCargo" },
  "gemfile": { format: "ruby", parserMethod: null },
  "dockerfile": { format: "docker", parserMethod: null },
  "docker-compose.yml": { format: "docker", parserMethod: null },
  "docker-compose.yaml": { format: "docker", parserMethod: null },
  "compose.yml": { format: "docker", parserMethod: null },
  "compose.yaml": { format: "docker", parserMethod: null },
  "pubspec.yaml": { format: "dart", parserMethod: null },
  "composer.json": { format: "composer", parserMethod: null },
  "chart.yaml": { format: "helm", parserMethod: null },
  "package.swift": { format: "swift", parserMethod: null },
  "mix.exs": { format: "hex", parserMethod: null },
});

async function discoverDependencyManifests(workspaceFolder, options = {}) {
  throwIfDiscoveryCancelled(options);
  const workspacePath = getWorkspacePath(workspaceFolder);
  const workspaceRoot = await resolveWorkspaceFilePath(workspacePath, workspacePath);
  if (!workspaceRoot) {
    return { manifests: [], warnings: [] };
  }

  const manifests = [];
  const warnings = [];
  const queue = [{ directory: workspaceRoot, depth: 0 }];
  let directoriesQueued = 1;
  let entriesScanned = 0;
  let truncated = false;
  let incompleteTraversal = false;

  while (queue.length > 0 && !truncated) {
    throwIfDiscoveryCancelled(options);
    const current = queue.shift();
    let directoryResult;
    try {
      directoryResult = await readBoundedDirectoryEntries(
        current.directory,
        MAX_DISCOVERY_ENTRIES - entriesScanned,
        { ...options, workspaceFolder: workspaceRoot }
      );
    } catch (error) {
      if (error && error.code === "ERR_DEPENDENCY_TRAVERSAL_CANCELLED") {
        throwIfDiscoveryCancelled(options);
        throw error;
      }
      incompleteTraversal = true;
      continue;
    }

    const entries = directoryResult.entries;
    if (directoryResult.truncated) truncated = true;
    entriesScanned += entries.length;
    // Sorting the bounded sample keeps processing stable without materializing
    // an unbounded directory. At the global cap, the filesystem determines the
    // sampled subset; the explicit truncation warning prevents claiming a full scan.
    entries.sort((left, right) => left.name.localeCompare(right.name));

    const childDirectories = [];
    for (const entry of entries) {
      throwIfDiscoveryCancelled(options);
      if (entry.isSymbolicLink()) {
        continue;
      }
      if (entry.isDirectory()) {
        if (
          current.depth < MAX_DISCOVERY_DEPTH
          && !EXCLUDED_DIRECTORIES.has(entry.name.toLowerCase())
        ) {
          childDirectories.push(path.join(current.directory, entry.name));
        }
        continue;
      }
      if (!entry.isFile()) {
        continue;
      }

      const descriptor = describeManifest(entry.name);
      if (!descriptor) {
        continue;
      }
      if (manifests.length >= MAX_DISCOVERED_MANIFESTS) {
        truncated = true;
        break;
      }
      manifests.push({
        filePath: path.join(current.directory, entry.name),
        format: descriptor.format,
        parserMethod: descriptor.parserMethod,
        workspaceFolder: workspaceRoot,
      });
    }

    childDirectories.sort((left, right) => left.localeCompare(right));
    for (const childDirectory of childDirectories) {
      throwIfDiscoveryCancelled(options);
      if (directoriesQueued >= MAX_DISCOVERY_DIRECTORIES) {
        truncated = true;
        break;
      }
      queue.push({ directory: childDirectory, depth: current.depth + 1 });
      directoriesQueued += 1;
    }
  }

  if (truncated) {
    warnings.push(
      "Dependency manifest discovery reached its bounded scan limit; some nested projects may not have been scanned."
    );
  }
  if (incompleteTraversal) {
    warnings.push(
      "Dependency manifest discovery could not safely scan every directory; some nested projects may not have been scanned."
    );
  }

  manifests.sort((left, right) => left.filePath.localeCompare(right.filePath));
  return { manifests, warnings };
}

function throwIfDiscoveryCancelled(options) {
  if (!(options && options.cancellationToken && options.cancellationToken.isCancellationRequested)) {
    return;
  }
  const error = new Error("Dependency manifest discovery was canceled.");
  error.code = "ERR_DEPENDENCY_DISCOVERY_CANCELLED";
  throw error;
}

function describeManifest(fileName) {
  const normalized = String(fileName || "").toLowerCase();
  if (MANIFEST_DESCRIPTORS[normalized]) {
    return MANIFEST_DESCRIPTORS[normalized];
  }
  if (normalized.startsWith("dockerfile.")) {
    return { format: "docker", parserMethod: null };
  }
  if (normalized.endsWith(".csproj")) {
    return { format: "nuget", parserMethod: null };
  }
  return null;
}

module.exports = {
  MAX_DISCOVERED_MANIFESTS,
  discoverDependencyManifests,
};

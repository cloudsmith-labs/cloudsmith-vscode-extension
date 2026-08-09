// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const fs = require("fs");
const path = require("path");
const {
  getWorkspacePath,
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

async function discoverDependencyManifests(workspaceFolder) {
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

  while (queue.length > 0 && !truncated) {
    const current = queue.shift();
    let directory;
    try {
      directory = await fs.promises.opendir(current.directory);
    } catch {
      continue;
    }

    const entries = [];
    const remainingEntryBudget = MAX_DISCOVERY_ENTRIES - entriesScanned;
    for await (const entry of directory) {
      if (entries.length >= remainingEntryBudget) {
        truncated = true;
        break;
      }
      entries.push(entry);
    }
    entriesScanned += entries.length;
    // Sorting the bounded sample keeps processing stable without materializing
    // an unbounded directory. At the global cap, the filesystem determines the
    // sampled subset; the explicit truncation warning prevents claiming a full scan.
    entries.sort((left, right) => left.name.localeCompare(right.name));

    const childDirectories = [];
    for (const entry of entries) {
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

  manifests.sort((left, right) => left.filePath.localeCompare(right.filePath));
  return { manifests, warnings };
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

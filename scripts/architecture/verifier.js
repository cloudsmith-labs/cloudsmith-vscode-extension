// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const fs = require("fs");
const path = require("path");
const { Linter } = require("eslint");

const METADATA_KEYS = Object.freeze([
  "adapterFiles",
  "canonicalFactoryFiles",
  "commandRegistrationFiles",
  "compositionFile",
  "cycleExemptions",
  "ignoredSegments",
  "internalCommandIds",
  "layers",
  "limits",
  "nonJavaScriptPackageFiles",
  "registrars",
  "runtimeRoots",
  "schemaVersion",
]);
const LIMIT_KEYS = Object.freeze([
  "maxDepth",
  "maxDiagnostics",
  "maxEntries",
  "maxFileBytes",
  "maxFiles",
  "maxImports",
  "maxTotalBytes",
]);
const LIMIT_MAXIMUMS = Object.freeze({
  maxDepth: 32,
  maxDiagnostics: 1024,
  maxEntries: 10000,
  maxFileBytes: 1024 * 1024,
  maxFiles: 1000,
  maxImports: 10000,
  maxTotalBytes: 32 * 1024 * 1024,
});
const DATA_RESOURCE_NAMES = new Set(["package.json"]);
const NON_JAVASCRIPT_EXACT_EXTENSIONS = new Set([
  ".gif",
  ".jpeg",
  ".jpg",
  ".md",
  ".png",
  ".svg",
]);
const NON_JAVASCRIPT_EXTENSIONLESS_NAMES = new Set(["LICENSE"]);
const DYNAMIC_CODE_CONSTRUCTORS = new Set([
  "AsyncFunction",
  "AsyncGeneratorFunction",
  "Function",
  "GeneratorFunction",
  "eval",
]);
const LAYER_KEYS = Object.freeze([
  "allowedExternals",
  "allowedLayers",
  "allowedResources",
  "excludeFiles",
  "files",
  "id",
  "roots",
]);
const REGISTRAR_KEYS = Object.freeze(["commands", "file", "function"]);
const LEGACY_PACKAGE_NAMES = new Set([
  "cdn_url",
  "cloudsmithWorkspace",
  "cloudsmithRepo",
  "cloudsmithMatch",
  "cloudsmithPackage",
  "checksum_sha256",
  "deny_policy_violated",
  "has_vulnerabilities",
  "is_copyable",
  "license_policy_violated",
  "license_url",
  "namespace",
  "num_vulnerabilities",
  "policy_violated",
  "raw_license",
  "security_scan_status",
  "slug_perm",
  "slug_perm_raw",
  "spdx_license",
  "status_reason",
  "status_str",
  "status_str_raw",
  "tags_raw",
  "unwrapValue",
  "extractPackageInfo",
  "getNestedInstallField",
  "getInstallTags",
  "version_digest",
  "vulnerability_policy_violated",
]);
class ArchitectureError extends Error {
  constructor(diagnostics) {
    const lines = diagnostics.map((diagnostic) => {
      const location = diagnostic.line ? `:${diagnostic.line}:${diagnostic.column || 1}` : "";
      return `${diagnostic.code} ${diagnostic.path}${location} ${diagnostic.message}`;
    });
    super(`Architecture verification failed with ${diagnostics.length} violation(s):\n${lines.join("\n")}`);
    this.name = "ArchitectureError";
    this.diagnostics = diagnostics;
  }
}

function diagnostic(code, relativePath, message, node = null) {
  return {
    code,
    path: toPosix(relativePath),
    message,
    ...(node?.loc?.start ? {
      line: node.loc.start.line,
      column: node.loc.start.column + 1,
    } : {}),
  };
}

function toPosix(value) {
  return String(value).split(path.sep).join("/");
}

function sameKeys(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value).sort();
  return actual.length === keys.length
    && actual.every((key, index) => key === [...keys].sort()[index]);
}

function isPlainStringArray(value) {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string");
}

function hasDuplicates(value) {
  return Array.isArray(value) && new Set(value).size !== value.length;
}

function normalizeMetadataPath(root, relativePath, diagnostics, owner = "architecture.json") {
  if (
    typeof relativePath !== "string"
    || !relativePath
    || relativePath.includes("\\")
    || path.posix.isAbsolute(relativePath)
    || path.win32.isAbsolute(relativePath)
    || relativePath !== path.posix.normalize(relativePath)
    || relativePath !== relativePath.normalize("NFC")
    || relativePath === "."
    || relativePath === ".."
    || relativePath.startsWith("../")
    || /[\u0000-\u001f\u007f]/.test(relativePath)
    || /[*?[\]]/.test(relativePath)
  ) {
    diagnostics.push(diagnostic(
      "ARCH_METADATA_PATH",
      owner,
      `Metadata path must be a normalized, repository-relative POSIX path: ${String(relativePath)}`,
    ));
    return null;
  }
  const absolutePath = path.resolve(root, ...relativePath.split("/"));
  const relative = path.relative(root, absolutePath);
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    diagnostics.push(diagnostic("ARCH_ROOT_ESCAPE", owner, `Metadata path escapes the repository: ${relativePath}`));
    return null;
  }
  return toPosix(relative);
}

function validateMetadata(root, metadata) {
  const diagnostics = [];
  if (!sameKeys(metadata, METADATA_KEYS)) {
    diagnostics.push(diagnostic("ARCH_METADATA_SCHEMA", "architecture.json", "Metadata has unsupported or missing top-level keys"));
    return { diagnostics, metadata: null };
  }
  if (metadata.schemaVersion !== 1) {
    diagnostics.push(diagnostic("ARCH_METADATA_SCHEMA", "architecture.json", "schemaVersion must be exactly 1"));
  }
  if (!sameKeys(metadata.limits, LIMIT_KEYS)) {
    diagnostics.push(diagnostic("ARCH_METADATA_SCHEMA", "architecture.json", "limits has unsupported or missing keys"));
  } else {
    for (const key of LIMIT_KEYS) {
      if (
        !Number.isSafeInteger(metadata.limits[key])
        || metadata.limits[key] <= 0
        || metadata.limits[key] > LIMIT_MAXIMUMS[key]
      ) {
        diagnostics.push(diagnostic(
          "ARCH_METADATA_LIMIT",
          "architecture.json",
          `${key} must be a positive safe integer no greater than ${LIMIT_MAXIMUMS[key]}`,
        ));
      }
    }
  }
  if (!isPlainStringArray(metadata.ignoredSegments) || metadata.ignoredSegments.length === 0) {
    diagnostics.push(diagnostic("ARCH_METADATA_SCHEMA", "architecture.json", "ignoredSegments must be a non-empty string array"));
  }
  for (const segment of metadata.ignoredSegments || []) {
    if (!segment || segment.includes("/") || segment.includes("\\") || /[*?[\]]/.test(segment)) {
      diagnostics.push(diagnostic("ARCH_METADATA_BYPASS", "architecture.json", `Ignored segment must be exact: ${String(segment)}`));
    }
  }
  for (const key of [
    "adapterFiles",
    "canonicalFactoryFiles",
    "commandRegistrationFiles",
    "internalCommandIds",
    "nonJavaScriptPackageFiles",
    "runtimeRoots",
  ]) {
    if (!isPlainStringArray(metadata[key])) {
      diagnostics.push(diagnostic("ARCH_METADATA_SCHEMA", "architecture.json", `${key} must be a string array`));
    } else if (hasDuplicates(metadata[key])) {
      diagnostics.push(diagnostic("ARCH_METADATA_DUPLICATE", "architecture.json", `${key} contains duplicates`));
    }
  }
  if (!Array.isArray(metadata.layers) || metadata.layers.length === 0 || metadata.layers.length > 64) {
    diagnostics.push(diagnostic("ARCH_METADATA_SCHEMA", "architecture.json", "layers must contain between 1 and 64 entries"));
  }
  if (!Array.isArray(metadata.registrars) || metadata.registrars.length === 0 || metadata.registrars.length > 32) {
    diagnostics.push(diagnostic("ARCH_METADATA_SCHEMA", "architecture.json", "registrars must contain between 1 and 32 entries"));
  }

  const normalized = {
    ...metadata,
    compositionFile: normalizeMetadataPath(root, metadata.compositionFile, diagnostics),
    adapterFiles: [],
    canonicalFactoryFiles: [],
    commandRegistrationFiles: [],
    cycleExemptions: [],
    layers: [],
    nonJavaScriptPackageFiles: [],
    registrars: [],
    runtimeRoots: [],
  };
  for (const key of [
    "adapterFiles",
    "canonicalFactoryFiles",
    "commandRegistrationFiles",
  ]) {
    for (const entry of metadata[key] || []) {
      const normalizedPath = normalizeMetadataPath(root, entry, diagnostics);
      if (normalizedPath) {
        normalized[key].push(normalizedPath);
      }
    }
  }
  for (const runtimeRoot of metadata.runtimeRoots || []) {
    const normalizedPath = normalizeMetadataPath(root, runtimeRoot, diagnostics);
    if (normalizedPath) normalized.runtimeRoots.push(normalizedPath);
  }
  for (const entry of metadata.nonJavaScriptPackageFiles || []) {
    const hasGlob = typeof entry === "string" && /[*?\[]/.test(entry);
    const exactExtension = typeof entry === "string" ? path.posix.extname(entry).toLowerCase() : "";
    if (
      typeof entry !== "string"
      || !entry
      || entry.includes("\\")
      || entry.includes("**")
      || path.posix.isAbsolute(entry)
      || path.win32.isAbsolute(entry)
      || entry !== path.posix.normalize(entry)
      || entry.startsWith("../")
      || /[\u0000-\u001f\u007f]/.test(entry)
      || /\.(?:cjs|js|mjs|node|wasm)(?:$|[*?\[])/i.test(entry)
      || (
        hasGlob
        && (
          !/^media\/(?:[A-Za-z0-9._*-]+\/)*[A-Za-z0-9._*-]+\.(?:gif|jpe?g|png|svg)$/.test(entry)
          || /[?\[]/.test(entry)
        )
      )
      || (
        !hasGlob
        && !NON_JAVASCRIPT_EXACT_EXTENSIONS.has(exactExtension)
        && !NON_JAVASCRIPT_EXTENSIONLESS_NAMES.has(path.posix.basename(entry))
      )
    ) {
      diagnostics.push(diagnostic(
        "ARCH_METADATA_PACKAGE_FILE",
        "architecture.json",
        `Non-JavaScript package entry is unsafe or broad: ${String(entry)}`,
      ));
      continue;
    }
    if (hasGlob) {
      const parent = entry.slice(0, entry.lastIndexOf("/"));
      const ancestor = symlinkAncestor(root, parent);
      const stats = fs.lstatSync(path.join(root, ...parent.split("/")), { throwIfNoEntry: false });
      if (ancestor || !stats?.isDirectory()) {
        diagnostics.push(diagnostic(
          "ARCH_METADATA_PACKAGE_FILE",
          "architecture.json",
          `Non-JavaScript package glob must have a real non-symlink directory: ${entry}`,
        ));
        continue;
      }
    } else {
      const normalizedPath = normalizeMetadataPath(root, entry, diagnostics);
      const ancestor = normalizedPath ? symlinkAncestor(root, normalizedPath) : null;
      const stats = normalizedPath
        ? fs.lstatSync(path.join(root, ...normalizedPath.split("/")), { throwIfNoEntry: false })
        : null;
      if (
        !normalizedPath
        || ancestor
        || !stats?.isFile()
        || stats.isSymbolicLink()
        || stats.size > (metadata.limits?.maxFileBytes || LIMIT_MAXIMUMS.maxFileBytes)
      ) {
        diagnostics.push(diagnostic(
          "ARCH_METADATA_PACKAGE_FILE",
          "architecture.json",
          `Non-JavaScript package entry must be a bounded regular non-symlink file: ${entry}`,
        ));
        continue;
      }
    }
    normalized.nonJavaScriptPackageFiles.push(entry);
  }
  if (!Array.isArray(metadata.cycleExemptions) || metadata.cycleExemptions.length > 16) {
    diagnostics.push(diagnostic("ARCH_METADATA_SCHEMA", "architecture.json", "cycleExemptions must be a bounded array"));
  } else {
    for (const exemption of metadata.cycleExemptions) {
      if (!isPlainStringArray(exemption) || exemption.length < 2 || exemption.length > 16 || hasDuplicates(exemption)) {
        diagnostics.push(diagnostic("ARCH_METADATA_CYCLE", "architecture.json", "Cycle exemptions must contain 2-16 unique exact files"));
        continue;
      }
      const normalizedExemption = exemption
        .map(file => normalizeMetadataPath(root, file, diagnostics))
        .filter(Boolean)
        .sort();
      if (normalizedExemption.length === exemption.length) normalized.cycleExemptions.push(normalizedExemption);
    }
  }

  const layerIds = new Set();
  const layerRoots = [];
  const claimedFiles = new Map();
  for (const layer of metadata.layers || []) {
    if (!sameKeys(layer, LAYER_KEYS)) {
      diagnostics.push(diagnostic("ARCH_METADATA_SCHEMA", "architecture.json", "A layer has unsupported or missing keys"));
      continue;
    }
    if (!/^[a-z][a-z0-9-]{1,63}$/.test(layer.id || "") || layerIds.has(layer.id)) {
      diagnostics.push(diagnostic("ARCH_METADATA_LAYER", "architecture.json", `Layer id is invalid or duplicated: ${String(layer.id)}`));
      continue;
    }
    layerIds.add(layer.id);
    if (
      !isPlainStringArray(layer.roots)
      || !isPlainStringArray(layer.files)
      || !isPlainStringArray(layer.excludeFiles)
      || !isPlainStringArray(layer.allowedLayers)
      || !isPlainStringArray(layer.allowedExternals)
      || !isPlainStringArray(layer.allowedResources)
    ) {
      diagnostics.push(diagnostic("ARCH_METADATA_SCHEMA", "architecture.json", `Layer ${layer.id} contains an invalid field type`));
      continue;
    }
    for (const [field, values] of [
      ["roots", layer.roots],
      ["files", layer.files],
      ["excludeFiles", layer.excludeFiles],
      ["allowedLayers", layer.allowedLayers],
      ["allowedExternals", layer.allowedExternals],
      ["allowedResources", layer.allowedResources],
    ]) {
      if (hasDuplicates(values)) {
        diagnostics.push(diagnostic("ARCH_METADATA_DUPLICATE", "architecture.json", `Layer ${layer.id} has duplicate ${field}`));
      }
    }
    if (layer.allowedExternals.some((entry) => !entry || /[\\/*?[\]]/.test(entry))) {
      diagnostics.push(diagnostic("ARCH_METADATA_BYPASS", "architecture.json", `Layer ${layer.id} has a broad or invalid external allowlist entry`));
    }
    if (layer.roots.length + layer.files.length === 0) {
      diagnostics.push(diagnostic("ARCH_METADATA_LAYER", "architecture.json", `Layer ${layer.id} has no roots or files`));
    }
    const normalizedLayer = {
      ...layer,
      roots: [],
      files: [],
      excludeFiles: [],
      allowedResources: [],
    };
    for (const rootPath of layer.roots) {
      const normalizedPath = normalizeMetadataPath(root, rootPath, diagnostics);
      if (normalizedPath) {
        normalizedLayer.roots.push(normalizedPath);
        layerRoots.push({ id: layer.id, path: normalizedPath });
      }
    }
    for (const filePath of layer.files) {
      const normalizedPath = normalizeMetadataPath(root, filePath, diagnostics);
      if (normalizedPath) {
        normalizedLayer.files.push(normalizedPath);
        const previous = claimedFiles.get(normalizedPath);
        if (previous) {
          diagnostics.push(diagnostic("ARCH_METADATA_OVERLAP", "architecture.json", `${normalizedPath} is claimed by ${previous} and ${layer.id}`));
        }
        claimedFiles.set(normalizedPath, layer.id);
      }
    }
    for (const filePath of layer.excludeFiles) {
      const normalizedPath = normalizeMetadataPath(root, filePath, diagnostics);
      if (normalizedPath) {
        normalizedLayer.excludeFiles.push(normalizedPath);
      }
    }
    for (const filePath of layer.allowedResources) {
      const normalizedPath = normalizeMetadataPath(root, filePath, diagnostics);
      if (normalizedPath) {
        normalizedLayer.allowedResources.push(normalizedPath);
      }
    }
    normalized.layers.push(normalizedLayer);
  }
  for (let left = 0; left < layerRoots.length; left += 1) {
    for (let right = left + 1; right < layerRoots.length; right += 1) {
      const a = `${layerRoots[left].path}/`;
      const b = `${layerRoots[right].path}/`;
      if (a.startsWith(b) || b.startsWith(a)) {
        diagnostics.push(diagnostic(
          "ARCH_METADATA_OVERLAP",
          "architecture.json",
          `Layer roots overlap: ${layerRoots[left].path} and ${layerRoots[right].path}`,
        ));
      }
    }
  }
  for (const [filePath, owner] of claimedFiles) {
    for (const layer of normalized.layers) {
      if (layer.id === owner || layer.excludeFiles.includes(filePath)) {
        continue;
      }
      if (layer.roots.some((rootPath) => filePath.startsWith(`${rootPath}/`))) {
        diagnostics.push(diagnostic("ARCH_METADATA_OVERLAP", "architecture.json", `${filePath} overlaps layer root ${layer.id}`));
      }
    }
  }
  for (const layer of normalized.layers) {
    for (const target of layer.allowedLayers) {
      if (!layerIds.has(target)) {
        diagnostics.push(diagnostic("ARCH_METADATA_EDGE", "architecture.json", `Layer ${layer.id} allows unknown layer ${target}`));
      }
    }
  }

  const registrarFiles = new Set();
  const ownedCommands = new Set();
  for (const registrar of metadata.registrars || []) {
    if (!sameKeys(registrar, REGISTRAR_KEYS)) {
      diagnostics.push(diagnostic("ARCH_METADATA_SCHEMA", "architecture.json", "A registrar has unsupported or missing keys"));
      continue;
    }
    const file = normalizeMetadataPath(root, registrar.file, diagnostics);
    if (
      !file
      || !file.startsWith("commands/")
      || !/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(registrar.function || "")
      || !isPlainStringArray(registrar.commands)
      || registrar.commands.length === 0
    ) {
      diagnostics.push(diagnostic("ARCH_METADATA_REGISTRAR", "architecture.json", `Registrar declaration is invalid: ${String(registrar.file)}`));
      continue;
    }
    if (registrarFiles.has(file)) {
      diagnostics.push(diagnostic("ARCH_METADATA_REGISTRAR", "architecture.json", `Registrar file is duplicated: ${file}`));
    }
    registrarFiles.add(file);
    for (const command of registrar.commands) {
      if (!/^cloudsmith-(?:vsc|vscode-extension)\.[A-Za-z0-9]+$/.test(command) || ownedCommands.has(command)) {
        diagnostics.push(diagnostic("ARCH_METADATA_COMMAND", "architecture.json", `Command id is invalid or duplicated: ${String(command)}`));
      }
      ownedCommands.add(command);
    }
    normalized.registrars.push({ ...registrar, file });
  }
  const internal = new Set(metadata.internalCommandIds || []);
  if (internal.size !== (metadata.internalCommandIds || []).length) {
    diagnostics.push(diagnostic("ARCH_METADATA_COMMAND", "architecture.json", "internalCommandIds contains duplicates"));
  }
  for (const command of internal) {
    if (!ownedCommands.has(command)) {
      diagnostics.push(diagnostic("ARCH_METADATA_COMMAND", "architecture.json", `Internal command has no owner: ${command}`));
    }
  }
  for (const file of normalized.adapterFiles) {
    const layer = normalized.layers.find((candidate) => candidate.id === "domain-adapter");
    if (!layer || !layer.files.includes(file)) {
      diagnostics.push(diagnostic("ARCH_METADATA_ADAPTER", "architecture.json", `Adapter allowlist file is not an exact domain-adapter file: ${file}`));
    }
  }
  const adapterLayerFiles = normalized.layers.find((candidate) => candidate.id === "domain-adapter")?.files || [];
  for (const file of adapterLayerFiles) {
    if (!normalized.adapterFiles.includes(file)) {
      diagnostics.push(diagnostic("ARCH_METADATA_ADAPTER", "architecture.json", `Domain adapter file lacks an exact allowlist entry: ${file}`));
    }
  }
  for (const file of normalized.canonicalFactoryFiles) {
    if (!normalized.layers.some((layer) => layer.files.includes(file) || layer.roots.some((rootPath) => file.startsWith(`${rootPath}/`)))) {
      diagnostics.push(diagnostic("ARCH_METADATA_FACTORY", "architecture.json", `Canonical factory file is outside declared layers: ${file}`));
    }
  }
  for (const runtimeRoot of normalized.runtimeRoots) {
    if (runtimeRoot.includes("/") || path.posix.extname(runtimeRoot)) {
      diagnostics.push(diagnostic(
        "ARCH_METADATA_RUNTIME_ROOT",
        "architecture.json",
        `Runtime roots must be exact top-level directories: ${runtimeRoot}`,
      ));
    }
  }
  for (const layer of normalized.layers) {
    for (const excluded of layer.excludeFiles) {
      const owner = normalized.layers.find(candidate => (
        candidate.id !== layer.id && candidate.files.includes(excluded)
      ));
      if (!owner) {
        diagnostics.push(diagnostic(
          "ARCH_METADATA_ORPHAN_EXCLUSION",
          "architecture.json",
          `${layer.id} excludes ${excluded} without another exact layer owner`,
        ));
      }
    }
    for (const resource of layer.allowedResources) {
      const ancestor = symlinkAncestor(root, resource);
      const absoluteResource = path.join(root, ...resource.split("/"));
      const stats = fs.lstatSync(absoluteResource, { throwIfNoEntry: false });
      if (
        !DATA_RESOURCE_NAMES.has(resource)
        || ancestor
        || !stats?.isFile()
        || stats.isSymbolicLink()
        || stats.size > (metadata.limits?.maxFileBytes || LIMIT_MAXIMUMS.maxFileBytes)
      ) {
        diagnostics.push(diagnostic(
          "ARCH_METADATA_RESOURCE_ALLOWLIST",
          "architecture.json",
          `${layer.id} resource must be an exact bounded reviewed JSON/data file: ${resource}`,
        ));
      }
    }
    for (const sourcePath of [...layer.roots, ...layer.files]) {
      if (!normalized.runtimeRoots.some(runtimeRoot => (
        sourcePath === runtimeRoot || sourcePath.startsWith(`${runtimeRoot}/`)
      ))) {
        diagnostics.push(diagnostic(
          "ARCH_METADATA_RUNTIME_ROOT",
          "architecture.json",
          `${layer.id} source ${sourcePath} is outside the packaged runtime roots`,
        ));
      }
    }
  }
  const approvedRegistrationFiles = new Set([
    "commands/registrar.js",
    ...normalized.registrars.map(registrar => registrar.file),
  ]);
  for (const file of normalized.commandRegistrationFiles) {
    const owner = layerForFile(normalized, file);
    if (
      !approvedRegistrationFiles.has(file)
      || !owner
      || !owner.id.startsWith("command-")
    ) {
      diagnostics.push(diagnostic(
        "ARCH_METADATA_REGISTRATION_ALLOWLIST",
        "architecture.json",
        `Command-registration allowlist entry is not approved plumbing: ${file}`,
      ));
    }
  }
  for (const file of approvedRegistrationFiles) {
    if (!normalized.commandRegistrationFiles.includes(file)) {
      diagnostics.push(diagnostic(
        "ARCH_METADATA_REGISTRATION_ALLOWLIST",
        "architecture.json",
        `Command-registration plumbing lacks an exact allowlist entry: ${file}`,
      ));
    }
  }
  for (const exemption of normalized.cycleExemptions) {
    for (const file of exemption) {
      const owner = layerForFile(normalized, file);
      if (!owner || owner.id !== "legacy-service") {
        diagnostics.push(diagnostic(
          "ARCH_METADATA_CYCLE",
          "architecture.json",
          `Cycle exemption is outside the protected legacy service layer: ${file}`,
        ));
      }
    }
  }
  return { diagnostics, metadata: normalized };
}

function readStableFile(absolutePath, relativePath, maxBytes) {
  const descriptor = fs.openSync(
    absolutePath,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.size > BigInt(maxBytes)) {
      throw new Error(`Bounded regular file required: ${relativePath}`);
    }
    const expectedSize = Number(before.size);
    const buffer = Buffer.alloc(expectedSize + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const bytesRead = fs.readSync(
        descriptor,
        buffer,
        offset,
        buffer.length - offset,
        offset,
      );
      if (!bytesRead) {
        break;
      }
      offset += bytesRead;
    }
    if (offset !== expectedSize) {
      throw new Error(`File changed size while being read: ${relativePath}`);
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    for (const field of ["dev", "ino", "size", "mtimeNs", "ctimeNs"]) {
      if (before[field] !== after[field]) {
        throw new Error(`File changed while being read: ${relativePath}`);
      }
    }
    return buffer.subarray(0, expectedSize).toString("utf8");
  } finally {
    fs.closeSync(descriptor);
  }
}

function validateRuntimeInventory(metadata, manifest) {
  const diagnostics = [];
  const main = typeof manifest?.main === "string" && manifest.main.startsWith("./")
    ? manifest.main.slice(2)
    : manifest?.main;
  if (main !== metadata.compositionFile) {
    diagnostics.push(diagnostic(
      "ARCH_RUNTIME_ENTRYPOINT",
      "package.json",
      "The package main entrypoint must exactly match the governed composition file",
    ));
  }
  const expected = [
    metadata.compositionFile,
    ...metadata.runtimeRoots.map(runtimeRoot => `${runtimeRoot}/**/*.js`),
    ...metadata.nonJavaScriptPackageFiles,
  ].sort();
  const actual = Array.isArray(manifest?.files) ? [...manifest.files].sort() : [];
  if (
    new Set(actual).size !== actual.length
    || actual.length !== expected.length
    || actual.some((entry, index) => entry !== expected[index])
  ) {
    diagnostics.push(diagnostic(
      "ARCH_RUNTIME_INVENTORY",
      "package.json",
      "package.json files must exactly match the governed runtime and non-JavaScript inventory",
    ));
  }
  return diagnostics;
}

function symlinkAncestor(root, relativePath) {
  let current = root;
  const traversed = [];
  for (const segment of relativePath.split("/")) {
    traversed.push(segment);
    current = path.join(current, segment);
    const stats = fs.lstatSync(current, { throwIfNoEntry: false });
    if (!stats) return null;
    if (stats.isSymbolicLink()) return traversed.join("/");
  }
  return null;
}

function collectArchitectureFiles(root, metadata) {
  const diagnostics = [];
  const files = new Map();
  const seenFolded = new Map();
  const visitedPaths = new Set();
  let totalBytes = 0;
  let discoveredEntries = 0;
  let traversalAborted = false;
  const ignored = new Set(metadata.ignoredSegments);
  const candidates = new Set([metadata.compositionFile]);
  for (const runtimeRoot of metadata.runtimeRoots) {
    candidates.add(runtimeRoot);
  }
  for (const layer of metadata.layers) {
    for (const entry of [...layer.roots, ...layer.files]) {
      candidates.add(entry);
    }
  }

  function addDiagnostic(entry) {
    if (traversalAborted && diagnostics.length >= metadata.limits.maxDiagnostics) {
      return false;
    }
    if (diagnostics.length >= metadata.limits.maxDiagnostics - 1) {
      diagnostics.push(diagnostic(
        "ARCH_DIAGNOSTIC_LIMIT",
        entry.path || "architecture",
        `Scan stopped after ${metadata.limits.maxDiagnostics} diagnostics`,
      ));
      traversalAborted = true;
      return false;
    }
    diagnostics.push(entry);
    return true;
  }

  function collect(relativePath, depth) {
    if (traversalAborted) return;
    const normalizationDiagnostics = [];
    const normalizedPath = normalizeMetadataPath(root, relativePath, normalizationDiagnostics);
    for (const entry of normalizationDiagnostics) {
      addDiagnostic(entry);
    }
    if (!normalizedPath || visitedPaths.has(normalizedPath)) {
      return;
    }
    visitedPaths.add(normalizedPath);
    if (depth > metadata.limits.maxDepth) {
      addDiagnostic(diagnostic("ARCH_SCAN_DEPTH", normalizedPath, `Traversal exceeds ${metadata.limits.maxDepth} levels`));
      return;
    }
    const ancestor = symlinkAncestor(root, normalizedPath);
    if (ancestor) {
      addDiagnostic(diagnostic("ARCH_SCAN_SYMLINK", ancestor, `Architecture path uses a symbolic-link component from ${normalizedPath}`));
      return;
    }
    const absolutePath = path.join(root, ...normalizedPath.split("/"));
    let stats;
    try {
      stats = fs.lstatSync(absolutePath);
    } catch (error) {
      addDiagnostic(diagnostic("ARCH_SCAN_MISSING", normalizedPath, `Declared architecture path is missing: ${error.code || "unknown"}`));
      return;
    }
    if (stats.isSymbolicLink()) {
      addDiagnostic(diagnostic("ARCH_SCAN_SYMLINK", normalizedPath, "Architecture roots may not contain symbolic links"));
      return;
    }
    if (stats.isDirectory()) {
      const entries = [];
      const directory = fs.opendirSync(absolutePath);
      try {
        let entry;
        while ((entry = directory.readSync())) {
          discoveredEntries += 1;
          if (discoveredEntries > metadata.limits.maxEntries) {
            addDiagnostic(diagnostic(
              "ARCH_SCAN_ENTRIES",
              normalizedPath,
              `Traversal exceeds ${metadata.limits.maxEntries} directory entries`,
            ));
            traversalAborted = true;
            break;
          }
          entries.push(entry);
        }
      } finally {
        directory.closeSync();
      }
      entries.sort((left, right) => left.name.localeCompare(right.name));
      for (const entry of entries) {
        if (traversalAborted) break;
        if (ignored.has(entry.name)) {
          if (metadata.runtimeRoots.some(runtimeRoot => (
            normalizedPath === runtimeRoot || normalizedPath.startsWith(`${runtimeRoot}/`)
          ))) {
            addDiagnostic(diagnostic(
              "ARCH_RUNTIME_IGNORED_SEGMENT",
              `${normalizedPath}/${entry.name}`,
              "Ignored segments may not exist beneath a packaged JavaScript runtime root",
            ));
          }
          continue;
        }
        collect(`${normalizedPath}/${entry.name}`, depth + 1);
      }
      return;
    }
    if (!stats.isFile()) {
      addDiagnostic(diagnostic("ARCH_SCAN_TYPE", normalizedPath, "Architecture input is not a regular file"));
      return;
    }
    if (!normalizedPath.endsWith(".js")) {
      addDiagnostic(diagnostic("ARCH_SCAN_TYPE", normalizedPath, "Declared architecture files must be JavaScript"));
      return;
    }
    if (stats.size > metadata.limits.maxFileBytes) {
      addDiagnostic(diagnostic("ARCH_SCAN_FILE_BYTES", normalizedPath, `File exceeds ${metadata.limits.maxFileBytes} bytes`));
      return;
    }
    totalBytes += stats.size;
    if (totalBytes > metadata.limits.maxTotalBytes) {
      addDiagnostic(diagnostic("ARCH_SCAN_TOTAL_BYTES", normalizedPath, `Scan exceeds ${metadata.limits.maxTotalBytes} total bytes`));
      traversalAborted = true;
      return;
    }
    if (files.size + 1 > metadata.limits.maxFiles) {
      addDiagnostic(diagnostic("ARCH_SCAN_FILES", normalizedPath, `Scan exceeds ${metadata.limits.maxFiles} files`));
      traversalAborted = true;
      return;
    }
    const folded = normalizedPath.toLowerCase();
    if (seenFolded.has(folded) && seenFolded.get(folded) !== normalizedPath) {
      addDiagnostic(diagnostic("ARCH_SCAN_CASE_COLLISION", normalizedPath, `Path collides under case folding with ${seenFolded.get(folded)}`));
      return;
    }
    seenFolded.set(folded, normalizedPath);
    try {
      files.set(
        normalizedPath,
        readStableFile(absolutePath, normalizedPath, metadata.limits.maxFileBytes),
      );
    } catch (error) {
      addDiagnostic(diagnostic("ARCH_SCAN_RACE", normalizedPath, error.message));
    }
  }

  for (const candidate of [...candidates].sort()) {
    if (candidate) {
      collect(candidate, 0);
    }
  }
  return { diagnostics, files };
}

function layerForFile(metadata, relativePath) {
  for (const layer of metadata.layers) {
    if (layer.files.includes(relativePath)) {
      return layer;
    }
  }
  let owner = null;
  for (const layer of metadata.layers) {
    if (layer.excludeFiles.includes(relativePath)) {
      continue;
    }
    for (const rootPath of layer.roots) {
      if (relativePath === rootPath || relativePath.startsWith(`${rootPath}/`)) {
        if (!owner || rootPath.length > owner.rootPath.length) {
          owner = { layer, rootPath };
        }
      }
    }
  }
  return owner?.layer || null;
}

function staticString(node) {
  if (node?.type === "Literal" && typeof node.value === "string") {
    return node.value;
  }
  if (node?.type === "TemplateLiteral" && node.expressions.length === 0) {
    return node.quasis[0]?.value?.cooked ?? null;
  }
  if (node?.type === "BinaryExpression" && node.operator === "+") {
    const left = staticString(node.left);
    const right = staticString(node.right);
    return left !== null && right !== null ? left + right : null;
  }
  if (
    node?.type === "CallExpression"
    && node.arguments.length <= 1
    && node.callee?.type === "MemberExpression"
    && propertyName(node.callee) === "join"
    && node.callee.object?.type === "ArrayExpression"
    && node.callee.object.elements.length <= 16
  ) {
    const separator = node.arguments.length === 0 ? "," : staticString(node.arguments[0]);
    const values = node.callee.object.elements.map(staticString);
    return separator !== null && values.every(value => value !== null)
      ? values.join(separator)
      : null;
  }
  return null;
}

function propertyName(node) {
  if (!node) {
    return null;
  }
  if (!node.computed && (node.property?.type === "Identifier" || node.key?.type === "Identifier")) {
    return node.property?.name || node.key?.name || null;
  }
  const property = node.property || node.key;
  return staticString(property);
}

function objectKeys(node) {
  return new Set((node.properties || []).map((property) => propertyName(property)).filter(Boolean));
}

function isJsonStringify(node) {
  return node?.callee?.type === "MemberExpression"
    && node.callee.object?.type === "Identifier"
    && node.callee.object.name === "JSON"
    && propertyName(node.callee) === "stringify";
}

function astContainsName(rootNode, expectedName) {
  const pending = [rootNode];
  const seen = new Set();
  let visited = 0;
  while (pending.length > 0 && visited < 512) {
    const node = pending.pop();
    if (!node || typeof node !== "object" || seen.has(node)) {
      continue;
    }
    seen.add(node);
    visited += 1;
    if (node.type === "Identifier" && node.name === expectedName) {
      return true;
    }
    if (node.type === "Literal" && node.value === expectedName) {
      return true;
    }
    for (const [key, value] of Object.entries(node)) {
      if (["parent", "loc", "range", "tokens", "comments"].includes(key)) {
        continue;
      }
      if (Array.isArray(value)) {
        pending.push(...value);
      } else if (value && typeof value === "object") {
        pending.push(value);
      }
    }
  }
  return false;
}

function astIdentifierNodes(rootNode) {
  const identifiers = new Set();
  const pending = [rootNode];
  const seen = new Set();
  let visited = 0;
  while (pending.length > 0 && visited < 512) {
    const node = pending.pop();
    if (!node || typeof node !== "object" || seen.has(node)) continue;
    seen.add(node);
    visited += 1;
    if (node.type === "Identifier") identifiers.add(node);
    for (const [key, value] of Object.entries(node)) {
      if (["parent", "loc", "range", "tokens", "comments"].includes(key)) continue;
      if (Array.isArray(value)) pending.push(...value);
      else if (value && typeof value === "object") pending.push(value);
    }
  }
  return identifiers;
}

function patternIdentifierNodes(node) {
  if (!node) return [];
  if (node.type === "Identifier") return [node];
  if (node.type === "RestElement") return patternIdentifierNodes(node.argument);
  if (node.type === "AssignmentPattern") return patternIdentifierNodes(node.left);
  if (node.type === "ArrayPattern") return node.elements.flatMap(patternIdentifierNodes);
  if (node.type === "ObjectPattern") return node.properties.flatMap(property => (
    property.type === "RestElement"
      ? patternIdentifierNodes(property.argument)
      : patternIdentifierNodes(property.value)
  ));
  if (node.type === "MemberExpression" && node.object?.type === "Identifier") {
    return [node.object];
  }
  return [];
}

function taintSourceNodes(node) {
  if (!node) return [];
  if (node.type === "Identifier") return [node];
  if (["Literal", "FunctionExpression", "ArrowFunctionExpression"].includes(node.type)) {
    return [];
  }
  if (node.type === "NewExpression") return node.arguments.flatMap(taintSourceNodes);
  if (node.type === "MemberExpression") {
    return [
      ...taintSourceNodes(node.object),
      ...(node.computed ? taintSourceNodes(node.property) : []),
    ];
  }
  if (node.type === "CallExpression") {
    const receiver = node.callee?.type === "MemberExpression" ? node.callee.object : null;
    const receiverSources = receiver?.type === "Identifier"
      ? [receiver]
      : receiver?.type === "NewExpression" || receiver?.computed
        ? taintSourceNodes(receiver)
        : [];
    return [
      ...receiverSources,
      ...node.arguments.flatMap(taintSourceNodes),
    ];
  }
  if (node.type === "Property") return taintSourceNodes(node.value);
  const identifiers = [];
  for (const [key, value] of Object.entries(node)) {
    if (["parent", "loc", "range", "tokens", "comments", "callee"].includes(key)) continue;
    if (Array.isArray(value)) identifiers.push(...value.flatMap(taintSourceNodes));
    else if (value && typeof value === "object") identifiers.push(...taintSourceNodes(value));
  }
  return identifiers;
}

function collectAstFacts(source, relativePath, maxFacts = 512) {
  const facts = {
    alternateRegistrationNodes: [],
    commandApiNodes: [],
    computedMemberNodes: [],
    deferredCommandNodes: [],
    dynamicCodeNodes: [],
    imports: [],
    registerCommandIdentifiers: [],
    registerCommandNodes: [],
    registerInventoryCalls: [],
    registrationFactoryCalls: [],
    registrationFactoryDefinitions: [],
    registrationFactoryExports: [],
    registrationFactoryIdentifiers: [],
    registrationFactoryImports: [],
    reflectiveAccessNodes: [],
    sharedCommandDependencyIdentifiers: [],
    taintCallFlows: [],
    taintFunctionParameters: [],
    taintRelations: [],
    taintSeeds: [],
    violations: [],
    parseMessages: [],
    truncated: false,
  };
  let factCount = 0;
  let taintFactCount = 0;
  const record = (bucket, value) => {
    if (factCount >= maxFacts) {
      facts.truncated = true;
      return;
    }
    factCount += 1;
    bucket.push(value);
  };
  const recordTaint = (bucket, value) => {
    if (taintFactCount >= Math.min(maxFacts * 16, 4096)) {
      facts.truncated = true;
      return;
    }
    taintFactCount += 1;
    bucket.push(value);
  };
  const rule = {
    create() {
      return {
        CallExpression(node) {
          const calleeName = node.callee?.type === "Identifier"
            ? node.callee.name
            : propertyName(node.callee);
          if (calleeName === "createCommandRegistration") {
            record(facts.registrationFactoryCalls, node);
          }
          if (calleeName === "registerCommands") {
            record(facts.registerInventoryCalls, node);
          }
          if (DYNAMIC_CODE_CONSTRUCTORS.has(calleeName)) {
            record(facts.dynamicCodeNodes, node);
          }
          if (["createRequire", "getBuiltinModule"].includes(calleeName)) {
            record(facts.violations, diagnostic(
              "ARCH_DYNAMIC_IMPORT",
              relativePath,
              `Alternate module loader is prohibited in gated runtime sources: ${calleeName}`,
              node,
            ));
          }
          if (
            node.callee?.type === "MemberExpression"
            && node.callee.object?.type === "Identifier"
            && (
              (node.callee.object.name === "Reflect" && ["get", "ownKeys"].includes(propertyName(node.callee)))
              || (
                node.callee.object.name === "Object"
                && [
                  "entries",
                  "getOwnPropertyDescriptor",
                  "getOwnPropertyDescriptors",
                  "keys",
                  "values",
                ].includes(propertyName(node.callee))
              )
            )
          ) {
            record(facts.reflectiveAccessNodes, node);
          }
          if (/^register[A-Za-z0-9_$]*Command$/.test(calleeName || "") && calleeName !== "registerCommand") {
            record(facts.alternateRegistrationNodes, node);
          }
          if (
            node.callee?.type === "MemberExpression"
            && node.callee.object?.type === "Identifier"
            && node.callee.object.name === "Reflect"
            && propertyName(node.callee) === "get"
            && staticString(node.arguments[1]) === "commands"
          ) {
            record(facts.commandApiNodes, node);
          }
          if (
            node.callee?.type === "MemberExpression"
            && node.callee.object?.type === "Identifier"
            && node.callee.object.name === "Reflect"
            && propertyName(node.callee) === "get"
            && node.arguments[0]?.type === "Identifier"
            && node.arguments[0].name === "vscode"
            && staticString(node.arguments[1]) === null
          ) {
            record(facts.commandApiNodes, node);
          }
          const callArgumentNodes = node.arguments.map(taintSourceNodes);
          if (node.callee?.type === "Identifier") {
            recordTaint(facts.taintCallFlows, { callee: node.callee, arguments: callArgumentNodes });
          } else if (
            node.callee?.type === "MemberExpression"
            && node.callee.object?.type === "Identifier"
            && ["add", "push", "set", "splice", "unshift"].includes(propertyName(node.callee))
          ) {
            recordTaint(facts.taintRelations, {
              targets: [node.callee.object],
              sources: callArgumentNodes.flat(),
            });
          }
          if (["queueMicrotask", "setImmediate", "setInterval", "setTimeout"].includes(calleeName)) {
            record(facts.deferredCommandNodes, node);
          }
          if (
            calleeName === "nextTick"
            && node.callee?.type === "MemberExpression"
            && node.callee.object?.type === "Identifier"
            && node.callee.object.name === "process"
          ) {
            record(facts.deferredCommandNodes, node);
          }
          if (
            node.arguments.some(argument => (
              ["ArrowFunctionExpression", "FunctionExpression"].includes(argument?.type)
              && (
                astContainsName(argument, "registerCommand")
                || astContainsName(argument, "registerCommands")
              )
            ))
          ) {
            record(facts.deferredCommandNodes, node);
          }
          if (node.callee?.type === "Identifier" && node.callee.name === "registerCommand") {
            record(facts.registerCommandNodes, node.callee);
          }
          const requireName = node.callee?.type === "Identifier" && node.callee.name === "require"
            ? "require"
            : node.callee?.type === "MemberExpression"
              && node.callee.object?.type === "Identifier"
              && node.callee.object.name === "module"
              && propertyName(node.callee) === "require"
              ? "require"
              : null;
          if (requireName) {
            const argument = node.arguments[0];
            if (node.arguments.length !== 1 || argument?.type !== "Literal" || typeof argument.value !== "string") {
              record(facts.violations, diagnostic("ARCH_DYNAMIC_IMPORT", relativePath, "Dynamic require is prohibited in gated layers", node));
            } else {
              record(facts.imports, { specifier: argument.value, node });
            }
          }
          if (isJsonStringify(node)) {
            const argument = node.arguments[0];
            if (argument?.type === "ArrayExpression") {
              if (["workspace", "repository", "packageIdentifier"].every(
                (name) => astContainsName(argument, name),
              )) {
                record(facts.violations, diagnostic("ARCH_MANUAL_PACKAGE_IDENTITY", relativePath, "Exact package identity must use the canonical helper", node));
              }
            }
          }
        },
        ImportDeclaration(node) {
          record(facts.imports, { specifier: node.source.value, node });
        },
        ImportExpression(node) {
          record(facts.violations, diagnostic("ARCH_DYNAMIC_IMPORT", relativePath, "Dynamic import() is prohibited in gated layers", node));
        },
        NewExpression(node) {
          const calleeName = node.callee?.type === "Identifier" ? node.callee.name : propertyName(node.callee);
          if (DYNAMIC_CODE_CONSTRUCTORS.has(calleeName)) {
            record(facts.dynamicCodeNodes, node);
          }
        },
        AssignmentExpression(node) {
          recordTaint(facts.taintRelations, {
            targets: patternIdentifierNodes(node.left),
            sources: taintSourceNodes(node.right),
          });
        },
        FunctionDeclaration(node) {
          if (node.id?.name === "createCommandRegistration") {
            record(facts.registrationFactoryDefinitions, node);
          }
          if (node.id?.name) {
            recordTaint(facts.taintFunctionParameters, {
              name: node.id,
              parameters: node.params.map(patternIdentifierNodes),
            });
          }
        },
        Identifier(node) {
          if (DYNAMIC_CODE_CONSTRUCTORS.has(node.name)) {
            record(facts.dynamicCodeNodes, node);
          }
          if (node.name === "registerCommand") {
            record(facts.registerCommandIdentifiers, node);
          }
          if (node.name === "sharedCommandDependencies") {
            record(facts.sharedCommandDependencyIdentifiers, node);
          }
          if (node.name === "createCommandRegistration") {
            record(facts.registrationFactoryIdentifiers, node);
          }
          if (/^register[A-Za-z0-9_$]*Command$/.test(node.name) && node.name !== "registerCommand") {
            record(facts.alternateRegistrationNodes, node);
          }
          if (
            node.name === "require"
            && !(node.parent?.type === "CallExpression" && node.parent.callee === node)
            && !(node.parent?.type === "MemberExpression" && node.parent.property === node)
          ) {
            record(facts.violations, diagnostic("ARCH_DYNAMIC_IMPORT", relativePath, "Aliased require is prohibited in gated layers", node));
          }
          if (
            node.name === "module"
            && !(
              node.parent?.type === "MemberExpression"
              && node.parent.object === node
              && propertyName(node.parent) === "exports"
            )
            && !(
              node.parent?.type === "MemberExpression"
              && node.parent.property === node
              && !node.parent.computed
            )
            && !(
              node.parent?.type === "Property"
              && node.parent.key === node
              && !node.parent.computed
              && !node.parent.shorthand
            )
            && !(
              node.parent?.type === "MemberExpression"
              && node.parent.object === node
              && propertyName(node.parent) === "require"
              && node.parent.parent?.type === "CallExpression"
              && node.parent.parent.callee === node.parent
            )
          ) {
            record(facts.violations, diagnostic(
              "ARCH_DYNAMIC_IMPORT",
              relativePath,
              "CommonJS module capability may only be used for exports or a direct literal module.require",
              node,
            ));
          }
          if (LEGACY_PACKAGE_NAMES.has(node.name)) {
            record(facts.violations, diagnostic("ARCH_LEGACY_PACKAGE_ALIAS", relativePath, `Legacy package alias/helper is prohibited: ${node.name}`, node));
          }
        },
        MemberExpression(node) {
          const name = propertyName(node);
          if (name === "constructor") {
            record(facts.dynamicCodeNodes, node);
          }
          if (["createRequire", "getBuiltinModule"].includes(name)) {
            record(facts.violations, diagnostic(
              "ARCH_DYNAMIC_IMPORT",
              relativePath,
              `Alternate module-loader capability is prohibited: ${name}`,
              node,
            ));
          }
          if (
            node.computed
            && name === null
            && !(node.property?.type === "Literal" && typeof node.property.value === "number")
          ) {
            record(facts.computedMemberNodes, node);
          }
          if (name === "commands" && !isReviewedCommandsApiUse(node)) {
            record(facts.commandApiNodes, node);
          }
          if (
            name === "require"
            && node.object?.type === "Identifier"
            && node.object.name === "module"
            && !(node.parent?.type === "CallExpression" && node.parent.callee === node)
          ) {
            record(facts.violations, diagnostic("ARCH_DYNAMIC_IMPORT", relativePath, "Aliased module require is prohibited in gated layers", node));
          }
          if (name === "registerCommand") {
            record(facts.registerCommandNodes, node);
          }
          if (LEGACY_PACKAGE_NAMES.has(name)) {
            record(facts.violations, diagnostic("ARCH_LEGACY_PACKAGE_ALIAS", relativePath, `Legacy package member is prohibited: ${name}`, node));
          }
          if (name === "value" && node.object?.type === "MemberExpression" && propertyName(node.object) === "value") {
            record(facts.violations, diagnostic("ARCH_LEGACY_WRAPPER_DEPTH", relativePath, "Nested .value.value unwrapping belongs in an explicit adapter", node));
          }
        },
        Property(node) {
          const name = propertyName(node);
          if (
            name === "createCommandRegistration"
            && node.parent?.type === "ObjectExpression"
            && node.parent.parent?.type === "AssignmentExpression"
            && node.parent.parent.left?.type === "MemberExpression"
            && node.parent.parent.left.object?.type === "Identifier"
            && node.parent.parent.left.object.name === "module"
            && propertyName(node.parent.parent.left) === "exports"
          ) {
            record(facts.registrationFactoryExports, node);
          }
          if (node.parent?.type === "ObjectPattern" && node.computed && name === null) {
            record(facts.computedMemberNodes, node);
          }
          if (name === "commands" && node.parent?.type === "ObjectPattern") {
            record(facts.commandApiNodes, node);
          }
          if (name === "registerCommand" && node.parent?.type === "ObjectPattern") {
            record(facts.registerCommandNodes, node);
          }
          if (LEGACY_PACKAGE_NAMES.has(name)) {
            record(facts.violations, diagnostic("ARCH_LEGACY_PACKAGE_ALIAS", relativePath, `Legacy package property is prohibited: ${name}`, node));
          }
        },
        Literal(node) {
          if (node.value === "registerCommand") {
            record(facts.registerCommandNodes, node);
          }
          if (typeof node.value === "string" && LEGACY_PACKAGE_NAMES.has(node.value)) {
            record(facts.violations, diagnostic("ARCH_LEGACY_PACKAGE_ALIAS", relativePath, `Legacy package string key is prohibited: ${node.value}`, node));
          }
        },
        BinaryExpression(node) {
          const value = staticString(node);
          if (value === "registerCommand") {
            record(facts.registerCommandNodes, node);
          }
          if (value !== null && LEGACY_PACKAGE_NAMES.has(value)) {
            record(facts.violations, diagnostic("ARCH_LEGACY_PACKAGE_ALIAS", relativePath, `Computed legacy package key is prohibited: ${value}`, node));
          }
        },
        TemplateLiteral(node) {
          if (staticString(node) === "registerCommand") {
            record(facts.registerCommandNodes, node);
          }
        },
        ObjectExpression(node) {
          const keys = objectKeys(node);
          if (["workspace", "repository", "packageIdentifier"].every((name) => keys.has(name))) {
            record(facts.violations, diagnostic("ARCH_MANUAL_PACKAGE_REF", relativePath, "Manual exact package reference must use the canonical helper", node));
          }
        },
        VariableDeclarator(node) {
          const targets = patternIdentifierNodes(node.id);
          if (targets.length > 0 && node.init) {
            recordTaint(facts.taintRelations, {
              targets,
              sources: taintSourceNodes(node.init),
            });
          }
          if (
            targets.length > 0
            && node.init?.type === "CallExpression"
            && node.init.callee?.type === "Identifier"
            && node.init.callee.name === "require"
            && staticString(node.init.arguments[0]) === "vscode"
          ) {
            for (const target of targets) recordTaint(facts.taintSeeds, target);
          }
          if (node.id?.type === "Identifier" && ["ArrowFunctionExpression", "FunctionExpression"].includes(node.init?.type)) {
            recordTaint(facts.taintFunctionParameters, {
              name: node.id,
              parameters: node.init.params.map(patternIdentifierNodes),
            });
          }
          if (
            node.id?.type === "ObjectPattern"
            && node.id.properties.length === 1
            && propertyName(node.id.properties[0]) === "createCommandRegistration"
            && node.id.properties[0].shorthand
            && node.init?.type === "CallExpression"
            && node.init.callee?.type === "Identifier"
            && node.init.callee.name === "require"
            && node.init.arguments.length === 1
            && staticString(node.init.arguments[0]) === "./commands/registrar"
          ) {
            record(facts.registrationFactoryImports, node);
          }
        },
      };
    },
  };
  const linter = new Linter({ configType: "flat" });
  facts.parseMessages = linter.verify(source, [{
    languageOptions: { ecmaVersion: 2022, sourceType: "commonjs" },
    linterOptions: { reportUnusedDisableDirectives: "off" },
    plugins: { architecture: { rules: { collect: rule } } },
    rules: { "architecture/collect": "error" },
  }], { filename: relativePath });

  const bindingByIdentifier = new Map();
  const globalBindingsByName = new Map();
  const scopeManager = linter.getSourceCode()?.scopeManager;
  for (const scope of scopeManager?.scopes || []) {
    for (const variable of scope.variables || []) {
      for (const identifier of variable.identifiers || []) {
        bindingByIdentifier.set(identifier, variable);
      }
      for (const reference of variable.references || []) {
        bindingByIdentifier.set(reference.identifier, variable);
      }
      if (scope.type === "global") {
        if (!globalBindingsByName.has(variable.name)) globalBindingsByName.set(variable.name, new Set());
        globalBindingsByName.get(variable.name).add(variable);
      }
    }
    for (const reference of scope.through || []) {
      if (!bindingByIdentifier.has(reference.identifier)) {
        const globalBinding = `global:${reference.identifier.name}`;
        bindingByIdentifier.set(reference.identifier, globalBinding);
        if (!globalBindingsByName.has(reference.identifier.name)) {
          globalBindingsByName.set(reference.identifier.name, new Set());
        }
        globalBindingsByName.get(reference.identifier.name).add(globalBinding);
      }
    }
  }
  const bindingFor = identifier => (
    bindingByIdentifier.get(identifier) || `unresolved:${identifier?.name || "unknown"}`
  );
  const bindingsFor = identifiers => identifiers.map(bindingFor);
  const rootBindings = (...names) => names.flatMap(name => (
    [...(globalBindingsByName.get(name) || [`global:${name}`])]
  ));
  const functionParameters = new Map(
    facts.taintFunctionParameters.map(entry => [
      bindingFor(entry.name),
      entry.parameters.map(bindingsFor),
    ])
  );
  const taintRelations = facts.taintRelations.map(relation => ({
    targets: bindingsFor(relation.targets),
    sources: bindingsFor(relation.sources),
  }));
  const taintCallFlows = facts.taintCallFlows.map(flow => ({
    callee: bindingFor(flow.callee),
    arguments: flow.arguments.map(bindingsFor),
  }));
  const expandTaint = (seeds, seedsAreBindings = false) => {
    const tainted = new Set(seedsAreBindings ? seeds : bindingsFor(seeds));
    for (let iteration = 0; iteration < 512; iteration += 1) {
      let changed = false;
      for (const relation of taintRelations) {
        if (!relation.sources.some(source => tainted.has(source))) continue;
        for (const target of relation.targets) {
          if (!tainted.has(target)) {
            tainted.add(target);
            changed = true;
          }
        }
      }
      for (const flow of taintCallFlows) {
        const parameters = functionParameters.get(flow.callee) || [];
        for (let index = 0; index < flow.arguments.length; index += 1) {
          if (!flow.arguments[index].some(source => tainted.has(source))) continue;
          for (const target of parameters[index] || []) {
            if (!tainted.has(target)) {
              tainted.add(target);
              changed = true;
            }
          }
        }
      }
      if (!changed) break;
    }
    return tainted;
  };
  const tainted = expandTaint(facts.taintSeeds);
  const dynamicGlobals = expandTaint(rootBindings("global", "globalThis"), true);
  const moduleLoaders = expandTaint(rootBindings("module", "require"), true);
  for (const node of facts.computedMemberNodes) {
    const receiverBindings = bindingsFor([...astIdentifierNodes(node.object)]);
    if (receiverBindings.some(binding => tainted.has(binding))) {
      record(facts.commandApiNodes, node);
    }
    if (receiverBindings.some(binding => dynamicGlobals.has(binding))) {
      record(facts.dynamicCodeNodes, node);
    }
    if (receiverBindings.some(binding => moduleLoaders.has(binding))) {
      record(facts.violations, diagnostic(
        "ARCH_DYNAMIC_IMPORT",
        relativePath,
        "Computed module-loader access is prohibited in gated runtime sources",
        node,
      ));
    }
  }
  for (const node of facts.reflectiveAccessNodes) {
    const targetBindings = bindingsFor([...astIdentifierNodes(node.arguments[0])]);
    if (targetBindings.some(binding => tainted.has(binding))) {
      record(facts.commandApiNodes, node);
    }
    if (targetBindings.some(binding => dynamicGlobals.has(binding))) {
      record(facts.dynamicCodeNodes, node);
    }
  }
  return facts;
}

function isReviewedCommandsApiUse(node) {
  const parent = node.parent;
  if (
    parent?.type === "MemberExpression"
    && parent.object === node
    && propertyName(parent) === "executeCommand"
  ) {
    return true;
  }
  if (parent?.type !== "CallExpression" || !parent.arguments.includes(node)) return false;
  if (parent.callee?.type === "Identifier" && parent.callee.name === "createCommandRegistration") {
    return true;
  }
  return parent.callee?.type === "MemberExpression"
    && propertyName(parent.callee) === "bind"
    && astContainsName(parent.callee.object, "executeCommand");
}

function isVscodeCommandsMember(node) {
  return node?.type === "MemberExpression"
    && !node.computed
    && node.object?.type === "Identifier"
    && node.object.name === "vscode"
    && propertyName(node) === "commands";
}

function validateCompositionRegistrationFlow(metadata, facts, relativePath, addDiagnostic) {
  const factoryCall = facts.registrationFactoryCalls.length === 1
    ? facts.registrationFactoryCalls[0]
    : null;
  const declaration = factoryCall?.parent;
  if (
    !factoryCall
    || facts.registrationFactoryImports.length !== 1
    || declaration?.type !== "VariableDeclarator"
    || declaration.id?.type !== "Identifier"
    || declaration.id.name !== "registerCommand"
    || factoryCall.arguments.length !== 1
    || !isVscodeCommandsMember(factoryCall.arguments[0])
  ) {
    addDiagnostic(diagnostic(
      "ARCH_EXTENSION_REGISTRATION_FLOW",
      relativePath,
      "Composition must construct the command registration capability exactly once in the reviewed binding",
      factoryCall || facts.registrationFactoryCalls[0],
    ));
    return;
  }

  for (const node of facts.registrationFactoryIdentifiers) {
    const property = node.parent;
    const isExactImport = property?.type === "Property"
      && property.parent?.type === "ObjectPattern"
      && property.shorthand
      && property.key?.type === "Identifier"
      && property.key.name === "createCommandRegistration"
      && property.value?.type === "Identifier"
      && property.value.name === "createCommandRegistration"
      && property.parent.parent === facts.registrationFactoryImports[0];
    const isFactoryCall = factoryCall.callee === node;
    if (!isExactImport && !isFactoryCall) {
      addDiagnostic(diagnostic(
        "ARCH_EXTENSION_REGISTRATION_FLOW",
        relativePath,
        "The registration factory must come only from the exact command registrar module",
        node,
      ));
      break;
    }
  }

  for (const node of facts.registerCommandIdentifiers) {
    const isDeclaration = node === declaration.id;
    const property = node.parent;
    const object = property?.parent;
    const isReviewedProperty = property?.type === "Property"
      && property.shorthand
      && property.key?.type === "Identifier"
      && property.key.name === "registerCommand"
      && property.value?.type === "Identifier"
      && property.value.name === "registerCommand"
      && object?.type === "ObjectExpression"
      && object.parent?.type === "VariableDeclarator"
      && object.parent.id?.type === "Identifier"
      && object.parent.id.name === "sharedCommandDependencies";
    if (!isDeclaration && !isReviewedProperty) {
      addDiagnostic(diagnostic(
        "ARCH_EXTENSION_REGISTRATION_FLOW",
        relativePath,
        "The registration capability may only enter the exact shared registrar dependency object",
        node,
      ));
      break;
    }
  }

  const registrarFunctions = new Set(metadata.registrars.map(registrar => registrar.function));
  for (const node of facts.sharedCommandDependencyIdentifiers) {
    const isDeclaration = node.parent?.type === "VariableDeclarator" && node.parent.id === node;
    const spread = node.parent;
    const object = spread?.parent;
    const call = object?.parent;
    const isReviewedRegistrarArgument = spread?.type === "SpreadElement"
      && object?.type === "ObjectExpression"
      && call?.type === "CallExpression"
      && call.arguments[0] === object
      && call.callee?.type === "Identifier"
      && registrarFunctions.has(call.callee.name);
    if (!isDeclaration && !isReviewedRegistrarArgument) {
      addDiagnostic(diagnostic(
        "ARCH_EXTENSION_REGISTRATION_FLOW",
        relativePath,
        "Shared command dependencies may only be passed directly to an exact production registrar",
        node,
      ));
      break;
    }
  }
}

function validateRegistrarStaticInventory(registrar, facts, addDiagnostic) {
  const call = facts.registerInventoryCalls.length === 1
    ? facts.registerInventoryCalls[0]
    : null;
  const entries = call?.arguments[1];
  const ids = [];
  let validShape = Boolean(
    call
    && call.callee?.type === "Identifier"
    && call.callee.name === "registerCommands"
    && call.arguments[0]?.type === "Identifier"
    && call.arguments[0].name === "registerCommand"
    && entries?.type === "ArrayExpression"
  );
  if (validShape) {
    for (const entry of entries.elements) {
      if (
        entry?.type !== "ArrayExpression"
        || entry.elements.length !== 2
        || entry.elements[0]?.type !== "Literal"
        || typeof entry.elements[0].value !== "string"
        || !entry.elements[1]
      ) {
        validShape = false;
        break;
      }
      ids.push(entry.elements[0].value);
    }
  }
  if (
    !validShape
    || ids.length !== registrar.commands.length
    || ids.some((id, index) => id !== registrar.commands[index])
  ) {
    addDiagnostic(diagnostic(
      "ARCH_REGISTRAR_STATIC_INVENTORY",
      registrar.file,
      "Registrar must use one literal ordered registerCommands tuple inventory matching metadata",
      call || facts.registerInventoryCalls[0],
    ));
  }

  for (const node of facts.registerCommandIdentifiers) {
    const property = node.parent;
    const isDestructuredDependency = property?.type === "Property"
      && property.parent?.type === "ObjectPattern"
      && property.shorthand
      && property.key?.type === "Identifier"
      && property.key.name === "registerCommand"
      && property.value?.type === "Identifier"
      && property.value.name === "registerCommand";
    const isInventoryArgument = call?.arguments[0] === node;
    if (!isDestructuredDependency && !isInventoryArgument) {
      addDiagnostic(diagnostic(
        "ARCH_REGISTRAR_STATIC_INVENTORY",
        registrar.file,
        "The injected registerCommand capability may only feed the literal registrar inventory",
        node,
      ));
      break;
    }
  }
  for (const node of facts.registerCommandNodes) {
    const isDestructuredDependency = node.type === "Property"
      && node.parent?.type === "ObjectPattern"
      && node.shorthand
      && node.key?.type === "Identifier"
      && node.key.name === "registerCommand"
      && node.value?.type === "Identifier"
      && node.value.name === "registerCommand";
    if (!isDestructuredDependency) {
      addDiagnostic(diagnostic(
        "ARCH_REGISTRAR_STATIC_INVENTORY",
        registrar.file,
        "Registrar sources may not rediscover or alias the registration capability",
        node,
      ));
      break;
    }
  }
}

function validateRegistrationFactorySource(facts, addDiagnostic) {
  const definition = facts.registrationFactoryDefinitions.length === 1
    ? facts.registrationFactoryDefinitions[0]
    : null;
  const statements = definition?.body?.body || [];
  const guard = statements[0];
  const returned = statements[1];
  const guardTest = guard?.test;
  const typeCheck = guardTest?.right;
  const guardedMember = typeCheck?.left?.argument;
  const thrown = guard?.consequent?.body?.[0];
  const returnCall = returned?.argument;
  const boundMember = returnCall?.callee?.object;
  const exactGuard = guard?.type === "IfStatement"
    && !guard.alternate
    && guardTest?.type === "LogicalExpression"
    && guardTest.operator === "||"
    && guardTest.left?.type === "UnaryExpression"
    && guardTest.left.operator === "!"
    && guardTest.left.argument?.type === "Identifier"
    && guardTest.left.argument.name === "commands"
    && typeCheck?.type === "BinaryExpression"
    && typeCheck.operator === "!=="
    && typeCheck.left?.type === "UnaryExpression"
    && typeCheck.left.operator === "typeof"
    && guardedMember?.type === "MemberExpression"
    && !guardedMember.computed
    && guardedMember.object?.type === "Identifier"
    && guardedMember.object.name === "commands"
    && propertyName(guardedMember) === "registerCommand"
    && typeCheck.right?.type === "Literal"
    && typeCheck.right.value === "function"
    && guard.consequent?.type === "BlockStatement"
    && guard.consequent.body.length === 1
    && thrown?.type === "ThrowStatement"
    && thrown.argument?.type === "NewExpression"
    && thrown.argument.callee?.type === "Identifier"
    && thrown.argument.callee.name === "TypeError"
    && thrown.argument.arguments.length === 1
    && thrown.argument.arguments[0]?.type === "Literal"
    && typeof thrown.argument.arguments[0].value === "string";
  const exactReturn = returned?.type === "ReturnStatement"
    && returnCall?.type === "CallExpression"
    && returnCall.arguments.length === 1
    && returnCall.arguments[0]?.type === "Identifier"
    && returnCall.arguments[0].name === "commands"
    && returnCall.callee?.type === "MemberExpression"
    && !returnCall.callee.computed
    && propertyName(returnCall.callee) === "bind"
    && boundMember?.type === "MemberExpression"
    && !boundMember.computed
    && boundMember.object?.type === "Identifier"
    && boundMember.object.name === "commands"
    && propertyName(boundMember) === "registerCommand";
  const exactDefinition = definition
    && definition.params.length === 1
    && definition.params[0]?.type === "Identifier"
    && definition.params[0].name === "commands"
    && statements.length === 2
    && exactGuard
    && exactReturn;
  const exported = facts.registrationFactoryExports.length === 1
    ? facts.registrationFactoryExports[0]
    : null;
  const exactExport = exported?.shorthand
    && exported.key?.type === "Identifier"
    && exported.key.name === "createCommandRegistration"
    && exported.value?.type === "Identifier"
    && exported.value.name === "createCommandRegistration";
  const identifierUsesExact = facts.registrationFactoryIdentifiers.every(node => (
    node === definition?.id
    || (
      node.parent === exported
      && exported?.key?.type === "Identifier"
      && exported.key.name === "createCommandRegistration"
      && exported.value?.type === "Identifier"
      && exported.value.name === "createCommandRegistration"
    )
  ));
  if (!exactDefinition || !exactExport || !identifierUsesExact) {
    addDiagnostic(diagnostic(
      "ARCH_REGISTRATION_FACTORY_SOURCE",
      "commands/registrar.js",
      "Registration factory must be the exact guarded bind-only capability constructor",
      definition || exported || facts.registrationFactoryIdentifiers[0],
    ));
  }
}

function resolveRelativeImport(root, sourcePath, specifier, addDiagnostic, node) {
  if (specifier.includes("\\")) {
    addDiagnostic(diagnostic("ARCH_IMPORT_PATH", sourcePath, `Relative import must use POSIX separators: ${specifier}`, node));
    return null;
  }
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(sourcePath), specifier));
  if (base === ".." || base.startsWith("../") || path.posix.isAbsolute(base)) {
    addDiagnostic(diagnostic("ARCH_ROOT_ESCAPE", sourcePath, `Relative import escapes the repository: ${specifier}`, node));
    return null;
  }
  const candidates = path.posix.extname(base)
    ? [base]
    : [base, `${base}.js`, `${base}.json`, `${base}/index.js`];
  for (const candidate of candidates) {
    const ancestor = symlinkAncestor(root, candidate);
    if (ancestor) {
      addDiagnostic(diagnostic("ARCH_SCAN_SYMLINK", ancestor, `Imported module uses a symbolic-link component from ${sourcePath}`, node));
      return null;
    }
    const absolutePath = path.join(root, ...candidate.split("/"));
    const stats = fs.lstatSync(absolutePath, { throwIfNoEntry: false });
    if (stats?.isSymbolicLink()) {
      addDiagnostic(diagnostic("ARCH_SCAN_SYMLINK", candidate, `Imported module is a symbolic link from ${sourcePath}`, node));
      return null;
    }
    if (stats?.isFile()) {
      return candidate;
    }
  }
  addDiagnostic(diagnostic("ARCH_IMPORT_MISSING", sourcePath, `Relative import does not resolve: ${specifier}`, node));
  return null;
}

function findCycles(graph, included) {
  const cycles = [];
  const indexByNode = new Map();
  const lowByNode = new Map();
  const stack = [];
  const onStack = new Set();
  let index = 0;
  function visit(node) {
    indexByNode.set(node, index);
    lowByNode.set(node, index);
    index += 1;
    stack.push(node);
    onStack.add(node);
    for (const target of graph.get(node) || []) {
      if (!included.has(target)) {
        continue;
      }
      if (!indexByNode.has(target)) {
        visit(target);
        lowByNode.set(node, Math.min(lowByNode.get(node), lowByNode.get(target)));
      } else if (onStack.has(target)) {
        lowByNode.set(node, Math.min(lowByNode.get(node), indexByNode.get(target)));
      }
    }
    if (lowByNode.get(node) === indexByNode.get(node)) {
      const component = [];
      let current;
      do {
        current = stack.pop();
        onStack.delete(current);
        component.push(current);
      } while (current !== node);
      if (component.length > 1 || (graph.get(node) || new Set()).has(node)) {
        cycles.push(component.sort());
      }
    }
  }
  for (const node of [...included].sort()) {
    if (!indexByNode.has(node)) {
      visit(node);
    }
  }
  return cycles;
}

function analyzeStaticArchitecture(root, metadata, files) {
  const diagnostics = [];
  const graph = new Map();
  let importCount = 0;
  let diagnosticLimitReached = false;
  const addDiagnostic = (entry) => {
    if (diagnosticLimitReached) return false;
    if (diagnostics.length >= metadata.limits.maxDiagnostics - 1) {
      diagnostics.push(diagnostic(
        "ARCH_DIAGNOSTIC_LIMIT",
        entry.path || "architecture",
        `Static analysis stopped after ${metadata.limits.maxDiagnostics} diagnostics`,
      ));
      diagnosticLimitReached = true;
      return false;
    }
    diagnostics.push(entry);
    return true;
  };
  const approvedRegistrationFiles = new Set(metadata.commandRegistrationFiles);
  for (const [relativePath, source] of files) {
    if (diagnosticLimitReached) break;
    const layer = layerForFile(metadata, relativePath);
    const facts = collectAstFacts(source, relativePath, metadata.limits.maxDiagnostics);
    if (facts.truncated) {
      addDiagnostic(diagnostic(
        "ARCH_AST_FACT_LIMIT",
        relativePath,
        `AST fact collection exceeds ${metadata.limits.maxDiagnostics} entries`,
      ));
    }
    for (const message of facts.parseMessages) {
      addDiagnostic({
        code: "ARCH_PARSE",
        path: relativePath,
        message: message.message,
        line: message.line,
        column: message.column,
      });
    }
    const composition = relativePath === metadata.compositionFile;
    const declaredRegistrar = metadata.registrars.find(registrar => registrar.file === relativePath);
    if (composition && facts.registerCommandNodes.length > 0) {
      addDiagnostic(diagnostic(
        "ARCH_EXTENSION_REGISTRATION",
        relativePath,
        "Composition root may not reference registerCommand directly",
        facts.registerCommandNodes[0],
      ));
    }
    if (composition && facts.commandApiNodes.length > 0) {
      addDiagnostic(diagnostic(
        "ARCH_EXTENSION_COMMAND_API",
        relativePath,
        "Composition may use vscode.commands only for executeCommand or exact registrar construction",
        facts.commandApiNodes[0],
      ));
    }
    if (composition && facts.computedMemberNodes.length > 0) {
      addDiagnostic(diagnostic(
        "ARCH_EXTENSION_COMPUTED_ACCESS",
        relativePath,
        "Computed member access is prohibited in the composition root",
        facts.computedMemberNodes[0],
      ));
    }
    if (composition) {
      validateCompositionRegistrationFlow(metadata, facts, relativePath, addDiagnostic);
    }
    if (declaredRegistrar) {
      validateRegistrarStaticInventory(declaredRegistrar, facts, addDiagnostic);
    }
    if (relativePath === "commands/registrar.js") {
      validateRegistrationFactorySource(facts, addDiagnostic);
    }
    if (
      !composition
      && relativePath !== "commands/registrar.js"
      && facts.registrationFactoryIdentifiers.length > 0
    ) {
      addDiagnostic(diagnostic(
        "ARCH_REGISTRATION_FACTORY_OWNERSHIP",
        relativePath,
        "Only the exact registrar module may define the composition registration factory",
        facts.registrationFactoryIdentifiers[0],
      ));
    }
    if (facts.dynamicCodeNodes.length > 0) {
      addDiagnostic(diagnostic(
        "ARCH_DYNAMIC_CODE",
        relativePath,
        "Runtime architecture sources may not evaluate generated code",
        facts.dynamicCodeNodes[0],
      ));
    }
    if (facts.alternateRegistrationNodes.length > 0) {
      addDiagnostic(diagnostic(
        "ARCH_COMMAND_REGISTRATION_API",
        relativePath,
        "Alternate command-registration APIs are prohibited; use the exact registrar inventory",
        facts.alternateRegistrationNodes[0],
      ));
    }
    if (
      !composition
      && facts.registerCommandNodes.length > 0
      && !approvedRegistrationFiles.has(relativePath)
    ) {
      addDiagnostic(diagnostic(
        "ARCH_REGISTRATION_OWNERSHIP",
        relativePath,
        "Only approved registrar plumbing may reference registerCommand",
        facts.registerCommandNodes[0],
      ));
    }
    if (
      !composition
      && facts.commandApiNodes.length > 0
    ) {
      addDiagnostic(diagnostic(
        "ARCH_COMMAND_API_OWNERSHIP",
        relativePath,
        "Runtime sources may execute commands but may not retain the command registry",
        facts.commandApiNodes[0],
      ));
    }
    const commandSource = relativePath.startsWith("commands/");
    const runtimeSource = metadata.runtimeRoots.some(runtimeRoot => (
      relativePath.startsWith(`${runtimeRoot}/`)
    ));
    if (runtimeSource && !layer) {
      addDiagnostic(diagnostic(
        "ARCH_UNCLASSIFIED_RUNTIME",
        relativePath,
        "Every packaged runtime JavaScript source must have a reviewed layer owner",
      ));
    }
    if (commandSource && !layer) {
      addDiagnostic(diagnostic(
        "ARCH_UNCLASSIFIED_COMMAND",
        relativePath,
        "Every command source must have an exact reviewed layer owner",
      ));
    }
    if (commandSource && facts.deferredCommandNodes.length > 0) {
      addDiagnostic(diagnostic(
        "ARCH_DEFERRED_COMMAND_REGISTRATION",
        relativePath,
        "Command registrar modules may not schedule deferred registration work",
        facts.deferredCommandNodes[0],
      ));
    }
    if (commandSource && facts.reflectiveAccessNodes.length > 0) {
      addDiagnostic(diagnostic(
        "ARCH_REFLECTIVE_COMMAND_ACCESS",
        relativePath,
        "Command modules may not enumerate or reflectively retrieve injected capabilities",
        facts.reflectiveAccessNodes[0],
      ));
    }
    const packageGate = commandSource || (layer && (
      layer.id.startsWith("domain-") || layer.id.startsWith("command-")
    ));
    const adapterExempt = metadata.adapterFiles.includes(relativePath);
    const factoryExempt = metadata.canonicalFactoryFiles.includes(relativePath);
    if (packageGate && !adapterExempt) {
      if (
        facts.computedMemberNodes.length > 0
        && relativePath !== "commands/registrar.js"
      ) {
        addDiagnostic(diagnostic(
          "ARCH_COMPUTED_PACKAGE_ACCESS",
          relativePath,
          "Dynamic property access is prohibited outside explicit package adapters",
          facts.computedMemberNodes[0],
        ));
      }
      for (const violation of facts.violations) {
        if (factoryExempt && ["ARCH_MANUAL_PACKAGE_REF", "ARCH_MANUAL_PACKAGE_IDENTITY"].includes(violation.code)) {
          continue;
        }
        addDiagnostic(violation);
      }
    } else if (layer) {
      for (const violation of facts.violations) {
        if (violation.code === "ARCH_DYNAMIC_IMPORT") addDiagnostic(violation);
      }
    } else if (composition) {
      for (const violation of facts.violations) {
        if (violation.code === "ARCH_DYNAMIC_IMPORT") addDiagnostic(violation);
      }
    }
    const targets = new Set();
    graph.set(relativePath, targets);
    for (const imported of facts.imports) {
      importCount += 1;
      if (importCount > metadata.limits.maxImports) {
        addDiagnostic(diagnostic("ARCH_SCAN_IMPORTS", relativePath, `Scan exceeds ${metadata.limits.maxImports} imports`, imported.node));
        diagnosticLimitReached = true;
        break;
      }
      if (!layer) {
        if (composition && imported.specifier.startsWith(".")) {
          const targetPath = resolveRelativeImport(
            root,
            relativePath,
            imported.specifier,
            addDiagnostic,
            imported.node,
          );
          const allowedCommandFiles = new Set([
            "commands/registrar.js",
            ...metadata.registrars.map((registrar) => registrar.file),
          ]);
          if (
            targetPath?.startsWith("commands/")
            && !allowedCommandFiles.has(targetPath)
          ) {
            addDiagnostic(diagnostic(
              "ARCH_COMPOSITION_EDGE",
              relativePath,
              `Composition root may import command registrars, not command implementation helpers (${targetPath})`,
              imported.node,
            ));
          }
          if (targetPath && (!files.has(targetPath) || !layerForFile(metadata, targetPath))) {
            addDiagnostic(diagnostic(
              "ARCH_COMPOSITION_EDGE",
              relativePath,
              `Composition may import only classified, scanned runtime JavaScript (${targetPath})`,
              imported.node,
            ));
          }
        }
        continue;
      }
      if (!imported.specifier.startsWith(".")) {
        if (!layer.allowedExternals.includes(imported.specifier)) {
          addDiagnostic(diagnostic("ARCH_EXTERNAL_IMPORT", relativePath, `Layer ${layer.id} may not import ${imported.specifier}`, imported.node));
        }
        continue;
      }
      const targetPath = resolveRelativeImport(root, relativePath, imported.specifier, addDiagnostic, imported.node);
      if (!targetPath) {
        continue;
      }
      targets.add(targetPath);
      const targetLayer = layerForFile(metadata, targetPath);
      if (targetLayer && !files.has(targetPath)) {
        addDiagnostic(diagnostic(
          "ARCH_UNSCANNED_IMPORT",
          relativePath,
          `Layer ${layer.id} imports a classified module outside the bounded scan (${targetPath})`,
          imported.node,
        ));
        continue;
      }
      if (!targetLayer) {
        if (!layer.allowedResources.includes(targetPath)) {
          addDiagnostic(diagnostic("ARCH_UNCLASSIFIED_IMPORT", relativePath, `Layer ${layer.id} imports unapproved local module ${targetPath}`, imported.node));
        }
      } else if (!layer.allowedLayers.includes(targetLayer.id)) {
        addDiagnostic(diagnostic("ARCH_LAYER_EDGE", relativePath, `Layer ${layer.id} may not import layer ${targetLayer.id} (${targetPath})`, imported.node));
      }
    }
  }
  const cycleFiles = new Set([...files.keys()].filter(file => layerForFile(metadata, file)));
  const exemptCycles = new Set(metadata.cycleExemptions.map(exemption => JSON.stringify(exemption)));
  for (const cycle of findCycles(graph, cycleFiles)) {
    if (exemptCycles.has(JSON.stringify(cycle))) continue;
    addDiagnostic(diagnostic("ARCH_DEPENDENCY_CYCLE", cycle[0], `New gated dependency cycle: ${cycle.join(" -> ")}`));
  }
  return { diagnostics, graph, importCount };
}

function createDependencyRecorder(onRegister, onDispose, registrationFactory = null) {
  const registerCommand = (command, handler) => {
    let disposed = false;
    const registration = {
      dispose() {
        if (disposed) return;
        disposed = true;
        onDispose(command);
      },
      get disposed() { return disposed; },
    };
    onRegister(command, handler, registration);
    return registration;
  };
  const inertChain = Object.freeze({
    catch() { return inertChain; },
    finally() { return inertChain; },
    then() { return inertChain; },
  });
  let callable;
  const commands = new Proxy({}, {
    get(target, property) {
      if (property === "registerCommand") {
        return registerCommand;
      }
      return callable;
    },
  });
  callable = new Proxy(function noOp() {}, {
    apply() {
      return inertChain;
    },
    get(target, property) {
      if (property === "then") {
        return undefined;
      }
      if (property === "registerCommand") {
        return registerCommand;
      }
      if (property === "commands") {
        return commands;
      }
      if (property === Symbol.toPrimitive) {
        return () => "";
      }
      return callable;
    },
  });
  const registrationCapability = typeof registrationFactory === "function"
    ? registrationFactory(commands)
    : registerCommand;
  if (typeof registrationCapability !== "function") {
    throw new TypeError("The reviewed registration factory did not return a capability");
  }
  return new Proxy({}, {
    get(target, property) {
      if (property === "registerCommand") {
        return registrationCapability;
      }
      if (property === "commands") {
        return commands;
      }
      if (property === "vscode") {
        return new Proxy(callable, { get(inner, name) { return name === "commands" ? commands : callable; } });
      }
      return callable;
    },
  });
}

function analyzeRegistrationFactory(root) {
  const diagnostics = [];
  const relativePath = "commands/registrar.js";
  const absolutePath = path.join(root, "commands", "registrar.js");
  let factory;
  try {
    const resolved = require.resolve(absolutePath);
    delete require.cache[resolved];
    factory = require(resolved)?.createCommandRegistration;
  } catch (error) {
    diagnostics.push(diagnostic("ARCH_REGISTRATION_FACTORY", relativePath, `Could not load registration factory: ${error.message}`));
    return diagnostics;
  }
  if (typeof factory !== "function") {
    diagnostics.push(diagnostic("ARCH_REGISTRATION_FACTORY", relativePath, "Missing createCommandRegistration factory"));
    return diagnostics;
  }
  const registrations = [];
  const registry = Object.freeze({
    registerCommand(command, handler) {
      let disposed = false;
      const registration = Object.freeze({
        dispose() { disposed = true; },
        get disposed() { return disposed; },
      });
      registrations.push({ command, handler, registration });
      return registration;
    },
  });
  let capability;
  try {
    capability = factory(registry);
  } catch (error) {
    diagnostics.push(diagnostic("ARCH_REGISTRATION_FACTORY", relativePath, `Registration factory threw: ${error.message}`));
    return diagnostics;
  }
  if (registrations.length !== 0 || typeof capability !== "function") {
    diagnostics.push(diagnostic(
      "ARCH_REGISTRATION_FACTORY",
      relativePath,
      "Factory construction must be side-effect free and return one registration capability",
    ));
    return diagnostics;
  }
  const probeHandler = () => undefined;
  let returned;
  try {
    returned = capability("cloudsmith-vsc.architectureProbe", probeHandler);
  } catch (error) {
    diagnostics.push(diagnostic("ARCH_REGISTRATION_FACTORY", relativePath, `Registration capability threw: ${error.message}`));
    return diagnostics;
  }
  const observed = registrations[0];
  if (
    registrations.length !== 1
    || observed.command !== "cloudsmith-vsc.architectureProbe"
    || observed.handler !== probeHandler
    || returned !== observed.registration
  ) {
    diagnostics.push(diagnostic(
      "ARCH_REGISTRATION_FACTORY",
      relativePath,
      "Registration capability must forward exactly one command, handler, and disposable",
    ));
    return diagnostics;
  }
  returned.dispose();
  if (!observed.registration.disposed) {
    diagnostics.push(diagnostic("ARCH_REGISTRATION_FACTORY", relativePath, "Registration capability did not forward disposal"));
  }
  return diagnostics;
}

function analyzeExecutableCommands(root, metadata, manifest) {
  const diagnostics = analyzeRegistrationFactory(root);
  const observed = [];
  let registrationFactory = null;
  try {
    const registrarModulePath = require.resolve(path.join(root, "commands", "registrar.js"));
    delete require.cache[registrarModulePath];
    registrationFactory = require(registrarModulePath)?.createCommandRegistration;
  } catch (error) {
    diagnostics.push(diagnostic("ARCH_REGISTRATION_FACTORY", "commands/registrar.js", `Could not reload registration factory: ${error.message}`));
  }
  for (const registrar of metadata.registrars) {
    const absolutePath = path.join(root, ...registrar.file.split("/"));
    let moduleExports;
    try {
      const resolved = require.resolve(absolutePath);
      delete require.cache[resolved];
      moduleExports = require(resolved);
    } catch (error) {
      diagnostics.push(diagnostic("ARCH_REGISTRAR_LOAD", registrar.file, `Could not load registrar: ${error.message}`));
      continue;
    }
    const register = moduleExports?.[registrar.function];
    if (typeof register !== "function") {
      diagnostics.push(diagnostic("ARCH_REGISTRAR_EXPORT", registrar.file, `Missing exported function ${registrar.function}`));
      continue;
    }
    const owned = [];
    const acquired = [];
    const disposed = [];
    let acceptingRegistrations = true;
    let dependencies;
    try {
      dependencies = createDependencyRecorder((command, handler, registration) => {
        if (!acceptingRegistrations) {
          throw new Error(`Registrar ${registrar.function} attempted a deferred registration`);
        }
        owned.push(command);
        acquired.push(registration);
        observed.push({ command, registrar: registrar.function, file: registrar.file });
        if (typeof command !== "string" || typeof handler !== "function") {
          diagnostics.push(diagnostic("ARCH_REGISTRATION_SHAPE", registrar.file, "registerCommand requires a string id and callback"));
        }
      }, command => disposed.push(command), registrationFactory);
    } catch (error) {
      acceptingRegistrations = false;
      diagnostics.push(diagnostic("ARCH_REGISTRATION_FACTORY", registrar.file, `Could not construct registrar dependencies: ${error.message}`));
      continue;
    }
    let disposable;
    try {
      disposable = register(dependencies);
    } catch (error) {
      acceptingRegistrations = false;
      diagnostics.push(diagnostic("ARCH_REGISTRAR_EXECUTION", registrar.file, `Registrar threw during executable inventory: ${error.message}`));
      continue;
    }
    acceptingRegistrations = false;
    if (disposable && typeof disposable.then === "function") {
      diagnostics.push(diagnostic("ARCH_REGISTRAR_ASYNC", registrar.file, "Registrar must register synchronously"));
    } else if (!disposable || typeof disposable.dispose !== "function") {
      diagnostics.push(diagnostic("ARCH_REGISTRAR_DISPOSABLE", registrar.file, "Registrar must return one aggregate disposable"));
    } else {
      try {
        disposable.dispose();
      } catch (error) {
        diagnostics.push(diagnostic("ARCH_REGISTRAR_DISPOSAL", registrar.file, `Aggregate disposable threw during inventory: ${error.message}`));
      }
      if (acquired.some(registration => !registration.disposed)) {
        diagnostics.push(diagnostic(
          "ARCH_REGISTRAR_OWNERSHIP_DISPOSAL",
          registrar.file,
          "Aggregate disposal did not release every executable command registration",
        ));
      } else if (disposed.some((command, index) => command !== [...owned].reverse()[index])) {
        diagnostics.push(diagnostic(
          "ARCH_REGISTRAR_DISPOSAL_ORDER",
          registrar.file,
          "Aggregate disposal must release registrations in exact reverse order",
        ));
      }
    }
    const expected = registrar.commands;
    if (owned.length !== expected.length || owned.some((command, index) => command !== expected[index])) {
      diagnostics.push(diagnostic(
        "ARCH_REGISTRAR_OWNERSHIP",
        registrar.file,
        `Observed registrations for ${registrar.function} do not match exact metadata order`,
      ));
    }
  }
  const manifestIds = (manifest.contributes?.commands || []).map((entry) => entry.command);
  const expectedIds = [...manifestIds, ...metadata.internalCommandIds];
  const expectedSet = new Set(expectedIds);
  const metadataIds = metadata.registrars.flatMap((registrar) => registrar.commands);
  const metadataSet = new Set(metadataIds);
  const observedIds = observed.map((entry) => entry.command);
  const observedSet = new Set(observedIds);
  for (const [label, ids] of [["manifest/internal", expectedIds], ["metadata", metadataIds], ["executable", observedIds]]) {
    if (new Set(ids).size !== ids.length) {
      diagnostics.push(diagnostic("ARCH_COMMAND_DUPLICATE", label === "executable" ? observed.find((entry, index) => observedIds.indexOf(entry.command) !== index)?.file || "commands" : "architecture.json", `${label} command inventory contains a duplicate`));
    }
  }
  for (const command of expectedSet) {
    if (!metadataSet.has(command)) {
      diagnostics.push(diagnostic("ARCH_COMMAND_METADATA_MISSING", "architecture.json", `No metadata owner for command ${command}`));
    }
    if (!observedSet.has(command)) {
      diagnostics.push(diagnostic("ARCH_COMMAND_REGISTRATION_MISSING", "commands", `No executable registration for command ${command}`));
    }
  }
  for (const command of metadataSet) {
    if (!expectedSet.has(command)) {
      diagnostics.push(diagnostic("ARCH_COMMAND_UNEXPECTED", "architecture.json", `Metadata owns unexpected command ${command}`));
    }
  }
  for (const entry of observed) {
    if (!expectedSet.has(entry.command)) {
      diagnostics.push(diagnostic("ARCH_COMMAND_UNEXPECTED", entry.file, `Registrar executed unexpected command ${String(entry.command)}`));
    }
  }
  return {
    diagnostics,
    observed: Object.freeze(observed.map(entry => Object.freeze({ ...entry }))),
  };
}

function sortDiagnostics(diagnostics) {
  return diagnostics.sort((left, right) => (
    left.path.localeCompare(right.path)
    || (left.line || 0) - (right.line || 0)
    || left.code.localeCompare(right.code)
    || left.message.localeCompare(right.message)
  ));
}

function loadMetadata(root, metadataPath = "scripts/architecture/architecture.json") {
  const absolutePath = path.join(root, ...metadataPath.split("/"));
  const stats = fs.lstatSync(absolutePath);
  if (!stats.isFile() || stats.isSymbolicLink() || stats.size > 256 * 1024) {
    throw new Error("Architecture metadata must be a bounded regular file");
  }
  return JSON.parse(readStableFile(absolutePath, metadataPath, 256 * 1024));
}

function verifyArchitecture({ root, metadata = null, manifest = null, throwOnError = true } = {}) {
  const repositoryRoot = path.resolve(root || path.join(__dirname, "../.."));
  let rawMetadata = metadata;
  let packageManifest = manifest;
  try {
    rawMetadata ||= loadMetadata(repositoryRoot);
    packageManifest ||= JSON.parse(fs.readFileSync(path.join(repositoryRoot, "package.json"), "utf8"));
  } catch (error) {
    const diagnostics = [diagnostic("ARCH_INPUT", "architecture.json", error.message)];
    if (throwOnError) {
      throw new ArchitectureError(diagnostics);
    }
    return { diagnostics };
  }
  const validation = validateMetadata(repositoryRoot, rawMetadata);
  const diagnostics = [...validation.diagnostics];
  if (validation.metadata) {
    diagnostics.push(...validateRuntimeInventory(validation.metadata, packageManifest));
  }
  if (!validation.metadata || diagnostics.length) {
    const sorted = sortDiagnostics(diagnostics);
    if (throwOnError) {
      throw new ArchitectureError(sorted);
    }
    return { diagnostics: sorted };
  }
  const scan = collectArchitectureFiles(repositoryRoot, validation.metadata);
  diagnostics.push(...scan.diagnostics);
  const staticResult = analyzeStaticArchitecture(repositoryRoot, validation.metadata, scan.files);
  diagnostics.push(...staticResult.diagnostics);
  const executableResult = staticResult.diagnostics.length === 0
    ? analyzeExecutableCommands(repositoryRoot, validation.metadata, packageManifest)
    : { diagnostics: [], observed: Object.freeze([]) };
  diagnostics.push(...executableResult.diagnostics);
  const sorted = sortDiagnostics(diagnostics);
  if (throwOnError && sorted.length) {
    throw new ArchitectureError(sorted);
  }
  return {
    diagnostics: sorted,
    files: [...scan.files.keys()].sort(),
    graph: staticResult.graph,
    observed: executableResult.observed,
  };
}

module.exports = {
  ArchitectureError,
  analyzeExecutableCommands,
  analyzeStaticArchitecture,
  collectArchitectureFiles,
  loadMetadata,
  validateMetadata,
  verifyArchitecture,
};

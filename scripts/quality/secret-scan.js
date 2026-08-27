// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const yauzl = require("yauzl");
const {
  ROOT,
  assertRealRepositoryRoot,
  assertRepositoryRelativePath,
  normalizePath,
  removeOutputFile,
  writeJson,
} = require("./common");

const GITLEAKS_VERSION = "8.30.1";
const REPORT_TEMPLATE = "scripts/quality/gitleaks-report.tmpl";
const CONFIG_PATH = ".gitleaks.toml";
const OUTPUT_ROOT = ".quality/secrets";
const SAFE_REPORT_KEYS = Object.freeze(["commit", "endLine", "file", "ruleId", "startLine"]);
const FORBIDDEN_REPORT_FIELDS = /"(?:Secret|Match|Fingerprint|Entropy|Author|Email|Message)"\s*:/u;
const SAFE_ENVIRONMENT_NAMES = Object.freeze([
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "WINDIR",
  "COMSPEC",
  "TMPDIR",
  "TMP",
  "TEMP",
  "USER",
  "LOGNAME",
  "USERNAME",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "NO_COLOR",
]);
const MAX_TRACKED_FILES = 30000;
const MAX_GENERATED_FILES = 10000;
const MAX_VSIX_ENTRIES = 10000;
const MAX_VSIX_ENTRY_BYTES = 50 * 1024 * 1024;
const MAX_VSIX_TOTAL_BYTES = 500 * 1024 * 1024;

function parseArguments(argv) {
  const args = [...argv];
  const mode = args.shift() || "current";
  if (!new Set(["current", "history", "artifacts", "evidence", "all"]).has(mode)) {
    throw new Error("Secret scan mode must be current, history, artifacts, evidence, or all.");
  }
  let includeLocalEvidence = false;
  for (const argument of args) {
    if (argument === "--include-local-evidence") includeLocalEvidence = true;
    else throw new Error(`Unknown secret scan argument: ${argument}`);
  }
  if (includeLocalEvidence && !new Set(["current", "all"]).has(mode)) {
    throw new Error("Local evidence may only be added to current or all scans.");
  }
  return { mode, includeLocalEvidence };
}

function scannerEnvironment(environment = process.env) {
  return Object.fromEntries(
    SAFE_ENVIRONMENT_NAMES
      .filter(name => typeof environment[name] === "string")
      .map(name => [name, environment[name]])
  );
}

function privateScannerEnvironment(environment, scannerHome) {
  const home = fs.realpathSync(scannerHome);
  const stat = fs.lstatSync(home);
  if (stat.isSymbolicLink() || !stat.isDirectory()
    || (process.platform !== "win32" && (stat.mode & 0o077) !== 0)) {
    throw new Error("Secret scanner HOME must be a private real directory.");
  }
  const directories = {
    XDG_CONFIG_HOME: path.join(home, "config"),
    XDG_CACHE_HOME: path.join(home, "cache"),
    XDG_DATA_HOME: path.join(home, "data"),
    XDG_STATE_HOME: path.join(home, "state"),
    TMPDIR: path.join(home, "tmp"),
  };
  for (const directory of Object.values(directories)) {
    fs.mkdirSync(directory, { mode: 0o700 });
    if (process.platform !== "win32") fs.chmodSync(directory, 0o700);
  }
  return Object.freeze({
    ...scannerEnvironment(environment),
    HOME: home,
    USERPROFILE: home,
    ...directories,
    TMP: directories.TMPDIR,
    TEMP: directories.TMPDIR,
    APPDATA: directories.XDG_CONFIG_HOME,
    LOCALAPPDATA: directories.XDG_DATA_HOME,
  });
}

function run(executable, args, options = {}) {
  const result = spawnSync(executable, args, {
    cwd: options.cwd || ROOT,
    encoding: "utf8",
    env: options.env || scannerEnvironment(),
    maxBuffer: 2 * 1024 * 1024,
    stdio: "pipe",
  });
  return result;
}

function assertScannerVersion(options = {}) {
  const execute = options.execute || run;
  const scannerHome = temporaryRoot("cloudsmith-gitleaks-home-");
  try {
    const result = execute("gitleaks", ["version"], {
      cwd: options.root || ROOT,
      env: privateScannerEnvironment(options.environment, scannerHome),
    });
    if (result.error || result.signal || result.status !== 0) {
      throw new Error(`Gitleaks ${GITLEAKS_VERSION} is required; install the pinned scanner before qualification.`);
    }
    if (String(result.stdout || "").trim() !== GITLEAKS_VERSION) {
      throw new Error(`Gitleaks version mismatch; expected ${GITLEAKS_VERSION}.`);
    }
    return GITLEAKS_VERSION;
  } finally {
    fs.rmSync(scannerHome, { recursive: true, force: true });
  }
}

function gitOutput(args, options = {}) {
  const execute = options.executeGit || run;
  const scannerHome = temporaryRoot("cloudsmith-secret-git-home-");
  try {
    const result = execute("git", args, {
      cwd: options.root || ROOT,
      env: privateScannerEnvironment(options.environment, scannerHome),
    });
    if (result.error || result.signal || result.status !== 0) {
      throw new Error("Git metadata required by the secret gate was unavailable.");
    }
    return String(result.stdout || "");
  } finally {
    fs.rmSync(scannerHome, { recursive: true, force: true });
  }
}

function currentHead(root = ROOT, options = {}) {
  const value = gitOutput(["rev-parse", "--verify", "HEAD^{commit}"], {
    ...options,
    root,
  }).trim();
  if (!/^[0-9a-f]{40}$/u.test(value)) {
    throw new Error("Secret gate could not resolve an exact source commit.");
  }
  return value;
}

function trackedFiles(root = ROOT, options = {}) {
  const output = gitOutput([
    "ls-files",
    "-z",
    "--cached",
    "--others",
    "--exclude-standard",
  ], { ...options, root });
  const files = output.split("\0").filter(Boolean).map(normalizePath);
  if (files.length === 0 || files.length > MAX_TRACKED_FILES) {
    throw new Error("Tracked-file secret scan inventory is empty or exceeds its safety bound.");
  }
  const unique = new Set();
  for (const file of files) {
    assertRepositoryRelativePath(file);
    if (unique.has(file)) throw new Error(`Tracked-file inventory contains a duplicate path: ${file}`);
    unique.add(file);
  }
  return [...unique].sort();
}

function ensureSnapshotDirectory(snapshotRoot, relativeDirectory) {
  if (relativeDirectory === "." || relativeDirectory === "") return snapshotRoot;
  let current = snapshotRoot;
  for (const segment of relativeDirectory.split("/")) {
    current = path.join(current, segment);
    if (!fs.existsSync(current)) fs.mkdirSync(current, { mode: 0o700 });
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new Error("Secret scan snapshot ancestry must use real directories.");
    }
  }
  return current;
}

function copyFileIntoSnapshot(source, relativePath, snapshotRoot) {
  assertRepositoryRelativePath(relativePath);
  const parent = ensureSnapshotDirectory(snapshotRoot, path.posix.dirname(relativePath));
  const destination = path.join(parent, path.posix.basename(relativePath));
  const stat = fs.lstatSync(source);
  if (stat.isSymbolicLink()) {
    fs.writeFileSync(destination, fs.readlinkSync(source), { encoding: "utf8", mode: 0o600, flag: "wx" });
  } else if (stat.isFile()) {
    fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
    fs.chmodSync(destination, 0o600);
  } else {
    throw new Error(`Secret scan source must be a regular file or tracked link: ${relativePath}`);
  }
}

function createTrackedSnapshot(root, snapshotRoot, options = {}) {
  const files = options.files || trackedFiles(root, options);
  const copied = [];
  const deleted = [];
  for (const file of files) {
    const source = path.join(root, ...file.split("/"));
    if (!fs.existsSync(source)) {
      deleted.push(file);
      continue;
    }
    copyFileIntoSnapshot(source, file, snapshotRoot);
    copied.push(file);
  }
  if (copied.length === 0) throw new Error("Tracked-file secret scan snapshot contains no files.");
  return { copied, deleted };
}

function walkGeneratedFiles(root, relativeDirectory, options = {}) {
  const absoluteRoot = path.join(root, ...relativeDirectory.split("/"));
  if (!fs.existsSync(absoluteRoot)) return [];
  const rootStat = fs.lstatSync(absoluteRoot);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
    throw new Error(`Generated evidence root must be a real directory: ${relativeDirectory}`);
  }
  const excludedPrefixes = options.excludedPrefixes || [];
  const files = [];
  const pending = [absoluteRoot];
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      const relative = normalizePath(path.relative(root, absolute));
      if (excludedPrefixes.some(prefix => relative === prefix || relative.startsWith(`${prefix}/`))) continue;
      const stat = fs.lstatSync(absolute);
      if (stat.isSymbolicLink()) {
        throw new Error(`Generated evidence scan rejects symbolic links: ${relative}`);
      }
      if (stat.isDirectory()) pending.push(absolute);
      else if (stat.isFile()) files.push(relative);
      else throw new Error(`Generated evidence scan rejects non-file entries: ${relative}`);
      if (files.length > MAX_GENERATED_FILES) {
        throw new Error("Generated evidence scan exceeded its structural bound.");
      }
    }
  }
  return files.sort();
}

function createSelectedSnapshot(root, snapshotRoot, files) {
  for (const file of files) {
    assertRepositoryRelativePath(file);
    copyFileIntoSnapshot(path.join(root, ...file.split("/")), file, snapshotRoot);
  }
  return [...files];
}

function temporaryRoot(prefix = "cloudsmith-secret-scan-") {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(directory, 0o700);
  return directory;
}

function safeInteger(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`Gitleaks safe report contains an invalid ${field}.`);
  }
  return value;
}

function normalizeReportedPath(value, scanRoot, label) {
  if (typeof value !== "string" || value.length === 0 || value.length > 1000
    || /[\u0000-\u001f\u007f-\u009f]/u.test(value)) {
    throw new Error("Gitleaks safe report contains an invalid file location.");
  }
  const normalizedValue = normalizePath(value);
  let relative = normalizedValue;
  if (path.isAbsolute(value)) relative = normalizePath(path.relative(scanRoot, value));
  relative = relative.replace(/^\.\//u, "");
  if (relative === ".." || relative.startsWith("../") || path.isAbsolute(relative)) {
    throw new Error("Gitleaks safe report escaped its scan root.");
  }
  return label ? `${label}/${relative}` : relative;
}

function parseSafeReport(reportPath, options = {}) {
  const text = fs.readFileSync(reportPath, "utf8");
  if (FORBIDDEN_REPORT_FIELDS.test(text)) {
    throw new Error("Gitleaks emitted a forbidden secret-bearing report field; refusing to parse it.");
  }
  const value = JSON.parse(text || "[]");
  if (!Array.isArray(value)) throw new Error("Gitleaks safe report must be an array.");
  return value.map(item => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error("Gitleaks safe report contains an invalid finding.");
    }
    const keys = Object.keys(item).sort();
    if (JSON.stringify(keys) !== JSON.stringify(SAFE_REPORT_KEYS)) {
      throw new Error("Gitleaks safe report contains unexpected fields.");
    }
    if (typeof item.ruleId !== "string" || !/^[a-z0-9][a-z0-9._-]{0,127}$/iu.test(item.ruleId)) {
      throw new Error("Gitleaks safe report contains an invalid rule identifier.");
    }
    const commit = item.commit === "" ? null : item.commit;
    if (commit !== null && !/^[0-9a-f]{40,64}$/iu.test(commit)) {
      throw new Error("Gitleaks safe report contains an invalid commit location.");
    }
    return {
      ruleId: item.ruleId,
      path: normalizeReportedPath(item.file, options.scanRoot, options.label),
      startLine: safeInteger(item.startLine, "start line"),
      endLine: safeInteger(item.endLine, "end line"),
      commit,
    };
  });
}

function scanWithGitleaks(kind, target, options = {}) {
  const root = options.root || ROOT;
  const execute = options.execute || run;
  const reportRoot = temporaryRoot("cloudsmith-gitleaks-report-");
  const reportPath = path.join(reportRoot, "safe-report.json");
  const scannerHome = path.join(reportRoot, "scanner-home");
  fs.mkdirSync(scannerHome, { mode: 0o700 });
  if (process.platform !== "win32") fs.chmodSync(scannerHome, 0o700);
  const args = [
    kind,
    "--config", path.join(root, CONFIG_PATH),
    "--redact=100",
    "--no-banner",
    "--no-color",
    "--log-level", "error",
    "--report-format", "template",
    "--report-template", path.join(root, REPORT_TEMPLATE),
    "--report-path", reportPath,
    "--exit-code", "1",
    "--timeout", "300",
  ];
  if (kind === "git") args.push("--log-opts=--all", target);
  else args.push("--max-archive-depth", "0", target);
  try {
    const result = execute("gitleaks", args, {
      cwd: root,
      env: privateScannerEnvironment(options.environment, scannerHome),
    });
    if (result.error || result.signal || !new Set([0, 1]).has(result.status)) {
      throw new Error("Gitleaks failed closed before producing a trustworthy result.");
    }
    if (!fs.existsSync(reportPath)) {
      if (result.status === 0) fs.writeFileSync(reportPath, "[]\n", { mode: 0o600, flag: "wx" });
      else throw new Error("Gitleaks reported findings without a safe metadata report.");
    }
    const findings = parseSafeReport(reportPath, {
      scanRoot: options.scanRoot || target,
      label: options.label,
    });
    if ((result.status === 0) !== (findings.length === 0)) {
      throw new Error("Gitleaks exit status disagrees with its safe metadata report.");
    }
    return findings;
  } finally {
    fs.rmSync(reportRoot, { recursive: true, force: true });
  }
}

function scanCurrentWorktreeValueBlind(root = ROOT, options = {}) {
  assertScannerVersion({ ...options, root });
  const component = scanTracked(root, options);
  return Object.freeze({
    status: component.findings.length === 0 ? "passed" : "failed",
    findingCount: component.findings.length,
  });
}

function scanTracked(root, options = {}) {
  const scratch = temporaryRoot();
  const snapshot = path.join(scratch, "tracked");
  fs.mkdirSync(snapshot, { mode: 0o700 });
  try {
    const inventory = createTrackedSnapshot(root, snapshot, options);
    return {
      id: "tracked-current",
      status: "scanned",
      fileCount: inventory.copied.length,
      omittedDeletedFileCount: inventory.deleted.length,
      findings: scanWithGitleaks("dir", snapshot, {
        ...options,
        root,
        scanRoot: snapshot,
      }),
    };
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

function scanGeneratedEvidence(root, relativeDirectory, options = {}) {
  const files = walkGeneratedFiles(root, relativeDirectory, options);
  const id = options.id || relativeDirectory.replace(/[^a-z0-9]+/giu, "-");
  if (files.length === 0) return { id, status: "not-present", fileCount: 0, findings: [] };
  const scratch = temporaryRoot();
  const snapshot = path.join(scratch, "evidence");
  fs.mkdirSync(snapshot, { mode: 0o700 });
  try {
    createSelectedSnapshot(root, snapshot, files);
    return {
      id,
      status: "scanned",
      fileCount: files.length,
      findings: scanWithGitleaks("dir", snapshot, {
        ...options,
        root,
        scanRoot: snapshot,
      }),
    };
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

function discoverVsixFiles(root) {
  const out = path.join(root, "out");
  if (!fs.existsSync(out)) return [];
  const pending = [out];
  const files = [];
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const target = path.join(directory, entry.name);
      const relative = normalizePath(path.relative(root, target));
      const stat = fs.lstatSync(target);
      if (stat.isSymbolicLink()) throw new Error(`VSIX discovery rejects symbolic links: ${relative}`);
      if (stat.isDirectory()) pending.push(target);
      else if (stat.isFile() && entry.name.endsWith(".vsix")) files.push(relative);
      if (files.length > 1000) throw new Error("VSIX discovery exceeded its structural bound.");
    }
  }
  return files.sort();
}

function validateArchiveEntryPath(entryName) {
  const normalized = normalizePath(entryName);
  if (!normalized || normalized.startsWith("/") || normalized.endsWith("/")
    || normalized.includes("\\") || normalized.includes("\0")
    || normalized === ".." || normalized.startsWith("../") || normalized.includes("/../")) {
    throw new Error("VSIX secret scan rejected an unsafe archive path.");
  }
  return normalized;
}

function extractVsix(filePath, destination) {
  return new Promise((resolve, reject) => {
    yauzl.open(filePath, { lazyEntries: true, autoClose: true, validateEntrySizes: true }, (openError, zip) => {
      if (openError) return reject(new Error("VSIX secret scan could not open the archive."));
      let entryCount = 0;
      let totalBytes = 0;
      let settled = false;
      const fail = (message) => {
        if (settled) return;
        settled = true;
        zip.close();
        reject(message instanceof Error ? message : new Error(message));
      };
      zip.on("error", () => fail("VSIX secret scan encountered an archive error."));
      zip.on("end", () => {
        if (settled) return;
        settled = true;
        resolve({ entryCount, totalBytes });
      });
      zip.on("entry", (entry) => {
        if (settled) return;
        entryCount += 1;
        if (entryCount > MAX_VSIX_ENTRIES) return fail("VSIX secret scan exceeded its entry bound.");
        const isDirectory = entry.fileName.endsWith("/");
        if (isDirectory) {
          zip.readEntry();
          return;
        }
        let relative;
        try {
          relative = validateArchiveEntryPath(entry.fileName);
        } catch (error) {
          fail(error);
          return;
        }
        const unixMode = (entry.externalFileAttributes >>> 16) & 0xffff;
        if ((unixMode & 0o170000) === 0o120000) return fail("VSIX secret scan rejects symbolic-link entries.");
        if (entry.uncompressedSize > MAX_VSIX_ENTRY_BYTES) return fail("VSIX secret scan exceeded its per-entry byte bound.");
        totalBytes += entry.uncompressedSize;
        if (totalBytes > MAX_VSIX_TOTAL_BYTES) return fail("VSIX secret scan exceeded its total byte bound.");
        const target = path.join(destination, ...relative.split("/"));
        ensureSnapshotDirectory(destination, path.posix.dirname(relative));
        zip.openReadStream(entry, (streamError, stream) => {
          if (streamError) return fail("VSIX secret scan could not read an archive entry.");
          const output = fs.createWriteStream(target, { flags: "wx", mode: 0o600 });
          stream.on("error", () => fail("VSIX secret scan could not read an archive entry."));
          output.on("error", () => fail("VSIX secret scan could not persist an archive entry."));
          output.on("finish", () => zip.readEntry());
          stream.pipe(output);
        });
      });
      zip.readEntry();
    });
  });
}

async function scanVsix(root, relativePath, options = {}) {
  assertRepositoryRelativePath(relativePath);
  const filePath = path.join(root, ...relativePath.split("/"));
  const stat = fs.lstatSync(filePath);
  if (stat.isSymbolicLink() || !stat.isFile()) throw new Error("VSIX secret scan requires a real archive file.");
  const archiveFindings = scanWithGitleaks("dir", filePath, {
    ...options,
    root,
    scanRoot: path.dirname(filePath),
    label: `${relativePath}::archive`,
  });
  const scratch = temporaryRoot("cloudsmith-vsix-secret-scan-");
  const expanded = path.join(scratch, "expanded");
  fs.mkdirSync(expanded, { mode: 0o700 });
  try {
    const extraction = await extractVsix(filePath, expanded);
    const expandedFindings = scanWithGitleaks("dir", expanded, {
      ...options,
      root,
      scanRoot: expanded,
      label: `${relativePath}::expanded`,
    });
    return {
      id: `vsix:${relativePath}`,
      status: "scanned",
      fileCount: extraction.entryCount + 1,
      findings: [...archiveFindings, ...expandedFindings],
    };
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

async function scanArtifacts(root, options = {}) {
  const files = discoverVsixFiles(root);
  if (files.length === 0) return [{ id: "vsix-artifacts", status: "not-present", fileCount: 0, findings: [] }];
  const results = [];
  for (const file of files) results.push(await scanVsix(root, file, options));
  return results;
}

function scanHistory(root, options = {}) {
  const findings = scanWithGitleaks("git", root, {
    ...options,
    root,
    scanRoot: root,
  });
  return { id: "git-history-all-refs", status: "scanned", fileCount: null, findings };
}

function resultDocument(mode, sourceSha, components, now = new Date()) {
  const findings = components.flatMap(component => component.findings.map(finding => ({
    component: component.id,
    ...finding,
  })));
  return {
    schemaVersion: 1,
    scanner: {
      name: "gitleaks",
      version: GITLEAKS_VERSION,
      redactionPercent: 100,
      secretBearingFieldsPersisted: false,
    },
    mode,
    status: findings.length === 0 ? "passed" : "failed",
    sourceSha,
    capturedAt: now.toISOString(),
    findingCount: findings.length,
    components: components.map(component => ({
      id: component.id,
      status: component.status,
      fileCount: component.fileCount,
      findingCount: component.findings.length,
      ...(Number.isInteger(component.omittedDeletedFileCount)
        ? { omittedDeletedFileCount: component.omittedDeletedFileCount }
        : {}),
    })),
    findings,
  };
}

async function executeScan(options = {}) {
  const root = assertRealRepositoryRoot(options.root || ROOT);
  const mode = options.mode || "current";
  assertScannerVersion({ ...options, root });
  const sourceSha = currentHead(root, options);
  const components = [];
  if (mode === "current" || mode === "all") {
    components.push(scanTracked(root, options));
  }
  if (mode === "current" || mode === "evidence" || mode === "all") {
    components.push(scanGeneratedEvidence(root, ".quality", {
      ...options,
      id: "generated-quality-evidence",
      excludedPrefixes: [OUTPUT_ROOT],
    }));
    if (options.includeLocalEvidence) {
      components.push(scanGeneratedEvidence(root, "internal_docs/quality", {
        ...options,
        id: "local-internal-quality-evidence",
      }));
    }
  }
  if (mode === "artifacts" || mode === "current" || mode === "all") {
    components.push(...await scanArtifacts(root, options));
  }
  if (mode === "history" || mode === "all") components.push(scanHistory(root, options));
  return resultDocument(mode, sourceSha, components, options.now || new Date());
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArguments(argv);
  const outputPath = `${OUTPUT_ROOT}/${options.mode}.json`;
  removeOutputFile(outputPath, ROOT);
  const result = await executeScan(options);
  writeJson(outputPath, result, ROOT);
  console.log(
    `Secret exposure gate ${result.status}: ${result.findingCount} finding(s) across `
    + `${result.components.length} scanned component(s).`
  );
  if (result.status !== "passed") process.exitCode = 1;
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`Secret exposure gate failed closed: ${error.message}`);
    process.exit(1);
  });
}

module.exports = {
  CONFIG_PATH,
  FORBIDDEN_REPORT_FIELDS,
  GITLEAKS_VERSION,
  REPORT_TEMPLATE,
  SAFE_REPORT_KEYS,
  assertScannerVersion,
  copyFileIntoSnapshot,
  createTrackedSnapshot,
  discoverVsixFiles,
  executeScan,
  extractVsix,
  parseArguments,
  parseSafeReport,
  resultDocument,
  scanGeneratedEvidence,
  scanCurrentWorktreeValueBlind,
  scanTracked,
  scanVsix,
  scanWithGitleaks,
  scannerEnvironment,
  privateScannerEnvironment,
  trackedFiles,
  validateArchiveEntryPath,
  walkGeneratedFiles,
};

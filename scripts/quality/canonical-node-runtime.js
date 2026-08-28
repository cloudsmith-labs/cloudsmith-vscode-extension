// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const path = require("path");
const {
  digestStableSingleLinkFile,
  exactFileIdentity,
  withStableSingleLinkFile,
} = require("./candidate-binding");
const {
  expectedExactCleanupTreeEntry,
  preserveNonAuthCleanupSubtree,
  removeExactOwnedDirectoryTree,
} = require("./non-auth-environment");

const NODE_VERSION_PIN_ERROR = "Canonical Node.js version pin is unsafe or invalid";
const NPM_RUNTIME_ERROR = "Canonical npm runtime is unsafe or invalid";
const NPM_LAUNCHER_ERROR = "Canonical npm launcher is unsafe or invalid";
const NPM_LAUNCHER_CLEANUP_ERROR = "Canonical npm launcher cleanup refused an unsafe or changed tree.";
const MAX_NODE_VERSION_PIN_BYTES = 64;
const MAX_NPM_VERSION_PIN_BYTES = 64;
const MAX_NPM_PACKAGE_JSON_BYTES = 1024 * 1024;
const MAX_NPM_CLI_BYTES = 1024 * 1024;
const MAX_NPM_INTEGRITY_PIN_BYTES = 256;
const MAX_NPM_INSTALLATION_ENTRIES = 5000;
const MAX_NPM_INSTALLATION_FILE_BYTES = 16 * 1024 * 1024;
const MAX_NPM_INSTALLATION_BYTES = 128 * 1024 * 1024;
const validatedNpmProvenance = new WeakSet();

function canonicalNpmCliSource(platform) {
  const newline = platform === "win32" ? "\r\n" : "\n";
  return Buffer.from(
    `#!/usr/bin/env node${newline}require('../lib/cli.js')(process)${newline}`,
    "utf8",
  );
}

function sameFilesystemPath(left, right, platform = process.platform) {
  const normalizedLeft = path.normalize(left);
  const normalizedRight = path.normalize(right);
  return platform === "win32"
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight;
}

function exactAbsolutePath(value, errorMessage) {
  if (typeof value !== "string" || value.length === 0
    || !path.isAbsolute(value) || path.normalize(value) !== value
    || path.resolve(value) !== value || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(errorMessage);
  }
  return value;
}

function assertExactRealDirectory(directory, errorMessage, options = {}) {
  const fileSystem = options.fileSystem || require("fs");
  const platform = options.platform || process.platform;
  const target = exactAbsolutePath(directory, errorMessage);
  const stat = fileSystem.lstatSync(target, { bigint: true });
  if (stat.isSymbolicLink() || !stat.isDirectory()
    || (options.rejectGroupWritable === true
      && process.platform !== "win32" && (stat.mode & 0o022n) !== 0n)
    || !sameFilesystemPath(fileSystem.realpathSync(target), target, platform)) {
    throw new Error(errorMessage);
  }
  return stat;
}

function assertExactNodeExecutable(executable = process.execPath, options = {}) {
  const errorMessage = "Canonical Node.js executable is unsafe or invalid";
  const fileSystem = options.fileSystem || require("fs");
  const platform = options.platform || process.platform;
  try {
    const target = exactAbsolutePath(executable, errorMessage);
    const stat = fileSystem.lstatSync(target, { bigint: true });
    if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink < 1n || stat.size <= 0n
      || (process.platform !== "win32" && (stat.mode & 0o022n) !== 0n)
      || !sameFilesystemPath(fileSystem.realpathSync(target), target, platform)) {
      throw new Error(errorMessage);
    }
    return target;
  } catch {
    throw new Error(errorMessage);
  }
}

function exactNodeExecutableBinding(executable = process.execPath, options = {}) {
  const fileSystem = options.fileSystem || require("fs");
  const platform = options.platform || process.platform;
  const target = assertExactNodeExecutable(executable, { fileSystem, platform });
  const directory = path.dirname(target);
  const nodeStat = fileSystem.lstatSync(target, { bigint: true });
  const directoryStat = assertExactRealDirectory(
    directory,
    "Canonical Node.js executable is unsafe or invalid",
    { fileSystem, platform, rejectGroupWritable: true },
  );
  return Object.freeze({
    directory,
    directoryIdentity: directoryIdentity(directoryStat),
    executable: target,
    executableIdentity: exactFileIdentity(nodeStat),
  });
}

function assertCanonicalNodeRuntime(repositoryRoot, actualVersion = process.version) {
  const expectedVersion = withStableSingleLinkFile(
    path.join(repositoryRoot, ".node-version"),
    {
      errorMessage: NODE_VERSION_PIN_ERROR,
      maximumBytes: MAX_NODE_VERSION_PIN_BYTES,
      minimumBytes: 1,
    },
    bytes => {
      const match = /^(\d+\.\d+\.\d+)(?:\r?\n)?$/u.exec(bytes.toString("utf8"));
      if (!match) throw new Error(NODE_VERSION_PIN_ERROR);
      return `v${match[1]}`;
    },
  );
  if (actualVersion !== expectedVersion) {
    throw new Error("Canonical Node.js runtime does not match the exact version pin");
  }
  return expectedVersion;
}

function directoryIdentity(stat) {
  return Object.freeze({
    changedNanoseconds: String(stat.ctimeNs),
    dev: String(stat.dev),
    gid: String(stat.gid),
    ino: String(stat.ino),
    mode: String(stat.mode),
    modifiedNanoseconds: String(stat.mtimeNs),
    nlink: String(stat.nlink),
    size: String(stat.size),
    uid: String(stat.uid),
  });
}

function sameIdentity(left, right) {
  return left && right && Object.keys(left).length === Object.keys(right).length
    && Object.keys(left).every(key => left[key] === right[key]);
}

function npmInstallationFingerprint(packageRoot, options = {}) {
  const fs = options.fileSystem || require("fs");
  const platform = options.platform || process.platform;
  const root = exactAbsolutePath(packageRoot, NPM_RUNTIME_ERROR);
  assertExactRealDirectory(root, NPM_RUNTIME_ERROR, {
    fileSystem: fs,
    platform,
    rejectGroupWritable: true,
  });
  const pending = [{ absolute: root, depth: 0, relative: "" }];
  const records = [];
  const runtimeRecords = [];
  let directoryCount = 0;
  let fileCount = 0;
  let entries = 0;
  let totalBytes = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    if (current.depth > 64) throw new Error(NPM_RUNTIME_ERROR);
    const beforeStat = fs.lstatSync(current.absolute, { bigint: true });
    if (beforeStat.isSymbolicLink() || !beforeStat.isDirectory()
      || !sameFilesystemPath(fs.realpathSync(current.absolute), current.absolute, platform)) {
      throw new Error(NPM_RUNTIME_ERROR);
    }
    const beforeIdentity = directoryIdentity(beforeStat);
    runtimeRecords.push(Object.freeze({
      identity: beforeIdentity,
      kind: "directory",
      path: current.relative,
    }));
    const names = fs.readdirSync(current.absolute).sort();
    if (names.length !== new Set(names).size) throw new Error(NPM_RUNTIME_ERROR);
    for (const name of names) {
      entries += 1;
      if (entries > MAX_NPM_INSTALLATION_ENTRIES || typeof name !== "string"
        || name.length === 0 || name === "." || name === ".."
        || /[\/\\\u0000-\u001f\u007f]/u.test(name)) {
        throw new Error(NPM_RUNTIME_ERROR);
      }
      const absolute = path.join(current.absolute, name);
      const relative = current.relative ? `${current.relative}/${name}` : name;
      const stat = fs.lstatSync(absolute, { bigint: true });
      if (relative === "node_modules/.bin") {
        throw new Error(NPM_RUNTIME_ERROR);
      }
      if (stat.isDirectory()) {
        if (stat.isSymbolicLink()
          || (process.platform !== "win32" && (stat.mode & 0o022n) !== 0n)
          || !sameFilesystemPath(fs.realpathSync(absolute), absolute, platform)) {
          throw new Error(NPM_RUNTIME_ERROR);
        }
        directoryCount += 1;
        records.push(Object.freeze({ kind: "directory", path: relative }));
        pending.push({ absolute, depth: current.depth + 1, relative });
        continue;
      }
      if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1n
        || (process.platform !== "win32" && (stat.mode & 0o022n) !== 0n)
        || stat.size < 0n || stat.size > BigInt(MAX_NPM_INSTALLATION_FILE_BYTES)) {
        throw new Error(NPM_RUNTIME_ERROR);
      }
      totalBytes += Number(stat.size);
      if (!Number.isSafeInteger(totalBytes) || totalBytes > MAX_NPM_INSTALLATION_BYTES) {
        throw new Error(NPM_RUNTIME_ERROR);
      }
      const identity = exactFileIdentity(stat);
      const proof = digestStableSingleLinkFile(absolute, {
        errorMessage: NPM_RUNTIME_ERROR,
        expectedIdentity: identity,
        fileSystem: fs,
        maximumBytes: MAX_NPM_INSTALLATION_FILE_BYTES,
        minimumBytes: 0,
      });
      fileCount += 1;
      records.push(Object.freeze({
        kind: "file",
        path: relative.split(path.sep).join("/"),
        sha256: proof.sha256,
        size: Number(stat.size),
      }));
      runtimeRecords.push(Object.freeze({
        identity: Object.freeze({
          ...identity,
          group: String(stat.gid),
          owner: String(stat.uid),
        }),
        kind: "file",
        path: relative.split(path.sep).join("/"),
      }));
    }
    const afterStat = fs.lstatSync(current.absolute, { bigint: true });
    if (!sameIdentity(beforeIdentity, directoryIdentity(afterStat))
      || JSON.stringify(names) !== JSON.stringify(fs.readdirSync(current.absolute).sort())) {
      throw new Error(NPM_RUNTIME_ERROR);
    }
  }
  records.sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
  const hash = crypto.createHash("sha256");
  hash.update("cloudsmith-canonical-npm-installation-v2\0");
  for (const record of records) {
    hash.update(`${record.kind}\0${record.path}\0`);
    if (record.kind === "file") hash.update(`${record.size}\0${record.sha256}\0`);
  }
  runtimeRecords.sort((left, right) => (
    left.path < right.path ? -1 : left.path > right.path ? 1 : left.kind.localeCompare(right.kind)
  ));
  const runtimeHash = crypto.createHash("sha256");
  runtimeHash.update("cloudsmith-canonical-npm-runtime-identity-v1\0");
  for (const record of runtimeRecords) {
    runtimeHash.update(`${record.kind}\0${record.path}\0${JSON.stringify(record.identity)}\0`);
  }
  return Object.freeze({
    directoryCount,
    fileCount,
    sha256: hash.digest("hex"),
    runtimeSha256: runtimeHash.digest("hex"),
    totalBytes,
  });
}

function copyCanonicalNpmInstallation(packageRoot, snapshotRoot, options = {}) {
  const fs = options.fileSystem || require("fs");
  const platform = options.platform || process.platform;
  const source = exactAbsolutePath(packageRoot, NPM_LAUNCHER_ERROR);
  const target = exactAbsolutePath(snapshotRoot, NPM_LAUNCHER_ERROR);
  const parent = path.dirname(target);
  assertExactRealDirectory(source, NPM_LAUNCHER_ERROR, {
    fileSystem: fs,
    platform,
    rejectGroupWritable: true,
  });
  assertExactRealDirectory(parent, NPM_LAUNCHER_ERROR, {
    fileSystem: fs,
    platform,
    rejectGroupWritable: true,
  });
  fs.mkdirSync(target, { mode: 0o700 });
  if (process.platform !== "win32") fs.chmodSync(target, 0o700);
  assertExactRealDirectory(target, NPM_LAUNCHER_ERROR, {
    fileSystem: fs,
    platform,
    rejectGroupWritable: true,
  });

  const pending = [{ source, target, depth: 0 }];
  let entries = 0;
  let totalBytes = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    if (current.depth > 64) throw new Error(NPM_LAUNCHER_ERROR);
    const beforeStat = fs.lstatSync(current.source, { bigint: true });
    if (beforeStat.isSymbolicLink() || !beforeStat.isDirectory()
      || (process.platform !== "win32" && (beforeStat.mode & 0o022n) !== 0n)
      || !sameFilesystemPath(fs.realpathSync(current.source), current.source, platform)) {
      throw new Error(NPM_LAUNCHER_ERROR);
    }
    const beforeIdentity = directoryIdentity(beforeStat);
    const names = fs.readdirSync(current.source).sort();
    if (names.length !== new Set(names).size) throw new Error(NPM_LAUNCHER_ERROR);
    for (const name of names) {
      entries += 1;
      if (entries > MAX_NPM_INSTALLATION_ENTRIES || typeof name !== "string"
        || name.length === 0 || name === "." || name === ".."
        || /[\/\\\u0000-\u001f\u007f]/u.test(name)) {
        throw new Error(NPM_LAUNCHER_ERROR);
      }
      const sourceEntry = path.join(current.source, name);
      const targetEntry = path.join(current.target, name);
      const stat = fs.lstatSync(sourceEntry, { bigint: true });
      if (stat.isDirectory()) {
        if (stat.isSymbolicLink()
          || (process.platform !== "win32" && (stat.mode & 0o022n) !== 0n)
          || !sameFilesystemPath(fs.realpathSync(sourceEntry), sourceEntry, platform)) {
          throw new Error(NPM_LAUNCHER_ERROR);
        }
        fs.mkdirSync(targetEntry, { mode: 0o700 });
        if (process.platform !== "win32") fs.chmodSync(targetEntry, 0o700);
        pending.push({
          source: sourceEntry,
          target: targetEntry,
          depth: current.depth + 1,
        });
        continue;
      }
      if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1n
        || (process.platform !== "win32" && (stat.mode & 0o022n) !== 0n)
        || stat.size < 0n || stat.size > BigInt(MAX_NPM_INSTALLATION_FILE_BYTES)) {
        throw new Error(NPM_LAUNCHER_ERROR);
      }
      totalBytes += Number(stat.size);
      if (!Number.isSafeInteger(totalBytes) || totalBytes > MAX_NPM_INSTALLATION_BYTES) {
        throw new Error(NPM_LAUNCHER_ERROR);
      }
      const sourceIdentity = exactFileIdentity(stat);
      withStableSingleLinkFile(sourceEntry, {
        errorMessage: NPM_LAUNCHER_ERROR,
        expectedIdentity: sourceIdentity,
        fileSystem: fs,
        maximumBytes: MAX_NPM_INSTALLATION_FILE_BYTES,
        minimumBytes: 0,
      }, bytes => {
        fs.writeFileSync(targetEntry, bytes, { flag: "wx", mode: 0o400 });
      });
      if (process.platform !== "win32") fs.chmodSync(targetEntry, 0o400);
      const copiedStat = fs.lstatSync(targetEntry, { bigint: true });
      if (copiedStat.isSymbolicLink() || !copiedStat.isFile() || copiedStat.nlink !== 1n
        || copiedStat.size !== stat.size
        || !sameFilesystemPath(fs.realpathSync(targetEntry), targetEntry, platform)
        || (typeof process.getuid === "function" && copiedStat.uid !== BigInt(process.getuid()))) {
        throw new Error(NPM_LAUNCHER_ERROR);
      }
    }
    const afterStat = fs.lstatSync(current.source, { bigint: true });
    if (!sameIdentity(beforeIdentity, directoryIdentity(afterStat))
      || JSON.stringify(names) !== JSON.stringify(fs.readdirSync(current.source).sort())) {
      throw new Error(NPM_LAUNCHER_ERROR);
    }
  }
  const snapshot = npmInstallationFingerprint(target, { fileSystem: fs, platform });
  if (!options.expectedInstallation
    || snapshot.sha256 !== options.expectedInstallation.sha256
    || snapshot.directoryCount !== options.expectedInstallation.directoryCount
    || snapshot.fileCount !== options.expectedInstallation.fileCount
    || snapshot.totalBytes !== options.expectedInstallation.totalBytes) {
    throw new Error(NPM_LAUNCHER_ERROR);
  }
  return snapshot;
}

function assertCanonicalNpmRuntime(repositoryRoot, npmExecPath, options = {}) {
  const fileSystem = options.fileSystem || require("fs");
  const platform = options.platform || process.platform;
  try {
    assertExactRealDirectory(
      repositoryRoot,
      NPM_RUNTIME_ERROR,
      { fileSystem, platform },
    );
    const node = exactNodeExecutableBinding(
      options.nodeExecutable || process.execPath,
      { fileSystem, platform },
    );
    const nodeExecutable = node.executable;
    const nodeDirectory = node.directory;
    const packageRoot = platform === "win32"
      ? path.join(nodeDirectory, "node_modules", "npm")
      : path.join(path.dirname(nodeDirectory), "lib", "node_modules", "npm");
    const binRoot = path.join(packageRoot, "bin");
    const cliPath = path.join(binRoot, "npm-cli.js");
    if (npmExecPath !== undefined && npmExecPath !== null
      && !sameFilesystemPath(
        exactAbsolutePath(npmExecPath, NPM_RUNTIME_ERROR),
        cliPath,
        platform,
      )) {
      throw new Error(NPM_RUNTIME_ERROR);
    }
    const libCliPath = path.join(packageRoot, "lib", "cli.js");
    const packageJsonPath = path.join(packageRoot, "package.json");
    const distributionRoot = platform === "win32" ? nodeDirectory : path.dirname(nodeDirectory);
    const ancestorDirectories = platform === "win32"
      ? [path.join(nodeDirectory, "node_modules"), packageRoot, binRoot, path.join(packageRoot, "lib")]
      : [
        distributionRoot,
        path.join(distributionRoot, "lib"),
        path.join(distributionRoot, "lib", "node_modules"),
        packageRoot,
        binRoot,
        path.join(packageRoot, "lib"),
      ];
    const ancestorIdentities = Object.freeze(ancestorDirectories.map(directory => Object.freeze({
      directory,
      identity: directoryIdentity(assertExactRealDirectory(
        directory,
        NPM_RUNTIME_ERROR,
        { fileSystem, platform, rejectGroupWritable: true },
      )),
    })));
    if (!sameFilesystemPath(path.join(binRoot, "npm-cli.js"), cliPath, platform)) {
      throw new Error(NPM_RUNTIME_ERROR);
    }
    const binding = withStableSingleLinkFile(
      path.join(repositoryRoot, ".npm-version"),
      {
        errorMessage: NPM_RUNTIME_ERROR,
        fileSystem,
        maximumBytes: MAX_NPM_VERSION_PIN_BYTES,
        minimumBytes: 1,
      },
      (pinBytes, npmVersionPinIdentity) => {
        const match = /^(\d+\.\d+\.\d+)(?:\r?\n)?$/u.exec(pinBytes.toString("utf8"));
        if (!match) throw new Error(NPM_RUNTIME_ERROR);
        const expectedVersion = match[1];
        return withStableSingleLinkFile(
          packageJsonPath,
          {
            errorMessage: NPM_RUNTIME_ERROR,
            fileSystem,
            maximumBytes: MAX_NPM_PACKAGE_JSON_BYTES,
            minimumBytes: 1,
          },
          (metadataBytes, packageJsonIdentity) => {
            const metadataText = metadataBytes.toString("utf8");
            if (!Buffer.from(metadataText, "utf8").equals(metadataBytes)) {
              throw new Error(NPM_RUNTIME_ERROR);
            }
            const metadata = JSON.parse(metadataText);
            const binKeys = metadata?.bin && typeof metadata.bin === "object"
              && !Array.isArray(metadata.bin) ? Object.keys(metadata.bin).sort() : [];
            if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)
              || metadata.name !== "npm" || metadata.version !== expectedVersion
              || metadata.main !== "./index.js"
              || JSON.stringify(binKeys) !== JSON.stringify(["npm", "npx"])
              || metadata.bin.npm !== "bin/npm-cli.js"
              || metadata.bin.npx !== "bin/npx-cli.js"
              || metadata.engines?.node !== "^18.17.0 || >=20.5.0") {
              throw new Error(NPM_RUNTIME_ERROR);
            }
            const declaredCli = path.join(packageRoot, ...metadata.bin.npm.split("/"));
            if (!sameFilesystemPath(declaredCli, cliPath, platform)) {
              throw new Error(NPM_RUNTIME_ERROR);
            }
            return withStableSingleLinkFile(
              cliPath,
              {
                errorMessage: NPM_RUNTIME_ERROR,
                fileSystem,
                maximumBytes: MAX_NPM_CLI_BYTES,
                minimumBytes: 1,
              },
              (cliBytes, cliIdentity) => {
                if (!cliBytes.equals(canonicalNpmCliSource(platform))) {
                  throw new Error(NPM_RUNTIME_ERROR);
                }
                return withStableSingleLinkFile(
                  libCliPath,
                  {
                    errorMessage: NPM_RUNTIME_ERROR,
                    fileSystem,
                    maximumBytes: MAX_NPM_CLI_BYTES,
                    minimumBytes: 1,
                  },
                  (_libCliBytes, libCliIdentity) => Object.freeze({
                    cliIdentity,
                    libCliIdentity,
                    npmVersionPinIdentity,
                    packageJsonIdentity,
                    version: expectedVersion,
                  }),
                );
              },
            );
          },
        );
      },
    );
    const installation = npmInstallationFingerprint(packageRoot, { fileSystem, platform });
    const integrityBinding = withStableSingleLinkFile(
      path.join(repositoryRoot, ".npm-integrity"),
      {
        errorMessage: NPM_RUNTIME_ERROR,
        fileSystem,
        maximumBytes: MAX_NPM_INTEGRITY_PIN_BYTES,
        minimumBytes: 1,
      },
      (bytes, identity) => {
        const text = bytes.toString("utf8");
        if (!Buffer.from(text, "utf8").equals(bytes)) throw new Error(NPM_RUNTIME_ERROR);
        const pins = JSON.parse(text);
        if (!pins || typeof pins !== "object" || Array.isArray(pins)
          || JSON.stringify(Object.keys(pins).sort()) !== JSON.stringify(["posix", "win32"])
          || !/^[a-f0-9]{64}$/u.test(pins.posix)
          || !/^[a-f0-9]{64}$/u.test(pins.win32)
          || pins[platform === "win32" ? "win32" : "posix"] !== installation.sha256) {
          throw new Error(NPM_RUNTIME_ERROR);
        }
        const canonical = JSON.stringify({ posix: pins.posix, win32: pins.win32 });
        if (text !== `${canonical}\n` && text !== `${canonical}\r\n`) {
          throw new Error(NPM_RUNTIME_ERROR);
        }
        return Object.freeze({ identity, pins: Object.freeze({ ...pins }) });
      },
    );
    if (ancestorIdentities.some(binding => !sameIdentity(
      binding.identity,
      directoryIdentity(assertExactRealDirectory(
        binding.directory,
        NPM_RUNTIME_ERROR,
        { fileSystem, platform, rejectGroupWritable: true },
      )),
    ))) {
      throw new Error(NPM_RUNTIME_ERROR);
    }
    const provenance = Object.freeze({
      binRoot,
      cliPath,
      identities: Object.freeze({
        ancestors: ancestorIdentities,
        cli: binding.cliIdentity,
        integrityPin: integrityBinding.identity,
        libCli: binding.libCliIdentity,
        nodeDirectory: node.directoryIdentity,
        nodeExecutable: node.executableIdentity,
        npmVersionPin: binding.npmVersionPinIdentity,
        packageJson: binding.packageJsonIdentity,
      }),
      installation,
      libCliPath,
      nodeExecutable,
      packageJsonPath,
      packageRoot,
      repositoryRoot,
      version: binding.version,
    });
    validatedNpmProvenance.add(provenance);
    return provenance;
  } catch {
    throw new Error(NPM_RUNTIME_ERROR);
  }
}

function npmProvenanceKey(npm) {
  return JSON.stringify({
    binRoot: npm.binRoot,
    cliPath: npm.cliPath,
    identities: npm.identities,
    installation: npm.installation,
    libCliPath: npm.libCliPath,
    nodeExecutable: npm.nodeExecutable,
    packageJsonPath: npm.packageJsonPath,
    packageRoot: npm.packageRoot,
    repositoryRoot: npm.repositoryRoot,
    version: npm.version,
  });
}

function revalidateCanonicalNpmProvenance(npm, options = {}) {
  if (!validatedNpmProvenance.has(npm)) throw new Error(NPM_LAUNCHER_ERROR);
  const current = assertCanonicalNpmRuntime(npm.repositoryRoot, npm.cliPath, {
    nodeExecutable: npm.nodeExecutable,
    platform: options.platform,
  });
  if (npmProvenanceKey(current) !== npmProvenanceKey(npm)) {
    throw new Error(NPM_LAUNCHER_ERROR);
  }
  return current;
}

function environmentValue(environment, platform, canonicalName) {
  if (!environment || typeof environment !== "object" || Array.isArray(environment)) {
    throw new Error("Canonical toolchain environment is unsafe or invalid");
  }
  const names = Object.keys(environment);
  const matches = platform === "win32"
    ? names.filter(name => name.toUpperCase() === canonicalName)
    : names.filter(name => name === canonicalName);
  if (matches.length > 1) {
    throw new Error(`Canonical toolchain ${canonicalName} has case-colliding keys`);
  }
  const value = matches.length === 1 ? environment[matches[0]] : "";
  if (typeof value !== "string" || value.length > 32768 || value.includes("\u0000")) {
    throw new Error(`Canonical toolchain ${canonicalName} is unsafe or invalid`);
  }
  return { key: matches[0] || null, value };
}

function canonicalWindowsCommandShell(environment, platform) {
  if (platform !== "win32" || process.platform !== "win32") return null;
  const systemRoot = environmentValue(environment, platform, "SYSTEMROOT").value;
  const windowsDirectory = environmentValue(environment, platform, "WINDIR").value;
  const comspec = environmentValue(environment, platform, "COMSPEC").value;
  const validRoot = value => typeof value === "string" && value.length > 0
    && path.win32.isAbsolute(value)
    && path.win32.normalize(value) === value
    && !/[\u0000-\u001f\u007f]/u.test(value);
  if (!validRoot(systemRoot) || !validRoot(windowsDirectory)
    || !sameFilesystemPath(systemRoot, windowsDirectory, platform)) {
    throw new Error("Canonical Windows command shell roots are unsafe or inconsistent");
  }
  const expected = path.win32.join(systemRoot, "System32", "cmd.exe");
  if (!sameFilesystemPath(comspec, expected, platform)) {
    throw new Error("Canonical Windows COMSPEC is unsafe or invalid");
  }
  const shell = assertExactNodeExecutable(expected, { platform });
  return Object.freeze({ root: systemRoot, shell });
}

function canonicalToolchainEnvironment(environment, options = {}) {
  const platform = options.platform || process.platform;
  const current = environmentValue(environment, platform, "PATH");
  const currentPathExt = platform === "win32"
    ? environmentValue(environment, platform, "PATHEXT")
    : null;
  const windowsShell = canonicalWindowsCommandShell(environment, platform);
  const nodeExecutable = assertExactNodeExecutable(options.nodeExecutable || process.execPath, {
    platform,
  });
  const prefixes = [];
  if (options.launcherDirectory !== undefined && options.launcherDirectory !== null) {
    prefixes.push(exactAbsolutePath(
      options.launcherDirectory,
      "Canonical npm launcher is unsafe or invalid",
    ));
  }
  prefixes.push(path.dirname(nodeExecutable));
  const sameEntry = (left, right) => sameFilesystemPath(left, right, platform);
  const remaining = current.value.split(path.delimiter).filter(entry => {
    if (!entry) return false;
    if (!path.isAbsolute(entry) || path.normalize(entry) !== entry
      || /[\u0000-\u001f\u007f]/u.test(entry)) {
      throw new Error("Canonical toolchain PATH is unsafe or invalid");
    }
    return !prefixes.some(prefix => sameEntry(entry, prefix));
  });
  const anchored = [...prefixes, ...remaining].join(path.delimiter);
  if (anchored.length > 32768 || anchored.includes("\u0000")) {
    throw new Error("Canonical toolchain PATH is unsafe or invalid");
  }
  const result = { ...environment };
  if (platform === "win32") {
    for (const name of Object.keys(result)) {
      if ([
        "COMSPEC",
        "NPM_CONFIG_SCRIPT_SHELL",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
      ].includes(name.toUpperCase())) {
        delete result[name];
      }
    }
  } else if (current.key && current.key !== "PATH") {
    delete result[current.key];
  }
  result.PATH = anchored;
  if (platform === "win32") {
    const extensions = currentPathExt.value.split(";").filter(Boolean).map(value => {
      const normalized = value.toUpperCase();
      if (!/^\.[A-Z0-9]+$/u.test(normalized)) {
        throw new Error("Canonical toolchain PATHEXT is unsafe or invalid");
      }
      return normalized;
    });
    result.PATHEXT = [".CMD", ...extensions.filter(value => value !== ".CMD")]
      .filter((value, index, values) => values.indexOf(value) === index)
      .join(";");
    if (windowsShell) {
      result.COMSPEC = windowsShell.shell;
      result.NPM_CONFIG_SCRIPT_SHELL = windowsShell.shell;
      result.SYSTEMROOT = windowsShell.root;
      result.WINDIR = windowsShell.root;
    }
  }
  if (options.scriptShell) {
    const scriptShell = exactAbsolutePath(
      options.scriptShell,
      NPM_LAUNCHER_ERROR,
    );
    if (platform === "win32" && windowsShell
      && !sameFilesystemPath(scriptShell, windowsShell.shell, platform)) {
      throw new Error(NPM_LAUNCHER_ERROR);
    }
    result.NPM_CONFIG_SCRIPT_SHELL = scriptShell;
  }
  return Object.freeze(result);
}

function assertNoNpmToolchainShadowing(repositoryRoot, options = {}) {
  const fs = options.fileSystem || require("fs");
  const platform = options.platform || process.platform;
  const root = exactAbsolutePath(repositoryRoot, NPM_RUNTIME_ERROR);
  assertExactRealDirectory(root, NPM_RUNTIME_ERROR, { fileSystem: fs, platform });
  const names = platform === "win32"
    ? ["node", "node.bat", "node.cmd", "node.com", "node.exe",
      "npm", "npm.bat", "npm.cmd", "npm.com", "npm.exe"]
    : ["node", "npm"];
  const directories = [];
  let current = root;
  while (true) {
    directories.push(path.join(current, "node_modules", ".bin"));
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  if (platform === "win32") directories.push(root);
  try {
    for (const directory of directories) {
      for (const name of names) {
        try {
          fs.lstatSync(path.join(directory, name));
        } catch (error) {
          if (error.code === "ENOENT") continue;
          throw error;
        }
        throw new Error(NPM_RUNTIME_ERROR);
      }
    }
  } catch {
    throw new Error("Canonical npm toolchain command resolution is unsafe or invalid");
  }
  return true;
}

function cleanupIdentity(stat) {
  return Object.freeze({
    changedNanoseconds: String(stat.ctimeNs),
    dev: String(stat.dev),
    ino: String(stat.ino),
    mode: String(stat.mode),
    modifiedNanoseconds: String(stat.mtimeNs),
    nlink: String(stat.nlink),
    size: String(stat.size),
  });
}

function posixQuote(value) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function cmdQuote(value) {
  if (value.includes('"')) throw new Error(NPM_LAUNCHER_ERROR);
  return `"${value.replaceAll("%", "%%")}"`;
}

function launcherSources(nodeExecutable, cliPath, directory, platform) {
  if (platform === "win32") {
    return Object.freeze({
      "node.cmd": `@echo off\r\nsetlocal DisableDelayedExpansion\r\n${cmdQuote(nodeExecutable)} %*\r\n`,
      "npm.cmd": `@echo off\r\nsetlocal DisableDelayedExpansion\r\n${cmdQuote(nodeExecutable)} ${cmdQuote(cliPath)} %*\r\n`,
    });
  }
  const shell = require("fs").realpathSync("/bin/sh");
  assertExactNodeExecutable(shell);
  return Object.freeze({
    node: `#!/bin/sh\nexec ${posixQuote(nodeExecutable)} "$@"\n`,
    npm: `#!/bin/sh\nexec ${posixQuote(nodeExecutable)} ${posixQuote(cliPath)} "$@"\n`,
    "script-shell": "#!/bin/sh\n"
      + `PATH=${posixQuote(directory)}:${posixQuote(path.dirname(nodeExecutable))}:"$PATH"\n`
      + "export PATH\n"
      + `exec ${posixQuote(shell)} "$@"\n`,
  });
}

function withCanonicalNpmLauncher(options, callback) {
  const fs = require("fs");
  const platform = options?.platform || process.platform;
  const npm = options?.npm;
  const nodeExecutable = assertExactNodeExecutable(options?.nodeExecutable || process.execPath, {
    platform,
  });
  if (!validatedNpmProvenance.has(npm) || typeof callback !== "function") {
    throw new Error(NPM_LAUNCHER_ERROR);
  }
  const temporaryParent = exactAbsolutePath(options?.temporaryParent, NPM_LAUNCHER_ERROR);
  try {
    assertExactRealDirectory(temporaryParent, NPM_LAUNCHER_ERROR, { platform });
  } catch {
    throw new Error(NPM_LAUNCHER_ERROR);
  }
  let directory;
  let directoryIdentity;
  const expectedRootEntries = [];
  let callbackError = null;
  let cleanupError = null;
  let provenanceError = null;
  let snapshotError = null;
  let snapshotInstallation = null;
  let snapshotRoot = null;
  let result;
  try {
    directory = fs.mkdtempSync(path.join(temporaryParent, "cloudsmith-npm-launcher-"));
    directory = fs.realpathSync(directory);
    if (path.dirname(directory) !== temporaryParent
      || !path.basename(directory).startsWith("cloudsmith-npm-launcher-")) {
      throw new Error(NPM_LAUNCHER_ERROR);
    }
    if (process.platform !== "win32") fs.chmodSync(directory, 0o700);
    const rootStat = assertExactRealDirectory(directory, NPM_LAUNCHER_ERROR, { platform });
    if (typeof process.getuid === "function" && rootStat.uid !== BigInt(process.getuid())) {
      throw new Error(NPM_LAUNCHER_ERROR);
    }
    directoryIdentity = cleanupIdentity(rootStat);
    const activeNpm = revalidateCanonicalNpmProvenance(npm, { platform });
    if (activeNpm.nodeExecutable !== nodeExecutable) throw new Error(NPM_LAUNCHER_ERROR);
    snapshotRoot = path.join(directory, "npm-runtime");
    snapshotInstallation = copyCanonicalNpmInstallation(
      activeNpm.packageRoot,
      snapshotRoot,
      { expectedInstallation: activeNpm.installation, platform },
    );
    revalidateCanonicalNpmProvenance(npm, { platform });
    expectedRootEntries.push(expectedExactCleanupTreeEntry(snapshotRoot, {
      errorMessage: NPM_LAUNCHER_CLEANUP_ERROR,
    }));
    const snapshotCliPath = path.join(snapshotRoot, "bin", "npm-cli.js");
    const sources = launcherSources(nodeExecutable, snapshotCliPath, directory, platform);
    for (const [name, source] of Object.entries(sources)) {
      const target = path.join(directory, name);
      fs.writeFileSync(target, source, { encoding: "utf8", flag: "wx", mode: 0o700 });
      if (process.platform !== "win32") fs.chmodSync(target, 0o700);
      const stat = fs.lstatSync(target, { bigint: true });
      if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1n
        || stat.size !== BigInt(Buffer.byteLength(source))
        || fs.realpathSync(target) !== target
        || (typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid()))
        || (process.platform !== "win32" && (stat.mode & 0o077n) !== 0n)) {
        throw new Error(NPM_LAUNCHER_ERROR);
      }
      expectedRootEntries.push(Object.freeze({
        name,
        kind: "file",
        identity: cleanupIdentity(stat),
      }));
    }
    const launcher = Object.freeze({
      directory,
      nodeCommand: platform === "win32" ? "node.cmd" : "node",
      npmCommand: platform === "win32" ? "npm.cmd" : "npm",
      npmCliPath: snapshotCliPath,
      scriptShell: platform === "win32" ? null : path.join(directory, "script-shell"),
    });
    try {
      result = callback(launcher);
      if (result && typeof result.then === "function") throw new Error(NPM_LAUNCHER_ERROR);
    } catch (error) {
      callbackError = error;
    }
    try {
      revalidateCanonicalNpmProvenance(npm, { platform });
    } catch (error) {
      provenanceError = error;
    }
    try {
      const currentSnapshot = npmInstallationFingerprint(snapshotRoot, { platform });
      if (JSON.stringify(currentSnapshot) !== JSON.stringify(snapshotInstallation)) {
        throw new Error(NPM_LAUNCHER_ERROR);
      }
    } catch (error) {
      snapshotError = error;
    }
  } catch (error) {
    if (!callbackError) callbackError = error;
  } finally {
    if (directory) {
      if (snapshotError) {
        preserveNonAuthCleanupSubtree(directory);
      } else {
        try {
          removeExactOwnedDirectoryTree(directory, {
            errorMessage: NPM_LAUNCHER_CLEANUP_ERROR,
            expectedRootEntries,
            expectedRootIdentity: directoryIdentity,
          });
        } catch (error) {
          preserveNonAuthCleanupSubtree(directory);
          cleanupError = error;
        }
      }
    }
  }
  if (provenanceError) throw new Error(NPM_LAUNCHER_ERROR);
  if (snapshotError) throw new Error(NPM_LAUNCHER_ERROR);
  if (cleanupError) throw new Error(NPM_LAUNCHER_CLEANUP_ERROR);
  if (callbackError) throw callbackError;
  return result;
}

module.exports = {
  assertCanonicalNpmRuntime,
  assertCanonicalNodeRuntime,
  assertExactNodeExecutable,
  assertNoNpmToolchainShadowing,
  canonicalToolchainEnvironment,
  npmInstallationFingerprint,
  withCanonicalNpmLauncher,
};

// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { TextDecoder } = require("util");

const HANDOFF_FILE = "credential.handoff";
const HANDOFF_OWNER = "cloudsmith-vscode-authenticated-ci";
const MAX_HANDOFF_BYTES = 40 * 1024;
const MAX_HEADER_BYTES = 4 * 1024;
const activeHandoffs = new Map();

function assertAbsoluteRealPath(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value)
    || path.normalize(value) !== value || path.resolve(value) !== value
    || value.includes("\u0000")) {
    throw new Error(`${label} must be an absolute normalized path.`);
  }
  return value;
}

function assertPrivateDirectory(target, label, identity = null) {
  assertAbsoluteRealPath(target, label);
  const stat = fs.lstatSync(target);
  if (stat.isSymbolicLink() || !stat.isDirectory()
    || fs.realpathSync(target) !== target
    || (process.platform !== "win32" && (stat.mode & 0o077) !== 0)
    || (identity && (stat.dev !== identity.dev || stat.ino !== identity.ino))) {
    throw new Error(`${label} is not the exact private directory created for this operation.`);
  }
  return stat;
}

function assertPrivateFile(target, label, identity = null) {
  assertAbsoluteRealPath(target, label);
  const stat = fs.lstatSync(target);
  if (stat.isSymbolicLink() || !stat.isFile()
    || fs.realpathSync(target) !== target
    || (process.platform !== "win32" && (stat.mode & 0o077) !== 0)
    || (identity && (stat.dev !== identity.dev || stat.ino !== identity.ino))) {
    throw new Error(`${label} is not the exact private file created for this operation.`);
  }
  return stat;
}

function createCredentialHandoff(options = {}) {
  const temporaryParent = fs.realpathSync(options.temporaryParent || os.tmpdir());
  const parentStat = fs.lstatSync(temporaryParent);
  if (parentStat.isSymbolicLink() || !parentStat.isDirectory()) {
    throw new Error("Credential handoff parent must be a real directory.");
  }
  if (typeof options.credential !== "string") {
    throw new Error("Qualification credential is missing.");
  }
  if (options.credential.length === 0) {
    throw new Error("Qualification credential is empty.");
  }
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(options.workspace || "")) {
    throw new Error("Qualification workspace is invalid.");
  }

  const operationId = (options.randomBytes || crypto.randomBytes)(32).toString("hex");
  if (!/^[a-f0-9]{64}$/u.test(operationId)) {
    throw new Error("Credential handoff operation identity is invalid.");
  }
  const header = Object.freeze({
    schemaVersion: 1,
    owner: HANDOFF_OWNER,
    operationId,
    workspace: options.workspace,
  });
  const headerBytes = Buffer.from(`${JSON.stringify(header)}\n`, "utf8");
  const credentialBytes = Buffer.from(options.credential, "utf8");
  if (headerBytes.length > MAX_HEADER_BYTES
    || credentialBytes.length === 0
    || headerBytes.length + credentialBytes.length > MAX_HANDOFF_BYTES) {
    credentialBytes.fill(0);
    throw new Error("Credential handoff exceeds its private transport bound.");
  }

  const root = fs.mkdtempSync(path.join(temporaryParent, "cloudsmith-auth-handoff-"));
  let descriptor = null;
  try {
    if (process.platform !== "win32") fs.chmodSync(root, 0o700);
    const rootStat = assertPrivateDirectory(root, "Credential handoff root");
    const file = path.join(root, HANDOFF_FILE);
    const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL
      | (fs.constants.O_NOFOLLOW || 0);
    descriptor = fs.openSync(file, flags, 0o600);
    fs.writeFileSync(descriptor, headerBytes);
    fs.writeFileSync(descriptor, credentialBytes);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = null;
    if (process.platform !== "win32") fs.chmodSync(file, 0o600);
    const fileStat = assertPrivateFile(file, "Credential handoff file");
    if (fileStat.dev !== rootStat.dev
      || fileStat.size !== headerBytes.length + credentialBytes.length) {
      throw new Error("Credential handoff was not written atomically inside its private root.");
    }
    const capability = Object.freeze({
      schemaVersion: 1,
      owner: HANDOFF_OWNER,
      operationId,
      workspace: options.workspace,
      root,
      rootDevice: rootStat.dev,
      rootInode: rootStat.ino,
      file,
      fileDevice: fileStat.dev,
      fileInode: fileStat.ino,
      fileBytes: fileStat.size,
    });
    activeHandoffs.set(root, capability);
    return capability;
  } catch (error) {
    if (descriptor !== null) fs.closeSync(descriptor);
    fs.rmSync(root, { recursive: true, force: true });
    throw error;
  } finally {
    headerBytes.fill(0);
    credentialBytes.fill(0);
  }
}

function validateCapability(capability) {
  if (!capability || typeof capability !== "object" || Array.isArray(capability)
    || Object.keys(capability).sort().join(",") !== [
      "file", "fileBytes", "fileDevice", "fileInode", "operationId", "owner",
      "root", "rootDevice", "rootInode", "schemaVersion", "workspace",
    ].sort().join(",")
    || capability.schemaVersion !== 1
    || capability.owner !== HANDOFF_OWNER
    || !/^[a-f0-9]{64}$/u.test(capability.operationId || "")
    || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(capability.workspace || "")
    || !Number.isSafeInteger(capability.rootDevice)
    || !Number.isSafeInteger(capability.rootInode)
    || !Number.isSafeInteger(capability.fileDevice)
    || !Number.isSafeInteger(capability.fileInode)
    || !Number.isSafeInteger(capability.fileBytes)
    || capability.fileBytes <= 0 || capability.fileBytes > MAX_HANDOFF_BYTES) {
    throw new Error("Credential handoff capability is invalid.");
  }
  assertAbsoluteRealPath(capability.root, "Credential handoff root");
  assertAbsoluteRealPath(capability.file, "Credential handoff file");
  if (capability.file !== path.join(capability.root, HANDOFF_FILE)) {
    throw new Error("Credential handoff file escaped its creator-owned root.");
  }
  return capability;
}

function consumeCredentialHandoff(capability) {
  validateCapability(capability);
  const rootIdentity = { dev: capability.rootDevice, ino: capability.rootInode };
  const fileIdentity = { dev: capability.fileDevice, ino: capability.fileInode };
  const rootStat = assertPrivateDirectory(
    capability.root, "Credential handoff root", rootIdentity
  );
  const pathStat = assertPrivateFile(
    capability.file, "Credential handoff file", fileIdentity
  );
  if (pathStat.dev !== rootStat.dev || pathStat.size !== capability.fileBytes) {
    throw new Error("Credential handoff identity changed before consumption.");
  }

  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
  const descriptor = fs.openSync(capability.file, flags);
  let bytes;
  try {
    const openStat = fs.fstatSync(descriptor);
    if (!openStat.isFile() || openStat.dev !== fileIdentity.dev
      || openStat.ino !== fileIdentity.ino || openStat.size !== capability.fileBytes) {
      throw new Error("Credential handoff changed while it was opened.");
    }
    bytes = Buffer.allocUnsafe(openStat.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count === 0) throw new Error("Credential handoff ended before its declared size.");
      offset += count;
    }
  } finally {
    fs.closeSync(descriptor);
  }

  try {
    const separator = bytes.indexOf(0x0a);
    if (separator <= 0 || separator > MAX_HEADER_BYTES || separator === bytes.length - 1) {
      throw new Error("Credential handoff framing is invalid.");
    }
    let header;
    try {
      header = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, separator)));
    } catch {
      throw new Error("Credential handoff header is invalid.");
    }
    if (!header || typeof header !== "object" || Array.isArray(header)
      || Object.keys(header).sort().join(",") !== "operationId,owner,schemaVersion,workspace"
      || header.schemaVersion !== capability.schemaVersion
      || header.owner !== capability.owner
      || header.operationId !== capability.operationId
      || header.workspace !== capability.workspace) {
      throw new Error("Credential handoff does not match its creator capability.");
    }

    assertPrivateFile(capability.file, "Credential handoff file", fileIdentity);
    assertPrivateDirectory(capability.root, "Credential handoff root", rootIdentity);
    fs.unlinkSync(capability.file);
    fs.rmdirSync(capability.root);
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(separator + 1));
  } finally {
    bytes.fill(0);
  }
}

function destroyCredentialHandoff(capability) {
  validateCapability(capability);
  const registered = activeHandoffs.get(capability.root);
  if (!registered || registered.operationId !== capability.operationId
    || registered.rootDevice !== capability.rootDevice
    || registered.rootInode !== capability.rootInode) {
    throw new Error("Credential handoff cleanup refuses an unowned capability.");
  }
  let rootStat;
  try {
    rootStat = fs.lstatSync(capability.root);
  } catch (error) {
    if (error.code === "ENOENT") {
      activeHandoffs.delete(capability.root);
      return false;
    }
    throw error;
  }
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()
    || rootStat.dev !== capability.rootDevice || rootStat.ino !== capability.rootInode) {
    throw new Error("Credential handoff cleanup refuses a replaced root.");
  }
  let fileStat;
  try {
    fileStat = fs.lstatSync(capability.file);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (fileStat && (fileStat.isSymbolicLink() || !fileStat.isFile()
    || fileStat.dev !== capability.fileDevice || fileStat.ino !== capability.fileInode)) {
    throw new Error("Credential handoff cleanup refuses a replaced file.");
  }
  if (fileStat) fs.unlinkSync(capability.file);
  fs.rmdirSync(capability.root);
  activeHandoffs.delete(capability.root);
  return true;
}

module.exports = {
  HANDOFF_FILE,
  HANDOFF_OWNER,
  createCredentialHandoff,
  consumeCredentialHandoff,
  destroyCredentialHandoff,
  validateCapability,
};

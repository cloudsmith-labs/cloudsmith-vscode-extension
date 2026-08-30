// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const { digestStableSingleLinkFile, withStableSingleLinkFile } = require("./candidate-binding");

const BUNDLE_NAMES = Object.freeze([
  "evidence.json", "result.json", "ui-candidate.json", "ui-candidate.vsix",
]);
const MAX_ARCHIVE_BYTES = 16 * 1024 * 1024;
const MAX_MEMBER_BYTES = 12 * 1024 * 1024;
const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const LOCAL_SIGNATURE = 0x04034b50;

function findEndOfCentralDirectory(bytes) {
  const minimum = Math.max(0, bytes.length - 65_557);
  for (let offset = bytes.length - 22; offset >= minimum; offset -= 1) {
    if (bytes.readUInt32LE(offset) === EOCD_SIGNATURE) return offset;
  }
  throw new Error("Signed-out artifact ZIP has no bounded central directory.");
}

function parseExactZipMembers(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 22 || bytes.length > MAX_ARCHIVE_BYTES) {
    throw new Error("Signed-out artifact ZIP is empty or oversized.");
  }
  const eocd = findEndOfCentralDirectory(bytes);
  const disk = bytes.readUInt16LE(eocd + 4);
  const centralDisk = bytes.readUInt16LE(eocd + 6);
  const diskEntries = bytes.readUInt16LE(eocd + 8);
  const totalEntries = bytes.readUInt16LE(eocd + 10);
  const centralSize = bytes.readUInt32LE(eocd + 12);
  const centralOffset = bytes.readUInt32LE(eocd + 16);
  const commentLength = bytes.readUInt16LE(eocd + 20);
  if (disk !== 0 || centralDisk !== 0
    || diskEntries !== BUNDLE_NAMES.length || totalEntries !== BUNDLE_NAMES.length
    || eocd + 22 + commentLength !== bytes.length
    || centralOffset + centralSize !== eocd) {
    throw new Error("Signed-out artifact ZIP central directory is invalid.");
  }
  const entries = [];
  let cursor = centralOffset;
  for (let index = 0; index < totalEntries; index += 1) {
    if (cursor + 46 > eocd || bytes.readUInt32LE(cursor) !== CENTRAL_SIGNATURE) {
      throw new Error("Signed-out artifact ZIP entry is invalid.");
    }
    const flags = bytes.readUInt16LE(cursor + 8);
    const method = bytes.readUInt16LE(cursor + 10);
    const compressedSize = bytes.readUInt32LE(cursor + 20);
    const uncompressedSize = bytes.readUInt32LE(cursor + 24);
    const nameLength = bytes.readUInt16LE(cursor + 28);
    const extraLength = bytes.readUInt16LE(cursor + 30);
    const entryCommentLength = bytes.readUInt16LE(cursor + 32);
    const localOffset = bytes.readUInt32LE(cursor + 42);
    const end = cursor + 46 + nameLength + extraLength + entryCommentLength;
    if (end > eocd || (flags & 0x1) !== 0 || ![0, 8].includes(method)
      || compressedSize < 1 || compressedSize > MAX_ARCHIVE_BYTES
      || uncompressedSize < 1 || uncompressedSize > MAX_MEMBER_BYTES) {
      throw new Error("Signed-out artifact ZIP entry is unsafe.");
    }
    const nameBytes = bytes.subarray(cursor + 46, cursor + 46 + nameLength);
    const name = nameBytes.toString("utf8");
    if (!BUNDLE_NAMES.includes(name) || !Buffer.from(name, "utf8").equals(nameBytes)) {
      throw new Error("Signed-out artifact ZIP inventory is invalid.");
    }
    entries.push({ name, flags, method, compressedSize, uncompressedSize, localOffset });
    cursor = end;
  }
  if (cursor !== eocd
    || new Set(entries.map(entry => entry.name)).size !== BUNDLE_NAMES.length) {
    throw new Error("Signed-out artifact ZIP inventory is incomplete.");
  }
  const members = new Map();
  const ranges = [];
  for (const entry of entries) {
    const offset = entry.localOffset;
    if (offset + 30 > centralOffset || bytes.readUInt32LE(offset) !== LOCAL_SIGNATURE) {
      throw new Error("Signed-out artifact ZIP local entry is invalid.");
    }
    const localFlags = bytes.readUInt16LE(offset + 6);
    const localMethod = bytes.readUInt16LE(offset + 8);
    const localNameLength = bytes.readUInt16LE(offset + 26);
    const localExtraLength = bytes.readUInt16LE(offset + 28);
    const nameStart = offset + 30;
    const dataStart = nameStart + localNameLength + localExtraLength;
    const dataEnd = dataStart + entry.compressedSize;
    const localName = bytes.subarray(nameStart, nameStart + localNameLength).toString("utf8");
    if (localFlags !== entry.flags || localMethod !== entry.method
      || localName !== entry.name || dataEnd > centralOffset) {
      throw new Error("Signed-out artifact ZIP local entry disagrees with its directory.");
    }
    if (ranges.some(range => dataStart < range.end && dataEnd > range.start)) {
      throw new Error("Signed-out artifact ZIP entries overlap.");
    }
    ranges.push({ start: offset, end: dataEnd });
    const compressed = bytes.subarray(dataStart, dataEnd);
    const value = entry.method === 0
      ? Buffer.from(compressed)
      : zlib.inflateRawSync(compressed, { maxOutputLength: entry.uncompressedSize });
    if (value.length !== entry.uncompressedSize) {
      value.fill(0);
      throw new Error("Signed-out artifact ZIP entry size is invalid.");
    }
    members.set(entry.name, value);
  }
  return members;
}

function verifyStagedBundleMatchesArchive(options) {
  const expectedDigest = options.expectedDigest;
  const archiveProof = withStableSingleLinkFile(options.archivePath, {
    errorMessage: "Remote signed-out UI archive is unsafe or changed.",
    fileSystem: options.fileSystem,
    maximumBytes: MAX_ARCHIVE_BYTES,
    minimumBytes: 1,
  }, bytes => {
    try {
      const digest = `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
      if (digest !== expectedDigest) {
        return { error: "Remote signed-out UI archive digest does not match GitHub metadata." };
      }
      return { error: null, members: parseExactZipMembers(Buffer.from(bytes)) };
    } catch (error) {
      return { error: error.message, members: null };
    }
  });
  if (archiveProof.error) throw new Error(archiveProof.error);
  const members = archiveProof.members;
  try {
    const stat = fs.lstatSync(options.bundleRoot);
    if (!stat.isDirectory() || stat.isSymbolicLink()
      || JSON.stringify(fs.readdirSync(options.bundleRoot).sort())
        !== JSON.stringify(BUNDLE_NAMES)) {
      throw new Error("Remote signed-out UI staged inventory is invalid.");
    }
    const memberDigests = {};
    for (const name of BUNDLE_NAMES) {
      const expected = members.get(name);
      const proof = digestStableSingleLinkFile(path.join(options.bundleRoot, name), {
        errorMessage: "Remote signed-out UI staged member is unsafe or changed.",
        fileSystem: options.fileSystem,
        expectedBytes: expected.length,
        maximumBytes: MAX_MEMBER_BYTES,
        minimumBytes: 1,
      });
      const expectedSha256 = crypto.createHash("sha256").update(expected).digest("hex");
      if (proof.sha256 !== expectedSha256) {
        throw new Error("Remote signed-out UI staged member does not match the GitHub archive.");
      }
      memberDigests[name] = expectedSha256;
    }
    return Object.freeze(memberDigests);
  } finally {
    for (const value of members.values()) value.fill(0);
  }
}

module.exports = {
  BUNDLE_NAMES,
  parseExactZipMembers,
  verifyStagedBundleMatchesArchive,
};

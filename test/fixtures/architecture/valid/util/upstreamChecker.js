// Copyright 2026 Cloudsmith Ltd. All rights reserved.
class UpstreamChecker {}

function isSafeInventoryUpstream(value) {
  return Boolean(value);
}

function sanitizeSafeInventoryUpstream(value) {
  return value;
}

function getAllUpstreamData() {
  return [];
}

function getUpstreamDataForFormats() {
  return [];
}

module.exports = {
  UpstreamChecker,
  getAllUpstreamData,
  getUpstreamDataForFormats,
  isSafeInventoryUpstream,
  sanitizeSafeInventoryUpstream,
};

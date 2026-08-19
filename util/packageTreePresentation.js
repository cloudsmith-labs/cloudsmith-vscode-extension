// Copyright 2026 Cloudsmith Ltd. All rights reserved.

function buildPackageRowDescription(values = {}) {
  const parts = [];
  addPart(parts, values.version);
  addPart(parts, values.format);
  addPart(parts, values.repository);

  const status = text(values.status);
  if (status && status.toLowerCase() !== "completed") {
    addPart(parts, status);
  }
  if (values.denyPolicyViolated === true) {
    addPart(parts, "Deny policy violation");
  } else if (values.policyViolated === true) {
    addPart(parts, "Policy violation");
  }
  if (values.upstreamSource) {
    addPart(parts, "Via upstream");
  }
  return parts.join(" · ");
}

function addPart(parts, value) {
  const normalized = text(value);
  if (normalized && !parts.includes(normalized)) parts.push(normalized);
}

function text(value) {
  if (value == null) return "";
  return String(value).trim();
}

module.exports = { buildPackageRowDescription };

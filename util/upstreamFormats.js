// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const FORMAT_DEFINITIONS = Object.freeze([
  ["alpine", true],
  ["cargo", true],
  ["cocoapods", false],
  ["composer", true],
  ["conan", false],
  ["conda", true],
  ["cran", true],
  ["dart", true],
  ["deb", true],
  ["docker", true],
  ["generic", true],
  ["go", true],
  ["helm", true],
  ["hex", true],
  ["huggingface", true],
  ["luarocks", false],
  ["maven", true],
  ["npm", true],
  ["nuget", true],
  ["python", true],
  ["raw", false],
  ["rpm", true],
  ["ruby", true],
  ["swift", true],
  ["terraform", false],
  ["vagrant", false],
]);

const UPSTREAM_FORMAT_DESCRIPTORS = Object.freeze(FORMAT_DEFINITIONS.map((definition) => {
  const [format, inspectable] = definition;
  const apiFormat = inspectable ? format : null;
  return Object.freeze({
    format,
    apiFormat,
    endpoint: apiFormat ? `upstream/${apiFormat}` : null,
    inspectable,
  });
}));

const descriptorByFormat = new Map(
  UPSTREAM_FORMAT_DESCRIPTORS.map(descriptor => [descriptor.format, descriptor])
);

const SUPPORTED_UPSTREAM_FORMATS = Object.freeze(
  UPSTREAM_FORMAT_DESCRIPTORS.map(descriptor => descriptor.format)
);

const INSPECTABLE_UPSTREAM_FORMAT_DESCRIPTORS = Object.freeze(
  UPSTREAM_FORMAT_DESCRIPTORS.filter(descriptor => descriptor.inspectable)
);

const INSPECTABLE_UPSTREAM_FORMATS = Object.freeze(
  INSPECTABLE_UPSTREAM_FORMAT_DESCRIPTORS.map(descriptor => descriptor.format)
);

function normalizeUpstreamFormat(format) {
  if (typeof format !== "string") {
    return null;
  }

  const normalized = format.trim().toLowerCase();
  return descriptorByFormat.has(normalized) ? normalized : null;
}

function getUpstreamFormatDescriptor(format) {
  const normalized = normalizeUpstreamFormat(format);
  return normalized ? descriptorByFormat.get(normalized) : null;
}

function getSupportedUpstreamFormats(formats = SUPPORTED_UPSTREAM_FORMATS) {
  return getUniqueDescriptors(formats).map(descriptor => descriptor.format);
}

function getInspectableUpstreamFormatDescriptors(formats = SUPPORTED_UPSTREAM_FORMATS) {
  return getUniqueDescriptors(formats).filter(descriptor => descriptor.inspectable);
}

function getInspectableUpstreamFormats(formats = SUPPORTED_UPSTREAM_FORMATS) {
  return getInspectableUpstreamFormatDescriptors(formats).map(descriptor => descriptor.format);
}

function getUniqueDescriptors(formats) {
  if (!Array.isArray(formats)) return [];
  const descriptors = [];
  const seen = new Set();

  for (const format of formats) {
    const descriptor = getUpstreamFormatDescriptor(format);
    if (!descriptor || seen.has(descriptor.format)) continue;
    seen.add(descriptor.format);
    descriptors.push(descriptor);
  }

  return descriptors;
}

module.exports = {
  getInspectableUpstreamFormatDescriptors,
  getInspectableUpstreamFormats,
  getSupportedUpstreamFormats,
  getUpstreamFormatDescriptor,
  INSPECTABLE_UPSTREAM_FORMAT_DESCRIPTORS,
  INSPECTABLE_UPSTREAM_FORMATS,
  normalizeUpstreamFormat,
  SUPPORTED_UPSTREAM_FORMATS,
  UPSTREAM_FORMAT_DESCRIPTORS,
};

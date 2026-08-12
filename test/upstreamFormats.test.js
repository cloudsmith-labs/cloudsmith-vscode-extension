const assert = require("assert");
const {
  getInspectableUpstreamFormatDescriptors,
  getInspectableUpstreamFormats,
  getSupportedUpstreamFormats,
  getUpstreamFormatDescriptor,
  INSPECTABLE_UPSTREAM_FORMAT_DESCRIPTORS,
  INSPECTABLE_UPSTREAM_FORMATS,
  normalizeUpstreamFormat,
  SUPPORTED_UPSTREAM_FORMATS,
  UPSTREAM_FORMAT_DESCRIPTORS,
} = require("../util/upstreamFormats");

const EXPECTED_FORMATS = Object.freeze([
  "alpine", "cargo", "cocoapods", "composer", "conan", "conda", "cran", "dart",
  "deb", "docker", "generic", "go", "helm", "hex", "huggingface", "luarocks",
  "maven", "npm", "nuget", "python", "raw", "rpm", "ruby", "swift", "terraform",
  "vagrant",
]);

const EXPECTED_INSPECTABLE_FORMATS = Object.freeze([
  "alpine", "cargo", "composer", "conda", "cran", "dart", "deb", "docker", "generic",
  "go", "helm", "hex", "huggingface", "maven", "npm", "nuget", "python", "rpm",
  "ruby", "swift",
]);

const EXPECTED_NOT_APPLICABLE_FORMATS = Object.freeze([
  "cocoapods", "conan", "luarocks", "raw", "terraform", "vagrant",
]);

suite("upstream format registry", () => {
  test("recognizes every canonical package format and rejects unknown values", () => {
    assert.strictEqual(SUPPORTED_UPSTREAM_FORMATS.length, 26);
    assert.deepStrictEqual(SUPPORTED_UPSTREAM_FORMATS, EXPECTED_FORMATS);
    assert.strictEqual(UPSTREAM_FORMAT_DESCRIPTORS.length, EXPECTED_FORMATS.length);

    for (const format of EXPECTED_FORMATS) {
      assert.strictEqual(normalizeUpstreamFormat(`  ${format.toUpperCase()}  `), format);
      const descriptor = getUpstreamFormatDescriptor(format);
      assert.ok(descriptor);
      assert.strictEqual(descriptor.format, format);
    }

    for (const value of [null, undefined, "", "unknown", {}, []]) {
      assert.strictEqual(normalizeUpstreamFormat(value), null);
      assert.strictEqual(getUpstreamFormatDescriptor(value), null);
    }
  });

  test("exposes exactly twenty inspectable API formats with canonical endpoints", () => {
    assert.strictEqual(INSPECTABLE_UPSTREAM_FORMATS.length, 20);
    assert.deepStrictEqual(INSPECTABLE_UPSTREAM_FORMATS, EXPECTED_INSPECTABLE_FORMATS);
    assert.strictEqual(INSPECTABLE_UPSTREAM_FORMAT_DESCRIPTORS.length, 20);
    assert.deepStrictEqual(getInspectableUpstreamFormats(), EXPECTED_INSPECTABLE_FORMATS);

    for (const descriptor of INSPECTABLE_UPSTREAM_FORMAT_DESCRIPTORS) {
      assert.strictEqual(descriptor.inspectable, true);
      assert.strictEqual(descriptor.apiFormat, descriptor.format);
      assert.strictEqual(descriptor.endpoint, `upstream/${descriptor.apiFormat}`);
    }
  });

  test("marks six recognized formats as neutral and without an API endpoint", () => {
    const descriptors = EXPECTED_NOT_APPLICABLE_FORMATS.map(getUpstreamFormatDescriptor);

    assert.strictEqual(descriptors.length, 6);
    for (const descriptor of descriptors) {
      assert.ok(descriptor);
      assert.strictEqual(descriptor.inspectable, false);
      assert.strictEqual(descriptor.apiFormat, null);
      assert.strictEqual(descriptor.endpoint, null);
    }
  });

  test("deduplicates and canonicalizes caller-provided formats without identity drift", () => {
    const requested = [" NPM ", "npm", "COCOAPODS", "unknown", null, "Python", "python"];

    assert.deepStrictEqual(getSupportedUpstreamFormats(requested), ["npm", "cocoapods", "python"]);
    assert.deepStrictEqual(getInspectableUpstreamFormats(requested), ["npm", "python"]);
    const descriptors = getInspectableUpstreamFormatDescriptors(requested);
    assert.deepStrictEqual(descriptors.map(descriptor => descriptor.format), ["npm", "python"]);
    assert.ok(descriptors.every(descriptor => descriptor.apiFormat === descriptor.format));
    assert.deepStrictEqual(getSupportedUpstreamFormats(null), []);
    assert.deepStrictEqual(getInspectableUpstreamFormats("npm"), []);
  });

  test("freezes registry constants and canonical descriptors", () => {
    for (const value of [
      SUPPORTED_UPSTREAM_FORMATS,
      INSPECTABLE_UPSTREAM_FORMATS,
      UPSTREAM_FORMAT_DESCRIPTORS,
      INSPECTABLE_UPSTREAM_FORMAT_DESCRIPTORS,
    ]) {
      assert.strictEqual(Object.isFrozen(value), true);
    }
    assert.ok(UPSTREAM_FORMAT_DESCRIPTORS.every(Object.isFrozen));

    const npmDescriptor = getUpstreamFormatDescriptor("npm");
    assert.strictEqual(Object.isFrozen(npmDescriptor), true);
    assert.strictEqual(Reflect.set(npmDescriptor, "apiFormat", "python"), false);
    assert.strictEqual(npmDescriptor.apiFormat, "npm");
    assert.strictEqual(getUpstreamFormatDescriptor("npm"), npmDescriptor);
  });
});

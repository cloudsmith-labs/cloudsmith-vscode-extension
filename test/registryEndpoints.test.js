const assert = require("assert");
const {
  buildRegistryTriggerPlan,
  dockerDigestMatches,
  findPythonDistributionUrl,
  parseComposerDistUrl,
  parseCargoDownloadUrl,
  parseCargoIndexEntry,
  parseDartArchiveUrl,
  parseDockerManifest,
  parseNpmTarballUrl,
  parseNuGetPackageUrl,
  resolveAndValidateDockerBlobRedirectUrl,
  resolveAndValidateScopedRegistryUrl,
} = require("../util/registryEndpoints");
const { getPackageLookupKeys } = require("../util/packageNameNormalizer");

suite("registryEndpoints Test Suite", () => {
  const workspace = "workspace";
  const repository = "repo";
  const trustScope = Object.freeze({ workspace, repository });

  test("npm uses exact-version metadata routes for unscoped, hyphenated, and scoped names", () => {
    const fixtures = [
      ["left-pad", "https://npm.cloudsmith.io/workspace/repo/left-pad/1.2.3-beta.1"],
      ["package-with-hyphens", "https://npm.cloudsmith.io/workspace/repo/package-with-hyphens/1.2.3-beta.1"],
      ["@scope/widget-name", "https://npm.cloudsmith.io/workspace/repo/%40scope%2Fwidget-name/1.2.3-beta.1"],
    ];

    for (const [name, expectedUrl] of fixtures) {
      const plan = buildRegistryTriggerPlan(workspace, repository, {
        format: "npm",
        name,
        version: "1.2.3-beta.1",
      });
      assert.ok(plan);
      assert.strictEqual(plan.strategy, "npm-packument");
      assert.strictEqual(plan.packageName, name);
      assert.strictEqual(plan.request.url, expectedUrl);
      assert.match(plan.request.headers.Accept, /application\/vnd\.npm\.install-v1\+json/);
    }
  });

  test("npm selects only the exact version tarball without assuming its filename", () => {
    const plan = buildRegistryTriggerPlan(workspace, repository, {
      format: "npm",
      name: "@scope/widget-name",
      version: "1.2.3-beta.1",
    });
    const arbitraryTarball = "https://npm.cloudsmith.io/workspace/repo/@scope/widget-name/-/content-addressed-7f3a.tgz";
    const body = JSON.stringify({
      name: "@scope/widget-name",
      versions: {
        "1.2.3": {
          version: "1.2.3",
          dist: { tarball: "https://npm.cloudsmith.io/workspace/repo/wrong.tgz" },
        },
        "1.2.3-beta.1": {
          version: "1.2.3-beta.1",
          dist: { tarball: arbitraryTarball },
        },
      },
    });

    assert.strictEqual(
      parseNpmTarballUrl(
        body,
        plan.packageName,
        "1.2.3-beta.1",
        plan.request.url,
        plan.trustScope
      ),
      arbitraryTarball
    );
    assert.strictEqual(
      parseNpmTarballUrl(
        JSON.stringify({
          name: "@scope/widget-name",
          version: "1.2.3-beta.1",
          dist: { tarball: arbitraryTarball },
        }),
        plan.packageName,
        "1.2.3-beta.1",
        plan.request.url,
        plan.trustScope
      ),
      arbitraryTarball
    );
    assert.strictEqual(
      parseNpmTarballUrl(body, plan.packageName, "1.2.3-beta.2", plan.request.url, plan.trustScope),
      null
    );
    assert.strictEqual(
      parseNpmTarballUrl(
        JSON.stringify({
          version: "1.2.3-beta.1",
          dist: { tarball: arbitraryTarball },
        }),
        plan.packageName,
        "1.2.3-beta.1",
        plan.request.url,
        plan.trustScope
      ),
      null
    );
    assert.strictEqual(
      parseNpmTarballUrl(
        JSON.stringify({
          name: "@scope/widget-name",
          dist: { tarball: arbitraryTarball },
        }),
        plan.packageName,
        "1.2.3-beta.1",
        plan.request.url,
        plan.trustScope
      ),
      null
    );
  });

  test("registry plans reject deeply encoded path separators and traversal controls", () => {
    const nested = (value) => {
      let encoded = value;
      for (let depth = 0; depth < 10; depth += 1) encoded = encodeURIComponent(encoded);
      return encoded;
    };
    for (const unsafe of ["%2f", "%5c", "%3f", "%23", "%00", "%2e", "%2e%2e"].map(nested)) {
      const dependency = { format: "npm", name: "safe-package", version: "1.0.0" };
      assert.strictEqual(buildRegistryTriggerPlan(unsafe, repository, dependency), null, unsafe);
      assert.strictEqual(buildRegistryTriggerPlan(workspace, unsafe, dependency), null, unsafe);
      assert.strictEqual(buildRegistryTriggerPlan(workspace, repository, {
        ...dependency,
        name: unsafe,
      }), null, unsafe);
      assert.strictEqual(buildRegistryTriggerPlan(workspace, repository, {
        ...dependency,
        version: unsafe,
      }), null, unsafe);
    }
  });

  test("Cargo uses native 1, 2, 3, and 4+ sparse index routing", () => {
    const fixtures = [
      ["a", "1/a"],
      ["ab", "2/ab"],
      ["abc", "3/a/abc"],
      ["serde", "se/rd/serde"],
    ];
    for (const [name, expectedPath] of fixtures) {
      const plan = buildRegistryTriggerPlan(workspace, repository, {
        format: "cargo",
        name,
        version: "1.0.0",
      });
      assert.ok(plan);
      assert.strictEqual(plan.strategy, "cargo-sparse-index");
      assert.strictEqual(
        plan.request.url,
        `https://cargo.cloudsmith.io/workspace/repo/${expectedPath}`
      );
      assert.strictEqual(
        plan.configRequest.url,
        "https://cargo.cloudsmith.io/workspace/repo/config.json"
      );
    }
  });

  test("Cargo exact index metadata expands its repository-scoped download template", () => {
    const checksum = "a".repeat(64);
    const indexBody = [
      JSON.stringify({ name: "serde", vers: "1.0.199", cksum: "b".repeat(64) }),
      JSON.stringify({ name: "serde", vers: "1.0.200", cksum: checksum }),
    ].join("\n");
    const entry = parseCargoIndexEntry(indexBody, "serde", "1.0.200");
    assert.deepStrictEqual(entry, {
      name: "serde",
      version: "1.0.200",
      checksum,
      yanked: false,
    });

    const baseUrl = "https://cargo.cloudsmith.io/workspace/repo/config.json";
    const configBody = JSON.stringify({
      dl: "https://cargo.cloudsmith.io/workspace/repo/api/v1/crates/{crate}/{version}/{sha256-checksum}/download",
    });
    assert.strictEqual(
      parseCargoDownloadUrl(
        configBody,
        entry.name,
        entry.version,
        entry.checksum,
        baseUrl,
        trustScope
      ),
      `https://cargo.cloudsmith.io/workspace/repo/api/v1/crates/serde/1.0.200/${checksum}/download`
    );
  });

  test("Cargo download markers use directory prefixes and preserve crate-name case", () => {
    const checksum = "c".repeat(64);
    const configBody = JSON.stringify({
      dl: "https://cargo.cloudsmith.io/workspace/repo/downloads/{prefix}/{lowerprefix}/{crate}/{version}",
    });
    const fixtures = [
      ["a", "1/1/a"],
      ["ab", "2/2/ab"],
      ["AbC", "3/A/3/a/AbC"],
      ["MyCrate", "My/Cr/my/cr/MyCrate"],
    ];

    for (const [crateName, expectedPath] of fixtures) {
      assert.strictEqual(parseCargoDownloadUrl(
        configBody,
        crateName,
        "1.2.3",
        checksum,
        "https://cargo.cloudsmith.io/workspace/repo/config.json",
        trustScope
      ), `https://cargo.cloudsmith.io/workspace/repo/downloads/${expectedPath}/1.2.3`);
    }
  });

  test("Go, NuGet, Docker, Ruby, and Dart plans follow native coordinate rules", () => {
    assert.strictEqual(
      buildRegistryTriggerPlan(workspace, repository, {
        format: "go",
        name: "github.com/MyOrg/MyModule",
        version: "v1.2.3-RC1+BuildMeta",
      }).request.url,
      "https://golang.cloudsmith.io/workspace/repo/github.com/!my!org/!my!module/@v/v1.2.3-!r!c1%2B!build!meta.zip"
    );

    const nugetPlan = buildRegistryTriggerPlan(workspace, repository, {
        format: "nuget",
        name: "Newtonsoft.JSON",
        version: "01.02.003.0-BETA+build.7",
      });
    assert.strictEqual(
      nugetPlan.request.url,
      "https://nuget.cloudsmith.io/workspace/repo/v3/index.json"
    );
    assert.strictEqual(nugetPlan.strategy, "nuget-service-index");
    assert.strictEqual(nugetPlan.packageName, "newtonsoft.json");
    assert.strictEqual(nugetPlan.packageVersion, "1.2.3-beta");

    const dockerDigest = `sha256:${"a".repeat(64)}`;
    const dockerPlan = buildRegistryTriggerPlan(workspace, repository, {
        format: "docker",
        name: "docker.io/nginx",
        version: "stable",
        qualifiers: { digest: dockerDigest, tag: "stable" },
      });
    assert.strictEqual(
      dockerPlan.request.url,
      `https://docker.cloudsmith.io/v2/workspace/repo/library/nginx/manifests/${encodeURIComponent(dockerDigest)}`
    );
    assert.strictEqual(dockerPlan.strategy, "docker-manifest");
    assert.strictEqual(
      dockerPlan.imageBaseUrl,
      "https://docker.cloudsmith.io/v2/workspace/repo/library/nginx"
    );
    assert.strictEqual(buildRegistryTriggerPlan(workspace, repository, {
      format: "docker",
      name: "nginx",
      version: "stable",
      qualifiers: { digest: `sha256:${"a".repeat(32)}` },
    }), null);

    assert.strictEqual(
      buildRegistryTriggerPlan(workspace, repository, {
        format: "ruby",
        name: "nokogiri",
        version: "1.16.5",
        qualifiers: { platform: "x86_64-linux" },
      }).request.url,
      "https://dl.cloudsmith.io/basic/workspace/repo/ruby/gems/nokogiri-1.16.5-x86_64-linux.gem"
    );
    assert.strictEqual(
      buildRegistryTriggerPlan(workspace, repository, {
        format: "ruby",
        name: "rake",
        version: "13.2.1",
        qualifiers: { platform: "ruby" },
      }).request.url,
      "https://dl.cloudsmith.io/basic/workspace/repo/ruby/gems/rake-13.2.1.gem"
    );

    const dartPlan = buildRegistryTriggerPlan(workspace, repository, {
        format: "dart",
        name: "collection",
        version: "1.19.0",
      });
    assert.strictEqual(
      dartPlan.request.headers.Accept,
      "application/vnd.pub.v2+json"
    );
    assert.strictEqual(dartPlan.request.authScheme, "bearer");
  });

  test("NuGet resolves its exact package URL from the scoped v3 service index", () => {
    const indexUrl = "https://nuget.cloudsmith.io/workspace/repo/v3/index.json";
    const packageUrl = parseNuGetPackageUrl(JSON.stringify({
      resources: [{
        "@id": "https://nuget.cloudsmith.io/workspace/repo/v3/flat/",
        "@type": "PackageBaseAddress/3.0.0",
      }],
    }), "Newtonsoft.JSON", "01.02.003.0-BETA+build.7", indexUrl,
    trustScope);
    assert.strictEqual(
      packageUrl,
      "https://nuget.cloudsmith.io/workspace/repo/v3/flat/newtonsoft.json/1.2.3-beta/newtonsoft.json.1.2.3-beta.nupkg"
    );
    assert.strictEqual(parseNuGetPackageUrl(JSON.stringify({
      resources: [{
        "@id": "https://example.com/v3/flat/",
        "@type": "PackageBaseAddress/3.0.0",
      }],
    }), "safe", "1.0.0", indexUrl,
    trustScope), null);
  });

  test("selects a bounded Docker platform manifest and its image blobs", () => {
    const amd64Digest = `sha256:${"a".repeat(64)}`;
    const arm64Digest = `sha256:${"b".repeat(64)}`;
    assert.deepStrictEqual(parseDockerManifest(JSON.stringify({
      schemaVersion: 2,
      manifests: [
        { digest: arm64Digest, platform: { os: "linux", architecture: "arm64" } },
        { digest: amd64Digest, platform: { os: "linux", architecture: "amd64" } },
      ],
    })), { manifestDigest: amd64Digest, blobDigests: [] });
    assert.deepStrictEqual(parseDockerManifest(JSON.stringify({
      schemaVersion: 2,
      manifests: [
        { digest: amd64Digest, platform: { os: "linux", architecture: "amd64" } },
        { digest: arm64Digest, platform: { os: "linux", architecture: "arm64", variant: "v8" } },
      ],
    }), { platform: "linux/arm64/v8" }), { manifestDigest: arm64Digest, blobDigests: [] });
    assert.strictEqual(parseDockerManifest(JSON.stringify({
      schemaVersion: 2,
      manifests: [
        { digest: amd64Digest, platform: { os: "linux", architecture: "amd64" } },
      ],
    }), { platform: "linux/arm64" }), null);

    const configDigest = `sha256:${"c".repeat(64)}`;
    const layerDigest = `sha256:${"d".repeat(64)}`;
    assert.deepStrictEqual(parseDockerManifest(JSON.stringify({
      schemaVersion: 2,
      config: { digest: configDigest },
      layers: [{ digest: layerDigest }, { digest: layerDigest }],
    })), { manifestDigest: null, blobDigests: [configDigest, layerDigest] });
    assert.strictEqual(parseDockerManifest(JSON.stringify({
      schemaVersion: 2,
      config: { digest: "../invalid" },
      layers: [],
    })), null);
  });

  test("Maven preserves type and classifier in the exact artifact request", () => {
    const qualifiedPlan = buildRegistryTriggerPlan(workspace, repository, {
      format: "maven",
      name: "com.example:demo",
      version: "1.2.3",
      qualifiers: { type: "test-jar", classifier: "tests" },
    });
    assert.strictEqual(
      qualifiedPlan.request.url,
      "https://dl.cloudsmith.io/basic/workspace/repo/maven/com/example/demo/1.2.3/demo-1.2.3-tests.jar"
    );
    assert.strictEqual(qualifiedPlan.strategy, "direct");
    assert.strictEqual(qualifiedPlan.artifactRequest, undefined);
    assert.strictEqual(
      buildRegistryTriggerPlan(workspace, repository, {
        format: "maven",
        name: "com.example:bom",
        version: "1.2.3",
        qualifiers: { type: "pom" },
      }).request.url,
      "https://dl.cloudsmith.io/basic/workspace/repo/maven/com/example/bom/1.2.3/bom-1.2.3.pom"
    );
    const implicitClassifiers = [
      ["test-jar", "tests"],
      ["java-source", "sources"],
      ["javadoc", "javadoc"],
      ["ejb-client", "client"],
    ];
    for (const [type, classifier] of implicitClassifiers) {
      assert.strictEqual(
        buildRegistryTriggerPlan(workspace, repository, {
          format: "maven",
          name: "com.example:demo",
          version: "1.2.3",
          qualifiers: { type },
        }).request.url,
        `https://dl.cloudsmith.io/basic/workspace/repo/maven/com/example/demo/1.2.3/demo-1.2.3-${classifier}.jar`
      );
    }
  });

  test("Swift registry pins retain dotted scope identity in trigger coordinates", () => {
    const plan = buildRegistryTriggerPlan(workspace, repository, {
      format: "swift",
      name: "Acme.Logging",
      version: "1.2.3",
      qualifiers: { scope: "acme" },
    });

    assert.ok(plan);
    assert.strictEqual(
      plan.request.url,
      "https://dl.cloudsmith.io/basic/workspace/repo/swift/acme/logging/1.2.3.zip"
    );
    assert.strictEqual(buildRegistryTriggerPlan(workspace, repository, {
      format: "swift",
      name: "logging",
      version: "1.2.3",
    }), null);
  });

  test("Swift API lookup aliases preserve dots inside the unscoped package name", () => {
    assert.deepStrictEqual(
      getPackageLookupKeys("acme/foo.bar", "swift", { scope: "acme" }),
      ["acme/foo.bar", "foo.bar"]
    );
  });

  test("Docker manifest selection normalizes architecture aliases and implicit arm64 v8", () => {
    const amd64Digest = `sha256:${"a".repeat(64)}`;
    const arm64Digest = `sha256:${"b".repeat(64)}`;
    const body = JSON.stringify({
      schemaVersion: 2,
      manifests: [
        { digest: amd64Digest, platform: { os: "linux", architecture: "amd64" } },
        { digest: arm64Digest, platform: { os: "linux", architecture: "arm64" } },
      ],
    });

    assert.deepStrictEqual(
      parseDockerManifest(body, { platform: "linux/x86_64" }),
      { manifestDigest: amd64Digest, blobDigests: [] }
    );
    assert.deepStrictEqual(
      parseDockerManifest(body, { platform: "linux/aarch64/v8" }),
      { manifestDigest: arm64Digest, blobDigests: [] }
    );
  });

  test("bare Docker digests prove only algorithms implied by their standard length", () => {
    const sha256 = "a".repeat(64);
    const sha512 = "b".repeat(128);
    assert.strictEqual(dockerDigestMatches(sha256, `sha256:${sha256}`), true);
    assert.strictEqual(dockerDigestMatches(sha512, `sha512:${sha512}`), true);
    assert.strictEqual(dockerDigestMatches(sha256, `unknown:${sha256}`), false);
  });

  test("Dart and Composer metadata require exact package identity before selecting artifacts", () => {
    const dartBase = "https://dart.cloudsmith.io/workspace/repo/api/packages/characters";
    const dartArchive = "https://dart.cloudsmith.io/workspace/repo/api/archives/characters-1.3.0.tar.gz";
    assert.strictEqual(parseDartArchiveUrl(JSON.stringify({
      name: "other-package",
      latest: { version: "1.3.0", archive_url: dartArchive },
    }), "characters", "1.3.0", dartBase, trustScope), null);
    assert.strictEqual(parseDartArchiveUrl(JSON.stringify({
      name: "characters",
      latest: { version: "1.3.0", archive_url: dartArchive },
    }), "characters", "1.3.0", dartBase, trustScope), dartArchive);

    const composerBase = "https://composer.cloudsmith.io/workspace/repo/p2/acme/widget.json";
    const composerArchive = "https://composer.cloudsmith.io/workspace/repo/dist/acme/widget-1.2.3.zip";
    assert.strictEqual(parseComposerDistUrl(JSON.stringify({
      packages: {
        "other/widget": [{ version: "1.2.3", dist: { url: composerArchive } }],
      },
    }), "acme/widget", "1.2.3", composerBase, trustScope), null);
    assert.strictEqual(parseComposerDistUrl(JSON.stringify({
      packages: {
        "Acme/Widget": [{
          name: "acme/widget",
          version: "1.2.3",
          dist: { url: composerArchive },
        }],
      },
    }), "acme/widget", "1.2.3", composerBase, trustScope), composerArchive);
  });

  test("Python artifact discovery requires exact distribution identity and strips hash fragments", () => {
    const baseUrl = "https://dl.cloudsmith.io/basic/workspace/repo/python/simple/requests/";
    const digest = "c".repeat(64);
    const html = [
      '<a href="../../packages/evilrequests-2.31.0-py3-none-any.whl">wrong name</a>',
      `<a href="../../packages/requests-2.31.0-py3-none-any.whl#sha256=${digest}">exact</a>`,
      '<a href="../../packages/requests-2.30.0-py3-none-any.whl">wrong version</a>',
    ].join("\n");

    assert.strictEqual(
      findPythonDistributionUrl(
        html,
        "requests",
        "2.31.0",
        baseUrl,
        trustScope
      ),
      "https://dl.cloudsmith.io/basic/workspace/repo/python/packages/requests-2.31.0-py3-none-any.whl"
    );
    assert.strictEqual(
      findPythonDistributionUrl(html, "other", "2.31.0", baseUrl),
      null
    );
  });

  test("Python artifact discovery rejects the legacy version-only call shape", () => {
    const baseUrl = "https://dl.cloudsmith.io/basic/workspace/repo/python/simple/requests/";
    const html = '<a href="../../packages/evilrequests-2.31.0-py3-none-any.whl">wrong name</a>';

    assert.strictEqual(
      findPythonDistributionUrl(html, "2.31.0", baseUrl),
      null
    );
  });

  test("metadata URLs are HTTPS, allowlisted, traversal-safe, and repository scoped", () => {
    const scope = trustScope;
    const baseUrl = "https://npm.cloudsmith.io/workspace/repo/package";
    assert.strictEqual(
      resolveAndValidateScopedRegistryUrl(
        "https://dl.cloudsmith.io/basic/workspace/repo/npm/package.tgz",
        baseUrl,
        scope
      ),
      "https://dl.cloudsmith.io/basic/workspace/repo/npm/package.tgz"
    );
    assert.strictEqual(
      resolveAndValidateScopedRegistryUrl(
        "https://dl.cloudsmith.io/signed/workspace/repo/upstream/filename/npm/package.tgz",
        baseUrl,
        scope
      ),
      "https://dl.cloudsmith.io/signed/workspace/repo/upstream/filename/npm/package.tgz"
    );
    assert.strictEqual(
      resolveAndValidateScopedRegistryUrl(
        "https://npm.cloudsmith.io/workspace/repo/package.tgz?redirect=registry",
        baseUrl,
        scope,
        { allowQuery: true }
      ),
      "https://npm.cloudsmith.io/workspace/repo/package.tgz?redirect=registry"
    );

    let overEncodedTraversal = "%2e%2e";
    for (let depth = 0; depth < 10; depth += 1) {
      overEncodedTraversal = encodeURIComponent(overEncodedTraversal);
    }
    const rejected = [
      "http://npm.cloudsmith.io/workspace/repo/package.tgz",
      "https://example.com/workspace/repo/package.tgz",
      "https://npm.cloudsmith.io/workspace/other/package.tgz",
      "https://npm.cloudsmith.io/other/repo/package.tgz",
      "https://npm.cloudsmith.io/workspace/repo/package.tgz?token=secret",
      "https://npm.cloudsmith.io/workspace/repo/%252e%252e/other/package.tgz",
      "https://npm.cloudsmith.io/workspace/repo/%2525252e%2525252e/other/package.tgz",
      `https://npm.cloudsmith.io/workspace/repo/${overEncodedTraversal}/other/package.tgz`,
      `https://npm.cloudsmith.io/workspace/repo/${"x".repeat(17000)}`,
      "https://user@npm.cloudsmith.io/workspace/repo/package.tgz",
    ];
    for (const candidate of rejected) {
      assert.strictEqual(
        resolveAndValidateScopedRegistryUrl(candidate, baseUrl, scope),
        null,
        candidate
      );
    }
  });

  test("Docker blob redirects allow safe HTTPS storage URLs without widening registry trust", () => {
    const baseUrl = "https://docker.cloudsmith.io/v2/workspace/repo/library/demo/blobs/sha256%3Aabc";
    const signedUrl = "https://bucket.s3.amazonaws.com/blobs/content?signature=abc&expires=123";
    assert.strictEqual(
      resolveAndValidateDockerBlobRedirectUrl(signedUrl, baseUrl),
      signedUrl
    );
    for (const rejected of [
      "http://storage.example.com/blobs/content?signature=abc",
      "https://127.0.0.1/blobs/content",
      "https://localhost/blobs/content",
      "https://localhost./blobs/content",
      "https://metadata.google.internal./computeMetadata/v1/",
      "https://169.254.169.254.nip.io/blobs/content",
      "https://storage.example.com/blobs/content",
      "https://storage.example.com/../private/content",
      "https://user:secret@storage.example.com/blobs/content",
      "https://storage.example.com/blobs/content#fragment",
      "https://docker.cloudsmith.io/v2/workspace/other/library/demo/blobs/sha256%3Aabc",
    ]) {
      assert.strictEqual(resolveAndValidateDockerBlobRedirectUrl(rejected, baseUrl), null);
    }
  });

  test("npm metadata cannot move an authenticated artifact request across repositories", () => {
    const baseUrl = "https://npm.cloudsmith.io/workspace/repo/left-pad";
    const body = JSON.stringify({
      name: "left-pad",
      versions: {
        "1.0.0": {
          version: "1.0.0",
          dist: {
            tarball: "https://npm.cloudsmith.io/workspace/other/left-pad/-/left-pad-1.0.0.tgz",
          },
        },
      },
    });
    assert.strictEqual(
      parseNpmTarballUrl(
        body,
        "left-pad",
        "1.0.0",
        baseUrl,
        trustScope
      ),
      null
    );
  });
});

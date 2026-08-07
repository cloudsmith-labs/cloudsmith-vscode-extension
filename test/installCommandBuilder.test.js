const assert = require("assert");
const {
  InstallCommandBuilder,
  InstallCommandValidationError,
} = require("../util/installCommandBuilder");

suite("InstallCommandBuilder Test Suite", () => {

  const ws = "my-org";
  const repo = "my-repo";
  const sha256 = "a".repeat(64);

  function assertValidationError(build, field) {
    assert.throws(build, error =>
      error instanceof InstallCommandValidationError
      && (!field || error.field === field)
    );
  }

  test("python generates pip install with index-url", () => {
    const result = InstallCommandBuilder.build("python", "flask", "3.0.0", ws, repo);
    assert.strictEqual(
      result.command,
      "# Verify package details before running\npip install 'flask==3.0.0' --index-url https://dl.cloudsmith.io/basic/my-org/my-repo/python/simple/"
    );
    assert.ok(result.note);
    assert.ok(result.note.includes("basic"));
  });

  test("npm generates npm install with registry", () => {
    const result = InstallCommandBuilder.build("npm", "lodash", "4.17.21", ws, repo);
    assert.strictEqual(
      result.command,
      "# Verify package details before running\nnpm install 'lodash@4.17.21' --registry=https://npm.cloudsmith.io/my-org/my-repo/"
    );
    assert.ok(result.note);
  });

  test("maven generates pom.xml snippet with groupId:artifactId split", () => {
    const result = InstallCommandBuilder.build("maven", "org.springframework:spring-core", "5.3.20", ws, repo);
    assert.ok(result.command.includes("<groupId>org.springframework</groupId>"));
    assert.ok(result.command.includes("<artifactId>spring-core</artifactId>"));
    assert.ok(result.command.includes("<version>5.3.20</version>"));
    assert.ok(result.command.includes(`https://dl.cloudsmith.io/basic/${ws}/${repo}/maven/`));
  });

  test("maven handles name without colon", () => {
    const result = InstallCommandBuilder.build("maven", "my-artifact", "1.0.0", ws, repo);
    assert.ok(result.command.includes("<groupId>my-artifact</groupId>"));
    assert.ok(result.command.includes("<artifactId>my-artifact</artifactId>"));
  });

  test("nuget generates dotnet add package", () => {
    const result = InstallCommandBuilder.build("nuget", "Newtonsoft.Json", "13.0.3", ws, repo);
    assert.strictEqual(
      result.command,
      "# Verify package details before running\ndotnet add package 'Newtonsoft.Json' --version '13.0.3' --source https://nuget.cloudsmith.io/my-org/my-repo/v3/index.json"
    );
  });

  test("docker generates tag-based pull command", () => {
    const result = InstallCommandBuilder.build("docker", "chainguard/python", "df07729a6842572922ea04b17580ce397f141fbfb9f88265972a840f5fbc567e", ws, repo, {
      tags: {
        version: ["latest"],
      },
    });
    assert.strictEqual(
      result.command,
      "# Verify package details before running\ndocker pull docker.cloudsmith.io/my-org/my-repo/chainguard/python:latest"
    );
    assert.ok(result.note);
    assert.ok(result.note.includes("docker login"));
    assert.ok(!result.alternatives, "No alternatives without digest opts");
  });

  test("docker falls back to latest when version is empty", () => {
    const result = InstallCommandBuilder.build("docker", "nginx", "", ws, repo);
    assert.ok(result.command.includes("nginx:latest"));
  });

  test("docker includes digest alternative when checksumSha256 provided", () => {
    const result = InstallCommandBuilder.build("docker", "nginx", "digest-value", ws, repo, {
      tags: {
        version: ["1.25"],
      },
      checksumSha256: sha256,
    });
    assert.ok(result.command.includes("nginx:1.25"), "Primary is tag-based");
    assert.ok(result.alternatives, "Should have alternatives");
    assert.strictEqual(result.alternatives.length, 1);
    assert.ok(result.alternatives[0].command.includes(`nginx@sha256:${sha256}`));
    assert.ok(result.alternatives[0].label.includes("digest"));
  });

  test("docker prefers tags.version over digest-like version", () => {
    const result = InstallCommandBuilder.build("docker", "flask-app", "7d954406d981866d429fcfd1d832391a38546fdea1aa8a3ae1d4db08a9a250f2", ws, repo, {
      tags: {
        version: ["stable"],
      },
    });
    assert.ok(result.command.includes("docker pull docker.cloudsmith.io/my-org/my-repo/flask-app:stable"));
    assert.ok(!result.command.includes("'flask-app'"));
    assert.ok(!result.command.includes("'stable'"));
  });

  test("docker rejects a digest used as a tag", () => {
    assertValidationError(
      () => InstallCommandBuilder.build("docker", "flask-app", `sha256:${sha256}`, ws, repo),
      "Docker tag"
    );
  });

  test("docker uses versionDigest when checksumSha256 is unavailable", () => {
    const result = InstallCommandBuilder.build("docker", "nginx", "1.25", ws, repo, {
      versionDigest: `sha256:${sha256}`,
    });
    assert.ok(result.alternatives, "Should have digest alternative");
    assert.strictEqual(result.alternatives.length, 1);
    assert.ok(result.alternatives[0].command.includes(`nginx@sha256:${sha256}`));
  });

  test("docker has no digest alternative when checksumSha256 is missing", () => {
    const result = InstallCommandBuilder.build("docker", "nginx", "1.25", ws, repo, {});
    assert.ok(!result.alternatives, "No alternatives without checksum");
  });

  test("extractDockerTag prefers tags.version before other fields", () => {
    const tag = InstallCommandBuilder.extractDockerTag({
      tags: {
        version: ["release-1.0.0"],
      },
      docker_tag: "ignored",
    });
    assert.strictEqual(tag, "release-1.0.0");
  });

  test("extractDockerTag reads the first version tag from arrays", () => {
    const tag = InstallCommandBuilder.extractDockerTag({
      tags_raw: {
        version: ["stable", "latest"],
      },
    });
    assert.strictEqual(tag, "stable");
  });

  test("toClipboardCommand removes the verification banner only", () => {
    const command = "# Verify package details before running\ndocker pull docker.cloudsmith.io/my-org/my-repo/nginx:1.25";
    assert.strictEqual(
      InstallCommandBuilder.toClipboardCommand(command),
      "docker pull docker.cloudsmith.io/my-org/my-repo/nginx:1.25"
    );
  });

  test("docker strips trailing .sig from image names", () => {
    const result = InstallCommandBuilder.build("docker", "chainguard/python.sig", "digest-value", ws, repo, {
      tags: {
        version: ["latest"],
      },
    });
    assert.ok(result.command.includes("docker pull docker.cloudsmith.io/my-org/my-repo/chainguard/python:latest"));
    assert.ok(!result.command.includes(".sig:latest"));
  });

  test("toClipboardCommand leaves raw commands unchanged", () => {
    const command = "curl -L -O https://example.com/file.tgz";
    assert.strictEqual(InstallCommandBuilder.toClipboardCommand(command), command);
  });

  test("helm generates helm install with repo URL", () => {
    const result = InstallCommandBuilder.build("helm", "my-chart", "1.0.0", ws, repo);
    assert.strictEqual(
      result.command,
      "# Verify package details before running\nhelm install 'my-chart' --repo https://dl.cloudsmith.io/basic/my-org/my-repo/helm/charts/ --version '1.0.0'"
    );
  });

  test("cargo generates cargo add with registry note", () => {
    const result = InstallCommandBuilder.build("cargo", "serde", "1.0.0", ws, repo);
    assert.strictEqual(result.command, "# Verify package details before running\ncargo add 'serde@1.0.0'");
    assert.ok(result.note);
    assert.ok(result.note.includes(".cargo/config.toml"));
    assert.ok(result.note.includes(`cargo.cloudsmith.io/${ws}/${repo}`));
  });

  test("go generates go get with GONOSUMCHECK", () => {
    const result = InstallCommandBuilder.build("go", "github.com/gin-gonic/gin", "1.9.1", ws, repo);
    assert.strictEqual(
      result.command,
      "# Verify package details before running\nGONOSUMCHECK='github.com/gin-gonic/gin' go get 'github.com/gin-gonic/gin@v1.9.1'"
    );
    assert.ok(result.note);
    assert.ok(result.note.includes("GOPROXY"));
  });

  test("ruby generates gem install", () => {
    const result = InstallCommandBuilder.build("ruby", "rails", "7.0.0", ws, repo);
    assert.strictEqual(
      result.command,
      "# Verify package details before running\ngem install 'rails' -v '7.0.0' --source https://dl.cloudsmith.io/basic/my-org/my-repo/ruby/"
    );
  });

  test("conda generates conda install", () => {
    const result = InstallCommandBuilder.build("conda", "numpy", "1.24.0", ws, repo);
    assert.strictEqual(
      result.command,
      "# Verify package details before running\nconda install -c https://conda.cloudsmith.io/my-org/my-repo/ 'numpy=1.24.0'"
    );
    assert.strictEqual(result.note, null);
  });

  test("composer generates composer require with repo note", () => {
    const result = InstallCommandBuilder.build("composer", "vendor/package", "2.0.0", ws, repo);
    assert.strictEqual(result.command, "# Verify package details before running\ncomposer require 'vendor/package:2.0.0'");
    assert.ok(result.note);
    assert.ok(result.note.includes("composer.json"));
  });

  test("dart generates dart pub add with hosted note", () => {
    const result = InstallCommandBuilder.build("dart", "my_pkg", "1.0.0", ws, repo);
    assert.strictEqual(result.command, "# Verify package details before running\ndart pub add 'my_pkg:1.0.0'");
    assert.ok(result.note);
    assert.ok(result.note.includes("pubspec.yaml"));
  });

  test("rpm generates dnf install with yum alternative", () => {
    const result = InstallCommandBuilder.build("rpm", "httpd", "2.4.57", ws, repo);
    assert.ok(result.command.includes("dnf install"));
    assert.ok(result.command.includes("'httpd-2.4.57'"));
    assert.ok(result.note);
    assert.ok(result.note.includes("yum.repos.d"));
    assert.ok(result.alternatives);
    assert.strictEqual(result.alternatives.length, 1);
    assert.ok(result.alternatives[0].command.includes("yum install"));
    assert.ok(result.alternatives[0].command.includes("'httpd-2.4.57'"));
  });

  test("raw generates curl download with wget alternative", () => {
    const result = InstallCommandBuilder.build("raw", "myfile", "1.0.0", ws, repo, {
      cdnUrl: "https://dl.cloudsmith.io/basic/my-org/my-repo/raw/files/myfile-1.0.0.tar.gz",
    });
    assert.ok(result.command.includes("curl -L -O"));
    assert.ok(result.command.includes("https://dl.cloudsmith.io/basic/my-org/my-repo/raw/files/myfile-1.0.0.tar.gz"));
    assert.ok(result.alternatives);
    assert.strictEqual(result.alternatives.length, 1);
    assert.ok(result.alternatives[0].command.includes("wget"));
    assert.ok(result.alternatives[0].command.includes("https://dl.cloudsmith.io/basic/my-org/my-repo/raw/files/myfile-1.0.0.tar.gz"));
  });

  test("raw constructs URL when cdnUrl is missing", () => {
    const result = InstallCommandBuilder.build("raw", "myfile", "1.0.0", ws, repo, {
      filename: "myfile-1.0.0.tar.gz",
    });
    assert.ok(result.command.includes("dl.cloudsmith.io/basic/my-org/my-repo/raw/names/myfile/versions/1.0.0/myfile-1.0.0.tar.gz"));
  });

  test("raw uses name-version as filename fallback", () => {
    const result = InstallCommandBuilder.build("raw", "myfile", "1.0.0", ws, repo);
    assert.ok(result.command.includes("raw/names/myfile/versions/1.0.0/myfile-1.0.0"));
  });

  test("generic routes to raw handler", () => {
    const result = InstallCommandBuilder.build("generic", "myfile", "1.0.0", ws, repo, {
      cdnUrl: "https://dl.cloudsmith.io/basic/my-org/my-repo/generic/files/file.bin",
    });
    assert.ok(result.command.includes("curl -L -O"));
    assert.ok(result.command.includes("https://dl.cloudsmith.io/basic/my-org/my-repo/generic/files/file.bin"));
  });

  test("unknown format returns comment with link", () => {
    const result = InstallCommandBuilder.build("unknown_format", "pkg", "1.0", ws, repo);
    assert.ok(result.command.startsWith("#"));
    assert.ok(result.command.includes("unknown_format"));
    assert.ok(result.note);
    assert.ok(result.note.includes(`app.cloudsmith.com/${ws}/${repo}`));
  });

  test("all private-repo formats have a note", () => {
    const privateFormats = ["python", "npm", "maven", "nuget", "docker", "helm", "cargo", "go", "ruby", "rpm", "raw"];
    for (const fmt of privateFormats) {
      const result = InstallCommandBuilder.build(fmt, "pkg", "1.0", ws, repo);
      assert.ok(result.note, `${fmt} should have a note about private repos`);
    }
  });

  test("shell command formats reject apostrophes that differ across shell dialects", () => {
    const shellFormats = [
      "python", "npm", "nuget", "helm", "cargo", "go",
      "ruby", "conda", "composer", "dart", "rpm",
    ];
    for (const format of shellFormats) {
      assertValidationError(
        () => InstallCommandBuilder.build(format, "evil'; echo injected; '", "1.0.0", ws, repo),
        "Package name"
      );
      assertValidationError(
        () => InstallCommandBuilder.build(format, "pkg", "1.0'; echo injected; '", ws, repo),
        "Package version"
      );
    }
  });

  test("maven escapes XML-sensitive values", () => {
    const result = InstallCommandBuilder.build("maven", "group<&>:artifact\"name", "1.0<&>\"", ws, repo);
    assert.ok(result.command.includes("<groupId>group&lt;&amp;&gt;</groupId>"));
    assert.ok(result.command.includes("<artifactId>artifact&quot;name</artifactId>"));
    assert.ok(result.command.includes("<version>1.0&lt;&amp;&gt;&quot;</version>"));
  });

  test("all shell command formats quote representative shell-active metadata", () => {
    const shellFormats = [
      "python", "npm", "nuget", "helm", "cargo", "go",
      "ruby", "conda", "composer", "dart", "rpm",
    ];
    const hostileValues = [
      "pkg$(touch /tmp/proof)",
      "pkg`touch /tmp/proof`",
      "pkg; echo injected",
      "pkg | echo injected",
      "pkg && echo injected",
      "pkg || echo injected",
      "pkg & echo injected",
      'pkg"quoted',
      "pkg with spaces",
      "pkg$HOME",
      "pkg\\path",
      "pkg(foo)<bar>",
    ];

    const coordinateFor = (format, name, version) => ({
      python: `${name}==${version}`,
      npm: `${name}@${version}`,
      cargo: `${name}@${version}`,
      go: `${name}@v${version}`,
      conda: `${name}=${version}`,
      composer: `${name}:${version}`,
      dart: `${name}:${version}`,
      rpm: `${name}-${version}`,
    }[format] || name);

    for (const format of shellFormats) {
      for (const hostileValue of hostileValues) {
        const result = InstallCommandBuilder.build(format, hostileValue, "1.0.0", ws, repo);
        const clipboardCommand = InstallCommandBuilder.toClipboardCommand(result.command);
        assert.ok(
          clipboardCommand.includes(InstallCommandBuilder.shellEscape(
            coordinateFor(format, hostileValue, "1.0.0")
          )),
          `${format} should render hostile package metadata as one quoted shell argument`
        );
        assert.strictEqual(clipboardCommand.split("\n").length, 1);

        const versionResult = InstallCommandBuilder.build(format, "pkg", hostileValue, ws, repo);
        const versionClipboardCommand = InstallCommandBuilder.toClipboardCommand(versionResult.command);
        const expectedVersionArgument = ["nuget", "helm", "ruby"].includes(format)
          ? hostileValue
          : coordinateFor(format, "pkg", hostileValue);
        assert.ok(
          versionClipboardCommand.includes(InstallCommandBuilder.shellEscape(expectedVersionArgument)),
          `${format} should render hostile version metadata as one quoted shell argument`
        );
        assert.strictEqual(versionClipboardCommand.split("\n").length, 1);
      }
    }
  });

  test("all generated command formats reject newlines in package metadata", () => {
    const formats = [
      "python", "npm", "maven", "nuget", "docker", "helm", "cargo",
      "go", "ruby", "conda", "composer", "dart", "rpm", "raw", "generic",
    ];
    for (const format of formats) {
      assertValidationError(
        () => InstallCommandBuilder.build(format, "package\necho injected", "1.0.0", ws, repo),
        "Package name"
      );
    }
  });

  test("all generated command formats reject shell-active Cloudsmith slugs", () => {
    const formats = [
      "python", "npm", "maven", "nuget", "docker", "helm", "cargo",
      "go", "ruby", "conda", "composer", "dart", "rpm", "raw", "generic",
    ];
    const hostileSlugs = [
      "ws$(touch)", "ws`touch`", "ws;echo", "ws|echo", "ws&&echo", "ws||echo",
      'ws"quote', "ws'quote", "ws with spaces", "ws$HOME", "../ws", "ws\\repo", "ws\necho",
    ];
    for (const format of formats) {
      for (const hostileSlug of hostileSlugs) {
        assertValidationError(
          () => InstallCommandBuilder.build(format, "pkg", "1.0.0", hostileSlug, repo),
          "Workspace slug"
        );
      }
      assertValidationError(
        () => InstallCommandBuilder.build(format, "pkg", "1.0.0", ws, "repo;echo injected"),
        "Repository slug"
      );
    }
  });

  test("maven safely renders shell metacharacters as XML text", () => {
    const result = InstallCommandBuilder.build(
      "maven",
      "group.$(touch):artifact;echo|value",
      "1.0-$HOME&&false",
      ws,
      repo
    );
    assert.ok(result.command.includes("<groupId>group.$(touch)</groupId>"));
    assert.ok(result.command.includes("<artifactId>artifact;echo|value</artifactId>"));
    assert.ok(result.command.includes("<version>1.0-$HOME&amp;&amp;false</version>"));
  });

  test("docker rejects malformed image names including the original proof case", () => {
    const invalidNames = [
      "image; echo injected",
      "image$(touch)",
      "image`touch`",
      "Image",
      ".image",
      "image..name",
      "team//image",
      "team/image:tag",
      "team/image with spaces",
      "../image",
    ];
    for (const name of invalidNames) {
      assertValidationError(
        () => InstallCommandBuilder.build("docker", name, "latest", ws, repo),
        "Docker image name"
      );
    }
  });

  test("docker rejects malformed tags", () => {
    const invalidTags = [
      "tag;echo", "tag|echo", "tag&&echo", "tag||echo", "tag$(touch)",
      "tag`touch`", "tag with spaces", ".tag", "-tag", "tag:other", "a".repeat(129),
    ];
    for (const tag of invalidTags) {
      assertValidationError(
        () => InstallCommandBuilder.build("docker", "image", "fallback", ws, repo, {
          tags: { version: [tag] },
        }),
        "Docker tag"
      );
    }
  });

  test("docker rejects malformed digests and accepts a canonical sha256 digest", () => {
    const invalidDigests = [
      "abc123",
      "sha512:" + "a".repeat(64),
      "sha256:" + "g".repeat(64),
      "sha256:" + "a".repeat(63),
      "sha256:" + "a".repeat(64) + ";echo",
      "sha256:$(touch)",
    ];
    for (const digest of invalidDigests) {
      assertValidationError(
        () => InstallCommandBuilder.build("docker", "image", "latest", ws, repo, {
          checksumSha256: digest,
        }),
        "Docker digest"
      );
    }

    const result = InstallCommandBuilder.build("docker", "team/image", "stable", ws, repo, {
      checksumSha256: `sha256:${sha256.toUpperCase()}`,
    });
    assert.ok(result.alternatives[0].command.endsWith(`@sha256:${sha256}`));
  });

  test("raw rejects malformed, untrusted, and credential-bearing URLs", () => {
    const invalidUrls = [
      "https://example.invalid/$(touch /tmp/cloudsmith-audit-proof)",
      "http://dl.cloudsmith.io/basic/ws/repo/raw/files/file",
      "ftp://dl.cloudsmith.io/basic/ws/repo/raw/files/file",
      "https://dl.cloudsmith.io.evil.invalid/file",
      "https://evil.dl.cloudsmith.io/file",
      "https://user:password@dl.cloudsmith.io/file",
      "https://dl.cloudsmith.io/file#fragment",
      "https://dl.cloudsmith.io/file with spaces",
      "https:\\dl.cloudsmith.io\\file",
      "not a URL",
    ];
    for (const cdnUrl of invalidUrls) {
      assertValidationError(
        () => InstallCommandBuilder.build("raw", "file", "1.0.0", ws, repo, { cdnUrl }),
        "Raw download URL"
      );
    }
  });

  test("raw renders shell-active URL query data as one quoted argument", () => {
    const cdnUrl = "https://dl.cloudsmith.io/basic/ws/repo/raw/files/file"
      + "?one=$(touch)&two=`id`;three=$HOME|false&&true||false";
    const result = InstallCommandBuilder.build("raw", "file", "1.0.0", ws, repo, { cdnUrl });
    assert.strictEqual(
      InstallCommandBuilder.toClipboardCommand(result.command),
      `curl -L -O ${InstallCommandBuilder.shellEscape(cdnUrl)}`
    );
  });

  test("raw encodes package path components and rejects filename traversal", () => {
    const result = InstallCommandBuilder.build("raw", "../file $(id)", "../1.0", ws, repo);
    assert.ok(result.command.includes("..%2Ffile%20%24%28id%29"));
    assert.ok(result.command.includes("..%2F1.0"));
    assert.ok(!result.command.includes("/../"));

    for (const filename of ["../payload", "..\\payload", ".", "..", "file\nname"]) {
      assertValidationError(
        () => InstallCommandBuilder.build("raw", "file", "1.0.0", ws, repo, { filename }),
        "Raw package filename"
      );
    }
  });

  test("rejects a format that could escape the unknown-format comment", () => {
    assertValidationError(
      () => InstallCommandBuilder.build("unknown\necho injected", "pkg", "1.0", ws, repo),
      "Package format"
    );
  });
});

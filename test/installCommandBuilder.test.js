const assert = require("assert");
const { parseStringPromise } = require("xml2js");
const {
  InstallCommandBuilder,
  InstallCommandValidationError,
} = require("../util/installCommandBuilder");

suite("InstallCommandBuilder Test Suite", () => {

  const ws = "my-org";
  const repo = "my-repo";
  const sha256 = "a".repeat(64);
  const SHELL_FORMATS_FOR_OPTION_TEST = [
    "python", "npm", "nuget", "helm", "cargo", "go",
    "ruby", "conda", "composer", "dart", "rpm",
  ];

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
      "# Verify package details before running\nnpm install 'lodash@4.17.21' --save-exact --registry=https://npm.cloudsmith.io/my-org/my-repo/"
    );
    assert.ok(result.note);
  });

  test("scoped npm packages override any inherited scope registry", () => {
    const result = InstallCommandBuilder.build("npm", "@scope/package", "1.2.3", ws, repo);
    assert.match(
      result.command,
      /--@scope:registry=https:\/\/npm\.cloudsmith\.io\/my-org\/my-repo\//
    );
  });

  test("maven generates pom.xml snippet with groupId:artifactId split", () => {
    const result = InstallCommandBuilder.build("maven", "org.springframework:spring-core", "5.3.20", ws, repo);
    assert.ok(result.command.includes("<groupId>org.springframework</groupId>"));
    assert.ok(result.command.includes("<artifactId>spring-core</artifactId>"));
    assert.ok(result.command.includes("<version>5.3.20</version>"));
    assert.ok(result.command.includes(`https://dl.cloudsmith.io/basic/${ws}/${repo}/maven/`));
  });

  test("maven rejects a package without an authoritative groupId", () => {
    assertValidationError(
      () => InstallCommandBuilder.build("maven", "my-artifact", "1.0.0", ws, repo),
      "Maven package name"
    );
  });

  test("nuget generates dotnet add package", () => {
    const result = InstallCommandBuilder.build("nuget", "Newtonsoft.Json", "13.0.3", ws, repo);
    assert.strictEqual(
      result.command,
      "# Verify package details before running\ndotnet add package 'Newtonsoft.Json' --version '[13.0.3]' --source https://nuget.cloudsmith.io/my-org/my-repo/v3/index.json"
    );
  });

  test("nuget accepts a native major-only version as an exact pin", () => {
    const result = InstallCommandBuilder.build("nuget", "Widget.Core", "1", ws, repo);
    assert.match(result.command, /--version '\[1\]'/u);
  });

  test("docker prefers an authoritative package-version digest over a mutable tag", () => {
    const result = InstallCommandBuilder.build("docker", "chainguard/python", "df07729a6842572922ea04b17580ce397f141fbfb9f88265972a840f5fbc567e", ws, repo, {
      tags: {
        version: ["latest"],
      },
    });
    assert.strictEqual(
      result.command,
      "# Verify package details before running\ndocker pull docker.cloudsmith.io/my-org/my-repo/chainguard/python@sha256:df07729a6842572922ea04b17580ce397f141fbfb9f88265972a840f5fbc567e"
    );
    assert.ok(result.note);
    assert.ok(result.note.includes("docker login"));
    assert.strictEqual(result.alternatives.length, 1);
    assert.ok(result.alternatives[0].command.endsWith(":latest"));
  });

  test("docker treats a canonical empty version-tag array as no tag", () => {
    const result = InstallCommandBuilder.build(
      "docker",
      "library/alpine",
      sha256,
      ws,
      repo,
      {
        tags: {
          info: ["upstream"],
          version: [],
        },
      }
    );

    assert.strictEqual(
      result.command,
      `# Verify package details before running\ndocker pull docker.cloudsmith.io/${ws}/${repo}/library/alpine@sha256:${sha256}`
    );
    assert.ok(!result.alternatives);
  });

  test("docker falls back to latest when version is empty", () => {
    const result = InstallCommandBuilder.build("docker", "nginx", "", ws, repo);
    assert.ok(result.command.includes("nginx:latest"));
  });

  test("docker never treats a generic artifact checksum as an OCI manifest digest", () => {
    const result = InstallCommandBuilder.build("docker", "nginx", "digest-value", ws, repo, {
      tags: {
        version: ["1.25"],
      },
      checksumSha256: sha256,
    });
    assert.ok(result.command.includes("nginx:1.25"));
    assert.ok(!result.alternatives);
    assert.doesNotMatch(result.command, /@sha256:/);
  });

  test("docker prefers tags.version over digest-like version", () => {
    const result = InstallCommandBuilder.build("docker", "flask-app", "7d954406d981866d429fcfd1d832391a38546fdea1aa8a3ae1d4db08a9a250f2", ws, repo, {
      tags: {
        version: ["stable"],
      },
    });
    assert.ok(result.command.includes("docker pull docker.cloudsmith.io/my-org/my-repo/flask-app@sha256:7d954406d981866d429fcfd1d832391a38546fdea1aa8a3ae1d4db08a9a250f2"));
    assert.ok(result.alternatives[0].command.endsWith(":stable"));
    assert.ok(!result.command.includes("'flask-app'"));
    assert.ok(!result.command.includes("'stable'"));
  });

  test("docker does not fabricate a digest-shaped tag alternative", () => {
    const digest = "b".repeat(64);
    const result = InstallCommandBuilder.build("docker", "nginx", digest, ws, repo);
    assert.match(result.command, new RegExp(`@sha256:${digest}$`));
    assert.ok(!result.alternatives);
  });

  test("docker recognizes a canonical qualified digest version", () => {
    const result = InstallCommandBuilder.build(
      "docker", "flask-app", `sha256:${sha256}`, ws, repo
    );
    assert.match(result.command, new RegExp(`@sha256:${sha256}$`));
    assert.ok(!result.alternatives);
  });

  test("docker uses only an explicit native digest qualifier for a non-digest version", () => {
    const ignored = InstallCommandBuilder.build("docker", "nginx", "1.25", ws, repo, {
      versionDigest: `sha256:${sha256}`,
    });
    const exact = InstallCommandBuilder.build("docker", "nginx", "1.25", ws, repo, {
      qualifiers: { digest: `sha256:${sha256}` },
    });
    assert.doesNotMatch(ignored.command, /@sha256:/);
    assert.match(exact.command, new RegExp(`@sha256:${sha256}$`));
    assert.ok(!exact.alternatives, "A version is not fabricated into an OCI tag");
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

  test("helm supplies both release-name semantics and the selected chart repository", () => {
    const result = InstallCommandBuilder.build("helm", "my-chart", "1.0.0", ws, repo);
    assert.strictEqual(
      result.command,
      "# Verify package details before running\n"
        + "helm install --generate-name 'my-chart' "
        + "--repo https://dl.cloudsmith.io/basic/my-org/my-repo/helm/charts/ "
        + "--version '1.0.0'"
    );
  });

  test("package-manager locators cannot bypass the selected Cloudsmith repository", () => {
    const rejected = [
      ["python", "pkg @ https://evil.example/pkg.whl", "1.2.3", "Python package name"],
      ["python", "pkg", "https://evil.example/pkg.whl", "Python package version"],
      ["npm", "lodash@https://evil.example/pkg.tgz", "1.2.3", "npm package name"],
      ["npm", "lodash", "https://evil.example/pkg.tgz", "npm package version"],
      ["npm", "npm:other", "1.2.3", "npm package name"],
      ["helm", "https://evil.example/chart.tgz", "1.2.3", "Helm chart name"],
      ["helm", "./local-chart", "1.2.3", "Helm chart name"],
      ["helm", "chart", "file:///tmp/chart", "Helm chart version"],
      ["cargo", "https://evil.example/crate", "1.2.3", "Cargo package name"],
      ["cargo", "crate", "git+https://evil.example/crate", "Cargo package version"],
      ["ruby", "./payload.gem", "1.2.3", "Ruby gem name"],
      ["ruby", "rack", "file:///tmp/payload.gem", "Ruby gem version"],
      ["composer", "https://evil.example/package", "1.2.3", "Composer package name"],
      ["composer", "vendor/package", "https://evil.example/package", "Composer package version"],
      ["dart", "dev:foo", "1.2.3", "Dart package name"],
      ["dart", "foo", "{git: https://evil.example/repo}", "Dart package version"],
    ];

    for (const [format, name, version, field] of rejected) {
      assertValidationError(
        () => InstallCommandBuilder.build(format, name, version, ws, repo),
        field
      );
    }
  });

  test("Ruby installs are remote-only even when a gem-like name is selected", () => {
    const result = InstallCommandBuilder.build("ruby", "payload.gem", "1.2.3", ws, repo);
    assert.match(result.command, /gem install 'payload\.gem' -v '1\.2\.3' --remote /u);
    assert.match(result.command, /--clear-sources --source https:\/\/dl\.cloudsmith\.io\/basic\//u);
  });

  test("cargo generates a repository-targeted cargo add with matching registry setup", () => {
    const result = InstallCommandBuilder.build("cargo", "serde", "1.0.0", ws, repo);
    assert.strictEqual(
      result.command,
      "# Verify package details before running\n"
        + "cargo add 'serde@=1.0.0' --registry 'cloudsmith-my-org-my-repo-54fab955da83'"
    );
    assert.ok(result.note);
    assert.ok(result.note.includes(".cargo/config.toml"));
    assert.ok(result.note.includes(`cargo.cloudsmith.io/${ws}/${repo}`));
  });

  test("cargo executable command explicitly selects the configured Cloudsmith registry", () => {
    const result = InstallCommandBuilder.build("cargo", "serde", "1.0.0", ws, repo);
    const command = InstallCommandBuilder.toClipboardCommand(result.command);

    assert.match(command, /^cargo add 'serde@=1\.0\.0' --registry '[A-Za-z0-9_-]+'$/);
    const registry = command.match(/--registry '([^']+)'$/)[1];
    assert.ok(result.note.split("\n").includes(`[registries.${registry}]`));
    assert.ok(result.note.includes("sparse+https://cargo.cloudsmith.io/my-org/my-repo/"));
  });

  test("cargo registry aliases cannot collide when Cloudsmith slugs normalize differently", () => {
    const dotted = InstallCommandBuilder.build("cargo", "serde", "1.0.0", "my.org", repo);
    const dashed = InstallCommandBuilder.build("cargo", "serde", "1.0.0", "my-org", repo);
    const uppercase = InstallCommandBuilder.build("cargo", "serde", "1.0.0", "My-Org", repo);
    const leftBoundary = InstallCommandBuilder.build("cargo", "serde", "1.0.0", "a-b", "c");
    const rightBoundary = InstallCommandBuilder.build("cargo", "serde", "1.0.0", "a", "b-c");
    const registry = result => result.command.match(/--registry '([^']+)'$/)[1];

    assert.notStrictEqual(registry(dotted), registry(dashed));
    assert.notStrictEqual(registry(uppercase), registry(dashed));
    assert.notStrictEqual(registry(leftBoundary), registry(rightBoundary));
    assert.ok(dotted.note.split("\n").includes(`[registries.${registry(dotted)}]`));
    assert.ok(dashed.note.split("\n").includes(`[registries.${registry(dashed)}]`));
  });

  test("go generates a repository-targeted go get with valid Go environment semantics", () => {
    const result = InstallCommandBuilder.build("go", "github.com/gin-gonic/gin", "1.9.1", ws, repo);
    assert.strictEqual(
      result.command,
      "# Verify package details before running\n"
        + "GOPROXY='https://golang.cloudsmith.io/my-org/my-repo/' GONOPROXY='none' "
        + "go get 'github.com/gin-gonic/gin@v1.9.1'"
    );
    assert.ok(result.note);
    assert.ok(result.note.includes("GONOSUMDB"));
    assert.deepStrictEqual(result.alternatives.map(value => value.label), [
      "PowerShell",
      "Command Prompt",
    ]);
    assert.match(result.alternatives[0].command, /\$env:GOPROXY=/);
    assert.match(result.alternatives[0].command, /\$env:GONOPROXY='none'/);
    assert.match(result.alternatives[0].command, /try \{.*GOPROXY=.*;.*GONOPROXY=.*; go get/);
    assert.match(result.alternatives[0].command, /finally \{/);
    assert.match(result.alternatives[0].command, /Remove-Item Env:GOPROXY/);
    assert.strictEqual(
      result.alternatives[1].command,
      "# Verify package details before running\n"
        + "cmd.exe /D /V:OFF /C \"set GOPROXY=https://golang.cloudsmith.io/my-org/my-repo/"
        + "&& set GONOPROXY=none&& go get github.com/gin-gonic/gin@v1.9.1\""
    );
    assert.doesNotMatch(result.alternatives[1].command, /,direct|\|direct/u);
  });

  test("go executable command routes the exact module through the selected Cloudsmith proxy", () => {
    const result = InstallCommandBuilder.build("go", "github.com/gin-gonic/gin", "1.9.1", ws, repo);
    const command = InstallCommandBuilder.toClipboardCommand(result.command);

    assert.strictEqual(
      command,
      "GOPROXY='https://golang.cloudsmith.io/my-org/my-repo/' GONOPROXY='none' go get 'github.com/gin-gonic/gin@v1.9.1'"
    );
    assert.doesNotMatch(`${result.command}\n${result.note || ""}`, /GONOSUMCHECK/);
  });

  test("maven preserves group, artifact, type, and classifier as parseable XML fields", async () => {
    const result = InstallCommandBuilder.build(
      "maven",
      "com.example:demo",
      "1.2.3",
      ws,
      repo,
      { qualifiers: { type: "test-jar", classifier: "tests", scope: "test" } }
    );

    assert.match(result.command, /<groupId>com\.example<\/groupId>/);
    assert.match(result.command, /<artifactId>demo<\/artifactId>/);
    assert.match(result.command, /<version>1\.2\.3<\/version>/);
    assert.match(result.command, /<type>test-jar<\/type>/);
    assert.match(result.command, /<classifier>tests<\/classifier>/);
    assert.match(result.command, /<scope>test<\/scope>/);
    assert.match(result.command, /<mirrorOf>\*<\/mirrorOf>/);
    assert.match(result.command, /cloudsmith-my-org-my-repo-[a-f0-9]{12}/);
    const otherWorkspace = InstallCommandBuilder.build(
      "maven",
      "com.example:demo",
      "1.2.3",
      "other-org",
      repo
    );
    const id = value => value.command.match(/<id>(cloudsmith-[^<]+)<\/id>/)[1];
    assert.notStrictEqual(id(result), id(otherWorkspace));
    assert.strictEqual(result.language, "markdown");
    assert.match(result.command, /^# Maven package setup/m);
    assert.match(result.command, /## `~\/\.m2\/settings\.xml`/);
    assert.match(result.command, /## `pom\.xml`/);

    const xmlBlocks = [...result.command.matchAll(/```xml\n([\s\S]*?)\n```/gu)]
      .map(match => match[1]);
    assert.strictEqual(xmlBlocks.length, 2);
    const [settingsDocument, dependencyDocument] = await Promise.all(
      xmlBlocks.map(xml => parseStringPromise(xml, {
        explicitArray: false,
        strict: true,
        trim: false,
      }))
    );
    assert.deepStrictEqual({ ...settingsDocument.settings.mirrors.mirror }, {
      id: result.command.match(/<id>(cloudsmith-[^<]+)<\/id>/u)[1],
      url: "https://dl.cloudsmith.io/basic/my-org/my-repo/maven/",
      mirrorOf: "*",
    });
    assert.deepStrictEqual({ ...dependencyDocument.dependency }, {
      groupId: "com.example",
      artifactId: "demo",
      version: "1.2.3",
      type: "test-jar",
      classifier: "tests",
      scope: "test",
    });
  });

  test("go preserves exactly one leading v in install coordinates", () => {
    const result = InstallCommandBuilder.build(
      "go", "github.com/gin-gonic/gin", "v1.9.1", "my-org", "my-repo"
    );
    assert.match(result.command, /github\.com\/gin-gonic\/gin@v1\.9\.1/);
    assert.doesNotMatch(result.command, /@vv/);
  });

  test("ruby generates gem install", () => {
    const result = InstallCommandBuilder.build("ruby", "rails", "7.0.0", ws, repo);
    assert.strictEqual(
      result.command,
      "# Verify package details before running\n"
        + "gem install 'rails' -v '7.0.0' --remote --clear-sources "
        + "--source https://dl.cloudsmith.io/basic/my-org/my-repo/ruby/"
    );
  });

  test("ruby preserves an authoritative platform qualifier", () => {
    const result = InstallCommandBuilder.build("ruby", "nokogiri", "1.18.0", ws, repo, {
      qualifiers: { platform: "x86_64-linux" },
    });
    assert.match(result.command, /--platform 'x86_64-linux'/);
  });

  test("conda generates an exact build/subdir MatchSpec", () => {
    const result = InstallCommandBuilder.build("conda", "numpy", "1.24.0", ws, repo, {
      qualifiers: { build: "py311h123_0", subdir: "linux-64" },
    });
    assert.strictEqual(
      result.command,
      "# Verify package details before running\n"
        + "conda install --override-channels -c https://conda.cloudsmith.io/my-org/my-repo/ "
        + "'numpy==1.24.0=py311h123_0[subdir=linux-64]'"
    );
    assert.match(result.note, /private repositories/);
  });

  test("conda rejects version-only identity with multiple possible builds or subdirs", () => {
    assertValidationError(
      () => InstallCommandBuilder.build("conda", "numpy", "1.24.0", ws, repo),
      "Conda qualifiers"
    );
  });

  test("conda preserves exact build and subdir qualifiers", () => {
    const result = InstallCommandBuilder.build("conda", "numpy", "1.24.0", ws, repo, {
      qualifiers: { build: "py311h123_0", subdir: "linux-64" },
    });
    assert.doesNotMatch(result.command, /--platform/u);
    assert.match(result.command, /'numpy==1\.24\.0=py311h123_0\[subdir=linux-64\]'/);
  });

  test("composer configures the selected repository before requiring the package", () => {
    const result = InstallCommandBuilder.build("composer", "vendor/package", "2.0.0", ws, repo);
    assert.strictEqual(
      result.command,
      "# Verify package details before running\n"
        + "composer config repositories.packagist.org false && "
        + "composer config repositories.cloudsmith composer "
        + "'https://composer.cloudsmith.io/my-org/my-repo/' "
        + "&& composer require 'vendor/package:2.0.0'"
    );
    assert.ok(result.note);
    assert.ok(result.note.includes("authentication"));
    assert.strictEqual(result.alternatives[0].label, "PowerShell");
    assert.doesNotMatch(result.alternatives[0].command, /&&/);
  });

  test("every secondary command preserves its selected Cloudsmith target and native identity", () => {
    const go = InstallCommandBuilder.build(
      "go",
      "github.com/gin-gonic/gin",
      "1.9.1",
      ws,
      repo
    );
    const goProxyUrl = "https://golang.cloudsmith.io/my-org/my-repo/";
    for (const variant of [go.command, ...go.alternatives.map(item => item.command)]) {
      assert.ok(
        variant.includes(`GOPROXY='${goProxyUrl}'`)
          || variant.includes(`set GOPROXY=${goProxyUrl}&&`)
      );
      assert.match(variant, /github\.com\/gin-gonic\/gin@v1\.9\.1/u);
      assert.match(variant, /GONOPROXY(?:=|=')none/u);
      assert.doesNotMatch(variant, /proxy\.golang\.org|,direct|\|direct|GONOSUMCHECK/u);
    }

    const composer = InstallCommandBuilder.build(
      "composer",
      "vendor/package",
      "2.0.0",
      ws,
      repo
    );
    assert.strictEqual(
      composer.command,
      "# Verify package details before running\n"
        + "composer config repositories.packagist.org false && "
        + "composer config repositories.cloudsmith composer "
        + "'https://composer.cloudsmith.io/my-org/my-repo/' "
        + "&& composer require 'vendor/package:2.0.0'"
    );
    assert.deepStrictEqual(composer.alternatives, [{
      label: "PowerShell",
      command: "# Verify package details before running\n"
        + "composer config repositories.packagist.org false; "
        + "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; "
        + "composer config repositories.cloudsmith composer "
        + "'https://composer.cloudsmith.io/my-org/my-repo/'; "
        + "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; "
        + "composer require 'vendor/package:2.0.0'",
    }]);

    const rpm = InstallCommandBuilder.build("rpm", "httpd", "2.4.57", ws, repo, {
      qualifiers: { epoch: "1", release: "8.el9", architecture: "x86_64" },
    });
    for (const variant of [rpm.command, ...rpm.alternatives.map(item => item.command)]) {
      assert.match(variant, /httpd-1:2\.4\.57-8\.el9\.x86_64/u);
      assert.match(variant, /--disablerepo='\*'/u);
      assert.match(variant, /--enablerepo='my-org-my-repo'/u);
    }

    const docker = InstallCommandBuilder.build("docker", "team/image", sha256, ws, repo, {
      tags: { version: ["stable"] },
    });
    const dockerRepository = "docker.cloudsmith.io/my-org/my-repo/team/image";
    assert.strictEqual(
      docker.command,
      `# Verify package details before running\ndocker pull ${dockerRepository}@sha256:${sha256}`
    );
    assert.deepStrictEqual(docker.alternatives, [{
      label: "Pull by tag",
      command: `# Verify package details before running\ndocker pull ${dockerRepository}:stable`,
    }]);
  });

  test("dart targets the selected hosted repository on the executable command", () => {
    const result = InstallCommandBuilder.build("dart", "my_pkg", "1.0.0", ws, repo);
    assert.strictEqual(
      result.command,
      "# Verify package details before running\n"
        + "dart pub add 'my_pkg:1.0.0' "
        + "--hosted 'https://dart.cloudsmith.io/my-org/my-repo/'"
    );
    assert.ok(result.note);
    assert.ok(result.note.includes("dart pub token add"));
  });

  test("rpm preserves NEVRA and selects the configured Cloudsmith repository", () => {
    const result = InstallCommandBuilder.build("rpm", "httpd", "2.4.57", ws, repo, {
      qualifiers: { epoch: "1", release: "8.el9", architecture: "x86_64" },
    });
    assert.ok(result.command.includes("dnf install-nevra"));
    assert.ok(result.command.includes("'httpd-1:2.4.57-8.el9.x86_64'"));
    assert.ok(result.command.includes("--disablerepo='*'"));
    assert.ok(result.command.includes("--enablerepo='my-org-my-repo'"));
    assert.ok(result.note);
    assert.ok(result.note.includes("cfg/setup/bash.rpm.sh"));
    assert.ok(result.alternatives);
    assert.strictEqual(result.alternatives.length, 1);
    assert.ok(result.alternatives[0].command.includes("yum install"));
    assert.ok(result.alternatives[0].command.includes("'httpd-1:2.4.57-8.el9.x86_64'"));
  });

  test("rpm rejects incomplete native identity instead of fabricating a NEVRA", () => {
    assertValidationError(
      () => InstallCommandBuilder.build("rpm", "httpd", "2.4.57", ws, repo),
      "RPM qualifiers"
    );
  });

  test("rpm accepts caret ordering in EVR and requires a numeric epoch", () => {
    const result = InstallCommandBuilder.build("rpm", "httpd", "2.4.57", ws, repo, {
      qualifiers: { epoch: "1", release: "8^git.el9", architecture: "x86_64" },
    });
    assert.match(result.command, /httpd-1:2\.4\.57-8\^git\.el9\.x86_64/);
    assertValidationError(
      () => InstallCommandBuilder.build("rpm", "httpd", "2.4.57", ws, repo, {
        qualifiers: { epoch: "latest", release: "8.el9", architecture: "x86_64" },
      }),
      "RPM epoch"
    );
  });

  test("rpm nativeVersion cannot replace the authoritative API version", () => {
    for (const version of ["1.0", "1.0-1"]) {
      assertValidationError(
        () => InstallCommandBuilder.build("rpm", "httpd", version, ws, repo, {
          qualifiers: {
            nativeVersion: "9.9",
            release: "1",
            architecture: "x86_64",
          },
        }),
        "RPM native version"
      );
    }
  });

  test("raw generates curl download with wget alternative", () => {
    const result = InstallCommandBuilder.build("raw", "myfile", "1.0.0", ws, repo, {
      cdnUrl: "https://dl.cloudsmith.io/basic/my-org/my-repo/raw/files/myfile-1.0.0.tar.gz",
    });
    assert.ok(result.command.includes("curl -fL -O"));
    assert.ok(result.command.includes("--proto '=https'"));
    assert.ok(result.command.includes("--proto-redir '=https'"));
    assert.ok(result.command.includes("https://dl.cloudsmith.io/basic/my-org/my-repo/raw/files/myfile-1.0.0.tar.gz"));
    assert.ok(result.alternatives);
    assert.strictEqual(result.alternatives.length, 1);
    assert.ok(result.alternatives[0].command.includes("wget"));
    assert.ok(result.alternatives[0].command.includes("--https-only"));
    assert.ok(result.alternatives[0].command.includes("https://dl.cloudsmith.io/basic/my-org/my-repo/raw/files/myfile-1.0.0.tar.gz"));
    assert.doesNotMatch(result.note, /authentication headers?/iu);
  });

  test("raw requires an authoritative URL rather than fabricating one URL shape", () => {
    assertValidationError(
      () => InstallCommandBuilder.build("raw", "myfile", "1.0.0", ws, repo),
      "Raw download URL"
    );
  });

  test("generic routes to raw handler", () => {
    const result = InstallCommandBuilder.build("generic", "myfile", "1.0.0", ws, repo, {
      cdnUrl: "https://dl.cloudsmith.io/basic/my-org/my-repo/generic/files/file.bin",
    });
    assert.ok(result.command.includes("curl -fL -O"));
    assert.ok(result.command.includes("https://dl.cloudsmith.io/basic/my-org/my-repo/generic/files/file.bin"));
  });

  test("generic requires an authoritative scoped CDN URL", () => {
    assertValidationError(
      () => InstallCommandBuilder.build("generic", "myfile", "1.0.0", ws, repo),
      "Generic download URL"
    );
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
      const name = fmt === "maven" ? "example:pkg" : "pkg";
      const options = fmt === "rpm"
        ? { qualifiers: { release: "1", architecture: "x86_64" } }
        : fmt === "raw"
          ? { cdnUrl: "https://dl.cloudsmith.io/basic/my-org/my-repo/raw/files/pkg" }
        : undefined;
      const version = ["npm", "helm", "cargo", "go"].includes(fmt) ? "1.0.0" : "1.0";
      const result = InstallCommandBuilder.build(fmt, name, version, ws, repo, options);
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

  test("maven rejects interpolation and non-native coordinate metadata", () => {
    const rejected = [
      ["group.${env.SECRET}:artifact", "1.0.0", undefined, "Maven groupId"],
      ["group:artifact${project.version}", "1.0.0", undefined, "Maven artifactId"],
      ["group:artifact", "${env.SECRET}", undefined, "Maven version"],
      ["group:artifact", "1.0.0", { type: "${env.TYPE}" }, "Maven type"],
      ["group:artifact", "1.0.0", { classifier: "../../local" }, "Maven classifier"],
      ["group:artifact", "1.0.0", { scope: "${env.SCOPE}" }, "Maven scope"],
      ["group:artifact", "1.0.0", { scope: "attacker" }, "Maven scope"],
    ];

    for (const [name, version, qualifiers, field] of rejected) {
      assertValidationError(
        () => InstallCommandBuilder.build(
          "maven", name, version, ws, repo, qualifiers ? { qualifiers } : undefined
        ),
        field
      );
    }
  });

  test("all shell command formats reject non-native shell-active metadata", () => {
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

    const nativeFields = {
      python: ["Python package name", "Python package version"],
      npm: ["npm package name", "npm package version"],
      nuget: ["NuGet package name", "NuGet package version"],
      helm: ["Helm chart name", "Helm chart version"],
      cargo: ["Cargo package name", "Cargo package version"],
      go: ["Go module path", "Go module version"],
      ruby: ["Ruby gem name", "Ruby gem version"],
      conda: ["Conda package name", "Conda package version"],
      composer: ["Composer package name", "Composer package version"],
      dart: ["Dart package name", "Dart package version"],
      rpm: ["RPM package name", "RPM version"],
    };
    const validNameForVersion = {
      composer: "vendor/pkg",
    };

    for (const format of shellFormats) {
      for (const hostileValue of hostileValues) {
        const options = format === "conda"
          ? { qualifiers: { build: "build_0", subdir: "linux-64" } }
          : format === "rpm"
            ? { qualifiers: { release: "1", architecture: "x86_64" } }
            : undefined;
        assertValidationError(
          () => InstallCommandBuilder.build(
            format, hostileValue, "1.0.0", ws, repo, options
          ),
          nativeFields[format][0]
        );
        assertValidationError(
          () => InstallCommandBuilder.build(
            format, validNameForVersion[format] || "pkg", hostileValue, ws, repo, options
          ),
          nativeFields[format][1]
        );
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

  test("shell package identities reject package-manager option injection", () => {
    for (const format of SHELL_FORMATS_FOR_OPTION_TEST) {
      assertValidationError(
        () => InstallCommandBuilder.build(format, "--config=attacker", "1.0.0", ws, repo),
        "Package name"
      );
      assertValidationError(
        () => InstallCommandBuilder.build(format, "pkg", "--config=attacker", ws, repo),
        "Package version"
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

  test("docker rejects mixed version-tag arrays unless every entry is valid", () => {
    const sparse = ["stable"];
    sparse.length = 2;
    const invalidArrays = [
      ["stable", "bad tag"],
      ["bad tag", "stable"],
      ["", "stable"],
      ["stable", ""],
      ["stable", 42],
      [42, "stable"],
      sparse,
    ];

    for (const field of ["tags", "tags_raw"]) {
      for (const version of invalidArrays) {
        assertValidationError(
          () => InstallCommandBuilder.build("docker", "image", sha256, ws, repo, {
            [field]: { version },
          }),
          "Docker tag"
        );
      }
    }
  });

  test("docker rejects malformed native digest qualifiers and ignores artifact checksums", () => {
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
          qualifiers: { digest },
        }),
        "Docker digest"
      );
    }

    const result = InstallCommandBuilder.build("docker", "team/image", "stable", ws, repo, {
      checksumSha256: `sha256:${sha256.toUpperCase()}`,
    });
    assert.doesNotMatch(result.command, /@sha256:/);
    assert.ok(!result.alternatives);
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
      "https://dl.cloudsmith.io/file'name",
      "https:\\dl.cloudsmith.io\\file",
      "https://dl.cloudsmith.io/basic/other-org/my-repo/raw/files/file",
      "https://dl.cloudsmith.io/basic/my-org/other-repo/raw/files/file",
      "https://dl.cloudsmith.io/secret-entitlement/my-org/my-repo/raw/files/file",
      "https://dl.cloudsmith.io/basic/my-org/my-repo/npm/files/file",
      "https://dl.cloudsmith.io/basic/my-org/my-repo/raw/files/file?token=secret",
      "https://dl.cloudsmith.io/basic/my-org/my-repo/raw/files/../evil",
      "https://dl.cloudsmith.io/basic/my-org/my-repo/raw/files/%2e/evil",
      "https://dl.cloudsmith.io/basic/my-org/my-repo/raw/files/%2e%2e/evil",
      "https://dl.cloudsmith.io/basic/my-org/my-repo/raw/files/%2Fother-repo",
      "https://dl.cloudsmith.io/basic/my-org/my-repo/raw/files/%252e%252e%252fother-repo",
      `https://dl.cloudsmith.io/basic/my-org/my-repo/raw/files/${"a".repeat(8193)}`,
      "not a URL",
    ];
    for (const cdnUrl of invalidUrls) {
      assertValidationError(
        () => InstallCommandBuilder.build("raw", "file", "1.0.0", ws, repo, { cdnUrl }),
        "Raw download URL"
      );
    }
  });

  test("raw accepts a credential-free CDN URL only in the selected repository scope", () => {
    const cdnUrl = "https://dl.cloudsmith.io/basic/my-org/my-repo/raw/files/"
      + "file%20with%20spaces.tar.gz";
    const result = InstallCommandBuilder.build("raw", "file", "1.0.0", ws, repo, { cdnUrl });
    assert.strictEqual(
      InstallCommandBuilder.toClipboardCommand(result.command),
      `curl -fL -O --no-clobber --proto '=https' --proto-redir '=https' ${InstallCommandBuilder.shellEscape(cdnUrl)}`
    );
  });

  test("raw authentication notes match basic, public, and generic URL shapes", () => {
    const basic = InstallCommandBuilder.build("raw", "file", "1.0.0", ws, repo, {
      cdnUrl: "https://dl.cloudsmith.io/basic/my-org/my-repo/raw/files/file.tar.gz",
    });
    const publicResult = InstallCommandBuilder.build("raw", "file", "1.0.0", ws, repo, {
      cdnUrl: "https://dl.cloudsmith.io/public/my-org/my-repo/raw/files/file.tar.gz",
    });
    const generic = InstallCommandBuilder.build("generic", "file", "1.0.0", ws, repo, {
      cdnUrl: "https://generic.cloudsmith.io/my-org/my-repo/files/file.tar.gz",
    });

    assert.match(basic.note, /replace "basic"/u);
    assert.match(publicResult.note, /public repository/u);
    assert.doesNotMatch(publicResult.note, /replace "basic"/u);
    assert.match(generic.note, /HTTP authentication/u);
    assert.doesNotMatch(generic.note, /replace "basic"/u);
  });

  test("raw download commands refuse to overwrite an existing local filename", () => {
    const cdnUrl = "https://dl.cloudsmith.io/basic/my-org/my-repo/raw/files/.env";
    const result = InstallCommandBuilder.build("raw", ".env", "1.0.0", ws, repo, { cdnUrl });

    assert.match(result.command, /\bcurl\b[^\n]*\s--no-clobber(?:\s|$)/);
    assert.match(result.alternatives[0].command, /\bwget\b[^\n]*\s--no-clobber(?:\s|$)/);
  });

  test("raw never reconstructs a URL from filename metadata", () => {
    for (const filename of ["../payload", "..\\payload", ".", "..", "file\nname"]) {
      assertValidationError(
        () => InstallCommandBuilder.build("raw", "file", "1.0.0", ws, repo, { filename }),
        "Raw download URL"
      );
    }
  });

  test("rejects a format that could escape the unknown-format comment", () => {
    assertValidationError(
      () => InstallCommandBuilder.build("unknown\necho injected", "pkg", "1.0", ws, repo),
      "Package format"
    );
  });

  test("Maven rejects ambiguous or empty native coordinate components", () => {
    for (const name of ["group:artifact:extra", ":artifact", "group:"]) {
      assertValidationError(
        () => InstallCommandBuilder.build("maven", name, "1.0.0", ws, repo),
        "Maven package name"
      );
    }
  });

  test("omitted options and omitted Maven qualifiers preserve safe defaults", () => {
    const omitted = InstallCommandBuilder.build("maven", "com.example:demo", "1.0.0", ws, repo);
    const explicit = InstallCommandBuilder.build(
      "maven",
      "com.example:demo",
      "1.0.0",
      ws,
      repo,
      { qualifiers: {} }
    );

    assert.strictEqual(omitted.command, explicit.command);
    assert.doesNotMatch(omitted.command, /<(?:type|classifier)>/);
  });

  test("hostile option reflection fails closed without exposing trap errors", () => {
    const hostileOptions = new Proxy({}, {
      getPrototypeOf() {
        throw new Error("secret option trap");
      },
    });
    const hostileQualifiers = new Proxy({}, {
      ownKeys() {
        throw new Error("secret qualifier trap");
      },
    });

    assertValidationError(
      () => InstallCommandBuilder.build("npm", "pkg", "1.0.0", ws, repo, hostileOptions),
      "Install command options"
    );
    assertValidationError(
      () => InstallCommandBuilder.build(
        "maven",
        "com.example:pkg",
        "1.0.0",
        ws,
        repo,
        { qualifiers: hostileQualifiers }
      ),
      "Package qualifiers"
    );
  });

  test("Docker tag arrays reject accessors and proxy traps as validation errors", () => {
    const trapped = new Proxy([], {
      get() {
        throw new Error("secret array trap");
      },
      getOwnPropertyDescriptor() {
        throw new Error("secret descriptor trap");
      },
    });
    const accessor = [];
    Object.defineProperty(accessor, "0", { get() { throw new Error("secret getter"); } });
    accessor.length = 1;

    for (const version of [trapped, accessor]) {
      assertValidationError(
        () => InstallCommandBuilder.build("docker", "image", "1.0.0", ws, repo, {
          tags: { version },
        }),
        "Docker tag"
      );
    }
  });

  test("Docker tag validation contains get-only length traps and revoked arrays", () => {
    const trappedNonEmpty = new Proxy(["bad tag"], {
      get(target, property, receiver) {
        if (property === "length") throw new Error("secret length trap");
        return Reflect.get(target, property, receiver);
      },
    });
    const trappedEmpty = new Proxy([], {
      get(target, property, receiver) {
        if (property === "length") throw new Error("secret empty length trap");
        return Reflect.get(target, property, receiver);
      },
    });
    const revoked = Proxy.revocable([], {});
    revoked.revoke();

    for (const version of [trappedNonEmpty, revoked.proxy]) {
      assertValidationError(
        () => InstallCommandBuilder.build("docker", "image", sha256, ws, repo, {
          tags: { version },
        }),
        "Docker tag"
      );
    }

    const empty = InstallCommandBuilder.build("docker", "image", sha256, ws, repo, {
      tags: { version: trappedEmpty },
    });
    assert.match(empty.command, new RegExp(`@sha256:${sha256}$`));
    assert.ok(!empty.alternatives);
  });
});

// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const {
  INSTALL_GUIDANCE_SUPPORT,
  buildInstallGuidanceForPackage,
  hasInstallGuidanceForPackage,
  installGuidanceSupportForFormat,
  usableInstallGuidance,
} = require("../domain/installGuidanceSupport");

const supportModulePath = require.resolve("../domain/installGuidanceSupport");

function loadProjectedSupportInventory(projectInventory) {
  const cachedModule = require.cache[supportModulePath];
  const originalFreeze = Object.freeze;
  delete require.cache[supportModulePath];
  try {
    Object.freeze = (value) => {
      const frozen = originalFreeze(value);
      if (
        value
        && typeof value === "object"
        && value.python
        && value.npm
        && value.generic
      ) {
        return projectInventory(frozen);
      }
      return frozen;
    };
    return require(supportModulePath);
  } finally {
    Object.freeze = originalFreeze;
    delete require.cache[supportModulePath];
    if (cachedModule) require.cache[supportModulePath] = cachedModule;
  }
}

// Construct these isolated closures while Mocha is loading the test file. That
// keeps the frozen inventory's declarations static for Stryker, while the tests
// below can still exercise the private ownership guard through its public API.
const callableInventoryModule = loadProjectedSupportInventory((inventory) => {
  function callableInventory() {}
  Object.defineProperty(callableInventory, "npm", {
    configurable: false,
    enumerable: true,
    value: inventory.npm,
    writable: false,
  });
  return callableInventory;
});
const primitiveInventoryModule = loadProjectedSupportInventory(() => "npm");

suite("Install guidance support authority", () => {
  const shellSupport = INSTALL_GUIDANCE_SUPPORT.npm;
  const documentSupport = INSTALL_GUIDANCE_SUPPORT.maven;
  const coordinate = Object.freeze({
    format: "npm",
    name: "@scope/package",
    version: "1.2.3",
    workspace: "acme",
    repository: "widgets",
    qualifiers: Object.freeze({ native: "exact" }),
  });

  function packageDomainFor(value = coordinate) {
    return {
      packageCoordinateFromExact(pkg) {
        assert.strictEqual(pkg.marker, "selected-package");
        return value;
      },
    };
  }

  function usableBuilder(overrides = {}) {
    return {
      build() {
        return { command: "# verify\nnpm install exact", language: "shell" };
      },
      toClipboardCommand(command) {
        return command.replace(/^# verify\n/u, "");
      },
      ...overrides,
    };
  }

  test("publishes the exact frozen support inventory and rejects non-own format keys", () => {
    const expected = {
      python: ["template", "shell-command", ["exact name and version"]],
      npm: ["template", "shell-command", ["exact native package name and version"]],
      maven: ["template", "setup-document", ["exact groupId:artifactId coordinate and version"]],
      nuget: ["template", "shell-command", ["exact package ID and version"]],
      helm: ["template", "shell-command", ["exact chart name and version"]],
      cargo: ["template", "shell-command", ["exact crate name and version"]],
      go: ["template", "shell-command", ["exact module path and semantic version"]],
      ruby: ["template", "shell-command", ["exact gem name and version", "platform when package-specific"]],
      conda: ["template", "shell-command", ["exact name and version", "build qualifier", "subdir qualifier"]],
      composer: ["template", "shell-command", ["exact vendor/package name and version"]],
      dart: ["template", "shell-command", ["exact package name and version"]],
      docker: ["docker", "shell-command", ["exact image name", "authoritative tag or sha256 digest"]],
      rpm: ["rpm", "shell-command", ["exact name and version", "release qualifier", "architecture qualifier"]],
      raw: ["download", "shell-command", ["authoritative repository-scoped CDN URL"]],
      generic: ["download", "shell-command", ["authoritative repository-scoped CDN URL"]],
    };

    assert.strictEqual(Object.isFrozen(INSTALL_GUIDANCE_SUPPORT), true);
    assert.deepStrictEqual(Object.keys(INSTALL_GUIDANCE_SUPPORT), Object.keys(expected));
    for (const [format, [strategy, output, requiredEvidence]] of Object.entries(expected)) {
      const support = installGuidanceSupportForFormat(format);
      assert.strictEqual(support, INSTALL_GUIDANCE_SUPPORT[format]);
      assert.deepStrictEqual(support, { strategy, output, requiredEvidence });
      assert.strictEqual(Object.isFrozen(support), true);
      assert.strictEqual(Object.isFrozen(support.requiredEvidence), true);
    }

    const coercibleFormat = {
      [Symbol.toPrimitive]() { return "npm"; },
    };
    for (const format of [
      "toString", "constructor", "__proto__", "NPM", " npm ", "unsupported", "",
      null, undefined, 0, false, {}, [], () => {}, Symbol("npm"),
      new String("npm"), coercibleFormat,
    ]) {
      assert.strictEqual(installGuidanceSupportForFormat(format), null, String(format));
    }
  });

  test("the ownership guard accepts callable data owners and rejects primitive owners", () => {
    assert.strictEqual(
      callableInventoryModule.installGuidanceSupportForFormat("npm"),
      callableInventoryModule.INSTALL_GUIDANCE_SUPPORT.npm
    );
    assert.strictEqual(
      primitiveInventoryModule.installGuidanceSupportForFormat("0"),
      null
    );
  });

  test("descriptor inspection failure stays fail-closed", () => {
    const original = Object.getOwnPropertyDescriptor;
    let support;
    try {
      Object.getOwnPropertyDescriptor = () => { throw new Error("hostile descriptor"); };
      support = installGuidanceSupportForFormat("npm");
    } finally {
      Object.getOwnPropertyDescriptor = original;
    }
    assert.strictEqual(support, null);
  });

  test("shell guidance requires non-comment clipboard content and preserves builder receiver", () => {
    const calls = [];
    const builder = {
      toClipboardCommand(command) {
        calls.push({ receiver: this, command });
        return "# review first\n\n  npm install exact";
      },
    };
    assert.strictEqual(
      usableInstallGuidance(
        { command: "# verify\nnpm install exact", language: "shell" },
        shellSupport,
        builder
      ),
      true
    );
    assert.deepStrictEqual(calls, [{ receiver: builder, command: "# verify\nnpm install exact" }]);

    const contents = [
      ["# comment", false],
      ["   # comment", false],
      ["REM install later", false],
      ["rem install later", false],
      ["\n# comment", false],
      ["# comment\r\nREM later", false],
      ["# comment\nnpm install exact", true],
      ["   \n# comment", false],
      ["echo # is an argument", true],
      ["REMOTE=value", true],
    ];
    for (const [content, expected] of contents) {
      assert.strictEqual(
        usableInstallGuidance(
          { command: "source-command", language: "shell" },
          shellSupport,
          { toClipboardCommand: () => content }
        ),
        expected,
        JSON.stringify(content)
      );
    }
  });

  test("setup documents require markdown and a substantive XML settings or dependency fence", () => {
    const validDocuments = [
      "```xml\n<!-- selected repository -->\n<settings></settings>\n```",
      "```xml\r\n  selected\r\n<dependency></dependency>\r\n```",
    ];
    for (const content of validDocuments) {
      assert.strictEqual(
        usableInstallGuidance(
          { command: "setup", language: "markdown" },
          documentSupport,
          { toClipboardCommand: () => content }
        ),
        true
      );
    }

    for (const [language, content] of [
      ["xml", validDocuments[0]],
      ["markdown", "```json\n<settings></settings>\n```"],
      ["markdown", "```xml\n<repository></repository>\n```"],
      ["markdown", "```xml<settings></settings>```"],
    ]) {
      assert.strictEqual(
        usableInstallGuidance(
          { command: "setup", language },
          documentSupport,
          { toClipboardCommand: () => content }
        ),
        false
      );
    }
  });

  test("malformed results, clipboard adapters, and unknown output modes are unusable", () => {
    const validResult = { command: "run exact", language: "shell" };
    const validBuilder = { toClipboardCommand: command => command };
    function callableResult() {}
    callableResult.command = "run exact";
    for (const [result, support, builder] of [
      [validResult, null, validBuilder],
      [null, shellSupport, validBuilder],
      [false, shellSupport, validBuilder],
      ["run exact", shellSupport, validBuilder],
      [callableResult, shellSupport, validBuilder],
      [{}, shellSupport, validBuilder],
      [{ command: null }, shellSupport, validBuilder],
      [{ command: "" }, shellSupport, validBuilder],
      [{ command: " \t\n" }, shellSupport, validBuilder],
      [{ command: "No install command template for format: hex" }, shellSupport, validBuilder],
      [validResult, shellSupport, null],
      [validResult, shellSupport, {}],
      [validResult, shellSupport, { toClipboardCommand: "not-callable" }],
      [validResult, shellSupport, { toClipboardCommand: () => null }],
      [validResult, shellSupport, { toClipboardCommand: () => "" }],
      [validResult, shellSupport, { toClipboardCommand: () => " \r\n" }],
      [validResult, { output: "future-output" }, validBuilder],
      [validResult, { output: "" }, validBuilder],
    ]) {
      assert.strictEqual(usableInstallGuidance(result, support, builder), false);
    }

    assert.strictEqual(
      usableInstallGuidance(
        { command: " \t\n", language: "shell" },
        shellSupport,
        { toClipboardCommand: () => "run exact" }
      ),
      false
    );

    let outputReads = 0;
    const unreadSupport = {};
    Object.defineProperty(unreadSupport, "output", {
      get() {
        outputReads += 1;
        return "shell-command";
      },
    });
    assert.strictEqual(
      usableInstallGuidance(
        validResult,
        unreadSupport,
        { toClipboardCommand: () => " \t\n" }
      ),
      false
    );
    assert.strictEqual(outputReads, 0, "empty clipboard content must stop before output dispatch");
  });

  test("build composes the canonical coordinate and optional package evidence exactly", () => {
    const cases = [
      [{ marker: "selected-package" }, { qualifiers: coordinate.qualifiers }],
      [{
        marker: "selected-package",
        tags: { info: ["stable"], version: [] },
      }, {
        qualifiers: coordinate.qualifiers,
        tags: { info: ["stable"], version: [] },
      }],
      [{
        marker: "selected-package",
        tags: { info: [], version: ["1.2.3"] },
        cdnUrl: "https://dl.cloudsmith.example/exact.tgz",
        filename: "exact.tgz",
      }, {
        qualifiers: coordinate.qualifiers,
        tags: { info: [], version: ["1.2.3"] },
        cdnUrl: "https://dl.cloudsmith.example/exact.tgz",
        filename: "exact.tgz",
      }],
      [{
        marker: "selected-package",
        tags: { info: [], version: [] },
        cdnUrl: "",
        filename: "",
      }, { qualifiers: coordinate.qualifiers }],
    ];

    for (const [pkg, expectedOptions] of cases) {
      const calls = [];
      const result = { command: "npm install exact", language: "shell" };
      const builder = usableBuilder({
        build(...args) {
          calls.push(args);
          return result;
        },
      });

      assert.strictEqual(
        buildInstallGuidanceForPackage(packageDomainFor(), builder, pkg),
        result
      );
      assert.deepStrictEqual(calls, [[
        "npm",
        "@scope/package",
        "1.2.3",
        "acme",
        "widgets",
        expectedOptions,
      ]]);
    }
  });

  test("build rejects unavailable dependencies, unsupported formats, and unusable builder output", () => {
    const pkg = { marker: "selected-package" };
    const domain = packageDomainFor();
    const builder = usableBuilder();
    for (const [packageDomain, commandBuilder] of [
      [null, builder],
      [{}, builder],
      [{ packageCoordinateFromExact: "not-callable" }, builder],
      [domain, null],
      [domain, {}],
      [domain, { build: "not-callable" }],
    ]) {
      assert.strictEqual(
        buildInstallGuidanceForPackage(packageDomain, commandBuilder, pkg),
        null
      );
    }

    let unsupportedBuilds = 0;
    assert.strictEqual(
      buildInstallGuidanceForPackage(
        packageDomainFor({ ...coordinate, format: "hex" }),
        usableBuilder({ build() { unsupportedBuilds += 1; } }),
        pkg
      ),
      null
    );
    assert.strictEqual(unsupportedBuilds, 0);

    for (const result of [
      null,
      {},
      { command: "" },
      { command: "# comment only", language: "shell" },
      { command: "No install command template for format: npm", language: "shell" },
    ]) {
      assert.strictEqual(
        buildInstallGuidanceForPackage(
          domain,
          usableBuilder({ build: () => result }),
          pkg
        ),
        null
      );
    }
  });

  test("availability catches coordinate, build, and clipboard failures and reflects usable output", () => {
    const pkg = { marker: "selected-package" };
    assert.strictEqual(hasInstallGuidanceForPackage(packageDomainFor(), usableBuilder(), pkg), true);
    assert.strictEqual(
      hasInstallGuidanceForPackage(
        { packageCoordinateFromExact() { throw new Error("coordinate failed"); } },
        usableBuilder(),
        pkg
      ),
      false
    );
    assert.strictEqual(
      hasInstallGuidanceForPackage(
        packageDomainFor(),
        usableBuilder({ build() { throw new Error("build failed"); } }),
        pkg
      ),
      false
    );
    assert.strictEqual(
      hasInstallGuidanceForPackage(
        packageDomainFor(),
        usableBuilder({ toClipboardCommand() { throw new Error("clipboard failed"); } }),
        pkg
      ),
      false
    );
    assert.strictEqual(
      hasInstallGuidanceForPackage(
        packageDomainFor({ ...coordinate, format: "unsupported" }),
        usableBuilder(),
        pkg
      ),
      false
    );
    assert.strictEqual(hasInstallGuidanceForPackage(null, null, pkg), false);
  });
});

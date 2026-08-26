// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const manifest = require("../package.json");
const { registerPackageCommands } = require("../commands/packages");
const { registerVulnerabilityCommands } = require("../commands/vulnerabilities");
const { isInstallablePackage } = require("../commands/support");
const packageAdapters = require("../domain/packageAdapters");
const packageDomain = require("../domain/package");
const {
  serializePackageCollectionInspection,
  serializePackageInspection,
} = require("../util/packageInspection");
const { normalizeCvssScore } = require("../util/vulnerabilitySeverity");
const {
  InstallCommandBuilder: ProductionInstallCommandBuilder,
  InstallCommandValidationError: ProductionInstallCommandValidationError,
} = require("../util/installCommandBuilder");

function recorder() {
  const handlers = new Map();
  return {
    handlers,
    registerCommand(id, handler) {
      handlers.set(id, handler);
      return { dispose() { handlers.delete(id); } };
    },
  };
}

function accountAccess() {
  const account = Object.freeze({ activationId: "activation-a", accountEpoch: 1 });
  return {
    connectionManager: {},
    captureAccount: () => account,
    isAccountCurrent: () => true,
  };
}

function exactPackage(overrides = {}) {
  return packageDomain.createExactPackage({
    workspace: "workspace-a",
    repository: "repo-a",
    packageIdentifier: "package-one",
    name: "widget",
    version: "1.0.0",
    format: "npm",
    status: "Completed",
    copyable: true,
    ...overrides,
  });
}

function apiPackageRecord(overrides = {}) {
  return {
    namespace: "workspace-api",
    repository: "repo-api",
    slug_perm: "package-api-id",
    name: "widget",
    version: "1.0.0",
    format: "npm",
    status_str: "Completed",
    is_copyable: true,
    ...overrides,
  };
}

class SearchQueryBuilder {
  raw() { return this; }
  status() { return this; }
  build() { return "query"; }
}

class InstallCommandBuilder {
  static build() {
    return {
      command: "npm install widget@1.0.0",
      alternatives: [{ label: "Alternative", command: "npm i widget@1.0.0" }],
    };
  }

  static toClipboardCommand(value) { return value; }
}

function packageDeps(registration, overrides = {}) {
  return {
    registerCommand: registration.registerCommand.bind(registration),
    vscode: {
      workspace: { getConfiguration: () => ({ get: () => false }) },
      window: {
        showInformationMessage() {},
        showWarningMessage() {},
        showErrorMessage() {},
      },
    },
    context: {},
    workspaceAccess: accountAccess(),
    packageAdapters,
    packageDomain,
    recentPackages: { getAll: () => [], add() {} },
    cloudsmithProvider: { refresh() {}, refreshNode() {} },
    searchProvider: { refresh() {}, refreshNode() {} },
    dependencyHealthProvider: { refresh() {}, refreshNode() {} },
    inspectOutputChannel: { clear() {}, show() {}, append() {} },
    CloudsmithAPI: class {},
    apiEndpoint: () => "packages/workspace-a/repo-a/package-one/",
    PaginatedFetch: class {},
    packageCollectionIdentity: () => "identity",
    SearchQueryBuilder,
    LicenseClassifier: {
      buildRestrictiveQuery: () => "license:restrictive",
      inspect: () => null,
    },
    InstallCommandBuilder,
    InstallCommandValidationError: class extends Error {},
    buildPackageUrl: () => "https://cloudsmith.example/package",
    buildPackageGroupUrl: () => "https://cloudsmith.example/group",
    filterState: { activeFilters: new Map() },
    serializePackageCollectionInspection,
    serializePackageInspection,
    formatApiError: error => error.message,
    isCurrentSelection: () => true,
    isCurrentPackageSelection: () => true,
    isCurrentPackageGroupSelection: () => true,
    isCurrentRepositorySelection: () => true,
    isCurrentEntitlementSelection: () => true,
    ...overrides,
  };
}

function vulnerabilityDeps(registration, overrides = {}) {
  const vulnerabilityStateService = {
    prime: defaultVulnerabilityState,
    async resolve(pkg) { return defaultVulnerabilityState(pkg); },
  };
  return {
    registerCommand: registration.registerCommand.bind(registration),
    vscode: {
      QuickPickItemKind: { Separator: 1 },
      window: {
        showInformationMessage() {},
        showWarningMessage() {},
        showErrorMessage() {},
      },
    },
    context: {},
    workspaceAccess: accountAccess(),
    packageAdapters,
    packageDomain,
    recentPackages: { getAll: () => [], add() {} },
    CloudsmithAPI: class {},
    RemediationHelper: class {},
    InstallCommandBuilder,
    InstallCommandValidationError: class extends Error {},
    buildPackageUrl: () => "https://cloudsmith.example/package",
    vulnerabilityProvider: { async show() {} },
    quarantineExplainProvider: { async show() {} },
    cloudsmithProvider: { refreshNode() {} },
    searchProvider: { refreshNode() {} },
    dependencyHealthProvider: { refreshNode() {}, getLastSuccessfulScope: () => null },
    vulnerabilityStateService,
    normalizeCvssScore,
    formatApiError: error => error.message,
    isCurrentSelection: () => true,
    isCurrentPackageSelection: () => true,
    isCurrentDependencySelection: () => true,
    ...overrides,
  };
}

function defaultVulnerabilityState(pkg) {
  if (pkg && pkg.version === "1.0.0") {
    return Object.freeze({
      status: "complete-vulnerable",
      complete: true,
      stale: false,
      count: 1,
      records: Object.freeze([Object.freeze({ vulnerability_id: "CVE-2026-0001" })]),
    });
  }
  return Object.freeze({
    status: "complete-clean",
    complete: true,
    stale: false,
    count: 0,
    records: Object.freeze([]),
  });
}

suite("Command selection freshness", () => {
  test("install menus and callbacks require exact copyable non-quarantined packages", async () => {
    const installCommands = new Set([
      "cloudsmith-vsc.copyInstallCommand",
      "cloudsmith-vsc.showInstallCommand",
    ]);
    const menuEntries = manifest.contributes.menus["view/item/context"]
      .filter(entry => installCommands.has(entry.command));
    assert.strictEqual(menuEntries.length, 6);
    assert(menuEntries.every(entry => !entry.when.includes("packageNotCopyable")));
    assert(menuEntries.every(entry => !entry.when.includes("packageQuarantined")));

    const registration = recorder();
    const warnings = [];
    let builds = 0;
    class RecordingBuilder extends InstallCommandBuilder {
      static build(...args) {
        builds += 1;
        return super.build(...args);
      }
    }
    registerPackageCommands(packageDeps(registration, {
      InstallCommandBuilder: RecordingBuilder,
      vscode: {
        workspace: { getConfiguration: () => ({ get: () => false }) },
        window: {
          showInformationMessage() {},
          showWarningMessage: message => warnings.push(message),
        },
      },
    }));
    const install = registration.handlers.get("cloudsmith-vsc.copyInstallCommand");
    await install(exactPackage({ copyable: false }));
    await install(exactPackage({ status: "Quarantined", copyable: true }));
    await install({
      namespace: "workspace-a",
      repository: "repo-a",
      name: "widget",
      format: "npm",
    });
    assert.strictEqual(builds, 0);
    assert.strictEqual(warnings.length, 3);
  });

  test("install variant and repository-filter prompts stop on same-account detachment", async () => {
    const registration = recorder();
    let packageOwned = true;
    let repositoryOwned = true;
    let clipboardWrites = 0;
    let refreshes = 0;
    const activeFilters = new Map();
    registerPackageCommands(packageDeps(registration, {
      isCurrentPackageSelection: () => packageOwned,
      isCurrentRepositorySelection: () => repositoryOwned,
      filterState: { activeFilters },
      cloudsmithProvider: { refresh() { refreshes += 1; } },
      vscode: {
        workspace: { getConfiguration: () => ({ get: () => false }) },
        env: { clipboard: { async writeText() { clipboardWrites += 1; } } },
        window: {
          showInformationMessage() {},
          showWarningMessage() {},
          async showQuickPick(items, options) {
            if (options.placeHolder === "Select an install command") {
              packageOwned = false;
            } else {
              repositoryOwned = false;
            }
            return items[0];
          },
        },
      },
    }));

    await registration.handlers.get("cloudsmith-vsc.copyInstallCommand")(exactPackage());
    assert.strictEqual(clipboardWrites, 0);

    await registration.handlers.get("cloudsmith-vsc.filterPackages")({
      workspace: "workspace-a",
      slug: "repo-a",
      name: "Repo A",
    });
    assert.strictEqual(activeFilters.size, 0);
    assert.strictEqual(refreshes, 0);
  });

  test("Show and Copy publish identical selected guidance across the required formats", async () => {
    const fixtures = [
      exactPackage({ format: "npm", name: "@scope/widget" }),
      exactPackage({ format: "python", name: "widget" }),
      exactPackage({
        format: "docker",
        name: "team/widget",
        version: "a".repeat(64),
        tags: { info: ["upstream"], version: [] },
      }),
      exactPackage({
        format: "maven",
        name: "widget",
        coordinateName: "com.example:widget",
        qualifiers: { type: "test-jar", classifier: "tests" },
      }),
      exactPackage({ format: "nuget", name: "Widget.Core" }),
      exactPackage({ format: "cargo", name: "widget" }),
      exactPackage({
        format: "ruby",
        name: "widget",
        qualifiers: { platform: "x86_64-linux" },
      }),
      exactPackage({ format: "go", name: "example.test/widget" }),
    ];

    for (const pkg of fixtures) {
      const registration = recorder();
      let shown = null;
      let copied = null;
      let language = null;
      const informationMessages = [];
      registerPackageCommands(packageDeps(registration, {
        InstallCommandBuilder: ProductionInstallCommandBuilder,
        InstallCommandValidationError: ProductionInstallCommandValidationError,
        vscode: {
          workspace: {
            getConfiguration: () => ({ get: () => false }),
            async openTextDocument(options) {
              shown = options.content;
              language = options.language;
              return options;
            },
          },
          env: { clipboard: { async writeText(value) { copied = value; } } },
          window: {
            showInformationMessage(message) { informationMessages.push(message); },
            showWarningMessage() {},
            showErrorMessage() {},
            async showQuickPick(items) { return items[items.length - 1]; },
            async showTextDocument() {},
          },
        },
      }));

      await registration.handlers.get("cloudsmith-vsc.showInstallCommand")(pkg);
      await registration.handlers.get("cloudsmith-vsc.copyInstallCommand")(pkg);
      assert.strictEqual(shown, copied, `${pkg.format} Show and Copy bytes should match`);
      assert.match(shown, /(?:#|##|REM) Note/, `${pkg.format} prerequisites should remain visible`);
      if (pkg.format === "maven") {
        assert.match(shown, /Setup guidance only/u);
        assert.deepStrictEqual(informationMessages, [
          "Maven setup guidance copied. Merge the XML into the named files; do not run it as a shell command.",
        ]);
      } else {
        assert.deepStrictEqual(informationMessages, ["Install command copied."]);
      }
      if (pkg.format === "go") {
        assert.match(shown, /\n\nREM Note\nREM /u);
        assert.doesNotMatch(shown, /\n# Note|\n# /u);
      }
      assert.strictEqual(language, pkg.format === "maven" ? "markdown" : "shellscript");
    }
  });

  test("an advertised install capability produces usable native guidance through registered Show and Copy handlers", async () => {
    const fixtures = [
      ["npm", exactPackage({ format: "npm", name: "@scope/widget", version: "1.2.3" }), /npm install .*--registry=https:\/\/npm\.cloudsmith\.io\/workspace-a\/repo-a\//u],
      ["python", exactPackage({ format: "python", name: "widget", version: "1.2.3" }), /pip install .*--index-url https:\/\/dl\.cloudsmith\.io\/basic\/workspace-a\/repo-a\/python\/simple\//u],
      ["maven", exactPackage({
        format: "maven",
        name: "widget",
        coordinateName: "com.example:widget",
        version: "1.2.3",
        qualifiers: { type: "test-jar", classifier: "tests" },
      }), /<dependency>[\s\S]*<groupId>com\.example<\/groupId>[\s\S]*<artifactId>widget<\/artifactId>[\s\S]*<classifier>tests<\/classifier>/u],
      ["nuget", exactPackage({ format: "nuget", name: "Widget.Core", version: "1.2.3" }), /dotnet add package 'Widget\.Core' --version '\[1\.2\.3\]'/u],
      ["helm", exactPackage({ format: "helm", name: "widget", version: "1.2.3" }), /helm install .*--repo https:\/\/dl\.cloudsmith\.io\/basic\/workspace-a\/repo-a\/helm\/charts\//u],
      ["cargo", exactPackage({ format: "cargo", name: "widget", version: "1.2.3" }), /cargo add 'widget@=1\.2\.3' --registry/u],
      ["go", exactPackage({ format: "go", name: "example.test/widget", version: "1.2.3" }), /go get 'example\.test\/widget@v1\.2\.3'/u],
      ["ruby", exactPackage({
        format: "ruby",
        name: "widget",
        version: "1.2.3",
        qualifiers: { platform: "x86_64-linux" },
      }), /gem install 'widget'.*--platform 'x86_64-linux'/u],
      ["conda", exactPackage({
        format: "conda",
        name: "numpy",
        version: "1.24.0",
        qualifiers: { build: "py311h123_0", subdir: "linux-64" },
      }), /conda install .*'numpy==1\.24\.0=py311h123_0\[subdir=linux-64\]'/u],
      ["composer", exactPackage({ format: "composer", name: "vendor/widget", version: "1.2.3" }), /composer require 'vendor\/widget:1\.2\.3'/u],
      ["dart", exactPackage({ format: "dart", name: "widget", version: "1.2.3" }), /dart pub add 'widget:1\.2\.3'.*dart\.cloudsmith\.io\/workspace-a\/repo-a\//u],
      ["docker", exactPackage({ format: "docker", name: "team/widget", version: "stable" }), /docker pull docker\.cloudsmith\.io\/workspace-a\/repo-a\/team\/widget:stable/u],
      ["rpm", exactPackage({
        format: "rpm",
        name: "httpd",
        version: "2.4.57",
        qualifiers: { release: "1.el9", architecture: "x86_64" },
      }), /dnf install-nevra 'httpd-2\.4\.57-1\.el9\.x86_64'.*--enablerepo='workspace-a-repo-a'/u],
      ["raw", exactPackage({
        format: "raw",
        name: "artifact.tar.gz",
        version: "1.2.3",
        cdnUrl: "https://dl.cloudsmith.io/basic/workspace-a/repo-a/raw/files/artifact.tar.gz",
      }), /curl .*https:\/\/dl\.cloudsmith\.io\/basic\/workspace-a\/repo-a\/raw\/files\/artifact\.tar\.gz/u],
      ["generic", exactPackage({
        format: "generic",
        name: "artifact.bin",
        version: "",
        cdnUrl: "https://generic.cloudsmith.io/workspace-a/repo-a/files/artifact.bin",
      }), /curl .*https:\/\/generic\.cloudsmith\.io\/workspace-a\/repo-a\/files\/artifact\.bin/u],
    ];

    for (const [format, pkg, nativeGuidance] of fixtures) {
      const registration = recorder();
      let shown = null;
      let copied = null;
      const deps = packageDeps(registration, {
        InstallCommandBuilder: ProductionInstallCommandBuilder,
        InstallCommandValidationError: ProductionInstallCommandValidationError,
        vscode: {
          workspace: {
            getConfiguration: () => ({ get: () => false }),
            async openTextDocument(options) {
              shown = options.content;
              return options;
            },
          },
          env: { clipboard: { async writeText(value) { copied = value; } } },
          window: {
            showInformationMessage() {},
            showWarningMessage() {},
            showErrorMessage() {},
            async showQuickPick(items) { return items[0]; },
            async showTextDocument() {},
          },
        },
      });
      registerPackageCommands(deps);

      assert.strictEqual(isInstallablePackage(pkg, deps), true, `${format} capability`);
      await registration.handlers.get("cloudsmith-vsc.showInstallCommand")(pkg);
      await registration.handlers.get("cloudsmith-vsc.copyInstallCommand")(pkg);

      assert.strictEqual(shown, copied, `${format} Show and Copy bytes`);
      assert.match(shown, nativeGuidance, `${format} native semantics`);
      assert.doesNotMatch(shown, /No install command template/u, `${format} fallback`);
      if (format === "maven") {
        assert.match(shown, /```xml/u, "Maven publishes mergeable XML");
      } else {
        assert(
          shown.split(/\r?\n/u).some(line => line.trim() && !/^\s*(?:#|REM\b)/iu.test(line)),
          `${format} guidance must contain a non-comment command`
        );
      }
    }
  });

  test("unsupported formats and missing native identity evidence withhold Install and never publish guidance", async () => {
    const fixtures = [
      ["unsupported format", exactPackage({ format: "swift", name: "widget", version: "1.2.3" })],
      ["valid Docker tag or digest", exactPackage({ format: "docker", name: "team/widget", version: "not a tag" })],
      ["Maven groupId", exactPackage({ format: "maven", name: "widget", version: "1.2.3" })],
      ["Conda build and subdir", exactPackage({ format: "conda", name: "numpy", version: "1.24.0" })],
      ["RPM release and architecture", exactPackage({ format: "rpm", name: "httpd", version: "2.4.57" })],
      ["Raw authoritative URL", exactPackage({ format: "raw", name: "artifact.tar.gz", version: "1.2.3" })],
      ["Generic authoritative URL", exactPackage({ format: "generic", name: "artifact.bin", version: "" })],
    ];

    for (const [evidence, pkg] of fixtures) {
      const registration = recorder();
      const published = [];
      const deps = packageDeps(registration, {
        InstallCommandBuilder: ProductionInstallCommandBuilder,
        InstallCommandValidationError: ProductionInstallCommandValidationError,
        vscode: {
          workspace: {
            getConfiguration: () => ({ get: () => false }),
            async openTextDocument(options) {
              published.push(["show", options.content]);
              return options;
            },
          },
          env: { clipboard: { async writeText(value) { published.push(["copy", value]); } } },
          window: {
            showInformationMessage() {},
            showWarningMessage() {},
            showErrorMessage() {},
            async showTextDocument() {},
          },
        },
      });
      registerPackageCommands(deps);

      const advertised = isInstallablePackage(pkg, deps);
      await registration.handlers.get("cloudsmith-vsc.showInstallCommand")(pkg);
      await registration.handlers.get("cloudsmith-vsc.copyInstallCommand")(pkg);

      assert.strictEqual(advertised, false, `${evidence} must not advertise Install`);
      assert.deepStrictEqual(published, [], `${evidence} must not publish Show or Copy output`);
    }
  });

  test("API package identity and qualifiers survive registered Show and Copy handlers", async () => {
    const fixtures = [
      {
        record: apiPackageRecord({
          slug_perm: "maven-api-id",
          name: "widget-maven",
          version: "2.3.4",
          format: "maven",
          identifiers: {
            group_id: "com.example.api",
            extension: "test-jar",
            classifier: "tests",
          },
        }),
        expectedPrefix: [
          "maven",
          "com.example.api:widget-maven",
          "2.3.4",
          "workspace-api",
          "repo-api",
        ],
        expectedQualifiers: { classifier: "tests", type: "test-jar" },
        outputPatterns: [
          /<groupId>com\.example\.api<\/groupId>/u,
          /<artifactId>widget-maven<\/artifactId>/u,
          /<version>2\.3\.4<\/version>/u,
          /<type>test-jar<\/type>/u,
          /<classifier>tests<\/classifier>/u,
          /workspace-api\/repo-api\/maven\//u,
        ],
      },
      {
        record: apiPackageRecord({
          slug_perm: "ruby-api-id",
          name: "widget-ruby",
          version: "5.6.7",
          format: "ruby",
          identifiers: { ruby_platform: "x86_64-linux" },
        }),
        expectedPrefix: [
          "ruby",
          "widget-ruby",
          "5.6.7",
          "workspace-api",
          "repo-api",
        ],
        expectedQualifiers: { platform: "x86_64-linux" },
        outputPatterns: [
          /gem install 'widget-ruby' -v '5\.6\.7' --remote --platform 'x86_64-linux'/u,
          /workspace-api\/repo-api\/ruby\//u,
        ],
      },
      {
        record: apiPackageRecord({
          slug_perm: "raw-api-id",
          name: "artifact.tar.gz",
          version: "1.2.3",
          format: "raw",
          filename: "artifact.tar.gz",
          cdn_url: "https://dl.cloudsmith.io/basic/workspace-api/repo-api/raw/files/artifact.tar.gz",
        }),
        expectedPrefix: [
          "raw",
          "artifact.tar.gz",
          "1.2.3",
          "workspace-api",
          "repo-api",
        ],
        expectedQualifiers: {},
        outputPatterns: [
          /curl -fL -O --no-clobber --proto '=https' --proto-redir '=https' 'https:\/\/dl\.cloudsmith\.io\/basic\/workspace-api\/repo-api\/raw\/files\/artifact\.tar\.gz'/u,
        ],
      },
    ];

    for (const fixture of fixtures) {
      const registration = recorder();
      const buildCalls = [];
      let shown = null;
      let copied = null;
      class RecordingBuilder extends ProductionInstallCommandBuilder {
        static build(...args) {
          buildCalls.push(args);
          return super.build(...args);
        }
      }
      registerPackageCommands(packageDeps(registration, {
        InstallCommandBuilder: RecordingBuilder,
        InstallCommandValidationError: ProductionInstallCommandValidationError,
        vscode: {
          workspace: {
            getConfiguration: () => ({ get: () => false }),
            async openTextDocument(options) {
              shown = options.content;
              return options;
            },
          },
          env: { clipboard: { async writeText(value) { copied = value; } } },
          window: {
            showInformationMessage() {},
            showWarningMessage() {},
            showErrorMessage() {},
            async showQuickPick(items) { return items[0]; },
            async showTextDocument() {},
          },
        },
      }));

      await registration.handlers.get("cloudsmith-vsc.showInstallCommand")(fixture.record);
      await registration.handlers.get("cloudsmith-vsc.copyInstallCommand")(fixture.record);

      assert.strictEqual(buildCalls.length, 4);
      for (const args of buildCalls) {
        assert.deepStrictEqual(args.slice(0, 5), fixture.expectedPrefix);
        assert.deepStrictEqual(args[5].qualifiers, fixture.expectedQualifiers);
      }
      assert.strictEqual(shown, copied);
      for (const pattern of fixture.outputPatterns) assert.match(shown, pattern);
    }
  });

  test("API-produced mixed Docker tag arrays fail safely before Show or Copy publication", async () => {
    const registration = recorder();
    const errors = [];
    const warnings = [];
    let shown = false;
    let copied = false;
    registerPackageCommands(packageDeps(registration, {
      InstallCommandBuilder: ProductionInstallCommandBuilder,
      InstallCommandValidationError: ProductionInstallCommandValidationError,
      vscode: {
        workspace: {
          getConfiguration: () => ({ get: () => false }),
          async openTextDocument() {
            shown = true;
            return {};
          },
        },
        env: { clipboard: { async writeText() { copied = true; } } },
        window: {
          showInformationMessage() {},
          showWarningMessage(message) { warnings.push(message); },
          showErrorMessage(message) { errors.push(message); },
          async showTextDocument() {},
        },
      },
    }));
    const record = apiPackageRecord({
      name: "team/widget",
      version: "a".repeat(64),
      format: "docker",
      tags: { info: ["upstream"], version: ["stable", "bad tag"] },
    });

    await registration.handlers.get("cloudsmith-vsc.showInstallCommand")(record);
    await registration.handlers.get("cloudsmith-vsc.copyInstallCommand")(record);

    assert.strictEqual(shown, false);
    assert.strictEqual(copied, false);
    assert.deepStrictEqual(errors, []);
    assert.deepStrictEqual(warnings, [
      "Install guidance is not available for this package.",
      "Install guidance is not available for this package.",
    ]);
  });

  test("API-produced empty Docker version tags preserve digest-only Show and Copy output", async () => {
    const registration = recorder();
    const buildCalls = [];
    const errors = [];
    let shown = null;
    let copied = null;
    let pickerCalls = 0;
    class RecordingBuilder extends ProductionInstallCommandBuilder {
      static build(...args) {
        buildCalls.push(args);
        return super.build(...args);
      }
    }
    registerPackageCommands(packageDeps(registration, {
      InstallCommandBuilder: RecordingBuilder,
      InstallCommandValidationError: ProductionInstallCommandValidationError,
      vscode: {
        workspace: {
          getConfiguration: () => ({ get: () => false }),
          async openTextDocument(options) {
            shown = options.content;
            return options;
          },
        },
        env: { clipboard: { async writeText(value) { copied = value; } } },
        window: {
          showInformationMessage() {},
          showWarningMessage() {},
          showErrorMessage(message) { errors.push(message); },
          async showQuickPick(items) {
            pickerCalls += 1;
            return items[0];
          },
          async showTextDocument() {},
        },
      },
    }));
    const digest = "b".repeat(64);
    const record = apiPackageRecord({
      slug_perm: "docker-api-id",
      name: "team/widget",
      version: digest,
      format: "docker",
      tags: { info: ["upstream"], version: [] },
    });

    await registration.handlers.get("cloudsmith-vsc.showInstallCommand")(record);
    await registration.handlers.get("cloudsmith-vsc.copyInstallCommand")(record);

    assert.strictEqual(buildCalls.length, 4);
    for (const args of buildCalls) {
      assert.deepStrictEqual(args.slice(0, 5), [
        "docker",
        "team/widget",
        digest,
        "workspace-api",
        "repo-api",
      ]);
      assert.deepStrictEqual(args[5].tags, { info: ["upstream"], version: [] });
    }
    const primary = `docker pull docker.cloudsmith.io/workspace-api/repo-api/team/widget@sha256:${digest}`;
    assert.ok(shown.startsWith(`${primary}\n\n# Note\n`));
    assert.strictEqual(shown, copied);
    assert.doesNotMatch(shown, /team\/widget:(?:latest|stable)/u);
    assert.strictEqual(pickerCalls, 0);
    assert.deepStrictEqual(errors, []);
  });

  test("install variant selection rejects an unoffered Quick Pick object", async () => {
    const registration = recorder();
    let clipboardWrites = 0;
    registerPackageCommands(packageDeps(registration, {
      vscode: {
        workspace: { getConfiguration: () => ({ get: () => false }) },
        env: { clipboard: { async writeText() { clipboardWrites += 1; } } },
        window: {
          showInformationMessage() {},
          showWarningMessage() {},
          async showQuickPick() { return { command: "unoffered text" }; },
        },
      },
    }));

    await registration.handlers.get("cloudsmith-vsc.copyInstallCommand")(exactPackage());
    assert.strictEqual(clipboardWrites, 0);
  });

  test("inspection failures retain operation context and stale service completions stay silent", async () => {
    const pkg = exactPackage();
    const errors = [];
    let owned = true;
    let staleOnRead = false;
    class FailingAPI {
      async get() {
        if (staleOnRead) owned = false;
        return { ok: false, error: { message: "service unavailable" } };
      }
    }
    const registration = recorder();
    registerPackageCommands(packageDeps(registration, {
      isCurrentPackageSelection: () => owned,
      CloudsmithAPI: FailingAPI,
      vscode: {
        workspace: { getConfiguration: () => ({ get: () => false }) },
        window: {
          showErrorMessage: message => errors.push(message),
          showWarningMessage() {},
        },
      },
    }));
    const inspect = registration.handlers.get("cloudsmith-vsc.inspectPackage");
    await inspect(pkg);
    assert.deepStrictEqual(errors, ["Could not inspect package. service unavailable"]);

    errors.length = 0;
    staleOnRead = true;
    await inspect(pkg);
    assert.deepStrictEqual(errors, []);

    const groupRegistration = recorder();
    registerPackageCommands(packageDeps(groupRegistration, {
      packageAdapters: {
        ...packageAdapters,
        fromPackageGroupNode: () => ({
          workspace: "workspace-a",
          repository: "repo-a",
          name: "widget",
          format: "npm",
        }),
      },
      SearchQueryBuilder: class {
        name() { return this; }
        format() { return this; }
        build() { return "name:widget"; }
      },
      PaginatedFetch: class {
        async fetchCollection() {
          return {
            complete: false,
            items: [],
            failures: [{ error: { message: "group service unavailable" } }],
            failureCount: 1,
          };
        }
      },
      vscode: { window: { showErrorMessage: message => errors.push(message) } },
    }));
    await groupRegistration.handlers.get("cloudsmith-vsc.inspectPackageGroup")({});
    assert.match(errors[0], /^Could not inspect package group\./);
  });

  test("inspection document and output-channel failures are contained with contextual errors", async () => {
    const errors = [];
    const apiRecord = {
      namespace: "workspace-a",
      repository: "repo-a",
      slug_perm: "package-one",
      name: "widget",
      version: "1.0.0",
      format: "npm",
      status_str: "Completed",
      is_copyable: true,
    };
    const registration = recorder();
    registerPackageCommands(packageDeps(registration, {
      CloudsmithAPI: class {
        async get() { return { ok: true, data: apiRecord }; }
      },
      vscode: {
        workspace: {
          getConfiguration: () => ({ get: () => true }),
          async openTextDocument() { throw new Error("document service unavailable"); },
        },
        window: {
          showErrorMessage: message => errors.push(message),
          showWarningMessage() {},
        },
      },
    }));
    await registration.handlers.get("cloudsmith-vsc.inspectPackage")(exactPackage());
    assert.deepStrictEqual(errors, [
      "Could not inspect package. The inspection output could not be opened.",
    ]);

    const groupRegistration = recorder();
    registerPackageCommands(packageDeps(groupRegistration, {
      packageAdapters: {
        ...packageAdapters,
        fromPackageGroupNode: () => ({
          workspace: "workspace-a",
          repository: "repo-a",
          name: "widget",
          format: "npm",
        }),
      },
      SearchQueryBuilder: class {
        name() { return this; }
        format() { return this; }
        build() { return "name:widget"; }
      },
      PaginatedFetch: class {
        async fetchCollection() {
          return {
            complete: true,
            items: [apiRecord],
            failureCount: 0,
          };
        }
      },
      inspectOutputChannel: {
        clear() { throw new Error("output channel unavailable"); },
        show() {},
        append() {},
      },
      vscode: {
        workspace: { getConfiguration: () => ({ get: () => false }) },
        window: { showErrorMessage: message => errors.push(message) },
      },
    }));
    await groupRegistration.handlers.get("cloudsmith-vsc.inspectPackageGroup")({});
    assert.deepStrictEqual(errors, [
      "Could not inspect package. The inspection output could not be opened.",
      "Could not inspect package group. The inspection output could not be opened.",
    ]);
  });

  test("package inspection rejects a same-repository response for a different package", async () => {
    const errors = [];
    const output = [];
    const registration = recorder();
    registerPackageCommands(packageDeps(registration, {
      CloudsmithAPI: class {
        async get() {
          return {
            ok: true,
            data: {
              namespace: "workspace-a",
              repository: "repo-a",
              slug_perm: "different-package",
              name: "widget",
              version: "1.0.0",
              format: "npm",
              status_str: "Completed",
              is_copyable: true,
            },
          };
        }
      },
      inspectOutputChannel: {
        clear() { output.push("clear"); },
        show() { output.push("show"); },
        append(value) { output.push(value); },
      },
      vscode: {
        workspace: { getConfiguration: () => ({ get: () => false }) },
        window: {
          showErrorMessage: message => errors.push(message),
          showWarningMessage() {},
        },
      },
    }));

    await registration.handlers.get("cloudsmith-vsc.inspectPackage")(exactPackage());

    assert.deepStrictEqual(errors, ["Could not safely inspect the package response."]);
    assert.deepStrictEqual(output, []);
  });

  test("quarantine explanation applies its predicate after canonical assertion", async () => {
    const registration = recorder();
    const warnings = [];
    let providerCalls = 0;
    let assertions = 0;
    registerVulnerabilityCommands(vulnerabilityDeps(registration, {
      packageDomain: {
        assertExactPackage(value) {
          assertions += 1;
          return packageDomain.assertExactPackage(value);
        },
      },
      quarantineExplainProvider: { async show() { providerCalls += 1; } },
      vscode: { window: { showWarningMessage: message => warnings.push(message) } },
    }));
    await registration.handlers.get("cloudsmith-vsc.explainQuarantine")(exactPackage());
    assert.strictEqual(assertions, 1);
    assert.strictEqual(providerCalls, 0);
    assert.deepStrictEqual(warnings, [
      "Quarantine details are available only for quarantined packages.",
    ]);
  });

  test("recovered quarantine selection is canonically asserted before eligibility and provider use", async () => {
    const registration = recorder();
    const quarantined = exactPackage({ status: "Quarantined" });
    let assertions = 0;
    let shown = null;
    registerVulnerabilityCommands(vulnerabilityDeps(registration, {
      packageDomain: {
        assertExactPackage(value) {
          assertions += 1;
          return packageDomain.assertExactPackage(value);
        },
      },
      recentPackages: { getAll: () => [quarantined], add() {} },
      quarantineExplainProvider: { async show(value) { shown = value; } },
      vscode: { window: { showQuickPick: async items => items[0] } },
    }));
    await registration.handlers.get("cloudsmith-vsc.explainQuarantine")();
    assert(assertions >= 2);
    assert.strictEqual(shown, quarantined);

    const rejectedRegistration = recorder();
    const information = [];
    let rejectedProviderCalls = 0;
    registerVulnerabilityCommands(vulnerabilityDeps(rejectedRegistration, {
      recentPackages: { getAll: () => [exactPackage()], add() {} },
      quarantineExplainProvider: { async show() { rejectedProviderCalls += 1; } },
      vscode: {
        window: { showInformationMessage: message => information.push(message) },
      },
    }));
    await rejectedRegistration.handlers.get("cloudsmith-vsc.explainQuarantine")();
    assert.strictEqual(rejectedProviderCalls, 0);
    assert.deepStrictEqual(information, [
      "No recent quarantined packages. Open a quarantined package, then try again.",
    ]);
  });

  test("vulnerability filters revalidate ownership after every picker, setter, and refresh", async () => {
    for (const staleAt of [1, 2, 3]) {
      const registration = recorder();
      let owned = true;
      let prompt = 0;
      let mutations = 0;
      let refreshes = 0;
      const summary = {
        setSeverityFilter() { mutations += 1; },
        setCvssThreshold() { mutations += 1; },
      };
      registerVulnerabilityCommands(vulnerabilityDeps(registration, {
        isCurrentSelection: item => owned && item === summary,
        cloudsmithProvider: { refreshNode() { refreshes += 1; } },
        searchProvider: { refreshNode() { refreshes += 1; } },
        dependencyHealthProvider: { refreshNode() { refreshes += 1; } },
        vscode: {
          window: {
            async showQuickPick(items) {
              prompt += 1;
              if (prompt === staleAt) owned = false;
              if (prompt === 1) return items.find(item => item.value === "cvss");
              return items.find(item => item.value === "custom");
            },
            async showInputBox() {
              prompt += 1;
              if (prompt === staleAt) owned = false;
              return "7.5";
            },
          },
        },
      }));
      await registration.handlers.get("cloudsmith-vsc.filterVulnerabilities")(summary);
      assert.strictEqual(mutations, 0);
      assert.strictEqual(refreshes, 0);
    }

    const registration = recorder();
    let owned = true;
    let searchRefreshes = 0;
    const summary = {
      setSeverityFilter() { owned = false; },
      setCvssThreshold() { throw new Error("must not run"); },
    };
    registerVulnerabilityCommands(vulnerabilityDeps(registration, {
      isCurrentSelection: item => owned && item === summary,
      cloudsmithProvider: { refreshNode() { owned = false; } },
      searchProvider: { refreshNode() { searchRefreshes += 1; } },
      vscode: {
        window: {
          showQuickPick: async items => items.find(item => item.value === "clear"),
        },
      },
    }));
    await registration.handlers.get("cloudsmith-vsc.filterVulnerabilities")(summary);
    assert.strictEqual(searchRefreshes, 0);
  });

  test("safe-version actions omit non-copyable installs and discard detached service results", async () => {
    for (const overrides of [
      { is_copyable: false, status_str: "Completed", deny_policy_violated: false },
    ]) {
      const registration = recorder();
      let actionItems = null;
      let picker = 0;
      class RemediationHelper {
        async findSafeVersions() {
          return {
            success: true,
            complete: true,
            totalCount: 1,
            versions: [{
              namespace: "workspace-a",
              repository: "repo-a",
              slug_perm: "safe-package",
              name: "widget",
              version: "2.0.0",
              format: "npm",
              ...overrides,
            }],
          };
        }
      }
      registerVulnerabilityCommands(vulnerabilityDeps(registration, {
        RemediationHelper,
        vscode: {
          QuickPickItemKind: { Separator: 1 },
          window: {
            async showQuickPick(items) {
              picker += 1;
              if (picker === 1) return items.find(item => item.package);
              actionItems = items;
              return undefined;
            },
            showErrorMessage() {},
            showWarningMessage() {},
          },
        },
      }));
      await registration.handlers.get("cloudsmith-vsc.findSafeVersion")(exactPackage());
      assert(actionItems);
      assert.strictEqual(actionItems.some(item => item.id === "install"), false);
    }

    const registration = recorder();
    let owned = true;
    let pickerCalls = 0;
    class DetachingRemediationHelper {
      async findSafeVersions() {
        owned = false;
        return { success: true, complete: true, totalCount: 0, versions: [] };
      }
    }
    registerVulnerabilityCommands(vulnerabilityDeps(registration, {
      isCurrentPackageSelection: () => owned,
      RemediationHelper: DetachingRemediationHelper,
      vscode: { window: { showQuickPick() { pickerCalls += 1; } } },
    }));
    await registration.handlers.get("cloudsmith-vsc.findSafeVersion")(exactPackage());
    assert.strictEqual(pickerCalls, 0);
  });

  test("known fix absent from the selected repository is truthful and never widens scope", async () => {
    const registration = recorder();
    const information = [];
    const source = exactPackage({
      name: "js-yaml",
      version: "3.14.2",
      packageIdentifier: "js-yaml-3-14-2",
      vulnerability: { evidence: "detected", detected: true, count: 1 },
    });
    const sourceState = Object.freeze({
      status: "complete-vulnerable",
      complete: true,
      stale: false,
      count: 1,
      records: Object.freeze([Object.freeze({
        vulnerability_id: "CVE-2026-53550",
        fixed_version: Object.freeze({ version: "4.2.0" }),
      })]),
    });
    let helperOptions = null;
    class RemediationHelper {
      async findSafeVersions(_workspace, _repository, _name, _format, options) {
        helperOptions = options;
        return {
          success: true,
          complete: true,
          totalCount: 0,
          absenceProven: true,
          versions: [],
        };
      }
      async findSafeVersionsAcrossRepos() {
        throw new Error("selected repository scope must not widen");
      }
    }
    const vulnerabilityStateService = {
      prime() { return sourceState; },
      async resolve() { return sourceState; },
    };
    registerVulnerabilityCommands(vulnerabilityDeps(registration, {
      RemediationHelper,
      vulnerabilityStateService,
      vscode: {
        QuickPickItemKind: { Separator: 1 },
        window: {
          showInformationMessage: message => information.push(message),
          showWarningMessage() {},
          showErrorMessage() {},
        },
      },
    }));

    await registration.handlers.get("cloudsmith-vsc.findSafeVersion")(source);

    assert.deepStrictEqual(helperOptions, {
      currentVersion: "3.14.2",
      fixedVersions: ["4.2.0"],
    });
    assert.deepStrictEqual(information, [
      'No compatible safe version for "js-yaml" is available in repo-a. The reported fix is 4.2.0.',
    ]);
  });

  test("a canonically complete-clean source stops remediation before searching", async () => {
    const registration = recorder();
    const information = [];
    let searches = 0;
    class RemediationHelper {
      async findSafeVersions() {
        searches += 1;
        throw new Error("clean sources must not be searched");
      }
    }
    const cleanState = Object.freeze({
      status: "complete-clean",
      complete: true,
      stale: false,
      count: 0,
      records: Object.freeze([]),
    });
    registerVulnerabilityCommands(vulnerabilityDeps(registration, {
      RemediationHelper,
      vulnerabilityStateService: {
        prime() { return cleanState; },
        async resolve() { return cleanState; },
      },
      vscode: {
        window: {
          showInformationMessage: message => information.push(message),
          showWarningMessage() {},
          showErrorMessage() {},
        },
      },
    }));

    await registration.handlers.get("cloudsmith-vsc.findSafeVersion")(exactPackage());

    assert.strictEqual(searches, 0);
    assert.deepStrictEqual(information, [
      'No known vulnerabilities were found for "widget" 1.0.0.',
    ]);
  });

  test("incomplete source truth states fail closed before remediation search", async () => {
    const states = [
      { status: "unknown", complete: false, stale: false, count: null, records: [] },
      { status: "loading", complete: false, stale: false, count: null, records: [] },
      { status: "partial", complete: false, stale: false, count: 1, records: [{}] },
      { status: "failed", complete: false, stale: false, count: null, records: [] },
      { status: "complete-vulnerable", complete: true, stale: true, count: 1, records: [{}] },
      {
        status: "complete-vulnerable",
        complete: true,
        stale: false,
        refreshing: true,
        count: 1,
        records: [{}],
      },
      {
        status: "complete-vulnerable",
        complete: true,
        stale: false,
        refreshFailure: { kind: "network" },
        count: 1,
        records: [{}],
      },
    ];
    for (const state of states) {
      const registration = recorder();
      const warnings = [];
      let searches = 0;
      class RemediationHelper {
        async findSafeVersions() { searches += 1; return { success: true, versions: [] }; }
      }
      registerVulnerabilityCommands(vulnerabilityDeps(registration, {
        RemediationHelper,
        vulnerabilityStateService: {
          prime() { return state; },
          async resolve() { return state; },
        },
        vscode: {
          window: {
            showInformationMessage() {},
            showWarningMessage: message => warnings.push(message),
            showErrorMessage() {},
          },
        },
      }));

      await registration.handlers.get("cloudsmith-vsc.findSafeVersion")(exactPackage());

      assert.strictEqual(searches, 0, state.status);
      assert.deepStrictEqual(warnings, ["Could not verify safe versions. Retry."], state.status);
    }
  });

  test("an incomplete empty search result does not claim compatible-version absence", async () => {
    const registration = recorder();
    const warnings = [];
    const information = [];
    class RemediationHelper {
      async findSafeVersions() {
        return {
          success: true,
          complete: false,
          totalCount: null,
          absenceProven: false,
          versions: [],
        };
      }
    }
    registerVulnerabilityCommands(vulnerabilityDeps(registration, {
      RemediationHelper,
      vscode: {
        window: {
          showInformationMessage: message => information.push(message),
          showWarningMessage: message => warnings.push(message),
          showErrorMessage() {},
        },
      },
    }));

    await registration.handlers.get("cloudsmith-vsc.findSafeVersion")(exactPackage());

    assert.deepStrictEqual(information, []);
    assert.deepStrictEqual(warnings, [
      "Could not verify whether compatible safe versions are available. Retry.",
    ]);
  });

  test("older, below-fix, and npm prerelease response rows fail closed before publication", async () => {
    for (const version of ["3.13.0", "4.1.0", "4.2.0-beta.1"]) {
      const registration = recorder();
      const errors = [];
      let pickerCalls = 0;
      const source = exactPackage({
        name: "js-yaml",
        version: "3.14.2",
        packageIdentifier: "js-yaml-3-14-2",
      });
      const sourceState = Object.freeze({
        status: "complete-vulnerable",
        complete: true,
        stale: false,
        count: 1,
        records: Object.freeze([Object.freeze({
          vulnerability_id: "CVE-2026-53550",
          fixed_version: Object.freeze({ version: "4.2.0" }),
        })]),
      });
      class RemediationHelper {
        async findSafeVersions() {
          return {
            success: true,
            complete: true,
            totalCount: 1,
            absenceProven: false,
            versions: [{
              namespace: "workspace-a",
              repository: "repo-a",
              slug_perm: `js-yaml-${version}`,
              name: "js-yaml",
              version,
              format: "npm",
              status_str: "Completed",
              deny_policy_violated: false,
            }],
          };
        }
      }
      registerVulnerabilityCommands(vulnerabilityDeps(registration, {
        RemediationHelper,
        vulnerabilityStateService: {
          prime(pkg) { return pkg.version === source.version ? sourceState : defaultVulnerabilityState(pkg); },
          async resolve(pkg) { return pkg.version === source.version ? sourceState : defaultVulnerabilityState(pkg); },
        },
        vscode: {
          window: {
            showInformationMessage() {},
            showWarningMessage() {},
            showErrorMessage: message => errors.push(message),
            showQuickPick() { pickerCalls += 1; },
          },
        },
      }));

      await registration.handlers.get("cloudsmith-vsc.findSafeVersion")(source);

      assert.deepStrictEqual(errors, [
        "Could not safely interpret the available package versions.",
      ]);
      assert.strictEqual(pickerCalls, 0);
    }
  });

  test("safe-version candidates cannot cross native artifact identity variants", async () => {
    const cases = [
      {
        source: exactPackage({
          format: "maven",
          name: "demo",
          coordinateName: "com.example:demo",
          qualifiers: { type: "test-jar", classifier: "tests" },
        }),
        candidate: {
          name: "demo",
          format: "maven",
          identifiers: {
            group_id: "org.other",
            extension: "test-jar",
            classifier: "tests",
          },
        },
      },
      {
        source: exactPackage({
          format: "maven",
          name: "demo",
          coordinateName: "com.example:demo",
          qualifiers: { type: "test-jar", classifier: "tests" },
        }),
        candidate: {
          name: "demo",
          format: "maven",
          identifiers: {
            group_id: "com.example",
            extension: "jar",
            classifier: "sources",
          },
        },
      },
      {
        source: exactPackage({
          format: "ruby",
          qualifiers: { platform: "x86_64-linux" },
        }),
        candidate: {
          name: "widget",
          format: "ruby",
          identifiers: { ruby_platform: "ruby" },
        },
      },
      {
        source: exactPackage({
          format: "conda",
          qualifiers: { build: "py311h123_0", subdir: "linux-64" },
        }),
        candidate: {
          name: "widget",
          format: "conda",
          identifiers: { build: "py312h456_0", subdir: "osx-64" },
        },
      },
      {
        source: exactPackage({ format: "maven" }),
        candidate: {
          name: "widget",
          format: "maven",
        },
      },
      {
        source: exactPackage({ format: "conda" }),
        candidate: {
          name: "widget",
          format: "conda",
        },
      },
      {
        source: exactPackage({
          format: "conda",
          qualifiers: { subdir: "linux-64" },
        }),
        candidate: {
          name: "widget",
          format: "conda",
        },
      },
      {
        source: exactPackage({ format: "conda" }),
        candidate: {
          name: "widget",
          format: "conda",
          identifiers: { subdir: "linux-64" },
        },
      },
      {
        source: exactPackage({ format: "rpm" }),
        candidate: {
          name: "widget",
          format: "rpm",
        },
      },
      {
        source: exactPackage({
          format: "rpm",
          qualifiers: { architecture: "x86_64" },
        }),
        candidate: {
          name: "widget",
          format: "rpm",
        },
      },
      {
        source: exactPackage({ format: "rpm" }),
        candidate: {
          name: "widget",
          format: "rpm",
          identifiers: { architecture: "x86_64" },
        },
      },
      {
        source: exactPackage({
          format: "rpm",
          qualifiers: { release: "1", architecture: "x86_64" },
        }),
        candidate: {
          name: "widget",
          format: "rpm",
          identifiers: { release: "2", architecture: "aarch64" },
        },
      },
    ];

    for (const [index, fixture] of cases.entries()) {
      const registration = recorder();
      const errors = [];
      let pickerCalls = 0;
      class RemediationHelper {
        async findSafeVersions() {
          return {
            success: true,
            complete: true,
            totalCount: 1,
            absenceProven: false,
            versions: [{
              namespace: "workspace-a",
              repository: "repo-a",
              slug_perm: `candidate-${index}`,
              version: "2.0.0",
              status_str: "Completed",
              deny_policy_violated: false,
              is_copyable: true,
              ...fixture.candidate,
            }],
          };
        }
      }
      registerVulnerabilityCommands(vulnerabilityDeps(registration, {
        RemediationHelper,
        vscode: {
          window: {
            showInformationMessage() {},
            showWarningMessage() {},
            showErrorMessage: message => errors.push(message),
            showQuickPick() { pickerCalls += 1; },
          },
        },
      }));

      await registration.handlers.get("cloudsmith-vsc.findSafeVersion")(fixture.source);

      assert.deepStrictEqual(errors, [
        "Could not safely interpret the available package versions.",
      ]);
      assert.strictEqual(pickerCalls, 0);
    }

    const positiveCases = [
      {
        source: exactPackage({
          format: "conda",
          qualifiers: { build: "py311h123_0", subdir: "linux-64" },
        }),
        candidate: {
            namespace: "workspace-a",
            repository: "repo-a",
            slug_perm: "conda-new-build",
            name: "widget",
            version: "2.0.0",
            format: "conda",
            status_str: "Completed",
            deny_policy_violated: false,
            is_copyable: true,
            identifiers: { build: "py312h456_0", subdir: "linux-64" },
        },
        expectedQualifiers: { build: "py312h456_0", subdir: "linux-64" },
      },
      {
        source: exactPackage({
          name: "demo",
          format: "maven",
          coordinateName: "com.example:demo",
        }),
        candidate: {
          namespace: "workspace-a",
          repository: "repo-a",
          slug_perm: "maven-default-jar",
          name: "demo",
          version: "2.0.0",
          format: "maven",
          status_str: "Completed",
          deny_policy_violated: false,
          is_copyable: true,
          identifiers: { group_id: "com.example" },
        },
        expectedQualifiers: {},
      },
      {
        source: exactPackage({
          format: "rpm",
          qualifiers: { release: "1", architecture: "x86_64" },
        }),
        candidate: {
          namespace: "workspace-a",
          repository: "repo-a",
          slug_perm: "rpm-new-release",
          name: "widget",
          version: "2.0.0",
          format: "rpm",
          status_str: "Completed",
          deny_policy_violated: false,
          is_copyable: true,
          identifiers: { release: "2", architecture: "x86_64" },
        },
        expectedQualifiers: { architecture: "x86_64", release: "2" },
      },
    ];

    for (const fixture of positiveCases) {
      const registration = recorder();
      const errors = [];
      let publishedItems = null;
      class RemediationHelper {
        async findSafeVersions() {
          return {
            success: true,
            complete: true,
            totalCount: 1,
            absenceProven: false,
            versions: [fixture.candidate],
          };
        }
      }
      registerVulnerabilityCommands(vulnerabilityDeps(registration, {
        RemediationHelper,
        vscode: {
          QuickPickItemKind: { Separator: 1 },
          window: {
            showInformationMessage() {},
            showWarningMessage() {},
            showErrorMessage: message => errors.push(message),
            showQuickPick(items) {
              publishedItems = items;
              return undefined;
            },
          },
        },
      }));

      await registration.handlers.get("cloudsmith-vsc.findSafeVersion")(fixture.source);

      assert.deepStrictEqual(errors, []);
      assert.strictEqual(publishedItems.length, 1);
      assert.deepStrictEqual(publishedItems[0].package.qualifiers, fixture.expectedQualifiers);
    }
  });

  test("safe-version picker publishes only canonically verified complete-clean candidates", async () => {
    const registration = recorder();
    const source = exactPackage({
      name: "js-yaml",
      version: "3.14.2",
      packageIdentifier: "js-yaml-3-14-2",
      vulnerability: { evidence: "detected", detected: true, count: 1 },
    });
    const sourceState = Object.freeze({
      status: "complete-vulnerable",
      complete: true,
      stale: false,
      count: 1,
      records: Object.freeze([Object.freeze({
        vulnerability_id: "CVE-2026-53550",
        fixed_version: Object.freeze({ version: "4.2.0" }),
      })]),
    });
    const candidates = [
      {
        namespace: "workspace-a",
        repository: "repo-a",
        slug_perm: "js-yaml-4-2-0",
        name: "js-yaml",
        version: "4.2.0",
        format: "npm",
        is_copyable: true,
        status_str: "Completed",
        deny_policy_violated: false,
      },
      {
        namespace: "workspace-a",
        repository: "repo-a",
        slug_perm: "js-yaml-5-0-0",
        name: "js-yaml",
        version: "5.0.0",
        format: "npm",
        is_copyable: true,
        status_str: "Completed",
        deny_policy_violated: false,
      },
      {
        namespace: "workspace-a",
        repository: "repo-a",
        slug_perm: "js-yaml-4-2-0-rebuilt",
        name: "js-yaml",
        version: "4.2.0",
        format: "npm",
        is_copyable: true,
        status_str: "Completed",
        deny_policy_violated: false,
      },
      {
        namespace: "workspace-a",
        repository: "repo-a",
        slug_perm: "js-yaml-4-3-0",
        name: "js-yaml",
        version: "4.3.0",
        format: "npm",
        is_copyable: true,
        status_str: "Quarantined",
        deny_policy_violated: false,
      },
      {
        namespace: "workspace-a",
        repository: "repo-a",
        slug_perm: "js-yaml-4-4-0",
        name: "js-yaml",
        version: "4.4.0",
        format: "npm",
        is_copyable: true,
        status_str: "Completed",
        deny_policy_violated: true,
      },
      {
        namespace: "workspace-a",
        repository: "repo-a",
        slug_perm: "js-yaml-4-5-0",
        name: "js-yaml",
        version: "4.5.0",
        format: "npm",
        is_copyable: true,
        deny_policy_violated: false,
      },
      {
        namespace: "workspace-a",
        repository: "repo-a",
        slug_perm: "js-yaml-4-6-0",
        name: "js-yaml",
        version: "4.6.0",
        format: "npm",
        is_copyable: true,
        status_str: "Completed",
      },
    ];
    class RemediationHelper {
      async findSafeVersions() {
        return {
          success: true,
          complete: true,
          totalCount: 2,
          absenceProven: false,
          versions: candidates,
        };
      }
    }
    const vulnerabilityStateService = {
      prime(pkg) {
        if (pkg.version === source.version) return sourceState;
        return Object.freeze({ status: "unknown", complete: false, stale: false, records: [] });
      },
      async resolve(pkg) {
        if (pkg.version === source.version) return sourceState;
        if (["4.2.0", "4.3.0", "4.4.0", "4.5.0", "4.6.0"].includes(pkg.version)) {
          return Object.freeze({
            status: "complete-clean",
            complete: true,
            stale: false,
            count: 0,
            records: Object.freeze([]),
          });
        }
        return Object.freeze({
          status: "failed",
          complete: false,
          stale: false,
          count: null,
          records: Object.freeze([]),
        });
      },
    };
    let publishedItems = null;
    registerVulnerabilityCommands(vulnerabilityDeps(registration, {
      RemediationHelper,
      vulnerabilityStateService,
      vscode: {
        QuickPickItemKind: { Separator: 1 },
        window: {
          async showQuickPick(items) {
            publishedItems = items;
            return undefined;
          },
          showInformationMessage() {},
          showWarningMessage() {},
          showErrorMessage() {},
        },
      },
    }));

    await registration.handlers.get("cloudsmith-vsc.findSafeVersion")(source);

    assert(publishedItems);
    assert.deepStrictEqual(
      publishedItems.filter(item => item.package).map(item => item.package.version),
      ["4.2.0", "4.2.0"]
    );
    assert.doesNotMatch(
      publishedItems.find(item => item.package)?.description || "",
      /null|undefined/u
    );
    const candidateDetails = publishedItems
      .filter(item => item.package)
      .map(item => item.detail);
    assert.strictEqual(new Set(candidateDetails).size, 2);
    assert(candidateDetails.some(detail => /js-yaml-4-2-0-rebuilt/u.test(detail)));
  });

  test("safe-version install copies the same prerequisite guidance as package install", async () => {
    const registration = recorder();
    const copied = [];
    let picker = 0;
    class RemediationHelper {
      async findSafeVersions() {
        return {
          success: true,
          complete: true,
          totalCount: 1,
          absenceProven: false,
          versions: [{
            namespace: "workspace-a",
            repository: "repo-a",
            slug_perm: "widget-2-0-0",
            name: "widget",
            version: "2.0.0",
            format: "cargo",
            is_copyable: true,
            status_str: "Completed",
            deny_policy_violated: false,
          }],
        };
      }
    }
    class GuidanceBuilder {
      static build() {
        return {
          command: "# Verify package details before running\ncargo add widget@=2.0.0 --registry cloudsmith-repo",
          note: "Add [registries.cloudsmith-repo] to .cargo/config.toml first.",
        };
      }
      static toClipboardCommand(command) {
        return command.replace("# Verify package details before running\n", "");
      }
    }
    registerVulnerabilityCommands(vulnerabilityDeps(registration, {
      InstallCommandBuilder: GuidanceBuilder,
      RemediationHelper,
      vscode: {
        QuickPickItemKind: { Separator: 1 },
        workspace: { getConfiguration: () => ({ get: () => false }) },
        env: { clipboard: { async writeText(value) { copied.push(value); } } },
        window: {
          async showQuickPick(items) {
            picker += 1;
            if (picker === 1) return items.find(item => item.package);
            return items.find(item => item.id === "install");
          },
          showInformationMessage() {},
          showWarningMessage() {},
          showErrorMessage() {},
        },
      },
    }));

    await registration.handlers.get("cloudsmith-vsc.findSafeVersion")(exactPackage({
      format: "cargo",
    }));

    assert.deepStrictEqual(copied, [
      "cargo add widget@=2.0.0 --registry cloudsmith-repo\n\n# Note\n# Add [registries.cloudsmith-repo] to .cargo/config.toml first.",
    ]);
  });

  test("safe-version Maven copy is explicitly setup guidance, never a shell-command claim", async () => {
    const registration = recorder();
    const copied = [];
    const informationMessages = [];
    let picker = 0;
    let actionLabel = null;
    class RemediationHelper {
      async findSafeVersions() {
        return {
          success: true,
          complete: true,
          totalCount: 1,
          absenceProven: false,
          versions: [apiPackageRecord({
            namespace: "workspace-a",
            repository: "repo-a",
            slug_perm: "widget-maven-2-0-0",
            name: "widget",
            version: "2.0.0",
            format: "maven",
            identifiers: {
              group_id: "com.example",
              extension: "test-jar",
              classifier: "tests",
            },
            deny_policy_violated: false,
          })],
        };
      }
    }
    registerVulnerabilityCommands(vulnerabilityDeps(registration, {
      InstallCommandBuilder: ProductionInstallCommandBuilder,
      InstallCommandValidationError: ProductionInstallCommandValidationError,
      RemediationHelper,
      vscode: {
        QuickPickItemKind: { Separator: 1 },
        env: { clipboard: { async writeText(value) { copied.push(value); } } },
        window: {
          async showQuickPick(items) {
            picker += 1;
            if (picker === 1) return items.find(item => item.package);
            const install = items.find(item => item.id === "install");
            actionLabel = install?.label || null;
            return install;
          },
          showInformationMessage(message) { informationMessages.push(message); },
          showWarningMessage() {},
          showErrorMessage() {},
        },
      },
    }));

    await registration.handlers.get("cloudsmith-vsc.findSafeVersion")(exactPackage({
      format: "maven",
      name: "widget",
      coordinateName: "com.example:widget",
      qualifiers: { type: "test-jar", classifier: "tests" },
    }));

    assert.strictEqual(actionLabel, "$(file-code) Copy Maven setup guidance");
    assert.strictEqual(copied.length, 1);
    assert.match(copied[0], /^# Maven package setup/u);
    assert.match(copied[0], /Setup guidance only/u);
    assert.match(copied[0], /<groupId>com\.example<\/groupId>/u);
    assert.match(copied[0], /<type>test-jar<\/type>/u);
    assert.match(copied[0], /<classifier>tests<\/classifier>/u);
    assert.deepStrictEqual(informationMessages, [
      "Maven setup guidance copied. Merge the XML into the named files; do not run it as a shell command.",
    ]);
  });

  test("safe-version URL construction failure is a warning", async () => {
    const registration = recorder();
    const warnings = [];
    let picker = 0;
    class RemediationHelper {
      async findSafeVersions() {
        return {
          success: true,
          complete: true,
          totalCount: 1,
          versions: [{
            namespace: "workspace-a",
            repository: "repo-a",
            slug_perm: "safe-package",
            name: "widget",
            version: "2.0.0",
            format: "npm",
            is_copyable: true,
            status_str: "Completed",
            deny_policy_violated: false,
          }],
        };
      }
    }
    registerVulnerabilityCommands(vulnerabilityDeps(registration, {
      RemediationHelper,
      buildPackageUrl: () => null,
      vscode: {
        QuickPickItemKind: { Separator: 1 },
        window: {
          async showQuickPick(items) {
            picker += 1;
            return picker === 1
              ? items.find(item => item.package)
              : items.find(item => item.id === "open");
          },
          showWarningMessage: message => warnings.push(message),
          showErrorMessage() {},
        },
      },
    }));
    await registration.handlers.get("cloudsmith-vsc.findSafeVersion")(exactPackage());
    assert.deepStrictEqual(warnings, ["Could not open this package in Cloudsmith."]);
  });
});

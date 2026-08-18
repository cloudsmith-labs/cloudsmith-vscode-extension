// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { verifyArchitecture } = require("./verifier");

const repositoryRoot = path.resolve(__dirname, "../..");
const fixturesRoot = path.join(repositoryRoot, "test/fixtures/architecture");

function fixtureMetadata(root) {
  const hasModels = fs.statSync(path.join(root, "models"), { throwIfNoEntry: false })?.isDirectory();
  const hasUtil = fs.statSync(path.join(root, "util"), { throwIfNoEntry: false })?.isDirectory();
  const runtimeRoots = ["commands", "domain", "models", "util", "views"].filter(
    entry => fs.statSync(path.join(root, entry), { throwIfNoEntry: false })?.isDirectory()
  );
  return {
    schemaVersion: 1,
    compositionFile: "extension.js",
    cycleExemptions: [],
    limits: {
      maxDepth: 12,
      maxDiagnostics: 64,
      maxEntries: 128,
      maxFileBytes: 64 * 1024,
      maxFiles: 64,
      maxImports: 128,
      maxTotalBytes: 512 * 1024,
    },
    ignoredSegments: ["node_modules", "coverage", "out", "vendor"],
    adapterFiles: [],
    canonicalFactoryFiles: ["domain/package.js"],
    commandRegistrationFiles: ["commands/registrar.js", "commands/general.js"],
    internalCommandIds: [],
    nonJavaScriptPackageFiles: [],
    runtimeRoots,
    upstreamOwnership: {
      checkerModule: "util/upstreamChecker.js",
      constructorExport: "UpstreamChecker",
      authorityModule: "util/upstreamRuntime.js",
      authorityExport: "UpstreamRuntime",
      compositionFile: "extension.js",
      safeConsumerExports: ["isSafeInventoryUpstream", "sanitizeSafeInventoryUpstream"],
      deprecatedAcquisitionExports: ["getAllUpstreamData", "getUpstreamDataForFormats"],
    },
    layers: [
      {
        id: "domain-core",
        roots: ["domain"],
        files: [],
        excludeFiles: [],
        allowedLayers: ["domain-core"],
        allowedExternals: [],
        allowedResources: [],
      },
      ...(hasModels ? [{
        id: "model-presentation",
        roots: ["models"],
        files: [],
        excludeFiles: [],
        allowedLayers: ["domain-core", ...(hasUtil ? ["legacy-service"] : []), "model-presentation"],
        allowedExternals: [],
        allowedResources: [],
      }] : []),
      ...(hasUtil ? [{
        id: "legacy-service",
        roots: ["util"],
        files: [],
        excludeFiles: ["util/upstreamRuntime.js"],
        allowedLayers: ["domain-core", "legacy-service"],
        allowedExternals: ["vscode"],
        allowedResources: [],
      }, {
        id: "application-upstream-runtime",
        roots: [],
        files: ["util/upstreamRuntime.js"],
        excludeFiles: [],
        allowedLayers: ["application-upstream-runtime", "legacy-service"],
        allowedExternals: [],
        allowedResources: [],
      }] : []),
      {
        id: "command-shared",
        roots: [],
        files: ["commands/registrar.js"],
        excludeFiles: [],
        allowedLayers: ["command-shared", "domain-core"],
        allowedExternals: [],
        allowedResources: [],
      },
      {
        id: "command-general",
        roots: [],
        files: ["commands/general.js"],
        excludeFiles: [],
        allowedLayers: ["command-general", "command-shared", "domain-core"],
        allowedExternals: [],
        allowedResources: [],
      },
    ],
    registrars: [{
      file: "commands/general.js",
      function: "registerGeneralCommands",
      commands: ["cloudsmith-vsc.valid"],
    }],
  };
}

function copyFixture(name) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsmith-architecture-"));
  fs.cpSync(path.join(fixturesRoot, "valid"), root, { recursive: true });
  if (name !== "valid") {
    fs.cpSync(path.join(fixturesRoot, name), root, { recursive: true, force: true });
  }
  return root;
}

function withFixture(name, callback) {
  const root = copyFixture(name);
  try {
    return callback(root, fixtureMetadata(root));
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
}

function fixtureManifest(root, metadata) {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  manifest.main ??= "./extension.js";
  manifest.files ??= [
    "extension.js",
    ...metadata.runtimeRoots.map(runtimeRoot => `${runtimeRoot}/**/*.js`),
    ...metadata.nonJavaScriptPackageFiles,
  ];
  return manifest;
}

function resultFor(name, mutate = null) {
  return withFixture(name, (root, metadata) => {
    mutate?.(root, metadata);
    const manifest = fixtureManifest(root, metadata);
    return verifyArchitecture({ root, metadata, manifest, throwOnError: false });
  });
}

function assertDiagnostic(result, code, relativePath) {
  assert.ok(
    result.diagnostics.some((entry) => entry.code === code && entry.path === relativePath),
    `Expected ${code} for ${relativePath}; received ${JSON.stringify(result.diagnostics)}`,
  );
}

function runArchitectureSelfTests() {
  assert.deepStrictEqual(resultFor("valid").diagnostics, []);
  assertDiagnostic(resultFor("pure-vscode"), "ARCH_EXTERNAL_IMPORT", "domain/bad.js");
  assertDiagnostic(resultFor("pure-builtin"), "ARCH_EXTERNAL_IMPORT", "domain/bad.js");
  assertDiagnostic(resultFor("pure-model"), "ARCH_LAYER_EDGE", "domain/bad.js");
  assertDiagnostic(resultFor("extension-registration"), "ARCH_EXTENSION_REGISTRATION", "extension.js");
  assertDiagnostic(resultFor("computed-registration"), "ARCH_EXTENSION_REGISTRATION", "extension.js");
  assertDiagnostic(resultFor("variable-registration"), "ARCH_EXTENSION_COMMAND_API", "extension.js");
  assertDiagnostic(resultFor("joined-registration"), "ARCH_EXTENSION_COMMAND_API", "extension.js");
  assertDiagnostic(resultFor("helper-registration"), "ARCH_EXTENSION_COMMAND_API", "extension.js");
  assertDiagnostic(resultFor("factory-registration"), "ARCH_EXTENSION_REGISTRATION_FLOW", "extension.js");
  assertDiagnostic(resultFor("factory-side-effect"), "ARCH_REGISTRATION_FACTORY_SOURCE", "commands/registrar.js");
  assertDiagnostic(resultFor("conditional-factory"), "ARCH_REGISTRATION_FACTORY_SOURCE", "commands/registrar.js");
  assertDiagnostic(resultFor("environment-factory"), "ARCH_REGISTRATION_FACTORY_SOURCE", "commands/registrar.js");
  assertDiagnostic(resultFor("fake-registration-factory"), "ARCH_EXTENSION_REGISTRATION_FLOW", "extension.js");
  assertDiagnostic(resultFor("rogue-registration"), "ARCH_REGISTRATION_OWNERSHIP", "util/rogue.js");
  assertDiagnostic(resultFor("unclassified-command"), "ARCH_UNCLASSIFIED_COMMAND", "commands/rogue.js");
  assertDiagnostic(resultFor("bridge-reverse"), "ARCH_LAYER_EDGE", "util/bridge.js");
  assertDiagnostic(resultFor("duplicate-registration"), "ARCH_COMMAND_DUPLICATE", "commands/general.js");
  assertDiagnostic(resultFor("missing-manifest"), "ARCH_COMMAND_REGISTRATION_MISSING", "commands");
  assertDiagnostic(resultFor("noop-disposable"), "ARCH_REGISTRAR_OWNERSHIP_DISPOSAL", "commands/general.js");
  assertDiagnostic(resultFor("deferred-registration"), "ARCH_DEFERRED_COMMAND_REGISTRATION", "commands/general.js");
  assertDiagnostic(resultFor("deferred-alias-registration"), "ARCH_REGISTRAR_STATIC_INVENTORY", "commands/general.js");
  assertDiagnostic(resultFor("conditional-registration"), "ARCH_REGISTRAR_STATIC_INVENTORY", "commands/general.js");
  assertDiagnostic(resultFor("descriptor-registration"), "ARCH_REGISTRAR_STATIC_INVENTORY", "commands/general.js");
  assertDiagnostic(resultFor("reflective-registration"), "ARCH_REFLECTIVE_COMMAND_ACCESS", "commands/general.js");
  assertDiagnostic(resultFor("alternate-registration"), "ARCH_COMMAND_REGISTRATION_API", "commands/general.js");
  assertDiagnostic(resultFor("destructured-command-registry"), "ARCH_COMMAND_API_OWNERSHIP", "util/rogue.js");
  assertDiagnostic(resultFor("computed-vscode-registry"), "ARCH_COMMAND_API_OWNERSHIP", "util/rogue.js");
  assertDiagnostic(resultFor("reflective-vscode-registry"), "ARCH_COMMAND_API_OWNERSHIP", "util/rogue.js");
  assertDiagnostic(resultFor("map-vscode-registry"), "ARCH_COMMAND_API_OWNERSHIP", "util/rogue.js");
  assertDiagnostic(resultFor("object-vscode-registry"), "ARCH_COMMAND_API_OWNERSHIP", "util/rogue.js");
  assertDiagnostic(resultFor("legacy-alias"), "ARCH_LEGACY_PACKAGE_ALIAS", "commands/general.js");
  assertDiagnostic(resultFor("joined-legacy-alias"), "ARCH_COMPUTED_PACKAGE_ACCESS", "commands/general.js");
  assertDiagnostic(resultFor("ignored-runtime"), "ARCH_RUNTIME_IGNORED_SEGMENT", "domain/vendor");
  assertDiagnostic(resultFor("entrypoint-mismatch"), "ARCH_RUNTIME_ENTRYPOINT", "package.json");
  assertDiagnostic(resultFor("broad-package"), "ARCH_RUNTIME_INVENTORY", "package.json");
  assertDiagnostic(resultFor("dynamic-composition"), "ARCH_DYNAMIC_IMPORT", "extension.js");
  assertDiagnostic(resultFor("eval-runtime"), "ARCH_DYNAMIC_CODE", "util/rogue.js");
  assertDiagnostic(resultFor("global-eval-runtime"), "ARCH_DYNAMIC_CODE", "util/rogue.js");
  assertDiagnostic(resultFor("function-constructor"), "ARCH_DYNAMIC_CODE", "util/rogue.js");
  assertDiagnostic(resultFor("computed-module-loader"), "ARCH_DYNAMIC_IMPORT", "util/rogue.js");
  assertDiagnostic(resultFor("pure-module-loader"), "ARCH_DYNAMIC_IMPORT", "domain/bad.js");
  assertDiagnostic(resultFor("pure-process-loader"), "ARCH_DYNAMIC_IMPORT", "domain/bad.js");
  assertDiagnostic(
    resultFor("upstream-command-construction"),
    "ARCH_UPSTREAM_CONSTRUCTION",
    "commands/general.js",
  );
  assertDiagnostic(
    resultFor("upstream-provider-construction"),
    "ARCH_UPSTREAM_CONSTRUCTION",
    "models/bad.js",
  );
  assertDiagnostic(
    resultFor("upstream-wrapper-usage"),
    "ARCH_UPSTREAM_WRAPPER",
    "models/bad.js",
  );

  const hiddenUpstreamConstruction = resultFor("upstream-hidden-helper");
  assertDiagnostic(
    hiddenUpstreamConstruction,
    "ARCH_UPSTREAM_MODULE_ACCESS",
    "util/hiddenCheckerFactory.js",
  );
  assertDiagnostic(
    hiddenUpstreamConstruction,
    "ARCH_UPSTREAM_CONSTRUCTION",
    "util/upstreamRuntime.js",
  );

  const secondUpstreamAuthority = resultFor("upstream-second-authority");
  assertDiagnostic(
    secondUpstreamAuthority,
    "ARCH_UPSTREAM_CONSTRUCTION",
    "commands/general.js",
  );
  assertDiagnostic(
    secondUpstreamAuthority,
    "ARCH_UPSTREAM_CONSTRUCTION",
    "extension.js",
  );

  assertDiagnostic(resultFor("nonjs-directory", (root, metadata) => {
    metadata.nonJavaScriptPackageFiles.push("rogue");
  }), "ARCH_METADATA_PACKAGE_FILE", "architecture.json");

  assertDiagnostic(resultFor("executable-package", (root, metadata) => {
    metadata.nonJavaScriptPackageFiles.push("rogue.cjs");
  }), "ARCH_METADATA_PACKAGE_FILE", "architecture.json");

  assertDiagnostic(resultFor("unsafe-resource", (root, metadata) => {
    metadata.layers[0].allowedResources.push("rogue.png");
  }), "ARCH_METADATA_RESOURCE_ALLOWLIST", "architecture.json");

  assertDiagnostic(resultFor("valid", (root, metadata) => {
    metadata.limits.maxEntries = Number.MAX_SAFE_INTEGER;
  }), "ARCH_METADATA_LIMIT", "architecture.json");

  assertDiagnostic(resultFor("wide-tree", (root, metadata) => {
    metadata.limits.maxEntries = 8;
  }), "ARCH_SCAN_ENTRIES", "domain/wide");

  assertDiagnostic(resultFor("valid", (root, metadata) => {
    metadata.layers[0].excludeFiles.push("domain/package.js");
  }), "ARCH_METADATA_ORPHAN_EXCLUSION", "architecture.json");

  assertDiagnostic(resultFor("valid", (root) => {
    fs.writeFileSync(
      path.join(root, "extension.js"),
      "// Copyright 2026 Cloudsmith Ltd. All rights reserved.\nfunction activate(vscode) { const { registerCommand: register } = vscode.commands; return register('cloudsmith-vsc.valid', () => undefined); } module.exports = { activate };\n",
    );
  }), "ARCH_EXTENSION_REGISTRATION", "extension.js");

  assertDiagnostic(resultFor("valid", (root) => {
    fs.writeFileSync(
      path.join(root, "extension.js"),
      "// Copyright 2026 Cloudsmith Ltd. All rights reserved.\nfunction activate(vscode) { return vscode.commands['register' + 'Command']('cloudsmith-vsc.valid', () => undefined); } module.exports = { activate };\n",
    );
  }), "ARCH_EXTENSION_REGISTRATION", "extension.js");

  assertDiagnostic(resultFor("valid", (root) => {
    fs.writeFileSync(
      path.join(root, "commands/general.js"),
      "// Copyright 2026 Cloudsmith Ltd. All rights reserved.\nconst { aggregate } = require('./registrar'); function registerGeneralCommands({ registerCommand }) { return aggregate([registerCommand('cloudsmith-vsc.valid', selection => selection['cloudsmith' + 'Workspace'])]); } module.exports = { registerGeneralCommands };\n",
    );
  }), "ARCH_LEGACY_PACKAGE_ALIAS", "commands/general.js");

  assertDiagnostic(resultFor("valid", (root) => {
    fs.writeFileSync(
      path.join(root, "commands/general.js"),
      "// Copyright 2026 Cloudsmith Ltd. All rights reserved.\nconst { aggregate } = require('./registrar'); function registerGeneralCommands({ registerCommand }) { return aggregate([registerCommand('cloudsmith-vsc.valid', selection => { const { slug_perm_raw: id } = selection; return id; })]); } module.exports = { registerGeneralCommands };\n",
    );
  }), "ARCH_LEGACY_PACKAGE_ALIAS", "commands/general.js");

  assertDiagnostic(resultFor("valid", (root) => {
    fs.writeFileSync(
      path.join(root, "domain/dynamic.js"),
      "// Copyright 2026 Cloudsmith Ltd. All rights reserved.\nconst target = './package'; module.exports = require(target);\n",
    );
  }), "ARCH_DYNAMIC_IMPORT", "domain/dynamic.js");

  assertDiagnostic(resultFor("valid", (root) => {
    fs.writeFileSync(
      path.join(root, "domain/escape.js"),
      "// Copyright 2026 Cloudsmith Ltd. All rights reserved.\nmodule.exports = require('../../outside');\n",
    );
  }), "ARCH_ROOT_ESCAPE", "domain/escape.js");

  assertDiagnostic(resultFor("valid", (root) => {
    fs.mkdirSync(path.join(root, "domain/vendor"));
    fs.writeFileSync(
      path.join(root, "domain/vendor/hidden.js"),
      "// Copyright 2026 Cloudsmith Ltd. All rights reserved.\nmodule.exports = require('vscode');\n",
    );
    fs.writeFileSync(
      path.join(root, "domain/hiddenImport.js"),
      "// Copyright 2026 Cloudsmith Ltd. All rights reserved.\nmodule.exports = require('./vendor/hidden');\n",
    );
  }), "ARCH_UNSCANNED_IMPORT", "domain/hiddenImport.js");

  assertDiagnostic(resultFor("valid", (root) => {
    fs.writeFileSync(
      path.join(root, "domain/cycleA.js"),
      "// Copyright 2026 Cloudsmith Ltd. All rights reserved.\nmodule.exports = require('./cycleB');\n",
    );
    fs.writeFileSync(
      path.join(root, "domain/cycleB.js"),
      "// Copyright 2026 Cloudsmith Ltd. All rights reserved.\nmodule.exports = require('./cycleA');\n",
    );
  }), "ARCH_DEPENDENCY_CYCLE", "domain/cycleA.js");

  assertDiagnostic(resultFor("valid", (root, metadata) => {
    fs.writeFileSync(
      path.join(root, "domain/large.js"),
      `// Copyright 2026 Cloudsmith Ltd. All rights reserved.\nmodule.exports = '${"x".repeat(1024)}';\n`,
    );
    metadata.limits.maxFileBytes = 512;
  }), "ARCH_SCAN_FILE_BYTES", "domain/large.js");

  const fileBound = resultFor("valid", (root, metadata) => {
    fs.writeFileSync(path.join(root, "domain/extra.js"), "// Copyright 2026 Cloudsmith Ltd. All rights reserved.\n");
    metadata.limits.maxFiles = 3;
  });
  assert.ok(fileBound.diagnostics.some((entry) => entry.code === "ARCH_SCAN_FILES"));

  assertDiagnostic(resultFor("valid", (root, metadata) => {
    metadata.compositionFile = "..\\extension.js";
  }), "ARCH_METADATA_PATH", "architecture.json");

  const caseCollision = resultFor("valid", (root, metadata) => {
    fs.writeFileSync(path.join(root, "domain/Case.js"), "// Copyright 2026 Cloudsmith Ltd. All rights reserved.\n");
    if (process.platform !== "win32") {
      fs.writeFileSync(path.join(root, "domain/case.js"), "// Copyright 2026 Cloudsmith Ltd. All rights reserved.\n");
    }
    metadata.layers[0].files.push("domain/case.js");
  });
  assert.ok(caseCollision.diagnostics.some((entry) => entry.code === "ARCH_SCAN_CASE_COLLISION"));

  const symlinkRoot = copyFixture("valid");
  try {
    const commands = path.join(symlinkRoot, "commands");
    const target = path.join(symlinkRoot, "real-commands");
    fs.renameSync(commands, target);
    fs.symlinkSync(target, commands, process.platform === "win32" ? "junction" : "dir");
    const symlinkResult = verifyArchitecture({
      root: symlinkRoot,
      metadata: fixtureMetadata(symlinkRoot),
      manifest: fixtureManifest(symlinkRoot, fixtureMetadata(symlinkRoot)),
      throwOnError: false,
    });
    assertDiagnostic(symlinkResult, "ARCH_SCAN_SYMLINK", "commands");
  } finally {
    fs.rmSync(symlinkRoot, { force: true, recursive: true });
  }

  return { invalidFixtures: 66, validFixtures: 1 };
}

module.exports = {
  assertDiagnostic,
  fixtureMetadata,
  resultFor,
  runArchitectureSelfTests,
};

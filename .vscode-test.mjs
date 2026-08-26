// Copyright 2026 Cloudsmith Ltd. All rights reserved.
import { defineConfig } from "@vscode/test-cli";
import os from "os";
import path from "path";
import { fileURLToPath } from "url";
import testInventories from "./test/testInventories.js";

const { VSCODE_CORE_TESTS, VSCODE_SMOKE_TESTS } = testInventories;
const repositoryRoot = path.dirname(fileURLToPath(import.meta.url));
const TEST_HARNESS_EXTENSION_PATH = path.join(repositoryRoot, "test", "harness-extension");

const version = process.env.VSCODE_TEST_VERSION || "1.134.0";
if (!/^\d+\.\d+\.\d+$/.test(version)) {
  throw new Error("VSCODE_TEST_VERSION must be an exact numeric VS Code version");
}

const evidenceReporter = process.env.CLOUDSMITH_QUALITY_TEST_EVIDENCE
  ? path.join(process.cwd(), "scripts", "quality", "mocha-evidence-reporter.js")
  : null;

function mochaOptions(timeout) {
  return {
    failZero: true,
    forbidOnly: true,
    forbidPending: true,
    timeout,
    ...(evidenceReporter ? { reporter: evidenceReporter } : {}),
  };
}

const common = {
  version,
  extensionDevelopmentPath: TEST_HARNESS_EXTENSION_PATH,
  skipExtensionDependencies: true,
};

function isolatedHost(label) {
  const runRoot = path.join(os.tmpdir(), `cloudsmith-vsc-${label}-${process.pid}`);
  const extensionsDir = path.join(runRoot, "extensions");
  return {
    env: {
      EXPECTED_EXTENSIONS_DIR: extensionsDir,
      EXPECTED_VSCODE_VERSION: version,
    },
    launchArgs: [
      `--user-data-dir=${path.join(runRoot, "user-data")}`,
      `--extensions-dir=${extensionsDir}`,
    ],
  };
}

export default defineConfig([
  {
    ...common,
    ...isolatedHost("core"),
    label: "core",
    files: VSCODE_CORE_TESTS,
    mocha: mochaOptions(20000),
  },
  {
    ...common,
    ...isolatedHost("smoke"),
    label: "smoke",
    files: VSCODE_SMOKE_TESTS,
    mocha: mochaOptions(20000),
  },
]);

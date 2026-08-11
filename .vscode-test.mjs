// Copyright 2026 Cloudsmith Ltd. All rights reserved.
import { defineConfig } from "@vscode/test-cli";
import os from "os";
import path from "path";

const version = process.env.VSCODE_TEST_VERSION || "1.132.0";
if (!/^\d+\.\d+\.\d+$/.test(version)) {
  throw new Error("VSCODE_TEST_VERSION must be an exact numeric VS Code version");
}

const common = {
  version,
  env: {
    EXPECTED_VSCODE_VERSION: version,
  },
  skipExtensionDependencies: true,
};

function userDataLaunchArgs(label) {
  return [`--user-data-dir=${path.join(os.tmpdir(), `cloudsmith-vsc-${label}-${process.pid}`)}`];
}

export default defineConfig([
  {
    ...common,
    label: "core",
    launchArgs: userDataLaunchArgs("core"),
    files: [
      "test/*.test.js",
      "test/lockfileParsers/*.test.js",
      "test/integration/manifestParser.test.js",
      "test/integration/licenseClassifier.test.js",
      "test/integration/installCommand.test.js",
    ],
    mocha: {
      failZero: true,
      forbidOnly: true,
      forbidPending: true,
      timeout: 20000,
    },
  },
  {
    ...common,
    label: "smoke",
    launchArgs: userDataLaunchArgs("smoke"),
    files: [
      "test/activation.test.js",
      "test/releaseGate.test.js",
    ],
    mocha: {
      failZero: true,
      forbidOnly: true,
      forbidPending: true,
      timeout: 20000,
    },
  },
  {
    ...common,
    label: "live",
    launchArgs: userDataLaunchArgs("live"),
    files: [
      "test/integration/search.test.js",
      "test/integration/vulnerabilities.test.js",
    ],
    mocha: {
      failZero: true,
      forbidOnly: true,
      timeout: 20000,
    },
  },
]);

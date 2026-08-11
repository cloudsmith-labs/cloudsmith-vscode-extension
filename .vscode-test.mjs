// Copyright 2026 Cloudsmith Ltd. All rights reserved.
import { defineConfig } from "@vscode/test-cli";
import os from "os";
import path from "path";
import testInventories from "./test/testInventories.js";

const { LIVE_TESTS, VSCODE_CORE_TESTS, VSCODE_SMOKE_TESTS } = testInventories;

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
    files: VSCODE_CORE_TESTS,
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
    files: VSCODE_SMOKE_TESTS,
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
    files: LIVE_TESTS,
    mocha: {
      failZero: true,
      forbidOnly: true,
      forbidPending: true,
      timeout: 20000,
    },
  },
]);

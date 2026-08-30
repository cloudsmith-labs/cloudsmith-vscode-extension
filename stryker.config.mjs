// Copyright 2026 Cloudsmith Ltd. All rights reserved.

import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const mutationBaseline = require("./quality/mutation-baseline.json");
const mutationTestFiles = Object.freeze([...new Set(
  mutationBaseline.scope.flatMap(target => mutationBaseline.files[target].testFiles)
)].sort());

export default {
  mutate: [...mutationBaseline.scope],
  testRunner: "mocha",
  testFiles: mutationTestFiles,
  mochaOptions: {
    ui: "tdd",
    spec: mutationTestFiles,
    "no-config": true,
    "no-package": true,
    "no-opts": true,
  },
  coverageAnalysis: "perTest",
  ignoreStatic: true,
  reporters: ["clear-text", "progress", "json", "html"],
  jsonReporter: { fileName: ".quality/mutation/mutation.json" },
  htmlReporter: { fileName: ".quality/mutation/mutation.html" },
  incrementalFile: ".quality/mutation/stryker-incremental.json",
  tempDirName: ".stryker-tmp",
  cleanTempDir: "always",
  ignorePatterns: [
    ".vscode-test",
    ".quality",
    "internal_docs",
    "out",
    "coverage",
    "*.vsix",
  ],
  concurrency: 4,
  timeoutMS: 10_000,
  // The wrapper applies the measured core and per-file changed-mode floors.
  // A single Stryker break value cannot represent both aggregate and scoped runs.
  thresholds: {
    high: mutationBaseline.thresholds.high,
    low: mutationBaseline.thresholds.low,
    break: 0,
  },
  allowEmpty: false,
};

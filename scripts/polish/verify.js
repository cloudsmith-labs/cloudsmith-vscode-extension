#!/usr/bin/env node
// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const { runSelfTests } = require("./self-test");
const { verifyRepository } = require("./verifier");

try {
  const result = verifyRepository();
  runSelfTests();
  console.log(`M14 polish verification passed: ${result.activeSettings} active settings, ${result.deprecatedSettings} deprecated settings, ${result.media} approved media files.`);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}

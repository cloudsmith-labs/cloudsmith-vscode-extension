// Copyright 2026 Cloudsmith Ltd. All rights reserved.
const path = require("path");
const { runArchitectureSelfTests } = require("./self-test");
const { verifyArchitecture } = require("./verifier");

function main() {
  const root = path.resolve(__dirname, "../..");
  const result = verifyArchitecture({ root });
  const selfTests = runArchitectureSelfTests();
  console.log(
    `Verified architecture across ${result.files.length} files and ${result.observed.length} executable command registrations; `
    + `${selfTests.validFixtures} valid and ${selfTests.invalidFixtures} invalid scanner fixtures passed.`,
  );
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

module.exports = { main };

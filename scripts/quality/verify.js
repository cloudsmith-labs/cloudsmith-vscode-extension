// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { verifyQualityContracts } = require("./verify-workflows");

const result = verifyQualityContracts();
if (result.errors.length > 0) {
  for (const error of result.errors) console.error(`quality: ${error}`);
  process.exit(1);
}
console.log(`Verified ${result.workflowCount} critical workflow contracts and every declared action/WebView boundary.`);

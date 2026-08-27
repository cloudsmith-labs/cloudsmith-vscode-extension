// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const { resetLocalQualificationProfile } = require("./qualification-profile");

function main(arguments_ = process.argv.slice(2)) {
  if (!Array.isArray(arguments_) || arguments_.length !== 0) {
    throw new Error("Local qualification reset accepts no path or profile arguments.");
  }
  const removed = resetLocalQualificationProfile();
  process.stdout.write(removed
    ? "Removed the dedicated local Cloudsmith qualification profile.\n"
    : "The dedicated local Cloudsmith qualification profile does not exist.\n");
  return removed;
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { main };

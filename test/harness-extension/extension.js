// Copyright 2026 Cloudsmith Ltd. All rights reserved.

function activate() {
  return Object.freeze({ kind: "credential-free-test-harness" });
}

function deactivate() {
  return undefined;
}

module.exports = { activate, deactivate };

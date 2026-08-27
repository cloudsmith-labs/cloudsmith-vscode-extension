// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const {
  createAPIKeyCredential,
  serializeCredential,
} = require("../../util/credentialEnvelope");
const { consumeCredentialHandoff } = require("./handoff");

const AUTH_TOKEN_KEY = "cloudsmith-vsc.authToken";
const SEED_COMMAND = "cloudsmith-vsc.qualification.authBootstrap.seed";
const CLEANUP_COMMAND = "cloudsmith-vsc.qualification.authBootstrap.cleanup";

async function seedCredential(context, request, adapters = {}) {
  if (!context?.secrets || typeof context.secrets.store !== "function") {
    throw new Error("Qualification SecretStorage is unavailable.");
  }
  if (!request || typeof request !== "object" || Array.isArray(request)
    || Object.keys(request).sort().join(",") !== "capability,operation"
    || request.operation !== "seed") {
    throw new Error("Qualification seed request is invalid.");
  }
  const consume = adapters.consumeCredentialHandoff || consumeCredentialHandoff;
  const createCredential = adapters.createAPIKeyCredential || createAPIKeyCredential;
  const serialize = adapters.serializeCredential || serializeCredential;
  let credential;
  try {
    credential = consume(request.capability);
    const envelope = serialize(createCredential(credential));
    credential = undefined;
    await context.secrets.store(AUTH_TOKEN_KEY, envelope);
    return Object.freeze({ status: "stored" });
  } finally {
    credential = undefined;
  }
}

async function cleanupCredential(context) {
  if (!context?.secrets || typeof context.secrets.delete !== "function") {
    throw new Error("Qualification SecretStorage is unavailable.");
  }
  await context.secrets.delete(AUTH_TOKEN_KEY);
  return Object.freeze({ status: "deleted" });
}

function activate(context) {
  const vscode = require("vscode");
  context.subscriptions.push(
    vscode.commands.registerCommand(SEED_COMMAND, request => seedCredential(context, request)),
    vscode.commands.registerCommand(CLEANUP_COMMAND, () => cleanupCredential(context)),
  );
}

function deactivate() {}

module.exports = {
  AUTH_TOKEN_KEY,
  CLEANUP_COMMAND,
  SEED_COMMAND,
  activate,
  cleanupCredential,
  deactivate,
  seedCredential,
};

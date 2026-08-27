// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const path = require("path");

const MANIFEST = require("./package.json");
const EXTENSION_ID = `${MANIFEST.publisher}.${MANIFEST.name}`;
const REQUEST_ENV = "CLOUDSMITH_AUTH_BOOTSTRAP_REQUEST";

function parseRequest(environment = process.env) {
  const encoded = environment[REQUEST_ENV];
  delete environment[REQUEST_ENV];
  if (typeof encoded !== "string" || encoded.length === 0 || encoded.length > 16 * 1024) {
    throw new Error("Authenticated CI bootstrap request is missing or invalid.");
  }
  let request;
  try {
    request = JSON.parse(encoded);
  } catch {
    throw new Error("Authenticated CI bootstrap request is not valid JSON.");
  }
  if (!request || typeof request !== "object" || Array.isArray(request)
    || Object.keys(request).sort().join(",") !== (
      request.operation === "seed" ? "capability,operation" : "operation"
    )
    || !new Set(["seed", "cleanup"]).has(request.operation)) {
    throw new Error("Authenticated CI bootstrap request has an invalid shape.");
  }
  return Object.freeze(request);
}

async function runWithVscode(vscode, request) {
  const extension = require("./extension");
  const owner = vscode.extensions?.getExtension?.(EXTENSION_ID);
  if (!owner || path.resolve(owner.extensionPath || "") !== __dirname
    || owner.packageJSON?.publisher !== MANIFEST.publisher
    || owner.packageJSON?.name !== MANIFEST.name
    || owner.packageJSON?.version !== MANIFEST.version) {
    throw new Error("Authenticated CI bootstrap is not owned by the exact same-ID companion.");
  }
  const command = request.operation === "seed"
    ? extension.SEED_COMMAND
    : extension.CLEANUP_COMMAND;
  const result = request.operation === "seed"
    ? await vscode.commands.executeCommand(command, request)
    : await vscode.commands.executeCommand(command);
  const expected = request.operation === "seed" ? "stored" : "deleted";
  if (!result || typeof result !== "object" || Array.isArray(result)
    || Object.keys(result).join(",") !== "status" || result.status !== expected) {
    throw new Error("Authenticated CI bootstrap command did not complete exactly.");
  }
}

async function run() {
  const request = parseRequest(process.env);
  const vscode = require("vscode");
  await runWithVscode(vscode, request);
}

module.exports = { EXTENSION_ID, REQUEST_ENV, parseRequest, run, runWithVscode };

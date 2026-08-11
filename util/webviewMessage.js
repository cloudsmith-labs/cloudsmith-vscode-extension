// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const MAX_MESSAGE_PROPERTIES = 2;
const MAX_COMMAND_LENGTH = 64;

/**
 * Copy a small, exact webview message without invoking accessors or accepting
 * inherited data. Contracts map command names to their required string fields.
 */
function parseWebviewMessage(message, contracts, stringLimits = {}) {
  if (!message || typeof message !== "object" || Array.isArray(message)) return null;

  let prototype;
  let keys;
  let descriptors;
  try {
    prototype = Object.getPrototypeOf(message);
    if (prototype !== Object.prototype && prototype !== null) return null;
    keys = Reflect.ownKeys(message);
    if (keys.length === 0 || keys.length > MAX_MESSAGE_PROPERTIES) return null;
    if (keys.some(key => typeof key !== "string")) return null;
    descriptors = Object.getOwnPropertyDescriptors(message);
  } catch {
    return null;
  }

  const commandDescriptor = descriptors.command;
  if (!isDataDescriptor(commandDescriptor)) return null;
  const command = commandDescriptor.value;
  if (
    typeof command !== "string"
    || command.length === 0
    || command.length > MAX_COMMAND_LENGTH
    || /[\u0000-\u001f\u007f]/.test(command)
  ) {
    return null;
  }

  const fields = contracts[command];
  if (!Array.isArray(fields)) return null;
  const expectedKeys = ["command", ...fields];
  if (keys.length !== expectedKeys.length || expectedKeys.some(key => !keys.includes(key))) {
    return null;
  }

  const parsed = { command };
  for (const field of fields) {
    const descriptor = descriptors[field];
    const limit = stringLimits[field];
    if (
      !isDataDescriptor(descriptor)
      || typeof descriptor.value !== "string"
      || descriptor.value.length === 0
      || !Number.isSafeInteger(limit)
      || limit < 1
      || descriptor.value.length > limit
      || /[\u0000-\u001f\u007f]/.test(descriptor.value)
    ) {
      return null;
    }
    parsed[field] = descriptor.value;
  }
  return Object.freeze(parsed);
}

function isDataDescriptor(descriptor) {
  return Boolean(descriptor) && Object.prototype.hasOwnProperty.call(descriptor, "value");
}

module.exports = { parseWebviewMessage };

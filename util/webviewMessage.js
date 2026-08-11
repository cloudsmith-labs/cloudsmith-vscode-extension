// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const MAX_MESSAGE_PROPERTIES = 2;
const MAX_COMMAND_LENGTH = 64;
const DEFAULT_WEBVIEW_STRING_LIMIT = 2048;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f-\u009f]/;
const RESERVED_FIELD_NAMES = new Set(["__proto__", "command", "constructor", "prototype"]);

/**
 * Copy a small, exact webview message without invoking accessors or accepting
 * inherited data. A message may contain a command and zero or one required
 * string field, all as own data properties on an Object.prototype or
 * null-prototype record. Command and required-field names are limited to 64
 * UTF-16 code units.
 * Required strings use a 2,048-code-unit limit unless their selected field has
 * an own positive safe-integer data-property override. An explicitly invalid
 * or accessor-based override rejects the message; unrelated limit keys are
 * ignored without being read. Contracts and limits are trusted configuration,
 * but their selected entries are still validated and reflection failures
 * return null.
 *
 * @param {object} message Exact own-data message received from a webview.
 * @param {Record<string, readonly string[]>} contracts Own-data command map.
 * @param {Record<string, number>} [stringLimits={}] Optional own-data limit map.
 * @returns {Readonly<Record<string, string>>|null} Frozen parsed copy or null.
 */
function parseWebviewMessage(message, contracts, stringLimits = {}) {
  if (!isPlainRecord(stringLimits)) return null;

  let prototype;
  let keys;
  let descriptors;
  try {
    if (!message || typeof message !== "object" || Array.isArray(message)) return null;
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
    || CONTROL_CHARACTER_PATTERN.test(command)
  ) {
    return null;
  }

  const fields = readContractFields(contracts, command);
  if (fields === null) return null;
  const expectedKeys = ["command", ...fields];
  if (keys.length !== expectedKeys.length || expectedKeys.some(key => !keys.includes(key))) {
    return null;
  }

  const parsed = { command };
  for (const field of fields) {
    const descriptor = descriptors[field];
    const limit = readStringLimit(stringLimits, field);
    if (
      !isDataDescriptor(descriptor)
      || typeof descriptor.value !== "string"
      || descriptor.value.length === 0
      || limit === null
      || descriptor.value.length > limit
      || CONTROL_CHARACTER_PATTERN.test(descriptor.value)
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

function isPlainRecord(value) {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function readContractFields(contracts, command) {
  if (!isPlainRecord(contracts)) return null;
  try {
    const contractDescriptor = Object.getOwnPropertyDescriptor(contracts, command);
    if (!isDataDescriptor(contractDescriptor) || !Array.isArray(contractDescriptor.value)) {
      return null;
    }
    const fields = contractDescriptor.value;
    if (Object.getPrototypeOf(fields) !== Array.prototype) return null;
    const fieldDescriptors = Object.getOwnPropertyDescriptors(fields);
    const ownKeys = Reflect.ownKeys(fields);
    const lengthDescriptor = fieldDescriptors.length;
    if (
      !isDataDescriptor(lengthDescriptor)
      || !Number.isSafeInteger(lengthDescriptor.value)
      || lengthDescriptor.value < 0
      || lengthDescriptor.value > MAX_MESSAGE_PROPERTIES - 1
    ) {
      return null;
    }
    const length = lengthDescriptor.value;
    const expectedKeys = length === 0 ? ["length"] : ["0", "length"];
    if (ownKeys.length !== expectedKeys.length || expectedKeys.some(key => !ownKeys.includes(key))) {
      return null;
    }
    if (length === 0) return Object.freeze([]);
    const fieldDescriptor = fieldDescriptors[0];
    if (!isDataDescriptor(fieldDescriptor)) return null;
    const field = fieldDescriptor.value;
    if (
      typeof field !== "string"
      || field.length === 0
      || field.length > MAX_COMMAND_LENGTH
      || RESERVED_FIELD_NAMES.has(field)
      || CONTROL_CHARACTER_PATTERN.test(field)
    ) {
      return null;
    }
    return Object.freeze([field]);
  } catch {
    return null;
  }
}

function readStringLimit(stringLimits, field) {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(stringLimits, field);
    if (descriptor === undefined) return DEFAULT_WEBVIEW_STRING_LIMIT;
    if (!isDataDescriptor(descriptor)) return null;
    const limit = descriptor.value;
    return Number.isSafeInteger(limit) && limit > 0 ? limit : null;
  } catch {
    return null;
  }
}

module.exports = { DEFAULT_WEBVIEW_STRING_LIMIT, parseWebviewMessage };

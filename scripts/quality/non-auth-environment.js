// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const CREDENTIAL_LIKE_ENVIRONMENT_NAME = /(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSCODE|MFA|CREDENTIAL|KEYCHAIN|ONEPASSWORD|1PASSWORD|PRIVATE_?KEY|ACCESS_?KEY|REFRESH_?TOKEN)/iu;

// Non-authenticated quality work starts from this exact set instead of the
// caller's complete environment. In particular, user/profile locations,
// package-manager configuration, credential-agent sockets, and arbitrary CI
// variables are intentionally absent.
const NON_AUTH_QUALITY_ENVIRONMENT_ALLOWLIST = Object.freeze([
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "WINDIR",
  "COMSPEC",
  "PROCESSOR_ARCHITECTURE",
  "NUMBER_OF_PROCESSORS",
  "LANG",
  "LC_ALL",
  "LC_COLLATE",
  "LC_CTYPE",
  "LC_MESSAGES",
  "LC_MONETARY",
  "LC_NUMERIC",
  "LC_TIME",
  "TZ",
  "TERM",
  "COLORTERM",
  "FORCE_COLOR",
  "NO_COLOR",
  "CI",
  "GITHUB_ACTIONS",
  "GITHUB_REF_NAME",
  "GITHUB_SHA",
  "RUNNER_OS",
  "RUNNER_ARCH",
  "DISPLAY",
  "WAYLAND_DISPLAY",
  "XAUTHORITY",
  "XDG_RUNTIME_DIR",
  "DBUS_SESSION_BUS_ADDRESS",
  "TMPDIR",
  "TMP",
  "TEMP",
  "USER",
  "LOGNAME",
  "USERNAME",
  "SHELL",
  "QUALITY_BASE",
  "M9_REQUIRE_CLEAN",
  "M9_SOURCE_SHA",
  "VSCODE_TEST_VERSION",
  "VSCODE_TEST_LABEL",
]);

const NON_AUTH_QUALITY_OVERRIDE_NAMES = Object.freeze([
  "CLOUDSMITH_QUALITY_SOURCE_SHA",
  "CLOUDSMITH_QUALITY_SOURCE_FINGERPRINT",
  "CLOUDSMITH_QUALITY_TEST_EVIDENCE",
  "CLOUDSMITH_QUALITY_TEST_SUITE",
  "SOURCE_DATE_EPOCH",
  "TZ",
]);

function assertSafeNames(names, label) {
  if (names.length !== new Set(names).size) {
    throw new Error(`${label} contains a duplicate name.`);
  }
  for (const name of names) {
    if (!/^[A-Z][A-Z0-9_]{0,127}$/u.test(name)
      || CREDENTIAL_LIKE_ENVIRONMENT_NAME.test(name)) {
      throw new Error(`${label} contains an unsafe name.`);
    }
  }
}

assertSafeNames(NON_AUTH_QUALITY_ENVIRONMENT_ALLOWLIST, "Non-auth environment allowlist");
assertSafeNames(NON_AUTH_QUALITY_OVERRIDE_NAMES, "Non-auth environment override list");

function isBoundedEnvironmentValue(value) {
  return typeof value === "string"
    && value.length <= 32768
    && !value.includes("\u0000");
}

function buildNonAuthQualityEnvironment(environment = process.env, overrides = {}, options = {}) {
  if (!environment || typeof environment !== "object" || Array.isArray(environment)) {
    throw new TypeError("Non-auth quality environment must be an object.");
  }
  if (!overrides || typeof overrides !== "object" || Array.isArray(overrides)) {
    throw new TypeError("Non-auth quality environment overrides must be an object.");
  }
  const platform = options.platform || process.platform;
  const sourceNames = Object.keys(environment);
  const readAllowlistedValue = expectedName => {
    if (platform !== "win32") {
      return Object.prototype.hasOwnProperty.call(environment, expectedName)
        ? environment[expectedName]
        : undefined;
    }
    const matches = sourceNames.filter(name => name.toUpperCase() === expectedName);
    if (matches.length > 1) {
      throw new Error(`Non-auth quality environment has a case-colliding key: ${expectedName}`);
    }
    return matches.length === 1 ? environment[matches[0]] : undefined;
  };

  const sanitized = {};
  for (const name of NON_AUTH_QUALITY_ENVIRONMENT_ALLOWLIST) {
    const value = readAllowlistedValue(name);
    if (isBoundedEnvironmentValue(value)) sanitized[name] = value;
  }

  const allowedOverrides = new Set(NON_AUTH_QUALITY_OVERRIDE_NAMES);
  for (const name of Object.keys(overrides)) {
    if (!allowedOverrides.has(name) || !isBoundedEnvironmentValue(overrides[name])) {
      throw new Error(`Non-auth quality environment override is unsafe: ${String(name)}`);
    }
    sanitized[name] = overrides[name];
  }
  return Object.freeze(sanitized);
}

module.exports = {
  CREDENTIAL_LIKE_ENVIRONMENT_NAME,
  NON_AUTH_QUALITY_ENVIRONMENT_ALLOWLIST,
  NON_AUTH_QUALITY_OVERRIDE_NAMES,
  buildNonAuthQualityEnvironment,
};

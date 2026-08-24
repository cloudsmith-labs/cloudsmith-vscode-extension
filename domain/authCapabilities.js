// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const PULL_THROUGH_API_KEY_MESSAGE =
  "Pull-through requires a Cloudsmith API key. Sign in with an API key to continue.";

const AUTHENTICATION_METHODS = Object.freeze([
  Object.freeze({
    id: "personal-api-key",
    label: "$(key) Enter API key",
    description: "Paste a personal API key",
    documentationLabel: "API key",
    method: "api-key",
  }),
  Object.freeze({
    id: "service-account-api-key",
    label: "$(server) Enter service account API key",
    description: "Paste a service account API key",
    documentationLabel: "Service account API key",
    method: "api-key",
  }),
  Object.freeze({
    id: "cloudsmith-cli",
    label: "$(folder-opened) Import API key from Cloudsmith CLI",
    description: "Import the [default] API key from a trusted credentials.ini",
    documentationLabel: "Import API key from Cloudsmith CLI",
    method: "import",
  }),
  Object.freeze({
    id: "sso-browser",
    label: "$(globe) Sign in with SSO",
    description: "Sign in through your organization's identity provider",
    documentationLabel: "Sign in with SSO",
    method: "sso-browser",
  }),
]);

const PULL_THROUGH_AVAILABLE = Object.freeze({ pullThroughAvailable: true });
const PULL_THROUGH_UNAVAILABLE = Object.freeze({ pullThroughAvailable: false });

function ownDataValue(value, key) {
  if ((typeof value !== "object" || value === null) && typeof value !== "function") {
    return undefined;
  }
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && Object.prototype.hasOwnProperty.call(descriptor, "value")
      ? descriptor.value
      : undefined;
  } catch {
    return undefined;
  }
}

function deriveAuthenticationCapabilities(value) {
  return ownDataValue(value, "sessionConnected") === true
    && ownDataValue(value, "credentialKind") === "api-key"
    ? PULL_THROUGH_AVAILABLE
    : PULL_THROUGH_UNAVAILABLE;
}

function authenticationCapabilitiesFor(source) {
  try {
    const method = source && source.getAuthenticationCapabilities;
    if (typeof method !== "function") return PULL_THROUGH_UNAVAILABLE;
    const capabilities = method.call(source);
    return ownDataValue(capabilities, "pullThroughAvailable") === true
      ? PULL_THROUGH_AVAILABLE
      : PULL_THROUGH_UNAVAILABLE;
  } catch {
    return PULL_THROUGH_UNAVAILABLE;
  }
}

function isPullThroughAvailable(source) {
  return authenticationCapabilitiesFor(source).pullThroughAvailable;
}

module.exports = {
  AUTHENTICATION_METHODS,
  PULL_THROUGH_API_KEY_MESSAGE,
  authenticationCapabilitiesFor,
  deriveAuthenticationCapabilities,
  isPullThroughAvailable,
};

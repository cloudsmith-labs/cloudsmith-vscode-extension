// Copyright 2026 Cloudsmith Ltd. All rights reserved.

// Human-readable error message formatter for structured API and local errors.

/**
 * Convert a structured API error or a local domain error into a user-friendly message.
 * @param   {Object|string} error  Cloudsmith API result/error or a local error message.
 * @returns {string}              Human-readable error message.
 */
function formatApiError(error) {
  const apiError = error && error.ok === false
    ? error.error
    : error && typeof error === "object" && typeof error.kind === "string"
      ? error
      : null;
  if (apiError && typeof apiError.message === "string") {
    return apiError.message;
  }
  if (error instanceof Error && typeof error.message === "string") {
    return sanitizeLocalMessage(error.message);
  }
  if (typeof error === "string" && error) {
    return sanitizeLocalMessage(error);
  }
  return "Could not complete the request.";
}

function sanitizeLocalMessage(message) {
  const sanitized = String(message).replace(/[\u0000-\u001f\u007f]/g, " ");
  const truncated = sanitized.length > 160 ? `${sanitized.slice(0, 160)}...` : sanitized;
  return `Request failed: ${truncated}`;
}

module.exports = { formatApiError };

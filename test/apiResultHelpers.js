function apiSuccess(data, options = {}) {
  const defaultHeaders = Array.isArray(data) && data.length > 0
    ? {
        "x-pagination-page": "1",
        "x-pagination-pagetotal": "1",
        "x-pagination-count": String(data.length),
        "x-pagination-pagesize": "100",
      }
    : {};
  return {
    ok: true,
    data,
    status: options.status || 200,
    headers: options.headers || defaultHeaders,
    requestId: options.requestId || "test-request-id",
    serverRequestId: null,
    attempts: options.attempts || 1,
    redirectCount: 0,
  };
}

function apiFailure(kind, options = {}) {
  const status = Object.prototype.hasOwnProperty.call(options, "status")
    ? options.status
    : null;
  const message = options.message || `Test ${kind} failure.`;
  const error = {
    kind,
    status,
    retryable: Boolean(options.retryable),
    message,
    requestId: options.requestId || "test-request-id",
    retryAfterMs: options.retryAfterMs || null,
    outcomeUnknown: Boolean(options.outcomeUnknown),
    diagnostic: {},
  };
  return {
    ok: false,
    status,
    headers: options.headers || {},
    requestId: error.requestId,
    serverRequestId: null,
    attempts: options.attempts || 1,
    error,
  };
}

module.exports = { apiFailure, apiSuccess };

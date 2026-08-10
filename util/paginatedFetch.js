// Copyright 2026 Cloudsmith Ltd. All rights reserved.

// Strict, bounded collection access for Cloudsmith's numeric pagination contract.

const crypto = require("crypto");
const { appendApiQuery } = require("./apiEndpoint");

const MAX_COLLECTION_FAILURE_DETAILS = 20;
const MAX_COLLECTION_DESCRIPTOR_LENGTH = 4096;
const MAX_PAGE_SIZE = 500;

class PaginatedFetch {
  constructor(cloudsmithAPI) {
    this.api = cloudsmithAPI;
  }

  /** Fetch one validated page. Collection-wide consistency is checked by fetchCollection. */
  async fetchPage(endpoint, page, pageSize, query, options = {}) {
    if (!isPositiveSafeInteger(page) || !isPageSize(pageSize)) {
      return failedPage(
        page,
        pageSize,
        localInvalidResponseError("The requested pagination values were invalid.")
      );
    }

    let url;
    try {
      url = appendApiQuery(endpoint, {
        page,
        page_size: pageSize,
        ...(query ? { query } : {}),
      });
    } catch {
      return failedPage(
        page,
        pageSize,
        localInvalidResponseError("The paginated API endpoint was invalid.")
      );
    }

    const decoder = createDecoder(options);
    if (!decoder) {
      return failedPage(
        page,
        pageSize,
        localInvalidResponseError("The paginated response decoder was invalid.")
      );
    }

    const requestOptions = {
      responseType: decoder.responseType,
      validate: decoder.validateResponse,
      retry: options.retry || "never",
      signal: options.signal,
      cancellationToken: options.cancellationToken,
    };
    if (Object.prototype.hasOwnProperty.call(options, "apiKey")) {
      requestOptions.apiKey = options.apiKey;
    }

    let result;
    try {
      result = await this.api.get(url, requestOptions);
    } catch (error) {
      return failedPage(page, pageSize, unexpectedRequestError(error));
    }

    if (!result || !result.ok) {
      return failedPage(
        page,
        pageSize,
        result && result.error
          ? result.error
          : localInvalidResponseError("Cloudsmith returned an invalid transport result.")
      );
    }

    let items;
    try {
      if (!decoder.validateResponse(result.data)) {
        throw new TypeError("The response envelope was invalid.");
      }
      items = decoder.extractItems(result.data);
      if (!Array.isArray(items) || !decoder.validateItems(items)) {
        throw new TypeError("The response collection was invalid.");
      }
    } catch {
      return failedPage(
        page,
        pageSize,
        localInvalidResponseError("Cloudsmith returned an invalid collection response.")
      );
    }

    const pagination = parsePagination(result.headers || {}, page, pageSize, items.length);
    if (!pagination) {
      return failedPage(
        page,
        pageSize,
        localInvalidResponseError("Cloudsmith returned invalid pagination metadata.")
      );
    }

    return {
      data: items,
      pagination,
      error: null,
    };
  }

  /**
   * Collect validated pages within cumulative page, request, and item limits.
   * `requestCount` is the number of logical page requests, including failed/cancelled calls;
   * transport retries remain owned and bounded by CloudsmithAPI.
   */
  async fetchCollection(endpoint, options = {}) {
    const settings = normalizeCollectionOptions(endpoint, options);
    if (settings.error) {
      return buildCollectionResult({
        failures: [failureDetail(1, settings.error)],
        failureCount: 1,
        termination: "invalid_request",
      });
    }

    const {
      pageSize,
      maxPages,
      maxRequests,
      maxItems,
      pageBatchLimit,
      canonicalIdentity,
      binding,
      descriptor,
      resume,
    } = settings;
    const resumed = validateResume(resume, {
      binding,
      descriptor,
      maxPages,
      maxRequests,
      maxItems,
    });
    if (resumed.error) {
      return buildCollectionResult({
        failures: [failureDetail(1, resumed.error)],
        failureCount: 1,
        termination: "invalid_continuation",
      });
    }

    let page = resumed.nextPage;
    let pageCount = resumed.pageCount;
    let requestCount = resumed.requestCount;
    let itemCount = resumed.itemCount;
    let duplicateCount = resumed.duplicateCount;
    let failureCount = resumed.failureCount;
    let pagination = resumed.anchor;
    const items = [];
    const failures = [];
    const seen = normalizeKnownIdentities(options.knownIdentities, itemCount);
    if (!seen) {
      return buildCollectionResult({
        failures: [failureDetail(page, localInvalidResponseError(
          "The collection continuation identities were invalid."
        ))],
        failureCount: failureCount + 1,
        termination: "invalid_continuation",
        pageCount,
        requestCount,
        duplicateCount,
        pagination,
      });
    }

    let batchPages = 0;
    while (true) {
      if (isCancelled(options)) {
        return buildStoppedResult("cancelled", {
          items,
          failures,
          failureCount,
          pageCount,
          requestCount,
          duplicateCount,
          pagination,
          itemCount,
          cancelled: true,
          continuation: makeContinuation(page, pagination, {
            binding,
            descriptor,
            pageCount,
            requestCount,
            itemCount,
            duplicateCount,
            failureCount,
            maxPages,
            maxRequests,
            maxItems,
          }),
        });
      }
      if (pageCount >= maxPages) {
        return buildStoppedResult("page_limit", {
          items,
          failures,
          failureCount,
          pageCount,
          requestCount,
          duplicateCount,
          pagination,
          itemCount,
        });
      }
      if (requestCount >= maxRequests) {
        return buildStoppedResult("request_limit", {
          items,
          failures,
          failureCount,
          pageCount,
          requestCount,
          duplicateCount,
          pagination,
          itemCount,
        });
      }
      if (itemCount >= maxItems) {
        return buildStoppedResult("item_limit", {
          items,
          failures,
          failureCount,
          pageCount,
          requestCount,
          duplicateCount,
          pagination,
          itemCount,
        });
      }

      requestCount += 1; // Reserve before dispatch so failures and cancellation consume budget.
      const result = await this.fetchPage(
        endpoint,
        page,
        pageSize,
        options.query || null,
        options
      );

      if (isCancelled(options) || isCancellationError(result && result.error)) {
        return buildStoppedResult("cancelled", {
          items,
          failures,
          failureCount,
          pageCount,
          requestCount,
          duplicateCount,
          pagination,
          itemCount,
          cancelled: true,
          continuation: requestCount < maxRequests
            ? makeContinuation(page, pagination, {
              binding,
              descriptor,
              pageCount,
              requestCount,
              itemCount,
              duplicateCount,
              failureCount: 0,
              maxPages,
              maxRequests,
              maxItems,
            })
            : null,
        });
      }

      if (!result || result.error) {
        failureCount += 1;
        if (failures.length < MAX_COLLECTION_FAILURE_DETAILS) {
          failures.push(failureDetail(page, result && result.error));
        }
        const retryable = isRetryableCollectionFailure(result && result.error);
        return buildStoppedResult("request_failed", {
          items,
          failures,
          failureCount,
          pageCount,
          requestCount,
          duplicateCount,
          pagination,
          itemCount,
          continuation: retryable && requestCount < maxRequests
            ? makeContinuation(page, pagination, {
              binding,
              descriptor,
              pageCount,
              requestCount,
              itemCount,
              duplicateCount,
              failureCount: 0,
              maxPages,
              maxRequests,
              maxItems,
            })
            : null,
        });
      }

      const currentPagination = normalizeFetchedPagination(
        result.pagination,
        page,
        pageSize,
        Array.isArray(result.data) ? result.data.length : -1
      );
      if (!currentPagination || !isStablePageSequence(pagination, currentPagination, page)) {
        failureCount += 1;
        if (failures.length < MAX_COLLECTION_FAILURE_DETAILS) {
          failures.push(failureDetail(page, localInvalidResponseError(
            "Cloudsmith changed pagination metadata while the collection was loading."
          )));
        }
        return buildStoppedResult("invalid_pagination", {
          items,
          failures,
          failureCount,
          pageCount,
          requestCount,
          duplicateCount,
          pagination,
          itemCount,
        });
      }

      const pageIdentities = new Set();
      let identityFailure = null;
      for (const item of result.data) {
        let identity;
        try {
          identity = canonicalIdentity(item);
        } catch {
          identityFailure = localInvalidResponseError(
            "Cloudsmith returned a record with an invalid collection identity."
          );
          break;
        }
        if (
          typeof identity !== "string"
          || identity.length === 0
          || identity.length > MAX_COLLECTION_DESCRIPTOR_LENGTH
        ) {
          identityFailure = localInvalidResponseError(
            "Cloudsmith returned a record with an invalid collection identity."
          );
          break;
        }
        if (seen.has(identity) || pageIdentities.has(identity)) {
          duplicateCount += 1;
          identityFailure = localInvalidResponseError(
            "Cloudsmith returned a duplicate collection identity."
          );
          break;
        }
        pageIdentities.add(identity);
      }
      if (identityFailure) {
        failureCount += 1;
        if (failures.length < MAX_COLLECTION_FAILURE_DETAILS) {
          failures.push(failureDetail(page, identityFailure));
        }
        return buildStoppedResult("duplicate_or_invalid_identity", {
          items,
          failures,
          failureCount,
          pageCount,
          requestCount,
          duplicateCount,
          pagination,
          itemCount,
        });
      }

      if (itemCount + result.data.length > maxItems) {
        return buildStoppedResult("item_limit", {
          items,
          failures,
          failureCount,
          pageCount,
          requestCount,
          duplicateCount,
          pagination,
          itemCount,
        });
      }

      // Commit the validated page atomically only after the final cancellation check.
      if (isCancelled(options)) {
        return buildStoppedResult("cancelled", {
          items,
          failures,
          failureCount,
          pageCount,
          requestCount,
          duplicateCount,
          pagination,
          itemCount,
          cancelled: true,
          continuation: requestCount < maxRequests
            ? makeContinuation(page, pagination, {
              binding,
              descriptor,
              pageCount,
              requestCount,
              itemCount,
              duplicateCount,
              failureCount,
              maxPages,
              maxRequests,
              maxItems,
            })
            : null,
        });
      }
      for (const identity of pageIdentities) seen.add(identity);
      items.push(...result.data);
      itemCount += result.data.length;
      pageCount += 1;
      batchPages += 1;
      pagination = currentPagination;

      if (page >= currentPagination.pageTotal) {
        if (currentPagination.countAuthoritative && itemCount !== currentPagination.count) {
          failureCount += 1;
          if (failures.length < MAX_COLLECTION_FAILURE_DETAILS) {
            failures.push(failureDetail(page, localInvalidResponseError(
              "The collected records did not match Cloudsmith's authoritative count."
            )));
          }
          return buildStoppedResult("invalid_pagination", {
            items,
            failures,
            failureCount,
            pageCount,
            requestCount,
            duplicateCount,
            pagination,
            itemCount,
          });
        }
        return buildCollectionResult({
          items,
          complete: true,
          termination: "exhausted",
          failures,
          failureCount,
          pageCount,
          requestCount,
          duplicateCount,
          pagination,
        });
      }

      page += 1;
      if (batchPages >= pageBatchLimit) {
        const continuation = pageCount < maxPages && requestCount < maxRequests
          ? makeContinuation(page, pagination, {
            binding,
            descriptor,
            pageCount,
            requestCount,
            itemCount,
            duplicateCount,
            failureCount,
            maxPages,
            maxRequests,
            maxItems,
          })
          : null;
        const termination = continuation
          ? "page_batch"
          : pageCount >= maxPages
            ? "page_limit"
            : requestCount >= maxRequests
              ? "request_limit"
              : "item_limit";
        return buildStoppedResult(
          termination,
          {
            items,
            failures,
            failureCount,
            pageCount,
            requestCount,
            duplicateCount,
            pagination,
            itemCount,
            continuation,
          }
        );
      }
    }
  }
}

function createDecoder(options) {
  const responseType = options.responseType || "array";
  const validateItems = typeof options.validate === "function" ? options.validate : isRecordArray;
  if (responseType === "array") {
    return {
      responseType,
      validateResponse: validateItems,
      extractItems: value => value,
      validateItems,
    };
  }
  if (
    typeof options.validateResponse !== "function"
    || typeof options.extractItems !== "function"
  ) {
    return null;
  }
  return {
    responseType,
    validateResponse: options.validateResponse,
    extractItems: options.extractItems,
    validateItems,
  };
}

function normalizeCollectionOptions(endpoint, options) {
  const pageSize = Number(options.pageSize);
  const maxPages = Number(options.maxPages ?? 20);
  const maxRequests = Number(options.maxRequests ?? maxPages);
  const maxItems = Number(options.maxItems ?? (maxPages * pageSize));
  const pageBatchLimit = Number(options.pageBatchLimit ?? maxPages);
  const descriptor = options.descriptor === undefined ? "" : options.descriptor;
  if (
    typeof endpoint !== "string"
    || endpoint.length === 0
    || !isPageSize(pageSize)
    || !isPositiveSafeInteger(maxPages)
    || !isPositiveSafeInteger(maxRequests)
    || !isPositiveSafeInteger(maxItems)
    || !isPositiveSafeInteger(pageBatchLimit)
    || typeof options.canonicalIdentity !== "function"
    || typeof descriptor !== "string"
    || descriptor.length > MAX_COLLECTION_DESCRIPTOR_LENGTH
  ) {
    return { error: localInvalidResponseError("The collection request was invalid.") };
  }
  return {
    pageSize,
    maxPages,
    maxRequests,
    maxItems,
    pageBatchLimit: Math.min(pageBatchLimit, maxPages),
    canonicalIdentity: options.canonicalIdentity,
    binding: collectionBinding(endpoint, options.query || null, descriptor, pageSize),
    descriptor,
    resume: options.resume || null,
  };
}

function collectionBinding(endpoint, query, descriptor, pageSize) {
  return crypto.createHash("sha256")
    .update(JSON.stringify([endpoint, query, descriptor, pageSize]))
    .digest("hex");
}

function validateResume(resume, bounds) {
  if (!resume) {
    return {
      nextPage: 1,
      anchor: null,
      pageCount: 0,
      requestCount: 0,
      itemCount: 0,
      duplicateCount: 0,
      failureCount: 0,
    };
  }
  const cumulative = resume.cumulative;
  const anchor = resume.anchor;
  if (
    !resume
    || typeof resume !== "object"
    || resume.binding !== bounds.binding
    || resume.descriptor !== bounds.descriptor
    || !isPositiveSafeInteger(resume.nextPage)
    || !cumulative
    || !isNonNegativeSafeInteger(cumulative.pageCount)
    || !isNonNegativeSafeInteger(cumulative.requestCount)
    || !isNonNegativeSafeInteger(cumulative.itemCount)
    || !isNonNegativeSafeInteger(cumulative.duplicateCount)
    || !isNonNegativeSafeInteger(cumulative.failureCount)
    || cumulative.pageCount >= bounds.maxPages
    || cumulative.requestCount < cumulative.pageCount
    || cumulative.requestCount >= bounds.maxRequests
    || cumulative.itemCount >= bounds.maxItems
    || cumulative.duplicateCount !== 0
    || cumulative.failureCount !== 0
    || (anchor !== null && !isResumeAnchor(anchor, resume.nextPage))
    || (anchor !== null && cumulative.pageCount !== anchor.page)
    || (anchor !== null && cumulative.itemCount !== committedItemCount(anchor))
    || (anchor === null && (
      resume.nextPage !== 1
      || cumulative.pageCount !== 0
      || cumulative.itemCount !== 0
    ))
  ) {
    return { error: localInvalidResponseError("The collection continuation was invalid.") };
  }
  return {
    nextPage: resume.nextPage,
    anchor,
    ...cumulative,
  };
}

function isResumeAnchor(anchor, nextPage) {
  return Boolean(
    anchor
    && isPositiveSafeInteger(anchor.page)
    && anchor.page + 1 === nextPage
    && isPositiveSafeInteger(anchor.pageTotal)
    && anchor.page < anchor.pageTotal
    && isPageSize(anchor.pageSize)
    && (anchor.count === null || isNonNegativeSafeInteger(anchor.count))
    && anchor.countAuthoritative === (anchor.count !== null)
  );
}

function committedItemCount(anchor) {
  const fullPageCount = anchor.page * anchor.pageSize;
  if (!Number.isSafeInteger(fullPageCount)) return -1;
  return anchor.countAuthoritative
    ? Math.min(anchor.count, fullPageCount)
    : fullPageCount;
}

function normalizeKnownIdentities(value, expectedSize) {
  if (expectedSize === 0 && (value === undefined || value === null)) return new Set();
  if (!(value instanceof Set) || value.size !== expectedSize) return null;
  const result = new Set();
  for (const identity of value) {
    if (
      typeof identity !== "string"
      || identity.length === 0
      || identity.length > MAX_COLLECTION_DESCRIPTOR_LENGTH
    ) return null;
    result.add(identity);
  }
  return result;
}

function makeContinuation(nextPage, anchor, state) {
  if (
    state.pageCount >= state.maxPages
    || state.requestCount >= state.maxRequests
    || state.itemCount >= state.maxItems
  ) return null;
  return Object.freeze({
    nextPage,
    anchor: anchor ? Object.freeze({ ...anchor }) : null,
    cumulative: Object.freeze({
      pageCount: state.pageCount,
      requestCount: state.requestCount,
      itemCount: state.itemCount,
      duplicateCount: state.duplicateCount,
      failureCount: state.failureCount,
    }),
    descriptor: state.descriptor,
    binding: state.binding,
  });
}

function buildStoppedResult(termination, state) {
  return buildCollectionResult({
    items: state.items,
    complete: false,
    cancelled: state.cancelled === true,
    continuation: state.continuation || null,
    failures: state.failures,
    failureCount: state.failureCount,
    termination,
    pageCount: state.pageCount,
    requestCount: state.requestCount,
    duplicateCount: state.duplicateCount,
    pagination: state.pagination,
  });
}

function buildCollectionResult(state = {}) {
  const items = Object.freeze([...(state.items || [])]);
  const complete = state.complete === true;
  const cancelled = state.cancelled === true;
  const failures = Object.freeze([...(state.failures || [])].slice(0, MAX_COLLECTION_FAILURE_DETAILS));
  const failureCount = state.failureCount ?? 0;
  const pageCount = state.pageCount ?? 0;
  const requestCount = state.requestCount ?? 0;
  const duplicateCount = state.duplicateCount ?? 0;
  const result = {
    items,
    complete,
    incomplete: !complete,
    partial: !complete && items.length > 0,
    cancelled,
    continuation: complete ? null : (state.continuation || null),
    failures,
    failureCount,
    termination: state.termination || (complete ? "exhausted" : "invalid_request"),
    pageCount,
    requestCount,
    duplicateCount,
    pagination: state.pagination ? Object.freeze({ ...state.pagination }) : null,
  };
  if (
    (complete && (
      result.termination !== "exhausted"
      || result.continuation !== null
      || result.cancelled
      || result.partial
      || result.failureCount > 0
    ))
    || result.partial !== (!result.complete && result.items.length > 0)
    || (result.cancelled && result.complete)
    || !isNonNegativeSafeInteger(result.pageCount)
    || !isNonNegativeSafeInteger(result.requestCount)
    || !isNonNegativeSafeInteger(result.duplicateCount)
    || !isNonNegativeSafeInteger(result.failureCount)
    || result.pageCount > result.requestCount
    || result.failureCount < result.failures.length
  ) {
    throw new Error("The collection result invariants were violated.");
  }
  return Object.freeze(result);
}

function collectionFailureResult(error, options = {}) {
  const page = isPositiveSafeInteger(options.page) ? options.page : 1;
  return buildCollectionResult({
    cancelled: options.cancelled === true,
    failures: [failureDetail(page, error)],
    failureCount: 1,
    termination: options.termination || "request_failed",
  });
}

function replaceCollectionItems(result, items) {
  if (!result || typeof result !== "object" || !Array.isArray(items)) {
    throw new TypeError("The collection result mapping was invalid.");
  }
  return buildCollectionResult({
    items,
    complete: result.complete === true,
    cancelled: result.cancelled === true,
    continuation: result.continuation || null,
    failures: result.failures || [],
    failureCount: result.failureCount || 0,
    termination: result.termination,
    pageCount: result.pageCount || 0,
    requestCount: result.requestCount || 0,
    duplicateCount: result.duplicateCount || 0,
    pagination: result.pagination || null,
  });
}

function isStablePageSequence(previous, current, requestedPage) {
  if (!current || current.page !== requestedPage) return false;
  if (!previous) return requestedPage === 1;
  return current.page === previous.page + 1
    && current.pageSize === previous.pageSize
    && current.pageTotal === previous.pageTotal
    && current.countAuthoritative === previous.countAuthoritative
    && current.count === previous.count;
}

function normalizeFetchedPagination(value, requestedPage, requestedPageSize, itemCount) {
  if (!value || typeof value !== "object" || itemCount < 0) return null;
  const countAuthoritative = value.countAuthoritative === undefined
    ? isNonNegativeSafeInteger(value.count)
    : value.countAuthoritative === true;
  const count = countAuthoritative ? value.count : null;
  if (
    value.page !== requestedPage
    || !isPositiveSafeInteger(value.pageTotal)
    || value.page > value.pageTotal
    || !isPageSize(value.pageSize)
    || value.pageSize > requestedPageSize
    || itemCount > value.pageSize
    || (countAuthoritative && !isNonNegativeSafeInteger(count))
  ) return null;
  if (countAuthoritative) {
    const calculatedPageTotal = Math.max(1, Math.ceil(count / value.pageSize));
    const expectedItems = Math.min(
      value.pageSize,
      Math.max(0, count - ((value.page - 1) * value.pageSize))
    );
    if (calculatedPageTotal !== value.pageTotal || expectedItems !== itemCount) return null;
  } else if (value.page < value.pageTotal && itemCount !== value.pageSize) {
    return null;
  }
  return Object.freeze({
    page: value.page,
    pageTotal: value.pageTotal,
    pageSize: value.pageSize,
    count,
    countAuthoritative,
  });
}

function isRecordArray(value) {
  return Array.isArray(value) && value.every(item => (
    Boolean(item) && typeof item === "object" && !Array.isArray(item)
  ));
}

function parseOptionalInteger(value) {
  if (value === undefined) return { present: false, valid: true, value: null };
  const normalized = String(value).trim();
  const parsed = /^\d+$/.test(normalized) ? Number(normalized) : NaN;
  return {
    present: true,
    valid: Number.isSafeInteger(parsed) && parsed >= 0,
    value: parsed,
  };
}

function parsePagination(headers, requestedPage, requestedPageSize, itemCount) {
  const page = parseOptionalInteger(headers["x-pagination-page"]);
  const pageTotal = parseOptionalInteger(headers["x-pagination-pagetotal"]);
  const count = parseOptionalInteger(headers["x-pagination-count"]);
  const pageSize = parseOptionalInteger(headers["x-pagination-pagesize"]);
  if (![page, pageTotal, count, pageSize].every(field => field.valid)) return null;

  const effectivePage = page.present ? page.value : requestedPage;
  const effectivePageSize = pageSize.present ? pageSize.value : requestedPageSize;
  if (
    !isPositiveSafeInteger(effectivePage)
    || effectivePage !== requestedPage
    || !isPageSize(effectivePageSize)
    || effectivePageSize > requestedPageSize
    || itemCount > effectivePageSize
    || (!pageTotal.present && !count.present)
  ) return null;

  const effectivePageTotal = pageTotal.present
    ? pageTotal.value
    : Math.max(1, Math.ceil(count.value / effectivePageSize));
  if (
    !isPositiveSafeInteger(effectivePageTotal)
    || effectivePage > effectivePageTotal
  ) return null;

  if (count.present) {
    const calculatedPageTotal = Math.max(1, Math.ceil(count.value / effectivePageSize));
    const expectedItems = Math.min(
      effectivePageSize,
      Math.max(0, count.value - ((effectivePage - 1) * effectivePageSize))
    );
    if (calculatedPageTotal !== effectivePageTotal || expectedItems !== itemCount) return null;
  } else if (effectivePage < effectivePageTotal && itemCount !== effectivePageSize) {
    return null;
  }

  return Object.freeze({
    page: effectivePage,
    pageTotal: effectivePageTotal,
    count: count.present ? count.value : null,
    countAuthoritative: count.present,
    pageSize: effectivePageSize,
  });
}

function failedPage(page, pageSize, error) {
  return {
    data: [],
    pagination: {
      page: isPositiveSafeInteger(page) ? page : 1,
      pageTotal: isPositiveSafeInteger(page) ? page : 1,
      count: null,
      countAuthoritative: false,
      pageSize: isPageSize(pageSize) ? pageSize : 1,
    },
    error,
  };
}

function failureDetail(page, error) {
  const safe = error && typeof error === "object" ? error : {};
  return Object.freeze({
    page: isPositiveSafeInteger(page) ? page : 1,
    error: Object.freeze({
      kind: boundedString(safe.kind, 80) || "request_failed",
      status: Number.isSafeInteger(safe.status) ? safe.status : null,
      retryable: safe.retryable === true,
      message: boundedString(safe.message, 1024) || "The collection request failed.",
      requestId: boundedString(safe.requestId, 256),
      retryAfterMs: isNonNegativeSafeInteger(safe.retryAfterMs) ? safe.retryAfterMs : null,
      outcomeUnknown: safe.outcomeUnknown === true,
    }),
  });
}

function boundedString(value, maxLength) {
  return typeof value === "string" && value.length <= maxLength ? value : null;
}

function isCancellationError(error) {
  return Boolean(error && typeof error === "object" && error.kind === "cancelled");
}

function isRetryableCollectionFailure(error) {
  return Boolean(
    error
    && typeof error === "object"
    && error.kind !== "invalid_response"
    && error.kind !== "invalid_request"
    && (error.kind === "rate_limited" || error.retryable === true)
  );
}

function isCancelled(options) {
  return options.signal?.aborted === true
    || options.cancellationToken?.isCancellationRequested === true;
}

function isPositiveSafeInteger(value) {
  return Number.isSafeInteger(value) && value >= 1;
}

function isNonNegativeSafeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function isPageSize(value) {
  return isPositiveSafeInteger(value) && value <= MAX_PAGE_SIZE;
}

function unexpectedRequestError(error) {
  return Object.freeze({
    kind: error && error.name === "AbortError" ? "cancelled" : "request_failed",
    status: null,
    retryable: false,
    // Thrown values are outside the typed transport boundary and can contain
    // credentials or other caller-owned data. Never retain their message.
    message: "The collection request failed unexpectedly.",
    requestId: null,
    retryAfterMs: null,
    outcomeUnknown: false,
    diagnostic: Object.freeze({}),
  });
}

function localInvalidResponseError(message) {
  return Object.freeze({
    kind: "invalid_response",
    status: null,
    retryable: false,
    message,
    requestId: null,
    retryAfterMs: null,
    outcomeUnknown: false,
    diagnostic: Object.freeze({}),
  });
}

module.exports = {
  MAX_COLLECTION_FAILURE_DETAILS,
  MAX_PAGE_SIZE,
  PaginatedFetch,
  collectionFailureResult,
  replaceCollectionItems,
};

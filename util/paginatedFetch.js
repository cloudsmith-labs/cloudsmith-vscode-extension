// Copyright 2026 Cloudsmith Ltd. All rights reserved.

// Handles paginated API responses from Cloudsmith.

const { appendApiQuery } = require("./apiEndpoint");

const MAX_FETCH_ALL_PAGES = 20;

class PaginatedFetch {
    constructor(cloudsmithAPI) {
        this.api = cloudsmithAPI;
    }

    /**
     * Fetch a single page with pagination metadata.
     *
     * @param   endpoint  Base endpoint (e.g., 'packages/owner/')
     * @param   page      Page number (1-indexed)
     * @param   pageSize  Results per page
     * @param   query     Optional query string to append
     * @returns { data: [], pagination: { page, pageTotal, count, pageSize } }
     */
    async fetchPage(endpoint, page, pageSize, query, options = {}) {
        let url;
        try {
            url = appendApiQuery(endpoint, {
                page,
                page_size: pageSize,
                ...(query ? { query } : {}),
            });
        } catch {
            return {
                data: [],
                pagination: { page: 1, pageTotal: 1, count: 0, pageSize: pageSize },
                error: localInvalidResponseError("The paginated API endpoint was invalid."),
            };
        }

        const requestOptions = {
            responseType: "array",
            validate: typeof options.validate === "function" ? options.validate : isRecordArray,
            retry: options.retry || "never",
            signal: options.signal,
            cancellationToken: options.cancellationToken,
        };
        if (Object.prototype.hasOwnProperty.call(options, "apiKey")) {
            requestOptions.apiKey = options.apiKey;
        }
        const result = await this.api.get(url, requestOptions);

        if (!result.ok) {
            return {
                data: [],
                pagination: { page: 1, pageTotal: 1, count: 0, pageSize: pageSize },
                error: result.error,
            };
        }

        const pagination = parsePagination(result.headers, page, pageSize, result.data.length);
        if (!pagination) {
            return {
                data: [],
                pagination: { page, pageTotal: page, count: 0, pageSize },
                error: localInvalidResponseError("Cloudsmith returned invalid pagination metadata."),
            };
        }

        return {
            data: result.data,
            pagination,
            error: null,
        };
    }

    /**
     * Fetch all available pages, capped at a hard ceiling to avoid runaway scans.
     *
     * @param   endpoint  Base endpoint (e.g., 'packages/owner/')
     * @param   pageSize  Results per page
     * @param   maxPagesOrQuery  Optional max page hint or query string
     * @param   query     Optional query string when a max page hint is supplied
     * @returns { data: [], pagination: { page, pageTotal, count, pageSize } }
     */
    async fetchAll(endpoint, pageSize, maxPagesOrQuery, query) {
        let maxPages = MAX_FETCH_ALL_PAGES;
        let searchQuery = query;

        if (typeof maxPagesOrQuery === "number") {
            maxPages = Math.max(1, Math.floor(maxPagesOrQuery));
        } else if (typeof maxPagesOrQuery === "string") {
            searchQuery = maxPagesOrQuery;
        }

        maxPages = Math.min(maxPages, MAX_FETCH_ALL_PAGES);

        const allData = [];
        let pagination = {
            page: 1,
            pageTotal: 1,
            count: 0,
            pageSize: pageSize,
        };

        for (let page = 1; page <= maxPages; page++) {
            const result = await this.fetchPage(endpoint, page, pageSize, searchQuery);
            if (result.error) {
                return result;
            }

            allData.push(...(result.data || []));
            pagination = {
                ...result.pagination,
                pageTotal: Math.min(result.pagination.pageTotal || 1, MAX_FETCH_ALL_PAGES),
            };

            if (page >= result.pagination.pageTotal) {
                break;
            }
        }

        return {
            data: allData,
            pagination,
        };
    }
}

function isRecordArray(value) {
    return Array.isArray(value) && value.every(item => (
        Boolean(item) && typeof item === "object" && !Array.isArray(item)
    ));
}

function parseOptionalInteger(value) {
    if (value === undefined) {
        return { present: false, valid: true, value: null };
    }
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
    if (![page, pageTotal, count, pageSize].every(field => field.valid)) {
        return null;
    }
    const effectivePage = page.present ? page.value : requestedPage;
    const effectivePageSize = pageSize.present ? pageSize.value : requestedPageSize;
    if (
        !Number.isInteger(effectivePage)
        || effectivePage < 1
        || effectivePage !== requestedPage
        || !Number.isInteger(effectivePageSize)
        || effectivePageSize < 1
        || itemCount > effectivePageSize
        || (!pageTotal.present && !count.present)
    ) {
        return null;
    }
    const effectivePageTotal = pageTotal.present
        ? pageTotal.value
        : Math.max(1, Math.ceil(count.value / effectivePageSize));
    if (!Number.isInteger(effectivePageTotal) || effectivePageTotal < 1 || effectivePage > effectivePageTotal) {
        return null;
    }
    if (count.present) {
        const calculatedPageTotal = Math.max(1, Math.ceil(count.value / effectivePageSize));
        const minimumReturned = ((effectivePage - 1) * effectivePageSize) + itemCount;
        if (calculatedPageTotal !== effectivePageTotal || minimumReturned > count.value) {
            return null;
        }
    }
    return {
        page: effectivePage,
        pageTotal: effectivePageTotal,
        count: count.present ? count.value : itemCount,
        pageSize: effectivePageSize,
    };
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

module.exports = { PaginatedFetch };

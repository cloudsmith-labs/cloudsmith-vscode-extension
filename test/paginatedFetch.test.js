const assert = require("assert");
const { PaginatedFetch, replaceCollectionItems } = require("../util/paginatedFetch");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");

suite("PaginatedFetch typed API boundary", () => {
  test("returns validated data and normalized pagination metadata", async () => {
    let requestOptions;
    const token = { isCancellationRequested: false };
    const apiKey = "candidate-key";
    const paginated = new PaginatedFetch({
      async get(endpoint, options) {
        requestOptions = options;
        assert.strictEqual(endpoint, "packages/workspace/?page=2&page_size=2&query=name%3Aartifact");
        return apiSuccess([{ name: "artifact" }], {
          headers: {
            "x-pagination-page": "2",
            "x-pagination-pagetotal": "2",
            "x-pagination-count": "3",
            "x-pagination-pagesize": "2",
          },
        });
      },
    });

    const result = await paginated.fetchPage(
      "packages/workspace/",
      2,
      2,
      "name:artifact",
      { apiKey, cancellationToken: token, retry: "never" }
    );

    assert.strictEqual(result.error, null);
    assert.deepStrictEqual(result.pagination, {
      page: 2,
      pageTotal: 2,
      count: 3,
      countAuthoritative: true,
      pageSize: 2,
    });
    assert.strictEqual(requestOptions.cancellationToken, token);
    assert.strictEqual(requestOptions.retry, "never");
    assert.strictEqual(requestOptions.apiKey, apiKey);
  });

  test("keeps typed transport failures distinct from empty pages", async () => {
    const failure = apiFailure("rate_limited", { status: 429 }).error;
    let requestOptions;
    const paginated = new PaginatedFetch({
      async get(_endpoint, options) {
        requestOptions = options;
        return { ...apiFailure("rate_limited", { status: 429 }), error: failure };
      },
    });

    const result = await paginated.fetchPage("packages/workspace/", 1, 100);

    assert.strictEqual(result.error, failure);
    assert.deepStrictEqual(result.data, []);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(requestOptions, "apiKey"), false);
  });

  test("rejects malformed arrays and incomplete or contradictory pagination metadata", async () => {
    const responses = [
      apiFailure("invalid_response", { status: 200 }),
      apiSuccess([], { headers: {} }),
      apiSuccess([{ name: "artifact" }], {
        headers: {
          "x-pagination-page": "2",
          "x-pagination-pagetotal": "1",
          "x-pagination-count": "1",
          "x-pagination-pagesize": "100",
        },
      }),
    ];
    const paginated = new PaginatedFetch({ async get() { return responses.shift(); } });

    for (let index = 0; index < 3; index += 1) {
      const result = await paginated.fetchPage("packages/workspace/", index === 2 ? 2 : 1, 100);
      assert.strictEqual(result.error.kind, "invalid_response");
    }
  });

  test("rejects a response whose authoritative page differs from the request", async () => {
    const paginated = new PaginatedFetch({
      async get() {
        return apiSuccess([{ name: "artifact" }], {
          headers: {
            "x-pagination-page": "1",
            "x-pagination-pagetotal": "2",
            "x-pagination-count": "3",
            "x-pagination-pagesize": "2",
          },
        });
      },
    });

    const result = await paginated.fetchPage("packages/workspace/", 2, 2);

    assert.strictEqual(result.error.kind, "invalid_response");
    assert.deepStrictEqual(result.data, []);
  });

  test("forwards a domain validator so blank records cannot cross pagination", async () => {
    let capturedValidator;
    const paginated = new PaginatedFetch({
      async get(_endpoint, options) {
        capturedValidator = options.validate;
        return apiFailure("invalid_response", { status: 200 });
      },
    });
    const repositoryValidator = value => Array.isArray(value) && value.every(repository => (
      typeof repository.slug === "string" && repository.slug.length > 0
    ));

    await paginated.fetchPage("repos/workspace/", 1, 100, null, {
      validate: repositoryValidator,
    });

    assert.strictEqual(capturedValidator, repositoryValidator);
    assert.strictEqual(capturedValidator([{}]), false);
    assert.strictEqual(capturedValidator([{ slug: "repo" }]), true);
  });

  test("keeps a missing count non-authoritative when page totals prove exhaustion", async () => {
    const paginated = new PaginatedFetch({
      async get() {
        return apiSuccess([{ name: "artifact" }], {
          headers: {
            "x-pagination-page": "1",
            "x-pagination-pagetotal": "1",
            "x-pagination-pagesize": "100",
          },
        });
      },
    });

    const result = await paginated.fetchPage("packages/workspace/", 1, 100);

    assert.strictEqual(result.error, null);
    assert.strictEqual(result.pagination.count, null);
    assert.strictEqual(result.pagination.countAuthoritative, false);
  });

  test("validates object envelopes before extracting collection items", async () => {
    const paginated = new PaginatedFetch({
      async get() {
        return apiSuccess({ results: [{ name: "artifact" }] }, {
          headers: {
            "x-pagination-page": "1",
            "x-pagination-pagetotal": "1",
            "x-pagination-count": "1",
            "x-pagination-pagesize": "100",
          },
        });
      },
    });

    const result = await paginated.fetchPage("groups/", 1, 100, null, {
      responseType: "object",
      validateResponse: value => Boolean(value && Array.isArray(value.results)),
      extractItems: value => value.results,
    });

    assert.strictEqual(result.error, null);
    assert.deepStrictEqual(result.data, [{ name: "artifact" }]);
  });

  test("rejects count-backed cardinality gaps and short non-final pages", async () => {
    const responses = [
      apiSuccess([{ id: "a" }], {
        headers: paginationHeaders(1, 2, 3, 2),
      }),
      apiSuccess([{ id: "a" }], {
        headers: {
          "x-pagination-page": "1",
          "x-pagination-pagetotal": "2",
          "x-pagination-pagesize": "2",
        },
      }),
    ];
    const paginated = new PaginatedFetch({ async get() { return responses.shift(); } });

    assert.strictEqual((await paginated.fetchPage("packages/", 1, 2)).error.kind, "invalid_response");
    assert.strictEqual((await paginated.fetchPage("packages/", 1, 2)).error.kind, "invalid_response");
  });
});

suite("PaginatedFetch bounded collection contract", () => {
  test("collects multiple pages and proves an authoritative empty collection", async () => {
    const calls = [];
    const paginated = createCollectionFetcher({
      1: page([{ id: "a" }, { id: "b" }], 1, 2, 3, 2),
      2: page([{ id: "c" }], 2, 2, 3, 2),
    }, calls);

    const result = await paginated.fetchCollection("records/", collectionOptions());

    assert.deepStrictEqual(result.items.map(item => item.id), ["a", "b", "c"]);
    assert.strictEqual(result.complete, true);
    assert.strictEqual(result.partial, false);
    assert.strictEqual(result.termination, "exhausted");
    assert.strictEqual(result.pageCount, 2);
    assert.strictEqual(result.requestCount, 2);
    assert.deepStrictEqual(calls, [1, 2]);

    const empty = createCollectionFetcher({ 1: page([], 1, 1, 0, 2) });
    const emptyResult = await empty.fetchCollection("records/", collectionOptions());
    assert.strictEqual(emptyResult.complete, true);
    assert.deepStrictEqual(emptyResult.items, []);
  });

  test("preserves successful pages when a later request fails", async () => {
    const rateLimit = apiFailure("rate_limited", { status: 429 });
    const paginated = createCollectionFetcher({
      1: page([{ id: "a" }, { id: "b" }], 1, 2, 4, 2),
      2: rateLimit,
    });

    const result = await paginated.fetchCollection("records/", collectionOptions());

    assert.deepStrictEqual(result.items.map(item => item.id), ["a", "b"]);
    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.partial, true);
    assert.strictEqual(result.termination, "request_failed");
    assert.strictEqual(result.failureCount, 1);
    assert.strictEqual(result.failures[0].error.kind, "rate_limited");
    assert.strictEqual(result.pageCount, 1);
    assert.strictEqual(result.requestCount, 2);
    assert.strictEqual(result.continuation.nextPage, 2);
  });

  test("distinguishes a failed first page from an authoritative empty collection", async () => {
    const paginated = createCollectionFetcher({
      1: apiFailure("network_error", { retryable: true }),
    });

    const result = await paginated.fetchCollection("records/", collectionOptions());

    assert.deepStrictEqual(result.items, []);
    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.partial, false);
    assert.strictEqual(result.termination, "request_failed");
    assert.strictEqual(result.failureCount, 1);
  });

  test("malformed pagination is terminal and cannot be resumed into another request", async () => {
    const calls = [];
    const paginated = createCollectionFetcher({
      1: apiSuccess([{ id: "a" }], { headers: {} }),
      2: page([{ id: "b" }], 2, 2, 2, 1),
    }, calls);

    const result = await paginated.fetchCollection("records/", collectionOptions());

    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.termination, "request_failed");
    assert.strictEqual(result.failures[0].error.kind, "invalid_response");
    assert.strictEqual(result.continuation, null);
    assert.deepStrictEqual(calls, [1]);
  });

  test("does not retain a message from an unexpected thrown request", async () => {
    const paginated = new PaginatedFetch({
      async get() {
        throw new Error("secret-bearing transport detail");
      },
    });

    const result = await paginated.fetchCollection("records/", collectionOptions());

    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.termination, "request_failed");
    assert.strictEqual(result.failures[0].error.message, "The collection request failed unexpectedly.");
    assert(!JSON.stringify(result).includes("secret-bearing transport detail"));
  });

  test("accepts a page-total-proven empty final page without inventing a count", async () => {
    const paginated = createCollectionFetcher({
      1: apiSuccess([{ id: "a" }, { id: "b" }], {
        headers: pageTotalHeaders(1, 2, 2),
      }),
      2: apiSuccess([], {
        headers: pageTotalHeaders(2, 2, 2),
      }),
    });

    const result = await paginated.fetchCollection("records/", collectionOptions());

    assert.strictEqual(result.complete, true);
    assert.deepStrictEqual(result.items.map(item => item.id), ["a", "b"]);
    assert.strictEqual(result.pagination.count, null);
    assert.strictEqual(result.pagination.countAuthoritative, false);
  });

  test("fails closed on metadata drift, duplicate identity, and no progress", async () => {
    const drift = createCollectionFetcher({
      1: page([{ id: "a" }, { id: "b" }], 1, 2, 4, 2),
      2: page([{ id: "c" }, { id: "d" }], 2, 3, 6, 2),
    });
    const driftResult = await drift.fetchCollection("records/", collectionOptions());
    assert.strictEqual(driftResult.complete, false);
    assert.strictEqual(driftResult.termination, "invalid_pagination");
    assert.deepStrictEqual(driftResult.items.map(item => item.id), ["a", "b"]);
    assert.strictEqual(driftResult.continuation, null);

    const duplicate = createCollectionFetcher({
      1: page([{ id: "a" }, { id: "b" }], 1, 2, 4, 2),
      2: page([{ id: "b" }, { id: "c" }], 2, 2, 4, 2),
    });
    const duplicateResult = await duplicate.fetchCollection("records/", collectionOptions());
    assert.strictEqual(duplicateResult.complete, false);
    assert.strictEqual(duplicateResult.termination, "duplicate_or_invalid_identity");
    assert.strictEqual(duplicateResult.duplicateCount, 1);
    assert.deepStrictEqual(duplicateResult.items.map(item => item.id), ["a", "b"]);
    assert.strictEqual(duplicateResult.continuation, null);
  });

  test("enforces page, request, and item limits without resumable cap bypass", async () => {
    const responses = {
      1: page([{ id: "a" }, { id: "b" }], 1, 3, 6, 2),
      2: page([{ id: "c" }, { id: "d" }], 2, 3, 6, 2),
      3: page([{ id: "e" }, { id: "f" }], 3, 3, 6, 2),
    };
    const pageLimited = await createCollectionFetcher(responses)
      .fetchCollection("records/", collectionOptions({ maxPages: 2, maxRequests: 3 }));
    assert.strictEqual(pageLimited.termination, "page_limit");
    assert.strictEqual(pageLimited.pageCount, 2);
    assert.strictEqual(pageLimited.requestCount, 2);
    assert.strictEqual(pageLimited.continuation, null);

    const requestLimited = await createCollectionFetcher(responses)
      .fetchCollection("records/", collectionOptions({ maxPages: 3, maxRequests: 1 }));
    assert.strictEqual(requestLimited.termination, "request_limit");
    assert.strictEqual(requestLimited.requestCount, 1);
    assert.strictEqual(requestLimited.continuation, null);

    const itemLimited = await createCollectionFetcher(responses)
      .fetchCollection("records/", collectionOptions({ maxItems: 3 }));
    assert.strictEqual(itemLimited.termination, "item_limit");
    assert.deepStrictEqual(itemLimited.items.map(item => item.id), ["a", "b"]);
    assert.strictEqual(itemLimited.continuation, null);
  });

  test("resumes one-page batches only with the same bound descriptor and cumulative identities", async () => {
    const responses = {
      1: page([{ id: "a" }, { id: "b" }], 1, 2, 3, 2),
      2: page([{ id: "c" }], 2, 2, 3, 2),
    };
    const paginated = createCollectionFetcher(responses);
    const first = await paginated.fetchCollection("records/", collectionOptions({
      pageBatchLimit: 1,
      descriptor: "account:workspace:records",
    }));
    assert.strictEqual(first.termination, "page_batch");
    assert.strictEqual(first.continuation.nextPage, 2);

    const second = await paginated.fetchCollection("records/", collectionOptions({
      pageBatchLimit: 1,
      descriptor: "account:workspace:records",
      resume: first.continuation,
      knownIdentities: new Set([JSON.stringify(["a"]), JSON.stringify(["b"])]),
    }));
    assert.strictEqual(second.complete, true);
    assert.deepStrictEqual(second.items.map(item => item.id), ["c"]);
    assert.strictEqual(second.pageCount, 2);
    assert.strictEqual(second.requestCount, 2);

    const invalid = await paginated.fetchCollection("records/", collectionOptions({
      descriptor: "different-scope",
      resume: first.continuation,
      knownIdentities: new Set([JSON.stringify(["a"]), JSON.stringify(["b"])]),
    }));
    assert.strictEqual(invalid.termination, "invalid_continuation");
    assert.strictEqual(invalid.requestCount, 0);

    const tampered = await paginated.fetchCollection("records/", collectionOptions({
      descriptor: "account:workspace:records",
      resume: {
        ...first.continuation,
        cumulative: {
          ...first.continuation.cumulative,
          pageCount: 0,
        },
      },
      knownIdentities: new Set([JSON.stringify(["a"]), JSON.stringify(["b"])]),
    }));
    assert.strictEqual(tampered.termination, "invalid_continuation");
    assert.strictEqual(tampered.requestCount, 0);

    const skippedPageCounters = await paginated.fetchCollection("records/", collectionOptions({
      descriptor: "account:workspace:records",
      resume: {
        ...first.continuation,
        nextPage: 6,
        anchor: {
          ...first.continuation.anchor,
          page: 5,
          pageTotal: 6,
        },
        cumulative: {
          ...first.continuation.cumulative,
          pageCount: 1,
          requestCount: 1,
        },
      },
      knownIdentities: new Set([JSON.stringify(["a"]), JSON.stringify(["b"])]),
    }));
    assert.strictEqual(skippedPageCounters.termination, "invalid_continuation");
    assert.strictEqual(skippedPageCounters.requestCount, 0);

    const skippedItems = await paginated.fetchCollection("records/", collectionOptions({
      descriptor: "account:workspace:records",
      resume: {
        ...first.continuation,
        cumulative: {
          ...first.continuation.cumulative,
          itemCount: 1,
        },
      },
      knownIdentities: new Set([JSON.stringify(["a"])]),
    }));
    assert.strictEqual(skippedItems.termination, "invalid_continuation");
    assert.strictEqual(skippedItems.requestCount, 0);
  });

  test("cancellation consumes dispatched requests and stops before the next page", async () => {
    const token = { isCancellationRequested: false };
    const calls = [];
    const paginated = new PaginatedFetch({
      async get(endpoint) {
        const requestedPage = Number(new URL(`https://example.test/${endpoint}`).searchParams.get("page"));
        calls.push(requestedPage);
        token.isCancellationRequested = true;
        return page([{ id: "a" }, { id: "b" }], 1, 2, 4, 2);
      },
    });

    const result = await paginated.fetchCollection("records/", collectionOptions({
      cancellationToken: token,
    }));

    assert.strictEqual(result.cancelled, true);
    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.pageCount, 0);
    assert.strictEqual(result.requestCount, 1);
    assert.deepStrictEqual(result.items, []);
    assert.deepStrictEqual(calls, [1]);
  });

  test("rejects malformed identities without publishing the malformed page", async () => {
    const paginated = createCollectionFetcher({
      1: page([{ id: "a" }, {}], 1, 1, 2, 2),
    });

    const result = await paginated.fetchCollection("records/", collectionOptions());

    assert.strictEqual(result.complete, false);
    assert.strictEqual(result.termination, "duplicate_or_invalid_identity");
    assert.deepStrictEqual(result.items, []);
    assert.strictEqual(result.failureCount, 1);
  });

  test("filtered incomplete results with no retained matches are incomplete, not partial", async () => {
    const source = await createCollectionFetcher({
      1: page([{ id: "a" }, { id: "b" }], 1, 2, 4, 2),
      2: apiFailure("rate_limited", { status: 429 }),
    }).fetchCollection("records/", collectionOptions());

    const filtered = replaceCollectionItems(source, []);

    assert.strictEqual(filtered.complete, false);
    assert.strictEqual(filtered.incomplete, true);
    assert.strictEqual(filtered.partial, false);
    assert.deepStrictEqual(filtered.items, []);
    assert.strictEqual(filtered.failureCount, 1);
  });
});

function paginationHeaders(pageNumber, pageTotal, count, pageSize) {
  return {
    "x-pagination-page": String(pageNumber),
    "x-pagination-pagetotal": String(pageTotal),
    "x-pagination-count": String(count),
    "x-pagination-pagesize": String(pageSize),
  };
}

function pageTotalHeaders(pageNumber, pageTotal, pageSize) {
  return {
    "x-pagination-page": String(pageNumber),
    "x-pagination-pagetotal": String(pageTotal),
    "x-pagination-pagesize": String(pageSize),
  };
}

function page(items, pageNumber, pageTotal, count, pageSize) {
  return apiSuccess(items, {
    headers: paginationHeaders(pageNumber, pageTotal, count, pageSize),
  });
}

function createCollectionFetcher(responses, calls = []) {
  return new PaginatedFetch({
    async get(endpoint) {
      const requestedPage = Number(new URL(`https://example.test/${endpoint}`).searchParams.get("page"));
      calls.push(requestedPage);
      const response = responses[requestedPage];
      return typeof response === "function" ? response() : response;
    },
  });
}

function collectionOptions(overrides = {}) {
  return {
    pageSize: 2,
    maxPages: 3,
    maxRequests: 3,
    maxItems: 6,
    canonicalIdentity: item => {
      if (!item || typeof item.id !== "string" || item.id.length === 0) {
        throw new TypeError("invalid identity");
      }
      return JSON.stringify([item.id]);
    },
    ...overrides,
  };
}

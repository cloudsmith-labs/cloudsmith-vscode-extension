const assert = require("assert");
const { PaginatedFetch } = require("../util/paginatedFetch");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");

suite("PaginatedFetch typed API boundary", () => {
  test("returns validated data and normalized pagination metadata", async () => {
    let requestOptions;
    const token = { isCancellationRequested: false };
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
      { cancellationToken: token, retry: "never" }
    );

    assert.strictEqual(result.error, null);
    assert.deepStrictEqual(result.pagination, { page: 2, pageTotal: 2, count: 3, pageSize: 2 });
    assert.strictEqual(requestOptions.cancellationToken, token);
    assert.strictEqual(requestOptions.retry, "never");
  });

  test("keeps typed transport failures distinct from empty pages", async () => {
    const failure = apiFailure("rate_limited", { status: 429 }).error;
    const paginated = new PaginatedFetch({
      async get() {
        return { ...apiFailure("rate_limited", { status: 429 }), error: failure };
      },
    });

    const result = await paginated.fetchPage("packages/workspace/", 1, 100);

    assert.strictEqual(result.error, failure);
    assert.deepStrictEqual(result.data, []);
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
});

const assert = require("assert");
const {
  apiEndpoint,
  appendApiQuery,
  encodeApiPathSegment,
} = require("../util/apiEndpoint");

suite("Cloudsmith API endpoint construction", () => {
  test("encodes dynamic path and query values without changing their structure", () => {
    assert.strictEqual(
      apiEndpoint(["packages", "workspace & team", "repo"], {
        query: { query: "name:widget & version:1.0", page_size: 100 },
      }),
      "packages/workspace%20%26%20team/repo/?query=name%3Awidget+%26+version%3A1.0&page_size=100"
    );
  });

  test("rejects direct and repeatedly encoded separators, traversal, controls, and query delimiters", () => {
    const unsafeValues = [
      ".",
      "..",
      "../outside",
      "repo/name",
      "repo\\name",
      "repo?admin=true",
      "repo#fragment",
      "%2foutside",
      "%252foutside",
      "%252e%252e",
      "repo\nname",
    ];

    for (const value of unsafeValues) {
      assert.throws(() => encodeApiPathSegment(value), /unsafe|unsupported|invalid/i, value);
    }
  });

  test("rejects secret query names and non-scalar values", () => {
    for (const name of [
      "api_key",
      "ApiKey",
      "access-token",
      "Authorization",
      "token",
      "x-api-key",
      "x_api_key",
      "client_secret",
      "refresh-token",
      "id_token",
      "password",
      "private_key",
    ]) {
      assert.throws(() => apiEndpoint(["packages"], { query: { [name]: "secret" } }), /credentials/i);
    }
    assert.throws(
      () => appendApiQuery("packages/?client%255fsecret=old-secret", { page: 1 }),
      /credentials/i
    );
    assert.throws(
      () => apiEndpoint(["packages"], { query: { filter: { name: "artifact" } } }),
      /invalid/i
    );
  });

  test("appends pagination without allowing endpoint root or secret-query escape", () => {
    assert.strictEqual(
      appendApiQuery("packages/workspace/", { page: 2, page_size: 100 }),
      "packages/workspace/?page=2&page_size=100"
    );
    assert.throws(() => appendApiQuery("https://evil.test/", { page: 1 }), /escaped/i);
    assert.throws(() => appendApiQuery("packages/?token=secret", { page: 1 }), /credentials/i);
  });
});

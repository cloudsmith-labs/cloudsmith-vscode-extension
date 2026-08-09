const assert = require("assert");
const { PromotionProvider } = require("../views/promotionProvider");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");

suite("PromotionProvider typed transport", () => {
  function createProvider() {
    const provider = new PromotionProvider({
      secrets: {
        async get() {
          return "candidate-key";
        },
      },
    });
    provider.getTagTemplates = () => ({ onPromote: [], onReceive: [] });
    return provider;
  }

  test("copy write is dispatched once and preserves ambiguous-outcome errors", async () => {
    const provider = createProvider();
    let postCalls = 0;
    provider.api = {
      async get() {
        return apiSuccess({
          name: "artifact",
          version: "1.0.0",
          format: "npm",
          slug_perm: "artifact-id",
        });
      },
      async post(_endpoint, _json, options) {
        postCalls += 1;
        assert.strictEqual(options.responseType, "object");
        return apiFailure("server_error", {
          status: 503,
          outcomeUnknown: true,
          message: "The request may have completed in Cloudsmith. Check the remote state before trying again.",
        });
      },
    };

    const result = await provider.promote(
      "workspace",
      "source",
      "artifact-id",
      "target"
    );

    assert.strictEqual(result.success, false);
    assert.strictEqual(result.error.outcomeUnknown, true);
    assert.strictEqual(postCalls, 1);
  });

  test("malformed successful write responses cannot be reported as promotion success", async () => {
    const provider = createProvider();
    let postCalls = 0;
    provider.api = {
      async get() {
        return apiSuccess({ name: "artifact", version: "1.0.0", format: "npm" });
      },
      async post() {
        postCalls += 1;
        return apiFailure("invalid_response", {
          status: 200,
          outcomeUnknown: true,
          message: "The request may have completed in Cloudsmith. Check the remote state before trying again.",
        });
      },
    };

    const result = await provider.promote(
      "workspace",
      "source",
      "artifact-id",
      "target"
    );

    assert.strictEqual(result.success, false);
    assert.strictEqual(result.error.kind, "invalid_response");
    assert.strictEqual(result.error.outcomeUnknown, true);
    assert.strictEqual(postCalls, 1);
  });

  test("promotion status keeps transport failure distinct from package absence", async () => {
    const provider = createProvider();
    provider.getPipeline = () => ["dev", "production"];
    provider.api = {
      async get() {
        return apiFailure("rate_limited", { status: 429, retryable: true });
      },
    };

    const result = await provider.getPromotionStatus(
      "workspace",
      "artifact",
      "1.0.0",
      "npm"
    );

    assert.deepStrictEqual(result.items, []);
    assert.strictEqual(result.error.kind, "rate_limited");
  });

  test("promotion status filters same-name versions by exact format", async () => {
    const provider = createProvider();
    provider.getPipeline = () => ["dev"];
    provider.api = {
      async get() {
        return apiSuccess([
          { name: "artifact", version: "1.0.0", format: "python", repository: "dev", status_str: "Quarantined" },
          { name: "artifact", version: "1.0.0", format: "npm", repository: "dev", status_str: "Completed" },
        ]);
      },
    };

    const result = await provider.getPromotionStatus("workspace", "artifact", "1.0.0", "npm");

    assert.strictEqual(result.error, null);
    assert.strictEqual(result.items[0].found, true);
    assert.strictEqual(result.items[0].status, "Completed");
  });

  test("a validated copy response completes without retrying or tagging", async () => {
    const provider = createProvider();
    let postCalls = 0;
    provider.api = {
      async get() {
        return apiSuccess({ name: "artifact", version: "1.0.0", format: "npm" });
      },
      async post() {
        postCalls += 1;
        return apiSuccess({
          name: "artifact",
          version: "1.0.0",
          format: "npm",
          repository: "target",
          slug_perm: "copied-id",
        });
      },
    };

    const result = await provider.promote(
      "workspace",
      "source",
      "artifact-id",
      "target"
    );

    assert.deepStrictEqual(result, { success: true, error: null });
    assert.strictEqual(postCalls, 1);
  });

  test("copy and tag validators require usable package identities and identifiers", async () => {
    const provider = createProvider();
    const validPackage = {
      name: "artifact",
      version: "1.0.0",
      format: "npm",
      repository: "target",
      slug_perm: "copied-id",
    };
    let copyValidated = false;
    let tagValidated = false;
    provider.api = {
      async get() {
        return apiSuccess(validPackage);
      },
      async post(endpoint, _json, options) {
        assert.strictEqual(options.validate({}), false);
        assert.strictEqual(options.validate(validPackage), true);
        if (endpoint.endsWith("/copy/")) {
          copyValidated = true;
          return apiSuccess(validPackage);
        }
        tagValidated = true;
        return apiSuccess(validPackage);
      },
    };
    provider.getTagTemplates = () => ({ onPromote: ["promoted"], onReceive: [] });

    const result = await provider.promote("workspace", "source", "artifact-id", "target");

    assert.strictEqual(result.success, true);
    assert.strictEqual(copyValidated, true);
    assert.strictEqual(tagValidated, true);
  });
});

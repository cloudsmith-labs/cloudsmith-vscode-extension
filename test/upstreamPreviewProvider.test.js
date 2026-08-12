const assert = require("assert");
const { UpstreamPreviewProvider } = require("../views/upstreamPreviewProvider");
const { UpstreamChecker } = require("../util/upstreamChecker");
const { apiSuccess } = require("./apiResultHelpers");

suite("UpstreamPreviewProvider Test Suite", () => {
  test("renders upstream resolution details without any policy section", () => {
    const provider = new UpstreamPreviewProvider({});

    const html = provider._getHtmlContent({
      name: "flask",
      format: "python",
      workspace: "acme",
      repo: "example-repo",
      local: {
        data: null,
        errorMessage: null,
        complete: true,
      },
      upstreams: {
        data: {
          total: 2,
          active: 1,
          configs: [
            {
              name: "PyPI",
              format: "python",
              _format: "python",
              origin: "https://pypi.org",
              is_active: true,
            },
            {
              name: "Legacy mirror",
              format: "python",
              _format: "python",
              origin: "https://legacy.example",
              is_active: false,
            },
          ],
        },
        errorMessage: null,
        complete: true,
      },
      canResolveViaUpstream: true,
    });

    assert.ok(html.includes("Upstream resolution preview"));
    assert.ok(html.includes("PyPI"));
    assert.ok(html.includes("Legacy mirror"));
    assert.ok(html.includes("<th>Origin</th>"));
    assert.match(html, /<td class="mono">https:\/\/pypi\.org<\/td>/);
    assert.ok(!html.includes("/simple/"));
    assert.ok(html.includes("Upstreams (1 active of 2)"));
    assert.ok(!html.includes("Active policies"));
    assert.ok(!html.includes("policy simulation"));
    assert.ok(!html.includes("Block Until Scan"));
    assert.ok(!html.includes("policy evaluation"));
  });

  test("renders upstream errors without expecting policy data", () => {
    const provider = new UpstreamPreviewProvider({});

    const html = provider._getHtmlContent({
      name: "flask",
      format: "python",
      workspace: "acme",
      repo: "example-repo",
      local: {
        data: null,
        errorMessage: null,
        complete: false,
      },
      upstreams: {
        data: {
          total: 0,
          active: 0,
          configs: [],
        },
        errorMessage: { message: "Upstream request failed", status: 500 },
        complete: false,
      },
      canResolveViaUpstream: false,
    });

    assert.ok(html.includes("Could not load upstream data"));
    assert.ok(html.includes("Upstream request failed"));
    assert.ok(!html.includes("[object Object]"));
    assert.ok(html.includes("Local package status is incomplete"));
    assert.ok(!html.includes("Not found in example-repo"));
    assert.ok(!html.includes("Active policies"));
    assert.ok(!html.includes("No active upstreams"));
    assert.ok(!html.includes("Upload the package directly"));
  });

  test("normalizes object errors, escapes HTML, and never exposes URL secrets", () => {
    const provider = new UpstreamPreviewProvider({});
    const html = provider._getHtmlContent({
      name: "<script>alert(1)</script>",
      format: "python",
      workspace: "acme",
      repo: "example-repo",
      local: { data: null, errorMessage: new Error("Request failed"), complete: false },
      upstreams: {
        data: {
          total: 1,
          active: 1,
          configs: [{
            name: "Private mirror",
            format: "python",
            _format: "python",
            origin: "",
            is_active: true,
          }],
        },
        errorMessage: null,
        complete: false,
      },
      canResolveViaUpstream: false,
    });

    assert.ok(html.includes("Request failed"));
    assert.match(html, /<td class="mono">Origin unavailable<\/td>/);
    assert.ok(!html.includes("[object Object]"));
    assert.ok(!html.includes("user:pass"));
    assert.ok(!html.includes("private/path"));
    assert.ok(!html.includes("token=secret"));
    assert.ok(!html.includes("#fragment"));
    assert.ok(!html.includes("<script>"));
    assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
  });

  test("replaces secret-bearing and HTML-shaped error messages with fixed public copy", () => {
    const provider = new UpstreamPreviewProvider({});
    for (const errorMessage of [
      new Error("https://user:pass@example.com/private?token=secret"),
      { message: "<script>alert(1)</script>", body: "private response body" },
      { unexpected: true },
    ]) {
      const html = provider._getHtmlContent({
        name: "package",
        format: "python",
        workspace: "acme",
        repo: "repo",
        local: { data: null, errorMessage: null, complete: true },
        upstreams: {
          data: { total: 0, active: 0, configs: [] },
          errorMessage,
          complete: false,
        },
        canResolveViaUpstream: false,
      });
      assert.ok(html.includes("Upstream availability could not be determined."));
      assert.ok(!html.includes("[object Object]"));
      assert.ok(!html.includes("user:pass"));
      assert.ok(!html.includes("token=secret"));
      assert.ok(!html.includes("private response body"));
      assert.ok(!html.includes("<script>"));
    }
  });

  test("bounds direct oversized upstream presentation truthfully", () => {
    const provider = new UpstreamPreviewProvider({});
    const configs = Array.from({ length: 101 }, (_, index) => ({
      name: `Mirror ${index}`,
      format: "python",
      _format: "python",
      origin: `https://mirror-${index}.example`,
      is_active: true,
    }));
    const html = provider._getHtmlContent({
      name: "package",
      format: "python",
      workspace: "acme",
      repo: "repo",
      local: { data: null, errorMessage: null, complete: true },
      upstreams: {
        data: { total: 101, active: 101, configs },
        errorMessage: null,
        complete: true,
      },
      canResolveViaUpstream: true,
    });

    assert.ok(html.includes("Showing 100 of 101 loaded upstreams."));
    assert.ok(!html.includes("Mirror 100"));
  });

  test("fails incomplete on contradictory counts and malformed configurations", () => {
    const provider = new UpstreamPreviewProvider({});
    const html = provider._getHtmlContent({
      name: "package",
      format: "python",
      workspace: "acme",
      repo: "repo",
      local: { data: null, errorMessage: null, complete: true },
      upstreams: {
        data: {
          total: 99,
          active: 99,
          configs: [{
            name: "Malformed", format: "python", _format: "python", origin: "",
            is_active: "true",
          }],
        },
        errorMessage: null,
        complete: true,
      },
      canResolveViaUpstream: "yes",
    });

    assert.ok(html.includes("Upstream inspection is incomplete"));
    assert.ok(html.includes("Upstream resolution could not be determined"));
    assert.ok(html.includes("0 active of 0 loaded"));
    assert.ok(!html.includes("99 active"));
    assert.ok(!html.includes("can likely resolve"));
    assert.ok(!html.includes("[object Object]"));
  });

  test("rejects inherited, accessor, and mismatched preview identities without invoking getters", () => {
    const provider = new UpstreamPreviewProvider({});
    const inherited = Object.create({
      name: "Inherited secret",
      format: "python",
      _format: "python",
      origin: "https://inherited.example",
      is_active: true,
    });
    let getterReads = 0;
    const accessor = {
      format: "python",
      _format: "python",
      origin: "https://accessor.example",
      is_active: true,
    };
    Object.defineProperty(accessor, "name", {
      enumerable: true,
      get() {
        getterReads += 1;
        return "Accessor secret";
      },
    });
    const mismatch = {
      name: "Mismatched secret",
      format: "npm",
      _format: "npm",
      origin: "https://mismatch.example",
      is_active: true,
    };

    const html = provider._getHtmlContent({
      name: "package",
      format: "python",
      workspace: "acme",
      repo: "repo",
      local: { data: null, errorMessage: null, complete: true },
      upstreams: {
        data: { total: 3, active: 3, configs: [inherited, accessor, mismatch] },
        errorMessage: null,
        complete: true,
      },
      canResolveViaUpstream: true,
    });

    assert.strictEqual(getterReads, 0);
    assert.ok(html.includes("Upstream inspection is incomplete"));
    assert.ok(html.includes("0 active of 0 loaded"));
    assert.ok(!html.includes("Inherited secret"));
    assert.ok(!html.includes("Accessor secret"));
    assert.ok(!html.includes("Mismatched secret"));
    assert.ok(!html.includes("can likely resolve"));

    let formatReads = 0;
    const hostileResult = {
      name: "package",
      workspace: "acme",
      repo: "repo",
      local: { data: null, errorMessage: null, complete: true },
      upstreams: {
        data: { total: 0, active: 0, configs: [] },
        errorMessage: null,
        complete: true,
      },
    };
    Object.defineProperty(hostileResult, "format", {
      enumerable: true,
      get() {
        formatReads += 1;
        return "python";
      },
    });
    const hostileHtml = provider._getHtmlContent(hostileResult);
    assert.strictEqual(formatReads, 0);
    assert.ok(hostileHtml.includes("<dt>Format</dt><dd>Unknown</dd>"));
    assert.ok(hostileHtml.includes("Upstream inspection is incomplete"));

    let nestedReads = 0;
    const hostileNested = {
      name: "package",
      format: "python",
      workspace: "acme",
      repo: "repo",
      local: {},
      upstreams: { data: { total: 0, active: 0, configs: [] } },
    };
    for (const [target, property, value] of [
      [hostileNested.local, "errorMessage", "secret"],
      [hostileNested.local, "data", { status_str: "secret" }],
      [hostileNested.local, "complete", true],
      [hostileNested.upstreams, "errorMessage", "secret"],
      [hostileNested.upstreams, "complete", true],
    ]) {
      Object.defineProperty(target, property, {
        enumerable: true,
        get() { nestedReads += 1; return value; },
      });
    }
    const nestedHtml = provider._getHtmlContent(hostileNested);
    assert.strictEqual(nestedReads, 0);
    assert.ok(nestedHtml.includes("Upstream inspection is incomplete"));
    assert.ok(!nestedHtml.includes("secret"));
  });

  test("account reset disposes the panel and null preview results are ignored", () => {
    const provider = new UpstreamPreviewProvider({});
    let disposed = 0;
    provider._panel = { dispose() { disposed += 1; } };

    provider.resetForAccountChange();
    provider.show(null);

    assert.strictEqual(disposed, 1);
    assert.strictEqual(provider._panel, null);
  });

  test("renders the real safe preview producer contract without raw URL fallback", async () => {
    const checker = new UpstreamChecker({}, {
      connectionManager: {
        getState() {
          return { activationId: "account-a", accountEpoch: 1, sessionConnected: true };
        },
      },
      cloudsmithAPI: {
        async get(endpoint) {
          assert.match(endpoint, /upstream\/python\//);
          return apiSuccess([{
            name: "Private PyPI",
            slug_perm: "private-pypi",
            upstream_url: "https://user:password@example.com/private?token=secret#signed",
            is_active: true,
          }]);
        },
      },
    });
    checker.existsLocally = async () => ({ data: null, error: null, complete: true });
    const result = await checker.previewResolution(
      "acme", "repo", "package-a", "python"
    );
    const html = new UpstreamPreviewProvider({})._getHtmlContent(result);

    assert.ok(html.includes("Private PyPI"));
    assert.ok(html.includes("Origin unavailable"));
    assert.strictEqual(result.upstreams.data.configs[0].origin, "");
    assert.strictEqual("upstream_url" in result.upstreams.data.configs[0], false);
    for (const secret of ["user:password", "/private", "token=secret", "#signed"]) {
      assert.ok(!html.includes(secret));
      assert.ok(!JSON.stringify(result).includes(secret));
    }
  });
});

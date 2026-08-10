const assert = require("assert");
const { UpstreamPreviewProvider } = require("../views/upstreamPreviewProvider");

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
        error: null,
        complete: true,
      },
      upstreams: {
        data: {
          total: 2,
          active: 1,
          configs: [
            {
              name: "PyPI",
              upstream_url: "https://pypi.org/simple/",
              is_active: true,
            },
            {
              name: "Legacy mirror",
              upstream_url: "https://legacy.example/python",
              is_active: false,
            },
          ],
        },
        error: null,
        complete: true,
      },
      canResolveViaUpstream: true,
    });

    assert.ok(html.includes("Upstream resolution preview"));
    assert.ok(html.includes("PyPI"));
    assert.ok(html.includes("Legacy mirror"));
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
        error: null,
        complete: false,
      },
      upstreams: {
        data: {
          total: 0,
          active: 0,
          configs: [],
        },
        error: "Upstream availability could not be determined.",
        complete: false,
      },
      canResolveViaUpstream: false,
    });

    assert.ok(html.includes("Could not load upstream data"));
    assert.ok(html.includes("Local package status is incomplete"));
    assert.ok(!html.includes("Not found in example-repo"));
    assert.ok(!html.includes("Active policies"));
    assert.ok(!html.includes("No active upstreams"));
    assert.ok(!html.includes("Upload the package directly"));
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
});

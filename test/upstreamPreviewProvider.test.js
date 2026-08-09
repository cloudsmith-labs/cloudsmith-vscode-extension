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
      },
      upstreams: {
        data: {
          total: 0,
          active: 0,
          configs: [],
        },
        error: "Upstream availability could not be determined.",
      },
      canResolveViaUpstream: false,
    });

    assert.ok(html.includes("Could not load upstream data"));
    assert.ok(!html.includes("Active policies"));
  });
});

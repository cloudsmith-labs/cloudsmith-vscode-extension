const assert = require("assert");
const { UpstreamDetailProvider, SUPPORTED_FORMATS } = require("../views/upstreamDetailProvider");
const { SUPPORTED_UPSTREAM_FORMATS } = require("../util/upstreamFormats");

suite("UpstreamDetailProvider Test Suite", () => {
  test("uses the shared upstream format list", () => {
    assert.strictEqual(SUPPORTED_FORMATS, SUPPORTED_UPSTREAM_FORMATS);
  });

  test("shows successful upstreams together with a truthful partial warning", () => {
    const provider = new UpstreamDetailProvider({});
    const groupedUpstreams = new Map([
      [
        "python",
        [
          {
            name: "PyPI",
            upstream_url: "https://pypi.org/",
            is_active: true,
          },
        ],
      ],
    ]);

    const html = provider._getHtmlContent("acme", "example-repo", "Example Repo", {
      groupedUpstreams,
      failedFormats: ["alpine"],
      successfulFormats: 1,
    });

    assert.ok(html.includes("PyPI"));
    assert.ok(html.includes("Some upstream data could not be loaded."));
    assert.ok(html.includes("alpine"));
    assert.ok(!html.includes("Could not load upstreams."));
  });

  test("shows an error state when upstream data cannot be determined", () => {
    const provider = new UpstreamDetailProvider({});

    const html = provider._getHtmlContent("acme", "example-repo", "Example Repo", {
      groupedUpstreams: new Map(),
      failedFormats: ["python"],
      successfulFormats: 0,
    });

    assert.ok(html.includes("Could not load upstreams."));
    assert.ok(html.includes("The upstream configuration could not be loaded for this repository."));
  });

  test("account reset aborts in-flight work and disposes the panel", () => {
    const provider = new UpstreamDetailProvider({});
    let aborted = 0;
    let disposed = 0;
    provider._abortController = { abort() { aborted += 1; } };
    provider._panel = { dispose() { disposed += 1; } };

    provider.resetForAccountChange();

    assert.strictEqual(aborted, 1);
    assert.strictEqual(disposed, 1);
    assert.strictEqual(provider._abortController, null);
    assert.strictEqual(provider._panel, null);
  });

  test("a null fetch result replaces loading state with a bounded failure state", async () => {
    const provider = new UpstreamDetailProvider({});
    const panel = {
      title: "",
      webview: { html: "" },
      reveal() {},
    };
    provider._getOrCreatePanel = () => {
      provider._panel = panel;
      return panel;
    };
    provider._fetchGroupedUpstreams = async () => null;

    await provider.show("acme", "example-repo", "Example Repo");

    assert.ok(panel.webview.html.includes("Could not load upstreams."));
    assert.ok(!panel.webview.html.includes("Loading upstreams..."));
  });
});

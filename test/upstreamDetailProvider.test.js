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
            upstream_url: "https://user:pass@pypi.org/simple/?token=secret#fragment",
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
    assert.ok(html.includes("Origin"));
    assert.ok(html.includes("https://pypi.org"));
    assert.ok(!html.includes("user:pass"));
    assert.ok(!html.includes("/simple/"));
    assert.ok(!html.includes("token=secret"));
    assert.ok(!html.includes("#fragment"));
    assert.ok(html.includes("Some upstream data could not be loaded."));
    assert.ok(html.includes("alpine"));
    assert.ok(!html.includes("Could not load upstreams."));
  });

  test("malformed and unsupported URLs fail closed without breaking cards", () => {
    const provider = new UpstreamDetailProvider({});
    const groupedUpstreams = new Map([
      ["python", [
        {
          name: "Malformed\u202ename",
          upstream_url: "not a URL",
          is_active: true,
          mode: { private: true },
          index_status: { private: true },
          distro_versions: ["version\u202eone", { private: true }, "x".repeat(10_000)],
        },
        { name: "Local file", upstream_url: "file:///tmp/secret", is_active: false },
      ]],
    ]);

    const html = provider._getHtmlContent("acme", "repo", "Repo", {
      groupedUpstreams,
      failedFormats: [],
      uninspectedFormats: [],
      successfulFormats: 26,
      complete: true,
    });

    assert.ok(html.includes("Malformed name"));
    assert.ok(html.includes("Local file"));
    assert.ok(html.includes("Origin unavailable"));
    assert.ok(!html.includes("not a URL"));
    assert.ok(!html.includes("file:///"));
    assert.ok(!html.includes("[object Object]"));
    assert.ok(!html.includes("\u202e"));
    assert.ok(html.length < 20_000);
  });

  test("caps rendered cards before joining HTML", () => {
    const provider = new UpstreamDetailProvider({});
    const groupedUpstreams = new Map([
      ["python", Array.from({ length: 201 }, (_, index) => ({
        name: `Mirror ${index}`,
        upstream_url: `https://mirror-${index}.example/path`,
      }))],
    ]);

    const html = provider._getHtmlContent("acme", "repo", "Repo", {
      groupedUpstreams,
      failedFormats: [],
      uninspectedFormats: [],
      successfulFormats: 26,
      complete: true,
    });
    assert.ok(html.includes("Showing 200 of 201 loaded upstreams."));
    assert.ok(!html.includes("Mirror 200"));
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

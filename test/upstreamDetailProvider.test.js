const assert = require("assert");
const vscode = require("vscode");
const { UpstreamDetailProvider, SUPPORTED_FORMATS } = require("../views/upstreamDetailProvider");
const { SUPPORTED_UPSTREAM_FORMATS } = require("../util/upstreamFormats");
const { formatUpstreamFailureCategory } = require("../util/upstreamPresentation");

suite("UpstreamDetailProvider Test Suite", () => {
  function aggregate(overrides = {}) {
    const result = {
      upstreams: [],
      failedFormats: [],
      uninspectedFormats: [],
      unsupportedFormats: [],
      failures: [],
      successfulFormats: 20,
      configuredTotal: 0,
      complete: true,
      state: "empty",
      ...overrides,
    };
    result.upstreams = result.upstreams.map(upstream => ({
      ...upstream,
      format: upstream.format || upstream._format,
      _format: upstream._format || upstream.format,
    }));
    result.failures = result.failures.map((failure) => {
      const category = failure.category || (/permission/i.test(failure.message || "")
        ? "permission"
        : /time/i.test(failure.message || "") ? "timeout" : "unknown");
      return {
        ...failure,
        category,
        message: formatUpstreamFailureCategory(category),
        retryable: failure.retryable === true,
      };
    });
    return result;
  }

  function deferred() {
    let resolve;
    const promise = new Promise(resolvePromise => { resolve = resolvePromise; });
    return { promise, resolve };
  }

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
    assert.match(
      html,
      /<div class="detail-label">Origin<\/div><div class="detail-value mono">https:\/\/pypi\.org<\/div>/
    );
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

  test("shows trust level without explanatory trust callouts", () => {
    const provider = new UpstreamDetailProvider({});
    const html = provider._getHtmlContent("acme", "repo", "Repo", {
      groupedUpstreams: new Map([
        ["python", [
          { name: "Trusted source", trust_level: "Trusted" },
          { name: "Untrusted source", trust_level: "Untrusted" },
        ]],
      ]),
      failedFormats: [],
      uninspectedFormats: [],
      successfulFormats: 20,
      configuredTotal: 2,
      complete: true,
      state: "complete",
    });

    assert.ok(html.includes("Trust level"));
    assert.ok(html.includes("Trusted"));
    assert.ok(html.includes("Untrusted"));
    assert.ok(!html.includes("Trusted upstream:"));
    assert.ok(!html.includes("Untrusted upstream (recommended):"));
    assert.ok(!html.includes("dependency confusion"));
    assert.ok(!html.includes("namesquatting"));
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
    assert.ok(html.includes("The upstream inventory could not be loaded for this repository."));
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

  test("shows safe per-format failures without hiding successful partial cards", async () => {
    const provider = new UpstreamDetailProvider({});
    const html = provider._getHtmlContent("acme", "repo", "Repo", {
      groupedUpstreams: new Map([["python", [{
        name: "PyPI <script>",
        origin: "https://pypi.org",
        is_active: true,
      }]]]),
      failedFormats: ["npm"],
      uninspectedFormats: [],
      unsupportedFormats: ["terraform"],
      failures: [{ format: "npm", category: "timeout", message: "The upstream request timed out." }],
      successfulFormats: 19,
      configuredTotal: null,
      complete: false,
      state: "partial",
    });

    assert.ok(html.includes("PyPI &lt;script&gt;"));
    assert.ok(html.includes("npm"));
    assert.ok(html.includes("timed out"));
    assert.ok(html.includes("Not applicable to this API: terraform"));
    assert.ok(html.includes(">Retry<"));
    assert.ok(/script-src 'nonce-[^']+'/.test(html));
    assert.ok(!html.includes("[object Object]"));
  });

  test("coalesces repeated Retry and replaces cards without duplication", async () => {
    const replacement = deferred();
    let calls = 0;
    const provider = new UpstreamDetailProvider({}, {
      loadUpstreams: async () => {
        calls += 1;
        if (calls === 1) {
          return aggregate({
            upstreams: [{ name: "Old", format: "python", origin: "https://old.example" }],
            failedFormats: ["npm"],
            failures: [{
              format: "npm",
              message: "The upstream request timed out.",
              retryable: true,
            }],
            successfulFormats: 19,
            configuredTotal: null,
            complete: false,
            state: "partial",
          });
        }
        return replacement.promise;
      },
    });
    const panel = { title: "", webview: { html: "" }, reveal() {} };
    provider._getOrCreatePanel = () => {
      provider._panel = panel;
      return panel;
    };
    await provider.show("acme", "repo", "Repo");
    const firstRetry = provider.retry();
    const duplicateRetry = provider.retry();
    assert.strictEqual(calls, 2);
    assert.ok(panel.webview.html.includes("Existing results remain visible"));
    replacement.resolve(aggregate({
      upstreams: [{ name: "New", format: "npm", origin: "https://new.example" }],
      configuredTotal: 1,
      state: "complete",
    }));
    await Promise.all([firstRetry, duplicateRetry]);
    assert.ok(panel.webview.html.includes("New"));
    assert.ok(panel.webview.html.includes("Old"));
    assert.strictEqual((panel.webview.html.match(/class="upstream-card"/g) || []).length, 2);
  });

  test("targets Retry to unavailable formats and retains success per format", async () => {
    const calls = [];
    const provider = new UpstreamDetailProvider({}, {
      loadUpstreams: async (_workspace, _repo, options) => {
        calls.push(options);
        if (calls.length === 1) {
          return aggregate({
            upstreams: [{ name: "PyPI", format: "python", _format: "python", origin: "https://pypi.org" }],
            failedFormats: ["npm"],
            failures: [{ format: "npm", message: "Timed out.", retryable: true }],
            successfulFormats: 19,
            configuredTotal: null,
            complete: false,
            state: "partial",
          });
        }
        return aggregate({
          upstreams: [{ name: "npmjs", format: "npm", _format: "npm", origin: "https://registry.npmjs.org" }],
          successfulFormats: 1,
          configuredTotal: 1,
          complete: true,
          state: "complete",
        });
      },
    });
    const panel = { title: "", webview: { html: "" }, reveal() {} };
    provider._getOrCreatePanel = () => {
      provider._panel = panel;
      return panel;
    };
    await provider.show("acme", "repo", "Repo");
    await provider.retry();

    assert.deepStrictEqual(calls[1].formats, ["npm"]);
    assert.ok(panel.webview.html.includes("PyPI"));
    assert.ok(panel.webview.html.includes("npmjs"));
    assert.strictEqual((panel.webview.html.match(/class="upstream-card"/g) || []).length, 2);
  });

  test("retains a verified format over an incomplete Retry page", async () => {
    let calls = 0;
    const provider = new UpstreamDetailProvider({}, {
      loadUpstreams: async () => {
        calls += 1;
        if (calls === 1) return aggregate({
          upstreams: [{ name: "Verified", format: "python", origin: "https://verified.example" }],
          uninspectedFormats: ["python"],
          failures: [{ format: "python", category: "timeout", retryable: true }],
          successfulFormats: 19,
          configuredTotal: null,
          complete: false,
          state: "partial",
        });
        return aggregate({
          upstreams: [{ name: "Partial page", format: "python", origin: "https://partial.example" }],
          uninspectedFormats: ["python"],
          failures: [{ format: "python", category: "invalid_response", retryable: false }],
          successfulFormats: 0,
          configuredTotal: null,
          complete: false,
          state: "partial",
        });
      },
    });
    const panel = { title: "", webview: { html: "" }, reveal() {} };
    provider._getOrCreatePanel = () => {
      provider._panel = panel;
      return panel;
    };
    await provider.show("acme", "repo", "Repo");
    await provider.retry();
    assert.ok(panel.webview.html.includes("Verified"));
    assert.ok(!panel.webview.html.includes("Partial page"));
    assert.ok(panel.webview.html.includes("Previously verified: python"));
  });

  test("keeps zero-card Retry partial when other formats were inspected empty", async () => {
    let calls = 0;
    const provider = new UpstreamDetailProvider({}, {
      loadUpstreams: async () => {
        calls += 1;
        return aggregate({
          failedFormats: ["npm"],
          failures: [{ format: "npm", category: "timeout", retryable: true }],
          successfulFormats: calls === 1 ? 19 : 0,
          configuredTotal: null,
          complete: false,
          state: calls === 1 ? "partial" : "failed",
        });
      },
    });
    const panel = { title: "", webview: { html: "" }, reveal() {} };
    provider._getOrCreatePanel = () => {
      provider._panel = panel;
      return panel;
    };
    await provider.show("acme", "repo", "Repo");
    await provider.retry();
    assert.strictEqual(provider._lastSettled.state, "partial");
    assert.strictEqual(provider._lastSettled.successfulFormats, 19);
  });

  test("keeps prior successful cards when Retry produces no useful replacement", async () => {
    let calls = 0;
    const provider = new UpstreamDetailProvider({}, {
      loadUpstreams: async () => {
        calls += 1;
        if (calls === 1) {
          return aggregate({
            upstreams: [{ name: "Existing", format: "python", origin: "https://pypi.org" }],
            failedFormats: ["npm"],
            failures: [{
              format: "npm",
              message: "The upstream request timed out.",
              retryable: true,
            }],
            successfulFormats: 19,
            configuredTotal: null,
            complete: false,
            state: "partial",
          });
        }
        return aggregate({
          failedFormats: ["npm"],
          failures: [{ format: "npm", message: "Permission denied." }],
          successfulFormats: 0,
          configuredTotal: null,
          complete: false,
          state: "failed",
        });
      },
    });
    const panel = { title: "", webview: { html: "" }, reveal() {} };
    provider._getOrCreatePanel = () => {
      provider._panel = panel;
      return panel;
    };

    await provider.show("acme", "repo", "Repo");
    await provider.retry();

    assert.ok(panel.webview.html.includes("Existing"));
    assert.ok(panel.webview.html.includes("You do not have permission"));
    assert.ok(panel.webview.html.includes("Refresh failed; showing the previous verified results."));
    assert.strictEqual((panel.webview.html.match(/class="upstream-card"/g) || []).length, 1);
  });

  test("an older repository completion cannot clear or publish over the current load", async () => {
    const oldLoad = deferred();
    const currentLoad = deferred();
    let calls = 0;
    const provider = new UpstreamDetailProvider({}, {
      loadUpstreams: async (_workspace, repoSlug) => {
        calls += 1;
        return repoSlug === "old" ? oldLoad.promise : currentLoad.promise;
      },
    });
    const panel = { title: "", webview: { html: "" }, reveal() {} };
    provider._getOrCreatePanel = () => {
      provider._panel = panel;
      return panel;
    };

    const older = provider.show("acme", "old", "Old");
    const current = provider.show("acme", "current", "Current");
    oldLoad.resolve(aggregate({
      upstreams: [{ name: "Stale", format: "python", origin: "https://stale.example" }],
      configuredTotal: 1,
      state: "complete",
    }));
    await older;

    const duplicateCurrent = provider.show("acme", "current", "Current");
    assert.strictEqual(calls, 2);
    currentLoad.resolve(aggregate({
      upstreams: [{ name: "Current", format: "python", origin: "https://current.example" }],
      configuredTotal: 1,
      state: "complete",
    }));
    await Promise.all([current, duplicateCurrent]);

    assert.ok(panel.webview.html.includes("Current"));
    assert.ok(!panel.webview.html.includes("Stale"));
  });

  test("settles an unexpected loader throw instead of leaving the loading state", async () => {
    const provider = new UpstreamDetailProvider({}, {
      loadUpstreams: async () => { throw new Error("https://user:secret@example.com/?token=secret"); },
    });
    const panel = { title: "", webview: { html: "" }, reveal() {} };
    provider._getOrCreatePanel = () => {
      provider._panel = panel;
      return panel;
    };

    await provider.show("acme", "repo", "Repo");

    assert.ok(panel.webview.html.includes("Could not load upstreams."));
    assert.ok(!panel.webview.html.includes("Loading upstreams..."));
    assert.ok(!panel.webview.html.includes("user:secret"));
    assert.ok(!panel.webview.html.includes("token=secret"));
  });

  test("fails closed on malformed aggregate contracts", async () => {
    for (const malformed of [undefined, {}, { upstreams: {} }, {
      ...aggregate(),
      complete: true,
      configuredTotal: null,
    }, aggregate({
      upstreams: [{
        name: "Secret origin",
        format: "python",
        origin: "https://user:secret@example.com/?token=secret",
      }],
      configuredTotal: 1,
      state: "complete",
    }), {
      ...aggregate({
        failedFormats: ["npm"],
        failures: [{
          format: "npm",
          category: "timeout",
          message: "https://user:secret@example.com/?token=secret",
        }],
        successfulFormats: 19,
        configuredTotal: null,
        complete: false,
        state: "failed",
      }),
      failures: [{
        format: "npm",
        category: "timeout",
        message: "https://user:secret@example.com/?token=secret",
      }],
    }]) {
      const provider = new UpstreamDetailProvider({}, { loadUpstreams: async () => malformed });
      const panel = { title: "", webview: { html: "" }, reveal() {} };
      provider._getOrCreatePanel = () => {
        provider._panel = panel;
        return panel;
      };
      await provider.show("acme", "repo", "Repo");
      assert.ok(panel.webview.html.includes("Could not load upstreams."));
      assert.ok(!panel.webview.html.includes("[object Object]"));
      assert.ok(!panel.webview.html.includes("user:secret"));
      assert.ok(!panel.webview.html.includes("token=secret"));
    }
  });

  test("accepts only the exact Retry message and disposes its listener", () => {
    const original = vscode.window.createWebviewPanel;
    let listener;
    let listenerDisposed = 0;
    let retries = 0;
    const panel = {
      webview: {
        html: "",
        onDidReceiveMessage(callback) {
          listener = callback;
          return { dispose() { listenerDisposed += 1; } };
        },
      },
      onDidDispose() {},
      reveal() {},
      dispose() {},
    };
    vscode.window.createWebviewPanel = () => panel;
    try {
      const provider = new UpstreamDetailProvider({});
      provider.retry = () => { retries += 1; };
      provider._getOrCreatePanel("Repo");
      listener({ command: "retry", extra: true });
      listener(Object.defineProperty({}, "command", { get() { throw new Error("hostile"); } }));
      listener({ command: "retry" });
      assert.strictEqual(retries, 1);
      provider.dispose();
      assert.strictEqual(listenerDisposed, 1);
    } finally {
      vscode.window.createWebviewPanel = original;
    }
  });
});

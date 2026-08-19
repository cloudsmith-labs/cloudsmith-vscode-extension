const assert = require("assert");
const vscode = require("vscode");
const {
  UpstreamDetailProvider: UpstreamDetailProviderImplementation,
  SUPPORTED_FORMATS,
} = require("../views/upstreamDetailProvider");
const { UpstreamChecker } = require("../util/upstreamChecker");
const {
  getUpstreamFormatDescriptor,
  SUPPORTED_UPSTREAM_FORMATS,
} = require("../util/upstreamFormats");
const { formatUpstreamFailureCategory } = require("../util/upstreamPresentation");
const { apiSuccess } = require("./apiResultHelpers");
const { assertWebviewDocument } = require("./helpers/webviewSemanticContract");

suite("UpstreamDetailProvider Test Suite", () => {
  const NON_INSPECTABLE_FORMATS = SUPPORTED_UPSTREAM_FORMATS.filter(format => (
    !getUpstreamFormatDescriptor(format)?.inspectable
  ));
  class UpstreamDetailProvider extends UpstreamDetailProviderImplementation {
    constructor(context, options = {}) {
      super(context, {
        loadUpstreams: async () => aggregate(),
        ...options,
      });
    }
  }

  test("requires a safe upstream inventory facade", () => {
    assert.throws(
      () => new UpstreamDetailProviderImplementation({}),
      /safe upstream inventory facade/
    );
  });

  function aggregate(overrides = {}) {
    const requestedFormats = Array.isArray(overrides.requestedFormats)
      ? overrides.requestedFormats
      : SUPPORTED_UPSTREAM_FORMATS;
    const aggregateOverrides = { ...overrides };
    delete aggregateOverrides.requestedFormats;
    const result = {
      upstreams: [],
      failedFormats: [],
      uninspectedFormats: [],
      unsupportedFormats: requestedFormats.filter(format => (
        !getUpstreamFormatDescriptor(format)?.inspectable
      )),
      failures: [],
      successfulFormats: 20,
      configuredTotal: 0,
      complete: true,
      state: "empty",
      ...aggregateOverrides,
    };
    result.upstreams = result.upstreams.map(upstream => ({
      ...upstream,
      format: upstream.format || upstream._format,
      _format: upstream._format || upstream.format,
      origin: Object.prototype.hasOwnProperty.call(upstream, "origin") ? upstream.origin : "",
    }));
    result.failures = result.failures.map((failure) => {
      const category = failure.category || (/permission/i.test(failure.message || "")
        ? "permission"
        : /time/i.test(failure.message || "") ? "timeout" : "unknown");
      return {
        ...failure,
        apiFormat: failure.apiFormat || failure.format,
        category,
        state: failure.state || (result.failedFormats.includes(failure.format)
          ? "failed"
          : "uninspected"),
        message: formatUpstreamFailureCategory(category),
        httpStatus: failure.httpStatus ?? null,
        retryable: failure.retryable === true,
        retryAfterMs: failure.retryAfterMs ?? null,
        requestId: failure.requestId ?? null,
        serverRequestId: failure.serverRequestId ?? null,
      };
    });
    if (!Object.prototype.hasOwnProperty.call(aggregateOverrides, "outcomes")) {
      const failed = new Set(result.failedFormats);
      const uninspected = new Set(result.uninspectedFormats);
      const unsupported = new Set(result.unsupportedFormats);
      result.outcomes = requestedFormats.map((format) => {
        const descriptor = getUpstreamFormatDescriptor(format);
        const entries = result.upstreams.filter(upstream => upstream.format === descriptor?.format);
        let state = "success";
        if (!descriptor?.inspectable || unsupported.has(descriptor.format)) state = "unsupported";
        else if (failed.has(descriptor.format)) state = "failed";
        else if (uninspected.has(descriptor.format)) state = "uninspected";
        const aggregateFailure = result.failures.find(failure => failure.format === descriptor?.format);
        const failure = ["failed", "uninspected"].includes(state)
          ? {
              category: aggregateFailure?.category || "unknown",
              message: aggregateFailure?.message || formatUpstreamFailureCategory("unknown"),
              httpStatus: aggregateFailure?.httpStatus ?? null,
              retryable: aggregateFailure?.retryable === true,
              retryAfterMs: aggregateFailure?.retryAfterMs ?? null,
              requestId: aggregateFailure?.requestId ?? null,
              serverRequestId: aggregateFailure?.serverRequestId ?? null,
            }
          : null;
        return {
          format: descriptor?.format,
          apiFormat: descriptor?.apiFormat ?? null,
          state,
          status: state === "success" ? "loaded" : state,
          entries,
          upstreams: entries,
          authoritative: ["success", "unsupported"].includes(state),
          failure,
          pageCount: state === "success" ? 1 : 0,
        };
      });
    }
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
            origin: "https://pypi.org",
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
    assertWebviewDocument(html, { interactive: true, scripted: true });

    assert.ok(html.includes("PyPI"));
    assert.match(html, /<article class="upstream-card" aria-labelledby="upstream-title-1">/);
    assert.match(html, /<h3 id="upstream-title-1" class="card-title">PyPI<\/h3>/);
    assert.ok(html.includes("Origin"));
    assert.match(
      html,
      /<dt class="detail-label">Origin<\/dt><dd class="detail-value mono">https:\/\/pypi\.org<\/dd>/
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

  test("shows supported trust values as status pills without explanatory copy", () => {
    const provider = new UpstreamDetailProvider({});
    const html = provider._getHtmlContent("acme", "repo", "Repo", {
      groupedUpstreams: new Map([
        ["python", [
          { name: "Trusted source", trust_level: "Trusted" },
          { name: "Untrusted source", trust_level: "Untrusted" },
          { name: "Future source", trust_level: "Future value" },
        ]],
      ]),
      failedFormats: [],
      uninspectedFormats: [],
      successfulFormats: 20,
      configuredTotal: 3,
      complete: true,
      state: "complete",
    });

    assert.match(html, /status-badge status-badge-trusted">Trusted<\/span>/);
    assert.match(html, /status-badge status-badge-untrusted">Untrusted<\/span>/);
    assert.ok(!html.includes("Trust level"));
    assert.ok(!html.includes("Future value"));
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
    assert.ok(!html.includes("Not applicable"));
    assert.ok(!html.includes("terraform"));
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
    assert.match(panel.webview.html, /const retryFocus = "pending"/);
    assert.match(panel.webview.html, /data-retry-progress/);
    replacement.resolve(aggregate({
      upstreams: [{ name: "New", format: "npm", origin: "https://new.example" }],
      requestedFormats: ["npm"],
      successfulFormats: 1,
      configuredTotal: 1,
      state: "complete",
    }));
    await Promise.all([firstRetry, duplicateRetry]);
    assert.ok(panel.webview.html.includes("New"));
    assert.ok(panel.webview.html.includes("Old"));
    assert.match(panel.webview.html, /const retryFocus = "settled"/);
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
          requestedFormats: options.formats,
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
          requestedFormats: ["python"],
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
          requestedFormats: calls === 1 ? SUPPORTED_UPSTREAM_FORMATS : ["npm"],
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
          requestedFormats: ["npm"],
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
    }), aggregate({
      upstreams: [{
        name: "Privileged", format: "python", origin: "", upstream_url: "https://example.com",
      }],
      configuredTotal: 1,
      state: "complete",
    }), aggregate({
      upstreams: [{ name: "Bad priority", format: "python", origin: "", priority: -1 }],
      configuredTotal: 1,
      state: "complete",
    }), aggregate({
      upstreams: [{
        name: "Bad indexing", format: "python", origin: "", index_package_count: "0",
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

  test("accepts only canonical or explicitly redacted origins at the aggregate boundary", async () => {
    const cases = [
      ["https://example.com", true],
      ["", true],
      [undefined, false],
      [" ", false],
      ["https://user:pass@example.com", false],
      ["https://example.com?token=secret", false],
      ["https://example.com#fragment", false],
      ["https://example.com/path", false],
      ["not a URL", false],
      ["Origin unavailable", false],
    ];
    for (const [origin, accepted] of cases) {
      const provider = new UpstreamDetailProvider({}, {
        loadUpstreams: async () => aggregate({
          upstreams: [{ name: "Mirror", format: "python", origin }],
          unsupportedFormats: NON_INSPECTABLE_FORMATS,
          successfulFormats: 20,
          configuredTotal: 1,
          complete: true,
          state: "complete",
        }),
      });
      const panel = { title: "", webview: { html: "" }, reveal() {} };
      provider._getOrCreatePanel = () => {
        provider._panel = panel;
        return panel;
      };
      await provider.show("acme", "repo", "Repo");
      assert.strictEqual(panel.webview.html.includes("Mirror"), accepted, String(origin));
      if (origin === "") {
        assert.ok(panel.webview.html.includes("Origin unavailable"));
        assert.doesNotMatch(panel.webview.html, /<h3 class="card-title">Mirror \(\)<\/h3>/);
      }
      assert.ok(!panel.webview.html.includes("user:pass"));
      assert.ok(!panel.webview.html.includes("token=secret"));
      assert.ok(!panel.webview.html.includes("#fragment"));
    }
  });

  test("binds aggregate completeness to the exact requested format scope", async () => {
    const oneFormat = aggregate({
      requestedFormats: ["python"],
      upstreams: [{ name: "Scoped", format: "python", origin: "" }],
      successfulFormats: 1,
      configuredTotal: 1,
      complete: true,
      state: "complete",
    });
    const provider = new UpstreamDetailProvider({}, { loadUpstreams: async () => oneFormat });
    const full = await provider._fetchGroupedUpstreams(
      "acme", "repo", new AbortController().signal
    );
    assert.strictEqual(full.state, "failed");

    const targeted = await provider._fetchGroupedUpstreams(
      "acme", "repo", new AbortController().signal, { formats: ["python"] }
    );
    assert.strictEqual(targeted.state, "complete");
    assert.strictEqual(targeted.groupedUpstreams.get("python")[0].name, "Scoped");
  });

  test("snapshots validated failure diagnostics and rejects proxy failures", async () => {
    const source = aggregate({
      requestedFormats: ["npm"],
      failedFormats: ["npm"],
      failures: [{ format: "npm", category: "timeout", retryable: true }],
      successfulFormats: 0,
      configuredTotal: null,
      complete: false,
      state: "failed",
    });
    const provider = new UpstreamDetailProvider({}, { loadUpstreams: async () => source });
    const settled = await provider._fetchGroupedUpstreams(
      "acme", "repo", new AbortController().signal, { formats: ["npm"] }
    );
    source.failures[0].format = "https://user:secret@example.com/?token=secret";
    source.failedFormats[0] = "https://user:secret@example.com/?token=secret";
    assert.deepStrictEqual(settled.failedFormats, ["npm"]);
    assert.strictEqual(settled.failures[0].format, "npm");
    assert.ok(Object.isFrozen(settled.failures));
    assert.ok(Object.isFrozen(settled.failures[0]));
    const html = provider._getHtmlContent("acme", "repo", "Repo", settled);
    assert.ok(!html.includes("user:secret"));
    assert.ok(!html.includes("token=secret"));

    let reads = 0;
    const hostile = aggregate({
      requestedFormats: ["npm"],
      failedFormats: ["npm"],
      failures: [{ format: "npm", category: "timeout", retryable: true }],
      successfulFormats: 0,
      configuredTotal: null,
      complete: false,
      state: "failed",
    });
    hostile.failures[0] = new Proxy(hostile.failures[0], {
      get(target, property, receiver) {
        reads += 1;
        return Reflect.get(target, property, receiver);
      },
    });
    const hostileProvider = new UpstreamDetailProvider({}, {
      loadUpstreams: async () => hostile,
    });
    const rejected = await hostileProvider._fetchGroupedUpstreams(
      "acme", "repo", new AbortController().signal, { formats: ["npm"] }
    );
    assert.strictEqual(rejected.state, "failed");
    assert.strictEqual(reads, 0);

    let rootReads = 0;
    const hostileRoot = aggregate({
      requestedFormats: ["npm"],
      failedFormats: ["npm"],
      failures: [{ format: "npm", category: "timeout", retryable: true }],
      successfulFormats: 0,
      configuredTotal: null,
      complete: false,
      state: "failed",
    });
    Object.defineProperty(hostileRoot, "failures", {
      enumerable: true,
      get() {
        rootReads += 1;
        return [{ format: "https://user:secret@example.com/?token=secret" }];
      },
    });
    const rootProvider = new UpstreamDetailProvider({}, {
      loadUpstreams: async () => hostileRoot,
    });
    const rootRejected = await rootProvider._fetchGroupedUpstreams(
      "acme", "repo", new AbortController().signal, { formats: ["npm"] }
    );
    assert.strictEqual(rootRejected.state, "failed");
    assert.strictEqual(rootReads, 0);

    let outcomeReads = 0;
    const hostileOutcome = aggregate({
      requestedFormats: ["npm"],
      failedFormats: ["npm"],
      failures: [{ format: "npm", category: "timeout", retryable: true }],
      successfulFormats: 0,
      configuredTotal: null,
      complete: false,
      state: "failed",
    });
    hostileOutcome.outcomes[0] = new Proxy(hostileOutcome.outcomes[0], {
      get(target, property, receiver) {
        outcomeReads += 1;
        return Reflect.get(target, property, receiver);
      },
    });
    const outcomeProvider = new UpstreamDetailProvider({}, {
      loadUpstreams: async () => hostileOutcome,
    });
    const outcomeRejected = await outcomeProvider._fetchGroupedUpstreams(
      "acme", "repo", new AbortController().signal, { formats: ["npm"] }
    );
    assert.strictEqual(outcomeRejected.state, "failed");
    assert.strictEqual(outcomeReads, 0);
  });

  test("rejects hostile flat aggregate entries without executing Proxy traps", async () => {
    const source = aggregate({
      requestedFormats: ["python"],
      upstreams: [{
        name: "PyPI",
        _format: "python",
        format: "python",
        origin: "https://pypi.org",
      }],
      successfulFormats: 1,
      configuredTotal: 1,
      complete: true,
      state: "complete",
    });
    let reads = 0;
    source.upstreams[0] = new Proxy({ ...source.upstreams[0] }, {
      get(target, property, receiver) {
        reads += 1;
        return Reflect.get(target, property, receiver);
      },
    });
    const provider = new UpstreamDetailProvider({}, { loadUpstreams: async () => source });

    const result = await provider._fetchGroupedUpstreams(
      "acme", "repo", new AbortController().signal, { formats: ["python"] }
    );

    assert.strictEqual(result.state, "failed");
    assert.strictEqual(reads, 0);
  });

  test("renders a real producer aggregate with a redacted origin without losing the card", async () => {
    const endpoints = [];
    const connectionManager = {
      getState() {
        return { activationId: "account-a", accountEpoch: 1, sessionConnected: true };
      },
    };
    const checker = new UpstreamChecker({}, {
      connectionManager,
      cloudsmithAPI: {
        async get(endpoint) {
          endpoints.push(endpoint);
          return endpoint.includes("upstream/python/")
            ? apiSuccess([{
                name: "Private PyPI",
                slug_perm: "private-pypi",
                upstream_url: "https://user:password@example.com/private?token=secret#signed",
                is_active: true,
                verify_ssl: false,
                priority: "10",
                trust_level: "Trusted",
                index_status: "Up-to-date",
                index_package_count: 0,
                distro_versions: ["3.12"],
              }])
            : apiSuccess([]);
        },
      },
    });
    const provider = new UpstreamDetailProvider({}, {
      loadUpstreams: (workspace, repo, options) => (
        checker.getAllUpstreamData(workspace, repo, options)
      ),
    });
    const panel = { title: "", webview: { html: "" }, reveal() {} };
    provider._getOrCreatePanel = () => {
      provider._panel = panel;
      return panel;
    };

    await provider.show("acme", "repo", "Repo");

    assert.strictEqual(endpoints.length, 20);
    assert.ok(endpoints.every(endpoint => !/upstream\/(raw|terraform|conan|cocoapods|luarocks|vagrant)\//.test(endpoint)));
    assert.ok(panel.webview.html.includes("Private PyPI"));
    assert.ok(panel.webview.html.includes("Origin unavailable"));
    assert.ok(panel.webview.html.includes(">Trusted<"));
    assert.ok(panel.webview.html.includes("Disabled"));
    assert.ok(panel.webview.html.includes(">10<"));
    assert.ok(panel.webview.html.includes("0 packages"));
    assert.ok(!panel.webview.html.includes("Could not load upstreams"));
    for (const secret of ["user:password", "/private", "token=secret", "#signed"]) {
      assert.ok(!panel.webview.html.includes(secret), secret);
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

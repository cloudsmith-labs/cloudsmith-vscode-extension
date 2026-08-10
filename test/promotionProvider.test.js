const assert = require("assert");
const { PromotionProvider } = require("../views/promotionProvider");
const { apiFailure, apiSuccess } = require("./apiResultHelpers");

suite("Safe package promotion workflow", () => {
  function deferred() {
    let resolve;
    const promise = new Promise(settle => { resolve = settle; });
    return { promise, resolve };
  }

  function page(data, options = {}) {
    const pageNumber = options.page || 1;
    const pageTotal = options.pageTotal || 1;
    return apiSuccess(data, {
      headers: options.malformedHeaders ? {} : {
        "x-pagination-page": String(pageNumber),
        "x-pagination-pagetotal": String(pageTotal),
        "x-pagination-count": String(options.count ?? data.length),
        "x-pagination-pagesize": String(options.pageSize || 100),
      },
    });
  }

  function createHarness(options = {}) {
    const calls = { get: [], post: [], quickPick: [], warning: [], info: [], error: [], progress: [] };
    const sourceTags = new Set(options.sourceTags || []);
    const targetTags = new Set(options.targetTags || []);
    let targetExists = options.targetExists === true;
    let targetQueryCount = 0;
    let sourceReadCount = 0;
    let state = {
      activationId: "activation-a",
      accountEpoch: 1,
      sessionConnected: true,
    };
    const manager = {
      getState() { return { ...state }; },
      changeAccount() {
        state = { activationId: "activation-b", accountEpoch: 2, sessionConnected: true };
      },
    };

    const sourceRecord = (overrides = {}) => ({
      namespace: "workspace",
      repository: "source",
      slug_perm: "source-package-id",
      name: "artifact",
      version: "1.0.0",
      format: "npm",
      is_copyable: true,
      checksum_sha256: "checksum-a",
      tags: { info: [...sourceTags] },
      ...overrides,
    });
    const targetRecord = (overrides = {}) => ({
      namespace: "workspace",
      repository: "target",
      slug_perm: "target-package-id",
      name: "artifact",
      version: "1.0.0",
      format: "npm",
      checksum_sha256: "checksum-a",
      tags: { info: [...targetTags] },
      status_str: "Completed",
      ...overrides,
    });

    const api = {
      async get(endpoint, requestOptions) {
        calls.get.push({ endpoint, options: requestOptions });
        if (requestOptions?.cancellationToken?.isCancellationRequested) {
          return apiFailure("cancelled", { outcomeUnknown: false });
        }
        if (endpoint === "packages/workspace/source/source-package-id/") {
          sourceReadCount += 1;
          if (options.sourceFailureAt === sourceReadCount) {
            return apiFailure(options.sourceFailureKind || "not_found", {
              status: options.sourceFailureStatus ?? 404,
              outcomeUnknown: false,
            });
          }
          const overrides = typeof options.sourceOverrides === "function"
            ? options.sourceOverrides(sourceReadCount)
            : options.sourceOverrides || {};
          return apiSuccess(sourceRecord(overrides));
        }
        if (endpoint === "repos/workspace/target/") {
          if (options.targetRepositoryFailure) {
            return apiFailure("forbidden", { status: 403, outcomeUnknown: false });
          }
          return apiSuccess({ name: "Target", slug: "target", namespace: "workspace" });
        }
        if (endpoint.startsWith("packages/workspace/target/?")) {
          targetQueryCount += 1;
          if (options.targetQueryFailureAt === targetQueryCount) {
            return apiFailure("network_error", { outcomeUnknown: false });
          }
          if (options.malformedPaginationAt === targetQueryCount) {
            return page([], { malformedHeaders: true });
          }
          if (options.targetAppearsOnQuery === targetQueryCount) targetExists = true;
          const data = targetExists ? [targetRecord()] : [];
          if (options.duplicateTargetAt === targetQueryCount && targetExists) {
            data.push(targetRecord({ slug_perm: "second-target-package-id" }));
          }
          const result = page(data, {
            pageTotal: options.targetPageTotalAt === targetQueryCount ? 21 : 1,
            count: options.targetPageTotalAt === targetQueryCount ? 2100 : data.length,
          });
          if (options.cancelPreflightAfterReads && requestOptions?.cancellationToken) {
            requestOptions.cancellationToken.isCancellationRequested = true;
          }
          return result;
        }
        if (endpoint.startsWith("packages/workspace/?")) {
          if (options.presenceHintFailure) {
            return apiFailure("network_error", { outcomeUnknown: false });
          }
          const data = options.hintExists || targetExists ? [targetRecord()] : [];
          return page(data);
        }
        throw new Error(`Unexpected GET ${endpoint}`);
      },
      async post(endpoint, json, requestOptions) {
        calls.post.push({ endpoint, json, options: requestOptions });
        if (endpoint.endsWith("/copy/")) {
          if (options.changeAccountAfterCopy) manager.changeAccount();
          if (options.copyThrows) {
            if (options.copyCompletesRemotely) targetExists = true;
            throw new Error("write socket closed");
          }
          if (options.copyFailure) {
            if (options.copyCompletesRemotely) targetExists = true;
            return apiFailure(options.copyFailureKind || "forbidden", {
              status: options.copyFailureStatus ?? 403,
              outcomeUnknown: options.copyAmbiguous === true,
            });
          }
          targetExists = true;
          if (options.copyMalformedResponse) return apiSuccess({});
          return apiSuccess(targetRecord(options.copyResponseOverrides));
        }
        if (endpoint === "packages/workspace/source/source-package-id/tag/") {
          if (options.sourceTagFailure) {
            if (options.sourceTagAppliedRemotely) {
              for (const tag of json.tags) sourceTags.add(tag);
            }
            return apiFailure(options.sourceTagFailureKind || "forbidden", {
              status: options.sourceTagFailureStatus ?? 403,
              outcomeUnknown: options.sourceTagAmbiguous === true,
            });
          }
          if (options.sourceTagMalformedResponse) return apiSuccess({});
          if (options.sourceTagPretendSuccess) return apiSuccess(sourceRecord());
          for (const tag of json.tags) sourceTags.add(tag);
          return apiSuccess(sourceRecord());
        }
        if (endpoint === "packages/workspace/target/target-package-id/tag/") {
          if (options.targetTagFailure) {
            if (options.targetTagAppliedRemotely) {
              for (const tag of json.tags) targetTags.add(tag);
            }
            return apiFailure(options.targetTagFailureKind || "forbidden", {
              status: options.targetTagFailureStatus ?? 403,
              outcomeUnknown: options.targetTagAmbiguous === true,
            });
          }
          for (const tag of json.tags) targetTags.add(tag);
          return apiSuccess(targetRecord(options.targetTagResponseOverrides));
        }
        throw new Error(`Unexpected POST ${endpoint}`);
      },
    };

    const confirmation = options.confirmationDeferred;
    const window = {
      async withProgress(progressOptions, task) {
        calls.progress.push(progressOptions);
        if (
          options.progressThrowsBeforeExecution
          && progressOptions.title.startsWith("Promoting ")
        ) {
          throw new Error("progress renderer unavailable");
        }
        const cancellationToken = {
          isCancellationRequested: options.cancelPreflight === true
            && progressOptions.title === "Checking promotion requirements...",
          onCancellationRequested() { return { dispose() {} }; },
        };
        const result = await task({ report() {} }, cancellationToken);
        if (
          options.progressThrowsAfterExecution
          && progressOptions.title.startsWith("Promoting ")
        ) {
          throw new Error("progress renderer unavailable");
        }
        return result;
      },
      async showQuickPick(items) {
        calls.quickPick.push(items);
        if (options.cancelTargetSelection) return undefined;
        return items.find(item => item._target?.repository === "target");
      },
      async showWarningMessage(message, dialogOptions, action) {
        calls.warning.push({ message, options: dialogOptions, action });
        if (action === "Promote package") {
          if (options.changeAccountAtConfirmation) manager.changeAccount();
          if (confirmation) return confirmation.promise;
          return options.confirm === false ? undefined : "Promote package";
        }
        return undefined;
      },
      async showInformationMessage(message) { calls.info.push(message); },
      async showErrorMessage(message) { calls.error.push(message); },
    };
    const workspace = {
      getConfiguration() {
        return {
          get(name) {
            if (name === "promotionPipeline") {
              return Object.prototype.hasOwnProperty.call(options, "pipeline")
                ? options.pipeline
                : [];
            }
            if (name === "promotionTags") {
              return options.tags || { onPromote: [], onReceive: [] };
            }
            return undefined;
          },
        };
      },
    };
    const repositoryResult = options.repositoryResult || {
      repositories: [
        { name: "Source", slug: "source", namespace: "workspace" },
        { name: "Target", slug: "target", namespace: "workspace" },
      ],
      error: null,
      warning: null,
      partial: false,
      stale: false,
    };
    const provider = new PromotionProvider({}, {
      api,
      connectionManager: manager,
      credentialManager: { async getApiKey() { return "credential-sentinel"; } },
      fetchWorkspaceRepositories: async () => repositoryResult,
      window,
      workspace,
      withProgress: window.withProgress,
      now: () => Date.parse("2026-08-09T12:00:00Z"),
    });
    const item = {
      namespace: "workspace",
      repository: "source",
      slug_perm: { id: "Slug", value: "source-package-id" },
      slug_perm_raw: "source-package-id",
      name: "stale-display-name",
      version: { value: "0.0.1" },
      format: "raw",
      is_copyable: false,
    };
    return {
      provider,
      calls,
      manager,
      item,
      sourceRecord,
      targetRecord,
      sourceTags,
      targetTags,
      targetExists: () => targetExists,
      targetQueryCount: () => targetQueryCount,
    };
  }

  test("full success uses fresh canonical identity, confirms, writes once per stage, and verifies", async () => {
    const harness = createHarness({
      tags: {
        onPromote: ["promoted-to-{target}", "approved-{date}"],
        onReceive: ["promoted-from-{source}"],
      },
    });
    let refreshes = 0;
    const outcome = await harness.provider.runPromotionWorkflow(harness.item, {
      refresh() { refreshes += 1; },
    });

    assert.strictEqual(outcome.overall, "succeeded");
    assert.strictEqual(outcome.copy.status, "succeeded");
    assert.strictEqual(outcome.sourceTag.status, "succeeded");
    assert.strictEqual(outcome.targetTag.status, "succeeded");
    assert.strictEqual(outcome.reconciliation.status, "succeeded");
    assert.strictEqual(outcome.source.name, "artifact");
    assert.strictEqual(outcome.source.version, "1.0.0");
    assert.strictEqual(refreshes, 1);
    assert.strictEqual(harness.provider._recentTargets.length, 1);
    assert(Object.isFrozen(outcome));
    assert.deepStrictEqual(harness.calls.post.map(call => call.json), [
      { destination: "workspace/target", republish: false },
      { action: "add", tags: ["promoted-to-target", "approved-2026-08-09"] },
      { action: "add", tags: ["promoted-from-source"] },
    ]);
    assert(harness.calls.post.every(call => call.options.retry === "never"));
    const confirmation = harness.calls.warning.find(call => call.action === "Promote package");
    assert(confirmation.message.includes("artifact"));
    assert(confirmation.options.detail.includes("Version: 1.0.0"));
    assert(confirmation.options.detail.includes("Source: workspace/source"));
    assert(confirmation.options.detail.includes("Target: workspace/target"));
    assert(confirmation.options.detail.includes("Target package: Not present"));
    assert(confirmation.options.detail.includes("Cloudsmith verifies this when promotion begins"));
    assert.strictEqual(harness.calls.info.length, 1);
    assert.strictEqual(
      harness.calls.progress.find(entry => entry.title.startsWith("Promoting ")).cancellable,
      false
    );
  });

  test("no configured tags is a verified full success without tag writes", async () => {
    const harness = createHarness();
    const outcome = await harness.provider.runPromotionWorkflow(harness.item);
    assert.strictEqual(outcome.overall, "succeeded");
    assert.strictEqual(outcome.sourceTag.status, "not_required");
    assert.strictEqual(outcome.targetTag.status, "not_required");
    assert.strictEqual(harness.calls.post.length, 1);
  });

  test("cancellation at target selection, preflight, or confirmation performs no writes", async () => {
    for (const options of [
      { cancelTargetSelection: true },
      { cancelPreflight: true },
      { cancelPreflightAfterReads: true },
      { confirm: false },
    ]) {
      const harness = createHarness(options);
      const outcome = await harness.provider.runPromotionWorkflow(harness.item);
      assert.strictEqual(outcome.overall, "cancelled");
      assert.strictEqual(harness.calls.post.length, 0);
    }
  });

  test("no write occurs while final confirmation is pending", async () => {
    const gate = deferred();
    const harness = createHarness({ confirmationDeferred: gate });
    const pending = harness.provider.runPromotionWorkflow(harness.item);
    for (let attempt = 0; attempt < 20 && harness.calls.warning.length === 0; attempt += 1) {
      await new Promise(resolve => setImmediate(resolve));
    }
    assert.strictEqual(harness.calls.post.length, 0);
    gate.resolve(undefined);
    const outcome = await pending;
    assert.strictEqual(outcome.overall, "cancelled");
    assert.strictEqual(harness.calls.post.length, 0);
  });

  test("fresh non-copyable, missing, malformed, and identity-changed packages stop before writes", async () => {
    const cases = [
      { sourceOverrides: { is_copyable: false }, expected: "package_not_copyable" },
      { sourceFailureAt: 1, expected: "source_missing" },
      { sourceOverrides: { is_copyable: "false" }, expected: "malformed_copyability" },
      { sourceOverrides: { slug_perm: "different" }, expected: "source_identity_changed" },
      { sourceOverrides: { checksum_sha256: null, version_digest: null }, expected: "missing_package_fingerprint" },
    ];
    for (const testCase of cases) {
      const harness = createHarness(testCase);
      const outcome = await harness.provider.runPromotionWorkflow(harness.item);
      assert.strictEqual(outcome.errorCode, testCase.expected);
      assert.strictEqual(harness.calls.post.length, 0);
    }
  });

  test("target existence hint and fresh target race both block before copy", async () => {
    const hinted = createHarness({ targetExists: true });
    const hintedOutcome = await hinted.provider.runPromotionWorkflow(hinted.item);
    assert.strictEqual(hintedOutcome.errorCode, "target_package_exists");
    assert.strictEqual(hinted.calls.post.length, 0);
    assert.strictEqual(hinted.calls.warning.some(call => call.action === "Promote package"), false);
    assert(hinted.calls.quickPick[0].find(item => item._target.repository === "target").detail.includes("unavailable"));

    const raced = createHarness({ presenceHintFailure: true, targetAppearsOnQuery: 1 });
    const racedOutcome = await raced.provider.runPromotionWorkflow(raced.item);
    assert.strictEqual(racedOutcome.errorCode, "target_package_exists");
    assert.strictEqual(raced.calls.post.length, 0);
  });

  test("missing target, permission failure, partial repository enumeration, and malformed pagination fail closed", async () => {
    const cases = [
      { targetRepositoryFailure: true },
      { repositoryResult: { repositories: [], error: null, warning: {}, partial: true, stale: false } },
      { malformedPaginationAt: 1 },
      { targetPageTotalAt: 1 },
    ];
    for (const options of cases) {
      const harness = createHarness({ ...options, presenceHintFailure: true });
      const outcome = await harness.provider.runPromotionWorkflow(harness.item);
      assert.strictEqual(outcome.overall, "failed");
      assert.strictEqual(harness.calls.post.length, 0);
    }
  });

  test("post-confirmation target drift invalidates approval before every write", async () => {
    const harness = createHarness({ presenceHintFailure: true, targetAppearsOnQuery: 2 });
    const outcome = await harness.provider.runPromotionWorkflow(harness.item);
    assert.strictEqual(outcome.errorCode, "preflight_changed");
    assert.strictEqual(harness.calls.post.length, 0);
    assert.strictEqual(harness.calls.warning.filter(call => call.action === "Promote package").length, 1);
  });

  test("definite copy failure is complete failure and never attempts tags or refresh", async () => {
    const harness = createHarness({
      copyFailure: true,
      tags: { onPromote: ["source-tag"], onReceive: ["target-tag"] },
    });
    let refreshes = 0;
    const outcome = await harness.provider.runPromotionWorkflow(harness.item, {
      refresh() { refreshes += 1; },
    });
    assert.strictEqual(outcome.overall, "failed");
    assert.strictEqual(outcome.copy.status, "failed");
    assert.strictEqual(harness.calls.post.length, 1);
    assert.strictEqual(refreshes, 0);
    assert.strictEqual(harness.calls.info.length, 0);
  });

  test("ambiguous copy is read back once but never attributed as success or tagged", async () => {
    for (const completesRemotely of [false, true]) {
      const harness = createHarness({
        copyFailure: true,
        copyAmbiguous: true,
        copyFailureKind: "timeout",
        copyFailureStatus: null,
        copyCompletesRemotely: completesRemotely,
        tags: { onPromote: ["source-tag"], onReceive: ["target-tag"] },
      });
      const outcome = await harness.provider.runPromotionWorkflow(harness.item);
      assert.strictEqual(outcome.overall, "ambiguous");
      assert.strictEqual(outcome.copy.status, "ambiguous");
      assert.strictEqual(outcome.reconciliation.status, completesRemotely ? "succeeded" : "ambiguous");
      assert.strictEqual(harness.calls.post.length, 1);
      assert.strictEqual(harness.calls.info.length, 0);
    }
  });

  test("thrown or malformed copy completion is ambiguous and never blindly retried", async () => {
    for (const options of [
      { copyThrows: true, copyCompletesRemotely: true },
      { copyMalformedResponse: true },
    ]) {
      const harness = createHarness(options);
      const outcome = await harness.provider.runPromotionWorkflow(harness.item);
      assert.strictEqual(outcome.overall, "ambiguous");
      assert.strictEqual(outcome.copy.status, "ambiguous");
      assert.strictEqual(harness.calls.post.filter(call => call.endpoint.endsWith("/copy/")).length, 1);
    }
  });

  test("post-copy duplicate or unreadable target state stops before all tag writes", async () => {
    for (const options of [
      { duplicateTargetAt: 3 },
      { targetQueryFailureAt: 3 },
    ]) {
      const harness = createHarness({
        ...options,
        tags: { onPromote: ["source-tag"], onReceive: ["target-tag"] },
      });
      const outcome = await harness.provider.runPromotionWorkflow(harness.item);
      assert.strictEqual(outcome.overall, "ambiguous");
      assert.strictEqual(outcome.copy.status, "succeeded");
      assert.strictEqual(outcome.sourceTag.status, "not_attempted");
      assert.strictEqual(outcome.targetTag.status, "not_attempted");
      assert.strictEqual(harness.calls.post.length, 1);
    }
  });

  test("source and target tag failures are independent and partial never becomes success", async () => {
    const variants = [
      { sourceTagFailure: true, expectedSource: "failed", expectedTarget: "succeeded" },
      { targetTagFailure: true, expectedSource: "succeeded", expectedTarget: "failed" },
      { sourceTagFailure: true, targetTagFailure: true, expectedSource: "failed", expectedTarget: "failed" },
    ];
    for (const variant of variants) {
      const harness = createHarness({
        ...variant,
        tags: { onPromote: ["source-tag"], onReceive: ["target-tag"] },
      });
      const outcome = await harness.provider.runPromotionWorkflow(harness.item);
      assert.strictEqual(outcome.overall, "partial");
      assert.strictEqual(outcome.sourceTag.status, variant.expectedSource);
      assert.strictEqual(outcome.targetTag.status, variant.expectedTarget);
      assert.strictEqual(harness.calls.post.length, 3);
      assert.strictEqual(harness.calls.info.length, 0);
      assert.strictEqual(harness.provider._recentTargets.length, 0);
    }
  });

  test("an ambiguous tag becomes success only when final reads observe every requested tag", async () => {
    const reconciled = createHarness({
      sourceTagFailure: true,
      sourceTagAmbiguous: true,
      sourceTagFailureKind: "timeout",
      sourceTagFailureStatus: null,
      sourceTagAppliedRemotely: true,
      tags: { onPromote: ["source-tag"], onReceive: [] },
    });
    const reconciledOutcome = await reconciled.provider.runPromotionWorkflow(reconciled.item);
    assert.strictEqual(reconciledOutcome.overall, "succeeded");
    assert.strictEqual(reconciledOutcome.sourceTag.status, "succeeded");
    assert.strictEqual(reconciledOutcome.sourceTag.evidence, "fresh_read");

    const unresolved = createHarness({
      sourceTagFailure: true,
      sourceTagAmbiguous: true,
      sourceTagFailureKind: "timeout",
      sourceTagFailureStatus: null,
      tags: { onPromote: ["source-tag"], onReceive: [] },
    });
    const unresolvedOutcome = await unresolved.provider.runPromotionWorkflow(unresolved.item);
    assert.strictEqual(unresolvedOutcome.overall, "ambiguous");
    assert.strictEqual(unresolvedOutcome.sourceTag.status, "ambiguous");
  });

  test("malformed or contradictory successful tag responses remain ambiguous until verified", async () => {
    for (const options of [
      { sourceTagMalformedResponse: true },
      { sourceTagPretendSuccess: true },
    ]) {
      const harness = createHarness({
        ...options,
        tags: { onPromote: ["source-tag"], onReceive: [] },
      });
      const outcome = await harness.provider.runPromotionWorkflow(harness.item);
      assert.strictEqual(outcome.overall, "ambiguous");
      assert.strictEqual(outcome.sourceTag.status, "ambiguous");
      assert.strictEqual(harness.calls.info.length, 0);
    }
  });

  test("a failed mandatory final read prevents full success", async () => {
    const harness = createHarness({ targetQueryFailureAt: 4 });
    const outcome = await harness.provider.runPromotionWorkflow(harness.item);
    assert.strictEqual(outcome.overall, "ambiguous");
    assert.strictEqual(outcome.copy.status, "succeeded");
    assert.strictEqual(outcome.reconciliation.status, "ambiguous");
    assert.strictEqual(harness.calls.info.length, 0);
  });

  test("pre-existing tags are proven by fresh reads and not written again", async () => {
    const harness = createHarness({
      sourceTags: ["source-tag"],
      targetTags: ["target-tag"],
      tags: { onPromote: ["source-tag"], onReceive: ["target-tag"] },
    });
    const outcome = await harness.provider.runPromotionWorkflow(harness.item);
    assert.strictEqual(outcome.overall, "succeeded");
    assert.strictEqual(outcome.sourceTag.status, "not_required");
    assert.strictEqual(outcome.targetTag.status, "not_required");
    assert.strictEqual(harness.calls.post.length, 1);
  });

  test("manual retry after ambiguous copy performs reads only and cannot duplicate copy", async () => {
    const harness = createHarness({
      copyFailure: true,
      copyAmbiguous: true,
      copyFailureKind: "timeout",
      copyFailureStatus: null,
      copyCompletesRemotely: true,
    });
    const first = await harness.provider.runPromotionWorkflow(harness.item);
    const second = await harness.provider.runPromotionWorkflow(harness.item);
    assert.strictEqual(first.overall, "ambiguous");
    assert.strictEqual(second.errorCode, "target_package_exists");
    assert.strictEqual(harness.calls.post.filter(call => call.endpoint.endsWith("/copy/")).length, 1);
  });

  test("duplicate invocation is rejected while confirmation is active and guard cleans up", async () => {
    const gate = deferred();
    const harness = createHarness({ confirmationDeferred: gate });
    const firstPending = harness.provider.runPromotionWorkflow(harness.item);
    for (let attempt = 0; attempt < 20 && harness.calls.warning.length === 0; attempt += 1) {
      await new Promise(resolve => setImmediate(resolve));
    }
    const duplicate = await harness.provider.runPromotionWorkflow(harness.item);
    assert.strictEqual(duplicate.errorCode, "promotion_busy");
    assert.strictEqual(harness.calls.post.length, 0);
    gate.resolve(undefined);
    await firstPending;

    const later = await harness.provider.runPromotionWorkflow(harness.item);
    assert.strictEqual(later.overall, "cancelled");
    assert.strictEqual(harness.calls.quickPick.length, 2);
  });

  test("result publication completes before the operation guard is released", async () => {
    const refreshGate = deferred();
    const harness = createHarness();
    const firstPending = harness.provider.runPromotionWorkflow(harness.item, {
      refresh: () => refreshGate.promise,
    });
    for (let attempt = 0; attempt < 30 && harness.calls.post.length === 0; attempt += 1) {
      await new Promise(resolve => setImmediate(resolve));
    }
    const duplicate = await harness.provider.runPromotionWorkflow(harness.item);
    assert.strictEqual(duplicate.errorCode, "promotion_busy");
    refreshGate.resolve();
    assert.strictEqual((await firstPending).overall, "succeeded");
  });

  test("account change during awaited refresh suppresses stale package result details", async () => {
    const refreshGate = deferred();
    const harness = createHarness();
    const pending = harness.provider.runPromotionWorkflow(harness.item, {
      refresh: () => refreshGate.promise,
    });
    for (let attempt = 0; attempt < 30 && harness.calls.post.length === 0; attempt += 1) {
      await new Promise(resolve => setImmediate(resolve));
    }
    const warningCountBeforeAccountChange = harness.calls.warning.length;
    harness.manager.changeAccount();
    refreshGate.resolve();

    const outcome = await pending;

    assert.strictEqual(outcome.overall, "succeeded");
    assert.strictEqual(harness.calls.info.length, 0);
    const laterWarnings = harness.calls.warning.slice(warningCountBeforeAccountChange);
    assert(laterWarnings.some(call => (
      call.message.includes("active Cloudsmith account changed")
    )));
    assert.strictEqual(laterWarnings.some(call => call.message.includes("artifact")), false);
  });

  test("account change before dispatch prevents writes", async () => {
    const harness = createHarness({ changeAccountAtConfirmation: true });
    const outcome = await harness.provider.runPromotionWorkflow(harness.item);
    assert.strictEqual(outcome.errorCode, "account_changed");
    assert.strictEqual(harness.calls.post.length, 0);
  });

  test("account change after copy suppresses later writes and stale package publication", async () => {
    const harness = createHarness({
      changeAccountAfterCopy: true,
      tags: { onPromote: ["source-tag"], onReceive: ["target-tag"] },
    });
    let refreshes = 0;
    const outcome = await harness.provider.runPromotionWorkflow(harness.item, {
      refresh() { refreshes += 1; },
    });
    assert.strictEqual(outcome.overall, "ambiguous");
    assert.strictEqual(harness.calls.post.length, 1);
    assert.strictEqual(refreshes, 0);
    assert.strictEqual(harness.calls.info.length, 0);
    assert(harness.calls.warning.some(call => call.message.includes("active Cloudsmith account changed")));
  });

  test("pipeline and tag configuration are validated before confirmation or writes", async () => {
    for (const options of [
      { pipeline: ["source", "source"] },
      { pipeline: "source" },
      { pipeline: { source: "target" } },
      { pipeline: null },
      { pipeline: ["source", "missing"] },
      { pipeline: ["target"] },
      { tags: { onPromote: ["{unknown}"], onReceive: [] } },
    ]) {
      const harness = createHarness(options);
      const outcome = await harness.provider.runPromotionWorkflow(harness.item);
      assert.strictEqual(outcome.overall, "failed");
      assert.strictEqual(harness.calls.post.length, 0);
    }
  });

  test("target tag write evidence requires the expected target package identifier", async () => {
    const harness = createHarness({
      targetTagResponseOverrides: { slug_perm: "different-target-package-id" },
      tags: { onPromote: [], onReceive: ["target-tag"] },
    });

    const outcome = await harness.provider.runPromotionWorkflow(harness.item);

    assert.strictEqual(outcome.overall, "succeeded");
    assert.strictEqual(outcome.targetTag.status, "succeeded");
    assert.strictEqual(outcome.targetTag.evidence, "fresh_read");
  });

  test("final reads can reconcile an unattempted tag verification failure", async () => {
    const harness = createHarness({
      sourceTags: ["source-tag"],
      sourceFailureAt: 4,
      sourceFailureKind: "network_error",
      sourceFailureStatus: null,
      tags: { onPromote: ["source-tag"], onReceive: [] },
    });

    const outcome = await harness.provider.runPromotionWorkflow(harness.item);

    assert.strictEqual(outcome.overall, "succeeded");
    assert.strictEqual(outcome.sourceTag.status, "succeeded");
    assert.strictEqual(outcome.sourceTag.attempted, false);
    assert.strictEqual(outcome.sourceTag.evidence, "fresh_read");
    assert.strictEqual(harness.calls.post.length, 1);
  });

  test("recent target ranking is scoped to the canonical package identifier", () => {
    const harness = createHarness();
    harness.provider._recentTargets.push({
      activationId: "activation-a",
      accountEpoch: 1,
      workspace: "workspace",
      sourceRepository: "source",
      packageIdentifier: "another-package-id",
      targetRepository: "target",
    });

    assert.deepStrictEqual(harness.provider._recentFor(
      { activationId: "activation-a", accountEpoch: 1 },
      { workspace: "workspace", repository: "source", packageIdentifier: "source-package-id" }
    ), []);
  });

  test("progress failures preserve whether a write was issued and any settled outcome", async () => {
    const beforeExecution = createHarness({ progressThrowsBeforeExecution: true });
    const beforeOutcome = await beforeExecution.provider.runPromotionWorkflow(beforeExecution.item);
    assert.strictEqual(beforeOutcome.overall, "failed");
    assert.strictEqual(beforeOutcome.copy.status, "not_attempted");
    assert.strictEqual(beforeOutcome.remoteState, "unchanged");
    assert.strictEqual(beforeExecution.calls.post.length, 0);

    const afterExecution = createHarness({ progressThrowsAfterExecution: true });
    const afterOutcome = await afterExecution.provider.runPromotionWorkflow(afterExecution.item);
    assert.strictEqual(afterOutcome.overall, "succeeded");
    assert.strictEqual(afterOutcome.copy.status, "succeeded");
    assert.strictEqual(afterExecution.calls.post.length, 1);
  });

  test("credentials and raw API diagnostics never enter outcomes or user messages", async () => {
    const harness = createHarness({ copyFailure: true });
    const outcome = await harness.provider.runPromotionWorkflow(harness.item);
    const serialized = JSON.stringify({
      outcome,
      warning: harness.calls.warning,
      info: harness.calls.info,
      error: harness.calls.error,
    });
    assert.strictEqual(serialized.includes("credential-sentinel"), false);
    assert.strictEqual(serialized.includes("Test forbidden failure"), false);
  });

  test("promotion status retains typed transport failure and exact format filtering", async () => {
    const failed = createHarness({ pipeline: ["source", "target"] });
    failed.provider.api = { async get() { return apiFailure("rate_limited", { status: 429 }); } };
    const failure = await failed.provider.getPromotionStatus("workspace", "artifact", "1.0.0", "npm");
    assert.deepStrictEqual(failure.items, []);
    assert.strictEqual(failure.error.kind, "rate_limited");

    const filtered = createHarness({ pipeline: ["source", "target"] });
    filtered.provider.api = {
      async get() {
        return apiSuccess([
          { name: "artifact", version: "1.0.0", format: "python", repository: "source" },
          { name: "artifact", version: "1.0.0", format: "npm", repository: "source", status_str: "Completed" },
        ]);
      },
    };
    const status = await filtered.provider.getPromotionStatus("workspace", "artifact", "1.0.0", "npm");
    assert.strictEqual(status.items[0].found, true);
    assert.strictEqual(status.items[0].status, "Completed");
  });
});

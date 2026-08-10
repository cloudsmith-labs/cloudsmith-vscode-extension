// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const vscode = require("vscode");
const { CloudsmithAPI } = require("../util/cloudsmithAPI");
const { apiEndpoint } = require("../util/apiEndpoint");
const { CredentialManager } = require("../util/credentialManager");
const { PaginatedFetch } = require("../util/paginatedFetch");
const { fetchWorkspaceRepositories } = require("../util/workspaceRepositoryFetcher");
const { buildExactPackageQuery, packageMatchesExactIdentity } = require("../util/packageQuery");
const { captureAccount, isAccountCurrent, resolveConnectionManager } = require("../util/accountOperation");
const {
  PromotionContractError,
  createOutcome,
  createSourceLocator,
  createStage,
  createTagPlan,
  deepFreeze,
  missingTags,
  normalizeFreshSource,
  normalizePipeline,
  normalizeTargetPackage,
  normalizeTargetRepository,
  preflightFingerprint,
} = require("../util/promotionContracts");

const EXACT_PACKAGE_PAGE_SIZE = 100;
const MAX_EXACT_PACKAGE_PAGES = 20;
const MAX_EXACT_PACKAGE_ITEMS = EXACT_PACKAGE_PAGE_SIZE * MAX_EXACT_PACKAGE_PAGES;
const MAX_RECENT_TARGETS = 20;

class PromotionProvider {
  constructor(context, options = {}) {
    this.context = context;
    this.api = options.api || new CloudsmithAPI(context);
    this._connectionManager = resolveConnectionManager(context, options.connectionManager);
    this._credentialManager = options.credentialManager
      || new CredentialManager(context, { connectionManager: this._connectionManager });
    this._paginatedFetch = options.paginatedFetch || new PaginatedFetch(this.api);
    this._fetchWorkspaceRepositories = options.fetchWorkspaceRepositories || fetchWorkspaceRepositories;
    this._window = options.window || vscode.window;
    this._workspace = options.workspace || vscode.workspace;
    this._withProgress = options.withProgress || this._window.withProgress.bind(this._window);
    this._now = options.now || (() => Date.now());
    this._activeOperations = new Map();
    this._recentTargets = [];
    this._operationSequence = 0;
    this._disposed = false;
  }

  dispose() {
    this._disposed = true;
    this._activeOperations.clear();
    this._recentTargets.length = 0;
  }

  resetForAccountChange() {
    this._recentTargets.length = 0;
  }

  getPipeline() {
    const config = this._workspace.getConfiguration("cloudsmith-vsc");
    return config.get("promotionPipeline");
  }

  getTagTemplates() {
    const config = this._workspace.getConfiguration("cloudsmith-vsc");
    return config.get("promotionTags");
  }

  async getPromotionStatus(workspace, name, version, format) {
    let pipeline;
    try {
      pipeline = normalizePipeline(this.getPipeline());
    } catch (error) {
      return { items: [], error };
    }
    if (pipeline.length === 0) return { items: [], error: null };
    if (!name || !version || !format) {
      return { items: [], error: new Error("Package identity is incomplete.") };
    }

    let endpoint;
    try {
      const query = buildExactPackageQuery(name, version, format);
      endpoint = apiEndpoint(["packages", workspace], { query: { query, page_size: 100 } });
    } catch (error) {
      return { items: [], error };
    }
    const results = await this.api.get(endpoint, {
      responseType: "array",
      validate: isPromotionStatusArray,
      retry: "never",
    });
    if (!results.ok) return { items: [], error: results.error };

    const repoMap = new Map();
    for (const pkg of results.data.filter(candidate => (
      packageMatchesExactIdentity(candidate, { name, version, format })
    ))) {
      repoMap.set(pkg.repository, pkg);
    }
    return {
      items: pipeline.map(repo => {
        const pkg = repoMap.get(repo) || null;
        return {
          repo,
          found: Boolean(pkg),
          status: pkg ? (pkg.status_str || "Unknown") : "Not present",
          quarantined: pkg ? pkg.status_str === "Quarantined" : false,
          policyViolated: pkg ? pkg.policy_violated === true : false,
          pkg,
        };
      }),
      error: null,
    };
  }

  async runPromotionWorkflow(item, options = {}) {
    let locator;
    try {
      locator = createSourceLocator(item);
    } catch (error) {
      const outcome = failureOutcome(errorCode(error, "malformed_source_locator"));
      await this._showFailure(outcome);
      return outcome;
    }

    const operation = this._acquireOperation(locator);
    if (!operation) {
      const outcome = failureOutcome("promotion_busy");
      await this._window.showInformationMessage(
        "A promotion is already in progress for this package. Wait for it to finish and try again."
      );
      return outcome;
    }

    let account = null;
    try {
      account = captureAccount(this._connectionManager);
      if (!account) return await this._publishFailure(failureOutcome("authentication_unavailable"));

      const apiKey = await this._credentialManager.getApiKey();
      if (!apiKey || !this._isCurrent(operation, account)) {
        return await this._publishStaleOrFailure(operation, account, "authentication_unavailable");
      }

      const sourceRead = await this._readSource(locator, apiKey, null, account);
      if (!sourceRead.ok) {
        const outcome = failureOutcome(sourceRead.errorCode);
        return await this._publish(outcome, operation, account, options);
      }
      if (!sourceRead.source.copyable) {
        const outcome = failureOutcome("package_not_copyable", { source: sourceRead.source });
        return await this._publish(outcome, operation, account, options);
      }

      let pipeline;
      try {
        pipeline = normalizePipeline(this.getPipeline());
      } catch (error) {
        const outcome = failureOutcome(errorCode(error, "malformed_pipeline"), { source: sourceRead.source });
        return await this._publish(outcome, operation, account, options);
      }

      const candidatesResult = await this._loadTargetCandidates(
        sourceRead.source,
        pipeline,
        account,
        apiKey
      );
      if (!candidatesResult.ok) {
        const outcome = failureOutcome(candidatesResult.errorCode, { source: sourceRead.source });
        return await this._publish(outcome, operation, account, options);
      }
      if (candidatesResult.targets.length === 0) {
        const outcome = failureOutcome("no_target_repositories", { source: sourceRead.source });
        return await this._publish(outcome, operation, account, options);
      }

      const presenceHints = await this._loadPresenceHints(sourceRead.source, apiKey, account);
      if (!this._isCurrent(operation, account)) {
        return await this._publish(this._staleOutcome(), operation, account, options);
      }
      const selectedTarget = await this._selectTarget(
        sourceRead.source,
        candidatesResult.targets,
        presenceHints,
        account
      );
      if (!selectedTarget) {
        return createOutcome({
          source: sourceRead.source,
          overall: "cancelled",
          confirmation: createStage("cancelled"),
          remoteState: "unchanged",
        });
      }
      if (presenceHints?.has(selectedTarget.repository)) {
        const outcome = failureOutcome("target_package_exists", {
          source: sourceRead.source,
          target: selectedTarget,
        });
        return await this._publish(outcome, operation, account, options);
      }

      let tagPlan;
      try {
        const date = new Date(this._now()).toISOString().slice(0, 10);
        tagPlan = createTagPlan(
          this.getTagTemplates(),
          sourceRead.source.repository,
          selectedTarget.repository,
          date
        );
      } catch (error) {
        const outcome = failureOutcome(errorCode(error, "malformed_tag_configuration"), {
          source: sourceRead.source,
          target: selectedTarget,
        });
        return await this._publish(outcome, operation, account, options);
      }

      const firstPreflightResult = await this._withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "Checking promotion requirements...",
          cancellable: true,
        },
        (_progress, cancellationToken) => this.preflight(
          locator,
          selectedTarget,
          tagPlan,
          account,
          apiKey,
          cancellationToken
        )
      );
      if (!firstPreflightResult.ok) {
        if (firstPreflightResult.errorCode === "cancelled") {
          return createOutcome({
            source: sourceRead.source,
            target: selectedTarget,
            preflight: createStage("cancelled"),
            overall: "cancelled",
            remoteState: "unchanged",
          });
        }
        const outcome = failureOutcome(firstPreflightResult.errorCode, {
          source: firstPreflightResult.source || sourceRead.source,
          target: selectedTarget,
          preflight: createStage("failed", { errorCode: firstPreflightResult.errorCode }),
        });
        return await this._publish(outcome, operation, account, options);
      }
      if (!this._isCurrent(operation, account)) {
        return await this._publish(this._staleOutcome(), operation, account, options);
      }

      const confirmation = await this._confirm(firstPreflightResult.preflight, tagPlan);
      if (confirmation !== "Promote package") {
        return createOutcome({
          source: firstPreflightResult.preflight.source,
          target: firstPreflightResult.preflight.target,
          preflight: createStage("succeeded", { evidence: "fresh_read" }),
          confirmation: createStage("cancelled"),
          overall: "cancelled",
          remoteState: "unchanged",
        });
      }
      if (!this._isCurrent(operation, account)) {
        return await this._publish(this._staleOutcome(), operation, account, options);
      }

      const finalPreflightResult = await this.preflight(
        locator,
        selectedTarget,
        tagPlan,
        account,
        apiKey,
        null
      );
      if (
        !finalPreflightResult.ok
        || preflightFingerprint(firstPreflightResult.preflight, account, tagPlan)
          !== preflightFingerprint(finalPreflightResult.preflight, account, tagPlan)
      ) {
        const outcome = failureOutcome("preflight_changed", {
          source: firstPreflightResult.preflight.source,
          target: firstPreflightResult.preflight.target,
          preflight: createStage("failed", { errorCode: "preflight_changed" }),
          confirmation: createStage("succeeded", { evidence: "user_confirmation" }),
        });
        return await this._publish(outcome, operation, account, options);
      }
      if (!this._isCurrent(operation, account)) {
        return await this._publish(this._staleOutcome(), operation, account, options);
      }

      let outcome;
      const executionState = {
        writeIssued: false,
        copy: null,
        sourceTag: null,
        targetTag: null,
        reconciliation: null,
        outcome: null,
      };
      try {
        outcome = await this._withProgress(
          {
            location: vscode.ProgressLocation.Notification,
            title: `Promoting ${finalPreflightResult.preflight.source.name}...`,
            cancellable: false,
          },
          async progress => {
            const result = await this.execute(
              finalPreflightResult.preflight,
              tagPlan,
              account,
              apiKey,
              operation,
              progress,
              executionState
            );
            executionState.outcome = result;
            return result;
          }
        );
      } catch {
        outcome = executionState.outcome || interruptedExecutionOutcome(
          finalPreflightResult.preflight,
          tagPlan,
          executionState
        );
      }
      return await this._publish(outcome, operation, account, options);
    } catch {
      const outcome = failureOutcome("unexpected_error");
      if (account && this._isCurrent(operation, account)) {
        return await this._publish(outcome, operation, account, options);
      }
      return outcome;
    } finally {
      this._releaseOperation(operation);
    }
  }

  async preflight(locator, selectedTarget, tagPlan, account, apiKey, cancellationToken) {
    if (!this._isAccountCurrent(account)) return preflightFailure("account_changed");
    const sourceRead = await this._readSource(locator, apiKey, cancellationToken, account);
    if (!sourceRead.ok) return preflightFailure(sourceRead.errorCode, sourceRead.source);
    if (!sourceRead.source.copyable) {
      return preflightFailure("package_not_copyable", sourceRead.source);
    }
    if (sourceRead.source.repository === selectedTarget.repository) {
      return preflightFailure("invalid_target", sourceRead.source);
    }

    const [targetRead, packageRead] = await Promise.all([
      this._readTargetRepository(selectedTarget, apiKey, cancellationToken, account),
      this._findTargetPackages(
        sourceRead.source,
        selectedTarget,
        apiKey,
        cancellationToken,
        account,
        { stopOnPresence: true }
      ),
    ]);
    if (cancellationToken?.isCancellationRequested) {
      return preflightFailure("cancelled", sourceRead.source);
    }
    if (!this._isAccountCurrent(account)) return preflightFailure("account_changed", sourceRead.source);
    if (!targetRead.ok) return preflightFailure(targetRead.errorCode, sourceRead.source);
    if (!packageRead.ok || !packageRead.complete) {
      return preflightFailure(packageRead.errorCode || "target_state_unknown", sourceRead.source);
    }
    if (packageRead.packages.length > 0) {
      return preflightFailure("target_package_exists", sourceRead.source);
    }

    const preflight = deepFreeze({
      source: sourceRead.source,
      target: targetRead.target,
      targetPackageState: "absent",
      targetPackageCount: 0,
      permissions: deepFreeze({
        sourceCopyability: "passed",
        targetReadable: "passed",
        targetWrite: "not_exposed",
      }),
      tagPlan,
      checkedAtMs: this._now(),
    });
    return deepFreeze({ ok: true, preflight, errorCode: null });
  }

  async execute(preflight, tagPlan, account, apiKey, operation, progress, executionState = {}) {
    const base = {
      source: preflight.source,
      target: preflight.target,
      preflight: createStage("succeeded", { evidence: "fresh_read" }),
      confirmation: createStage("succeeded", { evidence: "user_confirmation" }),
    };
    if (!this._isCurrent(operation, account)) {
      return createOutcome({ ...base, overall: "failed", errorCode: "account_changed" });
    }

    reportProgress(progress, "Copying package...");
    let copyResult;
    const copyEndpoint = apiEndpoint([
      "packages",
      preflight.source.workspace,
      preflight.source.repository,
      preflight.source.packageIdentifier,
      "copy",
    ]);
    try {
      executionState.writeIssued = true;
      copyResult = await this.api.post(
        copyEndpoint,
        { destination: `${preflight.target.workspace}/${preflight.target.repository}`, republish: false },
        { apiKey, responseType: "object", validate: isRecord, retry: "never" }
      );
    } catch {
      copyResult = null;
    }

    if (!copyResult || !copyResult.ok) {
      const ambiguous = !copyResult || !isDefiniteWriteFailure(copyResult.error);
      if (!ambiguous) {
        return createOutcome({
          ...base,
          copy: createStage("failed", {
            required: true,
            attempted: true,
            evidence: "write_response",
            errorCode: "copy_failed",
          }),
          overall: "failed",
          errorCode: "copy_failed",
          remoteState: "unchanged",
        });
      }
      return this._ambiguousCopyOutcome(preflight, tagPlan, account, apiKey, base);
    }

    let targetPackage;
    try {
      targetPackage = normalizeTargetPackage(copyResult.data, preflight.source, preflight.target);
    } catch {
      return this._ambiguousCopyOutcome(preflight, tagPlan, account, apiKey, base);
    }

    executionState.copy = createStage("succeeded", {
      required: true,
      attempted: true,
      evidence: "write_response",
    });

    if (!this._isCurrent(operation, account)) {
      return createOutcome({
        ...base,
        copy: createStage("succeeded", { required: true, attempted: true, evidence: "write_response" }),
        reconciliation: createStage("ambiguous", { errorCode: "account_changed" }),
        overall: "ambiguous",
        errorCode: "account_changed",
        remoteState: "changed",
      });
    }
    const postCopyRead = await this._findTargetPackages(
      preflight.source,
      preflight.target,
      apiKey,
      null,
      account,
      { stopOnPresence: false }
    );
    if (
      !postCopyRead.ok
      || !postCopyRead.complete
      || postCopyRead.packages.length !== 1
      || postCopyRead.packages[0].packageIdentifier !== targetPackage.packageIdentifier
    ) {
      return createOutcome({
        ...base,
        copy: createStage("succeeded", { required: true, attempted: true, evidence: "write_response" }),
        sourceTag: createStage(tagPlan.source.length ? "not_attempted" : "not_required", {
          required: tagPlan.source.length > 0,
        }),
        targetTag: createStage(tagPlan.target.length ? "not_attempted" : "not_required", {
          required: tagPlan.target.length > 0,
        }),
        reconciliation: createStage("ambiguous", { errorCode: "post_copy_state_unknown" }),
        overall: "ambiguous",
        errorCode: "post_copy_state_unknown",
        remoteState: "changed",
      });
    }
    targetPackage = postCopyRead.packages[0];

    let sourceTag = createStage(
      tagPlan.source.length > 0 ? "not_attempted" : "not_required",
      { required: tagPlan.source.length > 0 }
    );
    let targetTag = createStage(
      tagPlan.target.length > 0 ? "not_attempted" : "not_required",
      { required: tagPlan.target.length > 0 }
    );
    executionState.sourceTag = sourceTag;
    executionState.targetTag = targetTag;

    if (tagPlan.source.length > 0) {
      reportProgress(progress, "Checking source tags...");
      sourceTag = await this._applySourceTags(
        preflight.source,
        tagPlan.source,
        account,
        apiKey,
        operation
      );
      executionState.sourceTag = sourceTag;
    }
    if (tagPlan.target.length > 0 && this._isCurrent(operation, account)) {
      reportProgress(progress, "Checking target tags...");
      targetTag = await this._applyTargetTags(
        preflight.source,
        preflight.target,
        targetPackage.packageIdentifier,
        tagPlan.target,
        account,
        apiKey,
        operation
      );
      executionState.targetTag = targetTag;
    }

    if (!this._isCurrent(operation, account)) {
      return createOutcome({
        ...base,
        copy: createStage("succeeded", { required: true, attempted: true, evidence: "write_response" }),
        sourceTag,
        targetTag,
        reconciliation: createStage("ambiguous", { errorCode: "account_changed" }),
        overall: "ambiguous",
        errorCode: "account_changed",
        remoteState: "changed",
      });
    }

    reportProgress(progress, "Verifying promotion state...");
    const reconciliation = await this._reconcileFinalState(
      preflight.source,
      preflight.target,
      targetPackage.packageIdentifier,
      tagPlan,
      account,
      apiKey
    );
    executionState.reconciliation = reconciliation.ok
      ? createStage("succeeded", { evidence: "fresh_read" })
      : createStage("ambiguous", { errorCode: reconciliation.errorCode });
    if (!reconciliation.ok) {
      return createOutcome({
        ...base,
        copy: createStage("succeeded", { required: true, attempted: true, evidence: "write_response" }),
        sourceTag,
        targetTag,
        reconciliation: createStage("ambiguous", { errorCode: reconciliation.errorCode }),
        overall: "ambiguous",
        errorCode: reconciliation.errorCode,
        remoteState: "changed",
      });
    }

    sourceTag = reconcileTagStage(sourceTag, reconciliation.sourceMissing);
    targetTag = reconcileTagStage(targetTag, reconciliation.targetMissing);
    executionState.sourceTag = sourceTag;
    executionState.targetTag = targetTag;
    const hasAmbiguousTag = [sourceTag, targetTag].some(stage => stage.status === "ambiguous");
    const hasFailedTag = [sourceTag, targetTag].some(stage => stage.status === "failed");
    const overall = hasAmbiguousTag ? "ambiguous" : hasFailedTag ? "partial" : "succeeded";
    return createOutcome({
      ...base,
      copy: createStage("succeeded", { required: true, attempted: true, evidence: "write_response" }),
      sourceTag,
      targetTag,
      reconciliation: createStage("succeeded", { evidence: "fresh_read" }),
      overall,
      errorCode: overall === "succeeded" ? null : "tagging_incomplete",
      remoteState: "changed",
    });
  }

  async _ambiguousCopyOutcome(preflight, tagPlan, account, apiKey, base) {
    let reconciliation = createStage("ambiguous", { errorCode: "copy_outcome_unknown" });
    let remoteState = "possibly_changed";
    if (this._isAccountCurrent(account)) {
      const targetRead = await this._findTargetPackages(
        preflight.source,
        preflight.target,
        apiKey,
        null,
        account,
        { stopOnPresence: false }
      );
      if (targetRead.ok && targetRead.complete && targetRead.packages.length === 1) {
        reconciliation = createStage("succeeded", { evidence: "target_state_only" });
        remoteState = "present";
      }
    }
    return createOutcome({
      ...base,
      copy: createStage("ambiguous", {
        required: true,
        attempted: true,
        evidence: "write_dispatched",
        errorCode: "copy_outcome_unknown",
      }),
      sourceTag: createStage(tagPlan.source.length ? "not_attempted" : "not_required", {
        required: tagPlan.source.length > 0,
      }),
      targetTag: createStage(tagPlan.target.length ? "not_attempted" : "not_required", {
        required: tagPlan.target.length > 0,
      }),
      reconciliation,
      overall: "ambiguous",
      errorCode: "copy_outcome_unknown",
      remoteState,
    });
  }

  async _applySourceTags(source, requiredTags, account, apiKey, operation) {
    if (!this._isCurrent(operation, account)) return createStage("not_attempted", { required: true });
    const fresh = await this._readSource(
      { workspace: source.workspace, repository: source.repository, packageIdentifier: source.packageIdentifier },
      apiKey,
      null,
      account
    );
    if (!fresh.ok || !sameSource(source, fresh.source)) {
      return createStage("failed", { required: true, errorCode: "source_tag_state_unverified" });
    }
    const missing = missingTags(fresh.source.tags, requiredTags);
    if (missing.length === 0) {
      return createStage("not_required", { required: true, evidence: "fresh_read" });
    }
    if (!this._isCurrent(operation, account)) return createStage("not_attempted", { required: true });
    return this._postTags(
      source,
      source.packageIdentifier,
      missing,
      account,
      apiKey,
      "source",
      value => normalizeFreshSource(value, {
        workspace: source.workspace,
        repository: source.repository,
        packageIdentifier: source.packageIdentifier,
      })
    );
  }

  async _applyTargetTags(source, target, targetIdentifier, requiredTags, account, apiKey, operation) {
    if (!this._isCurrent(operation, account)) return createStage("not_attempted", { required: true });
    const fresh = await this._findTargetPackages(
      source,
      target,
      apiKey,
      null,
      account,
      { stopOnPresence: false }
    );
    if (
      !fresh.ok
      || !fresh.complete
      || fresh.packages.length !== 1
      || fresh.packages[0].packageIdentifier !== targetIdentifier
    ) {
      return createStage("failed", { required: true, errorCode: "target_tag_state_unverified" });
    }
    const missing = missingTags(fresh.packages[0].tags, requiredTags);
    if (missing.length === 0) {
      return createStage("not_required", { required: true, evidence: "fresh_read" });
    }
    if (!this._isCurrent(operation, account)) return createStage("not_attempted", { required: true });
    return this._postTags(
      target,
      targetIdentifier,
      missing,
      account,
      apiKey,
      "target",
      value => {
        const normalized = normalizeTargetPackage(value, source, target);
        if (normalized.packageIdentifier !== targetIdentifier) {
          throw new PromotionContractError("target_package_identity_mismatch");
        }
        return normalized;
      }
    );
  }

  async _postTags(scope, identifier, tags, account, apiKey, side, normalizeResponse) {
    if (!this._isAccountCurrent(account)) return createStage("not_attempted", { required: true });
    const endpoint = apiEndpoint(["packages", scope.workspace, scope.repository, identifier, "tag"]);
    let result;
    try {
      result = await this.api.post(
        endpoint,
        { action: "add", tags },
        { apiKey, responseType: "object", validate: isRecord, retry: "never" }
      );
    } catch {
      result = null;
    }
    if (!result || !result.ok) {
      if (!result || !isDefiniteWriteFailure(result.error)) {
        return createStage("ambiguous", {
          required: true,
          attempted: true,
          evidence: "write_dispatched",
          errorCode: `${side}_tag_outcome_unknown`,
        });
      }
      return createStage("failed", {
        required: true,
        attempted: true,
        evidence: "write_response",
        errorCode: `${side}_tag_failed`,
      });
    }
    try {
      const normalized = normalizeResponse(result.data);
      if (missingTags(normalized.tags, tags).length > 0) {
        return createStage("ambiguous", {
          required: true,
          attempted: true,
          evidence: "malformed_write_response",
          errorCode: `${side}_tag_outcome_unknown`,
        });
      }
    } catch {
      return createStage("ambiguous", {
        required: true,
        attempted: true,
        evidence: "malformed_write_response",
        errorCode: `${side}_tag_outcome_unknown`,
      });
    }
    return createStage("succeeded", {
      required: true,
      attempted: true,
      evidence: "write_response",
    });
  }

  async _reconcileFinalState(source, target, targetIdentifier, tagPlan, account, apiKey) {
    if (!this._isAccountCurrent(account)) return { ok: false, errorCode: "account_changed" };
    const [sourceRead, targetRead] = await Promise.all([
      this._readSource(
        { workspace: source.workspace, repository: source.repository, packageIdentifier: source.packageIdentifier },
        apiKey,
        null,
        account
      ),
      this._findTargetPackages(source, target, apiKey, null, account, { stopOnPresence: false }),
    ]);
    if (
      !this._isAccountCurrent(account)
      || !sourceRead.ok
      || !sameSource(source, sourceRead.source)
      || !targetRead.ok
      || !targetRead.complete
      || targetRead.packages.length !== 1
      || targetRead.packages[0].packageIdentifier !== targetIdentifier
    ) {
      return { ok: false, errorCode: "reconciliation_incomplete" };
    }
    return deepFreeze({
      ok: true,
      sourceMissing: missingTags(sourceRead.source.tags, tagPlan.source),
      targetMissing: missingTags(targetRead.packages[0].tags, tagPlan.target),
    });
  }

  async _readSource(locator, apiKey, cancellationToken, account) {
    if (!this._isAccountCurrent(account)) return { ok: false, errorCode: "account_changed" };
    const endpoint = apiEndpoint([
      "packages",
      locator.workspace,
      locator.repository,
      locator.packageIdentifier,
    ]);
    let result;
    try {
      result = await this.api.get(endpoint, {
        apiKey,
        responseType: "object",
        validate: isRecord,
        retry: "never",
        cancellationToken,
      });
    } catch {
      return { ok: false, errorCode: "source_unverified" };
    }
    if (!result.ok) return { ok: false, errorCode: readErrorCode(result.error, "source") };
    try {
      return { ok: true, source: normalizeFreshSource(result.data, locator) };
    } catch (error) {
      return { ok: false, errorCode: errorCode(error, "malformed_source_package") };
    }
  }

  async _readTargetRepository(target, apiKey, cancellationToken, account) {
    if (!this._isAccountCurrent(account)) return { ok: false, errorCode: "account_changed" };
    const endpoint = apiEndpoint(["repos", target.workspace, target.repository]);
    let result;
    try {
      result = await this.api.get(endpoint, {
        apiKey,
        responseType: "object",
        validate: isRecord,
        retry: "never",
        cancellationToken,
      });
    } catch {
      return { ok: false, errorCode: "target_unverified" };
    }
    if (!result.ok) return { ok: false, errorCode: readErrorCode(result.error, "target") };
    try {
      return {
        ok: true,
        target: normalizeTargetRepository(result.data, target.workspace, target.repository),
      };
    } catch (error) {
      return { ok: false, errorCode: errorCode(error, "malformed_target_repository") };
    }
  }

  async _findTargetPackages(source, target, apiKey, cancellationToken, account, options) {
    let endpoint;
    let query;
    try {
      endpoint = apiEndpoint(["packages", target.workspace, target.repository]);
      query = buildExactPackageQuery(source.name, source.version, source.format);
    } catch {
      return { ok: false, complete: false, packages: [], errorCode: "invalid_package_query" };
    }
    const packages = [];
    let itemCount = 0;
    for (let page = 1; page <= MAX_EXACT_PACKAGE_PAGES; page += 1) {
      if (!this._isAccountCurrent(account)) {
        return { ok: false, complete: false, packages: [], errorCode: "account_changed" };
      }
      let result;
      try {
        result = await this._paginatedFetch.fetchPage(
          endpoint,
          page,
          EXACT_PACKAGE_PAGE_SIZE,
          query,
          {
            apiKey,
            validate: isRecordArray,
            retry: "never",
            cancellationToken,
          }
        );
      } catch {
        return { ok: false, complete: false, packages: [], errorCode: "target_state_unverified" };
      }
      if (result.error) {
        return {
          ok: false,
          complete: false,
          packages: [],
          errorCode: readErrorCode(result.error, "target_state"),
        };
      }
      itemCount += result.data.length;
      if (itemCount > MAX_EXACT_PACKAGE_ITEMS) {
        return { ok: false, complete: false, packages: [], errorCode: "target_state_unknown" };
      }
      for (const candidate of result.data) {
        if (!packageMatchesExactIdentity(candidate, source)) continue;
        try {
          packages.push(normalizeTargetPackage(candidate, source, target));
        } catch (error) {
          return {
            ok: false,
            complete: false,
            packages: [],
            errorCode: errorCode(error, "malformed_target_package"),
          };
        }
        if (options.stopOnPresence) {
          return { ok: true, complete: true, packages: Object.freeze(packages) };
        }
        if (packages.length > 1) {
          return { ok: true, complete: true, packages: Object.freeze(packages) };
        }
      }
      if (page >= result.pagination.pageTotal) {
        return { ok: true, complete: true, packages: Object.freeze(packages) };
      }
      if (result.pagination.pageTotal > MAX_EXACT_PACKAGE_PAGES) {
        return { ok: false, complete: false, packages: [], errorCode: "target_state_unknown" };
      }
    }
    return { ok: false, complete: false, packages: [], errorCode: "target_state_unknown" };
  }

  async _loadPresenceHints(source, apiKey, account) {
    let endpoint;
    let query;
    try {
      endpoint = apiEndpoint(["packages", source.workspace]);
      query = buildExactPackageQuery(source.name, source.version, source.format);
    } catch {
      return null;
    }
    const repositories = new Set();
    for (let page = 1; page <= MAX_EXACT_PACKAGE_PAGES; page += 1) {
      if (!this._isAccountCurrent(account)) return null;
      let result;
      try {
        result = await this._paginatedFetch.fetchPage(
          endpoint,
          page,
          EXACT_PACKAGE_PAGE_SIZE,
          query,
          { apiKey, validate: isPackageLocationArray, retry: "never" }
        );
      } catch {
        return null;
      }
      if (result.error || result.pagination.pageTotal > MAX_EXACT_PACKAGE_PAGES) return null;
      for (const pkg of result.data) {
        if (packageMatchesExactIdentity(pkg, source)) repositories.add(pkg.repository);
      }
      if (page >= result.pagination.pageTotal) return repositories;
    }
    return null;
  }

  async _loadTargetCandidates(source, pipeline, account, apiKey) {
    if (!this._isAccountCurrent(account)) return { ok: false, errorCode: "account_changed" };
    let result;
    try {
      result = await this._fetchWorkspaceRepositories(this.context, source.workspace, {
        account,
        apiKey,
        cloudsmithAPI: this.api,
        connectionManager: this._connectionManager,
        withProgress: this._withProgress,
        retry: "safe-read",
      });
    } catch {
      return { ok: false, errorCode: "repository_list_incomplete" };
    }
    if (result.stale) return { ok: false, errorCode: "account_changed" };
    if (result.error || result.warning || result.partial) {
      return { ok: false, errorCode: "repository_list_incomplete" };
    }
    const repositories = new Map();
    try {
      for (const record of result.repositories) {
        const target = normalizeTargetRepository(record, source.workspace, record.slug);
        if (repositories.has(target.repository)) {
          return { ok: false, errorCode: "repository_list_incomplete" };
        }
        repositories.set(target.repository, target);
      }
    } catch (error) {
      return { ok: false, errorCode: errorCode(error, "repository_list_incomplete") };
    }

    if (pipeline.length > 0) {
      if (pipeline.some(repository => !repositories.has(repository))) {
        return { ok: false, errorCode: "pipeline_repository_missing" };
      }
      const sourceIndex = pipeline.indexOf(source.repository);
      if (sourceIndex < 0) return { ok: false, errorCode: "source_not_in_pipeline" };
      return {
        ok: true,
        targets: Object.freeze(pipeline.slice(sourceIndex + 1).map(repository => repositories.get(repository))),
      };
    }
    return {
      ok: true,
      targets: Object.freeze([...repositories.values()].filter(target => (
        target.repository !== source.repository
      ))),
    };
  }

  async _selectTarget(source, targets, presenceHints, account) {
    const recent = this._recentFor(account, source);
    const ordered = [
      ...recent.map(repository => targets.find(target => target.repository === repository)).filter(Boolean),
      ...targets.filter(target => !recent.includes(target.repository)),
    ];
    const items = ordered.map(target => {
      const present = presenceHints?.has(target.repository) === true;
      return {
        label: target.name,
        description: `${target.workspace}/${target.repository}`,
        detail: present
          ? `Already contains ${source.name} ${source.version} — unavailable`
          : "Package presence will be verified before promotion",
        _target: target,
      };
    });
    const picked = await this._window.showQuickPick(items, {
      placeHolder: `Select a target repository for ${source.name} ${source.version}`,
      matchOnDescription: true,
      matchOnDetail: true,
    });
    return picked?._target || null;
  }

  async _confirm(preflight, tagPlan) {
    const writes = [
      "copy the package",
      ...(tagPlan.source.length ? [`add ${tagPlan.source.length} source tag(s)`] : []),
      ...(tagPlan.target.length ? [`add ${tagPlan.target.length} target tag(s)`] : []),
    ].join("; ");
    const detail = [
      `Package: ${preflight.source.name}`,
      `Version: ${preflight.source.version}`,
      `Source: ${preflight.source.workspace}/${preflight.source.repository}`,
      `Target: ${preflight.target.workspace}/${preflight.target.repository}`,
      "Target package: Not present",
      "Preflight: Package, copyability, target repository, and target absence were verified",
      "Target write access: Cloudsmith verifies this when promotion begins",
      `Writes: ${writes}`,
      "The copy can complete even if a later tag write is denied.",
    ].join("\n");
    return this._window.showWarningMessage(
      `Promote “${preflight.source.name}” ${preflight.source.version} to ${preflight.target.repository}?`,
      { modal: true, detail },
      "Promote package"
    );
  }

  _acquireOperation(locator) {
    if (this._disposed) return null;
    let workspace = this._activeOperations.get(locator.workspace);
    if (!workspace) {
      workspace = new Map();
      this._activeOperations.set(locator.workspace, workspace);
    }
    let repository = workspace.get(locator.repository);
    if (!repository) {
      repository = new Map();
      workspace.set(locator.repository, repository);
    }
    if (repository.has(locator.packageIdentifier)) return null;
    const operation = Object.freeze({ locator, id: ++this._operationSequence });
    repository.set(locator.packageIdentifier, operation);
    return operation;
  }

  _releaseOperation(operation) {
    const workspace = this._activeOperations.get(operation.locator.workspace);
    const repository = workspace?.get(operation.locator.repository);
    if (repository?.get(operation.locator.packageIdentifier) !== operation) return;
    repository.delete(operation.locator.packageIdentifier);
    if (repository.size === 0) workspace.delete(operation.locator.repository);
    if (workspace.size === 0) this._activeOperations.delete(operation.locator.workspace);
  }

  _isAccountCurrent(account) {
    return !this._disposed && isAccountCurrent(this._connectionManager, account);
  }

  _isCurrent(operation, account) {
    if (!this._isAccountCurrent(account)) return false;
    const workspace = this._activeOperations.get(operation.locator.workspace);
    const repository = workspace?.get(operation.locator.repository);
    return repository?.get(operation.locator.packageIdentifier) === operation;
  }

  _recentFor(account, source) {
    return this._recentTargets
      .filter(entry => (
        entry.activationId === account.activationId
        && entry.accountEpoch === account.accountEpoch
        && entry.workspace === source.workspace
        && entry.sourceRepository === source.repository
        && entry.packageIdentifier === source.packageIdentifier
      ))
      .map(entry => entry.targetRepository)
      .slice(0, 5);
  }

  _recordRecent(account, outcome) {
    this._recentTargets = [
      {
        activationId: account.activationId,
        accountEpoch: account.accountEpoch,
        workspace: outcome.source.workspace,
        sourceRepository: outcome.source.repository,
        packageIdentifier: outcome.source.packageIdentifier,
        targetRepository: outcome.target.repository,
      },
      ...this._recentTargets.filter(entry => !(
        entry.activationId === account.activationId
        && entry.accountEpoch === account.accountEpoch
        && entry.workspace === outcome.source.workspace
        && entry.sourceRepository === outcome.source.repository
        && entry.packageIdentifier === outcome.source.packageIdentifier
        && entry.targetRepository === outcome.target.repository
      )),
    ].slice(0, MAX_RECENT_TARGETS);
  }

  async _publish(outcome, operation, account, options) {
    if (!this._isCurrent(operation, account)) {
      return this._suppressStalePublication(outcome);
    }
    if (outcome.overall === "succeeded") this._recordRecent(account, outcome);
    let refreshFailed = false;
    if (["changed", "possibly_changed", "present"].includes(outcome.remoteState)) {
      try {
        await Promise.resolve(options.refresh?.());
      } catch {
        refreshFailed = true;
      }
      if (!this._isCurrent(operation, account)) {
        return this._suppressStalePublication(outcome);
      }
      if (refreshFailed) {
        try {
          await this._window.showWarningMessage(
            "Promotion finished, but the package view could not be refreshed. Refresh it manually."
          );
        } catch {
          // Notification failures must not change the remote outcome.
        }
      }
      if (!this._isCurrent(operation, account)) {
        return this._suppressStalePublication(outcome);
      }
    }
    if (!this._isCurrent(operation, account)) return this._suppressStalePublication(outcome);
    await this._showOutcome(outcome);
    return outcome;
  }

  async _suppressStalePublication(outcome) {
    if (!this._disposed) {
      try {
        await this._window.showWarningMessage(
          "The active Cloudsmith account changed. Promotion results were not applied to the current view."
        );
      } catch {
        // Notification failures must not change the remote outcome.
      }
    }
    return outcome;
  }

  async _publishFailure(outcome) {
    await this._showFailure(outcome);
    return outcome;
  }

  async _publishStaleOrFailure(operation, account, code) {
    const outcome = failureOutcome(code);
    if (account && !this._isCurrent(operation, account)) return outcome;
    await this._showFailure(outcome);
    return outcome;
  }

  _staleOutcome() {
    return createOutcome({ overall: "failed", errorCode: "account_changed", remoteState: "unchanged" });
  }

  async _showOutcome(outcome) {
    try {
      if (outcome.overall === "cancelled") return;
      if (outcome.overall === "succeeded") {
        await this._window.showInformationMessage(
          `Promoted “${outcome.source.name}” ${outcome.source.version} from ${outcome.source.workspace}/${outcome.source.repository} to ${outcome.target.workspace}/${outcome.target.repository}. All required tags were verified.`
        );
        return;
      }
      if (outcome.overall === "partial") {
        await this._window.showWarningMessage(
          "The package was copied, but promotion tagging is incomplete.",
          {
            modal: true,
            detail: `${stageSummary(outcome)}\n\nAdd the missing configured tags directly in Cloudsmith. Do not repeat the copy.`,
          }
        );
        return;
      }
      if (outcome.overall === "ambiguous") {
        await this._window.showWarningMessage(
          "Promotion completion could not be confirmed.",
          {
            modal: true,
            detail: `${stageSummary(outcome)}\n\nInspect the target repository before retrying. Repeating the copy may create a duplicate.`,
          }
        );
        return;
      }
      await this._showFailure(outcome);
    } catch {
      // Notification failures must not change the remote outcome.
    }
  }

  async _showFailure(outcome) {
    try {
      const message = failureMessage(outcome.errorCode);
      if ([
        "malformed_source_locator",
        "conflicting_source_workspace",
        "conflicting_source_repository",
        "conflicting_source_identifier",
        "malformed_copyability",
        "malformed_source_package",
        "missing_package_fingerprint",
        "source_identity_changed",
        "package_not_copyable",
        "target_package_exists",
        "preflight_changed",
        "malformed_pipeline",
        "malformed_tag_configuration",
      ].includes(outcome.errorCode)) {
        await this._window.showWarningMessage(message);
        return;
      }
      await this._window.showErrorMessage(message);
    } catch {
      // Notification failures must not change the remote outcome.
    }
  }
}

function preflightFailure(errorCodeValue, source = null) {
  return deepFreeze({ ok: false, preflight: null, source, errorCode: errorCodeValue });
}

function reportProgress(progress, message) {
  try {
    progress?.report({ message });
  } catch {
    // Progress rendering is advisory and must not change remote-write semantics.
  }
}

function interruptedExecutionOutcome(preflight, tagPlan, executionState) {
  const base = {
    source: preflight.source,
    target: preflight.target,
    preflight: createStage("succeeded", { evidence: "fresh_read" }),
    confirmation: createStage("succeeded", { evidence: "user_confirmation" }),
  };
  if (!executionState.writeIssued) {
    return createOutcome({
      ...base,
      copy: createStage("not_attempted", { required: true }),
      sourceTag: createStage(tagPlan.source.length ? "not_attempted" : "not_required", {
        required: tagPlan.source.length > 0,
      }),
      targetTag: createStage(tagPlan.target.length ? "not_attempted" : "not_required", {
        required: tagPlan.target.length > 0,
      }),
      overall: "failed",
      errorCode: "write_workflow_interrupted",
      remoteState: "unchanged",
    });
  }
  const copy = executionState.copy || createStage("ambiguous", {
    required: true,
    attempted: true,
    evidence: "write_dispatched",
    errorCode: "write_workflow_interrupted",
  });
  return createOutcome({
    ...base,
    copy,
    sourceTag: executionState.sourceTag || createStage(
      tagPlan.source.length ? "not_attempted" : "not_required",
      { required: tagPlan.source.length > 0 }
    ),
    targetTag: executionState.targetTag || createStage(
      tagPlan.target.length ? "not_attempted" : "not_required",
      { required: tagPlan.target.length > 0 }
    ),
    reconciliation: executionState.reconciliation
      || createStage("ambiguous", { errorCode: "write_workflow_interrupted" }),
    overall: "ambiguous",
    errorCode: "write_workflow_interrupted",
    remoteState: copy.status === "succeeded" ? "changed" : "possibly_changed",
  });
}

function failureOutcome(code, options = {}) {
  return createOutcome({
    source: options.source || null,
    target: options.target || null,
    preflight: options.preflight || createStage("failed", { errorCode: code }),
    confirmation: options.confirmation,
    overall: "failed",
    errorCode: code,
    remoteState: "unchanged",
  });
}

function errorCode(error, fallback) {
  return error instanceof PromotionContractError && error.code ? error.code : fallback;
}

function readErrorCode(error, subject) {
  if (error?.kind === "cancelled") return "cancelled";
  if (error?.kind === "not_found" || error?.status === 404) return `${subject}_missing`;
  if (error?.kind === "forbidden" || error?.status === 403) return `${subject}_access_denied`;
  if (error?.kind === "invalid_response") return `${subject}_malformed`;
  return `${subject}_unverified`;
}

function isDefiniteWriteFailure(error) {
  if (!error || error.outcomeUnknown !== false) return false;
  if (error.kind === "invalid_request" && error.status == null) return true;
  return Number.isInteger(error.status) && error.status >= 400 && error.status < 500;
}

function sameSource(expected, actual) {
  return Boolean(actual)
    && expected.workspace === actual.workspace
    && expected.repository === actual.repository
    && expected.packageIdentifier === actual.packageIdentifier
    && expected.name === actual.name
    && expected.version === actual.version
    && expected.format === actual.format
    && expected.copyable === actual.copyable
    && expected.fingerprint.checksum === actual.fingerprint.checksum
    && expected.fingerprint.versionDigest === actual.fingerprint.versionDigest;
}

function reconcileTagStage(stage, missing) {
  if (stage.status === "failed" && stage.attempted) return stage;
  if (missing.length === 0) {
    if (stage.status === "ambiguous" || stage.status === "failed") {
      return createStage("succeeded", {
        required: stage.required,
        attempted: stage.attempted,
        evidence: "fresh_read",
      });
    }
    return stage;
  }
  if (stage.status === "ambiguous") return stage;
  return createStage("failed", {
    required: stage.required,
    attempted: stage.attempted,
    evidence: "fresh_read",
    errorCode: "tag_not_present",
  });
}

function stageSummary(outcome) {
  return [
    `Copy: ${outcome.copy.status}`,
    `Source tags: ${outcome.sourceTag.status}`,
    `Target tags: ${outcome.targetTag.status}`,
    `Final verification: ${outcome.reconciliation.status}`,
  ].join("\n");
}

function failureMessage(code) {
  const messages = {
    account_changed: "The active Cloudsmith account changed. No further promotion changes were attempted.",
    authentication_unavailable: "Cloudsmith authentication is not ready. Connect an account and try again.",
    cancelled: "Promotion was cancelled before any changes were made.",
    conflicting_source_identifier: "Package identifiers disagree. Refresh the package list and try again.",
    conflicting_source_repository: "Package repository details disagree. Refresh the package list and try again.",
    conflicting_source_workspace: "Package workspace details disagree. Refresh the package list and try again.",
    copy_failed: "Cloudsmith did not copy the package. No tags were attempted.",
    malformed_copyability: "Cloudsmith returned incomplete copyability information. No changes were made.",
    malformed_pipeline: "The promotion pipeline setting is invalid. Fix it before promoting a package.",
    malformed_source_locator: "Package details are incomplete. Refresh the package list and try again.",
    malformed_source_package: "Cloudsmith returned incomplete package details. No changes were made.",
    malformed_tag_configuration: "The promotion tag setting is invalid. Fix it before promoting a package.",
    missing_package_fingerprint: "The package cannot be verified strongly enough for a safe promotion. No changes were made.",
    no_target_repositories: "No valid target repositories are available for this package.",
    package_not_copyable: "This package is not copyable. No changes were made.",
    pipeline_repository_missing: "A configured promotion repository is unavailable. Check the pipeline and repository access.",
    preflight_changed: "Package or target state changed before promotion. No changes were made. Select the target again.",
    repository_list_incomplete: "The complete repository list could not be verified. No changes were made.",
    source_access_denied: "The source package could not be verified. Check repository access and try again.",
    source_identity_changed: "Package details changed. Refresh the package list and try again. No changes were made.",
    source_missing: "The source package is no longer available. Refresh the package list and try again.",
    source_not_in_pipeline: "The source repository is not a valid stage in the configured promotion pipeline.",
    target_access_denied: "The target repository could not be verified. Check repository access and try again.",
    target_missing: "The target repository is unavailable. Check repository access and try again.",
    target_package_exists: "This package already exists in the selected target repository. No changes were made.",
    target_state_unknown: "Target package state could not be verified. No changes were made.",
    unexpected_error: "Promotion stopped because of an unexpected error. No further changes were attempted.",
  };
  return messages[code] || "Promotion requirements could not be verified. No changes were made.";
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isRecordArray(value) {
  return Array.isArray(value) && value.every(isRecord);
}

function isPackageLocationArray(value) {
  return Array.isArray(value) && value.every(pkg => (
    isRecord(pkg)
    && typeof pkg.name === "string"
    && (typeof pkg.version === "string" || typeof pkg.version === "number")
    && typeof pkg.format === "string"
    && typeof pkg.repository === "string"
  ));
}

function isPromotionStatusArray(value) {
  return isPackageLocationArray(value);
}

module.exports = {
  MAX_EXACT_PACKAGE_ITEMS,
  MAX_EXACT_PACKAGE_PAGES,
  PromotionProvider,
};

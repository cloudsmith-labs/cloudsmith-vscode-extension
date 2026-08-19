// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const assert = require("assert");
const {
  captureCommandAccount,
  pickRecentPackage,
  resolveCommandRepository,
  resolveCommandWorkspace,
} = require("../commands/support");
const { assertExactPackage, createExactPackage } = require("../domain/package");

suite("Command recovery", () => {
  test("workspace recovery distinguishes valid, missing, stale, singleton, and partial defaults", async () => {
    const valid = recoveryHarness({
      defaultWorkspace: "workspace-a",
      workspaces: collection([
        workspace("workspace-a", "Workspace A"),
        workspace("workspace-b", "Workspace B"),
      ]),
    });
    assert.deepStrictEqual(
      await resolveCommandWorkspace(valid.deps, valid.account),
      frozenWorkspace("workspace-a", "Workspace A", "default")
    );
    assert.strictEqual(valid.quickPicks.length, 0);

    const missing = recoveryHarness({
      workspaces: collection([
        workspace("workspace-a", "Workspace A"),
        workspace("workspace-b", "Workspace B"),
      ]),
      select: items => items.find(item => item.workspace?.slug === "workspace-b"),
    });
    assert.deepStrictEqual(
      await resolveCommandWorkspace(missing.deps, missing.account),
      frozenWorkspace("workspace-b", "Workspace B", "picker")
    );

    const stale = recoveryHarness({
      defaultWorkspace: "synthetic-invalid-workspace",
      workspaces: collection([
        workspace("workspace-a", "Workspace A"),
        workspace("workspace-b", "Workspace B"),
      ]),
      select: items => items.find(item => item.workspace?.slug === "workspace-a"),
    });
    assert.deepStrictEqual(
      await resolveCommandWorkspace(stale.deps, stale.account),
      frozenWorkspace("workspace-a", "Workspace A", "picker")
    );
    assert.strictEqual(stale.configurationUpdates, 0);

    const singleton = recoveryHarness({
      workspaces: collection([workspace("workspace-only", "Only Workspace")]),
      select: () => { throw new Error("authoritative singleton must not prompt"); },
    });
    assert.deepStrictEqual(
      await resolveCommandWorkspace(singleton.deps, singleton.account),
      frozenWorkspace("workspace-only", "Only Workspace", "single")
    );
    assert.strictEqual(singleton.quickPicks.length, 0);
    assert.strictEqual(singleton.configurationUpdates, 0);

    const partial = recoveryHarness({
      defaultWorkspace: "synthetic-default-not-in-partial-result",
      workspaces: collection([
        workspace("workspace-visible", "Visible\u202e\nWorkspace"),
      ], false),
      select: items => items.find(item => item.workspace),
    });
    const partialResult = await resolveCommandWorkspace(partial.deps, partial.account, {
      maxRetries: 0,
    });
    assert.deepStrictEqual(
      partialResult,
      frozenWorkspace("workspace-visible", "Visible Workspace", "picker")
    );
    assert.strictEqual(partial.quickPicks.length, 1);
    assert.strictEqual(partial.quickPicks[0][0].kind, 1);
    assert.ok(partial.warnings.some(message => message.includes("incomplete")));

    const accountChange = recoveryHarness({
      workspaces: collection([
        workspace("workspace-a", "Workspace A"),
        workspace("workspace-b", "Workspace B"),
      ]),
      select(items, harness) {
        harness.current = false;
        return items.find(item => item.workspace?.slug === "workspace-a");
      },
    });
    assert.strictEqual(
      await resolveCommandWorkspace(accountChange.deps, accountChange.account),
      null
    );

    const unsafeSlug = recoveryHarness({
      workspaces: collection([
        workspace("workspace\u202e-hostile", "Hostile"),
        workspace("workspace-safe", "Safe Workspace"),
      ]),
      select: items => items.find(item => item.workspace?.slug === "workspace-safe"),
    });
    assert.deepStrictEqual(
      await resolveCommandWorkspace(unsafeSlug.deps, unsafeSlug.account, { maxRetries: 0 }),
      frozenWorkspace("workspace-safe", "Safe Workspace", "picker")
    );
    assert.strictEqual(unsafeSlug.quickPicks[0][0].kind, 1);
    assert.strictEqual(
      JSON.stringify(unsafeSlug.quickPicks).includes("workspace\u202e-hostile"),
      false
    );
  });

  test("repository recovery is scoped, truthful for partial collections, and silent on cancellation", async () => {
    const missingNode = recoveryHarness({
      defaultWorkspace: "workspace-a",
      workspaces: collection([workspace("workspace-a", "Workspace A")]),
      repositories: collection([repository("repo-only", "Only Repo")]),
      select: () => { throw new Error("authoritative singleton must not prompt"); },
    });
    assert.deepStrictEqual(
      await resolveCommandRepository(missingNode.deps, missingNode.account),
      frozenRepository("workspace-a", "repo-only", "Only Repo", "single")
    );
    assert.deepStrictEqual(missingNode.repositoryRequests, ["workspace-a"]);

    const partial = recoveryHarness({
      defaultWorkspace: "workspace-a",
      workspaces: collection([workspace("workspace-a", "Workspace A")]),
      repositories: collection([repository("repo-visible", "Visible\u2066 Repo")], false),
      select: items => items.find(item => item.repository),
    });
    assert.deepStrictEqual(
      await resolveCommandRepository(partial.deps, partial.account, { maxRetries: 0 }),
      frozenRepository("workspace-a", "repo-visible", "Visible Repo", "picker")
    );
    assert.strictEqual(partial.quickPicks[0][0].kind, 1);
    assert.deepStrictEqual(partial.information, []);

    const cancelled = recoveryHarness({
      defaultWorkspace: "workspace-a",
      workspaces: collection([workspace("workspace-a", "Workspace A")]),
      repositories: collection([
        repository("repo-a", "Repo A"),
        repository("repo-b", "Repo B"),
      ]),
      select: () => null,
    });
    assert.strictEqual(
      await resolveCommandRepository(cancelled.deps, cancelled.account),
      null
    );
    assert.deepStrictEqual(cancelled.information, []);
    assert.deepStrictEqual(cancelled.errors, []);
    assert.deepStrictEqual(cancelled.warnings, []);
  });

  test("explicit repository recovery validates identity before service work and can choose a verified partial alternative", async () => {
    const explicit = recoveryHarness({
      workspaces: collection([workspace("workspace-a", "Workspace A")]),
      repositories: collection([
        repository("repo-a", "Repo A"),
        repository("repo-b", "Repo B"),
      ]),
      packageAdapters: {
        fromRepositoryNode: () => ({
          workspace: "workspace-a",
          repository: "repo-b",
          name: "Repo B",
        }),
      },
      select: () => { throw new Error("an explicit verified repository must not prompt"); },
    });
    assert.deepStrictEqual(await resolveCommandRepository(explicit.deps, explicit.account, {
      explicitItem: {},
      currentSelection: () => true,
    }), frozenRepository("workspace-a", "repo-b", "Repo B", "explicit"));
    assert.strictEqual(explicit.quickPicks.length, 0);

    const invalid = recoveryHarness({
      packageAdapters: {
        fromRepositoryNode() { throw new TypeError("invalid"); },
      },
    });
    assert.strictEqual(await resolveCommandRepository(invalid.deps, invalid.account, {
      explicitItem: {},
      currentSelection: () => true,
    }), null);
    assert.strictEqual(invalid.workspaceRequests, 0);
    assert.deepStrictEqual(invalid.repositoryRequests, []);
    assert.deepStrictEqual(invalid.warnings, ["Could not determine repository details."]);

    const partial = recoveryHarness({
      workspaces: collection([workspace("workspace-a", "Workspace A")]),
      repositories: collection([repository("repo-b", "Repo B")], false),
      packageAdapters: {
        fromRepositoryNode: () => ({
          workspace: "workspace-a",
          repository: "repo-missing",
          name: "Missing Repo",
        }),
      },
      select: items => items.find(item => item.repository?.slug === "repo-b"),
    });
    assert.deepStrictEqual(await resolveCommandRepository(partial.deps, partial.account, {
      explicitItem: {},
      currentSelection: () => true,
      maxRetries: 0,
    }), frozenRepository("workspace-a", "repo-b", "Repo B", "picker"));
  });

  test("recent-package recovery disambiguates identical names and fails closed on account reset", async () => {
    const first = exactPackage("workspace-a", "repo-a");
    const second = exactPackage("workspace-b", "repo-b");
    const single = recoveryHarness({
      recentPackages: [first],
      select: items => items[0],
    });
    const singleResult = await pickRecentPackage(single.deps, {
      accountScope: single.account,
      currentSelection: () => true,
    });
    assert.strictEqual(singleResult, first);
    assert.strictEqual(assertExactPackage(singleResult), singleResult);
    assert.strictEqual(Object.isFrozen(singleResult), true);

    const picked = recoveryHarness({
      recentPackages: [first, second],
      select: items => items.find(item => item.package === second),
    });
    const result = await pickRecentPackage(picked.deps, {
      accountScope: picked.account,
      currentSelection: () => true,
    });
    assert.strictEqual(result, second);
    assert.strictEqual(Object.isFrozen(result), true);
    assert.deepStrictEqual(
      picked.quickPicks[0].map(item => item.description),
      ["python — workspace-a/repo-a", "python — workspace-b/repo-b"]
    );

    const reset = recoveryHarness({
      recentPackages: [first],
      select(items, harness) {
        harness.current = false;
        return items[0];
      },
    });
    assert.strictEqual(await pickRecentPackage(reset.deps, {
      accountScope: reset.account,
      currentSelection: () => true,
    }), null);

    const predicate = recoveryHarness({
      recentPackages: [
        Object.freeze({ ...first, copyable: false }),
        Object.freeze({ ...second, copyable: true }),
      ],
      select: items => items[0],
    });
    assert.strictEqual((await pickRecentPackage(predicate.deps, {
      accountScope: predicate.account,
      currentSelection: () => true,
      predicate: pkg => pkg.copyable === true,
    })).repository, "repo-b");
    assert.strictEqual(predicate.quickPicks[0].length, 1);

    const completed = createExactPackage({ ...first, packageIdentifier: "completed" });
    const quarantined = createExactPackage({
      ...second,
      packageIdentifier: "quarantined",
      status: "Quarantined",
    });
    const quarantineOnly = recoveryHarness({
      recentPackages: [completed, quarantined],
      select: items => items[0],
    });
    assert.strictEqual(await pickRecentPackage(quarantineOnly.deps, {
      accountScope: quarantineOnly.account,
      currentSelection: () => true,
      predicate: pkg => pkg.status === "Quarantined",
    }), quarantined);
    assert.strictEqual(quarantineOnly.quickPicks[0].length, 1);

    const hostileDisplay = Object.freeze({
      ...first,
      name: "safe\u202e\nname",
      repository: "repo\u2066-a",
    });
    const display = recoveryHarness({
      recentPackages: [hostileDisplay],
      select: items => items[0],
    });
    assert.strictEqual(await pickRecentPackage(display.deps, {
      accountScope: display.account,
      currentSelection: () => true,
    }), hostileDisplay);
    assert.strictEqual(display.quickPicks[0][0].label, "safe name 1.2.3");
    assert.strictEqual(
      display.quickPicks[0][0].description,
      "python — workspace-a/repo -a"
    );
  });
});

function recoveryHarness(options = {}) {
  const harness = {
    current: true,
    configurationUpdates: 0,
    errors: [],
    information: [],
    quickPicks: [],
    repositoryRequests: [],
    warnings: [],
    workspaceRequests: 0,
  };
  const accountIdentity = Object.freeze({ activationId: "activation-a", accountEpoch: 1 });
  const connectionManager = {
    onDidChange: () => ({ dispose() {} }),
  };
  const workspaceAccess = {
    context: {},
    connectionManager,
    workspaceContextProjector: {
      begin: () => ({}),
      async project() {},
    },
    captureAccount: () => (harness.current ? accountIdentity : null),
    isAccountCurrent: () => harness.current,
    createCloudsmithAPI: () => ({}),
    async fetchWorkspaces() {
      harness.workspaceRequests += 1;
      return options.workspaces || collection([workspace("workspace-a", "Workspace A")]);
    },
    normalizedWorkspaceName: value => value.name,
    replaceCollectionItems: (result, items) => ({ ...result, items }),
    async setHasMultipleWorkspacesContext() {},
    async fetchWorkspaceRepositories(_context, workspaceSlug) {
      harness.repositoryRequests.push(workspaceSlug);
      return options.repositories || collection([repository("repo-a", "Repo A")]);
    },
    formatApiError: error => error.message,
    vscode: {
      QuickPickItemKind: { Separator: 1 },
      window: {
        showErrorMessage: message => harness.errors.push(message),
        showInformationMessage: message => harness.information.push(message),
        showWarningMessage: message => harness.warnings.push(message),
      },
    },
  };
  const deps = {
    packageAdapters: options.packageAdapters || {
      fromRepositoryNode: item => item,
    },
    recentPackages: {
      getAll: () => options.recentPackages || [],
    },
    vscode: {
      QuickPickItemKind: { Separator: 1 },
      workspace: {
        getConfiguration: () => ({
          get: key => (key === "defaultWorkspace" ? (options.defaultWorkspace || "") : ""),
          update: () => { harness.configurationUpdates += 1; },
        }),
      },
      window: {
        showErrorMessage: message => harness.errors.push(message),
        showInformationMessage: message => harness.information.push(message),
        showWarningMessage: message => harness.warnings.push(message),
        async showQuickPick(items, promptOptions) {
          harness.quickPicks.push(items);
          const select = options.select || (() => null);
          return select(items, harness, promptOptions);
        },
      },
    },
    workspaceAccess,
  };
  harness.deps = deps;
  harness.account = captureCommandAccount(workspaceAccess);
  return harness;
}

function collection(items, complete = true) {
  return { items, complete, failures: complete ? [] : [{ error: { message: "partial" } }] };
}

function workspace(slug, name) {
  return { slug, name };
}

function repository(slug, name) {
  return { slug, name };
}

function frozenWorkspace(slug, name, source) {
  return Object.freeze({ slug, name, source });
}

function frozenRepository(workspaceSlug, slug, name, source) {
  return Object.freeze({ workspace: workspaceSlug, slug, name, source });
}

function exactPackage(workspaceSlug, repositorySlug) {
  return createExactPackage({
    workspace: workspaceSlug,
    repository: repositorySlug,
    name: "same-name",
    version: "1.2.3",
    format: "python",
    packageIdentifier: `${workspaceSlug}-${repositorySlug}`,
    copyable: true,
    status: "Completed",
  });
}

// Copyright 2026 Cloudsmith Ltd. All rights reserved.

const path = require("path");
const vscode = require("vscode");

const PRODUCT_ID = "Cloudsmith.cloudsmith-vsc";
const VIEW_ID = "repositoryLifecycleFixture";
const WORKSPACE = "fixture-workspace";
const REPOSITORY = "fixture-packages";

async function activate(context) {
  if (vscode.workspace.getConfiguration(VIEW_ID).get("enabled") !== true) return;
  const installed = vscode.extensions.getExtension(PRODUCT_ID);
  if (!installed || !path.isAbsolute(installed.extensionPath)
    || installed.packageJSON.name !== "cloudsmith-vsc"
    || installed.packageJSON.publisher !== "Cloudsmith") {
    throw new Error("Install the verified Cloudsmith candidate before enabling this fixture.");
  }
  const product = relative => require(path.join(installed.extensionPath, relative));
  const { CloudsmithAPI } = product("util/cloudsmithAPI");
  const { PaginatedFetch } = product("util/paginatedFetch");
  const { CloudsmithProvider } = product("views/cloudsmithProvider");
  const { UpstreamChecker } = product("util/upstreamChecker");
  const { VulnerabilityStateService } = product("util/vulnerabilityStateService");
  const { WorkspaceContextProjector } = product("util/workspaceContextProjector");
  const { fetchWorkspaceRepositories } = product("util/workspaceRepositoryFetcher");
  const { captureAccount, isAccountCurrent } = product("util/accountOperation");
  const { registerPackageCommands } = product("commands/packages");
  const { apiEndpoint } = product("util/apiEndpoint");
  const { LicenseClassifier } = product("util/licenseClassifier");
  const packageAdapters = product("domain/packageAdapters");
  const packageDomain = product("domain/package");
  const inspection = product("util/packageInspection");

  let settled = false;
  let disposed = false;
  const requests = new Map();
  const memory = new Map();
  const memoryState = {
    get: (key, fallback) => memory.has(key) ? memory.get(key) : fallback,
    update: async (key, value) => { memory.set(key, value); },
  };
  const productContext = {
    extensionPath: installed.extensionPath,
    globalState: memoryState,
    workspaceState: memoryState,
    subscriptions: [],
  };
  const accountState = Object.freeze({
    activationId: "repository-lifecycle-fixture",
    accountEpoch: 1,
    status: "connected",
    credentialPresent: true,
    sessionConnected: true,
  });
  const connectionManager = {
    getState: () => disposed ? { ...accountState, sessionConnected: false } : accountState,
    onDidChange: () => new vscode.Disposable(() => {}),
  };
  // Public fixture marker, never a real credential. It exists only in these API
  // instances and is consumed by an in-memory transport that cannot use a network.
  const credentialManager = { getApiKey: async () => "public-rendering-fixture" };
  const fixturePackages = () => [
    packageRecord("ready-sibling", true),
    packageRecord("processing-package", settled),
  ];
  async function fixtureFetch(input, options) {
    const url = new URL(input);
    if (disposed || options.signal?.aborted) throw new Error("Fixture request cancelled.");
    if (url.origin !== "https://api.cloudsmith.io" || options.method !== "GET") {
      throw new Error("Fixture transport rejected an unexpected operation.");
    }
    let category;
    let data;
    const prefix = `/v1/packages/${WORKSPACE}/${REPOSITORY}/`;
    if (url.pathname === `/v1/repos/${WORKSPACE}/`) {
      category = "repositories";
      data = [{ slug: REPOSITORY, slug_perm: REPOSITORY, name: "Lifecycle fixture repository" }];
    } else if (url.pathname === prefix) {
      category = "package-pages";
      data = fixturePackages();
    } else if (url.pathname === `${prefix}ready-sibling/`
      || url.pathname === `${prefix}processing-package/`) {
      category = "package-details";
      data = fixturePackages().find(pkg => url.pathname === `${prefix}${pkg.slug_perm}/`);
    } else if (url.pathname === `/v1/vulnerabilities/${WORKSPACE}/${REPOSITORY}/ready-sibling/`
      || url.pathname === `/v1/vulnerabilities/${WORKSPACE}/${REPOSITORY}/processing-package/`) {
      category = "vulnerability-pages";
      data = [];
    } else if (url.pathname.startsWith(`/v1/repos/${WORKSPACE}/${REPOSITORY}/upstream/`)) {
      category = "upstream-pages";
      data = [];
    } else if (url.pathname === `/v1/repos/${WORKSPACE}/${REPOSITORY}/`) {
      category = "repository-metadata";
      data = { slug: REPOSITORY, name: "Lifecycle fixture repository", storage_region: null };
    } else if (url.pathname === `/v1/quota/${WORKSPACE}/`) {
      category = "quota";
      data = {};
    } else {
      return new Response(JSON.stringify({ detail: "No fixture exists for this request." }), {
        status: 404, headers: { "content-type": "application/json" },
      });
    }
    const count = (requests.get(category) || 0) + 1;
    requests.set(category, count);
    if ([...requests.values()].reduce((sum, value) => sum + value, 0) > 200) {
      throw new Error("Fixture request budget exhausted.");
    }
    const headers = { "content-type": "application/json" };
    if (Array.isArray(data)) {
      Object.assign(headers, {
        "x-pagination-page": url.searchParams.get("page") || "1",
        "x-pagination-pagesize": url.searchParams.get("page_size") || "30",
        "x-pagination-pagetotal": "1",
        "x-pagination-count": String(data.length),
      });
    }
    return new Response(JSON.stringify(data), { status: 200, headers });
  }
  const createCloudsmithAPI = () => new CloudsmithAPI(productContext, {
    credentialManager, fetchImpl: fixtureFetch,
  });
  const vulnerabilityStateService = new VulnerabilityStateService(productContext, {
    connectionManager,
    createCloudsmithAPI,
  });
  const upstreamInventory = new UpstreamChecker(productContext, {
    connectionManager, cloudsmithAPI: createCloudsmithAPI(),
  });
  const projector = new WorkspaceContextProjector({
    executeCommand: (command, key, value) => vscode.commands.executeCommand(
      command, `${VIEW_ID}.${key}`, value
    ),
  });
  const provider = new CloudsmithProvider(productContext, {
    connectionManager,
    createCloudsmithAPI,
    createPaginatedFetch: api => new PaginatedFetch(api),
    upstreamInventory,
    vulnerabilityStateService,
    workspaceContextProjector: projector,
    fetchWorkspaceRepositories: (ctx, workspace, options) => fetchWorkspaceRepositories(
      ctx, workspace, { ...options, cloudsmithAPI: createCloudsmithAPI() }
    ),
  });
  const tree = vscode.window.createTreeView(VIEW_ID, { treeDataProvider: provider });
  provider.setTreeView(tree);
  tree.description = "Contract-derived; processing held";
  const output = vscode.window.createOutputChannel("Repository lifecycle fixture inspection");
  const commandRegistrations = registerPackageCommands({
    registerCommand(id, handler) {
      if (id !== "cloudsmith-vsc.inspectPackage") return new vscode.Disposable(() => {});
      return vscode.commands.registerCommand(`${VIEW_ID}.inspect`, item => {
        const selection = item || tree.selection[0];
        return handler(selection);
      });
    },
    vscode,
    context: productContext,
    packageAdapters,
    packageDomain,
    recentPackages: { add() {}, getAll: () => [] },
    cloudsmithProvider: provider,
    inspectOutputChannel: output,
    CloudsmithAPI: class FixtureAPI extends CloudsmithAPI {
      constructor() { super(productContext, { credentialManager, fetchImpl: fixtureFetch }); }
    },
    apiEndpoint,
    LicenseClassifier,
    serializePackageInspection: inspection.serializePackageInspection,
    workspaceAccess: { connectionManager, captureAccount, isAccountCurrent },
    isCurrentPackageSelection: item => provider.ownsPackageSelection(item),
    formatApiError: product("util/errorFormatter").formatApiError,
  });
  context.subscriptions.push(tree, output, commandRegistrations, projector,
    new vscode.Disposable(() => {
      disposed = true;
      try { provider.dispose(); } finally { vulnerabilityStateService.dispose(); }
    }),
    vscode.commands.registerCommand(`${VIEW_ID}.refresh`, () => provider.refresh()),
    vscode.commands.registerCommand(`${VIEW_ID}.settle`, () => {
      settled = true;
      tree.description = "Contract-derived; processing completed";
      provider.refresh();
    }),
    vscode.commands.registerCommand(`${VIEW_ID}.restart`, () => {
      settled = false;
      tree.description = "Contract-derived; processing held";
      provider.refresh();
    }),
    vscode.commands.registerCommand(`${VIEW_ID}.summary`, async () => {
      const document = await vscode.workspace.openTextDocument({
        language: "json",
        content: JSON.stringify({
          fixtureOrigin: "contract-derived",
          productVersion: installed.packageJSON.version,
          productPath: installed.extensionPath,
          processingReleased: settled,
          requestCounts: Object.fromEntries(requests),
        }, null, 2),
      });
      await vscode.window.showTextDocument(document, { preview: true });
    })
  );
}

function packageRecord(name, completed) {
  return {
    namespace: WORKSPACE,
    repository: REPOSITORY,
    slug_perm: name,
    slug: name,
    name,
    version: "1.0.0",
    format: "npm",
    status_str: completed ? "Completed" : "Sync In Progress",
    status_reason: completed ? null : "",
    is_sync_in_progress: !completed,
    is_sync_completed: completed,
    is_sync_failed: false,
    is_copyable: completed,
    security_scan_status: completed
      ? "Scan Detected No Vulnerabilities" : "Security Scanning in Progress",
    num_vulnerabilities: 0,
    has_vulnerabilities: false,
    deny_policy_violated: false,
  };
}

module.exports = { activate };

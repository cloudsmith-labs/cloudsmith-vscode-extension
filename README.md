<img src="media/readme/brand-banner.png" alt="" />

# Cloudsmith for Visual Studio Code

Browse Cloudsmith workspaces, repositories, package groups, and packages without leaving Visual Studio Code. The extension also provides package search, vulnerability and quarantine details, Dependency Health, upstream workflows, install commands, and package promotion.

## Install

Install **Cloudsmith** from the Visual Studio Marketplace or Open VSX Registry. In the Extensions view, search for `Cloudsmith` and choose the extension published by Cloudsmith.

The extension supports Visual Studio Code 1.99 and later.

## Connect to Cloudsmith

Open the Cloudsmith view and select **Set up Cloudsmith authentication**, or run the command from the Command Palette. The extension stores imported or entered credentials in VS Code's secure credential storage and validates them when the extension starts.

Supported authentication methods:

- **API key** — Enter a personal API key in a masked input.
- **Service account API key** — Enter an API key belonging to a service account in the same masked input.
- **Import from Cloudsmith CLI** — Import an API key from the local Cloudsmith CLI configuration. When no credential is stored, the extension may detect CLI credentials after startup and ask before importing them.
- **Sign in with SSO** — By default, open an integrated terminal for `cloudsmith auth`, then import the resulting CLI credential. The optional browser-based SSO flow is experimental and is controlled by `cloudsmith-vsc.experimentalSSOBrowser`.

Use **Clear stored credentials** to disconnect and remove the credential from VS Code's secure storage.

## Browse and inspect packages

The Workspaces view shows accessible workspaces, their repositories, and packages. Set a default workspace to open its repositories directly. Enable package grouping when a repository is easier to browse by package group.

Expanding a package shows its status, version, license when enabled, vulnerability summary, quarantine or policy state, source, and additional details such as format, downloads, tags, upload time, slugs, and workspace. Detail rows can be selected with the keyboard or pointer to copy their values.

**Inspect package** fetches the selected package, validates it against the extension's canonical package contract, and opens a bounded, safe JSON projection. The inspection output intentionally excludes arbitrary API fields, credentials, entitlement tokens, and delivery URLs. Set `cloudsmith-vsc.inspectOutput` to open inspection JSON in a text document instead of the Cloudsmith Output panel.

Package and search-result context menus provide actions such as:

- **Copy install command** and **Show install command**
- **View package in Cloudsmith**
- **Show vulnerabilities** and **Find safe version**
- **Explain quarantine** for quarantined packages
- **Show promotion status** and **Promote package** when the package is eligible

## Search packages

Use **Search packages** for a workspace-wide query. Recent searches can be selected and run again. **Advanced search** supports all repositories or a selected set of repositories, common security and license filters, format filters, and custom Cloudsmith search syntax.

Workspace and repository context menus include scoped search and filter shortcuts. These shortcuts are available only for the selected item; they are not global Command Palette commands. Use **Load more results** or the Load More row when additional pages are available.

## Vulnerabilities and quarantine

Vulnerability state is derived from canonical scan evidence. A package is shown as clean only when the available result authoritatively reports no known vulnerabilities; incomplete or failed data is not presented as clean.

**Show vulnerabilities** opens severity, CVSS, description, affected version, and fix-version details. **Find safe version** searches for eligible alternatives and offers follow-up package actions. Quarantine reasoning is presented separately through **Explain quarantine**, which shows the current reason and policy details when available.

## Dependency Health

Dependency Health discovers supported dependency files in the selected project, reads existing manifests, lockfiles, and recognized generated tree files, and checks eligible registry dependencies against Cloudsmith. It does not run package managers to create or update dependency files.

### Supported dependency inputs

| Family | Manifest or direct input | Lockfile or resolved input | Resolution notes |
|---|---|---|---|
| npm | `package.json` | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | Lockfiles provide resolved direct and transitive dependencies. |
| Python | `requirements.txt`, `pyproject.toml`, `Pipfile` | `uv.lock`, `poetry.lock`, `Pipfile.lock` | Requirements files are direct input; supported lockfiles add resolved dependencies. |
| Maven | `pom.xml` | `dependency-tree.txt`, `target/dependency-tree.txt`, `.mvn/dependency-tree.txt` | A pre-generated Maven dependency tree adds transitive relationships. |
| Gradle | `build.gradle`, `build.gradle.kts` | `gradle.lockfile` | The lockfile adds resolved versions; Gradle command output is not executed or parsed. |
| Go | `go.mod` | `go.mod` | Direct and indirect module declarations are read from the module file. |
| Cargo / Rust | `Cargo.toml` | `Cargo.lock` | The lockfile provides resolved dependencies. |
| Ruby | `Gemfile` | `Gemfile.lock` | The lockfile provides resolved dependencies. |
| Docker | `Dockerfile`, `Dockerfile.*`, `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, `compose.yaml` | — | Base images and Compose images are direct dependencies. |
| NuGet / .NET | `*.csproj` | `packages.lock.json` | Project references are direct; the lockfile provides resolved dependencies. |
| Dart | `pubspec.yaml` | `pubspec.lock` | The lockfile provides resolved dependencies. |
| Composer / PHP | `composer.json` | `composer.lock` | The lockfile provides resolved dependencies. |
| Helm | `Chart.yaml` | `Chart.lock` | Chart dependencies are treated as direct dependencies. |
| Swift | `Package.swift` | `Package.resolved` | The resolved file provides pinned dependencies. |
| Hex / Elixir | `mix.exs` | `mix.lock` | The lockfile provides resolved dependencies. |

Local, path, Git, and otherwise non-registry sources remain visible where useful, but they are not treated as verified Cloudsmith registry coordinates.

### Views, filters, and reports

Use **Cycle dependency view** to move between:

- **Direct** — top-level dependencies
- **Flat** — all resolved dependencies in a single list
- **Tree** — resolved parent and child relationships, with repeated diamond branches collapsed

Use **Sort & filter dependencies** to change ordering or show vulnerable, uncovered, restrictive-license, or policy-violating dependencies. The compliance report summarizes coverage, vulnerabilities, licenses, policy findings, upstream reachability, and unresolved lookup state; it is an engineering summary, not a compliance certification.

### Pull through an upstream

After a successful scan, **Pull dependencies** can fetch eligible uncovered packages through a matching repository upstream. This action can cause packages to be cached in Cloudsmith and always presents a confirmation before network writes. A dependency context menu can pull one eligible package. Coverage is refreshed after the operation.

## Upstreams

Repository context menus provide **View upstreams** for safe upstream inventory and detail, plus **Export as Terraform** for a reviewable repository configuration that omits plaintext upstream secrets. From an uncovered dependency, **Preview upstream resolution** shows the current repository result and relevant upstream configurations before any pull-through action.

## Promotion

Promotion is available for copyable, non-quarantined packages. **Show promotion status** displays package presence across the configured pipeline. **Promote package** selects a target, runs a fresh preflight, asks for confirmation, checks the target again, then copies the package and applies configured tags.

`cloudsmith-vsc.promotionPipeline` can define an ordered repository path. When it is empty, eligible workspace repositories are offered. `cloudsmith-vsc.promotionTags` controls tag templates applied to the source and target.

## Configuration

Open **Cloudsmith: Open Cloudsmith settings** to configure the extension.

### Active settings

| Setting | Default | Constraints | Purpose |
|---|---|---|---|
| `cloudsmith-vsc.inspectOutput` | `false` | Boolean | Open inspection JSON in a text document instead of the Output panel. |
| `cloudsmith-vsc.showMaxPackages` | `30` | Integer, 1–30 | Set the repository-tree page size. Load More can continue to the bounded expansion limit. |
| `cloudsmith-vsc.groupByPackageGroups` | `false` | Boolean | Group repository packages by package group. |
| `cloudsmith-vsc.showPermissibilityIndicators` | `true` | Boolean | Show quarantine and policy state icons; text continues to communicate material state. |
| `cloudsmith-vsc.searchPageSize` | `50` | Integer, 10–100 | Set results per repository for selected-repository Advanced Search. |
| `cloudsmith-vsc.recentSearches` | `10` | Integer, 0–50 | Set the number of searches to remember; `0` disables retention. |
| `cloudsmith-vsc.defaultWorkspace` | `""` | Workspace slug or empty | Open one workspace's repositories directly, or show all accessible workspaces when empty. |
| `cloudsmith-vsc.dependencyScanWorkspace` | `""` | Workspace slug or empty | Prefer a workspace for Dependency Health; empty allows the current default, sole workspace, or a prompt. |
| `cloudsmith-vsc.dependencyScanRepo` | `""` | Repository slug or empty | Limit Dependency Health to a repository in the selected workspace, or search the full workspace when empty. |
| `cloudsmith-vsc.maxDependenciesToScan` | `10000` | Integer, minimum 1 | Bound dependencies displayed and evaluated; pull operations retain the complete resolved input. |
| `cloudsmith-vsc.showLicenseIndicators` | `true` | Boolean | Show package and dependency license information. |
| `cloudsmith-vsc.flagRestrictiveLicenses` | `true` | Boolean | Add an explicit restrictive-license indication to Dependency Health rows. |
| `cloudsmith-vsc.showDockerDigestCommand` | `false` | Boolean | Offer an exact Docker pull-by-digest command when a digest is available. |
| `cloudsmith-vsc.experimentalSSOBrowser` | `false` | Boolean; experimental | Attempt browser-based SSO before falling back to the terminal and CLI import flow. |
| `cloudsmith-vsc.resolveTransitiveDependencies` | `true` | Boolean | Read supported lockfiles for transitive dependencies; when disabled, show direct manifest dependencies. |
| `cloudsmith-vsc.dependencyTreeDefaultView` | `"flat"` | `"direct"`, `"flat"`, `"tree"` | Set the initial Dependency Health view unless a workspace view choice is already stored. |
| `cloudsmith-vsc.showLegacyPolicies` | `false` | Boolean | Show classic deny, license, and vulnerability policy fields alongside current policy management. |
| `cloudsmith-vsc.restrictiveLicenses` | `["AGPL-3.0","GPL-3.0","GPL-2.0","SSPL-1.0"]` | Array of SPDX identifiers | Extend the built-in restrictive-license set. |
| `cloudsmith-vsc.promotionPipeline` | `[]` | Up to 50 unique repository slugs | Define an optional ordered promotion path. |
| `cloudsmith-vsc.promotionTags` | `{"onPromote":["promoted-to-{target}","approved-{date}"],"onReceive":["promoted-from-{source}"]}` | `{target}`, `{source}`, `{date}`; up to 20 templates per stage | Configure source and target tag templates. |
| `cloudsmith-vsc.showEntitlements` | `false` | Boolean; sensitive values | Optionally show active entitlement tokens under repositories. Tokens are sensitive and are copied only after an explicit warning. |

### Deprecated compatibility settings

These settings have no effect and remain contributed only so existing user and workspace configuration stays valid.

| Setting | Default | Status | Purpose |
|---|---|---|---|
| `cloudsmith-vsc.autoScanOnOpen` | `false` | Deprecated; no effect | Retained for configuration compatibility. |
| `cloudsmith-vsc.showRepoMetrics` | `false` | Deprecated; no effect | Retained for configuration compatibility. |

## Command surfaces

Commands appear under the **Cloudsmith** category. Availability also depends on connection, selection, search, and scan state.

### Command Palette workflows

These primary workflows are recoverable from the Command Palette and ask for missing context when appropriate.

| Surface | Command ID | Command | Purpose |
|---|---|---|---|
| Command Palette | `cloudsmith-vsc.configureCredentials` | `Set up Cloudsmith authentication` | Choose and configure an authentication method. |
| Command Palette | `cloudsmith-vsc.searchPackages` | `Search packages` | Search the current or selected workspace. |
| Command Palette | `cloudsmith-vsc.guidedSearch` | `Advanced search` | Build a scoped or filtered package query. |
| Command Palette | `cloudsmith-vsc.scanDependencies` | `Scan dependencies` | Scan supported dependency inputs. |
| Command Palette | `cloudsmith-vsc.depSortFilter` | `Sort & filter dependencies` | Change Dependency Health ordering and filters. |
| Command Palette | `cloudsmith-vsc.viewComplianceReport` | `View compliance report` | Open the latest completed report when available. |
| Command Palette | `cloudsmith-vsc.inspectPackage` | `Inspect package` | Select or reuse an eligible package and show its validated inspection JSON. |
| Command Palette | `cloudsmith-vsc.showVulnerabilities` | `Show vulnerabilities` | Select or reuse a package and open vulnerability details. |
| Command Palette | `cloudsmith-vsc.explainQuarantine` | `Explain quarantine` | Select or reuse a quarantined package. |
| Command Palette | `cloudsmith-vsc.inspectUpstreams` | `View upstreams` | Select or reuse a repository and open upstream details. |
| Command Palette | `cloudsmith-vsc.previewUpstreamResolution` | `Preview upstream resolution` | Preview a supported package and repository resolution. |
| Command Palette | `cloudsmith-vsc.showPromotionStatus` | `Show promotion status` | Select or reuse a package and show its pipeline state. |
| Command Palette | `cloudsmith-vsc.promotePackage` | `Promote package` | Select or reuse an eligible package and begin the confirmed promotion workflow. |

### View-title and context actions

View-title actions appear only when their state prerequisites are satisfied. For example, Dependency Health shows **Pull dependencies**, **Cycle dependency view**, **Sort & filter dependencies**, and **View compliance report** only after the required scan state exists.

Context-only actions include **Copy value**, **Inspect package group**, repository filter shortcuts, workspace and repository search shortcuts, **Open CVE in browser**, **Pull dependency**, **View license**, and **Copy entitlement token**. Use the context menu or keyboard context-menu command on the relevant tree item.

## Help and support

Open the Help and feedback view for [extension documentation](https://docs.cloudsmith.com/developer-tools/vscode), [Cloudsmith documentation](https://docs.cloudsmith.com/), the [issue tracker](https://github.com/cloudsmith-labs/cloudsmith-vscode-extension/issues), and the [verified new-issue form](https://github.com/cloudsmith-labs/cloudsmith-vscode-extension/issues/new/choose).

Package grouping is documented in [Cloudsmith package groups](https://docs.cloudsmith.com/artifact-management/package-groups).

## License

Apache 2.0
